# Clipboard history — Implementation Plan

**Goal:** Remember the recent clipboard contents a node settles on, in a bounded
in-memory ring, and add a `clipmesh history` subcommand that lists them, prints
one, and puts one back on the clipboard — locally or on a peer.

**Architecture:** `SyncEngine`'s `current` map moves into a new child module
`sync/settled.rs` together with the history, behind a type whose fields the
engine cannot reach, so the only way to move `current` is to hand the content to
the history in the same step. Two new `Pipeline` variants cover the paths that
did not exist before (`Remember` for a local copy a node will not send, `Recall`
for the restore write). The CLI is a one-shot mesh client over a new
`client::ask`, extracted from `paste::fetch_offer`'s select loop.

**Tech Stack:** Rust, tokio, reusing `transport`/`peer`/`mesh`/`protocol` as a
library. `PROTOCOL_VERSION` 8 → 9.

**Spec:** `docs/superpowers/specs/2026-09-18-clipboard-history-design.md`

---

## File structure

| File | Responsibility for this feature |
|------|---------------------------------|
| `src/sync/settled.rs` (new) | `Settled` (the `current` record + the history, private), `ContentState` (moved), the `History` ring, dedup/eviction, prefix lookup, `hex`, preview rendering. |
| `src/sync.rs` | `mod settled;`; `current` field → `settled`; the five call sites; `Pipeline::{Remember, Recall}`; `SelectionPolicy::remember`; `serve_history`/`restore_entry`/`on_history`; the `Message::History` dispatch arm. |
| `src/protocol.rs` | `Message::{History, HistoryReply}`, `HistoryRequest`/`HistoryEntry`/`HistoryResult`/`HistoryMiss`, `PROTOCOL_VERSION = 9`. |
| `src/client.rs` (new) | `ask` — the dial-as-Paster, send-one, wait-for-the-matching-reply loop. |
| `src/history.rs` (new) | The CLI: `HistoryArgs::parse`, target resolution, the listing/restore renderers, `explain`, `run`. |
| `src/paste.rs` | `fetch_offer` reduced to a `client::ask` call; `select_type`/`render`/`write_stdout`/`list_available` become `pub(crate)`. |
| `src/config.rs` | `history_entries`, `history_max_bytes`, `Config::local_addr`. |
| `src/config_template.rs` | Two `Block::Optional`s, before `Block::LinkSelections`. |
| `src/main.rs` | `history` detected as argv[1], before the daemon flag loop; `USAGE`. |
| `tests/history.rs` (new) | Two-process tests over the real Noise handshake. |
| `examples/config.toml` | **Generated** — `CLIPMESH_REGEN_EXAMPLE=1 cargo test --lib example_config_matches_template`. |
| `README.md`, `CLAUDE.md`, `docs/superpowers/specs/2026-06-12-clipmesh-design.md` | Docs; the last one's `Clipboard history` non-goal is struck through and pointed at the new spec. |

`src/sync.rs` keeps its path — `src/sync.rs` plus `src/sync/settled.rs` is the
same arrangement `clipboard/mutter.rs` and `clipboard/mutter/fake.rs` already
use — so no 5000-line file move.

---

## Tasks

Each task is landable on its own and leaves the suite green.

### 1. `Settled`, behaviour-neutral

The store and the gate, plus the five call-site rewrites (`broadcast_selection`,
`apply_inbound_clip` ×2 branches, `adopt_restored`, `on_peers_connected`) and the
test harness. `Config::for_test` has the production caps, so **the whole existing
suite is the regression test for this refactor**. Land it separately if possible:
it touches the LWW ordering path.

RED: the pure store tests in `settled.rs` — move-to-front, both caps, the
oversized-offer refusal, the front-entry guard, prefix lookup, preview
sanitizing, `adopt`'s replace-unless-identical rule.

### 2. Wire types

`PROTOCOL_VERSION = 9` with its `/// v9:` line, the four new types, the two
`Message` variants. RED: `history_messages_round_trip_through_the_wire_encoding`
— bincode is not self-describing, so every shape has to survive the encoder the
wire actually uses.

### 3. Config

Three-part change plus the regenerated example. RED: the defaults, the zero-budget
rejection pointing at `history_entries = 0`, and
`local_addr_turns_a_wildcard_bind_into_a_loopback_it_can_dial`.

### 4. Recording

`Pipeline::Remember`, `SelectionPolicy::remember` in `has_local_sink`, the
`!may_send` branch. RED: a local copy, inbound content and startup content are
each remembered; a receive-only node remembers without sending; a secret is
never remembered; **a send-blocked copy does not record unseen types into the
rules file** (the dangerous half of this task).

### 5. Serving and restoring

`on_history`, `serve_history`, `serve_entry`, `restore_entry`,
`Pipeline::Recall`. RED: a restore writes and broadcasts above the stamp it
replaces; **a restore is not re-broadcast as a local copy**; a receive-only
restore is local-only; a listing reads no clipboard at all (`block_reads` and
still answer); missing vs ambiguous; a narrowed `get`; an entry a rules change
now denies reports `Filtered(Denied)`, not `NotSynced`.

### 6. `client::ask`

Extract, reimplement `fetch_offer` on it. `tests/paste.rs` passing **unchanged**
is the proof. Keep the word "within" in the timeout message — two paste tests
assert on its absence to prove a node answered rather than timed out.

### 7. CLI

`history.rs` + the `main.rs` detection. RED: each verb and its id, both getopt
attached-value spellings, output flags refused on `list`/`restore`, the default
target, `age` tokens, the listing's columns and absence of trailing whitespace,
and `explain` rendering every `HistoryMiss` distinctly.

### 8. Integration

`tests/history.rs`: the listing, a narrowed `get`, **a restore on A landing on
B's clipboard**, an ambiguous prefix refusing rather than guessing, a disabled
node saying so, and the encoded-size assertions that pin "a listing carries no
payloads" on the wire rather than as an intention.

### 9. Docs

README section, the `CLAUDE.md` bullets, the spec and this plan, and the struck
non-goal. Then `./build.sh`.
