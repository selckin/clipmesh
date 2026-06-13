# clipmesh — share the MIME-rules file between nodes

**Date:** 2026-06-13
**Status:** Approved design

> **Update:** the rules file was subsequently switched from the line format
> described below to **TOML** (entries `"<mime>" = "allow"|"deny"|{ rule, max }`
> under `[rules]`; the managed version lives in a `[clipmesh]` table instead of a
> `# clipmesh-version:` comment). This was to support MIME types containing
> spaces/punctuation (e.g. Java dataflavors), which the whitespace-delimited
> format couldn't parse. The whole-file LWW design below is otherwise unchanged.

## Summary

Add an option (`share_mime_rules`, **default on**) that propagates the
per-type MIME allow/deny rules file across the mesh, so you curate
`~/.config/clipmesh/mimetypes` on one node and the rest converge to it.

The whole file is the synced unit, carrying a single last-writer-wins
version stamp `(stamp, origin)` reusing the clipboard's hybrid logical
clock. A node always sends its entire file (on connect and on change);
the receiver replaces its file verbatim when the incoming version is
newer. There is no per-type merge.

## Motivation

Today each node curates its own `mimetypes` independently. Copy a new
type on one host and it is appended deny-by-default *there*; every other
host re-discovers it separately and must be edited separately. For a
small personal mesh this is pure repetition — the rules are almost always
meant to be identical everywhere.

The inbound clipboard path deliberately does **not** write peer-advertised
types into the rules file (`SyncEngine::on_inbound` passes
`record_unseen: false`, "a peer must not write to our rules file"). This
feature does not change that path; it adds a *separate, explicit* message
that carries the rules file, gated behind `share_mime_rules`.

No new trust boundary: every peer already holds the PSK and can inject
arbitrary clipboard content, so accepting a peer's rules file is
consistent with the existing trust model. The `exclude_sensitive`
password-manager filter stays strictly local and is never shared.

## Non-goals (YAGNI)

- **Per-type merge / CRDT.** Whole-file LWW only. The newest full-file
  version wins outright and **replaces the loser entirely** — including any
  rules a node had that the winner never saw. So concurrent edits to
  *different* types on *different* nodes do not merge (the other edit is
  lost), and a node's locally-discovered types are dropped when it adopts a
  newer peer file — they get re-appended as plain deny-by-default the next
  time that type is copied, losing any allow/deny curation that wasn't shared.
  Accepted tradeoff.
- **Deltas.** Always send the entire file. It is a few hundred bytes to a
  couple KB; the bandwidth saving from diffing is not worth the
  complexity.
- **One-way / asymmetric sharing.** A single boolean. No "accept but never
  push" mode. Revisit only if a real need appears.
- **Backward-compatible wire protocol.** See Compatibility — this is a
  breaking protocol change; all nodes upgrade together.
- **Sharing any other config** (`config.toml`, psk). Only the rules file.

## Configuration

- New key `share_mime_rules: bool` on `RawConfig` and `Config`, with
  `#[serde(default = "default_true")]` — **default on**.
- Documented in `examples/config.toml`.
- **Independent of `direction`.** `direction` governs clipboard *content*;
  a `receive_only` node still curates and shares its rules file. The rules
  push on connect must therefore ignore both `direction` and
  `resync_on_connect` (those gate content only).
- `unknown_mime` is unchanged: a locally-discovered new type still gets the
  local default, but now appending it bumps the file version and the file
  is shared.
- `Config::for_test` defaults `share_mime_rules` to **false**, so the
  existing verbatim-file tests are unaffected; sharing has its own targeted
  tests that opt in.

## Data model — one version stamp per file

The whole file carries a single LWW coordinate `(stamp, origin)`, stored as
**one clipmesh-managed header line** at the top of the file:

```
# clipmesh-version: 1718200000000 550e8400-e29b-41d4-a716-446655440000
```

- It is a comment, so the existing parser already preserves it verbatim and
  ignores it for rules. `MimeRules` learns to recognise this one line, read
  `(stamp, origin)` from it, and rewrite it.
- `stamp` is a hybrid-logical-clock value (same scale as clipboard stamps:
  `max(wall-clock ms, highest seen)`); `origin` is the node UUID that last
  wrote the file. Ordering is the existing `(stamp, origin)` tuple compare
  (`ContentState::superseded_by`).
- **Baseline (before a real version exists):** the in-memory `(stamp, origin)`
  is `(file mtime in ms, own_id)`, falling back to `0` if mtime is unreadable.
  Using mtime (not 0) means that when sharing is first enabled across
  already-diverged files, the mesh converges on the **most-recently-edited**
  file rather than an arbitrary max-UUID winner. The first real local edit
  re-stamps with `tick()` and becomes authoritative regardless.
- **The header is materialised to disk on the first sync activity** — the
  first broadcast or the first adoption — not merely on a human edit. This
  pins the version on disk so it survives restarts: otherwise a restart would
  re-derive the baseline from the file's now-recent mtime and the version
  would drift on every reboot (a harmless but perpetual stamp ping-pong on
  identical content). Because sharing is default-on, in practice every sharing
  node grows the `# clipmesh-version:` line on its first connect. A node with
  sharing off never writes it, so its file stays exactly as hand-written.

## Protocol

New message variant:

```rust
Message::Rules {
    stamp: u64,
    origin: Uuid,
    body: String, // the entire file text, header line included
}
```

- **On (re)connect — bidirectional.** Both peers push their whole file to
  each other. `Mesh::register` already fires the connect event on both ends
  of a connection (initiator and responder each register the other and run
  `on_peer_connected`), so the newer `(stamp, origin)` wins on **each** side
  regardless of who dialed. Gated only by `share_mime_rules`.
- **On local change.** Broadcast the whole file to all peers.
- **Receiver.** Reject an implausibly-future `stamp`, `observe()` it into the
  clock (see Inbound Rules below for why both matter), then compare incoming
  `(stamp, origin)` against the local version. If it strictly supersedes,
  overwrite the *entire* file with `body` and re-stamp the header to the
  adopted `(stamp, origin)`, then reload. A correct peer's `body` already
  carries that exact header, so the re-stamp is idempotent and the two files
  end up byte-identical; the re-stamp only matters defensively (a body that
  somehow lacked the header would otherwise let `version()` fall back to the
  file's mtime and diverge). Older or equal versions are dropped.
- **No forwarding.** Every node already dials every node (the existing mesh
  invariant), so each receives the authoritative file directly from its
  origin — consistent with how clipboard updates are not relayed.

`body` is sent in full each time. The file is normally a few KB, but both the
send and the receive paths cap it at `max_payload_size` (the same budget
clipboard content uses) so the body always fits the transport frame
(`max_message` = `max_payload_size` + slack) and a peer cannot make us persist
an oversized file. An over-cap file is skipped with a warning rather than sent.

## Flow & wiring

### Local change → bump + broadcast

Two triggers, one handler:

1. **Auto-append** — the capture path discovers a new type and `ensure`
   appends it (existing behaviour). This runs on the engine task under the
   `mime_rules` mutex.
2. **Human edit** — fswatch detects the rules file changed (full-text change
   vs the `loaded` snapshot) and reloads it in place (existing behaviour).

When sharing is on, either trigger makes the engine: assign a fresh version
`(tick(), own_id)`, rewrite the header line, persist, and broadcast
`Message::Rules` with the whole file. The persist is self-write-suppressed
by the existing `loaded` content compare in `reload_if_changed`, so it does
not loop.

fswatch stays a dumb notifier: it already reloads the shared `MimeRules`; it
gains a lightweight notification to the engine (a small mpsc ping) so the
engine — which owns the clock and the mesh — performs the stamp + broadcast.
All clock/stamping logic stays on the single-threaded engine.

### Inbound Rules → adopt or drop

First reject an implausibly-future `stamp` (the same `MAX_FUTURE_SKEW_MS`
guard inbound `Clip` uses at `sync.rs`), so a peer with a broken clock can't
pin rule ordering forever. Then `observe()` the stamp into the clock —
exactly as the inbound `Clip` path does — so that a **later local edit
outranks the adopted version**. Without the observe, a local edit would be
stamped at `tick()` ≈ `now_ms()`, which can be *below* an adopted future-ish
stamp, so the edit would lose to the very version it just replaced and
silently revert. Finally compare `(stamp, origin)`; if it supersedes the
local version, write `body` verbatim and reload. That write is self-suppressed
by `loaded`, so adopting a peer file does not bounce back as a fake local edit
or re-broadcast.

### Startup

The engine reads the version from the loaded file (the header stamp if
present, otherwise the mtime baseline) and `observe()`s it into the clock, so
the next local edit outranks the existing version after a restart. Because the
header is materialised on first sync activity (see Data model), an established
version lives on disk and survives restarts.

### Inbound Clip is unchanged

The clipboard content path still passes `record_unseen: false` — peers'
*content* never writes the rules file. Only the explicit `Message::Rules`
writes rules. The existing
`inbound_peer_types_are_not_written_to_the_rules_file` test remains valid
unchanged.

## Components touched

| Unit | Change |
|------|--------|
| `config.rs` | Add `share_mime_rules` (default true); `for_test` defaults false. |
| `protocol.rs` | Add `Message::Rules { stamp, origin, body }`; add `protocol_version` to `Message::Hello`; bump `PROTOCOL_VERSION`. |
| `peer.rs` | Send `PROTOCOL_VERSION` in the hello and refuse a peer whose version differs (`check_protocol_version`). |
| `mime.rs` | Recognise/read/write the `# clipmesh-version:` header; baseline from mtime; methods to set a new version, render the full body, and replace the whole body from a received string. Learn the `share` flag. |
| `sync.rs` | On connect push the file (independent of `direction`/`resync_on_connect`); handle inbound `Rules` (LWW adopt); on local rules change bump version + broadcast; observe header stamp at startup; consume the fswatch ping via a new select arm. |
| `fswatch.rs` | After reloading the rules file, ping the engine that the rules changed. |
| `node.rs` / `main.rs` | Wire the rules-changed channel between fswatch and the engine; thread `share_mime_rules` into `MimeRules`. |
| `examples/config.toml`, `README.md` | Document the option and the convergence/LWW behaviour. |

## Implementation notes

- **Auto-append bump site.** `apply_mime_rules` is a sync filter; broadcasting
  from inside it is a layering smell. Detect "the capture path changed the
  file" and do the version-bump + broadcast at the `broadcast_selection`
  level (or right after the `ensure`/`persist`), not buried in the filter.
- **fswatch ↔ engine ordering.** fswatch reloads `MimeRules` *and* pings the
  engine. The engine's bump must not mistake its own header rewrite for a
  human edit — rely on the existing `loaded` self-write suppression and pin
  the exact sequence (reload → ping → engine bumps once → engine write is
  suppressed) so it terminates.
- **`mime_rules_path == None`** (in-memory ruleset, used by tests): sharing is
  a no-op — there is no file to send, materialise, or adopt. Guard every sync
  path on a present path.
- **Transport frame cap.** Cap the shared `body` at `max_payload_size` on
  **both** the send and the receive paths (a shared `rules_body_ok` helper),
  `warn!`ing and skipping an over-cap file. Tying the cap to `max_payload_size`
  (rather than a hardcoded constant) guarantees the body fits the transport
  frame (`max_message` = `max_payload_size` + 64 KiB) however the user tunes it,
  and the receive-side check stops a peer from making us persist a huge file.

## Compatibility

Adding `Message::Rules` is a **breaking wire change** — bincode is not
self-describing, so a pre-upgrade node that receives the new variant fails to
decode it and drops the connection. `install.sh` is re-run on every host and
nodes share a PSK, so the stance is: **treat this as a breaking release, bump
`PROTOCOL_VERSION`, and upgrade all nodes together.**

To make a mismatch *diagnosable* instead of a corruption-like decode loop,
`Message::Hello` now carries `protocol_version`, and the hello exchange refuses
a peer whose version differs with an actionable error ("peer speaks vN, we
speak vM — upgrade all clipmesh nodes"). This is itself a breaking change to the
`Hello` shape (so v2-and-earlier can't talk to this build at all), but from now
on `Hello`'s shape is fixed and version differences are conveyed by the
`protocol_version` field — a future protocol bump degrades to a clean refusal
rather than a silent drop.

## Security

- No new trust boundary: PSK-holding peers can already inject arbitrary
  clipboard content.
- `exclude_sensitive` (password-manager hint) filtering stays strictly local
  and is never part of the shared file.
- Explicit consequence to document: with sharing on, a peer flipping a type
  to `allow` *will* start it syncing on your node — that is the feature.

## Testing (TDD, RED first)

- Whole-file LWW: a newer `body` replaces the local file; an older one is
  ignored; equal stamps resolve deterministically by `origin`.
- A local edit bumps the version and broadcasts the whole file.
- An auto-appended new type (capture path) bumps the version and broadcasts.
- Inbound adoption overwrites the file verbatim and does **not** re-broadcast
  (no loop).
- **Adopting a future-ish version is `observe()`d**, so a subsequent local
  edit is stamped above it and wins, rather than reverting to the adopted file.
- **An implausibly-future rule stamp is rejected** (`MAX_FUTURE_SKEW_MS`).
- Baseline-from-mtime is superseded by a real later edit.
- Connect pushes the whole file **both ways** and both sides converge,
  including when the node being dialed holds the newer file and when one side
  is `receive_only`.
- **The version header is materialised on first broadcast/adoption and
  survives a restart** (no stamp drift / ping-pong across reboots).
- Restart: the engine observes the persisted header stamp so the next local
  edit outranks the loaded version.
- `share_mime_rules = false`: nothing is sent, inbound `Rules` is ignored,
  and no `# clipmesh-version:` header is ever written.
- Inbound `Clip` content still never writes the rules file.
- Header round-trips: parsing then re-rendering the file is idempotent and
  preserves the user's rules, comments, and ordering.
