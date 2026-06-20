# clipmesh — local clipboard↔primary selection bridge

**Date:** 2026-06-14
**Status:** Approved design

## Summary

Add a *local* bridge between the two selections on a single host: mirror
the regular CLIPBOARD selection into the PRIMARY (middle-click) selection
and/or vice versa. This is a different axis from the existing mesh sync —
`sync_primary` already syncs CLIPBOARD↔CLIPBOARD and PRIMARY↔PRIMARY
*across hosts*; this feature couples the two selections *on the same host*.

It is controlled per-direction by a new `link_selections` config, default
off. A bridged write rides the existing `broadcast_selection` path, so it
also propagates to the mesh to the extent that selection's own mesh sync is
enabled ("feed the mesh"). The bridge honors `exclude_sensitive` but
otherwise mirrors the full raw offer locally. No wire-protocol change.

## Motivation

On Wayland the CLIPBOARD selection (Ctrl-C / Ctrl-V) and the PRIMARY
selection (select-to-copy / middle-click-paste) are independent. Users
commonly want them coupled locally so that, e.g., a Ctrl-C is also
middle-click-pasteable. clipmesh already speaks both selections
(`SelectionKind::{Clipboard, Primary}`, `read_offer`/`write_offer` for
each), so the plumbing exists; what's missing is a local transform that
copies one selection's content into the other.

The two directions have very different ergonomics, so they are independently
controllable:

- **`clipboard → primary`** is harmless: after Ctrl-C the content is also
  middle-click-pasteable.
- **`primary → clipboard`** is a footgun: *selecting any text anywhere*
  overwrites the Ctrl-C clipboard — and, with `sync_primary`, every peer's
  clipboard too. It's off unless explicitly enabled (this is why X11 tools
  like autocutsel split the two directions).

## Non-goals (YAGNI)

- **New wire messages or a protocol bump.** The bridge is purely local; the
  mesh still only ever carries genuine per-selection `Clip` messages.
  `PROTOCOL_VERSION` is unchanged.
- **A separate "local-only, never touch the mesh" mode.** The chosen
  semantics are "feed the mesh": a bridged write is treated like a normal
  local copy and propagates per the selection's existing sync settings.
- **Applying MIME allow/deny or size caps to the local mirror.** Those
  govern *network* bandwidth; locally the partner selection should hold the
  full content. They still apply to anything that leaves on the wire.
- **A `Clipboard`-trait decorator that mirrors below the engine.** Rejected:
  it would duplicate the engine's per-selection dedup state and can't
  cleanly "feed the mesh".

## Architecture

All behavior lives in `src/sync.rs` (the bridge step + loop guard) and
`src/config.rs` (the new setting), with a one-field change in
`src/clipboard/wayland.rs` and one line in `src/main.rs` to decouple
PRIMARY watching from `sync_primary`. The transport, protocol, mesh, and
MIME-rules layers are untouched.

### Config surface

A new enum modeled on the existing `Direction` / `MimePolicy`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkSelections {
    Off,                  // default
    ClipboardToPrimary,
    PrimaryToClipboard,
    Both,
}

impl LinkSelections {
    fn clip_to_primary(self) -> bool { matches!(self, Self::ClipboardToPrimary | Self::Both) }
    fn primary_to_clip(self) -> bool { matches!(self, Self::PrimaryToClipboard | Self::Both) }
}
```

Exposed as `link_selections = "off" | "clipboard_to_primary" |
"primary_to_clipboard" | "both"`, default `off`. Named `link_selections`,
not `sync_*`: "sync" is the mesh vocabulary, "link" signals a local
coupling. The enum can't express a nonsensical state, matching the
`direction` idiom.

The field must be added in **four** places, because `RawConfig` is
`#[serde(deny_unknown_fields)]` (so any deployed config that sets
`link_selections` fails to parse unless `RawConfig` knows it) and `Config`
has no `Default`:

- `RawConfig`, with `#[serde(default)]` → `LinkSelections::Off`;
- `Config` (the resolved struct), next to `sync_primary`;
- the `RawConfig → Config` resolution (`from_toml`), copying the field;
- `Config::for_test`, which constructs `Config` field-by-field with no
  `..Default::default()` — defaulting to `LinkSelections::Off` there, or the
  crate won't compile.

### Watcher decoupling

Today `WaylandClipboard::watch()` calls `spawn_watcher(tx, self.sync_primary)`,
so PRIMARY is only observed when mesh-primary-sync is on. A
`primary → clipboard` link needs PRIMARY *observed* even when it isn't
mesh-synced (to detect select events). So:

- `WaylandClipboard` stores `watch_primary: bool` instead of `sync_primary`.
- `main.rs` computes it:
  `watch_primary = cfg.sync_primary || cfg.link_selections.primary_to_clip()`.
- `clipboard → primary` alone only *writes* PRIMARY and never needs to
  observe it, so it is correctly absent from that condition (PRIMARY then
  stays local and unbroadcast when `sync_primary` is off).

This is the one place the two axes (mesh-sync vs. local-link) touch.

### Engine state: the loop guard

One new field on `SyncEngine`:

```rust
/// Raw-content hash last mirrored to/from each selection by the bridge.
/// Separate from `current` (which holds *filtered* hashes): the bridge
/// writes *raw* offers, so a raw-vs-filtered comparison would never match
/// and would loop forever whenever filtering changes the content.
last_mirrored: Mutex<HashMap<SelectionKind, [u8; 32]>>,
```

`current[]` cannot serve as the guard because `broadcast_selection` records
the **filtered** content hash, while the bridge mirrors the **raw** offer.
When the filter alters the content (e.g. a denied MIME type is dropped on
the wire but kept in the local mirror), `current[partner]` and the raw
source hash never match, so a `current[]`-based guard would re-fire every
cycle and never terminate. `last_mirrored` tracks raw hashes, sidestepping
this entirely.

`last_mirrored` is a sibling of `current`, so it follows the same locking
discipline: lock with plain `.lock().unwrap()` (matching `current`, not the
`unwrap_or_else(into_inner)` recovery used for `mime_rules`), and **never
hold the lock across the `read_selection` / `write_offer` awaits** — take it
only for the brief read of the guard and the post-write stamp. The whole
engine runs on a single task, so the two mutexes cannot contend across tasks
and there is no added deadlock surface.

### The bridge step: `bridge_from(kind)`

A new method run immediately after `broadcast_selection(kind)` wherever a
pending change is drained:

1. Pick the partner/direction: `Clipboard` → mirror to `Primary` iff
   `link.clip_to_primary()`; `Primary` → mirror to `Clipboard` iff
   `link.primary_to_clip()`. If neither applies, return at once — so
   `link_selections = off` (the default) is a zero-cost no-op.
2. Read `kind`'s **raw** offer (`read_selection`, no filter). If the read
   fails or times out (`None`), return **without** touching `last_mirrored`,
   so it retries on the next change. If the offer is **empty**, return too —
   `bridge_from` bypasses `filter()` (which normally drops empties), so this
   guard must be explicit: clearing one selection must never wipe the
   partner. Otherwise `h = content_hash(raw)`.
3. **Guard:** if `last_mirrored[kind] == h`, return — already bridged.
4. **Sensitive filter:** if `cfg.exclude_sensitive && is_sensitive(raw)`,
   record `last_mirrored[kind] = h` and return — never mirror a secret, but
   remember it so it doesn't re-trigger.
5. `write_offer(partner, raw)`.
6. On success, set `last_mirrored[kind] = h` **and** `last_mirrored[partner] = h`.

**Why step 6 stamps both selections (termination proof sketch):** the
`write_offer(partner, raw)` fires the partner's watch, re-entering the loop
as a change on `partner`. When `bridge_from(partner)` then runs it reads the
partner's raw content — exactly `h` — finds `last_mirrored[partner] == h`,
and returns at step 3. The echo is absorbed with **zero redundant writes**,
after the partner's own `broadcast_selection` has had its chance to feed the
mesh. Because each genuine new content makes at most one write per selection
and then matches the guard, the chain always terminates.

This proof rests on one invariant: **the partner's raw read-back must
byte-equal what `bridge_from` wrote** (so its hash is exactly `h`). This is
the same round-trip-fidelity that `broadcast_selection`'s existing echo
suppression already depends on — the Wayland backend writes faithfully
(`omit_additional_text_mime_types`, `wayland.rs`), and the mock stores bytes
verbatim. If a backend ever rewrote content on read-back, both the existing
echo suppression and this guard would mis-fire; that backend would be the
bug, not the bridge. A test should bridge an offer carrying a denied and/or
multi-representation MIME type under `both` and assert no redundant writes,
to pin this invariant down.

**Observability.** When a mirror actually writes the partner (step 5
succeeds), emit a `verbose` line matching the broadcast path's style — e.g.
`mirrored {kind:?} → {partner:?} [{describe_offer(raw)}]` — gated on
`cfg.verbose` like the existing copy/receive summaries, so a user who turns
on `verbose` can see the bridge acting.

### Run-loop integration

There are **three literal `broadcast_selection(k)` call sites** in `run()`,
and all three must be patched (the `debounce_ms == 0` fast path is not a
single disjoint location — it appears in two different arms):

1. the post-prime flush, `debounce_ms == 0` branch (~`sync.rs:196`),
2. the watch arm, `debounce_ms == 0` branch (~`sync.rs:214`),
3. the debounce-deadline arm (~`sync.rs:230`).

Factor them through one helper:

```rust
async fn process(&self, kind: SelectionKind) {
    self.broadcast_selection(kind).await;
    self.bridge_from(kind).await;
}
```

and call `process` in all three drain sites. The bridge's `write_offer`
enqueues the partner as a fresh `pending` entry, so the partner is
broadcast/bridged on the next debounce tick (≤ `debounce_ms` later;
immediate when `0`).

`process(kind)` reads the selection twice — once in `broadcast_selection`,
once in `bridge_from`. This is correct but does two Wayland reads per change.
An optional optimization is to read the raw offer once in `process` and pass
it to both; not done initially to keep `broadcast_selection`'s signature and
its `verbose`-describe logic untouched. Revisit only if it shows up.

**Conflict resolution within one debounce window. A direct change beats the
mirror.** If a selection and its bridge partner both change inside a single
`debounce_ms` window, `pending` holds both and `process()` runs them in
arrival order. A naive `bridge_from` would overwrite the partner *before* the
partner's own `process()` reads it, so the first-seen change would win and the
other selection's concurrent change would be silently destroyed — its
now-stale read then re-broadcast as the winning content. With `sync_primary +
clipboard_to_primary` (or `primary_to_clipboard`) this is a real data-loss
bug: copy something and then select text within ~`debounce_ms`, and the
selection you just made is overwritten by the clipboard mirror and can never
be pasted (nor is it sent to the mesh).

The rule instead is **the directly-changed selection wins**: a user change to
a selection is never clobbered by a mirror *into* that selection from the same
window. `process()` passes the set of selections drained together (`batch`) to
`bridge_from`; when the partner is also in `batch` and holds content the bridge
did *not* just place there (tracked per-selection in `mirrored`, the raw hash
of the last value mirrored into each selection), that content is a fresh direct
user change and the mirror steps aside. The `mirrored` memo is what
distinguishes a genuine concurrent selection (preserve it) from the bridge's
own prior write echoing back into a later batch (safe to overwrite, so a new
copy still propagates). Under `both`, each selection therefore keeps its own
concurrent edit instead of one stomping the other.

### Interactions

- **Local write vs. the wire.** `bridge_from` writes the partner the raw
  offer minus the sensitive check only. MIME allow/deny and size caps are
  *not* applied to the local write, so the partner selection holds the
  complete content. Whatever then reaches the mesh is filtered normally,
  because it leaves via the partner's own `broadcast_selection` →
  `filter(.., true)`. Net: full content in both local selections; filtered
  content on the wire; secrets in neither partner.
- **Independence from `direction`.** The bridge is a local mirror, so it
  runs regardless of `direction` (a `receive_only` node still links its two
  local selections). Whether the mirror *propagates* is decided entirely by
  the partner's `may_send`, which already encodes both `direction` and
  `sync_primary`:
  - `clip → primary`, `sync_primary = false`: PRIMARY mirrored locally,
    **not** broadcast (and PRIMARY needn't be watched, and isn't — so the
    bridge's PRIMARY write produces no echo event at all; termination there
    is trivial, and the `last_mirrored[Primary]` stamp is simply never
    consulted).
  - `clip → primary`, `sync_primary = true`: PRIMARY mirrored locally **and**
    broadcast as a primary update.
- **Resync is unchanged.** `on_peer_connected` still resyncs only
  `synced_kinds()`; the bridge never drives resync directly. A
  `primary → clipboard` + `sync_primary = false` node still resyncs the
  bridged CLIPBOARD value (CLIPBOARD is always synced), but never resyncs
  PRIMARY (it isn't a mesh selection there).
- **Feed-the-mesh consequence (documented).** Because a bridged write rides
  the normal broadcast path, content received from a peer on one axis can be
  **re-emitted on the other axis** with a fresh `(stamp, origin = us)` —
  e.g. a peer's CLIPBOARD update lands locally, `bridge_from(Clipboard)`
  mirrors it to PRIMARY, and (with `sync_primary`) we broadcast it as a
  PRIMARY update. The mesh still converges: every host broadcasts a given
  `(selection, hash)` at most once (`current[]` echo-suppresses repeats and
  identical-content inbound applies don't re-write), so stamp churn is
  bounded by host count, not infinite. This is the accepted cost of "feed
  the mesh".

### Startup / priming

A restart must never *spontaneously* bridge — that would clobber the partner
(or, for `primary → clipboard`, the clipboard) with restored content. So
`prime()` will, for each **watched** selection, also seed `last_mirrored[kind]`
with that selection's raw content hash. Existing-at-startup content is then
treated as already-mirrored; only a genuine post-startup change (a different
raw hash) triggers the bridge. This mirrors the existing priming philosophy
(don't re-broadcast restored content as fresh).

The watched set is broader than the synced set: a `primary → clipboard` link
with `sync_primary = false` *watches* PRIMARY (to detect selections) without
*syncing* it. Priming therefore iterates the watched kinds — CLIPBOARD
always, PRIMARY when `watch_primary` — reading each selection once and
deriving both the filtered hash (recorded in `current[]` only for synced
kinds, used for broadcast echo suppression) and the raw hash (recorded in
`last_mirrored` for every watched kind). `synced_kinds()` keeps its current
meaning; a parallel `watched_kinds()` (or the `watch_primary` flag) drives
the priming and the seed. Since synced kinds are always a subset of watched
kinds, no `current[]` seeding is lost.

## Testing

All tests run on `MockClipboard`, which already fires its watch on
`write_offer` (see `mock.rs`), so the bridge's echo path is exercised
headless:

- **Single-direction mirror:** `clipboard_to_primary` mirrors a local
  clipboard copy into PRIMARY; `primary_to_clipboard` mirrors a selection
  into CLIPBOARD; each single direction does **not** mirror the other way.
- **No loop / no redundant write under `both`:** after one copy, assert each
  selection is written exactly once (instrument the mock's write count) and
  the engine settles. Include a variant whose offer carries a
  **denied and/or multi-representation** MIME type, to pin the read-back
  fidelity invariant the termination proof depends on.
- **Local mirror under `receive_only`:** with `direction = receive_only` and
  `link_selections = both`, a local change is mirrored into the partner
  selection but produces **zero** outbound broadcasts (the bridge is local;
  `may_send` blocks the wire).
- **Sensitive content** (`x-kde-passwordManagerHint = secret`) is **not**
  bridged when `exclude_sensitive`.
- **Empty / unreadable source:** an empty selection is **not** bridged (the
  partner is left intact, not cleared); a read that returns `None` leaves
  `last_mirrored` untouched so a later successful read still bridges.
- **Same-window conflict:** under `both`, queue a CLIPBOARD and a PRIMARY
  change with different content into one debounce window and assert the
  first-changed selection wins and both selections settle on its content
  (the documented resolution rule).
- **Feed-the-mesh:** with `sync_primary`, a clipboard copy under
  `clip → primary` produces **both** a `Clip{Clipboard}` and a
  `Clip{Primary}` broadcast (assert against captured outbound, as `mesh.rs`
  tests already do). Note the PRIMARY broadcast arrives on a *later* event-
  loop iteration (the bridge write re-enters via the watcher channel), even
  when `debounce_ms == 0` — the test must await two separate broadcasts, not
  expect them synchronously.
- **Startup:** priming an existing clipboard + primary under `both` triggers
  **no** bridge writes.
- **Default off:** `link_selections = off` performs zero bridge writes — a
  pure regression guard.
- **Config parsing (`config.rs`):** `link_selections` parses all four
  values and defaults to `off`.

## Docs

- `examples/config.toml`: document `link_selections` with the
  `primary → clipboard` warning ("selecting text overwrites your clipboard —
  and, with sync, your peers' clipboards").
- `README.md`: a short paragraph distinguishing the local selection bridge
  from mesh primary-sync.
- `CLAUDE.md`: a one-line note in the architecture section that the local
  selection bridge is a distinct axis from `sync_primary`.

## Risks

- **Reliance on `write_offer` firing the watch.** The bridge feeds the mesh
  and absorbs its own echo through the watcher. This is contractual (the
  `Clipboard` trait docs state the watch fires on `write_offer`, "real
  clipboards do this") and the mock honors it. If a future backend violated
  it, the bridged selection would not broadcast; the `last_mirrored` guard
  would still prevent loops.
- **Footgun amplification.** `primary → clipboard` with `sync_primary` means
  a local text selection overwrites every peer's clipboard. Mitigated by
  default-off and an explicit config warning; it is the user's deliberate
  choice.
- **Extra startup read.** Priming now derives a raw hash in addition to the
  filtered one; it still reads each selection once. Negligible.
- **Inbound update during the priming window.** Because `prime()` seeds
  `last_mirrored` from the live selection, a clipboard/primary update that
  arrives from a peer *during* priming is treated as already-mirrored and is
  not locally bridged; it bridges on the next genuine change. The window is
  the brief startup priming interval, so this is a narrow, transient
  limitation rather than a steady-state bug.
- **`current[partner]` is briefly stale after a bridge write.** `bridge_from`
  does not update `current[partner]`; it relies on the partner's echo
  `broadcast_selection` to record it (or, when the partner isn't synced, it
  is never recorded — and never needed). In the gap between the bridge write
  and that echo, an inbound peer update for the partner with identical
  content could cause one redundant clipboard write, or a stale
  `(stamp, origin)` could briefly let an older inbound win. This is the same
  self-healing, single-task-serialized class as the priming window and
  converges on the next event; it is not a divergence.
