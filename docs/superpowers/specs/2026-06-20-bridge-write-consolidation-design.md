# clipmesh — batch-deferred local propagation (write/echo consolidation)

**Date:** 2026-06-20
**Status:** Approved design

## Summary

Rework how the sync engine turns a debounce batch of local clipboard changes
into broadcasts and clipboard writes. Today each changed selection is processed
independently and propagation **rides watch echoes**: a local-bridge mirror
write fires a watch event whose re-read is what broadcasts the mirrored partner
to the mesh and (with `take_ownership`) re-offers it — so one user copy can write
the same selection twice and read it back several times.

Replace that with a **read → plan → execute** batch pipeline: read each fired
selection once, compute every broadcast and every write up front (a pure,
unit-testable plan), then execute — writing each selection **at most once** and
dropping the resulting echo instead of re-entering propagation. This eliminates
the mirror→own double-write, removes the dependency on echoes to *do work*,
caches reads within a batch, and collapses the two echo-tracking memos
(`self_written`, `mirrored`) into one.

## Motivation

With `take_ownership` + `clipboard_to_selection` + `sync_selection` on, a single
copy currently cascades: the genuine change is captured and broadcast, the bridge
mirrors it into the partner (a write), that write's echo re-broadcasts the
partner and triggers a **second** ownership write of the same selection, and each
write is then read back in full to be classified as an echo. The reads are cheap
local Wayland IPC, but the architecture is hard to reason about: echoes are
*load-bearing* (a mirror's echo is the only thing that broadcasts the partner),
which couples correctness to watch-event timing and makes the propagation logic
testable only through the full engine + mock-watcher round trip.

This change makes local propagation **deterministic and computed**, not
echo-driven, and removes the redundant write/echo on a mirrored-then-owned
selection.

## Scope: what this does and does not reduce

- **Does** remove the mirror→own double-write (and its echo) on the
  Ctrl+C-into-a-stale-selection path: the partner is written **once** in its
  final owned form, broadcast directly, and its echo dropped.
- **Does** cut reads to **one per fired selection per batch** (the bridge's
  reconcile re-read of an already-read selection is gone).
- **Does** make echoes pure noise: every engine write is dropped on sight next
  batch, never re-broadcast/re-mirrored/re-owned.
- **Does not** drop below **one write per genuinely-changed owned selection.**
  `take_ownership` must re-offer a freshly-copied selection to transfer ownership
  from the source app *even when the bytes are unchanged*, so a copy that sets
  both CLIPBOARD and SELECTION (e.g. copy-on-select) still produces two writes
  and two (dropped) echoes. That is inherent to ownership, not a missed
  optimization.
- **Does not** change observable behavior: the same broadcasts, the same final
  clipboard contents, the same `link_selections` / `take_ownership` /
  `sync_selection` / `direction` / sensitivity / size-cap semantics. This is an
  internal restructuring whose only external effects are fewer redundant
  clipboard re-offers (one write per selection instead of two on the mirror+own
  path) and fewer debug log lines.

## Non-goals (YAGNI)

- **Suppressing the echo *read*.** The watcher delivers a bare `SelectionKind`,
  never content, so distinguishing our echo from a fresh user copy still requires
  reading and comparing. A "skip the next N events on K" counter would race a
  real copy and is explicitly rejected.
- **Locally mirroring engine-written (inbound/restored) content.** Mesh-received
  and startup-restored content is still *not* bridged to the partner selection;
  `link_selections` remains a purely local coupling of *user* changes.
  Cross-host propagation stays `sync_selection`'s job. (Unchanged from today.)
- **Changing the debounce/select-loop structure** beyond the per-batch handler:
  priming, inbound handling, peer-connect, and rules-change arms are untouched.

## Architecture

All changes are in `src/sync.rs`. The transport/protocol/mesh/mime/config layers
are untouched. The debounce machinery in `run()` (the `pending` vector, the
`deadline`/`armed` arm, the `debounce_ms == 0` immediate path, and the
priming gate) is unchanged; only the body that drains a batch changes — today a
`for &k in &batch { self.process_local_change(k, &batch).await }` loop, replaced
by a single `self.handle_batch(batch).await` call from all three drain sites
(immediate path, deadline arm, and the post-prime flush).

### The single echo memo

Replace the two maps

```rust
self_written: Mutex<HashMap<SelectionKind, [u8; 32]>>,
mirrored:     Mutex<HashMap<SelectionKind, [u8; 32]>>,
```

with one:

```rust
/// Raw-content hash of the last value the engine itself wrote to each
/// selection (an ownership re-offer, a local-bridge mirror, an inbound mesh
/// apply, or the startup-restored baseline). The watcher re-reports every
/// write; an incoming change whose hash matches the recorded one is that echo
/// and is dropped — never broadcast, mirrored, or re-owned. One-shot: the
/// entry is removed when any change to that selection is classified, so a
/// stale marker can never suppress a later genuine copy of identical bytes.
last_written: Mutex<HashMap<SelectionKind, [u8; 32]>>,
```

Every engine write records `last_written[kind]` (replacing both prior memos).
This is sound because, unlike today, a mirror's broadcast is performed *directly*
during execute — so the mirror echo no longer needs to survive classification to
carry the broadcast. The `mirrored`-vs-`partner_now` clobber comparison
disappears: direct-change-wins is now decided structurally (below).

Recorders, all writing `last_written`:
- ownership re-offer (was `self_written`),
- local-bridge mirror (was `mirrored`),
- inbound mesh apply (`apply_inbound_clip`, was `self_written`),
- startup baseline (`prime`, was `self_written`, still `or_insert` to avoid
  clobbering a racing inbound apply).

### Phase 1 — Read & classify

`handle_batch(batch: Vec<SelectionKind>)` first reads each fired selection once
and keeps only genuine user changes:

```text
read:    IndexMap<SelectionKind, Offer>   // every read this batch (incl. echoes)
changed: Vec<SelectionKind>               // the genuine user changes, in batch order
for kind in batch:
    if !has_local_sink(kind):              // nothing would act on it — preserve
        verbose "copied {kind}: not sent (this node does not send)"; continue
    raw = read_selection(kind)             // the one read; None on error/timeout → skip
    // one-shot consume the echo memo, then classify
    match last_written.lock().remove(kind):
        Some(h) if h == content_hash(raw): pass        // our own echo → no propagation
        _:                                             // genuine change
            changed.push(kind)
    read.insert(kind, raw)
```

`read` is the batch's view of the clipboard and is the **only** store of content:
it holds echoes too, because a `Mirror` reconcile compares against the partner's
*actual* content even when that partner's own change was an echo of our last
write. `changed` carries no payload — it is all the planner needs.

This is the read cache and the echo gate. Because an echo is dropped here, it
never triggers a broadcast, mirror, or ownership write — there is no cascade.

### Phase 2 — Plan (pure)

A free function (no `self`, no I/O) computes the whole batch's intent so it can be
unit-tested directly:

```rust
/// One planned act of propagation. The plan *names* its content rather than
/// carrying it: every payload a batch propagates is the content of some
/// genuinely-changed selection — its own, or (for a mirrored partner) its bridge
/// source — so `source` always indexes phase 1's `read`.
struct Action {
    target: SelectionKind,   // the selection being broadcast or written
    source: SelectionKind,   // the change whose content fills it (== target if direct)
}

struct BatchPlan {
    /// Selections to broadcast to the mesh, in deterministic order.
    broadcasts: Vec<Action>,
    /// Selections to write locally, each target at most once.
    writes: Vec<(Action, Provenance)>,
}

/// Why a write happens — selects the reconcile rule in execute.
enum Provenance {
    /// take_ownership re-offer: write unconditionally (ownership transfer),
    /// even if the selection already holds these bytes.
    Own,
    /// Local-bridge mirror with take_ownership off: write only if the partner
    /// does not already hold this content (reconcile against drift).
    Mirror,
}

/// `changed` = the genuine local changes this batch. `link`, `own` come from
/// Config. Pure, and payload-free: the decision depends only on *which*
/// selections changed, so no clipboard content is copied to reach it. The caller
/// does the I/O, the may_send/filter/dedup on broadcasts, the synth+cap
/// transform on `Own` writes, and the drift reconcile for `Mirror`.
fn plan_batch(changed: &[SelectionKind], link: LinkSelections, own: bool) -> BatchPlan
```

Rules:

1. **Mirror targets.** For each genuine `K` with `bridge_partner(K) = Some(P)`
   (derived from `link`): if `P` is **also** in `changed` (a concurrent direct user
   change), **skip the mirror** — direct-change-wins, the clobber fix expressed
   structurally. Otherwise `P` receives `K`'s content (`Action { target: P, source: K }`). A selection is a *mirror
   target* if it is some genuine change's partner and is not itself a genuine
   change.

2. **Source per selection.** Each selection that is a genuine change or a mirror
   target names where its content comes from: itself (genuine change) or the
   source change (mirror target). The plan records only that *name*; execute
   looks the content up in `read`. The `Own` synth+cap transform is applied later,
   in execute, so `plan_batch` stays a pure decision over which selections act —
   and, because it never touches an `Offer`, planning copies nothing.

3. **Broadcasts.** Emit a broadcast for every genuine change and every mirror
   target. (A mirrored partner still reaches the mesh, matching today; the caller
   filters by `may_send`, the content filters, and the mesh-current dedup, so a
   non-synced or already-current selection produces no actual send.) Broadcast
   carries the **pre-synthesis** raw, consistent with the current broadcast path
   (synthesis is a capture-side affordance applied to what is *written locally for
   paste*, and `broadcast_selection` already synthesizes inside `filter` where
   applicable). Ordering is `reads` order, then mirror targets, for determinism.

4. **Writes.** For each selection with a final content:
   - if `own` → `Provenance::Own` (unconditional write of the owned/synth form);
   - else if it is a mirror target → `Provenance::Mirror` (reconciled write);
   - else (a genuine change with neither ownership nor an outbound mirror) → **no
     write** (nothing to write locally; it is only broadcast).

`plan_batch` does no sensitivity or size handling — those stay in execute
(sensitivity already gates both the broadcast `filter` and ownership; the size
cap is applied to owned content as today).

### Phase 3 — Execute

The caller turns the plan into I/O:

```text
for (kind, raw) in plan.broadcasts:
    broadcast_selection(kind, raw)          // unchanged: may_send → filter → dedup vs current → tick → send

for (kind, content, prov) in plan.writes:
    // sensitivity: never re-offer / mirror a password-manager secret
    if excludes_sensitive(content): continue
    let final = match prov:
        Own    => cap_to_payload_size(if synth { synthesize_text_plain(content) } else { content })
        Mirror => content                    // bridge bypasses MIME/size filters by design
    if final.is_empty(): continue
    if prov == Mirror:
        // Own writes are unconditional (ownership transfer) and skip this.
        // Mirror reconciles against the partner's ACTUAL content (handles
        // out-of-band drift; the partner may be unwatched): reuse the batch's
        // read if the partner fired this batch, else read it once here.
        partner_now = read.get(kind) or read_selection(kind)
        if content_hash(partner_now) == content_hash(final): continue
    // record BEFORE the write so the watch echo it produces is dropped next batch
    last_written.lock().insert(kind, content_hash(final))
    if write_offer(kind, final).await.is_err():
        last_written.lock().remove(kind)     // no echo will arrive; don't suppress a later copy
```

`Own` writes are unconditional (ownership transfer); `Mirror` writes reconcile.
When both ownership and an outbound mirror target the same selection, the plan
emits a single `Own` write of the owned content — the mirror+own merge — instead
of today's two writes.

### Worked examples

- **Copy-on-select (the reported log), `own`+`clip→sel`+`sync_sel`:** batch
  `[Clipboard, Selection]`, both genuine, equal content `Y`. No mirror (Selection
  is a genuine change → direct-change-wins skip). Plan: broadcast Clipboard,
  broadcast Selection; writes `Own(Clipboard)`, `Own(Selection)`. **2 writes, 2
  echoes** (dropped next batch). Same floor as today, no cascade.
- **Ctrl+C into a stale selection, same config:** batch `[Clipboard]`, genuine
  `Y`; Selection holds older `Z`. Mirror Clipboard→Selection (Selection not in
  reads). Plan: broadcast Clipboard, broadcast Selection (the mirror target);
  writes `Own(Clipboard)`, `Own(Selection)` (owned form). **2 writes, 2 echoes.**
  Today this path is **3 writes** (mirror Selection, own Clipboard, then the
  mirror echo broadcasts + owns Selection again) — this design removes the third.
- **Clobber case (`clip→sel`, no own):** user copies `X` to CLIPBOARD then selects
  `Y`; both in one window. `reads = {Clipboard: X, Selection: Y}`. Selection is a
  genuine change, so Clipboard→Selection mirror is skipped: Selection keeps `Y`.
  Both broadcast. **0 local writes**, Selection not clobbered.

## Error handling

- A failed/timed-out read of a fired selection skips that selection (already
  warned in `read_selection`); the batch proceeds with the rest.
- A failed `write_offer` removes the just-recorded `last_written` entry (so no
  phantom echo suppression) and warns, exactly as the current ownership path.
- A failed reconcile read for a `Mirror` write falls back to writing
  best-effort (an extra write is harmless and self-terminating), preserving the
  current `bridge_from` behavior.

## Testing

Two layers. **Pure plan tests** (new, fast, no engine) call `plan_batch` directly
and assert the `BatchPlan`:

- copy-on-select → two `Own` writes, no mirror, two broadcasts;
- Ctrl+C-stale → one mirror target, `Own` writes merged (no separate mirror
  write), partner broadcast present;
- clobber → mirror skipped when partner is a concurrent genuine change;
- one-direction vs both-direction `link_selections`;
- `own` off → mirror-only `Mirror` write; `own` on → `Own` supersedes;
- empty/no-sink selections produce no write;
- across every `link`/`own`/`changed` combination: no target is written twice,
  and no action sources content from a selection that did not change.

**Engine tests** (existing, must stay green — they guard the observable
behavior): `take_ownership_with_link_selections_terminates`, the
paste-after-select / clobber test, echo-suppression, prime/restore non-broadcast,
inbound-apply-not-rebridged, sensitive-never-owned/mirrored. Add one engine test
asserting a Ctrl+C-stale copy issues a single write per selection (no
mirror-then-own double write) via the mock clipboard's write log.

CI gates (`cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo test`) apply as usual. Tests use the mock clipboard (headless); the
Wayland path is verified manually.

## File-by-file changes

- **`src/sync.rs`:**
  - Replace the `self_written` + `mirrored` fields with `last_written`; update
    `prime`, `apply_inbound_clip`, ownership, and mirror writes to record it.
  - Add `handle_batch`, `BatchPlan`, `Provenance`, and the pure `plan_batch`;
    fold `process_local_change`, `bridge_from`, and `take_ownership_of` into the
    read/plan/execute phases (the reusable helpers — `broadcast_selection`,
    `excludes_sensitive`, `synthesize_text_plain`, `cap_to_payload_size`,
    `read_selection`, `has_local_sink`, `bridge_partner` — stay).
  - Point all three batch-drain sites in `run()` at `handle_batch`.
- **`docs/superpowers/specs/2026-06-14-local-selection-bridge-design.md`:** add a
  short "superseded" note pointing here for the propagation mechanics (the bridge
  *semantics* are unchanged; only how writes/broadcasts are scheduled changes).
- **No** `protocol.rs` / wire / `PROTOCOL_VERSION` change: this is engine-internal.
