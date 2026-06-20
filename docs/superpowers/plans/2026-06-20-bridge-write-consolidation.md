# Batch-Deferred Local Propagation (Write/Echo Consolidation) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the echo-driven, per-kind local-propagation path in the sync engine with a deterministic read → plan → execute batch pipeline that writes each selection at most once and drops its watch echo instead of re-driving propagation.

**Architecture:** A new pure `plan_batch` decides every broadcast and write (with `Own`/`Mirror` provenance) from the batch's genuine local changes; a new `handle_batch` reads each fired selection once, calls `plan_batch`, then executes the I/O. The two echo memos (`self_written`, `mirrored`) collapse into one `last_written`. All changes are inside `src/sync.rs`; no wire/protocol change.

**Tech Stack:** Rust (MSRV 1.80), tokio, `indexmap` (`Offer = IndexMap<String, Vec<u8>>`), the mock clipboard for tests.

**Design spec:** `docs/superpowers/specs/2026-06-20-bridge-write-consolidation-design.md` (read it first).

## Global Constraints

- **No observable behavior change** except a *reduction in redundant writes*: same broadcasts, same final selection contents, same `link_selections` / `take_ownership` / `sync_selection` / `direction` / sensitivity / size-cap semantics. The only sanctioned change to existing tests is **lowering `write_count` assertions** (and their explanatory comments) where the mirror+own merge removes a redundant write. Any assertion about selection *contents* or *broadcasts* must keep passing unchanged — if one fails, that is a regression to fix in code, not a test to relax.
- **No wire/protocol change:** `protocol::PROTOCOL_VERSION` stays at its current value; `Message` is untouched.
- **CI gates (all must pass):** `cargo fmt --check`; `cargo clippy --all-targets -- -D warnings`; `cargo test`. Tests run headless on the mock clipboard.
- **Direct-change-wins (clobber fix) and termination invariants must hold** — they are now expressed structurally in `plan_batch` (skip the mirror when the partner is a concurrent genuine change) and by dropping echoes in Phase 1.
- Commit as `Thomas Matthijs <selckin@selckin.be>` (repo-local config already set). Work directly on `main`.

## File Structure

- **`src/sync.rs`** — the only code file. Add `Provenance`, `BatchPlan`, free `link_partner`, pure `plan_batch`, async `handle_batch`, async `execute_write`. Replace fields `self_written` + `mirrored` with `last_written`. Delete `process_local_change`, `bridge_from`, `take_ownership_of` (their logic moves into `handle_batch`/`execute_write`). Route `bridge_partner` through `link_partner`. Point the three batch-drain sites in `run()` at `handle_batch`. Add pure `plan_batch` unit tests and one engine regression test; reconcile existing bridge/ownership tests' write-count assertions.
- **`docs/superpowers/specs/2026-06-14-local-selection-bridge-design.md`** — add a short superseded-pointer note (Task 2).

---

### Task 1: Batch-deferred propagation core

This is one atomic task: the mechanism change breaks existing engine tests' write counts, so the same task must reconcile them. Work in small TDD steps, but the task is complete only when the **entire** suite is green.

**Files:**
- Modify: `src/sync.rs`

**Interfaces:**
- Consumes (existing, unchanged): `Offer` (= `IndexMap<String, Vec<u8>>`), `SelectionKind { Clipboard, Selection }`, `LinkSelections` (`clip_to_selection()`, `selection_to_clip()`, consts `OFF`/`CLIPBOARD_TO_SELECTION`/`SELECTION_TO_CLIPBOARD`/`BOTH`), `content_hash(&Offer) -> [u8; 32]`, `synthesize_text_plain(Offer) -> Offer`, `cap_to_payload_size(Offer, usize) -> Offer`, `describe_offer(&Offer) -> String`, and `SyncEngine` methods `read_selection`, `has_local_sink`, `bridge_partner`, `excludes_sensitive`, `broadcast_selection`, `may_send`.
- Produces: `fn plan_batch(&IndexMap<SelectionKind, Offer>, LinkSelections, bool) -> BatchPlan`; `enum Provenance { Own, Mirror }`; `struct BatchPlan { broadcasts: Vec<(SelectionKind, Offer)>, writes: Vec<(SelectionKind, Offer, Provenance)> }`; `async fn SyncEngine::handle_batch(&self, Vec<SelectionKind>)`.

- [ ] **Step 1: Write the failing `plan_batch` unit tests**

Add to the `#[cfg(test)] mod tests` in `src/sync.rs` (the `offer(text)` helper already exists there). These reference `plan_batch`, `BatchPlan`, `Provenance`, which don't exist yet.

```rust
// ---- plan_batch (pure) ----
// `IndexMap` resolves via `use super::*` once Step 3 adds the module-level
// import; do NOT add a `use indexmap::IndexMap;` here (it would become a
// redundant import and fail clippy -D warnings).

fn reads_of(pairs: &[(SelectionKind, &str)]) -> IndexMap<SelectionKind, Offer> {
    pairs.iter().map(|(k, t)| (*k, offer(t))).collect()
}

#[test]
fn plan_copy_on_select_owns_both_with_no_mirror() {
    // Both selections genuinely changed to the same content: no mirror (direct
    // change wins on the partner), two unconditional ownership writes.
    let reads = reads_of(&[
        (SelectionKind::Clipboard, "Y"),
        (SelectionKind::Selection, "Y"),
    ]);
    let plan = plan_batch(&reads, LinkSelections::CLIPBOARD_TO_SELECTION, true);
    assert_eq!(
        plan.writes,
        vec![
            (SelectionKind::Clipboard, offer("Y"), Provenance::Own),
            (SelectionKind::Selection, offer("Y"), Provenance::Own),
        ]
    );
    assert_eq!(plan.broadcasts.len(), 2);
}

#[test]
fn plan_ctrl_c_stale_merges_mirror_into_one_owned_write() {
    // Only CLIPBOARD changed; SELECTION is a mirror target. With ownership on it
    // becomes a single Own write of SELECTION — not a mirror write plus a later
    // ownership write. SELECTION is still broadcast (mirror target).
    let reads = reads_of(&[(SelectionKind::Clipboard, "Y")]);
    let plan = plan_batch(&reads, LinkSelections::CLIPBOARD_TO_SELECTION, true);
    assert_eq!(
        plan.writes,
        vec![
            (SelectionKind::Clipboard, offer("Y"), Provenance::Own),
            (SelectionKind::Selection, offer("Y"), Provenance::Own),
        ]
    );
    let kinds: Vec<_> = plan.broadcasts.iter().map(|(k, _)| *k).collect();
    assert_eq!(kinds, vec![SelectionKind::Clipboard, SelectionKind::Selection]);
}

#[test]
fn plan_clobber_skips_mirror_when_partner_is_a_concurrent_change() {
    // CLIPBOARD=X and SELECTION=Y both genuine in one batch: CLIPBOARD->SELECTION
    // mirror is skipped so SELECTION keeps Y. Ownership off => no writes at all.
    let reads = reads_of(&[
        (SelectionKind::Clipboard, "X"),
        (SelectionKind::Selection, "Y"),
    ]);
    let plan = plan_batch(&reads, LinkSelections::CLIPBOARD_TO_SELECTION, false);
    assert!(plan.writes.is_empty());
    assert_eq!(plan.broadcasts.len(), 2);
}

#[test]
fn plan_mirror_only_when_ownership_off() {
    // CLIPBOARD changed, ownership off: SELECTION mirror target gets a reconciled
    // Mirror write; CLIPBOARD itself is broadcast only (the user put it there).
    let reads = reads_of(&[(SelectionKind::Clipboard, "Y")]);
    let plan = plan_batch(&reads, LinkSelections::CLIPBOARD_TO_SELECTION, false);
    assert_eq!(
        plan.writes,
        vec![(SelectionKind::Selection, offer("Y"), Provenance::Mirror)]
    );
}

#[test]
fn plan_no_link_broadcasts_without_writing() {
    let reads = reads_of(&[(SelectionKind::Clipboard, "Y")]);
    let plan = plan_batch(&reads, LinkSelections::OFF, false);
    assert!(plan.writes.is_empty());
    assert_eq!(plan.broadcasts, vec![(SelectionKind::Clipboard, offer("Y"))]);
}

#[test]
fn plan_selection_to_clipboard_mirrors_the_other_way() {
    let reads = reads_of(&[(SelectionKind::Selection, "Y")]);
    let plan = plan_batch(&reads, LinkSelections::SELECTION_TO_CLIPBOARD, false);
    assert_eq!(
        plan.writes,
        vec![(SelectionKind::Clipboard, offer("Y"), Provenance::Mirror)]
    );
}
```

- [ ] **Step 2: Run the unit tests to verify they fail**

Run: `cargo test --lib sync::tests::plan_`
Expected: compile error — `cannot find function plan_batch` / `cannot find type BatchPlan` / `Provenance`.

- [ ] **Step 3: Add `Provenance`, `BatchPlan`, `link_partner`, and `plan_batch`**

Place these near the other engine free functions in `src/sync.rs` (e.g. just above `impl SyncEngine`). Derive `PartialEq`/`Eq` on `Provenance` so the tuple asserts in Step 1 compile. **Add `use indexmap::IndexMap;` at module level** — `sync.rs` does not currently import it (it only uses the `Offer` type alias), and `plan_batch`/`handle_batch` reference the bare `IndexMap` name. The test module picks it up via its existing `use super::*`.

```rust
/// Why the engine writes a selection during a batch — selects the reconcile
/// rule in `execute_write`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provenance {
    /// `take_ownership` re-offer: write unconditionally (ownership transfer),
    /// even when the selection already holds these bytes.
    Own,
    /// Local-bridge mirror with `take_ownership` off: write only when the
    /// partner does not already hold this content (reconcile against drift).
    Mirror,
}

/// The broadcasts and writes a debounce batch produces, computed up front so
/// propagation never rides watch echoes. Each selection is written at most once.
struct BatchPlan {
    broadcasts: Vec<(SelectionKind, Offer)>,
    writes: Vec<(SelectionKind, Offer, Provenance)>,
}

/// The selection a configured link direction mirrors `kind` INTO, or `None`.
/// Free-function twin of `SyncEngine::bridge_partner`, so the pure planner needs
/// no `&self`.
fn link_partner(kind: SelectionKind, link: LinkSelections) -> Option<SelectionKind> {
    match kind {
        SelectionKind::Clipboard if link.clip_to_selection() => Some(SelectionKind::Selection),
        SelectionKind::Selection if link.selection_to_clip() => Some(SelectionKind::Clipboard),
        _ => None,
    }
}

/// Decide a batch's broadcasts and writes from its genuine local changes. Pure:
/// no I/O and no content transforms (the `Own` synth+cap and the `Mirror`
/// reconcile happen in `execute_write`). `reads` is every genuine user change
/// this batch (echoes already removed), in batch order.
fn plan_batch(
    reads: &IndexMap<SelectionKind, Offer>,
    link: LinkSelections,
    own: bool,
) -> BatchPlan {
    // Mirror targets: a selection some genuine change mirrors INTO that is not
    // itself a genuine change (direct-change-wins — never clobber a concurrent
    // user change). The two selections never share a partner (the mapping is a
    // bijection), so each target has a single source.
    let mut mirror_targets: IndexMap<SelectionKind, Offer> = IndexMap::new();
    for (&kind, raw) in reads {
        if let Some(partner) = link_partner(kind, link) {
            if !reads.contains_key(&partner) {
                mirror_targets.insert(partner, raw.clone());
            }
        }
    }

    // Broadcasts: every genuine change, then every mirror target (so a mirrored
    // partner still reaches the mesh, as today). The caller applies may_send +
    // content filters + mesh-current dedup, so a non-synced or unchanged
    // selection yields no actual send.
    let mut broadcasts = Vec::new();
    for (&kind, raw) in reads {
        broadcasts.push((kind, raw.clone()));
    }
    for (&kind, raw) in &mirror_targets {
        broadcasts.push((kind, raw.clone()));
    }

    // Writes, each selection at most once:
    //  - own on  -> Own (unconditional) for every genuine change AND every mirror
    //    target (the mirror+own merge: one owned write, no separate mirror write).
    //  - own off -> Mirror (reconciled) for mirror targets only; genuine changes
    //    are broadcast but not written locally.
    let mut writes = Vec::new();
    if own {
        for (&kind, raw) in reads {
            writes.push((kind, raw.clone(), Provenance::Own));
        }
        for (&kind, raw) in &mirror_targets {
            writes.push((kind, raw.clone(), Provenance::Own));
        }
    } else {
        for (&kind, raw) in &mirror_targets {
            writes.push((kind, raw.clone(), Provenance::Mirror));
        }
    }

    BatchPlan { broadcasts, writes }
}
```

- [ ] **Step 4: Run the unit tests to verify they pass**

Run: `cargo test --lib sync::tests::plan_`
Expected: all six `plan_*` tests PASS.

- [ ] **Step 5: Replace the two echo memos with `last_written`**

In the `SyncEngine` struct, delete the `self_written` and `mirrored` fields and add:

```rust
/// Raw-content hash of the last value the engine itself wrote to each
/// selection (an ownership re-offer, a local-bridge mirror, an inbound mesh
/// apply, or the startup-restored baseline). The watcher re-reports every
/// write; an incoming change whose hash matches is that echo and is dropped —
/// never broadcast, mirrored, or re-owned. One-shot: removed when any change
/// to that selection is classified, so a stale marker can never suppress a
/// later genuine copy of identical bytes.
last_written: Mutex<HashMap<SelectionKind, [u8; 32]>>,
```

Update the constructor (`SyncEngine::new`) to initialise `last_written: Mutex::new(HashMap::new())` and drop the two old initialisers. Update the recorders:
- `prime`: change `self.self_written...entry(kind).or_insert(raw_hash)` → `self.last_written...entry(kind).or_insert(raw_hash)` (keep `or_insert`).
- `apply_inbound_clip`: change `self.self_written.lock().unwrap().insert(kind, applied_hash)` → `self.last_written...insert(kind, applied_hash)`.

This step will not fully compile until Step 6 deletes the old functions that reference `self_written`/`mirrored`; that is expected.

- [ ] **Step 6: Add `handle_batch` + `execute_write`; delete the per-kind path**

Delete `process_local_change`, `bridge_from`, and `take_ownership_of`. Route `bridge_partner` through the new free function to avoid duplicating the mapping:

```rust
fn bridge_partner(&self, kind: SelectionKind) -> Option<SelectionKind> {
    link_partner(kind, self.cfg.link_selections)
}
```

Add the batch handler and the write executor:

```rust
/// Drain one debounce batch: read each fired selection once, plan every
/// broadcast and write up front, then execute — writing each selection at most
/// once and recording it in `last_written` so its watch echo is dropped next
/// batch rather than re-driving propagation.
async fn handle_batch(&self, batch: Vec<SelectionKind>) {
    // Phase 1: read & classify. `read_cache` holds every read (incl. echoes) so
    // a Mirror reconcile can reuse a partner that fired this batch.
    let mut reads: IndexMap<SelectionKind, Offer> = IndexMap::new();
    let mut read_cache: HashMap<SelectionKind, Offer> = HashMap::new();
    for kind in batch {
        if !self.has_local_sink(kind) {
            if self.cfg.verbose {
                info!("copied {kind:?}: not sent (this node does not send)");
            }
            continue;
        }
        let Some(raw) = self.read_selection(kind).await else {
            continue;
        };
        // One-shot consume the echo memo; hash only when a marker exists (the
        // common genuine-copy path does no hashing here).
        let is_echo = match self.last_written.lock().unwrap().remove(&kind) {
            Some(h) => h == content_hash(&raw),
            None => false,
        };
        read_cache.insert(kind, raw.clone());
        if is_echo {
            continue; // our own write echoing back — drop, no propagation
        }
        reads.insert(kind, raw);
    }
    if reads.is_empty() {
        return;
    }

    // Phase 2: plan (pure).
    let plan = plan_batch(&reads, self.cfg.link_selections, self.cfg.take_ownership);

    // Phase 3: execute.
    for (kind, raw) in plan.broadcasts {
        self.broadcast_selection(kind, raw).await;
    }
    for (kind, content, prov) in plan.writes {
        self.execute_write(kind, content, prov, &read_cache).await;
    }
}

/// Execute one planned write: apply the `Own` transform (synthesis + size cap)
/// or the `Mirror` reconcile, record `last_written` before writing so the echo
/// is dropped, and undo the record on write failure.
async fn execute_write(
    &self,
    kind: SelectionKind,
    content: Offer,
    prov: Provenance,
    read_cache: &HashMap<SelectionKind, Offer>,
) {
    // Never re-offer or mirror a password-manager secret.
    if self.excludes_sensitive(&content) {
        if prov == Provenance::Own {
            debug!("not taking ownership of {kind:?}: flagged sensitive");
        }
        return;
    }
    let final_offer = match prov {
        Provenance::Own => {
            let owned = if self.cfg.synthesize_text_plain {
                synthesize_text_plain(content)
            } else {
                content
            };
            // Cap so the owned offer round-trips the read-back budget (see the
            // original take_ownership_of note): an over-budget rewrite would be
            // re-read smaller, miss its marker, and churn.
            cap_to_payload_size(owned, self.cfg.max_payload_size)
        }
        // The bridge intentionally bypasses the MIME/size filters so locally
        // denied or oversized reps still reach the partner.
        Provenance::Mirror => content,
    };
    if final_offer.is_empty() {
        return;
    }
    if prov == Provenance::Mirror {
        // Reconcile against the partner's ACTUAL content (handles out-of-band
        // drift; the partner may be unwatched). Reuse a read from this batch if
        // the partner fired, else read once. A failed read falls through to a
        // best-effort, self-terminating mirror (matching the old bridge_from).
        let partner_now = match read_cache.get(&kind) {
            Some(o) => Some(o.clone()),
            None => self.read_selection(kind).await,
        };
        if let Some(now) = partner_now {
            if content_hash(&now) == content_hash(&final_offer) {
                return;
            }
        }
    }
    let h = content_hash(&final_offer);
    let copied = self.cfg.verbose.then(|| describe_offer(&final_offer));
    // Record BEFORE the write so the watch echo it produces is recognised.
    self.last_written.lock().unwrap().insert(kind, h);
    match self.clipboard.write_offer(kind, final_offer).await {
        Ok(()) => {
            if let (Provenance::Mirror, Some(copied)) = (prov, copied) {
                info!("mirrored into {kind:?} [{copied}]");
            }
        }
        Err(e) => {
            warn!("couldn't write the {kind:?} selection: {e:#}");
            // No echo will arrive; drop the marker so a later genuine copy of
            // identical bytes isn't wrongly suppressed.
            self.last_written.lock().unwrap().remove(&kind);
        }
    }
}
```

- [ ] **Step 7: Point `run()`'s three batch-drain sites at `handle_batch`**

In `run()`, replace each of the three occurrences of
```rust
let batch = std::mem::take(&mut pending);
for &k in &batch {
    self.process_local_change(k, &batch).await;
}
```
(the post-prime flush, the watch-immediate path, and the deadline arm) with:
```rust
self.handle_batch(std::mem::take(&mut pending)).await;
```

- [ ] **Step 8: Compile and run the full library suite**

Run: `cargo test --lib`
Expected: it compiles. The `plan_*` unit tests pass. Some bridge/ownership tests may now FAIL on `write_count` assertions (the consolidation removed redundant writes) — that is Step 9. Record the failing test names from the output.

- [ ] **Step 9: Reconcile existing engine tests (write counts only)**

For each test failing from Step 8, apply this rule:
- If the failure is a **`write_count` assertion** and the test's **content/broadcast assertions still pass**, the consolidation legitimately reduced the write count: update the expected number and rewrite the explanatory comment to describe the new single-write-per-selection behavior. **Known sanctioned change:** `take_ownership_with_link_selections_terminates` — change `write_count() == 3` to `== 2` and update the comment to: the CLIPBOARD ownership write and the SELECTION write are now one owned write each (the bridge mirror and the SELECTION ownership rewrite are merged), with no intermediate raw mirror write.
- If the failure is about **selection contents or broadcasts**, it is a **regression** — fix `handle_batch`/`execute_write`/`plan_batch`, do not relax the test.

Re-run `cargo test --lib` until green. Specifically confirm these still pass unchanged (they assert behavior, not counts): `clip_to_selection_does_not_clobber_a_concurrent_selection`, `same_window_conflict_keeps_each_direct_change`, `clip_to_selection_still_mirrors_a_new_copy_after_its_own_echo`, `recopy_remirrors_after_partner_drifts_out_of_band`, `recopy_remirrors_after_clipboard_drifts_out_of_band`, `no_redundant_mirror_when_partner_already_matches`, `sensitive_content_is_not_bridged`, `inbound_clip_is_not_re_bridged_or_re_broadcast`, `inbound_clip_is_not_re_bridged_in_both_mode`, `priming_does_not_spontaneously_bridge_restored_content`, `priming_does_not_spontaneously_bridge_restored_selection`, `mirrored_selection_is_fed_to_the_mesh_when_synced`, `bridge_runs_locally_under_receive_only_without_broadcasting`, `link_off_never_mirrors`, `take_ownership_rewrites_the_local_selection_once`, `take_ownership_caps_the_rewrite_to_max_payload_size`, `take_ownership_drops_its_marker_when_the_write_fails`, `take_ownership_never_persists_a_sensitive_secret`, `take_ownership_off_does_not_rewrite`.

- [ ] **Step 10: Add the regression test for the mirror+own merge**

Add an engine test proving the Ctrl+C-into-a-stale-selection path issues exactly one write per selection (no raw-mirror-then-own double write). Model it on `take_ownership_with_link_selections_terminates` (helpers `start`, `recv_clip`, `wait_applied`, `assert_no_broadcast`, `wait_for_write_count` already exist).

```rust
#[tokio::test]
async fn ctrl_c_into_stale_selection_writes_each_selection_once() {
    // CLIPBOARD copy with clipboard_to_selection + take_ownership, while the
    // SELECTION still holds older content. The SELECTION must end owning the new
    // content, but via a SINGLE owned write — not a raw mirror write followed by
    // an ownership rewrite. Two writes total (own CLIPBOARD, own SELECTION).
    let mut cfg = Config::for_test("s");
    cfg.take_ownership = true;
    cfg.link_selections = LinkSelections::CLIPBOARD_TO_SELECTION;
    let mut h = start_seeded_with(
        cfg,
        &[(SelectionKind::Selection, offer("old"))],
    )
    .await;
    h.clip.local_copy(SelectionKind::Clipboard, offer("new"));
    let (kind, _, o) = recv_clip(&mut h).await;
    assert_eq!((kind, o), (SelectionKind::Clipboard, offer("new")));
    wait_applied(&h, SelectionKind::Selection, &offer("new")).await;
    assert_no_broadcast(&mut h).await;
    assert_eq!(h.clip.get(SelectionKind::Clipboard), Some(offer("new")));
    assert_eq!(
        h.clip.write_count(),
        2,
        "one owned write per selection — mirror and ownership merged"
    );
}
```

If `start_seeded_with`'s priming records a `last_written` baseline for the seeded SELECTION that interferes, confirm the test still observes the final `offer("new")` and a write count of 2; adjust only the seeding (not the production code) if priming changes the observed count, and note any such adjustment in the report.

- [ ] **Step 11: Run the regression test, then the whole suite + lints**

Run: `cargo test --lib sync::tests::ctrl_c_into_stale_selection_writes_each_selection_once`
Expected: PASS.

Run: `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: all green (236+ lib tests, the two_nodes integration test, clippy clean, fmt clean).

- [ ] **Step 12: Commit**

```bash
git add src/sync.rs
git commit -m "refactor(sync): batch-deferred local propagation, write/echo consolidation"
```

---

### Task 2: Cross-reference the superseded propagation mechanics

**Files:**
- Modify: `docs/superpowers/specs/2026-06-14-local-selection-bridge-design.md`

- [ ] **Step 1: Add the superseded-pointer note**

Near the top of the 2026-06-14 spec (under its status/summary), add a short note: the bridge *semantics* (what mirrors where, direct-change-wins, sensitivity, termination) are unchanged, but the *mechanics* of how mirror/ownership writes and broadcasts are scheduled are superseded by `docs/superpowers/specs/2026-06-20-bridge-write-consolidation-design.md` (read → plan → execute; one write per selection per batch; the `self_written`/`mirrored` memos unified into `last_written`). Match the surrounding markdown style.

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/specs/2026-06-14-local-selection-bridge-design.md
git commit -m "docs: note the bridge propagation mechanics superseded by write consolidation"
```
