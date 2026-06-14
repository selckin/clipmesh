# Local clipboard↔primary selection bridge — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a local, per-direction bridge that mirrors the CLIPBOARD selection into the PRIMARY (middle-click) selection and/or vice versa on a single host, distinct from the existing cross-host mesh sync.

**Architecture:** A new `bridge_from(kind)` step runs after `broadcast_selection(kind)` on every drained clipboard-watch change (via a `process(kind)` helper wired into `run()`'s three drain sites). It writes the partner selection the raw offer (honoring `exclude_sensitive` only), and the partner's resulting watch event flows through the existing broadcast path ("feed the mesh"). A dedicated `last_mirrored` raw-hash map makes the echo loop-safe; PRIMARY watching is decoupled from `sync_primary`; priming seeds `last_mirrored` so a restart never spontaneously bridges.

**Tech Stack:** Rust, tokio, the existing clipmesh `SyncEngine`/`Clipboard`/`Config` modules. Tests run on `MockClipboard` (headless); the real Wayland path is verified manually as elsewhere in this repo.

**Spec:** `docs/superpowers/specs/2026-06-14-local-selection-bridge-design.md`

---

## File Structure

- `src/config.rs` — new `LinkSelections` enum + `link_selections` field (RawConfig, Config, `from_toml`, `for_test`) and its parse/helper tests.
- `src/clipboard/watch.rs` — rename `sync_primary` → `watch_primary` (the watcher now subscribes to PRIMARY for either mesh-sync *or* the bridge).
- `src/clipboard/wayland.rs` — same rename in `WaylandClipboard` (field + `new` param).
- `src/clipboard/mock.rs` — add `set_fail_reads` (mirror of the existing `set_fail_writes`) to test the bridge's read-failure path.
- `src/main.rs` — compute `watch_primary = cfg.sync_primary || cfg.link_selections.primary_to_clip()`.
- `src/sync.rs` — the bridge: `last_mirrored` field, `watched_kinds()`, `bridge_from()`, `process()`, run-loop wiring, prime seeding, and all bridge tests.
- `examples/config.toml`, `README.md`, `CLAUDE.md` — documentation.

Each task is self-contained and leaves the crate compiling and the suite green.

---

## Task 1: Config — `LinkSelections` setting

**Files:**
- Modify: `src/config.rs` (enum near `Direction`/`MimePolicy`; `RawConfig`; `Config`; `from_toml`; `for_test`)
- Test: `src/config.rs` (the existing `#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the failing tests**

Add to the `mod tests` block in `src/config.rs` (after `applies_defaults`):

```rust
    #[test]
    fn link_selections_defaults_off_and_parses_all_values() {
        let cfg = Config::from_toml("listen = \"x\"\npsk = \"s\"\n").unwrap();
        assert_eq!(cfg.link_selections, LinkSelections::Off);
        for (word, expected) in [
            ("off", LinkSelections::Off),
            ("clipboard_to_primary", LinkSelections::ClipboardToPrimary),
            ("primary_to_clipboard", LinkSelections::PrimaryToClipboard),
            ("both", LinkSelections::Both),
        ] {
            let toml = format!("listen = \"x\"\npsk = \"s\"\nlink_selections = \"{word}\"\n");
            let cfg = Config::from_toml(&toml).unwrap();
            assert_eq!(cfg.link_selections, expected, "parsing {word}");
        }
    }

    #[test]
    fn link_selections_direction_helpers() {
        assert!(!LinkSelections::Off.clip_to_primary());
        assert!(!LinkSelections::Off.primary_to_clip());
        assert!(LinkSelections::ClipboardToPrimary.clip_to_primary());
        assert!(!LinkSelections::ClipboardToPrimary.primary_to_clip());
        assert!(!LinkSelections::PrimaryToClipboard.clip_to_primary());
        assert!(LinkSelections::PrimaryToClipboard.primary_to_clip());
        assert!(LinkSelections::Both.clip_to_primary());
        assert!(LinkSelections::Both.primary_to_clip());
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib config::tests::link_selections_defaults_off_and_parses_all_values`
Expected: FAIL — compile error, `cannot find type/value LinkSelections`.

- [ ] **Step 3: Add the enum**

In `src/config.rs`, after the `MimePolicy` enum (around line 20):

```rust
/// Whether to mirror one local selection into the other on this host. A
/// purely *local* coupling, distinct from the cross-host `sync_primary`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkSelections {
    /// No local mirroring (default).
    #[default]
    Off,
    /// Mirror CLIPBOARD changes into PRIMARY.
    ClipboardToPrimary,
    /// Mirror PRIMARY changes into CLIPBOARD.
    PrimaryToClipboard,
    /// Both directions.
    Both,
}

impl LinkSelections {
    /// True when CLIPBOARD changes should be mirrored into PRIMARY.
    pub fn clip_to_primary(self) -> bool {
        matches!(self, Self::ClipboardToPrimary | Self::Both)
    }
    /// True when PRIMARY changes should be mirrored into CLIPBOARD.
    pub fn primary_to_clip(self) -> bool {
        matches!(self, Self::PrimaryToClipboard | Self::Both)
    }
}
```

- [ ] **Step 4: Add the field in all four places**

In `RawConfig`, immediately after the `sync_primary` field:

```rust
    #[serde(default)]
    link_selections: LinkSelections,
```

In `Config` (the resolved struct), immediately after `pub sync_primary: bool,`:

```rust
    /// Local clipboard↔primary mirroring (distinct from `sync_primary`).
    pub link_selections: LinkSelections,
```

In `from_toml`'s `Ok(Config { ... })`, immediately after `sync_primary: raw.sync_primary,`:

```rust
            link_selections: raw.link_selections,
```

In `Config::for_test`'s struct literal, immediately after `sync_primary: false,`:

```rust
            link_selections: LinkSelections::Off,
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --lib config::tests::link_selections_defaults_off_and_parses_all_values config::tests::link_selections_direction_helpers`
Expected: PASS (both).

- [ ] **Step 6: Verify gates and commit**

```bash
cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check
git add src/config.rs
git commit -m "feat: add link_selections config for the local selection bridge"
```

---

## Task 2: Decouple PRIMARY watching from `sync_primary`

This is a rename (`sync_primary` → `watch_primary`) in the watcher plus one logic change in `main.rs`. With `link_selections` defaulting to `Off`, `watch_primary == sync_primary`, so existing behavior is unchanged — the existing suite is the regression test. (The new real-backend behavior, watching PRIMARY for `primary_to_clipboard`, is only observable against a live compositor and is verified manually, like the rest of the Wayland path.)

**Files:**
- Modify: `src/clipboard/watch.rs` (8 occurrences)
- Modify: `src/clipboard/wayland.rs` (4 occurrences)
- Modify: `src/main.rs:74-77`

- [ ] **Step 1: Rename in `src/clipboard/watch.rs`**

Rename every `sync_primary` to `watch_primary` (lines 34, 35, 41, 50, 79, 121, 158, 165). Final forms:

```rust
pub fn spawn_watcher(tx: mpsc::UnboundedSender<SelectionKind>, watch_primary: bool) {
    thread::spawn(move || run(tx, watch_primary));
```
```rust
fn run(tx: mpsc::UnboundedSender<SelectionKind>, watch_primary: bool) {
```
```rust
        match watch_once(&tx, watch_primary) {
```
```rust
fn watch_once(tx: &mpsc::UnboundedSender<SelectionKind>, watch_primary: bool) -> Result<StopReason> {
```

In the `SelectionState` construction (line ~121), the field init becomes `watch_primary,`; the struct field (line ~158) becomes `watch_primary: bool,`; and the gate (line ~165) becomes:

```rust
        if kind == SelectionKind::Primary && !self.watch_primary {
```

- [ ] **Step 2: Rename in `src/clipboard/wayland.rs`**

```rust
pub struct WaylandClipboard {
    watch_primary: bool,
    max_payload: usize,
}

impl WaylandClipboard {
    pub fn new(watch_primary: bool, max_payload: usize) -> WaylandClipboard {
        WaylandClipboard {
            watch_primary,
            max_payload,
        }
    }
}
```

And in the `Clipboard for WaylandClipboard` impl's `watch` (line ~183):

```rust
        spawn_watcher(tx, self.watch_primary);
```

- [ ] **Step 3: Compute `watch_primary` in `src/main.rs`**

Replace the `WaylandClipboard::new(...)` call (lines 74-77):

```rust
    let clipboard = Arc::new(WaylandClipboard::new(
        cfg.sync_primary || cfg.link_selections.primary_to_clip(),
        cfg.max_payload_size,
    ));
```

- [ ] **Step 4: Verify the rename did not change behavior**

Run: `cargo build && cargo test`
Expected: builds; all existing tests PASS (no behavior change with `link_selections = off`).

- [ ] **Step 5: Verify gates and commit**

```bash
cargo clippy --all-targets -- -D warnings && cargo fmt --check
git add src/clipboard/watch.rs src/clipboard/wayland.rs src/main.rs
git commit -m "refactor: watch PRIMARY for the bridge too (sync_primary -> watch_primary)"
```

---

## Task 3: Engine core — `bridge_from`, `process`, run-loop wiring (clipboard→primary)

**Files:**
- Modify: `src/sync.rs` (struct field; `new`; new methods; `run` drain sites; test import)
- Test: `src/sync.rs` (`mod tests`)

- [ ] **Step 1: Write the failing test**

In `src/sync.rs` `mod tests`, change the config import line (line ~813) to include `LinkSelections`:

```rust
    use crate::config::{Config, Direction, LinkSelections, MimePolicy};
```

Add the test (after `local_copy_is_broadcast`):

```rust
    #[tokio::test(start_paused = true)]
    async fn clipboard_change_mirrors_to_primary() {
        let mut cfg = Config::for_test("s");
        cfg.link_selections = LinkSelections::ClipboardToPrimary;
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("foo"));
        // the clipboard change is broadcast as usual...
        let (kind, _, o) = recv_clip(&mut h).await;
        assert_eq!((kind, o), (SelectionKind::Clipboard, offer("foo")));
        // ...and mirrored into the primary selection locally.
        wait_applied(&h, SelectionKind::Primary, &offer("foo")).await;
        // primary isn't mesh-synced here, so it is not broadcast.
        assert_no_broadcast(&mut h).await;
        assert_eq!(h.clip.write_count(), 1);
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib sync::tests::clipboard_change_mirrors_to_primary`
Expected: FAIL — the primary selection is never written (`offer was not applied`), because no bridge exists yet.

- [ ] **Step 3: Add the `last_mirrored` field**

In the `SyncEngine` struct, after `rules_changed_tx: mpsc::Sender<()>,`:

```rust
    /// Raw-content hash last mirrored to/from each selection by the local
    /// selection bridge. Separate from `current` (which holds *filtered*
    /// hashes) so the raw-vs-filtered mismatch cannot defeat the loop guard.
    last_mirrored: Mutex<HashMap<SelectionKind, [u8; 32]>>,
```

In `SyncEngine::new`'s `Arc::new(SyncEngine { ... })`, after `rules_changed_tx,`:

```rust
            last_mirrored: Mutex::new(HashMap::new()),
```

- [ ] **Step 4: Add `bridge_from` and `process`**

In the `impl<C: Clipboard> SyncEngine<C>` block, after `broadcast_selection` (around line 475):

```rust
    /// Local selection bridge: mirror `kind`'s current content into the
    /// partner selection per `link_selections`. Runs after
    /// `broadcast_selection` on every drained change. The partner's resulting
    /// watch event then feeds the mesh through the normal broadcast path.
    /// Loop-safe via `last_mirrored` (raw hashes); never holds the lock across
    /// an await.
    async fn bridge_from(&self, kind: SelectionKind) {
        let partner = match kind {
            SelectionKind::Clipboard if self.cfg.link_selections.clip_to_primary() => {
                SelectionKind::Primary
            }
            SelectionKind::Primary if self.cfg.link_selections.primary_to_clip() => {
                SelectionKind::Clipboard
            }
            _ => return,
        };
        let Some(raw) = self.read_selection(kind).await else {
            return;
        };
        let h = content_hash(&raw);
        if self.last_mirrored.lock().unwrap().get(&kind) == Some(&h) {
            return; // already mirrored this content
        }
        // Describe before `raw` is moved into write_offer; logged only on a
        // successful mirror, matching the broadcast path's verbose style.
        let copied = self.cfg.verbose.then(|| describe_offer(&raw));
        match self.clipboard.write_offer(partner, raw).await {
            Ok(()) => {
                if let Some(copied) = copied {
                    info!("mirrored {kind:?} -> {partner:?} [{copied}]");
                }
                self.last_mirrored.lock().unwrap().insert(kind, h);
            }
            Err(e) => warn!("couldn't mirror {kind:?} to {partner:?}: {e:#}"),
        }
    }

    /// Drain one pending selection change: broadcast it to the mesh, then run
    /// the local selection bridge.
    async fn process(&self, kind: SelectionKind) {
        self.broadcast_selection(kind).await;
        self.bridge_from(kind).await;
    }
```

- [ ] **Step 5: Wire `process` into the run loop**

In `run()`, find-and-replace all three occurrences of the line

```rust
self.broadcast_selection(k).await;
```

with

```rust
self.process(k).await;
```

They are the post-prime `debounce_ms == 0` branch (~line 196), the watch-arm `debounce_ms == 0` branch (~line 214), and the deadline arm (~line 230) — and the only `self.broadcast_selection(k)` calls in `run()`. (Preserve each line's existing indentation.)

- [ ] **Step 6: Run the test to verify it passes**

Run: `cargo test --lib sync::tests::clipboard_change_mirrors_to_primary`
Expected: PASS.

- [ ] **Step 7: Verify gates and commit**

```bash
cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check
git add src/sync.rs
git commit -m "feat: local clipboard->primary selection bridge"
```

---

## Task 4: `primary→clipboard` direction and single-direction isolation

These verify the PRIMARY arm of `bridge_from` (already present from Task 3) and that one direction never mirrors the other way. They should pass immediately against Task 3's code; if either fails, Task 3 is incomplete.

**Files:**
- Test: `src/sync.rs` (`mod tests`)

- [ ] **Step 1: Write the tests**

```rust
    #[tokio::test(start_paused = true)]
    async fn primary_change_mirrors_to_clipboard() {
        let mut cfg = Config::for_test("s");
        cfg.link_selections = LinkSelections::PrimaryToClipboard;
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Primary, offer("sel"));
        // primary→clipboard: the selection lands in the clipboard and (because
        // clipboard is always mesh-synced) is broadcast as a clipboard update.
        let (kind, _, o) = recv_clip(&mut h).await;
        assert_eq!((kind, o), (SelectionKind::Clipboard, offer("sel")));
        wait_applied(&h, SelectionKind::Clipboard, &offer("sel")).await;
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn single_direction_does_not_mirror_the_other_way() {
        // clipboard_to_primary must NOT mirror a primary change into clipboard.
        let mut cfg = Config::for_test("s");
        cfg.sync_primary = true; // so the primary change is at least observable
        cfg.link_selections = LinkSelections::ClipboardToPrimary;
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Primary, offer("sel"));
        let (kind, _, o) = recv_clip(&mut h).await; // primary broadcast (sync_primary)
        assert_eq!((kind, o), (SelectionKind::Primary, offer("sel")));
        assert_eq!(h.clip.write_count(), 0); // clipboard never mirrored
        assert_eq!(h.clip.get(SelectionKind::Clipboard), None);
        assert_no_broadcast(&mut h).await;
    }
```

- [ ] **Step 2: Run the tests to verify they pass**

Run: `cargo test --lib sync::tests::primary_change_mirrors_to_clipboard sync::tests::single_direction_does_not_mirror_the_other_way`
Expected: PASS (both).

- [ ] **Step 3: Verify gates and commit**

```bash
cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check
git add src/sync.rs
git commit -m "test: primary->clipboard mirror and single-direction isolation"
```

---

## Task 5: Loop guard under `both` — no redundant writes

Under `both`, Task 3 stamps only `last_mirrored[kind]`, so the partner's echo re-mirrors back once (a redundant write). This task adds partner stamping so the echo is recognized and skipped, and pins the read-back-fidelity invariant with a denied-representation case.

**Files:**
- Modify: `src/sync.rs` (`bridge_from` success branch)
- Test: `src/sync.rs` (`mod tests`)

- [ ] **Step 1: Write the failing tests**

```rust
    #[tokio::test(start_paused = true)]
    async fn both_directions_settle_without_redundant_writes() {
        let mut cfg = Config::for_test("s");
        cfg.sync_primary = true;
        cfg.link_selections = LinkSelections::Both;
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("foo"));
        // exactly two broadcasts: the clipboard, then the mirrored primary
        let (k1, _, o1) = recv_clip(&mut h).await;
        assert_eq!((k1, o1), (SelectionKind::Clipboard, offer("foo")));
        let (k2, _, o2) = recv_clip(&mut h).await;
        assert_eq!((k2, o2), (SelectionKind::Primary, offer("foo")));
        assert_no_broadcast(&mut h).await;
        // one write only (the primary mirror); no echo ping-pong
        assert_eq!(h.clip.write_count(), 1);
        assert_eq!(h.clip.get(SelectionKind::Primary), Some(offer("foo")));
    }

    #[tokio::test(start_paused = true)]
    async fn both_directions_no_redundant_write_with_denied_rep() {
        let mut cfg = Config::for_test("s");
        cfg.sync_primary = true;
        cfg.link_selections = LinkSelections::Both;
        let _dir = with_rules(&mut cfg, MimePolicy::Allow, &[("image/png", "deny")]);
        let mut h = start(cfg).await;
        let mut o = offer("text part");
        o.insert("image/png".to_string(), vec![0u8; 16]);
        h.clip.local_copy(SelectionKind::Clipboard, o.clone());
        // the wire sees only the allowed text rep, on both axes
        let (k1, _, b1) = recv_clip(&mut h).await;
        assert_eq!((k1, b1), (SelectionKind::Clipboard, offer("text part")));
        let (k2, _, b2) = recv_clip(&mut h).await;
        assert_eq!((k2, b2), (SelectionKind::Primary, offer("text part")));
        assert_no_broadcast(&mut h).await;
        // primary holds the FULL raw offer (the denied rep is kept locally)
        assert_eq!(h.clip.get(SelectionKind::Primary), Some(o));
        // exactly one mirror write — read-back fidelity holds, no loop
        assert_eq!(h.clip.write_count(), 1);
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib sync::tests::both_directions_settle_without_redundant_writes`
Expected: FAIL — `write_count` is 2 (the primary mirror is re-mirrored back to the clipboard once).

- [ ] **Step 3: Stamp both selections on a mirror write**

In `bridge_from`'s success branch, replace the single stamp line:

```rust
                self.last_mirrored.lock().unwrap().insert(kind, h);
```

with both-selection stamping:

```rust
                // Stamp both selections: the partner now holds exactly this
                // raw content, so its echo watch event is recognized and
                // skipped — zero redundant writes, guaranteed termination.
                let mut lm = self.last_mirrored.lock().unwrap();
                lm.insert(kind, h);
                lm.insert(partner, h);
```

(The `if let Some(copied) = copied { info!(...) }` line above it stays.)

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib sync::tests::both_directions_settle_without_redundant_writes sync::tests::both_directions_no_redundant_write_with_denied_rep`
Expected: PASS (both).

- [ ] **Step 5: Verify gates and commit**

```bash
cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check
git add src/sync.rs
git commit -m "feat: loop-safe bidirectional bridge (stamp both selections)"
```

---

## Task 6: Do not bridge password-manager secrets

**Files:**
- Modify: `src/sync.rs` (`bridge_from`)
- Test: `src/sync.rs` (`mod tests`)

- [ ] **Step 1: Write the failing test**

```rust
    #[tokio::test(start_paused = true)]
    async fn sensitive_content_is_not_bridged() {
        let mut cfg = Config::for_test("s"); // exclude_sensitive on by default
        cfg.link_selections = LinkSelections::ClipboardToPrimary;
        let mut h = start(cfg).await;
        let mut o = offer("hunter2");
        o.insert("x-kde-passwordManagerHint".to_string(), b"secret".to_vec());
        h.clip.local_copy(SelectionKind::Clipboard, o);
        // sensitive: not broadcast (existing behavior) and not mirrored
        assert_no_broadcast(&mut h).await;
        assert_eq!(h.clip.write_count(), 0);
        assert_eq!(h.clip.get(SelectionKind::Primary), None);
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib sync::tests::sensitive_content_is_not_bridged`
Expected: FAIL — the secret is written into PRIMARY (`write_count` is 1).

- [ ] **Step 3: Add the sensitive guard**

In `bridge_from`, immediately after the `last_mirrored` guard block and before the `let copied = ...` line:

```rust
        if self.cfg.exclude_sensitive && is_sensitive(&raw) {
            // Never hop a secret between selections; record it so it does not
            // re-trigger, but do not write the partner.
            self.last_mirrored.lock().unwrap().insert(kind, h);
            return;
        }
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test --lib sync::tests::sensitive_content_is_not_bridged`
Expected: PASS.

- [ ] **Step 5: Verify gates and commit**

```bash
cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check
git add src/sync.rs
git commit -m "feat: never bridge password-manager secrets between selections"
```

---

## Task 7: Empty and unreadable sources

The bridge bypasses `filter()` (which drops empties), so it needs an explicit empty guard; and a failed read must not poison the guard. This task adds `set_fail_reads` to the mock and the empty guard to `bridge_from`. (The `None`-read short-circuit already exists via the `let-else` from Task 3; this verifies it.)

**Files:**
- Modify: `src/clipboard/mock.rs` (new `fail_reads` flag + `set_fail_reads` + `read_offer`)
- Modify: `src/sync.rs` (`bridge_from` empty guard)
- Test: `src/sync.rs` (`mod tests`)

- [ ] **Step 1: Write the failing tests**

```rust
    #[tokio::test(start_paused = true)]
    async fn clearing_a_selection_does_not_wipe_the_partner() {
        let mut cfg = Config::for_test("s");
        cfg.link_selections = LinkSelections::ClipboardToPrimary;
        let mut h = start(cfg).await;
        // put something in primary first (no reverse mirror, so it stays)
        h.clip.local_copy(SelectionKind::Primary, offer("keep"));
        assert_no_broadcast(&mut h).await;
        // now "clear" the clipboard (empty offer)
        h.clip.local_copy(SelectionKind::Clipboard, Offer::new());
        assert_no_broadcast(&mut h).await;
        assert_eq!(h.clip.write_count(), 0);
        assert_eq!(h.clip.get(SelectionKind::Primary), Some(offer("keep")));
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_read_does_not_poison_the_bridge() {
        let mut cfg = Config::for_test("s");
        cfg.link_selections = LinkSelections::ClipboardToPrimary;
        let mut h = start(cfg).await;
        h.clip.set_fail_reads(true);
        h.clip.local_copy(SelectionKind::Clipboard, offer("foo"));
        assert_no_broadcast(&mut h).await; // both reads bail
        assert_eq!(h.clip.write_count(), 0);
        // reads recover; the same content now bridges (the guard wasn't poisoned)
        h.clip.set_fail_reads(false);
        h.clip.local_copy(SelectionKind::Clipboard, offer("foo"));
        let (kind, _, o) = recv_clip(&mut h).await;
        assert_eq!((kind, o), (SelectionKind::Clipboard, offer("foo")));
        wait_applied(&h, SelectionKind::Primary, &offer("foo")).await;
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib sync::tests::a_failed_read_does_not_poison_the_bridge`
Expected: FAIL — compile error, `no method named set_fail_reads`.

- [ ] **Step 3: Add `set_fail_reads` to the mock**

In `src/clipboard/mock.rs`, add a field to `MockClipboard`, after `fail_writes: std::sync::atomic::AtomicBool,`:

```rust
    fail_reads: std::sync::atomic::AtomicBool,
```

In `MockClipboard::new`'s struct literal, after `fail_writes: std::sync::atomic::AtomicBool::new(false),`:

```rust
            fail_reads: std::sync::atomic::AtomicBool::new(false),
```

After the `set_fail_writes` method:

```rust
    /// Make subsequent read_offer calls fail (simulates a transient read error).
    pub fn set_fail_reads(&self, fail: bool) {
        self.fail_reads.store(fail, Ordering::SeqCst);
    }
```

Replace `read_offer` in the `Clipboard for MockClipboard` impl:

```rust
    async fn read_offer(&self, kind: SelectionKind) -> Result<Offer> {
        if self.fail_reads.load(Ordering::SeqCst) {
            anyhow::bail!("simulated clipboard read failure");
        }
        Ok(self.get(kind).unwrap_or_default())
    }
```

- [ ] **Step 4: Add the empty guard to `bridge_from`**

In `src/sync.rs` `bridge_from`, immediately after the `let Some(raw) = ... else { return };`:

```rust
        if raw.is_empty() {
            return; // bridge bypasses filter(); clearing one selection must
                    // not wipe the partner
        }
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --lib sync::tests::clearing_a_selection_does_not_wipe_the_partner sync::tests::a_failed_read_does_not_poison_the_bridge`
Expected: PASS (both).

- [ ] **Step 6: Verify gates and commit**

```bash
cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check
git add src/sync.rs src/clipboard/mock.rs
git commit -m "feat: bridge skips empty offers and survives failed reads"
```

---

## Task 8: Don't spontaneously bridge restored content on restart

`prime()` must seed `last_mirrored` so a restored selection (re-reported by the watcher at startup) is treated as already-mirrored. This task adds `watched_kinds()` and reworks `prime()`.

**Files:**
- Modify: `src/sync.rs` (`prime`; new `watched_kinds`)
- Test: `src/sync.rs` (`mod tests`)

- [ ] **Step 1: Write the failing test**

```rust
    #[tokio::test(start_paused = true)]
    async fn priming_does_not_spontaneously_bridge_restored_content() {
        let mut cfg = Config::for_test("s");
        cfg.link_selections = LinkSelections::ClipboardToPrimary;
        // restart over an existing clipboard
        let mut h = start_seeded(cfg, Some(offer("restored"))).await;
        // the watcher re-reports the restored clipboard (as a subscribe-time
        // event would); priming seeded last_mirrored, so it must NOT bridge.
        h.clip.local_copy(SelectionKind::Clipboard, offer("restored"));
        assert_no_broadcast(&mut h).await;
        assert_eq!(h.clip.write_count(), 0);
        assert_eq!(h.clip.get(SelectionKind::Primary), None);
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib sync::tests::priming_does_not_spontaneously_bridge_restored_content`
Expected: FAIL — the restored content is mirrored into PRIMARY (`write_count` is 1).

- [ ] **Step 3: Add `watched_kinds`**

In `src/sync.rs`, right after `synced_kinds` (around line 113):

```rust
    /// Selections this node watches: CLIPBOARD always, PRIMARY when it is
    /// mesh-synced or needed for the local primary→clipboard bridge. Broader
    /// than `synced_kinds` (PRIMARY may be watched but not synced).
    fn watched_kinds(&self) -> Vec<SelectionKind> {
        let mut kinds = vec![SelectionKind::Clipboard];
        if self.cfg.sync_primary || self.cfg.link_selections.primary_to_clip() {
            kinds.push(SelectionKind::Primary);
        }
        kinds
    }
```

- [ ] **Step 4: Rework `prime` to seed `last_mirrored`**

Replace the whole `prime` method body:

```rust
    async fn prime(&self) {
        let synced = self.synced_kinds();
        for kind in self.watched_kinds() {
            let Some(raw) = self.read_selection(kind).await else {
                continue;
            };
            if raw.is_empty() {
                continue;
            }
            // Seed the bridge guard so a restart never spontaneously mirrors
            // restored content on the next watcher event.
            let raw_hash = content_hash(&raw);
            self.last_mirrored
                .lock()
                .unwrap()
                .entry(kind)
                .or_insert(raw_hash);
            // Synced kinds also seed `current` (filtered, stamp 0) and record
            // any brand-new types — exactly as before.
            if !synced.contains(&kind) {
                continue;
            }
            if let Some(offer) = self.filter(raw, true) {
                let hash = content_hash(&offer);
                debug!(
                    "primed existing {kind:?} clipboard ({})",
                    describe_offer(&offer)
                );
                self.current
                    .lock()
                    .unwrap()
                    .entry(kind)
                    .or_insert(ContentState {
                        hash,
                        stamp: 0,
                        origin: self.mesh.own_id(),
                    });
            }
        }
    }
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test --lib sync::tests::priming_does_not_spontaneously_bridge_restored_content`
Expected: PASS.

- [ ] **Step 6: Verify the priming regression tests still pass**

Run: `cargo test --lib sync::tests::primed_content_is_not_rebroadcast_as_fresh sync::tests::primed_content_resyncs_with_stamp_zero sync::tests::primed_content_loses_resync_to_real_remote_content`
Expected: PASS (current[] seeding behavior is unchanged for synced kinds).

- [ ] **Step 7: Verify gates and commit**

```bash
cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check
git add src/sync.rs
git commit -m "feat: prime seeds the bridge guard so restarts don't re-mirror"
```

---

## Task 9: Coverage — feed-the-mesh, receive_only, default-off, same-window conflict

These assert spec requirements that already hold against the implementation; they are regression coverage. If any fails, an earlier task is incomplete.

**Files:**
- Test: `src/sync.rs` (`mod tests`)

- [ ] **Step 1: Write the tests**

```rust
    #[tokio::test(start_paused = true)]
    async fn mirrored_primary_is_fed_to_the_mesh_when_synced() {
        let mut cfg = Config::for_test("s");
        cfg.sync_primary = true;
        cfg.link_selections = LinkSelections::ClipboardToPrimary;
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("foo"));
        let (k1, _, o1) = recv_clip(&mut h).await;
        assert_eq!((k1, o1), (SelectionKind::Clipboard, offer("foo")));
        let (k2, _, o2) = recv_clip(&mut h).await;
        assert_eq!((k2, o2), (SelectionKind::Primary, offer("foo")));
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn bridge_runs_locally_under_receive_only_without_broadcasting() {
        let mut cfg = Config::for_test("s");
        cfg.direction = Direction::ReceiveOnly;
        cfg.sync_primary = true;
        cfg.link_selections = LinkSelections::Both;
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("foo"));
        wait_applied(&h, SelectionKind::Primary, &offer("foo")).await; // local mirror
        assert_no_broadcast(&mut h).await; // receive_only never broadcasts
        assert_eq!(h.clip.write_count(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn link_off_never_mirrors() {
        let mut h = start(Config::for_test("s")).await; // link_selections defaults Off
        h.clip.local_copy(SelectionKind::Clipboard, offer("foo"));
        let (kind, _, o) = recv_clip(&mut h).await;
        assert_eq!((kind, o), (SelectionKind::Clipboard, offer("foo")));
        assert_no_broadcast(&mut h).await;
        assert_eq!(h.clip.write_count(), 0);
        assert_eq!(h.clip.get(SelectionKind::Primary), None);
    }

    #[tokio::test(start_paused = true)]
    async fn same_window_conflict_first_change_wins() {
        let mut cfg = Config::for_test("s");
        cfg.debounce_ms = 100;
        cfg.sync_primary = true;
        cfg.link_selections = LinkSelections::Both;
        let mut h = start(cfg).await;
        // both selections change within one debounce window; clipboard changed
        // first, so it wins and overwrites the primary's concurrent change.
        h.clip.local_copy(SelectionKind::Clipboard, offer("clip"));
        h.clip.local_copy(SelectionKind::Primary, offer("prim"));
        let (k1, _, o1) = recv_clip(&mut h).await;
        assert_eq!((k1, o1), (SelectionKind::Clipboard, offer("clip")));
        let (k2, _, o2) = recv_clip(&mut h).await;
        assert_eq!((k2, o2), (SelectionKind::Primary, offer("clip")));
        assert_no_broadcast(&mut h).await;
        assert_eq!(h.clip.get(SelectionKind::Clipboard), Some(offer("clip")));
        assert_eq!(h.clip.get(SelectionKind::Primary), Some(offer("clip")));
    }
```

- [ ] **Step 2: Run the tests to verify they pass**

Run: `cargo test --lib sync::tests::mirrored_primary_is_fed_to_the_mesh_when_synced sync::tests::bridge_runs_locally_under_receive_only_without_broadcasting sync::tests::link_off_never_mirrors sync::tests::same_window_conflict_first_change_wins`
Expected: PASS (all four).

- [ ] **Step 3: Verify gates and commit**

```bash
cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check
git add src/sync.rs
git commit -m "test: bridge coverage (feed-mesh, receive_only, off, same-window)"
```

---

## Task 10: Documentation

**Files:**
- Modify: `examples/config.toml`
- Modify: `README.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Document the setting in `examples/config.toml`**

After the `sync_primary` line (line 29), add:

```toml
# link_selections = "off"     # locally mirror between the clipboard and the
#                             # middle-click primary selection on THIS host
#                             # (separate from sync_primary, which is mesh-wide).
#                             # "off" | "clipboard_to_primary" |
#                             # "primary_to_clipboard" | "both".
#                             # WARNING: "primary_to_clipboard" (and "both")
#                             # make selecting any text overwrite your clipboard
#                             # — and, with sync_primary, your peers' clipboards.
```

- [ ] **Step 2: Document it in `README.md`**

After the bullet list near the top (after the password-manager bullet, before "Resyncs on reconnect"), add a bullet:

```markdown
- Optionally links the two local selections on a host: `link_selections`
  mirrors the clipboard into the middle-click primary selection and/or the
  reverse (`clipboard_to_primary` | `primary_to_clipboard` | `both`, default
  off). This is local-only coupling, separate from `sync_primary` (which syncs
  each selection across the mesh). `primary_to_clipboard` means selecting text
  overwrites your clipboard — and, with `sync_primary`, your peers' too.
```

- [ ] **Step 3: Note the axis in `CLAUDE.md`**

In the `sync.rs` architecture bullet, append one sentence:

```markdown
A separate **local selection bridge** (`link_selections`, `bridge_from`) optionally mirrors the local CLIPBOARD↔PRIMARY selections on one host — distinct from `sync_primary` (which syncs each selection across the mesh); a bridged write rides the normal broadcast path and is loop-guarded by `last_mirrored` (raw hashes).
```

- [ ] **Step 4: Verify the build is clean and commit**

```bash
cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check
git add examples/config.toml README.md CLAUDE.md
git commit -m "docs: document the local link_selections selection bridge"
```

---

## Final verification

- [ ] Run the full gate one more time:

```bash
cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check
```

Expected: all tests PASS, no clippy warnings, formatting clean.
