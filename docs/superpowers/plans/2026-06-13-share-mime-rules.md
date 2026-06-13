# Share the MIME-rules file between nodes — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `share_mime_rules` (default on) so the per-type MIME allow/deny file converges across the mesh under whole-file last-writer-wins.

**Architecture:** The whole `mimetypes` file is one synced unit carrying a single `(stamp, origin)` version in a managed `# clipmesh-version:` header line (reusing the clipboard's hybrid logical clock). A node materialises the header on first sync activity, broadcasts the entire file on any local change, pushes it bidirectionally on connect, and on inbound replaces its file verbatim when the peer's version is newer. Inbound stamps are skew-rejected and `observe()`d so a later local edit always outranks an adopted version.

**Tech Stack:** Rust, tokio (async engine + `mpsc`), `bincode` wire messages, `inotify` (fswatch thread), `tempfile`/`#[tokio::test]` for tests.

**Spec:** `docs/superpowers/specs/2026-06-13-share-mime-rules-design.md`

---

## File structure

| File | Responsibility for this feature |
|------|---------------------------------|
| `src/config.rs` | New `share_mime_rules: bool` (default true; `for_test` false). |
| `src/protocol.rs` | New `Message::Rules { stamp, origin, body }`; `PROTOCOL_VERSION` constant. |
| `src/mime.rs` | The `# clipmesh-version:` header: read (`version`), write (`set_version`), detect (`has_version_header`), render the whole file (`body`), replace the whole file (`replace_from`), and report whether a reload changed anything (`reload_if_changed -> bool`). |
| `src/sync.rs` | Adopt inbound `Rules` (LWW + skew + observe); broadcast on local change via a `rules_changed` channel; push on connect (independent of `direction`/`resync_on_connect`); observe the persisted version at startup. |
| `src/fswatch.rs` | After a *real* rules reload, ping the engine over the `rules_changed` channel. |
| `src/node.rs` | Create the `rules_changed` channel, pass it to the engine, expose the sender on `NodeHandle`. |
| `src/main.rs` | Pass the sender to `fswatch::spawn`; log `PROTOCOL_VERSION` at startup. |
| `tests/two_nodes.rs` | End-to-end: two nodes converge their rules file on connect. |
| `examples/config.toml`, `README.md` | Document the option and the convergence/LWW behaviour. |

---

## Task 1: Config flag `share_mime_rules`

**Files:**
- Modify: `src/config.rs`

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` block in `src/config.rs`:

```rust
    #[test]
    fn share_mime_rules_defaults_on_and_parses() {
        // default on
        let cfg = Config::from_toml("listen = \"x:1\"\npsk = \"s\"\n").unwrap();
        assert!(cfg.share_mime_rules);
        // explicit off
        let cfg =
            Config::from_toml("listen = \"x:1\"\npsk = \"s\"\nshare_mime_rules = false\n").unwrap();
        assert!(!cfg.share_mime_rules);
        // tests opt out by default so existing verbatim-file tests are unaffected
        assert!(!Config::for_test("s").share_mime_rules);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib config::tests::share_mime_rules_defaults_on_and_parses`
Expected: FAIL to compile — `no field share_mime_rules on type Config`.

- [ ] **Step 3: Implement**

In `RawConfig` (after the `resync_on_connect` field), add:

```rust
    #[serde(default = "default_true")]
    share_mime_rules: bool,
```

In `struct Config` (after `pub resync_on_connect: bool,`), add:

```rust
    /// Share the per-type MIME-rules file across the mesh (whole-file
    /// last-writer-wins). Default on. Independent of `direction`.
    pub share_mime_rules: bool,
```

In `from_toml`'s returned `Config { .. }` (after `resync_on_connect: raw.resync_on_connect,`), add:

```rust
            share_mime_rules: raw.share_mime_rules,
```

In `for_test`'s `Config { .. }` (after `resync_on_connect: true,`), add:

```rust
            // Off in tests: existing tests assert verbatim file contents and
            // must not get a version header written. Sharing tests opt in.
            share_mime_rules: false,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib config::tests::share_mime_rules_defaults_on_and_parses`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/config.rs
git commit -m "feat: add share_mime_rules config flag (default on)"
```

---

## Task 2: Protocol — `Message::Rules` + `PROTOCOL_VERSION`

**Files:**
- Modify: `src/protocol.rs`

- [ ] **Step 1: Write the failing test**

Add to `#[cfg(test)] mod tests` in `src/protocol.rs`:

```rust
    #[test]
    fn rules_message_round_trips() {
        let msg = Message::Rules {
            stamp: 42,
            origin: Uuid::new_v4(),
            body: "# clipmesh-version: 42 x\nimage/png allow\n".to_string(),
        };
        assert_eq!(decode(&encode(&msg)).unwrap(), msg);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib protocol::tests::rules_message_round_trips`
Expected: FAIL to compile — `no variant named Rules`.

- [ ] **Step 3: Implement**

In `enum Message`, after the `Clip { .. }` variant, add:

```rust
    /// The full MIME-rules file, shared across the mesh under whole-file
    /// last-writer-wins. `body` is the entire file text (including the
    /// `# clipmesh-version:` header line); `(stamp, origin)` order it the same
    /// way a clipboard update is ordered.
    Rules {
        stamp: u64,
        origin: Uuid,
        body: String,
    },
```

Near the top of the file (after the `use` lines), add the version marker:

```rust
/// Wire protocol version. Bumped whenever the on-wire message format changes.
/// bincode is not self-describing, so mismatched versions cannot interoperate —
/// all nodes must run a compatible build. Logged at startup for diagnosis.
pub const PROTOCOL_VERSION: u32 = 2;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib protocol::tests::rules_message_round_trips`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/protocol.rs
git commit -m "feat: add Message::Rules variant and PROTOCOL_VERSION"
```

---

## Task 3a: MimeRules — version header read/write

**Files:**
- Modify: `src/mime.rs`

- [ ] **Step 1: Write the failing tests**

Add to `#[cfg(test)] mod tests` in `src/mime.rs`:

```rust
    #[test]
    fn version_reads_the_header_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        let origin = Uuid::from_u128(7);
        std::fs::write(
            &path,
            format!("# clipmesh-version: 1234 {origin}\nimage/png allow\n"),
        )
        .unwrap();
        let rules = MimeRules::load(Some(path), MimePolicy::Deny);
        assert_eq!(rules.version(Uuid::nil()), (1234, origin));
        assert!(rules.has_version_header());
    }

    #[test]
    fn version_falls_back_to_mtime_baseline_without_a_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        std::fs::write(&path, "image/png allow\n").unwrap();
        let rules = MimeRules::load(Some(path), MimePolicy::Deny);
        let own = Uuid::from_u128(9);
        let (stamp, origin) = rules.version(own);
        assert!(stamp > 0, "mtime baseline should be a real epoch-ms value");
        assert_eq!(origin, own);
        assert!(!rules.has_version_header());
    }

    #[test]
    fn set_version_inserts_then_replaces_a_single_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        std::fs::write(&path, "image/png allow\n").unwrap();
        let mut rules = MimeRules::load(Some(path.clone()), MimePolicy::Deny);
        let o = Uuid::from_u128(3);
        rules.set_version(100, o);
        rules.persist();
        rules.set_version(200, o); // must replace, not duplicate
        rules.persist();
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            body.matches("clipmesh-version").count(),
            1,
            "exactly one header:\n{body}"
        );
        assert!(
            body.starts_with(&format!("# clipmesh-version: 200 {o}")),
            "header at top:\n{body}"
        );
        assert_eq!(rules.version(Uuid::nil()), (200, o));
        assert!(rules.allows("image/png", 1), "rules survive header writes");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib mime::tests::version_reads_the_header_line`
Expected: FAIL to compile — `no method named version` / `Uuid` not in scope.

- [ ] **Step 3: Implement**

At the top of `src/mime.rs`, add the import (after the existing `use` lines):

```rust
use uuid::Uuid;
```

After the `UNPARSED_PREFIX` constant, add:

```rust
/// Header line clipmesh manages to stamp the file's whole-file LWW version
/// when rule-sharing is on: `# clipmesh-version: <stamp> <origin-uuid>`. It is
/// a comment, so it round-trips through parsing untouched.
const VERSION_PREFIX: &str = "# clipmesh-version: ";
```

Add these methods inside `impl MimeRules { .. }` (e.g. after `persist`):

```rust
    /// The file's whole-file LWW version. Reads the managed header line if
    /// present; otherwise falls back to a baseline of (file mtime in ms,
    /// own_id) so enabling sharing converges on the most-recently-edited file.
    /// mtime is 0 if unreadable or there is no path.
    pub fn version(&self, own_id: Uuid) -> (u64, Uuid) {
        for l in &self.lines {
            if let Some(rest) = l.text.strip_prefix(VERSION_PREFIX) {
                let mut f = rest.split_whitespace();
                if let (Some(s), Some(o)) = (f.next(), f.next()) {
                    if let (Ok(stamp), Ok(origin)) = (s.parse::<u64>(), o.parse::<Uuid>()) {
                        return (stamp, origin);
                    }
                }
            }
        }
        (self.file_mtime_ms(), own_id)
    }

    /// Whether the managed version header line is present.
    pub fn has_version_header(&self) -> bool {
        self.lines.iter().any(|l| l.text.starts_with(VERSION_PREFIX))
    }

    /// Set (or replace) the version header at the top of the file and mark
    /// dirty. Removes any existing header first, so there is always exactly one.
    pub fn set_version(&mut self, stamp: u64, origin: Uuid) {
        self.lines.retain(|l| !l.text.starts_with(VERSION_PREFIX));
        self.lines.insert(
            0,
            Line {
                text: format!("{VERSION_PREFIX}{stamp} {origin}"),
                rule: None,
            },
        );
        self.dirty = true;
    }

    /// The rules file's mtime in epoch-ms, or 0 if there is no path or it can't
    /// be read. Used as the version baseline before a header is materialised.
    fn file_mtime_ms(&self) -> u64 {
        let Some(path) = &self.path else {
            return 0;
        };
        fs::metadata(path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib mime::tests::version_reads_the_header_line && cargo test --lib mime::tests::version_falls_back_to_mtime_baseline_without_a_header && cargo test --lib mime::tests::set_version_inserts_then_replaces_a_single_header`
Expected: each PASS.

- [ ] **Step 5: Commit**

```bash
git add src/mime.rs
git commit -m "feat: read/write the clipmesh-version header in MimeRules"
```

---

## Task 3b: MimeRules — body, replace_from, reload returns changed

**Files:**
- Modify: `src/mime.rs`

- [ ] **Step 1: Write the failing tests**

Add to `#[cfg(test)] mod tests` in `src/mime.rs`:

```rust
    #[test]
    fn body_renders_all_lines_with_trailing_newlines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        std::fs::write(&path, "# c\nimage/png allow\n").unwrap();
        let rules = MimeRules::load(Some(path), MimePolicy::Deny);
        assert_eq!(rules.body(), "# c\nimage/png allow\n");
    }

    #[test]
    fn replace_from_swaps_the_whole_ruleset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        std::fs::write(&path, "image/png deny\n").unwrap();
        let mut rules = MimeRules::load(Some(path.clone()), MimePolicy::Deny);
        assert!(!rules.allows("image/png", 1));
        rules.replace_from("image/png allow\ntext/plain allow\n".to_string());
        rules.persist();
        assert!(rules.allows("image/png", 1));
        assert!(rules.allows("text/plain", 1));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "image/png allow\ntext/plain allow\n"
        );
    }

    #[test]
    fn reload_if_changed_reports_whether_it_changed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        std::fs::write(&path, "image/png deny\n").unwrap();
        let mut rules = MimeRules::load(Some(path.clone()), MimePolicy::Deny);
        assert!(!rules.reload_if_changed(), "no change immediately after load");
        std::fs::write(&path, "image/png allow\n").unwrap();
        assert!(rules.reload_if_changed(), "external edit must report changed");
        assert!(!rules.reload_if_changed(), "no change on re-check");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib mime::tests::body_renders_all_lines_with_trailing_newlines`
Expected: FAIL to compile — `no method named body`.

- [ ] **Step 3: Implement**

Add two methods inside `impl MimeRules { .. }`:

```rust
    /// Render the current ruleset to its on-disk text form, so it can be sent
    /// to peers verbatim. Identical to what `write_file` writes.
    pub fn body(&self) -> String {
        let mut text = String::new();
        for line in &self.lines {
            text.push_str(&line.text);
            text.push('\n');
        }
        text
    }

    /// Replace the entire ruleset with `text` (a file body received from a
    /// peer), marking it dirty so a subsequent `persist` writes it. Does not
    /// touch `loaded` — `persist` updates that once the bytes are on disk, so a
    /// concurrent watcher reload can't clobber the in-memory rules mid-adopt.
    pub fn replace_from(&mut self, text: String) {
        let (lines, _had_bad) = parse(&text);
        self.lines = lines;
        self.dirty = true;
    }
```

Refactor `write_file` to reuse `body()` — replace its text-building loop:

```rust
    fn write_file(&mut self) {
        let Some(path) = self.path.clone() else {
            return;
        };
        let text = self.body();
        match fs::write(&path, &text) {
            Ok(()) => {
                self.loaded = Some(text);
                self.dirty = false;
            }
            Err(e) => warn!("couldn't write MIME rules to {}: {e}", path.display()),
        }
    }
```

Change `reload_if_changed` to return `bool` (whether it applied a new file):

```rust
    pub fn reload_if_changed(&mut self) -> bool {
        let Some(path) = self.path.clone() else {
            return false;
        };
        match fs::read_to_string(&path) {
            Ok(text) if self.loaded.as_deref() == Some(text.as_str()) => false,
            Ok(text) => {
                debug!("MIME rules file changed on disk; reloading");
                self.ingest(text, &path);
                true
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                debug!("MIME rules file is momentarily absent; keeping current rules");
                false
            }
            Err(e) => {
                warn!("couldn't read MIME rules from {}: {e}", path.display());
                false
            }
        }
    }
```

(Existing callers ignore the return value, so they keep compiling.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib mime::`
Expected: PASS — all mime tests, including the three new ones and the unchanged verbatim-file ones.

- [ ] **Step 5: Commit**

```bash
git add src/mime.rs
git commit -m "feat: add MimeRules body/replace_from; reload_if_changed reports changes"
```

---

## Task 4: Engine — adopt inbound `Rules` (LWW + skew + observe)

**Files:**
- Modify: `src/sync.rs`

- [ ] **Step 1: Write the failing tests**

Add to `#[cfg(test)] mod tests` in `src/sync.rs`:

```rust
    #[tokio::test(start_paused = true)]
    async fn inbound_rules_newer_is_adopted() {
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        let dir = with_rules(&mut cfg, MimePolicy::Deny, "image/png deny\n");
        let path = dir.path().join("mimetypes");
        let mut h = start(cfg).await;
        h.in_tx
            .send((
                h.remote_id,
                Message::Rules {
                    stamp: future_stamp(1000),
                    origin: h.remote_id,
                    body: "image/png allow\n".to_string(),
                },
            ))
            .await
            .unwrap();
        timeout(Duration::from_secs(1), async {
            while std::fs::read_to_string(&path).unwrap() != "image/png allow\n" {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("newer rules were not adopted");
        // Adopting a peer file must not bounce back as a broadcast.
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_rules_equal_stamp_higher_origin_wins() {
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        // Seed a header with a known stamp and a LOW origin, so an equal-stamp
        // peer with a higher origin wins the deterministic tiebreak.
        let low = Uuid::from_u128(1);
        std::fs::write(
            &path,
            format!("# clipmesh-version: 5000 {low}\nimage/png deny\n"),
        )
        .unwrap();
        cfg.unknown_mime = MimePolicy::Deny;
        cfg.mime_rules_path = Some(path.clone());
        let h = start(cfg).await;
        let high = Uuid::from_u128(2);
        h.in_tx
            .send((
                h.remote_id,
                Message::Rules {
                    stamp: 5000,
                    origin: high,
                    body: "image/png allow\n".to_string(),
                },
            ))
            .await
            .unwrap();
        timeout(Duration::from_secs(1), async {
            while std::fs::read_to_string(&path).unwrap() != "image/png allow\n" {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("equal-stamp higher-origin peer should win the tiebreak");
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_rules_older_is_ignored() {
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        let dir = with_rules(&mut cfg, MimePolicy::Deny, "image/png allow\n");
        let path = dir.path().join("mimetypes");
        let h = start(cfg).await;
        // our baseline is the file's (recent) mtime, so stamp 1 must lose
        h.in_tx
            .send((
                h.remote_id,
                Message::Rules {
                    stamp: 1,
                    origin: h.remote_id,
                    body: "image/png deny\n".to_string(),
                },
            ))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "image/png allow\n",
            "older rules must not overwrite"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_rules_ignored_when_sharing_off() {
        let mut cfg = Config::for_test("s"); // sharing off by default
        let dir = with_rules(&mut cfg, MimePolicy::Deny, "image/png deny\n");
        let path = dir.path().join("mimetypes");
        let h = start(cfg).await;
        h.in_tx
            .send((
                h.remote_id,
                Message::Rules {
                    stamp: future_stamp(1000),
                    origin: h.remote_id,
                    body: "image/png allow\n".to_string(),
                },
            ))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "image/png deny\n",
            "sharing off must ignore inbound rules"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_future_rules_stamp_is_rejected() {
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        let dir = with_rules(&mut cfg, MimePolicy::Deny, "image/png deny\n");
        let path = dir.path().join("mimetypes");
        let h = start(cfg).await;
        let insane = now_ms() + 48 * 60 * 60 * 1000; // past the skew bound
        h.in_tx
            .send((
                h.remote_id,
                Message::Rules {
                    stamp: insane,
                    origin: h.remote_id,
                    body: "image/png allow\n".to_string(),
                },
            ))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "image/png deny\n",
            "implausibly-future rules must be rejected"
        );
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib sync::tests::inbound_rules_newer_is_adopted`
Expected: FAIL — the engine ignores `Message::Rules` (warns "unexpected message type"), so the file is never adopted; the `timeout` elapses and the test panics.

- [ ] **Step 3: Implement**

In `src/sync.rs`, rename the existing `async fn on_inbound(&self, from: Uuid, msg: Message)` to `on_inbound_clip` and give it destructured params. Replace its current prologue:

```rust
    async fn on_inbound(&self, from: Uuid, msg: Message) {
        let Message::Clip {
            kind,
            hash,
            offer,
            stamp,
            origin,
        } = msg
        else {
            warn!("ignoring an unexpected message type from peer {from} (expected a clipboard update)");
            return;
        };
```

with this signature (keep the **entire rest of the method body unchanged**):

```rust
    async fn on_inbound_clip(
        &self,
        from: Uuid,
        kind: SelectionKind,
        hash: [u8; 32],
        offer: Offer,
        stamp: u64,
        origin: Uuid,
    ) {
```

Then add a new dispatcher `on_inbound` and the rules handler:

```rust
    /// Dispatch an inbound message from a peer to the right handler.
    async fn on_inbound(&self, from: Uuid, msg: Message) {
        match msg {
            Message::Clip {
                kind,
                hash,
                offer,
                stamp,
                origin,
            } => self.on_inbound_clip(from, kind, hash, offer, stamp, origin).await,
            Message::Rules {
                stamp,
                origin,
                body,
            } => self.on_inbound_rules(from, stamp, origin, body),
            Message::Hello { .. } => {
                warn!("ignoring an unexpected Hello from peer {from} after handshake")
            }
        }
    }

    /// Adopt a peer's shared MIME-rules file under whole-file last-writer-wins.
    /// Ignored unless sharing is on and we have a rules file. Rejects
    /// implausibly-future stamps and `observe()`s the stamp so a later local
    /// edit outranks the adopted version (otherwise a local edit stamped below
    /// it would revert to the version it just replaced).
    fn on_inbound_rules(&self, from: Uuid, stamp: u64, origin: Uuid, body: String) {
        if !self.cfg.share_mime_rules || self.cfg.mime_rules_path.is_none() {
            return;
        }
        if stamp > now_ms().saturating_add(MAX_FUTURE_SKEW_MS) {
            warn!("rejecting MIME-rules from peer {from}: timestamp {stamp} is implausibly far in the future (peer clock skew?)");
            return;
        }
        self.observe(stamp);
        let own_id = self.mesh.own_id();
        let mut rules = self
            .mime_rules
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let current = rules.version(own_id);
        if (stamp, origin) > current {
            debug!(
                "adopting shared MIME-rules from peer {from} (stamp {stamp}); replaces our (stamp {}, origin {})",
                current.0, current.1
            );
            rules.replace_from(body);
            rules.persist();
        } else {
            debug!(
                "ignoring shared MIME-rules from peer {from} (stamp {stamp}); we hold a newer-or-equal version (stamp {})",
                current.0
            );
        }
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib sync::tests::inbound_rules_`
Expected: PASS for all five (`inbound_rules_newer_is_adopted`, `inbound_rules_equal_stamp_higher_origin_wins`, `inbound_rules_older_is_ignored`, `inbound_rules_ignored_when_sharing_off`, `inbound_future_rules_stamp_is_rejected`). Also run `cargo test --lib sync::` to confirm the renamed Clip path still passes all existing tests.

- [ ] **Step 5: Commit**

```bash
git add src/sync.rs
git commit -m "feat: adopt inbound shared MIME-rules under whole-file LWW"
```

---

## Task 5: Engine — broadcast on local change + channel wiring

**Files:**
- Modify: `src/sync.rs`
- Modify: `src/node.rs`

- [ ] **Step 1: Write the failing tests**

Add to `#[cfg(test)] mod tests` in `src/sync.rs`:

```rust
    #[tokio::test(start_paused = true)]
    async fn capturing_a_new_type_broadcasts_the_rules_file() {
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        cfg.unknown_mime = MimePolicy::Allow; // captured type also syncs
        let dir = tempfile::tempdir().unwrap();
        cfg.mime_rules_path = Some(dir.path().join("mimetypes"));
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("hello")); // text/plain is new
        // we should see a Clip (content) and, separately, a Rules broadcast
        let mut saw_rules = false;
        for _ in 0..3 {
            match recv_msg(&mut h).await {
                Message::Rules { body, .. } => {
                    assert!(body.contains("text/plain"), "body:\n{body}");
                    assert!(body.contains("clipmesh-version"), "body:\n{body}");
                    saw_rules = true;
                    break;
                }
                Message::Clip { .. } => {}
                other => panic!("unexpected {other:?}"),
            }
        }
        assert!(saw_rules, "capturing a new type should broadcast the rules file");
    }

    #[tokio::test(start_paused = true)]
    async fn capturing_a_new_type_does_not_broadcast_rules_when_sharing_off() {
        let mut cfg = Config::for_test("s"); // sharing off
        cfg.unknown_mime = MimePolicy::Allow;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        cfg.mime_rules_path = Some(path.clone());
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("hello"));
        assert!(matches!(recv_msg(&mut h).await, Message::Clip { .. }));
        assert_no_broadcast(&mut h).await; // no Rules follows
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(
            !body.contains("clipmesh-version"),
            "sharing off must not stamp the file:\n{body}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_local_change_outranks_the_persisted_version_after_restart() {
        // The engine observes the file's header stamp at startup, so a fresh
        // local change is stamped above it (not below, which would lose).
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        cfg.unknown_mime = MimePolicy::Allow;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        cfg.mime_rules_path = Some(path.clone());
        let peer = Uuid::from_u128(123);
        let high = now_ms() + 60 * 60 * 1000; // 1h ahead, within the skew bound
        std::fs::write(
            &path,
            format!("# clipmesh-version: {high} {peer}\ntext/plain allow\n"),
        )
        .unwrap();
        let mut h = start(cfg).await;
        // a NEW type (image/png) is captured -> append -> version bump
        let mut o = offer("x"); // text/plain already known
        o.insert("image/png".to_string(), vec![0u8; 4]);
        h.clip.local_copy(SelectionKind::Clipboard, o);
        let mut stamp = None;
        for _ in 0..3 {
            if let Message::Rules { stamp: s, .. } = recv_msg(&mut h).await {
                stamp = Some(s);
                break;
            }
        }
        assert!(
            stamp.unwrap() > high,
            "local change must outrank the observed header stamp {high}"
        );
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib sync::tests::capturing_a_new_type_broadcasts_the_rules_file`
Expected: FAIL — no `Rules` is ever broadcast (the `for` loop never sees one), so the test panics on the final assert. (It compiles because no signatures change yet.)

- [ ] **Step 3: Implement — engine**

In `src/sync.rs`, add the body-size cap constant near `READ_TIMEOUT`:

```rust
/// Upper bound on a shared rules file we'll put on the wire. Rules files are a
/// few KB; this guards a pathological file from exceeding the transport frame.
const MAX_RULES_BODY: usize = 256 * 1024;
```

Add a field to `struct SyncEngine<C>` (after `mime_rules`):

```rust
    /// Self-ping used by the capture path to ask the run loop to bump the
    /// shared rules version and broadcast the file (so the broadcast happens on
    /// the loop, not inside the sync filter). fswatch holds a clone too.
    rules_changed_tx: mpsc::Sender<()>,
```

Change `SyncEngine::new` to take and store it:

```rust
    pub fn new(
        clipboard: Arc<C>,
        mesh: Arc<Mesh>,
        cfg: Arc<Config>,
        mime_rules: Arc<Mutex<MimeRules>>,
        rules_changed_tx: mpsc::Sender<()>,
    ) -> Arc<SyncEngine<C>> {
        Arc::new(SyncEngine {
            clipboard,
            mesh,
            cfg,
            current: Mutex::new(HashMap::new()),
            clock: Mutex::new(0),
            mime_rules,
            rules_changed_tx,
        })
    }
```

Change `run` to accept the receiver and add startup-observe + a select arm. Update its signature:

```rust
    pub async fn run(
        self: Arc<Self>,
        mut inbound: mpsc::Receiver<(Uuid, Message)>,
        mut connects: mpsc::Receiver<Uuid>,
        mut rules_changed: mpsc::Receiver<()>,
    ) {
        let mut watch = self.clipboard.watch();

        // Adopt the rules file's persisted version into the clock so the next
        // local edit outranks it after a restart.
        {
            let own_id = self.mesh.own_id();
            let (stamp, _) = self
                .mime_rules
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .version(own_id);
            self.observe(stamp);
        }
```

(Leave the rest of `run`'s setup as-is.) Add this arm inside the `tokio::select! { .. }` (alongside the others):

```rust
                res = rules_changed.recv() => match res {
                    Some(()) => self.on_local_rules_changed(),
                    None => {
                        warn!("rules-change channel closed; shutting down the sync engine");
                        break;
                    }
                },
```

Add the two methods inside `impl<C: Clipboard> SyncEngine<C> { .. }`:

```rust
    /// Signal the run loop that the rules file changed locally, so it bumps the
    /// shared version and broadcasts. Cheap and coalescing: a full queue just
    /// means a bump is already pending.
    fn note_rules_changed(&self) {
        let _ = self.rules_changed_tx.try_send(());
    }

    /// A local change to the rules file (a captured new type, or a human edit
    /// the watcher picked up) bumps the file version and broadcasts the whole
    /// file. No-op when sharing is off or there is no rules file.
    fn on_local_rules_changed(&self) {
        if !self.cfg.share_mime_rules || self.cfg.mime_rules_path.is_none() {
            return;
        }
        let stamp = self.tick();
        let origin = self.mesh.own_id();
        let body = {
            let mut rules = self
                .mime_rules
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            rules.set_version(stamp, origin);
            rules.persist();
            rules.body()
        };
        if body.len() > MAX_RULES_BODY {
            warn!(
                "not sharing the MIME-rules file: it is {} (over the {} share limit)",
                human_bytes(body.len()),
                human_bytes(MAX_RULES_BODY)
            );
            return;
        }
        debug!("broadcasting shared MIME-rules (stamp {stamp})");
        self.mesh.broadcast(&Message::Rules {
            stamp,
            origin,
            body,
        });
    }
```

In `apply_mime_rules`, capture whether `ensure` appended and ping the loop. Replace the `record_unseen` block:

```rust
        if record_unseen {
            let mut appended = false;
            if rules.has_unseen(offer.keys()) {
                rules.reload_if_changed();
                appended = rules.ensure(offer.keys());
            }
            // No-op unless something is unsaved (incl. retrying a failed write).
            rules.persist();
            // A newly-recorded type changes the file; share it (try_send only —
            // we still hold the rules lock here, so we must not re-lock).
            if appended && self.cfg.share_mime_rules {
                self.note_rules_changed();
            }
        }
```

- [ ] **Step 4: Implement — channel wiring in node.rs**

In `src/node.rs`, add a field to `struct NodeHandle`:

```rust
    /// Sender the file watcher uses to notify the engine that the MIME-rules
    /// file changed on disk (so the engine bumps the version and broadcasts).
    pub rules_changed_tx: mpsc::Sender<()>,
```

In `spawn_node`, replace the engine construction/return (the block that builds `mime_rules`, the engine, and `NodeHandle`):

```rust
    let mime_rules = Arc::new(Mutex::new(MimeRules::load(
        cfg.mime_rules_path.clone(),
        cfg.unknown_mime,
    )));
    let (rules_changed_tx, rules_changed_rx) = mpsc::channel(8);
    let engine = SyncEngine::new(
        clipboard,
        mesh.clone(),
        cfg,
        mime_rules.clone(),
        rules_changed_tx.clone(),
    );
    let engine_task = tokio::spawn(engine.run(inbound_rx, connect_rx, rules_changed_rx));

    Ok(NodeHandle {
        local_addr,
        mesh,
        engine_task,
        mime_rules,
        rules_changed_tx,
    })
```

- [ ] **Step 5: Update the sync.rs test harness for the new signatures**

In `src/sync.rs`'s `#[cfg(test)] mod tests`, update the three places that construct the engine:

In `start_seeded`, replace the engine spawn:

```rust
        let mime_rules = Arc::new(Mutex::new(MimeRules::load(
            cfg.mime_rules_path.clone(),
            cfg.unknown_mime,
        )));
        let (rules_tx, rules_rx) = mpsc::channel(8);
        let engine = SyncEngine::new(clip.clone(), mesh.clone(), cfg, mime_rules, rules_tx);
        tokio::spawn(engine.run(in_rx, connect_rx, rules_rx));
```

In `inbound_is_handled_while_priming_is_still_blocked`, replace the engine spawn:

```rust
        let (rules_tx, rules_rx) = mpsc::channel(8);
        let engine = SyncEngine::new(clip.clone(), mesh, cfg, mime_rules, rules_tx);
        tokio::spawn(engine.run(in_rx, connect_rx, rules_rx));
```

In `capture_offer_times_out_on_a_hung_read`, replace the engine construction (it does not call `run`):

```rust
        let (rules_tx, _rules_rx) = mpsc::channel(8);
        let engine = SyncEngine::new(clip, mesh, cfg, mime_rules, rules_tx);
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test --lib sync:: && cargo build`
Expected: PASS — the three new task-5 tests pass, all existing sync tests pass, and `node.rs` compiles against the new engine signatures.

- [ ] **Step 7: Commit**

```bash
git add src/sync.rs src/node.rs
git commit -m "feat: broadcast the shared MIME-rules file on local change"
```

---

## Task 6: Engine — push the rules file on connect (bidirectional)

**Files:**
- Modify: `src/sync.rs`

- [ ] **Step 1: Write the failing tests**

Add to `#[cfg(test)] mod tests` in `src/sync.rs`:

```rust
    #[tokio::test(start_paused = true)]
    async fn connect_pushes_the_rules_file_to_a_new_peer() {
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        std::fs::write(&path, "image/png allow\n").unwrap();
        cfg.mime_rules_path = Some(path.clone());
        let h = start(cfg).await;
        // a new peer joins; it must receive our rules file
        let (tx2, mut rx2) = mpsc::channel(8);
        h.mesh.register(Uuid::new_v4(), tx2);
        let msg = timeout(Duration::from_secs(1), rx2.recv())
            .await
            .unwrap()
            .unwrap();
        match msg {
            Message::Rules { body, .. } => assert!(body.contains("image/png allow"), "body:\n{body}"),
            other => panic!("expected a Rules push, got {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn connect_pushes_rules_even_when_receive_only() {
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        cfg.direction = Direction::ReceiveOnly;
        cfg.resync_on_connect = false;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        std::fs::write(&path, "image/png allow\n").unwrap();
        cfg.mime_rules_path = Some(path.clone());
        let h = start(cfg).await;
        let (tx2, mut rx2) = mpsc::channel(8);
        h.mesh.register(Uuid::new_v4(), tx2);
        let msg = timeout(Duration::from_secs(1), rx2.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(msg, Message::Rules { .. }),
            "rules push must ignore direction/resync_on_connect"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn connect_materialises_the_version_header() {
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        std::fs::write(&path, "image/png allow\n").unwrap(); // no header yet
        cfg.mime_rules_path = Some(path.clone());
        let h = start(cfg).await;
        let (tx2, mut rx2) = mpsc::channel(8);
        h.mesh.register(Uuid::new_v4(), tx2);
        let _ = timeout(Duration::from_secs(1), rx2.recv())
            .await
            .unwrap()
            .unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(
            body.contains("clipmesh-version"),
            "header must be materialised on first push:\n{body}"
        );
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib sync::tests::connect_pushes_the_rules_file_to_a_new_peer`
Expected: FAIL — `on_peer_connected` pushes no rules, so `rx2.recv()` times out and the test panics.

- [ ] **Step 3: Implement**

In `src/sync.rs`, at the very top of `on_peer_connected`, push rules before the content-resync guard:

```rust
    async fn on_peer_connected(&self, peer: Uuid) {
        // Rules sharing is independent of clipboard direction/resync settings.
        self.resync_rules_to(peer);
        if !self.cfg.resync_on_connect || self.cfg.direction == Direction::ReceiveOnly {
            return;
        }
        // ... existing content-resync loop unchanged ...
```

Add the method inside `impl<C: Clipboard> SyncEngine<C> { .. }`:

```rust
    /// Push our whole MIME-rules file to a peer that just connected, so the
    /// mesh converges. Independent of `direction`/`resync_on_connect` (those
    /// gate clipboard content); gated only by `share_mime_rules` and having a
    /// file. Materialises the version header on first send so the version is
    /// pinned to disk and survives restarts.
    fn resync_rules_to(&self, peer: Uuid) {
        if !self.cfg.share_mime_rules || self.cfg.mime_rules_path.is_none() {
            return;
        }
        let own_id = self.mesh.own_id();
        let (stamp, origin, body) = {
            let mut rules = self
                .mime_rules
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !rules.has_version_header() {
                // Pin the current (baseline) version to disk; do NOT bump.
                let (s, o) = rules.version(own_id);
                rules.set_version(s, o);
                rules.persist();
            }
            let (stamp, origin) = rules.version(own_id);
            (stamp, origin, rules.body())
        };
        if body.len() > MAX_RULES_BODY {
            warn!(
                "not sharing the MIME-rules file with peer {peer}: it is {} (over the {} share limit)",
                human_bytes(body.len()),
                human_bytes(MAX_RULES_BODY)
            );
            return;
        }
        debug!("pushing shared MIME-rules to peer {peer} (stamp {stamp})");
        self.mesh.send_to(
            peer,
            &Message::Rules {
                stamp,
                origin,
                body,
            },
        );
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib sync::`
Expected: PASS — the three new tests plus all existing sync tests (existing tests use `for_test`, sharing off, so `resync_rules_to` returns early and their resync assertions are unchanged).

- [ ] **Step 5: Commit**

```bash
git add src/sync.rs
git commit -m "feat: push the shared MIME-rules file to peers on connect"
```

---

## Task 7: fswatch — ping the engine on a real rules reload; wire main.rs

**Files:**
- Modify: `src/fswatch.rs`
- Modify: `src/main.rs`

- [ ] **Step 1: Write the failing test**

Add to `#[cfg(test)] mod tests` in `src/fswatch.rs`:

```rust
    #[test]
    fn editing_the_rules_file_pings_the_engine() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, "listen = \"x:1\"\npsk = \"s\"\n").unwrap();
        let rules_path = dir.path().join("mimetypes");
        std::fs::write(&rules_path, "image/png deny\n").unwrap();
        let rules = Arc::new(Mutex::new(MimeRules::load(
            Some(rules_path.clone()),
            MimePolicy::Deny,
        )));
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);

        let rules_w = rules.clone();
        let cfg_w = config_path.clone();
        let rules_path_w = rules_path.clone();
        let tx_w = tx.clone();
        thread::spawn(move || {
            let mut noop = || {};
            let _ = run(&cfg_w, Some(&rules_path_w), &rules_w, &mut noop, &tx_w);
        });

        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            std::fs::write(&rules_path, "image/png allow\n").unwrap();
            if rx.try_recv().is_ok() {
                return; // got a ping — success
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("editing the rules file did not ping the engine");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib fswatch::tests::editing_the_rules_file_pings_the_engine`
Expected: FAIL to compile — `run` takes 4 args, not 5.

- [ ] **Step 3: Implement — fswatch**

Change `spawn` to accept and forward the sender:

```rust
pub fn spawn(
    config_path: PathBuf,
    original_config: String,
    rules_path: Option<PathBuf>,
    rules: Arc<Mutex<MimeRules>>,
    rules_changed_tx: tokio::sync::mpsc::Sender<()>,
) {
    thread::spawn(move || {
        watch_forever(
            &config_path,
            &original_config,
            rules_path.as_deref(),
            &rules,
            &rules_changed_tx,
        )
    });
}
```

Change `watch_forever` to thread the sender through to `run`:

```rust
fn watch_forever(
    config_path: &Path,
    original_config: &str,
    rules_path: Option<&Path>,
    rules: &Arc<Mutex<MimeRules>>,
    rules_changed_tx: &tokio::sync::mpsc::Sender<()>,
) {
```

and inside its loop, change the `run(...)` call:

```rust
        if let Err(e) = run(config_path, rules_path, rules, &mut on_config_change, rules_changed_tx) {
            warn!("file watcher error ({e:#}); reconnecting");
        }
```

Change `run`'s signature and its rules-reload branch:

```rust
fn run(
    config_path: &Path,
    rules_path: Option<&Path>,
    rules: &Arc<Mutex<MimeRules>>,
    on_config_change: &mut dyn FnMut(),
    rules_changed_tx: &tokio::sync::mpsc::Sender<()>,
) -> Result<()> {
```

```rust
        if rules_changed {
            let changed = rules
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .reload_if_changed();
            // Only ping on a *real* external change. Our own writes (adopt /
            // version bump) return false here, so they don't trigger a spurious
            // bump-and-rebroadcast loop.
            if changed {
                let _ = rules_changed_tx.try_send(());
            }
        }
```

Update the existing `editing_the_rules_file_reloads_it` test to pass a dummy sender. Its `thread::spawn` closure becomes:

```rust
        let rules_w = rules.clone();
        let cfg_w = config_path.clone();
        let rules_path_w = rules_path.clone();
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        thread::spawn(move || {
            let mut noop = || {};
            let _ = run(&cfg_w, Some(&rules_path_w), &rules_w, &mut noop, &tx);
        });
```

- [ ] **Step 4: Implement — main.rs wiring**

In `src/main.rs`, after the `tracing_subscriber` init block (right after `.init();`), log the protocol version:

```rust
    tracing::info!("clipmesh protocol v{}", clipmesh::protocol::PROTOCOL_VERSION);
```

Update the `fswatch::spawn` call to pass the engine's sender:

```rust
    clipmesh::fswatch::spawn(
        config_path,
        original_config,
        rules_path,
        handle.mime_rules.clone(),
        handle.rules_changed_tx.clone(),
    );
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --lib fswatch:: && cargo build`
Expected: PASS — the new ping test and the existing fswatch tests pass; the binary compiles with the new `fswatch::spawn` arity.

- [ ] **Step 6: Commit**

```bash
git add src/fswatch.rs src/main.rs
git commit -m "feat: notify the engine to share rules on a watched file edit"
```

---

## Task 8: End-to-end — two nodes converge their rules file on connect

**Files:**
- Modify: `tests/two_nodes.rs`

- [ ] **Step 1: Write the failing test**

Add to `tests/two_nodes.rs`:

```rust
#[tokio::test]
async fn mime_rules_converge_on_connect() {
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let path_a = dir_a.path().join("mimetypes");
    let path_b = dir_b.path().join("mimetypes");
    let origin_a = uuid::Uuid::from_u128(0xA);
    // A's file is stamped 1h ahead (within the skew bound), so it wins.
    let high = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        + 60 * 60 * 1000;
    std::fs::write(
        &path_a,
        format!("# clipmesh-version: {high} {origin_a}\nimage/webp allow\n"),
    )
    .unwrap();
    std::fs::write(&path_b, "image/webp deny\n").unwrap();

    let clip_a = MockClipboard::new();
    let clip_b = MockClipboard::new();

    let mut cfg_a = Config::for_test("rules");
    cfg_a.share_mime_rules = true;
    cfg_a.mime_rules_path = Some(path_a.clone());
    let node_a = start(cfg_a, clip_a.clone()).await;

    let mut cfg_b = Config::for_test("rules");
    cfg_b.share_mime_rules = true;
    cfg_b.mime_rules_path = Some(path_b.clone());
    cfg_b.peers = vec![node_a.local_addr.to_string()];
    start(cfg_b, clip_b.clone()).await;

    let pb = path_b.clone();
    wait_for(
        move || {
            std::fs::read_to_string(&pb)
                .map(|s| s.contains("image/webp allow"))
                .unwrap_or(false)
        },
        "B to adopt A's newer rules file",
    )
    .await;
}
```

- [ ] **Step 2: Run test to verify it fails**

First run it against the current state — it should already pass once Tasks 4–7 are in. To see a meaningful RED, temporarily confirm the wiring by running it now:

Run: `cargo test --test two_nodes mime_rules_converge_on_connect`
Expected: PASS (the feature is implemented). If it FAILS, the failure pinpoints a wiring gap from Tasks 4–6 to fix before continuing.

> Note: this is an integration test added after the unit-level RED/GREEN cycles already proved each piece; it guards the assembled behaviour. If you are practising strict RED-first here, stash Task 6's `resync_rules_to` call, watch this fail, then restore it.

- [ ] **Step 3: Run the whole integration suite**

Run: `cargo test --test two_nodes`
Expected: PASS — the new test plus all existing two-node tests (which use `for_test`, sharing off).

- [ ] **Step 4: Commit**

```bash
git add tests/two_nodes.rs
git commit -m "test: two nodes converge their MIME-rules file on connect"
```

---

## Task 9: Documentation

**Files:**
- Modify: `examples/config.toml`
- Modify: `README.md`

- [ ] **Step 1: Document the option in the example config**

In `examples/config.toml`, in the "Everything below is optional (defaults shown)" block (after the `resync_on_connect` line), add:

```toml
# share_mime_rules = true    # share the MIME-rules file across the mesh (below)
```

And after the `unknown_mime` explanation block, add a paragraph:

```toml
# When share_mime_rules is on (default), clipmesh keeps the MIME-rules file in
# sync across the mesh: edit it on one host and the others converge to it. It is
# whole-file last-writer-wins — the most recently edited file wins outright and
# replaces the others (it does not merge per-type), and clipmesh stamps the file
# with a managed "# clipmesh-version:" header line to order edits. Turn it off to
# keep each host's rules independent.
```

- [ ] **Step 2: Document the behaviour in the README**

In `README.md`, in the "MIME type rules" section (after the bullet list describing how clipmesh manages the file), add:

```markdown
- With `share_mime_rules` (on by default), the rules file is kept in sync
  across the mesh: edit it on one host and the others converge to it. It is
  whole-file last-writer-wins — the most recently edited file wins outright and
  replaces the others rather than merging per-type, so a type one host had
  curated but another never saw is dropped when the older file loses (it
  reappears, deny-by-default, the next time that type is copied). clipmesh
  stamps the file with a managed `# clipmesh-version:` header line to order
  edits; every sharing host grows that line on first connect. A peer that flips
  a type to `allow` will make it sync on your host — that is the point. The
  password-manager `exclude_sensitive` filter is never shared and stays local.
  Set `share_mime_rules = false` to keep each host's rules independent.
```

Also, in the top-of-README feature bullet about MIME rules (the one mentioning "deny-by-default"), append a sentence:

```markdown
  By default the rules file is shared across the mesh (whole-file
  last-writer-wins); disable with `share_mime_rules = false`.
```

- [ ] **Step 3: Verify the docs build/read cleanly**

Run: `cargo build` (confirms `examples/config.toml` is still only a doc file, nothing references it) and re-read both files.
Expected: no code impact; prose is accurate.

- [ ] **Step 4: Commit**

```bash
git add examples/config.toml README.md
git commit -m "docs: document share_mime_rules and whole-file LWW behaviour"
```

---

## Task 10: Final verification

**Files:** none (verification only)

- [ ] **Step 1: Full test suite**

Run: `cargo test`
Expected: PASS — all unit and integration tests green.

- [ ] **Step 2: Lint and format**

Run: `cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: no warnings, no formatting diffs. Fix any issues, then re-run.

- [ ] **Step 3: Sanity-check the wire-compat note**

Confirm `PROTOCOL_VERSION` is logged at startup (grep `protocol v` in `main.rs`) and that the README/spec "upgrade all nodes together" guidance is present.

- [ ] **Step 4: Commit any fixups**

```bash
git add -A
git commit -m "chore: clippy/fmt fixups for share_mime_rules"
```

(Skip if there is nothing to commit.)
