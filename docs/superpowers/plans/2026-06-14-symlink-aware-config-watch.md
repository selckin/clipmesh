# Symlink-aware config/rules watching — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `fswatch` detect edits to `config.toml`/`mimetypes` reached through a symlink (the dotfiles-repo setup), self-heal when a symlink is repointed/repaired, and emit clear startup diagnostics for a broken symlink.

**Architecture:** The watcher gains a second watch *site* per file — the symlink's resolved **target** directory — alongside today's link-site (parent-directory) watch. Events are matched against a small `(wd, name)` table; a bare `CREATE` only drives a read when the entry is a symlink, preserving today's empty-file protection. After each event batch, any file whose link fired is re-resolved and its target watch reconciled.

**Tech Stack:** Rust, `inotify` 0.11 (`Watches::add`/`remove`, `WatchDescriptor`), `anyhow`, `tracing`. Tests use `tempfile` + `std::os::unix::fs::symlink`, mirroring the existing deadline-loop integration tests in `fswatch.rs`.

---

## File Structure

- **`src/fswatch.rs`** — the bulk of the change. New resolution helpers and types, a rewritten `run()` that builds and dispatches a two-site watch table, and new tests. The reconnect loop (`watch_forever`), the config-change decision (`config_change_action` / `restart_on_config_change`), and `watch_dir` are unchanged.
- **`src/config.rs`** — `Config::load` gains a broken-symlink diagnostic (a few lines + a tiny helper + a test).
- **`src/mime.rs`** — `MimeRules::read_file`'s `NotFound` branch gains a broken-symlink warning (a few lines + a tiny helper + a test).

---

## Task 1: Resolution helpers and watch-table types

Pure helpers and plain types, unit-tested with `tempfile`. No behavior wired in yet.

**Files:**
- Modify: `src/fswatch.rs` (imports near the top; new types + helpers after the `use` block, before `run`)
- Test: `src/fswatch.rs` (`#[cfg(test)] mod tests`)

- [ ] **Step 1: Extend the imports**

In `src/fswatch.rs`, replace the inotify import and add three std imports. Current:

```rust
use inotify::{EventMask, Inotify, WatchMask};
use std::path::{Path, PathBuf};
```

becomes:

```rust
use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
```

- [ ] **Step 2: Write the failing tests**

Add to the `tests` module in `src/fswatch.rs`:

```rust
#[test]
fn resolve_link_target_follows_a_relative_symlink_against_its_own_dir() {
    let dir = tempfile::tempdir().unwrap();
    let real_dir = dir.path().join("dotfiles");
    std::fs::create_dir(&real_dir).unwrap();
    let real = real_dir.join("config.toml");
    std::fs::write(&real, "x").unwrap();
    // Relative link, like GNU Stow: config.toml -> dotfiles/config.toml
    let link = dir.path().join("config.toml");
    std::os::unix::fs::symlink("dotfiles/config.toml", &link).unwrap();
    assert_eq!(resolve_link_target(&link), real);
}

#[test]
fn target_site_resolves_a_symlinked_file_to_its_real_dir() {
    let dir = tempfile::tempdir().unwrap();
    let real_dir = dir.path().join("dotfiles");
    std::fs::create_dir(&real_dir).unwrap();
    std::fs::write(real_dir.join("mimetypes"), "x").unwrap();
    let link = dir.path().join("mimetypes");
    std::os::unix::fs::symlink(real_dir.join("mimetypes"), &link).unwrap();
    let site = target_site(&link).unwrap().expect("a symlink yields a target site");
    assert_eq!(site.dir, real_dir);
    assert_eq!(site.name, std::ffi::OsStr::new("mimetypes"));
}

#[test]
fn target_site_watches_an_existing_dir_even_when_the_file_is_absent() {
    let dir = tempfile::tempdir().unwrap();
    let real_dir = dir.path().join("dotfiles");
    std::fs::create_dir(&real_dir).unwrap();
    // Target file does NOT exist yet, but its directory does.
    let link = dir.path().join("config.toml");
    std::os::unix::fs::symlink(real_dir.join("config.toml"), &link).unwrap();
    let site = target_site(&link).unwrap().expect("dir exists → watch it");
    assert_eq!(site.dir, real_dir);
}

#[test]
fn target_site_is_none_for_a_regular_file() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("config.toml");
    std::fs::write(&f, "x").unwrap();
    assert!(target_site(&f).unwrap().is_none());
}

#[test]
fn target_site_errors_when_the_target_dir_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let link = dir.path().join("config.toml");
    std::os::unix::fs::symlink(dir.path().join("nope/config.toml"), &link).unwrap();
    assert!(target_site(&link).is_err());
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test --lib fswatch::tests::target_site 2>&1 | tail -20`
Expected: FAIL to compile — `resolve_link_target`, `target_site`, `SitePath` not found.

- [ ] **Step 4: Add the types and helpers**

Insert after the `use` block (before `pub fn spawn`) in `src/fswatch.rs`:

```rust
/// Which watched file an event pertains to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Target {
    Config,
    Rules,
}

impl Target {
    fn label(self) -> &'static str {
        match self {
            Target::Config => "config file",
            Target::Rules => "MIME-rules file",
        }
    }
}

/// Where a watch sits: the path itself (`Link`) or the resolved symlink
/// target (`Target`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Site {
    Link,
    Target,
}

/// A directory plus the file name to match within it.
struct SitePath {
    dir: PathBuf,
    name: OsString,
}

/// One registered watch: the `(dir, name)` events are matched against, tagged
/// with which file and site it represents, plus its inotify descriptor.
struct Entry {
    target: Target,
    site: Site,
    dir: PathBuf,
    name: OsString,
    wd: WatchDescriptor,
}

/// True if `path` is itself a symlink (does not follow it).
fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

/// The link site for a path: its own parent directory and file name — exactly
/// what the watcher has always watched.
fn link_site(path: &Path) -> SitePath {
    SitePath {
        dir: watch_dir(path),
        name: path.file_name().unwrap_or_default().to_os_string(),
    }
}

/// Follow a symlink to the file it ultimately names, resolving each relative
/// hop against the directory of the link being followed (stow's default links
/// are relative). Stops at the first non-symlink or unreadable component and
/// returns the deepest path reached, which may or may not exist.
fn resolve_link_target(path: &Path) -> PathBuf {
    const MAX_HOPS: usize = 8;
    let mut current = path.to_path_buf();
    for _ in 0..MAX_HOPS {
        match fs::read_link(&current) {
            Ok(target) if target.is_absolute() => current = target,
            Ok(target) => {
                let base = current.parent().unwrap_or_else(|| Path::new("."));
                current = base.join(target);
            }
            Err(_) => break,
        }
    }
    current
}

/// The target site for a path:
/// - `Ok(None)` when it is not a symlink,
/// - `Ok(Some(site))` when it is a symlink whose target *directory* exists
///   (watch that directory even if the file itself is currently absent),
/// - `Err(intended)` when the resolved target has no directory to watch.
fn target_site(path: &Path) -> std::result::Result<Option<SitePath>, PathBuf> {
    if !is_symlink(path) {
        return Ok(None);
    }
    let resolved = resolve_link_target(path);
    let dir = watch_dir(&resolved);
    if dir.is_dir() {
        Ok(Some(SitePath {
            dir,
            name: resolved.file_name().unwrap_or_default().to_os_string(),
        }))
    } else {
        Err(resolved)
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --lib fswatch::tests::target_site fswatch::tests::resolve_link_target 2>&1 | tail -20`
Expected: PASS (5 tests). `dead_code` warnings for the as-yet-unused types are fine — `run` uses them in Task 2.

- [ ] **Step 6: Commit**

```bash
git add src/fswatch.rs
git commit -m "feat: add symlink resolution helpers and watch-table types for fswatch"
```

---

## Task 2: Two-site watch table in `run()`

Rewrite `run()` to register a link-site and (for symlinks) a target-site watch per file, dispatch by `(wd, name)`, gate bare `CREATE`s on the entry being a symlink, and reconcile target watches after each batch. This fixes the core bug and adds self-healing.

**Files:**
- Modify: `src/fswatch.rs` (replace `run`; add `ensure_watch`, `add_file_watches`, `reconcile_target` above it)
- Test: `src/fswatch.rs` (`tests` module)

- [ ] **Step 1: Write the failing integration test (symlink target watched)**

Add to the `tests` module:

```rust
#[test]
fn editing_a_symlinked_rules_target_pings_the_engine() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    std::fs::write(&config_path, "listen = \"x\"\npsk = \"s\"\n").unwrap();

    // The real rules file lives in a separate dir; a symlink points to it.
    let dotfiles = dir.path().join("dotfiles");
    std::fs::create_dir(&dotfiles).unwrap();
    let real_rules = dotfiles.join("mimetypes");
    std::fs::write(&real_rules, "[rules]\n\"image/png\" = \"deny\"\n").unwrap();
    let rules_link = dir.path().join("mimetypes");
    std::os::unix::fs::symlink(&real_rules, &rules_link).unwrap();

    let rules = Arc::new(Mutex::new(MimeRules::load(
        Some(rules_link.clone()),
        MimePolicy::Deny,
    )));
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);

    let rules_w = rules.clone();
    let cfg_w = config_path.clone();
    let link_w = rules_link.clone();
    let tx_w = tx.clone();
    thread::spawn(move || {
        let mut noop = || {};
        let _ = run(&cfg_w, Some(&link_w), &rules_w, &mut noop, &tx_w);
    });

    // Edit the REAL file (in the dotfiles dir), not the symlink path.
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        std::fs::write(&real_rules, "[rules]\n\"image/png\" = \"allow\"\n").unwrap();
        if rx.try_recv().is_ok() {
            return; // ping received — the symlink target dir is watched
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("editing the symlink target did not ping the engine");
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --lib fswatch::tests::editing_a_symlinked_rules_target_pings_the_engine 2>&1 | tail -20`
Expected: FAIL — the test times out and panics (today only the symlink's own directory is watched, so edits to the real file are missed).

- [ ] **Step 3: Add `ensure_watch`, `add_file_watches`, `reconcile_target`**

Insert these three functions just above `fn run(` in `src/fswatch.rs`:

```rust
/// Add (or widen) the watch on `dir` to include `mask`, registering the UNION
/// of every mask requested for it — `inotify_add_watch` replaces rather than
/// ORs a mask, and one directory can host several files. Returns its descriptor.
fn ensure_watch(
    inotify: &mut Inotify,
    masks: &mut HashMap<PathBuf, WatchMask>,
    dir: &Path,
    mask: WatchMask,
) -> Result<WatchDescriptor> {
    let merged = masks.entry(dir.to_path_buf()).or_insert_with(WatchMask::empty);
    *merged |= mask;
    inotify
        .watches()
        .add(dir, *merged)
        .with_context(|| format!("watching {}", dir.display()))
}

/// Register the link-site watch (always) and, for a symlink, the target-site
/// watch for one file. A broken symlink logs and adds no target watch.
fn add_file_watches(
    inotify: &mut Inotify,
    masks: &mut HashMap<PathBuf, WatchMask>,
    entries: &mut Vec<Entry>,
    target: Target,
    path: &Path,
) -> Result<()> {
    // CREATE is needed at the link site to notice a symlink created by
    // symlink(2) (e.g. stow's `ln -sf`), which emits no CLOSE_WRITE/MOVED_TO.
    let link_mask = WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO | WatchMask::CREATE;
    let target_mask = WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO;

    let link = link_site(path);
    let wd = ensure_watch(inotify, masks, &link.dir, link_mask)?;
    entries.push(Entry {
        target,
        site: Site::Link,
        dir: link.dir,
        name: link.name,
        wd,
    });

    match target_site(path) {
        Ok(Some(site)) => {
            let wd = ensure_watch(inotify, masks, &site.dir, target_mask)?;
            info!(
                "{} {} is a symlink; also watching its target directory {}",
                target.label(),
                path.display(),
                site.dir.display()
            );
            entries.push(Entry {
                target,
                site: Site::Target,
                dir: site.dir,
                name: site.name,
                wd,
            });
        }
        Ok(None) => {}
        Err(intended) => warn!(
            "{} {} is a broken symlink (target {} has no directory to watch); \
             it will be picked up if the link is repaired",
            target.label(),
            path.display(),
            intended.display()
        ),
    }
    Ok(())
}

/// Re-resolve a file's target site after its link fired (the symlink may have
/// been (re)created or repointed) and update the target-site entry to match:
/// add the new directory's watch, drop the old entry, and remove the old kernel
/// watch when nothing else references it.
fn reconcile_target(
    inotify: &mut Inotify,
    masks: &mut HashMap<PathBuf, WatchMask>,
    entries: &mut Vec<Entry>,
    target: Target,
    path: &Path,
) {
    let desired = match target_site(path) {
        Ok(opt) => opt,
        Err(intended) => {
            warn!(
                "{} {} is now a broken symlink (target {} has no directory to watch)",
                target.label(),
                path.display(),
                intended.display()
            );
            None
        }
    };

    let pos = entries
        .iter()
        .position(|e| e.target == target && e.site == Site::Target);
    let current = pos.map(|i| (entries[i].dir.clone(), entries[i].name.clone()));
    let want = desired.as_ref().map(|s| (s.dir.clone(), s.name.clone()));
    if current == want {
        return;
    }

    let old = pos.map(|i| entries.remove(i));
    if let Some(site) = desired {
        let target_mask = WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO;
        match ensure_watch(inotify, masks, &site.dir, target_mask) {
            Ok(wd) => {
                info!(
                    "{} {} symlink target changed; now watching {}",
                    target.label(),
                    path.display(),
                    site.dir.display()
                );
                entries.push(Entry {
                    target,
                    site: Site::Target,
                    dir: site.dir,
                    name: site.name,
                    wd,
                });
            }
            Err(e) => warn!(
                "couldn't watch the new symlink target directory for {}: {e:#}",
                path.display()
            ),
        }
    }
    if let Some(old) = old {
        // Remove the old kernel watch only if no remaining entry uses it.
        // Ignore errors: a deleted directory's watch is auto-removed
        // (IN_IGNORED), so remove() then returns EINVAL — expected.
        if !entries.iter().any(|e| e.wd == old.wd) {
            let _ = inotify.watches().remove(old.wd);
        }
    }
}
```

- [ ] **Step 4: Replace `run()`**

Replace the entire existing `fn run(...) -> Result<()> { ... }` (the inotify loop, from its signature through its closing brace) with:

```rust
fn run(
    config_path: &Path,
    rules_path: Option<&Path>,
    rules: &Arc<Mutex<MimeRules>>,
    on_config_change: &mut dyn FnMut(),
    rules_changed_tx: &tokio::sync::mpsc::Sender<()>,
) -> Result<()> {
    let mut inotify = Inotify::init().context("initializing inotify")?;

    // Per-directory registered mask (so re-adding a dir registers the union)
    // and the table of (dir, name) → which file/site, matched against events.
    let mut masks: HashMap<PathBuf, WatchMask> = HashMap::new();
    let mut entries: Vec<Entry> = Vec::new();

    add_file_watches(&mut inotify, &mut masks, &mut entries, Target::Config, config_path)?;
    if let Some(rp) = rules_path {
        add_file_watches(&mut inotify, &mut masks, &mut entries, Target::Rules, rp)?;
    }
    info!("watching config and MIME-rule files for changes");

    // Sized to hold a burst of events in one read (each is a small struct plus
    // the file name) so an editor's flurry of temp-file writes is read at once.
    let mut buf = [0u8; 8192];
    loop {
        let events = inotify
            .read_events_blocking(&mut buf)
            .context("reading inotify events")?;
        let mut config_changed = false;
        let mut rules_changed = false;
        let mut reresolve_config = false;
        let mut reresolve_rules = false;

        for event in events {
            if event.mask.contains(EventMask::Q_OVERFLOW) {
                // The kernel dropped events; re-check (and re-resolve) both
                // files. The rules reload is idempotent and the config check
                // only restarts on a real, parseable content change.
                warn!("inotify event queue overflowed; re-checking config and MIME rules");
                config_changed = true;
                rules_changed = true;
                reresolve_config = true;
                reresolve_rules = true;
                continue;
            }
            let Some(name) = event.name else { continue };
            for entry in &entries {
                if entry.wd != event.wd || entry.name.as_os_str() != name {
                    continue;
                }
                let is_write = event
                    .mask
                    .intersects(EventMask::CLOSE_WRITE | EventMask::MOVED_TO);
                // A complete write drives a read. A bare CREATE only matters
                // when the entry is a symlink — a regular file's CREATE fires
                // before its contents are written, so reading it would see an
                // empty/partial file.
                let act = is_write
                    || (event.mask.contains(EventMask::CREATE)
                        && is_symlink(&entry.dir.join(&entry.name)));
                if !act {
                    continue;
                }
                match entry.target {
                    Target::Config => config_changed = true,
                    Target::Rules => rules_changed = true,
                }
                // A change at the link site may mean the symlink itself was
                // (re)created/repointed; re-resolve its target watch below.
                if entry.site == Site::Link {
                    match entry.target {
                        Target::Config => reresolve_config = true,
                        Target::Rules => reresolve_rules = true,
                    }
                }
            }
        }

        if reresolve_config {
            reconcile_target(&mut inotify, &mut masks, &mut entries, Target::Config, config_path);
        }
        if reresolve_rules {
            if let Some(rp) = rules_path {
                reconcile_target(&mut inotify, &mut masks, &mut entries, Target::Rules, rp);
            }
        }

        // Reload rules before (possibly) restarting on a config change, so a
        // simultaneous edit to both still takes effect.
        if rules_changed {
            let changed = rules
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .reload_if_changed();
            // Only ping on a *real* external change. Our own writes return
            // false here, so they don't trigger a bump-and-rebroadcast loop.
            if changed {
                let _ = rules_changed_tx.try_send(());
            }
        }
        if config_changed {
            on_config_change();
        }
    }
}
```

- [ ] **Step 5: Run the new test and the full suite**

Run: `cargo test --lib fswatch 2>&1 | tail -25`
Expected: PASS — `editing_a_symlinked_rules_target_pings_the_engine` plus all existing `fswatch` tests (`editing_the_rules_file_pings_the_engine`, `an_unchanged_rewrite_does_not_ping_the_engine`, `editing_the_rules_file_reloads_it`, `config_change_action_*`, `watch_dir_*`) and Task 1's tests.

- [ ] **Step 6: Commit**

```bash
git add src/fswatch.rs
git commit -m "feat: watch the symlink target of config/rules files"
```

---

## Task 3: Regression test for the bare-CREATE guard

Prove a regular file's `CREATE` (now in the link-site mask) drives nothing until its `CLOSE_WRITE`.

**Files:**
- Test: `src/fswatch.rs` (`tests` module)

- [ ] **Step 1: Write the test**

Add to the `tests` module:

```rust
#[test]
fn a_bare_create_of_a_regular_rules_file_does_not_ping_until_written() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    std::fs::write(&config_path, "listen = \"x\"\npsk = \"s\"\n").unwrap();
    let rules_path = dir.path().join("mimetypes");
    let rules = Arc::new(Mutex::new(MimeRules::load(
        Some(rules_path.clone()),
        MimePolicy::Deny,
    )));
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);

    let rules_w = rules.clone();
    let cfg_w = config_path.clone();
    let rp_w = rules_path.clone();
    let tx_w = tx.clone();
    thread::spawn(move || {
        let mut noop = || {};
        let _ = run(&cfg_w, Some(&rp_w), &rules_w, &mut noop, &tx_w);
    });

    // 1. Establish the watch is live: rewrite until a ping lands, then drain.
    let live = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(Instant::now() < live, "watcher never went live");
        std::fs::write(&rules_path, "[rules]\n\"image/png\" = \"deny\"\n").unwrap();
        if rx.try_recv().is_ok() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    while rx.try_recv().is_ok() {}

    // 2. Delete, then create-and-HOLD: a bare CREATE with no close yet.
    std::fs::remove_file(&rules_path).unwrap();
    let mut f = std::fs::File::create(&rules_path).unwrap();
    thread::sleep(Duration::from_millis(300));
    assert!(
        rx.try_recv().is_err(),
        "a bare CREATE of a regular file must not ping (empty-file guard)"
    );

    // 3. Write content + close → CLOSE_WRITE must ping.
    write!(f, "[rules]\n\"image/png\" = \"allow\"\n").unwrap();
    drop(f);
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if rx.try_recv().is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("the CLOSE_WRITE after writing content should have pinged");
}
```

- [ ] **Step 2: Run it**

Run: `cargo test --lib fswatch::tests::a_bare_create_of_a_regular_rules_file_does_not_ping_until_written 2>&1 | tail -20`
Expected: PASS — the guard implemented in Task 2 already makes this hold; this locks it in.

- [ ] **Step 3: Commit**

```bash
git add src/fswatch.rs
git commit -m "test: a bare CREATE of a regular rules file does not ping until written"
```

---

## Task 4: Self-heal test — repointing the symlink

Prove that after the symlink is repointed to a new target, edits to the new target are picked up (the target watch followed via `reconcile_target`).

**Files:**
- Test: `src/fswatch.rs` (`tests` module)

- [ ] **Step 1: Write the test**

Add to the `tests` module:

```rust
#[test]
fn repointing_the_rules_symlink_follows_to_the_new_target() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    std::fs::write(&config_path, "listen = \"x\"\npsk = \"s\"\n").unwrap();

    let a_dir = dir.path().join("a");
    let b_dir = dir.path().join("b");
    std::fs::create_dir(&a_dir).unwrap();
    std::fs::create_dir(&b_dir).unwrap();
    let a = a_dir.join("mimetypes");
    let b = b_dir.join("mimetypes");
    std::fs::write(&a, "[rules]\n\"image/png\" = \"deny\"\n").unwrap();
    std::fs::write(&b, "[rules]\n\"image/png\" = \"deny\"\n").unwrap();

    let link = dir.path().join("mimetypes");
    std::os::unix::fs::symlink(&a, &link).unwrap();

    let rules = Arc::new(Mutex::new(MimeRules::load(
        Some(link.clone()),
        MimePolicy::Deny,
    )));
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let rules_w = rules.clone();
    let cfg_w = config_path.clone();
    let link_w = link.clone();
    let tx_w = tx.clone();
    thread::spawn(move || {
        let mut noop = || {};
        let _ = run(&cfg_w, Some(&link_w), &rules_w, &mut noop, &tx_w);
    });

    // Let the watch go live on A (edit A until a ping lands), then drain.
    let live = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(Instant::now() < live, "watcher never went live on A");
        std::fs::write(&a, "[rules]\n\"image/png\" = \"allow\"\n").unwrap();
        if rx.try_recv().is_ok() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    while rx.try_recv().is_ok() {}

    // Repoint the symlink to B (ln -sf = unlink + symlink → CREATE at link site).
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&b, &link).unwrap();
    thread::sleep(Duration::from_millis(300)); // let reconcile + repoint reload settle
    while rx.try_recv().is_ok() {}

    // Now edits to B must ping — only possible if B's dir is being watched.
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        std::fs::write(&b, "[rules]\n\"image/png\" = \"allow\"\n").unwrap();
        if rx.try_recv().is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("edits to the repointed target B were not picked up");
}
```

- [ ] **Step 2: Run it**

Run: `cargo test --lib fswatch::tests::repointing_the_rules_symlink_follows_to_the_new_target 2>&1 | tail -20`
Expected: PASS — `reconcile_target` moves the target watch from `a/` to `b/` on the repoint `CREATE`.

- [ ] **Step 3: Commit**

```bash
git add src/fswatch.rs
git commit -m "test: repointing the rules symlink follows to the new target"
```

---

## Task 5: Broken-symlink diagnostic in `Config::load`

**Files:**
- Modify: `src/config.rs` (`load`; add a tiny helper; import `anyhow::anyhow` is NOT needed — uses `bail!`)
- Test: `src/config.rs` (`#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `src/config.rs` (create the module if absent, using the form below):

```rust
#[test]
fn load_reports_a_broken_config_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let link = dir.path().join("config.toml");
    std::os::unix::fs::symlink(dir.path().join("missing.toml"), &link).unwrap();
    let err = Config::load(&link).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("symlink"), "message should mention the symlink: {msg}");
    assert!(msg.contains("missing.toml"), "message should name the target: {msg}");
}
```

If `src/config.rs` has no `tests` module yet, add at the end of the file:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // (test from above goes here)
}
```

If a `tests` module already exists, add the test inside it and skip the wrapper.

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --lib config::tests::load_reports_a_broken_config_symlink 2>&1 | tail -20`
Expected: FAIL — the error message is the generic "reading config …", missing "symlink"/"missing.toml".

- [ ] **Step 3: Implement the diagnostic**

In `src/config.rs`, replace the first two lines of `Config::load`:

```rust
    pub fn load(path: &Path) -> Result<Config> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
```

with:

```rust
    pub fn load(path: &Path) -> Result<Config> {
        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if path_is_symlink(path) => {
                let target = fs::read_link(path)
                    .map(|t| t.display().to_string())
                    .unwrap_or_else(|_| "?".to_string());
                bail!(
                    "config {} is a symlink to {}, which can't be read ({e})",
                    path.display(),
                    target
                );
            }
            Err(e) => {
                return Err(e).with_context(|| format!("reading config {}", path.display()));
            }
        };
```

Add this free function near the bottom of `src/config.rs` (outside `impl Config`):

```rust
/// True if `path` is a symlink. After a failed read this means the link is
/// dangling — its target is missing or unreadable.
fn path_is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `cargo test --lib config::tests::load_reports_a_broken_config_symlink 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/config.rs
git commit -m "feat: name the dangling target when a config symlink can't be read"
```

---

## Task 6: Broken-symlink warning in `MimeRules::read_file`

**Files:**
- Modify: `src/mime.rs` (`read_file` `NotFound` branch; add a tiny helper)
- Test: `src/mime.rs` (`tests` module)

- [ ] **Step 1: Write the test**

Add to the `tests` module in `src/mime.rs`:

```rust
#[test]
fn a_broken_rules_symlink_loads_empty_and_materializes_at_the_target() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("real-mimetypes"); // does not exist yet
    let link = dir.path().join("mimetypes");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let rules = MimeRules::load(Some(link.clone()), MimePolicy::Deny);
    // Deny-by-default empty ruleset, and the fresh skeleton is written through
    // the (previously broken) symlink, creating the target.
    assert!(!rules.allows("image/png", 1));
    assert!(
        target.exists(),
        "a fresh skeleton should be materialized at the symlink target"
    );
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --lib mime::tests::a_broken_rules_symlink_loads_empty_and_materializes_at_the_target 2>&1 | tail -20`
Expected: FAIL to compile only if `MimePolicy` isn't imported in the mime tests module — if it fails to compile for that reason, add `use crate::config::MimePolicy;` to the `tests` module. Otherwise it should PASS at the behavior level even before Step 3 (materialization already works); Step 3 adds the warning. If it already passes, still do Step 3 to add the diagnostic, then re-run.

> Note: this test asserts behavior that largely holds today; its purpose is to lock in the broken-symlink path while Step 3 adds the operator-facing warning. The warning text itself isn't asserted (no log subscriber in unit tests).

- [ ] **Step 3: Add the warning**

In `src/mime.rs`, find the `NotFound` arm of `read_file`:

```rust
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
```

Replace it with:

```rust
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if path_is_symlink(&path) {
                    warn!(
                        "MIME-rules file {} is a symlink whose target is missing; \
                         starting from an empty ruleset (a fresh one is created on \
                         the next write)",
                        path.display()
                    );
                }
                let _ = e; // the NotFound itself isn't an error here
                true
            }
```

Add this free function near the bottom of `src/mime.rs` (outside `impl MimeRules`):

```rust
/// True if `path` is a symlink. Combined with a NotFound read, the link is
/// dangling (its target doesn't exist).
fn path_is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `cargo test --lib mime::tests::a_broken_rules_symlink_loads_empty_and_materializes_at_the_target 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/mime.rs
git commit -m "feat: warn when the MIME-rules file is a dangling symlink"
```

---

## Task 7: Full verification

**Files:** none (verification only)

- [ ] **Step 1: Build, lint, and run the whole suite**

Run: `cargo build 2>&1 | tail -5 && cargo clippy --all-targets 2>&1 | tail -15 && cargo test 2>&1 | tail -30`
Expected: clean build, no new clippy warnings in changed files, all tests (lib + `tests/two_nodes.rs`) green.

- [ ] **Step 2: Commit any lint fixups**

```bash
git add -A
git commit -m "chore: clippy fixups for symlink-aware watching" || echo "nothing to fix up"
```

---

## Notes for the implementer

- **Don't change `run`'s signature.** The existing tests call `run(&cfg, Some(&rules), &rules_arc, &mut closure, &tx)`; keep it identical so they compile unchanged.
- **`watch_dir` and the reconnect loop stay as-is.** A broken symlink yields no target watch (not an error), so it never forces the `watch_forever` backoff loop.
- **Writes already follow symlinks.** `mime.rs::write_file` uses `fs::write`, which follows the link and updates the target in place; the resulting `CLOSE_WRITE` lands on the target-site watch and is de-duplicated by `reload_if_changed` (content compare) — no rebroadcast loop. No change needed there.
- **Timing in tests:** mirror the existing pattern — rewrite-in-a-loop against a 5 s deadline rather than a single fixed sleep — so a not-yet-registered watch isn't a flake source. The one unavoidable fixed sleep (the bare-CREATE hold, the post-repoint settle) is bounded and used only where a one-shot event can't be retried.
