//! inotify watcher for the config and MIME-rules files. Runs on a dedicated
//! thread (inotify reads block). A rules-file change reloads the shared ruleset
//! in place; a config-file change that still parses restarts the process (most
//! settings can't be hot-applied) — systemd brings the daemon straight back.
//!
//! The parent directories are watched (rather than the files directly) so that
//! editors which save by writing a temp file and renaming it into place are
//! handled; events are dispatched by file name. When a watched file is a
//! symlink, its resolved target's directory is watched too, so edits made
//! through the link (e.g. into a dotfiles repo) are seen.

use crate::config::Config;
use crate::fsutil::{is_symlink, parent_dir, resolve_link_target};
use crate::mime::{lock_rules, MimeRules};
use anyhow::{Context, Result};
use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use tracing::{debug, info, warn};

/// Which watched file an event pertains to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Target {
    Config,
    Rules,
}

impl Target {
    /// Every watched file. Used to iterate the re-resolve pass, which is
    /// order-independent (the targets are distinct files with distinct watches).
    const ALL: [Target; 2] = [Target::Config, Target::Rules];

    /// This target's slot in a [`PerTarget`] flag set — its position in [`ALL`],
    /// so `ALL` is the single hand-maintained list.
    ///
    /// Deriving it matters: with the slot numbers written out separately, adding
    /// a third watched file compiles as soon as the new match arm returns `2`,
    /// leaving `PerTarget`'s array to panic at runtime and `ALL` to silently skip
    /// the new target in the re-resolve pass. Now the array is sized from `ALL`
    /// and the lookup is derived from it, so there is nothing left to forget.
    ///
    /// [`ALL`]: Target::ALL
    fn index(self) -> usize {
        Self::ALL
            .iter()
            .position(|&t| t == self)
            .expect("ALL lists every Target")
    }

    fn label(self) -> &'static str {
        match self {
            Target::Config => "config file",
            Target::Rules => "MIME-rules file",
        }
    }
}

/// One flag per watched file. Replaces a hand-maintained set of parallel
/// booleans: each `Target` was previously spelled out separately at every site
/// that set or tested one, so a third watched file meant finding them all with
/// no help from the compiler.
#[derive(Default, Clone, Copy)]
struct PerTarget([bool; Target::ALL.len()]);

impl PerTarget {
    /// Every target flagged — what a dropped-event queue overflow implies.
    const ALL: PerTarget = PerTarget([true; Target::ALL.len()]);

    fn set(&mut self, target: Target) {
        self.0[target.index()] = true;
    }

    fn get(self, target: Target) -> bool {
        self.0[target.index()]
    }
}

/// Where a watch sits: the path itself (`Link`) or the resolved symlink
/// target (`Target`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Site {
    Link,
    Target,
}

/// Resolving a watched file's symlink target yields one of three states.
enum TargetSite {
    /// The path is not a symlink — there is no separate target to watch.
    NotSymlink,
    /// A symlink whose resolved target directory exists; watch this path (the
    /// file itself may be currently absent, so a recreate self-heals).
    Watch(PathBuf),
    /// A symlink whose resolved target has no directory to watch; carries the
    /// intended target for logging. Recovers when the link is repaired.
    Broken(PathBuf),
}

/// One registered watch. `path` is the watched file — its directory
/// (`parent_dir(path)`) is what inotify watches and `path.file_name()` is what
/// events are matched against; `wd` is that directory's descriptor. Storing the
/// single path keeps the directory and the name from ever disagreeing.
struct Entry {
    target: Target,
    site: Site,
    path: PathBuf,
    wd: WatchDescriptor,
}

impl Entry {
    /// Does an event with descriptor `wd` and file name `name` target this
    /// entry? (Same directory watch, same file name.)
    fn matches(&self, wd: &WatchDescriptor, name: &OsStr) -> bool {
        self.wd == *wd && self.path.file_name() == Some(name)
    }
}

/// Resolve a path's symlink target into a [`TargetSite`]: `NotSymlink` for a
/// plain file; `Watch` for a symlink whose target *directory* exists (watch it
/// even if the file itself is currently absent); `Broken` for a symlink with no
/// watchable target directory.
fn target_site(path: &Path) -> TargetSite {
    if !is_symlink(path) {
        return TargetSite::NotSymlink;
    }
    let resolved = resolve_link_target(path);
    // Watch the target's directory if it resolves to one. `is_dir()` alone
    // would fold a transient stat failure (EACCES/EIO) into "broken" silently;
    // distinguish a genuinely-missing dir from a stat error and log the latter
    // (it self-heals on the next link-site event), mirroring `is_symlink`.
    match fs::metadata(parent_dir(&resolved)) {
        Ok(m) if m.is_dir() => TargetSite::Watch(resolved),
        Ok(_) => TargetSite::Broken(resolved),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => TargetSite::Broken(resolved),
        Err(e) => {
            debug!(
                "can't stat the target directory of {} ({e}); treating it as broken for now",
                path.display()
            );
            TargetSite::Broken(resolved)
        }
    }
}

/// Spawn the watcher thread. A failure to set it up isn't fatal — the daemon
/// keeps running, just without auto-reload/restart until the watcher recovers.
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

/// Reconnect loop: a transient inotify error (EINTR, the watched directory
/// being recreated, ...) would otherwise kill auto-reload/restart for the
/// whole process lifetime. Instead we re-init with the same backoff the
/// clipboard watcher uses, so the feature rides out hiccups. `run` only
/// returns on error (its inner loop never ends), so every return reconnects.
fn watch_forever(
    config_path: &Path,
    original_config: &str,
    rules_path: Option<&Path>,
    rules: &Arc<Mutex<MimeRules>>,
    rules_changed_tx: &tokio::sync::mpsc::Sender<()>,
) {
    crate::backoff::supervise("file watcher", || {
        let mut on_config_change = || restart_on_config_change(config_path, original_config);
        // run() only returns on error; falling through reconnects.
        if let Err(e) = run(
            config_path,
            rules_path,
            rules,
            &mut on_config_change,
            rules_changed_tx,
        ) {
            warn!("file watcher error ({e:#}); reconnecting");
        }
        ControlFlow::Continue(())
    });
}

/// Add (or widen) the watch on `dir` to include `mask`, registering the UNION
/// of every mask requested for it — `inotify_add_watch` replaces rather than
/// ORs a mask, and one directory can host several files. Returns its descriptor.
fn ensure_watch(
    inotify: &mut Inotify,
    masks: &mut HashMap<PathBuf, WatchMask>,
    dir: &Path,
    mask: WatchMask,
) -> Result<WatchDescriptor> {
    let merged = masks
        .entry(dir.to_path_buf())
        .or_insert_with(WatchMask::empty);
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
    let link_mask = target_mask() | WatchMask::CREATE;

    let link_dir = parent_dir(path);
    let wd = ensure_watch(inotify, masks, &link_dir, link_mask)?;
    entries.push(Entry {
        target,
        site: Site::Link,
        path: path.to_path_buf(),
        wd,
    });

    match target_site(path) {
        TargetSite::Watch(target_path) => {
            let dir = parent_dir(&target_path);
            let wd = ensure_watch(inotify, masks, &dir, target_mask())?;
            info!(
                "{} {} is a symlink; also watching its target directory {}",
                target.label(),
                path.display(),
                dir.display()
            );
            entries.push(Entry {
                target,
                site: Site::Target,
                path: target_path,
                wd,
            });
        }
        TargetSite::NotSymlink => {}
        TargetSite::Broken(intended) => warn!(
            "{} {} is a broken symlink (target {} has no directory to watch); \
             it will be picked up if the link is repaired",
            target.label(),
            path.display(),
            intended.display()
        ),
    }
    Ok(())
}

/// Events on a watched file's real directory that mean its contents settled: a
/// completed write, or an atomic replace via rename. Both registration sites
/// (initial and re-resolve) share this, so the two can't drift apart and start
/// watching for different events.
fn target_mask() -> WatchMask {
    WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO
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
    let desired: Option<PathBuf> = match target_site(path) {
        TargetSite::NotSymlink => None,
        TargetSite::Watch(target_path) => Some(target_path),
        TargetSite::Broken(intended) => {
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
    let current = pos.map(|i| entries[i].path.clone());
    if current == desired {
        return;
    }

    let old = pos.map(|i| entries.remove(i));
    if let Some(target_path) = desired {
        let dir = parent_dir(&target_path);
        match ensure_watch(inotify, masks, &dir, target_mask()) {
            Ok(wd) => {
                info!(
                    "{} {} symlink target changed; now watching {}",
                    target.label(),
                    path.display(),
                    dir.display()
                );
                entries.push(Entry {
                    target,
                    site: Site::Target,
                    path: target_path,
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
        // EINVAL is expected when the directory was deleted (the kernel
        // auto-removes the watch via IN_IGNORED); log anything else at debug
        // so an unexpected failure (a watch-bookkeeping smell) stays greppable.
        if !entries.iter().any(|e| e.wd == old.wd) {
            // Drop the directory's mask bookkeeping too, so `masks` doesn't grow
            // unbounded as a symlink is repointed across directories over time.
            masks.remove(&parent_dir(&old.path));
            if let Err(e) = inotify.watches().remove(old.wd) {
                debug!(
                    "removing the stale watch for {} failed ({e}); likely already auto-removed",
                    old.path.display()
                );
            }
        }
    }
}

/// The inotify loop. Calls `on_config_change` when the config file changes and
/// reloads `rules` when the rules file changes. Returns only on error.
///
/// Each watched file is followed through a symlink: the link's own directory
/// AND (for a symlink) the resolved target's directory are watched, and events
/// are matched against a `(wd, name)` table. A bare CREATE only drives a read
/// when the entry is a symlink — a regular file's CREATE fires before its
/// contents are written.
fn run(
    config_path: &Path,
    rules_path: Option<&Path>,
    rules: &Arc<Mutex<MimeRules>>,
    on_config_change: &mut dyn FnMut(),
    rules_changed_tx: &tokio::sync::mpsc::Sender<()>,
) -> Result<()> {
    let mut inotify = Inotify::init().context("initializing inotify")?;

    // Per-directory registered mask (so re-adding a dir registers the union)
    // and the table of (wd, name) → which file/site, matched against events.
    let mut masks: HashMap<PathBuf, WatchMask> = HashMap::new();
    let mut entries: Vec<Entry> = Vec::new();

    add_file_watches(
        &mut inotify,
        &mut masks,
        &mut entries,
        Target::Config,
        config_path,
    )?;
    if let Some(rp) = rules_path {
        add_file_watches(&mut inotify, &mut masks, &mut entries, Target::Rules, rp)?;
    }
    info!("watching config and MIME-rule files for changes");

    // The one place a target maps back to its path. `None` for the rules file
    // when none is configured.
    let path_of = |target: Target| -> Option<&Path> {
        match target {
            Target::Config => Some(config_path),
            Target::Rules => rules_path,
        }
    };

    // Sized to hold a burst of events in one read (each is a small struct plus
    // the file name) so an editor's flurry of temp-file writes is read at once.
    let mut buf = [0u8; 8192];
    loop {
        let events = inotify
            .read_events_blocking(&mut buf)
            .context("reading inotify events")?;
        let mut changed = PerTarget::default();
        let mut reresolve = PerTarget::default();

        for event in events {
            if event.mask.contains(EventMask::Q_OVERFLOW) {
                // The kernel dropped events under load; re-check (and re-resolve)
                // both files. The rules reload is idempotent and the config check
                // only restarts on a real, parseable content change.
                warn!("inotify event queue overflowed; re-checking config and MIME rules");
                changed = PerTarget::ALL;
                reresolve = PerTarget::ALL;
                continue;
            }
            let Some(name) = event.name else { continue };
            for entry in &entries {
                if !entry.matches(&event.wd, name) {
                    continue;
                }
                let is_write = event
                    .mask
                    .intersects(EventMask::CLOSE_WRITE | EventMask::MOVED_TO);
                // A complete write drives a read. A bare CREATE only matters when
                // the entry is a symlink — a regular file's CREATE fires before
                // its contents are written, so reading it would see an empty or
                // partial file. `is_symlink` re-stats the path live (not
                // `entry.site`): a just-created symlink was registered as a
                // Link-site regular-file watch, so its symlink-ness is only
                // knowable now — don't "simplify" this to `entry.site`.
                let act =
                    is_write || (event.mask.contains(EventMask::CREATE) && is_symlink(&entry.path));
                if !act {
                    continue;
                }
                changed.set(entry.target);
                // A change at the link site may mean the symlink itself was
                // (re)created/repointed; re-resolve its target watch below.
                if entry.site == Site::Link {
                    reresolve.set(entry.target);
                }
            }
        }

        for target in Target::ALL {
            if let (true, Some(path)) = (reresolve.get(target), path_of(target)) {
                reconcile_target(&mut inotify, &mut masks, &mut entries, target, path);
            }
        }

        // Reload rules before (possibly) restarting on a config change, so a
        // simultaneous edit to both still takes effect.
        if changed.get(Target::Rules) {
            let changed = lock_rules(rules).reload_if_changed();
            // Only ping on a *real* external change. Our own writes (adopt /
            // version bump / materialise) return false here, so they don't
            // trigger a spurious bump-and-rebroadcast loop.
            if changed {
                let _ = rules_changed_tx.try_send(());
            }
        }
        if changed.get(Target::Config) {
            on_config_change();
        }
    }
}

/// What to do when the config file changes.
#[derive(Debug, PartialEq, Eq)]
enum ConfigChange {
    /// The new config is usable; restart to apply it.
    Restart,
    /// The new config can't be read or parsed; keep the current one.
    KeepRunning,
}

/// Decide whether a config change should restart the daemon. Restarts only when
/// the file's contents actually differ from `original` AND still parse — so a
/// bare `touch` (or an event we can't attribute, e.g. after a queue overflow)
/// doesn't trigger a spurious restart, and a typo (or a transient read failure,
/// e.g. caught mid-rename) keeps the daemon running rather than looping it under
/// systemd's Restart=always.
fn config_change_action(config_path: &Path, original: &str) -> ConfigChange {
    let current = match std::fs::read_to_string(config_path) {
        Ok(t) => t,
        Err(e) => {
            warn!(
                "config file {} changed but can't be read ({e}); keeping the current configuration",
                config_path.display()
            );
            return ConfigChange::KeepRunning;
        }
    };
    if current == original {
        return ConfigChange::KeepRunning; // unchanged content
    }
    match Config::from_toml(&current) {
        Ok(_) => ConfigChange::Restart,
        Err(e) => {
            warn!(
                "config file {} changed but doesn't parse ({e:#}); keeping the current configuration",
                config_path.display()
            );
            ConfigChange::KeepRunning
        }
    }
}

/// Restart the process if the changed config is usable; otherwise log and keep
/// running. Splitting the decision out (above) keeps the `exit(0)` out of the
/// testable path.
fn restart_on_config_change(config_path: &Path, original: &str) {
    if config_change_action(config_path, original) == ConfigChange::Restart {
        info!(
            "config file {} changed; restarting to apply it",
            config_path.display()
        );
        // Clean exit; the systemd unit (Restart=always) starts a fresh process
        // with the new config. Abrupt by design — we want a from-scratch reload
        // rather than trying to hot-apply settings.
        std::process::exit(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MimePolicy;
    use std::time::{Duration, Instant};

    /// Poll `done` until it holds, running `poke` before each check, and panic
    /// with `what` if it never does.
    ///
    /// The poke is *repeated* on purpose: registering an inotify watch races the
    /// test thread, so a single write can land before the watch is live and be
    /// missed forever. Re-poking each round is what makes these tests
    /// deterministic rather than flaky. Pass a no-op poke to wait passively.
    fn poll_until(mut poke: impl FnMut(), mut done: impl FnMut() -> bool, what: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            poke();
            if done() {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("{what}");
    }

    /// Run the inotify loop under test on its own thread with a no-op
    /// config-change callback.
    ///
    /// A test that needs to observe the config-change callback firing spawns
    /// `run` inline with its own closure instead.
    fn spawn_watcher(
        config: &Path,
        rules_path: Option<&Path>,
        rules: &Arc<Mutex<MimeRules>>,
        tx: &tokio::sync::mpsc::Sender<()>,
    ) {
        let config = config.to_path_buf();
        let rules_path = rules_path.map(Path::to_path_buf);
        let rules = rules.clone();
        let tx = tx.clone();
        thread::spawn(move || {
            let mut noop = || {};
            let _ = run(&config, rules_path.as_deref(), &rules, &mut noop, &tx);
        });
    }

    #[test]
    fn target_site_resolves_a_symlinked_file_to_its_real_dir() {
        let dir = tempfile::tempdir().unwrap();
        let real_dir = dir.path().join("dotfiles");
        std::fs::create_dir(&real_dir).unwrap();
        std::fs::write(real_dir.join("mimetypes"), "x").unwrap();
        let link = dir.path().join("mimetypes");
        std::os::unix::fs::symlink(real_dir.join("mimetypes"), &link).unwrap();
        let TargetSite::Watch(p) = target_site(&link) else {
            panic!("a symlink yields a watchable target site");
        };
        assert_eq!(parent_dir(&p), real_dir);
        assert_eq!(p.file_name(), Some(std::ffi::OsStr::new("mimetypes")));
    }

    #[test]
    fn target_site_watches_an_existing_dir_even_when_the_file_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let real_dir = dir.path().join("dotfiles");
        std::fs::create_dir(&real_dir).unwrap();
        // Target file does NOT exist yet, but its directory does.
        let link = dir.path().join("config.toml");
        std::os::unix::fs::symlink(real_dir.join("config.toml"), &link).unwrap();
        let TargetSite::Watch(p) = target_site(&link) else {
            panic!("dir exists → expected a watchable target site");
        };
        assert_eq!(parent_dir(&p), real_dir);
    }

    #[test]
    fn target_site_is_notsymlink_for_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("config.toml");
        std::fs::write(&f, "x").unwrap();
        assert!(matches!(target_site(&f), TargetSite::NotSymlink));
    }

    #[test]
    fn target_site_is_broken_when_the_target_dir_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("config.toml");
        let missing = dir.path().join("nope/config.toml");
        std::os::unix::fs::symlink(&missing, &link).unwrap();
        // Broken carries the resolved intended target, used for the warning log.
        let TargetSite::Broken(intended) = target_site(&link) else {
            panic!("a symlink whose target dir is missing must be Broken");
        };
        assert_eq!(intended, missing);
    }

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

        spawn_watcher(&config_path, Some(&rules_link), &rules, &tx);

        // Edit the REAL file (in the dotfiles dir), not the symlink path.
        poll_until(
            || std::fs::write(&real_rules, "[rules]\n\"image/png\" = \"allow\"\n").unwrap(),
            || rx.try_recv().is_ok(),
            "editing the symlink target did not ping the engine",
        );
    }

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

        spawn_watcher(&config_path, Some(&rules_path), &rules, &tx);

        // 1. Establish the watch is live: rewrite until a ping lands, then drain.
        poll_until(
            || std::fs::write(&rules_path, "[rules]\n\"image/png\" = \"deny\"\n").unwrap(),
            || rx.try_recv().is_ok(),
            "watcher never went live",
        );
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
        poll_until(
            || {},
            || rx.try_recv().is_ok(),
            "the CLOSE_WRITE after writing content should have pinged",
        );
    }

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
        spawn_watcher(&config_path, Some(&link), &rules, &tx);

        // Let the watch go live on A (edit A until a ping lands), then drain.
        poll_until(
            || std::fs::write(&a, "[rules]\n\"image/png\" = \"allow\"\n").unwrap(),
            || rx.try_recv().is_ok(),
            "watcher never went live on A",
        );
        while rx.try_recv().is_ok() {}

        // Repoint the symlink to B (ln -sf = unlink + symlink → CREATE at link site).
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&b, &link).unwrap();
        thread::sleep(Duration::from_millis(300)); // let reconcile + repoint reload settle
        while rx.try_recv().is_ok() {}

        // Now edits to B must ping — only possible if B's dir is being watched.
        poll_until(
            || std::fs::write(&b, "[rules]\n\"image/png\" = \"allow\"\n").unwrap(),
            || rx.try_recv().is_ok(),
            "edits to the repointed target B were not picked up",
        );
    }

    #[test]
    fn editing_a_symlinked_config_target_triggers_on_config_change() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let dir = tempfile::tempdir().unwrap();

        // The real config lives in a separate dir; a symlink points to it.
        let dotfiles = dir.path().join("dotfiles");
        std::fs::create_dir(&dotfiles).unwrap();
        let real_config = dotfiles.join("config.toml");
        std::fs::write(&real_config, "listen = \"x\"\npsk = \"s\"\n").unwrap();
        let config_link = dir.path().join("config.toml");
        std::os::unix::fs::symlink(&real_config, &config_link).unwrap();

        // No rules file — keep the test focused on the config path.
        let rules = Arc::new(Mutex::new(MimeRules::load(None, MimePolicy::Deny)));
        let (tx, _rx) = tokio::sync::mpsc::channel(8);

        // The real daemon would exit(0) here; the test signals instead so it can
        // assert the config change was actually observed through the symlink.
        let fired = Arc::new(AtomicBool::new(false));
        let fired_w = fired.clone();
        let rules_w = rules.clone();
        let link_w = config_link.clone();
        let tx_w = tx.clone();
        thread::spawn(move || {
            let mut on_change = move || fired_w.store(true, Ordering::SeqCst);
            let _ = run(&link_w, None, &rules_w, &mut on_change, &tx_w);
        });

        // Edit the REAL config file (in the dotfiles dir), not the symlink path.
        poll_until(
            || std::fs::write(&real_config, "listen = \"y\"\npsk = \"s\"\n").unwrap(),
            || fired.load(Ordering::SeqCst),
            "editing the symlinked config target did not trigger on_config_change",
        );
    }

    #[test]
    fn a_repaired_broken_rules_symlink_is_picked_up() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, "listen = \"x\"\npsk = \"s\"\n").unwrap();

        // The symlink points into a dotfiles dir that does NOT exist yet, so it
        // is broken at startup: load() reads an empty ruleset and the watcher
        // adds no target entry (only the link site).
        let dotfiles = dir.path().join("dotfiles");
        let real_rules = dotfiles.join("mimetypes");
        let link = dir.path().join("mimetypes");
        std::os::unix::fs::symlink(&real_rules, &link).unwrap();

        let rules = Arc::new(Mutex::new(MimeRules::load(
            Some(link.clone()),
            MimePolicy::Deny,
        )));
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        spawn_watcher(&config_path, Some(&link), &rules, &tx);

        // Repair: create the target's dir + file, then re-point the link in a
        // retry loop. Each re-point (unlink + symlink) fires a link-site CREATE
        // that re-resolves the now-watchable target (the `pos == None` branch of
        // reconcile_target, adding the first target entry) and reloads the rules.
        std::fs::create_dir(&dotfiles).unwrap();
        std::fs::write(&real_rules, "[rules]\n\"image/png\" = \"allow\"\n").unwrap();
        poll_until(
            || {
                let _ = std::fs::remove_file(&link);
                std::os::unix::fs::symlink(&real_rules, &link).unwrap();
            },
            || rx.try_recv().is_ok(),
            "the repaired broken symlink was not picked up",
        );
    }

    #[test]
    fn config_change_action_restarts_only_for_a_changed_usable_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let original = "listen = \"x\"\npsk = \"s\"\n";

        // Same content (e.g. a bare `touch`): no restart, even though it parses.
        std::fs::write(&path, original).unwrap();
        assert_eq!(
            config_change_action(&path, original),
            ConfigChange::KeepRunning
        );

        // Changed and still parses: restart to apply it.
        std::fs::write(&path, "listen = \"y\"\npsk = \"s\"\n").unwrap();
        assert_eq!(config_change_action(&path, original), ConfigChange::Restart);

        // Changed but doesn't parse: keep running, so a typo can't put us into a
        // restart loop under systemd's Restart=always.
        std::fs::write(&path, "this = is = not = toml").unwrap();
        assert_eq!(
            config_change_action(&path, original),
            ConfigChange::KeepRunning
        );

        // An unreadable/missing file: keep running rather than crash.
        std::fs::remove_file(&path).unwrap();
        assert_eq!(
            config_change_action(&path, original),
            ConfigChange::KeepRunning
        );
    }

    #[test]
    fn editing_the_rules_file_pings_the_engine() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, "listen = \"x\"\npsk = \"s\"\n").unwrap();
        let rules_path = dir.path().join("mimetypes");
        std::fs::write(&rules_path, "[rules]\n\"image/png\" = \"deny\"\n").unwrap();
        let rules = Arc::new(Mutex::new(MimeRules::load(
            Some(rules_path.clone()),
            MimePolicy::Deny,
        )));
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);

        spawn_watcher(&config_path, Some(&rules_path), &rules, &tx);

        poll_until(
            || std::fs::write(&rules_path, "[rules]\n\"image/png\" = \"allow\"\n").unwrap(),
            || rx.try_recv().is_ok(),
            "editing the rules file did not ping the engine",
        );
    }

    #[test]
    fn an_unchanged_rewrite_does_not_ping_the_engine() {
        // Loop-prevention guard: an inotify CLOSE_WRITE whose content matches
        // what we already loaded (e.g. the engine's own adopt/bump/materialise
        // write) must NOT ping — otherwise our writes would re-broadcast forever.
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, "listen = \"x\"\npsk = \"s\"\n").unwrap();
        let rules_path = dir.path().join("mimetypes");
        std::fs::write(&rules_path, "[rules]\n\"image/png\" = \"deny\"\n").unwrap();
        let rules = Arc::new(Mutex::new(MimeRules::load(
            Some(rules_path.clone()),
            MimePolicy::Deny,
        )));
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);

        spawn_watcher(&config_path, Some(&rules_path), &rules, &tx);

        // Establish the watch and confirm a real change pings (this also makes
        // the watcher's loaded snapshot become "image/png allow\n").
        poll_until(
            || std::fs::write(&rules_path, "[rules]\n\"image/png\" = \"allow\"\n").unwrap(),
            || rx.try_recv().is_ok(),
            "watcher never delivered the initial change ping",
        );
        // Drain any further pings from the establishment phase.
        while rx.try_recv().is_ok() {}

        // Rewrite identical content: CLOSE_WRITE fires, but reload_if_changed()
        // returns false (content == loaded), so NO ping must be sent.
        std::fs::write(&rules_path, "[rules]\n\"image/png\" = \"allow\"\n").unwrap();
        thread::sleep(Duration::from_millis(300));
        assert!(
            rx.try_recv().is_err(),
            "an unchanged rewrite must not ping the engine (loop-prevention)"
        );
    }

    #[test]
    fn editing_the_rules_file_reloads_it() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, "listen = \"x\"\npsk = \"s\"\n").unwrap();
        let rules_path = dir.path().join("mimetypes");
        std::fs::write(&rules_path, "[rules]\n\"image/png\" = \"deny\"\n").unwrap();
        let rules = Arc::new(Mutex::new(MimeRules::load(
            Some(rules_path.clone()),
            MimePolicy::Deny,
        )));
        assert!(!rules.lock().unwrap().allows("image/png", 1));

        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        spawn_watcher(&config_path, Some(&rules_path), &rules, &tx);

        // Rewrite the file each iteration rather than sleeping a fixed amount
        // and writing once: if the watch isn't registered yet, a later write's
        // CLOSE_WRITE is still caught once it is — no timing assumption, so the
        // test isn't flaky under load.
        poll_until(
            || std::fs::write(&rules_path, "[rules]\n\"image/png\" = \"allow\"\n").unwrap(),
            || rules.lock().unwrap().allows("image/png", 1),
            "rules file change was not picked up by the inotify watcher",
        );
    }
}
