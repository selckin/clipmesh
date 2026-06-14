//! inotify watcher for the config and MIME-rules files. Runs on a dedicated
//! thread (inotify reads block). A rules-file change reloads the shared ruleset
//! in place; a config-file change that still parses restarts the process (most
//! settings can't be hot-applied) — systemd brings the daemon straight back.
//!
//! The parent directories are watched (rather than the files directly) so that
//! editors which save by writing a temp file and renaming it into place are
//! handled; events are dispatched by file name.

use crate::config::Config;
use crate::mime::MimeRules;
use anyhow::{Context, Result};
use inotify::{EventMask, Inotify, WatchMask};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tracing::{info, warn};

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
    const RESTART_MIN: Duration = Duration::from_secs(1);
    const RESTART_MAX: Duration = Duration::from_secs(30);
    /// A run shorter than this counts as a failure and escalates backoff.
    const STABLE_AFTER: Duration = Duration::from_secs(5);

    let mut delay = RESTART_MIN;
    loop {
        let started = Instant::now();
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
        delay = crate::backoff::next_delay(
            delay,
            started.elapsed(),
            RESTART_MIN,
            RESTART_MAX,
            STABLE_AFTER,
        );
        warn!("restarting the file watcher in {delay:?}");
        thread::sleep(delay);
    }
}

/// The inotify loop. Calls `on_config_change` when the config file changes and
/// reloads `rules` when the rules file changes. Returns only on error.
fn run(
    config_path: &Path,
    rules_path: Option<&Path>,
    rules: &Arc<Mutex<MimeRules>>,
    on_config_change: &mut dyn FnMut(),
    rules_changed_tx: &tokio::sync::mpsc::Sender<()>,
) -> Result<()> {
    let mut inotify = Inotify::init().context("initializing inotify")?;

    let config_name = config_path.file_name();
    let rules_name = rules_path.and_then(Path::file_name);

    // Watch each distinct parent directory (commonly just one — both files
    // live in ~/.config/clipmesh).
    let mut dirs: Vec<PathBuf> = vec![watch_dir(config_path)];
    if let Some(rp) = rules_path {
        let d = watch_dir(rp);
        if !dirs.contains(&d) {
            dirs.push(d);
        }
    }
    // Trigger only on events that signal a COMPLETE write: CLOSE_WRITE (in-place
    // edits) and MOVED_TO (atomic temp-file-rename saves). Deliberately NOT
    // CREATE: it fires the instant a file is created — before the editor has
    // written its contents — so reacting to it reads an empty/partial file. A
    // freshly-created file still fires CLOSE_WRITE once the editor closes it.
    let mask = WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO;
    for dir in &dirs {
        inotify
            .watches()
            .add(dir, mask)
            .with_context(|| format!("watching {}", dir.display()))?;
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
        for event in events {
            if event.mask.contains(EventMask::Q_OVERFLOW) {
                // The kernel dropped events under load; we don't know what we
                // missed, so re-check both files. The rules reload is cheap and
                // idempotent, and the config check only restarts if the file's
                // contents actually changed (so this can't spuriously restart).
                warn!("inotify event queue overflowed; re-checking config and MIME rules");
                rules_changed = true;
                config_changed = true;
                continue;
            }
            let Some(name) = event.name else { continue };
            if Some(name) == config_name {
                config_changed = true;
            } else if rules_name.is_some() && Some(name) == rules_name {
                rules_changed = true;
            }
        }
        // Reload rules before (possibly) restarting on a config change, so a
        // simultaneous edit to both still takes effect.
        if rules_changed {
            let changed = rules
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .reload_if_changed();
            // Only ping on a *real* external change. Our own writes (adopt /
            // version bump / materialise) return false here, so they don't
            // trigger a spurious bump-and-rebroadcast loop.
            if changed {
                let _ = rules_changed_tx.try_send(());
            }
        }
        if config_changed {
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

/// The directory to watch for a file: its parent, or "." when the path is a
/// bare file name.
fn watch_dir(path: &Path) -> PathBuf {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MimePolicy;
    use std::time::{Duration, Instant};

    #[test]
    fn watch_dir_uses_the_parent_or_falls_back_to_dot() {
        assert_eq!(watch_dir(Path::new("/a/b/c")), PathBuf::from("/a/b"));
        // A bare file name has an empty parent; watch the current directory.
        assert_eq!(watch_dir(Path::new("config.toml")), PathBuf::from("."));
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
            std::fs::write(&rules_path, "[rules]\n\"image/png\" = \"allow\"\n").unwrap();
            if rx.try_recv().is_ok() {
                return; // got a ping — success
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("editing the rules file did not ping the engine");
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

        let rules_w = rules.clone();
        let cfg_w = config_path.clone();
        let rules_path_w = rules_path.clone();
        let tx_w = tx.clone();
        thread::spawn(move || {
            let mut noop = || {};
            let _ = run(&cfg_w, Some(&rules_path_w), &rules_w, &mut noop, &tx_w);
        });

        // Establish the watch and confirm a real change pings (this also makes
        // the watcher's loaded snapshot become "image/png allow\n").
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if Instant::now() >= deadline {
                panic!("watcher never delivered the initial change ping");
            }
            std::fs::write(&rules_path, "[rules]\n\"image/png\" = \"allow\"\n").unwrap();
            if rx.try_recv().is_ok() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
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

        let rules_w = rules.clone();
        let cfg_w = config_path.clone();
        let rules_path_w = rules_path.clone();
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        thread::spawn(move || {
            let mut noop = || {};
            let _ = run(&cfg_w, Some(&rules_path_w), &rules_w, &mut noop, &tx);
        });

        // Rewrite the file each iteration rather than sleeping a fixed amount
        // and writing once: if the watch isn't registered yet, a later write's
        // CLOSE_WRITE is still caught once it is — no timing assumption, so the
        // test isn't flaky under load.
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            std::fs::write(&rules_path, "[rules]\n\"image/png\" = \"allow\"\n").unwrap();
            if rules.lock().unwrap().allows("image/png", 1) {
                return; // reloaded — success
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("rules file change was not picked up by the inotify watcher");
    }
}
