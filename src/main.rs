use anyhow::{bail, Context, Result};
use clipmesh::clipboard::wayland::WaylandClipboard;
use clipmesh::config::{self, Config, MimePolicy};
use clipmesh::config_template;
use clipmesh::mime::{MimeRules, Relation, RulesFileState, Verdict};
use clipmesh::{node, paste};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const USAGE: &str =
    "usage: clipmesh [--config <path>] [--allow <glob> | --deny <glob> | --rules | --sync-config]\n\
     \x20      clipmesh --paste [-t <mime>] [-l] [-n] [-p] [--node <host[:port]>]  (wl-paste mode)";

/// Decide paste mode from the program name and the args (everything after
/// argv[0]). Paste mode is entered when the binary is invoked as `wl-paste`
/// (a symlink), or when `--paste` appears in the args. Returns the wl-paste-style
/// args (with any `--paste` stripped) in that case, else `None` for the daemon /
/// normal CLI. Checked before the daemon flag loop so wl-paste flags (`-t`,
/// `-l`, …), which that loop would reject, reach the paste parser instead.
fn paste_mode_args(prog: &str, args: &[String]) -> Option<Vec<String>> {
    let invoked_as_wl_paste = Path::new(prog)
        .file_name()
        .is_some_and(|f| f.to_string_lossy() == "wl-paste");
    let has_paste_flag = args.iter().any(|a| a == "--paste");
    if invoked_as_wl_paste || has_paste_flag {
        Some(args.iter().filter(|a| *a != "--paste").cloned().collect())
    } else {
        None
    }
}

/// A one-shot CLI action (none = run the daemon).
enum CliAction {
    Edit { allow: bool, pattern: String },
    PrintRules,
    SyncConfig,
}

#[tokio::main]
async fn main() -> Result<()> {
    // wl-paste impersonation is a distinct mode: detect it before the daemon
    // flag loop (which would reject wl-paste's own flags) and delegate.
    let argv: Vec<String> = std::env::args().collect();
    if let Some(paste_args) = paste_mode_args(
        argv.first().map(String::as_str).unwrap_or("clipmesh"),
        argv.get(1..).unwrap_or(&[]),
    ) {
        // Quiet stderr-only logging (clipboard bytes go to stdout): surfaces a
        // warning from the reused connection stack without polluting the output.
        init_cli_logging();
        return paste::run(paste_args).await;
    }

    let mut config_path: Option<PathBuf> = None;
    let mut action: Option<CliAction> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        // Each flag may appear once, and the actions are mutually exclusive — a
        // repeat (or two actions) is a usage error rather than silently last-wins.
        match arg.as_str() {
            "--config" if config_path.is_some() => bail!(USAGE),
            "--config" => config_path = Some(PathBuf::from(args.next().context(USAGE)?)),
            "--allow" | "--deny" | "--rules" | "--sync-config" if action.is_some() => bail!(USAGE),
            "--allow" | "--deny" => {
                let pattern = args.next().context(USAGE)?;
                action = Some(CliAction::Edit {
                    allow: arg == "--allow",
                    pattern,
                });
            }
            "--rules" => action = Some(CliAction::PrintRules),
            "--sync-config" => action = Some(CliAction::SyncConfig),
            _ => bail!(USAGE),
        }
    }
    let config_path = config_path.unwrap_or_else(config::default_config_path);

    // The CLI actions are one-shot (not the daemon): apply and exit. A running
    // daemon picks up an edit through its file watcher.
    match action {
        Some(CliAction::Edit { allow, pattern }) => {
            return apply_rule_edit(&config_path, allow, &pattern)
        }
        Some(CliAction::PrintRules) => return print_rules(&config_path),
        Some(CliAction::SyncConfig) => return sync_config_action(&config_path),
        None => {}
    }

    let cfg = Arc::new(Config::load(&config_path)?);

    let filter = match tracing_subscriber::EnvFilter::try_from_default_env() {
        Ok(f) => f,
        Err(_) => tracing_subscriber::EnvFilter::try_new(&cfg.log_level)
            .with_context(|| format!("invalid log_level {:?} in config", cfg.log_level))?,
    };
    // No timestamp (the systemd journal already stamps every line) and no
    // module-path target, so journalctl output stays short and readable.
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .without_time()
        .with_target(false)
        .init();
    tracing::info!(
        "clipmesh protocol v{}",
        clipmesh::protocol::PROTOCOL_VERSION
    );

    // Which selections get watched is the engine's call, made when it
    // subscribes (see Clipboard::watch) — the backend needs no config for it.
    let clipboard = Arc::new(WaylandClipboard::new(cfg.max_payload_size));
    let rules_path = cfg.mime_rules_path.clone();
    // The config text as loaded, so a change is only acted on when the contents
    // really differ (not a bare touch). Empty on a read error — any later edit
    // then differs.
    let original_config = std::fs::read_to_string(&config_path).unwrap_or_default();
    let handle = node::spawn_node(cfg, clipboard).await?;
    // Watch the config and MIME-rules files (inotify). A rules edit reloads in
    // place on the watcher thread; a config edit is only *reported* here, since
    // ending the process is this function's call to make, not a watcher's.
    let (config_changed_tx, mut config_changed_rx) = tokio::sync::mpsc::channel(1);
    clipmesh::fswatch::spawn(
        config_path.clone(),
        rules_path,
        handle.mime_rules.clone(),
        handle.rules_changed_tx.clone(),
        config_changed_tx,
    );
    let mut engine_task = handle.engine_task;
    loop {
        tokio::select! {
            joined = &mut engine_task => {
                joined.context("sync engine panicked")?;
                break;
            }
            // A closed channel (the watcher gone for good) disables this branch
            // instead of spinning on it: the daemon keeps syncing, just without
            // restart-on-config-change.
            Some(()) = config_changed_rx.recv() => {
                restart_on_config_change(&config_path, &original_config)
            }
        }
    }
    // The engine never stops in normal operation; exit non-zero so systemd
    // (Restart=always) brings the daemon back.
    bail!("sync engine exited unexpectedly");
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
            tracing::warn!(
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
            tracing::warn!(
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
        tracing::info!(
            "config file {} changed; restarting to apply it",
            config_path.display()
        );
        // Clean exit; the systemd unit (Restart=always) starts a fresh process
        // with the new config. Abrupt by design — we want a from-scratch reload
        // rather than trying to hot-apply settings.
        std::process::exit(0);
    }
}

/// Normalize the config file (fill in missing options + comments) and exit.
fn sync_config_action(config_path: &Path) -> Result<()> {
    match config_template::sync_config(config_path)? {
        config_template::SyncOutcome::Unchanged => {
            println!("config {} is already up to date", config_path.display());
        }
        config_template::SyncOutcome::Rewrote { added } => {
            if added.is_empty() {
                println!("refreshed comments in {}", config_path.display());
            } else {
                println!(
                    "wrote {} ({} option(s) added as commented defaults: {})",
                    config_path.display(),
                    added.len(),
                    added.join(", ")
                );
            }
        }
    }
    Ok(())
}

/// Resolve the MIME rules path from the config and read the file for a one-shot
/// CLI command, through `MimeRules::open` — the constructor that never writes.
///
/// Which constructor is used is the whole point. `MimeRules::load` heals a file
/// it can't parse by replacing it with a fresh skeleton, dropping the
/// `[clipmesh]` mesh version with it; no CLI command may take that path just
/// because the user has a typo in their file. Reaching for `open` refuses it
/// here, once, for every command — and for any command added later.
///
/// So a file that exists but can't be used is a hard error, and the returned
/// `Err(RulesFileState)` only ever means "nothing on disk yet". Each command
/// answers that its own way: a writer creates the file, a reader says so and
/// stops.
fn open_rules_file(
    config_path: &Path,
) -> Result<(Config, PathBuf, Result<MimeRules, RulesFileState>)> {
    let cfg = Config::load(config_path)?;
    let path = cfg
        .mime_rules_path
        .clone()
        .context("no MIME rules file is configured")?;
    let opened = match MimeRules::open(Some(path.clone()), cfg.unknown_mime) {
        Err(RulesFileState::Malformed(e)) => {
            return Err(e)
                .with_context(|| format!("{} isn't valid TOML — fix or delete it", path.display()))
        }
        Err(RulesFileState::Unreadable(e)) => {
            return Err(e).with_context(|| format!("reading {}", path.display()))
        }
        opened => opened,
    };
    Ok((cfg, path, opened))
}

/// Apply a single `--allow`/`--deny` glob to the MIME-rules file and exit. Any
/// existing entries the new glob now covers are removed and echoed back so the
/// user can re-add the ones they want to keep as exceptions.
fn apply_rule_edit(config_path: &Path, allow: bool, pattern: &str) -> Result<()> {
    if pattern.trim().is_empty() {
        bail!("the --allow/--deny pattern must not be empty");
    }
    init_cli_logging();

    let (cfg, path, opened) = open_rules_file(config_path)?;
    // Nothing on disk yet is no obstacle to a writer: fall back to the healing
    // constructor, which creates the file from the built-in skeleton and then
    // takes the edit.
    let mut rules =
        opened.unwrap_or_else(|_| MimeRules::load(Some(path.clone()), cfg.unknown_mime));
    let removed = rules.apply_glob(allow, pattern);
    if !rules.persist() {
        bail!("couldn't write the MIME rules file {}", path.display());
    }

    let verb = clipmesh::mime::rule_word(allow);
    println!("Set \"{pattern}\" = \"{verb}\" in {}", path.display());
    if !removed.is_empty() {
        println!(
            "\nRemoved {} rule(s) now covered by \"{pattern}\" = \"{verb}\":",
            removed.len()
        );
        for line in &removed {
            println!("  {line}");
        }
        println!("\nRe-add any you want to keep as exceptions.");
    }
    Ok(())
}

/// Print the current MIME rules and, for each, any other glob that also matches
/// its key (redundant duplicates and precedence conflicts). Read-only — never
/// creates or rewrites the file.
fn print_rules(config_path: &Path) -> Result<()> {
    init_cli_logging();
    let (cfg, path, opened) = open_rules_file(config_path)?;
    let rules = match opened {
        Ok(rules) => rules,
        // Only "nothing on disk yet" reaches here — a file that exists but can't
        // be used came back as an error above — so there is nothing to list.
        Err(state) => {
            println!(
                "{}",
                match state {
                    RulesFileState::Empty =>
                        format!("The MIME rules file {} is empty.", path.display()),
                    _ => format!("No MIME rules file yet at {}", path.display()),
                }
            );
            return Ok(());
        }
    };
    let report = rules.rules_report();
    let default = match cfg.unknown_mime {
        MimePolicy::Allow => "✅ allow",
        MimePolicy::Deny => "⛔ deny",
    };
    println!(
        "{} rule(s) in {}   (unmatched types: {default})\n",
        report.len(),
        path.display(),
    );
    // Colour the glob wildcards, but only on a real terminal (and honouring
    // NO_COLOR), so piped/redirected output stays plain.
    let color = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
    // Align the key column to the widest key (by *visible* width, ignoring any
    // colour escapes we add).
    let key_w = report
        .iter()
        .map(|e| e.key.chars().count())
        .max()
        .unwrap_or(0);
    for entry in &report {
        let cap = entry
            .max
            .as_deref()
            .map(|m| format!("   ≤ {m}"))
            .unwrap_or_default();
        let pad = " ".repeat(key_w.saturating_sub(entry.key.chars().count()));
        let line = format!(
            "{}  {}{pad}{cap}",
            verdict_label(entry.verdict),
            colorize_globs(&entry.key, color),
        );
        println!("{}", line.trim_end());
        for o in &entry.overlaps {
            let relation = match o.relation {
                Relation::Redundant => "redundant, already covered by",
                Relation::Overrides => "overrides",
                Relation::OverriddenBy => "overridden by (more specific)",
                Relation::DecidesInstead => "decided instead by",
            };
            println!(
                "     ↳ {relation} {} {}",
                verdict_icon(o.verdict),
                colorize_globs(&o.key, color),
            );
        }
    }
    Ok(())
}

/// A verdict as the `--rules` listing writes it: the icon, then the word padded
/// to the width of the longest ("invalid") so the key column that follows lines
/// up.
///
/// The icon needs padding of its own, which is the part no format width can
/// express: `⚠️` is emoji-presentation by variation selector and renders one
/// column narrower than `✅`/`⛔` in most terminals, so it takes a second space
/// to land the word where the other two rows put it. That is a rendered-width
/// correction, not a character count — `{word:<7}` after a single space would
/// pull the whole invalid row one column left.
fn verdict_label(v: Verdict) -> String {
    let (word, icon_pad) = match v {
        Verdict::Allow => ("allow", " "),
        Verdict::Deny => ("deny", " "),
        Verdict::Invalid => ("invalid", "  "),
    };
    format!("{}{icon_pad}{word:<7}", verdict_icon(v))
}

/// Just the emoji for a verdict, for inline overlap references.
fn verdict_icon(v: Verdict) -> &'static str {
    match v {
        Verdict::Allow => "✅",
        Verdict::Deny => "⛔",
        Verdict::Invalid => "⚠️",
    }
}

/// Highlight the glob wildcards (`*`/`?`) in a key with colour, so globs stand
/// out from literal keys. Returns the key unchanged when `color` is false.
fn colorize_globs(key: &str, color: bool) -> String {
    const WILDCARD: &str = "\x1b[1;33m"; // bold yellow
    const RESET: &str = "\x1b[0m";
    if !color || !key.bytes().any(|b| b == b'*' || b == b'?') {
        return key.to_string();
    }
    let mut out = String::new();
    for c in key.chars() {
        if c == '*' || c == '?' {
            out.push_str(WILDCARD);
            out.push(c);
            out.push_str(RESET);
        } else {
            out.push(c);
        }
    }
    out
}

/// A minimal stderr subscriber for the one-shot CLI paths, which run before
/// `main()` installs the daemon's configured subscriber — so a `MimeRules`
/// warning (a write error, a file about to be reset) still reaches the user.
fn init_cli_logging() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .without_time()
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn paste_mode_via_flag_strips_the_paste_marker() {
        let got = paste_mode_args("clipmesh", &args(&["--paste", "-t", "text/plain"]));
        assert_eq!(got, Some(args(&["-t", "text/plain"])));
    }

    #[test]
    fn paste_mode_via_wl_paste_symlink() {
        // a symlink named wl-paste anywhere on PATH enters paste mode
        assert_eq!(
            paste_mode_args("/usr/local/bin/wl-paste", &args(&["-l"])),
            Some(args(&["-l"]))
        );
    }

    #[test]
    fn normal_invocations_are_not_paste_mode() {
        assert_eq!(paste_mode_args("clipmesh", &args(&["--rules"])), None);
        assert_eq!(paste_mode_args("clipmesh", &[]), None);
        assert_eq!(
            paste_mode_args("/usr/bin/clipmesh", &args(&["--config", "/c"])),
            None
        );
    }

    /// The listing's key column is aligned by these labels alone, and the
    /// correction for `⚠️`'s narrower rendering is invisible in the source. Pin
    /// the bytes, so a future tidy-up that "simplifies" the padding away has to
    /// argue with a test rather than silently skew a column.
    #[test]
    fn verdict_labels_render_to_one_aligned_column() {
        assert_eq!(verdict_label(Verdict::Allow), "✅ allow  ");
        assert_eq!(verdict_label(Verdict::Deny), "⛔ deny   ");
        assert_eq!(verdict_label(Verdict::Invalid), "⚠️  invalid");
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
}
