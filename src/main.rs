use anyhow::{bail, Context, Result};
use clipmesh::clipboard::wayland::WaylandClipboard;
use clipmesh::config::{Config, MimePolicy};
use clipmesh::mime::{MimeRules, Relation, Verdict};
use clipmesh::node;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const USAGE: &str = "usage: clipmesh [--config <path>] [--allow <glob> | --deny <glob> | --rules]";

/// A one-shot CLI action (none = run the daemon).
enum CliAction {
    Edit { allow: bool, pattern: String },
    PrintRules,
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut config_path: Option<PathBuf> = None;
    let mut action: Option<CliAction> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        // Each flag may appear once, and the actions are mutually exclusive — a
        // repeat (or two actions) is a usage error rather than silently last-wins.
        match arg.as_str() {
            "--config" if config_path.is_some() => bail!(USAGE),
            "--config" => config_path = Some(PathBuf::from(args.next().context(USAGE)?)),
            "--allow" | "--deny" | "--rules" if action.is_some() => bail!(USAGE),
            "--allow" | "--deny" => {
                let pattern = args.next().context(USAGE)?;
                action = Some(CliAction::Edit {
                    allow: arg == "--allow",
                    pattern,
                });
            }
            "--rules" => action = Some(CliAction::PrintRules),
            _ => bail!(USAGE),
        }
    }
    let config_path = config_path.unwrap_or_else(|| {
        PathBuf::from(shellexpand::tilde("~/.config/clipmesh/config.toml").into_owned())
    });

    // The CLI actions are one-shot (not the daemon): apply and exit. A running
    // daemon picks up an edit through its file watcher.
    match action {
        Some(CliAction::Edit { allow, pattern }) => {
            return apply_rule_edit(&config_path, allow, &pattern)
        }
        Some(CliAction::PrintRules) => return print_rules(&config_path),
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

    let clipboard = Arc::new(WaylandClipboard::new(
        cfg.sync_primary,
        cfg.max_payload_size,
    ));
    let rules_path = cfg.mime_rules_path.clone();
    // The config text as loaded, so the watcher only restarts on a real content
    // change (not a bare touch). Empty on a read error — any later edit differs.
    let original_config = std::fs::read_to_string(&config_path).unwrap_or_default();
    let handle = node::spawn_node(cfg, clipboard).await?;
    // Watch the config and MIME-rules files (inotify): a rules edit reloads in
    // place, a config edit that changes content and still parses restarts the
    // daemon (most settings can't be hot-applied).
    clipmesh::fswatch::spawn(
        config_path,
        original_config,
        rules_path,
        handle.mime_rules.clone(),
        handle.rules_changed_tx.clone(),
    );
    handle.engine_task.await.context("sync engine panicked")?;
    // The engine never stops in normal operation; exit non-zero so systemd
    // (Restart=always) brings the daemon back.
    bail!("sync engine exited unexpectedly");
}

/// Apply a single `--allow`/`--deny` glob to the MIME-rules file and exit. Any
/// existing entries the new glob now covers are removed and echoed back so the
/// user can re-add the ones they want to keep as exceptions.
fn apply_rule_edit(config_path: &Path, allow: bool, pattern: &str) -> Result<()> {
    if pattern.trim().is_empty() {
        bail!("the --allow/--deny pattern must not be empty");
    }
    init_cli_logging();

    let cfg = Config::load(config_path)?;
    let path = cfg
        .mime_rules_path
        .clone()
        .context("no MIME rules file is configured")?;
    // A one-shot edit must not silently discard the user's file: if it exists but
    // isn't valid TOML, refuse rather than let MimeRules::load reset it to a
    // fresh skeleton (which would also drop the [clipmesh] sync version).
    match std::fs::read_to_string(&path) {
        Ok(text) if !text.trim().is_empty() => {
            text.parse::<toml_edit::DocumentMut>().with_context(|| {
                format!(
                    "{} isn't valid TOML — fix or delete it before editing rules",
                    path.display()
                )
            })?;
        }
        Ok(_) => {} // absent-equivalent (empty): a fresh file is fine
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    }

    let mut rules = MimeRules::load(Some(path.clone()), cfg.unknown_mime);
    let removed = rules.apply_glob(allow, pattern);
    if !rules.persist() {
        bail!("couldn't write the MIME rules file {}", path.display());
    }

    let verb = if allow { "allow" } else { "deny" };
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
    let cfg = Config::load(config_path)?;
    let path = cfg
        .mime_rules_path
        .clone()
        .context("no MIME rules file is configured")?;
    match std::fs::read_to_string(&path) {
        Ok(text) if text.trim().is_empty() => {
            println!("The MIME rules file {} is empty.", path.display());
            return Ok(());
        }
        // Validate up front so a corrupt file reports a clear error instead of
        // MimeRules::load silently healing it into a fresh skeleton (a write).
        Ok(text) => {
            text.parse::<toml_edit::DocumentMut>()
                .with_context(|| format!("{} isn't valid TOML", path.display()))?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("No MIME rules file yet at {}", path.display());
            return Ok(());
        }
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    }
    // The file exists and is valid TOML, so this reads it without writing.
    let rules = MimeRules::load(Some(path.clone()), cfg.unknown_mime);
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
            verdict_emoji(entry.verdict),
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

/// Emoji + left-padded word for a verdict, used by the `--rules` listing so the
/// key column aligns (the words pad to the width of "invalid").
fn verdict_emoji(v: Verdict) -> &'static str {
    match v {
        Verdict::Allow => "✅ allow  ",
        Verdict::Deny => "⛔ deny   ",
        Verdict::Invalid => "⚠️  invalid",
    }
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
