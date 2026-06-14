use anyhow::{bail, Context, Result};
use clipmesh::clipboard::wayland::WaylandClipboard;
use clipmesh::config::Config;
use clipmesh::mime::MimeRules;
use clipmesh::node;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const USAGE: &str = "usage: clipmesh [--config <path>] [--allow <glob> | --deny <glob>]";

#[tokio::main]
async fn main() -> Result<()> {
    // clipmesh [--config <path>] [--allow <glob> | --deny <glob>]
    let mut config_path: Option<PathBuf> = None;
    let mut rule_edit: Option<(bool, String)> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            // Each flag may appear once; a repeat (or both --allow and --deny) is
            // a usage error rather than silently last-wins.
            "--config" if config_path.is_some() => bail!(USAGE),
            "--config" => config_path = Some(PathBuf::from(args.next().context(USAGE)?)),
            "--allow" | "--deny" if rule_edit.is_some() => bail!(USAGE),
            "--allow" | "--deny" => {
                let pattern = args.next().context(USAGE)?;
                rule_edit = Some((arg == "--allow", pattern));
            }
            _ => bail!(USAGE),
        }
    }
    let config_path = config_path.unwrap_or_else(|| {
        PathBuf::from(shellexpand::tilde("~/.config/clipmesh/config.toml").into_owned())
    });

    // --allow/--deny is a one-shot rules-file edit, not the daemon: apply it and
    // exit. A running daemon picks up the change through its file watcher.
    if let Some((allow, pattern)) = rule_edit {
        return apply_rule_edit(&config_path, allow, &pattern);
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
    // Surface MimeRules/Config warnings (this runs before main()'s subscriber):
    // e.g. a write error, or a file about to be reset, must reach the user.
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .without_time()
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

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
