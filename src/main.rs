use anyhow::{bail, Context, Result};
use clipmesh::clipboard::wayland::WaylandClipboard;
use clipmesh::config::Config;
use clipmesh::node;
use std::path::PathBuf;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let config_path = match args.as_slice() {
        [] => PathBuf::from(shellexpand::tilde("~/.config/clipmesh/config.toml").into_owned()),
        [flag, path] if flag == "--config" => PathBuf::from(path),
        _ => bail!("usage: clipmesh [--config <path>]"),
    };
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
