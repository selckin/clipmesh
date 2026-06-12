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
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let clipboard = Arc::new(WaylandClipboard::new(cfg.sync_primary, cfg.max_payload_size));
    let handle = node::spawn_node(cfg, clipboard).await?;
    handle.engine_task.await.context("sync engine panicked")?;
    // The engine never stops in normal operation; exit non-zero so
    // systemd's Restart=on-failure brings the daemon back.
    bail!("sync engine exited unexpectedly");
}
