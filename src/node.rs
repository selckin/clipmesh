use crate::clipboard::Clipboard;
use crate::config::Config;
use crate::mesh::Mesh;
use crate::peer;
use crate::sync::SyncEngine;
use anyhow::{anyhow, Result};
use rand::Rng;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{debug, info, warn};
use uuid::Uuid;

const MAX_INBOUND_CONNECTIONS: usize = 64;

pub struct NodeHandle {
    pub local_addr: SocketAddr,
    pub mesh: Arc<Mesh>,
    pub engine_task: JoinHandle<()>,
}

/// Start a node: listener + accept loop, a dial loop per configured peer,
/// and the sync engine. Returns once the listener is bound.
pub async fn spawn_node<C: Clipboard>(cfg: Arc<Config>, clipboard: Arc<C>) -> Result<NodeHandle> {
    let node_id = Uuid::new_v4();
    let (inbound_tx, inbound_rx) = mpsc::channel(64);
    let (connect_tx, connect_rx) = mpsc::channel(64);
    let mesh = Mesh::new(node_id, inbound_tx, connect_tx);

    let listener = bind_listener(&cfg.listen).await?;
    let local_addr = listener.local_addr()?;
    info!(%node_id, %local_addr, "clipmesh node started");

    // accept loop
    {
        let mesh = mesh.clone();
        let cfg = cfg.clone();
        // Bound concurrent inbound connections so unauthenticated LAN
        // traffic can't exhaust memory/fds with half-open handshakes.
        let permits = Arc::new(Semaphore::new(MAX_INBOUND_CONNECTIONS));
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        let Ok(permit) = permits.clone().try_acquire_owned() else {
                            warn!(%addr, "too many inbound connections; dropping");
                            continue;
                        };
                        let _ = stream.set_nodelay(true);
                        let mesh = mesh.clone();
                        let cfg = cfg.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(e) = peer::run_connection(
                                stream,
                                false,
                                cfg.psk,
                                cfg.max_payload_size,
                                mesh,
                            )
                            .await
                            {
                                // our own dialer already reports self-connections
                                if e.downcast_ref::<peer::SelfConnection>().is_some() {
                                    debug!(%addr, "inbound self-connection closed");
                                } else {
                                    warn!(%addr, "inbound connection ended: {e:#}");
                                }
                            }
                        });
                    }
                    Err(e) => {
                        warn!("accept failed: {e}");
                        sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });
    }

    // dial loops
    for peer_addr in cfg.peers.clone() {
        let mesh = mesh.clone();
        let cfg = cfg.clone();
        tokio::spawn(dial_loop(peer_addr, cfg, mesh));
    }

    let engine = SyncEngine::new(clipboard, mesh.clone(), cfg);
    let engine_task = tokio::spawn(engine.run(inbound_rx, connect_rx));

    Ok(NodeHandle {
        local_addr,
        mesh,
        engine_task,
    })
}

/// Bind the listen socket. tokio already sets SO_REUSEADDR (so restarting
/// over a previous instance's TIME_WAIT connections is fine), but a second
/// live bind to the same port still fails with EADDRINUSE — which almost
/// always means another clipmesh is already running. Turn that into an
/// actionable message rather than the bare OS error.
async fn bind_listener(listen: &str) -> Result<TcpListener> {
    match TcpListener::bind(listen).await {
        Ok(l) => Ok(l),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            let port = listen.rsplit(':').next().unwrap_or(listen);
            Err(anyhow!(
                "cannot bind {listen}: address already in use. Another process \
                 is bound to this port — most likely another clipmesh instance. \
                 Check: `ss -tlnp 'sport = :{port}'`, `systemctl --user status \
                 clipmesh`, `pgrep -af clipmesh`."
            ))
        }
        Err(e) => Err(anyhow::Error::new(e).context(format!("binding {listen}"))),
    }
}

/// Keep one outbound connection attempt going to a peer, forever.
/// Exponential backoff with jitter; reset after a connection that lived
/// long enough to be considered healthy.
async fn dial_loop(addr: String, cfg: Arc<Config>, mesh: Arc<Mesh>) {
    const INITIAL: Duration = Duration::from_secs(1);
    const CAP: Duration = Duration::from_secs(60);
    const HEALTHY: Duration = Duration::from_secs(30);
    let mut backoff = INITIAL;
    let mut dial_failures: u32 = 0;
    loop {
        match TcpStream::connect(&addr).await {
            Ok(stream) => {
                dial_failures = 0;
                let _ = stream.set_nodelay(true);
                info!(%addr, "connected");
                let started = Instant::now();
                match peer::run_connection(
                    stream,
                    true,
                    cfg.psk,
                    cfg.max_payload_size,
                    mesh.clone(),
                )
                .await
                {
                    Ok(()) => info!(%addr, "connection closed"),
                    Err(e) if e.downcast_ref::<peer::SelfConnection>().is_some() => {
                        warn!(%addr, "peer address is this node itself; not dialing it again");
                        return;
                    }
                    Err(e) => warn!(%addr, "connection ended: {e:#}"),
                }
                if started.elapsed() >= HEALTHY {
                    backoff = INITIAL;
                }
            }
            Err(e) => {
                // first failure of a streak at warn so a dead peer is
                // visible at the default log level; repeats at debug
                if dial_failures == 0 {
                    warn!(%addr, "dial failed: {e} (retrying with backoff)");
                } else {
                    debug!(%addr, "dial failed: {e}");
                }
                dial_failures += 1;
            }
        }
        let jitter_ms = rand::thread_rng().gen_range(0..=backoff.as_millis() as u64 / 2);
        sleep(backoff + Duration::from_millis(jitter_ms)).await;
        backoff = (backoff * 2).min(CAP);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bind_conflict_reports_already_in_use_with_a_hint() {
        // hold the port, then binding it again must fail with the actionable
        // message (this is exactly the user-reported EADDRINUSE situation)
        let held = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = held.local_addr().unwrap();

        let err = bind_listener(&addr.to_string()).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("already in use"), "got: {msg}");
        assert!(msg.contains("another clipmesh"), "got: {msg}");
        assert!(
            msg.contains(&addr.port().to_string()),
            "hint should name the port: {msg}"
        );
    }

    #[tokio::test]
    async fn bind_listener_succeeds_on_a_free_port() {
        assert!(bind_listener("127.0.0.1:0").await.is_ok());
    }
}
