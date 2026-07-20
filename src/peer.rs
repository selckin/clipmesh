use crate::mesh::Mesh;
use crate::protocol::{self, Message, PeerRole};
use crate::transport;
use anyhow::{anyhow, bail, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::task::JoinError;
use uuid::Uuid;

/// A connection that completes neither the Noise handshake nor the hello
/// exchange within this window is dropped, so a silent peer can't pin an
/// inbound slot open forever.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Marker error: the dialed/accepted peer announced our own node ID.
/// Dial loops treat this as permanent and stop retrying the address.
#[derive(Debug)]
pub struct SelfConnection;

impl std::fmt::Display for SelfConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "self-connection detected (is this node in its own peer list?)"
        )
    }
}

impl std::error::Error for SelfConnection {}

/// Aborts a spawned task when dropped, so cancelling run_connection
/// tears down its reader/writer children (and with them the stream).
struct AbortGuard(tokio::task::AbortHandle);

impl Drop for AbortGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn flatten(r: Result<Result<()>, JoinError>) -> Result<()> {
    match r {
        Ok(inner) => inner,
        Err(e) if e.is_cancelled() => Ok(()),
        Err(e) => Err(anyhow!("connection task panicked: {e}")),
    }
}

/// Refuse a peer whose wire protocol version differs from ours. bincode is not
/// self-describing, so two builds with different message formats would just
/// fail to decode each other's messages and drop the connection with a
/// corruption-like error; checking the version during the hello exchange turns
/// that into an actionable message instead.
fn check_protocol_version(remote: u32) -> Result<()> {
    if remote != protocol::PROTOCOL_VERSION {
        bail!(
            "protocol version mismatch: peer speaks v{remote}, we speak v{} — \
             upgrade all clipmesh nodes to the same version",
            protocol::PROTOCOL_VERSION
        );
    }
    Ok(())
}

/// Unregisters a peer connection from the mesh when dropped. This runs on
/// every exit path including cancellation (the future being dropped between
/// register and teardown), so a cancelled connection can never leak a dead
/// designated sender that would swallow all later sends to that peer.
struct Registration {
    mesh: Arc<Mesh>,
    remote: Uuid,
    conn_id: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.mesh.unregister(self.remote, self.conn_id);
    }
}

/// Drive one connection from raw stream to teardown. Returns when the
/// connection dies for any reason; the caller handles retry policy.
pub async fn run_connection<S>(
    io: S,
    initiator: bool,
    psk: [u8; 32],
    max_payload: usize,
    mesh: Arc<Mesh>,
    role: PeerRole,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    // allow some slack over the payload cap for encoding overhead
    let max_message = max_payload + 64 * 1024;
    let own_id = mesh.own_id();

    // Bound the handshake + hello exchange: a peer that connects and then
    // says nothing must not hold this connection (and its inbound slot) open.
    let (remote_id, remote_role, mut send, mut recv) =
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, async move {
            let (mut send, mut recv) =
                transport::handshake(io, &psk, initiator, max_message).await?;
            send.send(&protocol::encode(&Message::Hello {
                node_id: own_id,
                protocol_version: protocol::PROTOCOL_VERSION,
                role,
            }))
            .await?;
            let hello = protocol::decode(&recv.recv().await?)?;
            let Message::Hello {
                node_id: remote_id,
                protocol_version,
                role: remote_role,
            } = hello
            else {
                bail!("peer did not send hello first");
            };
            check_protocol_version(protocol_version)?;
            Ok::<_, anyhow::Error>((remote_id, remote_role, send, recv))
        })
        .await
        {
            Ok(r) => r?,
            Err(_) => bail!("handshake/hello exchange timed out"),
        };

    if remote_id == own_id {
        return Err(SelfConnection.into());
    }

    let (tx, mut rx) = mpsc::channel::<protocol::Frame>(16);
    let conn_id = mesh.register(remote_id, tx, remote_role);
    // Unregister on every exit path, cancellation included.
    let _registration = Registration {
        mesh: mesh.clone(),
        remote: remote_id,
        conn_id,
    };

    let reader_mesh = mesh.clone();
    let mut reader = tokio::spawn(async move {
        // The loop diverges, so the task's Result type is pinned by this binding
        // rather than by a trailing Ok(()) (which would be unreachable).
        let result: Result<()> = async {
            loop {
                let raw = recv.recv().await?;
                reader_mesh
                    .deliver(remote_id, protocol::decode(&raw)?)
                    .await;
            }
        }
        .await;
        result
    });
    let mut writer = tokio::spawn(async move {
        // Frames arrive already encoded (see protocol::Frame).
        while let Some(frame) = rx.recv().await {
            send.send(&frame).await?;
        }
        Ok::<(), anyhow::Error>(())
    });

    let _reader_guard = AbortGuard(reader.abort_handle());
    let _writer_guard = AbortGuard(writer.abort_handle());

    // Whichever half ends first, the guards above abort the other as they drop,
    // so neither arm tears down its sibling by hand — a third teardown path is
    // exactly what the guards exist to make unnecessary.
    tokio::select! {
        r = &mut reader => flatten(r),
        w = &mut writer => flatten(w),
    }
    // `_registration` unregisters the peer as it drops here.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::test_support::new_mesh;
    use crate::protocol::test_support::{clip, wait_for};

    const MAX: usize = 8 * 1024 * 1024;
    const PSK: [u8; 32] = [1u8; 32];

    #[test]
    fn matching_protocol_version_is_accepted() {
        assert!(check_protocol_version(protocol::PROTOCOL_VERSION).is_ok());
    }

    #[test]
    fn mismatched_protocol_version_is_rejected() {
        let err = check_protocol_version(protocol::PROTOCOL_VERSION.wrapping_add(1)).unwrap_err();
        assert!(
            format!("{err:#}").contains("protocol version mismatch"),
            "got: {err:#}"
        );
    }

    #[tokio::test]
    async fn peers_exchange_hello_and_clip_messages() {
        let (mesh_a, _in_a_rx, _crx_a) = new_mesh();
        let (mesh_b, mut in_b_rx, _crx_b) = new_mesh();

        let (io_a, io_b) = tokio::io::duplex(1 << 20);
        tokio::spawn(run_connection(
            io_a,
            true,
            PSK,
            MAX,
            mesh_a.clone(),
            PeerRole::Peer,
        ));
        tokio::spawn(run_connection(
            io_b,
            false,
            PSK,
            MAX,
            mesh_b.clone(),
            PeerRole::Peer,
        ));

        let (ma, mb) = (mesh_a.clone(), mesh_b.clone());
        wait_for("both nodes to see each other as a peer", move || {
            ma.peer_count() == 1 && mb.peer_count() == 1
        })
        .await;
        assert_eq!(mesh_a.peer_ids(), vec![mesh_b.own_id()]);
        assert_eq!(mesh_b.peer_ids(), vec![mesh_a.own_id()]);

        mesh_a.broadcast(&clip("over the wire"));
        let (from, got) = in_b_rx.recv().await.unwrap();
        assert_eq!(from, mesh_a.own_id());
        assert_eq!(got, clip("over the wire"));
    }

    #[tokio::test]
    async fn self_connection_is_rejected() {
        let (mesh, _in_rx, _crx) = new_mesh();
        let (io_a, io_b) = tokio::io::duplex(1 << 20);
        let a = tokio::spawn(run_connection(
            io_a,
            true,
            PSK,
            MAX,
            mesh.clone(),
            PeerRole::Peer,
        ));
        let b = tokio::spawn(run_connection(
            io_b,
            false,
            PSK,
            MAX,
            mesh.clone(),
            PeerRole::Peer,
        ));
        let (ra, rb) = tokio::join!(a, b);
        // the error must be typed so dial loops can stop retrying for good
        assert!(ra
            .unwrap()
            .unwrap_err()
            .downcast_ref::<SelfConnection>()
            .is_some());
        assert!(rb
            .unwrap()
            .unwrap_err()
            .downcast_ref::<SelfConnection>()
            .is_some());
        assert_eq!(mesh.peer_count(), 0);
    }

    #[tokio::test]
    async fn connection_unregisters_when_the_wire_drops() {
        let (mesh_a, _in_a_rx, _crx_a) = new_mesh();
        let (mesh_b, _in_b_rx, _crx_b) = new_mesh();

        let (io_a, io_b) = tokio::io::duplex(1 << 20);
        tokio::spawn(run_connection(
            io_a,
            true,
            PSK,
            MAX,
            mesh_a.clone(),
            PeerRole::Peer,
        ));
        let b_task = tokio::spawn(run_connection(
            io_b,
            false,
            PSK,
            MAX,
            mesh_b.clone(),
            PeerRole::Peer,
        ));

        let (ma, mb) = (mesh_a.clone(), mesh_b.clone());
        wait_for("both nodes to see each other as a peer", move || {
            ma.peer_count() == 1 && mb.peer_count() == 1
        })
        .await;

        b_task.abort(); // kill B's side; A must notice and unregister
        let ma = mesh_a.clone();
        wait_for("A to drop the peer after B's side died", move || {
            ma.peer_count() == 0
        })
        .await;
    }

    #[tokio::test]
    async fn cancelling_a_connection_unregisters_its_peer() {
        // the RAII registration guard must clean up even when the
        // run_connection future is cancelled (dropped) rather than ending
        // through its own select
        let (mesh_a, _in_a_rx, _crx_a) = new_mesh();
        let (mesh_b, _in_b_rx, _crx_b) = new_mesh();

        let (io_a, io_b) = tokio::io::duplex(1 << 20);
        let a_task = tokio::spawn(run_connection(
            io_a,
            true,
            PSK,
            MAX,
            mesh_a.clone(),
            PeerRole::Peer,
        ));
        tokio::spawn(run_connection(
            io_b,
            false,
            PSK,
            MAX,
            mesh_b.clone(),
            PeerRole::Peer,
        ));

        let ma = mesh_a.clone();
        wait_for("A to register its peer", move || ma.peer_count() == 1).await;

        a_task.abort(); // cancel A's own connection future
        let ma = mesh_a.clone();
        wait_for("A to drop the peer after cancellation", move || {
            ma.peer_count() == 0
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn handshake_times_out_on_a_silent_peer() {
        let (mesh, _in_rx, _crx) = new_mesh();
        // the other end of the duplex never responds to the handshake
        let (io_a, _io_b) = tokio::io::duplex(1 << 16);
        let res = run_connection(io_a, true, PSK, MAX, mesh.clone(), PeerRole::Peer).await;
        assert!(res.is_err());
        assert_eq!(mesh.peer_count(), 0);
    }
}
