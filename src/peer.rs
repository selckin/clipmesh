use crate::mesh::Mesh;
use crate::protocol::{self, Message};
use crate::transport;
use anyhow::{anyhow, bail, Result};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::task::JoinError;

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

/// Drive one connection from raw stream to teardown. Returns when the
/// connection dies for any reason; the caller handles retry policy.
pub async fn run_connection<S>(
    io: S,
    initiator: bool,
    psk: [u8; 32],
    max_payload: usize,
    mesh: Arc<Mesh>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    // allow some slack over the payload cap for encoding overhead
    let max_message = max_payload + 64 * 1024;
    let (mut send, mut recv) = transport::handshake(io, &psk, initiator, max_message).await?;

    // hello exchange, inside the encrypted channel
    send.send(&protocol::encode(&Message::Hello { node_id: mesh.own_id() })).await?;
    let hello = protocol::decode(&recv.recv().await?)?;
    let Message::Hello { node_id: remote_id } = hello else {
        bail!("peer did not send hello first");
    };
    if remote_id == mesh.own_id() {
        bail!("self-connection detected (is this node in its own peer list?)");
    }

    let (tx, mut rx) = mpsc::channel::<Message>(16);
    let conn_id = mesh.register(remote_id, tx);

    let reader_mesh = mesh.clone();
    let mut reader = tokio::spawn(async move {
        let result: Result<()> = async {
            loop {
                let raw = recv.recv().await?;
                reader_mesh.deliver(remote_id, protocol::decode(&raw)?).await;
            }
        }
        .await;
        result
    });
    let mut writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            send.send(&protocol::encode(&msg)).await?;
        }
        Ok::<(), anyhow::Error>(())
    });

    let _reader_guard = AbortGuard(reader.abort_handle());
    let _writer_guard = AbortGuard(writer.abort_handle());

    let result = tokio::select! {
        r = &mut reader => { writer.abort(); flatten(r) }
        w = &mut writer => { reader.abort(); flatten(w) }
    };
    mesh.unregister(remote_id, conn_id);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::Mesh;
    use crate::protocol::{content_hash, Message, Offer, SelectionKind};
    use std::time::Duration;
    use tokio::sync::mpsc;
    use uuid::Uuid;

    const MAX: usize = 8 * 1024 * 1024;
    const PSK: [u8; 32] = [1u8; 32];

    async fn wait_for(mut cond: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !cond() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("condition not met within 5s");
    }

    fn clip(text: &str) -> Message {
        let offer: Offer = [("text/plain".to_string(), text.as_bytes().to_vec())]
            .into_iter()
            .collect();
        Message::Clip {
            kind: SelectionKind::Clipboard,
            hash: content_hash(&offer),
            offer,
            set_at_ms: 0,
            resync: false,
        }
    }

    #[tokio::test]
    async fn peers_exchange_hello_and_clip_messages() {
        let (in_a_tx, _in_a_rx) = mpsc::channel(8);
        let (in_b_tx, mut in_b_rx) = mpsc::channel(8);
        let (ctx_a, _crx_a) = mpsc::channel(8);
        let (ctx_b, _crx_b) = mpsc::channel(8);
        let mesh_a = Mesh::new(Uuid::new_v4(), in_a_tx, ctx_a);
        let mesh_b = Mesh::new(Uuid::new_v4(), in_b_tx, ctx_b);

        let (io_a, io_b) = tokio::io::duplex(1 << 20);
        tokio::spawn(run_connection(io_a, true, PSK, MAX, mesh_a.clone()));
        tokio::spawn(run_connection(io_b, false, PSK, MAX, mesh_b.clone()));

        let (ma, mb) = (mesh_a.clone(), mesh_b.clone());
        wait_for(move || ma.peer_count() == 1 && mb.peer_count() == 1).await;
        assert_eq!(mesh_a.peer_ids(), vec![mesh_b.own_id()]);
        assert_eq!(mesh_b.peer_ids(), vec![mesh_a.own_id()]);

        mesh_a.broadcast(&clip("over the wire"));
        let (from, got) = in_b_rx.recv().await.unwrap();
        assert_eq!(from, mesh_a.own_id());
        assert_eq!(got, clip("over the wire"));
    }

    #[tokio::test]
    async fn self_connection_is_rejected() {
        let (in_tx, _in_rx) = mpsc::channel(8);
        let (ctx, _crx) = mpsc::channel(8);
        let mesh = Mesh::new(Uuid::new_v4(), in_tx, ctx);
        let (io_a, io_b) = tokio::io::duplex(1 << 20);
        let a = tokio::spawn(run_connection(io_a, true, PSK, MAX, mesh.clone()));
        let b = tokio::spawn(run_connection(io_b, false, PSK, MAX, mesh.clone()));
        let (ra, rb) = tokio::join!(a, b);
        assert!(ra.unwrap().is_err());
        assert!(rb.unwrap().is_err());
        assert_eq!(mesh.peer_count(), 0);
    }

    #[tokio::test]
    async fn connection_unregisters_when_the_wire_drops() {
        let (in_a_tx, _in_a_rx) = mpsc::channel(8);
        let (in_b_tx, _in_b_rx) = mpsc::channel(8);
        let (ctx_a, _crx_a) = mpsc::channel(8);
        let (ctx_b, _crx_b) = mpsc::channel(8);
        let mesh_a = Mesh::new(Uuid::new_v4(), in_a_tx, ctx_a);
        let mesh_b = Mesh::new(Uuid::new_v4(), in_b_tx, ctx_b);

        let (io_a, io_b) = tokio::io::duplex(1 << 20);
        tokio::spawn(run_connection(io_a, true, PSK, MAX, mesh_a.clone()));
        let b_task = tokio::spawn(run_connection(io_b, false, PSK, MAX, mesh_b.clone()));

        let (ma, mb) = (mesh_a.clone(), mesh_b.clone());
        wait_for(move || ma.peer_count() == 1 && mb.peer_count() == 1).await;

        b_task.abort(); // kill B's side; A must notice and unregister
        let ma = mesh_a.clone();
        wait_for(move || ma.peer_count() == 0).await;
    }
}
