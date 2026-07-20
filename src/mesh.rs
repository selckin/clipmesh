use crate::protocol::{encode_frame, Frame, Message};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use uuid::Uuid;

struct ConnHandle {
    id: u64,
    tx: mpsc::Sender<Frame>,
}

/// Live peer table. Connections are grouped by remote node ID; index 0 in
/// each group is the designated send connection, the rest are warm
/// standbys (we still receive on them; we just don't send).
pub struct Mesh {
    own_id: Uuid,
    next_conn_id: AtomicU64,
    peers: Mutex<HashMap<Uuid, Vec<ConnHandle>>>,
    inbound_tx: mpsc::Sender<(Uuid, Message)>,
    /// Notified with the remote node ID when a peer gains its first
    /// connection (i.e. it just joined or rejoined the mesh).
    connect_tx: mpsc::Sender<Uuid>,
}

impl Mesh {
    pub fn new(
        own_id: Uuid,
        inbound_tx: mpsc::Sender<(Uuid, Message)>,
        connect_tx: mpsc::Sender<Uuid>,
    ) -> Arc<Mesh> {
        Arc::new(Mesh {
            own_id,
            next_conn_id: AtomicU64::new(0),
            peers: Mutex::new(HashMap::new()),
            inbound_tx,
            connect_tx,
        })
    }

    pub fn own_id(&self) -> Uuid {
        self.own_id
    }

    /// Add a connection for a peer; returns its connection ID.
    pub fn register(&self, remote: Uuid, tx: mpsc::Sender<Frame>) -> u64 {
        let id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let first_connection = {
            let mut peers = self.peers.lock().unwrap();
            let conns = peers.entry(remote).or_default();
            conns.push(ConnHandle { id, tx });
            conns.len() == 1
        };
        if first_connection {
            info!("peer {remote} connected (connection {id})");
            if self.connect_tx.try_send(remote).is_err() {
                warn!("couldn't queue a resync for peer {remote}: the event queue is full");
            }
        } else {
            debug!("opened an additional connection {id} to peer {remote}");
        }
        id
    }

    /// Remove a connection. If it was the designated sender, the next
    /// connection (if any) is promoted automatically by position.
    pub fn unregister(&self, remote: Uuid, conn_id: u64) {
        let mut peers = self.peers.lock().unwrap();
        if let Some(conns) = peers.get_mut(&remote) {
            conns.retain(|c| c.id != conn_id);
            if conns.is_empty() {
                peers.remove(&remote);
                info!("peer {remote} disconnected");
            }
        }
    }

    /// Forward an inbound message to the sync engine.
    pub async fn deliver(&self, from: Uuid, msg: Message) {
        let _ = self.inbound_tx.send((from, msg)).await;
    }

    /// Send a message to every peer's designated connection. Uses try_send:
    /// a stalled peer drops the update rather than blocking the rest (the
    /// next clipboard change supersedes it anyway).
    pub fn broadcast(&self, msg: &Message) {
        let targets: Vec<(Uuid, mpsc::Sender<Frame>)> = self
            .peers
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(id, conns)| conns.first().map(|c| (*id, c.tx.clone())))
            .collect();
        debug!("broadcasting clipboard update to {} peer(s)", targets.len());
        if targets.is_empty() {
            return;
        }
        // Encode once; each peer gets a refcount, not a copy of the payload.
        let frame = encode_frame(msg);
        for (peer, tx) in targets {
            if tx.try_send(frame.clone()).is_err() {
                warn!("dropped update to peer {peer}: its send queue is full or closed");
            }
        }
    }

    /// Send a message to one peer's designated connection (used for
    /// targeted resyncs). Same try_send semantics as broadcast.
    pub fn send_to(&self, peer: Uuid, msg: &Message) {
        self.send_frame_to(peer, &encode_frame(msg));
    }

    /// Send an already-encoded frame to one peer.
    ///
    /// Split from `send_to` so a caller with the same message for several peers
    /// encodes it once and hands each a refcount, exactly as `broadcast` does —
    /// otherwise a resync burst re-serializes a whole clipboard payload (up to
    /// `max_payload_size`) per recipient.
    pub fn send_frame_to(&self, peer: Uuid, frame: &Frame) {
        let target = self
            .peers
            .lock()
            .unwrap()
            .get(&peer)
            .and_then(|conns| conns.first().map(|c| c.tx.clone()));
        match target {
            Some(tx) => {
                if tx.try_send(frame.clone()).is_err() {
                    warn!(
                        "dropped targeted message to peer {peer}: its send queue is full or closed"
                    );
                }
            }
            None => warn!("can't send targeted message: no connection to peer {peer}"),
        }
    }

    pub fn peer_count(&self) -> usize {
        self.peers.lock().unwrap().len()
    }

    #[cfg(test)]
    pub fn peer_ids(&self) -> Vec<Uuid> {
        self.peers.lock().unwrap().keys().copied().collect()
    }
}

/// Mesh construction shared by the unit tests across the crate.
///
/// Not reachable from `tests/*.rs` — those compile the library without
/// `cfg(test)` and have their own `tests/common`. Keeping this `cfg(test)`
/// keeps it out of the public API.
#[cfg(test)]
pub(crate) mod test_support {
    use super::Mesh;
    use crate::protocol::Message;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use uuid::Uuid;

    /// A mesh with a fresh node ID, together with its inbound and connect
    /// receivers.
    ///
    /// **Both receivers must stay alive for the test's duration**, even when
    /// the test never reads them — bind them to `_`-prefixed names rather than
    /// `_`. `Mesh::register` `try_send`s a connect event and warns when that
    /// fails, so a dropped connect receiver makes every registration log a
    /// spurious "couldn't queue a resync".
    pub(crate) fn new_mesh() -> (
        Arc<Mesh>,
        mpsc::Receiver<(Uuid, Message)>,
        mpsc::Receiver<Uuid>,
    ) {
        let (tx, rx) = mpsc::channel(8);
        let (ctx, crx) = mpsc::channel(8);
        (Mesh::new(Uuid::new_v4(), tx, ctx), rx, crx)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::new_mesh;
    use super::*;
    use crate::protocol::test_support::clip;
    use crate::protocol::Message;
    use tokio::sync::mpsc;
    use uuid::Uuid;

    /// Take the next frame off a connection channel and decode it, so tests can
    /// assert against `Message` values rather than encoded bytes.
    fn recv(rx: &mut mpsc::Receiver<Frame>) -> Message {
        crate::protocol::decode(&rx.try_recv().expect("no frame queued"))
            .expect("frame did not decode")
    }

    #[tokio::test]
    async fn first_connection_emits_a_connect_event_standby_does_not() {
        let (mesh, _rx, mut connects) = new_mesh();
        let peer = Uuid::new_v4();
        let (tx1, _rx1) = mpsc::channel(8);
        let (tx2, _rx2) = mpsc::channel(8);
        mesh.register(peer, tx1);
        assert_eq!(connects.try_recv().unwrap(), peer);
        // a duplicate (standby) connection must not re-trigger resync
        mesh.register(peer, tx2);
        assert!(connects.try_recv().is_err());
    }

    #[tokio::test]
    async fn send_to_reaches_only_the_target_peer() {
        let (mesh, _rx, _c) = new_mesh();
        let peer_a = Uuid::new_v4();
        let peer_b = Uuid::new_v4();
        let (tx_a, mut rx_a) = mpsc::channel(8);
        let (tx_b, mut rx_b) = mpsc::channel(8);
        mesh.register(peer_a, tx_a);
        mesh.register(peer_b, tx_b);
        mesh.send_to(peer_a, &clip("targeted"));
        assert_eq!(recv(&mut rx_a), clip("targeted"));
        assert!(rx_b.try_recv().is_err());
    }

    #[tokio::test]
    async fn broadcast_uses_only_the_designated_connection_per_peer() {
        let (mesh, _rx, _c) = new_mesh();
        let peer = Uuid::new_v4();
        let (tx1, mut rx1) = mpsc::channel(8);
        let (tx2, mut rx2) = mpsc::channel(8);
        let c1 = mesh.register(peer, tx1);
        let _c2 = mesh.register(peer, tx2);

        mesh.broadcast(&clip("a"));
        assert_eq!(recv(&mut rx1), clip("a"));
        assert!(
            rx2.try_recv().is_err(),
            "standby connection must not receive sends"
        );

        // failover: drop the designated connection, standby is promoted
        mesh.unregister(peer, c1);
        mesh.broadcast(&clip("b"));
        assert_eq!(recv(&mut rx2), clip("b"));
    }

    #[tokio::test]
    async fn broadcast_reaches_each_peer_exactly_once() {
        let (mesh, _rx, _c) = new_mesh();
        let (tx_a, mut rx_a) = mpsc::channel(8);
        let (tx_b, mut rx_b) = mpsc::channel(8);
        mesh.register(Uuid::new_v4(), tx_a);
        mesh.register(Uuid::new_v4(), tx_b);

        mesh.broadcast(&clip("x"));
        assert_eq!(recv(&mut rx_a), clip("x"));
        assert_eq!(recv(&mut rx_b), clip("x"));
        assert!(rx_a.try_recv().is_err());
        assert!(rx_b.try_recv().is_err());
    }

    #[tokio::test]
    async fn unregistering_the_last_connection_removes_the_peer() {
        let (mesh, _rx, _c) = new_mesh();
        let peer = Uuid::new_v4();
        let (tx, _krx) = mpsc::channel(8);
        let c = mesh.register(peer, tx);
        assert_eq!(mesh.peer_count(), 1);
        mesh.unregister(peer, c);
        assert_eq!(mesh.peer_count(), 0);
    }

    #[tokio::test]
    async fn deliver_forwards_to_the_inbound_channel() {
        let (mesh, mut rx, _c) = new_mesh();
        let from = Uuid::new_v4();
        mesh.deliver(from, clip("in")).await;
        assert_eq!(rx.recv().await.unwrap(), (from, clip("in")));
    }
}
