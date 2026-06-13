use crate::protocol::Message;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use uuid::Uuid;

struct ConnHandle {
    id: u64,
    tx: mpsc::Sender<Message>,
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
    pub fn register(&self, remote: Uuid, tx: mpsc::Sender<Message>) -> u64 {
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
        let targets: Vec<(Uuid, mpsc::Sender<Message>)> = self
            .peers
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(id, conns)| conns.first().map(|c| (*id, c.tx.clone())))
            .collect();
        debug!("broadcasting clipboard update to {} peer(s)", targets.len());
        for (peer, tx) in targets {
            if tx.try_send(msg.clone()).is_err() {
                warn!("dropped update to peer {peer}: its send queue is full or closed");
            }
        }
    }

    /// Send a message to one peer's designated connection (used for
    /// targeted resyncs). Same try_send semantics as broadcast.
    pub fn send_to(&self, peer: Uuid, msg: &Message) {
        let target = self
            .peers
            .lock()
            .unwrap()
            .get(&peer)
            .and_then(|conns| conns.first().map(|c| c.tx.clone()));
        match target {
            Some(tx) => {
                if tx.try_send(msg.clone()).is_err() {
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

    pub fn peer_ids(&self) -> Vec<Uuid> {
        self.peers.lock().unwrap().keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{content_hash, Message, Offer, SelectionKind};
    use tokio::sync::mpsc;
    use uuid::Uuid;

    fn clip(text: &str) -> Message {
        let offer: Offer = [("text/plain".to_string(), text.as_bytes().to_vec())]
            .into_iter()
            .collect();
        Message::Clip {
            kind: SelectionKind::Clipboard,
            hash: content_hash(&offer),
            offer,
            stamp: 0,
            origin: Uuid::nil(),
        }
    }

    fn new_mesh() -> (std::sync::Arc<Mesh>, mpsc::Receiver<(Uuid, Message)>) {
        let (tx, rx) = mpsc::channel(8);
        let (ctx, _crx) = mpsc::channel(8);
        (Mesh::new(Uuid::new_v4(), tx, ctx), rx)
    }

    fn new_mesh_with_connects() -> (
        std::sync::Arc<Mesh>,
        mpsc::Receiver<(Uuid, Message)>,
        mpsc::Receiver<Uuid>,
    ) {
        let (tx, rx) = mpsc::channel(8);
        let (ctx, crx) = mpsc::channel(8);
        (Mesh::new(Uuid::new_v4(), tx, ctx), rx, crx)
    }

    #[tokio::test]
    async fn first_connection_emits_a_connect_event_standby_does_not() {
        let (mesh, _rx, mut connects) = new_mesh_with_connects();
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
        let (mesh, _rx) = new_mesh();
        let peer_a = Uuid::new_v4();
        let peer_b = Uuid::new_v4();
        let (tx_a, mut rx_a) = mpsc::channel(8);
        let (tx_b, mut rx_b) = mpsc::channel(8);
        mesh.register(peer_a, tx_a);
        mesh.register(peer_b, tx_b);
        mesh.send_to(peer_a, &clip("targeted"));
        assert_eq!(rx_a.try_recv().unwrap(), clip("targeted"));
        assert!(rx_b.try_recv().is_err());
    }

    #[tokio::test]
    async fn broadcast_uses_only_the_designated_connection_per_peer() {
        let (mesh, _rx) = new_mesh();
        let peer = Uuid::new_v4();
        let (tx1, mut rx1) = mpsc::channel(8);
        let (tx2, mut rx2) = mpsc::channel(8);
        let c1 = mesh.register(peer, tx1);
        let _c2 = mesh.register(peer, tx2);

        mesh.broadcast(&clip("a"));
        assert_eq!(rx1.try_recv().unwrap(), clip("a"));
        assert!(
            rx2.try_recv().is_err(),
            "standby connection must not receive sends"
        );

        // failover: drop the designated connection, standby is promoted
        mesh.unregister(peer, c1);
        mesh.broadcast(&clip("b"));
        assert_eq!(rx2.try_recv().unwrap(), clip("b"));
    }

    #[tokio::test]
    async fn broadcast_reaches_each_peer_exactly_once() {
        let (mesh, _rx) = new_mesh();
        let (tx_a, mut rx_a) = mpsc::channel(8);
        let (tx_b, mut rx_b) = mpsc::channel(8);
        mesh.register(Uuid::new_v4(), tx_a);
        mesh.register(Uuid::new_v4(), tx_b);

        mesh.broadcast(&clip("x"));
        assert_eq!(rx_a.try_recv().unwrap(), clip("x"));
        assert_eq!(rx_b.try_recv().unwrap(), clip("x"));
        assert!(rx_a.try_recv().is_err());
        assert!(rx_b.try_recv().is_err());
    }

    #[tokio::test]
    async fn unregistering_the_last_connection_removes_the_peer() {
        let (mesh, _rx) = new_mesh();
        let peer = Uuid::new_v4();
        let (tx, _krx) = mpsc::channel(8);
        let c = mesh.register(peer, tx);
        assert_eq!(mesh.peer_count(), 1);
        mesh.unregister(peer, c);
        assert_eq!(mesh.peer_count(), 0);
    }

    #[tokio::test]
    async fn deliver_forwards_to_the_inbound_channel() {
        let (mesh, mut rx) = new_mesh();
        let from = Uuid::new_v4();
        mesh.deliver(from, clip("in")).await;
        assert_eq!(rx.recv().await.unwrap(), (from, clip("in")));
    }
}
