use crate::protocol::{encode_frame, Frame, Message, PeerRole};
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

/// Live connection tables, split by what the far end *is*.
///
/// A one-shot `--paste` client is not a mesh member, and this is where that
/// stops being a convention every reader has to remember: it lives in
/// `clients`, so `broadcast` and `peer_count` cannot see one at all. Keeping
/// both in `peers` also put a client on the designated-sender ladder, where
/// landing at index 0 of a real peer's group would have silently swallowed
/// every send to that peer instead of falling through to a live connection.
pub struct Mesh {
    own_id: Uuid,
    next_conn_id: AtomicU64,
    /// Mesh members. Connections are grouped by remote node ID; index 0 in each
    /// group is the designated send connection, the rest are warm standbys (we
    /// still receive on them; we just don't send).
    peers: Mutex<HashMap<Uuid, Vec<ConnHandle>>>,
    /// Paste clients, which ask one question and leave. Exactly one connection
    /// each, so there is no group and no designated sender to pick.
    clients: Mutex<HashMap<Uuid, mpsc::Sender<Frame>>>,
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
            clients: Mutex::new(HashMap::new()),
            inbound_tx,
            connect_tx,
        })
    }

    pub fn own_id(&self) -> Uuid {
        self.own_id
    }

    /// Add a connection for a peer or a paste client; returns its connection ID.
    ///
    /// This is the one place the role is dispatched on: a [`PeerRole::Paster`]
    /// goes into `clients`, where it can be answered but is invisible to every
    /// reader that means "mesh member". It fires no connect event either — the
    /// engine would spend a full resync on a client that will never sync. Only
    /// a real peer joining is mesh news.
    pub fn register(&self, remote: Uuid, tx: mpsc::Sender<Frame>, role: PeerRole) -> u64 {
        let id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        if role == PeerRole::Paster {
            self.clients.lock().unwrap().insert(remote, tx);
            debug!("paste client {remote} connected (connection {id})");
            return id;
        }
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
    ///
    /// Which table a node ID is in decides how it leaves, so a caller cannot
    /// retire a connection under the wrong role and strand it — a peer left
    /// behind in `peers` would be a dead designated sender swallowing every
    /// later send to it.
    pub fn unregister(&self, remote: Uuid, conn_id: u64) {
        // A client has exactly one connection, so its node ID identifies it;
        // `conn_id` is bookkeeping for the peer groups only. Symmetric with
        // `register`, its arrival and departure are both debug, so a node
        // serving `wl-paste` in a loop doesn't report a stream of phantom peers
        // joining and leaving the mesh at the default level.
        if self.clients.lock().unwrap().remove(&remote).is_some() {
            debug!("paste client {remote} disconnected");
            return;
        }
        let mut peers = self.peers.lock().unwrap();
        let Some(conns) = peers.get_mut(&remote) else {
            return;
        };
        conns.retain(|c| c.id != conn_id);
        if !conns.is_empty() {
            return;
        }
        peers.remove(&remote);
        info!("peer {remote} disconnected");
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

    /// The designated send connection for a peer, if it is connected.
    ///
    /// A method rather than an inline lookup so the table lock is released on
    /// return, and `send_frame_to` never holds both locks at once.
    fn peer_sender(&self, peer: Uuid) -> Option<mpsc::Sender<Frame>> {
        self.peers
            .lock()
            .unwrap()
            .get(&peer)
            .and_then(|conns| conns.first().map(|c| c.tx.clone()))
    }

    /// Send an already-encoded frame to one remote's designated connection (used
    /// for targeted resyncs, and to answer a paste client). Same try_send
    /// semantics as broadcast.
    ///
    /// The only reader that consults both tables: a reply has to reach a paste
    /// client precisely because it never will via `broadcast`.
    ///
    /// Takes an encoded frame rather than a `&Message` so a caller with the same
    /// message for several peers encodes it once and hands each a refcount,
    /// exactly as `broadcast` does — otherwise a resync burst re-serializes a
    /// whole clipboard payload (up to `max_payload_size`) per recipient.
    pub fn send_frame_to(&self, peer: Uuid, frame: &Frame) {
        let target = self
            .peer_sender(peer)
            .or_else(|| self.clients.lock().unwrap().get(&peer).cloned());
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

    /// How many mesh members are connected. Paste clients are not members and
    /// are not counted — by construction, not by filtering.
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
        mesh.register(peer, tx1, PeerRole::Peer);
        assert_eq!(connects.try_recv().unwrap(), peer);
        // a duplicate (standby) connection must not re-trigger resync
        mesh.register(peer, tx2, PeerRole::Peer);
        assert!(connects.try_recv().is_err());
    }

    #[tokio::test]
    async fn a_paster_costs_no_resync_and_receives_no_broadcast() {
        // A `--paste` client asks one question and leaves. Treating it as a peer
        // made every `wl-paste` cost the serving node a full connect resync — a
        // rules snapshot plus a live capture of every synced selection, which on
        // Wayland is one connection per advertised MIME type.
        let (mesh, _rx, mut connects) = new_mesh();
        let paster = Uuid::new_v4();
        let (tx, mut paste_rx) = mpsc::channel(8);
        let conn = mesh.register(paster, tx, PeerRole::Paster);
        assert!(
            connects.try_recv().is_err(),
            "a paster must not trigger a resync"
        );
        assert_eq!(mesh.peer_count(), 0, "a paster is not a mesh member");

        // It is still reachable for its reply...
        mesh.send_frame_to(paster, &encode_frame(&clip("the answer")));
        assert_eq!(recv(&mut paste_rx), clip("the answer"));

        // ...but is not a sync destination.
        mesh.broadcast(&clip("a later copy"));
        assert!(
            paste_rx.try_recv().is_err(),
            "a paster must not receive broadcasts"
        );

        // ...and leaves without disturbing the peer table it was never in.
        mesh.unregister(paster, conn);
        mesh.send_frame_to(paster, &encode_frame(&clip("too late")));
        assert!(paste_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn send_to_reaches_only_the_target_peer() {
        let (mesh, _rx, _c) = new_mesh();
        let peer_a = Uuid::new_v4();
        let peer_b = Uuid::new_v4();
        let (tx_a, mut rx_a) = mpsc::channel(8);
        let (tx_b, mut rx_b) = mpsc::channel(8);
        mesh.register(peer_a, tx_a, PeerRole::Peer);
        mesh.register(peer_b, tx_b, PeerRole::Peer);
        mesh.send_frame_to(peer_a, &encode_frame(&clip("targeted")));
        assert_eq!(recv(&mut rx_a), clip("targeted"));
        assert!(rx_b.try_recv().is_err());
    }

    #[tokio::test]
    async fn broadcast_uses_only_the_designated_connection_per_peer() {
        let (mesh, _rx, _c) = new_mesh();
        let peer = Uuid::new_v4();
        let (tx1, mut rx1) = mpsc::channel(8);
        let (tx2, mut rx2) = mpsc::channel(8);
        let c1 = mesh.register(peer, tx1, PeerRole::Peer);
        let _c2 = mesh.register(peer, tx2, PeerRole::Peer);

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
        mesh.register(Uuid::new_v4(), tx_a, PeerRole::Peer);
        mesh.register(Uuid::new_v4(), tx_b, PeerRole::Peer);

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
        let c = mesh.register(peer, tx, PeerRole::Peer);
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
