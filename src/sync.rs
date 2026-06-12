use crate::clipboard::Clipboard;
use crate::config::{Config, Direction};
use crate::mesh::Mesh;
use crate::protocol::{content_hash, Message, Offer, SelectionKind};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{debug, warn};
use uuid::Uuid;

pub const SENSITIVE_MIME: &str = "x-kde-passwordManagerHint";

/// Password managers mark secret clipboard contents with this hint.
pub fn is_sensitive(offer: &Offer) -> bool {
    offer
        .get(SENSITIVE_MIME)
        .map(|v| v.trim_ascii() == b"secret")
        .unwrap_or(false)
}

/// "text/plain" exact, "text/*" prefix, "*" everything.
pub fn mime_matches(pattern: &str, mime: &str) -> bool {
    if pattern == "*" || pattern == mime {
        return true;
    }
    match pattern.strip_suffix("/*") {
        Some(prefix) => mime.split('/').next() == Some(prefix),
        None => false,
    }
}

fn filter_offer(offer: Offer, allow: Option<&[String]>, deny: &[String]) -> Offer {
    offer
        .into_iter()
        .filter(|(m, _)| !deny.iter().any(|p| mime_matches(p, m)))
        .filter(|(m, _)| {
            allow
                .map(|a| a.iter().any(|p| mime_matches(p, m)))
                .unwrap_or(true)
        })
        .collect()
}

fn offer_size(offer: &Offer) -> usize {
    offer.iter().map(|(m, d)| m.len() + d.len()).sum()
}

/// Bridges the local clipboard and the mesh, with echo suppression,
/// dedup, debounce, direction control, and content filtering.
pub struct SyncEngine<C> {
    clipboard: Arc<C>,
    mesh: Arc<Mesh>,
    cfg: Arc<Config>,
    /// Hash of the last offer applied from the network, per selection.
    last_applied: Mutex<HashMap<SelectionKind, [u8; 32]>>,
    /// Hash of the last offer we broadcast, per selection.
    last_broadcast: Mutex<HashMap<SelectionKind, [u8; 32]>>,
    /// When the current content of each selection entered the mesh
    /// (ms since epoch). Arbitrates resyncs: newest content wins.
    current_ts: Mutex<HashMap<SelectionKind, u64>>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

impl<C: Clipboard> SyncEngine<C> {
    pub fn new(clipboard: Arc<C>, mesh: Arc<Mesh>, cfg: Arc<Config>) -> Arc<SyncEngine<C>> {
        Arc::new(SyncEngine {
            clipboard,
            mesh,
            cfg,
            last_applied: Mutex::new(HashMap::new()),
            last_broadcast: Mutex::new(HashMap::new()),
            current_ts: Mutex::new(HashMap::new()),
        })
    }

    /// Main loop. Runs until either the watcher or the inbound channel
    /// closes (at which point half the engine would be dead, so it stops).
    pub async fn run(
        self: Arc<Self>,
        mut inbound: mpsc::Receiver<(Uuid, Message)>,
        mut connects: mpsc::Receiver<Uuid>,
    ) {
        let mut watch = self.clipboard.watch();
        loop {
            tokio::select! {
                kind = watch.recv() => match kind {
                    Some(kind) => self.on_local_change(kind, &mut watch).await,
                    None => {
                        warn!("clipboard watcher channel closed; stopping sync engine");
                        break;
                    }
                },
                msg = inbound.recv() => match msg {
                    Some((from, msg)) => self.on_inbound(from, msg).await,
                    None => {
                        warn!("inbound channel closed; stopping sync engine");
                        break;
                    }
                },
                peer = connects.recv() => match peer {
                    Some(peer) => self.on_peer_connected(peer).await,
                    None => {
                        warn!("connect-event channel closed; stopping sync engine");
                        break;
                    }
                },
            }
        }
    }

    /// Debounce: keep absorbing change events until the clipboard has been
    /// quiet for debounce_ms, then broadcast the final state.
    async fn on_local_change(
        &self,
        first: SelectionKind,
        watch: &mut mpsc::UnboundedReceiver<SelectionKind>,
    ) {
        let mut kinds = vec![first];
        if self.cfg.debounce_ms > 0 {
            let window = Duration::from_millis(self.cfg.debounce_ms);
            let quiet = tokio::time::sleep(window);
            tokio::pin!(quiet);
            loop {
                tokio::select! {
                    _ = &mut quiet => break,
                    more = watch.recv() => match more {
                        Some(k) => {
                            if !kinds.contains(&k) {
                                kinds.push(k);
                            }
                            quiet.as_mut().reset(tokio::time::Instant::now() + window);
                        }
                        None => break,
                    },
                }
            }
        }
        for kind in kinds {
            self.broadcast_selection(kind).await;
        }
    }

    /// Read the selection and apply the content filters (sensitive, MIME,
    /// size). Returns None when there is nothing syncable.
    async fn capture_offer(&self, kind: SelectionKind) -> Option<Offer> {
        let offer = match self.clipboard.read_offer(kind).await {
            Ok(o) => o,
            Err(e) => {
                warn!("failed to read clipboard: {e:#}");
                return None;
            }
        };
        if offer.is_empty() {
            return None;
        }
        if self.cfg.exclude_sensitive && is_sensitive(&offer) {
            debug!("skipping sensitive clipboard contents");
            return None;
        }
        let offer = filter_offer(offer, self.cfg.mime_allow.as_deref(), &self.cfg.mime_deny);
        if offer.is_empty() {
            return None;
        }
        let size = offer_size(&offer);
        if size > self.cfg.max_payload_size {
            debug!(
                size,
                cap = self.cfg.max_payload_size,
                "skipping oversized clipboard contents"
            );
            return None;
        }
        Some(offer)
    }

    async fn broadcast_selection(&self, kind: SelectionKind) {
        if kind == SelectionKind::Primary && !self.cfg.sync_primary {
            return;
        }
        if self.cfg.direction == Direction::ReceiveOnly {
            return;
        }
        let Some(offer) = self.capture_offer(kind).await else {
            return;
        };
        let hash = content_hash(&offer);
        // echo: this change is the one we just applied from the network
        if self.last_applied.lock().unwrap().get(&kind) == Some(&hash) {
            return;
        }
        // dedup: we already broadcast exactly this content
        if self.last_broadcast.lock().unwrap().get(&kind) == Some(&hash) {
            return;
        }
        self.last_broadcast.lock().unwrap().insert(kind, hash);
        let set_at_ms = now_ms();
        self.current_ts.lock().unwrap().insert(kind, set_at_ms);
        debug!(
            ?kind,
            size = offer_size(&offer),
            "broadcasting clipboard update"
        );
        self.mesh.broadcast(&Message::Clip {
            kind,
            hash,
            offer,
            set_at_ms,
            resync: false,
        });
    }

    /// A peer just (re)connected: push our current state so it converges
    /// without waiting for the next copy. The receiver applies it only if
    /// it is newer than what it holds, so two nodes resyncing at each
    /// other settle on the most recent content instead of swapping.
    async fn on_peer_connected(&self, peer: Uuid) {
        if !self.cfg.resync_on_connect {
            return;
        }
        if self.cfg.direction == Direction::ReceiveOnly {
            return;
        }
        let mut kinds = vec![SelectionKind::Clipboard];
        if self.cfg.sync_primary {
            kinds.push(SelectionKind::Primary);
        }
        for kind in kinds {
            let Some(offer) = self.capture_offer(kind).await else {
                continue;
            };
            let hash = content_hash(&offer);
            // Only push content whose mesh entry time we know (it went
            // through a broadcast or an apply); anything else is in flux
            // and the watcher/debounce path will handle it.
            let known = self.last_broadcast.lock().unwrap().get(&kind) == Some(&hash)
                || self.last_applied.lock().unwrap().get(&kind) == Some(&hash);
            if !known {
                continue;
            }
            let Some(set_at_ms) = self.current_ts.lock().unwrap().get(&kind).copied() else {
                continue;
            };
            debug!(?kind, %peer, "resyncing clipboard state to reconnected peer");
            self.mesh.send_to(
                peer,
                &Message::Clip {
                    kind,
                    hash,
                    offer,
                    set_at_ms,
                    resync: true,
                },
            );
        }
    }

    async fn on_inbound(&self, from: Uuid, msg: Message) {
        let Message::Clip {
            kind,
            hash,
            offer,
            set_at_ms,
            resync,
        } = msg
        else {
            warn!(peer = %from, "unexpected message type after handshake");
            return;
        };
        if self.cfg.direction == Direction::SendOnly {
            return;
        }
        if kind == SelectionKind::Primary && !self.cfg.sync_primary {
            return;
        }
        if content_hash(&offer) != hash {
            warn!(peer = %from, "hash mismatch on inbound offer; dropping");
            return;
        }
        // Resyncs only apply when strictly newer than the content we hold;
        // live updates always apply (clock skew must not break normal use).
        if resync {
            let local_ts = self
                .current_ts
                .lock()
                .unwrap()
                .get(&kind)
                .copied()
                .unwrap_or(0);
            if set_at_ms <= local_ts {
                debug!(?kind, peer = %from, "ignoring stale resync");
                return;
            }
        }
        if self.last_applied.lock().unwrap().get(&kind) == Some(&hash) {
            return; // already applied (e.g. two peers relayed the same copy)
        }
        debug!(?kind, peer = %from, resync, "applying remote clipboard update");
        // Record as applied only on success, so a transient write failure
        // doesn't permanently block this content from being re-applied.
        match self.clipboard.write_offer(kind, offer).await {
            Ok(()) => {
                self.last_applied.lock().unwrap().insert(kind, hash);
                self.current_ts.lock().unwrap().insert(kind, set_at_ms);
            }
            Err(e) => warn!("failed to write clipboard: {e:#}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clipboard::mock::MockClipboard;
    use crate::config::{Config, Direction};
    use crate::mesh::Mesh;
    use std::time::Duration;
    use tokio::time::timeout;

    fn offer(text: &str) -> Offer {
        [("text/plain".to_string(), text.as_bytes().to_vec())]
            .into_iter()
            .collect()
    }

    struct Harness {
        clip: Arc<MockClipboard>,
        mesh: Arc<Mesh>,
        conn_rx: mpsc::Receiver<Message>,
        in_tx: mpsc::Sender<(Uuid, Message)>,
        remote_id: Uuid,
    }

    async fn start(cfg: Config) -> Harness {
        let (in_tx, in_rx) = mpsc::channel(64);
        let (connect_tx, connect_rx) = mpsc::channel(64);
        let mesh = Mesh::new(Uuid::new_v4(), in_tx.clone(), connect_tx);
        let (conn_tx, conn_rx) = mpsc::channel(64);
        let remote_id = Uuid::new_v4();
        mesh.register(remote_id, conn_tx);
        // drain the connect event from the initial registration so tests
        // that don't care about resync aren't affected
        let mut connect_rx = connect_rx;
        let _ = connect_rx.try_recv();
        let clip = MockClipboard::new();
        let engine = SyncEngine::new(clip.clone(), mesh.clone(), Arc::new(cfg));
        tokio::spawn(engine.run(in_rx, connect_rx));
        // wait until the engine has subscribed to the watcher
        while clip.watcher_count() == 0 {
            tokio::task::yield_now().await;
        }
        Harness {
            clip,
            mesh,
            conn_rx,
            in_tx,
            remote_id,
        }
    }

    async fn recv_clip(h: &mut Harness) -> (SelectionKind, [u8; 32], Offer) {
        match timeout(Duration::from_secs(1), h.conn_rx.recv())
            .await
            .unwrap()
            .unwrap()
        {
            Message::Clip {
                kind, hash, offer, ..
            } => (kind, hash, offer),
            other => panic!("expected Clip, got {other:?}"),
        }
    }

    async fn assert_no_broadcast(h: &mut Harness) {
        assert!(
            timeout(Duration::from_millis(200), h.conn_rx.recv())
                .await
                .is_err(),
            "unexpected broadcast"
        );
    }

    async fn send_inbound(h: &Harness, kind: SelectionKind, o: Offer) {
        send_inbound_full(h, kind, o, now_ms(), false).await;
    }

    async fn send_inbound_full(h: &Harness, kind: SelectionKind, o: Offer, ts: u64, resync: bool) {
        let msg = Message::Clip {
            kind,
            hash: content_hash(&o),
            offer: o,
            set_at_ms: ts,
            resync,
        };
        h.in_tx.send((h.remote_id, msg)).await.unwrap();
    }

    async fn wait_applied(h: &Harness, kind: SelectionKind, o: &Offer) {
        timeout(Duration::from_secs(1), async {
            while h.clip.get(kind).as_ref() != Some(o) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("offer was not applied");
    }

    #[tokio::test(start_paused = true)]
    async fn local_copy_is_broadcast() {
        let mut h = start(Config::for_test("s")).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("hello"));
        let (kind, hash, o) = recv_clip(&mut h).await;
        assert_eq!(kind, SelectionKind::Clipboard);
        assert_eq!(o, offer("hello"));
        assert_eq!(hash, content_hash(&o));
    }

    #[tokio::test(start_paused = true)]
    async fn identical_content_is_not_rebroadcast() {
        let mut h = start(Config::for_test("s")).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("same"));
        recv_clip(&mut h).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("same"));
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn sensitive_offers_are_not_broadcast() {
        let mut h = start(Config::for_test("s")).await;
        let mut o = offer("hunter2");
        o.insert("x-kde-passwordManagerHint".to_string(), b"secret".to_vec());
        h.clip.local_copy(SelectionKind::Clipboard, o);
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn sensitive_filter_can_be_disabled() {
        let mut cfg = Config::for_test("s");
        cfg.exclude_sensitive = false;
        let mut h = start(cfg).await;
        let mut o = offer("hunter2");
        o.insert("x-kde-passwordManagerHint".to_string(), b"secret".to_vec());
        h.clip.local_copy(SelectionKind::Clipboard, o.clone());
        let (_, _, got) = recv_clip(&mut h).await;
        assert_eq!(got, o);
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_clip_is_applied_and_not_echoed_back() {
        let mut h = start(Config::for_test("s")).await;
        let o = offer("from remote");
        send_inbound(&h, SelectionKind::Clipboard, o.clone()).await;
        wait_applied(&h, SelectionKind::Clipboard, &o).await;
        assert_eq!(h.clip.write_count(), 1);
        // applying re-fired the watcher; echo suppression must hold
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn failed_write_does_not_poison_dedup() {
        let h = start(Config::for_test("s")).await;
        let o = offer("retry me");
        // first delivery fails at the clipboard layer
        h.clip.set_fail_writes(true);
        send_inbound(&h, SelectionKind::Clipboard, o.clone()).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(h.clip.get(SelectionKind::Clipboard), None);
        // a relay of the same content must still be applied
        h.clip.set_fail_writes(false);
        send_inbound(&h, SelectionKind::Clipboard, o.clone()).await;
        wait_applied(&h, SelectionKind::Clipboard, &o).await;
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_with_bad_hash_is_rejected() {
        let mut h = start(Config::for_test("s")).await;
        let o = offer("tampered");
        let msg = Message::Clip {
            kind: SelectionKind::Clipboard,
            hash: [9u8; 32],
            offer: o,
            set_at_ms: 1,
            resync: false,
        };
        h.in_tx.send((h.remote_id, msg)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(h.clip.write_count(), 0);
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn receive_only_does_not_broadcast() {
        let mut cfg = Config::for_test("s");
        cfg.direction = Direction::ReceiveOnly;
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("local"));
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn send_only_ignores_inbound() {
        let mut cfg = Config::for_test("s");
        cfg.direction = Direction::SendOnly;
        let h = start(cfg).await;
        send_inbound(&h, SelectionKind::Clipboard, offer("remote")).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(h.clip.write_count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn primary_is_ignored_unless_enabled() {
        let mut h = start(Config::for_test("s")).await;
        h.clip.local_copy(SelectionKind::Primary, offer("sel"));
        assert_no_broadcast(&mut h).await;
        send_inbound(&h, SelectionKind::Primary, offer("rem")).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(h.clip.write_count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn primary_is_synced_when_enabled() {
        let mut cfg = Config::for_test("s");
        cfg.sync_primary = true;
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Primary, offer("sel"));
        let (kind, _, o) = recv_clip(&mut h).await;
        assert_eq!(kind, SelectionKind::Primary);
        assert_eq!(o, offer("sel"));
    }

    #[tokio::test(start_paused = true)]
    async fn oversized_offers_are_not_broadcast() {
        let mut cfg = Config::for_test("s");
        cfg.max_payload_size = 8;
        let mut h = start(cfg).await;
        h.clip
            .local_copy(SelectionKind::Clipboard, offer("way more than eight bytes"));
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn mime_deny_strips_matching_types() {
        let mut cfg = Config::for_test("s");
        cfg.mime_deny = vec!["image/*".to_string()];
        let mut h = start(cfg).await;
        let mut o = offer("text part");
        o.insert("image/png".to_string(), vec![0u8; 16]);
        h.clip.local_copy(SelectionKind::Clipboard, o);
        let (_, _, got) = recv_clip(&mut h).await;
        assert_eq!(got, offer("text part"));
    }

    #[tokio::test(start_paused = true)]
    async fn debounce_collapses_rapid_copies_into_final_state() {
        let mut cfg = Config::for_test("s");
        cfg.debounce_ms = 100;
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("one"));
        h.clip.local_copy(SelectionKind::Clipboard, offer("two"));
        let (_, _, got) = recv_clip(&mut h).await;
        assert_eq!(got, offer("two"));
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn mime_allow_restricts_broadcast_to_matching_types() {
        let mut cfg = Config::for_test("s");
        cfg.mime_allow = Some(vec!["text/*".to_string()]);
        let mut h = start(cfg).await;
        let mut o = offer("text part");
        o.insert("image/png".to_string(), vec![0u8; 16]);
        h.clip.local_copy(SelectionKind::Clipboard, o);
        let (_, _, got) = recv_clip(&mut h).await;
        assert_eq!(got, offer("text part"));
    }

    #[tokio::test(start_paused = true)]
    async fn offer_with_no_allowed_types_is_not_broadcast() {
        let mut cfg = Config::for_test("s");
        cfg.mime_allow = Some(vec!["text/*".to_string()]);
        let mut h = start(cfg).await;
        let o: Offer = [("image/png".to_string(), vec![0u8; 16])]
            .into_iter()
            .collect();
        h.clip.local_copy(SelectionKind::Clipboard, o);
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn debounce_window_resets_on_new_activity() {
        let mut cfg = Config::for_test("s");
        cfg.debounce_ms = 100;
        let mut h = start(cfg).await;
        // each copy lands inside the previous quiet window, so the window
        // keeps resetting and only the final state is broadcast once
        h.clip.local_copy(SelectionKind::Clipboard, offer("a"));
        tokio::time::sleep(Duration::from_millis(80)).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("b"));
        tokio::time::sleep(Duration::from_millis(80)).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("c"));
        let (_, _, got) = recv_clip(&mut h).await;
        assert_eq!(got, offer("c"));
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_primary_applies_to_primary_only() {
        let mut cfg = Config::for_test("s");
        cfg.sync_primary = true;
        let h = start(cfg).await;
        let o = offer("sel");
        send_inbound(&h, SelectionKind::Primary, o.clone()).await;
        wait_applied(&h, SelectionKind::Primary, &o).await;
        assert_eq!(h.clip.get(SelectionKind::Clipboard), None);
    }

    #[tokio::test(start_paused = true)]
    async fn payload_exactly_at_cap_is_broadcast() {
        // offer_size counts mime key bytes + data bytes
        let o = offer("12345678"); // "text/plain" (10) + 8 = 18
        let mut cfg = Config::for_test("s");
        cfg.max_payload_size = 18;
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Clipboard, o.clone());
        let (_, _, got) = recv_clip(&mut h).await;
        assert_eq!(got, o);

        let mut cfg = Config::for_test("s");
        cfg.max_payload_size = 17; // one byte under
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Clipboard, o);
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn resync_pushes_state_to_newly_connected_peer() {
        let mut h = start(Config::for_test("s")).await;
        h.clip
            .local_copy(SelectionKind::Clipboard, offer("current"));
        recv_clip(&mut h).await; // consume the live broadcast

        // a second peer joins; engine must push current state to it only
        let (tx2, mut rx2) = mpsc::channel(8);
        let peer2 = Uuid::new_v4();
        h.mesh.register(peer2, tx2);
        let msg = timeout(Duration::from_secs(1), rx2.recv())
            .await
            .unwrap()
            .unwrap();
        match msg {
            Message::Clip {
                offer: o, resync, ..
            } => {
                assert_eq!(o, offer("current"));
                assert!(resync);
            }
            other => panic!("expected resync Clip, got {other:?}"),
        }
        // the pre-existing peer must not receive a duplicate
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn resync_can_be_disabled() {
        let mut cfg = Config::for_test("s");
        cfg.resync_on_connect = false;
        let mut h = start(cfg).await;
        h.clip
            .local_copy(SelectionKind::Clipboard, offer("current"));
        recv_clip(&mut h).await;

        let (tx2, mut rx2) = mpsc::channel(8);
        h.mesh.register(Uuid::new_v4(), tx2);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(rx2.try_recv().is_err(), "resync must be disabled");
    }

    #[tokio::test(start_paused = true)]
    async fn fresh_node_applies_inbound_resync() {
        let h = start(Config::for_test("s")).await;
        let o = offer("restored");
        send_inbound_full(&h, SelectionKind::Clipboard, o.clone(), 5000, true).await;
        wait_applied(&h, SelectionKind::Clipboard, &o).await;
    }

    #[tokio::test(start_paused = true)]
    async fn stale_resync_is_ignored() {
        let h = start(Config::for_test("s")).await;
        let newer = offer("newer");
        send_inbound_full(&h, SelectionKind::Clipboard, newer.clone(), 5000, false).await;
        wait_applied(&h, SelectionKind::Clipboard, &newer).await;

        // an older resync (e.g. from a peer that slept) must not win
        send_inbound_full(&h, SelectionKind::Clipboard, offer("older"), 1000, true).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(h.clip.get(SelectionKind::Clipboard), Some(newer));
    }

    #[test]
    fn mime_matches_patterns() {
        assert!(mime_matches("text/plain", "text/plain"));
        assert!(mime_matches("text/*", "text/html"));
        assert!(mime_matches("*", "application/octet-stream"));
        assert!(!mime_matches("text/*", "image/png"));
        assert!(!mime_matches("text/plain", "text/html"));
    }
}
