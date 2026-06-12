use crate::clipboard::Clipboard;
use crate::config::{Config, Direction};
use crate::mesh::Mesh;
use crate::protocol::{content_hash, Message, Offer, SelectionKind};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
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
        .filter(|(m, _)| allow.map(|a| a.iter().any(|p| mime_matches(p, m))).unwrap_or(true))
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
}

impl<C: Clipboard> SyncEngine<C> {
    pub fn new(clipboard: Arc<C>, mesh: Arc<Mesh>, cfg: Arc<Config>) -> Arc<SyncEngine<C>> {
        Arc::new(SyncEngine {
            clipboard,
            mesh,
            cfg,
            last_applied: Mutex::new(HashMap::new()),
            last_broadcast: Mutex::new(HashMap::new()),
        })
    }

    /// Main loop. Runs until both the watcher and inbound channels close.
    pub async fn run(self: Arc<Self>, mut inbound: mpsc::Receiver<(Uuid, Message)>) {
        let mut watch = self.clipboard.watch();
        loop {
            tokio::select! {
                kind = watch.recv() => match kind {
                    Some(kind) => self.on_local_change(kind, &mut watch).await,
                    None => break,
                },
                msg = inbound.recv() => match msg {
                    Some((from, msg)) => self.on_inbound(from, msg).await,
                    None => break,
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

    async fn broadcast_selection(&self, kind: SelectionKind) {
        if kind == SelectionKind::Primary && !self.cfg.sync_primary {
            return;
        }
        if self.cfg.direction == Direction::ReceiveOnly {
            return;
        }
        let offer = match self.clipboard.read_offer(kind).await {
            Ok(o) => o,
            Err(e) => {
                warn!("failed to read clipboard: {e:#}");
                return;
            }
        };
        if offer.is_empty() {
            return;
        }
        if self.cfg.exclude_sensitive && is_sensitive(&offer) {
            debug!("skipping sensitive clipboard contents");
            return;
        }
        let offer = filter_offer(offer, self.cfg.mime_allow.as_deref(), &self.cfg.mime_deny);
        if offer.is_empty() {
            return;
        }
        let size = offer_size(&offer);
        if size > self.cfg.max_payload_size {
            debug!(size, cap = self.cfg.max_payload_size, "skipping oversized clipboard contents");
            return;
        }
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
        debug!(?kind, size, "broadcasting clipboard update");
        self.mesh.broadcast(&Message::Clip { kind, hash, offer });
    }

    async fn on_inbound(&self, from: Uuid, msg: Message) {
        let Message::Clip { kind, hash, offer } = msg else {
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
        if self.last_applied.lock().unwrap().get(&kind) == Some(&hash) {
            return; // already applied (e.g. two peers relayed the same copy)
        }
        self.last_applied.lock().unwrap().insert(kind, hash);
        debug!(?kind, peer = %from, "applying remote clipboard update");
        if let Err(e) = self.clipboard.write_offer(kind, offer).await {
            warn!("failed to write clipboard: {e:#}");
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
        [("text/plain".to_string(), text.as_bytes().to_vec())].into_iter().collect()
    }

    struct Harness {
        clip: Arc<MockClipboard>,
        conn_rx: mpsc::Receiver<Message>,
        in_tx: mpsc::Sender<(Uuid, Message)>,
        remote_id: Uuid,
    }

    async fn start(cfg: Config) -> Harness {
        let (in_tx, in_rx) = mpsc::channel(64);
        let mesh = Mesh::new(Uuid::new_v4(), in_tx.clone());
        let (conn_tx, conn_rx) = mpsc::channel(64);
        let remote_id = Uuid::new_v4();
        mesh.register(remote_id, conn_tx);
        let clip = MockClipboard::new();
        let engine = SyncEngine::new(clip.clone(), mesh, Arc::new(cfg));
        tokio::spawn(engine.run(in_rx));
        // wait until the engine has subscribed to the watcher
        while clip.watcher_count() == 0 {
            tokio::task::yield_now().await;
        }
        Harness { clip, conn_rx, in_tx, remote_id }
    }

    async fn recv_clip(h: &mut Harness) -> (SelectionKind, [u8; 32], Offer) {
        match timeout(Duration::from_secs(1), h.conn_rx.recv()).await.unwrap().unwrap() {
            Message::Clip { kind, hash, offer } => (kind, hash, offer),
            other => panic!("expected Clip, got {other:?}"),
        }
    }

    async fn assert_no_broadcast(h: &mut Harness) {
        assert!(
            timeout(Duration::from_millis(200), h.conn_rx.recv()).await.is_err(),
            "unexpected broadcast"
        );
    }

    async fn send_inbound(h: &Harness, kind: SelectionKind, o: Offer) {
        let msg = Message::Clip { kind, hash: content_hash(&o), offer: o };
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
    async fn inbound_with_bad_hash_is_rejected() {
        let mut h = start(Config::for_test("s")).await;
        let o = offer("tampered");
        let msg = Message::Clip { kind: SelectionKind::Clipboard, hash: [9u8; 32], offer: o };
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
        h.clip.local_copy(SelectionKind::Clipboard, offer("way more than eight bytes"));
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

    #[test]
    fn mime_matches_patterns() {
        assert!(mime_matches("text/plain", "text/plain"));
        assert!(mime_matches("text/*", "text/html"));
        assert!(mime_matches("*", "application/octet-stream"));
        assert!(!mime_matches("text/*", "image/png"));
        assert!(!mime_matches("text/plain", "text/html"));
    }
}
