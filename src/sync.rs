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

/// Reject inbound stamps more than this far in the future. A healthy hybrid
/// clock stamp is always near wall-clock time; a wildly larger value (a
/// buggy/malicious peer, or one with a broken RTC) would otherwise pin our
/// logical clock high and stop our own copies from ever winning again.
const MAX_FUTURE_SKEW_MS: u64 = 24 * 60 * 60 * 1000;

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

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// What this node believes is the mesh-current content of one selection.
/// One record replaces the former three parallel maps so the hash, the
/// ordering stamp, and the origin can never describe different contents.
#[derive(Clone, Copy)]
struct ContentState {
    hash: [u8; 32],
    /// Hybrid logical stamp; ordered with `origin` as `(stamp, origin)`.
    stamp: u64,
    origin: Uuid,
}

impl ContentState {
    /// True if `(stamp, origin)` strictly supersedes this state's order.
    fn superseded_by(&self, stamp: u64, origin: Uuid) -> bool {
        (stamp, origin) > (self.stamp, self.origin)
    }
}

/// Bridges the local clipboard and the mesh, with echo suppression,
/// ordering, debounce, direction control, and content filtering.
pub struct SyncEngine<C> {
    clipboard: Arc<C>,
    mesh: Arc<Mesh>,
    cfg: Arc<Config>,
    /// Mesh-current content per selection. Updated on both broadcast and
    /// apply; echo/dedup is "incoming hash == current hash", ordering is
    /// `(stamp, origin)`.
    current: Mutex<HashMap<SelectionKind, ContentState>>,
    /// Hybrid logical clock: max of wall-clock ms and the highest stamp
    /// seen, so reordered or modestly skewed updates still order sanely.
    clock: Mutex<u64>,
}

impl<C: Clipboard> SyncEngine<C> {
    pub fn new(clipboard: Arc<C>, mesh: Arc<Mesh>, cfg: Arc<Config>) -> Arc<SyncEngine<C>> {
        Arc::new(SyncEngine {
            clipboard,
            mesh,
            cfg,
            current: Mutex::new(HashMap::new()),
            clock: Mutex::new(0),
        })
    }

    /// Selections this node syncs (Primary only when enabled).
    fn synced_kinds(&self) -> Vec<SelectionKind> {
        let mut kinds = vec![SelectionKind::Clipboard];
        if self.cfg.sync_primary {
            kinds.push(SelectionKind::Primary);
        }
        kinds
    }

    fn may_send(&self, kind: SelectionKind) -> bool {
        self.cfg.direction != Direction::ReceiveOnly
            && (kind != SelectionKind::Primary || self.cfg.sync_primary)
    }

    fn may_recv(&self, kind: SelectionKind) -> bool {
        self.cfg.direction != Direction::SendOnly
            && (kind != SelectionKind::Primary || self.cfg.sync_primary)
    }

    /// Issue a fresh stamp for locally originated content. saturating_add
    /// keeps a poisoned clock from panicking (debug) or wrapping to 0
    /// (release) — defense in depth behind the inbound skew check.
    fn tick(&self) -> u64 {
        let mut c = self.clock.lock().unwrap();
        *c = c.saturating_add(1).max(now_ms());
        *c
    }

    /// Advance the logical clock past a stamp we received.
    fn observe(&self, stamp: u64) {
        let mut c = self.clock.lock().unwrap();
        *c = (*c).max(stamp);
    }

    /// Main loop. Debounce lives in the select as a deadline arm so that a
    /// storm of local change events can never starve inbound/connect
    /// processing. Runs until any of its input channels close.
    pub async fn run(
        self: Arc<Self>,
        mut inbound: mpsc::Receiver<(Uuid, Message)>,
        mut connects: mpsc::Receiver<Uuid>,
    ) {
        let mut watch = self.clipboard.watch();
        self.prime().await;

        let window = Duration::from_millis(self.cfg.debounce_ms);
        let mut pending: Vec<SelectionKind> = Vec::new();
        // Far-future placeholder; the `armed` precondition keeps it from
        // firing (and from registering a timer) until we arm it.
        let deadline = tokio::time::sleep(Duration::from_secs(86_400));
        tokio::pin!(deadline);
        let mut armed = false;

        loop {
            tokio::select! {
                kind = watch.recv() => match kind {
                    Some(kind) => {
                        if !pending.contains(&kind) {
                            pending.push(kind);
                        }
                        if self.cfg.debounce_ms == 0 {
                            for k in pending.drain(..) {
                                self.broadcast_selection(k).await;
                            }
                        } else {
                            deadline.as_mut().reset(tokio::time::Instant::now() + window);
                            armed = true;
                        }
                    }
                    None => {
                        warn!("clipboard watcher channel closed; stopping sync engine");
                        break;
                    }
                },
                _ = &mut deadline, if armed => {
                    armed = false;
                    for k in std::mem::take(&mut pending) {
                        self.broadcast_selection(k).await;
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

    /// Capture the existing clipboard at startup with stamp 0, so a
    /// restarted node neither re-broadcasts its restored clipboard as
    /// fresh content nor wins a resync against a peer's genuinely newer
    /// content (it can't know how old its restored clipboard is). The
    /// first real local copy stamps a real clock value and propagates
    /// normally.
    async fn prime(&self) {
        for kind in self.synced_kinds() {
            if let Some(offer) = self.capture_offer(kind).await {
                let hash = content_hash(&offer);
                debug!(
                    ?kind,
                    size = offer_size(&offer),
                    "primed existing clipboard state"
                );
                self.current.lock().unwrap().insert(
                    kind,
                    ContentState {
                        hash,
                        stamp: 0,
                        origin: self.mesh.own_id(),
                    },
                );
            }
        }
    }

    /// Read the selection and apply the content filters (sensitive, MIME,
    /// size). Returns None when there is nothing syncable.
    fn filter(&self, offer: Offer) -> Option<Offer> {
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
            // warn, not debug: at the default log level the user would
            // otherwise have no clue why a large copy never syncs.
            warn!(
                size,
                cap = self.cfg.max_payload_size,
                "clipboard contents exceed max_payload_size; not syncing"
            );
            return None;
        }
        Some(offer)
    }

    async fn capture_offer(&self, kind: SelectionKind) -> Option<Offer> {
        let offer = match self.clipboard.read_offer(kind).await {
            Ok(o) => o,
            Err(e) => {
                warn!("failed to read clipboard: {e:#}");
                return None;
            }
        };
        self.filter(offer)
    }

    async fn broadcast_selection(&self, kind: SelectionKind) {
        if !self.may_send(kind) {
            return;
        }
        let Some(offer) = self.capture_offer(kind).await else {
            return;
        };
        let hash = content_hash(&offer);
        // Already the mesh-current content (we just applied it, or the user
        // re-copied identical bytes): nothing to do.
        if self.current.lock().unwrap().get(&kind).map(|s| s.hash) == Some(hash) {
            return;
        }
        let stamp = self.tick();
        let origin = self.mesh.own_id();
        self.current.lock().unwrap().insert(
            kind,
            ContentState {
                hash,
                stamp,
                origin,
            },
        );
        debug!(
            ?kind,
            size = offer_size(&offer),
            "broadcasting clipboard update"
        );
        self.mesh.broadcast(&Message::Clip {
            kind,
            hash,
            offer,
            stamp,
            origin,
        });
    }

    /// A peer just (re)connected: push our current state so it converges
    /// without waiting for the next copy. The receiver orders it by
    /// `(stamp, origin)` like any other update, so two nodes resyncing at
    /// each other settle on the same content instead of swapping.
    async fn on_peer_connected(&self, peer: Uuid) {
        if !self.cfg.resync_on_connect || self.cfg.direction == Direction::ReceiveOnly {
            return;
        }
        for kind in self.synced_kinds() {
            let Some(state) = self.current.lock().unwrap().get(&kind).copied() else {
                continue;
            };
            let Some(offer) = self.capture_offer(kind).await else {
                continue;
            };
            // Only resync if the live clipboard still matches our recorded
            // state; otherwise the watcher path will carry the newer content.
            if content_hash(&offer) != state.hash {
                continue;
            }
            debug!(?kind, %peer, "resyncing clipboard state to reconnected peer");
            self.mesh.send_to(
                peer,
                &Message::Clip {
                    kind,
                    hash: state.hash,
                    offer,
                    stamp: state.stamp,
                    origin: state.origin,
                },
            );
        }
    }

    async fn on_inbound(&self, from: Uuid, msg: Message) {
        let Message::Clip {
            kind,
            hash,
            offer,
            stamp,
            origin,
        } = msg
        else {
            warn!(peer = %from, "unexpected message type after handshake");
            return;
        };
        if !self.may_recv(kind) {
            return;
        }
        if content_hash(&offer) != hash {
            warn!(peer = %from, "hash mismatch on inbound offer; dropping");
            return;
        }
        // Drop implausibly-future stamps before they reach the clock, so one
        // peer with a broken clock can't poison ordering for this node.
        if stamp > now_ms().saturating_add(MAX_FUTURE_SKEW_MS) {
            warn!(peer = %from, stamp, "rejecting update with implausibly-future stamp (peer clock skew?)");
            return;
        }
        self.observe(stamp);
        // Apply the receiver's own content policy: configs can differ
        // between peers, and a node must not write contents it would never
        // have sent (e.g. password-manager secrets, or denied MIME types).
        let Some(offer) = self.filter(offer) else {
            return;
        };
        let applied_hash = content_hash(&offer);
        {
            let current = self.current.lock().unwrap();
            if let Some(state) = current.get(&kind) {
                if state.hash == applied_hash {
                    return; // already hold exactly this content
                }
                if !state.superseded_by(stamp, origin) {
                    debug!(?kind, peer = %from, "ignoring older/equal update");
                    return;
                }
            }
        }
        debug!(?kind, peer = %from, "applying remote clipboard update");
        // Record as current only on a successful write, so a transient
        // failure doesn't permanently block this content from re-applying.
        // The whole handler runs to completion on the single engine task
        // (it is awaited inline in run()'s select), so `current` cannot be
        // mutated across this await — the post-write insert is not a TOCTOU.
        match self.clipboard.write_offer(kind, offer).await {
            Ok(()) => {
                self.current.lock().unwrap().insert(
                    kind,
                    ContentState {
                        hash: applied_hash,
                        stamp,
                        origin,
                    },
                );
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
        start_seeded(cfg, None).await
    }

    /// Start the engine, optionally with clipboard content already present
    /// before it primes (models a daemon restart over an existing clipboard).
    async fn start_seeded(cfg: Config, seed: Option<Offer>) -> Harness {
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
        if let Some(o) = seed {
            clip.seed(SelectionKind::Clipboard, o);
        }
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

    async fn recv_msg(h: &mut Harness) -> Message {
        timeout(Duration::from_secs(1), h.conn_rx.recv())
            .await
            .unwrap()
            .unwrap()
    }

    /// The stamp of the next broadcast/resync message.
    async fn recv_stamp(h: &mut Harness) -> u64 {
        match recv_msg(h).await {
            Message::Clip { stamp, .. } => stamp,
            other => panic!("expected Clip, got {other:?}"),
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
        send_inbound_full(h, kind, o, now_ms()).await;
    }

    /// A stamp guaranteed to beat a locally issued one (which uses now_ms()).
    fn future_stamp(offset: u64) -> u64 {
        now_ms() + offset
    }

    async fn send_inbound_full(h: &Harness, kind: SelectionKind, o: Offer, stamp: u64) {
        let msg = Message::Clip {
            kind,
            hash: content_hash(&o),
            offer: o,
            stamp,
            origin: h.remote_id,
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
            stamp: 1,
            origin: h.remote_id,
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
            Message::Clip { offer: o, .. } => assert_eq!(o, offer("current")),
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
        send_inbound_full(&h, SelectionKind::Clipboard, o.clone(), 5000).await;
        wait_applied(&h, SelectionKind::Clipboard, &o).await;
    }

    #[tokio::test(start_paused = true)]
    async fn stale_resync_is_ignored() {
        let h = start(Config::for_test("s")).await;
        let newer = offer("newer");
        send_inbound_full(&h, SelectionKind::Clipboard, newer.clone(), 5000).await;
        wait_applied(&h, SelectionKind::Clipboard, &newer).await;

        // an older update (e.g. a resync from a peer that slept) must not win
        send_inbound_full(&h, SelectionKind::Clipboard, offer("older"), 1000).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(h.clip.get(SelectionKind::Clipboard), Some(newer));
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_sensitive_content_is_not_applied() {
        // a peer running exclude_sensitive=false must not get us to write a
        // password-manager secret to our clipboard when ours is enabled
        let h = start(Config::for_test("s")).await;
        let mut o = offer("hunter2");
        o.insert("x-kde-passwordManagerHint".to_string(), b"secret".to_vec());
        send_inbound(&h, SelectionKind::Clipboard, o).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(h.clip.write_count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_mime_deny_strips_before_writing() {
        let mut cfg = Config::for_test("s");
        cfg.mime_deny = vec!["image/*".to_string()];
        let h = start(cfg).await;
        let mut o = offer("text part");
        o.insert("image/png".to_string(), vec![0u8; 16]);
        send_inbound(&h, SelectionKind::Clipboard, o).await;
        wait_applied(&h, SelectionKind::Clipboard, &offer("text part")).await;
    }

    #[tokio::test(start_paused = true)]
    async fn recopying_superseded_content_is_rebroadcast() {
        // regression: re-copying content the node previously broadcast, after
        // the mesh moved on, must NOT be suppressed as a stale dedup
        let mut h = start(Config::for_test("s")).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("foo"));
        recv_clip(&mut h).await; // broadcast foo
        send_inbound_full(
            &h,
            SelectionKind::Clipboard,
            offer("bar"),
            future_stamp(5000),
        )
        .await;
        wait_applied(&h, SelectionKind::Clipboard, &offer("bar")).await;
        // user re-copies foo; mesh holds bar, so foo is genuinely new again
        h.clip.local_copy(SelectionKind::Clipboard, offer("foo"));
        let (_, _, got) = recv_clip(&mut h).await;
        assert_eq!(got, offer("foo"));
    }

    #[tokio::test(start_paused = true)]
    async fn live_update_previously_applied_then_superseded_reapplies() {
        // regression: a live update whose hash was applied earlier must apply
        // again if our current content has since changed
        let mut h = start(Config::for_test("s")).await;
        send_inbound_full(
            &h,
            SelectionKind::Clipboard,
            offer("foo"),
            future_stamp(1000),
        )
        .await;
        wait_applied(&h, SelectionKind::Clipboard, &offer("foo")).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("bar"));
        recv_clip(&mut h).await; // current is now bar (local copy, now_ms stamp)
        send_inbound_full(
            &h,
            SelectionKind::Clipboard,
            offer("foo"),
            future_stamp(60_000),
        )
        .await;
        wait_applied(&h, SelectionKind::Clipboard, &offer("foo")).await;
    }

    #[tokio::test(start_paused = true)]
    async fn rejects_implausibly_future_stamp() {
        // a peer with a broken clock must not poison ordering or crash us
        let h = start(Config::for_test("s")).await;
        send_inbound_full(
            &h,
            SelectionKind::Clipboard,
            offer("from the future"),
            now_ms() + 48 * 60 * 60 * 1000, // 48h ahead, past the skew bound
        )
        .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(h.clip.write_count(), 0);
        // a normal local copy afterwards must still be able to win
        let mut h = h;
        h.clip.local_copy(SelectionKind::Clipboard, offer("normal"));
        let (_, _, got) = recv_clip(&mut h).await;
        assert_eq!(got, offer("normal"));
    }

    #[tokio::test(start_paused = true)]
    async fn clock_observes_remote_stamp_so_local_copies_outrank_it() {
        let mut h = start(Config::for_test("s")).await;
        let high = now_ms() + 60 * 60 * 1000; // 1h ahead, within the skew bound
        send_inbound_full(&h, SelectionKind::Clipboard, offer("remote"), high).await;
        wait_applied(&h, SelectionKind::Clipboard, &offer("remote")).await;
        // our next local copy must carry a stamp above the observed remote one
        h.clip.local_copy(SelectionKind::Clipboard, offer("local"));
        assert!(recv_stamp(&mut h).await > high);
    }

    #[tokio::test(start_paused = true)]
    async fn local_stamps_are_strictly_monotonic() {
        let mut h = start(Config::for_test("s")).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("a"));
        let s1 = recv_stamp(&mut h).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("b"));
        let s2 = recv_stamp(&mut h).await;
        assert!(s2 > s1, "{s2} must exceed {s1}");
    }

    #[tokio::test(start_paused = true)]
    async fn primed_content_loses_resync_to_real_remote_content() {
        // a restarted node's restored clipboard (stamp 0) must yield to a
        // peer's genuinely-stamped content
        let h = start_seeded(Config::for_test("s"), Some(offer("restored"))).await;
        send_inbound_full(
            &h,
            SelectionKind::Clipboard,
            offer("real"),
            future_stamp(1000),
        )
        .await;
        wait_applied(&h, SelectionKind::Clipboard, &offer("real")).await;
    }

    #[tokio::test(start_paused = true)]
    async fn primed_content_is_not_rebroadcast_as_fresh() {
        // the compositor's subscribe-time event for restored content (modelled
        // by a local_copy of the same bytes) must be suppressed, not broadcast
        let mut h = start_seeded(Config::for_test("s"), Some(offer("restored"))).await;
        h.clip
            .local_copy(SelectionKind::Clipboard, offer("restored"));
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn primed_content_resyncs_with_stamp_zero() {
        let h = start_seeded(Config::for_test("s"), Some(offer("restored"))).await;
        let (tx2, mut rx2) = mpsc::channel(8);
        h.mesh.register(Uuid::new_v4(), tx2);
        match timeout(Duration::from_secs(1), rx2.recv())
            .await
            .unwrap()
            .unwrap()
        {
            Message::Clip {
                offer: o, stamp, ..
            } => {
                assert_eq!(o, offer("restored"));
                assert_eq!(stamp, 0, "restored content must resync at stamp 0");
            }
            other => panic!("expected resync Clip, got {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_is_serviced_during_a_local_event_storm() {
        // the debounce-as-select-arm rewrite must not let a flood of local
        // change events starve inbound processing
        let mut cfg = Config::for_test("s");
        cfg.debounce_ms = 100;
        let h = start(cfg).await;
        for i in 0..50 {
            h.clip
                .local_copy(SelectionKind::Clipboard, offer(&format!("v{i}")));
        }
        send_inbound_full(
            &h,
            SelectionKind::Clipboard,
            offer("remote"),
            future_stamp(60_000),
        )
        .await;
        // the inbound must apply well before the 100ms debounce window closes
        timeout(Duration::from_millis(20), async {
            while h.clip.get(SelectionKind::Clipboard) != Some(offer("remote")) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("inbound starved by local-event storm");
    }

    #[test]
    fn ordering_is_by_stamp_then_origin() {
        let lo = Uuid::from_u128(1);
        let hi = Uuid::from_u128(2);
        let s = ContentState {
            hash: [0u8; 32],
            stamp: 5,
            origin: lo,
        };
        assert!(s.superseded_by(6, lo)); // higher stamp wins
        assert!(!s.superseded_by(4, hi)); // lower stamp loses despite higher origin
        assert!(s.superseded_by(5, hi)); // equal stamp: higher origin wins (converges)
        assert!(!s.superseded_by(5, lo)); // identical: not superseded
        assert!(!s.superseded_by(5, Uuid::from_u128(0))); // equal stamp, lower origin loses
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
