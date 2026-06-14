use crate::clipboard::Clipboard;
use crate::config::{Config, Direction};
use crate::mesh::Mesh;
use crate::mime::MimeRules;
use crate::protocol::{content_hash, describe_offer, human_bytes, Message, Offer, SelectionKind};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use uuid::Uuid;

pub const SENSITIVE_MIME: &str = "x-kde-passwordManagerHint";

/// Reject inbound stamps more than this far in the future. A healthy hybrid
/// clock stamp is always near wall-clock time; a wildly larger value (a
/// buggy/malicious peer, or one with a broken RTC) would otherwise pin our
/// logical clock high and stop our own copies from ever winning again.
const MAX_FUTURE_SKEW_MS: u64 = 24 * 60 * 60 * 1000;

/// Cap on a single clipboard read. The read runs inside the engine's select
/// loop, so an unbounded read of a slow/unresponsive selection owner would
/// freeze inbound/connect handling; this bounds that to a one-off skip.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Password managers mark secret clipboard contents with this hint.
pub fn is_sensitive(offer: &Offer) -> bool {
    offer
        .get(SENSITIVE_MIME)
        .map(|v| v.trim_ascii() == b"secret")
        .unwrap_or(false)
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
    /// Per-type allow/deny rules, shared with the file watcher (`fswatch`),
    /// which reloads them on external edits. `apply_mime_rules` reloads only
    /// when it's about to record a new type, so the common capture path does no
    /// file I/O.
    mime_rules: Arc<Mutex<MimeRules>>,
    /// Self-ping used by the capture path to ask the run loop to bump the
    /// shared rules version and broadcast the file (so the broadcast happens on
    /// the loop, not inside the sync filter). fswatch holds a clone too.
    rules_changed_tx: mpsc::Sender<()>,
}

impl<C: Clipboard> SyncEngine<C> {
    pub fn new(
        clipboard: Arc<C>,
        mesh: Arc<Mesh>,
        cfg: Arc<Config>,
        mime_rules: Arc<Mutex<MimeRules>>,
        rules_changed_tx: mpsc::Sender<()>,
    ) -> Arc<SyncEngine<C>> {
        Arc::new(SyncEngine {
            clipboard,
            mesh,
            cfg,
            current: Mutex::new(HashMap::new()),
            clock: Mutex::new(0),
            mime_rules,
            rules_changed_tx,
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
        mut rules_changed: mpsc::Receiver<()>,
    ) {
        let mut watch = self.clipboard.watch();

        // Adopt the rules file's persisted version into the clock so the next
        // local edit outranks it after a restart.
        {
            let own_id = self.mesh.own_id();
            let (stamp, _) = self
                .mime_rules
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .version(own_id);
            self.observe(stamp);
        }

        // Prime concurrently: reading the existing clipboard can block on a slow
        // selection owner, and must NOT stall inbound/connect handling (a node
        // would otherwise be unreachable on the mesh until the local selection
        // changed). Local changes are buffered (not broadcast) until priming has
        // recorded the restored clipboard, so it isn't re-sent as fresh content.
        let (primed_tx, mut primed_rx) = tokio::sync::oneshot::channel();
        {
            let me = Arc::clone(&self);
            tokio::spawn(async move {
                me.prime().await;
                let _ = primed_tx.send(());
            });
        }
        let mut primed = false;

        let window = Duration::from_millis(self.cfg.debounce_ms);
        let mut pending: Vec<SelectionKind> = Vec::new();
        // Far-future placeholder so the timer is always present in the
        // select; the `armed` precondition keeps it from firing until a
        // local change arms it.
        let deadline = tokio::time::sleep(Duration::from_secs(86_400));
        tokio::pin!(deadline);
        let mut armed = false;

        loop {
            tokio::select! {
                // Priming finished (or its task died); broadcast anything that
                // changed locally while we were priming.
                _ = &mut primed_rx, if !primed => {
                    primed = true;
                    if !pending.is_empty() {
                        if self.cfg.debounce_ms == 0 {
                            for k in pending.drain(..) {
                                self.broadcast_selection(k).await;
                            }
                        } else {
                            deadline.as_mut().reset(tokio::time::Instant::now() + window);
                            armed = true;
                        }
                    }
                },
                kind = watch.recv() => match kind {
                    Some(kind) => {
                        if !pending.contains(&kind) {
                            pending.push(kind);
                        }
                        // Until priming records the restored clipboard, just
                        // buffer — broadcasting now would re-send it as fresh.
                        if primed {
                            if self.cfg.debounce_ms == 0 {
                                for k in pending.drain(..) {
                                    self.broadcast_selection(k).await;
                                }
                            } else {
                                deadline.as_mut().reset(tokio::time::Instant::now() + window);
                                armed = true;
                            }
                        }
                    }
                    None => {
                        warn!("clipboard watcher stopped; shutting down the sync engine");
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
                        warn!("inbound channel closed; shutting down the sync engine");
                        break;
                    }
                },
                peer = connects.recv() => match peer {
                    Some(peer) => self.on_peer_connected(peer).await,
                    None => {
                        warn!("connect-event channel closed; shutting down the sync engine");
                        break;
                    }
                },
                res = rules_changed.recv() => match res {
                    Some(()) => self.on_local_rules_changed(),
                    // The engine itself holds a sender clone, so this channel
                    // can't actually close while run() is alive; the break is a
                    // safety net against a busy-loop if it somehow did.
                    None => {
                        warn!("rules-change channel closed unexpectedly; stopping the sync engine");
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
                    "primed existing {kind:?} clipboard ({})",
                    describe_offer(&offer)
                );
                // or_insert, not insert: priming now runs concurrently with the
                // main loop, so an inbound update may already have recorded this
                // selection's state — don't clobber it with a stamp-0 baseline.
                self.current
                    .lock()
                    .unwrap()
                    .entry(kind)
                    .or_insert(ContentState {
                        hash,
                        stamp: 0,
                        origin: self.mesh.own_id(),
                    });
            }
        }
    }

    /// Read the selection and apply the content filters (sensitive, MIME,
    /// size). Returns None when there is nothing syncable. `record_unseen`
    /// records brand-new types in the rules file — true for locally-captured
    /// content (so the user can curate what they copy), false for inbound peer
    /// offers (so a peer can't write to our rules file).
    fn filter(&self, offer: Offer, record_unseen: bool) -> Option<Offer> {
        if offer.is_empty() {
            debug!("nothing to sync: the clipboard is empty");
            return None;
        }
        if self.cfg.exclude_sensitive && is_sensitive(&offer) {
            debug!("not syncing: clipboard is flagged sensitive (password-manager contents)");
            return None;
        }
        let offer = self.apply_mime_rules(offer, record_unseen);
        if offer.is_empty() {
            debug!("nothing to sync: every MIME type was blocked by the rules");
            return None;
        }
        let offer = self.cap_to_payload_size(offer);
        if offer.is_empty() {
            debug!("nothing to sync: everything was over the max_payload_size budget");
            return None;
        }
        Some(offer)
    }

    /// Trim the offer to max_payload_size, dropping individual representations
    /// that don't fit (smallest-first, so a small text payload survives even
    /// when a giant image would blow the budget) instead of dropping the whole
    /// offer. Mirrors the read-path budget and the per-type size caps.
    fn cap_to_payload_size(&self, offer: Offer) -> Offer {
        let max = self.cfg.max_payload_size;
        if offer_size(&offer) <= max {
            return offer; // common case: the whole offer fits
        }
        let mut reps: Vec<(String, Vec<u8>)> = offer.into_iter().collect();
        reps.sort_by_key(|(m, d)| m.len() + d.len());
        let mut total = 0usize;
        let mut kept = Offer::new();
        for (mime, data) in reps {
            let sz = mime.len() + data.len();
            if total.saturating_add(sz) > max {
                // warn, not debug: at the default log level the user would
                // otherwise have no clue why a large copy never syncs.
                warn!(
                    "dropping {mime} ({}): doesn't fit the {} max_payload_size budget \
                     (raise max_payload_size to sync more)",
                    human_bytes(data.len()),
                    human_bytes(max)
                );
                continue;
            }
            total += sz;
            kept.insert(mime, data);
        }
        kept
    }

    /// Drop representations blocked by the per-type rules — denied types, or
    /// ones over their per-type max size. When `record_unseen`, brand-new types
    /// are added to the rules with the configured default and persisted so the
    /// user can tune them. Live external edits are handled by the inotify
    /// watcher (see fswatch), which shares this ruleset; the hot path only
    /// touches disk when there's actually a new type to record (and reloads
    /// first, so the append merges onto the user's latest edits rather than
    /// clobbering them). Recovers a poisoned lock rather than cascading the
    /// panic to the watcher thread.
    fn apply_mime_rules(&self, offer: Offer, record_unseen: bool) -> Offer {
        let mut rules = self
            .mime_rules
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if record_unseen {
            let mut appended = false;
            if rules.has_unseen(offer.keys()) {
                rules.reload_if_changed();
                appended = rules.ensure(offer.keys());
            }
            // No-op unless something is unsaved (incl. retrying a failed write).
            rules.persist();
            // A newly-recorded type changes the file; share it (try_send only —
            // we still hold the rules lock here, so we must not re-lock).
            if appended && self.cfg.share_mime_rules {
                self.note_rules_changed();
            }
        }
        offer
            .into_iter()
            .filter(|(mime, data)| {
                let allowed = rules.allows(mime, data.len());
                if !allowed {
                    debug!(
                        "dropping {mime} ({}): blocked by the MIME rules",
                        human_bytes(data.len())
                    );
                }
                allowed
            })
            .collect()
    }

    /// Read the selection with a bounded timeout (no filtering). Split out of
    /// `capture_offer` so the broadcast path can describe what was copied (for
    /// the verbose summary) before the content filters narrow it.
    ///
    /// Bound the read: this runs inside the select loop (and at startup), so a
    /// slow/unresponsive selection owner must not be able to freeze the engine.
    /// A real read of the size-capped clipboard takes milliseconds; exceeding
    /// this means the source isn't serving its pipe.
    async fn read_selection(&self, kind: SelectionKind) -> Option<Offer> {
        match tokio::time::timeout(READ_TIMEOUT, self.clipboard.read_offer(kind)).await {
            Ok(Ok(o)) => Some(o),
            Ok(Err(e)) => {
                warn!("couldn't read the clipboard: {e:#}");
                None
            }
            Err(_) => {
                warn!("clipboard read timed out after {READ_TIMEOUT:?}; skipping this {kind:?} update");
                None
            }
        }
    }

    async fn capture_offer(&self, kind: SelectionKind) -> Option<Offer> {
        let offer = self.read_selection(kind).await?;
        // Local content: record brand-new types so the user can curate them.
        self.filter(offer, true)
    }

    async fn broadcast_selection(&self, kind: SelectionKind) {
        if !self.may_send(kind) {
            if self.cfg.verbose {
                info!("copied {kind:?}: not sent (this node does not send)");
            }
            return;
        }
        let Some(raw) = self.read_selection(kind).await else {
            return;
        };
        // Describe what was copied before the filters narrow it, computed once.
        // The bracketed list means "what was copied" in every outcome below
        // (consistent with the received-update summary).
        let copied = self.cfg.verbose.then(|| describe_offer(&raw));
        let Some(offer) = self.filter(raw, true) else {
            if let Some(copied) = &copied {
                info!("copied {kind:?} [{copied}]: not sent (nothing passed the content filters)");
            }
            return;
        };
        let hash = content_hash(&offer);
        // Already the mesh-current content (we just applied it, or the user
        // re-copied identical bytes): nothing to do.
        if self.current.lock().unwrap().get(&kind).map(|s| s.hash) == Some(hash) {
            if let Some(copied) = &copied {
                info!("copied {kind:?} [{copied}]: not sent (already on the mesh)");
            }
            debug!("ignoring local {kind:?} change: identical to what's already on the mesh (echo suppressed)");
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
        if let Some(copied) = &copied {
            info!("copied {kind:?} [{copied}]: broadcast (stamp {stamp})");
        }
        debug!(
            "broadcasting {kind:?} update ({}, stamp {stamp})",
            describe_offer(&offer)
        );
        self.mesh.broadcast(&Message::Clip {
            kind,
            hash,
            offer,
            stamp,
            origin,
        });
    }

    /// Whether a rules-file body is small enough to put on (or accept off) the
    /// wire. The limit is `max_payload_size`, so the body always fits the
    /// transport frame (`max_message` = `max_payload_size` + slack) however the
    /// user tuned it — and a peer can't make us persist a file larger than that.
    /// Warns (naming the limit) when it doesn't fit, so an oversized file is
    /// diagnosable on both the send and receive sides.
    fn rules_body_ok(&self, len: usize, context: &str) -> bool {
        let limit = self.cfg.max_payload_size;
        if len > limit {
            warn!(
                "MIME-rules file{context} is {} (over the {} max_payload_size limit); skipping it",
                human_bytes(len),
                human_bytes(limit),
            );
            return false;
        }
        true
    }

    /// Push our whole MIME-rules file to a peer that just connected, so the
    /// mesh converges. Independent of `direction`/`resync_on_connect` (those
    /// gate clipboard content); gated only by `share_mime_rules` and having a
    /// file. Materialises the version header on first send so the version is
    /// pinned to disk and survives restarts.
    fn resync_rules_to(&self, peer: Uuid) {
        if !self.cfg.share_mime_rules || self.cfg.mime_rules_path.is_none() {
            return;
        }
        let own_id = self.mesh.own_id();
        let (stamp, origin, body) = {
            let mut rules = self
                .mime_rules
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // Read the version once; set_version below stores exactly this, so
            // it is also what we send.
            let (stamp, origin) = rules.version(own_id);
            if !rules.has_version_header() {
                // Pin the current (baseline) version to disk; do NOT bump. If
                // the write fails, roll back and don't push a version we didn't
                // durably persist (consistent with on_local_rules_changed).
                rules.set_version(stamp, origin);
                if !rules.persist() {
                    rules.revert_to_loaded();
                    return;
                }
            }
            (stamp, origin, rules.body())
        };
        if !self.rules_body_ok(body.len(), &format!(" for peer {peer}")) {
            return;
        }
        debug!("pushing shared MIME-rules to peer {peer} (stamp {stamp})");
        self.mesh.send_to(
            peer,
            &Message::Rules {
                stamp,
                origin,
                body,
            },
        );
    }

    /// A peer just (re)connected: push our current state so it converges
    /// without waiting for the next copy. The receiver orders it by
    /// `(stamp, origin)` like any other update, so two nodes resyncing at
    /// each other settle on the same content instead of swapping.
    async fn on_peer_connected(&self, peer: Uuid) {
        // Rules sharing is independent of clipboard direction/resync settings.
        self.resync_rules_to(peer);
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
            debug!("resyncing current {kind:?} to reconnected peer {peer}");
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

    /// Dispatch an inbound message from a peer to the right handler.
    async fn on_inbound(&self, from: Uuid, msg: Message) {
        match msg {
            Message::Clip {
                kind,
                hash,
                offer,
                stamp,
                origin,
            } => {
                self.on_inbound_clip(from, kind, hash, offer, stamp, origin)
                    .await
            }
            Message::Rules {
                stamp,
                origin,
                body,
            } => self.on_inbound_rules(from, stamp, origin, body),
            Message::Hello { .. } => {
                warn!("ignoring an unexpected Hello from peer {from} after handshake")
            }
        }
    }

    async fn on_inbound_clip(
        &self,
        from: Uuid,
        kind: SelectionKind,
        hash: [u8; 32],
        offer: Offer,
        stamp: u64,
        origin: Uuid,
    ) {
        // Describe before the offer is filtered/moved, for the verbose summary.
        let received = self.cfg.verbose.then(|| describe_offer(&offer));
        let outcome = self
            .apply_inbound_clip(from, kind, hash, offer, stamp, origin)
            .await;
        if let Some(received) = received {
            info!("received {kind:?} from peer {from} [{received}], stamp {stamp}: {outcome}");
        }
    }

    /// Decide and apply one inbound clip, returning a short outcome for the
    /// verbose per-message summary. Keeps the detailed debug lines (the
    /// non-verbose view) and the hard-error warnings.
    async fn apply_inbound_clip(
        &self,
        from: Uuid,
        kind: SelectionKind,
        hash: [u8; 32],
        offer: Offer,
        stamp: u64,
        origin: Uuid,
    ) -> &'static str {
        debug!(
            "received {kind:?} update from peer {from} ({}, stamp {stamp})",
            describe_offer(&offer)
        );
        if !self.may_recv(kind) {
            debug!("ignoring inbound {kind:?} from peer {from}: blocked by direction/sync_primary config");
            return "dropped (blocked by direction/sync_primary config)";
        }
        if content_hash(&offer) != hash {
            warn!("dropping update from peer {from}: content hash doesn't match (corrupted or tampered)");
            return "rejected (content hash mismatch)";
        }
        // Drop implausibly-future stamps before they reach the clock, so one
        // peer with a broken clock can't poison ordering for this node.
        if stamp > now_ms().saturating_add(MAX_FUTURE_SKEW_MS) {
            warn!("rejecting update from peer {from}: timestamp {stamp} is implausibly far in the future (peer clock skew?)");
            return "rejected (timestamp too far in the future)";
        }
        self.observe(stamp);
        // Apply the receiver's own content policy: configs can differ
        // between peers, and a node must not write contents it would never
        // have sent (e.g. password-manager secrets, or denied MIME types). Do
        // NOT record unseen types here — a peer must not write to our rules file.
        let Some(offer) = self.filter(offer, false) else {
            debug!("dropping inbound {kind:?} from peer {from}: our content filters removed everything");
            return "dropped (content filters removed everything)";
        };
        let applied_hash = content_hash(&offer);
        {
            let mut current = self.current.lock().unwrap();
            if let Some(state) = current.get(&kind).copied() {
                if state.hash == applied_hash {
                    // Already hold exactly this content, so no clipboard write
                    // is needed — but still adopt a higher (stamp, origin).
                    // The LWW timestamp must track the newest write of the
                    // current content; keeping a stale stamp would let a later
                    // update stamped between ours and a peer's newer one win
                    // here yet lose on that peer, diverging the mesh.
                    if state.superseded_by(stamp, origin) {
                        current.insert(
                            kind,
                            ContentState {
                                hash: applied_hash,
                                stamp,
                                origin,
                            },
                        );
                    }
                    debug!("inbound {kind:?} from peer {from} is already our current content; nothing to do");
                    return "already our current content";
                }
                if !state.superseded_by(stamp, origin) {
                    debug!("ignoring an older {kind:?} update from peer {from} (stamp {stamp}); we already hold newer content");
                    return "ignored (older than our content)";
                }
            }
        }
        debug!(
            "applying {kind:?} update from peer {from} ({}, stamp {stamp})",
            describe_offer(&offer)
        );
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
                "applied"
            }
            Err(e) => {
                warn!("couldn't write to the clipboard: {e:#}");
                "clipboard write failed"
            }
        }
    }

    /// Signal the run loop that the rules file changed locally, so it bumps the
    /// shared version and broadcasts. Cheap and coalescing: a full queue just
    /// means a bump is already pending.
    fn note_rules_changed(&self) {
        let _ = self.rules_changed_tx.try_send(());
    }

    /// A local change to the rules file (a captured new type, or a human edit
    /// the watcher picked up) bumps the file version and broadcasts the whole
    /// file. No-op when sharing is off or there is no rules file.
    fn on_local_rules_changed(&self) {
        if !self.cfg.share_mime_rules || self.cfg.mime_rules_path.is_none() {
            return;
        }
        let stamp = self.tick();
        let origin = self.mesh.own_id();
        let body = {
            let mut rules = self
                .mime_rules
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            rules.set_version(stamp, origin);
            // Measure the real (post-stamp) body, then persist. If it's over the
            // wire limit or the write fails, roll the stamp back: we must not
            // keep or announce a version that isn't durably on disk (it would
            // make version() outrank what peers actually have, and be lost on a
            // restart).
            let body = rules.body();
            if !self.rules_body_ok(body.len(), "") || !rules.persist() {
                rules.revert_to_loaded();
                return;
            }
            body
        };
        debug!("broadcasting shared MIME-rules (stamp {stamp})");
        self.mesh.broadcast(&Message::Rules {
            stamp,
            origin,
            body,
        });
    }

    /// Adopt a peer's shared MIME-rules file under whole-file last-writer-wins.
    /// Ignored unless sharing is on and we have a rules file. Rejects
    /// implausibly-future stamps and `observe()`s the stamp so a later local
    /// edit outranks the adopted version (otherwise a local edit stamped below
    /// it would revert to the version it just replaced).
    fn on_inbound_rules(&self, from: Uuid, stamp: u64, origin: Uuid, body: String) {
        if !self.cfg.share_mime_rules || self.cfg.mime_rules_path.is_none() {
            return;
        }
        // Reject an oversized body before parsing/persisting it: a peer must not
        // be able to make us write a huge file (the send-side cap only bounds
        // what WE send).
        if !self.rules_body_ok(body.len(), &format!(" from peer {from}")) {
            return;
        }
        if stamp > now_ms().saturating_add(MAX_FUTURE_SKEW_MS) {
            warn!("rejecting MIME-rules from peer {from}: timestamp {stamp} is implausibly far in the future (peer clock skew?)");
            return;
        }
        self.observe(stamp);
        let own_id = self.mesh.own_id();
        let mut rules = self
            .mime_rules
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let current = rules.version(own_id);
        if (stamp, origin) > current {
            debug!(
                "adopting shared MIME-rules from peer {from} (stamp {stamp}); replaces our (stamp {}, origin {})",
                current.0, current.1
            );
            rules.replace_from(body);
            // Stamp the adopted version explicitly so version() reflects
            // (stamp, origin) even if the peer body lacked the header line —
            // otherwise it would fall back to the new file's mtime and diverge.
            rules.set_version(stamp, origin);
            if !rules.persist() {
                // Couldn't durably write the adoption; roll back so memory
                // matches disk rather than silently diverging (which would be
                // lost on restart). The peer re-pushes on the next connect.
                rules.revert_to_loaded();
            }
        } else {
            debug!(
                "ignoring shared MIME-rules from peer {from} (stamp {stamp}); we hold a newer-or-equal version (stamp {})",
                current.0
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clipboard::mock::MockClipboard;
    use crate::config::{Config, Direction, MimePolicy};
    use crate::mesh::Mesh;
    use std::time::Duration;
    use tokio::time::timeout;

    fn offer(text: &str) -> Offer {
        [("text/plain".to_string(), text.as_bytes().to_vec())]
            .into_iter()
            .collect()
    }

    /// A `[rules]` TOML body from (mime, rule-word) pairs.
    fn rules_toml(rules: &[(&str, &str)]) -> String {
        let mut body = String::from("[rules]\n");
        for (mime, rule) in rules {
            body.push_str(&format!("\"{mime}\" = \"{rule}\"\n"));
        }
        body
    }

    /// Point `cfg` at a fresh TOML MIME-rules file with the given (mime, rule)
    /// entries and unknown-type policy. The returned TempDir must be kept alive
    /// for the duration of the test (dropping it deletes the file).
    fn with_rules(
        cfg: &mut Config,
        unknown: MimePolicy,
        rules: &[(&str, &str)],
    ) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("mimetypes"), rules_toml(rules)).unwrap();
        cfg.unknown_mime = unknown;
        cfg.mime_rules_path = Some(dir.path().join("mimetypes"));
        dir
    }

    /// A clipboard whose `read_offer` blocks until released, modelling a
    /// slow/unresponsive selection owner at startup. Used to prove that priming
    /// must not gate the engine's inbound/connect handling.
    struct GatedClipboard {
        gate: tokio::sync::Notify,
        watchers: Mutex<Vec<mpsc::UnboundedSender<SelectionKind>>>,
        applied: Mutex<Option<Offer>>,
    }

    #[async_trait::async_trait]
    impl Clipboard for GatedClipboard {
        fn watch(&self) -> mpsc::UnboundedReceiver<SelectionKind> {
            let (tx, rx) = mpsc::unbounded_channel();
            self.watchers.lock().unwrap().push(tx);
            rx
        }
        async fn read_offer(&self, _kind: SelectionKind) -> anyhow::Result<Offer> {
            self.gate.notified().await; // block until the test releases priming
            Ok(Offer::new())
        }
        async fn write_offer(&self, _kind: SelectionKind, offer: Offer) -> anyhow::Result<()> {
            *self.applied.lock().unwrap() = Some(offer);
            Ok(())
        }
    }

    #[tokio::test]
    async fn inbound_is_handled_while_priming_is_still_blocked() {
        // Priming reads the existing clipboard, which can block on a slow source.
        // That must not stall the engine's handling of peer messages/connects —
        // otherwise a node can't participate in the mesh until the local
        // selection changes and unblocks the read.
        let clip = Arc::new(GatedClipboard {
            gate: tokio::sync::Notify::new(),
            watchers: Mutex::new(Vec::new()),
            applied: Mutex::new(None),
        });
        let (in_tx, in_rx) = mpsc::channel(64);
        let (connect_tx, connect_rx) = mpsc::channel(64);
        let mesh = Mesh::new(Uuid::new_v4(), in_tx.clone(), connect_tx);
        let remote_id = Uuid::new_v4();
        let cfg = Arc::new(Config::for_test("s"));
        let mime_rules = Arc::new(Mutex::new(MimeRules::load(None, MimePolicy::Allow)));
        let (rules_tx, rules_rx) = mpsc::channel(8);
        let engine = SyncEngine::new(clip.clone(), mesh, cfg, mime_rules, rules_tx);
        tokio::spawn(engine.run(in_rx, connect_rx, rules_rx));

        // prime() is now awaiting read_offer (gated). A peer update should still
        // be applied to the local clipboard.
        let o = offer("from-peer");
        in_tx
            .send((
                remote_id,
                Message::Clip {
                    kind: SelectionKind::Clipboard,
                    hash: content_hash(&o),
                    offer: o.clone(),
                    stamp: now_ms() + 10_000,
                    origin: remote_id,
                },
            ))
            .await
            .unwrap();

        let handled = timeout(Duration::from_secs(2), async {
            while clip.applied.lock().unwrap().is_none() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        clip.gate.notify_waiters(); // let priming finish so the task winds down
        handled.expect("inbound update was not handled while priming was blocked");
        assert_eq!(clip.applied.lock().unwrap().as_ref(), Some(&o));
    }

    #[tokio::test(start_paused = true)]
    async fn capture_offer_times_out_on_a_hung_read() {
        // A read that never completes must yield None after the timeout rather
        // than awaiting forever — otherwise it would freeze the select loop it
        // runs in. (start_paused auto-advances time to the pending timeout.)
        let clip = Arc::new(GatedClipboard {
            gate: tokio::sync::Notify::new(), // never released
            watchers: Mutex::new(Vec::new()),
            applied: Mutex::new(None),
        });
        let (in_tx, _in_rx) = mpsc::channel(64);
        let (connect_tx, _connect_rx) = mpsc::channel::<Uuid>(64);
        let mesh = Mesh::new(Uuid::new_v4(), in_tx, connect_tx);
        let cfg = Arc::new(Config::for_test("s"));
        let mime_rules = Arc::new(Mutex::new(MimeRules::load(None, MimePolicy::Allow)));
        let (rules_tx, _rules_rx) = mpsc::channel(8);
        let engine = SyncEngine::new(clip, mesh, cfg, mime_rules, rules_tx);
        assert_eq!(engine.capture_offer(SelectionKind::Clipboard).await, None);
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
        let cfg = Arc::new(cfg);
        let mime_rules = Arc::new(Mutex::new(MimeRules::load(
            cfg.mime_rules_path.clone(),
            cfg.unknown_mime,
        )));
        let (rules_tx, rules_rx) = mpsc::channel(8);
        let engine = SyncEngine::new(clip.clone(), mesh.clone(), cfg, mime_rules, rules_tx);
        tokio::spawn(engine.run(in_rx, connect_rx, rules_rx));
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

    #[tokio::test]
    async fn apply_inbound_clip_reports_each_outcome() {
        // A standalone engine (not driven by run()), so we can call the inbound
        // handler directly and assert the one-line verbose summary's outcome.
        fn engine(cfg: Config) -> Arc<SyncEngine<MockClipboard>> {
            let clip = MockClipboard::new();
            let (in_tx, _in_rx) = mpsc::channel(64);
            let (connect_tx, _connect_rx) = mpsc::channel(64);
            let mesh = Mesh::new(Uuid::new_v4(), in_tx, connect_tx);
            let mime_rules = Arc::new(Mutex::new(MimeRules::load(
                cfg.mime_rules_path.clone(),
                cfg.unknown_mime,
            )));
            let (rules_tx, _rules_rx) = mpsc::channel(8);
            SyncEngine::new(clip, mesh, Arc::new(cfg), mime_rules, rules_tx)
        }
        let kind = SelectionKind::Clipboard;
        let from = Uuid::new_v4();

        // Default (allow) engine, verbose on so the logging wrapper runs too.
        let mut cfg = Config::for_test("s");
        cfg.verbose = true;
        let e = engine(cfg);

        let a = offer("hello");
        let ha = content_hash(&a);
        assert_eq!(
            e.apply_inbound_clip(from, kind, ha, a.clone(), 1000, from)
                .await,
            "applied"
        );
        assert_eq!(
            e.apply_inbound_clip(from, kind, ha, a, 1000, from).await,
            "already our current content"
        );
        let b = offer("older");
        assert_eq!(
            e.apply_inbound_clip(from, kind, content_hash(&b), b, 1, from)
                .await,
            "ignored (older than our content)"
        );
        assert_eq!(
            e.apply_inbound_clip(from, kind, [0u8; 32], offer("x"), 2000, from)
                .await,
            "rejected (content hash mismatch)"
        );
        let f = offer("future");
        let future = now_ms() + MAX_FUTURE_SKEW_MS + 60_000;
        assert_eq!(
            e.apply_inbound_clip(from, kind, content_hash(&f), f, future, from)
                .await,
            "rejected (timestamp too far in the future)"
        );
        // Exercise the verbose logging wrapper end-to-end (must not panic).
        let g = offer("newer");
        e.on_inbound_clip(from, kind, content_hash(&g), g, 5000, from)
            .await;

        // Send-only engine: inbound is dropped by the direction policy.
        let mut cfg = Config::for_test("s");
        cfg.direction = Direction::SendOnly;
        let e = engine(cfg);
        let c = offer("blocked");
        assert_eq!(
            e.apply_inbound_clip(from, kind, content_hash(&c), c, 1000, from)
                .await,
            "dropped (blocked by direction/sync_primary config)"
        );

        // Deny-everything rules: the content filters remove all of it.
        let mut cfg = Config::for_test("s");
        let _dir = with_rules(&mut cfg, MimePolicy::Deny, &[]);
        let e = engine(cfg);
        let d = offer("denied");
        assert_eq!(
            e.apply_inbound_clip(from, kind, content_hash(&d), d, 1000, from)
                .await,
            "dropped (content filters removed everything)"
        );
    }

    /// The stamp of the next clipboard broadcast/resync message. Skips rules
    /// pushes (present when share_mime_rules is on) so the helper stays usable
    /// in sharing-enabled tests.
    async fn recv_stamp(h: &mut Harness) -> u64 {
        loop {
            match recv_msg(h).await {
                Message::Clip { stamp, .. } => return stamp,
                Message::Rules { .. } => continue,
                other => panic!("expected Clip, got {other:?}"),
            }
        }
    }

    async fn recv_clip(h: &mut Harness) -> (SelectionKind, [u8; 32], Offer) {
        loop {
            match recv_msg(h).await {
                Message::Clip {
                    kind, hash, offer, ..
                } => return (kind, hash, offer),
                Message::Rules { .. } => continue,
                other => panic!("expected Clip, got {other:?}"),
            }
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
    async fn denied_mime_types_are_stripped() {
        let mut cfg = Config::for_test("s");
        let _dir = with_rules(&mut cfg, MimePolicy::Allow, &[("image/png", "deny")]);
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
    async fn unknown_deny_syncs_only_allowed_types() {
        let mut cfg = Config::for_test("s");
        let _dir = with_rules(&mut cfg, MimePolicy::Deny, &[("text/plain", "allow")]);
        let mut h = start(cfg).await;
        let mut o = offer("text part"); // text/plain explicitly allowed
        o.insert("image/png".to_string(), vec![0u8; 16]); // unknown -> denied
        h.clip.local_copy(SelectionKind::Clipboard, o);
        let (_, _, got) = recv_clip(&mut h).await;
        assert_eq!(got, offer("text part"));
    }

    #[tokio::test(start_paused = true)]
    async fn offer_with_only_denied_types_is_not_broadcast() {
        let mut cfg = Config::for_test("s");
        let _dir = with_rules(&mut cfg, MimePolicy::Deny, &[]); // deny everything unseen
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
    async fn payload_cap_drops_oversized_reps_but_keeps_small_ones() {
        // a small text rep fits the budget; a big rep alongside it doesn't, so
        // only the small one is broadcast (rather than dropping the whole offer)
        let mut cfg = Config::for_test("s");
        cfg.max_payload_size = 32;
        let mut h = start(cfg).await;
        let mut o = offer("hi"); // text/plain (10) + 2 = 12, fits
        o.insert("image/png".to_string(), vec![0u8; 64]); // 9 + 64 = 73, doesn't
        h.clip.local_copy(SelectionKind::Clipboard, o);
        let (_, _, got) = recv_clip(&mut h).await;
        assert_eq!(got, offer("hi"));
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
    async fn inbound_denied_types_are_stripped_before_writing() {
        let mut cfg = Config::for_test("s");
        let _dir = with_rules(&mut cfg, MimePolicy::Allow, &[("image/png", "deny")]);
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
    async fn same_content_newer_stamp_advances_lww_clock() {
        // Regression: receiving content we already hold, but stamped higher,
        // must advance our recorded (stamp, origin). Otherwise a later update
        // stamped between our stale stamp and a peer's newer one wins here
        // while losing on the peer that saw the higher stamp — permanent
        // divergence between two nodes holding the same content.
        let h = start(Config::for_test("s")).await;
        send_inbound_full(&h, SelectionKind::Clipboard, offer("x"), 100).await;
        wait_applied(&h, SelectionKind::Clipboard, &offer("x")).await;

        // identical bytes at a higher stamp: no clipboard write, but our
        // recorded stamp must move from 100 to 300
        send_inbound_full(&h, SelectionKind::Clipboard, offer("x"), 300).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        // an update stamped 200 (between the two) must now lose to our 300
        send_inbound_full(&h, SelectionKind::Clipboard, offer("y"), 200).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            h.clip.get(SelectionKind::Clipboard),
            Some(offer("x")),
            "intermediate-stamped update must lose after a same-content stamp bump"
        );
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

    #[tokio::test(start_paused = true)]
    async fn per_type_max_size_drops_oversized_representations() {
        let mut cfg = Config::for_test("s");
        let _dir = {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(
                dir.path().join("mimetypes"),
                "[rules]\n\"image/png\" = { rule = \"allow\", max = \"8B\" }\n",
            )
            .unwrap();
            cfg.unknown_mime = MimePolicy::Allow;
            cfg.mime_rules_path = Some(dir.path().join("mimetypes"));
            dir
        };
        let mut h = start(cfg).await;
        let mut o = offer("hi"); // text/plain (unknown -> allow, no cap)
        o.insert("image/png".to_string(), vec![0u8; 16]); // 16 B over the 8 B cap
        h.clip.local_copy(SelectionKind::Clipboard, o);
        let (_, _, got) = recv_clip(&mut h).await;
        assert_eq!(got, offer("hi"));
    }

    #[tokio::test(start_paused = true)]
    async fn unseen_types_are_recorded_in_the_rules_file() {
        let mut cfg = Config::for_test("s");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        cfg.unknown_mime = MimePolicy::Deny;
        cfg.mime_rules_path = Some(path.clone());
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("hello"));
        // deny-by-default: nothing syncs, but the new type is written out
        assert_no_broadcast(&mut h).await;
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(
            written.contains("\"text/plain\" = \"deny\""),
            "got:\n{written}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn editing_an_existing_rule_is_not_picked_up_without_the_watcher() {
        // The capture path only reloads when a NEW type appears (so the common
        // case does no blocking file I/O). Edits to existing rules are picked up
        // by the inotify watcher, which this harness doesn't run — so with no
        // new type, the engine keeps the rules it loaded at start.
        let mut cfg = Config::for_test("s");
        let dir = with_rules(&mut cfg, MimePolicy::Deny, &[("text/plain", "deny")]);
        let path = dir.path().join("mimetypes");
        let mut h = start(cfg).await;
        std::fs::write(&path, "[rules]\n\"text/plain\" = \"allow\"\n").unwrap();
        h.clip.local_copy(SelectionKind::Clipboard, offer("hello"));
        // No watcher + no new type -> the on-disk flip is not applied here.
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn recording_a_new_type_merges_concurrent_on_disk_edits() {
        // When a brand-new type is captured, apply_mime_rules reloads-then-
        // appends, so a concurrent on-disk edit is merged rather than clobbered
        // by the append (verified here without a running watcher).
        let mut cfg = Config::for_test("s");
        let dir = with_rules(&mut cfg, MimePolicy::Deny, &[("text/plain", "deny")]);
        let path = dir.path().join("mimetypes");
        let mut h = start(cfg).await;

        // User flips text/plain to allow on disk; no watcher fires.
        std::fs::write(&path, "[rules]\n\"text/plain\" = \"allow\"\n").unwrap();
        // Copy with a NEW type (image/png), which triggers record + persist.
        let mut o = offer("hi"); // text/plain
        o.insert("image/png".to_string(), vec![1, 2, 3]);
        h.clip.local_copy(SelectionKind::Clipboard, o);
        let (_, _, got) = recv_clip(&mut h).await;
        // text/plain (merged allow) syncs; image/png is newly deny-by-default.
        assert_eq!(got, offer("hi"));
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(
            body.contains("\"text/plain\" = \"allow\""),
            "user edit was clobbered:\n{body}"
        );
        assert!(
            body.contains("\"image/png\" = \"deny\""),
            "new type not recorded:\n{body}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_persist_does_not_broadcast_rules() {
        // If we can't durably write the new version, we must not announce it
        // (a peer would adopt a stamp our disk doesn't have, and we'd lose it on
        // restart). A directory at the rules path makes every write fail.
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        cfg.unknown_mime = MimePolicy::Allow;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        std::fs::create_dir(&path).unwrap();
        cfg.mime_rules_path = Some(path.clone());
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("hello"));
        // The clipboard content still broadcasts...
        assert!(matches!(recv_msg(&mut h).await, Message::Clip { .. }));
        // ...but no Rules push, because the version couldn't be persisted.
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_oversized_rules_is_rejected() {
        // A peer must not be able to make us persist a file larger than our
        // max_payload_size (the send-side cap only bounds what we send).
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        cfg.max_payload_size = 8; // tiny: any real rules body is over the limit
        let dir = with_rules(&mut cfg, MimePolicy::Deny, &[("image/png", "deny")]);
        let path = dir.path().join("mimetypes");
        let h = start(cfg).await;
        h.in_tx
            .send((
                h.remote_id,
                Message::Rules {
                    stamp: future_stamp(1000),
                    origin: h.remote_id,
                    body: rules_toml(&[("image/png", "allow")]), // well over the 8-byte cap
                },
            ))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            rules_toml(&[("image/png", "deny")]),
            "oversized inbound rules must be rejected, not written to disk"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_rules_newer_is_adopted() {
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        let dir = with_rules(&mut cfg, MimePolicy::Deny, &[("image/png", "deny")]);
        let path = dir.path().join("mimetypes");
        let mut h = start(cfg).await;
        h.in_tx
            .send((
                h.remote_id,
                Message::Rules {
                    stamp: future_stamp(1000),
                    origin: h.remote_id,
                    body: rules_toml(&[("image/png", "allow")]),
                },
            ))
            .await
            .unwrap();
        timeout(Duration::from_secs(1), async {
            while !std::fs::read_to_string(&path)
                .unwrap()
                .contains("\"image/png\" = \"allow\"")
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("newer rules were not adopted");
        // The adopted version is stamped into the header (so version() is
        // authoritative, not the file's mtime).
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("version ="),
            "adopted file must carry the version header"
        );
        // Adopting a peer file must not bounce back as a broadcast.
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_rules_equal_stamp_higher_origin_wins() {
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        // Seed a header with a known stamp and a LOW origin, so an equal-stamp
        // peer with a higher origin wins the deterministic tiebreak.
        let low = Uuid::from_u128(1);
        std::fs::write(
            &path,
            format!("[clipmesh]\nversion = 5000\norigin = \"{low}\"\n[rules]\n\"image/png\" = \"deny\"\n"),
        )
        .unwrap();
        cfg.unknown_mime = MimePolicy::Deny;
        cfg.mime_rules_path = Some(path.clone());
        let h = start(cfg).await;
        let high = Uuid::from_u128(2);
        h.in_tx
            .send((
                h.remote_id,
                Message::Rules {
                    stamp: 5000,
                    origin: high,
                    body: rules_toml(&[("image/png", "allow")]),
                },
            ))
            .await
            .unwrap();
        timeout(Duration::from_secs(1), async {
            while !std::fs::read_to_string(&path)
                .unwrap()
                .contains("\"image/png\" = \"allow\"")
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("equal-stamp higher-origin peer should win the tiebreak");
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_rules_older_is_ignored() {
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        let dir = with_rules(&mut cfg, MimePolicy::Deny, &[("image/png", "allow")]);
        let path = dir.path().join("mimetypes");
        let h = start(cfg).await;
        // our baseline is the file's (recent) mtime, so stamp 1 must lose
        h.in_tx
            .send((
                h.remote_id,
                Message::Rules {
                    stamp: 1,
                    origin: h.remote_id,
                    body: rules_toml(&[("image/png", "deny")]),
                },
            ))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            rules_toml(&[("image/png", "allow")]),
            "older rules must not overwrite"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_rules_ignored_when_sharing_off() {
        let mut cfg = Config::for_test("s"); // sharing off by default
        let dir = with_rules(&mut cfg, MimePolicy::Deny, &[("image/png", "deny")]);
        let path = dir.path().join("mimetypes");
        let h = start(cfg).await;
        h.in_tx
            .send((
                h.remote_id,
                Message::Rules {
                    stamp: future_stamp(1000),
                    origin: h.remote_id,
                    body: rules_toml(&[("image/png", "allow")]),
                },
            ))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            rules_toml(&[("image/png", "deny")]),
            "sharing off must ignore inbound rules"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_future_rules_stamp_is_rejected() {
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        let dir = with_rules(&mut cfg, MimePolicy::Deny, &[("image/png", "deny")]);
        let path = dir.path().join("mimetypes");
        let h = start(cfg).await;
        let insane = now_ms() + 48 * 60 * 60 * 1000; // past the skew bound
        h.in_tx
            .send((
                h.remote_id,
                Message::Rules {
                    stamp: insane,
                    origin: h.remote_id,
                    body: rules_toml(&[("image/png", "allow")]),
                },
            ))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            rules_toml(&[("image/png", "deny")]),
            "implausibly-future rules must be rejected"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_peer_types_are_not_written_to_the_rules_file() {
        // A peer's advertised MIME types must not grow/pollute our local rules
        // file; the inbound path applies rules but never records unseen types.
        let mut cfg = Config::for_test("s");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        cfg.unknown_mime = MimePolicy::Deny;
        cfg.mime_rules_path = Some(path.clone());
        let h = start(cfg).await;
        let before = std::fs::read_to_string(&path).unwrap();
        send_inbound(&h, SelectionKind::Clipboard, offer("from-peer")).await;
        // Give the inbound a moment to be processed.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            before, after,
            "inbound peer types were written to the rules file"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn capturing_a_new_type_broadcasts_the_rules_file() {
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        cfg.unknown_mime = MimePolicy::Allow; // captured type also syncs
        let dir = tempfile::tempdir().unwrap();
        cfg.mime_rules_path = Some(dir.path().join("mimetypes"));
        let mut h = start(cfg).await;
        // text/plain is a brand-new type
        h.clip.local_copy(SelectionKind::Clipboard, offer("hello"));
        // we should see a Clip (content) and, separately, a Rules broadcast
        let mut saw_rules = false;
        for _ in 0..3 {
            match recv_msg(&mut h).await {
                Message::Rules { body, .. } => {
                    assert!(body.contains("text/plain"), "body:\n{body}");
                    assert!(body.contains("version ="), "body:\n{body}");
                    saw_rules = true;
                    break;
                }
                Message::Clip { .. } => {}
                other => panic!("unexpected {other:?}"),
            }
        }
        assert!(
            saw_rules,
            "capturing a new type should broadcast the rules file"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn capturing_a_new_type_does_not_broadcast_rules_when_sharing_off() {
        let mut cfg = Config::for_test("s"); // sharing off
        cfg.unknown_mime = MimePolicy::Allow;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        cfg.mime_rules_path = Some(path.clone());
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("hello"));
        assert!(matches!(recv_msg(&mut h).await, Message::Clip { .. }));
        assert_no_broadcast(&mut h).await; // no Rules follows
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(
            !body.contains("version ="),
            "sharing off must not stamp the file:\n{body}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn connect_pushes_the_rules_file_to_a_new_peer() {
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        std::fs::write(&path, "[rules]\n\"image/png\" = \"allow\"\n").unwrap();
        cfg.mime_rules_path = Some(path.clone());
        let h = start(cfg).await;
        // a new peer joins; it must receive our rules file
        let (tx2, mut rx2) = mpsc::channel(8);
        h.mesh.register(Uuid::new_v4(), tx2);
        let msg = timeout(Duration::from_secs(1), rx2.recv())
            .await
            .unwrap()
            .unwrap();
        match msg {
            Message::Rules { body, .. } => {
                assert!(body.contains("\"image/png\" = \"allow\""), "body:\n{body}")
            }
            other => panic!("expected a Rules push, got {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn connect_pushes_rules_even_when_receive_only() {
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        cfg.direction = Direction::ReceiveOnly;
        cfg.resync_on_connect = false;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        std::fs::write(&path, "[rules]\n\"image/png\" = \"allow\"\n").unwrap();
        cfg.mime_rules_path = Some(path.clone());
        let h = start(cfg).await;
        let (tx2, mut rx2) = mpsc::channel(8);
        h.mesh.register(Uuid::new_v4(), tx2);
        let msg = timeout(Duration::from_secs(1), rx2.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(msg, Message::Rules { .. }),
            "rules push must ignore direction/resync_on_connect"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn connect_materialises_the_version_header() {
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        std::fs::write(&path, "[rules]\n\"image/png\" = \"allow\"\n").unwrap(); // no header yet
        cfg.mime_rules_path = Some(path.clone());
        let h = start(cfg).await;
        let (tx2, mut rx2) = mpsc::channel(8);
        h.mesh.register(Uuid::new_v4(), tx2);
        let _ = timeout(Duration::from_secs(1), rx2.recv())
            .await
            .unwrap()
            .unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(
            body.contains("version ="),
            "header must be materialised on first push:\n{body}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_local_change_outranks_the_persisted_version_after_restart() {
        // The engine observes the file's header stamp at startup, so a fresh
        // local change is stamped above it (not below, which would lose).
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        cfg.unknown_mime = MimePolicy::Allow;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        cfg.mime_rules_path = Some(path.clone());
        let peer = Uuid::from_u128(123);
        let high = now_ms() + 60 * 60 * 1000; // 1h ahead, within the skew bound
        std::fs::write(
            &path,
            format!("[clipmesh]\nversion = {high}\norigin = \"{peer}\"\n[rules]\n\"text/plain\" = \"allow\"\n"),
        )
        .unwrap();
        let mut h = start(cfg).await;
        // a NEW type (image/png) is captured -> append -> version bump
        let mut o = offer("x"); // text/plain already known
        o.insert("image/png".to_string(), vec![0u8; 4]);
        h.clip.local_copy(SelectionKind::Clipboard, o);
        let mut stamp = None;
        for _ in 0..3 {
            if let Message::Rules { stamp: s, .. } = recv_msg(&mut h).await {
                stamp = Some(s);
                break;
            }
        }
        assert!(
            stamp.unwrap() > high,
            "local change must outrank the observed header stamp {high}"
        );
    }
}
