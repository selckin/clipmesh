use crate::clipboard::{Clipboard, ClipboardEvent};
use crate::protocol::{Offer, SelectionKind};
use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, Semaphore};

/// In-memory clipboard for tests. Mirrors real-clipboard behavior:
/// programmatic writes re-fire the watcher (exercising echo suppression).
pub struct MockClipboard {
    state: Mutex<HashMap<SelectionKind, Offer>>,
    watchers: Mutex<Vec<mpsc::UnboundedSender<ClipboardEvent>>>,
    writes: AtomicUsize,
    fail_writes: std::sync::atomic::AtomicBool,
    fail_reads: std::sync::atomic::AtomicBool,
    /// `Some` while reads are gated by `block_reads`; `None` (the default) lets
    /// them through immediately.
    read_gate: Mutex<Option<Arc<Semaphore>>>,
}

impl MockClipboard {
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Arc<MockClipboard> {
        Arc::new(MockClipboard {
            state: Mutex::new(HashMap::new()),
            watchers: Mutex::new(Vec::new()),
            writes: AtomicUsize::new(0),
            fail_writes: std::sync::atomic::AtomicBool::new(false),
            fail_reads: std::sync::atomic::AtomicBool::new(false),
            read_gate: Mutex::new(None),
        })
    }

    /// Make subsequent write_offer calls fail (simulates transient
    /// compositor errors).
    pub fn set_fail_writes(&self, fail: bool) {
        self.fail_writes.store(fail, Ordering::SeqCst);
    }

    /// Make subsequent read_offer calls fail (simulates a transient read error).
    pub fn set_fail_reads(&self, fail: bool) {
        self.fail_reads.store(fail, Ordering::SeqCst);
    }

    /// Stall every subsequent `read_offer` until [`allow_reads`], modelling a
    /// slow or unresponsive selection owner. Left blocked, it models one that
    /// never answers at all.
    ///
    /// This is what lets the `Initial`-contract tests be exact rather than
    /// hopeful: with reads gated, any content the engine has must have come from
    /// the backend's `Initial` event, so "read it back later" implementations
    /// fail the test deterministically instead of occasionally.
    ///
    /// [`allow_reads`]: MockClipboard::allow_reads
    pub fn block_reads(&self) {
        *self.read_gate.lock().unwrap() = Some(Arc::new(Semaphore::new(0)));
    }

    /// Release reads stalled by [`block_reads`], and stop gating later ones.
    ///
    /// [`block_reads`]: MockClipboard::block_reads
    pub fn allow_reads(&self) {
        if let Some(gate) = self.read_gate.lock().unwrap().take() {
            gate.add_permits(Semaphore::MAX_PERMITS);
        }
    }

    /// Seed existing clipboard content without notifying watchers, modelling
    /// a selection that already existed before the daemon started (so tests
    /// can exercise the startup-restore path).
    pub fn seed(&self, kind: SelectionKind, offer: Offer) {
        self.state.lock().unwrap().insert(kind, offer);
    }

    /// Simulate a user copying something locally.
    pub fn local_copy(&self, kind: SelectionKind, offer: Offer) {
        self.set_and_notify(kind, offer);
    }

    /// Store `offer` and fire `Changed`, holding both locks across the pair in
    /// the same order `watch` takes them.
    ///
    /// That ordering is the whole point: a copy must land entirely before a
    /// subscribe (so `watch` reports it as `Initial` and no `Changed` follows)
    /// or entirely after it (so it arrives as `Changed`). Setting the state and
    /// notifying as two separate critical sections would let a subscribe slip
    /// between them and report the same copy as *both*, which is exactly the
    /// startup misattribution the `Initial` contract exists to rule out.
    fn set_and_notify(&self, kind: SelectionKind, offer: Offer) {
        let mut state = self.state.lock().unwrap();
        let mut watchers = self.watchers.lock().unwrap();
        state.insert(kind, offer);
        watchers.retain(|tx| tx.send(ClipboardEvent::Changed(kind)).is_ok());
    }

    pub fn get(&self, kind: SelectionKind) -> Option<Offer> {
        self.state.lock().unwrap().get(&kind).cloned()
    }

    /// Number of write_offer calls (i.e. network-applied updates).
    pub fn write_count(&self) -> usize {
        self.writes.load(Ordering::SeqCst)
    }

    pub fn watcher_count(&self) -> usize {
        self.watchers.lock().unwrap().len()
    }
}

#[async_trait]
impl Clipboard for MockClipboard {
    fn watch(&self, _kinds: &[SelectionKind]) -> mpsc::UnboundedReceiver<ClipboardEvent> {
        // The mock delivers whatever a test seeds; the engine filters. Honouring
        // `kinds` here would hide engine-side gating bugs from the tests.
        let (tx, rx) = mpsc::unbounded_channel();
        // Snapshot the seeded content and register the sender under BOTH locks,
        // in the order `local_copy` takes them. That makes the `Initial`
        // contract exact rather than probable: a copy racing this call either
        // lands before the snapshot (and is what `Initial` reports) or after the
        // sender is registered (and arrives as `Changed`) — never both, never
        // neither. The real backend can only approximate this; the mock is what
        // lets the engine's half be tested deterministically.
        let state = self.state.lock().unwrap();
        let mut watchers = self.watchers.lock().unwrap();
        for (kind, offer) in state.iter() {
            if offer.is_empty() {
                continue;
            }
            let _ = tx.send(ClipboardEvent::Initial {
                kind: *kind,
                offer: offer.clone(),
            });
        }
        watchers.push(tx);
        rx
    }

    async fn list_types(&self, kind: SelectionKind) -> Result<Vec<String>> {
        // Deliberately NOT gated by `read_gate`/`fail_reads`: the whole point of
        // `list_types` is that it doesn't read contents, so a test that blocks
        // content reads must still be able to list.
        Ok(self
            .get(kind)
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default())
    }

    async fn read_offer(&self, kind: SelectionKind, only: Option<&str>) -> Result<Offer> {
        if self.fail_reads.load(Ordering::SeqCst) {
            anyhow::bail!("simulated clipboard read failure");
        }
        // Clone the gate out before awaiting: the std mutex must not be held
        // across an await point.
        let gate = self.read_gate.lock().unwrap().clone();
        if let Some(gate) = gate {
            let _permit = gate.acquire().await;
        }
        let mut offer = self.get(kind).unwrap_or_default();
        if let Some(want) = only {
            offer.retain(|k, _| crate::protocol::type_matches(k, want));
        }
        Ok(offer)
    }

    async fn write_offer(&self, kind: SelectionKind, offer: Arc<Offer>) -> Result<()> {
        if self.fail_writes.load(Ordering::SeqCst) {
            anyhow::bail!("simulated clipboard write failure");
        }
        self.writes.fetch_add(1, Ordering::SeqCst);
        // The mock owns its state, so it takes a copy here — the real backend
        // has to copy into `copy_multi`'s boxed slices anyway.
        self.set_and_notify(kind, (*offer).clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::test_support::text_offer as offer;
    use crate::protocol::SelectionKind;

    #[tokio::test]
    async fn local_copy_notifies_watchers_and_updates_state() {
        let clip = MockClipboard::new();
        let mut watch = clip.watch(&[SelectionKind::Clipboard, SelectionKind::Selection]);
        clip.local_copy(SelectionKind::Clipboard, offer("hello"));
        assert_eq!(
            watch.recv().await,
            Some(ClipboardEvent::Changed(SelectionKind::Clipboard))
        );
        assert_eq!(
            clip.read_offer(SelectionKind::Clipboard, None)
                .await
                .unwrap(),
            offer("hello")
        );
    }

    #[tokio::test]
    async fn write_offer_counts_and_notifies_like_a_real_clipboard() {
        let clip = MockClipboard::new();
        let mut watch = clip.watch(&[SelectionKind::Clipboard, SelectionKind::Selection]);
        assert_eq!(clip.write_count(), 0);
        clip.write_offer(SelectionKind::Clipboard, offer("net").into())
            .await
            .unwrap();
        assert_eq!(clip.write_count(), 1);
        assert_eq!(clip.get(SelectionKind::Clipboard), Some(offer("net")));
        // real clipboards re-fire the watcher on programmatic set
        assert_eq!(
            watch.recv().await,
            Some(ClipboardEvent::Changed(SelectionKind::Clipboard))
        );
    }

    #[tokio::test]
    async fn selections_are_independent() {
        let clip = MockClipboard::new();
        clip.local_copy(SelectionKind::Selection, offer("prim"));
        assert_eq!(
            clip.read_offer(SelectionKind::Clipboard, None)
                .await
                .unwrap(),
            Offer::new()
        );
        assert_eq!(
            clip.read_offer(SelectionKind::Selection, None)
                .await
                .unwrap(),
            offer("prim")
        );
    }
}
