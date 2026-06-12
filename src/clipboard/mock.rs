use crate::clipboard::Clipboard;
use crate::protocol::{Offer, SelectionKind};
use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// In-memory clipboard for tests. Mirrors real-clipboard behavior:
/// programmatic writes re-fire the watcher (exercising echo suppression).
pub struct MockClipboard {
    state: Mutex<HashMap<SelectionKind, Offer>>,
    watchers: Mutex<Vec<mpsc::UnboundedSender<SelectionKind>>>,
    writes: AtomicUsize,
    fail_writes: std::sync::atomic::AtomicBool,
}

impl MockClipboard {
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Arc<MockClipboard> {
        Arc::new(MockClipboard {
            state: Mutex::new(HashMap::new()),
            watchers: Mutex::new(Vec::new()),
            writes: AtomicUsize::new(0),
            fail_writes: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Make subsequent write_offer calls fail (simulates transient
    /// compositor errors).
    pub fn set_fail_writes(&self, fail: bool) {
        self.fail_writes.store(fail, Ordering::SeqCst);
    }

    /// Seed existing clipboard content without notifying watchers, modelling
    /// a selection that already existed before the daemon started (so tests
    /// can exercise startup priming).
    pub fn seed(&self, kind: SelectionKind, offer: Offer) {
        self.state.lock().unwrap().insert(kind, offer);
    }

    /// Simulate a user copying something locally.
    pub fn local_copy(&self, kind: SelectionKind, offer: Offer) {
        self.state.lock().unwrap().insert(kind, offer);
        self.notify(kind);
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

    fn notify(&self, kind: SelectionKind) {
        self.watchers
            .lock()
            .unwrap()
            .retain(|tx| tx.send(kind).is_ok());
    }
}

#[async_trait]
impl Clipboard for MockClipboard {
    fn watch(&self) -> mpsc::UnboundedReceiver<SelectionKind> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.watchers.lock().unwrap().push(tx);
        rx
    }

    async fn read_offer(&self, kind: SelectionKind) -> Result<Offer> {
        Ok(self.get(kind).unwrap_or_default())
    }

    async fn write_offer(&self, kind: SelectionKind, offer: Offer) -> Result<()> {
        if self.fail_writes.load(Ordering::SeqCst) {
            anyhow::bail!("simulated clipboard write failure");
        }
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.state.lock().unwrap().insert(kind, offer);
        self.notify(kind);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::SelectionKind;

    fn offer(text: &str) -> crate::protocol::Offer {
        [("text/plain".to_string(), text.as_bytes().to_vec())]
            .into_iter()
            .collect()
    }

    #[tokio::test]
    async fn local_copy_notifies_watchers_and_updates_state() {
        let clip = MockClipboard::new();
        let mut watch = clip.watch();
        clip.local_copy(SelectionKind::Clipboard, offer("hello"));
        assert_eq!(watch.recv().await, Some(SelectionKind::Clipboard));
        assert_eq!(
            clip.read_offer(SelectionKind::Clipboard).await.unwrap(),
            offer("hello")
        );
    }

    #[tokio::test]
    async fn write_offer_counts_and_notifies_like_a_real_clipboard() {
        let clip = MockClipboard::new();
        let mut watch = clip.watch();
        assert_eq!(clip.write_count(), 0);
        clip.write_offer(SelectionKind::Clipboard, offer("net"))
            .await
            .unwrap();
        assert_eq!(clip.write_count(), 1);
        assert_eq!(clip.get(SelectionKind::Clipboard), Some(offer("net")));
        // real clipboards re-fire the watcher on programmatic set
        assert_eq!(watch.recv().await, Some(SelectionKind::Clipboard));
    }

    #[tokio::test]
    async fn selections_are_independent() {
        let clip = MockClipboard::new();
        clip.local_copy(SelectionKind::Primary, offer("prim"));
        assert_eq!(
            clip.read_offer(SelectionKind::Clipboard).await.unwrap(),
            Default::default()
        );
        assert_eq!(
            clip.read_offer(SelectionKind::Primary).await.unwrap(),
            offer("prim")
        );
    }
}
