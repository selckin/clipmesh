//! The sync engine's sole gateway to a [`Clipboard`] backend.

use crate::clipboard::{Clipboard, ClipboardEvent};
use crate::protocol::{Hashed, SelectionKind};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::warn;

/// Bound every read: they run inside the engine's select loop (and at startup),
/// so a slow or unresponsive selection owner must not be able to freeze it. A
/// real read of the size-capped clipboard takes milliseconds; exceeding this
/// means the source isn't serving its pipe.
///
/// Lives here rather than in the engine because it is a backend-liveness
/// concern, not a sync policy.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// The engine's clipboard gateway: every read, write and subscribe it performs
/// goes through here.
///
/// This type exists to make echo suppression **structural**. It owns the
/// `Arc<C>` in a module the engine cannot see into, so
/// [`Clipboard::write_offer`] is simply unreachable from `SyncEngine`: the only
/// way to write is [`write`], which records the content's hash in
/// `last_written` before writing and rolls the record back if the write fails.
/// A new engine write path therefore *cannot* forget to record its own write.
///
/// That mattered because the previous arrangement was a convention. `clipboard`
/// and `last_written` sat side by side as engine fields, so any line of the
/// ~1400-line `impl SyncEngine` could call `write_offer` directly and compile
/// cleanly — and the failure mode is an echo storm, precisely what the marker
/// exists to prevent. A doc comment asked people to route through
/// `write_selection`; nothing enforced it. This is the treatment [`Hashed`]
/// already gave stale hashes: unrepresentable rather than discouraged.
///
/// [`write`]: ClipboardIo::write
pub struct ClipboardIo<C> {
    clipboard: Arc<C>,
    /// Content the engine itself wrote, awaiting the watch echo it provokes.
    /// Consumed one-shot by [`take_marker`](ClipboardIo::take_marker).
    last_written: Mutex<HashMap<SelectionKind, [u8; 32]>>,
}

impl<C: Clipboard> ClipboardIo<C> {
    pub fn new(clipboard: Arc<C>) -> ClipboardIo<C> {
        ClipboardIo {
            clipboard,
            last_written: Mutex::new(HashMap::new()),
        }
    }

    /// Subscribe to changes on `kinds`. See [`ClipboardEvent`] for the
    /// `Initial`-before-`Changed` contract the backend owes.
    pub fn watch(&self, kinds: &[SelectionKind]) -> mpsc::UnboundedReceiver<ClipboardEvent> {
        self.clipboard.watch(kinds)
    }

    /// Read a selection, bounded by [`READ_TIMEOUT`]. `None` on error or
    /// timeout, both already logged — a failed read means "no update this
    /// round", never a stall.
    pub async fn read(&self, kind: SelectionKind) -> Option<Hashed> {
        match tokio::time::timeout(READ_TIMEOUT, self.clipboard.read_offer(kind)).await {
            Ok(Ok(o)) => Some(Hashed::new(o)),
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

    /// Write `content` to `kind` on the engine's behalf, recording it so the
    /// watch echo it provokes is dropped rather than re-driving propagation.
    /// Returns whether the write succeeded.
    ///
    /// Records *before* writing, because the echo can arrive as soon as the
    /// write lands, and rolls the record back on failure, since no echo follows
    /// a write that never happened (and a later genuine copy of identical bytes
    /// must not be suppressed).
    pub async fn write(&self, kind: SelectionKind, content: Hashed) -> bool {
        self.last_written
            .lock()
            .unwrap()
            .insert(kind, content.hash());
        match self.clipboard.write_offer(kind, content.into_offer()).await {
            Ok(()) => true,
            Err(e) => {
                warn!("couldn't write the {kind:?} selection: {e:#}");
                self.last_written.lock().unwrap().remove(&kind);
                false
            }
        }
    }

    /// Take the pending echo marker for `kind`, if any. One-shot: the marker
    /// suppresses exactly the one echo its write provokes, so a second identical
    /// copy by the user still propagates.
    pub fn take_marker(&self, kind: SelectionKind) -> Option<[u8; 32]> {
        self.last_written.lock().unwrap().remove(&kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clipboard::mock::MockClipboard;
    use crate::protocol::test_support::text_offer as offer;

    #[tokio::test]
    async fn a_write_records_a_marker_that_is_taken_once() {
        let io = ClipboardIo::new(MockClipboard::new());
        let content = Hashed::new(offer("x"));
        assert!(io.write(SelectionKind::Clipboard, content.clone()).await);
        assert_eq!(
            io.take_marker(SelectionKind::Clipboard),
            Some(content.hash())
        );
        // One-shot: a second identical copy by the user must still propagate.
        assert_eq!(io.take_marker(SelectionKind::Clipboard), None);
    }

    #[tokio::test]
    async fn a_failed_write_leaves_no_marker() {
        // Otherwise a later genuine copy of the same bytes would be swallowed as
        // the echo of a write that never happened.
        let clip = MockClipboard::new();
        clip.set_fail_writes(true);
        let io = ClipboardIo::new(clip);
        assert!(
            !io.write(SelectionKind::Clipboard, Hashed::new(offer("x")))
                .await
        );
        assert_eq!(io.take_marker(SelectionKind::Clipboard), None);
    }

    #[tokio::test]
    async fn a_read_that_never_answers_times_out_instead_of_stalling() {
        tokio::time::pause();
        let clip = MockClipboard::new();
        clip.block_reads();
        let io = ClipboardIo::new(clip);
        assert_eq!(io.read(SelectionKind::Clipboard).await, None);
    }
}
