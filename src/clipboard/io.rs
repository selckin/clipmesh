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

/// Who put the content a read returned onto the selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// A genuine change — the user, or another application. Propagates.
    User,
    /// The watch echo of the engine's own write. Must not propagate, or the
    /// write re-drives the pipeline that produced it.
    Echo,
}

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
    /// Consumed one-shot by
    /// [`read_classified`](ClipboardIo::read_classified) — the only reader that
    /// takes it.
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

    /// Read every representation of a selection, bounded by [`READ_TIMEOUT`].
    /// `None` on error or timeout, both already logged — a failed read means "no
    /// update this round", never a stall.
    pub async fn read(&self, kind: SelectionKind) -> Option<Hashed> {
        self.bounded(kind, self.clipboard.read_offer(kind, None))
            .await
            .map(Hashed::new)
    }

    /// Read only `mime` from a selection. Same bound and failure handling as
    /// [`read`](ClipboardIo::read), but the backend never touches the other
    /// representations — on Wayland each one costs its own connection.
    pub async fn read_one(&self, kind: SelectionKind, mime: &str) -> Option<Hashed> {
        self.bounded(kind, self.clipboard.read_offer(kind, Some(mime)))
            .await
            .map(Hashed::new)
    }

    /// The types a selection offers, with no content read at all.
    pub async fn list_types(&self, kind: SelectionKind) -> Option<Vec<String>> {
        self.bounded(kind, self.clipboard.list_types(kind)).await
    }

    /// Apply [`READ_TIMEOUT`] to one backend call and fold both failure modes
    /// into `None`, logged. One place, so a new read can't quietly go unbounded
    /// and stall the engine's select loop.
    async fn bounded<T>(
        &self,
        kind: SelectionKind,
        op: impl std::future::Future<Output = anyhow::Result<T>>,
    ) -> Option<T> {
        match tokio::time::timeout(READ_TIMEOUT, op).await {
            Ok(Ok(v)) => Some(v),
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
        match self.clipboard.write_offer(kind, content.into_arc()).await {
            Ok(()) => true,
            Err(e) => {
                warn!("couldn't write the {kind:?} selection: {e:#}");
                self.last_written.lock().unwrap().remove(&kind);
                false
            }
        }
    }

    /// Read a selection **and** classify what came back against the pending echo
    /// marker, consuming the marker in the same step.
    ///
    /// This is the other half of the write funnel, and it exists for the same
    /// reason. The marker has two rules pulling in opposite directions: exactly
    /// one reader — the batch classifier — *must* consume it, or engine writes
    /// re-drive propagation into the echo storm the marker exists to stop; and
    /// every other reader *must not*, or a real write's echo is later mistaken
    /// for a user copy and re-broadcast.
    ///
    /// With a free-standing `take_marker` beside a plain `read`, which side a new
    /// reader landed on was a coin flip, and both mistakes surface as a mesh that
    /// never settles rather than as a failing test. Now the question is answered
    /// by *which method you called*: [`read`](ClipboardIo::read) never consumes,
    /// this always does, and there is no third option to get wrong.
    pub async fn read_classified(&self, kind: SelectionKind) -> Option<(Hashed, Origin)> {
        let raw = self.read(kind).await?;
        // One-shot: the marker suppresses exactly the one echo its write
        // provokes, so a second identical copy by the user still propagates.
        let origin = match self.last_written.lock().unwrap().remove(&kind) {
            // The read already carries its hash, so this is a 32-byte compare.
            Some(written) if written == raw.hash() => Origin::Echo,
            _ => Origin::User,
        };
        Some((raw, origin))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clipboard::mock::MockClipboard;
    use crate::protocol::test_support::text_offer as offer;

    /// The origin `read_classified` reports for `kind`, discarding the content.
    async fn origin_of<C: Clipboard>(io: &ClipboardIo<C>, kind: SelectionKind) -> Origin {
        io.read_classified(kind).await.expect("read failed").1
    }

    #[tokio::test]
    async fn a_write_reads_back_as_an_echo_exactly_once() {
        let io = ClipboardIo::new(MockClipboard::new());
        io.write(SelectionKind::Clipboard, Hashed::new(offer("x")))
            .await;
        assert_eq!(
            origin_of(&io, SelectionKind::Clipboard).await,
            Origin::Echo,
            "the engine's own write must not propagate"
        );
        // One-shot: a second identical copy by the user is a real change.
        assert_eq!(
            origin_of(&io, SelectionKind::Clipboard).await,
            Origin::User,
            "a stale marker must not suppress a later genuine copy"
        );
    }

    #[tokio::test]
    async fn a_plain_read_does_not_consume_the_echo_marker() {
        // The distinction `read_classified` exists to make structural: readers
        // that are not the batch classifier must leave the marker alone, or a
        // real write's echo is later mistaken for a user copy and re-broadcast.
        let io = ClipboardIo::new(MockClipboard::new());
        io.write(SelectionKind::Clipboard, Hashed::new(offer("x")))
            .await;
        io.read(SelectionKind::Clipboard)
            .await
            .expect("read failed");
        assert_eq!(
            origin_of(&io, SelectionKind::Clipboard).await,
            Origin::Echo,
            "a plain read consumed the marker the classifier needed"
        );
    }

    #[tokio::test]
    async fn a_failed_write_reads_back_as_a_user_change() {
        // No echo follows a write that never happened, so a later genuine copy
        // of the same bytes must not be swallowed as one.
        let clip = MockClipboard::new();
        clip.set_fail_writes(true);
        let io = ClipboardIo::new(clip.clone());
        assert!(
            !io.write(SelectionKind::Clipboard, Hashed::new(offer("x")))
                .await
        );
        clip.set_fail_writes(false);
        clip.local_copy(SelectionKind::Clipboard, offer("x"));
        assert_eq!(origin_of(&io, SelectionKind::Clipboard).await, Origin::User);
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
