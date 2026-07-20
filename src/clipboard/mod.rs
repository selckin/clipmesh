pub mod atoms;
pub mod io;
pub mod mock;
pub mod watch;
pub mod wayland;

use crate::protocol::{Offer, SelectionKind};
use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc;

/// What a [`Clipboard`] watcher reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardEvent {
    /// The selection's content as of the `watch` call that produced this stream,
    /// captured by the backend. At most one per selection, always before any
    /// `Changed` for it, and omitted entirely when the selection was empty.
    ///
    /// The engine treats this as *restored* content: recorded so it is not
    /// re-broadcast as a fresh copy after a restart, and never bridged, re-owned
    /// or sent to the mesh under a new stamp.
    Initial { kind: SelectionKind, offer: Offer },
    /// The selection changed after `watch` was called — a genuine local action
    /// (or the echo of one of our own writes, which the engine filters).
    Changed(SelectionKind),
}

/// Abstraction over a system clipboard. The real implementation talks to
/// Wayland; the mock backs all tests.
#[async_trait]
pub trait Clipboard: Send + Sync + 'static {
    /// Subscribe to clipboard events for `kinds`.
    ///
    /// Fires a [`ClipboardEvent::Changed`] at least once per change of one of
    /// those selections, including changes made through `write_offer` (real
    /// clipboards do this). May deliver a kind outside `kinds` — the engine
    /// tolerates that; `kinds` is what the backend is asked to *guarantee*.
    ///
    /// Taking the set here rather than at construction keeps the contract
    /// self-contained: an implementation needs no configuration of its own, and
    /// the engine's notion of what it watches can't drift from the backend's.
    ///
    /// # The `Initial` contract
    ///
    /// Before any `Changed` for a selection, the implementation must deliver one
    /// [`ClipboardEvent::Initial`] for it carrying **the content as of this
    /// call** — or none at all, if the selection was empty.
    ///
    /// The content must be captured by the backend, not read back later. The
    /// engine reads lazily, after an event, so anything it reads reflects *now*
    /// rather than when the event fired; it therefore cannot tell restored
    /// content from a copy the user made a moment after startup. Getting that
    /// wrong is not cosmetic — misjudged content is suppressed instead of
    /// broadcast, and recorded at stamp 0 where a peer's *older* clipboard
    /// outranks it. Only the backend exists at subscribe time, so only the
    /// backend can answer the question.
    fn watch(&self, kinds: &[SelectionKind]) -> mpsc::UnboundedReceiver<ClipboardEvent>;
    /// The MIME types `kind` currently offers, without reading any contents.
    ///
    /// Separate from [`read_offer`](Clipboard::read_offer) because reading is
    /// not cheap: the Wayland backend spends a whole connection and roundtrip
    /// **per representation**, so answering "what types are on offer?" by
    /// reading them all turns one roundtrip into one per type — and for a
    /// clipboard holding a large image, megabytes of pipe reads to produce a
    /// list of names.
    async fn list_types(&self, kind: SelectionKind) -> Result<Vec<String>>;

    /// Read the offered MIME representations of the given selection, restricted
    /// to a single type (matched case-insensitively) when `only` is set.
    ///
    /// `only` exists for the same reason as `list_types`: a caller that wants
    /// one representation should not pay to read the rest.
    ///
    /// May return an error if the contents exceed the implementation's
    /// payload cap or a representation cannot be read in full.
    async fn read_offer(&self, kind: SelectionKind, only: Option<&str>) -> Result<Offer>;
    /// Set the given selection to the given representations.
    async fn write_offer(&self, kind: SelectionKind, offer: Offer) -> Result<()>;
}
