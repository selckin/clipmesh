pub mod mock;
pub mod wayland;

use crate::protocol::{Offer, SelectionKind};
use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc;

/// Abstraction over a system clipboard. The real implementation talks to
/// Wayland; the mock backs all tests.
#[async_trait]
pub trait Clipboard: Send + Sync + 'static {
    /// Subscribe to change notifications. Fires at least once per change of
    /// a watched selection (Primary only when enabled), including changes
    /// made through write_offer (real clipboards do this). Implementations
    /// may also fire once at subscribe time for the current selection.
    fn watch(&self) -> mpsc::UnboundedReceiver<SelectionKind>;
    /// Read all offered MIME representations of the given selection.
    /// May return an error if the contents exceed the implementation's
    /// payload cap or a representation cannot be read in full.
    async fn read_offer(&self, kind: SelectionKind) -> Result<Offer>;
    /// Set the given selection to the given representations.
    async fn write_offer(&self, kind: SelectionKind, offer: Offer) -> Result<()>;
}
