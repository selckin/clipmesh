pub mod mock;
// pub mod wayland; // implemented in Task 10

use crate::protocol::{Offer, SelectionKind};
use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc;

/// Abstraction over a system clipboard. The real implementation talks to
/// Wayland; the mock backs all tests.
#[async_trait]
pub trait Clipboard: Send + Sync + 'static {
    /// Subscribe to change notifications. Fires once per selection change,
    /// including changes made through write_offer (real clipboards do this).
    fn watch(&self) -> mpsc::UnboundedReceiver<SelectionKind>;
    /// Read all offered MIME representations of the given selection.
    async fn read_offer(&self, kind: SelectionKind) -> Result<Offer>;
    /// Set the given selection to the given representations.
    async fn write_offer(&self, kind: SelectionKind, offer: Offer) -> Result<()>;
}
