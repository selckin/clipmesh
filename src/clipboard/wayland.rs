use crate::clipboard::watch::spawn_watcher;
use crate::clipboard::Clipboard;
use crate::protocol::{describe_offer, Offer, SelectionKind};
use anyhow::{bail, Result};
use async_trait::async_trait;
use std::io::Read;
use tokio::sync::mpsc;
use tracing::{debug, warn};
use wl_clipboard_rs::copy;
use wl_clipboard_rs::paste;

/// Wayland clipboard via the data-control protocol. Requires a compositor
/// implementing ext-data-control-v1 or zwlr-data-control-v1 (niri, Sway,
/// Hyprland, KDE Plasma, ...). Reading, writing, and change watching are all
/// in-process over that protocol; no external wl-clipboard/wl-paste binary
/// is required.
pub struct WaylandClipboard {
    sync_primary: bool,
    max_payload: usize,
}

impl WaylandClipboard {
    pub fn new(sync_primary: bool, max_payload: usize) -> WaylandClipboard {
        WaylandClipboard {
            sync_primary,
            max_payload,
        }
    }
}

fn paste_type(kind: SelectionKind) -> paste::ClipboardType {
    match kind {
        SelectionKind::Clipboard => paste::ClipboardType::Regular,
        SelectionKind::Primary => paste::ClipboardType::Primary,
    }
}

fn copy_type(kind: SelectionKind) -> copy::ClipboardType {
    match kind {
        SelectionKind::Clipboard => copy::ClipboardType::Regular,
        SelectionKind::Primary => copy::ClipboardType::Primary,
    }
}

fn read_offer_blocking(kind: SelectionKind, max: usize) -> Result<Offer> {
    let ct = paste_type(kind);
    let types = match paste::get_mime_types(ct, paste::Seat::Unspecified) {
        Ok(t) => t,
        Err(paste::Error::NoSeats | paste::Error::ClipboardEmpty | paste::Error::NoMimeType) => {
            return Ok(Offer::new())
        }
        Err(e) => return Err(e.into()),
    };
    debug!(?kind, mimes = ?types, "clipboard offers MIME types; reading them");
    let mut offer = Offer::new();
    let mut total = 0usize;
    for mime in types {
        // A genuine read error aborts the whole offer: silently dropping one
        // representation would ship a mutated offer to peers. If the
        // clipboard changed mid-read, the watcher fires again anyway.
        let (pipe, _actual_mime) = match paste::get_contents(
            ct,
            paste::Seat::Unspecified,
            paste::MimeType::Specific(&mime),
        ) {
            Ok(x) => x,
            Err(e) => bail!("failed to read clipboard representation {mime}: {e}"),
        };
        // Bound the read by the remaining budget (+1 to detect overflow) so a
        // huge or unbounded representation can't OOM the daemon before the
        // cap is consulted. total never exceeds max, so the subtraction is safe.
        let budget = max - total;
        let mut data = Vec::new();
        pipe.take(budget as u64 + 1).read_to_end(&mut data)?;
        if mime.len() + data.len() > budget {
            // This representation would push the offer over the cap. Skip it
            // but keep the rest, so a small syncable payload alongside a giant
            // image (which can never sync) still propagates. warn, not debug,
            // so the user can see why a large representation isn't syncing.
            // The read stopped at the budget, so the true size is only known
            // to exceed it — raising max_payload_size is the fix for images.
            warn!(
                %mime,
                read_bytes = data.len(),
                remaining_budget = budget,
                cap = max,
                "clipboard representation does not fit the remaining max_payload_size \
                 budget; skipping it (raise max_payload_size to sync large images)"
            );
            continue;
        }
        debug!(%mime, bytes = data.len(), "read clipboard representation");
        total += mime.len() + data.len();
        offer.insert(mime, data);
    }
    debug!(?kind, reps = offer.len(), total, "captured clipboard offer");
    Ok(offer)
}

fn write_offer_blocking(kind: SelectionKind, offer: Offer) -> Result<()> {
    if offer.is_empty() {
        debug!(?kind, "write_offer: nothing to write (empty offer)");
        return Ok(());
    }
    debug!(
        ?kind,
        reps = offer.len(),
        total = offer.values().map(|d| d.len()).sum::<usize>(),
        mimes = %describe_offer(&offer),
        "writing clipboard offer"
    );
    let sources: Vec<copy::MimeSource> = offer
        .into_iter()
        .map(|(mime, data)| copy::MimeSource {
            source: copy::Source::Bytes(data.into_boxed_slice()),
            mime_type: copy::MimeType::Specific(mime),
        })
        .collect();
    let mut opts = copy::Options::new();
    opts.clipboard(copy_type(kind));
    // Advertise exactly the MIME types we were given. Without this,
    // wl-clipboard-rs adds text/plain, text/plain;charset=utf-8, STRING,
    // UTF8_STRING and TEXT whenever any text type is present, so reading the
    // selection back would not byte-match what we wrote — defeating echo
    // suppression and causing the node to re-broadcast a mutated offer (an
    // echo loop).
    opts.omit_additional_text_mime_types(true);
    opts.copy_multi(sources)?;
    Ok(())
}

#[async_trait]
impl Clipboard for WaylandClipboard {
    fn watch(&self) -> mpsc::UnboundedReceiver<SelectionKind> {
        let (tx, rx) = mpsc::unbounded_channel();
        // One in-process data-control listener covers both selections; see
        // clipboard::watch. (Was a wl-paste --watch subprocess per kind.)
        spawn_watcher(tx, self.sync_primary);
        rx
    }

    async fn read_offer(&self, kind: SelectionKind) -> Result<Offer> {
        let max = self.max_payload;
        tokio::task::spawn_blocking(move || read_offer_blocking(kind, max)).await?
    }

    async fn write_offer(&self, kind: SelectionKind, offer: Offer) -> Result<()> {
        tokio::task::spawn_blocking(move || write_offer_blocking(kind, offer)).await?
    }
}
