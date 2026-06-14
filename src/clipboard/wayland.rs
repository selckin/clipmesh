use crate::clipboard::watch::spawn_watcher;
use crate::clipboard::Clipboard;
use crate::protocol::{describe_offer, human_bytes, Offer, SelectionKind};
use anyhow::Result;
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
    watch_primary: bool,
    max_payload: usize,
}

impl WaylandClipboard {
    pub fn new(watch_primary: bool, max_payload: usize) -> WaylandClipboard {
        WaylandClipboard {
            watch_primary,
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
    debug!("reading the {kind:?} clipboard; offered types: {types:?}");
    // Bound each read by the remaining budget (+1 to detect overflow) so a
    // huge or unbounded representation can't OOM the daemon. Note the
    // max_payload_size budget is spent here, before sync.rs applies the
    // per-type MIME allow/deny rules, so a large rep the rules would later deny
    // can still consume budget.
    let (offer, total) = assemble_offer(types, max, |mime, budget| {
        let (pipe, _actual_mime) = paste::get_contents(
            ct,
            paste::Seat::Unspecified,
            paste::MimeType::Specific(mime),
        )?;
        let mut data = Vec::new();
        pipe.take(budget as u64 + 1).read_to_end(&mut data)?;
        Ok(data)
    });
    debug!(
        "captured the {kind:?} clipboard: {} type(s), {}",
        offer.len(),
        human_bytes(total)
    );
    Ok(offer)
}

/// Whether a failed read of this advertised type likely lost real content
/// (worth a warn) rather than an X11/XWayland pseudo-target that always errors
/// on read. Real MIME types carry a '/'; X11 also exposes plain text under a
/// few uppercase atoms that ARE content, so classify those as content too.
/// Everything else slashless (TARGETS, TIMESTAMP, MULTIPLE, an app's TK_* atoms,
/// ...) is selection metadata.
fn is_content_type(mime: &str) -> bool {
    mime.contains('/') || matches!(mime, "STRING" | "UTF8_STRING" | "TEXT" | "COMPOUND_TEXT")
}

/// Build an `Offer` from the advertised `types`, reading each with `read`
/// (given the mime and remaining byte budget; it may read up to budget+1 so we
/// can detect overflow). Returns the offer and its total byte size. A
/// representation that can't be read or won't fit is skipped rather than failing
/// the whole offer, so a real image/text offered alongside unreadable
/// pseudo-targets — or a giant rep over budget — still lets the rest sync. A
/// representation that changed mid-read is likewise skipped; the watcher fires
/// again for the new content.
///
/// Types are read in sorted order so that, when the budget can't fit everything,
/// which representations survive is deterministic rather than dependent on the
/// (HashSet) order the compositor's types arrived in.
fn assemble_offer(
    types: impl IntoIterator<Item = String>,
    max: usize,
    mut read: impl FnMut(&str, usize) -> Result<Vec<u8>>,
) -> (Offer, usize) {
    let mut types: Vec<String> = types.into_iter().collect();
    types.sort();
    let mut offer = Offer::new();
    let mut total = 0usize;
    for mime in types {
        // saturating_sub: total never exceeds max here, but guard against a
        // future change turning this into a panic on attacker-influenced input.
        let budget = max.saturating_sub(total);
        let data = match read(&mime, budget) {
            Ok(d) => d,
            Err(e) => {
                // A content type that won't read is real data loss worth a warn;
                // a pseudo-target erroring on read is expected, so keep it quiet.
                if is_content_type(&mime) {
                    warn!("skipping clipboard type {mime}: can't read it ({e:#})");
                } else {
                    debug!("skipping clipboard type {mime}: not readable content ({e:#})");
                }
                continue;
            }
        };
        if mime.len() + data.len() > budget {
            // This representation would push the offer over the cap. Skip it but
            // keep the rest, so a small syncable payload alongside a giant image
            // (which can never sync) still propagates. warn, not debug, so the
            // user can see why a large representation isn't syncing. The read
            // stopped at the budget, so the true size is only known to exceed
            // it — raising max_payload_size is the fix for images.
            warn!(
                "skipping clipboard type {mime}: it doesn't fit the remaining {} \
                 of the {} max_payload_size budget (raise max_payload_size to sync large images)",
                human_bytes(budget),
                human_bytes(max)
            );
            continue;
        }
        debug!("read clipboard type {mime} ({})", human_bytes(data.len()));
        total += mime.len() + data.len();
        offer.insert(mime, data);
    }
    (offer, total)
}

fn write_offer_blocking(kind: SelectionKind, offer: Offer) -> Result<()> {
    if offer.is_empty() {
        debug!("nothing to write to the {kind:?} clipboard (empty offer)");
        return Ok(());
    }
    debug!(
        "writing the {kind:?} clipboard ({})",
        describe_offer(&offer)
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
        spawn_watcher(tx, self.watch_primary);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assemble_offer_skips_unreadable_reps_and_keeps_the_rest() {
        // An X11/XWayland selection advertises pseudo-targets (no '/') that
        // error on read alongside the real content; the real type must survive.
        let types = vec!["TARGETS".into(), "image/png".into(), "TIMESTAMP".into()];
        let (offer, _) = assemble_offer(types, 1024, |mime, _budget| {
            if mime.contains('/') {
                Ok(vec![1u8, 2, 3])
            } else {
                Err(anyhow::anyhow!("pseudo-target, not readable"))
            }
        });
        assert_eq!(offer.len(), 1);
        assert_eq!(
            offer.get("image/png").map(Vec::as_slice),
            Some(&[1u8, 2, 3][..])
        );
    }

    #[test]
    fn assemble_offer_drops_reps_over_budget_but_keeps_small_ones() {
        // The big rep reads up to budget+1 and is dropped; the small one stays.
        let types = vec!["image/big".into(), "text/plain".into()];
        let (offer, total) = assemble_offer(types, 64, |mime, budget| {
            if mime == "image/big" {
                Ok(vec![0u8; budget + 1])
            } else {
                Ok(b"hi".to_vec())
            }
        });
        assert!(!offer.contains_key("image/big"));
        assert_eq!(offer.get("text/plain").map(Vec::as_slice), Some(&b"hi"[..]));
        assert_eq!(total, "text/plain".len() + 2); // running total, not recomputed
    }

    #[test]
    fn assemble_offer_is_empty_when_everything_fails() {
        let types = vec!["image/png".into(), "text/plain".into()];
        let (offer, total) = assemble_offer(types, 1024, |_mime, _budget| {
            Err(anyhow::anyhow!("read failed"))
        });
        assert!(offer.is_empty());
        assert_eq!(total, 0);
    }

    #[test]
    fn content_type_classification_covers_x11_text_atoms() {
        // Real MIME types and the X11 text atoms are content (a failed read is
        // worth a warn); selection-metadata atoms are not.
        for m in [
            "image/png",
            "text/plain",
            "STRING",
            "UTF8_STRING",
            "TEXT",
            "COMPOUND_TEXT",
        ] {
            assert!(is_content_type(m), "{m} should be content");
        }
        for m in [
            "TARGETS",
            "TIMESTAMP",
            "MULTIPLE",
            "SAVE_TARGETS",
            "TK_SELECTION",
        ] {
            assert!(!is_content_type(m), "{m} should not be content");
        }
    }

    #[test]
    fn assemble_offer_is_deterministic_regardless_of_input_order() {
        // Budget fits only the first rep read; the result must not depend on the
        // (HashSet-derived) iteration order of the advertised types.
        let (a, _) = assemble_offer(vec!["a/x".into(), "b/x".into()], 50, |_m, _b| {
            Ok(vec![0u8; 40])
        });
        let (b, _) = assemble_offer(vec!["b/x".into(), "a/x".into()], 50, |_m, _b| {
            Ok(vec![0u8; 40])
        });
        assert_eq!(
            a.keys().collect::<Vec<_>>(),
            b.keys().collect::<Vec<_>>(),
            "result depends on input order"
        );
        assert!(a.contains_key("a/x") && !a.contains_key("b/x"));
    }
}
