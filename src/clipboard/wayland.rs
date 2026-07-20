use crate::clipboard::watch::spawn_watcher;
use crate::clipboard::{Clipboard, ClipboardEvent};
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
    max_payload: usize,
}

impl WaylandClipboard {
    pub fn new(max_payload: usize) -> WaylandClipboard {
        WaylandClipboard { max_payload }
    }
}

fn paste_type(kind: SelectionKind) -> paste::ClipboardType {
    match kind {
        SelectionKind::Clipboard => paste::ClipboardType::Regular,
        SelectionKind::Selection => paste::ClipboardType::Primary,
    }
}

fn copy_type(kind: SelectionKind) -> copy::ClipboardType {
    match kind {
        SelectionKind::Clipboard => copy::ClipboardType::Regular,
        SelectionKind::Selection => copy::ClipboardType::Primary,
    }
}

pub(crate) fn read_offer_blocking(kind: SelectionKind, max: usize) -> Result<Offer> {
    let ct = paste_type(kind);
    // get_mime_types_ordered (not get_mime_types) preserves the compositor's
    // advertise order — preference order, richest first — so the offer we build
    // carries it through to remote pasters. get_mime_types returns a HashSet,
    // discarding that order before we ever see it.
    let types = match paste::get_mime_types_ordered(ct, paste::Seat::Unspecified) {
        Ok(t) => t,
        Err(paste::Error::NoSeats | paste::Error::ClipboardEmpty | paste::Error::NoMimeType) => {
            return Ok(Offer::new())
        }
        Err(e) => return Err(e.into()),
    };
    debug!("reading the {kind:?} clipboard; offered types: {types:?}");
    // Bound each read by the remaining budget (+1 to detect overflow) so a
    // huge or unbounded representation can't OOM the daemon.
    //
    // This budget and `sync::cap_to_payload_size` are both `max_payload_size`
    // but are NOT the same decision, and the difference is inherent rather than
    // an oversight (see `assemble_offer`).
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

/// ICCCM selection targets that are protocol machinery rather than content, and
/// that no source ever serves as data — reading one always fails.
///
/// Worth naming explicitly because a read is not cheap here: every
/// representation costs its own Wayland connection (see `read_offer_blocking`),
/// so attempting these spends a full connect-and-roundtrip per selection just to
/// be told no. Skipping them is exactly equivalent — a failed read is dropped
/// from the offer anyway — but does not pay for the answer.
///
/// Deliberately an exact list rather than "anything `!is_content_type`": an
/// unrecognised slashless atom might genuinely carry data, and is still attempted
/// (its failure is logged at debug, as before).
const SELECTION_MACHINERY: [&str; 7] = [
    "TARGETS",
    "TIMESTAMP",
    "MULTIPLE",
    "SAVE_TARGETS",
    "DELETE",
    "INSERT_SELECTION",
    "INSERT_PROPERTY",
];

/// Build an `Offer` from the advertised `types`, reading each with `read`
/// (given the mime and remaining byte budget; it may read up to budget+1 so we
/// can detect overflow). Returns the offer and its total byte size. A
/// representation that can't be read or won't fit is skipped rather than failing
/// the whole offer, so a real image/text offered alongside unreadable
/// pseudo-targets — or a giant rep over budget — still lets the rest sync. A
/// representation that changed mid-read is likewise skipped; the watcher fires
/// again for the new content.
///
/// Types are read in the compositor's advertise order (preference order, richest
/// first), which the offer then preserves end-to-end. When the budget can't fit
/// everything, the earlier-advertised (more-preferred) representations survive;
/// the order is deterministic because `get_mime_types_ordered` hands it to us as
/// an ordered list rather than an unordered set.
///
/// # Why this budget is not `cap_to_payload_size`
///
/// Both spend `max_payload_size`, but they answer different questions with
/// different information, and the duplication cannot be removed:
///
/// - Here, sizes are unknowable until a representation has been read, so the
///   only possible strategy is streaming and greedy: take them in advertise
///   order until the budget runs out. `cap_to_payload_size` runs afterwards with
///   every size in hand and can therefore choose smallest-first, which fits more
///   representations. Neither strategy can be used at the other's layer.
/// - This layer also cannot pre-filter by the MIME rules to avoid spending
///   budget on a representation that will later be denied. The rules govern what
///   leaves the host, not what the user may paste locally: `Stages::OWN` and
///   `Stages::MIRROR` deliberately re-offer denied representations to the local
///   selections. Filtering here would strip them before those pipelines ever
///   saw them. (Tried; `both_directions_no_redundant_write_with_denied_rep`
///   catches it.)
///
/// The residual wart is real but small: a large representation advertised early
/// can consume budget that a later one then can't have, even if the rules would
/// have dropped the first. Raising `max_payload_size` is the user-facing fix.
fn assemble_offer(
    types: impl IntoIterator<Item = String>,
    max: usize,
    mut read: impl FnMut(&str, usize) -> Result<Vec<u8>>,
) -> (Offer, usize) {
    let mut offer = Offer::new();
    let mut total = 0usize;
    for mime in types {
        // get_mime_types_ordered is a plain Vec with no dedup; a type advertised
        // twice must be read and counted once, or its bytes are double-charged to
        // the budget and could wrongly evict a later rep (the HashSet path used
        // to dedup for free).
        if offer.contains_key(&mime) {
            continue;
        }
        if SELECTION_MACHINERY.contains(&mime.as_str()) {
            debug!("skipping clipboard type {mime}: a selection target, never content");
            continue;
        }
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
    fn watch(&self, kinds: &[SelectionKind]) -> mpsc::UnboundedReceiver<ClipboardEvent> {
        let (tx, rx) = mpsc::unbounded_channel();
        // One in-process data-control listener covers both selections; see
        // clipboard::watch. (Was a wl-paste --watch subprocess per kind.)
        spawn_watcher(tx, kinds.to_vec(), self.max_payload);
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
    fn assemble_offer_never_spends_a_read_on_selection_machinery() {
        // Each read costs a whole Wayland connection, and these targets always
        // fail, so the cost buys nothing. Assert they are never attempted rather
        // than merely absent from the result.
        let mut attempted: Vec<String> = Vec::new();
        let (offer, total) = assemble_offer(
            [
                "TARGETS".to_string(),
                "TIMESTAMP".to_string(),
                "MULTIPLE".to_string(),
                "SAVE_TARGETS".to_string(),
                "text/plain".to_string(),
            ],
            1024,
            |mime, _| {
                attempted.push(mime.to_string());
                Ok(b"hi".to_vec())
            },
        );
        assert_eq!(attempted, vec!["text/plain"], "a selection target was read");
        assert_eq!(offer.len(), 1);
        assert_eq!(total, "text/plain".len() + 2);
    }

    #[test]
    fn assemble_offer_still_attempts_an_unrecognised_atom() {
        // Only the known machinery is skipped: an app-specific slashless atom
        // might genuinely carry data, so it is still tried.
        let mut attempted: Vec<String> = Vec::new();
        let (offer, _) = assemble_offer(["MY_APP_DATA".to_string()], 1024, |mime, _| {
            attempted.push(mime.to_string());
            Ok(b"payload".to_vec())
        });
        assert_eq!(attempted, vec!["MY_APP_DATA"]);
        assert!(offer.contains_key("MY_APP_DATA"));
    }

    #[test]
    fn assemble_offer_dedups_a_doubly_advertised_type() {
        // A type advertised twice (get_mime_types_ordered is a Vec with no
        // dedup) must be read and counted ONCE — otherwise its bytes are
        // double-charged to the budget and can wrongly evict a later rep.
        let types = vec!["a/x".into(), "a/x".into(), "b/x".into()];
        let mut reads = 0;
        let (offer, _) = assemble_offer(types, 50, |_m, _b| {
            reads += 1;
            Ok(vec![0u8; 20]) // mime(3) + 20 = 23 per rep; two fit in 50, three don't
        });
        assert!(
            offer.contains_key("a/x") && offer.contains_key("b/x"),
            "the duplicate must not double-count and evict b/x"
        );
        assert_eq!(reads, 2, "the duplicate type should not be read twice");
    }

    #[test]
    fn assemble_offer_preserves_advertised_order() {
        // Types are read and kept in the order the compositor advertised them
        // (preference order, richest first), not alphabetized.
        let types = vec!["text/html".into(), "text/plain".into(), "image/png".into()];
        let (offer, _) = assemble_offer(types, 1024, |_m, _b| Ok(vec![1u8, 2, 3]));
        assert_eq!(
            offer.keys().map(String::as_str).collect::<Vec<_>>(),
            ["text/html", "text/plain", "image/png"]
        );
    }

    #[test]
    fn assemble_offer_truncation_follows_advertised_order() {
        // Over budget, the earlier-advertised (more-preferred) rep is the one
        // that survives — not whichever sorts first alphabetically.
        let types = vec!["z/pref".into(), "a/other".into()];
        let (offer, _) = assemble_offer(types, 50, |_m, _b| Ok(vec![0u8; 40]));
        assert!(
            offer.contains_key("z/pref") && !offer.contains_key("a/other"),
            "the first-advertised rep should win the budget"
        );
    }
}
