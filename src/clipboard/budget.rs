//! The per-representation budget policy every backend's offer assembly runs
//! on: dedup, machinery skipping, and the greedy advertise-order byte budget.
//!
//! One type, because the Wayland backend assembles its offer in a blocking
//! loop and the Mutter backend in an async one, and the decision "read this
//! type, with this many bytes left; keep it or not" must be the same in both.
//! Neither loop owns the policy; they only drive it.
//!
//! # Why this budget is not `cap_to_payload_size`
//!
//! Both spend `max_payload_size`, but they answer different questions with
//! different information, and the duplication cannot be removed:
//!
//! - Here, sizes are unknowable until a representation has been read, so the
//!   only possible strategy is streaming and greedy: take them in advertise
//!   order until the budget runs out. `cap_to_payload_size` runs afterwards with
//!   every size in hand and can therefore choose smallest-first, which fits more
//!   representations. Neither strategy can be used at the other's layer.
//! - This layer also cannot pre-filter by the MIME rules to avoid spending
//!   budget on a representation that will later be denied. The rules govern what
//!   leaves the host, not what the user may paste locally: `Stages::OWN` and
//!   `Stages::MIRROR` deliberately re-offer denied representations to the local
//!   selections. Filtering here would strip them before those pipelines ever
//!   saw them. (Tried; `both_directions_no_redundant_write_with_denied_rep`
//!   catches it.)
//!
//! The residual wart is real but small: a large representation advertised early
//! can consume budget that a later one then can't have, even if the rules would
//! have dropped the first. Raising `max_payload_size` is the user-facing fix.

use crate::clipboard::atoms;
use crate::protocol::{human_bytes, Offer};
use tracing::{debug, warn};

/// An offer under construction, with the bytes still allowed to enter it.
///
/// Types are taken in the order they are offered to it (the compositor's
/// advertise order, richest first), which the offer then preserves end-to-end.
/// When the budget can't fit everything, the earlier-advertised representations
/// survive.
pub(crate) struct OfferBudget {
    max: usize,
    total: usize,
    offer: Offer,
}

impl OfferBudget {
    pub(crate) fn new(max: usize) -> OfferBudget {
        OfferBudget {
            max,
            total: 0,
            offer: Offer::new(),
        }
    }

    /// Whether `mime` is worth reading, and with how many bytes of budget.
    ///
    /// `None` means don't: it is already in the offer (a type advertised twice
    /// must be read and counted once, or its bytes are double-charged and could
    /// wrongly evict a later representation), or it is selection machinery that
    /// no source ever serves as data. `Some(budget)`: read up to `budget + 1`
    /// bytes, so an overflow is detectable by [`accept`](OfferBudget::accept).
    pub(crate) fn plan(&self, mime: &str) -> Option<usize> {
        if self.offer.contains_key(mime) {
            return None;
        }
        if atoms::is_machinery(mime) {
            debug!("skipping clipboard type {mime}: a selection target, never content");
            return None;
        }
        // saturating_sub: total never exceeds max here, but guard against a
        // future change turning this into a panic on attacker-influenced input.
        Some(self.max.saturating_sub(self.total))
    }

    /// Record a representation that was read. `false` when it doesn't fit what
    /// is left of the budget: it is dropped, logged, and the rest of the offer
    /// is unaffected — a small syncable payload alongside a giant image (which
    /// can never sync) still propagates.
    pub(crate) fn accept(&mut self, mime: String, data: Vec<u8>) -> bool {
        let budget = self.max.saturating_sub(self.total);
        if mime.len() + data.len() > budget {
            // warn, not debug, so the user can see why a large representation
            // isn't syncing. The read stopped at the budget, so the true size
            // is only known to exceed it — raising max_payload_size is the fix.
            warn!(
                "skipping clipboard type {mime}: it doesn't fit the remaining {} \
                 of the {} max_payload_size budget (raise max_payload_size to sync large images)",
                human_bytes(budget),
                human_bytes(self.max)
            );
            return false;
        }
        debug!("read clipboard type {mime} ({})", human_bytes(data.len()));
        self.total += mime.len() + data.len();
        self.offer.insert(mime, data);
        true
    }

    /// Log a representation that could not be read. A content type that won't
    /// read is real data loss worth a warn; a pseudo-target erroring on read is
    /// expected, so it stays quiet.
    pub(crate) fn skip_unreadable(mime: &str, err: &anyhow::Error) {
        if atoms::is_content(mime) {
            warn!("skipping clipboard type {mime}: can't read it ({err:#})");
        } else {
            debug!("skipping clipboard type {mime}: not readable content ({err:#})");
        }
    }

    /// The assembled offer and its total byte size (types and data).
    pub(crate) fn finish(self) -> (Offer, usize) {
        (self.offer, self.total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_declines_a_duplicate_and_machinery_and_budgets_the_rest() {
        let mut b = OfferBudget::new(100);
        assert_eq!(b.plan("TARGETS"), None, "machinery is never read");
        assert_eq!(b.plan("text/plain"), Some(100));
        assert!(b.accept("text/plain".into(), vec![0; 10]));
        assert_eq!(b.plan("text/plain"), None, "already in the offer");
        assert_eq!(b.plan("image/png"), Some(100 - "text/plain".len() - 10));
    }

    #[test]
    fn accept_refuses_what_does_not_fit_and_charges_what_does() {
        let mut b = OfferBudget::new(20);
        assert!(!b.accept("a/x".into(), vec![0; 18]), "3 + 18 > 20");
        assert!(b.accept("a/x".into(), vec![0; 17]), "3 + 17 == 20 fits");
        assert_eq!(b.plan("b/x"), Some(0), "nothing left, but still asked");
        let (offer, total) = b.finish();
        assert_eq!(offer.len(), 1);
        assert_eq!(total, 20);
    }
}
