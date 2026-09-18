//! The mesh-current content record, and the history every change to it feeds.
//!
//! This module exists to make remembering **structural**. [`Settled`] owns the
//! per-selection record privately, so `SyncEngine` cannot reach the map: the
//! only way to say "this is now the content of this selection" is [`set`],
//! which takes the *content* and derives the [`ContentState`] from it. A new
//! settling path therefore cannot forget to offer its content to the history,
//! and cannot record a hash that disagrees with the content it names.
//!
//! That is the treatment `ClipboardIo` gives echo suppression and `Hashed`
//! gives stale hashes: unrepresentable rather than discouraged. The failure
//! mode it forecloses is quiet — a sixth settling site added a year from now
//! that updates `current` and not the history leaves a clipboard the user
//! demonstrably had and cannot find, with nothing logged and no test failing.
//!
//! [`set`]: Settled::set

use crate::protocol::{
    is_text, Hashed, HistoryEntry, HistoryMiss, Offer, SelectionKind, Version, TEXT_PLAIN,
};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use tracing::debug;
use uuid::Uuid;

/// How many characters of preview text a listing row carries.
const PREVIEW_CHARS: usize = 60;

/// What this node believes is the mesh-current content of one selection.
/// One record so the hash and the ordering stamp can never describe different
/// contents.
#[derive(Clone, Copy)]
pub(super) struct ContentState {
    pub(super) hash: [u8; 32],
    /// Orders this content against every other; see [`Version`].
    pub(super) version: Version,
}

impl ContentState {
    /// True if `v` strictly supersedes this state's order.
    pub(super) fn superseded_by(&self, v: Version) -> bool {
        v > self.version
    }
}

/// One clipboard state this node held.
struct Entry {
    /// Shared, never copied: the same `Arc<Offer>` the engine broadcast, applied
    /// or wrote. Remembering a copy costs a refcount — and that refcount is also
    /// what keeps the payload alive, which is exactly what the two caps bound.
    content: Hashed,
    kind: SelectionKind,
    recorded_ms: u64,
    /// Cached size, so eviction never re-walks the offer.
    size: usize,
}

/// The bounded ring of remembered clipboard states, newest at the front.
struct History {
    entries: VecDeque<Entry>,
    bytes: usize,
    max_entries: usize,
    max_bytes: usize,
}

impl History {
    fn enabled(&self) -> bool {
        self.max_entries > 0
    }

    /// Remember `content`, if it is a state worth remembering.
    fn record(&mut self, kind: SelectionKind, content: &Hashed, now_ms: u64) {
        if !self.enabled() {
            return;
        }
        // Settling again on the content already at the front is not a new state.
        // Without this, a reconnect resync — which lands in
        // `apply_inbound_clip`'s "already our current content" branch once per
        // reconnecting peer — would refresh the newest entry's age on every
        // duplicate, so a flapping link would keep rewriting a timestamp that
        // describes a copy the user made an hour ago.
        if self
            .entries
            .front()
            .is_some_and(|e| e.content.hash() == content.hash())
        {
            return;
        }
        let size = offer_size(content.offer());
        // Bigger than the whole budget: refuse it outright rather than pushing
        // it and then evicting every other entry to make room for something that
        // cannot fit anyway. One `if` here is what lets the eviction loop below
        // stay a plain loop with no "except the one I just added" guard.
        if size > self.max_bytes {
            debug!(
                "not remembering a {size}-byte {kind:?} clipboard: larger than the whole history budget"
            );
            return;
        }
        // Move-to-front on a re-copy: one entry per distinct content, re-stamped
        // with the new time and selection. Keeping the old timestamp would sort a
        // just-re-copied item as old, which defeats moving it; keeping the old
        // selection would send a later restore to the wrong one.
        if let Some(pos) = self
            .entries
            .iter()
            .position(|e| e.content.hash() == content.hash())
        {
            let old = self.entries.remove(pos).expect("position came from iter");
            self.bytes -= old.size;
        }
        self.entries.push_front(Entry {
            content: content.clone(),
            kind,
            recorded_ms: now_ms,
            size,
        });
        self.bytes += size;
        while self.entries.len() > self.max_entries || self.bytes > self.max_bytes {
            let dropped = self
                .entries
                .pop_back()
                .expect("a non-empty history is over one of its caps");
            self.bytes -= dropped.size;
        }
    }

    /// Every remembered state, newest first, with its age.
    ///
    /// Handed out as content rather than as finished rows because the rows have
    /// to be built behind the MIME rules, which live under another lock and are
    /// reached on the blocking pool — so the summarizing happens there, out of
    /// this lock. `Hashed` is shared, so this moves refcounts, not payloads.
    fn entries(&self, now_ms: u64) -> Vec<(SelectionKind, u64, Hashed)> {
        self.entries
            .iter()
            .map(|e| {
                (
                    e.kind,
                    now_ms.saturating_sub(e.recorded_ms),
                    e.content.clone(),
                )
            })
            .collect()
    }

    /// The entry whose hex id starts with `id`.
    fn find(&self, id: &str) -> Result<(SelectionKind, Hashed), HistoryMiss> {
        if !self.enabled() {
            return Err(HistoryMiss::Disabled);
        }
        if self.entries.is_empty() {
            return Err(HistoryMiss::Empty);
        }
        if id.chars().any(|c| !c.is_ascii_hexdigit()) {
            return Err(HistoryMiss::NotHex);
        }
        let wanted = id.to_ascii_lowercase();
        let mut matches = self
            .entries
            .iter()
            .filter(|e| hex(&e.content.hash()).starts_with(&wanted));
        let Some(first) = matches.next() else {
            return Err(HistoryMiss::NoSuchEntry);
        };
        // A prefix naming several entries must not be resolved by picking one.
        // Choosing silently is the exact failure ids exist to prevent: the user
        // restores something they never saw, and nothing says so.
        let extra = matches.count();
        if extra > 0 {
            return Err(HistoryMiss::Ambiguous { matches: extra + 1 });
        }
        Ok((first.kind, first.content.clone()))
    }
}

/// The mesh-current content record plus the history it feeds.
pub(super) struct Settled {
    current: Mutex<HashMap<SelectionKind, ContentState>>,
    history: Mutex<History>,
}

impl Settled {
    pub(super) fn new(max_entries: usize, max_bytes: usize) -> Settled {
        Settled {
            current: Mutex::new(HashMap::new()),
            history: Mutex::new(History {
                entries: VecDeque::new(),
                bytes: 0,
                max_entries,
                max_bytes,
            }),
        }
    }

    pub(super) fn state(&self, kind: SelectionKind) -> Option<ContentState> {
        self.current.lock().unwrap().get(&kind).copied()
    }

    /// `content` is now the mesh-current content of `kind`: record the state and
    /// remember the content. The only way to advance the record.
    pub(super) fn set(&self, kind: SelectionKind, content: &Hashed, version: Version, now_ms: u64) {
        self.current.lock().unwrap().insert(
            kind,
            ContentState {
                hash: content.hash(),
                version,
            },
        );
        self.history.lock().unwrap().record(kind, content, now_ms);
    }

    /// Adopt a newer `(stamp, origin)` for content this node already holds.
    ///
    /// Takes no content because there is none to take: the hash is unchanged, so
    /// this changes only how the same content orders against a future update.
    /// That is why it may skip the history without weakening [`set`]'s
    /// guarantee — nothing new became current here.
    pub(super) fn reorder(&self, kind: SelectionKind, version: Version) {
        if let Some(state) = self.current.lock().unwrap().get_mut(&kind) {
            state.version = version;
        }
    }

    /// Adopt the clipboard that already existed at startup, at stamp 0.
    ///
    /// Keeps an existing record that already names this same content, whose
    /// version may have been raised above 0 by an inbound apply that landed
    /// between the subscribe and this event; re-seeding it at 0 would throw that
    /// away. The content is remembered either way — "inert" in `adopt_restored`
    /// means it does not propagate, not that it is forgotten, and the clipboard
    /// a user finds at startup is the one they are most likely to want back
    /// after copying over it.
    pub(super) fn adopt(&self, kind: SelectionKind, content: &Hashed, origin: Uuid, now_ms: u64) {
        {
            let mut current = self.current.lock().unwrap();
            if current.get(&kind).map(|s| s.hash) != Some(content.hash()) {
                current.insert(
                    kind,
                    ContentState {
                        hash: content.hash(),
                        version: Version::new(0, origin),
                    },
                );
            }
        }
        self.history.lock().unwrap().record(kind, content, now_ms);
    }

    /// Remember content that became this host's clipboard without becoming its
    /// *mesh-current* content — a local copy on a node that does not send.
    ///
    /// Deliberately cannot touch the record: advancing it from content this node
    /// never put on the mesh would make a peer's genuinely newer clip look older
    /// here and stop it being applied, on the very node whose whole job is to
    /// receive.
    pub(super) fn remember(&self, kind: SelectionKind, content: &Hashed, now_ms: u64) {
        self.history.lock().unwrap().record(kind, content, now_ms);
    }

    /// The remembered states to summarize, newest first.
    pub(super) fn entries(
        &self,
        now_ms: u64,
    ) -> Result<Vec<(SelectionKind, u64, Hashed)>, HistoryMiss> {
        let history = self.history.lock().unwrap();
        if !history.enabled() {
            return Err(HistoryMiss::Disabled);
        }
        let entries = history.entries(now_ms);
        if entries.is_empty() {
            return Err(HistoryMiss::Empty);
        }
        Ok(entries)
    }

    pub(super) fn find(&self, id: &str) -> Result<(SelectionKind, Hashed), HistoryMiss> {
        self.history.lock().unwrap().find(id)
    }
}

/// One listing row, built from the representations that pass `allows`.
///
/// The filter is applied *here*, not left to the caller, because a row reports
/// three things derived from the same set — its size, its type names and its
/// preview — and computing any of them over representations the node would
/// refuse to hand over is how a listing ends up advertising, and previewing,
/// content that `history get` and `--paste` both decline. `None` when nothing
/// survives: a row nobody can fetch or restore is worse than no row.
pub(super) fn summarize(
    kind: SelectionKind,
    age_ms: u64,
    content: &Hashed,
    allows: impl Fn(&str, usize) -> bool,
) -> Option<HistoryEntry> {
    let types: Vec<(String, u64)> = content
        .offer()
        .iter()
        .filter(|(mime, data)| allows(mime, data.len()))
        .map(|(mime, data)| (mime.clone(), data.len() as u64))
        .collect();
    if types.is_empty() {
        return None;
    }
    Some(HistoryEntry {
        hash: content.hash(),
        kind,
        age_ms,
        bytes: types.iter().map(|(_, n)| n).sum(),
        preview: preview_of(content.offer(), &allows),
        types,
    })
}

/// Lowercase hex of a content hash — the full id a short one is a prefix of.
pub(super) fn hex(hash: &[u8; 32]) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

/// Total bytes of an offer's representations.
fn offer_size(offer: &Offer) -> usize {
    offer.values().map(Vec::len).sum()
}

/// A one-line, terminal-safe preview of an offer's text, or `None` when nothing
/// in it is textual.
///
/// Rendered on the **node**, for two reasons that both matter. A listing has to
/// be bounded on the wire, so a 30 MB image's row costs a few hundred bytes
/// rather than the image. And clipboard content is arbitrary bytes about to be
/// written to a terminal: an escape sequence in a copied string must not be able
/// to repaint the screen or move the cursor, and a bidi override must not be
/// able to reorder what the user reads before they decide to restore it.
fn preview_of(offer: &Offer, allows: &impl Fn(&str, usize) -> bool) -> Option<String> {
    let (_, data) = preview_source(offer, allows)?;
    // Decode a bounded prefix, not the representation. A `text/plain` entry can
    // be megabytes, and this runs per row per listing — validating the whole
    // payload to show sixty characters of it would make `history list` scan the
    // entire history. `PREVIEW_CHARS` characters need at most four bytes each,
    // and the slack beyond that means a character split by the cut lands past
    // the sixtieth and is dropped by the truncation below rather than showing as
    // a replacement character.
    let bounded = &data[..data.len().min(PREVIEW_CHARS * 4 + 4)];
    let text = String::from_utf8_lossy(bounded);
    let mut out = String::new();
    let mut pending_space = false;
    let mut truncated = false;
    for c in text.chars() {
        // Controls (including newlines and ESC) and the bidi/format characters
        // that reorder or hide text collapse to whitespace rather than reaching
        // the terminal.
        let c = if c.is_control() || is_bidi_control(c) {
            ' '
        } else {
            c
        };
        if c.is_whitespace() {
            pending_space = !out.is_empty();
            continue;
        }
        if out.chars().count() >= PREVIEW_CHARS {
            truncated = true;
            break;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        out.push(c);
    }
    if truncated {
        out.push('…');
    }
    (!out.is_empty()).then_some(out)
}

/// The representation a preview is built from: the `text/plain` variants
/// richest-first, then any other `text/*`.
///
/// Deliberately the same preference order `paste::select_type` uses, so the
/// preview shows what a paste of that same entry would print. Two orders would
/// let a listing advertise one representation and a restore hand back another.
fn preview_source<'a>(
    offer: &'a Offer,
    allows: &impl Fn(&str, usize) -> bool,
) -> Option<(&'a str, &'a [u8])> {
    let servable = |k: &String, v: &Vec<u8>| allows(k, v.len());
    TEXT_PLAIN
        .iter()
        .find_map(|want| {
            offer
                .iter()
                .find(|(k, v)| k.eq_ignore_ascii_case(want) && servable(k, v))
                .map(|(k, v)| (k.as_str(), v.as_slice()))
        })
        .or_else(|| {
            offer
                .iter()
                .find(|(k, v)| is_text(k) && servable(k, v))
                .map(|(k, v)| (k.as_str(), v.as_slice()))
        })
}

/// The bidi and invisible-format characters that can reorder or hide rendered
/// text. `char::is_control` does not cover them — they are `Cf`, not `Cc`.
fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::test_support::{offer, text_offer};

    const CLIP: SelectionKind = SelectionKind::Clipboard;
    const SEL: SelectionKind = SelectionKind::Selection;

    fn settled() -> Settled {
        Settled::new(50, 64 * 1024)
    }

    /// The listing as a node with permissive rules would render it. The
    /// filtering itself is the engine's to supply, and is tested there.
    fn list(s: &Settled, now: u64) -> Result<Vec<HistoryEntry>, HistoryMiss> {
        Ok(s.entries(now)?
            .into_iter()
            .filter_map(|(kind, age, content)| summarize(kind, age, &content, |_, _| true))
            .collect())
    }

    /// The ids a listing shows, newest first.
    fn ids(s: &Settled, now: u64) -> Vec<String> {
        list(s, now)
            .unwrap()
            .iter()
            .map(|e| hex(&e.hash)[..8].to_string())
            .collect()
    }

    fn id_of(text: &str) -> String {
        hex(&Hashed::new(text_offer(text)).hash())
    }

    #[test]
    fn re_copying_content_moves_it_to_the_front_instead_of_duplicating_it() {
        let s = settled();
        for (i, t) in ["a", "b", "c"].iter().enumerate() {
            s.remember(CLIP, &Hashed::new(text_offer(t)), i as u64);
        }
        // Re-copy "a" from the middle of the ring.
        s.remember(SEL, &Hashed::new(text_offer("a")), 100);
        let listed = list(&s, 100).unwrap();
        assert_eq!(listed.len(), 3, "the re-copy duplicated an entry");
        assert_eq!(hex(&listed[0].hash), id_of("a"));
        assert_eq!(listed[0].age_ms, 0, "the re-copy kept the old timestamp");
        assert_eq!(
            listed[0].kind, SEL,
            "a restore of this entry would go to the selection it was last copied from"
        );
    }

    #[test]
    fn settling_on_content_already_at_the_front_is_not_a_new_state() {
        // A reconnect resync re-settles the current content once per peer. Each
        // must leave the newest entry's age describing when the user copied it.
        let s = settled();
        s.remember(CLIP, &Hashed::new(text_offer("a")), 0);
        s.remember(CLIP, &Hashed::new(text_offer("a")), 9_000);
        assert_eq!(list(&s, 9_000).unwrap()[0].age_ms, 9_000);
    }

    #[test]
    fn the_oldest_entry_is_dropped_when_the_entry_cap_is_reached() {
        let s = Settled::new(2, 64 * 1024);
        for (i, t) in ["a", "b", "c"].iter().enumerate() {
            s.remember(CLIP, &Hashed::new(text_offer(t)), i as u64);
        }
        assert_eq!(ids(&s, 9), vec![&id_of("c")[..8], &id_of("b")[..8]]);
    }

    #[test]
    fn the_oldest_entries_are_dropped_when_the_byte_cap_is_reached() {
        // Room for two 100-byte entries, not three.
        let s = Settled::new(50, 250);
        let big = |c: char| Hashed::new(offer(&[("text/plain", &[c as u8; 100])]));
        for (i, c) in ['a', 'b', 'c'].iter().enumerate() {
            s.remember(CLIP, &big(*c), i as u64);
        }
        assert_eq!(list(&s, 9).unwrap().len(), 2);
        // And a move-to-front must subtract before it adds, or the running total
        // double-counts and the ring shrinks on every re-copy.
        s.remember(CLIP, &big('b'), 10);
        assert_eq!(
            list(&s, 10).unwrap().len(),
            2,
            "the byte total double-counted"
        );
    }

    #[test]
    fn an_offer_larger_than_the_whole_budget_is_not_recorded() {
        let s = Settled::new(50, 100);
        s.remember(CLIP, &Hashed::new(text_offer("keep me")), 0);
        s.remember(
            CLIP,
            &Hashed::new(offer(&[("image/png", &vec![0u8; 500])])),
            1,
        );
        // It must neither be stored nor flush the entries it cannot fit beside.
        let listed = list(&s, 1).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(hex(&listed[0].hash), id_of("keep me"));
    }

    #[test]
    fn a_zero_entry_cap_records_nothing_and_answers_disabled() {
        let s = Settled::new(0, 64 * 1024);
        s.remember(CLIP, &Hashed::new(text_offer("a")), 0);
        assert_eq!(list(&s, 0), Err(HistoryMiss::Disabled));
        assert_eq!(s.find("00"), Err(HistoryMiss::Disabled));
    }

    #[test]
    fn an_empty_history_is_distinguished_from_a_disabled_one() {
        let s = settled();
        assert_eq!(list(&s, 0), Err(HistoryMiss::Empty));
        assert_eq!(s.find("00"), Err(HistoryMiss::Empty));
    }

    #[test]
    fn a_lookup_distinguishes_missing_from_ambiguous() {
        let s = settled();
        s.remember(CLIP, &Hashed::new(text_offer("a")), 0);
        s.remember(CLIP, &Hashed::new(text_offer("b")), 1);
        let a = id_of("a");
        assert_eq!(
            s.find(&a).unwrap().1.hash(),
            Hashed::new(text_offer("a")).hash()
        );
        assert_eq!(
            s.find(&a.to_ascii_uppercase()).unwrap().1.hash(),
            Hashed::new(text_offer("a")).hash(),
            "an id typed back in upper case must still match"
        );
        assert_eq!(s.find("ffffffffff").unwrap_err(), HistoryMiss::NoSuchEntry);
        // A typo and an evicted entry want opposite advice, so they are not the
        // same answer.
        assert_eq!(s.find("zz").unwrap_err(), HistoryMiss::NotHex);
        // The empty prefix matches everything, which is the ambiguity case with
        // nothing typed at all.
        assert_eq!(
            s.find("").unwrap_err(),
            HistoryMiss::Ambiguous { matches: 2 }
        );
    }

    #[test]
    fn the_recorded_state_always_names_the_content_it_was_given() {
        // `set` derives the hash rather than taking one, so the two cannot drift.
        let s = settled();
        let c = Hashed::new(text_offer("a"));
        s.set(CLIP, &c, Version::new(7, Uuid::nil()), 0);
        let state = s.state(CLIP).unwrap();
        assert_eq!(state.hash, c.hash());
        assert_eq!(state.version, Version::new(7, Uuid::nil()));
        assert_eq!(list(&s, 0).unwrap().len(), 1, "settling did not remember");
    }

    #[test]
    fn adopting_keeps_a_raised_version_for_content_already_recorded() {
        let s = settled();
        let c = Hashed::new(text_offer("a"));
        s.set(CLIP, &c, Version::new(42, Uuid::nil()), 0);
        s.adopt(CLIP, &c, Uuid::nil(), 1);
        assert_eq!(
            s.state(CLIP).unwrap().version,
            Version::new(42, Uuid::nil()),
            "re-seeding at stamp 0 would let a peer's older clipboard outrank ours"
        );
    }

    #[test]
    fn adopting_replaces_a_record_naming_different_content() {
        let s = settled();
        s.set(
            CLIP,
            &Hashed::new(text_offer("gone")),
            Version::new(42, Uuid::nil()),
            0,
        );
        let now = Hashed::new(text_offer("on the clipboard"));
        s.adopt(CLIP, &now, Uuid::nil(), 1);
        assert_eq!(s.state(CLIP).unwrap().hash, now.hash());
        assert_eq!(s.state(CLIP).unwrap().version.stamp, 0);
    }

    #[test]
    fn reorder_changes_the_ordering_without_adding_an_entry() {
        let s = settled();
        let c = Hashed::new(text_offer("a"));
        s.set(CLIP, &c, Version::new(1, Uuid::nil()), 0);
        s.reorder(CLIP, Version::new(9, Uuid::nil()));
        assert_eq!(s.state(CLIP).unwrap().version.stamp, 9);
        assert_eq!(s.state(CLIP).unwrap().hash, c.hash());
        assert_eq!(list(&s, 0).unwrap().len(), 1);
    }

    #[test]
    fn remembering_never_advances_the_mesh_current_record() {
        // A receive-only node's local copy must not outrank a peer's newer clip.
        let s = settled();
        s.remember(CLIP, &Hashed::new(text_offer("local")), 0);
        assert!(s.state(CLIP).is_none());
    }

    #[test]
    fn a_preview_is_one_line_and_free_of_control_and_bidi_characters() {
        let s = settled();
        s.remember(
            CLIP,
            &Hashed::new(text_offer("first\nsecond\x1b[2Jthird\u{202e}reversed")),
            0,
        );
        let preview = list(&s, 0).unwrap()[0].preview.clone().unwrap();
        assert!(!preview.contains('\n'), "got: {preview:?}");
        assert!(!preview.contains('\x1b'), "got: {preview:?}");
        assert!(!preview.contains('\u{202e}'), "got: {preview:?}");
        assert_eq!(preview, "first second [2Jthird reversed");
    }

    #[test]
    fn a_long_preview_is_truncated_with_an_ellipsis() {
        let s = settled();
        s.remember(CLIP, &Hashed::new(text_offer(&"x".repeat(200))), 0);
        let preview = list(&s, 0).unwrap()[0].preview.clone().unwrap();
        assert_eq!(preview.chars().count(), PREVIEW_CHARS + 1);
        assert!(preview.ends_with('…'));
    }

    /// The preview decodes only a bounded prefix, so a multi-byte character
    /// straddling the cut must not surface as a replacement character — and a
    /// text made entirely of them must still fill the column.
    #[test]
    fn a_bounded_decode_does_not_leave_a_split_character_in_the_preview() {
        let s = settled();
        s.remember(CLIP, &Hashed::new(text_offer(&"é".repeat(500))), 0);
        let preview = list(&s, 0).unwrap()[0].preview.clone().unwrap();
        assert_eq!(preview.chars().count(), PREVIEW_CHARS + 1);
        assert!(!preview.contains('\u{fffd}'), "got: {preview:?}");
        assert!(preview.starts_with("éé"), "got: {preview:?}");
    }

    #[test]
    fn a_preview_shows_what_a_paste_of_the_same_entry_would_print() {
        let s = settled();
        s.remember(
            CLIP,
            &Hashed::new(offer(&[
                ("text/html", b"<b>markup</b>"),
                ("text/plain", b"plain"),
                ("text/plain;charset=utf-8", b"utf8"),
            ])),
            0,
        );
        assert_eq!(list(&s, 0).unwrap()[0].preview.as_deref(), Some("utf8"));
    }

    #[test]
    fn an_entry_with_no_text_representation_has_no_preview() {
        let s = settled();
        s.remember(CLIP, &Hashed::new(offer(&[("image/png", b"\x89PNG")])), 0);
        let row = list(&s, 0).unwrap().remove(0);
        assert_eq!(row.preview, None);
        assert_eq!(row.types, vec![("image/png".to_string(), 4)]);
        assert_eq!(row.bytes, 4);
    }
}
