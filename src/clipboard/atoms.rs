//! X11/ICCCM selection-atom semantics.
//!
//! X11 exposes selections under uppercase atom names rather than MIME types, and
//! the rules about them — which atoms carry content, which are pure protocol
//! machinery, and what encoding each one declares — belong to neither layer that
//! asks. They are not an engine policy and not a Wayland detail; they are
//! properties of the X11 selection protocol. So they live here, and both
//! consumers take them from one place: `clipboard::wayland` when deciding what
//! is worth reading and what a failed read actually cost, and `sync` when
//! synthesizing a `text/plain` from a legacy atom.
//!
//! This knowledge used to be split across those two files, each with its own
//! overlapping-but-deliberately-different atom list, and a comment in one
//! existing only to explain why the other's list differed. Supporting a new
//! legacy atom meant editing two layers and re-deriving which list it belonged
//! in, with only prose to guide the choice.

use crate::protocol::Offer;

/// Legacy plain-text atoms a UTF-8 `text/plain` value can be derived from, in
/// descending order of how trustworthy their declared encoding is.
///
/// `COMPOUND_TEXT` is deliberately NOT here, even though [`is_content`] counts
/// it as content: that predicate only asks whether a failed read lost something
/// worth warning about, while this list asks whether the bytes can be turned
/// into clean UTF-8. Compound text is ISO 2022 — multi-byte, with escape
/// sequences switching character sets mid-string — so decoding it as UTF-8 or
/// latin-1 would paste the escapes as garbage. Adding it needs a real
/// compound-text decoder, not a list entry.
const PLAINTEXT: [&str; 3] = ["UTF8_STRING", "STRING", "TEXT"];

/// Text-bearing atoms that are content but are not in [`PLAINTEXT`], because
/// their bytes can't be re-encoded (see that list's note on `COMPOUND_TEXT`).
const TEXT_ONLY_CONTENT: [&str; 1] = ["COMPOUND_TEXT"];

/// ICCCM selection targets that are protocol machinery rather than content, and
/// that no source ever serves as data — reading one always fails.
///
/// Worth naming explicitly because a read is not cheap: every representation
/// costs its own Wayland connection (see `wayland::read_offer_blocking`), so
/// attempting these spends a full connect-and-roundtrip per selection just to be
/// told no. Skipping them is exactly equivalent — a failed read is dropped from
/// the offer anyway — but does not pay for the answer.
///
/// Deliberately an exact list rather than "anything `!is_content`": an
/// unrecognised slashless atom might genuinely carry data, and is still
/// attempted (its failure is logged at debug).
const MACHINERY: [&str; 7] = [
    "TARGETS",
    "TIMESTAMP",
    "MULTIPLE",
    "SAVE_TARGETS",
    "DELETE",
    "INSERT_SELECTION",
    "INSERT_PROPERTY",
];

/// Whether a failed read of this advertised type likely lost real content
/// (worth a warn) rather than an X11/XWayland pseudo-target that always errors
/// on read.
///
/// Real MIME types carry a '/'; X11 also exposes plain text under a few
/// uppercase atoms that ARE content, so those count too. Everything else
/// slashless (TARGETS, TIMESTAMP, an app's TK_* atoms, ...) is metadata.
pub fn is_content(mime: &str) -> bool {
    mime.contains('/') || PLAINTEXT.contains(&mime) || TEXT_ONLY_CONTENT.contains(&mime)
}

/// Whether this atom is pure selection machinery — never worth spending a read
/// on. See [`MACHINERY`].
pub fn is_machinery(mime: &str) -> bool {
    MACHINERY.contains(&mime)
}

/// The UTF-8 text value derivable from `offer`'s highest-priority legacy
/// plain-text atom, together with the atom it came from — or `None` when the
/// offer carries no such atom.
///
/// The atom name is returned because a caller synthesizing a representation
/// needs to place it relative to its source. It does not need to know *which*
/// atoms exist or how each declares its encoding, which is the point of this
/// living here: the engine asks for "a text value from this offer" without
/// knowing what ICCCM is.
pub fn text_value(offer: &Offer) -> Option<(&'static str, Vec<u8>)> {
    let atom = text_source(offer.keys().map(String::as_str))?;
    Some((atom, value_of(offer, atom)?))
}

/// The UTF-8 text value of one *named* legacy atom in `offer`.
///
/// [`text_value`] picks the atom and decodes it in one step, which suits a
/// caller holding only an offer. A caller that already decided which atom
/// applies — from the type names, before the read — needs the decoding half on
/// its own, and must get it from here rather than re-deriving the encoding
/// rules: which atom declares which encoding is exactly what this module exists
/// to keep in one place.
pub fn value_of(offer: &Offer, atom: &str) -> Option<Vec<u8>> {
    Some(clean(reencode(atom, offer.get(atom)?)))
}

/// The atom [`text_value`] would derive from, chosen from type *names* alone.
///
/// A caller holding only the advertised type list — deciding what is worth
/// reading, before paying for the read — needs the same priority order that
/// `text_value` applies to a full offer. Asking here rather than re-deriving it
/// is what keeps the two from disagreeing about which atom the synthesized
/// `text/plain` comes from; `text_value` is defined in terms of this.
pub fn text_source<'a>(names: impl IntoIterator<Item = &'a str>) -> Option<&'static str> {
    let names: Vec<&str> = names.into_iter().collect();
    PLAINTEXT.iter().copied().find(|atom| names.contains(atom))
}

/// Decode an atom's bytes to UTF-8 according to the encoding it declares:
/// - `UTF8_STRING` is already UTF-8 → verbatim.
/// - `STRING` is ISO-8859-1 per ICCCM → latin-1 decode.
/// - `TEXT`'s encoding is owner-defined → use it verbatim if it's valid UTF-8,
///   otherwise fall back to latin-1.
fn reencode(atom: &str, bytes: &[u8]) -> Vec<u8> {
    match atom {
        "STRING" => latin1_to_utf8(bytes),
        "TEXT" if std::str::from_utf8(bytes).is_err() => latin1_to_utf8(bytes),
        _ => bytes.to_vec(),
    }
}

/// Decode ISO-8859-1 (latin-1) bytes to UTF-8. Total and lossless: every byte
/// 0x00–0xFF maps to the Unicode scalar of the same value.
fn latin1_to_utf8(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .map(|&b| b as char)
        .collect::<String>()
        .into_bytes()
}

/// Clean a value derived from a legacy text atom for use as text/plain: drop the
/// trailing NUL(s) X11 apps often append, then a single trailing line terminator
/// (`\n` or `\r\n`, common on SELECTION line selections) so it doesn't paste as
/// a stray newline. Applied only to the derived value; the source atom keeps its
/// verbatim bytes.
fn clean(mut v: Vec<u8>) -> Vec<u8> {
    while v.last() == Some(&0) {
        v.pop();
    }
    if v.last() == Some(&b'\n') {
        v.pop();
        if v.last() == Some(&b'\r') {
            v.pop();
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::test_support::offer;

    #[test]
    fn content_types_are_mime_types_and_the_text_atoms() {
        for m in [
            "text/plain",
            "image/png",
            "STRING",
            "UTF8_STRING",
            "TEXT",
            "COMPOUND_TEXT",
        ] {
            assert!(is_content(m), "{m} should be content");
        }
        for m in ["TARGETS", "TIMESTAMP", "MULTIPLE", "TK_SOMETHING"] {
            assert!(!is_content(m), "{m} should not be content");
        }
    }

    #[test]
    fn machinery_is_an_exact_list_not_the_complement_of_content() {
        assert!(is_machinery("TARGETS"));
        // Slashless and not content, but not a known target either: still worth
        // attempting, because it might carry data.
        assert!(!is_machinery("TK_SOMETHING"));
    }

    #[test]
    fn text_value_prefers_utf8_string_over_the_weaker_atoms() {
        let o = offer(&[("TEXT", b"from-text"), ("UTF8_STRING", b"from-utf8")]);
        assert_eq!(text_value(&o), Some(("UTF8_STRING", b"from-utf8".to_vec())));
    }

    #[test]
    fn text_value_decodes_string_as_latin1() {
        // 0xE9 is é in latin-1; as UTF-8 it must become the two-byte encoding.
        let o = offer(&[("STRING", &[0xE9])]);
        assert_eq!(text_value(&o), Some(("STRING", "é".as_bytes().to_vec())));
    }

    #[test]
    fn text_value_keeps_valid_utf8_text_verbatim_and_falls_back_otherwise() {
        let o = offer(&[("TEXT", "é".as_bytes())]);
        assert_eq!(text_value(&o), Some(("TEXT", "é".as_bytes().to_vec())));
        // Not valid UTF-8, so it is read as latin-1 instead.
        let o = offer(&[("TEXT", &[0xE9])]);
        assert_eq!(text_value(&o), Some(("TEXT", "é".as_bytes().to_vec())));
    }

    #[test]
    fn text_value_strips_trailing_nuls_and_one_line_terminator() {
        assert_eq!(
            text_value(&offer(&[("UTF8_STRING", b"hi\0\0")])),
            Some(("UTF8_STRING", b"hi".to_vec()))
        );
        assert_eq!(
            text_value(&offer(&[("UTF8_STRING", b"hi\r\n")])),
            Some(("UTF8_STRING", b"hi".to_vec()))
        );
        // Only ONE terminator is stripped: a deliberate blank line survives.
        assert_eq!(
            text_value(&offer(&[("UTF8_STRING", b"hi\n\n")])),
            Some(("UTF8_STRING", b"hi\n".to_vec()))
        );
    }

    #[test]
    fn text_value_is_none_without_a_plaintext_atom() {
        assert_eq!(text_value(&offer(&[("COMPOUND_TEXT", b"x")])), None);
        assert_eq!(text_value(&offer(&[("image/png", b"x")])), None);
    }
}
