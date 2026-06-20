use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Wire protocol version. Bumped whenever the on-wire message format changes.
/// bincode is not self-describing, so mismatched versions cannot interoperate —
/// all nodes must run a compatible build. Logged at startup for diagnosis.
pub const PROTOCOL_VERSION: u32 = 4;

/// All MIME representations of one clipboard state, in the source compositor's
/// advertise order (preference order — richest first), which `IndexMap`
/// preserves end-to-end so a remote paster sees the same order. `content_hash`
/// sorts a copy internally, so identity/dedup stays order-independent.
pub type Offer = IndexMap<String, Vec<u8>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SelectionKind {
    Clipboard,
    Selection,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Message {
    /// First message on every connection: announces the sender's node ID and
    /// the wire protocol version it speaks. A peer whose version differs is
    /// refused during the handshake — bincode is not self-describing, so
    /// mismatched builds would otherwise just fail to decode each other's
    /// messages and drop the connection with a corruption-like error.
    Hello {
        node_id: Uuid,
        protocol_version: u32,
    },
    /// A clipboard update.
    Clip {
        kind: SelectionKind,
        hash: [u8; 32],
        offer: Offer,
        /// Hybrid logical stamp at the originating node: the max of its
        /// wall-clock ms and the highest stamp it has seen. Higher wins;
        /// `origin` breaks ties. Used to order every update (live and
        /// reconnect resync) by the same rule.
        stamp: u64,
        /// Node ID that created this content; deterministic tiebreaker
        /// when two updates carry the same stamp.
        origin: Uuid,
    },
    /// The full MIME-rules file, shared across the mesh under whole-file
    /// last-writer-wins. `body` is the entire file text (including the
    /// `# clipmesh-version:` header line); `(stamp, origin)` order it the same
    /// way a clipboard update is ordered.
    Rules {
        stamp: u64,
        origin: Uuid,
        body: String,
    },
}

/// BLAKE3 over the (mime, bytes) pairs, length-prefixed to avoid boundary
/// ambiguity. The pairs are sorted by MIME for hashing only — the `Offer` itself
/// keeps its advertise order — so two offers with the same content but different
/// order hash equal. This keeps echo suppression robust: when we write an offer
/// and the compositor hands the types back in a different order, the read-back
/// still matches and doesn't trigger a rebroadcast loop.
pub fn content_hash(offer: &Offer) -> [u8; 32] {
    let mut pairs: Vec<(&String, &Vec<u8>)> = offer.iter().collect();
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    let mut h = blake3::Hasher::new();
    for (mime, data) in pairs {
        h.update(&(mime.len() as u64).to_le_bytes());
        h.update(mime.as_bytes());
        h.update(&(data.len() as u64).to_le_bytes());
        h.update(data);
    }
    *h.finalize().as_bytes()
}

/// Compact `mime=size, mime=size` rendering of an offer for log lines, sizes
/// in human units, in the offer's advertise (insertion) order. Build it only
/// inside an enabled log statement — it allocates per call.
pub fn describe_offer(offer: &Offer) -> String {
    offer
        .iter()
        .map(|(mime, data)| format!("{mime}={}", human_bytes(data.len())))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Render a byte count in human-friendly units: "269 B", "70.4 KiB", "8.0 MiB".
pub fn human_bytes(n: usize) -> String {
    const KIB: f64 = 1024.0;
    if n < 1024 {
        return format!("{n} B");
    }
    let units = ["KiB", "MiB", "GiB", "TiB"];
    let mut value = n as f64 / KIB;
    let mut unit = 0;
    // Advance while the value, rounded to the one decimal we display, would
    // reach the next unit — so e.g. 1 MiB - 1 shows "1.0 MiB", not "1024.0 KiB".
    while unit + 1 < units.len() && (value * 10.0).round() / 10.0 >= KIB {
        value /= KIB;
        unit += 1;
    }
    format!("{value:.1} {}", units[unit])
}

pub fn encode(msg: &Message) -> Vec<u8> {
    bincode::serialize(msg).expect("message serialization cannot fail")
}

pub fn decode(buf: &[u8]) -> anyhow::Result<Message> {
    Ok(bincode::deserialize(buf)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn offer(pairs: &[(&str, &[u8])]) -> Offer {
        pairs
            .iter()
            .map(|(m, d)| (m.to_string(), d.to_vec()))
            .collect()
    }

    #[test]
    fn content_hash_is_deterministic_and_order_independent() {
        // content_hash sorts a copy of the pairs, so insertion order must not
        // matter even though the Offer (IndexMap) preserves it.
        let a = offer(&[("text/plain", b"hi"), ("text/html", b"<b>hi</b>")]);
        let b = offer(&[("text/html", b"<b>hi</b>"), ("text/plain", b"hi")]);
        assert_eq!(content_hash(&a), content_hash(&b));
    }

    #[test]
    fn content_hash_differs_for_different_content() {
        let a = offer(&[("text/plain", b"hi")]);
        let b = offer(&[("text/plain", b"ho")]);
        assert_ne!(content_hash(&a), content_hash(&b));
    }

    #[test]
    fn content_hash_is_not_confused_by_boundary_shifts() {
        // ("ab", "c") must hash differently from ("a", "bc")
        let a = offer(&[("ab", b"c")]);
        let b = offer(&[("a", b"bc")]);
        assert_ne!(content_hash(&a), content_hash(&b));
    }

    #[test]
    fn messages_round_trip_through_encode_decode() {
        let hello = Message::Hello {
            node_id: Uuid::new_v4(),
            protocol_version: PROTOCOL_VERSION,
        };
        assert_eq!(decode(&encode(&hello)).unwrap(), hello);

        let o = offer(&[("text/plain", b"payload")]);
        let clip = Message::Clip {
            kind: SelectionKind::Clipboard,
            hash: content_hash(&o),
            offer: o,
            stamp: 123,
            origin: Uuid::new_v4(),
        };
        assert_eq!(decode(&encode(&clip)).unwrap(), clip);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(decode(&[0xff; 64]).is_err());
    }

    #[test]
    fn describe_offer_lists_mimes_and_sizes_in_insertion_order() {
        // IndexMap iterates in insertion order, so the order the pairs were
        // built in is preserved (text/plain was inserted first here).
        let o = offer(&[("text/plain", b"hi"), ("image/png", b"\x89PNG")]);
        assert_eq!(describe_offer(&o), "text/plain=2 B, image/png=4 B");
        assert_eq!(describe_offer(&Offer::new()), "");
    }

    #[test]
    fn encode_decode_preserves_mime_order() {
        // A deliberately non-alphabetical order (preference order, richest
        // first) must survive the wire round-trip unchanged.
        let o = offer(&[
            ("text/html", b"<b>hi</b>"),
            ("text/plain", b"hi"),
            ("image/png", b"\x89PNG"),
        ]);
        let clip = Message::Clip {
            kind: SelectionKind::Clipboard,
            hash: content_hash(&o),
            offer: o,
            stamp: 1,
            origin: Uuid::new_v4(),
        };
        let Message::Clip { offer, .. } = decode(&encode(&clip)).unwrap() else {
            panic!("expected a Clip");
        };
        assert_eq!(
            offer.keys().map(String::as_str).collect::<Vec<_>>(),
            ["text/html", "text/plain", "image/png"]
        );
    }

    #[test]
    fn human_bytes_scales_units() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(269), "269 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(72081), "70.4 KiB");
        assert_eq!(human_bytes(8 * 1024 * 1024), "8.0 MiB");
        assert_eq!(human_bytes(1024 * 1024 * 1024), "1.0 GiB");
    }

    #[test]
    fn human_bytes_rolls_over_at_unit_boundaries() {
        // A value just under a unit must roll to the next unit when it would
        // otherwise round to "1024.0" of the smaller unit.
        assert_eq!(human_bytes(1024 * 1024 - 1), "1.0 MiB");
        assert_eq!(human_bytes(1024 * 1024 * 1024 - 1), "1.0 GiB");
    }

    #[test]
    fn rules_message_round_trips() {
        let msg = Message::Rules {
            stamp: 42,
            origin: Uuid::new_v4(),
            body: "# clipmesh-version: 42 x\nimage/png allow\n".to_string(),
        };
        assert_eq!(decode(&encode(&msg)).unwrap(), msg);
    }
}
