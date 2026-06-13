use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

/// All MIME representations of one clipboard state. BTreeMap keeps keys
/// sorted, which makes content_hash deterministic.
pub type Offer = BTreeMap<String, Vec<u8>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SelectionKind {
    Clipboard,
    Primary,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Message {
    /// First message on every connection: announces the sender's node ID.
    Hello { node_id: Uuid },
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
}

/// BLAKE3 over the sorted (mime, bytes) pairs, length-prefixed to avoid
/// boundary ambiguity.
pub fn content_hash(offer: &Offer) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    for (mime, data) in offer {
        h.update(&(mime.len() as u64).to_le_bytes());
        h.update(mime.as_bytes());
        h.update(&(data.len() as u64).to_le_bytes());
        h.update(data);
    }
    *h.finalize().as_bytes()
}

/// Compact `mime=bytes, mime=bytes` rendering of an offer for log lines.
/// Keys are already sorted (BTreeMap), so the output is stable. Build it
/// only inside an enabled log statement — it allocates per call.
pub fn describe_offer(offer: &Offer) -> String {
    offer
        .iter()
        .map(|(mime, data)| format!("{mime}={}", data.len()))
        .collect::<Vec<_>>()
        .join(", ")
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
        // BTreeMap sorts keys, so insertion order must not matter
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
    fn describe_offer_lists_mimes_and_sizes_in_sorted_order() {
        // BTreeMap iterates sorted, so image/png precedes text/plain
        let o = offer(&[("text/plain", b"hi"), ("image/png", b"\x89PNG")]);
        assert_eq!(describe_offer(&o), "image/png=4, text/plain=2");
        assert_eq!(describe_offer(&Offer::new()), "");
    }
}
