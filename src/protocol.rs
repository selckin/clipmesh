use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// Wire protocol version. Bumped whenever the on-wire message format changes.
/// bincode is not self-describing, so mismatched versions cannot interoperate —
/// all nodes must run a compatible build. Logged at startup for diagnosis.
///
/// v5: `Clip`/`Rules` carry a single `Version` instead of loose `stamp`/`origin`.
/// v6: `Hello` carries a `PeerRole`, and `--paste` asks with `Get`/`GetReply`
/// instead of scraping the connect-time resync push.
/// v7: `GetReply` answers "nothing to give" with a reason (`Unavailable`)
/// instead of a bare `Empty` that covered six distinct causes.
pub const PROTOCOL_VERSION: u32 = 7;

/// All MIME representations of one clipboard state, in the source compositor's
/// advertise order (preference order — richest first), which `IndexMap`
/// preserves end-to-end so a remote paster sees the same order. `content_hash`
/// sorts a copy internally, so identity/dedup stays order-independent.
pub type Offer = IndexMap<String, Vec<u8>>;

/// Whether an offered MIME type satisfies a requested one.
///
/// One definition because this is a **wire contract**: for `wl-paste -t <mime>`
/// the serving node narrows its read by this rule and the client then picks the
/// representation out of the reply by the same rule. With the two spelled out
/// separately, a normalization added to one side (stripping `;charset=…`,
/// trimming, Unicode folding) silently returns a representation the user didn't
/// ask for, or an offer whose only key the client then rejects as absent.
pub fn type_matches(offered: &str, requested: &str) -> bool {
    offered.eq_ignore_ascii_case(requested)
}

/// The `text/plain` representations, richest first.
///
/// One list because both ends depend on this exact order: `sync` synthesizes
/// them in it when back-filling from a legacy X11 atom, and `paste` prefers them
/// in it when picking what to print. Two copies would let a paster prefer a
/// representation the synthesizer had stopped producing.
pub const TEXT_PLAIN: [&str; 2] = ["text/plain;charset=utf-8", "text/plain"];

/// Whether `mime` is textual — the `text/*` family.
pub fn is_text(mime: &str) -> bool {
    mime.get(..5)
        .is_some_and(|p| p.eq_ignore_ascii_case("text/"))
}

/// Whether `mime` is a `text/plain` variant (`text/plain`,
/// `text/plain;charset=…`), i.e. matches the `text/plain*` glob.
pub fn is_text_plain(mime: &str) -> bool {
    mime.get(..10)
        .is_some_and(|p| p.eq_ignore_ascii_case("text/plain"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SelectionKind {
    Clipboard,
    Selection,
}

impl SelectionKind {
    /// Every selection, in the canonical order (CLIPBOARD first) that
    /// per-selection arrays are laid out in and that iteration reports.
    pub const ALL: [SelectionKind; 2] = [SelectionKind::Clipboard, SelectionKind::Selection];

    /// This selection's slot in a per-selection array laid out as [`ALL`].
    ///
    /// The `match` is exhaustive, so adding a variant is a compile error here
    /// rather than a runtime panic at the first lookup for the new kind.
    pub fn index(self) -> usize {
        match self {
            SelectionKind::Clipboard => 0,
            SelectionKind::Selection => 1,
        }
    }
}

/// The hybrid-logical-clock value that orders one piece of shared state.
///
/// Higher `stamp` wins; `origin` — the node that created the content — breaks
/// ties, so every node comparing the same pair reaches the same answer without
/// coordinating. Both clipboard updates and the shared MIME-rules file are
/// ordered by this, so the two can never order differently.
///
/// Field order is the comparison order: `derive(Ord)` compares `stamp` first,
/// then `origin`. Don't reorder them.
///
/// This type — not the two fields loose — is what crosses the wire, so the only
/// thing a receiver can write is a comparison of the whole `Version`. Splitting
/// it would let a site compare `stamp` alone, which compiles cleanly and
/// silently diverges the mesh on a tie.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Version {
    pub stamp: u64,
    pub origin: Uuid,
}

impl Version {
    pub fn new(stamp: u64, origin: Uuid) -> Self {
        Version { stamp, origin }
    }
}

/// What the far end of a connection is, announced in [`Message::Hello`].
///
/// A `Paster` is a one-shot `--paste` client, not a mesh member: it asks one
/// question and leaves. Distinguishing it is what stops every `wl-paste` from
/// costing the serving node a full connect-time resync (a rules snapshot plus a
/// live capture of every synced selection) for a peer that will never sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerRole {
    /// A clipmesh node. Participates in the mesh: resynced on connect, and a
    /// target for broadcasts.
    Peer,
    /// A `--paste` client. Registered only so its request can be answered.
    Paster,
}

/// What a [`Message::Get`] asks for.
///
/// Naming the three client modes on the wire is what lets the *node* narrow the
/// reply. Pulling a whole offer to print one representation was the other half
/// of the cost here: `-t text/plain` against a clipboard holding a 30 MB PNG
/// used to transfer the PNG too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GetWant {
    /// Every representation — the default, where the client picks by preference
    /// order and so must see them all.
    All,
    /// Only this type, matched case-insensitively (`--type`).
    One(String),
    /// No content at all, just the available type names (`--list-types`).
    TypesOnly,
}

/// Why a node has nothing to hand back.
///
/// These are the distinct outcomes the serving node's own pipeline already
/// distinguishes — it logs a different line for each — so returning the reason
/// as a value rather than a log string is what lets the *asking* side say
/// something true. Collapsing them loses real information: "the clipboard is
/// empty" is a actively misleading answer when the clipboard is full and every
/// type in it is denied by that node's MIME rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Unavailable {
    /// The node does not serve that selection at all — `sync_selection` is off
    /// for SELECTION, or `direction` makes this node receive-only.
    NotSynced,
    /// The selection genuinely holds nothing.
    Empty,
    /// Content exists but is password-manager-flagged, and `exclude_sensitive`
    /// is on. Deliberately still refused for a pull: what a push won't expose, a
    /// pull must not either.
    Sensitive,
    /// Content exists, but every representation is denied by that node's MIME
    /// rules.
    Denied,
    /// Content exists, but everything exceeds that node's `max_payload_size`.
    TooLarge,
    /// The node could not read its own clipboard — an error, or a selection
    /// owner that never answered.
    Unreadable,
}

/// The answer to a [`Message::Get`].
///
/// Every failure names its own cause. The pushed-resync design this replaced
/// could only ever time out, and its message had to list four unrelated
/// possibilities — empty clipboard, `resync_on_connect` off, `sync_selection`
/// off, or a slow transfer still in flight — because the client had never
/// actually asked a question.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GetResult {
    /// The requested representation(s), in the source's advertise order.
    Offer(Offer),
    /// The available type names, for [`GetWant::TypesOnly`].
    Types(Vec<String>),
    /// The node has content, but not the requested type.
    NotOffered { available: Vec<String> },
    /// Nothing to hand back, and why.
    Unavailable(Unavailable),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Message {
    /// First message on every connection: announces the sender's node ID, the
    /// wire protocol version it speaks, and whether it is a mesh peer or a
    /// one-shot paster. A peer whose version differs is refused during the
    /// handshake — bincode is not self-describing, so mismatched builds would
    /// otherwise just fail to decode each other's messages and drop the
    /// connection with a corruption-like error.
    Hello {
        node_id: Uuid,
        protocol_version: u32,
        role: PeerRole,
    },
    /// Ask for one selection's current content. Answered with [`Message::GetReply`].
    ///
    /// This is a *request*, which is the point: the previous `--paste` took
    /// whatever the node happened to push on connect, so it could not narrow the
    /// reply, could not be told why it got nothing, and forced the node into a
    /// full resync to produce an answer at all.
    Get { kind: SelectionKind, want: GetWant },
    /// The answer to a [`Message::Get`], echoing the `kind` asked about.
    GetReply {
        kind: SelectionKind,
        result: GetResult,
    },
    /// A clipboard update.
    Clip {
        kind: SelectionKind,
        hash: [u8; 32],
        /// Shared, not owned: this is the payload's terminal hop out of the
        /// engine, and the engine holds every planned action's content alive at
        /// once. Taking an owned `Offer` here would deep-copy the whole
        /// clipboard — up to `max_payload_size` — per broadcast. serde's `rc`
        /// feature serializes the pointee, so this is byte-identical on the wire
        /// to an owned `Offer`.
        offer: Arc<Offer>,
        /// Orders this update against every other, live or reconnect resync.
        version: Version,
    },
    /// The full MIME-rules file, shared across the mesh under whole-file
    /// last-writer-wins. `body` is the entire file text (including the
    /// `# clipmesh-version:` header line); `version` orders it the same way a
    /// clipboard update is ordered.
    Rules { version: Version, body: String },
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

/// An [`Offer`] together with its [`content_hash`], computed once at construction.
///
/// The hash *is* clipboard identity here — echo suppression, mesh dedup, the
/// bridge's drift reconcile and the LWW comparison all ask "same content?" — so
/// carrying it with the content means those comparisons never recompute it, and
/// `content_hash` has exactly one caller.
///
/// The offer is immutable behind this type, which is what makes a stale hash
/// unrepresentable: a transform that *changes* the content must build a new
/// `Hashed` (rehashing), and one that leaves it alone returns the same value,
/// carrying the hash forward for free. That turns "did this stage change
/// anything?" from a flag someone has to thread correctly into something the
/// types answer.
///
/// The offer sits behind an [`Arc`] because that immutability makes sharing
/// safe, and the engine clones a `Hashed` several times per copy event (one per
/// planned broadcast and write). Copying the payload each time would cost a full
/// duplicate of the clipboard — up to `max_payload_size` — per clone, so clones
/// bump a refcount instead.
///
/// **Terminal consumers take [`into_arc`], not [`into_offer`].** The `Arc` only
/// pays off if the *last* step keeps sharing: the engine's batch holds every
/// planned action's content alive at once, so a terminal `into_offer` finds
/// refcount > 1 and deep-copies — moving the copy rather than removing it. Both
/// ends of the wire and the clipboard write therefore carry `Arc<Offer>`, and
/// `into_offer` is left for the transform steps that genuinely need to take the
/// map apart and rebuild it.
///
/// [`into_arc`]: Hashed::into_arc
/// [`into_offer`]: Hashed::into_offer
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hashed {
    offer: Arc<Offer>,
    hash: [u8; 32],
}

impl Hashed {
    pub fn new(offer: Offer) -> Hashed {
        Hashed::from_arc(Arc::new(offer))
    }

    /// Hash content that is already shared — an offer straight off the wire,
    /// which arrives inside its own `Arc` and would otherwise be unwrapped and
    /// rewrapped for nothing.
    pub fn from_arc(offer: Arc<Offer>) -> Hashed {
        let hash = content_hash(&offer);
        Hashed { offer, hash }
    }

    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    pub fn offer(&self) -> &Offer {
        &self.offer
    }

    /// The shared offer. Always free — this is what terminal consumers (the
    /// wire, the clipboard write) take, so the payload is never copied on its
    /// way out.
    pub fn into_arc(self) -> Arc<Offer> {
        self.offer
    }

    /// Take ownership of the map to rebuild it. Free when this is the last
    /// holder, a full copy when it is still shared — so this is for the
    /// transform steps that must take the offer apart, never for handing it on.
    pub fn into_offer(self) -> Offer {
        Arc::try_unwrap(self.offer).unwrap_or_else(|shared| (*shared).clone())
    }

    pub fn is_empty(&self) -> bool {
        self.offer.is_empty()
    }
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

/// A wire-ready, already-encoded `Message`, shared by refcount.
///
/// `Message::Clip` owns its `Offer`, so handing connections a `Message` would
/// deep-copy a clipboard payload (up to `max_payload_size`, 32 MiB by default)
/// per peer and re-serialize the identical bytes in every writer task. Encoding
/// once at the fan-out point and sharing the result costs an atomic increment
/// per extra peer instead.
pub type Frame = std::sync::Arc<Vec<u8>>;

/// Encode `msg` once for delivery to one or more connections.
pub fn encode_frame(msg: &Message) -> Frame {
    std::sync::Arc::new(encode(msg))
}

pub fn decode(buf: &[u8]) -> anyhow::Result<Message> {
    Ok(bincode::deserialize(buf)?)
}

/// Offer/message builders shared by the unit tests across the crate.
///
/// Not reachable from `tests/*.rs` — those compile the library without
/// `cfg(test)` and have their own `tests/common`. Keeping these `cfg(test)`
/// keeps them out of the public API.
#[cfg(test)]
pub(crate) mod test_support {
    use super::{content_hash, Message, Offer, SelectionKind, Version};
    use std::time::Duration;
    use uuid::Uuid;

    /// How long `wait_for` polls before giving up, and how often it re-checks.
    /// One setting for the whole crate's unit tests: a flaky-timing tweak
    /// belongs here, not in per-module copies that drift apart.
    const WAIT_TIMEOUT: Duration = Duration::from_secs(5);
    const WAIT_POLL: Duration = Duration::from_millis(5);

    /// Poll `cond` until it holds, panicking after `WAIT_TIMEOUT` with `label`.
    /// The one place a unit test waits on asynchronously-driven state.
    pub(crate) async fn wait_for(label: &str, mut cond: impl FnMut() -> bool) {
        tokio::time::timeout(WAIT_TIMEOUT, async {
            while !cond() {
                tokio::time::sleep(WAIT_POLL).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {label}"));
    }

    /// An offer with the given MIME/bytes pairs, in the order given.
    pub(crate) fn offer(pairs: &[(&str, &[u8])]) -> Offer {
        pairs
            .iter()
            .map(|(m, d)| (m.to_string(), d.to_vec()))
            .collect()
    }

    /// A single-representation `text/plain` offer.
    pub(crate) fn text_offer(text: &str) -> Offer {
        offer(&[("text/plain", text.as_bytes())])
    }

    /// A `Clip` carrying `text`, stamped at the bottom of the clock so tests
    /// that care about ordering must set it explicitly.
    pub(crate) fn clip(text: &str) -> Message {
        let offer = text_offer(text);
        Message::Clip {
            kind: SelectionKind::Clipboard,
            hash: content_hash(&offer),
            offer: offer.into(),
            version: Version::new(0, Uuid::nil()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::offer;
    use super::*;
    use uuid::Uuid;

    #[test]
    fn hashed_carries_the_hash_of_its_content() {
        let o = offer(&[("text/html", b"<b>hi</b>"), ("text/plain", b"hi")]);
        let h = Hashed::new(o.clone());
        assert_eq!(h.hash(), content_hash(&o));
        assert_eq!(h.offer(), &o);
        assert!(!h.is_empty());
        assert_eq!(h.into_offer(), o, "the content round-trips unchanged");

        assert!(Hashed::new(Offer::new()).is_empty());
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
            role: PeerRole::Peer,
        };
        assert_eq!(decode(&encode(&hello)).unwrap(), hello);

        let get = Message::Get {
            kind: SelectionKind::Selection,
            want: GetWant::One("text/plain".to_string()),
        };
        assert_eq!(decode(&encode(&get)).unwrap(), get);

        let reply = Message::GetReply {
            kind: SelectionKind::Clipboard,
            result: GetResult::NotOffered {
                available: vec!["image/png".to_string()],
            },
        };
        assert_eq!(decode(&encode(&reply)).unwrap(), reply);

        let o = offer(&[("text/plain", b"payload")]);
        let clip = Message::Clip {
            kind: SelectionKind::Clipboard,
            hash: content_hash(&o),
            offer: o.into(),
            version: Version::new(123, Uuid::new_v4()),
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
            offer: o.into(),
            version: Version::new(1, Uuid::new_v4()),
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
            version: Version::new(42, Uuid::new_v4()),
            body: "# clipmesh-version: 42 x\nimage/png allow\n".to_string(),
        };
        assert_eq!(decode(&encode(&msg)).unwrap(), msg);
    }
}
