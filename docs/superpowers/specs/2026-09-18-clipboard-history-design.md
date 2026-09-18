# clipmesh — clipboard history

**Date:** 2026-09-18
**Status:** Implemented.

**Supersedes:** the `- Clipboard history.` non-goal in
`2026-06-12-clipmesh-design.md`.

## Summary

Remember the recent clipboard contents a node settles on — local copies *and*
content applied from a peer — in a bounded in-memory ring, and add a `clipmesh
history` subcommand to list them, print one, and put one back on the clipboard.
The CLI speaks the existing mesh protocol as a one-shot `PeerRole::Paster`, so
`--node` browses and restores a *peer's* history for the price of the flag.

## Motivation

clipmesh is a mirror, not a buffer: a copy is captured, broadcast, applied on
every peer, and gone the moment the next copy lands. Copy B over A and A is
unreachable on every host in the mesh at once — the sync makes the loss
mesh-wide. A headless host using `--paste` has no local clipboard manager to
fall back on either.

The original design listed history as a YAGNI non-goal. What changed is that the
engine now has a single, well-defined moment where it decides "this is the
content of this selection" (`ContentState`, one record per selection), so
remembering is a consequence of a decision already being made rather than a new
subsystem watching from the side.

## Decisions

### In memory only

No on-disk format, no clipboard bytes at rest, lost on restart — including the
automatic restart after a config edit. The cost is real (a restart empties it)
and accepted: persistence would mean a new file format for arbitrary binary
representations, a new state directory, and clipboard contents on disk by
default. The two caps therefore bound RAM, not a file.

### Everything the node settles on

Local copies, content applied from a peer, and the clipboard that already
existed at startup. "Inert" in `adopt_restored` means restored content does not
*propagate*; it is still a state this node holds, and it is the entry a user is
most likely to want back after copying over it.

Recording is made structural rather than conventional: `ContentState` and the
`current` map move into `sync/settled.rs`, whose fields the ~2000-line
`impl SyncEngine` cannot reach, so the only way to move `current` is
`Settled::set`, which takes the content and records it in the same step. This is
`ClipboardIo`'s treatment of the echo marker, applied to the other invariant
nobody would keep correct by hand: a sixth settling site added later that
updates `current` and forgets the history leaves a clipboard the user
demonstrably had and cannot find, with nothing logged and no test failing.

`Settled::reorder` is the one door that skips the history, and it is safe
because it cannot change the hash: raising the `(stamp, origin)` of content we
already hold is a re-stamp, not a new state.

### A send-blocked node still remembers

The history is local memory; `direction` is a wire policy. A `receive_only` node
whose user copies things still shows them. Two gates had to move for that:
`SelectionPolicy::remember` joins `has_local_sink`, because otherwise the batch
never even reads the selection; and `broadcast_selection`'s `!may_send` return
moves below the filters. That second change runs a send-blocked copy through a
pipeline where it ran through none, which is the most dangerous line in the
feature — hence `Pipeline::Remember`, `Broadcast`'s transforms with
`RulesStage::Apply`, so a copy this node will never send cannot append to its
shared MIME-rules file and push the whole ruleset mesh-wide.

`remember` deliberately cannot touch `current`: advancing it from content this
node never sent would make a peer's genuinely newer clip look older here and
stop it being applied, on the very node whose job is to receive.

Selections the node does not watch are not remembered. Remembering must not be a
reason to start watching PRIMARY — the Mutter backend has none at all, and
`sync_selection = false` means the user said not to.

### An entry has two names, and the node decides which was typed

A listing prints a row number and a short id, and `get`/`restore` take either.
They fail differently, which is why both exist.

A **row number** is what a human reads off the screen and retypes. It is a
position, and the CLI is one-shot: copy something between `history list` and
`history restore 2` and the rows below shift, so the command acts on an entry
the user never saw. An **id** — the start of the entry's BLAKE3 `content_hash` —
cannot do that; the worst it does is name an entry that has since been evicted,
which is a typed failure. A prefix matching several entries is `Ambiguous`,
never resolved by picking one.

The two namespaces are kept apart by one rule, in one place
(`Listing::resolve`): **a run of digits is a row number; anything else is an
id.** Both halves matter. Digits first, because the other way round `restore 3`
would be ambiguous most of the time — a sixteenth of all ids start with `3`. And
an out-of-range number is *not* retried as an id, because every decimal digit is
also a hex digit: a stale `restore 23` against a history that has since shrunk
would silently become a prefix search, land on whichever entry starts `23`, and
— for a restore — broadcast it mesh-wide reporting success. The cost is that an
id whose printed prefix is all digits, about one in forty, can only be named by
its row number; that number is on the same line of the same listing.

Numbering is assigned by the node, after the rules filter, and every request
resolves against the same `listing()` order — so `list`, `get` and `restore`
cannot disagree about which entry is number 2, and a row the listing omits never
silently consumes a number.

`Listing` deliberately keeps two lists. A number is a position, so it indexes
the filtered rows. An id names *content*, so it is matched against every
remembered entry, including the ones the rules currently hide — otherwise naming
a denied entry by its perfectly valid id answers "no such entry" instead of
`Filtered(Denied)`, and the user goes looking for an eviction that never
happened.

### Restoring is copying

The entry is written to the node's clipboard *and* broadcast under a freshly
minted `Version`, so peers follow exactly as they would from a fresh copy. It
goes through `io.write`, so the watch echo it provokes is suppressed and it is
not re-broadcast as a local change; `Settled::set` recording the hash first is a
second, independent guard.

`Pipeline::Recall` is its own variant even though its stages match `Serve`'s,
because `Pipeline` names *why* content is moving. Two choices in it are
load-bearing: `RulesStage::Apply` rather than `Record`, so a request cannot make
this node rewrite its rules and push them mesh-wide; and synthesis **off**, which
is the one place it differs from `Restore` — back-filling `text/plain` would hand
back bytes hashing differently from the id the user asked for, landing the
restore as a new entry beside the one they picked.

A node that does not send that selection still restores locally and reports
`broadcast: false`, so the CLI can say the mesh did not follow rather than
implying it did.

### A listing carries no payloads

`HistoryEntry` is a summary — id, selection, age, size, type names, preview —
for the reason `GetWant::TypesOnly` exists: fifty remembered entries must not
drag fifty clipboard offers across the wire to print a table. Pinned by a test
that measures the encoded reply for a 512 KiB image.

The preview is rendered **on the node**, and stripped of control and bidi
characters there. That is not tidiness: clipboard content is arbitrary bytes
about to be written to a terminal, and an escape sequence in a copied string
must not repaint the screen or move the cursor. Doing it node-side also means a
hostile *peer's* copy cannot attack the listing host's terminal.

Ages are resolved on the node too. An absolute timestamp would be rendered
against the *client's* clock, so `history list --node <peer>` would show ages
skewed by exactly the clock disagreement the mesh's stamp guard tolerates by
design.

### Every failure names itself

`HistoryMiss` has one value per cause, per `Unavailable`'s rule. `Filtered`
matters most: the MIME rules are shared mesh-wide, so an entry can outlive the
configuration that recorded it, and answering "this node has no such selection"
when the truth is "every type in it is now denied" sends the user to the wrong
setting.

### Secrets

`exclude_sensitive` (default on) drops password-manager content in
`apply_stages`, upstream of every recording site, so a secret is never
remembered. With `exclude_sensitive = false` the user has explicitly asked for
that content to be treated like any other, and it is — including here. That is a
deliberate consistency choice rather than an oversight; see **Open questions**.

## Constraints and risks

- **`PROTOCOL_VERSION` 10 forces a full-mesh upgrade.** Mismatched nodes refuse
  each other at the handshake, as designed. The README already tells users to
  upgrade every host together. (v9 shipped the history with ids only; adding row
  numbers moved fields inside `HistoryEntry` and `HistoryMiss`, which a
  non-self-describing encoding cannot survive without the bump.)
- **Memory profile changes in kind.** The daemon previously held roughly one
  clipboard payload alive; it can now hold `history_max_bytes` (64 MiB by
  default) pinned by `Arc`s nothing else holds. The cap counts payload bytes by
  the same `offer_size` measure `max_payload_size` uses, not the allocator's
  view of the `IndexMap`/`Arc` overhead around them.
- **Read exposure widens.** A psk holder could already pull a node's *current*
  clipboard and inject content; it can now read the last 50 states and their
  previews. This adds no new authority, but it widens what a compromised psk
  leaks. Named in the config template and the README, with `history_entries = 0`
  as the switch.
- **The `Settled` refactor touches the LWW path** mesh convergence depends on.
  It is behaviour-neutral by construction (the existing ordering tests are the
  guard) but it is the largest single diff here.

## Non-goals

- **On-disk persistence.** See above.
- **`history restore --primary`** — restoring into a selection other than the one
  the entry came from.
- **Search, pinning, or `--watch`.** A bounded list a human reads is the whole
  interface.
- **Bridging a restore.** `link_selections` mirroring rides the local-change
  classification, and a restore is an engine write whose echo is suppressed — the
  same reason content received from a peer is never re-mirrored. Making it an
  exception needs a second write racing `plan_batch`, for a marginal case.
  Documented instead.
- **`history get -l`.** A listing already carries every entry's type names, so
  asking for them again would be a round trip for something the client has.

## Open questions

- **Should the history refuse secrets unconditionally, ignoring
  `exclude_sensitive = false`?** The argument for: that flag consents to
  *propagation* — landing on a clipboard the password manager itself clears after
  ~30 seconds, which is what the `x-kde-passwordManagerHint` convention serves —
  whereas the history is *retention*, keeping it long after the clipboard moved
  on and showing a preview of it in a listing any psk holder can pull. Those are
  arguably different consents, and the existing flag grants only the first.
  Shipped following the flag, as one rule rather than two; it is a one-line guard
  in `History::record` to change.
- **Should serving a history be gated by `direction` the way `serve_get` is?**
  Not applied: the CLI's default target is this host's own daemon, and the gate
  would break `history list` for the owner of every `receive_only` node — the
  class with the most interesting history. Gating on "the client is on loopback"
  would be the principled version, but `Mesh` keys by node UUID, not socket
  address, so it needs the peer's address plumbed from `peer.rs`.
