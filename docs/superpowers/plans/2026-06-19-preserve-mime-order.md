# Preserve MIME-type order across the mesh — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Carry the *source compositor's* MIME-type advertise order (which is, by
convention, preference order — richest first) faithfully through capture →
transport → write, so a paster on a remote node sees the representations offered
in the same order as on the origin node.

## Why the order matters

The `wlr-/ext-data-control-v1` protocol advertises each MIME type with a
separate `offer` event; the spec assigns no formal meaning to their order, but
the de-facto convention is preference order (most-preferred first), and simpler
paste-side clients take the first type they recognize. clipmesh today
**normalizes everything to alphabetical** because `Offer = BTreeMap`, so e.g.
`image/*` sorts before `text/*` and a remote first-match paster can pick the
image when the source listed text first.

## Root cause (two places, both must change)

1. **Read** uses `wl_clipboard_rs::paste::get_mime_types`, which returns a
   `HashSet<String>` — order is discarded *inside the library* before clipmesh
   sees it. The library also offers `get_mime_types_ordered` →
   `Result<Vec<String>, Error>`, which "preserves their original order". We must
   call that variant instead.
2. **Container** `Offer = BTreeMap<String, Vec<u8>>` re-sorts alphabetically and
   would throw any order away again. Switch to `IndexMap<String, Vec<u8>>`
   (insertion-order, map API preserved, dedups by key like a map).

## Design

- **`Offer = IndexMap<String, Vec<u8>>`.** Drop-in for every method used
  (`new`/`get`/`keys`/`insert`/`iter`/`into_iter`/`is_empty`/`len`/`collect`);
  the only semantic change is iteration order: insertion order, not sorted.
  `indexmap` 2.x is already in the dependency tree; add it as a direct dep with
  the `serde` feature so bincode round-trips preserve order.
- **`content_hash` must stay order-independent.** It currently leans on
  BTreeMap's sorted iteration. With IndexMap it must **sort a copy just for
  hashing**. This is load-bearing for echo suppression: when clipmesh writes an
  offer and its own watcher reads it back, the compositor may hand the types
  back in a *different* order; an order-sensitive hash would then mismatch and
  cause an echo/rebroadcast loop. Order-only differences must hash equal.
- **Read path** (`assemble_offer`): walk types in advertise order and drop the
  `types.sort()`. Budget truncation now follows preference order (keep the
  most-preferred reps first) instead of alphabetical — a deliberate, better
  behavior. Input is now a `Vec` from `get_mime_types_ordered`, so it is
  deterministic by construction (no HashSet nondeterminism to guard against).
- **`cap_to_payload_size`**: keep the smallest-first *drop decision* (maximizes
  reps kept), but emit the survivors in the **original order**, so the
  over-budget path doesn't scramble preference order either.
- **Wire format**: the `offer` field's type changes (BTreeMap → IndexMap). The
  bincode encoding of a map is structurally identical (length + entries), so it
  would still decode across versions, but entries would arrive in the other
  side's order. Per the repo invariant ("any change to `Message` or its fields
  must bump `PROTOCOL_VERSION`"), bump `PROTOCOL_VERSION` 3 → 4 so mixed-version
  meshes are refused at handshake rather than silently degrading order.

## File Structure

- **`Cargo.toml`** — add `indexmap = { version = "2", features = ["serde"] }`.
- **`src/protocol.rs`** — `Offer` alias → IndexMap; `content_hash` sorts a copy;
  `PROTOCOL_VERSION` 3 → 4; `describe_offer` comment; tests.
- **`src/clipboard/wayland.rs`** — `get_mime_types_ordered`; drop the sort in
  `assemble_offer`; doc + tests.
- **`src/sync.rs`** — `cap_to_payload_size` emits survivors in original order;
  an end-to-end order-preservation test.

---

## Task 1: `Offer` → `IndexMap`, order-independent `content_hash`

- [ ] **Step 1 (RED):** In `src/protocol.rs` tests, add a round-trip test that a
  non-alphabetical multi-rep offer keeps its order through `encode`/`decode`, and
  change `describe_offer_lists_mimes_and_sizes_in_sorted_order` to expect
  **insertion** order (rename to `..._in_insertion_order`). Keep the existing
  `content_hash_is_deterministic_and_order_independent` test as-is. Run — the
  round-trip/insertion-order tests fail to compile (still BTreeMap) / fail.
- [ ] **Step 2 (GREEN):**
  - `Cargo.toml`: add `indexmap = { version = "2", features = ["serde"] }`.
  - `src/protocol.rs`: `use indexmap::IndexMap;`, `pub type Offer = IndexMap<String, Vec<u8>>;`,
    update the alias doc comment, and rewrite `content_hash` to collect+sort a
    copy of the pairs before hashing. Update `describe_offer`'s "already sorted"
    comment to "insertion order".
- [ ] **Step 3:** `cargo test --lib protocol 2>&1 | tail -20` — all green,
  including the unchanged order-independence test.
- [ ] **Step 4:** Commit.

## Task 2: Read in the compositor's advertise order

- [ ] **Step 1 (RED):** In `src/clipboard/wayland.rs` tests, replace
  `assemble_offer_is_deterministic_regardless_of_input_order` with
  `assemble_offer_preserves_advertised_order` (feed `["text/html","text/plain","image/png"]`,
  assert `offer.keys()` come back in exactly that order). Run — fails (the sort
  alphabetizes to `image/png, text/html, text/plain`).
- [ ] **Step 2 (GREEN):** In `read_offer_blocking`, call
  `paste::get_mime_types_ordered(ct, paste::Seat::Unspecified)`. In
  `assemble_offer`, collect types preserving order and **remove** `types.sort()`.
  Update the two doc comments that justify the sort.
- [ ] **Step 3:** `cargo test --lib clipboard::wayland 2>&1 | tail -20` — green
  (the over-budget / unreadable-skip tests still pass; their outcomes don't
  depend on the removed sort).
- [ ] **Step 4:** Commit.

## Task 3: Order-preserving over-budget truncation

- [ ] **Step 1 (RED):** In `src/sync.rs` tests, add
  `cap_to_payload_size_keeps_original_order_of_survivors`: an offer whose reps,
  in a non-size order, exceed the budget such that one is dropped; assert the
  kept reps appear in their original relative order (not size order). Run — fails
  (today survivors come out smallest-first).
- [ ] **Step 2 (GREEN):** Rework `cap_to_payload_size` to choose survivors via
  the smallest-first greedy pass (unchanged decision), then emit them by
  iterating the original offer order, keeping only chosen keys.
- [ ] **Step 3:** `cargo test --lib sync::tests::cap_to_payload_size 2>&1 | tail -20` — green.
- [ ] **Step 4:** Commit.

## Task 4: Bump protocol version + end-to-end order test

- [ ] **Step 1 (RED):** In `src/sync.rs` tests, add an end-to-end test: a node
  locally copies a multi-rep offer in a deliberately non-alphabetical order; the
  peer-bound `Clip` (via `recv_clip`) and the applied offer preserve that order.
  Run — should already pass after Tasks 1–3; if it does, it locks the behavior
  in. (If a multi-rep helper is missing, add one.)
- [ ] **Step 2:** `src/protocol.rs`: bump `PROTOCOL_VERSION` 3 → 4. Update the
  cross-cutting-invariant note if needed.
- [ ] **Step 3:** Commit.

## Task 5: Full verification

- [ ] `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`
  — clean build, no warnings, all lib + `tests/two_nodes.rs` green.
- [ ] Commit any fixups.

## Notes for the implementer

- **Echo suppression depends on `content_hash` ignoring order** — do not make it
  order-sensitive, or read-back reordering by the compositor will loop.
- **Write path needs no logic change** — `write_offer_blocking` iterates the
  offer and `copy_multi` advertises in that order, so it inherits whatever order
  the IndexMap carries.
- **Mixed-version meshes**: bumping `PROTOCOL_VERSION` means every node must run
  a build with this change to interoperate — consistent with the project's
  existing "all nodes run a compatible build" expectation.
