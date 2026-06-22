# clipmesh — a `wl-paste` impersonation mode that pulls from a node

**Date:** 2026-06-21
**Status:** Approved design

## Summary

Add a one-shot CLI mode that makes `clipmesh` behave like `wl-paste`, except
the clipboard data comes from a clipmesh **node over the network** instead of a
local Wayland compositor. Invoked as `clipmesh --paste [wl-paste-flags…]`, or by
symlinking the binary as `wl-paste` (argv[0] detection). It connects to a node
over the existing Noise-encrypted protocol, receives the clipboard that node
**already pushes on connect** (resync-on-connect), and writes the selected MIME
representation to stdout.

The motivating case is a host with **no Wayland compositor** (a server, a
headless box, a script context) that wants to paste the mesh's current
clipboard from a real desktop node.

## Motivation

clipmesh already syncs clipboards across the mesh, but reading the clipboard
requires a live Wayland compositor (`ext-data-control-v1`). On a host without
one — or in a script that just wants the current clipboard text — there is no
way to get at the data. Tools that expect `wl-paste` on `PATH` have nothing to
call.

A node already pushes its current clipboard to any peer that connects
(`on_peer_connected` → `resync_on_connect`). So "give me your clipboard" is, in
effect, already implemented as a push. This feature adds a thin client that
connects, takes that push, prints it, and exits — reusing the entire existing
connection stack (Noise handshake, `Hello` exchange, the reader path) with **no
wire-format change**.

## Non-goals (YAGNI)

- **No protocol change.** We reuse resync-on-connect, so `PROTOCOL_VERSION`
  stays at 4 and an unmodified node at the same version serves a paste client
  unchanged. The cost is the two inherent dependencies under *Constraints*.
- **No `wl-copy` (the reverse).** Setting a node's clipboard would need a write
  path / new message and is out of scope. Possible follow-up.
- **No `-w`/`--watch` (streaming).** `wl-paste --watch` runs a command on every
  change; that is a streaming feature, not a one-shot paste. Rejected with a
  clear "not supported" message rather than mis-parsed. Possible follow-up.
- **No new config.** The mode reuses `Config::load` for the PSK and the default
  target (`peers[0]`). `listen` stays a required config field even though the
  client never binds — reusing the existing loader is simpler than a second,
  partial config shape.
- **No local clipboard access.** The client never touches Wayland; it only
  prints bytes. It therefore builds and runs without a compositor.

## Constraints (inherent to reusing resync-on-connect)

These fall out of pulling via the existing push, not from extra restrictions:

1. The **target node must push on connect**: `resync_on_connect = true` (the
   default) and `direction != receive_only`. Otherwise no `Clip` arrives and the
   client times out with an actionable message.
2. **`-p`/`--primary` (the SELECTION) only works if the target has
   `sync_selection = true`** — a node only resyncs SELECTION when it syncs it.
   Against a node that doesn't, primary paste times out.

Both are documented and produce a clear timeout error naming the likely cause.

## Invocation & flags

Detected **before** the normal flag loop in `main`, so wl-paste-style flags
(which the daemon parser would reject) reach the paste parser instead:

- argv[0] basename is `wl-paste`, **or** `--paste` appears anywhere in the args
  (stripped before paste-arg parsing, so `--config`/`--node` ordering is free).

Flags (a practical `wl-paste` subset, plus two extensions):

| Flag | Meaning |
|------|---------|
| `-t`, `--type <mime>` | Print this exact MIME type; error if not offered. |
| `-l`, `--list-types` | List the offered MIME types, one per line, in advertise order. |
| `-n`, `--no-newline` | Don't append a trailing newline. |
| `-p`, `--primary` | Pull the SELECTION instead of the CLIPBOARD. |
| `--node <host[:port]>` | *(extension)* Pull from one specific node (config port applied). Default (no `--node`): race **every** configured peer, first to respond wins. |
| `--config <path>` | *(extension)* Config file; default `~/.config/clipmesh/config.toml`. |
| `-w`, `--watch` | Explicitly rejected: "not supported". |

**Default type selection** (no `-t`), matching `wl-paste`'s text-first
behaviour: prefer `text/plain;charset=utf-8`, then `text/plain`, then the first
`text/*`, then the first offered type.

**Trailing newline:** appended by default **only for `text/*`** types (binary
output is emitted verbatim); suppressed by `-n`. `--list-types` always newline-
terminates each entry.

**Output is binary-safe:** raw bytes are written to stdout with `write_all`; no
UTF-8 assumption. Logs/diagnostics go to **stderr** so stdout stays clean.

## Mechanism — reuse resync-on-connect

The client side, in one async function `fetch_offer`:

1. `TcpStream::connect(addr)` (connection-refused → a clear error).
2. Build a throwaway `Mesh` with a fresh random node-id and the inbound/connect
   channels, and drive `peer::run_connection(stream, initiator=true, psk,
   max_payload, mesh)` **inline** (`tokio::pin!`, not spawned) so returning from
   `fetch_offer` drops it and its `AbortGuard`s tear the connection down.
   `run_connection` performs the Noise handshake, sends our `Hello` (random
   node-id + `PROTOCOL_VERSION`), reads and version-checks the peer's `Hello`,
   registers, runs the reader, and adds its own framing slack on top of
   `max_payload` — all existing code.
3. Read inbound `(from, Message)` from the mesh channel, **ignoring** `Rules`
   and `Clip`s of the wrong kind, until a `Clip { kind == requested }` arrives →
   return its `Offer`.
4. The read races, in a `tokio::select!`, against (a) an overall **timeout** and
   (b) the `run_connection` future finishing — so a PSK / version mismatch or a
   dropped connection surfaces as that real error instead of a bare timeout.
   Whichever way the loop exits, a final non-blocking drain of the inbound
   channel rescues a `Clip` the reader delivered in the same tick the connection
   closed (which `select!`'s pseudo-random choice could otherwise lose).

On the **target** side nothing changes: a new connection that completes the
`Hello` exchange registers as a peer, fires the connect event, and
`on_peer_connected` pushes `Message::Rules` (if `share_mime_rules`) plus a
`Message::Clip` per synced kind (re-read live and confirmed against `current`).
The client picks out the `Clip` it wants.

The client uses a random node-id, so it is never mistaken for the target itself
(`SelfConnection`); a collision with the target's UUID is astronomically
unlikely and degrades to a clean error.

### Racing multiple nodes

By default (no `--node`) `resolve_targets` yields **every** configured peer and
`fetch_from_any` races `fetch_offer` across them via a `tokio::task::JoinSet`,
returning the offer from the **first node that responds**. Unreachable,
timed-out, or wrongly-configured nodes are tolerated as long as one succeeds; if
all fail the last error is reported (wrapped with the node count). The first
success drops the `JoinSet`, aborting the remaining in-flight fetches. A single
target (one peer, or an explicit `--node`) is fetched directly so its exact
error surfaces. This means a headless host needn't know which of its desktops is
up — it just lists them all as peers.

## Components touched

| Unit | Change |
|------|--------|
| `paste.rs` (new) | `fetch_offer` (network pull, reusing `peer::run_connection`); `fetch_from_any` (race all targets, first success wins); `resolve_targets` (`--node` → one, default → all peers); pure helpers `select_type` / `list_types` / newline handling; arg parsing into a `PasteArgs`; `run` wiring config + args + stdout. |
| `lib.rs` | `pub mod paste;` |
| `main.rs` | Detect paste mode (argv[0] == `wl-paste`, or `--paste` present) before the flag loop and delegate to `paste::run`. |
| `README.md`, `CLAUDE.md` | Document the mode, the `wl-paste` symlink, and the two constraints. (`examples/config.toml` is generated from `config_template.rs` and gains no key, so it is left untouched.) |

`protocol.rs`, `peer.rs`, `transport.rs`, `mesh.rs`, `sync.rs`, `node.rs` are
**unchanged** — the client reuses them as a library.

## Diagnostics & exit codes

- No target resolvable (`peers` empty and no `--node`) → error, exit non-zero.
- All targets fail (unreachable / timed-out / wrong PSK) → the last error,
  wrapped "couldn't paste from any of N nodes", exit non-zero. A single target
  surfaces its own exact error instead.
- Connection refused → error naming the address, exit non-zero.
- Handshake/version/PSK failure → surfaced from the connection future, exit
  non-zero.
- Timeout with no `Clip` of the requested kind → error naming the address and
  the likely cause (`resync_on_connect` off / empty clipboard / `-p` without
  `sync_selection` / slow large transfer), exit non-zero.
- `-t <mime>` not offered → error listing what *is* offered, exit non-zero.
- Broken pipe on stdout (e.g. `… | head`) → clean exit 0 (matches `wl-paste`).
- Success → bytes on stdout, exit 0.

## Testing (TDD, RED first)

Pure helpers (unit, no network):
- `select_type` prefers `text/plain;charset=utf-8`, then `text/plain`, then
  first `text/*`, then first key; honours an exact `-t`.
- `-t <mime>` that isn't offered is an error.
- `--list-types` renders keys in advertise order, one per line.
- Trailing newline appended for `text/*`, omitted for binary, suppressed by
  `-n`; output is byte-exact (binary-safe).
- Arg parsing: each flag maps to the right `PasteArgs`; `--watch` is rejected;
  unknown flags error; `--paste` stripping and argv[0] detection.

End-to-end (integration, mirroring `tests/two_nodes.rs` with `MockClipboard`):
- `fetch_offer` against an in-process node returns the node's current
  CLIPBOARD offer (exercises the real Noise handshake + resync push).
- With `sync_selection`, `fetch_offer` for SELECTION returns the SELECTION.
- Against a node with `resync_on_connect = false`, `fetch_offer` times out with
  the actionable error.
- Wrong PSK surfaces as a connection error, not a bare timeout.
- `fetch_from_any` over `[dead-addr, live-node]` returns the live node's offer
  (a dead node doesn't block the race); over all-unreachable it errors with
  "couldn't paste from any of N nodes".
- `fetch_offer` skips a `Rules` message (real `share_mime_rules`) and the
  unwanted selection's `Clip` before returning the requested kind; `--primary`
  against a node without `sync_selection` times out.
