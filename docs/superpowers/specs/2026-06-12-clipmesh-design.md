# clipmesh — encrypted LAN clipboard mesh

**Date:** 2026-06-12
**Status:** Approved design

## Summary

A single Rust binary, run as a systemd user service on each host, that keeps
Wayland clipboards in sync across a set of machines on the local network.
Every node has the same configuration shape: a listen address, a list of peer
hosts, and a preshared secret. When something is copied on one host, it is
pushed to all connected peers over a Noise-encrypted TCP connection.

Target environment: Wayland compositors implementing `ext-data-control-v1`
or `zwlr-data-control-v1` (niri, Sway, Hyprland, KDE Plasma, …). GNOME/Mutter
is explicitly out of scope (no data-control protocol).

## Goals

- Full peer mesh: every node dials the peers in its config and listens for
  inbound connections; a copy anywhere reaches every connected node.
- Any MIME type: mirror all representations offered on the clipboard, not
  just text, subject to a size cap.
- Encryption and mutual authentication from a preshared secret; a node
  without the secret can neither read traffic nor inject clipboard content.
- Robust unattended operation: reconnect with backoff, per-peer failure
  isolation, no mesh broadcast storms.

## Non-goals (YAGNI)

- Relaying/forwarding between peers (assumes full connectivity).
- Clipboard history.
- Peer auto-discovery (explicit host list only).
- X11, Windows, macOS backends (the `Clipboard` trait leaves the door open).
- Lazy/on-demand content fetch — content is captured and pushed eagerly.

## Architecture

One binary, tokio async runtime, modules with narrow interfaces:

| Module      | Responsibility |
|-------------|----------------|
| `config`    | Load and validate TOML config. |
| `clipboard` | `Clipboard` trait + Wayland impl (`wl-clipboard-rs`, data-control) + mock impl for tests. |
| `transport` | Noise `NNpsk0` handshake + length-prefixed AEAD frames over TCP. |
| `peer`      | Lifecycle of one connection: dial/accept, backoff, send/recv messages. |
| `mesh`      | Set of live peers; broadcast; dual-connection avoidance. |
| `sync`      | Glue: watcher → broadcast; inbound → apply; echo suppression; debounce; direction control; sensitive-content filtering. |

### `clipboard` interface

```rust
trait Clipboard {
    /// Stream of change notifications (regular clipboard and, if enabled,
    /// primary selection), each identifying which selection changed.
    fn watch(&self) -> impl Stream<Item = SelectionKind>;
    /// Read all offered MIME types eagerly, bounded by the size cap.
    async fn read_offer(&self, kind: SelectionKind) -> Offer; // {mime -> bytes}
    /// Set the local selection to the given representations.
    async fn write_offer(&self, kind: SelectionKind, offer: Offer);
}
```

The real implementation uses `wl-clipboard-rs` (data-control protocol).
A mock implementation backs unit and integration tests so CI needs no
compositor.

### Transport and security

- TCP between peers; each connection upgraded via Noise `NNpsk0`
  (`snow` crate), keyed by the preshared secret. This provides mutual
  authentication (only secret-holders complete the handshake), forward
  secrecy per session, and per-message AEAD with replay protection.
- The PSK is read from an inline config value, a file path, or an
  environment variable named in the config (exactly one of `psk`,
  `psk_file`, `psk_env`).
- After the handshake, messages are length-prefixed encrypted frames.
  A frame that fails to decrypt, exceeds the size cap, or fails to parse
  closes the connection (logged; reconnect applies).

### Mesh topology

- Symmetric config: every node lists every other node as a peer and also
  listens.
- **Dual-connection avoidance:** each node only *dials* peers whose
  identity (host:port string) sorts greater than its own listen identity,
  and *accepts* connections from the rest — exactly one connection per
  pair.
- Outbound connections retry with exponential backoff (with cap and
  jitter). One peer being down never affects the others.

### Data flow

1. Local copy → `watch()` fires → debounce window (default 100 ms) →
   `read_offer()` captures all MIME representations (cap enforced) →
   message `{content_hash, selection_kind, {mime: bytes}}` → broadcast to
   all connected peers.
2. Inbound message → sanity checks → `write_offer()` applies it locally →
   `content_hash` recorded as last-applied-from-network.
3. **Echo suppression:** applying a remote offer re-triggers the local
   watcher; if the re-read content hashes to the last network-applied
   hash (tracked separately per selection kind), it is consumed without
   rebroadcast. Combined with no-relaying, this prevents broadcast
   storms.

`content_hash` is a hash (BLAKE3) over the sorted `(mime, bytes)` pairs.

## Configuration

TOML, default path `~/.config/clipmesh/config.toml`:

```toml
listen = "0.0.0.0:48100"            # listen address
peers = ["host-b:48100", "host-c:48100"]
# exactly one of:
psk_file = "~/.config/clipmesh/psk"  # read PSK from file
# psk = "supersecret"                # inline in config
# psk_env = "CLIPMESH_PSK"           # from environment variable

max_payload_size = "8MiB"            # per-message cap, default 8 MiB
debounce_ms = 100                    # clipboard quiet period before send
sync_primary = false                 # also sync primary selection
direction = "both"                   # "both" | "send_only" | "receive_only"
exclude_sensitive = true             # skip x-kde-passwordManagerHint=secret
log_level = "info"                   # overridable via RUST_LOG

# optional MIME filtering
# mime_allow = ["text/*", "image/*"]
# mime_deny  = []
```

Option semantics:

- **`exclude_sensitive`** (default `true`): offers containing the
  `x-kde-passwordManagerHint` MIME type with value `secret` are never
  broadcast (KeePassXC and friends).
- **`sync_primary`** (default `false`): when enabled, the primary
  selection is watched and synced as a distinct `selection_kind`; remote
  primary updates apply only to the primary selection.
- **`direction`**: `send_only` broadcasts local copies but ignores inbound
  offers; `receive_only` applies inbound offers but never broadcasts.
  Connections are still established in both modes.
- **`debounce_ms`**: successive change events within the window collapse
  into one broadcast of the final state.
- **`max_payload_size`**: offers whose total captured size exceeds the cap
  are not sent (logged at debug). Inbound frames over the cap close the
  connection.

## Error handling

- Per-peer isolation; failures never propagate across peers.
- Decrypt/parse failure or oversized frame → drop connection, log, let
  reconnect logic recover.
- Clipboard read/write errors are logged and skipped (never crash the
  daemon).
- Config errors are fatal at startup with a clear message.

## Testing

- Unit tests: frame round-trip (encode/encrypt/decrypt/decode), echo
  suppression and dedup logic, debounce behavior, config parsing and
  validation, sensitive-content filtering, direction-control gating.
- Integration test: two in-process nodes over loopback TCP with mock
  clipboards; a copy on node A appears on node B (and vice versa), echo
  suppression verified by asserting no rebroadcast.
- No test requires a real Wayland session.

## Deployment

- `clipmesh` binary + example systemd user unit
  (`clipmesh.service`, `WantedBy=graphical-session.target`).
- Repo lives at `~/sources/workspace/clipmesh`.
