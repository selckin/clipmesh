# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

clipmesh is a Rust daemon that syncs Wayland clipboards across a LAN mesh of hosts over Noise-encrypted TCP. Copy on one host, paste on all. See `README.md` for user-facing behavior and configuration.

## Commands

```bash
cargo build                 # debug build
cargo build --release       # release build (CI gate)
cargo test                  # all tests (lib unit tests + tests/two_nodes.rs + tests/paste.rs)
cargo test --lib fswatch    # one module's tests
cargo test --lib config::tests::load_reports_a_broken_config_symlink   # one test
cargo test --test two_nodes # one integration-test file (likewise --test paste)
cargo clippy --all-targets -- -D warnings   # lint (CI gate; warnings are errors)
cargo fmt --check           # format check (CI gate)
cargo run -- --config ./examples/config.toml   # run the daemon
```

MSRV is Rust 1.80 (`Cargo.toml` `rust-version`). The binary is normally the long-running daemon, but a few flags are one-shot and exit: `--allow <glob>`, `--deny <glob>`, `--rules` (edit/inspect the MIME-rules file), `--sync-config` (rewrite the config as the canonical commented template — see `config_template.rs`), plus `--config <path>`. `--paste` (or invoking the binary via a `wl-paste` symlink) is a separate **wl-paste impersonation** mode that pulls a node's clipboard over the mesh and prints it (see `paste.rs`).

Running the **real** clipboard backend needs a live Wayland compositor implementing `ext-data-control-v1`/`zwlr-data-control-v1`. All automated tests use the mock clipboard instead, so they run headless in CI; the Wayland path is verified manually.

## Architecture

A node is assembled in `node::spawn_node` (called from `main`): it binds a listener + accept loop (bounded by a `Semaphore`), spawns one `dial_loop` per configured peer, builds the shared `MimeRules`, and starts the `SyncEngine`. Peers form a **full mesh** — every node dials every other; clipmesh never forwards between peers, so each node must list all others directly.

The stack, bottom to top:

- **`transport.rs`** — Noise `NNpsk0` (`Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s`) keyed by the preshared key. `handshake` splits a stream into `SendHalf`/`RecvHalf` sharing a *stateless* transport (independent per-direction nonces) so the two halves run in separate tasks. Records are chunked to Noise's 64 KiB cap.
- **`protocol.rs`** — wire messages `Message::{Hello, Clip, Rules}`, encoded with **bincode**. `Offer = IndexMap<String, Vec<u8>>` (one clipboard state's MIME representations, kept in the source compositor's advertise/preference order end-to-end); `content_hash` (BLAKE3) sorts a copy internally so identity/dedup stays order-independent even when the compositor hands types back reordered.
- **`peer.rs`** — `run_connection`: Noise handshake + `Hello` exchange (checks `PROTOCOL_VERSION` and rejects a self-connection via the `SelfConnection` marker error, which dial loops treat as permanent), then reader/writer tasks. `AbortGuard` tears the connection's child tasks down on cancel.
- **`mesh.rs`** — `Mesh`: live peer table keyed by remote node ID. Duplicate connections to one peer are expected (both nodes dial each other); index 0 of each peer's group is the designated sender, the rest are receive-only warm standbys. First connection to a peer fires `connect_tx`, which the engine turns into a resync.
- **`sync.rs`** — `SyncEngine`, the brain.
  - **Engine loop:** `run` selects over the local clipboard watch, inbound mesh messages, peer-connect events, and rules-changed pings. Handles echo suppression (compare incoming vs. current hash per selection), debounce, `Direction` (send/receive/both), payload caps, and content filtering. **Ordering everywhere — live updates and reconnect resync alike — is the hybrid logical clock `(stamp, origin)`** (`ContentState`); higher stamp wins, `origin` (node ID) breaks ties. Password-manager contents (`x-kde-passwordManagerHint = secret`) are dropped before broadcast (and, while `exclude_sensitive` is on, never re-owned).
  - **Capture-side features (both optional):** `synthesize_text_plain` back-fills `text/plain` (+`;charset=utf-8`) from a legacy `UTF8_STRING`/`STRING`/`TEXT` atom when none exists, and `take_ownership` re-offers each watched selection so clipmesh owns it (surviving the source app) — and, with synthesis, makes the back-filled `text/plain` paste on the origin host too.
  - **Local selection bridge (`link_selections`):** optionally mirrors the local CLIPBOARD and SELECTION on one host — distinct from `sync_selection` (which syncs each selection across the mesh). Local propagation runs as a deterministic read → plan → execute batch pipeline (`handle_batch`): read each changed selection once, a pure `plan_batch` decides every broadcast and every write (each selection written at most once, with `Own`/`Mirror` provenance) up front, then `execute_write` performs them. The bridge mirrors only *local* user changes: it reconciles against the partner's actual content (so an out-of-band drift is re-mirrored), and a concurrent direct change to the partner in the same batch is never clobbered (direct-change-wins, expressed structurally in `plan_batch`).
  - **Echo suppression of the engine's own writes:** content the engine itself wrote — an inbound mesh apply, content restored at startup, an ownership rewrite, or a bridge mirror — is recorded in `last_written` and its watch echo is dropped one-shot during `handle_batch`'s classification, so engine-written content is never re-broadcast, re-bridged, or re-owned (this is what makes propagation terminate). A mesh-synced mirror target is broadcast **directly** by `plan_batch` (not via its echo), so a synced partner is still fed to the mesh like any other local change. See `docs/superpowers/specs/2026-06-20-bridge-write-consolidation-design.md`.
- **`clipboard/`** — the `Clipboard` trait (`watch`/`read_offer`/`write_offer`). `wayland.rs` is the real in-process backend; `watch.rs` is its change listener (runs on a dedicated thread because Wayland dispatch blocks); `mock.rs` backs every test.
- **`paste.rs`** — the `wl-paste` impersonation mode (`--paste`, or a `wl-paste`-named symlink).
  - **Fetch mechanism:** `fetch_offer` dials a node as an ephemeral peer via `peer::run_connection` (a throwaway `Mesh` + a random node ID) and returns the `Clip` the node **already pushes on connect** (resync-on-connect) — so there is **no wire-format change**. `fetch_from_any` races `fetch_offer` across every target via a `tokio::task::JoinSet` and returns the first that responds; `resolve_targets` makes the default (no `--node`) every configured peer, `--node` a single one.
  - **Output & wiring:** pure helpers (`select_type`/`list_types`/`render`/`output_bytes`) decide the output; `run` wires `Config::load` and the wl-paste flags, writing raw bytes to stdout. Inherent constraints: a serving node needs `resync_on_connect` on and not `receive_only`; `--primary` needs its `sync_selection`. `main` detects the mode (argv[0] or `--paste`) before the daemon flag loop.
- **`mime.rs`** — `MimeRules`: a **program-managed** TOML file (via `toml_edit`). Per-type allow/deny with case-insensitive globs (most-specific match wins, deny-by-default). clipmesh auto-appends unknown types, sorts on save, and stamps a `[clipmesh]` version table so the file can be shared mesh-wide under whole-file last-writer-wins (`share_mime_rules`). `reload_if_changed` compares **content, not mtime**, so clipmesh's own writes don't trigger a reload→rebroadcast loop.
- **`config_template.rs`** — the canonical config-file template + the `--sync-config` normalizer: one ordered list of `Block`s describes every option, its comment, and its default; `render` emits the file overlaying the user's present values (options the user set stay active, the rest become commented defaults). `examples/config.toml` is **generated** from the same template and pinned by a golden test — never hand-edit the example (the test fails the build); change the template, then `CLIPMESH_REGEN_EXAMPLE=1 cargo test --lib example_config_matches_template`.
- **`config.rs` / `fswatch.rs`** — `Config::load` parses TOML and defaults `mime_rules_path` to sit beside the config. `fswatch` is an inotify watcher (dedicated thread) over both files, and is symlink-aware (follows a symlinked config/rules file to its real target). A **config** change makes the process exit cleanly so a supervisor restarts it (most settings can't hot-apply — this requires the systemd unit or any restart-on-exit supervisor); a **rules** change reloads in place.
- **`backoff.rs`** — the shared exponential-backoff helper (`next_delay`) plus the watcher restart policy (`RESTART_*` / `restart_delay`) used by the fswatch reconnect loop and the clipboard-watch reconnect. The dial loop in `node.rs` intentionally keeps its own schedule: a much lower cap (5s, so a returning LAN peer reconnects fast), a longer healthy threshold, and jitter to desynchronise simultaneous mesh reconnects.

### Cross-cutting invariants

- **bincode is not self-describing.** Any change to `Message` or its fields must bump `protocol::PROTOCOL_VERSION`; mismatched nodes are refused at handshake rather than failing to decode later.
- **tokio async** carries networking and the engine; **blocking work runs on dedicated `std::thread`s** (inotify in `fswatch`, Wayland dispatch in `clipboard::watch`) and reports back over mpsc channels.
- Shared state crosses the async/thread boundary as `Arc<Mutex<...>>` (e.g. `MimeRules` is shared between `SyncEngine` and `fswatch`).

## Conventions

- This repo uses a spec → plan → implementation workflow; design docs live under `docs/superpowers/specs/` and `docs/superpowers/plans/` (dated, one per feature). Read the matching spec before changing a subsystem it covers.
- CI (`.github/workflows/`) uses only first-party `actions/*` and installs the toolchain via plain `rustup` — do not introduce third-party GitHub Actions.
