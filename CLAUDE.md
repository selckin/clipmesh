# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

clipmesh is a Rust daemon that syncs Wayland clipboards across a LAN mesh of hosts over Noise-encrypted TCP. Copy on one host, paste on all. See `README.md` for user-facing behavior and configuration.

## Commands

```bash
./build.sh                  # every CI gate, in CI order -- run before pushing
cargo test --lib clipboard::mutter   # the GNOME backend against its in-process fake Mutter
cargo test --lib config::tests::load_reports_a_broken_config_symlink   # one test
cargo run -- --config ./examples/config.toml   # run the daemon
```

Otherwise standard `cargo` (`cargo test --test two_nodes` / `paste` / `history` runs one integration-test file).

The binary is normally the long-running daemon, but a few flags are one-shot and exit: `--allow <glob>`, `--deny <glob>`, `--rules` (edit/inspect the MIME-rules file), `--sync-config` (rewrite the config as the canonical commented template — see `config_template.rs`), plus `--config <path>`. Two separate **modes** are detected before that flag loop, because each has a grammar the loop would reject: `--paste` (or invoking the binary via a `wl-paste` symlink) is **wl-paste impersonation**, which pulls a node's clipboard over the mesh and prints it (`paste.rs`); `history` as argv[1] is the **clipboard-history subcommand** (`list` / `get <id>` / `restore <id>`, `history.rs`).

There are two real clipboard backends, picked at startup by `clipboard::Backend::select` (`backend = "auto" | "data-control" | "mutter"`): `wayland.rs`/`watch.rs` over `ext-data-control-v1`/`zwlr-data-control-v1`, and `mutter.rs` over Mutter's remote-desktop clipboard D-Bus API for GNOME, which implements neither protocol. The engine's tests use the mock clipboard, so they run headless in CI. The data-control path is verified manually (it needs a compositor); the Mutter path is tested against `clipboard/mutter/fake.rs`, a hand-rolled Mutter served over a zbus peer-to-peer socketpair (no bus daemon), and only its behaviour against real Mutter is verified by hand.

**`examples/config.toml` and `examples/mimetypes` are generated** from `config_template.rs`'s template and `mime.rs`'s `TEMPLATE`, each pinned by a golden test — never hand-edit them (the test fails the build). Change the template, then `CLIPMESH_REGEN_EXAMPLE=1 cargo test --lib example_config_matches_template` (likewise `example_mimetypes_matches_template`).

## Architecture

A node is assembled in `node::spawn_node` (called from `main`): it binds a listener + accept loop (bounded by a `Semaphore`), spawns one `dial_loop` per configured peer, builds the shared `MimeRules`, and starts the `SyncEngine`. Peers form a **full mesh** — every node dials every other; clipmesh never forwards between peers, so each node must list all others directly.

The stack, bottom to top: `transport.rs` (Noise) → `protocol.rs` (bincode wire messages, `Offer`/`Hashed`, `Version`) → `peer.rs` (one connection) → `mesh.rs` (peer table) → `sync.rs` (`SyncEngine`, the brain; history store in `sync/settled.rs`) over the `clipboard/` backends; one-shot clients `client.rs`, `paste.rs`, `history.rs`; `mime.rs` (rules file), `config_template.rs`, `config.rs`/`fswatch.rs`, `backoff.rs`.

**Per-module design notes — the invariants and the *why* behind each module's shape — are in `src/CLAUDE.md`** (clipboard backends: `src/clipboard/CLAUDE.md`). Read the module's entry before changing it.

### Cross-cutting invariants

- **bincode is not self-describing.** Any change to `Message` or its fields must bump `protocol::PROTOCOL_VERSION`; mismatched nodes are refused at handshake rather than failing to decode later. A bump means every node in the mesh must be upgraded — an old node and a new one simply refuse each other, so a partial rollout stops syncing rather than corrupting anything.
- **tokio async** carries networking and the engine; **blocking work runs on dedicated `std::thread`s** (inotify in `fswatch`, Wayland dispatch in `clipboard::watch`) and reports back over mpsc channels. Rules-file I/O goes through `SyncEngine::with_rules`, which runs the closure on the blocking pool — the engine is one task driving `run`'s select loop, so `std::fs` there stalls inbound messages and peer connects too. The one deliberate exception is the startup rules-version read, which runs before the loop, so there is nothing to stall.
- **Startup content comes from the backend, never from a read.** `Clipboard::watch` must deliver one `ClipboardEvent::Initial` per non-empty selection, carrying its content as of the subscribe, before any `Changed` for it. The engine reads *lazily*, after an event, so anything it reads reflects "now" — it cannot tell restored content from a copy made a moment after startup, and guessing wrong suppresses the copy and records it at stamp 0 where a peer's older clipboard outranks it. Only the backend exists at subscribe time, so only the backend can answer. `Initial` is adopted by `adopt_restored` (stamp 0, never broadcast/bridged/re-owned); `Changed` is a user action. `MockClipboard` honours this exactly by snapshotting and registering under both locks in `local_copy`'s order, which is what makes `a_copy_racing_startup_is_not_mistaken_for_restored_content` deterministic. The Wayland watcher reports `Initial` from its own startup roundtrip; the residual gap there is marked KNOWN GAP in `clipboard/watch.rs` and closes when content reads move onto the watcher's own connection.
- Shared state crosses the async/thread boundary as `Arc<Mutex<...>>` (e.g. `MimeRules` is shared between `SyncEngine` and `fswatch`).

## Conventions

- This repo uses a spec → plan → implementation workflow; design docs live under `docs/superpowers/specs/` and `docs/superpowers/plans/` (dated, one per feature). Read the matching spec before changing a subsystem it covers.
- CI (`.github/workflows/`) uses only first-party `actions/*` and installs the toolchain via plain `rustup` — do not introduce third-party GitHub Actions.
