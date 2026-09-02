# Mutter clipboard backend — Implementation Plan

**Goal:** Make clipmesh work on GNOME by adding a `Clipboard` backend over
Mutter's `org.gnome.Mutter.RemoteDesktop` D-Bus clipboard API, selected
automatically when the compositor offers no data-control protocol.

**Architecture:** A new `src/clipboard/mutter.rs` runs one D-Bus session task
on the tokio runtime (`CreateSession` → signal streams → `EnableClipboard`),
keeps the shared session state (type list, owned offer, is-owner flag, read
lock) and implements the four trait methods over it. A `Backend` enum in
`clipboard/mod.rs` delegates to either backend so `spawn_node<C>` stays
generic. The budget policy of `wayland::assemble_offer` is extracted into
`OfferBudget` and shared. A hand-rolled `FakeMutter` over a zbus p2p socketpair
makes the whole backend testable headless.

**Tech Stack:** Rust, tokio, `zbus` 5 (`tokio` feature; `p2p` for tests),
`tokio::net::unix::pipe` for the pipe fds, existing `wayland-client` for the
data-control probe.

**Spec:** `docs/superpowers/specs/2026-09-02-mutter-clipboard-backend-design.md`

---

## File structure

| File | Responsibility for this feature |
|------|---------------------------------|
| `src/clipboard/mutter.rs` (new) | `MutterClipboard`, `Shared`, the session task, read/write/watch. |
| `src/clipboard/mutter/proxies.rs` (new) | `#[zbus::proxy]` traits for `org.gnome.Mutter.RemoteDesktop` and `.Session`. |
| `src/clipboard/mutter/fake.rs` (new, `#[cfg(test)]`) | `FakeMutter` p2p service + `BusConnector` for a socketpair. |
| `src/clipboard/mod.rs` | `Backend` enum + `select`; `Connect` (moved); `OfferBudget`; `BusConnector` trait + `SessionBus`. |
| `src/clipboard/wayland.rs` | `assemble_offer` loops over `OfferBudget`. |
| `src/clipboard/watch.rs` | `data_control_available()`; `Connect` now imported from `mod.rs`. |
| `src/backoff.rs` | `supervise_async`. |
| `src/config.rs`, `src/config_template.rs`, `examples/config.toml` | `backend` option. |
| `src/main.rs` | `Backend::select(&cfg)`. |
| `Cargo.toml` | `zbus`, `rust-version = "1.87"`. |
| `README.md`, `CLAUDE.md` | Requirements (GNOME now supported, CLIPBOARD only), `backend`, the new module. |

---

## Task 0: Spike — prove the D-Bus plumbing (throwaway)

Before any real code, a `#[tokio::test]` in a scratch module that:

- builds a p2p pair with `zbus::connection::Builder::tokio_unix_stream(..)`
  (`.server(guid)` on one side, `.p2p()` on both), serves a trivial
  `#[zbus::interface]` with one method returning `h` (`zvariant::OwnedFd` of a
  pipe end) and one signal, and calls it through a `#[zbus::proxy]` built with
  the well-known destination name;
- converts the received fd with `tokio::net::unix::pipe::Receiver::from_owned_fd`
  and reads bytes the server wrote;
- confirms the ordering property the `Initial` drain relies on: server emits
  a signal *then* completes a method; client created the signal stream before
  the call; after the reply, `stream.next().now_or_never()` yields the signal.

Exit criteria: compiles on `zbus = "5"` with `default-features = false,
features = ["tokio"]`, MSRV bumped to `1.87`, `cargo clippy --all-targets
-- -D warnings` clean. Delete the scratch module afterwards; keep what it
taught in the fake.

## Task 1: Shared pieces

### 1a. `OfferBudget` (`clipboard/mod.rs`)

RED: move the existing `assemble_offer` tests' expectations onto the new type
(dedup, machinery skipped, over-budget skipped with the rest kept, advertise
order kept, unrecognised atom still attempted).

GREEN:

```rust
pub(crate) struct OfferBudget { max: usize, total: usize, offer: Offer }
impl OfferBudget {
    pub fn new(max: usize) -> Self;
    /// `None` = do not read (duplicate or machinery); `Some(budget)` = read up to budget + 1.
    pub fn plan(&self, mime: &str) -> Option<usize>;
    /// Accept a read representation; `false` (and a warn) when it does not fit.
    pub fn accept(&mut self, mime: String, data: Vec<u8>) -> bool;
    pub fn skip_unreadable(&self, mime: &str, err: &anyhow::Error);   // the warn/debug split by `atoms::is_content`
    pub fn finish(self) -> (Offer, usize);
}
```

`wayland::assemble_offer` becomes a loop over it; its tests stay green
unchanged.

### 1b. `Connect` moves to `clipboard/mod.rs` as `pub(crate)`

Pure move; `watch.rs` imports it. Doc comment goes with it.

### 1c. `backoff::supervise_async`

RED: a `#[tokio::test(start_paused = true)]` that a failing attempt is retried
after `RESTART_MIN`, escalates, and resets after a stable run — mirroring the
existing `Backoff` tests.

GREEN: same body as `supervise` with `tokio::time::sleep`, attempt is
`FnMut() -> impl Future<Output = ControlFlow<()>>`. Private constants stay
private.

### 1d. `watch::data_control_available() -> Result<bool>`

Connect, `registry_queue_init`, check `globals.contents()` for
`ext_data_control_manager_v1` or `zwlr_data_control_manager_v1`. `Err` only
when there is no Wayland display at all. Verified by hand (needs a compositor);
covered structurally by being three lines.

## Task 2: Proxies and the fake

### 2a. `mutter/proxies.rs`

```rust
#[zbus::proxy(interface = "org.gnome.Mutter.RemoteDesktop",
              default_service = "org.gnome.Mutter.RemoteDesktop",
              default_path = "/org/gnome/Mutter/RemoteDesktop")]
trait RemoteDesktop { fn create_session(&self) -> Result<OwnedObjectPath>; #[zbus(property)] fn version(&self) -> Result<i32>; }

#[zbus::proxy(interface = "org.gnome.Mutter.RemoteDesktop.Session",
              default_service = "org.gnome.Mutter.RemoteDesktop")]
trait RemoteDesktopSession {
    fn enable_clipboard(&self, options: HashMap<&str, Value<'_>>) -> Result<()>;
    fn disable_clipboard(&self) -> Result<()>;
    fn set_selection(&self, options: HashMap<&str, Value<'_>>) -> Result<()>;
    fn selection_write(&self, serial: u32) -> Result<OwnedFd>;
    fn selection_write_done(&self, serial: u32, success: bool) -> Result<()>;
    fn selection_read(&self, mime_type: &str) -> Result<OwnedFd>;
    fn stop(&self) -> Result<()>;
    #[zbus(signal)] fn selection_owner_changed(&self, options: HashMap<String, OwnedValue>) -> Result<()>;
    #[zbus(signal)] fn selection_transfer(&self, mime_type: String, serial: u32) -> Result<()>;
    #[zbus(signal)] fn closed(&self) -> Result<()>;
}
```

Plus one pure helper with unit tests: `parse_owner_changed(&map) ->
OwnerChange { types: Vec<String>, session_is_owner: bool }` (absent keys →
empty, not owner).

### 2b. `BusConnector` (`clipboard/mod.rs`)

```rust
#[async_trait]
pub trait BusConnector: Send + Sync + 'static { async fn connect(&self) -> Result<zbus::Connection>; }
pub struct SessionBus;   // zbus::Connection::session()
```

### 2c. `mutter/fake.rs` — `FakeMutter`

A `#[zbus::interface]` manager at `/org/gnome/Mutter/RemoteDesktop` creating
session objects at `/org/gnome/Mutter/RemoteDesktop/Session/uN`, served on the
server end of a `UnixStream::pair()`; a `PairConnector` hands the backend the
client end. Behaviour mirrored from mutter `gnome-46`:

- `EnableClipboard`: "Already enabled" error on a second call; **emits
  `SelectionOwnerChanged` for a current owner before returning**.
- `SetSelection`: empty list → error; records `session_owner = true`, emits
  owner-changed with `session-is-owner = true`.
- `SelectionRead`: error when no owner, when the session is owner ("Tried to
  read own selection"), when a read is pending ("Tried to read in parallel");
  otherwise creates a pipe, writes the seeded bytes on a task, returns the read
  end. A dropped read end (EPIPE) clears the pending flag.
- `SelectionWrite`/`SelectionWriteDone`: pairs with a `pull(mime)` hook that
  emits `SelectionTransfer(mime, serial)` and resolves with the bytes the
  backend wrote (or `None` on `success = false`).
- Hooks: `set_owner(types: &[(&str, &[u8])])` (emits owner-changed with
  `session-is-owner = false`), `clear_owner()` (emits with no keys),
  `close_session()` (emits `Closed`, drops the object), counters for
  `selection_read` calls.

RED/GREEN for the fake itself: a handshake test (create, enable, one
owner-changed round trip) so later failures point at the backend, not the
harness.

## Task 3: Session task — connect, subscribe, reconnect

RED (`mutter.rs` tests, each with a fresh `FakeMutter`):

- `initial_owner_is_reported_once_with_content_before_any_changed`
- `empty_clipboard_at_subscribe_reports_nothing`
- `a_change_after_enable_is_changed_not_initial`
- `a_closed_session_reconnects_and_reports_its_find_as_changed`
- `watcher_retires_when_the_engine_drops_the_receiver` (fake sees `Stop`, no
  further reconnect)
- `a_failed_first_attempt_still_reports_initial_on_the_first_enable` (connector
  fails once, then succeeds)

GREEN: `MutterClipboard::new(max_payload, connector)`; `watch(kinds)` spawns
`supervise_async("mutter clipboard session", attempt)`; `attempt` =
`session_once(shared, tx, connect)` following the spec's five steps; `Connect`
flips to `Reconnect` only after a successful `EnableClipboard`. The `Initial`
read goes through the same `read_offer` path as the engine's reads (it takes the
read lock like any other), bounded by `STARTUP_READ_TIMEOUT` reused from
`watch.rs` (move the constant next to `Connect`).

## Task 4: Reads

RED:

- `list_types_is_the_last_advertised_list_minus_machinery_and_costs_no_read`
- `read_offer_reads_each_type_in_advertise_order_within_budget`
- `read_offer_only_narrows_to_one_selection_read`
- `over_budget_representation_is_skipped_and_the_rest_kept`
- `reads_while_owner_come_from_the_owned_offer` (fake refuses like Mutter; the
  test asserts zero `SelectionRead` calls and byte equality with what was
  written)
- `concurrent_reads_are_serialized_never_refused` (two `read_offer` futures
  joined; fake counts no parallel-read refusal)
- `a_type_refused_mid_read_is_skipped` (fake changes owner between reads)
- `selection_kind_is_an_error`

GREEN: per the spec's Reads section, over `OfferBudget`, `read_lock`,
`pipe::Receiver::from_owned_fd`, `take(budget + 1).read_to_end`.

## Task 5: Writes and transfer serving

RED:

- `write_offer_sets_selection_with_keys_in_offer_order`
- `empty_offer_is_a_no_op` (no `SetSelection`)
- `a_transfer_is_served_byte_exact_and_completed_with_success`
- `a_transfer_for_an_unknown_mime_is_completed_with_failure`
- `owned_is_replaced_by_the_next_write_and_cleared_when_another_owner_appears`
- `own_write_echo_arrives_as_changed` (the trait requirement; engine-side echo
  handling is already covered in `io.rs`)
- `a_stalled_transfer_is_abandoned_before_mutters_cleanup` (`start_paused`,
  fake never drains; task ends with `WriteDone(false)` before 15 s)

GREEN: `owned` stored before `SetSelection`; one spawned task per
`SelectionTransfer` with `tokio::time::timeout(TRANSFER_TIMEOUT /* 10 s */)`,
`pipe::Sender::from_owned_fd`, `write_all`, drop, `SelectionWriteDone`.

## Task 6: Backend selection and config

RED:

- `config.rs`: `backend` parses `auto` (default when absent), `data-control`,
  `mutter`; anything else is a load error; `raw_config_keys_matches_the_struct`
  and `every_config_option_has_a_template_block` extended by construction.
- `clipboard/mod.rs`: `Backend::select`-level pure check
  `refuse_primary_features(cfg, chosen)`: `sync_selection` or any
  `link_selections` with `Mutter` → `Err` naming both keys; fine with
  `Wayland`; fine with `Mutter` when both are off.
- `config_template.rs`: `CLIPMESH_REGEN_EXAMPLE=1 cargo test --lib
  example_config_matches_template` after adding the block; golden test green.

GREEN:

- `Config.backend: BackendChoice { Auto, DataControl, Mutter }` (serde
  `rename_all = "kebab-case"`), `RAW_CONFIG_KEYS` (21), destructure in
  `from_toml`, template `Block::Optional { key: "backend", comment: "...",
  shown: Shown::Default("\"auto\"") }` placed after `debounce_ms`.
- `Backend` enum implementing `Clipboard` by delegation;
  `Backend::select(cfg: &Config) -> Result<Backend>`: `Auto` →
  `data_control_available()?` → `Wayland` else `Mutter`; forced values skip the
  probe; then `refuse_primary_features`; log `info!("clipboard backend: …")`.
- `main.rs`: `Arc::new(Backend::select(&cfg)?)`.

## Task 7: Docs, gates, manual verification

- `README.md` Requirements: GNOME supported through Mutter's remote-desktop
  clipboard API (CLIPBOARD only — `sync_selection`/`link_selections` are
  refused there); `backend` documented under Configuration; note the
  clipboard-manager narrowing wart and that a daemon restart keeps only
  text/image content on GNOME.
- `CLAUDE.md`: architecture bullet for `clipboard/mutter.rs` + `Backend`,
  the "one read at a time / own content read from `owned`" rules, the fake,
  and the MSRV change in Commands.
- `./build.sh` (all CI gates).
- On the GNOME host (Ubuntu 24.04):

  ```
  busctl --user introspect org.gnome.Mutter.RemoteDesktop /org/gnome/Mutter/RemoteDesktop
  systemctl --user restart clipmesh && journalctl --user -u clipmesh -f
  ```

  Expect `clipboard backend: mutter (remote-desktop API v1)`, one `Initial`
  at start, copies in both directions with a data-control peer, no
  "remote desktop" indicator in the top bar, and `wl-paste`-mode reads from a
  third host. Also check: copy in an app, close the app → one narrowed
  re-broadcast (known wart), not a loop.

---

## Commit plan

One commit per task after Task 0 (`clipboard: …` prefix), the spec committed
with Task 1 and the docs with Task 7. Task 0 is not committed.
