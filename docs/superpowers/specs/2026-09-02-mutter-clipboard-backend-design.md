# clipmesh — GNOME support via Mutter's remote-desktop clipboard API

**Date:** 2026-09-02
**Status:** Approved design

## Summary

Add a second clipboard backend, `clipboard::mutter`, that talks to GNOME's
compositor over the session bus instead of the Wayland data-control
protocol. Mutter implements neither `ext-data-control-v1` nor
`zwlr-data-control-unstable-v1` (both requests were closed the day they
were filed: mutter#524 in 2019, mutter#3941 in Feb 2025), so on GNOME the
current watcher fails on every attempt:

    ERROR clipboard watcher failed: compositor provides no usable
    data-control protocol (...); GNOME/Mutter is unsupported

What Mutter does expose is a clipboard interface on
`org.gnome.Mutter.RemoteDesktop.Session` — the private D-Bus API
gnome-remote-desktop uses for RDP clipboard sync, and what
`xdg-desktop-portal-gnome`'s Clipboard portal proxies. It maps onto the
`Clipboard` trait one-to-one, needs no X11, no shell extension, and shows
no consent dialog.

The backend is selected at startup (`backend = "auto"`): data-control when
the compositor offers it, Mutter otherwise. Nothing changes for niri, Sway,
Hyprland or KDE.

## The Mutter API (verified against mutter `gnome-46`, Ubuntu 24.04)

`data/dbus-interfaces/org.gnome.Mutter.RemoteDesktop.xml`,
`src/backends/meta-remote-desktop-session.c`:

| Call | Role for clipmesh |
|------|-------------------|
| `org.gnome.Mutter.RemoteDesktop.CreateSession() → o` | one session per daemon; no polkit, no dialog (`handle_create_session` just creates it) |
| `Session.EnableClipboard(a{sv})` | subscribe. With a current owner Mutter emits `SelectionOwnerChanged` **inside the handler, before completing the call** — the `Initial` contract for free |
| signal `SelectionOwnerChanged(a{sv})` | `mime-types` (as) + `session-is-owner` (b); **absent** keys mean "no owner". The change watch, and the only source of the type list (there is no query method) |
| `Session.SelectionRead(s) → h` | read one representation (Mutter creates a pipe, hands us the read end). Refused for the session's own source (`"Tried to read own selection"`) and while another read is pending (`"Tried to read in parallel"`, `LIMITS_EXCEEDED`) |
| `Session.SetSelection(a{sv})` | become owner for `mime-types` (non-empty list required); without the key: unset |
| signal `SelectionTransfer(s mime, u serial)` | a paster (or Mutter's own clipboard manager) wants a representation |
| `Session.SelectionWrite(u serial) → h`, `SelectionWriteDone(u, b)` | answer a transfer: write to the fd, close, report. Unanswered serials are cancelled after **15 s** (`TRANSFER_REQUEST_CLEANUP_TIMEOUT_MS`) |
| signal `Closed` | the session is gone (Mutter also closes it when our bus connection drops) |
| `Session.Start()` | **never called.** It is what creates the remote-access handle behind the top-bar "remote desktop" indicator and runs `check_permission`; the clipboard methods do not require a started session |
| property `Version` (i) | 1 on GNOME 46; logged, not gated on |

Facts that shape the design:

- **CLIPBOARD only.** The session code touches `META_SELECTION_CLIPBOARD`
  and nothing else; PRIMARY is not reachable through this API.
- **Own content is unreadable through Mutter**, so the backend must answer
  reads of its own selection from the offer it set.
- **One read at a time per session**, so reads are serialized in the
  backend (the engine and the `--paste` server can overlap).
- **Early close is the designed abort path**: `has_pending_read_operation`
  polls the pipe for `G_IO_ERR` and cancels, so dropping the fd on an
  over-budget representation is fine (Mutter logs a `g_warning` for it).
- **Mutter's clipboard manager fetches content right away** on every owner
  change (`meta-clipboard-manager.c`, mutter#3468): expect immediate
  `SelectionTransfer`s for the best `text/plain`/`image/*` after each write.
- **Ownership dies with the session.** When the daemon exits while owner,
  the clipboard manager keeps only its saved `text/plain`/`image/*` copy.
- The interface is identical between `gnome-46` and `main` apart from new
  keymap methods; the clipboard part has been stable since it was added for
  gnome-remote-desktop.

## Motivation

- A GNOME node today is dead in both directions: the watcher never
  connects, and `write_offer` (wl-clipboard-rs) needs the same protocol.
- The alternatives were rejected: X11 over Xwayland (a second protocol
  stack, and the user does not want an X11 dependency), wl-clipboard's
  focus-stealing popup surface (cannot watch; polling would steal keyboard
  focus on every tick), a GNOME Shell extension (an extension to maintain
  per GNOME release), and `org.freedesktop.portal.Clipboard` (tied to a
  RemoteDesktop portal session whose `Start` shows a consent dialog; the
  `restore_token` that would silence it needs xdg-desktop-portal 1.20, and
  Ubuntu 24.04 ships 1.18).

## Non-goals (YAGNI)

- PRIMARY on GNOME. Not exposed by the API; `sync_selection` and
  `link_selections` are refused at startup on this backend (see Config).
- The portal Clipboard interface. Same methods, one more hop, plus a
  dialog. Can be added later behind the same trait if a non-Mutter
  compositor ever needs it — but those all have data-control.
- Runtime backend switching. Selection happens once at startup; a config
  edit restarts the daemon anyway.
- Changing the engine. `SyncEngine`, `ClipboardIo` and every test keep
  working unmodified; the trait contract is met, not bent.

## Architecture

| Unit | Responsibility |
|------|----------------|
| `clipboard/mutter.rs` (new) | `MutterClipboard`: one D-Bus session task (connect → `CreateSession` → subscribe signals → `EnableClipboard`), the shared session state, and the four trait methods over it. |
| `clipboard/mutter/proxies.rs` (new) | The two `#[zbus::proxy]` traits (`RemoteDesktop`, `RemoteDesktopSession`), nothing else. |
| `clipboard/mutter/fake.rs` (new, `#[cfg(test)]`) | A hand-rolled Mutter over a p2p socketpair, mirroring the refusals above, so the backend is tested headless. |
| `clipboard/mod.rs` | `Backend` enum (`Wayland`/`Mutter`) implementing `Clipboard` by delegation; `Backend::select(cfg)`; `Connect` (moved from `watch.rs`) shared by both watchers; `OfferBudget`, the per-representation budget policy extracted from `wayland::assemble_offer`. |
| `clipboard/watch.rs` | `data_control_available()`: the startup probe (connect, registry roundtrip, look for either manager global). |
| `backoff.rs` | `supervise_async`, the tokio twin of `supervise` on the same private constants. |
| `config.rs`, `config_template.rs` | `backend = "auto" \| "data-control" \| "mutter"` (+ `RAW_CONFIG_KEYS`, template block, regenerated `examples/config.toml`). |
| `main.rs` | `Backend::select` instead of `WaylandClipboard::new`; log the choice. |
| `Cargo.toml` | `zbus` (tokio, no async-io), `rust-version` bump. |

`spawn_node<C: Clipboard>` and `SyncEngine<C>` stay generic; `main` passes
`Arc<Backend>`. An enum rather than `Arc<dyn Clipboard>` because the
generic bound runs through `ClipboardIo<C>` and `SyncEngine<C>`, and a
two-arm delegating impl is smaller than threading `?Sized` through them.

### Session lifecycle

`watch(kinds)` spawns the session task on the tokio runtime (zbus is
async; there is no blocking dispatch, so no dedicated thread as the Wayland
watcher needs). It runs under `supervise_async` and per attempt:

1. `zbus::Connection::session()`; `CreateSession` on
   `/org/gnome/Mutter/RemoteDesktop`; build the session proxy at the path
   returned.
2. Create the `SelectionOwnerChanged`, `SelectionTransfer` and `Closed`
   signal streams **before** step 3.
3. `EnableClipboard({})`.
4. Startup report, by `Connect`:
   - `Subscribe` (first attempt that reaches this point): drain the
     owner-changed signal that is already queued, if any, and read its
     content → one `Initial`. No signal → the clipboard is empty → nothing.
   - `Reconnect`: report `Changed` instead and read nothing (the daemon was
     blind; the content may be a copy made meanwhile — the same rule, for
     the same reason, as `clipboard::watch`).
5. Loop over the streams: owner-changed → update the shared state and send
   `Changed(Clipboard)`; transfer → spawn a serve task; `Closed`, a stream
   ending, or a D-Bus error → return `Continue` (restart with backoff).
   A send failing (`tx` closed: the engine is gone) → `Stop()` the session
   and `Break`.

The draining in step 4 is exact, not a timing guess: Mutter emits the
signal before completing the method call, D-Bus delivers messages in order
on one connection, and zbus feeds every stream from one in-order reader —
so when the reply has been observed, the signal is already in the stream's
queue and `now_or_never` sees it. The residual KNOWN GAP is the same as the
Wayland watcher's: the *content* is read after the signal, so a copy landing
in between is reported as `Initial`.

`Subscribe` means the first attempt that reaches `EnableClipboard`, not the
first attempt: content that pre-dates the daemon ever seeing the clipboard
is restored content whichever attempt finds it. (`clipboard::watch` flips
to `Reconnect` after the first *attempt*; that difference is noted, not
changed here.)

### Shared state

```
struct Shared {
    session:   Mutex<Option<RemoteDesktopSessionProxy<'static>>>, // None until enabled / after Closed
    types:     Mutex<Vec<String>>,       // last SelectionOwnerChanged, advertise order
    is_owner:  AtomicBool,               // last signal's session-is-owner
    owned:     Mutex<Option<Arc<Offer>>>,// what we last SetSelection'ed
    read_lock: tokio::sync::Mutex<()>,   // Mutter: one SelectionRead at a time
    max_payload: usize,
}
```

Trait methods snapshot `session`; `None` → `Err("not connected to
Mutter's clipboard API")`, which `ClipboardIo` already logs and skips.

### Reads

`list_types(Clipboard)` = cached `types` minus `atoms::is_machinery`, no
D-Bus call at all — cheaper than the Wayland backend, and the type list is
exactly what Mutter last advertised.

`read_offer(Clipboard, only)`:

1. If `is_owner`: answer from `owned` (narrowed by `only` with
   `type_matches`). This is the echo path — the engine's marker compares the
   hash, and the bytes are the ones we wrote.
2. Else take `read_lock`, then for each cached type (narrowed by `only`,
   deduped, machinery skipped, budgeted — all via `OfferBudget`):
   `SelectionRead(mime)` → `tokio::net::unix::pipe::Receiver::from_owned_fd`
   → `take(budget + 1).read_to_end`. Over budget → drop the fd (Mutter
   cancels on the broken pipe) and skip, keeping the rest. A refused type
   (owner changed under us) is skipped like an unreadable Wayland
   representation; the watcher fires again for the new content.

`OfferBudget` is the dedup/machinery/budget policy currently inlined in
`wayland::assemble_offer`, extracted so the async loop here and the sync
loop there cannot drift; `assemble_offer` becomes a thin loop over it and
its tests stay as they are.

### Writes

`write_offer(Clipboard, offer)`: empty → no-op (as Wayland). Otherwise
store `owned = Some(offer)` **first** (a transfer can race the reply), then
`SetSelection({"mime-types": keys in offer order})`. Mutter emits
owner-changed with `session-is-owner = true`, which the watch forwards as
`Changed` — the trait requires an event for our own writes, and
`ClipboardIo`'s marker turns it into `Origin::Echo`.

Serving `SelectionTransfer(mime, serial)`, one task per signal:
`SelectionWrite(serial)` → `pipe::Sender::from_owned_fd` → `write_all` of
`owned[mime]` → drop (EOF) → `SelectionWriteDone(serial, true)`. Any
failure, or a mime not in `owned` (a late request for a replaced source) →
`SelectionWriteDone(serial, false)`. The task is bounded at 10 s so a reader
that never drains cannot pin it and its fd forever. Mutter's own 15 s cleanup
does not cover this: `handle_selection_write` steals the request out of the
pending table, so once we have answered, bounding it is ours to do.

`owned` is replaced only by the next write, and a write that **fails** puts
the previous offer back rather than leaving nothing. A failed `SetSelection`
changed nothing about who Mutter thinks owns the clipboard, so if that was us
we must still be able to serve what we owned. Cleared instead, `is_owner`
stays true (no owner-change signal follows a failed call) while `owned` is
empty, so reads fall through to Mutter — which refuses to let a session read
its own selection — and every transfer is answered with failure: a clipboard
silently dead until the next copy, from one transient D-Bus error. The
restore is guarded on `Arc` identity so a concurrent write that did land is
not undone.

`owned` is never cleared by an owner change. Signals are processed in order, so clearing it on `session-is-owner
= false` would let a user copy announced just before our `SetSelection` wipe
the offer that write had just stored, leaving us owner with nothing to serve.
A straggling transfer for a source that no longer owns is refused by Mutter
itself (`"No current selection owned"`), so stale bytes are never served.

### Watch

Every `SelectionOwnerChanged` → `Changed(Clipboard)`, including our own
(see Writes) and the ownerless one (empty `types`; the engine reads an
empty offer, as it does when a data-control selection is cleared). `kinds`
outside `Clipboard` are ignored — permitted by the trait ("may deliver a
kind outside `kinds`" and, here, may not deliver one inside it, which
`Backend::select` has already ruled out by refusing the config).

A second `watch` call gets `Changed` fan-out from the same session and no
`Initial`; the engine calls it once. **The subscriber list and "is a session
task running" live under one lock** (`Watchers`), and the task's every exit
goes through one `attempt_finished` that prunes dead senders and clears the
flag in the same critical section. Split apart, the two disagree: the task
retiring down an error path (a closed session, a bus error) never pruned its
subscribers, so a later `watch` counted the leftover sender, decided a task
was already running, and returned a receiver nothing would ever send to.
Pairing them also means a subscriber that arrives *as* the task retires is
seen by that decision and keeps it alive, instead of starting a second
session.

### Backend selection and config

`backend` (new, optional):

- `"auto"` (default): `watch::data_control_available()` — one Wayland
  connection and registry roundtrip looking for either manager global —
  picks data-control; otherwise Mutter. A compositor with neither gets the
  Mutter backend's retry loop and an error naming both routes. A probe that
  *errors* also resolves to Mutter, deliberately: the error means there is no
  Wayland display to ask, and the Mutter backend needs none. A GNOME session
  that never exported `WAYLAND_DISPLAY` into the systemd user environment is
  exactly that case, and failing there would turn a working configuration
  into a restart loop under the unit's `Restart=always`. `resolve_kind` takes
  the probe as an argument so this is testable without a compositor.
- `"data-control"`, `"mutter"`: force one; the forced backend's own errors
  say why it cannot connect.

`Backend::select(&cfg)` also refuses, with a hard error at startup,
`sync_selection = true` or any `link_selections` direction on the Mutter
backend: both need PRIMARY, which GNOME does not expose. Loud rather than a
silent degrade, and the config is per host, so the fix is local. The
Selection arms of the trait methods return `Err` for defence in depth.

Nothing changes in `clipmesh.service`: a `systemctl --user` service has the
user bus (`$XDG_RUNTIME_DIR/bus`) without configuration.

### Dependencies

- `zbus = { version = "5", default-features = false, features = ["tokio"] }`.
  The `p2p` feature is added through a `[dev-dependencies]` entry for the
  same crate, so only test builds carry it.
- **MSRV moves from 1.80 to 1.87.** zbus 5.14+ requires 1.87; the last
  zbus with an MSRV ≤ 1.80 is 5.2 (Dec 2024). Pinning that old would be a
  worse trade than raising a floor whose only reason was `trim_ascii`. The
  local toolchain is 1.97.
- `tokio::net::unix::pipe` (tokio ≥ 1.28; the lock has 1.52) for the fds.

### Testing

The Wayland backend is verified by hand because it needs a compositor;
this backend is different: D-Bus is testable in-process. `fake.rs` hosts a
`FakeMutter` over `zbus`'s p2p mode on a `UnixStream::pair()` — no bus
daemon, so it runs in CI — serving the same interfaces via
`#[zbus::interface]`, with hooks (`set_owner(types, is_session)`,
`pull(mime) → bytes`, `close_session()`) and the same refusals as Mutter
(own-source read, parallel read, empty mime list). `MutterClipboard::new`
takes a `BusConnector` (a two-implementation trait: the session bus, or a
socketpair) so production and tests differ only there. Proxies need a
destination even on p2p (zbus `MissingParameter` otherwise); names mean
nothing there, so the well-known name is used unconditionally.

What that pins (each a rule from this document):

- initial owner → one `Initial` with content, before any `Changed`; no
  owner → no `Initial`; an owner change after enable → `Changed` only
- `Closed` → reconnect; the content found then is `Changed`, not `Initial`
- own write → `SetSelection` with the keys in offer order; a transfer is
  served byte-exact with `WriteDone(true)`; an unknown mime → `false`
- reads while owner come from `owned` (the fake refuses like Mutter)
- two concurrent `read_offer`s both succeed (serialized, never refused)
- `only` costs one `SelectionRead`; `list_types` costs none; machinery
  atoms are filtered
- an over-budget representation is skipped and the rest kept
- Selection: ignored by `watch`, `Err` from the other three
- `Backend::select`: the `backend` values, and the PRIMARY refusal

The engine's fake stays `MockClipboard`; nothing there changes.

## Known gaps and behaviour to be aware of

- **Mutter's clipboard manager narrows the offer when the source app
  exits.** It takes over as a memory source holding one saved
  representation, which arrives as an owner change → `Changed` → the engine
  reads a one-type offer whose hash differs from the current one and
  broadcasts it, so peers' clipboards narrow to that type. Not an echo
  storm (it happens once, and the content is the same bytes), but a wart
  wlroots compositors do not have. A later engine-level rule — "a strict
  subset of the current content with identical bytes is not a change" —
  would remove it; out of scope here.
- **A transfer that hits the 10 s bound can reach the requester truncated.**
  The write is already streaming into the pipe, and dropping the writer closes
  it, which a reader cannot tell from a complete transfer;
  `SelectionWriteDone(false)` does not help, because mutter's
  `handle_selection_write_done` never reads the flag (checked against
  `gnome-46` and `main`). A pipe carries no failure signal, so this is the
  price of not leaking a task and an fd per stalled paster. The bound sits far
  above what any real paster takes, and the timeout is logged.
- Same `Initial` read-after-signal window as the Wayland watcher.
- The API is private to Mutter ("for gnome-remote-desktop"); it has a
  `Version` property and a stable clipboard subset since GNOME 42, and the
  backend logs the version it found.

## Decisions worth a second look

1. MSRV 1.80 → 1.87 (vs pinning zbus ≤ 5.12 at MSRV 1.77).
2. Hard error for `sync_selection`/`link_selections` on Mutter (vs warn and
   degrade).
3. `backend` key values `auto`/`data-control`/`mutter`.
