# clipmesh — in-process clipboard change watcher

**Date:** 2026-06-13
**Status:** Approved design

## Summary

Replace the `wl-paste --watch` subprocess used for clipboard change
detection with an in-process Wayland data-control listener. After this
change clipmesh shells out to no external process at all: reads and
writes already go through the `wl-clipboard-rs` library in-process, and
this moves the last remaining subprocess (change watching) in-process
too.

This also removes the entire broken-pipe failure class fixed in
`f17d241`: the listener never opens a pipe to read clipboard contents,
it only observes selection-change events, so it cannot break the
selection owner's pipe and wipe the clipboard.

## Motivation

- The only forked process left is `wl-paste --watch`. Reads
  (`get_mime_types`/`get_contents`) and writes (`copy_multi`) are
  library calls.
- `wl-paste --watch CMD` pipes the full clipboard contents to `CMD` on
  every change; a command that does not drain stdin breaks the pipe and,
  above the ~64 KiB pipe buffer, destroys the selection. We worked
  around it by draining (`cat >/dev/null`), but an in-process listener
  that never reads contents removes the hazard structurally.
- Drops the `wl-clipboard` binary as a runtime dependency.

## Non-goals (YAGNI)

- Replacing `wl-clipboard-rs` for reads/writes. Those are in-process
  already and the `copy` serve loop is the tricky part we just debugged;
  keep using the library for it.
- Reading clipboard contents in the watcher. It needs only the "changed"
  signal; `SyncEngine` reads the contents via the existing path.
- Watching X11/other backends. The `Clipboard` trait stays open for them
  but this change is Wayland data-control only.

## Architecture

`src/clipboard/watch.rs` (new) implements the listener. `wayland.rs`
keeps the read/write code; its `watch()` method calls into the new
listener instead of spawning subprocesses. The `Clipboard` trait is
unchanged, so `SyncEngine` and all existing tests are untouched.

| Unit | Responsibility |
|------|----------------|
| `watch.rs::spawn_watcher` | Own a Wayland connection on a dedicated OS thread, translate data-control `selection`/`primary_selection` events into `SelectionKind` notifications, reconnect with backoff. |
| `wayland.rs::watch` | Create the mpsc channel and call `spawn_watcher`. |

### Threading

`wayland-client`'s `blocking_dispatch` is blocking, so the listener runs
on a dedicated `std::thread`, not the tokio runtime. A single connection
and device observe **both** the regular and primary selections, so one
thread replaces today's two `wl-paste` processes. Notifications are sent
on the existing `tokio::sync::mpsc::UnboundedSender<SelectionKind>`
(unbounded `send` is non-async and safe from a plain thread). When the
receiver is dropped (`send` errors), the thread exits.

### Protocol binding

Mirror `wl-clipboard-rs`: prefer `ext_data_control_manager_v1`, fall
back to `zwlr_data_control_manager_v1` (bind `1..=2` so primary
selection, added in zwlr v2, is available). Bind the first `wl_seat`
(matches the `Seat::Unspecified` behaviour of the read path) and call
`get_data_device(seat)`. `Dispatch` impls exist for both concrete
device and offer types; every impl ignores all events except the device
selection events.

### Data flow

The device event sequence per change is: `data_offer(new offer)` →
`offer(mime)`* → `selection(Option<offer>)` (and likewise
`primary_selection`). The listener:

1. On `data_offer`: store the new offer proxy as "pending" (destroying
   any previous pending proxy first, to avoid leaks).
2. On `offer(mime)`: ignore — contents/MIME types are not needed here.
3. On `selection(Some|None)`: send `SelectionKind::Clipboard`; destroy
   the pending offer. (`primary_selection` → `SelectionKind::Primary`,
   only when `sync_primary`.)

The listener **never calls `receive()`**, so no pipe is opened and the
broken-pipe class is impossible. On bind the device emits one
`selection` event reflecting current state — the same one-shot startup
fire `wl-paste --watch` produces today, suppressed by `prime()`'s
stamp-0 record exactly as before.

### Error handling / reconnect

Connect + dispatch run in a reconnect loop with the same backoff the
subprocess watcher uses (1 s → 30 s, reset after a stable run). A
`finished` event or any dispatch/connection error triggers reconnect. If
no data-control manager is advertised, log an actionable error naming
`ext-data-control-v1` / `zwlr-data-control-unstable-v1` instead of the
old "is wl-clipboard installed?".

## Dependencies

Add direct deps already present transitively (matching `wl-clipboard-rs`
versions/features): `wayland-client`, `wayland-protocols` (ext
data-control), `wayland-protocols-wlr` (wlr data-control). No new
third-party tooling; these are the official Smithay Wayland crates.

The `wl-clipboard` package is no longer a runtime requirement; update the
README accordingly.

## Testing

The listener requires a live compositor, so — like the subprocess it
replaces — it is verified manually on niri, not in CI. The `Clipboard`
trait is unchanged, so every mock-based engine/integration test stays
green. Real verification: copy an image (and text) across the two hosts
and confirm it persists and pastes.

## Risks

- `Dispatch` boilerplate for two protocols is verbose but mechanical;
  the listener loop itself is simpler than a subprocess + pipe.
- The watcher remains the one component without automated coverage
  (unchanged from today).
