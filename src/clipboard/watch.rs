//! In-process clipboard change watcher over the Wayland data-control
//! protocol. Replaces a `wl-paste --watch` subprocess: it observes only
//! the `selection`/`primary_selection` events and never reads contents, so
//! no pipe is ever opened (and the broken-pipe class that wiped large
//! copies cannot occur). Reading and writing still go through
//! `wl-clipboard-rs` in `wayland.rs`; this is the last subprocess removed.

use crate::clipboard::wayland::read_offer_blocking;
use crate::clipboard::ClipboardEvent;
use crate::protocol::SelectionKind;
use anyhow::{bail, Context, Result};
use std::ops::ControlFlow;
use std::thread;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use wayland_client::globals::{registry_queue_init, GlobalListContents};
use wayland_client::protocol::wl_registry::WlRegistry;
use wayland_client::protocol::wl_seat::WlSeat;
use wayland_client::{
    delegate_noop, event_created_child, Connection, Dispatch, Proxy, QueueHandle,
};
use wayland_protocols::ext::data_control::v1::client::ext_data_control_device_v1::{
    self, ExtDataControlDeviceV1,
};
use wayland_protocols::ext::data_control::v1::client::ext_data_control_manager_v1::ExtDataControlManagerV1;
use wayland_protocols::ext::data_control::v1::client::ext_data_control_offer_v1::ExtDataControlOfferV1;
use wayland_protocols_wlr::data_control::v1::client::zwlr_data_control_device_v1::{
    self, ZwlrDataControlDeviceV1,
};
use wayland_protocols_wlr::data_control::v1::client::zwlr_data_control_manager_v1::ZwlrDataControlManagerV1;
use wayland_protocols_wlr::data_control::v1::client::zwlr_data_control_offer_v1::ZwlrDataControlOfferV1;

/// Spawn the watcher on a dedicated OS thread (wayland-client's
/// `blocking_dispatch` is blocking, so it can't live on the tokio runtime).
/// A single connection handles every selection the compositor exposes; only
/// changes to a selection in `watched` are forwarded to `tx`. Taking the set
/// (rather than a per-selection flag) keeps the backend free of any assumption
/// about which selections the engine cares about.
pub fn spawn_watcher(
    tx: mpsc::UnboundedSender<ClipboardEvent>,
    watched: Vec<SelectionKind>,
    max_payload: usize,
) {
    thread::spawn(move || run(tx, watched, max_payload));
}

/// Reconnect loop: the same backoff the old subprocess watcher used, so a
/// compositor restart (or a transient Wayland error) is ridden out instead
/// of permanently losing change detection.
fn run(tx: mpsc::UnboundedSender<ClipboardEvent>, watched: Vec<SelectionKind>, max_payload: usize) {
    // Only the first connection is the subscribe; `supervise` reruns this
    // closure for every reconnect. See [`Connect`].
    let mut connect = Connect::Subscribe;
    crate::backoff::supervise("clipboard watcher", || {
        let result = watch_once(&tx, &watched, max_payload, connect);
        connect = Connect::Reconnect;
        match result {
            // engine gone; stop watching
            Ok(StopReason::ReceiverGone) => return ControlFlow::Break(()),
            Ok(StopReason::Finished) => {
                warn!("compositor closed the clipboard watcher; reconnecting")
            }
            Err(e) => error!("clipboard watcher failed: {e:#}"),
        }
        if tx.is_closed() {
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    });
}

/// Why this connection to the compositor is being made — which decides how its
/// startup burst is reported.
///
/// The distinction is load-bearing. `Clipboard::watch` promises `Initial`
/// "as of the subscribe", and the engine acts on that promise: `adopt_restored`
/// records the content at **stamp 0** and deliberately never broadcasts it,
/// because a node cannot know how old its restored clipboard is. That is right
/// for content that was already there when the daemon started, and wrong for
/// everything else — this watcher is supervised, so it reconnects after any
/// compositor restart or transient error, and reporting a reconnect's burst as
/// `Initial` demoted whatever the user had copied in the meantime to stamp 0,
/// where any peer's older clipboard outranked it and overwrote it on the next
/// resync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Connect {
    /// The first connection: this *is* the `watch` call, so what it finds is
    /// pre-existing content.
    Subscribe,
    /// A later connection. The watcher was blind while it was down, so what it
    /// finds now is reported as an ordinary local change: the engine reads it,
    /// stamps it now, and propagates it.
    Reconnect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StopReason {
    /// The notification receiver was dropped (the sync engine exited).
    ReceiverGone,
    /// The compositor invalidated our data-control device.
    Finished,
}

fn watch_once(
    tx: &mpsc::UnboundedSender<ClipboardEvent>,
    watched: &[SelectionKind],
    max_payload: usize,
    connect: Connect,
) -> Result<StopReason> {
    let conn = Connection::connect_to_env().context("connecting to the Wayland display")?;
    let (globals, mut queue) =
        registry_queue_init::<State>(&conn).context("initializing the Wayland registry")?;
    let qh = queue.handle();

    // The data-control device is per-seat; the first seat matches the
    // `Seat::Unspecified` behaviour of the read/write path.
    let _seat: WlSeat = globals
        .bind(&qh, 1..=1, ())
        .context("no wl_seat advertised by the compositor")?;

    // Prefer ext-data-control-v1; fall back to zwlr (bind up to v2 so the
    // primary selection, added in zwlr v2, is available). Match whatever
    // wl-clipboard-rs's read/write side uses. Keep both bind errors so the
    // failure says *why* (e.g. version mismatch) rather than only "unsupported".
    //
    // The device is built directly in each arm: the manager is used once, right
    // here, so naming it in its own enum would be a second two-variant type to
    // keep in lockstep with `Device` for every protocol version added.
    //
    // Keep the device alive for the lifetime of this connection.
    let _device = match globals.bind::<ExtDataControlManagerV1, _, _>(&qh, 1..=1, ()) {
        Ok(m) => {
            info!("clipboard watcher connected (ext-data-control-v1)");
            Device::Ext(m.get_data_device(&_seat, &qh, ()))
        }
        Err(ext_err) => match globals.bind::<ZwlrDataControlManagerV1, _, _>(&qh, 1..=2, ()) {
            Ok(m) => {
                info!("clipboard watcher connected (zwlr-data-control-unstable-v1)");
                Device::Zwlr(m.get_data_device(&_seat, &qh, ()))
            }
            Err(zwlr_err) => bail!(
                "compositor provides no usable data-control protocol (need \
                 ext-data-control-v1 or zwlr-data-control-unstable-v1); GNOME/Mutter \
                 is unsupported. ext: {ext_err}; zwlr: {zwlr_err}"
            ),
        },
    };

    let mut state = State {
        tx: tx.clone(),
        watched: watched.to_vec(),
        dead: false,
        finished: false,
        draining_initial: true,
        initial: Vec::new(),
    };

    // Flush the device request and drain the compositor's initial burst
    // (which includes a selection event for the current clipboard — the
    // same one-shot startup fire wl-paste --watch produced).
    queue
        .roundtrip(&mut state)
        .context("initial Wayland roundtrip")?;

    // Report the selections the compositor's burst named, before any `Changed`
    // can follow — the contract on `Clipboard::watch`. Reported from here rather
    // than left for the engine to read back, because a read the engine does
    // later cannot be told apart from a copy the user makes a moment after
    // startup.
    //
    // KNOWN GAP: `read_offer_blocking` opens its own connection, so a copy
    // landing between the roundtrip above and this read is still reported as
    // `Initial`. The window is two immediate operations on this thread rather
    // than the engine's whole scheduling path, but it is not zero. Closing it
    // needs the content read to come off *this* connection's live offer, which
    // is the same in-tree data-control read the per-MIME-type connection storm
    // in `wayland.rs` needs — worth doing once, for both.
    state.draining_initial = false;
    if let ControlFlow::Break(stop) =
        report_startup(connect, std::mem::take(&mut state.initial), tx, |kind| {
            read_offer_bounded(kind, max_payload)
        })
    {
        return Ok(stop);
    }

    loop {
        if state.dead {
            return Ok(StopReason::ReceiverGone);
        }
        if state.finished {
            return Ok(StopReason::Finished);
        }
        queue
            .blocking_dispatch(&mut state)
            .context("Wayland event dispatch")?;
    }
}

/// Report the selections the compositor named in its startup burst, as
/// [`Connect`] dictates: content-carrying `Initial` on the subscribe, a plain
/// `Changed` on a reconnect.
///
/// Takes the read as a closure so the rule can be tested without a compositor —
/// which is the only way any of this file is covered, and the reconnect arm's
/// whole point is that it does *not* call the reader.
fn report_startup(
    connect: Connect,
    initial: Vec<SelectionKind>,
    tx: &mpsc::UnboundedSender<ClipboardEvent>,
    read: impl Fn(SelectionKind) -> Result<crate::protocol::Offer>,
) -> ControlFlow<StopReason> {
    for kind in initial {
        let event = match connect {
            // A reconnect's find is an ordinary local change. `Changed` carries
            // no content, so this arm reads nothing at all — the engine reads
            // lazily, which is also what stamps it *now* rather than at 0.
            Connect::Reconnect => ClipboardEvent::Changed(kind),
            Connect::Subscribe => match read(kind) {
                // An empty selection has nothing to restore, so it is omitted
                // entirely — the `Initial` contract.
                Ok(offer) if offer.is_empty() => continue,
                Ok(offer) => ClipboardEvent::Initial { kind, offer },
                // One unreadable selection must not cost the host change
                // detection on the others.
                Err(e) => {
                    warn!("couldn't read the existing {kind:?} selection at startup: {e:#}");
                    continue;
                }
            },
        };
        if tx.send(event).is_err() {
            return ControlFlow::Break(StopReason::ReceiverGone);
        }
    }
    ControlFlow::Continue(())
}

/// [`read_offer_blocking`] with a hard bound, performed on a thread of its own.
///
/// The read blocks in `read_to_end` on a pipe the *selection owner* is
/// responsible for writing, so a frozen source (or one whose process is stopped)
/// never returns. It runs on the watcher thread, ahead of the dispatch loop that
/// detects every clipboard change on this host — so leaving it unbounded did not
/// make one copy slow, it made the daemon permanently deaf, with `watch_once`
/// never returning for `supervise` to restart and nothing logged. Every read the
/// engine performs is bounded for exactly this reason
/// (`ClipboardIo::READ_TIMEOUT`); this one, on the path everything else depends
/// on, was not.
///
/// The reader thread is detached, not joined: if it is stuck it stays stuck, and
/// waiting on it is the thing being avoided. It holds only its own connection,
/// and the compositor tears that down when the process exits.
fn read_offer_bounded(kind: SelectionKind, max_payload: usize) -> Result<crate::protocol::Offer> {
    let (done, wait) = std::sync::mpsc::channel();
    thread::spawn(move || {
        // The receiver is gone on timeout; the send simply fails, which is the
        // detachment.
        let _ = done.send(read_offer_blocking(kind, max_payload, None));
    });
    match wait.recv_timeout(STARTUP_READ_TIMEOUT) {
        Ok(result) => result,
        Err(_) => bail!(
            "the {kind:?} selection's owner did not serve its content within \
             {STARTUP_READ_TIMEOUT:?}; skipping it so change detection can start"
        ),
    }
}

/// Bound for the startup content read — see [`read_offer_bounded`]. Matches
/// `ClipboardIo::READ_TIMEOUT`: a real read of the size-capped clipboard takes
/// milliseconds, so exceeding this means the source is not serving its pipe.
const STARTUP_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[allow(dead_code)] // held only to keep the device proxy alive
enum Device {
    Ext(ExtDataControlDeviceV1),
    Zwlr(ZwlrDataControlDeviceV1),
}

struct State {
    tx: mpsc::UnboundedSender<ClipboardEvent>,
    watched: Vec<SelectionKind>,
    dead: bool,
    finished: bool,
    /// True while the compositor's initial burst is being drained. Selections
    /// reported during it are the *existing* clipboard, not a change, so they
    /// are collected here and reported as `Initial` instead of `Changed`.
    draining_initial: bool,
    initial: Vec<SelectionKind>,
}

impl State {
    fn notify(&mut self, kind: SelectionKind) {
        if !self.watched.contains(&kind) {
            return;
        }
        if self.draining_initial {
            if !self.initial.contains(&kind) {
                self.initial.push(kind);
            }
            return;
        }
        if self.tx.send(ClipboardEvent::Changed(kind)).is_err() {
            self.dead = true;
        }
    }
}

// The seat, managers and offers carry no events we care about. Offers do
// emit one `offer(mime)` event per MIME type before their selection event;
// we ignore those — the watcher needs only the "changed" signal, never the
// contents. Each offer is destroyed when its selection event arrives (see
// the device impl), so they don't accumulate.
delegate_noop!(State: ignore WlSeat);
delegate_noop!(State: ignore ExtDataControlManagerV1);
delegate_noop!(State: ignore ZwlrDataControlManagerV1);
delegate_noop!(State: ignore ExtDataControlOfferV1);
delegate_noop!(State: ignore ZwlrDataControlOfferV1);

impl Dispatch<WlRegistry, GlobalListContents> for State {
    fn event(
        _state: &mut Self,
        _proxy: &WlRegistry,
        _event: <WlRegistry as Proxy>::Event,
        _data: &GlobalListContents,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

/// One `Dispatch` impl per concrete device type (ext and zwlr). The only
/// events that matter are the selection ones; a `data_offer` introduces an
/// offer object that we let live (its MIME events are ignored) until its
/// selection event, where we destroy it after signalling the change.
macro_rules! impl_device_dispatch {
    ($device:ty, $offer:ty, $offer_opcode:path) => {
        impl Dispatch<$device, ()> for State {
            fn event(
                state: &mut Self,
                _device: &$device,
                event: <$device as Proxy>::Event,
                _data: &(),
                _conn: &Connection,
                _qh: &QueueHandle<Self>,
            ) {
                type Event = <$device as Proxy>::Event;
                match event {
                    Event::Selection { id } => {
                        if let Some(offer) = id {
                            offer.destroy();
                        }
                        state.notify(SelectionKind::Clipboard);
                    }
                    Event::PrimarySelection { id } => {
                        if let Some(offer) = id {
                            offer.destroy();
                        }
                        state.notify(SelectionKind::Selection);
                    }
                    Event::Finished => state.finished = true,
                    // DataOffer (the proxy is kept until its selection event)
                    // and any future events: nothing to do.
                    _ => {}
                }
            }

            event_created_child!(State, $device, [
                $offer_opcode => ($offer, ()),
            ]);
        }
    };
}

impl_device_dispatch!(
    ZwlrDataControlDeviceV1,
    ZwlrDataControlOfferV1,
    zwlr_data_control_device_v1::EVT_DATA_OFFER_OPCODE
);
impl_device_dispatch!(
    ExtDataControlDeviceV1,
    ExtDataControlOfferV1,
    ext_data_control_device_v1::EVT_DATA_OFFER_OPCODE
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Offer;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn offer(body: &str) -> Offer {
        let mut o = Offer::new();
        o.insert("text/plain".to_string(), body.as_bytes().to_vec());
        o
    }

    /// The first connection to the compositor *is* the subscribe, so what its
    /// startup burst finds is pre-existing content: `Initial`, carrying the
    /// content the backend captured.
    #[test]
    fn the_first_connection_reports_pre_existing_content_as_initial() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let flow = report_startup(
            Connect::Subscribe,
            vec![SelectionKind::Clipboard],
            &tx,
            |_| Ok(offer("existing")),
        );

        assert!(flow.is_continue());
        assert_eq!(
            rx.try_recv().unwrap(),
            ClipboardEvent::Initial {
                kind: SelectionKind::Clipboard,
                offer: offer("existing"),
            }
        );
    }

    /// A reconnect is not a subscribe. The watcher was blind for as long as the
    /// compositor was away, so whatever the selection holds now may be a copy
    /// the user made during the outage — a live change. Reporting it as
    /// `Initial` had the engine record it at stamp 0 and never broadcast it, so
    /// any peer's older clipboard outranked it and overwrote it on the next
    /// resync; the copy was lost mesh-wide.
    #[test]
    fn a_reconnect_reports_what_it_finds_as_a_live_change() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let reads = AtomicUsize::new(0);
        let flow = report_startup(
            Connect::Reconnect,
            vec![SelectionKind::Clipboard],
            &tx,
            |_| {
                reads.fetch_add(1, Ordering::SeqCst);
                Ok(offer("copied while the compositor was away"))
            },
        );

        assert!(flow.is_continue());
        assert_eq!(
            rx.try_recv().unwrap(),
            ClipboardEvent::Changed(SelectionKind::Clipboard),
            "a reconnect must report a live change, not restored content"
        );
        assert_eq!(
            reads.load(Ordering::SeqCst),
            0,
            "`Changed` carries no content, so the reconnect path must not read one"
        );
    }

    /// An empty selection has nothing to restore, so it is omitted entirely —
    /// the `Initial` contract on `ClipboardEvent`.
    #[test]
    fn an_empty_selection_is_not_reported_at_all() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let flow = report_startup(
            Connect::Subscribe,
            vec![SelectionKind::Clipboard],
            &tx,
            |_| Ok(Offer::new()),
        );

        assert!(flow.is_continue());
        assert!(rx.try_recv().is_err(), "an empty selection was reported");
    }

    /// A read that fails is logged and skipped; it must not take the watcher
    /// down, or one unreadable selection would cost the host change detection.
    #[test]
    fn an_unreadable_selection_is_skipped_not_fatal() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let flow = report_startup(
            Connect::Subscribe,
            vec![SelectionKind::Clipboard, SelectionKind::Selection],
            &tx,
            |kind| match kind {
                SelectionKind::Clipboard => bail!("the owner never served its pipe"),
                _ => Ok(offer("fine")),
            },
        );

        assert!(flow.is_continue());
        assert_eq!(
            rx.try_recv().unwrap(),
            ClipboardEvent::Initial {
                kind: SelectionKind::Selection,
                offer: offer("fine"),
            }
        );
    }

    /// The engine going away is the one reason to stop: `supervise` retires the
    /// watcher rather than reconnecting into a closed channel forever.
    #[test]
    fn a_dropped_receiver_stops_the_watcher() {
        let (tx, rx) = mpsc::unbounded_channel();
        drop(rx);
        let flow = report_startup(
            Connect::Subscribe,
            vec![SelectionKind::Clipboard],
            &tx,
            |_| Ok(offer("existing")),
        );

        assert_eq!(flow, ControlFlow::Break(StopReason::ReceiverGone));
    }
}
