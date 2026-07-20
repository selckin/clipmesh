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
    crate::backoff::supervise("clipboard watcher", || {
        match watch_once(&tx, &watched, max_payload) {
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

    // Report the pre-existing selections as `Initial`, with content, before any
    // `Changed` can follow — the contract on `Clipboard::watch`. Reported from
    // here rather than left for the engine to read back, because a read the
    // engine does later cannot be told apart from a copy the user makes a moment
    // after startup.
    //
    // KNOWN GAP: `read_offer_blocking` opens its own connection, so a copy
    // landing between the roundtrip above and this read is still reported as
    // `Initial`. The window is two immediate operations on this thread rather
    // than the engine's whole scheduling path, but it is not zero. Closing it
    // needs the content read to come off *this* connection's live offer, which
    // is the same in-tree data-control read the per-MIME-type connection storm
    // in `wayland.rs` needs — worth doing once, for both.
    state.draining_initial = false;
    for kind in std::mem::take(&mut state.initial) {
        match read_offer_blocking(kind, max_payload, None) {
            Ok(offer) if !offer.is_empty() => {
                if tx.send(ClipboardEvent::Initial { kind, offer }).is_err() {
                    return Ok(StopReason::ReceiverGone);
                }
            }
            Ok(_) => {}
            Err(e) => warn!("couldn't read the existing {kind:?} selection at startup: {e:#}"),
        }
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
