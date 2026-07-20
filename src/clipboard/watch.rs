//! In-process clipboard change watcher over the Wayland data-control
//! protocol. Replaces a `wl-paste --watch` subprocess: it observes only
//! the `selection`/`primary_selection` events and never reads contents, so
//! no pipe is ever opened (and the broken-pipe class that wiped large
//! copies cannot occur). Reading and writing still go through
//! `wl-clipboard-rs` in `wayland.rs`; this is the last subprocess removed.

use crate::protocol::SelectionKind;
use anyhow::{bail, Context, Result};
use std::thread;
use std::time::Instant;
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
/// A single connection handles both the clipboard and the middle-click
/// selection; the latter's events are forwarded to `tx` only when
/// `watch_selection` is true.
pub fn spawn_watcher(tx: mpsc::UnboundedSender<SelectionKind>, watch_selection: bool) {
    thread::spawn(move || run(tx, watch_selection));
}

/// Reconnect loop: the same backoff the old subprocess watcher used, so a
/// compositor restart (or a transient Wayland error) is ridden out instead
/// of permanently losing change detection.
fn run(tx: mpsc::UnboundedSender<SelectionKind>, watch_selection: bool) {
    let mut backoff = crate::backoff::watcher_restart();
    loop {
        let started = Instant::now();
        match watch_once(&tx, watch_selection) {
            Ok(StopReason::ReceiverGone) => return, // engine gone; stop watching
            Ok(StopReason::Finished) => {
                warn!("compositor closed the clipboard watcher; reconnecting")
            }
            Err(e) => error!("clipboard watcher failed: {e:#}"),
        }
        if tx.is_closed() {
            return;
        }
        backoff.reset_if_stable(started.elapsed(), crate::backoff::RESTART_STABLE_AFTER);
        let delay = backoff.next_delay();
        warn!("restarting the clipboard watcher in {delay:?}");
        thread::sleep(delay);
    }
}

enum StopReason {
    /// The notification receiver was dropped (the sync engine exited).
    ReceiverGone,
    /// The compositor invalidated our data-control device.
    Finished,
}

fn watch_once(
    tx: &mpsc::UnboundedSender<SelectionKind>,
    watch_selection: bool,
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
    let manager = match globals.bind::<ExtDataControlManagerV1, _, _>(&qh, 1..=1, ()) {
        Ok(m) => {
            info!("clipboard watcher connected (ext-data-control-v1)");
            Manager::Ext(m)
        }
        Err(ext_err) => match globals.bind::<ZwlrDataControlManagerV1, _, _>(&qh, 1..=2, ()) {
            Ok(m) => {
                info!("clipboard watcher connected (zwlr-data-control-unstable-v1)");
                Manager::Zwlr(m)
            }
            Err(zwlr_err) => bail!(
                "compositor provides no usable data-control protocol (need \
                 ext-data-control-v1 or zwlr-data-control-unstable-v1); GNOME/Mutter \
                 is unsupported. ext: {ext_err}; zwlr: {zwlr_err}"
            ),
        },
    };

    // Keep the device alive for the lifetime of this connection.
    let _device = match &manager {
        Manager::Ext(m) => Device::Ext(m.get_data_device(&_seat, &qh, ())),
        Manager::Zwlr(m) => Device::Zwlr(m.get_data_device(&_seat, &qh, ())),
    };

    let mut state = State {
        tx: tx.clone(),
        watch_selection,
        dead: false,
        finished: false,
    };

    // Flush the device request and drain the compositor's initial burst
    // (which includes a selection event for the current clipboard — the
    // same one-shot startup fire wl-paste --watch produced).
    queue
        .roundtrip(&mut state)
        .context("initial Wayland roundtrip")?;
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

enum Manager {
    Ext(ExtDataControlManagerV1),
    Zwlr(ZwlrDataControlManagerV1),
}

#[allow(dead_code)] // held only to keep the device proxy alive
enum Device {
    Ext(ExtDataControlDeviceV1),
    Zwlr(ZwlrDataControlDeviceV1),
}

struct State {
    tx: mpsc::UnboundedSender<SelectionKind>,
    watch_selection: bool,
    dead: bool,
    finished: bool,
}

impl State {
    fn notify(&mut self, kind: SelectionKind) {
        if kind == SelectionKind::Selection && !self.watch_selection {
            return;
        }
        if self.tx.send(kind).is_err() {
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
