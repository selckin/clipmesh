//! GNOME clipboard backend over Mutter's remote-desktop D-Bus API.
//!
//! Mutter implements neither data-control protocol (mutter#524, mutter#3941),
//! so `clipboard::wayland` cannot connect on GNOME at all. What Mutter exposes
//! instead is the clipboard half of `org.gnome.Mutter.RemoteDesktop.Session`
//! on the session bus — the API gnome-remote-desktop's RDP clipboard uses —
//! and it maps onto the [`Clipboard`] trait one-to-one. See
//! `docs/superpowers/specs/2026-09-02-mutter-clipboard-backend-design.md`.
//!
//! Three rules of Mutter's, verified in its `meta-remote-desktop-session.c`,
//! shape everything here:
//!
//! - **Our own content cannot be read back through Mutter** ("Tried to read
//!   own selection"), so while the session owns the clipboard, reads are
//!   answered from the offer we set. That is also the echo path: the engine's
//!   marker compares hashes, and these are the bytes it wrote.
//! - **One `SelectionRead` may be pending per session** ("Tried to read in
//!   parallel"), so every read takes [`Shared::read_lock`]. The engine and the
//!   `--paste` server do overlap.
//! - **Mutter announces the current owner from inside `EnableClipboard`,
//!   before completing the call.** D-Bus delivers in order on one connection
//!   and zbus feeds every stream from one in-order reader, so once the reply is
//!   in, the `Initial` signal is already queued: draining it is exact, not a
//!   timing guess.
//!
//! The session is never `Start`ed: that is what creates the remote-access
//! handle behind GNOME's top-bar "remote desktop" indicator, and the clipboard
//! members do not need it.
//!
//! CLIPBOARD only. The API does not reach PRIMARY, which `Backend::select`
//! has already refused in the config before this backend is built; the
//! Selection arms here are defence in depth.

pub(crate) mod proxies;

#[cfg(test)]
pub(crate) mod fake;

use crate::backoff::supervise_async;
use crate::clipboard::budget::OfferBudget;
use crate::clipboard::{Clipboard, ClipboardEvent, Connect, STARTUP_READ_TIMEOUT};
use crate::protocol::{describe_offer, type_matches, Offer, SelectionKind};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use futures_util::{FutureExt, StreamExt};
use proxies::{
    mime_types_option, parse_owner_changed, OwnerChange, RemoteDesktopProxy,
    RemoteDesktopSessionProxy,
};
use std::collections::HashMap;
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::pipe;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use zbus::Connection;

/// How the backend reaches Mutter. Production connects to the session bus;
/// the tests hand it one end of a socketpair with a fake Mutter on the other.
#[async_trait]
pub trait BusConnector: Send + Sync + 'static {
    async fn connect(&self) -> Result<Connection>;
}

/// The user's session bus, where Mutter lives.
pub struct SessionBus;

#[async_trait]
impl BusConnector for SessionBus {
    async fn connect(&self) -> Result<Connection> {
        Ok(Connection::session().await?)
    }
}

/// Bound on serving one `SelectionTransfer`, so a paster that never drains its
/// pipe cannot pin the task and its fd forever. Mutter's own 15 s cleanup does
/// **not** cover this: `handle_selection_write` steals the request out of its
/// pending table, so once we have answered with `SelectionWrite` the request is
/// ours to bound.
///
/// Hitting it is not free, and cannot be made free: the write is already
/// streaming into the pipe, and dropping the writer closes it, which the
/// requester cannot tell from a complete transfer. `SelectionWriteDone(false)`
/// does not help — mutter's `handle_selection_write_done` never reads the flag
/// (checked against `gnome-46` and `main`). A pipe carries no failure signal,
/// so a truncated representation is the price of not leaking; the value is set
/// far above what any real paster takes, and the timeout is logged.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(10);

/// Clipboard over Mutter's remote-desktop clipboard API.
pub struct MutterClipboard {
    shared: Arc<Shared>,
    connector: Arc<dyn BusConnector>,
}

/// Who wants clipboard events, and whether a session task is serving them.
///
/// One lock over both, because the two are decided together: `watch` starts a
/// task exactly when none is running, and the task retires exactly when the
/// last receiver is gone. Split across a `Vec` and a flag they could disagree —
/// a subscriber arriving as the task retires would either be left with a
/// receiver nothing ever sends to, or start a second session.
#[derive(Default)]
struct Watchers {
    senders: Vec<mpsc::UnboundedSender<ClipboardEvent>>,
    task_running: bool,
}

/// State the session task and the trait methods share.
struct Shared {
    max_payload: usize,
    transfer_timeout: Duration,
    /// The enabled session, once there is one; `None` until then and again
    /// after Mutter closes it. Every trait method starts by taking a clone.
    session: Mutex<Option<RemoteDesktopSessionProxy<'static>>>,
    /// The last `SelectionOwnerChanged`'s type list, in advertise order. Mutter
    /// has no query method: this *is* the answer to `list_types`.
    types: Mutex<Vec<String>>,
    /// The last `SelectionOwnerChanged`'s `session-is-owner`.
    is_owner: AtomicBool,
    /// What we last `SetSelection`ed: served to transfers and to our own
    /// reads. Replaced only by the next write — see `apply`.
    owned: Mutex<Option<Arc<Offer>>>,
    /// Mutter allows one pending `SelectionRead` per session.
    read_lock: tokio::sync::Mutex<()>,
    /// Set once `EnableClipboard` has succeeded for the first time: what an
    /// attempt after that finds was possibly copied while we were blind.
    subscribed: AtomicBool,
    watchers: Mutex<Watchers>,
    /// Attempts that got through their startup report; what the tests wait on.
    #[cfg(test)]
    ready: std::sync::atomic::AtomicUsize,
    /// Times the session task has retired. A test that wants the "no task is
    /// running" state has to wait for it, or it races the retirement and
    /// silently exercises the live-task path instead.
    #[cfg(test)]
    retired: std::sync::atomic::AtomicUsize,
}

impl MutterClipboard {
    pub fn new(max_payload: usize, connector: Arc<dyn BusConnector>) -> MutterClipboard {
        Self::with_transfer_timeout(max_payload, connector, TRANSFER_TIMEOUT)
    }

    fn with_transfer_timeout(
        max_payload: usize,
        connector: Arc<dyn BusConnector>,
        transfer_timeout: Duration,
    ) -> MutterClipboard {
        MutterClipboard {
            shared: Arc::new(Shared {
                max_payload,
                transfer_timeout,
                session: Mutex::new(None),
                types: Mutex::new(Vec::new()),
                is_owner: AtomicBool::new(false),
                owned: Mutex::new(None),
                read_lock: tokio::sync::Mutex::new(()),
                subscribed: AtomicBool::new(false),
                watchers: Mutex::new(Watchers::default()),
                #[cfg(test)]
                ready: std::sync::atomic::AtomicUsize::new(0),
                #[cfg(test)]
                retired: std::sync::atomic::AtomicUsize::new(0),
            }),
            connector,
        }
    }
}

fn unsupported(kind: SelectionKind) -> anyhow::Error {
    anyhow::anyhow!(
        "the {kind:?} selection is not available through Mutter's clipboard API (GNOME exposes only CLIPBOARD)"
    )
}

impl Shared {
    fn session(&self) -> Result<RemoteDesktopSessionProxy<'static>> {
        self.session
            .lock()
            .unwrap()
            .clone()
            .context("not connected to Mutter's clipboard API")
    }

    /// Fan an event out; `false` once nobody is listening any more.
    fn notify(&self, event: ClipboardEvent) -> bool {
        let mut watchers = self.watchers.lock().unwrap();
        watchers.senders.retain(|tx| tx.send(event.clone()).is_ok());
        !watchers.senders.is_empty()
    }

    /// End of one session attempt: drop the subscribers whose receivers are
    /// gone and decide whether to keep the task alive, clearing `task_running`
    /// in the *same* critical section when it retires.
    ///
    /// That pairing is the whole point. A `watch` that lands before this
    /// decision is seen by it, so the task keeps going and serves it; one that
    /// lands after finds `task_running == false` and starts a task of its own.
    /// Neither can fall between the two.
    fn attempt_finished(&self) -> ControlFlow<()> {
        let mut watchers = self.watchers.lock().unwrap();
        watchers.senders.retain(|tx| !tx.is_closed());
        if watchers.senders.is_empty() {
            watchers.task_running = false;
            #[cfg(test)]
            self.retired.fetch_add(1, Ordering::SeqCst);
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }

    fn apply(&self, change: &OwnerChange) {
        *self.types.lock().unwrap() = change.types.clone();
        self.is_owner
            .store(change.session_is_owner, Ordering::SeqCst);
        // `owned` is deliberately NOT cleared when someone else takes over.
        // Signals are processed in order, so a user copy announced just before
        // our `SetSelection` would otherwise wipe the offer that write had just
        // stored, leaving us owner with nothing to serve. A straggling transfer
        // for a source that no longer owns is refused by Mutter itself
        // ("No current selection owned"), never served stale bytes by us.
    }

    /// Our own content, when the session is the owner. `None` otherwise.
    fn owned_content(&self) -> Option<Arc<Offer>> {
        if !self.is_owner.load(Ordering::SeqCst) {
            return None;
        }
        self.owned.lock().unwrap().clone()
    }

    fn list_types(&self) -> Vec<String> {
        if let Some(owned) = self.owned_content() {
            return owned.keys().cloned().collect();
        }
        let mut types = self.types.lock().unwrap().clone();
        types.retain(|m| !crate::clipboard::atoms::is_machinery(m));
        types.dedup();
        types
    }

    async fn read_offer(&self, only: Option<&str>) -> Result<Offer> {
        if let Some(owned) = self.owned_content() {
            let mut offer = (*owned).clone();
            if let Some(want) = only {
                offer.retain(|k, _| type_matches(k, want));
            }
            return Ok(offer);
        }
        let session = self.session()?;
        let mut types = self.types.lock().unwrap().clone();
        // Narrow before reading, not after: each surviving type costs a D-Bus
        // roundtrip and a pipe read.
        if let Some(want) = only {
            types.retain(|m| type_matches(m, want));
        }
        debug!("reading the Clipboard clipboard via Mutter; offered types: {types:?}");
        let _one_at_a_time = self.read_lock.lock().await;
        let mut budget = OfferBudget::new(self.max_payload);
        for mime in types {
            let Some(allowed) = budget.plan(&mime) else {
                continue;
            };
            match read_one(&session, &mime, allowed).await {
                Ok(data) => {
                    budget.accept(mime, data);
                }
                Err(e) => OfferBudget::skip_unreadable(&mime, &e),
            }
        }
        let (offer, total) = budget.finish();
        debug!(
            "captured the Clipboard clipboard: {} type(s), {}",
            offer.len(),
            crate::protocol::human_bytes(total)
        );
        Ok(offer)
    }

    async fn write_offer(&self, offer: Arc<Offer>) -> Result<()> {
        if offer.is_empty() {
            debug!("nothing to write to the Clipboard clipboard (empty offer)");
            return Ok(());
        }
        let session = self.session()?;
        debug!(
            "writing the Clipboard clipboard via Mutter ({})",
            describe_offer(&offer)
        );
        let types: Vec<String> = offer.keys().cloned().collect();
        // Stored before the call: Mutter's clipboard manager requests the
        // content the moment the owner changes, which can race the reply.
        let previous = self.owned.lock().unwrap().replace(offer.clone());
        if let Err(e) = session.set_selection(mime_types_option(&types)).await {
            // Put the previous offer back rather than leaving nothing behind.
            // A call that failed changed nothing about who Mutter thinks owns
            // the clipboard, so if that was us, we must still be able to serve
            // what we owned. Cleared instead, `is_owner` stays true (no
            // owner-change signal follows a failed call) while `owned` is
            // empty, so reads fall through to Mutter — which refuses to let a
            // session read its own selection — and every transfer is answered
            // with failure. That is a clipboard silently dead until the next
            // copy, from one transient D-Bus error. Guarded on identity so a
            // concurrent write that did land is not undone.
            let mut owned = self.owned.lock().unwrap();
            if owned.as_ref().is_some_and(|o| Arc::ptr_eq(o, &offer)) {
                *owned = previous;
            }
            return Err(e).context("SetSelection");
        }
        Ok(())
    }
}

/// One representation, read up to `budget + 1` bytes (so the caller can see an
/// overflow), off the pipe Mutter hands out for it.
async fn read_one(
    session: &RemoteDesktopSessionProxy<'static>,
    mime: &str,
    budget: usize,
) -> Result<Vec<u8>> {
    let fd = session
        .selection_read(mime)
        .await
        .with_context(|| format!("SelectionRead({mime})"))?;
    let rx = pipe::Receiver::from_owned_fd(fd.into()).context("the fd Mutter handed out")?;
    // Pre-size within reason (see wayland.rs for the arithmetic).
    const PRESIZE_CAP: usize = 256 * 1024;
    let mut data = Vec::with_capacity((budget + 1).min(PRESIZE_CAP));
    rx.take(budget as u64 + 1).read_to_end(&mut data).await?;
    // Dropping `rx` before EOF is the designed abort: Mutter polls the pipe
    // for the error and cancels its side.
    Ok(data)
}

/// Answer one `SelectionTransfer` with the representation from `owned`.
async fn serve_transfer(
    shared: Arc<Shared>,
    session: RemoteDesktopSessionProxy<'static>,
    mime: String,
    serial: u32,
) {
    let owned = shared.owned.lock().unwrap().clone();
    let attempt = async {
        let bytes = owned.as_ref().and_then(|o| o.get(&mime)).with_context(|| {
            format!("{mime} is not part of the content we own (a stale request)")
        })?;
        let fd = session
            .selection_write(serial)
            .await
            .context("SelectionWrite")?;
        let mut tx = pipe::Sender::from_owned_fd(fd.into()).context("the fd Mutter handed out")?;
        tx.write_all(bytes).await?;
        drop(tx); // EOF
        debug!("served clipboard type {mime} to Mutter (transfer {serial})");
        anyhow::Ok(())
    };
    let timeout = shared.transfer_timeout;
    let success = match tokio::time::timeout(timeout, attempt).await {
        Ok(Ok(())) => true,
        Ok(Err(e)) => {
            warn!("couldn't serve clipboard type {mime} to Mutter: {e:#}");
            false
        }
        Err(_) => {
            warn!(
                "giving up serving clipboard type {mime}: the paster didn't take it within \
                 {timeout:?} (it may see a truncated value — see TRANSFER_TIMEOUT)"
            );
            false
        }
    };
    if let Err(e) = session.selection_write_done(serial, success).await {
        debug!("SelectionWriteDone({serial}) failed: {e:#}");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    /// Every subscriber is gone (the sync engine exited).
    EngineGone,
    /// Mutter closed the session.
    SessionClosed,
}

/// The supervised session loop. Only the first successful subscribe reports
/// `Initial`; see [`Connect`].
async fn run(shared: Arc<Shared>, connector: Arc<dyn BusConnector>) {
    supervise_async("Mutter clipboard session", || {
        let shared = shared.clone();
        let connector = connector.clone();
        async move {
            let result = session_once(&shared, &connector).await;
            *shared.session.lock().unwrap() = None;
            match result {
                Ok(Stop::EngineGone) => debug!("every clipboard subscriber is gone"),
                Ok(Stop::SessionClosed) => {
                    warn!("Mutter closed the clipboard session; reconnecting")
                }
                Err(e) => error!("Mutter clipboard session failed: {e:#}"),
            }
            // Every exit goes through one decision, so no path can retire the
            // task while a subscriber is still waiting on it.
            shared.attempt_finished()
        }
    })
    .await;
}

async fn session_once(shared: &Arc<Shared>, connector: &Arc<dyn BusConnector>) -> Result<Stop> {
    let conn = connector
        .connect()
        .await
        .context("connecting to the session bus")?;
    let manager = RemoteDesktopProxy::new(&conn)
        .await
        .context("building the Mutter remote-desktop proxy")?;
    let path = manager.create_session().await.context(
        "creating a Mutter remote-desktop session (is this a GNOME session, with Mutter's \
         remote-desktop support built in?)",
    )?;
    let session = RemoteDesktopSessionProxy::builder(&conn)
        .path(path)?
        .build()
        .await
        .context("building the Mutter session proxy")?;
    // Streams first: the owner announcement is emitted inside EnableClipboard.
    let mut owner_changes = session.receive_selection_owner_changed().await?;
    let mut transfers = session.receive_selection_transfer().await?;
    let mut closed = session.receive_closed().await?;
    session
        .enable_clipboard(HashMap::new())
        .await
        .context("enabling the clipboard on the Mutter session")?;
    let connect = if shared.subscribed.swap(true, Ordering::SeqCst) {
        Connect::Reconnect
    } else {
        Connect::Subscribe
    };
    *shared.session.lock().unwrap() = Some(session.clone());
    match manager.version().await {
        Ok(v) => info!("clipboard watcher connected (Mutter remote-desktop API v{v})"),
        Err(_) => info!("clipboard watcher connected (Mutter remote-desktop API)"),
    }

    // The current owner, if any, is already queued (see the module doc).
    if let Some(signal) = owner_changes.next().now_or_never().flatten() {
        let change = parse_owner_changed(signal.args()?.options());
        shared.apply(&change);
        let event = match connect {
            Connect::Reconnect => Some(ClipboardEvent::Changed(SelectionKind::Clipboard)),
            Connect::Subscribe => {
                match tokio::time::timeout(STARTUP_READ_TIMEOUT, shared.read_offer(None)).await {
                    Ok(Ok(offer)) if offer.is_empty() => None,
                    Ok(Ok(offer)) => Some(ClipboardEvent::Initial {
                        kind: SelectionKind::Clipboard,
                        offer,
                    }),
                    Ok(Err(e)) => {
                        warn!("couldn't read the existing Clipboard selection at startup: {e:#}");
                        None
                    }
                    Err(_) => {
                        warn!(
                            "the Clipboard selection's owner did not serve its content within \
                             {STARTUP_READ_TIMEOUT:?}; skipping it so change detection can start"
                        );
                        None
                    }
                }
            }
        };
        if let Some(event) = event {
            if !shared.notify(event) {
                let _ = session.stop().await;
                return Ok(Stop::EngineGone);
            }
        }
    }
    #[cfg(test)]
    shared.ready.fetch_add(1, Ordering::SeqCst);

    loop {
        tokio::select! {
            change = owner_changes.next() => {
                let Some(signal) = change else {
                    bail!("the SelectionOwnerChanged stream ended (bus connection lost?)");
                };
                let change = parse_owner_changed(signal.args()?.options());
                debug!(
                    "Mutter clipboard owner changed: {} type(s){}",
                    change.types.len(),
                    if change.session_is_owner { " (ours)" } else { "" }
                );
                shared.apply(&change);
                if !shared.notify(ClipboardEvent::Changed(SelectionKind::Clipboard)) {
                    let _ = session.stop().await;
                    return Ok(Stop::EngineGone);
                }
            }
            transfer = transfers.next() => {
                let Some(signal) = transfer else {
                    bail!("the SelectionTransfer stream ended (bus connection lost?)");
                };
                let args = signal.args()?;
                tokio::spawn(serve_transfer(
                    shared.clone(),
                    session.clone(),
                    args.mime_type().to_string(),
                    *args.serial(),
                ));
            }
            _ = closed.next() => return Ok(Stop::SessionClosed),
        }
    }
}

#[async_trait]
impl Clipboard for MutterClipboard {
    fn watch(&self, kinds: &[SelectionKind]) -> mpsc::UnboundedReceiver<ClipboardEvent> {
        let (tx, rx) = mpsc::unbounded_channel();
        if !kinds.contains(&SelectionKind::Clipboard) {
            debug!("Mutter clipboard backend asked to watch {kinds:?}: only CLIPBOARD is watched");
        }
        let start = {
            let mut watchers = self.shared.watchers.lock().unwrap();
            watchers.senders.push(tx);
            // Start a task only when none is running — not "am I the first
            // subscriber", which a retired task's leftover sender made false
            // forever, handing a later caller a receiver nothing would ever
            // send to.
            !std::mem::replace(&mut watchers.task_running, true)
        };
        if start {
            tokio::spawn(run(self.shared.clone(), self.connector.clone()));
        }
        rx
    }

    async fn list_types(&self, kind: SelectionKind) -> Result<Vec<String>> {
        if kind != SelectionKind::Clipboard {
            return Err(unsupported(kind));
        }
        let types = self.shared.list_types();
        debug!("listed the Clipboard clipboard types: {types:?}");
        Ok(types)
    }

    async fn read_offer(&self, kind: SelectionKind, only: Option<&str>) -> Result<Offer> {
        if kind != SelectionKind::Clipboard {
            return Err(unsupported(kind));
        }
        self.shared.read_offer(only).await
    }

    async fn write_offer(&self, kind: SelectionKind, offer: Arc<Offer>) -> Result<()> {
        if kind != SelectionKind::Clipboard {
            return Err(unsupported(kind));
        }
        self.shared.write_offer(offer).await
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeMutter;
    use super::*;
    use crate::protocol::test_support::text_offer;

    async fn next(rx: &mut mpsc::UnboundedReceiver<ClipboardEvent>) -> ClipboardEvent {
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("an event within 5s")
            .expect("the watcher is alive")
    }

    fn changed() -> ClipboardEvent {
        ClipboardEvent::Changed(SelectionKind::Clipboard)
    }

    fn offer(pairs: &[(&str, &[u8])]) -> Arc<Offer> {
        Arc::new(
            pairs
                .iter()
                .map(|(m, b)| (m.to_string(), b.to_vec()))
                .collect(),
        )
    }

    /// Short enough for a test, long enough that a normal transfer never hits it.
    const TEST_TRANSFER_TIMEOUT: Duration = Duration::from_millis(300);

    fn backend(max_payload: usize, connector: Arc<dyn BusConnector>) -> MutterClipboard {
        MutterClipboard::with_transfer_timeout(max_payload, connector, TEST_TRANSFER_TIMEOUT)
    }

    /// Until the backend's `n`th attempt has finished its startup report — so
    /// a change the test makes afterwards is a change, not the drained
    /// startup signal. (With Mutter the same window exists; here it would
    /// make the tests racy.)
    async fn wait_ready(clip: &MutterClipboard, n: usize) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while clip.shared.ready.load(Ordering::SeqCst) < n {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the backend never became ready"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    /// Until the session task has retired `n` times.
    async fn wait_retired(clip: &MutterClipboard, n: usize) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while clip.shared.retired.load(Ordering::SeqCst) < n {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the session task never retired"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    /// A backend watching a fresh fake, with the fake's clipboard as seeded.
    async fn start(
        max_payload: usize,
        seed: &[(&str, &[u8])],
    ) -> (
        FakeMutter,
        MutterClipboard,
        mpsc::UnboundedReceiver<ClipboardEvent>,
    ) {
        let (fake, connector) = FakeMutter::start().await;
        if !seed.is_empty() {
            fake.set_owner(seed).await;
        }
        let clip = backend(max_payload, connector);
        let rx = clip.watch(&[SelectionKind::Clipboard]);
        wait_ready(&clip, 1).await;
        (fake, clip, rx)
    }

    // ---- session: subscribe, reconnect, retire

    #[tokio::test]
    async fn initial_owner_is_reported_once_with_content_before_any_changed() {
        let (fake, _clip, mut rx) = start(1024, &[("text/plain", b"restored")]).await;
        assert_eq!(
            next(&mut rx).await,
            ClipboardEvent::Initial {
                kind: SelectionKind::Clipboard,
                offer: text_offer("restored")
            }
        );
        fake.set_owner(&[("text/plain", b"new")]).await;
        assert_eq!(next(&mut rx).await, changed());
    }

    #[tokio::test]
    async fn empty_clipboard_at_subscribe_reports_nothing_and_a_change_is_changed() {
        let (fake, _clip, mut rx) = start(1024, &[]).await;
        fake.set_owner(&[("text/plain", b"first copy")]).await;
        assert_eq!(
            next(&mut rx).await,
            changed(),
            "no Initial for an empty clipboard"
        );
    }

    #[tokio::test]
    async fn a_closed_session_reconnects_and_reports_its_find_as_changed() {
        let (fake, clip, mut rx) = start(1024, &[("text/plain", b"before")]).await;
        assert!(matches!(
            next(&mut rx).await,
            ClipboardEvent::Initial { .. }
        ));
        fake.close_session().await;
        // Real time: the supervisor's first restart delay is 1s.
        wait_ready(&clip, 2).await;
        assert_eq!(fake.sessions_created(), 2);
        // The fake still holds the same owner; found again after a blind spell
        // it is a change, never restored content.
        assert_eq!(next(&mut rx).await, changed());
        assert_eq!(
            clip.read_offer(SelectionKind::Clipboard, None)
                .await
                .unwrap(),
            text_offer("before")
        );
    }

    #[tokio::test]
    async fn a_failed_first_attempt_still_reports_initial_on_the_first_enable() {
        let (fake, connector) = FakeMutter::start().await;
        fake.set_owner(&[("text/plain", b"restored")]).await;
        connector.fail_next(1);
        let clip = backend(1024, connector);
        let mut rx = clip.watch(&[SelectionKind::Clipboard]);
        // Real time: the supervisor's first restart delay is 1s.
        wait_ready(&clip, 1).await;
        assert!(matches!(
            next(&mut rx).await,
            ClipboardEvent::Initial { .. }
        ));
    }

    #[tokio::test]
    async fn watcher_retires_when_the_engine_drops_the_receiver() {
        let (fake, _clip, rx) = start(1024, &[]).await;
        drop(rx);
        fake.set_owner(&[("text/plain", b"x")]).await;
        fake.wait_for_stops(1).await;
        assert!(
            !fake.has_session(),
            "the session was stopped, not reconnected"
        );
        assert_eq!(fake.stops(), 1);
    }

    #[tokio::test]
    async fn a_failed_set_selection_keeps_the_offer_we_still_own() {
        // Mutter's idea of the owner is unchanged by a call that failed, so we
        // are still its owner and must still be able to serve what we owned.
        let (fake, clip, mut rx) = start(1024, &[]).await;
        clip.write_offer(SelectionKind::Clipboard, offer(&[("text/plain", b"one")]))
            .await
            .unwrap();
        next(&mut rx).await;
        fake.fail_next_set_selection();
        assert!(clip
            .write_offer(SelectionKind::Clipboard, offer(&[("text/plain", b"two")]))
            .await
            .is_err());
        assert_eq!(
            clip.read_offer(SelectionKind::Clipboard, None)
                .await
                .unwrap(),
            *offer(&[("text/plain", b"one")]),
            "the clipboard must not go blank on a transient write error"
        );
        assert_eq!(fake.pull("text/plain").await.as_deref(), Some(&b"one"[..]));
        assert_eq!(
            fake.selection_reads(),
            0,
            "Mutter would refuse these anyway"
        );
    }

    #[tokio::test]
    async fn a_later_watch_restarts_a_retired_session_task() {
        let (fake, connector) = FakeMutter::start().await;
        let clip = backend(1024, connector);
        let rx = clip.watch(&[SelectionKind::Clipboard]);
        wait_ready(&clip, 1).await;
        // Retire the task down the *error* path: the session ends without a
        // send ever discovering the dropped receiver, so nothing prunes the
        // subscriber list on the way out.
        drop(rx);
        fake.close_session().await;
        // Wait for the retirement itself: subscribing before it happens keeps
        // the *existing* task alive, which is a different path entirely.
        wait_retired(&clip, 1).await;
        // A fresh subscriber must get a session of its own, not a receiver
        // nothing will ever send to.
        let mut rx = clip.watch(&[SelectionKind::Clipboard]);
        wait_ready(&clip, 2).await;
        fake.set_owner(&[("text/plain", b"y")]).await;
        assert_eq!(next(&mut rx).await, changed());
    }

    #[tokio::test]
    async fn an_emptied_clipboard_is_a_change_with_nothing_to_read() {
        // Mutter announces "no owner" as an options map with neither key.
        let (fake, clip, mut rx) = start(1024, &[("text/plain", b"x")]).await;
        next(&mut rx).await;
        let reads_before = fake.selection_reads();
        fake.clear_owner().await;
        assert_eq!(next(&mut rx).await, changed());
        assert!(clip
            .list_types(SelectionKind::Clipboard)
            .await
            .unwrap()
            .is_empty());
        assert!(clip
            .read_offer(SelectionKind::Clipboard, None)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(fake.selection_reads(), reads_before, "nothing to read");
    }

    // ---- reads

    #[tokio::test]
    async fn list_types_is_the_last_advertised_list_minus_machinery_and_costs_no_read() {
        let (fake, clip, mut rx) = start(1024, &[]).await;
        fake.set_owner(&[
            ("TARGETS", b""),
            ("text/html", b"<b>"),
            ("text/plain", b"b"),
        ])
        .await;
        next(&mut rx).await;
        assert_eq!(
            clip.list_types(SelectionKind::Clipboard).await.unwrap(),
            ["text/html", "text/plain"]
        );
        assert_eq!(fake.selection_reads(), 0);
    }

    #[tokio::test]
    async fn read_offer_reads_each_type_in_advertise_order_within_budget() {
        let (fake, clip, mut rx) = start(1024, &[]).await;
        fake.set_owner(&[("text/html", b"<b>x</b>"), ("text/plain", b"x")])
            .await;
        next(&mut rx).await;
        let offer = clip
            .read_offer(SelectionKind::Clipboard, None)
            .await
            .unwrap();
        assert_eq!(
            offer.keys().map(String::as_str).collect::<Vec<_>>(),
            ["text/html", "text/plain"]
        );
        assert_eq!(offer["text/html"], b"<b>x</b>");
        assert_eq!(fake.selection_reads(), 2);
    }

    #[tokio::test]
    async fn read_offer_only_narrows_to_one_selection_read() {
        let (fake, clip, mut rx) = start(1024, &[]).await;
        fake.set_owner(&[("text/html", b"<b>x</b>"), ("text/plain", b"x")])
            .await;
        next(&mut rx).await;
        let offer = clip
            .read_offer(SelectionKind::Clipboard, Some("text/plain"))
            .await
            .unwrap();
        assert_eq!(offer.len(), 1);
        assert_eq!(offer["text/plain"], b"x");
        assert_eq!(fake.selection_reads(), 1);
    }

    #[tokio::test]
    async fn over_budget_representation_is_skipped_and_the_rest_kept() {
        let (fake, clip, mut rx) = start(40, &[]).await;
        fake.set_owner(&[("image/png", &[0u8; 100]), ("text/plain", b"hi")])
            .await;
        next(&mut rx).await;
        let offer = clip
            .read_offer(SelectionKind::Clipboard, None)
            .await
            .unwrap();
        assert_eq!(
            offer.keys().map(String::as_str).collect::<Vec<_>>(),
            ["text/plain"]
        );
    }

    #[tokio::test]
    async fn reads_while_owner_come_from_the_owned_offer() {
        let (fake, clip, mut rx) = start(1024, &[]).await;
        let ours = offer(&[("text/html", b"<i>x</i>"), ("text/plain", b"x")]);
        clip.write_offer(SelectionKind::Clipboard, ours.clone())
            .await
            .unwrap();
        assert_eq!(
            next(&mut rx).await,
            changed(),
            "our own write echoes as Changed"
        );
        assert_eq!(
            clip.read_offer(SelectionKind::Clipboard, None)
                .await
                .unwrap(),
            *ours
        );
        assert_eq!(
            clip.read_offer(SelectionKind::Clipboard, Some("text/plain"))
                .await
                .unwrap()
                .keys()
                .collect::<Vec<_>>(),
            ["text/plain"]
        );
        assert_eq!(
            clip.list_types(SelectionKind::Clipboard).await.unwrap(),
            ["text/html", "text/plain"]
        );
        assert_eq!(fake.selection_reads(), 0, "Mutter would have refused these");
    }

    #[tokio::test]
    async fn concurrent_reads_are_serialized_never_refused() {
        let (fake, clip, mut rx) = start(1024, &[]).await;
        fake.set_owner(&[("text/plain", b"slow")]).await;
        next(&mut rx).await;
        fake.hold_reads();
        let release = async {
            // Let the first read start and block on EOF, then release it; the
            // second read must have waited its turn rather than been refused.
            while fake.selection_reads() < 1 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            fake.release_reads();
        };
        let (a, b, ()) = tokio::join!(
            clip.read_offer(SelectionKind::Clipboard, None),
            clip.read_offer(SelectionKind::Clipboard, None),
            release
        );
        assert_eq!(a.unwrap()["text/plain"], b"slow");
        assert_eq!(b.unwrap()["text/plain"], b"slow");
        assert_eq!(fake.parallel_refusals(), 0);
        assert_eq!(fake.selection_reads(), 2);
    }

    #[tokio::test]
    async fn selection_kind_is_an_error() {
        let (_fake, clip, _rx) = start(1024, &[]).await;
        assert!(clip.list_types(SelectionKind::Selection).await.is_err());
        assert!(clip
            .read_offer(SelectionKind::Selection, None)
            .await
            .is_err());
        assert!(clip
            .write_offer(SelectionKind::Selection, Arc::new(text_offer("x")))
            .await
            .is_err());
    }

    // ---- writes

    #[tokio::test]
    async fn write_offer_sets_selection_with_keys_in_offer_order() {
        let (fake, clip, mut rx) = start(1024, &[]).await;
        clip.write_offer(
            SelectionKind::Clipboard,
            offer(&[("text/html", b"<b>"), ("text/plain", b"b")]),
        )
        .await
        .unwrap();
        assert_eq!(next(&mut rx).await, changed());
        assert_eq!(
            fake.set_selections(),
            vec![vec!["text/html".to_string(), "text/plain".to_string()]]
        );
    }

    #[tokio::test]
    async fn empty_offer_is_a_no_op() {
        let (fake, clip, _rx) = start(1024, &[]).await;
        clip.write_offer(SelectionKind::Clipboard, Arc::new(Offer::new()))
            .await
            .unwrap();
        assert!(fake.set_selections().is_empty());
    }

    #[tokio::test]
    async fn a_transfer_is_served_byte_exact_and_an_unknown_mime_fails() {
        let (fake, clip, mut rx) = start(1024, &[]).await;
        clip.write_offer(
            SelectionKind::Clipboard,
            offer(&[("text/plain", b"served")]),
        )
        .await
        .unwrap();
        next(&mut rx).await;
        assert_eq!(
            fake.pull("text/plain").await.as_deref(),
            Some(&b"served"[..])
        );
        assert_eq!(fake.pull("image/png").await, None);
    }

    #[tokio::test]
    async fn owned_is_replaced_by_the_next_write_and_useless_once_another_owner_appears() {
        let (fake, clip, mut rx) = start(1024, &[]).await;
        clip.write_offer(SelectionKind::Clipboard, offer(&[("text/plain", b"one")]))
            .await
            .unwrap();
        next(&mut rx).await;
        clip.write_offer(SelectionKind::Clipboard, offer(&[("text/plain", b"two")]))
            .await
            .unwrap();
        next(&mut rx).await;
        assert_eq!(fake.pull("text/plain").await.as_deref(), Some(&b"two"[..]));
        fake.set_owner(&[("text/plain", b"theirs")]).await;
        next(&mut rx).await;
        assert_eq!(
            fake.pull("text/plain").await,
            None,
            "Mutter refuses SelectionWrite for a source that no longer owns"
        );
        assert_eq!(
            clip.read_offer(SelectionKind::Clipboard, None)
                .await
                .unwrap(),
            text_offer("theirs")
        );
    }

    #[tokio::test]
    async fn a_stalled_transfer_is_abandoned_before_mutters_cleanup() {
        let (fake, clip, mut rx) = start(1024 * 1024, &[]).await;
        fake.stall_transfers();
        // Larger than a pipe buffer, so the write blocks on the paster.
        clip.write_offer(
            SelectionKind::Clipboard,
            offer(&[("image/png", &vec![7u8; 256 * 1024])]),
        )
        .await
        .unwrap();
        next(&mut rx).await;
        let started = tokio::time::Instant::now();
        assert_eq!(fake.pull("image/png").await, None);
        assert!(started.elapsed() >= TEST_TRANSFER_TIMEOUT);
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
