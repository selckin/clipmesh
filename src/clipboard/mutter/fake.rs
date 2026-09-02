//! A hand-rolled Mutter for the backend's tests: the two interfaces served over
//! a zbus peer-to-peer socketpair, so no bus daemon is needed and the tests
//! run headless in CI. It behaves as mutter `gnome-46`'s
//! `meta-remote-desktop-session.c` does at every point the backend depends on:
//!
//! - `EnableClipboard` emits `SelectionOwnerChanged` for a current owner
//!   **before** returning (what makes the backend's `Initial` drain exact);
//! - `SelectionRead` refuses the session's own content ("Tried to read own
//!   selection"), a second read while one is pending ("Tried to read in
//!   parallel"), and an empty clipboard;
//! - `SetSelection` refuses an empty type list and emits an owner change with
//!   `session-is-owner = true`;
//! - `SelectionWrite`/`SelectionWriteDone` complete a `SelectionTransfer` the
//!   test raised with [`FakeMutter::pull`].
//!
//! Test payloads must fit the pipe buffer (they are bytes, not megabytes):
//! a read's content is written into the pipe synchronously, so a read is only
//! ever "pending" while [`FakeMutter::hold_reads`] is on — which is how a test
//! models the slow source that makes Mutter refuse a parallel read.

use super::BusConnector;
use anyhow::{bail, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::os::fd::OwnedFd as StdOwnedFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::pipe;
use tokio::net::UnixStream;
use tokio::sync::{oneshot, watch};
use zbus::connection::Builder;
use zbus::object_server::{ObjectServer, SignalEmitter};
use zbus::zvariant::{OwnedFd, OwnedObjectPath, OwnedValue, Value};
use zbus::{fdo, Connection, Guid};

const MANAGER_PATH: &str = "/org/gnome/Mutter/RemoteDesktop";

/// Who owns the fake's clipboard, and with what.
struct Owner {
    /// Advertise order. Bytes are empty for a session-owned type — the fake
    /// never reads those back (Mutter refuses that too).
    types: Vec<(String, Vec<u8>)>,
    by_session: bool,
}

struct Transfer {
    /// Drains what the backend writes; set by `SelectionWrite`.
    reader: Option<tokio::task::JoinHandle<Vec<u8>>>,
    /// Resolved by `SelectionWriteDone` — with the bytes on success.
    done: Option<oneshot::Sender<Option<Vec<u8>>>>,
}

#[derive(Default)]
struct State {
    owner: Option<Owner>,
    enabled: bool,
    /// The live session object, if any (the fake serves one at a time).
    session: Option<OwnedObjectPath>,
    sessions_created: u32,
    read_pending: bool,
    selection_reads: usize,
    parallel_refusals: usize,
    /// Every `SetSelection` type list, in call order.
    set_selections: Vec<Vec<String>>,
    next_serial: u32,
    transfers: HashMap<u32, Transfer>,
    stops: usize,
    /// When set, the next `SetSelection` fails (a transient D-Bus error).
    fail_next_set_selection: bool,
    /// When set, `SelectionWrite` hands out a pipe nobody drains.
    stall_transfers: bool,
    /// Undrained write ends' partners, kept alive so the writer blocks.
    stalled: Vec<pipe::Receiver>,
}

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state.lock().unwrap()
}

fn io_err(e: std::io::Error) -> fdo::Error {
    fdo::Error::Failed(e.to_string())
}

fn owner_changed_options(types: &[String], by_session: bool) -> HashMap<String, Value<'static>> {
    let mut options = HashMap::new();
    options.insert("mime-types".to_string(), Value::from(types.to_vec()));
    options.insert("session-is-owner".to_string(), Value::from(by_session));
    options
}

struct Manager {
    state: Arc<Mutex<State>>,
    hold: watch::Sender<bool>,
}

#[zbus::interface(name = "org.gnome.Mutter.RemoteDesktop")]
impl Manager {
    async fn create_session(
        &self,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> fdo::Result<OwnedObjectPath> {
        let path = {
            let mut st = lock(&self.state);
            st.sessions_created += 1;
            format!("{MANAGER_PATH}/Session/u{}", st.sessions_created)
        };
        let path = OwnedObjectPath::try_from(path).unwrap();
        let session = Session {
            state: self.state.clone(),
            hold: self.hold.clone(),
        };
        server
            .at(&path, session)
            .await
            .map_err(|e| fdo::Error::Failed(e.to_string()))?;
        let mut st = lock(&self.state);
        st.session = Some(path.clone());
        st.enabled = false;
        st.read_pending = false;
        Ok(path)
    }

    #[zbus(property)]
    fn version(&self) -> i32 {
        1
    }
}

struct Session {
    state: Arc<Mutex<State>>,
    hold: watch::Sender<bool>,
}

#[zbus::interface(name = "org.gnome.Mutter.RemoteDesktop.Session")]
impl Session {
    async fn enable_clipboard(
        &self,
        _options: HashMap<String, OwnedValue>,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> fdo::Result<()> {
        let current = {
            let mut st = lock(&self.state);
            if st.enabled {
                return Err(fdo::Error::Failed("Already enabled".into()));
            }
            st.enabled = true;
            st.owner.as_ref().map(|o| {
                (
                    o.types.iter().map(|(m, _)| m.clone()).collect::<Vec<_>>(),
                    o.by_session,
                )
            })
        };
        // Emitted before the reply, as Mutter does.
        if let Some((types, by_session)) = current {
            Self::selection_owner_changed(&emitter, owner_changed_options(&types, by_session))
                .await?;
        }
        Ok(())
    }

    async fn disable_clipboard(&self) -> fdo::Result<()> {
        let mut st = lock(&self.state);
        if !st.enabled {
            return Err(fdo::Error::Failed("Was not enabled".into()));
        }
        st.enabled = false;
        if st.owner.as_ref().is_some_and(|o| o.by_session) {
            st.owner = None;
        }
        Ok(())
    }

    async fn set_selection(
        &self,
        options: HashMap<String, OwnedValue>,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> fdo::Result<()> {
        let types = options
            .get("mime-types")
            .map(|v| Vec::<String>::try_from(v.clone()).unwrap());
        {
            let mut st = lock(&self.state);
            if !st.enabled {
                return Err(fdo::Error::Failed("Clipboard not enabled".into()));
            }
            if std::mem::take(&mut st.fail_next_set_selection) {
                return Err(fdo::Error::Failed("simulated SetSelection failure".into()));
            }
            match &types {
                Some(types) if types.is_empty() => {
                    return Err(fdo::Error::Failed(
                        "Invalid format list: No mime types in mime types list".into(),
                    ));
                }
                Some(types) => {
                    st.set_selections.push(types.clone());
                    st.owner = Some(Owner {
                        types: types.iter().map(|m| (m.clone(), Vec::new())).collect(),
                        by_session: true,
                    });
                }
                None => st.owner = None,
            }
        }
        match types {
            Some(types) => {
                Self::selection_owner_changed(&emitter, owner_changed_options(&types, true)).await?
            }
            None => Self::selection_owner_changed(&emitter, HashMap::new()).await?,
        }
        Ok(())
    }

    async fn selection_read(&self, mime_type: &str) -> fdo::Result<OwnedFd> {
        let (bytes, held) = {
            let mut st = lock(&self.state);
            if !st.enabled {
                return Err(fdo::Error::Failed("Clipboard not enabled".into()));
            }
            let Some(owner) = &st.owner else {
                return Err(fdo::Error::FileNotFound(
                    "No selection owner available".into(),
                ));
            };
            if owner.by_session {
                return Err(fdo::Error::Failed("Tried to read own selection".into()));
            }
            if st.read_pending {
                st.parallel_refusals += 1;
                return Err(fdo::Error::LimitsExceeded(
                    "Tried to read in parallel".into(),
                ));
            }
            let bytes = owner
                .types
                .iter()
                .find(|(m, _)| m == mime_type)
                .map(|(_, b)| b.clone())
                .unwrap_or_default();
            st.selection_reads += 1;
            let held = *self.hold.borrow();
            st.read_pending = held;
            (bytes, held)
        };
        let (mut tx, rx) = pipe::pipe().map_err(io_err)?;
        // Fits the pipe buffer, so this completes without a reader: the whole
        // payload is in the pipe before the fd is even handed over.
        assert!(
            bytes.len() < 32 * 1024,
            "fake payloads must fit the pipe buffer"
        );
        tx.write_all(&bytes).await.map_err(io_err)?;
        if held {
            // A slow source: EOF (and the end of the pending read) only once the
            // test releases it.
            let state = self.state.clone();
            let mut hold = self.hold.subscribe();
            tokio::spawn(async move {
                while *hold.borrow_and_update() {
                    if hold.changed().await.is_err() {
                        break;
                    }
                }
                drop(tx);
                lock(&state).read_pending = false;
            });
        }
        let fd: StdOwnedFd = rx.into_nonblocking_fd().map_err(io_err)?;
        Ok(fd.into())
    }

    async fn selection_write(&self, serial: u32) -> fdo::Result<OwnedFd> {
        let mut st = lock(&self.state);
        if !st.enabled {
            return Err(fdo::Error::Failed("Clipboard not enabled".into()));
        }
        if !st.owner.as_ref().is_some_and(|o| o.by_session) {
            return Err(fdo::Error::Failed("No current selection owned".into()));
        }
        if !st.transfers.contains_key(&serial) {
            return Err(fdo::Error::Failed(format!(
                "Transfer serial {serial} doesn't match any transfer request"
            )));
        }
        let (tx, mut rx) = pipe::pipe().map_err(io_err)?;
        if st.stall_transfers {
            st.stalled.push(rx);
        } else {
            let reader = tokio::spawn(async move {
                let mut buf = Vec::new();
                let _ = rx.read_to_end(&mut buf).await;
                buf
            });
            st.transfers.get_mut(&serial).unwrap().reader = Some(reader);
        }
        let fd: StdOwnedFd = tx.into_nonblocking_fd().map_err(io_err)?;
        Ok(fd.into())
    }

    async fn selection_write_done(&self, serial: u32, success: bool) -> fdo::Result<()> {
        let transfer = {
            let mut st = lock(&self.state);
            if !st.enabled {
                return Err(fdo::Error::Failed("Clipboard not enabled".into()));
            }
            // Mutter does not check the serial here either.
            st.transfers.remove(&serial)
        };
        if let Some(mut transfer) = transfer {
            let reader = transfer.reader.take();
            let done = transfer.done.take();
            tokio::spawn(async move {
                let bytes = match (success, reader) {
                    (true, Some(reader)) => reader.await.ok(),
                    (_, reader) => {
                        if let Some(reader) = reader {
                            reader.abort();
                        }
                        None
                    }
                };
                if let Some(done) = done {
                    let _ = done.send(bytes);
                }
            });
        }
        Ok(())
    }

    async fn stop(
        &self,
        #[zbus(object_server)] server: &ObjectServer,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> fdo::Result<()> {
        let path = {
            let mut st = lock(&self.state);
            st.stops += 1;
            st.enabled = false;
            st.session.take()
        };
        Self::closed(&emitter).await?;
        if let Some(path) = path {
            let _ = server.remove::<Session, _>(&path).await;
        }
        Ok(())
    }

    #[zbus(signal)]
    async fn selection_owner_changed(
        emitter: &SignalEmitter<'_>,
        options: HashMap<String, Value<'_>>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn selection_transfer(
        emitter: &SignalEmitter<'_>,
        mime_type: &str,
        serial: u32,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn closed(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;
}

/// The backend's side of the socketpair. `connect` hands out the one
/// connection; `fail_next` makes the next N attempts fail, for the
/// reconnect tests.
pub(crate) struct PairConnector {
    conn: Connection,
    fail_next: AtomicUsize,
}

impl PairConnector {
    pub(crate) fn fail_next(&self, attempts: usize) {
        self.fail_next.store(attempts, Ordering::SeqCst);
    }
}

#[async_trait]
impl BusConnector for PairConnector {
    async fn connect(&self) -> Result<Connection> {
        let remaining = self.fail_next.load(Ordering::SeqCst);
        if remaining > 0 {
            self.fail_next.store(remaining - 1, Ordering::SeqCst);
            bail!("simulated bus connection failure");
        }
        Ok(self.conn.clone())
    }
}

pub(crate) struct FakeMutter {
    state: Arc<Mutex<State>>,
    hold: watch::Sender<bool>,
    conn: Connection,
}

impl FakeMutter {
    pub(crate) async fn start() -> (FakeMutter, Arc<PairConnector>) {
        let (client_stream, server_stream) = UnixStream::pair().unwrap();
        let state = Arc::new(Mutex::new(State::default()));
        let (hold, _) = watch::channel(false);
        let manager = Manager {
            state: state.clone(),
            hold: hold.clone(),
        };
        let server = Builder::unix_stream(server_stream)
            .server(Guid::generate())
            .unwrap()
            .p2p()
            .serve_at(MANAGER_PATH, manager)
            .unwrap()
            .build();
        let client = Builder::unix_stream(client_stream).p2p().build();
        let (server, client) = tokio::try_join!(server, client).unwrap();
        let fake = FakeMutter {
            state,
            hold,
            conn: server,
        };
        let connector = Arc::new(PairConnector {
            conn: client,
            fail_next: AtomicUsize::new(0),
        });
        (fake, connector)
    }

    fn session_path(&self) -> OwnedObjectPath {
        lock(&self.state).session.clone().expect("a session exists")
    }

    async fn emit_owner_changed(&self, options: HashMap<String, Value<'static>>) {
        if !lock(&self.state).enabled {
            return;
        }
        let emitter = SignalEmitter::new(&self.conn, self.session_path()).unwrap();
        Session::selection_owner_changed(&emitter, options)
            .await
            .unwrap();
    }

    /// Another client takes the clipboard with these representations.
    pub(crate) async fn set_owner(&self, types: &[(&str, &[u8])]) {
        let names: Vec<String> = types.iter().map(|(m, _)| m.to_string()).collect();
        lock(&self.state).owner = Some(Owner {
            types: types
                .iter()
                .map(|(m, b)| (m.to_string(), b.to_vec()))
                .collect(),
            by_session: false,
        });
        self.emit_owner_changed(owner_changed_options(&names, false))
            .await;
    }

    /// The clipboard becomes empty (Mutter sends a keyless options map).
    pub(crate) async fn clear_owner(&self) {
        lock(&self.state).owner = None;
        self.emit_owner_changed(HashMap::new()).await;
    }

    /// Raise a `SelectionTransfer` for `mime` and wait for the backend to
    /// answer it: the bytes it wrote, or `None` for `SelectionWriteDone(false)`.
    pub(crate) async fn pull(&self, mime: &str) -> Option<Vec<u8>> {
        let (done, answered) = oneshot::channel();
        let serial = {
            let mut st = lock(&self.state);
            st.next_serial += 1;
            let serial = st.next_serial;
            st.transfers.insert(
                serial,
                Transfer {
                    reader: None,
                    done: Some(done),
                },
            );
            serial
        };
        let emitter = SignalEmitter::new(&self.conn, self.session_path()).unwrap();
        Session::selection_transfer(&emitter, mime, serial)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), answered)
            .await
            .expect("the transfer was answered")
            .unwrap()
    }

    /// Mutter closes the session (as it does when it shuts down).
    pub(crate) async fn close_session(&self) {
        let path = lock(&self.state).session.take().expect("a session exists");
        lock(&self.state).enabled = false;
        let emitter = SignalEmitter::new(&self.conn, &path).unwrap();
        Session::closed(&emitter).await.unwrap();
        let _ = self.conn.object_server().remove::<Session, _>(&path).await;
    }

    /// Reads stay pending (no EOF) until `release_reads`.
    pub(crate) fn hold_reads(&self) {
        self.hold.send_replace(true);
    }

    pub(crate) fn release_reads(&self) {
        self.hold.send_replace(false);
    }

    /// The next `SetSelection` fails, leaving Mutter's idea of the owner
    /// exactly as it was.
    pub(crate) fn fail_next_set_selection(&self) {
        lock(&self.state).fail_next_set_selection = true;
    }

    /// Transfers are never drained: the backend's writer blocks once the pipe
    /// is full, as it would on a paster that stalls.
    pub(crate) fn stall_transfers(&self) {
        lock(&self.state).stall_transfers = true;
    }

    async fn wait_until(&self, what: &str, pred: impl Fn(&State) -> bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !pred(&lock(&self.state)) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for {what}"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    pub(crate) async fn wait_for_stops(&self, n: usize) {
        self.wait_until("a Stop", |st| st.stops >= n).await;
    }

    pub(crate) fn selection_reads(&self) -> usize {
        lock(&self.state).selection_reads
    }

    pub(crate) fn parallel_refusals(&self) -> usize {
        lock(&self.state).parallel_refusals
    }

    pub(crate) fn set_selections(&self) -> Vec<Vec<String>> {
        lock(&self.state).set_selections.clone()
    }

    pub(crate) fn sessions_created(&self) -> u32 {
        lock(&self.state).sessions_created
    }

    pub(crate) fn stops(&self) -> usize {
        lock(&self.state).stops
    }

    pub(crate) fn has_session(&self) -> bool {
        lock(&self.state).session.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::super::proxies::{
        mime_types_option, parse_owner_changed, RemoteDesktopProxy, RemoteDesktopSessionProxy,
    };
    use super::*;
    use futures_util::{FutureExt, StreamExt};

    /// The harness itself, so a later failure points at the backend.
    #[tokio::test]
    async fn round_trips_enable_owner_change_read_and_a_transfer() {
        let (fake, connector) = FakeMutter::start().await;
        let conn = connector.connect().await.unwrap();
        let manager = RemoteDesktopProxy::new(&conn).await.unwrap();
        let path = manager.create_session().await.unwrap();
        let session = RemoteDesktopSessionProxy::builder(&conn)
            .path(path)
            .unwrap()
            .build()
            .await
            .unwrap();
        // Seeded before enable: no signal yet (the fake is not enabled).
        fake.set_owner(&[("text/plain", b"hi")]).await;
        let mut changes = session.receive_selection_owner_changed().await.unwrap();
        session.enable_clipboard(HashMap::new()).await.unwrap();
        let first = changes
            .next()
            .now_or_never()
            .flatten()
            .expect("the current owner is announced before the reply");
        let change = parse_owner_changed(first.args().unwrap().options());
        assert_eq!(change.types, ["text/plain"]);
        assert!(!change.session_is_owner);

        let fd = session.selection_read("text/plain").await.unwrap();
        let mut rx = pipe::Receiver::from_owned_fd(fd.into()).unwrap();
        let mut buf = Vec::new();
        rx.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"hi");

        let mut transfers = session.receive_selection_transfer().await.unwrap();
        session
            .set_selection(mime_types_option(&["x/y".to_string()]))
            .await
            .unwrap();
        let ours = changes.next().await.unwrap();
        assert!(parse_owner_changed(ours.args().unwrap().options()).session_is_owner);
        assert!(
            session.selection_read("x/y").await.is_err(),
            "own content is refused"
        );
        let (pulled, ()) = tokio::join!(fake.pull("x/y"), async {
            let transfer = transfers.next().await.unwrap();
            let args = transfer.args().unwrap();
            assert_eq!(args.mime_type(), "x/y");
            let fd = session.selection_write(*args.serial()).await.unwrap();
            let mut tx = pipe::Sender::from_owned_fd(fd.into()).unwrap();
            tx.write_all(b"served").await.unwrap();
            drop(tx);
            session
                .selection_write_done(*args.serial(), true)
                .await
                .unwrap();
        });
        assert_eq!(pulled.as_deref(), Some(&b"served"[..]));
        assert_eq!(fake.set_selections(), vec![vec!["x/y".to_string()]]);
    }
}
