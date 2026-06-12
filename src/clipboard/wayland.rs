use crate::clipboard::Clipboard;
use crate::protocol::{Offer, SelectionKind};
use anyhow::{bail, Result};
use async_trait::async_trait;
use std::io::Read;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tracing::{debug, error, warn};
use wl_clipboard_rs::copy;
use wl_clipboard_rs::paste;

/// Wayland clipboard via the data-control protocol. Requires a compositor
/// implementing ext-data-control-v1 or zwlr-data-control-v1 (niri, Sway,
/// Hyprland, KDE Plasma, ...). Watching requires the `wl-paste` binary
/// from the wl-clipboard package.
pub struct WaylandClipboard {
    sync_primary: bool,
    max_payload: usize,
}

impl WaylandClipboard {
    pub fn new(sync_primary: bool, max_payload: usize) -> WaylandClipboard {
        WaylandClipboard {
            sync_primary,
            max_payload,
        }
    }
}

fn paste_type(kind: SelectionKind) -> paste::ClipboardType {
    match kind {
        SelectionKind::Clipboard => paste::ClipboardType::Regular,
        SelectionKind::Primary => paste::ClipboardType::Primary,
    }
}

fn copy_type(kind: SelectionKind) -> copy::ClipboardType {
    match kind {
        SelectionKind::Clipboard => copy::ClipboardType::Regular,
        SelectionKind::Primary => copy::ClipboardType::Primary,
    }
}

fn read_offer_blocking(kind: SelectionKind, max: usize) -> Result<Offer> {
    let ct = paste_type(kind);
    let types = match paste::get_mime_types(ct, paste::Seat::Unspecified) {
        Ok(t) => t,
        Err(paste::Error::NoSeats | paste::Error::ClipboardEmpty | paste::Error::NoMimeType) => {
            return Ok(Offer::new())
        }
        Err(e) => return Err(e.into()),
    };
    let mut offer = Offer::new();
    let mut total = 0usize;
    for mime in types {
        // A genuine read error aborts the whole offer: silently dropping one
        // representation would ship a mutated offer to peers. If the
        // clipboard changed mid-read, the watcher fires again anyway.
        let (pipe, _actual_mime) = match paste::get_contents(
            ct,
            paste::Seat::Unspecified,
            paste::MimeType::Specific(&mime),
        ) {
            Ok(x) => x,
            Err(e) => bail!("failed to read clipboard representation {mime}: {e}"),
        };
        // Bound the read by the remaining budget (+1 to detect overflow) so a
        // huge or unbounded representation can't OOM the daemon before the
        // cap is consulted. total never exceeds max, so the subtraction is safe.
        let budget = max - total;
        let mut data = Vec::new();
        pipe.take(budget as u64 + 1).read_to_end(&mut data)?;
        if mime.len() + data.len() > budget {
            // This representation would push the offer over the cap. Skip it
            // but keep the rest, so a small syncable payload alongside a giant
            // image (which can never sync) still propagates.
            debug!(%mime, "skipping clipboard representation over size cap");
            continue;
        }
        total += mime.len() + data.len();
        offer.insert(mime, data);
    }
    Ok(offer)
}

fn write_offer_blocking(kind: SelectionKind, offer: Offer) -> Result<()> {
    let sources: Vec<copy::MimeSource> = offer
        .into_iter()
        .map(|(mime, data)| copy::MimeSource {
            source: copy::Source::Bytes(data.into_boxed_slice()),
            mime_type: copy::MimeType::Specific(mime),
        })
        .collect();
    if sources.is_empty() {
        return Ok(());
    }
    let mut opts = copy::Options::new();
    opts.clipboard(copy_type(kind));
    // Advertise exactly the MIME types we were given. Without this,
    // wl-clipboard-rs adds text/plain;charset=utf-8, STRING, UTF8_STRING and
    // TEXT whenever any text type is present, so reading the selection back
    // would not byte-match what we wrote — defeating echo suppression and
    // causing the node to re-broadcast a mutated offer (an echo loop).
    opts.omit_additional_text_mime_types(true);
    opts.copy_multi(sources)?;
    Ok(())
}

/// Spawn `wl-paste --watch` and translate its output lines into change
/// notifications. Restarts the subprocess if it exits, with backoff on
/// rapid failures (e.g. no data-control support, WAYLAND_DISPLAY unset)
/// and wl-paste's stderr forwarded to the log so the cause is visible.
fn spawn_watcher(tx: mpsc::UnboundedSender<SelectionKind>, kind: SelectionKind) {
    const RESTART_MIN: Duration = Duration::from_secs(1);
    const RESTART_MAX: Duration = Duration::from_secs(30);
    /// A run shorter than this counts as a failure and escalates backoff.
    const STABLE_AFTER: Duration = Duration::from_secs(5);
    tokio::spawn(async move {
        let mut delay = RESTART_MIN;
        loop {
            let started = std::time::Instant::now();
            let mut cmd = tokio::process::Command::new("wl-paste");
            if kind == SelectionKind::Primary {
                cmd.arg("--primary");
            }
            cmd.args(["--watch", "echo", "clipmesh-change"]);
            cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
            match cmd.spawn() {
                Ok(mut child) => {
                    if let Some(err) = child.stderr.take() {
                        tokio::spawn(async move {
                            let mut lines = BufReader::new(err).lines();
                            while let Ok(Some(line)) = lines.next_line().await {
                                warn!("wl-paste: {line}");
                            }
                        });
                    }
                    if let Some(out) = child.stdout.take() {
                        let mut lines = BufReader::new(out).lines();
                        while let Ok(Some(_)) = lines.next_line().await {
                            if tx.send(kind).is_err() {
                                let _ = child.kill().await;
                                return; // engine gone; stop watching
                            }
                        }
                    }
                    let _ = child.kill().await;
                }
                Err(e) => {
                    error!("failed to spawn wl-paste --watch (is wl-clipboard installed?): {e}");
                }
            }
            delay = if started.elapsed() < STABLE_AFTER {
                (delay * 2).min(RESTART_MAX)
            } else {
                RESTART_MIN
            };
            warn!(?kind, "clipboard watcher exited; restarting in {delay:?}");
            tokio::time::sleep(delay).await;
        }
    });
}

#[async_trait]
impl Clipboard for WaylandClipboard {
    fn watch(&self) -> mpsc::UnboundedReceiver<SelectionKind> {
        let (tx, rx) = mpsc::unbounded_channel();
        spawn_watcher(tx.clone(), SelectionKind::Clipboard);
        if self.sync_primary {
            spawn_watcher(tx, SelectionKind::Primary);
        }
        rx
    }

    async fn read_offer(&self, kind: SelectionKind) -> Result<Offer> {
        let max = self.max_payload;
        tokio::task::spawn_blocking(move || read_offer_blocking(kind, max)).await?
    }

    async fn write_offer(&self, kind: SelectionKind, offer: Offer) -> Result<()> {
        tokio::task::spawn_blocking(move || write_offer_blocking(kind, offer)).await?
    }
}
