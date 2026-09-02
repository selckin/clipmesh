pub mod atoms;
pub(crate) mod budget;
pub mod io;
pub mod mock;
pub mod mutter;
pub mod watch;
pub mod wayland;

use crate::config::{BackendChoice, Config};
use crate::protocol::{Offer, SelectionKind};
use anyhow::{bail, Result};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::info;

/// Why a watcher's connection to the compositor is being made — which decides
/// how its startup burst is reported.
///
/// The distinction is load-bearing. `Clipboard::watch` promises `Initial`
/// "as of the subscribe", and the engine acts on that promise: `adopt_restored`
/// records the content at **stamp 0** and deliberately never broadcasts it,
/// because a node cannot know how old its restored clipboard is. That is right
/// for content that was already there when the daemon started, and wrong for
/// everything else — the watchers are supervised, so they reconnect after any
/// compositor restart or transient error, and reporting a reconnect's burst as
/// `Initial` demoted whatever the user had copied in the meantime to stamp 0,
/// where any peer's older clipboard outranked it and overwrote it on the next
/// resync.
///
/// Shared by both watchers (`watch.rs` for data-control, `mutter.rs` for
/// GNOME) so the rule is stated once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Connect {
    /// The first connection: this *is* the `watch` call, so what it finds is
    /// pre-existing content.
    Subscribe,
    /// A later connection. The watcher was blind while it was down, so what it
    /// finds now is reported as an ordinary local change: the engine reads it,
    /// stamps it now, and propagates it.
    Reconnect,
}

/// Bound for a watcher's startup content read. Matches
/// `ClipboardIo::READ_TIMEOUT`: a real read of the size-capped clipboard takes
/// milliseconds, so exceeding this means the source is not serving its pipe —
/// and the read runs ahead of change detection, so it must not be allowed to
/// hang there (see `watch::read_offer_bounded`).
pub(crate) const STARTUP_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// What a [`Clipboard`] watcher reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardEvent {
    /// The selection's content as of the `watch` call that produced this stream,
    /// captured by the backend. At most one per selection, always before any
    /// `Changed` for it, and omitted entirely when the selection was empty.
    ///
    /// The engine treats this as *restored* content: recorded so it is not
    /// re-broadcast as a fresh copy after a restart, and never bridged, re-owned
    /// or sent to the mesh under a new stamp.
    Initial { kind: SelectionKind, offer: Offer },
    /// The selection changed after `watch` was called — a genuine local action
    /// (or the echo of one of our own writes, which the engine filters).
    Changed(SelectionKind),
}

/// Abstraction over a system clipboard. The real implementation talks to
/// Wayland; the mock backs all tests.
#[async_trait]
pub trait Clipboard: Send + Sync + 'static {
    /// Subscribe to clipboard events for `kinds`.
    ///
    /// Fires a [`ClipboardEvent::Changed`] at least once per change of one of
    /// those selections, including changes made through `write_offer` (real
    /// clipboards do this). May deliver a kind outside `kinds` — the engine
    /// tolerates that; `kinds` is what the backend is asked to *guarantee*.
    ///
    /// Taking the set here rather than at construction keeps the contract
    /// self-contained: an implementation needs no configuration of its own, and
    /// the engine's notion of what it watches can't drift from the backend's.
    ///
    /// # The `Initial` contract
    ///
    /// Before any `Changed` for a selection, the implementation must deliver one
    /// [`ClipboardEvent::Initial`] for it carrying **the content as of this
    /// call** — or none at all, if the selection was empty.
    ///
    /// The content must be captured by the backend, not read back later. The
    /// engine reads lazily, after an event, so anything it reads reflects *now*
    /// rather than when the event fired; it therefore cannot tell restored
    /// content from a copy the user made a moment after startup. Getting that
    /// wrong is not cosmetic — misjudged content is suppressed instead of
    /// broadcast, and recorded at stamp 0 where a peer's *older* clipboard
    /// outranks it. Only the backend exists at subscribe time, so only the
    /// backend can answer the question.
    fn watch(&self, kinds: &[SelectionKind]) -> mpsc::UnboundedReceiver<ClipboardEvent>;
    /// The MIME types `kind` currently offers, without reading any contents.
    ///
    /// Separate from [`read_offer`](Clipboard::read_offer) because reading is
    /// not cheap: the Wayland backend spends a whole connection and roundtrip
    /// **per representation**, so answering "what types are on offer?" by
    /// reading them all turns one roundtrip into one per type — and for a
    /// clipboard holding a large image, megabytes of pipe reads to produce a
    /// list of names.
    async fn list_types(&self, kind: SelectionKind) -> Result<Vec<String>>;

    /// Read the offered MIME representations of the given selection, restricted
    /// to a single type (matched case-insensitively) when `only` is set.
    ///
    /// `only` exists for the same reason as `list_types`: a caller that wants
    /// one representation should not pay to read the rest.
    ///
    /// May return an error if the contents exceed the implementation's
    /// payload cap or a representation cannot be read in full.
    async fn read_offer(&self, kind: SelectionKind, only: Option<&str>) -> Result<Offer>;
    /// Set the given selection to the given representations.
    ///
    /// Takes a shared offer for the same reason [`Message::Clip`] does: this is
    /// a terminal hop for the payload, and the engine's batch holds every
    /// planned action's content alive, so an owned parameter would deep-copy the
    /// whole clipboard per write.
    ///
    /// [`Message::Clip`]: crate::protocol::Message::Clip
    async fn write_offer(&self, kind: SelectionKind, offer: Arc<Offer>) -> Result<()>;
}

/// The clipboard backend the daemon runs, picked once at startup by
/// [`Backend::select`]. An enum rather than `Arc<dyn Clipboard>` because the
/// generic bound runs through `ClipboardIo<C>` and `SyncEngine<C>`, and a
/// two-arm delegating impl is smaller than threading `?Sized` through them.
pub enum Backend {
    /// The data-control protocol, in-process (`wayland.rs` + `watch.rs`).
    Wayland(wayland::WaylandClipboard),
    /// Mutter's remote-desktop clipboard D-Bus API (`mutter.rs`): GNOME.
    Mutter(mutter::MutterClipboard),
}

/// A resolved [`BackendChoice`]: what `auto` decided, or what was forced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackendKind {
    DataControl,
    Mutter,
}

impl Backend {
    /// Resolve `cfg.backend` and build the backend. `auto` probes the
    /// compositor for a data-control global and falls back to Mutter; a
    /// forced choice skips the probe, and its own connection errors then say
    /// why it cannot work. Refuses a config the chosen backend cannot honour
    /// (see [`refuse_primary_features`]).
    pub fn select(cfg: &Config) -> Result<Backend> {
        let kind = resolve_kind(cfg.backend, watch::data_control_available);
        refuse_primary_features(cfg, kind)?;
        Ok(match kind {
            BackendKind::DataControl => {
                info!("clipboard backend: Wayland data-control");
                Backend::Wayland(wayland::WaylandClipboard::new(cfg.max_payload_size))
            }
            BackendKind::Mutter => {
                info!("clipboard backend: Mutter remote-desktop clipboard API (CLIPBOARD only)");
                Backend::Mutter(mutter::MutterClipboard::new(
                    cfg.max_payload_size,
                    Arc::new(mutter::SessionBus),
                ))
            }
        })
    }
}

/// Which backend a [`BackendChoice`] means, probing the compositor only for
/// `auto`. Takes the probe so the rule can be tested without a compositor.
///
/// A probe that *errors* resolves to Mutter rather than failing: the error is
/// "there is no Wayland display to ask", and the Mutter backend needs none —
/// it speaks D-Bus. A GNOME session that never exported `WAYLAND_DISPLAY` into
/// the systemd user environment is exactly that case, and refusing to start
/// there turned a working configuration into a restart loop under the shipped
/// unit's `Restart=always`. Where Mutter genuinely isn't there either, its own
/// supervised loop says so, with backoff, instead of the process exiting.
fn resolve_kind(choice: BackendChoice, probe: impl FnOnce() -> Result<bool>) -> BackendKind {
    match choice {
        BackendChoice::DataControl => BackendKind::DataControl,
        BackendChoice::Mutter => BackendKind::Mutter,
        BackendChoice::Auto => match probe() {
            Ok(true) => BackendKind::DataControl,
            Ok(false) => {
                info!(
                    "the compositor offers no data-control protocol; using Mutter's \
                     clipboard API (set backend = \"data-control\" to insist)"
                );
                BackendKind::Mutter
            }
            Err(e) => {
                info!(
                    "couldn't ask the compositor for a data-control protocol ({e:#}); \
                     using Mutter's clipboard API"
                );
                BackendKind::Mutter
            }
        },
    }
}

/// The Mutter backend reaches only CLIPBOARD, and `sync_selection` and
/// `link_selections` both need PRIMARY. Refusing to start is deliberate: run
/// anyway and the settings are half-dead — PRIMARY changes are never seen, and
/// every inbound PRIMARY clip or clipboard→PRIMARY mirror fails with a warning,
/// forever. The config is per host, so the fix named here is local to it.
pub(crate) fn refuse_primary_features(cfg: &Config, kind: BackendKind) -> Result<()> {
    if kind != BackendKind::Mutter {
        return Ok(());
    }
    let mut offending = Vec::new();
    if cfg.sync_selection {
        offending.push("sync_selection");
    }
    if cfg.link_selections.clipboard_to_selection || cfg.link_selections.selection_to_clipboard {
        offending.push("link_selections");
    }
    if offending.is_empty() {
        return Ok(());
    }
    bail!(
        "{} need{} the PRIMARY (middle-click) selection, which GNOME does not expose \
         through Mutter's clipboard API; disable {} on this host",
        offending.join(" and "),
        if offending.len() == 1 { "s" } else { "" },
        if offending.len() == 1 { "it" } else { "them" }
    )
}

#[async_trait]
impl Clipboard for Backend {
    fn watch(&self, kinds: &[SelectionKind]) -> mpsc::UnboundedReceiver<ClipboardEvent> {
        match self {
            Backend::Wayland(c) => c.watch(kinds),
            Backend::Mutter(c) => c.watch(kinds),
        }
    }

    async fn list_types(&self, kind: SelectionKind) -> Result<Vec<String>> {
        match self {
            Backend::Wayland(c) => c.list_types(kind).await,
            Backend::Mutter(c) => c.list_types(kind).await,
        }
    }

    async fn read_offer(&self, kind: SelectionKind, only: Option<&str>) -> Result<Offer> {
        match self {
            Backend::Wayland(c) => c.read_offer(kind, only).await,
            Backend::Mutter(c) => c.read_offer(kind, only).await,
        }
    }

    async fn write_offer(&self, kind: SelectionKind, offer: Arc<Offer>) -> Result<()> {
        match self {
            Backend::Wayland(c) => c.write_offer(kind, offer).await,
            Backend::Mutter(c) => c.write_offer(kind, offer).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LinkSelections;

    fn test_cfg() -> Config {
        Config::for_test("s")
    }

    #[test]
    fn a_forced_backend_is_never_probed() {
        let probe = || panic!("a forced choice must not touch the compositor");
        assert_eq!(
            resolve_kind(BackendChoice::DataControl, probe),
            BackendKind::DataControl
        );
        assert_eq!(
            resolve_kind(BackendChoice::Mutter, probe),
            BackendKind::Mutter
        );
    }

    #[test]
    fn auto_follows_the_probe_and_falls_back_to_mutter_when_it_cannot_ask() {
        assert_eq!(
            resolve_kind(BackendChoice::Auto, || Ok(true)),
            BackendKind::DataControl
        );
        assert_eq!(
            resolve_kind(BackendChoice::Auto, || Ok(false)),
            BackendKind::Mutter
        );
        // No Wayland display to probe is not a reason to refuse to start: the
        // Mutter backend only needs D-Bus, and this is a GNOME host whose
        // WAYLAND_DISPLAY never reached the service environment.
        assert_eq!(
            resolve_kind(BackendChoice::Auto, || bail!("no Wayland display")),
            BackendKind::Mutter
        );
    }

    #[test]
    fn primary_features_are_fine_on_data_control() {
        let mut cfg = test_cfg();
        cfg.sync_selection = true;
        cfg.link_selections = LinkSelections::BOTH;
        assert!(refuse_primary_features(&cfg, BackendKind::DataControl).is_ok());
    }

    #[test]
    fn mutter_without_primary_features_is_fine() {
        assert!(refuse_primary_features(&test_cfg(), BackendKind::Mutter).is_ok());
    }

    #[test]
    fn mutter_refuses_each_primary_feature_by_name() {
        let mut cfg = test_cfg();
        cfg.sync_selection = true;
        let err = refuse_primary_features(&cfg, BackendKind::Mutter)
            .unwrap_err()
            .to_string();
        assert!(err.contains("sync_selection"), "{err}");
        assert!(!err.contains("link_selections"), "{err}");

        let mut cfg = test_cfg();
        cfg.link_selections = LinkSelections::CLIPBOARD_TO_SELECTION;
        let err = refuse_primary_features(&cfg, BackendKind::Mutter)
            .unwrap_err()
            .to_string();
        assert!(err.contains("link_selections"), "{err}");

        let mut cfg = test_cfg();
        cfg.sync_selection = true;
        cfg.link_selections = LinkSelections::SELECTION_TO_CLIPBOARD;
        let err = refuse_primary_features(&cfg, BackendKind::Mutter)
            .unwrap_err()
            .to_string();
        assert!(err.contains("sync_selection and link_selections"), "{err}");
    }
}
