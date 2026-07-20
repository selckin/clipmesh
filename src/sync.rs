use crate::clipboard::io::{ClipboardIo, Origin};
use crate::clipboard::{Clipboard, ClipboardEvent};
use crate::config::{Config, Direction, LinkSelections};
use crate::mesh::Mesh;
use crate::mime::{self, lock_rules, MimeRules};
use crate::protocol::{
    describe_offer, encode_frame, human_bytes, is_text_plain, GetResult, GetWant, Hashed, Message,
    Offer, SelectionKind, Unavailable, Version, TEXT_PLAIN,
};
use indexmap::IndexMap;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use uuid::Uuid;

pub const SENSITIVE_MIME: &str = "x-kde-passwordManagerHint";

/// Reject inbound stamps more than this far in the future. A healthy hybrid
/// clock stamp is always near wall-clock time; a wildly larger value (a
/// buggy/malicious peer, or one with a broken RTC) would otherwise pin our
/// logical clock high and stop our own copies from ever winning again.
const MAX_FUTURE_SKEW_MS: u64 = 24 * 60 * 60 * 1000;

/// Password managers mark secret clipboard contents with this hint.
pub fn is_sensitive(offer: &Offer) -> bool {
    offer
        .get(SENSITIVE_MIME)
        .map(|v| v.trim_ascii() == b"secret")
        .unwrap_or(false)
}

fn offer_size(offer: &Offer) -> usize {
    offer.iter().map(|(m, d)| m.len() + d.len()).sum()
}

/// Optional compatibility shim (`synthesize_text_plain` config): when an offer
/// carries a legacy plain-text atom but no `text/plain*` representation,
/// synthesize `text/plain;charset=utf-8` and `text/plain` immediately before the
/// source atom, so Wayland-native pasters that only understand `text/plain` can
/// still paste content copied from an X11/legacy app. A no-op if any
/// `text/plain*` already exists or no source atom is present.
///
/// Which atoms qualify and how each one's bytes decode is X11 selection
/// semantics, owned by [`atoms`] — this asks it for "a text value from this
/// offer" and only decides where to put the result.
///
/// [`atoms`]: crate::clipboard::atoms
fn synthesize_text_plain(content: Hashed) -> Hashed {
    let offer = content.offer();
    if offer.keys().any(|k| is_text_plain(k)) {
        return content;
    }
    let Some((src, value)) = crate::clipboard::atoms::text_value(offer) else {
        return content; // no legacy atom to derive from
    };
    let mut out = Offer::with_capacity(offer.len() + TEXT_PLAIN.len());
    for (k, v) in content.into_offer() {
        if k == src {
            // Richest first, the order `paste::select_type` prefers them in.
            for mime in TEXT_PLAIN {
                out.insert(mime.to_string(), value.clone());
            }
        }
        out.insert(k, v);
    }
    Hashed::new(out)
}

/// Trim the offer to `max` bytes, dropping individual representations that don't
/// fit (smallest-first, so a small text payload survives even when a giant image
/// would blow the budget) instead of dropping the whole offer. The smallest-first
/// pass only decides *which* reps survive; the kept reps are emitted in the
/// offer's original (advertise) order, so over-budget truncation preserves the
/// source's preference order.
///
/// This is the *policy* application of `max_payload_size`, run after the MIME
/// rules and with every representation's size known. The read path in
/// `wayland::assemble_offer` spends the same number as a *resource guard*, under
/// streaming ignorance of sizes and before the rules — see its doc comment for
/// why the two cannot be collapsed into one.
fn cap_to_payload_size(content: Hashed, max: usize) -> Hashed {
    if offer_size(content.offer()) <= max {
        return content; // common case: the whole offer fits
    }
    let reps: Vec<(String, Vec<u8>)> = content.into_offer().into_iter().collect();
    // Choose survivors smallest-first (maximizes how many fit), recording which
    // by original index so the output can preserve the advertise order.
    let mut by_size: Vec<usize> = (0..reps.len()).collect();
    by_size.sort_by_key(|&i| reps[i].0.len() + reps[i].1.len());
    let mut total = 0usize;
    let mut keep = vec![false; reps.len()];
    for i in by_size {
        let (mime, data) = &reps[i];
        let sz = mime.len() + data.len();
        if total.saturating_add(sz) > max {
            // warn, not debug: at the default log level the user would
            // otherwise have no clue why a large copy never syncs.
            warn!(
                "dropping {mime} ({}): doesn't fit the {} max_payload_size budget \
                 (raise max_payload_size to sync more)",
                human_bytes(data.len()),
                human_bytes(max)
            );
            continue;
        }
        total += sz;
        keep[i] = true;
    }
    Hashed::new(
        reps.into_iter()
            .enumerate()
            .filter(|(i, _)| keep[*i])
            .map(|(_, kv)| kv)
            .collect(),
    )
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// What this node believes is the mesh-current content of one selection.
/// One record replaces the former three parallel maps so the hash, the
/// ordering stamp, and the origin can never describe different contents.
#[derive(Clone, Copy)]
struct ContentState {
    hash: [u8; 32],
    /// Orders this content against any other; see [`Version`].
    version: Version,
}

impl ContentState {
    /// True if `v` strictly supersedes this state's order.
    fn superseded_by(&self, v: Version) -> bool {
        v > self.version
    }
}

/// Bridges the local clipboard and the mesh, with echo suppression,
/// ordering, debounce, direction control, and content filtering.
pub struct SyncEngine<C> {
    /// The only route to the clipboard backend. `ClipboardIo` owns the backend
    /// privately in another module, so the engine physically cannot call
    /// `Clipboard::write_offer` and skip the echo-suppression record — see its
    /// docs for why that is a type-level guarantee rather than a convention.
    io: ClipboardIo<C>,
    mesh: Arc<Mesh>,
    cfg: Arc<Config>,
    /// Mesh-current content per selection. Updated on both broadcast and
    /// apply; echo/dedup is "incoming hash == current hash", ordering is
    /// `(stamp, origin)`.
    current: Mutex<HashMap<SelectionKind, ContentState>>,
    /// Per-selection decisions, computed once from `cfg` (see [`SelectionPolicy`]).
    policies: Policies,
    /// Hybrid logical clock: max of wall-clock ms and the highest stamp
    /// seen, so reordered or modestly skewed updates still order sanely.
    clock: Mutex<u64>,
    /// Per-type allow/deny rules, shared with the file watcher (`fswatch`),
    /// which reloads them on external edits. `apply_mime_rules` reloads only
    /// when it's about to record a new type, so the common capture path does no
    /// file I/O.
    mime_rules: Arc<Mutex<MimeRules>>,
    /// Self-ping used by the capture path to ask the run loop to bump the
    /// shared rules version and broadcast the file (so the broadcast happens on
    /// the loop, not inside the sync filter). fswatch holds a clone too.
    rules_changed_tx: mpsc::Sender<()>,
}

/// What a pipeline does with the per-type MIME rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RulesStage {
    /// Apply them, and append types not seen before so the user can curate
    /// them. Local capture only.
    Record,
    /// Apply them without appending — a peer must not be able to write to our
    /// rules file.
    Apply,
    /// Don't consult them.
    Skip,
}

/// The content transforms one pipeline applies, in order.
///
/// There are four pipelines and they differ in ways a single boolean can't
/// express; declaring them side by side is the point, so a fifth is a new
/// constant rather than another flag threaded through a shared function.
/// Sensitivity is not listed: it gates every pipeline unconditionally.
#[derive(Debug, Clone, Copy)]
struct Stages {
    /// Back-fill `text/plain` from a legacy X11 atom. Capture-side only — it is
    /// a courtesy to local legacy apps, not something to do to a peer's content.
    synthesize: bool,
    rules: RulesStage,
    /// Trim to `max_payload_size`.
    cap: bool,
}

/// Why content is moving — and therefore which transforms apply to it.
///
/// **One taxonomy for every pipeline.** `Provenance` used to name only the two
/// *write* pipelines and map to `Stages` through a partial function, leaving the
/// other selections spelled out as constants at their call sites. Each new
/// consumer then went around the mapping rather than through it — `Serve` was
/// added that way — so the two taxonomies drifted apart by construction.
/// Naming the pipeline here and asking it for its stages means a sixth one is a
/// variant plus a match arm the compiler demands, not a new constant somebody
/// has to notice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pipeline {
    /// Locally captured content heading for the mesh.
    Broadcast,
    /// A peer's offer being applied locally.
    Inbound,
    /// The `take_ownership` re-offer.
    Own,
    /// The local bridge mirror.
    Mirror,
    /// Answering a remote `--paste` query.
    Serve,
}

impl Pipeline {
    /// The transforms this pipeline applies, in order. Total by construction —
    /// the one place a pipeline turns into transforms.
    fn stages(self) -> Stages {
        match self {
            // Everything applies.
            Pipeline::Broadcast => Stages {
                synthesize: true,
                rules: RulesStage::Record,
                cap: true,
            },
            // The receiver enforces its own content policy (configs differ
            // between peers, and a node must not write contents it would never
            // have sent), but records nothing — a peer must not be able to write
            // to our rules file.
            Pipeline::Inbound => Stages {
                synthesize: false,
                rules: RulesStage::Apply,
                cap: true,
            },
            // Synthesis is on so the back-filled `text/plain` pastes on this
            // host too, and the cap keeps the rewrite round-tripping the
            // read-back budget — an over-budget rewrite would be re-read
            // smaller, miss its marker, and churn.
            //
            // Rules are deliberately skipped: a deny rule governs what leaves
            // this host, not what the user may paste locally. Filtering here
            // would strip types out of the user's own clipboard.
            Pipeline::Own => Stages {
                synthesize: true,
                rules: RulesStage::Skip,
                cap: true,
            },
            // Deliberately unfiltered, so locally denied or oversized
            // representations still reach the partner selection — the bridge
            // moves content between two selections on one host and never
            // touches the wire.
            Pipeline::Mirror => Stages {
                synthesize: false,
                rules: RulesStage::Skip,
                cap: false,
            },
            // The same filters as `Broadcast` — a pull must not expose what a
            // push wouldn't, password-manager contents included — but `Apply`,
            // not `Record`. That difference is the point: `Record` appends
            // unseen types, persists the rules file and broadcasts it mesh-wide,
            // and answering a question is not capturing. A stranger's
            // `wl-paste` must not make this node rewrite its rules and push them
            // to every peer.
            Pipeline::Serve => Stages {
                synthesize: true,
                rules: RulesStage::Apply,
                cap: true,
            },
        }
    }
}

/// Why the engine writes a selection during a batch — selects the reconcile
/// rule in `execute_write`.
///
/// Deliberately narrower than [`Pipeline`]: only two pipelines can be the reason
/// for a *write*, and `plan_batch` should not be able to emit "broadcast" as a
/// write provenance. It converts into `Pipeline` rather than carrying its own
/// stage mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provenance {
    /// `take_ownership` re-offer: write unconditionally (ownership transfer),
    /// even when the selection already holds these bytes.
    Own,
    /// Local-bridge mirror with `take_ownership` off: write only when the
    /// partner does not already hold this content (reconcile against drift).
    Mirror,
}

impl Provenance {
    /// The pipeline this kind of write runs through.
    fn pipeline(self) -> Pipeline {
        match self {
            Provenance::Own => Pipeline::Own,
            Provenance::Mirror => Pipeline::Mirror,
        }
    }
}

/// One planned act of propagation: which selection it acts on, and which of the
/// batch's reads supplies the content.
///
/// The plan names its content rather than carrying it. Every payload a batch
/// propagates is the content of some genuinely-changed selection — its own, or
/// (for a mirrored partner) its bridge source — so `source` always indexes the
/// batch's reads. That keeps planning a decision about *selections*, with no
/// clipboard payload copied to reach it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Action {
    /// The selection being broadcast or written.
    target: SelectionKind,
    /// The changed selection whose content fills it. Equal to `target` for a
    /// genuine change; the bridge source for a mirrored partner.
    source: SelectionKind,
}

impl Action {
    /// A selection propagating its own content.
    fn direct(kind: SelectionKind) -> Action {
        Action {
            target: kind,
            source: kind,
        }
    }
}

/// The broadcasts and writes a debounce batch produces, computed up front so
/// propagation never rides watch echoes. Each selection is written at most once.
struct BatchPlan {
    broadcasts: Vec<Action>,
    writes: Vec<(Action, Provenance)>,
}

/// What this node does with one selection, decided once from the config.
///
/// Every per-selection question — may we send it, may we receive it, do we watch
/// it, do we re-own it, do we mirror it somewhere — used to be answered by its
/// own predicate re-deriving the rule from `Config`, so the same
/// `kind != Selection || sync_selection` condition appeared verbatim in several
/// places and in three more shapes elsewhere. Adding a selection or a
/// per-selection knob meant finding all of them, with no compiler help.
#[derive(Debug, Clone, Copy)]
struct SelectionPolicy {
    /// Broadcast local changes to this selection.
    send: bool,
    /// Apply peers' updates to this selection.
    recv: bool,
    /// Observe it at all (a superset of `send`/`recv`: the local bridge may need
    /// a selection this node never syncs).
    watch: bool,
    /// Re-offer it after a local copy so clipmesh owns the content.
    own: bool,
    /// The selection local changes to this one are mirrored INTO.
    mirror_into: Option<SelectionKind>,
}

impl SelectionPolicy {
    fn for_kind(kind: SelectionKind, cfg: &Config) -> Self {
        // SELECTION participates in the mesh only when explicitly enabled;
        // CLIPBOARD always does. This is the rule that was previously restated
        // at every call site.
        let on_mesh = kind != SelectionKind::Selection || cfg.sync_selection;
        let mirror_into = link_partner(kind, cfg.link_selections);
        SelectionPolicy {
            send: on_mesh && cfg.direction != Direction::ReceiveOnly,
            recv: on_mesh && cfg.direction != Direction::SendOnly,
            // Watched if it is synced, or if the bridge needs to see its changes
            // in order to mirror them. Note a mirror *target* is deliberately
            // NOT watched on that account: `execute_write` reconciles against it
            // by reading it on demand.
            watch: on_mesh || mirror_into.is_some(),
            own: cfg.take_ownership,
            mirror_into,
        }
    }

    /// Whether any local sink would act on a change to this selection: the mesh,
    /// the bridge, or the ownership rewrite. When none would, the batch skips
    /// the read entirely.
    fn has_local_sink(&self) -> bool {
        self.send || self.mirror_into.is_some() || self.own
    }
}

/// The per-selection policies, indexed by `SelectionKind`.
#[derive(Debug)]
struct Policies([SelectionPolicy; 2]);

impl Policies {
    fn new(cfg: &Config) -> Self {
        Policies(SelectionKind::ALL.map(|k| SelectionPolicy::for_kind(k, cfg)))
    }

    /// `SelectionKind::{ALL, index}` are the single definition of the array
    /// layout: `new` fills the slots through `ALL` and `get` looks them up
    /// through `index`, so one selection can't silently be handed another's
    /// policy. `index` is an exhaustive `match`, so the lookup is infallible.
    fn get(&self, kind: SelectionKind) -> &SelectionPolicy {
        &self.0[kind.index()]
    }

    /// The selections satisfying `pick`, in a stable order (CLIPBOARD first).
    fn kinds(&self, pick: impl Fn(&SelectionPolicy) -> bool) -> Vec<SelectionKind> {
        SelectionKind::ALL
            .into_iter()
            .filter(|k| pick(self.get(*k)))
            .collect()
    }
}

/// The selection a configured link direction mirrors `kind` INTO, or `None`.
/// Single place that maps the `link_selections` directions to a source→partner
/// pair. A free function so the pure planner needs no `&self`.
fn link_partner(kind: SelectionKind, link: LinkSelections) -> Option<SelectionKind> {
    match kind {
        SelectionKind::Clipboard if link.clipboard_to_selection => Some(SelectionKind::Selection),
        SelectionKind::Selection if link.selection_to_clipboard => Some(SelectionKind::Clipboard),
        _ => None,
    }
}

/// Decide a batch's broadcasts and writes from its genuine local changes. Pure:
/// no I/O, no content transforms (the `Own` synth+cap and the `Mirror` reconcile
/// happen in `execute_write`), and no clipboard payload at all — the decision
/// depends only on *which* selections changed, so `changed` is the list of
/// genuine user changes (echoes already removed) in batch order.
fn plan_batch(changed: &[SelectionKind], link: LinkSelections, own: bool) -> BatchPlan {
    // Every genuine change propagates its own content.
    let direct: Vec<Action> = changed.iter().copied().map(Action::direct).collect();

    // Mirror targets: a selection some genuine change mirrors INTO that is not
    // itself a genuine change (direct-change-wins — never clobber a concurrent
    // user change). The two selections never share a partner (the mapping is a
    // bijection), so each target has a single source.
    let mirrors: Vec<Action> = changed
        .iter()
        .filter_map(|&source| {
            let target = link_partner(source, link)?;
            (!changed.contains(&target)).then_some(Action { target, source })
        })
        .collect();

    // Broadcasts: every genuine change, then every mirror target (so a mirrored
    // partner still reaches the mesh, as today). The caller applies may_send +
    // content filters + mesh-current dedup, so a non-synced or unchanged
    // selection yields no actual send.
    let broadcasts: Vec<Action> = direct.iter().chain(&mirrors).copied().collect();

    // Writes, each selection at most once:
    //  - own on  -> Own (unconditional) for every genuine change AND every mirror
    //    target (the mirror+own merge: one owned write, no separate mirror write).
    //    That is exactly the broadcast set, so it is *derived* from `broadcasts`
    //    rather than rebuilt from the same two pieces — a second `direct.chain(
    //    &mirrors)` would leave the sets equal only by the two expressions
    //    staying in step, with a comment standing in for the guarantee.
    //  - own off -> Mirror (reconciled) for mirror targets only; genuine changes
    //    are broadcast but not written locally.
    let writes = if own {
        broadcasts.iter().map(|&a| (a, Provenance::Own)).collect()
    } else {
        mirrors.iter().map(|&a| (a, Provenance::Mirror)).collect()
    };

    BatchPlan { broadcasts, writes }
}

/// The content an action propagates: this batch's read of its source selection.
///
/// Panics rather than returning an `Option` the callers would have to fake-handle
/// with a silent `continue`: `plan_batch` only ever sources from `changed`, and
/// every changed selection was read into `read`. A miss would mean the planner
/// and the reader disagree — a bug, not a runtime condition.
fn content_for(read: &IndexMap<SelectionKind, Hashed>, action: Action) -> Hashed {
    read.get(&action.source)
        .unwrap_or_else(|| {
            panic!("planned {action:?} sources content from a selection this batch never read")
        })
        .clone()
}

impl<C: Clipboard> SyncEngine<C> {
    pub fn new(
        clipboard: Arc<C>,
        mesh: Arc<Mesh>,
        cfg: Arc<Config>,
        mime_rules: Arc<Mutex<MimeRules>>,
        rules_changed_tx: mpsc::Sender<()>,
    ) -> Arc<SyncEngine<C>> {
        Arc::new(SyncEngine {
            io: ClipboardIo::new(clipboard),
            mesh,
            policies: Policies::new(&cfg),
            cfg,
            current: Mutex::new(HashMap::new()),
            clock: Mutex::new(0),
            mime_rules,
            rules_changed_tx,
        })
    }

    /// Selections this node syncs over the mesh, in either direction. Only the
    /// tests ask this broad question now — the engine's own paths each name the
    /// direction they mean (`p.send` / `p.recv`) rather than the union.
    #[cfg(test)]
    fn synced_kinds(&self) -> Vec<SelectionKind> {
        self.policies.kinds(|p| p.send || p.recv)
    }

    /// Selections worth observing. Broader than `synced_kinds`: the local bridge
    /// may need a selection this node never syncs. Handed to `Clipboard::watch`,
    /// and by the startup-restore path to decide what to adopt.
    fn watched_kinds(&self) -> Vec<SelectionKind> {
        self.policies.kinds(|p| p.watch)
    }

    fn may_send(&self, kind: SelectionKind) -> bool {
        self.policies.get(kind).send
    }

    fn may_recv(&self, kind: SelectionKind) -> bool {
        self.policies.get(kind).recv
    }

    /// Issue a fresh stamp for locally originated content. saturating_add
    /// keeps a poisoned clock from panicking (debug) or wrapping to 0
    /// (release) — defense in depth behind the inbound skew check.
    fn tick(&self) -> u64 {
        let mut c = self.clock.lock().unwrap();
        *c = c.saturating_add(1).max(now_ms());
        *c
    }

    /// Advance the logical clock past a stamp we received.
    fn observe(&self, stamp: u64) {
        let mut c = self.clock.lock().unwrap();
        *c = (*c).max(stamp);
    }

    /// Gate an inbound stamp into the hybrid clock: drop implausibly-future
    /// stamps before they reach it, so one peer with a broken clock can't poison
    /// ordering for this node, then fold an accepted stamp in. `what` names the
    /// message kind for the warning. Returns whether the stamp was accepted.
    fn accept_stamp(&self, v: Version, from: Uuid, what: &str) -> bool {
        if v.stamp > now_ms().saturating_add(MAX_FUTURE_SKEW_MS) {
            warn!(
                "rejecting {what} from peer {from}: timestamp {} is implausibly far in the future (peer clock skew?)",
                v.stamp
            );
            return false;
        }
        self.observe(v.stamp);
        true
    }

    /// Main loop. Debounce lives in the select as a deadline arm so that a
    /// storm of local change events can never starve inbound/connect
    /// processing. Runs until any of its input channels close.
    pub async fn run(
        self: Arc<Self>,
        mut inbound: mpsc::Receiver<(Uuid, Message)>,
        mut connects: mpsc::Receiver<Uuid>,
        mut rules_changed: mpsc::Receiver<()>,
    ) {
        // The backend reports the pre-existing clipboard as `Initial` events on
        // this stream, ahead of any `Changed`. Startup content therefore arrives
        // *in order* with local changes rather than being read back separately,
        // which is what makes "restored" and "the user just copied this"
        // distinguishable at all — see `Clipboard::watch`.
        let mut watch = self.io.watch(&self.watched_kinds());

        // Adopt the rules file's persisted version into the clock so the next
        // local edit outranks it after a restart. Inline rather than through
        // `with_rules`: the select loop has not started, so there is nothing to
        // stall.
        {
            let own_id = self.mesh.own_id();
            let stamp = lock_rules(&self.mime_rules).version(own_id).stamp;
            self.observe(stamp);
        }

        let window = Duration::from_millis(self.cfg.debounce_ms);
        let mut pending: Vec<SelectionKind> = Vec::new();
        // Far-future placeholder so the timer is always present in the
        // select; the `armed` precondition keeps it from firing until a
        // local change arms it.
        let deadline = tokio::time::sleep(Duration::from_secs(86_400));
        tokio::pin!(deadline);
        let mut armed = false;

        loop {
            // Set by the arm that observes a local change, so the debounce
            // policy below is stated once rather than per arm.
            let mut local_change = false;
            tokio::select! {
                event = watch.recv() => match event {
                    // Pre-existing content, captured by the backend at subscribe
                    // time. Recorded, never propagated: it is not a user action.
                    Some(ClipboardEvent::Initial { kind, offer }) => {
                        self.adopt_restored(kind, Hashed::new(offer)).await;
                    }
                    Some(ClipboardEvent::Changed(kind)) => {
                        if !pending.contains(&kind) {
                            pending.push(kind);
                        }
                        local_change = true;
                    }
                    None => {
                        warn!("clipboard watcher stopped; shutting down the sync engine");
                        break;
                    }
                },
                _ = &mut deadline, if armed => {
                    armed = false;
                    self.handle_batch(std::mem::take(&mut pending)).await;
                },
                msg = inbound.recv() => match msg {
                    Some((from, msg)) => self.on_inbound(from, msg).await,
                    None => {
                        warn!("inbound channel closed; shutting down the sync engine");
                        break;
                    }
                },
                peer = connects.recv() => match peer {
                    Some(peer) => {
                        // Peers reconnect in bursts — a switch or AP blip, a
                        // laptop waking, this node restarting — and each
                        // connect would otherwise re-read the clipboard and
                        // re-serialize the same payload per peer. Drain the
                        // rest of the burst first so the resync costs one read
                        // and one encode for the whole group.
                        let mut peers = vec![peer];
                        while let Ok(more) = connects.try_recv() {
                            if !peers.contains(&more) {
                                peers.push(more);
                            }
                        }
                        self.on_peers_connected(&peers).await
                    }
                    None => {
                        warn!("connect-event channel closed; shutting down the sync engine");
                        break;
                    }
                },
                res = rules_changed.recv() => match res {
                    Some(()) => self.on_local_rules_changed().await,
                    // The engine itself holds a sender clone, so this channel
                    // can't actually close while run() is alive; the break is a
                    // safety net against a busy-loop if it somehow did.
                    None => {
                        warn!("rules-change channel closed unexpectedly; stopping the sync engine");
                        break;
                    }
                },
            }
            // The debounce policy, in one place: with no window, drain the batch
            // immediately; otherwise (re)start the window and let the deadline
            // arm above drain it.
            if local_change {
                if self.cfg.debounce_ms == 0 {
                    self.handle_batch(std::mem::take(&mut pending)).await;
                } else {
                    deadline
                        .as_mut()
                        .reset(tokio::time::Instant::now() + window);
                    armed = true;
                }
            }
        }
    }

    /// Record the clipboard that already existed when this node started (or when
    /// the watcher reconnected), as reported by the backend's `Initial` event.
    ///
    /// Restored content is deliberately inert: not broadcast, not bridged, not
    /// re-owned. It is seeded into `current` at **stamp 0** so a peer holding
    /// genuinely newer content wins a resync — this node cannot know how old its
    /// restored clipboard is, so it must not outrank anyone.
    ///
    /// Unlike the read-it-back-later approach this replaces, the content here is
    /// what the backend captured at subscribe time, so a copy the user makes a
    /// moment after startup arrives as `Changed` and propagates normally instead
    /// of being mistaken for restored content and suppressed.
    ///
    /// No `last_written` marker is needed: this event *is* the startup
    /// notification, so there is no separate echo of it to suppress.
    async fn adopt_restored(&self, kind: SelectionKind, raw: Hashed) {
        let p = self.policies.get(kind);
        if raw.is_empty() || !(p.send || p.recv) {
            return;
        }
        let Ok(content) = self.apply_stages(raw, Pipeline::Broadcast).await else {
            return;
        };
        debug!(
            "adopted the existing {kind:?} clipboard ({})",
            describe_offer(content.offer())
        );
        // or_insert: an inbound apply may already have recorded newer content
        // for this selection — don't clobber it with stamp-0 restored content.
        self.current
            .lock()
            .unwrap()
            .entry(kind)
            .or_insert(ContentState {
                hash: content.hash(),
                version: Version::new(0, self.mesh.own_id()),
            });
    }

    /// Whether this offer must be withheld because the user opted to exclude
    /// password-manager-flagged contents. Shared by the mesh `filter` and the
    /// local mirror/ownership writes in `execute_write`, so the secret-handling
    /// policy lives in one place.
    fn excludes_sensitive(&self, offer: &Offer) -> bool {
        self.cfg.exclude_sensitive && is_sensitive(offer)
    }

    /// Run the declared [`Stages`] over an already-read offer.
    ///
    /// Returns **why** nothing survived rather than a bare `None`. Most callers
    /// only branch on success, but a `--paste` client is told this over the wire,
    /// and "the clipboard is empty" is a bad answer to "every type you offered is
    /// denied by my rules". The reason existed already — each arm below logs a
    /// distinct line — it was just rendered into a debug string on the serving
    /// host instead of returned as a value.
    ///
    /// Sensitivity is checked first and is not a stage: it applies to every
    /// pipeline unconditionally, and checking it before synthesis skips needless
    /// work on secret content (synthesis never changes the verdict — it adds no
    /// password-manager hint).
    async fn apply_stages(
        &self,
        content: Hashed,
        pipeline: Pipeline,
    ) -> Result<Hashed, Unavailable> {
        let stages = pipeline.stages();
        if content.is_empty() {
            debug!("nothing to sync: the clipboard is empty");
            return Err(Unavailable::Empty);
        }
        if self.excludes_sensitive(content.offer()) {
            debug!("not syncing: clipboard is flagged sensitive (password-manager contents)");
            return Err(Unavailable::Sensitive);
        }
        let content = if stages.synthesize && self.cfg.synthesize_text_plain {
            synthesize_text_plain(content)
        } else {
            content
        };
        let content = match stages.rules {
            RulesStage::Skip => content,
            rules => {
                let content = self
                    .apply_mime_rules(content, rules == RulesStage::Record)
                    .await;
                if content.is_empty() {
                    debug!("nothing to sync: every MIME type was blocked by the rules");
                    return Err(Unavailable::Denied);
                }
                content
            }
        };
        if !stages.cap {
            // Nothing below can empty the offer, so it is still non-empty here.
            return Ok(content);
        }
        let content = cap_to_payload_size(content, self.cfg.max_payload_size);
        if content.is_empty() {
            debug!("nothing to sync: everything was over the max_payload_size budget");
            return Err(Unavailable::TooLarge);
        }
        Ok(content)
    }

    async fn apply_mime_rules(&self, content: Hashed, record_unseen: bool) -> Hashed {
        let share = self.cfg.share_mime_rules;
        let (content, appended) = self
            .with_rules(move |rules| {
                let mut appended = false;
                if record_unseen {
                    // A keys-only probe, not a full compile: the common capture
                    // has nothing new, and building the compiled view here would
                    // be thrown away and rebuilt below anyway.
                    if rules.has_unseen(content.offer().keys()) {
                        rules.reload_if_changed();
                        appended = rules.ensure(content.offer().keys());
                    }
                    // No-op unless something is unsaved (incl. retrying a failed write).
                    rules.persist();
                }
                // Compile once for the whole offer rather than re-walking the TOML per
                // representation. Deliberately after the block above: that may rewrite
                // the table, and the borrow checker enforces the recompile.
                let compiled = rules.compile();
                // Decide before rebuilding: when the rules deny nothing — the ordinary
                // case — the content is unchanged, so return it as-is and its hash stays
                // valid. Only a genuine drop rebuilds the map (and rehashes).
                let denied: Vec<String> = content
                    .offer()
                    .iter()
                    .filter(|(mime, data)| !compiled.allows(mime, data.len()))
                    .map(|(mime, _)| mime.clone())
                    .collect();
                if denied.is_empty() {
                    return (content, appended);
                }
                for mime in &denied {
                    debug!(
                        "dropping {mime} ({}): blocked by the MIME rules",
                        human_bytes(content.offer()[mime].len())
                    );
                }
                let denied: std::collections::HashSet<String> = denied.into_iter().collect();
                let kept = Hashed::new(
                    content
                        .into_offer()
                        .into_iter()
                        .filter(|(mime, _)| !denied.contains(mime))
                        .collect(),
                );
                (kept, appended)
            })
            .await;
        // A newly-recorded type changes the file; share it. Outside the closure
        // because the rules lock is gone by here — no re-lock hazard.
        if appended && share {
            self.note_rules_changed();
        }
        content
    }

    async fn capture_offer(&self, kind: SelectionKind) -> Option<Hashed> {
        let content = self.io.read(kind).await?;
        // Local content: record brand-new types so the user can curate them.
        self.apply_stages(content, Pipeline::Broadcast).await.ok()
    }

    /// Broadcast `raw` (the freshly-read content of `kind`) to the mesh after
    /// applying the content filters. The caller reads the selection once and
    /// shares `raw` with the bridge, so a single local change costs one read.
    async fn broadcast_selection(&self, kind: SelectionKind, raw: Hashed) {
        if !self.may_send(kind) {
            if self.cfg.verbose {
                info!("copied {kind:?}: not sent (this node does not send)");
            }
            return;
        }
        // Describe what was copied before the filters narrow it, computed once.
        // The bracketed list means "what was copied" in every outcome below
        // (consistent with the received-update summary).
        let copied = self.cfg.verbose.then(|| describe_offer(raw.offer()));
        let Ok(content) = self.apply_stages(raw, Pipeline::Broadcast).await else {
            if let Some(copied) = &copied {
                info!("copied {kind:?} [{copied}]: not sent (nothing passed the content filters)");
            }
            return;
        };
        let hash = content.hash();
        // Already the mesh-current content (we just applied it, or the user
        // re-copied identical bytes): nothing to do.
        if self.current.lock().unwrap().get(&kind).map(|s| s.hash) == Some(hash) {
            if let Some(copied) = &copied {
                info!("copied {kind:?} [{copied}]: not sent (already on the mesh)");
            }
            debug!("ignoring local {kind:?} change: identical to what's already on the mesh (echo suppressed)");
            return;
        }
        let version = Version::new(self.tick(), self.mesh.own_id());
        let stamp = version.stamp;
        self.current
            .lock()
            .unwrap()
            .insert(kind, ContentState { hash, version });
        if let Some(copied) = &copied {
            info!("copied {kind:?} [{copied}]: broadcast (stamp {stamp})");
        }
        debug!(
            "broadcasting {kind:?} update ({}, stamp {stamp})",
            describe_offer(content.offer())
        );
        self.mesh.broadcast(&Message::Clip {
            kind,
            hash,
            offer: content.into_arc(),
            version,
        });
    }

    /// Drain one debounce batch: read each fired selection once, plan every
    /// broadcast and write up front, then execute — writing each selection at most
    /// once, with `ClipboardIo` recording each write so its watch echo is dropped
    /// next batch rather than re-driving propagation.
    async fn handle_batch(&self, batch: Vec<SelectionKind>) {
        // Phase 1: read & classify. `read` is this batch's view of the clipboard
        // and holds every selection read, echoes included — a Mirror reconcile
        // compares against the partner's ACTUAL content, which is worth having
        // even when that partner's own change was an echo of our last write.
        // `changed` names the subset that was a genuine user change, in batch
        // order; it is all the planner needs.
        let mut read: IndexMap<SelectionKind, Hashed> = IndexMap::new();
        let mut changed: Vec<SelectionKind> = Vec::new();
        for kind in batch {
            if !self.policies.get(kind).has_local_sink() {
                if self.cfg.verbose {
                    // Distinct from `broadcast_selection`'s "does not send":
                    // this selection has no local sink AT ALL — not the mesh,
                    // not the bridge, not the ownership rewrite — so the batch
                    // skips even reading it. Sharing one message for both made
                    // the reason it gives wrong half the time.
                    info!("copied {kind:?}: ignored (nothing on this node acts on it)");
                }
                continue;
            }
            // The one read that consumes the echo marker. Every other reader in
            // the engine uses `io.read`, which leaves it alone — see
            // `read_classified` for why that distinction is a method rather than
            // a rule.
            let Some((raw, origin)) = self.io.read_classified(kind).await else {
                continue;
            };
            if origin == Origin::User {
                changed.push(kind); // else: our own write echoing back — no propagation
            }
            read.insert(kind, raw);
        }
        if changed.is_empty() {
            return;
        }

        // Phase 2: plan (pure, payload-free).
        let plan = plan_batch(&changed, self.cfg.link_selections, self.cfg.take_ownership);

        // Phase 3: execute. Each action gets its own copy because `apply_stages`
        // consumes and rewrites the offer per pipeline; the plan's actions are
        // exactly the number of copies the batch needs.
        for action in plan.broadcasts {
            self.broadcast_selection(action.target, content_for(&read, action))
                .await;
        }
        for (action, prov) in plan.writes {
            self.execute_write(action.target, content_for(&read, action), prov, &read)
                .await;
        }
    }

    /// Execute one planned write: apply the `Own` transform (synthesis + size cap)
    /// or the `Mirror` reconcile, record `last_written` before writing so the echo
    /// is dropped, and undo the record on write failure.
    async fn execute_write(
        &self,
        kind: SelectionKind,
        content: Hashed,
        prov: Provenance,
        read: &IndexMap<SelectionKind, Hashed>,
    ) {
        let Ok(final_content) = self.apply_stages(content, prov.pipeline()).await else {
            if prov == Provenance::Own {
                debug!("not taking ownership of {kind:?}: nothing left after its stages");
            }
            return;
        };
        if prov == Provenance::Mirror {
            // Reconcile against the partner's ACTUAL content (handles out-of-band
            // drift; the partner may be unwatched). Reuse a read from this batch if
            // the partner fired, else read once. A failed read falls through to a
            // best-effort, self-terminating mirror.
            let fresh;
            let partner_now = match read.get(&kind) {
                Some(o) => Some(o),
                None => {
                    fresh = self.io.read(kind).await;
                    fresh.as_ref()
                }
            };
            if partner_now.map(Hashed::hash) == Some(final_content.hash()) {
                return;
            }
        }
        let copied = self
            .cfg
            .verbose
            .then(|| describe_offer(final_content.offer()));
        if self.io.write(kind, final_content).await {
            if let (Provenance::Mirror, Some(copied)) = (prov, copied) {
                info!("mirrored into {kind:?} [{copied}]");
            }
        }
    }

    /// Run `f` over the shared MIME rules on the blocking pool.
    ///
    /// THE single way the engine touches the rules, because every interesting
    /// thing it does to them — reload, append, persist, snapshot — ends in
    /// `std::fs`. The engine is one task inside `run`'s select loop, so blocking
    /// file I/O there stalls inbound mesh messages, peer connects and clipboard
    /// batches for as long as the filesystem takes, which on a network mount is
    /// unbounded. The lock is taken *inside* the closure, so it is never held
    /// across the await.
    async fn with_rules<T, F>(&self, f: F) -> T
    where
        F: FnOnce(&mut MimeRules) -> T + Send + 'static,
        T: Send + 'static,
    {
        let rules = Arc::clone(&self.mime_rules);
        tokio::task::spawn_blocking(move || f(&mut lock_rules(&rules)))
            .await
            // `lock_rules` recovers a poisoned mutex, so the only way here is a
            // panic inside `f` — which is a bug, not a runtime condition.
            .expect("MIME-rules task panicked")
    }

    /// Report a failed snapshot. The transaction itself lives in `MimeRules`;
    /// the engine only supplies the context (which peer, if any) that makes the
    /// warning actionable.
    fn warn_snapshot_failed(&self, e: mime::SnapshotError, context: &str) {
        match e {
            mime::SnapshotError::TooLarge { len } => warn!(
                "MIME-rules file{context} is {} (over the {} max_payload_size limit); skipping it",
                human_bytes(len),
                human_bytes(self.cfg.max_payload_size),
            ),
            mime::SnapshotError::WriteFailed => warn!(
                "couldn't write the MIME-rules file{context}; not announcing a version we didn't persist"
            ),
        }
    }

    /// Whether a rules body arriving from a peer is small enough to accept.
    ///
    /// Checked before parsing or persisting, so a peer can't make us do work —
    /// or write a file — larger than `max_payload_size`. The send side is
    /// bounded by the same limit inside `MimeRules::snapshot_at`, which measures
    /// the rendered body rather than this one.
    fn inbound_rules_body_ok(&self, len: usize, from: Uuid) -> bool {
        let limit = self.cfg.max_payload_size;
        if len > limit {
            warn!(
                "MIME-rules file from peer {from} is {} (over the {} max_payload_size limit); skipping it",
                human_bytes(len),
                human_bytes(limit),
            );
            return false;
        }
        true
    }

    /// Push our whole MIME-rules file to a peer that just connected, so the
    /// mesh converges. Independent of `direction`/`resync_on_connect` (those
    /// gate clipboard content); gated only by `share_mime_rules` and having a
    /// file. Materialises the version header on first send so the version is
    /// pinned to disk and survives restarts.
    async fn resync_rules_to(&self, peers: &[Uuid]) {
        if !self.shares_rules() {
            return;
        }
        let own_id = self.mesh.own_id();
        let max = self.cfg.max_payload_size;
        let snapshot = self
            .with_rules(move |rules| rules.snapshot_baseline(own_id, max))
            .await;
        match snapshot {
            Ok(s) => {
                debug!(
                    "pushing shared MIME-rules to {} reconnected peer(s) (stamp {})",
                    peers.len(),
                    s.version.stamp
                );
                // Encode once for the whole burst; each peer gets a refcount.
                let frame = encode_frame(&Message::Rules {
                    version: s.version,
                    body: s.body,
                });
                for &peer in peers {
                    self.mesh.send_frame_to(peer, &frame);
                }
            }
            Err(e) => self.warn_snapshot_failed(e, &format!(" for {} peer(s)", peers.len())),
        }
    }

    /// A peer just (re)connected: push our current state so it converges
    /// without waiting for the next copy. The receiver orders it by
    /// `(stamp, origin)` like any other update, so two nodes resyncing at
    /// each other settle on the same content instead of swapping.
    async fn on_peers_connected(&self, peers: &[Uuid]) {
        // Rules sharing is independent of clipboard direction/resync settings.
        self.resync_rules_to(peers).await;
        if !self.cfg.resync_on_connect {
            return;
        }
        // Resync only the selections this node actually sends. Asking the policy
        // rather than re-deriving it (a global `direction == ReceiveOnly` check
        // plus the send-or-recv `synced_kinds`) keeps this correct if a
        // per-selection direction override is ever added — the two happen to
        // agree today, which is exactly how such a restatement rots unnoticed.
        for kind in self.policies.kinds(|p| p.send) {
            let Some(state) = self.current.lock().unwrap().get(&kind).copied() else {
                continue;
            };
            let Some(content) = self.capture_offer(kind).await else {
                continue;
            };
            // Only resync if the live clipboard still matches our recorded
            // state; otherwise the watcher path will carry the newer content.
            if content.hash() != state.hash {
                continue;
            }
            debug!(
                "resyncing current {kind:?} to {} reconnected peer(s)",
                peers.len()
            );
            // One read and one encode for the whole burst, not per peer.
            let frame = encode_frame(&Message::Clip {
                kind,
                hash: state.hash,
                offer: content.into_arc(),
                version: state.version,
            });
            for &peer in peers {
                self.mesh.send_frame_to(peer, &frame);
            }
        }
    }

    /// Dispatch an inbound message from a peer to the right handler.
    async fn on_inbound(&self, from: Uuid, msg: Message) {
        match msg {
            Message::Clip {
                kind,
                hash,
                offer,
                version,
            } => self.on_inbound_clip(from, kind, hash, offer, version).await,
            Message::Rules { version, body } => self.on_inbound_rules(from, version, body).await,
            Message::Get { kind, want } => self.on_get(from, kind, want).await,
            Message::Hello { .. } => {
                warn!("ignoring an unexpected Hello from peer {from} after handshake")
            }
            // Only a --paste client asks, and it is not a node, so nothing here
            // should ever receive one.
            Message::GetReply { .. } => {
                warn!("ignoring an unexpected GetReply from peer {from}")
            }
        }
    }

    /// Answer a `--paste` client's request for one selection.
    ///
    /// Reads live rather than serving `current`, so the paster gets what is on
    /// the clipboard now, and applies `Pipeline::Serve` so a pull respects
    /// exactly the same content filters as a push — notably, password-manager
    /// content is dropped here too rather than being pullable.
    async fn on_get(&self, from: Uuid, kind: SelectionKind, want: GetWant) {
        let result = self.serve_get(kind, want).await;
        debug!("answering a paste request for {kind:?} from {from}");
        self.mesh
            .send_frame_to(from, &encode_frame(&Message::GetReply { kind, result }));
    }

    /// Serve one request, reading only what it actually asked for.
    ///
    /// The narrowing reaches the *backend*, not just the wire: on Wayland a
    /// content read costs one connection and one pipe read per representation,
    /// so `TypesOnly` reads no contents at all and `One` reads exactly one.
    /// Narrowing only the reply would leave `wl-paste -l` pulling a 30 MB image
    /// off the compositor to print a list of names.
    async fn serve_get(&self, kind: SelectionKind, want: GetWant) -> GetResult {
        if !self.policies.get(kind).send {
            return GetResult::Unavailable(Unavailable::NotSynced);
        }
        // Names are not content, so they bypass the content pipeline entirely.
        // The rules still govern what leaves this host, so the list is filtered
        // to the types this node would actually serve.
        if want == GetWant::TypesOnly {
            let Some(types) = self.io.list_types(kind).await else {
                return GetResult::Unavailable(Unavailable::Unreadable);
            };
            let had_types = !types.is_empty();
            let allowed = self.filter_names(types).await;
            return match (allowed.is_empty(), had_types) {
                (false, _) => GetResult::Types(allowed),
                // The distinction the reason exists for: nothing offered at all,
                // versus types offered and all of them denied by our rules.
                (true, true) => GetResult::Unavailable(Unavailable::Denied),
                (true, false) => GetResult::Unavailable(Unavailable::Empty),
            };
        }
        let only = match &want {
            GetWant::One(t) => Some(t.as_str()),
            _ => None,
        };
        let served = match self.read_for_serve(kind, only).await {
            Ok(raw) => self.apply_stages(raw, Pipeline::Serve).await,
            Err(reason) => Err(reason),
        };
        match (served, only) {
            (Ok(content), _) => GetResult::Offer(content.into_offer()),
            // A narrowed request that came back with nothing: the type wasn't
            // offered, or it was and the rules/cap dropped it. Either way the
            // useful answer names what this node *would* serve.
            (Err(_), Some(_)) => self.not_offered(kind).await,
            (Err(reason), None) => GetResult::Unavailable(reason),
        }
    }

    /// Read for a `Get`, narrowed to `only` when one type was asked for.
    ///
    /// A narrowed read that comes back empty means that type isn't offered,
    /// which is `Empty` *for this request* — the caller turns it into the
    /// "here's what I do have" answer.
    async fn read_for_serve(
        &self,
        kind: SelectionKind,
        only: Option<&str>,
    ) -> Result<Hashed, Unavailable> {
        let raw = match only {
            Some(mime) => self.io.read_one(kind, mime).await,
            None => self.io.read(kind).await,
        };
        // `None` here is a failed or timed-out read, already logged — distinct
        // from a successful read of an empty selection.
        let raw = raw.ok_or(Unavailable::Unreadable)?;
        if raw.is_empty() {
            return Err(Unavailable::Empty);
        }
        Ok(raw)
    }

    /// `GetResult::NotOffered` carrying the types this node would serve, so the
    /// paster can say what *was* available. Costs one names-only roundtrip.
    ///
    /// Degrades to a plain reason when there is nothing to list: "that type is
    /// not offered (available: none)" is a worse answer than naming why the
    /// node has nothing.
    async fn not_offered(&self, kind: SelectionKind) -> GetResult {
        let types = self.io.list_types(kind).await.unwrap_or_default();
        let had_types = !types.is_empty();
        let available = self.filter_names(types).await;
        match (available.is_empty(), had_types) {
            (false, _) => GetResult::NotOffered { available },
            (true, true) => GetResult::Unavailable(Unavailable::Denied),
            (true, false) => GetResult::Unavailable(Unavailable::Empty),
        }
    }

    /// Drop the type names this node's MIME rules would not send.
    ///
    /// Size 0 asks "allowed ignoring size": a per-type cap is a maximum, so a
    /// zero-byte representation clears every cap and only the allow/deny
    /// decision remains. That is the most a names-only answer can know — a
    /// listed type may still be dropped by its cap once actually read, which is
    /// the honest cost of not reading it to answer `--list-types`.
    async fn filter_names(&self, types: Vec<String>) -> Vec<String> {
        self.with_rules(move |rules| {
            let compiled = rules.compile();
            types
                .into_iter()
                .filter(|m| compiled.allows(m, 0))
                .collect()
        })
        .await
    }

    async fn on_inbound_clip(
        &self,
        from: Uuid,
        kind: SelectionKind,
        hash: [u8; 32],
        offer: Arc<Offer>,
        version: Version,
    ) {
        // Describe before the offer is filtered/moved, for the verbose summary.
        let received = self.cfg.verbose.then(|| describe_offer(&offer));
        let stamp = version.stamp;
        let outcome = self
            .apply_inbound_clip(from, kind, hash, offer, version)
            .await;
        if let Some(received) = received {
            info!("received {kind:?} from peer {from} [{received}], stamp {stamp}: {outcome}");
        }
    }

    /// Decide and apply one inbound clip, returning a short outcome for the
    /// verbose per-message summary. Keeps the detailed debug lines (the
    /// non-verbose view) and the hard-error warnings.
    async fn apply_inbound_clip(
        &self,
        from: Uuid,
        kind: SelectionKind,
        hash: [u8; 32],
        offer: Arc<Offer>,
        version: Version,
    ) -> &'static str {
        // from_arc, not new: the offer arrives inside its own Arc off the wire,
        // so unwrapping and rewrapping it would copy the payload for nothing.
        let content = Hashed::from_arc(offer);
        debug!(
            "received {kind:?} update from peer {from} ({}, stamp {})",
            describe_offer(content.offer()),
            version.stamp
        );
        if !self.may_recv(kind) {
            debug!("ignoring inbound {kind:?} from peer {from}: blocked by direction/sync_selection config");
            return "dropped (blocked by direction/sync_selection config)";
        }
        if content.hash() != hash {
            warn!("dropping update from peer {from}: content hash doesn't match (corrupted or tampered)");
            return "rejected (content hash mismatch)";
        }
        if !self.accept_stamp(version, from, "update") {
            return "rejected (timestamp too far in the future)";
        }
        // Apply the receiver's own content policy: configs can differ
        // between peers, and a node must not write contents it would never
        // have sent (e.g. password-manager secrets, or denied MIME types). Do
        // NOT record unseen types here — a peer must not write to our rules file.
        let Ok(content) = self.apply_stages(content, Pipeline::Inbound).await else {
            debug!("dropping inbound {kind:?} from peer {from}: our content filters removed everything");
            return "dropped (content filters removed everything)";
        };
        // Free when the filters changed nothing — the common case — because the
        // hash rode along with the content instead of being recomputed.
        let applied_hash = content.hash();
        {
            let mut current = self.current.lock().unwrap();
            if let Some(state) = current.get(&kind).copied() {
                if state.hash == applied_hash {
                    // Already hold exactly this content, so no clipboard write
                    // is needed — but still adopt a higher (stamp, origin).
                    // The LWW timestamp must track the newest write of the
                    // current content; keeping a stale stamp would let a later
                    // update stamped between ours and a peer's newer one win
                    // here yet lose on that peer, diverging the mesh.
                    if state.superseded_by(version) {
                        current.insert(
                            kind,
                            ContentState {
                                hash: applied_hash,
                                version,
                            },
                        );
                    }
                    debug!("inbound {kind:?} from peer {from} is already our current content; nothing to do");
                    return "already our current content";
                }
                if !state.superseded_by(version) {
                    debug!("ignoring an older {kind:?} update from peer {from} (stamp {}); we already hold newer content", version.stamp);
                    return "ignored (older than our content)";
                }
            }
        }
        debug!(
            "applying {kind:?} update from peer {from} ({}, stamp {})",
            describe_offer(content.offer()),
            version.stamp
        );
        // `write_selection` marks this as engine-written, so the resulting watch
        // echo is not treated by the bridge as a fresh local change: mesh-received
        // content must not be re-mirrored to the partner selection nor
        // re-broadcast to the mesh under our own origin. `link_selections` is a
        // purely *local* coupling; cross-host propagation is `sync_selection`'s job.
        if !self.io.write(kind, content).await {
            return "clipboard write failed";
        }
        // Record as current only on a successful write, so a transient
        // failure doesn't permanently block this content from re-applying.
        // The whole handler runs to completion on the single engine task
        // (it is awaited inline in run()'s select), so `current` cannot be
        // mutated across this await — the post-write insert is not a TOCTOU.
        self.current.lock().unwrap().insert(
            kind,
            ContentState {
                hash: applied_hash,
                version,
            },
        );
        "applied"
    }

    /// Signal the run loop that the rules file changed locally, so it bumps the
    /// shared version and broadcasts. Cheap and coalescing: a full queue just
    /// means a bump is already pending.
    fn note_rules_changed(&self) {
        let _ = self.rules_changed_tx.try_send(());
    }

    /// Whether this node participates in mesh-wide MIME-rules sharing: the
    /// feature is on AND there is a file to share. One definition for all three
    /// rules paths (resync-to-peer, local change, inbound adoption) — with the
    /// condition spelled out at each, adding a term would mean finding them all.
    fn shares_rules(&self) -> bool {
        self.cfg.share_mime_rules && self.cfg.mime_rules_path.is_some()
    }

    /// A local change to the rules file (a captured new type, or a human edit
    /// the watcher picked up) bumps the file version and broadcasts the whole
    /// file. No-op when sharing is off or there is no rules file.
    async fn on_local_rules_changed(&self) {
        if !self.shares_rules() {
            return;
        }
        let version = Version::new(self.tick(), self.mesh.own_id());
        let max = self.cfg.max_payload_size;
        let snapshot = self
            .with_rules(move |rules| rules.snapshot_at(version, max))
            .await;
        match snapshot {
            Ok(s) => {
                debug!("broadcasting shared MIME-rules (stamp {})", s.version.stamp);
                self.mesh.broadcast(&Message::Rules {
                    version: s.version,
                    body: s.body,
                });
            }
            Err(e) => self.warn_snapshot_failed(e, ""),
        }
    }

    /// Adopt a peer's shared MIME-rules file under whole-file last-writer-wins.
    /// Ignored unless sharing is on and we have a rules file. Rejects
    /// implausibly-future stamps and `observe()`s the stamp so a later local
    /// edit outranks the adopted version (otherwise a local edit stamped below
    /// it would revert to the version it just replaced).
    async fn on_inbound_rules(&self, from: Uuid, incoming: Version, body: String) {
        if !self.shares_rules() {
            return;
        }
        // Reject an oversized body before parsing/persisting it: a peer must not
        // be able to make us write a huge file (the send-side cap only bounds
        // what WE send).
        if !self.inbound_rules_body_ok(body.len(), from) {
            return;
        }
        if !self.accept_stamp(incoming, from, "MIME-rules") {
            return;
        }
        let own_id = self.mesh.own_id();
        let max = self.cfg.max_payload_size;
        // Compare-and-adopt under one lock: reading our version and replacing the
        // file must not interleave with another adoption.
        let failed = self
            .with_rules(move |rules| {
                let current = rules.version(own_id);
                if incoming <= current {
                    debug!(
                        "ignoring shared MIME-rules from peer {from} (stamp {}); we hold a newer-or-equal version (stamp {})",
                        incoming.stamp, current.stamp
                    );
                    return None;
                }
                debug!(
                    "adopting shared MIME-rules from peer {from} (stamp {}); replaces our (stamp {}, origin {})",
                    incoming.stamp, current.stamp, current.origin
                );
                rules.replace_from(body);
                // Stamp the adopted version explicitly so version() reflects it even
                // if the peer's body lacked the header line — otherwise version()
                // would fall back to the new file's mtime and diverge. On failure
                // the snapshot rolls back, so memory matches disk rather than
                // silently diverging (which a restart would lose); the peer
                // re-pushes on its next connect.
                rules.snapshot_at(incoming, max).err()
            })
            .await;
        if let Some(e) = failed {
            self.warn_snapshot_failed(e, &format!(" from peer {from}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clipboard::mock::MockClipboard;
    use crate::config::{Config, Direction, LinkSelections, MimePolicy};
    use crate::mesh::Mesh;
    use crate::protocol::PeerRole;
    use std::path::PathBuf;
    use std::time::Duration;
    use tokio::time::timeout;

    use crate::protocol::content_hash;
    use crate::protocol::test_support::{text_offer as offer, wait_for};

    /// Run the pure capture transforms over a bare `Offer`. The engine works in
    /// `Hashed`; these tests are about the content, so they wrap and unwrap.
    fn synth(offer: Offer) -> Offer {
        synthesize_text_plain(Hashed::new(offer)).into_offer()
    }

    fn cap(offer: Offer, max: usize) -> Offer {
        cap_to_payload_size(Hashed::new(offer), max).into_offer()
    }

    #[test]
    fn a_transform_that_changes_nothing_carries_the_hash_forward() {
        // Load-bearing: the inbound path reuses the hash it already verified
        // against the wire, which is only sound because a no-op pipeline really
        // does hand back the same `Hashed`.
        let already_plain = Hashed::new(offer("hi"));
        let before = already_plain.hash();
        assert_eq!(
            synthesize_text_plain(already_plain).hash(),
            before,
            "synthesis with a text/plain already present must not alter the hash"
        );

        let fits = Hashed::new(offer("hi"));
        let before = fits.hash();
        assert_eq!(
            cap_to_payload_size(fits, 1 << 20).hash(),
            before,
            "an offer under budget must not alter the hash"
        );
    }

    #[test]
    fn a_transform_that_changes_content_rehashes() {
        // The other half: whenever the content is rebuilt the hash must track it,
        // or a stale hash would defeat echo suppression and mesh dedup.
        let capped = cap_to_payload_size(Hashed::new(offer("hello")), 1);
        assert!(capped.is_empty(), "nothing fits a 1-byte budget");
        assert_eq!(
            capped.hash(),
            content_hash(capped.offer()),
            "hash must match the content it carries"
        );

        let synthesized = synthesize_text_plain(Hashed::new(crate::protocol::test_support::offer(
            &[("UTF8_STRING", b"hi")],
        )));
        assert!(
            synthesized.offer().contains_key("text/plain"),
            "text/plain should have been back-filled"
        );
        assert_eq!(
            synthesized.hash(),
            content_hash(synthesized.offer()),
            "hash must match the content it carries"
        );
    }

    fn pairs(offer: &Offer) -> Vec<(&str, &[u8])> {
        offer
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_slice()))
            .collect()
    }

    #[test]
    fn synthesize_inserts_text_plain_reps_before_utf8_string() {
        let offer: Offer = [("UTF8_STRING".to_string(), b"hi".to_vec())]
            .into_iter()
            .collect();
        let out = synth(offer);
        assert_eq!(
            pairs(&out),
            [
                ("text/plain;charset=utf-8", &b"hi"[..]),
                ("text/plain", &b"hi"[..]),
                ("UTF8_STRING", &b"hi"[..]),
            ]
        );
    }

    #[test]
    fn synthesize_is_a_noop_when_any_text_plain_variant_exists() {
        // Exact text/plain present.
        let a: Offer = [
            ("text/plain".to_string(), b"x".to_vec()),
            ("UTF8_STRING".to_string(), b"y".to_vec()),
        ]
        .into_iter()
        .collect();
        assert_eq!(pairs(&synth(a.clone())), pairs(&a));
        // A parameterized text/plain;charset=... also counts.
        let b: Offer = [
            ("text/plain;charset=utf-8".to_string(), b"x".to_vec()),
            ("UTF8_STRING".to_string(), b"y".to_vec()),
        ]
        .into_iter()
        .collect();
        assert_eq!(pairs(&synth(b.clone())), pairs(&b));
    }

    #[test]
    fn synthesize_is_a_noop_without_a_source_atom() {
        let offer: Offer = [("image/png".to_string(), b"\x89PNG".to_vec())]
            .into_iter()
            .collect();
        assert_eq!(pairs(&synth(offer.clone())), pairs(&offer));
    }

    #[test]
    fn synthesize_reencodes_latin1_string_to_utf8() {
        // STRING is ISO-8859-1: 0xE9 is 'é', which is 0xC3 0xA9 in UTF-8.
        let offer: Offer = [("STRING".to_string(), vec![0xE9])].into_iter().collect();
        let out = synth(offer);
        assert_eq!(
            out.get("text/plain").map(Vec::as_slice),
            Some(&[0xC3u8, 0xA9][..]),
            "latin-1 STRING must be re-encoded to UTF-8"
        );
        assert_eq!(
            out.get("text/plain;charset=utf-8").map(Vec::as_slice),
            Some(&[0xC3u8, 0xA9][..])
        );
    }

    #[test]
    fn synthesize_prefers_utf8_string_over_string_and_text() {
        // All three atoms present: UTF8_STRING wins, and the reps go before it.
        let offer: Offer = [
            ("TEXT".to_string(), vec![0xE9]),
            ("STRING".to_string(), vec![0xE9]),
            ("UTF8_STRING".to_string(), "é".as_bytes().to_vec()),
        ]
        .into_iter()
        .collect();
        let out = synth(offer);
        assert_eq!(
            pairs(&out),
            [
                ("TEXT", &[0xE9u8][..]),
                ("STRING", &[0xE9u8][..]),
                ("text/plain;charset=utf-8", "é".as_bytes()),
                ("text/plain", "é".as_bytes()),
                ("UTF8_STRING", "é".as_bytes()),
            ]
        );
    }

    #[test]
    fn synthesize_strips_trailing_nul_and_newline_from_the_value() {
        // X11 atoms are often NUL-terminated and/or carry a trailing newline
        // (SELECTION line selections). The synthesized text/plain value is cleaned,
        // but the source atom keeps its verbatim bytes.
        let offer: Offer = [("UTF8_STRING".to_string(), b"hi\n\0".to_vec())]
            .into_iter()
            .collect();
        let out = synth(offer);
        assert_eq!(out.get("text/plain").map(Vec::as_slice), Some(&b"hi"[..]));
        assert_eq!(
            out.get("text/plain;charset=utf-8").map(Vec::as_slice),
            Some(&b"hi"[..])
        );
        assert_eq!(
            out.get("UTF8_STRING").map(Vec::as_slice),
            Some(&b"hi\n\0"[..]),
            "the source atom must keep its exact bytes"
        );
    }

    #[test]
    fn synthesize_strips_a_single_crlf_terminator() {
        let offer: Offer = [("UTF8_STRING".to_string(), b"a\n\r\n".to_vec())]
            .into_iter()
            .collect();
        // Only one trailing terminator is removed: "a\n\r\n" -> "a\n".
        assert_eq!(
            synth(offer).get("text/plain").map(Vec::as_slice),
            Some(&b"a\n"[..])
        );
    }

    #[test]
    fn synthesize_text_atom_sniffs_utf8_else_latin1() {
        // Valid UTF-8 TEXT is used verbatim.
        let utf8: Offer = [("TEXT".to_string(), "é".as_bytes().to_vec())]
            .into_iter()
            .collect();
        assert_eq!(
            synth(utf8).get("text/plain").map(Vec::as_slice),
            Some("é".as_bytes())
        );
        // Non-UTF-8 TEXT falls back to latin-1.
        let latin: Offer = [("TEXT".to_string(), vec![0xE9])].into_iter().collect();
        assert_eq!(
            synth(latin).get("text/plain").map(Vec::as_slice),
            Some(&[0xC3u8, 0xA9][..])
        );
    }

    #[test]
    fn cap_to_payload_size_keeps_original_order_of_survivors() {
        // Reps given in a non-size order; the budget forces dropping the biggest.
        // The survivors must come out in their ORIGINAL (advertise) order, not
        // reordered smallest-first by the drop-selection pass.
        let offer: Offer = [
            ("text/html".to_string(), vec![0u8; 30]),  // 9 + 30 = 39
            ("image/png".to_string(), vec![0u8; 100]), // 9 + 100 = 109 -> dropped
            ("text/plain".to_string(), vec![0u8; 5]),  // 10 + 5 = 15
        ]
        .into_iter()
        .collect();
        // Budget fits html + plain (54) but not png; png is the only drop.
        let capped = cap(offer, 60);
        assert_eq!(
            capped.keys().map(String::as_str).collect::<Vec<_>>(),
            ["text/html", "text/plain"]
        );
    }

    #[test]
    fn cap_to_payload_size_breaks_size_ties_in_advertise_order() {
        // All three reps are the same size, so the survivor selection is decided
        // purely by the stable sort: the budget fits two, and they must be the
        // first two advertised (a/x, b/x), kept in that order — c/x drops. This
        // pins the stable-sort dependency; an unstable sort could drop b instead.
        let offer: Offer = [
            ("a/x".to_string(), vec![0u8; 17]), // 3 + 17 = 20 each
            ("b/x".to_string(), vec![0u8; 17]),
            ("c/x".to_string(), vec![0u8; 17]),
        ]
        .into_iter()
        .collect();
        let capped = cap(offer, 45); // fits two (40), not three (60)
        assert_eq!(
            capped.keys().map(String::as_str).collect::<Vec<_>>(),
            ["a/x", "b/x"]
        );
    }

    /// A `[rules]` TOML body from (mime, rule-word) pairs.
    fn rules_toml(rules: &[(&str, &str)]) -> String {
        let mut body = String::from("[rules]\n");
        for (mime, rule) in rules {
            body.push_str(&format!("\"{mime}\" = \"{rule}\"\n"));
        }
        body
    }

    /// Point `cfg` at a MIME-rules path in a fresh temp dir, WITHOUT creating
    /// the file — `MimeRules::load` then materialises the shipped skeleton the
    /// way it does on a first run.
    ///
    /// Distinct from writing an empty body, which yields a file with zero rules
    /// and no skeleton; tests depend on the difference, so it gets its own name
    /// rather than being an accident of which helper was reached for.
    ///
    /// The returned TempDir must outlive the test (dropping it deletes the
    /// directory); the path is returned so call sites don't restate the
    /// filename this helper chose.
    fn with_rules_absent(cfg: &mut Config, unknown: MimePolicy) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        cfg.unknown_mime = unknown;
        cfg.mime_rules_path = Some(path.clone());
        (dir, path)
    }

    /// [`with_rules_absent`], with the file created holding `body` — for the
    /// tests that need a `[clipmesh]` header, a `max =` cap, or any other shape
    /// the (mime, rule) pair list can't express.
    fn with_rules_body(
        cfg: &mut Config,
        unknown: MimePolicy,
        body: &str,
    ) -> (tempfile::TempDir, PathBuf) {
        let (dir, path) = with_rules_absent(cfg, unknown);
        std::fs::write(&path, body).unwrap();
        (dir, path)
    }

    /// [`with_rules_body`] for the common case: simple (mime, rule-word) entries.
    fn with_rules(
        cfg: &mut Config,
        unknown: MimePolicy,
        rules: &[(&str, &str)],
    ) -> (tempfile::TempDir, PathBuf) {
        with_rules_body(cfg, unknown, &rules_toml(rules))
    }

    /// A wired-up engine plus the channel ends a test needs to drive and observe
    /// it: `engine.run(in_rx, connect_rx, rules_rx)` consumes the three
    /// receivers, `in_tx` injects peer messages, and `mesh` registers peers.
    struct Wiring<C> {
        engine: Arc<SyncEngine<C>>,
        mesh: Arc<Mesh>,
        in_tx: mpsc::Sender<(Uuid, Message)>,
        in_rx: mpsc::Receiver<(Uuid, Message)>,
        connect_rx: mpsc::Receiver<Uuid>,
        rules_rx: mpsc::Receiver<()>,
    }

    /// Build an engine over `clip` with a fresh node ID and the MIME rules `cfg`
    /// points at — the wiring every engine test needs, in one place.
    fn engine<C: Clipboard>(clip: Arc<C>, cfg: Config) -> Wiring<C> {
        let (in_tx, in_rx) = mpsc::channel(64);
        let (connect_tx, connect_rx) = mpsc::channel(64);
        let mesh = Mesh::new(Uuid::new_v4(), in_tx.clone(), connect_tx);
        let mime_rules = Arc::new(Mutex::new(MimeRules::load(
            cfg.mime_rules_path.clone(),
            cfg.unknown_mime,
        )));
        let (rules_tx, rules_rx) = mpsc::channel(8);
        let engine = SyncEngine::new(clip, mesh.clone(), Arc::new(cfg), mime_rules, rules_tx);
        Wiring {
            engine,
            mesh,
            in_tx,
            in_rx,
            connect_rx,
            rules_rx,
        }
    }

    #[tokio::test]
    async fn inbound_is_handled_while_a_startup_read_is_still_blocked() {
        // Priming reads the existing clipboard, which can block on a slow source.
        // That must not stall the engine's handling of peer messages/connects —
        // otherwise a node can't participate in the mesh until the local
        // selection changes and unblocks the read.
        let clip = MockClipboard::new();
        clip.block_reads();
        let remote_id = Uuid::new_v4();
        let w = engine(clip.clone(), Config::for_test("s"));
        let in_tx = w.in_tx.clone();
        tokio::spawn(w.engine.run(w.in_rx, w.connect_rx, w.rules_rx));

        // The startup read is gated and still pending. A peer update should still
        // be applied to the local clipboard.
        let o = offer("from-peer");
        in_tx
            .send((
                remote_id,
                Message::Clip {
                    kind: SelectionKind::Clipboard,
                    hash: content_hash(&o),
                    offer: o.clone().into(),
                    version: Version::new(now_ms() + 10_000, remote_id),
                },
            ))
            .await
            .unwrap();

        let handled = timeout(Duration::from_secs(2), async {
            while clip.get(SelectionKind::Clipboard).is_none() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        clip.allow_reads(); // let the startup read finish so the task winds down
        handled.expect("inbound update was not handled while the startup read was blocked");
        assert_eq!(clip.get(SelectionKind::Clipboard).as_ref(), Some(&o));
    }

    // The read timeout itself is tested where it now lives, in
    // `clipboard::io` (`a_read_that_never_answers_times_out_instead_of_stalling`);
    // this module used to carry a second copy of that test.

    struct Harness {
        clip: Arc<MockClipboard>,
        mesh: Arc<Mesh>,
        conn_rx: mpsc::Receiver<crate::protocol::Frame>,
        in_tx: mpsc::Sender<(Uuid, Message)>,
        remote_id: Uuid,
    }

    async fn start(cfg: Config) -> Harness {
        start_seeded_with(cfg, &[]).await
    }

    /// Start the engine with clipboard content already present before it adopts
    /// (models a daemon restart over an existing clipboard).
    async fn start_seeded(cfg: Config, seed: Offer) -> Harness {
        start_seeded_with(cfg, &[(SelectionKind::Clipboard, seed)]).await
    }

    /// Like `start_seeded` but seeds arbitrary selections first, so a
    /// restart over existing SELECTION content can be modelled too.
    async fn start_seeded_with(cfg: Config, seeds: &[(SelectionKind, Offer)]) -> Harness {
        let clip = MockClipboard::new();
        for (kind, o) in seeds {
            clip.seed(*kind, o.clone());
        }
        let mut w = engine(clip.clone(), cfg);
        let (conn_tx, conn_rx) = mpsc::channel(64);
        let remote_id = Uuid::new_v4();
        w.mesh.register(remote_id, conn_tx, PeerRole::Peer);
        // drain the connect event from the initial registration so tests
        // that don't care about resync aren't affected
        let _ = w.connect_rx.try_recv();
        let mesh = w.mesh.clone();
        let in_tx = w.in_tx.clone();
        let engine = w.engine.clone();
        let synced = engine.synced_kinds();
        tokio::spawn(w.engine.run(w.in_rx, w.connect_rx, w.rules_rx));
        // wait until the engine has subscribed to the watcher
        while clip.watcher_count() == 0 {
            tokio::task::yield_now().await;
        }
        // ...and, when the clipboard was seeded, until it has been adopted.
        // The engine deliberately does NOT gate connect/inbound handling on
        // the startup adopt (a slow selection owner must not make the node unreachable),
        // so without this a test racing a peer connect against it would pass
        // or fail on scheduling luck rather than on behaviour.
        for (kind, _) in seeds.iter().filter(|(k, _)| synced.contains(k)) {
            let engine = engine.clone();
            let kind = *kind;
            wait_for("the seeded clipboard to be adopted", move || {
                engine.current.lock().unwrap().contains_key(&kind)
            })
            .await;
        }
        Harness {
            clip,
            mesh,
            conn_rx,
            in_tx,
            remote_id,
        }
    }

    async fn recv_msg(h: &mut Harness) -> Message {
        recv_from(&mut h.conn_rx).await
    }

    /// Await the next frame on a connection channel and decode it. Connections
    /// carry encoded `mesh::Frame`s, so tests decode to assert on `Message`.
    async fn recv_from(rx: &mut mpsc::Receiver<crate::protocol::Frame>) -> Message {
        let frame = timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("timed out waiting for a frame")
            .expect("connection channel closed");
        crate::protocol::decode(&frame).expect("frame did not decode")
    }

    #[tokio::test]
    async fn serve_get_distinguishes_empty_from_denied_and_sensitive() {
        // The whole reason `Unavailable` is a value rather than a debug line on
        // the serving host. All three used to arrive at the paster as "the
        // clipboard is empty", and two of them are things the user can act on.
        let kind = SelectionKind::Clipboard;

        // Nothing on the clipboard at all.
        let clip = MockClipboard::new();
        let w = engine(clip, Config::for_test("s"));
        assert_eq!(
            w.engine.serve_get(kind, GetWant::All).await,
            GetResult::Unavailable(Unavailable::Empty)
        );

        // Full clipboard, every type denied by this node's rules.
        let clip = MockClipboard::new();
        clip.seed(kind, offer("denied"));
        let mut cfg = Config::for_test("s");
        let (_dir, _) = with_rules(&mut cfg, MimePolicy::Deny, &[("text/plain", "deny")]);
        let w = engine(clip, cfg);
        assert_eq!(
            w.engine.serve_get(kind, GetWant::All).await,
            GetResult::Unavailable(Unavailable::Denied),
            "a denied clipboard must not read as an empty one"
        );

        // Full clipboard, flagged as a password-manager secret.
        let clip = MockClipboard::new();
        clip.seed(
            kind,
            crate::protocol::test_support::offer(&[
                ("text/plain", b"hunter2"),
                (SENSITIVE_MIME, b"secret"),
            ]),
        );
        let w = engine(clip, Config::for_test("s"));
        assert_eq!(
            w.engine.serve_get(kind, GetWant::All).await,
            GetResult::Unavailable(Unavailable::Sensitive),
            "a pull must refuse secrets, and say that is why"
        );
    }

    #[tokio::test]
    async fn apply_inbound_clip_reports_each_outcome() {
        // A standalone engine (not driven by run()), so we can call the inbound
        // handler directly and assert the one-line verbose summary's outcome.
        let standalone = |cfg| engine(MockClipboard::new(), cfg).engine;
        let kind = SelectionKind::Clipboard;
        let from = Uuid::new_v4();

        // Default (allow) engine, verbose on so the logging wrapper runs too.
        let mut cfg = Config::for_test("s");
        cfg.verbose = true;
        let e = standalone(cfg);

        let a = offer("hello");
        let ha = content_hash(&a);
        assert_eq!(
            e.apply_inbound_clip(from, kind, ha, a.clone().into(), Version::new(1000, from))
                .await,
            "applied"
        );
        assert_eq!(
            e.apply_inbound_clip(from, kind, ha, a.into(), Version::new(1000, from))
                .await,
            "already our current content"
        );
        let b = offer("older");
        assert_eq!(
            e.apply_inbound_clip(
                from,
                kind,
                content_hash(&b),
                b.into(),
                Version::new(1, from)
            )
            .await,
            "ignored (older than our content)"
        );
        assert_eq!(
            e.apply_inbound_clip(
                from,
                kind,
                [0u8; 32],
                offer("x").into(),
                Version::new(2000, from)
            )
            .await,
            "rejected (content hash mismatch)"
        );
        let f = offer("future");
        let future = now_ms() + MAX_FUTURE_SKEW_MS + 60_000;
        assert_eq!(
            e.apply_inbound_clip(
                from,
                kind,
                content_hash(&f),
                f.into(),
                Version::new(future, from)
            )
            .await,
            "rejected (timestamp too far in the future)"
        );
        // Exercise the verbose logging wrapper end-to-end (must not panic).
        let g = offer("newer");
        e.on_inbound_clip(
            from,
            kind,
            content_hash(&g),
            g.into(),
            Version::new(5000, from),
        )
        .await;

        // Send-only engine: inbound is dropped by the direction policy.
        let mut cfg = Config::for_test("s");
        cfg.direction = Direction::SendOnly;
        let e = standalone(cfg);
        let c = offer("blocked");
        assert_eq!(
            e.apply_inbound_clip(
                from,
                kind,
                content_hash(&c),
                c.into(),
                Version::new(1000, from)
            )
            .await,
            "dropped (blocked by direction/sync_selection config)"
        );

        // Deny-everything rules: the content filters remove all of it.
        let mut cfg = Config::for_test("s");
        let (_dir, _) = with_rules(&mut cfg, MimePolicy::Deny, &[]);
        let e = standalone(cfg);
        let d = offer("denied");
        assert_eq!(
            e.apply_inbound_clip(
                from,
                kind,
                content_hash(&d),
                d.into(),
                Version::new(1000, from)
            )
            .await,
            "dropped (content filters removed everything)"
        );
    }

    /// The next clipboard broadcast/resync message. Skips rules pushes (present
    /// when share_mime_rules is on) so the helpers below stay usable in
    /// sharing-enabled tests.
    async fn recv_next_clip(h: &mut Harness) -> (SelectionKind, [u8; 32], Offer, u64) {
        loop {
            match recv_msg(h).await {
                Message::Clip {
                    kind,
                    hash,
                    offer,
                    version,
                } => return (kind, hash, (*offer).clone(), version.stamp),
                Message::Rules { .. } => continue,
                other => panic!("expected Clip, got {other:?}"),
            }
        }
    }

    async fn recv_stamp(h: &mut Harness) -> u64 {
        recv_next_clip(h).await.3
    }

    async fn recv_clip(h: &mut Harness) -> (SelectionKind, [u8; 32], Offer) {
        let (kind, hash, offer, _) = recv_next_clip(h).await;
        (kind, hash, offer)
    }

    async fn assert_no_broadcast(h: &mut Harness) {
        assert!(
            timeout(Duration::from_millis(200), h.conn_rx.recv())
                .await
                .is_err(),
            "unexpected broadcast"
        );
    }

    async fn send_inbound(h: &Harness, kind: SelectionKind, o: Offer) {
        send_inbound_full(h, kind, o, now_ms()).await;
    }

    /// A stamp guaranteed to beat a locally issued one (which uses now_ms()).
    fn future_stamp(offset: u64) -> u64 {
        now_ms() + offset
    }

    async fn send_inbound_full(h: &Harness, kind: SelectionKind, o: Offer, stamp: u64) {
        let msg = Message::Clip {
            kind,
            hash: content_hash(&o),
            offer: o.into(),
            version: Version::new(stamp, h.remote_id),
        };
        h.in_tx.send((h.remote_id, msg)).await.unwrap();
    }

    /// Deliver an inbound `Rules` push from the peer, with the given version and
    /// body. `origin` is explicit because the tiebreak tests need to control it.
    async fn send_rules(h: &Harness, stamp: u64, origin: Uuid, body: String) {
        h.in_tx
            .send((
                h.remote_id,
                Message::Rules {
                    version: Version::new(stamp, origin),
                    body,
                },
            ))
            .await
            .unwrap();
    }

    /// Poll the rules file at `path` until it contains `needle`, panicking with
    /// `label` on timeout.
    async fn wait_rules_contain(path: &std::path::Path, needle: &str, label: &str) {
        wait_for(label, || {
            std::fs::read_to_string(path).unwrap().contains(needle)
        })
        .await;
    }

    async fn wait_applied(h: &Harness, kind: SelectionKind, o: &Offer) {
        wait_for("offer to be applied", || {
            h.clip.get(kind).as_ref() == Some(o)
        })
        .await;
    }

    #[tokio::test]
    async fn a_copy_racing_startup_is_not_mistaken_for_restored_content() {
        // The race this design exists to close, forced rather than hoped for:
        // the clipboard already had content, reads are slow, and a user copy
        // lands while the engine is still dealing with startup.
        //
        // Reading startup content back later loses here — by the time the read
        // returns it sees "fresh", attributes it to startup, and the copy is
        // suppressed as an echo and recorded at stamp 0 where a peer's older
        // clipboard outranks it. Taking the content from the backend's `Initial`
        // event instead makes the two unambiguous no matter how slow reads are.
        // Seeded content + gated reads models a slow selection owner: the read
        // would complete long after the watcher went live, so anything that
        // relies on reading startup content back loses the race here.
        let clip = MockClipboard::new();
        clip.seed(SelectionKind::Clipboard, offer("restored"));
        clip.block_reads();
        let mut w = engine(clip.clone(), Config::for_test("s"));
        let (conn_tx, mut conn_rx) = mpsc::channel(64);
        w.mesh.register(Uuid::new_v4(), conn_tx, PeerRole::Peer);
        let _ = w.connect_rx.try_recv();
        tokio::spawn(w.engine.run(w.in_rx, w.connect_rx, w.rules_rx));

        while clip.watcher_count() == 0 {
            tokio::task::yield_now().await;
        }
        // The copy lands while any startup read would still be blocked.
        clip.local_copy(SelectionKind::Clipboard, offer("fresh"));
        clip.allow_reads();

        match recv_from(&mut conn_rx).await {
            Message::Clip {
                offer: o, version, ..
            } => {
                assert_eq!(*o, offer("fresh"), "the racing copy must reach the mesh");
                assert!(
                    version.stamp > 0,
                    "a user copy must carry a real stamp; stamp 0 would let a \
                     peer's older clipboard outrank it"
                );
            }
            other => panic!("expected the copy to be broadcast, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_copy_made_right_after_startup_is_still_broadcast() {
        // Reading startup content back later attributes whatever it reads to "the
        // clipboard at startup", so
        // anything that delays its read past a real copy makes that copy look
        // restored: dropped as an echo, and recorded at stamp 0 where a peer's
        // older content outranks it. `start` returns as soon as the watcher is
        // live, so this copies into exactly that window.
        //
        // Real time, not paused: the failure mode is a scheduling order, and
        // auto-advance would hide it. This is the test that goes red if anything
        // yieldable is added between `watch()` and the adopt path in `run`.
        let mut h = start(Config::for_test("s")).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("raced"));
        let (kind, _, o) = recv_clip(&mut h).await;
        assert_eq!(kind, SelectionKind::Clipboard);
        assert_eq!(
            o,
            offer("raced"),
            "a copy landing during startup must propagate, not be mistaken for restored content"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn local_copy_is_broadcast() {
        let mut h = start(Config::for_test("s")).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("hello"));
        let (kind, hash, o) = recv_clip(&mut h).await;
        assert_eq!(kind, SelectionKind::Clipboard);
        assert_eq!(o, offer("hello"));
        assert_eq!(hash, content_hash(&o));
    }

    #[tokio::test(start_paused = true)]
    async fn mime_order_is_preserved_through_capture_and_apply() {
        // A multi-rep offer in deliberate (non-alphabetical) preference order:
        // the whole pipeline must carry it unchanged in both directions.
        let order = ["text/html", "text/plain", "image/png"];
        let ordered: Offer = [
            ("text/html".to_string(), b"<b>hi</b>".to_vec()),
            ("text/plain".to_string(), b"hi".to_vec()),
            ("image/png".to_string(), b"\x89PNG".to_vec()),
        ]
        .into_iter()
        .collect();

        let mut h = start(Config::for_test("s")).await;

        // Capture → broadcast: the outgoing Clip keeps the advertise order.
        h.clip.local_copy(SelectionKind::Clipboard, ordered);
        let (_, _, broadcast) = recv_clip(&mut h).await;
        assert_eq!(
            broadcast.keys().map(String::as_str).collect::<Vec<_>>(),
            order,
            "capture/broadcast scrambled the MIME order"
        );

        // Inbound → apply → write: the clipboard is written in arrival order.
        let inbound: Offer = [
            ("text/html".to_string(), b"<i>x</i>".to_vec()),
            ("text/plain".to_string(), b"x".to_vec()),
            ("image/png".to_string(), b"\x89PN2".to_vec()),
        ]
        .into_iter()
        .collect();
        send_inbound_full(
            &h,
            SelectionKind::Clipboard,
            inbound.clone(),
            future_stamp(10_000),
        )
        .await;
        wait_applied(&h, SelectionKind::Clipboard, &inbound).await;
        assert_eq!(
            h.clip
                .get(SelectionKind::Clipboard)
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            order,
            "apply/write scrambled the MIME order"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn mime_order_survives_a_denied_type_in_the_middle() {
        // The rule filter must remove the denied type without disturbing the
        // advertise order of the survivors — apply_mime_rules collects into the
        // ordered Offer, so the gap left by the dropped middle type closes up.
        let mut cfg = Config::for_test("s");
        let (_dir, _) = with_rules(
            &mut cfg,
            MimePolicy::Allow,
            &[("application/x-blocked", "deny")],
        );
        let mut h = start(cfg).await;

        let raw: Offer = [
            ("text/html".to_string(), b"<b>hi</b>".to_vec()),
            ("application/x-blocked".to_string(), b"nope".to_vec()),
            ("text/plain".to_string(), b"hi".to_vec()),
            ("image/png".to_string(), b"\x89PNG".to_vec()),
        ]
        .into_iter()
        .collect();
        h.clip.local_copy(SelectionKind::Clipboard, raw);
        let (_, _, broadcast) = recv_clip(&mut h).await;
        assert_eq!(
            broadcast.keys().map(String::as_str).collect::<Vec<_>>(),
            ["text/html", "text/plain", "image/png"],
            "denied type dropped, but survivors must keep advertise order"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn synthesize_text_plain_backfills_on_capture_when_enabled() {
        let mut cfg = Config::for_test("s");
        cfg.synthesize_text_plain = true;
        let mut h = start(cfg).await;
        let raw: Offer = [("UTF8_STRING".to_string(), b"hi".to_vec())]
            .into_iter()
            .collect();
        h.clip.local_copy(SelectionKind::Clipboard, raw);
        let (_, _, broadcast) = recv_clip(&mut h).await;
        assert_eq!(
            broadcast.keys().map(String::as_str).collect::<Vec<_>>(),
            ["text/plain;charset=utf-8", "text/plain", "UTF8_STRING"],
            "the shim should back-fill text/plain before the atom and broadcast it"
        );
        assert_eq!(
            broadcast.get("text/plain").map(Vec::as_slice),
            Some(&b"hi"[..])
        );
    }

    #[tokio::test(start_paused = true)]
    async fn synthesize_text_plain_is_off_by_default() {
        let mut h = start(Config::for_test("s")).await; // flag defaults off
        let raw: Offer = [("UTF8_STRING".to_string(), b"hi".to_vec())]
            .into_iter()
            .collect();
        h.clip.local_copy(SelectionKind::Clipboard, raw);
        let (_, _, broadcast) = recv_clip(&mut h).await;
        assert_eq!(
            broadcast.keys().map(String::as_str).collect::<Vec<_>>(),
            ["UTF8_STRING"],
            "with the flag off the offer must be broadcast unchanged"
        );
    }

    async fn wait_for_write_count(h: &Harness, n: usize) {
        wait_for(&format!("write_count to reach {n}"), || {
            h.clip.write_count() >= n
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn take_ownership_rewrites_the_local_selection_once() {
        let mut cfg = Config::for_test("s");
        cfg.take_ownership = true;
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("hi"));
        // The copy is still broadcast exactly once.
        let (_, _, o) = recv_clip(&mut h).await;
        assert_eq!(o, offer("hi"));
        // clipmesh re-owns the selection (one write) with the same content, and
        // its own write does not loop into more writes or broadcasts.
        wait_for_write_count(&h, 1).await;
        assert_eq!(h.clip.get(SelectionKind::Clipboard), Some(offer("hi")));
        assert_no_broadcast(&mut h).await;
        assert_eq!(h.clip.write_count(), 1, "ownership rewrite must not loop");
    }

    #[tokio::test(start_paused = true)]
    async fn take_ownership_with_synthesis_backfills_the_local_clipboard() {
        let mut cfg = Config::for_test("s");
        cfg.take_ownership = true;
        cfg.synthesize_text_plain = true;
        let mut h = start(cfg).await;
        let raw: Offer = [("UTF8_STRING".to_string(), b"hi".to_vec())]
            .into_iter()
            .collect();
        h.clip.local_copy(SelectionKind::Clipboard, raw);
        let (_, _, broadcast) = recv_clip(&mut h).await;
        assert_eq!(
            broadcast.keys().map(String::as_str).collect::<Vec<_>>(),
            ["text/plain;charset=utf-8", "text/plain", "UTF8_STRING"]
        );
        // The LOCAL clipboard is re-owned WITH the synthesized reps, so a paste
        // on the origin host now sees text/plain too.
        wait_for_write_count(&h, 1).await;
        let owned = h.clip.get(SelectionKind::Clipboard).unwrap();
        assert_eq!(
            owned.keys().map(String::as_str).collect::<Vec<_>>(),
            ["text/plain;charset=utf-8", "text/plain", "UTF8_STRING"]
        );
        assert_eq!(owned.get("text/plain").map(Vec::as_slice), Some(&b"hi"[..]));
        assert_no_broadcast(&mut h).await;
        assert_eq!(h.clip.write_count(), 1, "ownership rewrite must not loop");
    }

    #[tokio::test(start_paused = true)]
    async fn take_ownership_off_does_not_rewrite() {
        let mut h = start(Config::for_test("s")).await; // take_ownership defaults off
        h.clip.local_copy(SelectionKind::Clipboard, offer("hi"));
        let _ = recv_clip(&mut h).await;
        assert_no_broadcast(&mut h).await;
        assert_eq!(
            h.clip.write_count(),
            0,
            "no ownership write when the flag is off"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn take_ownership_never_persists_a_sensitive_secret() {
        let mut cfg = Config::for_test("s"); // exclude_sensitive defaults true
        cfg.take_ownership = true;
        let mut h = start(cfg).await;
        let secret: Offer = [
            ("text/plain".to_string(), b"hunter2".to_vec()),
            (SENSITIVE_MIME.to_string(), b"secret".to_vec()),
        ]
        .into_iter()
        .collect();
        h.clip.local_copy(SelectionKind::Clipboard, secret);
        // Sensitive content is neither broadcast nor re-owned (a password manager
        // clears its clipboard; clipmesh must not keep serving it).
        assert_no_broadcast(&mut h).await;
        assert_eq!(
            h.clip.write_count(),
            0,
            "must not take ownership of a password-manager secret"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn take_ownership_with_link_selections_terminates() {
        // Ownership rewrites both the clipboard and (via the bridge) the selection;
        // each rewrite re-fires the watcher. The last_written markers must make
        // the whole thing quiesce rather than storm.
        let mut cfg = Config::for_test("s");
        cfg.take_ownership = true;
        cfg.link_selections = LinkSelections::CLIPBOARD_TO_SELECTION;
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("hi"));
        let (kind, _, o) = recv_clip(&mut h).await;
        assert_eq!((kind, o), (SelectionKind::Clipboard, offer("hi")));
        // Both selections settle on the content and the engine goes quiet.
        wait_applied(&h, SelectionKind::Selection, &offer("hi")).await;
        assert_no_broadcast(&mut h).await;
        assert_eq!(h.clip.get(SelectionKind::Clipboard), Some(offer("hi")));
        // Exactly two writes, both echo-suppressed afterward: the CLIPBOARD
        // ownership write and the SELECTION write are now one owned write each
        // (the bridge mirror and the SELECTION ownership rewrite are merged),
        // with no intermediate raw mirror write. A runaway loop would hang above
        // or exceed this.
        assert_eq!(
            h.clip.write_count(),
            2,
            "expected exactly 2 writes (own CLIPBOARD + own SELECTION, merged)"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn take_ownership_caps_the_rewrite_to_max_payload_size() {
        // Multi-rep, asymmetric sizes: a large image plus a UTF8_STRING with no
        // text/plain. Synthesis adds two text/plain reps before the atom, blowing
        // the budget; the cap must drop the oversized image while KEEPING the
        // synthesized text/plain (the feature's point) in advertise order — and
        // the capped set must round-trip the read budget without churning.
        let mut cfg = Config::for_test("s");
        cfg.take_ownership = true;
        cfg.synthesize_text_plain = true;
        cfg.max_payload_size = 150;
        let mut h = start(cfg).await;
        let raw: Offer = [
            ("image/png".to_string(), vec![0u8; 150]), // 159 B — over budget alone
            ("UTF8_STRING".to_string(), vec![b'x'; 30]),
        ]
        .into_iter()
        .collect();
        h.clip.local_copy(SelectionKind::Clipboard, raw);
        let _ = recv_clip(&mut h).await;
        wait_for_write_count(&h, 1).await;
        let owned = h.clip.get(SelectionKind::Clipboard).unwrap();
        // Image dropped (too big); synthesized text/plain reps + atom survive, in
        // advertise order.
        assert_eq!(
            owned.keys().map(String::as_str).collect::<Vec<_>>(),
            ["text/plain;charset=utf-8", "text/plain", "UTF8_STRING"]
        );
        let total = offer_size(&owned);
        assert!(total <= 150, "over budget: {total}");
        assert_no_broadcast(&mut h).await;
        assert_eq!(h.clip.write_count(), 1, "ownership rewrite must not loop");
    }

    #[tokio::test(start_paused = true)]
    async fn take_ownership_drops_its_marker_when_the_write_fails() {
        // A failed ownership write must drop the last_written marker it set, or a
        // later genuine copy of identical bytes would be wrongly suppressed (and
        // never re-owned). With the marker dropped, the retry re-owns (one write).
        let mut cfg = Config::for_test("s");
        cfg.take_ownership = true;
        let mut h = start(cfg).await;
        h.clip.set_fail_writes(true);
        h.clip.local_copy(SelectionKind::Clipboard, offer("a"));
        let _ = recv_clip(&mut h).await; // broadcast happens before the failed write
        h.clip.set_fail_writes(false);
        h.clip.local_copy(SelectionKind::Clipboard, offer("a")); // identical re-copy
                                                                 // Reaching one successful write proves the stale marker was not blocking
                                                                 // the echo check at the top of handle_batch.
        wait_for_write_count(&h, 1).await;
    }

    #[tokio::test(start_paused = true)]
    async fn take_ownership_re_owns_even_on_a_receive_only_node() {
        // A receive-only node never broadcasts, but with take_ownership it still
        // re-owns the local selection (the early-out guard must let it through).
        let mut cfg = Config::for_test("s");
        cfg.take_ownership = true;
        cfg.direction = Direction::ReceiveOnly;
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("hi"));
        assert_no_broadcast(&mut h).await; // receive-only: nothing sent
        wait_for_write_count(&h, 1).await; // but ownership still rewrites locally
        assert_eq!(h.clip.get(SelectionKind::Clipboard), Some(offer("hi")));
    }

    #[tokio::test(start_paused = true)]
    async fn clipboard_change_mirrors_to_selection() {
        let mut cfg = Config::for_test("s");
        cfg.link_selections = LinkSelections::CLIPBOARD_TO_SELECTION;
        cfg.verbose = true; // also exercises the bridge's verbose mirror log
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("foo"));
        // the clipboard change is broadcast as usual...
        let (kind, _, o) = recv_clip(&mut h).await;
        assert_eq!((kind, o), (SelectionKind::Clipboard, offer("foo")));
        // ...and mirrored into the selection locally.
        wait_applied(&h, SelectionKind::Selection, &offer("foo")).await;
        // sync_selection is off, so selection isn't in synced_kinds(): the mirror's
        // watcher event yields no broadcast.
        assert_no_broadcast(&mut h).await;
        // exactly one write_offer: the single selection mirror (local_copy does
        // not count; nothing inbound here).
        assert_eq!(h.clip.write_count(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn selection_change_mirrors_to_clipboard() {
        let mut cfg = Config::for_test("s");
        cfg.link_selections = LinkSelections::SELECTION_TO_CLIPBOARD;
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Selection, offer("sel"));
        // selection→clipboard: the selection lands in the clipboard and (because
        // clipboard is always mesh-synced) is broadcast as a clipboard update.
        let (kind, _, o) = recv_clip(&mut h).await;
        assert_eq!((kind, o), (SelectionKind::Clipboard, offer("sel")));
        wait_applied(&h, SelectionKind::Clipboard, &offer("sel")).await;
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn single_direction_does_not_mirror_the_other_way() {
        // clipboard_to_selection must NOT mirror a selection change into clipboard.
        let mut cfg = Config::for_test("s");
        cfg.sync_selection = true; // so the selection change is at least observable
        cfg.link_selections = LinkSelections::CLIPBOARD_TO_SELECTION;
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Selection, offer("sel"));
        let (kind, _, o) = recv_clip(&mut h).await; // selection broadcast (sync_selection)
        assert_eq!((kind, o), (SelectionKind::Selection, offer("sel")));
        assert_eq!(h.clip.write_count(), 0); // clipboard never mirrored
        assert_eq!(h.clip.get(SelectionKind::Clipboard), None);
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn identical_content_is_not_rebroadcast() {
        let mut h = start(Config::for_test("s")).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("same"));
        recv_clip(&mut h).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("same"));
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn sensitive_offers_are_not_broadcast() {
        let mut h = start(Config::for_test("s")).await;
        let mut o = offer("hunter2");
        o.insert("x-kde-passwordManagerHint".to_string(), b"secret".to_vec());
        h.clip.local_copy(SelectionKind::Clipboard, o);
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn sensitive_filter_can_be_disabled() {
        let mut cfg = Config::for_test("s");
        cfg.exclude_sensitive = false;
        let mut h = start(cfg).await;
        let mut o = offer("hunter2");
        o.insert("x-kde-passwordManagerHint".to_string(), b"secret".to_vec());
        h.clip.local_copy(SelectionKind::Clipboard, o.clone());
        let (_, _, got) = recv_clip(&mut h).await;
        assert_eq!(got, o);
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_clip_is_applied_and_not_echoed_back() {
        let mut h = start(Config::for_test("s")).await;
        let o = offer("from remote");
        send_inbound(&h, SelectionKind::Clipboard, o.clone()).await;
        wait_applied(&h, SelectionKind::Clipboard, &o).await;
        assert_eq!(h.clip.write_count(), 1);
        // applying re-fired the watcher; echo suppression must hold
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn failed_write_does_not_poison_dedup() {
        let h = start(Config::for_test("s")).await;
        let o = offer("retry me");
        // first delivery fails at the clipboard layer
        h.clip.set_fail_writes(true);
        send_inbound(&h, SelectionKind::Clipboard, o.clone()).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(h.clip.get(SelectionKind::Clipboard), None);
        // a relay of the same content must still be applied
        h.clip.set_fail_writes(false);
        send_inbound(&h, SelectionKind::Clipboard, o.clone()).await;
        wait_applied(&h, SelectionKind::Clipboard, &o).await;
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_with_bad_hash_is_rejected() {
        let mut h = start(Config::for_test("s")).await;
        let o = offer("tampered");
        let msg = Message::Clip {
            kind: SelectionKind::Clipboard,
            hash: [9u8; 32],
            offer: o.into(),
            version: Version::new(1, h.remote_id),
        };
        h.in_tx.send((h.remote_id, msg)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(h.clip.write_count(), 0);
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn receive_only_does_not_broadcast() {
        let mut cfg = Config::for_test("s");
        cfg.direction = Direction::ReceiveOnly;
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("local"));
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn send_only_ignores_inbound() {
        let mut cfg = Config::for_test("s");
        cfg.direction = Direction::SendOnly;
        let h = start(cfg).await;
        send_inbound(&h, SelectionKind::Clipboard, offer("remote")).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(h.clip.write_count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn selection_is_ignored_unless_enabled() {
        let mut h = start(Config::for_test("s")).await;
        h.clip.local_copy(SelectionKind::Selection, offer("sel"));
        assert_no_broadcast(&mut h).await;
        send_inbound(&h, SelectionKind::Selection, offer("rem")).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(h.clip.write_count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn selection_is_synced_when_enabled() {
        let mut cfg = Config::for_test("s");
        cfg.sync_selection = true;
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Selection, offer("sel"));
        let (kind, _, o) = recv_clip(&mut h).await;
        assert_eq!(kind, SelectionKind::Selection);
        assert_eq!(o, offer("sel"));
    }

    #[tokio::test(start_paused = true)]
    async fn oversized_offers_are_not_broadcast() {
        let mut cfg = Config::for_test("s");
        cfg.max_payload_size = 8;
        let mut h = start(cfg).await;
        h.clip
            .local_copy(SelectionKind::Clipboard, offer("way more than eight bytes"));
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn denied_mime_types_are_stripped() {
        let mut cfg = Config::for_test("s");
        let (_dir, _) = with_rules(&mut cfg, MimePolicy::Allow, &[("image/png", "deny")]);
        let mut h = start(cfg).await;
        let mut o = offer("text part");
        o.insert("image/png".to_string(), vec![0u8; 16]);
        h.clip.local_copy(SelectionKind::Clipboard, o);
        let (_, _, got) = recv_clip(&mut h).await;
        assert_eq!(got, offer("text part"));
    }

    #[tokio::test(start_paused = true)]
    async fn debounce_collapses_rapid_copies_into_final_state() {
        let mut cfg = Config::for_test("s");
        cfg.debounce_ms = 100;
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("one"));
        h.clip.local_copy(SelectionKind::Clipboard, offer("two"));
        let (_, _, got) = recv_clip(&mut h).await;
        assert_eq!(got, offer("two"));
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn unknown_deny_syncs_only_allowed_types() {
        let mut cfg = Config::for_test("s");
        let (_dir, _) = with_rules(&mut cfg, MimePolicy::Deny, &[("text/plain", "allow")]);
        let mut h = start(cfg).await;
        let mut o = offer("text part"); // text/plain explicitly allowed
        o.insert("image/png".to_string(), vec![0u8; 16]); // unknown -> denied
        h.clip.local_copy(SelectionKind::Clipboard, o);
        let (_, _, got) = recv_clip(&mut h).await;
        assert_eq!(got, offer("text part"));
    }

    #[tokio::test(start_paused = true)]
    async fn offer_with_only_denied_types_is_not_broadcast() {
        let mut cfg = Config::for_test("s");
        let (_dir, _) = with_rules(&mut cfg, MimePolicy::Deny, &[]); // deny everything unseen
        let mut h = start(cfg).await;
        let o: Offer = [("image/png".to_string(), vec![0u8; 16])]
            .into_iter()
            .collect();
        h.clip.local_copy(SelectionKind::Clipboard, o);
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn debounce_window_resets_on_new_activity() {
        let mut cfg = Config::for_test("s");
        cfg.debounce_ms = 100;
        let mut h = start(cfg).await;
        // each copy lands inside the previous quiet window, so the window
        // keeps resetting and only the final state is broadcast once
        h.clip.local_copy(SelectionKind::Clipboard, offer("a"));
        tokio::time::sleep(Duration::from_millis(80)).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("b"));
        tokio::time::sleep(Duration::from_millis(80)).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("c"));
        let (_, _, got) = recv_clip(&mut h).await;
        assert_eq!(got, offer("c"));
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_selection_applies_to_selection_only() {
        let mut cfg = Config::for_test("s");
        cfg.sync_selection = true;
        let h = start(cfg).await;
        let o = offer("sel");
        send_inbound(&h, SelectionKind::Selection, o.clone()).await;
        wait_applied(&h, SelectionKind::Selection, &o).await;
        assert_eq!(h.clip.get(SelectionKind::Clipboard), None);
    }

    #[tokio::test(start_paused = true)]
    async fn payload_exactly_at_cap_is_broadcast() {
        // offer_size counts mime key bytes + data bytes
        let o = offer("12345678"); // "text/plain" (10) + 8 = 18
        let mut cfg = Config::for_test("s");
        cfg.max_payload_size = 18;
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Clipboard, o.clone());
        let (_, _, got) = recv_clip(&mut h).await;
        assert_eq!(got, o);

        let mut cfg = Config::for_test("s");
        cfg.max_payload_size = 17; // one byte under
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Clipboard, o);
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn payload_cap_drops_oversized_reps_but_keeps_small_ones() {
        // a small text rep fits the budget; a big rep alongside it doesn't, so
        // only the small one is broadcast (rather than dropping the whole offer)
        let mut cfg = Config::for_test("s");
        cfg.max_payload_size = 32;
        let mut h = start(cfg).await;
        let mut o = offer("hi"); // text/plain (10) + 2 = 12, fits
        o.insert("image/png".to_string(), vec![0u8; 64]); // 9 + 64 = 73, doesn't
        h.clip.local_copy(SelectionKind::Clipboard, o);
        let (_, _, got) = recv_clip(&mut h).await;
        assert_eq!(got, offer("hi"));
    }

    #[tokio::test(start_paused = true)]
    async fn resync_pushes_state_to_newly_connected_peer() {
        let mut h = start(Config::for_test("s")).await;
        h.clip
            .local_copy(SelectionKind::Clipboard, offer("current"));
        recv_clip(&mut h).await; // consume the live broadcast

        // a second peer joins; engine must push current state to it only
        let (tx2, mut rx2) = mpsc::channel(8);
        let peer2 = Uuid::new_v4();
        h.mesh.register(peer2, tx2, PeerRole::Peer);
        let msg = recv_from(&mut rx2).await;
        match msg {
            Message::Clip { offer: o, .. } => assert_eq!(*o, offer("current")),
            other => panic!("expected resync Clip, got {other:?}"),
        }
        // the pre-existing peer must not receive a duplicate
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn resync_reaches_every_peer_of_a_reconnect_burst() {
        // Several peers reconnecting at once (a switch blip, a laptop waking)
        // are drained into one burst so the clipboard is read and encoded once.
        // Every peer in the burst must still get its own resync — the sharing is
        // of the encoded frame, not of the delivery.
        let mut h = start(Config::for_test("s")).await;
        h.clip
            .local_copy(SelectionKind::Clipboard, offer("current"));
        recv_clip(&mut h).await; // consume the live broadcast

        let mut rxs: Vec<_> = (0..3)
            .map(|_| {
                let (tx, rx) = mpsc::channel(8);
                h.mesh.register(Uuid::new_v4(), tx, PeerRole::Peer);
                rx
            })
            .collect();

        for (i, rx) in rxs.iter_mut().enumerate() {
            match recv_from(rx).await {
                Message::Clip { offer: o, .. } => {
                    assert_eq!(*o, offer("current"), "peer {i} got the wrong resync")
                }
                other => panic!("peer {i}: expected resync Clip, got {other:?}"),
            }
        }
        // and no duplicate to the peer that was already connected
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn resync_can_be_disabled() {
        let mut cfg = Config::for_test("s");
        cfg.resync_on_connect = false;
        let mut h = start(cfg).await;
        h.clip
            .local_copy(SelectionKind::Clipboard, offer("current"));
        recv_clip(&mut h).await;

        let (tx2, mut rx2) = mpsc::channel(8);
        h.mesh.register(Uuid::new_v4(), tx2, PeerRole::Peer);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(rx2.try_recv().is_err(), "resync must be disabled");
    }

    #[tokio::test(start_paused = true)]
    async fn fresh_node_applies_inbound_resync() {
        let h = start(Config::for_test("s")).await;
        let o = offer("restored");
        send_inbound_full(&h, SelectionKind::Clipboard, o.clone(), 5000).await;
        wait_applied(&h, SelectionKind::Clipboard, &o).await;
    }

    #[tokio::test(start_paused = true)]
    async fn stale_resync_is_ignored() {
        let h = start(Config::for_test("s")).await;
        let newer = offer("newer");
        send_inbound_full(&h, SelectionKind::Clipboard, newer.clone(), 5000).await;
        wait_applied(&h, SelectionKind::Clipboard, &newer).await;

        // an older update (e.g. a resync from a peer that slept) must not win
        send_inbound_full(&h, SelectionKind::Clipboard, offer("older"), 1000).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(h.clip.get(SelectionKind::Clipboard), Some(newer));
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_sensitive_content_is_not_applied() {
        // a peer running exclude_sensitive=false must not get us to write a
        // password-manager secret to our clipboard when ours is enabled
        let h = start(Config::for_test("s")).await;
        let mut o = offer("hunter2");
        o.insert("x-kde-passwordManagerHint".to_string(), b"secret".to_vec());
        send_inbound(&h, SelectionKind::Clipboard, o).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(h.clip.write_count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_denied_types_are_stripped_before_writing() {
        let mut cfg = Config::for_test("s");
        let (_dir, _) = with_rules(&mut cfg, MimePolicy::Allow, &[("image/png", "deny")]);
        let h = start(cfg).await;
        let mut o = offer("text part");
        o.insert("image/png".to_string(), vec![0u8; 16]);
        send_inbound(&h, SelectionKind::Clipboard, o).await;
        wait_applied(&h, SelectionKind::Clipboard, &offer("text part")).await;
    }

    #[tokio::test(start_paused = true)]
    async fn recopying_superseded_content_is_rebroadcast() {
        // regression: re-copying content the node previously broadcast, after
        // the mesh moved on, must NOT be suppressed as a stale dedup
        let mut h = start(Config::for_test("s")).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("foo"));
        recv_clip(&mut h).await; // broadcast foo
        send_inbound_full(
            &h,
            SelectionKind::Clipboard,
            offer("bar"),
            future_stamp(5000),
        )
        .await;
        wait_applied(&h, SelectionKind::Clipboard, &offer("bar")).await;
        // user re-copies foo; mesh holds bar, so foo is genuinely new again
        h.clip.local_copy(SelectionKind::Clipboard, offer("foo"));
        let (_, _, got) = recv_clip(&mut h).await;
        assert_eq!(got, offer("foo"));
    }

    #[tokio::test(start_paused = true)]
    async fn live_update_previously_applied_then_superseded_reapplies() {
        // regression: a live update whose hash was applied earlier must apply
        // again if our current content has since changed
        let mut h = start(Config::for_test("s")).await;
        send_inbound_full(
            &h,
            SelectionKind::Clipboard,
            offer("foo"),
            future_stamp(1000),
        )
        .await;
        wait_applied(&h, SelectionKind::Clipboard, &offer("foo")).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("bar"));
        recv_clip(&mut h).await; // current is now bar (local copy, now_ms stamp)
        send_inbound_full(
            &h,
            SelectionKind::Clipboard,
            offer("foo"),
            future_stamp(60_000),
        )
        .await;
        wait_applied(&h, SelectionKind::Clipboard, &offer("foo")).await;
    }

    #[tokio::test(start_paused = true)]
    async fn same_content_newer_stamp_advances_lww_clock() {
        // Regression: receiving content we already hold, but stamped higher,
        // must advance our recorded (stamp, origin). Otherwise a later update
        // stamped between our stale stamp and a peer's newer one wins here
        // while losing on the peer that saw the higher stamp — permanent
        // divergence between two nodes holding the same content.
        let h = start(Config::for_test("s")).await;
        send_inbound_full(&h, SelectionKind::Clipboard, offer("x"), 100).await;
        wait_applied(&h, SelectionKind::Clipboard, &offer("x")).await;

        // identical bytes at a higher stamp: no clipboard write, but our
        // recorded stamp must move from 100 to 300
        send_inbound_full(&h, SelectionKind::Clipboard, offer("x"), 300).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        // an update stamped 200 (between the two) must now lose to our 300
        send_inbound_full(&h, SelectionKind::Clipboard, offer("y"), 200).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            h.clip.get(SelectionKind::Clipboard),
            Some(offer("x")),
            "intermediate-stamped update must lose after a same-content stamp bump"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn rejects_implausibly_future_stamp() {
        // a peer with a broken clock must not poison ordering or crash us
        let h = start(Config::for_test("s")).await;
        send_inbound_full(
            &h,
            SelectionKind::Clipboard,
            offer("from the future"),
            now_ms() + 48 * 60 * 60 * 1000, // 48h ahead, past the skew bound
        )
        .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(h.clip.write_count(), 0);
        // a normal local copy afterwards must still be able to win
        let mut h = h;
        h.clip.local_copy(SelectionKind::Clipboard, offer("normal"));
        let (_, _, got) = recv_clip(&mut h).await;
        assert_eq!(got, offer("normal"));
    }

    #[tokio::test(start_paused = true)]
    async fn clock_observes_remote_stamp_so_local_copies_outrank_it() {
        let mut h = start(Config::for_test("s")).await;
        let high = now_ms() + 60 * 60 * 1000; // 1h ahead, within the skew bound
        send_inbound_full(&h, SelectionKind::Clipboard, offer("remote"), high).await;
        wait_applied(&h, SelectionKind::Clipboard, &offer("remote")).await;
        // our next local copy must carry a stamp above the observed remote one
        h.clip.local_copy(SelectionKind::Clipboard, offer("local"));
        assert!(recv_stamp(&mut h).await > high);
    }

    #[tokio::test(start_paused = true)]
    async fn local_stamps_are_strictly_monotonic() {
        let mut h = start(Config::for_test("s")).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("a"));
        let s1 = recv_stamp(&mut h).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("b"));
        let s2 = recv_stamp(&mut h).await;
        assert!(s2 > s1, "{s2} must exceed {s1}");
    }

    #[tokio::test(start_paused = true)]
    async fn restored_content_loses_resync_to_real_remote_content() {
        // a restarted node's restored clipboard (stamp 0) must yield to a
        // peer's genuinely-stamped content
        let h = start_seeded(Config::for_test("s"), offer("restored")).await;
        send_inbound_full(
            &h,
            SelectionKind::Clipboard,
            offer("real"),
            future_stamp(1000),
        )
        .await;
        wait_applied(&h, SelectionKind::Clipboard, &offer("real")).await;
    }

    #[tokio::test(start_paused = true)]
    async fn restored_content_is_not_rebroadcast_as_fresh() {
        // the compositor's subscribe-time event for restored content (modelled
        // by a local_copy of the same bytes) must be suppressed, not broadcast
        let mut h = start_seeded(Config::for_test("s"), offer("restored")).await;
        h.clip
            .local_copy(SelectionKind::Clipboard, offer("restored"));
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn restored_content_resyncs_with_stamp_zero() {
        let h = start_seeded(Config::for_test("s"), offer("restored")).await;
        let (tx2, mut rx2) = mpsc::channel(8);
        h.mesh.register(Uuid::new_v4(), tx2, PeerRole::Peer);
        match recv_from(&mut rx2).await {
            Message::Clip {
                offer: o, version, ..
            } => {
                assert_eq!(*o, offer("restored"));
                assert_eq!(version.stamp, 0, "restored content must resync at stamp 0");
            }
            other => panic!("expected resync Clip, got {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_is_serviced_during_a_local_event_storm() {
        // the debounce-as-select-arm rewrite must not let a flood of local
        // change events starve inbound processing
        let mut cfg = Config::for_test("s");
        cfg.debounce_ms = 100;
        let h = start(cfg).await;
        for i in 0..50 {
            h.clip
                .local_copy(SelectionKind::Clipboard, offer(&format!("v{i}")));
        }
        send_inbound_full(
            &h,
            SelectionKind::Clipboard,
            offer("remote"),
            future_stamp(60_000),
        )
        .await;
        // the inbound must apply well before the 100ms debounce window closes
        timeout(Duration::from_millis(20), async {
            while h.clip.get(SelectionKind::Clipboard) != Some(offer("remote")) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("inbound starved by local-event storm");
    }

    /// Pins the whole policy table per config. Every one of these answers used
    /// to come from its own predicate re-deriving the rule, and none of them had
    /// direct coverage — a refactor could change which selections get watched
    /// and no test would notice.
    #[test]
    fn selection_policy_matches_the_config() {
        use SelectionKind::{Clipboard, Selection};
        let policies = |f: &dyn Fn(&mut Config)| {
            let mut cfg = Config::for_test("s");
            f(&mut cfg);
            Policies::new(&cfg)
        };

        // Default: CLIPBOARD only, both directions, nothing local.
        let p = policies(&|_| {});
        assert!(p.get(Clipboard).send && p.get(Clipboard).recv && p.get(Clipboard).watch);
        assert!(!p.get(Selection).send && !p.get(Selection).recv && !p.get(Selection).watch);
        assert_eq!(p.kinds(|x| x.watch), vec![Clipboard]);

        // sync_selection puts SELECTION on the mesh.
        let p = policies(&|c| c.sync_selection = true);
        assert!(p.get(Selection).send && p.get(Selection).recv && p.get(Selection).watch);
        assert_eq!(p.kinds(|x| x.send || x.recv), vec![Clipboard, Selection]);

        // Direction gates send/recv but not watching.
        let p = policies(&|c| c.direction = Direction::ReceiveOnly);
        assert!(!p.get(Clipboard).send && p.get(Clipboard).recv && p.get(Clipboard).watch);
        let p = policies(&|c| c.direction = Direction::SendOnly);
        assert!(p.get(Clipboard).send && !p.get(Clipboard).recv);

        // selection_to_clipboard needs SELECTION changes, so it must be watched
        // even though it is not synced.
        let p = policies(&|c| c.link_selections = LinkSelections::SELECTION_TO_CLIPBOARD);
        assert!(p.get(Selection).watch, "the bridge source must be observed");
        assert!(!p.get(Selection).send, "watching does not imply syncing");
        assert_eq!(p.get(Selection).mirror_into, Some(Clipboard));

        // The reverse direction makes SELECTION a mirror *target*, which is
        // reconciled by an on-demand read rather than by watching it.
        let p = policies(&|c| c.link_selections = LinkSelections::CLIPBOARD_TO_SELECTION);
        assert!(!p.get(Selection).watch, "a mirror target is not watched");
        assert_eq!(p.get(Clipboard).mirror_into, Some(Selection));

        // take_ownership gives every selection a local sink even with no mesh.
        let p = policies(&|c| {
            c.direction = Direction::ReceiveOnly;
            c.take_ownership = true;
        });
        assert!(p.get(Clipboard).has_local_sink());
    }

    #[test]
    fn ordering_is_by_stamp_then_origin() {
        let lo = Uuid::from_u128(1);
        let hi = Uuid::from_u128(2);
        let s = ContentState {
            hash: [0u8; 32],
            version: Version::new(5, lo),
        };
        let v = Version::new;
        assert!(s.superseded_by(v(6, lo))); // higher stamp wins
        assert!(!s.superseded_by(v(4, hi))); // lower stamp loses despite higher origin
        assert!(s.superseded_by(v(5, hi))); // equal stamp: higher origin wins (converges)
        assert!(!s.superseded_by(v(5, lo))); // identical: not superseded
        assert!(!s.superseded_by(v(5, Uuid::from_u128(0)))); // equal stamp, lower origin loses
    }

    #[tokio::test(start_paused = true)]
    async fn per_type_max_size_drops_oversized_representations() {
        let mut cfg = Config::for_test("s");
        let (_dir, _) = with_rules_body(
            &mut cfg,
            MimePolicy::Allow,
            "[rules]\n\"image/png\" = { rule = \"allow\", max = \"8B\" }\n",
        );
        let mut h = start(cfg).await;
        let mut o = offer("hi"); // text/plain (unknown -> allow, no cap)
        o.insert("image/png".to_string(), vec![0u8; 16]); // 16 B over the 8 B cap
        h.clip.local_copy(SelectionKind::Clipboard, o);
        let (_, _, got) = recv_clip(&mut h).await;
        assert_eq!(got, offer("hi"));
    }

    #[tokio::test(start_paused = true)]
    async fn unseen_types_are_recorded_in_the_rules_file() {
        let mut cfg = Config::for_test("s");
        let (_dir, path) = with_rules_absent(&mut cfg, MimePolicy::Deny);
        let mut h = start(cfg).await;
        // A type the shipped defaults say nothing about, so it is genuinely
        // unseen (text/plain and friends now ship allowed in the skeleton).
        h.clip.local_copy(
            SelectionKind::Clipboard,
            crate::protocol::test_support::offer(&[("application/x-custom", b"hi")]),
        );
        // deny-by-default: nothing syncs, but the new type is written out
        assert_no_broadcast(&mut h).await;
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(
            written.contains("\"application/x-custom\" = \"deny\""),
            "got:\n{written}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn editing_an_existing_rule_is_not_picked_up_without_the_watcher() {
        // The capture path only reloads when a NEW type appears (so the common
        // case does no blocking file I/O). Edits to existing rules are picked up
        // by the inotify watcher, which this harness doesn't run — so with no
        // new type, the engine keeps the rules it loaded at start.
        let mut cfg = Config::for_test("s");
        let (_dir, path) = with_rules(&mut cfg, MimePolicy::Deny, &[("text/plain", "deny")]);
        let mut h = start(cfg).await;
        std::fs::write(&path, "[rules]\n\"text/plain\" = \"allow\"\n").unwrap();
        h.clip.local_copy(SelectionKind::Clipboard, offer("hello"));
        // No watcher + no new type -> the on-disk flip is not applied here.
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn recording_a_new_type_merges_concurrent_on_disk_edits() {
        // When a brand-new type is captured, apply_mime_rules reloads-then-
        // appends, so a concurrent on-disk edit is merged rather than clobbered
        // by the append (verified here without a running watcher).
        let mut cfg = Config::for_test("s");
        let (_dir, path) = with_rules(&mut cfg, MimePolicy::Deny, &[("text/plain", "deny")]);
        let mut h = start(cfg).await;

        // User flips text/plain to allow on disk; no watcher fires.
        std::fs::write(&path, "[rules]\n\"text/plain\" = \"allow\"\n").unwrap();
        // Copy with a NEW type (image/png), which triggers record + persist.
        let mut o = offer("hi"); // text/plain
        o.insert("image/png".to_string(), vec![1, 2, 3]);
        h.clip.local_copy(SelectionKind::Clipboard, o);
        let (_, _, got) = recv_clip(&mut h).await;
        // text/plain (merged allow) syncs; image/png is newly deny-by-default.
        assert_eq!(got, offer("hi"));
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(
            body.contains("\"text/plain\" = \"allow\""),
            "user edit was clobbered:\n{body}"
        );
        assert!(
            body.contains("\"image/png\" = \"deny\""),
            "new type not recorded:\n{body}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_persist_does_not_broadcast_rules() {
        // If we can't durably write the new version, we must not announce it
        // (a peer would adopt a stamp our disk doesn't have, and we'd lose it on
        // restart). A directory at the rules path makes every write fail.
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        cfg.unknown_mime = MimePolicy::Allow;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimetypes");
        std::fs::create_dir(&path).unwrap();
        cfg.mime_rules_path = Some(path.clone());
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("hello"));
        // The clipboard content still broadcasts...
        assert!(matches!(recv_msg(&mut h).await, Message::Clip { .. }));
        // ...but no Rules push, because the version couldn't be persisted.
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_oversized_rules_is_rejected() {
        // A peer must not be able to make us persist a file larger than our
        // max_payload_size (the send-side cap only bounds what we send).
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        cfg.max_payload_size = 8; // tiny: any real rules body is over the limit
        let (_dir, path) = with_rules(&mut cfg, MimePolicy::Deny, &[("image/png", "deny")]);
        let h = start(cfg).await;
        // the body is well over the 8-byte cap
        send_rules(
            &h,
            future_stamp(1000),
            h.remote_id,
            rules_toml(&[("image/png", "allow")]),
        )
        .await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            rules_toml(&[("image/png", "deny")]),
            "oversized inbound rules must be rejected, not written to disk"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_rules_newer_is_adopted() {
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        let (_dir, path) = with_rules(&mut cfg, MimePolicy::Deny, &[("image/png", "deny")]);
        let mut h = start(cfg).await;
        send_rules(
            &h,
            future_stamp(1000),
            h.remote_id,
            rules_toml(&[("image/png", "allow")]),
        )
        .await;
        wait_rules_contain(
            &path,
            "\"image/png\" = \"allow\"",
            "newer rules to be adopted",
        )
        .await;
        // The adopted version is stamped into the header (so version() is
        // authoritative, not the file's mtime).
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("version ="),
            "adopted file must carry the version header"
        );
        // Adopting a peer file must not bounce back as a broadcast.
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_rules_equal_stamp_higher_origin_wins() {
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        // Seed a header with a known stamp and a LOW origin, so an equal-stamp
        // peer with a higher origin wins the deterministic tiebreak.
        let low = Uuid::from_u128(1);
        let (_dir, path) = with_rules_body(
            &mut cfg,
            MimePolicy::Deny,
            &format!("[clipmesh]\nversion = 5000\norigin = \"{low}\"\n[rules]\n\"image/png\" = \"deny\"\n"),
        );
        let h = start(cfg).await;
        let high = Uuid::from_u128(2);
        send_rules(&h, 5000, high, rules_toml(&[("image/png", "allow")])).await;
        wait_rules_contain(
            &path,
            "\"image/png\" = \"allow\"",
            "the equal-stamp higher-origin peer to win the tiebreak",
        )
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_rules_older_is_ignored() {
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        let (_dir, path) = with_rules(&mut cfg, MimePolicy::Deny, &[("image/png", "allow")]);
        let h = start(cfg).await;
        // our baseline is the file's (recent) mtime, so stamp 1 must lose
        send_rules(&h, 1, h.remote_id, rules_toml(&[("image/png", "deny")])).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            rules_toml(&[("image/png", "allow")]),
            "older rules must not overwrite"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_rules_ignored_when_sharing_off() {
        let mut cfg = Config::for_test("s"); // sharing off by default
        let (_dir, path) = with_rules(&mut cfg, MimePolicy::Deny, &[("image/png", "deny")]);
        let h = start(cfg).await;
        send_rules(
            &h,
            future_stamp(1000),
            h.remote_id,
            rules_toml(&[("image/png", "allow")]),
        )
        .await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            rules_toml(&[("image/png", "deny")]),
            "sharing off must ignore inbound rules"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_future_rules_stamp_is_rejected() {
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        let (_dir, path) = with_rules(&mut cfg, MimePolicy::Deny, &[("image/png", "deny")]);
        let h = start(cfg).await;
        let insane = now_ms() + 48 * 60 * 60 * 1000; // past the skew bound
        send_rules(
            &h,
            insane,
            h.remote_id,
            rules_toml(&[("image/png", "allow")]),
        )
        .await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            rules_toml(&[("image/png", "deny")]),
            "implausibly-future rules must be rejected"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_peer_types_are_not_written_to_the_rules_file() {
        // A peer's advertised MIME types must not grow/pollute our local rules
        // file; the inbound path applies rules but never records unseen types.
        let mut cfg = Config::for_test("s");
        let (_dir, path) = with_rules_absent(&mut cfg, MimePolicy::Deny);
        let h = start(cfg).await;
        let before = std::fs::read_to_string(&path).unwrap();
        send_inbound(&h, SelectionKind::Clipboard, offer("from-peer")).await;
        // Give the inbound a moment to be processed.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            before, after,
            "inbound peer types were written to the rules file"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn capturing_a_new_type_broadcasts_the_rules_file() {
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        // captured type also syncs
        let (_dir, _) = with_rules_absent(&mut cfg, MimePolicy::Allow);
        let mut h = start(cfg).await;
        // a type the shipped defaults don't cover, so capturing it is new
        h.clip.local_copy(
            SelectionKind::Clipboard,
            crate::protocol::test_support::offer(&[("application/x-custom", b"hi")]),
        );
        // we should see a Clip (content) and, separately, a Rules broadcast
        let mut saw_rules = false;
        for _ in 0..3 {
            match recv_msg(&mut h).await {
                Message::Rules { body, .. } => {
                    assert!(body.contains("application/x-custom"), "body:\n{body}");
                    assert!(body.contains("version ="), "body:\n{body}");
                    saw_rules = true;
                    break;
                }
                Message::Clip { .. } => {}
                other => panic!("unexpected {other:?}"),
            }
        }
        assert!(
            saw_rules,
            "capturing a new type should broadcast the rules file"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn capturing_a_new_type_does_not_broadcast_rules_when_sharing_off() {
        let mut cfg = Config::for_test("s"); // sharing off
        let (_dir, path) = with_rules_absent(&mut cfg, MimePolicy::Allow);
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("hello"));
        assert!(matches!(recv_msg(&mut h).await, Message::Clip { .. }));
        assert_no_broadcast(&mut h).await; // no Rules follows
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(
            !body.contains("version ="),
            "sharing off must not stamp the file:\n{body}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn connect_pushes_the_rules_file_to_a_new_peer() {
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        let (_dir, _) = with_rules_body(
            &mut cfg,
            MimePolicy::Allow,
            "[rules]\n\"image/png\" = \"allow\"\n",
        );
        let h = start(cfg).await;
        // a new peer joins; it must receive our rules file
        let (tx2, mut rx2) = mpsc::channel(8);
        h.mesh.register(Uuid::new_v4(), tx2, PeerRole::Peer);
        let msg = recv_from(&mut rx2).await;
        match msg {
            Message::Rules { body, .. } => {
                assert!(body.contains("\"image/png\" = \"allow\""), "body:\n{body}")
            }
            other => panic!("expected a Rules push, got {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn connect_pushes_rules_even_when_receive_only() {
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        cfg.direction = Direction::ReceiveOnly;
        cfg.resync_on_connect = false;
        let (_dir, _) = with_rules_body(
            &mut cfg,
            MimePolicy::Allow,
            "[rules]\n\"image/png\" = \"allow\"\n",
        );
        let h = start(cfg).await;
        let (tx2, mut rx2) = mpsc::channel(8);
        h.mesh.register(Uuid::new_v4(), tx2, PeerRole::Peer);
        let msg = recv_from(&mut rx2).await;
        assert!(
            matches!(msg, Message::Rules { .. }),
            "rules push must ignore direction/resync_on_connect"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn connect_materialises_the_version_header() {
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        let (_dir, path) = with_rules_body(
            &mut cfg,
            MimePolicy::Allow,
            "[rules]\n\"image/png\" = \"allow\"\n",
        ); // no header yet
        let h = start(cfg).await;
        let (tx2, mut rx2) = mpsc::channel(8);
        h.mesh.register(Uuid::new_v4(), tx2, PeerRole::Peer);
        let _ = recv_from(&mut rx2).await;
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(
            body.contains("version ="),
            "header must be materialised on first push:\n{body}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_local_change_outranks_the_persisted_version_after_restart() {
        // The engine observes the file's header stamp at startup, so a fresh
        // local change is stamped above it (not below, which would lose).
        let mut cfg = Config::for_test("s");
        cfg.share_mime_rules = true;
        cfg.unknown_mime = MimePolicy::Allow;
        let peer = Uuid::from_u128(123);
        let high = now_ms() + 60 * 60 * 1000; // 1h ahead, within the skew bound
        let (_dir, _) = with_rules_body(
            &mut cfg,
            MimePolicy::Allow,
            &format!("[clipmesh]\nversion = {high}\norigin = \"{peer}\"\n[rules]\n\"text/plain\" = \"allow\"\n"),
        );
        let mut h = start(cfg).await;
        // a NEW type (image/png) is captured -> append -> version bump
        let mut o = offer("x"); // text/plain already known
        o.insert("image/png".to_string(), vec![0u8; 4]);
        h.clip.local_copy(SelectionKind::Clipboard, o);
        let mut stamp = None;
        for _ in 0..3 {
            if let Message::Rules { version, .. } = recv_msg(&mut h).await {
                stamp = Some(version.stamp);
                break;
            }
        }
        assert!(
            stamp.unwrap() > high,
            "local change must outrank the observed header stamp {high}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn both_directions_settle_without_redundant_writes() {
        let mut cfg = Config::for_test("s");
        cfg.sync_selection = true;
        cfg.link_selections = LinkSelections::BOTH;
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("foo"));
        // exactly two broadcasts: the clipboard, then the mirrored selection
        let (k1, _, o1) = recv_clip(&mut h).await;
        assert_eq!((k1, o1), (SelectionKind::Clipboard, offer("foo")));
        let (k2, _, o2) = recv_clip(&mut h).await;
        assert_eq!((k2, o2), (SelectionKind::Selection, offer("foo")));
        assert_no_broadcast(&mut h).await;
        // one write only (the selection mirror); no echo ping-pong
        assert_eq!(h.clip.write_count(), 1);
        assert_eq!(h.clip.get(SelectionKind::Selection), Some(offer("foo")));
    }

    #[tokio::test(start_paused = true)]
    async fn both_directions_no_redundant_write_with_denied_rep() {
        let mut cfg = Config::for_test("s");
        cfg.sync_selection = true;
        cfg.link_selections = LinkSelections::BOTH;
        let (_dir, _) = with_rules(&mut cfg, MimePolicy::Allow, &[("image/png", "deny")]);
        let mut h = start(cfg).await;
        let mut o = offer("text part");
        o.insert("image/png".to_string(), vec![0u8; 16]);
        h.clip.local_copy(SelectionKind::Clipboard, o.clone());
        // the wire sees only the allowed text rep, on both axes
        let (k1, _, b1) = recv_clip(&mut h).await;
        assert_eq!((k1, b1), (SelectionKind::Clipboard, offer("text part")));
        let (k2, _, b2) = recv_clip(&mut h).await;
        assert_eq!((k2, b2), (SelectionKind::Selection, offer("text part")));
        assert_no_broadcast(&mut h).await;
        // selection holds the FULL raw offer (the denied rep is kept locally)
        assert_eq!(h.clip.get(SelectionKind::Selection), Some(o));
        // exactly one mirror write — no echo loop
        assert_eq!(h.clip.write_count(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn clip_to_selection_does_not_clobber_a_concurrent_selection() {
        // sync_selection + clipboard_to_selection: a clipboard copy and a fresh SELECTION
        // selection land in the same debounce window. The user's direct selection
        // must win over the clipboard->selection mirror (last-writer-wins), and must
        // itself reach the mesh — without this the mirror overwrote SELECTION with the
        // clipboard content, so the selection couldn't be pasted and was never sent.
        let mut cfg = Config::for_test("s");
        cfg.sync_selection = true;
        cfg.link_selections = LinkSelections::CLIPBOARD_TO_SELECTION;
        cfg.debounce_ms = 100; // batch the copy and the selection together
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("copied"));
        h.clip
            .local_copy(SelectionKind::Selection, offer("selected"));
        // The clipboard entry is processed first, then the selection entry; each is
        // broadcast with its OWN content.
        let (k1, _, o1) = recv_clip(&mut h).await;
        assert_eq!((k1, o1), (SelectionKind::Clipboard, offer("copied")));
        let (k2, _, o2) = recv_clip(&mut h).await;
        assert_eq!((k2, o2), (SelectionKind::Selection, offer("selected")));
        assert_no_broadcast(&mut h).await;
        // The user's selection survives in SELECTION, and the mirror did not write.
        assert_eq!(
            h.clip.get(SelectionKind::Selection),
            Some(offer("selected"))
        );
        assert_eq!(
            h.clip.write_count(),
            0,
            "the mirror must not clobber a concurrent selection"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn clip_to_selection_still_mirrors_a_new_copy_after_its_own_echo() {
        // Guard against over-correction: a second clipboard copy must still mirror
        // into SELECTION even when the previous mirror's own watch echo shares its
        // debounce batch (the echo is not a user change, so it must not suppress
        // the new mirror).
        let mut cfg = Config::for_test("s");
        cfg.sync_selection = true;
        cfg.link_selections = LinkSelections::CLIPBOARD_TO_SELECTION;
        cfg.debounce_ms = 100;
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("A"));
        let (k1, _, o1) = recv_clip(&mut h).await; // clipboard A broadcast
        assert_eq!((k1, o1), (SelectionKind::Clipboard, offer("A")));
        // Copy B before the mirror's selection echo has drained, so they batch.
        h.clip.local_copy(SelectionKind::Clipboard, offer("B"));
        // SELECTION must follow the newest clipboard content, not stay stuck on A.
        wait_applied(&h, SelectionKind::Selection, &offer("B")).await;
    }

    #[tokio::test(start_paused = true)]
    async fn sensitive_content_is_not_bridged() {
        let mut cfg = Config::for_test("s"); // exclude_sensitive on by default
        cfg.link_selections = LinkSelections::CLIPBOARD_TO_SELECTION;
        let mut h = start(cfg).await;
        let mut o = offer("hunter2");
        o.insert("x-kde-passwordManagerHint".to_string(), b"secret".to_vec());
        h.clip.local_copy(SelectionKind::Clipboard, o);
        // sensitive: not broadcast (existing behavior) and not mirrored
        assert_no_broadcast(&mut h).await;
        assert_eq!(h.clip.write_count(), 0);
        assert_eq!(h.clip.get(SelectionKind::Selection), None);
    }

    #[tokio::test(start_paused = true)]
    async fn clearing_a_selection_does_not_wipe_the_partner() {
        let mut cfg = Config::for_test("s");
        cfg.link_selections = LinkSelections::CLIPBOARD_TO_SELECTION;
        let mut h = start(cfg).await;
        // put something in selection first (no reverse mirror, so it stays)
        h.clip.local_copy(SelectionKind::Selection, offer("keep"));
        assert_no_broadcast(&mut h).await;
        // now "clear" the clipboard (empty offer)
        h.clip.local_copy(SelectionKind::Clipboard, Offer::new());
        assert_no_broadcast(&mut h).await;
        assert_eq!(h.clip.write_count(), 0);
        assert_eq!(h.clip.get(SelectionKind::Selection), Some(offer("keep")));
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_read_does_not_poison_the_bridge() {
        let mut cfg = Config::for_test("s");
        cfg.link_selections = LinkSelections::CLIPBOARD_TO_SELECTION;
        let mut h = start(cfg).await;
        h.clip.set_fail_reads(true);
        h.clip.local_copy(SelectionKind::Clipboard, offer("foo"));
        assert_no_broadcast(&mut h).await; // both reads bail
        assert_eq!(h.clip.write_count(), 0);
        // reads recover; the same content now bridges (the guard wasn't poisoned)
        h.clip.set_fail_reads(false);
        h.clip.local_copy(SelectionKind::Clipboard, offer("foo"));
        let (kind, _, o) = recv_clip(&mut h).await;
        assert_eq!((kind, o), (SelectionKind::Clipboard, offer("foo")));
        wait_applied(&h, SelectionKind::Selection, &offer("foo")).await;
    }

    #[tokio::test(start_paused = true)]
    async fn restored_content_is_not_spontaneously_bridged() {
        let mut cfg = Config::for_test("s");
        cfg.link_selections = LinkSelections::CLIPBOARD_TO_SELECTION;
        // Restart over an existing clipboard: the backend reports it as
        // `Initial`, which is restored content and not a user action — so it
        // must not reach the mesh, and the bridge must not mirror it into the
        // partner selection.
        let mut h = start_seeded(cfg, offer("restored")).await;
        assert_no_broadcast(&mut h).await;
        assert_eq!(h.clip.write_count(), 0, "restored content was written");
        assert_eq!(h.clip.get(SelectionKind::Selection), None);
    }

    #[tokio::test(start_paused = true)]
    async fn restored_selection_is_not_spontaneously_bridged() {
        // The selection→clipboard symmetric case: this is the only test that
        // exercises watched_kinds()'s selection_to_clip branch (SELECTION watched
        // for the bridge while sync_selection is off).
        let mut cfg = Config::for_test("s");
        cfg.link_selections = LinkSelections::SELECTION_TO_CLIPBOARD;
        // restart over an existing selection; restored, so it must not mirror
        // into the clipboard
        let mut h = start_seeded_with(cfg, &[(SelectionKind::Selection, offer("restored"))]).await;
        assert_no_broadcast(&mut h).await;
        assert_eq!(h.clip.write_count(), 0, "restored content was written");
        assert_eq!(h.clip.get(SelectionKind::Clipboard), None);
    }

    #[tokio::test(start_paused = true)]
    async fn recopy_remirrors_after_partner_drifts_out_of_band() {
        // clipboard_to_selection, sync_selection off: SELECTION is unwatched, so it
        // can change without the engine ever seeing it. Re-copying the SAME
        // clipboard content must still re-establish the mirror — the bridge
        // reconciles against SELECTION's actual content, not a stale write memo.
        let mut cfg = Config::for_test("s");
        cfg.link_selections = LinkSelections::CLIPBOARD_TO_SELECTION;
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("foo"));
        let (kind, _, o) = recv_clip(&mut h).await;
        assert_eq!((kind, o), (SelectionKind::Clipboard, offer("foo")));
        wait_applied(&h, SelectionKind::Selection, &offer("foo")).await;
        // SELECTION drifts out of band (seed = no watcher event in this mode).
        h.clip.seed(SelectionKind::Selection, offer("bar"));
        // Re-copy identical clipboard bytes: echo-suppressed on the mesh...
        h.clip.local_copy(SelectionKind::Clipboard, offer("foo"));
        assert_no_broadcast(&mut h).await;
        // ...but re-mirrored locally, because SELECTION no longer holds it.
        wait_applied(&h, SelectionKind::Selection, &offer("foo")).await;
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_clip_is_not_re_bridged_or_re_broadcast() {
        // link_selections is a purely local coupling: content received from a
        // peer must NOT be re-mirrored into the partner selection nor
        // re-broadcast to the mesh under this node's own origin (which would
        // amplify traffic O(peers) and re-attribute the update).
        let mut cfg = Config::for_test("s");
        cfg.sync_selection = true;
        cfg.link_selections = LinkSelections::CLIPBOARD_TO_SELECTION;
        let mut h = start(cfg).await;
        send_inbound(&h, SelectionKind::Clipboard, offer("foo")).await;
        wait_applied(&h, SelectionKind::Clipboard, &offer("foo")).await;
        assert_no_broadcast(&mut h).await; // not re-broadcast
        assert_eq!(h.clip.get(SelectionKind::Selection), None); // not bridged
        assert_eq!(h.clip.write_count(), 1); // only the inbound apply itself
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_clip_is_not_re_bridged_in_both_mode() {
        // `both` arms BOTH bridge directions, so the inbound one-shot guard is
        // keyed on only one selection while both are live — verify received
        // content on either selection is still neither bridged nor re-broadcast.
        let mut cfg = Config::for_test("s");
        cfg.sync_selection = true;
        cfg.link_selections = LinkSelections::BOTH;
        let mut h = start(cfg).await;
        // inbound CLIPBOARD must not bridge into SELECTION
        send_inbound(&h, SelectionKind::Clipboard, offer("foo")).await;
        wait_applied(&h, SelectionKind::Clipboard, &offer("foo")).await;
        assert_no_broadcast(&mut h).await;
        assert_eq!(h.clip.get(SelectionKind::Selection), None);
        assert_eq!(h.clip.write_count(), 1);
        // inbound SELECTION must not bridge into CLIPBOARD (which keeps "foo")
        send_inbound(&h, SelectionKind::Selection, offer("bar")).await;
        wait_applied(&h, SelectionKind::Selection, &offer("bar")).await;
        assert_no_broadcast(&mut h).await;
        assert_eq!(h.clip.get(SelectionKind::Clipboard), Some(offer("foo")));
        assert_eq!(h.clip.write_count(), 2); // only the two inbound applies
    }

    #[tokio::test(start_paused = true)]
    async fn recopy_remirrors_after_clipboard_drifts_out_of_band() {
        // The selection→clipboard mirror axis of recopy_remirrors_...: here the
        // CLIPBOARD is the partner and drifts out of band; re-selecting the
        // same selection content must re-establish the mirror.
        let mut cfg = Config::for_test("s");
        cfg.link_selections = LinkSelections::SELECTION_TO_CLIPBOARD;
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Selection, offer("foo"));
        let (kind, _, o) = recv_clip(&mut h).await; // lands in (synced) clipboard
        assert_eq!((kind, o), (SelectionKind::Clipboard, offer("foo")));
        wait_applied(&h, SelectionKind::Clipboard, &offer("foo")).await;
        h.clip.seed(SelectionKind::Clipboard, offer("bar")); // out-of-band drift
        h.clip.local_copy(SelectionKind::Selection, offer("foo"));
        wait_applied(&h, SelectionKind::Clipboard, &offer("foo")).await; // re-mirrored
    }

    #[tokio::test(start_paused = true)]
    async fn no_redundant_mirror_when_partner_already_matches() {
        // The reconcile's termination guard: when the partner already holds the
        // source content, a re-copy must not issue another write.
        let mut cfg = Config::for_test("s");
        cfg.link_selections = LinkSelections::CLIPBOARD_TO_SELECTION;
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("foo"));
        let _ = recv_clip(&mut h).await;
        wait_applied(&h, SelectionKind::Selection, &offer("foo")).await;
        assert_eq!(h.clip.write_count(), 1);
        h.clip.local_copy(SelectionKind::Clipboard, offer("foo")); // identical re-copy
        assert_no_broadcast(&mut h).await;
        assert_eq!(h.clip.write_count(), 1); // partner already matches: no write
    }

    #[tokio::test(start_paused = true)]
    async fn mirrored_selection_is_fed_to_the_mesh_when_synced() {
        let mut cfg = Config::for_test("s");
        cfg.sync_selection = true;
        cfg.link_selections = LinkSelections::CLIPBOARD_TO_SELECTION;
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("foo"));
        let (k1, _, o1) = recv_clip(&mut h).await;
        assert_eq!((k1, o1), (SelectionKind::Clipboard, offer("foo")));
        let (k2, _, o2) = recv_clip(&mut h).await;
        assert_eq!((k2, o2), (SelectionKind::Selection, offer("foo")));
        assert_no_broadcast(&mut h).await;
    }

    #[tokio::test(start_paused = true)]
    async fn bridge_runs_locally_under_receive_only_without_broadcasting() {
        let mut cfg = Config::for_test("s");
        cfg.direction = Direction::ReceiveOnly;
        cfg.sync_selection = true;
        cfg.link_selections = LinkSelections::BOTH;
        let mut h = start(cfg).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("foo"));
        wait_applied(&h, SelectionKind::Selection, &offer("foo")).await; // local mirror
        assert_no_broadcast(&mut h).await; // receive_only never broadcasts
        assert_eq!(h.clip.write_count(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn link_off_never_mirrors() {
        let mut h = start(Config::for_test("s")).await; // link_selections defaults Off
        h.clip.local_copy(SelectionKind::Clipboard, offer("foo"));
        let (kind, _, o) = recv_clip(&mut h).await;
        assert_eq!((kind, o), (SelectionKind::Clipboard, offer("foo")));
        assert_no_broadcast(&mut h).await;
        assert_eq!(h.clip.write_count(), 0);
        assert_eq!(h.clip.get(SelectionKind::Selection), None);
    }

    #[tokio::test(start_paused = true)]
    async fn same_window_conflict_keeps_each_direct_change() {
        let mut cfg = Config::for_test("s");
        cfg.debounce_ms = 100;
        cfg.sync_selection = true;
        cfg.link_selections = LinkSelections::BOTH;
        let mut h = start(cfg).await;
        // Both selections are changed *directly* by the user within one debounce
        // window. A direct change outranks the mirror (last-writer-wins), so
        // neither clobbers the other: each selection keeps — and broadcasts — its
        // own content, instead of the first-seen change overwriting the second.
        h.clip.local_copy(SelectionKind::Clipboard, offer("clip"));
        h.clip.local_copy(SelectionKind::Selection, offer("prim"));
        let (k1, _, o1) = recv_clip(&mut h).await;
        assert_eq!((k1, o1), (SelectionKind::Clipboard, offer("clip")));
        let (k2, _, o2) = recv_clip(&mut h).await;
        assert_eq!((k2, o2), (SelectionKind::Selection, offer("prim")));
        assert_no_broadcast(&mut h).await;
        assert_eq!(h.clip.get(SelectionKind::Clipboard), Some(offer("clip")));
        assert_eq!(h.clip.get(SelectionKind::Selection), Some(offer("prim")));
        assert_eq!(
            h.clip.write_count(),
            0,
            "neither mirror may clobber a concurrent direct change"
        );
    }

    #[tokio::test]
    async fn ctrl_c_into_stale_selection_writes_each_selection_once() {
        // CLIPBOARD copy with clipboard_to_selection + take_ownership, while the
        // SELECTION still holds older content. The SELECTION must end owning the new
        // content, but via a SINGLE owned write — not a raw mirror write followed by
        // an ownership rewrite. Two writes total (own CLIPBOARD, own SELECTION).
        let mut cfg = Config::for_test("s");
        cfg.take_ownership = true;
        cfg.link_selections = LinkSelections::CLIPBOARD_TO_SELECTION;
        let mut h = start_seeded_with(cfg, &[(SelectionKind::Selection, offer("old"))]).await;
        h.clip.local_copy(SelectionKind::Clipboard, offer("new"));
        let (kind, _, o) = recv_clip(&mut h).await;
        assert_eq!((kind, o), (SelectionKind::Clipboard, offer("new")));
        wait_applied(&h, SelectionKind::Selection, &offer("new")).await;
        assert_no_broadcast(&mut h).await;
        assert_eq!(h.clip.get(SelectionKind::Clipboard), Some(offer("new")));
        assert_eq!(
            h.clip.write_count(),
            2,
            "one owned write per selection — mirror and ownership merged"
        );
    }

    // ---- plan_batch (pure) ----
    // The plan is payload-free, so these assert on selections alone: `direct(k)`
    // is k propagating its own content, `mirror(t, s)` is t filled from s.

    const CB: SelectionKind = SelectionKind::Clipboard;
    const SEL: SelectionKind = SelectionKind::Selection;

    fn direct(kind: SelectionKind) -> Action {
        Action::direct(kind)
    }

    fn mirror(target: SelectionKind, source: SelectionKind) -> Action {
        Action { target, source }
    }

    #[test]
    fn plan_copy_on_select_owns_both_with_no_mirror() {
        // Both selections genuinely changed: no mirror (direct change wins on the
        // partner), two unconditional ownership writes, each from its own read.
        let plan = plan_batch(&[CB, SEL], LinkSelections::CLIPBOARD_TO_SELECTION, true);
        assert_eq!(
            plan.writes,
            vec![
                (direct(CB), Provenance::Own),
                (direct(SEL), Provenance::Own),
            ]
        );
        assert_eq!(plan.broadcasts, vec![direct(CB), direct(SEL)]);
    }

    #[test]
    fn plan_ctrl_c_stale_merges_mirror_into_one_owned_write() {
        // Only CLIPBOARD changed; SELECTION is a mirror target. With ownership on it
        // becomes a single Own write of SELECTION — not a mirror write plus a later
        // ownership write — filled from CLIPBOARD's read. SELECTION is still
        // broadcast (mirror target).
        let plan = plan_batch(&[CB], LinkSelections::CLIPBOARD_TO_SELECTION, true);
        assert_eq!(
            plan.writes,
            vec![
                (direct(CB), Provenance::Own),
                (mirror(SEL, CB), Provenance::Own),
            ]
        );
        assert_eq!(plan.broadcasts, vec![direct(CB), mirror(SEL, CB)]);
    }

    #[test]
    fn plan_clobber_skips_mirror_when_partner_is_a_concurrent_change() {
        // CLIPBOARD and SELECTION both genuine in one batch: the CLIPBOARD->SELECTION
        // mirror is skipped so SELECTION keeps its own content. Ownership off => no
        // writes at all.
        let plan = plan_batch(&[CB, SEL], LinkSelections::CLIPBOARD_TO_SELECTION, false);
        assert!(plan.writes.is_empty());
        assert_eq!(plan.broadcasts, vec![direct(CB), direct(SEL)]);
    }

    #[test]
    fn plan_mirror_only_when_ownership_off() {
        // CLIPBOARD changed, ownership off: SELECTION mirror target gets a reconciled
        // Mirror write; CLIPBOARD itself is broadcast only (the user put it there).
        let plan = plan_batch(&[CB], LinkSelections::CLIPBOARD_TO_SELECTION, false);
        assert_eq!(plan.writes, vec![(mirror(SEL, CB), Provenance::Mirror)]);
    }

    #[test]
    fn plan_no_link_broadcasts_without_writing() {
        let plan = plan_batch(&[CB], LinkSelections::OFF, false);
        assert!(plan.writes.is_empty());
        assert_eq!(plan.broadcasts, vec![direct(CB)]);
    }

    #[test]
    fn plan_selection_to_clipboard_mirrors_the_other_way() {
        let plan = plan_batch(&[SEL], LinkSelections::SELECTION_TO_CLIPBOARD, false);
        assert_eq!(plan.writes, vec![(mirror(CB, SEL), Provenance::Mirror)]);
        assert_eq!(plan.broadcasts, vec![direct(SEL), mirror(CB, SEL)]);
    }

    #[test]
    fn plan_never_writes_a_selection_twice() {
        // The "each selection at most once" invariant, over every config: a target
        // appearing twice would mean two writes racing for the same selection.
        for link in [
            LinkSelections::OFF,
            LinkSelections::CLIPBOARD_TO_SELECTION,
            LinkSelections::SELECTION_TO_CLIPBOARD,
            LinkSelections::BOTH,
        ] {
            for own in [false, true] {
                for changed in [vec![CB], vec![SEL], vec![CB, SEL], vec![SEL, CB]] {
                    let plan = plan_batch(&changed, link, own);
                    let mut targets: Vec<_> = plan.writes.iter().map(|(a, _)| a.target).collect();
                    let before = targets.len();
                    targets.sort_by_key(|k| format!("{k:?}"));
                    targets.dedup();
                    assert_eq!(
                        targets.len(),
                        before,
                        "duplicate write target for {link:?}, own={own}, changed={changed:?}"
                    );
                    // A plan may only ever draw content from a genuine change.
                    for (a, _) in &plan.writes {
                        assert!(changed.contains(&a.source), "write source not a change");
                    }
                    for a in &plan.broadcasts {
                        assert!(changed.contains(&a.source), "broadcast source not a change");
                    }
                }
            }
        }
    }
}
