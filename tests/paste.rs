//! End-to-end tests for the `wl-paste` impersonation mode: `fetch_offer` asks an
//! in-process node for its clipboard over the real Noise handshake and the
//! `Get`/`GetReply` exchange, using the mock clipboard (no Wayland needed).

mod common;

use clipmesh::clipboard::mock::MockClipboard;
use clipmesh::config::{Config, MimePolicy};
use clipmesh::node::NodeHandle;
use clipmesh::paste::{fetch_from_any, fetch_offer};
use clipmesh::protocol::{GetWant, Offer, SelectionKind};
use common::{offer, start};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{sleep, timeout};

/// One `fetch_offer` against an in-process node, taking the address, psk and
/// payload cap from the node and its own config — everything a paste call site
/// derives mechanically. Tests that need a *different* psk call `fetch_offer`
/// directly, so the difference stays visible where it matters.
async fn fetch(
    node: &NodeHandle,
    cfg: &Config,
    kind: SelectionKind,
    narrow: GetWant,
    timeout: Duration,
) -> anyhow::Result<Offer> {
    fetch_offer(
        &node.local_addr.to_string(),
        cfg.psk,
        cfg.max_payload_size,
        kind,
        narrow,
        timeout,
    )
    .await
}

/// Retry `fetch` until the node answers with content.
///
/// This is the barrier for every test that seeds a copy: each attempt is a
/// fresh connect and the node reads live when it answers, so a success proves
/// the node is serving that copy *now*. A fixed sleep only guesses at the same
/// thing — slower than needed when the node is ready, and too short under load,
/// which is the connect-before-copy race this exists to remove.
async fn fetch_eventually(
    node: &NodeHandle,
    cfg: &Config,
    kind: SelectionKind,
    narrow: GetWant,
) -> Offer {
    timeout(Duration::from_secs(10), async {
        loop {
            match fetch(node, cfg, kind, narrow.clone(), Duration::from_millis(500)).await {
                Ok(o) => break o,
                Err(_) => sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await
    .expect("fetch_offer never returned content")
}

/// Start a node with `cfg`, copy each seed into its selection, then assert that
/// pasting `kind` comes back with `want`.
///
/// The config and the seeds stay at the call site: the one config field under
/// test, and which selections hold what, are the whole of what distinguishes
/// these tests from one another.
async fn assert_pastes(
    cfg: Config,
    seeds: &[(SelectionKind, &str)],
    kind: SelectionKind,
    want: &str,
) {
    let clip = MockClipboard::new();
    let node = start(cfg.clone(), clip.clone()).await;

    for (seeded, text) in seeds {
        clip.local_copy(*seeded, offer(text));
    }

    let got = fetch_eventually(&node, &cfg, kind, GetWant::All).await;
    assert_eq!(got, offer(want));
}

#[tokio::test]
async fn paste_pulls_the_current_clipboard_from_a_node() {
    assert_pastes(
        Config::for_test("paste-secret"),
        &[(SelectionKind::Clipboard, "from the mesh")],
        SelectionKind::Clipboard,
        "from the mesh",
    )
    .await;
}

#[tokio::test]
async fn paste_pulls_the_selection_when_the_node_syncs_it() {
    let mut cfg = Config::for_test("sel-secret");
    cfg.sync_selection = true;
    assert_pastes(
        cfg,
        &[(SelectionKind::Selection, "middle click")],
        SelectionKind::Selection,
        "middle click",
    )
    .await;
}

#[tokio::test]
async fn paste_works_when_the_node_does_not_resync_on_connect() {
    // `resync_on_connect` governs what a node PUSHES to a rejoining peer. Paste
    // asks a direct question, so it is answered either way — under the previous
    // scrape-the-push design this configuration made the node unpasteable, and
    // the client could only report a timeout.
    let mut cfg = Config::for_test("noresync");
    cfg.resync_on_connect = false;
    assert_pastes(
        cfg,
        &[(SelectionKind::Clipboard, "answered on request")],
        SelectionKind::Clipboard,
        "answered on request",
    )
    .await;
}

#[tokio::test]
async fn paste_works_against_a_node_that_shares_mime_rules() {
    // share_mime_rules on (with a real rules file) must not disturb a paste.
    // A paster fires no connect event, so it no longer receives the rules push
    // at all — this pins that the rules-sharing path stays out of its way.
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_test("rules-first");
    cfg.share_mime_rules = true;
    cfg.mime_rules_path = Some(dir.path().join("mimetypes"));
    assert_pastes(
        cfg,
        &[(SelectionKind::Clipboard, "after the rules")],
        SelectionKind::Clipboard,
        "after the rules",
    )
    .await;
}

#[tokio::test]
async fn paste_returns_the_requested_kind_when_both_are_synced() {
    // Both selections hold different content and both are synced, so answering
    // with the wrong one would be easy to do and easy to miss. A --primary paste
    // must come back with the SELECTION.
    let mut cfg = Config::for_test("both-synced");
    cfg.sync_selection = true;
    assert_pastes(
        cfg,
        &[
            (SelectionKind::Clipboard, "the clipboard"),
            (SelectionKind::Selection, "the selection"),
        ],
        SelectionKind::Selection,
        "the selection",
    )
    .await;
}

#[tokio::test]
async fn paste_with_the_wrong_psk_fails_fast_with_a_connection_error() {
    let cfg = Config::for_test("right-secret");
    let clip = MockClipboard::new();
    let node = start(cfg.clone(), clip.clone()).await;
    clip.local_copy(SelectionKind::Clipboard, offer("secret"));

    let wrong_psk = Config::for_test("wrong-secret").psk;
    let started = std::time::Instant::now();
    // spelled out rather than via `fetch`: the whole point is a psk that is
    // *not* the node's, plus a timeout long enough to prove we fail before it
    let err = fetch_offer(
        &node.local_addr.to_string(),
        wrong_psk,
        cfg.max_payload_size,
        SelectionKind::Clipboard,
        GetWant::All,
        Duration::from_secs(5),
    )
    .await
    .unwrap_err();
    let msg = format!("{err:#}");
    // a real connection failure, surfaced from the connection task — not the
    // bare timeout path (which would say "within …" and take the full 5s)
    assert!(msg.contains("connecting to"), "got: {msg}");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "wrong PSK should fail fast, not via the timeout: {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn paste_primary_is_refused_by_name_when_the_node_does_not_sync_selection() {
    // Default config has sync_selection = false. The node must say so rather
    // than stay silent: the old push-scraping design could only time out, and
    // had to guess at four possible causes in one message.
    let cfg = Config::for_test("primary-nosync");
    let clip = MockClipboard::new();
    let node = start(cfg.clone(), clip.clone()).await;

    clip.local_copy(SelectionKind::Clipboard, offer("clipboard content"));
    clip.local_copy(SelectionKind::Selection, offer("selection content"));
    // Wait until the node provably serves its CLIPBOARD. The refusal below is
    // config-driven and would arrive even from a node holding nothing, so
    // without this the last assertion — that it did not answer with the
    // clipboard instead — could pass simply because there was no clipboard yet.
    fetch_eventually(&node, &cfg, SelectionKind::Clipboard, GetWant::All).await;

    let started = std::time::Instant::now();
    let err = fetch(
        &node,
        &cfg,
        SelectionKind::Selection,
        GetWant::All,
        Duration::from_secs(5),
    )
    .await
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("does not serve") && msg.contains("sync_selection"),
        "expected a named refusal, got: {msg}"
    );
    assert!(
        !msg.contains("within") && started.elapsed() < Duration::from_secs(3),
        "the node answered, so this must not be a timeout: {msg}"
    );
    // ...and it must not have answered with the CLIPBOARD instead.
    assert!(!msg.contains("clipboard content"), "got: {msg}");
}

/// A multi-representation clipboard: a small text rep and a deliberately large
/// binary one, so "did the node send the whole offer?" is measurable.
fn text_and_big_image() -> Offer {
    let mut o = offer("just the text");
    o.insert("image/png".to_string(), vec![0u8; 512 * 1024]);
    o
}

/// A started node whose CLIPBOARD holds `seed` and is **provably serving it** —
/// the precondition every narrowing test needs before it can ask a question
/// whose answer depends on the content being there (otherwise a narrowed ask
/// comes back `Empty`, i.e. a different answer than the one under test).
///
/// `unknown_mime = Allow` so a test can seed a type the shipped rules say
/// nothing about without first writing a rules file.
async fn node_holding(secret: &str, seed: Offer) -> (NodeHandle, Config, Arc<MockClipboard>) {
    let mut cfg = Config::for_test(secret);
    cfg.unknown_mime = MimePolicy::Allow;
    let clip = MockClipboard::new();
    let node = start(cfg.clone(), clip.clone()).await;
    clip.local_copy(SelectionKind::Clipboard, seed);
    fetch_eventually(&node, &cfg, SelectionKind::Clipboard, GetWant::All).await;
    (node, cfg, clip)
}

#[tokio::test]
async fn listing_types_reads_no_representation_contents() {
    // Narrowing must reach the BACKEND, not just the wire: on Wayland a content
    // read costs one connection and one pipe read per representation, so
    // answering `-l` by reading everything would pull a 30 MB image off the
    // compositor to print a list of names.
    //
    // `MockClipboard::block_reads` gates content reads but not `list_types`, so
    // a node that can still answer here provably never read a representation.
    let (node, cfg, clip) = node_holding("list-no-read", text_and_big_image()).await;
    // The one place a sleep has to stay. `block_reads` gates the ENGINE's reads
    // too, and the engine answers `Get` from the same task that captures a local
    // copy — so blocking while its capture read is still pending stalls that
    // task for the whole read timeout and fails the `-l` below for the wrong
    // reason. "The engine has finished capturing" is not observable from out
    // here (nothing is written, and serving reads live), so there is nothing to
    // poll for; settling time is the only expression of it available.
    sleep(Duration::from_millis(200)).await;
    clip.block_reads(); // any content read from here on would hang

    let got = timeout(
        Duration::from_secs(3),
        fetch(
            &node,
            &cfg,
            SelectionKind::Clipboard,
            GetWant::TypesOnly,
            Duration::from_secs(5),
        ),
    )
    .await
    .expect("--list-types must not need a content read")
    .unwrap();
    assert!(got.contains_key("text/plain") && got.contains_key("image/png"));
}

#[tokio::test]
async fn answering_a_paste_does_not_record_types_into_the_rules_file() {
    // A query is not a capture. `Stages::BROADCAST`'s Record stage appends
    // unseen types, persists the rules file and broadcasts it mesh-wide — so
    // serving a paste through it would let any paster make this node rewrite its
    // rules and push them to every peer. Serving uses `Stages::SERVE` instead.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimetypes");
    let mut cfg = Config::for_test("no-record");
    cfg.unknown_mime = MimePolicy::Allow;
    cfg.mime_rules_path = Some(path.clone());
    let clip = MockClipboard::new();
    let node = start(cfg.clone(), clip.clone()).await;

    // Seed a type the shipped defaults say nothing about, WITHOUT a local copy
    // (which would legitimately record it via the capture path).
    let probe: Offer = [("application/x-paste-probe".to_string(), b"hi".to_vec())]
        .into_iter()
        .collect();
    clip.seed(SelectionKind::Clipboard, probe);
    let before = std::fs::read_to_string(&path).unwrap_or_default();

    let got = fetch(
        &node,
        &cfg,
        SelectionKind::Clipboard,
        GetWant::All,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert!(got.contains_key("application/x-paste-probe"));

    let after = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(
        before, after,
        "serving a paste rewrote the rules file; a query must not record types"
    );
}

#[tokio::test]
async fn asking_for_one_type_transfers_only_that_representation() {
    // The point of asking rather than scraping a push: `-t text/plain` against a
    // clipboard holding a large image must not drag the image over the wire too.
    let (node, cfg, _clip) = node_holding("narrow", text_and_big_image()).await;

    let got = fetch(
        &node,
        &cfg,
        SelectionKind::Clipboard,
        GetWant::One("text/plain".to_string()),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(
        got.keys().collect::<Vec<_>>(),
        vec!["text/plain"],
        "the node sent more than the requested representation"
    );
}

#[tokio::test]
async fn asking_for_a_missing_type_names_what_is_available() {
    // `node_holding` has already proved the node serves the text, so an "empty
    // clipboard" answer here would be a real failure rather than a slow start.
    let (node, cfg, _clip) = node_holding("missing-type", offer("only text here")).await;

    let err = fetch(
        &node,
        &cfg,
        SelectionKind::Clipboard,
        GetWant::One("image/png".to_string()),
        Duration::from_secs(5),
    )
    .await
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("not offered") && msg.contains("text/plain"),
        "expected the available types to be named, got: {msg}"
    );
}

#[tokio::test]
async fn listing_types_transfers_names_without_content() {
    let (node, cfg, _clip) = node_holding("list-types", text_and_big_image()).await;

    let got = fetch(
        &node,
        &cfg,
        SelectionKind::Clipboard,
        GetWant::TypesOnly,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert!(
        got.contains_key("text/plain") && got.contains_key("image/png"),
        "expected both type names, got: {:?}",
        got.keys().collect::<Vec<_>>()
    );
    assert!(
        got.values().all(|v| v.is_empty()),
        "--list-types must not pull representation data"
    );
}

#[tokio::test]
async fn an_empty_clipboard_is_reported_as_empty_not_as_a_timeout() {
    // Nothing is ever copied here, so there is nothing to wait for: the node is
    // started (which `start` already synchronises on) and asked straight away.
    let cfg = Config::for_test("empty");
    let clip = MockClipboard::new();
    let node = start(cfg.clone(), clip.clone()).await;

    let started = std::time::Instant::now();
    let err = fetch(
        &node,
        &cfg,
        SelectionKind::Clipboard,
        GetWant::All,
        Duration::from_secs(5),
    )
    .await
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("is empty"), "got: {msg}");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the node answered, so this must not be a timeout"
    );
}

#[tokio::test]
async fn paste_races_peers_and_returns_from_a_reachable_node() {
    // The default (no --node) tries every configured node concurrently and uses
    // the first that responds. One target is dead (nothing listens on :1); the
    // live node must still serve the paste.
    let cfg = Config::for_test("race");
    let clip = MockClipboard::new();
    let node = start(cfg.clone(), clip.clone()).await;
    clip.local_copy(SelectionKind::Clipboard, offer("from the live node"));
    // The live node must already be serving the copy, or "the race picked the
    // dead target" and "the live node had nothing to give yet" look alike.
    fetch_eventually(&node, &cfg, SelectionKind::Clipboard, GetWant::All).await;

    let targets = vec!["127.0.0.1:1".to_string(), node.local_addr.to_string()];
    let got = fetch_from_any(
        targets,
        cfg.psk,
        cfg.max_payload_size,
        SelectionKind::Clipboard,
        GetWant::All,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(got, offer("from the live node"));
}

#[tokio::test]
async fn paste_errors_when_all_nodes_are_unreachable() {
    let err = fetch_from_any(
        vec!["127.0.0.1:1".to_string(), "127.0.0.1:2".to_string()],
        Config::for_test("x").psk,
        1024,
        SelectionKind::Clipboard,
        GetWant::All,
        Duration::from_secs(1),
    )
    .await
    .unwrap_err();
    assert!(
        format!("{err:#}").contains("couldn't paste from any of 2 nodes"),
        "got: {err:#}"
    );
}

#[tokio::test]
async fn paste_reports_an_unreachable_node() {
    // nothing listening here: connect must fail with a clear, named error
    let err = fetch_offer(
        "127.0.0.1:1",
        Config::for_test("x").psk,
        1024,
        SelectionKind::Clipboard,
        GetWant::All,
        Duration::from_secs(1),
    )
    .await
    .unwrap_err();
    assert!(
        format!("{err:#}").contains("couldn't reach"),
        "got: {err:#}"
    );
}
