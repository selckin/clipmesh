//! End-to-end tests for the `wl-paste` impersonation mode: `fetch_offer` asks an
//! in-process node for its clipboard over the real Noise handshake and the
//! `Get`/`GetReply` exchange, using the mock clipboard (no Wayland needed).

mod common;

use clipmesh::clipboard::mock::MockClipboard;
use clipmesh::config::Config;
use clipmesh::node::NodeHandle;
use clipmesh::paste::{fetch_from_any, fetch_offer};
use clipmesh::protocol::{GetWant, Offer, SelectionKind};
use common::{offer, start};
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
    timeout: Duration,
) -> anyhow::Result<Offer> {
    fetch_offer(
        &node.local_addr.to_string(),
        cfg.psk,
        cfg.max_payload_size,
        kind,
        GetWant::All,
        timeout,
    )
    .await
}

/// Retry `fetch` until the node's clipboard actually holds the copy.
/// Avoids a connect-before-copy race: each attempt is a fresh connect, and the
/// node reads live when it answers.
async fn fetch_eventually(node: &NodeHandle, cfg: &Config, kind: SelectionKind) -> Offer {
    timeout(Duration::from_secs(10), async {
        loop {
            match fetch(node, cfg, kind, Duration::from_millis(500)).await {
                Ok(o) => break o,
                Err(_) => sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await
    .expect("fetch_offer never returned content")
}

#[tokio::test]
async fn paste_pulls_the_current_clipboard_from_a_node() {
    let cfg = Config::for_test("paste-secret");
    let clip = MockClipboard::new();
    let node = start(cfg.clone(), clip.clone()).await;

    clip.local_copy(SelectionKind::Clipboard, offer("from the mesh"));

    let got = fetch_eventually(&node, &cfg, SelectionKind::Clipboard).await;
    assert_eq!(got, offer("from the mesh"));
}

#[tokio::test]
async fn paste_pulls_the_selection_when_the_node_syncs_it() {
    let mut cfg = Config::for_test("sel-secret");
    cfg.sync_selection = true;
    let clip = MockClipboard::new();
    let node = start(cfg.clone(), clip.clone()).await;

    clip.local_copy(SelectionKind::Selection, offer("middle click"));

    let got = fetch_eventually(&node, &cfg, SelectionKind::Selection).await;
    assert_eq!(got, offer("middle click"));
}

#[tokio::test]
async fn paste_works_when_the_node_does_not_resync_on_connect() {
    // `resync_on_connect` governs what a node PUSHES to a rejoining peer. Paste
    // asks a direct question, so it is answered either way — under the previous
    // scrape-the-push design this configuration made the node unpasteable, and
    // the client could only report a timeout.
    let mut cfg = Config::for_test("noresync");
    cfg.resync_on_connect = false;
    let clip = MockClipboard::new();
    let node = start(cfg.clone(), clip.clone()).await;

    clip.local_copy(SelectionKind::Clipboard, offer("answered on request"));

    let got = fetch_eventually(&node, &cfg, SelectionKind::Clipboard).await;
    assert_eq!(got, offer("answered on request"));
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
    sleep(Duration::from_millis(200)).await; // let the node record both

    let started = std::time::Instant::now();
    let err = fetch(
        &node,
        &cfg,
        SelectionKind::Selection,
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

#[tokio::test]
async fn paste_works_against_a_node_that_shares_mime_rules() {
    // share_mime_rules on (with a real rules file) must not disturb a paste.
    // A paster fires no connect event, so it no longer receives the rules push
    // at all — this pins that the rules-sharing path stays out of its way.
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_test("rules-first");
    cfg.share_mime_rules = true;
    cfg.mime_rules_path = Some(dir.path().join("mimetypes"));
    let clip = MockClipboard::new();
    let node = start(cfg.clone(), clip.clone()).await;

    clip.local_copy(SelectionKind::Clipboard, offer("after the rules"));

    let got = fetch_eventually(&node, &cfg, SelectionKind::Clipboard).await;
    assert_eq!(got, offer("after the rules"));
}

#[tokio::test]
async fn paste_returns_the_requested_kind_when_both_are_synced() {
    // Both selections hold different content and both are synced, so answering
    // with the wrong one would be easy to do and easy to miss. A --primary paste
    // must come back with the SELECTION.
    let mut cfg = Config::for_test("both-synced");
    cfg.sync_selection = true;
    let clip = MockClipboard::new();
    let node = start(cfg.clone(), clip.clone()).await;

    clip.local_copy(SelectionKind::Clipboard, offer("the clipboard"));
    clip.local_copy(SelectionKind::Selection, offer("the selection"));

    let got = fetch_eventually(&node, &cfg, SelectionKind::Selection).await;
    assert_eq!(got, offer("the selection"));
}

/// `fetch` narrowed to a specific request shape.
async fn fetch_narrowed(node: &NodeHandle, cfg: &Config, narrow: GetWant) -> anyhow::Result<Offer> {
    fetch_offer(
        &node.local_addr.to_string(),
        cfg.psk,
        cfg.max_payload_size,
        SelectionKind::Clipboard,
        narrow,
        Duration::from_secs(5),
    )
    .await
}

/// A multi-representation clipboard: a small text rep and a deliberately large
/// binary one, so "did the node send the whole offer?" is measurable.
fn text_and_big_image() -> Offer {
    let mut o = offer("just the text");
    o.insert("image/png".to_string(), vec![0u8; 512 * 1024]);
    o
}

#[tokio::test]
async fn asking_for_one_type_transfers_only_that_representation() {
    // The point of asking rather than scraping a push: `-t text/plain` against a
    // clipboard holding a large image must not drag the image over the wire too.
    let mut cfg = Config::for_test("narrow");
    cfg.unknown_mime = clipmesh::config::MimePolicy::Allow;
    let clip = MockClipboard::new();
    let node = start(cfg.clone(), clip.clone()).await;
    clip.local_copy(SelectionKind::Clipboard, text_and_big_image());
    sleep(Duration::from_millis(200)).await;

    let got = fetch_narrowed(&node, &cfg, GetWant::One("text/plain".to_string()))
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
    let mut cfg = Config::for_test("missing-type");
    cfg.unknown_mime = clipmesh::config::MimePolicy::Allow;
    let clip = MockClipboard::new();
    let node = start(cfg.clone(), clip.clone()).await;
    clip.local_copy(SelectionKind::Clipboard, offer("only text here"));
    sleep(Duration::from_millis(200)).await;

    let err = fetch_narrowed(&node, &cfg, GetWant::One("image/png".to_string()))
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
    let mut cfg = Config::for_test("list-types");
    cfg.unknown_mime = clipmesh::config::MimePolicy::Allow;
    let clip = MockClipboard::new();
    let node = start(cfg.clone(), clip.clone()).await;
    clip.local_copy(SelectionKind::Clipboard, text_and_big_image());
    sleep(Duration::from_millis(200)).await;

    let got = fetch_narrowed(&node, &cfg, GetWant::TypesOnly)
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
    let cfg = Config::for_test("empty");
    let clip = MockClipboard::new();
    let node = start(cfg.clone(), clip.clone()).await;

    let started = std::time::Instant::now();
    let err = fetch(
        &node,
        &cfg,
        SelectionKind::Clipboard,
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
    sleep(Duration::from_millis(200)).await; // let the node record it

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
