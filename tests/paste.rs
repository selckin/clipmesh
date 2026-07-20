//! End-to-end tests for the `wl-paste` impersonation mode: `fetch_offer` pulls
//! the current clipboard from an in-process node over the real Noise handshake +
//! resync-on-connect path, using the mock clipboard (no Wayland needed).

mod common;

use clipmesh::clipboard::mock::MockClipboard;
use clipmesh::config::Config;
use clipmesh::node::NodeHandle;
use clipmesh::paste::{fetch_from_any, fetch_offer};
use clipmesh::protocol::{Offer, SelectionKind};
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
        timeout,
    )
    .await
}

/// Retry `fetch` until the node has recorded the copy and resyncs it.
/// Avoids a connect-before-record race: each attempt is a fresh connect, and the
/// node pushes the content on whichever connect lands after it recorded it.
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
async fn paste_times_out_when_the_node_does_not_resync() {
    let mut cfg = Config::for_test("noresync");
    cfg.resync_on_connect = false;
    let clip = MockClipboard::new();
    let node = start(cfg.clone(), clip.clone()).await;

    clip.local_copy(SelectionKind::Clipboard, offer("present but not pushed"));
    sleep(Duration::from_millis(200)).await; // let the node record it

    // a short timeout on purpose: this fetch is expected to expire
    let short = Duration::from_secs(1);
    let err = fetch(&node, &cfg, SelectionKind::Clipboard, short)
        .await
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("within"),
        "expected a timeout error, got: {err:#}"
    );
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
async fn paste_primary_times_out_when_the_node_does_not_sync_selection() {
    // Default config has sync_selection = false, so the node resyncs only the
    // CLIPBOARD on connect. A --primary paste must discard that wrong-kind Clip
    // and time out rather than returning the clipboard as if it were the
    // selection. Guards fetch_offer's `Some(_) => continue` discrimination.
    let cfg = Config::for_test("primary-nosync");
    let clip = MockClipboard::new();
    let node = start(cfg.clone(), clip.clone()).await;

    clip.local_copy(SelectionKind::Clipboard, offer("clipboard content"));
    clip.local_copy(SelectionKind::Selection, offer("selection content"));
    sleep(Duration::from_millis(200)).await; // let the node record both

    // a short timeout on purpose: this fetch is expected to expire
    let short = Duration::from_secs(1);
    let err = fetch(&node, &cfg, SelectionKind::Selection, short)
        .await
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("within"),
        "expected a timeout (the node never resyncs SELECTION), got: {err:#}"
    );
}

#[tokio::test]
async fn paste_skips_a_rules_message_and_returns_the_clip() {
    // With share_mime_rules on (and a real rules file), the node pushes a
    // Message::Rules before the Clip on connect. fetch_offer must skip it and
    // still return the clipboard.
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
async fn paste_skips_the_unwanted_kind_and_returns_the_requested_one() {
    // sync_selection on: the node pushes CLIPBOARD first then SELECTION on
    // connect. A --primary paste must skip the CLIPBOARD Clip that arrives
    // first and return the SELECTION — not whichever Clip lands first.
    let mut cfg = Config::for_test("both-synced");
    cfg.sync_selection = true;
    let clip = MockClipboard::new();
    let node = start(cfg.clone(), clip.clone()).await;

    clip.local_copy(SelectionKind::Clipboard, offer("the clipboard"));
    clip.local_copy(SelectionKind::Selection, offer("the selection"));

    let got = fetch_eventually(&node, &cfg, SelectionKind::Selection).await;
    assert_eq!(got, offer("the selection"));
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
        Duration::from_secs(1),
    )
    .await
    .unwrap_err();
    assert!(
        format!("{err:#}").contains("couldn't reach"),
        "got: {err:#}"
    );
}
