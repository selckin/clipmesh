//! End-to-end tests for `clipmesh history`: a one-shot client asks an
//! in-process node over the real Noise handshake and the `History`/
//! `HistoryReply` exchange, using the mock clipboard (no Wayland needed).

mod common;

use clipmesh::clipboard::mock::MockClipboard;
use clipmesh::config::Config;
use clipmesh::node::NodeHandle;
use clipmesh::protocol::{
    encode, HistoryEntry, HistoryMiss, HistoryRequest, HistoryResult, Message, Offer, SelectionKind,
};
use common::{offer, peered, start, wait_applied, wait_for};
use std::sync::Arc;
use std::time::Duration;

const ASK_TIMEOUT: Duration = Duration::from_secs(5);

/// One history request against an in-process node, taking the address, psk and
/// payload cap from the node and its config — everything the CLI derives
/// mechanically.
async fn ask(node: &NodeHandle, cfg: &Config, req: HistoryRequest) -> HistoryResult {
    clipmesh::client::ask(
        &node.local_addr.to_string(),
        cfg.psk,
        cfg.max_payload_size,
        Message::History { req },
        ASK_TIMEOUT,
        "history",
        |msg| match msg {
            Message::HistoryReply { result } => Some(result),
            _ => None,
        },
    )
    .await
    .expect("the node did not answer the history request")
}

async fn list(node: &NodeHandle, cfg: &Config) -> Result<Vec<HistoryEntry>, HistoryMiss> {
    match ask(node, cfg, HistoryRequest::List).await {
        HistoryResult::List(entries) => Ok(entries),
        HistoryResult::Failed(miss) => Err(miss),
        other => panic!("a list request was answered with {other:?}"),
    }
}

/// The full id of the entry previewing as `text`, once the node has remembered
/// it. A copy is detected, debounced and recorded asynchronously, so every test
/// that seeds one waits here rather than guessing at a sleep.
async fn id_of(node: &NodeHandle, cfg: &Config, text: &str) -> String {
    let mut found = None;
    wait_for(&format!("{text:?} to be remembered"), || {
        found = futures_lite_block(list(node, cfg))
            .unwrap_or_default()
            .into_iter()
            .find(|e| e.preview.as_deref() == Some(text));
        found.is_some()
    })
    .await;
    hex(&found.expect("the wait returned without an entry").hash)
}

/// Run a future to completion from inside a sync predicate.
///
/// `wait_for` takes a synchronous closure (it is shared with every other
/// integration test, where the condition really is synchronous), and a history
/// request is not. Blocking the current thread is safe here only because these
/// tests run on the multi-threaded runtime, where the node's tasks keep running
/// on other workers.
fn futures_lite_block<T>(fut: impl std::future::Future<Output = T>) -> T {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(fut))
}

fn hex(hash: &[u8; 32]) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

fn image(bytes: usize) -> Offer {
    [("image/png".to_string(), vec![0x41u8; bytes])]
        .into_iter()
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn history_lists_what_a_node_has_settled_on() {
    let cfg = Config::for_test("s");
    let clip = MockClipboard::new();
    let node = start(cfg.clone(), clip.clone()).await;

    clip.local_copy(SelectionKind::Clipboard, offer("first"));
    id_of(&node, &cfg, "first").await;
    clip.local_copy(SelectionKind::Clipboard, offer("second"));
    id_of(&node, &cfg, "second").await;

    let entries = list(&node, &cfg).await.unwrap();
    let previews: Vec<&str> = entries
        .iter()
        .map(|e| e.preview.as_deref().unwrap_or(""))
        .collect();
    assert_eq!(previews, ["second", "first"], "newest first");
    assert_eq!(entries[0].types, vec![("text/plain".to_string(), 6)]);
    assert_eq!(entries[0].kind, SelectionKind::Clipboard);
}

/// The reason a listing carries summaries and not offers, measured on the wire
/// rather than asserted as an intention: fifty remembered images must not cost
/// fifty images to enumerate.
#[tokio::test(flavor = "multi_thread")]
async fn a_listing_transfers_no_payloads() {
    const BIG: usize = 512 * 1024;
    let cfg = Config::for_test("s");
    let clip = MockClipboard::new();
    let node = start(cfg.clone(), clip.clone()).await;

    clip.local_copy(SelectionKind::Clipboard, image(BIG));
    wait_for("the image to be remembered", || {
        futures_lite_block(list(&node, &cfg)).is_ok()
    })
    .await;

    let result = ask(&node, &cfg, HistoryRequest::List).await;
    let HistoryResult::List(entries) = &result else {
        panic!("expected a listing, got {result:?}");
    };
    assert_eq!(entries[0].bytes, BIG as u64, "the row must report the size");
    assert_eq!(entries[0].preview, None, "an image has no text preview");
    let on_the_wire = encode(&Message::HistoryReply {
        result: result.clone(),
    })
    .len();
    assert!(
        on_the_wire < 4096,
        "a listing of one 512 KiB image cost {on_the_wire} bytes on the wire"
    );
}

/// `history get -t` transfers the one representation asked for, not the whole
/// entry beside it.
#[tokio::test(flavor = "multi_thread")]
async fn getting_an_entry_narrows_the_transfer_to_one_type() {
    const BIG: usize = 512 * 1024;
    let cfg = Config::for_test("s");
    let clip = MockClipboard::new();
    let node = start(cfg.clone(), clip.clone()).await;

    let mut rich = offer("the text");
    rich.extend(image(BIG));
    clip.local_copy(SelectionKind::Clipboard, rich);
    let id = id_of(&node, &cfg, "the text").await;

    let result = ask(
        &node,
        &cfg,
        HistoryRequest::Get {
            id: id[..8].to_string(),
            type_: Some("text/plain".into()),
        },
    )
    .await;
    assert_eq!(result, HistoryResult::Offer(offer("the text")));
    let on_the_wire = encode(&Message::HistoryReply { result }).len();
    assert!(
        on_the_wire < 4096,
        "a narrowed get dragged the image along ({on_the_wire} bytes)"
    );
}

/// The end-to-end proof that restoring is copying: it lands on the node that was
/// asked, and from there it reaches the rest of the mesh like any other copy.
#[tokio::test(flavor = "multi_thread")]
async fn restoring_over_the_wire_makes_a_peer_follow() {
    let clip_a = MockClipboard::new();
    let cfg_a = Config::for_test("s");
    let node_a = start(cfg_a.clone(), clip_a.clone()).await;

    let clip_b = MockClipboard::new();
    let node_b = start(peered("s", &[&node_a]), clip_b.clone()).await;
    let _ = &node_b;

    clip_a.local_copy(SelectionKind::Clipboard, offer("wanted"));
    let id = id_of(&node_a, &cfg_a, "wanted").await;
    wait_applied(
        "B to follow the first copy",
        &clip_b,
        SelectionKind::Clipboard,
        &offer("wanted"),
    )
    .await;

    clip_a.local_copy(SelectionKind::Clipboard, offer("newer"));
    wait_applied(
        "B to follow the second copy",
        &clip_b,
        SelectionKind::Clipboard,
        &offer("newer"),
    )
    .await;

    assert_eq!(
        ask(
            &node_a,
            &cfg_a,
            HistoryRequest::Restore {
                id: id[..8].to_string()
            }
        )
        .await,
        HistoryResult::Restored {
            kind: SelectionKind::Clipboard,
            broadcast: true
        }
    );
    wait_applied(
        "A's own clipboard",
        &clip_a,
        SelectionKind::Clipboard,
        &offer("wanted"),
    )
    .await;
    wait_applied(
        "B to follow the restore",
        &clip_b,
        SelectionKind::Clipboard,
        &offer("wanted"),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn restoring_by_an_ambiguous_prefix_is_an_error_not_a_guess() {
    let cfg = Config::for_test("s");
    let clip = MockClipboard::new();
    let node = start(cfg.clone(), clip.clone()).await;

    clip.local_copy(SelectionKind::Clipboard, offer("one"));
    id_of(&node, &cfg, "one").await;
    clip.local_copy(SelectionKind::Clipboard, offer("two"));
    id_of(&node, &cfg, "two").await;

    // The empty prefix matches everything — nothing typed at all.
    assert_eq!(
        ask(&node, &cfg, HistoryRequest::Restore { id: String::new() }).await,
        HistoryResult::Failed(HistoryMiss::Ambiguous { matches: 2 })
    );
    assert_eq!(
        ask(
            &node,
            &cfg,
            HistoryRequest::Restore {
                id: "ffffffffffffffff".into()
            }
        )
        .await,
        HistoryResult::Failed(HistoryMiss::NoSuchEntry)
    );
    // Neither guess touched the clipboard.
    assert_eq!(
        clip.get(SelectionKind::Clipboard).as_ref(),
        Some(&offer("two"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_node_with_the_history_off_says_so_rather_than_looking_empty() {
    let cfg = Config {
        history_entries: 0,
        ..Config::for_test("s")
    };
    let clip = MockClipboard::new();
    let node = start(cfg.clone(), clip.clone()).await;
    clip.local_copy(SelectionKind::Clipboard, offer("not kept"));

    assert_eq!(list(&node, &cfg).await, Err(HistoryMiss::Disabled));
}

// Silence the unused-import warning in builds where a helper is only used by
// some of the tests above.
#[allow(dead_code)]
fn _uses(_: Arc<MockClipboard>) {}
