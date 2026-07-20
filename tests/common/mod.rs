//! Shared scaffolding for the integration-test crates.
//!
//! Each `tests/*.rs` file is its own crate and compiles this module separately,
//! so anything only one of them uses looks dead to the other — hence the
//! blanket allow.
#![allow(dead_code)]

use clipmesh::clipboard::mock::MockClipboard;
use clipmesh::config::Config;
use clipmesh::node::{spawn_node, NodeHandle};
use clipmesh::protocol::{Offer, SelectionKind};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{sleep, timeout};

/// A single-representation `text/plain` offer — the usual payload under test.
pub fn offer(text: &str) -> Offer {
    [("text/plain".to_string(), text.as_bytes().to_vec())]
        .into_iter()
        .collect()
}

/// A test config that dials the given already-started nodes.
pub fn peered(secret: &str, peers: &[&NodeHandle]) -> Config {
    Config {
        peers: peers.iter().map(|p| p.local_addr.to_string()).collect(),
        ..Config::for_test(secret)
    }
}

/// Start a node and wait until its engine has subscribed to the clipboard.
/// Returning earlier lets an immediate `local_copy` fire into the void.
pub async fn start(cfg: Config, clip: Arc<MockClipboard>) -> NodeHandle {
    let node = spawn_node(Arc::new(cfg), clip.clone())
        .await
        .expect("node failed to start");
    while clip.watcher_count() == 0 {
        tokio::task::yield_now().await;
    }
    node
}

/// Poll `cond` until it holds, panicking with `label` if it never does.
///
/// Argument order deliberately mirrors `protocol::test_support::wait_for`, the
/// unit-test crate's copy. The two cannot share code — a `tests/` crate sees
/// only clipmesh's public API — so the next best thing is that a test moved
/// between them either compiles or doesn't, rather than silently transposing
/// its arguments. The timings differ on purpose: an integration test waits on a
/// real socket and a real mesh, so it polls less often and for longer than a
/// unit test waiting on an in-process engine.
pub async fn wait_for(label: &str, mut cond: impl FnMut() -> bool) {
    timeout(Duration::from_secs(10), async {
        while !cond() {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {label}"));
}

/// Poll until `clip`'s `kind` selection holds exactly `want`.
pub async fn wait_applied(
    label: &str,
    clip: &Arc<MockClipboard>,
    kind: SelectionKind,
    want: &Offer,
) {
    let clip = clip.clone();
    let want = want.clone();
    wait_for(label, move || clip.get(kind).as_ref() == Some(&want)).await;
}

/// Reserve a free port by binding and dropping (small reuse race, fine for tests).
pub fn reserve_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}
