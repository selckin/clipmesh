//! Shared scaffolding for the integration-test crates.
//!
//! Each `tests/*.rs` file is its own crate and compiles this module separately,
//! so anything only one of them uses looks dead to the other — hence the
//! blanket allow.
#![allow(dead_code)]

use clipmesh::clipboard::mock::MockClipboard;
use clipmesh::config::Config;
use clipmesh::node::{spawn_node, NodeHandle};
use clipmesh::protocol::Offer;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{sleep, timeout};

/// A single-representation `text/plain` offer — the usual payload under test.
pub fn offer(text: &str) -> Offer {
    [("text/plain".to_string(), text.as_bytes().to_vec())]
        .into_iter()
        .collect()
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

/// Poll `cond` until it holds, panicking with `what` if it never does.
pub async fn wait_for(mut cond: impl FnMut() -> bool, what: &str) {
    timeout(Duration::from_secs(10), async {
        while !cond() {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

/// Reserve a free port by binding and dropping (small reuse race, fine for tests).
pub fn reserve_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}
