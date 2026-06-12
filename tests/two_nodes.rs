use clipmesh::clipboard::mock::MockClipboard;
use clipmesh::config::Config;
use clipmesh::node::{spawn_node, NodeHandle};
use clipmesh::protocol::{Offer, SelectionKind};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{sleep, timeout};

fn offer(text: &str) -> Offer {
    [("text/plain".to_string(), text.as_bytes().to_vec())]
        .into_iter()
        .collect()
}

async fn wait_for(mut cond: impl FnMut() -> bool, what: &str) {
    timeout(Duration::from_secs(10), async {
        while !cond() {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

async fn start(cfg: Config, clip: Arc<MockClipboard>) -> NodeHandle {
    let node = spawn_node(Arc::new(cfg), clip.clone())
        .await
        .expect("node failed to start");
    // don't return before the engine is subscribed, or an immediate
    // local_copy can fire into the void
    while clip.watcher_count() == 0 {
        tokio::task::yield_now().await;
    }
    node
}

/// Reserve a free port by binding and dropping (small reuse race, fine for tests).
fn reserve_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

#[tokio::test]
async fn clipboard_syncs_both_ways_without_echo_storms() {
    let clip_a = MockClipboard::new();
    let clip_b = MockClipboard::new();

    let node_a = start(Config::for_test("shared-secret"), clip_a.clone()).await;
    let mut cfg_b = Config::for_test("shared-secret");
    cfg_b.peers = vec![node_a.local_addr.to_string()];
    let node_b = start(cfg_b, clip_b.clone()).await;

    // mesh forms
    let (ma, mb) = (node_a.mesh.clone(), node_b.mesh.clone());
    wait_for(
        move || ma.peer_count() == 1 && mb.peer_count() == 1,
        "mesh to form",
    )
    .await;

    // A -> B
    let o1 = offer("hello from a");
    clip_a.local_copy(SelectionKind::Clipboard, o1.clone());
    let cb = clip_b.clone();
    let expected = o1.clone();
    wait_for(
        move || cb.get(SelectionKind::Clipboard).as_ref() == Some(&expected),
        "A's copy on B",
    )
    .await;
    assert_eq!(clip_b.write_count(), 1);
    assert_eq!(
        clip_a.write_count(),
        0,
        "A must not receive its own copy back"
    );

    // B -> A
    let o2 = offer("hello from b");
    clip_b.local_copy(SelectionKind::Clipboard, o2.clone());
    let ca = clip_a.clone();
    let expected = o2.clone();
    wait_for(
        move || ca.get(SelectionKind::Clipboard).as_ref() == Some(&expected),
        "B's copy on A",
    )
    .await;
    assert_eq!(clip_a.write_count(), 1);

    // quiet period: no echo storm
    sleep(Duration::from_millis(300)).await;
    assert_eq!(clip_a.write_count(), 1);
    assert_eq!(clip_b.write_count(), 1);
}

#[tokio::test]
async fn content_copied_while_peer_offline_resyncs_on_connect() {
    // the sleep/wake scenario: A copies something while B is offline;
    // when B connects it must receive the current state without a new copy
    let clip_a = MockClipboard::new();
    let clip_b = MockClipboard::new();

    let node_a = start(Config::for_test("resync"), clip_a.clone()).await;
    let o = offer("copied while b was away");
    clip_a.local_copy(SelectionKind::Clipboard, o.clone());
    sleep(Duration::from_millis(200)).await; // broadcast goes to nobody

    let mut cfg_b = Config::for_test("resync");
    cfg_b.peers = vec![node_a.local_addr.to_string()];
    start(cfg_b, clip_b.clone()).await;

    let cb = clip_b.clone();
    let expected = o.clone();
    wait_for(
        move || cb.get(SelectionKind::Clipboard).as_ref() == Some(&expected),
        "offline copy to resync onto B",
    )
    .await;
    // and A must not have had anything written back
    assert_eq!(clip_a.write_count(), 0);
}

#[tokio::test]
async fn late_starting_peer_is_eventually_connected() {
    // exercises dial_loop's retry: B dials a peer that doesn't exist yet
    let clip_a = MockClipboard::new();
    let clip_b = MockClipboard::new();
    let port = reserve_port();

    let mut cfg_b = Config::for_test("late");
    cfg_b.peers = vec![format!("127.0.0.1:{port}")];
    let node_b = start(cfg_b, clip_b).await;

    // let several dial attempts fail before the peer appears
    sleep(Duration::from_millis(1500)).await;
    assert_eq!(node_b.mesh.peer_count(), 0);

    let mut cfg_a = Config::for_test("late");
    cfg_a.listen = format!("127.0.0.1:{port}");
    let node_a = start(cfg_a, clip_a).await;

    let (ma, mb) = (node_a.mesh.clone(), node_b.mesh.clone());
    wait_for(
        move || ma.peer_count() == 1 && mb.peer_count() == 1,
        "late peer to connect",
    )
    .await;
}

#[tokio::test]
async fn node_rejects_dialing_itself() {
    let clip = MockClipboard::new();
    // reserve a port, then listen on it and dial it
    let port = reserve_port();
    let mut cfg = Config::for_test("s");
    cfg.listen = format!("127.0.0.1:{port}");
    cfg.peers = vec![format!("127.0.0.1:{port}")];
    let node = start(cfg, clip).await;

    sleep(Duration::from_millis(500)).await;
    assert_eq!(
        node.mesh.peer_count(),
        0,
        "self-connection must not register a peer"
    );
}

#[tokio::test]
async fn wrong_psk_peers_never_form_a_mesh() {
    let clip_a = MockClipboard::new();
    let clip_b = MockClipboard::new();
    let node_a = start(Config::for_test("secret-one"), clip_a).await;
    let mut cfg_b = Config::for_test("secret-two");
    cfg_b.peers = vec![node_a.local_addr.to_string()];
    let node_b = start(cfg_b, clip_b).await;

    sleep(Duration::from_millis(500)).await;
    assert_eq!(node_a.mesh.peer_count(), 0);
    assert_eq!(node_b.mesh.peer_count(), 0);
}
