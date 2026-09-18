//! One-shot mesh request: dial a node as a [`PeerRole::Paster`], ask one
//! question, wait for its answer.
//!
//! Extracted from `paste::fetch_offer`, its only caller until the `history`
//! subcommand needed the identical loop. Duplicating it would have duplicated
//! four decisions that are each easy to get subtly wrong and impossible to
//! notice from the outside: driving the connection **inline** so returning from
//! here tears its reader/writer down, asking only **after** the connect event
//! (the writer is live by then, and the event carries the node ID, so the send
//! is targeted rather than a fan-out that happens to reach one peer), surfacing
//! the **connection's own** error rather than a timeout when it dies early, and
//! ignoring inbound messages that do not answer this question.

use crate::mesh::Mesh;
use crate::peer;
use crate::protocol::{self, Message, PeerRole};
use anyhow::{anyhow, Context, Result};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use uuid::Uuid;

/// Ask `addr` one question and return the matching answer.
///
/// `pick` decides which inbound message *is* the answer — `Some(T)` for the
/// reply this request waits for, `None` for anything else — so "a reply about
/// the other selection" stays the caller's rule rather than a special case in
/// here. `what` names the thing being asked for, for the timeout message.
pub async fn ask<T>(
    addr: &str,
    psk: [u8; 32],
    max_payload: usize,
    request: Message,
    timeout: Duration,
    what: &str,
    pick: impl Fn(Message) -> Option<T>,
) -> Result<T> {
    let stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("couldn't reach clipmesh node {addr}"))?;
    let _ = stream.set_nodelay(true);

    let (inbound_tx, mut inbound_rx) = mpsc::channel(64);
    // The node registers as a peer from our side, so this fires once the hello
    // exchange completes — which is when it is safe to send the request.
    let (connect_tx, mut connect_rx) = mpsc::channel(64);
    let mesh = Mesh::new(Uuid::new_v4(), inbound_tx, connect_tx);

    // Drive the connection inline (not spawned) so returning from this function
    // drops it, and `run_connection`'s AbortGuards tear down its reader/writer.
    // `run_connection` adds its own framing slack on top of `max_payload`.
    let conn = peer::run_connection(
        stream,
        true,
        psk,
        max_payload,
        mesh.clone(),
        PeerRole::Paster,
    );
    tokio::pin!(conn);

    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);

    // Exit the select loop with the error to surface; an answer returns early
    // from inside it.
    let err: anyhow::Error = loop {
        tokio::select! {
            _ = &mut deadline => break anyhow!(
                "no reply from {addr} within {timeout:?} — it may still be transferring a \
                 large {what} over a slow link"
            ),
            // The connection ended before answering: surface its real error
            // (PSK/version mismatch, reset) rather than timing out.
            res = &mut conn => break match res {
                Ok(()) => anyhow!("connection to {addr} closed before answering"),
                Err(e) => e.context(format!("connecting to clipmesh node {addr}")),
            },
            // Registered, so the writer is live: ask. The connect event carries
            // the node's ID, so this is a targeted send — reaching one known
            // connection through a fan-out primitive would work only by
            // accident, and only while `broadcast`'s role filter happens to keep
            // the remote in.
            Some(node) = connect_rx.recv() => {
                mesh.send_frame_to(node, &protocol::encode_frame(&request));
            }
            msg = inbound_rx.recv() => match msg {
                Some((_from, msg)) => match pick(msg) {
                    Some(answer) => return Ok(answer),
                    // Not an answer to this question: keep waiting.
                    None => continue,
                },
                None => break anyhow!("connection to {addr} closed unexpectedly"),
            },
        }
    };
    Err(err)
}
