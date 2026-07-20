//! `wl-paste` impersonation mode: pull the current clipboard from a clipmesh
//! node over the encrypted mesh protocol and print it to stdout — for hosts
//! with no Wayland compositor (or scripts) that want the mesh's clipboard.
//!
//! The client dials a node with `peer::run_connection`, announcing itself as
//! [`PeerRole::Paster`], and **asks**: `Message::Get`, answered with `GetReply`.
//! Because it is a request, the node can narrow the reply to what the invocation
//! needs ([`GetWant`]) and name the reason when it has nothing to give
//! ([`GetResult`]) instead of leaving the client to time out.
//!
//! A node only serves a selection it is configured to send, so `receive_only`
//! refuses and `--primary` needs the target's `sync_selection`. `resync_on_connect`
//! is NOT a prerequisite: it governs what a node pushes to a rejoining peer, not
//! whether it answers a question.
//!
//! The spec (`docs/superpowers/specs/2026-06-21-wl-paste-mode-design.md`)
//! describes the original push-scraping design and is superseded on that point.

use crate::config::{self, Config};
use crate::mesh::Mesh;
use crate::peer;
use crate::protocol::{self, GetResult, GetWant, Message, Offer, PeerRole, SelectionKind};
use anyhow::{anyhow, bail, Context, Result};
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use uuid::Uuid;

/// How long to wait for the node's answer (connect + handshake + transfer)
/// before giving up. Generous so a large clipboard over a slow link isn't
/// mistaken for an unreachable node — a *misconfigured* one now answers with a
/// reason rather than going quiet, so this bound is only about slowness.
const PASTE_TIMEOUT: Duration = Duration::from_secs(10);

/// Parsed `wl-paste`-style arguments for paste mode. `list` takes precedence
/// over `type_`/`no_newline` (matching `wl-paste -l`), so some field
/// combinations are inert rather than illegal.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PasteArgs {
    /// Which selection to pull — CLIPBOARD by default, SELECTION with `-p`.
    kind: SelectionKind,
    /// Print this exact MIME type (`-t`/`--type`); `None` auto-selects.
    type_: Option<String>,
    /// List the offered types instead of printing content (`-l`/`--list-types`).
    list: bool,
    /// Suppress the trailing newline for text types (`-n`/`--no-newline`).
    no_newline: bool,
    /// Node to pull from (`--node`); `None` races every configured peer.
    node: Option<String>,
    /// Config file (`--config`); `None` uses the default path.
    config: Option<PathBuf>,
}

impl PasteArgs {
    /// Parse a `wl-paste`-style argument list (a practical subset, plus the
    /// `--node`/`--config` extensions). Rejects `--watch` and unknown flags
    /// rather than mis-parsing them.
    fn parse(args: &[String]) -> Result<PasteArgs> {
        let mut out = PasteArgs {
            kind: SelectionKind::Clipboard,
            type_: None,
            list: false,
            no_newline: false,
            node: None,
            config: None,
        };
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            let mut value = |flag: &str| {
                it.next()
                    .cloned()
                    .with_context(|| format!("{flag} needs a value"))
            };
            match arg.as_str() {
                "-t" | "--type" => out.type_ = Some(value(arg)?),
                "-l" | "--list-types" => out.list = true,
                "-n" | "--no-newline" => out.no_newline = true,
                "-p" | "--primary" => out.kind = SelectionKind::Selection,
                "--node" => out.node = Some(value(arg)?),
                "--config" => out.config = Some(PathBuf::from(value(arg)?)),
                "-w" | "--watch" => {
                    bail!(
                        "{arg} is not supported by clipmesh's wl-paste mode (one-shot paste only)"
                    )
                }
                other => bail!("unknown paste flag: {other}"),
            }
        }
        Ok(out)
    }
}

/// Whether a MIME type is textual (gets a trailing newline by default).
fn is_text(mime: &str) -> bool {
    mime.get(..5)
        .is_some_and(|p| p.eq_ignore_ascii_case("text/"))
}

/// Pick the MIME type to print. With an explicit request, require an exact
/// (case-insensitive) match. Otherwise prefer `text/plain;charset=utf-8`, then
/// `text/plain`, then the first `text/*`, then the first offered type.
fn select_type<'a>(requested: Option<&str>, offer: &'a Offer) -> Result<&'a str> {
    let find = |want: &str| {
        offer
            .keys()
            .map(String::as_str)
            .find(|k| protocol::type_matches(k, want))
    };
    if let Some(req) = requested {
        return find(req).ok_or_else(|| {
            anyhow!(
                "type {req:?} is not offered (available: {})",
                list_available(offer.keys().map(String::as_str))
            )
        });
    }
    find("text/plain;charset=utf-8")
        .or_else(|| find("text/plain"))
        .or_else(|| offer.keys().map(String::as_str).find(|k| is_text(k)))
        .or_else(|| offer.keys().next().map(String::as_str))
        .ok_or_else(|| anyhow!("the clipboard is empty"))
}

/// A comma-separated list of offered types, for error messages.
///
/// Takes names rather than an `Offer` so the two "that type isn't offered"
/// errors a user can hit — one raised locally by `select_type`, one relayed from
/// the node as [`GetResult::NotOffered`] — render identically instead of
/// drifting apart.
fn list_available<'a>(types: impl IntoIterator<Item = &'a str>) -> String {
    let names: Vec<&str> = types.into_iter().collect();
    if names.is_empty() {
        return "none".to_string();
    }
    names.join(", ")
}

/// The offered types, one per line in advertise order, newline-terminated.
fn list_types(offer: &Offer) -> String {
    let mut s = String::new();
    for k in offer.keys() {
        s.push_str(k);
        s.push('\n');
    }
    s
}

/// The bytes to emit for `mime`: the representation's data, with a trailing
/// newline appended for `text/*` types unless `no_newline`. Binary-safe.
fn render(mut data: Vec<u8>, mime: &str, no_newline: bool) -> Vec<u8> {
    if !no_newline && is_text(mime) {
        data.push(b'\n');
    }
    data
}

/// The node addresses to try: just `--node` if given (config port applied to a
/// bare host), else **every** configured peer (already port-resolved by
/// `Config`). The default races them and uses the first that responds, so a
/// headless host needn't know which of its desktops is up.
fn resolve_targets(pa: &PasteArgs, cfg: &Config) -> Result<Vec<String>> {
    if let Some(node) = &pa.node {
        return Ok(vec![config::with_default_port(node, &cfg.port.to_string())]);
    }
    if cfg.peers.is_empty() {
        bail!("no node to paste from: pass --node <host[:port]> or list a peer in the config");
    }
    Ok(cfg.peers.clone())
}

/// Connect to `addr` as a one-shot paste client, ask it for `want`, and return
/// what it answers.
///
/// This is a *request*, not a scrape. The connection is announced as
/// [`PeerRole::Paster`], so the node registers it only to reply: it fires no
/// connect event, spends no resync (a rules snapshot plus a live capture of
/// every synced selection) on a client that will never sync, and never
/// broadcasts to it. `narrow` also lets the node send back only the
/// representation actually wanted.
///
/// Reuses the full peer connection stack (`peer::run_connection`), so the Noise
/// handshake, version check and framing are identical to a mesh link.
pub async fn fetch_offer(
    addr: &str,
    psk: [u8; 32],
    max_payload: usize,
    want: SelectionKind,
    narrow: GetWant,
    timeout: Duration,
) -> Result<Offer> {
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

    // Exit the select loop with the error to surface; a reply returns early from
    // inside it.
    let err: anyhow::Error = loop {
        tokio::select! {
            _ = &mut deadline => break anyhow!(
                "no reply from {addr} within {timeout:?} — it may still be transferring a \
                 large clipboard over a slow link"
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
                let frame = protocol::encode_frame(
                    &Message::Get { kind: want, want: narrow.clone() },
                );
                mesh.send_frame_to(node, &frame);
            }
            msg = inbound_rx.recv() => match msg {
                Some((_from, Message::GetReply { kind, result })) if kind == want => {
                    return interpret(result, addr, want);
                }
                // A reply about the other selection, or anything else: keep waiting.
                Some(_) => continue,
                None => break anyhow!("connection to {addr} closed unexpectedly"),
            },
        }
    };
    Err(err)
}

/// Turn a node's answer into an offer or a specific error.
///
/// Each failure names its own cause, which is the point of asking rather than
/// waiting for a push: the old design could only ever time out, and had to list
/// four unrelated possible reasons in one message.
fn interpret(result: GetResult, addr: &str, want: SelectionKind) -> Result<Offer> {
    match result {
        GetResult::Offer(o) => Ok(o),
        GetResult::Types(types) => Ok(types.into_iter().map(|t| (t, Vec::new())).collect()),
        GetResult::Empty => bail!("the {want:?} clipboard on {addr} is empty"),
        GetResult::NotOffered { available } => bail!(
            "that type is not offered by {addr} (available: {})",
            list_available(available.iter().map(String::as_str))
        ),
        GetResult::NotSynced => bail!(
            "{addr} does not serve its {want:?} selection — it is configured \
             receive-only, or (for --primary) without sync_selection"
        ),
    }
}

/// Race `fetch_offer` across every target concurrently and return the offer from
/// the first node that yields one. Unreachable, timed-out, or wrongly-configured
/// nodes are tolerated as long as one succeeds; if all fail, the last error is
/// reported. A single target is fetched directly so its exact error surfaces.
pub async fn fetch_from_any(
    targets: Vec<String>,
    psk: [u8; 32],
    max_payload: usize,
    want: SelectionKind,
    narrow: GetWant,
    timeout: Duration,
) -> Result<Offer> {
    if let [addr] = targets.as_slice() {
        return fetch_offer(addr, psk, max_payload, want, narrow, timeout).await;
    }
    let mut set = tokio::task::JoinSet::new();
    for addr in targets.clone() {
        // psk/max_payload/want/timeout are Copy; addr and narrow are cloned per task.
        let narrow = narrow.clone();
        set.spawn(async move { fetch_offer(&addr, psk, max_payload, want, narrow, timeout).await });
    }
    let mut last_err: Option<anyhow::Error> = None;
    // First success wins; dropping `set` on return aborts the remaining fetches.
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(Ok(offer)) => return Ok(offer),
            Ok(Err(e)) => last_err = Some(e),
            Err(join_err) => last_err = Some(anyhow!("paste task failed: {join_err}")),
        }
    }
    Err(last_err
        .unwrap_or_else(|| anyhow!("no nodes to paste from"))
        .context(format!(
            "couldn't paste from any of {} nodes",
            targets.len()
        )))
}

/// The bytes paste mode writes to stdout for a fetched offer: either the type
/// listing (`-l`) or the selected representation (rendered with the newline
/// rule). Kept pure so the output decision is testable without a node or stdout.
fn output_bytes(pa: &PasteArgs, mut offer: Offer) -> Result<Vec<u8>> {
    if pa.list {
        return Ok(list_types(&offer).into_bytes());
    }
    // Take the chosen representation out of the offer rather than copying it:
    // the offer is dropped immediately after, and a rep can be max_payload_size
    // large. `select_type` borrows from `offer`, so settle on the key first.
    let mime = select_type(pa.type_.as_deref(), &offer)?.to_string();
    let data = offer
        .swap_remove(&mime)
        .ok_or_else(|| anyhow!("selected type {mime:?} is unexpectedly absent from the offer"))?;
    Ok(render(data, &mime, pa.no_newline))
}

/// Write `bytes` to stdout, treating a downstream-closed pipe (e.g. `… | head`)
/// as a clean stop rather than an error — matching `wl-paste`/`cat`. Other write
/// failures (out of space, …) still propagate.
fn write_stdout(bytes: &[u8]) -> Result<()> {
    let mut out = std::io::stdout().lock();
    match out.write_all(bytes).and_then(|()| out.flush()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(e) => Err(e).context("writing to stdout"),
    }
}

/// How much of the offer this invocation actually needs, so the node can send
/// only that. `-l` needs names but no bytes; `-t` needs exactly one
/// representation; the default picks by preference order and so must see them
/// all.
fn narrowing(pa: &PasteArgs) -> GetWant {
    if pa.list {
        return GetWant::TypesOnly;
    }
    match &pa.type_ {
        Some(t) => GetWant::One(t.clone()),
        None => GetWant::All,
    }
}

/// Entry point for paste mode: parse args, load config, pull from a node, and
/// write the selected representation to stdout.
pub async fn run(args: Vec<String>) -> Result<()> {
    let pa = PasteArgs::parse(&args)?;
    let config_path = pa
        .config
        .clone()
        .unwrap_or_else(config::default_config_path);
    let cfg = Config::load(&config_path)?;
    let targets = resolve_targets(&pa, &cfg)?;
    let offer = fetch_from_any(
        targets,
        cfg.psk,
        cfg.max_payload_size,
        pa.kind,
        narrowing(&pa),
        PASTE_TIMEOUT,
    )
    .await?;
    write_stdout(&output_bytes(&pa, offer)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::test_support::offer;

    // ---- select_type ----

    #[test]
    fn select_type_prefers_utf8_text_plain() {
        let o = offer(&[
            ("text/html", b"<b>"),
            ("text/plain", b"x"),
            ("text/plain;charset=utf-8", b"y"),
        ]);
        assert_eq!(select_type(None, &o).unwrap(), "text/plain;charset=utf-8");
    }

    #[test]
    fn select_type_falls_back_plain_then_text_then_first() {
        // text/plain when there's no charset=utf-8 variant
        let o = offer(&[("text/html", b"<b>"), ("text/plain", b"x")]);
        assert_eq!(select_type(None, &o).unwrap(), "text/plain");
        // first text/* when there's no text/plain at all
        let o = offer(&[("image/png", b"\x89"), ("text/html", b"<b>")]);
        assert_eq!(select_type(None, &o).unwrap(), "text/html");
        // first offered type when nothing is textual
        let o = offer(&[("image/png", b"\x89"), ("application/pdf", b"%PDF")]);
        assert_eq!(select_type(None, &o).unwrap(), "image/png");
    }

    #[test]
    fn select_type_honours_an_explicit_request_case_insensitively() {
        let o = offer(&[("text/plain", b"x"), ("image/PNG", b"\x89")]);
        assert_eq!(select_type(Some("image/png"), &o).unwrap(), "image/PNG");
    }

    #[test]
    fn select_type_errors_when_requested_type_absent() {
        let o = offer(&[("text/plain", b"x")]);
        let err = select_type(Some("image/png"), &o).unwrap_err();
        assert!(format!("{err:#}").contains("not offered"), "got: {err:#}");
    }

    #[test]
    fn select_type_errors_on_empty_offer() {
        assert!(select_type(None, &Offer::new()).is_err());
    }

    // ---- list_types ----

    #[test]
    fn list_types_lists_keys_in_advertise_order() {
        let o = offer(&[("text/html", b"<b>"), ("text/plain", b"x")]);
        assert_eq!(list_types(&o), "text/html\ntext/plain\n");
    }

    // ---- render ----

    #[test]
    fn render_appends_newline_for_text_by_default() {
        assert_eq!(render(b"hi".to_vec(), "text/plain", false), b"hi\n");
        assert_eq!(
            render(b"hi".to_vec(), "text/plain;charset=utf-8", false),
            b"hi\n"
        );
    }

    #[test]
    fn render_suppresses_newline_for_text_with_no_newline() {
        assert_eq!(render(b"hi".to_vec(), "text/plain", true), b"hi");
    }

    #[test]
    fn render_never_appends_newline_for_binary() {
        let png = vec![0x89, b'P', b'N', b'G'];
        assert_eq!(render(png.clone(), "image/png", false), png);
    }

    #[test]
    fn render_is_binary_safe() {
        let data = vec![0u8, 0xff, 0x00, 0x80];
        assert_eq!(
            render(data.clone(), "application/octet-stream", false),
            data
        );
    }

    // ---- PasteArgs::parse ----

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_defaults_to_clipboard_and_auto_type() {
        let a = PasteArgs::parse(&[]).unwrap();
        assert_eq!(a.kind, SelectionKind::Clipboard);
        assert_eq!(a.type_, None);
        assert!(!a.list);
        assert!(!a.no_newline);
        assert_eq!(a.node, None);
        assert_eq!(a.config, None);
    }

    #[test]
    fn parse_maps_short_flags() {
        let a = PasteArgs::parse(&args(&[
            "-p",
            "-l",
            "-n",
            "-t",
            "image/png",
            "--node",
            "host:9",
            "--config",
            "/c.toml",
        ]))
        .unwrap();
        assert_eq!(a.kind, SelectionKind::Selection);
        assert!(a.list);
        assert!(a.no_newline);
        assert_eq!(a.type_.as_deref(), Some("image/png"));
        assert_eq!(a.node.as_deref(), Some("host:9"));
        assert_eq!(a.config, Some(PathBuf::from("/c.toml")));
    }

    #[test]
    fn parse_maps_long_flags() {
        let a = PasteArgs::parse(&args(&[
            "--primary",
            "--list-types",
            "--no-newline",
            "--type",
            "text/plain",
        ]))
        .unwrap();
        assert_eq!(a.kind, SelectionKind::Selection);
        assert!(a.list);
        assert!(a.no_newline);
        assert_eq!(a.type_.as_deref(), Some("text/plain"));
    }

    #[test]
    fn parse_rejects_watch() {
        let err = PasteArgs::parse(&args(&["--watch"])).unwrap_err();
        assert!(format!("{err:#}").contains("not supported"), "got: {err:#}");
        assert!(PasteArgs::parse(&args(&["-w"])).is_err());
    }

    #[test]
    fn parse_rejects_unknown_flag() {
        assert!(PasteArgs::parse(&args(&["--bogus"])).is_err());
    }

    #[test]
    fn parse_errors_on_a_missing_flag_value() {
        assert!(PasteArgs::parse(&args(&["-t"])).is_err());
        assert!(PasteArgs::parse(&args(&["--node"])).is_err());
    }

    // ---- resolve_targets ----

    fn cfg_with(peers_and_port: &str) -> Config {
        Config::from_toml(&format!(
            "listen = \"0.0.0.0\"\nport = 48100\npsk = \"s\"\n{peers_and_port}"
        ))
        .unwrap()
    }

    fn paste_args_node(node: Option<&str>) -> PasteArgs {
        PasteArgs {
            kind: SelectionKind::Clipboard,
            type_: None,
            list: false,
            no_newline: false,
            node: node.map(|s| s.to_string()),
            config: None,
        }
    }

    #[test]
    fn resolve_targets_uses_only_node_and_applies_the_config_port() {
        let cfg = cfg_with("peers = [\"desktop\", \"laptop\"]\n");
        // --node wins (peers ignored); a bare host gets the configured port
        assert_eq!(
            resolve_targets(&paste_args_node(Some("box")), &cfg).unwrap(),
            vec!["box:48100"]
        );
        // an explicit port on --node is kept
        assert_eq!(
            resolve_targets(&paste_args_node(Some("box:7000")), &cfg).unwrap(),
            vec!["box:7000"]
        );
    }

    #[test]
    fn resolve_targets_defaults_to_every_peer() {
        let cfg = cfg_with("peers = [\"desktop\", \"laptop:9\"]\n");
        assert_eq!(
            resolve_targets(&paste_args_node(None), &cfg).unwrap(),
            // peers are already port-resolved by Config
            vec!["desktop:48100", "laptop:9"]
        );
    }

    #[test]
    fn resolve_targets_errors_without_node_or_peers() {
        let cfg = cfg_with("");
        assert!(resolve_targets(&paste_args_node(None), &cfg).is_err());
    }

    // ---- output_bytes ----

    fn paste_args(type_: Option<&str>, list: bool, no_newline: bool) -> PasteArgs {
        PasteArgs {
            kind: SelectionKind::Clipboard,
            type_: type_.map(|s| s.to_string()),
            list,
            no_newline,
            node: None,
            config: None,
        }
    }

    #[test]
    fn output_bytes_lists_types_with_l() {
        let o = offer(&[("text/html", b"<b>"), ("text/plain", b"x")]);
        let pa = paste_args(None, true, false);
        assert_eq!(output_bytes(&pa, o).unwrap(), b"text/html\ntext/plain\n");
    }

    #[test]
    fn output_bytes_auto_selects_and_appends_newline() {
        let o = offer(&[("image/png", b"\x89"), ("text/plain", b"hi")]);
        let pa = paste_args(None, false, false);
        assert_eq!(output_bytes(&pa, o).unwrap(), b"hi\n");
    }

    #[test]
    fn output_bytes_explicit_binary_type_is_verbatim() {
        let png = vec![0x89u8, b'P', b'N', b'G'];
        let o: Offer = [("image/png".to_string(), png.clone())]
            .into_iter()
            .collect();
        let pa = paste_args(Some("image/png"), false, false);
        assert_eq!(output_bytes(&pa, o).unwrap(), png);
    }

    #[test]
    fn output_bytes_errors_when_requested_type_absent() {
        let o = offer(&[("text/plain", b"x")]);
        let pa = paste_args(Some("image/png"), false, false);
        assert!(output_bytes(&pa, o).is_err());
    }
}
