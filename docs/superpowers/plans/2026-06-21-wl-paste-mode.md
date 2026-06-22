# wl-paste impersonation mode — Implementation Plan

**Goal:** Add a one-shot `clipmesh --paste` mode (also a `wl-paste` symlink) that
pulls the current clipboard from a node over the existing encrypted protocol and
prints the selected MIME representation to stdout — a `wl-paste` drop-in for
hosts with no Wayland compositor.

**Architecture:** A new `src/paste.rs` client reuses `peer::run_connection` to
dial a node as an ephemeral peer and receives the `Clip` the node already pushes
on connect (resync-on-connect), so there is **no wire-format change**. Pure
helpers select the type / format output; `run` wires `Config::load` (PSK +
default target `peers[0]`) and the wl-paste-style args, and writes bytes to
stdout. `main` detects paste mode before its flag loop.

**Tech Stack:** Rust, tokio (`TcpStream`, `mpsc`, `tokio::time::timeout`,
`#[tokio::test]`), reusing `transport`/`peer`/`mesh`/`protocol` as a library.

**Spec:** `docs/superpowers/specs/2026-06-21-wl-paste-mode-design.md`

---

## File structure

| File | Responsibility for this feature |
|------|---------------------------------|
| `src/paste.rs` (new) | `PasteArgs` + parsing; pure `select_type`/`list_types`/`render`; async `fetch_offer` (network pull); async `run` (config + args + stdout). |
| `src/lib.rs` | `pub mod paste;` |
| `src/main.rs` | Detect paste mode (argv[0] == `wl-paste`, or `--paste` present), strip `--paste`, delegate to `paste::run`. |
| `README.md`, `CLAUDE.md` | Document the mode + the two constraints. (`examples/config.toml` is generated and unchanged — no new key.) |

---

## Task 1: Pure output helpers (`select_type`, `list_types`, `render`)

RED: unit tests in `paste.rs`:
- `select_type(None, offer)` prefers `text/plain;charset=utf-8` → `text/plain` →
  first `text/*` → first key.
- `select_type(Some("image/png"), offer)` returns it; `Some(absent)` → `None`/Err.
- `list_types` joins keys in advertise order, newline-terminated.
- `render(bytes, mime, no_newline)`: appends `\n` only for `text/*` and only when
  `!no_newline`; binary verbatim; byte-exact.

GREEN: implement the three pure fns. They take/return owned bytes, no I/O.

## Task 2: Arg parsing (`PasteArgs::parse`)

RED: unit tests:
- `-t/--type`, `-l/--list-types`, `-n/--no-newline`, `-p/--primary`,
  `--node`, `--config` each map to the right field.
- `-w`/`--watch` → Err("not supported").
- unknown flag → Err.
- combined short forms / value-taking flags parse.

GREEN: a small hand-rolled parser returning `PasteArgs { kind, type_, list,
no_newline, node, config }` (consistent with the existing hand-rolled arg loop
in `main.rs` — no clap dependency).

## Task 3: Network pull (`fetch_offer`)

RED: integration test in `tests/` (new `tests/paste.rs`, `MockClipboard`):
- start a node, `local_copy` a CLIPBOARD offer, `fetch_offer(addr, psk, max,
  Clipboard, timeout)` returns that offer.

GREEN: implement `fetch_offer`:
```
TcpStream::connect(addr) -> map_err to a clear "couldn't reach <addr>"
let (inbound_tx, mut inbound_rx) = mpsc::channel(64);
let (connect_tx, _connect_rx) = mpsc::channel(64);   // keep rx alive: register try_sends once
let mesh = Mesh::new(Uuid::new_v4(), inbound_tx, connect_tx);
// drive inline (pin!, not spawn) so returning drops it -> AbortGuards tear down;
// run_connection adds its own +64KiB framing slack, so pass max_payload as-is.
let conn = run_connection(stream, true, psk, max_payload, mesh); tokio::pin!(conn);
loop with tokio::select! over:
  - timeout(deadline): Err("no <kind> from <addr> within …; is resync_on_connect on? …")
  - (&mut conn): the connection ended first -> surface its Err (PSK/version/refused)
  - inbound_rx.recv(): on Clip{kind==want} return offer; else ignore and continue
then drain inbound_rx (try_recv) once for a buffered Clip{kind==want} before
surfacing the loop's error (select! could pick the conn/timeout arm in the same
tick the wanted Clip was delivered).
```
Returning from `fetch_offer` drops the pinned `conn`, closing the socket promptly.

## Task 4: More integration coverage

RED/GREEN (tests/paste.rs):
- SELECTION pull works when the node has `sync_selection = true`.
- `resync_on_connect = false` → `fetch_offer` times out with the actionable error.
- wrong PSK → connection error (not a bare timeout).

## Task 5: `run` + `main` wiring

RED: an arg-level test that `run` with `--list-types` against an in-process node
prints the keys (or keep `run` thin and rely on Task 1–4 coverage; `main`
detection covered by a small unit test on the detect helper).

GREEN:
- `paste::run(args: Vec<String>)`: parse args; `Config::load`; `resolve_targets`
  (`--node` → one address with the config port applied; default → **all** peers);
  `fetch_from_any` (race `fetch_offer` across targets via `tokio::task::JoinSet`,
  first success wins, single target fetched directly); then `--list-types` →
  print keys, or select the type and `write_stdout(render(...))` (broken pipe →
  clean exit). Diagnostics to stderr; non-zero exit via `Result`.
- `main.rs`: a `paste_mode_args(argv) -> Option<Vec<String>>` helper (argv[0]
  basename `wl-paste`, or `--paste` present → the args with `--paste` removed),
  checked before the flag loop; `Some(args)` → `return paste::run(args).await`.

## Task 6: Docs

- `README.md`: a "Pasting from a node (wl-paste mode)" section — usage, the
  `wl-paste` symlink, and the two constraints (`resync_on_connect`; `-p` needs
  `sync_selection`).
- `CLAUDE.md`: one bullet under Architecture for `paste.rs`; note the
  one-shot-flags list in the MSRV/flags paragraph.
- `examples/config.toml`: no change — it is generated from `config_template.rs`
  (a test asserts it isn't stale) and the mode adds no config key.

---

## Verification

- `cargo test` (lib unit + `tests/paste.rs` + existing `tests/two_nodes.rs`).
- `cargo clippy --all-targets -- -D warnings`.
- `cargo fmt --check`.
