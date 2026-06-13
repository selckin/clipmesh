# clipmesh

Encrypted clipboard sync for a mesh of Wayland machines on a LAN.
Copy on one host, paste on all of them.

- Full peer mesh over TCP, every node dials every other; duplicate
  connections are tolerated by design (node-ID based dedup). Peers are
  connected point-to-point and clipmesh does not forward between them, so
  every node must list every other node directly — leaving a node out of
  another's `peers` means copies won't reach it, even via a shared third node.
- Noise NNpsk0 encryption keyed by a preshared secret: peers without the
  secret can neither read nor inject clipboard contents.
- Mirrors clipboard MIME representations (text, images, ...), capped at 32 MiB
  total. Which types sync is controlled per-type by a rules file, deny-by-default
  (see Configuration). By default the rules file is shared across the mesh (whole-file
  last-writer-wins); disable with `share_mime_rules = false`.
- Skips password-manager-flagged contents by default.
- Resyncs on reconnect: content copied while a peer was offline is pushed
  to it when it comes back, newer content wins (ties broken deterministically
  by node ID; disable with `resync_on_connect = false`).

## Requirements

- A Wayland compositor implementing ext-data-control-v1 or
  zwlr-data-control-v1 (niri, Sway, Hyprland, KDE Plasma; **not** GNOME).
  Change watching and read/write are all in-process over that protocol, so
  no external `wl-clipboard`/`wl-paste` binary is required.

## Setup

On each host:

    ./install.sh

The script builds and installs the binary, the systemd user unit, a config
skeleton, a starter MIME-rules file, and generates a secret on first run
(existing config/rules/psk are never touched). Re-run it after every update; it
restarts the service for you.

Then, first time only:

    $EDITOR ~/.config/clipmesh/config.toml   # set listen + peers
    # copy ~/.config/clipmesh/psk to every other host
    systemctl --user enable --now clipmesh

<details>
<summary>Manual setup (what the script does)</summary>

    cargo install --path .
    mkdir -p ~/.config/clipmesh
    cp examples/config.toml ~/.config/clipmesh/config.toml
    openssl rand -hex 32 > ~/.config/clipmesh/psk
    chmod 600 ~/.config/clipmesh/psk
    $EDITOR ~/.config/clipmesh/config.toml   # set listen + peers

Distribute the same psk file to every host, then:

    cp clipmesh.service ~/.config/systemd/user/
    systemctl --user daemon-reload
    systemctl --user enable --now clipmesh

</details>

## Configuration

See `examples/config.toml` for all options and defaults.

clipmesh watches `config.toml` and restarts itself when it changes (most
settings — listen, peers, psk, ... — can't be applied live), so editing the
config takes effect automatically, no manual `systemctl restart` needed. A
change that doesn't parse is logged and ignored, leaving the running daemon
untouched.

Restarting means exiting cleanly and relying on the supervisor to start a fresh
process, so this needs the bundled systemd unit (`Restart=always`) or any
supervisor that restarts on exit. Run outside a supervisor (e.g. in the
foreground) and a config change just stops the daemon. Live MIME-rule reloads
(below) happen in place and don't need a supervisor.

### MIME type rules

Which clipboard types sync is decided per-type by a rules file kept next to the
config (default `~/.config/clipmesh/mimetypes`; see `examples/mimetypes`). Each
line is:

    <mime> <allow|deny> [max-size]

e.g. `image/png allow 4MiB`. The optional max-size caps that one type, on top of
the global `max_payload_size`.

clipmesh manages the file for you:

- The `unknown_mime` config option decides what happens to a type with no rule
  yet — **`deny` by default**, so nothing syncs until you allow it. Set it to
  `allow` to sync everything you haven't explicitly denied.
- Any new type clipmesh sees is appended automatically at the end of the file
  with the `unknown_mime` default — so to curate what syncs, copy a few things,
  then edit the generated file and flip types to `allow`/`deny`. Your existing
  lines, comments, and ordering are left as-is (the file is not reordered).
- The file is watched and reloaded as soon as it changes, so edits take effect
  right away — no restart needed. A line that can't be parsed is kept but
  commented out rather than dropped.
- With `share_mime_rules` (on by default), the rules file is kept in sync
  across the mesh: edit it on one host and the others converge to it. It is
  whole-file last-writer-wins — the most recently edited file wins outright and
  replaces the others rather than merging per-type, so a type one host had
  curated but another never saw is dropped when the older file loses (it
  reappears, deny-by-default, the next time that type is copied). clipmesh
  stamps the file with a managed `# clipmesh-version:` header line to order
  edits; every sharing host grows that line on first connect. A peer that flips
  a type to `allow` will make it sync on your host — that is the point. The
  password-manager `exclude_sensitive` filter is never shared and stays local.
  Set `share_mime_rules = false` to keep each host's rules independent.
