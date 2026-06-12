# clipmesh

Encrypted clipboard sync for a mesh of Wayland machines on a LAN.
Copy on one host, paste on all of them.

- Full peer mesh over TCP, every node dials every other; duplicate
  connections are tolerated by design (node-ID based dedup).
- Noise NNpsk0 encryption keyed by a preshared secret: peers without the
  secret can neither read nor inject clipboard contents.
- Mirrors all MIME representations (text, images, ...), capped at 8 MiB.
- Skips password-manager-flagged contents by default.

## Requirements

- A Wayland compositor implementing ext-data-control-v1 or
  zwlr-data-control-v1 (niri, Sway, Hyprland, KDE Plasma; **not** GNOME).
- `wl-clipboard` installed (`wl-paste` is used for change watching).

## Setup

On each host:

    ./install.sh

The script builds and installs the binary, the systemd user unit, a config
skeleton, and generates a secret on first run (existing config/psk are never
touched). Re-run it after every update; it restarts the service for you.

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
