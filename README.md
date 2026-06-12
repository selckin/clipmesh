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

    cargo install --path .
    mkdir -p ~/.config/clipmesh
    cp examples/config.toml ~/.config/clipmesh/config.toml
    openssl rand -hex 32 > ~/.config/clipmesh/psk
    chmod 600 ~/.config/clipmesh/psk
    $EDITOR ~/.config/clipmesh/config.toml   # set listen + peers

Distribute the same psk file to every host, then:

    cp clipmesh.service ~/.config/systemd/user/
    systemctl --user enable --now clipmesh

## Configuration

See `examples/config.toml` for all options and defaults.
