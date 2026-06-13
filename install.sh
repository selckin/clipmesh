#!/usr/bin/env bash
# Build and install clipmesh on this host. Idempotent: safe to re-run
# after every update; existing config and psk are never overwritten.
set -euo pipefail
umask 077  # secret material is created below; never expose it via umask

cd "$(dirname "$0")"

CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/clipmesh"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
CONFIG="$CONFIG_DIR/config.toml"
MIMETYPES="$CONFIG_DIR/mimetypes"
PSK="$CONFIG_DIR/psk"

echo "==> Building and installing binary"
cargo install --path . --quiet
if BIN=$(command -v clipmesh); then
    echo "    installed $BIN"
else
    echo "    warning: clipmesh not on PATH (is ~/.cargo/bin in PATH?); the systemd unit uses the absolute path and will still work"
fi

echo "==> Installing systemd user unit"
mkdir -p "$UNIT_DIR"
cp clipmesh.service "$UNIT_DIR/"
systemctl --user daemon-reload

mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

fresh_config=0
if [[ ! -f "$CONFIG" ]]; then
    cp examples/config.toml "$CONFIG"
    fresh_config=1
    echo "==> Created $CONFIG from example -- edit listen/peers before starting"
else
    echo "==> Keeping existing $CONFIG"
fi

# Seed the MIME-rules file from the example so common text/image types sync out
# of the box (clipmesh otherwise creates a header-only file and, with the
# deny-by-default policy, syncs nothing until you curate it). Never overwrite an
# existing file -- it's yours to edit and clipmesh appends to it.
if [[ ! -f "$MIMETYPES" ]]; then
    cp examples/mimetypes "$MIMETYPES"
    echo "==> Created $MIMETYPES from example -- edit to allow/deny types"
else
    echo "==> Keeping existing $MIMETYPES"
fi

if [[ ! -f "$PSK" ]]; then
    if command -v openssl >/dev/null; then
        openssl rand -hex 32 > "$PSK"
    else
        head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$PSK"
    fi
    chmod 600 "$PSK"
    echo "==> Generated new secret in $PSK"
    echo "    Copy this file to every other host (e.g. scp $PSK other-host:$PSK)"
else
    echo "==> Keeping existing $PSK"
fi

if [[ $fresh_config -eq 1 ]]; then
    echo
    echo "Next steps:"
    echo "  1. Edit $CONFIG (set listen and peers)"
    echo "  2. Distribute $PSK to the other hosts"
    echo "  3. systemctl --user enable --now clipmesh"
elif systemctl --user is-active --quiet clipmesh; then
    echo "==> Restarting running service to pick up the new binary"
    systemctl --user restart clipmesh
else
    echo "==> Service not running; start it with: systemctl --user enable --now clipmesh"
fi
