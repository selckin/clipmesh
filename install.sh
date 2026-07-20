#!/usr/bin/env bash
# Build and install clipmesh on this host. Idempotent: safe to re-run
# after every update; existing config and psk are never overwritten.
die() { echo "$*" >&2; exit 1; }

umask 077  # secret material is created below; never expose it via umask

cd "$(dirname "$0")" || die "cannot cd to the repo root"

CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/clipmesh"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
CONFIG="$CONFIG_DIR/config.toml"
MIMETYPES="$CONFIG_DIR/mimetypes"
PSK="$CONFIG_DIR/psk"

echo "==> Building and installing binary"
cargo install --path . --quiet || die "build failed; nothing was installed"
if BIN=$(command -v clipmesh); then
    echo "    installed $BIN"
else
    echo "    warning: clipmesh not on PATH (is ~/.cargo/bin in PATH?); the systemd unit uses the absolute path and will still work"
fi

echo "==> Installing systemd user unit"
mkdir -p "$UNIT_DIR" || die "cannot create $UNIT_DIR"
cp clipmesh.service "$UNIT_DIR/" || die "cannot install the unit into $UNIT_DIR"
systemctl --user daemon-reload || die "systemctl daemon-reload failed"

mkdir -p "$CONFIG_DIR" || die "cannot create $CONFIG_DIR"
chmod 700 "$CONFIG_DIR" || die "cannot restrict $CONFIG_DIR (it holds the psk)"

fresh_config=0
if [[ ! -f "$CONFIG" ]]; then
    cp examples/config.toml "$CONFIG" || die "cannot write $CONFIG"
    # The example names the default location literally (psk_file =
    # "~/.config/clipmesh/psk"), so on a host that sets XDG_CONFIG_HOME the
    # copy would point at a psk this script never created -- the daemon then
    # fails to start with "reading psk_file ...: No such file or directory".
    # Point the copy at the directory we actually installed into.
    if [[ "$CONFIG_DIR" != "$HOME/.config/clipmesh" ]]; then
        sed -i "s|~/.config/clipmesh/|$CONFIG_DIR/|g" "$CONFIG" \
            || die "cannot point $CONFIG at $CONFIG_DIR"
    fi
    fresh_config=1
    echo "==> Created $CONFIG from example -- edit listen/peers before starting"
else
    echo "==> Keeping existing $CONFIG"
fi

# Put the MIME-rules file in place up front so it's there to edit before the
# first run. clipmesh creates the identical file itself if this is skipped --
# examples/mimetypes is generated from the same built-in skeleton -- so this is
# a convenience, not a requirement. Never overwrite an existing file: it's yours
# to edit and clipmesh appends to it.
if [[ ! -f "$MIMETYPES" ]]; then
    cp examples/mimetypes "$MIMETYPES" || die "cannot write $MIMETYPES"
    echo "==> Created $MIMETYPES from example -- edit to allow/deny types"
else
    echo "==> Keeping existing $MIMETYPES"
fi

if [[ ! -f "$PSK" ]]; then
    # Generate into a temp and only move it into place once it is known good.
    # `> "$PSK"` creates the file before the generator runs, so a failure leaves
    # a zero-byte psk behind -- and the next run then reports "Keeping existing"
    # while the daemon refuses to start with "preshared secret is empty", with
    # nothing pointing at the generation that never happened. The emptiness
    # check also catches a failing `head` in the pipeline below, whose exit
    # status is `tr`'s rather than its own.
    psk_tmp="$PSK.tmp.$$"
    trap 'rm -f "$psk_tmp"' EXIT
    if command -v openssl >/dev/null; then
        openssl rand -hex 32 > "$psk_tmp" || die "openssl could not generate a secret"
    else
        head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$psk_tmp" \
            || die "could not generate a secret from /dev/urandom"
    fi
    [[ -s "$psk_tmp" ]] || die "the generated secret is empty; refusing to install it"
    chmod 600 "$psk_tmp" || die "cannot restrict the generated secret"
    mv "$psk_tmp" "$PSK" || die "cannot move the generated secret into $PSK"
    trap - EXIT
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
