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
- Optionally links the two local selections on a host: `link_selections`
  mirrors the clipboard into the middle-click primary selection and/or the
  reverse (`clipboard_to_primary` | `primary_to_clipboard` | `both`, default
  off). This is local-only coupling, separate from `sync_primary` (which syncs
  each selection across the mesh). Note `primary_to_clipboard` (and `both`)
  means selecting any text overwrites your clipboard — and, since the clipboard
  is always synced when this node sends to the mesh, that selection lands on
  every peer's clipboard too (regardless of `sync_primary`).
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

Which clipboard types sync is decided per-type by a TOML rules file kept next to
the config (default `~/.config/clipmesh/mimetypes`; see `examples/mimetypes`).
Each entry under `[rules]` is:

    "<mime>" = "allow" | "deny"           # or, with a per-type size cap:
    "<mime>" = { rule = "allow", max = "4MiB" }

The MIME is a quoted TOML key, so types with spaces, `;`, `=` or other
punctuation (e.g. Java dataflavors) work. The optional `max` caps that one type,
on top of the global `max_payload_size`.

A key may also be a **glob**: `*` matches any run of characters and `?` matches
exactly one, so `"JAVA_DATATRANSFER*" = "deny"` covers a whole family at once and
`"*;charset=utf-16*" = "deny"` covers every UTF-16 variant. `*` and `?` are
always wildcards (there's no escape, so a key can't match a literal `*`/`?` — MIME
types never contain them). Matching is **case-insensitive** (ASCII). When more
than one key matches a type the most specific
wins — an exact key beats a glob, and among globs the one with more literal
(non-wildcard) characters wins (ties break toward `deny`). So a broad
`"*;charset=utf-16*" = "deny"` alongside an exact
`"text/uri-list;charset=utf-8" = "allow"` denies the UTF-16 variants while still
allowing UTF-8. A type already covered by a matching glob is not appended again,
so one glob keeps churn-y families (e.g. per-paste Java dataflavor cookies) out
of the file.

clipmesh manages the file for you:

- The `unknown_mime` config option decides what happens to a type with no rule
  yet — **`deny` by default**, so nothing syncs until you allow it. Set it to
  `allow` to sync everything you haven't explicitly denied.
- `synthesize_text_plain` (off by default) back-fills `text/plain;charset=utf-8`
  and `text/plain` from a legacy `UTF8_STRING`/`STRING`/`TEXT` atom when a copied
  selection offers no `text/plain*` rep, so Wayland-native apps can paste content
  copied from X11/legacy apps (`STRING` is re-encoded from latin-1, `TEXT` is
  sniffed). The synthesized types pass through these rules, so with
  `unknown_mime = "deny"` you must allow `text/plain*` or they're stripped.
- Any new type clipmesh sees is appended automatically with the `unknown_mime`
  default — so to curate what syncs, copy a few things, then edit the generated
  file and flip types to `allow`/`deny`. On save the `[rules]` table is sorted
  by key and any comments placed among the entries are dropped; comments above
  `[rules]` (and the managed `[clipmesh]` table holding the sync version) are
  kept.
- The file is watched and reloaded as soon as it changes, so edits take effect
  right away — no restart needed. An entry with an invalid value is ignored
  (with a warning) but kept in the file rather than dropped.
- You can manage rules from the command line instead of opening the file:

      clipmesh --allow "<glob>"     # add an allow rule
      clipmesh --deny  "<glob>"     # add a deny rule
      clipmesh --rules              # list the rules and flag overlaps

  An `--allow`/`--deny` writes the rule (a literal type or a glob) and exits; a
  running daemon picks the change up through its watcher (and reshares it if
  `share_mime_rules` is on). Any existing entries the new glob now covers are
  removed and printed back so you can re-add the ones you want to keep as
  exceptions. `--rules` is read-only: it prints the rules and, for each, any
  other glob that also matches its key — marking redundant duplicates and
  precedence conflicts. Pass `--config <path>` to target a non-default config.
- With `share_mime_rules` (on by default), the rules file is kept in sync
  across the mesh: edit it on one host and the others converge to it. It is
  whole-file last-writer-wins — the most recently edited file wins outright and
  replaces the others rather than merging per-type, so a type one host had
  curated but another never saw is dropped when the older file loses (it
  reappears, deny-by-default, the next time that type is copied). clipmesh
  stamps the file with a managed `[clipmesh]` table (holding `version` and
  `origin`) to order edits; every sharing host gains that table on first
  connect. A peer that flips
  a type to `allow` will make it sync on your host — that is the point. The
  password-manager `exclude_sensitive` filter is never shared and stays local.
  Set `share_mime_rules = false` to keep each host's rules independent.
- `synthesize_text_plain` (off by default) helps content copied from X11/legacy
  apps. When a copied selection offers only a `UTF8_STRING`, `STRING`, or `TEXT`
  atom and no `text/plain*` type, clipmesh derives `text/plain;charset=utf-8` and
  `text/plain` from it — re-encoded to UTF-8 (`STRING` is latin-1; `TEXT` is
  sniffed) and trimmed of a trailing NUL/newline — so Wayland-native apps that
  only understand `text/plain` can paste it. The synthesized types pass through
  the rules above, so under deny-by-default you must allow `text/plain*` or they
  are stripped.
