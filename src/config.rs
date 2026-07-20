use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Both,
    SendOnly,
    ReceiveOnly,
}

/// What to do with a MIME type that has no rule in the rules file yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MimePolicy {
    Allow,
    Deny,
}

/// Whether to mirror one local selection into the other on this host — one
/// boolean per direction, each off by default. A purely *local* coupling,
/// distinct from the cross-host `sync_selection`. Parsed directly from the
/// `[link_selections]` table; the two directions are independent, so this is
/// just the table itself (no separate raw/resolved shapes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LinkSelections {
    /// A Ctrl+C clipboard copy is also written to the middle-click selection.
    pub clipboard_to_selection: bool,
    /// A mouse text selection is also written to the Ctrl+C clipboard.
    pub selection_to_clipboard: bool,
}

impl LinkSelections {
    /// No mirroring in either direction (the default).
    pub const OFF: Self = Self {
        clipboard_to_selection: false,
        selection_to_clipboard: false,
    };
    /// Mirror CLIPBOARD changes into the SELECTION only.
    pub const CLIPBOARD_TO_SELECTION: Self = Self {
        clipboard_to_selection: true,
        selection_to_clipboard: false,
    };
    /// Mirror SELECTION changes into the CLIPBOARD only.
    pub const SELECTION_TO_CLIPBOARD: Self = Self {
        clipboard_to_selection: false,
        selection_to_clipboard: true,
    };
    /// Mirror both directions.
    pub const BOTH: Self = Self {
        clipboard_to_selection: true,
        selection_to_clipboard: true,
    };
}

/// Raw on-disk shape; resolved into `Config`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    /// Bind address (host or IP, no port); combined with `port`.
    listen: String,
    /// Port to listen on, and the default for peers that omit their own.
    #[serde(default = "default_port")]
    port: u16,
    #[serde(default)]
    peers: Vec<String>,
    psk: Option<String>,
    psk_file: Option<String>,
    psk_env: Option<String>,
    #[serde(default = "default_max_payload")]
    max_payload_size: String,
    #[serde(default = "default_debounce_ms")]
    debounce_ms: u64,
    #[serde(default)]
    sync_selection: bool,
    #[serde(default)]
    link_selections: LinkSelections,
    #[serde(default = "default_direction")]
    direction: Direction,
    #[serde(default = "default_true")]
    exclude_sensitive: bool,
    #[serde(default = "default_true")]
    resync_on_connect: bool,
    #[serde(default = "default_true")]
    share_mime_rules: bool,
    /// Log a one-line summary for every detected copy and received update.
    #[serde(default)]
    verbose: bool,
    #[serde(default = "default_log_level")]
    log_level: String,
    /// Allow or deny a MIME type that has no rule yet (default deny).
    #[serde(default = "default_unknown_mime")]
    unknown_mime: MimePolicy,
    /// When a captured selection offers a legacy UTF8_STRING/STRING/TEXT atom
    /// but no text/plain* representation, synthesize text/plain;charset=utf-8 and
    /// text/plain from it (re-encoded to UTF-8). Off by default.
    #[serde(default)]
    synthesize_text_plain: bool,
    /// After a local copy, re-write the selection so clipmesh owns it (the
    /// content then survives the source app exiting), and — with
    /// synthesize_text_plain — back-fill text/plain locally too. Off by default.
    #[serde(default)]
    take_ownership: bool,
    /// Per-type allow/deny rules file; defaults to `mimetypes` beside this
    /// config when unset.
    mime_rules_file: Option<String>,
}

/// Every TOML key the config parser accepts — the schema `config_template`
/// checks its `TEMPLATE` against, so an option with no block is caught here
/// instead of being silently deleted from a user's file by `--sync-config`.
///
/// Written out by hand but not taken on trust, from both directions: adding a
/// field to `RawConfig` breaks the no-rest-pattern destructure in `from_toml`
/// (which points back here), and `raw_config_keys_matches_the_struct` pins this
/// list to the field names serde itself reports, so a typo, a stale entry, or a
/// `#[serde(rename)]` that moves a key can't pass unnoticed.
pub const RAW_CONFIG_KEYS: [&str; 20] = [
    "listen",
    "port",
    "peers",
    "psk",
    "psk_file",
    "psk_env",
    "max_payload_size",
    "debounce_ms",
    "sync_selection",
    "link_selections",
    "direction",
    "exclude_sensitive",
    "resync_on_connect",
    "share_mime_rules",
    "verbose",
    "log_level",
    "unknown_mime",
    "synthesize_text_plain",
    "take_ownership",
    "mime_rules_file",
];

fn default_port() -> u16 {
    48100
}
fn default_max_payload() -> String {
    "32MiB".into()
}
fn default_debounce_ms() -> u64 {
    100
}
fn default_direction() -> Direction {
    Direction::Both
}
fn default_true() -> bool {
    true
}
fn default_log_level() -> String {
    "info".into()
}
fn default_unknown_mime() -> MimePolicy {
    MimePolicy::Deny
}

/// `PartialEq` exists for `config_template`'s default check, which asserts that
/// activating the template's commented defaults yields exactly the config a
/// minimal file parses to. Comparing whole values keeps that test from listing
/// the fields itself — a hand-written list there would be one more copy of the
/// defaults, which is the drift the test is there to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub listen: String,
    /// The configured port — the default applied to any peer (or `--node`
    /// paste target) given without an explicit port.
    pub port: u16,
    pub peers: Vec<String>,
    /// 32-byte Noise PSK, derived from the configured secret via BLAKE3.
    pub psk: [u8; 32],
    pub max_payload_size: usize,
    pub debounce_ms: u64,
    pub sync_selection: bool,
    /// Local clipboard↔selection mirroring (distinct from `sync_selection`).
    pub link_selections: LinkSelections,
    pub direction: Direction,
    pub exclude_sensitive: bool,
    /// Push current clipboard state to peers when they (re)connect;
    /// the receiving side applies it only if it is newer than its own.
    pub resync_on_connect: bool,
    /// Share the per-type MIME-rules file across the mesh (whole-file
    /// last-writer-wins). Default on. Independent of `direction`.
    pub share_mime_rules: bool,
    /// Log a one-line summary for every detected copy and every received
    /// update (at `info` level). Off by default.
    pub verbose: bool,
    pub log_level: String,
    /// Allow or deny a MIME type that is not yet listed in the rules file.
    pub unknown_mime: MimePolicy,
    /// Back-fill text/plain (+ ;charset=utf-8) from a legacy UTF8_STRING/STRING/
    /// TEXT atom on the capture side when no text/plain* rep exists. Off by
    /// default. The synthesized reps go through the normal MIME rules and cap.
    pub synthesize_text_plain: bool,
    /// After a local copy, re-offer the selection so clipmesh owns it (content
    /// survives the source app exiting); with `synthesize_text_plain` the
    /// re-offered set includes the synthesized text/plain so it pastes locally.
    /// Applies to every watched selection. Off by default. Never persists
    /// password-manager secrets (subject to `exclude_sensitive`).
    pub take_ownership: bool,
    /// Path to the per-type rules file. Resolved to `mimetypes` next to the
    /// config file by `load` when not set explicitly; `None` keeps the rules
    /// in memory only (used by tests).
    pub mime_rules_path: Option<PathBuf>,
}

/// Parse "8MiB" / "512KiB" / "64B" / "1048576" into bytes.
pub fn parse_size(s: &str) -> Result<usize> {
    let s = s.trim();
    let (num, mult): (&str, usize) = if let Some(n) = s.strip_suffix("MiB") {
        (n, 1024 * 1024)
    } else if let Some(n) = s.strip_suffix("KiB") {
        (n, 1024)
    } else if let Some(n) = s.strip_suffix('B') {
        (n, 1)
    } else {
        (s, 1)
    };
    let value: usize = num
        .trim()
        .parse()
        .with_context(|| format!("invalid size: {s:?}"))?;
    value
        .checked_mul(mult)
        .with_context(|| format!("size overflows: {s:?}"))
}

/// The port portion of a `host:port` address, or `None` if it has none.
/// Handles `host:port`, `1.2.3.4:port`, and bracketed `[v6]:port`; a bare
/// hostname/IPv4 or an unbracketed IPv6 literal (e.g. `::1`) has no port.
fn port_of(addr: &str) -> Option<&str> {
    if addr.starts_with('[') {
        // bracketed IPv6: the port is whatever follows the closing `]:`
        return addr
            .rsplit_once(']')?
            .1
            .strip_prefix(':')
            .filter(|p| !p.is_empty());
    }
    let (head, last) = addr.rsplit_once(':')?;
    // More than one colon and unbracketed means a bare IPv6 literal, not a port.
    if head.contains(':') {
        None
    } else {
        Some(last).filter(|p| !p.is_empty())
    }
}

/// The default config path (`$XDG_CONFIG_HOME/clipmesh/config.toml`, falling
/// back to `~/.config/clipmesh/config.toml`), used by `main` (daemon + CLI
/// actions) and the paste mode alike.
pub fn default_config_path() -> PathBuf {
    config_root(std::env::var("XDG_CONFIG_HOME").ok())
        .join("clipmesh")
        .join("config.toml")
}

/// The XDG config root for a given `$XDG_CONFIG_HOME` value.
///
/// Taking the value as an argument rather than reading the environment keeps
/// the rule — including the two ways the spec says to ignore a value —
/// testable without mutating the process environment out from under every
/// other test in the binary.
fn config_root(xdg_config_home: Option<String>) -> PathBuf {
    // Per the XDG basedir spec: unset *or empty* means the default, and a
    // relative path is invalid and must be ignored.
    match xdg_config_home {
        Some(dir) if Path::new(&dir).is_absolute() => PathBuf::from(dir),
        _ => PathBuf::from(shellexpand::tilde("~/.config").into_owned()),
    }
}

/// Append `default_port` to an address that lacks one (bracketing a bare IPv6
/// literal so the result stays a valid `host:port`). Addresses that already
/// carry a port are returned unchanged.
pub(crate) fn with_default_port(addr: &str, default_port: &str) -> String {
    if port_of(addr).is_some() {
        return addr.to_string();
    }
    if !addr.starts_with('[') && addr.contains(':') {
        format!("[{addr}]:{default_port}")
    } else {
        format!("{addr}:{default_port}")
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if crate::fsutil::is_symlink(path) => {
                let target = fs::read_link(path)
                    .map(|t| t.display().to_string())
                    .unwrap_or_else(|_| "?".to_string());
                bail!(
                    "config {} is a symlink to {}, which can't be read ({e})",
                    path.display(),
                    target
                );
            }
            Err(e) => {
                return Err(e).with_context(|| format!("reading config {}", path.display()));
            }
        };
        let mut cfg = Config::from_toml(&text)?;
        // Default the rules file to live beside the config (e.g.
        // ~/.config/clipmesh/mimetypes) unless the user set an explicit path.
        if cfg.mime_rules_path.is_none() {
            cfg.mime_rules_path = Some(crate::fsutil::parent_dir(path).join("mimetypes"));
        }
        Ok(cfg)
    }

    pub fn from_toml(text: &str) -> Result<Config> {
        let raw: RawConfig = toml::from_str(text).context("parsing config")?;
        // Destructured with no `..` rest pattern on purpose. A field added to
        // `RawConfig` then fails to compile right here until it is handled —
        // which is the moment to also add it to `RAW_CONFIG_KEYS` above, and so
        // to the `--sync-config` template. Without that stop, a new option would
        // parse fine and quietly vanish from any config file that set it.
        let RawConfig {
            listen,
            port,
            peers,
            psk,
            psk_file,
            psk_env,
            max_payload_size,
            debounce_ms,
            sync_selection,
            link_selections,
            direction,
            exclude_sensitive,
            resync_on_connect,
            share_mime_rules,
            verbose,
            log_level,
            unknown_mime,
            synthesize_text_plain,
            take_ownership,
            mime_rules_file,
        } = raw;
        let secret = match (psk, psk_file, psk_env) {
            (Some(s), None, None) => s,
            (None, Some(f), None) => {
                let path = shellexpand::tilde(&f).into_owned();
                fs::read_to_string(&path)
                    .with_context(|| format!("reading psk_file {path}"))?
                    .trim()
                    .to_string()
            }
            (None, None, Some(var)) => {
                std::env::var(&var).with_context(|| format!("reading psk_env {var}"))?
            }
            _ => bail!("exactly one of psk, psk_file, psk_env must be set"),
        };
        if secret.is_empty() {
            bail!("preshared secret is empty");
        }
        // `listen` is the bind address and `port` the port to listen on. A port
        // left inside `listen` would silently shadow `port` (and the port peers
        // inherit), turning a half-migrated config into a mesh that never forms,
        // so reject it with a pointer to the right field.
        if let Some(p) = port_of(&listen) {
            bail!(
                "listen must not include a port (found {p:?} in {listen:?}); \
                 set the port with the separate `port` field instead"
            );
        }
        // Combine them, and let any peer without its own port reuse the port.
        let port_text = port.to_string();
        Ok(Config {
            listen: with_default_port(&listen, &port_text),
            port,
            peers: peers
                .iter()
                .map(|p| with_default_port(p, &port_text))
                .collect(),
            psk: *blake3::hash(secret.as_bytes()).as_bytes(),
            max_payload_size: match parse_size(&max_payload_size)? {
                0 => bail!("max_payload_size must be greater than 0"),
                n => n,
            },
            debounce_ms,
            sync_selection,
            link_selections,
            direction,
            exclude_sensitive,
            resync_on_connect,
            share_mime_rules,
            verbose,
            log_level,
            unknown_mime,
            synthesize_text_plain,
            take_ownership,
            mime_rules_path: mime_rules_file
                .map(|f| PathBuf::from(shellexpand::tilde(&f).into_owned())),
        })
    }

    /// Convenience constructor for tests (unit and integration).
    ///
    /// Built by parsing a minimal config so every production default flows in
    /// on its own. Spelling the fields out instead made this a second, silent
    /// copy of the defaults: the compiler catches a new *field* but says
    /// nothing about a changed *value*, so tests kept asserting against
    /// defaults production had already moved off.
    ///
    /// The four overrides below are the only intended departures, each for a
    /// test-harness reason rather than because it is what clipmesh does.
    pub fn for_test(secret: &str) -> Config {
        // `listen` may not carry a port, so the bind address is set below; the
        // rest of the file is the smallest input the parser accepts.
        let minimal = format!("listen = \"127.0.0.1\"\npsk = {secret:?}\n");
        Config {
            // Bind an ephemeral port so parallel tests don't collide. `port`
            // deliberately keeps its production value: it is also the port a
            // peer address without one inherits, which tests do exercise.
            listen: "127.0.0.1:0".into(),
            // No quiet period: tests step the engine copy by copy and would
            // otherwise wait out the real debounce on every one.
            debounce_ms: 0,
            // Off, because tests assert verbatim rules-file contents and must
            // not find a shared-rules version header in them. Sharing tests
            // turn it back on.
            share_mime_rules: false,
            // Permissive, so an engine test can run without first writing a
            // rules file. Note this is the opposite of production's `Deny`:
            // deny-by-default is covered by the rules tests in `mime`, which
            // set their own policy and rules path, not by anything built here.
            unknown_mime: MimePolicy::Allow,
            ..Config::from_toml(&minimal).expect("the minimal test config parses")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Parse `extra` on top of the two keys every config must have. Most tests
    /// here are about one option, and repeating the required pair around it
    /// buries which line they are actually testing.
    fn cfg_with(extra: &str) -> Result<Config> {
        Config::from_toml(&format!("listen = \"x\"\npsk = \"s\"\n{extra}"))
    }

    #[test]
    fn verbose_defaults_off_and_parses_when_set() {
        assert!(!cfg_with("").unwrap().verbose);
        assert!(cfg_with("verbose = true\n").unwrap().verbose);
    }

    #[test]
    fn load_reports_a_broken_config_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("config.toml");
        std::os::unix::fs::symlink(dir.path().join("missing.toml"), &link).unwrap();
        let err = Config::load(&link).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("symlink"),
            "message should mention the symlink: {msg}"
        );
        assert!(
            msg.contains("missing.toml"),
            "message should name the target: {msg}"
        );
    }

    #[test]
    fn zero_max_payload_size_is_rejected() {
        // A 0 cap would silently drop every representation; reject it loudly.
        assert!(cfg_with("max_payload_size = \"0B\"\n").is_err());
    }

    #[test]
    fn parses_full_config() {
        let toml = r#"
listen = "0.0.0.0"
port = 48100
peers = ["host-b:48100", "host-c:48100"]
psk = "supersecret"
max_payload_size = "2MiB"
debounce_ms = 250
sync_selection = true
direction = "send_only"
exclude_sensitive = false
resync_on_connect = false
log_level = "debug"
unknown_mime = "allow"
mime_rules_file = "/tmp/clipmesh-test/mimetypes"

[link_selections]
clipboard_to_selection = true
selection_to_clipboard = true
"#;
        let cfg = Config::from_toml(toml).unwrap();
        assert_eq!(cfg.listen, "0.0.0.0:48100"); // listen + port combined
        assert_eq!(cfg.port, 48100);
        assert_eq!(cfg.peers, vec!["host-b:48100", "host-c:48100"]);
        assert_eq!(cfg.psk, *blake3::hash(b"supersecret").as_bytes());
        assert_eq!(cfg.max_payload_size, 2 * 1024 * 1024);
        assert_eq!(cfg.debounce_ms, 250);
        assert!(cfg.sync_selection);
        assert_eq!(cfg.direction, Direction::SendOnly);
        assert!(!cfg.exclude_sensitive);
        assert!(!cfg.resync_on_connect);
        assert_eq!(cfg.log_level, "debug");
        assert_eq!(cfg.unknown_mime, MimePolicy::Allow);
        assert_eq!(
            cfg.mime_rules_path,
            Some(PathBuf::from("/tmp/clipmesh-test/mimetypes"))
        );
        assert_eq!(cfg.link_selections, LinkSelections::BOTH);
    }

    #[test]
    fn applies_defaults() {
        let cfg = Config::from_toml("listen = \"0.0.0.0\"\npsk = \"s\"\n").unwrap();
        assert!(cfg.peers.is_empty());
        assert_eq!(cfg.listen, "0.0.0.0:48100"); // port defaults to 48100
        assert_eq!(cfg.port, 48100);
        assert_eq!(cfg.max_payload_size, 32 * 1024 * 1024);
        assert_eq!(cfg.debounce_ms, 100);
        assert!(!cfg.sync_selection);
        assert_eq!(cfg.direction, Direction::Both);
        assert!(cfg.exclude_sensitive);
        assert!(cfg.resync_on_connect);
        assert_eq!(cfg.log_level, "info");
        assert_eq!(cfg.unknown_mime, MimePolicy::Deny);
        // from_toml has no config dir to resolve against; load() fills this in
        assert_eq!(cfg.mime_rules_path, None);
    }

    #[test]
    fn requires_exactly_one_psk_source() {
        assert!(Config::from_toml("listen = \"x\"\n").is_err());
        assert!(Config::from_toml("listen = \"x\"\npsk = \"a\"\npsk_env = \"B\"\n").is_err());
    }

    #[test]
    fn rejects_empty_secret() {
        assert!(Config::from_toml("listen = \"x\"\npsk = \"\"\n").is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(cfg_with("typo_field = 1\n").is_err());
    }

    #[test]
    fn reads_psk_from_file_trimmed() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "filesecret").unwrap(); // trailing newline must be trimmed
        let toml = format!("listen = \"x\"\npsk_file = \"{}\"\n", f.path().display());
        let cfg = Config::from_toml(&toml).unwrap();
        assert_eq!(cfg.psk, *blake3::hash(b"filesecret").as_bytes());
    }

    /// `install.sh` writes the config, the psk and the systemd unit under
    /// `${XDG_CONFIG_HOME:-$HOME/.config}`. A daemon that looked only at
    /// `~/.config` could not find what its own installer had just placed, so on
    /// a host that sets the variable the install reported success and the unit
    /// restart-looped on "reading config …: No such file or directory".
    #[test]
    fn the_default_config_root_follows_xdg_config_home() {
        assert_eq!(
            config_root(Some("/home/u/.dotconfig".to_string())),
            PathBuf::from("/home/u/.dotconfig")
        );

        // Per the XDG basedir spec an unset or empty value means the default,
        // and a relative path is invalid and must be ignored.
        let fallback = PathBuf::from(shellexpand::tilde("~/.config").into_owned());
        assert_eq!(config_root(None), fallback);
        assert_eq!(config_root(Some(String::new())), fallback);
        assert_eq!(config_root(Some("relative/dir".to_string())), fallback);
    }

    #[test]
    fn reads_psk_from_env() {
        std::env::set_var("CLIPMESH_TEST_PSK", "envsecret");
        let cfg = Config::from_toml("listen = \"x\"\npsk_env = \"CLIPMESH_TEST_PSK\"\n").unwrap();
        assert_eq!(cfg.psk, *blake3::hash(b"envsecret").as_bytes());
    }

    #[test]
    fn share_mime_rules_defaults_on_and_parses() {
        assert!(cfg_with("").unwrap().share_mime_rules);
        assert!(
            !cfg_with("share_mime_rules = false\n")
                .unwrap()
                .share_mime_rules
        );
        // tests opt out by default so existing verbatim-file tests are unaffected
        assert!(!Config::for_test("s").share_mime_rules);
    }

    #[test]
    fn listen_and_port_combine_into_a_bind_address() {
        let cfg = Config::from_toml("listen = \"0.0.0.0\"\nport = 51000\npsk = \"s\"\n").unwrap();
        assert_eq!(cfg.listen, "0.0.0.0:51000");
    }

    #[test]
    fn ipv6_listen_address_is_bracketed_with_the_port() {
        let cfg = Config::from_toml("listen = \"::\"\nport = 48100\npsk = \"s\"\n").unwrap();
        assert_eq!(cfg.listen, "[::]:48100");
    }

    #[test]
    fn listen_with_a_port_is_rejected() {
        // The port lives in its own field now; a port inside `listen` would
        // silently shadow it, so it must be rejected loudly.
        let err = Config::from_toml("listen = \"0.0.0.0:9000\"\nport = 48100\npsk = \"s\"\n")
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("listen must not include a port"), "got: {msg}");
    }

    #[test]
    fn peer_without_port_inherits_listen_port() {
        // A node listed without a port reuses the port we listen on; an
        // explicit port is left untouched.
        let toml =
            "listen = \"0.0.0.0\"\nport = 48100\npsk = \"s\"\npeers = [\"host-b\", \"host-c:51000\"]\n";
        let cfg = Config::from_toml(toml).unwrap();
        assert_eq!(cfg.peers, vec!["host-b:48100", "host-c:51000"]);
    }

    #[test]
    fn bracketed_ipv6_peer_without_port_inherits_listen_port() {
        // `[::1]` is the realistic way to write a portless bracketed IPv6 peer.
        let toml = "listen = \"::\"\nport = 48100\npsk = \"s\"\npeers = [\"[::1]\"]\n";
        let cfg = Config::from_toml(toml).unwrap();
        assert_eq!(cfg.peers, vec!["[::1]:48100"]);
    }

    #[test]
    fn bare_ipv6_peer_is_bracketed_with_listen_port() {
        // A bare IPv6 literal must be bracketed before a port can be appended;
        // an already-bracketed peer with a port is kept verbatim.
        let toml =
            "listen = \"::\"\nport = 48100\npsk = \"s\"\npeers = [\"::1\", \"[fe80::2]:5000\"]\n";
        let cfg = Config::from_toml(toml).unwrap();
        assert_eq!(cfg.peers, vec!["[::1]:48100", "[fe80::2]:5000"]);
    }

    #[test]
    fn sync_selection_parses_and_defaults_off() {
        assert!(!cfg_with("").unwrap().sync_selection);
        assert!(cfg_with("sync_selection = true\n").unwrap().sync_selection);
    }

    #[test]
    fn link_selections_table_parses_into_directions() {
        // Omitted table -> Off.
        assert_eq!(cfg_with("").unwrap().link_selections, LinkSelections::OFF);
        // Each boolean combination maps to the matching direction.
        let cases = [
            (
                "clipboard_to_selection = true\n",
                LinkSelections::CLIPBOARD_TO_SELECTION,
            ),
            (
                "selection_to_clipboard = true\n",
                LinkSelections::SELECTION_TO_CLIPBOARD,
            ),
            (
                "clipboard_to_selection = true\nselection_to_clipboard = true\n",
                LinkSelections::BOTH,
            ),
            (
                "clipboard_to_selection = false\nselection_to_clipboard = false\n",
                LinkSelections::OFF,
            ),
        ];
        for (body, expected) in cases {
            let table = format!("[link_selections]\n{body}");
            let parsed = cfg_with(&table).unwrap();
            assert_eq!(parsed.link_selections, expected, "parsing:\n{table}");
        }
    }

    #[test]
    fn link_selections_rejects_unknown_keys() {
        assert!(cfg_with("[link_selections]\ntypo = true\n").is_err());
    }

    #[test]
    fn pre_table_config_forms_are_rejected() {
        // The pre-table surface is gone: the old string form of link_selections
        // and the renamed `sync_primary` key must fail loudly (not silently
        // misparse), so an unmigrated config errors on load rather than running
        // with the wrong settings.
        assert!(cfg_with("link_selections = \"both\"\n").is_err());
        assert!(cfg_with("sync_primary = true\n").is_err());
    }

    /// A `Deserializer` that answers nothing and only records the field list
    /// serde hands it for a struct. Derived `Deserialize` impls pass that list
    /// to `deserialize_struct` — it is the same list `deny_unknown_fields`
    /// builds its error message from, but taken from the API instead of scraped
    /// out of the prose, and already carrying any `#[serde(rename)]`.
    struct FieldSpy<'a>(&'a mut Vec<&'static str>);

    /// The spy always stops immediately; nothing inspects why.
    #[derive(Debug)]
    struct Stop;

    impl std::fmt::Display for Stop {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("field capture stops here")
        }
    }
    impl std::error::Error for Stop {}
    impl serde::de::Error for Stop {
        fn custom<T: std::fmt::Display>(_: T) -> Self {
            Stop
        }
    }

    impl<'de> serde::Deserializer<'de> for FieldSpy<'_> {
        type Error = Stop;

        fn deserialize_struct<V: serde::de::Visitor<'de>>(
            self,
            _name: &'static str,
            fields: &'static [&'static str],
            _visitor: V,
        ) -> Result<V::Value, Stop> {
            self.0.extend_from_slice(fields);
            Err(Stop)
        }

        fn deserialize_any<V: serde::de::Visitor<'de>>(
            self,
            _visitor: V,
        ) -> Result<V::Value, Stop> {
            Err(Stop)
        }

        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
            bytes byte_buf option unit unit_struct newtype_struct seq tuple
            tuple_struct map enum identifier ignored_any
        }
    }

    /// `RAW_CONFIG_KEYS` must name exactly the keys `RawConfig` accepts. The
    /// compiler catches a *new* field (`from_toml`'s destructure won't build
    /// until it's handled), but nothing stops that fix from touching only the
    /// destructure — so pin the list to serde's own view of the struct, which
    /// also catches a removed field left behind here and a renamed key.
    #[test]
    fn raw_config_keys_matches_the_struct() {
        let mut fields = Vec::new();
        let _ = RawConfig::deserialize(FieldSpy(&mut fields));
        fields.sort_unstable();
        let mut declared = RAW_CONFIG_KEYS;
        declared.sort_unstable();
        assert_eq!(
            fields, declared,
            "RAW_CONFIG_KEYS has drifted from RawConfig's fields"
        );
    }

    #[test]
    fn parse_size_variants() {
        assert_eq!(parse_size("8MiB").unwrap(), 8 * 1024 * 1024);
        assert_eq!(parse_size("512KiB").unwrap(), 512 * 1024);
        assert_eq!(parse_size("64B").unwrap(), 64);
        assert_eq!(parse_size("1048576").unwrap(), 1048576);
        assert!(parse_size("eight").is_err());
        assert!(parse_size("9999999999999999999MiB").is_err()); // overflow
    }
}
