use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Both,
    SendOnly,
    ReceiveOnly,
}

/// Raw on-disk shape; resolved into `Config`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    listen: String,
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
    sync_primary: bool,
    #[serde(default = "default_direction")]
    direction: Direction,
    #[serde(default = "default_true")]
    exclude_sensitive: bool,
    #[serde(default = "default_true")]
    resync_on_connect: bool,
    #[serde(default = "default_log_level")]
    log_level: String,
    mime_allow: Option<Vec<String>>,
    #[serde(default)]
    mime_deny: Vec<String>,
}

fn default_max_payload() -> String {
    "8MiB".into()
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

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: String,
    pub peers: Vec<String>,
    /// 32-byte Noise PSK, derived from the configured secret via BLAKE3.
    pub psk: [u8; 32],
    pub max_payload_size: usize,
    pub debounce_ms: u64,
    pub sync_primary: bool,
    pub direction: Direction,
    pub exclude_sensitive: bool,
    /// Push current clipboard state to peers when they (re)connect;
    /// the receiving side applies it only if it is newer than its own.
    pub resync_on_connect: bool,
    pub log_level: String,
    pub mime_allow: Option<Vec<String>>,
    pub mime_deny: Vec<String>,
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
    let value: usize = num.trim().parse().with_context(|| format!("invalid size: {s:?}"))?;
    value.checked_mul(mult).with_context(|| format!("size overflows: {s:?}"))
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        Config::from_toml(&text)
    }

    pub fn from_toml(text: &str) -> Result<Config> {
        let raw: RawConfig = toml::from_str(text).context("parsing config")?;
        let secret = match (&raw.psk, &raw.psk_file, &raw.psk_env) {
            (Some(s), None, None) => s.clone(),
            (None, Some(f), None) => {
                let path = shellexpand::tilde(f).into_owned();
                fs::read_to_string(&path)
                    .with_context(|| format!("reading psk_file {path}"))?
                    .trim()
                    .to_string()
            }
            (None, None, Some(var)) => {
                std::env::var(var).with_context(|| format!("reading psk_env {var}"))?
            }
            _ => bail!("exactly one of psk, psk_file, psk_env must be set"),
        };
        if secret.is_empty() {
            bail!("preshared secret is empty");
        }
        Ok(Config {
            listen: raw.listen,
            peers: raw.peers,
            psk: *blake3::hash(secret.as_bytes()).as_bytes(),
            max_payload_size: parse_size(&raw.max_payload_size)?,
            debounce_ms: raw.debounce_ms,
            sync_primary: raw.sync_primary,
            direction: raw.direction,
            exclude_sensitive: raw.exclude_sensitive,
            resync_on_connect: raw.resync_on_connect,
            log_level: raw.log_level,
            mime_allow: raw.mime_allow,
            mime_deny: raw.mime_deny,
        })
    }

    /// Convenience constructor for tests (unit and integration).
    pub fn for_test(secret: &str) -> Config {
        Config {
            listen: "127.0.0.1:0".into(),
            peers: vec![],
            psk: *blake3::hash(secret.as_bytes()).as_bytes(),
            max_payload_size: 8 * 1024 * 1024,
            debounce_ms: 0,
            sync_primary: false,
            direction: Direction::Both,
            exclude_sensitive: true,
            resync_on_connect: true,
            log_level: "info".into(),
            mime_allow: None,
            mime_deny: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parses_full_config() {
        let toml = r#"
listen = "0.0.0.0:48100"
peers = ["host-b:48100", "host-c:48100"]
psk = "supersecret"
max_payload_size = "2MiB"
debounce_ms = 250
sync_primary = true
direction = "send_only"
exclude_sensitive = false
resync_on_connect = false
log_level = "debug"
mime_allow = ["text/*"]
mime_deny = ["image/bmp"]
"#;
        let cfg = Config::from_toml(toml).unwrap();
        assert_eq!(cfg.listen, "0.0.0.0:48100");
        assert_eq!(cfg.peers, vec!["host-b:48100", "host-c:48100"]);
        assert_eq!(cfg.psk, *blake3::hash(b"supersecret").as_bytes());
        assert_eq!(cfg.max_payload_size, 2 * 1024 * 1024);
        assert_eq!(cfg.debounce_ms, 250);
        assert!(cfg.sync_primary);
        assert_eq!(cfg.direction, Direction::SendOnly);
        assert!(!cfg.exclude_sensitive);
        assert!(!cfg.resync_on_connect);
        assert_eq!(cfg.log_level, "debug");
        assert_eq!(cfg.mime_allow, Some(vec!["text/*".to_string()]));
        assert_eq!(cfg.mime_deny, vec!["image/bmp".to_string()]);
    }

    #[test]
    fn applies_defaults() {
        let cfg = Config::from_toml("listen = \"0.0.0.0:1\"\npsk = \"s\"\n").unwrap();
        assert!(cfg.peers.is_empty());
        assert_eq!(cfg.max_payload_size, 8 * 1024 * 1024);
        assert_eq!(cfg.debounce_ms, 100);
        assert!(!cfg.sync_primary);
        assert_eq!(cfg.direction, Direction::Both);
        assert!(cfg.exclude_sensitive);
        assert!(cfg.resync_on_connect);
        assert_eq!(cfg.log_level, "info");
        assert_eq!(cfg.mime_allow, None);
        assert!(cfg.mime_deny.is_empty());
    }

    #[test]
    fn requires_exactly_one_psk_source() {
        assert!(Config::from_toml("listen = \"x:1\"\n").is_err());
        assert!(Config::from_toml("listen = \"x:1\"\npsk = \"a\"\npsk_env = \"B\"\n").is_err());
    }

    #[test]
    fn rejects_empty_secret() {
        assert!(Config::from_toml("listen = \"x:1\"\npsk = \"\"\n").is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(Config::from_toml("listen = \"x:1\"\npsk = \"s\"\ntypo_field = 1\n").is_err());
    }

    #[test]
    fn reads_psk_from_file_trimmed() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "filesecret").unwrap(); // trailing newline must be trimmed
        let toml = format!("listen = \"x:1\"\npsk_file = \"{}\"\n", f.path().display());
        let cfg = Config::from_toml(&toml).unwrap();
        assert_eq!(cfg.psk, *blake3::hash(b"filesecret").as_bytes());
    }

    #[test]
    fn reads_psk_from_env() {
        std::env::set_var("CLIPMESH_TEST_PSK", "envsecret");
        let cfg = Config::from_toml("listen = \"x:1\"\npsk_env = \"CLIPMESH_TEST_PSK\"\n").unwrap();
        assert_eq!(cfg.psk, *blake3::hash(b"envsecret").as_bytes());
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
