//! The two interfaces of Mutter's remote-desktop D-Bus API the backend uses,
//! transcribed from mutter's `data/dbus-interfaces/org.gnome.Mutter.RemoteDesktop.xml`
//! (`gnome-46`; the clipboard part is unchanged on `main`). Only the clipboard
//! members and what is needed to get a session are declared: the input,
//! keymap and screen-cast members are not this backend's business.
//!
//! `Start` is deliberately absent. It is what creates the remote-access handle
//! behind GNOME's top-bar "remote desktop" indicator and runs Mutter's
//! permission check; none of the clipboard methods require a started session.

use std::collections::HashMap;
use zbus::zvariant::{OwnedFd, OwnedObjectPath, OwnedValue, Value};

#[zbus::proxy(
    interface = "org.gnome.Mutter.RemoteDesktop",
    default_service = "org.gnome.Mutter.RemoteDesktop",
    default_path = "/org/gnome/Mutter/RemoteDesktop",
    gen_blocking = false
)]
pub(crate) trait RemoteDesktop {
    fn create_session(&self) -> zbus::Result<OwnedObjectPath>;

    /// Mutter's API version (1 on GNOME 46). Logged, never gated on.
    #[zbus(property)]
    fn version(&self) -> zbus::Result<i32>;
}

#[zbus::proxy(
    interface = "org.gnome.Mutter.RemoteDesktop.Session",
    default_service = "org.gnome.Mutter.RemoteDesktop",
    gen_blocking = false
)]
pub(crate) trait RemoteDesktopSession {
    /// Subscribe. With a current owner Mutter emits `SelectionOwnerChanged`
    /// from inside the handler, before completing this call.
    fn enable_clipboard(&self, options: HashMap<&str, Value<'_>>) -> zbus::Result<()>;

    fn disable_clipboard(&self) -> zbus::Result<()>;

    /// Become the owner for `mime-types` (a non-empty `as`); without the key,
    /// unset our ownership.
    fn set_selection(&self, options: HashMap<&str, Value<'_>>) -> zbus::Result<()>;

    /// Answer a `SelectionTransfer`: the fd to write the representation to.
    fn selection_write(&self, serial: u32) -> zbus::Result<OwnedFd>;

    fn selection_write_done(&self, serial: u32, success: bool) -> zbus::Result<()>;

    /// The fd to read one representation of the current owner's content from.
    /// Refused for our own content and while another read is pending.
    fn selection_read(&self, mime_type: &str) -> zbus::Result<OwnedFd>;

    fn stop(&self) -> zbus::Result<()>;

    #[zbus(signal)]
    fn selection_owner_changed(&self, options: HashMap<String, OwnedValue>) -> zbus::Result<()>;

    #[zbus(signal)]
    fn selection_transfer(&self, mime_type: String, serial: u32) -> zbus::Result<()>;

    #[zbus(signal)]
    fn closed(&self) -> zbus::Result<()>;
}

/// A `SelectionOwnerChanged` payload, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OwnerChange {
    /// The new owner's types in its advertise order. Empty when there is no
    /// owner: Mutter then sends an options map with **neither** key.
    pub types: Vec<String>,
    /// Whether the new owner is this session's own source.
    pub session_is_owner: bool,
}

pub(crate) fn parse_owner_changed(options: &HashMap<String, OwnedValue>) -> OwnerChange {
    let types = options
        .get("mime-types")
        .and_then(|v| Vec::<String>::try_from(v.clone()).ok())
        .unwrap_or_default();
    let session_is_owner = options
        .get("session-is-owner")
        .and_then(|v| bool::try_from(v).ok())
        .unwrap_or(false);
    OwnerChange {
        types,
        session_is_owner,
    }
}

/// The `options` for `EnableClipboard`/`SetSelection`: only `mime-types`.
pub(crate) fn mime_types_option(types: &[String]) -> HashMap<&'static str, Value<'static>> {
    let mut options = HashMap::new();
    options.insert("mime-types", Value::from(types.to_vec()));
    options
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(pairs: Vec<(&str, Value<'static>)>) -> HashMap<String, OwnedValue> {
        pairs
            .into_iter()
            .map(|(k, v)| (k.to_string(), OwnedValue::try_from(v).unwrap()))
            .collect()
    }

    #[test]
    fn parses_types_and_the_owner_flag() {
        let change = parse_owner_changed(&options(vec![
            ("mime-types", Value::from(vec!["text/html", "text/plain"])),
            ("session-is-owner", Value::from(true)),
        ]));
        assert_eq!(change.types, ["text/html", "text/plain"]);
        assert!(change.session_is_owner);
    }

    #[test]
    fn an_ownerless_change_has_neither_key() {
        // Mutter's `generate_owner_changed_variant` adds no keys at all when
        // the owner is NULL; that must decode as "nothing offered, not ours".
        let change = parse_owner_changed(&HashMap::new());
        assert_eq!(
            change,
            OwnerChange {
                types: vec![],
                session_is_owner: false
            }
        );
    }
}
