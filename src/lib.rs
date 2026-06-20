//! Encrypted LAN clipboard mesh: syncs Wayland clipboards across hosts over
//! Noise-NNpsk0-encrypted TCP, keyed by a preshared secret. See README.md.

pub mod backoff;
pub mod clipboard;
pub mod config;
pub mod config_template;
pub mod fsutil;
pub mod fswatch;
pub mod mesh;
pub mod mime;
pub mod node;
pub mod peer;
pub mod protocol;
pub mod sync;
pub mod transport;
