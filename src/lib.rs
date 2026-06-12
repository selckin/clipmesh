//! Encrypted LAN clipboard mesh: syncs Wayland clipboards across hosts over
//! Noise-NNpsk0-encrypted TCP, keyed by a preshared secret. See README.md.

pub mod clipboard;
pub mod config;
pub mod mesh;
pub mod node;
pub mod peer;
pub mod protocol;
pub mod sync;
pub mod transport;
