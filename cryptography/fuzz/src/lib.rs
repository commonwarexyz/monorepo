//! Shared fuzz drivers for `commonware-cryptography`.
//!
//! Generic, setting-parametrized drivers live here so that thin per-setting
//! binaries under `fuzz_targets/` only need to monomorphize them.

pub mod certificate;
