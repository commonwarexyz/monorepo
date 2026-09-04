//! Test support for the local Multimmit state machine.

/// Deterministic utilities shared by unit tests and fuzz targets.
pub(crate) mod test_utils;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod telemetry;

#[cfg(test)]
include!("machine.rs");
