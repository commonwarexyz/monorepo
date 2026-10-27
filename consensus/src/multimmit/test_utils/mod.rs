//! Opaque entry points for out-of-crate fuzz and benchmark targets.
//!
//! They exercise production Multimmit mechanisms without exposing the private core lifecycle.

pub use super::config::profile::ResourceLimits;
use super::{
    Inspection,
    config::{Error as ConfigError, Profile, Protocol, Role, Tuning},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};

#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod bench;

/// Benchmark scenarios over the private core.
///
/// The benchmark targets build outside this crate and cannot name the crate-private machine, so
/// this module re-exports only the scenario drivers and the reports they return.
pub mod benchmarks {
    pub use super::{
        super::storage::bench::{JournalScenario, run_journal},
        bench::{
            CompletionProfile, ENGINE_BLOCKS_PER_CHAIN, ENGINE_NODES, ENGINE_VIEW_ADVANCE,
            EngineReport, EngineRun, HotPathOperations, IdleOperations,
            MACHINE_SCALE_BLOCKS_PER_CHAIN, MACHINE_SCALE_COMPLETION_PROFILE,
            MACHINE_SCALE_PARTICIPANTS, MACHINE_SCALE_VIEWS, MachineScaleReport, MachineScenario,
            engine_parameters, machine_scale_report, run_engine_profile, run_machine,
        },
    };
}

/// Exercises every private network-plane envelope without exporting its concrete message union.
pub fn fuzz_wire(input: &[u8]) {
    super::wire::fuzz::exercise(input);
}

/// Drives the private deterministic core from a bounded byte schedule.
pub fn fuzz_machine(input: &[u8]) {
    super::machine::testing::world::fuzz::exercise(input);
}

/// Exercises signed certificate transcripts and cached verification against an independent oracle.
pub fn fuzz_artifacts(input: &[u8]) {
    super::scheme::fuzz::exercise(input);
}

/// Checks incremental vote histories against materialized ancestry and support counts.
pub fn fuzz_algebra(input: &[u8]) {
    super::algebra::fuzz::exercise(input);
}

/// Checks ordered history openings, partial delivery, and replay against an explicit sequence.
pub fn fuzz_marshal(input: &[u8]) {
    super::marshal::fuzz::exercise(input);
}

/// Runs one bounded adversarial Twins schedule followed by a fair recovery suffix.
pub fn fuzz_twins(input: &[u8]) {
    super::twins::randomized::exercise(input);
}

/// Returns the acknowledged journal cursor behind `inspection`, which never decreases for one
/// node, including across restarts.
pub const fn inspection_cursor<D: Digest>(inspection: &Inspection<D>) -> u64 {
    inspection.cursor().get()
}

/// Returns the completion-correlation generation behind `inspection`, which never decreases for
/// one node, including across restarts.
pub const fn inspection_generation<D: Digest>(inspection: &Inspection<D>) -> u64 {
    inspection.generation().get()
}

/// Returns the resource limits an engine derives from `tuning` under `protocol`.
///
/// # Errors
///
/// Returns an error when `tuning` is invalid for `protocol`.
pub fn resource_limits<H: Hasher, V: Variant>(
    protocol: Protocol<H::Digest>,
    tuning: Tuning,
) -> Result<ResourceLimits, ConfigError> {
    Ok(Profile::new::<V>(protocol, Role::Observer, tuning)?.resources())
}
