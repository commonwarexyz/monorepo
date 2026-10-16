//! Opaque entry points for out-of-crate fuzz and benchmark targets.
//!
//! They exercise production Multimmit mechanisms without exposing the private core lifecycle.

pub use super::config::profile::ResourceLimits;
use super::{
    Inspection,
    config::{Error as ConfigError, Profile, Protocol, Role, Tuning},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};

mod bench;
mod view;

/// Benchmark scenarios over the private core, storage, the extraction algebra, and complete
/// engines.
///
/// The benchmark targets build outside this crate and cannot name the crate-private machine,
/// journal, or algebra, so this module re-exports only the scenario drivers and their reports.
pub mod benchmarks {
    pub use super::{
        super::storage::bench::{JournalScenario, run_journal},
        bench::{
            ENGINE_BLOCKS_PER_CHAIN, ENGINE_NODES, ENGINE_VIEW_ADVANCE, EngineReport, EngineRun,
            HotPathOperations, MACHINE_VIEWS, MachineScenario, STREAM_CAP, STREAM_PARTICIPANTS,
            STREAM_TICKS, STREAM_VIEWS, STREAM_VQCS, Script, Stream, StreamReport,
            engine_parameters, run_engine_profile, run_machine, run_stream,
        },
        view::{AttestedVote, ViewScenario, VoteShape},
    };
}

/// Exercises every private network-plane envelope without exporting its concrete message union.
pub fn fuzz_wire(input: &[u8]) {
    super::wire::fuzz::exercise(input);
}

/// Exercises signed certificate transcripts and cached verification against an independent oracle.
pub fn fuzz_artifacts(input: &[u8]) {
    super::scheme::fuzz::exercise(input);
}

/// Checks the extraction and ordering algebra against its naive reference on random producer
/// forests and vote mixes.
pub fn fuzz_algebra(input: &[u8]) {
    super::algebra::fuzz::exercise(input);
}

/// Checks ordered history openings, partial delivery, and replay against an explicit enumeration
/// of the order.
pub fn fuzz_marshal(input: &[u8]) {
    super::marshal::fuzz::exercise(input);
}

/// Runs six correct production machines on the schedule `input` encodes, one choice per byte, then
/// a fair suffix, checking delivered-order agreement, write-once resolution, floors, one statement
/// per signing slot, and journal replay.
pub fn fuzz_machine(input: &[u8]) {
    super::machine::world::exercise(input);
}

/// Runs a twins campaign at `n = 6, f = 1` that `input` encodes: the Byzantine participant runs as
/// two equivocating halves split between the correct nodes, which must stay safe, never quarantine
/// a correct participant, and keep finalizing.
pub fn fuzz_twins(input: &[u8]) {
    super::twins::exercise(input);
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
