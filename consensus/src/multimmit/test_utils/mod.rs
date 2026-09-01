//! Opaque entry points for out-of-crate fuzz and benchmark targets.

#[cfg(all(feature = "mocks", not(target_arch = "wasm32")))]
use {
    super::{
        actors::wire::{
            CertificateMessage, ConsensusMessage, DataMessage, Envelope, EnvelopeConfig,
        },
        config::{CodecConfig, Limits},
    },
    crate::types::Epoch,
    commonware_codec::{Codec, Copying, Decode as _, Encode as _},
    commonware_cryptography::{
        bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    },
    core::fmt::Debug,
};

#[cfg(not(target_arch = "wasm32"))]
pub mod benchmarks {
    pub use super::super::machine::benchmarks::{
        CompletionProfile, JournalScenario, MACHINE_SCALE_BLOCKS_PER_CHAIN,
        MACHINE_SCALE_COMPLETION_PROFILE, MACHINE_SCALE_PARTICIPANTS, MACHINE_SCALE_VIEWS,
        MachineScaleReport, MachineScenario, machine_scale_report, run_journal, run_machine,
    };
}

/// Exercises every private network-plane envelope without exporting its concrete message union.
#[cfg(not(target_arch = "wasm32"))]
pub fn fuzz_wire(input: &[u8]) {
    const MAX_FRAME_BYTES: usize = 1024 * 1024;

    fn roundtrip<M>(input: &[u8], config: &EnvelopeConfig<M::Cfg>)
    where
        M: Codec + PartialEq + Debug,
    {
        if let Ok(envelope) = Envelope::<M>::decode_cfg(Copying(input), config) {
            assert_eq!(envelope.encode().as_ref(), input);
        }
    }

    let codec = CodecConfig::new(6, 2, Limits::new(2, 1).unwrap()).unwrap();
    let epoch = Epoch::new(7);
    roundtrip::<DataMessage<MinPk, Sha256Digest>>(
        input,
        &EnvelopeConfig {
            max_frame_bytes: MAX_FRAME_BYTES,
            epoch,
            payload: (),
        },
    );
    roundtrip::<ConsensusMessage<MinPk, Sha256Digest>>(
        input,
        &EnvelopeConfig {
            max_frame_bytes: MAX_FRAME_BYTES,
            epoch,
            payload: codec,
        },
    );
    roundtrip::<CertificateMessage<MinPk, Sha256Digest>>(
        input,
        &EnvelopeConfig {
            max_frame_bytes: MAX_FRAME_BYTES,
            epoch,
            payload: codec,
        },
    );
}

/// Drives the private deterministic core from a bounded byte schedule.
pub fn fuzz_machine(input: &[u8]) {
    super::machine::tests::test_utils::exercise_world(input);
}

/// Exercises signed certificate transcripts and cached verification against an independent oracle.
pub fn fuzz_artifacts(input: &[u8]) {
    super::machine::tests::artifacts_fuzz::exercise(input);
}

/// Checks incremental vote histories against materialized ancestry and support counts.
pub fn fuzz_algebra(input: &[u8]) {
    super::machine::algebra::fuzz::exercise(input);
}

/// Checks ordered history openings, partial delivery, and replay against an explicit sequence.
#[cfg(not(target_arch = "wasm32"))]
pub fn fuzz_marshal(input: &[u8]) {
    super::marshal::protocol::fuzz::exercise(input);
}

/// Runs one bounded adversarial Twins schedule followed by a fair recovery suffix.
#[cfg(not(target_arch = "wasm32"))]
pub fn fuzz_twins(input: &[u8]) {
    super::twins::fuzz(input);
}
