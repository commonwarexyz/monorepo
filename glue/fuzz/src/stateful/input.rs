//! The libFuzzer-facing input and its hand-written `Arbitrary`.
//!
//! Structured knobs are drawn first so their weights are explicit and shrinking
//! stays monotone; the remaining bytes become the run's tape, which seeds both
//! the deterministic runtime and every sampler in the harness. The tape is
//! never printed in `Debug` output.

use super::{MAX_REQUIRED_HEIGHTS, MAX_TERM_LENGTH, app::FaultArming};
use arbitrary::Arbitrary;
use commonware_consensus::types::TermLength;
use commonware_utils::NZU32;
use std::fmt;

/// Largest tape a run consumes.
const MAX_RAW_BYTES: usize = 32_768;

/// Largest restart schedule a run may draw.
const MAX_RESTARTS: u8 = 3;

/// One run of the stateful twins target.
#[derive(Clone)]
pub struct StatefulTwinsFuzzInput {
    /// Selects one case from the sampled twins scenario set.
    pub case_selector: u16,
    /// Repeat one partition pattern across the adversarial prefix.
    pub sustained: bool,
    /// Which deviations the faulty application may take.
    pub faults: FaultArming,
    /// Heights past the adversarial prefix each correct node must deliver
    /// before the run ends.
    pub required_heights: u8,
    /// Leader term length. A term longer than one view makes the scenario's
    /// scripted leader stable across several views.
    pub term_length: TermLength,
    /// Byte tape seeding the deterministic runtime, the scenario sampler, the
    /// fault schedule, and the restart schedule.
    pub raw_bytes: Vec<u8>,
}

impl fmt::Debug for StatefulTwinsFuzzInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatefulTwinsFuzzInput")
            .field("case_selector", &self.case_selector)
            .field("sustained", &self.sustained)
            .field("faults", &self.faults)
            .field("required_heights", &self.required_heights)
            .field("term_length", &self.term_length)
            .field("raw_bytes_len", &self.raw_bytes.len())
            .finish()
    }
}

impl Arbitrary<'_> for StatefulTwinsFuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let case_selector = u.arbitrary()?;
        let sustained = u.arbitrary()?;

        // Every deviation stays armed unless the input turns it off, so the
        // adversary keeps its reach as the surrounding axes mutate.
        let mut armed = || u.int_in_range(0..=9).map(|sample| sample != 9);
        let faults = FaultArming {
            reject_verification: armed()?,
            abstain_verification: armed()?,
            divergent_proposal: armed()?,
            decline_proposal: armed()?,
        };

        let required_heights = u.int_in_range(1..=MAX_REQUIRED_HEIGHTS)?;
        let term_length = TermLength::new(NZU32!(u.int_in_range(1..=MAX_TERM_LENGTH)?));

        let remaining = u.len().min(MAX_RAW_BYTES);
        let raw_bytes = if remaining == 0 {
            vec![0]
        } else {
            u.bytes(remaining)?.to_vec()
        };

        Ok(Self {
            case_selector,
            sustained,
            faults,
            required_heights,
            term_length,
            raw_bytes,
        })
    }
}

/// One run of the stateful restart target.
///
/// Every identity is correct here; the only fault is environmental.
#[derive(Clone)]
pub struct StatefulRestartsFuzzInput {
    /// Heights each node must apply before the run ends.
    pub required_heights: u8,
    /// Leader term length.
    pub term_length: TermLength,
    /// Number of scheduled crash/restart events over correct identities.
    pub restarts: u8,
    /// Byte tape seeding the deterministic runtime and the restart schedule.
    pub raw_bytes: Vec<u8>,
}

impl fmt::Debug for StatefulRestartsFuzzInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatefulRestartsFuzzInput")
            .field("required_heights", &self.required_heights)
            .field("term_length", &self.term_length)
            .field("restarts", &self.restarts)
            .field("raw_bytes_len", &self.raw_bytes.len())
            .finish()
    }
}

impl Arbitrary<'_> for StatefulRestartsFuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let required_heights = u.int_in_range(1..=MAX_REQUIRED_HEIGHTS)?;
        let term_length = TermLength::new(NZU32!(u.int_in_range(1..=MAX_TERM_LENGTH)?));

        // A run with no restart exercises nothing this target exists for, so the
        // schedule always has at least one event.
        let restarts = u.int_in_range(1..=MAX_RESTARTS)?;

        let remaining = u.len().min(MAX_RAW_BYTES);
        let raw_bytes = if remaining == 0 {
            vec![0]
        } else {
            u.bytes(remaining)?.to_vec()
        };

        Ok(Self {
            required_heights,
            term_length,
            restarts,
            raw_bytes,
        })
    }
}
