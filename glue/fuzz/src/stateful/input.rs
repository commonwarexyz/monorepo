//! The libFuzzer-facing input and its hand-written `Arbitrary`.
//!
//! Structured knobs are drawn first so their weights are explicit and shrinking
//! stays monotone; the remaining bytes become the run's tape, which seeds both
//! the deterministic runtime and every sampler in the harness. The tape is
//! never printed in `Debug` output.

use super::{
    MAX_ADVANCE_STEPS, MAX_MINIMUM_EPOCH, MAX_PROBE_EVENTS, MAX_RAW_PAYLOAD, MAX_REQUIRED_HEIGHTS,
    MAX_SOURCE_HEIGHT, MAX_TERM_LENGTH, NUM_SOURCES, app::FaultArming,
};
use arbitrary::Arbitrary;
use commonware_consensus::types::TermLength;
use commonware_utils::NZU32;
use std::fmt;

/// Largest tape a run consumes.
const MAX_RAW_BYTES: usize = 32_768;

/// Largest restart schedule a run may draw.
const MAX_RESTARTS: u8 = 3;

/// The tape: every byte the structured knobs left, or one zero byte so a run
/// always has entropy to seed from.
fn tape(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    let remaining = u.len().min(MAX_RAW_BYTES);
    if remaining == 0 {
        Ok(vec![0])
    } else {
        Ok(u.bytes(remaining)?.to_vec())
    }
}

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

/// The twins controls, which the database-adapter twins target shares.
struct TwinsControls {
    case_selector: u16,
    sustained: bool,
    faults: FaultArming,
    required_heights: u8,
    term_length: TermLength,
}

impl TwinsControls {
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
        Ok(Self {
            case_selector,
            sustained,
            faults,
            required_heights,
            term_length,
        })
    }
}

impl Arbitrary<'_> for StatefulTwinsFuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let TwinsControls {
            case_selector,
            sustained,
            faults,
            required_heights,
            term_length,
        } = TwinsControls::arbitrary(u)?;
        let raw_bytes = tape(u)?;

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

/// One run of the database-adapter twins target: the twins target's controls
/// over a selected adapter class.
#[derive(Clone)]
pub struct StatefulDbTwinsFuzzInput {
    /// The database every engine manages.
    pub database: DatabaseKind,
    /// Selects one case from the sampled twins scenario set.
    pub case_selector: u16,
    /// Repeat one partition pattern across the adversarial prefix.
    pub sustained: bool,
    /// Which deviations the faulty application may take.
    pub faults: FaultArming,
    /// Heights past the adversarial prefix each correct node must deliver
    /// before the run ends.
    pub required_heights: u8,
    /// Leader term length.
    pub term_length: TermLength,
    /// Byte tape seeding the deterministic runtime, the scenario sampler, and
    /// the fault schedule.
    pub raw_bytes: Vec<u8>,
}

impl StatefulDbTwinsFuzzInput {
    /// Split into the selected adapter and the twins controls it runs under.
    pub(super) fn into_controls(self) -> (DatabaseKind, StatefulTwinsFuzzInput) {
        (
            self.database,
            StatefulTwinsFuzzInput {
                case_selector: self.case_selector,
                sustained: self.sustained,
                faults: self.faults,
                required_heights: self.required_heights,
                term_length: self.term_length,
                raw_bytes: self.raw_bytes,
            },
        )
    }
}

impl fmt::Debug for StatefulDbTwinsFuzzInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatefulDbTwinsFuzzInput")
            .field("database", &self.database)
            .field("case_selector", &self.case_selector)
            .field("sustained", &self.sustained)
            .field("faults", &self.faults)
            .field("required_heights", &self.required_heights)
            .field("term_length", &self.term_length)
            .field("raw_bytes_len", &self.raw_bytes.len())
            .finish()
    }
}

impl Arbitrary<'_> for StatefulDbTwinsFuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let database = u.arbitrary()?;
        let TwinsControls {
            case_selector,
            sustained,
            faults,
            required_heights,
            term_length,
        } = TwinsControls::arbitrary(u)?;
        let raw_bytes = tape(u)?;

        Ok(Self {
            database,
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

impl StatefulRestartsFuzzInput {
    /// Draw the restart controls, which the database-adapter target shares.
    fn controls(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<(u8, TermLength, u8)> {
        let required_heights = u.int_in_range(1..=MAX_REQUIRED_HEIGHTS)?;
        let term_length = TermLength::new(NZU32!(u.int_in_range(1..=MAX_TERM_LENGTH)?));

        // A run with no restart exercises nothing this target exists for, so the
        // schedule always has at least one event.
        let restarts = u.int_in_range(1..=MAX_RESTARTS)?;
        Ok((required_heights, term_length, restarts))
    }
}

impl Arbitrary<'_> for StatefulRestartsFuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let (required_heights, term_length, restarts) = Self::controls(u)?;
        let raw_bytes = tape(u)?;

        Ok(Self {
            required_heights,
            term_length,
            restarts,
            raw_bytes,
        })
    }
}

/// One database-adapter class the database target can select.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatabaseKind {
    /// The `any` adapter: keyed reads and writes.
    Any,
    /// The `current` adapter: keyed reads and writes over a grafted database
    /// whose canonical root differs from its operations root.
    Current,
    /// The journaled immutable adapter: fresh-key inserts.
    ImmutableStandard,
    /// The compact immutable adapter: fresh-key inserts, no historical reads.
    ImmutableCompact,
    /// The journaled keyless adapter: appends.
    KeylessStandard,
    /// The compact keyless adapter: appends, no historical reads.
    KeylessCompact,
}

impl DatabaseKind {
    /// Every adapter class, in selector order.
    pub const ALL: [Self; 6] = [
        Self::Any,
        Self::Current,
        Self::ImmutableStandard,
        Self::ImmutableCompact,
        Self::KeylessStandard,
        Self::KeylessCompact,
    ];
}

impl Arbitrary<'_> for DatabaseKind {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let selector = u.int_in_range(0..=Self::ALL.len() - 1)?;
        Ok(Self::ALL[selector])
    }
}

/// One run of the database-adapter target: the restart target's controls over
/// a selected adapter class.
#[derive(Clone)]
pub struct StatefulDbRestartsFuzzInput {
    /// The database every node manages.
    pub database: DatabaseKind,
    /// Heights each node must apply before the run ends.
    pub required_heights: u8,
    /// Leader term length.
    pub term_length: TermLength,
    /// Number of scheduled crash/restart events over correct identities.
    pub restarts: u8,
    /// Byte tape seeding the deterministic runtime and the restart schedule.
    pub raw_bytes: Vec<u8>,
}

impl StatefulDbRestartsFuzzInput {
    /// Split into the selected adapter and the restart controls it runs under.
    pub(super) fn into_controls(self) -> (DatabaseKind, StatefulRestartsFuzzInput) {
        (
            self.database,
            StatefulRestartsFuzzInput {
                required_heights: self.required_heights,
                term_length: self.term_length,
                restarts: self.restarts,
                raw_bytes: self.raw_bytes,
            },
        )
    }
}

impl fmt::Debug for StatefulDbRestartsFuzzInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatefulDbRestartsFuzzInput")
            .field("database", &self.database)
            .field("required_heights", &self.required_heights)
            .field("term_length", &self.term_length)
            .field("restarts", &self.restarts)
            .field("raw_bytes_len", &self.raw_bytes.len())
            .finish()
    }
}

impl Arbitrary<'_> for StatefulDbRestartsFuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let database = u.arbitrary()?;
        let (required_heights, term_length, restarts) = StatefulRestartsFuzzInput::controls(u)?;
        let raw_bytes = tape(u)?;

        Ok(Self {
            database,
            required_heights,
            term_length,
            restarts,
            raw_bytes,
        })
    }
}

/// One step of the probe target's adversarial event program.
///
/// Sources are numbered `0..NUM_SOURCES`; a node index of zero is the
/// discovering probe and `1..=NUM_SOURCES` its sources. An origin names a
/// source, or the non-member identity when it is `NUM_SOURCES` or more.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeEvent {
    /// Open a floor subscription on the discovering probe.
    Subscribe,
    /// Drop the oldest open floor subscription.
    Unsubscribe,
    /// Attach a node's marshal mailbox to its probe.
    Attach {
        /// The node, modulo the node count.
        node: u8,
    },
    /// Deliver the response most recently captured from a source, from that
    /// source.
    Release {
        /// The source, modulo the source count.
        source: u8,
    },
    /// Deliver a source's captured response again, from that source.
    Duplicate {
        /// The source, modulo the source count.
        source: u8,
    },
    /// Deliver a source's captured response from the non-member identity.
    Replay {
        /// The source, modulo the source count.
        source: u8,
    },
    /// Deliver a strict prefix, possibly empty, of a source's captured
    /// response from that source. Only a response the discovering probe
    /// judges is truncated, so the result is always malformed.
    Truncate {
        /// The source, modulo the source count.
        source: u8,
        /// The prefix length, modulo the response length.
        keep: u8,
    },
    /// Deliver a strict prefix, possibly empty, of a source's captured
    /// response from any identity. Only a response the discovering probe
    /// judges is used, so the result is always malformed.
    Fragment {
        /// The sending identity: a source, or the non-member.
        origin: u8,
        /// The source whose response is used, modulo the source count.
        source: u8,
        /// The prefix length, modulo the response length.
        keep: u8,
    },
    /// Deliver bytes starting like neither message the probe exchanges, from
    /// any identity: malformed by construction. The bytes are shorter than
    /// any encoded response; if they start like a request or a response, or
    /// no response has been captured yet to compare against, nothing is sent.
    Junk {
        /// The sending identity: a source, or the non-member.
        origin: u8,
        /// The bytes, at least one.
        payload: Vec<u8>,
    },
    /// Advance deterministic time, possibly across a retry boundary.
    Advance {
        /// Steps of the probe target's time unit.
        steps: u8,
    },
}

impl Arbitrary<'_> for ProbeEvent {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(0..=9u8)? {
            0 => Self::Subscribe,
            1 => Self::Unsubscribe,
            2 => Self::Attach {
                node: u.int_in_range(0..=NUM_SOURCES)?,
            },
            3 => Self::Release {
                source: u.int_in_range(0..=NUM_SOURCES - 1)?,
            },
            4 => Self::Duplicate {
                source: u.int_in_range(0..=NUM_SOURCES - 1)?,
            },
            5 => Self::Replay {
                source: u.int_in_range(0..=NUM_SOURCES - 1)?,
            },
            6 => Self::Truncate {
                source: u.int_in_range(0..=NUM_SOURCES - 1)?,
                keep: u.arbitrary()?,
            },
            7 => Self::Fragment {
                origin: u.int_in_range(0..=NUM_SOURCES)?,
                source: u.int_in_range(0..=NUM_SOURCES - 1)?,
                keep: u.arbitrary()?,
            },
            8 => {
                let len = u.int_in_range(1..=MAX_RAW_PAYLOAD)?;
                Self::Junk {
                    origin: u.int_in_range(0..=NUM_SOURCES)?,
                    payload: u.bytes(usize::from(len))?.to_vec(),
                }
            }
            _ => Self::Advance {
                steps: u.int_in_range(1..=MAX_ADVANCE_STEPS)?,
            },
        })
    }
}

/// One run of the probe target.
#[derive(Clone)]
pub struct StatefulProbeFuzzInput {
    /// The finalized height each source holds; zero holds none. The height
    /// decides the finalization's epoch, and with it whether the discovering
    /// probe can judge the response and whether it is stale.
    pub sources: [u8; NUM_SOURCES as usize],
    /// Whether each source's history is certified by a committee the
    /// discovering probe does not know, so its responses decode but cannot
    /// verify.
    pub unverifiable: [bool; NUM_SOURCES as usize],
    /// The epoch below which the discovering probe treats responses as stale.
    pub minimum_epoch: u8,
    /// The adversarial event program.
    pub events: Vec<ProbeEvent>,
    /// Byte tape seeding the deterministic runtime.
    pub raw_bytes: Vec<u8>,
}

impl fmt::Debug for StatefulProbeFuzzInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatefulProbeFuzzInput")
            .field("sources", &self.sources)
            .field("unverifiable", &self.unverifiable)
            .field("minimum_epoch", &self.minimum_epoch)
            .field("events", &self.events)
            .field("raw_bytes_len", &self.raw_bytes.len())
            .finish()
    }
}

impl Arbitrary<'_> for StatefulProbeFuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let mut sources = [0u8; NUM_SOURCES as usize];
        for source in &mut sources {
            *source = u.int_in_range(0..=MAX_SOURCE_HEIGHT)?;
        }
        let mut unverifiable = [false; NUM_SOURCES as usize];
        for source in &mut unverifiable {
            *source = u.arbitrary()?;
        }
        let minimum_epoch = u.int_in_range(0..=MAX_MINIMUM_EPOCH)?;
        let count = u.int_in_range(0..=MAX_PROBE_EVENTS)?;
        let events = (0..count)
            .map(|_| u.arbitrary())
            .collect::<arbitrary::Result<Vec<_>>>()?;
        let raw_bytes = tape(u)?;

        Ok(Self {
            sources,
            unverifiable,
            minimum_epoch,
            events,
            raw_bytes,
        })
    }
}
