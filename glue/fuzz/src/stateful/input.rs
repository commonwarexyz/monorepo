//! The libFuzzer-facing input and its hand-written `Arbitrary`.
//!
//! Structured knobs are drawn first so their weights are explicit and shrinking
//! stays monotone; the remaining bytes become the run's tape, which seeds both
//! the deterministic runtime and every sampler in the harness. The tape is
//! never printed in `Debug` output.

use super::{
    MAX_ADVANCE_STEPS, MAX_EXTRA_HEIGHTS, MAX_JOIN_AFTER, MAX_JOINER_CRASH_STEPS,
    MAX_MAINTENANCE_INTERVAL, MAX_MINIMUM_EPOCH, MAX_POST_HEIGHTS, MAX_PROBE_EVENTS,
    MAX_RAW_PAYLOAD, MAX_REQUIRED_HEIGHTS, MAX_RETAINED_BLOCKS, MAX_SERVED_HEIGHTS,
    MAX_SOURCE_HEIGHT, MAX_SYNC_BATCH, MAX_TERM_LENGTH, NUM_SOURCES, app::FaultArming,
};
use arbitrary::Arbitrary;
use commonware_consensus::types::TermLength;
use commonware_glue::stateful::PruneConfig;
use commonware_utils::{NZU32, NZU64, NZUsize};
use std::{fmt, num::NonZeroU64};

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

/// The bounded controls decoded before the twins target's byte tape.
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

/// The periodic pruning every node in a restart run performs.
///
/// The stateful actor prunes marshal and QMDB history behind its
/// acknowledgement window; the retention windows here are what it keeps
/// beyond that. QMDB retention never exceeds marshal retention, which the
/// actor asserts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PruneControls {
    /// Finalized blocks between pruning attempts.
    pub maintenance_interval: u8,
    /// Finalized blocks retained in marshal beyond the acknowledgement window.
    pub retained_marshal_blocks: u8,
    /// Finalized blocks' worth of operations retained in QMDB beyond the
    /// acknowledgement window, at most `retained_marshal_blocks`.
    pub retained_qmdb_blocks: u8,
}

impl PruneControls {
    /// The actor configuration these controls name.
    pub fn config(self) -> PruneConfig {
        PruneConfig {
            maintenance_interval: NZUsize!(usize::from(self.maintenance_interval)),
            retained_marshal_blocks: usize::from(self.retained_marshal_blocks),
            retained_qmdb_blocks: usize::from(self.retained_qmdb_blocks),
        }
    }
}

impl Arbitrary<'_> for PruneControls {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let maintenance_interval = u.int_in_range(1..=MAX_MAINTENANCE_INTERVAL)?;
        let retained_marshal_blocks = u.int_in_range(0..=MAX_RETAINED_BLOCKS)?;
        let retained_qmdb_blocks = u.int_in_range(0..=retained_marshal_blocks)?;
        Ok(Self {
            maintenance_interval,
            retained_marshal_blocks,
            retained_qmdb_blocks,
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
    /// Periodic pruning, or none.
    pub prune: Option<PruneControls>,
    /// Byte tape seeding the deterministic runtime and the restart schedule.
    pub raw_bytes: Vec<u8>,
}

impl fmt::Debug for StatefulRestartsFuzzInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatefulRestartsFuzzInput")
            .field("required_heights", &self.required_heights)
            .field("term_length", &self.term_length)
            .field("restarts", &self.restarts)
            .field("prune", &self.prune)
            .field("raw_bytes_len", &self.raw_bytes.len())
            .finish()
    }
}

/// The bounded controls decoded before a restart run's byte tape.
pub(super) struct RestartControls {
    pub(super) required_heights: u8,
    pub(super) term_length: TermLength,
    pub(super) restarts: u8,
    pub(super) prune: Option<PruneControls>,
}

impl RestartControls {
    /// Draw the restart controls, which the database-adapter target shares.
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let required_heights = u.int_in_range(1..=MAX_REQUIRED_HEIGHTS)?;
        let term_length = TermLength::new(NZU32!(u.int_in_range(1..=MAX_TERM_LENGTH)?));

        // A run with no restart exercises nothing this target exists for, so the
        // schedule always has at least one event.
        let restarts = u.int_in_range(1..=MAX_RESTARTS)?;

        // Pruning stays on unless the input turns it off, so the prune path
        // keeps its reach as the surrounding axes mutate.
        let prune = if u.int_in_range(0..=7)? == 7 {
            None
        } else {
            Some(u.arbitrary()?)
        };
        Ok(Self {
            required_heights,
            term_length,
            restarts,
            prune,
        })
    }
}

impl Arbitrary<'_> for StatefulRestartsFuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let RestartControls {
            required_heights,
            term_length,
            restarts,
            prune,
        } = RestartControls::arbitrary(u)?;
        let raw_bytes = tape(u)?;

        Ok(Self {
            required_heights,
            term_length,
            restarts,
            prune,
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
    /// Periodic pruning, or none.
    pub prune: Option<PruneControls>,
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
                prune: self.prune,
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
            .field("prune", &self.prune)
            .field("raw_bytes_len", &self.raw_bytes.len())
            .finish()
    }
}

impl Arbitrary<'_> for StatefulDbRestartsFuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let database = u.arbitrary()?;
        let RestartControls {
            required_heights,
            term_length,
            restarts,
            prune,
        } = RestartControls::arbitrary(u)?;
        let raw_bytes = tape(u)?;

        Ok(Self {
            database,
            required_heights,
            term_length,
            restarts,
            prune,
            raw_bytes,
        })
    }
}

/// One run of the state-sync target: three serving nodes, a late joiner
/// that peer syncs, and restarts over all of them.
#[derive(Clone)]
pub struct StatefulStateSyncFuzzInput {
    /// Heights each node, the joiner included, must apply before the run
    /// ends.
    pub required_heights: u8,
    /// Leader term length.
    pub term_length: TermLength,
    /// Heights the serving nodes apply before the joiner starts.
    pub join_after: u8,
    /// Operations the joiner fetches and applies per sync step.
    pub sync_batch: NonZeroU64,
    /// Crash the joiner this many steps of ten simulated milliseconds after
    /// it starts, before the general restart schedule, so a sync in flight is
    /// interrupted and must resume.
    pub joiner_crash: Option<u8>,
    /// Number of scheduled crash/restart events over every node.
    pub restarts: u8,
    /// Periodic pruning on every node, or none.
    pub prune: Option<PruneControls>,
    /// Byte tape seeding the deterministic runtime and the restart schedule.
    pub raw_bytes: Vec<u8>,
}

impl fmt::Debug for StatefulStateSyncFuzzInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatefulStateSyncFuzzInput")
            .field("required_heights", &self.required_heights)
            .field("term_length", &self.term_length)
            .field("join_after", &self.join_after)
            .field("sync_batch", &self.sync_batch)
            .field("joiner_crash", &self.joiner_crash)
            .field("restarts", &self.restarts)
            .field("prune", &self.prune)
            .field("raw_bytes_len", &self.raw_bytes.len())
            .finish()
    }
}

impl Arbitrary<'_> for StatefulStateSyncFuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let required_heights = u.int_in_range(1..=MAX_REQUIRED_HEIGHTS)?;
        let term_length = TermLength::new(NZU32!(u.int_in_range(1..=MAX_TERM_LENGTH)?));
        let join_after = u.int_in_range(1..=MAX_JOIN_AFTER)?;
        let sync_batch = NZU64!(u.int_in_range(1..=MAX_SYNC_BATCH)?);
        let joiner_crash = if u.arbitrary()? {
            Some(u.int_in_range(0..=MAX_JOINER_CRASH_STEPS)?)
        } else {
            None
        };
        let restarts = u.int_in_range(0..=MAX_RESTARTS)?;

        // Pruning competes with serving the joiner, so half the runs prune.
        let prune = if u.arbitrary()? {
            Some(u.arbitrary()?)
        } else {
            None
        };
        let raw_bytes = tape(u)?;
        Ok(Self {
            required_heights,
            term_length,
            join_after,
            sync_batch,
            joiner_crash,
            restarts,
            prune,
            raw_bytes,
        })
    }
}

/// One shape of database set the database-set target can sync.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetShape {
    /// A single database of one adapter class.
    Single(DatabaseKind),
    /// An `any` database beside a compact immutable one.
    Pair,
    /// A `current` database beside a journaled and a compact keyless one.
    Triple,
}

impl SetShape {
    /// Every shape, in selector order.
    pub const ALL: [Self; 8] = [
        Self::Single(DatabaseKind::Any),
        Self::Single(DatabaseKind::Current),
        Self::Single(DatabaseKind::ImmutableStandard),
        Self::Single(DatabaseKind::ImmutableCompact),
        Self::Single(DatabaseKind::KeylessStandard),
        Self::Single(DatabaseKind::KeylessCompact),
        Self::Pair,
        Self::Triple,
    ];
}

impl Arbitrary<'_> for SetShape {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let selector = u.int_in_range(0..=Self::ALL.len() - 1)?;
        Ok(Self::ALL[selector])
    }
}

/// The sync engine tuning a database-set run syncs under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncControls {
    /// Operations fetched per request.
    pub fetch_batch_size: NonZeroU64,
    /// Operations applied per local step.
    pub apply_batch_size: NonZeroU64,
    /// Outstanding requests at once.
    pub max_outstanding_requests: u8,
    /// Capacity of the per-database target-update channels and of the tip
    /// update channel feeding the coordinator.
    pub update_channel_size: u8,
    /// Historical roots retained for proof verification across target
    /// updates.
    pub max_retained_roots: u8,
}

impl Arbitrary<'_> for SyncControls {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            fetch_batch_size: NZU64!(u.int_in_range(1..=MAX_SYNC_BATCH)?),
            apply_batch_size: NZU64!(u.int_in_range(1..=MAX_SYNC_BATCH)?),
            max_outstanding_requests: u.int_in_range(1..=4)?,
            update_channel_size: u.int_in_range(1..=4)?,
            max_retained_roots: u.int_in_range(1..=8)?,
        })
    }
}

/// How the peers of a database-set run answer, as densities out of eight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerControls {
    /// Answers served from the divergent set.
    pub divergent: u8,
    /// Answers served after a delay.
    pub delayed: u8,
}

impl Arbitrary<'_> for PeerControls {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            divergent: u.int_in_range(0..=4)?,
            delayed: u.int_in_range(0..=4)?,
        })
    }
}

/// One run of the database-set target: a state sync of one set shape from a
/// serving set, followed by pruning, replay, and rewind of the result.
#[derive(Clone)]
pub struct StatefulDbSyncFuzzInput {
    /// The set shape to sync.
    pub shape: SetShape,
    /// Heights the serving set applies before the sync starts.
    pub served_heights: u8,
    /// Heights the serving set applies while the sync runs.
    pub extra_heights: u8,
    /// Heights the serving set applies after the sync converges, for the
    /// synced set to reproduce.
    pub post_heights: u8,
    /// Sync engine tuning.
    pub sync: SyncControls,
    /// Peer answer densities.
    pub peer: PeerControls,
    /// Byte tape seeding the deterministic runtime, the peer schedule, and
    /// the tip update schedule.
    pub raw_bytes: Vec<u8>,
}

impl fmt::Debug for StatefulDbSyncFuzzInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatefulDbSyncFuzzInput")
            .field("shape", &self.shape)
            .field("served_heights", &self.served_heights)
            .field("extra_heights", &self.extra_heights)
            .field("post_heights", &self.post_heights)
            .field("sync", &self.sync)
            .field("peer", &self.peer)
            .field("raw_bytes_len", &self.raw_bytes.len())
            .finish()
    }
}

impl Arbitrary<'_> for StatefulDbSyncFuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let shape = u.arbitrary()?;
        let served_heights = u.int_in_range(1..=MAX_SERVED_HEIGHTS)?;
        let extra_heights = u.int_in_range(0..=MAX_EXTRA_HEIGHTS)?;
        let post_heights = u.int_in_range(0..=MAX_POST_HEIGHTS)?;
        let sync = u.arbitrary()?;
        let peer = u.arbitrary()?;
        let raw_bytes = tape(u)?;
        Ok(Self {
            shape,
            served_heights,
            extra_heights,
            post_heights,
            sync,
            peer,
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
