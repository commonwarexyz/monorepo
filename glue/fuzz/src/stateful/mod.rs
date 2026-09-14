//! Fuzzing for the glue [`commonware_glue::stateful`] module: the
//! [`Stateful`](commonware_glue::stateful::Stateful) actor under twins,
//! restarts, and every QMDB adapter class, and the
//! [`Probe`](commonware_glue::stateful::probe::Probe) actor under adversarial
//! peers. The twins and restart clusters each run once over the `any`
//! backend, with their own corpora, and once over a backend the input
//! selects.
//!
//! In the cluster targets, five engines run over four identities: three
//! correct identities with one engine each, and one compromised identity
//! running two engines that share a signing key. The compromised identity's
//! primary half runs the correct application; its secondary half runs a faulty
//! one. Every engine runs the real stack (Simplex, marshal in the Standard
//! `Deferred` configuration, the real `Stateful` actor, and a QMDB-backed
//! database set). The Twins target uses the `any` backend. The restart targets
//! run four correct identities instead and crash and restart them on a
//! schedule; the database-adapter restart target selects from every supported
//! backend class.
//!
//! The cluster targets check safety only: the correct nodes must agree on the
//! chain, on the database state that chain produces, and on whether a block
//! verifies. No liveness property is asserted and a stalled run is healthy.
//! The probe target checks that every floor the discovering probe emits is
//! justified by valid responses from distinct committee members.
//!
//! # Layout
//!
//! - `input` is the libFuzzer-facing input and its hand-written `Arbitrary`.
//! - `network` splits the compromised identity's channels per the twins scenario.
//! - `app` holds the correct and faulty applications.
//! - `backend` holds the statically dispatched database backends: what differs
//!   between the QMDB adapter classes and nothing else.
//! - `marshal` holds the two marshal variants an engine may run, the standard
//!   `Deferred` wrapper over buffered block broadcast and the coding
//!   `Marshaled` wrapper over shard dissemination, and the type-erased
//!   application and reporter that keep consensus monomorphized once per
//!   variant rather than once per backend and application.
//! - `stack` builds one engine and is the unit a restart rebuilds.
//! - `runner` holds what the cluster drivers share: cluster setup, correct-node
//!   startup and restart, the height waiters, and the measurement point.
//! - `twins` is the byzantine driver: five engines, no crashes. It runs over
//!   the standard marshal and, as its own target, over the coding marshal.
//! - `restarts` is the environment driver: four correct engines, crashed and
//!   restarted on a schedule.
//! - `db_restarts` runs the restart driver over every database backend.
//! - `db_sync` drives a database set through state sync, pruning, replay,
//!   and rewind with no consensus above it, against peers that are
//!   sometimes slow and sometimes serve a divergent history.
//! - `state_sync` is the late-joiner driver: three correct engines run from
//!   genesis, a fourth joins later through peer state sync, and restarts may
//!   interrupt the sync or follow its completion.
//! - `probe` drives the real `Probe` actors through their public boundaries
//!   under an adversarial event program and checks floor provenance.
//! - `invariants` records what each engine delivered, committed, and verified,
//!   and holds the checks.

// A target-specific feature deliberately leaves shared generic support unused.
#![cfg_attr(not(feature = "stateful-all"), allow(dead_code))]

mod app;
mod backend;
#[cfg(feature = "stateful-cert-mock-restarts-db")]
mod db_restarts;
#[cfg(feature = "stateful-db-sync")]
mod db_sync;
mod input;
mod invariants;
mod marshal;
#[cfg(any(
    feature = "stateful-cert-mock-twins",
    feature = "stateful-cert-mock-twins-coding"
))]
mod network;
#[cfg(feature = "stateful-probe")]
mod probe;
#[cfg(any(
    feature = "stateful-cert-mock-restarts",
    feature = "stateful-cert-mock-restarts-db"
))]
mod restarts;
mod runner;
mod stack;
#[cfg(feature = "stateful-cert-mock-state-sync")]
mod state_sync;
#[cfg(any(
    feature = "stateful-cert-mock-twins",
    feature = "stateful-cert-mock-twins-coding"
))]
mod twins;

use commonware_consensus::simplex::{mocks::scheme::Scheme as MockScheme, types::Context};
use commonware_cryptography::{ed25519, sha256};
use commonware_utils::{NZU16, NZU64, NZUsize};
#[cfg(feature = "stateful-cert-mock-restarts-db")]
pub use db_restarts::{fuzz_stateful_cert_mock_restarts_db, run_stateful_db_restarts};
#[cfg(feature = "stateful-db-sync")]
pub use db_sync::{DbSyncReport, SyncOutcome, fuzz_stateful_db_sync, run_stateful_db_sync};
pub use input::{
    DatabaseKind, PeerControls, ProbeEvent, PruneControls, SetShape, StatefulDbRestartsFuzzInput,
    StatefulDbSyncFuzzInput, StatefulProbeFuzzInput, StatefulRestartsFuzzInput,
    StatefulStateSyncFuzzInput, StatefulTwinsFuzzInput, SyncControls,
};
pub use invariants::Counts;
use marshal::Marshal;
#[cfg(feature = "stateful-probe")]
pub use probe::{ProbeReport, fuzz_stateful_probe, run_stateful_probe};
#[cfg(any(
    feature = "stateful-cert-mock-restarts",
    feature = "stateful-cert-mock-restarts-db"
))]
pub use restarts::{fuzz_stateful_cert_mock_restarts, run_stateful_restarts};
pub use runner::{Outcome, RunReport};
#[cfg(feature = "stateful-cert-mock-state-sync")]
pub use state_sync::{fuzz_stateful_cert_mock_state_sync, run_stateful_state_sync};
use std::{
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    time::Duration,
};
#[cfg(feature = "stateful-cert-mock-twins")]
pub use twins::{fuzz_stateful_cert_mock_twins, run_stateful_twins};
#[cfg(feature = "stateful-cert-mock-twins-coding")]
pub use twins::{fuzz_stateful_cert_mock_twins_coding, run_stateful_twins_coding};

/// Identity key type.
pub(crate) type PublicKey = ed25519::PublicKey;

/// Block and state digest type.
pub(crate) type Digest = sha256::Digest;

/// The mock certificate scheme. No real cryptography is used in the
/// signing or certificate path.
///
/// Non-attributable: the twins pair equivocates by construction, and this
/// harness has no use for the fault evidence attribution would produce.
pub(crate) type Scheme = MockScheme<PublicKey, false>;

/// The consensus context embedded in every block: the payload votes and
/// certificates name is the marshal variant's.
type Ctx<M> = Context<<M as Marshal>::Payload, PublicKey>;

/// Namespace for the mock certificate scheme fixture.
pub(crate) const NAMESPACE: &[u8] = b"glue_fuzz_stateful";

/// Identities in the validator set. Quorum is three of four.
pub(crate) const NUM_IDENTITIES: u32 = 4;

/// Adversarial twins rounds before the synchronous suffix.
pub(crate) const PREFIX_ROUNDS: usize = 3;

/// Upper bound on the suffix heights a run may require. The exact number
/// is drawn per run; reaching it is not required, since the run is also bounded.
pub(crate) const MAX_REQUIRED_HEIGHTS: u8 = 10;

/// Longest leader term a run may draw.
pub(crate) const MAX_TERM_LENGTH: u32 = 4;

/// Most finalized blocks between pruning attempts a restart run may draw.
pub(crate) const MAX_MAINTENANCE_INTERVAL: u8 = 8;

/// Most finalized blocks a restart run may retain beyond the acknowledgement
/// window before pruning.
pub(crate) const MAX_RETAINED_BLOCKS: u8 = 6;

/// Most heights the state-sync target's serving nodes apply before the
/// joiner starts.
pub(crate) const MAX_JOIN_AFTER: u8 = 6;

/// The unit of the state-sync target's joiner crash delay.
pub(crate) const JOINER_CRASH_STEP: Duration = Duration::from_millis(10);

/// Most crash-delay steps the state-sync target's joiner may be given.
pub(crate) const MAX_JOINER_CRASH_STEPS: u8 = 40;

/// Most heights the database-set target's serving set applies before the
/// sync starts.
pub(crate) const MAX_SERVED_HEIGHTS: u8 = 8;

/// Most heights the database-set target's serving set applies while the sync
/// runs.
pub(crate) const MAX_EXTRA_HEIGHTS: u8 = 6;

/// Most heights the database-set target's serving set applies after the
/// sync converges.
pub(crate) const MAX_POST_HEIGHTS: u8 = 4;

/// Largest fetch or apply batch the database-set target syncs in.
pub(crate) const MAX_SYNC_BATCH: u64 = 16;

/// Answers in a peer's schedule before it repeats.
pub(crate) const PEER_SCHEDULE_LEN: usize = 32;

/// How long a delayed peer answer waits.
pub(crate) const PEER_DELAY: Duration = Duration::from_millis(50);

/// The unit of the tape-driven pause before each height served during a
/// sync.
pub(crate) const TIP_UPDATE_DELAY: Duration = Duration::from_millis(100);

/// Bound on the simulated duration of a database-set sync. Unlike the
/// cluster targets, reaching it is a failure: the peers answer honestly
/// eventually and the history is finite, so the coordinator must converge.
pub(crate) const SYNC_RUN_TIMEOUT: Duration = Duration::from_secs(600);

/// Bound on the simulated duration of a run. The run normally ends when
/// every correct node has delivered its required suffix heights; this bound
/// exists so a stalled cluster still terminates, and a run that hits it is
/// healthy, not a failure.
pub(crate) const RUN_TIMEOUT: Duration = Duration::from_secs(30);

/// Twins cases sampled before one is selected.
pub(crate) const MAX_CASES: usize = 64;

/// Storage page size.
pub(crate) const PAGE_SIZE: NonZeroU16 = NZU16!(1024);

/// Storage page cache size.
pub(crate) const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(8);

/// Storage read/write buffer size.
pub(crate) const IO_BUFFER_SIZE: NonZeroUsize = NZUsize!(1024);

/// QMDB write buffer size.
pub(crate) const QMDB_INIT_BUFFER: NonZeroUsize = NZUsize!(1 << 12);

/// QMDB cache size.
pub(crate) const QMDB_INIT_CACHE: NonZeroUsize = NZUsize!(64);

/// Actor mailbox capacity.
pub(crate) const MAILBOX_SIZE: NonZeroUsize = NZUsize!(100);

/// Epoch length. One epoch spans the whole run, so no engine crosses an epoch
/// boundary.
pub(crate) const EPOCH_LENGTH: NonZeroU64 = NZU64!(u64::MAX);

/// Simulated downtime between a crash and the matching restart.
pub(crate) const RESTART_DOWNTIME: Duration = Duration::from_millis(500);

/// Source probes in the probe target. With the discovering probe they form the
/// four-member committee, so `f + 1` is two.
pub(crate) const NUM_SOURCES: u8 = 3;

/// Highest finalized height a probe source may hold.
pub(crate) const MAX_SOURCE_HEIGHT: u8 = 5;

/// Heights per epoch in the probe target, so the source heights span three
/// epochs: heights 1 fall in epoch 0, 2 and 3 in epoch 1, 4 and 5 in epoch 2.
pub(crate) const PROBE_EPOCH_LENGTH: NonZeroU64 = NZU64!(2);

/// Epochs the discovering probe's provider can verify: 0 and 1. A
/// finalization from epoch 2 is unjudgeable.
pub(crate) const PROBE_KNOWN_EPOCHS: u64 = 2;

/// Highest minimum epoch a probe run may configure. At 1, epoch-0
/// finalizations are stale.
pub(crate) const MAX_MINIMUM_EPOCH: u8 = 1;

/// Longest event program a probe run may draw.
pub(crate) const MAX_PROBE_EVENTS: u8 = 24;

/// Largest junk payload a probe event may deliver. It is shorter than any
/// encoded response, so junk is never mistaken for a valid one.
pub(crate) const MAX_RAW_PAYLOAD: u8 = 32;

/// Most time steps one probe event may advance.
pub(crate) const MAX_ADVANCE_STEPS: u8 = 15;

/// The probe target's time unit: what one advance step spans, and how long
/// every event lets the actors settle.
pub(crate) const PROBE_STEP: Duration = Duration::from_millis(100);

/// How long the discovering probe waits for replies before re-requesting:
/// ten event settles and well within one advance, offset by a millisecond so
/// a retry never coincides with an event boundary.
pub(crate) const PROBE_RETRY_TIMEOUT: Duration = Duration::from_millis(1001);

/// Bound on the simulated duration of a probe run.
pub(crate) const PROBE_RUN_TIMEOUT: Duration = Duration::from_secs(20);
