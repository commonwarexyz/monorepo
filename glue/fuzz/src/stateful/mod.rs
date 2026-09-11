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
//! - `stack` builds one engine and is the unit a restart rebuilds.
//! - `runner` holds what the cluster drivers share: cluster setup, correct-node
//!   startup and restart, the height waiters, and the measurement point.
//! - `twins` is the byzantine driver: five engines, no crashes.
//! - `restarts` is the environment driver: four correct engines, crashed and
//!   restarted on a schedule.
//! - `db_restarts` runs the restart driver over every database backend.
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
mod input;
mod invariants;
#[cfg(feature = "stateful-cert-mock-twins")]
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
#[cfg(feature = "stateful-cert-mock-twins")]
mod twins;

use commonware_consensus::simplex::{mocks::scheme::Scheme as MockScheme, types::Context};
use commonware_cryptography::{ed25519, sha256};
use commonware_utils::{NZU16, NZU64, NZUsize};
#[cfg(feature = "stateful-cert-mock-restarts-db")]
pub use db_restarts::{fuzz_stateful_cert_mock_restarts_db, run_stateful_db_restarts};
pub use input::{
    DatabaseKind, ProbeEvent, StatefulDbRestartsFuzzInput, StatefulProbeFuzzInput,
    StatefulRestartsFuzzInput, StatefulTwinsFuzzInput,
};
pub use invariants::Counts;
#[cfg(feature = "stateful-probe")]
pub use probe::{ProbeReport, fuzz_stateful_probe, run_stateful_probe};
#[cfg(any(
    feature = "stateful-cert-mock-restarts",
    feature = "stateful-cert-mock-restarts-db"
))]
pub use restarts::{fuzz_stateful_cert_mock_restarts, run_stateful_restarts};
pub use runner::{Outcome, RunReport};
use std::{
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    time::Duration,
};
#[cfg(feature = "stateful-cert-mock-twins")]
pub use twins::{fuzz_stateful_cert_mock_twins, run_stateful_twins};

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

/// The consensus context embedded in every block.
pub(crate) type Ctx = Context<Digest, PublicKey>;

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
