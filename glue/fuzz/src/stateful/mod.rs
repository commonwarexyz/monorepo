//! Twins fuzzing for the glue [`commonware_glue::stateful::Stateful`] actor.
//!
//! Five engines run over four identities: three correct identities with one
//! engine each, and one compromised identity running two engines that share a
//! signing key. The compromised identity's primary half runs the correct
//! application; its secondary half runs a faulty one. Every engine runs the
//! real stack (Simplex, marshal in the Standard `Deferred` configuration, the
//! real `Stateful` actor, and a QMDB-backed database set).
//!
//! The target checks safety only: the correct nodes must agree on the chain,
//! on the database state that chain produces, and on whether a block verifies.
//! No liveness property is asserted and a stalled run is healthy.
//!
//! # Layout
//!
//! - `input` is the libFuzzer-facing input and its hand-written `Arbitrary`.
//! - `network` splits the compromised identity's channels per the twins scenario.
//! - `app` holds the correct and faulty applications.
//! - `stack` builds one engine and is the unit a restart rebuilds.
//! - `runner` selects the scenario, starts the engines, schedules restarts, and
//!   drives the run to its measurement point.
//! - `invariants` records what each engine delivered, committed, and verified,
//!   and holds the checks.

mod app;
mod input;
mod invariants;
mod network;
mod runner;
mod stack;

use commonware_consensus::simplex::{mocks::scheme::Scheme as MockScheme, types::Context};
use commonware_cryptography::{Sha256, ed25519, sha256};
use commonware_glue::stateful::db::Shared;
use commonware_parallel::Sequential;
use commonware_runtime::deterministic;
use commonware_storage::{mmr, qmdb::any::unordered::fixed, translator::TwoCap};
use commonware_utils::{NZU16, NZU64, NZUsize};
pub use input::StatefulTwinsFuzzInput;
pub use invariants::Counts;
pub use runner::{Outcome, RunReport, fuzz_stateful_cert_mock_twins, run_stateful_twins};
use std::{
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    time::Duration,
};

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

/// The single QMDB database every node manages.
pub(crate) type Qmdb =
    fixed::Db<mmr::Family, deterministic::Context, Digest, Digest, Sha256, TwoCap, Sequential>;

/// The single-database set every node manages.
pub(crate) type Databases = Shared<Qmdb>;

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
