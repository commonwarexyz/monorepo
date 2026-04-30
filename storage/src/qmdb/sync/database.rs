use crate::{
    merkle::{Bagging, Family, Location, Proof},
    qmdb::sync::Journal,
    translator::Translator,
};
use commonware_cryptography::Digest;
use commonware_parallel::Strategy;
use commonware_utils::range::NonEmptyRange;
use std::future::Future;

pub trait Config {
    type JournalConfig;
    fn journal_config(&self) -> Self::JournalConfig;
}

impl<T: Translator, J: Clone, S: Strategy> Config for crate::qmdb::any::Config<T, J, S> {
    type JournalConfig = J;

    fn journal_config(&self) -> Self::JournalConfig {
        self.journal_config.clone()
    }
}

impl<T: Translator, C: Clone, S: Strategy> Config for crate::qmdb::immutable::Config<T, C, S> {
    type JournalConfig = C;

    fn journal_config(&self) -> Self::JournalConfig {
        self.log.clone()
    }
}

impl<J: Clone, S: Strategy> Config for crate::qmdb::keyless::Config<J, S> {
    type JournalConfig = J;

    fn journal_config(&self) -> Self::JournalConfig {
        self.log.clone()
    }
}

pub trait Database: Sized + Send {
    type Family: Family;
    type Op: Send;
    type Journal: Journal<Self::Family, Context = Self::Context, Op = Self::Op>;
    type Config: Config<JournalConfig = <Self::Journal as Journal<Self::Family>>::Config>;
    type Digest: Digest;
    type Context: commonware_runtime::Storage
        + commonware_runtime::Clock
        + commonware_runtime::Metrics;
    type Hasher: commonware_cryptography::Hasher<Digest = Self::Digest>;

    /// Build a database from the journal and pinned nodes populated by the sync engine.
    fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        journal: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        range: NonEmptyRange<Location<Self::Family>>,
        apply_batch_size: usize,
    ) -> impl Future<Output = Result<Self, crate::qmdb::Error<Self::Family>>> + Send;

    /// Returns whether persisted local state already matches the requested sync target.
    ///
    /// Databases can override this to let the sync engine finish immediately when an
    /// on-disk database already reflects the target. Simple append-only variants may
    /// verify only the persisted tree size and root. Variants with additional
    /// pruning-dependent state should also ensure their persisted lower bound still
    /// covers `target.range.start()`.
    fn has_local_target_state(
        _context: Self::Context,
        _config: &Self::Config,
        _target: &crate::qmdb::sync::Target<Self::Family, Self::Digest>,
    ) -> impl Future<Output = bool> + Send {
        async { false }
    }

    /// Get the root digest of the database for verification
    fn root(&self) -> Self::Digest;

    /// Return the inactive_peaks count for verifying an ops proof against this database's
    /// configured policy. The bagging is supplied via the hasher passed to verification.
    fn proof_inactive_peaks(
        config: &Self::Config,
        proof: &Proof<Self::Family, Self::Digest>,
    ) -> usize;

    /// Bagging policy used by this database when computing roots/proofs.
    fn root_bagging(config: &Self::Config) -> Bagging;
}
