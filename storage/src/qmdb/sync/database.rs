use crate::{mmr::Location, qmdb::sync::Journal, translator::Translator};
use commonware_cryptography::Digest;
use std::{future::Future, ops::Range};

pub trait Config {
    type JournalConfig;
    fn journal_config(&self) -> Self::JournalConfig;
}

impl<T: Translator, J: Clone> Config for crate::qmdb::any::Config<T, J> {
    type JournalConfig = J;

    fn journal_config(&self) -> Self::JournalConfig {
        self.journal_config.clone()
    }
}

impl<T: Translator, C: Clone> Config for crate::qmdb::immutable::Config<T, C> {
    type JournalConfig = C;

    fn journal_config(&self) -> Self::JournalConfig {
        self.log.clone()
    }
}

impl<J: Clone> Config for crate::qmdb::keyless::Config<J> {
    type JournalConfig = J;

    fn journal_config(&self) -> Self::JournalConfig {
        self.log.clone()
    }
}
pub trait Database: Sized + Send {
    type Op: Send;
    type Journal: Journal<Context = Self::Context, Op = Self::Op>;
    type Config: Config<JournalConfig = <Self::Journal as Journal>::Config>;
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
        range: Range<Location>,
        apply_batch_size: usize,
    ) -> impl Future<Output = Result<Self, crate::qmdb::Error<crate::merkle::mmr::Family>>> + Send;

    /// Returns whether persisted local state already matches the requested sync target.
    ///
    /// Databases can override this to allow the sync engine to complete immediately
    /// when an on-disk database already matches the target and can be rebuilt without
    /// fetching fresh boundary pins.
    ///
    /// # Caller contract
    ///
    /// `target.range.start()` **must** equal the committed inactivity floor of
    /// the target state (i.e. the floor carried by the last `CommitFloor` op).
    /// Implementations are free to verify only that the persisted tree size and
    /// root match and to skip checking the persisted merkle pruning boundary
    /// directly. Callers that set `target.range.start()` below the committed
    /// floor (or that prune their own database past the committed floor) can cause
    /// a later [`Self::from_sync_result`] rebuild to fail with `MissingNode` even
    /// though this function returned `true`.
    fn has_local_target_state(
        _context: Self::Context,
        _config: &Self::Config,
        _target: &crate::qmdb::sync::Target<Self::Digest>,
    ) -> impl Future<Output = bool> + Send {
        async { false }
    }

    /// Get the root digest of the database for verification
    fn root(&self) -> Self::Digest;
}
