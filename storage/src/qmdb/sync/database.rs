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

    /// Get the root digest of the database for verification
    fn root(&self) -> Self::Digest;
}
