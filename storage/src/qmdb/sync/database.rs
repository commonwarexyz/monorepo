use crate::{
    merkle::{Family, Location},
    qmdb::{current::sync::CurrentOverlayState, sync::Journal},
    translator::Translator,
};
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
    /// The merkle family backing this database (e.g. MMR or MMB).
    type Family: Family;
    type Op: Send;
    type Journal: Journal<Self::Family, Context = Self::Context, Op = Self::Op>;
    type Config: Config<JournalConfig = <Self::Journal as Journal<Self::Family>>::Config>;
    type Digest: Digest;
    type Context: commonware_runtime::Storage
        + commonware_runtime::Clock
        + commonware_runtime::Metrics;
    type Hasher: commonware_cryptography::Hasher<Digest = Self::Digest>;

    /// Build a database from the journal and boundary state populated by the sync engine.
    ///
    /// `overlay_state` carries the sender's grafted pruning state for `current` sync; it is
    /// `None` for databases that do not use overlay state (`any`, `immutable`, `keyless`).
    ///
    /// `canonical_root` is the trusted canonical root from [`Target::canonical_root`] —
    /// used by `current` to authenticate the reconstructed overlay state by comparing the
    /// rebuilt database's canonical root against this value. `None` means the caller did
    /// not supply one (either the database doesn't need it, or current sync was started
    /// without canonical-root authentication).
    ///
    /// Implementations that do not distinguish between ops and canonical roots should
    /// ignore `overlay_state` and `canonical_root`.
    ///
    /// [`Target::canonical_root`]: crate::qmdb::sync::Target::canonical_root
    #[allow(clippy::too_many_arguments)]
    fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        journal: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        overlay_state: Option<CurrentOverlayState<Self::Digest>>,
        canonical_root: Option<Self::Digest>,
        range: Range<Location<Self::Family>>,
        apply_batch_size: usize,
    ) -> impl Future<Output = Result<Self, crate::qmdb::Error<Self::Family>>> + Send;

    /// Get the root digest of the database for verification
    fn root(&self) -> Self::Digest;
}
