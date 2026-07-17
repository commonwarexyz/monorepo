use crate::{
    Context,
    merkle::{Family, Location, full},
    qmdb::sync::{Journal, Target},
    translator::Translator,
};
use commonware_cryptography::{Digest, Hasher};
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

    /// Return locally available boundary nodes for the target, if persisted local state can
    /// authenticate them.
    ///
    /// Returning `Some` lets a completed sync journal reuse boundary nodes from an on-disk
    /// database instead of fetching them from peers. Returning `None` always falls back to
    /// fetching from peers. Simple append-only variants may verify only the persisted tree size
    /// and root. Variants with additional pruning-dependent state should also ensure their
    /// persisted lower bound still covers `target.range.start()`.
    fn local_boundary_nodes(
        context: Self::Context,
        config: &Self::Config,
        target: &crate::qmdb::sync::Target<Self::Family, Self::Digest>,
        journal: &Self::Journal,
    ) -> impl Future<Output = Result<Option<Vec<Self::Digest>>, crate::qmdb::Error<Self::Family>>> + Send;

    /// Get the root digest of the database for verification
    fn root(&self) -> Self::Digest;
}

/// Whether a completed sync journal's `bounds` cover `range`: retained data reaches back to
/// `range.start()` and ends exactly at `range.end()`.
pub(crate) fn journal_covers_range<F: Family>(
    bounds: std::ops::Range<u64>,
    range: &NonEmptyRange<Location<F>>,
) -> bool {
    Location::new(bounds.start) <= range.start() && Location::new(bounds.end) == range.end()
}

/// Shared body for [`Database::local_boundary_nodes`] implementations backed by a persisted
/// [`full::Merkle`]: reopen it from `config` under `context` and return the boundary nodes at
/// `target.range.start()` if the persisted bounds cover the target and the root, computed with
/// `inactivity_floor`, matches `target.root`. Returns `Ok(None)` when the persisted state
/// cannot authenticate the target.
pub(crate) async fn local_boundary_nodes<F, E, H, S>(
    context: E,
    config: full::Config<S>,
    target: &Target<F, H::Digest>,
    inactivity_floor: Location<F>,
) -> Result<Option<Vec<H::Digest>>, crate::qmdb::Error<F>>
where
    F: Family,
    E: Context,
    H: Hasher,
    S: Strategy,
{
    let hasher = crate::qmdb::hasher::<H>();
    let merkle = full::Merkle::<F, _, _, S>::init(context, &hasher, config).await?;
    let bounds = merkle.bounds();
    if bounds.start > target.range.start() || bounds.end != target.range.end() {
        return Ok(None);
    }

    let inactive_peaks = F::inactive_peaks(
        F::location_to_position(target.range.end()),
        inactivity_floor,
    );
    if merkle.root(&hasher, inactive_peaks)? != target.root {
        return Ok(None);
    }

    merkle
        .pinned_nodes_at(target.range.start())
        .await
        .map(Some)
        .map_err(Into::into)
}
