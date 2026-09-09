use crate::{
    Context,
    merkle::{Family, Location, full},
    qmdb::sync::{Journal, Target},
    translator::Translator,
};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_utils::range::NonEmptyRange;
use std::{future::Future, num::NonZeroU64};

/// Database configuration that can produce the configuration for its sync journal.
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

impl<C: Clone + Send + Sync + 'static, S: Strategy> Config for crate::qmdb::compact::Config<C, S> {
    type JournalConfig = ();

    fn journal_config(&self) -> Self::JournalConfig {}
}

pub trait Database: Sized + Send {
    type Family: Family;
    type Op: Send + Sync;
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
        apply_batch_size: NonZeroU64,
    ) -> impl Future<Output = Result<Self, crate::qmdb::Error<Self::Family>>> + Send;

    /// Persist any state that must remain provisional until the engine verifies the rebuilt root.
    ///
    /// The engine calls this only after [`Self::root`] matches the requested target. Implementations
    /// that persist everything in [`Self::from_sync_result`] must explicitly return `Ok(self)`.
    fn persist_sync_result(
        self,
    ) -> impl Future<Output = Result<Self, crate::qmdb::Error<Self::Family>>> + Send;

    /// Return locally available pinned nodes for the target, if persisted local state can
    /// authenticate them.
    ///
    /// Returning `Some` lets a completed sync journal reuse pinned nodes from an on-disk
    /// database instead of fetching them from peers. Returning `None` always falls back to
    /// fetching from peers.
    fn local_pinned_nodes(
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

/// Shared body for [`Database::local_pinned_nodes`] implementations backed by a persisted
/// [`full::Merkle`]. Reopens it from `config` under `context` and returns the pinned nodes at
/// `target.range.start()` if the persisted bounds cover the target and the root, computed with
/// `inactivity_floor`, matches `target.root`. Returns `Ok(None)` when the persisted state
/// cannot authenticate the target, including when an interrupted reset left required local
/// nodes unavailable.
pub(crate) async fn local_pinned_nodes<F, E, H, S>(
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

    // A crash can persist a node-journal reset before its replacement metadata.
    // Missing local pins then use a peer-authenticated boundary. Other errors still propagate.
    let merkle = match full::Merkle::<F, _, _, S>::init(context, &hasher, config).await {
        Ok(merkle) => merkle,
        Err(crate::merkle::Error::MissingNode(_)) => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let bounds = merkle.bounds();
    if bounds.start > target.range.start() || bounds.end != target.range.end() {
        return Ok(None);
    }

    let inactive_peaks = F::inactive_peaks(target.range.end(), inactivity_floor);
    if merkle.root(&hasher, inactive_peaks)? != target.root {
        return Ok(None);
    }

    merkle
        .pinned_nodes_at(target.range.start())
        .await
        .map(Some)
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::{journal_covers_range, local_pinned_nodes};
    use crate::{
        journal::contiguous::fixed,
        merkle::{Location, Position, full, mmr::Family as MmrFamily},
        qmdb::sync::Target,
    };
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        BufferPooler, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, non_empty_range, range::NonEmptyRange};

    fn merkle_config(pooler: &impl BufferPooler) -> full::Config<Sequential> {
        full::Config {
            journal_partition: "local-pins-journal".into(),
            metadata_partition: "local-pins-metadata".into(),
            items_per_blob: NZU64!(7),
            write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
            strategy: Sequential,
            page_cache: CacheRef::from_pooler(pooler, NZU16!(111), NZUsize!(5)),
        }
    }

    #[test]
    fn test_journal_covers_range() {
        let range: NonEmptyRange<Location<MmrFamily>> =
            non_empty_range!(Location::new(10), Location::new(20));

        // Bounds reaching at least back to the start and ending exactly at the end cover.
        assert!(journal_covers_range(10..20, &range));
        assert!(journal_covers_range(5..20, &range));

        // Bounds starting after the range start do not cover.
        assert!(!journal_covers_range(11..20, &range));

        // Bounds ending anywhere but exactly at the range end do not cover.
        assert!(!journal_covers_range(10..19, &range));
        assert!(!journal_covers_range(10..21, &range));
        assert!(!journal_covers_range(0..0, &range));
    }

    #[test]
    fn local_pinned_nodes_treats_interrupted_reset_as_unavailable() {
        deterministic::Runner::default().start(|context| async move {
            let hasher = crate::qmdb::hasher::<Sha256>();
            let config = merkle_config(&context);
            let mut merkle = full::Merkle::<MmrFamily, _, Digest, Sequential>::init(
                context.child("init"),
                &hasher,
                config.clone(),
            )
            .await
            .unwrap();
            let mut batch = merkle.new_batch();
            for i in 0u64..50 {
                batch = batch.add(&hasher, &i.to_be_bytes());
            }
            let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
            merkle = merkle.apply_batch(&batch).unwrap();
            let merkle = merkle.sync().await.unwrap();
            let merkle = merkle.prune(Location::new(30)).await.unwrap();
            let merkle = merkle.sync().await.unwrap();
            drop(merkle);

            // Model a crash after an incompatible reset durably cleared the node journal but
            // before it replaced the prior target's pinned metadata.
            let restart = Location::new(7);
            let journal_config = fixed::Config {
                partition: config.journal_partition.clone(),
                items_per_blob: config.items_per_blob,
                page_cache: config.page_cache.clone(),
                write_buffer: config.write_buffer,
                replay_buffer: config.replay_buffer,
            };
            let journal = fixed::Journal::<_, Digest>::init(
                context.child("interrupted_reset"),
                journal_config,
            )
            .await
            .unwrap();
            let reset_pos = Position::<MmrFamily>::try_from(restart).unwrap();
            let journal = journal.clear_to_size(*reset_pos).await.unwrap();
            drop(journal);

            let target = Target {
                root: Digest::from([0; 32]),
                range: non_empty_range!(restart, Location::new(20)),
            };
            let pinned = local_pinned_nodes::<MmrFamily, _, Sha256, Sequential>(
                context.child("local_pins"),
                config,
                &target,
                restart,
            )
            .await
            .unwrap();
            assert!(pinned.is_none());
        });
    }
}
