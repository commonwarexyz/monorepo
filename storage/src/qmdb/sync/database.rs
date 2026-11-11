use crate::{
    Context,
    journal::Error as JournalError,
    merkle::{self, Family, Location, full},
    qmdb::sync::{Journal, Target},
    translator::Translator,
};
use commonware_codec::Encode;
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_utils::range::NonEmptyRange;
use std::{future::Future, num::NonZeroU64, ops::Range};

/// Database configuration that can produce the configuration for its sync journal.
pub trait Config {
    /// Configuration for the journal the sync engine fills before building the database.
    type JournalConfig;

    /// Return the configuration for the sync journal.
    fn journal_config(&self) -> Self::JournalConfig;
}

impl<T: Translator, J: Clone, S: Strategy, B> Config for crate::qmdb::any::Config<T, J, S, B> {
    type JournalConfig = J;

    fn journal_config(&self) -> Self::JournalConfig {
        self.log.clone()
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

/// A database that [`sync`](super::sync) can build from operations fetched from a [`Source`].
///
/// Every authenticated QMDB variant implements this trait, and callers drive it through
/// [`sync`](super::sync). The engine calls [`Self::discard_local_state`] with the operations that
/// the sync journal left on disk resumes, and [`Self::local_pinned_nodes`] when that journal
/// already reaches the target. It then fetches and verifies the remaining operations, builds the
/// database with [`Self::from_sync_result`], checks [`Self::ops_root`] against the target, and
/// only then calls [`Self::persist_sync_result`].
///
/// [`Source`]: super::Source
pub trait Database: Sized + Send {
    /// The Merkle family of the operations log.
    type Family: Family;

    /// The operation type stored in the log.
    type Op: Encode + Send + Sync;

    /// The journal the engine fills with fetched operations.
    type Journal: Journal<Self::Family, Context = Self::Context, Op = Self::Op>;

    /// The database configuration, which also configures the sync journal.
    type Config: Config<JournalConfig = <Self::Journal as Journal<Self::Family>>::Config>;

    /// The digest type of the database's root.
    type Digest: Digest;

    /// The runtime context the database is built in.
    type Context: commonware_runtime::Storage
        + commonware_runtime::Clock
        + commonware_runtime::Metrics;

    /// The hasher producing [`Self::Digest`].
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
    /// The engine calls this only after [`Self::ops_root`] matches the requested target.
    /// Implementations that persist everything in [`Self::from_sync_result`] must explicitly
    /// return `Ok(self)`.
    fn persist_sync_result(
        self,
    ) -> impl Future<Output = Result<Self, crate::qmdb::Error<Self::Family>>> + Send;

    /// Durably discard persisted state that the sync journal does not back.
    ///
    /// The engine calls this once it opens the sync journal and before it appends any fetched
    /// operation. `resumed` spans the operations of the target's range that the journal holds
    /// and is empty when it holds none.
    ///
    /// State derived from an operation at or after `resumed.end` is discarded, and all derived
    /// state is discarded when `resumed` is empty. State left in place would be read as
    /// describing the operations fetched at those locations. Implementations that persist no
    /// state beside the journal must explicitly return `Ok(())`.
    fn discard_local_state(
        context: Self::Context,
        config: &Self::Config,
        resumed: Range<Location<Self::Family>>,
    ) -> impl Future<Output = Result<(), crate::qmdb::Error<Self::Family>>> + Send;

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

    /// Return the operations root the engine compares against the target.
    ///
    /// For [`current`](crate::qmdb::current), this differs from the canonical database root.
    fn ops_root(&self) -> Self::Digest;
}

/// Whether a completed sync journal's `bounds` cover `range`: retained data reaches back to
/// `range.start()` and ends exactly at `range.end()`.
pub(crate) fn journal_covers_range<F: Family>(
    bounds: std::ops::Range<u64>,
    range: &NonEmptyRange<Location<F>>,
) -> bool {
    Location::new(bounds.start) <= range.start() && Location::new(bounds.end) == range.end()
}

/// Shared body for [`Database::discard_local_state`] implementations backed by a persisted
/// [`full::Merkle`]. Durably caps the structure that `config` names at `resumed.end` leaves. When
/// `resumed` is empty or the structure cannot be rebuilt within that cap, durably empties the
/// structure, including its pruning boundary and pins.
pub(crate) async fn discard_local_state<F, E, H, S>(
    context: E,
    config: full::Config<S>,
    resumed: Range<Location<F>>,
) -> Result<(), crate::qmdb::Error<F>>
where
    F: Family,
    E: Context,
    H: Hasher,
    S: Strategy,
{
    let hasher = crate::qmdb::hasher::<H>();

    // A leaf at or after the end of the resumed operations describes an operation the journal
    // does not hold, so the structure keeps at most that many leaves.
    if !resumed.is_empty() {
        let capped = full::Merkle::<F, _, H::Digest, S>::init_at_most(
            context.child("cap"),
            &hasher,
            config.clone(),
            resumed.end,
        )
        .await;
        match capped {
            Ok(_) => return Ok(()),

            // A structure pruned past the cap retains no leaf within it, and one that an
            // interrupted reset left without the nodes or pins of its pruning boundary cannot be
            // rebuilt. Neither holds a leaf that the journal backs.
            Err(
                merkle::Error::ElementPruned(_)
                | merkle::Error::MissingNode(_)
                | merkle::Error::Journal(JournalError::ItemPruned(_)),
            ) => {}
            Err(err) => return Err(err.into()),
        }
    }

    // The journal backs no leaf of the structure, so its pruning boundary and pins go with its
    // nodes.
    full::Merkle::<F, _, H::Digest, S>::prepare(
        context.child("discard"),
        &hasher,
        config,
        full::Retain::Nothing,
    )
    .await?
    .finish()
    .await?;
    Ok(())
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

    // An interrupted reset can leave durable boundary metadata ahead of the node journal.
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
    use super::{discard_local_state, journal_covers_range, local_pinned_nodes};
    use crate::{
        journal::{Error as JournalError, contiguous::fixed},
        merkle::{self, Location, Position, full, mmr::Family as MmrFamily},
        metadata::{Config as MetadataConfig, Metadata},
        qmdb::sync::Target,
    };
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_utils::{
        NZU16, NZU64, NZUsize, non_empty_range, range::NonEmptyRange, sequence::prefixed_u64::U64,
    };
    use std::ops::Range;

    type Merkle = full::Merkle<MmrFamily, deterministic::Context, Digest, Sequential>;

    fn merkle_config() -> full::Config<Sequential> {
        full::Config {
            journal_partition: "local-pins-journal".into(),
            metadata_partition: "local-pins-metadata".into(),
            items_per_blob: NZU64!(7),
            write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
            strategy: Sequential,
            page_cache: CacheRef::new(NZU16!(111), NZUsize!(5)),
        }
    }

    /// Appends the leaves `leaves` to the structure of `config`, makes it durable, and returns
    /// its root.
    async fn persist_merkle(
        context: deterministic::Context,
        config: &full::Config<Sequential>,
        leaves: Range<u64>,
    ) -> Digest {
        let hasher = crate::qmdb::hasher::<Sha256>();
        let mut merkle = Merkle::init(context, &hasher, config.clone())
            .await
            .unwrap();
        let mut batch = merkle.new_batch();
        for i in leaves {
            batch = batch.add(&hasher, &i.to_be_bytes());
        }
        let batch = batch.merkleize(merkle.mem(), &hasher);
        merkle = merkle.apply_batch(&batch).unwrap();
        let merkle = merkle.sync().await.unwrap();
        merkle.root(&hasher, 0).unwrap()
    }

    /// Persists a structure of 50 leaves pruned to leaf 30 under `config`.
    async fn persist_pruned_merkle(
        context: deterministic::Context,
        config: &full::Config<Sequential>,
    ) {
        let hasher = crate::qmdb::hasher::<Sha256>();
        persist_merkle(context.child("leaves"), config, 0..50).await;
        let merkle = Merkle::init(context.child("prune"), &hasher, config.clone())
            .await
            .unwrap();
        let merkle = merkle.prune(Location::new(30)).await.unwrap();
        drop(merkle.sync().await.unwrap());
    }

    /// Empties the node journal of `config` at leaf `restart`. A reset of the structure that
    /// stops after its node journal leaves the journal in that state.
    async fn reset_node_journal(
        context: deterministic::Context,
        config: &full::Config<Sequential>,
        restart: Location<MmrFamily>,
    ) {
        let journal_config = fixed::Config {
            partition: config.journal_partition.clone(),
            items_per_blob: config.items_per_blob,
            page_cache: config.page_cache.clone(),
            write_buffer: config.write_buffer,
            replay_buffer: config.replay_buffer,
        };
        let reset_pos = Position::<MmrFamily>::try_from(restart).unwrap();
        let journal =
            fixed::Journal::<_, Digest>::init_at_size(context, journal_config, *reset_pos)
                .await
                .unwrap();
        drop(journal);
    }

    /// Returns the error that capping the structure of `config` at `cap` leaves fails with.
    async fn cap_error(
        context: deterministic::Context,
        config: &full::Config<Sequential>,
        cap: u64,
    ) -> merkle::Error<MmrFamily> {
        let hasher = crate::qmdb::hasher::<Sha256>();
        Merkle::init_at_most(context, &hasher, config.clone(), Location::new(cap))
            .await
            .unwrap_err()
    }

    /// Discards the state of `config` that a journal resuming `resumed` does not back, then
    /// reopens the structure.
    async fn discard_and_reopen(
        context: deterministic::Context,
        config: &full::Config<Sequential>,
        resumed: Range<u64>,
    ) -> Merkle {
        let hasher = crate::qmdb::hasher::<Sha256>();
        discard_local_state::<MmrFamily, _, Sha256, Sequential>(
            context.child("discard"),
            config.clone(),
            Location::new(resumed.start)..Location::new(resumed.end),
        )
        .await
        .unwrap();
        Merkle::init(context.child("reopen"), &hasher, config.clone())
            .await
            .unwrap()
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
    fn local_pinned_nodes_treats_reset_journal_as_unavailable() {
        deterministic::Runner::default().start(|context| async move {
            let config = merkle_config();
            persist_pruned_merkle(context.child("init"), &config).await;

            // A node journal reset below the persisted pin boundary cannot supply local pins.
            let restart = Location::new(7);
            reset_node_journal(context.child("interrupted_reset"), &config, restart).await;

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

    /// A structure holding leaves past the operations the journal resumes is capped at their
    /// end, and one that ends before it keeps every leaf.
    #[test]
    fn discard_local_state_caps_merkle_at_resumed_end() {
        deterministic::Runner::default().start(|context| async move {
            // The journal backs the first 20 of the 50 leaves the structure holds.
            let hasher = crate::qmdb::hasher::<Sha256>();
            let config = merkle_config();
            let root = persist_merkle(context.child("backed"), &config, 0..20).await;
            persist_merkle(context.child("unbacked"), &config, 20..50).await;

            // Leaves at or after the end of the resumed operations are discarded.
            let merkle = discard_and_reopen(context.child("ahead"), &config, 5..20).await;
            assert_eq!(merkle.bounds(), Location::new(0)..Location::new(20));
            assert_eq!(merkle.root(&hasher, 0).unwrap(), root);
            drop(merkle);

            // A structure that ends before the resumed operations do is left whole.
            let merkle = discard_and_reopen(context.child("behind"), &config, 5..60).await;
            assert_eq!(merkle.bounds(), Location::new(0)..Location::new(20));
            assert_eq!(merkle.root(&hasher, 0).unwrap(), root);
        });
    }

    /// A structure is emptied when the journal resumes nothing, and when the structure cannot be
    /// rebuilt within the operations the journal resumes.
    #[test]
    fn discard_local_state_empties_merkle_it_cannot_cap() {
        deterministic::Runner::default().start(|context| async move {
            let config = merkle_config();
            let empty = Location::new(0)..Location::new(0);

            // A journal that resumes nothing backs no leaf.
            persist_pruned_merkle(context.child("nothing"), &config).await;
            let merkle = discard_and_reopen(context.child("nothing"), &config, 35..35).await;
            assert_eq!(merkle.bounds(), empty);
            merkle.destroy().await.unwrap();

            // A structure pruned past the resumed operations retains no leaf among them.
            persist_pruned_merkle(context.child("pruned"), &config).await;
            assert!(matches!(
                cap_error(context.child("pruned_cap"), &config, 20).await,
                merkle::Error::ElementPruned(_)
            ));
            let merkle = discard_and_reopen(context.child("pruned"), &config, 5..20).await;
            assert_eq!(merkle.bounds(), empty);
            merkle.destroy().await.unwrap();

            // A node journal reset below the persisted pin boundary lacks the pins.
            persist_pruned_merkle(context.child("reset"), &config).await;
            reset_node_journal(context.child("reset_journal"), &config, Location::new(7)).await;
            assert!(matches!(
                cap_error(context.child("reset_cap"), &config, 40).await,
                merkle::Error::MissingNode(_)
            ));
            let merkle = discard_and_reopen(context.child("reset"), &config, 7..40).await;
            assert_eq!(merkle.bounds(), empty);
            merkle.destroy().await.unwrap();

            // A reset that lowers the pruning boundary records it before it clears the node
            // journal. The nodes that journal retains then start past the resumed operations.
            persist_pruned_merkle(context.child("lowered"), &config).await;
            let mut metadata = Metadata::<_, U64, Vec<u8>>::init(
                context.child("lowered_boundary"),
                MetadataConfig {
                    partition: config.metadata_partition.clone(),
                    codec_config: ((0..).into(), ()),
                },
            )
            .await
            .unwrap();
            metadata.put(
                U64::new(full::PRUNED_TO_PREFIX, 0),
                10u64.to_be_bytes().to_vec(),
            );
            drop(metadata.sync().await.unwrap());
            assert!(matches!(
                cap_error(context.child("lowered_cap"), &config, 20).await,
                merkle::Error::Journal(JournalError::ItemPruned(_))
            ));
            let merkle = discard_and_reopen(context.child("lowered"), &config, 10..20).await;
            assert_eq!(merkle.bounds(), empty);
            merkle.destroy().await.unwrap();
        });
    }
}
