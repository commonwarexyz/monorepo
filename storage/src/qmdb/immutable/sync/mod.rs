use crate::{
    index::unordered::Index,
    journal::{
        authenticated,
        contiguous::{Mutable, Reader as _},
        Error as JournalError,
    },
    merkle::{
        journaled::{self, Journaled},
        Family, Location,
    },
    qmdb::{
        any::ValueEncoding,
        build_snapshot_from_log,
        immutable::{self, Operation},
        operation::Key,
        sync::{self},
        Error,
    },
    translator::Translator,
    Context, Persistable,
};
use commonware_codec::EncodeShared;
use commonware_cryptography::Hasher;
use commonware_utils::range::NonEmptyRange;

type StandardHasher<H> = crate::merkle::hasher::Standard<H>;

impl<F, E, K, V, C, H, T> sync::Database for immutable::Immutable<F, E, K, V, C, H, T>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<K, V>>
        + Persistable<Error = JournalError>
        + sync::Journal<F, Context = E, Op = Operation<K, V>>,
    C::Item: EncodeShared,
    C::Config: Clone + Send,
    H: Hasher,
    T: Translator,
{
    type Family = F;
    type Op = Operation<K, V>;
    type Journal = C;
    type Hasher = H;
    type Config = immutable::Config<T, C::Config>;
    type Digest = H::Digest;
    type Context = E;

    /// Returns an [Immutable](immutable::Immutable) initialized from data collected in the sync process.
    ///
    /// # Behavior
    ///
    /// This method handles different initialization scenarios based on existing data:
    /// - If the Merkle journal is empty or the last item is before the range start, it creates a
    ///   fresh Merkle structure from the provided `pinned_nodes`
    /// - If the Merkle journal has data but is incomplete (has length < range end), missing
    ///   operations from the log are applied to bring it up to the target state
    /// - If the Merkle journal has data beyond the range end, it is rewound to match the sync
    ///   target
    ///
    /// # Returns
    ///
    /// A [super::Immutable] db populated with the state from the given range.
    /// The pruning boundary is set to the range start.
    async fn from_sync_result(
        context: Self::Context,
        db_config: Self::Config,
        log: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        range: NonEmptyRange<Location<F>>,
        apply_batch_size: usize,
    ) -> Result<Self, Error<F>> {
        let hasher = StandardHasher::new();

        // Initialize Merkle structure for sync
        let merkle = Journaled::init_sync(
            context.with_label("merkle"),
            journaled::SyncConfig {
                config: db_config.merkle_config.clone(),
                range,
                pinned_nodes,
            },
            &hasher,
        )
        .await?;

        let journal = authenticated::Journal::<_, _, _, _>::from_components(
            merkle,
            log,
            hasher,
            apply_batch_size as u64,
        )
        .await?;

        let mut snapshot: Index<T, Location<F>> =
            Index::new(context.with_label("snapshot"), db_config.translator.clone());

        let last_commit_loc = {
            // Get the start of the log.
            let reader = journal.journal.reader().await;
            let bounds = reader.bounds();
            let start_loc = Location::<F>::new(bounds.start);

            // Build snapshot from the log
            build_snapshot_from_log::<F, _, _, _>(start_loc, &reader, &mut snapshot, |_, _| {})
                .await?;

            Location::new(bounds.end.checked_sub(1).expect("commit should exist"))
        };

        let db = Self {
            journal,
            snapshot,
            last_commit_loc,
        };

        db.sync().await?;
        Ok(db)
    }

    fn root(&self) -> Self::Digest {
        self.root()
    }
}

#[cfg(test)]
mod tests;
