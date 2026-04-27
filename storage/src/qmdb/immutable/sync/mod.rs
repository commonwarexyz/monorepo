use crate::{
    index::unordered::Index,
    journal::{
        authenticated,
        contiguous::{Mutable, Reader as _},
        Error as JournalError,
    },
    merkle::{
        full::{self, Merkle},
        Family, Location, Proof, RootSpec as MerkleRootSpec,
    },
    qmdb::{
        any::ValueEncoding,
        build_snapshot_from_log, compact_witness,
        immutable::{self, CompactDb, Operation},
        operation::{Key, Operation as _},
        sync::{self},
        Error, RootSpec,
    },
    translator::Translator,
    Context, Persistable,
};
use commonware_codec::{Encode, EncodeShared, Read};
use commonware_cryptography::Hasher;
use commonware_utils::range::NonEmptyRange;

type StandardHasher<H> = crate::merkle::hasher::Standard<H>;

impl<F, E, K, V, C, H, T> sync::Database for immutable::Immutable<F, E, K, V, C, H, T>
where
    F: Family + RootSpec,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>>
        + Persistable<Error = JournalError>
        + sync::Journal<F, Context = E, Op = Operation<F, K, V>>,
    C::Item: EncodeShared,
    C::Config: Clone + Send,
    H: Hasher,
    T: Translator,
{
    type Family = F;
    type Op = Operation<F, K, V>;
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
        let merkle = Merkle::init_sync(
            context.with_label("merkle"),
            full::SyncConfig {
                config: db_config.merkle_config.clone(),
                range: range.clone(),
                pinned_nodes,
            },
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

        let (last_commit_loc, inactivity_floor_loc) = {
            let reader = journal.journal.reader().await;
            let bounds = reader.bounds();
            let last_commit_loc =
                Location::<F>::new(bounds.end.checked_sub(1).expect("commit should exist"));

            // Read the floor from the last commit operation.
            let last_op = reader.read(*last_commit_loc).await?;
            let inactivity_floor_loc = last_op
                .has_floor()
                .expect("last operation should be a commit with floor");

            // Replay the log from the inactivity floor to build the snapshot.
            build_snapshot_from_log::<F, _, _, _>(
                inactivity_floor_loc,
                &reader,
                &mut snapshot,
                |_, _| {},
            )
            .await?;

            (last_commit_loc, inactivity_floor_loc)
        };
        let inactive_peaks = F::inactive_peaks(
            F::location_to_position(Location::new(*last_commit_loc + 1)),
            inactivity_floor_loc,
        );
        let root = journal.root(F::root_spec(inactive_peaks))?;

        let db = Self {
            journal,
            root,
            snapshot,
            last_commit_loc,
            inactivity_floor_loc,
        };

        db.sync().await?;
        Ok(db)
    }

    fn root(&self) -> Self::Digest {
        self.root()
    }

    fn proof_spec(proof: &Proof<Self::Family, Self::Digest>) -> MerkleRootSpec {
        F::root_spec(proof.inactive_peaks)
    }
}

impl<F, E, K, V, H, Cfg> sync::compact::Database for CompactDb<F, E, K, V, H, Cfg>
where
    F: Family + RootSpec,
    E: Context,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, K, V>: EncodeShared,
    Operation<F, K, V>: Read<Cfg = Cfg>,
    Cfg: Clone + Send + Sync + 'static,
{
    type Family = F;
    type Op = Operation<F, K, V>;
    type Config = immutable::CompactConfig<Cfg>;
    type Digest = H::Digest;
    type Context = E;
    type Hasher = H;

    async fn from_compact_state(
        context: Self::Context,
        config: Self::Config,
        state: sync::compact::State<Self::Family, Self::Op, Self::Digest>,
    ) -> Result<Self, Error<F>> {
        let sync::compact::State {
            leaf_count,
            pinned_nodes,
            last_commit_op,
            last_commit_proof,
        } = state;
        let last_commit_loc = Location::new(*leaf_count - 1);
        let Operation::Commit(last_commit_metadata, inactivity_floor_loc) = last_commit_op else {
            return Err(Error::UnexpectedData(last_commit_loc));
        };
        let commit_codec_config = config.commit_codec_config.clone();
        let commit_op_bytes =
            Operation::<F, K, V>::Commit(last_commit_metadata.clone(), inactivity_floor_loc)
                .encode()
                .to_vec();
        let hasher = StandardHasher::<H>::new();
        let merkle = crate::merkle::compact::Merkle::init_from_compact_state(
            context.with_label("merkle"),
            config.merkle,
            leaf_count,
            pinned_nodes.clone(),
        )
        .await?;
        let inactive_peaks =
            F::inactive_peaks(F::location_to_position(leaf_count), inactivity_floor_loc);
        let root = merkle
            .root(&hasher, F::root_spec(inactive_peaks))
            .map_err(|_| Error::DataCorrupted("failed to compute compact state root"))?;
        Self::init_from_verified_state(
            merkle,
            commit_codec_config,
            last_commit_metadata,
            inactivity_floor_loc,
            root,
            commit_op_bytes,
            last_commit_proof,
            pinned_nodes,
        )
    }

    fn root(&self) -> Self::Digest {
        self.root()
    }

    fn proof_spec(proof: &Proof<Self::Family, Self::Digest>) -> MerkleRootSpec {
        F::root_spec(proof.inactive_peaks)
    }

    async fn persist_compact_state(&self) -> Result<(), Error<F>> {
        compact_witness::persist_cached_serve_state(self).await
    }
}

#[cfg(test)]
mod tests;
