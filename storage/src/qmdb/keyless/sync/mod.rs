use crate::{
    journal::{
        authenticated,
        contiguous::{Contiguous as _, Mutable, Reader as _},
        Error as JournalError,
    },
    merkle::{
        self,
        full::{self, Merkle},
        Bagging, Family, Location,
    },
    qmdb::{
        self,
        any::value::ValueEncoding,
        compact_witness,
        keyless::{operation::Codec, CompactDb, Keyless, Operation},
        sync,
    },
    Context, Persistable,
};
use commonware_codec::{Encode, EncodeShared, Read};
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_utils::range::NonEmptyRange;

impl<F, E, V, C, H, S> sync::Database for Keyless<F, E, V, C, H, S>
where
    F: Family,
    E: Context,
    V: ValueEncoding + Codec,
    C: Mutable<Item = Operation<F, V>>
        + Persistable<Error = JournalError>
        + sync::Journal<F, Context = E, Op = Operation<F, V>>,
    C::Config: Clone + Send,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
{
    type Family = F;
    type Op = Operation<F, V>;
    type Journal = C;
    type Hasher = H;
    type Config = super::Config<C::Config, S>;
    type Digest = H::Digest;
    type Context = E;

    const ROOT_BAGGING: Bagging = merkle::Bagging::BackwardFold;

    /// Returns a [Keyless] db initialized from data collected in the sync process.
    ///
    /// # Behavior
    ///
    /// This method handles different initialization scenarios based on existing data:
    /// - If the Merkle journal is empty or the last item is before the range start, it creates
    ///   a fresh Merkle structure from the provided `pinned_nodes`
    /// - If the Merkle journal has data but is incomplete (has length < range end), missing
    ///   operations from the log are applied to bring it up to the target state
    /// - If the Merkle journal has data beyond the range end, it is rewound to match the sync
    ///   target
    ///
    /// # Returns
    ///
    /// A [Keyless] db populated with the state from the given range.
    async fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        log: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        range: NonEmptyRange<Location<F>>,
        apply_batch_size: usize,
    ) -> Result<Self, qmdb::Error<F>> {
        let hasher = merkle::hasher::Standard::<H>::with_bagging(merkle::Bagging::BackwardFold);

        let merkle = Merkle::<F, _, _, S>::init_sync(
            context.child("merkle"),
            full::SyncConfig {
                config: config.merkle.clone(),
                range: range.clone(),
                pinned_nodes,
            },
        )
        .await?;

        let journal = authenticated::Journal::<F, _, _, _, S>::from_components(
            merkle,
            log,
            hasher,
            apply_batch_size as u64,
        )
        .await?;

        let (last_commit_loc, inactivity_floor_loc) = {
            let reader = journal.reader().await;
            let loc = reader
                .bounds()
                .end
                .checked_sub(1)
                .expect("journal should not be empty");
            let op = reader.read(loc).await?;
            let floor = op
                .has_floor()
                .expect("last operation should be a commit with floor");
            (Location::new(loc), floor)
        };
        let inactive_peaks = F::inactive_peaks(
            F::location_to_position(Location::new(*last_commit_loc + 1)),
            inactivity_floor_loc,
        );
        let root = journal.root(inactive_peaks)?;

        let db = Self {
            journal,
            root,
            last_commit_loc,
            inactivity_floor_loc,
        };

        db.sync().await?;
        Ok(db)
    }

    fn root(&self) -> Self::Digest {
        self.root()
    }
}

impl<F, E, V, H, Cfg, S> sync::compact::Database for CompactDb<F, E, V, H, Cfg, S>
where
    F: Family,
    E: Context,
    V: ValueEncoding + Codec,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
    Operation<F, V>: Read<Cfg = Cfg>,
    Cfg: Clone + Send + Sync + 'static,
{
    type Family = F;
    type Op = Operation<F, V>;
    type Config = super::CompactConfig<Cfg, S>;
    type Digest = H::Digest;
    type Context = E;
    type Hasher = H;

    const ROOT_BAGGING: Bagging = merkle::Bagging::BackwardFold;

    async fn from_compact_state(
        context: Self::Context,
        config: Self::Config,
        state: sync::compact::State<Self::Family, Self::Op, Self::Digest>,
    ) -> Result<Self, qmdb::Error<F>> {
        let sync::compact::State {
            leaf_count,
            pinned_nodes,
            last_commit_op,
            last_commit_proof,
        } = state;
        let last_commit_loc = Location::new(*leaf_count - 1);
        let Operation::Commit(last_commit_metadata, inactivity_floor_loc) = last_commit_op else {
            return Err(qmdb::Error::UnexpectedData(last_commit_loc));
        };
        let commit_codec_config = config.commit_codec_config.clone();
        let commit_op_bytes =
            Operation::<F, V>::Commit(last_commit_metadata.clone(), inactivity_floor_loc)
                .encode()
                .to_vec();
        let hasher = merkle::hasher::Standard::<H>::with_bagging(merkle::Bagging::BackwardFold);
        let merkle = crate::merkle::compact::Merkle::init_from_compact_state(
            context.child("merkle"),
            config.merkle,
            leaf_count,
            pinned_nodes.clone(),
        )
        .await?;
        let inactive_peaks =
            F::inactive_peaks(F::location_to_position(leaf_count), inactivity_floor_loc);
        let root = merkle
            .root(&hasher, inactive_peaks)
            .map_err(|_| qmdb::Error::DataCorrupted("failed to compute compact state root"))?;
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

    async fn persist_compact_state(&self) -> Result<(), qmdb::Error<F>> {
        compact_witness::persist_cached_serve_state(self).await
    }
}

#[cfg(test)]
mod tests;
