//! An _unordered_ variant of a [crate::qmdb::current] authenticated database optimized for
//! fixed-size values.
//!
//! This variant does not maintain key ordering, so it cannot generate exclusion proofs. Use
//! [super::super::ordered::fixed] if exclusion proofs are required.
//!
//! See [Db] for the main database type.

#[cfg(any(test, feature = "test-traits"))]
use crate::qmdb::any::states::{
    CleanAny, MerkleizedNonDurableAny, MutableAny, UnmerkleizedDurableAny,
};
use crate::{
    bitmap::CleanBitMap,
    kv::{self, Batchable},
    mmr::{Location, Proof, StandardHasher},
    qmdb::{
        any::{
            unordered::{
                fixed::{Db as AnyDb, Operation},
                Update,
            },
            FixedValue,
        },
        current::{
            merkleize_grafted_bitmap,
            proof::{OperationProof, RangeProof},
            root, FixedConfig as Config,
        },
        store::{self, LogStore, MerkleizedStore, PrunableStore},
        DurabilityState, Durable, Error, MerkleizationState, Merkleized, NonDurable, Unmerkleized,
    },
    translator::Translator,
    AuthenticatedBitMap as BitMap, Persistable,
};
use commonware_codec::FixedSize;
use commonware_cryptography::{DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage as RStorage};
use commonware_utils::Array;
use core::ops::Range;
use std::num::NonZeroU64;

/// Proof information for verifying a key has a particular value in the database.
pub type KeyValueProof<D, const N: usize> = OperationProof<D, N>;

/// A key-value QMDB based on an MMR over its log of operations, supporting authentication of
/// whether a key ever had a specific value, and whether the key currently has that value.
///
/// Note: The generic parameter N is not really generic, and must be manually set to double the size
/// of the hash digest being produced by the hasher. A compile-time assertion is used to prevent any
/// other setting.
pub struct Db<
    E: RStorage + Clock + Metrics,
    K: Array,
    V: FixedValue,
    H: Hasher,
    T: Translator,
    const N: usize,
    M: MerkleizationState<DigestOf<H>> = Merkleized<H>,
    D: DurabilityState = Durable,
> {
    /// An authenticated database that provides the ability to prove whether a key ever had a
    /// specific value.
    any: AnyDb<E, K, V, H, T, M, D>,

    /// The bitmap over the activity status of each operation. Supports augmenting [Db] proofs in
    /// order to further prove whether a key _currently_ has a specific value.
    status: BitMap<H::Digest, N, M>,

    context: E,

    bitmap_metadata_partition: String,

    /// Cached root digest. Invariant: valid when in Clean state.
    cached_root: Option<H::Digest>,
}

// Functionality shared across all DB states, such as most non-mutating operations.
impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
        M: MerkleizationState<DigestOf<H>>,
        D: DurabilityState,
    > Db<E, K, V, H, T, N, M, D>
{
    /// The number of operations that have been applied to this db, including those that have been
    /// pruned and those that are not yet committed.
    pub fn op_count(&self) -> Location {
        self.any.op_count()
    }

    /// Return the inactivity floor location. This is the location before which all operations are
    /// known to be inactive. Operations before this point can be safely pruned.
    pub const fn inactivity_floor_loc(&self) -> Location {
        self.any.inactivity_floor_loc()
    }

    /// Get the value of `key` in the db, or None if it has no value.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        self.any.get(key).await
    }

    /// Get the metadata associated with the last commit.
    pub async fn get_metadata(&self) -> Result<Option<V>, Error> {
        self.any.get_metadata().await
    }

    /// Whether the db currently has no active keys.
    pub const fn is_empty(&self) -> bool {
        self.any.is_empty()
    }

    /// Get the level of the base MMR into which we are grafting.
    ///
    /// This value is log2 of the chunk size in bits. Since we assume the chunk size is a power of
    /// 2, we compute this from trailing_zeros.
    const fn grafting_height() -> u32 {
        CleanBitMap::<H::Digest, N>::CHUNK_SIZE_BITS.trailing_zeros()
    }

    /// Return true if the proof authenticates that `key` currently has value `value` in the db with
    /// the provided `root`.
    pub fn verify_key_value_proof(
        hasher: &mut H,
        key: K,
        value: V,
        proof: &KeyValueProof<H::Digest, N>,
        root: &H::Digest,
    ) -> bool {
        let op = Operation::Update(Update(key, value));

        proof.verify(hasher, Self::grafting_height(), op, root)
    }

    /// Return true if the given sequence of `ops` were applied starting at location `start_loc` in
    /// the log with the provided root.
    pub fn verify_range_proof(
        hasher: &mut H,
        proof: &RangeProof<H::Digest>,
        start_loc: Location,
        ops: &[Operation<K, V>],
        chunks: &[[u8; N]],
        root: &H::Digest,
    ) -> bool {
        let height = Self::grafting_height();

        proof.verify(hasher, height, start_loc, ops, chunks, root)
    }
}

// Functionality for the Clean state.
impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > Db<E, K, V, H, T, N, Merkleized<H>, Durable>
{
    /// Initializes a [Db] authenticated database from the given `config`. Leverages parallel
    /// Merkleization to initialize the bitmap MMR if a thread pool is provided.
    pub async fn init(context: E, config: Config<T>) -> Result<Self, Error> {
        // TODO: Re-evaluate assertion placement after `generic_const_exprs` is stable.
        const {
            // A compile-time assertion that the chunk size is some multiple of digest size. A
            // multiple of 1 is optimal with respect to proof size, but a higher multiple allows for
            // a smaller (RAM resident) merkle tree over the structure.
            assert!(
                N.is_multiple_of(H::Digest::SIZE),
                "chunk size must be some multiple of the digest size",
            );
            // A compile-time assertion that chunk size is a power of 2, which is necessary to allow
            // the status bitmap tree to be aligned with the underlying operations MMR.
            assert!(N.is_power_of_two(), "chunk size must be a power of 2");
        }

        let thread_pool = config.thread_pool.clone();
        let bitmap_metadata_partition = config.bitmap_metadata_partition.clone();

        let mut hasher = StandardHasher::<H>::new();
        let mut status = CleanBitMap::restore_pruned(
            context.with_label("bitmap"),
            &bitmap_metadata_partition,
            thread_pool,
            &mut hasher,
        )
        .await?
        .into_dirty();

        // Initialize the anydb with a callback that initializes the status bitmap.
        let last_known_inactivity_floor = Location::new_unchecked(status.len());
        let any = AnyDb::init_with_callback(
            context.with_label("any"),
            config.to_any_config(),
            Some(last_known_inactivity_floor),
            |append: bool, loc: Option<Location>| {
                status.push(append);
                if let Some(loc) = loc {
                    status.set_bit(*loc, false);
                }
            },
        )
        .await?;

        let height = Self::grafting_height();
        let status = merkleize_grafted_bitmap(&mut hasher, status, &any.log.mmr, height).await?;

        // Compute and cache the root
        let cached_root = Some(root(&mut hasher, height, &status, &any.log.mmr).await?);

        Ok(Self {
            any,
            status,
            context,
            bitmap_metadata_partition,
            cached_root,
        })
    }

    /// Return the cached root of the db.
    pub const fn root(&self) -> H::Digest {
        self.cached_root.expect("Clean state must have cached root")
    }

    /// Sync all database state to disk.
    pub async fn sync(&mut self) -> Result<(), Error> {
        self.any.sync().await?;

        // Write the bitmap pruning boundary to disk so that next startup doesn't have to
        // re-Merkleize the inactive portion up to the inactivity floor.
        self.status
            .write_pruned(
                self.context.with_label("bitmap"),
                &self.bitmap_metadata_partition,
            )
            .await
            .map_err(Into::into)
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        // Clean up bitmap metadata partition.
        CleanBitMap::<H::Digest, N>::destroy(self.context, &self.bitmap_metadata_partition).await?;

        // Clean up Any components (MMR and log).
        self.any.destroy().await
    }

    /// Transition into the mutable state.
    pub fn into_mutable(self) -> Db<E, K, V, H, T, N, Unmerkleized, NonDurable> {
        Db {
            any: self.any.into_mutable(),
            status: self.status.into_dirty(),
            context: self.context,
            bitmap_metadata_partition: self.bitmap_metadata_partition,
            cached_root: None,
        }
    }
}

// Functionality for any Merkleized state (both Durable and NonDurable).
impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
        D: store::State,
    > Db<E, K, V, H, T, N, Merkleized<H>, D>
{
    /// Prune historical operations prior to `prune_loc`. This does not affect the db's root
    /// or current snapshot.
    pub async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        // Write the pruned portion of the bitmap to disk *first* to ensure recovery in case of
        // failure during pruning. If we don't do this, we may not be able to recover the bitmap
        // because it may require replaying of pruned operations.
        self.status
            .write_pruned(
                self.context.with_label("bitmap"),
                &self.bitmap_metadata_partition,
            )
            .await?;

        self.any.prune(prune_loc).await
    }

    /// Returns a proof that the specified range of operations are part of the database, along with
    /// the operations from the range. A truncated range (from hitting the max) can be detected by
    /// looking at the length of the returned operations vector. Also returns the bitmap chunks
    /// required to verify the proof.
    ///
    /// # Errors
    ///
    /// Returns [crate::mmr::Error::LocationOverflow] if `start_loc` > [crate::mmr::MAX_LOCATION].
    /// Returns [crate::mmr::Error::RangeOutOfBounds] if `start_loc` >= number of leaves in the MMR.
    pub async fn range_proof(
        &self,
        hasher: &mut H,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(RangeProof<H::Digest>, Vec<Operation<K, V>>, Vec<[u8; N]>), Error> {
        RangeProof::<H::Digest>::new_with_ops(
            hasher,
            &self.status,
            Self::grafting_height(),
            &self.any.log.mmr,
            &self.any.log,
            start_loc,
            max_ops,
        )
        .await
    }

    /// Generate and return a proof of the current value of `key`, along with the other
    /// [KeyValueProof] required to verify the proof. Returns KeyNotFound error if the key is not
    /// currently assigned any value.
    ///
    /// # Errors
    ///
    /// Returns [Error::KeyNotFound] if the key is not currently assigned any value.
    pub async fn key_value_proof(
        &self,
        hasher: &mut H,
        key: K,
    ) -> Result<KeyValueProof<H::Digest, N>, Error> {
        let op_loc = self.any.get_with_loc(&key).await?;
        let Some((_, loc)) = op_loc else {
            return Err(Error::KeyNotFound);
        };
        let height = Self::grafting_height();
        let mmr = &self.any.log.mmr;

        OperationProof::<H::Digest, N>::new(hasher, &self.status, height, mmr, loc).await
    }
}

// Functionality for the Mutable state.
impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > Db<E, K, V, H, T, N, Unmerkleized, NonDurable>
{
    /// Updates `key` to have value `value`. The operation is reflected in the snapshot, but will be
    /// subject to rollback until the next successful `commit`.
    pub async fn update(&mut self, key: K, value: V) -> Result<(), Error> {
        if let Some(old_loc) = self.any.update_key(key, value).await? {
            self.status.set_bit(*old_loc, false);
        }
        self.status.push(true);

        Ok(())
    }

    /// Creates a new key-value pair in the db. The operation is reflected in the snapshot, but will
    /// be subject to rollback until the next successful `commit`. Returns true if the key was
    /// created, false if it already existed.
    pub async fn create(&mut self, key: K, value: V) -> Result<bool, Error> {
        if !self.any.create(key, value).await? {
            return Ok(false);
        }
        self.status.push(true);

        Ok(true)
    }

    /// Delete `key` and its value from the db. Deleting a key that already has no value is a no-op.
    /// The operation is reflected in the snapshot, but will be subject to rollback until the next
    /// successful `commit`. Returns true if the key was deleted, false if it was already inactive.
    pub async fn delete(&mut self, key: K) -> Result<bool, Error> {
        let Some(loc) = self.any.delete_key(key).await? else {
            return Ok(false);
        };

        self.status.push(false);
        self.status.set_bit(*loc, false);

        Ok(true)
    }

    /// Commit any pending operations to the database, ensuring their durability upon return from
    /// this function. Also raises the inactivity floor according to the schedule. Returns the
    /// `[start_loc, end_loc)` location range of committed operations.
    async fn apply_commit_op(&mut self, metadata: Option<V>) -> Result<Range<Location>, Error> {
        let start_loc = self.any.last_commit_loc + 1;

        // Inactivate the current commit operation.
        self.status.set_bit(*self.any.last_commit_loc, false);

        // Raise the inactivity floor by taking `self.steps` steps, plus 1 to account for the
        // previous commit becoming inactive.
        let inactivity_floor_loc = self.any.raise_floor_with_bitmap(&mut self.status).await?;

        // Append the commit operation with the new floor and tag it as active in the bitmap.
        self.status.push(true);
        let commit_op = Operation::CommitFloor(metadata, inactivity_floor_loc);

        self.any.apply_commit_op(commit_op).await?;

        Ok(start_loc..self.op_count())
    }

    /// Commit any pending operations to the database, ensuring their durability upon return.
    /// This transitions to the Durable state without merkleizing. Returns the committed database
    /// and the `[start_loc, end_loc)` range of committed operations.
    pub async fn commit(
        mut self,
        metadata: Option<V>,
    ) -> Result<(Db<E, K, V, H, T, N, Unmerkleized, Durable>, Range<Location>), Error> {
        let range = self.apply_commit_op(metadata).await?;

        // Transition to Durable state without merkleizing
        let any = AnyDb {
            log: self.any.log,
            inactivity_floor_loc: self.any.inactivity_floor_loc,
            last_commit_loc: self.any.last_commit_loc,
            snapshot: self.any.snapshot,
            durable_state: store::Durable,
            active_keys: self.any.active_keys,
            _update: core::marker::PhantomData,
        };

        Ok((
            Db {
                any,
                status: self.status,
                context: self.context,
                bitmap_metadata_partition: self.bitmap_metadata_partition,
                cached_root: None, // Not merkleized yet
            },
            range,
        ))
    }

    /// Merkleize the database and transition to the provable state without committing.
    /// This enables proof generation while keeping the database in the non-durable state.
    pub async fn into_merkleized(
        self,
    ) -> Result<Db<E, K, V, H, T, N, Merkleized<H>, NonDurable>, Error> {
        // Merkleize the any db's log
        let any = AnyDb {
            log: self.any.log.merkleize(),
            inactivity_floor_loc: self.any.inactivity_floor_loc,
            last_commit_loc: self.any.last_commit_loc,
            snapshot: self.any.snapshot,
            durable_state: self.any.durable_state,
            active_keys: self.any.active_keys,
            _update: core::marker::PhantomData,
        };

        // Merkleize the bitmap using the clean MMR
        let mut hasher = StandardHasher::<H>::new();
        let height = Db::<E, K, V, H, T, N, Merkleized<H>, NonDurable>::grafting_height();
        let mut status =
            merkleize_grafted_bitmap(&mut hasher, self.status, &any.log.mmr, height).await?;

        // Prune the bitmap of no-longer-necessary bits.
        status.prune_to_bit(*any.inactivity_floor_loc)?;

        // Compute and cache the root
        let cached_root = Some(root(&mut hasher, height, &status, &any.log.mmr).await?);

        Ok(Db {
            any,
            status,
            context: self.context,
            bitmap_metadata_partition: self.bitmap_metadata_partition,
            cached_root,
        })
    }
}

// Functionality for (Merkleized, NonDurable) state.
impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > Db<E, K, V, H, T, N, Merkleized<H>, NonDurable>
{
    /// Transition into the mutable state.
    pub fn into_mutable(self) -> Db<E, K, V, H, T, N, Unmerkleized, NonDurable> {
        Db {
            any: self.any.into_mutable(),
            status: self.status.into_dirty(),
            context: self.context,
            bitmap_metadata_partition: self.bitmap_metadata_partition,
            cached_root: None,
        }
    }

    /// Commit any pending operations to the database, ensuring their durability upon return.
    /// Returns the committed database and the range of committed operations.
    pub async fn commit(
        self,
        metadata: Option<V>,
    ) -> Result<
        (
            Db<E, K, V, H, T, N, Merkleized<H>, Durable>,
            Range<Location>,
        ),
        Error,
    > {
        let (durable, range) = self.into_mutable().commit(metadata).await?;
        Ok((durable.into_merkleized().await?, range))
    }
}

// Functionality for (Unmerkleized, Durable) state.
impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > Db<E, K, V, H, T, N, Unmerkleized, Durable>
{
    /// Merkleize the database and transition to the provable state.
    pub async fn into_merkleized(
        self,
    ) -> Result<Db<E, K, V, H, T, N, Merkleized<H>, Durable>, Error> {
        // Merkleize the any db's log
        let any = AnyDb {
            log: self.any.log.merkleize(),
            inactivity_floor_loc: self.any.inactivity_floor_loc,
            last_commit_loc: self.any.last_commit_loc,
            snapshot: self.any.snapshot,
            durable_state: self.any.durable_state,
            active_keys: self.any.active_keys,
            _update: core::marker::PhantomData,
        };

        // Merkleize the bitmap using the clean MMR
        let mut hasher = StandardHasher::<H>::new();
        let height = Db::<E, K, V, H, T, N, Merkleized<H>, Durable>::grafting_height();
        let mut status =
            merkleize_grafted_bitmap(&mut hasher, self.status, &any.log.mmr, height).await?;

        // Prune the bitmap of no-longer-necessary bits.
        status.prune_to_bit(*any.inactivity_floor_loc)?;

        // Compute and cache the root
        let cached_root = Some(root(&mut hasher, height, &status, &any.log.mmr).await?);

        Ok(Db {
            any,
            status,
            context: self.context,
            bitmap_metadata_partition: self.bitmap_metadata_partition,
            cached_root,
        })
    }

    /// Transition into the mutable state.
    pub fn into_mutable(self) -> Db<E, K, V, H, T, N, Unmerkleized, NonDurable> {
        Db {
            any: self.any.into_mutable(),
            status: self.status,
            context: self.context,
            bitmap_metadata_partition: self.bitmap_metadata_partition,
            cached_root: None,
        }
    }
}

// LogStore implementation for all states.
impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
        M: MerkleizationState<DigestOf<H>>,
        D: DurabilityState,
    > LogStore for Db<E, K, V, H, T, N, M, D>
{
    type Value = V;

    fn op_count(&self) -> Location {
        self.op_count()
    }

    fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc()
    }

    async fn get_metadata(&self) -> Result<Option<V>, Error> {
        self.get_metadata().await
    }

    fn is_empty(&self) -> bool {
        self.any.is_empty()
    }
}

// Store implementation for all states
impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
        M: MerkleizationState<DigestOf<H>>,
        D: DurabilityState,
    > kv::Gettable for Db<E, K, V, H, T, N, M, D>
{
    type Key = K;
    type Value = V;
    type Error = Error;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
        self.get(key).await
    }
}

// StoreMut for (Unmerkleized,NonDurable) (aka mutable) state
impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > kv::Updatable for Db<E, K, V, H, T, N, Unmerkleized, NonDurable>
{
    async fn update(&mut self, key: Self::Key, value: Self::Value) -> Result<(), Self::Error> {
        self.update(key, value).await
    }
}

// StoreDeletable for (Unmerkleized,NonDurable) (aka mutable) state
impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > kv::Deletable for Db<E, K, V, H, T, N, Unmerkleized, NonDurable>
{
    async fn delete(&mut self, key: Self::Key) -> Result<bool, Self::Error> {
        self.delete(key).await
    }
}

// Batchable for (Unmerkleized,NonDurable) (aka mutable) state
impl<E, K, V, T, H, const N: usize> Batchable for Db<E, K, V, H, T, N, Unmerkleized, NonDurable>
where
    E: RStorage + Clock + Metrics,
    K: Array,
    V: FixedValue,
    T: Translator,
    H: Hasher,
{
    async fn write_batch(
        &mut self,
        iter: impl Iterator<Item = (K, Option<V>)>,
    ) -> Result<(), Error> {
        let status = &mut self.status;
        self.any
            .write_batch_with_callback(iter, move |append: bool, loc: Option<Location>| {
                status.push(append);
                if let Some(loc) = loc {
                    status.set_bit(*loc, false);
                }
            })
            .await
    }
}

// MerkleizedStore for Merkleized states (both Durable and NonDurable)
// TODO(https://github.com/commonwarexyz/monorepo/issues/2560): This is broken -- it's computing
// proofs only over the any db mmr not the grafted mmr, so they won't validate against the grafted
// root.
impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
        D: store::State,
    > MerkleizedStore for Db<E, K, V, H, T, N, Merkleized<H>, D>
{
    type Digest = H::Digest;
    type Operation = Operation<K, V>;

    fn root(&self) -> Self::Digest {
        self.cached_root
            .expect("Merkleized state must have cached root")
    }

    async fn historical_proof(
        &self,
        historical_size: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<Self::Digest>, Vec<Self::Operation>), Error> {
        self.any
            .historical_proof(historical_size, start_loc, max_ops)
            .await
    }
}

// PrunableStore for both Merkleized states.
impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
        D: DurabilityState,
    > PrunableStore for Db<E, K, V, H, T, N, Merkleized<H>, D>
{
    async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        self.prune(prune_loc).await
    }
}

// Persistable for Clean state
impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > Persistable for Db<E, K, V, H, T, N, Merkleized<H>, Durable>
{
    type Error = Error;

    async fn commit(&mut self) -> Result<(), Self::Error> {
        // No-op, DB already recoverable.
        Ok(())
    }

    async fn sync(&mut self) -> Result<(), Self::Error> {
        self.sync().await
    }

    async fn destroy(self) -> Result<(), Self::Error> {
        self.destroy().await
    }
}

// CleanAny implementation
#[cfg(any(test, feature = "test-traits"))]
impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > CleanAny for Db<E, K, V, H, T, N, Merkleized<H>, Durable>
{
    type Mutable = Db<E, K, V, H, T, N, Unmerkleized, NonDurable>;

    fn into_mutable(self) -> Self::Mutable {
        self.into_mutable()
    }
}

// UnmerkleizedDurableAny implementation
#[cfg(any(test, feature = "test-traits"))]
impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > UnmerkleizedDurableAny for Db<E, K, V, H, T, N, Unmerkleized, Durable>
{
    type Digest = H::Digest;
    type Operation = Operation<K, V>;
    type Mutable = Db<E, K, V, H, T, N, Unmerkleized, NonDurable>;
    type Merkleized = Db<E, K, V, H, T, N, Merkleized<H>, Durable>;

    fn into_mutable(self) -> Self::Mutable {
        Db {
            any: self.any.into_mutable(),
            status: self.status,
            context: self.context,
            bitmap_metadata_partition: self.bitmap_metadata_partition,
            cached_root: None,
        }
    }

    async fn into_merkleized(self) -> Result<Self::Merkleized, Error> {
        self.into_merkleized().await
    }
}

// MerkleizedNonDurableAny implementation
#[cfg(any(test, feature = "test-traits"))]
impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > MerkleizedNonDurableAny for Db<E, K, V, H, T, N, Merkleized<H>, NonDurable>
{
    type Mutable = Db<E, K, V, H, T, N, Unmerkleized, NonDurable>;
    type Durable = Db<E, K, V, H, T, N, Merkleized<H>, Durable>;

    async fn commit(self, metadata: Option<V>) -> Result<(Self::Durable, Range<Location>), Error> {
        self.commit(metadata).await
    }

    fn into_mutable(self) -> Self::Mutable {
        self.into_mutable()
    }
}

// MutableAny implementation
#[cfg(any(test, feature = "test-traits"))]
impl<
        E: RStorage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
    > MutableAny for Db<E, K, V, H, T, N, Unmerkleized, NonDurable>
{
    type Digest = H::Digest;
    type Operation = Operation<K, V>;
    type Durable = Db<E, K, V, H, T, N, Unmerkleized, Durable>;
    type Merkleized = Db<E, K, V, H, T, N, Merkleized<H>, NonDurable>;

    async fn commit(self, metadata: Option<V>) -> Result<(Self::Durable, Range<Location>), Error> {
        self.commit(metadata).await
    }

    async fn into_merkleized(self) -> Result<Self::Merkleized, Error> {
        self.into_merkleized().await
    }

    fn steps(&self) -> u64 {
        self.any.durable_state.steps
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::{
        index::Unordered as _, mmr::hasher::Hasher as _, qmdb::store::batch_tests,
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{buffer::PoolRef, deterministic, Runner as _};
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use std::{
        collections::HashMap,
        num::{NonZeroU16, NonZeroUsize},
    };
    use tracing::warn;

    const PAGE_SIZE: NonZeroU16 = NZU16!(88);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(8);

    fn current_db_config(partition_prefix: &str) -> Config<TwoCap> {
        Config {
            mmr_journal_partition: format!("{partition_prefix}_journal_partition"),
            mmr_metadata_partition: format!("{partition_prefix}_metadata_partition"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_journal_partition: format!("{partition_prefix}_partition_prefix"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            bitmap_metadata_partition: format!("{partition_prefix}_bitmap_metadata_partition"),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    /// A type alias for the concrete [Db] type used in these unit tests (Merkleized, Durable).
    type CleanCurrentTest = Db<deterministic::Context, Digest, Digest, Sha256, TwoCap, 32>;

    /// A type alias for the Dirty (Unmerkleized, NonDurable) variant of CurrentTest.
    type DirtyCurrentTest =
        Db<deterministic::Context, Digest, Digest, Sha256, TwoCap, 32, Unmerkleized, NonDurable>;

    /// Return an [Db] database initialized with a fixed config.
    async fn open_db(context: deterministic::Context, partition_prefix: &str) -> CleanCurrentTest {
        CleanCurrentTest::init(context, current_db_config(partition_prefix))
            .await
            .unwrap()
    }

    /// Build a small database, then close and reopen it and ensure state is preserved.
    #[test_traced("DEBUG")]
    pub fn test_current_db_build_small_close_reopen() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let partition = "build_small";
            let db = open_db(context.clone(), partition).await;
            assert_eq!(db.op_count(), 1);
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(0));
            let root0 = db.root();
            drop(db);
            let db = open_db(context.clone(), partition).await;
            assert_eq!(db.op_count(), 1);
            assert!(db.get_metadata().await.unwrap().is_none());
            assert_eq!(db.root(), root0);

            // Add one key.
            let mut db = db.into_mutable();
            let k1 = Sha256::hash(&0u64.to_be_bytes());
            let v1 = Sha256::hash(&10u64.to_be_bytes());
            assert!(db.create(k1, v1).await.unwrap());
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            let (db, range) = db.commit(None).await.unwrap();
            let db = db.into_merkleized().await.unwrap();
            assert_eq!(*range.start, 1);
            assert_eq!(*range.end, 4);
            assert!(db.get_metadata().await.unwrap().is_none());
            assert_eq!(db.op_count(), 4); // 1 update, 1 commit, 1 move + 1 initial commit.
            let root1 = db.root();
            assert!(root1 != root0);
            drop(db);
            let db = open_db(context.clone(), partition).await;
            assert_eq!(db.op_count(), 4); // 1 update, 1 commit, 1 moves + 1 initial commit.
            assert!(db.get_metadata().await.unwrap().is_none());
            assert_eq!(db.root(), root1);

            // Create of same key should fail.
            let mut db = db.into_mutable();
            assert!(!db.create(k1, v1).await.unwrap());

            // Delete that one key.
            assert!(db.delete(k1).await.unwrap());
            let metadata = Sha256::hash(&1u64.to_be_bytes());
            let (db, range) = db.commit(Some(metadata)).await.unwrap();
            let db = db.into_merkleized().await.unwrap();
            assert_eq!(*range.start, 4);
            assert_eq!(*range.end, 6);
            assert_eq!(db.op_count(), 6); // 1 update, 2 commits, 1 move, 1 delete.
            assert_eq!(db.get_metadata().await.unwrap().unwrap(), metadata);
            let root2 = db.root();

            // Repeated delete of same key should fail.
            let mut db = db.into_mutable();
            assert!(!db.delete(k1).await.unwrap());
            let (db, _) = db.commit(None).await.unwrap();
            let mut db = db.into_merkleized().await.unwrap();
            db.sync().await.unwrap();
            // Commit adds a commit even for no-op, so op_count increases and root changes.
            assert_eq!(db.op_count(), 7);
            let root3 = db.root();
            assert!(root3 != root2);

            // Confirm re-open preserves state.
            drop(db);
            let db = open_db(context.clone(), partition).await;
            assert_eq!(db.op_count(), 7);
            // Last commit had no metadata (passed None to commit).
            assert!(db.get_metadata().await.unwrap().is_none());
            assert_eq!(db.root(), root3);

            // Confirm all activity bits are false except for the last commit.
            for i in 0..*db.op_count() - 1 {
                assert!(!db.status.get_bit(i));
            }
            assert!(db.status.get_bit(*db.op_count() - 1));

            // Test that we can do a non-durable root.
            let mut db = db.into_mutable();
            db.update(k1, v1).await.unwrap();
            let db = db.into_merkleized().await.unwrap();
            assert_ne!(db.root(), root3);

            // Test that we can do a merkleized commit.
            let (db, _) = db.commit(None).await.unwrap();
            assert!(db.get_metadata().await.unwrap().is_none());
            assert_eq!(db.op_count(), 10);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_current_db_build_big() {
        let executor = deterministic::Runner::default();
        // Build a db with 1000 keys, some of which we update and some of which we delete, and
        // confirm that the end state of the db matches that of an identically updated hashmap.
        const ELEMENTS: u64 = 1000;
        executor.start(|context| async move {
            let mut db = open_db(context.clone(), "build_big").await.into_mutable();

            let mut map = HashMap::<Digest, Digest>::default();
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&i.to_be_bytes());
                let v = Sha256::hash(&(i * 1000).to_be_bytes());
                db.update(k, v).await.unwrap();
                map.insert(k, v);
            }

            // Update every 3rd key
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                let v = Sha256::hash(&((i + 1) * 10000).to_be_bytes());
                db.update(k, v).await.unwrap();
                map.insert(k, v);
            }

            // Delete every 7th key
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Sha256::hash(&i.to_be_bytes());
                db.delete(k).await.unwrap();
                map.remove(&k);
            }

            assert_eq!(db.op_count(), 1478);
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(0));
            assert_eq!(db.op_count(), 1478);
            assert_eq!(db.any.snapshot.items(), 857);

            // Test that commit + sync w/ pruning will raise the activity floor.
            let (db, _) = db.commit(None).await.unwrap();
            let mut db = db.into_merkleized().await.unwrap();
            db.sync().await.unwrap();
            db.prune(db.inactivity_floor_loc()).await.unwrap();
            assert_eq!(db.op_count(), 1957);
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(838));
            assert_eq!(db.any.snapshot.items(), 857);

            // Drop & reopen the db, making sure it has exactly the same state.
            let root = db.root();
            db.sync().await.unwrap();
            drop(db);
            let db = open_db(context.clone(), "build_big").await;
            assert_eq!(root, db.root());
            assert_eq!(db.op_count(), 1957);
            assert_eq!(db.inactivity_floor_loc(), Location::new_unchecked(838));
            assert_eq!(db.any.snapshot.items(), 857);

            // Confirm the db's state matches that of the separate map we computed independently.
            for i in 0u64..1000 {
                let k = Sha256::hash(&i.to_be_bytes());
                if let Some(map_value) = map.get(&k) {
                    let Some(db_value) = db.get(&k).await.unwrap() else {
                        panic!("key not found in db: {k}");
                    };
                    assert_eq!(*map_value, db_value);
                } else {
                    assert!(db.get(&k).await.unwrap().is_none());
                }
            }
        });
    }

    // Test that merkleization state changes don't reset `steps`.
    #[test_traced("DEBUG")]
    fn test_current_unordered_fixed_db_steps_not_reset() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_db(context, "steps_test").await;
            crate::qmdb::any::test::test_any_db_steps_not_reset(db).await;
        });
    }

    /// Build a tiny database and make sure we can't convince the verifier that some old value of a
    /// key is active. We specifically test over the partial chunk case, since these bits are yet to
    /// be committed to the underlying MMR.
    #[test_traced("DEBUG")]
    pub fn test_current_db_verify_proof_over_bits_in_uncommitted_chunk() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            let partition = "build_small";
            let mut db = open_db(context.clone(), partition).await.into_mutable();

            // Add one key.
            let k = Sha256::fill(0x01);
            let v1 = Sha256::fill(0xA1);
            db.update(k, v1).await.unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let db = db.into_merkleized().await.unwrap();

            let (_, op_loc) = db.any.get_with_loc(&k).await.unwrap().unwrap();
            let proof = db.key_value_proof(hasher.inner(), k).await.unwrap();

            // Proof should be verifiable against current root.
            let root = db.root();
            assert!(CleanCurrentTest::verify_key_value_proof(
                hasher.inner(),
                k,
                v1,
                &proof,
                &root
            ));

            let v2 = Sha256::fill(0xA2);
            // Proof should not verify against a different value.
            assert!(!CleanCurrentTest::verify_key_value_proof(
                hasher.inner(),
                k,
                v2,
                &proof,
                &root,
            ));

            // Update the key to a new value (v2), which inactivates the previous operation.
            let mut db = db.into_mutable();
            db.update(k, v2).await.unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let db = db.into_merkleized().await.unwrap();
            let root = db.root();

            // New value should not be verifiable against the old proof.
            assert!(!CleanCurrentTest::verify_key_value_proof(
                hasher.inner(),
                k,
                v2,
                &proof,
                &root,
            ));

            // But the new value should verify against a new proof.
            let proof = db.key_value_proof(hasher.inner(), k).await.unwrap();
            assert!(CleanCurrentTest::verify_key_value_proof(
                hasher.inner(),
                k,
                v2,
                &proof,
                &root,
            ));

            // Old value will not verify against new proof.
            assert!(!CleanCurrentTest::verify_key_value_proof(
                hasher.inner(),
                k,
                v1,
                &proof,
                &root,
            ));

            // Create a proof of the now-inactive update operation assigining v1 to k against the
            // current root.
            let (range_proof, _, chunks) = db
                .range_proof(hasher.inner(), op_loc, NZU64!(1))
                .await
                .unwrap();
            let proof_inactive = KeyValueProof {
                loc: op_loc,
                chunk: chunks[0],
                range_proof,
            };
            // This proof should verify using verify_range_proof which does not check activity
            // status.
            let op = Operation::Update(Update(k, v1));
            assert!(CleanCurrentTest::verify_range_proof(
                hasher.inner(),
                &proof_inactive.range_proof,
                proof_inactive.loc,
                &[op],
                &[proof_inactive.chunk],
                &root,
            ));

            // But this proof should *not* verify as a key value proof, since verification will see
            // that the operation is inactive.
            assert!(!CleanCurrentTest::verify_key_value_proof(
                hasher.inner(),
                k,
                v1,
                &proof_inactive,
                &root,
            ));

            // Attempt #1 to "fool" the verifier:  change the location to that of an active
            // operation. This should not fool the verifier if we're properly validating the
            // inclusion of the operation itself, and not just the chunk.
            let (_, active_loc) = db.any.get_with_loc(&k).await.unwrap().unwrap();
            // The new location should differ but still be in the same chunk.
            assert_ne!(active_loc, proof_inactive.loc);
            assert_eq!(
                CleanBitMap::<Digest, 32>::leaf_pos(*active_loc),
                CleanBitMap::<Digest, 32>::leaf_pos(*proof_inactive.loc)
            );
            let mut fake_proof = proof_inactive.clone();
            fake_proof.loc = active_loc;
            assert!(!CleanCurrentTest::verify_key_value_proof(
                hasher.inner(),
                k,
                v1,
                &fake_proof,
                &root,
            ));

            // Attempt #2 to "fool" the verifier: Modify the chunk in the proof info to make it look
            // like the operation is active by flipping its corresponding bit to 1. This should not
            // fool the verifier if we are correctly incorporating the partial chunk information
            // into the root computation.
            let mut modified_chunk = proof_inactive.chunk;
            let bit_pos = *proof_inactive.loc;
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            modified_chunk[byte_idx as usize] |= 1 << bit_idx;

            let mut fake_proof = proof_inactive.clone();
            fake_proof.chunk = modified_chunk;
            assert!(!CleanCurrentTest::verify_key_value_proof(
                hasher.inner(),
                k,
                v1,
                &fake_proof,
                &root,
            ));

            db.destroy().await.unwrap();
        });
    }

    /// Apply random operations to the given db, committing them (randomly & at the end) only if
    /// `commit_changes` is true. Returns a dirty db; callers should commit if needed.
    async fn apply_random_ops(
        num_elements: u64,
        commit_changes: bool,
        rng_seed: u64,
        mut db: DirtyCurrentTest,
    ) -> Result<DirtyCurrentTest, Error> {
        // Log the seed with high visibility to make failures reproducible.
        warn!("rng_seed={}", rng_seed);
        let mut rng = StdRng::seed_from_u64(rng_seed);

        for i in 0u64..num_elements {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = Sha256::hash(&rng.next_u32().to_be_bytes());
            db.update(k, v).await.unwrap();
        }

        // Randomly update / delete them. We use a delete frequency that is 1/7th of the update
        // frequency.
        for _ in 0u64..num_elements * 10 {
            let rand_key = Sha256::hash(&(rng.next_u64() % num_elements).to_be_bytes());
            if rng.next_u32() % 7 == 0 {
                db.delete(rand_key).await.unwrap();
                continue;
            }
            let v = Sha256::hash(&rng.next_u32().to_be_bytes());
            db.update(rand_key, v).await.unwrap();
            if commit_changes && rng.next_u32() % 20 == 0 {
                // Commit every ~20 updates.
                let (durable_db, _) = db.commit(None).await?;
                let clean_db = durable_db.into_merkleized().await?;
                db = clean_db.into_mutable();
            }
        }
        if commit_changes {
            let (durable_db, _) = db.commit(None).await?;
            let clean_db = durable_db.into_merkleized().await?;
            db = clean_db.into_mutable();
        }
        Ok(db)
    }

    #[test_traced("DEBUG")]
    pub fn test_current_db_range_proofs() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let partition = "range_proofs";
            let mut hasher = StandardHasher::<Sha256>::new();
            let db = open_db(context.clone(), partition).await;
            let root = db.root();

            // Empty range proof should not crash or verify, since even an empty db has a single
            // commit op.
            let proof = RangeProof {
                proof: Proof::default(),
                partial_chunk_digest: None,
            };
            assert!(!CleanCurrentTest::verify_range_proof(
                hasher.inner(),
                &proof,
                Location::new_unchecked(0),
                &[],
                &[],
                &root,
            ));

            let db = apply_random_ops(200, true, context.next_u64(), db.into_mutable())
                .await
                .unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let db = db.into_merkleized().await.unwrap();
            let root = db.root();

            // Make sure size-constrained batches of operations are provable from the oldest
            // retained op to tip.
            let max_ops = 4;
            let end_loc = db.op_count();
            let start_loc = db.any.inactivity_floor_loc();

            for loc in *start_loc..*end_loc {
                let loc = Location::new_unchecked(loc);
                let (proof, ops, chunks) = db
                    .range_proof(hasher.inner(), loc, NZU64!(max_ops))
                    .await
                    .unwrap();
                assert!(
                    CleanCurrentTest::verify_range_proof(
                        hasher.inner(),
                        &proof,
                        loc,
                        &ops,
                        &chunks,
                        &root
                    ),
                    "failed to verify range at start_loc {start_loc}",
                );
                // Proof should not verify if we include extra chunks.
                let mut chunks_with_extra = chunks.clone();
                chunks_with_extra.push(chunks[chunks.len() - 1]);
                assert!(!CleanCurrentTest::verify_range_proof(
                    hasher.inner(),
                    &proof,
                    loc,
                    &ops,
                    &chunks_with_extra,
                    &root,
                ));
            }

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    pub fn test_current_db_key_value_proof() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let partition = "range_proofs";
            let mut hasher = StandardHasher::<Sha256>::new();
            let db = open_db(context.clone(), partition).await.into_mutable();
            let db = apply_random_ops(500, true, context.next_u64(), db)
                .await
                .unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let db = db.into_merkleized().await.unwrap();
            let root = db.root();

            // Confirm bad keys produce the expected error.
            let bad_key = Sha256::fill(0xAA);
            let res = db.key_value_proof(hasher.inner(), bad_key).await;
            assert!(matches!(res, Err(Error::KeyNotFound)));

            let start = *db.inactivity_floor_loc();
            for i in start..db.status.len() {
                if !db.status.get_bit(i) {
                    continue;
                }
                // Found an active operation! Create a proof for its active current key/value if
                // it's a key-updating operation.
                let (key, value) = match db.any.log.read(Location::new_unchecked(i)).await.unwrap()
                {
                    Operation::Update(Update(key, value)) => (key, value),
                    Operation::CommitFloor(_, _) => continue,
                    Operation::Delete(_) => {
                        unreachable!("location does not reference update/commit operation")
                    }
                };

                let proof = db.key_value_proof(hasher.inner(), key).await.unwrap();
                // Proof should validate against the current value and correct root.
                assert!(CleanCurrentTest::verify_key_value_proof(
                    hasher.inner(),
                    key,
                    value,
                    &proof,
                    &root
                ));
                // Proof should fail against the wrong value.
                let wrong_val = Sha256::fill(0xFF);
                assert!(!CleanCurrentTest::verify_key_value_proof(
                    hasher.inner(),
                    key,
                    wrong_val,
                    &proof,
                    &root
                ));
                // Proof should fail against the wrong key.
                let wrong_key = Sha256::fill(0xEE);
                assert!(!CleanCurrentTest::verify_key_value_proof(
                    hasher.inner(),
                    wrong_key,
                    value,
                    &proof,
                    &root
                ));
                // Proof should fail against the wrong root.
                let wrong_root = Sha256::fill(0xDD);
                assert!(!CleanCurrentTest::verify_key_value_proof(
                    hasher.inner(),
                    key,
                    value,
                    &proof,
                    &wrong_root,
                ));
            }

            db.destroy().await.unwrap();
        });
    }

    /// This test builds a random database, and makes sure that its state is correctly restored
    /// after closing and re-opening.
    #[test_traced("WARN")]
    pub fn test_current_db_build_random_close_reopen() {
        // Number of elements to initially insert into the db.
        const ELEMENTS: u64 = 1000;

        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let partition = "build_random";
            let rng_seed = context.next_u64();
            let db = open_db(context.clone(), partition).await.into_mutable();
            let db = apply_random_ops(ELEMENTS, true, rng_seed, db)
                .await
                .unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let mut db = db.into_merkleized().await.unwrap();
            db.sync().await.unwrap();

            // Drop and reopen the db
            let root = db.root();

            drop(db);
            let db = open_db(context, partition).await;

            // Ensure the root matches
            assert_eq!(db.root(), root);

            db.destroy().await.unwrap();
        });
    }

    /// Repeatedly update the same key to a new value and ensure we can prove its current value
    /// after each update.
    #[test_traced("WARN")]
    pub fn test_current_db_proving_repeated_updates() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            let partition = "build_small";
            let mut db = open_db(context.clone(), partition).await;

            // Add one key.
            let k = Sha256::fill(0x00);
            let mut old_val = Sha256::fill(0x00);
            for i in 1u8..=255 {
                let v = Sha256::fill(i);
                let mut dirty_db = db.into_mutable();
                dirty_db.update(k, v).await.unwrap();
                assert_eq!(dirty_db.get(&k).await.unwrap().unwrap(), v);
                let (durable_db, _) = dirty_db.commit(None).await.unwrap();
                db = durable_db.into_merkleized().await.unwrap();
                let root = db.root();

                // Create a proof for the current value of k.
                let proof = db.key_value_proof(hasher.inner(), k).await.unwrap();
                assert!(
                    CleanCurrentTest::verify_key_value_proof(hasher.inner(), k, v, &proof, &root),
                    "proof of update {i} failed to verify"
                );
                // Ensure the proof does NOT verify if we use the previous value.
                assert!(
                    !CleanCurrentTest::verify_key_value_proof(
                        hasher.inner(),
                        k,
                        old_val,
                        &proof,
                        &root
                    ),
                    "proof of update {i} verified when it should not have"
                );
                old_val = v;
            }

            db.destroy().await.unwrap();
        });
    }

    /// This test builds a random database and simulates we can recover from different types of
    /// failure scenarios.
    #[test_traced("WARN")]
    pub fn test_current_db_simulate_write_failures() {
        // Number of elements to initially insert into the db.
        const ELEMENTS: u64 = 1000;

        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let partition = "build_random_fail_commit";
            let rng_seed = context.next_u64();
            let db = open_db(context.clone(), partition).await.into_mutable();
            let db = apply_random_ops(ELEMENTS, true, rng_seed, db)
                .await
                .unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let mut db = db.into_merkleized().await.unwrap();
            let committed_root = db.root();
            let committed_op_count = db.op_count();
            let committed_inactivity_floor = db.any.inactivity_floor_loc();
            db.prune(committed_inactivity_floor).await.unwrap();

            // Perform more random operations without committing any of them.
            let db = apply_random_ops(ELEMENTS, false, rng_seed + 1, db.into_mutable())
                .await
                .unwrap();

            // SCENARIO #1: Simulate a crash that happens before any writes. Upon reopening, the
            // state of the DB should be as of the last commit.
            drop(db);
            let db = open_db(context.clone(), partition).await;
            assert_eq!(db.root(), committed_root);
            assert_eq!(db.op_count(), committed_op_count);

            // Re-apply the exact same uncommitted operations.
            let db = apply_random_ops(ELEMENTS, false, rng_seed + 1, db.into_mutable())
                .await
                .unwrap();

            // SCENARIO #2: Simulate a crash that happens after the any db has been committed, but
            // before the state of the pruned bitmap can be written to disk (i.e., before
            // into_merkleized is called). We do this by committing and then dropping the durable
            // db without calling close or into_merkleized.
            let (durable_db, _) = db.commit(None).await.unwrap();
            let committed_op_count = durable_db.op_count();
            drop(durable_db);

            // We should be able to recover, so the root should differ from the previous commit, and
            // the op count should be greater than before.
            let db = open_db(context.clone(), partition).await;
            let scenario_2_root = db.root();

            // To confirm the second committed hash is correct we'll re-build the DB in a new
            // partition, but without any failures. They should have the exact same state.
            let fresh_partition = "build_random_fail_commit_fresh";
            let db = open_db(context.clone(), fresh_partition)
                .await
                .into_mutable();
            let db = apply_random_ops(ELEMENTS, true, rng_seed, db)
                .await
                .unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let db = apply_random_ops(ELEMENTS, false, rng_seed + 1, db.into_mutable())
                .await
                .unwrap();
            let (db, _) = db.commit(None).await.unwrap();
            let mut db = db.into_merkleized().await.unwrap();
            db.prune(db.any.inactivity_floor_loc()).await.unwrap();
            // State from scenario #2 should match that of a successful commit.
            assert_eq!(db.op_count(), committed_op_count);
            assert_eq!(db.root(), scenario_2_root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    pub fn test_current_db_different_pruning_delays_same_root() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create two databases that are identical other than how they are pruned.
            let db_config_no_pruning = current_db_config("no_pruning_test");

            let db_config_pruning = current_db_config("pruning_test");

            let mut db_no_pruning =
                CleanCurrentTest::init(context.clone(), db_config_no_pruning.clone())
                    .await
                    .unwrap()
                    .into_mutable();
            let mut db_pruning = CleanCurrentTest::init(context.clone(), db_config_pruning.clone())
                .await
                .unwrap()
                .into_mutable();

            // Apply identical operations to both databases, but only prune one.
            const NUM_OPERATIONS: u64 = 1000;
            for i in 0..NUM_OPERATIONS {
                let key = Sha256::hash(&i.to_be_bytes());
                let value = Sha256::hash(&(i * 1000).to_be_bytes());

                db_no_pruning.update(key, value).await.unwrap();
                db_pruning.update(key, value).await.unwrap();

                // Commit periodically
                if i % 50 == 49 {
                    let (db_1, _) = db_no_pruning.commit(None).await.unwrap();
                    let clean_no_pruning = db_1.into_merkleized().await.unwrap();
                    let (db_2, _) = db_pruning.commit(None).await.unwrap();
                    let mut clean_pruning = db_2.into_merkleized().await.unwrap();
                    clean_pruning
                        .prune(clean_no_pruning.any.inactivity_floor_loc())
                        .await
                        .unwrap();
                    db_no_pruning = clean_no_pruning.into_mutable();
                    db_pruning = clean_pruning.into_mutable();
                }
            }

            // Final commit
            let (db_1, _) = db_no_pruning.commit(None).await.unwrap();
            let db_no_pruning = db_1.into_merkleized().await.unwrap();
            let (db_2, _) = db_pruning.commit(None).await.unwrap();
            let db_pruning = db_2.into_merkleized().await.unwrap();

            // Get roots from both databases
            let root_no_pruning = db_no_pruning.root();
            let root_pruning = db_pruning.root();

            // Verify they generate the same roots
            assert_eq!(root_no_pruning, root_pruning);

            drop(db_no_pruning);
            drop(db_pruning);

            // Restart both databases
            let db_no_pruning = CleanCurrentTest::init(context.clone(), db_config_no_pruning)
                .await
                .unwrap();
            let db_pruning = CleanCurrentTest::init(context.clone(), db_config_pruning)
                .await
                .unwrap();
            assert_eq!(
                db_no_pruning.inactivity_floor_loc(),
                db_pruning.inactivity_floor_loc()
            );

            // Get roots after restart
            let root_no_pruning_restart = db_no_pruning.root();
            let root_pruning_restart = db_pruning.root();

            // Ensure roots still match after restart
            assert_eq!(root_no_pruning, root_no_pruning_restart);
            assert_eq!(root_pruning, root_pruning_restart);

            db_no_pruning.destroy().await.unwrap();
            db_pruning.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    fn test_batch() {
        batch_tests::test_batch(|mut ctx| async move {
            let seed = ctx.next_u64();
            let prefix = format!("current_unordered_batch_{seed}");
            open_db(ctx, &prefix).await.into_mutable()
        });
    }
}
