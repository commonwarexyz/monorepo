//! An _Any_ authenticated database provides succinct proofs of any value ever associated with a
//! key.
//!
//! The specific variants provided within this module include:
//! - Unordered: The database does not maintain or require any ordering over the key space.
//!   - Fixed-size values
//!   - Variable-size values
//! - Ordered: The database maintains a total order over active keys.
//!   - Fixed-size values
//!   - Variable-size values
//!
//! An Any database can be in one of four states based on two orthogonal dimensions:
//! - Merkleization: `Merkleized` (has computed root) or `Unmerkleized` (root not yet computed)
//! - Durability: `Durable` (committed to disk) or `NonDurable` (uncommitted changes)
//!
//! State transitions:
//! - `init()`                                    → `(Merkleized,Durable)`
//! - `(Merkleized,Durable).into_mutable()`       → `(Unmerkleized,NonDurable)`
//! - `(Unmerkleized,Durable).into_mutable()`     → `(Unmerkleized,NonDurable)`
//! - `(Merkleized,NonDurable).into_mutable()`    → `(Unmerkleized,NonDurable)`
//! - `(Unmerkleized,Durable).into_merkleized()`    → `(Merkleized,Durable)`
//! - `(Unmerkleized,NonDurable).into_merkleized()` → `(Merkleized,NonDurable)`
//! - `(Unmerkleized,NonDurable).commit()`        → `(Unmerkleized,Durable)`
//!
//! We call the combined (Unmerkleized,NonDurable) state the _Mutable_ state since it's the only
//! state in which the database state (as reflected by its `root`) can be changed.
//!
//! The database implements [Store] and [LogStore] in every state. The additional functionality
//! offered by specific states is as follow:
//!
//! - (Merkleized,Durable):      [MerkleizedStore], [PrunableStore], [Persistable]
//! - (Merkleized,NonDurable):   [MerkleizedStore], [PrunableStore]
//! - (Unmerkleized,NonDurable): [StoreDeletable] (create/update/delete/commit) [Batchable]
//! - (Unmerkleized,Durable):    <None>

use crate::{
    journal::{
        authenticated,
        contiguous::fixed::{Config as JConfig, Journal},
    },
    mmr::{journaled::Config as MmrConfig, mem::Clean, Location},
    qmdb::{
        operation::Committable,
        store::{MerkleizedStore, Batchable, LogStore, PrunableStore},
        Error,
    },
    store::{Store, StoreDeletable},
    translator::Translator,
    Persistable,
};
use commonware_codec::{Codec, CodecFixed};
use commonware_cryptography::{Digest, DigestOf, Hasher};
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage, ThreadPool};
use commonware_utils::Array;
use std::{
    future::Future,
    num::{NonZeroU64, NonZeroUsize},
    ops::Range,
};

pub mod db;
mod operation;

mod value;
pub(crate) use value::{FixedValue, ValueEncoding, VariableValue};

mod ext;
pub mod ordered;
pub mod unordered;

//pub use ext::AnyExt;

/// Trait for the (Merkleized,Durable) state.
///
/// This state allows authentication (root, proofs), pruning, and persistence operations
/// (sync/close/destroy). Use `into_mutable` to transition to the (Unmerkleized,Non-durable) state.
pub trait MerkleizedDurableAny:
    MerkleizedStore
    + PrunableStore
    + Persistable<Error = Error>
    + Store<Key: Array, Value = <Self as LogStore>::Value, Error = Error>
{
    /// The mutable state type (Unmerkleized,Non-durable).
    type Mutable: UnmerkleizedNonDurableAny<
            Key = Self::Key,
            Digest = <Self as MerkleizedStore>::Digest,
            Operation = <Self as MerkleizedStore>::Operation,
            // Cycle constraint for path: into_merkleized() then commit()
            Provable: MerkleizedNonDurableAny<Durable = Self>
                          + MerkleizedStore<
                Digest = <Self as MerkleizedStore>::Digest,
                Operation = <Self as MerkleizedStore>::Operation,
            >,
            // Cycle constraints for path: commit() then into_merkleized() or into_mutable()
            Durable: UnmerkleizedDurableAny<Provable = Self, Mutable = Self::Mutable>,
        > + LogStore<Value = <Self as LogStore>::Value>;

    /// Convert this database into the mutable (Unmerkleized, Non-durable) state.
    fn into_mutable(self) -> Self::Mutable;
}

/// Trait for the (Unmerkleized,Durable) state.
///
/// Use `into_mutable` to transition to the (Unmerkleized,NonDurable) state, or `into_merkleized` to
/// transition to the (Merkleized,Durable) state.
pub trait UnmerkleizedDurableAny:
    LogStore + Store<Key: Array, Value = <Self as LogStore>::Value, Error = Error>
{
    /// The digest type used by Merkleized states in this database's state machine.
    type Digest: Digest;

    /// The operation type used by Merkleized states in this database's state machine.
    type Operation: Codec;

    /// The mutable state type (Unmerkleized,NonDurable).
    type Mutable: UnmerkleizedNonDurableAny<
            Key = Self::Key,
            Digest = Self::Digest,
            Operation = Self::Operation,
        > + LogStore<Value = <Self as LogStore>::Value>;

    /// The provable state type (Merkleized,Durable).
    type Provable: MerkleizedDurableAny<Key = Self::Key>
        + MerkleizedStore<
            Value = <Self as LogStore>::Value,
            Digest = Self::Digest,
            Operation = Self::Operation,
        >;

    /// Convert this database into the mutable (Unmerkleized,NonDurable) state.
    fn into_mutable(self) -> Self::Mutable;

    /// Convert this database into the provable (Merkleized,Durable) state.
    fn into_merkleized(self) -> impl Future<Output = Result<Self::Provable, Error>>;
}

/// Trait for the (Merkleized,NonDurable) state.
///
/// This state allows authentication (root, proofs) and pruning. Use `commit` to transition to the
/// Merkleized, Durable state.
pub trait MerkleizedNonDurableAny:
    MerkleizedStore
    + PrunableStore
    + Store<Key: Array, Value = <Self as LogStore>::Value, Error = Error>
{
    /// The durable state type (Merkleized,Durable).
    type Durable: MerkleizedDurableAny<Key = Self::Key>
        + MerkleizedStore<
            Value = <Self as LogStore>::Value,
            Digest = <Self as MerkleizedStore>::Digest,
            Operation = <Self as MerkleizedStore>::Operation,
        >;

    /// Commit any pending operations to the database, ensuring their durability. Returns the
    /// durable state and the location range of committed operations.
    fn commit(
        self,
        metadata: Option<<Self as LogStore>::Value>,
    ) -> impl Future<Output = Result<(Self::Durable, Range<Location>), Error>>;
}

/// Trait for the (Unmerkleized,NonDurable) state.
///
/// This is the only state that allows mutations (create/update/delete). Use `commit` to transition
/// to the Unmerkleized, Durable state, or `into_merkleized` to transition to the Merkleized,
/// NonDurable state.
pub trait UnmerkleizedNonDurableAny:
    LogStore + StoreDeletable<Key: Array, Value = <Self as LogStore>::Value, Error = Error> + Batchable
{
    /// The digest type used by Merkleized states in this database's state machine.
    type Digest: Digest;

    /// The operation type used by Merkleized states in this database's state machine.
    type Operation: Codec;

    /// The durable state type (Unmerkleized,Durable).
    type Durable: UnmerkleizedDurableAny<Key = Self::Key, Digest = Self::Digest, Operation = Self::Operation>
        + LogStore<Value = <Self as LogStore>::Value>;

    /// The provable state type (Merkleized,NonDurable).
    type Provable: MerkleizedNonDurableAny<Key = Self::Key>
        + MerkleizedStore<
            Value = <Self as LogStore>::Value,
            Digest = Self::Digest,
            Operation = Self::Operation,
        >;

    /// Commit any pending operations to the database, ensuring their durability. Returns the
    /// durable state and the location range of committed operations.
    fn commit(
        self,
        metadata: Option<<Self as LogStore>::Value>,
    ) -> impl Future<Output = Result<(Self::Durable, Range<Location>), Error>>;

    /// Convert this database into the provable (Merkleized, Non-durable) state.
    fn into_merkleized(self) -> impl Future<Output = Result<Self::Provable, Error>>;
}

/// Configuration for an `Any` authenticated db with fixed-size values.
#[derive(Clone)]
pub struct FixedConfig<T: Translator> {
    /// The name of the [Storage] partition used for the MMR's backing journal.
    pub mmr_journal_partition: String,

    /// The items per blob configuration value used by the MMR journal.
    pub mmr_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the MMR journal.
    pub mmr_write_buffer: NonZeroUsize,

    /// The name of the [Storage] partition used for the MMR's metadata.
    pub mmr_metadata_partition: String,

    /// The name of the [Storage] partition used to persist the (pruned) log of operations.
    pub log_journal_partition: String,

    /// The items per blob configuration value used by the log journal.
    pub log_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the log journal.
    pub log_write_buffer: NonZeroUsize,

    /// The translator used by the compressed index.
    pub translator: T,

    /// An optional thread pool to use for parallelizing batch operations.
    pub thread_pool: Option<ThreadPool>,

    /// The buffer pool to use for caching data.
    pub buffer_pool: PoolRef,
}

/// Configuration for an `Any` authenticated db with variable-sized values.
#[derive(Clone)]
pub struct VariableConfig<T: Translator, C> {
    /// The name of the [Storage] partition used for the MMR's backing journal.
    pub mmr_journal_partition: String,

    /// The items per blob configuration value used by the MMR journal.
    pub mmr_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the MMR journal.
    pub mmr_write_buffer: NonZeroUsize,

    /// The name of the [Storage] partition used for the MMR's metadata.
    pub mmr_metadata_partition: String,

    /// The name of the [Storage] partition used to persist the log of operations.
    pub log_partition: String,

    /// The size of the write buffer to use for each blob in the log journal.
    pub log_write_buffer: NonZeroUsize,

    /// Optional compression level (using `zstd`) to apply to log data before storing.
    pub log_compression: Option<u8>,

    /// The codec configuration to use for encoding and decoding log items.
    pub log_codec_config: C,

    /// The number of items to put in each blob of the journal.
    pub log_items_per_blob: NonZeroU64,

    /// The translator used by the compressed index.
    pub translator: T,

    /// An optional thread pool to use for parallelizing batch operations.
    pub thread_pool: Option<ThreadPool>,

    /// The buffer pool to use for caching data.
    pub buffer_pool: PoolRef,
}

type AuthenticatedLog<E, O, H, S = Clean<DigestOf<H>>> =
    authenticated::Journal<E, Journal<E, O>, H, S>;

/// Initialize the authenticated log from the given config, returning it along with the inactivity
/// floor specified by the last commit.
pub(crate) async fn init_fixed_authenticated_log<
    E: Storage + Clock + Metrics,
    O: Committable + CodecFixed<Cfg = ()>,
    H: Hasher,
    T: Translator,
>(
    context: E,
    cfg: FixedConfig<T>,
) -> Result<AuthenticatedLog<E, O, H>, Error> {
    let mmr_config = MmrConfig {
        journal_partition: cfg.mmr_journal_partition,
        metadata_partition: cfg.mmr_metadata_partition,
        items_per_blob: cfg.mmr_items_per_blob,
        write_buffer: cfg.mmr_write_buffer,
        thread_pool: cfg.thread_pool,
        buffer_pool: cfg.buffer_pool.clone(),
    };

    let journal_config = JConfig {
        partition: cfg.log_journal_partition,
        items_per_blob: cfg.log_items_per_blob,
        write_buffer: cfg.log_write_buffer,
        buffer_pool: cfg.buffer_pool,
    };

    let log = AuthenticatedLog::new(
        context.with_label("log"),
        mmr_config,
        journal_config,
        O::is_commit,
    )
    .await?;

    Ok(log)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        qmdb::any::{FixedConfig, VariableConfig},
        translator::TwoCap,
    };
    use commonware_utils::{NZUsize, NZU64};

    // Janky page & cache sizes to exercise boundary conditions.
    const PAGE_SIZE: usize = 101;
    const PAGE_CACHE_SIZE: usize = 11;

    pub(super) fn fixed_db_config(suffix: &str) -> FixedConfig<TwoCap> {
        FixedConfig {
            mmr_journal_partition: format!("journal_{suffix}"),
            mmr_metadata_partition: format!("metadata_{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_journal_partition: format!("log_journal_{suffix}"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }

    pub(super) fn variable_db_config(suffix: &str) -> VariableConfig<TwoCap, ()> {
        VariableConfig {
            mmr_journal_partition: format!("journal_{suffix}"),
            mmr_metadata_partition: format!("metadata_{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_partition: format!("log_journal_{suffix}"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            log_compression: None,
            log_codec_config: (),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }
}
