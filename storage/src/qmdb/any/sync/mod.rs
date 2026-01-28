//! Shared synchronization logic for [crate::qmdb::any] databases.
//! Contains implementation of [crate::qmdb::sync::Database] for all [Db] variants
//! (ordered/unordered, fixed/variable).

use crate::{
    index::{ordered, unordered},
    journal::{
        authenticated,
        contiguous::{fixed, variable, MutableContiguous},
    },
    mmr::{journaled::Config as MmrConfig, mem::Clean, Location, Position, StandardHasher},
    qmdb::{
        self,
        any::{
            db::Db,
            ordered::{
                fixed::{
                    Db as OrderedFixedDb, Operation as OrderedFixedOp, Update as OrderedFixedUpdate,
                },
                variable::{
                    Db as OrderedVariableDb, Operation as OrderedVariableOp,
                    Update as OrderedVariableUpdate,
                },
            },
            unordered::{
                fixed::{
                    Db as UnorderedFixedDb, Operation as UnorderedFixedOp,
                    Update as UnorderedFixedUpdate,
                },
                variable::{
                    Db as UnorderedVariableDb, Operation as UnorderedVariableOp,
                    Update as UnorderedVariableUpdate,
                },
            },
            FixedConfig, FixedValue, VariableConfig, VariableValue,
        },
        operation::{Committable, Operation},
        Durable, Merkleized,
    },
    translator::Translator,
};
use commonware_codec::CodecShared;
use commonware_cryptography::{DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use std::ops::Range;

#[cfg(test)]
pub(crate) mod tests;

/// Shared helper to build a [Db] from sync components.
async fn build_db<E, O, I, H, U, C>(
    context: E,
    mmr_config: MmrConfig,
    log: C,
    index: I,
    pinned_nodes: Option<Vec<H::Digest>>,
    range: Range<Location>,
    apply_batch_size: usize,
) -> Result<Db<E, C, I, H, U, Merkleized<H>, Durable>, qmdb::Error>
where
    E: Storage + Clock + Metrics,
    O: Operation + Committable + CodecShared + Send + Sync + 'static,
    I: crate::index::Unordered<Value = Location>,
    H: Hasher,
    U: Send + Sync + 'static,
    C: MutableContiguous<Item = O>,
{
    let mut hasher = StandardHasher::<H>::new();

    let mmr = crate::mmr::journaled::Mmr::init_sync(
        context.with_label("mmr"),
        crate::mmr::journaled::SyncConfig {
            config: mmr_config,
            range: Position::try_from(range.start)?..Position::try_from(range.end + 1)?,
            pinned_nodes,
        },
        &mut hasher,
    )
    .await?;

    let log = authenticated::Journal::<_, _, _, Clean<DigestOf<H>>>::from_components(
        mmr,
        log,
        hasher,
        apply_batch_size as u64,
    )
    .await?;
    let db = Db::from_components(range.start, log, index).await?;

    Ok(db)
}

/// Extract MMR config from FixedConfig
fn mmr_config_from_fixed<T: Translator>(config: &FixedConfig<T>) -> MmrConfig {
    MmrConfig {
        journal_partition: config.mmr_journal_partition.clone(),
        metadata_partition: config.mmr_metadata_partition.clone(),
        items_per_blob: config.mmr_items_per_blob,
        write_buffer: config.mmr_write_buffer,
        thread_pool: config.thread_pool.clone(),
        buffer_pool: config.buffer_pool.clone(),
    }
}

/// Extract MMR config from VariableConfig
fn mmr_config_from_variable<T: Translator, C>(config: &VariableConfig<T, C>) -> MmrConfig {
    MmrConfig {
        journal_partition: config.mmr_journal_partition.clone(),
        metadata_partition: config.mmr_metadata_partition.clone(),
        items_per_blob: config.mmr_items_per_blob,
        write_buffer: config.mmr_write_buffer,
        thread_pool: config.thread_pool.clone(),
        buffer_pool: config.buffer_pool.clone(),
    }
}

impl<E, K, V, H, T> qmdb::sync::Database for UnorderedFixedDb<E, K, V, H, T, Merkleized<H>, Durable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: FixedValue + 'static,
    H: Hasher,
    T: Translator,
{
    type Context = E;
    type Op = UnorderedFixedOp<K, V>;
    type Journal = fixed::Journal<E, Self::Op>;
    type Hasher = H;
    type Config = FixedConfig<T>;
    type Digest = H::Digest;

    async fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        log: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        range: Range<Location>,
        apply_batch_size: usize,
    ) -> Result<Self, qmdb::Error> {
        let mmr_config = mmr_config_from_fixed(&config);
        let index = unordered::Index::new(context.with_label("index"), config.translator.clone());
        build_db::<_, Self::Op, _, H, UnorderedFixedUpdate<K, V>, _>(
            context,
            mmr_config,
            log,
            index,
            pinned_nodes,
            range,
            apply_batch_size,
        )
        .await
    }

    fn root(&self) -> Self::Digest {
        self.log.root()
    }
}

impl<E, K, V, H, T> qmdb::sync::Database
    for UnorderedVariableDb<E, K, V, H, T, Merkleized<H>, Durable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue + 'static,
    H: Hasher,
    T: Translator,
{
    type Context = E;
    type Op = UnorderedVariableOp<K, V>;
    type Journal = variable::Journal<E, Self::Op>;
    type Hasher = H;
    type Config = VariableConfig<T, V::Cfg>;
    type Digest = H::Digest;

    async fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        log: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        range: Range<Location>,
        apply_batch_size: usize,
    ) -> Result<Self, qmdb::Error> {
        let mmr_config = mmr_config_from_variable(&config);
        let index = unordered::Index::new(context.with_label("index"), config.translator.clone());
        build_db::<_, Self::Op, _, H, UnorderedVariableUpdate<K, V>, _>(
            context,
            mmr_config,
            log,
            index,
            pinned_nodes,
            range,
            apply_batch_size,
        )
        .await
    }

    fn root(&self) -> Self::Digest {
        self.log.root()
    }
}

impl<E, K, V, H, T> qmdb::sync::Database for OrderedFixedDb<E, K, V, H, T, Merkleized<H>, Durable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: FixedValue + 'static,
    H: Hasher,
    T: Translator,
{
    type Context = E;
    type Op = OrderedFixedOp<K, V>;
    type Journal = fixed::Journal<E, Self::Op>;
    type Hasher = H;
    type Config = FixedConfig<T>;
    type Digest = H::Digest;

    async fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        log: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        range: Range<Location>,
        apply_batch_size: usize,
    ) -> Result<Self, qmdb::Error> {
        let mmr_config = mmr_config_from_fixed(&config);
        let index = ordered::Index::new(context.with_label("index"), config.translator.clone());
        build_db::<_, Self::Op, _, H, OrderedFixedUpdate<K, V>, _>(
            context,
            mmr_config,
            log,
            index,
            pinned_nodes,
            range,
            apply_batch_size,
        )
        .await
    }

    fn root(&self) -> Self::Digest {
        self.log.root()
    }
}

impl<E, K, V, H, T> qmdb::sync::Database
    for OrderedVariableDb<E, K, V, H, T, Merkleized<H>, Durable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: VariableValue + 'static,
    H: Hasher,
    T: Translator,
{
    type Context = E;
    type Op = OrderedVariableOp<K, V>;
    type Journal = variable::Journal<E, Self::Op>;
    type Hasher = H;
    type Config = VariableConfig<T, V::Cfg>;
    type Digest = H::Digest;

    async fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        log: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        range: Range<Location>,
        apply_batch_size: usize,
    ) -> Result<Self, qmdb::Error> {
        let mmr_config = mmr_config_from_variable(&config);
        let index = ordered::Index::new(context.with_label("index"), config.translator.clone());
        build_db::<_, Self::Op, _, H, OrderedVariableUpdate<K, V>, _>(
            context,
            mmr_config,
            log,
            index,
            pinned_nodes,
            range,
            apply_batch_size,
        )
        .await
    }

    fn root(&self) -> Self::Digest {
        self.log.root()
    }
}
