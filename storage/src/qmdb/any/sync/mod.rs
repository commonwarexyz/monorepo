//! Shared synchronization logic for [crate::qmdb::any] databases.
//! Contains implementation of [crate::qmdb::sync::Database] for all [Db] variants
//! (ordered/unordered, fixed/variable).

use crate::{
    index::{ordered, unordered},
    journal::{
        authenticated,
        contiguous::{fixed, variable, Mutable},
    },
    merkle::mmr::{self, journaled, Location, StandardHasher},
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
        operation::{Committable, Key, Operation},
    },
    translator::Translator,
    Context,
};
use commonware_codec::{CodecShared, Read as CodecRead};
use commonware_cryptography::Hasher;
use commonware_utils::Array;
use std::ops::Range;

#[cfg(test)]
pub(crate) mod tests;

/// Shared helper to build a [Db] from sync components.
async fn build_db<E, O, I, H, U, C>(
    context: E,
    mmr_config: journaled::Config,
    log: C,
    index: I,
    pinned_nodes: Option<Vec<H::Digest>>,
    range: Range<Location>,
    apply_batch_size: usize,
) -> Result<Db<mmr::Family, E, C, I, H, U>, qmdb::Error<mmr::Family>>
where
    E: Context,
    O: Operation<mmr::Family> + Committable + CodecShared + Send + Sync + 'static,
    I: crate::index::Unordered<Value = Location>,
    H: Hasher,
    U: Send + Sync + 'static,
    C: Mutable<Item = O>,
{
    let hasher = StandardHasher::<H>::new();

    let mmr = crate::mmr::journaled::Mmr::init_sync(
        context.with_label("mmr"),
        crate::mmr::journaled::SyncConfig {
            config: mmr_config,
            range: range.clone(),
            pinned_nodes,
        },
        &hasher,
    )
    .await?;

    let log = authenticated::Journal::<mmr::Family, _, _, _>::from_components(
        mmr,
        log,
        hasher,
        apply_batch_size as u64,
    )
    .await?;
    let db = Db::from_components(range.start, log, index).await?;

    Ok(db)
}

impl<E, K, V, H, T> qmdb::sync::Database for UnorderedFixedDb<mmr::Family, E, K, V, H, T>
where
    E: Context,
    K: Array,
    V: FixedValue + 'static,
    H: Hasher,
    T: Translator,
{
    type Context = E;
    type Op = UnorderedFixedOp<mmr::Family, K, V>;
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
    ) -> Result<Self, qmdb::Error<mmr::Family>> {
        let mmr_config = config.merkle_config.clone();
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

impl<E, K, V, H, T> qmdb::sync::Database for UnorderedVariableDb<mmr::Family, E, K, V, H, T>
where
    E: Context,
    K: Key,
    V: VariableValue + 'static,
    H: Hasher,
    T: Translator,
    UnorderedVariableOp<mmr::Family, K, V>: CodecShared,
{
    type Context = E;
    type Op = UnorderedVariableOp<mmr::Family, K, V>;
    type Journal = variable::Journal<E, Self::Op>;
    type Hasher = H;
    type Config = VariableConfig<T, <UnorderedVariableOp<mmr::Family, K, V> as CodecRead>::Cfg>;
    type Digest = H::Digest;

    async fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        log: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        range: Range<Location>,
        apply_batch_size: usize,
    ) -> Result<Self, qmdb::Error<mmr::Family>> {
        let mmr_config = config.merkle_config.clone();
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

impl<E, K, V, H, T> qmdb::sync::Database for OrderedFixedDb<mmr::Family, E, K, V, H, T>
where
    E: Context,
    K: Array,
    V: FixedValue + 'static,
    H: Hasher,
    T: Translator,
{
    type Context = E;
    type Op = OrderedFixedOp<mmr::Family, K, V>;
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
    ) -> Result<Self, qmdb::Error<mmr::Family>> {
        let mmr_config = config.merkle_config.clone();
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

impl<E, K, V, H, T> qmdb::sync::Database for OrderedVariableDb<mmr::Family, E, K, V, H, T>
where
    E: Context,
    K: Key,
    V: VariableValue + 'static,
    H: Hasher,
    T: Translator,
    OrderedVariableOp<mmr::Family, K, V>: CodecShared,
{
    type Context = E;
    type Op = OrderedVariableOp<mmr::Family, K, V>;
    type Journal = variable::Journal<E, Self::Op>;
    type Hasher = H;
    type Config = VariableConfig<T, <OrderedVariableOp<mmr::Family, K, V> as CodecRead>::Cfg>;
    type Digest = H::Digest;

    async fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        log: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        range: Range<Location>,
        apply_batch_size: usize,
    ) -> Result<Self, qmdb::Error<mmr::Family>> {
        let mmr_config = config.merkle_config.clone();
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
