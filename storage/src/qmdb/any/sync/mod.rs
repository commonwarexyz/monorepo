//! Shared synchronization logic for [crate::qmdb::any] databases.
//! Contains implementation of [crate::qmdb::sync::Database] for all [Db] variants
//! (ordered/unordered, fixed/variable).

use crate::{
    index::Factory as IndexFactory,
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
async fn build_db<E, O, I, H, U, C, T>(
    context: E,
    mmr_config: journaled::Config,
    log: C,
    translator: T,
    pinned_nodes: Option<Vec<H::Digest>>,
    range: Range<Location>,
    apply_batch_size: usize,
) -> Result<Db<mmr::Family, E, C, I, H, U>, qmdb::Error<mmr::Family>>
where
    E: Context,
    O: Operation<mmr::Family> + Committable + CodecShared + Send + Sync + 'static,
    I: IndexFactory<T, Value = Location>,
    H: Hasher,
    U: Send + Sync + 'static,
    T: Translator,
    C: Mutable<Item = O>,
{
    let hasher = StandardHasher::<H>::new();

    let mmr = crate::mmr::journaled::Mmr::init_sync(
        context.child("mmr"),
        crate::mmr::journaled::SyncConfig {
            config: mmr_config,
            range: range.clone(),
            pinned_nodes,
        },
        &hasher,
    )
    .await?;

    let index = I::new(context.child("index"), translator);

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

macro_rules! impl_sync_database {
    ($db:ident, $op:ident, $update:ident,
     $journal:ty, $config:ty,
     $key_bound:path, $value_bound:ident
     $(; $($where_extra:tt)+)?) => {
        impl<E, K, V, H, T> qmdb::sync::Database for $db<mmr::Family, E, K, V, H, T>
        where
            E: Context,
            K: $key_bound,
            V: $value_bound + 'static,
            H: Hasher,
            T: Translator,
            $($($where_extra)+)?
        {
            type Context = E;
            type Op = $op<mmr::Family, K, V>;
            type Journal = $journal;
            type Hasher = H;
            type Config = $config;
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
                let translator = config.translator.clone();
                build_db::<_, Self::Op, _, H, $update<K, V>, _, T>(
                    context,
                    mmr_config,
                    log,
                    translator,
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
    };
}

impl_sync_database!(
    UnorderedFixedDb, UnorderedFixedOp, UnorderedFixedUpdate,
    fixed::Journal<E, Self::Op>, FixedConfig<T>,
    Array, FixedValue
);

impl_sync_database!(
    UnorderedVariableDb, UnorderedVariableOp, UnorderedVariableUpdate,
    variable::Journal<E, Self::Op>,
    VariableConfig<T, <UnorderedVariableOp<mmr::Family, K, V> as CodecRead>::Cfg>,
    Key, VariableValue;
    UnorderedVariableOp<mmr::Family, K, V>: CodecShared
);

impl_sync_database!(
    OrderedFixedDb, OrderedFixedOp, OrderedFixedUpdate,
    fixed::Journal<E, Self::Op>, FixedConfig<T>,
    Array, FixedValue
);

impl_sync_database!(
    OrderedVariableDb, OrderedVariableOp, OrderedVariableUpdate,
    variable::Journal<E, Self::Op>,
    VariableConfig<T, <OrderedVariableOp<mmr::Family, K, V> as CodecRead>::Cfg>,
    Key, VariableValue;
    OrderedVariableOp<mmr::Family, K, V>: CodecShared
);
