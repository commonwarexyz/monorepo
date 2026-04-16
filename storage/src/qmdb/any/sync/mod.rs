//! Shared synchronization logic for [crate::qmdb::any] databases.
//! Contains implementation of [crate::qmdb::sync::Database] for all [Db] variants
//! (ordered/unordered, fixed/variable).

use crate::{
    index::Factory as IndexFactory,
    journal::{
        authenticated,
        contiguous::{fixed, variable, Mutable},
    },
    merkle::{self, hasher::Standard as StandardHasher, journaled, Location},
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
async fn build_db<F, E, O, I, H, U, C, T>(
    context: E,
    merkle_config: journaled::Config,
    log: C,
    translator: T,
    pinned_nodes: Option<Vec<H::Digest>>,
    range: Range<Location<F>>,
    apply_batch_size: usize,
) -> Result<Db<F, E, C, I, H, U>, qmdb::Error<F>>
where
    F: merkle::Family,
    E: Context,
    O: Operation<F> + Committable + CodecShared + Send + Sync + 'static,
    I: IndexFactory<T, Value = Location<F>>,
    H: Hasher,
    U: Send + Sync + 'static,
    T: Translator,
    C: Mutable<Item = O>,
{
    let hasher = StandardHasher::<H>::new();

    let merkle = journaled::Journaled::<F, _, _>::init_sync(
        context.with_label("merkle"),
        journaled::SyncConfig {
            config: merkle_config,
            range: range.clone(),
            pinned_nodes,
        },
        &hasher,
    )
    .await?;

    let index = I::new(context.with_label("index"), translator);

    let log = authenticated::Journal::<F, _, _, _>::from_components(
        merkle,
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
        impl<F, E, K, V, H, T> qmdb::sync::Database for $db<F, E, K, V, H, T>
        where
            F: merkle::Family,
            E: Context,
            K: $key_bound,
            V: $value_bound + 'static,
            H: Hasher,
            T: Translator,
            $($($where_extra)+)?
        {
            type Family = F;
            type Context = E;
            type Op = $op<F, K, V>;
            type Journal = $journal;
            type Hasher = H;
            type Config = $config;
            type Digest = H::Digest;

            async fn from_sync_result(
                context: Self::Context,
                config: Self::Config,
                log: Self::Journal,
                pinned_nodes: Option<Vec<Self::Digest>>,
                // `any` does not distinguish between ops and canonical roots and does not
                // use overlay state; ignore both fields entirely.
                _overlay_state: Option<
                    crate::qmdb::current::sync::CurrentOverlayState<Self::Digest>,
                >,
                _canonical_root: Option<Self::Digest>,
                range: Range<Location<F>>,
                apply_batch_size: usize,
            ) -> Result<Self, qmdb::Error<F>> {
                let merkle_config = config.merkle_config.clone();
                let translator = config.translator.clone();
                build_db::<F, _, Self::Op, _, H, $update<K, V>, _, T>(
                    context,
                    merkle_config,
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
    VariableConfig<T, <UnorderedVariableOp<F, K, V> as CodecRead>::Cfg>,
    Key, VariableValue;
    UnorderedVariableOp<F, K, V>: CodecShared
);

impl_sync_database!(
    OrderedFixedDb, OrderedFixedOp, OrderedFixedUpdate,
    fixed::Journal<E, Self::Op>, FixedConfig<T>,
    Array, FixedValue
);

impl_sync_database!(
    OrderedVariableDb, OrderedVariableOp, OrderedVariableUpdate,
    variable::Journal<E, Self::Op>,
    VariableConfig<T, <OrderedVariableOp<F, K, V> as CodecRead>::Cfg>,
    Key, VariableValue;
    OrderedVariableOp<F, K, V>: CodecShared
);
