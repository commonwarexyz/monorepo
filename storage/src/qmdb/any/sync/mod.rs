//! Shared synchronization logic for [crate::qmdb::any] databases.
//! Contains implementation of [crate::qmdb::sync::Database] for all [Db] variants
//! (ordered/unordered, fixed/variable).
//!
//! Callers verifying `any` sync proofs directly should use `qmdb::hasher`.

use crate::{
    index::Factory as IndexFactory,
    journal::{
        authenticated,
        contiguous::{fixed, variable, Contiguous, Mutable, Reader as _},
    },
    merkle::{self, full, Location},
    qmdb::{
        self,
        any::{
            db::{Db, Metrics},
            operation::{update::Update, Operation},
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
        operation::{Committable, Key},
    },
    translator::Translator,
    Context, Persistable,
};
use commonware_codec::{Codec, CodecShared, Read as CodecRead};
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_utils::{range::NonEmptyRange, Array};

#[cfg(test)]
pub(crate) mod tests;

/// Shared helper to build a [Db] from sync components.
#[allow(clippy::too_many_arguments)]
async fn build_db<F, E, U, I, H, C, T, S>(
    context: E,
    merkle_config: full::Config<S>,
    log: C,
    translator: T,
    pinned_nodes: Option<Vec<H::Digest>>,
    range: NonEmptyRange<Location<F>>,
    apply_batch_size: usize,
) -> Result<Db<F, E, C, I, H, U, { crate::qmdb::any::BITMAP_CHUNK_BYTES }, S>, qmdb::Error<F>>
where
    F: merkle::Family,
    E: Context,
    U: Update + Send + Sync + 'static,
    I: IndexFactory<T, Value = Location<F>>,
    H: Hasher,
    T: Translator,
    C: Mutable<Item = Operation<F, U>> + Persistable<Error = crate::journal::Error>,
    S: Strategy,
    Operation<F, U>: Codec + Committable + CodecShared,
{
    let hasher = qmdb::hasher::<H>();

    let merkle = full::Merkle::<F, _, _, S>::init_sync(
        context.child("merkle"),
        full::SyncConfig {
            config: merkle_config,
            range: range.clone(),
            pinned_nodes,
        },
    )
    .await?;

    let index = I::new(context.child("index"), translator);

    let log = authenticated::Journal::<F, _, _, _, S>::from_components(
        merkle,
        log,
        hasher,
        apply_batch_size as u64,
    )
    .await?;
    let metrics = Metrics::new(context);
    let db = Db::init_from_log(index, log, None, metrics).await?;

    Ok(db)
}

macro_rules! impl_sync_database {
    ($db:ident, $op:ident, $update:ident,
     $journal:ty, $config:ty,
     $key_bound:path, $value_bound:ident
     $(; $($where_extra:tt)+)?) => {
        impl<F, E, K, V, H, T, S> qmdb::sync::Database for $db<F, E, K, V, H, T, S>
        where
            F: merkle::Family,
            E: Context,
            K: $key_bound,
            V: $value_bound + 'static,
            H: Hasher,
            T: Translator,
            S: Strategy,
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
                range: NonEmptyRange<Location<F>>,
                apply_batch_size: usize,
            ) -> Result<Self, qmdb::Error<F>> {
                let merkle_config = config.merkle_config.clone();
                let translator = config.translator.clone();
                build_db::<F, _, $update<K, V>, _, H, _, T, S>(
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

            async fn local_boundary_nodes(
                context: Self::Context,
                config: &Self::Config,
                target: &qmdb::sync::Target<Self::Family, Self::Digest>,
                journal: &Self::Journal,
            ) -> Result<Option<Vec<Self::Digest>>, qmdb::Error<F>> {
                if target.range.start() == Location::new(0) {
                    return Ok(None);
                }

                let reader = Contiguous::reader(journal).await;
                let bounds = reader.bounds();
                if Location::new(bounds.start) > target.range.start()
                    || Location::new(bounds.end) != target.range.end()
                {
                    return Ok(None);
                }
                drop(reader);

                let hasher = qmdb::hasher::<H>();
                let merkle = full::Merkle::<F, _, _, S>::init(
                    context.child("local_boundary_merkle"),
                    &hasher,
                    config.merkle_config.clone(),
                )
                .await?;
                let bounds = merkle.bounds();
                if bounds.start > target.range.start() || bounds.end != target.range.end() {
                    return Ok(None);
                }

                let inactive_peaks = F::inactive_peaks(
                    F::location_to_position(target.range.end()),
                    target.range.start(),
                );
                if merkle.root(&hasher, inactive_peaks)? != target.root {
                    return Ok(None);
                }

                merkle
                    .pinned_nodes_at(target.range.start())
                    .await
                    .map(Some)
                    .map_err(Into::into)
            }

            fn root(&self) -> Self::Digest {
                crate::qmdb::any::db::Db::root(self)
            }
        }
    };
}

impl_sync_database!(
    UnorderedFixedDb, UnorderedFixedOp, UnorderedFixedUpdate,
    fixed::Journal<E, Self::Op>, FixedConfig<T, S>,
    Array, FixedValue
);

impl_sync_database!(
    UnorderedVariableDb, UnorderedVariableOp, UnorderedVariableUpdate,
    variable::Journal<E, Self::Op>,
    VariableConfig<T, <UnorderedVariableOp<F, K, V> as CodecRead>::Cfg, S>,
    Key, VariableValue;
    UnorderedVariableOp<F, K, V>: CodecShared
);

impl_sync_database!(
    OrderedFixedDb, OrderedFixedOp, OrderedFixedUpdate,
    fixed::Journal<E, Self::Op>, FixedConfig<T, S>,
    Array, FixedValue
);

impl_sync_database!(
    OrderedVariableDb, OrderedVariableOp, OrderedVariableUpdate,
    variable::Journal<E, Self::Op>,
    VariableConfig<T, <OrderedVariableOp<F, K, V> as CodecRead>::Cfg, S>,
    Key, VariableValue;
    OrderedVariableOp<F, K, V>: CodecShared
);
