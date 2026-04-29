//! Shared synchronization logic for [crate::qmdb::any] databases.
//! Contains implementation of [crate::qmdb::sync::Database] for all [Db] variants
//! (ordered/unordered, fixed/variable).

use crate::{
    index::Factory as IndexFactory,
    journal::{
        authenticated,
        contiguous::{fixed, variable, Mutable},
    },
    merkle::{self, full, hasher::Standard as StandardHasher, Location, RootSpec},
    qmdb::{
        self,
        any::{
            db::Db,
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
use commonware_utils::{range::NonEmptyRange, Array};

#[cfg(test)]
pub(crate) mod tests;

/// Returns whether persisted local state already matches the requested sync target.
///
/// Shared helper for [crate::qmdb::any] sync implementations, which can reuse persisted
/// state by checking only the operations-tree size and root.
///
/// [crate::qmdb::current] performs an additional lower-bound check because its grafted-state
/// reconstruction depends on the persisted pruning point remaining at or below
/// `target.range.start()`.
pub async fn has_local_target_state<F, E, H>(
    context: E,
    merkle_config: full::Config,
    target: &qmdb::sync::Target<F, H::Digest>,
    spec: RootSpec,
) -> bool
where
    F: merkle::Family,
    E: Context,
    H: Hasher,
{
    let hasher = StandardHasher::<H>::new();
    let peek = full::Merkle::<F, _, _>::peek_root(
        context.with_label("local_target_probe"),
        merkle_config,
        &hasher,
        spec,
    )
    .await;
    // Size + root identify a unique state, so if they match the target's we can reuse
    // the persisted DB without fetching boundary pins.
    matches!(
        peek,
        Ok(Some((_, journal_leaves, root)))
            if journal_leaves == target.range.end() && root == target.root
    )
}

/// Shared helper to build a [Db] from sync components.
#[allow(clippy::too_many_arguments)]
async fn build_db<F, E, U, I, H, C, T>(
    context: E,
    merkle_config: full::Config,
    log: C,
    translator: T,
    pinned_nodes: Option<Vec<H::Digest>>,
    range: NonEmptyRange<Location<F>>,
    apply_batch_size: usize,
    split_root: bool,
    root_bagging: merkle::Bagging,
) -> Result<Db<F, E, C, I, H, U>, qmdb::Error<F>>
where
    F: merkle::Family,
    E: Context,
    U: Update + Send + Sync + 'static,
    I: IndexFactory<T, Value = Location<F>>,
    H: Hasher,
    T: Translator,
    C: Mutable<Item = Operation<F, U>> + Persistable<Error = crate::journal::Error>,
    Operation<F, U>: Codec + Committable + CodecShared,
{
    let hasher = StandardHasher::<H>::new();

    let merkle = full::Merkle::<F, _, _>::init_sync(
        context.with_label("merkle"),
        full::SyncConfig {
            config: merkle_config,
            range: range.clone(),
            pinned_nodes,
        },
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
    let db = Db::init_from_log(index, log, None, split_root, root_bagging).await?;

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
                range: NonEmptyRange<Location<F>>,
                apply_batch_size: usize,
            ) -> Result<Self, qmdb::Error<F>> {
                let merkle_config = config.merkle_config.clone();
                let translator = config.translator.clone();
                let split_root = config.split_root;
                let root_bagging = config.root_bagging;
                build_db::<F, _, $update<K, V>, _, H, _, T>(
                    context,
                    merkle_config,
                    log,
                    translator,
                    pinned_nodes,
                    range,
                    apply_batch_size,
                    split_root,
                    root_bagging,
                )
                .await
            }

            async fn has_local_target_state(
                context: Self::Context,
                config: &Self::Config,
                target: &qmdb::sync::Target<Self::Family, Self::Digest>,
            ) -> bool {
                let inactive_peaks = F::inactive_peaks(
                    F::location_to_position(target.range.end()),
                    target.range.start(),
                );
                qmdb::any::sync::has_local_target_state::<F, _, H>(
                    context,
                    config.merkle_config.clone(),
                    target,
                    RootSpec::from_split_policy(
                        config.split_root,
                        config.root_bagging,
                        inactive_peaks,
                    ),
                )
                .await
            }

            fn root(&self) -> Self::Digest {
                crate::qmdb::any::db::Db::root(self)
            }

            fn proof_spec(
                config: &Self::Config,
                proof: &crate::merkle::Proof<Self::Family, Self::Digest>,
            ) -> RootSpec {
                RootSpec::from_split_policy(
                    config.split_root,
                    config.root_bagging,
                    proof.inactive_peaks,
                )
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
