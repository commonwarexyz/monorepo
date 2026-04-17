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
use commonware_utils::{range::NonEmptyRange, Array};

#[cfg(test)]
pub(crate) mod tests;

/// Returns whether persisted local state already matches the requested sync target.
///
/// Shared across [crate::qmdb::any] and [crate::qmdb::current] sync because both
/// build on the same operations-MMR layout and share the same merkle partition.
///
/// # Caller contract
///
/// `target.range.start()` **must** equal the committed inactivity floor of the
/// target state (i.e. the floor carried by the last `CommitFloor` op). Only the
/// persisted tree size and root are checked; the merkle pruning boundary is not.
/// Callers that set `target.range.start()` below the committed floor (or that
/// prune their own database past the committed floor) can cause a later
/// [`qmdb::sync::Database::from_sync_result`] rebuild to fail with `MissingNode`
/// even though this function returned `true`.
pub async fn has_local_target_state<F, E, H>(
    context: E,
    merkle_config: journaled::Config,
    target: &qmdb::sync::Target<F, H::Digest>,
) -> bool
where
    F: merkle::Family,
    E: Context,
    H: Hasher,
{
    let hasher = StandardHasher::<H>::new();
    let peek = journaled::Journaled::<F, _, _>::peek_root(
        context.with_label("local_target_probe"),
        merkle_config,
        &hasher,
    )
    .await;
    // Size + root match implies the last CommitFloor op (and therefore the
    // committed inactivity floor) matches, per the caller contract above.
    matches!(
        peek,
        Ok(Some((_, journal_leaves, root)))
            if journal_leaves == target.range.end() && root == target.root
    )
}

/// Shared helper to build a [Db] from sync components.
async fn build_db<F, E, O, I, H, U, C, T>(
    context: E,
    merkle_config: journaled::Config,
    log: C,
    translator: T,
    pinned_nodes: Option<Vec<H::Digest>>,
    range: NonEmptyRange<Location<F>>,
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
    let db = Db::from_components(range.start(), log, index).await?;

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

            async fn has_local_target_state(
                context: Self::Context,
                config: &Self::Config,
                target: &qmdb::sync::Target<Self::Family, Self::Digest>,
            ) -> bool {
                qmdb::any::sync::has_local_target_state::<F, _, H>(
                    context,
                    config.merkle_config.clone(),
                    target,
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
