//! Shared synchronization logic for [crate::qmdb::any] databases.
//! Contains implementation of `qmdb::sync::Database` for all [Db] variants
//! (ordered/unordered, fixed/variable).
//!
//! Callers verifying `any` sync proofs directly should use `qmdb::hasher`.

use crate::{
    index::Factory as IndexFactory,
    journal::{
        authenticated,
        contiguous::{fixed, variable, Mutable, Reader as _},
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
use commonware_codec::{
    Codec, CodecShared, EncodeSize, Error as CodecError, Read, Read as CodecRead, ReadExt as _,
    Write,
};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_runtime::{Buf, BufMut};
use commonware_utils::{range::NonEmptyRange, Array};

#[cfg(test)]
pub(crate) mod tests;

/// Sync target for `any` databases.
#[derive(Debug)]
pub struct Target<F: merkle::Family, D: Digest> {
    /// The database root expected after sync completes.
    pub root: D,
    /// Range of operations to sync.
    pub range: NonEmptyRange<Location<F>>,
}

impl<F: merkle::Family, D: Digest> Target<F, D> {
    /// Create a target from a root and operation range.
    pub const fn new(root: D, range: NonEmptyRange<Location<F>>) -> Self {
        Self { root, range }
    }
}

impl<F: merkle::Family, D: Digest> Clone for Target<F, D> {
    fn clone(&self) -> Self {
        Self {
            root: self.root,
            range: self.range.clone(),
        }
    }
}

impl<F: merkle::Family, D: Digest> PartialEq for Target<F, D> {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root && self.range == other.range
    }
}

impl<F: merkle::Family, D: Digest> Eq for Target<F, D> {}

impl<F: merkle::Family, D: Digest> qmdb::sync::Target for Target<F, D> {
    type Family = F;
    type Digest = D;

    fn root(&self) -> Self::Digest {
        self.root
    }

    fn ops_root(&self) -> Self::Digest {
        self.root
    }

    fn range(&self) -> &NonEmptyRange<Location<Self::Family>> {
        &self.range
    }
}

impl<F: merkle::Family, D: Digest> Write for Target<F, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.root.write(buf);
        self.range.write(buf);
    }
}

impl<F: merkle::Family, D: Digest> EncodeSize for Target<F, D> {
    fn encode_size(&self) -> usize {
        self.root.encode_size() + self.range.encode_size()
    }
}

impl<F: merkle::Family, D: Digest> Read for Target<F, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let root = D::read(buf)?;
        let range = NonEmptyRange::<Location<F>>::read(buf)?;
        if !range.start().is_valid() || !range.end().is_valid() {
            return Err(CodecError::Invalid(
                "storage::qmdb::any::sync::Target",
                "range bounds out of valid range",
            ));
        }
        Ok(Self { root, range })
    }
}

#[cfg(feature = "arbitrary")]
impl<F: merkle::Family, D: Digest> arbitrary::Arbitrary<'_> for Target<F, D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let root = u.arbitrary()?;
        let max_loc = F::MAX_LEAVES;
        let lower = u.int_in_range(0..=*max_loc - 1)?;
        let upper = u.int_in_range(lower + 1..=*max_loc)?;
        Ok(Self {
            root,
            range: commonware_utils::non_empty_range!(Location::new(lower), Location::new(upper)),
        })
    }
}

#[cfg(test)]
mod target_tests {
    use super::*;
    use crate::merkle::mmr;
    use commonware_codec::Error as CodecError;
    use commonware_cryptography::sha256;
    use commonware_utils::non_empty_range;
    use std::io::Cursor;

    #[test]
    fn test_sync_target_serialization() {
        let target = Target::<mmr::Family, sha256::Digest>::new(
            sha256::Digest::from([42; 32]),
            non_empty_range!(Location::new(100), Location::new(500)),
        );

        let mut buffer = Vec::new();
        target.write(&mut buffer);

        assert_eq!(buffer.len(), target.encode_size());

        let mut cursor = Cursor::new(buffer);
        let deserialized = Target::read(&mut cursor).unwrap();

        assert_eq!(target, deserialized);
        assert_eq!(target.root, deserialized.root);
        assert_eq!(target.range, deserialized.range);
    }

    #[test]
    fn test_sync_target_read_invalid_bounds() {
        let mut buffer = Vec::new();
        sha256::Digest::from([42; 32]).write(&mut buffer);
        Location::<mmr::Family>::new(100).write(&mut buffer);
        Location::<mmr::Family>::new(50).write(&mut buffer);

        let mut cursor = Cursor::new(buffer);
        assert!(matches!(
            Target::<mmr::Family, sha256::Digest>::read(&mut cursor),
            Err(CodecError::Invalid("Range", "start must be <= end"))
        ));

        let mut buffer = Vec::new();
        sha256::Digest::from([42; 32]).write(&mut buffer);
        (Location::<mmr::Family>::new(100)..Location::<mmr::Family>::new(100)).write(&mut buffer);

        let mut cursor = Cursor::new(buffer);
        assert!(matches!(
            Target::<mmr::Family, sha256::Digest>::read(&mut cursor),
            Err(CodecError::Invalid("NonEmptyRange", "start must be < end"))
        ));
    }
}

#[cfg(all(test, feature = "arbitrary"))]
mod conformance {
    use super::*;
    use crate::merkle::mmr;
    use commonware_codec::conformance::CodecConformance;
    use commonware_cryptography::sha256;

    commonware_conformance::conformance_tests! {
        CodecConformance<Target<mmr::Family, sha256::Digest>>,
    }
}

/// Returns whether persisted local state already matches the requested sync target by confirming
/// that the derived `ops_root` matches the one from the target.
pub(crate) async fn has_local_target_state<F, E, H, S, T>(
    context: E,
    merkle_config: full::Config<S>,
    target: &T,
    inactive_peaks: usize,
) -> bool
where
    F: merkle::Family,
    E: Context,
    H: Hasher,
    S: Strategy,
    T: qmdb::sync::Target<Family = F, Digest = H::Digest>,
{
    let hasher = qmdb::hasher::<H>();
    let peek = full::Merkle::<F, _, _, S>::peek_root(
        context.child("local_target_probe"),
        merkle_config,
        &hasher,
        inactive_peaks,
    )
    .await;
    // Size + root identify a unique state, so if they match the target's we can reuse
    // the persisted DB without fetching boundary pins.
    matches!(
        peek,
        Ok(Some((_, journal_leaves, ops_root)))
            if journal_leaves == target.range().end() && ops_root == target.ops_root()
    )
}

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

            async fn has_local_target_state<Target>(
                context: Self::Context,
                config: &Self::Config,
                target: &Target,
            ) -> bool
            where
                Target: qmdb::sync::Target<Family = Self::Family, Digest = Self::Digest>,
            {
                let Ok(journal) = <$journal>::init(
                    context.child("local_target_journal_probe"),
                    config.journal_config.clone(),
                )
                .await
                else {
                    return false;
                };
                if Location::new(journal.reader().await.bounds().start) > target.range().start() {
                    return false;
                }

                let inactive_peaks = F::inactive_peaks(
                    F::location_to_position(target.range().end()),
                    target.range().start(),
                );
                qmdb::any::sync::has_local_target_state::<F, _, H, S, _>(
                    context.child("local_target_merkle_probe"),
                    config.merkle_config.clone(),
                    target,
                    inactive_peaks,
                )
                .await
            }

            fn ops_root(&self) -> Self::Digest {
                crate::qmdb::any::db::Db::root(self)
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
