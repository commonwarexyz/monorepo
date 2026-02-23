//! An authenticated database that provides succinct proofs of _any_ value ever associated with a
//! key, where both keys and values can have varying sizes.
//!
//! Unlike other QMDB variants that require fixed-size keys (`K: Array`), this variant accepts any
//! key type implementing the [`Key`] trait (such as `Vec<u8>`), supporting arbitrary-length byte
//! sequences as keys.
//!
//! _If your keys are all the same fixed size, use [super::fixed] or [super::variable] instead for
//! better performance. If your values are fixed-size, use [super::varkey_fixed] instead._

use crate::{
    index::unordered::Index,
    journal::contiguous::variable::Journal,
    mmr::Location,
    qmdb::{
        any::{
            encoding::{VariableBoth, VariableVal},
            init_variable, unordered,
        },
        operation::Key,
        Durable, Error, Merkleized,
    },
    translator::Translator,
};
use commonware_codec::{Codec, Read};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};

pub type Update<K, V> = unordered::Update<VariableBoth<K, V>>;
pub type Operation<K, V> = unordered::Operation<VariableBoth<K, V>>;

/// A key-value QMDB with variable-length keys and variable-length values.
pub type Db<E, K, V, H, T, S = Merkleized<H>, D = Durable> =
    super::Db<E, Journal<E, Operation<K, V>>, Index<T, Location>, H, Update<K, V>, S, D>;

impl<E, K, V, H, T> Db<E, K, V, H, T, Merkleized<H>, Durable>
where
    E: Storage + Clock + Metrics,
    K: Key + Codec,
    V: VariableVal,
    H: Hasher,
    T: Translator,
    Operation<K, V>: Codec,
{
    /// Returns a [Db] QMDB initialized from `cfg`. Uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(
        context: E,
        cfg: crate::qmdb::any::VariableConfig<T, <Operation<K, V> as Read>::Cfg>,
    ) -> Result<Self, Error> {
        init_variable(context, cfg, None, |_, _| {}, |ctx, t| Index::new(ctx, t)).await
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{qmdb::any::VariableConfig, translator::TwoCap};
    use commonware_codec::RangeCfg;
    use commonware_cryptography::Sha256;
    use commonware_macros::test_traced;
    use commonware_runtime::{
        buffer::paged::CacheRef,
        deterministic::{self, Context},
        BufferPooler, Runner as _,
    };
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use std::num::{NonZeroU16, NonZeroUsize};

    const PAGE_SIZE: NonZeroU16 = NZU16!(77);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(9);

    type VariableKeyDb = Db<deterministic::Context, Vec<u8>, Vec<u8>, Sha256, TwoCap>;

    type VariableKeyCfg = VariableConfig<TwoCap, ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>;

    fn create_config(suffix: &str, pooler: &impl BufferPooler) -> VariableKeyCfg {
        VariableConfig {
            mmr_journal_partition: format!("vk-journal-{suffix}"),
            mmr_metadata_partition: format!("vk-metadata-{suffix}"),
            mmr_items_per_blob: NZU64!(13),
            mmr_write_buffer: NZUsize!(1024),
            log_partition: format!("vk-log-{suffix}"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            log_compression: None,
            log_codec_config: (
                (RangeCfg::from(0..=10000), ()),
                (RangeCfg::from(0..=10000), ()),
            ),
            translator: TwoCap,
            thread_pool: None,
            page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    async fn open_db(context: Context) -> VariableKeyDb {
        let cfg = create_config("partition", &context);
        VariableKeyDb::init(context, cfg).await.unwrap()
    }

    /// Test with actual variable-length Vec<u8> keys of varying sizes. This is the unique
    /// capability of the varkey variants that the generic (Digest-keyed) tests don't cover.
    #[test_traced("INFO")]
    fn test_varkey_variable_db_variable_length_keys() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.with_label("db")).await.into_mutable();

            let keys: Vec<Vec<u8>> =
                vec![vec![], vec![1], vec![1, 2], vec![0; 100], vec![0xFF; 1000]];

            for (i, key) in keys.iter().enumerate() {
                let value = format!("value_{i}").into_bytes();
                db.write_batch([(key.clone(), Some(value))]).await.unwrap();
            }

            for (i, key) in keys.iter().enumerate() {
                let expected = format!("value_{i}").into_bytes();
                assert_eq!(db.get(key).await.unwrap().unwrap(), expected);
            }

            let (db, _) = db.commit(None).await.unwrap();
            let root = db.into_merkleized().root();
            let db = open_db(context.with_label("db_reopen")).await;
            assert_eq!(db.root(), root);

            for (i, key) in keys.iter().enumerate() {
                let expected = format!("value_{i}").into_bytes();
                assert_eq!(db.get(key).await.unwrap().unwrap(), expected);
            }

            db.destroy().await.unwrap();
        });
    }

    // ---------------------------------------------------------------------------------
    // Generic test helpers (using Digest keys to match TestableAnyDb<Digest> interface)
    // ---------------------------------------------------------------------------------

    use crate::qmdb::any::{
        test::varkey_db_config,
        unordered::test::{
            test_any_db_basic, test_any_db_build_and_authenticate, test_any_db_empty,
        },
    };
    use commonware_cryptography::sha256::Digest;

    type DigestVariableKeyDb = Db<deterministic::Context, Digest, Digest, Sha256, TwoCap>;

    async fn open_digest_db(context: Context) -> DigestVariableKeyDb {
        let cfg = varkey_db_config::<TwoCap>("partition", &context);
        DigestVariableKeyDb::init(context, cfg).await.unwrap()
    }

    #[inline]
    fn to_digest(i: u64) -> Digest {
        Sha256::hash(&i.to_be_bytes())
    }

    #[test_traced("INFO")]
    fn test_varkey_variable_generic_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_digest_db(context.with_label("db_0")).await;
            let ctx = context.clone();
            test_any_db_empty(db, move |idx| {
                let ctx = ctx.with_label(&format!("db_{}", idx + 1));
                Box::pin(open_digest_db(ctx))
            })
            .await;
        });
    }

    #[test_traced("INFO")]
    fn test_varkey_variable_generic_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_digest_db(context.with_label("db_0")).await;
            let ctx = context.clone();
            test_any_db_basic(db, move |idx| {
                let ctx = ctx.with_label(&format!("db_{}", idx + 1));
                Box::pin(open_digest_db(ctx))
            })
            .await;
        });
    }

    #[test_traced("WARN")]
    fn test_varkey_variable_generic_build_and_authenticate() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db_context = context.with_label("db");
            let db = open_digest_db(db_context.clone()).await;
            test_any_db_build_and_authenticate(
                db_context,
                db,
                |ctx| Box::pin(open_digest_db(ctx)),
                to_digest,
            )
            .await;
        });
    }
}
