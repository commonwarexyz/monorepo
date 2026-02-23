//! An authenticated database that provides succinct proofs of _any_ value ever associated with a
//! key, where keys have varying sizes but values are fixed-size.
//!
//! Unlike other QMDB variants that require fixed-size keys (`K: Array`), this variant accepts any
//! key type implementing the [`Key`] trait (such as `Vec<u8>`), supporting arbitrary-length byte
//! sequences as keys.
//!
//! _If your keys are all the same fixed size, use [super::fixed] instead for better performance.
//! If your values are also variable-size, use [super::varkey_variable] instead._

use crate::{
    index::unordered::Index,
    journal::contiguous::variable::Journal,
    mmr::Location,
    qmdb::{
        any::{
            encoding::{FixedVal, VariableKey},
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

pub type Update<K, V> = unordered::Update<VariableKey<K, V>>;
pub type Operation<K, V> = unordered::Operation<VariableKey<K, V>>;

/// A key-value QMDB with variable-length keys and fixed-size values.
pub type Db<E, K, V, H, T, S = Merkleized<H>, D = Durable> =
    super::Db<E, Journal<E, Operation<K, V>>, Index<T, Location>, H, Update<K, V>, S, D>;

impl<E, K, V, H, T> Db<E, K, V, H, T, Merkleized<H>, Durable>
where
    E: Storage + Clock + Metrics,
    K: Key + Codec,
    V: FixedVal,
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
    use crate::{
        qmdb::any::{test::variable_db_config, VariableConfig},
        translator::TwoCap,
    };
    use commonware_codec::RangeCfg;
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        buffer::paged::CacheRef,
        deterministic::{self, Context},
        Runner as _,
    };
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use std::num::{NonZeroU16, NonZeroUsize};

    const PAGE_SIZE: NonZeroU16 = NZU16!(77);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(9);

    /// Test with actual variable-length Vec<u8> keys and fixed-size u64 values.
    #[test_traced("INFO")]
    fn test_varkey_fixed_db_variable_length_keys() {
        type VariableKeyFixedDb = Db<deterministic::Context, Vec<u8>, u64, Sha256, TwoCap>;
        type Cfg = VariableConfig<TwoCap, (RangeCfg<usize>, ())>;

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg: Cfg = VariableConfig {
                mmr_journal_partition: "vkf-journal".into(),
                mmr_metadata_partition: "vkf-metadata".into(),
                mmr_items_per_blob: NZU64!(13),
                mmr_write_buffer: NZUsize!(1024),
                log_partition: "vkf-log".into(),
                log_items_per_blob: NZU64!(7),
                log_write_buffer: NZUsize!(1024),
                log_compression: None,
                log_codec_config: (RangeCfg::from(0..=10000), ()),
                translator: TwoCap,
                thread_pool: None,
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let mut db = VariableKeyFixedDb::init(context.with_label("db"), cfg)
                .await
                .unwrap()
                .into_mutable();

            let keys: Vec<Vec<u8>> =
                vec![vec![], vec![1], vec![1, 2], vec![0; 100], vec![0xFF; 1000]];

            for (i, key) in keys.iter().enumerate() {
                db.write_batch([(key.clone(), Some(i as u64))])
                    .await
                    .unwrap();
            }

            for (i, key) in keys.iter().enumerate() {
                assert_eq!(db.get(key).await.unwrap().unwrap(), i as u64);
            }

            let (db, _) = db.commit(None).await.unwrap();
            let db = db.into_merkleized();

            for (i, key) in keys.iter().enumerate() {
                assert_eq!(db.get(key).await.unwrap().unwrap(), i as u64);
            }

            db.destroy().await.unwrap();
        });
    }

    // ---------------------------------------------------------------------------------
    // Generic test helpers (using Digest keys to match TestableAnyDb<Digest> interface)
    // ---------------------------------------------------------------------------------

    use crate::qmdb::any::unordered::test::{
        test_any_db_basic, test_any_db_build_and_authenticate, test_any_db_empty,
    };

    type DigestVariableKeyFixedDb = Db<deterministic::Context, Digest, Digest, Sha256, TwoCap>;

    async fn open_digest_db(context: Context) -> DigestVariableKeyFixedDb {
        let cfg = variable_db_config::<TwoCap>("partition", &context);
        DigestVariableKeyFixedDb::init(context, cfg).await.unwrap()
    }

    #[inline]
    fn to_digest(i: u64) -> Digest {
        Sha256::hash(&i.to_be_bytes())
    }

    #[test_traced("INFO")]
    fn test_varkey_fixed_generic_empty() {
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
    fn test_varkey_fixed_generic_basic() {
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
    fn test_varkey_fixed_generic_build_and_authenticate() {
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
