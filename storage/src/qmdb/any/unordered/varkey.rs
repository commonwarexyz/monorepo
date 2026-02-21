//! An authenticated database that provides succinct proofs of _any_ value ever associated
//! with a variable-length key, where values can also have varying sizes.
//!
//! Unlike other QMDB variants that require fixed-size keys (`K: Array`), this variant uses
//! `Vec<u8>` as the key type, supporting arbitrary-length byte sequences as keys.
//!
//! _If your keys are all the same fixed size, use [super::fixed] or [super::variable] instead
//! for better performance._

use crate::{
    index::unordered::Index,
    journal::contiguous::variable::Journal,
    mmr::Location,
    qmdb::{
        any::{init_variable, unordered, value::VarKeyEncoding, VariableValue},
        operation::Key,
        Durable, Error, Merkleized,
    },
    translator::Translator,
};
use commonware_codec::{Codec, Read};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};

pub type Update<K, V> = unordered::Update<K, VarKeyEncoding<V>>;
pub type Operation<K, V> = unordered::Operation<K, VarKeyEncoding<V>>;

/// A key-value QMDB based on an authenticated log of operations, supporting authentication of any
/// value ever associated with a variable-length key.
pub type Db<E, K, V, H, T, S = Merkleized<H>, D = Durable> = super::Db<
    E,
    Journal<E, Operation<K, V>>,
    Index<T, Location>,
    H,
    Update<K, V>,
    S,
    D,
>;

impl<E, K, V, H, T> Db<E, K, V, H, T, Merkleized<H>, Durable>
where
    E: Storage + Clock + Metrics,
    K: Key + Codec,
    V: VariableValue,
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
        mmr::{Location, StandardHasher},
        qmdb::{
            any::VariableConfig,
            store::LogStore,
            verify_proof,
        },
        translator::TwoCap,
    };
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

    type VarKeyDb = Db<deterministic::Context, Vec<u8>, Vec<u8>, Sha256, TwoCap>;

    type VarKeyCfg =
        VariableConfig<TwoCap, ((RangeCfg<usize>, ()), (RangeCfg<usize>, ()))>;

    fn create_config(suffix: &str, pooler: &impl BufferPooler) -> VarKeyCfg {
        VariableConfig {
            mmr_journal_partition: format!("vk-journal-{suffix}"),
            mmr_metadata_partition: format!("vk-metadata-{suffix}"),
            mmr_items_per_blob: NZU64!(13),
            mmr_write_buffer: NZUsize!(1024),
            log_partition: format!("vk-log-{suffix}"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            log_compression: None,
            log_codec_config: ((RangeCfg::from(0..=10000), ()), (RangeCfg::from(0..=10000), ())),
            translator: TwoCap,
            thread_pool: None,
            page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    async fn open_db(context: Context) -> VarKeyDb {
        let cfg = create_config("partition", &context);
        VarKeyDb::init(context, cfg).await.unwrap()
    }

    #[test_traced("INFO")]
    fn test_varkey_db_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_db(context.with_label("db_0")).await;
            assert_eq!(db.bounds().await.end, 1);
            assert!(db.get_metadata().await.unwrap().is_none());

            // Commit on empty db.
            let db = db.into_mutable();
            let (db, range) = db.commit(Some(vec![42])).await.unwrap();
            assert_eq!(range.start, 1);
            assert_eq!(range.end, 2);
            let db = db.into_merkleized();
            assert_eq!(db.get_metadata().await.unwrap(), Some(vec![42]));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_varkey_db_basic_crud() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.with_label("db")).await.into_mutable();

            let k1 = b"hello".to_vec();
            let k2 = b"world".to_vec();
            let v1 = b"value1".to_vec();
            let v2 = b"value2".to_vec();

            assert!(db.get(&k1).await.unwrap().is_none());

            db.write_batch([(k1.clone(), Some(v1.clone()))])
                .await
                .unwrap();
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
            assert!(db.get(&k2).await.unwrap().is_none());

            db.write_batch([(k2.clone(), Some(v2.clone()))])
                .await
                .unwrap();
            assert_eq!(db.get(&k2).await.unwrap().unwrap(), v2);

            // Update k1.
            db.write_batch([(k1.clone(), Some(v2.clone()))])
                .await
                .unwrap();
            assert_eq!(db.get(&k1).await.unwrap().unwrap(), v2);

            // Delete k1.
            db.write_batch([(k1.clone(), None)]).await.unwrap();
            assert!(db.get(&k1).await.unwrap().is_none());
            assert_eq!(db.get(&k2).await.unwrap().unwrap(), v2);

            // Commit.
            let (db, _) = db.commit(None).await.unwrap();
            let db = db.into_merkleized();

            // Re-open and verify.
            let root = db.root();
            drop(db);
            let db = open_db(context.with_label("db_reopen")).await;
            assert_eq!(db.root(), root);
            assert!(db.get(&k1).await.unwrap().is_none());
            assert_eq!(db.get(&k2).await.unwrap().unwrap(), v2);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_varkey_db_variable_length_keys() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.with_label("db")).await.into_mutable();

            let keys: Vec<Vec<u8>> = vec![
                vec![],
                vec![1],
                vec![1, 2],
                vec![0; 100],
                vec![0xFF; 1000],
            ];

            for (i, key) in keys.iter().enumerate() {
                let value = format!("value_{i}").into_bytes();
                db.write_batch([(key.clone(), Some(value))])
                    .await
                    .unwrap();
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

    #[test_traced("INFO")]
    fn test_varkey_db_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_db(context.with_label("open1")).await;
            let root = db.root();

            // Write without committing, then drop (simulate crash).
            let mut db = db.into_mutable();
            for i in 0u64..100 {
                let key = i.to_be_bytes().to_vec();
                let value = vec![(i % 255) as u8; 10];
                db.write_batch([(key, Some(value))]).await.unwrap();
            }
            drop(db);

            // Re-open should rollback to previous root.
            let db = open_db(context.with_label("open2")).await;
            assert_eq!(root, db.root());

            // Now write and commit.
            let mut db = db.into_mutable();
            for i in 0u64..100 {
                let key = i.to_be_bytes().to_vec();
                let value = vec![(i % 255) as u8; 10];
                db.write_batch([(key, Some(value))]).await.unwrap();
            }
            let (db, _) = db.commit(None).await.unwrap();
            let db = db.into_merkleized();
            let root = db.root();

            // Re-open should preserve committed state.
            drop(db);
            let db = open_db(context.with_label("open3")).await;
            assert_eq!(root, db.root());

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_varkey_db_build_and_authenticate() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.with_label("db")).await.into_mutable();
            const ELEMENTS: u64 = 200;

            for i in 0u64..ELEMENTS {
                let key = Sha256::hash(&i.to_be_bytes()).to_vec();
                let value = vec![(i % 255) as u8; ((i % 13) + 7) as usize];
                db.write_batch([(key, Some(value))]).await.unwrap();
            }

            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let key = Sha256::hash(&i.to_be_bytes()).to_vec();
                let value = vec![((i + 1) % 255) as u8; ((i % 13) + 8) as usize];
                db.write_batch([(key, Some(value))]).await.unwrap();
            }

            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let key = Sha256::hash(&i.to_be_bytes()).to_vec();
                db.write_batch([(key, None)]).await.unwrap();
            }

            let (db, _) = db.commit(None).await.unwrap();
            let mut db = db.into_merkleized();
            db.sync().await.unwrap();
            let prune_loc = db.inactivity_floor_loc();
            db.prune(prune_loc).await.unwrap();
            let root = db.root();

            let mut hasher = StandardHasher::<Sha256>::new();
            let bounds = db.bounds().await;
            for loc in *bounds.start..*bounds.end {
                let loc = Location::new_unchecked(loc);
                let (proof, ops) = db.proof(loc, NZU64!(10)).await.unwrap();
                assert!(verify_proof(&mut hasher, &proof, loc, &ops, &root));
            }

            db.sync().await.unwrap();
            drop(db);
            let db = open_db(context.with_label("db_reopen")).await;
            assert_eq!(root, db.root());

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_varkey_db_prune_beyond_floor() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.with_label("db")).await.into_mutable();

            db.write_batch([(b"k1".to_vec(), Some(vec![1]))])
                .await
                .unwrap();
            db.write_batch([(b"k2".to_vec(), Some(vec![2]))])
                .await
                .unwrap();
            let (db, _) = db.commit(None).await.unwrap();

            let floor = db.inactivity_floor_loc();
            let beyond = Location::new_unchecked(*floor + 1);

            let mut db = db.into_merkleized();
            let result = db.prune(beyond).await;
            assert!(matches!(
                result,
                Err(Error::PruneBeyondMinRequired(loc, f)) if loc == beyond && f == floor
            ));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_varkey_db_multiple_commits() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_db(context.with_label("db")).await.into_mutable();

            for i in 0u64..10 {
                let key = format!("key_{i}").into_bytes();
                let value = format!("val_{i}").into_bytes();
                db.write_batch([(key, Some(value))]).await.unwrap();
            }
            let (db, _) = db.commit(Some(b"meta1".to_vec())).await.unwrap();
            let mut db = db.into_merkleized().into_mutable();

            for i in 0u64..10 {
                let key = format!("key_{i}").into_bytes();
                if i % 3 == 0 {
                    db.write_batch([(key, None)]).await.unwrap();
                } else {
                    let value = format!("updated_{i}").into_bytes();
                    db.write_batch([(key, Some(value))]).await.unwrap();
                }
            }
            let (db, _) = db.commit(Some(b"meta2".to_vec())).await.unwrap();
            let db = db.into_merkleized();

            assert_eq!(db.get_metadata().await.unwrap(), Some(b"meta2".to_vec()));

            for i in 0u64..10 {
                let key = format!("key_{i}").into_bytes();
                if i % 3 == 0 {
                    assert!(db.get(&key).await.unwrap().is_none());
                } else {
                    let expected = format!("updated_{i}").into_bytes();
                    assert_eq!(db.get(&key).await.unwrap().unwrap(), expected);
                }
            }

            let bounds = db.bounds().await;
            assert!(bounds.end - db.inactivity_floor_loc() <= 12);

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

    type DigestVarKeyDb = Db<deterministic::Context, Digest, Digest, Sha256, TwoCap>;

    async fn open_digest_db(context: Context) -> DigestVarKeyDb {
        let cfg = varkey_db_config::<TwoCap>("partition", &context);
        DigestVarKeyDb::init(context, cfg).await.unwrap()
    }

    #[inline]
    fn to_digest(i: u64) -> Digest {
        Sha256::hash(&i.to_be_bytes())
    }

    #[test_traced("INFO")]
    fn test_varkey_generic_empty() {
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
    fn test_varkey_generic_basic() {
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
    fn test_varkey_generic_build_and_authenticate() {
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
