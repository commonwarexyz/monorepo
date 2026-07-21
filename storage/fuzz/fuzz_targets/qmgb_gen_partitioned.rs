#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_parallel::Sequential;
use commonware_runtime::{
    BufferPooler, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::{
    journal::contiguous::fixed::Config as JournalConfig,
    merkle::{Graftable, full::Config as MerkleConfig, mmb, mmr},
    qmdb::{
        any::{
            FixedConfig as AnyConfig, ordered::fixed::partitioned::Db as AnyOrdered,
            unordered::fixed::partitioned::Db as AnyUnordered,
        },
        current::{
            FixedConfig as CurrentConfig, ordered::fixed::partitioned::Db as CurrentOrdered,
            unordered::fixed::partitioned::Db as CurrentUnordered,
        },
    },
    translator::TwoCap,
};
use commonware_utils::{FuzzRng, NZU16, NZU64, NZUsize};
use libfuzzer_sys::fuzz_target;
use std::{collections::BTreeMap, num::NonZeroU16};

const MAX_OPERATIONS: usize = 20;
const PAGE_SIZE: NonZeroU16 = NZU16!(139);
const PARTITION_BYTES: usize = 1;
const BITMAP_CHUNK_BYTES: usize = 32;

type AnyOrderedDb<F> = AnyOrdered<
    F,
    deterministic::Context,
    Digest,
    Digest,
    Sha256,
    TwoCap,
    PARTITION_BYTES,
    Sequential,
>;
type AnyUnorderedDb<F> = AnyUnordered<
    F,
    deterministic::Context,
    Digest,
    Digest,
    Sha256,
    TwoCap,
    PARTITION_BYTES,
    Sequential,
>;
type CurrentOrderedDb<F> = CurrentOrdered<
    F,
    deterministic::Context,
    Digest,
    Digest,
    Sha256,
    TwoCap,
    PARTITION_BYTES,
    BITMAP_CHUNK_BYTES,
    Sequential,
>;
type CurrentUnorderedDb<F> = CurrentUnordered<
    F,
    deterministic::Context,
    Digest,
    Digest,
    Sha256,
    TwoCap,
    PARTITION_BYTES,
    BITMAP_CHUNK_BYTES,
    Sequential,
>;

#[derive(Arbitrary, Clone, Debug)]
enum Operation {
    Update { key: [u8; 32], value: [u8; 32] },
    Delete { key: [u8; 32] },
    Commit,
    Get { key: [u8; 32] },
    Sync,
    ToBatch,
}

#[derive(Debug)]
struct FuzzInput {
    raw_bytes: Vec<u8>,
    operations: Vec<Operation>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let raw_len = u.len().min(8);
        let raw_bytes = u.bytes(raw_len)?.to_vec();
        let operation_count = u.int_in_range(1..=MAX_OPERATIONS)?;
        let operations = (0..operation_count)
            .map(|_| Operation::arbitrary(u))
            .collect::<arbitrary::Result<Vec<_>>>()?;
        Ok(Self {
            raw_bytes,
            operations,
        })
    }
}

fn journal_config(name: &str, pooler: &impl BufferPooler) -> JournalConfig {
    JournalConfig {
        partition: format!("{name}-log"),
        items_per_blob: NZU64!(7),
        write_buffer: NZUsize!(1024),
        page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, NZUsize!(8)),
    }
}

fn any_config(
    name: &str,
    pooler: &impl BufferPooler,
) -> AnyConfig<TwoCap, Sequential, std::num::NonZeroUsize> {
    let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, NZUsize!(8));
    AnyConfig {
        merkle_config: MerkleConfig {
            journal_partition: format!("{name}-merkle"),
            metadata_partition: format!("{name}-metadata"),
            items_per_blob: NZU64!(11),
            write_buffer: NZUsize!(1024),
            strategy: Sequential,
            page_cache,
        },
        journal_config: journal_config(name, pooler),
        translator: TwoCap,
        init_cache_size: Some(NZUsize!(32)),
        init_buffer: NZUsize!(1 << 16),
        init_concurrency: NZUsize!(1),
    }
}

fn current_config(
    name: &str,
    pooler: &impl BufferPooler,
) -> CurrentConfig<TwoCap, Sequential, std::num::NonZeroUsize> {
    let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, NZUsize!(8));
    CurrentConfig {
        merkle_config: MerkleConfig {
            journal_partition: format!("{name}-merkle"),
            metadata_partition: format!("{name}-metadata"),
            items_per_blob: NZU64!(11),
            write_buffer: NZUsize!(1024),
            strategy: Sequential,
            page_cache,
        },
        journal_config: journal_config(name, pooler),
        grafted_metadata_partition: format!("{name}-grafted"),
        translator: TwoCap,
        init_cache_size: Some(NZUsize!(32)),
        init_buffer: NZUsize!(1 << 16),
        init_concurrency: NZUsize!(1),
    }
}

macro_rules! exercise {
    ($db:expr, $operations:expr) => {{
        let mut db = $db;
        let mut committed = BTreeMap::<Digest, Digest>::new();
        let mut pending = BTreeMap::<Digest, Option<Digest>>::new();

        for operation in $operations {
            match operation {
                Operation::Update { key, value } => {
                    pending.insert(Digest::from(*key), Some(Digest::from(*value)));
                }
                Operation::Delete { key } => {
                    let key = Digest::from(*key);
                    if pending.get(&key).is_some_and(Option::is_some)
                        || (!pending.contains_key(&key) && committed.contains_key(&key))
                    {
                        pending.insert(key, None);
                    }
                }
                Operation::Commit => {
                    let mut batch = db.new_batch();
                    for (key, value) in &pending {
                        batch = batch.write(*key, *value);
                    }
                    let batch = batch
                        .merkleize(&db, None)
                        .await
                        .expect("merkleize partitioned batch");
                    assert!(db.validate_batch(&batch).is_ok());
                    let expected_root = batch.root();
                    let start = db.bounds().end;
                    let (next, range) = db
                        .apply_batch(batch)
                        .await
                        .expect("apply partitioned batch");
                    db = next.commit().await.expect("commit partitioned db");
                    assert_eq!(range.start, start);
                    assert_eq!(range.end, db.bounds().end);
                    assert_eq!(db.root(), expected_root);
                    for (key, value) in std::mem::take(&mut pending) {
                        if let Some(value) = value {
                            committed.insert(key, value);
                        } else {
                            committed.remove(&key);
                        }
                    }
                }
                Operation::Get { key } => {
                    let key = Digest::from(*key);
                    assert_eq!(
                        db.get(&key).await.expect("read partitioned db"),
                        committed.get(&key).copied()
                    );
                }
                Operation::Sync => {
                    let expected = (db.bounds(), db.root());
                    db = db.sync().await.expect("sync partitioned db");
                    assert_eq!(
                        (db.bounds(), db.root()),
                        expected,
                        "sync should preserve partitioned database state"
                    );
                    for (key, expected) in &committed {
                        assert_eq!(
                            db.get(key).await.expect("read synced partitioned db"),
                            Some(*expected)
                        );
                    }
                }
                Operation::ToBatch => {
                    let snapshot = db.to_batch();
                    assert_eq!(snapshot.root(), db.root());
                }
            }
        }

        db.destroy().await.expect("destroy partitioned db");
    }};
}

fn fuzz_family<F: Graftable>(input: &FuzzInput, family: &str) {
    let runtime =
        deterministic::Config::new().with_rng(Box::new(FuzzRng::new(input.raw_bytes.clone())));
    deterministic::Runner::new(runtime).start(|context| async move {
        let name = format!("qmgb-any-ordered-{family}");
        let db: AnyOrderedDb<F> =
            AnyOrderedDb::init(context.child("any_ordered"), any_config(&name, &context))
                .await
                .expect("init partitioned Any ordered db");
        exercise!(db, &input.operations);

        let name = format!("qmgb-any-unordered-{family}");
        let db: AnyUnorderedDb<F> =
            AnyUnorderedDb::init(context.child("any_unordered"), any_config(&name, &context))
                .await
                .expect("init partitioned Any unordered db");
        exercise!(db, &input.operations);

        let name = format!("qmgb-current-ordered-{family}");
        let db: CurrentOrderedDb<F> = CurrentOrderedDb::init(
            context.child("current_ordered"),
            current_config(&name, &context),
        )
        .await
        .expect("init partitioned Current ordered db");
        exercise!(db, &input.operations);

        let name = format!("qmgb-current-unordered-{family}");
        let db: CurrentUnorderedDb<F> = CurrentUnorderedDb::init(
            context.child("current_unordered"),
            current_config(&name, &context),
        )
        .await
        .expect("init partitioned Current unordered db");
        exercise!(db, &input.operations);
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz_family::<mmr::Family>(&input, "mmr");
    fuzz_family::<mmb::Family>(&input, "mmb");
});
