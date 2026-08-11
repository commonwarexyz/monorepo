#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::Sha256;
use commonware_parallel::Sequential;
use commonware_runtime::{
    BufferPooler, Runner, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::{
    journal::contiguous::fixed::Config as FConfig,
    merkle::{Graftable, full::Config as MerkleConfig, mmb, mmr},
    qmdb::current::{FixedConfig as Config, unordered::fixed::Db as CurrentDb},
    translator::OneCap,
};
use commonware_utils::{FuzzRng, NZU16, NZU64, NZUsize, sequence::FixedBytes};
use libfuzzer_sys::fuzz_target;
use std::num::NonZeroU16;

type Key = FixedBytes<32>;
type Value = FixedBytes<32>;
type Db<F> = CurrentDb<F, deterministic::Context, Key, Value, Sha256, OneCap, 32, Sequential>;

const PAGE_SIZE: NonZeroU16 = NZU16!(137);
const COLLISION_GROUPS: u8 = 4;
const KEY_SPACE: u64 = 32;
const MAX_INITIAL_WRITES: usize = 16;
const MAX_PARENT_MUTATIONS: usize = 16;
const MAX_CHILD_MUTATIONS: usize = 16;

#[derive(Arbitrary, Debug, Clone, Copy)]
struct KeySeed {
    prefix: u8,
    suffix: u64,
}

#[derive(Arbitrary, Debug, Clone)]
struct SeededWrite {
    key: KeySeed,
    value: [u8; 32],
}

#[derive(Arbitrary, Debug, Clone)]
enum Mutation {
    Write { key: KeySeed, value: [u8; 32] },
    Delete { key: KeySeed },
}

#[derive(Debug)]
struct FuzzInput {
    initial: Vec<SeededWrite>,
    parent: Vec<Mutation>,
    child: Vec<Mutation>,
    raw_bytes: Vec<u8>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let raw_len = u.len().min(8);
        let raw_bytes = u.bytes(raw_len)?.to_vec();
        let initial_len = u.int_in_range(0..=MAX_INITIAL_WRITES)?;
        let parent_len = u.int_in_range(1..=MAX_PARENT_MUTATIONS)?;
        let child_len = u.int_in_range(1..=MAX_CHILD_MUTATIONS)?;

        let initial = (0..initial_len)
            .map(|_| SeededWrite::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;
        let parent = (0..parent_len)
            .map(|_| Mutation::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;
        let child = (0..child_len)
            .map(|_| Mutation::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            initial,
            parent,
            child,
            raw_bytes,
        })
    }
}

fn test_config(name: &str, pooler: &impl BufferPooler) -> Config<OneCap, Sequential> {
    let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, NZUsize!(2));
    Config {
        merkle_config: MerkleConfig {
            journal_partition: format!("{name}-merkle"),
            metadata_partition: format!("{name}-meta"),
            items_per_blob: NZU64!(17),
            write_buffer: NZUsize!(1024),
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        journal_config: FConfig {
            partition: format!("{name}-log"),
            items_per_blob: NZU64!(13),
            write_buffer: NZUsize!(1024),
            page_cache,
        },
        grafted_metadata_partition: format!("{name}-grafted"),
        translator: OneCap,
        init_cache_size: Some(NZUsize!(3)),
        init_buffer: NZUsize!(1 << 21),
        init_concurrency: (),
    }
}

fn key_from_seed(seed: KeySeed) -> Key {
    let mut bytes = [0u8; 32];
    bytes[0] = seed.prefix % COLLISION_GROUPS;
    let suffix = seed.suffix % KEY_SPACE;
    bytes[24..].copy_from_slice(&suffix.to_be_bytes());
    Key::new(bytes)
}

fn value_from_bytes(bytes: [u8; 32]) -> Value {
    Value::new(bytes)
}

fn fuzz_family<F: Graftable>(input: &FuzzInput, test_name: &str) {
    let cfg =
        deterministic::Config::new().with_rng(Box::new(FuzzRng::new(input.raw_bytes.clone())));
    let runner = deterministic::Runner::new(cfg);

    let test_name = test_name.to_string();
    runner.start(|context| async move {
        let cfg = test_config(&test_name, &context);
        let db: Db<F> = Db::init(context.child("storage"), cfg)
            .await
            .expect("init current unordered db");

        // Seed the committed base state so the wrapper sees collision-heavy
        // inner batching before parent/child comparisons.
        let mut batch = db.new_batch();
        for write in &input.initial {
            batch = batch.write(
                key_from_seed(write.key),
                Some(value_from_bytes(write.value)),
            );
        }
        let initial = batch.merkleize(&db, None).await.unwrap();
        let (db, _) = db.apply_batch(initial).await.unwrap();
        let db = db.commit().await.unwrap();

        // Build the child while the parent is still pending.
        let mut batch = db.new_batch();
        for mutation in &input.parent {
            batch = match mutation {
                Mutation::Write { key, value } => {
                    batch.write(key_from_seed(*key), Some(value_from_bytes(*value)))
                }
                Mutation::Delete { key } => batch.write(key_from_seed(*key), None),
            };
        }
        let parent_keys = input
            .parent
            .iter()
            .map(|mutation| match mutation {
                Mutation::Write { key, .. } | Mutation::Delete { key } => key_from_seed(*key),
            })
            .collect::<Vec<_>>();
        let parent_key_refs = parent_keys.iter().collect::<Vec<_>>();
        let parent_many = batch.get_many(&parent_key_refs, &db).await.unwrap();
        let mut parent_single = Vec::with_capacity(parent_keys.len());
        for key in &parent_keys {
            parent_single.push(batch.get(key, &db).await.unwrap());
        }
        assert_eq!(
            parent_many, parent_single,
            "unmerkleized batch get_many diverged from repeated get"
        );
        let parent = batch.merkleize(&db, None).await.unwrap();
        assert_eq!(
            *parent.bounds().base.size,
            *db.bounds().end,
            "parent batch should start at the committed database size"
        );
        assert!(
            *parent.bounds().tip.size > *parent.bounds().base.size,
            "merkleized batch should include a commit operation"
        );
        let parent_many = parent.get_many(&parent_key_refs, &db).await.unwrap();
        let mut parent_single = Vec::with_capacity(parent_keys.len());
        for key in &parent_keys {
            parent_single.push(parent.get(key, &db).await.unwrap());
        }
        assert_eq!(
            parent_many, parent_single,
            "merkleized batch get_many diverged from repeated get"
        );
        let mut batch = parent.new_batch::<Sha256>();
        for mutation in &input.child {
            batch = match mutation {
                Mutation::Write { key, value } => {
                    batch.write(key_from_seed(*key), Some(value_from_bytes(*value)))
                }
                Mutation::Delete { key } => batch.write(key_from_seed(*key), None),
            };
        }
        let pending_child = batch.merkleize(&db, None).await.unwrap();

        // Commit the parent, then rebuild the same logical child from the
        // committed wrapper state. Both canonical and ops roots must match.
        let (db, _) = db.apply_batch(parent).await.unwrap();
        let db = db.commit().await.unwrap();
        let snapshot = db.to_batch();
        assert_eq!(
            snapshot.root(),
            db.root(),
            "snapshot root should match the database"
        );
        assert_eq!(
            snapshot.ops_root(),
            db.ops_root(),
            "snapshot ops root should match the database"
        );
        assert_eq!(
            *snapshot.bounds().tip.size,
            *db.bounds().end,
            "snapshot size should match the database"
        );
        assert_eq!(
            snapshot.sync_boundary(),
            db.sync_boundary(),
            "snapshot sync boundary should match the database"
        );

        let mut batch = db.new_batch();
        for mutation in &input.child {
            batch = match mutation {
                Mutation::Write { key, value } => {
                    batch.write(key_from_seed(*key), Some(value_from_bytes(*value)))
                }
                Mutation::Delete { key } => batch.write(key_from_seed(*key), None),
            };
        }
        let committed_child = batch.merkleize(&db, None).await.unwrap();

        assert_eq!(
            pending_child.bounds().base.size,
            committed_child.bounds().base.size,
            "child base size depended on pending-vs-committed parent path"
        );
        assert_eq!(
            pending_child.bounds().tip.size,
            committed_child.bounds().tip.size,
            "child total size depended on pending-vs-committed parent path"
        );
        assert_eq!(
            pending_child.sync_boundary(),
            committed_child.sync_boundary(),
            "child sync boundary depended on pending-vs-committed parent path"
        );
        assert!(
            db.validate_batch(&pending_child).is_ok(),
            "child of the committed parent should validate"
        );
        assert!(
            db.validate_batch(&committed_child).is_ok(),
            "fresh child of the committed database should validate"
        );

        let child_keys = input
            .child
            .iter()
            .map(|mutation| match mutation {
                Mutation::Write { key, .. } | Mutation::Delete { key } => key_from_seed(*key),
            })
            .collect::<Vec<_>>();
        let child_key_refs = child_keys.iter().collect::<Vec<_>>();
        let pending_many = pending_child.get_many(&child_key_refs, &db).await.unwrap();
        let committed_many = committed_child
            .get_many(&child_key_refs, &db)
            .await
            .unwrap();
        assert_eq!(
            pending_many, committed_many,
            "child reads depended on pending-vs-committed parent path"
        );

        assert_eq!(
            pending_child.root(),
            committed_child.root(),
            "current root depended on pending-vs-committed parent path"
        );
        assert_eq!(
            pending_child.ops_root(),
            committed_child.ops_root(),
            "current ops root depended on pending-vs-committed parent path"
        );

        // Apply the pending child and verify the DB state matches.
        let (db, _) = db.apply_batch(pending_child).await.unwrap();
        assert_eq!(
            db.root(),
            committed_child.root(),
            "pending child canonical root diverged"
        );
        assert_eq!(
            db.ops_root(),
            committed_child.ops_root(),
            "pending child ops root diverged"
        );
        assert_eq!(
            db.bounds().end,
            committed_child.bounds().tip.size,
            "applied child size should match its batch bounds"
        );
        assert_eq!(
            db.sync_boundary(),
            committed_child.sync_boundary(),
            "applied child sync boundary should match its batch"
        );
        assert!(
            matches!(
                db.validate_batch(&committed_child),
                Err(commonware_storage::qmdb::Error::StaleBatch)
            ),
            "sibling child should be stale after the other branch is applied"
        );

        db.destroy().await.unwrap();
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz_family::<mmr::Family>(&input, "fuzz-mmr-current-unordered-batch-root");
    fuzz_family::<mmb::Family>(&input, "fuzz-mmb-current-unordered-batch-root");
});
