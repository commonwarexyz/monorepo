#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_runtime::{buffer::paged::CacheRef, deterministic, BufferPooler, Runner};
use commonware_storage::{
    journal::contiguous::fixed::Config as FConfig,
    merkle::mmr::Family,
    mmr::journaled::Config as MmrConfig,
    qmdb::any::{unordered::fixed::Db as AnyDb, FixedConfig as Config},
    translator::OneCap,
};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU16, NZU64};
use libfuzzer_sys::fuzz_target;
use std::num::NonZeroU16;

type Key = FixedBytes<32>;
type Value = FixedBytes<32>;
type Db = AnyDb<Family, deterministic::Context, Key, Value, Sha256, OneCap>;

const PAGE_SIZE: NonZeroU16 = NZU16!(131);
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
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
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
        })
    }
}

fn test_config(name: &str, pooler: &impl BufferPooler) -> Config<OneCap> {
    let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, NZUsize!(2));
    Config {
        merkle_config: MmrConfig {
            journal_partition: format!("{name}-mmr"),
            metadata_partition: format!("{name}-meta"),
            items_per_blob: NZU64!(17),
            write_buffer: NZUsize!(1024),
            thread_pool: None,
            page_cache: page_cache.clone(),
        },
        journal_config: FConfig {
            partition: format!("{name}-log"),
            items_per_blob: NZU64!(13),
            write_buffer: NZUsize!(1024),
            page_cache,
        },
        translator: OneCap,
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

fn fuzz(input: FuzzInput) {
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let cfg = test_config("fuzz-qmdb-unordered-pending-vs-committed-root", &context);
        let mut db = Db::init(context.clone(), cfg)
            .await
            .expect("init unordered any db");

        // Seed the committed base state so parent/child batching sees both
        // translated-key collisions and ordinary committed lookups.
        let mut batch = db.new_batch();
        for write in &input.initial {
            batch = batch.write(
                key_from_seed(write.key),
                Some(value_from_bytes(write.value)),
            );
        }
        let initial = batch.merkleize(None, &db).await.unwrap();
        db.apply_batch(initial).await.unwrap();
        db.commit().await.unwrap();

        // Build a parent batch, then build the child while the parent is still
        // pending so the child must resolve through base_diff plus the stale
        // committed snapshot.
        let mut batch = db.new_batch();
        for mutation in &input.parent {
            batch = match mutation {
                Mutation::Write { key, value } => {
                    batch.write(key_from_seed(*key), Some(value_from_bytes(*value)))
                }
                Mutation::Delete { key } => batch.write(key_from_seed(*key), None),
            };
        }
        let parent = batch.merkleize(None, &db).await.unwrap();
        let mut batch = parent.new_batch::<Sha256>();
        for mutation in &input.child {
            batch = match mutation {
                Mutation::Write { key, value } => {
                    batch.write(key_from_seed(*key), Some(value_from_bytes(*value)))
                }
                Mutation::Delete { key } => batch.write(key_from_seed(*key), None),
            };
        }
        let pending_child = batch.merkleize(None, &db).await.unwrap();

        // Commit the parent, then rebuild the same logical child from the
        // committed DB state. Both speculative roots must match.
        db.apply_batch(parent).await.unwrap();
        db.commit().await.unwrap();

        let mut batch = db.new_batch();
        for mutation in &input.child {
            batch = match mutation {
                Mutation::Write { key, value } => {
                    batch.write(key_from_seed(*key), Some(value_from_bytes(*value)))
                }
                Mutation::Delete { key } => batch.write(key_from_seed(*key), None),
            };
        }
        let committed_child = batch.merkleize(None, &db).await.unwrap();

        assert_eq!(
            pending_child.root(),
            committed_child.root(),
            "child root depended on pending-vs-committed parent path"
        );

        // Apply the pending child and verify the DB state matches.
        db.apply_batch(pending_child).await.unwrap();
        assert_eq!(
            db.root(),
            committed_child.root(),
            "pending child root diverged"
        );

        db.destroy().await.unwrap();
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
