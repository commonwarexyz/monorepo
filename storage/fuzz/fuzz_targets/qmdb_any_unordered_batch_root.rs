#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_parallel::Sequential;
use commonware_runtime::{
    BufferPooler, Runner, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::{
    journal::contiguous::fixed::Config as FConfig,
    merkle::{Family as MerkleFamily, full::Config as MerkleConfig, mmb, mmr},
    qmdb::any::{
        FixedConfig as Config,
        batch::UnmerkleizedBatch,
        unordered::fixed::{Db as AnyDb, Update},
    },
    translator::OneCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize, sequence::FixedBytes};
use libfuzzer_sys::fuzz_target;
use std::num::NonZeroU16;

type Key = FixedBytes<32>;
type Value = FixedBytes<32>;
type Db<F> = AnyDb<F, deterministic::Context, Key, Value, Sha256, OneCap, Sequential>;
type Batch<F> = UnmerkleizedBatch<F, Sha256, Update<Key, Value>, Sequential>;

const PAGE_SIZE: NonZeroU16 = NZU16!(131);
const COLLISION_GROUPS: u8 = 4;
const KEY_SPACE: u64 = 32;
const MAX_INITIAL_WRITES: usize = 16;
const MAX_PARENT_MUTATIONS: usize = 16;
const MAX_CHILD_MUTATIONS: usize = 16;
const MAX_GRANDCHILD_MUTATIONS: usize = 16;

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Schedule {
    PendingParent,
    DroppedCommittedPrefix,
}

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
    schedule: Schedule,
    initial: Vec<SeededWrite>,
    parent: Vec<Mutation>,
    child: Vec<Mutation>,
    grandchild: Vec<Mutation>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let schedule = Schedule::arbitrary(u)?;
        let initial_len = u.int_in_range(0..=MAX_INITIAL_WRITES)?;
        let parent_len = u.int_in_range(1..=MAX_PARENT_MUTATIONS)?;
        let child_len = u.int_in_range(1..=MAX_CHILD_MUTATIONS)?;
        let grandchild_len = u.int_in_range(1..=MAX_GRANDCHILD_MUTATIONS)?;

        let initial = (0..initial_len)
            .map(|_| SeededWrite::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;
        let parent = (0..parent_len)
            .map(|_| Mutation::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;
        let child = (0..child_len)
            .map(|_| Mutation::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;
        let grandchild = (0..grandchild_len)
            .map(|_| Mutation::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            schedule,
            initial,
            parent,
            child,
            grandchild,
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
            replay_buffer: NZUsize!(1024),
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        journal_config: FConfig {
            partition: format!("{name}-log"),
            items_per_blob: NZU64!(13),
            write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
            page_cache,
        },
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

fn apply_mutations<F: MerkleFamily>(mut batch: Batch<F>, mutations: &[Mutation]) -> Batch<F> {
    for mutation in mutations {
        batch = match mutation {
            Mutation::Write { key, value } => {
                batch.write(key_from_seed(*key), Some(value_from_bytes(*value)))
            }
            Mutation::Delete { key } => batch.write(key_from_seed(*key), None),
        };
    }
    batch
}

fn fuzz_family<F: MerkleFamily>(input: &FuzzInput, suffix: &str) {
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let cfg = test_config(suffix, &context);
        let db: Db<F> = Db::init(context.child("storage"), cfg)
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
        let initial = batch.merkleize(&db, None).await.unwrap();
        let (db, _) = db.apply_batch(initial).await.unwrap();
        let db = db.commit().await.unwrap();

        let db = match input.schedule {
            Schedule::PendingParent => {
                // Build a parent batch, then build the child while the parent is still
                // pending so the child must resolve through base_diff plus the stale
                // committed snapshot.
                let batch = apply_mutations(db.new_batch(), &input.parent);
                let parent = batch.merkleize(&db, None).await.unwrap();
                let batch = apply_mutations(parent.new_batch::<Sha256>(), &input.child);
                let pending_child = batch.merkleize(&db, None).await.unwrap();

                // Commit the parent, then rebuild the same logical child from the
                // committed DB state. Both speculative roots must match.
                let (db, _) = db.apply_batch(parent).await.unwrap();
                let db = db.commit().await.unwrap();

                let batch = apply_mutations(db.new_batch(), &input.child);
                let committed_child = batch.merkleize(&db, None).await.unwrap();

                assert_eq!(
                    pending_child.root(),
                    committed_child.root(),
                    "child root depended on pending-vs-committed parent path"
                );

                // Apply the pending child and verify the DB state matches.
                let (db, _) = db.apply_batch(pending_child).await.unwrap();
                assert_eq!(
                    db.root(),
                    committed_child.root(),
                    "pending child root diverged"
                );
                db
            }
            Schedule::DroppedCommittedPrefix => {
                // Build A -> B, then commit and drop A before merkleizing C. C must retain
                // only B and position that suffix relative to the now-committed A.
                let batch = apply_mutations(db.new_batch(), &input.parent);
                let a = batch.merkleize(&db, None).await.unwrap();
                let batch = apply_mutations(a.new_batch::<Sha256>(), &input.child);
                let b = batch.merkleize(&db, None).await.unwrap();

                // Applying A consumes its last strong reference; B retains only a Weak parent.
                let (db, _) = db.apply_batch(a).await.unwrap();
                let db = db.commit().await.unwrap();

                let batch = apply_mutations(b.new_batch::<Sha256>(), &input.grandchild);
                let retained_child = batch.merkleize(&db, None).await.unwrap();

                // Rebuild B -> C from the committed A state as a reference.
                let batch = apply_mutations(db.new_batch(), &input.child);
                let rebuilt_b = batch.merkleize(&db, None).await.unwrap();
                let batch = apply_mutations(rebuilt_b.new_batch::<Sha256>(), &input.grandchild);
                let rebuilt_child = batch.merkleize(&db, None).await.unwrap();

                assert_eq!(
                    retained_child.root(),
                    rebuilt_child.root(),
                    "child root depended on a committed-and-dropped prefix"
                );

                let (db, _) = db.apply_batch(retained_child).await.unwrap();
                assert_eq!(
                    db.root(),
                    rebuilt_child.root(),
                    "retained-suffix child root diverged"
                );
                db
            }
        };

        db.destroy().await.unwrap();
    });
}

fuzz_target!(|input: FuzzInput| {
    match input.schedule {
        Schedule::PendingParent => {
            fuzz_family::<mmr::Family>(&input, "fuzz-mmr-qmdb-unordered-batch-root");
            fuzz_family::<mmb::Family>(&input, "fuzz-mmb-qmdb-unordered-batch-root");
        }
        Schedule::DroppedCommittedPrefix => {
            fuzz_family::<mmb::Family>(&input, "fuzz-mmb-qmdb-unordered-dropped-prefix");
        }
    }
});
