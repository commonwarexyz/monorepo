#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_parallel::Sequential;
use commonware_runtime::{
    BufferPooler, Runner, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::{
    journal::contiguous::fixed::Config as FConfig,
    merkle::{Graftable, Location, full::Config as MerkleConfig, mmb, mmr},
    qmdb::{
        any::{ordered::Update, traits::DbAny as _, value::FixedEncoding as FixedEncodingGeneric},
        current::{
            FixedConfig as Config,
            batch::{MerkleizedBatch, UnmerkleizedBatch},
            ordered::fixed::Db as CurrentDb,
        },
    },
    translator::OneCap,
};
use commonware_storage_fuzz::{
    assert_ordered_neighbors,
    floor::{Plan, Recorder},
};
use commonware_utils::{NZU16, NZU64, NZUsize, sequence::FixedBytes};
use libfuzzer_sys::fuzz_target;
use std::{collections::BTreeMap, num::NonZeroU16, sync::Arc};

type Key = FixedBytes<32>;
type Value = FixedBytes<32>;
type FixedEncoding = FixedEncodingGeneric<Value>;
type Db<F> = CurrentDb<F, deterministic::Context, Key, Value, Sha256, OneCap, 32, Sequential>;
type Batch<F> = UnmerkleizedBatch<F, Sha256, Update<Key, FixedEncoding>, 32, Sequential>;
type Merkleized<F> = MerkleizedBatch<F, Digest, Update<Key, FixedEncoding>, 32, Sequential>;

const PAGE_SIZE: NonZeroU16 = NZU16!(137);

// A small key space with few translated-key buckets forces frequent collisions between distinct
// full keys, so a parent-deleted key and a colliding sibling routinely land in one bucket.
const COLLISION_GROUPS: u8 = 4;
const KEY_SPACE: u64 = 32;
const MAX_INITIAL_WRITES: usize = 16;
const MAX_PARENT_MUTATIONS: usize = 16;
const MAX_CHILD_MUTATIONS: usize = 16;
const MAX_GRANDCHILD_MUTATIONS: usize = 16;

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Schedule {
    PendingParent,
    PendingChain,
    DroppedPrefixChain,
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
    initial_plan: Plan,
    parent_plan: Plan,
    child_plan: Plan,
    grandchild_plan: Plan,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let schedule = Schedule::arbitrary(u)?;
        let initial_plan = Plan::arbitrary(u)?;
        let parent_plan = Plan::arbitrary(u)?;
        let child_plan = Plan::arbitrary(u)?;
        let grandchild_plan = Plan::arbitrary(u)?;
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
            initial_plan,
            parent_plan,
            child_plan,
            grandchild_plan,
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
        grafted_metadata_partition: format!("{name}-grafted"),
        translator: OneCap,
        init_cache: Some(NZUsize!(3)),
        init_buffer: NZUsize!(1 << 21),
        init_concurrency: (),
    }
}

fn key_from_seed(seed: KeySeed) -> Key {
    let mut bytes = [0u8; 32];
    // The first byte selects the translated-key bucket (OneCap keys on it), the suffix keeps the
    // full keys distinct within a bucket so ordered next-key bookkeeping stays exercised.
    bytes[0] = seed.prefix % COLLISION_GROUPS;
    let suffix = seed.suffix % KEY_SPACE;
    bytes[24..].copy_from_slice(&suffix.to_be_bytes());
    Key::new(bytes)
}

fn value_from_bytes(bytes: [u8; 32]) -> Value {
    Value::new(bytes)
}

fn replacement(seed: u8) -> Value {
    Value::new([seed; 32])
}

fn apply_mutations<F: Graftable>(mut batch: Batch<F>, mutations: &[Mutation]) -> Batch<F> {
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

/// Advance the batch's logical key-value model independently of ancestor application.
///
/// The same expected neighbors apply before and after ancestors are applied to the database.
fn apply_to_model(model: &mut BTreeMap<Key, Value>, mutations: &[Mutation]) {
    for mutation in mutations {
        let key = key_from_seed(match mutation {
            Mutation::Write { key, .. } | Mutation::Delete { key } => *key,
        });
        match mutation {
            Mutation::Write { value, .. } => {
                model.insert(key, value_from_bytes(*value));
            }
            Mutation::Delete { .. } => {
                model.remove(&key);
            }
        }
    }
}

/// Merkleize `batch` under `plan` from the `inherited` floor, check its floor walk against
/// `model` (already advanced by the batch's writes), and replay the walk's decisions into it.
async fn merkleize<F: Graftable>(
    db: &Db<F>,
    batch: Batch<F>,
    inherited: Location<F>,
    plan: &Plan,
    model: &mut BTreeMap<Key, Value>,
) -> (Arc<Merkleized<F>>, Recorder<Key, Value>) {
    let mut policy = Recorder::new(plan, replacement);
    let merkleized = batch.merkleize(db, None, &mut policy).await.unwrap();
    let bounds = merkleized.bounds();
    policy.check(
        model,
        inherited,
        bounds.inactivity_floor,
        bounds.tip.size - 1,
    );
    (merkleized, policy)
}

/// Merkleize `batch`, which rebuilds the batch `original` walked along another path, and check
/// that its walk makes the same decisions.
async fn rebuild<F: Graftable>(
    db: &Db<F>,
    batch: Batch<F>,
    plan: &Plan,
    original: &Recorder<Key, Value>,
) -> Arc<Merkleized<F>> {
    let mut policy = Recorder::new(plan, replacement);
    let merkleized = batch.merkleize(db, None, &mut policy).await.unwrap();
    policy.assert_same_walk(original);
    merkleized
}

/// Check strict, non-wrapping neighbors across the mutation key space, including absent keys.
/// A query above that space also checks the upper boundary.
async fn assert_batch_neighbors<F: Graftable>(
    db: &Db<F>,
    batch: &Merkleized<F>,
    model: &BTreeMap<Key, Value>,
) {
    let queries = (0..COLLISION_GROUPS)
        .flat_map(|prefix| {
            (0..KEY_SPACE).map(move |suffix| key_from_seed(KeySeed { prefix, suffix }))
        })
        .chain([Key::new([u8::MAX; 32])]);
    for key in queries {
        assert_ordered_neighbors(
            model.keys().cloned(),
            &key,
            batch.get_prev_key(&key, db).await.unwrap(),
            batch.get_next_key(&key, db).await.unwrap(),
        );
    }
}

/// Check every key in the mutation key space against the model.
async fn assert_matches_model<F: Graftable>(db: &Db<F>, model: &BTreeMap<Key, Value>) {
    assert_eq!(db.is_empty(), model.is_empty(), "empty-db state diverged");
    let keys = (0..COLLISION_GROUPS).flat_map(|prefix| {
        (0..KEY_SPACE).map(move |suffix| key_from_seed(KeySeed { prefix, suffix }))
    });
    for key in keys {
        let got = db.get(&key).await.expect("get should not fail");
        assert_eq!(got.as_ref(), model.get(&key), "db diverged from model");
    }
}

/// Commit `db`, then reopen it and check that recovery rebuilds the same roots, floor, and live
/// state from the log, including the floor walks' rewrites and evictions.
async fn assert_recovers<F: Graftable>(
    context: &deterministic::Context,
    name: &str,
    db: Db<F>,
    model: &BTreeMap<Key, Value>,
) {
    let db = db.commit().await.unwrap();
    assert_matches_model(&db, model).await;
    let roots = (db.root(), db.ops_root());
    let floor = db.inactivity_floor_loc();
    drop(db);

    let db: Db<F> = Db::init(context.child("reopened"), test_config(name, context), None)
        .await
        .expect("reopen current ordered db");
    assert_eq!(
        (db.root(), db.ops_root()),
        roots,
        "roots changed across reopen"
    );
    assert_eq!(
        db.inactivity_floor_loc(),
        floor,
        "floor changed across reopen"
    );
    assert_matches_model(&db, model).await;
    db.destroy().await.unwrap();
}

fn fuzz_family<F: Graftable>(input: &FuzzInput, test_name: &str) {
    let runner = deterministic::Runner::default();

    let test_name = test_name.to_string();
    runner.start(|context| async move {
        let cfg = test_config(&test_name, &context);
        let db: Db<F> = Db::init(context.child("storage"), cfg, None)
            .await
            .expect("init current ordered db");

        // Seed committed base state so recursive batching sees translated-key collisions
        // against the committed snapshot.
        let mut model = BTreeMap::new();
        let mut batch = db.new_batch();
        for write in &input.initial {
            batch = batch.write(
                key_from_seed(write.key),
                Some(value_from_bytes(write.value)),
            );
            model.insert(key_from_seed(write.key), value_from_bytes(write.value));
        }
        let floor = db.inactivity_floor_loc();
        let (initial, _) = merkleize(&db, batch, floor, &input.initial_plan, &mut model).await;
        assert_batch_neighbors(&db, &initial, &model).await;
        let (db, _) = db.apply_batch(initial).await.unwrap();
        let db = db.commit().await.unwrap();

        match input.schedule {
            Schedule::PendingParent => {
                // Build the child while the parent is still pending, so the child resolves
                // through the parent's diff plus the committed snapshot. A parent-deleted key
                // with a colliding committed sibling is the advisory's trigger.
                let batch = apply_mutations(db.new_batch(), &input.parent);
                apply_to_model(&mut model, &input.parent);
                let floor = db.inactivity_floor_loc();
                let (parent, _) =
                    merkleize(&db, batch, floor, &input.parent_plan, &mut model).await;
                assert_batch_neighbors(&db, &parent, &model).await;
                let batch = apply_mutations(parent.new_batch::<Sha256>(), &input.child);
                apply_to_model(&mut model, &input.child);
                let floor = parent.bounds().inactivity_floor;
                let (pending_child, child_walk) =
                    merkleize(&db, batch, floor, &input.child_plan, &mut model).await;
                assert_batch_neighbors(&db, &pending_child, &model).await;

                // Commit the parent, then rebuild the same logical child from committed state.
                // Both the canonical root and the ops root must be independent of the parent's
                // pending state.
                let (db, _) = db.apply_batch(parent).await.unwrap();
                let db = db.commit().await.unwrap();

                let batch = apply_mutations(db.new_batch(), &input.child);
                let committed_child = rebuild(&db, batch, &input.child_plan, &child_walk).await;
                assert_batch_neighbors(&db, &committed_child, &model).await;
                assert_batch_neighbors(&db, &pending_child, &model).await;

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

                assert_recovers(&context, &test_name, db, &model).await;
            }
            Schedule::PendingChain => {
                // Build parent -> child -> grandchild with parent and child both pending, so
                // the grandchild's grafted layer overlays two live ancestor diffs on the
                // committed bitmap. This is the only schedule that checks a multi-diff
                // ancestor walk against a committed-only reference.
                let batch = apply_mutations(db.new_batch(), &input.parent);
                apply_to_model(&mut model, &input.parent);
                let floor = db.inactivity_floor_loc();
                let (parent, _) =
                    merkleize(&db, batch, floor, &input.parent_plan, &mut model).await;
                assert_batch_neighbors(&db, &parent, &model).await;
                let batch = apply_mutations(parent.new_batch::<Sha256>(), &input.child);
                apply_to_model(&mut model, &input.child);
                let floor = parent.bounds().inactivity_floor;
                let (child, _) = merkleize(&db, batch, floor, &input.child_plan, &mut model).await;
                assert_batch_neighbors(&db, &child, &model).await;
                let batch = apply_mutations(child.new_batch::<Sha256>(), &input.grandchild);
                apply_to_model(&mut model, &input.grandchild);
                let floor = child.bounds().inactivity_floor;
                let (pending_grandchild, grandchild_walk) =
                    merkleize(&db, batch, floor, &input.grandchild_plan, &mut model).await;
                assert_batch_neighbors(&db, &pending_grandchild, &model).await;

                let (db, _) = db.apply_batch(parent).await.unwrap();
                let db = db.commit().await.unwrap();
                let (db, _) = db.apply_batch(child).await.unwrap();
                let db = db.commit().await.unwrap();

                let batch = apply_mutations(db.new_batch(), &input.grandchild);
                let committed_grandchild =
                    rebuild(&db, batch, &input.grandchild_plan, &grandchild_walk).await;
                assert_batch_neighbors(&db, &committed_grandchild, &model).await;
                assert_batch_neighbors(&db, &pending_grandchild, &model).await;

                assert_eq!(
                    pending_grandchild.root(),
                    committed_grandchild.root(),
                    "current root depended on pending-vs-committed ancestor chain"
                );
                assert_eq!(
                    pending_grandchild.ops_root(),
                    committed_grandchild.ops_root(),
                    "current ops root depended on pending-vs-committed ancestor chain"
                );

                let (db, _) = db.apply_batch(pending_grandchild).await.unwrap();
                assert_eq!(
                    db.root(),
                    committed_grandchild.root(),
                    "pending grandchild canonical root diverged"
                );
                assert_eq!(
                    db.ops_root(),
                    committed_grandchild.ops_root(),
                    "pending grandchild ops root diverged"
                );

                assert_recovers(&context, &test_name, db, &model).await;
            }
            Schedule::DroppedPrefixChain => {
                // Build A -> B -> C, commit and drop A, then merkleize D on C: D's grafted
                // layer overlays two live ancestor diffs while base locations trace across the
                // dropped committed prefix. C reuses the parent mutations so the chain
                // re-deletes and re-creates the same colliding keys.
                let batch = apply_mutations(db.new_batch(), &input.parent);
                apply_to_model(&mut model, &input.parent);
                let floor = db.inactivity_floor_loc();
                let (a, _) = merkleize(&db, batch, floor, &input.parent_plan, &mut model).await;
                assert_batch_neighbors(&db, &a, &model).await;
                let batch = apply_mutations(a.new_batch::<Sha256>(), &input.child);
                apply_to_model(&mut model, &input.child);
                let floor = a.bounds().inactivity_floor;
                let (b, b_walk) = merkleize(&db, batch, floor, &input.child_plan, &mut model).await;
                assert_batch_neighbors(&db, &b, &model).await;
                let batch = apply_mutations(b.new_batch::<Sha256>(), &input.parent);
                apply_to_model(&mut model, &input.parent);
                let floor = b.bounds().inactivity_floor;
                let (c, c_walk) =
                    merkleize(&db, batch, floor, &input.parent_plan, &mut model).await;
                assert_batch_neighbors(&db, &c, &model).await;

                // Applying A consumes its last strong reference. B retains only a Weak parent.
                let (db, _) = db.apply_batch(a).await.unwrap();
                let db = db.commit().await.unwrap();

                let batch = apply_mutations(c.new_batch::<Sha256>(), &input.grandchild);
                apply_to_model(&mut model, &input.grandchild);
                let floor = c.bounds().inactivity_floor;
                let (retained_d, d_walk) =
                    merkleize(&db, batch, floor, &input.grandchild_plan, &mut model).await;
                assert_batch_neighbors(&db, &retained_d, &model).await;

                // Rebuild B -> C -> D from the committed A state as a reference.
                let batch = apply_mutations(db.new_batch(), &input.child);
                let rebuilt_b = rebuild(&db, batch, &input.child_plan, &b_walk).await;
                let batch = apply_mutations(rebuilt_b.new_batch::<Sha256>(), &input.parent);
                let rebuilt_c = rebuild(&db, batch, &input.parent_plan, &c_walk).await;
                let batch = apply_mutations(rebuilt_c.new_batch::<Sha256>(), &input.grandchild);
                let rebuilt_d = rebuild(&db, batch, &input.grandchild_plan, &d_walk).await;
                assert_batch_neighbors(&db, &rebuilt_d, &model).await;

                assert_eq!(
                    retained_d.root(),
                    rebuilt_d.root(),
                    "current root depended on a committed-and-dropped prefix"
                );
                assert_eq!(
                    retained_d.ops_root(),
                    rebuilt_d.ops_root(),
                    "current ops root depended on a committed-and-dropped prefix"
                );

                let (db, _) = db.apply_batch(retained_d).await.unwrap();
                assert_eq!(
                    db.root(),
                    rebuilt_d.root(),
                    "retained-chain canonical root diverged"
                );
                assert_eq!(
                    db.ops_root(),
                    rebuilt_d.ops_root(),
                    "retained-chain ops root diverged"
                );

                assert_recovers(&context, &test_name, db, &model).await;
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    match input.schedule {
        Schedule::PendingParent | Schedule::PendingChain => {
            fuzz_family::<mmr::Family>(&input, "fuzz-mmr-current-ordered-batch-root");
            fuzz_family::<mmb::Family>(&input, "fuzz-mmb-current-ordered-batch-root");
        }
        Schedule::DroppedPrefixChain => {
            fuzz_family::<mmr::Family>(&input, "fuzz-mmr-current-ordered-dropped-chain");
            fuzz_family::<mmb::Family>(&input, "fuzz-mmb-current-ordered-dropped-chain");
        }
    }
});
