#![no_main]

//! Focused fuzzer for Current QMDB prune/grow divergence under MMB Merkle family. The test is MMB
//! specific since grafted MMR root witnesses are stable as the tree grows.
//!
//! This target intentionally avoids proof generation and broader API coverage. It concentrates on
//! the narrow state shape that previously caused canonical root drift in live pruned MMB state:
//! deterministically bootstrap into a pruned state, then force a short post-prune growth window
//! with root comparisons after every commit. That keeps the corpus focused on the delayed-settle
//! region without relying on libFuzzer to randomly discover the first successful prune. It also
//! performs pruned-side close/reopen steps, because this bug family is especially interesting when
//! compacted grafted state must survive a metadata round-trip without changing the canonical root.

use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Metrics as _, Runner};
use commonware_storage::{
    journal::contiguous::fixed::Config as FConfig,
    merkle::{journaled::Config as MerkleConfig, mmb},
    qmdb::current::{unordered::fixed::Db as CurrentDb, BitmapPrunedBits, FixedConfig as Config},
    translator::TwoCap,
};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU16, NZU64};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::{HashMap, HashSet},
    num::NonZeroU16,
};

// We use a tiny keyspace to ensure plenty of key updates, which force floor raising.
type Key = FixedBytes<1>;
type Value = FixedBytes<32>;
type LogicalKey = u8;
type RawValue = [u8; 32];
type Db = CurrentDb<mmb::Family, deterministic::Context, Key, Value, Sha256, TwoCap, 32>;

#[derive(Arbitrary, Debug, Clone)]
enum CurrentOperation {
    Update {
        #[arbitrary(with = bounded_logical_key)]
        key: LogicalKey,
        value: RawValue,
    },
    UpdateBurst {
        #[arbitrary(with = bounded_logical_key)]
        key: LogicalKey,
        value: RawValue,
        #[arbitrary(with = bounded_burst_count)]
        count: u8,
    },
    Delete {
        #[arbitrary(with = bounded_logical_key)]
        key: LogicalKey,
    },
    DeleteBurst {
        #[arbitrary(with = bounded_logical_key)]
        key: LogicalKey,
        #[arbitrary(with = bounded_burst_count)]
        count: u8,
    },
    Commit,
    CloseReopen,
    Root,
}

const MAX_OPERATIONS: usize = 100;
const MAX_ACTUAL_WRITES: usize = 64;
const LOGICAL_KEY_SPACE: u8 = 8;
const POST_PRUNE_WINDOW_STEPS: u8 = 127;

// With SHA-256, N=32 means one bitmap chunk covers 256 ops. Bootstrap commits one hot-key mutation
// at a time, so we intentionally go comfortably past one full chunk before expecting the inactivity
// floor to advance into genuinely pruned territory. The extra 64 commits are deterministic
// headroom.
const BOOTSTRAP_COMMITS: u16 = 320;

#[derive(Debug, Clone)]
struct FuzzInput {
    operations: Vec<CurrentOperation>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let num_ops = u.int_in_range(1..=MAX_OPERATIONS)?;
        let operations = (0..num_ops)
            .map(|_| CurrentOperation::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(FuzzInput { operations })
    }
}

fn bounded_burst_count(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<u8> {
    u.int_in_range(1..=8)
}

fn bounded_logical_key(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<LogicalKey> {
    u.int_in_range(0..=(LOGICAL_KEY_SPACE - 1))
}

fn encode_key(key: LogicalKey) -> Key {
    Key::new([key])
}

fn burst_key(key: LogicalKey, offset: u8) -> LogicalKey {
    let span = u16::from(LOGICAL_KEY_SPACE);
    let sum = u16::from(key) + u16::from(offset);
    let reduced = sum % span;
    reduced as u8
}

fn burst_value(mut value: RawValue, offset: u8) -> RawValue {
    value[31] = value[31].wrapping_add(offset);
    value
}

fn expected_value_for_key(
    key: LogicalKey,
    committed_state: &HashMap<LogicalKey, Option<RawValue>>,
    pending_expected: &HashMap<LogicalKey, Option<RawValue>>,
) -> Option<RawValue> {
    match pending_expected.get(&key).copied() {
        Some(value) => value,
        None => committed_state.get(&key).copied().flatten(),
    }
}

fn find_live_key(
    preferred: LogicalKey,
    committed_state: &HashMap<LogicalKey, Option<RawValue>>,
    pending_expected: &HashMap<LogicalKey, Option<RawValue>>,
) -> Option<LogicalKey> {
    for offset in 0..LOGICAL_KEY_SPACE {
        let candidate = burst_key(preferred, offset);
        if expected_value_for_key(candidate, committed_state, pending_expected).is_some() {
            return Some(candidate);
        }
    }
    None
}

const PAGE_SIZE: NonZeroU16 = NZU16!(88);
const PAGE_CACHE_SIZE: usize = 2;
const MERKLE_ITEMS_PER_BLOB: u64 = 11;
const LOG_ITEMS_PER_BLOB: u64 = 7;
const WRITE_BUFFER_SIZE: usize = 1024;

fn test_config(name: &str, page_cache: CacheRef) -> Config<TwoCap> {
    Config {
        merkle_config: MerkleConfig {
            journal_partition: format!("fuzz-current-mmb-pruning-{name}-merkle-journal"),
            metadata_partition: format!("fuzz-current-mmb-pruning-{name}-merkle-metadata"),
            items_per_blob: NZU64!(MERKLE_ITEMS_PER_BLOB),
            write_buffer: NZUsize!(WRITE_BUFFER_SIZE),
            thread_pool: None,
            page_cache: page_cache.clone(),
        },
        journal_config: FConfig {
            partition: format!("fuzz-current-mmb-pruning-{name}-log-journal"),
            items_per_blob: NZU64!(LOG_ITEMS_PER_BLOB),
            write_buffer: NZUsize!(WRITE_BUFFER_SIZE),
            page_cache,
        },
        grafted_metadata_partition: format!("fuzz-current-mmb-pruning-{name}-grafted-metadata"),
        translator: TwoCap,
    }
}

async fn apply_pending(db: &mut Db, writes: &[(Key, Option<Value>)]) {
    let mut batch = db.new_batch();
    for (key, value) in writes.iter().cloned() {
        batch = batch.write(key, value);
    }
    let merkleized = batch.merkleize(db, None).await.unwrap();
    db.apply_batch(merkleized)
        .await
        .expect("commit should not fail");
    db.commit().await.expect("commit fsync should not fail");
}

async fn assert_matches_reference(db: &Db, reference_db: &Db, context: &str) {
    assert_eq!(
        db.bounds().await.end,
        reference_db.bounds().await.end,
        "op count mismatch after {context}"
    );
    assert_eq!(
        db.ops_root(),
        reference_db.ops_root(),
        "ops root mismatch after {context}"
    );
    assert_eq!(
        db.root(),
        reference_db.root(),
        "canonical root mismatch after {context}"
    );
}

async fn commit_pending(
    db: &mut Db,
    reference_db: &mut Db,
    pending_writes: &mut Vec<(Key, Option<Value>)>,
    committed_state: &mut HashMap<LogicalKey, Option<RawValue>>,
    pending_expected: &mut HashMap<LogicalKey, Option<RawValue>>,
) {
    if pending_writes.is_empty() {
        assert_matches_reference(db, reference_db, "empty commit").await;
        return;
    }

    let writes = std::mem::take(pending_writes);
    apply_pending(db, &writes).await;
    apply_pending(reference_db, &writes).await;
    committed_state.extend(pending_expected.drain());
    assert_matches_reference(db, reference_db, "commit").await;
}

async fn prune_to_floor(db: &mut Db, reference_db: &Db, context: &str) {
    let boundary = db
        .sync_boundary()
        .expect("sync_boundary should not overflow");
    db.prune(boundary).await.expect("prune should not fail");
    assert_matches_reference(db, reference_db, context).await;
}

async fn reopen_pruned_db(
    db: Db,
    context: &deterministic::Context,
    config: &Config<TwoCap>,
    reference_db: &Db,
    reopen_count: usize,
) -> Db {
    let root_before = db.root();
    let ops_root_before = db.ops_root();
    let bounds_before = db.bounds().await;
    let pruned_bits_before = db.pruned_bits();
    drop(db);

    let reopen_label = format!("pruned_reopen_{reopen_count}");
    let reopen_context = context.with_label(&reopen_label);
    let reopened = Db::init(reopen_context, config.clone())
        .await
        .expect("reopen pruned current db");
    assert_eq!(
        reopened.root(),
        root_before,
        "canonical root changed after reopen"
    );
    assert_eq!(
        reopened.ops_root(),
        ops_root_before,
        "ops root changed after reopen"
    );
    assert_eq!(
        reopened.bounds().await,
        bounds_before,
        "bounds changed after reopen"
    );
    assert_eq!(
        reopened.pruned_bits(),
        pruned_bits_before,
        "pruned bits changed after reopen"
    );
    assert_matches_reference(&reopened, reference_db, "reopen").await;
    reopened
}

async fn bootstrap_pruned_state(
    db: &mut Db,
    reference_db: &mut Db,
    committed_state: &mut HashMap<LogicalKey, Option<RawValue>>,
    pending_expected: &mut HashMap<LogicalKey, Option<RawValue>>,
    all_keys: &mut HashSet<LogicalKey>,
) {
    // `step as u8` intentionally wraps for step >= 256; uniqueness is not required here,
    // we just need to drive the inactivity floor forward.
    for step in 0..BOOTSTRAP_COMMITS {
        let key = (step as u8) % LOGICAL_KEY_SPACE;
        let mut value = [0u8; 32];
        value[0] = 0xB0;
        value[1] = step as u8;
        value[31] = key;
        let mut pending_writes = vec![(encode_key(key), Some(Value::new(value)))];
        pending_expected.insert(key, Some(value));
        all_keys.insert(key);
        commit_pending(
            db,
            reference_db,
            &mut pending_writes,
            committed_state,
            pending_expected,
        )
        .await;
        prune_to_floor(db, reference_db, "bootstrap").await;
        if db.pruned_bits() > 0 {
            return;
        }
    }
    panic!("bootstrap should create a genuinely pruned state");
}

struct ReopenEnv<'a> {
    context: &'a deterministic::Context,
    config: &'a Config<TwoCap>,
    count: &'a mut usize,
}

async fn drive_post_prune_window(
    mut db: Db,
    reference_db: &mut Db,
    committed_state: &mut HashMap<LogicalKey, Option<RawValue>>,
    pending_expected: &mut HashMap<LogicalKey, Option<RawValue>>,
    all_keys: &mut HashSet<LogicalKey>,
    reopen: &mut ReopenEnv<'_>,
) -> Db {
    let midpoint = POST_PRUNE_WINDOW_STEPS / 2;
    for step in 0..POST_PRUNE_WINDOW_STEPS {
        let key = step % LOGICAL_KEY_SPACE;
        let current_value = expected_value_for_key(key, committed_state, pending_expected);
        let write = if current_value.is_some() && step % 2 == 1 {
            (encode_key(key), None)
        } else {
            let mut value = [0u8; 32];
            value[0] = step;
            value[31] = key;
            pending_expected.insert(key, Some(value));
            (encode_key(key), Some(Value::new(value)))
        };

        if write.1.is_none() {
            pending_expected.insert(key, None);
        }
        all_keys.insert(key);

        let mut writes = vec![write];
        commit_pending(
            &mut db,
            reference_db,
            &mut writes,
            committed_state,
            pending_expected,
        )
        .await;
        prune_to_floor(&mut db, reference_db, "forced-post-prune-window").await;

        // Reopen midway through the window to exercise the metadata round-trip while
        // delayed merges are still in progress.
        if step == midpoint {
            *reopen.count += 1;
            db = reopen_pruned_db(
                db,
                reopen.context,
                reopen.config,
                reference_db,
                *reopen.count,
            )
            .await;
        }
    }
    db
}

fn fuzz(data: FuzzInput) {
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let pruned_context = context.with_label("pruned");
        let pruned_cache =
            CacheRef::from_pooler(&pruned_context, PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE));
        let pruned_config = test_config("pruned", pruned_cache);
        let mut db = Db::init(pruned_context, pruned_config.clone())
            .await
            .expect("init pruned current db");

        let reference_context = context.with_label("reference");
        let reference_cache =
            CacheRef::from_pooler(&reference_context, PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE));
        let mut reference_db =
            Db::init(reference_context, test_config("reference", reference_cache))
                .await
                .expect("init reference current db");

        let mut committed_state: HashMap<LogicalKey, Option<RawValue>> = HashMap::new();
        let mut pending_expected: HashMap<LogicalKey, Option<RawValue>> = HashMap::new();
        let mut all_keys = HashSet::new();
        let mut pending_writes: Vec<(Key, Option<Value>)> = Vec::new();
        let mut issued_writes = 0usize;
        let mut forced_window_ran = false;
        let mut reopen_env = ReopenEnv {
            context: &context,
            config: &pruned_config,
            count: &mut 0usize,
        };

        bootstrap_pruned_state(
            &mut db,
            &mut reference_db,
            &mut committed_state,
            &mut pending_expected,
            &mut all_keys,
        )
        .await;

        for op in &data.operations {
            match op {
                CurrentOperation::Update { key, value } => {
                    if issued_writes >= MAX_ACTUAL_WRITES {
                        continue;
                    }
                    pending_writes.push((encode_key(*key), Some(Value::new(*value))));
                    pending_expected.insert(*key, Some(*value));
                    all_keys.insert(*key);
                    issued_writes += 1;
                }
                CurrentOperation::UpdateBurst { key, value, count } => {
                    for offset in 0..*count {
                        if issued_writes >= MAX_ACTUAL_WRITES {
                            break;
                        }
                        let derived_key = burst_key(*key, offset);
                        let derived_value = burst_value(*value, offset);
                        pending_writes
                            .push((encode_key(derived_key), Some(Value::new(derived_value))));
                        pending_expected.insert(derived_key, Some(derived_value));
                        all_keys.insert(derived_key);
                        issued_writes += 1;
                    }
                }
                CurrentOperation::Delete { key } => {
                    if issued_writes >= MAX_ACTUAL_WRITES {
                        continue;
                    }
                    let Some(live_key) = find_live_key(*key, &committed_state, &pending_expected)
                    else {
                        continue;
                    };
                    pending_writes.push((encode_key(live_key), None));
                    pending_expected.insert(live_key, None);
                    all_keys.insert(live_key);
                    issued_writes += 1;
                }
                CurrentOperation::DeleteBurst { key, count } => {
                    for offset in 0..*count {
                        if issued_writes >= MAX_ACTUAL_WRITES {
                            break;
                        }
                        let preferred = burst_key(*key, offset);
                        let Some(live_key) =
                            find_live_key(preferred, &committed_state, &pending_expected)
                        else {
                            break;
                        };
                        pending_writes.push((encode_key(live_key), None));
                        pending_expected.insert(live_key, None);
                        all_keys.insert(live_key);
                        issued_writes += 1;
                    }
                }
                CurrentOperation::Commit | CurrentOperation::Root => {
                    commit_pending(
                        &mut db,
                        &mut reference_db,
                        &mut pending_writes,
                        &mut committed_state,
                        &mut pending_expected,
                    )
                    .await;
                    prune_to_floor(&mut db, &reference_db, "commit+prune").await;
                    if db.pruned_bits() > 0 && !forced_window_ran {
                        forced_window_ran = true;
                        db = drive_post_prune_window(
                            db,
                            &mut reference_db,
                            &mut committed_state,
                            &mut pending_expected,
                            &mut all_keys,
                            &mut reopen_env,
                        )
                        .await;
                    }
                }
                CurrentOperation::CloseReopen => {
                    commit_pending(
                        &mut db,
                        &mut reference_db,
                        &mut pending_writes,
                        &mut committed_state,
                        &mut pending_expected,
                    )
                    .await;
                    prune_to_floor(&mut db, &reference_db, "close-reopen-prep").await;
                    *reopen_env.count += 1;
                    db = reopen_pruned_db(
                        db,
                        reopen_env.context,
                        reopen_env.config,
                        &reference_db,
                        *reopen_env.count,
                    )
                    .await;
                }
            }
        }

        if !pending_writes.is_empty() {
            commit_pending(
                &mut db,
                &mut reference_db,
                &mut pending_writes,
                &mut committed_state,
                &mut pending_expected,
            )
            .await;
        }

        prune_to_floor(&mut db, &reference_db, "final").await;
        assert_eq!(
            db.bounds().await.end,
            reference_db.bounds().await.end,
            "final op count mismatch"
        );

        for key in &all_keys {
            let k = encode_key(*key);
            let result = db.get(&k).await.expect("final get should not fail");
            let reference_result = reference_db
                .get(&k)
                .await
                .expect("reference final get should not fail");
            assert_eq!(
                result, reference_result,
                "final get diverged for key {key:?}"
            );

            match committed_state.get(key) {
                Some(Some(expected_value)) => {
                    assert!(result.is_some(), "Lost value for key {key:?} at end");
                    let actual_value = result.expect("Should have value");
                    let actual_bytes: &[u8; 32] = actual_value
                        .as_ref()
                        .try_into()
                        .expect("Value should be 32 bytes");
                    assert_eq!(
                        actual_bytes, expected_value,
                        "Final value mismatch for key {key:?}"
                    );
                }
                Some(None) => {
                    assert!(
                        result.is_none(),
                        "Deleted key {key:?} should remain deleted"
                    );
                }
                None => {
                    assert!(result.is_none(), "Unset key {key:?} should not exist");
                }
            }
        }

        db.destroy().await.expect("destroy should not fail");
        reference_db
            .destroy()
            .await
            .expect("reference destroy should not fail");
    });
}

fuzz_target!(|input: FuzzInput| fuzz(input));
