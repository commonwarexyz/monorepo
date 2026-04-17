#![no_main]

//! Fuzz test for Current QMDB crash recovery with fault injection.
//!
//! Phase 1 runs state-changing operations (update, delete, commit, prune) with
//! injected write/sync failures, then "crashes". Phase 2 recovers from the
//! checkpoint and verifies that `init()` succeeds and the DB is usable.

use arbitrary::{Arbitrary, Result, Unstructured};
use commonware_cryptography::{Hasher as _, Sha256};
use commonware_runtime::{
    buffer::paged::CacheRef,
    deterministic::{self, Context},
    Metrics as _, Runner,
};
use commonware_storage::{
    journal::contiguous::variable::Config as VConfig,
    mmr::{self, journaled::Config as MmrConfig, Location},
    qmdb::current::{unordered::variable::Db as Current, VariableConfig},
    translator::TwoCap,
};
use commonware_utils::{sequence::FixedBytes, NZU64};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::HashMap,
    num::{NonZeroU16, NonZeroUsize},
};

type Key = FixedBytes<32>;
type Value = FixedBytes<32>;
type RawKey = [u8; 32];
type RawValue = [u8; 32];

/// Maximum write buffer size.
const MAX_WRITE_BUF: usize = 2048;

type Db = Current<mmr::Family, deterministic::Context, Key, Value, Sha256, TwoCap, 32>;

fn bounded_page_size(u: &mut Unstructured<'_>) -> Result<u16> {
    u.int_in_range(1..=256)
}

fn bounded_page_cache_size(u: &mut Unstructured<'_>) -> Result<usize> {
    u.int_in_range(1..=16)
}

fn bounded_items_per_blob(u: &mut Unstructured<'_>) -> Result<u64> {
    u.int_in_range(1..=64)
}

fn bounded_write_buffer(u: &mut Unstructured<'_>) -> Result<usize> {
    u.int_in_range(1..=MAX_WRITE_BUF)
}

fn bounded_nonzero_rate(u: &mut Unstructured<'_>) -> Result<f64> {
    let percent: u8 = u.int_in_range(1..=100)?;
    Ok(f64::from(percent) / 100.0)
}

/// State-changing operations that exercise disk writes.
#[derive(Arbitrary, Debug, Clone)]
enum CurrentOperation {
    Update { key: RawKey, value: RawValue },
    Delete { key: RawKey },
    Commit,
    Prune,
}

/// Fuzz input containing fault injection parameters and operations.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    seed: u64,
    #[arbitrary(with = bounded_page_size)]
    page_size: u16,
    #[arbitrary(with = bounded_page_cache_size)]
    page_cache_size: usize,
    #[arbitrary(with = bounded_items_per_blob)]
    mmr_items_per_blob: u64,
    #[arbitrary(with = bounded_items_per_blob)]
    log_items_per_blob: u64,
    #[arbitrary(with = bounded_write_buffer)]
    write_buffer: usize,
    #[arbitrary(with = bounded_nonzero_rate)]
    sync_failure_rate: f64,
    #[arbitrary(with = bounded_nonzero_rate)]
    write_failure_rate: f64,
    operations: Vec<CurrentOperation>,
}

fn make_config(
    ctx: &Context,
    suffix: &str,
    page_size: NonZeroU16,
    page_cache_size: NonZeroUsize,
    mmr_items_per_blob: u64,
    log_items_per_blob: u64,
    write_buffer: NonZeroUsize,
) -> VariableConfig<TwoCap, ((), ())> {
    let page_cache = CacheRef::from_pooler(ctx, page_size, page_cache_size);
    VariableConfig {
        merkle_config: MmrConfig {
            journal_partition: format!("crash-mmr-journal-{suffix}"),
            metadata_partition: format!("crash-mmr-metadata-{suffix}"),
            items_per_blob: NZU64!(mmr_items_per_blob),
            write_buffer,
            thread_pool: None,
            page_cache: page_cache.clone(),
        },
        journal_config: VConfig {
            partition: format!("crash-log-{suffix}"),
            items_per_section: NZU64!(log_items_per_blob),
            write_buffer,
            compression: None,
            codec_config: ((), ()),
            page_cache,
        },
        grafted_metadata_partition: format!("crash-grafted-mmr-metadata-{suffix}"),
        translator: TwoCap,
    }
}

/// Remove affected keys from committed since their recovered value is unknown.
fn forget_pending(
    pending: &HashMap<RawKey, Option<RawValue>>,
    committed: &mut HashMap<RawKey, RawValue>,
) {
    for key in pending.keys() {
        committed.remove(key);
    }
}

/// Merge pending changes into committed after a successful commit.
fn apply_pending(
    pending: &mut HashMap<RawKey, Option<RawValue>>,
    committed: &mut HashMap<RawKey, RawValue>,
) {
    for (k, v) in pending.drain() {
        match v {
            Some(val) => {
                committed.insert(k, val);
            }
            None => {
                committed.remove(&k);
            }
        }
    }
}

/// Commit pending writes. Returns `true` on success, `false` on error.
async fn commit_pending(
    db: &mut Db,
    pending_writes: &mut Vec<(Key, Option<Value>)>,
    pending: &mut HashMap<RawKey, Option<RawValue>>,
    committed: &mut HashMap<RawKey, RawValue>,
) -> bool {
    let mut batch = db.new_batch();
    for (k, v) in pending_writes.drain(..) {
        batch = batch.write(k, v);
    }
    let merkleized = match batch.merkleize(db, None).await {
        Ok(m) => m,
        Err(_) => {
            forget_pending(pending, committed);
            return false;
        }
    };
    let result = db.apply_batch(merkleized).await;
    if result.is_err() {
        forget_pending(pending, committed);
        return false;
    }
    if db.commit().await.is_err() {
        forget_pending(pending, committed);
        return false;
    }
    apply_pending(pending, committed);
    true
}

fn fuzz(input: FuzzInput) {
    if input.operations.is_empty() {
        return;
    }

    let page_size = NonZeroU16::new(input.page_size).unwrap();
    let page_cache_size = NonZeroUsize::new(input.page_cache_size).unwrap();
    let mmr_items_per_blob = input.mmr_items_per_blob;
    let log_items_per_blob = input.log_items_per_blob;
    let write_buffer = NonZeroUsize::new(input.write_buffer).unwrap();
    let sync_failure_rate = input.sync_failure_rate;
    let write_failure_rate = input.write_failure_rate;
    let operations = input.operations;
    let suffix = format!("current_{}", input.seed);

    let cfg = deterministic::Config::default().with_seed(input.seed);
    let runner = deterministic::Runner::new(cfg);

    // Phase 1: Execute operations with fault injection until crash.
    // Track committed KV state so we can verify it survives recovery.
    let (committed, checkpoint) = runner.start_and_recover(|ctx| {
        let suffix = suffix.clone();
        let operations = operations.clone();
        async move {
            let mut db = Db::init(
                ctx.with_label("db"),
                make_config(
                    &ctx,
                    &suffix,
                    page_size,
                    page_cache_size,
                    mmr_items_per_blob,
                    log_items_per_blob,
                    write_buffer,
                ),
            )
            .await
            .unwrap();

            let fault_cfg = ctx.storage_fault_config();
            *fault_cfg.write() = deterministic::FaultConfig {
                sync_rate: Some(sync_failure_rate),
                write_rate: Some(write_failure_rate),
                ..Default::default()
            };

            // Active KV pairs after the last successful commit.
            let mut committed: HashMap<RawKey, RawValue> = HashMap::new();
            // Uncommitted changes since the last commit. None = delete, Some = upsert.
            let mut pending: HashMap<RawKey, Option<RawValue>> = HashMap::new();

            // Accumulate writes until Commit, matching the intended
            // pending/committed separation.
            let mut pending_writes: Vec<(Key, Option<Value>)> = Vec::new();

            for op in &operations {
                match op {
                    CurrentOperation::Update { key, value } => {
                        pending_writes.push((Key::new(*key), Some(Value::new(*value))));
                        pending.insert(*key, Some(*value));
                    }
                    CurrentOperation::Delete { key } => {
                        pending_writes.push((Key::new(*key), None));
                        pending.insert(*key, None);
                    }
                    CurrentOperation::Commit => {
                        if !commit_pending(
                            &mut db,
                            &mut pending_writes,
                            &mut pending,
                            &mut committed,
                        )
                        .await
                        {
                            break;
                        }
                    }
                    CurrentOperation::Prune => {
                        if !commit_pending(
                            &mut db,
                            &mut pending_writes,
                            &mut pending,
                            &mut committed,
                        )
                        .await
                        {
                            break;
                        }
                        let Ok(boundary) = db.sync_boundary() else {
                            break;
                        };
                        if db.prune(boundary).await.is_err() {
                            break;
                        }
                    }
                }
            }

            committed
        }
    });

    // Phase 2: Recover and verify consistency.
    let runner = deterministic::Runner::from(checkpoint);
    runner.start(|ctx| {
        let suffix = suffix.clone();
        async move {
            *ctx.storage_fault_config().write() = deterministic::FaultConfig::default();

            let mut db = Db::init(
                ctx.with_label("recovered"),
                make_config(
                    &ctx,
                    &suffix,
                    page_size,
                    page_cache_size,
                    mmr_items_per_blob,
                    log_items_per_blob,
                    write_buffer,
                ),
            )
            .await
            .expect("recovery must succeed");

            let mut hasher = Sha256::new();

            // Verify all committed KV pairs survived the crash and are provable.
            let root = db.root();
            for (key, value) in &committed {
                let k = Key::new(*key);
                let v = Value::new(*value);

                let result = db.get(&k).await.expect("get should not fail");
                assert_eq!(
                    result,
                    Some(v.clone()),
                    "committed KV pair lost after crash recovery"
                );

                let proof = db
                    .key_value_proof(&mut hasher, k.clone())
                    .await
                    .expect("proof generation should not fail for committed key");
                assert!(
                    Db::verify_key_value_proof(&mut hasher, k, v, &proof, &root),
                    "key value proof failed to verify after crash recovery"
                );
            }

            // Verify range proofs over the recovered DB.
            let floor = *db
                .sync_boundary()
                .expect("sync_boundary should not overflow");
            let size = *db.bounds().await.end;
            for i in floor..size {
                let loc = Location::new(i);
                let (proof, ops, chunks) = db
                    .range_proof(&mut hasher, loc, NZU64!(4))
                    .await
                    .expect("range proof should not fail after recovery");
                assert!(
                    Db::verify_range_proof(&mut hasher, &proof, loc, &ops, &chunks, &root),
                    "range proof failed to verify after crash recovery at loc {loc}"
                );
            }

            // Verify the recovered DB is usable.
            let test_key = Key::new([0xAB; 32]);
            let test_value = Value::new([0xCD; 32]);
            let batch = db
                .new_batch()
                .write(test_key, Some(test_value))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(batch)
                .await
                .expect("apply_batch after recovery should succeed");
            db.commit()
                .await
                .expect("commit after recovery should succeed");

            db.destroy()
                .await
                .expect("destroy after recovery should succeed");
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
