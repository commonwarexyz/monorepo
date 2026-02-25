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
    mmr::Location,
    qmdb::{
        current::{unordered::variable::Db as Current, VariableConfig},
        store::LogStore as _,
    },
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

type CleanDb = Current<deterministic::Context, Key, Value, Sha256, TwoCap, 32>;

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
) -> VariableConfig<TwoCap, ()> {
    VariableConfig {
        mmr_journal_partition: format!("crash-mmr-journal-{suffix}"),
        mmr_metadata_partition: format!("crash-mmr-metadata-{suffix}"),
        mmr_items_per_blob: NZU64!(mmr_items_per_blob),
        mmr_write_buffer: write_buffer,
        log_partition: format!("crash-log-{suffix}"),
        log_items_per_blob: NZU64!(log_items_per_blob),
        log_write_buffer: write_buffer,
        log_compression: None,
        log_codec_config: (),
        grafted_mmr_metadata_partition: format!("crash-grafted-mmr-metadata-{suffix}"),
        translator: TwoCap,
        page_cache: CacheRef::from_pooler(ctx, page_size, page_cache_size),
        thread_pool: None,
    }
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
            let db = CleanDb::init(
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
            // Uncommitted changes since the last commit. None = delete, Some = update.
            let mut pending: HashMap<RawKey, Option<RawValue>> = HashMap::new();

            let mut db = Some(db.into_mutable());

            for op in &operations {
                let Some(mut current) = db.take() else {
                    break;
                };

                match op {
                    CurrentOperation::Update { key, value } => {
                        let k = Key::new(*key);
                        let v = Value::new(*value);
                        if current.write_batch([(k, Some(v))]).await.is_err() {
                            break;
                        }
                        pending.insert(*key, Some(*value));
                        db = Some(current);
                    }
                    CurrentOperation::Delete { key } => {
                        let k = Key::new(*key);
                        if current.write_batch([(k, None)]).await.is_err() {
                            break;
                        }
                        pending.insert(*key, None);
                        db = Some(current);
                    }
                    CurrentOperation::Commit => {
                        let Ok((durable_db, _)) = current.commit(None).await else {
                            // A failed commit may have partially persisted
                            // pending operations.
                            // Remove affected keys from committed since their
                            // recovered value is unknown.
                            for key in pending.keys() {
                                committed.remove(key);
                            }
                            break;
                        };
                        // Data is durable. Merge pending into committed.
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
                        let Ok(clean_db) = durable_db.into_merkleized().await else {
                            break;
                        };
                        db = Some(clean_db.into_mutable());
                    }
                    CurrentOperation::Prune => {
                        let Ok(mut merkleized_db) = current.into_merkleized().await else {
                            break;
                        };
                        let floor = merkleized_db.inactivity_floor_loc();
                        if merkleized_db.prune(floor).await.is_err() {
                            break;
                        }
                        db = Some(merkleized_db.into_mutable());
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

            let db = CleanDb::init(
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
            let root = db.root().expect("root should be available after init");
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
                    CleanDb::verify_key_value_proof(&mut hasher, k, v, &proof, &root),
                    "key value proof failed to verify after crash recovery"
                );
            }

            // Verify range proofs over the recovered DB.
            let floor = *db.inactivity_floor_loc();
            let size = *db.size().await;
            for i in floor..size {
                let loc = Location::new(i).unwrap();
                let (proof, ops, chunks) = db
                    .range_proof(&mut hasher, loc, NZU64!(4))
                    .await
                    .expect("range proof should not fail after recovery");
                assert!(
                    CleanDb::verify_range_proof(&mut hasher, &proof, loc, &ops, &chunks, &root),
                    "range proof failed to verify after crash recovery at loc {loc}"
                );
            }

            // Verify the recovered DB is usable.
            let mut db = db.into_mutable();
            let test_key = Key::new([0xAB; 32]);
            let test_value = Value::new([0xCD; 32]);
            db.write_batch([(test_key, Some(test_value))])
                .await
                .expect("write_batch after recovery should succeed");

            let (durable_db, _) = db
                .commit(None)
                .await
                .expect("commit after recovery should succeed");
            let clean_db = durable_db
                .into_merkleized()
                .await
                .expect("merkleize after recovery should succeed");

            clean_db
                .destroy()
                .await
                .expect("destroy after recovery should succeed");
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
