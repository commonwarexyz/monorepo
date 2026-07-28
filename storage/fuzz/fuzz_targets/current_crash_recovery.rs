#![no_main]

//! Fuzz test for Current QMDB crash recovery with fault injection.
//!
//! Phase 1 runs state-changing operations with injected write/sync failures,
//! then "crashes". Phase 2 recovers and commits a sentinel, and phase 3 crosses
//! another crash boundary to verify the concrete recovered state.

use arbitrary::{Arbitrary, Result, Unstructured};
use commonware_cryptography::{Hasher, Sha256};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Runner, Supervisor as _,
    buffer::paged::CacheRef,
    deterministic::{self, Context},
};
use commonware_storage::{
    journal::contiguous::variable::Config as VConfig,
    merkle::{Graftable, Location, full::Config as MerkleConfig, mmb, mmr},
    qmdb::{
        current::{VariableConfig, unordered::variable::Db as Current},
        verify_proof,
    },
    translator::TwoCap,
};
use commonware_storage_fuzz::{
    RNG_BYTES, bounded_items_per_section, bounded_page_cache_size, bounded_page_size, bounded_rate,
    fuzz_runner, interrupt_faults,
};
use commonware_utils::{NZU64, NZUsize, sequence::FixedBytes};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::BTreeMap,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
};

type Key = FixedBytes<32>;
type Value = FixedBytes<32>;
type RawKey = [u8; 32];
type RawValue = [u8; 32];

/// Maximum write buffer size.
const MAX_WRITE_BUF: usize = 2048;

/// Maximum number of operations per fuzz input.
const MAX_OPERATIONS: usize = 128;

/// Smallest valid bitmap chunk size for SHA-256.
const BITMAP_CHUNK_BYTES: usize = 32;

/// Batches and keys needed to put MMB beyond its first absorbed chunk pair.
const PRUNE_PREP_ROUNDS: usize = 24;
const PRUNE_PREP_KEYS: usize = 32;

type Db<F> =
    Current<F, deterministic::Context, Key, Value, Sha256, TwoCap, BITMAP_CHUNK_BYTES, Sequential>;

fn bounded_write_buffer(u: &mut Unstructured<'_>) -> Result<usize> {
    u.int_in_range(1..=MAX_WRITE_BUF)
}

fn bounded_operations(u: &mut Unstructured<'_>) -> Result<Vec<CurrentOperation>> {
    let count = u.int_in_range(0..=MAX_OPERATIONS)?;
    (0..count).map(|_| CurrentOperation::arbitrary(u)).collect()
}

/// State-changing operations that exercise disk writes.
#[derive(Arbitrary, Debug, Clone)]
enum CurrentOperation {
    Update {
        key: RawKey,
        value: RawValue,
    },
    Delete {
        key: RawKey,
    },
    /// Apply pending changes to storage and crash before committing them.
    Apply,
    Commit,
    Prune {
        selector: u8,
    },
}

/// Fuzz input containing fault injection parameters and operations.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Fuzzer-controlled randomness for deterministic runtime choices.
    raw_bytes: [u8; RNG_BYTES],
    /// Select the MMB family instead of MMR without changing runtime randomness.
    mmb: bool,
    /// Enable the variable journal's minimal useful compression level.
    compression: bool,
    #[arbitrary(with = bounded_page_size)]
    page_size: u16,
    #[arbitrary(with = bounded_page_cache_size)]
    page_cache_size: usize,
    #[arbitrary(with = bounded_items_per_section)]
    merkle_items_per_blob: u64,
    #[arbitrary(with = bounded_items_per_section)]
    log_items_per_blob: u64,
    #[arbitrary(with = bounded_write_buffer)]
    write_buffer: usize,
    #[arbitrary(with = bounded_rate)]
    sync_failure_rate: f64,
    #[arbitrary(with = bounded_rate)]
    write_failure_rate: f64,
    #[arbitrary(with = bounded_operations)]
    operations: Vec<CurrentOperation>,
}

#[derive(Clone, Copy)]
struct Params {
    page_size: NonZeroU16,
    page_cache_size: NonZeroUsize,
    merkle_items_per_blob: u64,
    log_items_per_blob: u64,
    compression: bool,
    write_buffer: NonZeroUsize,
}

fn make_config(
    ctx: &Context,
    suffix: &str,
    params: Params,
) -> VariableConfig<TwoCap, ((), ()), Sequential> {
    let page_cache = CacheRef::from_pooler(ctx, params.page_size, params.page_cache_size);
    VariableConfig {
        merkle_config: MerkleConfig {
            journal_partition: format!("crash-merkle-journal-{suffix}"),
            metadata_partition: format!("crash-merkle-metadata-{suffix}"),
            items_per_blob: NZU64!(params.merkle_items_per_blob),
            write_buffer: params.write_buffer,
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        journal_config: VConfig {
            partition: format!("crash-log-{suffix}"),
            items_per_section: NZU64!(params.log_items_per_blob),
            write_buffer: params.write_buffer,
            compression: params.compression.then_some(3),
            codec_config: ((), ()),
            page_cache,
        },
        grafted_metadata_partition: format!("crash-grafted-merkle-metadata-{suffix}"),
        translator: TwoCap,
        init_cache_size: Some(NZUsize!(3)),
        init_buffer: NZUsize!(1 << 21),
        init_concurrency: (),
    }
}

type State = BTreeMap<RawKey, Option<RawValue>>;
type Root = <Sha256 as Hasher>::Digest;

#[derive(Clone)]
struct Snapshot {
    state: State,
    root: Root,
    min_start: u64,
    max_start: u64,
    end: u64,
    sync_boundary: u64,
}

impl Snapshot {
    fn from_db<F: Graftable>(db: &Db<F>, state: State) -> Self {
        let bounds = db.bounds();
        Self {
            state,
            root: db.root(),
            min_start: bounds.start.as_u64(),
            max_start: bounds.start.as_u64(),
            end: bounds.end.as_u64(),
            sync_boundary: db.sync_boundary().as_u64(),
        }
    }
}

#[derive(Clone)]
enum Expected {
    Exact(Snapshot),
    Either { old: Snapshot, new: Snapshot },
}

fn apply_pending_model(pending: &mut State, state: &mut State) {
    state.append(pending);
}

fn prospective_state(pending: &State, expected: &Expected) -> State {
    let Expected::Exact(snapshot) = expected else {
        unreachable!("operations stop after state becomes uncertain")
    };
    let mut state = snapshot.state.clone();
    state.extend(pending.clone());
    state
}

fn commit_pending_model<F: Graftable>(pending: &mut State, expected: &mut Expected, db: &Db<F>) {
    let Expected::Exact(snapshot) = expected else {
        unreachable!("operations stop after state becomes uncertain")
    };
    let mut state = std::mem::take(&mut snapshot.state);
    apply_pending_model(pending, &mut state);
    *snapshot = Snapshot::from_db(db, state);
}

fn mark_pending_uncertain(pending: &mut State, expected: &mut Expected, new: Snapshot) {
    let Expected::Exact(old) = expected else {
        unreachable!("operations stop after state becomes uncertain")
    };
    pending.clear();
    if old.root != new.root || old.end != new.end {
        *expected = Expected::Either {
            old: old.clone(),
            new,
        };
    }
}

/// Commit pending writes. Returns the db on success; `None` on error (the db
/// is dropped, simulating a crash).
async fn commit_pending<F: Graftable>(
    db: Db<F>,
    pending_writes: &mut Vec<(Key, Option<Value>)>,
    pending: &mut State,
    expected: &mut Expected,
) -> Option<Db<F>> {
    if pending_writes.is_empty() {
        return db.commit().await.ok();
    }

    let mut batch = db.new_batch();
    for (k, v) in pending_writes.drain(..) {
        batch = batch.write(k, v);
    }
    let merkleized = match batch.merkleize(&db, None).await {
        Ok(m) => m,
        Err(_) => return None,
    };
    let start = db.bounds().start.as_u64();
    let prospective = Snapshot {
        state: prospective_state(pending, expected),
        root: merkleized.root(),
        min_start: start,
        max_start: start,
        end: merkleized.bounds().total_size,
        sync_boundary: merkleized.sync_boundary().as_u64(),
    };
    let db = match db.apply_batch(merkleized).await {
        Ok((db, _)) => db,
        Err(_) => {
            mark_pending_uncertain(pending, expected, prospective);
            return None;
        }
    };
    let prospective = Snapshot::from_db(&db, prospective.state);
    let db = match db.commit().await {
        Ok(db) => db,
        Err(_) => {
            mark_pending_uncertain(pending, expected, prospective);
            return None;
        }
    };
    pending.clear();
    *expected = Expected::Exact(Snapshot::from_db(&db, prospective.state));
    Some(db)
}

fn prune_prep_key(index: usize) -> RawKey {
    let mut key = [0xFF; 32];
    key[31] = index as u8;
    key
}

fn prune_prep_value(round: usize, index: usize) -> RawValue {
    let mut value = [0; 32];
    value[..8].copy_from_slice(&(round as u64).to_be_bytes());
    value[31] = index as u8;
    value
}

/// Build enough inactive history for a nonzero prune while keeping the work bounded.
async fn prepare_nonzero_prune<F: Graftable>(
    mut db: Db<F>,
    pending_writes: &mut Vec<(Key, Option<Value>)>,
    pending: &mut State,
    expected: &mut Expected,
) -> Db<F> {
    for round in 0..PRUNE_PREP_ROUNDS {
        for index in 0..PRUNE_PREP_KEYS {
            let key = prune_prep_key(index);
            let value = prune_prep_value(round, index);
            pending_writes.push((Key::new(key), Some(Value::new(value))));
            pending.insert(key, Some(value));
        }

        // Rewriting every other live key in the final batch moves the inactivity floor beyond
        // the old history. The 23 preceding 33-op batches put this batch past MMB's 767-leaf
        // absorption threshold while adding only 32 modeled keys.
        if round + 1 == PRUNE_PREP_ROUNDS {
            let Expected::Exact(snapshot) = expected else {
                unreachable!("operations stop after state becomes uncertain")
            };
            let live = snapshot
                .state
                .iter()
                .filter_map(|(key, value)| value.map(|value| (*key, value)))
                .collect::<Vec<_>>();
            for (key, value) in live {
                if pending.contains_key(&key) {
                    continue;
                }
                pending_writes.push((Key::new(key), Some(Value::new(value))));
                pending.insert(key, Some(value));
            }
        }

        let mut batch = db.new_batch();
        for (key, value) in pending_writes.drain(..) {
            batch = batch.write(key, value);
        }
        let batch = batch
            .merkleize(&db, None)
            .await
            .expect("fault-free prune preparation must merkleize");
        (db, _) = db
            .apply_batch(batch)
            .await
            .expect("fault-free prune preparation must apply");
        commit_pending_model(pending, expected, &db);
    }
    let db = db
        .commit()
        .await
        .expect("fault-free prune preparation must commit");
    let Expected::Exact(snapshot) = expected else {
        unreachable!("fault-free prune preparation remains exact")
    };
    *snapshot = Snapshot::from_db(&db, snapshot.state.clone());
    db
}

async fn apply_pending_for_crash<F: Graftable>(
    db: Db<F>,
    pending_writes: &mut Vec<(Key, Option<Value>)>,
    pending: &mut State,
    expected: &mut Expected,
) {
    if pending_writes.is_empty() {
        return;
    }
    let mut batch = db.new_batch();
    for (key, value) in pending_writes.drain(..) {
        batch = batch.write(key, value);
    }
    let Ok(batch) = batch.merkleize(&db, None).await else {
        return;
    };
    let start = db.bounds().start.as_u64();
    let prospective = Snapshot {
        state: prospective_state(pending, expected),
        root: batch.root(),
        min_start: start,
        max_start: start,
        end: batch.bounds().total_size,
        sync_boundary: batch.sync_boundary().as_u64(),
    };
    let prospective = match db.apply_batch(batch).await {
        Ok((db, _)) => Snapshot::from_db(&db, prospective.state),
        Err(_) => prospective,
    };
    mark_pending_uncertain(pending, expected, prospective);
}

fn state_matches(actual: &State, expected: &State) -> bool {
    actual
        .iter()
        .all(|(key, value)| *value == expected.get(key).copied().flatten())
}

fn snapshot_matches<F: Graftable>(db: &Db<F>, actual: &State, expected: &Snapshot) -> bool {
    let bounds = db.bounds();
    let start = bounds.start.as_u64();
    state_matches(actual, &expected.state)
        && db.root() == expected.root
        && (start == expected.min_start || start == expected.max_start)
        && bounds.end.as_u64() == expected.end
        && db.sync_boundary().as_u64() == expected.sync_boundary
}

async fn verify_recovery<F: Graftable>(
    db: &Db<F>,
    expected: &Expected,
    log_items_per_blob: u64,
) -> State {
    let root = db.root();
    let bounds = db.bounds();
    assert_eq!(
        bounds.start.as_u64() % log_items_per_blob,
        0,
        "recovered start is not a physical log section boundary"
    );
    let mut actual = State::new();
    let (old, new) = match expected {
        Expected::Exact(state) => (state, None),
        Expected::Either { old, new } => (old, Some(new)),
    };
    for raw_key in old
        .state
        .keys()
        .chain(new.into_iter().flat_map(|snapshot| snapshot.state.keys()))
    {
        if actual.contains_key(raw_key) {
            continue;
        }
        let key = Key::new(*raw_key);
        let value = db.get(&key).await.expect("get after recovery");
        actual.insert(
            *raw_key,
            value
                .as_ref()
                .map(|value| value.as_ref().try_into().expect("fixed value length")),
        );

        if let Some(value) = value {
            let proof = db
                .key_value_proof(key.clone())
                .await
                .expect("proof for recovered key");
            assert!(
                Db::<F>::verify_key_value_proof(key, value, &proof, &root),
                "recovered key-value proof failed"
            );
        }
    }
    let matches = snapshot_matches(db, &actual, old)
        || new.is_some_and(|new| snapshot_matches(db, &actual, new));
    assert!(
        matches,
        "recovery did not match a modeled whole-database state/root/bounds"
    );

    // Authenticate every physically retained operation against the raw ops-tree root. This covers
    // the section-granular prefix below the bitmap's sync boundary as well as the active suffix.
    let start = *bounds.start;
    let size = *bounds.end;
    if start < size {
        let retained = size - start;
        let max_ops = NonZeroU64::new(retained).expect("non-empty retained operation range");
        let (proof, ops) = db
            .ops_historical_proof(Location::<F>::new(size), Location::<F>::new(start), max_ops)
            .await
            .expect("complete ops-tree proof after recovery");
        assert_eq!(
            u64::try_from(ops.len()).expect("operation count fits in u64"),
            retained,
            "complete ops-tree proof omitted retained operations"
        );
        assert!(
            verify_proof::<Sha256, _, _>(&proof, Location::<F>::new(start), &ops, &db.ops_root(),),
            "complete ops-tree proof failed after recovery"
        );
    }

    // Also authenticate every operation whose bitmap history remains available against the
    // canonical Current root. This verifies the grafted activity overlay in addition to raw ops.
    let floor = *db.sync_boundary();
    if floor < size {
        let retained = size - floor;
        let max_ops = NonZeroU64::new(retained).expect("non-empty retained operation range");
        let (proof, ops, chunks) = db
            .range_proof(Location::<F>::new(floor), max_ops)
            .await
            .expect("complete range proof after recovery");
        assert_eq!(
            u64::try_from(ops.len()).expect("operation count fits in u64"),
            retained,
            "complete range proof omitted retained operations"
        );
        assert!(
            Db::<F>::verify_range_proof(&proof, Location::<F>::new(floor), &ops, &chunks, &root,),
            "complete range proof failed after recovery"
        );
    }

    actual
}

fn fuzz_family<F: Graftable>(input: &FuzzInput, suffix_base: &str) {
    let params = Params {
        page_size: NonZeroU16::new(input.page_size).unwrap(),
        page_cache_size: NonZeroUsize::new(input.page_cache_size).unwrap(),
        merkle_items_per_blob: input.merkle_items_per_blob,
        log_items_per_blob: input.log_items_per_blob,
        compression: input.compression,
        write_buffer: NonZeroUsize::new(input.write_buffer).unwrap(),
    };
    let sync_failure_rate = input.sync_failure_rate;
    let write_failure_rate = input.write_failure_rate;
    let operations = input.operations.clone();
    let suffix = suffix_base.to_string();

    let runner = fuzz_runner(&input.raw_bytes);

    // Phase 1: Execute operations with fault injection until crash.
    let (expected, checkpoint) = runner.start_and_recover(|ctx| {
        let suffix = suffix.clone();
        let operations = operations.clone();
        async move {
            let mut db: Db<F> = Db::init(ctx.child("db"), make_config(&ctx, &suffix, params))
                .await
                .unwrap();

            let fault_cfg = ctx.storage_fault_config();
            let injected_faults = deterministic::FaultConfig {
                sync_rate: Some(sync_failure_rate),
                write_rate: Some(write_failure_rate),
                partial_write_rate: Some(1.0),
                ..Default::default()
            };
            *fault_cfg.write() = injected_faults.clone();

            // Exact durable state, or coherent old/new states after an interrupted batch.
            let mut expected = Expected::Exact(Snapshot::from_db(&db, State::new()));
            // Uncommitted changes since the last commit. None = delete, Some = upsert.
            let mut pending = State::new();

            // Accumulate writes until Commit, matching the intended
            // pending/committed separation.
            let mut pending_writes: Vec<(Key, Option<Value>)> = Vec::new();

            for op in &operations {
                db = match op {
                    CurrentOperation::Update { key, value } => {
                        pending_writes.push((Key::new(*key), Some(Value::new(*value))));
                        pending.insert(*key, Some(*value));
                        db
                    }
                    CurrentOperation::Delete { key } => {
                        pending_writes.push((Key::new(*key), None));
                        pending.insert(*key, None);
                        db
                    }
                    CurrentOperation::Apply => {
                        apply_pending_for_crash(
                            db,
                            &mut pending_writes,
                            &mut pending,
                            &mut expected,
                        )
                        .await;
                        break;
                    }
                    CurrentOperation::Commit => {
                        let Some(db) =
                            commit_pending(db, &mut pending_writes, &mut pending, &mut expected)
                                .await
                        else {
                            break;
                        };
                        db
                    }
                    CurrentOperation::Prune { selector } => {
                        let Some(db) =
                            commit_pending(db, &mut pending_writes, &mut pending, &mut expected)
                                .await
                        else {
                            break;
                        };
                        let db = if db.sync_boundary() == Location::new(0) {
                            *fault_cfg.write() = deterministic::FaultConfig::default();
                            let db = prepare_nonzero_prune(
                                db,
                                &mut pending_writes,
                                &mut pending,
                                &mut expected,
                            )
                            .await;
                            *fault_cfg.write() = injected_faults.clone();
                            db
                        } else {
                            db
                        };
                        let boundary = db.sync_boundary();
                        assert!(
                            boundary > Location::new(0),
                            "prune boundary must be nonzero"
                        );
                        let current_start = db.bounds().start.as_u64();
                        let max_start = boundary.as_u64() / params.log_items_per_blob
                            * params.log_items_per_blob;
                        if max_start <= current_start {
                            db
                        } else {
                            let sections = (max_start - current_start) / params.log_items_per_blob;
                            let target = current_start
                                + (u64::from(*selector) % sections + 1) * params.log_items_per_blob;
                            match db.prune(Location::new(target)).await {
                                Ok(db) => {
                                    assert_eq!(
                                        db.bounds().start,
                                        Location::new(target),
                                        "prune must advance to the selected journal section"
                                    );
                                    let Expected::Exact(snapshot) = &expected else {
                                        unreachable!("prune starts from an exact state")
                                    };
                                    expected = Expected::Exact(Snapshot::from_db(
                                        &db,
                                        snapshot.state.clone(),
                                    ));
                                    db
                                }
                                Err(_) => {
                                    let Expected::Exact(snapshot) = &mut expected else {
                                        unreachable!("prune starts from an exact state")
                                    };
                                    snapshot.max_start = target;
                                    break;
                                }
                            }
                        }
                    }
                };
            }

            expected
        }
    });

    // Recover, verify all modeled values (including tombstones), and commit a sentinel.
    let verify_suffix = suffix.clone();
    let (expected, checkpoint) =
        deterministic::Runner::from(checkpoint).start_and_recover(|ctx| async move {
            *ctx.storage_fault_config().write() = deterministic::FaultConfig::default();
            let db: Db<F> = Db::init(
                ctx.child("recovered"),
                make_config(&ctx, &verify_suffix, params),
            )
            .await
            .expect("recovery must succeed");
            let mut concrete = verify_recovery(&db, &expected, params.log_items_per_blob).await;

            let raw_key = [0xAB; 32];
            let raw_value = [0xCD; 32];
            let batch = db
                .new_batch()
                .write(Key::new(raw_key), Some(Value::new(raw_value)))
                .merkleize(&db, None)
                .await
                .expect("sentinel merkleize after recovery");
            let (db, _) = db
                .apply_batch(batch)
                .await
                .expect("sentinel apply after recovery");
            let db = db.commit().await.expect("sentinel commit after recovery");
            concrete.insert(raw_key, Some(raw_value));
            Snapshot::from_db(&db, concrete)
        });

    // Cross a second crash boundary, verify the recovered database, then interrupt its real
    // composite destroy.
    let redestroy_suffix = suffix.clone();
    let (_, checkpoint) =
        deterministic::Runner::from(checkpoint).start_and_recover(|ctx| async move {
            let db: Db<F> = Db::init(ctx.child("sentinel"), make_config(&ctx, &suffix, params))
                .await
                .expect("sentinel recovery must succeed");
            verify_recovery(&db, &Expected::Exact(expected), params.log_items_per_blob).await;
            *ctx.storage_fault_config().write() = interrupt_faults();
            let _ = db.destroy().await;
        });

    deterministic::Runner::from(checkpoint).start(|ctx| async move {
        *ctx.storage_fault_config().write() = deterministic::FaultConfig::default();
        let db: Db<F> = Db::init(
            ctx.child("redestroy"),
            make_config(&ctx, &redestroy_suffix, params),
        )
        .await
        .expect("Current must reopen after interrupted destroy");
        db.destroy().await.expect("destroy retry must succeed");
    });
}

fn fuzz(input: FuzzInput) {
    if input.mmb {
        fuzz_family::<mmb::Family>(&input, "current-crash-mmb");
    } else {
        fuzz_family::<mmr::Family>(&input, "current-crash-mmr");
    }
}

fuzz_target!(|input: FuzzInput| fuzz(input));
