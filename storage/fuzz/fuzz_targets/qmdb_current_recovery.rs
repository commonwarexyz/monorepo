#![no_main]

//! Fuzz test for Current QMDB crash recovery with fault injection.
//!
//! Phase 1 runs state-changing operations (update, delete, commit, prune) under injected
//! write/sync failures, with remove faults armed only around each prune drive, then
//! "crashes". A chain of one to four faulted recovery attempts follows, each restoring the
//! crash image under fresh input-driven faults and crashing into the next. Phase 2 recovers
//! cleanly and checks the oracle: the recovered (state, root) pair must be atomic at a
//! recorded batch boundary, key-value and range proofs must verify against that root, and
//! a fresh batch proves the recovered DB is usable.

use arbitrary::Arbitrary;
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Runner, Supervisor as _,
    buffer::paged::CacheRef,
    deterministic::{self, Context},
};
use commonware_storage::{
    journal::contiguous::variable::Config as VConfig,
    merkle::{Graftable, Location, full::Config as MerkleConfig, mmb, mmr},
    qmdb::current::{VariableConfig, unordered::variable::Db as Current},
    translator::TwoCap,
};
use commonware_storage_fuzz::{
    bounded_buffer, bounded_items, bounded_nonzero_rate, bounded_page_cache_size,
    bounded_page_size, faulted_recovery,
};
use commonware_utils::{Entropy, NZU64, NZUsize, Probability, sequence::FixedBytes};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::{BTreeSet, HashMap},
    num::{NonZeroU16, NonZeroUsize},
};

type Key = FixedBytes<32>;
type Value = FixedBytes<32>;
type RawKey = [u8; 32];
type RawValue = [u8; 32];

type Db<F> = Current<F, deterministic::Context, Key, Value, Sha256, TwoCap, 32, Sequential>;

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
    /// Page size for buffer pool.
    #[arbitrary(with = bounded_page_size)]
    page_size: u16,
    /// Number of pages in the buffer pool cache.
    #[arbitrary(with = bounded_page_cache_size)]
    page_cache_size: usize,
    /// Items per blob for the Merkle journal.
    #[arbitrary(with = bounded_items)]
    merkle_items_per_blob: u64,
    /// Items per section for the operations log.
    #[arbitrary(with = bounded_items)]
    log_items_per_blob: u64,
    /// Write buffer size.
    #[arbitrary(with = bounded_buffer)]
    write_buffer: usize,
    /// Replay buffer size.
    #[arbitrary(with = bounded_buffer)]
    replay_buffer: usize,
    /// Failure rate for sync operations (0, 1].
    #[arbitrary(with = bounded_nonzero_rate)]
    sync_failure_rate: Probability,
    /// Failure and byte-retention configuration for write operations.
    write_config: deterministic::WriteConfig,
    /// Remove failure rate (percent) armed only around each prune drive, sampled per blob
    /// removal so the ops-log prune inside can fail after removing only some blobs, leaving
    /// pruning metadata ahead of a partially pruned log. Currently latent: the sync boundary
    /// is bitmap-chunk aligned, so the log removes nothing below 256 committed operations,
    /// beyond reachable input sizes.
    remove_failure: u8,
    /// Sequence of operations to execute.
    operations: Vec<CurrentOperation>,
    /// Byte stream driving the runtime rng: all in-run randomness, fault sampling, and the
    /// faulted recovery chain's depth and shapes.
    entropy: Entropy,
}

#[derive(Clone, Copy)]
struct ConfigParams {
    page_size: NonZeroU16,
    page_cache_size: NonZeroUsize,
    merkle_items_per_blob: u64,
    log_items_per_blob: u64,
    write_buffer: NonZeroUsize,
    replay_buffer: NonZeroUsize,
}

fn make_config(
    ctx: &Context,
    suffix: &str,
    params: ConfigParams,
) -> VariableConfig<TwoCap, ((), ()), Sequential> {
    let ConfigParams {
        page_size,
        page_cache_size,
        merkle_items_per_blob,
        log_items_per_blob,
        write_buffer,
        replay_buffer,
    } = params;
    let page_cache = CacheRef::from_pooler(ctx, page_size, page_cache_size);
    VariableConfig {
        merkle_config: MerkleConfig {
            journal_partition: format!("crash-merkle-journal-{suffix}"),
            metadata_partition: format!("crash-merkle-metadata-{suffix}"),
            items_per_blob: NZU64!(merkle_items_per_blob),
            write_buffer,
            replay_buffer,
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        journal_config: VConfig {
            partition: format!("crash-log-{suffix}"),
            items_per_section: NZU64!(log_items_per_blob),
            write_buffer,
            replay_buffer,
            compression: None,
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

/// Committed key-value state tracked across batch boundaries.
type State = HashMap<RawKey, RawValue>;

/// Merge pending changes into committed after a successful commit.
fn apply_pending(pending: &mut HashMap<RawKey, Option<RawValue>>, committed: &mut State) {
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

/// Return the complete (state, root) snapshots recovery may expose after an errored batch.
///
/// An applied batch can be KV-identical to the committed state while still appending
/// operations (and changing the root), so entries collapse only when the roots also match.
fn failure_states(
    pending: &HashMap<RawKey, Option<RawValue>>,
    committed: &State,
    committed_root: Digest,
    post_root: Digest,
) -> Vec<(State, Digest)> {
    let mut post = committed.clone();
    for (key, value) in pending {
        match value {
            Some(value) => {
                post.insert(*key, *value);
            }
            None => {
                post.remove(key);
            }
        }
    }

    if post == *committed && post_root == committed_root {
        vec![(committed.clone(), committed_root)]
    } else {
        vec![(committed.clone(), committed_root), (post, post_root)]
    }
}

/// Commit pending writes, returning the (state, root) snapshots allowed after failure.
///
/// On success, `committed_root` advances to the applied batch's canonical root, which
/// equals the db's root after `apply_batch` (commit changes durability, not the root).
async fn commit_pending<F: Graftable>(
    db: Db<F>,
    pending_writes: &mut Vec<(Key, Option<Value>)>,
    pending: &mut HashMap<RawKey, Option<RawValue>>,
    committed: &mut State,
    committed_root: &mut Digest,
) -> Result<Db<F>, Vec<(State, Digest)>> {
    let mut batch = db.new_batch();
    for (k, v) in pending_writes.drain(..) {
        batch = batch.write(k, v);
    }
    // Merkleize only reads and hashes, and reads are never fault-injected, so an
    // error here is a real bug rather than a legal crash trigger.
    let merkleized = batch
        .merkleize(&db, None)
        .await
        .expect("merkleize failed without any mutable operation");
    let post_root = merkleized.root();
    let db = match db.apply_batch(merkleized).await {
        Ok((db, _)) => db,
        Err(_) => {
            return Err(failure_states(
                pending,
                committed,
                *committed_root,
                post_root,
            ));
        }
    };
    let db = match db.commit().await {
        Ok(db) => db,
        Err(_) => {
            return Err(failure_states(
                pending,
                committed,
                *committed_root,
                post_root,
            ));
        }
    };
    apply_pending(pending, committed);
    *committed_root = post_root;
    Ok(db)
}

fn fuzz_family<F: Graftable>(input: &FuzzInput, suffix_base: &str) {
    let params = ConfigParams {
        page_size: NonZeroU16::new(input.page_size).unwrap(),
        page_cache_size: NonZeroUsize::new(input.page_cache_size).unwrap(),
        merkle_items_per_blob: input.merkle_items_per_blob,
        log_items_per_blob: input.log_items_per_blob,
        write_buffer: NonZeroUsize::new(input.write_buffer).unwrap(),
        replay_buffer: NonZeroUsize::new(input.replay_buffer).unwrap(),
    };
    let sync_failure_rate = input.sync_failure_rate;
    let write_config = input.write_config;
    let remove_rate = Probability::new(u64::from(input.remove_failure) % 101, 100).unwrap();
    let operations = input.operations.clone();
    let suffix = suffix_base.to_string();

    let cfg = deterministic::Config::default().with_rng(input.entropy.clone());
    let runner = deterministic::Runner::new(cfg);

    // Phase 1: Execute operations with fault injection until crash.
    // Track committed KV state and per-boundary roots so recovery can be
    // verified against an independently recorded snapshot.
    let ((known_keys, allowed_states), checkpoint) = runner.start_and_recover(|ctx| {
        let suffix = suffix.clone();
        let operations = operations.clone();
        async move {
            let mut db: Db<F> = Db::init(ctx.child("db"), make_config(&ctx, &suffix, params))
                .await
                .expect("initial init failed");

            // Root recorded at the last successful commit boundary (initially empty).
            let mut committed_root = db.root();

            let fault_cfg = ctx.storage_fault_config();
            *fault_cfg.write() = deterministic::FaultConfig {
                sync_rate: Some(sync_failure_rate),
                write_rate: Some(write_config),
                ..Default::default()
            };

            // Active KV pairs after the last successful commit.
            let mut committed = State::new();
            // Uncommitted changes since the last commit. None = delete, Some = upsert.
            let mut pending: HashMap<RawKey, Option<RawValue>> = HashMap::new();
            let mut known_keys = BTreeSet::new();
            let mut failure = None;

            // Accumulate writes until Commit, matching the intended
            // pending/committed separation.
            let mut pending_writes: Vec<(Key, Option<Value>)> = Vec::new();

            for op in &operations {
                db = match op {
                    CurrentOperation::Update { key, value } => {
                        known_keys.insert(*key);
                        pending_writes.push((Key::new(*key), Some(Value::new(*value))));
                        pending.insert(*key, Some(*value));
                        db
                    }
                    CurrentOperation::Delete { key } => {
                        known_keys.insert(*key);
                        pending_writes.push((Key::new(*key), None));
                        pending.insert(*key, None);
                        db
                    }
                    CurrentOperation::Commit => {
                        match commit_pending(
                            db,
                            &mut pending_writes,
                            &mut pending,
                            &mut committed,
                            &mut committed_root,
                        )
                        .await
                        {
                            Ok(db) => db,
                            Err(states) => {
                                failure = Some(states);
                                break;
                            }
                        }
                    }
                    CurrentOperation::Prune => {
                        let db = match commit_pending(
                            db,
                            &mut pending_writes,
                            &mut pending,
                            &mut committed,
                            &mut committed_root,
                        )
                        .await
                        {
                            Ok(db) => db,
                            Err(states) => {
                                failure = Some(states);
                                break;
                            }
                        };
                        let boundary = db.sync_boundary();

                        // Remove faults are armed only around the prune drive: the ops-log
                        // prune inside can then fail after removing only some blobs, leaving
                        // pruning metadata ahead of a partially pruned log (the supported
                        // mid-prune crash shape) for recovery to reconcile.
                        *fault_cfg.write() = deterministic::FaultConfig {
                            remove_rate: Some(remove_rate),
                            sync_rate: Some(sync_failure_rate),
                            write_rate: Some(write_config),
                            ..Default::default()
                        };
                        let result = db.prune(boundary).await;
                        *fault_cfg.write() = deterministic::FaultConfig {
                            sync_rate: Some(sync_failure_rate),
                            write_rate: Some(write_config),
                            ..Default::default()
                        };
                        match result {
                            Ok(db) => db,
                            Err(_) => break,
                        }
                    }
                };
            }

            // A failed prune leaves both the committed state and the root unchanged, even
            // when its log removals tore partway: pruning drops only history below the sync
            // boundary and never alters the live snapshot or its root.
            let allowed = failure.unwrap_or_else(|| vec![(committed, committed_root)]);
            (known_keys.into_iter().collect::<Vec<_>>(), allowed)
        }
    });

    let recovery_suffix = suffix.clone();
    let checkpoint = faulted_recovery(checkpoint, move |ctx| {
        let recovery_suffix = recovery_suffix.clone();
        async move {
            Db::<F>::init(
                ctx.child("faulted_recovery"),
                make_config(&ctx, &recovery_suffix, params),
            )
            .await
        }
    });

    // Phase 2: Recover and verify consistency.
    let runner = deterministic::Runner::from(checkpoint);
    runner.start(|ctx| {
        let suffix = suffix.clone();
        async move {
            *ctx.storage_fault_config().write() = deterministic::FaultConfig::default();

            let db: Db<F> = Db::init(ctx.child("recovered"), make_config(&ctx, &suffix, params))
                .await
                .expect("recovery failed");

            // Read every observed key in one batch so the result must match one atomic
            // snapshot, and require the recovered root to match the root recorded at
            // that same boundary: the root is a pure function of the log, so accepting
            // the instance's own root would let a self-consistent rebuild bug pass.
            let root = db.root();
            let keys = known_keys.iter().copied().map(Key::new).collect::<Vec<_>>();
            let key_refs = keys.iter().collect::<Vec<_>>();
            let recovered = db
                .get_many(&key_refs)
                .await
                .expect("whole-snapshot read failed on recovered data");
            let matches_allowed = allowed_states.iter().any(|(state, expected_root)| {
                *expected_root == root
                    && known_keys
                        .iter()
                        .map(|key| state.get(key).copied().map(Value::new))
                        .eq(recovered.iter().cloned())
            });
            assert!(
                matches_allowed,
                "recovery exposed a (state, root) pair that was not atomic at a batch boundary"
            );

            // Verify all recovered KV pairs are provable against the matched root.
            for (key, value) in keys
                .into_iter()
                .zip(recovered)
                .filter_map(|(key, value)| value.map(|value| (key, value)))
            {
                let proof = db
                    .key_value_proof(key.clone())
                    .await
                    .expect("proof generation failed for a recovered key");
                assert!(
                    Db::<F>::verify_key_value_proof(key, value, &proof, &root),
                    "key value proof failed to verify after crash recovery"
                );
            }

            // Verify range proofs over the recovered DB.
            let floor = *db.sync_boundary();
            let size = *db.bounds().end;
            for i in floor..size {
                let loc = Location::<F>::new(i);
                let (proof, ops, chunks) = db
                    .range_proof(loc, NZU64!(4))
                    .await
                    .expect("range proof generation failed after recovery");
                assert!(
                    Db::<F>::verify_range_proof(&proof, loc, &ops, &chunks, &root),
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
                .expect("post-recovery merkleize failed");
            let (db, _) = db
                .apply_batch(batch)
                .await
                .expect("post-recovery apply_batch failed");
            let db = db.commit().await.expect("post-recovery commit failed");

            db.destroy().await.expect("destroy failed");
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz_family::<mmr::Family>(&input, "current-crash-mmr");
    fuzz_family::<mmb::Family>(&input, "current-crash-mmb");
});
