use crate::{
    adb::{
        self,
        any::{
            sync::{
                resolver::{GetOperationsResult, Resolver},
                Error,
            },
            SyncConfig,
        },
        operation::Operation,
    },
    journal::fixed::{Config as JConfig, Journal},
    mmr::{self, iterator::leaf_num_to_pos},
    translator::Translator,
};
use commonware_cryptography::Hasher;
use commonware_runtime::{
    telemetry::metrics::histogram::{Buckets, Timed},
    Clock, Metrics as MetricsTrait, Storage,
};
use commonware_utils::Array;
use prometheus_client::metrics::{counter::Counter, histogram::Histogram};
use std::{num::NonZeroU64, sync::Arc};
use tracing::{debug, info, warn};

/// Configuration for the sync client
pub struct Config<E, K, V, H, T, R>
where
    E: Storage + Clock + MetricsTrait,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<Digest = H::Digest, Key = K, Value = V>,
{
    /// Context for the database.
    pub context: E,

    /// Database configuration.
    pub db_config: adb::any::Config<T>,

    /// Maximum operations to fetch per batch.
    pub fetch_batch_size: NonZeroU64,

    /// Target hash of the database.
    pub target_hash: H::Digest,

    /// Lower bound of operations to sync.
    /// This will be the inactivity floor and pruning boundary
    /// of the synced database.
    pub lower_bound_ops: u64,

    /// Upper bound of operations to sync (inclusive).
    pub upper_bound_ops: u64,

    /// Resolves requests for proofs and operations.
    pub resolver: R,

    /// Hasher for root hashes.
    pub hasher: mmr::hasher::Standard<H>,

    /// The maximum number of operations to keep in memory
    /// before committing the database while applying operations.
    /// Higher value will cause more memory usage during sync.
    pub apply_batch_size: usize,
}

/// Prometheus metrics for the sync client.
pub struct Metrics<E: Clock> {
    /// Number of valid batches successfully received and processed.
    valid_batches_received: Counter<u64>,
    /// Number of invalid batches received that failed validation.
    invalid_batches_received: Counter<u64>,
    /// Total number of operations fetched during sync.
    operations_fetched: Counter<u64>,
    /// Total time spent fetching operations from resolver (seconds).
    fetch_duration: Timed<E>,
    /// Total time spent verifying proofs (seconds).
    proof_verification_duration: Timed<E>,
    /// Total time spent applying operations to the log (seconds).
    apply_duration: Timed<E>,
}

impl<E: Clock + MetricsTrait> Metrics<E> {
    /// Register metrics with the provided runtime metrics context and return the struct.
    pub fn new(context: E) -> Self {
        let fetch_histogram = Histogram::new(Buckets::NETWORK.into_iter());
        let proof_verification_histogram = Histogram::new(Buckets::CRYPTOGRAPHY.into_iter());
        let apply_histogram = Histogram::new(Buckets::LOCAL.into_iter());

        let metrics = Self {
            valid_batches_received: Counter::default(),
            invalid_batches_received: Counter::default(),
            operations_fetched: Counter::default(),
            fetch_duration: Timed::new(fetch_histogram.clone(), Arc::new(context.clone())),
            proof_verification_duration: Timed::new(
                proof_verification_histogram.clone(),
                Arc::new(context.clone()),
            ),
            apply_duration: Timed::new(apply_histogram.clone(), Arc::new(context.clone())),
        };

        // Register metrics.
        context.register(
            "valid_batches_received",
            "Number of valid operation batches processed during ADB sync",
            metrics.valid_batches_received.clone(),
        );
        context.register(
            "invalid_batches_received",
            "Number of invalid operation batches encountered during ADB sync",
            metrics.invalid_batches_received.clone(),
        );
        context.register(
            "operations_fetched",
            "Total number of operations fetched during ADB sync",
            metrics.operations_fetched.clone(),
        );
        context.register(
            "fetch_duration_seconds",
            "Histogram of durations spent fetching operation batches during ADB sync",
            fetch_histogram,
        );
        context.register(
            "proof_verification_duration_seconds",
            "Histogram of durations spent verifying proofs during ADB sync",
            proof_verification_histogram,
        );
        context.register(
            "apply_duration_seconds",
            "Histogram of durations spent applying operations during ADB sync",
            apply_histogram,
        );

        metrics
    }
}

/// Client that syncs an [adb::any::Any] database.
#[allow(clippy::large_enum_variant)]
pub(super) enum Client<E, K, V, H, T, R>
where
    E: Storage + Clock + MetricsTrait,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<Digest = H::Digest, Key = K, Value = V>,
{
    /// Next step is to fetch and verify operations.
    FetchData {
        config: Config<E, K, V, H, T, R>,
        log: Journal<E, Operation<K, V>>,
        /// Extracted pinned nodes from first batch proof
        pinned_nodes: Option<Vec<H::Digest>>,
        metrics: Metrics<E>,
    },
    /// Next step is to apply fetched operations to the log.
    ApplyData {
        config: Config<E, K, V, H, T, R>,
        log: Journal<E, Operation<K, V>>,
        pinned_nodes: Option<Vec<H::Digest>>,
        batch_ops: Vec<Operation<K, V>>,
        metrics: Metrics<E>,
    },
    /// Sync completed. Database is fully constructed.
    Done { db: adb::any::Any<E, K, V, H, T> },
}

impl<E, K, V, H, T, R> Client<E, K, V, H, T, R>
where
    E: Storage + Clock + MetricsTrait,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<Digest = H::Digest, Key = K, Value = V>,
{
    /// Create a new sync client
    pub(crate) async fn new(config: Config<E, K, V, H, T, R>) -> Result<Self, Error> {
        // Validate bounds (inclusive)
        if config.lower_bound_ops > config.upper_bound_ops {
            return Err(Error::InvalidTarget {
                lower_bound_pos: config.lower_bound_ops,
                upper_bound_pos: config.upper_bound_ops,
            });
        }

        // Initialize the operations journal.
        // It may have data in the target range.
        let log = Journal::<E, Operation<K, V>>::init_sync(
            config.context.clone().with_label("log"),
            JConfig {
                partition: config.db_config.log_journal_partition.clone(),
                items_per_blob: config.db_config.log_items_per_blob,
                write_buffer: config.db_config.log_write_buffer,
                buffer_pool: config.db_config.buffer_pool.clone(),
            },
            config.lower_bound_ops,
            config.upper_bound_ops,
        )
        .await
        .map_err(adb::Error::JournalError)
        .map_err(Error::Adb)?;

        // Check how many operations are already in the log.
        let log_size = log
            .size()
            .await
            .map_err(|e| Error::Adb(adb::Error::JournalError(e)))?;

        // Assert invariant from [Journal::init_sync]
        assert!(log_size <= config.upper_bound_ops + 1);
        if log_size == config.upper_bound_ops + 1 {
            // We already have all the operations we need in the log.
            // Build the database immediately without fetching more operations.
            let db = adb::any::Any::init_synced(
                config.context.clone(),
                SyncConfig {
                    db_config: config.db_config.clone(),
                    log,
                    lower_bound: config.lower_bound_ops,
                    upper_bound: config.upper_bound_ops,
                    pinned_nodes: None,
                    apply_batch_size: config.apply_batch_size,
                },
            )
            .await
            .map_err(Error::Adb)?;

            return Ok(Client::Done { db });
        }

        Ok(Client::FetchData {
            metrics: Metrics::new(config.context.clone()),
            config,
            log,
            pinned_nodes: None,
        })
    }

    /// Process the next step in the sync process
    async fn step(self) -> Result<Self, Error> {
        match self {
            Client::FetchData {
                mut config,
                log,
                mut pinned_nodes,
                metrics,
            } => {
                // Get current position in the log
                let log_size = log
                    .size()
                    .await
                    .map_err(|e| Error::Adb(adb::Error::JournalError(e)))?;

                // Calculate remaining operations to sync (inclusive upper bound)
                let remaining_ops = if log_size <= config.upper_bound_ops {
                    config.upper_bound_ops - log_size + 1
                } else {
                    // We're at/past the target.
                    warn!(
                        log_size,
                        upper_bound = config.upper_bound_ops,
                        "Sync target exceeded"
                    );
                    return Err(Error::InvalidState);
                };

                let batch_size = std::cmp::min(config.fetch_batch_size.get(), remaining_ops);
                let batch_size = NonZeroU64::new(batch_size).ok_or(Error::InvalidState)?;

                debug!(
                    target_hash = ?config.target_hash,
                    lower_bound_pos = config.lower_bound_ops,
                    upper_bound_pos = config.upper_bound_ops,
                    current_pos = log_size,
                    remaining_ops = remaining_ops,
                    batch_size = batch_size.get(),
                    "Fetching proof and operations"
                );

                // Get proof and operations from resolver
                let GetOperationsResult {
                    proof,
                    operations,
                    success_tx,
                } = {
                    let _timer = metrics.fetch_duration.timer();
                    let target_size = config.upper_bound_ops + 1;
                    config
                        .resolver
                        .get_operations(target_size, log_size, batch_size)
                        .await?
                };

                let operations_len = operations.len() as u64;

                // Validate that we didn't get more operations than requested
                // or that we didn't get an empty proof. We should never get an empty proof
                // because we will never request an empty proof (i.e. a proof over an empty database).
                if operations_len > batch_size.get() || operations_len == 0 {
                    debug!(
                        operations_len,
                        batch_size = batch_size.get(),
                        "Received invalid batch size from resolver"
                    );
                    metrics.invalid_batches_received.inc();
                    let _ = success_tx.send(false);
                    return Ok(Client::FetchData {
                        config,
                        log,
                        pinned_nodes,
                        metrics,
                    });
                }

                debug!(operations_len, "Received operations from resolver");

                // Verify the proof is valid over the given operations
                let proof_valid = {
                    let _timer = metrics.proof_verification_duration.timer();
                    adb::any::Any::<E, K, V, H, T>::verify_proof(
                        &mut config.hasher,
                        &proof,
                        log_size,
                        &operations,
                        &config.target_hash,
                    )
                };
                let _ = success_tx.send(proof_valid);

                if !proof_valid {
                    debug!("Proof verification failed, retrying");
                    metrics.invalid_batches_received.inc();
                    return Ok(Client::FetchData {
                        config,
                        log,
                        pinned_nodes,
                        metrics,
                    });
                }

                // Install pinned nodes on first successful batch.
                if pinned_nodes.is_none() {
                    let start_pos = leaf_num_to_pos(log_size);
                    let end_pos = leaf_num_to_pos(log_size + operations_len - 1);
                    let Ok(new_pinned_nodes) = proof.extract_pinned_nodes(start_pos, end_pos)
                    else {
                        warn!("Failed to extract pinned nodes, retrying");
                        metrics.invalid_batches_received.inc();
                        return Ok(Client::FetchData {
                            config,
                            log,
                            pinned_nodes,
                            metrics,
                        });
                    };
                    pinned_nodes = Some(new_pinned_nodes);
                }

                // Record successful batch metrics
                metrics.valid_batches_received.inc();
                metrics.operations_fetched.inc_by(operations_len);

                Ok(Client::ApplyData {
                    config,
                    log,
                    pinned_nodes,
                    batch_ops: operations,
                    metrics,
                })
            }

            Client::ApplyData {
                config,
                mut log,
                pinned_nodes,
                batch_ops,
                metrics,
            } => {
                // Apply operations to the log
                {
                    let _timer = metrics.apply_duration.timer();
                    for op in batch_ops.into_iter() {
                        log.append(op)
                            .await
                            .map_err(adb::Error::JournalError)
                            .map_err(Error::Adb)?;
                        // No need to sync here -- the log will periodically sync its storage
                        // and we will also sync when we're done.
                    }
                }

                // Check if we've applied all needed operations
                let log_size = log
                    .size()
                    .await
                    .map_err(|e| Error::Adb(adb::Error::JournalError(e)))?;

                // Calculate the target log size (upper bound is inclusive)
                let target_log_size = config
                    .upper_bound_ops
                    .checked_add(1)
                    .ok_or(Error::InvalidState)?;

                // Check if we've completed sync
                if log_size >= target_log_size {
                    if log_size > target_log_size {
                        warn!(log_size, target_log_size, "Log size exceeded sync target");
                        return Err(Error::InvalidState);
                    }

                    // Build the complete database from the log
                    let db = adb::any::Any::init_synced(
                        config.context.clone(),
                        SyncConfig {
                            db_config: config.db_config.clone(),
                            log,
                            lower_bound: config.lower_bound_ops,
                            upper_bound: config.upper_bound_ops,
                            pinned_nodes,
                            apply_batch_size: config.apply_batch_size,
                        },
                    )
                    .await
                    .map_err(Error::Adb)?;

                    // Verify the final hash matches the target
                    let mut hasher = mmr::hasher::Standard::<H>::new();
                    let got_hash = db.root(&mut hasher);
                    if got_hash != config.target_hash {
                        return Err(Error::HashMismatch {
                            expected: Box::new(config.target_hash),
                            actual: Box::new(got_hash),
                        });
                    }

                    info!(
                        target_hash = ?config.target_hash,
                        lower_bound_ops = config.lower_bound_ops,
                        upper_bound_ops = config.upper_bound_ops,
                        log_size = log_size,
                        valid_batches_received = metrics.valid_batches_received.get(),
                        invalid_batches_received = metrics.invalid_batches_received.get(),
                        "Sync completed successfully");

                    return Ok(Client::Done { db });
                }

                // Need to fetch more
                Ok(Client::FetchData {
                    config,
                    log,
                    pinned_nodes,
                    metrics,
                })
            }

            Client::Done { .. } => Err(Error::AlreadyComplete),
        }
    }

    /// Run the complete sync process
    pub(crate) async fn sync(mut self) -> Result<adb::any::Any<E, K, V, H, T>, Error> {
        info!("Starting complete sync process");

        loop {
            self = self.step().await?;
            if let Client::Done { db } = self {
                return Ok(db);
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        adb::any::{
            sync::{resolver::tests::FailResolver, sync},
            test::{apply_ops, create_test_db, create_test_ops},
        },
        translator,
    };
    use commonware_cryptography::{sha256::Digest, Digest as _, Sha256};
    use commonware_runtime::{buffer::PoolRef, deterministic, Runner as _};
    use commonware_utils::NZU64;
    use rand::{rngs::StdRng, RngCore as _, SeedableRng as _};
    use std::collections::{HashMap, HashSet};
    use test_case::test_case;

    type TestHash = Sha256;
    type TestTranslator = translator::TwoCap;

    const PAGE_SIZE: usize = 111;
    const PAGE_CACHE_SIZE: usize = 5;

    fn create_test_hasher() -> crate::mmr::hasher::Standard<TestHash> {
        crate::mmr::hasher::Standard::<TestHash>::new()
    }

    fn create_test_config(seed: u64) -> adb::any::Config<TestTranslator> {
        adb::any::Config {
            mmr_journal_partition: format!("mmr_journal_{seed}"),
            mmr_metadata_partition: format!("mmr_metadata_{seed}"),
            mmr_items_per_blob: 1024,
            mmr_write_buffer: 64,
            log_journal_partition: format!("log_journal_{seed}"),
            log_items_per_blob: 1024,
            log_write_buffer: 64,
            translator: TestTranslator::default(),
            thread_pool: None,
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            pruning_delay: 100,
        }
    }

    #[test_case(1, NZU64!(1); "singleton db with batch size == 1")]
    #[test_case(1, NZU64!(2); "singleton db with batch size > db size")]
    #[test_case(1000, NZU64!(1); "db with batch size 1")]
    #[test_case(1000, NZU64!(3); "db size not evenly divided by batch size")]
    #[test_case(1000, NZU64!(999); "db size not evenly divided by batch size; different batch size")]
    #[test_case(1000, NZU64!(100); "db size divided by batch size")]
    #[test_case(1000, NZU64!(1000); "db size == batch size")]
    #[test_case(1000, NZU64!(1001); "batch size > db size")]
    fn test_sync(target_db_ops: usize, fetch_batch_size: NonZeroU64) {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let target_db = create_test_db(context.clone()).await;
            let target_db_ops = create_test_ops(target_db_ops);
            let mut target_db = apply_ops(target_db, target_db_ops.clone()).await;
            target_db.commit().await.unwrap();
            let target_op_count = target_db.op_count();
            let target_inactivity_floor = target_db.inactivity_floor_loc;
            let target_log_size = target_db.log.size().await.unwrap();
            let mut hasher = create_test_hasher();
            let target_hash = target_db.root(&mut hasher);

            // After commit, the database may have pruned early operations
            // Start syncing from the inactivity floor, not 0
            let lower_bound_ops = target_db.inactivity_floor_loc;

            // Capture target database state and deleted keys before moving into config
            let mut expected_kvs = HashMap::new();
            let mut deleted_keys = HashSet::new();
            for op in &target_db_ops {
                match op {
                    Operation::Update(key, _) => {
                        if let Some((value, loc)) = target_db.get_with_loc(key).await.unwrap() {
                            expected_kvs.insert(*key, (value, loc));
                            deleted_keys.remove(key);
                        }
                    }
                    Operation::Deleted(key) => {
                        expected_kvs.remove(key);
                        deleted_keys.insert(*key);
                    }
                    _ => {}
                }
            }

            let config = Config {
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size,
                target_hash,
                lower_bound_ops,
                upper_bound_ops: target_op_count - 1, // target_op_count is the count, operations are 0-indexed
                context,
                resolver: &target_db,
                hasher,
                apply_batch_size: 1024,
            };
            let got_db = sync(config).await.unwrap();

            // Verify database state
            let mut hasher = create_test_hasher();
            assert_eq!(got_db.op_count(), target_op_count);
            assert_eq!(got_db.inactivity_floor_loc, target_inactivity_floor);
            assert_eq!(got_db.log.size().await.unwrap(), target_log_size);
            assert_eq!(
                got_db.ops.pruned_to_pos(),
                leaf_num_to_pos(target_inactivity_floor)
            );

            // Verify the root hash matches the target
            assert_eq!(got_db.root(&mut hasher), target_hash);

            // Verify that the synced database matches the target state
            for (key, &(value, loc)) in &expected_kvs {
                let synced_opt = got_db.get_with_loc(key).await.unwrap();
                assert_eq!(synced_opt, Some((value, loc)));
            }
            // Verify that deleted keys are absent
            for key in &deleted_keys {
                assert!(got_db.get_with_loc(key).await.unwrap().is_none(),);
            }

            // Put more key-value pairs into both databases
            let mut new_ops = Vec::new();
            let mut rng = StdRng::seed_from_u64(42);
            let mut new_kvs = HashMap::new();
            for _ in 0..expected_kvs.len() {
                let key = Digest::random(&mut rng);
                let value = Digest::random(&mut rng);
                new_ops.push(Operation::Update(key, value));
                new_kvs.insert(key, value);
            }
            let mut got_db = apply_ops(got_db, new_ops.clone()).await;
            let mut target_db = apply_ops(target_db, new_ops).await;
            got_db.commit().await.unwrap();
            target_db.commit().await.unwrap();

            // Verify that the databases match
            for (key, value) in &new_kvs {
                let got_value = got_db.get(key).await.unwrap().unwrap();
                let target_value = target_db.get(key).await.unwrap().unwrap();
                assert_eq!(got_value, target_value);
                assert_eq!(got_value, *value);
            }
            assert_eq!(got_db.root(&mut hasher), target_db.root(&mut hasher));
        });
    }

    /// Test that invalid bounds are rejected
    #[test]
    fn test_sync_invalid_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let target_db = create_test_db(context.clone()).await;

            let config = Config {
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(10),
                target_hash: Digest::from([1u8; 32]),
                lower_bound_ops: 31, // Invalid: lower > upper
                upper_bound_ops: 30,
                context,
                resolver: &target_db,
                hasher: create_test_hasher(),
                apply_batch_size: 1024,
            };

            let result = Client::new(config).await;
            match result {
                Err(Error::InvalidTarget {
                    lower_bound_pos: 31,
                    upper_bound_pos: 30,
                }) => {
                    // Expected error
                }
                _ => panic!("Expected InvalidTarget error for invalid bounds"),
            }
        });
    }

    /// Test that sync works when target database has operations beyond the requested range
    /// of operations to sync.
    #[test]
    fn test_sync_subset_of_target_database() {
        const TARGET_DB_OPS: usize = 1000;
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(TARGET_DB_OPS);
            // Apply all but the last operation
            let mut target_db =
                apply_ops(target_db, target_ops[0..TARGET_DB_OPS - 1].to_vec()).await;
            target_db.commit().await.unwrap();

            let mut hasher = create_test_hasher();
            let upper_bound_ops = target_db.op_count() - 1;
            let target_hash = target_db.root(&mut hasher);
            let lower_bound_ops = target_db.inactivity_floor_loc;

            // Add another operation after the sync range
            let final_op = &target_ops[TARGET_DB_OPS - 1];
            let mut target_db = apply_ops(target_db, vec![final_op.clone()]).await; // TODO: this is wrong
            target_db.commit().await.unwrap();

            // Start of the sync range is after the inactivity floor
            let config = Config {
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(10),
                target_hash,
                lower_bound_ops,
                upper_bound_ops,
                context,
                resolver: &target_db,
                hasher: create_test_hasher(),
                apply_batch_size: 1024,
            };

            let synced_db = sync(config).await.unwrap();

            // Verify the synced database has the correct range of operations
            assert_eq!(synced_db.inactivity_floor_loc, lower_bound_ops);
            assert_eq!(synced_db.oldest_retained_loc(), Some(lower_bound_ops));
            assert_eq!(
                synced_db.ops.pruned_to_pos(),
                leaf_num_to_pos(lower_bound_ops)
            );
            assert_eq!(synced_db.op_count(), upper_bound_ops + 1);

            // Verify the final hash matches our target
            assert_eq!(synced_db.root(&mut hasher), target_hash);

            // Verify the synced database doesn't have any operations beyond the sync range.
            assert_eq!(
                synced_db.get(final_op.to_key().unwrap()).await.unwrap(),
                None
            );
        });
    }

    // Test syncing where the sync client has some but not all of the operations in the target
    // database.
    #[test]
    fn test_sync_use_existing_db_partial_match() {
        const ORIGINAL_DB_OPS: usize = 1_000;

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let original_ops = create_test_ops(ORIGINAL_DB_OPS);

            // Create two databases
            let mut target_db = create_test_db(context.clone()).await;
            let sync_db_config = create_test_config(1337);
            let mut sync_db = adb::any::Any::init(context.clone(), sync_db_config.clone())
                .await
                .unwrap();

            // Apply the same operations to both databases
            target_db = apply_ops(target_db, original_ops.clone()).await;
            sync_db = apply_ops(sync_db, original_ops.clone()).await;
            target_db.commit().await.unwrap();
            sync_db.commit().await.unwrap();

            let original_db_op_count = target_db.op_count();

            // Close sync_db
            sync_db.close().await.unwrap();

            // Add one more operation and commit the target database
            let last_op = create_test_ops(1);
            target_db = apply_ops(target_db, last_op.clone()).await;
            target_db.commit().await.unwrap();
            let mut hasher = create_test_hasher();
            let target_hash = target_db.root(&mut hasher);
            let lower_bound_ops = target_db.inactivity_floor_loc;
            let upper_bound_ops = target_db.op_count() - 1; // Up to the last operation

            // Reopen the sync database and sync it to the target database
            let config = Config {
                db_config: sync_db_config, // Use same config as before
                fetch_batch_size: NZU64!(10),
                target_hash,
                lower_bound_ops,
                upper_bound_ops,
                context: context.clone(),
                resolver: &target_db,
                hasher: create_test_hasher(),
                apply_batch_size: 1024,
            };
            let sync_db = sync(config).await.unwrap();

            // Verify database state
            assert_eq!(sync_db.op_count(), upper_bound_ops + 1);
            assert_eq!(sync_db.inactivity_floor_loc, target_db.inactivity_floor_loc);
            assert_eq!(sync_db.oldest_retained_loc().unwrap(), lower_bound_ops);
            assert_eq!(
                sync_db.log.size().await.unwrap(),
                target_db.log.size().await.unwrap()
            );
            assert_eq!(
                sync_db.ops.pruned_to_pos(),
                leaf_num_to_pos(lower_bound_ops)
            );
            // Verify the root hash matches the target
            assert_eq!(sync_db.root(&mut hasher), target_hash);

            // Verify that the operations in the overlapping range are present and correct
            for i in lower_bound_ops..original_db_op_count {
                let expected_op = target_db.log.read(i).await.unwrap();
                let synced_op = sync_db.log.read(i).await.unwrap();
                assert_eq!(expected_op, synced_op);
            }

            for target_op in &original_ops {
                if let Some(key) = target_op.to_key() {
                    let target_value = target_db.get(key).await.unwrap();
                    let synced_value = sync_db.get(key).await.unwrap();
                    assert_eq!(target_value, synced_value);
                }
            }
            // Verify the last operation is present
            let last_key = last_op[0].to_key().unwrap();
            let last_value = *last_op[0].to_value().unwrap();
            assert_eq!(sync_db.get(last_key).await.unwrap(), Some(last_value));

            sync_db.destroy().await.unwrap();
            target_db.destroy().await.unwrap();
        });
    }

    /// Test case where existing database on disk exactly matches the sync target
    #[test]
    fn test_sync_use_existing_db_exact_match() {
        const NUM_OPS: usize = 1_000;

        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let target_ops = create_test_ops(NUM_OPS);

            // Create two databases
            let target_config = create_test_config(context.next_u64());
            let mut target_db = adb::any::Any::init(context.clone(), target_config)
                .await
                .unwrap();
            let sync_config = create_test_config(context.next_u64());
            let mut sync_db = adb::any::Any::init(context.clone(), sync_config.clone())
                .await
                .unwrap();

            // Apply the same operations to both databases
            target_db = apply_ops(target_db, target_ops.clone()).await;
            sync_db = apply_ops(sync_db, target_ops.clone()).await;
            target_db.commit().await.unwrap();
            sync_db.commit().await.unwrap();

            target_db.sync().await.unwrap();
            sync_db.sync().await.unwrap();

            // Close sync_db
            sync_db.close().await.unwrap();

            // Reopen sync_db
            let mut hasher = create_test_hasher();
            let target_hash = target_db.root(&mut hasher);
            let lower_bound_ops = target_db.inactivity_floor_loc;
            let upper_bound_ops = target_db.op_count() - 1;
            // sync_db should never ask the resolver for operations
            // because it is already complete. Use a resolver that always fails
            // to ensure that it's not being used.
            let resolver = FailResolver::<Digest, Digest, Digest>::new();
            let config = Config {
                db_config: sync_config, // Use same config to access same partitions
                fetch_batch_size: NZU64!(10),
                target_hash,
                lower_bound_ops,
                upper_bound_ops,
                context: context.clone(),
                resolver,
                hasher: create_test_hasher(),
                apply_batch_size: 1024,
            };
            let sync_db = sync(config).await.unwrap();

            // Verify database state
            assert_eq!(sync_db.op_count(), upper_bound_ops + 1);
            assert_eq!(sync_db.op_count(), target_db.op_count());
            assert_eq!(sync_db.oldest_retained_loc().unwrap(), lower_bound_ops);
            assert_eq!(
                sync_db.log.size().await.unwrap(),
                target_db.log.size().await.unwrap()
            );
            assert_eq!(
                sync_db.ops.pruned_to_pos(),
                leaf_num_to_pos(lower_bound_ops)
            );

            // Verify the root hash matches the target
            assert_eq!(sync_db.root(&mut hasher), target_hash);

            // Verify state matches for sample operations
            for target_op in &target_ops {
                if let Some(key) = target_op.to_key() {
                    let target_value = target_db.get(key).await.unwrap();
                    let synced_value = sync_db.get(key).await.unwrap();
                    assert_eq!(target_value, synced_value);
                }
            }

            sync_db.destroy().await.unwrap();
            target_db.destroy().await.unwrap();
        });
    }
}
