use crate::{
    adb::{
        self,
        any::{
            sync::{resolver::Resolver, Error},
            SyncConfig,
        },
        operation::Operation,
    },
    index::Translator,
    journal::fixed::{Config as JConfig, Journal},
    mmr::{self, iterator::leaf_num_to_pos},
};
use commonware_cryptography::Hasher;
use commonware_runtime::{
    telemetry::metrics::histogram::Buckets, Clock, Metrics as MetricsTrait, Storage,
};
use commonware_utils::Array;
use prometheus_client::metrics::{counter::Counter, histogram::Histogram};
use std::{marker::PhantomData, num::NonZeroU64};
use tracing::{debug, info, warn};

/// Configuration for the sync client
pub struct Config<E, K, V, H, T, R>
where
    E: Storage + Clock + MetricsTrait,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<H, K, V>,
{
    /// Context for the database.
    pub context: E,

    /// Database configuration.
    pub db_config: adb::any::Config<T>,

    /// Maximum operations to fetch per batch.
    pub fetch_batch_size: NonZeroU64,

    /// Maximum number of retries for fetching operations.
    pub max_retries: u64,

    /// Target hash of the database.
    pub target_hash: H::Digest,

    /// Lower bound of operations to sync (pruning boundary, inclusive).
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

    _phantom: PhantomData<(K, V)>,
}

/// Prometheus metrics for the sync client.
pub struct Metrics {
    /// Number of valid batches successfully received and processed.
    valid_batches_received: Counter<u64>,
    /// Number of invalid batches received that failed validation.
    invalid_batches_received: Counter<u64>,
    /// Total number of operations fetched during sync.
    operations_fetched: Counter<u64>,
    /// Total time spent fetching operations from resolver (seconds).
    fetch_duration: Histogram,
    /// Total time spent verifying proofs (seconds).
    proof_verification_duration: Histogram,
    /// Total time spent applying operations to the log (seconds).
    apply_duration: Histogram,
}

impl Metrics {
    /// Register metrics with the provided runtime metrics context and return the struct.
    pub fn new<E: MetricsTrait>(context: E) -> Self {
        let metrics = Self {
            valid_batches_received: Counter::default(),
            invalid_batches_received: Counter::default(),
            operations_fetched: Counter::default(),
            fetch_duration: Histogram::new(Buckets::NETWORK.into_iter()),
            proof_verification_duration: Histogram::new(Buckets::CRYPTOGRAPHY.into_iter()),
            apply_duration: Histogram::new(Buckets::LOCAL.into_iter()),
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
            metrics.fetch_duration.clone(),
        );
        context.register(
            "proof_verification_duration_seconds",
            "Histogram of durations spent verifying proofs during ADB sync",
            metrics.proof_verification_duration.clone(),
        );
        context.register(
            "apply_duration_seconds",
            "Histogram of durations spent applying operations during ADB sync",
            metrics.apply_duration.clone(),
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
    R: Resolver<H, K, V>,
{
    /// Next step: fetch and verify proofs, holding only the pruned log.
    FetchData {
        config: Config<E, K, V, H, T, R>,
        log: Journal<E, Operation<K, V>>,
        /// Extracted pinned nodes from first batch proof
        pinned_nodes: Option<Vec<H::Digest>>,
        metrics: Metrics,
    },
    /// Apply fetched operations to the log only.
    ApplyData {
        config: Config<E, K, V, H, T, R>,
        log: Journal<E, Operation<K, V>>,
        pinned_nodes: Option<Vec<H::Digest>>,
        batch_ops: Vec<Operation<K, V>>,
        metrics: Metrics,
    },
    /// Sync completed, full database constructed.
    Done { db: adb::any::Any<E, K, V, H, T> },
}

impl<E, K, V, H, T, R> Client<E, K, V, H, T, R>
where
    E: Storage + Clock + MetricsTrait,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<H, K, V>,
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

        // Initialize only the pruned operation log. No MMR or snapshot yet.
        let log = Journal::<E, Operation<K, V>>::init_pruned(
            config.context.clone().with_label("log"),
            JConfig {
                partition: config.db_config.log_journal_partition.clone(),
                items_per_blob: config.db_config.log_items_per_blob,
                write_buffer: config.db_config.log_write_buffer,
            },
            config.lower_bound_ops,
        )
        .await
        .map_err(adb::Error::JournalError)
        .map_err(Error::Adb)?;

        // Initialize metrics
        let metrics = Metrics::new(config.context.clone());

        Ok(Client::FetchData {
            config,
            log,
            pinned_nodes: None,
            metrics,
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
                // Calculate total operations needed and current position (inclusive bounds)
                let total_ops_needed = config
                    .upper_bound_ops
                    .checked_sub(config.lower_bound_ops)
                    .ok_or(Error::InvalidTarget {
                    lower_bound_pos: config.lower_bound_ops,
                    upper_bound_pos: config.upper_bound_ops,
                })? + 1;
                // Get the absolute position of the next operation to be appended
                let next_op_loc = log.size().await.unwrap();

                // Calculate relative count of operations applied since pruning boundary
                let applied_ops =
                    next_op_loc
                        .checked_sub(config.lower_bound_ops)
                        .ok_or_else(|| {
                            warn!(
                                next_op_loc,
                                lower_bound_ops = config.lower_bound_ops,
                                "InvalidState: next_op_pos < lower_bound_ops"
                            );
                            Error::InvalidState
                        })?;

                debug!(
                    lower_bound_ops = config.lower_bound_ops,
                    upper_bound_ops = config.upper_bound_ops,
                    total_ops_needed = total_ops_needed,
                    next_op_pos = next_op_loc,
                    applied_ops = applied_ops,
                    "Calculating remaining operations"
                );

                let remaining_ops = total_ops_needed.checked_sub(applied_ops).ok_or_else(|| {
                    warn!(
                        total_ops_needed,
                        applied_ops, "InvalidState: applied_ops > total_ops_needed"
                    );
                    Error::InvalidState
                })?;

                let batch_size = std::cmp::min(config.fetch_batch_size.get(), remaining_ops);
                let batch_size = NonZeroU64::new(batch_size).ok_or(Error::InvalidState)?;

                debug!(
                    target_hash = ?config.target_hash,
                    lower_bound_pos = config.lower_bound_ops,
                    upper_bound_pos = config.upper_bound_ops,
                    next_op_loc = next_op_loc,
                    remaining_ops = remaining_ops,
                    batch_size = batch_size.get(),
                    "Fetching proof and operations"
                );

                // Get proof and operations from resolver with timing
                let fetch_start = config.context.current();
                let (proof, new_operations) =
                    config.resolver.get_proof(next_op_loc, batch_size).await?;
                let fetch_end = config.context.current();
                let fetch_secs = fetch_end
                    .duration_since(fetch_start)
                    .unwrap_or_default()
                    .as_secs_f64();
                metrics.fetch_duration.observe(fetch_secs);

                let new_operations_len = new_operations.len() as u64;

                // Validate that we didn't get more operations than requested
                // or that we didn't get an empty proof. We should never get an empty proof
                // because we will never request an empty proof (i.e. a proof over an empty database).
                if new_operations_len > batch_size.get() || new_operations_len == 0 {
                    metrics.invalid_batches_received.inc();
                    if metrics.invalid_batches_received.get() > config.max_retries {
                        return Err(Error::MaxRetriesExceeded);
                    }
                    return Ok(Client::FetchData {
                        config,
                        log,
                        pinned_nodes,
                        metrics,
                    });
                }

                debug!(
                    num_ops = new_operations_len,
                    "Received operations from resolver"
                );

                // Verify the proof is valid over the given operations with timing
                let verification_start = config.context.current();
                let proof_valid = adb::any::Any::<E, K, V, H, T>::verify_proof(
                    &mut config.hasher,
                    &proof,
                    next_op_loc,
                    &new_operations,
                    &config.target_hash,
                );
                let verification_end = config.context.current();
                let verify_secs = verification_end
                    .duration_since(verification_start)
                    .unwrap_or_default()
                    .as_secs_f64();
                metrics.proof_verification_duration.observe(verify_secs);

                if !proof_valid {
                    debug!("Proof verification failed, retrying");
                    metrics.invalid_batches_received.inc();
                    if metrics.invalid_batches_received.get() > config.max_retries {
                        return Err(Error::MaxRetriesExceeded);
                    }

                    return Ok(Client::FetchData {
                        config,
                        log,
                        pinned_nodes,
                        metrics,
                    });
                }

                // Install pinned nodes on first successful batch.
                if applied_ops == 0 {
                    let start_pos = leaf_num_to_pos(next_op_loc);
                    let end_pos = leaf_num_to_pos(next_op_loc + new_operations_len - 1);
                    let Ok(new_pinned_nodes) = proof.extract_pinned_nodes(start_pos, end_pos)
                    else {
                        warn!("Failed to extract pinned nodes, retrying");
                        metrics.invalid_batches_received.inc();
                        if metrics.invalid_batches_received.get() > config.max_retries {
                            return Err(Error::MaxRetriesExceeded);
                        }
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
                metrics.operations_fetched.inc_by(new_operations_len);

                Ok(Client::ApplyData {
                    config,
                    log,
                    pinned_nodes,
                    batch_ops: new_operations,
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
                // Apply operations to the log with timing
                let apply_start = config.context.current();
                for op in batch_ops.into_iter() {
                    log.append(op)
                        .await
                        .map_err(adb::Error::JournalError)
                        .map_err(Error::Adb)?;
                }
                let apply_end = config.context.current();
                let apply_secs = apply_end
                    .duration_since(apply_start)
                    .unwrap_or_default()
                    .as_secs_f64();
                metrics.apply_duration.observe(apply_secs);

                // No need to sync here -- we will occasionally do so on `append`
                // and then when we're done.

                // Check if we've applied all needed operations
                let next_op_loc = log.size().await.unwrap();
                let applied_ops = next_op_loc - config.lower_bound_ops;
                let total_ops_needed = config.upper_bound_ops - config.lower_bound_ops + 1;

                if applied_ops >= total_ops_needed {
                    // Build the complete database from the log
                    let db = adb::any::Any::init_pruned(
                        config.context.clone(),
                        SyncConfig {
                            db_config: config.db_config.clone(),
                            log,
                            pruned_to_loc: config.lower_bound_ops,
                            pinned_nodes: pinned_nodes.unwrap(),
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
            sync::sync,
            test::{apply_ops, create_test_db, create_test_ops},
        },
        index,
        mmr::verification::Proof,
    };
    use commonware_cryptography::{sha256::Digest, Digest as _, Sha256};
    use commonware_runtime::{deterministic, Runner as _};
    use commonware_utils::NZU64;
    use rand::{rngs::StdRng, RngCore as _, SeedableRng as _};
    use std::{
        collections::{HashMap, HashSet},
        sync::{atomic::AtomicU64, Arc},
    };
    use test_case::test_case;

    type TestHash = Sha256;
    type TestKey = Digest;
    type TestValue = Digest;
    type TestTranslator = index::translator::EightCap;

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
            pool: None,
        }
    }

    #[test_case(1, NZU64!(1))]
    #[test_case(1, NZU64!(2))]
    #[test_case(10, NZU64!(1))]
    #[test_case(10, NZU64!(3))]
    #[test_case(250, NZU64!(1))]
    #[test_case(250, NZU64!(100))]
    #[test_case(250, NZU64!(251))]
    #[test_case(1000, NZU64!(1))]
    #[test_case(1000, NZU64!(3))]
    #[test_case(1000, NZU64!(100))]
    #[test_case(1000, NZU64!(1000))]
    #[test_case(1000, NZU64!(1001))]
    #[test_case(10_000, NZU64!(13))]
    fn test_sync(target_db_ops: usize, fetch_batch_size: NonZeroU64) {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let target_db = create_test_db(context.clone()).await;
            let target_db_ops = create_test_ops(target_db_ops);
            let mut target_db = apply_ops(target_db, target_db_ops.clone()).await;
            target_db.commit().await.unwrap();
            let target_op_count = target_db.op_count();
            let target_inactivity_floor = target_db.inactivity_floor_loc;
            let target_pruned_pos = target_db.ops.pruned_to_pos();
            let target_log_size = target_db.log.size().await.unwrap();
            let mut hasher = create_test_hasher();
            let target_hash = target_db.root(&mut hasher);

            // After commit, the database may have pruned early operations
            // Start syncing from the oldest retained location, not 0
            let lower_bound_ops = target_db.oldest_retained_loc().unwrap();

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
                max_retries: 0,
                target_hash,
                lower_bound_ops,
                upper_bound_ops: target_op_count - 1, // target_op_count is the count, operations are 0-indexed
                context,
                resolver: &mut target_db,
                hasher,
                apply_batch_size: 1024,
                _phantom: PhantomData,
            };
            let got_db = sync(config).await.unwrap();
            let mut hasher = create_test_hasher();
            assert_eq!(got_db.root(&mut hasher), target_hash);
            assert_eq!(got_db.op_count(), target_op_count);
            assert_eq!(got_db.inactivity_floor_loc, target_inactivity_floor);
            assert_eq!(got_db.ops.pruned_to_pos(), target_pruned_pos);
            assert_eq!(got_db.log.size().await.unwrap(), target_log_size);

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

    /// A simple resolver that always returns too many operations to trigger retry logic.
    /// Increments `call_count` on each call to `get_proof`.
    struct FailingResolver {
        call_count: std::sync::Arc<std::sync::atomic::AtomicU64>,
    }

    impl FailingResolver {
        fn new(call_count: std::sync::Arc<std::sync::atomic::AtomicU64>) -> Self {
            Self { call_count }
        }
    }

    impl Resolver<TestHash, TestKey, TestValue> for FailingResolver {
        async fn get_proof(
            &mut self,
            _start_index: u64,
            max_ops: NonZeroU64,
        ) -> Result<
            (
                Proof<<TestHash as Hasher>::Digest>,
                Vec<Operation<TestKey, TestValue>>,
            ),
            Error,
        > {
            self.call_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

            // Return more operations than requested to trigger retry logic
            let mut ops = Vec::new();
            for i in 0..(max_ops.get() + 1) {
                ops.push(Operation::Update(
                    TestKey::from([(i % 256) as u8; 32]),
                    TestValue::from([0u8; 32]),
                ));
            }

            Ok((
                Proof {
                    size: 1,
                    digests: vec![Digest::from([0u8; 32])],
                },
                ops,
            ))
        }
    }

    /// Test that we return an error after max_retries attempts to get a proof fail.
    #[test]
    fn test_sync_max_retries() {
        const MAX_RETRIES: u64 = 2;
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let get_proof_call_count = Arc::new(AtomicU64::new(0));
            let resolver = FailingResolver::new(get_proof_call_count.clone());
            let config = Config {
                db_config: create_test_config(context.next_u64()),
                fetch_batch_size: NZU64!(10),
                max_retries: MAX_RETRIES,
                target_hash: Digest::from([1u8; 32]),
                lower_bound_ops: 0,
                upper_bound_ops: 100,
                context,
                resolver,
                hasher: create_test_hasher(),
                apply_batch_size: 1024,
                _phantom: PhantomData,
            };

            let result = sync(config).await;

            // Should fail after max_retries attempts
            match result {
                Err(Error::MaxRetriesExceeded) => {}
                _ => panic!("Expected MaxRetriesExceeded error for max retries exceeded"),
            }
            // Verify we made max_retries + 1 calls before giving up
            assert_eq!(
                get_proof_call_count.load(std::sync::atomic::Ordering::SeqCst),
                MAX_RETRIES + 1
            );
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
                max_retries: 0,
                target_hash: Digest::from([1u8; 32]),
                lower_bound_ops: 31, // Invalid: lower > upper
                upper_bound_ops: 30,
                context,
                resolver: target_db,
                hasher: create_test_hasher(),
                apply_batch_size: 1024,
                _phantom: PhantomData,
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
}
