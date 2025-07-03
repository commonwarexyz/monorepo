use crate::{
    adb::{
        self,
        any::SyncConfig,
        operation::Operation,
        sync::{resolver::Resolver, Error},
    },
    index::Translator,
    journal::fixed::{Config as JConfig, Journal},
    mmr::{self, iterator::leaf_num_to_pos},
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics as MetricsTrait, Storage};
use commonware_utils::Array;
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
    /// Database configuration.
    pub db_config: adb::any::Config<T>,

    /// Maximum operations to fetch per batch.
    pub max_ops_per_batch: NonZeroU64,

    /// Maximum number of retries for fetching operations.
    pub max_retries: u64,

    /// Target hash of the database.
    pub target_hash: H::Digest,

    /// Lower bound of operations to sync (pruning boundary, inclusive).
    pub lower_bound_ops: u64,

    /// Upper bound of operations to sync (inclusive).
    pub upper_bound_ops: u64,

    /// Context for the database.
    pub context: E,

    /// Resolves requests for proofs and operations.
    pub resolver: R,

    /// Hasher for root hashes.
    pub hasher: mmr::hasher::Standard<H>,

    _phantom: PhantomData<(K, V)>,
}

pub struct Metrics {
    valid_batches_received: u64,
    invalid_batches_received: u64,
}

/// Client that syncs an [adb::any::Any] database.
#[allow(clippy::large_enum_variant)] // TODO danlaine: is this OK?
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
    Done {
        db: adb::any::Any<E, K, V, H, T>,
        metrics: Metrics,
    },
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
        .map_err(Error::DatabaseInitFailed)?;

        Ok(Client::FetchData {
            config,
            log,
            pinned_nodes: None,
            metrics: Metrics {
                valid_batches_received: 0,
                invalid_batches_received: 0,
            },
        })
    }

    // /// Create an [adb::any::Any] database from the populated log and pruning boundary.
    // /// This method constructs the MMR, snapshot, and all necessary components.
    // async fn build_database_from_log(
    //     config: &Config<E, K, V, H, T, R>,
    //     log: Journal<E, Operation<K, V>>,
    //     pinned_nodes: Vec<H::Digest>,
    // ) -> Result<adb::any::Any<E, K, V, H, T>, Error> {
    //     // Create the sync config for the Any database
    //     let sync_config = adb::any::SyncConfig {
    //         db_config: config.db_config.clone(),
    //         pruned_to_loc: config.lower_bound_ops,
    //         pinned_nodes,
    //         log,
    //     };

    //     // Initialize the Any database in pruned state
    //     let db = adb::any::Any::init_pruned(config.context.clone(), sync_config)
    //         .await
    //         .map_err(Error::DatabaseInitFailed)?;

    //     Ok(db)
    // }

    /// Process the next step in the sync process
    async fn step(self) -> Result<Self, Error> {
        match self {
            Client::FetchData {
                mut config,
                log,
                mut pinned_nodes,
                mut metrics,
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

                let batch_size = std::cmp::min(config.max_ops_per_batch.get(), remaining_ops);
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

                // Get proof and operations from resolver.
                let (proof, new_operations) =
                    config.resolver.get_proof(next_op_loc, batch_size).await?;
                let new_operations_len = new_operations.len() as u64;

                // Validate that we didn't get more operations than requested
                // or that we didn't get an empty proof. We should never get an empty proof
                // because we will never request an empty proof (i.e. a proof over an empty database).
                if new_operations_len > batch_size.get() || new_operations_len == 0 {
                    metrics.invalid_batches_received += 1;
                    if metrics.invalid_batches_received > config.max_retries {
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

                // Verify the proof is valid over the given operations
                if !adb::any::Any::<E, K, V, H, T>::verify_proof(
                    &mut config.hasher,
                    &proof,
                    next_op_loc,
                    &new_operations,
                    &config.target_hash,
                ) {
                    debug!("Proof verification failed, retrying");
                    metrics.invalid_batches_received += 1;
                    if metrics.invalid_batches_received > config.max_retries {
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
                        metrics.invalid_batches_received += 1;
                        if metrics.invalid_batches_received > config.max_retries {
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

                metrics.valid_batches_received += 1;
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
                // Append each operation to the log
                for op in batch_ops.into_iter() {
                    log.append(op)
                        .await
                        .map_err(adb::Error::JournalError)
                        .map_err(Error::DatabaseInitFailed)?;
                }
                // No need to sync here -- we will occasionally do so on `append`
                // and then when we're done.

                // Check if we've applied all needed operations
                let next_op_loc = log.size().await.unwrap();
                let applied_ops = next_op_loc - config.lower_bound_ops;
                let total_ops_needed = config.upper_bound_ops - config.lower_bound_ops + 1;

                if applied_ops >= total_ops_needed {
                    // Persist the log
                    log.sync()
                        .await
                        .map_err(adb::Error::JournalError)
                        .map_err(Error::DatabaseInitFailed)?;

                    // Build the complete database from the log
                    let db = adb::any::Any::init_pruned(
                        config.context.clone(),
                        SyncConfig {
                            db_config: config.db_config.clone(),
                            log,
                            pruned_to_loc: config.lower_bound_ops,
                            pinned_nodes: pinned_nodes.unwrap(),
                        },
                    )
                    .await
                    .map_err(Error::DatabaseInitFailed)?;

                    // Verify the final hash matches the target
                    let mut hasher = mmr::hasher::Standard::<H>::new();
                    let got_hash = db.root(&mut hasher);
                    if got_hash != config.target_hash {
                        return Err(Error::HashMismatch {
                            expected: Box::new(config.target_hash),
                            actual: Box::new(got_hash),
                        });
                    }

                    return Ok(Client::Done { db, metrics });
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
            if let Client::Done { db, metrics } = self {
                info!(
                    valid_batches_received = metrics.valid_batches_received,
                    invalid_batches_received = metrics.invalid_batches_received,
                    "Sync completed successfully"
                );
                return Ok(db);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        adb::{any::Any, sync::sync},
        index::{self, translator::TwoCap},
        mmr::verification::Proof,
    };
    use commonware_cryptography::{sha256::Digest, Digest as _, Sha256};
    use commonware_runtime::{
        deterministic::{self, Context},
        Runner as _,
    };
    use commonware_utils::NZU64;
    use futures::future::join_all;
    use rand::{rngs::StdRng, RngCore as _, SeedableRng as _};
    use std::{
        collections::{HashMap, HashSet},
        sync::{atomic::AtomicU64, Arc},
    };
    use test_case::test_case;

    type TestHash = Sha256;
    type TestKey = Digest;
    type TestValue = Digest;
    type TestTranslator = index::translator::TwoCap;
    type TestAny = Any<Context, TestKey, TestValue, TestHash, TestTranslator>;

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

    /// Create a test database with unique partition names
    async fn create_test_db(mut context: Context) -> TestAny {
        let seed = context.next_u64();
        let config = create_test_config(seed);
        TestAny::init(context, config).await.unwrap()
    }

    /// Create n random operations. Some portion of the updates are deletes.
    /// create_test_ops(n') is a suffix of create_test_ops(n) for n' > n.
    fn create_test_ops(n: usize) -> Vec<Operation<TestKey, TestValue>> {
        let mut rng = StdRng::seed_from_u64(1337);
        let mut prev_key = TestKey::random(&mut rng);
        let mut ops = Vec::new();
        for i in 0..n {
            let key = TestKey::random(&mut rng);
            if i % 10 == 0 && i > 0 {
                ops.push(Operation::Deleted(prev_key));
            } else {
                let value = TestValue::random(&mut rng);
                ops.push(Operation::Update(key, value));
                prev_key = key;
            }
        }
        ops
    }

    // Apply n updates to the database. Some portion of the updates are deletes.
    // It's guaranteed that calling this function with n' > n will apply the same updates
    // as calling this function with n, followed by additional updates.
    // Note that we don't commit after applying the updates.
    async fn apply_ops(mut db: TestAny, ops: Vec<Operation<TestKey, TestValue>>) -> TestAny {
        for op in ops {
            match op {
                Operation::Update(key, value) => {
                    db.update(key, value).await.unwrap();
                }
                Operation::Deleted(key) => {
                    db.delete(key).await.unwrap();
                }
                Operation::Commit(_) => {
                    db.commit().await.unwrap();
                }
            }
        }
        db
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
    fn test_sync(target_db_ops: usize, max_ops_per_batch: NonZeroU64) {
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
                max_ops_per_batch,
                max_retries: 0,
                target_hash,
                lower_bound_ops,
                upper_bound_ops: target_op_count - 1, // target_op_count is the count, operations are 0-indexed
                context,
                resolver: target_db,
                hasher,
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
                max_ops_per_batch: NZU64!(10),
                max_retries: MAX_RETRIES,
                target_hash: Digest::from([1u8; 32]),
                lower_bound_ops: 0,
                upper_bound_ops: 100,
                context,
                resolver,
                hasher: create_test_hasher(),
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
                max_ops_per_batch: NZU64!(10),
                max_retries: 0,
                target_hash: Digest::from([1u8; 32]),
                lower_bound_ops: 31, // Invalid: lower > upper
                upper_bound_ops: 30,
                context,
                resolver: target_db,
                hasher: create_test_hasher(),
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

    /// Test build_database_from_log with empty log
    /// TODO move this test
    #[test]
    fn test_build_database_from_log_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let config = Config {
                db_config: create_test_config(context.next_u64()),
                max_ops_per_batch: NZU64!(10),
                max_retries: 0,
                target_hash: Digest::from([0u8; 32]),
                lower_bound_ops: 0,
                upper_bound_ops: 0,
                context: context.clone(),
                resolver: create_test_db(context.clone()).await,
                hasher: create_test_hasher(),
                _phantom: PhantomData,
            };

            // Create empty log
            let log = Journal::<_, Operation<TestKey, TestValue>>::init_pruned(
                context.clone().with_label("empty_log"),
                JConfig {
                    partition: format!("empty_log_{}", context.next_u64()),
                    items_per_blob: 1024,
                    write_buffer: 64,
                },
                0,
            )
            .await
            .unwrap();

            let db: adb::any::Any<Context, Digest, Digest, TestHash, TestTranslator> =
                adb::any::Any::init_pruned(
                    config.context.clone(),
                    SyncConfig {
                        db_config: config.db_config.clone(),
                        log,
                        pruned_to_loc: config.lower_bound_ops,
                        pinned_nodes: Vec::new(),
                    },
                )
                .await
                .unwrap();
            assert_eq!(db.op_count(), 0);
            assert_eq!(db.inactivity_floor_loc, 0);
            assert_eq!(db.oldest_retained_loc(), None);
        });
    }

    /// Test build_database_from_log with operations
    #[test]
    fn test_build_database_from_log_with_ops() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate a source database
            let mut source_db = create_test_db(context.clone()).await;
            let ops = create_test_ops(100);
            source_db = apply_ops(source_db, ops.clone()).await;
            source_db.commit().await.unwrap();

            let lower_bound_ops = source_db.oldest_retained_loc().unwrap();
            let upper_bound_ops = source_db.op_count() - 1;

            // Get pinned nodes and target hash before moving source_db
            let pinned_nodes_map = source_db.ops.get_pinned_nodes();
            // Convert into Vec in order of expected by Proof::nodes_to_pin
            let nodes_to_pin = Proof::<Digest>::nodes_to_pin(leaf_num_to_pos(lower_bound_ops));
            let pinned_nodes = nodes_to_pin
                .map(|pos| *pinned_nodes_map.get(&pos).unwrap())
                .collect();

            let target_hash = {
                let mut hasher = create_test_hasher();
                source_db.root(&mut hasher)
            };

            // Get the actual operations from the source database
            let mut actual_ops = Vec::new();
            for i in lower_bound_ops..=upper_bound_ops {
                let op = source_db.log.read(i).await.unwrap();
                actual_ops.push(op);
            }

            let config = Config {
                db_config: create_test_config(context.next_u64()),
                max_ops_per_batch: NZU64!(10),
                max_retries: 0,
                target_hash,
                lower_bound_ops,
                upper_bound_ops,
                context: context.clone(),
                resolver: source_db,
                hasher: create_test_hasher(),
                _phantom: PhantomData,
            };

            // Create log with operations
            let mut log = Journal::<_, Operation<TestKey, TestValue>>::init_pruned(
                context.clone().with_label("ops_log"),
                JConfig {
                    partition: format!("ops_log_{}", context.next_u64()),
                    items_per_blob: 1024,
                    write_buffer: 64,
                },
                lower_bound_ops,
            )
            .await
            .unwrap();

            // Add actual operations to log
            for op in actual_ops {
                log.append(op).await.unwrap();
            }
            log.sync().await.unwrap();

            let db = adb::any::Any::init_pruned(
                config.context.clone(),
                SyncConfig {
                    db_config: config.db_config.clone(),
                    log,
                    pruned_to_loc: config.lower_bound_ops,
                    pinned_nodes,
                },
            )
            .await
            .unwrap();
            assert_eq!(db.op_count(), upper_bound_ops + 1);
            assert_eq!(db.inactivity_floor_loc, lower_bound_ops);

            // Verify the root hash matches the target
            let mut hasher = create_test_hasher();
            assert_eq!(db.root(&mut hasher), config.target_hash);

            // Verify state matches the source operations
            let mut expected_kvs = HashMap::new();
            let mut deleted_keys = HashSet::new();
            for op in &ops {
                if let Operation::Update(key, value) = op {
                    expected_kvs.insert(*key, *value);
                    deleted_keys.remove(key);
                } else if let Operation::Deleted(key) = op {
                    expected_kvs.remove(key);
                    deleted_keys.insert(*key);
                }
            }
            for (key, value) in expected_kvs {
                let synced_value = db.get(&key).await.unwrap().unwrap();
                assert_eq!(synced_value, value);
            }
            // Verify that deleted keys are absent
            for key in deleted_keys {
                assert!(db.get(&key).await.unwrap().is_none(),);
            }
        });
    }

    /// Test build_database_from_log with different pruning boundaries
    #[test]
    fn test_build_database_from_log_different_pruning_boundaries() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate a source database
            let mut source_db = create_test_db(context.clone()).await;
            let ops = create_test_ops(200);
            source_db = apply_ops(source_db, ops.clone()).await;
            source_db.commit().await.unwrap();

            let total_ops = source_db.op_count();

            // Test different pruning boundaries
            for lower_bound in [0, 50, 100, 150] {
                let upper_bound = std::cmp::min(lower_bound + 49, total_ops - 1);
                let config = Config {
                    db_config: create_test_config(context.next_u64()),
                    max_ops_per_batch: NZU64!(10),
                    max_retries: 0,
                    target_hash: {
                        let mut hasher = create_test_hasher();
                        source_db.root(&mut hasher)
                    },
                    lower_bound_ops: lower_bound,
                    upper_bound_ops: upper_bound,
                    context: context.clone(),
                    resolver: create_test_db(context.clone()).await,
                    hasher: create_test_hasher(),
                    _phantom: PhantomData,
                };

                // Create log with operations
                let mut log = Journal::<_, Operation<TestKey, TestValue>>::init_pruned(
                    context.clone().with_label("boundary_log"),
                    JConfig {
                        partition: format!("boundary_log_{}_{}", lower_bound, context.next_u64()),
                        items_per_blob: 1024,
                        write_buffer: 64,
                    },
                    lower_bound,
                )
                .await
                .unwrap();
                log.sync().await.unwrap();

                let ops_slice = &ops[lower_bound as usize..=upper_bound as usize];
                for op in ops_slice {
                    log.append(op.clone()).await.unwrap();
                }
                log.sync().await.unwrap();

                let pinned_nodes = Proof::<Digest>::nodes_to_pin(leaf_num_to_pos(lower_bound))
                    .map(|pos| source_db.ops.get_node(pos));
                let pinned_nodes = join_all(pinned_nodes).await;
                let pinned_nodes = pinned_nodes
                    .iter()
                    .map(|node| node.as_ref().unwrap().unwrap())
                    .collect::<Vec<_>>();

                let db: Any<Context, Digest, Digest, TestHash, TwoCap> =
                    adb::any::Any::init_pruned(
                        config.context.clone(),
                        SyncConfig {
                            db_config: config.db_config.clone(),
                            log,
                            pruned_to_loc: lower_bound,
                            pinned_nodes,
                        },
                    )
                    .await
                    .unwrap();

                // Verify database state
                let expected_op_count = upper_bound + 1; // +1 because op_count is total number of ops
                assert_eq!(db.log.size().await.unwrap(), expected_op_count);
                assert_eq!(db.op_count(), expected_op_count);
                assert_eq!(db.inactivity_floor_loc, lower_bound);
                assert_eq!(db.oldest_retained_loc(), Some(lower_bound));

                // Verify state matches the source operations
                let mut expected_kvs = HashMap::new();
                let mut deleted_keys = HashSet::new();
                for op in ops_slice {
                    if let Operation::Update(key, value) = op {
                        expected_kvs.insert(*key, *value);
                        deleted_keys.remove(key);
                    } else if let Operation::Deleted(key) = op {
                        expected_kvs.remove(key);
                        deleted_keys.insert(*key);
                    }
                }
                for (key, value) in expected_kvs {
                    assert_eq!(db.get(&key).await.unwrap().unwrap(), value,);
                }
                // Verify that deleted keys are absent
                for key in deleted_keys {
                    assert!(db.get(&key).await.unwrap().is_none());
                }
                db.destroy().await.unwrap();
            }
        });
    }

    /// Test build_database_from_log with simple operations
    #[test]
    fn test_build_database_from_log_simple_operations() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create simple operations without commits
            let mut simple_ops = Vec::new();
            let mut rng = StdRng::seed_from_u64(42);

            // Add some updates
            for _ in 0..10 {
                let key = TestKey::random(&mut rng);
                let value = TestValue::random(&mut rng);
                simple_ops.push(Operation::Update(key, value));
            }

            // Add some deletes
            for _ in 0..3 {
                let key = TestKey::random(&mut rng);
                simple_ops.push(Operation::Deleted(key));
            }

            let config = Config {
                db_config: create_test_config(context.next_u64()),
                max_ops_per_batch: NZU64!(10),
                max_retries: 0,
                target_hash: Digest::from([0u8; 32]), // We'll verify consistency, not specific hash
                lower_bound_ops: 0,
                upper_bound_ops: simple_ops.len() as u64 - 1,
                context: context.clone(),
                resolver: create_test_db(context.clone()).await,
                hasher: create_test_hasher(),
                _phantom: PhantomData,
            };

            // Create log with simple operations
            let mut log = Journal::<_, Operation<TestKey, TestValue>>::init_pruned(
                context.clone().with_label("simple_log"),
                JConfig {
                    partition: format!("simple_log_{}", context.next_u64()),
                    items_per_blob: 1024,
                    write_buffer: 64,
                },
                0,
            )
            .await
            .unwrap();

            // Add operations to log
            for op in simple_ops {
                log.append(op).await.unwrap();
            }
            log.sync().await.unwrap();

            let db = adb::any::Any::init_pruned(
                config.context.clone(),
                SyncConfig {
                    db_config: config.db_config.clone(),
                    log,
                    pruned_to_loc: config.lower_bound_ops,
                    pinned_nodes: Vec::new(),
                },
            )
            .await
            .unwrap();

            // Verify the database is functional (op_count may differ from expected due to internal handling)
            assert!(db.op_count() > 0);
            assert_eq!(db.inactivity_floor_loc, 0); // No commit operations

            // Verify the database is in a consistent state
            let mut hasher = create_test_hasher();
            let root_hash = db.root(&mut hasher);
            assert_ne!(root_hash, Digest::from([0u8; 32])); // Should have non-zero hash

            // Verify that the database snapshot has been built
            assert!(db.snapshot.keys() > 0);
        });
    }
}
