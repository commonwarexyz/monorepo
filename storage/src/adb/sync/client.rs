use crate::{
    adb::{
        self,
        operation::Operation,
        sync::{resolver::Resolver, Error},
    },
    index::Translator,
    mmr::{self, iterator::leaf_num_to_pos, verification::Proof},
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics as MetricsTrait, Storage};
use commonware_utils::Array;
use std::{collections::HashMap, marker::PhantomData, num::NonZeroU64};
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
    /// Next step is to fetch data from resolver.
    FetchData {
        config: Config<E, K, V, H, T, R>,
        db: adb::any::Any<E, K, V, H, T>,
        applied_ops: u64,
        metrics: Metrics,
    },
    /// Apply operations of the latest verified batch.
    ApplyData {
        config: Config<E, K, V, H, T, R>,
        db: adb::any::Any<E, K, V, H, T>,
        batch_ops: Vec<Operation<K, V>>,
        applied_ops: u64,
        metrics: Metrics,
    },
    /// Sync completed.
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

        // Create an empty pruned database. Pinned nodes will be installed after the first proof.
        let db = adb::any::Any::<E, K, V, H, T>::init_pruned(
            config.context.clone(),
            crate::adb::any::SyncConfig {
                config: config.db_config.clone(),
                pruned_to_loc: config.lower_bound_ops,
            },
        )
        .await
        .map_err(Error::DatabaseInitFailed)?;

        Ok(Client::FetchData {
            config,
            db,
            applied_ops: 0,
            metrics: Metrics {
                valid_batches_received: 0,
                invalid_batches_received: 0,
            },
        })
    }

    /// Process the next step in the sync process
    async fn step(self) -> Result<Self, Error> {
        match self {
            Client::FetchData {
                mut config,
                mut db,
                applied_ops,
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
                let remaining_ops = total_ops_needed
                    .checked_sub(applied_ops)
                    .ok_or(Error::InvalidState)?;

                let batch_size = std::cmp::min(config.max_ops_per_batch.get(), remaining_ops);
                let batch_size = NonZeroU64::new(batch_size).ok_or(Error::InvalidState)?;

                // Current position in the global operation sequence
                let current_global_pos = config.lower_bound_ops + applied_ops;

                debug!(
                    target_hash = ?config.target_hash,
                    lower_bound_pos = config.lower_bound_ops,
                    upper_bound_pos = config.upper_bound_ops,
                    current_global_pos = current_global_pos,
                    remaining_ops = remaining_ops,
                    batch_size = batch_size.get(),
                    "Fetching proof and operations"
                );

                // Get proof and operations from resolver.
                let (proof, new_operations) = config
                    .resolver
                    .get_proof(current_global_pos, batch_size)
                    .await?;
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
                        db,
                        applied_ops,
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
                    current_global_pos,
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
                        db,
                        applied_ops,
                        metrics,
                    });
                }

                // Install pinned nodes on first successful batch.
                if applied_ops == 0 {
                    let start_pos = leaf_num_to_pos(current_global_pos);
                    let end_pos = leaf_num_to_pos(current_global_pos + new_operations_len - 1);
                    match proof.extract_pinned_nodes(start_pos, end_pos) {
                        Ok(new_pinned_nodes) => {
                            let nodes_to_pin =
                                Proof::<H::Digest>::nodes_to_pin(start_pos).collect::<Vec<_>>();
                            assert_eq!(nodes_to_pin.len(), new_pinned_nodes.len());
                            let pinned_nodes =
                                HashMap::from_iter(nodes_to_pin.into_iter().zip(new_pinned_nodes));
                            db.set_pinned_nodes(pinned_nodes);
                        }
                        Err(_) => {
                            warn!("Failed to extract pinned nodes, retrying");
                            metrics.invalid_batches_received += 1;
                            if metrics.invalid_batches_received > config.max_retries {
                                return Err(Error::MaxRetriesExceeded);
                            }
                            return Ok(Client::FetchData {
                                config,
                                db,
                                applied_ops,
                                metrics,
                            });
                        }
                    }
                }

                metrics.valid_batches_received += 1;
                Ok(Client::ApplyData {
                    config,
                    db: db,
                    batch_ops: new_operations,
                    applied_ops,
                    metrics,
                })
            }

            Client::ApplyData {
                mut config,
                mut db,
                batch_ops,
                mut applied_ops,
                metrics,
            } => {
                // Apply each operation
                let batch_len = batch_ops.len() as u64;
                for op in batch_ops.into_iter() {
                    db.replay_logged_op(op)
                        .await
                        .map_err(Error::DatabaseInitFailed)?;
                }
                applied_ops += batch_len;

                // Flush dirty nodes so that future root computations won't panic.
                // TODO danlaine: make sure writes result in consistent state.
                db.sync().await.map_err(Error::DatabaseInitFailed)?;

                if applied_ops >= (config.upper_bound_ops - config.lower_bound_ops + 1) {
                    let got_hash = db.root(&mut config.hasher);
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
                    db,
                    applied_ops,
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
        index,
        mmr::verification::Proof,
    };
    use commonware_cryptography::{sha256::Digest, Digest as _, Sha256};
    use commonware_runtime::{
        deterministic::{self, Context},
        Runner as _,
    };
    use commonware_utils::NZU64;
    use rand::{rngs::StdRng, RngCore as _, SeedableRng as _};
    use std::{
        collections::HashMap,
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
            let target_ops = target_db.op_count();
            let mut hasher = create_test_hasher();
            let target_hash = target_db.root(&mut hasher);

            // After commit, the database may have pruned early operations
            // Start syncing from the oldest retained location, not 0
            let lower_bound_ops = target_db.oldest_retained_loc().unwrap();

            // Get target database state before moving it into the config
            let mut target_key_values = HashMap::new();
            for op in &target_db_ops {
                if let Operation::Update(key, _) = op {
                    let value = target_db.get(key).await.unwrap();
                    target_key_values.insert(*key, value);
                }
            }

            let config = Config {
                db_config: create_test_config(context.next_u64()),
                max_ops_per_batch,
                max_retries: 0,
                target_hash,
                lower_bound_ops,
                upper_bound_ops: target_ops - 1, // target_ops is the count, operations are 0-indexed
                context,
                resolver: target_db,
                hasher,
                _phantom: PhantomData,
            };
            let got_db = sync(config).await.unwrap();
            let mut hasher = create_test_hasher();
            assert_eq!(got_db.root(&mut hasher), target_hash);
            assert_eq!(got_db.op_count(), target_ops);

            // Verify that the synced database produces the same final state
            // by checking that all keys match the target database state
            for (key, target_value) in target_key_values {
                let synced_value = got_db.get(&key).await.unwrap();
                assert_eq!(target_value, synced_value, "Mismatch for key {key}");
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
}
