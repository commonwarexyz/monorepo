use crate::{resolver::Resolver, Error};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics as MetricsTrait, Storage};
use commonware_storage::{
    adb::{self, operation::Operation},
    index::Translator,
};
use commonware_utils::Array;
use std::{marker::PhantomData, num::NonZeroU64};
use tracing::{debug, info};

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

    /// Target operations to sync.
    pub target_ops: u64,

    /// Context for the database.
    pub context: E,

    /// Resolves requests for proofs and operations.
    pub resolver: R,

    /// Hasher for root hashes.
    pub hasher: commonware_storage::mmr::hasher::Standard<H>,

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
    /// The next step is to fetch data.
    FetchData {
        config: Config<E, K, V, H, T, R>,
        operations: Vec<Operation<K, V>>,
        metrics: Metrics,
    },
    /// We're done fetching data.
    /// The next step is to apply the fetched data to the local database.
    ApplyData {
        config: Config<E, K, V, H, T, R>,
        operations: Vec<Operation<K, V>>,
        metrics: Metrics,
    },
    /// We're done syncing.
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
    pub(crate) fn new(config: Config<E, K, V, H, T, R>) -> Result<Self, Error> {
        Ok(Client::FetchData {
            config,
            operations: vec![],
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
                mut operations,
                mut metrics,
            } => {
                // Calculate how many operations we need
                let current_ops = operations.len() as u64;
                let remaining_ops = config
                    .target_ops
                    .checked_sub(current_ops)
                    .and_then(NonZeroU64::new)
                    .ok_or(Error::InvalidState)?;
                let batch_size = std::cmp::min(config.max_ops_per_batch, remaining_ops);

                debug!(
                    ?config.target_hash,
                    config.target_ops,
                    remaining_ops,
                    batch_size,
                    "Fetching proof and operations"
                );

                let (proof, new_operations) =
                    config.resolver.get_proof(current_ops, batch_size).await?;

                // Validate that we didn't get more operations than requested
                if new_operations.len() as u64 > batch_size.get() {
                    // TODO danlaine: add more comprehensive retry logic
                    metrics.invalid_batches_received += 1;
                    if metrics.invalid_batches_received > config.max_retries {
                        return Err(Error::InvalidResolver(
                            "Max retries reached for fetching operations".to_string(),
                        ));
                    }

                    return Ok(Client::FetchData {
                        config,
                        operations,
                        metrics,
                    });
                }

                debug!(
                    num_ops = new_operations.len(),
                    "Received operations from resolver"
                );

                if !adb::any::Any::<E, K, V, H, T>::verify_proof(
                    &mut config.hasher,
                    &proof,
                    current_ops,
                    &new_operations,
                    &config.target_hash,
                ) {
                    debug!("Proof verification failed, retrying");
                    metrics.invalid_batches_received += 1;
                    if metrics.invalid_batches_received > config.max_retries {
                        return Err(Error::InvalidResolver(
                            "Max retries reached for verifying proof".to_string(),
                        ));
                    }

                    return Ok(Client::FetchData {
                        config,
                        operations,
                        metrics,
                    });
                }
                operations.extend(new_operations);

                metrics.valid_batches_received += 1;
                let next_state = if operations.len() as u64 >= config.target_ops {
                    Client::ApplyData {
                        config,
                        operations,
                        metrics,
                    }
                } else {
                    Client::FetchData {
                        config,
                        operations,
                        metrics,
                    }
                };
                Ok(next_state)
            }

            Client::ApplyData {
                mut config,
                operations,
                metrics,
            } => {
                let db = adb::any::Any::<E, K, V, H, T>::init_sync(
                    config.context,
                    adb::any::SyncConfig {
                        config: config.db_config,
                        mmr_pinned_nodes: Default::default(), // TODO danlaine: support pruning
                        pruned_to_loc: 0,                     // TODO danlaine: support pruning
                        operations,
                    },
                )
                .await
                .map_err(|e| Error::InvalidResolver(e.to_string()))?; // TODO danlaine: handle this error

                let got_hash = db.root(&mut config.hasher);
                if got_hash != config.target_hash {
                    return Err(Error::HashMismatch {
                        expected: Box::new(config.target_hash),
                        actual: Box::new(got_hash),
                    });
                }

                Ok(Client::Done { db, metrics })
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
    use crate::sync;
    use commonware_cryptography::{sha256::Digest, Digest as _, Sha256};
    use commonware_runtime::{
        deterministic::{self, Context},
        Runner as _,
    };
    use commonware_storage::{adb::any::Any, index, mmr::verification::Proof};
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
    type TestTranslator = index::translator::TwoCap;
    type TestAny = Any<Context, TestKey, TestValue, TestHash, TestTranslator>;

    fn create_test_hasher() -> commonware_storage::mmr::hasher::Standard<TestHash> {
        commonware_storage::mmr::hasher::Standard::<TestHash>::new()
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
    #[test_case(10, NZU64!(1))]
    #[test_case(50, NZU64!(10))]
    #[test_case(250, NZU64!(1))]
    #[test_case(250, NZU64!(100))]
    // TODO danlaine: add tests for larger databases
    // when pruning is supported

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

            let config = Config {
                db_config: create_test_config(context.next_u64()),
                max_ops_per_batch,
                max_retries: 0,
                target_hash,
                target_ops,
                context,
                resolver: target_db,
                hasher,
                _phantom: PhantomData,
            };
            let got_db = sync(config).await.unwrap();
            let mut hasher = create_test_hasher();
            assert_eq!(got_db.root(&mut hasher), target_hash);
            assert_eq!(got_db.op_count(), target_ops);

            let mut key_values = HashMap::new();
            let mut deleted_keys = HashSet::new();
            // Make sure the synced database has the same operations as the target database
            for op in target_db_ops {
                match op {
                    Operation::Update(key, value) => {
                        key_values.insert(key, value);
                        deleted_keys.remove(&key);
                    }
                    Operation::Deleted(key) => {
                        key_values.remove(&key);
                        deleted_keys.insert(key);
                    }
                    Operation::Commit(_) => {}
                }
            }

            for (key, value) in key_values {
                assert_eq!(got_db.get(&key).await.unwrap(), Some(value));
            }
            for key in deleted_keys {
                assert_eq!(got_db.get(&key).await.unwrap(), None);
            }
        });
    }

    /// A simple resolver that always returns too many operations to trigger retry logic
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
                target_ops: 100,
                context,
                resolver,
                hasher: create_test_hasher(),
                _phantom: PhantomData,
            };

            let result = sync(config).await;

            // Should fail after max_retries attempts
            match result {
                Err(Error::InvalidResolver(_)) => {}
                _ => panic!("Expected InvalidResolver error for max retries exceeded"),
            }
            // Verify we made max_retries + 1 calls before giving up
            assert_eq!(
                get_proof_call_count.load(std::sync::atomic::Ordering::SeqCst),
                MAX_RETRIES + 1
            );
        });
    }
}
