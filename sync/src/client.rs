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

/// Current state of the sync client
enum ClientState<E, K, V, H, T, R>
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

/// Sync client for Any ADB
pub(crate) struct Client<E, K, V, H, T, R>
where
    E: Storage + Clock + MetricsTrait,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<H, K, V>,
{
    state: Option<ClientState<E, K, V, H, T, R>>,
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
        let state = ClientState::FetchData {
            config,
            operations: vec![],
            metrics: Metrics {
                valid_batches_received: 0,
                invalid_batches_received: 0,
            },
        };
        Ok(Self { state: Some(state) })
    }

    /// Process the next step in the sync process
    async fn step(mut self) -> Result<Self, Error> {
        let current_state = self.state.take().ok_or(Error::InvalidState)?;

        match current_state {
            ClientState::FetchData {
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
                    metrics.invalid_batches_received += 1;
                    return Err(Error::InvalidResolver(format!(
                        "Resolver returned {} operations but only {} were requested",
                        new_operations.len(),
                        batch_size.get()
                    )));
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
                    // TODO danlaine: add max retry logic
                    self.state = Some(ClientState::FetchData {
                        config,
                        operations,
                        metrics,
                    });
                    return Ok(self);
                }
                operations.extend(new_operations);

                metrics.valid_batches_received += 1;
                if operations.len() as u64 >= config.target_ops {
                    self.state = Some(ClientState::ApplyData {
                        config,
                        operations,
                        metrics,
                    });
                } else {
                    self.state = Some(ClientState::FetchData {
                        config,
                        operations,
                        metrics,
                    });
                }
                Ok(self)
            }

            ClientState::ApplyData {
                config,
                operations,
                metrics,
            } => {
                let db = adb::any::Any::<E, K, V, H, T>::init_sync(
                    config.context,
                    adb::any::SyncConfig {
                        config: config.db_config,
                        mmr_pinned_nodes: Default::default(), // TODO danlaine: support pruning
                        pruned_to_loc: 0,                     // TODO danlaine: support pruning
                        operations: operations,
                    },
                )
                .await
                .map_err(|e| Error::InvalidResolver(e.to_string()))?; // TODO danlaine: handle this error

                self.state = Some(ClientState::Done { db, metrics });
                Ok(self)
            }

            ClientState::Done { .. } => Err(Error::AlreadyComplete),
        }
    }

    /// Run the complete sync process
    pub(crate) async fn sync(mut self) -> Result<adb::any::Any<E, K, V, H, T>, Error> {
        info!("Starting complete sync process");

        loop {
            self = self.step().await?;
            if let Some(ClientState::Done { db, metrics }) = self.state {
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
    use crate::{resolver::LocalResolver, sync};
    use commonware_cryptography::{sha256::Digest, Digest as _, Sha256};
    use commonware_runtime::{
        deterministic::{self, Context},
        Runner as _,
    };
    use commonware_storage::{
        adb::any::{Any, Config},
        index,
    };
    use commonware_utils::NZU64;
    use rand::{rngs::StdRng, RngCore as _, SeedableRng as _};
    use test_case::test_case;

    type TestHash = Sha256;
    type TestKey = Digest;
    type TestValue = Digest;
    type TestTranslator = index::translator::TwoCap;
    type TestAny = Any<Context, TestKey, TestValue, TestHash, TestTranslator>;
    type TestResolver = LocalResolver<Context, TestKey, TestValue, TestHash, TestTranslator>;

    /// Create a test database with unique partition names
    async fn create_test_db(mut context: Context) -> TestAny {
        let n = context.next_u64();
        let config = Config {
            mmr_journal_partition: format!("mmr_journal_{n}"),
            mmr_metadata_partition: format!("mmr_metadata_{n}"),
            mmr_items_per_blob: 1024,
            mmr_write_buffer: 64,
            log_journal_partition: format!("log_journal_{n}"),
            log_items_per_blob: 1024,
            log_write_buffer: 64,
            translator: TestTranslator::default(),
            pool: None,
        };
        TestAny::init(context, config).await.unwrap()
    }

    // Apply n updates to the database. Some portion of the updates are deletes.
    // It's guaranteed that calling this function with n' > n will apply the same updates
    // as calling this function with n, followed by additional updates.
    // Note that we don't commit after applying the updates.
    async fn apply_test_ops(mut db: TestAny, n: usize) -> TestAny {
        let mut rng = StdRng::seed_from_u64(1337);
        let mut prev_key = TestKey::random(&mut rng);
        for i in 0..n {
            let key = TestKey::random(&mut rng);
            if i % 10 == 0 && i > 0 {
                db.delete(prev_key).await.unwrap();
            } else {
                let value = TestValue::random(&mut rng);
                db.update(key, value).await.unwrap();
                prev_key = key;
            }
        }
        db
    }

    // #[test]
    // fn test_client_configuration() {
    //     let config = Config::default();
    //     assert_eq!(config.max_ops_per_batch.get(), 1000);

    //     let custom_config = Config {
    //         max_ops_per_batch: NZU64!(5),
    //     };
    //     assert_eq!(custom_config.max_ops_per_batch.get(), 5);
    // }

    // Test that the client returns an error if the target ops is less than the current ops.
    // #[test]
    // fn test_invalid_target_error() {
    //     let executor = deterministic::Runner::default();
    //     executor.start(|context| async move {
    //         let target_db = create_test_db(context.clone()).await;
    //         let mut target_db = apply_test_ops(target_db, 9).await;
    //         target_db.commit().await.unwrap();
    //         let mut hasher = commonware_storage::mmr::hasher::Standard::<TestHash>::new();
    //         let target_hash = target_db.root(&mut hasher);
    //         let sync_db = create_test_db(context.clone()).await;
    //         let mut sync_db = apply_test_ops(sync_db, 10).await;
    //         sync_db.commit().await.unwrap();

    //         let resolver = TestResolver::_new(sync_db);
    //         let client = Client::new(resolver, Config::default(), 0, target_hash).unwrap();
    //         let result: Result<TestAny, Error> = client.sync().await;
    //         match result {
    //             Ok(_) => panic!("Expected error"),
    //             Err(Error::InvalidTarget { .. }) => {}
    //             Err(e) => panic!("Expected InvalidTarget, got {:?}", e),
    //         }
    //     });
    // }

    // #[test_case(0, 1, NZU64!(1))]
    // #[test_case(0, 1, NZU64!(10))]
    // #[test_case(1, 2, NZU64!(1))]
    // #[test_case(1, 2, NZU64!(10))]
    // #[test_case(0, 100, NZU64!(1))]
    // #[test_case(0, 100, NZU64!(10))]
    // #[test_case(5, 100, NZU64!(1))]
    // #[test_case(5, 100, NZU64!(10))]
    // #[test_case(99, 100, NZU64!(1))]
    // #[test_case(99, 100, NZU64!(10))]
    // fn test_sync(sync_db_ops: usize, target_db_ops: usize, max_ops_per_batch: NonZeroU64) {
    //     let executor = deterministic::Runner::default();
    //     executor.start(|context| async move {
    //         let target_db = create_test_db(context.clone()).await;
    //         let mut target_db = apply_test_ops(target_db, target_db_ops).await;
    //         target_db.commit().await.unwrap();
    //         let target_ops = target_db.op_count();
    //         let mut hasher = commonware_storage::mmr::hasher::Standard::<TestHash>::new();
    //         let target_hash = target_db.root(&mut hasher);
    //         let resolver = TestResolver::_new(target_db);
    //         let sync_db = create_test_db(context).await;
    //         let sync_db = apply_test_ops(sync_db, sync_db_ops).await;
    //         let config = ClientConfig { max_ops_per_batch };

    //         let result = sync(sync_db, resolver, target_ops, target_hash, config)
    //             .await
    //             .unwrap();
    //         assert_eq!(result.root(&mut hasher), target_hash);
    //         assert_eq!(result.op_count(), target_ops);
    //     });
    // }

    // #[test]
    // fn test_delete_me() {
    //     let executor = deterministic::Runner::default();
    //     executor.start(|context| async move {
    //         let target_db = create_test_db(context.clone()).await;
    //         let mut target_db = apply_test_ops(target_db, 100).await;
    //         target_db.commit().await.unwrap();
    //         let target_ops = target_db.op_count();
    //         let floor = target_db.oldest_retained_loc().unwrap();
    //         let mut hasher = commonware_storage::mmr::hasher::Standard::<TestHash>::new();
    //         let target_hash = target_db.root(&mut hasher);

    //         let ops = target_db
    //             .proof(floor, NonZeroU64::new(target_ops).unwrap())
    //             .await
    //             .unwrap();
    //     });
    // }
}
