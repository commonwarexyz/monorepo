use crate::{
    adb::{
        immutable::{Config, Immutable},
        operation::Variable,
        sync::{self, Journal as _},
    },
    journal::variable,
    mmr::hasher::Standard,
    translator::Translator,
};
use commonware_codec::Codec;
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use futures::{pin_mut, StreamExt};

mod journal;
mod verifier;

pub type Error = crate::adb::Error;

impl<E, K, V, H, T> sync::Database for Immutable<E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Codec,
    H: Hasher,
    T: Translator,
{
    type Op = Variable<K, V>;
    type Journal = journal::ImmutableSyncJournal<E, K, V>;
    type Verifier = verifier::Verifier<H>;
    type Error = crate::adb::Error;
    type Config = Config<T, V::Cfg>;
    type Digest = H::Digest;
    type Context = E;

    async fn create_journal(
        context: Self::Context,
        config: &Self::Config,
        lower_bound: u64,
        upper_bound: u64,
    ) -> Result<Self::Journal, <Self::Journal as sync::Journal>::Error> {
        let journal_config = variable::Config {
            partition: config.log_journal_partition.clone(),
            compression: config.log_compression,
            codec_config: config.log_codec_config.clone(),
            write_buffer: config.log_write_buffer,
        };

        // Create the Variable journal using init_sync
        let variable_journal = variable::Journal::init_sync(
            context.with_label("log"),
            journal_config,
            lower_bound,
            upper_bound,
            std::num::NonZeroU64::new(config.log_items_per_section).unwrap(),
        )
        .await?;

        // Count existing operations in the retained range to continue from the correct location
        let mut existing_ops: u64 = 0;
        {
            let stream = variable_journal.replay(1024).await?;
            pin_mut!(stream);
            while let Some(item) = stream.next().await {
                match item {
                    Ok(_) => existing_ops += 1,
                    Err(e) => return Err(<Self::Journal as sync::Journal>::Error::from(e)),
                }
            }
        }

        // Wrap it in our sync journal wrapper
        // The current_size should be lower_bound + existing_ops so we advance sections correctly
        let sync_journal = journal::ImmutableSyncJournal::new(
            variable_journal,
            config.log_items_per_section,
            lower_bound,
            upper_bound,
            lower_bound.saturating_add(existing_ops),
        );

        Ok(sync_journal)
    }

    fn create_verifier() -> Self::Verifier {
        verifier::Verifier::new(Standard::<H>::new())
    }

    async fn from_sync_result(
        context: Self::Context,
        db_config: Self::Config,
        journal: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        target: sync::Target<Self::Digest>,
        apply_batch_size: usize,
    ) -> Result<Self, Self::Error> {
        // Extract the Variable journal from the wrapper
        let variable_journal = journal.into_inner();

        // Create a SyncConfig-like structure for init_synced
        let sync_config = ImmutableSyncConfig {
            db_config,
            log: variable_journal,
            lower_bound: target.lower_bound_ops,
            upper_bound: target.upper_bound_ops,
            pinned_nodes,
            apply_batch_size,
        };

        Self::init_synced(context, sync_config).await
    }

    fn root(&self) -> Self::Digest {
        let mut hasher = Standard::<H>::new();
        self.root(&mut hasher)
    }

    async fn resize_journal(
        journal: Self::Journal,
        context: Self::Context,
        config: &Self::Config,
        lower_bound: u64,
        upper_bound: u64,
    ) -> Result<Self::Journal, Self::Error> {
        // Check if there are operations at or after lower_bound
        let has_operations = journal
            .has_operations_from(lower_bound)
            .await
            .map_err(crate::adb::Error::from)?;

        if !has_operations {
            // Close existing journal and create new one
            journal.close().await.map_err(crate::adb::Error::from)?;
            Self::create_journal(context, config, lower_bound, upper_bound)
                .await
                .map_err(crate::adb::Error::from)
        } else {
            // Extract the Variable journal to perform section-based pruning
            let mut variable_journal = journal.into_inner();

            // Use Variable journal's section-based pruning
            let items_per_section =
                std::num::NonZeroU64::new(config.log_items_per_section).unwrap();
            let lower_section = lower_bound / items_per_section.get();
            variable_journal
                .prune(lower_section)
                .await
                .map_err(crate::adb::Error::from)?;

            // Count existing operations after pruning to set the correct current_size
            let mut existing_ops: u64 = 0;
            {
                let stream = variable_journal.replay(1024).await?;
                pin_mut!(stream);
                while let Some(item) = stream.next().await {
                    match item {
                        Ok(_) => existing_ops += 1,
                        Err(e) => return Err(e.into()),
                    }
                }
            }

            // Wrap the pruned journal back in our sync wrapper
            let sync_journal = journal::ImmutableSyncJournal::new(
                variable_journal,
                config.log_items_per_section,
                lower_bound,
                upper_bound,
                lower_bound.saturating_add(existing_ops),
            );

            Ok(sync_journal)
        }
    }
}

/// Configuration for syncing an [Immutable] to a pruned target state.
pub struct ImmutableSyncConfig<E, K, V, T, D, C>
where
    E: Storage + Metrics,
    K: Array,
    V: Codec,
    T: Translator,
    D: commonware_cryptography::Digest,
{
    /// Database configuration.
    pub db_config: Config<T, C>,

    /// The [Immutable]'s log of operations. It has elements from `lower_bound` to `upper_bound`, inclusive.
    /// Reports `lower_bound` as its pruning boundary (oldest retained operation index).
    pub log: variable::Journal<E, Variable<K, V>>,

    /// Sync lower boundary (inclusive) - operations below this index are pruned.
    pub lower_bound: u64,

    /// Sync upper boundary (inclusive) - operations above this index are not synced.
    pub upper_bound: u64,

    /// The pinned nodes the MMR needs at the pruning boundary given by
    /// `lower_bound`, in the order specified by `Proof::nodes_to_pin`.
    /// If `None`, the pinned nodes will be computed from the MMR's journal and metadata,
    /// which are expected to have the necessary pinned nodes.
    pub pinned_nodes: Option<Vec<D>>,

    /// The maximum number of operations to keep in memory
    /// before committing the database while applying operations.
    /// Higher value will cause more memory usage during sync.
    pub apply_batch_size: usize,
}

#[cfg(test)]
mod tests {
    use crate::{
        adb::{
            immutable,
            operation::Variable,
            sync::{
                self,
                engine::{EngineConfig, NextStep},
                Engine, Journal, Target,
            },
        },
        mmr::hasher::Standard,
    };
    use commonware_cryptography::{sha256, Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner as _, RwLock};
    use commonware_utils::NZU64;
    use futures::{channel::mpsc, SinkExt as _};
    use rand::{rngs::StdRng, RngCore as _, SeedableRng as _};
    use std::{collections::HashMap, num::NonZeroU64, sync::Arc};
    use test_case::test_case;

    /// Type alias for sync tests with simple codec config
    type ImmutableSyncTest = immutable::Immutable<
        deterministic::Context,
        sha256::Digest,
        sha256::Digest,
        Sha256,
        crate::translator::TwoCap,
    >;

    fn test_hasher() -> Standard<Sha256> {
        Standard::<Sha256>::new()
    }

    /// Create a simple config for sync tests
    fn create_sync_config(suffix: &str) -> immutable::Config<crate::translator::TwoCap, ()> {
        use crate::translator::TwoCap;
        use commonware_runtime::buffer::PoolRef;

        const PAGE_SIZE: usize = 77;
        const PAGE_CACHE_SIZE: usize = 9;
        const ITEMS_PER_SECTION: u64 = 5;

        immutable::Config {
            mmr_journal_partition: format!("journal_{suffix}"),
            mmr_metadata_partition: format!("metadata_{suffix}"),
            mmr_items_per_blob: 11,
            mmr_write_buffer: 1024,
            log_journal_partition: format!("log_journal_{suffix}"),
            log_items_per_section: ITEMS_PER_SECTION,
            log_compression: None,
            log_codec_config: (),
            log_write_buffer: 1024,
            locations_journal_partition: format!("locations_journal_{suffix}"),
            locations_items_per_blob: 7,
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    /// Create a test database with unique partition names
    async fn create_test_db(mut context: deterministic::Context) -> ImmutableSyncTest {
        let seed = context.next_u64();
        let config = create_sync_config(&format!("sync_test_{seed}"));
        ImmutableSyncTest::init(context, config).await.unwrap()
    }

    /// Create n random Set operations.
    /// create_test_ops(n') is a suffix of create_test_ops(n) for n' > n.
    fn create_test_ops(n: usize) -> Vec<Variable<sha256::Digest, sha256::Digest>> {
        let mut rng = StdRng::seed_from_u64(1337);
        let mut ops = Vec::new();
        for _i in 0..n {
            let key = sha256::Digest::random(&mut rng);
            let value = sha256::Digest::random(&mut rng);
            ops.push(Variable::Set(key, value));
        }
        ops
    }

    /// Applies the given operations to the database.
    async fn apply_ops(
        db: &mut ImmutableSyncTest,
        ops: Vec<Variable<sha256::Digest, sha256::Digest>>,
    ) {
        for op in ops {
            match op {
                Variable::Set(key, value) => {
                    db.set(key, value).await.unwrap();
                }
                Variable::Commit() => {
                    db.commit().await.unwrap();
                }
            }
        }
    }

    #[test_case(1, NZU64!(1); "singleton db with batch size == 1")]
    #[test_case(1, NZU64!(2); "singleton db with batch size > db size")]
    #[test_case(100, NZU64!(1); "db with batch size 1")]
    #[test_case(100, NZU64!(3); "db size not evenly divided by batch size")]
    #[test_case(100, NZU64!(99); "db size not evenly divided by batch size; different batch size")]
    #[test_case(100, NZU64!(50); "db size divided by batch size")]
    #[test_case(100, NZU64!(100); "db size == batch size")]
    #[test_case(100, NZU64!(101); "batch size > db size")]
    fn test_sync(target_db_ops: usize, fetch_batch_size: NonZeroU64) {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut target_db = create_test_db(context.clone()).await;
            let target_db_ops = create_test_ops(target_db_ops);
            apply_ops(&mut target_db, target_db_ops.clone()).await;
            target_db.commit().await.unwrap();
            let target_op_count = target_db.op_count();
            let target_oldest_retained_loc = target_db.oldest_retained_loc;
            let mut hasher = test_hasher();
            let target_root = target_db.root(&mut hasher);

            // Capture target database state before moving into config
            let mut expected_kvs: HashMap<sha256::Digest, sha256::Digest> = HashMap::new();
            for op in &target_db_ops {
                if let Variable::Set(key, value) = op {
                    expected_kvs.insert(*key, *value);
                }
            }

            let db_config = create_sync_config(&format!("sync_client_{}", context.next_u64()));

            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));
            let config = EngineConfig {
                db_config: db_config.clone(),
                fetch_batch_size,
                target: Target {
                    root: target_root,
                    lower_bound_ops: target_oldest_retained_loc,
                    upper_bound_ops: target_op_count - 1, // target_op_count is the count, operations are 0-indexed
                },
                context: context.clone(),
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_receiver: None,
            };
            let mut got_db: ImmutableSyncTest = sync::sync(config).await.unwrap();

            // Verify database state
            let mut hasher = test_hasher();
            assert_eq!(got_db.op_count(), target_op_count);
            assert_eq!(got_db.oldest_retained_loc, target_oldest_retained_loc);

            // Verify the root digest matches the target
            assert_eq!(got_db.root(&mut hasher), target_root);

            // Verify that the synced database matches the target state
            for (key, expected_value) in &expected_kvs {
                let synced_value = got_db.get(key).await.unwrap();
                assert_eq!(synced_value, Some(*expected_value));
            }

            // Put more key-value pairs into both databases
            let mut new_ops = Vec::new();
            let mut rng = StdRng::seed_from_u64(42);
            let mut new_kvs: HashMap<sha256::Digest, sha256::Digest> = HashMap::new();
            for _i in 0..expected_kvs.len() {
                let key = sha256::Digest::random(&mut rng);
                let value = sha256::Digest::random(&mut rng);
                new_ops.push(Variable::Set(key, value));
                new_kvs.insert(key, value);
            }

            // Apply new operations to both databases
            apply_ops(&mut got_db, new_ops.clone()).await;
            {
                let mut target_db = target_db.write().await;
                apply_ops(&mut target_db, new_ops).await;
            }

            // Verify both databases have the same state after additional operations
            for (key, expected_value) in &new_kvs {
                let synced_value = got_db.get(key).await.unwrap();
                let target_value = {
                    let target_db = target_db.read().await;
                    target_db.get(key).await.unwrap()
                };
                assert_eq!(synced_value, Some(*expected_value));
                assert_eq!(target_value, Some(*expected_value));
            }

            got_db.destroy().await.unwrap();
            let target_db = match Arc::try_unwrap(target_db) {
                Ok(rw_lock) => rw_lock.into_inner(),
                Err(_) => panic!("Failed to unwrap Arc - still has references"),
            };
            target_db.destroy().await.unwrap();
        });
    }

    /// Test that sync works when the target database is initially empty
    #[test_traced("WARN")]
    fn test_sync_empty_to_nonempty() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create an empty target database
            let mut target_db = create_test_db(context.clone()).await;
            target_db.commit().await.unwrap(); // Commit to establish a valid root

            let target_op_count = target_db.op_count();
            let target_oldest_retained_loc = target_db.oldest_retained_loc;
            let mut hasher = test_hasher();
            let target_root = target_db.root(&mut hasher);

            let db_config = create_sync_config(&format!("empty_sync_{}", context.next_u64()));
            let target_db = Arc::new(RwLock::new(target_db));
            let config = EngineConfig {
                db_config,
                fetch_batch_size: NZU64!(10),
                target: Target {
                    root: target_root,
                    lower_bound_ops: target_oldest_retained_loc,
                    upper_bound_ops: target_op_count - 1,
                },
                context: context.clone(),
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_receiver: None,
            };
            let got_db: ImmutableSyncTest = sync::sync(config).await.unwrap();

            // Verify database state
            let mut hasher = test_hasher();
            assert_eq!(got_db.op_count(), target_op_count);
            assert_eq!(got_db.oldest_retained_loc, target_oldest_retained_loc);
            assert_eq!(got_db.root(&mut hasher), target_root);

            got_db.destroy().await.unwrap();
            let target_db = match Arc::try_unwrap(target_db) {
                Ok(rw_lock) => rw_lock.into_inner(),
                Err(_) => panic!("Failed to unwrap Arc - still has references"),
            };
            target_db.destroy().await.unwrap();
        });
    }

    // TODO: Test that sync fails gracefully when the resolver fails
    // Note: FailResolver is designed for Fixed operations, but Immutable uses Variable operations
    // This test is commented out until we create a proper FailResolver for Variable operations
    // #[test_traced("WARN")]
    // fn test_sync_resolver_failure() { ... }

    /// Test demonstrating that a synced database can be reopened and retain its state.
    #[test_traced("WARN")]
    fn test_sync_database_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create and populate a simple target database
            let mut target_db = create_test_db(context.clone()).await;
            let target_ops = create_test_ops(10);
            apply_ops(&mut target_db, target_ops.clone()).await;
            target_db.commit().await.unwrap();

            // Capture target state
            let mut hasher = test_hasher();
            let target_root = target_db.root(&mut hasher);
            let lower_bound = target_db.oldest_retained_loc;
            let upper_bound = target_db.op_count() - 1;

            // Perform sync
            let db_config = create_sync_config("persistence_test");
            let context_clone = context.clone();
            let target_db = Arc::new(RwLock::new(target_db));
            let config = EngineConfig {
                db_config: db_config.clone(),
                fetch_batch_size: NZU64!(5),
                target: Target {
                    root: target_root,
                    lower_bound_ops: lower_bound,
                    upper_bound_ops: upper_bound,
                },
                context,
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_receiver: None,
            };
            let synced_db: ImmutableSyncTest = sync::sync(config).await.unwrap();

            // Verify initial sync worked
            let mut hasher = test_hasher();
            assert_eq!(synced_db.root(&mut hasher), target_root);

            // Save state before closing
            let expected_root = synced_db.root(&mut hasher);
            let expected_op_count = synced_db.op_count();
            let expected_oldest_retained_loc = synced_db.oldest_retained_loc;

            // Close and reopen the database to test persistence
            synced_db.close().await.unwrap();
            let reopened_db = ImmutableSyncTest::init(context_clone, db_config)
                .await
                .unwrap();

            // Verify state is preserved
            let mut hasher = test_hasher();
            assert_eq!(reopened_db.root(&mut hasher), expected_root);
            assert_eq!(reopened_db.op_count(), expected_op_count);
            assert_eq!(
                reopened_db.oldest_retained_loc,
                expected_oldest_retained_loc
            );

            // Verify data integrity
            for op in &target_ops {
                if let Variable::Set(key, value) = op {
                    let stored_value = reopened_db.get(key).await.unwrap();
                    assert_eq!(stored_value, Some(*value));
                }
            }

            reopened_db.destroy().await.unwrap();
            let target_db = match Arc::try_unwrap(target_db) {
                Ok(rw_lock) => rw_lock.into_inner(),
                Err(_) => panic!("Failed to unwrap Arc - still has references"),
            };
            target_db.destroy().await.unwrap();
        });
    }

    /// Test that target updates work correctly during sync
    #[test_traced("WARN")]
    fn test_target_update_during_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            // Create and populate initial target database
            let mut target_db = create_test_db(context.clone()).await;
            let initial_ops = create_test_ops(50);
            apply_ops(&mut target_db, initial_ops.clone()).await;
            target_db.commit().await.unwrap();

            // Capture the state after first commit
            let mut hasher = test_hasher();
            let initial_lower_bound = target_db.oldest_retained_loc;
            let initial_upper_bound = target_db.op_count() - 1;
            let initial_root = target_db.root(&mut hasher);

            // Add more operations to create the extended target
            let additional_ops = create_test_ops(25);
            apply_ops(&mut target_db, additional_ops.clone()).await;
            target_db.commit().await.unwrap();
            let final_upper_bound = target_db.op_count() - 1;
            let final_root = target_db.root(&mut hasher);

            // Wrap target database for shared mutable access
            let target_db = Arc::new(commonware_runtime::RwLock::new(target_db));

            // Create client with initial smaller target and very small batch size
            let (mut update_sender, update_receiver) = mpsc::channel(1);
            let client = {
                let config = EngineConfig {
                    context: context.clone(),
                    db_config: create_sync_config(&format!("update_test_{}", context.next_u64())),
                    target: Target {
                        root: initial_root,
                        lower_bound_ops: initial_lower_bound,
                        upper_bound_ops: initial_upper_bound,
                    },
                    resolver: target_db.clone(),
                    fetch_batch_size: NZU64!(2), // Very small batch size to ensure multiple batches needed
                    max_outstanding_requests: 10,
                    apply_batch_size: 1024,
                    update_receiver: Some(update_receiver),
                };
                let mut client: Engine<ImmutableSyncTest, _> = Engine::new(config).await.unwrap();
                client.schedule_requests().await.unwrap();
                loop {
                    // Step the client until we have processed a batch of operations
                    client = match client.step().await.unwrap() {
                        NextStep::Continue(new_client) => new_client,
                        NextStep::Complete(_) => panic!("client should not be complete"),
                    };
                    let log_size = client.journal.size().await.unwrap();
                    if log_size > initial_lower_bound {
                        break client;
                    }
                }
            };

            // Send target update with SAME lower bound but higher upper bound
            update_sender
                .send(Target {
                    root: final_root,
                    lower_bound_ops: initial_lower_bound,
                    upper_bound_ops: final_upper_bound,
                })
                .await
                .unwrap();

            // Complete the sync
            let synced_db = client.sync().await.unwrap();

            // Verify the synced database has the expected final state
            let mut hasher = test_hasher();
            assert_eq!(synced_db.root(&mut hasher), final_root);

            // Verify the target database matches the synced database
            let target_db = match Arc::try_unwrap(target_db) {
                Ok(rw_lock) => rw_lock.into_inner(),
                Err(_) => panic!("Failed to unwrap Arc - still has references"),
            };
            {
                assert_eq!(synced_db.op_count(), target_db.op_count());
                assert_eq!(synced_db.oldest_retained_loc, target_db.oldest_retained_loc);
                assert_eq!(synced_db.root(&mut hasher), target_db.root(&mut hasher));
            }

            // Verify all expected operations are present in the synced database
            let all_ops = [initial_ops, additional_ops].concat();
            for op in &all_ops {
                if let Variable::Set(key, value) = op {
                    let synced_value = synced_db.get(key).await.unwrap();
                    assert_eq!(synced_value, Some(*value));
                }
            }

            synced_db.destroy().await.unwrap();
            target_db.destroy().await.unwrap();
        });
    }
}
