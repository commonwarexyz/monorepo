use crate::{
    journal::{
        authenticated,
        contiguous::{Contiguous as _, Mutable, Reader as _},
        Error as JournalError,
    },
    merkle::{
        journaled::{self, Journaled},
        mmr::{self, Location, StandardHasher},
    },
    qmdb::{
        self,
        any::value::ValueEncoding,
        keyless::{operation::Codec, Keyless, Operation},
        sync,
    },
    Context, Persistable,
};
use commonware_codec::EncodeShared;
use commonware_cryptography::Hasher;
use std::ops::Range;

impl<E, V, C, H> sync::Database for Keyless<mmr::Family, E, V, C, H>
where
    E: Context,
    V: ValueEncoding + Codec,
    C: Mutable<Item = Operation<mmr::Family, V>>
        + Persistable<Error = JournalError>
        + sync::Journal<Context = E, Op = Operation<mmr::Family, V>>,
    C::Config: Clone + Send,
    H: Hasher,
    Operation<mmr::Family, V>: EncodeShared,
{
    type Op = Operation<mmr::Family, V>;
    type Journal = C;
    type Hasher = H;
    type Config = super::Config<C::Config>;
    type Digest = H::Digest;
    type Context = E;

    /// Returns a [Keyless] db initialized from data collected in the sync process.
    ///
    /// # Behavior
    ///
    /// This method handles different initialization scenarios based on existing data:
    /// - If the Merkle journal is empty or the last item is before the range start, it creates
    ///   a fresh Merkle structure from the provided `pinned_nodes`
    /// - If the Merkle journal has data but is incomplete (has length < range end), missing
    ///   operations from the log are applied to bring it up to the target state
    /// - If the Merkle journal has data beyond the range end, it is rewound to match the sync
    ///   target
    ///
    /// # Returns
    ///
    /// A [Keyless] db populated with the state from the given range.
    async fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        log: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        range: Range<Location>,
        apply_batch_size: usize,
    ) -> Result<Self, qmdb::Error<mmr::Family>> {
        let hasher = StandardHasher::<H>::new();

        let merkle = Journaled::init_sync(
            context.with_label("merkle"),
            journaled::SyncConfig {
                config: config.merkle.clone(),
                range,
                pinned_nodes,
            },
            &hasher,
        )
        .await?;

        let journal = authenticated::Journal::<mmr::Family, _, _, _>::from_components(
            merkle,
            log,
            hasher,
            apply_batch_size as u64,
        )
        .await?;

        let (last_commit_loc, inactivity_floor_loc) = {
            let reader = journal.reader().await;
            let loc = reader
                .bounds()
                .end
                .checked_sub(1)
                .expect("journal should not be empty");
            let op = reader.read(loc).await?;
            let floor = op
                .has_floor()
                .expect("last operation should be a commit with floor");
            (Location::new(loc), floor)
        };

        let db = Self {
            journal,
            last_commit_loc,
            inactivity_floor_loc,
        };

        db.sync().await?;
        Ok(db)
    }

    fn root(&self) -> Self::Digest {
        self.root()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        journal::contiguous::Contiguous,
        merkle::mmr::{self, Location},
        qmdb::{
            keyless::{self, variable, Operation},
            sync::{
                self,
                engine::{Config, NextStep},
                resolver::tests::FailResolver,
                Engine, Target,
            },
        },
    };
    use commonware_cryptography::{sha256, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, BufferPooler, Metrics, Runner as _,
    };
    use commonware_utils::{
        channel::mpsc, non_empty_range, test_rng_seeded, NZUsize, NZU16, NZU64,
    };
    use rand::RngCore as _;
    use rstest::rstest;
    use std::{
        num::{NonZeroU16, NonZeroU64, NonZeroUsize},
        sync::Arc,
    };

    /// Type alias for sync tests with variable-length values.
    type KeylessSyncTest = variable::Db<mmr::Family, deterministic::Context, Vec<u8>, Sha256>;

    type VariableOp = Operation<mmr::Family, crate::qmdb::any::value::VariableEncoding<Vec<u8>>>;

    // Used by both `create_sync_config` and `test_sync_fixed`.
    const PAGE_SIZE: NonZeroU16 = NZU16!(77);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(9);

    /// Create a simple config for sync tests.
    fn create_sync_config(
        suffix: &str,
        pooler: &(impl BufferPooler + commonware_runtime::Metrics),
    ) -> variable::Config<(commonware_codec::RangeCfg<usize>, ())> {
        const ITEMS_PER_SECTION: NonZeroU64 = NZU64!(5);

        let page_cache =
            CacheRef::from_pooler(&pooler.with_label("page_cache"), PAGE_SIZE, PAGE_CACHE_SIZE);
        keyless::Config {
            merkle: crate::merkle::journaled::Config {
                journal_partition: format!("journal-{suffix}"),
                metadata_partition: format!("metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                thread_pool: None,
                page_cache: page_cache.clone(),
            },
            log: crate::journal::contiguous::variable::Config {
                partition: format!("log-{suffix}"),
                items_per_section: ITEMS_PER_SECTION,
                compression: None,
                codec_config: ((0..=10000).into(), ()),
                page_cache,
                write_buffer: NZUsize!(1024),
            },
        }
    }

    /// Create a test database with unique partition names.
    async fn create_test_db(mut context: deterministic::Context) -> KeylessSyncTest {
        let seed = context.next_u64();
        let config = create_sync_config(&format!("sync-test-{seed}"), &context);
        KeylessSyncTest::init(context, config).await.unwrap()
    }

    /// Create n random Append operations using the default seed (0).
    /// create_test_ops(n) is a prefix of create_test_ops(n') for n < n'.
    fn create_test_ops(n: usize) -> Vec<VariableOp> {
        create_test_ops_seeded(n, 0)
    }

    /// Create n random Append operations using a specific seed.
    /// Use different seeds when you need non-overlapping values in the same test.
    fn create_test_ops_seeded(n: usize, seed: u64) -> Vec<VariableOp> {
        let mut rng = test_rng_seeded(seed);
        let mut ops = Vec::with_capacity(n);
        for _ in 0..n {
            let len = (rng.next_u32() % 100 + 1) as usize;
            let mut value = vec![0u8; len];
            rng.fill_bytes(&mut value);
            ops.push(Operation::Append(value));
        }
        ops
    }

    /// Applies the given operations and commits the database, advancing the inactivity floor to
    /// the new commit location so sync tests that exercise pruning can do so freely.
    async fn apply_ops(db: &mut KeylessSyncTest, ops: Vec<VariableOp>, metadata: Option<Vec<u8>>) {
        let mut appends = 0u64;
        let mut batch = db.new_batch();
        for op in ops {
            match op {
                Operation::Append(value) => {
                    batch = batch.append(value);
                    appends += 1;
                }
                Operation::Commit(_, _) => {
                    panic!("Commit operation not supported in apply_ops");
                }
            }
        }
        let new_commit = Location::new(db.last_commit_loc().as_u64() + 1 + appends);
        let merkleized = batch.merkleize(db, metadata, new_commit);
        db.apply_batch(merkleized).await.unwrap();
    }

    /// Test that resolver failure is handled correctly.
    #[test_traced("WARN")]
    fn test_sync_resolver_fails() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let resolver = FailResolver::<VariableOp, sha256::Digest>::new();
            let db_config = create_sync_config(&context.next_u64().to_string(), &context);
            let config = Config {
                context: context.with_label("client"),
                target: Target {
                    root: sha256::Digest::from([0; 32]),
                    range: non_empty_range!(Location::new(0), Location::new(5)),
                },
                resolver,
                apply_batch_size: 2,
                max_outstanding_requests: 2,
                fetch_batch_size: NZU64!(2),
                db_config,
                update_rx: None,
                finish_rx: None,
                reached_target_tx: None,
                max_retained_roots: 8,
            };

            let result: Result<KeylessSyncTest, _> = sync::sync(config).await;
            assert!(result.is_err());
        });
    }

    #[rstest]
    #[case::singleton_batch_size_one(1, NZU64!(1))]
    #[case::singleton_batch_size_gt_db_size(1, NZU64!(2))]
    #[case::batch_size_one(1000, NZU64!(1))]
    #[case::floor_div_db_batch_size(1000, NZU64!(3))]
    #[case::floor_div_db_batch_size_2(1000, NZU64!(999))]
    #[case::div_db_batch_size(1000, NZU64!(100))]
    #[case::db_size_eq_batch_size(1000, NZU64!(1000))]
    #[case::batch_size_gt_db_size(1000, NZU64!(1001))]
    fn test_sync(#[case] target_db_ops: usize, #[case] fetch_batch_size: NonZeroU64) {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut target_db = create_test_db(context.with_label("target")).await;
            let target_ops = create_test_ops(target_db_ops);
            apply_ops(&mut target_db, target_ops.clone(), Some(vec![42])).await;
            let bounds = target_db.bounds().await;
            let target_op_count = bounds.end;
            let target_oldest_retained_loc = bounds.start;
            let target_root = target_db.root();
            let target_floor = target_db.inactivity_floor_loc();

            let db_config =
                create_sync_config(&format!("sync_client_{}", context.next_u64()), &context);

            let target_db = Arc::new(target_db);
            let config = Config {
                db_config: db_config.clone(),
                fetch_batch_size,
                target: Target {
                    root: target_root,
                    range: non_empty_range!(target_oldest_retained_loc, target_op_count),
                },
                context: context.with_label("client"),
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: None,
                finish_rx: None,
                reached_target_tx: None,
                max_retained_roots: 8,
            };
            let got_db: KeylessSyncTest = sync::sync(config).await.unwrap();

            // Verify database state
            let bounds = got_db.bounds().await;
            assert_eq!(bounds.end, target_op_count);
            assert_eq!(bounds.start, target_oldest_retained_loc);
            assert_eq!(got_db.root(), target_root);
            // Explicit: sync must reproduce the inactivity floor, not just the root.
            assert_eq!(got_db.inactivity_floor_loc(), target_floor);

            // Verify values match
            for (i, op) in target_ops.iter().enumerate() {
                if let Operation::Append(value) = op {
                    // +1 because location 0 is the initial commit
                    let got = got_db.get(Location::new(i as u64 + 1)).await.unwrap();
                    assert_eq!(got.as_ref(), Some(value));
                }
            }

            // Apply more operations to both databases and verify they remain consistent
            let new_ops = create_test_ops_seeded(target_db_ops, 1);
            let mut got_db = got_db;
            apply_ops(&mut got_db, new_ops.clone(), None).await;
            let mut target_db = Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("target_db should have no other references"));
            apply_ops(&mut target_db, new_ops, None).await;

            assert_eq!(got_db.root(), target_db.root());

            got_db.destroy().await.unwrap();
            target_db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_sync_empty_to_nonempty() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut target_db = create_test_db(context.with_label("target")).await;
            apply_ops(&mut target_db, vec![], Some(vec![1, 2, 3])).await;

            let bounds = target_db.bounds().await;
            let target_op_count = bounds.end;
            let target_oldest_retained_loc = bounds.start;
            let target_root = target_db.root();

            let db_config =
                create_sync_config(&format!("empty_sync_{}", context.next_u64()), &context);
            let target_db = Arc::new(target_db);
            let config = Config {
                db_config,
                fetch_batch_size: NZU64!(10),
                target: Target {
                    root: target_root,
                    range: non_empty_range!(target_oldest_retained_loc, target_op_count),
                },
                context: context.with_label("client"),
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: None,
                finish_rx: None,
                reached_target_tx: None,
                max_retained_roots: 8,
            };
            let got_db: KeylessSyncTest = sync::sync(config).await.unwrap();

            let bounds = got_db.bounds().await;
            assert_eq!(bounds.end, target_op_count);
            assert_eq!(bounds.start, target_oldest_retained_loc);
            assert_eq!(got_db.root(), target_root);
            assert_eq!(got_db.get_metadata().await.unwrap(), Some(vec![1, 2, 3]));

            got_db.destroy().await.unwrap();
            let target_db =
                Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("Failed to unwrap Arc"));
            target_db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_sync_database_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut target_db = create_test_db(context.with_label("target")).await;
            let target_ops = create_test_ops(10);
            apply_ops(&mut target_db, target_ops.clone(), Some(vec![0])).await;

            let target_root = target_db.root();
            let bounds = target_db.bounds().await;
            let lower_bound = bounds.start;
            let op_count = bounds.end;

            let db_config = create_sync_config("persistence-test", &context);
            let client_context = context.with_label("client");
            let target_db = Arc::new(target_db);
            let config = Config {
                db_config: db_config.clone(),
                fetch_batch_size: NZU64!(5),
                target: Target {
                    root: target_root,
                    range: non_empty_range!(lower_bound, op_count),
                },
                context: client_context.clone(),
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: None,
                finish_rx: None,
                reached_target_tx: None,
                max_retained_roots: 8,
            };
            let synced_db: KeylessSyncTest = sync::sync(config).await.unwrap();

            assert_eq!(synced_db.root(), target_root);
            let expected_root = synced_db.root();
            let bounds = synced_db.bounds().await;
            let expected_op_count = bounds.end;
            let expected_oldest_retained_loc = bounds.start;

            // Drop and reopen
            synced_db.sync().await.unwrap();
            drop(synced_db);
            let reopened_db = KeylessSyncTest::init(context.with_label("reopened"), db_config)
                .await
                .unwrap();

            assert_eq!(reopened_db.root(), expected_root);
            let bounds = reopened_db.bounds().await;
            assert_eq!(bounds.end, expected_op_count);
            assert_eq!(bounds.start, expected_oldest_retained_loc);

            // Verify data integrity
            for (i, op) in target_ops.iter().enumerate() {
                if let Operation::Append(value) = op {
                    let got = reopened_db.get(Location::new(i as u64 + 1)).await.unwrap();
                    assert_eq!(got.as_ref(), Some(value));
                }
            }

            reopened_db.destroy().await.unwrap();
            let target_db =
                Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("Failed to unwrap Arc"));
            target_db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_target_update_during_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut target_db = create_test_db(context.with_label("target")).await;
            let initial_ops = create_test_ops(50);
            apply_ops(&mut target_db, initial_ops, None).await;

            let bounds = target_db.bounds().await;
            let initial_lower_bound = bounds.start;
            let initial_upper_bound = bounds.end;
            let initial_root = target_db.root();

            let additional_ops = create_test_ops_seeded(25, 1);
            apply_ops(&mut target_db, additional_ops, None).await;
            let final_upper_bound = target_db.bounds().await.end;
            let final_root = target_db.root();

            let target_db = Arc::new(target_db);

            let (update_sender, update_receiver) = mpsc::channel(1);
            let client = {
                let config = Config {
                    context: context.with_label("client"),
                    db_config: create_sync_config(
                        &format!("update_test_{}", context.next_u64()),
                        &context,
                    ),
                    target: Target {
                        root: initial_root,
                        range: non_empty_range!(initial_lower_bound, initial_upper_bound),
                    },
                    resolver: target_db.clone(),
                    fetch_batch_size: NZU64!(2),
                    max_outstanding_requests: 10,
                    apply_batch_size: 1024,
                    update_rx: Some(update_receiver),
                    finish_rx: None,
                    reached_target_tx: None,
                    max_retained_roots: 1,
                };
                let mut client: Engine<KeylessSyncTest, _> = Engine::new(config).await.unwrap();
                loop {
                    client = match client.step().await.unwrap() {
                        NextStep::Continue(new_client) => new_client,
                        NextStep::Complete(_) => panic!("client should not be complete"),
                    };
                    let log_size = Contiguous::size(client.journal()).await;
                    if log_size > initial_lower_bound {
                        break client;
                    }
                }
            };

            update_sender
                .send(Target {
                    root: final_root,
                    range: non_empty_range!(initial_lower_bound, final_upper_bound),
                })
                .await
                .unwrap();

            let synced_db = client.sync().await.unwrap();
            assert_eq!(synced_db.root(), final_root);

            let target_db =
                Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("Failed to unwrap Arc"));
            {
                let bounds = synced_db.bounds().await;
                let target_bounds = target_db.bounds().await;
                assert_eq!(bounds.end, target_bounds.end);
                assert_eq!(bounds.start, target_bounds.start);
                assert_eq!(synced_db.root(), target_db.root());
            }

            synced_db.destroy().await.unwrap();
            target_db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_sync_subset_of_target_database() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut target_db = create_test_db(context.with_label("target")).await;
            let target_ops = create_test_ops(30);
            // Apply all but the last operation
            apply_ops(&mut target_db, target_ops[..29].to_vec(), None).await;

            let target_root = target_db.root();
            let bounds = target_db.bounds().await;
            let lower_bound = bounds.start;
            let op_count = bounds.end;

            // Add final op after capturing the range
            apply_ops(&mut target_db, target_ops[29..].to_vec(), None).await;

            let target_db = Arc::new(target_db);
            let config = Config {
                db_config: create_sync_config(&format!("subset_{}", context.next_u64()), &context),
                fetch_batch_size: NZU64!(10),
                target: Target {
                    root: target_root,
                    range: non_empty_range!(lower_bound, op_count),
                },
                context: context.with_label("client"),
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: None,
                finish_rx: None,
                reached_target_tx: None,
                max_retained_roots: 8,
            };
            let synced_db: KeylessSyncTest = sync::sync(config).await.unwrap();

            assert_eq!(synced_db.root(), target_root);
            assert_eq!(synced_db.bounds().await.end, op_count);

            synced_db.destroy().await.unwrap();
            let target_db =
                Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc"));
            target_db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_sync_use_existing_db_partial_match() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let original_ops = create_test_ops(50);

            let mut target_db = create_test_db(context.with_label("target")).await;
            let sync_db_config =
                create_sync_config(&format!("partial_{}", context.next_u64()), &context);
            let client_context = context.with_label("client");
            let mut sync_db: KeylessSyncTest =
                KeylessSyncTest::init(client_context.clone(), sync_db_config.clone())
                    .await
                    .unwrap();

            // Apply same operations to both
            apply_ops(&mut target_db, original_ops.clone(), None).await;
            apply_ops(&mut sync_db, original_ops, None).await;

            drop(sync_db);

            // Add one more op to target
            let last_op = create_test_ops_seeded(1, 1);
            apply_ops(&mut target_db, last_op, None).await;
            let root = target_db.root();
            let bounds = target_db.bounds().await;
            let lower_bound = bounds.start;
            let upper_bound = bounds.end;
            let target_floor = target_db.inactivity_floor_loc();

            let target_db = Arc::new(target_db);
            let config = Config {
                db_config: sync_db_config,
                fetch_batch_size: NZU64!(10),
                target: Target {
                    root,
                    range: non_empty_range!(lower_bound, upper_bound),
                },
                context: context.with_label("sync"),
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: None,
                finish_rx: None,
                reached_target_tx: None,
                max_retained_roots: 8,
            };
            let sync_db: KeylessSyncTest = sync::sync(config).await.unwrap();

            assert_eq!(sync_db.bounds().await.end, upper_bound);
            assert_eq!(sync_db.root(), root);
            assert_eq!(sync_db.inactivity_floor_loc(), target_floor);

            sync_db.destroy().await.unwrap();
            let target_db =
                Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc"));
            target_db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_sync_use_existing_db_exact_match() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let target_ops = create_test_ops(40);

            let mut target_db = create_test_db(context.with_label("target")).await;
            let sync_config =
                create_sync_config(&format!("exact_{}", context.next_u64()), &context);
            let client_context = context.with_label("client");
            let mut sync_db: KeylessSyncTest =
                KeylessSyncTest::init(client_context.clone(), sync_config.clone())
                    .await
                    .unwrap();

            apply_ops(&mut target_db, target_ops.clone(), None).await;
            apply_ops(&mut sync_db, target_ops, None).await;

            drop(sync_db);

            let root = target_db.root();
            let bounds = target_db.bounds().await;
            let lower_bound = bounds.start;
            let upper_bound = bounds.end;
            let target_floor = target_db.inactivity_floor_loc();

            let resolver = Arc::new(target_db);
            let config = Config {
                db_config: sync_config,
                fetch_batch_size: NZU64!(10),
                target: Target {
                    root,
                    range: non_empty_range!(lower_bound, upper_bound),
                },
                context: context.with_label("sync"),
                resolver: resolver.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: None,
                finish_rx: None,
                reached_target_tx: None,
                max_retained_roots: 8,
            };
            let sync_db: KeylessSyncTest = sync::sync(config).await.unwrap();

            assert_eq!(sync_db.bounds().await.end, upper_bound);
            assert_eq!(sync_db.root(), root);
            assert_eq!(sync_db.inactivity_floor_loc(), target_floor);

            sync_db.destroy().await.unwrap();
            let target_db =
                Arc::try_unwrap(resolver).unwrap_or_else(|_| panic!("failed to unwrap Arc"));
            target_db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_target_update_lower_bound_decrease() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut target_db = create_test_db(context.with_label("target")).await;
            let target_ops = create_test_ops(100);
            apply_ops(&mut target_db, target_ops, None).await;

            target_db.prune(Location::new(10)).await.unwrap();

            let bounds = target_db.bounds().await;
            let initial_lower_bound = bounds.start;
            let initial_upper_bound = bounds.end;
            let initial_root = target_db.root();

            let (update_sender, update_receiver) = mpsc::channel(1);
            let target_db = Arc::new(target_db);
            let config = Config {
                context: context.with_label("client"),
                db_config: create_sync_config(&format!("lb-dec-{}", context.next_u64()), &context),
                fetch_batch_size: NZU64!(5),
                target: Target {
                    root: initial_root,
                    range: non_empty_range!(initial_lower_bound, initial_upper_bound),
                },
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_rx: Some(update_receiver),
                finish_rx: None,
                reached_target_tx: None,
                max_retained_roots: 1,
            };
            let client: Engine<KeylessSyncTest, _> = Engine::new(config).await.unwrap();

            update_sender
                .send(Target {
                    root: initial_root,
                    range: non_empty_range!(
                        initial_lower_bound.checked_sub(1).unwrap(),
                        initial_upper_bound
                    ),
                })
                .await
                .unwrap();

            let result = client.step().await;
            assert!(matches!(
                result,
                Err(sync::Error::Engine(
                    sync::EngineError::SyncTargetMovedBackward { .. }
                ))
            ));

            let target_db =
                Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc"));
            target_db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_target_update_upper_bound_decrease() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut target_db = create_test_db(context.with_label("target")).await;
            let target_ops = create_test_ops(50);
            apply_ops(&mut target_db, target_ops, None).await;

            let bounds = target_db.bounds().await;
            let initial_lower_bound = bounds.start;
            let initial_upper_bound = bounds.end;
            let initial_root = target_db.root();

            let (update_sender, update_receiver) = mpsc::channel(1);
            let target_db = Arc::new(target_db);
            let config = Config {
                context: context.with_label("client"),
                db_config: create_sync_config(&format!("ub-dec-{}", context.next_u64()), &context),
                fetch_batch_size: NZU64!(5),
                target: Target {
                    root: initial_root,
                    range: non_empty_range!(initial_lower_bound, initial_upper_bound),
                },
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_rx: Some(update_receiver),
                finish_rx: None,
                reached_target_tx: None,
                max_retained_roots: 1,
            };
            let client: Engine<KeylessSyncTest, _> = Engine::new(config).await.unwrap();

            update_sender
                .send(Target {
                    root: initial_root,
                    range: non_empty_range!(initial_lower_bound, initial_upper_bound - 1),
                })
                .await
                .unwrap();

            let result = client.step().await;
            assert!(matches!(
                result,
                Err(sync::Error::Engine(
                    sync::EngineError::SyncTargetMovedBackward { .. }
                ))
            ));

            let target_db =
                Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc"));
            target_db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_target_update_bounds_increase() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut target_db = create_test_db(context.with_label("target")).await;
            let target_ops = create_test_ops(100);
            apply_ops(&mut target_db, target_ops, None).await;

            let bounds = target_db.bounds().await;
            let initial_lower_bound = bounds.start;
            let initial_upper_bound = bounds.end;
            let initial_root = target_db.root();

            let more_ops = create_test_ops_seeded(5, 1);
            apply_ops(&mut target_db, more_ops, None).await;

            target_db.prune(Location::new(10)).await.unwrap();
            apply_ops(&mut target_db, vec![], None).await;

            let bounds = target_db.bounds().await;
            let final_lower_bound = bounds.start;
            let final_upper_bound = bounds.end;
            let final_root = target_db.root();

            assert_ne!(final_lower_bound, initial_lower_bound);
            assert_ne!(final_upper_bound, initial_upper_bound);

            let (update_sender, update_receiver) = mpsc::channel(1);
            let target_db = Arc::new(target_db);
            let config = Config {
                context: context.with_label("client"),
                db_config: create_sync_config(
                    &format!("bounds_inc_{}", context.next_u64()),
                    &context,
                ),
                fetch_batch_size: NZU64!(1),
                target: Target {
                    root: initial_root,
                    range: non_empty_range!(initial_lower_bound, initial_upper_bound),
                },
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: Some(update_receiver),
                finish_rx: None,
                reached_target_tx: None,
                max_retained_roots: 1,
            };

            update_sender
                .send(Target {
                    root: final_root,
                    range: non_empty_range!(final_lower_bound, final_upper_bound),
                })
                .await
                .unwrap();

            let synced_db: KeylessSyncTest = sync::sync(config).await.unwrap();

            assert_eq!(synced_db.root(), final_root);
            let bounds = synced_db.bounds().await;
            assert_eq!(bounds.end, final_upper_bound);
            assert_eq!(bounds.start, final_lower_bound);

            synced_db.destroy().await.unwrap();
            let target_db =
                Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("Failed to unwrap Arc"));
            target_db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_target_update_on_done_client() {
        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let mut target_db = create_test_db(context.with_label("target")).await;
            let target_ops = create_test_ops(10);
            apply_ops(&mut target_db, target_ops, None).await;

            let bounds = target_db.bounds().await;
            let lower_bound = bounds.start;
            let upper_bound = bounds.end;
            let root = target_db.root();

            let (update_sender, update_receiver) = mpsc::channel(1);
            let target_db = Arc::new(target_db);
            let config = Config {
                context: context.with_label("client"),
                db_config: create_sync_config(&format!("done_{}", context.next_u64()), &context),
                fetch_batch_size: NZU64!(20),
                target: Target {
                    root,
                    range: non_empty_range!(lower_bound, upper_bound),
                },
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 10,
                update_rx: Some(update_receiver),
                finish_rx: None,
                reached_target_tx: None,
                max_retained_roots: 1,
            };

            let synced_db: KeylessSyncTest = sync::sync(config).await.unwrap();

            let _ = update_sender
                .send(Target {
                    root: sha256::Digest::from([2u8; 32]),
                    range: non_empty_range!(lower_bound + 1, upper_bound + 1),
                })
                .await;

            assert_eq!(synced_db.root(), root);
            let bounds = synced_db.bounds().await;
            assert_eq!(bounds.end, upper_bound);
            assert_eq!(bounds.start, lower_bound);

            synced_db.destroy().await.unwrap();
            Arc::try_unwrap(target_db)
                .unwrap_or_else(|_| panic!("failed to unwrap Arc"))
                .destroy()
                .await
                .unwrap();
        });
    }

    // Extra test verifying the generic sync::Database impl works for fixed-size journals.
    // Not present in immutable (which only tests variable).
    #[test_traced("WARN")]
    fn test_sync_fixed() {
        use crate::qmdb::keyless::fixed;
        use commonware_utils::sequence::U64;

        type FixedSyncTest = fixed::Db<mmr::Family, deterministic::Context, U64, Sha256>;

        let executor = deterministic::Runner::default();
        executor.start(|mut context| async move {
            let page_cache = CacheRef::from_pooler(
                &context.with_label("page_cache"),
                PAGE_SIZE,
                PAGE_CACHE_SIZE,
            );
            let target_config = fixed::Config {
                merkle: crate::merkle::journaled::Config {
                    journal_partition: format!("fixed-journal-target-{}", context.next_u64()),
                    metadata_partition: format!("fixed-metadata-target-{}", context.next_u64()),
                    items_per_blob: NZU64!(11),
                    write_buffer: NZUsize!(1024),
                    thread_pool: None,
                    page_cache: page_cache.clone(),
                },
                log: crate::journal::contiguous::fixed::Config {
                    partition: format!("fixed-log-target-{}", context.next_u64()),
                    items_per_blob: NZU64!(7),
                    page_cache: page_cache.clone(),
                    write_buffer: NZUsize!(1024),
                },
            };

            let mut target_db: FixedSyncTest =
                FixedSyncTest::init(context.with_label("target"), target_config)
                    .await
                    .unwrap();

            // Add some values
            let mut batch = target_db.new_batch();
            for i in 0..20u64 {
                batch = batch.append(U64::new(i * 10 + 1));
            }
            let floor = target_db.inactivity_floor_loc();
            let merkleized = batch.merkleize(&target_db, None, floor);
            target_db.apply_batch(merkleized).await.unwrap();

            let target_root = target_db.root();
            let bounds = target_db.bounds().await;
            let lower_bound = bounds.start;
            let upper_bound = bounds.end;

            let client_page_cache = CacheRef::from_pooler(
                &context.with_label("client_page_cache"),
                PAGE_SIZE,
                PAGE_CACHE_SIZE,
            );
            let client_config = fixed::Config {
                merkle: crate::merkle::journaled::Config {
                    journal_partition: format!("fixed-journal-client-{}", context.next_u64()),
                    metadata_partition: format!("fixed-metadata-client-{}", context.next_u64()),
                    items_per_blob: NZU64!(11),
                    write_buffer: NZUsize!(1024),
                    thread_pool: None,
                    page_cache: client_page_cache.clone(),
                },
                log: crate::journal::contiguous::fixed::Config {
                    partition: format!("fixed-log-client-{}", context.next_u64()),
                    items_per_blob: NZU64!(7),
                    page_cache: client_page_cache,
                    write_buffer: NZUsize!(1024),
                },
            };

            let target_db = Arc::new(target_db);
            let config = Config {
                db_config: client_config,
                fetch_batch_size: NZU64!(5),
                target: Target {
                    root: target_root,
                    range: non_empty_range!(lower_bound, upper_bound),
                },
                context: context.with_label("client"),
                resolver: target_db.clone(),
                apply_batch_size: 1024,
                max_outstanding_requests: 1,
                update_rx: None,
                finish_rx: None,
                reached_target_tx: None,
                max_retained_roots: 8,
            };
            let synced_db: FixedSyncTest = sync::sync(config).await.unwrap();

            assert_eq!(synced_db.root(), target_root);
            let bounds = synced_db.bounds().await;
            assert_eq!(bounds.end, upper_bound);
            assert_eq!(bounds.start, lower_bound);

            // Verify values
            for i in 0..20u64 {
                let got = synced_db.get(Location::new(i + 1)).await.unwrap();
                assert_eq!(got, Some(U64::new(i * 10 + 1)));
            }

            synced_db.destroy().await.unwrap();
            let target_db =
                Arc::try_unwrap(target_db).unwrap_or_else(|_| panic!("failed to unwrap Arc"));
            target_db.destroy().await.unwrap();
        });
    }
}
