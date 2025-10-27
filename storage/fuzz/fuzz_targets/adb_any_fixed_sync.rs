#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_runtime::{buffer::PoolRef, deterministic, Runner, RwLock};
use commonware_storage::{
    adb::{
        any::fixed::{unordered::Any, Config},
        operation::fixed::unordered::Operation as Fixed,
        sync,
    },
    mmr::StandardHasher as Standard,
    translator::TwoCap,
};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU64};
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;

type Key = FixedBytes<32>;
type Value = FixedBytes<32>;

const MAX_OPERATIONS: usize = 50;

#[derive(Debug)]
enum Operation {
    // Basic ops to build source state
    Update {
        key: [u8; 32],
        value: [u8; 32],
    },
    Delete {
        key: [u8; 32],
    },
    Commit,
    Prune,

    // Sync scenarios
    SyncFull {
        fetch_batch_size: u64,
    },

    // Failure simulation
    SimulateFailure {
        sync_log: bool,
        sync_mmr: bool,
        write_limit: u8,
    },
}

impl<'a> Arbitrary<'a> for Operation {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice: u8 = u.arbitrary()?;
        match choice % 8 {
            0 | 1 => {
                let key = u.arbitrary()?;
                let value = u.arbitrary()?;
                Ok(Operation::Update { key, value })
            }
            2 => {
                let key = u.arbitrary()?;
                Ok(Operation::Delete { key })
            }
            3 => Ok(Operation::Commit),
            4 => Ok(Operation::Prune),
            5 => {
                let fetch_batch_size = u.arbitrary()?;
                Ok(Operation::SyncFull { fetch_batch_size })
            }
            6 => {
                let sync_log: bool = u.arbitrary()?;
                let sync_mmr: bool = u.arbitrary()?;
                let write_limit = if sync_mmr { 0 } else { u.arbitrary()? };
                Ok(Operation::SimulateFailure {
                    sync_log,
                    sync_mmr,
                    write_limit,
                })
            }
            7 => {
                let key = u.arbitrary()?;
                Ok(Operation::Delete { key })
            }
            _ => unreachable!(),
        }
    }
}

#[derive(Debug)]
struct FuzzInput {
    ops: Vec<Operation>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let num_ops = u.int_in_range(1..=MAX_OPERATIONS)?;
        let ops = (0..num_ops)
            .map(|_| Operation::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(FuzzInput { ops })
    }
}

const PAGE_SIZE: usize = 128;

fn test_config(test_name: &str) -> Config<TwoCap> {
    Config {
        mmr_journal_partition: format!("{test_name}_mmr"),
        mmr_metadata_partition: format!("{test_name}_meta"),
        mmr_items_per_blob: NZU64!(3),
        mmr_write_buffer: NZUsize!(1024),
        log_journal_partition: format!("{test_name}_log"),
        log_items_per_blob: NZU64!(3),
        log_write_buffer: NZUsize!(1024),
        translator: TwoCap,
        thread_pool: None,
        buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(1)),
    }
}

async fn test_sync<
    R: sync::resolver::Resolver<
        Digest = commonware_cryptography::sha256::Digest,
        Op = Fixed<Key, Value>,
    >,
>(
    context: deterministic::Context,
    resolver: R,
    target: sync::Target<commonware_cryptography::sha256::Digest>,
    fetch_batch_size: u64,
    test_name: &str,
) -> bool {
    let db_config = test_config(test_name);
    let expected_root = target.root;

    let sync_config: sync::engine::Config<Any<_, Key, Value, Sha256, TwoCap>, R> =
        sync::engine::Config {
            context,
            update_rx: None,
            db_config,
            fetch_batch_size: NZU64!((fetch_batch_size % 100) + 1),
            target,
            resolver,
            apply_batch_size: 100,
            max_outstanding_requests: 10,
        };

    if let Ok(synced) = sync::sync(sync_config).await {
        let mut hasher = Standard::<Sha256>::new();
        let actual_root = synced.root(&mut hasher);
        assert_eq!(
            actual_root, expected_root,
            "Synced root must match target root"
        );

        synced.destroy().await.is_ok()
    } else {
        false
    }
}

fn fuzz(input: FuzzInput) {
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let mut db = Any::<_, Key, Value, Sha256, TwoCap>::init(
            context.clone(),
            test_config("adb_any_fixed_fuzz_test"),
        )
        .await
        .expect("Failed to init source db");

        let mut sync_id = 0;

        for op in &input.ops {
            match op {
                Operation::Update { key, value } => {
                    db.update(Key::new(*key), Value::new(*value))
                        .await
                        .expect("Update should not fail");
                }

                Operation::Delete { key } => {
                    db.delete(Key::new(*key))
                        .await
                        .expect("Delete should not fail");
                }

                Operation::Commit => {
                    db.commit().await.expect("Commit should not fail");
                }

                Operation::Prune => {
                    db.prune(db.inactivity_floor_loc())
                        .await
                        .expect("Prune should not fail");
                }

                Operation::SyncFull { fetch_batch_size } => {
                    if db.op_count() == 0 {
                        continue;
                    }
                    db.commit()
                        .await
                        .expect("Commit before sync should not fail");

                    let mut hasher = Standard::<Sha256>::new();
                    let target = sync::Target {
                        root: db.root(&mut hasher),
                        range: db.inactivity_floor_loc()..db.op_count(),
                    };

                    let wrapped_src = Arc::new(RwLock::new(db));
                    let _result = test_sync(
                        context.clone(),
                        wrapped_src.clone(),
                        target,
                        *fetch_batch_size,
                        &format!("full_{sync_id}"),
                    )
                    .await;
                    db = Arc::try_unwrap(wrapped_src)
                        .unwrap_or_else(|_| panic!("Failed to unwrap src"))
                        .into_inner();
                    sync_id += 1;
                }

                Operation::SimulateFailure {
                    sync_log,
                    sync_mmr,
                    write_limit,
                } => {
                    db.simulate_failure(*sync_log, *sync_mmr, *write_limit as usize)
                        .await
                        .expect("Simulate failure should not fail");

                    db = Any::<_, Key, Value, Sha256, TwoCap>::init(
                        context.clone(),
                        test_config("src"),
                    )
                    .await
                    .expect("Failed to init source db");
                }
            }
        }

        db.destroy().await.expect("Destroy should not fail");
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
