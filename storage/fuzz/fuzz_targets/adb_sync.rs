#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_runtime::{buffer::PoolRef, deterministic, Runner, RwLock};
use commonware_storage::{
    adb::{
        any::fixed::{Any, Config},
        sync,
    },
    mmr::{Location, StandardHasher as Standard},
    store::operation::Fixed,
    translator::TwoCap,
};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU64};
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;

type Key = FixedBytes<32>;
type Value = FixedBytes<32>;

#[derive(Arbitrary, Debug)]
enum SyncOp {
    // Basic ops to build source state
    Update { key: [u8; 32], value: [u8; 32] },
    Delete { key: [u8; 32] },
    Commit,
    Prune,

    // Sync scenarios
    SyncFull { fetch_batch_size: u64 },
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    ops: Vec<SyncOp>,
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
        let mut src =
            Any::<_, Key, Value, Sha256, TwoCap>::init(context.clone(), test_config("src"))
                .await
                .expect("Failed to init source db");

        let mut sync_id = 0;

        for op in input.ops.iter().take(50) {
            match op {
                SyncOp::Update { key, value } => {
                    src.update(Key::new(*key), Value::new(*value))
                        .await
                        .expect("Update should not fail");
                }

                SyncOp::Delete { key } => {
                    src.delete(Key::new(*key))
                        .await
                        .expect("Delete should not fail");
                }

                SyncOp::Commit => {
                    src.commit().await.expect("Commit should not fail");
                }

                SyncOp::Prune => {
                    src.prune(src.inactivity_floor_loc())
                        .await
                        .expect("Prune should not fail");
                }

                SyncOp::SyncFull { fetch_batch_size } => {
                    if src.op_count() == 0 {
                        continue;
                    }
                    src.commit()
                        .await
                        .expect("Commit before sync should not fail");

                    let mut hasher = Standard::<Sha256>::new();
                    let target = sync::Target {
                        root: src.root(&mut hasher),
                        lower_bound: src.inactivity_floor_loc(),
                        upper_bound: Location::new(src.op_count() - 1),
                    };

                    let wrapped_src = Arc::new(RwLock::new(src));
                    let _result = test_sync(
                        context.clone(),
                        wrapped_src.clone(),
                        target,
                        *fetch_batch_size,
                        &format!("full_{sync_id}"),
                    )
                    .await;
                    src = Arc::try_unwrap(wrapped_src)
                        .unwrap_or_else(|_| panic!("Failed to unwrap src"))
                        .into_inner();
                    sync_id += 1;
                }
            }
        }

        src.destroy().await.expect("Destroy should not fail");
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
