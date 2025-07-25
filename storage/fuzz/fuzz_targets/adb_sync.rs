#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_runtime::{buffer::PoolRef, deterministic, Runner};
use commonware_storage::{
    adb::any::{sync, Any, Config},
    mmr::hasher::Standard,
    translator::TwoCap,
};
use commonware_utils::{array::FixedBytes, NZU64};
use libfuzzer_sys::fuzz_target;

type Key = FixedBytes<32>;
type Value = FixedBytes<32>;

#[derive(Arbitrary, Debug)]
enum SyncOp {
    // Basic ops to build source state
    Update { key: [u8; 32], value: [u8; 32] },
    Delete { key: [u8; 32] },
    Commit,

    // Sync scenarios
    SyncFull { batch_size: u8 },
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    ops: Vec<SyncOp>,
}

const PAGE_SIZE: usize = 128;

fn base_config() -> Config<TwoCap> {
    Config {
        mmr_journal_partition: "".into(),
        mmr_metadata_partition: "".into(),
        mmr_items_per_blob: 3,
        mmr_write_buffer: 1024,
        log_journal_partition: "".into(),
        log_items_per_blob: 3,
        log_write_buffer: 1024,
        translator: TwoCap,
        thread_pool: None,
        buffer_pool: PoolRef::new(PAGE_SIZE, 1),
        pruning_delay: 5,
    }
}

async fn test_sync(
    context: deterministic::Context,
    src: &Any<deterministic::Context, Key, Value, Sha256, TwoCap>,
    target: sync::SyncTarget<commonware_cryptography::sha256::Digest>,
    batch_size: u8,
    test_name: &str,
) -> bool {
    let mut config = base_config();
    config.mmr_journal_partition = format!("{}_mmr", test_name);
    config.mmr_metadata_partition = format!("{}_meta", test_name);
    config.log_journal_partition = format!("{}_log", test_name);

    let expected_root = target.root;

    let sync_config = sync::client::Config {
        context,
        update_receiver: None,
        db_config: config,
        fetch_batch_size: NZU64!((batch_size as u64).clamp(1, 100)),
        target,
        resolver: src,
        hasher: Standard::<Sha256>::new(),
        apply_batch_size: 100,
    };

    if let Ok(mut synced) = sync::sync(sync_config).await {
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

fuzz_target!(|input: FuzzInput| {
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let mut src = Any::<_, Key, Value, Sha256, TwoCap>::init(context.clone(), {
            let mut cfg = base_config();
            cfg.mmr_journal_partition = "src_mmr".into();
            cfg.mmr_metadata_partition = "src_meta".into();
            cfg.log_journal_partition = "src_log".into();
            cfg
        })
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

                SyncOp::SyncFull { batch_size } => {
                    if src.op_count() == 0 {
                        continue;
                    }
                    src.commit()
                        .await
                        .expect("Commit before sync should not fail");

                    let mut hasher = Standard::<Sha256>::new();
                    let target = sync::SyncTarget {
                        root: src.root(&mut hasher),
                        lower_bound_ops: src.inactivity_floor_loc(),
                        upper_bound_ops: src.op_count() - 1,
                    };

                    test_sync(
                        context.clone(),
                        &src,
                        target,
                        *batch_size,
                        &format!("full_{}", sync_id),
                    )
                    .await;
                    sync_id += 1;
                }
            }
        }

        src.destroy().await.expect("Destroy should not fail");
    });
});
