#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::Sha256;
use commonware_runtime::{buffer::PoolRef, deterministic, Runner};
use commonware_storage::{
    adb::any::{Any, Config},
    mmr::hasher::Standard,
    translator::TwoCap,
};
use commonware_utils::array::FixedBytes;
use libfuzzer_sys::fuzz_target;

type Key = FixedBytes<32>;
type Value = FixedBytes<32>;
type RawKey = [u8; 32];
type RawValue = [u8; 32];

#[derive(Arbitrary, Debug, Clone)]
enum AnyOperation {
    Update {
        key: RawKey,
        value: RawValue,
    },
    Delete {
        key: RawKey,
    },
    Commit,
    Proof {
        start_loc: u64,
        max_ops: u64,
    },
    HistoricalProof {
        size: u64,
        start_loc: u64,
        max_ops: u64,
    },
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    operations: Vec<AnyOperation>,
}

const PAGE_SIZE: usize = 88;
const PAGE_CACHE_SIZE: usize = 8;

fn fuzz(data: FuzzInput) {
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let cfg = Config {
            mmr_journal_partition: "fuzz_adb_any_sync".into(),
            mmr_metadata_partition: "fuzz_adb_any_sync_meta".into(),
            mmr_items_per_blob: 11,
            mmr_write_buffer: 1024,
            log_journal_partition: "fuzz_adb_any_sync_log".into(),
            log_items_per_blob: 7,
            log_write_buffer: 1024,
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        };

        let mut adb = Any::<deterministic::Context, Key, Value, Sha256, TwoCap>::init(context, cfg)
            .await
            .expect("Failed to initialize database");

        let mut hasher = Standard::<Sha256>::new();

        for op in data.operations.iter().take(20) {
            match op {
                AnyOperation::Update { key, value } => {
                    let k = Key::new(*key);
                    let v = Value::new(*value);
                    let _ = adb.update(k, v).await;
                }

                AnyOperation::Delete { key } => {
                    let k = Key::new(*key);
                    let _ = adb.delete(k).await;
                }

                AnyOperation::Commit => {
                    let _ = adb.commit().await;
                }

                AnyOperation::Proof { start_loc, max_ops } => {
                    let total = adb.op_count();
                    if total == 0 || *max_ops == 0 {
                        continue;
                    }

                    let _ = adb.commit().await;

                    let start = *start_loc % total;
                    let span = (*max_ops % 10).max(1);

                    if let Ok((proof, ops)) = adb.proof(start, span).await {
                        let root = adb.root(&mut hasher);
                        let _ =
                            Any::<deterministic::Context, Key, Value, Sha256, TwoCap>::verify_proof(
                                &mut hasher,
                                &proof,
                                start,
                                &ops,
                                &root,
                            );
                    }
                }

                AnyOperation::HistoricalProof {
                    size,
                    start_loc,
                    max_ops,
                } => {
                    let total = adb.op_count();
                    if total == 0 || *max_ops == 0 || *size == 0 {
                        continue;
                    }

                    let _ = adb.commit().await;

                    let hist_size = (*size % total.max(1)).max(1);
                    let start = *start_loc % hist_size;
                    let span = (*max_ops % 10).max(1);

                    if let Ok((proof, ops)) = adb.historical_proof(hist_size, start, span).await {
                        let root = adb.root(&mut hasher);
                        let _ =
                            Any::<deterministic::Context, Key, Value, Sha256, TwoCap>::verify_proof(
                                &mut hasher,
                                &proof,
                                start,
                                &ops,
                                &root,
                            );
                    }
                }
            }
        }

        let _ = adb.close().await;
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
