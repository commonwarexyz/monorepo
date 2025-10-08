#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::blake3::Digest;
use commonware_runtime::{buffer::PoolRef, deterministic, Runner};
use commonware_storage::{
    mmr::Location,
    store::{Config, Store},
    translator::TwoCap,
};
use commonware_utils::{NZUsize, NZU64};
use libfuzzer_sys::fuzz_target;

const MAX_OPERATIONS: usize = 50;

type Key = Digest;
type Value = Vec<u8>;

#[derive(Debug)]
enum Operation {
    Update {
        key: [u8; 32],
        value_bytes: Vec<u8>,
    },
    Delete {
        key: [u8; 32],
    },
    Commit {
        metadata_bytes: Option<Vec<u8>>,
    },
    Get {
        key: [u8; 32],
    },
    GetLoc {
        loc_offset: u32,
    },
    GetMetadata,
    Sync,
    Prune,
    OpCount,
    InactivityFloorLoc,
    SimulateFailure {
        sync_locations: bool,
        sync_log: bool,
    },
}

impl<'a> Arbitrary<'a> for Operation {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let choice: u8 = u.arbitrary()?;
        match choice % 12 {
            0 => {
                let key = u.arbitrary()?;
                let value_len: u16 = u.arbitrary()?;
                let actual_len = ((value_len as usize) % 10000) + 1;
                let value_bytes = u.bytes(actual_len)?.to_vec();
                Ok(Operation::Update { key, value_bytes })
            }
            1 => {
                let key = u.arbitrary()?;
                Ok(Operation::Delete { key })
            }
            2 => {
                let has_metadata: bool = u.arbitrary()?;
                let metadata_bytes = if has_metadata {
                    let metadata_len: u16 = u.arbitrary()?;
                    let actual_len = ((metadata_len as usize) % 1000) + 1;
                    Some(u.bytes(actual_len)?.to_vec())
                } else {
                    None
                };
                Ok(Operation::Commit { metadata_bytes })
            }
            3 => {
                let key = u.arbitrary()?;
                Ok(Operation::Get { key })
            }
            4 => {
                let loc_offset = u.arbitrary()?;
                Ok(Operation::GetLoc { loc_offset })
            }
            5 => Ok(Operation::GetMetadata),
            6 => Ok(Operation::Sync),
            7 => Ok(Operation::Prune),
            8 => Ok(Operation::OpCount),
            9 => Ok(Operation::InactivityFloorLoc),
            10 | 11 => {
                let sync_locations: bool = u.arbitrary()?;
                let sync_log: bool = u.arbitrary()?;
                Ok(Operation::SimulateFailure {
                    sync_locations,
                    sync_log,
                })
            }
            _ => unreachable!(),
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    ops: Vec<Operation>,
}

const PAGE_SIZE: usize = 128;
const PAGE_CACHE_SIZE: usize = 8;

fn test_config(test_name: &str) -> Config<TwoCap, (commonware_codec::RangeCfg<usize>, ())> {
    Config {
        log_journal_partition: format!("{test_name}_log"),
        log_write_buffer: NZUsize!(1024),
        log_compression: None,
        log_codec_config: ((0..=10000).into(), ()),
        log_items_per_section: NZU64!(7),
        locations_journal_partition: format!("{test_name}_locations"),
        locations_items_per_blob: NZU64!(11),
        translator: TwoCap,
        buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
    }
}

fn fuzz(input: FuzzInput) {
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let mut store =
            Store::<_, Key, Value, TwoCap>::init(context.clone(), test_config("store_fuzz_test"))
                .await
                .expect("Failed to init store");

        for op in input.ops.iter().take(MAX_OPERATIONS) {
            match op {
                Operation::Update { key, value_bytes } => {
                    store
                        .update(Digest(*key), value_bytes.clone())
                        .await
                        .expect("Update should not fail");
                }

                Operation::Delete { key } => {
                    store
                        .delete(Digest(*key))
                        .await
                        .expect("Delete should not fail");
                }

                Operation::Commit { metadata_bytes } => {
                    store
                        .commit(metadata_bytes.clone())
                        .await
                        .expect("Commit should not fail");
                }

                Operation::Get { key } => {
                    let _ = store.get(&Digest(*key)).await;
                }

                Operation::GetLoc { loc_offset } => {
                    let op_count = store.op_count();
                    if op_count > 0 {
                        let loc = (*loc_offset as u64) % op_count.as_u64();
                        let _ = store.get_loc(Location::new(loc)).await;
                    }
                }

                Operation::GetMetadata => {
                    let _ = store.get_metadata().await;
                }

                Operation::Sync => {
                    store.sync().await.expect("Sync should not fail");
                }

                Operation::Prune => {
                    store
                        .prune(store.inactivity_floor_loc())
                        .await
                        .expect("Prune should not fail");
                }

                Operation::OpCount => {
                    let _ = store.op_count();
                }

                Operation::InactivityFloorLoc => {
                    let _ = store.inactivity_floor_loc();
                }

                Operation::SimulateFailure {
                    sync_locations,
                    sync_log,
                } => {
                    store
                        .simulate_failure(*sync_locations, *sync_log)
                        .await
                        .expect("Simulate failure should not fail");

                    store = Store::<_, Key, Value, TwoCap>::init(
                        context.clone(),
                        test_config("store_fuzz_test"),
                    )
                    .await
                    .expect("Failed to init store");
                }
            }
        }

        store.destroy().await.expect("Destroy should not fail");
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
