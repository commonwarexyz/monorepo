#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{DecodeExt, FixedSize};
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner, Supervisor as _};
use commonware_storage::freezer::{Checkpoint, Config, Cursor, Freezer, Identifier};
use commonware_utils::{sequence::FixedBytes, FuzzRng, NZUsize, NZU16};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::HashMap,
    num::{NonZeroU16, NonZeroUsize},
};

#[derive(Arbitrary, Debug)]
enum Op {
    Put { key: Vec<u8>, value: i32 },
    Get { key: Vec<u8> },
    GetCursor { idx: u8 },
    Sync,
    Restart { mode: u8 },
    Close,
    Destroy,
}

const MAX_OPERATIONS: usize = 64;

#[derive(Debug)]
struct FuzzInput {
    table_initial_size: u32,
    table_resize_frequency: u8,
    table_resize_chunk_size: u32,
    zero_checkpoint: bool,
    ops: Vec<Op>,
    raw_bytes: Vec<u8>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Keep the table small so resizes are reachable within MAX_OPERATIONS.
        let table_initial_size = 1u32 << u.int_in_range(0..=4)?;
        let table_resize_frequency = u.int_in_range(1..=4)?;
        let table_resize_chunk_size = u.int_in_range(1..=8)?;
        let zero_checkpoint = bool::arbitrary(u)?;
        let num_ops = u.int_in_range(1..=MAX_OPERATIONS)?;
        let ops = (0..num_ops)
            .map(|_| Op::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;
        let raw_bytes = u.bytes(u.len())?.to_vec();
        Ok(FuzzInput {
            table_initial_size,
            table_resize_frequency,
            table_resize_chunk_size,
            zero_checkpoint,
            ops,
            raw_bytes,
        })
    }
}

/// State captured at sync time: the checkpoint plus the expected key-value
/// map and cursors valid as of that checkpoint.
type SyncedState = (Checkpoint, HashMap<FixedBytes<32>, i32>, Vec<(Cursor, i32)>);

fn vec_to_key(v: &[u8]) -> FixedBytes<32> {
    let mut buf = [0u8; 32];
    let len = v.len().min(32);
    buf[..len].copy_from_slice(&v[..len]);
    FixedBytes::<32>::new(buf)
}

const PAGE_SIZE: NonZeroU16 = NZU16!(393);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(100);

fn fuzz(input: FuzzInput) {
    let cfg = deterministic::Config::new().with_rng(Box::new(FuzzRng::new(input.raw_bytes)));
    let runner = deterministic::Runner::new(cfg);

    runner.start(|context| async move {
        let cfg = Config {
            key_partition: "fuzz-key".into(),
            key_write_buffer: NZUsize!(1024 * 1024),
            key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            value_partition: "fuzz-value".into(),
            value_compression: None,
            value_write_buffer: NZUsize!(1024 * 1024),
            value_target_size: 10 * 1024 * 1024,
            table_partition: "fuzz-table".into(),
            table_initial_size: input.table_initial_size,
            table_resize_frequency: input.table_resize_frequency,
            table_resize_chunk_size: input.table_resize_chunk_size,
            table_replay_buffer: NZUsize!(64 * 1024),
            codec_config: (),
        };
        // Initializing a fresh freezer with an empty checkpoint must behave
        // like initializing without one.
        let init_checkpoint = input
            .zero_checkpoint
            .then(|| Checkpoint::decode([0u8; Checkpoint::SIZE].as_ref()).unwrap());
        let mut freezer = Freezer::<_, FixedBytes<32>, i32>::init_with_checkpoint(
            context.child("storage"),
            cfg.clone(),
            init_checkpoint,
        )
        .await
        .unwrap();

        let mut expected_state: HashMap<FixedBytes<32>, i32> = HashMap::new();
        let mut cursors: Vec<(Cursor, i32)> = Vec::new();
        let mut synced: Option<SyncedState> = None;
        let mut restarts = 0usize;

        for op in input.ops {
            match op {
                Op::Put { key, value } => {
                    let k = vec_to_key(&key);
                    let cursor = freezer.put(k.clone(), value).await.unwrap();
                    expected_state.insert(k, value);
                    cursors.push((cursor, value));
                }
                Op::Get { key } => {
                    let k = vec_to_key(&key);
                    let res = freezer.get(Identifier::Key(&k)).await.unwrap();
                    assert_eq!(res, expected_state.get(&k).cloned());
                }
                Op::GetCursor { idx } => {
                    if cursors.is_empty() {
                        continue;
                    }
                    let (cursor, value) = cursors[idx as usize % cursors.len()];
                    assert_eq!(&*cursor, cursor.as_ref());
                    let res = freezer.get(Identifier::Cursor(cursor)).await.unwrap();
                    assert_eq!(res, Some(value));
                }
                Op::Sync => {
                    let checkpoint = freezer.sync().await.unwrap();
                    synced = Some((checkpoint, expected_state.clone(), cursors.clone()));
                }
                Op::Restart { mode } => {
                    let checkpoint = match mode % 3 {
                        // Close and recover from the table alone
                        0 => {
                            freezer.close().await.unwrap();
                            None
                        }
                        // Close and restore from the returned checkpoint
                        1 => Some(freezer.close().await.unwrap()),
                        // Crash (drop without close) and restore from the latest
                        // synced checkpoint, rolling back to its state
                        _ => match synced.clone() {
                            Some((checkpoint, state, synced_cursors)) => {
                                drop(freezer);
                                expected_state = state;
                                cursors = synced_cursors;
                                Some(checkpoint)
                            }
                            None => Some(freezer.close().await.unwrap()),
                        },
                    };
                    freezer = Freezer::<_, FixedBytes<32>, i32>::init_with_checkpoint(
                        context
                            .child("storage")
                            .with_attribute("instance", restarts),
                        cfg.clone(),
                        checkpoint,
                    )
                    .await
                    .unwrap();
                    restarts += 1;
                }
                Op::Close => {
                    freezer.close().await.unwrap();
                    return;
                }
                Op::Destroy => {
                    freezer.destroy().await.unwrap();
                    return;
                }
            }
        }

        freezer.close().await.unwrap();
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
