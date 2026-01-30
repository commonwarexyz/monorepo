#![no_main]

use arbitrary::Arbitrary;
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner};
use commonware_storage::freezer::{Config, Freezer, Identifier};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU16};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::HashMap,
    num::{NonZeroU16, NonZeroUsize},
};

#[derive(Arbitrary, Debug)]
enum Op {
    Put { key: Vec<u8>, value: i32 },
    Get { key: Vec<u8> },
    Sync,
    Close,
    Destroy,
}

const MAX_OPERATIONS: usize = 64;

#[derive(Debug)]
struct FuzzInput {
    ops: Vec<Op>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let num_ops = u.int_in_range(1..=MAX_OPERATIONS)?;
        let ops = (0..num_ops)
            .map(|_| Op::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(FuzzInput { ops })
    }
}

fn vec_to_key(v: &[u8]) -> FixedBytes<32> {
    let mut buf = [0u8; 32];
    let len = v.len().min(32);
    buf[..len].copy_from_slice(&v[..len]);
    FixedBytes::<32>::new(buf)
}

const PAGE_SIZE: NonZeroU16 = NZU16!(393);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(100);

fn fuzz(input: FuzzInput) {
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let cfg = Config {
            key_partition: "fuzz_key".into(),
            key_write_buffer: NZUsize!(1024 * 1024),
            key_page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            value_partition: "fuzz_value".into(),
            value_compression: None,
            value_write_buffer: NZUsize!(1024 * 1024),
            value_target_size: 10 * 1024 * 1024,
            table_partition: "fuzz_table".into(),
            table_initial_size: 256,
            table_resize_frequency: 4,
            table_resize_chunk_size: 128,
            table_replay_buffer: NZUsize!(64 * 1024),
            codec_config: (),
        };
        let mut freezer = Freezer::<_, FixedBytes<32>, i32>::init(context.clone(), cfg.clone())
            .await
            .unwrap();

        let mut expected_state: HashMap<FixedBytes<32>, i32> = HashMap::new();

        for op in input.ops {
            match op {
                Op::Put { key, value } => {
                    let k = vec_to_key(&key);
                    freezer.put(k.clone(), value).await.unwrap();
                    expected_state.insert(k, value);
                }
                Op::Get { key } => {
                    let k = vec_to_key(&key);
                    let res = freezer.get(Identifier::Key(&k)).await.unwrap();
                    assert_eq!(res, expected_state.get(&k).cloned());
                }
                Op::Sync => {
                    freezer.sync().await.unwrap();
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
