#![no_main]

use arbitrary::Arbitrary;
use commonware_runtime::{deterministic, Runner};
use commonware_storage::freezer::{Config, Freezer, Identifier};
use commonware_utils::{sequence::FixedBytes, NZUsize};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

#[derive(Arbitrary, Debug)]
enum Op {
    Put { key: Vec<u8>, value: i32 },
    Get { key: Vec<u8> },
    Sync,
    Close,
    Destroy,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    ops: Vec<Op>,
}

fn vec_to_key(v: &[u8]) -> FixedBytes<32> {
    let mut buf = [0u8; 32];
    let len = v.len().min(32);
    buf[..len].copy_from_slice(&v[..len]);
    FixedBytes::<32>::new(buf)
}

fn fuzz(input: FuzzInput) {
    let runner = deterministic::Runner::default();

    runner.start(|context| async move {
        let cfg = Config {
            journal_partition: "fuzz_journal".into(),
            journal_compression: None,
            journal_write_buffer: NZUsize!(1024 * 1024),
            journal_target_size: 10 * 1024 * 1024,
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

        for op in input.ops.into_iter().take(64) {
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
