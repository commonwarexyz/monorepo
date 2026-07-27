#![no_main]

use arbitrary::Arbitrary;
use commonware_runtime::{Runner, Supervisor as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::freezer::{Checkpoint, Config, Cursor, Freezer, Identifier};
use commonware_utils::{FuzzRng, NZU16, NZUsize, sequence::FixedBytes};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::{NonZeroU16, NonZeroUsize},
};

#[derive(Arbitrary, Debug)]
enum Op {
    Put { key: [u8; 32], value: i32 },
    Get { key: [u8; 32] },
    Sync,
    Close,
    Destroy,
    Crash,
}

const MAX_OPERATIONS: usize = 64;
const RNG_BYTES: usize = 32;

#[derive(Debug)]
struct FuzzInput {
    raw_bytes: [u8; RNG_BYTES],
    compression: Option<u8>,
    ops: Vec<Op>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let raw_bytes = u.arbitrary()?;
        let compression = u.arbitrary::<bool>()?.then_some(3);
        let num_ops = u.int_in_range(1..=MAX_OPERATIONS)?;
        let ops = (0..num_ops)
            .map(|_| Op::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(FuzzInput {
            raw_bytes,
            compression,
            ops,
        })
    }
}

const PAGE_SIZE: NonZeroU16 = NZU16!(393);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(100);

fn config(context: &deterministic::Context, compression: Option<u8>) -> Config<()> {
    Config {
        key_partition: "fuzz-key".into(),
        key_write_buffer: NZUsize!(1024),
        key_page_cache: CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE),
        value_partition: "fuzz-value".into(),
        value_compression: compression,
        value_write_buffer: NZUsize!(1024),
        value_target_size: 64,
        table_partition: "fuzz-table".into(),
        table_initial_size: 4,
        table_resize_frequency: 2,
        table_resize_chunk_size: 1,
        table_replay_buffer: NZUsize!(64 * 1024),
        codec_config: (),
    }
}

type Model = BTreeMap<FixedBytes<32>, i32>;
type CursorModel = Vec<(Cursor, i32)>;

#[derive(Default)]
struct Expected {
    checkpoint: Option<Checkpoint>,
    durable: Model,
    durable_cursors: CursorModel,
    seen: BTreeSet<FixedBytes<32>>,
}

async fn verify(
    freezer: &Freezer<deterministic::Context, FixedBytes<32>, i32>,
    expected: &Expected,
) {
    for key in &expected.seen {
        assert_eq!(
            freezer.get(Identifier::Key(key)).await.unwrap(),
            expected.durable.get(key).copied()
        );
    }
    for &(cursor, value) in &expected.durable_cursors {
        assert_eq!(
            freezer.get(Identifier::Cursor(cursor)).await.unwrap(),
            Some(value)
        );
    }
}

fn split_cycles(ops: Vec<Op>) -> Vec<Vec<Op>> {
    let mut cycles = Vec::new();
    let mut current = Vec::new();
    for op in ops {
        if matches!(op, Op::Crash) {
            cycles.push(std::mem::take(&mut current));
        } else {
            current.push(op);
        }
    }
    cycles.push(current);
    cycles
}

fn run_cycle(
    runner: deterministic::Runner,
    compression: Option<u8>,
    expected: Expected,
    ops: Vec<Op>,
) -> (Expected, deterministic::Checkpoint) {
    runner.start_and_recover(move |context| async move {
        let mut freezer = Freezer::<_, FixedBytes<32>, i32>::init(
            context.child("storage"),
            config(&context, compression),
            expected.checkpoint,
        )
        .await
        .expect("recovery should succeed");
        verify(&freezer, &expected).await;

        let mut live = expected.durable.clone();
        let mut durable = expected.durable;
        let mut live_cursors = expected.durable_cursors.clone();
        let mut durable_cursors = expected.durable_cursors;
        let mut seen = expected.seen;
        let mut checkpoint = expected.checkpoint;

        for op in ops {
            match op {
                Op::Put { key, value } => {
                    let key = FixedBytes::new(key);
                    let cursor;
                    (freezer, cursor) = freezer.put(key.clone(), value).await.unwrap();
                    seen.insert(key.clone());
                    live.insert(key, value);
                    live_cursors.push((cursor, value));
                }
                Op::Get { key } => {
                    let key = FixedBytes::new(key);
                    assert_eq!(
                        freezer.get(Identifier::Key(&key)).await.unwrap(),
                        live.get(&key).copied()
                    );
                }
                Op::Sync => {
                    let next_checkpoint;
                    (freezer, next_checkpoint) = freezer.sync().await.unwrap();
                    checkpoint = Some(next_checkpoint);
                    durable.clone_from(&live);
                    durable_cursors.clone_from(&live_cursors);
                }
                Op::Close => {
                    checkpoint = Some(freezer.close().await.unwrap());
                    durable = live;
                    durable_cursors = live_cursors;
                    return Expected {
                        checkpoint,
                        durable,
                        durable_cursors,
                        seen,
                    };
                }
                Op::Destroy => {
                    freezer.destroy().await.unwrap();
                    return Expected {
                        checkpoint: None,
                        durable: Model::new(),
                        durable_cursors: CursorModel::new(),
                        seen,
                    };
                }
                Op::Crash => unreachable!("Crash operations are cycle separators"),
            }
        }

        // The published checkpoint remains authoritative. Dirty writes may survive beneath it,
        // but the next boot must repair back to this exact model.
        Expected {
            checkpoint,
            durable,
            durable_cursors,
            seen,
        }
    })
}

fn fuzz(input: FuzzInput) {
    let rng = FuzzRng::new(input.raw_bytes.to_vec());
    let mut runner =
        deterministic::Runner::new(deterministic::Config::default().with_rng(Box::new(rng)));
    let compression = input.compression;
    let mut expected = Expected::default();

    for cycle in split_cycles(input.ops) {
        let checkpoint;
        (expected, checkpoint) = run_cycle(runner, compression, expected, cycle);
        runner = deterministic::Runner::from(checkpoint);
    }

    // Recover the last fuzz cycle, commit a sentinel, and cross one more crash boundary.
    let (expected, runtime_checkpoint) = runner.start_and_recover(move |context| async move {
        let mut freezer = Freezer::<_, FixedBytes<32>, i32>::init(
            context.child("sentinel"),
            config(&context, compression),
            expected.checkpoint,
        )
        .await
        .expect("sentinel recovery should succeed");
        verify(&freezer, &expected).await;

        let sentinel = FixedBytes::new([0xFF; 32]);
        let cursor;
        (freezer, cursor) = freezer.put(sentinel.clone(), i32::MAX).await.unwrap();
        let checkpoint;
        (freezer, checkpoint) = freezer.sync().await.unwrap();
        let mut durable = expected.durable;
        durable.insert(sentinel.clone(), i32::MAX);
        let mut durable_cursors = expected.durable_cursors;
        durable_cursors.push((cursor, i32::MAX));
        let mut seen = expected.seen;
        seen.insert(sentinel);
        drop(freezer);
        Expected {
            checkpoint: Some(checkpoint),
            durable,
            durable_cursors,
            seen,
        }
    });

    let (_, runtime_checkpoint) = deterministic::Runner::from(runtime_checkpoint)
        .start_and_recover(move |context| async move {
            let freezer = Freezer::<_, FixedBytes<32>, i32>::init(
                context.child("final"),
                config(&context, compression),
                expected.checkpoint,
            )
            .await
            .expect("final recovery should succeed");
            verify(&freezer, &expected).await;
            *context.storage_fault_config().write() =
                deterministic::FaultConfig::default().remove(0.5);
            let _ = freezer.destroy().await;
        });

    deterministic::Runner::from(runtime_checkpoint).start(move |context| async move {
        *context.storage_fault_config().write() = deterministic::FaultConfig::default();
        // Once destroy starts, the external checkpoint must be invalidated. Reopening without it
        // exercises both an interrupted destroy and the documented reset path before retrying.
        let freezer = Freezer::<_, FixedBytes<32>, i32>::init(
            context.child("redestroy"),
            config(&context, compression),
            None,
        )
        .await
        .expect("freezer reset must clean up interrupted destroy state");
        freezer.destroy().await.expect("destroy retry must succeed");
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
