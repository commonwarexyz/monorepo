#![no_main]

//! Freezer recovery across supported partial-write crash cuts.

use arbitrary::Arbitrary;
use commonware_cryptography::Crc32;
use commonware_runtime::{
    BufferPooler, Runner, Supervisor as _,
    buffer::paged::CacheRef,
    deterministic::{self, PartialWriteMode, WriteConfig},
};
use commonware_storage::freezer::{Config, Freezer, Identifier};
use commonware_utils::{NZU16, NZUsize, Probability, sequence::FixedBytes};
use libfuzzer_sys::fuzz_target;

type Key = FixedBytes<32>;

const TABLE_SIZE: u32 = 4;

#[derive(Arbitrary, Clone, Copy, Debug)]
enum WritePath {
    Put,
    Resize,
}

#[derive(Arbitrary, Clone, Copy, Debug)]
enum CrashKind {
    FailedWrite,
    UnsyncedWrite,
}

#[derive(Arbitrary, Clone, Debug)]
struct FuzzInput {
    seed: u64,
    path: WritePath,
    crash: CrashKind,
    retention: u8,
}

fn config(pooler: &impl BufferPooler) -> Config<()> {
    Config {
        key_partition: "freezer-recovery-index".into(),
        key_write_buffer: NZUsize!(1),
        key_page_cache: CacheRef::from_pooler(pooler, NZU16!(128), NZUsize!(4)),
        value_partition: "freezer-recovery-values".into(),
        value_compression: None,
        value_write_buffer: NZUsize!(1),
        value_target_size: 64,
        table_partition: "freezer-recovery-table".into(),
        table_initial_size: TABLE_SIZE,
        table_resize_frequency: 1,
        table_resize_chunk_size: 1,
        table_replay_buffer: NZUsize!(512),
        codec_config: (),
    }
}

fn key_for_slot(slot: u32, tag: u8) -> Key {
    for nonce in 0..10_000u64 {
        let mut key = [0u8; 32];
        key[0] = tag;
        key[8..16].copy_from_slice(&nonce.to_be_bytes());
        if Crc32::checksum(&key) & (TABLE_SIZE - 1) == slot {
            return Key::new(key);
        }
    }
    unreachable!("bounded key search must cover every four-entry table slot")
}

fn baseline_key(slot: u32) -> Key {
    key_for_slot(slot, 0x10 + slot as u8)
}

fn candidate_key() -> Key {
    key_for_slot(1, 0x80)
}

fn sentinel_key() -> Key {
    key_for_slot(3, 0xF0)
}

async fn assert_values<E: commonware_storage::Context>(
    freezer: &Freezer<E, Key, i32>,
    expected: &[(Key, i32)],
) {
    let mut candidates = (0..3).map(baseline_key).collect::<Vec<_>>();
    candidates.extend([candidate_key(), sentinel_key()]);
    for key in candidates {
        let expected_value = expected
            .iter()
            .find_map(|(expected_key, value)| (expected_key == &key).then_some(*value));
        assert_eq!(
            freezer.get(Identifier::Key(&key)).await.unwrap(),
            expected_value,
            "unexpected value for freezer key {key:?}"
        );
        assert_eq!(freezer.has(&key).await.unwrap(), expected_value.is_some());
    }
}

fn run(input: &FuzzInput, mode: PartialWriteMode) {
    let phase_input = input.clone();
    let runner = deterministic::Runner::new(deterministic::Config::default().with_seed(input.seed));
    let ((freezer_checkpoint, baseline), runtime_checkpoint) =
        runner.start_and_recover(move |context| async move {
            // Build a checkpointed baseline. The resize case deliberately leaves a bounded resize
            // in progress so the next sync writes both the old and new table regions.
            let mut freezer =
                Freezer::<_, Key, i32>::init(context.child("freezer"), config(&context), None)
                    .await
                    .expect("initial freezer init failed");
            let baseline_slots: &[u32] = match phase_input.path {
                WritePath::Put => &[0],
                WritePath::Resize => &[0, 1, 2],
            };
            let mut baseline = Vec::new();
            for &slot in baseline_slots {
                let key = baseline_key(slot);
                let value = 100 + slot as i32;
                (freezer, _) = freezer
                    .put(key.clone(), value)
                    .await
                    .expect("baseline put failed");
                baseline.push((key, value));
            }
            let freezer_checkpoint;
            (freezer, freezer_checkpoint) = freezer.sync().await.expect("baseline sync failed");

            // Failed writes retain selected submitted bytes immediately. Successful writes remain
            // unsynced by forcing the next durability operation to fail, after which the instance
            // is dropped without further use.
            let failure_rate = match phase_input.crash {
                CrashKind::FailedWrite => Probability::new(1, 1).unwrap(),
                CrashKind::UnsyncedWrite => Probability::new(0, 1).unwrap(),
            };
            let sync_rate = match phase_input.crash {
                CrashKind::FailedWrite => None,
                CrashKind::UnsyncedWrite => Some(Probability::new(1, 1).unwrap()),
            };
            *context.storage_fault_config().write() = deterministic::FaultConfig {
                write_rate: Some(WriteConfig {
                    failure_rate,
                    retention_rate: Probability::new(u64::from(phase_input.retention % 101), 100)
                        .unwrap(),
                    mode,
                }),
                sync_rate,
                ..Default::default()
            };

            match phase_input.path {
                WritePath::Put => {
                    let updated = freezer.put(baseline_key(0), 900).await;
                    let mut freezer = match updated {
                        Ok((freezer, _)) => freezer,
                        Err(_) => {
                            assert!(matches!(phase_input.crash, CrashKind::FailedWrite));
                            return (freezer_checkpoint, baseline);
                        }
                    };
                    let inserted = freezer.put(candidate_key(), 901).await;
                    freezer = match inserted {
                        Ok((freezer, _)) => freezer,
                        Err(_) => {
                            assert!(matches!(phase_input.crash, CrashKind::FailedWrite));
                            return (freezer_checkpoint, baseline);
                        }
                    };
                    assert!(
                        freezer.sync().await.is_err(),
                        "faulted candidate sync unexpectedly succeeded"
                    );
                }
                WritePath::Resize => {
                    assert!(
                        freezer.sync().await.is_err(),
                        "faulted resize sync unexpectedly succeeded"
                    );
                }
            }

            (freezer_checkpoint, baseline)
        });

    deterministic::Runner::from(runtime_checkpoint).start(move |context| async move {
        *context.storage_fault_config().write() = deterministic::FaultConfig::default();

        // A supplied checkpoint is the Freezer authority: recovery trims the oversized journal,
        // table epochs, and an interrupted resize back to exactly the checkpointed logical state.
        let mut freezer = Freezer::<_, Key, i32>::init(
            context.child("recovered"),
            config(&context),
            Some(freezer_checkpoint),
        )
        .await
        .expect("freezer recovery failed");
        assert_values(&freezer, &baseline).await;

        // Prove the recovered structure can publish a new checkpoint and survive another reopen.
        let sentinel = sentinel_key();
        let mut expected = baseline;
        (freezer, _) = freezer
            .put(sentinel.clone(), 999)
            .await
            .expect("post-recovery put failed");
        expected.push((sentinel, 999));
        let checkpoint;
        (freezer, checkpoint) = freezer.sync().await.expect("post-recovery sync failed");
        drop(freezer);

        let freezer = Freezer::<_, Key, i32>::init(
            context.child("reopened"),
            config(&context),
            Some(checkpoint),
        )
        .await
        .expect("post-recovery reopen failed");
        assert_values(&freezer, &expected).await;
        freezer.destroy().await.expect("freezer destroy failed");
    });
}

fn fuzz(input: FuzzInput) {
    for mode in [PartialWriteMode::Prefix, PartialWriteMode::Subset] {
        run(&input, mode);
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
