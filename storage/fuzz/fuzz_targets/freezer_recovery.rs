#![no_main]

//! Freezer recovery across supported partial-write crash cuts.
//!
//! The crash cuts either the put path (candidate writes past a checkpointed baseline) or
//! the resize path (a sync that writes both table regions while a bounded resize is in
//! progress), through failed writes that retain selected submitted bytes or successful
//! writes left volatile by a failed durability barrier. The deepen arm first completes a
//! table resize and rolls past one value section, so recovery trims a multi-section value
//! journal against a doubled table.
//!
//! The oracle treats the supplied checkpoint as the Freezer authority: recovery must trim
//! the oversized journal, table epochs, and any interrupted resize back to exactly the
//! checkpointed logical state, and every cursor from the discarded candidate suffix must
//! be unreadable. A sentinel put, sync, and reopen then prove the recovered instance can
//! publish a new checkpoint.

use arbitrary::Arbitrary;
use commonware_cryptography::Crc32;
use commonware_runtime::{
    BufferPooler, Runner, Supervisor as _,
    buffer::paged::CacheRef,
    deterministic::{self, PartialWriteMode, WriteConfig},
};
use commonware_storage::freezer::{Config, Freezer, Identifier};
use commonware_storage_fuzz::{bounded_entropy, faulted_recovery};
use commonware_utils::{FuzzRng, NZU16, NZUsize, Probability, sequence::FixedBytes};
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
    /// Write path the crash cuts: candidate puts or an in-progress table resize sync.
    path: WritePath,
    /// Cut through failed writes (bytes retained immediately) or successful writes
    /// left volatile by a failed durability barrier.
    crash: CrashKind,
    /// Byte retention rate (percent) for the partial writes the crash leaves behind.
    retention: u8,
    /// Let the first candidate write succeed (volatile) and fail the second,
    /// so the failed-write cut can land past a pending update.
    fail_second: bool,
    /// Deepen the checkpointed baseline with filler puts and syncs that complete
    /// a table resize and roll past one value section before the crash scenario.
    deepen: bool,
    /// Byte stream driving the runtime rng: all in-run randomness, fault sampling, and the
    /// faulted recovery chain's depth and shapes.
    #[arbitrary(with = bounded_entropy)]
    entropy: Vec<u8>,
}

/// Build the deterministic Freezer configuration used by the recovery scenario.
fn config(pooler: &impl BufferPooler) -> Config<()> {
    Config {
        key_partition: "freezer-recovery-index".into(),
        key_write_buffer: NZUsize!(1),
        // A page size that no key-record size divides, so terminal boundary entries straddle
        // pages and restore exercises the multi-page tail read.
        key_page_cache: CacheRef::from_pooler(pooler, NZU16!(72), NZUsize!(4)),
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

/// Find a deterministic key whose checksum maps to `slot`.
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

/// Return the baseline key for `slot`.
fn baseline_key(slot: u32) -> Key {
    key_for_slot(slot, 0x10 + slot as u8)
}

/// Return the candidate key mapped to table slot 1.
fn candidate_key() -> Key {
    key_for_slot(1, 0x80)
}

/// Return the sentinel key used for post-recovery checks.
fn sentinel_key() -> Key {
    key_for_slot(3, 0xF0)
}

/// Assert all scenario keys expose the expected values and presence state.
async fn assert_values<E: commonware_storage::Context>(
    freezer: &Freezer<E, Key, i32>,
    expected: &[(Key, i32)],
) {
    let mut candidates = (0..4).map(baseline_key).collect::<Vec<_>>();
    candidates.extend([candidate_key(), sentinel_key()]);
    candidates.extend(expected.iter().map(|(key, _)| key.clone()));
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

/// Run one crash/recovery scenario for the selected partial-write mode.
fn run(input: &FuzzInput, mode: PartialWriteMode) {
    let phase_input = input.clone();
    let cfg =
        deterministic::Config::default().with_rng(Box::new(FuzzRng::new(input.entropy.clone())));
    let runner = deterministic::Runner::new(cfg);
    let ((freezer_checkpoint, baseline, candidate_cursors), runtime_checkpoint) = runner
        .start_and_recover(move |context| async move {
            // Build a checkpointed baseline. The resize case deliberately leaves a bounded resize
            // in progress so the next sync writes both the old and new table regions.
            let mut freezer =
                Freezer::<_, Key, i32>::init(context.child("freezer"), config(&context), None)
                    .await
                    .expect("initial freezer init failed");
            let mut baseline = Vec::new();

            // Deepen the checkpointed state: mark every initial slot, then advance the
            // bounded resize one chunk per sync until it completes (start plus three more
            // advances for a four-entry table), doubling the table and resetting every
            // slot's added count. Eight framed values also roll past one value section,
            // so restore later trims a multi-section journal against a doubled table.
            if phase_input.deepen {
                for round in 0..8u32 {
                    let key = key_for_slot(round % TABLE_SIZE, 0x30 + round as u8);
                    let value = 300 + round as i32;
                    (freezer, _) = freezer
                        .put(key.clone(), value)
                        .await
                        .expect("filler put failed");
                    baseline.push((key, value));
                }
                for _ in 0..4 {
                    (freezer, _) = freezer.sync().await.expect("filler sync failed");
                }
            }

            // A deepened resize scenario marks four slots: after the completed resize the
            // threshold doubles, and the distinct low residues land in distinct slots of
            // the doubled table, so the checkpoint sync leaves a fresh resize in progress.
            let baseline_slots: &[u32] = match (phase_input.path, phase_input.deepen) {
                (WritePath::Put, _) => &[0],
                (WritePath::Resize, false) => &[0, 1, 2],
                (WritePath::Resize, true) => &[0, 1, 2, 3],
            };
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
            // is dropped without further use. With `fail_second`, the first candidate write
            // succeeds (volatile) and the failure is armed just before the second, so the cut
            // lands past a pending update.
            let fail_second = matches!(phase_input.path, WritePath::Put)
                && matches!(phase_input.crash, CrashKind::FailedWrite)
                && phase_input.fail_second;
            let failure_rate = match phase_input.crash {
                CrashKind::FailedWrite if fail_second => Probability::new(0, 1).unwrap(),
                CrashKind::FailedWrite => Probability::new(1, 1).unwrap(),
                CrashKind::UnsyncedWrite => Probability::new(0, 1).unwrap(),
            };
            let sync_rate = match phase_input.crash {
                CrashKind::FailedWrite => None,
                CrashKind::UnsyncedWrite => Some(Probability::new(1, 1).unwrap()),
            };
            let fault_config = context.storage_fault_config();
            *fault_config.write() = deterministic::FaultConfig {
                write_rate: Some(WriteConfig {
                    failure_rate,
                    retention_rate: Probability::new(u64::from(phase_input.retention % 101), 100)
                        .unwrap(),
                    mode,
                }),
                sync_rate,
                ..Default::default()
            };

            let candidate_cursors = match phase_input.path {
                WritePath::Put => {
                    let updated = freezer.put(baseline_key(0), 900).await;
                    let (freezer, updated_cursor) = match updated {
                        Ok(result) => result,
                        Err(_) => {
                            // With fail_second the failure rate is still zero here, so
                            // the first put has no legal way to fail.
                            assert!(
                                matches!(phase_input.crash, CrashKind::FailedWrite) && !fail_second
                            );
                            return (freezer_checkpoint, baseline, Vec::new());
                        }
                    };
                    if fail_second {
                        fault_config
                            .write()
                            .write_rate
                            .as_mut()
                            .expect("write faults configured")
                            .failure_rate = Probability::new(1, 1).unwrap();
                    }
                    let inserted = freezer.put(candidate_key(), 901).await;
                    let (freezer, inserted_cursor) = match inserted {
                        Ok(result) => result,
                        Err(_) => {
                            assert!(matches!(phase_input.crash, CrashKind::FailedWrite));
                            return (freezer_checkpoint, baseline, vec![updated_cursor]);
                        }
                    };
                    assert!(
                        freezer.sync().await.is_err(),
                        "faulted candidate sync unexpectedly succeeded"
                    );
                    vec![updated_cursor, inserted_cursor]
                }
                WritePath::Resize => {
                    assert!(
                        freezer.sync().await.is_err(),
                        "faulted resize sync unexpectedly succeeded"
                    );
                    Vec::new()
                }
            };

            (freezer_checkpoint, baseline, candidate_cursors)
        });

    // Chain faulted recovery attempts, each restoring the checkpoint under fresh faults
    // and crashing into the next.
    let runtime_checkpoint = faulted_recovery(runtime_checkpoint, move |context| async move {
        Freezer::<_, Key, i32>::init(
            context.child("faulted_recovery"),
            config(&context),
            Some(freezer_checkpoint),
        )
        .await
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

        // Cursor reads bypass the table, so restoring a checkpoint must make every cursor from
        // the discarded candidate suffix unreadable as well as hiding its keys.
        for cursor in candidate_cursors {
            assert!(
                freezer.get(Identifier::Cursor(cursor)).await.is_err(),
                "checkpoint recovery left a discarded cursor readable: {cursor}",
            );
        }

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

/// Exercise recovery under both supported partial-write retention modes.
fn fuzz(input: FuzzInput) {
    for mode in [PartialWriteMode::Prefix, PartialWriteMode::Subset] {
        run(&input, mode);
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
