#![no_main]

//! Immutable archive recovery across supported partial-write crash cuts.

use arbitrary::Arbitrary;
use commonware_runtime::{
    BufferPooler, Runner, Supervisor as _,
    buffer::paged::CacheRef,
    deterministic::{self, PartialWriteMode, WriteConfig},
};
use commonware_storage::{
    archive::{
        Archive as ArchiveTrait, Identifier,
        immutable::{Archive, Config},
    },
    rmap::RMap,
};
use commonware_storage_fuzz::faulted_recovery;
use commonware_utils::{NZU16, NZU64, NZUsize, Probability, sequence::FixedBytes};
use libfuzzer_sys::fuzz_target;

type Key = FixedBytes<16>;
type Value = FixedBytes<32>;
type TestArchive = Archive<deterministic::Context, Key, Value>;

#[derive(Arbitrary, Clone, Copy, Debug)]
enum FaultKind {
    Write,
    Sync,
}

#[derive(Arbitrary, Clone, Debug)]
struct FuzzInput {
    seed: u64,
    fault: FaultKind,
    rate: u8,
    retention: u8,
    payload: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
enum Outcome {
    PutFailed,
    SyncFailed,
    Synced,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Entry {
    index: u64,
    key: Key,
    value: Value,
}

/// Build the immutable archive configuration used by the recovery scenario.
fn config(pooler: &impl BufferPooler) -> Config<()> {
    Config {
        metadata_partition: "immutable-recovery-metadata".into(),
        freezer_table_partition: "immutable-recovery-table".into(),
        freezer_table_initial_size: 4,
        freezer_table_resize_frequency: 1,
        freezer_table_resize_chunk_size: 1,
        freezer_key_partition: "immutable-recovery-keys".into(),
        // A page size that no key-record size divides, so terminal boundary entries straddle
        // pages and restore exercises the multi-page tail read.
        freezer_key_page_cache: CacheRef::from_pooler(pooler, NZU16!(72), NZUsize!(4)),
        freezer_value_partition: "immutable-recovery-values".into(),
        freezer_value_target_size: 64,
        freezer_value_compression: None,
        ordinal_partition: "immutable-recovery-ordinal".into(),
        items_per_section: NZU64!(4),
        freezer_key_write_buffer: NZUsize!(1),
        freezer_value_write_buffer: NZUsize!(1),
        ordinal_write_buffer: NZUsize!(1),
        replay_buffer: NZUsize!(512),
        codec_config: (),
    }
}

/// Construct a deterministic entry for `index` and `tag`.
fn entry(input: &FuzzInput, index: u64, tag: u8) -> Entry {
    let mut key = [0u8; 16];
    key[..8].copy_from_slice(&index.to_be_bytes());
    key[8] = tag;
    let mut value = input.payload;
    value[0] = tag;
    Entry {
        index,
        key: Key::new(key),
        value: Value::new(value),
    }
}

/// Return the sparse baseline and complete candidate states for recovery.
fn intended(input: &FuzzInput) -> (Vec<Entry>, Vec<Entry>) {
    let baseline = vec![entry(input, 0, 0x10), entry(input, 2, 0x12)];
    let mut candidate = baseline.clone();
    candidate.extend([entry(input, 1, 0x21), entry(input, 3, 0x23)]);
    candidate.sort_by_key(|entry| entry.index);
    (baseline, candidate)
}

/// Verify each intended entry through index and key APIs and return those found.
async fn snapshot(archive: &TestArchive, intended: &[Entry]) -> Vec<Entry> {
    let mut recovered = Vec::new();
    for entry in intended {
        let by_index = archive
            .get(Identifier::Index(entry.index))
            .await
            .unwrap_or_else(|err| panic!("get by index {} failed: {err:?}", entry.index));
        let by_key = archive
            .get(Identifier::Key(&entry.key))
            .await
            .unwrap_or_else(|err| panic!("get by key {} failed: {err:?}", entry.index));
        assert_eq!(
            by_index, by_key,
            "index/key views diverged at {}",
            entry.index
        );
        assert_eq!(
            archive.has(Identifier::Index(entry.index)).await.unwrap(),
            by_index.is_some()
        );
        assert_eq!(
            archive.has(Identifier::Key(&entry.key)).await.unwrap(),
            by_key.is_some()
        );
        if let Some(value) = by_index {
            assert_eq!(value, entry.value, "wrong value at index {}", entry.index);
            recovered.push(entry.clone());
        }
    }
    recovered
}

/// Compare range, gap, and missing-item helpers with the supplied entries.
fn assert_ranges(archive: &TestArchive, entries: &[Entry]) {
    let mut model = RMap::new();
    for entry in entries {
        model.insert(entry.index);
    }
    let expected = model
        .iter()
        .map(|(&start, &end)| (start, end))
        .collect::<Vec<_>>();
    assert_eq!(archive.ranges().collect::<Vec<_>>(), expected);
    assert_eq!(archive.first_index(), model.first_index());
    assert_eq!(archive.last_index(), model.last_index());
    for start in 0..=5 {
        assert_eq!(
            archive.ranges_from(start).collect::<Vec<_>>(),
            model
                .iter_from(start)
                .map(|(&range_start, &range_end)| (range_start, range_end))
                .collect::<Vec<_>>()
        );
        assert_eq!(archive.next_gap(start), model.next_gap(start));
        assert_eq!(
            archive.missing_items(start, 5),
            model.missing_items(start, 5)
        );
    }
}

/// Run one immutable archive crash/recovery scenario for the selected write mode.
fn run(input: &FuzzInput, mode: PartialWriteMode) {
    let phase_input = input.clone();
    let recovery_input = input.clone();
    let (baseline, candidate) = intended(input);
    let phase_baseline = baseline.clone();
    let phase_candidate = candidate.clone();
    let runner = deterministic::Runner::new(deterministic::Config::default().with_seed(input.seed));
    let (outcome, checkpoint) = runner.start_and_recover(move |context| async move {
        // Commit a sparse baseline so both values and gap metadata have an acknowledged floor.
        let mut archive =
            Archive::<_, Key, Value>::init(context.child("archive"), config(&context))
                .await
                .expect("initial immutable archive init failed");
        for entry in &phase_baseline {
            archive = archive
                .put(entry.index, entry.key.clone(), entry.value.clone())
                .await
                .expect("baseline put failed");
        }
        archive = archive.sync().await.expect("baseline sync failed");

        // Candidate puts and their sync run under one partial-write policy. Any mutating error ends
        // the phase immediately.
        let rate = Probability::new(u64::from(phase_input.rate % 100) + 1, 100).unwrap();
        let (failure_rate, sync_rate) = match phase_input.fault {
            FaultKind::Write => (rate, None),
            FaultKind::Sync => (Probability::new(0, 1).unwrap(), Some(rate)),
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

        for entry in phase_candidate.iter().filter(|entry| {
            !phase_baseline
                .iter()
                .any(|baseline| baseline.index == entry.index)
        }) {
            archive = match archive
                .put(entry.index, entry.key.clone(), entry.value.clone())
                .await
            {
                Ok(archive) => archive,
                Err(_) => return Outcome::PutFailed,
            };
        }
        match archive.sync().await {
            Ok(archive) => {
                drop(archive);
                Outcome::Synced
            }
            Err(_) => Outcome::SyncFailed,
        }
    });

    // A failed recovery instance is abandoned. Its crash checkpoint must remain recoverable by
    // the same ordinary initialization path with faults disabled.
    let checkpoint = faulted_recovery(checkpoint, input.seed, |context| async move {
        Archive::<_, Key, Value>::init(context.child("faulted_recovery"), config(&context)).await
    });

    deterministic::Runner::from(checkpoint).start(move |context| async move {
        *context.storage_fault_config().write() = deterministic::FaultConfig::default();

        // Immutable metadata publishes the Freezer checkpoint and Ordinal bitmap as one CRC-valid
        // snapshot after both lower stores sync. Recovery therefore exposes the baseline or the
        // complete candidate, never a mixed public view.
        let mut archive =
            Archive::<_, Key, Value>::init(context.child("recovered"), config(&context))
                .await
                .expect("immutable archive recovery failed");
        let recovered = snapshot(&archive, &candidate).await;
        match outcome {
            Outcome::PutFailed => assert_eq!(recovered, baseline),
            Outcome::SyncFailed => assert!(
                recovered == baseline || recovered == candidate,
                "immutable archive recovered a mixed state: {recovered:?}"
            ),
            Outcome::Synced => assert_eq!(recovered, candidate),
        }
        assert_ranges(&archive, &recovered);

        // Publish one new index, then reopen and recheck every public view used by range-driven
        // consumers.
        let sentinel = entry(&recovery_input, 4, 0xEF);
        archive = archive
            .put(sentinel.index, sentinel.key.clone(), sentinel.value.clone())
            .await
            .expect("post-recovery put failed");
        archive = archive.sync().await.expect("post-recovery sync failed");
        let mut expected = recovered;
        expected.push(sentinel);
        drop(archive);

        let archive = Archive::<_, Key, Value>::init(context.child("reopened"), config(&context))
            .await
            .expect("post-recovery reopen failed");
        assert_eq!(snapshot(&archive, &expected).await, expected);
        assert_ranges(&archive, &expected);
        archive.destroy().await.expect("archive destroy failed");
    });
}

/// Exercise the scenario under both supported partial-write modes.
fn fuzz(input: FuzzInput) {
    for mode in [PartialWriteMode::Prefix, PartialWriteMode::Subset] {
        run(&input, mode);
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
