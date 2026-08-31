#![no_main]

//! Metadata recovery across supported partial-write crash cuts.

use arbitrary::Arbitrary;
use commonware_codec::Read;
use commonware_runtime::{
    Runner, Supervisor as _,
    deterministic::{self, PartialWriteMode, WriteConfig},
    mocks::{DelayedSyncContext, PendingSyncs, drive_pending_syncs},
};
use commonware_storage::metadata::{Config, Metadata};
use commonware_storage_fuzz::faulted_recovery;
use commonware_utils::{Probability, sequence::U64};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

const PARTITION: &str = "metadata-recovery";
const SENTINEL_KEY: u64 = 99;

#[derive(Arbitrary, Clone, Copy, Debug)]
enum WritePath {
    Rewrite,
    Overwrite,
    Remove,
}

#[derive(Arbitrary, Clone, Copy, Debug)]
enum CrashKind {
    FailedWrite,
    UnsyncedWrite,
    AckedSync,
}

#[derive(Arbitrary, Clone, Debug)]
struct FuzzInput {
    seed: u64,
    path: WritePath,
    crash: CrashKind,
    retention: u8,
    payload: [u8; 32],
}

fn config() -> Config<<Vec<u8> as Read>::Cfg> {
    Config {
        partition: PARTITION.into(),
        codec_config: ((0..).into(), ()),
    }
}

fn value(input: &FuzzInput, tag: u8) -> Vec<u8> {
    let mut value = vec![tag];
    value.extend_from_slice(&input.payload);
    value
}

/// Snapshot the store's complete key set, so a load that fabricates or misparses
/// an extra key diverges from the expected map.
fn snapshot<E: commonware_storage::Context>(
    metadata: &Metadata<E, U64, Vec<u8>>,
) -> BTreeMap<u64, Vec<u8>> {
    metadata
        .keys()
        .map(|key| {
            let value = metadata
                .get(key)
                .expect("listed key must be readable")
                .clone();
            (u64::from(key), value)
        })
        .collect()
}

fn run(input: &FuzzInput, mode: PartialWriteMode) {
    let phase_input = input.clone();
    let crash = input.crash;
    let path = input.path;
    let retention_percent = input.retention % 101;
    let runner = deterministic::Runner::new(deterministic::Config::default().with_seed(input.seed));
    let ((baseline, candidate), checkpoint) = runner.start_and_recover(move |context| {
        let fault_config = context.storage_fault_config();
        let pending = PendingSyncs::default();
        let context = DelayedSyncContext {
            inner: context,
            pending: pending.clone(),
        };
        async move {
            // Put the same baseline in both alternating copies. The next mutation can exercise
            // equal-size overwrite, growing rewrite, or shrinking rewrite plus resize.
            let mut metadata =
                Metadata::<_, U64, Vec<u8>>::init(context.child("metadata"), config())
                    .await
                    .expect("initial metadata init failed");
            let baseline = BTreeMap::from([
                (0, value(&phase_input, 0x10)),
                (1, value(&phase_input, 0x11)),
            ]);
            for (key, value) in &baseline {
                metadata.put(U64::new(*key), value.clone());
            }
            metadata = metadata.sync().await.expect("first baseline sync failed");
            metadata = metadata.sync().await.expect("second baseline sync failed");

            let mut candidate = baseline.clone();
            match phase_input.path {
                WritePath::Rewrite => {
                    let value = value(&phase_input, 0x20);
                    metadata.put(U64::new(2), value.clone());
                    candidate.insert(2, value);
                }
                WritePath::Overwrite => {
                    let value = value(&phase_input, 0x21);
                    metadata.put(U64::new(0), value.clone());
                    candidate.insert(0, value);
                }
                WritePath::Remove => {
                    assert!(metadata.remove(&U64::new(1)).is_some());
                    candidate.remove(&1);
                }
            }

            // A failed write may retain some submitted bytes immediately. An unsynced write
            // reaches the delayed durability barrier and is then cut by the runtime crash.
            // An acked sync completes that barrier first, so the cut must find nothing volatile.
            let failure_rate = match phase_input.crash {
                CrashKind::FailedWrite => Probability::new(1, 1).unwrap(),
                CrashKind::UnsyncedWrite | CrashKind::AckedSync => Probability::new(0, 1).unwrap(),
            };
            let retention = Probability::new(u64::from(phase_input.retention % 101), 100).unwrap();
            *fault_config.write() = deterministic::FaultConfig {
                write_rate: Some(WriteConfig {
                    failure_rate,
                    retention_rate: retention,
                    mode,
                }),
                ..Default::default()
            };

            match phase_input.crash {
                CrashKind::FailedWrite => {
                    assert!(
                        metadata.start_sync().await.is_err(),
                        "a write configured to fail must fail the metadata sync"
                    );
                }
                CrashKind::UnsyncedWrite => {
                    let (_metadata, handle) = metadata
                        .start_sync()
                        .await
                        .expect("fault-free writes must reach start_sync");
                    assert_eq!(pending.lock().len(), 1, "metadata sync must remain pending");
                    drop(handle);
                }
                CrashKind::AckedSync => {
                    let (_metadata, handle) = metadata
                        .start_sync()
                        .await
                        .expect("fault-free writes must reach start_sync");
                    assert_eq!(
                        pending.lock().len(),
                        1,
                        "metadata sync must park before release"
                    );
                    drive_pending_syncs(&pending, handle)
                        .await
                        .expect("a released fault-free sync must complete");
                }
            }

            (baseline, candidate)
        }
    });

    // Metadata::init performs no write_at and no remove, so force the faulted pass's
    // mutation selector to the sync (1) or resize (2) arm it can actually exercise.
    let fault_seed = (input.seed & !0x03) | (1 + (input.seed & 1));
    let checkpoint = faulted_recovery(checkpoint, fault_seed, |context| async move {
        Metadata::<_, U64, Vec<u8>>::init(context.child("faulted_recovery"), config()).await
    });

    deterministic::Runner::from(checkpoint).start(move |context| async move {
        *context.storage_fault_config().write() = deterministic::FaultConfig::default();

        // The checksum makes each alternating copy authoritative as a whole. Recovery may select
        // the last durable copy or a complete attempted copy, but never a mixture of the two.
        let mut metadata = Metadata::<_, U64, Vec<u8>>::init(context.child("recovered"), config())
            .await
            .expect("metadata recovery failed");
        let recovered = snapshot(&metadata);
        assert!(
            recovered == baseline || recovered == candidate,
            "metadata recovered a mixed state: {recovered:?}"
        );

        // An acknowledged sync is a durability guarantee: the acked candidate copy must survive
        // the crash cut exactly, for every write path, retention rate, and cut mode.
        if matches!(crash, CrashKind::AckedSync) {
            assert_eq!(
                recovered, candidate,
                "crash after an acked sync lost acked data"
            );
        }

        if matches!(crash, CrashKind::UnsyncedWrite) && retention_percent == 0 {
            assert_eq!(
                recovered, baseline,
                "zero retention recovered attempted bytes"
            );
        }

        // Full write retention guarantees a complete candidate only when recovery does not also
        // depend on an independently unsynced resize.
        if matches!(crash, CrashKind::UnsyncedWrite)
            && retention_percent == 100
            && !matches!(path, WritePath::Remove)
        {
            assert_eq!(
                recovered, candidate,
                "full retention lost a complete attempted metadata copy"
            );
        }

        // Prove the repaired store remains writable and that the selected state survives a clean
        // sync and reopen. Shrink first: a stale tail left behind by an unrepaired mirror would
        // survive the larger sentinel rewrite, so the first write must be smaller than any
        // reachable crash image.
        let mut expected = recovered;
        metadata.remove(&U64::new(0));
        expected.remove(&0);
        metadata = metadata
            .sync()
            .await
            .expect("post-recovery shrink sync failed");
        let sentinel = vec![0xEF; 32];
        metadata.put(U64::new(SENTINEL_KEY), sentinel.clone());
        expected.insert(SENTINEL_KEY, sentinel);
        metadata = metadata.sync().await.expect("post-recovery sync failed");
        drop(metadata);

        let metadata = Metadata::<_, U64, Vec<u8>>::init(context.child("reopened"), config())
            .await
            .expect("post-recovery reopen failed");
        assert_eq!(snapshot(&metadata), expected);
        metadata.destroy().await.expect("metadata destroy failed");
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
