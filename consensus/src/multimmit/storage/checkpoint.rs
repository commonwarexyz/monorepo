//! Durable machine checkpoints, stored outside the safety journal.
//!
//! A checkpoint is one acknowledged machine [`Snapshot`], atomically swapped in a
//! [`Metadata`] store: writes land in the older of two blobs and only replace the newer once
//! synced, so a crash mid-checkpoint always recovers the previous complete snapshot. Keeping
//! the snapshot out of the journal decouples its size, which grows with the committee, from
//! the journal's per-record bounds.

#[cfg(test)]
use crate::multimmit::machine::Cursor;
use crate::{
    multimmit::{
        machine::{CoreState, Snapshot, SnapshotCodecConfig},
        storage::SafetyJournal,
    },
    types::Epoch,
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_runtime::{Metrics, Storage};
use commonware_storage::{
    Context as StorageContext,
    metadata::{Config as MetadataConfig, Error as MetadataError, Metadata},
};
use commonware_utils::sequence::U64;
use std::num::NonZeroUsize;

/// The single key under which the newest snapshot lives.
const SNAPSHOT_KEY: u64 = 0;

/// Atomic store for the newest acknowledged machine snapshot.
pub struct CheckpointStore<E: StorageContext, V: Variant, D: Digest> {
    inner: Metadata<E, U64, Snapshot<V, D>>,
}

/// A checkpoint store failure. Fatal to the current instance.
#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    /// The underlying metadata store failed.
    #[error("checkpoint store failed: {0}")]
    Storage(#[from] MetadataError),
    /// The stored snapshot belongs to another epoch.
    #[error("checkpoint does not match the epoch manifest")]
    Context,
}

impl<E, V, D> CheckpointStore<E, V, D>
where
    E: StorageContext,
    V: Variant,
    D: Digest,
{
    /// Opens the store without an allocation ceiling in tests that exercise the storage wrapper.
    #[cfg(test)]
    async fn open(
        context: E,
        partition: String,
        codec: SnapshotCodecConfig,
        epoch: Epoch,
    ) -> Result<(Self, Option<Snapshot<V, D>>), CheckpointError> {
        Self::open_bounded(
            context,
            partition,
            codec,
            NonZeroUsize::new(usize::MAX).expect("usize::MAX is non-zero"),
            epoch,
        )
        .await
    }

    /// Opens the store and returns the newest durable snapshot, if any.
    ///
    /// A slot larger than `max_blob_size` is discarded before allocation, allowing the other
    /// atomic slot to recover without accepting storage-controlled memory use.
    pub async fn open_bounded(
        context: E,
        partition: String,
        codec: SnapshotCodecConfig,
        max_blob_size: NonZeroUsize,
        epoch: Epoch,
    ) -> Result<(Self, Option<Snapshot<V, D>>), CheckpointError> {
        let inner = Metadata::init_bounded(
            context,
            MetadataConfig {
                partition,
                codec_config: codec,
            },
            max_blob_size,
        )
        .await?;
        let snapshot: Option<Snapshot<V, D>> = inner.get(&U64::new(SNAPSHOT_KEY)).cloned();
        if let Some(snapshot) = snapshot.as_ref()
            && snapshot.epoch() != epoch
        {
            return Err(CheckpointError::Context);
        }
        Ok((Self { inner }, snapshot))
    }

    #[cfg(test)]
    fn covered(&self) -> Cursor {
        self.inner
            .get(&U64::new(SNAPSHOT_KEY))
            .map_or(Cursor::zero(), Snapshot::cursor)
    }

    /// Durably replaces the newest snapshot.
    ///
    /// Blocks until the swap is synced; callers off the hot path may run it on a task and
    /// reclaim the store from the handle.
    pub async fn store(self, snapshot: Snapshot<V, D>) -> Result<Self, CheckpointError> {
        let inner = self
            .inner
            .put_sync(U64::new(SNAPSHOT_KEY), snapshot)
            .await?;
        Ok(Self { inner })
    }
}

/// Complete protocol owner and journal returned after silent suffix replay.
pub(crate) struct Recovered<E: Storage + Metrics, H: Hasher, V: Variant> {
    pub core: CoreState<H, V>,
    pub journal: SafetyJournal<E, V, H::Digest>,
    /// Durable journal events replayed after the newest checkpoint.
    pub events_since_checkpoint: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multimmit::{
        config::Limits,
        machine::{Profile, Role, Tuning},
        mocks::Committee,
    };
    use commonware_codec::{EncodeSize as _, Write as _};
    use commonware_cryptography::{
        Crc32, Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };
    use commonware_runtime::{
        Blob as _, Runner as _, Spawner as _, Supervisor as _, WriteOptions, deterministic,
        mocks::{
            DeferredSync, DelayedSyncContext, PendingSyncs, WriteFaultContext, WriteFaults,
            next_pending_sync,
        },
    };
    use std::num::NonZeroUsize;

    const PARTITION: &str = "multimmit-checkpoints";

    type TestSnapshot = Snapshot<MinPk, Sha256Digest>;

    struct Fixture {
        epoch: Epoch,
        codec: SnapshotCodecConfig,
        first: TestSnapshot,
        replacement: TestSnapshot,
    }

    fn fixture() -> Fixture {
        let epoch = Epoch::new(7);
        let committee = Committee::<MinPk>::new(7, 1, Limits::new(2, 1).unwrap());
        let profile: Profile<Sha256, MinPk> =
            Profile::new(committee.config, Role::Observer, Tuning::default()).unwrap();
        let codec = SnapshotCodecConfig::from_profile(&profile);
        let snapshot = CoreState::fresh(profile, NonZeroUsize::MIN)
            .unwrap()
            .snapshot();
        let first = snapshot.clone().at_cursor_for_test(Cursor::new(7));
        let replacement = snapshot.at_cursor_for_test(Cursor::new(11));

        Fixture {
            epoch,
            codec,
            first,
            replacement,
        }
    }

    #[test]
    fn opens_empty() {
        let fixture = fixture();
        deterministic::Runner::default().start(|context| async move {
            let (store, snapshot) = CheckpointStore::<_, MinPk, Sha256Digest>::open(
                context.child("open"),
                PARTITION.into(),
                fixture.codec,
                fixture.epoch,
            )
            .await
            .unwrap();

            assert_eq!(snapshot, None);
            assert_eq!(store.covered(), Cursor::zero());
        });
    }

    #[test]
    fn stores_and_reopens_exact_snapshot() {
        let fixture = fixture();
        deterministic::Runner::default().start(|context| async move {
            let (store, snapshot) = CheckpointStore::<_, MinPk, Sha256Digest>::open(
                context.child("open"),
                PARTITION.into(),
                fixture.codec,
                fixture.epoch,
            )
            .await
            .unwrap();
            assert_eq!(snapshot, None);

            let store = store.store(fixture.first.clone()).await.unwrap();
            assert_eq!(store.covered(), fixture.first.cursor());
            drop(store);

            let (store, snapshot) = CheckpointStore::<_, MinPk, Sha256Digest>::open(
                context.child("reopen"),
                PARTITION.into(),
                fixture.codec,
                fixture.epoch,
            )
            .await
            .unwrap();
            assert_eq!(snapshot, Some(fixture.first.clone()));
            assert_eq!(store.covered(), fixture.first.cursor());
        });
    }

    #[test]
    fn replaces_snapshot() {
        let fixture = fixture();
        deterministic::Runner::default().start(|context| async move {
            let (store, _) = CheckpointStore::<_, MinPk, Sha256Digest>::open(
                context.child("open"),
                PARTITION.into(),
                fixture.codec,
                fixture.epoch,
            )
            .await
            .unwrap();
            let store = store.store(fixture.first).await.unwrap();
            let store = store.store(fixture.replacement.clone()).await.unwrap();
            drop(store);

            let (store, snapshot) = CheckpointStore::<_, MinPk, Sha256Digest>::open(
                context.child("reopen"),
                PARTITION.into(),
                fixture.codec,
                fixture.epoch,
            )
            .await
            .unwrap();
            assert_eq!(snapshot, Some(fixture.replacement.clone()));
            assert_eq!(store.covered(), fixture.replacement.cursor());
        });
    }

    #[test]
    fn rejects_snapshot_from_another_epoch() {
        let fixture = fixture();
        deterministic::Runner::default().start(|context| async move {
            let (store, _) = CheckpointStore::<_, MinPk, Sha256Digest>::open(
                context.child("open"),
                PARTITION.into(),
                fixture.codec,
                fixture.epoch,
            )
            .await
            .unwrap();
            let store = store.store(fixture.first).await.unwrap();
            drop(store);

            let result = CheckpointStore::<_, MinPk, Sha256Digest>::open(
                context.child("wrong_epoch"),
                PARTITION.into(),
                fixture.codec,
                Epoch::new(fixture.epoch.get() + 1),
            )
            .await;
            assert!(matches!(result, Err(CheckpointError::Context)));
        });
    }

    #[test]
    fn checksum_mismatch_recovers_previous_snapshot() {
        let fixture = fixture();
        deterministic::Runner::default().start(|context| async move {
            let (store, _) = CheckpointStore::<_, MinPk, Sha256Digest>::open(
                context.child("open"),
                PARTITION.into(),
                fixture.codec,
                fixture.epoch,
            )
            .await
            .unwrap();
            let store = store.store(fixture.first.clone()).await.unwrap();
            let store = store.store(fixture.replacement).await.unwrap();
            drop(store);

            let (current, _) = context.open(PARTITION, b"left").await.unwrap();
            current
                .write_at(0, b"malformed".to_vec(), WriteOptions::SYNC)
                .await
                .unwrap();

            let (store, snapshot) = CheckpointStore::<_, MinPk, Sha256Digest>::open(
                context.child("reopen"),
                PARTITION.into(),
                fixture.codec,
                fixture.epoch,
            )
            .await
            .unwrap();
            assert_eq!(snapshot, Some(fixture.first.clone()));
            assert_eq!(store.covered(), fixture.first.cursor());
        });
    }

    #[test]
    fn malformed_checkpoint_slot_recovers_previous_snapshot() {
        let fixture = fixture();
        deterministic::Runner::default().start(|context| async move {
            let (store, _) = CheckpointStore::<_, MinPk, Sha256Digest>::open(
                context.child("open"),
                PARTITION.into(),
                fixture.codec,
                fixture.epoch,
            )
            .await
            .unwrap();
            let store = store.store(fixture.first.clone()).await.unwrap();
            let store = store.store(fixture.replacement).await.unwrap();
            drop(store);

            // The envelope is complete and checksum-valid, but its snapshot payload is not.
            // The other atomic slot still contains the previous durable snapshot.
            let mut malformed = Vec::new();
            100u64.write(&mut malformed);
            U64::new(SNAPSHOT_KEY).write(&mut malformed);
            u8::MAX.write(&mut malformed);
            let checksum = Crc32::checksum(&malformed);
            malformed.extend_from_slice(&checksum.to_be_bytes());
            let (current, _) = context.open(PARTITION, b"left").await.unwrap();
            current.resize(malformed.len() as u64).await.unwrap();
            current
                .write_at(0, malformed, WriteOptions::SYNC)
                .await
                .unwrap();

            let (store, snapshot) = CheckpointStore::<_, MinPk, Sha256Digest>::open(
                context.child("reopen"),
                PARTITION.into(),
                fixture.codec,
                fixture.epoch,
            )
            .await
            .unwrap();
            assert_eq!(snapshot, Some(fixture.first.clone()));
            assert_eq!(store.covered(), fixture.first.cursor());
        });
    }

    #[test]
    fn oversized_checkpoint_slot_recovers_previous_snapshot_without_reading_it() {
        let fixture = fixture();
        deterministic::Runner::default().start(|context| async move {
            let max_blob_size = NonZeroUsize::new(
                fixture
                    .first
                    .encode_size()
                    .max(fixture.replacement.encode_size())
                    + 1024,
            )
            .unwrap();
            let (store, _) = CheckpointStore::<_, MinPk, Sha256Digest>::open(
                context.child("open"),
                PARTITION.into(),
                fixture.codec,
                fixture.epoch,
            )
            .await
            .unwrap();
            let store = store.store(fixture.first.clone()).await.unwrap();
            let store = store.store(fixture.replacement).await.unwrap();
            drop(store);

            let (current, _) = context.open(PARTITION, b"left").await.unwrap();
            current
                .resize(max_blob_size.get() as u64 + 1)
                .await
                .unwrap();
            current.sync().await.unwrap();
            drop(current);

            let (store, snapshot) = CheckpointStore::<_, MinPk, Sha256Digest>::open_bounded(
                context.child("reopen"),
                PARTITION.into(),
                fixture.codec,
                max_blob_size,
                fixture.epoch,
            )
            .await
            .unwrap();
            assert_eq!(snapshot, Some(fixture.first.clone()));
            assert_eq!(store.covered(), fixture.first.cursor());
        });
    }

    #[test]
    fn failed_replacement_preserves_previous_snapshot() {
        let fixture = fixture();
        deterministic::Runner::default().start(|context| async move {
            let faults = WriteFaults::default();
            let storage = WriteFaultContext {
                inner: context.child("open"),
                faults: faults.clone(),
            };
            let (store, _) = CheckpointStore::<_, MinPk, Sha256Digest>::open(
                storage,
                PARTITION.into(),
                fixture.codec,
                fixture.epoch,
            )
            .await
            .unwrap();
            let store = store.store(fixture.first.clone()).await.unwrap();

            faults.arm();
            let result = store.store(fixture.replacement).await;
            assert!(matches!(result, Err(CheckpointError::Storage(_))));
            faults.disarm();

            let storage = WriteFaultContext {
                inner: context.child("reopen"),
                faults,
            };
            let (store, snapshot) = CheckpointStore::<_, MinPk, Sha256Digest>::open(
                storage,
                PARTITION.into(),
                fixture.codec,
                fixture.epoch,
            )
            .await
            .unwrap();
            assert_eq!(snapshot, Some(fixture.first.clone()));
            assert_eq!(store.covered(), fixture.first.cursor());
        });
    }

    #[test]
    fn crash_during_replacement_recovers_old_then_completed_replacement_recovers_new() {
        let fixture = fixture();
        let epoch = fixture.epoch;
        let codec = fixture.codec;
        let first = fixture.first;
        let replacement = fixture.replacement;
        let crash_first = first.clone();
        let crash_replacement = replacement.clone();
        let (_, checkpoint) =
            deterministic::Runner::default().start_and_recover(|context| async move {
                let pending = PendingSyncs::default();
                let storage = DelayedSyncContext {
                    inner: context.child("open"),
                    pending: pending.clone(),
                };
                let (store, _) = CheckpointStore::<_, MinPk, Sha256Digest>::open(
                    storage,
                    PARTITION.into(),
                    codec,
                    epoch,
                )
                .await
                .unwrap();
                let store = store.store(crash_first).await.unwrap();

                pending.arm();
                let DeferredSync { release, blocked } = next_pending_sync(&pending);
                let _swap = context
                    .child("swap")
                    .spawn(move |_| async move { store.store(crash_replacement).await });
                blocked.await.unwrap();
                drop(release);
            });

        let recovered_first = first;
        let completed_replacement = replacement.clone();
        let (_, checkpoint) =
            deterministic::Runner::from(checkpoint).start_and_recover(|context| async move {
                let (store, snapshot) = CheckpointStore::<_, MinPk, Sha256Digest>::open(
                    context.child("recover_old"),
                    PARTITION.into(),
                    codec,
                    epoch,
                )
                .await
                .unwrap();
                assert_eq!(snapshot, Some(recovered_first));

                let store = store.store(completed_replacement.clone()).await.unwrap();
                assert_eq!(store.covered(), completed_replacement.cursor());
            });

        deterministic::Runner::from(checkpoint).start(|context| async move {
            let (store, snapshot) = CheckpointStore::<_, MinPk, Sha256Digest>::open(
                context.child("recover_new"),
                PARTITION.into(),
                codec,
                epoch,
            )
            .await
            .unwrap();
            assert_eq!(snapshot, Some(replacement.clone()));
            assert_eq!(store.covered(), replacement.cursor());
        });
    }
}
