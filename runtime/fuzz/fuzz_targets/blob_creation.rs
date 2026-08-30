//! Fuzz blob creation recovery after partial header writes.
//!
//! A [TornCreation] shape is materialized over the canonical V1 region and installed as the
//! blob's raw contents, and reopening is held to [creation_outcome]: images classifiable as
//! a torn canonical creation must heal into an empty usable blob, and everything else must
//! fail loudly without mutation.

#![no_main]

use arbitrary::Arbitrary;
use commonware_runtime::{
    Blob, BufferPooler, ReadOptions, Runner, Storage, WriteOptions, deterministic,
    mocks::{CreationOutcome, MemoryStorage, TornCreation, creation_outcome},
};
use libfuzzer_sys::fuzz_target;

const PARTITION: &str = "blob_creation";
const PAYLOAD: &[u8] = b"payload!";
const NAME: &[u8] = b"blob";

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    blob_version: u16,
    torn: TornCreation,
}

/// Verify that a recoverable creation crash image heals into an empty, usable blob.
async fn assert_recovers(
    storage: &MemoryStorage,
    name: &[u8],
    blob_version: u16,
    expected_header: &[u8],
) {
    let versions = blob_version..=blob_version;

    // Reopen the installed crash image and verify recovery restored its logical metadata.
    let (blob, size, version) = storage
        .open_versioned(PARTITION, name, versions.clone())
        .await
        .expect("partial blob creation did not recover");
    assert_eq!(size, 0);
    assert_eq!(version, blob_version);

    // Inspect durable bytes before writing payload data so only header recovery shaped the image.
    let healed = storage
        .raw_blob(PARTITION, name)
        .expect("recovered blob has no durable image");
    assert_eq!(healed, expected_header);

    // A synced logical-offset-zero write and another reopen verify the recovered data offset.
    blob.write_at(0, PAYLOAD, WriteOptions::SYNC)
        .await
        .expect("write after creation recovery failed");
    drop(blob);
    let (blob, size, version) = storage
        .open_versioned(PARTITION, name, versions)
        .await
        .expect("reopening healed blob failed");
    assert_eq!(size, PAYLOAD.len() as u64);
    assert_eq!(version, blob_version);
    let read = blob
        .read_at(0, PAYLOAD.len(), ReadOptions::default())
        .await
        .expect("reading healed blob failed");
    assert_eq!(read.coalesce().as_ref(), PAYLOAD);
}

/// Verify that an unclassifiable crash image fails loudly without being mutated.
async fn assert_rejects(storage: &MemoryStorage, name: &[u8], blob_version: u16, image: &[u8]) {
    let versions = blob_version..=blob_version;
    assert!(
        storage
            .open_versioned(PARTITION, name, versions)
            .await
            .is_err(),
        "non-canonical crash image was accepted"
    );
    let raw = storage
        .raw_blob(PARTITION, name)
        .expect("rejected blob lost its image");
    assert_eq!(raw, image, "rejected open mutated the image");
}

fn fuzz(input: FuzzInput) {
    deterministic::Runner::default().start(|context| async move {
        let storage = MemoryStorage::new(context.storage_buffer_pool().clone());
        let versions = input.blob_version..=input.blob_version;

        // Create the canonical V1 region through the same storage path used in production.
        let (blob, size, version) = storage
            .open_versioned(PARTITION, NAME, versions)
            .await
            .expect("initial blob creation failed");
        assert_eq!(size, 0);
        assert_eq!(version, input.blob_version);
        drop(blob);
        let canonical = storage
            .raw_blob(PARTITION, NAME)
            .expect("created blob has no durable image");

        // Install a crash image over the canonical blob and hold recovery to the oracle.
        let image = input.torn.image(&canonical);
        storage.set_raw_blob(PARTITION, NAME, image.clone());
        match creation_outcome(&image, input.blob_version) {
            CreationOutcome::Recreated => {
                assert_recovers(&storage, NAME, input.blob_version, &canonical).await
            }
            CreationOutcome::Kept => {
                assert_recovers(&storage, NAME, input.blob_version, &image).await
            }
            CreationOutcome::Rejected => {
                assert_rejects(&storage, NAME, input.blob_version, &image).await
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
