//! Fuzz blob creation recovery after partial header writes.

#![no_main]

use arbitrary::Arbitrary;
use commonware_runtime::{
    Blob, BufferPooler, ReadOptions, Runner, Storage, WriteOptions, deterministic,
    mocks::MemoryStorage,
};
use libfuzzer_sys::fuzz_target;

const PARTITION: &str = "blob_creation";
const PAYLOAD: &[u8] = b"payload!";
const V0_NAME: &[u8] = b"v0";
const V1_NAME: &[u8] = b"v1";

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    blob_version: u16,
    retained_prefix: u16,
    persisted_tail: u16,
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

fn fuzz(input: FuzzInput) {
    deterministic::Runner::default().start(|context| async move {
        let storage = MemoryStorage::new(context.storage_buffer_pool().clone());
        let versions = input.blob_version..=input.blob_version;

        // Create the canonical V1 region through the same storage path used in production.
        let (blob, size, version) = storage
            .open_versioned(PARTITION, V1_NAME, versions.clone())
            .await
            .expect("initial blob creation failed");
        assert_eq!(size, 0);
        assert_eq!(version, input.blob_version);
        drop(blob);
        let canonical_v1 = storage
            .raw_blob(PARTITION, V1_NAME)
            .expect("created blob has no durable image");

        // Model a partial V1 creation write as a retained canonical prefix. The file length may
        // stop at that prefix or persist farther, in which case the unwritten tail reads as zeros.
        let retained = usize::from(input.retained_prefix) % (canonical_v1.len() + 1);
        let persisted =
            retained + usize::from(input.persisted_tail) % (canonical_v1.len() - retained + 1);
        let mut interrupted = vec![0u8; persisted];
        interrupted[..retained].copy_from_slice(&canonical_v1[..retained]);
        storage.set_raw_blob(PARTITION, V1_NAME, interrupted);
        assert_recovers(&storage, V1_NAME, input.blob_version, &canonical_v1).await;

        // Create a canonical V0 region through the pre-V1 storage path, then model a writer that
        // left only a prefix of its prelude. A complete prelude remains V0; every shorter prefix
        // is treated as a new blob and recreated V1.
        let (blob, size, version) = storage
            .open_versioned_v0(PARTITION, V0_NAME, versions)
            .expect("legacy blob creation failed");
        assert_eq!(size, 0);
        assert_eq!(version, input.blob_version);
        drop(blob);
        let canonical_v0 = storage
            .raw_blob(PARTITION, V0_NAME)
            .expect("created legacy blob has no durable image");
        let retained = usize::from(input.retained_prefix) % (canonical_v0.len() + 1);
        storage.set_raw_blob(PARTITION, V0_NAME, canonical_v0[..retained].to_vec());
        let expected_header = if retained == canonical_v0.len() {
            canonical_v0.as_slice()
        } else {
            canonical_v1.as_slice()
        };
        assert_recovers(&storage, V0_NAME, input.blob_version, expected_header).await;
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
