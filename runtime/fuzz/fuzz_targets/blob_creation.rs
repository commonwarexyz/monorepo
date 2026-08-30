//! Fuzz blob recovery from arbitrary durable images.

#![no_main]

use arbitrary::{Arbitrary, Result, Unstructured};
use commonware_cryptography::Crc32;
use commonware_runtime::{
    Blob, BufferPooler, ReadOptions, Runner, Storage, WriteOptions, deterministic,
    mocks::MemoryStorage,
};
use libfuzzer_sys::fuzz_target;

const PARTITION: &str = "blob_creation";
const PAYLOAD: &[u8] = b"payload!";
const NAME: &[u8] = b"blob";

/// Header spec constants (see runtime/src/storage/header.rs): the prelude, the prelude plus
/// its V1 CRC, the V1 region size, and each layout's magic plus runtime version bytes. The
/// V1 values are asserted against a real creation before every image is classified.
const PRELUDE: usize = 8;
const PARSE_LEN: usize = 12;
const REGION: usize = 4096;
const V0_PREFIX: [u8; 6] = *b"CWIC\x00\x00";
const V1_PREFIX: [u8; 6] = *b"CWIK\x00\x01";

/// Bound the image to the sizes recovery distinguishes: everything past the region plus a
/// small payload margin behaves identically.
fn bounded_image(u: &mut Unstructured<'_>) -> Result<Vec<u8>> {
    let len = u.int_in_range(0..=REGION + PRELUDE)?;
    Ok(u.bytes(len.min(u.len()))?.to_vec())
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    blob_version: u16,
    /// Raw durable contents installed as the blob's crash image.
    #[arbitrary(with = bounded_image)]
    image: Vec<u8>,
}

/// Required recovery outcome when a blob's raw contents are an arbitrary image.
enum CreationOutcome {
    /// The open succeeds and recreates the canonical V1 region for the requested version.
    Recreated,
    /// The open succeeds against the intact header, leaving the contents unchanged, with
    /// the given logical size.
    Kept { size: u64 },
    /// The open fails without mutating the contents.
    Rejected,
}

/// Classify the required recovery outcome for an installed image, per the header spec: a
/// sub-prelude file is always recreated, a parseable header is honored before healing is
/// considered (a blob version disagreement or nonzero padding on an intact region never
/// heals), and only failures a torn write can produce fall through to the torn-creation
/// classifier, which accepts a canonical prefix (with any blob version, the CRC binding the
/// written prelude) followed by zeros.
fn creation_outcome(image: &[u8], version: u16) -> CreationOutcome {
    // Too short to hold any header: recreated as new regardless of content.
    if image.len() < PRELUDE {
        return CreationOutcome::Recreated;
    }
    let stamped = u16::from_be_bytes([image[6], image[7]]);

    // An intact V0 magic and runtime version parse as a legacy blob: the stamped version
    // decides, and a mismatch is a genuine disagreement that never heals.
    if image[..6] == V0_PREFIX {
        return if stamped == version {
            CreationOutcome::Kept {
                size: (image.len() - PRELUDE) as u64,
            }
        } else {
            CreationOutcome::Rejected
        };
    }

    // A CRC-validated full V1 region parses: nonzero padding and a stamped version mismatch
    // are corruption, not torn writes. A valid CRC over a truncated region still falls
    // through to the torn-creation classifier.
    if image[..6] == V1_PREFIX
        && image.len() >= PARSE_LEN
        && image[PRELUDE..PARSE_LEN] == Crc32::checksum(&image[..PRELUDE]).to_be_bytes()
        && image.len() >= REGION
    {
        if image[PARSE_LEN..REGION].iter().any(|&byte| byte != 0) {
            return CreationOutcome::Rejected;
        }
        return if stamped == version {
            CreationOutcome::Kept {
                size: (image.len() - REGION) as u64,
            }
        } else {
            CreationOutcome::Rejected
        };
    }

    // Torn-creation classifier: the written prefix ends at the last nonzero byte, must match
    // a canonical V1 region (blob version free, CRC bytes prefixing the CRC over the written
    // prelude), and everything past it must be zero.
    if image.len() > REGION {
        return CreationOutcome::Rejected;
    }
    let head_len = image.len().min(PARSE_LEN);
    if image[head_len..].iter().any(|&byte| byte != 0) {
        return CreationOutcome::Rejected;
    }
    let head = &image[..head_len];
    let written = head
        .iter()
        .rposition(|&byte| byte != 0)
        .map_or(0, |i| i + 1);
    let canonical = if written <= PRELUDE {
        head[..written.min(6)] == V1_PREFIX[..written.min(6)]
    } else {
        head[..6] == V1_PREFIX
            && head[PRELUDE..written]
                == Crc32::checksum(&head[..PRELUDE]).to_be_bytes()[..written - PRELUDE]
    };
    if canonical {
        CreationOutcome::Recreated
    } else {
        CreationOutcome::Rejected
    }
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

/// Verify that an intact non-empty blob image opens unchanged at its logical size.
async fn assert_kept(
    storage: &MemoryStorage,
    name: &[u8],
    blob_version: u16,
    image: &[u8],
    size: u64,
) {
    let versions = blob_version..=blob_version;
    let (_, opened, version) = storage
        .open_versioned(PARTITION, name, versions)
        .await
        .expect("intact image did not open");
    assert_eq!(opened, size);
    assert_eq!(version, blob_version);
    let raw = storage
        .raw_blob(PARTITION, name)
        .expect("opened blob lost its image");
    assert_eq!(raw, image, "open mutated an intact image");
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

        // Create the canonical V1 region through the same storage path used in production: a
        // healed image must recreate exactly this, and it anchors the spec constants.
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
        assert_eq!(canonical.len(), REGION);
        assert_eq!(canonical[..6], V1_PREFIX);

        // Install the image and hold recovery to the oracle.
        storage.set_raw_blob(PARTITION, NAME, input.image.clone());
        match creation_outcome(&input.image, input.blob_version) {
            CreationOutcome::Recreated => {
                assert_recovers(&storage, NAME, input.blob_version, &canonical).await
            }
            CreationOutcome::Kept { size: 0 } => {
                assert_recovers(&storage, NAME, input.blob_version, &input.image).await
            }
            CreationOutcome::Kept { size } => {
                assert_kept(&storage, NAME, input.blob_version, &input.image, size).await
            }
            CreationOutcome::Rejected => {
                assert_rejects(&storage, NAME, input.blob_version, &input.image).await
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
