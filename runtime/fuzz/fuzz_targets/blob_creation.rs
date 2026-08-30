//! Fuzz blob creation recovery after partial header writes.
//!
//! Creation writes one canonical header region over a zero-length file, so a crash leaves a
//! canonical prefix, a persisted length whose unwritten tail reads as zeros, and possibly zero
//! holes where device writeback persisted bytes out of order. Every such image is classified
//! by an oracle derived from the header spec: images matching a torn canonical creation must
//! heal into an empty usable blob, and everything else must fail loudly without mutation.

#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::Crc32;
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
    /// Bit `i` zeroes byte `i` of the installed image: a hole torn by out-of-order writeback.
    /// The low bits cover the parseable header; higher bits fall on padding or off the image.
    holes: u16,
}

/// Model a creation write interrupted mid-flight: a canonical prefix survives, the persisted
/// file length may extend past it (unwritten bytes read as zeros after `set_len(0)`), and
/// holes mark bytes writeback never persisted. A hole can only zero a byte, never invent one:
/// creation starts from an empty file, so unwritten storage reads as zeros.
fn crash_image(canonical: &[u8], input: &FuzzInput) -> Vec<u8> {
    let retained = usize::from(input.retained_prefix) % (canonical.len() + 1);
    let persisted =
        retained + usize::from(input.persisted_tail) % (canonical.len() - retained + 1);
    let mut image = vec![0u8; persisted];
    image[..retained].copy_from_slice(&canonical[..retained]);
    for bit in 0..u16::BITS as usize {
        if input.holes & (1 << bit) != 0 {
            if let Some(byte) = image.get_mut(bit) {
                *byte = 0;
            }
        }
    }
    image
}

/// Expected recovery outcome for an installed creation image, derived from the header spec:
/// `Some(header)` when reopening must succeed and leave that durable header region, `None`
/// when it must fail without mutating the image.
///
/// Mirrors header resolution for images no longer than their creation region. Parsing
/// preempts healing: an intact header is honored, and a blob version disagreement or nonzero
/// padding on an otherwise valid region is genuine corruption. Only failures a torn write can
/// produce (bad magic, runtime version, checksum, truncation) reach the torn-creation
/// classifier, which accepts a canonical prefix (with any blob version, the CRC binding the
/// written prelude) followed by zeros.
fn expected_recovery<'a>(
    image: &[u8],
    version: u16,
    canonical_v0: &'a [u8],
    canonical_v1: &'a [u8],
) -> Option<&'a [u8]> {
    let prelude = canonical_v0.len();
    let parse_len = prelude + 4;
    let region = canonical_v1.len();

    // Too short to hold any header: recreated as new regardless of content.
    if image.len() < prelude {
        return Some(canonical_v1);
    }
    let stamped = u16::from_be_bytes([image[6], image[7]]);

    // An intact V0 magic and runtime version parse as a legacy blob: the stamped version
    // decides, and a mismatch is a genuine disagreement that never heals. Creation images
    // never extend a valid V0 header, so a longer image cannot arise here.
    if image[..6] == canonical_v0[..6] {
        return (image.len() == prelude && stamped == version).then_some(canonical_v0);
    }

    // A CRC-validated full V1 region parses: nonzero padding and a stamped version mismatch
    // are corruption, not torn writes. A valid CRC over a truncated region still falls
    // through to the classifier.
    if image[..6] == canonical_v1[..6]
        && image.len() >= parse_len
        && image[prelude..parse_len] == Crc32::checksum(&image[..prelude]).to_be_bytes()
        && image.len() >= region
    {
        if image[parse_len..].iter().any(|&byte| byte != 0) {
            return None;
        }
        return (stamped == version).then_some(canonical_v1);
    }

    // Torn-creation classifier: the written prefix ends at the last nonzero byte, must match
    // the canonical V1 region (blob version free, CRC bytes prefixing the CRC over the
    // written prelude), and everything past it must be zero.
    if image.len() > region {
        return None;
    }
    let head_len = image.len().min(parse_len);
    if image[head_len..].iter().any(|&byte| byte != 0) {
        return None;
    }
    let head = &image[..head_len];
    let written = head.iter().rposition(|&byte| byte != 0).map_or(0, |i| i + 1);
    let canonical = if written <= prelude {
        head[..written.min(6)] == canonical_v1[..written.min(6)]
    } else {
        head[..6] == canonical_v1[..6]
            && head[prelude..written]
                == Crc32::checksum(&head[..prelude]).to_be_bytes()[..written - prelude]
    };
    canonical.then_some(canonical_v1)
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
            .open_versioned(PARTITION, V1_NAME, versions.clone())
            .await
            .expect("initial blob creation failed");
        assert_eq!(size, 0);
        assert_eq!(version, input.blob_version);
        drop(blob);
        let canonical_v1 = storage
            .raw_blob(PARTITION, V1_NAME)
            .expect("created blob has no durable image");

        // Create a canonical V0 region through the pre-V1 storage path.
        let (blob, size, version) = storage
            .open_versioned_v0(PARTITION, V0_NAME, versions)
            .expect("legacy blob creation failed");
        assert_eq!(size, 0);
        assert_eq!(version, input.blob_version);
        drop(blob);
        let canonical_v0 = storage
            .raw_blob(PARTITION, V0_NAME)
            .expect("created legacy blob has no durable image");

        // Install a crash image over each canonical blob and hold recovery to the oracle.
        for (name, canonical) in [(V1_NAME, &canonical_v1), (V0_NAME, &canonical_v0)] {
            let image = crash_image(canonical, &input);
            storage.set_raw_blob(PARTITION, name, image.clone());
            match expected_recovery(&image, input.blob_version, &canonical_v0, &canonical_v1) {
                Some(header) => assert_recovers(&storage, name, input.blob_version, header).await,
                None => assert_rejects(&storage, name, input.blob_version, &image).await,
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
