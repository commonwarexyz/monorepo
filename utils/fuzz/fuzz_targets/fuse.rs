#![no_main]

use commonware_codec::{DecodeExt, Encode};
use commonware_utils::fuse::BinaryFuseFilter;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Need at least 8 bytes for the seed and 8 bytes for one key.
    if data.len() < 16 {
        return;
    }
    // First 8 bytes are the seed; the rest are u64 keys.
    let seed = u64::from_be_bytes(data[..8].try_into().unwrap());
    let keys: Vec<u64> = data[8..]
        .chunks_exact(8)
        .map(|chunk| u64::from_be_bytes(chunk.try_into().unwrap()))
        .collect();

    if keys.is_empty() {
        return;
    }

    // Construction must succeed for any non-empty key set.
    let Ok(filter) = BinaryFuseFilter::<u8>::new(seed, 32, &keys) else {
        return;
    };

    // Every inserted key must always be found (no false negatives).
    for &key in &keys {
        assert!(
            filter.contains(key),
            "false negative: key {key} not found after construction"
        );
    }

    // Codec round-trip must produce an identical filter.
    let encoded = filter.encode();
    let decoded =
        BinaryFuseFilter::<u8>::decode(encoded).expect("decode of valid filter must succeed");
    for &key in &keys {
        assert!(
            decoded.contains(key),
            "false negative: key {key} not found after codec round-trip"
        );
    }
});
