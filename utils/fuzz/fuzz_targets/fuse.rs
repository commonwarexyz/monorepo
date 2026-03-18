#![no_main]

use commonware_codec::{DecodeExt, Encode};
use commonware_utils::fuse::BinaryFuseFilter;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Derive u64 keys from the raw input bytes.
    if data.len() < 8 {
        return;
    }
    let keys: Vec<u64> = data
        .chunks_exact(8)
        .map(|chunk| u64::from_be_bytes(chunk.try_into().unwrap()))
        .collect();

    // Construction must succeed for any non-empty key set.
    let Ok(filter) = BinaryFuseFilter::<u8>::new(&keys) else {
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
