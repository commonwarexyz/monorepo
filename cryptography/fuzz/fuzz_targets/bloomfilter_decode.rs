#![no_main]

use std::num::{NonZeroU16, NonZeroU8};
use arbitrary::Arbitrary;
use commonware_codec::Decode;
use commonware_cryptography::BloomFilter;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    encoded_bloom_filter: Vec<u8>,
    test_items: Vec<Vec<u8>>,
    hashers_min: NonZeroU8,
    hashers_max: NonZeroU8,
    bits_min: NonZeroU16,
    bits_max: NonZeroU16,
}

fn fuzz(data: &[u8]) {
    if let Ok(input) = FuzzInput::arbitrary(&mut arbitrary::Unstructured::new(data)) {

        let bits_min = input.bits_min;
        let bits_max = input.bits_max.max(bits_min);

        let cfg = (
            (input.hashers_min..=input.hashers_max).into(),
            (bits_min..=bits_max).into(),
        );


        if let Ok(bloom_filter) = BloomFilter::decode_cfg(&input.encoded_bloom_filter[..], &cfg) {
            for item in input.test_items.iter().take(10) {
                let _ = bloom_filter.contains(item);
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    fuzz(data);
});
