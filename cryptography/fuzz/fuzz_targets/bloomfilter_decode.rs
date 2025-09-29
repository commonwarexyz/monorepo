#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::Decode;
use commonware_cryptography::BloomFilter;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    encoded_bloom_filter: Vec<u8>,
    test_items: Vec<Vec<u8>>,
    hashers_min: u8,
    hashers_max: u8,
    bits_min: usize,
    bits_max: usize,
}

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = FuzzInput::arbitrary(&mut arbitrary::Unstructured::new(data)) {
        let hashers_min = input.hashers_min.max(1) as usize;
        let hashers_max = input.hashers_max.max(input.hashers_min.max(1)) as usize;

        let bits_min = input.bits_min;
        let bits_max = input.bits_max.max(bits_min);

        let cfg = (
            (hashers_min..=hashers_max).into(),
            (bits_min..=bits_max).into(),
        );

        if let Ok(bloom_filter) = BloomFilter::decode_cfg(&input.encoded_bloom_filter[..], &cfg) {
            for item in input.test_items.iter().take(10) {
                let _ = bloom_filter.contains(item);
            }
        }
    }
});
