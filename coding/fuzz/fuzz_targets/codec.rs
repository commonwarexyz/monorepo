#![no_main]

use arbitrary::Arbitrary;
use commonware_coding::{Config, PhasedAsScheme, ReedSolomon, Scheme, Zoda};
use commonware_cryptography::Sha256;
use commonware_parallel::Sequential;
use libfuzzer_sys::fuzz_target;
use std::num::NonZeroU16;

const MAX_DATA_LEN: usize = 4096;
const MAX_SHARDS: u16 = 1024;
const STRATEGY: Sequential = Sequential;

#[derive(Arbitrary, Debug)]
enum SchemeSelector {
    Zoda,
    ReedSolomon,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    scheme: SchemeSelector,
    minimum_shards: u16,
    extra_shards: u16,
    data: Vec<u8>,
}

fn fuzz_encode<S: Scheme>(minimum_shards: u16, extra_shards: u16, data: Vec<u8>) {
    let config = Config {
        minimum_shards: NonZeroU16::new(minimum_shards.clamp(1, MAX_SHARDS)).unwrap(),
        extra_shards: NonZeroU16::new(extra_shards.clamp(1, MAX_SHARDS)).unwrap(),
    };
    let mut data = data;
    if data.len() > MAX_DATA_LEN {
        data.truncate(MAX_DATA_LEN);
    }
    let _ = S::encode(&config, data.as_slice(), &STRATEGY);
}

fuzz_target!(|input: FuzzInput| {
    match input.scheme {
        SchemeSelector::Zoda => fuzz_encode::<PhasedAsScheme<Zoda<Sha256>>>(
            input.minimum_shards,
            input.extra_shards,
            input.data,
        ),
        SchemeSelector::ReedSolomon => {
            fuzz_encode::<ReedSolomon<Sha256>>(input.minimum_shards, input.extra_shards, input.data)
        }
    }
});
