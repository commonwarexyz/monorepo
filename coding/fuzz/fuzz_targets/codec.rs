#![no_main]

use arbitrary::Arbitrary;
use commonware_coding::{Config, NoCoding, ReedSolomon, Scheme, Zoda};
use commonware_cryptography::Sha256;
use libfuzzer_sys::fuzz_target;

const MAX_DATA_LEN: usize = 4096;
const MAX_SHARDS: u16 = 1024;

#[derive(Arbitrary, Debug)]
enum SchemeSelector {
    Zoda,
    ReedSolomon,
    NoCoding,
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
        minimum_shards: minimum_shards.min(MAX_SHARDS),
        extra_shards: extra_shards.min(MAX_SHARDS),
    };
    let mut data = data;
    if data.len() > MAX_DATA_LEN {
        data.truncate(MAX_DATA_LEN);
    }
    let _ = S::encode(&config, data.as_slice());
}

fuzz_target!(|input: FuzzInput| {
    match input.scheme {
        SchemeSelector::Zoda => {
            fuzz_encode::<Zoda<Sha256>>(input.minimum_shards, input.extra_shards, input.data)
        }
        SchemeSelector::ReedSolomon => {
            fuzz_encode::<ReedSolomon<Sha256>>(input.minimum_shards, input.extra_shards, input.data)
        }
        SchemeSelector::NoCoding => {
            fuzz_encode::<NoCoding<Sha256>>(input.minimum_shards, input.extra_shards, input.data)
        }
    }
});
