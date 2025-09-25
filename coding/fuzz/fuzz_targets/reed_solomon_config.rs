#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_coding::{Config, ReedSolomon, Scheme};
use commonware_cryptography::Sha256;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    minimum_shards: u16,
    extra_shards: u16,
    data: Vec<u8>,
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(input) = FuzzInput::arbitrary(&mut u) else {
        return;
    };

    let config = Config {
        minimum_shards: input.minimum_shards,
        extra_shards: input.extra_shards,
    };

    if config.minimum_shards == 0 {
        return;
    }

    if config.extra_shards == 0 {
        return;
    }

    let total_shards = config.minimum_shards.saturating_add(config.extra_shards);
    if total_shards <= config.minimum_shards {
        return;
    }

    let _ = <ReedSolomon<Sha256> as Scheme>::encode(&config, input.data.as_slice());
});
