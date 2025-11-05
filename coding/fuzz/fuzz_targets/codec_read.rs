#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::Read;
use commonware_coding::{Config, NoCoding, ReedSolomon, Scheme, Zoda};
use commonware_cryptography::Sha256;
use libfuzzer_sys::fuzz_target;

const MAX_DATA_BYTES: usize = 1 << 20;
const MAX_TOTAL_SHARDS: u16 = 512;
const MAX_INPUT_LEN: usize = 1 << 20;

#[derive(Arbitrary, Debug)]
enum SchemeSelector {
    Zoda,
    ReedSolomon,
    NoCoding,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    scheme: SchemeSelector,
    max_data_bytes: u32,
    minimum_shards: u16,
    extra_shards: u16,
    shard_bytes: Vec<u8>,
}

fn fuzz_read<S: Scheme>(
    max_data_bytes: u32,
    minimum_shards: u16,
    extra_shards: u16,
    shard_bytes: Vec<u8>,
) {
    let max_data_bytes = (max_data_bytes as usize).clamp(1, MAX_DATA_BYTES);
    let minimum_shards = minimum_shards.clamp(1, MAX_TOTAL_SHARDS);
    let extra_limit = MAX_TOTAL_SHARDS.saturating_sub(minimum_shards);
    let extra_shards = extra_shards.min(extra_limit);

    let mut shard_bytes = shard_bytes;
    if shard_bytes.len() > MAX_INPUT_LEN {
        shard_bytes.truncate(MAX_INPUT_LEN);
    }

    let config = Config {
        minimum_shards,
        extra_shards,
    };

    let mut buf = shard_bytes.as_slice();
    let _ = <S::Shard as Read>::read_cfg(&mut buf, &(max_data_bytes, config));
}

fn fuzz(input: FuzzInput) {
    match input.scheme {
        SchemeSelector::Zoda => fuzz_read::<Zoda<Sha256>>(
            input.max_data_bytes,
            input.minimum_shards,
            input.extra_shards,
            input.shard_bytes,
        ),
        SchemeSelector::ReedSolomon => fuzz_read::<ReedSolomon<Sha256>>(
            input.max_data_bytes,
            input.minimum_shards,
            input.extra_shards,
            input.shard_bytes,
        ),
        SchemeSelector::NoCoding => fuzz_read::<NoCoding<Sha256>>(
            input.max_data_bytes,
            input.minimum_shards,
            input.extra_shards,
            input.shard_bytes,
        ),
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
