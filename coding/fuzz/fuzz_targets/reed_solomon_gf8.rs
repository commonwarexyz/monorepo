#![no_main]

use commonware_coding::{Config, ReedSolomon8, Scheme};
use commonware_cryptography::Sha256;
use commonware_parallel::Sequential;
use commonware_utils::NZU16;
use libfuzzer_sys::fuzz_target;

const STRATEGY: Sequential = Sequential;

/// GF(2^8) supports at most 255 total shards, so we generate constrained inputs.
#[derive(Debug, arbitrary::Arbitrary)]
struct Gf8FuzzInput {
    /// 1..=127
    min: u8,
    /// 1..=127
    recovery: u8,
    data: Vec<u8>,
}

fuzz_target!(|input: Gf8FuzzInput| {
    let min = (input.min % 127) + 1;
    let recovery = (input.recovery % 127) + 1;
    let total = u16::from(min) + u16::from(recovery);
    if total > 255 {
        return;
    }

    let config = Config {
        minimum_shards: NZU16!(u16::from(min)),
        extra_shards: NZU16!(u16::from(recovery)),
    };

    let Ok((commitment, shards)) =
        ReedSolomon8::<Sha256>::encode(&config, input.data.as_slice(), &STRATEGY)
    else {
        return;
    };

    // Pick the last shard as "ours"
    let my_idx = shards.len() - 1;
    let my_shard = shards[my_idx].clone();
    let Ok((checking_data, my_checked, _)) =
        ReedSolomon8::<Sha256>::weaken(&config, &commitment, my_idx as u16, my_shard)
    else {
        return;
    };

    // Check and collect min-1 other shards
    let mut checked = vec![my_checked];
    for (i, shard) in shards.into_iter().enumerate().take(min as usize - 1) {
        let Ok((_, _, weak)) =
            ReedSolomon8::<Sha256>::weaken(&config, &commitment, i as u16, shard)
        else {
            return;
        };
        let Ok(c) = ReedSolomon8::<Sha256>::check(&config, &commitment, &checking_data, i as u16, weak)
        else {
            return;
        };
        checked.push(c);
    }

    let decoded =
        ReedSolomon8::<Sha256>::decode(&config, &commitment, checking_data, &checked, &STRATEGY)
            .unwrap();
    assert_eq!(decoded, input.data);
});
