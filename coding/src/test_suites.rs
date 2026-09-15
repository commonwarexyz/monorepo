//! Shared round-trip checks for coding schemes.

use crate::{CodecConfig, Config, PhasedScheme, Scheme};
use arbitrary::Unstructured;
use commonware_codec::{Encode, Read};
use commonware_parallel::Sequential;
use commonware_utils::NZU16;

const MAX_SHARD_SIZE: usize = 1 << 31;
const MAX_SHARDS: u16 = 32;
const MAX_DATA: usize = 1024;
const MIN_EXTRA_SHARDS: u16 = 1;

pub fn generate_case(u: &mut Unstructured<'_>) -> arbitrary::Result<(Config, Vec<u8>, Vec<u16>)> {
    let minimum_shards = (u.arbitrary::<u16>()? % MAX_SHARDS) + 1;
    let extra_shards =
        MIN_EXTRA_SHARDS + (u.arbitrary::<u16>()? % (MAX_SHARDS - MIN_EXTRA_SHARDS + 1));
    let total_shards = minimum_shards + extra_shards;

    let data_len = usize::from(u.arbitrary::<u16>()?) % (MAX_DATA + 1);
    let data = u.bytes(data_len)?.to_vec();

    let selected_len = usize::from(minimum_shards)
        + (usize::from(u.arbitrary::<u16>()?) % (usize::from(extra_shards) + 1));
    let mut selected: Vec<u16> = (0..total_shards).collect();
    for i in 0..selected_len {
        let remaining = usize::from(total_shards) - i;
        let j = i + (usize::from(u.arbitrary::<u16>()?) % remaining);
        selected.swap(i, j);
    }
    selected.truncate(selected_len);

    Ok((
        Config {
            minimum_shards: NZU16!(minimum_shards),
            extra_shards: NZU16!(extra_shards),
        },
        data,
        selected,
    ))
}

pub fn roundtrip<S: Scheme>(config: &Config, data: &[u8], selected: &[u16]) {
    let (commitment, shards) = S::encode(config, data, &Sequential).unwrap();
    let read_cfg = CodecConfig {
        maximum_shard_size: MAX_SHARD_SIZE,
    };
    for shard in &shards {
        let decoded_shard = S::Shard::read_cfg(&mut shard.encode(), &read_cfg).unwrap();
        assert_eq!(decoded_shard, *shard);
    }

    let mut checked_shards = Vec::new();
    for (i, shard) in shards.into_iter().enumerate() {
        if !selected.contains(&(i as u16)) {
            continue;
        }
        let checked = S::check(config, &commitment, i as u16, &shard, &Sequential).unwrap();
        checked_shards.push(checked);
    }

    checked_shards.reverse();
    let decoded = S::decode(config, &commitment, checked_shards.iter(), &Sequential).unwrap();
    assert_eq!(decoded, data);
}

pub fn phased_roundtrip<S: PhasedScheme>(config: &Config, data: &[u8], selected: &[u16]) {
    let owner = *selected.first().expect("selected must not be empty");
    let (commitment, shards) = S::encode(b"", config, data, &Sequential).unwrap();
    let read_cfg = CodecConfig {
        maximum_shard_size: MAX_SHARD_SIZE,
    };
    for shard in &shards {
        let decoded_shard = S::StrongShard::read_cfg(&mut shard.encode(), &read_cfg).unwrap();
        assert_eq!(decoded_shard, *shard);
    }

    let (checking_data, own_checked, _) = S::weaken(
        b"",
        config,
        &commitment,
        owner,
        shards[owner as usize].clone(),
        &Sequential,
    )
    .unwrap();
    let mut checked_shards = vec![own_checked];
    for &index in selected {
        if index == owner {
            continue;
        }
        let (_, _, weak_shard) = S::weaken(
            b"",
            config,
            &commitment,
            index,
            shards[index as usize].clone(),
            &Sequential,
        )
        .unwrap();
        let decoded_weak = S::WeakShard::read_cfg(&mut weak_shard.encode(), &read_cfg).unwrap();
        assert_eq!(decoded_weak, weak_shard);
        let checked = S::check(
            config,
            &commitment,
            &checking_data,
            index,
            decoded_weak,
            &Sequential,
        )
        .unwrap();
        checked_shards.push(checked);
    }

    checked_shards.reverse();
    let decoded = S::decode(
        config,
        &commitment,
        checking_data,
        checked_shards.iter(),
        &Sequential,
    )
    .unwrap();
    assert_eq!(decoded, data);
}
