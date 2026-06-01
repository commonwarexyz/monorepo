use arbitrary::{Arbitrary, Unstructured};
use commonware_codec::{Encode, Read};
use commonware_coding::{CodecConfig, Config, PhasedAsScheme, PhasedScheme, Scheme};
use commonware_parallel::Sequential;
use commonware_utils::NZU16;
use std::iter;

const STRATEGY: Sequential = Sequential;

#[derive(Debug)]
struct Shuffle {
    choices: Vec<usize>,
}

impl Shuffle {
    fn arbitrary<'a>(u: &mut Unstructured<'a>, len: usize) -> arbitrary::Result<Self> {
        let choices = (0..len - 1)
            .map(|i| Ok(i + u.choose_index(len - i)?))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { choices })
    }

    fn shuffle<T>(&self, data: &mut [T]) {
        assert_eq!(
            self.choices.len() + 1,
            data.len(),
            "data length must match shuffle length"
        );
        for (i, &choice) in self.choices.iter().enumerate() {
            data.swap(i, choice);
        }
    }
}

#[derive(Debug)]
pub struct FuzzInput {
    min: u16,
    recovery: u16,
    to_use: u16,
    data: Vec<u8>,
    shuffle: Shuffle,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let min = u.int_in_range(1..=512)?;
        let recovery = u.int_in_range(min..=512)?;
        let to_use = u.int_in_range(min..=min + recovery)?;
        let data = u.arbitrary::<Vec<u8>>()?;
        let shuffle = Shuffle::arbitrary(u, (min + recovery) as usize)?;

        Ok(FuzzInput {
            recovery,
            min,
            to_use,
            data,
            shuffle,
        })
    }
}

pub fn fuzz<S: Scheme>(input: FuzzInput) {
    let FuzzInput {
        recovery,
        min,
        to_use,
        data,
        shuffle,
    } = input;

    let config = Config {
        minimum_shards: NZU16!(min),
        extra_shards: NZU16!(recovery),
    };
    let (commitment, shards) = S::encode(&config, data.as_slice(), &STRATEGY).unwrap();
    assert_eq!(shards.len(), (recovery + min) as usize);
    let mut shards = (0u16..).zip(shards).collect::<Vec<_>>();
    if let Some((_, shard)) = shards.first() {
        exercise_codec(shard, data.len());
    }
    shuffle.shuffle(&mut shards);

    // Check and collect `to_use` shards.
    let checked_shards = shards
        .into_iter()
        .take(to_use as usize)
        .map(|(i, shard)| S::check(&config, &commitment, i, &shard).unwrap())
        .collect::<Vec<_>>();

    let decoded = S::decode(&config, &commitment, checked_shards.iter(), &STRATEGY).unwrap();
    assert_eq!(&decoded, &data);
}

/// Input for phased fuzz targets (e.g. Zoda). Bounds total shards to 64
/// because `weaken()` recomputes topology + FFT per shard.
#[derive(Debug)]
pub struct PhasedFuzzInput {
    min: u16,
    recovery: u16,
    to_use: u16,
    data: Vec<u8>,
    shuffle: Shuffle,
}

const MAX_PHASED_DATA: usize = 4096;

impl<'a> Arbitrary<'a> for PhasedFuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let min = u.int_in_range(1..=63)?;
        let recovery = u.int_in_range(1..=(64 - min))?;
        let to_use = u.int_in_range(min..=min + recovery)?;
        let shuffle = Shuffle::arbitrary(u, (min + recovery) as usize)?;
        let data_len = u.int_in_range(0..=MAX_PHASED_DATA.min(u.len()))?;
        let data = u.bytes(data_len)?.to_vec();

        Ok(PhasedFuzzInput {
            recovery,
            min,
            to_use,
            data,
            shuffle,
        })
    }
}

pub fn fuzz_phased<S: PhasedScheme>(input: PhasedFuzzInput) {
    let PhasedFuzzInput {
        recovery,
        min,
        to_use,
        data,
        shuffle,
    } = input;

    let config = Config {
        minimum_shards: NZU16!(min),
        extra_shards: NZU16!(recovery),
    };
    let (commitment, shards) = S::encode(b"", &config, data.as_slice(), &STRATEGY).unwrap();
    assert_eq!(shards.len(), (recovery + min) as usize);
    let mut shards = (0u16..).zip(shards).collect::<Vec<_>>();
    if let Some((_, shard)) = shards.first() {
        exercise_codec(shard, data.len());
    }

    let scheme_checked_shards = shards
        .iter()
        .take(to_use as usize)
        .map(|(i, shard)| {
            <PhasedAsScheme<S> as Scheme>::check(&config, &commitment, *i, shard).unwrap()
        })
        .collect::<Vec<_>>();
    let decoded = <PhasedAsScheme<S> as Scheme>::decode(
        &config,
        &commitment,
        scheme_checked_shards.iter(),
        &STRATEGY,
    )
    .unwrap();
    assert_eq!(&decoded, &data);
    let _ = <PhasedAsScheme<S> as Scheme>::decode(&config, &commitment, iter::empty(), &STRATEGY);
    if let Some(first) = scheme_checked_shards.first() {
        let mut other_data = data.clone();
        other_data.push(0);
        let (other_commitment, other_shards) =
            S::encode(b"", &config, other_data.as_slice(), &STRATEGY).unwrap();
        let other_checked =
            <PhasedAsScheme<S> as Scheme>::check(&config, &other_commitment, 0, &other_shards[0])
                .unwrap();
        let _ = <PhasedAsScheme<S> as Scheme>::decode(
            &config,
            &commitment,
            [first, &other_checked].into_iter(),
            &STRATEGY,
        );
    }

    shuffle.shuffle(&mut shards);

    // From here on, we take the point of view of the last participant.
    // This lets us move our strong shard out directly while keeping the rest for forwarding.
    let (my_i, my_shard) = shards.pop().unwrap();
    let (my_checking_data, my_checked_shard, my_weak_shard) =
        S::weaken(b"", &config, &commitment, my_i, my_shard).unwrap();
    exercise_codec(&my_weak_shard, data.len());

    // Check `to_use - 1` forwarded shards, then include our own checked shard.
    let checked_shards = shards
        .into_iter()
        .take((to_use - 1) as usize)
        .map(|(i, shard)| {
            let (_, _, weak_shard) = S::weaken(b"", &config, &commitment, i, shard).unwrap();
            S::check(&config, &commitment, &my_checking_data, i, weak_shard).unwrap()
        })
        .chain(iter::once(my_checked_shard))
        .collect::<Vec<_>>();

    let decoded = S::decode(
        &config,
        &commitment,
        my_checking_data,
        checked_shards.iter(),
        &STRATEGY,
    )
    .unwrap();
    assert_eq!(&decoded, &data);
}

fn exercise_codec<T>(shard: &T, maximum_shard_size: usize)
where
    T: Clone + Encode + Eq + Read<Cfg = CodecConfig>,
{
    let encoded = shard.encode();
    let cfg = CodecConfig {
        maximum_shard_size: encoded.len().max(maximum_shard_size).max(1),
    };
    let mut buf = encoded.as_ref();
    let _ = T::read_cfg(&mut buf, &cfg);
    let _ = shard == &shard.clone();
}
