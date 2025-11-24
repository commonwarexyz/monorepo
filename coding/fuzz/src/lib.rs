use arbitrary::{Arbitrary, Unstructured};
use commonware_coding::{Config, Scheme};
use std::iter;

const CONCURRENCY: usize = 1;

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
        minimum_shards: min,
        extra_shards: recovery,
    };
    let (commitment, shards) = S::encode(&config, data.as_slice(), CONCURRENCY).unwrap();
    assert_eq!(shards.len(), (recovery + min) as usize);
    // We don't use enumerate to get u16s.
    let mut shards = (0u16..).zip(shards).collect::<Vec<_>>();
    shuffle.shuffle(&mut shards);
    // From here on, we take the point of view of the last participant.
    // (This is so that we can move their shard out of the vector easily).
    let (my_i, my_shard) = shards.pop().unwrap();
    let (my_checking_data, my_checked_shard, _) =
        S::reshard(&config, &commitment, my_i, my_shard).unwrap();

    // Check to_use - 1 shards, then include our own checked shards.
    let checked_shards = shards
        .into_iter()
        .take((to_use - 1) as usize)
        .map(|(i, shard)| {
            let (_, _, reshard) = S::reshard(&config, &commitment, i, shard).unwrap();
            S::check(&config, &commitment, &my_checking_data, i, reshard).unwrap()
        })
        .chain(iter::once(my_checked_shard))
        .collect::<Vec<_>>();

    let decoded = S::decode(
        &config,
        &commitment,
        my_checking_data,
        &checked_shards,
        CONCURRENCY,
    )
    .unwrap();
    assert_eq!(&decoded, &data);
}
