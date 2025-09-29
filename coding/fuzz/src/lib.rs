use arbitrary::{Arbitrary, Unstructured};
use commonware_coding::{Config, Scheme};

#[derive(Debug)]
pub struct FuzzInput {
    min: u16,
    recovery: u16,
    to_use: u16,
    data: Vec<u8>,
    shuffle_bytes: Vec<u8>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // We need to generate parameters which satisfy the conditions of valid RS coding,
        // which are such that if min <= 2^16 - 2^n, then recovery <= 2^n.
        let n: u64 = u.int_in_range(0..=15)?;
        let mut min = u.int_in_range(1..=u16::try_from((1 << 16) - (1 << n)).unwrap())?;
        let mut recovery = u.int_in_range(1..=u16::try_from(1 << n).unwrap())?;
        // Correction to make sure that we can fit min + recovery in a u16.
        if min.checked_add(recovery).is_none() {
            if recovery > 1 {
                recovery -= 1;
            } else {
                min -= 1;
            }
        }
        let to_use = u.int_in_range(min..=min + recovery)?;
        let data_len = u.int_in_range(0..=u32::MAX)?; // data.len() <= u32:Max
        let data = u.bytes(data_len as usize)?.to_vec();
        let shuffle_bytes = u.bytes(8)?.to_vec();

        Ok(FuzzInput {
            recovery,
            min,
            to_use,
            data,
            shuffle_bytes,
        })
    }
}

fn shuffle<T>(shuffle_bytes: &[u8], data: &mut [T]) {
    let mut u = Unstructured::new(shuffle_bytes);

    for i in (1..data.len()).rev() {
        let j = u.int_in_range(0..=i).unwrap();
        data.swap(i, j);
    }
}

pub fn fuzz<S: Scheme>(input: FuzzInput) {
    let FuzzInput {
        recovery,
        min,
        to_use,
        data,
        shuffle_bytes,
    } = input;

    let config = Config {
        minimum_shards: min,
        extra_shards: recovery,
    };
    let (commitment, mut shards) = S::encode(&config, data.as_slice()).unwrap();
    assert_eq!(shards.len(), (recovery + min) as usize);
    // Each participant checks their shard
    let mut reshards = shards
        .iter()
        .map(|(shard, proof)| S::check(&commitment, proof, shard).unwrap())
        .collect::<Vec<_>>();
    // The last shard is "ours"
    let (my_shard, _) = shards.pop().unwrap();
    // We shuffle the remaining reshards
    reshards.truncate(reshards.len() - 1);
    shuffle(&shuffle_bytes, &mut reshards);
    // We decode using the specified number of reshards, and ours.
    let decoded = S::decode(
        &config,
        &commitment,
        my_shard,
        &reshards[..(to_use - 1) as usize],
    )
    .unwrap();
    assert_eq!(&decoded, &data);
}
