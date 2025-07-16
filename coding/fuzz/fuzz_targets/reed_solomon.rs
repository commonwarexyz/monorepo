#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_coding::reed_solomon::{decode, encode, Chunk};
use commonware_cryptography::Sha256;
use libfuzzer_sys::fuzz_target;

#[derive(Debug)]
struct FuzzInput {
    total: u16,
    min: u16,
    data: Vec<u8>,
    shuffle_bytes: Vec<u8>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let min = u.int_in_range(1..=256)?; // min > 0
        let total = u.int_in_range(min + 1..=1000)?; // total > min
        let data_len = u.int_in_range(0..=u16::MAX)?; // data.len() <= u32:Max
        let data = u.bytes(data_len as usize)?.to_vec();
        let shuffle_bytes = u.bytes(8)?.to_vec();

        Ok(FuzzInput {
            total,
            min,
            data,
            shuffle_bytes,
        })
    }
}

#[derive(Clone)]
pub struct ShuffledChunks {
    pub chunks: Vec<Chunk<Sha256>>,
}

impl ShuffledChunks {
    pub fn from_chunks<I>(chunks: I, fuzz_bytes: &[u8]) -> arbitrary::Result<Self>
    where
        I: IntoIterator<Item = Chunk<Sha256>>,
    {
        let mut chunks: Vec<_> = chunks.into_iter().collect();
        let mut u = Unstructured::new(fuzz_bytes);

        for i in (1..chunks.len()).rev() {
            let j = u.int_in_range(0..=i)?;
            chunks.swap(i, j);
        }

        Ok(ShuffledChunks { chunks })
    }
}

fn fuzz(input: FuzzInput) {
    let total = input.total;
    let min = input.min;
    let payload = input.data;
    let shuffle_bytes = input.shuffle_bytes;

    let (root, chunks) = match encode::<Sha256>(total, min, payload.to_vec()) {
        Ok(result) => result,
        Err(_) => return,
    };

    assert_eq!(chunks.len(), total as usize);

    for chunk in &chunks {
        assert!(chunk.verify(&root), "failed to verify chunk");
    }

    let decoded = match decode::<Sha256>(total, min, &root, chunks.clone()) {
        Ok(data) => data,
        Err(e) => panic!("decode with all chunks failed: {e:?}"),
    };
    assert_eq!(decoded, payload, "decode with all chunks failed");

    let subset =
        ShuffledChunks::from_chunks(chunks, &shuffle_bytes).expect("failed to shuffle chunks");

    let decoded_subset = match decode::<Sha256>(total, min, &root, subset.chunks) {
        Ok(data) => data,
        Err(e) => panic!("decode with min chunks failed: {e:?}"),
    };
    assert_eq!(decoded_subset, payload);
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
