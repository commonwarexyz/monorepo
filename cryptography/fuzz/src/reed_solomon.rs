//! Differential fuzz driver for `commonware-cryptography` Reed-Solomon engines.
//!
//! A single [`fuzz`] driver encodes and decodes through the engine under test, selected by the
//! type parameter, with every [`Engine`] operation checked against the [`Naive`] reference on a
//! copy of its input. Peers on different architectures exchange shards, so every engine must
//! agree with the reference exactly, not merely roundtrip with itself.

use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::reed_solomon::{
    Decoder,
    engine::{Engine, GF_ORDER, GfElement, Naive, SHARD_CHUNK_BYTES, ShardsRefMut},
    rate::{DefaultRateDecoder, DefaultRateEncoder, RateDecoder, RateEncoder},
};
use commonware_utils::TestRng;
use rand::{RngExt as _, seq::SliceRandom};

const MAX_SHARDS: usize = 256;
const MAX_SHARD_BYTES: usize = 3 * SHARD_CHUNK_BYTES;

#[derive(Debug)]
pub struct FuzzInput {
    original_count: usize,
    recovery_count: usize,
    shard_bytes: usize,
    compute_recovery: bool,
    seed: u64,
    original_received: Vec<bool>,
    recovery_received: Vec<bool>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let original_count = u.int_in_range(1..=MAX_SHARDS)?;
        let recovery_count = u.int_in_range(1..=MAX_SHARDS)?;
        let shard_bytes = 2 * u.int_in_range(1..=MAX_SHARD_BYTES / 2)?;
        let compute_recovery = u.arbitrary()?;
        // The fuzzer picks how many originals are missing and how many spare recovery shards
        // are supplied (the decode is always solvable); a seeded RNG picks which ones, so
        // erasure positions stay uniform at any shard count without consuming input bytes.
        let missing = u.int_in_range(0..=original_count.min(recovery_count))?;
        let supplied = missing + u.int_in_range(0..=recovery_count - missing)?;
        let seed = u.arbitrary()?;

        let mut rng = TestRng::new(seed);
        let original_received = received_mask(&mut rng, original_count, original_count - missing);
        let recovery_received = received_mask(&mut rng, recovery_count, supplied);

        Ok(FuzzInput {
            original_count,
            recovery_count,
            shard_bytes,
            compute_recovery,
            seed,
            original_received,
            recovery_received,
        })
    }
}

fn received_mask(rng: &mut TestRng, count: usize, received: usize) -> Vec<bool> {
    let mut indices = (0..count).collect::<Vec<_>>();
    indices.shuffle(rng);
    let mut mask = vec![false; count];
    for index in &indices[..received] {
        mask[*index] = true;
    }
    mask
}

/// [`Engine`] that runs every operation through `E` and [`Naive`], keeps the output of `E`, and
/// asserts the two agree wherever the [`Engine`] contract defines the result.
struct Checked<E> {
    engine: E,
    naive: Naive,
}

impl<E: Default> Default for Checked<E> {
    fn default() -> Self {
        Self {
            engine: E::default(),
            naive: Naive::default(),
        }
    }
}

/// Owned copy of a [`ShardsRefMut`] for running the reference operation on.
struct Shards {
    shard_count: usize,
    chunk_count: usize,
    data: Vec<[u8; SHARD_CHUNK_BYTES]>,
}

impl Shards {
    fn copy_of(shards: &ShardsRefMut<'_>) -> Self {
        let shard_count = shards.len();
        let chunk_count = if shard_count == 0 { 0 } else { shards[0].len() };
        let data = (0..shard_count)
            .flat_map(|index| shards[index].iter().copied())
            .collect();
        Self {
            shard_count,
            chunk_count,
            data,
        }
    }

    fn as_ref_mut(&mut self) -> ShardsRefMut<'_> {
        ShardsRefMut::new(self.shard_count, self.chunk_count, &mut self.data)
    }

    fn shard(&self, index: usize) -> &[[u8; SHARD_CHUNK_BYTES]] {
        &self.data[index * self.chunk_count..(index + 1) * self.chunk_count]
    }
}

impl<E: Engine> Checked<E> {
    /// Runs a transform of `data[pos..pos + size]` on both engines and compares every shard
    /// whose result is defined: the first `truncated_size`, plus the rest for an IFFT whose tail
    /// was zero on input (the rate code relies on that; it equals the untruncated IFFT).
    /// [`Engine::fft`] documents the same zero-tail clause, but a truncated FFT does not honor it
    /// even in [`Naive`] (its tail differs from the untruncated FFT of the same input), engines
    /// skip different butterflies there, and no caller reads it. Shards outside the range must be
    /// untouched.
    fn transform(
        &self,
        data: &mut ShardsRefMut<'_>,
        pos: usize,
        size: usize,
        truncated_size: usize,
        inverse: bool,
        run: impl Fn(&dyn Engine, &mut ShardsRefMut<'_>),
    ) {
        let op = if inverse { "ifft" } else { "fft" };
        let tail = pos + truncated_size..pos + size;
        let tail_defined = inverse
            && tail.clone().all(|index| {
                data[index]
                    .iter()
                    .all(|chunk| *chunk == [0; SHARD_CHUNK_BYTES])
            });
        let mut reference = Shards::copy_of(data);
        run(&self.naive, &mut reference.as_ref_mut());
        run(&self.engine, data);
        for index in 0..data.len() {
            if !tail_defined && tail.contains(&index) {
                continue;
            }
            assert!(
                data[index] == *reference.shard(index),
                "{op} shard {index} differs from Naive (pos={pos} size={size} truncated_size={truncated_size})"
            );
        }
    }
}

impl<E: Engine> Engine for Checked<E> {
    fn fft(
        &self,
        data: &mut ShardsRefMut<'_>,
        pos: usize,
        size: usize,
        truncated_size: usize,
        skew_delta: usize,
    ) {
        self.transform(data, pos, size, truncated_size, false, |engine, data| {
            engine.fft(data, pos, size, truncated_size, skew_delta)
        });
    }

    fn ifft(
        &self,
        data: &mut ShardsRefMut<'_>,
        pos: usize,
        size: usize,
        truncated_size: usize,
        skew_delta: usize,
    ) {
        self.transform(data, pos, size, truncated_size, true, |engine, data| {
            engine.ifft(data, pos, size, truncated_size, skew_delta)
        });
    }

    fn mul(&self, x: &mut [[u8; SHARD_CHUNK_BYTES]], log_m: GfElement) {
        let mut reference = x.to_vec();
        self.naive.mul(&mut reference, log_m);
        self.engine.mul(x, log_m);
        assert!(*x == *reference, "mul by log_m={log_m} differs from Naive");
    }

    fn eval_poly(erasures: &mut [GfElement; GF_ORDER], truncated_size: usize) {
        let mut reference = *erasures;
        Naive::eval_poly(&mut reference, truncated_size);
        E::eval_poly(erasures, truncated_size);
        assert!(
            erasures[..] == reference[..],
            "eval_poly with truncated_size={truncated_size} differs from Naive"
        );
    }
}

fn original_shards(input: &FuzzInput) -> Vec<Vec<u8>> {
    let mut rng = TestRng::new(input.seed);
    (0..input.original_count)
        .map(|_| {
            let mut shard = vec![0u8; input.shard_bytes];
            rng.fill(&mut shard[..]);
            shard
        })
        .collect()
}

fn missing_indices(received: &[bool]) -> Vec<usize> {
    received
        .iter()
        .enumerate()
        .filter(|(_, received)| !**received)
        .map(|(index, _)| index)
        .collect()
}

fn encode<E: Engine>(engine: E, input: &FuzzInput, original: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut encoder = DefaultRateEncoder::new(
        input.original_count,
        input.recovery_count,
        input.shard_bytes,
        engine,
        None,
    )
    .unwrap();
    for shard in original {
        encoder.add_original_shard(shard).unwrap();
    }
    encoder
        .encode()
        .unwrap()
        .recovery_iter()
        .map(<[u8]>::to_vec)
        .collect()
}

type Restored = Vec<(usize, Vec<u8>)>;

fn received<'a>(
    mask: &'a [bool],
    shards: &'a [Vec<u8>],
) -> impl Iterator<Item = (usize, &'a [u8])> {
    shards
        .iter()
        .enumerate()
        .filter(move |(index, _)| mask[*index])
        .map(|(index, shard)| (index, shard.as_slice()))
}

fn owned((index, shard): (usize, &[u8])) -> (usize, Vec<u8>) {
    (index, shard.to_vec())
}

/// Restored originals from `E`. The rate API exposes nothing else; reconstructed recovery
/// shards are checked per operation by [`Checked`] and end to end by [`decode_default`].
fn decode<E: Engine>(
    engine: E,
    input: &FuzzInput,
    original: &[Vec<u8>],
    recovery: &[Vec<u8>],
) -> Option<Restored> {
    let mut decoder = DefaultRateDecoder::new(
        input.original_count,
        input.recovery_count,
        input.shard_bytes,
        engine,
        None,
    )
    .unwrap();
    for (index, shard) in received(&input.original_received, original) {
        decoder.add_original_shard(index, shard).unwrap();
    }
    for (index, shard) in received(&input.recovery_received, recovery) {
        decoder.add_recovery_shard(index, shard).unwrap();
    }
    decoder
        .decode(input.compute_recovery)
        .unwrap()
        .map(|result| result.original_iter().map(owned).collect())
}

/// Restored originals and recovery shards from the [`Decoder`] wrapper, the only public path to
/// reconstructed recovery shards (it decodes with the host's default engine).
fn decode_default(
    input: &FuzzInput,
    original: &[Vec<u8>],
    recovery: &[Vec<u8>],
) -> Option<(Restored, Restored)> {
    let mut decoder = Decoder::new(
        input.original_count,
        input.recovery_count,
        input.shard_bytes,
    )
    .unwrap();
    for (index, shard) in received(&input.original_received, original) {
        decoder.add_original_shard(index, shard).unwrap();
    }
    for (index, shard) in received(&input.recovery_received, recovery) {
        decoder.add_recovery_shard(index, shard).unwrap();
    }
    decoder.decode_with_recovery().unwrap().map(|result| {
        (
            result.original_iter().map(owned).collect(),
            result.recovery_iter().map(owned).collect(),
        )
    })
}

fn assert_restored(restored: &Restored, missing: &[usize], truth: &[Vec<u8>], kind: &str) {
    let indices = restored.iter().map(|(index, _)| *index).collect::<Vec<_>>();
    assert_eq!(indices, missing, "restored {kind} indices are wrong");
    for (index, shard) in restored {
        assert_eq!(
            shard, &truth[*index],
            "restored {kind} shard {index} is wrong"
        );
    }
}

/// Encodes and decodes `input` through `E` with every engine operation checked against
/// [`Naive`], then asserts the restored shards match the data that was encoded.
pub fn fuzz<E: Engine + Default>(input: FuzzInput) {
    let original = original_shards(&input);

    let recovery = encode(Checked::<E>::default(), &input, &original);
    let restored = decode(Checked::<E>::default(), &input, &original, &recovery);

    let missing_original = missing_indices(&input.original_received);
    match &restored {
        Some(restored) => assert_restored(restored, &missing_original, &original, "original"),
        None => assert!(missing_original.is_empty()),
    }

    if input.compute_recovery {
        let (restored_original, restored_recovery) =
            decode_default(&input, &original, &recovery).unzip();
        assert_eq!(
            restored_original, restored,
            "default engine restored shards differ"
        );
        if let Some(restored_recovery) = restored_recovery {
            let missing_recovery = missing_indices(&input.recovery_received);
            assert_restored(&restored_recovery, &missing_recovery, &recovery, "recovery");
        }
    }
}
