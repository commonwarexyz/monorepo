//! Shared setup for the proof generation and verification benchmarks.

use commonware_cryptography::{Sha256, sha256};
use commonware_math::algebra::Random as _;
use commonware_storage::merkle::{
    self, Bagging::ForwardFold, Family, Location, LocationRangeExt as _, mem::Mem,
};
use commonware_utils::test_rng;
use futures::executor::block_on;
use rand::{RngExt as _, seq::IndexedRandom};
use std::ops::Range;

pub type StandardHasher<H> = merkle::hasher::Standard<H>;

/// Number of proofs generated or verified per iteration.
pub const SAMPLE_SIZE: usize = 100;

#[cfg(not(full_bench))]
pub const N_LEAVES: [usize; 2] = [10_000, 100_000];
#[cfg(full_bench)]
pub const N_LEAVES: [usize; 5] = [10_000, 100_000, 1_000_000, 5_000_000, 10_000_000];

/// A proven leaf and its location.
pub type SingleSample<F> = (Location<F>, sha256::Digest);

/// A proven range of leaves and their elements.
pub type RangeSample<F> = (Range<Location<F>>, Vec<sha256::Digest>);

/// Builds an in-memory tree of `n` random elements and returns it with its root
/// and the elements in location order.
fn build<F: Family>(n: usize) -> (Mem<F, sha256::Digest>, sha256::Digest, Vec<sha256::Digest>) {
    let hasher = StandardHasher::<Sha256>::new(ForwardFold);
    let mut mem = Mem::<F, _>::new();
    let mut elements = Vec::with_capacity(n);
    let mut sampler = test_rng();
    block_on(async {
        let batch = {
            let mut batch = mem.new_batch();
            for _ in 0..n {
                let element = sha256::Digest::random(&mut sampler);
                batch = batch.add(&hasher, &element);
                elements.push(element);
            }
            batch.merkleize(&mem, &hasher)
        };
        mem.apply_batch(&batch).unwrap();
    });
    let root = mem.root(&hasher, 0).unwrap();
    (mem, root, elements)
}

/// Builds a tree of `n` elements and samples `SAMPLE_SIZE` distinct leaves to prove.
pub fn single_samples<F: Family>(
    n: usize,
) -> (Mem<F, sha256::Digest>, sha256::Digest, Vec<SingleSample<F>>) {
    let (mem, root, elements) = build::<F>(n);
    let mut sampler = test_rng();
    let samples = elements
        .iter()
        .enumerate()
        .collect::<Vec<_>>()
        .sample(&mut sampler, SAMPLE_SIZE)
        .map(|&(loc, element)| (Location::<F>::new(loc as u64), *element))
        .collect();
    (mem, root, samples)
}

/// Builds a tree of `n` elements and samples `SAMPLE_SIZE` ranges of `range`
/// leaves with distinct starts to prove.
pub fn range_samples<F: Family>(
    n: usize,
    range: u64,
) -> (Mem<F, sha256::Digest>, sha256::Digest, Vec<RangeSample<F>>) {
    let (mem, root, elements) = build::<F>(n);
    let mut sampler = test_rng();
    let max_start = n as u64 - range;
    let mut samples: Vec<RangeSample<F>> = Vec::with_capacity(SAMPLE_SIZE);
    while samples.len() < SAMPLE_SIZE {
        let start_index = sampler.random_range(0..max_start);
        let leaf_range = Location::<F>::new(start_index)..Location::<F>::new(start_index + range);
        if samples
            .iter()
            .any(|(range, _)| range.start == leaf_range.start)
        {
            continue;
        }
        let expected = elements[leaf_range.to_usize_range()].to_vec();
        samples.push((leaf_range, expected));
    }
    (mem, root, samples)
}
