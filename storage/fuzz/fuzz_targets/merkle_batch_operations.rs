#![no_main]

//! Mix appends and leaf updates across stacked batches, with `add_many` split into up to 8
//! ranges, and compare each root against a tree built by appending every final leaf digest.

use arbitrary::Arbitrary;
use commonware_codec::Encode;
use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest};
use commonware_parallel::{Manual, Rayon, Strategy as _};
use commonware_storage::merkle::{
    Bagging::ForwardFold,
    Error, Family as MerkleFamily, Location,
    batch::{MerkleizedBatch, UnmerkleizedBatch},
    hasher::{Hasher as _, Standard},
    mem::Mem,
    mmb, mmr,
};
use commonware_utils::NZUsize;
use core::num::NonZeroUsize;
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;

/// Leaves past this count are ignored, so a reference rebuild stays cheap.
const LEAF_CAP: usize = 4096;

#[derive(Arbitrary, Debug)]
enum Operation {
    Add { data: Vec<u8> },
    AddMany { count: u16, seed: u8 },
    AddDigests { count: u16, seed: u8 },
    Update { location: u16, data: Vec<u8> },
    UpdateDigests { locations: Vec<u16>, seed: u8 },
    Merkleize,
    Apply,
    Prune { location: u16 },
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    committed: u8,
    parallelism: u8,
    operations: Vec<Operation>,
}

/// A strategy that splits work into up to `parallelism` batches, run on one thread.
type Split = Manual<Rayon>;
type Batch<F> = UnmerkleizedBatch<F, Digest, Split>;
/// Merkleized batches not yet applied, oldest first.
type Chain<F> = Vec<Arc<MerkleizedBatch<F, Digest, Split>>>;

fn limit(data: &[u8]) -> &[u8] {
    &data[..data.len().min(16)]
}

/// The digest of `element` as the leaf at `index`.
fn leaf<F: MerkleFamily>(hasher: &Standard<Sha256>, index: usize, element: &[u8]) -> Digest {
    hasher.leaf_digest(
        F::location_to_position(Location::new(index as u64)),
        element,
    )
}

/// The root of a tree holding `leaves`, each appended one at a time.
fn reference_root<F: MerkleFamily>(hasher: &Standard<Sha256>, leaves: &[Digest]) -> Digest {
    let empty = Mem::<F, Digest>::new();
    let mut batch = empty.new_batch();
    for &leaf in leaves {
        batch = batch.add_leaf_digest(leaf);
    }
    batch
        .merkleize(&empty, hasher)
        .root(&empty, hasher, 0)
        .unwrap()
}

fn fuzz_family<F: MerkleFamily>(input: &FuzzInput) {
    let hasher = Standard::<Sha256>::new(ForwardFold);
    // One thread, but `Manual` skips the adaptive policy, so work splits whenever it can.
    let parallelism = NonZeroUsize::new(usize::from(input.parallelism % 8) + 1).unwrap();
    let strategy = Rayon::new(NZUsize!(1))
        .unwrap()
        .with_parallelism(parallelism)
        .manual();

    let mut leaves: Vec<Digest> = (0..input.committed)
        .map(|i| Sha256::hash(&[&[i]]))
        .collect();
    let mut base = Mem::<F, Digest>::new();
    let mut batch = base.new_batch();
    for &leaf in &leaves {
        batch = batch.add_leaf_digest(leaf);
    }
    base.apply_batch(&batch.merkleize(&base, &hasher)).unwrap();

    // Kept alive so later batches can read them.
    let mut chain: Chain<F> = Vec::new();
    let new_batch = |base: &Mem<F, Digest>, chain: &Chain<F>| {
        chain.last().map_or_else(
            || MerkleizedBatch::from_mem_with_strategy(base, strategy.clone()).new_batch(),
            |parent| parent.new_batch(),
        )
    };
    let mut batch: Batch<F> = new_batch(&base, &chain);

    let merkleize =
        |batch: Batch<F>, base: &Mem<F, Digest>, chain: &mut Chain<F>, leaves: &[Digest]| {
            let merkleized = batch.merkleize(base, &hasher);
            assert_eq!(
                merkleized.root(base, &hasher, 0).unwrap(),
                reference_root::<F>(&hasher, leaves),
                "root mismatch with {} leaves",
                leaves.len()
            );
            chain.push(merkleized);
        };

    for op in &input.operations {
        match op {
            Operation::Add { data } => {
                if leaves.len() >= LEAF_CAP {
                    continue;
                }
                let data = limit(data);
                batch = batch.add(&hasher, data);
                leaves.push(leaf::<F>(&hasher, leaves.len(), data));
            }
            Operation::AddMany { count, seed } => {
                let count = usize::from(*count % 600).min(LEAF_CAP - leaves.len());
                let items: Vec<Vec<u8>> = (0..count)
                    .map(|i| vec![*seed; i % 5].into_iter().chain([i as u8]).collect())
                    .collect();
                batch = batch.add_many(&hasher, &items);
                for item in &items {
                    leaves.push(leaf::<F>(&hasher, leaves.len(), &item.encode()));
                }
            }
            Operation::AddDigests { count, seed } => {
                let count = usize::from(*count % 600).min(LEAF_CAP - leaves.len());
                let digests: Vec<Digest> = (0..count as u16)
                    .map(|i| Sha256::hash(&[&[*seed], &i.to_be_bytes()]))
                    .collect();
                batch = match digests.as_slice() {
                    [digest] => batch.add_leaf_digest(*digest),
                    _ => batch.add_leaf_digests(digests.iter().copied()),
                };
                leaves.extend(digests);
            }
            Operation::Update { location, data } => {
                if leaves.is_empty() {
                    continue;
                }
                let index = usize::from(*location) % leaves.len();
                let loc = Location::new(index as u64);
                let data = limit(data);
                if loc < base.pruning_boundary() {
                    // Check the error on a spare batch, since a failed update consumes the batch.
                    let result = new_batch(&base, &chain).update_leaf(&hasher, loc, data);
                    assert!(matches!(result, Err(Error::ElementPruned(_))));
                    continue;
                }
                batch = batch.update_leaf(&hasher, loc, data).unwrap();
                leaves[index] = leaf::<F>(&hasher, index, data);
            }
            Operation::UpdateDigests { locations, seed } => {
                if leaves.is_empty() {
                    continue;
                }
                let boundary = *base.pruning_boundary() as usize;
                let updates: Vec<(Location<F>, Digest)> = locations
                    .iter()
                    .take(64)
                    .map(|&location| {
                        let index =
                            boundary + usize::from(location) % (leaves.len() - boundary).max(1);
                        let digest = Sha256::hash(&[&[*seed], &location.to_be_bytes()]);
                        (Location::new(index as u64), digest)
                    })
                    .filter(|(loc, _)| (**loc as usize) < leaves.len())
                    .collect();
                if seed % 4 == 0 {
                    // A location past the end fails the whole update. Check that on a spare batch.
                    let mut invalid = updates.clone();
                    invalid.push((
                        Location::new(leaves.len() as u64),
                        Sha256::hash(&[&[*seed]]),
                    ));
                    let result = new_batch(&base, &chain).update_leaf_batched(&invalid);
                    assert!(matches!(result, Err(Error::LeafOutOfBounds(_))));
                }
                batch = match updates.as_slice() {
                    [(loc, digest)] => batch.update_leaf_digest(*loc, *digest).unwrap(),
                    _ => batch.update_leaf_batched(&updates).unwrap(),
                };
                // Later updates to the same leaf win.
                for (loc, digest) in updates {
                    leaves[*loc as usize] = digest;
                }
            }
            Operation::Merkleize => {
                merkleize(batch, &base, &mut chain, &leaves);
                batch = new_batch(&base, &chain);
            }
            Operation::Apply => {
                merkleize(batch, &base, &mut chain, &leaves);
                base.apply_batch(chain.last().unwrap()).unwrap();
                chain.clear();
                batch = new_batch(&base, &chain);
            }
            Operation::Prune { location } => {
                // Merkleize and apply first, since a batch reads unpruned siblings from the base.
                merkleize(batch, &base, &mut chain, &leaves);
                base.apply_batch(chain.last().unwrap()).unwrap();
                chain.clear();
                let loc = Location::new(u64::from(*location) % (leaves.len() as u64 + 1));
                if loc > base.pruning_boundary() {
                    base.prune(loc).unwrap();
                }
                batch = new_batch(&base, &chain);
            }
        }
    }
    merkleize(batch, &base, &mut chain, &leaves);
}

fuzz_target!(|input: FuzzInput| {
    fuzz_family::<mmr::Family>(&input);
    fuzz_family::<mmb::Family>(&input);
});
