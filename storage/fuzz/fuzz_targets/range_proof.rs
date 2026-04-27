#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_storage::merkle::{
    hasher::Standard,
    mem::{Config, Mem},
    mmb, mmr, Family as MerkleFamily, Location, RootSpec,
};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    // Raw `u64` so we also exercise `Mem::init`'s overflow / near-overflow rejection paths
    // for each family (`Location<F>: Arbitrary` would silently clamp to `F::MAX_LEAVES`).
    pruned_to: u64,
    nodes: Vec<[u8; 32]>,
    pinned_nodes: Vec<[u8; 32]>,
}

fn fuzz_family<F: MerkleFamily>(input: &FuzzInput) {
    let nodes: Vec<Digest> = input.nodes.iter().copied().map(Digest::from).collect();
    let pinned_nodes: Vec<Digest> = input
        .pinned_nodes
        .iter()
        .copied()
        .map(Digest::from)
        .collect();

    let config = Config::<F, Digest> {
        nodes,
        pruning_boundary: Location::<F>::new(input.pruned_to),
        pinned_nodes,
    };

    let hasher = Standard::<Sha256>::new();
    let Ok(merkle) = Mem::<F, Digest>::init(config) else {
        return;
    };

    if input.pruned_to == u64::MAX || input.pruned_to == u64::MAX - 1 {
        return;
    }

    let leaves = merkle.leaves();
    if leaves > 0 {
        let _ = merkle.range_proof(
            &hasher,
            Location::<F>::new(0)..leaves,
            RootSpec::FULL_FORWARD,
        );
    }
}

fn fuzz(input: FuzzInput) {
    fuzz_family::<mmr::Family>(&input);
    fuzz_family::<mmb::Family>(&input);
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = FuzzInput::arbitrary(&mut unstructured) else {
        return;
    };
    fuzz(input);
});
