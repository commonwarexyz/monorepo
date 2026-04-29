#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_storage::merkle::{
    hasher::Standard,
    mem::{Config, Mem},
    mmb, mmr, Bagging, Family as MerkleFamily, Location, RootSpec,
};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    // Raw `u64` so we also exercise `Mem::init`'s overflow / near-overflow rejection paths
    // for each family (`Location<F>: Arbitrary` would silently clamp to `F::MAX_LEAVES`).
    pruned_to: u64,
    nodes: Vec<[u8; 32]>,
    pinned_nodes: Vec<[u8; 32]>,
    range_start: u64,
}

/// All `RootSpec` shapes a range proof may legitimately be requested for: both `Full` baggings
/// plus every `Split` count from 0 up to the number of peaks. Mirrors the helper in
/// `proofs_malleability.rs`.
fn supported_root_specs<F: MerkleFamily>(merkle: &Mem<F, Digest>) -> Vec<RootSpec> {
    let peak_count = F::peaks(merkle.size()).count();
    let mut specs = Vec::with_capacity(2 + 2 * (peak_count + 1));
    let mut push_unique = |spec| {
        if !specs.contains(&spec) {
            specs.push(spec);
        }
    };
    push_unique(RootSpec::FULL_FORWARD);
    push_unique(RootSpec::Full {
        bagging: Bagging::BackwardFold,
    });
    for inactive_peaks in 0..=peak_count {
        push_unique(RootSpec::split_forward(inactive_peaks));
        push_unique(RootSpec::split_backward(inactive_peaks));
    }
    specs
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
    if leaves == 0 {
        return;
    }
    let start = Location::<F>::new(input.range_start % *leaves);
    for spec in supported_root_specs::<F>(&merkle) {
        let _ = merkle.range_proof(&hasher, start..leaves, spec);
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
