#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::Sha256;
use commonware_storage::mmr::{
    mem::{Config, Mmr},
    Location, Position,
};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    pruned_to_pos: u64,
    nodes: Vec<[u8; 32]>,
    pinned_nodes: Vec<[u8; 32]>,
}

fn fuzz(input: FuzzInput) {
    let nodes: Vec<_> = input
        .nodes
        .into_iter()
        .map(<Sha256 as commonware_cryptography::Hasher>::Digest::from)
        .collect();

    let pinned_nodes: Vec<_> = input
        .pinned_nodes
        .into_iter()
        .map(<Sha256 as commonware_cryptography::Hasher>::Digest::from)
        .collect();

    let config = Config::<Sha256> {
        nodes,
        pruned_to_pos: Position::new(input.pruned_to_pos),
        pinned_nodes,
        pool: None,
    };

    let Ok(mmr) = Mmr::init(config) else {
        return;
    };

    if input.pruned_to_pos == u64::MAX || input.pruned_to_pos == u64::MAX - 1 {
        return;
    }

    let leaves = mmr.leaves();
    if leaves > 0 {
        if let Some(start_loc) = Location::new(0) {
            let _ = mmr.range_proof(start_loc..leaves);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = FuzzInput::arbitrary(&mut unstructured) else {
        return;
    };
    fuzz(input);
});
