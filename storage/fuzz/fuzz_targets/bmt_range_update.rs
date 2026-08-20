#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{Decode, Encode};
use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest};
use commonware_storage::bmt::{Builder, RangeUpdateProof};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

const MAX_LEAVES: usize = 32;
const MAX_PIECES: usize = 8;
const MAX_HOSTILE_HASHES: usize = 64;

#[derive(Arbitrary, Debug)]
struct Input {
    opening: Vec<u64>,
    replacements: Vec<(u8, u64)>,
    pieces: u8,
    hostile: Vec<u8>,
    hostile_start: u8,
    hostile_end: u8,
    hostile_positions: Vec<u8>,
}

fn tree(leaves: &[Digest]) -> commonware_storage::bmt::Tree<Digest> {
    let mut builder = Builder::<Sha256>::new(leaves.len());
    for leaf in leaves {
        builder.add(leaf);
    }
    builder.build()
}

fuzz_target!(|input: Input| {
    let opening = input
        .opening
        .iter()
        .take(MAX_LEAVES)
        .map(|value| Sha256::hash(&[b"opening", &value.to_be_bytes()]))
        .collect::<Vec<_>>();
    let opening_tree = tree(&opening);
    let mut closing = opening.clone();
    let mut replacements = BTreeMap::new();
    for (position, value) in input.replacements.into_iter().take(MAX_LEAVES) {
        if opening.is_empty() {
            break;
        }
        let position = usize::from(position) % opening.len();
        replacements.insert(position, Sha256::hash(&[b"closing", &value.to_be_bytes()]));
    }
    for (&position, &leaf) in &replacements {
        closing[position] = leaf;
    }
    let changes = replacements
        .into_iter()
        .filter(|(position, leaf)| opening[*position] != *leaf)
        .map(|(position, leaf)| (position as u32, leaf))
        .collect::<Vec<_>>();
    let closing_tree = tree(&closing);
    let update = opening_tree
        .update::<Sha256>(&changes)
        .expect("canonical fuzz changes must build");
    assert_eq!(update.root(), closing_tree.root());

    let piece_count = usize::from(input.pieces) % MAX_PIECES + 1;
    let leaf_count = opening.len() as u32;
    let boundaries = (0..=piece_count)
        .map(|piece| (piece * opening.len() / piece_count) as u32)
        .collect::<Vec<_>>();
    let proofs = opening_tree
        .range_update_proofs(&update, &boundaries)
        .expect("exhaustive fuzz boundaries must build");
    for (interval, proof) in boundaries.windows(2).zip(&proofs) {
        let local = changes
            .iter()
            .filter(|(position, _)| *position >= interval[0] && *position < interval[1])
            .collect::<Vec<_>>();
        let positions = local
            .iter()
            .map(|(position, _)| *position)
            .collect::<Vec<_>>();
        let opening_leaves = positions
            .iter()
            .map(|position| opening[*position as usize])
            .collect::<Vec<_>>();
        let closing_leaves = positions
            .iter()
            .map(|position| closing[*position as usize])
            .collect::<Vec<_>>();
        proof
            .verify::<Sha256>(
                interval[0]..interval[1],
                &positions,
                &opening_leaves,
                &closing_leaves,
                &opening_tree.root(),
                &closing_tree.root(),
            )
            .expect("generated paired proof must verify");
        assert_eq!(
            proof
                .roots::<Sha256>(
                    interval[0]..interval[1],
                    &positions,
                    &opening_leaves,
                    &closing_leaves,
                )
                .expect("generated paired proof must reconstruct"),
            (opening_tree.root(), closing_tree.root())
        );
        assert_eq!(
            RangeUpdateProof::<Digest>::decode_cfg(
                proof.encode(),
                &(proof.shared.len(), proof.outside.len()),
            )
            .expect("encoded paired proof must decode"),
            *proof
        );
    }

    let Ok(hostile) = RangeUpdateProof::<Digest>::decode_cfg(
        input.hostile.as_slice(),
        &(MAX_HOSTILE_HASHES, MAX_HOSTILE_HASHES),
    ) else {
        return;
    };
    let modulus = leaf_count.saturating_add(1);
    let start = u32::from(input.hostile_start) % modulus;
    let end = u32::from(input.hostile_end) % modulus;
    let positions = input
        .hostile_positions
        .into_iter()
        .take(MAX_LEAVES)
        .map(|position| u32::from(position) % modulus)
        .collect::<Vec<_>>();
    let opening_leaves = positions
        .iter()
        .map(|position| {
            opening
                .get(*position as usize)
                .copied()
                .unwrap_or_else(|| Sha256::hash(&[b"missing-opening"]))
        })
        .collect::<Vec<_>>();
    let closing_leaves = positions
        .iter()
        .map(|position| {
            closing
                .get(*position as usize)
                .copied()
                .unwrap_or_else(|| Sha256::hash(&[b"missing-closing"]))
        })
        .collect::<Vec<_>>();
    let _ = hostile.roots::<Sha256>(start..end, &positions, &opening_leaves, &closing_leaves);
});
