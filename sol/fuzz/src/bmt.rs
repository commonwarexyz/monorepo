//! Binary Merkle Tree proof oracle using Commonware's Keccak256 implementation.
//!
//! Generation and verification share the ABI tuple
//! `(root, leaves, start, indices, elements, proof)`. Materialized generation is
//! limited to 1,000,000 leaves. Synthetic single proofs support the full u32 domain.

use super::merkle::leaf;
use alloy_sol_macro::sol;
use alloy_sol_types::{SolValue as _, sol_data};
use clap::{Subcommand, ValueEnum};
use commonware_cryptography::{
    Hasher as _, Keccak256,
    keccak256::{self, Digest},
};
use commonware_storage::bmt::{Builder, Proof};

type U256 = <sol_data::Uint<256> as alloy_sol_types::SolType>::RustType;

sol! {
    struct BmtPayload {
        bytes32 root;
        uint256 leaves;
        uint256 start;
        uint256[] indices;
        bytes32[] elements;
        bytes32[] proof;
    }
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Build at most 1,000,000 leaves and return a contiguous range proof.
    Generate {
        leaves: u32,
        start: u32,
        count: u32,
        seed: u64,
    },
    /// Build at most 1,000,000 leaves and prove comma-separated indices in input order.
    GenerateMulti {
        leaves: u32,
        indices: String,
        seed: u64,
    },
    /// Construct a single proof without allocating the complete tree.
    Synthetic { leaves: u32, index: u32, seed: u64 },
    /// Verify a canonical ABI tuple; single and range ignore the indices array.
    Check {
        #[arg(value_enum)]
        mode: Mode,
        abi_hex: String,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum Mode {
    Single,
    Range,
    Multi,
}

struct Output {
    root: Digest,
    leaves: u32,
    start: u32,
    indices: Vec<u32>,
    elements: Vec<Digest>,
    proof: Vec<Digest>,
}

fn generate(
    leaves: u32,
    start: u32,
    indices: Vec<u32>,
    seed: u64,
    mode: Mode,
) -> Result<Output, String> {
    if leaves > 1_000_000 {
        return Err("materialized generation requires at most 1000000 leaves; use synthetic for larger trees".into());
    }
    let mut builder = Builder::<Keccak256>::new(leaves as usize);
    for index in 0..leaves {
        builder.add(&keccak256::Digest(leaf(seed, u64::from(index))));
    }
    let tree = builder.build();
    let proof = match mode {
        Mode::Range => tree.range_proof(start, indices.last().copied().unwrap_or(0)),
        Mode::Multi if leaves == 0 && indices.is_empty() => Ok(Proof::default()),
        Mode::Multi => tree.multi_proof(&indices),
        Mode::Single => tree.proof(start),
    }
    .map_err(|error| format!("failed to generate proof: {error}"))?;
    let elements = indices
        .iter()
        .map(|index| keccak256::Digest(leaf(seed, u64::from(*index))))
        .collect();
    let output = Output {
        root: tree.root(),
        leaves,
        start,
        indices,
        elements,
        proof: proof.siblings,
    };
    if !check(mode, &encode(&output)) {
        return Err("Commonware rejected its generated proof".into());
    }
    Ok(output)
}

fn generate_range(leaves: u32, start: u32, count: u32, seed: u64) -> Result<Output, String> {
    let end = start.checked_add(count).ok_or("range overflow")?;
    if end > leaves || (count == 0 && (leaves != 0 || start != 0)) {
        return Err("invalid range".into());
    }
    if leaves > 1_000_000 {
        return Err("materialized generation requires at most 1000000 leaves; use synthetic for larger trees".into());
    }
    generate(leaves, start, (start..end).collect(), seed, Mode::Range)
}

/// Siblings represent deterministic subtrees, independent of the materialized seed tree.
fn synthetic(leaves: u32, index: u32, seed: u64) -> Result<Output, String> {
    if index >= leaves {
        return Err("invalid position".into());
    }
    let element = keccak256::Digest(leaf(seed, u64::from(index)));
    let mut node = Keccak256::hash(&[&index.to_be_bytes(), element.as_ref()]);
    let mut position = index;
    let mut width = leaves;
    let mut proof = Vec::new();
    let mut level = 0;
    while width > 1 {
        let sibling = if position.is_multiple_of(2) && position + 1 == width {
            node
        } else {
            let sibling = keccak256::Digest(leaf(seed ^ u64::MAX, level));
            proof.push(sibling);
            sibling
        };
        node = if position.is_multiple_of(2) {
            Keccak256::hash(&[node.as_ref(), sibling.as_ref()])
        } else {
            Keccak256::hash(&[sibling.as_ref(), node.as_ref()])
        };
        position /= 2;
        width = width.div_ceil(2);
        level += 1;
    }
    let output = Output {
        root: Keccak256::hash(&[&leaves.to_be_bytes(), node.as_ref()]),
        leaves,
        start: index,
        indices: vec![index],
        elements: vec![element],
        proof,
    };
    if !check(Mode::Single, &encode(&output)) {
        return Err("Commonware rejected synthetic proof".into());
    }
    Ok(output)
}

fn encode(output: &Output) -> Vec<u8> {
    BmtPayload {
        root: output.root.0.into(),
        leaves: U256::from(output.leaves),
        start: U256::from(output.start),
        indices: output
            .indices
            .iter()
            .map(|index| U256::from(*index))
            .collect(),
        elements: output
            .elements
            .iter()
            .map(|digest| digest.0.into())
            .collect(),
        proof: output.proof.iter().map(|digest| digest.0.into()).collect(),
    }
    .abi_encode_params()
}

fn check(mode: Mode, encoded: &[u8]) -> bool {
    let Ok(payload) = BmtPayload::abi_decode_params_validate(encoded) else {
        return false;
    };
    // Dynamic tails must be contiguous in field order and consume the entire input.
    if payload.abi_encode_params() != encoded {
        return false;
    }
    let Ok(leaves) = u32::try_from(payload.leaves) else {
        return false;
    };
    let start = match mode {
        Mode::Multi => 0,
        Mode::Single | Mode::Range => {
            let Ok(start) = u32::try_from(payload.start) else {
                return false;
            };
            start
        }
    };
    let root = keccak256::Digest(payload.root.0);
    let proof = Proof {
        leaf_count: leaves,
        siblings: payload
            .proof
            .into_iter()
            .map(|digest| keccak256::Digest(digest.0))
            .collect(),
    };
    let elements: Vec<_> = payload
        .elements
        .into_iter()
        .map(|digest| keccak256::Digest(digest.0))
        .collect();
    match mode {
        Mode::Single => {
            elements.len() == 1
                && proof
                    .verify_element_inclusion::<Keccak256>(&elements[0], start, &root)
                    .is_ok()
        }
        Mode::Range => proof
            .verify_range_inclusion::<Keccak256>(start, &elements, &root)
            .is_ok(),
        Mode::Multi => {
            if payload.indices.len() != elements.len() {
                return false;
            }
            let Ok(positions) = payload
                .indices
                .into_iter()
                .map(u32::try_from)
                .collect::<Result<Vec<_>, _>>()
            else {
                return false;
            };
            let elements: Vec<_> = elements.into_iter().zip(positions).collect();
            proof
                .verify_multi_inclusion::<Keccak256>(&elements, &root)
                .is_ok()
        }
    }
}

impl Command {
    pub(crate) fn execute(self) -> Result<Vec<u8>, String> {
        let output = match self {
            Self::Generate {
                leaves,
                start,
                count,
                seed,
            } => generate_range(leaves, start, count, seed)?,
            Self::GenerateMulti {
                leaves,
                indices,
                seed,
            } => {
                let indices = if indices.is_empty() {
                    Vec::new()
                } else {
                    indices
                        .split(',')
                        .map(|index| {
                            index
                                .parse::<u32>()
                                .map_err(|error| format!("invalid index: {error}"))
                        })
                        .collect::<Result<Vec<_>, _>>()?
                };
                generate(leaves, 0, indices, seed, Mode::Multi)?
            }
            Self::Synthetic {
                leaves,
                index,
                seed,
            } => synthetic(leaves, index, seed)?,
            Self::Check { mode, abi_hex } => {
                let encoded = const_hex::decode(abi_hex.strip_prefix("0x").unwrap_or(&abi_hex))
                    .map_err(|error| format!("invalid ABI hex: {error}"))?;
                return Ok(check(mode, &encoded).abi_encode());
            }
        };
        Ok(encode(&output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Cli;
    use clap::Parser as _;

    #[test]
    fn materialized_ranges_and_unordered_multi() {
        for leaves in [1, 2, 3, 7, 8, 11] {
            for start in 0..leaves {
                for count in 1..=leaves - start {
                    let encoded = encode(&generate_range(leaves, start, count, 42).unwrap());
                    assert!(check(Mode::Range, &encoded));
                    assert!(check(Mode::Multi, &encoded));
                    assert_eq!(check(Mode::Single, &encoded), count == 1);
                }
            }
        }
        let output = generate(11, 0, vec![10, 2, 7, 0], 42, Mode::Multi).unwrap();
        assert_eq!(output.indices, [10, 2, 7, 0]);
        assert!(check(Mode::Multi, &encode(&output)));
        assert!(generate(11, 0, vec![2, 2], 42, Mode::Multi).is_err());
        let mut duplicate = output;
        duplicate.indices[1] = duplicate.indices[0];
        assert!(!check(Mode::Multi, &encode(&duplicate)));
    }

    #[test]
    fn empty_and_generation_bounds() {
        let empty = encode(&generate_range(0, 0, 0, 42).unwrap());
        assert_eq!(empty.len(), 9 * 32);
        assert_eq!(&empty[96..192], (192u64, 224u64, 256u64).abi_encode());
        assert!(check(Mode::Range, &empty));
        assert!(check(Mode::Multi, &empty));
        assert!(!check(Mode::Single, &empty));
        assert_eq!(
            empty,
            encode(&generate(0, 0, vec![], 42, Mode::Multi).unwrap())
        );
        for (leaves, start, count) in [
            (1, 0, 0),
            (0, 1, 0),
            (1, 1, 1),
            (u32::MAX, u32::MAX, 1),
            (1_000_001, 0, 1),
        ] {
            assert!(generate_range(leaves, start, count, 42).is_err());
        }
    }

    #[test]
    fn synthetic_full_u32_domain() {
        for leaves in [1, 3, 11, 1 << 31, u32::MAX] {
            for index in [0, leaves / 2, leaves - 1] {
                let output = synthetic(leaves, index, 42).unwrap();
                assert!(output.proof.len() <= 32);
                for mode in [Mode::Single, Mode::Range, Mode::Multi] {
                    assert!(check(mode, &encode(&output)));
                }
            }
        }
        assert!(synthetic(0, 0, 42).is_err());
        assert!(synthetic(u32::MAX, u32::MAX, 42).is_err());
    }

    #[test]
    fn malformed_and_mutated_inputs() {
        let mut output = generate_range(11, 2, 1, 42).unwrap();
        let encoded = encode(&output);
        for mode in [Mode::Single, Mode::Range, Mode::Multi] {
            for length in 0..encoded.len() {
                assert!(!check(mode, &encoded[..length]));
            }
            for offset in [0, 32, 64, 96, 128, 160, 192, 256, 320] {
                let mut malformed = encoded.clone();
                malformed[offset] ^= 1;
                assert_eq!(
                    check(mode, &malformed),
                    offset == 64 && matches!(mode, Mode::Multi)
                );
            }
            let mut trailing = encoded.clone();
            trailing.extend_from_slice(&[0; 32]);
            assert!(!check(mode, &trailing));
        }
        let mut noncanonical = encode(&generate_range(0, 0, 0, 42).unwrap());
        noncanonical[96..128].copy_from_slice(&224u64.abi_encode());
        noncanonical[128..160].copy_from_slice(&192u64.abi_encode());
        assert!(!check(Mode::Range, &noncanonical));
        assert!(!check(Mode::Multi, &noncanonical));
        let mut ignored_indices = encoded.clone();
        ignored_indices[224..256].fill(0xff);
        assert!(check(Mode::Single, &ignored_indices));
        assert!(check(Mode::Range, &ignored_indices));
        assert!(!check(Mode::Multi, &ignored_indices));
        let mut oversized_count = encoded;
        oversized_count[32..64].copy_from_slice(&(u64::from(u32::MAX) + 1).abi_encode());
        for mode in [Mode::Single, Mode::Range, Mode::Multi] {
            assert!(!check(mode, &oversized_count));
        }
        output.proof.push(keccak256::Digest([0; 32]));
        for mode in [Mode::Single, Mode::Range, Mode::Multi] {
            assert!(!check(mode, &encode(&output)));
        }
        output.proof.pop();
        output.proof.pop();
        for mode in [Mode::Single, Mode::Range, Mode::Multi] {
            assert!(!check(mode, &encode(&output)));
        }
    }

    #[test]
    fn cli_round_trips() {
        for args in [
            vec!["generate", "11", "2", "1", "42"],
            vec!["generate-multi", "11", "10,2,0", "42"],
            vec!["generate-multi", "0", "", "42"],
            vec!["synthetic", "4294967295", "4294967294", "42"],
        ] {
            let encoded = Cli::try_parse_from(["fuzz", "bmt"].into_iter().chain(args))
                .unwrap()
                .command
                .execute()
                .unwrap();
            let hex = const_hex::encode(&encoded);
            let accepted = Cli::try_parse_from(["fuzz", "bmt", "check", "multi", &hex])
                .unwrap()
                .command
                .execute()
                .unwrap();
            assert_eq!(accepted, true.abi_encode());
        }
    }
}
