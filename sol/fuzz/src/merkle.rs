//! Commonware proof oracle for the Solidity differential tests.
//!
//! Commands emit a single hex-encoded ABI value. Tree construction, proof layout,
//! and verification belong to Commonware. This binary adapts command-line inputs and ABI I/O.

use alloy_sol_macro::sol;
use alloy_sol_types::{SolType, SolValue};
use clap::{Args, Subcommand, ValueEnum};
use commonware_cryptography::{Hasher, Keccak256, keccak256};
use commonware_storage::merkle::{
    Bagging, Family, Location, Proof, hasher::Standard, mem::Mem, mmb, mmr,
};

mod multi;

type Uint256 = <sol!(uint256) as SolType>::RustType;
type Digest = keccak256::Digest;
type MerkleHasher = Standard<Keccak256>;

sol! {
    struct RangeOutput {
        bytes32 root;
        bytes32[] elements;
        bytes32[] proof;
        uint256 leaves;
    }

    struct RangeInput {
        bytes32 root;
        uint256 leaves;
        uint256 start;
        bytes32[] elements;
        bytes32[] proof;
    }
}

struct Output {
    root: Digest,
    elements: Vec<[u8; 32]>,
    proof: Vec<Digest>,
    leaves: u64,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Build a complete tree and return a range proof.
    Generate {
        #[arg(value_enum)]
        kind: TreeKind,
        #[command(flatten)]
        range: RangeArgs,
    },
    /// Reconstruct a root from deterministic siblings without building the tree.
    Synthetic {
        #[arg(value_enum)]
        kind: TreeKind,
        #[command(flatten)]
        range: RangeArgs,
    },
    /// Verify an ABI-encoded (root, leaves, start, elements, proof) tuple.
    Check {
        #[arg(value_enum)]
        kind: TreeKind,
        abi_hex: String,
        #[command(flatten)]
        policy: Policy,
    },
    /// Build a complete tree and return a sparse multiproof.
    GenerateMulti {
        #[arg(value_enum)]
        kind: TreeKind,
        #[command(flatten)]
        args: multi::MultiArgs,
    },
    /// Build only the selected paths and return a deep sparse multiproof.
    SyntheticMulti {
        #[arg(value_enum)]
        kind: TreeKind,
        #[command(flatten)]
        args: multi::MultiArgs,
    },
    /// Verify an ABI-encoded sparse multiproof tuple.
    CheckMulti {
        #[arg(value_enum)]
        kind: TreeKind,
        abi_hex: String,
        #[command(flatten)]
        policy: Policy,
    },
    /// Shorthand for `generate mmr`.
    Mmr(RangeArgs),
    /// Shorthand for `generate mmb`.
    Mmb(RangeArgs),
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum TreeKind {
    Mmr,
    Mmb,
}

#[derive(Clone, Copy, Default, ValueEnum)]
enum Fold {
    #[default]
    Forward,
    Backward,
}

#[derive(Args, Clone, Copy, Default)]
pub(crate) struct Policy {
    #[arg(long, value_enum, default_value = "forward")]
    bagging: Fold,
    #[arg(long, default_value_t = 0)]
    inactive_peaks: usize,
}

impl Policy {
    const fn hasher(self) -> MerkleHasher {
        MerkleHasher::new(match self.bagging {
            Fold::Forward => Bagging::ForwardFold,
            Fold::Backward => Bagging::BackwardFold,
        })
    }
}

#[derive(Args)]
pub(crate) struct RangeArgs {
    leaf_count: u64,
    start: u64,
    length: u64,
    seed: u64,
    /// Check rejection of mutated roots, elements, and proof digests.
    /// Synthetic generation always performs these checks.
    #[arg(long)]
    check_mutated: bool,
    #[command(flatten)]
    policy: Policy,
}

/// Raw elements are deterministic across tree families and generation modes.
pub(super) fn leaf(seed: u64, index: u64) -> [u8; 32] {
    Keccak256::hash(&[&seed.to_be_bytes(), &index.to_be_bytes()]).0
}

/// Builds the full seed-derived tree and verifies its canonical range proof.
fn generate<F: Family>(
    leaf_count: u64,
    start: u64,
    length: u64,
    seed: u64,
    check_mutated: bool,
    policy: Policy,
) -> Result<Output, String> {
    if leaf_count > *F::MAX_LEAVES || leaf_count > 1_000_000 {
        return Err("materialized generation requires at most 1000000 leaves; use synthetic for larger trees".into());
    }
    let end = start
        .checked_add(length)
        .ok_or_else(|| "start + length overflows u64".to_owned())?;
    if length == 0 {
        return Err("length must be non-zero".to_owned());
    }
    if end > leaf_count {
        return Err(format!(
            "range [{start}, {end}) exceeds leaf count {leaf_count}"
        ));
    }

    let hasher = policy.hasher();
    let tree = materialize::<F>(leaf_count, seed, &hasher)?;

    let root = tree
        .root(&hasher, policy.inactive_peaks)
        .map_err(|error| format!("failed to compute root: {error}"))?;
    let proof = tree
        .range_proof(
            &hasher,
            Location::new(start)..Location::new(end),
            policy.inactive_peaks,
        )
        .map_err(|error| format!("failed to generate proof: {error}"))?;
    let elements: Vec<_> = (start..end).map(|index| leaf(seed, index)).collect();

    if !proof.verify_range_inclusion(&hasher, &elements, Location::new(start), &root) {
        return Err("Commonware rejected its generated proof".to_owned());
    }

    if check_mutated {
        check_rejections(&hasher, &proof, &elements, start, root)?;
    }

    Ok(Output {
        root,
        elements,
        proof: proof.digests,
        leaves: leaf_count,
    })
}

fn materialize<F: Family>(
    leaf_count: u64,
    seed: u64,
    hasher: &MerkleHasher,
) -> Result<Mem<F, Digest>, String> {
    if leaf_count > *F::MAX_LEAVES || leaf_count > 1_000_000 {
        return Err("materialized generation requires at most 1000000 leaves".into());
    }
    let mut tree = Mem::<F, Digest>::new();
    let batch = {
        let mut batch = tree.new_batch();
        for index in 0..leaf_count {
            batch = batch.add(hasher, &leaf(seed, index));
        }
        batch.merkleize(&tree, hasher)
    };
    tree.apply_batch(&batch)
        .map_err(|error| format!("failed to construct tree: {error}"))?;
    Ok(tree)
}

fn check_rejections<F: Family>(
    hasher: &MerkleHasher,
    proof: &Proof<F, Digest>,
    elements: &[[u8; 32]],
    start: u64,
    root: Digest,
) -> Result<(), String> {
    let mut bad_root = root;
    bad_root.0[0] ^= 1;
    if proof.verify_range_inclusion(hasher, elements, Location::new(start), &bad_root) {
        return Err("proof unexpectedly accepted a mutated root".to_owned());
    }

    let mut bad_elements = elements.to_vec();
    bad_elements[0][0] ^= 1;
    if proof.verify_range_inclusion(hasher, &bad_elements, Location::new(start), &root) {
        return Err("proof unexpectedly accepted a mutated element".to_owned());
    }

    if !proof.digests.is_empty() {
        let mut bad_proof = proof.clone();
        bad_proof.digests[0].0[0] ^= 1;
        if bad_proof.verify_range_inclusion(hasher, elements, Location::new(start), &root) {
            return Err("proof unexpectedly accepted a mutated proof digest".to_owned());
        }
    }
    Ok(())
}

/// Finds the canonical proof length using Commonware's root reconstruction.
/// Sibling digests are arbitrary deterministic values, so the resulting root
/// commits to these subtrees rather than to the full seed-derived tree.
fn synthetic<F: Family>(
    leaves: u64,
    start: u64,
    length: u64,
    seed: u64,
    policy: Policy,
) -> Result<Output, String> {
    let end = start.checked_add(length).ok_or("range overflow")?;
    if leaves > *F::MAX_LEAVES || length == 0 || end > leaves || length > 4096 {
        return Err("invalid synthetic range (maximum 4096 elements)".into());
    }
    let hasher = policy.hasher();
    let elements: Vec<_> = (start..end).map(|index| leaf(seed, index)).collect();
    let mut proof = Proof::<F, Digest> {
        leaves: Location::new(leaves),
        inactive_peaks: policy.inactive_peaks,
        digests: Vec::new(),
    };
    // Reconstruction enforces Commonware's canonical proof length. A contiguous range has
    // at most two boundary paths plus the peaks outside it, each bounded by 64 levels.
    for count in 0..=192 {
        if let Ok(root) = proof.reconstruct_root(&hasher, &elements, Location::new(start)) {
            if !proof.verify_range_inclusion(&hasher, &elements, Location::new(start), &root) {
                return Err("Commonware rejected reconstructed proof".into());
            }
            check_rejections(&hasher, &proof, &elements, start, root)?;
            return Ok(Output {
                root,
                elements,
                proof: proof.digests,
                leaves,
            });
        }
        proof
            .digests
            .push(keccak256::Digest(leaf(seed ^ u64::MAX, count)));
    }
    Err("no canonical synthetic proof length found".into())
}

/// Reads an ABI integer only if its upper 192 bits are zero.
fn abi_u64(encoded: &[u8], offset: usize) -> Option<u64> {
    <sol!(uint256)>::abi_decode(encoded.get(offset..offset.checked_add(32)?)?)
        .ok()?
        .try_into()
        .ok()
}

fn abi_array(encoded: &[u8], head_offset: usize) -> Option<Vec<[u8; 32]>> {
    let offset = usize::try_from(abi_u64(encoded, head_offset)?).ok()?;
    if offset < 160 || !offset.is_multiple_of(32) {
        return None;
    }
    let length = usize::try_from(abi_u64(encoded, offset)?).ok()?;
    let start = offset.checked_add(32)?;
    let end = start.checked_add(length.checked_mul(32)?)?;
    Some(encoded.get(start..end)?.as_chunks::<32>().0.to_vec())
}

/// Verifies `(root, leaves, start, elements, proof)` under the selected policy.
/// Malformed ABI fields and values outside the family domain return false.
fn check<F: Family>(encoded: &[u8], policy: Policy) -> bool {
    let Some(leaves) = abi_u64(encoded, 32) else {
        return false;
    };
    let Some(start) = abi_u64(encoded, 64) else {
        return false;
    };
    if leaves > *F::MAX_LEAVES || start > leaves {
        return false;
    }
    let Some(elements) = abi_array(encoded, 96) else {
        return false;
    };
    let Some(digests) = abi_array(encoded, 128) else {
        return false;
    };
    if elements.len() as u64 > leaves - start {
        return false;
    }
    let Some(root) = encoded.get(..32) else {
        return false;
    };
    let proof = Proof::<F, Digest> {
        leaves: Location::new(leaves),
        inactive_peaks: policy.inactive_peaks,
        digests: digests.into_iter().map(keccak256::Digest).collect(),
    };
    proof.verify_range_inclusion(
        &policy.hasher(),
        &elements,
        Location::new(start),
        &keccak256::Digest(root.try_into().unwrap()),
    )
}

/// Encodes `(root, elements, proof, leaves)` for Solidity FFI callers.
fn abi_encode(output: &Output) -> Vec<u8> {
    RangeOutput {
        root: output.root.0.into(),
        elements: output.elements.iter().copied().map(Into::into).collect(),
        proof: output.proof.iter().map(|digest| digest.0.into()).collect(),
        leaves: Uint256::from(output.leaves),
    }
    .abi_encode_params()
}

impl RangeArgs {
    fn generate<F: Family>(&self, synthetic_mode: bool) -> Result<Output, String> {
        if synthetic_mode {
            synthetic::<F>(
                self.leaf_count,
                self.start,
                self.length,
                self.seed,
                self.policy,
            )
        } else {
            generate::<F>(
                self.leaf_count,
                self.start,
                self.length,
                self.seed,
                self.check_mutated,
                self.policy,
            )
        }
    }
}

impl Command {
    pub(crate) fn execute(self) -> Result<Vec<u8>, String> {
        let multi_check = matches!(&self, Self::CheckMulti { .. });
        let (kind, range, synthetic_mode) = match self {
            Self::Check {
                kind,
                abi_hex,
                policy,
            }
            | Self::CheckMulti {
                kind,
                abi_hex,
                policy,
            } => {
                let encoded = const_hex::decode(abi_hex.strip_prefix("0x").unwrap_or(&abi_hex))
                    .map_err(|error| format!("invalid ABI hex: {error}"))?;
                let accepted = match kind {
                    TreeKind::Mmr => {
                        if multi_check {
                            multi::check::<mmr::Family>(&encoded, policy)
                        } else {
                            check::<mmr::Family>(&encoded, policy)
                        }
                    }
                    TreeKind::Mmb => {
                        if multi_check {
                            multi::check::<mmb::Family>(&encoded, policy)
                        } else {
                            check::<mmb::Family>(&encoded, policy)
                        }
                    }
                };
                return Ok(accepted.abi_encode());
            }
            Self::GenerateMulti { kind, args } => return args.execute(kind, false),
            Self::SyntheticMulti { kind, args } => return args.execute(kind, true),
            Self::Generate { kind, range } => (kind, range, false),
            Self::Synthetic { kind, range } => (kind, range, true),
            Self::Mmr(range) => (TreeKind::Mmr, range, false),
            Self::Mmb(range) => (TreeKind::Mmb, range, false),
        };
        let output = match kind {
            TreeKind::Mmr => range.generate::<mmr::Family>(synthetic_mode)?,
            TreeKind::Mmb => range.generate::<mmb::Family>(synthetic_mode)?,
        };
        Ok(abi_encode(&output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Cli;
    use clap::Parser;

    #[test]
    fn cli_preserves_generation_forms_and_check_encoding() {
        use clap::CommandFactory;

        Cli::command().debug_assert();
        for kind in ["mmr", "mmb"] {
            for mode in ["generate", "synthetic"] {
                let explicit = Cli::try_parse_from([
                    "commonware-sol-fuzz",
                    "merkle",
                    mode,
                    kind,
                    "11",
                    "2",
                    "6",
                    "42",
                    "--check-mutated",
                ])
                .unwrap()
                .command
                .execute()
                .unwrap();
                let expected = match (kind, mode) {
                    ("mmr", "generate") => {
                        generate::<mmr::Family>(11, 2, 6, 42, true, Policy::default())
                    }
                    ("mmb", "generate") => {
                        generate::<mmb::Family>(11, 2, 6, 42, true, Policy::default())
                    }
                    ("mmr", _) => synthetic::<mmr::Family>(11, 2, 6, 42, Policy::default()),
                    ("mmb", _) => synthetic::<mmb::Family>(11, 2, 6, 42, Policy::default()),
                    _ => unreachable!(),
                }
                .unwrap();
                assert_eq!(explicit, abi_encode(&expected));
                if mode == "generate" {
                    let shorthand = Cli::try_parse_from([
                        "commonware-sol-fuzz",
                        "merkle",
                        kind,
                        "11",
                        "2",
                        "6",
                        "42",
                        "--check-mutated",
                    ])
                    .unwrap()
                    .command
                    .execute()
                    .unwrap();
                    assert_eq!(shorthand, explicit);
                }
                let input = const_hex::encode(check_input(&expected, 2));
                for hex in [input.clone(), format!("0x{input}")] {
                    let accepted =
                        Cli::try_parse_from(["commonware-sol-fuzz", "merkle", "check", kind, &hex])
                            .unwrap()
                            .command
                            .execute()
                            .unwrap();
                    assert_eq!(accepted, 1u64.abi_encode());
                }
            }
        }
    }

    #[test]
    fn generates_and_checks_all_modes() {
        for check_mutated in [false, true] {
            let mmr_single =
                generate::<mmr::Family>(11, 8, 1, 7, check_mutated, Policy::default()).unwrap();
            let mmr_range =
                generate::<mmr::Family>(11, 2, 6, 7, check_mutated, Policy::default()).unwrap();
            let mmb_single =
                generate::<mmb::Family>(11, 8, 1, 7, check_mutated, Policy::default()).unwrap();
            let mmb_range =
                generate::<mmb::Family>(11, 2, 6, 7, check_mutated, Policy::default()).unwrap();
            assert_eq!(mmr_single.leaves, 11);
            assert_eq!(mmr_range.leaves, 11);
            assert_eq!(mmb_single.leaves, 11);
            assert_eq!(mmb_range.leaves, 11);
        }
    }

    fn check_input(output: &Output, start: u64) -> Vec<u8> {
        RangeInput {
            root: output.root.0.into(),
            leaves: Uint256::from(output.leaves),
            start: Uint256::from(start),
            elements: output.elements.iter().copied().map(Into::into).collect(),
            proof: output.proof.iter().map(|digest| digest.0.into()).collect(),
        }
        .abi_encode_params()
    }

    fn submitted_mutations<F: Family>() {
        let output = generate::<F>(11, 2, 6, 42, true, Policy::default()).unwrap();
        let encoded = check_input(&output, 2);
        assert!(check::<F>(&encoded, Policy::default()));
        let proof_offset = abi_u64(&encoded, 128).unwrap() as usize;
        for index in [0, 63, 95, 192, proof_offset + 32] {
            let mut changed = encoded.clone();
            changed[index] ^= 1;
            assert!(
                !check::<F>(&changed, Policy::default()),
                "accepted mutation at byte {index}"
            );
        }
        let mut excessive_leaves = encoded.clone();
        excessive_leaves[32] = 1;
        assert!(!check::<F>(&excessive_leaves, Policy::default()));
        assert!(!check::<F>(
            &encoded[..encoded.len() - 32],
            Policy::default()
        ));
        let mut extra_digest = encoded;
        extra_digest[proof_offset..proof_offset + 32]
            .copy_from_slice(&(output.proof.len() as u64 + 1).abi_encode());
        extra_digest.extend_from_slice(&[0; 32]);
        assert!(!check::<F>(&extra_digest, Policy::default()));
    }

    #[test]
    fn checks_submitted_mutations() {
        submitted_mutations::<mmr::Family>();
        submitted_mutations::<mmb::Family>();
    }

    fn empty_tree<F: Family>() {
        let mut output = Output {
            root: Keccak256::hash(&[&0u64.to_be_bytes()]),
            elements: Vec::new(),
            proof: Vec::new(),
            leaves: 0,
        };
        assert!(check::<F>(&check_input(&output, 0), Policy::default()));
        assert!(!check::<F>(&check_input(&output, 1), Policy::default()));
        output.leaves = 1;
        assert!(!check::<F>(&check_input(&output, 0), Policy::default()));
        output.leaves = 0;
        output.root.0[0] ^= 1;
        assert!(!check::<F>(&check_input(&output, 0), Policy::default()));
        output.root.0[0] ^= 1;
        output.proof.push(keccak256::Digest([0; 32]));
        assert!(!check::<F>(&check_input(&output, 0), Policy::default()));
    }

    #[test]
    fn checks_empty_tree_and_rejects_invalid_empty_proofs() {
        empty_tree::<mmr::Family>();
        empty_tree::<mmb::Family>();
    }

    fn high_sizes<F: Family>() {
        for leaves in [1 << 62, *F::MAX_LEAVES - 1, *F::MAX_LEAVES] {
            for (start, length) in [(0, 1), (leaves / 2 - 1, 3), (leaves - 1, 1)] {
                let output = synthetic::<F>(leaves, start, length, 42, Policy::default()).unwrap();
                assert!(check::<F>(&check_input(&output, start), Policy::default()));
            }
        }
    }

    #[test]
    fn reconstructs_maximum_size_proofs() {
        high_sizes::<mmr::Family>();
        high_sizes::<mmb::Family>();
    }

    fn range_policies<F: Family>() {
        for leaves in [3, 7, 11, 31] {
            let peak_count = F::peaks(F::location_to_position(Location::new(leaves))).count();
            for bagging in [Fold::Forward, Fold::Backward] {
                for inactive_peaks in 0..=peak_count {
                    let policy = Policy {
                        bagging,
                        inactive_peaks,
                    };
                    for (start, length) in [(0, 1), (leaves / 2, 2), (leaves - 1, 1), (0, leaves)] {
                        for output in [
                            generate::<F>(leaves, start, length, 42, true, policy).unwrap(),
                            synthetic::<F>(leaves, start, length, 42, policy).unwrap(),
                        ] {
                            let encoded = check_input(&output, start);
                            assert!(check::<F>(&encoded, policy));
                            let wrong = Policy {
                                inactive_peaks: (inactive_peaks + 1) % (peak_count + 1),
                                ..policy
                            };
                            assert!(!check::<F>(&encoded, wrong));
                        }
                    }
                }
            }
        }
        let leaves = *F::MAX_LEAVES;
        let peak_count = F::peaks(F::location_to_position(Location::new(leaves))).count();
        for inactive_peaks in [0, 1, peak_count] {
            let policy = Policy {
                bagging: Fold::Backward,
                inactive_peaks,
            };
            for start in [0, leaves / 2, leaves - 1] {
                let output = synthetic::<F>(leaves, start, 1, 42, policy).unwrap();
                assert!(check::<F>(&check_input(&output, start), policy));
            }
        }
    }

    #[test]
    fn range_proofs_cover_policies_and_boundary_commitments() {
        range_policies::<mmr::Family>();
        range_policies::<mmb::Family>();
    }

    #[test]
    fn abi_tuple_offsets_are_canonical() {
        let output = generate::<mmr::Family>(3, 1, 1, 99, false, Policy::default()).unwrap();
        let encoded = abi_encode(&output);
        assert_eq!(&encoded[32..64], &128u64.abi_encode());
        assert_eq!(&encoded[128..160], &1u64.abi_encode());
        assert_eq!(encoded.len() % 32, 0);
        assert_eq!(&encoded[96..128], &3u64.abi_encode());
    }
}
