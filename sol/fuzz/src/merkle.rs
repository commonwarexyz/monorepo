//! Commonware proof oracle for the Solidity differential tests.
//!
//! Commands emit a single hex-encoded ABI value. Tree construction, proof layout,
//! and verification belong to Commonware. This binary adapts command-line inputs and ABI I/O.

use crate::Hash;
use alloy_sol_macro::sol;
use alloy_sol_types::{SolType, SolValue, abi::AbiDecoderConfig};
use clap::{Args, Subcommand, ValueEnum};
use commonware_codec::{Copying, DecodeExt};
use commonware_cryptography::{Hasher, Keccak256, Sha256, keccak256};
use commonware_storage::merkle::{
    Bagging, Family, Location, Proof, hasher::Standard, mem::Mem, mmb, mmr,
};

mod multi;

type Uint256 = <sol!(uint256) as SolType>::RustType;
type Digest = keccak256::Digest;
type MerkleHasher<H> = Standard<H>;

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
    root: [u8; 32],
    elements: Vec<[u8; 32]>,
    proof: Vec<[u8; 32]>,
    leaves: u64,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Build a complete tree and return a range proof.
    Generate {
        #[arg(long, value_enum)]
        kind: TreeKind,
        #[command(flatten)]
        range: RangeArgs,
    },
    /// Reconstruct a root from deterministic siblings without building the tree.
    Synthetic {
        #[arg(long, value_enum)]
        kind: TreeKind,
        #[command(flatten)]
        range: RangeArgs,
    },
    /// Verify an ABI-encoded (root, leaves, start, elements, proof) tuple.
    Check {
        #[arg(long, value_enum)]
        kind: TreeKind,
        #[arg(long)]
        abi_hex: String,
        #[command(flatten)]
        policy: Policy,
    },
    /// Build a complete tree and return a sparse multiproof.
    GenerateMulti {
        #[arg(long, value_enum)]
        kind: TreeKind,
        #[command(flatten)]
        args: multi::MultiArgs,
    },
    /// Build only the selected paths and return a deep sparse multiproof.
    SyntheticMulti {
        #[arg(long, value_enum)]
        kind: TreeKind,
        #[command(flatten)]
        args: multi::MultiArgs,
    },
    /// Verify an ABI-encoded sparse multiproof tuple.
    CheckMulti {
        #[arg(long, value_enum)]
        kind: TreeKind,
        #[arg(long)]
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
    const fn hasher<H: Hasher>(self) -> MerkleHasher<H> {
        MerkleHasher::new(match self.bagging {
            Fold::Forward => Bagging::ForwardFold,
            Fold::Backward => Bagging::BackwardFold,
        })
    }
}

#[derive(Args)]
pub(crate) struct RangeArgs {
    #[arg(long)]
    leaf_count: u64,
    #[arg(long)]
    start: u64,
    #[arg(long)]
    length: u64,
    #[arg(long)]
    seed: u64,
    /// Check rejection of mutated roots, elements, and proof digests.
    /// Synthetic generation always performs these checks.
    #[arg(long)]
    check_mutated: bool,
    #[command(flatten)]
    policy: Policy,
}

/// Raw elements are deterministic across tree families, hash functions, and generation modes.
pub(super) fn leaf(seed: u64, index: u64) -> [u8; 32] {
    Keccak256::hash(&[&seed.to_be_bytes(), &index.to_be_bytes()]).0
}

/// Builds the full seed-derived tree and verifies its canonical range proof.
fn generate<F: Family, H: Hasher>(
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

    let hasher = policy.hasher::<H>();
    let tree = materialize::<F, H>(leaf_count, seed, &hasher)?;

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
        check_rejections::<F, H>(&hasher, &proof, &elements, start, root)?;
    }

    Ok(Output {
        root: root.as_ref().try_into().unwrap(),
        elements,
        proof: proof
            .digests
            .iter()
            .map(|d| d.as_ref().try_into().unwrap())
            .collect(),
        leaves: leaf_count,
    })
}

fn materialize<F: Family, H: Hasher>(
    leaf_count: u64,
    seed: u64,
    hasher: &MerkleHasher<H>,
) -> Result<Mem<F, H::Digest>, String> {
    if leaf_count > *F::MAX_LEAVES || leaf_count > 1_000_000 {
        return Err("materialized generation requires at most 1000000 leaves".into());
    }
    let mut tree = Mem::<F, H::Digest>::new();
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

fn check_rejections<F: Family, H: Hasher>(
    hasher: &MerkleHasher<H>,
    proof: &Proof<F, H::Digest>,
    elements: &[[u8; 32]],
    start: u64,
    root: H::Digest,
) -> Result<(), String> {
    let mut bytes = root.as_ref().to_vec();
    bytes[0] ^= 1;
    let bad_root = H::Digest::decode(Copying(bytes.as_slice())).unwrap();
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
        let mut bytes = bad_proof.digests[0].as_ref().to_vec();
        bytes[0] ^= 1;
        bad_proof.digests[0] = H::Digest::decode(Copying(bytes.as_slice())).unwrap();
        if bad_proof.verify_range_inclusion(hasher, elements, Location::new(start), &root) {
            return Err("proof unexpectedly accepted a mutated proof digest".to_owned());
        }
    }
    Ok(())
}

/// Finds the canonical proof length using Commonware's root reconstruction.
/// Sibling digests are arbitrary deterministic values, so the resulting root
/// commits to these subtrees rather than to the full seed-derived tree.
fn synthetic<F: Family, H: Hasher>(
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
    let hasher = policy.hasher::<H>();
    let elements: Vec<_> = (start..end).map(|index| leaf(seed, index)).collect();
    let mut proof = Proof::<F, H::Digest> {
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
            check_rejections::<F, H>(&hasher, &proof, &elements, start, root)?;
            return Ok(Output {
                root: root.as_ref().try_into().unwrap(),
                elements,
                proof: proof
                    .digests
                    .iter()
                    .map(|d| d.as_ref().try_into().unwrap())
                    .collect(),
                leaves,
            });
        }
        proof
            .digests
            .push(H::Digest::decode(Copying(leaf(seed ^ u64::MAX, count).as_slice())).unwrap());
    }
    Err("no canonical synthetic proof length found".into())
}

/// Reads an ABI integer only if its upper 192 bits are zero.
#[cfg(test)]
fn abi_u64(encoded: &[u8], offset: usize) -> Option<u64> {
    <sol!(uint256)>::abi_decode(encoded.get(offset..offset.checked_add(32)?)?)
        .ok()?
        .try_into()
        .ok()
}

/// Verifies a canonical ABI `(root, leaves, start, elements, proof)` tuple under the selected policy.
/// Malformed ABI fields and values outside the family domain return false.
fn check<F: Family, H: Hasher>(encoded: &[u8], policy: Policy) -> bool {
    let Ok(payload) = <RangeInput as SolValue>::abi_decode_params_with_config(
        encoded,
        AbiDecoderConfig::new().strict(true),
    ) else {
        return false;
    };
    let Ok(leaves) = u64::try_from(payload.leaves) else {
        return false;
    };
    let Ok(start) = u64::try_from(payload.start) else {
        return false;
    };
    if leaves > *F::MAX_LEAVES || start > leaves {
        return false;
    }
    if payload.elements.len() as u64 > leaves - start {
        return false;
    }
    let proof = Proof::<F, H::Digest> {
        leaves: Location::new(leaves),
        inactive_peaks: policy.inactive_peaks,
        digests: payload
            .proof
            .into_iter()
            .map(|d| H::Digest::decode(Copying(d.as_slice())).unwrap())
            .collect(),
    };
    proof.verify_range_inclusion(
        &policy.hasher::<H>(),
        &payload.elements,
        Location::new(start),
        &H::Digest::decode(Copying(payload.root.as_slice())).unwrap(),
    )
}

/// Encodes `(root, elements, proof, leaves)` for Solidity FFI callers.
fn abi_encode(output: &Output) -> Vec<u8> {
    RangeOutput {
        root: output.root.into(),
        elements: output.elements.iter().copied().map(Into::into).collect(),
        proof: output.proof.iter().map(|digest| (*digest).into()).collect(),
        leaves: Uint256::from(output.leaves),
    }
    .abi_encode_params()
}

impl RangeArgs {
    fn generate<F: Family, H: Hasher>(&self, synthetic_mode: bool) -> Result<Output, String> {
        if synthetic_mode {
            synthetic::<F, H>(
                self.leaf_count,
                self.start,
                self.length,
                self.seed,
                self.policy,
            )
        } else {
            generate::<F, H>(
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
    pub(crate) fn execute(self, hash: Hash) -> Result<Vec<u8>, String> {
        match hash {
            Hash::Keccak => self.execute_with::<Keccak256>(),
            Hash::Sha256 => self.execute_with::<Sha256>(),
        }
    }

    fn execute_with<H: Hasher>(self) -> Result<Vec<u8>, String> {
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
                            multi::check::<mmr::Family, H>(&encoded, policy)
                        } else {
                            check::<mmr::Family, H>(&encoded, policy)
                        }
                    }
                    TreeKind::Mmb => {
                        if multi_check {
                            multi::check::<mmb::Family, H>(&encoded, policy)
                        } else {
                            check::<mmb::Family, H>(&encoded, policy)
                        }
                    }
                };
                return Ok(accepted.abi_encode());
            }
            Self::GenerateMulti { kind, args } => return args.execute::<H>(kind, false),
            Self::SyntheticMulti { kind, args } => return args.execute::<H>(kind, true),
            Self::Generate { kind, range } => (kind, range, false),
            Self::Synthetic { kind, range } => (kind, range, true),
            Self::Mmr(range) => (TreeKind::Mmr, range, false),
            Self::Mmb(range) => (TreeKind::Mmb, range, false),
        };
        let output = match kind {
            TreeKind::Mmr => range.generate::<mmr::Family, H>(synthetic_mode)?,
            TreeKind::Mmb => range.generate::<mmb::Family, H>(synthetic_mode)?,
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
                    "--hash",
                    "keccak",
                    mode,
                    "--kind",
                    kind,
                    "--leaf-count",
                    "11",
                    "--start",
                    "2",
                    "--length",
                    "6",
                    "--seed",
                    "42",
                    "--check-mutated",
                ])
                .unwrap()
                .command
                .execute()
                .unwrap();
                let expected = match (kind, mode) {
                    ("mmr", "generate") => {
                        generate::<mmr::Family, Keccak256>(11, 2, 6, 42, true, Policy::default())
                    }
                    ("mmb", "generate") => {
                        generate::<mmb::Family, Keccak256>(11, 2, 6, 42, true, Policy::default())
                    }
                    ("mmr", _) => {
                        synthetic::<mmr::Family, Keccak256>(11, 2, 6, 42, Policy::default())
                    }
                    ("mmb", _) => {
                        synthetic::<mmb::Family, Keccak256>(11, 2, 6, 42, Policy::default())
                    }
                    _ => unreachable!(),
                }
                .unwrap();
                assert_eq!(explicit, abi_encode(&expected));
                if mode == "generate" {
                    let shorthand = Cli::try_parse_from([
                        "commonware-sol-fuzz",
                        "merkle",
                        "--hash",
                        "keccak",
                        kind,
                        "--leaf-count",
                        "11",
                        "--start",
                        "2",
                        "--length",
                        "6",
                        "--seed",
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
                    let accepted = Cli::try_parse_from([
                        "commonware-sol-fuzz",
                        "merkle",
                        "--hash",
                        "keccak",
                        "check",
                        "--kind",
                        kind,
                        "--abi-hex",
                        &hex,
                    ])
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
    fn cli_requires_valid_hash() {
        for args in [
            vec![
                "generate",
                "--kind",
                "mmr",
                "--leaf-count",
                "11",
                "--start",
                "2",
                "--length",
                "6",
                "--seed",
                "42",
            ],
            vec![
                "synthetic",
                "--kind",
                "mmb",
                "--leaf-count",
                "11",
                "--start",
                "2",
                "--length",
                "6",
                "--seed",
                "42",
            ],
            vec!["check", "--kind", "mmr", "--abi-hex", "00"],
            vec![
                "generate-multi",
                "--kind",
                "mmb",
                "--leaf-count",
                "11",
                "--locations",
                "2",
                "--seed",
                "42",
            ],
            vec![
                "synthetic-multi",
                "--kind",
                "mmr",
                "--leaf-count",
                "11",
                "--locations",
                "2",
                "--seed",
                "42",
            ],
            vec!["check-multi", "--kind", "mmb", "--abi-hex", "00"],
            vec![
                "mmr",
                "--leaf-count",
                "11",
                "--start",
                "2",
                "--length",
                "6",
                "--seed",
                "42",
            ],
            vec![
                "mmb",
                "--leaf-count",
                "11",
                "--start",
                "2",
                "--length",
                "6",
                "--seed",
                "42",
            ],
        ] {
            assert!(Cli::try_parse_from(["fuzz", "merkle"].into_iter().chain(args)).is_err());
        }
        assert!(
            Cli::try_parse_from([
                "fuzz",
                "merkle",
                "--hash",
                "blake3",
                "generate",
                "--kind",
                "mmr",
                "--leaf-count",
                "11",
                "--start",
                "2",
                "--length",
                "6",
                "--seed",
                "42",
            ])
            .is_err()
        );
    }

    #[test]
    fn generates_and_checks_all_modes() {
        generates_and_checks_all_modes_with::<Keccak256>();
        generates_and_checks_all_modes_with::<Sha256>();
    }

    fn generates_and_checks_all_modes_with<H: Hasher>() {
        for check_mutated in [false, true] {
            let mmr_single =
                generate::<mmr::Family, H>(11, 8, 1, 7, check_mutated, Policy::default()).unwrap();
            let mmr_range =
                generate::<mmr::Family, H>(11, 2, 6, 7, check_mutated, Policy::default()).unwrap();
            let mmb_single =
                generate::<mmb::Family, H>(11, 8, 1, 7, check_mutated, Policy::default()).unwrap();
            let mmb_range =
                generate::<mmb::Family, H>(11, 2, 6, 7, check_mutated, Policy::default()).unwrap();
            assert_eq!(mmr_single.leaves, 11);
            assert_eq!(mmr_range.leaves, 11);
            assert_eq!(mmb_single.leaves, 11);
            assert_eq!(mmb_range.leaves, 11);
        }
    }

    fn check_input(output: &Output, start: u64) -> Vec<u8> {
        RangeInput {
            root: output.root.into(),
            leaves: Uint256::from(output.leaves),
            start: Uint256::from(start),
            elements: output.elements.iter().copied().map(Into::into).collect(),
            proof: output.proof.iter().map(|digest| (*digest).into()).collect(),
        }
        .abi_encode_params()
    }

    fn submitted_mutations<F: Family, H: Hasher>() {
        let output = generate::<F, H>(11, 2, 6, 42, true, Policy::default()).unwrap();
        let encoded = check_input(&output, 2);
        assert!(check::<F, H>(&encoded, Policy::default()));
        let proof_offset = abi_u64(&encoded, 128).unwrap() as usize;
        for index in [0, 63, 95, 192, proof_offset + 32] {
            let mut changed = encoded.clone();
            changed[index] ^= 1;
            assert!(
                !check::<F, H>(&changed, Policy::default()),
                "accepted mutation at byte {index}"
            );
        }
        let mut excessive_leaves = encoded.clone();
        excessive_leaves[32] = 1;
        assert!(!check::<F, H>(&excessive_leaves, Policy::default()));
        assert!(!check::<F, H>(
            &encoded[..encoded.len() - 32],
            Policy::default()
        ));
        let mut extra_digest = encoded;
        extra_digest[proof_offset..proof_offset + 32]
            .copy_from_slice(&(output.proof.len() as u64 + 1).abi_encode());
        extra_digest.extend_from_slice(&[0; 32]);
        assert!(!check::<F, H>(&extra_digest, Policy::default()));
    }

    #[test]
    fn checks_submitted_mutations() {
        checks_submitted_mutations_with::<Keccak256>();
        checks_submitted_mutations_with::<Sha256>();
    }

    fn checks_submitted_mutations_with<H: Hasher>() {
        submitted_mutations::<mmr::Family, H>();
        submitted_mutations::<mmb::Family, H>();
    }

    fn empty_tree<F: Family, H: Hasher>() {
        let mut output = Output {
            root: H::hash(&[&0u64.to_be_bytes()]).as_ref().try_into().unwrap(),
            elements: Vec::new(),
            proof: Vec::new(),
            leaves: 0,
        };
        let encoded = check_input(&output, 0);
        assert!(check::<F, H>(&encoded, Policy::default()));
        let mut trailing = encoded.clone();
        trailing.extend_from_slice(&[0; 32]);
        let mut overlapping = encoded;
        overlapping.copy_within(96..128, 128);
        for malformed in [trailing, overlapping] {
            assert!(!check::<F, H>(&malformed, Policy::default()));
        }
        assert!(!check::<F, H>(&check_input(&output, 1), Policy::default()));
        output.leaves = 1;
        assert!(!check::<F, H>(&check_input(&output, 0), Policy::default()));
        output.leaves = 0;
        output.root[0] ^= 1;
        assert!(!check::<F, H>(&check_input(&output, 0), Policy::default()));
        output.root[0] ^= 1;
        output.proof.push([0; 32]);
        assert!(!check::<F, H>(&check_input(&output, 0), Policy::default()));
    }

    #[test]
    fn checks_empty_tree_and_rejects_invalid_empty_proofs() {
        checks_empty_tree_and_rejects_invalid_empty_proofs_with::<Keccak256>();
        checks_empty_tree_and_rejects_invalid_empty_proofs_with::<Sha256>();
    }

    fn checks_empty_tree_and_rejects_invalid_empty_proofs_with<H: Hasher>() {
        empty_tree::<mmr::Family, H>();
        empty_tree::<mmb::Family, H>();
    }

    fn high_sizes<F: Family, H: Hasher>() {
        for leaves in [1 << 62, *F::MAX_LEAVES - 1, *F::MAX_LEAVES] {
            for (start, length) in [(0, 1), (leaves / 2 - 1, 3), (leaves - 1, 1)] {
                let output =
                    synthetic::<F, H>(leaves, start, length, 42, Policy::default()).unwrap();
                assert!(check::<F, H>(
                    &check_input(&output, start),
                    Policy::default()
                ));
            }
        }
    }

    #[test]
    fn reconstructs_maximum_size_proofs() {
        reconstructs_maximum_size_proofs_with::<Keccak256>();
        reconstructs_maximum_size_proofs_with::<Sha256>();
    }

    fn reconstructs_maximum_size_proofs_with<H: Hasher>() {
        high_sizes::<mmr::Family, H>();
        high_sizes::<mmb::Family, H>();
    }

    fn range_policies<F: Family, H: Hasher>() {
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
                            generate::<F, H>(leaves, start, length, 42, true, policy).unwrap(),
                            synthetic::<F, H>(leaves, start, length, 42, policy).unwrap(),
                        ] {
                            let encoded = check_input(&output, start);
                            assert!(check::<F, H>(&encoded, policy));
                            let wrong = Policy {
                                inactive_peaks: (inactive_peaks + 1) % (peak_count + 1),
                                ..policy
                            };
                            assert!(!check::<F, H>(&encoded, wrong));
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
                let output = synthetic::<F, H>(leaves, start, 1, 42, policy).unwrap();
                assert!(check::<F, H>(&check_input(&output, start), policy));
            }
        }
    }

    #[test]
    fn range_proofs_cover_policies_and_boundary_commitments() {
        range_proofs_cover_policies_and_boundary_commitments_with::<Keccak256>();
        range_proofs_cover_policies_and_boundary_commitments_with::<Sha256>();
    }

    fn range_proofs_cover_policies_and_boundary_commitments_with<H: Hasher>() {
        range_policies::<mmr::Family, H>();
        range_policies::<mmb::Family, H>();
    }

    #[test]
    fn abi_tuple_offsets_are_canonical() {
        abi_tuple_offsets_are_canonical_with::<Keccak256>();
        abi_tuple_offsets_are_canonical_with::<Sha256>();
    }

    fn abi_tuple_offsets_are_canonical_with<H: Hasher>() {
        let output = generate::<mmr::Family, H>(3, 1, 1, 99, false, Policy::default()).unwrap();
        let encoded = abi_encode(&output);
        assert_eq!(&encoded[32..64], &128u64.abi_encode());
        assert_eq!(&encoded[128..160], &1u64.abi_encode());
        assert_eq!(encoded.len() % 32, 0);
        assert_eq!(&encoded[96..128], &3u64.abi_encode());
    }
    #[test]
    fn cli_hash_selection() {
        for kind in ["mmr", "mmb"] {
            for mode in ["generate", "synthetic", "shorthand"] {
                let mut outputs = Vec::new();
                for hash in ["keccak", "sha256"] {
                    let mut args = vec!["fuzz", "merkle", "--hash", hash];
                    if mode != "shorthand" {
                        args.extend([mode, "--kind"]);
                    }
                    args.extend([
                        kind,
                        "--leaf-count",
                        "11",
                        "--start",
                        "2",
                        "--length",
                        "6",
                        "--seed",
                        "42",
                    ]);
                    let encoded = Cli::try_parse_from(args)
                        .unwrap()
                        .command
                        .execute()
                        .unwrap();
                    let output =
                        <RangeOutput as SolValue>::abi_decode_params_validate(&encoded).unwrap();
                    let input = RangeInput {
                        root: output.root,
                        leaves: output.leaves,
                        start: Uint256::from(2),
                        elements: output.elements,
                        proof: output.proof,
                    }
                    .abi_encode_params();
                    let hex = const_hex::encode(input);
                    for check_hash in ["keccak", "sha256"] {
                        let accepted = Cli::try_parse_from([
                            "fuzz",
                            "merkle",
                            "--hash",
                            check_hash,
                            "check",
                            "--kind",
                            kind,
                            "--abi-hex",
                            &hex,
                        ])
                        .unwrap()
                        .command
                        .execute()
                        .unwrap();
                        assert_eq!(accepted, (hash == check_hash).abi_encode());
                    }
                    outputs.push(encoded);
                }
                assert_ne!(outputs[0], outputs[1]);
            }
        }
    }

    #[test]
    fn cli_requires_named_fields() {
        assert!(
            Cli::try_parse_from([
                "fuzz", "merkle", "--hash", "keccak", "generate", "mmr", "11", "2", "6", "42"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "fuzz",
                "merkle",
                "--hash",
                "keccak",
                "generate",
                "--kind",
                "mmr",
                "--leaf-count",
                "11",
                "--start",
                "2",
                "--length",
                "6"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "fuzz", "merkle", "--hash", "keccak", "check", "--kind", "mmr", "00"
            ])
            .is_err()
        );
    }
}
