//! Range and sparse QMDB fixtures verified by the production Rust proof APIs.
//!
//! Operations use production fixed and variable codecs. Current bitmaps are materialized test
//! inputs for grafting geometry; their status does not claim a database lifecycle.

use super::{
    Encoding, RootKind, TreeArgs, Uint256, VARIABLE_LENGTHS, key, materialize_current,
    materialize_ops, operation, with_chunk_bytes,
};
use crate::{
    Hash,
    merkle::{TreeKind, leaf, qmdb_positions},
};
use alloy_sol_macro::sol;
use alloy_sol_types::{SolType, SolValue};
use clap::{Args, ValueEnum};
use commonware_codec::Codec;
use commonware_cryptography::{Digest, Hasher, Keccak256, Sha256};
use commonware_storage::{
    merkle::{Bagging, Graftable, Location, PendingChunk as _, mem::Mem, mmb, mmr, verification},
    qmdb::{
        self,
        any::{
            ordered, unordered,
            value::{FixedEncoding, VariableEncoding},
        },
        current::proof::RangeProof,
        immutable, keyless,
    },
};
use commonware_utils::{bitmap::Prunable, sequence::FixedBytes};
use futures::executor::block_on;

type Bytes32 = <sol!(bytes32) as SolType>::RustType;
type Bytes = <sol!(bytes) as SolType>::RustType;

sol! {
    struct RangeOutput {
        bytes32 root;
        uint256 leaves;
        uint256 start;
        uint256 inactivePeaks;
        bytes32[] digests;
        bytes[] operations;
    }

    struct MultiOutput {
        bytes32 root;
        uint256 leaves;
        uint256[] locations;
        uint256 inactivePeaks;
        uint256[] positions;
        bytes32[] digests;
        bytes[] operations;
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum Variant {
    Ordered,
    Unordered,
    Keyless,
    Immutable,
}

#[derive(Clone, Copy, ValueEnum)]
enum Activity {
    All,
    Mixed,
    Zero,
}

#[derive(Args)]
struct Options {
    #[arg(long, value_enum)]
    family: TreeKind,
    #[arg(long, value_enum)]
    variant: Variant,
    /// Production operation codec; variable values span word and varint boundaries.
    #[arg(long, value_enum)]
    encoding: Encoding,
    /// Root authenticated by the proof; sparse Current proofs authenticate historical operations only.
    #[arg(long, value_enum)]
    root: RootKind,
    #[arg(long)]
    inactivity_floor: u64,
    /// Materialized Current activity; mixed has every third chunk zero and every third bit inactive.
    #[arg(long, value_enum, required_if_eq("root", "current"))]
    activity: Option<Activity>,
    /// Current activity bitmap chunk size in bytes.
    #[arg(long, required_if_eq("root", "current"))]
    chunk_bytes: Option<usize>,
}

#[derive(Args)]
pub(crate) struct RangeArgs {
    #[arg(long)]
    leaves: u64,
    #[arg(long)]
    start: u64,
    #[arg(long)]
    count: u64,
    #[arg(long)]
    seed: u64,
    #[command(flatten)]
    options: Options,
}

#[derive(Args)]
pub(crate) struct MultiArgs {
    #[arg(long)]
    leaves: u64,
    /// Comma-separated locations in caller order; duplicates must name identical operation bytes.
    #[arg(long, value_delimiter = ',', num_args = 1, required = true)]
    locations: Vec<u64>,
    #[arg(long)]
    seed: u64,
    #[command(flatten)]
    options: Options,
}

enum Selection {
    Range { start: u64, count: u64 },
    Multi(Vec<u64>),
}

impl RangeArgs {
    pub(super) fn execute(self, hash: Hash) -> Result<Vec<u8>, String> {
        execute(
            hash,
            self.leaves,
            self.seed,
            &self.options,
            Selection::Range {
                start: self.start,
                count: self.count,
            },
        )
    }
}

impl MultiArgs {
    pub(super) fn execute(self, hash: Hash) -> Result<Vec<u8>, String> {
        execute(
            hash,
            self.leaves,
            self.seed,
            &self.options,
            Selection::Multi(self.locations),
        )
    }
}

fn execute(
    hash: Hash,
    leaves: u64,
    seed: u64,
    options: &Options,
    selection: Selection,
) -> Result<Vec<u8>, String> {
    if matches!(options.root, RootKind::Current)
        && matches!(options.variant, Variant::Keyless | Variant::Immutable)
    {
        return Err("--root current requires an ordered or unordered variant".into());
    }
    match (options.family, hash) {
        (TreeKind::Mmr, Hash::Keccak256) => {
            generate::<mmr::Family, Keccak256>(leaves, seed, options, &selection)
        }
        (TreeKind::Mmr, Hash::Sha256) => {
            generate::<mmr::Family, Sha256>(leaves, seed, options, &selection)
        }
        (TreeKind::Mmb, Hash::Keccak256) => {
            generate::<mmb::Family, Keccak256>(leaves, seed, options, &selection)
        }
        (TreeKind::Mmb, Hash::Sha256) => {
            generate::<mmb::Family, Sha256>(leaves, seed, options, &selection)
        }
    }
}

fn generate<F: Graftable, H: Hasher>(
    leaves: u64,
    seed: u64,
    options: &Options,
    selection: &Selection,
) -> Result<Vec<u8>, String> {
    let location = match selection {
        Selection::Range { start, count } => {
            if *count == 0 || start.checked_add(*count).is_none_or(|end| end > leaves) {
                return Err("range requires count > 0 and start + count <= leaves".into());
            }
            *start
        }
        Selection::Multi(locations) => {
            if locations.is_empty()
                || locations.len() > 4096
                || locations
                    .iter()
                    .any(|&loc| loc < options.inactivity_floor || loc >= leaves)
            {
                return Err(
                    "multi requires 1..=4096 locations within inactivity-floor..leaves".into(),
                );
            }
            locations[0]
        }
    };
    let tree = TreeArgs {
        leaves,
        location,
        seed,
        family: options.family,
        inactivity_floor: options.inactivity_floor,
    };
    super::validate_tree(&tree)?;
    let value = |index| {
        let length = VARIABLE_LENGTHS[((seed % VARIABLE_LENGTHS.len() as u64 + index)
            % VARIABLE_LENGTHS.len() as u64) as usize];
        leaf(seed, index).into_iter().cycle().take(length).collect()
    };
    match (options.variant, options.encoding) {
        (Variant::Ordered, Encoding::Fixed) => {
            prove::<F, H, _>(&tree, options, selection, |index| {
                operation::<F>(seed, index, leaves)
            })
        }
        (Variant::Unordered, Encoding::Fixed) => {
            prove::<F, H, _>(&tree, options, selection, |index| {
                unordered::fixed::Operation::<F, FixedBytes<32>, FixedBytes<32>>::Update(
                    unordered::Update(key(index), FixedBytes::new(leaf(seed, index))),
                )
            })
        }
        (Variant::Keyless, Encoding::Fixed) => {
            prove::<F, H, _>(&tree, options, selection, |index| {
                keyless::Operation::<F, FixedEncoding<FixedBytes<32>>>::Append(FixedBytes::new(
                    leaf(seed, index),
                ))
            })
        }
        (Variant::Immutable, Encoding::Fixed) => {
            prove::<F, H, _>(&tree, options, selection, |index| {
                immutable::Operation::<F, FixedBytes<32>, FixedEncoding<FixedBytes<32>>>::Set(
                    key(index),
                    FixedBytes::new(leaf(seed, index)),
                )
            })
        }
        (Variant::Ordered, Encoding::Variable) => {
            prove::<F, H, _>(&tree, options, selection, |index| {
                ordered::variable::Operation::<F, FixedBytes<32>, Vec<u8>>::Update(
                    ordered::variable::Update {
                        key: key(index),
                        value: value(index),
                        next_key: key((index + 1) % leaves),
                    },
                )
            })
        }
        (Variant::Unordered, Encoding::Variable) => {
            prove::<F, H, _>(&tree, options, selection, |index| {
                unordered::variable::Operation::<F, FixedBytes<32>, Vec<u8>>::Update(
                    unordered::Update(key(index), value(index)),
                )
            })
        }
        (Variant::Keyless, Encoding::Variable) => {
            prove::<F, H, _>(&tree, options, selection, |index| {
                keyless::Operation::<F, VariableEncoding<Vec<u8>>>::Append(value(index))
            })
        }
        (Variant::Immutable, Encoding::Variable) => {
            prove::<F, H, _>(&tree, options, selection, |index| {
                immutable::Operation::<F, FixedBytes<32>, VariableEncoding<Vec<u8>>>::Set(
                    key(index),
                    value(index),
                )
            })
        }
    }
}

fn bytes32<D: Digest>(digest: D) -> Bytes32 {
    Bytes32::from_slice(digest.as_ref())
}

fn prove<F: Graftable, H: Hasher, O: Codec + Clone>(
    tree: &TreeArgs,
    options: &Options,
    selection: &Selection,
    operation: impl Fn(u64) -> O,
) -> Result<Vec<u8>, String> {
    match options.root {
        RootKind::Operations => {
            if options.activity.is_some() {
                return Err("--activity requires --root current".into());
            }
            if options.chunk_bytes.is_some() {
                return Err("--chunk-bytes requires --root current".into());
            }
            prove_operations::<F, H, O>(tree, selection, operation)
        }
        RootKind::Current => {
            let activity = options
                .activity
                .ok_or("--root current requires --activity")?;
            let chunk_bytes = options
                .chunk_bytes
                .ok_or("--root current requires --chunk-bytes")?;
            with_chunk_bytes!(chunk_bytes, |N| {
                prove_current::<F, H, O, N>(tree, activity, selection, operation)
            })
        }
    }
}

fn prove_current<F: Graftable, H: Hasher, O: Codec + Clone, const N: usize>(
    tree: &TreeArgs,
    activity: Activity,
    selection: &Selection,
    operation: impl Fn(u64) -> O,
) -> Result<Vec<u8>, String> {
    let chunk_bits = Prunable::<N>::CHUNK_SIZE_BITS;
    let current = materialize_current::<F, H, N>(
        tree,
        &|index, bytes| operation(index).write(bytes),
        &|index: u64| {
            index >= tree.inactivity_floor
                && match activity {
                    Activity::All => true,
                    Activity::Mixed => {
                        !(index / chunk_bits).is_multiple_of(3) && !index.is_multiple_of(3)
                    }
                    Activity::Zero => false,
                }
        },
    )?;
    let pending = current
        .witness
        .pending_chunk_digest
        .as_ref()
        .copied()
        .map_or(Bytes32::ZERO, bytes32);
    let partial = current
        .witness
        .partial_chunk
        .map_or(Bytes32::ZERO, |(_, digest)| bytes32(digest));
    match selection {
        Selection::Range { start, count } => {
            let end = start + count;
            let proof = block_on(RangeProof::<F, H::Digest>::new::<H, _, N>(
                &current.status,
                &current.grafted,
                Location::new(tree.inactivity_floor),
                Location::new(*start)..Location::new(end),
                current.ops_root,
            ))
            .map_err(|error| error.to_string())?;
            let operations: Vec<_> = (*start..end).map(&operation).collect();
            let chunks: Vec<_> = (*start / chunk_bits..=(end - 1) / chunk_bits)
                .map(|index| *current.status.get_chunk(index as usize))
                .collect();
            if !proof.verify::<H, _, N>(Location::new(*start), &operations, &chunks, &current.root)
            {
                return Err("Commonware rejected its Current range proof".into());
            }
            Ok((
                bytes32(current.root),
                Uint256::from(tree.leaves),
                Uint256::from(*start),
                Uint256::from(proof.proof.inactive_peaks),
                proof
                    .proof
                    .digests
                    .into_iter()
                    .map(bytes32)
                    .collect::<Vec<_>>(),
                operations
                    .iter()
                    .map(|op| Bytes::from(op.encode().to_vec()))
                    .collect::<Vec<_>>(),
                Bytes::from(chunks.into_iter().flatten().collect::<Vec<_>>()),
                bytes32(current.ops_root),
                pending,
                partial,
            )
                .abi_encode_params())
        }
        Selection::Multi(locations) => {
            if !current
                .witness
                .verify::<H>(&current.ops_root, &current.root)
            {
                return Err("Commonware rejected its operations-root witness".into());
            }
            let output =
                multi::<F, H, O>(tree, &current.ops, current.ops_root, locations, &operation)?;
            Ok((
                bytes32(current.root),
                output.leaves,
                output.locations,
                output.inactivePeaks,
                output.positions,
                output.digests,
                output.operations,
                bytes32(current.ops_root),
                bytes32(current.witness.grafted_root),
                pending,
                partial,
            )
                .abi_encode_params())
        }
    }
}

fn prove_operations<F: Graftable, H: Hasher, O: Codec + Clone>(
    tree: &TreeArgs,
    selection: &Selection,
    operation: impl Fn(u64) -> O,
) -> Result<Vec<u8>, String> {
    let ops = materialize_ops::<F, H>(tree, &|index, bytes| operation(index).write(bytes))?;
    let inactive = F::inactive_peaks(
        Location::new(tree.leaves),
        Location::new(tree.inactivity_floor),
    );
    let root = ops
        .root(&qmdb::hasher::<H>(), inactive)
        .map_err(|error| error.to_string())?;
    match selection {
        Selection::Range { start, count } => {
            let proof = ops
                .range_proof(
                    &qmdb::hasher::<H>(),
                    Location::new(*start)..Location::new(start + count),
                    inactive,
                )
                .map_err(|error| error.to_string())?;
            let operations: Vec<_> = (*start..start + count).map(&operation).collect();
            if !qmdb::verify_proof::<H, F, _>(&proof, Location::new(*start), &operations, &root) {
                return Err("Commonware rejected its operations range proof".into());
            }
            Ok(RangeOutput {
                root: bytes32(root),
                leaves: Uint256::from(tree.leaves),
                start: Uint256::from(*start),
                inactivePeaks: Uint256::from(inactive),
                digests: proof.digests.into_iter().map(bytes32).collect(),
                operations: operations
                    .iter()
                    .map(|op| op.encode().to_vec().into())
                    .collect(),
            }
            .abi_encode_params())
        }
        Selection::Multi(locations) => multi::<F, H, O>(tree, &ops, root, locations, &operation)
            .map(|output| output.abi_encode_params()),
    }
}

fn multi<F: Graftable, H: Hasher, O: Codec + Clone>(
    tree: &TreeArgs,
    ops: &Mem<F, H::Digest>,
    root: H::Digest,
    locations: &[u64],
    operation: &impl Fn(u64) -> O,
) -> Result<MultiOutput, String> {
    let inactive = F::inactive_peaks(
        Location::new(tree.leaves),
        Location::new(tree.inactivity_floor),
    );
    let locs: Vec<_> = locations.iter().copied().map(Location::new).collect();
    let proof = block_on(verification::multi_proof(
        ops,
        inactive,
        Bagging::BackwardFold,
        &locs,
    ))
    .map_err(|error| error.to_string())?;
    let operations: Vec<_> = locations
        .iter()
        .map(|&loc| (Location::new(loc), operation(loc)))
        .collect();
    if !qmdb::verify_multi_proof::<H, F, _>(&proof, &operations, &root) {
        return Err("Commonware rejected its operations multiproof".into());
    }
    let positions = qmdb_positions::<F>(tree.leaves, &locs, inactive)?;
    if positions.len() != proof.digests.len() {
        return Err("multiproof positions and digests disagree".into());
    }
    Ok(MultiOutput {
        root: bytes32(root),
        leaves: Uint256::from(tree.leaves),
        locations: locations.iter().copied().map(Uint256::from).collect(),
        inactivePeaks: Uint256::from(inactive),
        positions: positions.into_iter().map(Uint256::from).collect(),
        digests: proof.digests.into_iter().map(bytes32).collect(),
        operations: operations
            .iter()
            .map(|(_, op)| op.encode().to_vec().into())
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Cli;
    use clap::Parser;

    type CurrentRange = <sol!((bytes32, uint256, uint256, uint256, bytes32[], bytes[], bytes, bytes32, bytes32, bytes32)) as SolType>::RustType;
    type CurrentMulti = <sol!((bytes32, uint256, uint256[], uint256, uint256[], bytes32[], bytes[], bytes32, bytes32, bytes32, bytes32)) as SolType>::RustType;

    fn run(args: &[&str]) -> Result<Vec<u8>, String> {
        Cli::try_parse_from(["fuzz", "qmdb"].into_iter().chain(args.iter().copied()))
            .unwrap()
            .command
            .execute()
    }

    #[test]
    fn range_and_multi_use_all_operation_codecs() {
        for family in ["mmr", "mmb"] {
            for hash in ["keccak256", "sha256"] {
                for (variant, width) in [
                    ("ordered", 97),
                    ("unordered", 65),
                    ("keyless", 42),
                    ("immutable", 65),
                ] {
                    for (leaves, start, count, floor) in [
                        (1u64, 0u64, 1u64, 0u64),
                        (11, 2, 8, 0),
                        (1023, 768, 255, 768),
                    ] {
                        let encoded = run(&[
                            "--hash",
                            hash,
                            "range",
                            "--leaves",
                            &leaves.to_string(),
                            "--start",
                            &start.to_string(),
                            "--count",
                            &count.to_string(),
                            "--seed",
                            "71",
                            "--family",
                            family,
                            "--variant",
                            variant,
                            "--inactivity-floor",
                            &floor.to_string(),
                            "--encoding",
                            "fixed",
                            "--root",
                            "operations",
                        ])
                        .unwrap();
                        let range = <RangeOutput as SolValue>::abi_decode_params_validate(&encoded)
                            .unwrap();
                        assert_eq!(range.leaves, leaves);
                        assert_eq!(range.start, start);
                        assert_eq!(range.operations.len(), count as usize);
                        assert!(range.operations.iter().all(|op| op.len() == width));
                        if floor != 0 {
                            assert_ne!(range.inactivePeaks, 0);
                        }
                        let locations = format!("{},{},{}", start + count - 1, start, start);
                        let encoded = run(&[
                            "--hash",
                            hash,
                            "multi",
                            "--leaves",
                            &leaves.to_string(),
                            "--locations",
                            &locations,
                            "--seed",
                            "71",
                            "--family",
                            family,
                            "--variant",
                            variant,
                            "--inactivity-floor",
                            &floor.to_string(),
                            "--encoding",
                            "fixed",
                            "--root",
                            "operations",
                        ])
                        .unwrap();
                        let multi = <MultiOutput as SolValue>::abi_decode_params_validate(&encoded)
                            .unwrap();
                        assert_eq!(multi.root, range.root);
                        assert_eq!(multi.inactivePeaks, range.inactivePeaks);
                        assert_eq!(
                            multi.locations,
                            vec![
                                Uint256::from(start + count - 1),
                                Uint256::from(start),
                                Uint256::from(start)
                            ]
                        );
                        assert_eq!(
                            multi.operations,
                            vec![
                                range.operations.last().unwrap().clone(),
                                range.operations[0].clone(),
                                range.operations[0].clone()
                            ]
                        );
                        assert_eq!(multi.positions.len(), multi.digests.len());
                        assert!(multi.positions.windows(2).all(|pair| pair[0] < pair[1]));
                    }
                }
            }
        }
    }

    #[test]
    fn variable_batches_cover_codecs_and_length_boundaries() {
        for family in ["mmr", "mmb"] {
            for hash in ["keccak256", "sha256"] {
                for (variant, overhead) in [
                    ("ordered", 65),
                    ("unordered", 33),
                    ("keyless", 1),
                    ("immutable", 33),
                ] {
                    for root_kind in [RootKind::Operations, RootKind::Current] {
                        if matches!(root_kind, RootKind::Current)
                            && matches!(variant, "keyless" | "immutable")
                        {
                            continue;
                        }
                        let mut options = vec![
                            "--family",
                            family,
                            "--variant",
                            variant,
                            "--encoding",
                            "variable",
                            "--inactivity-floor",
                            "0",
                            "--root",
                            match root_kind {
                                RootKind::Operations => "operations",
                                RootKind::Current => "current",
                            },
                        ];
                        if matches!(root_kind, RootKind::Current) {
                            options.extend(["--activity", "mixed", "--chunk-bytes", "1"]);
                        }
                        let mut args = vec![
                            "--hash", hash, "range", "--leaves", "17", "--start", "0", "--count",
                            "8", "--seed", "0",
                        ];
                        args.extend_from_slice(&options);
                        let encoded = run(&args).unwrap();
                        let (root, operations) = if matches!(root_kind, RootKind::Current) {
                            let range = CurrentRange::abi_decode_params_validate(&encoded).unwrap();
                            (range.0, range.5)
                        } else {
                            let range =
                                <RangeOutput as SolValue>::abi_decode_params_validate(&encoded)
                                    .unwrap();
                            (range.root, range.operations)
                        };
                        for (operation, length) in operations.iter().zip(VARIABLE_LENGTHS) {
                            assert_eq!(
                                operation.len(),
                                overhead + length + if length < 128 { 1 } else { 2 }
                            );
                        }
                        let mut args = vec![
                            "--hash",
                            hash,
                            "multi",
                            "--leaves",
                            "17",
                            "--locations",
                            "7,0,7",
                            "--seed",
                            "0",
                        ];
                        args.extend_from_slice(&options);
                        let encoded = run(&args).unwrap();
                        let (multi_root, multi_operations) =
                            if matches!(root_kind, RootKind::Current) {
                                let multi =
                                    CurrentMulti::abi_decode_params_validate(&encoded).unwrap();
                                (multi.0, multi.6)
                            } else {
                                let multi =
                                    <MultiOutput as SolValue>::abi_decode_params_validate(&encoded)
                                        .unwrap();
                                (multi.root, multi.operations)
                            };
                        assert_eq!(multi_root, root);
                        assert_eq!(
                            multi_operations,
                            vec![
                                operations[7].clone(),
                                operations[0].clone(),
                                operations[7].clone()
                            ]
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn current_ranges_cover_zero_mixed_pending_partial_and_inactive_chunks() {
        for family in ["mmr", "mmb"] {
            for hash in ["keccak256", "sha256"] {
                for activity in ["all", "mixed", "zero"] {
                    for (leaves, start, count, floor) in [
                        (1u64, 0u64, 1u64, 0u64),
                        (255, 0, 255, 0),
                        (256, 0, 256, 0),
                        (257, 250, 7, 0),
                        (383, 250, 133, 0),
                        (638, 250, 388, 0),
                        (639, 0, 639, 0),
                        (1023, 768, 255, 768),
                        (1535, 1024, 511, 1024),
                    ] {
                        let encoded = run(&[
                            "--hash",
                            hash,
                            "range",
                            "--leaves",
                            &leaves.to_string(),
                            "--start",
                            &start.to_string(),
                            "--count",
                            &count.to_string(),
                            "--seed",
                            "71",
                            "--family",
                            family,
                            "--variant",
                            "unordered",
                            "--root",
                            "current",
                            "--activity",
                            activity,
                            "--inactivity-floor",
                            &floor.to_string(),
                            "--chunk-bytes",
                            "32",
                            "--encoding",
                            "fixed",
                        ])
                        .unwrap();
                        let output = CurrentRange::abi_decode_params_validate(&encoded).unwrap();
                        assert_eq!(output.1, leaves);
                        assert_eq!(output.2, start);
                        assert_eq!(output.5.len(), count as usize);
                        assert_eq!(
                            output.6.len(),
                            ((start + count - 1) / 256 - start / 256 + 1) as usize * 32
                        );
                        if floor != 0 {
                            assert_ne!(output.3, 0);
                        }
                        if family == "mmr" {
                            assert_eq!(output.8, Bytes32::ZERO);
                        }
                        if leaves == 638 && family == "mmb" {
                            assert_ne!(output.8, Bytes32::ZERO);
                            assert_ne!(output.9, Bytes32::ZERO);
                        }
                        for (chunk_index, chunk) in output.6.as_chunks::<32>().0.iter().enumerate()
                        {
                            for bit in 0..256u64 {
                                let index = (start / 256 + chunk_index as u64) * 256 + bit;
                                let active = index < leaves
                                    && index >= floor
                                    && match activity {
                                        "all" => true,
                                        "mixed" => {
                                            !(index / 256).is_multiple_of(3)
                                                && !index.is_multiple_of(3)
                                        }
                                        _ => false,
                                    };
                                assert_eq!(
                                    chunk[(bit / 8) as usize] & (1 << (bit % 8)) != 0,
                                    active
                                );
                            }
                        }
                        let locations = format!("{},{},{}", start + count - 1, start, start);
                        let encoded = run(&[
                            "--hash",
                            hash,
                            "multi",
                            "--leaves",
                            &leaves.to_string(),
                            "--locations",
                            &locations,
                            "--seed",
                            "71",
                            "--family",
                            family,
                            "--variant",
                            "unordered",
                            "--root",
                            "current",
                            "--activity",
                            activity,
                            "--inactivity-floor",
                            &floor.to_string(),
                            "--chunk-bytes",
                            "32",
                            "--encoding",
                            "fixed",
                        ])
                        .unwrap();
                        let multi = CurrentMulti::abi_decode_params_validate(&encoded).unwrap();
                        assert_eq!(multi.0, output.0);
                        assert_eq!(multi.7, output.7);
                        assert_eq!(multi.9, output.8);
                        assert_eq!(multi.10, output.9);
                        assert!(multi.4.windows(2).all(|pair| pair[0] < pair[1]));
                    }
                }
            }
        }
    }

    #[test]
    fn current_ranges_and_witnesses_use_configured_bitmap_chunks() {
        for chunk_bytes in [1u64, 2, 16, 32, 64, 128] {
            let chunk_bits = chunk_bytes * 8;
            let leaves = 2 * chunk_bits + 3;
            let start = chunk_bits - 2;
            let count = chunk_bits + 5;
            for family in ["mmr", "mmb"] {
                let encoded = run(&[
                    "--hash",
                    "keccak256",
                    "range",
                    "--leaves",
                    &leaves.to_string(),
                    "--start",
                    &start.to_string(),
                    "--count",
                    &count.to_string(),
                    "--seed",
                    "71",
                    "--family",
                    family,
                    "--variant",
                    "unordered",
                    "--root",
                    "current",
                    "--activity",
                    "mixed",
                    "--chunk-bytes",
                    &chunk_bytes.to_string(),
                    "--inactivity-floor",
                    "0",
                    "--encoding",
                    "fixed",
                ])
                .unwrap();
                let range = CurrentRange::abi_decode_params_validate(&encoded).unwrap();
                assert_eq!(range.6.len(), chunk_bytes as usize * 3);
                for (chunk_offset, chunk) in range.6.chunks_exact(chunk_bytes as usize).enumerate()
                {
                    for bit in 0..chunk_bits {
                        let index = (start / chunk_bits + chunk_offset as u64) * chunk_bits + bit;
                        let expected = index < leaves
                            && !(index / chunk_bits).is_multiple_of(3)
                            && !index.is_multiple_of(3);
                        assert_eq!(chunk[(bit / 8) as usize] & (1 << (bit % 8)) != 0, expected);
                    }
                }

                let locations = format!("{},{},{}", start + count - 1, start, start);
                let encoded = run(&[
                    "--hash",
                    "keccak256",
                    "multi",
                    "--leaves",
                    &leaves.to_string(),
                    "--locations",
                    &locations,
                    "--seed",
                    "71",
                    "--family",
                    family,
                    "--variant",
                    "unordered",
                    "--root",
                    "current",
                    "--activity",
                    "mixed",
                    "--chunk-bytes",
                    &chunk_bytes.to_string(),
                    "--inactivity-floor",
                    "0",
                    "--encoding",
                    "fixed",
                ])
                .unwrap();
                let witness = CurrentMulti::abi_decode_params_validate(&encoded).unwrap();
                assert_eq!(witness.0, range.0);
                assert_eq!(witness.7, range.7);
                assert_eq!(witness.9, range.8);
                assert_eq!(witness.10, range.9);
            }
        }
    }

    #[test]
    fn batch_cli_requires_current_configuration_only_for_current_roots() {
        use clap::error::ErrorKind;

        for selection in [
            vec!["range", "--start", "0", "--count", "1"],
            vec!["multi", "--locations", "0"],
        ] {
            let mut current = vec!["fuzz", "qmdb", "--hash", "keccak256"];
            current.extend(selection);
            current.extend([
                "--leaves",
                "3",
                "--seed",
                "71",
                "--family",
                "mmb",
                "--variant",
                "ordered",
                "--encoding",
                "fixed",
                "--inactivity-floor",
                "0",
                "--root",
                "current",
                "--activity",
                "all",
                "--chunk-bytes",
                "32",
            ]);
            for field in ["--activity", "--chunk-bytes"] {
                let mut missing = current.clone();
                let index = missing.iter().position(|arg| *arg == field).unwrap();
                missing.drain(index..index + 2);
                let error = Cli::try_parse_from(missing).err().unwrap();
                assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument, "{error}");
                assert!(error.to_string().contains(field), "{error}");
            }

            for (field, value) in [("--activity", "all"), ("--chunk-bytes", "32")] {
                let mut operations = current[..current.len() - 6].to_vec();
                operations.extend(["--root", "operations", field, value]);
                let error = Cli::try_parse_from(operations)
                    .unwrap()
                    .command
                    .execute()
                    .unwrap_err();
                assert_eq!(error, format!("{field} requires --root current"));
            }
        }
    }

    #[test]
    fn batch_rejects_invalid_requests() {
        for args in [
            vec![
                "--hash",
                "keccak256",
                "range",
                "--leaves",
                "0",
                "--start",
                "0",
                "--count",
                "1",
                "--seed",
                "71",
                "--family",
                "mmb",
                "--inactivity-floor",
                "0",
                "--variant",
                "ordered",
                "--encoding",
                "fixed",
                "--root",
                "operations",
            ],
            vec![
                "--hash",
                "keccak256",
                "range",
                "--leaves",
                "3",
                "--start",
                "0",
                "--count",
                "0",
                "--seed",
                "71",
                "--family",
                "mmb",
                "--inactivity-floor",
                "0",
                "--variant",
                "ordered",
                "--encoding",
                "fixed",
                "--root",
                "operations",
            ],
            vec![
                "--hash",
                "keccak256",
                "range",
                "--leaves",
                "3",
                "--start",
                "2",
                "--count",
                "2",
                "--seed",
                "71",
                "--family",
                "mmb",
                "--inactivity-floor",
                "0",
                "--variant",
                "ordered",
                "--encoding",
                "fixed",
                "--root",
                "operations",
            ],
            vec![
                "--hash",
                "keccak256",
                "range",
                "--leaves",
                "3",
                "--start",
                "18446744073709551615",
                "--count",
                "2",
                "--seed",
                "71",
                "--family",
                "mmb",
                "--inactivity-floor",
                "0",
                "--variant",
                "ordered",
                "--encoding",
                "fixed",
                "--root",
                "operations",
            ],
            vec![
                "--hash",
                "keccak256",
                "range",
                "--leaves",
                "3",
                "--start",
                "0",
                "--count",
                "1",
                "--seed",
                "71",
                "--inactivity-floor",
                "1",
                "--family",
                "mmb",
                "--variant",
                "ordered",
                "--encoding",
                "fixed",
                "--root",
                "operations",
            ],
            vec![
                "--hash",
                "keccak256",
                "range",
                "--leaves",
                "1000001",
                "--start",
                "0",
                "--count",
                "1",
                "--seed",
                "71",
                "--family",
                "mmb",
                "--inactivity-floor",
                "0",
                "--variant",
                "ordered",
                "--encoding",
                "fixed",
                "--root",
                "operations",
            ],
            vec![
                "--hash",
                "keccak256",
                "range",
                "--leaves",
                "3",
                "--start",
                "0",
                "--count",
                "1",
                "--seed",
                "71",
                "--root",
                "current",
                "--variant",
                "keyless",
                "--family",
                "mmb",
                "--inactivity-floor",
                "0",
                "--chunk-bytes",
                "32",
                "--encoding",
                "fixed",
                "--activity",
                "all",
            ],
            vec![
                "--hash",
                "keccak256",
                "multi",
                "--leaves",
                "3",
                "--locations",
                "3",
                "--seed",
                "71",
                "--family",
                "mmb",
                "--inactivity-floor",
                "0",
                "--variant",
                "ordered",
                "--encoding",
                "fixed",
                "--root",
                "operations",
            ],
            vec![
                "--hash",
                "keccak256",
                "multi",
                "--leaves",
                "3",
                "--locations",
                "0,2",
                "--seed",
                "71",
                "--inactivity-floor",
                "1",
                "--family",
                "mmb",
                "--variant",
                "ordered",
                "--encoding",
                "fixed",
                "--root",
                "operations",
            ],
            vec![
                "--hash",
                "keccak256",
                "multi",
                "--leaves",
                "3",
                "--locations",
                "0,2",
                "--seed",
                "71",
                "--root",
                "current",
                "--variant",
                "immutable",
                "--family",
                "mmb",
                "--inactivity-floor",
                "0",
                "--chunk-bytes",
                "32",
                "--encoding",
                "fixed",
                "--activity",
                "all",
            ],
        ] {
            assert!(run(&args).is_err(), "{args:?}");
        }
    }
}
