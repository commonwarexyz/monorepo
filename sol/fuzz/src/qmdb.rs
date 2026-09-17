//! Materialized MMB fixtures for current QMDB with 32-byte bitmap chunks.
//!
//! The operations and bitmap form a deterministic proof snapshot. This exercises the
//! production tree, codec, and current-proof APIs without a persistent database lifecycle.

use crate::{Hash, merkle::leaf};
use alloy_sol_macro::sol;
use alloy_sol_types::{SolType, SolValue};
use clap::{Args, Subcommand};
use commonware_codec::Encode;
use commonware_cryptography::{Hasher, Keccak256, Sha256};
use commonware_storage::{
    merkle::{Family, Location, mem::Mem, mmb},
    qmdb::{
        self,
        any::ordered::fixed,
        current::{
            grafting,
            proof::{OpsRootWitness, operation},
        },
    },
};
use commonware_utils::{bitmap::Prunable, sequence::FixedBytes};

type F = mmb::Family;
type Uint256 = <sol!(uint256) as SolType>::RustType;
type Operation = fixed::Operation<F, FixedBytes<32>, FixedBytes<32>>;

sol! {
    struct OperationOutput {
        bytes32 root;
        uint256 leaves;
        uint256 location;
        uint256 inactivePeaks;
        bytes32 chunk;
        bytes32 opsRoot;
        bytes32 pending;
        bytes32 partial;
        bytes32[] digests;
        bytes operation;
    }
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Build an operations tree and its activity-grafted tree, then prove one active update.
    Generate(GenerateArgs),
}

#[derive(Args)]
pub(crate) struct GenerateArgs {
    leaves: u64,
    location: u64,
    seed: u64,
    #[arg(long, value_enum, default_value = "keccak")]
    hash: Hash,
    /// Operations below this location are inactive; proofs fold only chunk-aligned peaks.
    #[arg(long, default_value_t = 0)]
    inactivity_floor: u64,
}

fn operation(seed: u64, index: u64, leaves: u64) -> Operation {
    let key = |index: u64| {
        let mut bytes = [0; 32];
        bytes[24..].copy_from_slice(&index.to_be_bytes());
        FixedBytes::new(bytes)
    };
    Operation::Update(fixed::Update {
        key: key(index),
        value: FixedBytes::new(leaf(seed, index)),
        next_key: key((index + 1) % leaves),
    })
}

fn generate<H: Hasher>(args: &GenerateArgs) -> Result<OperationOutput, String> {
    let GenerateArgs {
        leaves,
        location,
        seed,
        inactivity_floor,
        ..
    } = *args;
    if leaves == 0 || leaves > 1_000_000 || location >= leaves || location < inactivity_floor {
        return Err(
            "require 1 <= leaves <= 1000000 and inactivity-floor <= location < leaves".into(),
        );
    }
    let mut status = Prunable::<32>::new();
    for index in 0..leaves {
        status.push(index >= inactivity_floor);
    }
    let chunks: Vec<_> = (0..leaves.div_ceil(256))
        .map(|index| status.get_chunk(index as usize).as_slice())
        .collect();
    let graftable = grafting::graftable_chunks::<F>(leaves, 8);
    let hasher = qmdb::hasher::<H>();
    let verifier = grafting::Verifier::<F, H>::new(8, 0, chunks, graftable);
    let mut ops = Mem::<F, H::Digest>::new();
    let mut grafted = Mem::<F, H::Digest>::new();
    let mut ops_batch = ops.new_batch();
    let mut grafted_batch = grafted.new_batch();
    for index in 0..leaves {
        let encoded = operation(seed, index, leaves).encode();
        ops_batch = ops_batch.add(&hasher, &encoded);
        grafted_batch = grafted_batch.add(&verifier, &encoded);
    }
    let ops_batch = ops_batch.merkleize(&ops, &hasher);
    let grafted_batch = grafted_batch.merkleize(&grafted, &verifier);
    ops.apply_batch(&ops_batch).map_err(|e| e.to_string())?;
    grafted
        .apply_batch(&grafted_batch)
        .map_err(|e| e.to_string())?;

    // Any roots fold all peaks wholly below the floor. Current roots additionally
    // require a chunk-aligned boundary, which OperationProof::new derives itself.
    let inactive_ops = F::inactive_peaks(Location::new(leaves), Location::new(inactivity_floor));
    let ops_root = ops.root(&hasher, inactive_ops).map_err(|e| e.to_string())?;
    let proof =
        futures::executor::block_on(operation::Proof::<F, H::Digest, [u8; 32]>::new::<H, _>(
            &status,
            &grafted,
            Location::new(inactivity_floor),
            Location::new(location),
            ops_root,
        ))
        .map_err(|e| e.to_string())?;
    let range = &proof.range_proof;
    let grafted_root = grafted
        .root(&hasher, range.proof.inactive_peaks)
        .map_err(|e| e.to_string())?;
    let pending =
        (leaves / 256 > graftable).then(|| H::hash(&[status.get_chunk(graftable as usize)]));
    let partial = (!leaves.is_multiple_of(256)).then(|| {
        (
            leaves % 256,
            H::hash(&[status.get_chunk((leaves / 256) as usize)]),
        )
    });
    let root = OpsRootWitness::<F, H::Digest> {
        grafted_root,
        pending_chunk_digest: pending,
        partial_chunk: partial,
    }
    .root::<H>(&ops_root);
    let op = operation(seed, location, leaves);
    if !proof.verify::<H, _>(op.clone(), &root) {
        return Err("Commonware rejected proof against the materialized canonical root".into());
    }
    let bytes32 = |digest: H::Digest| -> [u8; 32] { digest.as_ref().try_into().unwrap() };
    Ok(OperationOutput {
        root: bytes32(root).into(),
        leaves: Uint256::from(leaves),
        location: Uint256::from(location),
        inactivePeaks: Uint256::from(range.proof.inactive_peaks),
        chunk: proof.chunk.into(),
        opsRoot: bytes32(ops_root).into(),
        pending: pending.map_or([0; 32], bytes32).into(),
        partial: partial
            .map_or([0; 32], |(_, digest)| bytes32(digest))
            .into(),
        digests: range
            .proof
            .digests
            .iter()
            .map(|d| bytes32(*d).into())
            .collect(),
        operation: op.encode().to_vec().into(),
    })
}

impl Command {
    pub(crate) fn execute(self) -> Result<Vec<u8>, String> {
        let Self::Generate(args) = self;
        let output = match args.hash {
            Hash::Keccak => generate::<Keccak256>(&args),
            Hash::Sha256 => generate::<Sha256>(&args),
        }?;
        Ok(output.abi_encode_params())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Cli;
    use clap::Parser;
    use commonware_codec::{Copying, DecodeExt};
    use commonware_storage::{merkle::Proof, qmdb::current::proof::RangeProof};

    fn verify_output<H: Hasher>(output: &OperationOutput) {
        let leaves = u64::try_from(output.leaves).unwrap();
        let digest = |bytes: &[u8]| H::Digest::decode(Copying(bytes)).unwrap();
        let graftable = grafting::graftable_chunks::<F>(leaves, 8);
        let proof = operation::Proof {
            loc: Location::<F>::new(u64::try_from(output.location).unwrap()),
            chunk: output.chunk.0,
            range_proof: RangeProof {
                proof: Proof {
                    leaves: Location::new(leaves),
                    inactive_peaks: usize::try_from(output.inactivePeaks).unwrap(),
                    digests: output
                        .digests
                        .iter()
                        .map(|d| digest(d.as_slice()))
                        .collect(),
                },
                pending_chunk_digest: (leaves / 256 > graftable)
                    .then(|| digest(output.pending.as_slice())),
                partial_chunk_digest: (!leaves.is_multiple_of(256))
                    .then(|| digest(output.partial.as_slice())),
                ops_root: digest(output.opsRoot.as_slice()),
            },
        };
        let op = Operation::decode(Copying(output.operation.as_ref())).unwrap();
        assert!(proof.verify::<H, _>(op, &digest(output.root.as_slice())));
    }

    #[test]
    fn materialized_current_proofs_cover_chunk_boundaries() {
        for hash in ["keccak", "sha256"] {
            for leaves in [
                1u64, 255, 256, 257, 382, 383, 384, 511, 512, 513, 638, 639, 640, 1024, 4097,
            ] {
                for location in [0, leaves / 2, leaves - 1] {
                    for floor in [0, location] {
                        let encoded = Cli::try_parse_from([
                            "fuzz",
                            "qmdb",
                            "generate",
                            &leaves.to_string(),
                            &location.to_string(),
                            "42",
                            "--hash",
                            hash,
                            "--inactivity-floor",
                            &floor.to_string(),
                        ])
                        .unwrap()
                        .command
                        .execute()
                        .unwrap();
                        let output =
                            <OperationOutput as SolValue>::abi_decode_params_validate(&encoded)
                                .unwrap();
                        match hash {
                            "keccak" => verify_output::<Keccak256>(&output),
                            _ => verify_output::<Sha256>(&output),
                        }
                        assert_eq!(output.leaves, leaves);
                        assert_eq!(output.location, location);
                        assert_eq!(output.operation.len(), 97);
                        assert_eq!(output.operation[0], 0xD2);
                        assert_ne!(
                            output.chunk[(location % 256 / 8) as usize] & (1 << (location % 8)),
                            0
                        );
                        let graftable = if leaves < 383 {
                            0
                        } else {
                            (leaves - 383) / 256 + 1
                        };
                        assert_eq!(output.pending != [0; 32], leaves / 256 > graftable);
                        assert_eq!(output.partial != [0; 32], leaves % 256 != 0);
                        if floor >= 512 {
                            assert_ne!(output.inactivePeaks, 0);
                        }
                    }
                }
            }
        }
    }
}
