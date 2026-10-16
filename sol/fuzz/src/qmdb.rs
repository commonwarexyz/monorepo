//! Materialized MMR and MMB fixtures for any, keyless, immutable, and current QMDB.
//!
//! Materialized operation logs and activity bitmaps exercise the production tree,
//! codec, and proof APIs. Lifecycle fixtures additionally use persistent databases.

use crate::{
    Hash,
    merkle::{TreeKind, leaf},
};
use alloy_sol_macro::sol;
use alloy_sol_types::{SolType, SolValue};
use clap::{Args, Subcommand};
use commonware_codec::{Codec, Encode};
use commonware_cryptography::{Digest, Hasher, Keccak256, Sha256};
use commonware_storage::{
    merkle::{Family, Graftable, Location, PendingChunk as _, mem::Mem, mmb, mmr},
    qmdb::{
        self,
        any::{
            ordered::fixed,
            unordered,
            value::{FixedEncoding, ValueEncoding, VariableEncoding},
        },
        current::{
            grafting,
            proof::{OpsRootWitness, operation},
        },
        immutable, keyless,
    },
};
use commonware_utils::{bitmap::Prunable, sequence::FixedBytes};

mod batch;
mod exclusion;
mod lifecycle;

type Uint256 = <sol!(uint256) as SolType>::RustType;
type Operation<F> = fixed::Operation<F, FixedBytes<32>, FixedBytes<32>>;

macro_rules! with_chunk_bytes {
    ($chunk_bytes:expr, |$n:ident| $body:expr) => {
        match $chunk_bytes {
            1 => {
                const $n: usize = 1;
                $body
            }
            2 => {
                const $n: usize = 2;
                $body
            }
            16 => {
                const $n: usize = 16;
                $body
            }
            32 => {
                const $n: usize = 32;
                $body
            }
            64 => {
                const $n: usize = 64;
                $body
            }
            128 => {
                const $n: usize = 128;
                $body
            }
            size => Err(format!(
                "unsupported chunk size {size}; expected 1, 2, 16, 32, 64, or 128 bytes"
            )),
        }
    };
}

pub(super) use with_chunk_bytes;

sol! {
    struct AnyOutput {
        bytes32 root;
        uint256 leaves;
        uint256 location;
        uint256 inactivePeaks;
        bytes32[] digests;
        bytes operation;
    }

    struct OperationOutput {
        bytes32 root;
        uint256 leaves;
        uint256 location;
        uint256 inactivePeaks;
        bytes chunk;
        bytes32 opsRoot;
        bytes32 pending;
        bytes32 partial;
        bytes32[] digests;
        bytes operation;
    }
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Prove operations from a persistent database lifecycle.
    Lifecycle(lifecycle::LifecycleArgs),
    /// Prove a contiguous range of exact encoded operations.
    Range(batch::RangeArgs),
    /// Prove historical operations at sparse locations.
    Multi(batch::MultiArgs),
    /// Prove membership of an ordered operation in the plain operations root.
    Any(AnyArgs),
    /// Prove unordered operations, optionally including their Current activity verdict.
    Unordered(UnorderedArgs),
    /// Prove membership of an encoded keyless append or commit.
    Keyless(KeylessArgs),
    /// Prove membership of an encoded immutable set or commit.
    Immutable(ImmutableArgs),
    /// Build an operations tree and its activity-grafted tree, then prove one active update.
    Current(CurrentArgs),
    /// Prove exclusion using a cyclic key interval or an empty database commit.
    Exclude(exclusion::ExcludeArgs),
}

#[derive(Args, Clone, Copy)]
pub(crate) struct TreeArgs {
    #[arg(long)]
    leaves: u64,
    #[arg(long)]
    location: u64,
    #[arg(long)]
    seed: u64,
    #[arg(long, value_enum)]
    family: TreeKind,
    /// Operations below this location are inactive; current proofs fold chunk-aligned peaks.
    #[arg(long)]
    inactivity_floor: u64,
}

#[derive(Args)]
pub(crate) struct CurrentArgs {
    #[command(flatten)]
    tree: TreeArgs,
    /// Current activity bitmap chunk size in bytes.
    #[arg(long)]
    chunk_bytes: usize,
}

#[derive(Args, Clone, Copy)]
struct ExclusionTreeArgs {
    #[arg(long)]
    leaves: u64,
    #[arg(long)]
    location: u64,
    #[arg(long)]
    seed: u64,
    #[arg(long, value_enum)]
    family: TreeKind,
    /// Current activity bitmap chunk size in bytes.
    #[arg(long)]
    chunk_bytes: usize,
}

impl ExclusionTreeArgs {
    const fn tree(self, mode: ExclusionMode) -> TreeArgs {
        TreeArgs {
            leaves: self.leaves,
            location: self.location,
            seed: self.seed,
            family: self.family,
            inactivity_floor: match mode {
                ExclusionMode::Interval => 0,
                ExclusionMode::Single | ExclusionMode::Empty => self.location,
            },
        }
    }
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum History {
    /// Derive keys from operation locations using the command's indexed schedule.
    Indexed,
    /// Repeat key zero throughout the operation stream.
    Updated,
    /// Repeat key zero, then delete it in the final operation.
    Deleted,
}

#[derive(Args)]
pub(crate) struct AnyArgs {
    #[command(flatten)]
    tree: TreeArgs,
    /// Key schedule; indexed derives keys from operation locations, while updated/deleted repeat
    /// key zero.
    #[arg(long, value_enum)]
    history: History,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum Encoding {
    Fixed,
    Variable,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum RootKind {
    Operations,
    Current,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum UnorderedOperation {
    Update,
    Delete,
    Commit,
    CommitMetadata,
}

#[derive(Args)]
pub(crate) struct UnorderedArgs {
    #[command(flatten)]
    tree: TreeArgs,
    /// Root authenticated by the proof.
    #[arg(long, value_enum)]
    root: RootKind,
    /// Current activity bitmap chunk size in bytes.
    #[arg(long, required_if_eq("root", "current"))]
    chunk_bytes: Option<usize>,
    #[arg(long, value_enum)]
    encoding: Encoding,
    /// Fixture mode: update generates the selected history; other modes place the named
    /// operation at --location in an indexed update log.
    #[arg(long, value_enum)]
    operation: UnorderedOperation,
    /// Full-log history for update mode; indexed cycles keys over the active window.
    /// Deleted ends with a delete, returned when --location selects the final record.
    #[arg(long, value_enum, required_if_eq("operation", "update"))]
    history: Option<History>,
    /// Variable value and metadata length, required for variable encoding.
    #[arg(long, required_if_eq("encoding", "variable"))]
    value_length: Option<u16>,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum KeylessOperation {
    Append,
    Commit,
    CommitMetadata,
}

#[derive(Args)]
pub(crate) struct KeylessArgs {
    #[command(flatten)]
    tree: TreeArgs,
    #[arg(long, value_enum)]
    encoding: Encoding,
    #[arg(long, value_enum)]
    operation: KeylessOperation,
    /// Variable value and metadata length, required for variable encoding.
    #[arg(long, required_if_eq("encoding", "variable"))]
    value_length: Option<u16>,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum ImmutableOperation {
    Set,
    Commit,
    CommitMetadata,
}

#[derive(Args)]
pub(crate) struct ImmutableArgs {
    #[command(flatten)]
    tree: TreeArgs,
    #[arg(long, value_enum)]
    encoding: Encoding,
    #[arg(long, value_enum)]
    operation: ImmutableOperation,
    /// Variable value and metadata length, required for variable encoding.
    #[arg(long, required_if_eq("encoding", "variable"))]
    value_length: Option<u16>,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum ExclusionMode {
    Interval,
    Single,
    Empty,
}

fn key(index: u64) -> FixedBytes<32> {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&index.to_be_bytes());
    FixedBytes::new(bytes)
}

fn operation<F: Family>(seed: u64, index: u64, leaves: u64) -> Operation<F> {
    Operation::Update(fixed::Update {
        key: key(index),
        value: FixedBytes::new(leaf(seed, index)),
        next_key: key((index + 1) % leaves),
    })
}

fn materialize_ops<F: Family, H: Hasher>(
    args: &TreeArgs,
    encode: &dyn Fn(u64, &mut Vec<u8>),
) -> Result<Mem<F, H::Digest>, String> {
    validate_tree(args)?;
    let hasher = qmdb::hasher::<H>();
    let mut ops = Mem::<F, H::Digest>::new();
    let mut batch = ops.new_batch();
    let mut encoded = Vec::new();
    for index in 0..args.leaves {
        encoded.clear();
        encode(index, &mut encoded);
        batch = batch.add(&hasher, &encoded);
    }
    let batch = batch.merkleize(&ops, &hasher);
    ops.apply_batch(&batch).map_err(|e| e.to_string())?;
    Ok(ops)
}

fn validate_tree(args: &TreeArgs) -> Result<(), String> {
    if args.leaves == 0
        || args.leaves > 1_000_000
        || args.location >= args.leaves
        || args.location < args.inactivity_floor
    {
        return Err(
            "require 1 <= leaves <= 1000000 and inactivity-floor <= location < leaves".into(),
        );
    }
    Ok(())
}

fn any_operation<F: Family>(args: &AnyArgs, index: u64) -> Operation<F> {
    match args.history {
        History::Indexed => operation(args.tree.seed, index, args.tree.leaves),
        History::Deleted if index == args.tree.leaves - 1 => Operation::Delete(key(0)),
        History::Updated | History::Deleted => Operation::Update(fixed::Update {
            key: key(0),
            value: FixedBytes::new(leaf(args.tree.seed, index)),
            next_key: key(0),
        }),
    }
}

fn any<F: Family, H: Hasher>(args: &AnyArgs) -> Result<AnyOutput, String> {
    let tree = &args.tree;
    if !matches!(args.history, History::Indexed) && (tree.leaves < 2 || tree.location != 0) {
        return Err("updated and deleted history require leaves >= 2 and location = 0".into());
    }
    plain_proof::<F, H, _>(tree, |index| any_operation::<F>(args, index))
}

fn plain_proof<F: Family, H: Hasher, O: Encode>(
    tree: &TreeArgs,
    operation: impl Fn(u64) -> O,
) -> Result<AnyOutput, String> {
    let ops = materialize_ops::<F, H>(tree, &|index, bytes| operation(index).write(bytes))?;
    let hasher = qmdb::hasher::<H>();
    let inactive = F::inactive_peaks(
        Location::new(tree.leaves),
        Location::new(tree.inactivity_floor),
    );
    let root = ops.root(&hasher, inactive).map_err(|e| e.to_string())?;
    let location = Location::new(tree.location);
    let proof = ops
        .range_proof(
            &hasher,
            location..Location::new(tree.location + 1),
            inactive,
        )
        .map_err(|e| e.to_string())?;
    let op = operation(tree.location);
    if !qmdb::verify_proof::<H, F, _>(&proof, location, core::slice::from_ref(&op), &root) {
        return Err("Commonware rejected the materialized operations proof".into());
    }
    let bytes32 = |digest: H::Digest| -> [u8; 32] { digest.as_ref().try_into().unwrap() };
    Ok(AnyOutput {
        root: bytes32(root).into(),
        leaves: Uint256::from(tree.leaves),
        location: Uint256::from(tree.location),
        inactivePeaks: Uint256::from(inactive),
        digests: proof.digests.iter().map(|d| bytes32(*d).into()).collect(),
        operation: op.encode().to_vec().into(),
    })
}

// Fixture matrices cover word and varint boundaries for values and metadata.
const VARIABLE_LENGTHS: [usize; 8] = [0, 1, 31, 32, 33, 127, 128, 129];

fn keyless_operation<F: Family, V: qmdb::any::value::ValueEncoding>(
    args: &KeylessArgs,
    index: u64,
    value: V::Value,
) -> keyless::Operation<F, V> {
    use keyless::Operation::{Append, Commit};
    if index == 0 {
        return Commit(None, Location::new(0));
    }
    if index == args.tree.location {
        return match args.operation {
            KeylessOperation::Append => Append(value),
            KeylessOperation::Commit => Commit(None, Location::new(args.tree.inactivity_floor)),
            KeylessOperation::CommitMetadata => {
                Commit(Some(value), Location::new(args.tree.inactivity_floor))
            }
        };
    }
    if index == args.tree.leaves - 1 {
        return Commit(None, Location::new(args.tree.inactivity_floor));
    }
    Append(value)
}

fn keyless<F: Family, H: Hasher>(args: &KeylessArgs) -> Result<AnyOutput, String> {
    if args.tree.location == 0 && !matches!(args.operation, KeylessOperation::Commit) {
        return Err("location 0 is the bootstrap commit; require --operation commit".into());
    }
    if args.value_length.is_some() && matches!(args.encoding, Encoding::Fixed) {
        return Err("value-length requires --encoding variable".into());
    }
    match args.encoding {
        Encoding::Fixed => plain_proof::<F, H, _>(&args.tree, |index| {
            keyless_operation::<F, FixedEncoding<FixedBytes<32>>>(
                args,
                index,
                FixedBytes::new(leaf(args.tree.seed, index)),
            )
        }),
        Encoding::Variable => {
            let len = usize::from(
                args.value_length
                    .ok_or("variable encoding requires --value-length")?,
            );
            plain_proof::<F, H, _>(&args.tree, |index| {
                let bytes = leaf(args.tree.seed, index);
                keyless_operation::<F, qmdb::any::value::VariableEncoding<Vec<u8>>>(
                    args,
                    index,
                    bytes.into_iter().cycle().take(len).collect(),
                )
            })
        }
    }
}

fn immutable_operation<F: Family, V: qmdb::any::value::ValueEncoding>(
    args: &ImmutableArgs,
    index: u64,
    value: V::Value,
) -> immutable::Operation<F, FixedBytes<32>, V> {
    use immutable::Operation::{Commit, Set};
    if index == 0 {
        return Commit(None, Location::new(0));
    }
    if index == args.tree.location {
        return match args.operation {
            ImmutableOperation::Set => Set(key(index), value),
            ImmutableOperation::Commit => Commit(None, Location::new(args.tree.inactivity_floor)),
            ImmutableOperation::CommitMetadata => {
                Commit(Some(value), Location::new(args.tree.inactivity_floor))
            }
        };
    }
    if index == args.tree.leaves - 1 {
        return Commit(None, Location::new(args.tree.inactivity_floor));
    }
    Set(key(index), value)
}

fn immutable<F: Family, H: Hasher>(args: &ImmutableArgs) -> Result<AnyOutput, String> {
    validate_tree(&args.tree)?;
    if args.tree.location == 0 && !matches!(args.operation, ImmutableOperation::Commit) {
        return Err("location 0 is the bootstrap commit; require --operation commit".into());
    }
    if args.value_length.is_some() && matches!(args.encoding, Encoding::Fixed) {
        return Err("value-length requires --encoding variable".into());
    }
    match args.encoding {
        Encoding::Fixed => plain_proof::<F, H, _>(&args.tree, |index| {
            immutable_operation::<F, FixedEncoding<FixedBytes<32>>>(
                args,
                index,
                FixedBytes::new(leaf(args.tree.seed, index)),
            )
        }),
        Encoding::Variable => {
            let len = usize::from(
                args.value_length
                    .ok_or("variable encoding requires --value-length")?,
            );
            plain_proof::<F, H, _>(&args.tree, |index| {
                let bytes = leaf(args.tree.seed, index);
                immutable_operation::<F, qmdb::any::value::VariableEncoding<Vec<u8>>>(
                    args,
                    index,
                    bytes.into_iter().cycle().take(len).collect(),
                )
            })
        }
    }
}

fn unordered<F: Graftable, H: Hasher>(args: &UnorderedArgs) -> Result<Vec<u8>, String> {
    validate_tree(&args.tree)?;
    match (args.root, args.chunk_bytes) {
        (RootKind::Operations, Some(_)) => {
            return Err("--chunk-bytes requires --root current".into());
        }
        (RootKind::Current, None) => {
            return Err("--root current requires --chunk-bytes".into());
        }
        _ => {}
    }
    if args.value_length.is_some() && matches!(args.encoding, Encoding::Fixed) {
        return Err("value-length requires --encoding variable".into());
    }
    match (args.operation, args.history) {
        (UnorderedOperation::Update, None) => {
            return Err("--operation update requires --history".into());
        }
        (UnorderedOperation::Update, Some(History::Updated | History::Deleted))
            if args.tree.leaves < 2 =>
        {
            return Err("updated and deleted history require leaves >= 2".into());
        }
        (UnorderedOperation::Update, Some(_)) | (_, None) => {}
        (_, Some(_)) => return Err("--history requires --operation update".into()),
    }
    match args.encoding {
        Encoding::Fixed => {
            unordered_encoded::<F, H, FixedEncoding<FixedBytes<32>>>(args, |index| {
                FixedBytes::new(leaf(args.tree.seed, index))
            })
        }
        Encoding::Variable => {
            let len = usize::from(
                args.value_length
                    .ok_or("variable encoding requires --value-length")?,
            );
            unordered_encoded::<F, H, VariableEncoding<Vec<u8>>>(args, |index| {
                leaf(args.tree.seed, index)
                    .into_iter()
                    .cycle()
                    .take(len)
                    .collect()
            })
        }
    }
}

fn unordered_encoded<F: Graftable, H: Hasher, V: ValueEncoding>(
    args: &UnorderedArgs,
    value: impl Fn(u64) -> V::Value,
) -> Result<Vec<u8>, String>
where
    unordered::Operation<F, FixedBytes<32>, V>: Codec,
{
    let tree = &args.tree;
    let op = |index| {
        match args.history {
            Some(History::Deleted) if index + 1 == tree.leaves => {
                return unordered::Operation::Delete(key(0));
            }
            Some(History::Updated | History::Deleted) => {
                return unordered::Operation::Update(unordered::Update(key(0), value(index)));
            }
            Some(History::Indexed) | None => {}
        }
        if index == tree.location {
            match args.operation {
                UnorderedOperation::Update => {}
                UnorderedOperation::Delete => return unordered::Operation::Delete(key(0)),
                UnorderedOperation::Commit => {
                    return unordered::Operation::CommitFloor(
                        None,
                        Location::new(tree.inactivity_floor),
                    );
                }
                UnorderedOperation::CommitMetadata => {
                    return unordered::Operation::CommitFloor(
                        Some(value(index)),
                        Location::new(tree.inactivity_floor),
                    );
                }
            }
        }
        unordered::Operation::Update(unordered::Update(
            key(index % (tree.leaves - tree.inactivity_floor)),
            value(index),
        ))
    };
    if matches!(args.root, RootKind::Operations) {
        return plain_proof::<F, H, _>(tree, op).map(|output| output.abi_encode_params());
    }
    // Replay key ownership: only the latest surviving update and latest commit are active.
    let mut live = std::collections::BTreeMap::new();
    let mut commit = None;
    for index in 0..tree.leaves {
        match op(index) {
            unordered::Operation::Update(unordered::Update(key, _)) => {
                live.insert(key, index);
            }
            unordered::Operation::Delete(key) => {
                live.remove(&key);
            }
            unordered::Operation::CommitFloor(_, _) => commit = Some(index),
        }
    }
    let mut active = vec![false; usize::try_from(tree.leaves).map_err(|e| e.to_string())?];
    for index in live.into_values().chain(commit) {
        if index < tree.inactivity_floor {
            return Err("inactivity-floor crosses an active operation".into());
        }
        active[index as usize] = true;
    }
    let chunk_bytes = args
        .chunk_bytes
        .ok_or("--root current requires --chunk-bytes")?;
    let fixture = materialize::<F, H, _>(tree, chunk_bytes, op, |index| active[index as usize])?;
    let expected = fixture
        .proof
        .verify::<H, _>(op(tree.location), &fixture.root);
    Ok(current_output(fixture.output, expected))
}

fn current_output(output: OperationOutput, expected: bool) -> Vec<u8> {
    (
        output.root,
        output.leaves,
        output.location,
        output.inactivePeaks,
        output.chunk,
        output.opsRoot,
        output.pending,
        output.partial,
        output.digests,
        output.operation,
        expected,
    )
        .abi_encode_params()
}

struct Materialized<F: Graftable, D: Digest> {
    output: OperationOutput,
    proof: operation::Proof<F, D, Vec<u8>>,
    root: D,
}

struct CurrentTree<F: Graftable, D: Digest, const N: usize> {
    root: D,
    ops_root: D,
    ops: Mem<F, D>,
    grafted: Mem<F, D>,
    status: Prunable<N>,
    witness: OpsRootWitness<F, D>,
}

fn materialize_current<F: Graftable, H: Hasher, const N: usize>(
    args: &TreeArgs,
    encode: &dyn Fn(u64, &mut Vec<u8>),
    active: &dyn Fn(u64) -> bool,
) -> Result<CurrentTree<F, H::Digest, N>, String> {
    validate_tree(args)?;
    let TreeArgs {
        leaves,
        inactivity_floor,
        ..
    } = *args;
    let mut status = Prunable::<N>::new();
    for index in 0..leaves {
        status.push(active(index));
    }
    let chunk_bits = Prunable::<N>::CHUNK_SIZE_BITS;
    let height = grafting::height::<N>();
    let chunks: Vec<_> = (0..leaves.div_ceil(chunk_bits))
        .map(|index| status.get_chunk(index as usize).as_slice())
        .collect();
    let graftable = grafting::graftable_chunks::<F>(leaves, height);
    let hasher = qmdb::hasher::<H>();
    let verifier = grafting::Verifier::<F, H>::new(height, 0, chunks, graftable);
    let mut ops = Mem::<F, H::Digest>::new();
    let mut ops_batch = ops.new_batch();
    let mut grafted = Mem::<F, H::Digest>::new();
    let mut grafted_batch = grafted.new_batch();
    let mut encoded = Vec::new();
    for index in 0..leaves {
        encoded.clear();
        encode(index, &mut encoded);
        ops_batch = ops_batch.add(&hasher, &encoded);
        grafted_batch = grafted_batch.add(&verifier, &encoded);
    }
    let ops_batch = ops_batch.merkleize(&ops, &hasher);
    ops.apply_batch(&ops_batch).map_err(|e| e.to_string())?;
    let grafted_batch = grafted_batch.merkleize(&grafted, &verifier);
    grafted
        .apply_batch(&grafted_batch)
        .map_err(|e| e.to_string())?;

    let inactive_ops = F::inactive_peaks(Location::new(leaves), Location::new(inactivity_floor));
    let ops_root = ops.root(&hasher, inactive_ops).map_err(|e| e.to_string())?;
    // The maximal whole-peak prefix below a chunk-aligned floor is chunk-aligned.
    let inactive_current = F::inactive_peaks(
        Location::new(leaves),
        Location::new(inactivity_floor & !(chunk_bits - 1)),
    );
    let grafted_root = grafted
        .root(&hasher, inactive_current)
        .map_err(|e| e.to_string())?;
    let pending =
        (leaves / chunk_bits > graftable).then(|| H::hash(&[status.get_chunk(graftable as usize)]));
    let partial = (!leaves.is_multiple_of(chunk_bits)).then(|| {
        (
            leaves % chunk_bits,
            H::hash(&[status.get_chunk((leaves / chunk_bits) as usize)]),
        )
    });
    let witness = OpsRootWitness::<F, H::Digest> {
        grafted_root,
        pending_chunk_digest: pending.try_into().unwrap(),
        partial_chunk: partial,
    };
    let root = witness.root::<H>(&ops_root);
    Ok(CurrentTree {
        root,
        ops_root,
        ops,
        grafted,
        status,
        witness,
    })
}

fn materialize_singleton<F: Graftable, H: Hasher, const N: usize>(
    args: &TreeArgs,
    encode: &dyn Fn(u64, &mut Vec<u8>),
    active: &dyn Fn(u64) -> bool,
) -> Result<Materialized<F, H::Digest>, String> {
    let current = materialize_current::<F, H, N>(args, encode, active)?;
    let proof =
        futures::executor::block_on(operation::Proof::<F, H::Digest, [u8; N]>::new::<H, _>(
            &current.status,
            &current.grafted,
            Location::new(args.inactivity_floor),
            Location::new(args.location),
            current.ops_root,
        ))
        .map_err(|e| e.to_string())?;
    let proof = operation::Proof {
        loc: proof.loc,
        chunk: proof.chunk.to_vec(),
        range_proof: proof.range_proof,
    };
    let bytes32 = |digest: H::Digest| -> [u8; 32] { digest.as_ref().try_into().unwrap() };
    let mut encoded = Vec::new();
    encode(args.location, &mut encoded);
    let output = OperationOutput {
        root: bytes32(current.root).into(),
        leaves: Uint256::from(args.leaves),
        location: Uint256::from(args.location),
        inactivePeaks: Uint256::from(proof.range_proof.proof.inactive_peaks),
        chunk: proof.chunk.clone().into(),
        opsRoot: bytes32(current.ops_root).into(),
        pending: current
            .witness
            .pending_chunk_digest
            .as_ref()
            .copied()
            .map_or([0; 32], bytes32)
            .into(),
        partial: current
            .witness
            .partial_chunk
            .map_or([0; 32], |(_, digest)| bytes32(digest))
            .into(),
        digests: proof
            .range_proof
            .proof
            .digests
            .iter()
            .map(|d| bytes32(*d).into())
            .collect(),
        operation: encoded.into(),
    };
    Ok(Materialized {
        output,
        proof,
        root: current.root,
    })
}

fn materialize<F: Graftable, H: Hasher, O: Codec + Clone>(
    args: &TreeArgs,
    chunk_bytes: usize,
    operation: impl Fn(u64) -> O,
    active: impl Fn(u64) -> bool,
) -> Result<Materialized<F, H::Digest>, String> {
    let fixture = with_chunk_bytes!(chunk_bytes, |N| {
        materialize_singleton::<F, H, N>(
            args,
            &|index, bytes| operation(index).write(bytes),
            &active,
        )
    })?;
    let op = operation(args.location);
    if !fixture.proof.range_proof.verify_with_chunk_size::<H, _>(
        Location::new(args.location),
        core::slice::from_ref(&op),
        core::slice::from_ref(&fixture.proof.chunk),
        chunk_bytes,
        &fixture.root,
    ) || fixture.proof.verify::<H, _>(op, &fixture.root) != active(args.location)
    {
        return Err("Commonware rejected proof against the materialized canonical root".into());
    }
    Ok(fixture)
}

fn current<F: Graftable, H: Hasher>(args: &CurrentArgs) -> Result<OperationOutput, String> {
    materialize::<F, H, _>(
        &args.tree,
        args.chunk_bytes,
        |index| operation::<F>(args.tree.seed, index, args.tree.leaves),
        |index| index >= args.tree.inactivity_floor,
    )
    .map(|fixture| fixture.output)
}

impl Command {
    pub(crate) fn execute(self, hash: Hash) -> Result<Vec<u8>, String> {
        match self {
            Self::Lifecycle(args) => args.execute(hash),
            Self::Exclude(args) => args.execute(hash),
            Self::Range(args) => args.execute(hash),
            Self::Multi(args) => args.execute(hash),
            Self::Unordered(args) => match (args.tree.family, hash) {
                (TreeKind::Mmr, Hash::Keccak256) => unordered::<mmr::Family, Keccak256>(&args),
                (TreeKind::Mmr, Hash::Sha256) => unordered::<mmr::Family, Sha256>(&args),
                (TreeKind::Mmb, Hash::Keccak256) => unordered::<mmb::Family, Keccak256>(&args),
                (TreeKind::Mmb, Hash::Sha256) => unordered::<mmb::Family, Sha256>(&args),
            },
            Self::Any(args) => {
                let output = match (args.tree.family, hash) {
                    (TreeKind::Mmr, Hash::Keccak256) => any::<mmr::Family, Keccak256>(&args),
                    (TreeKind::Mmr, Hash::Sha256) => any::<mmr::Family, Sha256>(&args),
                    (TreeKind::Mmb, Hash::Keccak256) => any::<mmb::Family, Keccak256>(&args),
                    (TreeKind::Mmb, Hash::Sha256) => any::<mmb::Family, Sha256>(&args),
                }?;
                Ok(output.abi_encode_params())
            }
            Self::Keyless(args) => {
                let output = match (args.tree.family, hash) {
                    (TreeKind::Mmr, Hash::Keccak256) => keyless::<mmr::Family, Keccak256>(&args),
                    (TreeKind::Mmr, Hash::Sha256) => keyless::<mmr::Family, Sha256>(&args),
                    (TreeKind::Mmb, Hash::Keccak256) => keyless::<mmb::Family, Keccak256>(&args),
                    (TreeKind::Mmb, Hash::Sha256) => keyless::<mmb::Family, Sha256>(&args),
                }?;
                Ok(output.abi_encode_params())
            }
            Self::Immutable(args) => {
                let output = match (args.tree.family, hash) {
                    (TreeKind::Mmr, Hash::Keccak256) => immutable::<mmr::Family, Keccak256>(&args),
                    (TreeKind::Mmr, Hash::Sha256) => immutable::<mmr::Family, Sha256>(&args),
                    (TreeKind::Mmb, Hash::Keccak256) => immutable::<mmb::Family, Keccak256>(&args),
                    (TreeKind::Mmb, Hash::Sha256) => immutable::<mmb::Family, Sha256>(&args),
                }?;
                Ok(output.abi_encode_params())
            }
            Self::Current(args) => {
                let output = match (args.tree.family, hash) {
                    (TreeKind::Mmr, Hash::Keccak256) => current::<mmr::Family, Keccak256>(&args),
                    (TreeKind::Mmr, Hash::Sha256) => current::<mmr::Family, Sha256>(&args),
                    (TreeKind::Mmb, Hash::Keccak256) => current::<mmb::Family, Keccak256>(&args),
                    (TreeKind::Mmb, Hash::Sha256) => current::<mmb::Family, Sha256>(&args),
                }?;
                Ok(output.abi_encode_params())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Cli;
    use clap::Parser;
    use commonware_codec::{Copying, DecodeExt};
    use commonware_parallel::Sequential;
    use commonware_runtime::deterministic;
    use commonware_storage::{
        merkle::Proof,
        qmdb::{current::proof::RangeProof, sync::Database as _},
    };

    #[test]
    fn cli_requires_variable_value_length() {
        use clap::error::ErrorKind;

        for (command, operation) in [
            ("unordered", "update"),
            ("keyless", "append"),
            ("immutable", "set"),
        ] {
            let mut args = vec![
                "fuzz",
                "qmdb",
                "--hash",
                "keccak256",
                command,
                "--leaves",
                "3",
                "--location",
                "1",
                "--seed",
                "42",
                "--family",
                "mmb",
                "--inactivity-floor",
                "0",
                "--operation",
                operation,
                "--encoding",
                "variable",
            ];
            if command == "unordered" {
                args.extend(["--root", "operations", "--history", "indexed"]);
            }
            let error = Cli::try_parse_from(&args).err().unwrap();
            assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
            assert!(error.to_string().contains("--value-length"), "{error}");
            args.extend(["--value-length", "0"]);
            assert!(Cli::try_parse_from(&args).is_ok());
            let encoding = args.iter().position(|arg| *arg == "--encoding").unwrap() + 1;
            args[encoding] = "fixed";
            let error = Cli::try_parse_from(&args)
                .unwrap()
                .command
                .execute()
                .unwrap_err();
            assert!(
                error.contains("value-length requires --encoding variable"),
                "{error}"
            );
            args.truncate(args.len() - 2);
            assert!(Cli::try_parse_from(args).is_ok());
        }
    }

    #[test]
    fn cli_requires_explicit_named_inputs() {
        use clap::error::ErrorKind;

        for (command, selection) in [
            ("lifecycle", vec![]),
            (
                "any",
                vec!["--leaves", "3", "--location", "1", "--history", "indexed"],
            ),
            ("current", vec!["--leaves", "3", "--location", "1"]),
            (
                "unordered",
                vec![
                    "--leaves",
                    "3",
                    "--location",
                    "1",
                    "--encoding",
                    "fixed",
                    "--operation",
                    "update",
                    "--history",
                    "indexed",
                    "--root",
                    "operations",
                ],
            ),
            (
                "keyless",
                vec![
                    "--leaves",
                    "3",
                    "--location",
                    "1",
                    "--encoding",
                    "fixed",
                    "--operation",
                    "append",
                ],
            ),
            (
                "immutable",
                vec![
                    "--leaves",
                    "3",
                    "--location",
                    "1",
                    "--encoding",
                    "fixed",
                    "--operation",
                    "set",
                ],
            ),
            (
                "exclude",
                vec![
                    "--leaves",
                    "3",
                    "--location",
                    "1",
                    "--key",
                    "00",
                    "--mode",
                    "interval",
                    "--encoding",
                    "variable",
                    "--key-size",
                    "variable",
                    "--value-size",
                    "variable",
                    "--value-length",
                    "31",
                    "--keys",
                    "00,01,02",
                ],
            ),
            (
                "range",
                vec![
                    "--leaves",
                    "3",
                    "--start",
                    "1",
                    "--count",
                    "2",
                    "--variant",
                    "ordered",
                    "--encoding",
                    "fixed",
                    "--root",
                    "operations",
                ],
            ),
            (
                "multi",
                vec![
                    "--leaves",
                    "3",
                    "--locations",
                    "2,0,2",
                    "--variant",
                    "ordered",
                    "--encoding",
                    "fixed",
                    "--root",
                    "operations",
                ],
            ),
        ] {
            for hash in ["keccak256", "sha256"] {
                let mut args = vec![
                    "fuzz", "qmdb", "--hash", hash, command, "--seed", "42", "--family", "mmb",
                ];
                match command {
                    "any" | "unordered" | "keyless" | "immutable" | "range" | "multi" => {
                        args.extend(["--inactivity-floor", "0"]);
                    }
                    "current" => {
                        args.extend(["--inactivity-floor", "0", "--chunk-bytes", "32"]);
                    }
                    "exclude" => {
                        args.extend(["--chunk-bytes", "32"]);
                    }
                    "lifecycle" => {}
                    _ => unreachable!(),
                }
                args.extend_from_slice(&selection);
                assert!(Cli::try_parse_from(&args).is_ok(), "{args:?}");

                for index in (2..args.len()).filter(|&index| args[index].starts_with("--")) {
                    let mut missing = args.clone();
                    missing.drain(index..index + 2);
                    let error = Cli::try_parse_from(&missing).err().unwrap();
                    assert_eq!(
                        error.kind(),
                        ErrorKind::MissingRequiredArgument,
                        "{missing:?}: {error}"
                    );
                    assert!(error.to_string().contains(args[index]), "{error}");

                    if matches!(
                        args[index],
                        "--leaves"
                            | "--location"
                            | "--seed"
                            | "--start"
                            | "--count"
                            | "--locations"
                            | "--key"
                    ) {
                        let mut positional = args.clone();
                        positional.remove(index);
                        let error = Cli::try_parse_from(&positional).err().unwrap();
                        assert_eq!(
                            error.kind(),
                            ErrorKind::UnknownArgument,
                            "{positional:?}: {error}"
                        );
                    }
                }

                let mut misplaced = args.clone();
                misplaced.drain(2..4);
                misplaced.extend(["--hash", hash]);
                let error = Cli::try_parse_from(&misplaced).err().unwrap();
                assert_eq!(
                    error.kind(),
                    ErrorKind::UnknownArgument,
                    "{misplaced:?}: {error}"
                );

                args[3] = "blake3";
                let error = Cli::try_parse_from(&args).err().unwrap();
                assert_eq!(error.kind(), ErrorKind::InvalidValue, "{args:?}: {error}");
            }
        }
    }

    #[test]
    fn cli_requires_applicable_history_modes() {
        use clap::error::ErrorKind;

        let any = [
            "fuzz",
            "qmdb",
            "--hash",
            "keccak256",
            "any",
            "--leaves",
            "3",
            "--location",
            "1",
            "--seed",
            "42",
            "--family",
            "mmb",
            "--inactivity-floor",
            "0",
        ];
        let error = Cli::try_parse_from(any).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument, "{error}");
        assert!(error.to_string().contains("--history"), "{error}");

        let update = [
            "fuzz",
            "qmdb",
            "--hash",
            "keccak256",
            "unordered",
            "--leaves",
            "3",
            "--location",
            "1",
            "--seed",
            "42",
            "--family",
            "mmb",
            "--inactivity-floor",
            "0",
            "--encoding",
            "fixed",
            "--operation",
            "update",
            "--root",
            "operations",
        ];
        let error = Cli::try_parse_from(update).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument, "{error}");
        assert!(error.to_string().contains("--history"), "{error}");

        for history in ["updated", "deleted"] {
            let mut repeated = update.to_vec();
            let leaves = repeated.iter().position(|arg| *arg == "--leaves").unwrap() + 1;
            repeated[leaves] = "1";
            let location = repeated
                .iter()
                .position(|arg| *arg == "--location")
                .unwrap()
                + 1;
            repeated[location] = "0";
            repeated.extend(["--history", history]);
            let error = Cli::try_parse_from(repeated)
                .unwrap()
                .command
                .execute()
                .unwrap_err();
            assert_eq!(error, "updated and deleted history require leaves >= 2");
        }

        for operation in ["delete", "commit", "commit-metadata"] {
            for history in ["indexed", "updated", "deleted"] {
                let error = Cli::try_parse_from([
                    "fuzz",
                    "qmdb",
                    "--hash",
                    "keccak256",
                    "unordered",
                    "--leaves",
                    "3",
                    "--location",
                    "1",
                    "--seed",
                    "42",
                    "--family",
                    "mmb",
                    "--inactivity-floor",
                    "0",
                    "--encoding",
                    "fixed",
                    "--operation",
                    operation,
                    "--history",
                    history,
                    "--root",
                    "operations",
                ])
                .unwrap()
                .command
                .execute()
                .unwrap_err();
                assert_eq!(error, "--history requires --operation update");
            }
        }
    }

    #[test]
    fn cli_enforces_conditional_configuration() {
        use clap::error::ErrorKind;

        for (command, operation) in [
            ("any", None),
            ("keyless", Some("append")),
            ("immutable", Some("set")),
        ] {
            let mut args = vec![
                "fuzz",
                "qmdb",
                "--hash",
                "keccak256",
                command,
                "--leaves",
                "3",
                "--location",
                "1",
                "--seed",
                "42",
                "--family",
                "mmb",
                "--inactivity-floor",
                "0",
                "--chunk-bytes",
                "32",
            ];
            if let Some(operation) = operation {
                args.extend(["--encoding", "fixed", "--operation", operation]);
            } else {
                args.extend(["--history", "indexed"]);
            }
            let error = Cli::try_parse_from(args).err().unwrap();
            assert_eq!(error.kind(), ErrorKind::UnknownArgument, "{error}");
            assert!(error.to_string().contains("--chunk-bytes"), "{error}");
        }

        let current = [
            "fuzz",
            "qmdb",
            "--hash",
            "keccak256",
            "unordered",
            "--leaves",
            "3",
            "--location",
            "1",
            "--seed",
            "42",
            "--family",
            "mmb",
            "--inactivity-floor",
            "0",
            "--encoding",
            "fixed",
            "--operation",
            "update",
            "--history",
            "indexed",
            "--root",
            "current",
        ];
        let error = Cli::try_parse_from(current).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument, "{error}");
        assert!(error.to_string().contains("--chunk-bytes"), "{error}");

        let operations = current.iter().copied().take(current.len() - 1).chain([
            "operations",
            "--chunk-bytes",
            "32",
        ]);
        let error = Cli::try_parse_from(operations)
            .unwrap()
            .command
            .execute()
            .unwrap_err();
        assert_eq!(error, "--chunk-bytes requires --root current");

        let error = Cli::try_parse_from([
            "fuzz",
            "qmdb",
            "--hash",
            "keccak256",
            "exclude",
            "--leaves",
            "1",
            "--location",
            "0",
            "--seed",
            "42",
            "--family",
            "mmb",
            "--chunk-bytes",
            "32",
            "--key",
            "00",
            "--mode",
            "single",
            "--encoding",
            "fixed",
            "--key-size",
            "32",
            "--value-size",
            "32",
            "--keys",
            "00",
            "--inactivity-floor",
            "0",
        ])
        .err()
        .unwrap();
        assert_eq!(error.kind(), ErrorKind::UnknownArgument, "{error}");
        assert!(error.to_string().contains("--inactivity-floor"), "{error}");
    }

    #[test]
    fn exclude_cli_rejects_legacy_keyhex() {
        use clap::error::ErrorKind;

        let error = Cli::try_parse_from([
            "fuzz",
            "qmdb",
            "--hash",
            "keccak256",
            "exclude",
            "--leaves",
            "1",
            "--location",
            "0",
            "--seed",
            "42",
            "--family",
            "mmb",
            "--chunk-bytes",
            "32",
            "--keyhex",
            "00",
            "--mode",
            "single",
            "--encoding",
            "fixed",
            "--key-size",
            "32",
            "--value-size",
            "32",
            "--keys",
            "00",
        ])
        .err()
        .unwrap();
        assert_eq!(error.kind(), ErrorKind::UnknownArgument, "{error}");
        assert!(error.to_string().contains("--keyhex"), "{error}");
    }

    #[test]
    fn cli_rejects_legacy_current_flag() {
        use clap::error::ErrorKind;

        for tail in [
            vec![
                "unordered",
                "--leaves",
                "3",
                "--location",
                "1",
                "--operation",
                "update",
                "--history",
                "indexed",
                "--root",
                "operations",
            ],
            vec![
                "range",
                "--leaves",
                "3",
                "--start",
                "1",
                "--count",
                "2",
                "--variant",
                "ordered",
                "--root",
                "operations",
            ],
        ] {
            let args = [
                "fuzz",
                "qmdb",
                "--hash",
                "keccak256",
                tail[0],
                "--seed",
                "42",
                "--family",
                "mmb",
                "--inactivity-floor",
                "0",
                "--encoding",
                "fixed",
                "--current",
            ]
            .into_iter()
            .chain(tail.into_iter().skip(1));
            let error = Cli::try_parse_from(args).err().unwrap();
            assert_eq!(error.kind(), ErrorKind::UnknownArgument, "{error}");
            assert!(error.to_string().contains("--current"), "{error}");
        }
    }

    fn current_proof<F: Graftable, H: Hasher, const N: usize>(
        output: &OperationOutput,
    ) -> operation::Proof<F, H::Digest, [u8; N]> {
        let leaves = u64::try_from(output.leaves).unwrap();
        let digest = |bytes: &[u8]| H::Digest::decode(Copying(bytes)).unwrap();
        let chunk_bits = Prunable::<N>::CHUNK_SIZE_BITS;
        let graftable = grafting::graftable_chunks::<F>(leaves, grafting::height::<N>());
        operation::Proof {
            loc: Location::<F>::new(u64::try_from(output.location).unwrap()),
            chunk: output.chunk.as_ref().try_into().unwrap(),
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
                pending_chunk_digest: (leaves / chunk_bits > graftable)
                    .then(|| digest(output.pending.as_slice()))
                    .try_into()
                    .unwrap(),
                partial_chunk_digest: (!leaves.is_multiple_of(chunk_bits))
                    .then(|| digest(output.partial.as_slice())),
                ops_root: digest(output.opsRoot.as_slice()),
            },
        }
    }

    fn verify_output<F: Graftable, H: Hasher, const N: usize>(output: &OperationOutput) {
        let proof = current_proof::<F, H, N>(output);
        let digest = |bytes: &[u8]| H::Digest::decode(Copying(bytes)).unwrap();
        let op = Operation::<F>::decode(Copying(output.operation.as_ref())).unwrap();
        let root = digest(output.root.as_slice());
        assert!(proof.verify::<H, _>(op.clone(), &root));
        let mut inactive = proof;
        let bit = *inactive.loc % Prunable::<N>::CHUNK_SIZE_BITS;
        inactive.chunk[(bit / 8) as usize] &= !(1 << (bit % 8));
        assert!(!inactive.verify::<H, _>(op, &root));
    }

    fn verify_any_output<F: Family, H: Hasher>(output: &AnyOutput) {
        let digest = |bytes: &[u8]| H::Digest::decode(Copying(bytes)).unwrap();
        let proof = Proof::<F, H::Digest> {
            leaves: Location::new(u64::try_from(output.leaves).unwrap()),
            inactive_peaks: usize::try_from(output.inactivePeaks).unwrap(),
            digests: output
                .digests
                .iter()
                .map(|d| digest(d.as_slice()))
                .collect(),
        };
        let location = Location::new(u64::try_from(output.location).unwrap());
        let op = Operation::<F>::decode(Copying(output.operation.as_ref())).unwrap();
        let root = digest(output.root.as_slice());
        let verify = |proof: &Proof<F, H::Digest>, op: &Operation<F>, root: &H::Digest| {
            qmdb::verify_proof::<H, F, _>(proof, location, core::slice::from_ref(op), root)
        };
        assert!(verify(&proof, &op, &root));
        let mut bad_root = output.root.0;
        bad_root[0] ^= 1;
        assert!(!verify(&proof, &op, &digest(&bad_root)));
        let mut bad_op = op.clone();
        let Operation::Update(update) = &mut bad_op else {
            unreachable!()
        };
        update.value = FixedBytes::new([0xff; 32]);
        assert!(!verify(&proof, &bad_op, &root));
        let mut extra = proof.clone();
        extra.digests.push(root);
        assert!(!verify(&extra, &op, &root));
        if !proof.digests.is_empty() {
            let mut truncated = proof.clone();
            truncated.digests.pop();
            assert!(!verify(&truncated, &op, &root));
            let mut changed = proof;
            let mut bytes = changed.digests[0].as_ref().to_vec();
            bytes[0] ^= 1;
            changed.digests[0] = digest(&bytes);
            assert!(!verify(&changed, &op, &root));
        }
    }

    fn verify_keyless_output<F: Family, H: Hasher>(
        output: &AnyOutput,
        encoding: &str,
        operation: &str,
        seed: u64,
        floor: u64,
    ) {
        use commonware_codec::Decode;
        use keyless::Operation::{Append, Commit};
        let digest = |bytes: &[u8]| H::Digest::decode(Copying(bytes)).unwrap();
        let proof = Proof::<F, H::Digest> {
            leaves: Location::new(u64::try_from(output.leaves).unwrap()),
            inactive_peaks: usize::try_from(output.inactivePeaks).unwrap(),
            digests: output
                .digests
                .iter()
                .map(|d| digest(d.as_slice()))
                .collect(),
        };
        let location = Location::new(u64::try_from(output.location).unwrap());
        let root = digest(output.root.as_slice());
        let expected_value = leaf(seed, *location);
        let encoded = output.operation.as_ref();
        let verify = |bytes: &[u8]| {
            proof.verify_element_inclusion(&qmdb::hasher::<H>(), bytes, location, &root)
        };
        match encoding {
            "fixed" => {
                let op = keyless::fixed::Operation::<F, FixedBytes<32>>::decode(Copying(encoded))
                    .unwrap();
                assert_eq!(encoded.len(), 42);
                match (&op, operation) {
                    (Append(value), "append") => {
                        assert_eq!(value.as_ref(), expected_value);
                        assert_eq!(&encoded[33..], &[0; 9]);
                    }
                    (Commit(metadata, actual_floor), "commit" | "commit-metadata") => {
                        assert_eq!(**actual_floor, floor);
                        assert_eq!(
                            *metadata,
                            (operation == "commit-metadata")
                                .then(|| FixedBytes::new(expected_value))
                        );
                    }
                    _ => panic!("unexpected operation"),
                }
                assert!(qmdb::verify_proof::<H, F, _>(
                    &proof,
                    location,
                    &[op],
                    &root
                ));
            }
            _ => {
                let op = keyless::variable::Operation::<F, Vec<u8>>::decode_cfg(
                    Copying(encoded),
                    &((0..=129).into(), ()),
                )
                .unwrap();
                let len = VARIABLE_LENGTHS[seed as usize % VARIABLE_LENGTHS.len()];
                let value: Vec<_> = expected_value.into_iter().cycle().take(len).collect();
                match (&op, operation) {
                    (Append(actual), "append") => assert_eq!(*actual, value),
                    (Commit(metadata, actual_floor), "commit" | "commit-metadata") => {
                        assert_eq!(**actual_floor, floor);
                        assert_eq!(*metadata, (operation == "commit-metadata").then_some(value));
                    }
                    _ => panic!("unexpected operation"),
                }
                assert!(qmdb::verify_proof::<H, F, _>(
                    &proof,
                    location,
                    &[op],
                    &root
                ));
            }
        }
        if *proof.leaves == 1 {
            let initial = match encoding {
                "fixed" => keyless::fixed::Db::<
                    F,
                    deterministic::Context,
                    FixedBytes<32>,
                    H,
                    Sequential,
                >::initial_target()
                .root,
                _ => keyless::variable::Db::<
                    F,
                    deterministic::Context,
                    Vec<u8>,
                    H,
                    Sequential,
                >::initial_target()
                .root,
            };
            assert_eq!(root, initial);
        }
        assert!(verify(encoded));
        let mut changed = encoded.to_vec();
        *changed.last_mut().unwrap() ^= 1;
        assert!(!verify(&changed));
    }

    fn check_unordered<F: Graftable, H: Hasher, O: Codec + Clone>(
        encoded: &[u8],
        root_kind: RootKind,
        cfg: &O::Cfg,
        expected: bool,
        inactive: bool,
    ) {
        let digest = |bytes: &[u8]| H::Digest::decode(Copying(bytes)).unwrap();
        if matches!(root_kind, RootKind::Current) {
            type ResultTuple = <sol!((bytes32, uint256, uint256, uint256, bytes, bytes32, bytes32, bytes32, bytes32[], bytes, bool)) as SolType>::RustType;
            let (
                root,
                leaves,
                location,
                inactive_peaks,
                chunk,
                ops_root,
                pending,
                partial,
                digests,
                operation,
                verdict,
            ) = ResultTuple::abi_decode_params_validate(encoded).unwrap();
            assert_eq!(verdict, expected);
            let output = OperationOutput {
                root,
                leaves,
                location,
                inactivePeaks: inactive_peaks,
                chunk,
                opsRoot: ops_root,
                pending,
                partial,
                digests,
                operation,
            };
            let op = O::decode_cfg(Copying(output.operation.as_ref()), cfg).unwrap();
            assert_eq!(op.encode().as_ref(), output.operation.as_ref());
            let proof = current_proof::<F, H, 32>(&output);
            let root = digest(output.root.as_slice());
            assert!(proof.range_proof.verify::<H, _, 32>(
                proof.loc,
                core::slice::from_ref(&op),
                &[proof.chunk],
                &root
            ));
            assert_eq!(proof.verify::<H, _>(op.clone(), &root), expected);
            let bit = *proof.loc % 256;
            assert_eq!(
                proof.chunk[(bit / 8) as usize] & (1 << (bit % 8)) != 0,
                expected
            );
            let mut forged = proof;
            forged.chunk[(bit / 8) as usize] ^= 1 << (bit % 8);
            assert!(!forged.verify::<H, _>(op, &root));
            if inactive {
                assert_ne!(output.inactivePeaks, 0);
            }
        } else {
            let output = <AnyOutput as SolValue>::abi_decode_params_validate(encoded).unwrap();
            let op = O::decode_cfg(Copying(output.operation.as_ref()), cfg).unwrap();
            assert_eq!(op.encode().as_ref(), output.operation.as_ref());
            let proof = Proof::<F, H::Digest> {
                leaves: Location::new(u64::try_from(output.leaves).unwrap()),
                inactive_peaks: usize::try_from(output.inactivePeaks).unwrap(),
                digests: output
                    .digests
                    .iter()
                    .map(|d| digest(d.as_slice()))
                    .collect(),
            };
            assert!(qmdb::verify_proof::<H, F, _>(
                &proof,
                Location::new(u64::try_from(output.location).unwrap()),
                &[op],
                &digest(output.root.as_slice())
            ));
            if inactive {
                assert_ne!(output.inactivePeaks, 0);
            }
        }
    }

    fn unordered_matrix<F: Graftable, H: Hasher>(family: &str, hash: &str) {
        for encoding in ["fixed", "variable"] {
            for root_kind in [RootKind::Operations, RootKind::Current] {
                for (leaves, location, floor, operation, history, expected) in [
                    (1u64, 0u64, 0u64, "update", "indexed", true),
                    (1023, 1022, 768, "update", "indexed", true),
                    (257, 256, 0, "delete", "", false),
                    (383, 382, 0, "commit", "", true),
                    (639, 638, 0, "commit-metadata", "", true),
                    (255, 0, 0, "update", "updated", false),
                    (256, 255, 0, "update", "updated", true),
                    (257, 0, 0, "update", "deleted", false),
                    (513, 512, 0, "update", "deleted", false),
                ] {
                    for length in VARIABLE_LENGTHS {
                        let mut args = vec![
                            "fuzz".to_owned(),
                            "qmdb".into(),
                            "--hash".into(),
                            hash.into(),
                            "unordered".into(),
                            "--leaves".into(),
                            leaves.to_string(),
                            "--location".into(),
                            location.to_string(),
                            "--seed".into(),
                            "71".into(),
                            "--family".into(),
                            family.into(),
                            "--inactivity-floor".into(),
                            floor.to_string(),
                            "--encoding".into(),
                            encoding.into(),
                            "--operation".into(),
                            operation.into(),
                            "--root".into(),
                            match root_kind {
                                RootKind::Operations => "operations".into(),
                                RootKind::Current => "current".into(),
                            },
                        ];
                        if matches!(root_kind, RootKind::Current) {
                            args.extend(["--chunk-bytes".into(), "32".into()]);
                        }
                        if !history.is_empty() {
                            args.extend(["--history".into(), history.into()]);
                        }
                        if encoding == "variable" {
                            args.extend(["--value-length".into(), length.to_string()]);
                        }
                        let encoded = Cli::try_parse_from(args)
                            .unwrap()
                            .command
                            .execute()
                            .unwrap();
                        if encoding == "fixed" {
                            check_unordered::<
                                F,
                                H,
                                unordered::fixed::Operation<F, FixedBytes<32>, FixedBytes<32>>,
                            >(
                                &encoded, root_kind, &(), expected, floor != 0
                            );
                            break;
                        } else {
                            check_unordered::<
                                F,
                                H,
                                unordered::variable::Operation<F, FixedBytes<32>, Vec<u8>>,
                            >(
                                &encoded,
                                root_kind,
                                &((), ((0..=129).into(), ())),
                                expected,
                                floor != 0,
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn unordered_cli_rejects_invalid_options_and_active_floors() {
        for tail in [
            vec![
                "--leaves",
                "0",
                "--location",
                "0",
                "--seed",
                "71",
                "--family",
                "mmb",
                "--inactivity-floor",
                "0",
                "--root",
                "operations",
                "--encoding",
                "fixed",
                "--operation",
                "update",
                "--history",
                "indexed",
            ],
            vec![
                "--leaves",
                "1000001",
                "--location",
                "0",
                "--seed",
                "71",
                "--family",
                "mmb",
                "--inactivity-floor",
                "0",
                "--root",
                "operations",
                "--encoding",
                "fixed",
                "--operation",
                "update",
                "--history",
                "indexed",
            ],
            vec![
                "--leaves",
                "3",
                "--location",
                "3",
                "--seed",
                "71",
                "--family",
                "mmb",
                "--inactivity-floor",
                "0",
                "--root",
                "operations",
                "--encoding",
                "fixed",
                "--operation",
                "update",
                "--history",
                "indexed",
            ],
            vec![
                "--leaves",
                "3",
                "--location",
                "1",
                "--seed",
                "71",
                "--inactivity-floor",
                "2",
                "--family",
                "mmb",
                "--root",
                "operations",
                "--encoding",
                "fixed",
                "--operation",
                "update",
                "--history",
                "indexed",
            ],
            vec![
                "--leaves",
                "3",
                "--location",
                "1",
                "--seed",
                "71",
                "--value-length",
                "32",
                "--family",
                "mmb",
                "--inactivity-floor",
                "0",
                "--root",
                "operations",
                "--encoding",
                "fixed",
                "--operation",
                "update",
                "--history",
                "indexed",
            ],
            vec![
                "--leaves",
                "1",
                "--location",
                "0",
                "--seed",
                "71",
                "--history",
                "updated",
                "--family",
                "mmb",
                "--inactivity-floor",
                "0",
                "--root",
                "operations",
                "--encoding",
                "fixed",
                "--operation",
                "update",
            ],
            vec![
                "--leaves",
                "3",
                "--location",
                "1",
                "--seed",
                "71",
                "--history",
                "updated",
                "--operation",
                "delete",
                "--family",
                "mmb",
                "--inactivity-floor",
                "0",
                "--root",
                "operations",
                "--encoding",
                "fixed",
            ],
            vec![
                "--leaves",
                "3",
                "--location",
                "2",
                "--seed",
                "71",
                "--root",
                "current",
                "--inactivity-floor",
                "2",
                "--operation",
                "commit",
                "--family",
                "mmb",
                "--chunk-bytes",
                "32",
                "--encoding",
                "fixed",
            ],
        ] {
            let result = Cli::try_parse_from(
                ["fuzz", "qmdb", "--hash", "keccak256", "unordered"]
                    .into_iter()
                    .chain(tail),
            )
            .unwrap()
            .command
            .execute();
            assert!(result.is_err());
        }
    }

    #[test]
    fn unordered_cli_codecs_activity_and_inactive_prefixes() {
        unordered_matrix::<mmr::Family, Keccak256>("mmr", "keccak256");
        unordered_matrix::<mmr::Family, Sha256>("mmr", "sha256");
        unordered_matrix::<mmb::Family, Keccak256>("mmb", "keccak256");
        unordered_matrix::<mmb::Family, Sha256>("mmb", "sha256");
    }

    #[test]
    fn immutable_cli_codecs_operations_and_inactive_prefixes() {
        for family in ["mmr", "mmb"] {
            for hash in ["keccak256", "sha256"] {
                for encoding in ["fixed", "variable"] {
                    for operation in ["set", "commit", "commit-metadata"] {
                        for (leaves, location, floor) in
                            [(1u64, 0u64, 0u64), (2, 1, 0), (1023, 1022, 512)]
                        {
                            if location == 0 && operation != "commit" {
                                continue;
                            }
                            let mut args = vec![
                                "fuzz".to_string(),
                                "qmdb".into(),
                                "--hash".into(),
                                hash.into(),
                                "immutable".into(),
                                "--leaves".into(),
                                leaves.to_string(),
                                "--location".into(),
                                location.to_string(),
                                "--seed".into(),
                                "71".into(),
                                "--family".into(),
                                family.into(),
                                "--encoding".into(),
                                encoding.into(),
                                "--operation".into(),
                                operation.into(),
                                "--inactivity-floor".into(),
                                floor.to_string(),
                            ];
                            if encoding == "variable" {
                                args.extend(["--value-length".into(), "128".into()]);
                            }
                            let bytes = Cli::try_parse_from(args)
                                .unwrap()
                                .command
                                .execute()
                                .unwrap();
                            let output =
                                <AnyOutput as SolValue>::abi_decode_params_validate(&bytes)
                                    .unwrap();
                            assert_eq!(output.leaves, leaves);
                            assert_eq!(output.location, location);
                            if floor != 0 {
                                assert_ne!(output.inactivePeaks, 0);
                            }
                            let mut expected = vec![u8::from(operation != "set")];
                            if operation == "set" {
                                expected.extend_from_slice(key(location).as_ref());
                            } else {
                                expected.push(u8::from(operation == "commit-metadata"));
                            }
                            if operation != "commit" {
                                let value = leaf(71, location);
                                if encoding == "variable" {
                                    expected.extend_from_slice(&[0x80, 0x01]);
                                    expected.extend(value.into_iter().cycle().take(128));
                                } else {
                                    expected.extend_from_slice(&value);
                                }
                            } else if encoding == "fixed" {
                                expected.extend_from_slice(&[0; 32]);
                            }
                            if operation != "set" {
                                if encoding == "fixed" {
                                    expected.extend_from_slice(&floor.to_be_bytes());
                                    expected.extend_from_slice(&[0; 23]);
                                } else if floor == 512 {
                                    expected.extend_from_slice(&[0x80, 0x04]);
                                } else {
                                    expected.push(0);
                                }
                            }
                            assert_eq!(output.operation.as_ref(), expected.as_slice());
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn immutable_cli_rejects_invalid_arguments() {
        for (leaves, location, floor, operation, length) in [
            (0, 0, 0, "commit", None),
            (1_000_001, 1, 0, "set", None),
            (3, 3, 0, "set", None),
            (3, 1, 2, "set", None),
            (1, 0, 0, "set", None),
            (1, 0, 0, "commit-metadata", None),
            (2, 1, 0, "set", Some("32")),
        ] {
            let mut args = vec![
                "fuzz".to_string(),
                "qmdb".into(),
                "--hash".into(),
                "keccak256".into(),
                "immutable".into(),
                "--leaves".into(),
                leaves.to_string(),
                "--location".into(),
                location.to_string(),
                "--seed".into(),
                "71".into(),
                "--inactivity-floor".into(),
                floor.to_string(),
                "--operation".into(),
                operation.into(),
                "--family".into(),
                "mmb".into(),
                "--encoding".into(),
                "fixed".into(),
            ];
            if let Some(length) = length {
                args.extend(["--value-length".into(), length.into()]);
            }
            assert!(
                Cli::try_parse_from(args)
                    .unwrap()
                    .command
                    .execute()
                    .is_err()
            );
        }
    }

    #[test]
    fn keyless_cli_variable_lengths() {
        use commonware_codec::Decode;
        for length in [0u16, 31, 32, 33, 127, 128, 65535] {
            for operation in ["append", "commit-metadata"] {
                let args = [
                    "fuzz",
                    "qmdb",
                    "--hash",
                    "keccak256",
                    "keyless",
                    "--leaves",
                    "3",
                    "--location",
                    "1",
                    "--seed",
                    "42",
                    "--encoding",
                    "variable",
                    "--operation",
                    operation,
                    "--value-length",
                    &length.to_string(),
                    "--family",
                    "mmb",
                    "--inactivity-floor",
                    "0",
                ];
                let encoded = Cli::try_parse_from(args)
                    .unwrap()
                    .command
                    .execute()
                    .unwrap();
                let output = <AnyOutput as SolValue>::abi_decode_params_validate(&encoded).unwrap();
                let op = keyless::variable::Operation::<mmb::Family, Vec<u8>>::decode_cfg(
                    Copying(output.operation.as_ref()),
                    &((0..=65535).into(), ()),
                )
                .unwrap();
                let expected: Vec<_> = leaf(42, 1)
                    .into_iter()
                    .cycle()
                    .take(usize::from(length))
                    .collect();
                assert_eq!(op.into_value(), Some(expected));
            }
        }
        let result = Cli::try_parse_from([
            "fuzz",
            "qmdb",
            "--hash",
            "keccak256",
            "keyless",
            "--leaves",
            "3",
            "--location",
            "1",
            "--seed",
            "42",
            "--value-length",
            "32",
            "--family",
            "mmb",
            "--inactivity-floor",
            "0",
            "--encoding",
            "fixed",
            "--operation",
            "append",
        ])
        .unwrap()
        .command
        .execute();
        assert!(result.is_err());
    }

    #[test]
    fn keyless_cli_rejects_invalid_log_boundaries() {
        for (leaves, location, floor, operation) in [
            (0, 0, 0, "commit"),
            (1_000_001, 1, 0, "append"),
            (3, 3, 0, "append"),
            (3, 1, 2, "append"),
            (1, 0, 0, "append"),
            (1, 0, 0, "commit-metadata"),
        ] {
            let result = Cli::try_parse_from([
                "fuzz",
                "qmdb",
                "--hash",
                "keccak256",
                "keyless",
                "--leaves",
                &leaves.to_string(),
                "--location",
                &location.to_string(),
                "--seed",
                "42",
                "--inactivity-floor",
                &floor.to_string(),
                "--operation",
                operation,
                "--family",
                "mmb",
                "--encoding",
                "fixed",
            ])
            .unwrap()
            .command
            .execute();
            assert!(result.is_err());
        }
    }

    #[test]
    fn keyless_cli_covers_codecs_operations_and_inactive_prefixes() {
        for family in ["mmr", "mmb"] {
            for hash in ["keccak256", "sha256"] {
                for encoding in ["fixed", "variable"] {
                    for operation in ["append", "commit", "commit-metadata"] {
                        for (leaves, location, floor) in [
                            (1u64, 0u64, 0u64),
                            (3, 1, 0),
                            (11, 9, 8),
                            (257, 256, 128),
                            (1793, 1792, 1792),
                        ] {
                            if location == 0 && operation != "commit" {
                                continue;
                            }
                            for seed in 0..8u64 {
                                let length = VARIABLE_LENGTHS[seed as usize].to_string();
                                let length_args = if encoding == "variable" {
                                    vec!["--value-length", length.as_str()]
                                } else {
                                    vec![]
                                };
                                let encoded = Cli::try_parse_from(
                                    [
                                        "fuzz",
                                        "qmdb",
                                        "--hash",
                                        hash,
                                        "keyless",
                                        "--leaves",
                                        &leaves.to_string(),
                                        "--location",
                                        &location.to_string(),
                                        "--seed",
                                        &seed.to_string(),
                                        "--family",
                                        family,
                                        "--inactivity-floor",
                                        &floor.to_string(),
                                        "--encoding",
                                        encoding,
                                        "--operation",
                                        operation,
                                    ]
                                    .into_iter()
                                    .chain(length_args),
                                )
                                .unwrap()
                                .command
                                .execute()
                                .unwrap();
                                let output =
                                    <AnyOutput as SolValue>::abi_decode_params_validate(&encoded)
                                        .unwrap();
                                assert_eq!(output.leaves, leaves);
                                assert_eq!(output.location, location);
                                if leaves == 1793 {
                                    assert_ne!(output.inactivePeaks, 0);
                                }
                                match (family, hash) {
                                    ("mmr", "keccak256") => {
                                        verify_keyless_output::<mmr::Family, Keccak256>(
                                            &output, encoding, operation, seed, floor,
                                        )
                                    }
                                    ("mmr", _) => verify_keyless_output::<mmr::Family, Sha256>(
                                        &output, encoding, operation, seed, floor,
                                    ),
                                    (_, "keccak256") => {
                                        verify_keyless_output::<mmb::Family, Keccak256>(
                                            &output, encoding, operation, seed, floor,
                                        )
                                    }
                                    _ => verify_keyless_output::<mmb::Family, Sha256>(
                                        &output, encoding, operation, seed, floor,
                                    ),
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn any_cli_covers_boundaries_inactive_prefixes_and_history() {
        for family in ["mmr", "mmb"] {
            for hash in ["keccak256", "sha256"] {
                for leaves in [1u64, 2, 3, 7, 11, 31, 255, 256, 257, 383, 513, 1793] {
                    for location in [0, leaves / 2, leaves - 1] {
                        for floor in [0, location] {
                            for history in ["indexed", "updated", "deleted"] {
                                if history != "indexed" && (leaves < 2 || location != 0) {
                                    continue;
                                }
                                let args = vec![
                                    "fuzz".to_owned(),
                                    "qmdb".into(),
                                    "--hash".into(),
                                    hash.into(),
                                    "any".into(),
                                    "--leaves".into(),
                                    leaves.to_string(),
                                    "--location".into(),
                                    location.to_string(),
                                    "--seed".into(),
                                    "42".into(),
                                    "--family".into(),
                                    family.into(),
                                    "--inactivity-floor".into(),
                                    floor.to_string(),
                                    "--history".into(),
                                    history.into(),
                                ];
                                let encoded = Cli::try_parse_from(args)
                                    .unwrap()
                                    .command
                                    .execute()
                                    .unwrap();
                                let output =
                                    <AnyOutput as SolValue>::abi_decode_params_validate(&encoded)
                                        .unwrap();
                                assert_eq!(output.leaves, leaves);
                                assert_eq!(output.location, location);
                                assert_eq!(output.operation.len(), 97);
                                assert_eq!(output.operation[0], 0xD2);
                                match (family, hash) {
                                    ("mmr", "keccak256") => {
                                        verify_any_output::<mmr::Family, Keccak256>(&output)
                                    }
                                    ("mmr", _) => verify_any_output::<mmr::Family, Sha256>(&output),
                                    (_, "keccak256") => {
                                        verify_any_output::<mmb::Family, Keccak256>(&output)
                                    }
                                    _ => verify_any_output::<mmb::Family, Sha256>(&output),
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn any_history_contains_later_mutations_of_the_proven_key() {
        for history in [History::Updated, History::Deleted] {
            let args = AnyArgs {
                tree: TreeArgs {
                    leaves: 3,
                    location: 0,
                    seed: 42,
                    family: TreeKind::Mmb,
                    inactivity_floor: 0,
                },
                history,
            };
            let Operation::Update(first) = any_operation::<mmb::Family>(&args, 0) else {
                unreachable!()
            };
            assert_eq!(first.key, key(0));
            assert_eq!(first.next_key, key(0));
            match any_operation::<mmb::Family>(&args, 2) {
                Operation::Update(last) => {
                    assert_eq!(last.key, first.key);
                    assert_eq!(last.next_key, first.next_key);
                    assert_ne!(last.value, first.value);
                }
                Operation::Delete(key) => assert_eq!(key, first.key),
                _ => unreachable!(),
            }
            let before = any::<mmb::Family, Keccak256>(&AnyArgs {
                tree: TreeArgs {
                    leaves: 1,
                    ..args.tree
                },
                history: History::Indexed,
            })
            .unwrap();
            let output = any::<mmb::Family, Keccak256>(&args).unwrap();
            assert_eq!(before.operation, output.operation);
            assert_ne!(before.root, output.root);
            verify_any_output::<mmb::Family, Keccak256>(&before);
            assert_eq!(
                output.operation.as_ref(),
                any_operation::<mmb::Family>(&args, 0).encode().as_ref()
            );
            verify_any_output::<mmb::Family, Keccak256>(&output);
            assert!(
                any::<mmb::Family, Keccak256>(&AnyArgs {
                    tree: TreeArgs {
                        leaves: 1,
                        ..args.tree
                    },
                    history,
                })
                .is_err()
            );
            assert!(
                any::<mmb::Family, Keccak256>(&AnyArgs {
                    tree: TreeArgs {
                        location: 1,
                        ..args.tree
                    },
                    history,
                })
                .is_err()
            );
        }
    }

    #[test]
    fn materialized_current_proofs_cover_chunk_boundaries() {
        for family in ["mmr", "mmb"] {
            for hash in ["keccak256", "sha256"] {
                for leaves in [
                    1u64, 255, 256, 257, 382, 383, 384, 511, 512, 513, 638, 639, 640, 769, 1024,
                    1793, 4097,
                ] {
                    for location in [0, leaves / 2, leaves - 1] {
                        for floor in [0, location] {
                            let encoded = Cli::try_parse_from([
                                "fuzz",
                                "qmdb",
                                "--hash",
                                hash,
                                "current",
                                "--leaves",
                                &leaves.to_string(),
                                "--location",
                                &location.to_string(),
                                "--seed",
                                "42",
                                "--family",
                                family,
                                "--inactivity-floor",
                                &floor.to_string(),
                                "--chunk-bytes",
                                "32",
                            ])
                            .unwrap()
                            .command
                            .execute()
                            .unwrap();
                            let output =
                                <OperationOutput as SolValue>::abi_decode_params_validate(&encoded)
                                    .unwrap();
                            match (family, hash) {
                                ("mmr", "keccak256") => {
                                    verify_output::<mmr::Family, Keccak256, 32>(&output)
                                }
                                ("mmr", _) => verify_output::<mmr::Family, Sha256, 32>(&output),
                                (_, "keccak256") => {
                                    verify_output::<mmb::Family, Keccak256, 32>(&output)
                                }
                                _ => verify_output::<mmb::Family, Sha256, 32>(&output),
                            }
                            assert_eq!(output.leaves, leaves);
                            assert_eq!(output.location, location);
                            assert_eq!(output.operation.len(), 97);
                            assert_eq!(output.operation[0], 0xD2);
                            assert_ne!(
                                output.chunk[(location % 256 / 8) as usize] & (1 << (location % 8)),
                                0
                            );
                            let graftable = match family {
                                "mmr" => leaves / 256,
                                _ if leaves < 383 => 0,
                                _ => (leaves - 383) / 256 + 1,
                            };
                            assert_eq!(output.pending != [0; 32], leaves / 256 > graftable);
                            assert_eq!(output.partial != [0; 32], leaves % 256 != 0);
                            if family == "mmb" && leaves == 513 && floor == 512 {
                                assert_ne!(output.inactivePeaks, 0);
                            }
                            if family == "mmr" {
                                if leaves.is_power_of_two() {
                                    assert_eq!(output.inactivePeaks, 0);
                                } else if leaves == 513 && floor == 512 {
                                    assert_eq!(output.inactivePeaks, 1);
                                } else if leaves == 1793 && floor == 1792 {
                                    assert_eq!(output.inactivePeaks, 3);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn exclusion_matches_cyclic_intervals_and_empty_commits() {
        type ExclusionOutput = <sol!((bytes32, uint256, uint256, uint256, bytes, bytes32, bytes32, bytes32, bytes32[], bytes, bool)) as SolType>::RustType;
        for family in ["mmr", "mmb"] {
            for hash in ["keccak256", "sha256"] {
                for leaves in [1u64, 256, 257, 383, 513] {
                    for location in [0, leaves - 1] {
                        for mode in ["interval", "single", "empty"] {
                            for metadata in [false, true] {
                                if metadata && mode != "empty" {
                                    continue;
                                }
                                let start = 2 * (location + 1);
                                let end = 2 * ((location + 1) % leaves + 1);
                                let keys = match mode {
                                    "interval" => Some(
                                        (1..=leaves)
                                            .map(|index| const_hex::encode(key(2 * index)))
                                            .collect::<Vec<_>>()
                                            .join(","),
                                    ),
                                    "single" => Some(const_hex::encode(key(start))),
                                    _ => None,
                                };
                                for query in [0, start - 1, start, start + 1, end, u64::MAX] {
                                    let query_hex = const_hex::encode(key(query));
                                    let mut arguments = vec![
                                        "fuzz".to_owned(),
                                        "qmdb".into(),
                                        "--hash".into(),
                                        hash.into(),
                                        "exclude".into(),
                                        "--leaves".into(),
                                        leaves.to_string(),
                                        "--location".into(),
                                        location.to_string(),
                                        "--seed".into(),
                                        "42".into(),
                                        "--key".into(),
                                        query_hex,
                                        "--family".into(),
                                        family.into(),
                                        "--mode".into(),
                                        mode.into(),
                                        "--encoding".into(),
                                        "fixed".into(),
                                        "--key-size".into(),
                                        "32".into(),
                                        "--value-size".into(),
                                        "32".into(),
                                        "--chunk-bytes".into(),
                                        "32".into(),
                                    ];
                                    if let Some(keys) = &keys {
                                        arguments.extend(["--keys".into(), keys.clone()]);
                                    } else {
                                        arguments.push("--derive-keys".into());
                                    }
                                    if metadata {
                                        arguments.push("--metadata".into());
                                    }
                                    let result =
                                        Cli::try_parse_from(arguments).unwrap().command.execute();
                                    if mode != "interval" && location != leaves - 1 {
                                        assert!(result.is_err());
                                        continue;
                                    }
                                    let encoded = result.unwrap();
                                    let output =
                                        ExclusionOutput::abi_decode_params_validate(&encoded)
                                            .unwrap();
                                    let expected = match mode {
                                        "empty" => true,
                                        "single" => query != start,
                                        _ if start == end => query != start,
                                        _ if start < end => query > start && query < end,
                                        _ => query > start || query < end,
                                    };
                                    assert_eq!(
                                        output.10, expected,
                                        "{family} {hash} {leaves} {location} {mode} {metadata} {query}"
                                    );
                                    assert_eq!(output.1, leaves);
                                    assert_eq!(output.2, location);
                                    assert_eq!(output.9.len(), 97);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn current_singletons_use_configured_bitmap_chunks() {
        for chunk_bytes in [1usize, 2, 16, 32, 64, 128] {
            let chunk_bits = u64::try_from(chunk_bytes * 8).unwrap();
            let leaves = 2 * chunk_bits + 3;
            let location = chunk_bits + 1;
            for family in ["mmr", "mmb"] {
                let encoded = Cli::try_parse_from([
                    "fuzz",
                    "qmdb",
                    "--hash",
                    "keccak256",
                    "current",
                    "--leaves",
                    &leaves.to_string(),
                    "--location",
                    &location.to_string(),
                    "--seed",
                    "42",
                    "--family",
                    family,
                    "--chunk-bytes",
                    &chunk_bytes.to_string(),
                    "--inactivity-floor",
                    "0",
                ])
                .unwrap()
                .command
                .execute()
                .unwrap();
                let output =
                    <OperationOutput as SolValue>::abi_decode_params_validate(&encoded).unwrap();
                assert_eq!(output.chunk.len(), chunk_bytes);
                with_chunk_bytes!(chunk_bytes, |N| {
                    match family {
                        "mmr" => verify_output::<mmr::Family, Keccak256, N>(&output),
                        _ => verify_output::<mmb::Family, Keccak256, N>(&output),
                    }
                    Ok::<(), String>(())
                })
                .unwrap();
            }
        }
    }

    #[test]
    fn current_cli_rejects_unavailable_chunk_sizes() {
        for chunk_bytes in [0usize, 3, 256] {
            let result = Cli::try_parse_from([
                "fuzz",
                "qmdb",
                "--hash",
                "keccak256",
                "current",
                "--leaves",
                "3",
                "--location",
                "1",
                "--seed",
                "42",
                "--chunk-bytes",
                &chunk_bytes.to_string(),
                "--family",
                "mmb",
                "--inactivity-floor",
                "0",
            ])
            .unwrap()
            .command
            .execute();
            assert!(result.is_err());
        }
    }
}
