//! Materialized MMR and MMB fixtures for any, keyless, immutable, and current QMDB.
//!
//! Deterministic operation logs and activity bitmaps exercise the production tree,
//! codec, and proof APIs without a persistent database lifecycle.

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
    merkle::{Family, Graftable, Location, mem::Mem, mmb, mmr},
    qmdb::{
        self,
        any::{
            ordered::fixed,
            unordered,
            value::{FixedEncoding, ValueEncoding, VariableEncoding},
        },
        current::{
            grafting,
            ordered::proof::ExclusionProof,
            proof::{OpsRootWitness, operation},
        },
        immutable, keyless,
    },
};
use commonware_utils::{bitmap::Prunable, sequence::FixedBytes};

mod batch;
mod exclusion;

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
    Current(GenerateArgs),
    /// Prove exclusion using a cyclic key interval or an empty database commit.
    Exclude(ExcludeArgs),
    /// Prove exclusion with independently fixed or vector byte fields.
    ExcludeVariable(exclusion::ExcludeVariableArgs),
}

#[derive(Args)]
pub(crate) struct GenerateArgs {
    leaves: u64,
    location: u64,
    seed: u64,
    #[arg(long, value_enum, default_value = "keccak")]
    hash: Hash,
    #[arg(long, value_enum, default_value = "mmb")]
    family: TreeKind,
    /// Operations below this location are inactive; current proofs fold chunk-aligned peaks.
    #[arg(long, default_value_t = 0)]
    inactivity_floor: u64,
    /// Current activity bitmap chunk size in bytes.
    #[arg(long, default_value_t = 32)]
    chunk_bytes: usize,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum History {
    Updated,
    Deleted,
}

#[derive(Args)]
pub(crate) struct AnyArgs {
    #[command(flatten)]
    tree: GenerateArgs,
    /// Authenticate the first update after later updates or deletion of its key.
    #[arg(long, value_enum)]
    history: Option<History>,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum Encoding {
    Fixed,
    Variable,
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
    tree: GenerateArgs,
    /// Return a Current proof and its Rust activity verdict.
    #[arg(long)]
    current: bool,
    #[arg(long, value_enum, default_value = "fixed")]
    encoding: Encoding,
    #[arg(long, value_enum, default_value = "update")]
    operation: UnorderedOperation,
    /// Repeat one key before a final overwrite or delete.
    #[arg(long, value_enum)]
    history: Option<History>,
    /// Variable value and metadata length; otherwise selected by the seed.
    #[arg(long)]
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
    tree: GenerateArgs,
    #[arg(long, value_enum, default_value = "fixed")]
    encoding: Encoding,
    #[arg(long, value_enum, default_value = "append")]
    operation: KeylessOperation,
    /// Variable value and metadata length; defaults to a boundary size selected by the seed.
    #[arg(long)]
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
    tree: GenerateArgs,
    #[arg(long, value_enum, default_value = "fixed")]
    encoding: Encoding,
    #[arg(long, value_enum, default_value = "set")]
    operation: ImmutableOperation,
    /// Variable value and metadata length; defaults to a boundary size selected by the seed.
    #[arg(long)]
    value_length: Option<u16>,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum ExclusionMode {
    Interval,
    Single,
    Empty,
}

#[derive(Args)]
pub(crate) struct ExcludeArgs {
    #[command(flatten)]
    tree: GenerateArgs,
    keyhex: String,
    #[arg(long, value_enum, default_value = "interval")]
    mode: ExclusionMode,
    #[arg(long)]
    metadata: bool,
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

fn materialize_ops<F: Family, H: Hasher, O: Encode>(
    args: &GenerateArgs,
    operation: &impl Fn(u64) -> O,
) -> Result<Mem<F, H::Digest>, String> {
    validate_tree(args)?;
    let hasher = qmdb::hasher::<H>();
    let mut ops = Mem::<F, H::Digest>::new();
    let mut batch = ops.new_batch();
    for index in 0..args.leaves {
        batch = batch.add(&hasher, &operation(index).encode());
    }
    let batch = batch.merkleize(&ops, &hasher);
    ops.apply_batch(&batch).map_err(|e| e.to_string())?;
    Ok(ops)
}

fn validate_tree(args: &GenerateArgs) -> Result<(), String> {
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
        Some(History::Deleted) if index == args.tree.leaves - 1 => Operation::Delete(key(0)),
        Some(_) => Operation::Update(fixed::Update {
            key: key(0),
            value: FixedBytes::new(leaf(args.tree.seed, index)),
            next_key: key(0),
        }),
        None => operation(args.tree.seed, index, args.tree.leaves),
    }
}

fn any<F: Family, H: Hasher>(args: &AnyArgs) -> Result<AnyOutput, String> {
    let tree = &args.tree;
    if args.history.is_some() && (tree.leaves < 2 || tree.location != 0) {
        return Err("history requires leaves >= 2 and location = 0".into());
    }
    plain_proof::<F, H, _>(tree, |index| any_operation::<F>(args, index))
}

fn plain_proof<F: Family, H: Hasher, O: Encode>(
    tree: &GenerateArgs,
    operation: impl Fn(u64) -> O,
) -> Result<AnyOutput, String> {
    let ops = materialize_ops::<F, H, _>(tree, &operation)?;
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

// The seed selects sizes around word and varint boundaries for both values and metadata.
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
        Encoding::Variable => plain_proof::<F, H, _>(&args.tree, |index| {
            let bytes = leaf(args.tree.seed, index);
            let len = args.value_length.map_or_else(
                || VARIABLE_LENGTHS[(args.tree.seed % VARIABLE_LENGTHS.len() as u64) as usize],
                usize::from,
            );
            keyless_operation::<F, qmdb::any::value::VariableEncoding<Vec<u8>>>(
                args,
                index,
                bytes.into_iter().cycle().take(len).collect(),
            )
        }),
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
        Encoding::Variable => plain_proof::<F, H, _>(&args.tree, |index| {
            let bytes = leaf(args.tree.seed, index);
            let len = args.value_length.map_or_else(
                || VARIABLE_LENGTHS[(args.tree.seed % VARIABLE_LENGTHS.len() as u64) as usize],
                usize::from,
            );
            immutable_operation::<F, qmdb::any::value::VariableEncoding<Vec<u8>>>(
                args,
                index,
                bytes.into_iter().cycle().take(len).collect(),
            )
        }),
    }
}

fn unordered<F: Graftable, H: Hasher>(args: &UnorderedArgs) -> Result<Vec<u8>, String> {
    validate_tree(&args.tree)?;
    if args.value_length.is_some() && matches!(args.encoding, Encoding::Fixed) {
        return Err("value-length requires --encoding variable".into());
    }
    if args.history.is_some()
        && (args.tree.leaves < 2 || !matches!(args.operation, UnorderedOperation::Update))
    {
        return Err("history requires leaves >= 2 and --operation update".into());
    }
    with_chunk_bytes!(args.tree.chunk_bytes, |N| match args.encoding {
        Encoding::Fixed => {
            unordered_encoded::<F, H, FixedEncoding<FixedBytes<32>>, N>(args, |index| {
                FixedBytes::new(leaf(args.tree.seed, index))
            })
        }
        Encoding::Variable => {
            unordered_encoded::<F, H, VariableEncoding<Vec<u8>>, N>(args, |index| {
                let len = args.value_length.map_or_else(
                    || VARIABLE_LENGTHS[(args.tree.seed % VARIABLE_LENGTHS.len() as u64) as usize],
                    usize::from,
                );
                leaf(args.tree.seed, index)
                    .into_iter()
                    .cycle()
                    .take(len)
                    .collect()
            })
        }
    })
}

fn unordered_encoded<F: Graftable, H: Hasher, V: ValueEncoding, const N: usize>(
    args: &UnorderedArgs,
    value: impl Fn(u64) -> V::Value,
) -> Result<Vec<u8>, String>
where
    unordered::Operation<F, FixedBytes<32>, V>: Codec,
{
    let tree = &args.tree;
    let op = |index| {
        if let Some(history) = args.history {
            return if matches!(history, History::Deleted) && index + 1 == tree.leaves {
                unordered::Operation::Delete(key(0))
            } else {
                unordered::Operation::Update(unordered::Update(key(0), value(index)))
            };
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
    if !args.current {
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
    let fixture = materialize::<F, H, _, N>(tree, op, |index| active[index as usize])?;
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

struct Materialized<F: Graftable, D: Digest, const N: usize> {
    output: OperationOutput,
    proof: operation::Proof<F, D, [u8; N]>,
    root: D,
    ops_root: D,
    ops: Mem<F, D>,
    grafted: Mem<F, D>,
    status: Prunable<N>,
    witness: OpsRootWitness<F, D>,
}

fn materialize<F: Graftable, H: Hasher, O: Codec + Clone, const N: usize>(
    args: &GenerateArgs,
    operation: impl Fn(u64) -> O,
    active: impl Fn(u64) -> bool,
) -> Result<Materialized<F, H::Digest, N>, String> {
    let GenerateArgs {
        leaves,
        location,
        inactivity_floor,
        ..
    } = *args;
    let ops = materialize_ops::<F, H, _>(args, &operation)?;
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
    let mut grafted = Mem::<F, H::Digest>::new();
    let mut grafted_batch = grafted.new_batch();
    for index in 0..leaves {
        let encoded = operation(index).encode();
        grafted_batch = grafted_batch.add(&verifier, &encoded);
    }
    let grafted_batch = grafted_batch.merkleize(&grafted, &verifier);
    grafted
        .apply_batch(&grafted_batch)
        .map_err(|e| e.to_string())?;

    // Any roots fold all peaks wholly below the floor. Current roots additionally
    // require a chunk-aligned boundary, which OperationProof::new derives itself.
    let inactive_ops = F::inactive_peaks(Location::new(leaves), Location::new(inactivity_floor));
    let ops_root = ops.root(&hasher, inactive_ops).map_err(|e| e.to_string())?;
    let proof =
        futures::executor::block_on(operation::Proof::<F, H::Digest, [u8; N]>::new::<H, _>(
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
    let op = operation(location);
    if !range.verify::<H, _, N>(
        Location::new(location),
        core::slice::from_ref(&op),
        &[proof.chunk],
        &root,
    ) || proof.verify::<H, _>(op.clone(), &root) != active(location)
    {
        return Err("Commonware rejected proof against the materialized canonical root".into());
    }
    let bytes32 = |digest: H::Digest| -> [u8; 32] { digest.as_ref().try_into().unwrap() };
    let output = OperationOutput {
        root: bytes32(root).into(),
        leaves: Uint256::from(leaves),
        location: Uint256::from(location),
        inactivePeaks: Uint256::from(range.proof.inactive_peaks),
        chunk: proof.chunk.to_vec().into(),
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
    };
    Ok(Materialized {
        output,
        proof,
        root,
        ops_root,
        ops,
        grafted,
        status,
        witness,
    })
}

fn current<F: Graftable, H: Hasher, const N: usize>(
    args: &GenerateArgs,
) -> Result<OperationOutput, String> {
    materialize::<F, H, _, N>(
        args,
        |index| operation::<F>(args.seed, index, args.leaves),
        |index| index >= args.inactivity_floor,
    )
    .map(|fixture| fixture.output)
}

fn exclude<F: Graftable, H: Hasher, const N: usize>(args: &ExcludeArgs) -> Result<Vec<u8>, String> {
    let query = const_hex::decode(args.keyhex.strip_prefix("0x").unwrap_or(&args.keyhex))
        .map_err(|e| e.to_string())?;
    let query = FixedBytes::<32>::new(query.try_into().map_err(|_| "key must be 32 bytes")?);
    if args.tree.inactivity_floor != 0 {
        return Err("exclude derives its inactivity floor from the mode".into());
    }
    if args.metadata && !matches!(args.mode, ExclusionMode::Empty) {
        return Err("metadata requires empty mode".into());
    }
    if matches!(args.mode, ExclusionMode::Empty | ExclusionMode::Single)
        && args.tree.leaves.checked_sub(1) != Some(args.tree.location)
    {
        return Err("empty and single modes require location = leaves - 1".into());
    }
    let tree = GenerateArgs {
        inactivity_floor: match args.mode {
            ExclusionMode::Interval => 0,
            _ => args.tree.location,
        },
        ..args.tree
    };
    let op = |index| match args.mode {
        ExclusionMode::Empty => Operation::<F>::CommitFloor(
            args.metadata
                .then(|| FixedBytes::new(leaf(tree.seed, index))),
            Location::new(index),
        ),
        ExclusionMode::Interval | ExclusionMode::Single => Operation::Update(fixed::Update {
            key: key(2
                * (match args.mode {
                    ExclusionMode::Single => tree.location,
                    _ => index,
                } + 1)),
            value: FixedBytes::new(leaf(tree.seed, index)),
            next_key: key(2
                * (match args.mode {
                    ExclusionMode::Single => tree.location,
                    _ => (index + 1) % tree.leaves,
                } + 1)),
        }),
    };
    let Materialized {
        output,
        proof,
        root,
        ..
    } = materialize::<F, H, _, N>(&tree, op, |index| {
        matches!(args.mode, ExclusionMode::Interval) || index == tree.location
    })?;
    let exclusion: ExclusionProof<F, FixedBytes<32>, FixedEncoding<FixedBytes<32>>, H::Digest, _> =
        match op(tree.location) {
            Operation::Update(update) => ExclusionProof::KeyValue(proof, update),
            Operation::CommitFloor(metadata, _) => ExclusionProof::Commit(proof, metadata),
            _ => unreachable!(),
        };
    let expected = exclusion.verify::<H>(&query, &root);
    Ok(current_output(output, expected))
}

impl Command {
    pub(crate) fn execute(self) -> Result<Vec<u8>, String> {
        match self {
            Self::ExcludeVariable(args) => args.execute(),
            Self::Range(args) => args.execute(),
            Self::Multi(args) => args.execute(),
            Self::Unordered(args) => match (args.tree.family, args.tree.hash) {
                (TreeKind::Mmr, Hash::Keccak) => unordered::<mmr::Family, Keccak256>(&args),
                (TreeKind::Mmr, Hash::Sha256) => unordered::<mmr::Family, Sha256>(&args),
                (TreeKind::Mmb, Hash::Keccak) => unordered::<mmb::Family, Keccak256>(&args),
                (TreeKind::Mmb, Hash::Sha256) => unordered::<mmb::Family, Sha256>(&args),
            },
            Self::Any(args) => {
                let output = match (args.tree.family, args.tree.hash) {
                    (TreeKind::Mmr, Hash::Keccak) => any::<mmr::Family, Keccak256>(&args),
                    (TreeKind::Mmr, Hash::Sha256) => any::<mmr::Family, Sha256>(&args),
                    (TreeKind::Mmb, Hash::Keccak) => any::<mmb::Family, Keccak256>(&args),
                    (TreeKind::Mmb, Hash::Sha256) => any::<mmb::Family, Sha256>(&args),
                }?;
                Ok(output.abi_encode_params())
            }
            Self::Keyless(args) => {
                let output = match (args.tree.family, args.tree.hash) {
                    (TreeKind::Mmr, Hash::Keccak) => keyless::<mmr::Family, Keccak256>(&args),
                    (TreeKind::Mmr, Hash::Sha256) => keyless::<mmr::Family, Sha256>(&args),
                    (TreeKind::Mmb, Hash::Keccak) => keyless::<mmb::Family, Keccak256>(&args),
                    (TreeKind::Mmb, Hash::Sha256) => keyless::<mmb::Family, Sha256>(&args),
                }?;
                Ok(output.abi_encode_params())
            }
            Self::Immutable(args) => {
                let output = match (args.tree.family, args.tree.hash) {
                    (TreeKind::Mmr, Hash::Keccak) => immutable::<mmr::Family, Keccak256>(&args),
                    (TreeKind::Mmr, Hash::Sha256) => immutable::<mmr::Family, Sha256>(&args),
                    (TreeKind::Mmb, Hash::Keccak) => immutable::<mmb::Family, Keccak256>(&args),
                    (TreeKind::Mmb, Hash::Sha256) => immutable::<mmb::Family, Sha256>(&args),
                }?;
                Ok(output.abi_encode_params())
            }
            Self::Current(args) => {
                let output = match (args.family, args.hash) {
                    (TreeKind::Mmr, Hash::Keccak) => {
                        with_chunk_bytes!(
                            args.chunk_bytes,
                            |N| current::<mmr::Family, Keccak256, N>(&args)
                        )
                    }
                    (TreeKind::Mmr, Hash::Sha256) => {
                        with_chunk_bytes!(args.chunk_bytes, |N| current::<mmr::Family, Sha256, N>(
                            &args
                        ))
                    }
                    (TreeKind::Mmb, Hash::Keccak) => {
                        with_chunk_bytes!(
                            args.chunk_bytes,
                            |N| current::<mmb::Family, Keccak256, N>(&args)
                        )
                    }
                    (TreeKind::Mmb, Hash::Sha256) => {
                        with_chunk_bytes!(args.chunk_bytes, |N| current::<mmb::Family, Sha256, N>(
                            &args
                        ))
                    }
                }?;
                Ok(output.abi_encode_params())
            }
            Self::Exclude(args) => match (args.tree.family, args.tree.hash) {
                (TreeKind::Mmr, Hash::Keccak) => {
                    with_chunk_bytes!(args.tree.chunk_bytes, |N| exclude::<
                        mmr::Family,
                        Keccak256,
                        N,
                    >(&args))
                }
                (TreeKind::Mmr, Hash::Sha256) => {
                    with_chunk_bytes!(
                        args.tree.chunk_bytes,
                        |N| exclude::<mmr::Family, Sha256, N>(&args)
                    )
                }
                (TreeKind::Mmb, Hash::Keccak) => {
                    with_chunk_bytes!(args.tree.chunk_bytes, |N| exclude::<
                        mmb::Family,
                        Keccak256,
                        N,
                    >(&args))
                }
                (TreeKind::Mmb, Hash::Sha256) => {
                    with_chunk_bytes!(
                        args.tree.chunk_bytes,
                        |N| exclude::<mmb::Family, Sha256, N>(&args)
                    )
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Cli;
    use clap::Parser;
    use commonware_codec::{Copying, DecodeExt};
    use commonware_storage::{merkle::Proof, qmdb::current::proof::RangeProof};

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
                "fixed" => keyless::initial_root::<F, FixedEncoding<FixedBytes<32>>, H>(),
                _ => keyless::initial_root::<F, qmdb::any::value::VariableEncoding<Vec<u8>>, H>(),
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
        current: bool,
        cfg: &O::Cfg,
        expected: bool,
        inactive: bool,
    ) {
        let digest = |bytes: &[u8]| H::Digest::decode(Copying(bytes)).unwrap();
        if current {
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
            for current in [false, true] {
                for (leaves, location, floor, operation, history, expected) in [
                    (1u64, 0u64, 0u64, "update", "", true),
                    (1023, 1022, 768, "update", "", true),
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
                            "unordered".into(),
                            leaves.to_string(),
                            location.to_string(),
                            "71".into(),
                            "--family".into(),
                            family.into(),
                            "--hash".into(),
                            hash.into(),
                            "--inactivity-floor".into(),
                            floor.to_string(),
                            "--encoding".into(),
                            encoding.into(),
                            "--operation".into(),
                            operation.into(),
                        ];
                        if current {
                            args.push("--current".into());
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
                                &encoded, current, &(), expected, floor != 0
                            );
                            break;
                        } else {
                            check_unordered::<
                                F,
                                H,
                                unordered::variable::Operation<F, FixedBytes<32>, Vec<u8>>,
                            >(
                                &encoded,
                                current,
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
            vec!["0", "0", "71"],
            vec!["1000001", "0", "71"],
            vec!["3", "3", "71"],
            vec!["3", "1", "71", "--inactivity-floor", "2"],
            vec!["3", "1", "71", "--value-length", "32"],
            vec!["1", "0", "71", "--history", "updated"],
            vec![
                "3",
                "1",
                "71",
                "--history",
                "updated",
                "--operation",
                "delete",
            ],
            vec![
                "3",
                "2",
                "71",
                "--current",
                "--inactivity-floor",
                "2",
                "--operation",
                "commit",
            ],
        ] {
            let result = Cli::try_parse_from(["fuzz", "qmdb", "unordered"].into_iter().chain(tail))
                .unwrap()
                .command
                .execute();
            assert!(result.is_err());
        }
    }

    #[test]
    fn unordered_cli_codecs_activity_and_inactive_prefixes() {
        unordered_matrix::<mmr::Family, Keccak256>("mmr", "keccak");
        unordered_matrix::<mmr::Family, Sha256>("mmr", "sha256");
        unordered_matrix::<mmb::Family, Keccak256>("mmb", "keccak");
        unordered_matrix::<mmb::Family, Sha256>("mmb", "sha256");
    }

    #[test]
    fn immutable_cli_codecs_operations_and_inactive_prefixes() {
        for family in ["mmr", "mmb"] {
            for hash in ["keccak", "sha256"] {
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
                                "immutable".into(),
                                leaves.to_string(),
                                location.to_string(),
                                "71".into(),
                                "--family".into(),
                                family.into(),
                                "--hash".into(),
                                hash.into(),
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
                "immutable".into(),
                leaves.to_string(),
                location.to_string(),
                "71".into(),
                "--inactivity-floor".into(),
                floor.to_string(),
                "--operation".into(),
                operation.into(),
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
    fn keyless_cli_variable_length_overrides_seed() {
        use commonware_codec::Decode;
        for length in [0u16, 31, 32, 33, 127, 128, 65535] {
            for operation in ["append", "commit-metadata"] {
                let args = [
                    "fuzz",
                    "qmdb",
                    "keyless",
                    "3",
                    "1",
                    "42",
                    "--encoding",
                    "variable",
                    "--operation",
                    operation,
                    "--value-length",
                    &length.to_string(),
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
            "keyless",
            "3",
            "1",
            "42",
            "--value-length",
            "32",
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
                "keyless",
                &leaves.to_string(),
                &location.to_string(),
                "42",
                "--inactivity-floor",
                &floor.to_string(),
                "--operation",
                operation,
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
            for hash in ["keccak", "sha256"] {
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
                                let encoded = Cli::try_parse_from([
                                    "fuzz",
                                    "qmdb",
                                    "keyless",
                                    &leaves.to_string(),
                                    &location.to_string(),
                                    &seed.to_string(),
                                    "--family",
                                    family,
                                    "--hash",
                                    hash,
                                    "--inactivity-floor",
                                    &floor.to_string(),
                                    "--encoding",
                                    encoding,
                                    "--operation",
                                    operation,
                                ])
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
                                    ("mmr", "keccak") => {
                                        verify_keyless_output::<mmr::Family, Keccak256>(
                                            &output, encoding, operation, seed, floor,
                                        )
                                    }
                                    ("mmr", _) => verify_keyless_output::<mmr::Family, Sha256>(
                                        &output, encoding, operation, seed, floor,
                                    ),
                                    (_, "keccak") => {
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
            for hash in ["keccak", "sha256"] {
                for leaves in [1u64, 2, 3, 7, 11, 31, 255, 256, 257, 383, 513, 1793] {
                    for location in [0, leaves / 2, leaves - 1] {
                        for floor in [0, location] {
                            for history in [None, Some("updated"), Some("deleted")] {
                                if history.is_some() && (leaves < 2 || location != 0) {
                                    continue;
                                }
                                let mut args = vec![
                                    "fuzz".to_owned(),
                                    "qmdb".into(),
                                    "any".into(),
                                    leaves.to_string(),
                                    location.to_string(),
                                    "42".into(),
                                    "--family".into(),
                                    family.into(),
                                    "--hash".into(),
                                    hash.into(),
                                    "--inactivity-floor".into(),
                                    floor.to_string(),
                                ];
                                if let Some(history) = history {
                                    args.extend(["--history".into(), history.into()]);
                                }
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
                                    ("mmr", "keccak") => {
                                        verify_any_output::<mmr::Family, Keccak256>(&output)
                                    }
                                    ("mmr", _) => verify_any_output::<mmr::Family, Sha256>(&output),
                                    (_, "keccak") => {
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
                tree: GenerateArgs {
                    leaves: 3,
                    location: 0,
                    seed: 42,
                    hash: Hash::Keccak,
                    family: TreeKind::Mmb,
                    inactivity_floor: 0,
                    chunk_bytes: 32,
                },
                history: Some(history),
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
                tree: GenerateArgs {
                    leaves: 1,
                    ..args.tree
                },
                history: None,
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
        }
    }

    #[test]
    fn materialized_current_proofs_cover_chunk_boundaries() {
        for family in ["mmr", "mmb"] {
            for hash in ["keccak", "sha256"] {
                for leaves in [
                    1u64, 255, 256, 257, 382, 383, 384, 511, 512, 513, 638, 639, 640, 769, 1024,
                    1793, 4097,
                ] {
                    for location in [0, leaves / 2, leaves - 1] {
                        for floor in [0, location] {
                            let encoded = Cli::try_parse_from([
                                "fuzz",
                                "qmdb",
                                "current",
                                &leaves.to_string(),
                                &location.to_string(),
                                "42",
                                "--family",
                                family,
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
                            match (family, hash) {
                                ("mmr", "keccak") => {
                                    verify_output::<mmr::Family, Keccak256, 32>(&output)
                                }
                                ("mmr", _) => verify_output::<mmr::Family, Sha256, 32>(&output),
                                (_, "keccak") => {
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
            for hash in ["keccak", "sha256"] {
                for leaves in [1u64, 256, 257, 383, 513] {
                    for location in [0, leaves - 1] {
                        for mode in ["interval", "single", "empty"] {
                            for metadata in [false, true] {
                                if metadata && mode != "empty" {
                                    continue;
                                }
                                let start = 2 * (location + 1);
                                let end = 2 * ((location + 1) % leaves + 1);
                                for query in [0, start - 1, start, start + 1, end, u64::MAX] {
                                    let queryhex = const_hex::encode(key(query));
                                    let mut arguments = vec![
                                        "fuzz".to_owned(),
                                        "qmdb".into(),
                                        "exclude".into(),
                                        leaves.to_string(),
                                        location.to_string(),
                                        "42".into(),
                                        queryhex,
                                        "--family".into(),
                                        family.into(),
                                        "--hash".into(),
                                        hash.into(),
                                        "--mode".into(),
                                        mode.into(),
                                    ];
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
    fn cli_defaults_to_mmb() {
        for hash in ["keccak", "sha256"] {
            let args = [
                "fuzz", "qmdb", "current", "383", "256", "42", "--hash", hash,
            ];
            let default = Cli::try_parse_from(args)
                .unwrap()
                .command
                .execute()
                .unwrap();
            let explicit = Cli::try_parse_from(args.into_iter().chain(["--family", "mmb"]))
                .unwrap()
                .command
                .execute()
                .unwrap();
            assert_eq!(default, explicit);
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
                    "current",
                    &leaves.to_string(),
                    &location.to_string(),
                    "42",
                    "--family",
                    family,
                    "--chunk-bytes",
                    &chunk_bytes.to_string(),
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
                "current",
                "3",
                "1",
                "42",
                "--chunk-bytes",
                &chunk_bytes.to_string(),
            ])
            .unwrap()
            .command
            .execute();
            assert!(result.is_err());
        }
    }
}
