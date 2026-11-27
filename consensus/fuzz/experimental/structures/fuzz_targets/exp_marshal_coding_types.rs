#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_codec::{Copying, Decode, DecodeExt, Encode, EncodeSize, FixedSize, ReadExt};
use commonware_coding::{Config as CodingConfig, ReedSolomon, Scheme as CodingScheme};
use commonware_consensus::{
    BoundedBlock, CertifiableBlock,
    marshal::{
        coding::{
            Coding,
            types::{CodedBlock, Shard, StoredCodedBlock, coding_config_for_participants},
        },
        core::{ExpectedCommitment, Variant},
        mocks::harness::{CodingB, CodingCtx},
    },
    types::{Epoch, Height, Round, View, coding::Commitment},
};
use commonware_cryptography::{
    Committable, Digestible, Hasher, Sha256, ed25519::PublicKey, sha256::Digest as Sha256Digest,
};
use commonware_parallel::{Sequential, Strategy as _};
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;

type RS = ReedSolomon<Sha256>;
type TestCommitment = Commitment<CodingB, RS, Sha256>;
type TestShard = Shard<CodingB, RS, Sha256>;
type TestCodedBlock = CodedBlock<CodingB, RS, Sha256>;
type TestStoredBlock = StoredCodedBlock<CodingB, RS, Sha256>;
type TestVariant = Coding<CodingB, RS, Sha256, PublicKey>;

const MIN_PARTICIPANTS: u16 = 4;
const MAX_PARTICIPANTS: u16 = 16;
const MAX_SPLICE: usize = 16;
const MAX_LIMIT_FACTOR: usize = 2;
const WIRE_FAULT_KINDS: u8 = 5;
const COMMITMENT_FAULT_KINDS: u8 = 5;

/// A change an attacker makes to honest wire bytes before they are decoded.
#[derive(Debug)]
enum WireFault {
    None,
    Flip { at: usize, mask: u8 },
    Truncate { at: usize },
    Append { bytes: Vec<u8> },
    Overwrite { at: usize, bytes: Vec<u8> },
}

impl WireFault {
    fn bytes(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
        let len = u.int_in_range(1..=MAX_SPLICE)?;
        (0..len).map(|_| u.arbitrary::<u8>()).collect()
    }

    fn apply(&self, honest: &[u8]) -> Vec<u8> {
        let mut bytes = honest.to_vec();
        match self {
            Self::None => {}
            Self::Flip { at, mask } => {
                let at = at % bytes.len();
                bytes[at] ^= mask | 1;
            }
            Self::Truncate { at } => bytes.truncate(at % bytes.len()),
            Self::Append { bytes: extra } => bytes.extend_from_slice(extra),
            Self::Overwrite { at, bytes: patch } => {
                let at = at % bytes.len();
                for (byte, value) in bytes[at..].iter_mut().zip(patch) {
                    *byte = *value;
                }
            }
        }
        bytes
    }
}

impl<'a> Arbitrary<'a> for WireFault {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(0..=WIRE_FAULT_KINDS - 1)? {
            0 => Self::None,
            1 => Self::Flip {
                at: u.arbitrary()?,
                mask: u.arbitrary()?,
            },
            2 => Self::Truncate { at: u.arbitrary()? },
            3 => Self::Append {
                bytes: Self::bytes(u)?,
            },
            _ => Self::Overwrite {
                at: u.arbitrary()?,
                bytes: Self::bytes(u)?,
            },
        })
    }
}

/// A component of the commitment the decoder is asked to match that differs from the honest one.
#[derive(Debug)]
enum CommitmentFault {
    None,
    Block(Sha256Digest),
    Root(Sha256Digest),
    Context(Sha256Digest),
    Config(CodingConfig),
}

impl CommitmentFault {
    fn apply(&self, honest: TestCommitment) -> TestCommitment {
        let (mut block, mut root, mut context, mut config) = (
            honest.block(),
            honest.root(),
            honest.context(),
            honest.config(),
        );
        match self {
            Self::None => {}
            Self::Block(digest) => block = *digest,
            Self::Root(digest) => root = *digest,
            Self::Context(digest) => context = *digest,
            Self::Config(other) => config = *other,
        }
        Commitment::from((block, root, context, config))
    }
}

impl<'a> Arbitrary<'a> for CommitmentFault {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(0..=COMMITMENT_FAULT_KINDS - 1)? {
            0 => Self::None,
            1 => Self::Block(digest(u)?),
            2 => Self::Root(digest(u)?),
            3 => Self::Context(digest(u)?),
            _ => Self::Config(coding_config_for_participants(participants(u)?)),
        })
    }
}

#[derive(Debug)]
struct FuzzInput {
    participants: u16,
    context: CodingCtx,
    parent: Sha256Digest,
    height: Height,
    timestamp: u64,
    block_fault: WireFault,
    commitment_fault: CommitmentFault,
    trusted: bool,
    stored_fault: WireFault,
    shard_index: u16,
    shard_fault: WireFault,
    shard_limit: usize,
}

fn digest(u: &mut Unstructured<'_>) -> arbitrary::Result<Sha256Digest> {
    Ok(Sha256::hash(&[&u.arbitrary::<u64>()?.to_be_bytes()]))
}

fn participants(u: &mut Unstructured<'_>) -> arbitrary::Result<u16> {
    u.int_in_range(MIN_PARTICIPANTS..=MAX_PARTICIPANTS)
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let participants = participants(u)?;
        let parent_commitment = Commitment::from((
            digest(u)?,
            digest(u)?,
            digest(u)?,
            coding_config_for_participants(participants),
        ));
        let context = CodingCtx {
            round: Round::new(Epoch::new(u.arbitrary()?), View::new(u.arbitrary()?)),
            leader: u.arbitrary()?,
            parent: (View::new(u.arbitrary()?), parent_commitment),
        };
        Ok(Self {
            participants,
            context,
            parent: digest(u)?,
            height: Height::new(u.arbitrary()?),
            timestamp: u.arbitrary()?,
            block_fault: u.arbitrary()?,
            commitment_fault: u.arbitrary()?,
            trusted: u.arbitrary()?,
            stored_fault: u.arbitrary()?,
            shard_index: u.int_in_range(0..=MAX_PARTICIPANTS)?,
            shard_fault: u.arbitrary()?,
            shard_limit: u.int_in_range(0..=MAX_LIMIT_FACTOR * application_bound())?,
        })
    }
}

fn application_bound() -> usize {
    CodingB::max_encode_size(&())
}

fn context_digest(context: &CodingCtx) -> Sha256Digest {
    Sha256::hash(&[&context.encode()])
}

fn decode_block(
    bytes: &[u8],
    expected: TestCommitment,
    trusted: bool,
) -> Option<Arc<TestCodedBlock>> {
    let expected = if trusted {
        ExpectedCommitment::Trusted(expected)
    } else {
        ExpectedCommitment::Untrusted(expected)
    };
    Sequential
        .block_on(TestVariant::decode_block(
            Copying(bytes),
            &(),
            expected,
            &Sequential,
        ))
        .ok()
}

/// Checks a coded block that decoded from `bytes` against the block and config read by the
/// plain codec.
fn check_coded_block(
    decoded: &TestCodedBlock,
    bytes: &[u8],
    block: &CodingB,
    config: CodingConfig,
    expected: TestCommitment,
    trusted: bool,
    honest: (&TestCodedBlock, &[u8]),
) {
    assert!(decoded.commitment() == expected);
    assert_eq!(decoded.digest(), expected.block());
    assert_eq!(decoded.config(), config);
    assert_eq!(decoded.inner(), block);
    assert_eq!(decoded.encode().as_ref(), bytes);
    assert!(bytes.len() <= TestVariant::max_backfill_block_size(application_bound()));

    let again =
        decode_block(&decoded.encode(), expected, trusted).expect("re-encoded block must decode");
    assert!(*again == *decoded);
    let clone = decoded.clone();
    assert!(clone == *decoded);
    assert_eq!(clone.encode().as_ref(), bytes);

    let (honest, wire) = honest;
    assert_eq!(
        *decoded == *honest,
        bytes == wire && expected == honest.commitment()
    );
}

/// Checks the stored form of a decoded block, and a decode of its stored bytes after `fault`.
fn check_stored_block(decoded: &Arc<TestCodedBlock>, fault: &WireFault) -> TestStoredBlock {
    let expected = decoded.commitment();
    let stored = TestStoredBlock::from(Arc::clone(decoded));
    assert!(stored == TestStoredBlock::new(TestCodedBlock::clone(decoded)));
    assert!(stored == TestStoredBlock::from(TestCodedBlock::clone(decoded)));
    assert!(stored.commitment() == expected);
    assert_eq!(stored.digest(), expected.block());
    assert_eq!(stored.inner(), decoded.inner());

    let honest = stored.encode();
    let mut layout = decoded.inner().encode().to_vec();
    layout.extend_from_slice(&expected.encode());
    assert_eq!(honest.as_ref(), layout.as_slice());

    let bytes = fault.apply(&honest);
    let model = <(CodingB, TestCommitment)>::decode(Copying(bytes.as_slice()));
    let result = TestStoredBlock::decode(Copying(bytes.as_slice()));
    match (model, result) {
        (Ok((block, commitment)), Ok(other)) => {
            assert_eq!(other.inner(), &block);
            assert!(other.commitment() == commitment);
            assert_eq!(other.encode().as_ref(), bytes.as_slice());
            assert!(other.clone() == other);
            assert_eq!(other == stored, bytes == honest.as_ref());
        }
        (Err(_), Err(_)) => {}
        (model, result) => panic!(
            "stored block decode disagrees with its layout: model ok {}, decode ok {}",
            model.is_ok(),
            result.is_ok()
        ),
    }
    stored
}

/// Checks a shard decoded from `bytes` with `limit` against its wire layout and size bounds.
fn check_shard(
    shard: &TestShard,
    bytes: &[u8],
    limit: usize,
    honest: &[u8],
    config: CodingConfig,
    participants: u16,
) {
    let Ok(decoded) = TestShard::decode_cfg(Copying(bytes), &limit) else {
        return;
    };
    let commitment = TestCommitment::read(&mut Copying(&bytes[..TestCommitment::SIZE]))
        .expect("decoded shard must start with its commitment");
    let index = u16::read(&mut Copying(
        &bytes[TestCommitment::SIZE..TestCommitment::SIZE + u16::SIZE],
    ))
    .expect("decoded shard must carry its index");
    assert!(decoded.commitment() == commitment);
    assert!(Committable::commitment(&decoded) == commitment);
    assert_eq!(decoded.index(), index);
    assert_eq!(decoded.encode().as_ref(), bytes);
    assert_eq!(decoded.encode_size(), bytes.len());

    let clone = decoded.clone();
    assert!(clone == decoded);
    assert_eq!(decoded == *shard, bytes == honest);
    let again = TestShard::decode_cfg(Copying(bytes), &limit).expect("shard must decode again");
    assert!(again == decoded);
    assert_eq!(
        clone.into_inner().encode().as_ref(),
        &bytes[TestCommitment::SIZE + u16::SIZE..]
    );

    // Both bounds hold only for encoder output: a decoded shard may carry more proof siblings
    // than the tree for `config` has.
    if bytes == honest {
        let widest = RS::max_shard_size(&config, limit.saturating_add(CodingConfig::SIZE));
        assert!(bytes.len() <= TestShard::max_encode_size(widest));
        assert!(bytes.len() <= TestVariant::max_buffer_payload_size(participants.into(), limit));
    }
}

fn fuzz(input: FuzzInput) {
    let config = coding_config_for_participants(input.participants);
    let total = usize::from(input.participants);
    let block = CodingB::new::<Sha256>(input.context, input.parent, input.height, input.timestamp);
    let mut wire = block.encode().to_vec();
    wire.extend_from_slice(&config.encode());
    let (root, shards) =
        RS::encode(&config, wire.as_slice(), &Sequential).expect("honest block must encode");
    assert_eq!(shards.len(), total);
    let honest = Commitment::from((
        block.digest(),
        root,
        context_digest(&block.context()),
        config,
    ));

    let honest_block =
        decode_block(&wire, honest, input.trusted).expect("honest block must decode");

    // Decode the coded block a peer sends, and predict the outcome from the plain codec and an
    // independent coding of the same bytes.
    let expected = input.commitment_fault.apply(honest);
    let bytes = input.block_fault.apply(&wire);
    let model = <(CodingB, CodingConfig)>::decode(Copying(bytes.as_slice())).ok();
    let model_coding = model
        .as_ref()
        .filter(|(_, claimed)| *claimed == expected.config())
        .map(|(_, claimed)| {
            RS::encode(claimed, bytes.as_slice(), &Sequential)
                .expect("supported config must encode")
        });
    let model_root = model_coding.as_ref().map(|(root, _)| *root);
    let accept = model.as_ref().is_some_and(|(block, claimed)| {
        *claimed == expected.config()
            && block.digest() == expected.block()
            && context_digest(&block.context()) == expected.context()
            && (input.trusted || model_root == Some(expected.root()))
    });
    let decoded = decode_block(&bytes, expected, input.trusted);
    assert_eq!(
        decoded.is_some(),
        accept,
        "coded block decode disagrees with its commitment"
    );

    if let (Some(decoded), Some((block, claimed))) = (&decoded, &model) {
        check_coded_block(
            decoded,
            &bytes,
            block,
            *claimed,
            expected,
            input.trusted,
            (&honest_block, &wire),
        );
        let stored = check_stored_block(decoded, &input.stored_fault);
        let restored = TestVariant::restore(stored.clone(), expected.block());
        let across = Sequential.block_on(TestVariant::restore_across(stored, &Sequential));
        assert!(restored.commitment() == expected && across.commitment() == expected);
        assert_eq!(restored.inner(), block);

        // A trusted commitment may name a root these bytes do not code to; shards are only
        // generated when it does.
        if let Some((root, model_shards)) = &model_coding
            && *root == expected.root()
        {
            let coded = decoded.shards(&Sequential);
            assert_eq!(coded, model_shards.as_slice());
            assert_eq!(restored.shards(&Sequential), coded);
            assert!(*restored == **decoded);
            let index = input.shard_index;
            let shard = decoded.shard(index);
            assert_eq!(shard.is_some(), usize::from(index) < coded.len());
            if let Some(shard) = shard {
                assert!(
                    shard == TestShard::new(expected, index, coded[usize::from(index)].clone())
                );
            }
        }
    }

    // Decode a shard a peer sends, built from the honest coding.
    let index = input.shard_index;
    let shard = TestShard::new(honest, index, shards[usize::from(index) % total].clone());
    let honest_shard = shard.encode().to_vec();
    assert!(
        honest_shard.len()
            <= TestVariant::max_buffer_payload_size(input.participants.into(), block.encode_size())
    );
    let shard_bytes = input.shard_fault.apply(&honest_shard);
    let limit = input.shard_limit;
    if shard_bytes == honest_shard && block.encode_size() <= limit {
        assert!(TestShard::decode_cfg(Copying(shard_bytes.as_slice()), &limit).is_ok());
    }
    check_shard(
        &shard,
        &shard_bytes,
        limit,
        &honest_shard,
        config,
        input.participants,
    );
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
