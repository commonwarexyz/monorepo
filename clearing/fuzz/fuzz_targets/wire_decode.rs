#![no_main]

use commonware_clearing::bajillion::{
    admission::{
        Committee,
        bls12381::{Certificate, Vote},
    },
    boundary::{DepositBatch, SignedWithdrawal, WithdrawalBatch, WithdrawalBody},
    challenge::{
        AccountLookup, Challenge, ChallengeError, RangeLower, RowOpening, StateLookup,
        StateOpening, adjudicate, decode_bounded,
    },
    commitment::{MultiOpening, Opening, RangeOpening, VectorKind, VectorRoot, empty_root},
    credit::{CreditRoot, ShardHead, ShardLookup, ShardOpening, ShardSet},
    payment::{Payment, PaymentContext},
    state::{AccountRow, AccountState, Prefix, StateLeaf},
    transition::{
        Assignment, BatchId, ChangeRange, Close, CloseContext, CloseLimits, Header, LayoutRange,
        PayoutProof, ProofSlice, RootBundle, SliceBoundary, SliceCodecConfig, StateCache,
        StateRange,
    },
};
use commonware_codec::{Decode, Encode, EncodeSize, RangeCfg, Read};
use commonware_cryptography::{Hasher, Sha256, Signer, sha256::Digest};
use commonware_cryptography_curve25519::signing::{SigningKey, StrictVerifyingKey as VerifyingKey};
use libfuzzer_sys::fuzz_target;
use std::fmt::Debug;

const MAX_INPUT_BYTES: usize = 16 * 1024;
const MAX_ITEMS: usize = 16;
const MAX_DESTINATION_BYTES: usize = 256;
const MAX_STATES: usize = 16;
const MAX_ROWS: usize = 8;
const MAX_SHARDS_PER_ACCOUNT: usize = 8;
const MAX_TOTAL_SHARDS: usize = 32;

fn roundtrip<T>(bytes: &[u8], cfg: &<T as Read>::Cfg)
where
    T: Decode + Encode + Debug + Eq,
{
    let Ok(value) = T::decode_cfg(bytes, cfg) else {
        return;
    };

    let encoded = value.encode();
    assert_eq!(encoded.len(), value.encode_size());
    let decoded = T::decode_cfg(encoded, cfg).expect("encoded value must remain decodable");
    assert_eq!(decoded, value);
}

fn semantic_header(
    seed: u8,
) -> (
    CloseContext<VerifyingKey, Digest>,
    Header<Digest>,
    RootBundle<Digest>,
) {
    let operator = SigningKey::from_seed(u64::from(seed));
    let cache = StateCache::new::<Sha256>(Vec::new()).expect("empty cache is canonical");
    let deposits = DepositBatch::empty();
    let withdrawals = WithdrawalBatch::empty();
    let context = CloseContext::new::<Sha256>(
        Sha256::hash(&[b"wire-decode-challenge", &[seed]]),
        u64::from(seed),
        operator.public_key(),
        &cache,
        &deposits,
        &withdrawals,
        u64::from(seed),
        u64::from(seed) + 1,
        CloseLimits::protocol_maximum(),
        Assignment::new(Sha256::hash(&[b"wire-decode-committee"]), 0)
            .expect("zero-bit assignment is valid"),
    )
    .expect("bounded semantic context must construct");
    let roots = RootBundle {
        opening: cache.root(),
        change: empty_root::<Sha256>(VectorKind::Change),
        closing: cache.root(),
        layout: empty_root::<Sha256>(VectorKind::Layout),
    };
    let header = Header::new::<Sha256, _>(context.payment(), &roots);
    (context, header, roots)
}

fn rebind_batch(challenge: &mut Challenge<VerifyingKey, Digest>, batch: BatchId<Digest>) {
    match challenge {
        Challenge::LatestAcknowledgedSend { batch: current, .. }
        | Challenge::HigherShardTip { batch: current, .. }
        | Challenge::InconsistentReceiptRange { batch: current, .. }
        | Challenge::ReceiptFork { batch: current, .. } => *current = batch,
    }
}

fn challenge_roundtrip(bytes: &[u8], seed: u8) {
    let Ok(challenge) = decode_bounded::<VerifyingKey, Digest>(bytes, MAX_INPUT_BYTES) else {
        return;
    };

    let encoded = challenge.encode();
    assert_eq!(encoded.len(), challenge.encode_size());
    let decoded = decode_bounded::<VerifyingKey, Digest>(&encoded, MAX_INPUT_BYTES)
        .expect("encoded challenge must remain bounded and decodable");
    assert_eq!(decoded, challenge);

    let (context, header, roots) = semantic_header(seed);
    let mut semantic = decoded;
    rebind_batch(&mut semantic, header.batch_id::<Sha256>());
    let _ = adjudicate::<Sha256, _>(
        &context,
        &header,
        &roots,
        context.challenge_deadline(),
        &semantic,
    );
}

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT_BYTES)];
    let Some((&selector, remainder)) = data.split_first() else {
        return;
    };
    let Some((&limit_selector, bytes)) = remainder.split_first() else {
        return;
    };

    let item_limit = usize::from(limit_selector) % (MAX_ITEMS + 1);
    let destination_limit = usize::from(limit_selector) % (MAX_DESTINATION_BYTES + 1);
    let close_limits = CloseLimits::new(
        u64::from(limit_selector)
            % (u64::try_from(MAX_STATES).expect("state bound fits in u64") + 1),
        u64::from(limit_selector) % (u64::try_from(MAX_ROWS).expect("row bound fits in u64") + 1),
        u64::try_from(item_limit).expect("withdrawal bound fits in u64"),
        u64::from(limit_selector)
            % (u64::try_from(MAX_SHARDS_PER_ACCOUNT).expect("per-account shard bound fits in u64")
                + 1),
        u64::from(limit_selector)
            % (u64::try_from(MAX_TOTAL_SHARDS).expect("total shard bound fits in u64") + 1),
        u64::MAX,
        u64::MAX,
        u64::MAX,
    );
    match selector % 39 {
        0 => roundtrip::<DepositBatch<VerifyingKey>>(bytes, &RangeCfg::new(..=item_limit)),
        1 => roundtrip::<WithdrawalBody<Digest>>(bytes, &RangeCfg::new(..=destination_limit)),
        2 => roundtrip::<SignedWithdrawal<VerifyingKey, Digest>>(
            bytes,
            &RangeCfg::new(..=destination_limit),
        ),
        3 => roundtrip::<WithdrawalBatch<VerifyingKey, Digest>>(
            bytes,
            &(
                RangeCfg::new(..=item_limit),
                RangeCfg::new(..=destination_limit),
            ),
        ),
        4 => roundtrip::<Committee>(bytes, &item_limit),
        5 => roundtrip::<Certificate>(bytes, &item_limit),
        6 => roundtrip::<AccountState>(bytes, &()),
        7 => roundtrip::<StateLeaf<VerifyingKey>>(bytes, &()),
        8 => roundtrip::<Prefix>(bytes, &()),
        9 => roundtrip::<AccountRow<VerifyingKey, Digest>>(bytes, &()),
        10 => roundtrip::<Opening<Digest>>(bytes, &()),
        11 => roundtrip::<MultiOpening<Digest>>(bytes, &()),
        12 => roundtrip::<ShardSet<VerifyingKey, Digest>>(bytes, &()),
        13 => roundtrip::<ShardOpening<VerifyingKey, Digest>>(bytes, &()),
        14 => roundtrip::<ShardLookup<VerifyingKey, Digest>>(bytes, &()),
        15 => roundtrip::<RowOpening<VerifyingKey, Digest>>(bytes, &()),
        16 => roundtrip::<StateOpening<VerifyingKey, Digest>>(bytes, &()),
        17 => roundtrip::<StateLookup<VerifyingKey, Digest>>(bytes, &()),
        18 => roundtrip::<AccountLookup<VerifyingKey, Digest>>(bytes, &()),
        19 => roundtrip::<RangeLower<VerifyingKey, Digest>>(bytes, &()),
        20 => challenge_roundtrip(bytes, limit_selector),
        21 => roundtrip::<Close<VerifyingKey, Digest>>(bytes, &close_limits),
        22 => roundtrip::<PaymentContext<VerifyingKey, Digest>>(bytes, &()),
        23 => roundtrip::<Payment<VerifyingKey, Digest>>(bytes, &()),
        24 => roundtrip::<Header<Digest>>(bytes, &()),
        25 => roundtrip::<CreditRoot<Digest>>(bytes, &()),
        26 => roundtrip::<VectorRoot<Digest>>(bytes, &()),
        27 => roundtrip::<ShardHead<VerifyingKey, Digest>>(bytes, &()),
        28 => roundtrip::<CloseLimits>(bytes, &()),
        29 => roundtrip::<Assignment<Digest>>(bytes, &()),
        30 => roundtrip::<RangeOpening<Digest>>(bytes, &item_limit),
        31 => roundtrip::<SliceBoundary>(bytes, &()),
        32 => roundtrip::<LayoutRange<Digest>>(bytes, &()),
        33 => roundtrip::<ChangeRange<VerifyingKey, Digest>>(bytes, &item_limit),
        34 => roundtrip::<StateRange<VerifyingKey, Digest>>(bytes, &item_limit),
        35 => roundtrip::<ProofSlice<VerifyingKey, Digest>>(
            bytes,
            &SliceCodecConfig::new(close_limits, item_limit),
        ),
        36 => roundtrip::<PayoutProof<VerifyingKey, Digest>>(bytes, &close_limits),
        37 => roundtrip::<RootBundle<Digest>>(bytes, &()),
        38 => roundtrip::<Vote>(bytes, &()),
        _ => unreachable!(),
    }

    if !bytes.is_empty() {
        assert!(matches!(
            decode_bounded::<VerifyingKey, Digest>(bytes, bytes.len() - 1),
            Err(ChallengeError::TooLarge)
        ));
    }
});
