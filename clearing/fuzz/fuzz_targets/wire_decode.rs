#![no_main]

use commonware_clearing::bajillion::{
    admission::{Committee, curve25519::Certificate},
    boundary::{DepositBatch, SignedWithdrawal, WithdrawalBatch, WithdrawalBody},
    challenge::{
        AccountLookup, Challenge, ChallengeError, RangeLower, RowOpening, StateOpening, adjudicate,
        decode_bounded,
    },
    commitment::{
        MultiOpening, Opening, RangeOpening, RangeUpdate, SparseUpdate, VectorKind, VectorRoot,
        empty_root,
    },
    credit::{CreditRoot, ShardHead, ShardLookup, ShardOpening, ShardSet},
    payment::{Payment, PaymentContext},
    state::{AccountRow, Prefix},
    transition::{
        Assignment, BatchId, ChangeRange, Close, CloseLimits, Header, ProofSlice, SliceCodecConfig,
        StateBounds,
    },
};
use commonware_codec::{Decode, Encode, EncodeSize, RangeCfg, Read};
use commonware_cryptography::{
    Hasher, Sha256, Signer,
    curve25519::{SigningKey, VerifyingKey},
    sha256::Digest,
};
use libfuzzer_sys::fuzz_target;
use std::fmt::Debug;

const MAX_INPUT_BYTES: usize = 16 * 1024;
const MAX_ITEMS: usize = 16;
const MAX_DESTINATION_BYTES: usize = 256;
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

fn semantic_header(seed: u8) -> Header<VerifyingKey, Digest> {
    let operator = SigningKey::from_seed(u64::from(seed));
    let context = PaymentContext::new(
        Sha256::hash(&[b"wire-decode-challenge", &[seed]]),
        u64::from(seed),
        operator.public_key(),
    );
    let opening_root = empty_root::<Sha256>(VectorKind::State);
    Header {
        context,
        opening_root,
        change_root: empty_root::<Sha256>(VectorKind::Change),
        closing_root: opening_root,
        totals: Prefix::default(),
        opening_liability: 0,
        closing_liability: 0,
        challenge_deadline: u64::from(seed),
    }
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

    let header = semantic_header(seed);
    let mut semantic = decoded;
    rebind_batch(&mut semantic, header.batch_id::<Sha256>());
    let _ = adjudicate::<Sha256, _>(&header, header.challenge_deadline, &semantic);
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
        u64::from(limit_selector) % (u64::try_from(MAX_ROWS).expect("row bound fits in u64") + 1),
        u64::from(limit_selector)
            % (u64::try_from(MAX_ROWS).expect("withdrawal bound fits in u64") + 1),
        u64::from(limit_selector)
            % (u64::try_from(MAX_SHARDS_PER_ACCOUNT).expect("per-account shard bound fits in u64")
                + 1),
        u64::from(limit_selector)
            % (u64::try_from(MAX_TOTAL_SHARDS).expect("total shard bound fits in u64") + 1),
        u64::MAX,
        u64::MAX,
        u64::MAX,
    );
    match selector % 32 {
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
        4 => roundtrip::<Committee<VerifyingKey>>(bytes, &item_limit),
        5 => roundtrip::<Certificate>(bytes, &item_limit),
        6 => roundtrip::<AccountRow<VerifyingKey, Digest>>(bytes, &()),
        7 => roundtrip::<Opening<Digest>>(bytes, &()),
        8 => roundtrip::<MultiOpening<Digest>>(bytes, &()),
        9 => roundtrip::<SparseUpdate<Digest>>(bytes, &()),
        10 => roundtrip::<ShardSet<VerifyingKey, Digest>>(bytes, &()),
        11 => roundtrip::<ShardOpening<VerifyingKey, Digest>>(bytes, &()),
        12 => roundtrip::<ShardLookup<VerifyingKey, Digest>>(bytes, &()),
        13 => roundtrip::<RowOpening<VerifyingKey, Digest>>(bytes, &()),
        14 => roundtrip::<StateOpening<VerifyingKey, Digest>>(bytes, &()),
        15 => roundtrip::<AccountLookup<VerifyingKey, Digest>>(bytes, &()),
        16 => roundtrip::<RangeLower<VerifyingKey, Digest>>(bytes, &()),
        17 => challenge_roundtrip(bytes, limit_selector),
        18 => roundtrip::<Close<VerifyingKey, Digest>>(bytes, &close_limits),
        19 => roundtrip::<PaymentContext<VerifyingKey, Digest>>(bytes, &()),
        20 => roundtrip::<Payment<VerifyingKey, Digest>>(bytes, &()),
        21 => roundtrip::<Header<VerifyingKey, Digest>>(bytes, &()),
        22 => roundtrip::<CreditRoot<Digest>>(bytes, &()),
        23 => roundtrip::<VectorRoot<Digest>>(bytes, &()),
        24 => roundtrip::<ShardHead<VerifyingKey, Digest>>(bytes, &()),
        25 => roundtrip::<CloseLimits>(bytes, &()),
        26 => roundtrip::<Assignment<Digest>>(bytes, &()),
        27 => roundtrip::<RangeOpening<Digest>>(bytes, &item_limit),
        28 => roundtrip::<RangeUpdate<Digest>>(bytes, &(item_limit, item_limit, item_limit)),
        29 => roundtrip::<ChangeRange<VerifyingKey, Digest>>(bytes, &item_limit),
        30 => roundtrip::<StateBounds<VerifyingKey, Digest>>(bytes, &()),
        31 => roundtrip::<ProofSlice<VerifyingKey, Digest>>(
            bytes,
            &SliceCodecConfig::new(close_limits, item_limit),
        ),
        _ => unreachable!(),
    }

    if !bytes.is_empty() {
        assert!(matches!(
            decode_bounded::<VerifyingKey, Digest>(bytes, bytes.len() - 1),
            Err(ChallengeError::TooLarge)
        ));
    }
});
