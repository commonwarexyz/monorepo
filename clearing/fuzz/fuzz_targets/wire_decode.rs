#![no_main]

mod support;

use commonware_clearing::bajillion::{
    admission::{
        Committee,
        bls12381::{Certificate, Vote},
    },
    boundary::{DepositBatch, SignedWithdrawal, WithdrawalAction, WithdrawalBatch, WithdrawalBody},
    challenge::{
        AccountLookup, AckWitness, ChallengeError, ChangeAbsence, ChangeOpening, EntryWitness,
        HigherEntryLookup, adjudicate, decode_bounded,
    },
    commitment::{MultiOpening, Opening, RangeOpening, VectorKind, VectorRoot, empty_root},
    payment::{EntryReceipt, PaymentContext, SendAuthorization, VectorAck, VectorSendBody},
    posted,
    qmdb::{StateLookup, StateOpening, StateRoot, StateValueOpening},
    state::{AccountChange, ChangeGuard, ChangeValue, ChangeValueCore, SettlementOutput},
    transition::{
        BatchId, CloseAmounts, CloseContext, CloseLimits, ExternalPayoutClaim, Header, RootBundle,
        WithdrawalClaim, WithdrawalOutput,
    },
    vector::{OutEntry, OutTipLookup, OutVector},
};
use commonware_codec::{Decode, Encode, EncodeSize, RangeCfg, Read};
use commonware_cryptography::{Hasher, Sha256, Signer, sha256::Digest};
use commonware_cryptography_curve25519::signing::{SigningKey, StrictVerifyingKey as VerifyingKey};
use commonware_runtime::{Runner as _, deterministic};
use libfuzzer_sys::fuzz_target;
use std::fmt::Debug;

const MAX_INPUT_BYTES: usize = 16 * 1024;
const MAX_ITEMS: usize = 16;
const MAX_DESTINATION_BYTES: usize = 256;
const MAX_STATES: usize = 16;
const MAX_ROWS: usize = 8;
const MAX_ACCOUNT_ENTRIES: usize = 8;
const MAX_TOTAL_ENTRIES: usize = 32;

fn roundtrip<T>(bytes: &[u8], cfg: &<T as Read>::Cfg)
where
    T: Decode + Encode + Debug + Eq,
{
    let Ok(value) = T::decode_cfg(bytes, cfg) else {
        return;
    };

    let encoded = value.encode();
    assert_eq!(encoded.len(), value.encode_size());
    if !encoded.is_empty() {
        assert!(T::decode_cfg(&encoded[..encoded.len() - 1], cfg).is_err());
    }
    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert!(T::decode_cfg(trailing.as_slice(), cfg).is_err());
    let decoded = T::decode_cfg(encoded, cfg).expect("encoded value must remain decodable");
    assert_eq!(decoded, value);
}

async fn semantic_header(
    seed: u8,
    runtime: deterministic::Context,
) -> (
    CloseContext<VerifyingKey, Digest>,
    Header<Digest>,
    RootBundle<Digest>,
    CloseAmounts,
) {
    let operator = SigningKey::from_seed(u64::from(seed));
    let state = support::new_state(runtime, "wire", Vec::new()).await;
    let deposits = DepositBatch::empty();
    let withdrawals = WithdrawalBatch::empty();
    let context = support::close_context(
        Sha256::hash(&[b"wire-decode-challenge", &[seed]]),
        u64::from(seed),
        operator.public_key(),
        &state,
        &deposits,
        &withdrawals,
        u64::from(seed),
        u64::from(seed) + 1,
        CloseLimits::protocol_maximum(),
        Sha256::hash(&[b"wire-decode-committee"]),
    )
    .await;
    let roots = RootBundle {
        change: empty_root::<Sha256>(VectorKind::Change),
        withdrawal_outputs: empty_root::<Sha256>(VectorKind::WithdrawalOutput),
        successor: state.root(),
    };
    let amounts = CloseAmounts::default();
    let header = Header::new::<Sha256, _>(&context, &roots, &amounts);
    (context, header, roots, amounts)
}

async fn challenge_roundtrip(bytes: &[u8], seed: u8, runtime: deterministic::Context) {
    let Ok(challenge) = decode_bounded::<VerifyingKey, Digest>(bytes, MAX_INPUT_BYTES) else {
        return;
    };

    let encoded = challenge.encode();
    assert_eq!(encoded.len(), challenge.encode_size());
    let decoded = decode_bounded::<VerifyingKey, Digest>(&encoded, MAX_INPUT_BYTES)
        .expect("encoded challenge must remain bounded and decodable");
    assert_eq!(decoded, challenge);

    let (context, header, roots, amounts) = semantic_header(seed, runtime).await;
    let _ = adjudicate::<Sha256, _, _>(&context, &header, &roots, &amounts, &decoded);
}

async fn dealing_roundtrip(bytes: &[u8], limits: CloseLimits, runtime: deterministic::Context) {
    let state = support::new_state(runtime, "dealing", Vec::new()).await;
    let deposits = DepositBatch::empty();
    let withdrawals = WithdrawalBatch::empty();
    let operator = SigningKey::from_seed(0);
    let context = support::close_context(
        Sha256::hash(&[b"wire"]),
        0,
        operator.public_key(),
        &state,
        &deposits,
        &withdrawals,
        0,
        1,
        limits,
        Sha256::hash(&[b"committee"]),
    )
    .await;
    if let Ok(dealing) = posted::decode::<VerifyingKey, Digest>(bytes.to_vec().into(), &context) {
        assert_eq!(dealing.encoded().as_ref(), bytes);
        let decoded =
            posted::decode::<VerifyingKey, Digest>(dealing.encoded().clone(), &context).unwrap();
        assert_eq!(decoded.header(), dealing.header());
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(posted::decode::<VerifyingKey, Digest>(trailing.into(), &context).is_err());
    }
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
            % (u64::try_from(MAX_ACCOUNT_ENTRIES).expect("per-account entry bound fits in u64")
                + 1),
        u64::from(limit_selector)
            % (u64::try_from(MAX_TOTAL_ENTRIES).expect("total entry bound fits in u64") + 1),
        u64::MAX,
        u64::MAX,
        u64::MAX,
    );
    match selector % 52 {
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
        6 => roundtrip::<Vote>(bytes, &()),
        7 => roundtrip::<WithdrawalAction>(bytes, &()),
        8 => roundtrip::<StateRoot<Digest>>(bytes, &()),
        9 => roundtrip::<StateValueOpening<Digest>>(bytes, &item_limit),
        10 => roundtrip::<CloseAmounts>(bytes, &()),
        11 => roundtrip::<core::num::NonZeroU64>(bytes, &()),
        12 => roundtrip::<SettlementOutput>(bytes, &()),
        13 => roundtrip::<AccountChange<VerifyingKey, Digest>>(bytes, &()),
        14 => roundtrip::<ChangeValue<Digest>>(bytes, &()),
        15 => roundtrip::<ChangeValueCore>(bytes, &()),
        16 => roundtrip::<ChangeGuard<VerifyingKey, Digest>>(bytes, &()),
        17 => roundtrip::<Opening<Digest>>(bytes, &()),
        18 => roundtrip::<MultiOpening<Digest>>(bytes, &()),
        19 => roundtrip::<RangeOpening<Digest>>(bytes, &item_limit),
        20 => roundtrip::<VectorRoot<Digest>>(bytes, &()),
        21 => roundtrip::<PaymentContext<VerifyingKey, Digest>>(bytes, &()),
        22 => roundtrip::<VectorSendBody<VerifyingKey, Digest>>(bytes, &()),
        23 => roundtrip::<SendAuthorization<VerifyingKey, Digest>>(bytes, &()),
        24 => roundtrip::<VectorAck<VerifyingKey, Digest>>(bytes, &()),
        25 => roundtrip::<EntryReceipt<VerifyingKey, Digest>>(bytes, &()),
        26 => roundtrip::<OutEntry<VerifyingKey>>(bytes, &()),
        27 => roundtrip::<OutVector<VerifyingKey>>(bytes, &()),
        28 => roundtrip::<OutTipLookup<VerifyingKey, Digest>>(bytes, &()),
        29 => roundtrip::<StateLookup<Digest>>(bytes, &item_limit),
        30 => roundtrip::<CloseContext<VerifyingKey, Digest>>(bytes, &()),
        31 => roundtrip::<StateOpening<VerifyingKey, Digest>>(bytes, &item_limit),
        32 => roundtrip::<StateLookup<Digest>>(bytes, &item_limit),
        33 => roundtrip::<AccountLookup<VerifyingKey, Digest>>(bytes, &()),
        34 => roundtrip::<ChangeOpening<Digest>>(bytes, &()),
        35 => roundtrip::<ChangeAbsence<VerifyingKey, Digest>>(bytes, &()),
        36 => roundtrip::<AckWitness<VerifyingKey, Digest>>(bytes, &()),
        37 => roundtrip::<EntryWitness<VerifyingKey, Digest>>(bytes, &()),
        38 => roundtrip::<HigherEntryLookup<VerifyingKey, Digest>>(bytes, &()),
        39 => {
            deterministic::Runner::seeded(u64::from(limit_selector)).start(|runtime| async move {
                challenge_roundtrip(bytes, limit_selector, runtime).await
            })
        }
        40 => roundtrip::<Header<Digest>>(bytes, &()),
        41 => roundtrip::<RootBundle<Digest>>(bytes, &()),
        42 => roundtrip::<BatchId<Digest>>(bytes, &()),
        43 => roundtrip::<CloseLimits>(bytes, &()),
        44 => roundtrip::<StateRoot<Digest>>(bytes, &()),
        45 => roundtrip::<StateValueOpening<Digest>>(bytes, &item_limit),
        46 => roundtrip::<StateOpening<VerifyingKey, Digest>>(bytes, &item_limit),
        47 => roundtrip::<CloseAmounts>(bytes, &()),
        48 => roundtrip::<WithdrawalOutput>(bytes, &RangeCfg::new(..=destination_limit)),
        49 => roundtrip::<WithdrawalClaim<Digest>>(bytes, &RangeCfg::new(..=destination_limit)),
        50 => roundtrip::<ExternalPayoutClaim<VerifyingKey, Digest>>(bytes, &()),
        51 => deterministic::Runner::seeded(u64::from(limit_selector))
            .start(|runtime| async move { dealing_roundtrip(bytes, close_limits, runtime).await }),
        _ => unreachable!(),
    }

    if !bytes.is_empty() {
        assert!(matches!(
            decode_bounded::<VerifyingKey, Digest>(bytes, bytes.len() - 1),
            Err(ChallengeError::TooLarge)
        ));
    }
});
