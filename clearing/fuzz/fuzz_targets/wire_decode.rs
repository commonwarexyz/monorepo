#![no_main]

use commonware_clearing::bajillion::{
    admission::{
        Committee,
        bls12381::{Certificate, Vote},
    },
    boundary::{DepositBatch, SignedWithdrawal, WithdrawalAction, WithdrawalBatch, WithdrawalBody},
    challenge::{
        AccountLookup, AckWitness, ChallengeError, ChangeAbsence, ChangeOpening, EntryWitness,
        HigherEntryLookup, StateLookup, StateOpening, adjudicate, decode_bounded,
    },
    commitment::{MultiOpening, Opening, RangeOpening, VectorKind, VectorRoot, empty_root},
    payment::{EntryReceipt, PaymentContext, SendAuthorization, VectorAck, VectorSendBody},
    state::{
        AccountChange, AccountRow, AccountState, ChangeGuard, ChangeValue, ChangeValueCore, Prefix,
        SettlementOutput, StateLeaf,
    },
    transition::{
        Assignment, BatchId, CloseContext, CloseLimits, CoverageRange, EpochContext,
        ExternalPayoutClaim, Header, RootBundle, SliceBoundary, StateCache, TerminalProof,
        WithdrawalClaim, WithdrawalOutput, decode_slice_bounded,
    },
    vector::{
        OutEntry, OutTipLookup, OutVector, TransposeEntry, read_transpose, transpose_encode_size,
        write_transpose,
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
    let context = EpochContext::new::<Sha256>(
        Sha256::hash(&[b"wire-decode-challenge", &[seed]]),
        u64::from(seed),
        operator.public_key(),
        &deposits,
        &withdrawals,
        cache.liability(),
        u64::from(seed),
        u64::from(seed) + 1,
        CloseLimits::protocol_maximum(),
        Assignment::new(Sha256::hash(&[b"wire-decode-committee"]), 0)
            .expect("zero-bit assignment is valid"),
    )
    .and_then(|epoch| epoch.bind::<Sha256>(&cache, &deposits, &withdrawals))
    .expect("bounded semantic context must construct");
    let roots = RootBundle {
        change: empty_root::<Sha256>(VectorKind::Change),
        withdrawal_outputs: empty_root::<Sha256>(VectorKind::WithdrawalOutput),
        successor: cache.root(),
        coverage: empty_root::<Sha256>(VectorKind::Coverage),
        transpose: empty_root::<Sha256>(VectorKind::Transpose),
        transpose_len: 0,
    };
    let header = Header::new::<Sha256, _>(&context, &roots);
    (context, header, roots)
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
    let _ = adjudicate::<Sha256, _, _>(&context, &header, &roots, &decoded);
}

fn slice_roundtrip(bytes: &[u8], limits: CloseLimits) {
    let Ok(slice) = decode_slice_bounded::<VerifyingKey, Digest>(bytes, limits, MAX_INPUT_BYTES)
    else {
        return;
    };

    let encoded = slice.encode();
    assert_eq!(encoded.len(), slice.encoded_size());
    let decoded = decode_slice_bounded::<VerifyingKey, Digest>(
        &encoded,
        limits,
        MAX_INPUT_BYTES.max(encoded.len()),
    )
    .expect("encoded slice must remain bounded and decodable");
    assert_eq!(decoded, slice);
}

fn transpose_roundtrip(bytes: &[u8], max: usize) {
    let Ok(entries) = read_transpose::<VerifyingKey>(&mut &bytes[..], max) else {
        return;
    };

    // The decoder accepts adjacent runs sharing one recipient that the encoder would merge,
    // so parity is asserted on the canonical re-encoding rather than the input bytes.
    let mut encoded = Vec::new();
    write_transpose(&entries, &mut encoded);
    assert_eq!(encoded.len(), transpose_encode_size(&entries));
    let decoded = read_transpose::<VerifyingKey>(&mut &encoded[..], entries.len())
        .expect("encoded transpose interval must remain decodable");
    assert_eq!(decoded, entries);
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
        8 => roundtrip::<AccountState>(bytes, &()),
        9 => roundtrip::<StateLeaf<VerifyingKey>>(bytes, &()),
        10 => roundtrip::<Prefix>(bytes, &()),
        11 => roundtrip::<AccountRow<VerifyingKey, Digest>>(bytes, &()),
        12 => roundtrip::<SettlementOutput>(bytes, &()),
        13 => roundtrip::<AccountChange<VerifyingKey, Digest>>(bytes, &()),
        14 => roundtrip::<ChangeValue<Digest>>(bytes, &()),
        15 => roundtrip::<ChangeValueCore<Digest>>(bytes, &()),
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
        29 => roundtrip::<TransposeEntry<VerifyingKey>>(bytes, &()),
        30 => transpose_roundtrip(bytes, item_limit),
        31 => roundtrip::<StateOpening<VerifyingKey, Digest>>(bytes, &()),
        32 => roundtrip::<StateLookup<VerifyingKey, Digest>>(bytes, &()),
        33 => roundtrip::<AccountLookup<VerifyingKey, Digest>>(bytes, &()),
        34 => roundtrip::<ChangeOpening<Digest>>(bytes, &()),
        35 => roundtrip::<ChangeAbsence<VerifyingKey, Digest>>(bytes, &()),
        36 => roundtrip::<AckWitness<VerifyingKey, Digest>>(bytes, &()),
        37 => roundtrip::<EntryWitness<VerifyingKey, Digest>>(bytes, &()),
        38 => roundtrip::<HigherEntryLookup<VerifyingKey, Digest>>(bytes, &()),
        39 => challenge_roundtrip(bytes, limit_selector),
        40 => roundtrip::<Header<Digest>>(bytes, &()),
        41 => roundtrip::<RootBundle<Digest>>(bytes, &()),
        42 => roundtrip::<BatchId<Digest>>(bytes, &()),
        43 => roundtrip::<CloseLimits>(bytes, &()),
        44 => roundtrip::<Assignment<Digest>>(bytes, &()),
        45 => roundtrip::<SliceBoundary>(bytes, &()),
        46 => roundtrip::<CoverageRange<Digest>>(bytes, &()),
        47 => roundtrip::<TerminalProof<Digest>>(bytes, &()),
        48 => roundtrip::<WithdrawalOutput>(bytes, &RangeCfg::new(..=destination_limit)),
        49 => roundtrip::<WithdrawalClaim<Digest>>(bytes, &RangeCfg::new(..=destination_limit)),
        50 => roundtrip::<ExternalPayoutClaim<VerifyingKey, Digest>>(bytes, &()),
        51 => slice_roundtrip(bytes, close_limits),
        _ => unreachable!(),
    }

    if !bytes.is_empty() {
        assert!(matches!(
            decode_bounded::<VerifyingKey, Digest>(bytes, bytes.len() - 1),
            Err(ChallengeError::TooLarge)
        ));
    }
});
