#![no_main]

use arbitrary::Arbitrary;
use commonware_clearing::bajillion::{
    Amounts, BalanceProof, Challenge, Close, Deposit, Flow, ForcedWithdrawal, Limits, Lookup,
    Opening, Payout, PayoutProof, Payouts, Processed, Receipt, Request, Row, State, Summary,
    Withdrawal,
};
use commonware_codec::{Codec, Copying, RangeCfg};
use commonware_cryptography::{Sha256, ed25519::PublicKey, sha256::Digest};
use libfuzzer_sys::fuzz_target;
use std::fmt::Debug;

/// The most receivers a request or row may pay when decoding bytes.
const RECEIVERS: usize = 16;

/// The limits closes are decoded from bytes with.
const LIMITS: Limits = Limits {
    rows: 16,
    receivers: RECEIVERS,
    withdrawals: 16,
};

/// A value of one wire type, or bytes to decode as every wire type.
#[allow(clippy::large_enum_variant)]
#[derive(Arbitrary, Debug)]
enum FuzzInput {
    Amounts(Amounts<PublicKey, u64>),
    State(State<PublicKey, Digest>),
    Request(Request<PublicKey, Digest, u64>),
    Receipt(Receipt<PublicKey, PublicKey, Digest, u64>),
    Challenge(Challenge<PublicKey, PublicKey, Digest, u64>),
    Withdrawal(Withdrawal<PublicKey, u64>),
    Deposit(Deposit<PublicKey, u64>),
    ForcedWithdrawal(ForcedWithdrawal<PublicKey, u64>),
    Row(Row<PublicKey, u64>),
    Close(Close<PublicKey, PublicKey, u64>),
    Lookup(Lookup<PublicKey, u64, Digest>),
    Opening(Opening<PublicKey, Digest, u64>),
    Flow(Flow<u64>),
    Processed(Processed<Digest>),
    Payouts(Payouts<Digest>),
    Summary(Summary<Sha256>),
    Payout(Payout<PublicKey, u64>),
    PayoutProof(PayoutProof<PublicKey, Digest, u64>),
    BalanceProof(BalanceProof<Digest, u64>),
    Bytes(Vec<u8>),
}

/// Checks that `value` encodes to its stated size and decodes back to itself under `cfg`.
fn roundtrip<T: Codec + PartialEq + Debug>(value: &T, cfg: &T::Cfg) {
    let encoded = value.encode();
    assert_eq!(encoded.len(), value.encode_size());
    let decoded = T::decode_cfg(encoded, cfg).expect("an encoded value must decode");
    assert_eq!(&decoded, value);
}

/// Decodes `bytes` as a `T` under `cfg`. A value that decodes must round-trip, and bytes that
/// do not decode must be refused without panicking.
fn decode<T: Codec + PartialEq + Debug>(bytes: &[u8], cfg: &T::Cfg) {
    if let Ok(value) = T::decode_cfg(Copying(bytes), cfg) {
        roundtrip(&value, cfg);
    }
}

fuzz_target!(|input: FuzzInput| {
    match input {
        FuzzInput::Amounts(value) => roundtrip(&value, &RangeCfg::new(..=value.len())),
        FuzzInput::State(value) => roundtrip(&value, &()),
        FuzzInput::Request(value) => roundtrip(&value, &value.batch.len()),
        FuzzInput::Receipt(value) => roundtrip(&value, &()),
        FuzzInput::Challenge(value) => roundtrip(&value, &()),
        FuzzInput::Withdrawal(value) => roundtrip(&value, &()),
        FuzzInput::Deposit(value) => roundtrip(&value, &()),
        FuzzInput::ForcedWithdrawal(value) => roundtrip(&value, &()),
        FuzzInput::Row(value) => roundtrip(&value, &value.payments.len()),
        FuzzInput::Close(value) => {
            let limits = Limits {
                rows: value.rows().len(),
                receivers: value
                    .rows()
                    .iter()
                    .map(|row| row.payments.len())
                    .max()
                    .unwrap_or(0),
                withdrawals: value.withdrawals().len(),
            };
            roundtrip(&value, &limits)
        }
        FuzzInput::Lookup(value) => roundtrip(&value, &()),
        FuzzInput::Opening(value) => roundtrip(&value, &()),
        FuzzInput::Flow(value) => roundtrip(&value, &()),
        FuzzInput::Processed(value) => roundtrip(&value, &()),
        FuzzInput::Payouts(value) => roundtrip(&value, &()),
        FuzzInput::Summary(value) => roundtrip(&value, &()),
        FuzzInput::Payout(value) => roundtrip(&value, &()),
        FuzzInput::PayoutProof(value) => roundtrip(&value, &()),
        FuzzInput::BalanceProof(value) => roundtrip(&value, &()),
        FuzzInput::Bytes(bytes) => {
            decode::<Amounts<PublicKey, u64>>(&bytes, &RangeCfg::new(..=RECEIVERS));
            decode::<State<PublicKey, Digest>>(&bytes, &());
            decode::<Request<PublicKey, Digest, u64>>(&bytes, &RECEIVERS);
            decode::<Receipt<PublicKey, PublicKey, Digest, u64>>(&bytes, &());
            decode::<Challenge<PublicKey, PublicKey, Digest, u64>>(&bytes, &());
            decode::<Withdrawal<PublicKey, u64>>(&bytes, &());
            decode::<Deposit<PublicKey, u64>>(&bytes, &());
            decode::<ForcedWithdrawal<PublicKey, u64>>(&bytes, &());
            decode::<Row<PublicKey, u64>>(&bytes, &RECEIVERS);
            decode::<Close<PublicKey, PublicKey, u64>>(&bytes, &LIMITS);
            decode::<Lookup<PublicKey, u64, Digest>>(&bytes, &());
            decode::<Opening<PublicKey, Digest, u64>>(&bytes, &());
            decode::<Flow<u64>>(&bytes, &());
            decode::<Processed<Digest>>(&bytes, &());
            decode::<Payouts<Digest>>(&bytes, &());
            decode::<Summary<Sha256>>(&bytes, &());
            decode::<Payout<PublicKey, u64>>(&bytes, &());
            decode::<PayoutProof<PublicKey, Digest, u64>>(&bytes, &());
            decode::<BalanceProof<Digest, u64>>(&bytes, &());
        }
    }
});
