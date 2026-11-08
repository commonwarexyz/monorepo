#![no_main]

use arbitrary::Arbitrary;
use commonware_clearing::bajillion::{
    BalanceProof, Challenge, Close, Deposit, Flow, ForcedWithdrawal, Limits, Lookup, Opening,
    Payout, PayoutProof, Receipt, Request, Row, State, Summary, Withdrawal,
};
use commonware_codec::Codec;
use commonware_cryptography::{Sha256, ed25519::PublicKey, sha256::Digest};
use libfuzzer_sys::fuzz_target;

/// The most receivers a request or row may pay.
const RECEIVERS: usize = 16;

/// The limits closes are decoded with.
const LIMITS: Limits = Limits {
    rows: 16,
    receivers: RECEIVERS,
    withdrawals: 16,
};

/// A value of one wire type, or bytes to decode as every wire type.
#[allow(clippy::large_enum_variant)]
#[derive(Arbitrary, Debug)]
enum Input {
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
    Summary(Summary<Sha256>),
    Payout(Payout<PublicKey, u64>),
    PayoutProof(PayoutProof<PublicKey, Digest, u64>),
    BalanceProof(BalanceProof<Digest, u64>),
    Bytes(Vec<u8>),
}

/// Checks that `value` encodes to its stated size and decodes back to itself under `cfg`.
fn roundtrip<T: Codec + PartialEq + std::fmt::Debug>(value: &T, cfg: &T::Cfg) {
    let encoded = value.encode();
    assert_eq!(encoded.len(), value.encode_size());
    let decoded = T::decode_cfg(encoded, cfg).expect("an encoded value must decode");
    assert_eq!(&decoded, value);
}

/// Decodes `bytes` as a `T` under `cfg`. A value that decodes must round-trip, and bytes that
/// do not decode must be refused without panicking.
fn decode<T: Codec + PartialEq + std::fmt::Debug>(bytes: &[u8], cfg: &T::Cfg) {
    if let Ok(value) = T::decode_cfg(bytes.to_vec(), cfg) {
        roundtrip(&value, cfg);
    }
}

fuzz_target!(|input: Input| {
    match input {
        Input::State(value) => roundtrip(&value, &()),
        Input::Request(value) => roundtrip(&value, &RECEIVERS),
        Input::Receipt(value) => roundtrip(&value, &()),
        Input::Challenge(value) => roundtrip(&value, &()),
        Input::Withdrawal(value) => roundtrip(&value, &()),
        Input::Deposit(value) => roundtrip(&value, &()),
        Input::ForcedWithdrawal(value) => roundtrip(&value, &()),
        Input::Row(value) => roundtrip(&value, &RECEIVERS),
        Input::Close(value) => roundtrip(&value, &LIMITS),
        Input::Lookup(value) => roundtrip(&value, &()),
        Input::Opening(value) => roundtrip(&value, &()),
        Input::Flow(value) => roundtrip(&value, &()),
        Input::Summary(value) => roundtrip(&value, &()),
        Input::Payout(value) => roundtrip(&value, &()),
        Input::PayoutProof(value) => roundtrip(&value, &()),
        Input::BalanceProof(value) => roundtrip(&value, &()),
        Input::Bytes(bytes) => {
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
            decode::<Summary<Sha256>>(&bytes, &());
            decode::<Payout<PublicKey, u64>>(&bytes, &());
            decode::<PayoutProof<PublicKey, Digest, u64>>(&bytes, &());
            decode::<BalanceProof<Digest, u64>>(&bytes, &());
        }
    }
});
