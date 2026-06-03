//! Codec fuzz harness for the `aggregation` types.
//!
//! Exercises the `Read`/`read_cfg`, `Write`/`EncodeSize`, and `Arbitrary` impls
//! for [`Item`], [`Ack`], [`TipAck`], [`Certificate`], and [`Activity`] that the
//! engine harness never reaches: an arbitrary value is built, encoded, and
//! decoded back (roundtrip equality), and the raw input bytes are also fed
//! through each `read_cfg` to drive the decode error paths.

use crate::aggregation_certificate_mock::Scheme as MockScheme;
use arbitrary::{Arbitrary, Unstructured};
use commonware_codec::{Decode, DecodeExt, Encode, EncodeSize, Read, ReadExt};
use commonware_consensus::aggregation::types::{Ack, Activity, Certificate, Item, TipAck};
use commonware_cryptography::{ed25519::PublicKey, sha256::Digest as Sha256Digest};

/// Concrete mock scheme matching the flags used by the aggregation engine
/// harness (`fixture_with::<false, true, true>`). Its `Certificate`/`Signature`
/// are `U64`, so every codec config below is `()`.
type Scheme = MockScheme<PublicKey, false, true, true>;

pub fn fuzz(data: &[u8]) {
    let mut u = Unstructured::new(data);

    roundtrip_item(&mut u);
    roundtrip_ack(&mut u);
    roundtrip_tip_ack(&mut u);
    roundtrip_certificate(&mut u);
    roundtrip_activity(&mut u);

    // Decode error paths: feed the remaining raw bytes through each reader and
    // discard the result. These must never panic.
    let rest = u.take_rest();
    let _ = Item::<Sha256Digest>::decode(rest);
    let _ = Ack::<Scheme, Sha256Digest>::decode(rest);
    let _ = TipAck::<Scheme, Sha256Digest>::decode(rest);
    let _ = Certificate::<Scheme, Sha256Digest>::decode_cfg(rest, &());
    let _ = Activity::<Scheme, Sha256Digest>::decode_cfg(rest, &());
}

fn roundtrip_item(u: &mut Unstructured<'_>) {
    let Ok(item) = Item::<Sha256Digest>::arbitrary(u) else {
        return;
    };
    let encoded = item.encode();
    assert_eq!(encoded.len(), item.encode_size());
    let decoded = Item::<Sha256Digest>::read(&mut encoded.as_ref()).unwrap();
    assert_eq!(item, decoded);
}

fn roundtrip_ack(u: &mut Unstructured<'_>) {
    let Ok(ack) = Ack::<Scheme, Sha256Digest>::arbitrary(u) else {
        return;
    };
    let encoded = ack.encode();
    assert_eq!(encoded.len(), ack.encode_size());
    let decoded = Ack::<Scheme, Sha256Digest>::read(&mut encoded.as_ref()).unwrap();
    assert_eq!(encoded, decoded.encode());
}

fn roundtrip_tip_ack(u: &mut Unstructured<'_>) {
    let Ok(tip_ack) = TipAck::<Scheme, Sha256Digest>::arbitrary(u) else {
        return;
    };
    let encoded = tip_ack.encode();
    assert_eq!(encoded.len(), tip_ack.encode_size());
    let decoded = TipAck::<Scheme, Sha256Digest>::read(&mut encoded.as_ref()).unwrap();
    assert_eq!(encoded, decoded.encode());
}

fn roundtrip_certificate(u: &mut Unstructured<'_>) {
    let Ok(certificate) = Certificate::<Scheme, Sha256Digest>::arbitrary(u) else {
        return;
    };
    let encoded = certificate.encode();
    assert_eq!(encoded.len(), certificate.encode_size());
    let decoded =
        Certificate::<Scheme, Sha256Digest>::read_cfg(&mut encoded.as_ref(), &()).unwrap();
    // `Scheme` has no `PartialEq`, so the derived `Certificate: PartialEq` bound
    // is unavailable; compare re-encoded bytes instead.
    assert_eq!(encoded, decoded.encode());
}

fn roundtrip_activity(u: &mut Unstructured<'_>) {
    let Ok(activity) = Activity::<Scheme, Sha256Digest>::arbitrary(u) else {
        return;
    };
    let encoded = activity.encode();
    assert_eq!(encoded.len(), activity.encode_size());
    let decoded = Activity::<Scheme, Sha256Digest>::read_cfg(&mut encoded.as_ref(), &()).unwrap();
    // See `roundtrip_certificate`: compare re-encoded bytes (no `Scheme: PartialEq`).
    assert_eq!(encoded, decoded.encode());
}
