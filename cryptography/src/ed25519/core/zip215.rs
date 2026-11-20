//! ZIP215 conformance cases ported from `ed25519-zebra`'s `small_order` test suite.
//!
//! ZIP215 requires non-canonical point encodings to be accepted and the cofactored
//! verification equation `[8][s]B = [8]R + [8][k]A` to be used, so every signature whose `R`
//! and `A` are low-order points with `s = 0` verifies. These cases pin that behavior for both
//! individual and batch verification.

use super::{Signature, VerificationKey, batch};
use commonware_parallel::Sequential;
use commonware_utils::test_rng;
use curve25519_dalek::{
    constants::EIGHT_TORSION,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    traits::IsIdentity,
};

const MSG: &[u8] = b"Zcash";

/// The 19 field elements that also have a non-canonical 255-bit encoding `y + p`.
fn non_canonical_field_encodings() -> Vec<[u8; 32]> {
    let mut bytes = [0xff; 32];
    bytes[31] = 0x7f;
    (0..19u8)
        .map(|i| {
            bytes[0] = 237 + i;
            bytes
        })
        .collect()
}

/// All 26 non-canonical point encodings. The first six are low order.
///
/// An encoding is non-canonical either because `x = 0` and the sign bit is set (`y = 1` or
/// `y = -1`) or because `y` is encoded as `y + p`; twelve of the nineteen such field elements
/// are `y` coordinates of curve points, and each of those decodes with either sign bit.
fn non_canonical_point_encodings() -> Vec<[u8; 32]> {
    let mut encodings = Vec::new();

    // Canonical y with a non-canonical sign bit.
    let mut y1 = [0u8; 32];
    y1[0] = 1;
    y1[31] = 128;
    encodings.push(y1);
    let mut ym1 = [0xff; 32];
    ym1[0] = 236;
    encodings.push(ym1);

    // Non-canonical y with either sign bit, kept only when it decodes to a curve point.
    for mut y in non_canonical_field_encodings() {
        if CompressedEdwardsY(y).decompress().is_some() {
            encodings.push(y);
        }
        y[31] |= 128;
        if CompressedEdwardsY(y).decompress().is_some() {
            encodings.push(y);
        }
    }

    assert_eq!(encodings.len(), 26);
    for encoding in &encodings {
        let point = CompressedEdwardsY(*encoding).decompress().unwrap();
        assert_ne!(point.compress().to_bytes(), *encoding);
    }
    encodings
}

/// Every encoding of a low-order point: the eight canonical torsion encodings plus the six
/// low-order non-canonical encodings.
fn low_order_encodings() -> Vec<[u8; 32]> {
    let non_canonical = non_canonical_point_encodings();
    let (low, high) = non_canonical.split_at(6);
    for encoding in low {
        let point = CompressedEdwardsY(*encoding).decompress().unwrap();
        assert!(point.mul_by_cofactor().is_identity());
    }
    for encoding in high {
        let point = CompressedEdwardsY(*encoding).decompress().unwrap();
        assert!(!point.mul_by_cofactor().is_identity());
    }
    EIGHT_TORSION
        .iter()
        .map(|point| point.compress().to_bytes())
        .chain(low.iter().copied())
        .collect()
}

/// Builds the signature `(R, 0)` for the given `R` encoding.
fn zero_s_signature(r: [u8; 32]) -> Signature {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&r);
    Signature::from(bytes)
}

fn verify_individually(vk: [u8; 32], sig: &Signature) -> bool {
    VerificationKey::try_from(vk).is_ok_and(|vk| vk.verify(sig, MSG).is_ok())
}

fn verify_batched(vk: [u8; 32], sig: &Signature) -> bool {
    VerificationKey::try_from(vk).is_ok_and(|vk| {
        let mut verifier = batch::Verifier::new(1);
        verifier.queue(vk, *sig, MSG);
        verifier.verify(test_rng(), &Sequential).is_ok()
    })
}

#[test]
fn non_canonical_encodings_are_accepted() {
    for encoding in non_canonical_point_encodings() {
        assert!(VerificationKey::try_from(encoding).is_ok(), "{encoding:?}");
    }
}

#[test]
fn small_order_signatures_verify() {
    let encodings = low_order_encodings();
    assert_eq!(encodings.len(), 14);
    for a in &encodings {
        for r in &encodings {
            let sig = zero_s_signature(*r);
            assert!(verify_individually(*a, &sig), "A={a:?} R={r:?}");
        }
    }
}

#[test]
fn small_order_signatures_reject_full_order_r() {
    let identity = EIGHT_TORSION[0].compress().to_bytes();
    let full_order = EdwardsPoint::mul_base(&curve25519_dalek::scalar::Scalar::ONE)
        .compress()
        .to_bytes();
    let sig = zero_s_signature(full_order);
    assert!(!verify_individually(identity, &sig));
    assert!(!verify_batched(identity, &sig));
}

#[test]
fn individual_matches_batch_verification() {
    let encodings = low_order_encodings();
    for a in &encodings {
        for r in &encodings {
            let sig = zero_s_signature(*r);
            assert_eq!(
                verify_individually(*a, &sig),
                verify_batched(*a, &sig),
                "A={a:?} R={r:?}"
            );
        }
    }
}
