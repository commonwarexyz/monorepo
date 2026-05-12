//! Project Wycheproof verification tests for Ed25519.
//!
//! These tests load real Wycheproof test vectors (not random keys generated at
//! runtime) and feed them through the same verification path used in
//! production: [`crate::ed25519::core::VerificationKey::verify`]. The raw
//! `core` entry point is intentional; the [`crate::Verifier`] surface prefixes
//! messages with a namespace via `union_unique`, which would invalidate every
//! upstream vector.
//!
//! # Source
//!
//! Vectors come from `testvectors_v1/ed25519_test.json` in
//! [Project Wycheproof](https://github.com/C2SP/wycheproof), pinned at commit
//! `6d9d6de30f02e229dfc160323722c3ddac866181`:
//!
//! <https://github.com/C2SP/wycheproof/blob/6d9d6de30f02e229dfc160323722c3ddac866181/testvectors_v1/ed25519_test.json>
//!
//! The JSON is vendored at
//! `cryptography/test_vectors/wycheproof/ed25519_test.json` and preprocessed
//! offline into the `VECTORS` constant in
//! [`super::wycheproof_vectors`]. Offline preprocessing keeps the crate free of
//! a JSON parser dependency (per `CONTRIBUTING.md`); to refresh the vectors,
//! run `python3 cryptography/test_vectors/wycheproof/regenerate.py`.
//!
//! # ZIP215 deviations from strict RFC 8032
//!
//! This crate implements [ZIP215](https://zips.z.cash/zip-0215), which is
//! deliberately more permissive than the strict RFC 8032 verifier Wycheproof
//! targets:
//!
//! * Non-canonical encodings of `A_bytes` and `R_bytes` MUST be accepted as
//!   long as they decompress to a valid Edwards point.
//! * `s_bytes` MUST be canonical (`s < l`).
//! * The cofactored equation `[8][s]B = [8]R + [8][k]A` is used.
//!
//! Consequently, some vectors that Wycheproof labels `invalid` (typically those
//! exercising non-canonical encodings or small-order / low-order subgroup
//! points) are legitimately accepted by a correct ZIP215 implementation. Any
//! such vector must appear in [`ZIP215_DEVIATIONS`] with a justification.
//!
//! At the pinned commit, an empirical run found no vectors that require an
//! exception, so `ZIP215_DEVIATIONS` is currently empty. The framework is
//! retained so that future upstream additions can be audited explicitly rather
//! than silently masked.

use super::{
    core::{Signature, VerificationKey},
    wycheproof_vectors::{NUMBER_OF_TESTS, VECTORS},
};
use core::convert::TryFrom;

/// Expected verdict for a single Wycheproof vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Verdict {
    /// Strict RFC 8032 verifiers (and ZIP215) must accept.
    Valid,
    /// Strict RFC 8032 verifiers must reject. ZIP215 verifiers must also
    /// reject unless the `tcId` appears in [`ZIP215_DEVIATIONS`].
    Invalid,
}

/// A single Wycheproof Ed25519 test vector.
///
/// Bytes are stored already-decoded from the upstream hex strings so the test
/// loop performs no parsing of its own.
#[derive(Debug)]
pub(super) struct Vector {
    pub tc_id: u32,
    pub comment: &'static str,
    pub public_key: &'static [u8],
    pub msg: &'static [u8],
    pub sig: &'static [u8],
    pub result: Verdict,
    pub flags: &'static [&'static str],
}

/// Wycheproof `tcId`s where ZIP215 deliberately diverges from the strict
/// RFC 8032 verdict (Wycheproof says `invalid`, ZIP215 accepts).
///
/// Each entry must cite the deviation class so reviewers can audit it:
///
/// * "non-canonical A": `A_bytes` decompresses to a valid point but is not the
///   canonical encoding.
/// * "non-canonical R": same, for the signature's `R_bytes`.
/// * "low-order / small-subgroup point": `A` or `R` lies in a non-prime-order
///   subgroup; ZIP215's cofactored equation `[8][s]B = [8]R + [8][k]A` still
///   holds.
///
/// At the pinned upstream commit this list is empty. Adding an entry should
/// be a deliberate auditing step paired with a comment justifying the class.
const ZIP215_DEVIATIONS: &[(u32, &str)] = &[];

fn is_deviation(tc_id: u32) -> Option<&'static str> {
    ZIP215_DEVIATIONS
        .iter()
        .find(|(id, _)| *id == tc_id)
        .map(|(_, reason)| *reason)
}

/// Run a Wycheproof vector through the production verifier and return whether
/// it was accepted. Vectors whose key or signature have the wrong on-wire
/// length are reported as rejected without invoking `verify`; both RFC 8032
/// and ZIP215 reject these at the parse step.
fn verify_vector(v: &Vector) -> bool {
    let vk = match <[u8; 32]>::try_from(v.public_key) {
        Ok(bytes) => match VerificationKey::try_from(bytes) {
            Ok(vk) => vk,
            Err(_) => return false,
        },
        Err(_) => return false,
    };
    let sig = match <[u8; 64]>::try_from(v.sig) {
        Ok(bytes) => Signature::from(bytes),
        Err(_) => return false,
    };
    vk.verify(&sig, v.msg).is_ok()
}

/// Every Wycheproof vector labelled `valid` must verify under ZIP215.
/// ZIP215 is a superset of RFC 8032 with respect to acceptance, so any failure
/// here is a real bug.
#[test]
fn wycheproof_valid_vectors_verify() {
    let mut failures = Vec::new();
    for v in VECTORS.iter().filter(|v| v.result == Verdict::Valid) {
        if !verify_vector(v) {
            failures.push(format!(
                "tcId={} ({}) flags={:?} unexpectedly rejected",
                v.tc_id, v.comment, v.flags
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "valid-vector failures:\n  {}",
        failures.join("\n  ")
    );
}

/// Every Wycheproof vector labelled `invalid` must be rejected, except for
/// entries explicitly carved out in [`ZIP215_DEVIATIONS`] (currently none at
/// the pinned commit).
#[test]
fn wycheproof_invalid_vectors_rejected() {
    let mut unexpected_accepts = Vec::new();
    let mut stale_deviations = Vec::new();
    for v in VECTORS.iter().filter(|v| v.result == Verdict::Invalid) {
        let accepted = verify_vector(v);
        match (accepted, is_deviation(v.tc_id)) {
            (false, None) => {}
            (true, Some(_)) => {}
            (true, None) => unexpected_accepts.push(format!(
                "tcId={} ({}) flags={:?} accepted but Wycheproof labels invalid; \
                 either fix the verifier or add to ZIP215_DEVIATIONS with a class citation",
                v.tc_id, v.comment, v.flags
            )),
            (false, Some(reason)) => stale_deviations.push(format!(
                "tcId={} listed in ZIP215_DEVIATIONS ({}) but the verifier now rejects it; \
                 remove the stale entry",
                v.tc_id, reason
            )),
        }
    }
    assert!(
        unexpected_accepts.is_empty() && stale_deviations.is_empty(),
        "invalid-vector mismatches:\n  unexpected accepts:\n    {}\n  stale deviations:\n    {}",
        unexpected_accepts.join("\n    "),
        stale_deviations.join("\n    "),
    );
}

/// Guard against accidental truncation of the auto-generated vector array.
/// `NUMBER_OF_TESTS` is the `numberOfTests` field from upstream at the pinned
/// commit; if these diverge, the regeneration script has produced a partial
/// file.
#[test]
fn vector_count_matches_upstream() {
    assert_eq!(
        VECTORS.len(),
        NUMBER_OF_TESTS,
        "generated VECTORS length ({}) does not match upstream numberOfTests ({}); \
         re-run cryptography/test_vectors/wycheproof/regenerate.py",
        VECTORS.len(),
        NUMBER_OF_TESTS,
    );
}
