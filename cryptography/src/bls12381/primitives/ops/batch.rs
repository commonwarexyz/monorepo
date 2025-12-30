//! Batch verification for BLS12-381 signatures.
//!
//! This module provides batch verification functions that ensure each individual
//! signature is valid (not just the aggregate). Use [`aggregate`](super::aggregate) instead
//! if you only need to verify aggregate validity (more efficient).
//!
//! # How It Works
//!
//! These functions apply random scalar weights to prevent attacks where an attacker
//! could redistribute signature components between signers while keeping the aggregate
//! unchanged. This ensures that if batch verification passes, each individual signature
//! was valid.

use super::{
    super::{group::Scalar, variant::Variant, Error},
    hash_message_with_namespace,
};
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use commonware_math::algebra::{Additive, Random, Space};
use rand_core::CryptoRngCore;

/// Verifies multiple signatures over the same message from different public keys,
/// ensuring each individual signature is valid.
///
/// Returns the indices of any invalid signatures found. Uses bisection internally
/// to efficiently identify which signatures are invalid.
///
/// # Warning
///
/// This function assumes a group check was already performed on each public key
/// and signature.
pub fn verify_multiple_public_keys<R, V>(
    rng: &mut R,
    namespace: Option<&[u8]>,
    message: &[u8],
    entries: &[(V::Public, V::Signature)],
) -> Vec<usize>
where
    R: CryptoRngCore,
    V: Variant,
{
    if entries.is_empty() {
        return Vec::new();
    }

    // Hash the message once
    let hm = hash_message_with_namespace::<V>(namespace, message);

    // Generate random scalars once for all entries
    let scalars: Vec<Scalar> = (0..entries.len())
        .map(|_| Scalar::random(&mut *rng))
        .collect();

    // Pre-compute weighted values once: weighted_pk[i] = scalar[i] * pk[i]
    let weighted_pks: Vec<V::Public> = entries
        .iter()
        .zip(&scalars)
        .map(|((pk, _), s)| *pk * s)
        .collect();
    let weighted_sigs: Vec<V::Signature> = entries
        .iter()
        .zip(&scalars)
        .map(|((_, sig), s)| *sig * s)
        .collect();

    // Iteratively bisect to find invalid signatures
    let mut invalid = Vec::new();
    let mut stack = vec![(0, entries.len())];
    while let Some((start, end)) = stack.pop() {
        if start >= end {
            continue;
        }

        // Sum pre-computed weighted values for this slice
        let mut sum_pk = V::Public::zero();
        let mut sum_sig = V::Signature::zero();
        for i in start..end {
            sum_pk += &weighted_pks[i];
            sum_sig += &weighted_sigs[i];
        }

        // Verify: e(sum_pk, H(m)) == e(sum_sig, G)
        if V::verify(&sum_pk, &hm, &sum_sig).is_err() {
            if end - start == 1 {
                invalid.push(start);
            } else {
                let mid = start + (end - start) / 2;
                stack.push((mid, end));
                stack.push((start, mid));
            }
        }
    }

    invalid
}

/// Verifies multiple signatures over multiple messages from a single public key,
/// ensuring each individual signature is valid.
///
/// Each entry is a tuple of (namespace, message, signature).
///
/// # Warning
///
/// This function assumes a group check was already performed on `public` and each `signature`.
/// It is not safe to provide an aggregate public key. Duplicate messages are safe because
/// random scalar weights ensure each (message, signature) pair is verified independently.
pub fn verify_multiple_messages<'a, R, V, I>(
    rng: &mut R,
    public: &V::Public,
    entries: I,
    concurrency: usize,
) -> Result<(), Error>
where
    R: CryptoRngCore,
    V: Variant,
    I: IntoIterator<Item = &'a (Option<&'a [u8]>, &'a [u8], V::Signature)>,
{
    let entries: Vec<_> = entries.into_iter().collect();

    if entries.is_empty() {
        return Ok(());
    }

    // Generate random scalars for each message/signature pair
    let scalars: Vec<Scalar> = (0..entries.len())
        .map(|_| Scalar::random(&mut *rng))
        .collect();

    // Hash all messages and collect signatures
    let hms: Vec<V::Signature> = entries
        .iter()
        .map(|(namespace, msg, _)| hash_message_with_namespace::<V>(*namespace, msg))
        .collect();
    let sigs: Vec<V::Signature> = entries.iter().map(|(_, _, sig)| *sig).collect();

    // Compute weighted sums using MSM
    let weighted_hm = V::Signature::msm(&hms, &scalars, concurrency);
    let weighted_sig = V::Signature::msm(&sigs, &scalars, concurrency);

    // Verify: e(pk, weighted_hm) == e(weighted_sig, G)
    V::verify(public, &weighted_hm, &weighted_sig)
}

#[cfg(test)]
mod tests {
    use super::{
        super::{aggregate, hash_message, keypair, sign_message, verify_message},
        *,
    };
    use crate::bls12381::primitives::variant::{MinPk, MinSig};
    use commonware_math::algebra::{CryptoGroup, Random};
    use commonware_utils::test_rng;

    fn verify_multiple_messages_correct<V: Variant>() {
        let mut rng = test_rng();
        let (private, public) = keypair::<_, V>(&mut rng);
        let namespace = Some(&b"test"[..]);
        let messages: &[(Option<&[u8]>, &[u8])] = &[
            (namespace, b"Message 1"),
            (namespace, b"Message 2"),
            (namespace, b"Message 3"),
        ];
        let entries: Vec<_> = messages
            .iter()
            .map(|(ns, msg)| (*ns, *msg, sign_message::<V>(&private, *ns, msg)))
            .collect();

        verify_multiple_messages::<_, V, _>(&mut rng, &public, &entries, 1)
            .expect("valid signatures should be accepted");

        verify_multiple_messages::<_, V, _>(&mut rng, &public, &entries, 4)
            .expect("valid signatures should be accepted with parallelism");
    }

    #[test]
    fn test_verify_multiple_messages_correct() {
        verify_multiple_messages_correct::<MinPk>();
        verify_multiple_messages_correct::<MinSig>();
    }

    fn verify_multiple_messages_wrong_signature<V: Variant>() {
        let mut rng = test_rng();
        let (private, public) = keypair::<_, V>(&mut rng);
        let namespace = Some(&b"test"[..]);
        let messages: &[(Option<&[u8]>, &[u8])] = &[
            (namespace, b"Message 1"),
            (namespace, b"Message 2"),
            (namespace, b"Message 3"),
        ];
        let mut entries: Vec<_> = messages
            .iter()
            .map(|(ns, msg)| (*ns, *msg, sign_message::<V>(&private, *ns, msg)))
            .collect();

        let random_scalar = Scalar::random(&mut rng);
        entries[1].2 += &(V::Signature::generator() * &random_scalar);

        let result = verify_multiple_messages::<_, V, _>(&mut rng, &public, &entries, 1);
        assert!(result.is_err(), "corrupted signature should be rejected");
    }

    #[test]
    fn test_verify_multiple_messages_wrong_signature() {
        verify_multiple_messages_wrong_signature::<MinPk>();
        verify_multiple_messages_wrong_signature::<MinSig>();
    }

    fn resists_signature_redistribution<V: Variant>() {
        let mut rng = test_rng();
        let (private, public) = keypair::<_, V>(&mut rng);
        let msg1: &[u8] = b"message 1";
        let msg2: &[u8] = b"message 2";

        let sig1 = sign_message::<V>(&private, None, msg1);
        let sig2 = sign_message::<V>(&private, None, msg2);

        verify_message::<V>(&public, None, msg1, &sig1).expect("sig1 should be valid");
        verify_message::<V>(&public, None, msg2, &sig2).expect("sig2 should be valid");

        // Create forged signatures by redistributing components
        let random_scalar = Scalar::random(&mut rng);
        let delta = V::Signature::generator() * &random_scalar;
        let forged_sig1 = sig1 - &delta;
        let forged_sig2 = sig2 + &delta;

        // Forged signatures are invalid individually
        assert!(
            verify_message::<V>(&public, None, msg1, &forged_sig1).is_err(),
            "forged sig1 should be invalid individually"
        );
        assert!(
            verify_message::<V>(&public, None, msg2, &forged_sig2).is_err(),
            "forged sig2 should be invalid individually"
        );

        // But aggregates are identical (the attack)
        let forged_agg = aggregate::combine_signatures::<V, _>(&[forged_sig1, forged_sig2]);
        let valid_agg = aggregate::combine_signatures::<V, _>(&[sig1, sig2]);
        assert_eq!(forged_agg, valid_agg, "aggregates should be equal");

        // Naive aggregate verification accepts forged signatures
        let hm1 = hash_message::<V>(V::MESSAGE, msg1);
        let hm2 = hash_message::<V>(V::MESSAGE, msg2);
        let hm_sum = hm1 + &hm2;
        V::verify(&public, &hm_sum, forged_agg.inner())
            .expect("naive aggregate verification accepts forged aggregate");

        // Batch verification (with random weights) rejects forged signatures
        let forged_entries = vec![(None, msg1, forged_sig1), (None, msg2, forged_sig2)];
        let result = verify_multiple_messages::<_, V, _>(&mut rng, &public, &forged_entries, 1);
        assert!(
            result.is_err(),
            "batch verification should reject forged signatures"
        );

        // Batch verification accepts valid signatures
        let valid_entries = vec![(None, msg1, sig1), (None, msg2, sig2)];
        verify_multiple_messages::<_, V, _>(&mut rng, &public, &valid_entries, 1)
            .expect("batch verification should accept valid signatures");
    }

    #[test]
    fn test_resists_signature_redistribution() {
        resists_signature_redistribution::<MinPk>();
        resists_signature_redistribution::<MinSig>();
    }
}
