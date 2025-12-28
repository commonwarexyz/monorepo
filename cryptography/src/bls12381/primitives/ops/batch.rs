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
    core::{hash_message, hash_message_namespace},
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use commonware_math::algebra::{Random, Space};
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
    let hm = namespace.map_or_else(
        || hash_message::<V>(V::MESSAGE, message),
        |ns| hash_message_namespace::<V>(V::MESSAGE, ns, message),
    );

    // Iteratively bisect to find invalid signatures
    let mut invalid = Vec::new();
    let mut stack = vec![(0, entries.len())];
    while let Some((start, end)) = stack.pop() {
        let slice = &entries[start..end];
        if slice.is_empty() {
            continue;
        }

        // Generate random scalars for each signature in this slice
        let scalars: Vec<Scalar> = (0..slice.len())
            .map(|_| Scalar::random(&mut *rng))
            .collect();

        // Compute weighted sums: sum(r_i * pk_i) and sum(r_i * sig_i)
        let pks: Vec<V::Public> = slice.iter().map(|(pk, _)| *pk).collect();
        let sigs: Vec<V::Signature> = slice.iter().map(|(_, sig)| *sig).collect();
        let weighted_pk = V::Public::msm(&pks, &scalars, 1);
        let weighted_sig = V::Signature::msm(&sigs, &scalars, 1);

        // Verify: e(weighted_pk, H(m)) == e(weighted_sig, G)
        if V::verify(&weighted_pk, &hm, &weighted_sig).is_err() {
            if slice.len() == 1 {
                invalid.push(start);
            } else {
                let mid = slice.len() / 2;
                stack.push((start + mid, end));
                stack.push((start, start + mid));
            }
        }
    }

    invalid
}

/// Verifies multiple signatures over multiple unique messages from a single public key,
/// ensuring each individual signature is valid.
///
/// Each entry is a tuple of (namespace, message, signature).
///
/// # Warning
///
/// This function assumes a group check was already performed on `public` and each `signature`.
/// It is not safe to provide an aggregate public key or to provide duplicate messages.
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
        .map(|(namespace, msg, _)| {
            namespace.as_ref().map_or_else(
                || hash_message::<V>(V::MESSAGE, msg),
                |namespace| hash_message_namespace::<V>(V::MESSAGE, namespace, msg),
            )
        })
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
        super::core::{keypair, sign_message},
        *,
    };
    use crate::bls12381::primitives::variant::{MinPk, MinSig};
    use commonware_math::algebra::CryptoGroup;
    use rand::prelude::*;

    fn verify_multiple_messages_correct<V: Variant>() {
        let (private, public) = keypair::<_, V>(&mut thread_rng());
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

        verify_multiple_messages::<_, V, _>(&mut thread_rng(), &public, &entries, 1)
            .expect("valid signatures should be accepted");

        verify_multiple_messages::<_, V, _>(&mut thread_rng(), &public, &entries, 4)
            .expect("valid signatures should be accepted with parallelism");
    }

    #[test]
    fn test_verify_multiple_messages_correct() {
        verify_multiple_messages_correct::<MinPk>();
        verify_multiple_messages_correct::<MinSig>();
    }

    fn verify_multiple_messages_wrong_signature<V: Variant>() {
        let (private, public) = keypair::<_, V>(&mut thread_rng());
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

        let random_scalar = Scalar::random(&mut thread_rng());
        entries[1].2 += &(V::Signature::generator() * &random_scalar);

        let result = verify_multiple_messages::<_, V, _>(&mut thread_rng(), &public, &entries, 1);
        assert!(result.is_err(), "corrupted signature should be rejected");
    }

    #[test]
    fn test_verify_multiple_messages_wrong_signature() {
        verify_multiple_messages_wrong_signature::<MinPk>();
        verify_multiple_messages_wrong_signature::<MinSig>();
    }
}
