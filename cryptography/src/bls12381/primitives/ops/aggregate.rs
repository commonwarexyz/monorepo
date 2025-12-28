//! Aggregation operations for BLS12-381 signatures.
//!
//! This module provides functions for aggregating public keys and signatures,
//! as well as verifying aggregate signatures.
//!
//! # Security Considerations
//!
//! Some functions in this module are vulnerable to signature malleability attacks
//! when used incorrectly. See the documentation for each function for details.
//! Use [`batch`](super::batch) instead when you need to ensure each individual signature is valid.

use super::{
    super::{variant::Variant, Error},
    core::{hash_message, hash_message_namespace, verify_message},
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use commonware_math::algebra::Additive;
#[cfg(feature = "std")]
use rayon::{prelude::*, ThreadPoolBuilder};

/// Aggregates multiple public keys.
///
/// # Warning
///
/// This function assumes a group check was already performed on all `public_keys`,
/// that each `public_key` is unique, and that the caller has a Proof-of-Possession (PoP)
/// for each `public_key`. If any of these assumptions are violated, an attacker can
/// exploit this function to verify an incorrect aggregate signature.
pub fn public_keys<'a, V, I>(public_keys: I) -> V::Public
where
    V: Variant,
    I: IntoIterator<Item = &'a V::Public>,
    V::Public: 'a,
{
    let mut p = V::Public::zero();
    for pk in public_keys {
        p += pk;
    }
    p
}

/// Aggregates multiple signatures.
///
/// # Warning
///
/// This function assumes a group check was already performed on each `signature` and
/// that each `signature` is unique. If any of these assumptions are violated, an attacker can
/// exploit this function to verify an incorrect aggregate signature.
pub fn signatures<'a, V, I>(signatures: I) -> V::Signature
where
    V: Variant,
    I: IntoIterator<Item = &'a V::Signature>,
    V::Signature: 'a,
{
    let mut s = V::Signature::zero();
    for sig in signatures {
        s += sig;
    }
    s
}

/// Verifies the aggregate signature over a single message from multiple public keys.
///
/// # Warning
///
/// This function assumes the caller has performed a group check and collected a proof-of-possession
/// for all provided `public`. This function assumes a group check was already performed on the
/// `signature`. It is not safe to provide duplicate public keys.
pub fn verify_multiple_public_keys<'a, V, I>(
    public: I,
    namespace: Option<&[u8]>,
    message: &[u8],
    signature: &V::Signature,
) -> Result<(), Error>
where
    V: Variant,
    I: IntoIterator<Item = &'a V::Public>,
    V::Public: 'a,
{
    // Aggregate public keys
    //
    // We can take advantage of the bilinearity property of pairings to aggregate public keys
    // that have all signed the same message (as long as all public keys are unique).
    let agg_public = public_keys::<V, _>(public);

    // Verify the signature
    verify_message::<V>(&agg_public, namespace, message, signature)
}

/// Verifies an aggregate signature over multiple unique messages from a single public key.
///
/// Each entry is a tuple of (namespace, message). The signature must be the aggregate
/// of all individual signatures.
///
/// # Warning
///
/// This function is vulnerable to signature malleability when used with signatures
/// that were aggregated from different messages. An attacker can redistribute
/// signature components between messages while keeping the aggregate unchanged.
/// Use [`batch::verify_multiple_messages`](super::batch::verify_multiple_messages) instead when signatures are provided individually.
///
/// This function assumes a group check was already performed on `public` and `signature`.
/// It is not safe to provide an aggregate public key or to provide duplicate messages.
pub fn verify_multiple_messages<'a, V, I>(
    public: &V::Public,
    messages: I,
    signature: &V::Signature,
    #[cfg_attr(not(feature = "std"), allow(unused_variables))] concurrency: usize,
) -> Result<(), Error>
where
    V: Variant,
    I: IntoIterator<Item = &'a (Option<&'a [u8]>, &'a [u8])> + Send + Sync,
    I::IntoIter: Send + Sync,
{
    #[cfg(not(feature = "std"))]
    let hm_sum = compute_hm_sum::<V, I>(messages);

    #[cfg(feature = "std")]
    let hm_sum = if concurrency == 1 {
        compute_hm_sum::<V, I>(messages)
    } else {
        let pool = ThreadPoolBuilder::new()
            .num_threads(concurrency)
            .build()
            .expect("Unable to build thread pool");

        pool.install(move || {
            messages
                .into_iter()
                .par_bridge()
                .map(|(namespace, msg)| {
                    namespace.as_ref().map_or_else(
                        || hash_message::<V>(V::MESSAGE, msg),
                        |namespace| hash_message_namespace::<V>(V::MESSAGE, namespace, msg),
                    )
                })
                .reduce(V::Signature::zero, |mut sum, hm| {
                    sum += &hm;
                    sum
                })
        })
    };

    V::verify(public, &hm_sum, signature)
}

/// Computes the sum over the hash of each message.
fn compute_hm_sum<'a, V, I>(messages: I) -> V::Signature
where
    V: Variant,
    I: IntoIterator<Item = &'a (Option<&'a [u8]>, &'a [u8])>,
{
    let mut hm_sum = V::Signature::zero();
    for (namespace, msg) in messages {
        let hm = namespace.as_ref().map_or_else(
            || hash_message::<V>(V::MESSAGE, msg),
            |namespace| hash_message_namespace::<V>(V::MESSAGE, namespace, msg),
        );
        hm_sum += &hm;
    }
    hm_sum
}

#[cfg(test)]
mod tests {
    use super::{
        super::{
            aggregate,
            batch::verify_multiple_messages,
            core::{hash_message, keypair, sign_message, verify_message},
        },
        *,
    };
    use crate::bls12381::primitives::{
        group::{Scalar, G1_MESSAGE, G2_MESSAGE},
        variant::{MinPk, MinSig},
        Error,
    };
    use blst::BLST_ERROR;
    use commonware_codec::Encode;
    use commonware_math::algebra::{CryptoGroup, Random};
    use commonware_utils::union_unique;
    use rand::prelude::*;

    fn blst_aggregate_verify_multiple_public_keys<'a, V, I>(
        public: I,
        message: &[u8],
        signature: &V::Signature,
    ) -> Result<(), BLST_ERROR>
    where
        V: Variant,
        I: IntoIterator<Item = &'a V::Public>,
        V::Public: 'a,
    {
        match V::MESSAGE {
            G1_MESSAGE => {
                let public = public
                    .into_iter()
                    .map(|pk| blst::min_sig::PublicKey::from_bytes(&pk.encode()).unwrap())
                    .collect::<Vec<_>>();
                let public = public.iter().collect::<Vec<_>>();
                let signature = blst::min_sig::Signature::from_bytes(&signature.encode()).unwrap();
                match signature.fast_aggregate_verify(true, message, V::MESSAGE, &public) {
                    BLST_ERROR::BLST_SUCCESS => Ok(()),
                    e => Err(e),
                }
            }
            G2_MESSAGE => {
                let public = public
                    .into_iter()
                    .map(|pk| blst::min_pk::PublicKey::from_bytes(&pk.encode()).unwrap())
                    .collect::<Vec<_>>();
                let public = public.iter().collect::<Vec<_>>();
                let signature = blst::min_pk::Signature::from_bytes(&signature.encode()).unwrap();
                match signature.fast_aggregate_verify(true, message, V::MESSAGE, &public) {
                    BLST_ERROR::BLST_SUCCESS => Ok(()),
                    e => Err(e),
                }
            }
            _ => panic!("Unsupported Variant"),
        }
    }

    fn aggregate_verify_multiple_public_keys_correct<V: Variant>() {
        let (private1, public1) = keypair::<_, V>(&mut thread_rng());
        let (private2, public2) = keypair::<_, V>(&mut thread_rng());
        let (private3, public3) = keypair::<_, V>(&mut thread_rng());
        let namespace = b"test";
        let message = b"message";
        let sig1 = sign_message::<V>(&private1, Some(namespace), message);
        let sig2 = sign_message::<V>(&private2, Some(namespace), message);
        let sig3 = sign_message::<V>(&private3, Some(namespace), message);
        let pks = vec![public1, public2, public3];
        let signatures = vec![sig1, sig2, sig3];

        let aggregate_sig = aggregate::signatures::<V, _>(&signatures);

        verify_multiple_public_keys::<V, _>(
            &pks,
            Some(namespace),
            message,
            &aggregate_sig,
        )
        .expect("Aggregated signature should be valid");

        let payload = union_unique(namespace, message);
        blst_aggregate_verify_multiple_public_keys::<V, _>(&pks, &payload, &aggregate_sig)
            .expect("Aggregated signature should be valid");
    }

    #[test]
    fn test_aggregate_verify_multiple_public_keys() {
        aggregate_verify_multiple_public_keys_correct::<MinPk>();
        aggregate_verify_multiple_public_keys_correct::<MinSig>();
    }

    fn aggregate_verify_wrong_public_keys<V: Variant>() {
        let (private1, public1) = keypair::<_, V>(&mut thread_rng());
        let (private2, public2) = keypair::<_, V>(&mut thread_rng());
        let (private3, _) = keypair::<_, V>(&mut thread_rng());
        let namespace = b"test";
        let message = b"message";
        let sig1 = sign_message::<V>(&private1, Some(namespace), message);
        let sig2 = sign_message::<V>(&private2, Some(namespace), message);
        let sig3 = sign_message::<V>(&private3, Some(namespace), message);
        let signatures = vec![sig1, sig2, sig3];

        let aggregate_sig = aggregate::signatures::<V, _>(&signatures);

        let (_, public4) = keypair::<_, V>(&mut thread_rng());
        let wrong_pks = vec![public1, public2, public4];
        let result = verify_multiple_public_keys::<V, _>(
            &wrong_pks,
            Some(namespace),
            message,
            &aggregate_sig,
        );
        assert!(matches!(result, Err(Error::InvalidSignature)));
    }

    #[test]
    fn test_aggregate_verify_wrong_public_keys() {
        aggregate_verify_wrong_public_keys::<MinPk>();
        aggregate_verify_wrong_public_keys::<MinSig>();
    }

    fn aggregate_verify_wrong_public_key_count<V: Variant>() {
        let (private1, public1) = keypair::<_, V>(&mut thread_rng());
        let (private2, public2) = keypair::<_, V>(&mut thread_rng());
        let (private3, _) = keypair::<_, V>(&mut thread_rng());
        let namespace = b"test";
        let message = b"message";
        let sig1 = sign_message::<V>(&private1, Some(namespace), message);
        let sig2 = sign_message::<V>(&private2, Some(namespace), message);
        let sig3 = sign_message::<V>(&private3, Some(namespace), message);
        let signatures = vec![sig1, sig2, sig3];

        let aggregate_sig = aggregate::signatures::<V, _>(&signatures);

        let wrong_pks = vec![public1, public2];
        let result = verify_multiple_public_keys::<V, _>(
            &wrong_pks,
            Some(namespace),
            message,
            &aggregate_sig,
        );
        assert!(matches!(result, Err(Error::InvalidSignature)));
    }

    #[test]
    fn test_aggregate_verify_wrong_public_key_count() {
        aggregate_verify_wrong_public_key_count::<MinPk>();
        aggregate_verify_wrong_public_key_count::<MinSig>();
    }

    fn blst_aggregate_verify_multiple_messages<'a, V, I>(
        public: &V::Public,
        msgs: I,
        signature: &V::Signature,
    ) -> Result<(), BLST_ERROR>
    where
        V: Variant,
        I: IntoIterator<Item = &'a [u8]>,
    {
        match V::MESSAGE {
            G1_MESSAGE => {
                let public = blst::min_sig::PublicKey::from_bytes(&public.encode()).unwrap();
                let msgs = msgs.into_iter().collect::<Vec<_>>();
                let pks = vec![&public; msgs.len()];
                let signature = blst::min_sig::Signature::from_bytes(&signature.encode()).unwrap();
                match signature.aggregate_verify(true, &msgs, V::MESSAGE, &pks, true) {
                    BLST_ERROR::BLST_SUCCESS => Ok(()),
                    e => Err(e),
                }
            }
            G2_MESSAGE => {
                let public = blst::min_pk::PublicKey::from_bytes(&public.encode()).unwrap();
                let msgs = msgs.into_iter().collect::<Vec<_>>();
                let pks = vec![&public; msgs.len()];
                let signature = blst::min_pk::Signature::from_bytes(&signature.encode()).unwrap();
                match signature.aggregate_verify(true, &msgs, V::MESSAGE, &pks, true) {
                    BLST_ERROR::BLST_SUCCESS => Ok(()),
                    e => Err(e),
                }
            }
            _ => panic!("Unsupported Variant"),
        }
    }

    fn aggregate_verify_multiple_messages_correct<V: Variant>() {
        let (private, public) = keypair::<_, V>(&mut thread_rng());
        let namespace = Some(&b"test"[..]);
        let messages: Vec<(Option<&[u8]>, &[u8])> = vec![
            (namespace, b"Message 1"),
            (namespace, b"Message 2"),
            (namespace, b"Message 3"),
        ];
        let signatures: Vec<_> = messages
            .iter()
            .map(|(namespace, msg)| sign_message::<V>(&private, *namespace, msg))
            .collect();

        let aggregate_sig = aggregate::signatures::<V, _>(&signatures);

        aggregate::verify_multiple_messages::<V, _>(&public, &messages, &aggregate_sig, 1)
            .expect("Aggregated signature should be valid");

        aggregate::verify_multiple_messages::<V, _>(&public, &messages, &aggregate_sig, 4)
            .expect("Aggregated signature should be valid with parallelism");

        let payload_msgs: Vec<_> = messages
            .iter()
            .map(|(ns, msg)| union_unique(ns.unwrap(), msg))
            .collect();
        let payload_refs: Vec<&[u8]> = payload_msgs.iter().map(|p| p.as_ref()).collect();
        blst_aggregate_verify_multiple_messages::<V, _>(&public, payload_refs, &aggregate_sig)
            .expect("blst should also accept aggregated signature");
    }

    #[test]
    fn test_aggregate_verify_multiple_messages_correct() {
        aggregate_verify_multiple_messages_correct::<MinPk>();
        aggregate_verify_multiple_messages_correct::<MinSig>();
    }

    fn aggregate_verify_fail_on_malleability<V: Variant>() {
        let (private, public) = keypair::<_, V>(&mut thread_rng());
        let msg1: &[u8] = b"message 1";
        let msg2: &[u8] = b"message 2";

        let sig1 = sign_message::<V>(&private, None, msg1);
        let sig2 = sign_message::<V>(&private, None, msg2);

        verify_message::<V>(&public, None, msg1, &sig1).expect("sig1 should be valid");
        verify_message::<V>(&public, None, msg2, &sig2).expect("sig2 should be valid");

        let random_scalar = Scalar::random(&mut thread_rng());
        let delta = V::Signature::generator() * &random_scalar;
        let forged_sig1 = sig1 - &delta;
        let forged_sig2 = sig2 + &delta;

        assert!(
            verify_message::<V>(&public, None, msg1, &forged_sig1).is_err(),
            "forged sig1 should be invalid individually"
        );
        assert!(
            verify_message::<V>(&public, None, msg2, &forged_sig2).is_err(),
            "forged sig2 should be invalid individually"
        );

        let forged_agg = aggregate::signatures::<V, _>(&[forged_sig1, forged_sig2]);
        let valid_agg = aggregate::signatures::<V, _>(&[sig1, sig2]);
        assert_eq!(forged_agg, valid_agg, "aggregates should be equal");

        let hm1 = hash_message::<V>(V::MESSAGE, msg1);
        let hm2 = hash_message::<V>(V::MESSAGE, msg2);
        let hm_sum = hm1 + &hm2;
        V::verify(&public, &hm_sum, &forged_agg)
            .expect("vulnerable naive verification accepts forged aggregate");

        let forged_entries = vec![(None, msg1, forged_sig1), (None, msg2, forged_sig2)];
        let result =
            verify_multiple_messages::<_, V, _>(&mut thread_rng(), &public, &forged_entries, 1);
        assert!(
            result.is_err(),
            "secure function should reject forged signatures"
        );

        let valid_entries = vec![(None, msg1, sig1), (None, msg2, sig2)];
        verify_multiple_messages::<_, V, _>(&mut thread_rng(), &public, &valid_entries, 1)
            .expect("secure function should accept valid signatures");
    }

    #[test]
    fn test_aggregate_verify_fail_on_malleability() {
        aggregate_verify_fail_on_malleability::<MinPk>();
        aggregate_verify_fail_on_malleability::<MinSig>();
    }
}
