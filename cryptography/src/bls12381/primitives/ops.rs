//! Digital signatures over the BLS12-381 curve.

use super::{
    group::{self, equal, Element, Point, Share},
    poly::{self, Eval},
    Error,
};
use commonware_utils::union_unique;
use rand::RngCore;
use rayon::{prelude::*, ThreadPoolBuilder};
use std::collections::HashSet;

/// Returns a new keypair derived from the provided randomness.
pub fn keypair<R: RngCore>(rng: &mut R) -> (group::Private, group::Public) {
    let private = group::Private::rand(rng);
    let mut public = group::Public::one();
    public.mul(&private);
    (private, public)
}

/// Signs the provided message with the private key.
///
/// The message is hashed according to RFC 9380.
///
/// # Determinism
///
/// Signatures produced by this function are deterministic and are safe
/// to use in a consensus-critical context.
pub fn sign(private: &group::Private, namespace: &[u8], message: &[u8]) -> group::Signature {
    let payload = union_unique(namespace, message);
    let mut s = group::Signature::zero();
    s.map(&payload);
    s.mul(private);
    s
}

/// Verifies the signature with the provided public key.
pub fn verify(
    public: &group::Public,
    namespace: &[u8],
    message: &[u8],
    signature: &group::Signature,
) -> Result<(), Error> {
    let payload = union_unique(namespace, message);
    let mut hm = group::Signature::zero();
    hm.map(&payload);
    if !equal(public, signature, &hm) {
        return Err(Error::InvalidSignature);
    }
    Ok(())
}

/// Signs the provided message with the key share.
pub fn partial_sign(private: &Share, namespace: &[u8], message: &[u8]) -> Eval<group::Signature> {
    let sig = sign(&private.private, namespace, message);
    Eval {
        value: sig,
        index: private.index,
    }
}

/// Verifies the partial signature against the public polynomial.
pub fn partial_verify(
    public: &poly::Public,
    namespace: &[u8],
    message: &[u8],
    partial: &Eval<group::Signature>,
) -> Result<(), Error> {
    let public = public.evaluate(partial.index);
    verify(&public.value, namespace, message, &partial.value)
}

/// Aggregates the partial signatures into a final signature.
///
/// # Determinism
///
/// Signatures recovered by this function are deterministic and are safe
/// to use in a consensus-critical context.
pub fn partial_aggregate(
    threshold: u32,
    partials: Vec<Eval<group::Signature>>,
) -> Result<group::Signature, Error> {
    let sigs = partials.len() as u32;
    if threshold > sigs {
        return Err(Error::NotEnoughPartialSignatures(threshold, sigs));
    }
    poly::Signature::recover(threshold, partials)
}

/// Aggregates multiple signatures over unique messages from the same public key.
///
/// If the same signatures is provided multiple times, the function will not error
/// but any attempt to verify the aggregated signature will fail.
pub fn aggregate(signatures: &[group::Signature]) -> group::Signature {
    let mut s = group::Signature::zero();
    for sig in signatures {
        s.add(sig);
    }
    s
}

/// Verifies the aggregate signature over multiple unique messages from the same public key.
///
/// If the same message is provided multiple times, the function will error.
pub fn verify_aggregate(
    public: &group::Public,
    namespace: &[u8],
    messages: &[&[u8]],
    signature: &group::Signature,
    concurrency: usize,
) -> Result<(), Error> {
    // Check for duplicate messages before parallel processing
    {
        let mut seen = HashSet::new();
        for msg in messages {
            if !seen.insert(*msg) {
                return Err(Error::DuplicateMessage);
            }
        }
    }

    // Build a thread pool with the specified concurrency
    let pool = ThreadPoolBuilder::new()
        .num_threads(concurrency)
        .build()
        .expect("Unable to build thread pool");

    // Perform hashing an summation of messages in parallel
    let hm_sum = pool.install(|| {
        messages
            .par_iter()
            .map(|msg| {
                let payload = union_unique(namespace, msg);
                let mut hm = group::Signature::zero();
                hm.map(&payload);
                hm
            })
            .reduce(group::Signature::zero, |mut sum, hm| {
                sum.add(&hm);
                sum
            })
    });

    // Verify the signature
    if !equal(public, signature, &hm_sum) {
        return Err(Error::InvalidSignature);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::{dkg::ops::generate_shares, primitives::group::DST_G2};
    use blst::BLST_ERROR;
    use rand::prelude::*;

    /// Verify that a given signature is valid according to `blst`.
    fn blst_verify(
        public: &group::Public,
        msg: &[u8],
        signature: &group::Signature,
    ) -> Result<(), BLST_ERROR> {
        let public = blst::min_pk::PublicKey::from_bytes(public.serialize().as_slice()).unwrap();
        let signature =
            blst::min_pk::Signature::from_bytes(signature.serialize().as_slice()).unwrap();
        match signature.verify(true, msg, DST_G2, &[], &public, true) {
            BLST_ERROR::BLST_SUCCESS => Ok(()),
            e => Err(e),
        }
    }

    #[test]
    fn test_bad_namespace() {
        let (private, public) = keypair(&mut thread_rng());
        let msg = &[1, 9, 6, 9];
        let sig = sign(&private, b"good", msg);
        assert!(matches!(
            verify(&public, b"bad", msg, &sig).unwrap_err(),
            Error::InvalidSignature
        ));
    }

    #[test]
    fn test_single_compatibility() {
        let (private, public) = keypair(&mut thread_rng());
        let msg = &[1, 9, 6, 9];
        let namespace = b"test";
        let sig = sign(&private, namespace, msg);
        verify(&public, namespace, msg, &sig).expect("signature should be valid");
        let payload = union_unique(namespace, msg);
        blst_verify(&public, &payload, &sig).expect("signature should be valid");
    }

    #[test]
    fn test_threshold_compatibility() {
        let (n, t) = (5, 4);
        let (public, shares) = generate_shares(None, n, t);
        let msg = &[1, 9, 6, 9];
        let namespace = b"test";
        let partials: Vec<_> = shares
            .iter()
            .map(|s| partial_sign(s, namespace, msg))
            .collect();
        for p in &partials {
            partial_verify(&public, namespace, msg, p).expect("signature should be valid");
        }
        let threshold_sig = partial_aggregate(t, partials).unwrap();
        let threshold_pub = poly::public(&public);
        verify(&threshold_pub, namespace, msg, &threshold_sig).expect("signature should be valid");
        let payload = union_unique(namespace, msg);
        blst_verify(&threshold_pub, &payload, &threshold_sig).expect("signature should be valid");
    }

    #[test]
    fn test_aggregate_signatures() {
        // Generate signatures
        let (private, public) = keypair(&mut thread_rng());
        let messages: Vec<&[u8]> = vec![b"Message 1", b"Message 2", b"Message 3"];
        let namespace = b"test";
        let signatures: Vec<_> = messages
            .iter()
            .map(|msg| sign(&private, namespace, msg))
            .collect();

        // Aggregate the signatures
        let aggregate_sig = aggregate(&signatures);

        // Verify the aggregated signature
        verify_aggregate(&public, namespace, &messages, &aggregate_sig, 4)
            .expect("Aggregated signature should be valid");
    }

    #[test]
    fn test_aggregate_signatures_wrong_messages() {
        // Generate signatures
        let (private, public) = keypair(&mut thread_rng());
        let messages: Vec<&[u8]> = vec![b"Message 1", b"Message 2", b"Message 3"];
        let namespace = b"test";
        let signatures: Vec<_> = messages
            .iter()
            .map(|msg| sign(&private, namespace, msg))
            .collect();

        // Aggregate the signatures
        let aggregate_sig = aggregate(&signatures);

        // Verify the aggregated signature
        let wrong_messages: Vec<&[u8]> = vec![b"Message 1", b"Message 2", b"Message 4"];
        let result = verify_aggregate(&public, namespace, &wrong_messages, &aggregate_sig, 4);
        assert!(matches!(result, Err(Error::InvalidSignature)));
    }

    #[test]
    fn test_aggregate_signatures_duplicate_messages() {
        // Generate signatures
        let (private, public) = keypair(&mut thread_rng());
        let messages: Vec<&[u8]> = vec![b"Message 1", b"Message 2", b"Message 2"];
        let namespace = b"test";
        let signatures: Vec<_> = messages
            .iter()
            .map(|msg| sign(&private, namespace, msg))
            .collect();

        // Aggregate the signatures
        let aggregate_sig = aggregate(&signatures);

        // Verify the aggregated signature
        let result = verify_aggregate(&public, namespace, &messages, &aggregate_sig, 4);
        assert!(matches!(result, Err(Error::DuplicateMessage)));
    }

    #[test]
    fn test_aggregate_signatures_wrong_message_count() {
        // Generate signatures
        let (private, public) = keypair(&mut thread_rng());
        let messages: Vec<&[u8]> = vec![b"Message 1", b"Message 2", b"Message 3"];
        let namespace = b"test";
        let signatures: Vec<_> = messages
            .iter()
            .map(|msg| sign(&private, namespace, msg))
            .collect();

        // Aggregate the signatures
        let aggregate_sig = aggregate(&signatures);

        // Verify the aggregated signature
        let wrong_messages: Vec<&[u8]> = vec![b"Message 1", b"Message 2"];
        let result = verify_aggregate(&public, namespace, &wrong_messages, &aggregate_sig, 4);
        assert!(matches!(result, Err(Error::InvalidSignature)));
    }
}
