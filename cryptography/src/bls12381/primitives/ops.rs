//! Digital signatures over the BLS12-381 curve using G1 as the Public Key (48 bytes)
//! and G2 as the Signature (96 bytes).
//!
//! # Domain Separation Tag (DST)
//!
//! All signatures use the `POP` (Proof of Possession) scheme during signing. For Proof-of-Posession (POP) signatures,
//! the domain separation tag is `BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`. For signatures over other messages, the
//! domain separation tag is `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`. You can read more about DSTs [here](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05#section-4.2).

use super::{
    group::{self, equal, Element, Point, Share, DST, MESSAGE, PROOF_OF_POSSESSION},
    poly::{self, Eval},
    Error,
};
use commonware_utils::union_unique;
use rand::RngCore;
use rayon::{prelude::*, ThreadPoolBuilder};
use std::{borrow::Cow, collections::HashSet};

/// Returns a new keypair derived from the provided randomness.
pub fn keypair<R: RngCore>(rng: &mut R) -> (group::Private, group::Public) {
    let private = group::Private::rand(rng);
    let mut public = group::Public::one();
    public.mul(&private);
    (private, public)
}

/// Sign the provided payload with the private key.
fn sign(private: &group::Private, dst: DST, payload: &[u8]) -> group::Signature {
    let mut s = group::Signature::zero();
    s.map(dst, payload);
    s.mul(private);
    s
}

/// Verify the signature from the provided public key.
fn verify(
    public: &group::Public,
    dst: DST,
    payload: &[u8],
    signature: &group::Signature,
) -> Result<(), Error> {
    let mut hm = group::Signature::zero();
    hm.map(dst, payload);
    if !equal(public, signature, &hm) {
        return Err(Error::InvalidSignature);
    }
    Ok(())
}

/// Generates a proof of possession for the private key.
pub fn sign_proof_of_possession(private: &group::Private) -> group::Signature {
    // Get public key
    let mut public = group::Public::one();
    public.mul(private);

    // Sign the public key
    sign(private, PROOF_OF_POSSESSION, public.serialize().as_slice())
}

/// Verifies a proof of possession for the provided public key.
pub fn verify_proof_of_possession(
    public: &group::Public,
    signature: &group::Signature,
) -> Result<(), Error> {
    verify(
        public,
        PROOF_OF_POSSESSION,
        public.serialize().as_slice(),
        signature,
    )
}

/// Signs the provided message with the private key.
///
/// # Determinism
///
/// Signatures produced by this function are deterministic and are safe
/// to use in a consensus-critical context.
pub fn sign_message(
    private: &group::Private,
    namespace: Option<&[u8]>,
    message: &[u8],
) -> group::Signature {
    let payload = match namespace {
        Some(namespace) => Cow::Owned(union_unique(namespace, message)),
        None => Cow::Borrowed(message),
    };
    sign(private, MESSAGE, &payload)
}

/// Verifies the signature with the provided public key.
///
/// # Warning
///
/// This function assumes a group check was already performed on
/// `public` and `signature`.
pub fn verify_message(
    public: &group::Public,
    namespace: Option<&[u8]>,
    message: &[u8],
    signature: &group::Signature,
) -> Result<(), Error> {
    let payload = match namespace {
        Some(namespace) => Cow::Owned(union_unique(namespace, message)),
        None => Cow::Borrowed(message),
    };
    verify(public, MESSAGE, &payload, signature)
}

/// Signs the provided message with the key share.
pub fn partial_sign_message(
    private: &Share,
    namespace: Option<&[u8]>,
    message: &[u8],
) -> Eval<group::Signature> {
    let sig = sign_message(&private.private, namespace, message);
    Eval {
        value: sig,
        index: private.index,
    }
}

/// Verifies the partial signature against the public polynomial.
///
/// # Warning
///
/// This function assumes a group check was already performed on `signature`.
pub fn partial_verify_message(
    public: &poly::Public,
    namespace: Option<&[u8]>,
    message: &[u8],
    partial: &Eval<group::Signature>,
) -> Result<(), Error> {
    let public = public.evaluate(partial.index);
    verify_message(&public.value, namespace, message, &partial.value)
}

/// Recovers a signature from at least `threshold` partial signatures.
///
/// # Determinism
///
/// Signatures recovered by this function are deterministic and are safe
/// to use in a consensus-critical context.
pub fn signature_recover(
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
///
/// # Warning
///
/// This function assumes a group check was already performed on each `signature`.
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
///
/// # Warning
///
/// This function assumes a group check was already performed on `public` and `signature`.
pub fn verify_aggregate(
    public: &group::Public,
    namespace: Option<&[u8]>,
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

    // Perform hashing and summation of messages in parallel
    //
    // Just like public key aggregation takes advantage of the bilinearity property of
    // pairings, so too can we reduce the number of pairings required to verify multiple
    // messages signed by a single public key (as long as all messages are unique).
    let hm_sum = pool.install(|| {
        messages
            .par_iter()
            .map(|msg| {
                let mut hm = group::Signature::zero();
                match namespace {
                    Some(namespace) => hm.map(MESSAGE, &union_unique(namespace, msg)),
                    None => hm.map(MESSAGE, msg),
                };
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
        let sig = sign(&private, Some(b"good"), msg);
        assert!(matches!(
            verify(&public, Some(b"bad"), msg, &sig).unwrap_err(),
            Error::InvalidSignature
        ));
    }

    #[test]
    fn test_single_compatibility() {
        let (private, public) = keypair(&mut thread_rng());
        let msg = &[1, 9, 6, 9];
        let namespace = b"test";
        let sig = sign(&private, Some(namespace), msg);
        verify(&public, Some(namespace), msg, &sig).expect("signature should be valid");
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
            .map(|s| partial_sign(s, Some(namespace), msg))
            .collect();
        for p in &partials {
            partial_verify(&public, Some(namespace), msg, p).expect("signature should be valid");
        }
        let threshold_sig = partial_aggregate(t, partials).unwrap();
        let threshold_pub = poly::public(&public);
        verify(&threshold_pub, Some(namespace), msg, &threshold_sig)
            .expect("signature should be valid");
        let payload = union_unique(namespace, msg);
        blst_verify(&threshold_pub, &payload, &threshold_sig).expect("signature should be valid");
    }

    #[test]
    fn test_aggregate_signatures() {
        // Generate signatures
        let (private, public) = keypair(&mut thread_rng());
        let messages: Vec<&[u8]> = vec![b"Message 1", b"Message 2", b"Message 3"];
        let namespace = Some(&b"test"[..]);
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
        let namespace = Some(&b"test"[..]);
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
        let namespace = Some(&b"test"[..]);
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
        let namespace = Some(&b"test"[..]);
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
