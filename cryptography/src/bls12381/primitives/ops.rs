//! Digital signatures over the BLS12-381 curve using G1 as the Public Key and G2 as the Signature.

use super::{
    group::{self, equal, Element, Point, Share, DST_MESSAGE, DST_PROOF_OF_POSSESSION},
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

/// Sign the provided payload with the canonical domain separation tag.
fn sign_dst(private: &group::Private, dst: &[u8], payload: &[u8]) -> group::Signature {
    let mut s = group::Signature::zero();
    s.map(dst, payload);
    s.mul(private);
    s
}

/// Verify the provided payload with the canonical domain separation tag.
fn verify_dst(
    public: &group::Public,
    dst: &[u8],
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
    sign_dst(
        private,
        DST_PROOF_OF_POSSESSION,
        public.serialize().as_slice(),
    )
}

/// Verifies a proof of possession for the provided public key.
pub fn verify_proof_of_possession(
    public: &group::Public,
    signature: &group::Signature,
) -> Result<(), Error> {
    verify_dst(
        public,
        DST_PROOF_OF_POSSESSION,
        public.serialize().as_slice(),
        signature,
    )
}

/// Signs the provided message with the private key.
///
/// The message is hashed according to RFC 9380.
///
/// # Determinism
///
/// Signatures produced by this function are deterministic and are safe
/// to use in a consensus-critical context.
pub fn sign_message(
    private: &group::Private,
    namespace: &[u8],
    message: &[u8],
) -> group::Signature {
    let payload = union_unique(namespace, message);
    sign_dst(private, DST_MESSAGE, &payload)
}

/// Verifies the signature with the provided public key.
///
/// # Warning
///
/// This function assumes a group check was already performed on
/// `public` and `signature`.
pub fn verify_message(
    public: &group::Public,
    namespace: &[u8],
    message: &[u8],
    signature: &group::Signature,
) -> Result<(), Error> {
    let payload = union_unique(namespace, message);
    verify_dst(public, DST_MESSAGE, &payload, signature)
}

/// Signs the provided message with the key share.
pub fn partial_sign_message(
    private: &Share,
    namespace: &[u8],
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
    namespace: &[u8],
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
/// If the same signature is provided multiple times, the function will not error
/// but any attempt to verify the aggregated signature will fail using `verify_aggregate_signature`.
///
/// # Warning
///
/// This function assumes a group check was already performed on each `signature`.
pub fn aggregate_signatures(signatures: &[group::Signature]) -> group::Signature {
    let mut s = group::Signature::zero();
    for sig in signatures {
        s.add(sig);
    }
    s
}

/// Verifies the aggregated signature over multiple unique messages from the same public key.
///
/// If the same message is provided multiple times, the function will error.
///
/// # Warning
///
/// This function assumes a group check was already performed on `public` and `signature`.
pub fn verify_aggregated_signature(
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
                hm.map(DST_MESSAGE, &payload);
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
    use crate::bls12381::dkg::ops::generate_shares;
    use blst::BLST_ERROR;
    use rand::prelude::*;

    #[test]
    fn test_encoding() {
        // Encode private/public key
        let (private, public) = keypair(&mut thread_rng());
        let (private_bytes, public_bytes) = (private.serialize(), public.serialize());

        // Decode private/public key
        let (private_decoded, public_decoded) = (
            group::Private::deserialize(&private_bytes).unwrap(),
            group::Public::deserialize(&public_bytes).unwrap(),
        );

        // Ensure equal
        assert_eq!(private, private_decoded);
        assert_eq!(public, public_decoded);

        // Ensure blst compatibility
        blst::min_pk::SecretKey::from_bytes(private_bytes.as_slice()).unwrap();
        let blst_public_decoded =
            blst::min_pk::PublicKey::from_bytes(public_bytes.as_slice()).unwrap();
        blst_public_decoded.validate().unwrap();
        let blst_public_encoded = blst_public_decoded.compress().to_vec();
        assert_eq!(public_bytes, blst_public_encoded.as_slice());
    }

    #[test]
    fn test_bad_namespace() {
        let (private, public) = keypair(&mut thread_rng());
        let msg = &[1, 9, 6, 9];
        let sig = sign_message(&private, b"good", msg);
        assert!(matches!(
            verify_message(&public, b"bad", msg, &sig).unwrap_err(),
            Error::InvalidSignature
        ));
    }

    fn blst_verify_proof_of_possession(
        public: &group::Public,
        signature: &group::Signature,
    ) -> Result<(), BLST_ERROR> {
        let msg = public.serialize();
        let public = blst::min_pk::PublicKey::from_bytes(public.serialize().as_slice()).unwrap();
        let signature =
            blst::min_pk::Signature::from_bytes(signature.serialize().as_slice()).unwrap();
        match signature.verify(true, &msg, DST_PROOF_OF_POSSESSION, &[], &public, true) {
            BLST_ERROR::BLST_SUCCESS => Ok(()),
            e => Err(e),
        }
    }

    #[test]
    fn test_proof_of_posession() {
        // Generate PoP
        let (private, public) = keypair(&mut thread_rng());
        let pop = sign_proof_of_possession(&private);

        // Verify PoP
        verify_proof_of_possession(&public, &pop).expect("PoP should be valid");

        // Verify PoP using blst
        blst_verify_proof_of_possession(&public, &pop).expect("PoP should be valid");
    }

    /// Verify that a given signature is valid according to `blst`.
    fn blst_verify_message(
        public: &group::Public,
        msg: &[u8],
        signature: &group::Signature,
    ) -> Result<(), BLST_ERROR> {
        let public = blst::min_pk::PublicKey::from_bytes(public.serialize().as_slice()).unwrap();
        let signature =
            blst::min_pk::Signature::from_bytes(signature.serialize().as_slice()).unwrap();
        match signature.verify(true, msg, DST_MESSAGE, &[], &public, true) {
            BLST_ERROR::BLST_SUCCESS => Ok(()),
            e => Err(e),
        }
    }

    #[test]
    fn test_single_message() {
        // Generate signature
        let (private, public) = keypair(&mut thread_rng());
        let msg = &[1, 9, 6, 9];
        let namespace = b"test";
        let sig = sign_message(&private, namespace, msg);

        // Verify the signature
        verify_message(&public, namespace, msg, &sig).expect("signature should be valid");

        // Verify the signature using blst
        let payload = union_unique(namespace, msg);
        blst_verify_message(&public, &payload, &sig).expect("signature should be valid");
    }

    #[test]
    fn test_threshold_message() {
        // Generate partial signatures
        let (n, t) = (5, 4);
        let (public, shares) = generate_shares(None, n, t);
        let msg = &[1, 9, 6, 9];
        let namespace = b"test";
        let partials: Vec<_> = shares
            .iter()
            .map(|s| partial_sign_message(s, namespace, msg))
            .collect();

        // Verify partial signatures
        for p in &partials {
            partial_verify_message(&public, namespace, msg, p).expect("signature should be valid");
        }

        // Aggregate partial signatures
        let threshold_sig = signature_recover(t, partials).unwrap();
        let threshold_pub = poly::public(&public);

        // Verify the aggregated signature
        verify_message(&threshold_pub, namespace, msg, &threshold_sig)
            .expect("signature should be valid");

        // Verify the aggregated signature using blst
        let payload = union_unique(namespace, msg);
        blst_verify_message(&threshold_pub, &payload, &threshold_sig)
            .expect("signature should be valid");
    }

    fn blst_verify_aggregate(
        public: &group::Public,
        msgs: &[&[u8]],
        signature: &group::Signature,
    ) -> Result<(), BLST_ERROR> {
        let public = blst::min_pk::PublicKey::from_bytes(public.serialize().as_slice()).unwrap();
        let pks = vec![&public; msgs.len()];
        let signature =
            blst::min_pk::Signature::from_bytes(signature.serialize().as_slice()).unwrap();
        match signature.aggregate_verify(true, msgs, DST_MESSAGE, &pks, true) {
            BLST_ERROR::BLST_SUCCESS => Ok(()),
            e => Err(e),
        }
    }

    #[test]
    fn test_verify_aggregated_signature() {
        // Generate signatures
        let (private, public) = keypair(&mut thread_rng());
        let messages: Vec<&[u8]> = vec![b"Message 1", b"Message 2", b"Message 3"];
        let namespace = b"test";
        let signatures: Vec<_> = messages
            .iter()
            .map(|msg| sign_message(&private, namespace, msg))
            .collect();

        // Aggregate the signatures
        let aggregate_sig = aggregate_signatures(&signatures);

        // Verify the aggregated signature
        verify_aggregated_signature(&public, namespace, &messages, &aggregate_sig, 4)
            .expect("Aggregated signature should be valid");

        // Verify the aggregated signature using blst
        let messages = messages
            .iter()
            .map(|msg| union_unique(namespace, msg))
            .collect::<Vec<_>>();
        let messages = messages
            .iter()
            .map(|msg| msg.as_slice())
            .collect::<Vec<_>>();
        blst_verify_aggregate(&public, &messages, &aggregate_sig)
            .expect("Aggregated signature should be valid");
    }

    #[test]
    fn test_verify_aggregated_signature_wrong_messages() {
        // Generate signatures
        let (private, public) = keypair(&mut thread_rng());
        let messages: Vec<&[u8]> = vec![b"Message 1", b"Message 2", b"Message 3"];
        let namespace = b"test";
        let signatures: Vec<_> = messages
            .iter()
            .map(|msg| sign_message(&private, namespace, msg))
            .collect();

        // Aggregate the signatures
        let aggregate_sig = aggregate_signatures(&signatures);

        // Verify the aggregated signature
        let wrong_messages: Vec<&[u8]> = vec![b"Message 1", b"Message 2", b"Message 4"];
        let result =
            verify_aggregated_signature(&public, namespace, &wrong_messages, &aggregate_sig, 4);
        assert!(matches!(result, Err(Error::InvalidSignature)));
    }

    #[test]
    fn test_verify_aggregated_signature_duplicate_messages() {
        // Generate signatures
        let (private, public) = keypair(&mut thread_rng());
        let messages: Vec<&[u8]> = vec![b"Message 1", b"Message 2", b"Message 2"];
        let namespace = b"test";
        let signatures: Vec<_> = messages
            .iter()
            .map(|msg| sign_message(&private, namespace, msg))
            .collect();

        // Aggregate the signatures
        let aggregate_sig = aggregate_signatures(&signatures);

        // Verify the aggregated signature
        let result = verify_aggregated_signature(&public, namespace, &messages, &aggregate_sig, 4);
        assert!(matches!(result, Err(Error::DuplicateMessage)));
    }

    #[test]
    fn test_verify_aggregated_signature_wrong_message_count() {
        // Generate signatures
        let (private, public) = keypair(&mut thread_rng());
        let messages: Vec<&[u8]> = vec![b"Message 1", b"Message 2", b"Message 3"];
        let namespace = b"test";
        let signatures: Vec<_> = messages
            .iter()
            .map(|msg| sign_message(&private, namespace, msg))
            .collect();

        // Aggregate the signatures
        let aggregate_sig = aggregate_signatures(&signatures);

        // Verify the aggregated signature
        let wrong_messages: Vec<&[u8]> = vec![b"Message 1", b"Message 2"];
        let result =
            verify_aggregated_signature(&public, namespace, &wrong_messages, &aggregate_sig, 4);
        assert!(matches!(result, Err(Error::InvalidSignature)));
    }
}
