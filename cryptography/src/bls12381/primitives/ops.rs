//! Digital signatures over the BLS12-381 curve using G1 as the Public Key (48 bytes)
//! and G2 as the Signature (96 bytes).
//!
//! # Domain Separation Tag (DST)
//!
//! All signatures use the `POP` (Proof of Possession) scheme during signing. For Proof-of-Possession (POP) signatures,
//! the domain separation tag is `BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`. For signatures over other messages, the
//! domain separation tag is `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`. You can read more about DSTs [here](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05#section-4.2).

use super::{
    group::{self, Element, Point, Share},
    poly::{self, Eval, PartialSignature, Weight},
    variant::Variant,
    Error,
};
use crate::bls12381::primitives::poly::{compute_weights, prepare_evaluations};
use commonware_codec::Encode;
use commonware_utils::union_unique;
use rand::RngCore;
use rayon::{prelude::*, ThreadPoolBuilder};
use std::{borrow::Cow, collections::BTreeMap};

/// Returns a new keypair derived from the provided randomness.
pub fn keypair<R: RngCore, V: Variant>(rng: &mut R) -> (group::Private, V::Public) {
    let private = group::Private::rand(rng);
    let mut public = V::Public::one();
    public.mul(&private);
    (private, public)
}

/// Generates a proof of possession for the private key.
pub fn sign_proof_of_possession<V: Variant>(private: &group::Private) -> V::Signature {
    // Get public key
    let mut public = V::Public::one();
    public.mul(private);

    // Sign the public key
    V::sign(private, V::PROOF_OF_POSSESSION, &public.encode())
}

/// Verifies a proof of possession for the provided public key.
pub fn verify_proof_of_possession<V: Variant>(
    public: &V::Public,
    signature: &V::Signature,
) -> Result<(), Error> {
    V::verify(public, V::PROOF_OF_POSSESSION, &public.encode(), signature)
}

/// Signs the provided message with the private key.
///
/// # Determinism
///
/// Signatures produced by this function are deterministic and are safe
/// to use in a consensus-critical context.
pub fn sign_message<V: Variant>(
    private: &group::Private,
    namespace: Option<&[u8]>,
    message: &[u8],
) -> V::Signature {
    let payload = match namespace {
        Some(namespace) => Cow::Owned(union_unique(namespace, message)),
        None => Cow::Borrowed(message),
    };
    V::sign(private, V::MESSAGE, &payload)
}

/// Verifies the signature with the provided public key.
///
/// # Warning
///
/// This function assumes a group check was already performed on
/// `public` and `signature`.
pub fn verify_message<V: Variant>(
    public: &V::Public,
    namespace: Option<&[u8]>,
    message: &[u8],
    signature: &V::Signature,
) -> Result<(), Error> {
    let payload = match namespace {
        Some(namespace) => Cow::Owned(union_unique(namespace, message)),
        None => Cow::Borrowed(message),
    };
    V::verify(public, V::MESSAGE, &payload, signature)
}

/// Generates a proof of possession for the private key share.
pub fn partial_sign_proof_of_possession<V: Variant>(
    public: &poly::Public<V>,
    private: &Share,
) -> PartialSignature<V> {
    // Get public key
    let threshold_public = poly::public::<V>(public);

    // Sign the public key
    let sig = V::sign(
        &private.private,
        V::PROOF_OF_POSSESSION,
        &threshold_public.encode(),
    );
    Eval {
        value: sig,
        index: private.index,
    }
}

/// Verifies the proof of possession for the provided public polynomial.
///
/// # Warning
///
/// This function assumes a group check was already performed on `signature`.
pub fn partial_verify_proof_of_possession<V: Variant>(
    public: &poly::Public<V>,
    partial: &PartialSignature<V>,
) -> Result<(), Error> {
    let threshold_public = poly::public::<V>(public);
    let public = public.evaluate(partial.index);
    V::verify(
        &public.value,
        V::PROOF_OF_POSSESSION,
        &threshold_public.encode(),
        &partial.value,
    )
}

/// Signs the provided message with the key share.
pub fn partial_sign_message<V: Variant>(
    private: &Share,
    namespace: Option<&[u8]>,
    message: &[u8],
) -> PartialSignature<V> {
    let sig = sign_message::<V>(&private.private, namespace, message);
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
pub fn partial_verify_message<V: Variant>(
    public: &poly::Public<V>,
    namespace: Option<&[u8]>,
    message: &[u8],
    partial: &PartialSignature<V>,
) -> Result<(), Error> {
    let public = public.evaluate(partial.index);
    verify_message::<V>(&public.value, namespace, message, &partial.value)
}

/// Aggregates multiple partial signatures into a single signature.
///
/// # Warning
///
/// This function assumes a group check was already performed on each `signature` and
/// that each `signature` is unique. If any of these assumptions are violated, an attacker can
/// exploit this function to verify an incorrect aggregate signature.
pub fn partial_aggregate_signatures<'a, V, I>(partials: I) -> Option<(u32, V::Signature)>
where
    V: Variant,
    I: IntoIterator<Item = &'a PartialSignature<V>>,
    V::Signature: 'a,
{
    let mut iter = partials.into_iter().peekable();
    let index = iter.peek()?.index;
    let mut s = V::Signature::zero();
    for partial in iter {
        if partial.index != index {
            return None;
        }
        s.add(&partial.value);
    }
    Some((index, s))
}

/// Verifies the signatures from multiple partial signatures over multiple unique messages from a single
/// signer.
///
/// # Warning
///
/// This function assumes a group check was already performed on each `signature`.
pub fn partial_verify_multiple_messages<'a, V, I, J>(
    public: &poly::Public<V>,
    partial_signer: u32,
    messages: I,
    signatures: J,
) -> Result<(), Error>
where
    V: Variant,
    I: IntoIterator<Item = &'a (Option<&'a [u8]>, &'a [u8])>,
    J: IntoIterator<Item = &'a PartialSignature<V>>,
    V::Signature: 'a,
{
    // Aggregate the partial signatures
    let (index, signature) =
        partial_aggregate_signatures::<V, _>(signatures).ok_or(Error::InvalidSignature)?;
    if partial_signer != index {
        return Err(Error::InvalidSignature);
    }
    let public = public.evaluate(index).value;

    // Sum the hashed messages
    let mut hm_sum = V::Signature::zero();
    for (namespace, msg) in messages {
        let mut hm = V::Signature::zero();
        match namespace {
            Some(namespace) => hm.map(V::MESSAGE, &union_unique(namespace, msg)),
            None => hm.map(V::MESSAGE, msg),
        };
        hm_sum.add(&hm);
    }

    // Verify the signature
    V::verify_prehashed(&public, &hm_sum, &signature)
}

/// Interpolate the value of some [Point] with precomputed Barycentric Weights
/// and multi-scalar multiplication (MSM).
pub fn msm_interpolate<'a, P, I>(weights: &BTreeMap<u32, Weight>, evals: I) -> Result<P, Error>
where
    P: Point + 'a,
    I: IntoIterator<Item = &'a Eval<P>>,
{
    // Populate points and scalars
    let mut points = Vec::with_capacity(weights.len());
    let mut scalars = Vec::with_capacity(weights.len());
    for e in evals {
        points.push(e.value.clone());
        scalars.push(
            weights
                .get(&e.index)
                .ok_or(Error::InvalidIndex)?
                .as_scalar()
                .clone(),
        );
    }

    // Perform multi-scalar multiplication
    Ok(P::msm(&points, &scalars))
}

/// Recovers a signature from `threshold` partial signatures.
///
/// # Determinism
///
/// Signatures recovered by this function are deterministic and are safe
/// to use in a consensus-critical context.
///
/// # Warning
///
/// This function assumes that each partial signature is unique and that
/// that there exists exactly one partial signature for each index in
/// the `weights` map.
pub fn threshold_signature_recover_with_weights<'a, V, I>(
    weights: &BTreeMap<u32, Weight>,
    partials: I,
) -> Result<V::Signature, Error>
where
    V: Variant,
    I: IntoIterator<Item = &'a PartialSignature<V>>,
    V::Signature: 'a,
{
    msm_interpolate(weights, partials)
}

/// Recovers a signature from at least `threshold` partial signatures.
///
/// # Determinism
///
/// Signatures recovered by this function are deterministic and are safe
/// to use in a consensus-critical context.
///
/// # Warning
///
/// This function assumes that each partial signature is unique.
pub fn threshold_signature_recover<'a, V, I>(
    threshold: u32,
    partials: I,
) -> Result<V::Signature, Error>
where
    V: Variant,
    I: IntoIterator<Item = &'a PartialSignature<V>>,
    V::Signature: 'a,
{
    // Prepare evaluations
    let evals = prepare_evaluations(threshold, partials)?;

    // Compute weights
    let indices = evals.iter().map(|e| e.index).collect::<Vec<_>>();
    let weights = compute_weights(indices)?;

    // Perform interpolation with the precomputed weights.
    //
    // We call this function instead of `poly::recover_with_weights` because
    // it will use multi-scalar multiplication (MSM) to recover the signature.
    threshold_signature_recover_with_weights::<V, _>(&weights, evals)
}

/// Recovers multiple signatures from multiple sets of at least `threshold`
/// partial signatures.
///
/// # Determinism
///
/// Signatures recovered by this function are deterministic and are safe
/// to use in a consensus-critical context.
///
/// # Warning
///
/// This function assumes that each partial signature is unique and that
/// each set of partial signatures has the same indices.
pub fn threshold_signature_recover_multiple<'a, V, I>(
    threshold: u32,
    mut many_evals: Vec<I>,
) -> Result<Vec<V::Signature>, Error>
where
    V: Variant,
    I: IntoIterator<Item = &'a PartialSignature<V>>,
    V::Signature: 'a,
{
    // Process first set of evaluations
    let evals = many_evals.swap_remove(0).into_iter().collect::<Vec<_>>();
    let evals = prepare_evaluations(threshold, evals)?;
    let mut prepared_evals = vec![evals];

    // Prepare other evaluations and ensure they have the same indices
    for evals in many_evals {
        let evals = evals.into_iter().collect::<Vec<_>>();
        let evals = prepare_evaluations(threshold, evals)?;
        for (i, e) in prepared_evals[0].iter().enumerate() {
            if e.index != evals[i].index {
                return Err(Error::InvalidIndex);
            }
        }
        prepared_evals.push(evals);
    }

    // Compute weights
    let indices = prepared_evals[0]
        .iter()
        .map(|e| e.index)
        .collect::<Vec<_>>();
    let weights = compute_weights(indices)?;

    // Recover signatures
    let mut signatures = Vec::with_capacity(prepared_evals.len());
    for evals in prepared_evals {
        let signature = threshold_signature_recover_with_weights::<V, _>(&weights, evals)?;
        signatures.push(signature);
    }
    Ok(signatures)
}

/// Recovers a pair of signatures from two sets of at least `threshold` partial signatures.
///
/// This is just a wrapper around `threshold_signature_recover_multiple`.
pub fn threshold_signature_recover_pair<'a, V, I>(
    threshold: u32,
    first: I,
    second: I,
) -> Result<(V::Signature, V::Signature), Error>
where
    V: Variant,
    I: IntoIterator<Item = &'a PartialSignature<V>>,
    V::Signature: 'a,
{
    let mut sigs = threshold_signature_recover_multiple::<V, _>(threshold, vec![first, second])?;
    let second_sig = sigs.pop().unwrap();
    let first_sig = sigs.pop().unwrap();
    Ok((first_sig, second_sig))
}

/// Aggregates multiple public keys.
///
/// # Warning
///
/// This function assumes a group check was already performed on all `public_keys`,
/// that each `public_key` is unique, and that the caller has a Proof-of-Possession (PoP)
/// for each `public_key`. If any of these assumptions are violated, an attacker can
/// exploit this function to verify an incorrect aggregate signature.
pub fn aggregate_public_keys<'a, V, I>(public_keys: I) -> V::Public
where
    V: Variant,
    I: IntoIterator<Item = &'a V::Public>,
    V::Public: 'a,
{
    let mut p = V::Public::zero();
    for pk in public_keys {
        p.add(pk);
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
pub fn aggregate_signatures<'a, V, I>(signatures: I) -> V::Signature
where
    V: Variant,
    I: IntoIterator<Item = &'a V::Signature>,
    V::Signature: 'a,
{
    let mut s = V::Signature::zero();
    for sig in signatures {
        s.add(sig);
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
pub fn aggregate_verify_multiple_public_keys<'a, V, I>(
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
    let agg_public = aggregate_public_keys::<V, _>(public);

    // Verify the signature
    verify_message::<V>(&agg_public, namespace, message, signature)
}

/// Verifies the aggregate signature over multiple unique messages from a single public key.
///
/// # Warning
///
/// This function assumes a group check was already performed on `public` and `signature`. It is not
/// safe to provide an aggregate public key or to provide duplicate messages.
///
/// ## Why not aggregate public keys?
///
/// We rely on bilinearity to reduce pairing operations in this function, like in `aggregate_verify_multiple_public_keys`,
/// and sum hashed messages together before performing a single pairing operation (instead of summing `len(messages)` pairings of
/// hashed message and public key). If the public key itself is an aggregate of multiple public keys, an attacker can exploit
/// this optimization to cause this function to return that an aggregate signature is valid when it really isn't.
pub fn aggregate_verify_multiple_messages<'a, V, I>(
    public: &V::Public,
    messages: I,
    signature: &V::Signature,
    concurrency: usize,
) -> Result<(), Error>
where
    V: Variant,
    I: IntoIterator<Item = &'a (Option<&'a [u8]>, &'a [u8])>
        + IntoParallelIterator<Item = &'a (Option<&'a [u8]>, &'a [u8])>
        + Send
        + Sync,
{
    let hm_sum = if concurrency == 1 {
        // Avoid pool overhead when concurrency is 1
        let mut hm_sum = V::Signature::zero();
        for (namespace, msg) in messages {
            let mut hm = V::Signature::zero();
            match namespace {
                Some(namespace) => hm.map(V::MESSAGE, &union_unique(namespace, msg)),
                None => hm.map(V::MESSAGE, msg),
            };
            hm_sum.add(&hm);
        }
        hm_sum
    } else {
        // Build a thread pool with the specified concurrency
        let pool = ThreadPoolBuilder::new()
            .num_threads(concurrency)
            .build()
            .expect("Unable to build thread pool");

        // Perform hashing to curve and summation of messages in parallel
        pool.install(move || {
            messages
                .into_par_iter()
                .map(|(namespace, msg)| {
                    let mut hm = V::Signature::zero();
                    match namespace {
                        Some(namespace) => hm.map(V::MESSAGE, &union_unique(namespace, msg)),
                        None => hm.map(V::MESSAGE, msg),
                    };
                    hm
                })
                .reduce(V::Signature::zero, |mut sum, hm| {
                    sum.add(&hm);
                    sum
                })
        })
    };

    // Verify the signature
    V::verify_prehashed(public, &hm_sum, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::{
        dkg::ops::generate_shares,
        primitives::variant::{MinPk, MinSig},
    };
    use blst::BLST_ERROR;
    use commonware_codec::DecodeExt;
    use commonware_utils::quorum;
    use group::{G1, G1_MESSAGE, G2, G2_MESSAGE};
    use poly::Poly;
    use rand::prelude::*;

    fn codec<V: Variant>() {
        // Encode private/public key
        let (private, public) = keypair::<_, V>(&mut thread_rng());
        let (private_bytes, public_bytes) = (private.encode(), public.encode());

        // Decode private/public key
        let (private_decoded, public_decoded) = (
            group::Private::decode(private_bytes.clone()).unwrap(),
            V::Public::decode(public_bytes.clone()).unwrap(),
        );

        // Ensure equal
        assert_eq!(private, private_decoded);
        assert_eq!(public, public_decoded);

        // Ensure blst compatibility
        match V::MESSAGE {
            G1_MESSAGE => {
                blst::min_sig::SecretKey::from_bytes(&private_bytes).unwrap();
                let blst_public_decoded =
                    blst::min_sig::PublicKey::from_bytes(&public_bytes).unwrap();
                blst_public_decoded.validate().unwrap();
                let blst_public_encoded = blst_public_decoded.compress().to_vec();
                assert_eq!(public_bytes, blst_public_encoded.as_slice());
            }
            G2_MESSAGE => {
                blst::min_pk::SecretKey::from_bytes(&private_bytes).unwrap();
                let blst_public_decoded =
                    blst::min_pk::PublicKey::from_bytes(&public_bytes).unwrap();
                blst_public_decoded.validate().unwrap();
                let blst_public_encoded = blst_public_decoded.compress().to_vec();
                assert_eq!(public_bytes, blst_public_encoded.as_slice());
            }
            _ => panic!("Unsupported Variant"),
        }
    }

    #[test]
    fn test_codec() {
        codec::<MinPk>();
        codec::<MinSig>();
    }

    /// Verify that a given proof-of-possession signature is valid according to `blst`.
    fn blst_verify_proof_of_possession<V: Variant>(
        public: &V::Public,
        signature: &V::Signature,
    ) -> Result<(), BLST_ERROR> {
        let msg = public.encode();
        match V::MESSAGE {
            G1_MESSAGE => {
                let public = blst::min_sig::PublicKey::from_bytes(&public.encode()).unwrap();
                let signature = blst::min_sig::Signature::from_bytes(&signature.encode()).unwrap();
                match signature.verify(true, &msg, V::PROOF_OF_POSSESSION, &[], &public, true) {
                    BLST_ERROR::BLST_SUCCESS => Ok(()),
                    e => Err(e),
                }
            }
            G2_MESSAGE => {
                let public = blst::min_pk::PublicKey::from_bytes(&public.encode()).unwrap();
                let signature = blst::min_pk::Signature::from_bytes(&signature.encode()).unwrap();
                match signature.verify(true, &msg, V::PROOF_OF_POSSESSION, &[], &public, true) {
                    BLST_ERROR::BLST_SUCCESS => Ok(()),
                    e => Err(e),
                }
            }
            _ => panic!("Unsupported Variant"),
        }
    }

    fn single_proof_of_possession<V: Variant>() {
        // Generate PoP
        let (private, public) = keypair::<_, V>(&mut thread_rng());
        let pop = sign_proof_of_possession::<V>(&private);

        // Verify PoP
        verify_proof_of_possession::<V>(&public, &pop).expect("PoP should be valid");

        // Verify PoP using blst
        blst_verify_proof_of_possession::<V>(&public, &pop).expect("PoP should be valid");
    }

    #[test]
    fn test_single_proof_of_possession() {
        single_proof_of_possession::<MinPk>();
        single_proof_of_possession::<MinSig>();
    }

    fn threshold_proof_of_possession<V: Variant>() {
        // Generate PoP
        let (n, t) = (5, 4);
        let mut rng = StdRng::seed_from_u64(0);
        let (public, shares) = generate_shares::<_, V>(&mut rng, None, n, t);
        let partials: Vec<_> = shares
            .iter()
            .map(|s| partial_sign_proof_of_possession::<V>(&public, s))
            .collect();
        for p in &partials {
            partial_verify_proof_of_possession::<V>(&public, p).expect("signature should be valid");
        }
        let threshold_sig = threshold_signature_recover::<V, _>(t, &partials).unwrap();
        let threshold_pub = poly::public::<V>(&public);

        // Verify PoP
        verify_proof_of_possession::<V>(threshold_pub, &threshold_sig)
            .expect("signature should be valid");

        // Verify PoP using blst
        blst_verify_proof_of_possession::<V>(threshold_pub, &threshold_sig)
            .expect("signature should be valid");
    }

    #[test]
    fn test_threshold_proof_of_possession() {
        threshold_proof_of_possession::<MinPk>();
        threshold_proof_of_possession::<MinSig>();
    }

    /// Verify that a given message signature is valid according to `blst`.
    fn blst_verify_message<V: Variant>(
        public: &V::Public,
        msg: &[u8],
        signature: &V::Signature,
    ) -> Result<(), BLST_ERROR> {
        match V::MESSAGE {
            G1_MESSAGE => {
                let public = blst::min_sig::PublicKey::from_bytes(&public.encode()).unwrap();
                let signature = blst::min_sig::Signature::from_bytes(&signature.encode()).unwrap();
                match signature.verify(true, msg, V::MESSAGE, &[], &public, true) {
                    BLST_ERROR::BLST_SUCCESS => Ok(()),
                    e => Err(e),
                }
            }
            G2_MESSAGE => {
                let public = blst::min_pk::PublicKey::from_bytes(&public.encode()).unwrap();
                let signature = blst::min_pk::Signature::from_bytes(&signature.encode()).unwrap();
                match signature.verify(true, msg, V::MESSAGE, &[], &public, true) {
                    BLST_ERROR::BLST_SUCCESS => Ok(()),
                    e => Err(e),
                }
            }
            _ => panic!("Unsupported Variant"),
        }
    }

    #[test]
    fn test_bad_namespace() {
        let (private, public) = keypair(&mut thread_rng());
        let msg = &[1, 9, 6, 9];
        let sig = sign_message(&private, Some(b"good"), msg);
        assert!(matches!(
            verify_message(&public, Some(b"bad"), msg, &sig).unwrap_err(),
            Error::InvalidSignature
        ));
    }

    #[test]
    fn test_single_message() {
        let (private, public) = keypair(&mut thread_rng());
        let msg = &[1, 9, 6, 9];
        let namespace = b"test";
        let sig = sign_message(&private, Some(namespace), msg);
        verify_message(&public, Some(namespace), msg, &sig).expect("signature should be valid");
        let payload = union_unique(namespace, msg);
        blst_verify_message(&public, &payload, &sig).expect("signature should be valid");
    }

    #[test]
    fn test_threshold_message() {
        // Generate signature
        let (n, t) = (5, 4);
        let mut rng = StdRng::seed_from_u64(0);
        let (public, shares) = generate_shares(&mut rng, None, n, t);
        let msg = &[1, 9, 6, 9];
        let namespace = b"test";
        let partials: Vec<_> = shares
            .iter()
            .map(|s| partial_sign_message(s, Some(namespace), msg))
            .collect();
        for p in &partials {
            partial_verify_message(&public, Some(namespace), msg, p)
                .expect("signature should be valid");
        }
        let threshold_sig = threshold_signature_recover(t, &partials).unwrap();
        let threshold_pub = poly::public(&public);

        // Verify the signature
        verify_message(threshold_pub, Some(namespace), msg, &threshold_sig)
            .expect("signature should be valid");

        // Verify the signature using blst
        let payload = union_unique(namespace, msg);
        blst_verify_message(threshold_pub, &payload, &threshold_sig)
            .expect("signature should be valid");
    }

    #[test]
    fn test_single_message_min_sig() {
        // Generate keypair
        let private = group::Private::rand(&mut thread_rng());
        let mut public = group::G2::one();
        public.mul(&private);

        // Sign message
        let msg = &[1, 9, 6, 9];
        let namespace = b"test";
        let payload = union_unique(namespace, msg);
        let mut signature = G1::zero();
        signature.map(G1_MESSAGE, &payload);
        signature.mul(&private);

        // Verify signature using blst
        let public = blst::min_sig::PublicKey::from_bytes(&public.encode()).unwrap();
        let signature = blst::min_sig::Signature::from_bytes(&signature.encode()).unwrap();
        let result = match signature.verify(true, &payload, G1_MESSAGE, &[], &public, true) {
            BLST_ERROR::BLST_SUCCESS => Ok(()),
            e => Err(e),
        };
        result.expect("signature should be valid");
    }

    fn blst_aggregate_verify_multiple_public_keys<'a, I>(
        public: I,
        message: &[u8],
        signature: &group::Signature,
    ) -> Result<(), BLST_ERROR>
    where
        I: IntoIterator<Item = &'a group::Public>,
    {
        let public = public
            .into_iter()
            .map(|pk| blst::min_sig::PublicKey::from_bytes(&pk.encode()).unwrap())
            .collect::<Vec<_>>();
        let public = public.iter().collect::<Vec<_>>();
        let signature = blst::min_sig::Signature::from_bytes(&signature.encode()).unwrap();
        match signature.fast_aggregate_verify(true, message, MESSAGE, &public) {
            BLST_ERROR::BLST_SUCCESS => Ok(()),
            e => Err(e),
        }
    }

    #[test]
    fn test_aggregate_verify_multiple_public_keys() {
        // Generate signatures
        let (private1, public1) = keypair(&mut thread_rng());
        let (private2, public2) = keypair(&mut thread_rng());
        let (private3, public3) = keypair(&mut thread_rng());
        let namespace = b"test";
        let message = b"message";
        let sig1 = sign_message(&private1, Some(namespace), message);
        let sig2 = sign_message(&private2, Some(namespace), message);
        let sig3 = sign_message(&private3, Some(namespace), message);
        let pks = vec![public1, public2, public3];
        let signatures = vec![sig1, sig2, sig3];

        // Aggregate the signatures
        let aggregate_sig = aggregate_signatures(&signatures);

        // Verify the aggregated signature
        aggregate_verify_multiple_public_keys(&pks, Some(namespace), message, &aggregate_sig)
            .expect("Aggregated signature should be valid");

        // Verify the aggregated signature using blst
        let payload = union_unique(namespace, message);
        blst_aggregate_verify_multiple_public_keys(&pks, &payload, &aggregate_sig)
            .expect("Aggregated signature should be valid");
    }

    #[test]
    fn test_aggregate_verify_wrong_public_keys() {
        // Generate signatures
        let (private1, public1) = keypair(&mut thread_rng());
        let (private2, public2) = keypair(&mut thread_rng());
        let (private3, _) = keypair(&mut thread_rng());
        let namespace = b"test";
        let message = b"message";
        let sig1 = sign_message(&private1, Some(namespace), message);
        let sig2 = sign_message(&private2, Some(namespace), message);
        let sig3 = sign_message(&private3, Some(namespace), message);
        let signatures = vec![sig1, sig2, sig3];

        // Aggregate the signatures
        let aggregate_sig = aggregate_signatures(&signatures);

        // Verify the aggregated signature
        let (_, public4) = keypair(&mut thread_rng());
        let wrong_pks = vec![public1, public2, public4];
        let result = aggregate_verify_multiple_public_keys(
            &wrong_pks,
            Some(namespace),
            message,
            &aggregate_sig,
        );
        assert!(matches!(result, Err(Error::InvalidSignature)));
    }

    #[test]
    fn test_aggregate_verify_wrong_public_key_count() {
        // Generate signatures
        let (private1, public1) = keypair(&mut thread_rng());
        let (private2, public2) = keypair(&mut thread_rng());
        let (private3, _) = keypair(&mut thread_rng());
        let namespace = b"test";
        let message = b"message";
        let sig1 = sign_message(&private1, Some(namespace), message);
        let sig2 = sign_message(&private2, Some(namespace), message);
        let sig3 = sign_message(&private3, Some(namespace), message);
        let signatures = vec![sig1, sig2, sig3];

        // Aggregate the signatures
        let aggregate_sig = aggregate_signatures(&signatures);

        // Verify the aggregated signature
        let wrong_pks = vec![public1, public2];
        let result = aggregate_verify_multiple_public_keys(
            &wrong_pks,
            Some(namespace),
            message,
            &aggregate_sig,
        );
        assert!(matches!(result, Err(Error::InvalidSignature)));
    }

    fn blst_aggregate_verify_multiple_messages<'a, I>(
        public: &group::Public,
        msgs: I,
        signature: &group::Signature,
    ) -> Result<(), BLST_ERROR>
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let public = blst::min_sig::PublicKey::from_bytes(&public.encode()).unwrap();
        let msgs = msgs.into_iter().collect::<Vec<_>>();
        let pks = vec![&public; msgs.len()];
        let signature = blst::min_sig::Signature::from_bytes(&signature.encode()).unwrap();
        match signature.aggregate_verify(true, &msgs, MESSAGE, &pks, true) {
            BLST_ERROR::BLST_SUCCESS => Ok(()),
            e => Err(e),
        }
    }

    #[test]
    fn test_aggregate_verify_multiple_messages() {
        // Generate signatures
        let (private, public) = keypair(&mut thread_rng());
        let namespace = Some(&b"test"[..]);
        let messages: Vec<(Option<&[u8]>, &[u8])> = vec![
            (namespace, b"Message 1"),
            (namespace, b"Message 2"),
            (namespace, b"Message 3"),
        ];
        let signatures: Vec<_> = messages
            .iter()
            .map(|(namespace, msg)| sign_message(&private, *namespace, msg))
            .collect();

        // Aggregate the signatures
        let aggregate_sig = aggregate_signatures(&signatures);

        // Verify the aggregated signature without parallelism
        aggregate_verify_multiple_messages(&public, &messages, &aggregate_sig, 1)
            .expect("Aggregated signature should be valid");

        // Verify the aggregated signature with parallelism
        aggregate_verify_multiple_messages(&public, &messages, &aggregate_sig, 4)
            .expect("Aggregated signature should be valid");

        // Verify the aggregated signature using blst
        let messages = messages
            .iter()
            .map(|(namespace, msg)| union_unique(namespace.unwrap(), msg))
            .collect::<Vec<_>>();
        let messages = messages
            .iter()
            .map(|msg| msg.as_slice())
            .collect::<Vec<_>>();
        blst_aggregate_verify_multiple_messages(&public, messages, &aggregate_sig)
            .expect("Aggregated signature should be valid");
    }

    #[test]
    fn test_aggregate_verify_wrong_messages() {
        // Generate signatures
        let (private, public) = keypair(&mut thread_rng());
        let namespace = Some(&b"test"[..]);
        let messages: Vec<(Option<&[u8]>, &[u8])> = vec![
            (namespace, b"Message 1"),
            (namespace, b"Message 2"),
            (namespace, b"Message 3"),
        ];
        let signatures: Vec<_> = messages
            .iter()
            .map(|(namespace, msg)| sign_message(&private, *namespace, msg))
            .collect();

        // Aggregate the signatures
        let aggregate_sig = aggregate_signatures(&signatures);

        // Construct wrong messages
        let wrong_messages: Vec<(Option<&[u8]>, &[u8])> = vec![
            (namespace, b"Message 1"),
            (namespace, b"Message 2"),
            (namespace, b"Message 4"),
        ];

        // Verify the aggregated signature without parallelism
        let result =
            aggregate_verify_multiple_messages(&public, &wrong_messages, &aggregate_sig, 1);
        assert!(matches!(result, Err(Error::InvalidSignature)));

        // Verify the aggregated signature with parallelism
        let result =
            aggregate_verify_multiple_messages(&public, &wrong_messages, &aggregate_sig, 4);
        assert!(matches!(result, Err(Error::InvalidSignature)));
    }

    #[test]
    fn test_aggregate_verify_wrong_message_count() {
        // Generate signatures
        let (private, public) = keypair(&mut thread_rng());
        let namespace = Some(&b"test"[..]);
        let messages: Vec<(Option<&[u8]>, &[u8])> = vec![
            (namespace, b"Message 1"),
            (namespace, b"Message 2"),
            (namespace, b"Message 3"),
        ];
        let signatures: Vec<_> = messages
            .iter()
            .map(|(namespace, msg)| sign_message(&private, *namespace, msg))
            .collect();

        // Aggregate the signatures
        let aggregate_sig = aggregate_signatures(&signatures);

        // Construct wrong messages
        let wrong_messages: Vec<(Option<&[u8]>, &[u8])> =
            vec![(namespace, b"Message 1"), (namespace, b"Message 2")];

        // Verify the aggregated signature without parallelism
        let result =
            aggregate_verify_multiple_messages(&public, &wrong_messages, &aggregate_sig, 1);
        assert!(matches!(result, Err(Error::InvalidSignature)));

        // Verify the aggregated signature with parallelism
        let result =
            aggregate_verify_multiple_messages(&public, &wrong_messages, &aggregate_sig, 4);
        assert!(matches!(result, Err(Error::InvalidSignature)));
    }

    #[test]
    fn test_partial_verify_multiple_messages() {
        // Generate polynomial and shares
        let n = 5;
        let t = quorum(n);
        let (public, shares) = generate_shares(&mut thread_rng(), None, n, t);

        // Select signer with index 0
        let signer = &shares[0];

        // Successful verification with namespaced messages
        let messages: Vec<(Option<&[u8]>, &[u8])> = vec![
            (Some(&b"ns"[..]), b"msg1"),
            (Some(&b"ns"[..]), b"msg2"),
            (Some(&b"ns"[..]), b"msg3"),
        ];
        let partials: Vec<PartialSignature> = messages
            .iter()
            .map(|(ns, msg)| partial_sign_message(signer, *ns, msg))
            .collect();
        partial_verify_multiple_messages(&public, signer.index, &messages, &partials)
            .expect("Verification with namespaced messages should succeed");

        // Successful verification with non-namespaced messages
        let messages_no_ns: Vec<(Option<&[u8]>, &[u8])> =
            vec![(None, b"msg1"), (None, b"msg2"), (None, b"msg3")];
        let partials_no_ns: Vec<PartialSignature> = messages_no_ns
            .iter()
            .map(|(ns, msg)| partial_sign_message(signer, *ns, msg))
            .collect();
        partial_verify_multiple_messages(&public, signer.index, &messages_no_ns, &partials_no_ns)
            .expect("Verification with non-namespaced messages should succeed");

        // Successful verification with mixed namespaces
        let messages_mixed: Vec<(Option<&[u8]>, &[u8])> = vec![
            (Some(&b"ns1"[..]), b"msg1"),
            (None, b"msg2"),
            (Some(&b"ns2"[..]), b"msg3"),
        ];
        let partials_mixed: Vec<PartialSignature> = messages_mixed
            .iter()
            .map(|(ns, msg)| partial_sign_message(signer, *ns, msg))
            .collect();
        partial_verify_multiple_messages(&public, signer.index, &messages_mixed, &partials_mixed)
            .expect("Verification with mixed namespaces should succeed");

        // Failure with wrong signer index
        assert!(matches!(
            partial_verify_multiple_messages(&public, 1, &messages, &partials),
            Err(Error::InvalidSignature)
        ));

        // Success with swapped partial signatures
        let mut partials_swapped = partials.clone();
        partials_swapped.swap(0, 1);
        partial_verify_multiple_messages(&public, signer.index, &messages, &partials_swapped)
            .expect("Verification with swapped partials should succeed");

        // Failure with fewer signatures than messages
        let partials_fewer = partials[..2].to_vec();
        assert!(matches!(
            partial_verify_multiple_messages(&public, signer.index, &messages, &partials_fewer),
            Err(Error::InvalidSignature)
        ));

        // Failure with more signatures than messages
        let extra_message = (Some(&b"ns"[..]), b"msg4");
        let extra_partial = partial_sign_message(signer, extra_message.0, extra_message.1);
        let mut partials_more = partials.clone();
        partials_more.push(extra_partial);
        assert!(matches!(
            partial_verify_multiple_messages(&public, signer.index, &messages, &partials_more),
            Err(Error::InvalidSignature)
        ));

        // Failure with signatures from different signers
        let signer2 = &shares[1];
        let partial2 = partial_sign_message(signer2, messages[0].0, messages[0].1);
        let mut partials_mixed_signers = partials.clone();
        partials_mixed_signers[0] = partial2;
        assert!(matches!(
            partial_verify_multiple_messages(
                &public,
                signer.index,
                &messages,
                &partials_mixed_signers
            ),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn test_threshold_signature_recover_with_weights() {
        let mut rng = StdRng::seed_from_u64(3333);
        let (n, t) = (6, quorum(6));
        let (group_poly, shares) = crate::bls12381::dkg::ops::generate_shares(&mut rng, None, n, t);

        // Produce partial signatures for the first `t` shares.
        let partials: Vec<_> = shares
            .iter()
            .take(t as usize)
            .map(|s| partial_sign_message(s, None, b"payload"))
            .collect();

        // Compute barycentric weights once.
        let indices = partials.iter().map(|e| e.index).collect::<Vec<_>>();
        let weights = compute_weights(indices).unwrap();

        // Path-1: generic recover
        let sig1 = threshold_signature_recover(t, &partials).unwrap();

        // Path-2: recover with *pre-computed* weights
        let sig2 = threshold_signature_recover_with_weights(&weights, &partials).unwrap();

        assert_eq!(sig1, sig2);

        // Verify with the aggregated public key.
        let pk = poly::public(&group_poly);
        verify_message(pk, None, b"payload", &sig1).unwrap();
    }

    #[test]
    fn test_threshold_signature_recover_multiple() {
        let mut rng = StdRng::seed_from_u64(3333);
        let (n, t) = (6, quorum(6));
        let (group_poly, shares) = crate::bls12381::dkg::ops::generate_shares(&mut rng, None, n, t);

        // Produce partial signatures for the first `t` shares.
        let partials_1: Vec<_> = shares
            .iter()
            .take(t as usize)
            .map(|s| partial_sign_message(s, None, b"payload1"))
            .collect();
        let partials_2: Vec<_> = shares
            .iter()
            .take(t as usize)
            .map(|s| partial_sign_message(s, None, b"payload2"))
            .collect();

        // Recover signatures
        let (sig_1, sig_2) = threshold_signature_recover_pair(t, &partials_1, &partials_2).unwrap();

        // Verify with the aggregated public key.
        let pk = poly::public(&group_poly);
        verify_message(pk, None, b"payload1", &sig_1).unwrap();
        verify_message(pk, None, b"payload2", &sig_2).unwrap();
    }

    #[test]
    fn test_msm_interpolate_vs_poly_recover() {
        let mut rng = StdRng::seed_from_u64(4242);
        let degree = 5;
        let threshold = degree + 1;
        let poly_scalar = poly::new_from(degree, &mut rng);

        // Commit to G1 (Signature group)
        let poly_g1 = Poly::<G1>::commit(poly_scalar);

        // Generate evaluations (enough to meet threshold)
        let evals: Vec<_> = (0..threshold).map(|i| poly_g1.evaluate(i)).collect();
        let eval_refs: Vec<_> = evals.iter().collect(); // Get references

        // Compute weights
        let indices: Vec<u32> = eval_refs.iter().map(|e| e.index).collect();
        let weights = poly::compute_weights(indices).expect("Failed to compute weights");

        // Calculate using original polynomial recovery (naive interpolation)
        let expected_result = poly::Signature::recover_with_weights(&weights, eval_refs.clone())
            .expect("poly::recover_with_weights failed");

        // Calculate using MSM interpolation
        let msm_result = msm_interpolate(&weights, eval_refs).expect("msm_interpolate failed");

        // Compare results
        assert_eq!(
            expected_result, msm_result,
            "MSM interpolation result differs from polynomial recovery"
        );

        // Also check against the known constant term
        assert_eq!(
            expected_result,
            *poly_g1.constant(),
            "Recovered value does not match original constant term"
        );
    }

    #[test]
    fn test_msm_interpolate_invalid_index() {
        let mut rng = StdRng::seed_from_u64(5555);
        let degree = 2;
        let threshold = degree + 1;
        let poly_scalar = poly::new_from(degree, &mut rng);
        let poly_g2 = Poly::<G2>::commit(poly_scalar);

        // Generate threshold evaluations
        let evals: Vec<_> = (0..threshold).map(|i| poly_g2.evaluate(i)).collect();
        let eval_refs: Vec<_> = evals.iter().collect();

        // Compute weights for *different* indices
        let wrong_indices: Vec<u32> = (threshold..threshold * 2).collect();
        let weights = poly::compute_weights(wrong_indices).expect("Failed to compute weights");

        // Try to interpolate with mismatched weights/evals
        let result = msm_interpolate::<G2, _>(&weights, eval_refs);

        // Expect InvalidIndex error
        assert!(
            matches!(result, Err(Error::InvalidIndex)),
            "Expected InvalidIndex error for mismatched weights"
        );
    }

    #[test]
    fn test_msm_interpolate_empty() {
        let weights: BTreeMap<u32, Weight> = BTreeMap::new();
        let evals: Vec<Eval<G2>> = Vec::new();
        let eval_refs: Vec<&Eval<G2>> = evals.iter().collect();

        // Interpolate with empty inputs
        let result = msm_interpolate(&weights, eval_refs).expect("msm_interpolate failed on empty");

        // Expect identity element
        assert_eq!(
            result,
            G2::zero(),
            "Expected G2 identity for empty interpolation"
        );
    }
}
