//! Digital signatures over the BLS12-381 curve using G1 as the Public Key (48 bytes)
//! and G2 as the Signature (96 bytes).
//!
//! # Domain Separation Tag (DST)
//!
//! All signatures use the `POP` (Proof of Possession) scheme during signing. For Proof-of-Possession (POP) signatures,
//! the domain separation tag is `BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`. For signatures over other messages, the
//! domain separation tag is `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`. You can read more about DSTs [here](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05#section-4.2).

use super::{
    group::{self, Element, Point, Scalar, Share, DST},
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

/// Computes the public key from the private key.
pub fn compute_public<V: Variant>(private: &Scalar) -> V::Public {
    let mut public = V::Public::one();
    public.mul(private);
    public
}

/// Returns a new keypair derived from the provided randomness.
pub fn keypair<R: RngCore, V: Variant>(rng: &mut R) -> (group::Private, V::Public) {
    let private = group::Private::from_rand(rng);
    let public = compute_public::<V>(&private);
    (private, public)
}

/// Hashes the provided message with the domain separation tag (DST) to
/// the curve.
pub fn hash_message<V: Variant>(dst: DST, message: &[u8]) -> V::Signature {
    let mut hm = V::Signature::zero();
    hm.map(dst, message);
    hm
}

/// Hashes the provided message with the domain separation tag (DST) and namespace to
/// the curve.
pub fn hash_message_namespace<V: Variant>(
    dst: DST,
    namespace: &[u8],
    message: &[u8],
) -> V::Signature {
    let mut hm = V::Signature::zero();
    hm.map(dst, &union_unique(namespace, message));
    hm
}

/// Signs the provided message with the private key.
pub fn sign<V: Variant>(private: &Scalar, dst: DST, message: &[u8]) -> V::Signature {
    let mut hm = hash_message::<V>(dst, message);
    hm.mul(private);
    hm
}

/// Generates a proof of possession for the private key.
pub fn sign_proof_of_possession<V: Variant>(private: &group::Private) -> V::Signature {
    // Get public key
    let public = compute_public::<V>(private);

    // Sign the public key
    sign::<V>(private, V::PROOF_OF_POSSESSION, &public.encode())
}

/// Verifies the signature with the provided public key.
pub fn verify<V: Variant>(
    public: &V::Public,
    dst: DST,
    message: &[u8],
    signature: &V::Signature,
) -> Result<(), Error> {
    // Create hashed message `hm`
    let hm = hash_message::<V>(dst, message);

    // Verify the signature
    V::verify(public, &hm, signature)
}

/// Verifies a proof of possession for the provided public key.
pub fn verify_proof_of_possession<V: Variant>(
    public: &V::Public,
    signature: &V::Signature,
) -> Result<(), Error> {
    verify::<V>(public, V::PROOF_OF_POSSESSION, &public.encode(), signature)
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
    sign::<V>(private, V::MESSAGE, &payload)
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
    verify::<V>(public, V::MESSAGE, &payload, signature)
}

/// Generates a proof of possession for the private key share.
pub fn partial_sign_proof_of_possession<V: Variant>(
    public: &poly::Public<V>,
    private: &Share,
) -> PartialSignature<V> {
    // Get public key
    let threshold_public = poly::public::<V>(public);

    // Sign the public key
    let sig = sign::<V>(
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
    verify::<V>(
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
    index: u32,
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
    let (parsed_index, signature) =
        partial_aggregate_signatures::<V, _>(signatures).ok_or(Error::InvalidSignature)?;
    if index != parsed_index {
        return Err(Error::InvalidSignature);
    }
    let public = public.evaluate(index).value;

    // Sum the hashed messages
    let mut hm_sum = V::Signature::zero();
    for (namespace, msg) in messages {
        let hm = match namespace {
            Some(namespace) => hash_message_namespace::<V>(V::MESSAGE, namespace, msg),
            None => hash_message::<V>(V::MESSAGE, msg),
        };
        hm_sum.add(&hm);
    }

    // Verify the signature
    V::verify(&public, &hm_sum, &signature)
}

/// Verify a list of [PartialSignature]s by performing aggregate verification,
/// performing repeated bisection to find invalid signatures (if any exist).
///
/// TODO (#903): parallelize this
fn partial_verify_multiple_public_keys_bisect<'a, V, VP>(
    pending: &[(VP, &'a PartialSignature<V>)],
    mut invalid: Vec<&'a PartialSignature<V>>,
    namespace: Option<&[u8]>,
    message: &[u8],
) -> Result<(), Vec<&'a PartialSignature<V>>>
where
    V: Variant,
    VP: AsRef<V::Public>,
{
    // Iteratively bisect to find invalid signatures
    let mut stack = vec![(0, pending.len())];
    while let Some((start, end)) = stack.pop() {
        // Skip if range is empty
        let slice = &pending[start..end];
        if slice.is_empty() {
            continue;
        }

        // Create aggregate public key and signature
        let mut agg_pk = V::Public::zero();
        let mut agg_sig = V::Signature::zero();
        for (pk, partial) in slice {
            agg_pk.add(pk.as_ref());
            agg_sig.add(&partial.value);
        }

        // If aggregate signature is invalid, bisect. Otherwise, continue.
        if verify_message::<V>(&agg_pk, namespace, message, &agg_sig).is_err() {
            if slice.len() == 1 {
                invalid.push(slice[0].1);
            } else {
                let mid = slice.len() / 2;
                stack.push((start + mid, end));
                stack.push((start, start + mid));
            }
        }
    }

    // Return invalid partial signatures, if any
    if !invalid.is_empty() {
        return Err(invalid);
    }
    Ok(())
}

/// Attempts to verify multiple [PartialSignature]s over the same message as a single
/// aggregate signature (or returns any invalid signature found).
///
/// Unlike `partial_verify_multiple_public_keys`, this function requires the public keys
/// of all partial signatures to be precomputed (avoids a significant amount of compute
/// evaluating each signer on the public polynomial).
pub fn partial_verify_multiple_public_keys_precomputed<'a, V, I>(
    polynomial: &[V::Public],
    namespace: Option<&[u8]>,
    message: &[u8],
    partials: I,
) -> Result<(), Vec<&'a PartialSignature<V>>>
where
    V: Variant,
    I: IntoIterator<Item = &'a PartialSignature<V>>,
{
    // Ensure all partial signatures are associated with a signer
    let partials = partials.into_iter();
    let mut pending = Vec::with_capacity(partials.size_hint().0);
    let mut invalid = Vec::new();
    for partial in partials {
        match polynomial.get(partial.index as usize) {
            Some(public_key) => pending.push((public_key, partial)),
            None => invalid.push(partial),
        }
    }

    // Find any invalid partial signatures
    partial_verify_multiple_public_keys_bisect::<V, _>(&pending, invalid, namespace, message)
}

/// Attempts to verify multiple [PartialSignature]s over the same message as a single
/// aggregate signature (or returns any invalid signature found).
///
/// # Warning
///
/// This function assumes a group check was already performed on each `signature`.
pub fn partial_verify_multiple_public_keys<'a, V, I>(
    public: &poly::Public<V>,
    namespace: Option<&[u8]>,
    message: &[u8],
    partials: I,
) -> Result<(), Vec<&'a PartialSignature<V>>>
where
    V: Variant,
    I: IntoIterator<Item = &'a PartialSignature<V>>,
{
    // Evaluate public polynomial to compute signer public keys
    let pending = partials
        .into_iter()
        .map(|partial| {
            let public_key = public.evaluate(partial.index).value;
            (public_key, partial)
        })
        .collect::<Vec<_>>();

    // Find any invalid partial signatures
    partial_verify_multiple_public_keys_bisect::<V, _>(&pending, Vec::new(), namespace, message)
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
    concurrency: usize,
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

    // If concurrency is not required, recover signatures sequentially
    let concurrency = std::cmp::min(concurrency, prepared_evals.len());
    if concurrency == 1 {
        return prepared_evals
            .iter()
            .map(|evals| {
                threshold_signature_recover_with_weights::<V, _>(&weights, evals.iter().cloned())
            })
            .collect();
    }

    // Build a thread pool with the specified concurrency
    let pool = ThreadPoolBuilder::new()
        .num_threads(concurrency)
        .build()
        .expect("Unable to build thread pool");

    // Recover signatures
    pool.install(move || {
        prepared_evals
            .par_iter()
            .map(|evals| {
                threshold_signature_recover_with_weights::<V, _>(&weights, evals.iter().cloned())
            })
            .collect()
    })
}

/// Recovers a pair of signatures from two sets of at least `threshold` partial signatures.
///
/// This is just a wrapper around `threshold_signature_recover_multiple` with concurrency set to 2.
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
    let mut sigs = threshold_signature_recover_multiple::<V, _>(threshold, vec![first, second], 2)?;
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
            let hm = match namespace {
                Some(namespace) => hash_message_namespace::<V>(V::MESSAGE, namespace, msg),
                None => hash_message::<V>(V::MESSAGE, msg),
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
                .map(|(namespace, msg)| match namespace {
                    Some(namespace) => hash_message_namespace::<V>(V::MESSAGE, namespace, msg),
                    None => hash_message::<V>(V::MESSAGE, msg),
                })
                .reduce(V::Signature::zero, |mut sum, hm| {
                    sum.add(&hm);
                    sum
                })
        })
    };

    // Verify the signature
    V::verify(public, &hm_sum, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::{
        dkg::ops::{evaluate_all, generate_shares},
        primitives::variant::{MinPk, MinSig},
    };
    use blst::BLST_ERROR;
    use commonware_codec::{DecodeExt, ReadExt};
    use commonware_utils::{from_hex_formatted, quorum};
    use group::{Private, G1_MESSAGE, G2_MESSAGE};
    use poly::Poly;
    use rand::{prelude::*, rngs::OsRng};

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

    fn bad_namespace<V: Variant>() {
        let (private, public) = keypair::<_, V>(&mut thread_rng());
        let msg = &[1, 9, 6, 9];
        let sig = sign_message::<V>(&private, Some(b"good"), msg);
        assert!(matches!(
            verify_message::<V>(&public, Some(b"bad"), msg, &sig).unwrap_err(),
            Error::InvalidSignature
        ));
    }

    #[test]
    fn test_bad_namespace() {
        bad_namespace::<MinPk>();
        bad_namespace::<MinSig>();
    }

    fn single_message<V: Variant>() {
        let (private, public) = keypair::<_, V>(&mut thread_rng());
        let msg = &[1, 9, 6, 9];
        let namespace = b"test";
        let sig = sign_message::<V>(&private, Some(namespace), msg);
        verify_message::<V>(&public, Some(namespace), msg, &sig)
            .expect("signature should be valid");
        let payload = union_unique(namespace, msg);
        blst_verify_message::<V>(&public, &payload, &sig).expect("signature should be valid");
    }

    #[test]
    fn test_single_message() {
        single_message::<MinPk>();
        single_message::<MinSig>();
    }

    fn threshold_message<V: Variant>() {
        // Generate signature
        let (n, t) = (5, 4);
        let mut rng = StdRng::seed_from_u64(0);
        let (public, shares) = generate_shares::<_, V>(&mut rng, None, n, t);
        let msg = &[1, 9, 6, 9];
        let namespace = b"test";
        let partials: Vec<_> = shares
            .iter()
            .map(|s| partial_sign_message::<V>(s, Some(namespace), msg))
            .collect();
        for p in &partials {
            partial_verify_message::<V>(&public, Some(namespace), msg, p)
                .expect("signature should be valid");
        }
        let threshold_sig = threshold_signature_recover::<V, _>(t, &partials).unwrap();
        let threshold_pub = poly::public::<V>(&public);

        // Verify the signature
        verify_message::<V>(threshold_pub, Some(namespace), msg, &threshold_sig)
            .expect("signature should be valid");

        // Verify the signature using blst
        let payload = union_unique(namespace, msg);
        blst_verify_message::<V>(threshold_pub, &payload, &threshold_sig)
            .expect("signature should be valid");
    }

    #[test]
    fn test_threshold_message() {
        threshold_message::<MinPk>();
        threshold_message::<MinSig>();
    }

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
        // Generate signatures
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

        // Aggregate the signatures
        let aggregate_sig = aggregate_signatures::<V, _>(&signatures);

        // Verify the aggregated signature
        aggregate_verify_multiple_public_keys::<V, _>(
            &pks,
            Some(namespace),
            message,
            &aggregate_sig,
        )
        .expect("Aggregated signature should be valid");

        // Verify the aggregated signature using blst
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
        // Generate signatures
        let (private1, public1) = keypair::<_, V>(&mut thread_rng());
        let (private2, public2) = keypair::<_, V>(&mut thread_rng());
        let (private3, _) = keypair::<_, V>(&mut thread_rng());
        let namespace = b"test";
        let message = b"message";
        let sig1 = sign_message::<V>(&private1, Some(namespace), message);
        let sig2 = sign_message::<V>(&private2, Some(namespace), message);
        let sig3 = sign_message::<V>(&private3, Some(namespace), message);
        let signatures = vec![sig1, sig2, sig3];

        // Aggregate the signatures
        let aggregate_sig = aggregate_signatures::<V, _>(&signatures);

        // Verify the aggregated signature
        let (_, public4) = keypair::<_, V>(&mut thread_rng());
        let wrong_pks = vec![public1, public2, public4];
        let result = aggregate_verify_multiple_public_keys::<V, _>(
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
        // Generate signatures
        let (private1, public1) = keypair::<_, V>(&mut thread_rng());
        let (private2, public2) = keypair::<_, V>(&mut thread_rng());
        let (private3, _) = keypair::<_, V>(&mut thread_rng());
        let namespace = b"test";
        let message = b"message";
        let sig1 = sign_message::<V>(&private1, Some(namespace), message);
        let sig2 = sign_message::<V>(&private2, Some(namespace), message);
        let sig3 = sign_message::<V>(&private3, Some(namespace), message);
        let signatures = vec![sig1, sig2, sig3];

        // Aggregate the signatures
        let aggregate_sig = aggregate_signatures::<V, _>(&signatures);

        // Verify the aggregated signature
        let wrong_pks = vec![public1, public2];
        let result = aggregate_verify_multiple_public_keys::<V, _>(
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
        // Generate signatures
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

        // Aggregate the signatures
        let aggregate_sig = aggregate_signatures::<V, _>(&signatures);

        // Verify the aggregated signature without parallelism
        aggregate_verify_multiple_messages::<V, _>(&public, &messages, &aggregate_sig, 1)
            .expect("Aggregated signature should be valid");

        // Verify the aggregated signature with parallelism
        aggregate_verify_multiple_messages::<V, _>(&public, &messages, &aggregate_sig, 4)
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
        blst_aggregate_verify_multiple_messages::<V, _>(&public, messages, &aggregate_sig)
            .expect("Aggregated signature should be valid");
    }

    #[test]
    fn test_aggregate_verify_multiple_messages() {
        aggregate_verify_multiple_messages_correct::<MinPk>();
        aggregate_verify_multiple_messages_correct::<MinSig>();
    }

    fn aggregate_verify_wrong_messages<V: Variant>() {
        // Generate signatures
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

        // Aggregate the signatures
        let aggregate_sig = aggregate_signatures::<V, _>(&signatures);

        // Construct wrong messages
        let wrong_messages: Vec<(Option<&[u8]>, &[u8])> = vec![
            (namespace, b"Message 1"),
            (namespace, b"Message 2"),
            (namespace, b"Message 4"),
        ];

        // Verify the aggregated signature without parallelism
        let result =
            aggregate_verify_multiple_messages::<V, _>(&public, &wrong_messages, &aggregate_sig, 1);
        assert!(matches!(result, Err(Error::InvalidSignature)));

        // Verify the aggregated signature with parallelism
        let result =
            aggregate_verify_multiple_messages::<V, _>(&public, &wrong_messages, &aggregate_sig, 4);
        assert!(matches!(result, Err(Error::InvalidSignature)));
    }

    #[test]
    fn test_aggregate_verify_wrong_messages() {
        aggregate_verify_wrong_messages::<MinPk>();
        aggregate_verify_wrong_messages::<MinSig>();
    }

    fn aggregate_verify_wrong_message_count<V: Variant>() {
        // Generate signatures
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

        // Aggregate the signatures
        let aggregate_sig = aggregate_signatures::<V, _>(&signatures);

        // Construct wrong messages
        let wrong_messages: Vec<(Option<&[u8]>, &[u8])> =
            vec![(namespace, b"Message 1"), (namespace, b"Message 2")];

        // Verify the aggregated signature without parallelism
        let result =
            aggregate_verify_multiple_messages::<V, _>(&public, &wrong_messages, &aggregate_sig, 1);
        assert!(matches!(result, Err(Error::InvalidSignature)));

        // Verify the aggregated signature with parallelism
        let result =
            aggregate_verify_multiple_messages::<V, _>(&public, &wrong_messages, &aggregate_sig, 4);
        assert!(matches!(result, Err(Error::InvalidSignature)));
    }

    #[test]
    fn test_aggregate_verify_wrong_message_count() {
        aggregate_verify_wrong_message_count::<MinPk>();
        aggregate_verify_wrong_message_count::<MinSig>();
    }

    fn partial_verify_multiple_messages_correct<V: Variant>() {
        // Generate polynomial and shares
        let n = 5;
        let t = quorum(n);
        let (public, shares) = generate_shares::<_, V>(&mut thread_rng(), None, n, t);

        // Select signer with index 0
        let signer = &shares[0];

        // Successful verification with namespaced messages
        let messages: Vec<(Option<&[u8]>, &[u8])> = vec![
            (Some(&b"ns"[..]), b"msg1"),
            (Some(&b"ns"[..]), b"msg2"),
            (Some(&b"ns"[..]), b"msg3"),
        ];
        let partials: Vec<PartialSignature<V>> = messages
            .iter()
            .map(|(ns, msg)| partial_sign_message::<V>(signer, *ns, msg))
            .collect();
        partial_verify_multiple_messages::<V, _, _>(&public, signer.index, &messages, &partials)
            .expect("Verification with namespaced messages should succeed");

        // Successful verification with non-namespaced messages
        let messages_no_ns: Vec<(Option<&[u8]>, &[u8])> =
            vec![(None, b"msg1"), (None, b"msg2"), (None, b"msg3")];
        let partials_no_ns: Vec<PartialSignature<V>> = messages_no_ns
            .iter()
            .map(|(ns, msg)| partial_sign_message::<V>(signer, *ns, msg))
            .collect();
        partial_verify_multiple_messages::<V, _, _>(
            &public,
            signer.index,
            &messages_no_ns,
            &partials_no_ns,
        )
        .expect("Verification with non-namespaced messages should succeed");

        // Successful verification with mixed namespaces
        let messages_mixed: Vec<(Option<&[u8]>, &[u8])> = vec![
            (Some(&b"ns1"[..]), b"msg1"),
            (None, b"msg2"),
            (Some(&b"ns2"[..]), b"msg3"),
        ];
        let partials_mixed: Vec<PartialSignature<V>> = messages_mixed
            .iter()
            .map(|(ns, msg)| partial_sign_message::<V>(signer, *ns, msg))
            .collect();
        partial_verify_multiple_messages::<V, _, _>(
            &public,
            signer.index,
            &messages_mixed,
            &partials_mixed,
        )
        .expect("Verification with mixed namespaces should succeed");

        // Failure with wrong signer index
        assert!(matches!(
            partial_verify_multiple_messages::<V, _, _>(&public, 1, &messages, &partials),
            Err(Error::InvalidSignature)
        ));

        // Success with swapped partial signatures
        let mut partials_swapped = partials.clone();
        partials_swapped.swap(0, 1);
        partial_verify_multiple_messages::<V, _, _>(
            &public,
            signer.index,
            &messages,
            &partials_swapped,
        )
        .expect("Verification with swapped partials should succeed");

        // Failure with fewer signatures than messages
        let partials_fewer = partials[..2].to_vec();
        assert!(matches!(
            partial_verify_multiple_messages::<V, _, _>(
                &public,
                signer.index,
                &messages,
                &partials_fewer
            ),
            Err(Error::InvalidSignature)
        ));

        // Failure with more signatures than messages
        let extra_message = (Some(&b"ns"[..]), b"msg4");
        let extra_partial = partial_sign_message::<V>(signer, extra_message.0, extra_message.1);
        let mut partials_more = partials.clone();
        partials_more.push(extra_partial);
        assert!(matches!(
            partial_verify_multiple_messages::<V, _, _>(
                &public,
                signer.index,
                &messages,
                &partials_more
            ),
            Err(Error::InvalidSignature)
        ));

        // Failure with signatures from different public_keys
        let signer2 = &shares[1];
        let partial2 = partial_sign_message::<V>(signer2, messages[0].0, messages[0].1);
        let mut partials_mixed_public_keys = partials.clone();
        partials_mixed_public_keys[0] = partial2;
        assert!(matches!(
            partial_verify_multiple_messages::<V, _, _>(
                &public,
                signer.index,
                &messages,
                &partials_mixed_public_keys
            ),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn test_partial_verify_multiple_messages() {
        partial_verify_multiple_messages_correct::<MinPk>();
        partial_verify_multiple_messages_correct::<MinSig>();
    }

    fn threshold_signature_recover_with_weights_correct<V: Variant>() {
        let mut rng = StdRng::seed_from_u64(3333);
        let (n, t) = (6, quorum(6));
        let (group_poly, shares) = generate_shares::<_, V>(&mut rng, None, n, t);

        // Produce partial signatures for the first `t` shares.
        let partials: Vec<_> = shares
            .iter()
            .take(t as usize)
            .map(|s| partial_sign_message::<V>(s, None, b"payload"))
            .collect();

        // Compute barycentric weights once.
        let indices = partials.iter().map(|e| e.index).collect::<Vec<_>>();
        let weights = compute_weights(indices).unwrap();

        // Path-1: generic recover
        let sig1 = threshold_signature_recover::<V, _>(t, &partials).unwrap();

        // Path-2: recover with *pre-computed* weights
        let sig2 = threshold_signature_recover_with_weights::<V, _>(&weights, &partials).unwrap();

        assert_eq!(sig1, sig2);

        // Verify with the aggregated public key.
        let pk = poly::public::<V>(&group_poly);
        verify_message::<V>(pk, None, b"payload", &sig1).unwrap();
    }

    #[test]
    fn test_threshold_signature_recover_with_weights() {
        threshold_signature_recover_with_weights_correct::<MinPk>();
        threshold_signature_recover_with_weights_correct::<MinSig>();
    }

    fn threshold_signature_recover_multiple<V: Variant>() {
        let mut rng = StdRng::seed_from_u64(3333);
        let (n, t) = (6, quorum(6));
        let (group_poly, shares) = generate_shares::<_, V>(&mut rng, None, n, t);

        // Produce partial signatures for the first `t` shares.
        let partials_1: Vec<_> = shares
            .iter()
            .take(t as usize)
            .map(|s| partial_sign_message::<V>(s, None, b"payload1"))
            .collect();
        let partials_2: Vec<_> = shares
            .iter()
            .take(t as usize)
            .map(|s| partial_sign_message::<V>(s, None, b"payload2"))
            .collect();

        // Recover signatures
        let (sig_1, sig_2) =
            threshold_signature_recover_pair::<V, _>(t, &partials_1, &partials_2).unwrap();

        // Verify with the aggregated public key.
        let pk = poly::public::<V>(&group_poly);
        verify_message::<V>(pk, None, b"payload1", &sig_1).unwrap();
        verify_message::<V>(pk, None, b"payload2", &sig_2).unwrap();
    }

    #[test]
    fn test_threshold_signature_recover_multiple() {
        threshold_signature_recover_multiple::<MinPk>();
        threshold_signature_recover_multiple::<MinSig>();
    }

    fn msm_interpolate_vs_poly_recover<V: Variant>() {
        let mut rng = StdRng::seed_from_u64(4242);
        let degree = 5;
        let threshold = degree + 1;
        let poly_scalar = poly::new_from(degree, &mut rng);

        // Commit to Signature group
        let poly_g1 = Poly::<V::Signature>::commit(poly_scalar);

        // Generate evaluations (enough to meet threshold)
        let evals: Vec<_> = (0..threshold).map(|i| poly_g1.evaluate(i)).collect();
        let eval_refs: Vec<_> = evals.iter().collect(); // Get references

        // Compute weights
        let indices: Vec<u32> = eval_refs.iter().map(|e| e.index).collect();
        let weights = poly::compute_weights(indices).expect("Failed to compute weights");

        // Calculate using original polynomial recovery (naive interpolation)
        let expected_result =
            poly::Signature::<V>::recover_with_weights(&weights, eval_refs.clone())
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
    fn test_msm_interpolate_vs_poly_recover() {
        msm_interpolate_vs_poly_recover::<MinPk>();
        msm_interpolate_vs_poly_recover::<MinSig>();
    }

    fn msm_interpolate_invalid_index<V: Variant>() {
        let mut rng = StdRng::seed_from_u64(5555);
        let degree = 2;
        let threshold = degree + 1;
        let poly_scalar = poly::new_from(degree, &mut rng);
        let poly_g2 = Poly::<V::Public>::commit(poly_scalar);

        // Generate threshold evaluations
        let evals: Vec<_> = (0..threshold).map(|i| poly_g2.evaluate(i)).collect();
        let eval_refs: Vec<_> = evals.iter().collect();

        // Compute weights for *different* indices
        let wrong_indices: Vec<u32> = (threshold..threshold * 2).collect();
        let weights = poly::compute_weights(wrong_indices).expect("Failed to compute weights");

        // Try to interpolate with mismatched weights/evals
        let result = msm_interpolate::<V::Public, _>(&weights, eval_refs);

        // Expect InvalidIndex error
        assert!(
            matches!(result, Err(Error::InvalidIndex)),
            "Expected InvalidIndex error for mismatched weights"
        );
    }

    #[test]
    fn test_msm_interpolate_invalid_index() {
        msm_interpolate_invalid_index::<MinPk>();
        msm_interpolate_invalid_index::<MinSig>();
    }

    fn msm_interpolate_empty<V: Variant>() {
        let weights: BTreeMap<u32, Weight> = BTreeMap::new();
        let evals: Vec<Eval<V::Public>> = Vec::new();
        let eval_refs: Vec<&Eval<V::Public>> = evals.iter().collect();

        // Interpolate with empty inputs
        let result = msm_interpolate(&weights, eval_refs).expect("msm_interpolate failed on empty");

        // Expect identity element
        assert_eq!(
            result,
            V::Public::zero(),
            "Expected G2 identity for empty interpolation"
        );
    }

    #[test]
    fn test_msm_interpolate_empty() {
        msm_interpolate_empty::<MinPk>();
        msm_interpolate_empty::<MinSig>();
    }

    fn partial_aggregate_signature_correct<V: Variant>() {
        let (n, t) = (5, 4);
        let mut rng = StdRng::seed_from_u64(0);

        // Create the private key polynomial and evaluate it at `n`
        // points to generate the shares.
        //
        // If receiving a share from an untrusted party, the recipient
        // should verify the share is on the public polynomial.
        let (group, shares) = generate_shares::<_, V>(&mut rng, None, n, t);

        // Generate the partial signatures
        let namespace = Some(&b"test"[..]);
        let msg = b"hello";
        let partials = shares
            .iter()
            .map(|s| partial_sign_message::<V>(s, namespace, msg))
            .collect::<Vec<_>>();

        // Each partial sig can be partially verified against the public polynomial
        partials.iter().for_each(|partial| {
            partial_verify_message::<V>(&group, namespace, msg, partial).unwrap();
        });

        // Generate and verify the threshold sig
        let threshold_sig = threshold_signature_recover::<V, _>(t, &partials).unwrap();
        let threshold_pub = poly::public::<V>(&group);
        verify_message::<V>(threshold_pub, namespace, msg, &threshold_sig).unwrap();
    }

    #[test]
    fn test_partial_aggregate_signature_correct() {
        partial_aggregate_signature_correct::<MinPk>();
        partial_aggregate_signature_correct::<MinSig>();
    }

    fn partial_aggregate_signature_bad_namespace<V: Variant>() {
        let (n, t) = (5, 4);
        let mut rng = StdRng::seed_from_u64(0);

        // Create the private key polynomial and evaluate it at `n`
        // points to generate the shares.
        //
        // If receiving a share from an untrusted party, the recipient
        // should verify the share is on the public polynomial.
        let (group, shares) = generate_shares::<_, V>(&mut rng, None, n, t);

        // Generate the partial signatures
        let namespace = Some(&b"test"[..]);
        let msg = b"hello";
        let partials = shares
            .iter()
            .map(|s| partial_sign_message::<V>(s, namespace, msg))
            .collect::<Vec<_>>();

        // Each partial sig can be partially verified against the public polynomial
        let namespace = Some(&b"bad"[..]);
        partials.iter().for_each(|partial| {
            assert!(matches!(
                partial_verify_message::<V>(&group, namespace, msg, partial).unwrap_err(),
                Error::InvalidSignature
            ));
        });

        // Generate and verify the threshold sig
        let threshold_sig = threshold_signature_recover::<V, _>(t, &partials).unwrap();
        let threshold_pub = poly::public::<V>(&group);
        assert!(matches!(
            verify_message::<V>(threshold_pub, namespace, msg, &threshold_sig).unwrap_err(),
            Error::InvalidSignature
        ));
    }

    #[test]
    fn test_partial_aggregate_signature_bad_namespace() {
        partial_aggregate_signature_bad_namespace::<MinPk>();
        partial_aggregate_signature_bad_namespace::<MinSig>();
    }

    fn partial_aggregate_signature_insufficient<V: Variant>() {
        let (n, t) = (5, 4);
        let mut rng = StdRng::seed_from_u64(0);

        // Create the private key polynomial and evaluate it at `n`
        // points to generate the shares
        let (group, shares) = generate_shares::<_, V>(&mut rng, None, n, t);

        // Only take t-1 shares
        let shares = shares.into_iter().take(t as usize - 1).collect::<Vec<_>>();

        // Generate the partial signatures
        let namespace = Some(&b"test"[..]);
        let msg = b"hello";
        let partials = shares
            .iter()
            .map(|s| partial_sign_message::<V>(s, namespace, msg))
            .collect::<Vec<_>>();

        // Each partial sig can be partially verified against the public polynomial
        partials.iter().for_each(|partial| {
            partial_verify_message::<V>(&group, namespace, msg, partial).unwrap();
        });

        // Generate the threshold sig
        assert!(matches!(
            threshold_signature_recover::<V, _>(t, &partials).unwrap_err(),
            Error::NotEnoughPartialSignatures(4, 3)
        ));
    }

    #[test]
    fn test_partial_aggregate_signature_insufficient() {
        partial_aggregate_signature_insufficient::<MinPk>();
        partial_aggregate_signature_insufficient::<MinSig>();
    }

    fn partial_aggregate_signature_bad_share<V: Variant>() {
        let (n, t) = (5, 4);
        let mut rng = StdRng::seed_from_u64(0);

        // Create the private key polynomial and evaluate it at `n`
        // points to generate the shares
        let (group, mut shares) = generate_shares::<_, V>(&mut rng, None, n, t);

        // Corrupt a share
        let share = shares.get_mut(3).unwrap();
        share.private = Private::from_rand(&mut rand::thread_rng());

        // Generate the partial signatures
        let namespace = Some(&b"test"[..]);
        let msg = b"hello";
        let partials = shares
            .iter()
            .map(|s| partial_sign_message::<V>(s, namespace, msg))
            .collect::<Vec<_>>();

        // Each partial sig can be partially verified against the public polynomial
        partials.iter().for_each(|partial| {
            partial_verify_message::<V>(&group, namespace, msg, partial).unwrap();
        });

        // Generate and verify the threshold sig
        let threshold_sig = threshold_signature_recover::<V, _>(t, &partials).unwrap();
        let threshold_pub = poly::public::<V>(&group);
        verify_message::<V>(threshold_pub, namespace, msg, &threshold_sig).unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn test_partial_aggregate_signature_bad_share() {
        partial_aggregate_signature_bad_share::<MinPk>();
        partial_aggregate_signature_bad_share::<MinSig>();
    }

    #[test]
    fn test_partial_verify_multiple_public_keys() {
        let mut rng = StdRng::seed_from_u64(0);
        let (n, t) = (5, 4);
        let (public, shares) = generate_shares::<_, MinSig>(&mut rng, None, n, t);
        let namespace = Some(&b"test"[..]);
        let msg = b"hello";

        // Generate partial signatures
        let partials: Vec<_> = shares
            .iter()
            .map(|s| partial_sign_message::<MinSig>(s, namespace, msg))
            .collect();

        // Verify all signatures
        partial_verify_multiple_public_keys::<MinSig, _>(&public, namespace, msg, &partials)
            .expect("all signatures should be valid");
        let polynomial = evaluate_all::<MinSig>(&public, n);
        partial_verify_multiple_public_keys_precomputed::<MinSig, _>(
            &polynomial,
            namespace,
            msg,
            &partials,
        )
        .expect("all signatures should be valid");
    }

    #[test]
    fn test_partial_verify_multiple_public_keys_one_invalid() {
        let mut rng = StdRng::seed_from_u64(0);
        let (n, t) = (5, 4);
        let (public, mut shares) = generate_shares::<_, MinSig>(&mut rng, None, n, t);
        let namespace = Some(&b"test"[..]);
        let msg = b"hello";

        // Corrupt the second share's private key
        let corrupted_index = 1;
        shares[corrupted_index].private = Private::from_rand(&mut rng);

        // Generate partial signatures
        let partials: Vec<_> = shares
            .iter()
            .map(|s| partial_sign_message::<MinSig>(s, namespace, msg))
            .collect();

        // Attempt verification and expect failure with bisection identifying the invalid signature
        let result_1 =
            partial_verify_multiple_public_keys::<MinSig, _>(&public, namespace, msg, &partials);
        let polynomial = evaluate_all::<MinSig>(&public, n);
        let result_2 = partial_verify_multiple_public_keys_precomputed::<MinSig, _>(
            &polynomial,
            namespace,
            msg,
            &partials,
        );
        for result in [result_1, result_2] {
            match result {
                Err(invalid_sigs) => {
                    assert_eq!(
                        invalid_sigs.len(),
                        1,
                        "Exactly one signature should be invalid"
                    );
                    assert_eq!(
                        invalid_sigs[0].index, corrupted_index as u32,
                        "The invalid signature should match the corrupted share's index"
                    );
                }
                _ => panic!("Expected an error with invalid signatures"),
            }
        }
    }

    #[test]
    fn test_partial_verify_multiple_public_keys_many_invalid() {
        let mut rng = StdRng::seed_from_u64(0);
        let (n, t) = (6, 5);
        let (public, mut shares) = generate_shares::<_, MinSig>(&mut rng, None, n, t);
        let namespace = Some(&b"test"[..]);
        let msg = b"hello";

        // Corrupt shares at indices 1 and 3
        let corrupted_indices = vec![1, 3];
        for &idx in &corrupted_indices {
            shares[idx].private = Private::from_rand(&mut rng);
        }

        // Generate partial signatures
        let partials: Vec<_> = shares
            .iter()
            .map(|s| partial_sign_message::<MinSig>(s, namespace, msg))
            .collect();

        // Attempt verification and expect failure with bisection identifying invalid signatures
        let result_1 =
            partial_verify_multiple_public_keys::<MinSig, _>(&public, namespace, msg, &partials);
        let polynomial = evaluate_all::<MinSig>(&public, n);
        let result_2 = partial_verify_multiple_public_keys_precomputed::<MinSig, _>(
            &polynomial,
            namespace,
            msg,
            &partials,
        );
        for result in [result_1, result_2] {
            match result {
                Err(invalid_sigs) => {
                    assert_eq!(
                        invalid_sigs.len(),
                        corrupted_indices.len(),
                        "Number of invalid signatures should match number of corrupted shares"
                    );
                    let invalid_indices: Vec<u32> =
                        invalid_sigs.iter().map(|sig| sig.index).collect();
                    let expected_indices: Vec<u32> =
                        corrupted_indices.iter().map(|&i| i as u32).collect();
                    assert_eq!(
                        invalid_indices, expected_indices,
                        "Invalid signature indices should match corrupted share indices"
                    );
                }
                _ => panic!("Expected an error with invalid signatures"),
            }
        }
    }

    #[test]
    fn test_partial_verify_multiple_public_keys_precomputed_out_of_range() {
        let mut rng = StdRng::seed_from_u64(0);
        let (n, t) = (5, 4);
        let (public, shares) = generate_shares::<_, MinSig>(&mut rng, None, n, t);
        let namespace = Some(&b"test"[..]);
        let msg = b"hello";

        // Generate partial signatures
        let mut partials: Vec<_> = shares
            .iter()
            .map(|s| partial_sign_message::<MinSig>(s, namespace, msg))
            .collect();

        // Corrupt partial signature index
        partials[0].index = 100;

        // Attempt verification and expect failure with bisection identifying the invalid signature
        let polynomial = evaluate_all::<MinSig>(&public, n);
        let result = partial_verify_multiple_public_keys_precomputed::<MinSig, _>(
            &polynomial,
            namespace,
            msg,
            &partials,
        );
        match result {
            Err(invalid_sigs) => {
                assert_eq!(
                    invalid_sigs.len(),
                    1,
                    "Exactly one signature should be invalid"
                );
                assert_eq!(
                    invalid_sigs[0].index, 100,
                    "The invalid signature should match the corrupted index"
                );
            }
            _ => panic!("Expected an error with invalid signatures"),
        }
    }

    #[test]
    fn test_partial_verify_multiple_public_keys_single() {
        let mut rng = StdRng::seed_from_u64(0);
        let (public, shares) = generate_shares::<_, MinSig>(&mut rng, None, 1, 1);
        let namespace = Some(&b"test"[..]);
        let msg = b"hello";

        let partials: Vec<_> = shares
            .iter()
            .map(|s| partial_sign_message::<MinSig>(s, namespace, msg))
            .collect();

        partial_verify_multiple_public_keys::<MinSig, _>(&public, namespace, msg, &partials)
            .expect("signature should be valid");
        let polynomial = evaluate_all::<MinSig>(&public, 1);
        partial_verify_multiple_public_keys_precomputed::<MinSig, _>(
            &polynomial,
            namespace,
            msg,
            &partials,
        )
        .expect("signature should be valid");
    }

    #[test]
    fn test_partial_verify_multiple_public_keys_single_invalid() {
        let mut rng = StdRng::seed_from_u64(0);
        let (public, mut shares) = generate_shares::<_, MinSig>(&mut rng, None, 1, 1);
        let namespace = Some(&b"test"[..]);
        let msg = b"hello";

        shares[0].private = Private::from_rand(&mut rng);

        let partials: Vec<_> = shares
            .iter()
            .map(|s| partial_sign_message::<MinSig>(s, namespace, msg))
            .collect();

        let result1 =
            partial_verify_multiple_public_keys::<MinSig, _>(&public, namespace, msg, &partials);
        let polynomial = evaluate_all::<MinSig>(&public, 1);
        let result2 = partial_verify_multiple_public_keys_precomputed::<MinSig, _>(
            &polynomial,
            namespace,
            msg,
            &partials,
        );
        for result in [result1, result2] {
            match result {
                Err(invalid_sigs) => {
                    assert_eq!(invalid_sigs.len(), 1);
                    assert_eq!(invalid_sigs[0].index, 0);
                }
                _ => panic!("Expected an error with invalid signatures"),
            }
        }
    }

    #[test]
    fn test_partial_verify_multiple_public_keys_last_invalid() {
        let mut rng = StdRng::seed_from_u64(0);
        let (n, t) = (5, 4);
        let (public, mut shares) = generate_shares::<_, MinSig>(&mut rng, None, n, t);
        let namespace = Some(&b"test"[..]);
        let msg = b"hello";

        let corrupted_index = n - 1;
        shares[corrupted_index as usize].private = Private::from_rand(&mut rng);

        let partials: Vec<_> = shares
            .iter()
            .map(|s| partial_sign_message::<MinSig>(s, namespace, msg))
            .collect();

        let result1 =
            partial_verify_multiple_public_keys::<MinSig, _>(&public, namespace, msg, &partials);
        let polynomial = evaluate_all::<MinSig>(&public, n);
        let result2 = partial_verify_multiple_public_keys_precomputed::<MinSig, _>(
            &polynomial,
            namespace,
            msg,
            &partials,
        );

        for result in [result1, result2] {
            match result {
                Err(invalid_sigs) => {
                    assert_eq!(invalid_sigs.len(), 1);
                    assert_eq!(invalid_sigs[0].index, corrupted_index);
                }
                _ => panic!("Expected an error with invalid signatures"),
            }
        }
    }

    // Source: https://github.com/paulmillr/noble-curves/blob/bee1ffe0000095f95b982a969d06baaa3dd8ce73/test/bls12-381/bls12-381-g1-test-vectors.txt
    //
    // The test vectors are in the format: `<private>:<message>:<signature>`.
    const MIN_SIG_TESTS: &str = "25d8cef413ba263e8d5732d3fca51fd369db74712655a5fd7b0b3a58d8095be8::800134e27aacc74dc91153a6bd65f96a5f8c8365c722da2f1e12eb048e0aed6987fa4168a51241ce41434fd05fd4bdd9
611810ebd8f5a7faad47b2249f9d13be0506131db987b6948f1ca3194fa6b643:68:94250c0cc62ae9041c6f6e5042202b3c327991ce4b2841a4145d270f6c8311bc95673c826ada72a6d69e92a833d649e6
419bb1de76e11a476f8d5cc5d85a648ec04f24bf75f6cf1f3fae43e57bf9a491:c8d0:898f660c5b26e8c9461ab3f42eb394465d5a115702c05d2a2bc761a8873ac0f33d21f9ea9cf4c435cd31391f5c8c0a91
0d1bd9077705325666408124339dca98c0c842b35a90bc3cea8e0c36f2d35583:c43623:94f60dc44a4dbb2505befe346c0c143190fc877ded5e877418f0f890b8ae357a40e8fcc189139aaa509d2b6500f623a5
50ff7bd9b21916e55debbd0757e945386b6159ef481d9d774ee67d9b07d0e4ed:7e846556:8d8d9e84012c9c0958018202fe944b4517b618cb7df0b61b1f1ce40b43c2da6330ee0c30a37ac6c7ba0f16aeaa5b99db
29a8af03f8c73c64e14807cdabae877cb0f273169bc5ebf17f3e4ef334690656:ce8e5953d7:b37528df8825b94349cfe90a8c8665915cc49e6c41d78e28f8f1a05c5956ee9af850b82e9be756f024e396fd85d9b1ca
732fbcaef0e216eae6420eff93c68e3547267b69ca48c7ae9d79d481a466fab9:ae9eb5f425ee:b0adf372fe871a5f7efd30ba8f4ea563460a14651b903789324b78fe12c06b23569766c2d7eecdfb734de4485fee2436
4a8135a8847019dad5c1f1b609b50ee72bf5e6459f9c4206ce43de04c2a7103a:01a6d7836c68ad:914a38d1fa13ffdff56cbadd1bd77a3108aae19f76ff2a99d18784cf5c7620d44543045d757f61bdd4fa66780b25eb46
0681339753344b5a346aeec93a9b3b9d1282d620a3cdfc4fb4f0e7a075a99fa0:c335129a7fa17398:a01d6f24c038ebc110d742babcc9dd0a32eb518e1e52fac73a3e0a3395012e708112e86a314649aa1edf90dc51007042
67a4cad01442be6649e8f3de5b14d126baee62c7525ac61e0b2fe3387e7681b5:bb8a6f6e15fce1f262:82aa70654ca48c6ef55ce3edc88ee77922e1064c763aa50fb0d4a2e8b206d4e14ed849b4d175b096481a6afac232c588
1e36e3af518a276dedb69eb0e9df882721116cdb336f692eb691a6d2c7f2ec15:5fbb696cc48ea826a789:8a8f9a764916f3fd5b6cc882f9869ebd1d6a24a057a6e436509c916a9a1e9308e5f891e8e49f39afa0e9afbd3d209cb5
5984b05cfa8100d150b3a9a0a0c1e2be149a09e2ff6218b0648651f82b4e773e:5d1bf1b69e2774fdb03500:91703b32c962a8bda991561258c29cb726fea6300742cfe37ed929f68087638169750a423b5c4b465f5498b64ec660ce
4d84a172794eeeda6217cf4d10fa36f1b21103742926d4948845a8a0e417d13f:8ec1a5032dfff9289fffefaa:92142c1955d234c700373b823ab4b4b308897218096a88ea504267b26c9330b939191c72e770aaed0af3281b418af173
4de6bd9f522e6edf20d0e54cc17cc22f558f115b58478ae6155291e67c28e096:3a5e5a964d6acedcae7b23189a:838d07c7d28c62b1e5aadf8c621c4f360407b3124ac7f7ae3a40a56b1b848b8104f59b4d74e278639e35f4ffa64a3767
64fe9caf26b773198b6700a23c2618d36c7382440339a60236e210fc7f61ade3:8873768b317b84b32fca283a4082:b9fb8bc5cfda68938437c17e9f5cb448ca4bb79be278d8f1eac42b9f9b03039673c3170af211c24d7006d1af522f805e
2b5bf5af15c13c167173ac0b4750a27cd36ebb90cb0ee90d6168fc81eea0c30a:0a93cd89817651705b4fd414054a44:a2216d350329553d3adc81d0d79d000c0edf634443dafe7c292e8f7193d09facf7a6361e02e5df957021429ae306d879
507bf8c00a3364d9f297b3df5f523fc786806b3fc60123d8b231831af5dabce5:691cec082f50711675043ed04233437d:aabdfee018464bba85027210a8a8322f9de64b452d296f31bc8c507c05289b70e8642fb2b6aaa33759d857ece7735231
46b4cd59574a6c1f845d2a57d41c42096db5d53ffc9ec8d4b080c1542e24f30b:9a877c2bef8fd2ef71b2852e35afde4912:88eaa4631bb68b510601e6b099376adfe05c1eed52757611897935974d82bcc2751036723bcbfaf29c7f8c09bfd93b1f
3e04f740b39a8792e414144a3cb0c8816350f5c4744cf6569f258fc9df82a7d9:e5781adf4d2c0501969d2669619934145ffe:92989055e334649063b2242af5890a445a3d9f5fedcc127318da402d3c68f0ef658d0dc0074579218e02e31cb5ece4f2
5ff00a071e807e2beee582b790e4f37ea23211273008e37ca683b34632546b90:75659a273db98e3b14cd464cdfb217823f0496:9721a974cdd68946477db08a4221db9b9c2ca07c01b1daf7307ffcaa16603ee9f12e0ea5e446af292bde7b21f5eb4d3d
59c6a3ac6fef4c048486c141825a539e5b65ecc5f0a4425c4aa1015735928f0b:d26e8b19e6065dbdf5a7a50954fcf52e046e4a79:8be8f6ec5b39a43b6d24967009b0444a4c30ad57f285ad737b632a963aa3e9511f6e6ef27a502071bea00c4b653fe01d
053840cde56e2fab07d92aad4ca4126db0c79b582ae5b6074336f10faa1ce27d:18277161538b41f2116b62f1b4f15f763db71bc95a:a0350c66b6c72e8e745ecacd973aca076c110b218e0275b34976e7e23a3c834b260256227dbd8902e8454bb1d620e92c
4dae7ee2946935ab3799f54a67f7f3a1ede349786ac2169c0d4b66bee8659c88:ff0bc27c426ba610feb7b8d7262d27314884f9e98438:b6b4f053da80dc91f5311b1ff12c3de305b0dca42a84818d600644a2e9955afd4f68f61415ba5e4f6684e33da0fc8071
2b36bee50f49a23bf9a01d51e5b67acd8dcca3efb310708a742d93e1cb7089ef:5d9bb535996b1a0158f988ad523cdaeb934a69b043b84a:ad4ffad27a2d8e375549a7cdbfea761712f5b422fbc6d619a2de7b985f4c401b524905adb067bf40e1f1cda75a99edbf
364aa3c72c66b518e1bb9f28febcfa56f29ca5825fc8f1bb60792703124a7638:cbe2e518132f31a040fdde8e4665130d05aa7ff233d12bc6:902dca0a36d551de11ad849888e93d91023493c6a87ebe242ffba54e299747f8a122d015135a70a2473dd83f401d88bc
49a257e61ae16bf1f02cd6e81333ec3dc3b509843a56267ed0d40191c44a823b:df0079e080bbe83a8c3255fbdd26bf143c174ddcf80c969e4b:a3b5027454751a60c5a1204e8b25fe88c278ae2f29449e77c91766feb55ad81c978562e60c00084ff8244b1d8c02a2cd
4f7443821af744a272e3fae9ac7350d6344d61d47bdecd23587f794cfe29758a:e8be2bbfa55b3767413a37778a1940104c4a941e018daca7e3b8:963af9ffa575e398bbbba35e68e8a99d8ba77c870f98a6dfe5b48a283a61ccb19071121398669418f2ebbfa910782f29
22144d627be8fdea6127df0dcc8b17a141a41b44041548bd367840e372c8de90:a4c9b9b49bf2267674fd979e1eecce161cf13b5042d4ad769b45ad:86eeca7b5d03763d96bece0a865e315d260db6b6d728519bad150ef1d086bd78848994ed769da6f8ecf5ef99550588d0
25682a90cf7d1672adc57afe312e0695039d130dc2fa052174d1754dd6bf6f2c:939f9bcd0063da5bba708f16520a7ded65857ac4824e79ab1d6acc8d:a9b56b5df672c163219eb68807c39911bfdd00a6d413f6f1ee75da967017b2ef9ab99528345ed9af70bccc30b49b424d
6f4dc51d61fc10750a53a448b0177ab4ddd4727bc3690031615ef5f3ee9a37fd:b64ca223bac328283a133a74cf95ae4b14d6d68784115dba9af1a14e55:b7c5f00708da137f5e8e90b13cf9b41305173f1a616a31f69b37b89d2832d0956e1e6da88838969ce67d90f49c5d4f2e
5ca692a6163c55c4945758e4640c46ff0ca34fb870cdee9e067a22b0c0bdabed:bcff7f9acc78a02edb0e163769d6bc4e3a97e9bd3677b98a68d82c6d3b90:93d2e2d57cfe2502ac87207653bad819fe1c13cb321dc34ac074aaf647f3b1637d00f99a3ff0cb527465d45f6be31809
2b617ae10e1dc16e41fae911b14e9c150196912a4e89e20981ebcf472b4dd5dc:fc4d92a56983fc61b38b9a8b10abf5f2e914100ce449d4ff8e0ad586e7314d:864b93049434dd8c32b29c8c164b9ce286772da4e61be06b009c4fdba74f9915545cfe005602cabf6b9dfe76e084f0b6
3d12a889a4c1cb6066919f7b97086faecaa640580c43a9df4b8263160177a94f:3f0660a2f3dbc7e532fb7961b7cd00e4b95f5a44702e6e19a04321bbd4fedc02:93070b7ff8f81c45cefa10209107e37d567ae22aa92a45ba1e7a922eab7c58f5c7ef7a77881c8be9de29fad6a3ba3081
012d893034dbeb4cd2f4a7e7afa16e885e7139ffb2770f4d508ce187ebd01e1a:ae6c892504739f742ca90a2d94b84e1092e63288f220a5a75829ea83c49cacd031:a910f08de82e243ae5feeac46648d19f51b10046959bed0a887b7a2e2e4d9c5c0791c6ee9769c81a85efdcbf51c408d0
417e34572c751f1f4cddb3fa89f48640d9471e857e2424a701aa8d7283ba72d1:0f942d30f2b1090003d0faa02a8b1f4fc14500e93ef0df241d0996c7e4711ccac3a8:a3c9cf0e9e9cffdf97ef6fd8c57c60fbf5175d01b6943923eee9c12861d059bcef315c40791e8952861fe3c04f65c203
2a4bc53e3c5dd8d2c46ce784b52db7a66b1509a80103329364b78c5243e3b52a:f387978fe8bb746d7500f470ebb28bcad43501780fad6a8dc116052f93831a205b4116:abcbc4a6f49ef189dab4205790c23c0053474d9a1b02bce3979017137566d21eb2b5ce05b7f9bce8be73654ef582349d
231fd161a30aae15d7069ea9e81e06bd8a43c483468f8095cfb4b255128df5ec:dd1e2f364fcb24ad18349e07d6f74353cbd48def87b6a8a7147f3d0a461882a61a9fc77d:b9328c61b63b045372ec8fec0541cc70eada8d99414934a385680d5d3c98dd1aae317cd030c7372c1150c117a405335b
0e6dc865b8ceacd9e9e1edf3e146a00de60c08aab08dde3cb200fefc24e41eb0:b19a008107d7d89d804ad8a6cae7c039e3d003fd40b93adc746fbee76af5bbf299076482c1:8ac945e4ce9bcbd1042df2d4f29574fedcdca79d25d2358de9acf2ef860c0fc0e528d13c311e6119b73024bfbdd1ff36
41c6a0777609d976880906dcfeee73104a93f8527a23c78d5d7f7917401183db:47766621f49ec5c8235c30275ae2a92a615435d29f6bae651bdc90082a6738741e76ce43a3d2:ad5e2a36345fe3e3f6781e8936dafbd6ca0b0371ea59ba1ecb7091a6c40ede7547a82fc8a28b13bdb06a948446542e4d
6e6f8e2f4652e14aaa4ef111d7fc8be7ac4d8ada4d051caa52465a4345181990:8a266363f67331b303b5c4594e222a343ae7f5512d94a6df766d3212d1ad4ec2ddd88e62d88c51:a9c21fb52afa29e1c4a8f993e0cf6327023a1fe00db739bb915d9ab3e3238205bda9bc8b6be2f9f87cc29ff69bff9233
256a2028788ae24683db9af7d8d976782cfa323ceaf5db0e62272c222c83d331:23204fef64b612a246c470551a58b7e3c4b8ae558edd55c118001ba74ce4c11d22831683f597169e:a382ec60cea2596f472b8805b0271a0978a125c680d523a1f2d4291fffb01a3aa5d22bfe62ca439573525065fd6ec885
37b73537fcbb0f6b8bff910fcc0116d905f0960a2233a564d4cbe0b4c53f88ab:43ac6d7da7b0a419d6c893e9ccdbf3b891ec5ca9460fd70d9b2fb6dc9bd482c835af88922d74e4ef38:aafcf57e5db3c378a4d37bfa461ed23113bfa95fa9aece77a4569cb836cc86d311800e9425448c5d0d4302fe180810d1
700fb2aa7050df22fede481f8fbc24a937812ddd19dc19404351e2b5c72dc21d:381d1c6c2357c8fa5a07865e5dd0f76f5c4d63d115a49c24a7302d4cd66117683e549be5796ecd16fc56:b4409c7e09d8c79dc2f7a083a23cb02e83ba3c8f4af8ccfca70ad4ce90991333e4ff742fc912afb0de93610c1ec83261
56dbc180d43e8688bece1a617d284f2d3880e570650a3f260e9a3abae32c2c3c:7f62eaa50b2ea4288c03ecbbb42a8178aa1289bd1dcd9bb1664be0b8cf971b023b5e29cf47dbeb779f0098:a3fdcffe61c67de9a482e4fccf42ddb9344c8aa4fc3733ff711750287ae87329a82e235c5f9954a8cc5015ce7877ab9a
30a003ea75cc507f2b0861d68af83522b451976fbf9f71c6be340ab4b96bc0d2:bf5f878d46a8fa3e3a476fd161a86d053cea93675f18c30fbaab758a1f8f5f6818aaa193fc37f3fee0467264:8c223b8239b826c91eae0c24327e016129c3c13e99ef187a2abd9d710c33db5efd6e05aa4547252182050e06921510f0
6c27dc9a7c6291647e61015e9d1f6aa46a38c4f32086b36acb476af525399c0b:1881b2ada37e78f7883d64ff35ad98de04b98d277104534d3d8ae6ef37fe5c584887bf8304ebcbea472bfac050:a6c834443faf4f7d068e48a9a927f15ad5c68c22cb245bbd206ea772493393e6d01b55a31a227643629098ff29b20309
5cbc4de784ef59caa11a1faf1c5919499ca1dedecc92840e19adc121cb2a7aa9:ee42c4b9217735f1d9e32ece935893008d8c4009abd98dffa7c2f8214f26e31467f5ebd125abe9f7b6a62b5789a8:8159b26a583da405b5c5dd4da330d358465268e6f65b82c87683f2bec8521d7eb2dc5e13665cad7ee7f8bdc3a9713657
3a7c8b649c0c3826efd2646d01ba9800690a39a58af824762412403838042cd9:9aac7c53d666ac80d21af3f9422bce65ae0588acb274b6efec9b2ea75e7b12848da9f038449a5f8f8ac453af28fd02:83660e10ea5050381dcc5a8d8354f5322d60ade1758734a700221abf2cf0e2a04cda83b4cc85783476304cb8431907e3
3e5c7d16ffee2ab46e45da4aa41975bc6ece396a8d78bf3d072cbcf7c3d0c687:bf7f6717ac2a33428ad090c12cbc27dcd12a94e143c9eb46aeb11a6c65e7b09d90dd0da5b855ba80620b0ddf48a3843c:83efa6580768eec9514cb4d3c0c22e6a584aea44aee4f7dbf72bff8375668c9ee1935ba5eaae2cda072e5159a0166dbe
67db8b638d15e0f17848dfafa0105f04dc100c6bbbb8ca44cfbd7308497f648e:a4e30c5dfe87cd43153142a023fd297a9d1dde2c996f0cf3253623d5f04b36c46a7a70d815774c99d836cfce29cc876464:8f792b13eed2694c24a97623679c8be7bf325b74ee14a3b7e4b764e4ad402618bc1213ed21b04ee43af0aa0d7117f1a5
0c0a951ad354113eb871b3b9dd9db522d0abdc98f09c6caabe617a22986838a6:ab9226d0a78fc564c1c1a8a961b90cfe029160cd71e5ba95e6adc258f2ed491c36456e639d9dffd53a338cfe3190a8ab7b83:b8c474f01a43a045047ad4d8b6cfb7296ba6660eca20bb1de26fc158bd8c3744abcbb9867781f7f2a04aabff7a498b19
64518ed6d49e33c45c7dbb6b53aa3ae8032be58907f952b7d6d2efcc9b2b1f75:e7c2ac2eab22fae320a9c4aec6fc173668aa9df68d7ab00a75a65da0b121db6283bad06b131282d7045c0ce50a2c9c786c5f88:86625b564b51dca8139c4178453c3376c08a42621de931c9e1abef3f7e23d8c23a23ec617ecce51c241e25dff8949325
1796013211bb13b2f2df46e8e8f430ac043fadfe36b46904ca77fe404bc54b1e:67690484edea6aa1ab2b3a0ceca61fc08eefd1362cd4839827b4e45604911f4f97607d989388f707ffddddf42cfa0c779bf4633b:8e283416d53afb6a1281986686e7f40ee59c2abdbf633e7fd8416f0d7a40e7232ea49630fab5d752b0eddc0849816d70
3c83aed296db0756243f1c33607cae018f02c30eff97384b788817ee98e08281:ee9b7b3741e1594515e755ce40998a535e9f2ed7d382714ba2137329b5d491ae8fd8a56ce7a74058131e98fed9b3282961fd11d7df:a353943c14bf9e8553ff5d1627e121e8c0819e4406f3346b3d2c7d2721b192863d666262ddaabd0bdef1b2606acfa75e
6ab5abc9b803639a1ba34750c7baeb2c0ba315c96dcf70fcfdf634fc1e5b2197:b8b107a526fc51ce96996fa008d806f29052ed82512e73178426e1d694066534b1c7337dc522b0a59dd50cc472700b2642b512d30707:a040803c3d4f0d631b6396e5413d2ee8e5f088bf9272bb6a53789c6c9b41b12d50357b140825483fa7e215499b912439
5f6d5c23ab6996e98a6ed399472d97ceedf551135ed029cf68cab520f6ab2313:37b88c5975d31b1206b769943df826568dca065ff27c17232f5bd04bfd1ed4d01a5f1b0f70a89f3e5dc5af7fc2917594c8ae0cb3908b4b:a6ac886556754f0f99489c7fe92fb1231461afd7f6076584564ba58bd80f4e387d035dd1976e1a815b790d350b2707de
1696edc94cdf62da22c85e36c9a18580408040012de878ab6d10eeff6c51f049:72df71d31b9843d13ccafee2580500fbd486a54ed42ef9db70e074eeaa2a496054ad1782f504f5e2a7e65a42249a589c358dbfb3e307b864:a4d11fa6abad203f8ad0aa6fc98ce40b8e00ee652a0cf3c2bbdb3b3934757db0cdcb9368585633e277af90417c2ce078
1b61072c204850b8ed425526568e9d57f5f9973cea8499b9d3f3e65ee411f7d1:752d9ca07b296305ce8addc54eaaa7e03472aed19626860796c00f3230593e6812dc8114c125a78e7f2c93bb66a8abd3be431b868579cbd193:afa0a0c0472878e0b97d7e4938ee560d4e5d7fb909228fa57567e01394011339adade27d99097e5f663b5aa56f4ed01a
49f8b73e487ea32e90fbfa5967d382f828cb03dea8b6e91420e3835590964bb8:11753040da26b28d466fdd0f88494801f9e2a03b42a671a740bbf7d43e90c38fb383a9fb9992912c171f65c66096de05cfc896e449e18a16e3b9:81ad82f0ca54744103651a5ed1daa464e89ad3fd8c26c4d6a2743f8a58ca3fd4693dd338e09264829f8285494d564eff
3d7a0771e3c698956350570578e3dba2093315388fb1958a32e387bbd33845f5:247362f06c8f20e956031eed27d8f3be62dbe2154dedf195bb1f9539aecb0ae77aae3c71e6fee8acbdbb6ef8d68244ccd9f6b5a32de290a4001ea5:8e806bd7479057360710060b40be772789f6e7bc52e7e781e6c82a3877d485bb017e69078c1c3f9be628a3f09e857e91
3245ff9022c5f0af88741b86344a9dc9473c4dbb28b595711cd4138ca1bffca6:b793d1c58943269274404568a01a756b7b576659334121dfc401963d51bd0de1cf011a6ab6c5d3c8f6a42ea0bc5ee5bed2f70a096c0c05e35356c03f:abb639f7c6d7e6aedf5b2aa0696f5ba1f327668cc1c352a0b5f713e043f5204dc951571d7be952f34a126133d05e8fac
26d1b6697b3189154389abdff3eb2d909fb12a0e8440694b59b8ec5a73c366fb:37ce9416c6e2b8d4944beb6cb3775d296bf0364ea3f6d6ebebde5c36a077d2ace37c8a629d8d8abc8a89cd0e7c1a182b7ce81d7173c3a376615a9515e8:a6c860a4ebf8b54adbca5507a5b8414cb1541283e817777350f2424848d290abf0c980fce31e7d3c93ebe409f4735b50
1e384f2be1cbda26e0ff77699e1cb94b9a4a58a24159f6cf8ad5413547393e07:822f7451153b2281f3f89715f1d2edaa76628deb8913c0c11fd7e6ca6783ffcf19c4f2ceebe002b0fbc63cbe335d6ebe3ee39c5548d60fae6896dbc2eecb:859a858fdf08c16b720d5a25f89f7660fdab3f1e4be76c7f36d8bb95b53add7232e06af5eac2f71ed0e4e85fd69f0edb
0f6c6c95d4d24a72caee5861097970c074842ca0183982006d0d5b9fdcb65513:67ae1492457369dc0b494a5142c0e721613848a76870d369ab53bc4e7599398cb49c89e08b703366bfb964301e09c7b99350283e31616ecf4ae999fbff00e7:ad5378c136d51ca64e4fa7f21aa6732222622b80f30c5dd4ecc572e645a9ee2001a72b43284658d32ef10eb4c1018b95
11fa08cd0740c0c37a7c0269215f272855e378dd0f8d81f45b99033f74b721f2:bd8b3e41b647eba1d285853d9254d1f121b2371d3e38c67f31a9d8a718c7d7898664dcf216355f41ecaff9f73f77c35f625ddd7a7614ac7fc4d1754778f84f58:8b02f921cc83b296ef4cfc6baf0ac306567846012223a4bcd89c532eb5c39c80e35e577b368a67b8fd8e687325350fe6
6f38baf1cee3a83a4a99b403ed5ae143233d5b228c80b9d421f5772c7439b05d:3fb1e8ef6e99240cba6d89e6642e402e18eb3c135e104f18466b95bb90258ac84b3fbf6327fa6cedbced6e942b64d4d636e40b59ed39d92acbdb2933014f6e9b44:8f82cc3207c5880dd276d59ea1b42e194504b8188467587700da208a6459ea00dbdc3dc54ef3105489dd2c71b0f30fef
5e653c12f6483d2fbd963ce05862562ac3843884d961298f7ebf65f05e958d1f:547ddc66f31911b05895c2011da903eb00feb4b1d752ccdd4b862a27ad4b0de4832161bf6b3e132dd0b238902deb0ab8e7edad34fcdfd959032ae311b7e01e40f32f:a12db7e5a27a1a581a5e601d08e907e8ff61cee91a27638e177e048a408a67e2224bf16358c24652e0ea768979c506db
08073f9d18132bece9c3f23225118fd7feeadcc0266c1861231d01990f3d3018:1c028e2d3b3376712b2203d418b705b6d317a03c9c257f104660f007737ff11b3f430182181567625f4afdb6358ee862aeaca19c67b3b253fed777595bd79f4f6b9d26:b2adb57dd304ca200aa95254c790784635235ec3cc418ba0deaf0efcc6232434705b00e29889f4e259e704ac4f353633
691ede2f41856cddd0cb79cc89f5ad5bfa16c62942b660cb01bf5cab13a22d98:a76de84ca3f22c96b2995e2ba8474ee7f8d7f36aba70f46f26375c1f647fa3bdfe05e13c9b18f16b7933b6809d1cbd0fee5f0e1b780cce726a5c414c406f54e090098345:85dcda6d83ef31d423bcfc1d87444a6226ebd57018f4da52ef8d9e7b45c100f9bf36028bc9b0537b4baf240cf11293cc
1a518478b36de27cdb26516d1a96939a515729bca7c51c1f1e240974f3aa73f8:ec6d1b89686f1692c0fb79f6ed782bc1265475764946494aef7ebe64572bbf70e34c72214c276cf9c3c1a1b3b22c01e8a1c1c709dbdd97a199dd854cf7ec23bf564a3d6f16:ae4fd56430e237111e2886d09cd7e5f37f959d32ffae5f87ec51fa2f7bd2faa2c0c81fc60e98bc146f236929def7fc5a
359a75965e374ebe361c795d1d7fdbfe40c5709227289966c65d93ba68372832:bbbbde79882192bb916805775b36b769e652a80332897ce32f4757bede663953b40be828ec62b717ae7d3872b4baacd37bbdd85f3c501c5e11f0c738b6d16fe7a66cbf18704f:8d498db4b54bd914a9be4cf650a988e063f7d016b7a3bdee3ce330d9ab4c978bcac3c2958afec8e67cb1e244fbcb1e05
67dc679b1a67908eed7a36e1b20a557c0c1eabe7eaaae1cf8e4899da020dd8d2:c01d86741a47ca1c78edad008b24246ba9684e5f12d57ff8659b8453c187efedb4a2f697f414a823f72ee805554fecfc48047d465592c6d8425bd9ab7a1135ac370a22478d52df:9520a5b80e5569a2b07b2365ca780dfee80ad21e12a904e9e974f8cf183ae1655f2b95a598f9f80d6b9bc52040f881df
13d5386a288b72437a9279c0caf667533ef11f707ced34362eb6a4570be82b2f:55ce5ac51a3b5da8a128f2e00af927584e8b59694972ee0e6f95e012c308a180e339121050c56a8a900b04fbbe9cddc09c4c3a234d30885da9833b2bef66754015e81b5413d98652:903b042c823a494e6d833dc6f7a0050d4750f80e8b68224712425ff086239b87ea5fbcad5a13f69d7ee7dacfe47e619a
2b7969fbf66336b8928f48f6afd3a161254ac01eb4cf94451fba62d9d475f6f1:f53eaf6b0f992c803b28d2984ac74d9292763b8ee599cc0cfe8f135f89bca18ddf87db85d0914760a55d52aa4412008217f836c8517f8dd7390ff82d47ee6a62a306791d27295761e2:b37da593bc046212fa4d0ef084cf456ca7d3fd165ec863d2e980472c441f597a0aa858bf368aa4f4e77dd4b8ba071e69
65013f0a26a6e628f8c598af20dcfee2b9b5419e393ca6f832cf5d97a6ba34fa:227d5ccd9bbe4b7a586aaefd083b6a674a126ab864f5d90826cf7e67c4dbaacc7994a1879c50ed2752667066dc00006cc3d47ca53bdafcda5d38995c5b66d95b68c142da786339136332:8204f9b1e6227be7c64b5e629e5d75bfa7bfac17b2cde876ed57ace0be3da8c108fed9c189171741f2840302f1756456
1b942e9b54bc8eb2ef0a3deaec60e3c37955a44a3543b9bc0980e16675a1f904:d47e4fe5c7f225d00de4dd5284bb29d2ec57fb8a854596de15669a80e3bb8b1d9b5cb0251f1142f0d5a4b58d2b1090d94799be1d38a7ad65009cd6863ec0e5020850e1b09e5c502a12e23c:b03e1643481f7fd0c98ead4b8185100cb20718c7d4b816aa8b8b3e94987d0c1cb4558860d8e73b198a1655d1138fbf53
19d8a8169d57cc62ba1e4c4d9d22a45d0b2280945b2462f031907cb8bd83bb4a:e3ba46786a411d27a815d8fbac5f44e5cfd6f4ffe799e978d606235fd0ee14d58b68c8fd06845632c0030d1d919c90efbcc42a69b22afb1cf3e503f9a7d8193c8d3c297d7ff25740e483af34:82595dfb2e1380680208ca15077487d563e4c02381d2f4663498ee5798307de8391b2694089fe62c9efd1d2e5cc0b089
1bff7b1d26603e3f6efbeccdf394ed922e7a1c707365496113d3ad6fcc871195:145b190cd7bf22f6c45aab5e7cb87cf37a4098c5ea1b0d8df9837bd776551f4dca8bc6a6a830ceffac56033ca67d6fcf1f31794abc831f9dc83505f0201e52961fb4816ab21974ed05241eda1f:852af6a672913c27a0e240b7246399e4d23089e4ee727d44ac9a0aa3a7b13b100be82abf201edd35e3ce8c4f506ce484
371c2a48d2cd9ae2a13b3dfce09d7fbc9a01b61cf328f096fa87dfeb9e3ac883:785412beb888a53f807e537200ae520df044246aeaf2f86e8d65dc3a30056b57056cc44084fc2762069c49634cdb557cda102d5a7ea8a45bec6813738481b3e5996367d80faad7138791d510ad81:9616060a912f463131d3c0e0c9b5f8e9a40f6cf00b9d6253dd105e77604a687fb2ea7b466ee9421833f3331c25fac1ca
61d7787ebbe947d746063f1599c9313f8df517be1494a38cbb7f196a31ee7cd3:4b797f6782ee555113b5ea4166e2c3a2cbe3359256034745c66e59149b97cfba790bd091aa6f809721d6341acca9673a47f34bcdc08499080e30bb1e81defca019f62c886677577ab289be4981436d:a337aa2a22010cb98c0736df043acf9a01d0de654448f144ccc6e35dc53b5f6cc78583c5a465b282ae8add2005caed30
6a1a038e5c2bfab87ad3cd29b808c8e7a8b12961f7722d62d4ff7fd8936c6eee:2fc8caa666aeb84beb71d7c6918a8456a23c406b1378a6476607e4b27d651c4c9fde2c8682ed6005ca757dce710c4451372efc5886972cfc89f1eb7e19d80648b9869ba74ca305c6f88b464388ae3f72:9876a586403cb4c0f2b56373996ee524a489d4ded44df55b7db74a749ab74795470cc0a66a6e58193730195c5c444e76
3f528ca57a9a03e0e1af999cff2a602d43a8a7fc9774a5b35b91d46ba2332590:5c52e68adbf3a47d0352d333bca88b4559579fe3dc2efe7369fce4c10acea51c4166e8ab22d243741d7e2c2ae49a0ba35f729456f8c37b7bd31e858205a968cc0a6e5afaf2b3964b09619e241b3438c6d7:a2b1e39069444e3b1f14aab6015a6e25543ed0baa4a23ab6b187ac300c54d433580ea036af283a3a25d5421a945409ce
1cb19f5b2b6d2d76b26eefeb36d2995bccb77a0048e886b47552b209253e04d9:e8804b79ae38a9ad21cfd3e6e538b9bce254dc020dd42ebd62d4f282fe5da900b97aa86d40d5cab39516c74c33b769ab3e0a644a63a97c4cf9b59e55dfb42c1df038b1bb4ebec3d344ded09a5f90f4bafca8:8c37c7eec66b0c88268aeb7326e85d30a2e8e851750a74aa95870a7259d20f6fddab8dff3e0d4955ae79ca8e80fb515b
689216f2c9e7a748c94c898640d7f95d57dd0582eb017ce04351c44f10265472:1b9e066095b608967db1d6b93691bcdb4417f6693e6065186fbd8d1ed5267951db49d215328044d35e3555f6e1ac89fee959625b6bcfe510fe63bfd05de60b7e1e9fb5df9e721141c65bcd7a7e3363e1b5b472:8041368450aa99afec459dc86fc883d9b0ddc846e63a826b93bc07cd64e3520cb09ea5efbd049522fd049f0ab55fb61e
0b32a4f24c0c259951660e96457c1e1fa18bb7928c4796dd085dec96a99b0e37:01db4eaaf51d3322aea498726538eac137f248085db057f1faa77fdc8091e331e1d497b4b3276a51a5dc420af871a826c55dbffac511afc9319e9658e68de1ea204808c282e93100a29df7b089ae5551ff2bf95d:9634bb34b8bdb100b233df021f1d99afc8c9c9e8e76a7ff7d3fc62d733ff0819df55e71cfda092f54505a98783f786ea
04633de27fae1f070ff87e490e10528e9b40857b5109175a64543eb0ec6c82b7:85fde85aa169a8e44917086910fb1a9bee9f1b30b2d29e154998c6d659206307b5b66a1a3b1af3603becf751d37605e5b1c110578b2094062ad1e62ebd3bb75121d3569bca60bcb26fef490288da106258b904509f:80db12ebb3064c79d372d4779d4900e10c4bd141f109ecaca9c25cb3e789fa4cfd727ce372b6845c956f206f6a73901b
44dc2ef437107d48be57678f252e523a08bf63dc720da85b8da7486e875740b2:ee998b1edd10ffaf7d3eb7b163842726e33116efc46d77476fe2d3e8bb3b79f44f065e9bab6d1b9a32912744c2b8538ebdb8dc634c58ed19e179a889d7ca53983eda22ca0dfac2e5b6761f5e7a129a950dcfadc27cdb:8c7cc3d5822bc3b6ff0f9be230cf9fe91f5d86caed86bf3ee8679deaaba06b545f1cf87f63fc601a56da381e74b39e3b
5fae658e1beb5ce5aca9025861b991ffe5f0210562e0383a89372c3e9bb01683:391cbe0fbe656e0ca05e1f7ba659d7b931c8c32fc1b4a7477128a3d36fcf2e04e70f930fce6c42d667595b6870da22b29c4b667e08d905f9be6b94d01c5cb6d652b44fab93ec2da57edf40234c2998581fbc6bef11f098:ad2d3e2f04aee369179540b8d78d358ab6f49f03e540b242505eb0e9212d48843e3a4de840cf6534e8e492f4af7468e9
3c47c2af3e6fde7084b94f7125003b4730274dc73da91c3a6436a36a58b2d371:34e74e595a04107b38cffc124b941d3d549cef01e3552a75487ed3f1f23ea31046fe6db758683e6b9f034c5d4c63b6b7e92beabe3b7d599efb98250b4dcca3aa6515456b6b19ba984314260fd115b0e12380a5e68ffbcaa1:b140516e7bf5edf67a20fb360ab2932e7af32f38f669053d9fd9506453e71870ad598251dac0ab34117e4562fc946766
2e8e531b369ccefd7ac3e91b3a5e4dd671db1b2a05863e5b8170ae0dc27840b6:bbb0b60a66dbdc06791effb0aa45b5e4dd40777822a00aa1e52dbd7d0ba9cd30797612fb128c7c7debf3aa24a4967ab032180a527da239f913bc3551050b23b972642156240d2e42265053cf84e5d870fdb7a1c9c6f4c185ae:90d33306d8ccbf0b4c2f439e59d3633118bcda2a2fee59df40f4dbcb15a5b07c3198385a5d635e0eb8abdf005fe68996
4f7f6c0df5d8fb728033a4c7927b121353505ed518112592381faaf17bffe927:c870ba3e0fd1477ef1140246404729dbc4b516e32dc033abaff6149b3ecf4b932243bf9257c26777e1c064b7f3c64bcb3a5fa2e3f0fc7d40bb1b20636d90bd00536de78958c64893fe07a2528f806e2811bddfae9958b241c026:a908968636312fda482872680603307f1f5549e592eb611517e27aa9fac9e9f509356105a5e4fa5013d97613a976ffab
0feea23e93e2bb1c9714af6e8a125b6fb179dcc24b2456e40548061359e83034:b927770e3c3ecaf04844ede61c8f82c5394a636a9b481245f03cdb0b6fc75b5263e65a3dddbeadb8e5699edf04fb6b5cc2aff7af1a2b4c042669a9e3f03c0b564fa378ea9332581b8851a88ddd08f9959e0b9f66333ed081733d19:b9e40340b6f649a87312eb663694e24ddf4e842da1c38e5ed90185a61429487877463a9ce0c091f6a6803daee43d0480
26af207030b1958690b8da361e81044ab71b4ffdfd9a26f853b090d1c3a0da84:84f1728578942b1f41af223ac189c0de40fbf013608711acc97568ca4d5eb3f357ec7f76902a0b59b94d28959a25c832bde18c56ebe2749e684fd7bd1d5cabcc3ff50088271bda5b12f8cc79e53334ae997493fbc0bda2c56e27acdb:8fb67df1fdf9759139547dac10312170a10d0e220cf83e74a321778198f6ba6f93fe2bbd7e64d061392a195e835f97bb
420560ba6da9075a590bff683af1b816c6ed855dbfb89e584cb4904a1c3c18fc:87b7039c154b1ea17e34125afc51b31eb1882d5b0a27f800859c8570f7084d35d9edeeb285aa034bd0de63c85b9f22fc39b6faa69f6d420dad742c0a7828c0e5c16f9dbe93db95c8baab1b20826af7f942872e5e78345b9346a1baf203:a748c3e20476dfde9dd8ae0b1da0be834938d1a3843a93acf1e24a4dbcb808780d0812e78707326f23919f573b529883
23d5808d404b06f00e2e97215d55c84b735c4d0552577d842e0138431f69aa4e:528f09550299e52818e5a3af380374b63615c820ee972f8af249167d38c76ff28ce387f6c8712c6a21e529a048ddce22e794f221f8da9efe720e793624f66b5fde02c12c3fad14324dc7923ca6f44b7c610d5ce51e456c3027a303c71b9d:afe5949e2d7d89387864394b31745b922b4a50f7c08a1f092155007b700efc0c4c0fb3aded7c764b4a89d4638b55e033
2c2d04eeaa29b0383ffcf3607828ac5f39ca1ab6bececaa6fc8d10c1896fae79:564a760045e175bb5bcf5199f0330c9ee8a9178d7b7e2b574b42c4e8f549d63f05729d7559e1dd43431ef6f0e78a05ab1e676d8e9e972aa625feba814c5ac5b6aecbadcfb926c8de16026fb25d66d347813e636c3356208a704520de0a2f0a:9983cc5cbe5a8bcbe56bc1a71b2ca5b4a32923518ac2959aff0949c28af4124658ebb111d8fb390ca2afa50f089a3e75
6ea04b1ac55b80bd9e6f19b34eb635f6f40d65603dc312bd976245aa3a7ec2e9:94ed5fd16860d3062a01b1596040a0d60bc09f9b3c214ead3403109ab805a23210fd385ccfd5a65e80488dd13c1993fb2ec65d1093c8d87095c73a74589abd071bf41a645b0f177f3561165ea3426d29cffcd2315855599bd1dca971a026c906:aa7526a6ba48e05d1be7150815fa8ac4f80a59a08f44b2b7d77c8926e17a058fd6436b5c681ce8dad46351155217b87a
272d038fdbc32dc27d9113e69838acc52d61e764a00dec66b9174d1296734b8f:d58f636770468f71344828aa13c8b5c7dcddfc3c00d13e6480102ce6d4a2e0ef04f834058475ae8674b5536c2f5bf1a253a0fd54a36247abb73d1bac90464c214e871bcf737b269045ac59fd176294cdd0a3ad01391d1fd9f1d44db5ceb36244cf:a53737c41fd01aea3fed126a1ac8dab7d7439df0338ccb90f20f7173f3b210da7b3c091d90cd672e8f38c7b7864a56b1
62a13093e8754c1423e0f7e73218eb645f38cfc64b072bcbf2a0265946574329:113d0efee5cb3e1f678e684ebe613889dedd0a7820e8120926f4979322ef70bcef21cabcbf8a974eda198deaaddeb7ec5d0f9220f1706aca8f1df10340ca8d40025fca3688ccfba6b010b59110fede77cf0c54b6764756551e99d7016a6728b935a0:a6c302484226d30ab4bb5331c138915c34dfc1bb1a634eaa741af2aaf7a389e4945083ea2ae6ff9142f7010b0ff7360e
328b4abd2dfe8702172058f7ac506b1974a5911c4a574e3130950044214c6fbb:821030677bab3b8219adea5fd2fda6987be0422a47acadb76a27792719865f21c433b53fec7cfafb044240918492c7e6da4a1743fe84a472411beaf7e3630862e04c5b53213bcdb7dfe1cde18fff29d049c191f8b72bc8d1fda7a5c57cae62f9c96824:821b0ea7d9ba44a7fe751d380cdad155a44c20959c04c7caa3489983bf25ade2822e53031ebf0ccfc5a76b83ae0344a4
3b23859211b5eab5590185e6ae39a645b35012906f894108586824df61906152:8a25a986cc1df8d66b18a058e697ca2df03abf385ec0c39eabfe89bd340046c298a5a2752a7f555a5fbe3a5cd51b7eed0d950ed2c9c5e3a093590fbdcf3e41496ab510f238019733cc43f3a19f0773bed46d101ef847dcb91260ac36dcc7bb11c405bd8d:aaf17bb51a15ecf27d7aafe6a223eac092f257d5aac5d76b989ecb555251d7989ec56e46e7cbf6f68d478dd37d74b740
40a563397ead8c7bd84fe395aaf3994ee4b0373a8066e5f6ccd8b01a548229fe:38a06d00930a6247ff7c2ab303dc4f88e07d55442597c0b063ba32ab9dcea20748220f88c7354da3a5d21708b7a01491d58280434914ed16cf64f65e83e2bdc000491d719a5aca31f86c3df94559df1ae950a9d64d948a44f468d87909cb1a1db15c8d5e14:953ef1cd533f2986ac1bc2280ebf4e2522521a8f7b8c2689f04c133f1911405b0b6ea46f879ee7153f99f71d888c4b7e
02b22feedeacb437a6c10fd8867c831ff07b370aa287b1d57dbafe34de46ee05:dc59ca5873612bf0e0b0039ac451a3fd6913521bde999bafd87beaf2923802ae09630c05cd07e9d3e8c8bb3497f5a5fa6882d2e6c221470728dce51d96959843e799f02e5a64e1b7d7fb8c9b0ead75e7cc748825be932f735e4b639cacd8d32e0de9242e78ce:96bb0c83dfdfab8b9ecc8b360b3ba2642e285531b4e3ba861ee5169f48d9fa8bd4c84aadbe433ae3e3732eeaff15b9fc
58604274117a63977ca1d67b67fd59ebc9562d603f8ee39a02e2e83c2b115f42:769e80b21c38e39215d69c1f1c485ffee1023950edb5d375cd30a2c0e00890a952336be867909c9a55daa9ccf48b9ab5d874bac77635331d13effcadfe2dc321135fa8922c212b81820e3f49045f001f746321465b91d6a0ed34632cc1529848e7ef9fbf41f7d1:8726065a9813ad3449498ddfd51ac0d35e103d05b491880d51418b2782061e4f034b3034880e49c7dbe1e168226dd150
4d462264104d551ed98c229ee16d4aa4df79bd2fe3151554b0adb12ca48d2753:86863eb1262d36d8e51130f7a9e85229828a35a458cfb810ec97020df5fbfba89568a81bfdcd6014593cc1621da57720c54523720398dd58e006b89747d75e6eeff0d1d7852f79afd83907f7749245e64a5023f14d4ad663a2b41927ae7f77c3572fa2963fe19615:afd58b032b13a3974494f15d2113a7acca322c50ee686c763948b999641e3334f970ec89c6235b65c59edf5f1a63fd84
4d7d222d9de5be19af35cb1a31f556efff92b5afd8e92ddeb0d6820f5cf4103d:8d03abe66a28da061a733753df81c97d5abbdf1d324aba4e4276b43065532f48898dbf7dc7b87cc40cb65d6dc3db0a2a7f084240360dd2485ab44406f1ab90a790d851d49a1cf78cf4dd218b26e16eabbc4f0f7da27d0573dd30032e01134ca7e3c9569eee3b29fcc5:a915963bc69bcca6ac41a68d5587d22042cb44dc9bb58f85448818420126a9438cec846a72ac50da1f1a5bfb9fddd5e2
6f2091abc6dd00690688ae8e0644b30fc8b8f931a716ba6fed186981673f929e:cea5ee44948390d5d5f3fded51538f5fcb2a6f3a79b88d5df17f0de46280acb25ae5a918f58275991598f414f6f9a00bea7c30555057a6c04393ba1c9ad6ac555d450b96fdc8abd0b0f6d280ecb6594e021f776415bddf392e6f96d1f5ea074ce6ef81fbb26d3cdf8fe9:a4254a9388bcec6d88f08da8f18973bc381a3065d4bd3cd8c16468e073970cd6508eb77217a9fe3643dfa471faf374d8
462a706b92aa64cc85b9e376b5d27cd62f970ec3b7edb817e5b7ac6e239a0e0a:73ef7f6ddc19ad065a9000768ceeae6c455a41281fc581ca31ddde892669a7d9cf1428abfe9f32d410103ad8ade80c1c7d44aacdad110ea4011750aa40ddff3f959c13b04228a5d9f4e9b6ca71ed4f4f06b9995a09050620f18751e18dbf22e7b1793990ec8016717e9be2:b6747c6b843526201d6153e545d3d4fc270da6979d8a9ff291e36b41ab43a3c9308215f3ecfb8873a491bae22b5df37b
65237177f0ab7dd39df8c2345e6f56db27159988c7751646bee0dd2cb35f43d5:f473dd71b0fb705be4b377aeb7071bef91dcd49ac24ab5e2a593ef6fbe402b70bb2db06178b3fd6ea7c5a8333e09e721cfea23d63057a363050a0e3afbbe6b7f0def485edb1ad7345cd1cfc52fef5e688a4b9bc205307699fc22fa3fb6cad8ef9fa3eec1c013285417ad256a:913c8c823160436437293495f66e6c91022530e4c9505d25b3cd174a34c4981147d9671f13f84cf85ec78b800d3b07e4
64a1fe88f385b2d200a3dc9a5e985a13a3c351d8af112cccbdee1bb62c780688:8206710e7302d8167d219794244b11c906eac5c1c4478343bdd4e88367e18a863423a0ac012ccc9358e76be56a973b4336c81e4f31b068a57eb72c7ccb58d0bd9f9782e5eab8e4137d225b875609ef530b26d85b7c552770c66df01396fad7dab75302acb4c27f752b75b0ce49:96df03f30fbe2c5da70980d45ad4024067a82d4796de091159c197ce448d548bc5b3bc954d18e348bad62dd3c2bcab39
32dbc3afc15773c332a2605f24ce2ca3df38567b17a3c7566e772b8fa49f0db8:049f4b3cec24969d680486ead26e96798af64b7a12bcf61da12004c72680bd4f17570d235babbd92cf00037b62da694d16ec1ab11ad22861b14d128c83d9e59b182a264b8fd01d3e69ca91aea576b02ed3038f330c148345b621c4c0fba4ded3003d5b1aa1aa13c1659a4803514c:add4db113f3133a78ee27610aece4df4ff99946b4241fe0cd125025623bd7690d08e2969a59878f9feb4f82e9021772b
50034db59355c0cc3205033a648315c297c6bd57f33c5335a66b6d0dd3ce54fa:8f15974518b575933f99af74fa1305c13c6ccb5b004e379c3df457e05eed5e03aacff98d3dbfb5f4b0ef54decfa025cf83765db9a4c9d39054b3e146ad0b4fde2e4a5c208b698d2ba3842544e9df5f6bc17aab787127329bbe8b45ff40245d77e88f437637cd9a1b71a9ca0dc00b77:b32b1cba0fe06dd6d780bcc1c631df9721e8d3fbcaef372da23f40bdf5f6354e366728185e41e6d2dc04ad3e01d8b4d0
6294ef0407265a0d19bb3ff7530babd8e32f10a34dff0b37135cd28e82984a8b:f822e5229abe4eabbc054bb516ac3586e182beabdcae28d33336fdbdd23cda050e06a33e03e652165c4a5c32734138126b970308bf20086e9074a3bc8a9d5bdd391fdf7205b21716ba441782fd91245be12ef7a68a07e66b22ada6235f1b3c480f78ce4f945f3b7f985d89106831adfb:a58f90af0ee34e2bc2d13ee421aa90d80bb7c2007cce5b65ac0991a0558dc3a1ea46a8c55819bff404ab297c6ae45066
527fce2b29171bbdb60fb573e3639342633b1266e3f695ebce316abc86dd371c:2e549082f9eeb2534d30b90664e5091cf3411ba33fe14e1d86c353837cef4ce5178a59c68f6fea06507291770b52c8f8f28c7791961b2809a0ba682ac78a36de351bc0bd0c54a2916723d5ff2be3c73fb754e7bef4c0388f914ddd31b0f27581369d7a69b78dffc0018f2e1cd9bb840891:a94d698e8362efb86b25b7249fa09c5e627b8f976793ecb85d0f9b06e2ff8077ebafcc8ca104ff869e29f403d9cc9dc7
5a03fe3b4164b562d93e129103200ce033da05153fb1a1dc35452c00c8133f6d:7be5bfa4f0ae60a0c2f5258de564ea6f6a42ccd2802928a3fd14b513262b040d78825696aa9e3891947625af2a8e5ab0f663892eb6afc4d463034ff5e7480538f7b32f93f1cb326a52af92d26305d8f3555807597cc66973d29421ce1721872753fa882a3665536f7a9e05ca536b11f8cc4d:84b36b5b7ede2b059a87e6f6b8d7daeb253b9c39438ec407b5885d4186d958e9388af554e236475642eb1102f774a956
6136e51d3eadb2a46fb631b099565e6e3cc9feff15f33b9c08b49598d4a664f3:c72773b9026f66fa1299f4412a3e0df893a53a1f9c890a1cd653097459691b72387acaaf5574e293f83820117dc074d7396fee2ebbac34fb69a14ad5a528c03ca409438047e02e9c0ea765c200e3b482224af6874e03484ae19595827374b6eb4ca23d399e9e66f2c8a3732a3f2a27a796703e:98b9ad1abf6655723b2d685b84cb29861d19f8244f505a7ae4d2e4cc97eb203fadb87d2eaec040b07c100b5a790f0432
5672c6aeba5dfecc8314b1625f509a4e0dcc36846035bab283e547a5f6d1d4f4:92ed1627ec780c62d968d13bcc181dfaf6470fc1704c92cf7a068a85eae494b7630159f5e044f42a9a7c02e2dde16c8ec81eaf650b4ded6e6cb4e92ac5e54ca4e0d69a4ad3c6d93a0e91a5eaafe989c96c07f5785bdc0b73295eecac04cb71f85fa3744da3cefb9689674d994b52f98ae6a4c784:ac129ded0f581e58ae8f7616633712c68194923db58498290a267552b2885715e437f9414a9b9fb99080f968b56d836a
46c3fc71ef1b3c5a5297f9e6a8e3298838c014ab9598eb9f9adbfe067edb4e16:cd6290b58efc9e7b269dd477525cf240a050b30aebf8784a9749183a139f2c8f2b620cb1555d0006cfb0e6610f5b2b3505cf3541c37ad881c898e8f49d6b1f2618792b3c122f93148c14abebc3be947443f968af0c6a0a77ed159eff04e18852d8ffa2f35ec73e21640a1408a51526011fd7a33161:b04276d98fd1b27645187512e20927e735df17d9dc5bf003cb45661119875a6353286f3dcae081df36f0fda36e71e367
502ee3c386728a0c1b0cd6787ca78b7d6eb8aed2a9fa0ce7cc50b7c91869917c:7f5a1e1ab71a43bf38cd7accfd20af1e99ae55fba55ec043c5f71e4bce2535ca4c8e50f2e85432658670b6b20a8a1d9620b204938fa1aab412b959a364a5272b7364a0204fc3de15490bca3ecb572ab1ae0dba017619cfabbd10138e65399687c9288caac4ad7f2e81e6156dcfe30ee7d1f7770e03c4:94ab75ad8fc599d4a0f077df652a0c9992486dafcacfd5a5d2d8ba3b5ba0db4fd64f322106d9647aff961766aa6ec719
0d59c2cbc5a01509788f8d78768f6b4c70e1e56a3d064ee3a5d214b051373de0:1fb41c046728bc666e16ad566131a5c38b8562942c0f8ab175f2a82886e710e55c3af18be343a496f2426144f985c1101a08ecdd9c39081d650c7192af82a203272661c8424aad5dfd70afbff908f8cdf1b6a12cb3078663e836e317b37b47c7f986b1b4e97f7166dfaaef116205e763eb9998d64964e4:ab511a041e0ada5b71f4699a8b52479c181e1ad068ecd2f5d87fb124f2ecae402f7672851f368ec78d1d0e5ee7514cab
03b0c798cc56bd541ccf9b674cb12a8580fd6a0829ac9f5d2f2ce198c1fabf59:6310c538bdba8e586904f3283421e272ad4518bdbde268184bcc3c33b6078d9460b1a295e927a2310dd291a9b9e2bb4b49cc52b972ac6ac9f7a2bd8d8d8b2737224660135cfa5ddcc874186c794dc3898be4302cc771cb6483a7463830fdfc611adcf09b9a28d71c3ef6ff45228e40c12d84459974b8c944:b8291ecf685152e7bc7c1f3753a4dd2bd213c0ffe969249ab8927a6676ecfab3b67a73f3f7ed0f6187fa976b3e8aeec0
5ae1bb72838eb38c1f4340c6e22686961e3e34b4d2d518d76ab4f881fd479c94:332c3bbd162c8cb774480ef81cede2aa52a0967a869663cab7c8d105e33038562599881f6ef77aa4e3f4225131fc864a27db9c58f5198e6190d5eec728ec4e698b96d1f982edc5d22231b3d76be10a7deeab8f32af36a2cf5d8aed42102ae20679cbb5c8befc8a65f13837710bf86f344590bc74f96e052eae:80e602213b6c748b3e68430ccd1c4fa288aa5c0a411466dd8994ff19ae8be60ad281da36e8a35e2f2b427ac2edc255cc
4113f2add0abb7f05cf56a1281457e9e4f7cfb39d093854b3b4e3bbde237ea23:a83d1cd6999e4940b0d71be96e000e46246a6e451c646756d893b3edb330f2f445858ed12d1d35412fc0eee90204aba0d4fa88583bbc37ee389f88fe0c8dd4c34ffaa8d8c6affeb7feb5f3064af0c06ad3f7a51e4b58f8edc95bd22a02ec4bbe2b2c660762e345d00548995ddcfb10299dd192344d45791ea8bb:a37b03f854b9cb12dc7fc109bea2ccc3423418b89d283715fb8c18db78a68d60b19bdd7e6acf869090b97f538a35df66
17c979dc43d5da70f57027cffc420c6df4245db222a2c3060c7499b2663f6093:c20c4351abcf4ecda9b5478cff8af859ec743eb0d67f6ce2b347349460a2854475d0a6e8165b5174434ca77c088e641c109ac8b8d5879586c034eadfa6bc3a1e66faa02a3dc0fed87af670cc8626df5c71a8360e1911159632558e7a99d4830ce21bcbf3f551465bd1061888b83db174343692b6d796460791ab8d:8ff5917a45cdda175f9d6f4a4a99308617ceec290794fda33d7585f4a3964febf0274479f77210373f3ca6350ae0639b
50adb11ff487000da2714e104241c0039dc6c2eca5e976a6bca8cc80fd2f22d5:3ca6b6f64aab22ea7dcf85eeb05e5eff6102731bb47c94bb737e77b389334742be939b79219fff38452b411052bba588b7872654d0b40f7be1516b8f243047a9aefb40fb70f93e53def38147fe564214605ef2d7508bd7ef44fdfee7882d754e735ba282e044bb953f18f131212d879def4d4d6923d0dcc0d3bb6a14:989e4389faf99c5cbf6798a147fd85cf1331e1e7faa966d6fbed2cd43c673d6a382e0e304f560e5ba816eb1a0b306cf9
55bdf02943f5a8130bcb537972f870043f5d7e3561df8717740e1a7a39bf73df:e288bfeeead0c3050ec6834694323af7bd77dcb52fee6cb54167a73181e487583ac75e63c95e71760cd9a1584b711842f602237f72afb268ef039a044d293d4091abc1807cbec9041ece11905b32ace59db1114047f60ae679c53b465afe03a8ba02ee89e85efebbb93226eaf1cd5c6ce1ef913fbf549934dfbda69dff:94c74729eaecf336b25d82a10798adc97e70cb345313413cf6550d622b0b92b9d4dcf606afb1b7e88db6b3ce106aba04
49a477ecf8786a9f5a44a9da0a83da977b844198068f1cadce28c599d9ebddbd:9944eeed83dde7b21b72ff1491cad3d7a1ceae3f9c5c880be49024d9ec055c55189de80b521df30fd17d558f7bc6ff6d5c9dcacae3ec1242929fae1fd8bd7fedea51acd344a1fa0120f60b1a4679e5177588fc27d713173f4fd47cccc16feb8b44a2d670d7b04c8c14bf37527230f3daa6d7c3a6e958c78376c5940f1063:8045a0358069c43170b238e7dc98952bf84e1caa0925905922b5822ab28b498297e901614909376fa04ced4c852c39da
6bbc2807b27b635285670a68a42d8fafb461fab581e4e2773c199b29088bc554:0c149764b95e6461e820206e5e2b7fa4acf62a3a132db955d5c4ff1cafbfef3b3816aab1bc9bbcf14af47a4e7753f0243842d9b53b3c3c26b9a2e244f2eb06461e2128949e9b437c96cddbddb52d9d6062d4692d05dc624f94fac39401ce51389576f0fd52e670841602645b4ed6a76cc845ec8454538782b3b179e44cd5ec:aaaa82c3fd810924f41b74bdf484460810f5f3274f8102520099f9ca384a5965e50202a36edfa5b0999c7b3c2548ae74";

    #[test]
    fn test_min_sig() {
        // Source: https://github.com/paulmillr/noble-curves/blob/bee1ffe0000095f95b982a969d06baaa3dd8ce73/src/bls12-381.ts#L358
        const DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

        // Parse lines
        let mut publics = Vec::new();
        let mut hms = Vec::new();
        let mut signatures = Vec::new();
        for line in MIN_SIG_TESTS.lines() {
            // Extract parts
            let parts: Vec<_> = line.split(':').collect();
            let private = from_hex_formatted(parts[0]).unwrap();
            let private = Scalar::read(&mut private.as_ref()).unwrap();
            let message = from_hex_formatted(parts[1]).unwrap();
            let signature = from_hex_formatted(parts[2]).unwrap();
            let mut signature =
                <MinSig as Variant>::Signature::read(&mut signature.as_ref()).unwrap();

            // Sign message
            let computed = sign::<MinSig>(&private, DST, &message);
            assert_eq!(signature, computed);

            // Verify signature
            let public = compute_public::<MinSig>(&private);
            verify::<MinSig>(&public, DST, &message, &signature).unwrap();

            // Add to batch
            publics.push(public);
            hms.push(hash_message::<MinSig>(DST, &message));
            signatures.push(signature);

            // Fail verification with a manipulated signature
            signature.add(&<MinSig as Variant>::Signature::one());
            assert!(verify::<MinSig>(&public, DST, &message, &signature).is_err());
        }

        // Batch verification
        assert!(MinSig::batch_verify(&mut OsRng, &publics, &hms, &signatures).is_ok());

        // Fail batch verification with a manipulated signature
        signatures[0].add(&<MinSig as Variant>::Signature::one());
        assert!(MinSig::batch_verify(&mut OsRng, &publics, &hms, &signatures).is_err());
    }

    /// Source: https://github.com/paulmillr/noble-curves/blob/bee1ffe0000095f95b982a969d06baaa3dd8ce73/test/bls12-381/bls12-381-g2-test-vectors.txt
    ///
    /// The test vectors are in the format: `<private>:<message>:<signature>`.
    const MIN_PK_TESTS: &str =
    "28b90deaf189015d3a325908c5e0e4bf00f84f7e639b056ff82d7e70b6eede4c:09:8647aa9680cd0cdf065b94e818ff2bb948cc97838bcee987b9bc1b76d0a0a6e0d85db4e9d75aaedfc79d4ea2733a21ae0579014de7636dd2943d45b87c82b1c66a289006b0b9767921bb8edd3f6c5c5dec0d54cd65f61513113c50cc977849e5
177c50ec35b1da25f68b9f7bad8f1c443a01fa2b20de37be0caec8b62db5c902:d2:8166ef48e7c1de5f8256a670511aad114f956382eed36f3bb45a7a1bf473e982f0e399924b4dc92795d043d9475402aa0d065e10f05a2026a0961882b6c2e6c6ae429edd17c7a43586a814121044e41c5c1d3397452b2fc61fdc523cc943ef68
2c864f383cd664839ce6d7d049f8083870b628d7bb8a4539cc84a35bbd723736:4a35:88c76ed5872fb011f4fc0fc8ff2751513dd6f22a9b7cb125ed39bdfffdd996ba1b5d9ea6332e8b4c34e591cb9dcf4efe112a096754db0d723269bb1a758f986d5e0cfbdcc22f8678f72f1804459c98be59ee7632c666206255dcaa816188cf2b
43a5b55a3823acebca9e55face42697b5cd0e2398a44a56ebc22d936a05c3893:94b0b9:8b4f817e0815a9ca1fb91a5fd9e88714d72c2d6b4ea037ab43cde4149691109336edca72fb55936b5ba8f4576ffd49780dde24d48f9a9d5a07d1527ac3a9bc38c05a0fc58bac710cd4983c6cd21e56175a6e597954ac68207db1a8b86efe84cf
736057053101fbb9240808bfe83121382a8cd559a97f8633ae170b3e1ac9efee:0d83b078:b028a3c5877113519d0da87fd67edebcb80b37869f58505997c459fad745194407e004503fb49f4d9e0ea289d5cd9c63151c2d40e09cd3988cf7b0191718d4f4d07fa149c965fdc4a25fece97efd72fb9337099b5f47979c6acb9b30f0c2fbe3
5737b8adab24e7ec10fdd0a420c603392cb2c43f6466d6033eb14d1012470dbb:07d6e7a31a2f:99d2bc134b268397759e77b7f59c26862264454a659b90664cd7ff9fd5701b083ef6aee3df959643816958515059e42205abf0c959ea64910c3bdbb447a1afca4caf271f7dbd50085d886c2e3f5294167ea3631767acfee5d89cb6e04def2dd8
281c1297034c8aaa2ea6368dd038833429673b99dd4da4622908de8d9674f99d:033d69a90f6073fceb:8bd05333f0d076558b8a25a75b76b14af7454f69452918d363a905a49089663e23c0ede69b4882790178a02ff83b8a3d0c945e6ce0e18c5c3abfb22c32e2bee71145fd319f4daef46463471df9691a372a8f30427c427fb025155109269ef363
6fbbae45973a06226abf29b6d978429cc2775b4af6c736f6fa1eecb042c3b089:b28bfd61695d25590c:90f9298f281b350add0e8b1789e99d38a42021ea971d1a0b1a28f8d11906602bd0a22eeee4b149443541f149721a926b0ddd2a496a88ac47a9f59e0a80aa91f88baa129035d2f2d38028ab024ac38ec0ae1768c1bcd156c2349a26e01b94a516
342fb513e70e2a7cdee072a9d8c1cfc86aa9691687dbef91fca2d15870e4adaa:011ddb2e7d45df2e05fb8a:96324a72624c99ae74fc334cb8fe70885d7e9c840e4608e5b19a8a5ef8fe68277e7cac7c4b6889e206f6244dc49fc19a0a3ac2992e51d0f0076a528fa6c11afb4a3f127286714c1548a3c4c9eac7e67eb32bcd2c480e2c7d36504a5fa52d6ea1
498f8139fa03ac326e5ff321a9c8083d22eb048de74fcec128de3621a1dd5675:64024e14b436cb94e3209c:8723e4effda2455dd5d552bcf6116f88dd70187b031edb7660fa673ce22bd0fbe9ccaf28be6d9c78b783fa6310a0fda00b29cbce1adcef4204d31694bb47cc84de102d2dfab833e907887bcc8371119244b5b69b791c9dcd667e899971a37295
055873520343a11f937aa23abfdfee0d1929c461bd2fcfc85d8d07ef44230c69:04f00076b77983d6ee7ab6979d:afd0d6908f62ce579dde390b463d535dcfd1f5ee6664d46a583952c50178a61f15cf072153a21b4e6044dece53a755b1025170d84046c57252ea6c0a9c45ca42b0c77544e80856634e552c1e2b86eabf1f92535e1b27ea43281f8dc3a8672211
13ed1173e146edb9ae6a77e289155354d6e0107aa2fcd4dc89441619553448a3:07c50e920e060f06243084d32afe:a89faa2c99e76386d80f709e1af822e830385d07b0cc4bf8b46315273f0b11c9f77845e431d5bbb86d07e4b0e15c66bb1958e8d0728a0a0961e5f233fcba72278f5b0ffbbd67fbf62aa7b7a1572d9dababed755a60d37906dc30bdfc3d9d4c2e
5c3f7aef904cd9aa5cf093f993f49d46c3f20b7450552d52b23569239849f31b:6f455d61ee48d1990ec61dd70dbd:aaede5d58e5c71c170b2fbff350cb596bf43f2d0ee6b0e83f8863350ea4fd756129150e856c83e45734db8649a3617150c4a7a37ec596d89ff6cc6749dbe6d54f41cb36662279b3a82335e3f4b946afd94740e3214e93a45643bbabdac93a25c
00cc17223e74b58d2e465bad2f5d0ecc5a85081d143fc4b8ab8eb10b44c6c45f:0800350f624966388e327b17cbb9fa:8333c0c7d9da5f79c67ed5fd13d92bbc91c5680837cd0cf816f2876106720a93323477ba28dbce0f554ffc0f37db9fc20386aa12d005be7a2ce5a660ef8ff46c7381bd0446cabcc4a3f4b8b75b9608615ab2497beb425415c778c278f38a6d81
21fa64295c0fc47d81f69ba31d4661604c4d9eae6d2077c094ff758b1757e3c1::845c89e3bc5350275cc5b2669bda8ae127b8bf731517bb1bd5ebf0670add6df037f6b8c382aa03f729c5e8049e817dab0cc310e8af80d78cff447f034d32e7e7a1e8f27c8df390c5b640a7e341d6ab94311c4ae35a754f3990371c9186f97f0e
4f35aaddd4587dcde04341ecfdb62636fb140bd363738c9dd8f53b45fe740d09:07d29e93:a20dc2b369dcf1f609e24f795ded8d606bd5931a2f3e8e045840eae489da759f4e00a036ac2eb678c61fab587dccb55f164241799be62a63958df72533fdac653fe23983ece98119991c3a7e7910d9f837ffb3b0579c326fb46a5c3b55527a09
275d76e250f6f44585d23c95f9984ffe762afb7bec52906657ad4ffdbf264e7d:050c5aff03:85ca53a9b9ac376b09c3538f40ea50cd0ab4b16b205fd434befc6aece17e807204ef8333a63522a1df41b4c8f38a3d3c086565227513ffa50e31d3bcc9870f693d9527d10e9c26386dafd48cd8bca9e39363ec220e1196edd636fd2248ad113a
697ef015b81f5a3c31ba3ba4482b1182f2a106aba7bd94948a073861297e9c4b:0caf34f67e39:a5aa61367ef1f50257c1614863c9a41f493e01487e522bd83fffa8c2d7eac5656ab355db421e4a3e9c6a325e8fa8ae4e05875a490b3baec6529799c8f65efd7526aa7e9fd33ebb1e7506ed36012b35ffbabddaa63748cbed227bebc2738eb647
41dabe002f7aa9792a9f04527048159e6f1be97c7e0207ed1566c4262a12f789:968e85352fc3df11:8962a7d1541633a888526a8d3d010280a7c6c8c268074ef489019a8651ed0099c1c2ff60a99146b74a47f4c432d5d04a08c05fa9be0e048cdc283da719dd0fa1c7032c8353ad6846f81dce05f92ea083f75f1fd09ea67462bc8c8d46943654ac
27d3382462061f32036e9f25746697298c03ac135eb53cce40e6c8d0b61a38e5:5c3c39865260362265879f:8e234853e19f022389dc7dd7240798c45f81c7be9e650088d380f3498743f30c961e856bf9579c21f280061cd087609b15f91f02936e082bee165690c5e2a792d336bbab9c6bc5f27256889953744b81d685356cd6f23827aed5e8a9a23236f8
1e13a5be7f36189f5ffcf35c210de27b6571d64aa3d00111fa0831f48c4fa165:08ed73f10fd0e2fa0ebe1932:b1aa7f5fa8af643ebcd8410b580fb93dbd2ba82d64bf9a802846606b39d3a4fcd651f80736a9f189694a6910b41ab6ef0fc2b90bd374410feb42496002e435f6c11b18ebe8897d8e64630a1290398bd11d36bf83e398db9932bb7e0e94cd54cb
6ce4f45b393a54d6e12064738e740c870fc3066655827af9f071dadc7554a45f:0cb23a6f4693b24a16a0e5d11f:8a5e73d0e38f3e8786fdc7e2fb313b9a6b34ea7658e1eeb63c4270ac1ed80c42f22716283843ea29f72c599b1b69edd002903b75545342fd3f94c5633216cdf4e7a39d3aa146119f5c6fd555c359068ce15a3c344e18bc631d1f9ed94e266e2c
330d6be474e54d85deec0aff3afa587eb4c5f803a94077d9ee86bd74a034a40d::a8492b918727dfe480e954c52126666872e243489ec6ef42d669c4483c3d09c83d5a49b8092685aa3410d1a1fab33fb6004c07e312df7faa3e88a53b414dd653fe4f417ef9450c7220a02ae99936a0a18b264ed1cfade17ffffe4f6c0b334dbb
461fbcff221f0655c19f9c5e1c2a5437c8842ba0910a983be007cff9df19f627:92e6e8:857d69d8830474de73df377034c57e619c954041b80b6c23ae769ea5dae40a5d42d8f855248d4f78c8703970435042110b256d1de0c1061c05e5a544de326035ece92e7bebc665f1575d5d8f0183303a8a7e1478a6600db96d47eeac05ef5645
69a75aca260d679aa24f49481164930b71e72fdb5db887cf484a6db6852a72a4:0428b032:91f8b2609fd551c13eda568f103f5be9f7b2a2b42e2cf263da628c6cb735ad04d436b878fc7363baf969f415550d02800f562e606085ad0962be2adbe8c617b36a418c31d81bb10577f0e3743be8f39142e7fdf5d3637a120dced8b73ff79262
182733a6720089b476c298a084a30a2a4a717b2a16ecb3b7be894b222c3ca5e1:26a7d91d:a39166d0499752ff885611e994ee3d39f8a9a6d734327ff43045535cfc882e3c4c99d62bc75da26474981013fa5214d6068dae1b90637e8ea5cad091d364badc6934288339c600059124d347a7a09b7a674435e1c7ba9d519d6b6d0b04051700
53438f53eb749aba12412357262d5445e4cfb69ba645b30a9f116d6ec45a1994:0251be974654:80480c5941ae1fdfd3ffcb429a1b9928ffd08d8a759e5284dab6b5b73724b50bf76deae9d2dee2bc4250ba65feb9de620c2d7691e116476b81facfc873f8842a27c3de5f0730b480dabe0aaa4d24bca4df3564b71090e280191daba77c607089
566f89bee9480150bd9cd346e9fe7f681af96562ca82a98ab9be4cd319401a16:315a32bba44f89:aa8a8bedcb31ea6d67957fc7e09c336e561f63fd085c84c8bafafb610b961921fe1aca3c6b7c2a104fe84a72fd771dc20f51d9c28cfb7fbf842dbc9343d3cb4861f187c7ad02032f3a347dbff315233c3b2c12b8cae7dc40ce3bb3ae0cf28633
6bb60100e45c2a7601a1075a70a8f804eaf016bdb2cfb67c76bea74c49c6a99f:07ce73a170e9e3b5d3:8c87485bbffeb5033466993d3924100696c90bbb6cb8a7cc25e92f1e72fc93dd65eced2046b35165278a41c75c261a310590bd11ecd4b79be049fa201c1387962912dff8d309a9d4ffb0a192bccd3fd51a43edb42447d86162e6c5e367a0ebb0
0c5e59158036e95517480734dd946ccd840a2ae0d7bfd04afb561eb07b651f65:097fba98b1044aa38ecc:8b92528bb299945e6eaa1c1543982b4719ce6ffeaa46182b31f5fb12d04bc52d1edd242f26bbbd1d6bca7df14a6e713f07047747eb44048db73e17dd0cd86944525641e439686c0d926fa6aac347956b76448f6aed53cf5e150b26f62697eb0a
482f5eec6aab3190b3e85c3358e906470e29f5028c1c1ff27334744a5389b046:f1903bd31ed169bd2ed5:b1bd64412e722ff2568737f965458f12923a38d94dbb9d08413a0122a993f159a4e69322bd142ffba038abf617809f4c183d1bc8397bb0d4e755854b06df29be5290b068bdaeb6a3bf66af947f9de650fc992b24795e109d66e1c1b8597c0e4d
6cf0808dd7e4aafedc33bca4bdc5cd2ea5b199f09e60f818874d06edd808b711:053d7b09d32505e7f8a86a:915bbe14cd1bc66d46c572217d7834da1396304f1a00964717eb9fd078954db38ac2d3cfee23a2cadf2e239cbab2dd4004879ceaf6d2a0484284e8bb939e707f83166527df1b7f07f5b55e987e400183e051bcd02eaca19c8a825405f25a5fa0
516a6fc917c2677b196e831913c67137d99bfbfcd279dab6c8189b8235777958:6244fe979e6507bf1affd7:96329a5e5c8c2f96941f8281b85f884fbf36732b9c20a497dbf2364ab5c885fdd2ea901a0b8142965643123b9959e6a0032fab81535cccec3f89f2f5743ab18ade1681b339dceb146a653356b676ba5044fd338a313edf9a1506c42a8eec2ec0
64c8a98a1d399e67005062aa67492603ae501ecb1a954d61a30a4ebe4d161f2f:082fa093ef30ed114342696f1a:ae8d8bebf524ffb11e11ed6c29cdefab488749c11c2ee5cf3cbb02731d3b936ea11f4e41902d29cf977e483a21f398a20d904494d3ab7305015b4b8f6032df5240b29278689b72fb4a9496458879c00815fa3e29b3b5f3df78765e161ed3dc64
2544f3764d9102fb80bb5fa446f4d9b9050e229f42e92cd36b1e17b8f91c850d:feb1f3d7e800a829cca384707f:afdee7bc926e4df643a69a431bfc91aadc659e912e83fc20a7d162ad675e37d07e95b04ea17ada1ddecda83799c7dddf0cc95db48879e6f694d7198f4d0637327df4d5d29b6542b71bfa773f66e6d518d8c700b58a677a089f82a1a838097ef4
6004e1aea40b85274c75b056608d372ce8f4fb1710e8f5a6ba6da20f9b559605:cb80b0a3621bb0528735ddb062a8:97d80bd51856d3efba40917d7463dcfd49411a00951b19f35eaf21b470fcbfbec7dcfabc4542146003ab4c691ce565670d49c7405f5cb3e40d4cd13808738c5f9c5da520ae8c8d664af17bdccc87872da5e314dc51455a7816e197dac9f3c37f
06db1da0e8e44d06028401ff614557bc44d04330ebdeffacbef03278630f3f49::b82b0511b133a0723fcc1643c6ae16b16acb8328fa10782c3d8dd532bea9e6c3e5758bdfbcdaaf37771ad70989e107f309adabc1dd10359caabfc0471db16d5d9abd47e8e48c3a2ef07483989fc0babf6080e8a156d432b9bd2323d3b9beb152
4f9bd257d3cdd870d0774c460a7a819fcb05b328606c33d541843c4062631d1f:57:a5178ee9b4f18bab44f49dae208cc1c9a387b518d25fd0c9ab8c5545d3f8aa9802764dba201683b4fb36bb3f5f95a8150bfd63971e086acd76eb2ec7a941c454c8f32152dd0894ffed21265982f3da9f6f47c2aa76ee526fe252b5f921c59a95
37114bc315ea4daed2d27c47dafe0b8c9a9280f3e9c5628ce6196d3e444b3a48:2e62:81c8811fe65a4528384d8f5a6f7840ac530d9d66a58888e8e550e73cf03b2d0695b3794dd8e2ccf7936407ee6bc3487d169a8f3c99718f1e8884032477e212c53427a7b5f18c02dfe52a14e73cce697c21fa210fb2c9d0b093347a82ed4a09eb
55be56ae7328ccf31edcfec667c1fadccde36d44c4f7d420cd13b563478163e2:09d14ad8:86b20e8dc583fd7727e1a1afe20b205a14fcc27339d7871db9ec5347dbde1818357c825c1d8158e730df80de1bc6979a037dfab2f893f710a201dc61792bc4e1f3291fbbd99babaa8ee17afd2b6abc6b9341edd3392c738876bedadbfa3f1c87
0ce187daaf68a1af9fa954c1b00dfa0b4a7f99d72f2c0417dcbeb01bf3abbba1:06cf3372:878c0c0dbcf4810933c3033e0bc70b58a53e761ab2946e45c1806f8f2bc8228ca944794c59378e1775adb9b7e647e2c9108de40b3b067e82c6c2e432fff08925a1d97670403ea80318e0b1c51765c390594667db46e076e2141fce896cbe606a
320f214da563ab7020bf54c97ae7c86868bc5c89abed25159c90896ab9fcd72c:14110a5a07:90799eb2c1b7f0970f1fef2d1de9f9c66be0992658b73f3c7690dc35f3923a9502c45bcfff360affb554d6469818622e035136a8acd2a73918ae85abf6379f22c8343bd7a2039ea2998cb5c47c68b6cd85408452983d5faf70fb4b1d3c8c00f8
6bc5dad1ad7f6cbda1f1817da2dbaaa1d35bad490ad2ead25cd2eea895324ead:42ed6e9eba7c:a95e3f826879865c2479853984da1075164dd2cd84cecf66ba253d16561510456dc346d1257cccb12155331c072bce5b05b294c2bc870d21c0ab9055f92e70dd880ce8c7c144a5f956c5395aa49d8a5186b45627c2c56f41fdae021da95f26ea
4223e4d4129f4b89380844bb31b46288ba449b37a9fb376d96cce1eaa628e2b2:a192e9b18da043:b47e432e1c6158e0c17620c61e801a1401dfe8578db5b61cb131567800f40ef1f5c125f1df5ef171770165481047f09117b2ba7ca45f5caebed2777cec8858db2a5bafec8f7adce972044429437b3afc7831640ea9181ed20ca023b109a056fc
569d72679eb7a0f07797892b09fcf7a1dbb61fae4a73d4e798ef7cb35fc99f77:01ec22b832611852c2:883e8e05f6e32dd24c9640666d58f1952ccb32afcabe0eb7960a18abc20bdbcd3f5e00f1b633e4d35424a8cc71a341380fa31634c7f5e8f3d3c173b4fdfcced456d9d5dfadcf9a71fb8ad2182734f9aee6fe0b11e3c7331279d2530e5a042f71
6f3c9137e679a12e1cbd241b7436e8bb6807aa491bbf083c6b68398894cadb4f:580e2bb1668220c7f7:848be794b037494823c76cae9de6083a69902dceee2979893d27b04efc18eee6b28a4754288d7e20f5970e540709cc4f040fc33482c6be06311d1793fbecd66194fc97f9b491631257e19babb61bb58a464888a02924d5e10ba4113b2e9d990f
34ab9c6ba4a97fe9ef761c6f8ad6f4afe5dc390bf159e213b58e3f2175c142b7:0e30de7147d7eb5e2458:adea87d3e463b6a97e05dfd57b45a8f1a21953e2747bb0b324c54e8904da0e16a1e83565426ef32852d70af76dd654ac050c4c27b708066f52cff440196502e3ec527a6fedc68f21f1dda783bda9f09d415a4d47384836cae99b417089a3179d
0589e72a73238a9973bed6260ce69db89e210806dd01619cc1ccc9dc695a0f74:04e9af42b0a27a52d319d9:8d622962af2e158c2a363822c72616d6d071aaa93f628b50573d856a04da48ae8c907d1f42e680828b34fb70b53ca73f0bfe51ca9afe03f7892eb2ae754d247c7974949f4c35e7a21800d5e4b5cd7a6efe4f3bcc7b1a3a99d8bcf8164f47cde5
394fb7dd9c5847027d1c9cf411a2386e1f42adaaef4ec8a1b50204976189bf5a:04be6e8b23f4bcc91a8624d6:b8a5acf1925863fcebe3d59d5426186e852d14e93fc24910cef1a3d356a8279ef3dc6ab622ff23ab977a90c203587a000840ab5561de0713cc495cc35f1f00909435562d42ce852cc75776aee6b06b88e86920ae2cdf3f36bab3175c44018a7c
3750907c1368d256e95ff098a026cf81aaa0e8aab92560cb0cde140eabde4095:0e5665dad423cd2d935a3832ae:a9e64f0739ef9addd3bde83650b5b372562222d7c81db9c7c49c14fe8224ab18de355d23964dee080ed66d93a72f171901bb78cf7146957efecb006c5f7d49369569b02055389694f9ab44aca690eef31e3a0cc670dfdb53dcd4644de805c95e
32812bafbe9535c8530406a5f81d88f9d677ee0693d6c5c63271b3e154ffdf23:a61dc6c0c4ff587b31ef4b0cba:86b48e37dd075088b860e7c04d0101ec1ba8705dd9e7e4d6db16c23a250a3628a3b904570f95598ea286c2ce7acebe22139fa6320fd132423b163cf76e34329145a609e1cb9e17133175df426ca598495e6f4962baef021e7ab6013143d47527
2ad285390978c933fda0b3d51bb58e6251f59083e89ebca66a565689eb373cc2:0d0470c09284578db66c65d1ed7117:9562202c7186f6c8a91e2284f7ce16546c8e9c29d9016caa9d3d8b2510b3af30c379f3fc459c8ec370bea57010df69051836658aa5d4fe2ab7d3748fcf1cc7a65996e157d83a522b5c7a09256024938ab32712e1dabc937b1b0e566202302377
1d41aed618eb90a7a481032fc0624c3b381f899b5aba3ecf4945ecb7bcbba248:042a:8f48ff4108ae64b1d6475bb156fbdad895c6a38954ddbad95fafac32c9046800565bc80d05382072d3fa790275680850194effaf3c8f4c33e74e451bb4fed479f08bba1b25c70a3eed0236fe773cffcecd5136ca78793dfb6317b7bbebfcaeff
166ab7cc55be4235e4dbdff65beb5dc78eb3bdcf74531ddf43c5dcf9231ab5b6:1894:aed80a028af501c35a3607f83a405d40695b0247856f615d87a5effc041bed61994d5ade2a446649ecfb53d35c802a6e1407e7eb7f580723dfa4472cec745b33972920a4e391ac8cd24081be533a0f77f82e92056edde55034fdb5a1e62cdc67
6c3639c6647ea53eaa46bc577bbba99b305b2cb9853dfb2cfdc702665fbcb546:7ec9dcd7:85cdb3b39c6db0633cd69f414d984a990149d391314a179a8df5ca53aec19d99ff5589bc6ac1ead6194a176450760eb518631ccf74397565fe7d0f141c33c5d990df1d92aec61c7774673e6db2bc9c010660d1a960bd9bf04b34cfbbe7ec16fd
49fa1f7a79dfa239e804f5e320337a708862416bb909bb9caec81301f2fe451e:0025641feaaa:a51b7b4da153ac896f5e9eeec421a1d61bc915fe349334644f7315d9bf74dfb46b24808c0874ee61f003173d678b59bc041fcb22788e0cb292b3ee98d827b476e0081fb63cd99441736d4ae6bf04d6b78de252825c42457c1415914cbe997ce9
3c0bdcd071ba70b2ea73d1a4c5768a3cbbf3e3642f8ce5e3fbc62b558a1693d0:c43263af0875:9592ef2b65a5312262ed8dd2128f8ab8e610003c459b1eab81e93aa0a97316a327b9f8d2b894e70e585a93aaa82b79fb0c4b2ef732646fd290a388f5ed453ed27b038d0a62e7c5d22023cabbab6278884564721b56342eb0bbf3cb839bacf7d8
177d9b3bb86c602d76157c078bf48e764ed0ef61a65a953e078fd13abd89c883:19b6771ccd870f:b1e8c3c34a731873f24420b7375304df17dc7162e70fb9c2f3899c30a012b01816edf2ae231554762db8f19a74eeb9681981bcd70b87bb078968f12de45537c4401524508de636975b038a9494ee47e324f842ddf19517a0be5bff0b4b5142b9
0e98cba458139123b6478608980bfcbbac2a71b7b27c4a71757cf3b6b775eef5:07724a519ed1b1ec:92bed7e9beeb8d14899246a1f8b7212e10155a413e4c8e09436a6a3a2a8858b99410f4f06afe005f71de6caa9ae9858a123bbd12ef19f123a3de91811525dd41c5be9b87e07ded826c0130a85d3b3fb4f88fdf99cfe3b565b799fcfe85789d4b
6412cd26afd7b8774454ac305e8a32ab2dc489c33ab2dd853ea23d5d7c2dd741:531f475669c44d40:941462a5e2ff1eb47f4ae8467fe10161dcfb5bd04cbe0249b6bd29f46f04dc82057681af846e76e6aba3f052db1008af043f532601dcb71cbf3635763191035a33f68d4c3b33a9ddff0ca041fae49c17154d5a0df5a56eaa9686a560e27c2576
2b4736db74d642173c2e685c02b9ce4c4cf415334fa2ae0ff6dea6e475f0e6fe:07896277799fa172688b9d4f:8972f8c3910f79643f026bb5551fc9096bda8cf94efd19add195524dad7fbdbc7c28aa6b5f40175519f9b6117fef50b5015a920196b7a02943d6b01c77dc411872ed74a65fee33952f0f899ecce37d5d47adb8c0a9766da7d2c41f3f60a29d58
6886577263e5f25976f323beec475ba37e4060056ae6c32cd10aa3a47d17131d:0419e98cd72a702b453801a8cc73:96a39e6a1c6a3f2b282f4cd65d8e490c9d5117f9dd5503feb83b6cb44bbf3fa3993ea2d107297637a476ad7037679f5210802c078e65d791ff741d61986b8854ad3abf21323a5a9a2d6728dbdcd8c341dfcb3a2ac1c7535868b476c7d0258d8b
4e0239f3665744032462d5e5999b62e4a224c4de38552e06d96fe0afc8a56579:2a5e3e96548d9a9a35ed8d497b54:b8bb08d7c5abed07781cc5d3120a6c62a5a41514eab9580be86007e0049c0cd2f8622bcf30a93d43752e1256310ec0e80895f6dd37df67140340be45743a0fd92089a174f4cf550b988a4e717f65b823fdef076a25d521402b6962198b6f81b4
1cabe26d6ce80e9e03c326d02decd6970947a0e79f8e89b0ae3d31a96a79c698:0ffcc1f7376eedceef0e1195bf735f:b06db65ebc8cfbc7899b10a2c706d585783f3f10547f919b9d9460de50d292172813838b61c75fb1f409c833c98ceb2c1698a5c414ac31d60928ca4253ad36a90808e74797a11e1d50ed132b3278bf30669790ec6499b8e9eacfbe22a1790c44
1c9ed5349162e2d667b1972293b551b9e847b4cf5a0b271d8da70ec586f14186:0d:a103483d0dc05ad0a66d99f4faac54eb4a4e763ffb3aa337a84843f4c7be4b3010c10f9c8d0f0bca4813d9f5d1efe50917a587c6fed3a21fdc2e3f6cadfd1b7738d19434f54d370a2fc8672a9dce11b50c38c69b9eaccbbeba5f80af6d371edf
4fa311dc95281b95c653d295510303839d609cfab1ae20e42f6ecdd8222b0232:96:8a153cd16762f07269ef6b019eece8e79d7590681d9ba154a4424531f6ba697ec0f8c773a445a6c1b6607bc904f8d4e60e6b4b05e152395ad25db09f6baab0d7d8b5979047a439566cbe19b9ef28d020c3272ecff416cc13a94ab0d12c2263ca
17b308d35f2b2107ea16bb5805456c49829f328a25360b371003a91a33c02d1a:e3f4:a1da28132bd68317dce7f6a4b10e64e2fc6917829d50c4a8700c1493bea394e2926cd47c315f97900007f877d25b8156074a1acdcaec936a04ef3b7ce18e4145afee3977d3ba18c760becd1a0fb7c81c4ef0dec32d0aec97ce0a1cc8946fb793
0a5c7cfd06a465381127918d0d1ea38c1e4c933444dcb7b62262d87fa08b95cc:926bfa1a:a71c91e486195316156f3d78740a93421d8a8c03c4c37bba17f971cd14d964ed66973c9934acfb06478f0d76a26eb04410fb8aac44abfad7835cca9a2a8f4d21ba3b6364dd710c8e58ab1f06184126aadefbe10b1b5a82c0af6266ccf2d82f98
6459107c9acc6d52cc5fe0e1a7601e6f8004d5c78fd89d41bd4999aa5eb1a551:009e79cfe03cc0:8bce396182f6e23370ebe56bcb26284e082f0b07f6473be655c39863db041630c75ad570dc0edcad57d1ace944b44e6218ab9c714bebc6e5f81026b9fd53c736579e2287fc0760acacef4f20922ad7204656eb282d4f861f0e46ea23fa6c61e2
21bffeb6ce5ca75da4665264c683fa70fe0570d95a481dde0ea9aecd3cf53565:0a1c395c722f4fd83e:b98d13103b26b3728d140d535be1997e6125c204ee09e0ec5420718b34ce5bca87c5ca5df9b327128e124a458d4ab375128af9b687e55742931d9df5796b74c2bc10e772a5a849588baf8f8e805a5fcb431d2d2b2b646c3f0b9d9ecec29e9238
3fcabeab0355751e59abbfcfaba97d1c018aadfdf56c9bfe6152a3554db48bd7:e6809c7244d39b55e2:93a0f2f5b469ee5396552e7a9038bbe989092d5fcbf6627e035f7107f362ffa212140fb8718b0c182b5f24e3bec720f30fee24cb1a3321ecd333a5380a64d691ba71365ba385b727d2b82f6185498ae4a6506c70b65a623fed121665ec95c891
241762137d3743ecbe71f1cf05391a1a371399c2c8254f4c138aa1d362d795ec:c7f22dbd191d66754852:90fc4ef59d11bc5fd47f20fa97f8d7cdfd10c9569d2bb352c5ae521b0310d8d8b220914ae087b207c61ccadc53c7bf4019f524a1079f9868dbab853dc69a34de7cba72d7540be146282ab20a43add794d8a66032ac64e5d072ae492322176d88
6f463430d2e2baeec5e16c4fbdce282a80db31b3a6cdf1fad692d261ba78821a:2122e2d2571c6649a02801:9353963e93194b91c1aa71ef9e9d66dddd868f368d58456effcf266024f131d1ff35e0adc9a6959b338049a4fc40b20619d0f509cbaef3bf5743890a414d6e7d39f2c4cf7e66e85aec70a33bfee3b58f3e84ebeb71c4e4edcb88e460783aa8f5
59e8933963a382d0d1634b52f6d789d09afe9f411de832caa89c88622470f70c:5264749d484be5119deec774:b716c49e3aec7684f8aaa1f61012cb8af522d73749717534c8097d95056611e3475e351e0a294937071c644dbe9db238023dc1a740bcb55c79ddec3b3b2cac01c8c8d975a4887166b7600ed1fe454b203b4e5ee49906dc7988bc72fb8b629d36
328cac74a8f771183690de87e99ddb3be023ca62c37c243aa2ecb3ab096c32c0:0d9caae939afd6f2036b4c6466:908cced630b0c17a0b862479d99eaaf1773b6053b8f5b6fbb044ace6722da5d1fb4668fdf4e468c4dc5407718bfa490b0d7cbe01c0919a8b8a5f342c8fc3ba06e2c4529f82536122061281e4c3ca1f607cd9c2b75eba03585a5689b9427877ed
2060526e5e104aaa6f56144304a6f4e2953b231fdc97ade6435835ac9d3ba7e4:0ceba10020c42ab9cf4d64ae3486:951fae47292841fd1b50ee4b32b06f961ab29d12a57c156a7fc2868b2a0b4bf42a472453a782d63bb7ef789c1e337faa040703b34f967e2446330b6120766266c70acdb659654daddf6446d80afa984cf89901149bc039cb7e541992363d3909
0c87d91d1d69e322839804c1cf3c90034f39a9279014ee549d284a20e232bc7c:07cc:88ba6e38e788cf59896005510a3396bf326be507d91e9c45d10aadde83513996011b4d2eb100197d2d9c10783a5ea27b138adae4497a49af8439329062d7bf3da2a3bec50661aacec7d916e5da0484a9e58a8c0b054717dbe30eae80013f9e82
15981c773dca2cc1948c4614f26e6d6cd0beec3eb672dd7ca5b1ebb2d38b6430:350fd6:aed8d80da4ab66cf0dabed854284e88de19a97663698c0dd91e59120b363411e46fd455827cbcc933f97a781a035546301ba0f1bc2d5fa9d48416eb6c00cc2c673529009e89034c10a40fb9baa4da241e20e8bb01f33e675a4f01ae527761167
14d83b474474caaf07e920cda1919759593bb48e125da09ac7013825b613942f:0db5516c:8ca43cd2679bbac2d9de3763aa28612e89a746fc2227b72e212a725c9acd6d9ecb983e4d665d64d76d64bc1c67d22ad701af6d74cbfeebebda30ba5c00de436c6f78b2163ee4fab88561e4121dcca80ac56df3379267e3be26c06a1034edff7d
29f5e89e7a6afab3da8c1ad738665a9da193af9a647e47753c235bd043e9d8b2:095ce9c7:81057773b78041728ae80f63e3bff13d9253414f592162945995ee98a8beddbd5b61f2753a7ea62c53cbb80f935d3d530a143945ac5b3532589253e2b7cb42bf2a0e463b0de9027f89cbdf710195c2c6c0cf823ec3333360fce1c0e6349a5093
4213489df97e792eda26d981492a7cdc3100e3cf4bbda19cf13676bfa5140584:020d6ab3af:81d792916be49cacb0d4f3950367bff32c035dfb083634912fd9bc043c0c5e60efd22199de3cc93374c1cced2e836b3e0c678e9b94b277734be7e127ede167c6051907587e43fa4532420ff77cc23e84e9622a16aa0e4c69de7c72da3d6ae605
4db4f6404c0c0fadcee5f26717ece570d846f5d0bba9ea9d93713a067c54e03a:3b8cefb4a9:ae1a72ee38dc209ba1c6fe7a295abd821e2898e18db1a479edddfbc2cf889159b8355472d301c905619b170b91e20cb7161a5c823d6ae8090c90f6846b0fd0fb930c28a2fd03c293737a1568b3a135ce04009757287e58a4a3e914a14b13467d
7101cdcf4291ca054a76be43a72be2e7c57b142d697d5f4591c416a2ba20a6ae:dd2ccabadb72:84a751209648d7dfdf43bb68863a3ed0a2c07281c5b8557ead46cb0168d4ff1d8491edb55cc69a0ea4eb06359a23285e0d844c8b0da3d91f7f7543e251f8652f210c0bce4f819f55ca1dac972fd4eddeb5277c9be73974df310fbfdd42090e9e
5833ac79250158123f356effd33c11b69f4970480a1724b2c0a0a1f3c5d86e48:6fe2514b0b040a:a655dfcb28d84ffcefae998f1d0c87359d4c522d549f1d18307c374d54f189403c4f95065a2b5b366272c1a0e1938b2a0fb4ba410290ed83ac3b55532d406d02a34001d6c6f150721c21cc86792a9ef94a3c1e498092c318957f4559aa3fb4aa
60759490c3c1dbc40d682ac8ec5b23e79df8679f527ce5bcd4b98da79172579a:03d670b0a31bb074:88adcbe23b4538911ca0555c28c4667b65993141ae797a71ee54573ee9b2d450c8f5902f24ec0dbf98a32ca7a4c84ba00c1675075b8804244f9ee5c8e746ab0ac18653802fa7eb2e8f44a1346b28a0299fe17fab2a2100d1932c1c8017c04790
0c8beec5b19b6d49422b9be911384dfdb5f7b784fb7931a9fee03f2b2b1435ab:52d257e3246a8717:9602df4f595bda5df4fd932daac3ec093fdc743d3b3880e3099324ef3d33b87385ff8fe7b4932044c726645cec05911d0586eda7726ac6b96dd8a7fe19f75b98bd21c926433a2995bbb75aea2c1cd6ad443de37d64fdd54b8711b225813a6efb
3e5ea9be9e47d5c03426c6b23851b839462cf2792e62c12ae9057785f0bfaacb:0edc3a78b6d6190566:b7aba102c730342367a96b64920ebe60f749b0d42ed4e91d51c18e31d791142895275fcd39ef09c7a6759d13651bdcc4022f8c93c77a0968a77e46202f8621ae7969e1410ff6cf5ed9ecf6df14905322a3c7dfdcd01afaeb0bf1bdd72545e7b7
4bf3c40acac842af8eaffabbe90ef74faaa20030a57e029137a61663db033997:0ae34aa529a1053f8c:b2de94c41c453ff9b60696043f6ed76a3431bc1ab53bbd9e7c89eb482423872a2b59e8546c8fb9b8b37a1c8b76f43e29147b10e64485ba5db48c0012c7a969ba99fa7718b7540252d9e49968b5f41722f454cc4b1785551ad7c7427e49ca4012
250d8a3e1d48cb69ae2841db1b6ba57cc0db311bc03570143204f9884bc5324d:0a9e59fb4f4d4ba10ec2:a0e4a43be108ddb82fddef1e59a6e7dd9fc84ad183ce393015d472b596b8bcf84a16b9a54a1b340ea001776bcc8d5e6502624aa4cc16bb3817da98669796dec60fb23c9d0a003cb78aae4c2b690d56e98026fb5a06257e39fe01e6530ed177f9
480a573b009ad6847742cf6eb26226401a21fcb00d15605d61d07cb2dd36ce16:a450b2f5e5993ef50a4c:970893411b7a3187dd195dd078cb9d49e64d6fa70adbb2b0e900a82048ecfc2d95dc60cb2cbb066a04c2b036e9d8c952155197e6dad3ea08385f7c5e8ebfcffac5dee95a3ec24a894e9471341f7ec40ed9d51db2985d491fa90b959b952f8be1
6f3d3d9ae77d068a241ef8832a9532f77c810f5fb66837401cf9824a77fdfc4a:8ebaad7cb6874e96ac767b:99e80404714e26ac20dc0c1d87b548a08fd427723dd4bf8093eca93c7903657b49c7c8eaf36cc98de460fff8b5dd0055169f9a58b0a249cfb335ebc06318bb1a81ab24fe7df3aa2d299a23298e9b29b98bc5c0d64d349b398fa763398ee9ddfc
23bc491c2142f7ddee2e8985a3175857f897c399f697411762554cbeb00de659:91b32862312873e4b7b3cba7:82a5feea0abebef1b71659cbbb51e396d1d6a9bdaf3dbc45790023d6a5b46b20dbbb6c368af1b034c6e6e5f8039d1c28099ddcadf7b4153d4411af1f79277571764467f1d083f5815ad45d265184f431b5c05166e708d55ba049c6882683d331
7272daf5146e93e068b6cce38fd07be2c254f6d2dc02c7d078f9e080bdf5408f:089e270bb1a4308c4578e0f6c0:916be2b7d46f009d2439a4c8b83caa6877b100cb0af4170ba0c5837bc92047d84e883295e441b44e0195dbefafcf8892126b27ca5bd2b126b6115b2a53ad8c5c889d3c78807dff9d72bc4e9a064743465ad025c1e2c08fbf99b0101b15264417
47655f711cd82a199e9418d4a5baa779d206d939f7f41a9b6ffb9f87d6ceea07:d90c4391d34e0b2b40366115d1:a33b21611a27397b7c02e0891582c1f5023d2cbc69e0643a7c32d7267e6d8042ff8e65839e5093d1a753e97da63ea7d600ff1c5957771f57850c574d167a8ee54cc986096f32ccc40cbc42d9fdd83acbe11f4e4ef9db36b9e41f7aa558f4eed8
59014aad89bd97fa2489c2b43508c31347ae8437240d8306987e63eca954dc6b:b29de70979d3459bf0f52480634a:94a813a737aab6aa68919278613a28c7a79e6e64b3f925538a498338e7eae29c0f73ab43a2d1f0e9a99d06ceadf57f8d166e8c4295b50269a117aff566ddaa02a5e6d4fd40834a96e3257ee219089e5843c3d1e1fa97f7a6b3119d4a55a0693c
079cb55cbf7d8668c79aa7be998336c9e44232f2040c19fe44b28651956888f3:06884140ea3d1aa1afa058dd19602f:add5d4e8f20484f247dbe0ae2705ff8a84f98ee988ee14d0398bf58ff2711c78064c3f9a284089267dfb1ad9828ae6f116f7118e93978f1c8ff92f1cc52c8860b509270a39523ad6473bc48029877a26df0f074f959532a5aafcbb348ad4f712
1d56829c94f18e598084ccc64e4d2fff82566d80a0d00446078fe2744ea47c29:04:8cc2f05194bb4fea2eb6c816626d6b17c33de7961c0597a74aadb51585d41fc0b04eea200fa70da10ba6701abe128a5409c374cc6ee11e516c408c11233a54175aba1f9acf49907560da8389745f9c3fe2622be20a68c9bc733d6a5ba63fed2b
1e243e4a9db47f767b6c9dc99f211312c3dde97b50c7bed9ad6585d5bbd2be78:2b:a8f31f44ad30aeccb0d801adc3d0d6c850532eb82baeaea38cf3829cffbe9936a4ce0b76bf158ef2e011245c4c9b7f5307c47379f4767efb52366dad98393d67fa56defb7831cd786375558f2c1b4fc76d3338a468859c014c8563d7be49ac97
3fa39be7a361c621ce0e944e01727db44e74baa23c82b4a48d9c0b350c680eb2:1de37a:ae2c347f8718815b992d93c9a8f8db741ec2958ec95123aba339537fdbc63f802c06f6cf41e65f0f6e3e5d567d3cda0207c9223f7144b1bdcc6a575b3e667f3d22724bea3e7bcacf28458e7112c96898d0bf5695159a7bdb5d7799834eba3fb9
3463763af0f0745e8e5ccecc3448d54521ec6360b31cd1f61461baa8d9430d85:81a2b9cf:b86cc9994a7664a88cc678bdc8074ef6fed1fd9d67487aaf51d11fba9c9677a8317bc3c6b93ebcd15faeaee195497a0e19393efb8a53aae96610701b7d827fbc72869c454bc3ed54abd119ce51873262e96c00e378778b7d6d7c44e8afd3da5f
43635608d29694b3fbe8c491bd2f56aafc95017e99a7c53028fc8aba1a6a655d:cc326cb7df:951d25da783cefe075e22de837614c0f03791a0e7113a6a6f5505a39c199538ccdf58e08a0e4f39acbb9459be5fcb4e30db05466f472c7cafa8cca9d0fa7a50d2644dd71c6c1f212d9fcda2a4038fbba2f16c8acc2af3098dd42257cf1953f6e
5062a749d8f40402f17c8793aa929f5cf33faed38663561a38d590bd26d1bd93:7bd0c2a0cd58:8e666a772334f4a599fc3360efd49c00e0062071dd6aab348acaab791a9faeee4c5156a7771cbf5342d49dca753f312d0e436cdb2d00003d25d41e06ed593d5dfe59f2a231a5fc890c59f6c784be18ec502eefe1fe90c2ad6c2f7f1b3ef561ce
01064d4e8efdc6631fbfbcbf7389572e82cd5107f47356989b9eeb1626ae277d:1db604a6a3737f:8c8891f0bcd2331d4395a75f47d9206da3553c839054ca8e7e59ee64f991d69b0ed42e43e2c96956b216626a3da15e2403a620650189b389a13f14c39a75c44cda966f7dc69a93e79d6678f0420407d66e7916057ba8e2eeb19d0bebd508058a
07247477ab86d4b41a3ad3bced6c08f93bf4dafe52bb88215faebef0de956746:8fdebf997b921d22:b50e9f99992a08959991fcda9654f5462ecc015d3b894c3477752b29a65dc05248c75d7acf152d7cac32ec45df93671d0fc07dc7e0a46ab0f5246951575e290b74ea6483ce7512a106529dc5f342d172ace7f5a72c6cfa9a929b00f616411251
49bc2b3d85e073e9d9bca649fe7d77624cd0c4186cc816ec767ee5907be6d4c7:08a6d70240e42b76c2:aa666c6474f8550ab282b480c15355737b1c3c3f496d0924e6dece36d052eb6b8c37adba328759dc6f930c1bf40e866a04cf9306d728be9d00d56115509c74c54a62b0456de48556e728335864f4f99f3835d03e5742219a0ba1fc135976ac0d
6e1ee2e476dc25bb44a8ce9a100ba3719b0be25802292723688b6094fa1e47fc:9ab597b9bc1f9f0c04:98bb5a200468cc4a7bfff04f913d87c386a5f42fa67d39c22924b24c985726db18c066b45fd4715fd94c339246cd683312120e2d6abe091f5fd3b0d75c4621fb716e88588e9449db8ea0754a06fb5372000391c781aa9109e0675b210d8a6399
51951b1c9e647dd724bbb68c7dd976d9e10f0eae1ac3f6fc1df04446c8f6558b:0d01c99a3ebabb5bb8d241:8a902cb59d6ded491e703682530990074ac486fc8ea5308f8797df59019e429a536f10a2acb5b9906d3a26bbf38c6bdc005bbf81104edd3b384b46553d6b66b2db8568c00e74037ce07eb9fca764850e9921d412e0287d9ed2a1bb7c3660d7fd
106b77fe23dda6e79c770e3e7d8d0dc5f01f6a21859f1ea2e37211b7e3e9d20c:9778045c939a60ba245568:84586f8b09fd69b3a38d317e89d3f3f5885bc6aac18c9a3ed5d0801df91f07c95bd77db9864ea986ceb9a4bd19fb4ea419ec7c46c35e477251fa47c05d7b0a6175e3ccfbb24196aa3b2b2cb48ddf9c8c0882a6fb32707a83d0260980a9b5528d
24182d5dcebb1f234add96901337c0b173a5dfc0735ab8476a44e8d1497eee11:2a590d539dbcd9cdb8dca9af:8b10c6a7efdf6afbbf600543bde5d43ca322a83e6b085e5dc08c0eb9b2cec92a69776e1dbc64de47a4d2f4d091426d79182531706ca25ef3ec81306da03edf70161bddc53df3bfd1447530da7ae1b94344cab0d829060abf14827a87568c114a
29f81c0bdcb8098de92efc9aca45df19b581174bdddfa7f9dd4eafa217f46231:0c413b91f979ef7e3e3d0c2a43:8dcc40e3267a209ecdb869a11199a018acd9bc872a2738296a46769ba1f3d5f6ebb75471b2c063dcd3ee89ee34eb032918d78468608500ec66c6496c28d3f56f1baf87a4097de60617c0938895a55f10d54c362ed86b3899edf48fef00f0607e
2a9c0a14191b6c8d9da54c2e7323197fc5972d6c2113b8d3f4aba8eb2419f402:80d1192fbe8c7edd9ae58a5fa715:84b02c4f728778a29ce1273b6e77a393941a87173764e4e10593faffca0a04b97e444b1f512e6f92de1fc9096ce991a90f389e78e5745f64c5b589a331aa9e157a71a993c96917024e67f13c97ba2e070fe1e3b2db91e0b95882f1f3d64727ef
344bb9ed7b08f405ac402c210d6ce9a251700f8f39d9c13e72921f993b0fa657:078698bed3b7f59cf6041cc5bbc27f:a0946c200a29a99ad8d348d3ec627c0944cb42a6ae105f18815ac85798d656b33acacdbb954adbbd65ba6bf031896e1c016a0dc7b667ec3662e54b8951d93a3e03a2c8bf3c3b88af29c02e5e3bc6d221166902d98a94842d855ec65506ad6911
41e6f409f3a9ec0d1b53ec441b6302e388941b23005ac48c750924bffc28c95d:09:8002a5f881006ea6f1c6f318e7529b1c8d9d1cb7cc93d75fce7d14286f125e03c47090f9e2bb89350ab85ead94e172230cdf1e9d76265579cee29c487e8a15884d6ff78646e634d01f7d66a9e155bde7908657f655aa711ec53fff05d31a3d55
01ef1ede58b87f0f257a1cd96d71c1eb98fac782ee687a639833fc73cb64df93:79c2:afcea670ffff566a171fabc5892ce1c974aaecca3d86a968c479f9689ef37b7980614a837207e53c2f7ec0701daf17bc13ed6e80f50853a606c8d6d690cb3778094c161ad162666f46c2f76d315f24b8ff90cc57c1e57e15bbc27aa94d41049d
1bb7932556e42f4f4fe9ba0f59ff17bb2245fd79203f78e8bc3de488fee40f11:8d0ef3:97dea1e05ef0d1af9289e64866c91e7b8fe6275aa87f6f70c3a9f16b411692332a0d1e86666799faa91eada62e23ba6705a69a55de44696b2d2de12bb8bafe1529217c87bfac57bac8d866b09aa208ca8ae62156568fb7172ceb0f411a171299
6730284b18c2d383fedf4e0c32480b06e9d05b380530e7acb9bb055400fa33ee:05866e46:a81e828917d5e25475db2e23e35f36c069150f5ebd846061f00bfcf270d3124b42103b48f915bd73236fff0f88afab460508c356998e8951806ca54967f26eba9ac1e68ce22da4119b1b3ef4721bc286a0455048a7542df4af460e1b53d9c351
1b538e8f7f079ccd4a564273a913e96a54c654a0c028e39d2e9597c9ff2a9813:c20027c1:b0636af64caa68aa331a61d5b6d6f826ee3a4838a6d1ec9693559227e80737b244829f72976c7908948e633040f0a47b073979d05bdbeebad1c49acaab6aec7a1dfbc45554bc102e0e88e924f49bb7ab492f7e1011da3814ea05071bb722c8eb
4adb9229610309100770fca18fd5e6e707e7f27f4b911ec0f53a6114a906230e:02c7973ed4:94e16548d624b5493cb0449579376d234c2ae597b347d681f394ef3e55fb3279bd361d83e3194b32676c1210d616db8204064b33a8f0d67a21859db0689da9447b3fce39972996967e6a85a0839f9a0253bb63265ad751661e035c8326ad1fff
0fc195c56cd4f54fc81f4f78a4abc2ba834b5b0018bfc150a64e7c6a5823933c:ed0afd7c4881:a40286e1cc833d2adde1d0640abbcc2199b2767b27ef540420dc96f12deb14af17eb655cd2e958a52a68ba2bed2e3e160344101b101eacbc33f3c5277fb1ee6bf6d9b866b5b8f5794f55a5d7236d3ca0de4356bc1e8cac30a2cb87f94eff4817
64813900e765c40ab4e7eb9522e2c21c1c30756fd5fbe40489441f11c6908ed4:021256b10a08ae:a01a1eed626ffdb57dcfaf3123c4ebcf03eb441f287bf36f2209f4d36ea874ff42c3bf8f90a7fa164f0d133692e0cee50ae42593571b8b876152fd37ae62af446ac1b9f2aacd9e335e67e7735ec92e3b5aa85fc4b97379a08dd2c8cad23cbf30
4a06c487852299ff3e247514706ef7aa6da0d2c1a1f7176b3317cc095d01a51e:5a04c28464f32d:b8b7111ca66dec968135c1b9716a3d162ad946f8e24d7587b27c0db7a39c70bf7d97c1d968691c569f913ae5255c3bb1120cf1f87fff3014a37d5f8f79a5ef9f9d1f86bbbc6c5b3662d1fa3de2fbdb3c20d0960671cd6dbc1336f16f3222f399
19ae9daeb0826f765cd2fee0f6678724da5cc4f8ad39a339fbeca86754f8b19e:39c99c18e1c62745:8b04d6db47c8acea29079dee12e9e31e435930bbac9ecd2dfb425898829b629ce3264661e16e6993be9540aa52828061079055fa69ce690fbfde7befc621147a02b94c86e43f2d7066e986f7f6857ac521e005e08c70a8558a19d549067bbe68
0a39e99b16a69b706fce5095dd0e7fe85b4dc521702e3bc99a6fa919415c73a5:619b95b11e4f8c670e:ae67f2f1f4d8134691100ad694bba172b1997f4d1888bffe4e0386382f09bfbcd56520a7a3647d2cf3565c7f8fd47d1808d7ea678acc1c17e272484296378fcf44f1719af50db7ff6ea3d64d5435e33bc20658b4fd6294ce6103138be0d74401
26828c6e8108d8e5965e8b91fc59b95dea696580517437c42c27bdeb650d3cc8:65267bef23e56c1361b4:843e467dc7ba66fa39dc0daf8cdbaaba07dc8c38493779320f8b7d148f9554e1a4eebfa8589f3fa403ce1fef29f649f00692a0342041527416e476ad36181eddda07556639f921c1d09b4f53767c9436c1b69925a3b391475580796bf449a960
28cae903780d94f5a17c6f07cc27c0c55d8860decf2f923e1bac274533f04509:ebdabd1cb56e3150770e59:85075ccf9926542cf2f6e13463f4ac970cbb8d65711f84911c31fd0639a009102745cb328ce660cbd9b63b2acf87fa2b0e65f7416691f14bbba4b4e8e5a46b35435a2290e43022bb799bae0c697891ea4a0ae90022d7efcf192ba2ff730b9183
43b47b97088f55c15c22418b81078b9678c7539d5b6ef30b3dceeb248fd7d610:e0f4c7d85159379b8d4dfa2ed3:8f0e1fcaa287321526d7f7974f68236187022c8ffe12e3dca46423745a4796292224f4e875824df2f2d5944dd547c80817e4bf1c4bb5f98dc2b17b2367bf048bedae6c0827be5f2128949fffa9787e4f9b2aaac78f19128ced220cb1cdce9376
365b875da7ee5cf2a37716770bcd2a49012b03b5bbe828026ba4a17a999b2b1f:d5cdf315f32aa5e54d3b993e15ef:a0dc1746699105974d79a75f5a051bca821dc341d5e2921ea45ace70828d87ee672c293854fc18921f56ea6edf067e8209c2692b9e1365483d4dc9c6e70e1092a5b678318778975aa44e51a6c273283d66348915a9b1f66230dfc1a4f41b0423
4ae51471cb64596dddd4ba384f6914c62e635fe7fe2b48bfed3560b9853c9c5f::80d9dfb35f77f8087eb5bb5bb7b73b3361c7547aa9ce1e640052b348b61f113d22be6344300458369b64d5bc16bbdad20c13c1c0a7310fdac807c9660c5ce709a837d487d0bcc69d247b5973e470d982cafe077ab1a5244fe7a21fe99af4fdce
24e5956ce7e1c26764a1212f5b70c8c635f53313eb8ffa24bd4b22178a70400e:0e:a1bade1469fd0949d6916cf467a67ad56245a9c234a9fb1da011489f5819a01da10b40983151650a3baff01d4931f117084e15225f8b2143196f8c55323e5e1dbcaed2c9339083504b97dfa31d01fe5b320660ac4b348867d97aa5bfae4708c3
1d25ef5627abdf5331c07eb922d70e8c141a952a16aaa63602a664e30e193964:02a8:80970283042e91719fce9271122ae72d780709ae2bfe8476f37abf6384e4c1d741585f0679010a15f18aa87e132bd120030618a443a25096f1beca1958c93f28696f2e9938242f7f83d6287eae5e3f1093c63bd3c8c9841ab9a3f9d6afddbae6
2f5307f7723b2702ef203499e5f01314f62ffbd448c859debab940d0d13acddf:9b71:83c20f7dfd803feab7b92e4619d3fcdeedd617056d3f4a863d2aa8c762ae2f0e9d10fb639fb1cb24cf775da646c887cd170e169aa3f99665227a8be8b74f37eb64c45d431afbb453a10c1059dec817550eca3ac5798fe97b6fcac44b05c3f39e
4fc8dced9af2d9b5839fc71f2242f29b210a75012360b76fb73e7a0f67236ab8:0518a3:8282811085e6a7532edb00ce977b1cc0ca00c5c482d572764350f0e15e5ecd745bc0ba1f124906b72f10e704d7ad091805b1990e4f5749526bb3f33f3e145ff3a364bb0850efe302dd3f1de79e77df272b27c8a33d1bd1bc9dd594590949f92a
110f155f50537bd283dcf6a0b32d76e33369875d25522912c8ac5c5999d15c92:060ce567:b6344848642b6fd3b15d5cfe8f58ba33803bdaf8d2499fb6cfebba69932fed5a25cebc0873cf7cae39ad0317e2cd62de069eb4563cf7efc33a644eea6bc6f3788805bdf3ca2371814854223fe970c39d66d7216da597865c7371ff3b3af6c7fa
7222141d6c07c9311bd3ed536a0a9038844c025fe2241ba3e172a74c5dd055a6:a6623761:b1ddbf83dc85a9f597a16cded7074f8aec09c5260c7d4d896fcc5b9857c81c77a9f48339f65e916c5e464b02ee4275521072edadb67d97bfa0e01250e5236f90cddc5afd7c4731ea9a4cd97c54c229c4a1f0793f62d124abc6801c392bd84394
39643613cc7ca678aea24c2350bdfef54da2740dc84bea3eb0f5086d8f3757ae:ff5a601d9ae5:93694096221d3ce0fbb2ae96d606102bafccf7f4b286a44cba04dd41ac7ac52d2fd20a87f0757313d2b9cf16eba1ae68176845a18688852eb7fca668232088e707cd9367c7638ff586240b3012602f114740b8f23142fe5eb4d1c92a0aa3cdb7
2f48137f2c80335ceedb56aea36d1d37630ceb603d25dc38c5aaad9edd6740f2:c596c4507b8c21:8b29ed205d9763ebe6f59787bd54490ccdeab56855382ab985cf6dcf02d3ab01b3074b858d2493917b156a9caa7dc0d513f3616b61f279410580ac6286175a8326ead7fb8b9319d3063da2d94dcc9331f85c9ac82d84ad1a3c0c14c00cbaf106
5e104f67360bd7be86562856628f7ca8d6f6090e58d78d1bad5faf7b6d01ba96:0ddd0c7f788fa3c2:8abbf1c71d4b4d62046e7557f34ddefcf0ddf8b7991ae8674fa3d73de1865065e98f914fa49772348b4665f102f2ca1515d21364050ab724a0ae95002ac7f2bdfbbe7d7ec1bb8f6b343c4409ad993b39b0d2ebd4a1a001909a1570760d29c246
2301e3208dc15a69334232fa6249a28238e7eebcbabca532719b50dcbb6eab16:03c1ad665dea01bfa5:820ef925b76285789c449fece5f0765661cf3ce95ef7b6482c6c35151e61f5be1f7f08a25cc647d1e2539e5e4811fe771829d666c84f6db43f351c41252e3fa27432a399af25272dade4b6d1da95aec40d6b83a5b82dee79b7ea3568e8a8dd6c
5a0155ddda1e372e176dd4841998d8373a4db70f720e13f8191a323dae9151f8:ed74bc9283fe9f0df46a:97bf50cf9ce75ddb14e7fe58fbe911aba7f2ff24c5982ac33803ffc578aa7f956c2cca4d436ee7cc0f66c3378470251a05b6570964abbdfaee44f9761581b89468833d000ff8f4f6432c5bbb7f084757328ce3501c055d9b8d1a44a797e7b93b
1620bf3cc64af7a12e3bf1a65859c37c0deceabc9765295f24294e5e408ad93f:0723c6a62f4e556ad97947:8abf62b2bf3d9c3524cb6639f3c94cb4e215aaead42ac8608d0a8c1495f766d7626299bed2eb309e3b3566d76ca87de7168bb651726d0427f6395ff81bea526afe56614486444fd1fdf01a2f836e35fd7dc740be034b02a2ccf585bb490e6f07
25eaab4800d7b399f81ed647c1c2062db996f9edaeba7411c9b1e47936963816:51410ca4fbc1eef3fe15e8:8d0e31286039c789bc46dc89914a3a7afb47bf3c1b6e3e06b618e5310f8efbbd43f484bd182b1a25d4977fb4d6965e670db5b4fbb9be287d8f3a5596e118c43032d199f93fcc8a60546d45c4b0745b4fd8432534175e9a620782bbf5c72b6c79
1c37c9dfbce948e9b854a16e5705d39d6814c99db8cd4d21bd17e4b489be8ec0:f29274076eb714c9a1e0cc7c4a:90436ee33fc91061cfeeec29ee065bbf0fb1504c588a057bc7a47e6d706826a03eb75916b5a0802e6bccd600e479579709af6bf0e69892f863cea2d17c7cee0b4aa0d01ad38a100c1f0a92a0d9bb8a662a4802e68fc61a6f89ae5a967e2ade24
4e6237d14a3cd9ea629413caa7c05627220e7f4e87ad60fa17a35916e111d5b3:0b:ad095916915d21a753c5ed1036f8ce695bc763c753dacf18fc696a691cb2d9d4d305255f0371ed05459225b52f45a9ce102fced5a32e0776ef97b2f047c73833a90196bf6e7cfc424dc3b9538e4a49a41c584c093be2851d08f3ef7118e4a71c
0d1bf48acabe43f47aa49c94e212dba63a3d375a788df8905cfb624c6e7a2f0b:ea:96c1a767ef41d3b3ea6fb01cc5c76951fc28189a8e34ebd0a5dadc330242ecac0fad824f4c6ed4bda3bcfda260b8e2b40b4a9f7c1a27976edb4a92e4cbdd4316dbf58bfe8e3224324a9a5c1e5e1fcadf4550f6c95ff446c1242e94b8cd84cae3
2e5cd6061fa48f1596cd81dbe4e689696a8cd79f70194d18d1992404244a1395:0388:83ed89345a2f35aabffbfe3e386351928087554e65d611365620360707e0d7d772379afe3565f5d40ec75977f3a24edc1172fbe9e78a8392934b67934c81729cd3de2cefda2ae13a749d20e89492091b71d56b23e113a5caa28a6392c56f6a35
584f578299fdedd0311bab4134250c8b3ef4580aeaffecb540a3050ab09bca6d:047eefc2ff88:8b67172d81f3ddd80ec9ef70a36629546639638086d97269bcf8d1d28c15a33dfd6ec0fda6a06277b0d9ed68537e92050d184ffd30e108e28e33c3d3c21e31f537f6eaa58652ff4c91326cc8faad3d3a705b8a66d4b4287fdb17db3caa0e1d9e
368f0355b86d025ed847ebba2b7fba334ba98eb7d3e1dd7a4225d550434fb67a:0b64f53253494b:a96613ec8e861672d7f25356e438682cbdd2fda9f1cf0e64662b770910203b25dc886fb02474b8c9baef1e91d9bdb6ad0402c5702d1aaf4c640679e7a9c54fad7d0069226cc74da8bfbac94bc4397cc1f1c9c39f5e2d9e2d7fe40145b2905aa1
0126eedaf3dcec0112ce5f44f181618cc5eb70ef0ef899f7329b3f10067c932d:09577238413c7bcd:a15c5c64ec5e4efd56363ae703343f1d87a8571347562d3aaca2ca4ea24c71249a55e9fbc393207bddfc696c151dfc420feb0f33f27fd24f184ed877bab13a5cce779f0a446ad0dc7577d5658dddf0179ef5bdc604d492d9a3a062194c4b5cbd
06123d03bdc50fb3bdfdc8fe60892ecc110cfd9b941d1c183470e79ab184fd64:010c6409424adb9edaf5:854031eef2a80b533862df645b40fa90c50c5e9572ae5a5732b9686db5a479282b0d46bede9df391a55f220c322369a900a8c3ce642af7154f5ea728711da75a6463608f3eac64af631b47561abad7a30d758fbe0379ccc545839fb3775bf5c2
29dcd911b82d242702e281f02493107eda90028b53efd067f5a8b1b3b402f87f:9919aea3f2c254e0af98:91308917daa0c1f3833a3de67893c754e2f362eed5f6df9d410200fb9d0ba0e4587546cc88d241a1a0cb496960524f440ffabfc0d17126c8941a5cbf9913f547cd3fb59f856b46bd5d6880f566b88e419cac04a49c6ccf37b539eb3a80b4e7c7
3caf69b84927248e842ccbf1e5cf6f793cdc69b0966ba04df1f7a2669e7a9a38:07b4ed6bedd1e2ef2db8488baf:8dfaa7179531aabbd23bba0e27d43e9eab3de719e966b47c0a76493092947137815b23f4fa5c74f4d2bd96ef6d2430ce0c5dabcef379d98395caafa8e68739fcf2c1f3e840e1dac9ad703b2e090dc5ea437e008d5b8fe2f0b1be6708552033fe
4d4792f59fe96d8f7418dee1d043e49f62ee63f0a2ab4b6271314f34bcb9409c:6930e7a417e42a0eae0debfdf30d:aae8cd57c22303af560fb04e7798bb68c649abb0fc1bbaed005db7b148e0a0df674ce75b8f023c31b8d4f35961c9712c0d6854d78d19f465ba844547acd18fb873cc1013b6f187ca491e5accaa20aac9fe43d254c916c9563d4ceb56b058836d
1431fe22a4ca0320403bbab6c29089ca1591c5fb447f6dc35d102959594a6d16:028773ab2e2754ac5a75a715d78bff:a53aea82c839d80b8603699e271df8c7ae119be1ef69c912d3c1a68b3e1c419fa50f10435497853206c41524cb97ccef19eeded83fe6b4af2392e16ca7e660d3e2c79232665c396ab9b5fd3594ff2ea93067d8c1080df6dc8ff55c9cce9b35e5
1f4d0636ba8bdd4ea49221a270176378c01a7458e3a7fe0ce4d4ffb088d1d4c0::99781a5e42b7dd8c022bd519ea9acc6008a7aa116245e8f14a12f40d87b02bd3ea071d3dbbc09db01395e6dd8b3485ed12ce0d5943637cae60e682e3d2b7530fc1966dee8b53b4f6f6f755865778691a7b5b3911801be279a0731a9aefaf8351
2c8dba24af03feb0bd91fcf67d8b1ef2000305bbb8d4e0851ef151c21457c49b:aa4a:94442f44bd4ea1447f776ceb43590dcca856f02c1220147ab020438c7d52e61d002c4833198994b207422ab6d408fa9110b3d2316c740ebc11352c2658e0176fbfe9ef2fb880ad61c6ddc4ad362a5c806534ad8a37885ebafe89b2eaeebeb35b
6968eed29d12fd07d53fba6e07fde6bf6f37d8a3d9f53673f6bd1db6c28e2cdd:84f05a:8ca8d57e7189f7648c2f2163d71b7868aca21ec8f196bb067f43aba576301282023ebbdb688ec4baf1bee5da5b719b1600a529c1169b0dbe796fd79714ad4ce6b67cce01c3fc955a33570923ad95a13b8ef0e7a953d56fbe3bd9f3fffdb8ec2d
5770504add317933bdbe89f35463e784d798ce20b5b1dd258569955e8df4068d:0f709c6798:817f1def1b321a6cb1d47dd1558e00692605b0072f9fe2ac07859fa30d1b9da5d8b8fe09a0f7eed404190a72778609e1010ca80ad5528cbdf5d54e4981a52534c096631e38a9533e52bc18b2d52309cc452f03949f6d50fd96f0251c765aaf8d
24612966cd6601308edbd27423d622dfbcb27746b31b3e9f6939b571cc865f14:5c2b9e06cf:b6066c1bdd416fa78630fb1073c20fc1813596b6ce0bbd36c407ab18fbf488ad2f4cbe7526bfbf168c2014ad2f887dcd04825625e8a83728a7940c46a689512cd4a2025830a70df7ab84f2b76964f7acb839fd562def8b9021d3575a9d794d82
6716da7e6965ea890857c0fae1c57828ce35279eb69f7dd8ba29c8aef11fbeec:2657f15d8adc:88198312d9975e2ec4823c5a0e490323e745c4fe41e75e25c4ba0c5dd32030b02597c90b24d2952e78c6cb91b90f920d13514e193eccd54212f7cd3a0dca90197f920fa7c0e85dd0c8a8009f1c98deb823a5eeb632b73bf44b102ed38c68eb67
6a6f8a98610a5a4acdf6da669ea3990fb299e1aedf2ac327c97b0ce96adc753b:057de0b81f4f9a736c:b834e23d96490775c3f0b2d674d2506149d2345f94f157c3b124759ff61fe2f3d0773b6b9bb0e1566d370fdaf273f55808fff04433d5f8a5537a3142cb299e8996c42a420ae36e6c9335d2e630600c287bf283b745f5d5985b7819a6e889efbd
6422d62c14662cc8ad1fc10875ae58813fa9ee349c019c452a917d2b7ec98404:8956593d05c7b5814d:b6abb8bf4ce2feea01a0f6fdb881cd276c6576bdd92e460e3827f6081d44263bf21498d5bad1c3b534753214f30b15500b0bced8b763ebc1b292d5676021c1a2db09e35d5d3f306b4d1436087bdf8b4720e4ddf3bf89c323804dc006ce9a6a91
67cb55964dfc93f1ea615a89ea49b26c677ccb4a2a0f512935b45b3a54bf70a2:02c10d2e5e685de181b0:adda564e2367e13037727867cfdfc0a22be7ada7670a01a66f3954b54745256ea89ffea82dd5e68e98f4663fdcb4ca3d017fd21d25b491191c69fc3eedcf8064a5991ae58ae6ca81e05605212e166a6cb5d53f6f89fa96a0764c26674092ad45
295b144cdec443e032d21c906e46b3594a1e50b3e6f29118028767f189ce12b6:07d1ad37496c013d3f099071:ab4b0c1a0402c5a63a76c88a9e2c2f36b20f22f1a1de61f620ee9634605d7d9dd12e27dc2d04f1d96538f9d28a1e93a10d5fb540051787346a2633759c2fa8a2f85db615b1e901158b4c22455402cfed378f4acdd4524de4a39ca4b18644bd35
2b614a7871bf0d74e53bc6c7714372353b4a22ed47f1f627d3bbb1ef7532dc77:624a8baf7884b4568d2e6b31:85aa088a9bc03c585a4238a49e5e6aa36434609590a3fb8611d012442ff6b841d23aaed5011df2eb61e2be3389f684f600f219ddf20da10f8cde2dda151c74153020e2cb7e804999c9a99bd02b12a11ed65f8b1e73f8b27dd819faeb46ebc7bd
422ad85c60720ef2d06cfc26ad0e7ee1af49cfd6ba025692d405b1cb41fcf71f:0ddbe34431448b194f1b29bb60:b8fa03a4ddcf857e50f142ed3949c3c43937ddab3b67491634137a478b0f74ff12a4eb17d030bdb3859ce2a3ceff5c13136b61832182c1808fe914c5471cdb963870f2477a6d59c842e4e23fd7558488fdfbb46899aaaa67c55b48b9c94f594e
3a6ccf539c217a904fd7a718d2815c985325e3c9cfb7bf458a219b8ae78f775e:df33154deaa3d687d45a694ab80e:a269482d849517a2fffb267782152bf07daa7bbded7df8a18b7d74c9e5a4f46c09d6f795f7a9eefb8df107d10e5598f203cad912865152985d407f3d7303287fe9b0c16c650016bfd9dab49da95665e98442ac1e10ce427bb16c8bbe81130c08
41c836e9c4069d15ad4e871a12a81fd91fa062ba39905b659ece6a8000dfb125:01214f40af921429a48897d9d286de:95a2dfaaf34691b69b9df2a3356bb25ccb9f416e0c619a5f6bc1a25b267d95de7c5fcbc50d0e6de1d79afbb083255b22158ede7ceeca628a162d3b7d4887574e7cd947e1ee5704b3970aaaf92e47697623089bbb032ee1ca15505604beaedeca
25563baa30cdb1664317a7f6a11fadf24dbd7e33f758ae9edffb4a3bc6e47809::ae9b09587dde61b31dc3a252ee5da28b118778ea40e6940695c0cb14e927810dc1bdc3580421e6a6349770e468ef624a0b1edf2a2fca77e3afb1d4cecddd443db8c5b1e92d0bbf123f9a7d3ecbb94b6d7a72bd0754bb5339e807baec26fe6688
324c59624d455e439661cd33bf2691779493f51ab154942bceaeaf9a3f8d2e5d:0c:89243606a295632aee72da9fa717b04274ca61ca99279b75705fdca338a6712f9d92939b9c868210ae1a80c2a315f9a10944326c7e753c7f7a62ed69fd2a0e27321a52f1305facfc2fb091722bda6f1edc3ffae29a990907d7340715dd763e0a
3d7eff177604e52315b47e30500f9d1419496f5da2d9d2b4691b9e840b5a07fa:07c5:b5b0f787446da8bae5a3468d5efac5b06769486650d42ca5d0e8a9b1a7b4c47b9e84def60984469ec8fa311753fae2ff0feb1f42f107114031d8e6c25ed3d7ce8b882d05bc169c2fb30e301b5555211d31e24c4eb67242d7ae71770426336f4e
017efc554478e7f73876fb6ed0b036ba4c6c653f5baa2c13c8a705e8d936900d:5298548f3f:973c337a1e2632ee2355af6a1b259c764e3d1f99ba9e1c9840b1e3df0d27e3eb477b670976e3d0099c49b4eff639260c07f19d0c474d152ce3656f422ab27e65c6288d61760d5a96e8af9560f4460ef4dd53a802536fb19eef9abd257653332f
4d7f9479becad152a443f2c759aab6e02a1f0feb15dfd49c11804d2a104b39f8:07bd8740d5e5:93b4364b292786fb255cb06ba55cfb0805923229ce394fb5370a3571c4773b7d8b6801318e6262a4499d73ff181b3bdb09347f73aa4a2ca7f6e99df8be366346ae43ca8faad4458e2d30d26adf049a7542e3f0ca72f86006cdbac3ceaf038515
63c95845cf70d1470e0f6de57729b5838f977a8706c1979388829f9b5b3700e9:08aa3ec1c57996:a950729885949d9a8b50a031ad184d1887b2992601c0abaa9e5b6ed71e5beaac0534ea2c9d93a7c564b77d0c5c77bc5818fa164575d3d58714687c7f549058eaf3d0fb432d328e3bc8da3ae7646ffde2297421a2c418dff28026da3d29d1d498
22059d7b3332f4def25399ce17b1e1481028ec4d2d8ab835a69b7ebdaa16b461:4195fc080b251a:91ca4b0a098ab6678c54643b2546a3535696b109bc49f3e50d8e6966a56ffa61ad37d2eb29b1c6a19793aeb30edfae53021b2a322a300bdae1ce9e9f67267727e682a4568845b1312e652ba439f6d0432c36342151234eb639c9cc8153ecf743
6bc4bc3efec07ce22fa5a5f0e0fc4a4142f8fc4c078e6915ab7f14c9743752da:0fdc2eb64cd67bee:933de772ca7a3f1fa61c87a5a4ef914b1f6074facdc6a98c6e8fdb886a3e53e5acd2766390d9c6c8e8b48a268c4c227b056a5f4f7895590e48b44863d26c44677091acd4585a85c88c8de2ddcc1c530b918233d7655e858ead521bdf1d66b526
2178be06e144b58fc271dd130182d6ce562fce547c545adae7df409c61262876:0f72ecc940599630cc:abb38edc8b7232a479a51b23e3d0d5fce3e6967190e2e68df73fb95e3e2367b2b1b6360fa0b06c508c664d90f8cc345a09e8b8255945b850ce8c1c5e389258767a709810e519220abad9ea7d9fc37d947038634ad059821d591a671595df762b
1a1924318927acc40cd3cb8265dbe703db0386b0d94199dba5d67cfcbb497032:387376ba00fc30b6c0:a2e6514012c1fe9484cb9df2925a80c1451d33cda78b89302cee7f59aea190ff34a71a6c4a46a77652785b44dcbcee100aba9beb37612e961bf83139abb690449e6e05a351d8408939585b026fc83b1fa0ca0d0303295503c65a40bce402d12c
30e446fc468b579fdda3a09ede2c456f9799fadd07c069c44794c1cabae3d555:25538c2c57aa03118f9f:98eafa9da5b2802b9932fa056ac3c81f09b4c4dddcfd5ad963de9374731c11720d7b85bfb5e3955c71f81a86f32b4e7611022aa8717dbd032e4fa4635dae9209df6ee3dd34598fdf504cdd4aa3fff1292d11f74f17af500703ccc127faec4c48
6440fb50661c3b9c45c557d216accce15185891f98080b6a7c1c6dd701e029d4:0a9333dc2d78c73c53507e:8e633dee7c8fa3270472078f93dd5181f92f43e7b42929a9acf42563367256c59b3355d23c18ca8dcdfced828b5009e4133de13a3e875d2a6880977f9a0f00d17649550419ad5da3194df083f685162ac7241d864c8c72082cac5ecfbc581db8
084caa7f9ee6060620c5db1416f5cadd4a54984c23dc804cf23ac5ec645cac2b:0f3cf7f7ffe9279288b56ab8:922c3c5844803907b8b2bd08df8edd00018df0ccc9e515faf8814ed865850fe7cae1240495bf4e947540c325a536d0020f1f15f5583cb6e5a127de49856515b933425ede9aad615c9007c533c85cf25a6380c7f7e45b48d644871f7f72152a27
2581c1782074316f855d5d184ed4066962371b58935c672672943aab3a67d005:0d85756630cfa82ed2cd35ef:8ff6a1d75fe9ac8362c40d9405b1d8d3633eb6ae08e12b9008da03eddf47f632d780e6f7f257d27569ded6414ebbc7330f3d3eee1b1bfeed420288ae89511afe701d34e6973df7f9379cf5027ba456cc958b09288191b4a7ae157db428363a99
396f95f097863db7d343484be8ea7c26d2db9e022397e42845a3aba66eac2165:e46812d0412dbf137a84b49d4b0b:abd154aac031f055c524185d56e1e4f259800a87bf234b04fcc509181626d4e519e97c7a32da1fba04e6e322e0a8760b0424065e8b99348548ceafea44d107bebdd119d47f7df4d27ae0e14b5fff497408e8ce381256c41721477971925345bf
3b79d30b7558a89767dec3f3d1f3393d13ee5e648786ed6bac49186f8a2ca2c3::83ecd612c577ef99af50938c218bee6b7693d2d5aa1a06144346f6c8e46e5f741ca66a154106ad512bf5a2d9357b89da13b797530e42d298f6f74559cf5452694de538328301df16a8c91ffa5a6737befaced0d81ba45f68f3587639890f6ce7
164811a45674f804c655c8c5ad3863b359ac9041c7f1e72c0ae20f80f41170c3:0e:9359a49c73685f2a8a9b6c46fb2773a56061a586ad1b7eb38d7789d23260f96741f4046ebbd119c06ebf64e9ed7b81f510cf95305be70c83193faa2d16866e76cfeab918c608d9b4dce6fff60e807358ae142eff4a8b55a01bb5da982e89aa37
07b300ed4a2db3bc21642adc74521eb70ba2c81a5e0f07b7759a80ecd27033aa:05:a9a3b90336d9ef805992939d52302e641c74c10216cf320696ce6262dd1ce58ae82099c2d0575892650a13c6daf2017c11c84edae1256b035f82d467737c7586992d84d0d521882ac2c0babe65e06d8d0df64963667972ed2670fe25b8dd2804
1ebe5d4cde886b9f5f4555e7c02bc14987dd021999a713d020cf3c08ff9a4f60:405e:a49cb23f9b25095c9d28d94ff6b1763cdc257e5824350ee79c726fc4dfa4307ce365283342978bf2534782898afa949204e5ff271d495a577dce076bc8b42ecffcf5cc6219955a4e914c42f41c3fafe35a1464ad06bb35032b56408e44fa8ac9
34df86999c7c40e1f0d423e8b788e5a617132c37dfe7865e4e6052b7b7c0c08f:09c6ab:99aca067bd01d52542141bee5e7941265cb45d058b090e3b5f2965d2c92d17f691e10f489148cac52a72c0428c470af2071d2f484b6bc772a4ec04cd9c9910bba345603371925c1c29789417f507d8539cf5981f07a77185b0adf8c9f7704199
028927e8f7fa65d681ea43b9f38590748308f9f304e54f52de2ba454d0bf966b:fc76ab2e:8163b7efeed623df2c44a5cd27568bda4a11b66192fce2b1d46ed98f8b33c7823fe124632bdb42abbb6e1d0a0780d1cc0ee9e9ed28aa5e818bc8aa24bbd8befc01f8448f4b02cab157a3d6c46cb52e085ae5c67fd8ebdba1077c8eb87520d1f5
2dd2d83fe918f321e588516529cb8d8e2f9dfdfc7e24b03ddf4de7d68feff2c6:0eee5a001b13:8ec481206906594421366b291c9921d6044044b40c5a43f45a603eca52de182cc744b38d80d1e1f2346119d3a127bdf0084369d7d317a0664aadb36b0fc421c6ba61bdc97a406ce1bd9a05a351ffca89a78f21de6c06f9da474098c343918c39
62f441d4421c9e841f5e6afa99346dd757ce3cf4d958815107f80ec965d52fe6:dbd901bfaeeb:85b1619d9be7bffa4fa4dfd3be3161d1be679a48c3e0bb5d637f55ef35ce43c86611a21d078f178908ffd329c709dc8214784af6b2603b944d84a6b70837a7c5b0c38baa97f0b0705c4619f8bb44d1f91f4b248d60ba3bbeb65f3fa189044216
2ca95104bc934be172b9738942c9d929aa6c63e8fb38be3435aba875613fbfd7:0fb528fd90c1075b:ae6ecfe94e796391077d18644f61bdd6e9ca6e45c18856af798811199a8ce77dc408bd139c92a086b1a8541104b3b7e6187f5e6484fd5b3bc6fe125a78a8778ae7a658d74cf0b8bd29509996acae061af6c1cd26365defab654390b8fd130c41
2cb2345b9fe58baeec3e0d35f6c2bd71f7a460eecc1c1f24687b71c6ee8dac6b:8890d3f6a2efd9c8e5:94e89bb4e2da9fc43ef06ee1f02377b7645ff17d8c02e1c3035417c445279d0ad26dc4622fc864de7b93599dde21135218024b6d8e9bbeaca09d51b4b616c13788c7ec29b63eb8f9f87701010c7f6146e33a37a7c8bfa5920dcba068a304f1d4
54079aec7ad7a051158086c3986871746ba540c53c519617a01e559a5cb96360:d449f821249be81a006f:9679c59342a6b68f9350777c5a85d30dce3a9d51082406f39fd21a695a9014175e9b61ab668a1ecf06b0f571b3d5f6a80c5c8d53062129cf3665032c36d9a743a452f0366bad6de34a8264de28a1283f7d1cd584a070611db23322af5472349c
608544d7bdda540aaccfc89a03a47946636c732226f4841b31f47a247e4a29ed:5dca12c82d6470eba98ac1:8dae26cfdec9849d7d4701e85c160f3db109aa9e4e26d9f4ab2c158008df740fa526f71541daefbfe61553d23b3fc94c194a3bc097ae33be51480c8f91804147f88e95b054e88ee0faf3ae718135fdbc92cbaa26277f76cae42315771599b2e9
7368161af24ad459f868fb847e287532a3d7625fbdc97f912b513f5ce525a9f0:0d43de10726e1ded2f111aa8:8bbabb617042316158491db3e4f83ac5b9ea8acefaad2225b2663d500b6119e48fac354adcf994968e3ddd88e20684f805a88ce038caf4bdab372fa9444a471636e979f1862b1519efed6cf003af1ab9cd66b9707a8ffe4d9e1f9e4a4c59ee8f
694d55ee8633e2f3ab91c1f79953d6368875e40afbb6e4674109132d5612aa9a:a72ea58ebdf4589cc1b0dd9b:b89f66033ab23bd10456d1cf977d9fc87dce07e1390f876815875a909128f4f5e5f5f1617c8862b01daffa868661a764097139b2198472db19448e7eb9449d32334193c10af650f56626dfa5f2a670ebd2eb1af484afde7f0410c2695a485280
30ddb0c578ed5b6d16b7c923efcc5003494faeebbdc509704126599ed93ba6d2:f2fbf39b84983f5edbdaceb18c:ae7880c31a54ab6c30fbe220415fbbd33a9e005d565f9f875c879b8e9ba20b22d6e054456f8e780faef0d30658b5e7920a9619f6b7608a9f84fe37ec1cf890f2382e8b77d570d6ff7cbf595e091cad7b74e70248c974825f8a93e9299ab2139f
4a7a6e21534410573a72d8af48f592489ba283a9ddf4cf8844783b0e4e076694::a630c152277ba70a0316f42a01e07b875bc31b8c5dce53dd5001818ff5c4144017c848c6679004a9eca6edda08dbf64c0fcf94f891d2e957dd2988f2a459a51836483813f211690295dced48aaf19ac31a1bed284ec16b6465eb1fa9c8ab67ae
064588d00f156a6708a9fc75c95e25050d795f89f427be6df0948500f7d5665f:b16a2d:865a1462974af0147f0f382dbd9661f5864d7f18d309b19e332d2445b8c150b3c16dc7870b5aa2b1d5df89bfd600f24e177c08e1009c9e666d755797d8d220fbc35171c1415c9e183e86cbf2a06f9ec574e4a462fd942d1801e7da6dfa931972
4c7469ccb41795860f7e228a4a50665828cf1ea62f64ca5af3dbcc90026b5173:e444ff3e:b06c465da8342a430774e64595e567e03a905735f443afd74e0d2dd06b99f8ae460062271e1e41ca7dad9e78ead9404e0e9f626b8af3275c84111956a7a146b29619435f357f5310276221c8c425023a792a561f7159ae4bea27eb6be013fb28
31e6a9f2bfd89057675b9986a2326af50fc5b4fa6900e06392500d6a7cb8281e:41e77882d77d:83a3cf3e0e9b4726f76ce301c93db6d15e563bfdb5f93e885c37f0fcf28362e54c86e30d0e6a63f831f097eb624c153e15f8061c8dfd215e7d3a3da513b8f35061b2376457391db393bbafcf43e032f4b3c39a8dd20a1f4e8df3a217113ca007
4fdfb35d853e9b99ce5bf7211f55d15aebb153258109c22be3cae0161928159b:053633d112c82e:b42f071afa8cd509dbfb7f4a4cdaa57d1d0910e2ad9307beadcf6ea5bd9518a2095d68cca7dad010907341aca3770134010b8fcae728a60d27f821d759107cfe8fafb2ed9aaf09f1765e3be3d758880b243c5377be3ab293ab6bafc85442f147
3c4a5789f7d5a24505f69fde12f2157e066612ce25e54c000812718f7b360a5f:038845e18495f26a:a141c5d16c5720fe2c37f0b79ed69ff6b0f92267d7b4b4acccc015876943d692174dae68b9bbf8c152e57f3fa1af159e000d2bd8ad67e5a884daf0a8c0fa9206b3f72c9d5e1a0464b2240b9b6eb22263e457c7c5c0b20564a79ae488178fe475
2cf6644db3ab59850d71010dc15b65ac7e5741f6bff4d9034bb65b499d9ed4a3:064263c5a80c376f18b1cf:ae86f1e1d6d95316820b7c9ca82b2c642ee2fa2894ba52690817b571dbe031b7eb608cff31af60febbbec43a71a55add10944382f9037bd4c9294dd8403810992253f743ceca93e9a9c02390e7d12d5d1f0de8cd03572eb401309e3898e76528
29bcd632044c3f3d1f2b6c37b60a1fa531cbc380902ca7ea5e417081337631a4:5dd355519020c4a2979f09a3:b6400ded257d0e63d8ce4ff8935e6b312be17f24395b26563fe4e532e176906aa0d60d5efe7cdb8855f900dff31bb4b017b7675545f874d80e1e5fb4c0ca85d64b4bdb439a723c337226f70ea3fd9509b364665b3aac65b2e272a3f6a5e902ad
420594483d27e3b09be201b4d447480d41e61748f5b1ac863ac5b5b8349986f6:66f576cac592391bb05fec22e72b:b121a5242c9ac3c6ae0c5801b9823bcffcab4b9a0f5a507196e29c55941397c526f9c47569bc5f077bdfee8085a7ea0200d31cd16c8071c5a8816e3b2fe90f196fbfc4cd3c1c0bfdb972e93f88b1e9b10ca5853f79c780ab6b799819f71d8830
3a7f21f4ad9cde926ff41a5b657d3665ca5391f50427bbbb397c7197aa465e34:0173f8cb823680bedb605f5faf82e8:a3bb11f1159447f09fef369475daf7cf10d51cc93f060d737d77a24268139f121a504ec373d094ce92f290d43a87f1ed136939270f0c1c33d57c285173ba3fb448990e908e5bbc9fdcf41096dd1684a5d0ac811ff3c85ace8ec7c35c80fd2d10
7143d5b6a3a6475478b34b5317d3acd571bab149986804b50381cc326550689c::b04c05cb1b41a8a683b07fc0c768496bae0b4ec8f4b509101e1c581297ab12cf6341df1cfc5496cd7d0edd5f41903f9e1440e655fe2e9ade8d2e09ff4ba64576423a00712b6f66112d72b792c2238944f6b5a6d12ffca7ead0ad1217c2a68ccd
5107fc58427eb056153b4c8e26e41b0de05d78339821f91bdc56cfc3f261f62b:00:8ceb7e8cbfbf9b3b04e70bc7e49df066799e6ab312ac17df4603c6af4ec3f5a0e0f6caa19916cf711bd15b3f54bc2837046d7e85b97f5570c3d13f1dc5d791db9a9089b61264aff25f3f4c5834dc41e1ca6d91bdc2e8b3bc33cdf4a5c3909f47
48b4784f1e9e070b95cb181904e3ecb7cf6234e327e2666ba598b88904cf0960:48ec55:ace8ac4ea4040d382f6bd290498940bffb49a25bca1903dfec23f0eca9edc0848bc6c1e6c1ccb7ea71732ff09ae369500e944bd739ebb760e41965978d0ecc6815a1174e3ec4c9fdd5967656953714b0c31f5a546fbe4505934f77628b554363
4bc72dda1b98ff6e1722ebe5ca4ae11940483948f73a6d44b87cdb93675b2cec:9883069a:a7499c26f769bc11a65e32e3c274987f5d272242016069882a28946854af8625eaa38953f1c35e4c8af78bdf3652a88a10a7c1a52be2dde6af14fd6298da96f8b7c9329b5cbf4e725528fafc813a8bb6151d7e9fb15123c7b60a2db34463fde9
25e95bec8613b28e98fc135365d012acb38c72551d71f41989033a59aabb75c3:0d8db89e47:aba0be6046df2a730f3f00284c64b8121f77c0b10cdf8ea0f60c7b38e1a2cc583acbf5a27819ce7e510503ade8149ca8198793f2d84ce1c071655da4795a7281b3dbb6a522ba9a091f8b5a37262ec1a43935fb89bf0a9dd2ae59390bec7c605f
4e1a6cca760e6b46c90b190da25d4277d07ed704d4377a414a0d7aebb38c5962:05161ae4b3c2:b72f19ff530219ff699a73e523564e36254e73eaedbf22d9c7a354dc3945dee58deb89a1c095779a12df44a1b4a6c9560001d978c499eabb966d477560f5d171276a44c94bbebe3461c2b6c576f0e3861e9ea76931a4f3949399a514b2a49b3f
4b063743b91c96b198a889e2d68cc9cafdda87c4e49ebc7904eb3fe516e78a15:bdd472d8486708:a28e113b23dbf0c2faae0ec7755c9f826845f85827ed0e3d4d2033c818fbccba06d5645db7afe08ee18b92a2046019a911f3fbfdc84ed796181c76506c636e4f07a32dd2b6b4cc03d59ca0272dbebe4f2addd35f9b24ed7d880314ddfd30b9c6
2d7b35ebbe2e91a94cd857f349142b354941e34c30916493307068d8a6cf2ebe:0ea8b5464c8ffdfd:824252f8347eb299d1105323304e2b7f6985ed6ab1860baee4a5cbcc476d49db56e1d834f5f6293d0e1c1143fa60bccd1551af939d5435d514afa710ff8f3dd80b76bd7c75f728c9abe76c636ed588f406efe7b509c1b747496bbb6b18ffefb0
3e88b2286bc087bc7f6476652e444155922e8e239af3a1ebaea2ee36cd0dad1a:d0e9ee7908a105c0:ab625e2a5abdc53a9b882caba06492c661233c7e4fac9bafc8c1db9ea44cad455cbfd618e917703fb732e0540e3208fb0f198420380962c078d15304a7bbe9c1a259e8cf2ec49fdca4dbb39ff69f1ab5c58f97fec90e1756666115fb0b63219c
5e3d08aeafc50403c0de0166ae2fc6f39615e6012a04f03552e6c8869a702a5e:02f34cdeaa6f8e5cbe:b5b111acd6950b2862627f2d0ba6fe5b24cd3541be4ee2ae887c86ddcdd480a0a09c8003f9639c88b35c2d233b75d2ee101a66be894f438e4e1dc87e9bf2c80db7b34a3486c213281aac163a276f0850ff8b6d7681ee73a7b2fdd0f7b832caa7
276b38d5aa2723f4cefa785cfc077559323a5c98328b3caeff1884c0367cab4f:4dadca20bba5e6776b:8a8b0a03047d87df975304f41187c006a310858272d6aa84f37c8f4a44e78ebcfa70f968dcf5b5a6b308c9aceb8bc9b4113901fe031e4deddc7fd40d85759b38df88d8e22b29166f2deae074320a742ef10610cf4793255ebf5eb456606c583b
11c5ef8785ec31234ef347fdce2a1534a49967245245f9523c319938daaf0a53:b936534e227a3c5cf272:98ceb3072a2bf95c95c6523451c3ef7f2e5e852e7e3ef77e60dbd26ae6a4020230c558b1d044792e48f6ab2cc755143102e9a2d79e2047d90c1c1dc2c7e1d0befe1b9249bf9026f74e4aa229c6798721a694fc1204df374a52465fd1d85360bf
33a895e2e1d632737f6f11ff5a6857f971cf37873c1b95df2cab888c6bd582db:0acf93e56587dc54e775f1dc:85f3f86e176ef7934ded7f5cbc419f99d08727770b7172645b94c235d73f1311451dcc54a8735e8d2bceb15caa53a04a0a402b14af9e7b49323cdb728b004a09a695761b5051eb944bc861ac7b656c162d0e4a9578559883f9419b3033dc0c83
356522ef840b1ac132686085f346558a94f2943b48b75988c2cf512cbdfeb678:07b7666dfcf9541697392813a2:903225b431efb0f426aa962edb914c1182e6bd208aab9ffa0f9e502ad0edf4f7cd1fe139ec67597c0c9ba2f2b96b890216aadc7fca55a57c38b236056fbe2aba71f033b143fcc73abff454269a8de40e7c92777c5b0391fd3bb4d6991de096bb
2724b641a54745be949a396375b50735b1e4bba8b5c9df6df1ada80c4f9edebf:7e959c39b0c4f95e90e05d4e6b:8359dcc9a9c233b2d871991cd5587f83f2544bd1c0bf83e006dbe148609ee40c5fa7c72e4861061b6e226d8a3d28736d08820f8f8cbde45af586ce9877e8783df86094e0b28d3cd40c04fbf5450961d26e9b61901ccb80e457da79ee1687d53a
69e59beafbff787b405498a1c4258811a7855cee59cd24100cbc29e9a5338890:af:9899c81ec05be74370c381d6da9e537ab96b94a3a140baf23bef0a8ed396c885ac83355c0e4636f16fc609de2954952f110a5a9e928729a7baa9bfe7cc91151f1243e4e3e109c6828dd3a4b847fbb9ec0b950640dec5706e09fd97f00ea85c89
3732ed34c394b61efbe6762470519f7cbc01b3238ccd16bb3811e76f78b28969:0f07:90b715bae0ff837187f346b8312a03450a61a6bc13f4b65e788570e4d04dad2098f29ec0024b4318792c4d276c5ebb8f176555d6eda15b985714cf68946d40f8ebd451e9d01ce383cde7c14e0701cadc68fb0bfd3d43f69ed3159b24f73b0ad5
4e4e37b3e34497a6a2b9f29dc48bcc66c68b108ab5ae3ec7de6b9163c8089f53:dd2c:84386746faefd739875a51b6bf0a3f10ab8fd8ac06e7f9d3fc8be1140416429c33ba4e9617982cd9bebbff8b3b40f06c16627e316c6f4828d771314e56b2ca0fdde30b7ab5d7ed0c2046c70d1416cdbaf68a760fc9c3f16578a588c743f1e5e8
0d64a2304ab3d884c758a634c8e02a39df28d28f45326ffcfa227a4d09d317dc:0c57df3a:8e666a9f47f8b5f671e69c2aa41bc1db30a397555509fba48b1d017010ee52970b190bd133ff5a33459b700602a13df20079005abf2d1273d64fecb6ecf0bb61c6f1d6f6cc89666aa102accce758bf8fdb2fcd82fb1fd7955c1256d18c7da5d8
58298a7fde5847078d221ac45fe91d7a5cacbe6facc6b0d1c1c846bdec788bf8:71d0ada1a638:9017e5e0d91dcda6a826f290bab407db01e3163d4f1bb47d6a2b9d8ec455006e078dcd193f8fa27655f6991b512e92130fb0e9b6d168a7d1df3c63b476cac683c10e061081c54ed0c648a07616a1de01f0a39d5b8c68bbea4253b1dd260e9a2d
1f7d8693d3e0e5f58120e12386830ab8278db6af93a9aea5e317009d5c7abd90:0a9f29d796cf7d:942bffd18f0d166ecd548b79aefd37590814cfc02d793125d7e01f3f46e83ac50c9e4d4a7d7dbab364411ee8c3f57c200d05c047af7859678c8776d98de90f6830a74649d917ce8f950242b05a1b33f164970bd1aabdcc66f2070536ed175d9f
2ef3156af349a534508e4448c8eb2cb32f38bf79061ee4960affee1592fe8a33:0f8cdbb84ee69ea1:b115204c338f8930528efe7c5d3a4a42018fe1944b738edf3128cb04c804ef73ffa2209f0f5eafe2d825ce73604db3a503cf47cf3b34b613ed5fe10a3f5e9de3c27d8ef2a3894d1287fc045b01b97a4d17ceee0f03d31b81cded5a52758e1fb9
6087f431c3cf8344bd95e09c9b5891150c4dc82ab8cf49d4edb3445848525787:06930ab93e2941fb:b8aaa4968d500766e2cc15e5eb3b6841bf90fa2208b2699a1498d824509b79bbbed192e2e5142a6562d49826d020dbd30d06f3804c321b560c81b4ea02e281ae2d635cff541f82e5cbe2c96f22dcc8b41eb01e4c21957092c7bacfd4cbd367e3
2fa90ec2bb82b7523acd10174510e9e1f3cd8d914d5df1c1add12294f4201b55:31116320fd8ffbf65edf62:820727a6167a7d5d65e5718f3a8003e0a1bd19f82439f2398a0f7ea568aed18e177c8562806785afbb4dfc8625c5ab9c0a0afca6fc38309ed111ce68f3780fa49b1a48625fd960436c8033b0fbf78c58077633a964a513d95db6a0f22471df30
3967f728a6fc9b97d815a8a76c5df791d8252cb44fbab8a52bee1aa59228f26a:96dc2c37e0f9efb8f177873b:8dda9f419ff275828006089d7e4e1342b5eb17dcf7c51a2fb7c5cd6ebfcc2064b987c3b2d100c166b8499d82d705905511682b1210616c5674b11c3f6b472fd92879b1532d2c60a2c05535d8224832efcfbae410cdeeaff9428af6159f07621f
1cc92dbca460512827bb5ae49b2f5ff3b0aa556470ebc4e08d06006794fa95e4:0cee8bc396fe6f2e44bb0c608bed:923613d71c89bedf640787cdb031492059309a702410308fd904c2b29c6d78a75d2fd5e6758e759a91c07c8dc55310120651f208d9f1184ce02f02bf287c20f85f05c660838b0baf964b1785dd4b72ad18a4c86410f14d79d5b6aaf8a8093c9b
2d94bebfcdf3a3adf32af3036e6098bf51bacf2d8e97fbe53ecaf302fa176076:c1f3a335ed2198cf83bd46540c43:a40961a61862c95fa04a3327b9ba847d986cbc1e789b9a4009182a1921fd728e051cc3f879ed6fbae67b7ed40f8cd3350de0d91a7a58cb9ed3c9b6cf267a84c7021a7a83931c0834a79a432e75a8ff1603e974a3654da2bafdfd8d122ed6c4ef
16c7703dbff0bc635e0f1616f11ccdae9c50c48030b50d17f40a583f4b8a8a42::afc773584e0e50446d784ff525edad44d3c774dd141e13346c7db92be76f34b356844d2206473f75c5b66f8962ec9cef082fa43a05398273bd066ce7620f59ee443f663c9c278ae9a64f181d332eb0cca3fbe3616bef48d5ad881f12301c4012
2bc35b91d5972e10dbf0160c138ac436079d6c43e4eefbf3fcc9c06767bb31da:06:af9b614adc4f80d9554b0167e1361d0ffa413f9f36e16930d707c4da190fb83701984916a2584fd24d65f350a6dc93e606877656031e847dc9b31485213ddd3c318fbf27addfd209e80deef7c23e174be7e7f34639a1af09dd6fa018bd4ed1db
4456acde3242387fce74bb201e5624c1097686e3ac5ce87d212f8fd1d2d4378c:85:99b45e3ed1021db6bc869adb284f025bb9b930a8782dc9646d1d5840b67b2c1e957b6a1200cd67e2c05b1e2a016bf58206d0067bfb59b47946e99fe99bbf8d1689ec20cb1bcd3312600b24e8345e43c1cac95f03c742e9cfc4629465a35643ee
3a161a88b0434351865dc4b322ae2db86d38e26b354a8072ecb007bd8397c08c:0eea0b:962a8ab094224d90904a2a48d6b63efff7bb702ed993d9cac630dd219988cdbe264be9505ecc24c82821591e3c70b385093bb570ecfeb81f50f66f74b9d19335fab464b782f98ec0c7233b83b895458616ba23205478c048c7f43187353e5159
4b9dfc470db493399476bd07c30de9b8463e6ff0e1a5461d7cb25920caa74e9e:0a77069c:a2ea5c1c6917c5c74352fdcbbf0320c86f09ad9ac0c29b44941d1c2fcf094a03105a3a1c7829f70c21282750f912f64a16b0d077b38e2e94b3841f3ddbbe29538bed0c3a15b9f3fb3365812c26423ed8769588ccb0ce4007500bcda73e934c5c
182d193ba7412d09b8cd8b486c72f7163ab7d572b08b95b4aa8e41118072b63f:8f1ee0cb:a9eeb586a08cad5422594833c53cec8826e1ee18d62eb695226df14d68e8973c067c5a88522d72a424170733b05723f41925613e55bf883158bbb77a7944e867a71f5350558594467329ea8381f9f8ea064300f46e0b2436fb177af41b6465dc
4a373adf9961e3ef98ae8009188e948ce309d3582d63d850a13fe2c304dd7065:08cbc08a8e:81664cbbfbee94ca1c567f980bb39e686e390e94e527a30d4e4f3dbf3f5a48c4adb5fdab07992633788a45750ddbbb1916d3ab5e77ee56d166ac28e81a3246dcb5e183a3692d7eb7f192a0487d219d79514c657d20db0c4ff1ac3d4af5fdf33f
520133987bf9a4eccaa0da403ba0a0c44dc83d25ed8345976ddecfffe207fcb0:4f03ee2e2a:a1d71d93ff022b10538bad0580e0fe30c476abcdab5ed8114a5ebf1c5ff8b2818bf6bd963c9c69f38ca8fca73da91c1612fbdb7b3323396d1b27afcd05679dfb360bf79dbc0e2bd9b6afb8e64dad7f00ff9e50ed2dd199f53c45a58cc2d09cc2
5bbe2155b1ca1a37d4cb75762dabccdce894cec7452561bac5651f92b4ac1fe3:0cdde70cf2bf55:8474f69d3efaf0005b1c62e54650c5d49ea3117049923d108f00e7c67f9d57aa967e675d5b72b9619cafeaeb11ff057f10f952ddf35de97125a062874492aa7f90836bc1bdd1b942d877410706547f6a0ae0ab25e993c3a4aa65de7a180237a6
123a411e3335542f1dc720d8354437476c9b81d568daf817b2db83981629c3d9:fd67000db24705:a5d2ff627c1a4b7f52a71d158926f2949aae9fdc3e206f9fdf9117ec88ae8c8cbe4d23d17c713b2e09e82d557d996dd71847b7e86bc1c74015c09abeeafb72873da6945e0fdf5b5cd91c622a1cfa9bc258cc6eff0125377d2e44b16630360381
498848b5fd8f6fe2008c039e5f972cf6d6ab2e909acd594ba8cddf7da3233167:640a244c2ecbeb26:ace162832f586c088e3ef9d558228a99c6475e1eaed0f875c512fed3f800f876409e8f5b28831a6563511ec1edbf16fe067cd73fa6413030c0892e6c67b8ca3a14451642959e50cbf18c7e6c0052dd7ac9b98145694cb5f83feb506c13238811
370642447c6763c7f6ce66b4013df4b46a4de47ca9f34d2c2d1fc130b4e2c9e1:395025a2d1d88e0635:9259229b65e9c1e95c876ecac32d33acec12d5ba217d9aacb30f52d356338954feadd6f9fec797d974b79bc2ef0e41f60a82c3d4cfdcf3c399bef3ff026f0082cff184a3300d0de1a863fbb498cbc6c87e28967ae4250c8ebacb8ed3f4a4bfd9
3832a8792ea9547d7fc8b3fe8d5df2f35660272dce5bf6ccbe7941ac7700b194:0ea3967ee0e677fce984:8b135befb49f3fc8ca4472935515b3c90c2d9ac6e13b0ed17da999fbdd5981b580ca387c0ffb3fab8c2b44559cff3c211404f792f243d32f5b775db0bab61ee480238540e2281ef0953cce57457d78ea77ff1342f695c16af62b5a9f97e94961
409c98029b0014f8ee36ba5040a2e96deece25c632cf48aa97b58d95648be79f:0177c0f8148194de3e6477:91e278b31a481a970895fc0e5dccaa045a05cdd70bda29f64ec239a5c4fc0d5189eb6c3cbce3affb3294ff4251a2e84c0633db7d2363fb53250d092d3f3b59121dc6ad3a4a5b8455f280b03d173d71a18275e7817936016e7db825540885081b
3174e6aaabd794e3be89e48aedd486ed9d9aecac2f8a3d5f7a179883765e136b:fd1c24b053333e986927fd:93176d6cb5987f8912225a77166a053f7de30345718c4c081f8dcd71c1b6560a4c8a1cd096e7458073d7b42084b0ba9b15f2e378e7a2a2f3df81b29e594aef47e877545b9d56e2427364e4adfcd6dbe5d6ffd2190fea6e791a695a3135e8111e
49d8f16c96e0bd5c151911fe49f9d3125188b7461168badd9256066863490658:0e2c67ef06692c5c01ee1881:88b6ccc20bcb7bfda958cdb80ef563d8364655bac922d065a05579b9de50b81c5d72e9f3b7ec5b9a64306e79d67d48500f89e80ad1e06c1f94a2cdf1d4522ef8f19467cb7206cda4ba86f9c111cabf418cc60e46b3e2ca8e841f7cd2e4d66e48
18e90f391db888d2173eece1532225b2c3eb31011772322ef7db8985db83c5e2:3cf06f1f7bf3f1fd5c1c34e0:98090e7c9348e3bddaeba1a423c1dd5d34ff397d48d9b295f7725f9cfeec287c34ef032a7a1017e98aa2b8db17d8894e0b0b72559cbeab2a3a6af1ff5b33373c24602ebf87c2341078d54c6d825ed6f883693a69b46dedb9e812fbe8627eb5ce
2f171467ffed42c0aad55340a3d29f42132032b4b1c0cafbbfe267d5d9b9d975:ff0fbc6886cf7119c13cac2047:ae45427a61d4acea474a57867e7276ebaf10f1065478c6cbec3861d14ccfcee9d91b2052fe976e145ef8c88518fafcf812cb469d5881ef0fd8ef4563634e498041e7cd2b0d269bfe592aed2d7cae94f9787de91528e15a18efa74715bfb8f289
675943c3633d2906548ab8fd99d59c902c3613d931316631df8d892d21971f37:0662c76b721017ba5a676b65b5b3:b44020ba6ea5bb53aecc946da3422dcab97cbd38678043b3476d3e5570d5c55a422f5bf7981fad6ef90b15a13bb904bf17eb164d5e1824956e3972bf2971257b051593be8d2bf025b01938216bd30d65142a40575d2d2c752f5eae06e5eaeb1d
3d9039b23297115dba92c2d7b4ad882749bbb47bbc378da7a2e2308fe97762af::b68588e7e1728b2fe5769dd3c936c209059f05d89fa1c97e73de4d6ebae113d25a3ff152d59e8e080644b9ff405b60a5016700792fd7b3e15e1644492d5b49c9d529f75ff089483975721c55405de377d4601b983d4151f86b11ff7f259b2880
360763630528bf256a78b0c8c0b8bde84d1db6edea081a08d7a9903eddb9a85f:0f:b70412c89cc6041217c89898d9b4902c38988d80018c29b5c9a160f641ac867a5b6e7460efe1e807d4b16927ba057abf0ad222b6c81eb3cf46bb18ea5a1f4640b62ed3436360f359baf3dd7443f68fbd490acbd7a25901bf8f3daef6157426e5
673f104c3fda7085a1b6afb787ea36dda1eecb87b45375e4204919b19bdb4f0d:ce:a3097321693e4dc5f56e65dc09014d517c942f731b6d7aa2a630cbaa5616298cb589475134f6333c8fd3c95a851c9c0b0e300cda7469cfa3e426b1d393361738077e8610f1b61ea3a75ed9dc8d7c19e804dba831dcde6fb5180b272f336f7778
165ccbe631f789288f180dd299248be3019185f0326aa2cb5c01b0f381e3f952:0858:b42d38c4a715d724b80a8ba5ba3937d51ef57b82c473fc0e363b68112c61fda0c0a51d252d5893075db03f96b46458420af2dbb16b2890d27ece7710d5a16bc208a903ad0ad0173b35c40bcc0abff09c6871382ad936aae88464320667edfd45
3e0db6c5848ea10fbe9dfb7fa937cf57e96cb947f4d47b4f7dad8da1ad718a75:b696:8c36fccafcb8221a13835cf8f2ef34207e62d82ae27b35f9c24c16c12ef4d24d45a253a0ace92b3260dd63a65b4e22af14fd2e743951349401c770ec39060e926ba076a4ae4ba9be82761b891956254585fa8e2e73ab101a8cc80a1ab523c16f
4efc64d65ec6317d11c98d299bdbb177b48afafb4c77276885a5bad19e86d898:0013ab:84ec582064629c67d7f2cd893680e3f1296c666fc23309063d8a26144cd0075abaaddddf2835f41ef971cdb3c8929d1e0637b3bbfd1f01ee02b94750fead9b7f331e145cf4551bdbe9e77ee7e1a7c18b81792d02437f23c8a14b90883f044961
1aa58cd8fe28bc296fdfca3d5af1841643527635d15d7ba7b9f52781f920503c:0276ce38:8fa25f0ec24a14482424d15128f365ca70adef6c497c6a3f2ad3a4129e0f44d0552adda1a2242e7936cc38014475a2d402794449c904b8db66387d4fa6cf938f040e9adb4ca3fa0fba4ae3c2a4a74881c261d3dbfb155ea922936a2238789c33
20213ae7786685baef612a88f1ef008dffb01d185db47155300674b934996e68:19b49baf:8678b97a5e70c4287cc3ce06ff106b811ee91a7fe2b4a2ada4e933c17bbbfda3fa99be519b80e2a3ca7777eec5127e740a3c6d0f5fbbb3a125aba2bdfd325c1de980e2ccbc34023d06afcda5c4d70cabef3961cd73eeda2ffbfaa7146848bdb5
0bac27b57ca7109489235328a4fdf27ba4a84ac64cb3d89f76c3c53d148d83d4:09c78eb62a:afc8c64ca140a9706f972319f48edffee405b5eed88dbad1c946d9bb8bab48bec8547d066bde4cb1cc7e99eee0d53faf01057a99d49bee517d424d0156e02486733a0fd4f311951ed4420a2125b092fa9041a3e01fd3e642e1c2d844b3dd64d3
27826e51f6e6446065e32c5b8e60aaf0109008d4eb9c2336a437ecb6fe415618:4f77125824409934:894e75525f6c5067b5274b52f39f3d0991ef27b9396ead5555f0dac07d07a962f3cc00b20e8324b69873abff1f8285d904428f93fc42354bb1cc50d95149014dd25b7000b161c4dbaaae54a90bcbde7e8c99c2111181e4e1e08648b4bec81cb4";

    #[test]
    fn test_min_pk() {
        // Source: https://github.com/paulmillr/noble-curves/blob/bee1ffe0000095f95b982a969d06baaa3dd8ce73/src/bls12-381.ts#L358
        const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

        // Parse lines
        let mut publics = Vec::new();
        let mut hms = Vec::new();
        let mut signatures = Vec::new();
        for line in MIN_PK_TESTS.lines() {
            // Extract parts
            let parts: Vec<_> = line.split(':').collect();
            let private = from_hex_formatted(parts[0]).unwrap();
            let private = Scalar::read(&mut private.as_ref()).unwrap();
            let message = from_hex_formatted(parts[1]).unwrap();
            let signature = from_hex_formatted(parts[2]).unwrap();
            let mut signature =
                <MinPk as Variant>::Signature::read(&mut signature.as_ref()).unwrap();

            // Sign message
            let computed = sign::<MinPk>(&private, DST, &message);
            assert_eq!(signature, computed);

            // Verify signature
            let public = compute_public::<MinPk>(&private);
            verify::<MinPk>(&public, DST, &message, &signature).unwrap();

            // Add to batch
            publics.push(public);
            hms.push(hash_message::<MinPk>(DST, &message));
            signatures.push(signature);

            // Fail verification with a manipulated signature
            signature.add(&<MinPk as Variant>::Signature::one());
            assert!(verify::<MinPk>(&public, DST, &message, &signature).is_err());
        }

        // Batch verification
        assert!(MinPk::batch_verify(&mut OsRng, &publics, &hms, &signatures).is_ok());

        // Fail batch verification with a manipulated signature
        signatures[0].add(&<MinPk as Variant>::Signature::one());
        assert!(MinPk::batch_verify(&mut OsRng, &publics, &hms, &signatures).is_err());
    }

    fn threshold_derive_missing_partials<V: Variant>() {
        // Helper to compute the Lagrange basis polynomial l_i(x) evaluated at a specific point `eval_at_x`.
        fn lagrange_coeff(eval_x: u32, i_x: u32, x_coords: &[u32]) -> Scalar {
            // Initialize the numerator and denominator.
            let mut num = Scalar::one();
            let mut den = Scalar::one();

            // Initialize the evaluation point and the index.
            let eval_x = Scalar::from_index(eval_x);
            let xi = Scalar::from_index(i_x);

            // Compute the Lagrange coefficients.
            for &j_x in x_coords {
                // Skip if the index is the same.
                if i_x == j_x {
                    continue;
                }

                // Initialize the other index.
                let xj = Scalar::from_index(j_x);

                // Numerator: product over j!=i of (eval_x - x_j)
                let mut term = eval_x.clone();
                term.sub(&xj);
                num.mul(&term);

                // Denominator: product over j!=i of (x_i - x_j)
                let mut diff = xi.clone();
                diff.sub(&xj);
                den.mul(&diff);
            }

            // The result is num / den
            num.mul(&den.inverse().expect("should not have duplicate indices"));
            num
        }

        // Generate the public polynomial and the private shares for n participants.
        let mut rng = StdRng::seed_from_u64(0);
        let (n, t) = (5, quorum(5));
        let (public, shares) = generate_shares::<_, V>(&mut rng, None, n, t);

        // Produce partial signatures for every participant.
        let namespace = Some(&b"test"[..]);
        let msg = b"hello";
        let all_partials: Vec<_> = shares
            .iter()
            .map(|s| partial_sign_message::<V>(s, namespace, msg))
            .collect();

        // Take the first `t` partials to use for deriving the others.
        let recovery_partials: Vec<_> = all_partials.iter().take(t as usize).collect();
        let recovery_indices: Vec<u32> = recovery_partials.iter().map(|p| p.index).collect();

        // For each participant, derive their partial signature from the recovery set.
        //
        // The derived signature is a linear combination of the recovery signatures:
        // s_target = sum_{i in recovery_set} s_i * l_i(target_x)
        for target in &shares {
            // Get the target index.
            let target = target.index;

            // Compute the Lagrange coefficients (the scalars) for this combination.
            let scalars: Vec<Scalar> = recovery_indices
                .iter()
                .map(|&recovery_index| lagrange_coeff(target, recovery_index, &recovery_indices))
                .collect();

            // We then use MSM (Multi-Scalar Multiplication) to compute the sum efficiently.
            let points: Vec<_> = recovery_partials.iter().map(|p| p.value).collect();
            let derived = <V as Variant>::Signature::msm(&points, &scalars);
            let derived = Eval {
                index: target,
                value: derived,
            };

            // Verify that the derived partial signature is cryptographically valid.
            partial_verify_message::<V>(&public, namespace, msg, &derived)
                .expect("derived signature should be valid");

            // Verify that the derived signature matches the one originally created.
            let original = all_partials.iter().find(|p| p.index == target).unwrap();
            assert_eq!(derived.value, original.value);
        }
    }

    #[test]
    fn test_threshold_derive_missing_partials() {
        threshold_derive_missing_partials::<MinPk>();
        threshold_derive_missing_partials::<MinSig>();
    }
}
