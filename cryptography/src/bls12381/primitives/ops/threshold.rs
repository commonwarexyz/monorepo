//! Threshold signature operations for BLS12-381.
//!
//! This module provides functions for threshold signature schemes, including:
//! - Partial signing and verification
//! - Signature recovery from partial signatures
//! - Batch verification of partial signatures
//!
//! Threshold signatures allow a group of participants to collectively sign a message
//! where at least `t` out of `n` participants must contribute partial signatures.

use super::{
    super::{
        group::Share,
        sharing::Sharing,
        variant::{PartialSignature, Variant},
        Error,
    },
    batch::{verify_multiple_messages, verify_multiple_public_keys},
    core::{sign, sign_message, verify, verify_message},
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use commonware_codec::Encode;
use commonware_math::algebra::Additive;
use commonware_utils::ordered::Map;
use rand_core::CryptoRngCore;
#[cfg(feature = "std")]
use rayon::{prelude::*, ThreadPoolBuilder};

/// Prepares partial signature evaluations for threshold recovery.
fn prepare_evaluations<'a, V: Variant>(
    threshold: u32,
    partials: impl IntoIterator<Item = &'a PartialSignature<V>>,
) -> Result<Map<u32, V::Signature>, Error> {
    let mut out = Map::from_iter_dedup(partials.into_iter().map(|eval| (eval.index, eval.value)));
    let t = threshold as usize;
    out.truncate(t);
    if out.len() < t {
        return Err(Error::NotEnoughPartialSignatures(t, out.len()));
    }
    Ok(out)
}

// =============================================================================
// PARTIAL SIGNING AND VERIFICATION
// =============================================================================

/// Signs the provided message with the key share.
pub fn partial_sign_message<V: Variant>(
    private: &Share,
    namespace: Option<&[u8]>,
    message: &[u8],
) -> PartialSignature<V> {
    let sig = sign_message::<V>(&private.private, namespace, message);
    PartialSignature {
        value: sig,
        index: private.index,
    }
}

/// Generates a proof of possession for the private key share.
pub fn partial_sign_proof_of_possession<V: Variant>(
    sharing: &Sharing<V>,
    private: &Share,
) -> PartialSignature<V> {
    // Sign the public key
    let sig = sign::<V>(
        &private.private,
        V::PROOF_OF_POSSESSION,
        &sharing.public().encode(),
    );
    PartialSignature {
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
    sharing: &Sharing<V>,
    namespace: Option<&[u8]>,
    message: &[u8],
    partial: &PartialSignature<V>,
) -> Result<(), Error> {
    verify_message::<V>(
        &sharing.partial_public(partial.index)?,
        namespace,
        message,
        &partial.value,
    )
}

/// Verifies the proof of possession for the provided public polynomial.
///
/// # Warning
///
/// This function assumes a group check was already performed on `signature`.
pub fn partial_verify_proof_of_possession<V: Variant>(
    sharing: &Sharing<V>,
    partial: &PartialSignature<V>,
) -> Result<(), Error> {
    verify::<V>(
        &sharing.partial_public(partial.index)?,
        V::PROOF_OF_POSSESSION,
        &sharing.public().encode(),
        &partial.value,
    )
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
        s += &partial.value;
    }
    Some((index, s))
}

// =============================================================================
// BATCH VERIFICATION OF PARTIAL SIGNATURES
// =============================================================================

/// Verifies the signatures from multiple partial signatures over multiple unique messages from a single
/// signer.
///
/// This function applies random scalar weights to each message/signature pair before verification
/// to prevent signature malleability attacks where an attacker could redistribute signature
/// components while keeping the aggregate unchanged.
///
/// Each entry is a tuple of (namespace, message, partial_signature).
///
/// # Warning
///
/// This function assumes a group check was already performed on each `signature`.
pub fn partial_verify_multiple_messages<'a, R, V, I>(
    rng: &mut R,
    sharing: &Sharing<V>,
    index: u32,
    entries: I,
    concurrency: usize,
) -> Result<(), Error>
where
    R: CryptoRngCore,
    V: Variant,
    I: IntoIterator<Item = &'a (Option<&'a [u8]>, &'a [u8], PartialSignature<V>)>,
{
    // Verify all signatures have the correct index and build combined entries
    let combined: Vec<_> = entries
        .into_iter()
        .map(|(ns, msg, ps)| {
            if ps.index != index {
                Err(Error::InvalidSignature)
            } else {
                Ok((*ns, *msg, ps.value))
            }
        })
        .collect::<Result<_, _>>()?;

    let public = sharing.partial_public(index)?;

    verify_multiple_messages::<_, V, _>(rng, &public, &combined, concurrency)
}

/// Verify a list of [PartialSignature]s by performing aggregate verification with random
/// scalar weights, performing repeated bisection to find invalid signatures (if any exist).
///
/// Random scalar weights prevent signature malleability attacks where an attacker could
/// redistribute signature components while keeping the aggregate unchanged.
fn partial_verify_multiple_public_keys_bisect<'a, R, V>(
    rng: &mut R,
    pending: &[(V::Public, &'a PartialSignature<V>)],
    namespace: Option<&[u8]>,
    message: &[u8],
) -> Vec<&'a PartialSignature<V>>
where
    R: CryptoRngCore,
    V: Variant,
{
    // Convert to the format expected by verify_multiple_public_keys
    let entries: Vec<(V::Public, V::Signature)> = pending
        .iter()
        .map(|(pk, partial)| (*pk, partial.value))
        .collect();

    // Use the generic verification function
    let invalid_indices = verify_multiple_public_keys::<_, V>(rng, namespace, message, &entries);

    // Map indices back to PartialSignature references
    invalid_indices
        .into_iter()
        .map(|idx| pending[idx].1)
        .collect()
}

/// Attempts to verify multiple [PartialSignature]s over the same message as a single
/// aggregate signature (or returns any invalid signature found).
///
/// This function applies random scalar weights to prevent signature malleability attacks
/// where an attacker could redistribute signature components while keeping the aggregate
/// unchanged.
///
/// # Warning
///
/// This function assumes a group check was already performed on each `signature`.
pub fn partial_verify_multiple_public_keys<'a, R, V, I>(
    rng: &mut R,
    sharing: &Sharing<V>,
    namespace: Option<&[u8]>,
    message: &[u8],
    partials: I,
) -> Result<(), Vec<&'a PartialSignature<V>>>
where
    R: CryptoRngCore,
    V: Variant,
    I: IntoIterator<Item = &'a PartialSignature<V>>,
{
    let partials = partials.into_iter();
    let mut pending = Vec::with_capacity(partials.size_hint().0);
    let mut invalid = Vec::new();
    for partial in partials {
        match sharing.partial_public(partial.index) {
            Ok(p) => pending.push((p, partial)),
            Err(_) => invalid.push(partial),
        }
    }

    // Find any invalid partial signatures
    let bad = partial_verify_multiple_public_keys_bisect::<_, V>(
        rng,
        pending.as_slice(),
        namespace,
        message,
    );
    invalid.extend(bad);

    if invalid.is_empty() {
        Ok(())
    } else {
        Err(invalid)
    }
}

// =============================================================================
// THRESHOLD SIGNATURE RECOVERY
// =============================================================================

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
    sharing: &Sharing<V>,
    partials: I,
) -> Result<V::Signature, Error>
where
    V: Variant,
    I: IntoIterator<Item = &'a PartialSignature<V>>,
    V::Signature: 'a,
{
    let evals = prepare_evaluations::<V>(sharing.required(), partials)?;
    sharing
        .interpolator(evals.keys())?
        .interpolate(&evals, 1)
        .ok_or(Error::InvalidRecovery)
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
    sharing: &Sharing<V>,
    many_evals: Vec<I>,
    #[cfg_attr(not(feature = "std"), allow(unused_variables))] concurrency: usize,
) -> Result<Vec<V::Signature>, Error>
where
    V: Variant,
    I: IntoIterator<Item = &'a PartialSignature<V>>,
    V::Signature: 'a,
{
    let prepared_evals = many_evals
        .into_iter()
        .map(|evals| prepare_evaluations::<V>(sharing.required(), evals))
        .collect::<Result<Vec<_>, _>>()?;
    let Some(first_eval) = prepared_evals.first() else {
        return Ok(Vec::new());
    };
    if !prepared_evals
        .iter()
        .skip(1)
        .all(|other_eval| other_eval.keys() == first_eval.keys())
    {
        return Err(Error::InvalidIndex);
    }

    let interpolator = sharing.interpolator(first_eval.keys())?;
    #[cfg(feature = "std")]
    {
        let concurrency = core::cmp::min(concurrency, prepared_evals.len());
        if concurrency != 1 {
            // Build a thread pool with the specified concurrency
            let pool = ThreadPoolBuilder::new()
                .num_threads(concurrency)
                .build()
                .expect("Unable to build thread pool");

            // Recover signatures
            return pool.install(move || {
                prepared_evals
                    .par_iter()
                    .map(|evals| {
                        interpolator
                            .interpolate(evals, 1)
                            .ok_or(Error::InvalidRecovery)
                    })
                    .collect()
            });
        }
    }
    prepared_evals
        .into_iter()
        .map(|evals| {
            interpolator
                .interpolate(&evals, 1)
                .ok_or(Error::InvalidRecovery)
        })
        .collect()
}

/// Recovers a pair of signatures from two sets of at least `threshold` partial signatures.
///
/// This is just a wrapper around `threshold_signature_recover_multiple` with concurrency set to 2.
pub fn threshold_signature_recover_pair<'a, V, I>(
    sharing: &Sharing<V>,
    first: I,
    second: I,
) -> Result<(V::Signature, V::Signature), Error>
where
    V: Variant,
    I: IntoIterator<Item = &'a PartialSignature<V>>,
    V::Signature: 'a,
{
    let mut sigs = threshold_signature_recover_multiple::<V, _>(sharing, vec![first, second], 2)?;
    let second_sig = sigs.pop().unwrap();
    let first_sig = sigs.pop().unwrap();
    Ok((first_sig, second_sig))
}
