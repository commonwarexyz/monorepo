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
    batch, core,
};
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
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
pub fn sign_message<V: Variant>(
    private: &Share,
    namespace: Option<&[u8]>,
    message: &[u8],
) -> PartialSignature<V> {
    let sig = core::sign_message::<V>(&private.private, namespace, message);
    PartialSignature {
        value: sig,
        index: private.index,
    }
}

/// Generates a proof of possession for the private key share.
pub fn sign_proof_of_possession<V: Variant>(
    sharing: &Sharing<V>,
    private: &Share,
) -> PartialSignature<V> {
    // Sign the public key
    let sig = core::sign::<V>(
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
pub fn verify_message<V: Variant>(
    sharing: &Sharing<V>,
    namespace: Option<&[u8]>,
    message: &[u8],
    partial: &PartialSignature<V>,
) -> Result<(), Error> {
    core::verify_message::<V>(
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
pub fn verify_proof_of_possession<V: Variant>(
    sharing: &Sharing<V>,
    partial: &PartialSignature<V>,
) -> Result<(), Error> {
    core::verify::<V>(
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
pub fn aggregate_signatures<'a, V, I>(partials: I) -> Option<(u32, V::Signature)>
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
pub fn verify_multiple_messages<'a, R, V, I>(
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

    batch::verify_multiple_messages::<_, V, _>(rng, &public, &combined, concurrency)
}

/// Verify a list of [PartialSignature]s by performing aggregate verification with random
/// scalar weights, performing repeated bisection to find invalid signatures (if any exist).
///
/// Random scalar weights prevent signature malleability attacks where an attacker could
/// redistribute signature components while keeping the aggregate unchanged.
fn verify_multiple_public_keys_bisect<'a, R, V>(
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
    let invalid_indices = batch::verify_multiple_public_keys::<_, V>(rng, namespace, message, &entries);

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
pub fn verify_multiple_public_keys<'a, R, V, I>(
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
    let bad = verify_multiple_public_keys_bisect::<_, V>(
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
pub fn recover<'a, V, I>(sharing: &Sharing<V>, partials: I) -> Result<V::Signature, Error>
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
pub fn recover_multiple<'a, V, I>(
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
        let concurrency = ::core::cmp::min(concurrency, prepared_evals.len());
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
/// This is just a wrapper around `recover_multiple` with concurrency set to 2.
pub fn recover_pair<'a, V, I>(
    sharing: &Sharing<V>,
    first: I,
    second: I,
) -> Result<(V::Signature, V::Signature), Error>
where
    V: Variant,
    I: IntoIterator<Item = &'a PartialSignature<V>>,
    V::Signature: 'a,
{
    let mut sigs = recover_multiple::<V, _>(sharing, vec![first, second], 2)?;
    let second_sig = sigs.pop().unwrap();
    let first_sig = sigs.pop().unwrap();
    Ok((first_sig, second_sig))
}

#[cfg(test)]
mod tests {
    use super::{
        super::core::{self as core, hash_message_namespace},
        *,
    };
    use crate::bls12381::{
        dkg,
        primitives::{
            group::{Private, Scalar, G1_MESSAGE, G2_MESSAGE},
            variant::{MinPk, MinSig},
        },
    };
    use blst::BLST_ERROR;
    use commonware_codec::Encode;
    use commonware_math::algebra::{CryptoGroup, Field as _, Random, Ring, Space};
    use commonware_utils::{quorum, union_unique, NZU32};
    use rand::prelude::*;

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

    fn threshold_proof_of_possession<V: Variant>() {
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);
        let (sharing, shares) = dkg::deal_anonymous::<V>(&mut rng, Default::default(), NZU32!(n));
        let partials: Vec<_> = shares
            .iter()
            .map(|s| sign_proof_of_possession::<V>(&sharing, s))
            .collect();
        for p in &partials {
            verify_proof_of_possession::<V>(&sharing, p)
                .expect("signature should be valid");
        }
        let threshold_sig = recover::<V, _>(&sharing, &partials).unwrap();
        let threshold_pub = sharing.public();

        core::verify_proof_of_possession::<V>(threshold_pub, &threshold_sig)
            .expect("signature should be valid");

        blst_verify_proof_of_possession::<V>(threshold_pub, &threshold_sig)
            .expect("signature should be valid");
    }

    #[test]
    fn test_threshold_proof_of_possession() {
        threshold_proof_of_possession::<MinPk>();
        threshold_proof_of_possession::<MinSig>();
    }

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

    fn threshold_message<V: Variant>() {
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);
        let (sharing, shares) = dkg::deal_anonymous::<V>(&mut rng, Default::default(), NZU32!(n));
        let msg = &[1, 9, 6, 9];
        let namespace = b"test";
        let partials: Vec<_> = shares
            .iter()
            .map(|s| sign_message::<V>(s, Some(namespace), msg))
            .collect();
        for p in &partials {
            verify_message::<V>(&sharing, Some(namespace), msg, p)
                .expect("signature should be valid");
        }
        let threshold_sig = recover::<V, _>(&sharing, &partials).unwrap();
        let threshold_pub = sharing.public();

        core::verify_message::<V>(threshold_pub, Some(namespace), msg, &threshold_sig)
            .expect("signature should be valid");

        let payload = union_unique(namespace, msg);
        blst_verify_message::<V>(threshold_pub, &payload, &threshold_sig)
            .expect("signature should be valid");
    }

    #[test]
    fn test_threshold_message() {
        threshold_message::<MinPk>();
        threshold_message::<MinSig>();
    }

    fn verify_multiple_messages_correct<V: Variant>() {
        let n = 5;
        let (public, shares) =
            dkg::deal_anonymous::<V>(&mut thread_rng(), Default::default(), NZU32!(n));

        let signer = &shares[0];

        let messages: &[(Option<&[u8]>, &[u8])] = &[
            (Some(&b"ns"[..]), b"msg1"),
            (Some(&b"ns"[..]), b"msg2"),
            (Some(&b"ns"[..]), b"msg3"),
        ];
        let entries: Vec<_> = messages
            .iter()
            .map(|(ns, msg)| (*ns, *msg, sign_message::<V>(signer, *ns, msg)))
            .collect();
        verify_multiple_messages::<_, V, _>(
            &mut thread_rng(),
            &public,
            signer.index,
            &entries,
            1,
        )
        .expect("Verification with namespaced messages should succeed");

        let messages_no_ns: &[(Option<&[u8]>, &[u8])] =
            &[(None, b"msg1"), (None, b"msg2"), (None, b"msg3")];
        let entries_no_ns: Vec<_> = messages_no_ns
            .iter()
            .map(|(ns, msg)| (*ns, *msg, sign_message::<V>(signer, *ns, msg)))
            .collect();
        verify_multiple_messages::<_, V, _>(
            &mut thread_rng(),
            &public,
            signer.index,
            &entries_no_ns,
            1,
        )
        .expect("Verification with non-namespaced messages should succeed");

        let messages_mixed: &[(Option<&[u8]>, &[u8])] = &[
            (Some(&b"ns1"[..]), b"msg1"),
            (None, b"msg2"),
            (Some(&b"ns2"[..]), b"msg3"),
        ];
        let entries_mixed: Vec<_> = messages_mixed
            .iter()
            .map(|(ns, msg)| (*ns, *msg, sign_message::<V>(signer, *ns, msg)))
            .collect();
        verify_multiple_messages::<_, V, _>(
            &mut thread_rng(),
            &public,
            signer.index,
            &entries_mixed,
            1,
        )
        .expect("Verification with mixed namespaces should succeed");

        assert!(matches!(
            verify_multiple_messages::<_, V, _>(&mut thread_rng(), &public, 1, &entries, 1),
            Err(Error::InvalidSignature)
        ));

        let mut entries_swapped = entries.clone();
        let temp_sig = entries_swapped[0].2.clone();
        entries_swapped[0].2 = entries_swapped[1].2.clone();
        entries_swapped[1].2 = temp_sig;
        assert!(
            verify_multiple_messages::<_, V, _>(
                &mut thread_rng(),
                &public,
                signer.index,
                &entries_swapped,
                1,
            )
            .is_err(),
            "Verification with swapped signatures should fail"
        );

        let signer2 = &shares[1];
        let partial2 = sign_message::<V>(signer2, messages[0].0, messages[0].1);
        let mut entries_mixed_signers = entries;
        entries_mixed_signers[0].2 = partial2;
        assert!(matches!(
            verify_multiple_messages::<_, V, _>(
                &mut thread_rng(),
                &public,
                signer.index,
                &entries_mixed_signers,
                1
            ),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn test_verify_multiple_messages() {
        verify_multiple_messages_correct::<MinPk>();
        verify_multiple_messages_correct::<MinSig>();
    }

    fn recover_with_weights_correct<V: Variant>() {
        let mut rng = StdRng::seed_from_u64(3333);
        let (n, t) = (6, quorum(6));
        let (sharing, shares) = dkg::deal_anonymous::<V>(&mut rng, Default::default(), NZU32!(n));

        let partials: Vec<_> = shares
            .iter()
            .take(t as usize)
            .map(|s| sign_message::<V>(s, None, b"payload"))
            .collect();

        let sig1 = recover::<V, _>(&sharing, &partials).unwrap();

        core::verify_message::<V>(sharing.public(), None, b"payload", &sig1).unwrap();
    }

    #[test]
    fn test_recover_with_weights() {
        recover_with_weights_correct::<MinPk>();
        recover_with_weights_correct::<MinSig>();
    }

    fn recover_multiple_test<V: Variant>() {
        let mut rng = StdRng::seed_from_u64(3333);
        let (n, t) = (6, quorum(6));
        let (sharing, shares) = dkg::deal_anonymous::<V>(&mut rng, Default::default(), NZU32!(n));

        let partials_1: Vec<_> = shares
            .iter()
            .take(t as usize)
            .map(|s| sign_message::<V>(s, None, b"payload1"))
            .collect();
        let partials_2: Vec<_> = shares
            .iter()
            .take(t as usize)
            .map(|s| sign_message::<V>(s, None, b"payload2"))
            .collect();

        let (sig_1, sig_2) =
            recover_pair::<V, _>(&sharing, &partials_1, &partials_2).unwrap();

        core::verify_message::<V>(sharing.public(), None, b"payload1", &sig_1).unwrap();
        core::verify_message::<V>(sharing.public(), None, b"payload2", &sig_2).unwrap();
    }

    #[test]
    fn test_recover_multiple() {
        recover_multiple_test::<MinPk>();
        recover_multiple_test::<MinSig>();
    }

    fn partial_aggregate_signature_correct<V: Variant>() {
        let (n, _) = (5, 4);
        let mut rng = StdRng::seed_from_u64(0);

        let (sharing, shares) = dkg::deal_anonymous::<V>(&mut rng, Default::default(), NZU32!(n));

        let namespace = Some(&b"test"[..]);
        let msg = b"hello";
        let partials = shares
            .iter()
            .map(|s| sign_message::<V>(s, namespace, msg))
            .collect::<Vec<_>>();

        partials.iter().for_each(|partial| {
            verify_message::<V>(&sharing, namespace, msg, partial).unwrap();
        });

        let threshold_sig = recover::<V, _>(&sharing, &partials).unwrap();
        core::verify_message::<V>(sharing.public(), namespace, msg, &threshold_sig).unwrap();
    }

    #[test]
    fn test_partial_aggregate_signature_correct() {
        partial_aggregate_signature_correct::<MinPk>();
        partial_aggregate_signature_correct::<MinSig>();
    }

    fn partial_aggregate_signature_bad_namespace<V: Variant>() {
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        let (sharing, shares) = dkg::deal_anonymous::<V>(&mut rng, Default::default(), NZU32!(n));

        let namespace = Some(&b"test"[..]);
        let msg = b"hello";
        let partials = shares
            .iter()
            .map(|s| sign_message::<V>(s, namespace, msg))
            .collect::<Vec<_>>();

        let namespace = Some(&b"bad"[..]);
        partials.iter().for_each(|partial| {
            assert!(matches!(
                verify_message::<V>(&sharing, namespace, msg, partial).unwrap_err(),
                Error::InvalidSignature
            ));
        });

        let threshold_sig = recover::<V, _>(&sharing, &partials).unwrap();
        assert!(matches!(
            core::verify_message::<V>(sharing.public(), namespace, msg, &threshold_sig).unwrap_err(),
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

        let (group, shares) = dkg::deal_anonymous::<V>(&mut rng, Default::default(), NZU32!(n));

        let shares = shares.into_iter().take(t as usize - 1).collect::<Vec<_>>();

        let namespace = Some(&b"test"[..]);
        let msg = b"hello";
        let partials = shares
            .iter()
            .map(|s| sign_message::<V>(s, namespace, msg))
            .collect::<Vec<_>>();

        partials.iter().for_each(|partial| {
            verify_message::<V>(&group, namespace, msg, partial).unwrap();
        });

        assert!(matches!(
            recover::<V, _>(&group, &partials).unwrap_err(),
            Error::NotEnoughPartialSignatures(4, 3)
        ));
    }

    #[test]
    fn test_partial_aggregate_signature_insufficient() {
        partial_aggregate_signature_insufficient::<MinPk>();
        partial_aggregate_signature_insufficient::<MinSig>();
    }

    fn partial_aggregate_signature_bad_share<V: Variant>() {
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        let (sharing, mut shares) =
            dkg::deal_anonymous::<V>(&mut rng, Default::default(), NZU32!(n));

        let share = shares.get_mut(3).unwrap();
        share.private = Private::random(&mut rand::thread_rng());

        let namespace = Some(&b"test"[..]);
        let msg = b"hello";
        let partials = shares
            .iter()
            .map(|s| sign_message::<V>(s, namespace, msg))
            .collect::<Vec<_>>();

        partials.iter().for_each(|partial| {
            verify_message::<V>(&sharing, namespace, msg, partial).unwrap();
        });

        let threshold_sig = recover::<V, _>(&sharing, &partials).unwrap();
        core::verify_message::<V>(sharing.public(), namespace, msg, &threshold_sig).unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn test_partial_aggregate_signature_bad_share() {
        partial_aggregate_signature_bad_share::<MinPk>();
        partial_aggregate_signature_bad_share::<MinSig>();
    }

    #[test]
    fn test_verify_multiple_public_keys() {
        let mut rng = StdRng::seed_from_u64(0);
        let n = 5;
        let (sharing, shares) =
            dkg::deal_anonymous::<MinSig>(&mut rng, Default::default(), NZU32!(n));
        let namespace = Some(&b"test"[..]);
        let msg = b"hello";

        let partials: Vec<_> = shares
            .iter()
            .map(|s| sign_message::<MinSig>(s, namespace, msg))
            .collect();
        sharing.precompute_partial_publics();

        verify_multiple_public_keys::<_, MinSig, _>(
            &mut thread_rng(),
            &sharing,
            namespace,
            msg,
            &partials,
        )
        .expect("all signatures should be valid");
    }

    #[test]
    fn test_verify_multiple_public_keys_one_invalid() {
        let mut rng = StdRng::seed_from_u64(0);
        let n = 5;
        let (sharing, mut shares) =
            dkg::deal_anonymous::<MinSig>(&mut rng, Default::default(), NZU32!(n));
        let namespace = Some(&b"test"[..]);
        let msg = b"hello";

        let corrupted_index = 1;
        shares[corrupted_index].private = Private::random(&mut rng);

        let partials: Vec<_> = shares
            .iter()
            .map(|s| sign_message::<MinSig>(s, namespace, msg))
            .collect();

        sharing.precompute_partial_publics();
        let result = verify_multiple_public_keys::<_, MinSig, _>(
            &mut thread_rng(),
            &sharing,
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
                    invalid_sigs[0].index, corrupted_index as u32,
                    "The invalid signature should match the corrupted share's index"
                );
            }
            _ => panic!("Expected an error with invalid signatures"),
        }
    }

    #[test]
    fn test_verify_multiple_public_keys_many_invalid() {
        let mut rng = StdRng::seed_from_u64(0);
        let n = 6;
        let (sharing, mut shares) =
            dkg::deal_anonymous::<MinSig>(&mut rng, Default::default(), NZU32!(n));
        let namespace = Some(&b"test"[..]);
        let msg = b"hello";

        let corrupted_indices = vec![1, 3];
        for &idx in &corrupted_indices {
            shares[idx].private = Private::random(&mut rng);
        }

        let partials: Vec<_> = shares
            .iter()
            .map(|s| sign_message::<MinSig>(s, namespace, msg))
            .collect();
        sharing.precompute_partial_publics();

        let result = verify_multiple_public_keys::<_, MinSig, _>(
            &mut thread_rng(),
            &sharing,
            namespace,
            msg,
            &partials,
        );
        match result {
            Err(invalid_sigs) => {
                assert_eq!(
                    invalid_sigs.len(),
                    corrupted_indices.len(),
                    "Number of invalid signatures should match number of corrupted shares"
                );
                let invalid_indices: Vec<u32> = invalid_sigs.iter().map(|sig| sig.index).collect();
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

    #[test]
    fn test_verify_multiple_public_keys_out_of_range() {
        let mut rng = StdRng::seed_from_u64(0);
        let n = 5;
        let (sharing, shares) =
            dkg::deal_anonymous::<MinSig>(&mut rng, Default::default(), NZU32!(n));
        let namespace = Some(&b"test"[..]);
        let msg = b"hello";

        let mut partials: Vec<_> = shares
            .iter()
            .map(|s| sign_message::<MinSig>(s, namespace, msg))
            .collect();

        partials[0].index = 100;

        sharing.precompute_partial_publics();
        let result = verify_multiple_public_keys::<_, MinSig, _>(
            &mut thread_rng(),
            &sharing,
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
    fn test_verify_multiple_public_keys_single() {
        let mut rng = StdRng::seed_from_u64(0);
        let (sharing, shares) =
            dkg::deal_anonymous::<MinSig>(&mut rng, Default::default(), NZU32!(1));
        let namespace = Some(&b"test"[..]);
        let msg = b"hello";

        let partials: Vec<_> = shares
            .iter()
            .map(|s| sign_message::<MinSig>(s, namespace, msg))
            .collect();

        verify_multiple_public_keys::<_, MinSig, _>(
            &mut thread_rng(),
            &sharing,
            namespace,
            msg,
            &partials,
        )
        .expect("signature should be valid");
    }

    #[test]
    fn test_verify_multiple_public_keys_single_invalid() {
        let mut rng = StdRng::seed_from_u64(0);
        let (sharing, mut shares) =
            dkg::deal_anonymous::<MinSig>(&mut rng, Default::default(), NZU32!(1));
        let namespace = Some(&b"test"[..]);
        let msg = b"hello";

        shares[0].private = Private::random(&mut rng);

        let partials: Vec<_> = shares
            .iter()
            .map(|s| sign_message::<MinSig>(s, namespace, msg))
            .collect();

        let result = verify_multiple_public_keys::<_, MinSig, _>(
            &mut thread_rng(),
            &sharing,
            namespace,
            msg,
            &partials,
        );
        match result {
            Err(invalid_sigs) => {
                assert_eq!(invalid_sigs.len(), 1);
                assert_eq!(invalid_sigs[0].index, 0);
            }
            _ => panic!("Expected an error with invalid signatures"),
        }
    }

    #[test]
    fn test_verify_multiple_public_keys_last_invalid() {
        let mut rng = StdRng::seed_from_u64(0);
        let n = 5;
        let (sharing, mut shares) =
            dkg::deal_anonymous::<MinSig>(&mut rng, Default::default(), NZU32!(n));
        let namespace = Some(&b"test"[..]);
        let msg = b"hello";

        let corrupted_index = n - 1;
        shares[corrupted_index as usize].private = Private::random(&mut rng);

        let partials: Vec<_> = shares
            .iter()
            .map(|s| sign_message::<MinSig>(s, namespace, msg))
            .collect();

        let result = verify_multiple_public_keys::<_, MinSig, _>(
            &mut thread_rng(),
            &sharing,
            namespace,
            msg,
            &partials,
        );
        match result {
            Err(invalid_sigs) => {
                assert_eq!(invalid_sigs.len(), 1);
                assert_eq!(invalid_sigs[0].index, corrupted_index);
            }
            _ => panic!("Expected an error with invalid signatures"),
        }
    }

    fn threshold_derive_missing_partials<V: Variant>() {
        fn lagrange_coeff(scalars: &[Scalar], eval_x: u32, i_x: u32, x_coords: &[u32]) -> Scalar {
            let mut num = Scalar::one();
            let mut den = Scalar::one();

            let eval_x = scalars[eval_x as usize].clone();
            let xi = scalars[i_x as usize].clone();

            for &j_x in x_coords {
                if i_x == j_x {
                    continue;
                }

                let xj = scalars[j_x as usize].clone();

                let mut term = eval_x.clone();
                term -= &xj;
                num *= &term;

                let mut diff = xi.clone();
                diff -= &xj;
                den *= &diff;
            }

            num *= &den.inv();
            num
        }

        let mut rng = StdRng::seed_from_u64(0);
        let (n, t) = (NZU32!(5), quorum(5));
        let (public, shares) = dkg::deal_anonymous::<V>(&mut rng, Default::default(), n);
        let scalars = public.mode().all_scalars(n).collect::<Vec<_>>();

        let namespace = Some(&b"test"[..]);
        let msg = b"hello";
        let all_partials: Vec<_> = shares
            .iter()
            .map(|s| sign_message::<V>(s, namespace, msg))
            .collect();

        let recovery_partials: Vec<_> = all_partials.iter().take(t as usize).collect();
        let recovery_indices: Vec<u32> = recovery_partials.iter().map(|p| p.index).collect();

        for target in &shares {
            let target = target.index;

            let weights: Vec<Scalar> = recovery_indices
                .iter()
                .map(|&recovery_index| {
                    lagrange_coeff(&scalars, target, recovery_index, &recovery_indices)
                })
                .collect();

            let points: Vec<_> = recovery_partials.iter().map(|p| p.value).collect();
            let derived = <<V as Variant>::Signature as Space<Scalar>>::msm(&points, &weights, 1);
            let derived = PartialSignature {
                index: target,
                value: derived,
            };

            verify_message::<V>(&public, namespace, msg, &derived)
                .expect("derived signature should be valid");

            let original = all_partials.iter().find(|p| p.index == target).unwrap();
            assert_eq!(derived.value, original.value);
        }
    }

    #[test]
    fn test_threshold_derive_missing_partials() {
        threshold_derive_missing_partials::<MinPk>();
        threshold_derive_missing_partials::<MinSig>();
    }

    fn verify_multiple_public_keys_fail_on_malleability<V: Variant>() {
        let mut rng = StdRng::seed_from_u64(12345);
        let n = 5;
        let (sharing, shares) = dkg::deal_anonymous::<V>(&mut rng, Default::default(), NZU32!(n));
        let namespace_bytes: &[u8] = b"test";
        let namespace = Some(namespace_bytes);
        let msg = b"message";

        let partial1 = sign_message::<V>(&shares[0], namespace, msg);
        let partial2 = sign_message::<V>(&shares[1], namespace, msg);

        verify_message::<V>(&sharing, namespace, msg, &partial1)
            .expect("partial1 should be valid");
        verify_message::<V>(&sharing, namespace, msg, &partial2)
            .expect("partial2 should be valid");

        let random_scalar = Scalar::random(&mut rng);
        let delta = V::Signature::generator() * &random_scalar;
        let forged_partial1 = PartialSignature {
            index: partial1.index,
            value: partial1.value - &delta,
        };
        let forged_partial2 = PartialSignature {
            index: partial2.index,
            value: partial2.value + &delta,
        };

        assert!(
            verify_message::<V>(&sharing, namespace, msg, &forged_partial1).is_err(),
            "forged partial1 should be invalid individually"
        );
        assert!(
            verify_message::<V>(&sharing, namespace, msg, &forged_partial2).is_err(),
            "forged partial2 should be invalid individually"
        );

        let forged_sum = forged_partial1.value + &forged_partial2.value;
        let valid_sum = partial1.value + &partial2.value;
        assert_eq!(
            forged_sum, valid_sum,
            "signature value sums should be equal"
        );

        let pk1 = sharing.partial_public(partial1.index).unwrap();
        let pk2 = sharing.partial_public(partial2.index).unwrap();
        let pk_sum = pk1 + &pk2;
        let hm = hash_message_namespace::<V>(V::MESSAGE, namespace_bytes, msg);
        V::verify(&pk_sum, &hm, &forged_sum)
            .expect("vulnerable naive verification accepts forged aggregate");

        let forged_partials = [forged_partial1, forged_partial2];
        let result = verify_multiple_public_keys::<_, V, _>(
            &mut thread_rng(),
            &sharing,
            namespace,
            msg,
            &forged_partials,
        );
        assert!(
            result.is_err(),
            "secure function should reject forged partial signatures"
        );

        let valid_partials = [partial1, partial2];
        verify_multiple_public_keys::<_, V, _>(
            &mut thread_rng(),
            &sharing,
            namespace,
            msg,
            &valid_partials,
        )
        .expect("secure function should accept valid partial signatures");
    }

    #[test]
    fn test_verify_multiple_public_keys_fail_on_malleability() {
        verify_multiple_public_keys_fail_on_malleability::<MinPk>();
        verify_multiple_public_keys_fail_on_malleability::<MinSig>();
    }

    fn verify_multiple_messages_fail_on_malleability<V: Variant>() {
        let mut rng = StdRng::seed_from_u64(54321);
        let n = 5;
        let (sharing, shares) = dkg::deal_anonymous::<V>(&mut rng, Default::default(), NZU32!(n));
        let namespace_bytes: &[u8] = b"test";
        let namespace = Some(namespace_bytes);
        let msg1: &[u8] = b"message 1";
        let msg2: &[u8] = b"message 2";

        let signer = &shares[0];
        let partial1 = sign_message::<V>(signer, namespace, msg1);
        let partial2 = sign_message::<V>(signer, namespace, msg2);

        verify_message::<V>(&sharing, namespace, msg1, &partial1)
            .expect("partial1 should be valid");
        verify_message::<V>(&sharing, namespace, msg2, &partial2)
            .expect("partial2 should be valid");

        let random_scalar = Scalar::random(&mut rng);
        let delta = V::Signature::generator() * &random_scalar;
        let forged_partial1 = PartialSignature {
            index: partial1.index,
            value: partial1.value - &delta,
        };
        let forged_partial2 = PartialSignature {
            index: partial2.index,
            value: partial2.value + &delta,
        };

        assert!(
            verify_message::<V>(&sharing, namespace, msg1, &forged_partial1).is_err(),
            "forged partial1 should be invalid individually"
        );
        assert!(
            verify_message::<V>(&sharing, namespace, msg2, &forged_partial2).is_err(),
            "forged partial2 should be invalid individually"
        );

        let forged_sum = forged_partial1.value + &forged_partial2.value;
        let valid_sum = partial1.value + &partial2.value;
        assert_eq!(
            forged_sum, valid_sum,
            "signature value sums should be equal"
        );

        let pk = sharing.partial_public(signer.index).unwrap();
        let hm1 = hash_message_namespace::<V>(V::MESSAGE, namespace_bytes, msg1);
        let hm2 = hash_message_namespace::<V>(V::MESSAGE, namespace_bytes, msg2);
        let hm_sum = hm1 + &hm2;
        V::verify(&pk, &hm_sum, &forged_sum)
            .expect("vulnerable naive verification accepts forged aggregate");

        let forged_entries = vec![
            (namespace, msg1, forged_partial1),
            (namespace, msg2, forged_partial2),
        ];
        let result = verify_multiple_messages::<_, V, _>(
            &mut thread_rng(),
            &sharing,
            signer.index,
            &forged_entries,
            1,
        );
        assert!(
            result.is_err(),
            "secure function should reject forged partial signatures"
        );

        let valid_entries = vec![(namespace, msg1, partial1), (namespace, msg2, partial2)];
        verify_multiple_messages::<_, V, _>(
            &mut thread_rng(),
            &sharing,
            signer.index,
            &valid_entries,
            1,
        )
        .expect("secure function should accept valid partial signatures");
    }

    #[test]
    fn test_verify_multiple_messages_fail_on_malleability() {
        verify_multiple_messages_fail_on_malleability::<MinPk>();
        verify_multiple_messages_fail_on_malleability::<MinSig>();
    }
}
