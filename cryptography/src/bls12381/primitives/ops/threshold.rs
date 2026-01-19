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
    batch,
};
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use commonware_codec::Encode;
use commonware_macros::ready;
use commonware_parallel::Strategy;
use commonware_utils::{ordered::Map, union_unique, Faults, Participant};
use rand_core::CryptoRngCore;

/// Prepares partial signature evaluations for threshold recovery.
fn prepare_evaluations<'a, V: Variant>(
    threshold: u32,
    partials: impl IntoIterator<Item = &'a PartialSignature<V>>,
) -> Result<Map<Participant, V::Signature>, Error> {
    let mut out = Map::from_iter_dedup(partials.into_iter().map(|eval| (eval.index, eval.value)));
    let t = threshold as usize;
    out.truncate(t);
    if out.len() < t {
        return Err(Error::NotEnoughPartialSignatures(t, out.len()));
    }
    Ok(out)
}

/// Signs the provided message with the key share.
#[ready(0)]
pub fn sign_message<V: Variant>(
    share: &Share,
    namespace: &[u8],
    message: &[u8],
) -> PartialSignature<V> {
    let sig = super::sign_message::<V>(&share.private, namespace, message);

    PartialSignature {
        value: sig,
        index: share.index,
    }
}

/// Generates a proof of possession for the private key share.
///
/// This signs the *threshold* public key (not the share's individual public key)
/// so that partial signatures can be recovered into a threshold signature
/// verifiable with `ops::verify_proof_of_possession`.
#[ready(0)]
pub fn sign_proof_of_possession<V: Variant>(
    sharing: &Sharing<V>,
    share: &Share,
    namespace: &[u8],
) -> PartialSignature<V> {
    let sig = super::sign::<V>(
        &share.private,
        V::PROOF_OF_POSSESSION,
        &union_unique(namespace, &sharing.public().encode()),
    );

    PartialSignature {
        value: sig,
        index: share.index,
    }
}

/// Verifies the partial signature against the public polynomial.
///
/// # Warning
///
/// This function assumes a group check was already performed on `signature`.
#[ready(0)]
pub fn verify_message<V: Variant>(
    sharing: &Sharing<V>,
    namespace: &[u8],
    message: &[u8],
    partial: &PartialSignature<V>,
) -> Result<(), Error> {
    super::verify_message::<V>(
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
#[ready(0)]
pub fn verify_proof_of_possession<V: Variant>(
    sharing: &Sharing<V>,
    namespace: &[u8],
    partial: &PartialSignature<V>,
) -> Result<(), Error> {
    super::verify::<V>(
        &sharing.partial_public(partial.index)?,
        V::PROOF_OF_POSSESSION,
        &union_unique(namespace, &sharing.public().encode()),
        &partial.value,
    )
}

/// Verifies multiple partial signatures over multiple messages from a single signer.
///
/// Randomness ensures batch verification returns the same result as checking each signature
/// individually.
///
/// Each entry is a tuple of (namespace, message, partial_signature).
///
/// # Warning
///
/// This function assumes a group check was already performed on each `signature`.
/// Duplicate messages are safe because random scalar weights ensure each
/// (message, signature) pair is verified independently.
#[ready(0)]
pub fn batch_verify_same_signer<'a, R, V, I>(
    rng: &mut R,
    sharing: &Sharing<V>,
    index: Participant,
    entries: I,
    strategy: &impl Strategy,
) -> Result<(), Error>
where
    R: CryptoRngCore,
    V: Variant,
    I: IntoIterator<Item = &'a (&'a [u8], &'a [u8], PartialSignature<V>)>,
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

    batch::verify_same_signer::<_, V, _>(rng, &public, &combined, strategy)
}

/// Verify a list of [PartialSignature]s over the same message from different signers,
/// ensuring each individual signature is valid (see [`batch`] for more details on how
/// this works).
///
/// Returns the indices of any invalid signatures found.
///
/// # Performance
///
/// Uses bisection to identify which signatures are invalid. In the worst case, this can require
/// more verifications than checking each signature individually. If an invalid signer is detected,
/// consider blocking them from participating in future batches to better amortize the cost of this
/// search.
fn batch_verify_same_message_bisect<'a, R, V>(
    rng: &mut R,
    pending: &[(V::Public, &'a PartialSignature<V>)],
    namespace: &[u8],
    message: &[u8],
    strategy: &impl Strategy,
) -> Vec<&'a PartialSignature<V>>
where
    R: CryptoRngCore,
    V: Variant,
{
    // Convert to the format expected by verify_same_message
    let entries: Vec<(V::Public, V::Signature)> = pending
        .iter()
        .map(|(pk, partial)| (*pk, partial.value))
        .collect();

    // Use the generic verification function
    let invalid_indices =
        batch::verify_same_message::<_, V>(rng, namespace, message, &entries, strategy);

    // Map indices back to PartialSignature references
    invalid_indices
        .into_iter()
        .map(|idx| pending[idx].1)
        .collect()
}

/// Batch verifies multiple [PartialSignature]s over the same message, returning
/// any invalid signatures found.
///
/// Randomness ensures batch verification returns the same result as checking each signature
/// individually.
///
/// # Warning
///
/// This function assumes a group check was already performed on each `signature`.
/// Duplicate signers are safe because random scalar weights ensure each
/// (public key, signature) pair is verified independently.
#[ready(0)]
pub fn batch_verify_same_message<'a, R, V, I>(
    rng: &mut R,
    sharing: &Sharing<V>,
    namespace: &[u8],
    message: &[u8],
    partials: I,
    strategy: &impl Strategy,
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
    let bad = batch_verify_same_message_bisect::<_, V>(
        rng,
        pending.as_slice(),
        namespace,
        message,
        strategy,
    );
    invalid.extend(bad);

    if invalid.is_empty() {
        Ok(())
    } else {
        Err(invalid)
    }
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
#[ready(0)]
pub fn recover<'a, V, I, M>(
    sharing: &Sharing<V>,
    partials: I,
    strategy: &impl Strategy,
) -> Result<V::Signature, Error>
where
    V: Variant,
    I: IntoIterator<Item = &'a PartialSignature<V>>,
    V::Signature: 'a,
    M: Faults,
{
    let evals = prepare_evaluations::<V>(sharing.required::<M>(), partials)?;
    sharing
        .interpolator(evals.keys())?
        .interpolate(&evals, strategy)
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
#[ready(0)]
pub fn recover_multiple<'a, V, I, M>(
    sharing: &Sharing<V>,
    many_evals: Vec<I>,
    strategy: &impl Strategy,
) -> Result<Vec<V::Signature>, Error>
where
    V: Variant,
    I: IntoIterator<Item = &'a PartialSignature<V>>,
    V::Signature: 'a,
    M: Faults,
{
    let prepared_evals = many_evals
        .into_iter()
        .map(|evals| prepare_evaluations::<V>(sharing.required::<M>(), evals))
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
    let results: Vec<_> = strategy.map_init_collect_vec(
        &prepared_evals,
        || &interpolator,
        |interpolator, evals| {
            interpolator
                .interpolate(evals, strategy)
                .ok_or(Error::InvalidRecovery)
        },
    );
    results.into_iter().collect()
}

/// Recovers a pair of signatures from two sets of at least `threshold` partial signatures.
///
/// This is just a wrapper around `recover_multiple`.
#[ready(0)]
pub fn recover_pair<'a, V, I, M>(
    sharing: &Sharing<V>,
    first: I,
    second: I,
    strategy: &impl Strategy,
) -> Result<(V::Signature, V::Signature), Error>
where
    V: Variant,
    I: IntoIterator<Item = &'a PartialSignature<V>>,
    V::Signature: 'a,
    M: Faults,
{
    let mut sigs = recover_multiple::<V, _, M>(sharing, vec![first, second], strategy)?;
    let second_sig = sigs.pop().unwrap();
    let first_sig = sigs.pop().unwrap();
    Ok((first_sig, second_sig))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::{
        dkg,
        primitives::{
            group::{Private, Scalar, G1_MESSAGE, G2_MESSAGE},
            ops::{self, hash_with_namespace},
            variant::{MinPk, MinSig},
        },
    };
    use blst::BLST_ERROR;
    use commonware_codec::Encode;
    use commonware_math::algebra::{CryptoGroup, Field as _, Random, Ring, Space};
    use commonware_parallel::{Rayon, Sequential};
    use commonware_utils::{test_rng, union_unique, Faults, N3f1, NZUsize, NZU32};

    fn blst_verify_proof_of_possession<V: Variant>(
        public: &V::Public,
        namespace: &[u8],
        signature: &V::Signature,
    ) -> Result<(), BLST_ERROR> {
        let msg = union_unique(namespace, &public.encode());
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
        let mut rng = test_rng();
        let namespace = b"test";
        let (sharing, shares) =
            dkg::deal_anonymous::<V, N3f1>(&mut rng, Default::default(), NZU32!(n));
        let partials: Vec<_> = shares
            .iter()
            .map(|s| sign_proof_of_possession::<V>(&sharing, s, namespace))
            .collect();
        for p in &partials {
            verify_proof_of_possession::<V>(&sharing, namespace, p)
                .expect("signature should be valid");
        }
        let threshold_sig = recover::<V, _, N3f1>(&sharing, &partials, &Sequential).unwrap();
        let threshold_pub = sharing.public();

        ops::verify_proof_of_possession::<V>(threshold_pub, namespace, &threshold_sig)
            .expect("signature should be valid");

        blst_verify_proof_of_possession::<V>(threshold_pub, namespace, &threshold_sig)
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
        let mut rng = test_rng();
        let (sharing, shares) =
            dkg::deal_anonymous::<V, N3f1>(&mut rng, Default::default(), NZU32!(n));
        let msg = &[1, 9, 6, 9];
        let namespace = b"test";
        let partials: Vec<_> = shares
            .iter()
            .map(|s| sign_message::<V>(s, namespace, msg))
            .collect();
        for p in &partials {
            verify_message::<V>(&sharing, namespace, msg, p).expect("signature should be valid");
        }
        let threshold_sig = recover::<V, _, N3f1>(&sharing, &partials, &Sequential).unwrap();
        let threshold_pub = sharing.public();

        ops::verify_message::<V>(threshold_pub, namespace, msg, &threshold_sig)
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

    fn batch_verify_same_signer_correct<V: Variant>() {
        let mut rng = test_rng();
        let n = 5;
        let (public, shares) =
            dkg::deal_anonymous::<V, N3f1>(&mut rng, Default::default(), NZU32!(n));

        let signer = &shares[0];

        let messages: &[(&[u8], &[u8])] = &[(b"ns", b"msg1"), (b"ns", b"msg2"), (b"ns", b"msg3")];
        let entries: Vec<_> = messages
            .iter()
            .map(|(ns, msg)| (*ns, *msg, sign_message::<V>(signer, ns, msg)))
            .collect();
        batch_verify_same_signer::<_, V, _>(&mut rng, &public, signer.index, &entries, &Sequential)
            .expect("Verification with namespaced messages should succeed");

        let strategy = Rayon::new(NZUsize!(4)).unwrap();
        batch_verify_same_signer::<_, V, _>(&mut rng, &public, signer.index, &entries, &strategy)
            .expect("Verification with parallel strategy should succeed");

        let messages_alt_ns: &[(&[u8], &[u8])] =
            &[(b"alt", b"msg1"), (b"alt", b"msg2"), (b"alt", b"msg3")];
        let entries_alt_ns: Vec<_> = messages_alt_ns
            .iter()
            .map(|(ns, msg)| (*ns, *msg, sign_message::<V>(signer, ns, msg)))
            .collect();
        batch_verify_same_signer::<_, V, _>(
            &mut rng,
            &public,
            signer.index,
            &entries_alt_ns,
            &Sequential,
        )
        .expect("Verification with alternate namespace messages should succeed");

        let messages_mixed: &[(&[u8], &[u8])] =
            &[(b"ns1", b"msg1"), (b"ns2", b"msg2"), (b"ns3", b"msg3")];
        let entries_mixed: Vec<_> = messages_mixed
            .iter()
            .map(|(ns, msg)| (*ns, *msg, sign_message::<V>(signer, ns, msg)))
            .collect();
        batch_verify_same_signer::<_, V, _>(
            &mut rng,
            &public,
            signer.index,
            &entries_mixed,
            &Sequential,
        )
        .expect("Verification with mixed namespaces should succeed");

        assert!(matches!(
            batch_verify_same_signer::<_, V, _>(
                &mut rng,
                &public,
                Participant::new(1),
                &entries,
                &Sequential
            ),
            Err(Error::InvalidSignature)
        ));

        let mut entries_swapped = entries.clone();
        let temp_sig = entries_swapped[0].2.clone();
        entries_swapped[0].2 = entries_swapped[1].2.clone();
        entries_swapped[1].2 = temp_sig;
        assert!(
            batch_verify_same_signer::<_, V, _>(
                &mut rng,
                &public,
                signer.index,
                &entries_swapped,
                &Sequential,
            )
            .is_err(),
            "Verification with swapped signatures should fail"
        );

        let signer2 = &shares[1];
        let partial2 = sign_message::<V>(signer2, messages[0].0, messages[0].1);
        let mut entries_mixed_signers = entries;
        entries_mixed_signers[0].2 = partial2;
        assert!(matches!(
            batch_verify_same_signer::<_, V, _>(
                &mut rng,
                &public,
                signer.index,
                &entries_mixed_signers,
                &Sequential,
            ),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn test_batch_verify_same_signer() {
        batch_verify_same_signer_correct::<MinPk>();
        batch_verify_same_signer_correct::<MinSig>();
    }

    fn recover_with_weights_correct<V: Variant>() {
        let mut rng = test_rng();
        let (n, t) = (6, N3f1::quorum(6));
        let (sharing, shares) =
            dkg::deal_anonymous::<V, N3f1>(&mut rng, Default::default(), NZU32!(n));

        let partials: Vec<_> = shares
            .iter()
            .take(t as usize)
            .map(|s| sign_message::<V>(s, b"test", b"payload"))
            .collect();

        let sig1 = recover::<V, _, N3f1>(&sharing, &partials, &Sequential).unwrap();

        ops::verify_message::<V>(sharing.public(), b"test", b"payload", &sig1).unwrap();
    }

    #[test]
    fn test_recover_with_weights() {
        recover_with_weights_correct::<MinPk>();
        recover_with_weights_correct::<MinSig>();
    }

    fn recover_multiple_test<V: Variant>() {
        let mut rng = test_rng();
        let (n, t) = (6, N3f1::quorum(6));
        let (sharing, shares) =
            dkg::deal_anonymous::<V, N3f1>(&mut rng, Default::default(), NZU32!(n));

        let partials_1: Vec<_> = shares
            .iter()
            .take(t as usize)
            .map(|s| sign_message::<V>(s, b"test", b"payload1"))
            .collect();
        let partials_2: Vec<_> = shares
            .iter()
            .take(t as usize)
            .map(|s| sign_message::<V>(s, b"test", b"payload2"))
            .collect();

        let (sig_1, sig_2) =
            recover_pair::<V, _, N3f1>(&sharing, &partials_1, &partials_2, &Sequential).unwrap();

        ops::verify_message::<V>(sharing.public(), b"test", b"payload1", &sig_1).unwrap();
        ops::verify_message::<V>(sharing.public(), b"test", b"payload2", &sig_2).unwrap();

        let parallel = Rayon::new(NZUsize!(4)).unwrap();
        let (sig_1_par, sig_2_par) =
            recover_pair::<V, _, N3f1>(&sharing, &partials_1, &partials_2, &parallel).unwrap();

        assert_eq!(sig_1, sig_1_par);
        assert_eq!(sig_2, sig_2_par);
    }

    #[test]
    fn test_recover_multiple() {
        recover_multiple_test::<MinPk>();
        recover_multiple_test::<MinSig>();
    }

    fn recover_with_verification<V: Variant>() {
        let (n, _) = (5, 4);
        let mut rng = test_rng();

        let (sharing, shares) =
            dkg::deal_anonymous::<V, N3f1>(&mut rng, Default::default(), NZU32!(n));

        let namespace = b"test";
        let msg = b"hello";
        let partials = shares
            .iter()
            .map(|s| sign_message::<V>(s, namespace, msg))
            .collect::<Vec<_>>();

        partials.iter().for_each(|partial| {
            verify_message::<V>(&sharing, namespace, msg, partial).unwrap();
        });

        let threshold_sig = recover::<V, _, N3f1>(&sharing, &partials, &Sequential).unwrap();
        ops::verify_message::<V>(sharing.public(), namespace, msg, &threshold_sig).unwrap();
    }

    #[test]
    fn test_recover_with_verification() {
        recover_with_verification::<MinPk>();
        recover_with_verification::<MinSig>();
    }

    fn recover_bad_namespace<V: Variant>() {
        let n = 5;
        let mut rng = test_rng();

        let (sharing, shares) =
            dkg::deal_anonymous::<V, N3f1>(&mut rng, Default::default(), NZU32!(n));

        let namespace = b"test";
        let msg = b"hello";
        let partials = shares
            .iter()
            .map(|s| sign_message::<V>(s, namespace, msg))
            .collect::<Vec<_>>();

        let namespace = b"bad";
        partials.iter().for_each(|partial| {
            assert!(matches!(
                verify_message::<V>(&sharing, namespace, msg, partial).unwrap_err(),
                Error::InvalidSignature
            ));
        });

        let threshold_sig = recover::<V, _, N3f1>(&sharing, &partials, &Sequential).unwrap();
        assert!(matches!(
            ops::verify_message::<V>(sharing.public(), namespace, msg, &threshold_sig).unwrap_err(),
            Error::InvalidSignature
        ));
    }

    #[test]
    fn test_recover_bad_namespace() {
        recover_bad_namespace::<MinPk>();
        recover_bad_namespace::<MinSig>();
    }

    fn recover_insufficient<V: Variant>() {
        let (n, t) = (5, 4);
        let mut rng = test_rng();

        let (group, shares) =
            dkg::deal_anonymous::<V, N3f1>(&mut rng, Default::default(), NZU32!(n));

        let shares = shares.into_iter().take(t as usize - 1).collect::<Vec<_>>();

        let namespace = b"test";
        let msg = b"hello";
        let partials = shares
            .iter()
            .map(|s| sign_message::<V>(s, namespace, msg))
            .collect::<Vec<_>>();

        partials.iter().for_each(|partial| {
            verify_message::<V>(&group, namespace, msg, partial).unwrap();
        });

        assert!(matches!(
            recover::<V, _, N3f1>(&group, &partials, &Sequential).unwrap_err(),
            Error::NotEnoughPartialSignatures(4, 3)
        ));
    }

    #[test]
    fn test_recover_insufficient() {
        recover_insufficient::<MinPk>();
        recover_insufficient::<MinSig>();
    }

    fn recover_bad_share<V: Variant>() {
        let n = 5;
        let mut rng = test_rng();

        let (sharing, mut shares) =
            dkg::deal_anonymous::<V, N3f1>(&mut rng, Default::default(), NZU32!(n));

        let share = shares.get_mut(3).unwrap();
        share.private = Private::random(&mut rng);

        let namespace = b"test";
        let msg = b"hello";
        let partials = shares
            .iter()
            .map(|s| sign_message::<V>(s, namespace, msg))
            .collect::<Vec<_>>();

        partials.iter().for_each(|partial| {
            verify_message::<V>(&sharing, namespace, msg, partial).unwrap();
        });

        let threshold_sig = recover::<V, _, N3f1>(&sharing, &partials, &Sequential).unwrap();
        ops::verify_message::<V>(sharing.public(), namespace, msg, &threshold_sig).unwrap();
    }

    #[test]
    #[should_panic(expected = "InvalidSignature")]
    fn test_recover_bad_share() {
        recover_bad_share::<MinPk>();
        recover_bad_share::<MinSig>();
    }

    #[test]
    fn test_batch_verify_same_message() {
        let mut rng = test_rng();
        let n = 5;
        let (sharing, shares) =
            dkg::deal_anonymous::<MinSig, N3f1>(&mut rng, Default::default(), NZU32!(n));
        let namespace = b"test";
        let msg = b"hello";

        let partials: Vec<_> = shares
            .iter()
            .map(|s| sign_message::<MinSig>(s, namespace, msg))
            .collect();
        sharing.precompute_partial_publics();

        batch_verify_same_message::<_, MinSig, _>(
            &mut rng,
            &sharing,
            namespace,
            msg,
            &partials,
            &Sequential,
        )
        .expect("all signatures should be valid");
    }

    #[test]
    fn test_batch_verify_same_message_one_invalid() {
        let mut rng = test_rng();
        let n = 5;
        let (sharing, mut shares) =
            dkg::deal_anonymous::<MinSig, N3f1>(&mut rng, Default::default(), NZU32!(n));
        let namespace = b"test";
        let msg = b"hello";

        let corrupted_index = 1;
        shares[corrupted_index].private = Private::random(&mut rng);

        let partials: Vec<_> = shares
            .iter()
            .map(|s| sign_message::<MinSig>(s, namespace, msg))
            .collect();

        sharing.precompute_partial_publics();
        let result = batch_verify_same_message::<_, MinSig, _>(
            &mut rng,
            &sharing,
            namespace,
            msg,
            &partials,
            &Sequential,
        );
        match result {
            Err(invalid_sigs) => {
                assert_eq!(
                    invalid_sigs.len(),
                    1,
                    "Exactly one signature should be invalid"
                );
                assert_eq!(
                    invalid_sigs[0].index,
                    Participant::from_usize(corrupted_index),
                    "The invalid signature should match the corrupted share's index"
                );
            }
            _ => panic!("Expected an error with invalid signatures"),
        }
    }

    #[test]
    fn test_batch_verify_same_message_many_invalid() {
        let mut rng = test_rng();
        let n = 6;
        let (sharing, mut shares) =
            dkg::deal_anonymous::<MinSig, N3f1>(&mut rng, Default::default(), NZU32!(n));
        let namespace = b"test";
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

        let result = batch_verify_same_message::<_, MinSig, _>(
            &mut rng,
            &sharing,
            namespace,
            msg,
            &partials,
            &Sequential,
        );
        match result {
            Err(invalid_sigs) => {
                assert_eq!(
                    invalid_sigs.len(),
                    corrupted_indices.len(),
                    "Number of invalid signatures should match number of corrupted shares"
                );
                let invalid_indices: Vec<Participant> =
                    invalid_sigs.iter().map(|sig| sig.index).collect();
                let expected_indices: Vec<Participant> = corrupted_indices
                    .iter()
                    .map(|&i| Participant::from_usize(i))
                    .collect();
                assert_eq!(
                    invalid_indices, expected_indices,
                    "Invalid signature indices should match corrupted share indices"
                );
            }
            _ => panic!("Expected an error with invalid signatures"),
        }
    }

    #[test]
    fn test_batch_verify_same_message_out_of_range() {
        let mut rng = test_rng();
        let n = 5;
        let (sharing, shares) =
            dkg::deal_anonymous::<MinSig, N3f1>(&mut rng, Default::default(), NZU32!(n));
        let namespace = b"test";
        let msg = b"hello";

        let mut partials: Vec<_> = shares
            .iter()
            .map(|s| sign_message::<MinSig>(s, namespace, msg))
            .collect();

        partials[0].index = Participant::new(100);

        sharing.precompute_partial_publics();
        let result = batch_verify_same_message::<_, MinSig, _>(
            &mut rng,
            &sharing,
            namespace,
            msg,
            &partials,
            &Sequential,
        );
        match result {
            Err(invalid_sigs) => {
                assert_eq!(
                    invalid_sigs.len(),
                    1,
                    "Exactly one signature should be invalid"
                );
                assert_eq!(
                    invalid_sigs[0].index,
                    Participant::new(100),
                    "The invalid signature should match the corrupted index"
                );
            }
            _ => panic!("Expected an error with invalid signatures"),
        }
    }

    #[test]
    fn test_batch_verify_same_message_single() {
        let mut rng = test_rng();
        let (sharing, shares) =
            dkg::deal_anonymous::<MinSig, N3f1>(&mut rng, Default::default(), NZU32!(1));
        let namespace = b"test";
        let msg = b"hello";

        let partials: Vec<_> = shares
            .iter()
            .map(|s| sign_message::<MinSig>(s, namespace, msg))
            .collect();

        batch_verify_same_message::<_, MinSig, _>(
            &mut rng,
            &sharing,
            namespace,
            msg,
            &partials,
            &Sequential,
        )
        .expect("signature should be valid");
    }

    #[test]
    fn test_batch_verify_same_message_single_invalid() {
        let mut rng = test_rng();
        let (sharing, mut shares) =
            dkg::deal_anonymous::<MinSig, N3f1>(&mut rng, Default::default(), NZU32!(1));
        let namespace = b"test";
        let msg = b"hello";

        shares[0].private = Private::random(&mut rng);

        let partials: Vec<_> = shares
            .iter()
            .map(|s| sign_message::<MinSig>(s, namespace, msg))
            .collect();

        let result = batch_verify_same_message::<_, MinSig, _>(
            &mut rng,
            &sharing,
            namespace,
            msg,
            &partials,
            &Sequential,
        );
        match result {
            Err(invalid_sigs) => {
                assert_eq!(invalid_sigs.len(), 1);
                assert_eq!(invalid_sigs[0].index, Participant::new(0));
            }
            _ => panic!("Expected an error with invalid signatures"),
        }
    }

    #[test]
    fn test_batch_verify_same_message_last_invalid() {
        let mut rng = test_rng();
        let n = 5;
        let (sharing, mut shares) =
            dkg::deal_anonymous::<MinSig, N3f1>(&mut rng, Default::default(), NZU32!(n));
        let namespace = b"test";
        let msg = b"hello";

        let corrupted_index = n - 1;
        shares[corrupted_index as usize].private = Private::random(&mut rng);

        let partials: Vec<_> = shares
            .iter()
            .map(|s| sign_message::<MinSig>(s, namespace, msg))
            .collect();

        let result = batch_verify_same_message::<_, MinSig, _>(
            &mut rng,
            &sharing,
            namespace,
            msg,
            &partials,
            &Sequential,
        );
        match result {
            Err(invalid_sigs) => {
                assert_eq!(invalid_sigs.len(), 1);
                assert_eq!(invalid_sigs[0].index, Participant::new(corrupted_index));
            }
            _ => panic!("Expected an error with invalid signatures"),
        }
    }

    fn threshold_derive_missing_partials<V: Variant>() {
        fn lagrange_coeff(
            scalars: &[Scalar],
            eval_x: Participant,
            i_x: Participant,
            x_coords: &[Participant],
        ) -> Scalar {
            let mut num = Scalar::one();
            let mut den = Scalar::one();

            let eval_x = scalars[usize::from(eval_x)].clone();
            let xi = scalars[usize::from(i_x)].clone();

            for &j_x in x_coords {
                if i_x == j_x {
                    continue;
                }

                let xj = scalars[usize::from(j_x)].clone();

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

        let mut rng = test_rng();
        let (n, t) = (NZU32!(5), N3f1::quorum(5));
        let (public, shares) = dkg::deal_anonymous::<V, N3f1>(&mut rng, Default::default(), n);
        let scalars = public.mode().all_scalars(n).collect::<Vec<_>>();

        let namespace = b"test";
        let msg = b"hello";
        let all_partials: Vec<_> = shares
            .iter()
            .map(|s| sign_message::<V>(s, namespace, msg))
            .collect();

        let recovery_partials: Vec<_> = all_partials.iter().take(t as usize).collect();
        let recovery_indices: Vec<Participant> =
            recovery_partials.iter().map(|p| p.index).collect();

        for target in &shares {
            let target = target.index;

            let weights: Vec<Scalar> = recovery_indices
                .iter()
                .map(|&recovery_index| {
                    lagrange_coeff(&scalars, target, recovery_index, &recovery_indices)
                })
                .collect();

            let points: Vec<_> = recovery_partials.iter().map(|p| p.value).collect();
            let derived =
                <<V as Variant>::Signature as Space<Scalar>>::msm(&points, &weights, &Sequential);
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

    fn batch_verify_same_message_rejects_malleability<V: Variant>() {
        let mut rng = test_rng();
        let n = 5;
        let (sharing, shares) =
            dkg::deal_anonymous::<V, N3f1>(&mut rng, Default::default(), NZU32!(n));
        let namespace = b"test";
        let msg = b"message";

        let partial1 = sign_message::<V>(&shares[0], namespace, msg);
        let partial2 = sign_message::<V>(&shares[1], namespace, msg);

        verify_message::<V>(&sharing, namespace, msg, &partial1).expect("partial1 should be valid");
        verify_message::<V>(&sharing, namespace, msg, &partial2).expect("partial2 should be valid");

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
        let hm = hash_with_namespace::<V>(V::MESSAGE, namespace, msg);
        V::verify(&pk_sum, &hm, &forged_sum)
            .expect("vulnerable naive verification accepts forged aggregate");

        let forged_partials = [forged_partial1, forged_partial2];
        let result = batch_verify_same_message::<_, V, _>(
            &mut rng,
            &sharing,
            namespace,
            msg,
            &forged_partials,
            &Sequential,
        );
        assert!(
            result.is_err(),
            "secure function should reject forged partial signatures"
        );

        let valid_partials = [partial1, partial2];
        batch_verify_same_message::<_, V, _>(
            &mut rng,
            &sharing,
            namespace,
            msg,
            &valid_partials,
            &Sequential,
        )
        .expect("secure function should accept valid partial signatures");
    }

    #[test]
    fn test_batch_verify_same_message_rejects_malleability() {
        batch_verify_same_message_rejects_malleability::<MinPk>();
        batch_verify_same_message_rejects_malleability::<MinSig>();
    }

    fn batch_verify_same_signer_rejects_malleability<V: Variant>() {
        let mut rng = test_rng();
        let n = 5;
        let (sharing, shares) =
            dkg::deal_anonymous::<V, N3f1>(&mut rng, Default::default(), NZU32!(n));
        let namespace: &[u8] = b"test";
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
        let hm1 = hash_with_namespace::<V>(V::MESSAGE, namespace, msg1);
        let hm2 = hash_with_namespace::<V>(V::MESSAGE, namespace, msg2);
        let hm_sum = hm1 + &hm2;
        V::verify(&pk, &hm_sum, &forged_sum)
            .expect("vulnerable naive verification accepts forged aggregate");

        let forged_entries = vec![
            (namespace, msg1, forged_partial1),
            (namespace, msg2, forged_partial2),
        ];
        let result = batch_verify_same_signer::<_, V, _>(
            &mut rng,
            &sharing,
            signer.index,
            &forged_entries,
            &Sequential,
        );
        assert!(
            result.is_err(),
            "secure function should reject forged partial signatures"
        );

        let valid_entries = vec![(namespace, msg1, partial1), (namespace, msg2, partial2)];
        batch_verify_same_signer::<_, V, _>(
            &mut rng,
            &sharing,
            signer.index,
            &valid_entries,
            &Sequential,
        )
        .expect("secure function should accept valid partial signatures");
    }

    #[test]
    fn test_batch_verify_same_signer_rejects_malleability() {
        batch_verify_same_signer_rejects_malleability::<MinPk>();
        batch_verify_same_signer_rejects_malleability::<MinSig>();
    }
}
