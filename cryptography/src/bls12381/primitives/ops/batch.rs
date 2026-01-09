//! Batch verification for BLS12-381 signatures.
//!
//! This module provides batch verification functions that ensure each individual
//! signature is valid (not just the aggregate). Use [`aggregate`](super::aggregate) instead
//! if you only need to verify aggregate validity (more efficient).
//!
//! # How It Works
//!
//! These functions apply random scalar weights to each signature before internally performing
//! [`aggregate`](super::aggregate) verification. Without weights, an attacker could forge invalid
//! signatures that cancel out when aggregated (e.g., one signature "too high" and another "too low"
//! by the same amount). With random weights `r_i`, the errors must satisfy `sum(r_i * err_i) = 0`,
//! which requires predicting the weights before they're generated (probability ~1/2^255 per invalid
//! signature). Note, the weights must be unpredictable to the attacker for this to work (i.e. they
//! must be generated securely).
use super::{
    super::{group::SmallScalar, variant::Variant, Error},
    hash_with_namespace,
};
#[cfg(not(feature = "std"))]
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec,
    vec::Vec,
};
use commonware_math::algebra::Space;
use commonware_parallel::Strategy;
use rand_core::CryptoRngCore;
#[cfg(feature = "std")]
use std::collections::{BTreeMap, BTreeSet};

struct SumTree<V: Variant> {
    len: usize,
    /// This could be optimized to use a more compact data structure, but correctness
    /// matters more
    values: BTreeMap<(usize, usize), (V::Public, V::Signature)>,
}

impl<V: Variant> SumTree<V> {
    pub fn build(leaves: &[(V::Public, V::Signature)]) -> Self {
        let mut values = BTreeMap::new();
        let len = leaves.len();
        if len == 0 {
            return Self { len, values };
        }

        // Use an explicit stack to build bottom-up with halving intervals.
        // Phase 0 = first visit (push children), Phase 1 = second visit (compute value)
        let mut stack: Vec<(usize, usize, u8)> = vec![(0, len, 0)];

        while let Some((start, end, phase)) = stack.pop() {
            if end - start == 1 {
                values.insert((start, end), leaves[start]);
            } else if phase == 0 {
                let mid = start + (end - start) / 2;
                stack.push((start, end, 1)); // Come back to compute this node
                stack.push((mid, end, 0)); // Right child
                stack.push((start, mid, 0)); // Left child
            } else {
                let mid = start + (end - start) / 2;
                let left = values.get(&(start, mid)).expect("left child should exist");
                let right = values.get(&(mid, end)).expect("right child should exist");
                values.insert((start, end), (left.0 + &right.0, left.1 + &right.1));
            }
        }

        Self { len, values }
    }

    pub fn verify(&self, hm: &V::Signature) -> Vec<usize> {
        let mut good = (0..self.len).collect::<BTreeSet<_>>();
        let mut work = vec![(0, self.len)];
        while let Some((start, end)) = work.pop() {
            if start == end {
                continue;
            }
            let (pk, sig) = self
                .values
                .get(&(start, end))
                .expect("SumTree should be correctly constructed");
            if V::verify(pk, hm, sig).is_ok() {
                continue;
            }
            if end == start + 1 {
                good.remove(&start);
                continue;
            }
            let mid = start + (end - start) / 2;
            work.push((start, mid));
            work.push((mid, end));
        }
        (0..self.len).filter(|x| !good.contains(x)).collect()
    }
}

fn bisect<V: Variant>(entries: &[(V::Public, V::Signature)], hm: &V::Signature) -> Vec<usize> {
    SumTree::<V>::build(entries).verify(hm)
}

fn bisect_par<V: Variant>(
    entries: &[(V::Public, V::Signature)],
    hm: &V::Signature,
    par: &impl Strategy,
) -> Vec<usize> {
    if entries.is_empty() {
        return Vec::new();
    }
    let par_hint = par.parallelism_hint();
    let chunk_size = entries.len().div_ceil(par_hint);

    let mut out = par.fold(
        entries.chunks(chunk_size).enumerate(),
        || Vec::with_capacity(entries.len()),
        |mut acc, (i, chunk)| {
            // We need to correct for the fact that bisect returns indices relative
            // to the local slice.
            let shift = i * chunk_size;
            acc.extend(bisect::<V>(chunk, hm).into_iter().map(|j| shift + j));
            acc
        },
        |mut acc_l, mut acc_r| {
            acc_l.append(&mut acc_r);
            acc_l
        },
    );
    // Just in case parallelism ends up re-ordering things.
    out.sort_unstable();
    out
}

/// Verifies multiple signatures over the same message from different public keys,
/// ensuring each individual signature is valid.
///
/// Returns the indices of any invalid signatures found.
///
/// # Performance
///
/// Uses MSM (multi-scalar multiplication) for efficient batch verification. The pk and sig
/// MSMs are computed in parallel when possible. Uses bisection to identify which signatures
/// are invalid (only when the batch fails). In the worst case, bisection can require more
/// verifications than checking each signature individually. If an invalid signer is detected,
/// consider blocking them from participating in future batches to better amortize the cost.
///
/// # Warning
///
/// This function assumes a group check was already performed on each public key
/// and signature. Duplicate public keys are safe because random scalar weights
/// ensure each (public key, signature) pair is verified independently.
pub fn verify_same_message<R, V>(
    rng: &mut R,
    namespace: &[u8],
    message: &[u8],
    entries: &[(V::Public, V::Signature)],
    par: &impl Strategy,
) -> Vec<usize>
where
    R: CryptoRngCore,
    V: Variant,
{
    if entries.is_empty() {
        return Vec::new();
    }

    let hm = hash_with_namespace::<V>(V::MESSAGE, namespace, message);

    let len = entries.len();

    // Generate 128-bit random scalars (sufficient for batch verification security)
    let scalars: Vec<SmallScalar> = (0..len).map(|_| SmallScalar::random(&mut *rng)).collect();

    // Extract pks and sigs for MSM
    let (pks, sigs) = entries.iter().cloned().collect::<(Vec<_>, Vec<_>)>();

    // Compute MSMs for pk and sig in parallel using 128-bit scalars.
    let (sum_pk, sum_sig) = par.join(
        || V::Public::msm(&pks, &scalars, par),
        || V::Signature::msm(&sigs, &scalars, par),
    );

    // Fast path: if all signatures are valid, return empty
    if V::verify(&sum_pk, &hm, &sum_sig).is_ok() {
        return Vec::new();
    }

    // Slow path: bisection to find invalid signatures
    // Pre-compute individual weighted values for bisection
    let weighted_entries = par.map_collect_vec(
        scalars.iter().zip(pks.iter().zip(sigs.iter())),
        |(s, (&pk, &sig))| (pk * s, sig * s),
    );
    bisect_par::<V>(&weighted_entries, &hm, par)
}

/// Verifies multiple signatures over multiple messages from a single public key,
/// ensuring each individual signature is valid.
///
/// Each entry is a tuple of (namespace, message, signature).
///
/// # Warning
///
/// This function assumes a group check was already performed on `public` and each `signature`.
/// Duplicate messages are safe because random scalar weights ensure each (message, signature)
/// pair is verified independently.
pub fn verify_same_signer<'a, R, V, I>(
    rng: &mut R,
    public: &V::Public,
    entries: I,
    strategy: &impl Strategy,
) -> Result<(), Error>
where
    R: CryptoRngCore,
    V: Variant,
    I: IntoIterator<Item = &'a (&'a [u8], &'a [u8], V::Signature)>,
{
    let entries: Vec<_> = entries.into_iter().collect();

    if entries.is_empty() {
        return Ok(());
    }

    // Generate 128-bit random scalars (sufficient for batch verification security)
    let scalars: Vec<SmallScalar> = (0..entries.len())
        .map(|_| SmallScalar::random(&mut *rng))
        .collect();

    // Hash all messages and collect signatures
    let hms: Vec<V::Signature> = strategy.map_collect_vec(entries.iter(), |(namespace, msg, _)| {
        hash_with_namespace::<V>(V::MESSAGE, namespace, msg)
    });
    let sigs: Vec<V::Signature> = entries.iter().map(|(_, _, sig)| *sig).collect();

    // Compute weighted sums in parallel using MSM with 128-bit scalars.
    let (weighted_hm, weighted_sig) = strategy.join(
        || V::Signature::msm(&hms, &scalars, strategy),
        || V::Signature::msm(&sigs, &scalars, strategy),
    );

    // Verify: e(pk, weighted_hm) == e(weighted_sig, G)
    V::verify(public, &weighted_hm, &weighted_sig)
}

#[cfg(test)]
mod tests {
    use super::{
        super::{
            super::group::Scalar, aggregate, hash_with_namespace, keypair, sign_message,
            verify_message,
        },
        *,
    };
    use crate::bls12381::primitives::variant::{MinPk, MinSig};
    use commonware_math::algebra::{CryptoGroup, Random};
    use commonware_parallel::{Rayon, Sequential};
    use commonware_utils::{test_rng, NZUsize};

    fn verify_same_signer_correct<V: Variant>() {
        let mut rng = test_rng();
        let (private, public) = keypair::<_, V>(&mut rng);
        let namespace = b"test";
        let messages: &[(&[u8], &[u8])] = &[
            (namespace, b"Message 1"),
            (namespace, b"Message 2"),
            (namespace, b"Message 3"),
        ];
        let entries: Vec<_> = messages
            .iter()
            .map(|(ns, msg)| (*ns, *msg, sign_message::<V>(&private, ns, msg)))
            .collect();

        verify_same_signer::<_, V, _>(&mut rng, &public, &entries, &Sequential)
            .expect("valid signatures should be accepted");

        let strategy = Rayon::new(NZUsize!(4)).unwrap();
        verify_same_signer::<_, V, _>(&mut rng, &public, &entries, &strategy)
            .expect("valid signatures should be accepted with parallel strategy");
    }

    #[test]
    fn test_verify_same_signer_correct() {
        verify_same_signer_correct::<MinPk>();
        verify_same_signer_correct::<MinSig>();
    }

    fn verify_same_signer_wrong_signature<V: Variant>() {
        let mut rng = test_rng();
        let (private, public) = keypair::<_, V>(&mut rng);
        let namespace = b"test";
        let messages: &[(&[u8], &[u8])] = &[
            (namespace, b"Message 1"),
            (namespace, b"Message 2"),
            (namespace, b"Message 3"),
        ];
        let mut entries: Vec<_> = messages
            .iter()
            .map(|(ns, msg)| (*ns, *msg, sign_message::<V>(&private, ns, msg)))
            .collect();

        let random_scalar = Scalar::random(&mut rng);
        entries[1].2 += &(V::Signature::generator() * &random_scalar);

        let result = verify_same_signer::<_, V, _>(&mut rng, &public, &entries, &Sequential);
        assert!(result.is_err(), "corrupted signature should be rejected");
    }

    #[test]
    fn test_verify_same_signer_wrong_signature() {
        verify_same_signer_wrong_signature::<MinPk>();
        verify_same_signer_wrong_signature::<MinSig>();
    }

    fn rejects_malleability<V: Variant>() {
        let mut rng = test_rng();
        let (private, public) = keypair::<_, V>(&mut rng);
        let namespace = b"test";
        let msg1: &[u8] = b"message 1";
        let msg2: &[u8] = b"message 2";

        let sig1 = sign_message::<V>(&private, namespace, msg1);
        let sig2 = sign_message::<V>(&private, namespace, msg2);

        verify_message::<V>(&public, namespace, msg1, &sig1).expect("sig1 should be valid");
        verify_message::<V>(&public, namespace, msg2, &sig2).expect("sig2 should be valid");

        // Create forged signatures that cancel out when aggregated
        let random_scalar = Scalar::random(&mut rng);
        let delta = V::Signature::generator() * &random_scalar;
        let forged_sig1 = sig1 - &delta;
        let forged_sig2 = sig2 + &delta;

        // Forged signatures are invalid individually
        assert!(
            verify_message::<V>(&public, namespace, msg1, &forged_sig1).is_err(),
            "forged sig1 should be invalid individually"
        );
        assert!(
            verify_message::<V>(&public, namespace, msg2, &forged_sig2).is_err(),
            "forged sig2 should be invalid individually"
        );

        // But aggregates are identical (the attack)
        let forged_agg = aggregate::combine_signatures::<V, _>(&[forged_sig1, forged_sig2]);
        let valid_agg = aggregate::combine_signatures::<V, _>(&[sig1, sig2]);
        assert_eq!(forged_agg, valid_agg, "aggregates should be equal");

        // Naive aggregate verification accepts forged signatures
        let hm1 = hash_with_namespace::<V>(V::MESSAGE, namespace, msg1);
        let hm2 = hash_with_namespace::<V>(V::MESSAGE, namespace, msg2);
        let hm_sum = hm1 + &hm2;
        V::verify(&public, &hm_sum, forged_agg.inner())
            .expect("naive aggregate verification accepts forged aggregate");

        // Batch verification (with random weights) rejects forged signatures
        let forged_entries: Vec<(&[u8], &[u8], _)> = vec![
            (namespace, msg1, forged_sig1),
            (namespace, msg2, forged_sig2),
        ];
        let result = verify_same_signer::<_, V, _>(&mut rng, &public, &forged_entries, &Sequential);
        assert!(
            result.is_err(),
            "batch verification should reject forged signatures"
        );

        // Batch verification accepts valid signatures
        let valid_entries: Vec<(&[u8], &[u8], _)> =
            vec![(namespace, msg1, sig1), (namespace, msg2, sig2)];
        verify_same_signer::<_, V, _>(&mut rng, &public, &valid_entries, &Sequential)
            .expect("batch verification should accept valid signatures");
    }

    #[test]
    fn test_rejects_malleability() {
        rejects_malleability::<MinPk>();
        rejects_malleability::<MinSig>();
    }
}
