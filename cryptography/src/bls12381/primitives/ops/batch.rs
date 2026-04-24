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
use alloc::{vec, vec::Vec};
use commonware_math::algebra::Space;
use commonware_parallel::Strategy;
use rand_core::CryptoRngCore;

/// Segment tree for batch verification bisection.
///
/// Stores aggregated (public_key, signature) sums at each node, enabling O(log k)
/// identification of k invalid signatures. Uses 1-indexed array layout:
///
/// ```text
///            [1]           <- root covers [0, 4)
///           /   \
///        [2]     [3]       <- cover [0, 2) and [2, 4)
///        / \     / \
///      [4] [5] [6] [7]     <- leaves cover [0,1), [1,2), [2,3), [3,4)
/// ```
///
/// Node `i` has children at `2i` (left) and `2i+1` (right).
struct SegmentTree<V: Variant> {
    len: usize,
    tree: Vec<Option<(V::Public, V::Signature)>>,
}

impl<V: Variant> SegmentTree<V> {
    /// Build segment tree from leaves in O(n) time.
    fn build(leaves: &[(V::Public, V::Signature)]) -> Self {
        let len = leaves.len();
        if len == 0 {
            return Self {
                len,
                tree: Vec::new(),
            };
        }

        // 4n allocation safely handles all tree sizes (non-power-of-2 included).
        let mut tree = vec![None; 4 * len];

        // Iterative post-order traversal: visit children before parent.
        // `children_built` tracks whether we've already processed children.
        let mut stack = vec![(1usize, 0usize, len, false)];
        while let Some((node, start, end, children_built)) = stack.pop() {
            if end - start == 1 {
                tree[node] = Some(leaves[start]);
            } else if !children_built {
                // First visit: descend into children, revisit this node after.
                let mid = start + (end - start) / 2;
                stack.push((node, start, end, true));
                stack.push((2 * node + 1, mid, end, false));
                stack.push((2 * node, start, mid, false));
            } else {
                // Second visit: combine children.
                let left = tree[2 * node].expect("left child built");
                let right = tree[2 * node + 1].expect("right child built");
                tree[node] = Some((left.0 + &right.0, left.1 + &right.1));
            }
        }

        Self { len, tree }
    }

    /// Returns indices of invalid leaves by bisecting into failing subtrees.
    ///
    /// If `root_invalid` is true, skips verifying the root node (useful when
    /// caller has already verified the aggregate is invalid).
    fn verify(&self, hm: &V::Signature, root_invalid: bool) -> Vec<usize> {
        if self.len == 0 {
            return Vec::new();
        }

        // Initialize stack based on whether root is known invalid.
        let mut invalid = Vec::new();
        let mut stack = if root_invalid && self.len > 1 {
            // Skip root, start with its children.
            let mid = self.len / 2;
            vec![(2usize, 0, mid), (3usize, mid, self.len)]
        } else if root_invalid {
            // Single leaf and root is invalid means this leaf is invalid.
            invalid.push(0);
            return invalid;
        } else {
            vec![(1usize, 0usize, self.len)]
        };

        while let Some((node, start, end)) = stack.pop() {
            let (pk, sig) = self.tree[node].expect("node exists");

            // Valid subtree - all leaves below are valid.
            if V::verify(&pk, hm, &sig).is_ok() {
                continue;
            }

            // Invalid leaf found.
            if end - start == 1 {
                invalid.push(start);
                continue;
            }

            // Recurse into children to find invalid leaves.
            let mid = start + (end - start) / 2;
            stack.push((2 * node, start, mid));
            stack.push((2 * node + 1, mid, end));
        }

        invalid
    }
}

/// Find invalid entries using parallel bisection.
///
/// Splits entries into chunks for parallel processing, then uses segment tree
/// bisection within each chunk to identify invalid indices.
///
/// If `aggregate_invalid` is true, aggregate verification over all entries is skipped (already
/// known to be invalid). This enables callers to check the aggregate externally first before
/// setting up bisection (without performing a duplicate check here).
fn bisect<V: Variant>(
    entries: &[(V::Public, V::Signature)],
    hm: &V::Signature,
    aggregate_invalid: bool,
    strategy: &impl Strategy,
) -> Vec<usize> {
    if entries.is_empty() {
        return Vec::new();
    }

    // Single chunk: skip aggregate verification if caller already checked it.
    let par_hint = strategy.parallelism_hint();
    let chunk_size = entries.len().div_ceil(par_hint);
    if entries.len() <= chunk_size {
        let mut out = SegmentTree::<V>::build(entries).verify(hm, aggregate_invalid);
        out.sort_unstable();
        return out;
    }

    // Multiple chunks: verify each chunk root (may be valid or invalid).
    let mut out = strategy.fold(
        entries.chunks(chunk_size).enumerate(),
        || Vec::with_capacity(entries.len()),
        |mut acc, (i, chunk)| {
            // Indices returned are relative to chunk, so shift by chunk offset.
            let offset = i * chunk_size;
            acc.extend(
                SegmentTree::<V>::build(chunk)
                    .verify(hm, false)
                    .into_iter()
                    .map(|j| offset + j),
            );
            acc
        },
        |mut acc_l, mut acc_r| {
            acc_l.append(&mut acc_r);
            acc_l
        },
    );
    // Parallelism may re-order results.
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

    // Generate 128-bit random scalars (sufficient for batch verification security)
    let scalars: Vec<SmallScalar> = (0..entries.len())
        .map(|_| SmallScalar::random(&mut *rng))
        .collect();

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
    bisect::<V>(&weighted_entries, &hm, true, par)
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
