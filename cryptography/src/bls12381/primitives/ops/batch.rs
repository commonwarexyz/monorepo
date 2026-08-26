//! Batch verification for BLS12-381 signatures.
//!
//! This module provides batch verification functions that ensure each independently supplied
//! signature claim is valid. Multi-term aggregate claims are verified atomically.
//! Use [`aggregate`](super::aggregate) when only the combined aggregate must be valid.
//!
//! # How It Works
//!
//! These functions apply random scalar weights to each signature before internally performing
//! [`aggregate`](super::aggregate) verification. Without weights, an attacker could forge invalid
//! signatures that cancel out when aggregated (e.g., one signature "too high" and another "too low"
//! by the same amount). With random weights `r_i`, the errors must satisfy `sum(r_i * err_i) = 0`,
//! which an attacker cannot arrange without predicting the weights. The soundness error is at most
//! `2^-128` per check.
use super::{
    super::{Error, group::SmallScalar, variant::Variant},
    hash_with_namespace,
};
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use commonware_math::algebra::Space;
use commonware_parallel::Strategy;
use rand_core::CryptoRng;

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
    let manual = strategy.manual();
    let parallelism = manual.parallelism();
    let chunk_size = entries.len().div_ceil(parallelism);
    if entries.len() <= chunk_size {
        let mut out = SegmentTree::<V>::build(entries).verify(hm, aggregate_invalid);
        out.sort_unstable();
        return out;
    }

    // Multiple chunks: verify each chunk root (may be valid or invalid).
    let mut out = manual.fold(
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
    R: CryptoRng,
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

commonware_macros::stability_scope!(ALPHA {
    use commonware_math::algebra::Additive;
    use hashbrown::{HashMap, HashSet};

    type Term<'a, V> = (<V as Variant>::Public, &'a [u8], &'a [u8]);

    /// A durable batch of independently verifiable signature claims.
    ///
    /// A claim with one term is an ordinary signature. A claim with multiple terms is an aggregate
    /// signature, such as a quorum certificate over distinct votes, and is accepted or rejected as a
    /// unit.
    #[derive(Clone, Debug)]
    pub struct Verifier<'a, V: Variant> {
        claims: Vec<Claim<'a, V>>,
    }

    #[derive(Clone, Debug)]
    struct Claim<'a, V: Variant> {
        signature: V::Signature,
        terms: Vec<Term<'a, V>>,
    }

    struct CanonicalClaim<'a, V: Variant> {
        index: usize,
        signature: V::Signature,
        terms: Vec<Term<'a, V>>,
        message_groups: Vec<Term<'a, V>>,
    }

    impl<'a, V: Variant> Verifier<'a, V> {
        /// Creates a verifier with space for `capacity` claims.
        pub fn new(capacity: usize) -> Self {
            Self {
                claims: Vec::with_capacity(capacity),
            }
        }

        /// Queues a signature over the provided attributed terms.
        ///
        /// Public keys must be non-zero and unique within a claim. A claim must contain at least one
        /// term, and public keys signing the same message must be bound to their owners, such as by
        /// verified proofs of possession or a trusted threshold sharing.
        pub fn queue(&mut self, signature: V::Signature, terms: Vec<(V::Public, &'a [u8], &'a [u8])>) {
            self.claims.push(Claim { signature, terms });
        }

        /// Verifies every queued claim and returns the indices of invalid claims.
        ///
        /// Claims are randomly scaled so invalid signatures cannot cancel across claims. Pairing terms
        /// are grouped by common messages or common public keys, whichever requires fewer pairings.
        /// Structurally invalid claims are reported without entering the batch.
        ///
        /// # Warning
        ///
        /// This function assumes every public key and signature was group-checked while decoding.
        pub fn verify<R: CryptoRng>(self, rng: &mut R, strategy: &impl Strategy) -> Vec<usize> {
            let mut invalid = Vec::new();
            let mut pending = Vec::with_capacity(self.claims.len());
            for (index, claim) in self.claims.into_iter().enumerate() {
                if claim.signature == V::Signature::zero() {
                    invalid.push(index);
                    continue;
                }
                let Some(message_groups) = canonicalize::<V>(claim.terms.clone()) else {
                    invalid.push(index);
                    continue;
                };
                pending.push(CanonicalClaim {
                    index,
                    signature: claim.signature,
                    terms: claim.terms,
                    message_groups,
                });
            }
            verify_claims_bisect::<R, V>(rng, &pending, &mut invalid, strategy);
            invalid.sort_unstable();
            invalid
        }
    }

    fn group_by_message<V: Variant>(mut terms: Vec<Term<'_, V>>) -> Vec<Term<'_, V>> {
        terms.sort_unstable_by(|left, right| (left.1, left.2).cmp(&(right.1, right.2)));
        terms.dedup_by(|next, current| {
            if (next.1, next.2) != (current.1, current.2) {
                return false;
            }
            current.0 += &next.0;
            true
        });
        terms
    }

    fn canonicalize<V: Variant>(terms: Vec<Term<'_, V>>) -> Option<Vec<Term<'_, V>>> {
        if terms.is_empty() {
            return None;
        }

        let mut publics = HashSet::with_capacity(terms.len());
        if terms
            .iter()
            .any(|(public, _, _)| public == &V::Public::zero() || !publics.insert(*public))
        {
            return None;
        }

        let groups = group_by_message::<V>(terms);
        (!groups
            .iter()
            .any(|(public, _, _)| public == &V::Public::zero()))
        .then_some(groups)
    }

    fn verify_claims_bisect<R, V>(
        rng: &mut R,
        pending: &[CanonicalClaim<'_, V>],
        invalid: &mut Vec<usize>,
        strategy: &impl Strategy,
    ) where
        R: CryptoRng,
        V: Variant,
    {
        if pending.is_empty() || claims_product_holds::<R, V>(rng, pending, strategy) {
            return;
        }
        if pending.len() == 1 {
            invalid.push(pending[0].index);
            return;
        }
        let (left, right) = pending.split_at(pending.len() / 2);
        verify_claims_bisect::<R, V>(rng, left, invalid, strategy);
        verify_claims_bisect::<R, V>(rng, right, invalid, strategy);
    }

    fn claims_product_holds<R, V>(
        rng: &mut R,
        pending: &[CanonicalClaim<'_, V>],
        strategy: &impl Strategy,
    ) -> bool
    where
        R: CryptoRng,
        V: Variant,
    {
        // Draw scalars before parallel work so RNG consumption is independent of the strategy.
        let scalars: Vec<SmallScalar> = pending
            .iter()
            .map(|_| SmallScalar::random(&mut *rng))
            .collect();
        let signatures: Vec<V::Signature> = pending.iter().map(|claim| claim.signature).collect();
        let combined = V::Signature::msm(&signatures, &scalars, strategy);

        let term_count = pending.iter().map(|claim| claim.terms.len()).sum();
        let mut distinct_messages = HashSet::with_capacity(term_count);
        let mut distinct_publics = HashSet::with_capacity(term_count);
        for claim in pending {
            for &(public, namespace, message) in &claim.terms {
                distinct_messages.insert((namespace, message));
                distinct_publics.insert(public);
            }
        }

        let (publics, messages) = if distinct_publics.len() < distinct_messages.len() {
            group_messages_by_public::<V>(pending, &scalars, strategy)
        } else {
            group_publics_by_message::<V>(pending, &scalars, strategy)
        };
        V::verify_pairing_product(&publics, &messages, &combined, strategy).is_ok()
    }

    fn group_publics_by_message<V: Variant>(
        pending: &[CanonicalClaim<'_, V>],
        scalars: &[SmallScalar],
        strategy: &impl Strategy,
    ) -> (Vec<V::Public>, Vec<V::Signature>) {
        let scaled: Vec<Term<'_, V>> = strategy.map_collect_vec(
            pending.iter().zip(scalars).flat_map(|(claim, scalar)| {
                claim
                    .message_groups
                    .iter()
                    .map(move |&(public, namespace, message)| (public, namespace, message, scalar))
            }),
            |(public, namespace, message, scalar)| (public * scalar, namespace, message),
        );
        let terms = strategy.map_collect_vec(
            group_by_message::<V>(scaled),
            |(public, namespace, message)| {
                (
                    public,
                    hash_with_namespace::<V>(V::MESSAGE, namespace, message),
                )
            },
        );
        terms.into_iter().unzip()
    }

    fn group_messages_by_public<V: Variant>(
        pending: &[CanonicalClaim<'_, V>],
        scalars: &[SmallScalar],
        strategy: &impl Strategy,
    ) -> (Vec<V::Public>, Vec<V::Signature>) {
        let scaled = strategy.map_collect_vec(
            pending.iter().zip(scalars).flat_map(|(claim, scalar)| {
                claim
                    .terms
                    .iter()
                    .map(move |&(public, namespace, message)| (public, namespace, message, scalar))
            }),
            |(public, namespace, message, scalar)| {
                (
                    public,
                    hash_with_namespace::<V>(V::MESSAGE, namespace, message) * scalar,
                )
            },
        );

        let mut grouped = HashMap::with_capacity(scaled.len());
        for (public, message) in scaled {
            grouped
                .entry(public)
                .and_modify(|sum: &mut V::Signature| *sum += &message)
                .or_insert(message);
        }
        grouped.into_iter().unzip()
    }
});

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
    R: CryptoRng,
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
    use commonware_utils::{NZUsize, test_rng};

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

    fn claim_fixture<V: Variant>(
        rng: &mut impl rand_core::CryptoRng,
        count: usize,
    ) -> (Vec<V::Public>, Vec<Claim<'static, V>>) {
        let namespace: &'static [u8] = b"batch-claims";
        let messages: &'static [&'static [u8]] = &[
            b"message 0",
            b"message 1",
            b"message 2",
            b"message 3",
            b"message 4",
            b"message 5",
            b"message 6",
            b"message 7",
        ];
        let mut publics = Vec::with_capacity(count);
        let mut claims = Vec::with_capacity(count);
        for index in 0..count {
            let (private, public) = keypair::<_, V>(&mut *rng);
            let message = messages[index % messages.len()];
            let signature = sign_message::<V>(&private, namespace, message);
            publics.push(public);
            claims.push(Claim {
                signature,
                terms: vec![(public, namespace, message)],
            });
        }
        (publics, claims)
    }

    fn verifier<V: Variant>(claims: Vec<Claim<'static, V>>) -> Verifier<'static, V> {
        Verifier { claims }
    }

    fn verify_claims_correct<V: Variant>() {
        let mut rng = test_rng();
        assert!(
            Verifier::<V>::new(0)
                .verify(&mut rng, &Sequential)
                .is_empty()
        );

        let (_, claims) = claim_fixture::<V>(&mut rng, 6);
        assert!(
            verifier(claims.clone())
                .verify(&mut rng, &Sequential)
                .is_empty(),
            "valid claims should be accepted"
        );
        let strategy = Rayon::new(NZUsize!(4)).unwrap();
        assert!(
            verifier(claims).verify(&mut rng, &strategy).is_empty(),
            "valid claims should be accepted with parallel strategy"
        );
    }

    #[test]
    fn test_verify_claims_correct() {
        verify_claims_correct::<MinPk>();
        verify_claims_correct::<MinSig>();
    }

    fn verify_claims_isolates_invalid<V: Variant>() {
        let mut rng = test_rng();
        let (_, mut claims) = claim_fixture::<V>(&mut rng, 7);
        let tweak = Scalar::random(&mut rng);
        claims[2].signature += &(V::Signature::generator() * &tweak);
        claims[5].signature += &(V::Signature::generator() * &tweak);
        assert_eq!(
            verifier(claims).verify(&mut rng, &Sequential),
            vec![2, 5],
            "exactly the corrupted claims must be isolated"
        );
    }

    #[test]
    fn test_verify_claims_isolates_invalid() {
        verify_claims_isolates_invalid::<MinPk>();
        verify_claims_isolates_invalid::<MinSig>();
    }

    fn verify_claims_rejects_cross_cancellation<V: Variant>() {
        let mut rng = test_rng();
        let (_, mut claims) = claim_fixture::<V>(&mut rng, 4);
        let delta = V::Signature::generator() * &Scalar::random(&mut rng);
        claims[1].signature += &delta;
        claims[3].signature -= &delta;
        assert_eq!(
            verifier(claims).verify(&mut rng, &Sequential),
            vec![1, 3],
            "cancelling forgeries must both be rejected"
        );
    }

    #[test]
    fn test_verify_claims_rejects_cross_cancellation() {
        verify_claims_rejects_cross_cancellation::<MinPk>();
        verify_claims_rejects_cross_cancellation::<MinSig>();
    }

    fn verify_claims_multi_term_atomic<V: Variant>() {
        let mut rng = test_rng();
        let namespace: &[u8] = b"batch-claims";
        let (private_a, public_a) = keypair::<_, V>(&mut rng);
        let (private_b, public_b) = keypair::<_, V>(&mut rng);
        let sig_a = sign_message::<V>(&private_a, namespace, b"vote a");
        let sig_b = sign_message::<V>(&private_b, namespace, b"vote b");
        let aggregate = sig_a + &sig_b;
        let valid = Claim::<V> {
            signature: aggregate,
            terms: vec![
                (public_a, namespace, b"vote a" as &[u8]),
                (public_b, namespace, b"vote b" as &[u8]),
            ],
        };
        let (_, mut claims) = claim_fixture::<V>(&mut rng, 2);
        claims.push(valid);
        assert!(
            Verifier {
                claims: claims.clone()
            }
            .verify(&mut rng, &Sequential)
            .is_empty(),
            "a valid aggregate claim should be accepted alongside ordinary signatures"
        );

        claims[2] = Claim::<V> {
            signature: claims[2].signature,
            terms: vec![
                (public_a, namespace, b"vote a" as &[u8]),
                (public_b, namespace, b"vote c" as &[u8]),
            ],
        };
        assert_eq!(
            Verifier { claims }.verify(&mut rng, &Sequential),
            vec![2],
            "a broken aggregate claim must not poison ordinary signatures"
        );
    }

    #[test]
    fn test_verify_claims_multi_term_atomic() {
        verify_claims_multi_term_atomic::<MinPk>();
        verify_claims_multi_term_atomic::<MinSig>();
    }

    fn verify_claims_group_both_sides<V: Variant>() {
        let mut rng = test_rng();
        let namespace: &'static [u8] = b"batch-claims";
        let messages: [&'static [u8]; 4] = [b"one", b"two", b"three", b"four"];
        let (private, public) = keypair::<_, V>(&mut rng);
        let same_public: Vec<_> = messages
            .iter()
            .map(|&message| Claim::<V> {
                signature: sign_message::<V>(&private, namespace, message),
                terms: vec![(public, namespace, message)],
            })
            .collect();
        assert!(
            verifier(same_public.clone())
                .verify(&mut rng, &Sequential)
                .is_empty()
        );
        let mut corrupted = same_public;
        corrupted[2].signature += &(V::Signature::generator() * &Scalar::random(&mut rng));
        assert_eq!(verifier(corrupted).verify(&mut rng, &Sequential), vec![2]);

        let same_message: Vec<_> = (0..4)
            .map(|_| {
                let (private, public) = keypair::<_, V>(&mut rng);
                Claim::<V> {
                    signature: sign_message::<V>(&private, namespace, b"same"),
                    terms: vec![(public, namespace, b"same")],
                }
            })
            .collect();
        assert!(
            verifier(same_message)
                .verify(&mut rng, &Sequential)
                .is_empty()
        );
    }

    #[test]
    fn test_verify_claims_group_both_sides() {
        verify_claims_group_both_sides::<MinPk>();
        verify_claims_group_both_sides::<MinSig>();
    }

    fn verify_claims_structural_guards<V: Variant>() {
        let mut rng = test_rng();
        let (publics, mut claims) = claim_fixture::<V>(&mut rng, 3);
        claims.push(Claim {
            signature: claims[0].signature,
            terms: Vec::new(),
        });
        claims.push(Claim {
            signature: V::Signature::zero(),
            terms: vec![(publics[0], b"batch-claims", b"message 0")],
        });
        claims.push(Claim {
            signature: claims[1].signature,
            terms: vec![(V::Public::zero(), b"batch-claims", b"message 1")],
        });
        assert_eq!(
            Verifier { claims }.verify(&mut rng, &Sequential),
            vec![3, 4, 5],
            "empty, zero-signature, and zero-public claims are invalid"
        );
    }

    #[test]
    fn test_verify_claims_structural_guards() {
        verify_claims_structural_guards::<MinPk>();
        verify_claims_structural_guards::<MinSig>();
    }

    fn verify_claims_rejects_duplicate_publics<V: Variant>() {
        let mut rng = test_rng();
        let namespace: &[u8] = b"batch-claims";
        let (private, public) = keypair::<_, V>(&mut rng);
        let signature = sign_message::<V>(&private, namespace, b"duplicate");
        let duplicated = Claim::<V> {
            signature: signature + &signature,
            terms: vec![
                (public, namespace, b"duplicate" as &[u8]),
                (public, namespace, b"duplicate" as &[u8]),
            ],
        };
        assert_eq!(
            Verifier {
                claims: vec![duplicated]
            }
            .verify(&mut rng, &Sequential),
            vec![0]
        );
    }

    #[test]
    fn test_verify_claims_rejects_duplicate_publics() {
        verify_claims_rejects_duplicate_publics::<MinPk>();
        verify_claims_rejects_duplicate_publics::<MinSig>();
    }

    fn verify_claims_rejects_zero_sum_groups<V: Variant>() {
        let mut rng = test_rng();
        let namespace: &[u8] = b"batch-claims";
        let (base_private, base_public) = keypair::<_, V>(&mut rng);
        let base_signature = sign_message::<V>(&base_private, namespace, b"base");
        let (_, cancelling_public) = keypair::<_, V>(&mut rng);
        let cancelling = Claim::<V> {
            signature: base_signature,
            terms: vec![
                (base_public, namespace, b"base" as &[u8]),
                (cancelling_public, namespace, b"extra" as &[u8]),
                (-cancelling_public, namespace, b"extra" as &[u8]),
            ],
        };
        assert_eq!(
            Verifier {
                claims: vec![cancelling]
            }
            .verify(&mut rng, &Sequential),
            vec![0]
        );
    }

    #[test]
    fn test_verify_claims_rejects_zero_sum_groups() {
        verify_claims_rejects_zero_sum_groups::<MinPk>();
        verify_claims_rejects_zero_sum_groups::<MinSig>();
    }
}
