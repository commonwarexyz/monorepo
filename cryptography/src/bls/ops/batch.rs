//! Batch verification for BLS signatures.
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
//! which an attacker cannot arrange without predicting the weights. The soundness error is at most
//! `2^-128` per check.
use super::{
    super::{Error, variant::Variant},
    hash_with_namespace,
};
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use commonware_math::algebra::{Additive, CryptoGroup, PairingGroup, Random, Space};
use commonware_parallel::Strategy;
use commonware_utils::iter::NonEmpty;
use core::num::NonZeroUsize;
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

    /// Returns indices of invalid leaves, in ascending order, by bisecting into failing
    /// subtrees.
    ///
    /// If `root_invalid` is true, skips verifying the root node (useful when
    /// caller has already verified the aggregate is invalid).
    fn verify(&self, hm: &V::Signature, root_invalid: bool) -> Vec<usize> {
        if self.len == 0 {
            return Vec::new();
        }

        // Initialize stack based on whether root is known invalid. Each node's right child is
        // pushed before its left, so invalid leaves are found in ascending order.
        let mut invalid = Vec::new();
        let mut stack = if root_invalid && self.len > 1 {
            // Skip root, start with its children.
            let mid = self.len / 2;
            vec![(3usize, mid, self.len), (2usize, 0, mid)]
        } else if root_invalid {
            // Single leaf and root is invalid means this leaf is invalid.
            invalid.push(0);
            return invalid;
        } else {
            vec![(1usize, 0usize, self.len)]
        };

        while let Some((node, start, end)) = stack.pop() {
            let (pk, sig) = self.tree[node].expect("node exists");

            // A valid subtree has only valid leaves.
            if super::verify_hashed::<V>(&pk, hm, &sig).is_ok() {
                continue;
            }

            // Invalid leaf found.
            if end - start == 1 {
                invalid.push(start);
                continue;
            }

            // Recurse into children to find invalid leaves.
            let mid = start + (end - start) / 2;
            stack.push((2 * node + 1, mid, end));
            stack.push((2 * node, start, mid));
        }

        invalid
    }
}

/// Find the indices of invalid entries, in ascending order, by bisecting each batch the strategy
/// splits the entries into.
///
/// The aggregate of all entries must have already failed verification.
fn bisect<V: Variant>(
    entries: &[(V::Public, V::Signature)],
    hm: &V::Signature,
    strategy: &impl Strategy,
) -> Vec<usize> {
    if entries.is_empty() {
        return Vec::new();
    }

    // A whole-input batch's root is the aggregate the caller already found invalid, so it skips
    // verifying that root. A split batch's root may be valid, so every split batch verifies its
    // own. Batches cover ascending ranges in order, so concatenating their ascending indices
    // needs no sort.
    strategy.run_batches(entries.len(), NonZeroUsize::MIN, 1, |batches| {
        let root_invalid = batches.is_whole();
        batches
            .map_collect_vec(
                |ranges| ranges,
                |range| {
                    let offset = range.start;
                    SegmentTree::<V>::build(&entries[range])
                        .verify(hm, root_invalid)
                        .into_iter()
                        .map(|index| offset + index)
                        .collect::<Vec<_>>()
                },
            )
            .into_iter()
            .flatten()
            .collect()
    })
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
pub fn verify_same_message<R, V, I>(
    rng: &mut R,
    namespace: &[u8],
    message: &[u8],
    entries: NonEmpty<I>,
    par: &impl Strategy,
) -> Vec<usize>
where
    R: CryptoRng,
    V: Variant,
    I: Iterator<Item = (V::Public, V::Signature)>,
{
    // Every entry signs the same message, so hash it once for the shared pairing input.
    let hm = hash_with_namespace::<V>(V::MESSAGE, namespace, message);

    // Extract pks and sigs for MSM.
    let (pks, sigs) = entries.into_iter().collect::<(Vec<_>, Vec<_>)>();

    // Generate 128-bit random scalars (sufficient for batch verification security)
    let scalars: Vec<V::Challenge> = (0..pks.len())
        .map(|_| V::Challenge::random(&mut *rng))
        .collect();

    // Compute MSMs for pk and sig in parallel using 128-bit scalars.
    let (sum_pk, sum_sig) = par.join(
        || V::Public::msm(&pks, &scalars, par),
        || V::Signature::msm(&sigs, &scalars, par),
    );

    // Fast path: if all signatures are valid, return empty
    if super::verify_hashed::<V>(&sum_pk, &hm, &sum_sig).is_ok() {
        return Vec::new();
    }

    // Slow path: bisection to find invalid signatures
    // Pre-compute individual weighted values for bisection
    let weighted_entries = par.map_collect_vec(
        scalars.iter().zip(pks.iter().zip(sigs.iter())),
        |(s, (&pk, &sig))| (pk * s, sig * s),
    );
    bisect::<V>(&weighted_entries, &hm, par)
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
    entries: NonEmpty<I>,
    strategy: &impl Strategy,
) -> Result<(), Error>
where
    R: CryptoRng,
    V: Variant,
    I: Iterator<Item = (&'a [u8], &'a [u8], V::Signature)>,
{
    let entries: Vec<_> = entries.into_iter().collect();

    // Generate 128-bit random scalars (sufficient for batch verification security)
    let scalars: Vec<V::Challenge> = (0..entries.len())
        .map(|_| V::Challenge::random(&mut *rng))
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
    super::verify_hashed::<V>(public, &weighted_hm, &weighted_sig)
}

/// Verifies signatures over distinct pre-hashed messages from distinct public keys, as one
/// check.
///
/// An empty batch and any batch containing an identity signature are invalid.
///
/// This outperforms individual verification (`2` pairings per signature) by verifying a random
/// linear combination of the equations (`n+1` pairings for `n` signatures). Unlike
/// [verify_same_message], it does not identify which signatures are invalid.
///
/// Source: <https://ethresear.ch/t/security-of-bls-batch-verification/10748>
///
/// # Panics
///
/// Panics if `publics`, `hms`, and `signatures` have different lengths.
pub fn verify_hashed<V: Variant>(
    rng: &mut impl CryptoRng,
    publics: &[V::Public],
    hms: &[V::Signature],
    signatures: &[V::Signature],
    strategy: &impl Strategy,
) -> Result<(), Error> {
    assert_eq!(publics.len(), hms.len());
    assert_eq!(publics.len(), signatures.len());
    if publics.is_empty() || signatures.contains(&V::Signature::zero()) {
        return Err(Error::InvalidSignature);
    }

    // Each signature satisfies e(pk_i, hm_i) - e(g, sig_i) == 0. With independent challenges
    // r_i, bilinearity turns sum_i r_i * (e(pk_i, hm_i) - e(g, sig_i)) == 0 into
    // sum_i r_i * e(pk_i, hm_i) + e(-g, sum_i r_i * sig_i) == 0.
    let challenges: Vec<V::Challenge> = (0..publics.len())
        .map(|_| V::Challenge::random(&mut *rng))
        .collect();
    let aggregate = V::Signature::msm(signatures, &challenges, strategy);

    // The aggregate term is already weighted, so it joins the scaled multi-pairing as the last
    // pair, which has no challenge and is added unscaled. A separate pairing would cost a second
    // final exponentiation.
    let mut lefts = publics.to_vec();
    lefts.push(-V::Public::generator());
    let mut rights = hms.to_vec();
    rights.push(aggregate);

    let sum = V::Public::scaled_multi_pairing(&lefts, &rights, &challenges, strategy);
    if sum != <V::Public as PairingGroup>::Target::zero() {
        return Err(Error::InvalidSignature);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        super::{aggregate, hash_with_namespace, keypair, sign_message, verify_message},
        *,
    };
    use crate::bls12381::primitives::variant::{MinPk, MinSig};
    use commonware_math::algebra::{Additive, CryptoGroup, Random};
    use commonware_parallel::{Sequential, mocks::explore};
    use commonware_utils::{non_empty, test_rng};

    fn verify_hashed_correct<V: Variant>() {
        let mut rng = test_rng();
        let (private1, public1) = keypair::<_, V>(&mut rng);
        let (private2, public2) = keypair::<_, V>(&mut rng);
        let (private3, public3) = keypair::<_, V>(&mut rng);

        let msg1: &[u8] = b"message 1";
        let msg2: &[u8] = b"message 2";
        let msg3: &[u8] = b"message 3";

        let sig1 = sign_message::<V>(&private1, b"test", msg1);
        let sig2 = sign_message::<V>(&private2, b"test", msg2);
        let sig3 = sign_message::<V>(&private3, b"test", msg3);

        let hm1 = hash_with_namespace::<V>(V::MESSAGE, b"test", msg1);
        let hm2 = hash_with_namespace::<V>(V::MESSAGE, b"test", msg2);
        let hm3 = hash_with_namespace::<V>(V::MESSAGE, b"test", msg3);

        assert!(
            explore(|strategy| {
                verify_hashed::<V>(
                    &mut rng,
                    &[public1, public2, public3],
                    &[hm1, hm2, hm3],
                    &[sig1, sig2, sig3],
                    strategy,
                )
                .is_ok()
            }),
            "a valid batch must verify"
        );
    }

    #[test]
    fn test_batch_verify_correct() {
        verify_hashed_correct::<MinPk>();
        verify_hashed_correct::<MinSig>();
    }

    fn verify_hashed_rejects_empty<V: Variant>() {
        assert!(matches!(
            verify_hashed::<V>(&mut test_rng(), &[], &[], &[], &Sequential),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn test_batch_verify_rejects_empty() {
        verify_hashed_rejects_empty::<MinPk>();
        verify_hashed_rejects_empty::<MinSig>();
    }

    fn verify_hashed_rejects_identity_entry<V: Variant>() {
        let mut rng = test_rng();
        let (private, public) = keypair::<_, V>(&mut rng);
        let namespace = b"test";
        let message = b"message";
        let signature = sign_message::<V>(&private, namespace, message);
        let hm = hash_with_namespace::<V>(V::MESSAGE, namespace, message);
        let identity_public = V::Public::zero();
        let identity_signature = V::Signature::zero();
        let identity_hm = hash_with_namespace::<V>(V::MESSAGE, namespace, b"identity entry");

        assert!(matches!(
            verify_hashed::<V>(
                &mut rng,
                &[public, identity_public],
                &[hm, identity_hm],
                &[signature, identity_signature],
                &Sequential,
            ),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn test_batch_verify_rejects_identity_entry() {
        verify_hashed_rejects_identity_entry::<MinPk>();
        verify_hashed_rejects_identity_entry::<MinSig>();
    }

    // An identity public key or hashed message pairs to zero, so an entry with one and a
    // signature that is not the identity breaks the batch equation.
    fn verify_hashed_rejects_identity_public<V: Variant>() {
        let mut rng = test_rng();
        let (private1, public1) = keypair::<_, V>(&mut rng);
        let (private2, _) = keypair::<_, V>(&mut rng);
        let sig1 = sign_message::<V>(&private1, b"test", b"message 1");
        let sig2 = sign_message::<V>(&private2, b"test", b"message 2");
        let hm1 = hash_with_namespace::<V>(V::MESSAGE, b"test", b"message 1");
        let hm2 = hash_with_namespace::<V>(V::MESSAGE, b"test", b"message 2");

        assert!(matches!(
            verify_hashed::<V>(
                &mut rng,
                &[public1, V::Public::zero()],
                &[hm1, hm2],
                &[sig1, sig2],
                &Sequential,
            ),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn test_batch_verify_rejects_identity_public() {
        verify_hashed_rejects_identity_public::<MinPk>();
        verify_hashed_rejects_identity_public::<MinSig>();
    }

    fn verify_hashed_rejects_identity_message<V: Variant>() {
        let mut rng = test_rng();
        let (private1, public1) = keypair::<_, V>(&mut rng);
        let (private2, public2) = keypair::<_, V>(&mut rng);
        let sig1 = sign_message::<V>(&private1, b"test", b"message 1");
        let sig2 = sign_message::<V>(&private2, b"test", b"message 2");
        let hm1 = hash_with_namespace::<V>(V::MESSAGE, b"test", b"message 1");

        assert!(matches!(
            verify_hashed::<V>(
                &mut rng,
                &[public1, public2],
                &[hm1, V::Signature::zero()],
                &[sig1, sig2],
                &Sequential,
            ),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn test_batch_verify_rejects_identity_message() {
        verify_hashed_rejects_identity_message::<MinPk>();
        verify_hashed_rejects_identity_message::<MinSig>();
    }

    fn verify_same_message_detects_identity_public<V: Variant>() {
        let mut rng = test_rng();
        let (private1, public1) = keypair::<_, V>(&mut rng);
        let (private2, _) = keypair::<_, V>(&mut rng);
        let namespace = b"test";
        let message = b"message";
        let entries = [
            (public1, sign_message::<V>(&private1, namespace, message)),
            (
                V::Public::zero(),
                sign_message::<V>(&private2, namespace, message),
            ),
        ];

        assert_eq!(
            verify_same_message::<_, V, _>(
                &mut rng,
                namespace,
                message,
                non_empty![@entries.iter().copied()],
                &Sequential,
            ),
            vec![1]
        );
    }

    #[test]
    fn test_verify_same_message_detects_identity_public() {
        verify_same_message_detects_identity_public::<MinPk>();
        verify_same_message_detects_identity_public::<MinSig>();
    }

    fn verify_same_signer_rejects_identity_public<V: Variant>() {
        let mut rng = test_rng();
        let (private, _) = keypair::<_, V>(&mut rng);
        let namespace: &[u8] = b"test";
        let message: &[u8] = b"message";
        let entries = [(
            namespace,
            message,
            sign_message::<V>(&private, namespace, message),
        )];

        assert!(matches!(
            verify_same_signer::<_, V, _>(
                &mut rng,
                &V::Public::zero(),
                non_empty![@entries.iter().copied()],
                &Sequential,
            ),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn test_verify_same_signer_rejects_identity_public() {
        verify_same_signer_rejects_identity_public::<MinPk>();
        verify_same_signer_rejects_identity_public::<MinSig>();
    }

    fn verify_hashed_rejects_malleability<V: Variant>() {
        let mut rng = test_rng();
        let (private1, public1) = keypair::<_, V>(&mut rng);
        let (private2, public2) = keypair::<_, V>(&mut rng);

        let msg1: &[u8] = b"message 1";
        let msg2: &[u8] = b"message 2";

        let sig1 = sign_message::<V>(&private1, b"test", msg1);
        let sig2 = sign_message::<V>(&private2, b"test", msg2);

        let hm1 = hash_with_namespace::<V>(V::MESSAGE, b"test", msg1);
        let hm2 = hash_with_namespace::<V>(V::MESSAGE, b"test", msg2);

        // Forge signatures that cancel out: sig1' = sig1 - delta, sig2' = sig2 + delta
        let random_scalar = V::Scalar::random(&mut rng);
        let delta = V::Signature::generator() * &random_scalar;
        let forged_sig1 = sig1 - &delta;
        let forged_sig2 = sig2 + &delta;

        // Individual verification should fail for forged signatures
        assert!(
            super::super::verify_hashed::<V>(&public1, &hm1, &forged_sig1).is_err(),
            "forged sig1 should be invalid individually"
        );
        assert!(
            super::super::verify_hashed::<V>(&public2, &hm2, &forged_sig2).is_err(),
            "forged sig2 should be invalid individually"
        );

        // Naive aggregate verification would accept forged signatures because:
        // sig1' + sig2' = (sig1 - delta) + (sig2 + delta) = sig1 + sig2
        let forged_agg = forged_sig1 + &forged_sig2;
        let valid_agg = sig1 + &sig2;
        assert_eq!(forged_agg, valid_agg, "aggregates should be equal");

        // batch_verify with random weights should reject forged signatures
        let result = verify_hashed::<V>(
            &mut rng,
            &[public1, public2],
            &[hm1, hm2],
            &[forged_sig1, forged_sig2],
            &Sequential,
        );
        assert!(
            result.is_err(),
            "batch_verify should reject forged signatures"
        );

        // Valid signatures should still pass
        verify_hashed::<V>(
            &mut rng,
            &[public1, public2],
            &[hm1, hm2],
            &[sig1, sig2],
            &Sequential,
        )
        .expect("valid signatures should pass batch_verify");
    }

    #[test]
    fn test_batch_verify_rejects_malleability() {
        verify_hashed_rejects_malleability::<MinPk>();
        verify_hashed_rejects_malleability::<MinSig>();
    }

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

        assert!(
            explore(|strategy| {
                verify_same_signer::<_, V, _>(
                    &mut rng,
                    &public,
                    non_empty![@entries.iter().copied()],
                    strategy,
                )
                .is_ok()
            }),
            "valid signatures must verify"
        );
    }

    #[test]
    fn test_verify_same_signer_correct() {
        verify_same_signer_correct::<MinPk>();
        verify_same_signer_correct::<MinSig>();
    }

    fn verify_same_signer_rejects_identity_signature<V: Variant>() {
        let mut rng = test_rng();
        let (_, public) = keypair::<_, V>(&mut rng);
        let namespace: &[u8] = b"test";
        let message: &[u8] = b"message";
        let entries = [(namespace, message, V::Signature::zero())];

        assert!(matches!(
            verify_same_signer::<_, V, _>(
                &mut rng,
                &public,
                non_empty![@entries.iter().copied()],
                &Sequential,
            ),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn test_verify_same_signer_rejects_identity_signature() {
        verify_same_signer_rejects_identity_signature::<MinPk>();
        verify_same_signer_rejects_identity_signature::<MinSig>();
    }

    fn verify_same_message_detects_identity_signature<V: Variant>() {
        let mut rng = test_rng();
        let (_, public) = keypair::<_, V>(&mut rng);
        let namespace = b"test";
        let message = b"message";
        let entries = [(public, V::Signature::zero())];

        assert_eq!(
            verify_same_message::<_, V, _>(
                &mut rng,
                namespace,
                message,
                non_empty![@entries.iter().copied()],
                &Sequential,
            ),
            vec![0]
        );
    }

    #[test]
    fn test_verify_same_message_detects_identity_signature() {
        verify_same_message_detects_identity_signature::<MinPk>();
        verify_same_message_detects_identity_signature::<MinSig>();
    }

    /// Bisection must report exactly the corrupted entries in every execution shape.
    ///
    /// Entries are corrupted alone and in pairs, at every position, in inputs shorter and longer
    /// than the planning parallelism. Parallel runs include single-entry batches, where assuming
    /// the root invalid would report a valid entry.
    ///
    /// A pair is corrupted by opposite offsets that cancel in an unweighted aggregate, so the test
    /// also checks that bisection runs on the weighted entries.
    fn verify_same_message_finds_corrupted_entries_in_every_shape<V: Variant>() {
        fn find<V: Variant>(
            rng: &mut impl CryptoRng,
            entries: &[(V::Public, V::Signature)],
            strategy: &impl Strategy,
        ) -> Vec<usize> {
            verify_same_message::<_, V, _>(
                rng,
                b"test",
                b"message",
                non_empty![@entries.iter().copied()],
                strategy,
            )
        }
        let mut rng = test_rng();
        for total in 1..=9 {
            let valid: Vec<(V::Public, V::Signature)> = (0..total)
                .map(|_| {
                    let (private, public) = keypair::<_, V>(&mut rng);
                    (public, sign_message::<V>(&private, b"test", b"message"))
                })
                .collect();
            let singles = (0..total).map(|i| vec![i]);
            let pairs = (0..total).flat_map(|i| (i + 1..total).map(move |j| vec![i, j]));
            for corrupted in singles.chain(pairs) {
                let mut entries = valid.clone();
                let offset = V::Signature::generator() * &V::Scalar::random(&mut rng);
                match corrupted[..] {
                    [index] => entries[index].1 += &offset,
                    [first, second] => {
                        entries[first].1 += &offset;
                        entries[second].1 -= &offset;
                    }
                    _ => unreachable!(),
                }
                let found = explore(|strategy| find::<V>(&mut rng, &entries, strategy));
                assert_eq!(
                    found, corrupted,
                    "bisection must report exactly {corrupted:?} of {total} entries"
                );
            }
        }
    }

    #[test]
    fn test_verify_same_message_finds_corrupted_entries_in_every_shape() {
        verify_same_message_finds_corrupted_entries_in_every_shape::<MinPk>();
        verify_same_message_finds_corrupted_entries_in_every_shape::<MinSig>();
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

        let random_scalar = V::Scalar::random(&mut rng);
        entries[1].2 += &(V::Signature::generator() * &random_scalar);

        let result = verify_same_signer::<_, V, _>(
            &mut rng,
            &public,
            non_empty![@entries.iter().copied()],
            &Sequential,
        );
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
        let random_scalar = V::Scalar::random(&mut rng);
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
        let forged_signatures = [forged_sig1, forged_sig2];
        let valid_signatures = [sig1, sig2];
        let forged_agg =
            aggregate::combine_signatures::<V, _>(non_empty![@forged_signatures.iter()]);
        let valid_agg = aggregate::combine_signatures::<V, _>(non_empty![@valid_signatures.iter()]);
        assert_eq!(forged_agg, valid_agg, "aggregates should be equal");

        // Naive aggregate verification accepts forged signatures
        let hm1 = hash_with_namespace::<V>(V::MESSAGE, namespace, msg1);
        let hm2 = hash_with_namespace::<V>(V::MESSAGE, namespace, msg2);
        let hm_sum = hm1 + &hm2;
        crate::bls::ops::verify_hashed::<V>(&public, &hm_sum, forged_agg.inner())
            .expect("naive aggregate verification accepts forged aggregate");

        // Batch verification (with random weights) rejects forged signatures
        let forged_entries: Vec<(&[u8], &[u8], _)> = vec![
            (namespace, msg1, forged_sig1),
            (namespace, msg2, forged_sig2),
        ];
        let result = verify_same_signer::<_, V, _>(
            &mut rng,
            &public,
            non_empty![@forged_entries.iter().copied()],
            &Sequential,
        );
        assert!(
            result.is_err(),
            "batch verification should reject forged signatures"
        );

        // Batch verification accepts valid signatures
        let valid_entries: Vec<(&[u8], &[u8], _)> =
            vec![(namespace, msg1, sig1), (namespace, msg2, sig2)];
        verify_same_signer::<_, V, _>(
            &mut rng,
            &public,
            non_empty![@valid_entries.iter().copied()],
            &Sequential,
        )
        .expect("batch verification should accept valid signatures");
    }

    #[test]
    fn test_rejects_malleability() {
        rejects_malleability::<MinPk>();
        rejects_malleability::<MinSig>();
    }
}
