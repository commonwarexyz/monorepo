//! Batch verification for BLS12-381 signatures.
//!
//! This module provides batch verification functions that ensure each independently supplied
//! signature or aggregate transcript is valid. Multi-term transcripts are verified atomically.
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
#[stability(ALPHA)]
use super::aggregate::{TranscriptEntry, group_entries, group_transcript};
use super::{
    super::{Error, group::SmallScalar, variant::Variant},
    hash_with_namespace,
};
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use commonware_macros::stability;
#[stability(ALPHA)]
use commonware_math::algebra::Additive;
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

/// One independently signed transcript: `signature` covers every `(public, namespace,
/// message)` term.
///
/// A single-term transcript is an ordinary signature. A multi-term transcript is an aggregate
/// (e.g. a quorum certificate over distinct votes), which stands or falls atomically.
#[stability(ALPHA)]
#[derive(Clone, Debug)]
pub struct Transcript<'a, V: Variant> {
    /// The signature covering every term.
    pub signature: V::Signature,
    /// The signed `(public, namespace, message)` terms.
    pub terms: Vec<TranscriptEntry<'a, V>>,
}

/// A structurally valid transcript grouped by `(namespace, message)`.
#[stability(ALPHA)]
struct CanonicalTranscript<'a, V: Variant> {
    index: usize,
    signature: V::Signature,
    groups: Vec<TranscriptEntry<'a, V>>,
}

/// Verifies many independently signed transcripts at once, ensuring each individual
/// transcript is valid.
///
/// Returns the indices of any invalid transcripts found.
///
/// Every transcript is scaled by an unpredictable 128-bit scalar, so an error in one cannot
/// cancel an error in another (see the module docs). The whole batch uses one Miller loop per
/// distinct `(namespace, message)`, one for the combined signature, and one final exponentiation.
///
/// # Performance
///
/// Uses bisection to identify invalid transcripts when the batch fails. In the worst case, this
/// requires more work than checking each transcript individually.
///
/// # Security
///
/// This function assumes a group check was already performed on every public key and signature.
/// Each transcript must have at least one term, a non-zero signature, unique non-zero public keys,
/// and a non-zero public-key sum for each distinct `(namespace, message)` pair. Structurally invalid
/// transcripts are reported without entering the batch. When different public keys sign the same
/// message within a transcript, each key must be bound to its owner, such as by a verified proof of
/// possession or a trusted threshold sharing. Otherwise, the transcript is vulnerable to rogue-key
/// attacks. Duplicate public keys or messages across independently scaled transcripts are safe.
#[stability(ALPHA)]
pub fn verify_transcripts<R, V>(
    rng: &mut R,
    transcripts: &[Transcript<'_, V>],
    strategy: &impl Strategy,
) -> Vec<usize>
where
    R: CryptoRng,
    V: Variant,
{
    let mut invalid = Vec::new();
    let mut pending = Vec::with_capacity(transcripts.len());
    for (index, transcript) in transcripts.iter().enumerate() {
        if transcript.signature == V::Signature::zero() {
            invalid.push(index);
            continue;
        }
        let Ok(groups) = group_transcript::<V>(transcript.terms.iter().copied()) else {
            invalid.push(index);
            continue;
        };
        pending.push(CanonicalTranscript {
            index,
            signature: transcript.signature,
            groups,
        });
    }
    verify_transcripts_bisect::<R, V>(rng, &pending, &mut invalid, strategy);
    invalid.sort_unstable();
    invalid
}

/// Recursively bisects `pending` into halves until every invalid transcript is isolated.
#[stability(ALPHA)]
fn verify_transcripts_bisect<R, V>(
    rng: &mut R,
    pending: &[CanonicalTranscript<'_, V>],
    invalid: &mut Vec<usize>,
    strategy: &impl Strategy,
) where
    R: CryptoRng,
    V: Variant,
{
    if pending.is_empty() {
        return;
    }
    if transcripts_product_holds::<R, V>(rng, pending, strategy) {
        return;
    }
    if pending.len() == 1 {
        invalid.push(pending[0].index);
        return;
    }
    let (left, right) = pending.split_at(pending.len() / 2);
    verify_transcripts_bisect::<R, V>(rng, left, invalid, strategy);
    verify_transcripts_bisect::<R, V>(rng, right, invalid, strategy);
}

/// Checks the scaled pairing product over one set of transcripts.
#[stability(ALPHA)]
fn transcripts_product_holds<R, V>(
    rng: &mut R,
    pending: &[CanonicalTranscript<'_, V>],
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
    let signatures: Vec<V::Signature> = pending
        .iter()
        .map(|transcript| transcript.signature)
        .collect();
    let scaled_terms: Vec<TranscriptEntry<'_, V>> = strategy.map_collect_vec(
        pending
            .iter()
            .zip(scalars.iter())
            .flat_map(|(transcript, scalar)| {
                transcript
                    .groups
                    .iter()
                    .map(move |&(public, namespace, message)| (public, namespace, message, scalar))
            }),
        |(public, namespace, message, scalar)| (public * scalar, namespace, message),
    );
    let combined = V::Signature::msm(&signatures, &scalars, strategy);

    // Group identical (namespace, message) pairs so each distinct pair costs one pairing.
    let groups = group_entries::<V>(scaled_terms);
    let terms = strategy.map_collect_vec(groups, |(public, namespace, message)| {
        let message = hash_with_namespace::<V>(V::MESSAGE, namespace, message);
        (public, message)
    });
    let (publics, messages): (Vec<_>, Vec<_>) = terms.into_iter().unzip();
    V::verify_pairing_product(&publics, &messages, &combined, strategy).is_ok()
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
    use crate::bls12381::primitives::variant::{
        MinPk, MinSig, final_exponentiations, reset_final_exponentiations,
    };
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

    fn transcript_fixture<V: Variant>(
        rng: &mut impl rand_core::CryptoRng,
        count: usize,
    ) -> (Vec<V::Public>, Vec<Transcript<'static, V>>) {
        let namespace: &'static [u8] = b"batch-transcripts";
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
        let mut transcripts = Vec::with_capacity(count);
        for index in 0..count {
            let (private, public) = keypair::<_, V>(&mut *rng);
            let message = messages[index % messages.len()];
            let signature = sign_message::<V>(&private, namespace, message);
            publics.push(public);
            transcripts.push(Transcript {
                signature,
                terms: vec![(public, namespace, message)],
            });
        }
        (publics, transcripts)
    }

    fn verify_transcripts_correct<V: Variant>() {
        let mut rng = test_rng();
        let (_, transcripts) = transcript_fixture::<V>(&mut rng, 6);
        assert!(
            verify_transcripts::<_, V>(&mut rng, &transcripts, &Sequential).is_empty(),
            "valid transcripts should be accepted"
        );
        let strategy = Rayon::new(NZUsize!(4)).unwrap();
        assert!(
            verify_transcripts::<_, V>(&mut rng, &transcripts, &strategy).is_empty(),
            "valid transcripts should be accepted with parallel strategy"
        );
    }

    #[test]
    fn test_verify_transcripts_correct() {
        verify_transcripts_correct::<MinPk>();
        verify_transcripts_correct::<MinSig>();
    }

    fn verify_transcripts_uses_one_final_exponentiation<V: Variant>() {
        let mut rng = test_rng();
        let (_, transcripts) = transcript_fixture::<V>(&mut rng, 6);

        reset_final_exponentiations();
        assert!(verify_transcripts::<_, V>(&mut rng, &transcripts, &Sequential).is_empty());
        assert_eq!(final_exponentiations(), 1);

        let strategy = Rayon::new(NZUsize!(4)).unwrap();
        reset_final_exponentiations();
        assert!(verify_transcripts::<_, V>(&mut rng, &transcripts, &strategy).is_empty());
        assert_eq!(final_exponentiations(), 1);
    }

    #[test]
    fn test_verify_transcripts_uses_one_final_exponentiation() {
        verify_transcripts_uses_one_final_exponentiation::<MinPk>();
        verify_transcripts_uses_one_final_exponentiation::<MinSig>();
    }

    fn verify_transcripts_isolates_invalid<V: Variant>() {
        let mut rng = test_rng();
        let (_, mut transcripts) = transcript_fixture::<V>(&mut rng, 7);
        let tweak = Scalar::random(&mut rng);
        transcripts[2].signature += &(V::Signature::generator() * &tweak);
        transcripts[5].signature += &(V::Signature::generator() * &tweak);
        assert_eq!(
            verify_transcripts::<_, V>(&mut rng, &transcripts, &Sequential),
            vec![2, 5],
            "exactly the corrupted transcripts must be isolated"
        );
    }

    #[test]
    fn test_verify_transcripts_isolates_invalid() {
        verify_transcripts_isolates_invalid::<MinPk>();
        verify_transcripts_isolates_invalid::<MinSig>();
    }

    fn verify_transcripts_rejects_cross_cancellation<V: Variant>() {
        // Two invalid signatures whose errors cancel: their sum verifies as an aggregate, so
        // any unscaled batch would accept both. Random per-transcript weights must not.
        let mut rng = test_rng();
        let (_, mut transcripts) = transcript_fixture::<V>(&mut rng, 4);
        let delta = V::Signature::generator() * &Scalar::random(&mut rng);
        transcripts[1].signature += &delta;
        transcripts[3].signature -= &delta;
        assert_eq!(
            verify_transcripts::<_, V>(&mut rng, &transcripts, &Sequential),
            vec![1, 3],
            "cancelling forgeries must both be rejected"
        );
    }

    #[test]
    fn test_verify_transcripts_rejects_cross_cancellation() {
        verify_transcripts_rejects_cross_cancellation::<MinPk>();
        verify_transcripts_rejects_cross_cancellation::<MinSig>();
    }

    fn verify_transcripts_multi_term_atomic<V: Variant>() {
        // A multi-term transcript models a QC: one aggregate signature over distinct
        // messages. It verifies as a unit and fails as a unit.
        let mut rng = test_rng();
        let namespace: &[u8] = b"batch-transcripts";
        let (private_a, public_a) = keypair::<_, V>(&mut rng);
        let (private_b, public_b) = keypair::<_, V>(&mut rng);
        let sig_a = sign_message::<V>(&private_a, namespace, b"vote a");
        let sig_b = sign_message::<V>(&private_b, namespace, b"vote b");
        let aggregate = sig_a + &sig_b;
        let valid = Transcript::<V> {
            signature: aggregate,
            terms: vec![
                (public_a, namespace, b"vote a" as &[u8]),
                (public_b, namespace, b"vote b" as &[u8]),
            ],
        };
        let (_, singles) = transcript_fixture::<V>(&mut rng, 2);
        let mut transcripts = singles;
        transcripts.push(valid);
        assert!(
            verify_transcripts::<_, V>(&mut rng, &transcripts, &Sequential).is_empty(),
            "a valid aggregate transcript should be accepted alongside singles"
        );

        // Swapping one term's message breaks the whole transcript, and only it.
        let broken = Transcript::<V> {
            signature: transcripts[2].signature,
            terms: vec![
                (public_a, namespace, b"vote a" as &[u8]),
                (public_b, namespace, b"vote c" as &[u8]),
            ],
        };
        transcripts[2] = broken;
        assert_eq!(
            verify_transcripts::<_, V>(&mut rng, &transcripts, &Sequential),
            vec![2],
            "a broken aggregate transcript must be isolated without poisoning singles"
        );
    }

    #[test]
    fn test_verify_transcripts_multi_term_atomic() {
        verify_transcripts_multi_term_atomic::<MinPk>();
        verify_transcripts_multi_term_atomic::<MinSig>();
    }

    fn verify_transcripts_structural_guards<V: Variant>() {
        let mut rng = test_rng();
        let (publics, mut transcripts) = transcript_fixture::<V>(&mut rng, 3);
        transcripts.push(Transcript {
            signature: transcripts[0].signature,
            terms: Vec::new(),
        });
        transcripts.push(Transcript {
            signature: V::Signature::zero(),
            terms: vec![(
                publics[0],
                b"batch-transcripts" as &[u8],
                b"message 0" as &[u8],
            )],
        });
        transcripts.push(Transcript {
            signature: transcripts[1].signature,
            terms: vec![(
                V::Public::zero(),
                b"batch-transcripts" as &[u8],
                b"message 1" as &[u8],
            )],
        });
        assert_eq!(
            verify_transcripts::<_, V>(&mut rng, &transcripts, &Sequential),
            vec![3, 4, 5],
            "empty, zero-signature, and zero-public transcripts are invalid without batching"
        );
    }

    #[test]
    fn test_verify_transcripts_structural_guards() {
        verify_transcripts_structural_guards::<MinPk>();
        verify_transcripts_structural_guards::<MinSig>();
    }

    fn verify_transcripts_rejects_duplicate_publics<V: Variant>() {
        let mut rng = test_rng();
        let namespace: &[u8] = b"batch-transcripts";
        let (private, public) = keypair::<_, V>(&mut rng);
        let signature = sign_message::<V>(&private, namespace, b"duplicate");
        let duplicated = Transcript {
            signature: signature + &signature,
            terms: vec![
                (public, namespace, b"duplicate" as &[u8]),
                (public, namespace, b"duplicate" as &[u8]),
            ],
        };
        assert_eq!(
            verify_transcripts::<_, V>(&mut rng, &[duplicated], &Sequential),
            vec![0],
            "duplicate public keys must not inflate transcript participation"
        );
    }

    #[test]
    fn test_verify_transcripts_rejects_duplicate_publics() {
        verify_transcripts_rejects_duplicate_publics::<MinPk>();
        verify_transcripts_rejects_duplicate_publics::<MinSig>();
    }

    fn verify_transcripts_rejects_zero_sum_groups<V: Variant>() {
        let mut rng = test_rng();
        let namespace: &[u8] = b"batch-transcripts";
        let (base_private, base_public) = keypair::<_, V>(&mut rng);
        let base_signature = sign_message::<V>(&base_private, namespace, b"base");
        let (_, cancelling_public) = keypair::<_, V>(&mut rng);
        let cancelling = Transcript {
            signature: base_signature,
            terms: vec![
                (base_public, namespace, b"base" as &[u8]),
                (cancelling_public, namespace, b"extra" as &[u8]),
                (-cancelling_public, namespace, b"extra" as &[u8]),
            ],
        };
        assert_eq!(
            verify_transcripts::<_, V>(&mut rng, &[cancelling], &Sequential),
            vec![0],
            "a zero-sum public-key group must not create unattributed terms"
        );
    }

    #[test]
    fn test_verify_transcripts_rejects_zero_sum_groups() {
        verify_transcripts_rejects_zero_sum_groups::<MinPk>();
        verify_transcripts_rejects_zero_sum_groups::<MinSig>();
    }
}
