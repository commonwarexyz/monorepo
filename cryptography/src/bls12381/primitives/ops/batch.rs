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
use commonware_macros::stability;
#[stability(ALPHA)]
use commonware_math::algebra::Additive;
use commonware_math::algebra::Space;
use commonware_parallel::Strategy;
use commonware_utils::iter::NonEmpty;
#[stability(ALPHA)]
use core::cmp::Ordering;
use core::ops::Range;
#[stability(ALPHA)]
use hashbrown::{HashMap, HashSet};
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
        bisect_ranges(self.len, root_invalid, |node, _| {
            let (pk, sig) = self.tree[node].expect("node exists");
            V::verify(&pk, hm, &sig).is_ok()
        })
    }
}

/// Returns the leaves in `0..len` that fail `holds`, descending only into failing ranges.
///
/// Ranges follow the [`SegmentTree`] layout: `holds` receives a node index and the range of
/// leaves under it. If `root_invalid` is true, the root is treated as failing without a check.
fn bisect_ranges(
    len: usize,
    root_invalid: bool,
    mut holds: impl FnMut(usize, Range<usize>) -> bool,
) -> Vec<usize> {
    let mut invalid = Vec::new();
    if len == 0 {
        return invalid;
    }
    let mut stack = vec![(1usize, 0usize, len)];
    while let Some((node, start, end)) = stack.pop() {
        // Valid range: every leaf under it is valid.
        let known_invalid = root_invalid && node == 1;
        if !known_invalid && holds(node, start..end) {
            continue;
        }

        // Invalid leaf found.
        if end - start == 1 {
            invalid.push(start);
            continue;
        }

        // Descend into both halves to find the invalid leaves.
        let mid = start + (end - start) / 2;
        stack.push((2 * node, start, mid));
        stack.push((2 * node + 1, mid, end));
    }
    invalid
}

/// Draws one random 128-bit scalar per entry (sufficient for batch verification security).
fn random_scalars(rng: &mut impl CryptoRng, len: usize) -> Vec<SmallScalar> {
    (0..len).map(|_| SmallScalar::random(&mut *rng)).collect()
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

    let scalars = random_scalars(rng, pks.len());

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

/// A public key and the namespaced message it signed.
#[stability(ALPHA)]
#[derive(Clone, Debug)]
pub struct Term<'a, V: Variant> {
    /// Public key of the signer.
    pub public: V::Public,
    /// Namespace the message was signed under.
    pub namespace: &'a [u8],
    /// Signed message.
    pub message: &'a [u8],
}

/// A signature over one or more [`Term`]s.
///
/// A claim with one term is an ordinary signature. A claim with multiple terms is an aggregate
/// signature, such as a quorum certificate over distinct votes, and is accepted or rejected as a
/// unit.
#[stability(ALPHA)]
#[derive(Clone, Debug)]
pub struct Claim<'a, V: Variant> {
    /// Signature, or aggregate signature, over every term.
    pub signature: V::Signature,
    /// Terms the signature covers.
    pub terms: Vec<Term<'a, V>>,
}

/// Verifies independently supplied claims and returns the indices of invalid claims, in
/// ascending order.
///
/// Claims are randomly scaled so invalid signatures cannot cancel across claims. A claim is
/// structurally invalid, and reported without entering the batch, if its signature is zero, it
/// has no terms, one of its public keys is zero or repeated, or its public keys signing one
/// message sum to zero.
///
/// # Performance
///
/// Pairing terms are grouped by common messages or common public keys, whichever requires fewer
/// pairings. If the batch fails, bisection isolates the invalid claims and reuses the batch's
/// scalars at every step, grouping each checked range the cheaper way.
///
/// # Warning
///
/// This function assumes every public key and signature was group-checked while decoding, and
/// that public keys signing the same message are bound to their owners, such as by verified
/// proofs of possession or a trusted threshold sharing.
#[stability(ALPHA)]
pub fn verify_claims<R, V>(
    rng: &mut R,
    claims: &[Claim<'_, V>],
    strategy: &impl Strategy,
) -> Vec<usize>
where
    R: CryptoRng,
    V: Variant,
{
    let mut invalid = Vec::new();
    let mut pending = Vec::with_capacity(claims.len());
    for (index, claim) in claims.iter().enumerate() {
        let Some(message_groups) = canonicalize(claim) else {
            invalid.push(index);
            continue;
        };
        pending.push(CanonicalClaim {
            index,
            claim,
            message_groups,
        });
    }
    if pending.is_empty() {
        return invalid;
    }

    // Draw scalars before parallel work so RNG consumption is independent of the strategy.
    let scalars = random_scalars(rng, pending.len());
    let failed = IndexedClaims::new(&pending, strategy).verify(&scalars, strategy);
    invalid.extend(failed.into_iter().map(|position| pending[position].index));
    invalid.sort_unstable();
    invalid
}

/// A structurally valid claim with its terms grouped by message.
#[stability(ALPHA)]
struct CanonicalClaim<'c, 'a, V: Variant> {
    index: usize,
    claim: &'c Claim<'a, V>,
    message_groups: Vec<Term<'a, V>>,
}

/// Groups a claim's terms by message, summing the public keys that sign the same message.
///
/// Returns `None` if the claim is structurally invalid (see [`verify_claims`]).
#[stability(ALPHA)]
fn canonicalize<'a, V: Variant>(claim: &Claim<'a, V>) -> Option<Vec<Term<'a, V>>> {
    if claim.signature == V::Signature::zero() || claim.terms.is_empty() {
        return None;
    }
    let mut publics = HashSet::with_capacity(claim.terms.len());
    if claim
        .terms
        .iter()
        .any(|term| term.public == V::Public::zero() || !publics.insert(term.public))
    {
        return None;
    }

    let mut groups = claim.terms.clone();
    groups.sort_unstable_by(|left, right| {
        (left.namespace, left.message).cmp(&(right.namespace, right.message))
    });
    groups.dedup_by(|next, current| {
        if (next.namespace, next.message) != (current.namespace, current.message) {
            return false;
        }
        current.public += &next.public;
        true
    });
    if groups.iter().any(|group| group.public == V::Public::zero()) {
        return None;
    }
    Some(groups)
}

/// Pending claims with public keys and messages replaced by indices into shared tables.
///
/// A pairing product over a range of claims can group its terms two ways: by public key, with
/// one pairing `e(pk, sum of r_i * H(m_i))` per distinct key, or by message, with one pairing
/// `e(sum of r_i * pk_i, H(m))` per distinct message. The entries of the claim at position `i`
/// live at `terms[term_offsets[i]..term_offsets[i + 1]]` and
/// `groups[group_offsets[i]..group_offsets[i + 1]]`, so a range of claims owns a contiguous
/// range of each.
#[stability(ALPHA)]
struct IndexedClaims<V: Variant> {
    /// Distinct public keys.
    publics: Vec<V::Public>,
    /// Hashes of the distinct messages.
    hms: Vec<V::Signature>,
    /// Signature of each claim.
    signatures: Vec<V::Signature>,
    /// Public key index and message index of every term.
    terms: Vec<(usize, usize)>,
    term_offsets: Vec<usize>,
    /// Message index and summed public key of every message group.
    groups: Vec<(usize, V::Public)>,
    group_offsets: Vec<usize>,
}

#[stability(ALPHA)]
impl<V: Variant> IndexedClaims<V> {
    /// Indexes the pending claims and hashes every distinct message once.
    fn new(pending: &[CanonicalClaim<'_, '_, V>], strategy: &impl Strategy) -> Self {
        let term_count = pending.iter().map(|claim| claim.claim.terms.len()).sum();
        let group_count = pending.iter().map(|claim| claim.message_groups.len()).sum();
        // Keys repeat across claims (committee members sign many claims), so distinct keys are
        // usually bounded by the larger of the claim count and the widest claim.
        let widest = pending.iter().map(|claim| claim.claim.terms.len()).max();
        let public_bound = widest.map_or(0, |widest| widest.max(pending.len()).min(term_count));
        let mut message_indices = HashMap::with_capacity(group_count);
        let mut messages = Vec::with_capacity(group_count);
        let mut public_indices = HashMap::with_capacity(public_bound);
        let mut publics = Vec::with_capacity(public_bound);
        let mut terms = Vec::with_capacity(term_count);
        let mut term_offsets = Vec::with_capacity(pending.len() + 1);
        let mut groups = Vec::with_capacity(group_count);
        let mut group_offsets = Vec::with_capacity(pending.len() + 1);
        term_offsets.push(0);
        group_offsets.push(0);
        for claim in pending {
            for group in &claim.message_groups {
                let key = (group.namespace, group.message);
                let message = *message_indices.entry(key).or_insert_with(|| {
                    messages.push(key);
                    messages.len() - 1
                });
                groups.push((message, group.public));
            }
            group_offsets.push(groups.len());
            for term in &claim.claim.terms {
                let public = *public_indices.entry(term.public).or_insert_with(|| {
                    publics.push(term.public);
                    publics.len() - 1
                });
                terms.push((public, message_indices[&(term.namespace, term.message)]));
            }
            term_offsets.push(terms.len());
        }
        let hms = strategy.map_collect_vec(&messages, |(namespace, message)| {
            hash_with_namespace::<V>(V::MESSAGE, namespace, message)
        });
        Self {
            publics,
            hms,
            signatures: pending.iter().map(|claim| claim.claim.signature).collect(),
            terms,
            term_offsets,
            groups,
            group_offsets,
        }
    }

    /// Verifies the claims and returns the positions of invalid claims.
    ///
    /// A [`SegmentTree`] cannot hold these claims: a node would store every group of terms under
    /// it, not one aggregate pair. Bisection instead reuses the batch's scalars and regroups each
    /// checked range, pairing it by public key or by message, whichever has fewer distinct keys
    /// in that range (the batch's grouping on a tie). Each claim's entries are scaled at most
    /// once per grouping, when a checked range first needs them.
    fn verify(&self, scalars: &[SmallScalar], strategy: &impl Strategy) -> Vec<usize> {
        let claims = self.signatures.len();
        let mut weights = Weights {
            by_public: Scaled::default(),
            by_message: Scaled::default(),
        };
        let batch = if self.publics.len() < self.hms.len() {
            Grouping::ByPublic
        } else {
            Grouping::ByMessage
        };

        // Fast path: the whole batch holds.
        let combined = V::Signature::msm(&self.signatures, scalars, strategy);
        if self.holds(batch, 0..claims, &combined, &mut weights, scalars, strategy) {
            return Vec::new();
        }

        // Slow path: bisect over claims with the same scalars.
        let signatures = strategy.map_collect_vec(
            self.signatures.iter().zip(scalars),
            |(signature, scalar)| *signature * scalar,
        );
        bisect_ranges(claims, true, |_, range| {
            let signature = signatures[range.clone()]
                .iter()
                .fold(V::Signature::zero(), |sum, signature| sum + signature);
            let publics = distinct_keys(
                &self.terms[self.term_offsets[range.start]..self.term_offsets[range.end]],
            );
            let messages = distinct_keys(
                &self.groups[self.group_offsets[range.start]..self.group_offsets[range.end]],
            );
            let grouping = match publics.cmp(&messages) {
                Ordering::Less => Grouping::ByPublic,
                Ordering::Greater => Grouping::ByMessage,
                Ordering::Equal => batch,
            };
            self.holds(grouping, range, &signature, &mut weights, scalars, strategy)
        })
    }

    /// Returns whether `signature` matches the product of pairings over the claims in `claims`,
    /// grouped as `grouping`.
    fn holds(
        &self,
        grouping: Grouping,
        claims: Range<usize>,
        signature: &V::Signature,
        weights: &mut Weights<V>,
        scalars: &[SmallScalar],
        strategy: &impl Strategy,
    ) -> bool {
        let (publics, hms): (Vec<_>, Vec<_>) = match grouping {
            Grouping::ByPublic => {
                let scaled = &mut weights.by_public;
                scaled.fill(
                    claims.clone(),
                    &self.term_offsets,
                    scalars,
                    |term| self.hms[self.terms[term].1],
                    strategy,
                );
                let terms = self.term_offsets[claims.start]..self.term_offsets[claims.end];
                group(terms.map(|term| (self.terms[term].0, scaled.points[term])))
                    .into_iter()
                    .map(|(public, hm)| (self.publics[public], hm))
                    .unzip()
            }
            Grouping::ByMessage => {
                let scaled = &mut weights.by_message;
                scaled.fill(
                    claims.clone(),
                    &self.group_offsets,
                    scalars,
                    |group| self.groups[group].1,
                    strategy,
                );
                let groups = self.group_offsets[claims.start]..self.group_offsets[claims.end];
                group(groups.map(|group| (self.groups[group].0, scaled.points[group])))
                    .into_iter()
                    .map(|(message, public)| (public, self.hms[message]))
                    .unzip()
            }
        };
        V::verify_pairing_product(&publics, &hms, signature, strategy).is_ok()
    }
}

/// How a pairing product groups its terms.
#[stability(ALPHA)]
#[derive(Clone, Copy)]
enum Grouping {
    /// One pairing `e(pk, sum of r_i * H(m_i))` per distinct public key.
    ByPublic,
    /// One pairing `e(sum of r_i * pk_i, H(m))` per distinct message.
    ByMessage,
}

/// Scaled pairing inputs of both groupings.
#[stability(ALPHA)]
struct Weights<V: Variant> {
    /// Each term's message hash times its claim's scalar.
    by_public: Scaled<V::Signature>,
    /// Each message group's summed public key times its claim's scalar.
    by_message: Scaled<V::Public>,
}

/// Points scaled by their claim's scalar, filled in claim by claim on first use.
///
/// Both buffers stay empty until the first fill, so a grouping the batch never uses costs no
/// allocation.
#[stability(ALPHA)]
struct Scaled<P> {
    /// Scaled point of every entry; meaningful only for claims marked in `ready`.
    points: Vec<P>,
    /// Whether each claim's entries are scaled.
    ready: Vec<bool>,
}

#[stability(ALPHA)]
impl<P> Default for Scaled<P> {
    fn default() -> Self {
        Self {
            points: Vec::new(),
            ready: Vec::new(),
        }
    }
}

#[stability(ALPHA)]
impl<P: Space<SmallScalar> + Copy + Send + Sync> Scaled<P> {
    /// Scales the entries of every claim in `claims` that is not scaled yet, where claim `i` owns
    /// entries `offsets[i]..offsets[i + 1]` and `point` returns an entry's unscaled point.
    fn fill(
        &mut self,
        claims: Range<usize>,
        offsets: &[usize],
        scalars: &[SmallScalar],
        point: impl Fn(usize) -> P + Send + Sync,
        strategy: &impl Strategy,
    ) {
        let total = offsets.len() - 1;
        let scale = |(entry, claim): (usize, usize)| point(entry) * &scalars[claim];

        // A first fill of every claim produces the whole buffer in order.
        if self.ready.is_empty() && claims == (0..total) {
            self.points = strategy.map_collect_vec(unready(claims, offsets, &[]), scale);
            self.ready = vec![true; total];
            return;
        }
        if self.ready.is_empty() {
            self.points = vec![P::zero(); offsets[total]];
            self.ready = vec![false; total];
        }
        let scaled = strategy.map_collect_vec(unready(claims.clone(), offsets, &self.ready), scale);
        for ((entry, _), point) in unready(claims.clone(), offsets, &self.ready).zip(scaled) {
            self.points[entry] = point;
        }
        self.ready[claims].fill(true);
    }
}

/// Returns `(entry, claim)` for every entry of the claims in `claims` not marked in `ready`, where
/// claim `i` owns entries `offsets[i]..offsets[i + 1]` and claims past the end of `ready` are
/// unmarked.
#[stability(ALPHA)]
fn unready<'a>(
    claims: Range<usize>,
    offsets: &'a [usize],
    ready: &'a [bool],
) -> impl Iterator<Item = (usize, usize)> + Send + 'a {
    claims
        .filter(move |&claim| !ready.get(claim).copied().unwrap_or(false))
        .flat_map(move |claim| {
            (offsets[claim]..offsets[claim + 1]).map(move |entry| (entry, claim))
        })
}

/// Sums the points that share a key.
#[stability(ALPHA)]
fn group<P: Additive + Copy>(
    entries: impl ExactSizeIterator<Item = (usize, P)>,
) -> HashMap<usize, P> {
    let mut groups = HashMap::with_capacity(entries.len());
    for (key, point) in entries {
        groups
            .entry(key)
            .and_modify(|sum: &mut P| *sum += &point)
            .or_insert(point);
    }
    groups
}

/// Returns the number of distinct keys among `entries`.
#[stability(ALPHA)]
fn distinct_keys<P>(entries: &[(usize, P)]) -> usize {
    entries
        .iter()
        .map(|(key, _)| *key)
        .collect::<HashSet<_>>()
        .len()
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
    let scalars = random_scalars(rng, entries.len());

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
    use commonware_math::algebra::{Additive, CryptoGroup, Random};
    use commonware_parallel::{Rayon, Sequential};
    use commonware_utils::{NZUsize, non_empty, test_rng};

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

        verify_same_signer::<_, V, _>(
            &mut rng,
            &public,
            non_empty![@entries.iter().copied()],
            &Sequential,
        )
        .expect("valid signatures should be accepted");

        let strategy = Rayon::new(NZUsize!(4)).unwrap();
        verify_same_signer::<_, V, _>(
            &mut rng,
            &public,
            non_empty![@entries.iter().copied()],
            &strategy,
        )
        .expect("valid signatures should be accepted with parallel strategy");
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
        V::verify(&public, &hm_sum, forged_agg.inner())
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

    const CLAIM_NAMESPACE: &[u8] = b"batch-claims";

    fn term<V: Variant>(public: V::Public, message: &'static [u8]) -> Term<'static, V> {
        Term {
            public,
            namespace: CLAIM_NAMESPACE,
            message,
        }
    }

    fn claim_fixture<V: Variant>(
        rng: &mut impl rand_core::CryptoRng,
        count: usize,
    ) -> (Vec<V::Public>, Vec<Claim<'static, V>>) {
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
            let signature = sign_message::<V>(&private, CLAIM_NAMESPACE, message);
            publics.push(public);
            claims.push(Claim::<V> {
                signature,
                terms: vec![term(public, message)],
            });
        }
        (publics, claims)
    }

    fn verify_claims_correct<V: Variant>() {
        let mut rng = test_rng();
        assert!(verify_claims::<_, V>(&mut rng, &[], &Sequential).is_empty());

        let (_, claims) = claim_fixture::<V>(&mut rng, 6);
        assert!(
            verify_claims(&mut rng, &claims, &Sequential).is_empty(),
            "valid claims should be accepted"
        );
        let strategy = Rayon::new(NZUsize!(4)).unwrap();
        assert!(
            verify_claims(&mut rng, &claims, &strategy).is_empty(),
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
            verify_claims(&mut rng, &claims, &Sequential),
            vec![2, 5],
            "exactly the corrupted claims must be isolated"
        );
        let strategy = Rayon::new(NZUsize!(4)).unwrap();
        assert_eq!(verify_claims(&mut rng, &claims, &strategy), vec![2, 5]);
    }

    #[test]
    fn test_verify_claims_isolates_invalid() {
        verify_claims_isolates_invalid::<MinPk>();
        verify_claims_isolates_invalid::<MinSig>();
    }

    fn verify_claims_prepares_distinct_messages_once<V: Variant>() {
        let mut rng = test_rng();
        let namespaces: [&[u8]; 2] = [b"namespace 0", b"namespace 1"];
        let messages: [&[u8]; 4] = [b"message 0", b"message 1", b"message 2", b"message 3"];
        let distinct = namespaces.len() * messages.len();
        let claim_count = 2 * distinct;
        let mut claims = Vec::with_capacity(claim_count);
        for index in 0..claim_count {
            let pair = index % distinct;
            let namespace = namespaces[pair / messages.len()];
            let message = messages[pair % messages.len()];
            let (private, public) = keypair::<_, V>(&mut rng);
            let mut signature = sign_message::<V>(&private, namespace, message);
            signature += &V::Signature::generator();
            claims.push(Claim::<V> {
                signature,
                terms: vec![Term {
                    public,
                    namespace,
                    message,
                }],
            });
        }

        let pending = claims
            .iter()
            .enumerate()
            .map(|(index, claim)| CanonicalClaim::<V> {
                index,
                claim,
                message_groups: canonicalize(claim).unwrap(),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            IndexedClaims::new(&pending, &Sequential).hms.len(),
            distinct
        );

        // Every claim is invalid, so bisection descends to every leaf
        assert_eq!(
            verify_claims(&mut rng, &claims, &Sequential),
            (0..claim_count).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_verify_claims_prepares_distinct_messages_once() {
        verify_claims_prepares_distinct_messages_once::<MinPk>();
        verify_claims_prepares_distinct_messages_once::<MinSig>();
    }

    fn verify_claims_rejects_cross_cancellation<V: Variant>() {
        let mut rng = test_rng();
        let (_, mut claims) = claim_fixture::<V>(&mut rng, 4);
        let delta = V::Signature::generator() * &Scalar::random(&mut rng);
        claims[1].signature += &delta;
        claims[3].signature -= &delta;
        assert_eq!(
            verify_claims(&mut rng, &claims, &Sequential),
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
        let (private_a, public_a) = keypair::<_, V>(&mut rng);
        let (private_b, public_b) = keypair::<_, V>(&mut rng);
        let sig_a = sign_message::<V>(&private_a, CLAIM_NAMESPACE, b"vote a");
        let sig_b = sign_message::<V>(&private_b, CLAIM_NAMESPACE, b"vote b");
        let valid = Claim::<V> {
            signature: sig_a + &sig_b,
            terms: vec![term(public_a, b"vote a"), term(public_b, b"vote b")],
        };
        let (_, mut claims) = claim_fixture::<V>(&mut rng, 2);
        claims.push(valid);
        assert!(
            verify_claims(&mut rng, &claims, &Sequential).is_empty(),
            "a valid aggregate claim should be accepted alongside ordinary signatures"
        );

        claims[2].terms[1] = term(public_b, b"vote c");
        assert_eq!(
            verify_claims(&mut rng, &claims, &Sequential),
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
        let tweak = V::Signature::generator() * &Scalar::random(&mut rng);

        // One public key over many messages groups by public key
        let messages: [&'static [u8]; 4] = [b"one", b"two", b"three", b"four"];
        let (private, public) = keypair::<_, V>(&mut rng);
        let mut same_public: Vec<_> = messages
            .iter()
            .map(|&message| Claim::<V> {
                signature: sign_message::<V>(&private, CLAIM_NAMESPACE, message),
                terms: vec![term(public, message)],
            })
            .collect();
        assert!(verify_claims(&mut rng, &same_public, &Sequential).is_empty());
        same_public[2].signature += &tweak;
        assert_eq!(verify_claims(&mut rng, &same_public, &Sequential), vec![2]);

        // Many public keys over one message groups by message
        let mut same_message: Vec<_> = (0..4)
            .map(|_| {
                let (private, public) = keypair::<_, V>(&mut rng);
                Claim::<V> {
                    signature: sign_message::<V>(&private, CLAIM_NAMESPACE, b"same"),
                    terms: vec![term(public, b"same")],
                }
            })
            .collect();
        assert!(verify_claims(&mut rng, &same_message, &Sequential).is_empty());
        same_message[1].signature += &tweak;
        same_message[3].signature += &tweak;
        assert_eq!(
            verify_claims(&mut rng, &same_message, &Sequential),
            vec![1, 3]
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
        claims.push(Claim::<V> {
            signature: claims[0].signature,
            terms: Vec::new(),
        });
        claims.push(Claim::<V> {
            signature: V::Signature::zero(),
            terms: vec![term(publics[0], b"message 0")],
        });
        claims.push(Claim::<V> {
            signature: claims[1].signature,
            terms: vec![term(V::Public::zero(), b"message 1")],
        });
        assert_eq!(
            verify_claims(&mut rng, &claims, &Sequential),
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
        let (private, public) = keypair::<_, V>(&mut rng);
        let signature = sign_message::<V>(&private, CLAIM_NAMESPACE, b"duplicate");
        let duplicated = Claim::<V> {
            signature: signature + &signature,
            terms: vec![term(public, b"duplicate"), term(public, b"duplicate")],
        };
        assert_eq!(verify_claims(&mut rng, &[duplicated], &Sequential), vec![0]);
    }

    #[test]
    fn test_verify_claims_rejects_duplicate_publics() {
        verify_claims_rejects_duplicate_publics::<MinPk>();
        verify_claims_rejects_duplicate_publics::<MinSig>();
    }

    fn verify_claims_rejects_zero_sum_groups<V: Variant>() {
        let mut rng = test_rng();
        let (base_private, base_public) = keypair::<_, V>(&mut rng);
        let base_signature = sign_message::<V>(&base_private, CLAIM_NAMESPACE, b"base");
        let (_, cancelling_public) = keypair::<_, V>(&mut rng);
        let cancelling = Claim::<V> {
            signature: base_signature,
            terms: vec![
                term(base_public, b"base"),
                term(cancelling_public, b"extra"),
                term(-cancelling_public, b"extra"),
            ],
        };
        assert_eq!(verify_claims(&mut rng, &[cancelling], &Sequential), vec![0]);
    }

    #[test]
    fn test_verify_claims_rejects_zero_sum_groups() {
        verify_claims_rejects_zero_sum_groups::<MinPk>();
        verify_claims_rejects_zero_sum_groups::<MinSig>();
    }

    fn verify_claims_single_claim<V: Variant>() {
        let mut rng = test_rng();
        let (_, mut claims) = claim_fixture::<V>(&mut rng, 1);
        assert!(verify_claims(&mut rng, &claims, &Sequential).is_empty());
        claims[0].signature += &V::Signature::generator();
        assert_eq!(verify_claims(&mut rng, &claims, &Sequential), vec![0]);
    }

    #[test]
    fn test_verify_claims_single_claim() {
        verify_claims_single_claim::<MinPk>();
        verify_claims_single_claim::<MinSig>();
    }

    /// Aggregate claims from a few signers, each over its own message, pair by public key.
    fn verify_claims_bisects_aggregates_by_public<V: Variant>() {
        const SIGNERS: usize = 4;
        const CLAIMS: usize = 8;
        let mut rng = test_rng();
        let keys: Vec<_> = (0..SIGNERS).map(|_| keypair::<_, V>(&mut rng)).collect();
        let messages: Vec<Vec<u8>> = (0..CLAIMS * SIGNERS)
            .map(|index| format!("vote {index}").into_bytes())
            .collect();
        let mut claims: Vec<_> = (0..CLAIMS)
            .map(|claim| {
                let mut signature = V::Signature::zero();
                let mut terms = Vec::with_capacity(SIGNERS);
                for (signer, (private, public)) in keys.iter().enumerate() {
                    let message = messages[claim * SIGNERS + signer].as_slice();
                    signature += &sign_message::<V>(private, CLAIM_NAMESPACE, message);
                    terms.push(Term {
                        public: *public,
                        namespace: CLAIM_NAMESPACE,
                        message,
                    });
                }
                Claim::<V> { signature, terms }
            })
            .collect();
        assert!(verify_claims(&mut rng, &claims, &Sequential).is_empty());

        let tweak = V::Signature::generator() * &Scalar::random(&mut rng);
        claims[3].signature += &tweak;
        claims[5].signature += &tweak;
        assert_eq!(verify_claims(&mut rng, &claims, &Sequential), vec![3, 5]);
        let strategy = Rayon::new(NZUsize!(4)).unwrap();
        assert_eq!(verify_claims(&mut rng, &claims, &strategy), vec![3, 5]);
    }

    #[test]
    fn test_verify_claims_bisects_aggregates_by_public() {
        verify_claims_bisects_aggregates_by_public::<MinPk>();
        verify_claims_bisects_aggregates_by_public::<MinSig>();
    }

    /// Certificates from one key over distinct messages followed by votes from distinct keys over
    /// one message. Bisection must pair each half its own cheaper way, scaling the other grouping
    /// on first use.
    fn verify_claims_mixed_shapes<V: Variant>(certificates: usize, votes: usize) {
        const MESSAGES: [&[u8]; 8] = [b"c0", b"c1", b"c2", b"c3", b"c4", b"c5", b"c6", b"c7"];
        let mut rng = test_rng();
        let (private, public) = keypair::<_, V>(&mut rng);
        let mut claims: Vec<_> = MESSAGES[..certificates]
            .iter()
            .map(|&message| Claim::<V> {
                signature: sign_message::<V>(&private, CLAIM_NAMESPACE, message),
                terms: vec![term(public, message)],
            })
            .collect();
        for _ in 0..votes {
            let (private, public) = keypair::<_, V>(&mut rng);
            claims.push(Claim::<V> {
                signature: sign_message::<V>(&private, CLAIM_NAMESPACE, b"vote"),
                terms: vec![term(public, b"vote")],
            });
        }
        assert!(verify_claims(&mut rng, &claims, &Sequential).is_empty());

        let tweak = V::Signature::generator() * &Scalar::random(&mut rng);
        let expected = vec![2, certificates + 1, certificates + 4];
        for &index in &expected {
            claims[index].signature += &tweak;
        }
        assert_eq!(verify_claims(&mut rng, &claims, &Sequential), expected);
        let strategy = Rayon::new(NZUsize!(4)).unwrap();
        assert_eq!(verify_claims(&mut rng, &claims, &strategy), expected);
    }

    #[test]
    fn test_verify_claims_mixed_shapes() {
        // 7 keys and 7 messages tie, so the batch pairs by message and the certificate half
        // scales by public key on first use.
        verify_claims_mixed_shapes::<MinPk>(6, 6);
        verify_claims_mixed_shapes::<MinSig>(6, 6);
        // 7 keys and 8 messages pair the batch by public key, so the vote half scales by message
        // on first use.
        verify_claims_mixed_shapes::<MinPk>(7, 6);
        verify_claims_mixed_shapes::<MinSig>(7, 6);
    }

    /// Aggregates where several keys sign the same message (the V-QC shape) sum those keys into
    /// one message group, mixed with ordinary votes.
    fn verify_claims_shared_message_aggregates<V: Variant>() {
        const AGGREGATES: usize = 6;
        const SIGNERS: usize = 3;
        let mut rng = test_rng();
        let keys: Vec<_> = (0..5).map(|_| keypair::<_, V>(&mut rng)).collect();
        let messages: Vec<Vec<u8>> = (0..2 * AGGREGATES)
            .map(|index| format!("round {index}").into_bytes())
            .collect();
        let mut claims = Vec::with_capacity(2 * AGGREGATES);
        for (index, message) in messages[..AGGREGATES].iter().enumerate() {
            let mut signature = V::Signature::zero();
            let mut terms = Vec::with_capacity(SIGNERS);
            for (private, public) in keys.iter().cycle().skip(index).take(SIGNERS) {
                signature += &sign_message::<V>(private, CLAIM_NAMESPACE, message);
                terms.push(Term {
                    public: *public,
                    namespace: CLAIM_NAMESPACE,
                    message: message.as_slice(),
                });
            }
            claims.push(Claim::<V> { signature, terms });
        }
        for (index, message) in messages[AGGREGATES..].iter().enumerate() {
            let (private, public) = &keys[index % keys.len()];
            claims.push(Claim::<V> {
                signature: sign_message::<V>(private, CLAIM_NAMESPACE, message),
                terms: vec![Term {
                    public: *public,
                    namespace: CLAIM_NAMESPACE,
                    message: message.as_slice(),
                }],
            });
        }
        assert!(verify_claims(&mut rng, &claims, &Sequential).is_empty());
        let strategy = Rayon::new(NZUsize!(4)).unwrap();
        assert!(verify_claims(&mut rng, &claims, &strategy).is_empty());

        let tweak = V::Signature::generator() * &Scalar::random(&mut rng);
        let expected = vec![1, 4, AGGREGATES + 2];
        for &index in &expected {
            claims[index].signature += &tweak;
        }
        assert_eq!(verify_claims(&mut rng, &claims, &Sequential), expected);
        assert_eq!(verify_claims(&mut rng, &claims, &strategy), expected);
    }

    #[test]
    fn test_verify_claims_shared_message_aggregates() {
        verify_claims_shared_message_aggregates::<MinPk>();
        verify_claims_shared_message_aggregates::<MinSig>();
    }

    fn verify_same_message_isolates_invalid<V: Variant>() {
        let mut rng = test_rng();
        let namespace = b"test";
        let message = b"message";
        let mut entries: Vec<_> = (0..7)
            .map(|_| {
                let (private, public) = keypair::<_, V>(&mut rng);
                (public, sign_message::<V>(&private, namespace, message))
            })
            .collect();
        let tweak = V::Signature::generator() * &Scalar::random(&mut rng);
        entries[0].1 += &tweak;
        entries[4].1 += &tweak;
        entries[6].1 += &tweak;
        for strategy in [
            Rayon::new(NZUsize!(1)).unwrap(),
            Rayon::new(NZUsize!(3)).unwrap(),
        ] {
            assert_eq!(
                verify_same_message::<_, V, _>(
                    &mut rng,
                    namespace,
                    message,
                    non_empty![@entries.iter().copied()],
                    &strategy,
                ),
                vec![0, 4, 6]
            );
        }
    }

    #[test]
    fn test_verify_same_message_isolates_invalid() {
        verify_same_message_isolates_invalid::<MinPk>();
        verify_same_message_isolates_invalid::<MinSig>();
    }
}
