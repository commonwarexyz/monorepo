//! Ed25519 verification internals.

mod hash;
mod msm;
mod scalar;

use crate::curve::{Backend, G, GAffine, LANES, WithBackend, with_backend};
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use commonware_parallel::{Sequential, Strategy};
use core::ops::Range;
use msm::Term;
use rand_core::CryptoRng;
pub(super) use scalar::Scalar;
use sha2::{Digest, Sha512};

/// The exact byte encoding used to identify an Ed25519 verifying key.
///
/// Batch verification hashes and groups keys by this encoding, then decompresses each distinct
/// key in its point-processing phase.
#[derive(Copy, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct VerifyingKeyBytes([u8; 32]);

impl VerifyingKeyBytes {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Computes `SHA-512(parts[0] || parts[1] || ...)`, the Ed25519 challenge hash `H(R || A || M)`.
fn sha512(parts: &[&[u8]]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// An Ed25519 signature split into its two wire components.
#[derive(Copy, Clone, Debug)]
pub(super) struct Signature {
    r: [u8; 32],
    s: [u8; 32],
}

impl Signature {
    /// Constructs a signature from its 64-byte wire encoding (`R || s`).
    pub(super) fn from_bytes(bytes: [u8; 64]) -> Self {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..]);
        Self { r, s }
    }
}

/// Derives four consecutive 128-bit batch coefficients `z_{4*block} .. z_{4*block + 3}` from
/// `seed` as one SHA-512 output, in counter mode. The signature at index `i` of the batch takes
/// `z_i`.
///
/// The batch equation's soundness needs each `z_i` to be uniform, independent, and unpredictable
/// to whoever assembled the batch. PRF outputs under a seed drawn freshly from the caller's CSPRNG
/// (and never revealed) are indistinguishable from exactly that. Deriving each coefficient from
/// its signature's index, rather than drawing all of them from the shared `rng` up front, lets
/// every thread compute its own signatures' coefficients locally. It also makes the batch's
/// coefficients and verdict deterministic functions of `(items, seed)`, identical at every thread
/// count.
fn batch_coefficients(seed: &[u8; 32], block: u64) -> [Scalar; 4] {
    let digest = sha512(&[seed, &block.to_le_bytes()]);
    core::array::from_fn(|k| {
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[k * 16..(k + 1) * 16]);
        Scalar::from_u128(u128::from_le_bytes(bytes))
    })
}

/// Returns every item's `(key, original index)` pair, ordered by key and then by index: the order
/// a stable sort by key produces.
///
/// A counting pass over each key's leading bits places the pairs in buckets of about 8, and each
/// bucket is then sorted alone. Keys that share their leading bits fall into one bucket, which then
/// costs one ordinary sort.
///
/// `items.len()` must fit in `u32`.
fn sort_keys(items: &[(&VerifyingKeyBytes, &Signature, &[u8])]) -> Vec<(VerifyingKeyBytes, u32)> {
    let prefix = |key: &VerifyingKeyBytes| {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&key.0[..8]);
        u64::from_be_bytes(bytes)
    };
    let bits = (items.len() / 8).max(2).ilog2().min(16);
    let bucket = |key: &VerifyingKeyBytes| (prefix(key) >> (64 - bits)) as usize;

    let mut starts = vec![0usize; (1 << bits) + 1];
    for (key, _, _) in items {
        starts[bucket(key) + 1] += 1;
    }
    for i in 1..starts.len() {
        starts[i] += starts[i - 1];
    }
    let mut next = starts.clone();
    let mut order = vec![(VerifyingKeyBytes([0; 32]), 0); items.len()];
    for (i, (key, _, _)) in items.iter().enumerate() {
        let slot = &mut next[bucket(key)];
        order[*slot] = (**key, i as u32);
        *slot += 1;
    }
    for run in starts.windows(2) {
        order[run[0]..run[1]]
            .sort_unstable_by(|x, y| (prefix(&x.0), &x.0, x.1).cmp(&(prefix(&y.0), &y.0, y.1)));
    }
    order
}

/// Groups `sorted` (pre-sorted `(key, original index)` pairs) into runs of equal keys, returned
/// as `(start, end)` positions into `sorted`. This is batch verification's `A`-term coalescing:
/// a signer reused across the batch contributes one MSM term instead of one per signature, and
/// operating on raw `[u8; 32]` keys (rather than decompressed points) means a repeated `A` is
/// only ever decompressed once, not once per occurrence.
fn group_ranges(sorted: &[(VerifyingKeyBytes, u32)]) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    let mut start = 0;
    for i in 1..=sorted.len() {
        if i == sorted.len() || sorted[i].0 != sorted[start].0 {
            out.push((start as u32, i as u32));
            start = i;
        }
    }
    out
}

/// Signatures per [`signature_phase`] unit: one per [`hash::LANES`] lane and per decompression
/// lane, covering whole [`batch_coefficients`] blocks.
const UNIT: usize = hash::LANES;
const _: () = assert!(UNIT == LANES && UNIT.is_multiple_of(4));

/// Splits `units` consecutive units into contiguous ranges of near-equal length for a parallel
/// pass: a few per worker at `parallelism`, each at least `min_len` units long unless `units` is
/// shorter. More ranges than workers let a late-waking worker simply take fewer of them.
fn partitions(units: usize, min_len: usize, parallelism: usize) -> Vec<Range<usize>> {
    const PARTITIONS_PER_WORKER: usize = 4;
    let count = parallelism
        .saturating_mul(PARTITIONS_PER_WORKER)
        .min((units / min_len).max(1))
        .min(units);
    if count == 0 {
        return Vec::new();
    }
    let len = units / count;
    let remainder = units % count;
    let mut ranges = Vec::with_capacity(count);
    let mut start = 0;
    for partition in 0..count {
        let end = start + len + usize::from(partition < remainder);
        ranges.push(start..end);
        start = end;
    }
    ranges
}

/// One [`signature_phase`] unit's scalars: each signature's coefficient `z`, the scalar of its
/// `R` term, and `z*h`, its share of its signer's coalesced `A` scalar.
struct ScalarBlock {
    z: [Scalar; UNIT],
    zh: [Scalar; UNIT],
}

/// One [`signature_phase`] partition's output.
struct Partition {
    terms: Vec<[Term; LANES]>,
    scalars: Vec<ScalarBlock>,
    zs_sum: Scalar,
    valid: bool,
}

/// The output of [`signature_phase`], in partitions of consecutive units.
struct Signatures {
    /// Every `R` point as a term with its `z`.
    terms: Vec<Vec<[Term; LANES]>>,
    /// Every unit's scalars, partitioned like `terms`.
    scalars: Vec<Vec<ScalarBlock>>,
    /// `sum(z*s) mod L`, the coalesced basepoint scalar.
    s_sum: Scalar,
}

/// The encoding of the identity point, which pads the final unit of a decompression batch.
const IDENTITY_ENCODING: [u8; 32] = {
    let mut encoding = [0; 32];
    encoding[0] = 1;
    encoding
};

/// Decompresses `N` units of point encodings with one backend batch and appends them to `terms`
/// as terms of scalar zero.
///
/// Returns whether every encoding decompressed.
fn decompress_terms<B: Backend, const N: usize>(
    backend: B,
    encodings: &[[[u8; 32]; LANES]; N],
    terms: &mut Vec<[Term; LANES]>,
) -> bool {
    let mut valid = true;
    for points in GAffine::decompress_batch(backend, encodings) {
        terms.push(points.map(|point| {
            point.map_or_else(
                || {
                    valid = false;
                    Term::zero(GAffine::IDENTITY)
                },
                Term::zero,
            )
        }));
    }
    valid
}

/// Recodes every `R` term in `terms` with its coefficient from `blocks` at `width`.
fn recode_r(terms: &mut [[Term; LANES]], blocks: &[ScalarBlock], width: u32) {
    for (terms, block) in terms.iter_mut().zip(blocks) {
        for (term, z) in terms.iter_mut().zip(&block.z) {
            term.recode(z, width);
        }
    }
}

/// Processes the `N` consecutive units starting at `first` into `partition`, recoding the `R`
/// terms at `width`. Each unit's challenges are hashed together, and all `N` units' `R`
/// encodings decompress in one backend batch. The batch's final unit is padded with identity
/// terms.
fn signature_units<B: Backend, const N: usize>(
    backend: B,
    items: &[(&VerifyingKeyBytes, &Signature, &[u8])],
    seed: &[u8; 32],
    width: u32,
    first: usize,
    partition: &mut Partition,
) {
    // The partition holds one term array and one scalar block per unit.
    let offset = partition.scalars.len();
    let mut encodings = [[IDENTITY_ENCODING; LANES]; N];
    for (unit, encodings) in encodings.iter_mut().enumerate() {
        let start = (first + unit) * UNIT;
        let lanes = &items[start..items.len().min(start + UNIT)];
        let mut z = [Scalar::ZERO; UNIT];
        for (block, coefficients) in z
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .take(lanes.len().div_ceil(4))
            .enumerate()
        {
            *coefficients = batch_coefficients(seed, (start / 4 + block) as u64);
        }
        let mut messages: [[&[u8]; 3]; UNIT] = [[&[]; 3]; UNIT];
        for ((message, encoding), &(a_bytes, sig, msg)) in
            messages.iter_mut().zip(encodings.iter_mut()).zip(lanes)
        {
            *message = [&sig.r, a_bytes.as_bytes(), msg];
            *encoding = sig.r;
        }
        let digests = hash::digest(&messages[..lanes.len()]);

        let mut block = ScalarBlock {
            z: [Scalar::ZERO; UNIT],
            zh: [Scalar::ZERO; UNIT],
        };
        for (j, (_, sig, _)) in lanes.iter().enumerate() {
            let Some(s) = Scalar::from_canonical_bytes(&sig.s) else {
                partition.valid = false;
                continue;
            };
            let h = Scalar::from_bytes_mod_order_wide(&digests[j]);
            block.z[j] = z[j];
            block.zh[j] = z[j].mul_mod_l(&h);
            partition.zs_sum = partition.zs_sum.add_mod_l(&z[j].mul_mod_l(&s));
        }
        partition.scalars.push(block);
    }
    partition.valid &= decompress_terms(backend, &encodings, &mut partition.terms);
    recode_r(
        &mut partition.terms[offset..],
        &partition.scalars[offset..],
        width,
    );
}

/// The per-signature phase, parallel over [`UNIT`]-signature units in batch order: for each
/// signature, derives `z` (see [`batch_coefficients`]), rejects a non-canonical `s`, computes the
/// challenge `h = H(R || A || M)` and the scalars `z*h` and `z*s`, and decompresses `R` into a
/// term recoded at `width`. Returns `None` if any `s` is non-canonical or any `R` fails to
/// decompress.
///
/// Each partition decompresses its units in pairs (see [`signature_units`]), giving the backend
/// two independent square-root chains to overlap. The phase needs no `A` point and no grouping,
/// so it runs while [`verify_batch_inner`] sorts the keys.
fn signature_phase<B: Backend>(
    backend: B,
    items: &[(&VerifyingKeyBytes, &Signature, &[u8])],
    seed: &[u8; 32],
    width: u32,
    strategy: &impl Strategy,
) -> Option<Signatures> {
    const MIN_UNITS_PER_PARTITION: usize = 2;
    let ranges = partitions(
        items.len().div_ceil(UNIT),
        MIN_UNITS_PER_PARTITION,
        strategy.manual().parallelism(),
    );
    let partitions = strategy.map_collect_vec(ranges, |range| {
        let mut partition = Partition {
            terms: Vec::with_capacity(range.len()),
            scalars: Vec::with_capacity(range.len()),
            zs_sum: Scalar::ZERO,
            valid: true,
        };
        for unit in range.clone().step_by(2) {
            if unit + 1 < range.end {
                signature_units::<_, 2>(backend, items, seed, width, unit, &mut partition);
            } else {
                signature_units::<_, 1>(backend, items, seed, width, unit, &mut partition);
            }
        }
        partition
    });

    let mut signatures = Signatures {
        terms: Vec::with_capacity(partitions.len()),
        scalars: Vec::with_capacity(partitions.len()),
        s_sum: Scalar::ZERO,
    };
    for partition in partitions {
        if !partition.valid {
            return None;
        }
        signatures.terms.push(partition.terms);
        signatures.scalars.push(partition.scalars);
        signatures.s_sum = signatures.s_sum.add_mod_l(&partition.zs_sum);
    }
    Some(signatures)
}

/// The decompression phase: turns a flat worklist of `count` point encodings, resolved by index
/// via `encoding`, into terms of scalar zero, in one parallel pass over [`LANES`]-sized units.
/// Each partition decompresses its units in pairs (see [`decompress_terms`]), giving the backend
/// two independent square-root chains to overlap, into one exactly sized term vector. The final
/// unit is padded with identity terms.
///
/// Returns the term vectors in worklist order, or `None` if any encoding fails to decompress.
fn decompress_phase<B, F>(
    backend: B,
    count: usize,
    encoding: F,
    strategy: &impl Strategy,
) -> Option<Vec<Vec<[Term; LANES]>>>
where
    B: Backend,
    F: Fn(usize) -> [u8; 32] + Send + Sync,
{
    const MIN_UNITS_PER_PARTITION: usize = 2;
    let ranges = partitions(
        count.div_ceil(LANES),
        MIN_UNITS_PER_PARTITION,
        strategy.manual().parallelism(),
    );
    let unit = |unit: usize| -> [[u8; 32]; LANES] {
        core::array::from_fn(|lane| {
            let index = unit * LANES + lane;
            if index < count {
                encoding(index)
            } else {
                IDENTITY_ENCODING
            }
        })
    };
    strategy
        .map_collect_vec(ranges, |range| {
            let mut terms = Vec::with_capacity(range.len());
            let mut valid = true;
            for first in range.clone().step_by(2) {
                valid &= if first + 1 < range.end {
                    decompress_terms(backend, &[unit(first), unit(first + 1)], &mut terms)
                } else {
                    decompress_terms(backend, &[unit(first)], &mut terms)
                };
            }
            valid.then_some(terms)
        })
        .into_iter()
        .collect()
}

/// A signer with more signatures than this sums their `z*h` scalars in parallel, this many per
/// task.
const SUM_CHUNK: usize = 1024;

/// The batch-verification pipeline: a short sequence of data-parallel phases over flat arrays,
/// with `A` coalescing falling out of a sort.
///
/// 1. Two concurrent tasks. [`signature_phase`] derives coefficients, hashes, computes the
///    per-signature scalars, and decompresses every `R` into a term with its `z`. Meanwhile
///    [`sort_keys`] and [`group_ranges`] place every signer's signatures adjacent in sorted order
///    and group them, and [`decompress_phase`] decompresses every distinct `A`.
/// 2. Every `A` term is recoded with its coalesced scalar, the sum of its signatures' `z*h`. The
///    `R` terms are recoded again if grouping changed the MSM window width.
/// 3. One tile-parallel MSM over the terms, with the coalesced basepoint term `sum(z*s)*(-B)`
///    riding along as one final term, then the cofactored identity check.
fn verify_batch_inner<B: Backend>(
    backend: B,
    rng: &mut impl CryptoRng,
    items: &[(&VerifyingKeyBytes, &Signature, &[u8])],
    strategy: &impl Strategy,
) -> bool {
    let n = items.len();
    if n == 0 {
        return false;
    }

    // Every phase has a fixed work shape derived from the available parallelism. Disable adaptive
    // policy decisions and let the supplied strategy execute that shape directly.
    let strategy = &strategy.manual();

    // Sorting and grouping use compact indices.
    if u32::try_from(n).is_err() {
        return false;
    }

    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);

    // The MSM window width is a per-batch choice (see [`msm::width_for`]) that every term must
    // share. It counts every `R`, every distinct `A`, and the basepoint, so it is known only once
    // the keys are grouped. The `R` terms are recoded at the width for distinct signers, and
    // again only if the batch's width differs.
    let parallelism = strategy.parallelism();
    let distinct = msm::width_for(2 * n + 1, parallelism);
    let (signatures, (order, groups, a_terms)) = strategy.join(
        || signature_phase(backend, items, &seed, distinct, strategy),
        || {
            let order = sort_keys(items);
            let groups = group_ranges(&order);
            let encoding = |i: usize| *order[groups[i].0 as usize].0.as_bytes();
            let a_terms = decompress_phase(backend, groups.len(), encoding, strategy);
            (order, groups, a_terms)
        },
    );
    let (
        Some(Signatures {
            terms: mut r_terms,
            scalars,
            s_sum,
        }),
        Some(mut a_terms),
    ) = (signatures, a_terms)
    else {
        return false;
    };

    let width = msm::width_for(n + groups.len() + 1, parallelism);

    // A signer's coalesced scalar: the sum of `z*h` over its run of `order`.
    let blocks: Vec<&ScalarBlock> = scalars.iter().flatten().collect();
    let sum = |run: &[(VerifyingKeyBytes, u32)]| {
        run.iter()
            .map(|&(_, index)| blocks[index as usize / UNIT].zh[index as usize % UNIT])
            .reduce(|total, zh| total.add_mod_l(&zh))
            .unwrap_or(Scalar::ZERO)
    };
    let group_scalar = |(start, end): (u32, u32)| {
        let run = &order[start as usize..end as usize];
        if run.len() <= SUM_CHUNK {
            return sum(run);
        }
        strategy.fold(
            run.chunks(SUM_CHUNK),
            || Scalar::ZERO,
            |total, chunk| total.add_mod_l(&sum(chunk)),
            |left, right| left.add_mod_l(&right),
        )
    };
    // Every `A` term vector with the index of its first group.
    let mut next = 0;
    let a_work: Vec<_> = a_terms
        .iter_mut()
        .map(|terms| {
            let first = next;
            next += terms.len() * LANES;
            (terms, first)
        })
        .collect();
    strategy.join(
        || {
            if width != distinct {
                strategy.map_collect_vec(r_terms.iter_mut().zip(&scalars), |(terms, blocks)| {
                    recode_r(terms, blocks, width)
                });
            }
        },
        || {
            strategy.map_collect_vec(a_work, |(terms, first)| {
                for (terms, groups) in terms.iter_mut().zip(groups[first..].chunks(LANES)) {
                    // Summing a unit's groups before recoding any of them overlaps the scattered
                    // loads of their summands.
                    let mut scalars = [Scalar::ZERO; LANES];
                    for (scalar, &group) in scalars.iter_mut().zip(groups) {
                        *scalar = group_scalar(group);
                    }
                    for (term, scalar) in terms.iter_mut().zip(&scalars[..groups.len()]) {
                        term.recode(scalar, width);
                    }
                }
            })
        },
    );

    // The coalesced basepoint term: `sum(z*s)·B` moved to the equation's other side by negating
    // its scalar, one more ordinary MSM term.
    let basepoint = [Term::new(GAffine::BASEPOINT, &s_sum.neg_mod_l(), width)];
    let mut chunks: Vec<&[Term]> = r_terms
        .iter()
        .chain(&a_terms)
        .map(|chunk| chunk.as_flattened())
        .collect();
    chunks.push(basepoint.as_slice());
    let result = msm::multiscalar_mul(backend, &chunks, width, strategy);
    result.mul_by_cofactor().is_identity()
}

/// Width of the non-adjacent forms [`straus`] recodes its scalars into.
const NAF_WIDTH: usize = 5;

/// Computes `sum(scalar*point)` over `terms` with Straus's method: one doubling chain shared by
/// every term, adding `digit*point` at each nonzero digit of the scalars' non-adjacent forms from
/// a per-term table of odd multiples `point, 3*point, ..., 15*point`.
///
/// Variable-time, so the points and scalars must be public.
fn straus<const N: usize>(terms: [(GAffine, Scalar); N]) -> G {
    let digits = terms.map(|(_, scalar)| scalar.naf::<NAF_WIDTH>());
    let tables = terms.map(|(point, _)| {
        let point = point.to_extended();
        let double = point.double();
        let mut table = [point; 1 << (NAF_WIDTH - 2)];
        let mut multiple = point;
        for entry in &mut table[1..] {
            multiple = multiple.add(double);
            *entry = multiple;
        }
        table
    });
    let Some(top) = digits
        .iter()
        .filter_map(|digits| digits.iter().rposition(|&digit| digit != 0))
        .max()
    else {
        return G::IDENTITY;
    };

    let mut sum = G::IDENTITY;
    for i in (0..=top).rev() {
        sum = sum.double();
        for (digits, table) in digits.iter().zip(&tables) {
            let digit = digits[i];
            if digit != 0 {
                let mut multiple = table[digit.unsigned_abs() as usize / 2];
                if digit < 0 {
                    multiple = multiple.negate();
                }
                sum = sum.add(multiple);
            }
        }
    }
    sum
}

/// Verifies one signature per the [module's validation criteria](super).
///
/// `a_point`, when present, must be the point `a_bytes` encodes.
pub(super) fn verify(
    a_bytes: &VerifyingKeyBytes,
    a_point: Option<&GAffine>,
    sig: &Signature,
    msg: &[u8],
) -> bool {
    let Some(s) = Scalar::from_canonical_bytes(&sig.s) else {
        return false;
    };
    let Some(r) = GAffine::decompress(&sig.r) else {
        return false;
    };
    let a = match a_point {
        Some(point) => *point,
        None => {
            let Some(point) = GAffine::decompress(a_bytes.as_bytes()) else {
                return false;
            };
            point
        }
    };
    let h = Scalar::from_bytes_mod_order_wide(&sha512(&[&sig.r, a_bytes.as_bytes(), msg]));

    // With `v = u*h (mod L)`, `[8](u*s*B - u*R - v*A) = u*[8](s*B - R - h*A)` because `[8]`
    // maps every point into the prime-order subgroup. Since `0 < |u| < L`, one side is the
    // identity exactly when the other is. The combination below is `sign(u)` times the left
    // side, with `u*s` split at bit 128 so that all four scalars are below `2^128`.
    let (u, v) = h.half_size();
    let a = if u < 0 { a } else { a.negate() };
    let u = Scalar::from_u128(u.unsigned_abs());
    let (low, high) = s.mul_mod_l(&u).halves();
    straus([
        (GAffine::BASEPOINT, Scalar::from_u128(low)),
        (GAffine::BASEPOINT_128, Scalar::from_u128(high)),
        (r.negate(), u),
        (a, Scalar::from_u128(v)),
    ])
    .mul_by_cofactor()
    .is_identity()
}

struct VerifyBatchCall<'a, 'b, R, S> {
    rng: &'a mut R,
    items: &'a [(&'b VerifyingKeyBytes, &'b Signature, &'b [u8])],
    strategy: &'a S,
}

impl<R: CryptoRng, S: Strategy> WithBackend for VerifyBatchCall<'_, '_, R, S> {
    type Output = bool;

    fn call<B: Backend>(self, backend: B) -> Self::Output {
        verify_batch_inner(backend, self.rng, self.items, self.strategy)
    }
}

/// Batches below this many signatures verify on the calling thread.
const SEQUENTIAL_MAX_SIGNATURES: usize = 16;

fn verify_batch_dispatch<'a, R: CryptoRng, S: Strategy>(
    rng: &mut R,
    items: &[(&'a VerifyingKeyBytes, &'a Signature, &'a [u8])],
    strategy: &S,
) -> bool {
    if items.len() < SEQUENTIAL_MAX_SIGNATURES {
        return with_backend(VerifyBatchCall {
            rng,
            items,
            strategy: &Sequential,
        });
    }
    with_backend(VerifyBatchCall {
        rng,
        items,
        strategy,
    })
}

/// Verifies a batch of `(verifying_key_bytes, signature, message)` triples using a randomized
/// linear combination.
///
/// Empty input is rejected.
///
/// `A` is coalesced by its raw encoding before ever being decompressed (see [`group_ranges`]), so
/// a signer reused across the batch is decompressed once, not once per signature.
pub(super) fn verify_batch_bytes<'a>(
    rng: &mut impl CryptoRng,
    items: impl IntoIterator<Item = (&'a VerifyingKeyBytes, &'a Signature, &'a [u8])>,
    strategy: &impl Strategy,
) -> bool {
    let items: Vec<_> = items.into_iter().collect();
    verify_batch_dispatch(rng, &items, strategy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbitrary::Unstructured;
    use commonware_invariants::minifuzz::Builder;
    use commonware_parallel::Sequential;
    use commonware_utils::FuzzRng;
    use ed25519_consensus::SigningKey as RefSigningKey;

    #[test]
    fn group_ranges_groups_adjacent_equal_keys() {
        let sorted = vec![
            (VerifyingKeyBytes::new([1u8; 32]), 4),
            (VerifyingKeyBytes::new([1u8; 32]), 0),
            (VerifyingKeyBytes::new([2u8; 32]), 3),
            (VerifyingKeyBytes::new([3u8; 32]), 1),
            (VerifyingKeyBytes::new([3u8; 32]), 2),
            (VerifyingKeyBytes::new([3u8; 32]), 5),
        ];
        assert_eq!(group_ranges(&sorted), vec![(0, 2), (2, 3), (3, 6)]);
    }

    #[test]
    fn sort_keys_matches_stable_sort() {
        let signature = Signature::from_bytes([0; 64]);
        let mut rng = commonware_utils::test_rng();
        for n in [0, 1, 2, 15, 16, 17, 1000] {
            // Random keys, keys repeated across the batch, and keys sharing their leading bits.
            let keys: Vec<VerifyingKeyBytes> = (0..n)
                .map(|i| {
                    let mut key = [0u8; 32];
                    rand_core::Rng::fill_bytes(&mut rng, &mut key);
                    match i % 4 {
                        0 => key[..8].fill(0xab),
                        1 => key = [i as u8 % 3; 32],
                        _ => {}
                    }
                    VerifyingKeyBytes::new(key)
                })
                .collect();
            let items: Vec<_> = keys.iter().map(|key| (key, &signature, &[][..])).collect();
            let mut expected: Vec<_> = keys.iter().copied().zip(0u32..).collect();
            expected.sort_by_key(|x| x.0);
            assert!(sort_keys(&items) == expected, "n={n}");
        }
    }

    #[test]
    fn group_ranges_handles_empty_and_no_duplicates() {
        assert!(group_ranges(&[]).is_empty());

        let sorted = vec![
            (VerifyingKeyBytes::new([1u8; 32]), 0),
            (VerifyingKeyBytes::new([2u8; 32]), 1),
        ];
        assert_eq!(group_ranges(&sorted), vec![(0, 1), (1, 2)]);
    }

    /// [`straus`] matches independent double-and-add over points with torsion components and
    /// scalars of every size.
    #[test]
    fn straus_matches_double_and_add() {
        assert!(straus([(GAffine::BASEPOINT, Scalar::ZERO)]).is_identity());
        Builder::default()
            .with_seed(0)
            .with_search_limit(64)
            .test(|u| {
                let mut terms = [(GAffine::IDENTITY, Scalar::ZERO); 4];
                for term in &mut terms {
                    let encoding: [u8; 32] = u.arbitrary()?;
                    let point = GAffine::decompress(&encoding).unwrap_or(GAffine::BASEPOINT);
                    let torsion = GAffine::decompress(u.choose(&crate::test::ZIP215_POINTS)?)
                        .unwrap()
                        .to_extended();
                    *term = (point.to_extended().add(torsion).to_affine(), u.arbitrary()?);
                }
                let expected = terms.iter().fold(G::IDENTITY, |sum, (point, scalar)| {
                    sum.add(point.to_extended().scalar_mul(scalar.bits_be()))
                });
                assert!(straus(terms).add(expected.negate()).is_identity());
                Ok(())
            });
    }

    #[test]
    fn batch_coefficients_are_deterministic_and_block_dependent() {
        let seed = [7u8; 32];
        let a = batch_coefficients(&seed, 0);
        let b = batch_coefficients(&seed, 0);
        for k in 0..4 {
            assert_eq!(a[k].to_bytes(), b[k].to_bytes());
        }
        assert_ne!(
            batch_coefficients(&seed, 0)[0].to_bytes(),
            batch_coefficients(&seed, 1)[0].to_bytes()
        );
        assert_ne!(
            batch_coefficients(&seed, 0)[0].to_bytes(),
            batch_coefficients(&[8u8; 32], 0)[0].to_bytes()
        );
    }

    /// An encoding of no curve point.
    fn undecodable() -> [u8; 32] {
        (2..=u8::MAX)
            .map(|y| {
                let mut encoding = [0; 32];
                encoding[0] = y;
                encoding
            })
            .find(|encoding| GAffine::decompress(encoding).is_none())
            .unwrap()
    }

    /// [`partitions`] covers the units with contiguous ranges of near-equal length, a few per
    /// worker, each at least `min_len` units long unless there is only one.
    #[test]
    fn partitions_cover_units_contiguously() {
        for units in 0..200 {
            for min_len in [1, 2, 8] {
                for parallelism in [1, 3, 32] {
                    let ranges = partitions(units, min_len, parallelism);
                    assert!(ranges.len() <= 4 * parallelism);
                    assert_eq!(ranges.first().map_or(0, |range| range.start), 0);
                    assert_eq!(ranges.last().map_or(0, |range| range.end), units);
                    assert!(ranges.windows(2).all(|pair| pair[0].end == pair[1].start));
                    let shortest = ranges.iter().map(Range::len).min().unwrap_or(0);
                    let longest = ranges.iter().map(Range::len).max().unwrap_or(0);
                    assert!(longest - shortest <= 1);
                    assert!(ranges.len() <= 1 || shortest >= min_len);
                }
            }
        }
    }

    /// [`decompress_phase`] decompresses consecutive units in pairs and a partition's trailing unit
    /// alone, and returns the terms in worklist order under every strategy. Every entry must
    /// become one term carrying its own point, and an undecodable encoding in any position must
    /// reject the worklist.
    #[test]
    fn decompress_phase_pairs_units() {
        fn check<B: Backend>(backend: B, strategy: &impl Strategy) {
            // Entry `i` encodes `(i + 1)*B`.
            let base = GAffine::BASEPOINT.to_extended();
            let mut point = base;
            let encodings: Vec<[u8; 32]> = (0..18 * LANES + 3)
                .map(|_| {
                    let encoding = point.to_bytes();
                    point = point.add(base);
                    encoding
                })
                .collect();
            let invalid = undecodable();

            // One to four units in one or two partitions, and nineteen units in partitions of
            // five, five, five, and four under `Sequential` or of two and three under the pool.
            for count in [
                1,
                LANES,
                LANES + 1,
                2 * LANES,
                3 * LANES - 1,
                3 * LANES + 1,
                4 * LANES,
                18 * LANES + 3,
            ] {
                // With entry `i` recoded at scalar `i + 1`, the terms sum to `sum((i + 1)^2)*B`.
                let mut terms = decompress_phase(backend, count, |i| encodings[i], strategy)
                    .expect("valid encodings decompress");
                let units: usize = terms.iter().map(Vec::len).sum();
                assert_eq!(units, count.div_ceil(LANES));
                let width = msm::width_for(count, 1);
                for (i, term) in terms
                    .iter_mut()
                    .flat_map(|chunk| chunk.as_flattened_mut())
                    .take(count)
                    .enumerate()
                {
                    term.recode(&Scalar::from_u128(i as u128 + 1), width);
                }
                let chunks: Vec<&[Term]> = terms.iter().map(|chunk| chunk.as_flattened()).collect();
                let actual = msm::multiscalar_mul(backend, &chunks, width, &Sequential);
                let total: u128 = (1..=count as u128).map(|i| i * i).sum();
                let expected = base.scalar_mul(Scalar::from_u128(total).bits_be());
                assert_eq!(actual.to_bytes(), expected.to_bytes(), "count {count}");

                // An undecodable encoding in the first unit, the second unit, the middle, or the
                // last unit rejects.
                for bad in [0, LANES.min(count - 1), count / 2, count - 1] {
                    let encoding = |i: usize| if i == bad { invalid } else { encodings[i] };
                    assert!(
                        decompress_phase(backend, count, encoding, strategy).is_none(),
                        "count {count}, bad {bad}",
                    );
                }
            }
        }

        struct Check;

        impl WithBackend for Check {
            type Output = ();

            fn call<B: Backend>(self, backend: B) {
                check(backend, &Sequential);
                let parallel = commonware_parallel::Rayon::new(commonware_utils::NZUsize!(4))
                    .unwrap()
                    .manual();
                check(backend, &parallel);
            }
        }

        with_backend(Check);
    }

    type BatchItem = (VerifyingKeyBytes, Signature, Vec<u8>);

    /// A batch of both independent signers and a repeated signer (every position divisible by 3),
    /// spanning multiple signature-phase and decompression partitions. Keys and messages come
    /// from one drawn seed, so they stay distinct however short the fuzzer's input is. The tests
    /// below verify it under `Manual`, which disables the adaptive serial/parallel policy so every
    /// `strategy` call genuinely dispatches across the thread pool.
    fn mixed_batch_with_repeats(
        u: &mut Unstructured<'_>,
        n: usize,
    ) -> arbitrary::Result<Vec<BatchItem>> {
        let mut rng = commonware_utils::TestRng::new(u.arbitrary()?);
        let mut draw = || {
            let mut bytes = [0u8; 32];
            rand_core::Rng::fill_bytes(&mut rng, &mut bytes);
            bytes
        };
        let repeated_signer = RefSigningKey::from(draw());
        let batch: Vec<BatchItem> = (0..n)
            .map(|i| {
                let message = draw().to_vec();
                // Every third signature reuses `repeated_signer`, exercising `A`-term coalescing
                // alongside the independent-signer common case.
                let signer = if i % 3 == 0 {
                    repeated_signer.clone()
                } else {
                    RefSigningKey::from(draw())
                };
                (
                    VerifyingKeyBytes::new(signer.verification_key().to_bytes()),
                    Signature::from_bytes(signer.sign(&message).to_bytes()),
                    message,
                )
            })
            .collect();
        let mut keys: Vec<_> = batch.iter().map(|(key, _, _)| *key).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), 1 + n - n.div_ceil(3));
        Ok(batch)
    }

    /// 700 signatures from 468 signers make 1169 terms, past both the serial and the parallel
    /// Straus cutoffs, so the bucket method runs under the pool.
    #[test]
    fn verify_batch_bytes_accepts_valid_batch_under_real_parallelism() {
        let strategy = commonware_parallel::Rayon::new(commonware_utils::NZUsize!(4))
            .unwrap()
            .manual();
        Builder::default()
            .with_seed(0)
            .with_search_limit(4)
            .test(|u| {
                let rng_seed: [u8; 32] = u.arbitrary()?;
                let batch = mixed_batch_with_repeats(u, 700)?;
                let items = batch.iter().map(|(vk, sig, msg)| (vk, sig, msg.as_slice()));
                assert!(verify_batch_bytes(
                    &mut FuzzRng::new(rng_seed.to_vec()),
                    items,
                    &strategy,
                ));
                Ok(())
            });
    }

    /// Batch verification's verdict is a deterministic function of `(items, seed)` (see
    /// [`batch_coefficients`]), so serial and parallel strategies must agree on every batch --
    /// including invalid ones, where the accept/reject outcome depends on the derived
    /// coefficients.
    #[test]
    fn verify_batch_bytes_agrees_across_strategies_on_invalid_batch() {
        let strategy = commonware_parallel::Rayon::new(commonware_utils::NZUsize!(4))
            .unwrap()
            .manual();
        Builder::default()
            .with_seed(0)
            .with_search_limit(4)
            .test(|u| {
                let rng_seed: [u8; 32] = u.arbitrary()?;
                let mut batch = mixed_batch_with_repeats(u, 300)?;
                batch[123].1.s[0] ^= 1;

                let items = batch.iter().map(|(vk, sig, msg)| (vk, sig, msg.as_slice()));
                let serial =
                    verify_batch_bytes(&mut FuzzRng::new(rng_seed.to_vec()), items, &Sequential);

                let items = batch.iter().map(|(vk, sig, msg)| (vk, sig, msg.as_slice()));
                let parallel =
                    verify_batch_bytes(&mut FuzzRng::new(rng_seed.to_vec()), items, &strategy);

                assert!(!serial);
                assert_eq!(serial, parallel);
                Ok(())
            });
    }

    /// Verifies `batch` with a fixed seed.
    fn verify_with(batch: &[BatchItem], strategy: &impl Strategy) -> bool {
        let items = batch.iter().map(|(vk, sig, msg)| (vk, sig, msg.as_slice()));
        verify_batch_bytes(&mut FuzzRng::new(vec![7; 32]), items, strategy)
    }

    /// Verifies `batch` under `Sequential` and every pool, asserting that all reach the same
    /// verdict, and returns it.
    fn verdict(batch: &[BatchItem], pools: &[impl Strategy]) -> bool {
        let serial = verify_with(batch, &Sequential);
        for pool in pools {
            assert_eq!(verify_with(batch, pool), serial);
        }
        serial
    }

    /// Pools of two and four threads, for [`verdict`].
    fn pools() -> [impl Strategy; 2] {
        [2, 4].map(|threads| {
            commonware_parallel::Rayon::new(core::num::NonZeroUsize::new(threads).unwrap())
                .unwrap()
                .manual()
        })
    }

    /// An undecodable `R` or `A`, a non-canonical `s`, or a signature over another message
    /// rejects the batch wherever it sits: in the first or last lane of a unit, on either side of
    /// pair and partition boundaries, and on the repeated signer or an independent one.
    #[test]
    fn verify_batch_bytes_rejects_invalid_signature_at_any_position() {
        let pools = pools();
        let invalid = undecodable();
        Builder::default()
            .with_seed(0)
            .with_search_limit(1)
            .test(|u| {
                // The intact batch verifies.
                let batch = mixed_batch_with_repeats(u, 70)?;
                assert!(verdict(&batch, &pools));

                // Every corruption rejects it at every position. Every strategy here splits the
                // nine units into partitions of three, two, two, and two.
                for position in [0, 1, 7, 8, 15, 16, 23, 24, 39, 40, 63, 64, 69] {
                    for corruption in 0..4 {
                        let mut batch = batch.clone();
                        let (key, sig, msg) = &mut batch[position];
                        match corruption {
                            0 => sig.r = invalid,
                            1 => *key = VerifyingKeyBytes::new(invalid),
                            2 => sig.s[31] |= 0x80,
                            _ => msg[0] ^= 1,
                        }
                        assert!(
                            !verdict(&batch, &pools),
                            "position {position}, corruption {corruption}"
                        );
                    }
                }
                Ok(())
            });
    }

    /// Signatures whose equation holds when an undecodable point counts as the identity, so only
    /// the decoding check rejects them. Each comes with a control that swaps the undecodable
    /// encoding for the identity's encoding and verifies.
    fn decode_only_forgeries() -> [(BatchItem, BatchItem); 2] {
        let invalid = undecodable();
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let basepoint = GAffine::BASEPOINT.to_extended().to_bytes();
        let message = b"decode only".to_vec();
        let item = |r: [u8; 32], key: [u8; 32], s: Scalar| {
            let mut bytes = [0u8; 64];
            bytes[..32].copy_from_slice(&r);
            bytes[32..].copy_from_slice(&s.to_bytes());
            (
                VerifyingKeyBytes::new(key),
                Signature::from_bytes(bytes),
                message.clone(),
            )
        };

        // With `A = B` and `s = h`, the equation `s*B = R + h*A` holds for `R` the identity.
        let challenge = |r: &[u8; 32], key: &[u8; 32]| {
            Scalar::from_bytes_mod_order_wide(&sha512(&[r, key, &message]))
        };
        let bad_r = item(invalid, basepoint, challenge(&invalid, &basepoint));
        let good_r = item(identity, basepoint, challenge(&identity, &basepoint));

        // With `R = k*B` and `s = k`, the equation holds for `A` the identity.
        let k = Scalar::from_u128(0x1234_5678_9abc_def0);
        let r = G::mul_base_secret(&k.to_bytes()).to_bytes();
        [(bad_r, good_r), (item(r, invalid, k), item(r, identity, k))]
    }

    /// An undecodable `R` or `A` rejects the batch even where the rest of its equation holds,
    /// wherever it sits.
    #[test]
    fn verify_batch_bytes_rejects_undecodable_points_alone() {
        let pools = pools();
        Builder::default()
            .with_seed(0)
            .with_search_limit(1)
            .test(|u| {
                let batch = mixed_batch_with_repeats(u, 70)?;
                for (forged, control) in decode_only_forgeries() {
                    for position in [0, 7, 8, 15, 16, 39, 69] {
                        let mut accepted = batch.clone();
                        accepted[position] = control.clone();
                        assert!(verdict(&accepted, &pools), "position {position}");
                        let mut rejected = batch.clone();
                        rejected[position] = forged.clone();
                        assert!(!verdict(&rejected, &pools), "position {position}");
                    }
                    assert!(verdict(core::slice::from_ref(&control), &pools));
                    assert!(!verdict(core::slice::from_ref(&forged), &pools));
                }
                Ok(())
            });
    }

    /// Batches dominated by repeated signers verify, and a signature over another message rejects
    /// them. The single-signer batches recode their `R` terms at a narrower width than the
    /// distinct-signer one (with 520 signatures under `Sequential`, with 1100 under the pools),
    /// and with 1100 signatures the signer's scalars sum in parallel chunks.
    #[test]
    fn verify_batch_bytes_coalesces_repeated_signers() {
        // The batch sizes reach the narrower widths and the chunked sum.
        assert_ne!(msm::width_for(2 * 520 + 1, 1), msm::width_for(520 + 2, 1));
        for threads in [2, 4] {
            assert_ne!(
                msm::width_for(2 * 1100 + 1, threads),
                msm::width_for(1100 + 2, threads)
            );
        }
        const { assert!(1100 > SUM_CHUNK) };

        // Each batch verifies, and rejects once one of its signatures covers another message.
        let pools = pools();
        let signers: Vec<RefSigningKey> = (1..=3u8).map(|i| RefSigningKey::from([i; 32])).collect();
        for (n, distinct) in [(520, 1), (1100, 1), (300, 3)] {
            let batch: Vec<BatchItem> = (0..n)
                .map(|i| {
                    let signer = &signers[i % distinct];
                    let message = (i as u64).to_le_bytes().to_vec();
                    (
                        VerifyingKeyBytes::new(signer.verification_key().to_bytes()),
                        Signature::from_bytes(signer.sign(&message).to_bytes()),
                        message,
                    )
                })
                .collect();
            assert!(verdict(&batch, &pools), "n {n}");
            let mut batch = batch;
            batch[n / 2].2[0] ^= 1;
            assert!(!verdict(&batch, &pools), "n {n}");
        }
    }
}
