//! Ed25519 verification internals.

mod hash;
mod msm;
mod scalar;

use crate::curve::{Backend, G, GAffine, LANES, WithBackend, with_backend};
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use commonware_parallel::{Sequential, Strategy};
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
/// `seed` as one SHA-512 output, in counter mode.
///
/// The batch equation's soundness needs each `z_i` to be uniform, independent, and unpredictable
/// to whoever assembled the batch; PRF outputs under a seed drawn freshly from the caller's
/// CSPRNG (and never revealed) are indistinguishable from exactly that. Deriving each signature's
/// coefficient from its *position* rather than drawing all of them from the shared `rng` up
/// front lets every thread compute its own signatures' coefficients locally -- and makes the
/// batch's coefficients and verdict deterministic functions of `(items, seed)`, identical at
/// every thread count.
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

/// Signatures per [`scalar_phase`] unit: one per [`hash::LANES`] lane, covering whole
/// [`batch_coefficients`] blocks.
const UNIT: usize = hash::LANES;
const _: () = assert!(UNIT.is_multiple_of(4));

/// One [`scalar_phase`] output block: the `z*h` scalars (each signature's contribution to its
/// signer's coalesced `A` term) and `z` scalars (each `R` point's own MSM scalar) for the
/// [`UNIT`] consecutive sorted positions of one unit, plus the unit's `sum(z*s)` contribution to
/// the coalesced basepoint scalar.
struct ScalarBlock {
    zh: [Scalar; UNIT],
    zr: [Scalar; UNIT],
    zs_sum: Scalar,
    valid: bool,
}

/// The per-signature scalar phase, parallel over [`UNIT`]-signature units of the sorted batch:
/// for each sorted position, derives `z` (see [`batch_coefficients`]), rejects a non-canonical
/// `s`, computes the challenge `h = H(R || A || M)`, and packs `z*h`/`z` into that position's
/// [`ScalarBlock`] slot. Returns the blocks together with `sum(z*s) mod L` -- the coalesced
/// basepoint scalar -- or `None` if any `s` was non-canonical (a structurally invalid signature,
/// rejected before point decompression begins).
///
/// The parallel unit fills every [`hash::digest`] lane and never derives a coefficient block
/// twice. It is produced as a value and collected, so there is no output array to pre-zero or
/// scatter into, and the pool's demand-driven splitting balances the pass at unit granularity: a
/// late-waking worker simply takes fewer units (see [`decompress_phase`] for the same
/// principle). This phase touches no curve points: it is uniform per signature regardless of how
/// the batch's signers are distributed.
fn scalar_phase(
    items: &[(&VerifyingKeyBytes, &Signature, &[u8])],
    order: &[(VerifyingKeyBytes, u32)],
    seed: &[u8; 32],
    strategy: &impl Strategy,
) -> Option<(Vec<ScalarBlock>, Scalar)> {
    let n = items.len();
    let body = |unit: usize| {
        let start = UNIT * unit;
        let positions = &order[start..n.min(start + UNIT)];
        let mut z = [Scalar::ZERO; UNIT];
        for (block, coefficients) in z
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .take(positions.len().div_ceil(4))
            .enumerate()
        {
            *coefficients = batch_coefficients(seed, (start / 4 + block) as u64);
        }
        let mut messages: [[&[u8]; 3]; UNIT] = [[&[]; 3]; UNIT];
        for (message, &(_, index)) in messages.iter_mut().zip(positions) {
            let (a_bytes, sig, msg) = items[index as usize];
            *message = [&sig.r, a_bytes.as_bytes(), msg];
        }
        let digests = hash::digest(&messages[..positions.len()]);

        let mut zh = [Scalar::ZERO; UNIT];
        let mut zr = [Scalar::ZERO; UNIT];
        let mut zs_sum = Scalar::ZERO;
        let mut valid = true;
        for (j, &(_, index)) in positions.iter().enumerate() {
            let (_, sig, _) = items[index as usize];
            let Some(s) = Scalar::from_canonical_bytes(&sig.s) else {
                valid = false;
                continue;
            };
            let h = Scalar::from_bytes_mod_order_wide(&digests[j]);
            zh[j] = z[j].mul_mod_l(&h);
            zr[j] = z[j];
            zs_sum = zs_sum.add_mod_l(&z[j].mul_mod_l(&s));
        }
        ScalarBlock {
            zh,
            zr,
            zs_sum,
            valid,
        }
    };

    let blocks: Vec<ScalarBlock> = strategy.map_collect_vec(0..n.div_ceil(UNIT), body);
    let mut s_sum = Scalar::ZERO;
    for block in &blocks {
        if !block.valid {
            return None;
        }
        s_sum = s_sum.add_mod_l(&block.zs_sum);
    }
    Some((blocks, s_sum))
}

/// Decompresses the `N` consecutive units starting at `first` with one backend batch and appends
/// their MSM terms to `terms`, padding entries at or past `count` with identity/zero terms.
///
/// Returns whether every encoding decompressed.
fn decompress_units<B: Backend, const N: usize>(
    backend: B,
    first: usize,
    count: usize,
    resolve: &impl Fn(usize) -> ([u8; 32], Scalar),
    width: u32,
    terms: &mut Vec<[Term; LANES]>,
) -> bool {
    let mut identity_encoding = [0u8; 32];
    identity_encoding[0] = 1;
    let resolved: [[_; LANES]; N] = core::array::from_fn(|unit| {
        core::array::from_fn(|lane| {
            let index = (first + unit) * LANES + lane;
            if index < count {
                resolve(index)
            } else {
                (identity_encoding, Scalar::ZERO)
            }
        })
    });
    let bytes = resolved.map(|unit| unit.map(|(bytes, _)| bytes));
    let points = GAffine::decompress_batch(backend, &bytes);
    let placeholder = || Term::new(GAffine::IDENTITY, &Scalar::ZERO, width);
    let mut valid = true;
    for (unit, (resolved, points)) in resolved.iter().zip(points).enumerate() {
        let base = (first + unit) * LANES;
        terms.push(core::array::from_fn(|lane| {
            if base + lane >= count {
                return placeholder();
            }
            points[lane].map_or_else(
                || {
                    valid = false;
                    placeholder()
                },
                |point| Term::new(point, &resolved[lane].1, width),
            )
        }));
    }
    valid
}

/// The decompression phase: turns a flat worklist of `count` point encodings (resolved by index
/// via `resolve`, which returns an encoding and its already-final MSM scalar) into MSM terms, in
/// one parallel pass over [`LANES`]-sized units -- the finest split that keeps the sqrt kernel
/// running 8-wide (see [`GAffine::decompress_batch`]), so the pool's demand-driven
/// splitting balances the pass at ~7us granularity and a late-waking worker simply takes fewer
/// units. Each partition decompresses its units in pairs (see [`decompress_units`]), giving the
/// backend two independent square-root chains to overlap. Each fixed partition builds one exactly
/// sized term vector, then the parallel fold joins validity and vectors of those buffers without
/// shared state or copying point data. The final unit is padded with identity/zero terms, keeping
/// decompression SIMD-wide without changing the MSM.
///
/// Returns `None` if any encoding fails to decompress.
fn decompress_phase<B, F>(
    backend: B,
    count: usize,
    resolve: F,
    width: u32,
    strategy: &impl Strategy,
) -> Option<Vec<Vec<[Term; LANES]>>>
where
    B: Backend,
    F: Fn(usize) -> ([u8; 32], Scalar) + Send + Sync,
{
    let units = count.div_ceil(LANES);
    if units == 0 {
        return Some(Vec::new());
    }

    const PARTITIONS_PER_WORKER: usize = 4;
    const MIN_UNITS_PER_PARTITION: usize = 8;
    let target_partitions = strategy
        .manual()
        .parallelism()
        .saturating_mul(PARTITIONS_PER_WORKER);
    let max_partitions = (units / MIN_UNITS_PER_PARTITION).max(1);
    let partition_count = target_partitions.min(max_partitions).min(units);
    let partition_len = units / partition_count;
    let remainder = units % partition_count;
    let mut ranges = Vec::with_capacity(partition_count);
    let mut start = 0;
    for partition in 0..partition_count {
        let len = partition_len + usize::from(partition < remainder);
        ranges.push(start..start + len);
        start += len;
    }

    let (valid, chunks) = strategy.fold(
        ranges,
        || (true, Vec::new()),
        |(valid, mut chunks), range| {
            let mut chunk_valid = true;
            let mut terms = Vec::with_capacity(range.len());
            for unit in range.clone().step_by(2) {
                chunk_valid &= if unit + 1 < range.end {
                    decompress_units::<_, 2>(backend, unit, count, &resolve, width, &mut terms)
                } else {
                    decompress_units::<_, 1>(backend, unit, count, &resolve, width, &mut terms)
                };
            }
            chunks.push(terms);
            (valid && chunk_valid, chunks)
        },
        |(left_valid, mut left_chunks), (right_valid, right_chunks)| {
            left_chunks.extend(right_chunks);
            (left_valid && right_valid, left_chunks)
        },
    );
    valid.then_some(chunks)
}

/// The batch-verification pipeline: a short sequence of data-parallel phases over flat arrays,
/// with `A` coalescing falling out of a sort.
///
/// 1. Sort of `(A encoding, original index)` pairs, so every signer's signatures sit adjacent
///    and grouping becomes local information ([`group_ranges`]).
/// 2. [`scalar_phase`]: coefficient derivation, hashing, and scalar arithmetic -- uniform per
///    signature, no curve points.
/// 3. [`decompress_phase`] over a flat worklist containing every `R` and every distinct `A`, into
///    contiguous term chunks. A signer's coalesced scalar (the sum of its signatures' `z*h` over
///    a contiguous [`ScalarBlock`] run) is computed lazily by whichever unit resolves its `A`
///    entry, so there is no separate group-sum pass.
/// 4. One tile-parallel MSM over the term slices (with the coalesced basepoint term
///    `sum(z*s)·(-B)` riding along as one final term), then the cofactored identity check.
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

    // Byte-identical keys keep their original order, making the position-derived coefficients
    // deterministic across strategies.
    let order = sort_keys(items);

    let Some((blocks, s_sum)) = scalar_phase(items, &order, &seed, strategy) else {
        return false;
    };
    let zr = |i: usize| blocks[i / UNIT].zr[i % UNIT];
    // A signer's coalesced scalar: the sum of its contiguous sorted run's `z*h` scalars. Cheap
    // mod-L additions, computed lazily (each group is resolved exactly once, by the worklist
    // entry for its `A` term), so the summing itself rides inside a parallel phase. A batch
    // dominated by one signer folds its whole run in that signer's single resolve call --
    // acceptable, since even a 16k-signature run is far cheaper than one decompression unit's
    // point arithmetic.
    let group_scalar = |(start, end): (u32, u32)| {
        (start as usize..end as usize).fold(Scalar::ZERO, |acc, i| {
            acc.add_mod_l(&blocks[i / UNIT].zh[i % UNIT])
        })
    };

    let groups = group_ranges(&order);
    // The MSM window width is a per-batch choice (see [`msm::width_for`]) and every term must
    // be recoded at the same width, so it is fixed here, before any term is built: the term
    // count is every `R`, every distinct `A`, and the basepoint.
    let width = msm::width_for(n + groups.len() + 1, strategy.parallelism());
    let resolve_r = |i: usize| {
        let (_, sig, _) = items[order[i].1 as usize];
        (sig.r, zr(i))
    };

    // The coalesced basepoint term: `sum(z*s)·B` moved to the equation's other side by negating
    // its scalar, one more ordinary MSM term.
    let basepoint = [Term::new(GAffine::BASEPOINT, &s_sum.neg_mod_l(), width)];

    let resolve = |i: usize| {
        if i < n {
            resolve_r(i)
        } else {
            let group = groups[i - n];
            (*order[group.0 as usize].0.as_bytes(), group_scalar(group))
        }
    };
    let Some(terms) = decompress_phase(backend, n + groups.len(), resolve, width, strategy) else {
        return false;
    };
    let mut chunks: Vec<&[Term]> = terms.iter().map(|chunk| chunk.as_flattened()).collect();
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
/// a signer reused across the batch is decompressed once, not once per signature, and the
/// deduplicated `A` encodings join `R`'s per-signature encodings in the same decompression pass.
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

    /// [`decompress_phase`] decompresses consecutive units in pairs and a partition's trailing unit
    /// alone. Every entry must become one term carrying its own point and scalar, and an
    /// undecodable encoding in any position must reject the worklist.
    #[test]
    fn decompress_phase_pairs_units() {
        struct Check;

        impl WithBackend for Check {
            type Output = ();

            fn call<B: Backend>(self, backend: B) {
                // Entry `i` encodes `(i + 1)*B` and carries scalar `i + 1`.
                let base = GAffine::BASEPOINT.to_extended();
                let mut point = base;
                let encodings: Vec<[u8; 32]> = (0..18 * LANES + 3)
                    .map(|_| {
                        let encoding = point.to_bytes();
                        point = point.add(base);
                        encoding
                    })
                    .collect();
                let scalar = |i: usize| Scalar::from_u128(i as u128 + 1);
                let invalid = (2..=u8::MAX)
                    .map(|y| {
                        let mut encoding = [0; 32];
                        encoding[0] = y;
                        encoding
                    })
                    .find(|encoding| GAffine::decompress(encoding).is_none())
                    .unwrap();

                // One to four units in one partition, and nineteen units in partitions of ten
                // and nine.
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
                    // The terms sum to `sum((i + 1)^2)*B`.
                    let width = msm::width_for(count, 1);
                    let resolve = |i: usize| (encodings[i], scalar(i));
                    let terms = decompress_phase(backend, count, resolve, width, &Sequential)
                        .expect("valid encodings decompress");
                    let units: usize = terms.iter().map(Vec::len).sum();
                    assert_eq!(units, count.div_ceil(LANES));
                    let chunks: Vec<&[Term]> =
                        terms.iter().map(|chunk| chunk.as_flattened()).collect();
                    let actual = msm::multiscalar_mul(backend, &chunks, width, &Sequential);
                    let total: u128 = (1..=count as u128).map(|i| i * i).sum();
                    let expected = base.scalar_mul(Scalar::from_u128(total).bits_be());
                    assert_eq!(actual.to_bytes(), expected.to_bytes(), "count {count}");

                    // An undecodable encoding in the first unit, the second unit, the middle, or
                    // the last unit rejects.
                    for bad in [0, LANES.min(count - 1), count / 2, count - 1] {
                        let resolve = |i: usize| {
                            let encoding = if i == bad { invalid } else { encodings[i] };
                            (encoding, scalar(i))
                        };
                        assert!(
                            decompress_phase(backend, count, resolve, width, &Sequential).is_none(),
                            "count {count}, bad {bad}",
                        );
                    }
                }
            }
        }

        with_backend(Check);
    }

    type BatchItem = (VerifyingKeyBytes, Signature, Vec<u8>);

    /// A batch of both independent signers and a repeated signer, spanning multiple scalar-phase
    /// chunks and decompression chunks, verified under `Manual` -- which disables the adaptive
    /// serial/parallel policy so every `strategy` call in this test genuinely dispatches across
    /// the thread pool, rather than the policy falling back to serial for a size it judges too
    /// small. Every other test in this module uses `Sequential`, so these are the only ones
    /// exercising real concurrent execution of the sort, the scalar phase, the fused
    /// decompression pass, and the tile-parallel MSM end to end.
    fn mixed_batch_with_repeats(
        u: &mut Unstructured<'_>,
        n: usize,
    ) -> arbitrary::Result<Vec<BatchItem>> {
        let seed: [u8; 32] = u.arbitrary()?;
        let repeated_signer = RefSigningKey::from(seed);
        let repeated_key = repeated_signer.verification_key().to_bytes();

        (0..n)
            .map(|i| {
                let message = u.arbitrary::<[u8; 32]>()?.to_vec();
                // Every third signature reuses `repeated_signer`, exercising `A`-term coalescing
                // alongside the independent-signer common case.
                let item = if i % 3 == 0 {
                    let signature = repeated_signer.sign(&message);
                    (
                        VerifyingKeyBytes::new(repeated_key),
                        Signature::from_bytes(signature.to_bytes()),
                        message,
                    )
                } else {
                    let seed: [u8; 32] = u.arbitrary()?;
                    let signing_key = RefSigningKey::from(seed);
                    let verifying_key = signing_key.verification_key().to_bytes();
                    let signature = signing_key.sign(&message);
                    (
                        VerifyingKeyBytes::new(verifying_key),
                        Signature::from_bytes(signature.to_bytes()),
                        message,
                    )
                };
                Ok(item)
            })
            .collect()
    }

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
                let batch = mixed_batch_with_repeats(u, 600)?;
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
}
