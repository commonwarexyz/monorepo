//! Ed25519 verification internals.

mod msm;
mod scalar;

use super::{PublicKey, Signature};
use crate::curve::{
    Backend, G, GAffine, LANES, ODD_MULTIPLES, ODD_MULTIPLES_NAF_WIDTH, WithBackend, with_backend,
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use commonware_codec::Write as _;
use commonware_cryptography::{Hasher as _, Sha512, sha512::Digest};
use commonware_parallel::{Sequential, Strategy};
use commonware_utils::Widen;
use core::num::NonZeroUsize;
use msm::Term;
use rand_core::CryptoRng;
pub(super) use scalar::Scalar;

/// One signature's verification inputs, borrowed from the caller.
#[derive(Clone, Copy)]
pub(super) struct Item<'a> {
    /// The signer's key.
    pub(super) key: &'a PublicKey,
    /// The signature to verify.
    pub(super) signature: &'a Signature,
    /// The namespace framed ahead of `message` in the challenge, or `None` to hash `message`
    /// alone.
    pub(super) namespace: Option<&'a [u8]>,
    /// The signed message.
    pub(super) message: &'a [u8],
}

/// The encoding of the identity point. It pads the final unit of a decompression batch.
const IDENTITY_ENCODING: [u8; 32] = {
    let mut encoding = [0; 32];
    encoding[0] = 1;
    encoding
};

/// Decompresses `count` point encodings, [`LANES`] at a time with the lane-wise square root of
/// the selected backend, across `strategy`. `encoding` yields the encoding at each position.
///
/// Returns each point at its encoding's position, and `None` where the encoding is not a curve
/// point. Every encoding is decompressed even after a failure.
pub(super) fn decompress_many<E>(
    count: usize,
    encoding: E,
    strategy: &impl Strategy,
) -> Vec<Option<GAffine>>
where
    E: Fn(usize) -> [u8; 32] + Sync,
{
    with_backend(DecompressMany {
        count,
        encoding,
        strategy,
    })
}

/// The inputs of [`decompress_many`].
struct DecompressMany<'a, E, S> {
    count: usize,
    encoding: E,
    strategy: &'a S,
}

impl<E, S> WithBackend for DecompressMany<'_, E, S>
where
    E: Fn(usize) -> [u8; 32] + Sync,
    S: Strategy,
{
    type Output = Vec<Option<GAffine>>;

    // Inlined so the lane-wise decompression compiles inside the backend's target-feature entry,
    // where its field operations can inline.
    #[inline(always)]
    fn call<B: Backend>(self, backend: B) -> Self::Output {
        let Self {
            count,
            encoding,
            strategy,
        } = self;
        strategy.run_batches(count.div_ceil(LANES), NonZeroUsize::MIN, LANES, |batches| {
            batches
                .map_collect_vec(
                    |ranges| ranges,
                    |range| {
                        let mut points = Vec::with_capacity(range.len() * LANES);
                        for unit in range {
                            // A unit decompresses its encodings in one backend batch, with the
                            // identity encoding in every lane past the last encoding.
                            let start = unit * LANES;
                            let lanes = count.min(start + LANES) - start;
                            let mut encodings = [IDENTITY_ENCODING; LANES];
                            for (lane, slot) in encodings.iter_mut().take(lanes).enumerate() {
                                *slot = encoding(start + lane);
                            }
                            let decompressed = GAffine::decompress_batch(backend, &encodings);
                            points.extend_from_slice(&decompressed[..lanes]);
                        }
                        points
                    },
                )
                .concat()
        })
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
    let digest = Sha512::hash(&[seed, &block.to_le_bytes()]).0;
    core::array::from_fn(|k| {
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[k * 16..(k + 1) * 16]);
        Scalar::from_u128(u128::from_le_bytes(bytes))
    })
}

/// Groups `sorted` (pre-sorted `(key, original index)` pairs) into runs of equal keys, returned
/// as `(start, end)` positions into `sorted`. Each run becomes one `A` term in batch
/// verification, so a signer reused across the batch contributes one MSM term for all of its
/// signatures.
fn group_ranges(sorted: &[([u8; 32], u32)]) -> Vec<(u32, u32)> {
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

// A `signature_phase` unit holds one signature per SHA-512 lane. Units cover whole
// `batch_coefficients` blocks of four, so the lane count must be a multiple of 4.
const _: () = assert!(LANES.is_multiple_of(4));

/// The output of one [`signature_phase`] partition, holding its signatures' `R` terms, each
/// unit's `z*h` (its signatures' shares of their signers' coalesced `A` scalars), and the
/// partition's share of `sum(z*s) mod L`.
struct Partition {
    terms: Vec<Term>,
    zh: Vec<[Scalar; LANES]>,
    zs_sum: Scalar,
}

/// Hashes the challenges `R || A || M` of unit `unit`, with `M` the framed message.
///
/// The unit's scalar work cannot split, but long messages make its hashing worth spreading across
/// workers. [`Sha512::hash_many`] splits the challenges across `strategy` only between whole
/// batches of the SHA-512 kernel, so a unit can spread only where that kernel hashes fewer than
/// [`LANES`] messages at once.
fn hash_unit(
    items: &[Item<'_>],
    unit: usize,
    challenges: &mut Vec<u8>,
    strategy: &impl Strategy,
) -> Vec<Digest> {
    // `Sha512::hash_many` takes each message as one slice, so every lane's `R || A || M` is
    // staged back to back in `challenges`, a buffer reused across units, with the namespace
    // framed before the message.
    let start = unit * LANES;
    let lanes = &items[start..items.len().min(start + LANES)];
    let mut ends = [0; LANES];
    challenges.clear();
    for (end, item) in ends.iter_mut().zip(lanes) {
        challenges.extend_from_slice(item.signature.r_bytes());
        challenges.extend_from_slice(&item.key.bytes);
        if let Some(namespace) = item.namespace {
            namespace.len().write(challenges);
            challenges.extend_from_slice(namespace);
        }
        challenges.extend_from_slice(item.message);
        *end = challenges.len();
    }

    // Cut the staged bytes back into one input per lane, and hash them.
    let mut inputs: [&[u8]; LANES] = [&[]; LANES];
    let mut start = 0;
    for (input, &end) in inputs.iter_mut().zip(&ends[..lanes.len()]) {
        *input = &challenges[start..end];
        start = end;
    }
    Sha512::hash_many(&inputs[..lanes.len()], strategy)
}

/// Processes unit `unit` into `partition`, recoding its `R` terms at `width`. `digests` holds
/// the unit's challenge hashes (see [`hash_unit`]).
fn signature_unit(
    items: &[Item<'_>],
    seed: &[u8; 32],
    width: u32,
    unit: usize,
    digests: &[Digest],
    partition: &mut Partition,
) {
    // Signature `i` of the batch takes `z_i` (see `batch_coefficients`). A unit starts at a
    // multiple of 4, so it derives only the blocks from `start / 4` that cover its items.
    let start = unit * LANES;
    let lanes = &items[start..items.len().min(start + LANES)];
    let mut z = [Scalar::ZERO; LANES];
    for (block, coefficients) in z
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .take(lanes.len().div_ceil(4))
        .enumerate()
    {
        *coefficients = batch_coefficients(seed, Widen::<u64>::widen(start / 4 + block));
    }

    // `z*h` is the signature's share of its signer's coalesced `A` scalar, `z*s` accumulates
    // into the partition's share of `sum(z*s)`, and the signature's `R` term takes its `z`.
    let mut zh = [Scalar::ZERO; LANES];
    for (j, item) in lanes.iter().enumerate() {
        let h = Scalar::from_bytes_mod_order_wide(&digests[j].0);
        zh[j] = z[j].mul_mod_l(&h);
        partition.zs_sum = partition
            .zs_sum
            .add_mod_l(&z[j].mul_mod_l(&item.signature.s));
        partition
            .terms
            .push(Term::new(item.signature.r, &z[j], width));
    }
    partition.zh.push(zh);
}

/// The per-signature phase, parallel over [`LANES`]-signature units in batch order: for each
/// signature, derives `z` (see [`batch_coefficients`]), computes the challenge
/// `h = H(R || A || M)` and the scalars `z*h` and `z*s`, and recodes `R` into a term at `width`.
///
/// A strategy batch may hold a single unit. Where the SHA-512 kernel hashes fewer than [`LANES`]
/// messages at once, a unit can spread its hashing further (see [`hash_unit`]), so a batch of a few
/// long messages can still use more workers than it has units.
///
/// The phase needs no grouping, so it runs while [`verify_pipeline`] sorts the keys.
fn signature_phase(
    items: &[Item<'_>],
    seed: &[u8; 32],
    width: u32,
    strategy: &impl Strategy,
) -> Vec<Partition> {
    strategy.run_batches(
        items.len().div_ceil(LANES),
        NonZeroUsize::MIN,
        LANES,
        |batches| {
            batches.map_collect_vec(
                |ranges| ranges,
                |range| {
                    // A batch is a contiguous range of units, and its partition holds one `zh`
                    // block per unit, in unit order. Partitions return in batch order, so their
                    // flattened blocks are indexed by unit.
                    let mut partition = Partition {
                        terms: Vec::with_capacity(range.len() * LANES),
                        zh: Vec::with_capacity(range.len()),
                        zs_sum: Scalar::ZERO,
                    };
                    let mut challenges = Vec::new();
                    for unit in range {
                        let digests = hash_unit(items, unit, &mut challenges, strategy);
                        signature_unit(items, seed, width, unit, &digests, &mut partition);
                    }
                    partition
                },
            )
        },
    )
}

/// A signer with more signatures than this sums their `z*h` scalars in parallel, this many per
/// task.
const SUM_CHUNK: usize = 1024;

/// Verifies `items` as one batch under a fresh seed from `rng`.
///
/// The MSM window width is a per-batch choice (see [`msm::width_for`]) that every term must
/// share, so it is fixed before any term is recoded. It counts one `R` and one `A` per signature
/// and the basepoint, as if every signer were distinct, so the `R` terms can be recoded before
/// the keys are grouped. A parallel run picks a window no wider than a serial run would (see
/// [`msm::width_for`]), so the strategy's choice between running the pipeline serially and in
/// parallel also picks the width.
fn verify_batch_inner<B: Backend>(
    backend: B,
    rng: &mut impl CryptoRng,
    items: &[Item<'_>],
    strategy: &impl Strategy,
) -> bool {
    let n = items.len();
    if n == 0 {
        return false;
    }

    // Sorting and grouping use compact indices.
    if u32::try_from(n).is_err() {
        return false;
    }

    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let terms = 2 * n + 1;
    strategy.run(
        n,
        || {
            verify_pipeline(
                backend,
                items,
                &seed,
                msm::width_for(terms, false),
                &Sequential,
            )
        },
        || verify_pipeline(backend, items, &seed, msm::width_for(terms, true), strategy),
    )
}

/// The batch-verification pipeline: a short sequence of data-parallel phases over flat arrays,
/// with `A` coalescing falling out of a sort.
///
/// 1. Two concurrent tasks. [`signature_phase`] derives coefficients, hashes, computes the
///    per-signature scalars, and recodes every `R` into a term with its `z`. Meanwhile a sort by
///    key and [`group_ranges`] group each signer's signatures.
/// 2. One parallel pass over the signers builds each signer's `A` term from the point its key
///    carries, recoded with its coalesced scalar (the sum of its signatures' `z*h`).
/// 3. One MSM over the terms, with the coalesced basepoint term `sum(z*s)*(-B)` riding along as
///    one final term, then the cofactored identity check.
///
/// Returns whether the batch equation holds.
fn verify_pipeline<B: Backend>(
    backend: B,
    items: &[Item<'_>],
    seed: &[u8; 32],
    width: u32,
    strategy: &impl Strategy,
) -> bool {
    let (signatures, (order, groups)) = strategy.join(
        || signature_phase(items, seed, width, strategy),
        || {
            // Each key carries its signature's original index, which leads from a signer's run
            // in `order` back to its signatures' `z*h`.
            let mut order: Vec<([u8; 32], u32)> = items
                .iter()
                .enumerate()
                .map(|(i, item)| (item.key.bytes, i as u32))
                .collect();

            // The signature phase occupies the pool meanwhile, so sort on this thread.
            order.sort_unstable_by_key(|&(key, _)| key);
            let groups = group_ranges(&order);
            (order, groups)
        },
    );

    // A signer's coalesced scalar: the sum of `z*h` over its run of `order`. Partitions hold
    // consecutive units in batch order, so an original index selects its unit's block and lane.
    let blocks: Vec<&[Scalar; LANES]> = signatures
        .iter()
        .flat_map(|partition| &partition.zh)
        .collect();
    let sum = |run: &[([u8; 32], u32)]| {
        run.iter()
            .map(|&(_, index)| blocks[index as usize / LANES][index as usize % LANES])
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

    // The signatures of a run share one key encoding and so one point. Build every distinct
    // signer's `A` term from the key of its run's first signature. Each signer is weighted by its
    // average share of the summed signatures and recoded groups, so the strategy's estimates for
    // different batch sizes stay apart.
    let first = |signer: usize| {
        &items[Widen::<usize>::widen(order[Widen::<usize>::widen(groups[signer].0)].1)]
    };
    let work_per_signer = (order.len() + groups.len()).div_ceil(groups.len());
    let a_terms: Vec<Vec<Term>> = strategy.run_batches(
        groups.len(),
        NonZeroUsize::MIN,
        work_per_signer,
        |batches| {
            batches.map_collect_vec(
                |ranges| ranges,
                |range| {
                    range
                        .map(|signer| {
                            Term::new(
                                first(signer).key.point,
                                &group_scalar(groups[signer]),
                                width,
                            )
                        })
                        .collect()
                },
            )
        },
    );

    // The coalesced basepoint term: `sum(z*s)*B` moved to the equation's other side by negating
    // its scalar, one more ordinary MSM term.
    let s_sum = signatures.iter().fold(Scalar::ZERO, |sum, partition| {
        sum.add_mod_l(&partition.zs_sum)
    });
    let basepoint = [Term::new(GAffine::BASEPOINT, &s_sum.neg_mod_l(), width)];

    // One MSM reads the `R` terms, the `A` terms, and the basepoint term in place. It sums
    // `z*R + z*h*A - z*s*B` over every signature, so a valid batch's result is the identity once
    // multiplied by the cofactor.
    let mut chunks: Vec<&[Term]> = signatures
        .iter()
        .map(|partition| &partition.terms)
        .chain(&a_terms)
        .map(Vec::as_slice)
        .collect();
    chunks.push(basepoint.as_slice());
    let result = msm::multiscalar_mul(backend, &chunks, width, strategy);
    result.mul_by_cofactor().is_identity()
}

/// Width of the non-adjacent forms [`straus`] recodes its variable-base scalars into.
const NAF_WIDTH: usize = 5;

/// The number of odd multiples a width-[`NAF_WIDTH`] digit can select.
const TABLE_LEN: usize = 1 << (NAF_WIDTH - 2);

/// Returns the odd multiples `point, 3*point, ..., 15*point`, built by repeatedly adding
/// `2*point`, so a width-[`NAF_WIDTH`] digit `d` selects entry `|d| / 2`.
#[inline(always)]
fn odd_multiples<B: Backend>(backend: B, point: &G) -> [B::Cached; TABLE_LEN] {
    let point = backend.load(point);
    let double = backend.cache(backend.to_extended(backend.double(backend.project(point))));
    let mut table = [backend.cache(point); TABLE_LEN];
    let mut multiple = point;
    for entry in &mut table[1..] {
        multiple = backend.to_extended(backend.add_cached(multiple, double, false));
        *entry = backend.cache(multiple);
    }
    table
}

/// Computes `base[0]*B + base[1]*2^128*B + sum(scalar*point)` over `terms` with Straus's
/// method: one doubling chain shared by every term, adding `digit*point` at each nonzero digit
/// of the scalars' non-adjacent forms from a table of odd multiples of each point.
///
/// Variable-time, so the points and scalars must be public.
#[inline(always)]
fn straus<B: Backend, const N: usize>(
    backend: B,
    base: [Scalar; 2],
    terms: [(G, Scalar); N],
) -> B::Projective {
    // The basepoint multiples come from static tables, which afford a wider window and so fewer
    // additions than the per-call tables. In a width-`w` non-adjacent form every nonzero digit
    // is odd with magnitude below `2^(w-1)`, and at least `w - 1` zeros separate nonzero digits.
    let base_digits = base.map(|scalar| scalar.naf::<ODD_MULTIPLES_NAF_WIDTH>());
    let digits = terms.map(|(_, scalar)| scalar.naf::<NAF_WIDTH>());

    // One loop builds every table, so the inlined table builder appears once. The identity's
    // cache only initializes the array.
    let placeholder = backend.cache(backend.load(&G::IDENTITY));
    let mut tables = [[placeholder; TABLE_LEN]; N];
    for (table, (point, _)) in tables.iter_mut().zip(&terms) {
        *table = odd_multiples(backend, point);
    }

    // The shared doubling chain starts at the highest nonzero digit of any scalar. If every
    // scalar is zero, so is the sum.
    let identity = backend.project(backend.load(&G::IDENTITY));
    let Some(top) = base_digits
        .iter()
        .chain(&digits)
        .filter_map(|digits| digits.iter().rposition(|&digit| digit != 0))
        .max()
    else {
        return identity;
    };

    // Horner's rule over digit positions, most significant first: double the running sum once
    // per position, then add each term's selected multiple, negated for a negative digit.
    // Doublings and additions leave a completed point, converted to extended coordinates only
    // when an addition, which reads `T`, comes next.
    let mut sum = identity;
    for i in (0..=top).rev() {
        let mut step = backend.double(sum);
        for (digits, table) in base_digits.iter().zip(&ODD_MULTIPLES) {
            let digit = digits[i];
            if digit != 0 {
                let multiple = &table[usize::from(digit.unsigned_abs()) / 2];
                step = backend.add_niels(backend.to_extended(step), multiple, digit < 0);
            }
        }
        for (digits, table) in digits.iter().zip(&tables) {
            let digit = digits[i];
            if digit != 0 {
                let multiple = table[usize::from(digit.unsigned_abs()) / 2];
                step = backend.add_cached(backend.to_extended(step), multiple, digit < 0);
            }
        }
        sum = backend.to_projective(step);
    }
    sum
}

/// Verifies one signature per the [module's validation criteria](super).
pub(super) fn verify(key: &PublicKey, sig: &Signature, msg: &[u8]) -> bool {
    with_backend(Verify { key, sig, msg })
}

/// The inputs of [`verify`], checked with the selected backend's single-point operations.
struct Verify<'a> {
    key: &'a PublicKey,
    sig: &'a Signature,
    msg: &'a [u8],
}

impl WithBackend for Verify<'_> {
    type Output = bool;

    // Inlined so the algorithm compiles inside the backend's target-feature entry, where its
    // point operations can inline.
    #[inline(always)]
    fn call<B: Backend>(self, backend: B) -> bool {
        let h = Scalar::from_bytes_mod_order_wide(
            &Sha512::hash(&[self.sig.r_bytes(), &self.key.bytes, self.msg]).0,
        );

        // With `v = u*h (mod L)`, `[8](u*s*B - u*R - v*A) = u*[8](s*B - R - h*A)` because `[8]`
        // maps every point into the prime-order subgroup. Since `0 < |u| < L`, one side is the
        // identity exactly when the other is. The combination below is `sign(u)` times the left
        // side: it multiplies by `|u|`, negates `A` only when `u` is nonnegative, and splits
        // `|u|*s (mod L)` at bit 128 so that all four scalars are below `2^128`.
        let (u, v) = h.half_size();
        let a = self.key.point.to_extended();
        let a = if u < 0 { a } else { a.negate() };
        let u = Scalar::from_u128(u.unsigned_abs());
        let (low, high) = self.sig.s.mul_mod_l(&u).halves();
        let mut sum = straus(
            backend,
            [Scalar::from_u128(low), Scalar::from_u128(high)],
            [
                (self.sig.r.to_extended().negate(), u),
                (a, Scalar::from_u128(v)),
            ],
        );

        // Multiplying by the cofactor (8) maps the sum into the prime-order subgroup.
        for _ in 0..3 {
            sum = backend.to_projective(backend.double(sum));
        }
        backend.store_projective(sum).is_identity()
    }
}

struct VerifyBatchCall<'a, 'b, R, S> {
    rng: &'a mut R,
    items: &'a [Item<'b>],
    strategy: &'a S,
}

impl<R: CryptoRng, S: Strategy> WithBackend for VerifyBatchCall<'_, '_, R, S> {
    type Output = bool;

    fn call<B: Backend>(self, backend: B) -> Self::Output {
        verify_batch_inner(backend, self.rng, self.items, self.strategy)
    }
}

/// Verifies a batch of items using a randomized linear combination.
///
/// Empty input is rejected.
///
/// Signers are coalesced by their key encodings in [`group_ranges`], so a signer reused across
/// the batch contributes one `A` term.
pub(super) fn verify_batch(
    rng: &mut impl CryptoRng,
    items: &[Item<'_>],
    strategy: &impl Strategy,
) -> bool {
    with_backend(VerifyBatchCall {
        rng,
        items,
        strategy,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        curve::test_backend,
        signing::{PublicKeyBytes, SignatureBytes},
    };
    use arbitrary::Unstructured;
    use commonware_invariants::minifuzz::Builder;
    use commonware_parallel::{
        Rayon,
        mocks::{Explorer, explore},
        rayon::ThreadPoolBuilder,
    };
    use commonware_utils::{FuzzRng, NZUsize};
    use core::slice::from_ref;
    use ed25519_consensus::SigningKey as RefSigningKey;

    #[test]
    fn group_ranges_groups_adjacent_equal_keys() {
        let sorted = vec![
            ([1u8; 32], 4),
            ([1u8; 32], 0),
            ([2u8; 32], 3),
            ([3u8; 32], 1),
            ([3u8; 32], 2),
            ([3u8; 32], 5),
        ];
        assert_eq!(group_ranges(&sorted), vec![(0, 2), (2, 3), (3, 6)]);
    }

    #[test]
    fn group_ranges_handles_empty_and_no_duplicates() {
        assert!(group_ranges(&[]).is_empty());

        let sorted = vec![([1u8; 32], 0), ([2u8; 32], 1)];
        assert_eq!(group_ranges(&sorted), vec![(0, 1), (1, 2)]);
    }

    /// [`straus`] matches independent double-and-add over points with torsion components and
    /// scalars of every size.
    #[test]
    fn straus_matches_double_and_add() {
        // With every scalar zero, no digit is nonzero, which takes the early return.
        let basepoint = GAffine::BASEPOINT.to_extended();
        assert!(
            test_backend()
                .store_projective(straus(
                    test_backend(),
                    [Scalar::ZERO; 2],
                    [(basepoint, Scalar::ZERO)]
                ))
                .is_identity()
        );

        // Each variable point gains a low-order component, and the difference from
        // double-and-add must be exactly the identity, so the torsion part is checked too.
        let bases = [
            basepoint,
            basepoint.scalar_mul((0..=128).map(|bit| bit == 0)),
        ];
        Builder::default()
            .with_seed(0)
            .with_search_limit(64)
            .test(|u| {
                let base: [Scalar; 2] = u.arbitrary()?;
                let mut terms = [(G::IDENTITY, Scalar::ZERO); 4];
                for term in &mut terms {
                    let encoding: [u8; 32] = u.arbitrary()?;
                    let point = GAffine::decompress(&encoding).unwrap_or(GAffine::BASEPOINT);
                    let torsion = GAffine::decompress(u.choose(&crate::test::ZIP215_POINTS)?)
                        .unwrap()
                        .to_extended();
                    *term = (point.to_extended().add(torsion), u.arbitrary()?);
                }
                let expected = bases
                    .iter()
                    .zip(&base)
                    .chain(terms.iter().map(|(point, scalar)| (point, scalar)))
                    .fold(G::IDENTITY, |sum, (point, scalar)| {
                        sum.add(point.scalar_mul(scalar.bits_be()))
                    });
                assert!(
                    test_backend()
                        .store_projective(straus(test_backend(), base, terms))
                        .to_extended()
                        .add(expected.negate())
                        .is_identity()
                );
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

    /// [`decompress_many`] returns every point at its encoding's position under every strategy,
    /// and `None` exactly where an encoding is undecodable, whichever unit holds it.
    #[test]
    fn decompress_many_keeps_order() {
        // Encoding `i` is of the point `(i + 1)*B`.
        let base = GAffine::BASEPOINT.to_extended();
        let mut point = base;
        let encodings: Vec<[u8; 32]> = (0..18 * LANES + 3)
            .map(|_| {
                let encoding = point.compress();
                point = point.add(base);
                encoding
            })
            .collect();
        let invalid = undecodable();
        explore(|strategy| {
            // Empty input, whole units, and partial tails keep every point at its position.
            for count in [
                0,
                1,
                LANES,
                LANES + 1,
                2 * LANES,
                3 * LANES - 1,
                3 * LANES + 1,
                4 * LANES,
                18 * LANES + 3,
            ] {
                let points = decompress_many(count, |i| encodings[i], strategy);
                assert_eq!(points.len(), count, "count {count}");
                for (point, encoding) in points.iter().zip(&encodings) {
                    assert_eq!(point.unwrap().compress(), *encoding, "count {count}");
                }

                // An undecodable encoding in the first unit, the second unit, the middle, or the
                // last unit is `None` at its position alone.
                if count == 0 {
                    continue;
                }
                for bad in [0, LANES.min(count - 1), count / 2, count - 1] {
                    let mut encodings = encodings[..count].to_vec();
                    encodings[bad] = invalid;
                    let points = decompress_many(count, |i| encodings[i], strategy);
                    assert_eq!(points.len(), count, "count {count}, bad {bad}");
                    for (i, point) in points.iter().enumerate() {
                        assert_eq!(
                            point.is_none(),
                            i == bad,
                            "count {count}, bad {bad}, at {i}"
                        );
                    }
                }
            }
        });
    }

    type BatchItem = (PublicKey, Signature, Vec<u8>);

    /// Builds a key from an encoding of a curve point.
    fn public_key(bytes: [u8; 32]) -> PublicKey {
        PublicKey::try_from(PublicKeyBytes::new(bytes)).unwrap()
    }

    /// Builds a signature from a well-formed encoding.
    fn signature(bytes: [u8; 64]) -> Signature {
        Signature::try_from(SignatureBytes::new(bytes)).unwrap()
    }

    /// Returns `signature` with the lowest bit of `s` flipped. Only `s = L - 1` would become
    /// non-canonical.
    fn flip_s(signature: &Signature) -> Signature {
        let mut bytes = signature.bytes;
        bytes[32] ^= 1;
        self::signature(bytes)
    }

    /// Borrows `batch` as items whose messages are hashed as given.
    fn items(batch: &[BatchItem]) -> Vec<Item<'_>> {
        batch
            .iter()
            .map(|(key, signature, message)| Item {
                key,
                signature,
                namespace: None,
                message,
            })
            .collect()
    }

    /// A batch of both independent signers and a repeated signer (every position divisible by 3),
    /// spanning multiple signature-phase partitions. Keys and messages come from one drawn seed,
    /// so they stay distinct however short the fuzzer's input is.
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
                    public_key(signer.verification_key().to_bytes()),
                    signature(signer.sign(&message).to_bytes()),
                    message,
                )
            })
            .collect();

        // One repeated key plus one key per position not divisible by 3.
        let mut keys: Vec<_> = batch.iter().map(|(key, _, _)| key.bytes).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), 1 + n - n.div_ceil(3));
        Ok(batch)
    }

    /// 700 signatures from 467 signers make 1168 terms, past both the serial and the parallel
    /// Straus cutoffs, so the bucket method runs under the pool.
    #[test]
    fn verify_batch_accepts_valid_batch_under_real_parallelism() {
        let strategy =
            Explorer::parallel(&Rayon::new(ThreadPoolBuilder::new(NZUsize!(4))).unwrap());
        Builder::default()
            .with_seed(0)
            .with_search_limit(4)
            .test(|u| {
                let rng_seed: [u8; 32] = u.arbitrary()?;
                let batch = mixed_batch_with_repeats(u, 700)?;
                assert!(verify_batch(
                    &mut FuzzRng::new(rng_seed.to_vec()),
                    &items(&batch),
                    &strategy,
                ));
                Ok(())
            });
    }

    /// Batch verification's verdict is a deterministic function of `(items, seed)` (see
    /// [`batch_coefficients`]), so serial and parallel strategies must agree on every batch,
    /// including invalid ones, where the accept/reject outcome depends on the derived
    /// coefficients.
    #[test]
    fn verify_batch_agrees_across_strategies_on_invalid_batch() {
        Builder::default()
            .with_seed(0)
            .with_search_limit(4)
            .test(|u| {
                let rng_seed: [u8; 32] = u.arbitrary()?;
                let mut batch = mixed_batch_with_repeats(u, 300)?;
                batch[123].1 = flip_s(&batch[123].1);

                let items = items(&batch);
                assert!(!explore(|strategy| verify_batch(
                    &mut FuzzRng::new(rng_seed.to_vec()),
                    &items,
                    strategy,
                )));
                Ok(())
            });
    }

    /// Coefficients and phase outputs follow original signature indices under every strategy.
    #[test]
    fn signature_phase_preserves_indexed_coefficients() {
        fn check<B: Backend>(backend: B, strategy: &impl Strategy, batch: &[BatchItem]) {
            let seed = [7; 32];
            let width = msm::width_for(2 * batch.len() + 1, false);
            let items = items(batch);
            let partitions = signature_phase(&items, &seed, width, strategy);
            let zh: Vec<_> = partitions
                .iter()
                .flat_map(|partition| &partition.zh)
                .collect();

            // Recompute each signature's coefficient and scalars from its original index alone.
            // Its `z*h` must sit at the unit and lane that index selects, whatever the partitions.
            let mut expected_sum = Scalar::ZERO;
            let mut expected_terms = Vec::with_capacity(batch.len());
            for (i, item) in items.iter().enumerate() {
                let z = batch_coefficients(&seed, (i / 4) as u64)[i % 4];
                let h = Scalar::from_bytes_mod_order_wide(
                    &Sha512::hash(&[item.signature.r_bytes(), &item.key.bytes, item.message]).0,
                );
                assert_eq!(
                    zh[i / LANES][i % LANES].to_bytes(),
                    z.mul_mod_l(&h).to_bytes()
                );
                expected_sum = expected_sum.add_mod_l(&z.mul_mod_l(&item.signature.s));
                expected_terms.push(Term::new(item.signature.r, &z, width));
            }

            // The partitions' `z*s` shares add up to the batch's sum, and the `R` terms carry the
            // same coefficients.
            let actual_sum = partitions.iter().fold(Scalar::ZERO, |sum, partition| {
                sum.add_mod_l(&partition.zs_sum)
            });
            assert_eq!(actual_sum.to_bytes(), expected_sum.to_bytes());
            let chunks: Vec<_> = partitions
                .iter()
                .map(|partition| partition.terms.as_slice())
                .collect();
            assert_eq!(
                chunks.iter().map(|chunk| chunk.len()).sum::<usize>(),
                batch.len()
            );
            let actual = msm::multiscalar_mul(backend, &chunks, width, &Sequential);
            let expected = msm::multiscalar_mul(backend, &[&expected_terms], width, &Sequential);
            assert_eq!(actual.compress(), expected.compress());
        }

        struct Check;
        impl WithBackend for Check {
            type Output = ();

            fn call<B: Backend>(self, backend: B) {
                Builder::default()
                    .with_seed(0)
                    .with_search_limit(1)
                    .test(|u| {
                        let batch = mixed_batch_with_repeats(u, 70)?;

                        // Partial, exact, and several units, each in every execution shape.
                        for count in [1, LANES - 1, LANES, LANES + 1, 4 * LANES + 1, 70] {
                            explore(|strategy| check(backend, strategy, &batch[..count]));
                        }
                        Ok(())
                    });
            }
        }
        with_backend(Check);
    }

    /// Verifies `batch` with a fixed seed.
    fn verify_with(batch: &[BatchItem], strategy: &impl Strategy) -> bool {
        verify_batch(&mut FuzzRng::new(vec![7; 32]), &items(batch), strategy)
    }

    /// Single and batch verification hash the encodings a key and a signature carry and use the
    /// points they carry, without decompressing an encoding again. A signature whose challenge
    /// hashes an undecodable key encoding verifies under the key that pairs that encoding with
    /// the signer's point. A signature whose challenge hashes an undecodable `R` encoding
    /// verifies when it pairs that encoding with the nonce's point.
    #[test]
    fn verification_uses_decoded_points() {
        let secret = Scalar::from_u128(0x1111_2222_3333_4444);
        let point = G::mul_base_secret(&secret.to_bytes()).to_affine();
        let nonce = Scalar::from_u128(0x5555_6666_7777_8888);
        let r = G::mul_base_secret(&nonce.to_bytes()).to_affine();
        let message = b"decoded".to_vec();
        let sign = |key_bytes: [u8; 32], r_bytes: [u8; 32]| {
            let h = Scalar::from_bytes_mod_order_wide(
                &Sha512::hash(&[&r_bytes, &key_bytes, &message]).0,
            );
            let s = nonce.add_mod_l(&h.mul_mod_l(&secret));
            let mut bytes = [0u8; 64];
            bytes[..32].copy_from_slice(&r_bytes);
            bytes[32..].copy_from_slice(&s.to_bytes());
            let key = PublicKey {
                bytes: key_bytes,
                point,
            };
            (key, Signature { bytes, r, s }, message.clone())
        };
        for item in [
            sign(undecodable(), r.compress()),
            sign(point.compress(), undecodable()),
        ] {
            assert!(verify(&item.0, &item.1, &item.2));
            assert!(explore(|strategy| verify_with(from_ref(&item), strategy)));
        }
    }

    /// A signature under another key, with another `R`, with another `s`, or over another
    /// message rejects the batch wherever it sits, whether in the first or last lane of a unit, on
    /// either side of partition boundaries, or on the repeated signer or an independent one.
    #[test]
    fn verify_batch_rejects_invalid_signature_at_any_position() {
        let other_key = public_key(GAffine::BASEPOINT.compress());
        Builder::default()
            .with_seed(0)
            .with_search_limit(1)
            .test(|u| {
                let batch = mixed_batch_with_repeats(u, 70)?;
                explore(|strategy| {
                    // The intact batch verifies.
                    assert!(verify_with(&batch, strategy));

                    // Every corruption rejects at both sides of unit boundaries and in the tail.
                    for position in [0, 1, 7, 8, 15, 16, 23, 24, 39, 40, 63, 64, 69] {
                        for corruption in 0..4 {
                            let mut batch = batch.clone();
                            let (key, sig, msg) = &mut batch[position];
                            match corruption {
                                0 => *key = other_key.clone(),
                                1 => {
                                    let mut bytes = sig.bytes;
                                    bytes[..32].copy_from_slice(&IDENTITY_ENCODING);
                                    *sig = signature(bytes);
                                }
                                2 => *sig = flip_s(sig),
                                _ => msg[0] ^= 1,
                            }
                            assert!(
                                !verify_with(&batch, strategy),
                                "position {position}, corruption {corruption}"
                            );
                        }
                    }
                });
                Ok(())
            });
    }

    /// Batches dominated by repeated signers verify, and a signature over another message rejects
    /// them. With 1100 signatures the signer's scalars sum in parallel chunks.
    #[test]
    fn verify_batch_coalesces_repeated_signers() {
        const { assert!(1100 > SUM_CHUNK) };

        // Each batch verifies, and rejects once one of its signatures covers another message.
        let signers: Vec<RefSigningKey> = (1..=3u8).map(|i| RefSigningKey::from([i; 32])).collect();
        for (n, distinct) in [(520, 1), (1100, 1), (300, 3)] {
            let batch: Vec<BatchItem> = (0..n)
                .map(|i| {
                    let signer = &signers[i % distinct];
                    let message = (i as u64).to_le_bytes().to_vec();
                    (
                        public_key(signer.verification_key().to_bytes()),
                        signature(signer.sign(&message).to_bytes()),
                        message,
                    )
                })
                .collect();
            assert!(explore(|strategy| verify_with(&batch, strategy)), "n {n}");
            let mut batch = batch;
            batch[n / 2].2[0] ^= 1;
            assert!(!explore(|strategy| verify_with(&batch, strategy)), "n {n}");
        }
    }
}
