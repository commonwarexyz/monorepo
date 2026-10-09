//! Ed25519 verification internals.

mod msm;
mod scalar;

use crate::curve::{
    Backend, G, GAffine, LANES, ODD_MULTIPLES, ODD_MULTIPLES_NAF_WIDTH, WithBackend, with_backend,
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use commonware_codec::Write as _;
use commonware_cryptography::{Hasher as _, Sha512, sha512::Digest};
use commonware_parallel::{Sequential, Strategy};
use core::num::NonZeroUsize;
use msm::Term;
use rand_core::CryptoRng;
pub(super) use scalar::Scalar;

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

/// One signature's batch-verification inputs, borrowed from the caller.
#[derive(Clone, Copy)]
pub(super) struct Item<'a> {
    pub(super) key: &'a VerifyingKeyBytes,
    pub(super) r: &'a [u8; 32],
    pub(super) s: &'a [u8; 32],
    pub(super) namespace: Option<&'a [u8]>,
    pub(super) message: &'a [u8],
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

// A `signature_phase` unit holds one signature per decompression lane. Units cover whole
// `batch_coefficients` blocks of four, so the lane count must be a multiple of 4.
const _: () = assert!(LANES.is_multiple_of(4));

/// One [`signature_phase`] partition's output: each unit's `R` terms and its signatures' `z*h`
/// (their shares of their signers' coalesced `A` scalars), and the partition's share of
/// `sum(z*s) mod L`.
struct Partition {
    terms: Vec<[Term; LANES]>,
    zh: Vec<[Scalar; LANES]>,
    zs_sum: Scalar,
}

/// The encoding of the identity point, which pads the final unit of a decompression batch.
const IDENTITY_ENCODING: [u8; 32] = {
    let mut encoding = [0; 32];
    encoding[0] = 1;
    encoding
};

/// Decompresses one unit of point encodings and appends it to `terms` as terms of scalar zero.
///
/// Returns whether every encoding decompressed.
fn decompress_terms<B: Backend>(
    backend: B,
    encodings: &[[u8; 32]; LANES],
    terms: &mut Vec<[Term; LANES]>,
) -> bool {
    // An undecodable lane still gets a term, the identity, so every unit stays `LANES` wide and
    // the failure travels in the returned flag.
    let mut valid = true;
    terms.push(GAffine::decompress_batch(backend, encodings).map(|point| {
        point.map_or_else(
            || {
                valid = false;
                Term::zero(GAffine::IDENTITY)
            },
            Term::zero,
        )
    }));
    valid
}

/// Hashes the challenges `R || A || M` of unit `unit`, with `M` the framed message.
///
/// The unit's curve work cannot split, but long messages make its hashing worth spreading across
/// workers. [`Sha512::hash_many_with`] splits the challenges across `strategy` only between whole
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
        challenges.extend_from_slice(item.r);
        challenges.extend_from_slice(item.key.as_bytes());
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
    Sha512::hash_many_with(&inputs[..lanes.len()], strategy)
}

/// Processes unit `unit` into `partition`, recoding its `R` terms at `width`. `digests` holds
/// the unit's challenge hashes (see [`hash_unit`]), and its `R` encodings decompress in one
/// backend batch. Lanes past the last item hold identity terms.
///
/// Returns whether every signature in the unit has a canonical `s` and a decodable `R`.
fn signature_unit<B: Backend>(
    backend: B,
    items: &[Item<'_>],
    seed: &[u8; 32],
    width: u32,
    unit: usize,
    digests: &[Digest],
    partition: &mut Partition,
) -> bool {
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
        *coefficients = batch_coefficients(seed, (start / 4 + block) as u64);
    }

    // Lanes past the last item keep the identity encoding for decompression.
    let mut encodings = [IDENTITY_ENCODING; LANES];
    for (encoding, item) in encodings.iter_mut().zip(lanes) {
        *encoding = *item.r;
    }

    // `z*h` is the signature's share of its signer's coalesced `A` scalar, and `z*s` accumulates
    // into the partition's share of `sum(z*s)`. A non-canonical `s` fails the batch, leaving its
    // lane's `z*h` zero, and the remaining lanes still finish.
    let mut valid = true;
    let mut zh = [Scalar::ZERO; LANES];
    for (j, item) in lanes.iter().enumerate() {
        let Some(s) = Scalar::from_canonical_bytes(item.s) else {
            valid = false;
            continue;
        };
        let h = Scalar::from_bytes_mod_order_wide(&digests[j].0);
        zh[j] = z[j].mul_mod_l(&h);
        partition.zs_sum = partition.zs_sum.add_mod_l(&z[j].mul_mod_l(&s));
    }
    partition.zh.push(zh);

    // Decompress the unit's `R` encodings in one backend batch, then give each item's term its
    // `z`. An undecodable `R` fails the batch. Padding lanes keep identity terms of scalar zero.
    let offset = partition.terms.len();
    valid &= decompress_terms(backend, &encodings, &mut partition.terms);
    for (term, coefficient) in partition.terms[offset].iter_mut().zip(&z[..lanes.len()]) {
        term.recode(coefficient, width);
    }
    valid
}

/// The per-signature phase, parallel over [`LANES`]-signature units in batch order: for each
/// signature, derives `z` (see [`batch_coefficients`]), rejects a non-canonical `s`, computes the
/// challenge `h = H(R || A || M)` and the scalars `z*h` and `z*s`, and decompresses `R` into a
/// term recoded at `width`. Returns `None` if any `s` is non-canonical or any `R` fails to
/// decompress.
///
/// A strategy batch may hold a single unit. Where the SHA-512 kernel hashes fewer than [`LANES`]
/// messages at once, a unit can spread its hashing further (see [`hash_unit`]), so a batch of a few
/// long messages can still use more workers than it has units.
///
/// The phase needs no `A` point and no grouping, so it runs while [`verify_pipeline`] sorts the
/// keys.
fn signature_phase<B: Backend>(
    backend: B,
    items: &[Item<'_>],
    seed: &[u8; 32],
    width: u32,
    strategy: &impl Strategy,
) -> Option<Vec<Partition>> {
    strategy.run_batches(
        items.len().div_ceil(LANES),
        NonZeroUsize::MIN,
        LANES,
        |batches| {
            // Every batch finishes all of its units even after a failure, and the phase returns
            // `None` if any unit failed.
            batches
                .map_collect_vec(
                    |ranges| ranges,
                    |range| {
                        // A batch is a contiguous range of units, and its partition holds one
                        // `terms` entry and one `zh` block per unit, in unit order. Partitions
                        // return in batch order, so their flattened blocks are indexed by unit.
                        let mut partition = Partition {
                            terms: Vec::with_capacity(range.len()),
                            zh: Vec::with_capacity(range.len()),
                            zs_sum: Scalar::ZERO,
                        };
                        let mut challenges = Vec::new();
                        let mut valid = true;
                        for unit in range {
                            let digests = hash_unit(items, unit, &mut challenges, strategy);
                            valid &= signature_unit(
                                backend,
                                items,
                                seed,
                                width,
                                unit,
                                &digests,
                                &mut partition,
                            );
                        }
                        valid.then_some(partition)
                    },
                )
                .into_iter()
                .collect()
        },
    )
}

/// The decompression phase: turns a flat worklist of `count` point encodings, resolved by index
/// via `encoding`, into terms of scalar zero, in one parallel pass over [`LANES`]-sized units.
/// Each partition decompresses its units into one exactly sized term vector. The final unit is
/// padded with identity terms.
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
    // Unit `u` holds worklist entries from `u * LANES`, and entries past `count` pad the final
    // unit with the identity encoding.
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
    strategy.run_batches(count.div_ceil(LANES), NonZeroUsize::MIN, LANES, |batches| {
        // Each batch decompresses its contiguous range of units into its own vector, finishing
        // every unit even after a failure. The vectors return in batch order, so together they
        // follow the worklist, and the phase returns `None` if any encoding failed.
        batches
            .map_collect_vec(
                |ranges| ranges,
                |range| {
                    let mut terms = Vec::with_capacity(range.len());
                    let mut valid = true;
                    for index in range {
                        valid &= decompress_terms(backend, &unit(index), &mut terms);
                    }
                    valid.then_some(terms)
                },
            )
            .into_iter()
            .collect()
    })
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

    // A structurally invalid batch stops before its MSM, so only pipelines that reach the batch
    // equation inform the strategy's choice between the two shapes.
    strategy
        .try_run(
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
        .unwrap_or(false)
}

/// The batch-verification pipeline: a short sequence of data-parallel phases over flat arrays,
/// with `A` coalescing falling out of a sort.
///
/// 1. Two concurrent tasks. [`signature_phase`] derives coefficients, hashes, computes the
///    per-signature scalars, and decompresses every `R` into a term with its `z`. Meanwhile
///    a sort by key and [`group_ranges`] place every signer's signatures adjacent in sorted
///    order and group them, and [`decompress_phase`] decompresses every distinct `A`.
/// 2. Every `A` term is recoded with its coalesced scalar, the sum of its signatures' `z*h`.
/// 3. One MSM over the terms, with the coalesced basepoint term `sum(z*s)*(-B)` riding along as
///    one final term, then the cofactored identity check.
///
/// Returns `Err` if any `s` is non-canonical or any `R` or `A` fails to decompress, which
/// stops the pipeline before the MSM, and otherwise whether the batch equation holds.
///
/// Step 1 finishes every unit of both tasks even after a failure. Signatures that are well
/// formed but wrong already reach the MSM, so stopping step 1 early would not bound the work an
/// adversary can cause.
fn verify_pipeline<B: Backend>(
    backend: B,
    items: &[Item<'_>],
    seed: &[u8; 32],
    width: u32,
    strategy: &impl Strategy,
) -> Result<bool, ()> {
    let (signatures, (order, groups, a_terms)) = strategy.join(
        || signature_phase(backend, items, seed, width, strategy),
        || {
            // Each key carries its signature's original index, which leads from a signer's run
            // in `order` back to its signatures' `z*h`.
            let mut order: Vec<(VerifyingKeyBytes, u32)> = items
                .iter()
                .enumerate()
                .map(|(i, item)| (*item.key, i as u32))
                .collect();

            // The signature phase occupies the pool meanwhile, so sort on this thread.
            order.sort_unstable_by_key(|&(key, _)| key);
            let groups = group_ranges(&order);

            // Each signer's `A` decompresses once, from the key at the start of its run.
            let encoding = |i: usize| *order[groups[i].0 as usize].0.as_bytes();
            let a_terms = decompress_phase(backend, groups.len(), encoding, strategy);
            (order, groups, a_terms)
        },
    );

    // Both tasks have finished every unit, and a non-canonical `s` or an undecodable `R` or `A`
    // rejects the batch before the MSM.
    let (Some(signatures), Some(mut a_terms)) = (signatures, a_terms) else {
        return Err(());
    };

    // A signer's coalesced scalar: the sum of `z*h` over its run of `order`. Partitions hold
    // consecutive units in batch order, so an original index selects its unit's block and lane.
    let blocks: Vec<&[Scalar; LANES]> = signatures
        .iter()
        .flat_map(|partition| &partition.zh)
        .collect();
    let sum = |run: &[(VerifyingKeyBytes, u32)]| {
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

    // The partition count stops growing at the strategy's parallelism, so each partition is
    // weighted by its average share of the summed signatures and recoded groups, which keeps the
    // strategy's estimates for different batch sizes apart.
    let work_per_partition = (order.len() + groups.len()).div_ceil(a_work.len());
    strategy.map_collect_vec_with_multiplier(a_work, work_per_partition, |(terms, first)| {
        // Unit `k` of a vector holds groups from `first + k * LANES`. Padding lanes in the final
        // unit have no group and keep scalar zero.
        for (terms, groups) in terms.iter_mut().zip(groups[first..].chunks(LANES)) {
            // Summing a unit's groups before recoding any of them overlaps the scattered loads of
            // their summands.
            let mut scalars = [Scalar::ZERO; LANES];
            for (scalar, &group) in scalars.iter_mut().zip(groups) {
                *scalar = group_scalar(group);
            }
            for (term, scalar) in terms.iter_mut().zip(&scalars[..groups.len()]) {
                term.recode(scalar, width);
            }
        }
    });

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
        .map(|chunk| chunk.as_flattened())
        .collect();
    chunks.push(basepoint.as_slice());
    let result = msm::multiscalar_mul(backend, &chunks, width, strategy);
    Ok(result.mul_by_cofactor().is_identity())
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
///
/// `a_point`, when present, must be the point `a_bytes` encodes.
pub fn verify(
    a_bytes: &VerifyingKeyBytes,
    a_point: Option<&G>,
    sig: &Signature,
    msg: &[u8],
) -> bool {
    with_backend(Verify {
        a_bytes,
        a_point,
        sig,
        msg,
    })
}

/// The inputs of [`verify`], checked with the selected backend's single-point operations.
/// Without a cached point, the backend also decompresses the signature's `R` together with `A`.
struct Verify<'a> {
    a_bytes: &'a VerifyingKeyBytes,
    a_point: Option<&'a G>,
    sig: &'a Signature,
    msg: &'a [u8],
}

impl WithBackend for Verify<'_> {
    type Output = bool;

    // Inlined so the algorithm compiles inside the backend's target-feature entry, where its
    // point operations can inline.
    #[inline(always)]
    fn call<B: Backend>(self, backend: B) -> bool {
        let Some(s) = Scalar::from_canonical_bytes(&self.sig.s) else {
            return false;
        };
        let points = self.a_point.map_or_else(
            || {
                backend
                    .decompress_pair([&self.sig.r, self.a_bytes.as_bytes()])
                    .map(|[r, a]| (r, a.to_extended()))
            },
            |point| GAffine::decompress(&self.sig.r).map(|r| (r, *point)),
        );
        let Some((r, a)) = points else {
            return false;
        };
        let h = Scalar::from_bytes_mod_order_wide(
            &Sha512::hash(&[&self.sig.r, self.a_bytes.as_bytes(), self.msg]).0,
        );

        // With `v = u*h (mod L)`, `[8](u*s*B - u*R - v*A) = u*[8](s*B - R - h*A)` because `[8]`
        // maps every point into the prime-order subgroup. Since `0 < |u| < L`, one side is the
        // identity exactly when the other is. The combination below is `sign(u)` times the left
        // side: it multiplies by `|u|`, negates `A` only when `u` is nonnegative, and splits
        // `|u|*s (mod L)` at bit 128 so that all four scalars are below `2^128`.
        let (u, v) = h.half_size();
        let a = if u < 0 { a } else { a.negate() };
        let u = Scalar::from_u128(u.unsigned_abs());
        let (low, high) = s.mul_mod_l(&u).halves();
        let mut sum = straus(
            backend,
            [Scalar::from_u128(low), Scalar::from_u128(high)],
            [(r.to_extended().negate(), u), (a, Scalar::from_u128(v))],
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
/// `A` is coalesced by its raw encoding before ever being decompressed (see [`group_ranges`]), so
/// a signer reused across the batch is decompressed once, not once per signature.
pub(super) fn verify_batch_bytes(
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
        signing::{SigningKey, VerifyingKey},
        test::strategy::Recording,
    };
    use arbitrary::Unstructured;
    use commonware_codec::{Copying, DecodeExt};
    use commonware_cryptography::{BatchEntry, BatchVerifier as _};
    use commonware_invariants::minifuzz::Builder;
    use commonware_parallel::Sequential;
    use commonware_utils::FuzzRng;
    use ed25519_consensus::SigningKey as RefSigningKey;

    #[test]
    fn structural_rejection_does_not_record_complete_work() {
        // A valid signature, copies with a non-canonical `s` (top bit set) and an undecodable
        // `R`, and a key with an undecodable encoding.
        let signer = SigningKey::from_seed(&[7; 32]);
        let key = signer.verifying_key();
        let valid = signer.sign(b"resource", b"control");
        let mut bad_s = valid.clone();
        bad_s.bytes[63] |= 0x80;
        let mut bad_r = valid.clone();
        bad_r.bytes[..32].copy_from_slice(&undecodable());
        let bad_key =
            crate::signing::VerifyingKey::decode(Copying(undecodable().as_slice())).unwrap();

        // The last sample comes from the batch's outer `try_run`, which counts complete work only
        // when the pipeline reaches the batch equation. A signature over another message reaches
        // it and fails there.
        for parallel in [false, true] {
            for (key, signature, message, valid, complete) in [
                (&key, &valid, b"control".as_slice(), true, true),
                (&key, &bad_s, b"control".as_slice(), false, false),
                (&key, &bad_r, b"control".as_slice(), false, false),
                (&bad_key, &valid, b"control".as_slice(), false, false),
                (&key, &valid, b"different".as_slice(), false, true),
            ] {
                let strategy = Recording::new(parallel);
                let verified = VerifyingKey::verify_batch(
                    &mut commonware_utils::test_rng(),
                    &[()],
                    |_, _| BatchEntry {
                        namespace: b"resource",
                        message,
                        public_key: key,
                        signature,
                    },
                    &strategy,
                );
                assert_eq!(verified, valid);
                assert_eq!(strategy.samples.lock().last(), Some(&complete));
            }
        }
    }

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

    /// [`decompress_phase`] returns the terms in worklist order under every strategy. Every entry
    /// must become one term carrying its own point, and an undecodable encoding in any position
    /// must reject the worklist.
    #[test]
    fn decompress_phase_keeps_worklist_order() {
        fn check<B: Backend>(backend: B, strategy: &impl Strategy) {
            // Entry `i` encodes `(i + 1)*B`.
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

            // Whole units and partial tails must preserve the original worklist indices.
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
                let width = msm::width_for(count, false);
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
                assert_eq!(actual.compress(), expected.compress(), "count {count}");

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

    /// Borrows `batch` as items whose messages are hashed as given.
    fn items(batch: &[BatchItem]) -> Vec<Item<'_>> {
        batch
            .iter()
            .map(|(key, sig, message)| Item {
                key,
                r: &sig.r,
                s: &sig.s,
                namespace: None,
                message,
            })
            .collect()
    }

    /// A batch of both independent signers and a repeated signer (every position divisible by 3),
    /// spanning multiple signature-phase and decompression partitions. Keys and messages come
    /// from one drawn seed, so they stay distinct however short the fuzzer's input is.
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

        // One repeated key plus one key per position not divisible by 3.
        let mut keys: Vec<_> = batch.iter().map(|(key, _, _)| *key).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), 1 + n - n.div_ceil(3));
        Ok(batch)
    }

    /// 700 signatures from 467 signers make 1168 terms, past both the serial and the parallel
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
                assert!(verify_batch_bytes(
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

                let items = items(&batch);
                let serial =
                    verify_batch_bytes(&mut FuzzRng::new(rng_seed.to_vec()), &items, &Sequential);
                let parallel =
                    verify_batch_bytes(&mut FuzzRng::new(rng_seed.to_vec()), &items, &strategy);

                assert!(!serial);
                assert_eq!(serial, parallel);
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
            let partitions = signature_phase(backend, &items, &seed, width, strategy).unwrap();
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
                    &Sha512::hash(&[item.r, item.key.as_bytes(), item.message]).0,
                );
                assert_eq!(
                    zh[i / LANES][i % LANES].to_bytes(),
                    z.mul_mod_l(&h).to_bytes()
                );
                let s = Scalar::from_canonical_bytes(item.s).unwrap();
                expected_sum = expected_sum.add_mod_l(&z.mul_mod_l(&s));
                expected_terms.push(Term::new(GAffine::decompress(item.r).unwrap(), &z, width));
            }

            // The partitions' `z*s` shares add up to the batch's sum, and the `R` terms carry the
            // same coefficients. Padding lanes hold identity terms, which add nothing to the MSM.
            let actual_sum = partitions.iter().fold(Scalar::ZERO, |sum, partition| {
                sum.add_mod_l(&partition.zs_sum)
            });
            assert_eq!(actual_sum.to_bytes(), expected_sum.to_bytes());
            let chunks: Vec<_> = partitions
                .iter()
                .map(|partition| partition.terms.as_flattened())
                .collect();
            let actual = msm::multiscalar_mul(backend, &chunks, width, &Sequential);
            let expected = msm::multiscalar_mul(backend, &[&expected_terms], width, &Sequential);
            assert_eq!(actual.compress(), expected.compress());
        }

        struct Check;
        impl WithBackend for Check {
            type Output = ();

            fn call<B: Backend>(self, backend: B) {
                let parallel = commonware_parallel::Rayon::new(commonware_utils::NZUsize!(4))
                    .unwrap()
                    .manual();
                let adaptive =
                    commonware_parallel::Rayon::new(commonware_utils::NZUsize!(4)).unwrap();
                Builder::default()
                    .with_seed(0)
                    .with_search_limit(1)
                    .test(|u| {
                        let batch = mixed_batch_with_repeats(u, 70)?;

                        // Partial, exact, and several units, each under a serial, a forced
                        // parallel, and an adaptive strategy.
                        for count in [1, LANES - 1, LANES, LANES + 1, 4 * LANES + 1, 70] {
                            check(backend, &Sequential, &batch[..count]);
                            check(backend, &parallel, &batch[..count]);
                            check(backend, &adaptive, &batch[..count]);
                        }
                        Ok(())
                    });
            }
        }
        with_backend(Check);
    }

    /// Verifies `batch` with a fixed seed.
    fn verify_with(batch: &[BatchItem], strategy: &impl Strategy) -> bool {
        verify_batch_bytes(&mut FuzzRng::new(vec![7; 32]), &items(batch), strategy)
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

    /// Manual pools of two and four threads force parallel execution for [`verdict`].
    fn pools() -> [impl Strategy; 2] {
        [2, 4].map(|threads| {
            commonware_parallel::Rayon::new(core::num::NonZeroUsize::new(threads).unwrap())
                .unwrap()
                .manual()
        })
    }

    /// An undecodable `R` or `A`, a non-canonical `s`, or a signature over another message
    /// rejects the batch wherever it sits: in the first or last lane of a unit, on either side of
    /// partition boundaries, and on the repeated signer or an independent one.
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

                // Every corruption rejects at both sides of unit boundaries and in the tail.
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
        let basepoint = GAffine::BASEPOINT.to_extended().compress();
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
            Scalar::from_bytes_mod_order_wide(&Sha512::hash(&[r, key, &message]).0)
        };
        let bad_r = item(invalid, basepoint, challenge(&invalid, &basepoint));
        let good_r = item(identity, basepoint, challenge(&identity, &basepoint));

        // With `R = k*B` and `s = k`, the equation holds for `A` the identity.
        let k = Scalar::from_u128(0x1234_5678_9abc_def0);
        let r = G::mul_base_secret(&k.to_bytes()).compress();
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
                    // In place of one signature of a valid batch, the control keeps the batch
                    // valid, so the forgery can fail only on its undecodable point. Alone, the
                    // pair must behave the same.
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
    /// them. With 1100 signatures the signer's scalars sum in parallel chunks.
    #[test]
    fn verify_batch_bytes_coalesces_repeated_signers() {
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
