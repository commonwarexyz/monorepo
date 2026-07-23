//! Multi-scalar multiplication (MSM): computing `sum(points[i] * scalars[i])` for many
//! `(point, scalar)` pairs at once.
//!
//! Batch signature verification needs exactly one such sum, over roughly `2n` points for a batch
//! of `n` signatures (see [`super::verify_batch`]). Computing each term independently and adding
//! the results costs `O(n * 256)` point additions (one addition per scalar bit, per term).
//! Pippenger's bucket method below instead processes the terms window by window: within each
//! window it buckets every term by its digit in a single pass, then folds the buckets together,
//! so the `256/WIDTH` windows share the cost of the additions across all `n` terms. This is
//! variable-time, which is fine since verification only ever operates on public data.
//!
//! There are two implementations of the same algorithm here:
//!
//! - [`scalar::multiscalar_mul`]: the classic, non-vectorized version, operating on
//!   [`EdwardsPoint`] directly.
//! - [`transposed::multiscalar_mul`]: the same algorithm reorganized so its window doublings and
//!   bucket reductions run as vectorized [`super::point::PointVec`] operations across [`LANES`]
//!   independent sub-MSMs instead of scalar [`EdwardsPoint`] ones (the design notes' "transposed
//!   Pippenger").
//!
//! [`multiscalar_mul`] picks whichever is actually faster on the running CPU
//! ([`crate::field_vec::simd_available`]): packing/unpacking `PointVec` lanes costs the same
//! either way, so the transposed version is strictly *more* work than the scalar one unless the
//! packed arithmetic is genuinely hardware-accelerated (see [`crate::field_vec`]'s docs). Without
//! real SIMD it is pure overhead; with it, the packed multiplies it feeds through
//! [`super::point::PointVec::add`] run 8-wide instead of one at a time.

use super::{point::EdwardsPoint, scalar::Scalar};
use crate::field_vec::{self, LANES};
use commonware_parallel::Strategy;

/// Window width in bits. Widening it shrinks the number of windows (fewer point doublings) at
/// the cost of a larger bucket array (`2^(WIDTH-1)` points) to fold every window; this value is a
/// starting point, not yet tuned against real hardware.
const WIDTH: u32 = 6;

/// `256` scalar bits divided into `WIDTH`-bit windows, rounding up to cover the top window, plus
/// one: recoding into *signed* digits (see [`Scalar::signed_digits`]) can carry a final `+1` past
/// the naive window count, and this spare window is where it lands.
const NUM_WINDOWS: usize = 256usize.div_ceil(WIDTH as usize) + 1;

/// One bucket per nonzero digit *magnitude*: a signed digit only ever needs a bucket for
/// `abs(digit)`, which ranges `1..=2^(WIDTH-1)` -- half as many buckets as the `1..2^WIDTH` an
/// unsigned digit would need (see [`Scalar::signed_digits`]).
const NUM_BUCKETS: usize = 1usize << (WIDTH - 1);

mod scalar {
    use super::{EdwardsPoint, NUM_BUCKETS, NUM_WINDOWS, Scalar, WIDTH};

    /// Computes `sum(points[i] * scalars[i])` via Pippenger's bucket method, using signed
    /// digit recoding (see [`Scalar::signed_digits`]) to halve the bucket count at the cost of a
    /// point negation (cheap; see [`EdwardsPoint::negate`]) for negative digits.
    ///
    /// `points` and `scalars` must have equal length.
    pub(super) fn multiscalar_mul(points: &[EdwardsPoint], scalars: &[Scalar]) -> EdwardsPoint {
        debug_assert_eq!(points.len(), scalars.len());

        let digits: Vec<[i32; NUM_WINDOWS]> =
            scalars.iter().map(|s| s.signed_digits(WIDTH)).collect();

        let mut result = EdwardsPoint::IDENTITY;
        for window in (0..NUM_WINDOWS).rev() {
            for _ in 0..WIDTH {
                result = result.double();
            }

            // Bucket every term by its digit's magnitude in this window, negating the point for
            // negative digits: `buckets[m - 1]` accumulates the sum of every (possibly negated)
            // point whose digit has magnitude `m`, for `m` in `1..=NUM_BUCKETS`.
            let mut buckets = [EdwardsPoint::IDENTITY; NUM_BUCKETS];
            for (point, digit_row) in points.iter().zip(&digits) {
                let digit = digit_row[window];
                if digit > 0 {
                    let i = digit as usize - 1;
                    buckets[i] = buckets[i].add(point);
                } else if digit < 0 {
                    let i = digit.unsigned_abs() as usize - 1;
                    buckets[i] = buckets[i].add(&point.negate());
                }
            }

            // Fold `sum(m * buckets[m - 1])` via a running sum, from the highest magnitude down:
            // adding each bucket into `sum` and then `sum` into `window_sum` accumulates every
            // bucket once for every magnitude at or below its own, which is exactly its weight
            // `m`.
            let mut sum = EdwardsPoint::IDENTITY;
            let mut window_sum = EdwardsPoint::IDENTITY;
            for bucket in buckets.iter().rev() {
                sum = sum.add(bucket);
                window_sum = window_sum.add(&sum);
            }
            result = result.add(&window_sum);
        }
        result
    }
}

mod transposed {
    use super::{EdwardsPoint, LANES, NUM_BUCKETS, NUM_WINDOWS, Scalar, WIDTH};
    use crate::signing::point::PointVec;

    /// Computes `sum(points[i] * scalars[i])` via a lane-transposed Pippenger bucket method: the
    /// `n` terms are split into [`LANES`] contiguous, equal-length (zero-padded) groups, each
    /// running its own independent Pippenger MSM over its own group, all in lockstep across the
    /// `LANES` [`PointVec`] lanes -- so every window's doublings and every window's bucket
    /// reduction run as one vectorized [`PointVec::add`] instead of `LANES` scalar
    /// [`EdwardsPoint::add`] calls. Summing the `LANES` lanes' partial results at the very end is
    /// valid because MSM is linear in its terms.
    ///
    /// `points` and `scalars` must have equal length and must not be empty.
    pub(super) fn multiscalar_mul(points: &[EdwardsPoint], scalars: &[Scalar]) -> EdwardsPoint {
        debug_assert_eq!(points.len(), scalars.len());
        debug_assert!(!points.is_empty());

        // Every lane's group is padded to the same length with (IDENTITY, all-zero-digits) filler
        // pairs: an all-zero digit row never lands in a bucket and contributes nothing, letting
        // every lane run the exact same number of loop iterations. Scalars are recoded into
        // signed digits (see `Scalar::signed_digits`) up front rather than per window, since a
        // window's digit here needs to be looked up `NUM_WINDOWS` times (once per window) and
        // recoding is a one-time, whole-scalar computation.
        let group_len = points.len().div_ceil(LANES);
        let mut groups: [Vec<(EdwardsPoint, [i32; NUM_WINDOWS])>; LANES] =
            core::array::from_fn(|_| Vec::with_capacity(group_len));
        for (group, (point_chunk, scalar_chunk)) in groups
            .iter_mut()
            .zip(points.chunks(group_len).zip(scalars.chunks(group_len)))
        {
            group.extend(
                point_chunk
                    .iter()
                    .copied()
                    .zip(scalar_chunk.iter().map(|s| s.signed_digits(WIDTH))),
            );
        }
        for group in &mut groups {
            group.resize(group_len, (EdwardsPoint::IDENTITY, [0i32; NUM_WINDOWS]));
        }

        let mut result = PointVec::identity();
        let mut buckets = [[EdwardsPoint::IDENTITY; NUM_BUCKETS]; LANES];
        for window in (0..NUM_WINDOWS).rev() {
            for _ in 0..WIDTH {
                result = result.double();
            }

            buckets.fill([EdwardsPoint::IDENTITY; NUM_BUCKETS]);

            // Bucket every term by its digit's magnitude in this window, one wave of `LANES`
            // terms (one per lane) at a time: gather each lane's current bucket value (a scalar
            // array read, cheap and branch-free since a digit of 0 just gathers-and-discards the
            // identity), add the wave's incoming (possibly negated, for a negative digit) points
            // via one vectorized `PointVec::add`, then scatter the results back (again cheap
            // scalar writes, skipped only for zero-digit lanes since there is no bucket to write
            // into).
            #[allow(clippy::needless_range_loop)]
            for k in 0..group_len {
                let mut incoming = [EdwardsPoint::IDENTITY; LANES];
                let mut current = [EdwardsPoint::IDENTITY; LANES];
                let mut bucket_index = [None::<usize>; LANES];
                for lane in 0..LANES {
                    let (point, digit_row) = &groups[lane][k];
                    let digit = digit_row[window];
                    if digit > 0 {
                        bucket_index[lane] = Some(digit as usize - 1);
                        incoming[lane] = *point;
                    } else if digit < 0 {
                        bucket_index[lane] = Some(digit.unsigned_abs() as usize - 1);
                        incoming[lane] = point.negate();
                    }
                    if let Some(i) = bucket_index[lane] {
                        current[lane] = buckets[lane][i];
                    }
                }
                let updated = PointVec::from_lanes(&current)
                    .add(&PointVec::from_lanes(&incoming))
                    .to_lanes();
                for lane in 0..LANES {
                    if let Some(i) = bucket_index[lane] {
                        buckets[lane][i] = updated[lane];
                    }
                }
            }

            // Fold `sum(m * buckets[m - 1])` via a running sum, from the highest magnitude down,
            // for all `LANES` lanes' bucket arrays at once (see `scalar::multiscalar_mul` for the
            // non-transposed version of this same running-sum trick).
            let mut sum = PointVec::identity();
            let mut window_sum = PointVec::identity();
            for d in (0..NUM_BUCKETS).rev() {
                let bucket_group: [EdwardsPoint; LANES] =
                    core::array::from_fn(|lane| buckets[lane][d]);
                sum = sum.add(&PointVec::from_lanes(&bucket_group));
                window_sum = window_sum.add(&sum);
            }
            result = result.add(&window_sum);
        }

        result
            .to_lanes()
            .into_iter()
            .fold(EdwardsPoint::IDENTITY, |acc, partial| acc.add(&partial))
    }
}

/// Computes `sum(points[i] * scalars[i])`, dispatching to whichever of [`scalar`]'s or
/// [`transposed`]'s implementation is actually faster on the running CPU (see the module docs).
///
/// `points` and `scalars` must have equal length.
pub(crate) fn multiscalar_mul(points: &[EdwardsPoint], scalars: &[Scalar]) -> EdwardsPoint {
    if !points.is_empty() && field_vec::simd_available() {
        transposed::multiscalar_mul(points, scalars)
    } else {
        scalar::multiscalar_mul(points, scalars)
    }
}

/// Points/scalars per chunk before parallelizing across cores. MSM is linear in its terms, so
/// splitting the pairs into independent chunks, running [`multiscalar_mul`] on each chunk
/// separately, and summing the partial results computes exactly the same thing as running it on
/// the whole input at once. `256` matches this crate's target per-core batch size (see the design
/// notes).
const PARALLEL_CHUNK_SIZE: usize = 256;

/// Parallel counterpart to [`multiscalar_mul`]: splits `points`/`scalars` into chunks, computes
/// each chunk's partial sum via `strategy`, and adds the partial sums together.
///
/// `points` and `scalars` must have equal length.
pub(crate) fn multiscalar_mul_parallel(
    points: &[EdwardsPoint],
    scalars: &[Scalar],
    strategy: &impl Strategy,
) -> EdwardsPoint {
    debug_assert_eq!(points.len(), scalars.len());

    let chunks = points
        .chunks(PARALLEL_CHUNK_SIZE)
        .zip(scalars.chunks(PARALLEL_CHUNK_SIZE));
    strategy
        .map_collect_vec(chunks, |(p, s)| multiscalar_mul(p, s))
        .into_iter()
        .fold(EdwardsPoint::IDENTITY, |acc, partial| acc.add(&partial))
}

/// Decompresses one chunk of raw point encodings and immediately runs [`multiscalar_mul`] on the
/// resulting points, all within the same unit of work -- unlike decompressing a whole batch into
/// a shared `Vec<EdwardsPoint>` first and only starting the MSM afterward, this never hands a
/// decompressed point off from the thread that produced it to a different thread (or a separate
/// parallel barrier) that consumes it. `extra`, when present, is folded in as one more point/scalar
/// pair for *this* chunk's `multiscalar_mul` call, so its cost is shared with this chunk's window
/// doublings instead of paid for as a standalone scalar multiplication (see
/// [`multiscalar_mul_from_bytes_parallel`]'s use of it for the batch equation's coalesced
/// basepoint term).
///
/// Returns `None` if any point in `bytes` fails to decompress.
fn decompress_and_msm_chunk(
    bytes: &[[u8; 32]],
    scalars: &[Scalar],
    extra: Option<(EdwardsPoint, Scalar)>,
) -> Option<EdwardsPoint> {
    debug_assert_eq!(bytes.len(), scalars.len());
    let mut points = Vec::with_capacity(bytes.len() + 1);
    for chunk in bytes.chunks(LANES) {
        if let Ok(chunk) = <[[u8; 32]; LANES]>::try_from(chunk) {
            for point in EdwardsPoint::decompress_batch(&chunk) {
                points.push(point?);
            }
        } else {
            for b in chunk {
                points.push(EdwardsPoint::decompress(b)?);
            }
        }
    }

    let mut scalars = scalars.to_vec();
    if let Some((point, scalar)) = extra {
        points.push(point);
        scalars.push(scalar);
    }
    Some(multiscalar_mul(&points, &scalars))
}

/// Parallel counterpart to [`decompress_and_msm_chunk`]: every `(bytes, scalars)` pair in
/// `sources` is split into [`PARALLEL_CHUNK_SIZE`] chunks, every source's chunks are flattened
/// into one combined list (so e.g. a deduplicated `A`'s chunks and `R`'s chunks interleave across
/// the thread pool instead of running as two separate parallel barriers), and the partial sums are
/// added together. `extra` rides along with whichever chunk ends up first in the combined list
/// (guaranteed to exist -- a synthetic empty chunk is inserted if every source is empty -- so it
/// is never silently dropped).
///
/// Every `(bytes, scalars)` pair in `sources` must have equal-length `bytes`/`scalars`. Returns
/// `None` if any point across every source fails to decompress.
pub(crate) fn multiscalar_mul_from_bytes_parallel(
    sources: &[(&[[u8; 32]], &[Scalar])],
    extra: Option<(EdwardsPoint, Scalar)>,
    strategy: &impl Strategy,
) -> Option<EdwardsPoint> {
    let mut chunks: Vec<(&[[u8; 32]], &[Scalar])> = Vec::new();
    for &(bytes, scalars) in sources {
        debug_assert_eq!(bytes.len(), scalars.len());
        chunks.extend(
            bytes
                .chunks(PARALLEL_CHUNK_SIZE)
                .zip(scalars.chunks(PARALLEL_CHUNK_SIZE)),
        );
    }
    if chunks.is_empty() && extra.is_some() {
        chunks.push((&[], &[]));
    }

    let partials = strategy.map_collect_vec(chunks.into_iter().enumerate(), |(i, (b, s))| {
        decompress_and_msm_chunk(b, s, if i == 0 { extra } else { None })
    });

    partials
        .into_iter()
        .try_fold(EdwardsPoint::IDENTITY, |acc, partial| {
            Some(acc.add(&partial?))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::scalar::test_support::rand_scalar;
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;
    use ed25519_consensus::SigningKey;
    use rand_core::Rng;

    /// A 32-byte encoding with no corresponding curve point (`y = 2`, for which `x^2 = u/v` has no
    /// square root -- see the module's differential tests below).
    const INVALID_POINT_BYTES: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0] = 2;
        b
    };

    /// Returns `n` distinct valid 32-byte point encodings, using `ed25519-consensus` verification
    /// keys as a source of arbitrary valid points (this crate has no point *compression* yet, only
    /// decompression, so real signature-scheme keys are the easiest way to get valid encodings).
    fn valid_point_bytes(n: usize) -> Vec<[u8; 32]> {
        let mut rng = test_rng();
        (0..n)
            .map(|_| {
                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed);
                SigningKey::from(seed).verification_key().to_bytes()
            })
            .collect()
    }

    #[test]
    fn decompress_and_msm_chunk_matches_decompress_then_multiscalar_mul() {
        let mut rng = test_rng();
        for n in [0, 1, 2, 5, 8, 9, 32] {
            let bytes = valid_point_bytes(n);
            let scalars: Vec<Scalar> = (0..n).map(|_| rand_scalar(&mut rng)).collect();
            let extra_point = EdwardsPoint::basepoint().scalar_mul(&rand_scalar(&mut rng));
            let extra_scalar = rand_scalar(&mut rng);

            for extra in [None, Some((extra_point, extra_scalar))] {
                let mut points: Vec<EdwardsPoint> = bytes
                    .iter()
                    .map(|b| EdwardsPoint::decompress(b).unwrap())
                    .collect();
                let mut expected_scalars = scalars.clone();
                if let Some((p, s)) = extra {
                    points.push(p);
                    expected_scalars.push(s);
                }
                let expected = multiscalar_mul(&points, &expected_scalars);

                let actual = decompress_and_msm_chunk(&bytes, &scalars, extra).unwrap();
                assert!(actual.add(&expected.negate()).is_identity());
            }
        }
    }

    #[test]
    fn decompress_and_msm_chunk_rejects_invalid_point() {
        let bytes = [INVALID_POINT_BYTES];
        let scalars = [Scalar::from_u128(1)];
        assert!(decompress_and_msm_chunk(&bytes, &scalars, None).is_none());
    }

    #[test]
    fn multiscalar_mul_from_bytes_parallel_matches_decompress_then_parallel() {
        let mut rng = test_rng();
        for sizes in [
            vec![0usize, 0],
            vec![1, 0],
            vec![0, 5],
            vec![3, 4],
            vec![300, 5],
            vec![256, 256, 1],
        ] {
            let sources_bytes: Vec<Vec<[u8; 32]>> =
                sizes.iter().map(|&n| valid_point_bytes(n)).collect();
            let sources_scalars: Vec<Vec<Scalar>> = sizes
                .iter()
                .map(|&n| (0..n).map(|_| rand_scalar(&mut rng)).collect())
                .collect();
            let extra_point = EdwardsPoint::basepoint().scalar_mul(&rand_scalar(&mut rng));
            let extra_scalar = rand_scalar(&mut rng);

            for extra in [None, Some((extra_point, extra_scalar))] {
                let mut expected_points: Vec<EdwardsPoint> = sources_bytes
                    .iter()
                    .flatten()
                    .map(|b| EdwardsPoint::decompress(b).unwrap())
                    .collect();
                let mut expected_scalars: Vec<Scalar> =
                    sources_scalars.iter().flatten().copied().collect();
                if let Some((p, s)) = extra {
                    expected_points.push(p);
                    expected_scalars.push(s);
                }
                let expected =
                    multiscalar_mul_parallel(&expected_points, &expected_scalars, &Sequential);

                let sources: Vec<(&[[u8; 32]], &[Scalar])> = sources_bytes
                    .iter()
                    .zip(&sources_scalars)
                    .map(|(b, s)| (b.as_slice(), s.as_slice()))
                    .collect();
                let actual =
                    multiscalar_mul_from_bytes_parallel(&sources, extra, &Sequential).unwrap();
                assert!(actual.add(&expected.negate()).is_identity());
            }
        }
    }

    #[test]
    fn multiscalar_mul_from_bytes_parallel_matches_under_real_parallelism() {
        // `Manual` disables the adaptive serial/parallel policy, forcing every call through actual
        // Rayon dispatch (rather than the policy falling back to serial for small inputs) -- this
        // is the only test in the module that exercises genuine concurrent execution, since every
        // other test uses `Sequential`.
        let strategy = commonware_parallel::Rayon::new(commonware_utils::NZUsize!(4))
            .unwrap()
            .manual();

        let mut rng = test_rng();
        let a_bytes = valid_point_bytes(600);
        let a_scalars: Vec<Scalar> = (0..600).map(|_| rand_scalar(&mut rng)).collect();
        let r_bytes = valid_point_bytes(500);
        let r_scalars: Vec<Scalar> = (0..500).map(|_| rand_scalar(&mut rng)).collect();
        let extra = (
            EdwardsPoint::basepoint().scalar_mul(&rand_scalar(&mut rng)),
            rand_scalar(&mut rng),
        );

        let mut expected_points: Vec<EdwardsPoint> = a_bytes
            .iter()
            .chain(&r_bytes)
            .map(|b| EdwardsPoint::decompress(b).unwrap())
            .collect();
        let mut expected_scalars: Vec<Scalar> =
            a_scalars.iter().chain(&r_scalars).copied().collect();
        expected_points.push(extra.0);
        expected_scalars.push(extra.1);
        let expected = multiscalar_mul_parallel(&expected_points, &expected_scalars, &Sequential);

        let sources: Vec<(&[[u8; 32]], &[Scalar])> =
            vec![(&a_bytes, &a_scalars), (&r_bytes, &r_scalars)];
        let actual = multiscalar_mul_from_bytes_parallel(&sources, Some(extra), &strategy).unwrap();
        assert!(actual.add(&expected.negate()).is_identity());
    }

    #[test]
    fn multiscalar_mul_from_bytes_parallel_rejects_invalid_point() {
        let bytes = vec![INVALID_POINT_BYTES];
        let scalars = vec![Scalar::from_u128(1)];
        let sources: Vec<(&[[u8; 32]], &[Scalar])> = vec![(&bytes, &scalars)];
        assert!(multiscalar_mul_from_bytes_parallel(&sources, None, &Sequential).is_none());
    }

    #[test]
    fn matches_naive_double_and_add() {
        let mut rng = test_rng();
        for n in [0, 1, 2, 5, 8, 9, 32, 64, 100] {
            let points: Vec<EdwardsPoint> = (0..n)
                .map(|_| EdwardsPoint::basepoint().scalar_mul(&rand_scalar(&mut rng)))
                .collect();
            let scalars: Vec<Scalar> = (0..n).map(|_| rand_scalar(&mut rng)).collect();

            let expected = points
                .iter()
                .zip(&scalars)
                .fold(EdwardsPoint::IDENTITY, |acc, (p, s)| {
                    acc.add(&p.scalar_mul(s))
                });
            let actual = multiscalar_mul(&points, &scalars);
            assert!(actual.add(&expected.negate()).is_identity());
        }
    }

    #[test]
    fn transposed_matches_scalar() {
        let mut rng = test_rng();
        for n in [1, 2, 5, 8, 9, 32, 64, 100] {
            let points: Vec<EdwardsPoint> = (0..n)
                .map(|_| EdwardsPoint::basepoint().scalar_mul(&rand_scalar(&mut rng)))
                .collect();
            let scalars: Vec<Scalar> = (0..n).map(|_| rand_scalar(&mut rng)).collect();

            let expected = scalar::multiscalar_mul(&points, &scalars);
            let actual = transposed::multiscalar_mul(&points, &scalars);
            assert!(actual.add(&expected.negate()).is_identity());
        }
    }

    #[test]
    fn parallel_matches_serial() {
        let mut rng = test_rng();
        for n in [0, 1, 2, 5, 32, 600] {
            let points: Vec<EdwardsPoint> = (0..n)
                .map(|_| EdwardsPoint::basepoint().scalar_mul(&rand_scalar(&mut rng)))
                .collect();
            let scalars: Vec<Scalar> = (0..n).map(|_| rand_scalar(&mut rng)).collect();

            let expected = multiscalar_mul(&points, &scalars);
            let actual = multiscalar_mul_parallel(&points, &scalars, &Sequential);
            assert!(actual.add(&expected.negate()).is_identity());
        }
    }
}
