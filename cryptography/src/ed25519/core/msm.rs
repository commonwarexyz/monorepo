//! Variable-time multiscalar multiplication for batch verification.
//!
//! One Pippenger instance covers two columns that share a window grid:
//! full-width terms (the basepoint and coalesced verification keys) and
//! 128-bit terms (the per-signature randomizers), whose digits populate only
//! the low windows and so cost roughly half as much per term as routing them
//! through a generic 256-bit multiscalar multiplication.

use super::point::{self, Affine, CachedAffine, CachedExtended, Extended};
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec, vec::Vec};
use commonware_parallel::{Manual, Strategy};
use curve25519_dalek::{constants::ED25519_BASEPOINT_COMPRESSED, scalar::Scalar};
use once_cell::race::OnceBox;

/// The basepoint in this crate's representation, with its table of cached
/// odd multiples, built on first use.
pub(crate) fn basepoint() -> &'static (Affine, [CachedExtended; 8]) {
    static BASEPOINT: OnceBox<(Affine, [CachedExtended; 8])> = OnceBox::new();
    BASEPOINT.get_or_init(|| {
        let b =
            point::decompress(&ED25519_BASEPOINT_COMPRESSED.0).expect("the basepoint decompresses");
        Box::new((b, naf_table(&b)))
    })
}

/// Compute `[a]P + [b]Q` from cached odd-multiple tables, in variable time.
pub(crate) fn double_mul(
    a: &Scalar,
    p_table: &[CachedExtended; 8],
    b: &Scalar,
    q_table: &[CachedExtended; 8],
) -> Extended {
    let mut a_naf = [0i8; 254];
    naf5(&wide_limbs(a), &mut a_naf);
    let mut b_naf = [0i8; 254];
    naf5(&wide_limbs(b), &mut b_naf);
    let mut acc = Extended::IDENTITY;
    for i in (0..254).rev() {
        acc = acc.mul_by_pow_2(1);
        acc = add_naf_digit(acc, p_table, a_naf[i]);
        acc = add_naf_digit(acc, q_table, b_naf[i]);
    }
    acc
}

/// Number of signed radix-2^w digits needed for a `bits`-bit scalar: when the
/// top window spans a full w bits its carry needs one more window.
const fn window_count(bits: usize, w: u32) -> usize {
    let windows = bits.div_ceil(w as usize);
    let top_bits = bits - (windows - 1) * w as usize;
    if top_bits >= w as usize {
        windows + 1
    } else {
        windows
    }
}

/// Decompose the little-endian value in `limbs` (padded with at least one
/// trailing zero limb past its top window) into signed digits in
/// (-2^(w-1), 2^(w-1)], writing them to `out`. The digits satisfy
/// `value = sum(out[j] * 2^(j * w))`.
fn signed_digits(limbs: &[u64], w: u32, out: &mut [i16]) {
    let base = 1u64 << w;
    let half = base >> 1;
    let mask = base - 1;
    let mut carry = 0u64;
    for (j, digit) in out.iter_mut().enumerate() {
        let shift = j as u32 * w;
        let idx = (shift / 64) as usize;
        let bit = shift % 64;
        let buf = ((limbs[idx] as u128) | ((limbs[idx + 1] as u128) << 64)) >> bit;
        let raw = ((buf as u64) & mask) + carry;
        if raw > half {
            *digit = raw as i16 - base as i16;
            carry = 1;
        } else {
            *digit = raw as i16;
            carry = 0;
        }
    }
    debug_assert_eq!(carry, 0);
}

/// Little-endian limbs of a 128-bit randomizer, padded for [`signed_digits`].
const fn narrow_limbs(z: u128) -> [u64; 4] {
    [z as u64, (z >> 64) as u64, 0, 0]
}

/// Little-endian limbs of a full scalar, padded for [`signed_digits`].
fn wide_limbs(s: &Scalar) -> [u64; 5] {
    let b = s.to_bytes();
    let load = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
    [load(0), load(8), load(16), load(24), 0]
}

/// Sort each point into the bucket for its window-`j` digit (negating for
/// negative digits).
fn scan_column(
    buckets: &mut [Extended],
    cached: &[CachedAffine],
    digits: &[i16],
    windows: usize,
    j: usize,
) {
    for (i, point) in cached.iter().enumerate() {
        let d = digits[i * windows + j];
        match d.cmp(&0) {
            core::cmp::Ordering::Greater => {
                let b = (d - 1) as usize;
                buckets[b] = buckets[b].add_cached(point);
            }
            core::cmp::Ordering::Less => {
                let b = (-d - 1) as usize;
                buckets[b] = buckets[b].add_cached(&point.neg());
            }
            core::cmp::Ordering::Equal => {}
        }
    }
}

/// Fold buckets with the running-sum trick so bucket b contributes with
/// weight b + 1.
fn fold_buckets(buckets: &[Extended]) -> Extended {
    let mut running = Extended::IDENTITY;
    let mut sum = Extended::IDENTITY;
    for bucket in buckets.iter().rev() {
        running = running.add(bucket);
        sum = sum.add(&running);
    }
    sum
}

/// Combine per-window sums, most significant first, with w doublings between
/// windows.
fn combine_windows(sums: impl DoubleEndedIterator<Item = Extended>, w: u32) -> Extended {
    let mut acc = Extended::IDENTITY;
    for (i, sum) in sums.rev().enumerate() {
        if i != 0 {
            acc = acc.mul_by_pow_2(w);
        }
        acc = acc.add(&sum);
    }
    acc
}

/// Term counts up to this use Straus with per-point NAF tables (one shared
/// doubling chain, no bucket-fold overhead); larger counts use Pippenger
/// windows, whose per-term cost is lower once the buckets amortize. The
/// analogue of dalek's Straus/Pippenger switch at 190 points.
const STRAUS_LIMIT: usize = 350;

/// Window size for [`msm_global`] by total term count: bigger batches
/// amortize bigger buckets across their ~253-bit window columns.
const fn window_size_global(n: usize) -> u32 {
    match n {
        0..1500 => 7,
        1500..6000 => 9,
        6000..12000 => 10,
        12000..32000 => 11,
        32000..80000 => 12,
        _ => 13,
    }
}

/// Width-5 non-adjacent form of the little-endian value in `limbs` (padded
/// with at least one trailing zero limb past `out`): digits in
/// {0, +-1, +-3, ..., +-15} with at most one nonzero in any five consecutive
/// positions, satisfying `value = sum(out[i] * 2^i)`. `out` must extend one
/// position past the value's top bit for the final carry.
fn naf5(limbs: &[u64], out: &mut [i8]) {
    let mut pos = 0;
    let mut carry = 0u64;
    while pos < out.len() {
        let idx = pos / 64;
        let bit = (pos % 64) as u32;
        let buf = ((limbs[idx] as u128) | ((limbs[idx + 1] as u128) << 64)) >> bit;
        let window = carry + ((buf as u64) & 31);
        if window & 1 == 0 {
            pos += 1;
            continue;
        }
        if window < 16 {
            carry = 0;
            out[pos] = window as i8;
        } else {
            carry = 1;
            out[pos] = (window as i8).wrapping_sub(32);
        }
        pos += 5;
    }
    debug_assert_eq!(carry, 0);
}

/// Table of cached odd multiples P, 3P, ..., 15P.
pub(crate) fn naf_table(p: &Affine) -> [CachedExtended; 8] {
    let p1 = p.to_extended();
    let p2 = p1.mul_by_pow_2(1).to_cached();
    let mut cur = p1;
    core::array::from_fn(|i| {
        let entry = cur.to_cached();
        if i < 7 {
            cur = cur.add_cached_extended(&p2);
        }
        entry
    })
}

/// Add the NAF digit at position `i` to `acc` from `table`.
fn add_naf_digit(acc: Extended, table: &[CachedExtended; 8], d: i8) -> Extended {
    match d.cmp(&0) {
        core::cmp::Ordering::Greater => acc.add_cached_extended(&table[d as usize / 2]),
        core::cmp::Ordering::Less => {
            acc.add_cached_extended(&table[d.unsigned_abs() as usize / 2].neg())
        }
        core::cmp::Ordering::Equal => acc,
    }
}

/// Straus's method with width-5 NAF over both columns: per-point tables of
/// odd multiples share one doubling chain, so small batches skip the
/// bucket-fold overhead of the windowed path entirely.
fn straus(
    wide: &[(Scalar, Affine)],
    narrow_scalars: &[u128],
    narrow_points: &[Affine],
) -> Extended {
    let wide_entries: Vec<([i8; 254], [CachedExtended; 8])> = wide
        .iter()
        .map(|(s, p)| {
            let mut naf = [0i8; 254];
            naf5(&wide_limbs(s), &mut naf);
            (naf, naf_table(p))
        })
        .collect();
    let narrow_entries: Vec<([i8; 129], [CachedExtended; 8])> = narrow_scalars
        .iter()
        .zip(narrow_points)
        .map(|(z, p)| {
            let mut naf = [0i8; 129];
            naf5(&narrow_limbs(*z), &mut naf);
            (naf, naf_table(p))
        })
        .collect();

    let mut acc = Extended::IDENTITY;
    for i in (0..254).rev() {
        acc = acc.mul_by_pow_2(1);
        for (naf, table) in &wide_entries {
            acc = add_naf_digit(acc, table, naf[i]);
        }
        if i < 129 {
            for (naf, table) in &narrow_entries {
                acc = add_naf_digit(acc, table, naf[i]);
            }
        }
    }
    acc
}

/// Compute `sum(wide[i].0 * wide[i].1) + sum(narrow_scalars[i] *
/// narrow_points[i])` in variable time, with each Pippenger window bucketed
/// as an independent task under `manual`.
///
/// Full-width and 128-bit terms share one window grid, so the narrow terms
/// contribute buckets only to the low windows. Window tasks are uniform in
/// cost and small relative to the batch, letting faster cores absorb more of
/// them instead of a monolithic per-shard multiplication gating the wall
/// clock on the slowest core.
///
/// `narrow_scalars` and `narrow_points` must have equal lengths.
pub(crate) fn msm_global<S: Strategy>(
    manual: &Manual<S>,
    wide: &[(Scalar, Affine)],
    narrow_scalars: &[u128],
    narrow_points: &[Affine],
) -> Extended {
    assert_eq!(narrow_scalars.len(), narrow_points.len());
    let terms = wide.len() + narrow_scalars.len();
    if terms == 0 {
        return Extended::IDENTITY;
    }
    if terms <= STRAUS_LIMIT {
        return straus(wide, narrow_scalars, narrow_points);
    }
    let w = window_size_global(terms);
    // Scalars are reduced modulo the group order, which is under 2^253.
    let wide_windows = window_count(253, w);
    let narrow_windows = window_count(128, w);

    let mut wide_digits = vec![0i16; wide.len() * wide_windows];
    let mut wide_cached = Vec::with_capacity(wide.len());
    for (i, (s, p)) in wide.iter().enumerate() {
        signed_digits(
            &wide_limbs(s),
            w,
            &mut wide_digits[i * wide_windows..(i + 1) * wide_windows],
        );
        wide_cached.push(p.to_cached());
    }
    let mut narrow_digits = vec![0i16; narrow_scalars.len() * narrow_windows];
    let mut narrow_cached = Vec::with_capacity(narrow_points.len());
    for (i, (z, p)) in narrow_scalars.iter().zip(narrow_points).enumerate() {
        signed_digits(
            &narrow_limbs(*z),
            w,
            &mut narrow_digits[i * narrow_windows..(i + 1) * narrow_windows],
        );
        narrow_cached.push(p.to_cached());
    }

    let sums = manual.map_collect_vec(0..wide_windows, |j| {
        let mut buckets = vec![Extended::IDENTITY; 1 << (w - 1)];
        scan_column(&mut buckets, &wide_cached, &wide_digits, wide_windows, j);
        if j < narrow_windows {
            scan_column(
                &mut buckets,
                &narrow_cached,
                &narrow_digits,
                narrow_windows,
                j,
            );
        }
        fold_buckets(&buckets)
    });
    combine_windows(sums.into_iter(), w)
}

#[cfg(test)]
mod tests {
    use super::{super::point::decompress_batch, *};
    use commonware_utils::test_rng;
    use curve25519_dalek::{
        constants::EIGHT_TORSION, edwards::EdwardsPoint, scalar::Scalar,
        traits::VartimeMultiscalarMul,
    };
    use rand::RngExt as _;

    #[test]
    fn test_signed_digits_reconstruct() {
        let mut rng = test_rng();
        for w in 5u32..=12 {
            let windows = window_count(128, w);
            let mut out = vec![0i16; windows];
            let mut cases = vec![0u128, 1, u128::MAX, u128::MAX - 1, 1 << 127];
            for _ in 0..64 {
                cases.push(rng.random());
            }
            for z in cases {
                signed_digits(&narrow_limbs(z), w, &mut out);
                // Every digit lies in (-2^(w-1), 2^(w-1)].
                let half = 1i16 << (w - 1);
                assert!(out.iter().all(|d| *d > -half && *d <= half));
                // Reconstruct modulo 2^128 (a digit at shift >= 128 carries
                // weight 0 here, which is exact because z < 2^128 forces its
                // net contribution to be a multiple of 2^128, and the MSM
                // test covers exactness end to end against dalek).
                let mut acc = 0u128;
                for (j, d) in out.iter().enumerate() {
                    let shift = j as u32 * w;
                    if shift >= 128 {
                        assert!(*d == 0 || *d == 1);
                        continue;
                    }
                    acc = acc.wrapping_add((*d as i128 as u128) << shift);
                }
                assert_eq!(acc, z, "w={w} z={z}");
            }
        }
    }

    #[test]
    fn test_msm_global_matches_dalek() {
        let mut rng = test_rng();
        let strategies = (
            commonware_parallel::Sequential.manual(),
            commonware_parallel::Rayon::new(commonware_utils::NZUsize!(4))
                .unwrap()
                .manual(),
        );
        // Term counts crossing the global window-size thresholds.
        for (n_wide, n_narrow) in [(1, 0), (0, 1), (5, 3), (40, 40), (300, 300), (1100, 1100)] {
            let mut wide: Vec<(Scalar, EdwardsPoint)> = Vec::with_capacity(n_wide);
            let mut narrow: Vec<(u128, EdwardsPoint)> = Vec::with_capacity(n_narrow);
            for i in 0..n_wide + n_narrow {
                let mut sb = [0u8; 32];
                rng.fill(&mut sb);
                let p = if i == 2 || i == n_wide + 2 {
                    EIGHT_TORSION[3]
                } else {
                    EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order(sb))
                };
                let mut cb = [0u8; 32];
                rng.fill(&mut cb);
                if i < n_wide {
                    let s = if i == 0 {
                        Scalar::ZERO
                    } else {
                        Scalar::from_bytes_mod_order(cb)
                    };
                    wide.push((s, p));
                } else {
                    let z = if i == n_wide { u128::MAX } else { rng.random() };
                    narrow.push((z, p));
                }
            }
            let expected = EdwardsPoint::vartime_multiscalar_mul(
                wide.iter()
                    .map(|(s, _)| *s)
                    .chain(narrow.iter().map(|(z, _)| Scalar::from(*z))),
                wide.iter()
                    .map(|(_, p)| *p)
                    .chain(narrow.iter().map(|(_, p)| *p)),
            );
            let wide_encodings: Vec<[u8; 32]> = wide.iter().map(|(_, p)| p.compress().0).collect();
            let narrow_encodings: Vec<[u8; 32]> =
                narrow.iter().map(|(_, p)| p.compress().0).collect();
            let wide_own: Vec<(Scalar, super::Affine)> = wide
                .iter()
                .map(|(s, _)| *s)
                .zip(decompress_batch(wide_encodings.iter().copied()).unwrap())
                .collect();
            let narrow_scalars: Vec<u128> = narrow.iter().map(|(z, _)| *z).collect();
            let narrow_points = decompress_batch(narrow_encodings.iter().copied()).unwrap();
            for result in [
                msm_global(&strategies.0, &wide_own, &narrow_scalars, &narrow_points),
                msm_global(&strategies.1, &wide_own, &narrow_scalars, &narrow_points),
            ] {
                assert_eq!(
                    result.compress(),
                    expected.compress().0,
                    "wide={n_wide} narrow={n_narrow}"
                );
            }
        }
    }
}
