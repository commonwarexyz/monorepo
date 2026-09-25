//! Fast Walsh-Hadamard transform modulo `GF_MODULUS`, used by `eval_poly` and the Walsh tables.

use crate::reed_solomon::engine::{GF_ORDER, GfElement, utils};

/// Decimation in time (DIT) Fast Walsh-Hadamard Transform modulo `GF_MODULUS`.
///
/// Entries at and after `m_truncated` must be zero. The transform is unnormalized. Applying it
/// twice multiplies every entry by `data.len()` modulo `GF_MODULUS`.
///
/// # Panics
///
/// If `data.len()` is not a power of two no larger than `GF_ORDER`, or
/// `m_truncated > data.len()`.
#[inline(always)]
pub(crate) fn fwht(data: &mut [GfElement], m_truncated: usize) {
    assert!(data.len().is_power_of_two() && data.len() <= GF_ORDER);
    assert!(m_truncated <= data.len());

    // A radix-8 pass (`fwht_8`) is slightly faster on x86 (AMD Ryzen 5 3600) but slower on ARM
    // (Apple silicon M1). A radix-16 pass (`fwht_16`) is always slower. See branch
    // AndersTrier/FWHT_8_and_16.
    let mut dist = 1;
    let mut dist4 = 4;
    while dist4 <= data.len() {
        for r in (0..m_truncated).step_by(dist4) {
            for offset in r..r + dist {
                fwht_4(data, offset as u16, dist as u16);
            }
        }

        dist = dist4;
        dist4 <<= 2;
    }

    // An odd log2(data.len()) leaves one radix-2 layer at dist == data.len() / 2.
    if dist < data.len() {
        for r in (0..m_truncated).step_by(2 * dist) {
            for i in r..r + dist {
                let (sum, difference) = fwht_2(data[i], data[i + dist]);
                data[i] = sum;
                data[i + dist] = difference;
            }
        }
    }
}

/// Returns `(a + b, a - b)` modulo `GF_MODULUS`.
#[inline(always)]
fn fwht_2(a: GfElement, b: GfElement) -> (GfElement, GfElement) {
    let sum = utils::add_mod(a, b);
    let dif = utils::sub_mod(a, b);
    (sum, dif)
}

/// Applies the radix-2 layers at distances `dist` and `2 * dist` to the four entries
/// `data[offset + k * dist]` for `k` in `0..4`.
///
/// `offset + 3 * dist` must fit in a `u16`.
#[inline(always)]
fn fwht_4(data: &mut [GfElement], offset: u16, dist: u16) {
    // Indices. u16 arithmetic keeps each index below GF_ORDER (u16::MAX + 1), so bounds
    // checks can be elided when `data.len() == GF_ORDER`.
    let i0 = usize::from(offset);
    let i1 = usize::from(offset + dist);
    let i2 = usize::from(offset + dist * 2);
    let i3 = usize::from(offset + dist * 3);

    let (s0, d0) = fwht_2(data[i0], data[i1]);
    let (s1, d1) = fwht_2(data[i2], data[i3]);
    let (s2, d2) = fwht_2(s0, s1);
    let (s3, d3) = fwht_2(d0, d1);

    data[i0] = s2;
    data[i1] = s3;
    data[i2] = d2;
    data[i3] = d3;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;
    use rand::{RngExt as _, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    /// Reference radix-2 implementation of `fwht` over the whole slice.
    fn fwht_naive(data: &mut [GfElement]) {
        let mut dist = 1;
        let mut dist2 = 2;
        while dist2 <= data.len() {
            for r in (0..data.len()).step_by(dist2) {
                for offset in r..r + dist {
                    let (sum, dif) = fwht_2_naive(data[offset], data[offset + dist]);
                    data[offset] = sum;
                    data[offset + dist] = dif;
                }
            }

            dist = dist2;
            dist2 *= 2;
        }
    }

    /// Reference `fwht_2` built on wrapping `u16` arithmetic.
    fn fwht_2_naive(a: GfElement, b: GfElement) -> (GfElement, GfElement) {
        let (mut sum, sum_overflow) = a.overflowing_add(b);
        if sum_overflow {
            // `overflowing_add` reduced `sum` mod 65536. Adding one reduces it mod `GF_MODULUS`
            // (65535) instead.
            sum += 1;
        }

        let (mut dif, dif_overflow) = a.overflowing_sub(b);
        if dif_overflow {
            dif -= 1;
        }

        (sum, dif)
    }

    #[test]
    fn test_full() {
        let mut rng = ChaCha8Rng::from_seed([0; 32]);

        let mut data1 = [(); GF_ORDER].map(|_| rng.random());
        let mut data2 = data1;

        fwht(&mut data1, GF_ORDER);
        fwht_naive(&mut data2);

        assert_eq!(data1, data2);
    }

    #[test]
    fn test_truncated() {
        let mut rng = ChaCha8Rng::from_seed([0; 32]);
        let random: Vec<GfElement> = (0..GF_ORDER).map(|_| rng.random()).collect();

        for nonzero_count in [
            0,
            1,
            2,
            3,
            4,
            64,
            127,
            16384 - 1,
            16384 + 1,
            GF_ORDER / 2 - 1,
            GF_ORDER / 2,
            GF_ORDER / 2 + 1,
            GF_ORDER - 4,
            GF_ORDER - 3,
            GF_ORDER - 2,
            GF_ORDER - 1,
            GF_ORDER,
        ] {
            let mut data1 = [0; GF_ORDER];

            data1[..nonzero_count].copy_from_slice(&random[..nonzero_count]);
            let mut data2 = data1;

            fwht(&mut data1, nonzero_count);
            fwht_naive(&mut data2);

            assert_eq!(data1, data2);
        }
    }

    #[test]
    fn test_short_odd_and_even_lengths() {
        let mut rng = ChaCha8Rng::from_seed([7; 32]);
        for n in [1, 2, 4, 8, 16, 512, 1024] {
            for nonzero in [0, 1, n / 2, n] {
                let mut actual = (0..n)
                    .map(|_| rng.random::<GfElement>())
                    .collect::<Vec<_>>();
                actual[nonzero..].fill(0);
                let mut expected = actual.clone();
                fwht(&mut actual, nonzero);
                fwht_naive(&mut expected);
                assert_eq!(actual, expected, "n={n} nonzero={nonzero}");
            }
        }
    }
}
