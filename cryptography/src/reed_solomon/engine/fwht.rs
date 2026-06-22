use crate::reed_solomon::engine::{utils, GfElement, GF_ORDER};

// ======================================================================
// FWHT (fast Walsh-Hadamard transform) - CRATE

/// Decimation in time (DIT) Fast Walsh-Hadamard Transform.
/// `m_truncated`: Number of non-zero elements in `data` (at the front).
#[inline(always)]
pub(crate) fn fwht(data: &mut [GfElement; GF_ORDER], m_truncated: usize) {
    // Note to self: fwht_8 is slightly faster on x86 (AMD Ryzen 5 3600),
    // but slower on ARM (Apple silicon M1).
    // fwht_16 is always slower. See branch: AndersTrier/FWHT_8_and_16
    let mut dist = 1;
    let mut dist4 = 4;
    while dist4 <= GF_ORDER {
        for r in (0..m_truncated).step_by(dist4) {
            for offset in r..r + dist {
                fwht_4(data, offset as u16, dist as u16);
            }
        }

        dist = dist4;
        dist4 <<= 2;
    }
}

// ======================================================================
// FWHT - PRIVATE

#[inline(always)]
fn fwht_2(a: GfElement, b: GfElement) -> (GfElement, GfElement) {
    let sum = utils::add_mod(a, b);
    let dif = utils::sub_mod(a, b);
    (sum, dif)
}

#[inline(always)]
fn fwht_4(data: &mut [GfElement; GF_ORDER], offset: u16, dist: u16) {
    // Indices. u16 additions and multiplication to avoid bounds checks
    // on array access. (GF_ORDER == (u16::MAX+1))
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

// ======================================================================
// FWHT - TESTS

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    // Reference implementation
    fn fwht_naive(data: &mut [GfElement; GF_ORDER]) {
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

    fn fwht_2_naive(a: GfElement, b: GfElement) -> (GfElement, GfElement) {
        let (mut sum, sum_overflow) = a.overflowing_add(b);
        if sum_overflow {
            // `sum` got reduced mod 65536, but we want to
            // reduce it mod GF_MODULUS (65535) instead.
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

        let mut data1 = [(); GF_ORDER].map(|_| rng.gen());
        let mut data2 = data1;

        fwht(&mut data1, GF_ORDER);
        fwht_naive(&mut data2);

        assert_eq!(data1, data2);
    }

    #[test]
    fn test_truncated() {
        let mut rng = ChaCha8Rng::from_seed([0; 32]);
        let random: Vec<GfElement> = (0..GF_ORDER).map(|_| rng.gen()).collect();

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
}
