//! Signed, fixed-capacity integer polynomials and exact CRT lifting.

use super::{
    super::alloc::{vec, vec::Vec},
    mp31::{PRIMES, SmallPrime, mp_Rx31, mp_mmul},
    ntt::{mp_NTT, mp_iNTT, mp_mkgmigm, poly_max_bitlength},
    zint31::{
        zint_add_scaled_mul_small, zint_bezout, zint_mod_small_signed, zint_mul_small,
        zint_rebuild_CRT,
    },
};
use zeroize::Zeroizing;

const MASK: u32 = 0x7fff_ffff;

pub(super) struct Poly {
    pub(super) logn: u32,
    pub(super) limbs: usize,
    pub(super) words: Zeroizing<Vec<u32>>,
}

pub(super) struct Pair {
    pub(super) f: Poly,
    pub(super) g: Poly,
}

impl Poly {
    pub(super) fn zero(logn: u32, limbs: usize) -> Self {
        Self {
            logn,
            limbs,
            words: Zeroizing::new(vec![0; (1 << logn) * limbs]),
        }
    }

    pub(super) fn small(logn: u32, a: &[i8]) -> Self {
        let mut p = Self::zero(logn, 1);
        for (w, &x) in p.words.iter_mut().zip(a) {
            *w = (x as u32) & MASK;
        }
        p
    }

    pub(super) const fn n(&self) -> usize {
        1 << self.logn
    }

    pub(super) fn bits(&self) -> u32 {
        poly_max_bitlength(self.logn, &self.words, self.limbs)
    }

    pub(super) fn resized(&self, limbs: usize) -> Option<Self> {
        let n = self.n();
        let mut p = Self::zero(self.logn, limbs);
        let common = core::cmp::min(limbs, self.limbs);
        p.words[..common * n].copy_from_slice(&self.words[..common * n]);
        let mut bad = 0;
        for i in 0..n {
            let sign = (p.words[(common - 1) * n + i] >> 30).wrapping_neg() & MASK;
            for j in common..limbs {
                p.words[j * n + i] = sign;
            }
            for j in common..self.limbs {
                bad |= self.words[j * n + i] ^ sign;
            }
        }
        (bad == 0).then_some(p)
    }

    fn to_mod(&self, sp: &SmallPrime, a: &mut [u32]) {
        let rx = mp_Rx31(self.limbs as u32, sp.p, sp.p0i, sp.R2);
        for (i, x) in a.iter_mut().enumerate() {
            *x = zint_mod_small_signed(
                &self.words[i..],
                self.limbs,
                self.n(),
                sp.p,
                sp.p0i,
                sp.R2,
                rx,
            );
        }
    }

    // A secret shift selects words through a complete scan. Out-of-range
    // high words are sign extension; low words are zero.
    fn word(&self, i: usize, index: i32) -> u32 {
        let n = self.n();
        let sign = (self.words[(self.limbs - 1) * n + i] >> 30).wrapping_neg() & MASK;
        let mut w = sign & 0u32.wrapping_sub((index >= self.limbs as i32) as u32);
        for j in 0..self.limbs {
            w |= self.words[j * n + i] & 0u32.wrapping_sub((index == j as i32) as u32);
        }
        w
    }

    // Returns floor(x * 2^48 / 2^shift) * factor. The capacity check keeps
    // the extracted signed window inside i64 even at negative endpoints.
    pub(super) fn scaled(&self, shift: u32, factor: i128) -> Option<Zeroizing<Vec<i128>>> {
        let factor_bits = if factor == 36 { 6 } else { 0 };
        if self.bits() + factor_bits > shift + 12 {
            return None;
        }
        let base = ((shift + 14) / 31) as i32 - 2;
        let rem = (shift + 14) % 31;
        let mut a = Zeroizing::new(vec![0; self.n()]);
        for (i, x) in a.iter_mut().enumerate() {
            // The bound puts the raw value in [-2^60,2^60). Three limbs
            // leave at least 63 bits after shifting, so bit 62 is its sign.
            let w = (self.word(i, base) as u128)
                | ((self.word(i, base + 1) as u128) << 31)
                | ((self.word(i, base + 2) as u128) << 62);
            let signed = (((w >> rem) as u64) << 1) as i64 >> 1;
            *x = i128::from(signed).checked_mul(factor)?;
        }
        Some(a)
    }

    pub(super) fn small_values(&self) -> Option<Zeroizing<Vec<i64>>> {
        if self.bits() > 62 {
            return None;
        }
        let mut a = Zeroizing::new(vec![0; self.n()]);
        for (i, x) in a.iter_mut().enumerate() {
            let w = (self.word(i, 0) as u64)
                | ((self.word(i, 1) as u64) << 31)
                | ((self.word(i, 2) as u64) << 62);
            *x = w as i64;
        }
        Some(a)
    }

    // The caller allocates enough limbs for every partial sum in the
    // complete reduction schedule. No discarded carry is significant.
    pub(super) fn sub_scaled(&mut self, small: &Self, k: &[i32], scale: u32) {
        let n = self.n();
        let sch = scale / 31;
        let scl = scale % 31;
        for (i, &ki) in k.iter().enumerate() {
            for j in i..n {
                zint_add_scaled_mul_small(
                    &mut self.words[j..],
                    self.limbs,
                    &small.words[j - i..],
                    small.limbs,
                    n,
                    -ki,
                    sch,
                    scl,
                );
            }
            for j in 0..i {
                zint_add_scaled_mul_small(
                    &mut self.words[j..],
                    self.limbs,
                    &small.words[j + n - i..],
                    small.limbs,
                    n,
                    ki,
                    sch,
                    scl,
                );
            }
        }
    }
}

impl Pair {
    pub(super) fn small(logn: u32, f: &[i8], g: &[i8]) -> Self {
        Self {
            f: Poly::small(logn, f),
            g: Poly::small(logn, g),
        }
    }

    pub(super) fn resized(&self, limbs: usize) -> Option<Self> {
        Some(Self {
            f: self.f.resized(limbs)?,
            g: self.g.resized(limbs)?,
        })
    }
}

// All listed primes exceed 2^30. A strict |x| < 2^bound therefore has a
// unique centered representative with this many primes, including its sign.
pub(super) const fn prime_count(bound: u32) -> usize {
    (bound + 1).div_ceil(30) as usize
}
pub(super) const fn limb_count(bound: u32) -> usize {
    (bound + 1).div_ceil(31) as usize
}

const fn product(a: u32, b: u32, sp: &SmallPrime) -> u32 {
    mp_mmul(mp_mmul(a, b, sp.p, sp.p0i), sp.R2, sp.p, sp.p0i)
}

fn reconstruct(pair: &mut Pair) {
    let n = pair.f.n();
    let limbs = pair.f.limbs;
    let mut tmp = Zeroizing::new(vec![0; limbs]);
    zint_rebuild_CRT(&mut pair.f.words, limbs, n, 1, true, &mut tmp);
    zint_rebuild_CRT(&mut pair.g.words, limbs, n, 1, true, &mut tmp);
}

pub(super) fn descend(pair: &Pair, bound: u32) -> Pair {
    let logn = pair.f.logn;
    let n = pair.f.n();
    let hn = n / 2;
    let limbs = prime_count(bound);
    let mut out = Pair {
        f: Poly::zero(logn - 1, limbs),
        g: Poly::zero(logn - 1, limbs),
    };
    let mut a = Zeroizing::new(vec![0; n]);
    let mut b = Zeroizing::new(vec![0; n]);
    let mut gm = vec![0; n];
    let mut igm = vec![0; n];
    for (j, sp) in PRIMES[..limbs].iter().enumerate() {
        mp_mkgmigm(logn, sp.g, sp.ig, sp.p, sp.p0i, &mut gm, &mut igm);
        pair.f.to_mod(sp, &mut a);
        pair.g.to_mod(sp, &mut b);
        mp_NTT(logn, &mut a, &gm, sp.p, sp.p0i);
        mp_NTT(logn, &mut b, &gm, sp.p, sp.p0i);
        for i in 0..hn {
            a[i] = product(a[2 * i], a[2 * i + 1], sp);
            b[i] = product(b[2 * i], b[2 * i + 1], sp);
        }
        mp_iNTT(logn - 1, &mut a[..hn], &igm, sp.p, sp.p0i);
        mp_iNTT(logn - 1, &mut b[..hn], &igm, sp.p, sp.p0i);
        out.f.words[j * hn..(j + 1) * hn].copy_from_slice(&a[..hn]);
        out.g.words[j * hn..(j + 1) * hn].copy_from_slice(&b[..hn]);
    }
    reconstruct(&mut out);
    out
}

pub(super) fn solve_base(pair: &Pair, bound: u32) -> Option<Pair> {
    let len = pair.f.limbs;
    if pair.f.logn != 0
        || pair.f.words[0] & pair.g.words[0] & 1 == 0
        || (pair.f.words[len - 1] | pair.g.words[len - 1]) >> 30 != 0
    {
        return None;
    }
    let mut out = Pair {
        f: Poly::zero(0, len + 1),
        g: Poly::zero(0, len + 1),
    };
    let mut tmp = Zeroizing::new(vec![0; 4 * len]);
    if zint_bezout(
        &mut out.g.words[..len],
        &mut out.f.words[..len],
        &pair.f.words,
        &pair.g.words,
        &mut tmp,
    ) == 0
    {
        return None;
    }
    if zint_mul_small(&mut out.f.words, 12289) | zint_mul_small(&mut out.g.words, 12289) != 0 {
        return None;
    }
    if out.f.bits() > bound || out.g.bits() > bound {
        return None;
    }
    out.resized(limb_count(bound))
}

// In the paired evaluation order, adjacent roots differ by sign. Multiplying
// the embedded lower-degree solution by g(-X), respectively f(-X), lifts its
// determinant from the norm ring back to the current ring exactly.
pub(super) fn lift(pair: &Pair, big: &Pair, bound: u32) -> Pair {
    let logn = pair.f.logn;
    let n = pair.f.n();
    let hn = n / 2;
    let limbs = prime_count(bound);
    let mut out = Pair {
        f: Poly::zero(logn, limbs),
        g: Poly::zero(logn, limbs),
    };
    let mut a = Zeroizing::new(vec![0; n]);
    let mut b = Zeroizing::new(vec![0; n]);
    let mut af = Zeroizing::new(vec![0; hn]);
    let mut ag = Zeroizing::new(vec![0; hn]);
    let mut gm = vec![0; n];
    let mut igm = vec![0; n];
    for (j, sp) in PRIMES[..limbs].iter().enumerate() {
        mp_mkgmigm(logn, sp.g, sp.ig, sp.p, sp.p0i, &mut gm, &mut igm);
        pair.f.to_mod(sp, &mut a);
        pair.g.to_mod(sp, &mut b);
        big.f.to_mod(sp, &mut af);
        big.g.to_mod(sp, &mut ag);
        mp_NTT(logn, &mut a, &gm, sp.p, sp.p0i);
        mp_NTT(logn, &mut b, &gm, sp.p, sp.p0i);
        mp_NTT(logn - 1, &mut af, &gm, sp.p, sp.p0i);
        mp_NTT(logn - 1, &mut ag, &gm, sp.p, sp.p0i);
        for i in 0..hn {
            let a0 = a[2 * i];
            let b0 = b[2 * i];
            b[2 * i] = product(af[i], b[2 * i + 1], sp);
            b[2 * i + 1] = product(af[i], b0, sp);
            a[2 * i] = product(ag[i], a[2 * i + 1], sp);
            a[2 * i + 1] = product(ag[i], a0, sp);
        }
        mp_iNTT(logn, &mut a, &igm, sp.p, sp.p0i);
        mp_iNTT(logn, &mut b, &igm, sp.p, sp.p0i);
        out.f.words[j * n..(j + 1) * n].copy_from_slice(&b);
        out.g.words[j * n..(j + 1) * n].copy_from_slice(&a);
    }
    reconstruct(&mut out);
    out
}

#[cfg(test)]
#[path = "integer_tests.rs"]
mod tests;
