//! Checked Q48 approximation with an exact certificate for final rounding.

use super::{
    super::alloc::{vec, vec::Vec},
    integer::Pair,
    roots::ROOTS,
};
use zeroize::Zeroizing;

pub(super) const ONE: i128 = 1 << 48;
pub(super) const K_LIMIT: i32 = 1 << 20;

fn mul(a: i128, b: i128) -> Option<i128> {
    Some(a.checked_mul(b)? >> 48)
}

fn complex_mul(ar: i128, ai: i128, br: i128, bi: i128) -> Option<(i128, i128)> {
    Some((
        mul(ar, br)?.checked_sub(mul(ai, bi)?)?,
        mul(ar, bi)?.checked_add(mul(ai, br)?)?,
    ))
}

// Restoring division has a fixed schedule. The divisor fits 127 bits, so
// shifting a remainder smaller than it cannot overflow its u128 storage.
pub(super) fn div_rem(n: u128, d: u128) -> Option<(u128, u128)> {
    if d == 0 || d >> 127 != 0 {
        return None;
    }
    let mut q = 0;
    let mut r = 0;
    for i in (0..128).rev() {
        r = (r << 1) | ((n >> i) & 1);
        let take = (r >= d) as u128;
        r = r.wrapping_sub(d & 0u128.wrapping_sub(take));
        q |= take << i;
    }
    Some((q, r))
}

fn div(a: i128, b: i128) -> Option<i128> {
    if b <= 0 {
        return None;
    }
    let a = a.checked_mul(ONE)?;
    let (q, _) = div_rem(a.unsigned_abs(), b as u128)?;
    let q = i128::try_from(q).ok()?;
    let sign = a >> 127;
    (q ^ sign).checked_sub(sign)
}

pub(super) fn round(x: i128) -> Option<i32> {
    let q = x >> 48;
    let r = x & (ONE - 1);
    let q = q.checked_add(((r > ONE / 2) | ((r == ONE / 2) & (q & 1 != 0))) as i128)?;
    if q < -i128::from(K_LIMIT) || q > i128::from(K_LIMIT) {
        return None;
    }
    Some(q as i32)
}

// The split-complex, negacyclic FFT ordering follows fn-dsa-kgen 0.4.0
// vect.rs (Unlicense). Every arithmetic operation is checked, including
// the products before their Q48 rescaling.
pub(super) fn fft(logn: u32, a: &mut [i128], inverse: bool) -> Option<()> {
    let hn = 1usize << (logn - 1);
    if inverse {
        let mut ht = 1;
        for lm in (1..logn).rev() {
            let m = 1usize << lm;
            let t = ht << 1;
            for i in 0..m / 2 {
                let (sr, si) = ROOTS[m + i];
                let j0 = i * t;
                for j in j0..j0 + ht {
                    let xr = a[j];
                    let xi = a[j + hn];
                    let yr = a[j + ht];
                    let yi = a[j + ht + hn];
                    a[j] = xr.checked_add(yr)? >> 1;
                    a[j + hn] = xi.checked_add(yi)? >> 1;
                    let (re, im) = complex_mul(
                        xr.checked_sub(yr)? >> 1,
                        xi.checked_sub(yi)? >> 1,
                        i128::from(sr),
                        -i128::from(si),
                    )?;
                    a[j + ht] = re;
                    a[j + ht + hn] = im;
                }
            }
            ht = t;
        }
    } else {
        let mut t = hn;
        for lm in 1..logn {
            let m = 1usize << lm;
            let ht = t >> 1;
            for i in 0..m / 2 {
                let (sr, si) = ROOTS[m + i];
                let j0 = i * t;
                for j in j0..j0 + ht {
                    let xr = a[j];
                    let xi = a[j + hn];
                    let (yr, yi) =
                        complex_mul(a[j + ht], a[j + ht + hn], i128::from(sr), i128::from(si))?;
                    a[j] = xr.checked_add(yr)?;
                    a[j + hn] = xi.checked_add(yi)?;
                    a[j + ht] = xr.checked_sub(yr)?;
                    a[j + ht + hn] = xi.checked_sub(yi)?;
                }
            }
            t = ht;
        }
    }
    Some(())
}

pub(super) struct Projection {
    f: Zeroizing<Vec<i128>>,
    g: Zeroizing<Vec<i128>>,
    denominator: Zeroizing<Vec<i128>>,
    scale: u32,
    factor: i128,
}

impl Projection {
    pub(super) fn new(pair: &Pair, weighted: bool) -> Option<Self> {
        let factor = if weighted { 36 } else { 1 };
        let scale = core::cmp::max(pair.f.bits() + if weighted { 6 } else { 0 }, pair.g.bits());
        let mut f = pair.f.scaled(scale, factor)?;
        let mut g = pair.g.scaled(scale, 1)?;
        let hn = pair.f.n() / 2;
        fft(pair.f.logn, &mut f, false)?;
        fft(pair.f.logn, &mut g, false)?;
        let mut denominator = Zeroizing::new(vec![0; hn]);
        for i in 0..hn {
            let d = mul(f[i], f[i])?
                .checked_add(mul(f[i + hn], f[i + hn])?)?
                .checked_add(mul(g[i], g[i])?)?
                .checked_add(mul(g[i + hn], g[i + hn])?)?;
            if d <= 0 {
                return None;
            }
            denominator[i] = d;
        }
        Some(Self {
            f,
            g,
            denominator,
            scale,
            factor,
        })
    }

    #[allow(clippy::type_complexity)]
    pub(super) fn quotient(
        &self,
        big: &Pair,
        scale: u32,
    ) -> Option<(Zeroizing<Vec<i128>>, Zeroizing<Vec<i32>>)> {
        let mut f = big.f.scaled(self.scale + scale, self.factor)?;
        let mut g = big.g.scaled(self.scale + scale, 1)?;
        let hn = big.f.n() / 2;
        fft(big.f.logn, &mut f, false)?;
        fft(big.f.logn, &mut g, false)?;
        for i in 0..hn {
            let re = mul(f[i], self.f[i])?
                .checked_add(mul(f[i + hn], self.f[i + hn])?)?
                .checked_add(mul(g[i], self.g[i])?)?
                .checked_add(mul(g[i + hn], self.g[i + hn])?)?;
            let im = mul(f[i + hn], self.f[i])?
                .checked_sub(mul(f[i], self.f[i + hn])?)?
                .checked_add(mul(g[i + hn], self.g[i])?)?
                .checked_sub(mul(g[i], self.g[i + hn])?)?;
            f[i] = div(re, self.denominator[i])?;
            f[i + hn] = div(im, self.denominator[i])?;
        }
        fft(big.f.logn, &mut f, true)?;
        let mut k = Zeroizing::new(vec![0; big.f.n()]);
        for (ki, &x) in k.iter_mut().zip(f.iter()) {
            *ki = round(x)?;
        }
        Some((f, k))
    }
}

// Certify k = round(B/A), where A = 1296*f*adj(f)+g*adj(g) and
// B = 1296*F*adj(f)+G*adj(g). The exact residual B-A*u bounds the
// approximation error through the smallest eigenvalue of convolution by A.
// Thus intermediate approximations need no correct-rounding assumption.
pub(super) fn certify(pair: &Pair, big: &Pair, u: &[i128], k: &[i32]) -> Option<()> {
    let n = pair.f.n();
    if n != 512 || pair.f.bits() > 7 || pair.g.bits() > 7 || big.f.bits() > 20 || big.g.bits() > 20
    {
        return None;
    }
    let f = pair.f.small_values()?;
    let g = pair.g.small_values()?;
    let big_f = big.f.small_values()?;
    let big_g = big.g.small_values()?;
    let mut a = Zeroizing::new(vec![0i128; n]);
    let mut b = Zeroizing::new(vec![0i128; n]);
    for i in 0..n {
        for j in 0..n {
            let (index, sign) = if i >= j { (i - j, 1) } else { (i + n - j, -1) };
            a[index] += sign
                * (1296 * i128::from(f[i]) * i128::from(f[j])
                    + i128::from(g[i]) * i128::from(g[j]));
            b[index] += sign
                * (1296 * i128::from(big_f[i]) * i128::from(f[j])
                    + i128::from(big_g[i]) * i128::from(g[j]));
        }
    }
    let mut spectrum = Zeroizing::new(vec![0; n]);
    for (dst, &x) in spectrum.iter_mut().zip(a.iter()) {
        if x.unsigned_abs() > 605000 {
            return None;
        }
        *dst = x * ONE;
    }
    fft(9, &mut spectrum, false)?;

    // For |A_i| <= 605000, root error <= 2^-48 and eight butterfly
    // stages give absolute error <= 8*4^8*605001/2^48 < 1. Subtracting
    // one from the floored real part gives a rigorous eigenvalue lower bound.
    let mut lambda = i128::MAX;
    for &x in &spectrum[..n / 2] {
        lambda = core::cmp::min(lambda, (x >> 48) - 1);
    }
    if lambda <= 0 {
        return None;
    }
    let mut residual = Zeroizing::new(vec![0; n]);
    for (r, &x) in residual.iter_mut().zip(b.iter()) {
        *r = x * ONE;
    }
    for i in 0..n {
        for j in 0..n {
            let x = a[i].checked_mul(u[j])?;
            if i + j < n {
                residual[i + j] = residual[i + j].checked_sub(x)?;
            } else {
                residual[i + j - n] = residual[i + j - n].checked_add(x)?;
            }
        }
    }
    let mut maximum = 0;
    for &r in residual.iter() {
        maximum = core::cmp::max(maximum, r.unsigned_abs());
    }
    let (error, remainder) = div_rem(maximum.checked_mul(n as u128)?, lambda as u128)?;
    let error = error.checked_add((remainder != 0) as u128)?;
    for (&x, &ki) in u.iter().zip(k) {
        let distance = x
            .checked_sub(i128::from(ki) * ONE)?
            .unsigned_abs()
            .checked_add(error)?;
        if distance > (ONE / 2) as u128
            || (distance == (ONE / 2) as u128 && (error != 0 || ki & 1 != 0))
        {
            return None;
        }
    }
    Some(())
}

#[cfg(test)]
#[path = "fixed_tests.rs"]
mod tests;
