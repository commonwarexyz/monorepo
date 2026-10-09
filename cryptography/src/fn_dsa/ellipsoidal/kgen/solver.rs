//! Exact NTRU recursion with bounded, rejecting numerical reduction.

use super::{
    super::{KeyMaterial, alloc::vec::Vec, sign},
    fixed::{Projection, certify},
    integer::{Pair, descend, lift, limb_count, solve_base},
    sample::{sample_f, sample_g},
};
use fn_dsa_comm::{RngCore, mq::mqpoly_small_is_invertible};
use zeroize::{Zeroize, Zeroizing};

// For depth d >= 1, m=2^d and n=512/m, Parseval and AM-GM give
// |coefficient| <= n^(m/2-1) * ||input||_2^m. Both squared input norms are
// strictly below 2^19. Each entry is the resulting strict power-of-two bound.
pub(super) const INPUT_BITS: [u32; 10] = [7, 19, 45, 94, 187, 364, 701, 1342, 2559, 4864];
const REDUCTION_STEP: u32 = 8;

const fn output_bound(depth: usize) -> u32 {
    INPUT_BITS[depth] + 16
}
const fn lift_bound(depth: usize) -> u32 {
    INPUT_BITS[depth] + output_bound(depth + 1) + 9 - depth as u32
}

pub(in super::super) fn generate<R: RngCore>(rng: &mut R) -> KeyMaterial {
    loop {
        let f = Zeroizing::new(sample_f(rng));
        let g = Zeroizing::new(sample_g(rng));
        let norm: u32 = g
            .iter()
            .map(|&x| (i32::from(x) * i32::from(x)) as u32)
            .sum();
        if norm > 303032 {
            continue;
        }
        let mut tmp = Zeroizing::new([0u16; 512]);
        if !mqpoly_small_is_invertible(9, &*f, &mut *tmp) || !sign::acceptable_fg(&f, &g) {
            continue;
        }
        let Some(big) = solve(&f, &g) else {
            continue;
        };
        let Some(big_f) = big.f.small_values() else {
            continue;
        };
        let Some(big_g) = big.g.small_values() else {
            continue;
        };
        let mut bad = false;
        for i in 0..512 {
            bad |= !(-2047..=2047).contains(&big_f[i]) || !(-2047..=2047).contains(&big_g[i]);
        }
        if bad {
            continue;
        }
        let mut out = KeyMaterial {
            f: *f,
            g: *g,
            big_f: [0; 512],
            big_g: [0; 512],
        };
        for i in 0..512 {
            out.big_f[i] = big_f[i] as i16;
            out.big_g[i] = big_g[i] as i16;
        }
        if sign::check_key(&out) {
            return out;
        }
        out.zeroize();
    }
}

fn solve(f: &[i8; 512], g: &[i8; 512]) -> Option<Pair> {
    let mut weight = 0;
    let mut norm = 0u32;
    let mut parity = 0u32;
    let mut bad = false;
    for (&x, &y) in f.iter().zip(g) {
        bad |= !(-1..=1).contains(&x) || y == i8::MIN;
        weight += u32::from(x != 0);
        norm += (i32::from(y) * i32::from(y)) as u32;
        parity ^= y as u32;
    }
    if bad || weight != 233 || norm > 303032 || parity & 1 == 0 {
        return None;
    }
    let mut levels = Vec::with_capacity(10);
    levels.push(Pair::small(9, f, g));
    for depth in 1..10 {
        levels.push(descend(&levels[depth - 1], INPUT_BITS[depth]));
    }
    let mut big = solve_base(&levels[9], output_bound(9))?;
    for depth in (0..9).rev() {
        let small = &levels[depth];
        let bound = lift_bound(depth);
        let max_scale = bound.div_ceil(REDUCTION_STEP) * REDUCTION_STEP;

        // Fewer than 1024 rounds, n terms per product, |k_i| <= 2^20,
        // |f_i|,|g_i| < 2^INPUT_BITS[d], and scale <= max_scale bound
        // every partial sum by 2^(INPUT_BITS[d]+max_scale+logn+31).
        let capacity = INPUT_BITS[depth] + max_scale + small.f.logn + 34;
        big = lift(small, &big, bound).resized(limb_count(capacity))?;
        let projection = Projection::new(small, depth == 0)?;
        for step in (0..=max_scale / REDUCTION_STEP).rev() {
            let scale = step * REDUCTION_STEP;
            let (u, k) = projection.quotient(&big, scale)?;
            if depth == 0 && scale == 0 {
                certify(small, &big, &u, &k)?;
            }
            big.f.sub_scaled(&small.f, &k, scale);
            big.g.sub_scaled(&small.g, &k, scale);
        }
        if big.f.bits() > output_bound(depth) || big.g.bits() > output_bound(depth) {
            return None;
        }
        big = big.resized(limb_count(output_bound(depth)))?;
    }
    let bf = big.f.small_values()?;
    let bg = big.g.small_values()?;
    if !exact_equation(f, g, &bf, &bg) {
        return None;
    }
    Some(big)
}

fn exact_equation(f: &[i8; 512], g: &[i8; 512], big_f: &[i64], big_g: &[i64]) -> bool {
    // solve() bounds F,G by 2^23. With |f_i| <= 1 and |g_i| <= 127,
    // every accumulated coefficient is below 512*128*2^23 = 2^39.
    let mut determinant = Zeroizing::new([0i64; 512]);
    for i in 0..512 {
        for j in 0..512 {
            let x = i64::from(f[i]) * big_g[j] - i64::from(g[i]) * big_f[j];
            if i + j < 512 {
                determinant[i + j] += x;
            } else {
                determinant[i + j - 512] -= x;
            }
        }
    }
    let mut difference = determinant[0] ^ 12289;
    for &x in &determinant[1..] {
        difference |= x;
    }
    difference == 0
}

#[cfg(test)]
#[path = "solver_tests.rs"]
mod tests;
