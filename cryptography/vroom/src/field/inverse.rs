// Copyright Supranational LLC
// Copyright Commonware contributors
// SPDX-License-Identifier: Apache-2.0
//
// Binary GCD batching follows blst's no_asm.h and Thomas Pornin's
// Optimized Binary GCD for Modular Inversion (2020/972, revised August 23).

use super::Modulus;
use core::hint::black_box;

const BATCH: usize = 31;
const MASK: u64 = (1 << BATCH) - 1;

#[inline(always)]
const fn select(a: u64, b: u64, mask: u64) -> u64 {
    a ^ ((a ^ b) & mask)
}

// Keep the sign mask opaque so LLVM retains masked multiword additions.
#[inline(always)]
const fn negative(x: u64) -> u64 {
    black_box((x as i64 >> 63) as u64)
}

#[inline(always)]
const fn negate(x: u64, mask: u64) -> u64 {
    (x ^ mask).wrapping_sub(mask)
}

fn approximate<const N: usize>(a: &[u64; N], b: &[u64; N]) -> (u64, u64) {
    let (mut ah, mut al, mut bh, mut bl) = (0, 0, 0, 0);
    for i in (1..N).rev() {
        let mask = 0u64.wrapping_sub(u64::from(ah | bh == 0));
        ah = select(ah, a[i], mask);
        al = select(al, a[i - 1], mask);
        bh = select(bh, b[i], mask);
        bl = select(bl, b[i - 1], mask);
    }
    let shift = (ah | bh).leading_zeros() & 63;
    let mask = 0u64.wrapping_sub(u64::from(shift != 0));
    ah = ah.wrapping_shl(shift) | (al.wrapping_shr(64 - shift) & mask);
    bh = bh.wrapping_shl(shift) | (bl.wrapping_shr(64 - shift) & mask);
    let mut big = 0u64;
    for i in 1..N {
        big |= a[i] | b[i];
    }
    let mask = 0u64.wrapping_sub(u64::from(big != 0));
    (
        select(a[0], (a[0] & MASK) | (ah & !MASK), mask),
        select(b[0], (b[0] & MASK) | (bh & !MASK), mask),
    )
}

// Each 32-bit half encodes a coefficient plus 2^31-1; all 31 updates stay in range.
fn factors(mut a: u64, mut b: u64, steps: usize) -> [i64; 4] {
    const BIAS: u64 = 0x7fff_ffff;
    const PAIR_BIAS: u64 = BIAS | (BIAS << 32);
    let mut fg0 = PAIR_BIAS + 1;
    let mut fg1 = PAIR_BIAS + (1 << 32);
    for _ in 0..steps {
        let odd = 0u64.wrapping_sub(a & 1);
        let (difference, borrow) = a.overflowing_sub(b & odd);
        let mask = 0u64.wrapping_sub(u64::from(borrow));
        let reverse = b.wrapping_sub(a);
        let next_b = select(b, a, mask);
        a = select(difference, reverse, mask) >> 1;
        b = next_b;
        let next_fg0 = select(fg0, fg1, mask);
        fg1 = select(fg1, fg0, mask);
        fg0 = next_fg0
            .wrapping_sub(fg1 & odd)
            .wrapping_add(PAIR_BIAS & odd);
        fg1 = fg1.wrapping_mul(2).wrapping_sub(PAIR_BIAS);
    }
    [
        i64::from(fg0 as u32) - BIAS as i64,
        (fg0 >> 32) as i64 - BIAS as i64,
        i64::from(fg1 as u32) - BIAS as i64,
        (fg1 >> 32) as i64 - BIAS as i64,
    ]
}

// The row's L1 norm is at most 2^steps. Each signed accumulation fits i128.
#[inline(always)]
fn update<const N: usize>(
    a: &[u64; N],
    b: &[u64; N],
    f: &mut i64,
    g: &mut i64,
    steps: usize,
) -> [u64; N] {
    let mut out = [0u64; N];
    let mut carry = 0i128;
    let mut low = 0u64;
    for i in 0..N {
        let z = (i128::from(a[i]) * i128::from(*f))
            .wrapping_add(i128::from(b[i]) * i128::from(*g))
            .wrapping_add(carry);
        if i != 0 {
            out[i - 1] = (low >> steps) | ((z as u64) << (64 - steps));
        }
        low = z as u64;
        carry = z >> 64;
    }
    out[N - 1] = (low >> steps) | ((carry as u64) << (64 - steps));
    let sign = negative(carry as u64);
    *f = negate(*f as u64, sign) as i64;
    *g = negate(*g as u64, sign) as i64;
    let mut carry = sign & 1;
    for word in &mut out {
        let z = u128::from(*word ^ sign) + u128::from(carry);
        *word = z as u64;
        carry = (z >> 64) as u64;
    }
    out
}

// The unreduced quotient lies in (-p, 2p); the two corrections are fixed.
#[inline(always)]
fn update_mod<const N: usize>(
    a: &[u64; N],
    b: &[u64; N],
    f: i64,
    g: i64,
    p: &[u64; N],
    inverse: u64,
    steps: usize,
) -> [u64; N] {
    let low = a[0]
        .wrapping_mul(f as u64)
        .wrapping_add(b[0].wrapping_mul(g as u64));
    let m = low.wrapping_mul(inverse) & ((1u64 << steps) - 1);
    let mut out = [0u64; N];
    let mut carry = 0i128;
    let mut low = 0u64;
    for i in 0..N {
        let z = (i128::from(a[i]) * i128::from(f))
            .wrapping_add(i128::from(b[i]) * i128::from(g))
            .wrapping_add(i128::from(p[i]) * i128::from(m))
            .wrapping_add(carry);
        if i != 0 {
            out[i - 1] = (low >> steps) | ((z as u64) << (64 - steps));
        }
        low = z as u64;
        carry = z >> 64;
    }
    out[N - 1] = (low >> steps) | ((carry as u64) << (64 - steps));
    let sign = negative(carry as u64);
    let mut carry = 0u128;
    for i in 0..N {
        carry += u128::from(out[i]) + u128::from(p[i] & sign);
        out[i] = carry as u64;
        carry >>= 64;
    }
    let mut reduced = [0u64; N];
    let mut borrow = 0u128;
    for i in 0..N {
        let z = u128::from(out[i]).wrapping_sub(u128::from(p[i]) + borrow);
        reduced[i] = z as u64;
        borrow = (z >> 64) & 1;
    }
    let mask = 0u64.wrapping_sub(borrow as u64);
    for i in 0..N {
        out[i] = select(reduced[i], out[i], mask);
    }
    out
}

fn invert_words<const N: usize>(input: &[u64; N], modulus: &[u64; N]) -> [u64; N] {
    let mut a = *input;
    let mut b = *modulus;
    let mut u = [0u64; N];
    let mut v = [0u64; N];
    u[0] = 1;
    let mut inverse = 1u64;
    for _ in 0..6 {
        inverse = inverse.wrapping_mul(2u64.wrapping_sub(modulus[0].wrapping_mul(inverse)));
    }
    inverse = inverse.wrapping_neg();
    let total = 128 * N;
    for _ in 0..total / BATCH {
        let steps = BATCH;
        let (ap, bp) = approximate(&a, &b);
        let [mut f0, mut g0, mut f1, mut g1] = factors(ap, bp, steps);
        let next_a = update(&a, &b, &mut f0, &mut g0, steps);
        b = update(&a, &b, &mut f1, &mut g1, steps);
        a = next_a;
        let next_u = update_mod(&u, &v, f0, g0, modulus, inverse, steps);
        v = update_mod(&u, &v, f1, g1, modulus, inverse, steps);
        u = next_u;
    }
    // Nonzero inputs leave at most 24 bits after the full batches. Zero keeps v=0.
    let [_, _, f, g] = factors(a[0], b[0], total % BATCH);
    update_mod(&u, &v, f, g, modulus, inverse, total % BATCH)
}

// The sealed moduli are odd, below 2^(64N-1), and use exactly four or six words.
// Inputs and outputs are canonical; zero maps to zero.
pub(super) fn invert<P: Modulus>(input: &[u64; 6]) -> [u64; 6] {
    let p = &P::PARAMETERS.modulus;
    if P::PARAMETERS.bits > 256 {
        invert_words(input, p)
    } else {
        let small_input = [input[0], input[1], input[2], input[3]];
        let small_p = [p[0], p[1], p[2], p[3]];
        let mut out = [0; 6];
        out[..4].copy_from_slice(&invert_words(&small_input, &small_p));
        out
    }
}
