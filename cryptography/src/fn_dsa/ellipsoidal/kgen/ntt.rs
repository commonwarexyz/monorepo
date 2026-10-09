// Scalar arithmetic adapted from Thomas Pornin's fn-dsa-kgen 0.4.0 (Unlicense).
// See PROVENANCE.md for the source and local arithmetic contracts.

#![allow(non_snake_case)]

use super::{mp31::*, zint31::bitlength};

// Compute the roots for NTT and inverse NTT.
// Inputs:
//    logn   wanted degree (logarithmic, 0 to 10)
//    g      primitive 2048-th root of 1 modulo p (Montgomery representation)
//    ig     inverse of g modulo p (Montgomery representation)
//    p      modulus
//    p0i    -1/p mod 2^32
// Outputs are written into gm[] and igm[]; in both slices, exactly
// n = 2^logn values are written. Output values are in Montgomery
// representation.
pub(crate) fn mp_mkgmigm(
    logn: u32,
    g: u32,
    ig: u32,
    p: u32,
    p0i: u32,
    gm: &mut [u32],
    igm: &mut [u32],
) {
    // We want a primitive 2n-th root of 1; we have a primitive 2048-th root
    // of 1, so we must square it a few times if logn < 10.
    let mut g = g;
    let mut ig = ig;
    for _ in logn..10 {
        g = mp_mmul(g, g, p, p0i);
        ig = mp_mmul(ig, ig, p, p0i);
    }

    let k = 10 - logn;
    let mut x1 = mp_R(p);
    let mut x2 = mp_hR(p);
    for i in 0..(1 << logn) {
        let v = REV10[i << k] as usize;
        gm[v] = x1;
        igm[v] = x2;
        x1 = mp_mmul(x1, g, p, p0i);
        x2 = mp_mmul(x2, ig, p, p0i);
    }
}

// Apply NTT over a polynomial in GF(p)[X]/(X^n+1). Input coefficients are
// expected in unsigned representation. The polynomial is modified in place.
// The number of coefficients is n = 2^logn, with 0 <= logn <= 10. The gm[]
// table must have been initialized with mp_mkgm() (or mp_mkgmigm()) with
// at least n elements.
pub(crate) fn mp_NTT(logn: u32, a: &mut [u32], gm: &[u32], p: u32, p0i: u32) {
    if logn == 0 {
        return;
    }
    let mut t = 1 << logn;
    for lm in 0..logn {
        let m = 1 << lm;
        let ht = t >> 1;
        let mut j0 = 0;
        for i in 0..m {
            let s = gm[i + m];
            for j in 0..ht {
                let j1 = j0 + j;
                let j2 = j1 + ht;
                let x1 = a[j1];
                let x2 = mp_mmul(a[j2], s, p, p0i);
                a[j1] = mp_add(x1, x2, p);
                a[j2] = mp_sub(x1, x2, p);
            }
            j0 += t;
        }
        t = ht;
    }
}

// Apply inverse NTT over a polynomial in GF(p)[X]/(X^n+1). Input
// coefficients are expected in unsigned representation. The polynomial is
// modified in place. The number of coefficients is n = 2^logn, with
// 0 <= logn <= 10. The igm[] table must have been initialized with
// mp_mkigm() (or mp_mkgmigm()) with at least n elements.
pub(crate) fn mp_iNTT(logn: u32, a: &mut [u32], igm: &[u32], p: u32, p0i: u32) {
    if logn == 0 {
        return;
    }
    let mut t = 1;
    for lm in 0..logn {
        let hm = 1 << (logn - 1 - lm);
        let dt = t << 1;
        let mut j0 = 0;
        for i in 0..hm {
            let s = igm[i + hm];
            for j in 0..t {
                let j1 = j0 + j;
                let j2 = j1 + t;
                let x1 = a[j1];
                let x2 = a[j2];
                a[j1] = mp_half(mp_add(x1, x2, p), p);
                a[j2] = mp_mmul(mp_sub(x1, x2, p), s, p, p0i);
            }
            j0 += dt;
        }
        t = dt;
    }
}

// Get the maximum bitlength of the coefficients of the provided polynomial
// (degree 2^logn, coefficients in plain representation, xlen words per
// coefficient).
pub(crate) fn poly_max_bitlength(logn: u32, x: &[u32], xlen: usize) -> u32 {
    let n = 1usize << logn;
    let mut t = 0u32;
    let mut tk = 0u32;
    for i in 0..n {
        // Extend sign bit into a 31-bit mask.
        let m = (x[i + ((xlen - 1) << logn)] >> 30).wrapping_neg() & 0x7FFFFFFF;

        // Get top non-zero sign-adjusted word, with index.
        //   c    top non-zero word
        //   ck   index at which c was found
        let mut c = 0u32;
        let mut ck = 0u32;
        for j in 0..xlen {
            // Sign-adjust the word.
            let w = x[i + (j << logn)] ^ m;

            // If the word is non-zero, then update c and ck.
            let nz = (w.wrapping_sub(1) >> 31).wrapping_sub(1);
            c ^= nz & (c ^ w);
            ck ^= nz & (ck ^ (j as u32));
        }

        // If ck > tk, or ck == tk but c > t, then (c,ck) must replace
        // (t,tk) as current candidate.
        let nz1 = tk.wrapping_sub(ck);
        let nz2 = (tk ^ ck).wrapping_sub(1) & t.wrapping_sub(c);
        let nz = tbmask(nz1 | nz2);
        t ^= nz & (t ^ c);
        tk ^= nz & (tk ^ ck);
    }

    31 * tk + bitlength(t)
}
