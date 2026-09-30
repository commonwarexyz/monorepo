//! Phase-3 golden of checked-arithmetic printing (E0, design §11.5): every
//! checked `+ - * << >>` is proven (from guards and constants) and printed
//! through the `crate::__rt::chk` helpers — at every width, with shift
//! amounts of other widths than `u32`, and in compound assignments on a
//! local, a field and an array element. Division keeps its operator, and so
//! does the `const` initializer.
#![forbid(unsafe_code)]
use sandblaster::prelude::*;

/// A constant (its initializer is evaluated by rustc: operators stay).
pub const LIMIT: u64 = 1000 * 4 + 1;

#[derive(Clone, Copy)]
pub struct Acc {
    pub lo: u32,
    pub hi: u64,
}

/// Checked operations at every width, proven from the guard.
pub fn widths(a: u64, b: u32, c: u16, d: u8, e: usize) -> (u64, u32, u16, u8, usize) {
    if a >= LIMIT || b >= 1000 || c >= 1000 || d >= 100 || e >= 1000 {
        return (0, 0, 0, 0, 0);
    }
    (a * 7 - a, b / 2 + 3, c * 2 + 1, d + 100, (e << 2u8) >> 1u64)
}

/// Checked compound assignments on an array element, a field and a local.
pub fn compound(xs: [u32; 4], i: usize, v: u8) -> ([u32; 4], Acc) {
    let mut ys = xs;
    let mut acc = Acc { lo: 1, hi: 2 };
    let mut n: u64 = 5;
    if i < 4 && ys[i] < 1000 {
        ys[i] += 7;
        ys[i] <<= 1u8;
    }
    acc.lo *= 3;
    n -= 1;
    n >>= 2u64;
    acc.hi += n;
    if v < 60 {
        acc.hi <<= v;
    }
    (ys, acc)
}

/// A loop whose per-element arithmetic is checked.
pub fn prefix(xs: &[u8; 8]) -> u32 {
    let mut s: u32 = 0;
    for i in 0usize..8 {
        s = s.wrapping_add(xs[i] as u32 + i as u32);
    }
    s
}
