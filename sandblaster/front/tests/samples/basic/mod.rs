//! A sample sandblaster crate exercising the exec subset.
#![forbid(unsafe_code)]

use sandblaster::prelude::*;

mod shapes;
pub mod codec;

pub use codec::read_u32_be;

/// A 32-byte digest.
pub type Digest = [u8; 32];

pub const LIMIT: u32 = 7;

/// Sum with wrapping.
pub fn wsum(xs: &[u32]) -> u32 {
    let mut acc: u32 = 0;
    for i in 0..xs.len() {
        acc = acc.wrapping_add(xs[i]);
    }
    acc
}

/// Or-pattern with guard: rustc retries the guard per alternative.
pub fn pick(a: Option<u32>, b: Option<u32>) -> u32 {
    match (a, b) {
        (Some(x), _) | (_, Some(x)) if x > 5 => x,
        _ => 0,
    }
}

/// Tail-recursive xor fold over a slice.
pub fn xor_fold(s: &[u8], acc: u8) -> u8 {
    match s {
        [] => acc,
        [h, t @ ..] => xor_fold(t, acc ^ *h),
    }
}

/// Depth-bounded recursion. The depth bound is a hidden precondition, so
/// `pow2` is not a boundary function (DESIGN.md §3.1): the boundary exports
/// the total wrapper `pow2_total`.
#[decreases(n, max = 64)]
pub(crate) fn pow2(n: u32) -> u64 {
    if n == 0 { 1 } else { 2 * pow2(n - 1) }
}

pub fn pow2_total(n: u32) -> u64 {
    if n <= 63 { pow2(n) } else { 0 }
}

pub fn first_two(s: &[u8]) -> Option<(u8, u8)> {
    let (a, rest) = s.split_first()?;
    let b = rest.first()?;
    Some((*a, *b))
}

pub fn widen(k: u32) -> u64 {
    (1u64 << k) as u64
}

pub fn classify(x: u8) -> u8 {
    match x {
        0 => 0,
        1..=9 => 1,
        10 | 20 | 30 => 2,
        _ => 3,
    }
}

pub fn digest_eq(a: &Digest, b: &Digest) -> bool {
    a == b
}

pub fn fill(v: u8) -> [u8; 8] {
    let mut out = [0u8; 8];
    let src: [u8; 4] = [v, v, v, v];
    out[0..4].copy_from_slice(&src);
    out[7] = v ^ 0xFF;
    out
}

pub fn count_down(n: u32) -> u32 {
    let mut i = n;
    let mut steps: u32 = 0;
    while i > 0 {
        proof! { decreases(i); }
        i -= 1;
        steps += 1;
    }
    steps
}

pub fn area(s: shapes::Shape) -> u64 {
    s.area()
}

pub fn get_or(s: &[u32], i: usize, d: u32) -> u32 {
    let Some(v) = s.get(i) else { return d; };
    *v
}
