//! Patterns, guards, `?`, loops and tail recursion.
#![forbid(unsafe_code)]

use sandblaster::prelude::*;

/// Nested or-patterns with a guard: every matching alternative is tried.
pub fn nested_or(a: Option<u8>, b: Option<u8>, c: u8) -> u8 {
    match ((a, b), c) {
        ((Some(x), _) | (_, Some(x)), 0 | 1) if x > 2 => x,
        ((None, None), k) if k > 5 => k,
        _ => 0,
    }
}

/// The order in which nested alternatives are tried is observable.
pub fn order(p: (Option<u8>, Option<u8>), q: (Option<u8>, Option<u8>)) -> u16 {
    match (p, q) {
        ((Some(x), _) | (_, Some(x)), (Some(y), _) | (_, Some(y))) if (x as u16) + (y as u16) > 10 => (x as u16) * 256 + (y as u16),
        _ => 0,
    }
}

pub fn let_or(p: (u8, u8)) -> u8 {
    let ((a, 0) | (0, a)) = p else {
        return 255;
    };
    a
}

pub fn if_let_chain(o: Option<u8>, s: &[u8]) -> u8 {
    if let Some(v) = o {
        v
    } else if let [h, ..] = s {
        *h
    } else {
        0
    }
}

pub fn try_chain(s: &[u8]) -> Option<u16> {
    let (a, rest) = s.split_first()?;
    let (b, _) = rest.split_first()?;
    Some(((*a as u16) << 8u32) | (*b as u16))
}

pub fn slices(s: &[u8]) -> u32 {
    match s {
        [] => 0,
        [a] => *a as u32,
        [a, b] => (*a as u32) + (*b as u32) * 2,
        [first, .., last] => (*first as u32) * 1000 + (*last as u32),
    }
}

pub fn tail_sum(s: &[u8], acc: u32) -> u32 {
    match s {
        [] => acc,
        [h, t @ ..] => tail_sum(t, acc.wrapping_add(*h as u32)),
    }
}

/// Generic over the element type, so not a boundary function: host code
/// could instantiate it with a zero-sized type (DESIGN.md §3.1). The
/// boundary exports monomorphic instances.
fn count<T: Copy>(s: &[T], n: usize) -> usize {
    match s {
        [] => n,
        [_, t @ ..] => count(t, n + 1),
    }
}

pub fn count_u64(s: &[u64], n: usize) -> usize {
    count(s, n)
}

pub fn count_u8(s: &[u8], n: usize) -> usize {
    count(s, n)
}

pub fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 {
        a
    } else {
        gcd(b, a % b)
    }
}

pub fn init_last(s: &[u8]) -> u8 {
    match s {
        [init @ .., last] => *last ^ (init.len() as u8),
        [] => 0,
    }
}

pub fn arrays(a: [u8; 4]) -> u8 {
    let [x, y, rest @ ..] = a;
    x ^ y ^ rest[0] ^ rest[1]
}

pub fn ranges(x: u64) -> u8 {
    match x {
        0 => 0,
        1..=9 => 1,
        10..=99 => 2,
        _ => 3,
    }
}

/// `for i in k..n` runs zero times when `k > n`; `..=MAX` does not overflow.
pub fn range_loops(k: u32, n: u32) -> u32 {
    let mut c: u32 = 0;
    for _i in k..n {
        c += 1;
    }
    for j in 250u8..=u8::MAX {
        c += j as u32;
    }
    c
}

pub fn guards_fallthrough(x: u8) -> u8 {
    match x {
        v if v % 2 == 0 => 1,
        3 | 5 if x > 3 => 2,
        v => v,
    }
}

pub fn bool_ops(a: bool, b: bool, x: u8) -> u8 {
    let c = a && (x > 3 || !b);
    let d = a ^ b & !c;
    (c as u8) + ((d as u8) << 1u32) + ((a | b) as u8)
}

pub fn nested_loops(n: u8) -> u32 {
    let mut total: u32 = 0;
    let mut grid = [[0u8; 3]; 3];
    for i in 0..3usize {
        for j in 0..3usize {
            grid[i][j] = (i as u8) * 3 + (j as u8) + n;
            total += grid[i][j] as u32;
        }
    }
    total + grid[2][1] as u32
}
