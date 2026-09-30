//! Per-construct elaboration tests with a K-style differential check
//! (DESIGN.md §10.3): each program is written once (see `program!`),
//! compiled natively by rustc into this test binary and elaborated by
//! sandblaster; every definition must be kernel-checked with all obligations
//! proven, and the kernel evaluation of each sample call must equal the
//! native result.

#[path = "elab_util.rs"]
#[macro_use]
mod util;

use sandblaster_front::driver::ProverSet;
use util::differential;

program!(arith {
    pub fn widen_add(a: u8, b: u8) -> u16 {
        a as u16 + b as u16
    }
    pub fn mix(a: u32, b: u32) -> u32 {
        (a ^ b).rotate_left(5u32).wrapping_mul(0x9e37_79b9u32) ^ (a & !b) | (b >> 3u32)
    }
    pub fn sub_or_zero(a: u64, b: u64) -> u64 {
        if a >= b { a - b } else { 0 }
    }
    pub fn div_mod(a: u32, b: u32) -> u32 {
        if b == 0 { 0 } else { (a / b).wrapping_add(a % b) }
    }
    pub fn shifts(x: u32, k: u32) -> u32 {
        if k < 32 { (x << k) ^ (x >> (31 - k)) } else { x.wrapping_shl(k) }
    }
    pub fn bits(x: u64) -> u32 {
        x.count_ones() + (x >> 32u32).count_ones() + x.leading_zeros().min(64u32) + (x.trailing_zeros() & 7u32)
    }
    pub fn sat(a: u8, b: u8) -> (u8, u8) {
        (a.saturating_add(b), a.saturating_sub(b))
    }
    pub fn casts(x: u64) -> (u8, u32) {
        (x as u8, (x >> 32u32) as u32)
    }
    pub fn cmp(a: u16, b: u16) -> bool {
        a < b || (a == b && a != 0)
    }
    pub fn mid(a: u32, b: u32) -> u32 {
        a.min(b) + (a.max(b) - a.min(b)) / 2
    }
    pub fn checked(a: u32, b: u32) -> Option<u32> {
        let s = a.checked_add(b)?;
        s.checked_mul(3u32)
    }
    pub fn bytes(x: u32) -> [u8; 4] {
        let b = x.to_be_bytes();
        let l = x.swap_bytes().to_le_bytes();
        [b[0] ^ l[0], b[1], b[2], u32::from_be_bytes(b).wrapping_add(u32::from_le_bytes(l)) as u8]
    }
});

#[test]
fn arithmetic_and_bits() {
    let cases = calls!(arith;
        widen_add(255u8, 255u8); widen_add(0u8, 7u8);
        mix(0u32, 0u32); mix(0xdead_beefu32, 12345u32); mix(u32::MAX, 1u32);
        sub_or_zero(5u64, 9u64); sub_or_zero(9u64, 5u64); sub_or_zero(u64::MAX, 0u64);
        div_mod(17u32, 5u32); div_mod(17u32, 0u32); div_mod(u32::MAX, 1u32);
        shifts(1u32, 0u32); shifts(0x8000_0001u32, 31u32); shifts(7u32, 40u32);
        bits(0u64); bits(u64::MAX); bits(0x00f0_0000_0000_0100u64);
        sat(200u8, 100u8); sat(3u8, 9u8);
        casts(0x1234_5678_9abc_def0u64);
        cmp(1u16, 2u16); cmp(2u16, 2u16); cmp(0u16, 0u16); cmp(3u16, 2u16);
        mid(10u32, 20u32); mid(u32::MAX, 0u32);
        checked(1u32, 2u32); checked(u32::MAX, 1u32); checked(0x6000_0000u32, 0u32);
        bytes(0x0102_0304u32); bytes(u32::MAX);
    );
    differential(arith::SRC, ProverSet::Basic, &cases);
}

program!(control {
    pub fn classify(x: u8) -> u32 {
        match x {
            0 => 100,
            1..=9 => 200 + x as u32,
            10 | 20 | 30 => 300,
            y if y % 2 == 0 => 400,
            _ => 500,
        }
    }
    pub fn first_some(a: Option<u32>, b: Option<u32>) -> u32 {
        match (a, b) {
            (Some(x), _) | (_, Some(x)) if x > 5 => x,
            (Some(x), Some(y)) => x.wrapping_add(y),
            _ => 0,
        }
    }
    pub fn early(xs: &[u32]) -> u32 {
        if xs.is_empty() {
            return 7;
        }
        let mut acc = 0u32;
        let mut stopped = false;
        for i in 0..xs.len() {
            if xs[i] == 0 {
                stopped = true;
            }
            if !stopped {
                acc = acc.wrapping_add(xs[i]);
            }
        }
        acc
    }
    pub fn try_chain(a: Option<u8>, b: Option<u8>) -> Option<u16> {
        let x = a?;
        let y = b?;
        Some(x as u16 * 256 + y as u16)
    }
    pub fn let_else(v: Option<(u8, u8)>) -> u8 {
        let Some((a, b)) = v else { return 0 };
        a ^ b
    }
    pub fn short(a: bool, b: bool, x: u8) -> u8 {
        let c = a && (x > 3 || !b);
        let d = a ^ b & !c;
        (c as u8) + ((d as u8) << 1u32)
    }
    pub fn nested(x: u32, y: u32) -> u32 {
        let r: u32 = if x > y {
            if x - y > 10 { 1 } else { 2 }
        } else if x == y {
            3
        } else {
            match y - x {
                1 => 4,
                _ => 5,
            }
        };
        r * 10
    }
    pub fn assign_branches(x: u32) -> (u32, u32) {
        let mut a = 1u32;
        let mut b = 2u32;
        if x > 5 {
            a = x;
        } else {
            b = x + a;
        }
        if a > 100 {
            b = 0;
        }
        (a, b)
    }
    pub fn unreachable_arm(x: u8) -> u8 {
        let y = x % 3;
        match y {
            0 => 1,
            1 => 2,
            2 => 3,
            _ => unreachable!(),
        }
    }
});

#[test]
fn control_flow_and_patterns() {
    let cases = calls!(control;
        classify(0u8); classify(5u8); classify(10u8); classify(30u8); classify(42u8); classify(43u8); classify(255u8);
        first_some(Some(1u32), Some(9u32)); first_some(Some(7u32), Some(9u32)); first_some(Some(1u32), Some(2u32)); first_some(None::<u32>, Some(3u32)); first_some(None::<u32>, None::<u32>);
        early(&[0u32; 0][..]); early(&[1u32, 2, 3][..]); early(&[5u32, 0, 9][..]); early(&[u32::MAX, 2][..]);
        try_chain(Some(1u8), Some(2u8)); try_chain(None::<u8>, Some(2u8)); try_chain(Some(255u8), None::<u8>);
        let_else(Some((3u8, 5u8))); let_else(None::<(u8, u8)>);
        short(true, true, 5u8); short(true, false, 1u8); short(false, true, 9u8); short(false, false, 0u8); short(true, true, 2u8);
        nested(30u32, 5u32); nested(8u32, 5u32); nested(5u32, 5u32); nested(5u32, 6u32); nested(0u32, 9u32);
        assign_branches(3u32); assign_branches(7u32); assign_branches(500u32);
        unreachable_arm(0u8); unreachable_arm(4u8); unreachable_arm(8u8);
    );
    differential(control::SRC, ProverSet::Basic, &cases);
}

program!(loops {
    pub fn sum_to(n: u8) -> u32 {
        let mut acc = 0u32;
        for i in 0u32..n as u32 {
            proof! { invariant(acc <= i * 255); }
            acc += i;
        }
        acc
    }
    pub fn inclusive(n: u8) -> u32 {
        let mut c = 0u32;
        for i in 0u8..=n {
            proof! { invariant(c <= i as u32); }
            c += 1;
        }
        c
    }
    pub fn grid(n: u8) -> u32 {
        let mut total: u32 = 0;
        let mut g = [[0u8; 3]; 3];
        for i in 0u32..3 {
            for j in 0u32..3 {
                g[i as usize][j as usize] = ((i * 3 + j) as u8).wrapping_add(n);
                total = total.wrapping_add(g[i as usize][j as usize] as u32);
            }
        }
        total.wrapping_add(g[2][1] as u32)
    }
    pub fn row_sum(n: u8) -> u32 {
        let mut total: u32 = 0;
        let mut row = [0u8; 4];
        for j in 0u32..4 {
            proof! { invariant(total <= j * 255); }
            row[j as usize] = (j as u8).wrapping_mul(n);
            total += row[j as usize] as u32;
        }
        total
    }
    pub fn countdown(n: u32) -> u32 {
        let mut i = n;
        let mut steps = 0u32;
        while i > 0 {
            proof! {
                decreases(i);
                invariant((steps as Int) + (i as Int) == (n as Int));
            }
            i -= 1;
            steps += 1;
        }
        steps
    }
    pub fn xor_all(xs: &[u8]) -> u8 {
        let mut x = 0u8;
        for i in 0..xs.len() {
            x ^= xs[i];
        }
        x
    }
});

#[test]
fn loops_and_invariants() {
    let cases = calls!(loops;
        sum_to(0u8); sum_to(1u8); sum_to(10u8); sum_to(255u8);
        inclusive(0u8); inclusive(5u8); inclusive(255u8);
        grid(0u8); grid(250u8); row_sum(0u8); row_sum(200u8);
        countdown(0u32); countdown(17u32);
        xor_all(&[0u8; 0][..]); xor_all(&[1u8, 2, 4, 8][..]);
    );
    differential(loops::SRC, ProverSet::Basic, &cases);
}

program!(memory {
    pub fn get_or(xs: &[u32], i: usize, d: u32) -> u32 {
        if i < xs.len() { xs[i] } else { d }
    }
    pub fn window(xs: &[u8]) -> u32 {
        if xs.len() < 4 {
            return 0;
        }
        let w = &xs[1..3];
        w[0] as u32 * 256 + w[1] as u32 + xs[xs.len() - 1] as u32
    }
    pub fn ends(s: &[u8]) -> u32 {
        match s {
            [] => 0,
            [x] => *x as u32,
            [first, .., last] => (*first as u32) * 1000 + (*last as u32),
        }
    }
    pub fn head_tail(s: &[u16]) -> (u16, usize) {
        match s {
            [a, b, rest @ ..] => (a.wrapping_add(*b), rest.len()),
            _ => (0, s.len()),
        }
    }
    pub fn fill(n: u8) -> [u8; 4] {
        let mut a = [0u8; 4];
        a[0] = n;
        a[3] = n ^ 0xff;
        let mut b = [1u8; 2];
        b[1] = 9;
        a[1..3].copy_from_slice(&b);
        a
    }
    pub fn arr_pat(a: [u8; 3]) -> u8 {
        let [x, y, z] = a;
        x ^ y ^ z
    }
    pub fn split(xs: &[u8]) -> (usize, usize) {
        if xs.len() >= 2 {
            let (a, b) = xs.split_at(2);
            (a.len(), b.len())
        } else {
            (0, 0)
        }
    }
    pub fn chunk(xs: &[u8]) -> Option<u32> {
        let c = xs.first_chunk::<4>()?;
        Some(u32::from_le_bytes(*c))
    }
    pub fn opts(xs: &[u8]) -> u32 {
        let a = match xs.first() { Some(x) => *x as u32, None => 0 };
        let b = match xs.last() { Some(x) => *x as u32, None => 0 };
        let c = match xs.get(1) { Some(x) => *x as u32, None => 7 };
        a + b + c
    }
    pub fn has_head(xs: &[u8]) -> u32 {
        let d = xs.split_first().is_some() as u32;
        d.wrapping_add(1)
    }
    pub fn eq_digest(a: &[u8; 4], b: &[u8; 4]) -> bool {
        a == b
    }
});

#[test]
fn arrays_slices_and_slice_patterns() {
    let cases = calls!(memory;
        get_or(&[4u32, 5][..], 1usize, 9u32); get_or(&[4u32, 5][..], 2usize, 9u32);
        window(&[1u8, 2, 3][..]); window(&[1u8, 2, 3, 4, 5][..]);
        ends(&[0u8; 0][..]); ends(&[7u8][..]); ends(&[1u8, 2][..]); ends(&[9u8, 8, 7, 6][..]);
        head_tail(&[1u16][..]); head_tail(&[1u16, 2][..]); head_tail(&[u16::MAX, 2, 3, 4][..]);
        fill(3u8);
        arr_pat([1u8, 2, 4]);
        split(&[1u8][..]); split(&[1u8, 2, 3, 4, 5][..]);
        chunk(&[1u8, 2, 3][..]); chunk(&[1u8, 2, 3, 4, 5][..]);
        opts(&[0u8; 0][..]); opts(&[5u8][..]); opts(&[5u8, 6, 7][..]);
        has_head(&[0u8; 0][..]); has_head(&[1u8][..]);
        eq_digest(&[1u8, 2, 3, 4], &[1u8, 2, 3, 4]); eq_digest(&[1u8, 2, 3, 4], &[1u8, 2, 3, 5]);
    );
    differential(memory::SRC, ProverSet::Basic, &cases);
}

program!(adts {
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Point {
        pub x: u32,
        pub y: u32,
    }
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Shape {
        Dot,
        Line(u32),
        Rect { w: u16, h: u16 },
    }
    impl Point {
        pub fn new(x: u32, y: u32) -> Point {
            Point { x, y }
        }
        pub fn manhattan(&self) -> u64 {
            self.x as u64 + self.y as u64
        }
    }
    pub fn area(s: Shape) -> u32 {
        match s {
            Shape::Dot => 0,
            Shape::Line(n) => n,
            Shape::Rect { w, h } => w as u32 * h as u32,
        }
    }
    pub const ORIGIN: Point = Point { x: 0, y: 0 };
    pub fn moved(p: Point, dx: u32) -> Point {
        let mut q = p;
        q.x = q.x.wrapping_add(dx);
        q
    }
    pub fn same(a: u32, b: u32, c: u32) -> (bool, bool) {
        let p = Point::new(a, b);
        let q = Point { x: a, y: c };
        (p == q, p == ORIGIN)
    }
    pub fn shape_eq(a: u16, b: u16) -> (bool, bool) {
        (Shape::Rect { w: a, h: b } == Shape::Rect { w: b, h: a }, Shape::Line(a as u32) == Shape::Dot)
    }
    pub fn dist(a: u32, b: u32) -> u64 {
        Point::new(a, b).manhattan()
    }
    pub fn areas(a: u16, b: u16, n: u32) -> u32 {
        area(Shape::Dot) ^ area(Shape::Line(n)) ^ area(Shape::Rect { w: a, h: b })
    }
});

#[test]
fn structs_enums_methods_and_derived_eq() {
    let cases = calls!(adts;
        same(1u32, 2u32, 2u32); same(1u32, 2u32, 3u32); same(0u32, 0u32, 0u32);
        shape_eq(3u16, 3u16); shape_eq(3u16, 4u16);
        dist(u32::MAX, u32::MAX); dist(1u32, 2u32);
        areas(u16::MAX, u16::MAX, 5u32); areas(2u16, 3u16, 0u32);
    );
    differential(adts::SRC, ProverSet::Basic, &cases);
}

program!(recursion {
    pub fn count(n: u32, acc: u64) -> u64 {
        if n == 0 { acc } else { count(n - 1, acc.wrapping_add(n as u64)) }
    }
    pub fn stride(n: u32, acc: u32) -> u32 {
        if n >= 3 { stride(n - 3, acc ^ n) } else { acc }
    }
    pub fn sum_slice(xs: &[u8], acc: u32) -> u32 {
        match xs {
            [] => acc,
            [x, rest @ ..] => sum_slice(rest, acc.wrapping_add(*x as u32)),
        }
    }
});

#[test]
fn tail_recursion_with_inferred_measures() {
    let cases = calls!(recursion;
        count(0u32, 5u64); count(100u32, 0u64);
        stride(0u32, 1u32); stride(2u32, 1u32); stride(3u32, 1u32); stride(100u32, 0u32);
        sum_slice(&[0u8; 0][..], 0u32); sum_slice(&[1u8, 2, 3, 250][..], 7u32);
    );
    differential(recursion::SRC, ProverSet::Basic, &cases);
}
