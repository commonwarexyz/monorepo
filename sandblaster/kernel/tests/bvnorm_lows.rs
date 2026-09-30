//! `bvnorm` rule 7, distributed low chunks (DESIGN.md §9.8; `bvnorm/word.rs`
//! module doc, `lows`).
//!
//! The low chunk of a sum (or of an `and`/`or` set or a truth table) is
//! distributed into the sum of the truncated summands, a new class. Before
//! the `lows` record that class was a base atom of its own, so zero-extending
//! or re-chunking it could not find its bits in the wide word again: the
//! bytes of a sum `s` regrouped into 16-bit halves (the `u16` view of
//! `PBLENDW`, `_mm_blend_epi16`) and back normalized to `(s & 0xffff0000) ^
//! (zext(T8(s)) & 0xff) ^ (zext(T16(s)) & 0xff00)` instead of `s`, which is
//! what kept `compress_shani`'s `VariantEquiv` from being proven.
//!
//! * completeness: the round trips of the SHA-NI shapes through `u8`/`u16`/
//!   `u32`/`u64` land in the class of the wide word, by the normalizer alone
//!   (`classify`) and through the kernel's `bvrefl` (with the tripwire);
//! * must reject: near misses (a swapped byte, a shift off by one, a byte of
//!   a different sum with the same low byte, a missing high byte), each
//!   checked unequal natively first;
//! * soundness: exhaustive over two `U8` atoms (65,536 valuations) with low
//!   chunks of several sums that share a low byte (so one narrow class has
//!   several wide origins), in both creation orders; and random trees mixing
//!   `u8`/`u16`/`u32`/`u64` casts around sums, sets and truth tables,
//!   cross-checked on random valuations.

mod common;

use std::collections::HashMap;
use std::rc::Rc;

use common::*;
use sandblaster_kernel::api::*;
use sandblaster_kernel::bvnorm::{BvOptions, BvVerdict, classify, decide};
use sandblaster_kernel::term::*;
use sandblaster_kernel::util::mk;

// ---------------------------------------------------------------------------
// A small expression language with an independent native semantics.
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum Ex {
    Atom(u32, Width),
    Lit(Width, u64),
    Not(E),
    Bin(B, E, E),
    Sh(S, E, u32),
    /// Zero-extension or truncation.
    Cast(Width, E),
}
type E = Rc<Ex>;

#[derive(Clone, Copy, Debug, PartialEq)]
enum B {
    And,
    Or,
    Xor,
    Add,
    Sub,
}
#[derive(Clone, Copy, Debug)]
enum S {
    Shl,
    Shr,
    Rotr,
}

use Width::{U8, U16, U32, U64};

fn bits(w: Width) -> u32 {
    w.bits().unwrap()
}
fn mask(w: Width) -> u64 {
    if bits(w) == 64 { u64::MAX } else { (1u64 << bits(w)) - 1 }
}
fn width(e: &Ex) -> Width {
    match e {
        Ex::Atom(_, w) | Ex::Lit(w, _) | Ex::Cast(w, _) => *w,
        Ex::Not(a) | Ex::Sh(_, a, _) | Ex::Bin(_, a, _) => width(a),
    }
}
fn atom(l: u32, w: Width) -> E {
    Rc::new(Ex::Atom(l, w))
}
fn lit(w: Width, n: u64) -> E {
    Rc::new(Ex::Lit(w, n & mask(w)))
}
fn bin(b: B, x: &E, y: &E) -> E {
    assert_eq!(width(x), width(y), "{x:?} {y:?}");
    Rc::new(Ex::Bin(b, x.clone(), y.clone()))
}
fn add(x: &E, y: &E) -> E {
    bin(B::Add, x, y)
}
fn and(x: &E, y: &E) -> E {
    bin(B::And, x, y)
}
fn or(x: &E, y: &E) -> E {
    bin(B::Or, x, y)
}
fn xor(x: &E, y: &E) -> E {
    bin(B::Xor, x, y)
}
fn not(a: &E) -> E {
    Rc::new(Ex::Not(a.clone()))
}
fn shl(a: &E, k: u32) -> E {
    Rc::new(Ex::Sh(S::Shl, a.clone(), k))
}
fn shr(a: &E, k: u32) -> E {
    Rc::new(Ex::Sh(S::Shr, a.clone(), k))
}
fn rotr(a: &E, k: u32) -> E {
    Rc::new(Ex::Sh(S::Rotr, a.clone(), k))
}
fn cast(w: Width, a: &E) -> E {
    Rc::new(Ex::Cast(w, a.clone()))
}
/// `Ch(e, f, g) = (e & f) ^ (!e & g)` (a truth table of three variables).
fn ch(e: &E, f: &E, g: &E) -> E {
    xor(&and(e, f), &and(&not(e), g))
}

fn eval(e: &Ex, env: &[u64]) -> u64 {
    match e {
        Ex::Atom(l, w) => env[*l as usize] & mask(*w),
        Ex::Lit(_, n) => *n,
        Ex::Not(a) => !eval(a, env) & mask(width(a)),
        Ex::Bin(b, x, y) => {
            let (w, p, q) = (width(x), eval(x, env), eval(y, env));
            (match b {
                B::And => p & q,
                B::Or => p | q,
                B::Xor => p ^ q,
                B::Add => p.wrapping_add(q),
                B::Sub => p.wrapping_sub(q),
            }) & mask(w)
        }
        Ex::Sh(s, a, k) => {
            let (w, v) = (width(a), eval(a, env));
            let (n, k) = (bits(w), k % bits(w));
            match s {
                S::Shl => (v << k) & mask(w),
                S::Shr => v >> k,
                S::Rotr => {
                    if k == 0 {
                        v
                    } else {
                        ((v >> k) | (v << (n - k))) & mask(w)
                    }
                }
            }
        }
        Ex::Cast(w, a) => eval(a, env) & mask(*w),
    }
}

fn tm(e: &Ex, depth: u32) -> Tm {
    use PrimOp::*;
    match e {
        Ex::Atom(l, _) => mk::var(depth - 1 - l),
        Ex::Lit(w, n) => mk::lit(*w, *n),
        Ex::Not(a) => mk::prim(Not(width(a)), vec![tm(a, depth)], vec![]),
        Ex::Bin(b, x, y) => {
            let w = width(x);
            let op = match b {
                B::And => And(w),
                B::Or => Or(w),
                B::Xor => Xor(w),
                B::Add => WAdd(w),
                B::Sub => WSub(w),
            };
            mk::prim(op, vec![tm(x, depth), tm(y, depth)], vec![])
        }
        Ex::Sh(s, a, k) => {
            let w = width(a);
            let op = match s {
                S::Shl => WShl(w),
                S::Shr => WShr(w),
                S::Rotr => Rotr(w),
            };
            mk::prim(op, vec![tm(a, depth), mk::lit(U32, *k as u64)], vec![])
        }
        Ex::Cast(to, a) => mk::prim(Cast { from: width(a), to: *to }, vec![tm(a, depth)], vec![]),
    }
}

fn show(e: &Ex) -> String {
    match e {
        Ex::Atom(l, _) => ["x", "y", "z"][*l as usize].to_string(),
        Ex::Lit(_, n) => format!("{n:#x}"),
        Ex::Not(a) => format!("!{}", show(a)),
        Ex::Bin(b, x, y) => format!("({} {} {})", show(x), ["&", "|", "^", "+", "-"][*b as usize], show(y)),
        Ex::Sh(s, a, k) => format!("{}({}, {k})", ["shl", "shr", "rotr"][*s as usize], show(a)),
        Ex::Cast(w, a) => format!("({} as {w:?})", show(a)),
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn ctx_of(env: &Env, ws: &[Width]) -> Ctx {
    let mut c = Ctx::default();
    for (i, w) in ws.iter().enumerate() {
        let tv = env.eval(&env.ctx_venv(&c), c.depth(), &mk::int_ty(*w), &mut budget()).unwrap();
        c = c.push(CtxEntry { name: ["x", "y", "z"][i].into(), rel: Rel::Rel, ty: tv, def: None });
    }
    c
}

/// Do `a` and `b` agree on corner and random valuations (natively)?
fn agree(a: &Ex, b: &Ex, natoms: usize, rng: &mut Rng) -> bool {
    for c in [0u64, u64::MAX, 1, 0x8000_0000_0000_0000, 0xFF, 0xFF00, 0x00FF_00FF_00FF_00FF] {
        if eval(a, &vec![c; natoms]) != eval(b, &vec![c; natoms]) {
            return false;
        }
    }
    (0..2000).all(|_| {
        let env: Vec<u64> = (0..natoms).map(|_| rng.next()).collect();
        eval(a, &env) == eval(b, &env)
    })
}

// ---------------------------------------------------------------------------
// The SHA-NI shapes.
// ---------------------------------------------------------------------------

/// Byte `k` of `x`: `(x >> 8k) as u8`.
fn byte(x: &E, k: u32) -> E {
    cast(U8, &if k == 0 { x.clone() } else { shr(x, 8 * k) })
}

/// `from_le_bytes` as the prelude unfolds it in the `BvRefl` mode: `zext(b0)
/// | zext(b1) << 8 | …` at width `w`.
fn from_le(w: Width, bytes: &[E]) -> E {
    let mut acc = cast(w, &bytes[0]);
    for (k, b) in bytes.iter().enumerate().skip(1) {
        acc = or(&acc, &shl(&cast(w, b), 8 * k as u32));
    }
    acc
}

/// The `u16` word view of 16 bytes (`view_u16`, PBLENDW's lanes) and back to
/// bytes (`from_u16x8`): each pair of bytes becomes a `u16`, each `u16`
/// two bytes again.
fn through_u16(bytes: &[E]) -> Vec<E> {
    bytes
        .chunks(2)
        .flat_map(|p| {
            let h = from_le(U16, p);
            [byte(&h, 0), byte(&h, 1)]
        })
        .collect()
}

/// Wide words of the SHA-NI shapes over atoms `x`, `y` (`U32`): sums (the
/// final `state + work` lanes), sets, a truth table, a rotated sum.
fn bases32() -> Vec<E> {
    let (x, y) = (atom(0, U32), atom(1, U32));
    vec![
        add(&x, &y),
        add(&add(&x, &y), &lit(U32, 0x428a_2f98)),
        add(&rotr(&x, 6), &xor(&rotr(&y, 11), &rotr(&y, 25))),
        and(&x, &y),
        or(&x, &shl(&y, 3)),
        ch(&x, &y, &rotr(&x, 7)),
        bin(B::Sub, &x, &y),
    ]
}

/// Assert `lhs == rhs` modulo word algebra: by the normalizer alone and by
/// the kernel's `bvrefl` (with the tripwire). Both are checked equal
/// natively first.
fn assert_equal(env: &Env, ctx: &Ctx, natoms: usize, lhs: &E, rhs: &E, rng: &mut Rng) {
    assert!(agree(lhs, rhs, natoms, rng), "test bug: {} and {} differ", show(lhs), show(rhs));
    let d = natoms as u32;
    let (l, r) = (tm(lhs, d), tm(rhs, d));
    let cs = classify(env, ctx, &[l.clone(), r.clone()], &mut budget()).unwrap();
    assert_eq!(cs[0], cs[1], "incomplete: {} == {}", show(lhs), show(rhs));
    let v = decide(env, ctx, &l, &r, BvOptions::default(), &mut budget()).unwrap();
    assert_eq!(v, BvVerdict::Equal, "{} == {}", show(lhs), show(rhs));
    let t = Rc::new(Term::BvRefl { ty: mk::int_ty(width(lhs)), lhs: l, rhs: r });
    env.infer(ctx, &t, &mut budget()).unwrap_or_else(|e| panic!("kernel rejects {} == {}: {e}", show(lhs), show(rhs)));
}

/// Assert `lhs != rhs` natively, and that neither the normalizer (tripwire
/// off) nor the kernel accepts the equation.
fn assert_rejected(env: &Env, ctx: &Ctx, natoms: usize, lhs: &E, rhs: &E, rng: &mut Rng) {
    assert!(!agree(lhs, rhs, natoms, rng), "test bug: {} and {} agree", show(lhs), show(rhs));
    let d = natoms as u32;
    let (l, r) = (tm(lhs, d), tm(rhs, d));
    let v = decide(env, ctx, &l, &r, BvOptions { tripwire: false }, &mut budget()).unwrap();
    assert!(matches!(v, BvVerdict::Different(_)), "UNSOUND: the normalizer equates {} and {}", show(lhs), show(rhs));
    let t = Rc::new(Term::BvRefl { ty: mk::int_ty(width(lhs)), lhs: l, rhs: r });
    assert!(env.infer(ctx, &t, &mut budget()).is_err(), "UNSOUND: the kernel accepts {} == {}", show(lhs), show(rhs));
}

#[test]
fn low_chunks_rewiden_to_their_base() {
    let env = prelude();
    let ctx = ctx_of(&env, &[U32, U32]);
    let mut rng = Rng(0x1015);
    for s in bases32() {
        let bytes: Vec<E> = (0..4).map(|k| byte(&s, k)).collect();
        // the four bytes, reassembled
        assert_equal(&env, &ctx, 2, &from_le(U32, &bytes), &s, &mut rng);
        // regrouped into 16-bit halves and back (PBLENDW's view), then reassembled
        assert_equal(&env, &ctx, 2, &from_le(U32, &through_u16(&bytes)), &s, &mut rng);
        // twice (the state packing and unpacking both blend)
        assert_equal(&env, &ctx, 2, &from_le(U32, &through_u16(&through_u16(&bytes))), &s, &mut rng);
        // 16-bit halves
        let halves = [cast(U16, &s), cast(U16, &shr(&s, 16))];
        let from_halves = or(&cast(U32, &halves[0]), &shl(&cast(U32, &halves[1]), 16));
        assert_equal(&env, &ctx, 2, &from_halves, &s, &mut rng);
        // the low byte re-widened next to the second byte is the low half
        assert_equal(&env, &ctx, 2, &from_le(U16, &bytes[..2]), &cast(U16, &s), &mut rng);
        assert_equal(&env, &ctx, 2, &cast(U16, &cast(U8, &s)), &and(&cast(U16, &s), &lit(U16, 0xFF)), &mut rng);
        // chunks of the low half are chunks of the word
        assert_equal(&env, &ctx, 2, &cast(U8, &cast(U16, &s)), &byte(&s, 0), &mut rng);
        assert_equal(&env, &ctx, 2, &cast(U8, &shr(&cast(U16, &s), 8)), &byte(&s, 1), &mut rng);
        assert_equal(&env, &ctx, 2, &cast(U32, &cast(U8, &s)), &and(&s, &lit(U32, 0xFF)), &mut rng);
    }
    // u64 lanes over u32 sums (the `u64` view of two `u32` lanes, as in AVX-512 qword shuffles)
    let ctx3 = ctx_of(&env, &[U32, U32, U32]);
    let (x, y, z) = (atom(0, U32), atom(1, U32), atom(2, U32));
    let (s0, s1) = (add(&x, &y), add(&y, &and(&x, &z)));
    let bytes: Vec<E> = (0..4).map(|k| byte(&s0, k)).chain((0..4).map(|k| byte(&s1, k))).collect();
    let q = from_le(U64, &bytes);
    let q_ref = or(&cast(U64, &s0), &shl(&cast(U64, &s1), 32));
    assert_equal(&env, &ctx3, 3, &q, &q_ref, &mut rng);
    assert_equal(&env, &ctx3, 3, &cast(U32, &q), &s0, &mut rng);
    assert_equal(&env, &ctx3, 3, &cast(U32, &shr(&q, 32)), &s1, &mut rng);
    assert_equal(&env, &ctx3, 3, &from_le(U64, &through_u16(&bytes)), &q_ref, &mut rng);
    // a u64 sum's low half, re-widened through u16 pieces
    let ctx64 = ctx_of(&env, &[U64, U64]);
    let w = add(&atom(0, U64), &atom(1, U64));
    let lo32 = cast(U32, &w);
    let lo_bytes: Vec<E> = (0..4).map(|k| byte(&lo32, k)).collect();
    assert_equal(&env, &ctx64, 2, &from_le(U32, &through_u16(&lo_bytes)), &lo32, &mut rng);
    assert_equal(&env, &ctx64, 2, &cast(U64, &from_le(U32, &through_u16(&lo_bytes))), &and(&w, &lit(U64, 0xFFFF_FFFF)), &mut rng);
}

#[test]
fn near_misses_are_rejected() {
    let env = prelude();
    let ctx = ctx_of(&env, &[U32, U32]);
    let mut rng = Rng(0xBAD);
    let (x, y) = (atom(0, U32), atom(1, U32));
    for s in bases32() {
        let bytes: Vec<E> = (0..4).map(|k| byte(&s, k)).collect();
        // two bytes swapped (before and after the u16 regrouping)
        let mut sw = bytes.clone();
        sw.swap(0, 1);
        assert_rejected(&env, &ctx, 2, &from_le(U32, &through_u16(&sw)), &s, &mut rng);
        let mut sw2 = through_u16(&bytes);
        sw2.swap(1, 2);
        assert_rejected(&env, &ctx, 2, &from_le(U32, &sw2), &s, &mut rng);
        // a byte extracted with a shift off by one
        let mut off = bytes.clone();
        off[1] = cast(U8, &shr(&s, 7));
        assert_rejected(&env, &ctx, 2, &from_le(U32, &through_u16(&off)), &s, &mut rng);
        // the low byte alone is not the low half, nor the word
        assert_rejected(&env, &ctx, 2, &cast(U16, &cast(U8, &s)), &cast(U16, &s), &mut rng);
        assert_rejected(&env, &ctx, 2, &cast(U32, &cast(U16, &s)), &s, &mut rng);
        // a u16 half placed in the wrong half
        let lo = cast(U32, &cast(U16, &s));
        assert_rejected(&env, &ctx, 2, &or(&lo, &shl(&lo, 16)), &s, &mut rng);
    }
    // Aliasing origins: `s` and `s + 256` share their low byte (one narrow
    // class, two wide origins), but not their second byte. Build the low
    // byte from `s2` first, so its recorded origin is `s2`, then mix.
    let s = add(&x, &y);
    let s2 = add(&s, &lit(U32, 0x100));
    let (b0_s2, b1_s, b1_s2) = (byte(&s2, 0), byte(&s, 1), byte(&s2, 1));
    let mixed_true = from_le(U16, &[b0_s2.clone(), b1_s.clone()]); // == s as u16
    let mixed_false = from_le(U16, &[byte(&s, 0), b1_s2.clone()]); // == s2 as u16, != s as u16
    assert_rejected(&env, &ctx, 2, &mixed_false, &cast(U16, &s), &mut rng);
    assert_rejected(&env, &ctx, 2, &mixed_true, &cast(U16, &s2), &mut rng);
    assert_rejected(&env, &ctx, 2, &from_le(U32, &through_u16(&[b0_s2, b1_s2, byte(&s, 2), byte(&s, 3)])), &s, &mut rng);
    // truncation of a sum vs the sum of truncations plus one
    let t = add(&add(&cast(U16, &x), &cast(U16, &y)), &lit(U16, 1));
    assert_rejected(&env, &ctx, 2, &cast(U16, &s), &t, &mut rng);
}

// ---------------------------------------------------------------------------
// Soundness: exhaustive over two bytes, and random cross-width trees.
// ---------------------------------------------------------------------------

/// Classify `exprs` (atoms `x`, `y : U8`) in one normalizer; every class must
/// have a single value table over all 65,536 valuations.
fn exhaustive(env: &Env, name: &str, exprs: &[E]) -> (usize, usize) {
    let ctx = ctx_of(env, &[U8, U8]);
    let terms: Vec<Tm> = exprs.iter().map(|e| tm(e, 2)).collect();
    let classes = classify(env, &ctx, &terms, &mut budget()).unwrap_or_else(|e| panic!("{e}"));
    let table = |e: &Ex| -> Vec<u16> { (0..65536u64).map(|i| eval(e, &[i & 0xFF, i >> 8]) as u16).collect() };
    let mut by_class: HashMap<u32, (usize, Vec<u16>)> = HashMap::new();
    let mut functions: HashMap<Vec<u16>, Vec<u32>> = HashMap::new();
    for (i, e) in exprs.iter().enumerate() {
        let t = table(e);
        match by_class.get(&classes[i]) {
            Some((j, tj)) => assert!(*tj == t, "{name}: UNSOUND: the normalizer equates {} and {}", show(&exprs[*j]), show(e)),
            None => {
                by_class.insert(classes[i], (i, t.clone()));
            }
        }
        let cs = functions.entry(t).or_default();
        if !cs.contains(&classes[i]) {
            cs.push(classes[i]);
        }
    }
    let split = functions.values().filter(|cs| cs.len() > 1).count();
    eprintln!("{name}: {} expressions, {} classes, {} functions, {split} split", exprs.len(), by_class.len(), functions.len());
    (functions.len(), split)
}

#[test]
fn exhaustive_low_chunks_over_two_bytes() {
    let env = prelude();
    let (x, y) = (atom(0, U8), atom(1, U8));
    let (zx, zy) = (cast(U16, &x), cast(U16, &y));
    // U16 bases, several sharing a low byte (s, s + 256, s + 512, s ^ 0x100 …)
    let s = add(&zx, &shl(&zy, 3));
    let bases: Vec<E> = vec![
        s.clone(),
        add(&s, &lit(U16, 0x100)),
        add(&s, &lit(U16, 0x200)),
        xor(&s, &lit(U16, 0x100)),
        add(&zx, &zy),
        add(&add(&zx, &zy), &shl(&zx, 8)),
        and(&rotr(&zx, 4), &add(&zy, &lit(U16, 0x3F7))),
        or(&shl(&zx, 5), &zy),
        ch(&rotr(&zx, 3), &zy, &add(&zx, &zy)),
        bin(B::Sub, &shl(&zy, 8), &zx),
    ];
    let mut es: Vec<E> = Vec::new();
    for b in &bases {
        let (lo, hi) = (byte(b, 0), byte(b, 1));
        es.push(b.clone());
        es.push(lo.clone());
        es.push(hi.clone());
        es.push(cast(U16, &lo));
        es.push(and(b, &lit(U16, 0xFF)));
        es.push(from_le(U16, &[lo.clone(), hi.clone()]));
        es.push(from_le(U16, &[hi.clone(), lo.clone()]));
        es.push(rotr(b, 8));
        es.push(cast(U16, &add(&lo, &x)));
        es.push(cast(U16, &cast(U8, &cast(U16, &lo))));
    }
    // mixes of bytes of different bases (aliasing origins), both orders
    for b1 in &bases {
        for b2 in &bases {
            es.push(from_le(U16, &[byte(b1, 0), byte(b2, 1)]));
            es.push(or(&cast(U16, &byte(b1, 0)), &and(b2, &lit(U16, 0xFF00))));
            es.push(add(&cast(U16, &byte(b1, 0)), &shl(&cast(U16, &byte(b2, 0)), 8)));
        }
    }
    // narrow sums built directly (before and after the wide ones distribute)
    let direct = vec![add(&x, &y), add(&x, &shl(&y, 3)), and(&x, &y), add(&add(&x, &y), &lit(U8, 7))];
    for d in &direct {
        es.push(cast(U16, d));
        es.push(from_le(U16, &[d.clone(), byte(&s, 1)]));
    }
    let mut rng = Rng(0xE8);
    let pool = es.clone();
    for _ in 0..600 {
        let a = pool[rng.below(pool.len() as u64) as usize].clone();
        let e = if width(&a) == U8 {
            match rng.below(3) {
                0 => cast(U16, &a),
                1 => from_le(U16, &[a.clone(), byte(&bases[rng.below(bases.len() as u64) as usize], 1)]),
                _ => cast(U16, &add(&a, &byte(&bases[rng.below(bases.len() as u64) as usize], 0))),
            }
        } else {
            let b = pool.iter().filter(|p| width(p) == U16).nth(rng.below(50) as usize).unwrap().clone();
            match rng.below(5) {
                0 => add(&a, &b),
                1 => xor(&a, &b),
                2 => cast(U16, &byte(&add(&a, &b), rng.below(2) as u32)),
                3 => from_le(U16, &[byte(&a, 0), byte(&b, rng.below(2) as u32)]),
                _ => rotr(&a, rng.below(16) as u32),
            }
        };
        es.push(e);
    }
    // both creation orders of the narrow classes
    exhaustive(&env, "low chunks, U16 over U8 x U8", &es);
    let rev: Vec<E> = es.iter().rev().cloned().collect();
    exhaustive(&env, "low chunks, reversed order", &rev);
}

/// Random trees mixing `u8`/`u16`/`u32`/`u64` casts around sums, sets and
/// truth tables over three `U64` atoms: equal classes must agree on random
/// valuations.
#[test]
fn random_cross_width_trees() {
    let env = prelude();
    let ctx = ctx_of(&env, &[U64, U64, U64]);
    let mut rng = Rng(0xC0FFEE);
    let widths = [U8, U16, U32, U64];
    let mut exprs: Vec<E> = Vec::new();
    for round in 0..40 {
        let mut pool: Vec<E> = (0..3).map(|l| atom(l, U64)).collect();
        for _ in 0..60 {
            let a = pool[rng.below(pool.len() as u64) as usize].clone();
            let w = width(&a);
            let same: Vec<E> = pool.iter().filter(|p| width(p) == w).cloned().collect();
            let b = same[rng.below(same.len() as u64) as usize].clone();
            let e = match rng.below(9) {
                0 | 1 => cast(widths[rng.below(4) as usize], &a),
                2 => add(&a, &b),
                3 => add(&a, &lit(w, rng.next())),
                4 => and(&a, &b),
                5 => ch(&a, &b, &same[rng.below(same.len() as u64) as usize]),
                6 => shr(&a, 8 * rng.below(bits(w) as u64 / 8) as u32),
                7 => rotr(&a, rng.below(bits(w) as u64) as u32),
                _ => {
                    // regroup the bytes of `a` through u16 and back to its width
                    let n = bits(w) / 8;
                    let bs: Vec<E> = (0..n).map(|k| byte(&a, k)).collect();
                    let bs = if n >= 2 { through_u16(&bs) } else { bs };
                    from_le(w, &bs)
                }
            };
            pool.push(e);
        }
        let _ = round;
        exprs.extend(pool.into_iter().skip(3));
    }
    let terms: Vec<Tm> = exprs.iter().map(|e| tm(e, 3)).collect();
    let classes = classify(&env, &ctx, &terms, &mut budget()).unwrap();
    let mut first: HashMap<u32, usize> = HashMap::new();
    let mut checked = 0;
    for (i, e) in exprs.iter().enumerate() {
        if let Some(&j) = first.get(&classes[i]) {
            assert!(agree(&exprs[j], e, 3, &mut rng), "UNSOUND: the normalizer equates {} and {}", show(&exprs[j]), show(e));
            checked += 1;
        } else {
            first.insert(classes[i], i);
        }
    }
    eprintln!("random cross-width trees: {} expressions, {} classes, {checked} equal pairs cross-checked", exprs.len(), first.len());
}
