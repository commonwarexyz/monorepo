//! `bvnorm` soundness and completeness tests (DESIGN.md §9.8, §10.3;
//! docs/review-1.md, hardware lens).
//!
//! * Every unsound candidate rule from the review is rejected — by the
//!   normalizer alone (tripwire off) and by the kernel's `bvrefl`.
//! * Exhaustive generators over `U8` and `U16` (two byte atoms, or one `U16`
//!   atom: 65536 valuations) targeting the known traps — `not` under
//!   shifts, overlapping `|`/`^`/`+`, casts around sums — plus random
//!   combinations: two expressions in the same normalizer class must have
//!   identical value tables (the normalizer never equates unequal
//!   expressions). Tables are computed by an independent native evaluator.
//! * Structured tests at `u32`/`u64` with **every** shift amount, and random
//!   expression trees whose classes are cross-checked on random valuations.
//! * Equal-by-construction variants (random sound rewrites) measure
//!   completeness (reported, not asserted).
//! * The tripwire rejects sides that differ on a corner or random valuation.

mod common;

use std::collections::HashMap;
use std::rc::Rc;

use common::*;
use sandblaster_kernel::api::*;
use sandblaster_kernel::bvnorm::{BvOptions, BvVerdict, classify, decide, tripwire_agrees};
use sandblaster_kernel::term::*;
use sandblaster_kernel::util::mk;

// ---------------------------------------------------------------------------
// A small expression language with an independent native semantics.
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum Ex {
    /// A context variable (level) of the given width.
    Atom(u32, Width),
    Lit(Width, u64),
    Un(U, E),
    Bin(B, E, E),
    Sh(S, E, u32),
    /// Zero-extension or truncation to the given width.
    Cast(Width, E),
}
type E = Rc<Ex>;

#[derive(Clone, Copy, Debug)]
enum U {
    Not,
    Neg,
}
#[derive(Clone, Copy, Debug, PartialEq)]
enum B {
    And,
    Or,
    Xor,
    Add,
    Sub,
    Mul,
}
#[derive(Clone, Copy, Debug)]
enum S {
    Shl,
    Shr,
    Rotr,
    Rotl,
}

fn bits(w: Width) -> u32 {
    w.bits().unwrap()
}
fn mask(w: Width) -> u64 {
    if bits(w) == 64 { u64::MAX } else { (1u64 << bits(w)) - 1 }
}

fn width(e: &Ex) -> Width {
    match e {
        Ex::Atom(_, w) | Ex::Lit(w, _) | Ex::Cast(w, _) => *w,
        Ex::Un(_, a) | Ex::Sh(_, a, _) => width(a),
        Ex::Bin(_, a, _) => width(a),
    }
}

fn atom(l: u32, w: Width) -> E {
    Rc::new(Ex::Atom(l, w))
}
fn lit(w: Width, n: u64) -> E {
    Rc::new(Ex::Lit(w, n & mask(w)))
}
fn un(u: U, a: &E) -> E {
    Rc::new(Ex::Un(u, a.clone()))
}
fn bin(b: B, x: &E, y: &E) -> E {
    assert_eq!(width(x), width(y));
    Rc::new(Ex::Bin(b, x.clone(), y.clone()))
}
fn sh(s: S, a: &E, k: u32) -> E {
    Rc::new(Ex::Sh(s, a.clone(), k))
}
fn cast(w: Width, a: &E) -> E {
    Rc::new(Ex::Cast(w, a.clone()))
}
fn not(a: &E) -> E {
    un(U::Not, a)
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
fn add(x: &E, y: &E) -> E {
    bin(B::Add, x, y)
}
fn sub(x: &E, y: &E) -> E {
    bin(B::Sub, x, y)
}
fn shl(a: &E, k: u32) -> E {
    sh(S::Shl, a, k)
}
fn shr(a: &E, k: u32) -> E {
    sh(S::Shr, a, k)
}
fn rotr(a: &E, k: u32) -> E {
    sh(S::Rotr, a, k)
}

/// Native semantics (Rust's wrapping operators; shift/rotation amounts mod
/// the width; casts zero-extend or truncate).
fn eval(e: &Ex, env: &[u64]) -> u64 {
    match e {
        Ex::Atom(l, _) => env[*l as usize],
        Ex::Lit(_, n) => *n,
        Ex::Un(u, a) => {
            let (w, v) = (width(a), eval(a, env));
            match u {
                U::Not => !v & mask(w),
                U::Neg => 0u64.wrapping_sub(v) & mask(w),
            }
        }
        Ex::Bin(b, x, y) => {
            let (w, p, q) = (width(x), eval(x, env), eval(y, env));
            (match b {
                B::And => p & q,
                B::Or => p | q,
                B::Xor => p ^ q,
                B::Add => p.wrapping_add(q),
                B::Sub => p.wrapping_sub(q),
                B::Mul => p.wrapping_mul(q),
            }) & mask(w)
        }
        Ex::Sh(s, a, k) => {
            let (w, v) = (width(a), eval(a, env));
            let n = bits(w);
            let k = k % n;
            match s {
                S::Shl => (v << k) & mask(w),
                S::Shr => v >> k,
                S::Rotr | S::Rotl => {
                    let r = if matches!(s, S::Rotr) { k } else { (n - k) % n };
                    if r == 0 { v } else { ((v >> r) | (v << (n - r))) & mask(w) }
                }
            }
        }
        Ex::Cast(w, a) => eval(a, env) & mask(*w),
    }
}

/// The kernel term (context depth `depth`).
fn tm(e: &Ex, depth: u32) -> Tm {
    use PrimOp::*;
    match e {
        Ex::Atom(l, _) => mk::var(depth - 1 - l),
        Ex::Lit(w, n) => mk::lit(*w, *n),
        Ex::Un(u, a) => {
            let w = width(a);
            mk::prim(if matches!(u, U::Not) { Not(w) } else { WNeg(w) }, vec![tm(a, depth)], vec![])
        }
        Ex::Bin(b, x, y) => {
            let w = width(x);
            let op = match b {
                B::And => And(w),
                B::Or => Or(w),
                B::Xor => Xor(w),
                B::Add => WAdd(w),
                B::Sub => WSub(w),
                B::Mul => WMul(w),
            };
            mk::prim(op, vec![tm(x, depth), tm(y, depth)], vec![])
        }
        Ex::Sh(s, a, k) => {
            let w = width(a);
            let op = match s {
                S::Shl => WShl(w),
                S::Shr => WShr(w),
                S::Rotr => Rotr(w),
                S::Rotl => Rotl(w),
            };
            mk::prim(op, vec![tm(a, depth), mk::lit(Width::U32, *k)], vec![])
        }
        Ex::Cast(to, a) => mk::prim(Cast { from: width(a), to: *to }, vec![tm(a, depth)], vec![]),
    }
}

fn show(e: &Ex) -> String {
    match e {
        Ex::Atom(l, _) => ["x", "y", "z"][*l as usize].to_string(),
        Ex::Lit(_, n) => format!("{n:#x}"),
        Ex::Un(u, a) => format!("{}{}", if matches!(u, U::Not) { "!" } else { "-" }, show(a)),
        Ex::Bin(b, x, y) => {
            let o = match b {
                B::And => "&",
                B::Or => "|",
                B::Xor => "^",
                B::Add => "+",
                B::Sub => "-",
                B::Mul => "*",
            };
            format!("({} {o} {})", show(x), show(y))
        }
        Ex::Sh(s, a, k) => format!("{}({}, {k})", ["shl", "shr", "rotr", "rotl"][*s as usize], show(a)),
        Ex::Cast(w, a) => format!("({} as {w:?})", show(a)),
    }
}

/// Deterministic pseudo-random numbers.
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
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len() as u64) as usize]
    }
}

/// A context of fresh variables of the given widths.
fn ctx_of(env: &Env, ws: &[Width]) -> Ctx {
    let mut c = Ctx::default();
    for (i, w) in ws.iter().enumerate() {
        let tv = env.eval(&env.ctx_venv(&c), c.depth(), &mk::int_ty(*w), &mut budget()).unwrap();
        c = c.push(CtxEntry { name: ["x", "y", "z"][i].into(), rel: Rel::Rel, ty: tv, def: None });
    }
    c
}

// ---------------------------------------------------------------------------
// Exhaustive tables over 65536 valuations.
// ---------------------------------------------------------------------------

/// Value tables of every subexpression over all valuations (memoized by node).
struct Tables {
    inputs: Vec<[u64; 2]>,
    memo: HashMap<*const Ex, Rc<Vec<u16>>>,
}

impl Tables {
    fn new(inputs: Vec<[u64; 2]>) -> Self {
        Tables { inputs, memo: HashMap::new() }
    }

    fn table(&mut self, e: &E) -> Rc<Vec<u16>> {
        let key = Rc::as_ptr(e);
        if let Some(t) = self.memo.get(&key) {
            return t.clone();
        }
        let n = self.inputs.len();
        let t: Vec<u16> = match &**e {
            Ex::Atom(l, _) => self.inputs.iter().map(|i| i[*l as usize] as u16).collect(),
            Ex::Lit(_, v) => vec![*v as u16; n],
            Ex::Un(_, a) | Ex::Sh(_, a, _) | Ex::Cast(_, a) => {
                let ta = self.table(a);
                (0..n)
                    .map(|i| {
                        // Re-evaluate the node on the child's value through
                        // the reference semantics.
                        let leaf = Rc::new(Ex::Lit(width(a), ta[i] as u64));
                        let node = match &**e {
                            Ex::Un(u, _) => Ex::Un(*u, leaf),
                            Ex::Sh(s, _, k) => Ex::Sh(*s, leaf, *k),
                            Ex::Cast(w, _) => Ex::Cast(*w, leaf),
                            _ => unreachable!(),
                        };
                        eval(&node, &[]) as u16
                    })
                    .collect()
            }
            Ex::Bin(b, x, y) => {
                let (tx, ty) = (self.table(x), self.table(y));
                let w = width(x);
                (0..n)
                    .map(|i| {
                        let node = Ex::Bin(*b, Rc::new(Ex::Lit(w, tx[i] as u64)), Rc::new(Ex::Lit(w, ty[i] as u64)));
                        eval(&node, &[]) as u16
                    })
                    .collect()
            }
        };
        let t = Rc::new(t);
        self.memo.insert(key, t.clone());
        t
    }
}

/// Classify all expressions in one normalizer; assert that every class has a
/// single value table (soundness); cross-check `decide` (tripwire off)
/// against `classify` on class representatives; return (functions,
/// functions split over several classes).
fn exhaustive(env: &Env, name: &str, atoms: &[Width], exprs: &[E], inputs: Vec<[u64; 2]>) -> (usize, usize) {
    let ctx = ctx_of(env, atoms);
    let depth = atoms.len() as u32;
    let terms: Vec<Tm> = exprs.iter().map(|e| tm(e, depth)).collect();
    let classes = classify(env, &ctx, &terms, &mut budget()).unwrap_or_else(|e| panic!("{e}"));
    let mut tables = Tables::new(inputs);
    let mut by_class: HashMap<u32, usize> = HashMap::new();
    let mut by_table: HashMap<Rc<Vec<u16>>, Vec<u32>> = HashMap::new();
    for (i, e) in exprs.iter().enumerate() {
        let t = tables.table(e);
        match by_class.get(&classes[i]) {
            Some(&j) => {
                let tj = tables.table(&exprs[j]);
                assert!(*tj == *t, "{name}: UNSOUND: the normalizer equates {} and {}, which differ", show(&exprs[j]), show(e));
                // The per-problem entry point agrees.
                let v = decide(env, &ctx, &terms[j], &terms[i], BvOptions { tripwire: false }, &mut budget()).unwrap();
                assert_eq!(v, BvVerdict::Equal, "{name}: decide disagrees with classify on {} vs {}", show(&exprs[j]), show(e));
            }
            None => {
                by_class.insert(classes[i], i);
            }
        }
        let cs = by_table.entry(t).or_default();
        if !cs.contains(&classes[i]) {
            cs.push(classes[i]);
        }
    }
    let split = by_table.values().filter(|cs| cs.len() > 1).count();
    eprintln!(
        "{name}: {} expressions, {} classes, {} distinct functions, {} functions split over several classes",
        exprs.len(),
        by_class.len(),
        by_table.len(),
        split
    );
    (by_table.len(), split)
}

fn dedup(v: Vec<E>) -> Vec<E> {
    let mut seen = std::collections::HashSet::new();
    v.into_iter().filter(|e| seen.insert(show(e))).collect()
}

/// Random combinations of `pool` (same width), deterministic.
fn random_combos(rng: &mut Rng, pool: &[E], n: usize, shifts: &[u32]) -> Vec<E> {
    let mut out = Vec::new();
    let bs = [B::And, B::Or, B::Xor, B::Add, B::Sub, B::Mul];
    let ss = [S::Shl, S::Shr, S::Rotr, S::Rotl];
    for _ in 0..n {
        let a = rng.pick(pool).clone();
        let same: Vec<E> = pool.iter().filter(|b| width(b) == width(&a)).cloned().collect();
        let e = match rng.below(4) {
            0 => not(&a),
            1 => sh(*rng.pick(&ss), &a, *rng.pick(shifts)),
            _ => {
                let b = rng.pick(&same).clone();
                bin(*rng.pick(&bs), &a, &b)
            }
        };
        out.push(e);
    }
    out
}

fn byte_pairs() -> Vec<[u64; 2]> {
    (0..65536u64).map(|i| [i & 0xFF, i >> 8]).collect()
}

#[test]
fn exhaustive_u8_two_atoms() {
    let env = prelude();
    let w = Width::U8;
    let (x, y) = (atom(0, w), atom(1, w));
    let consts: Vec<E> = [0u64, 0xFF, 1, 0x80, 0x0F, 0xF0, 0x55].iter().map(|&c| lit(w, c)).collect();
    let mut es: Vec<E> = vec![x.clone(), y.clone()];
    es.extend(consts.iter().cloned());
    // Not under shifts / rotations, every amount (including ≥ 8: mod 8).
    for k in 0..10u32 {
        for a in [&x, &y] {
            es.push(shr(&not(a), k));
            es.push(not(&shr(a, k)));
            es.push(xor(&shr(a, k), &lit(w, 0xFF >> (k % 8))));
            es.push(shl(&not(a), k));
            es.push(not(&shl(a, k)));
            es.push(xor(&shl(a, k), &lit(w, (0xFF << (k % 8)) & 0xFF)));
            es.push(rotr(&not(a), k));
            es.push(not(&rotr(a, k)));
            es.push(sh(S::Rotl, a, k));
            es.push(rotr(a, (8 - k % 8) % 8));
        }
    }
    // Overlapping and disjoint |, ^, + (bit-slice concatenation traps).
    for (a, b) in [(4, 4), (3, 5), (4, 3), (1, 7), (2, 6), (5, 5), (0, 0)] {
        for (p, q) in [(&x, &y), (&x, &x)] {
            let (l, r) = (shl(p, a), shr(q, b));
            es.push(or(&l, &r));
            es.push(xor(&l, &r));
            es.push(add(&l, &r));
        }
    }
    for (m1, m2) in [(0x0Fu64, 0xF0u64), (0x1F, 0xF0), (0x0F, 0x0F), (0xFF, 0x00), (0x3C, 0xC3), (0x80, 0x7F)] {
        let (l, r) = (and(&x, &lit(w, m1)), and(&y, &lit(w, m2)));
        es.push(or(&l, &r));
        es.push(xor(&l, &r));
        es.push(add(&l, &r));
        let (l2, r2) = (and(&x, &lit(w, m1)), and(&x, &lit(w, m2)));
        es.push(or(&l2, &r2));
        es.push(add(&l2, &r2));
    }
    // Sums vs shifts and rotations.
    for k in [1u32, 3, 7] {
        es.push(shr(&add(&x, &y), k));
        es.push(add(&shr(&x, k), &shr(&y, k)));
        es.push(rotr(&add(&x, &y), k));
        es.push(add(&rotr(&x, k), &rotr(&y, k)));
        es.push(shl(&add(&x, &y), k));
        es.push(add(&shl(&x, k), &shl(&y, k)));
        es.push(bin(B::Mul, &x, &lit(w, 1 << k)));
    }
    es.push(add(&x, &x));
    es.push(shl(&x, 1));
    es.push(sub(&add(&x, &y), &y));
    es.push(add(&xor(&x, &y), &shl(&and(&x, &y), 1)));
    es.push(add(&x, &y));
    es.push(add(&or(&x, &y), &and(&x, &y)));
    es.push(un(U::Neg, &not(&x)));
    es.push(add(&x, &lit(w, 1)));
    // Bitwise identities (truth tables).
    es.push(xor(&or(&x, &y), &and(&x, &y)));
    es.push(xor(&x, &y));
    es.push(or(&x, &y));
    es.push(or(&and(&x, &y), &and(&x, &not(&y))));
    es.push(and(&x, &or(&x, &y)));
    es.push(not(&and(&x, &y)));
    es.push(or(&not(&x), &not(&y)));
    es.push(not(&or(&x, &y)));
    es.push(and(&not(&x), &not(&y)));
    es.push(xor(&xor(&x, &y), &y));
    // Random combinations of everything so far.
    let pool = dedup(es.clone());
    let mut rng = Rng(8);
    es.extend(random_combos(&mut rng, &pool, 400, &[0, 1, 2, 3, 4, 5, 7, 8, 9]));
    let es = dedup(es);
    exhaustive(&env, "U8 x U8", &[w, w], &es, byte_pairs());
}

#[test]
fn exhaustive_u16_byte_atoms_and_casts() {
    let env = prelude();
    let (w8, w16) = (Width::U8, Width::U16);
    let (x, y) = (atom(0, w8), atom(1, w8));
    let (zx, zy) = (cast(w16, &x), cast(w16, &y));
    let mut es: Vec<E> = vec![zx.clone(), zy.clone()];
    // Byte concatenation: disjoint vs overlapping |, ^, +.
    for (a, b) in [(8u32, 0u32), (4, 0), (8, 4), (7, 0), (9, 0), (8, 8), (12, 4), (0, 8)] {
        let (l, r) = (shl(&zx, a), shl(&zy, b));
        es.push(or(&l, &r));
        es.push(xor(&l, &r));
        es.push(add(&l, &r));
    }
    es.push(add(&bin(B::Mul, &zx, &lit(w16, 256)), &zy));
    // Casts around sums: zero-extension does not distribute, truncation does.
    let s8 = add(&x, &y);
    let s16 = add(&zx, &zy);
    es.push(cast(w16, &s8));
    es.push(s16.clone());
    es.push(and(&s16, &lit(w16, 0xFF)));
    es.push(cast(w16, &cast(w8, &s16)));
    es.push(cast(w16, &sub(&x, &y)));
    es.push(sub(&zx, &zy));
    es.push(cast(w16, &un(U::Neg, &x)));
    es.push(un(U::Neg, &zx));
    es.push(cast(w16, &not(&x)));
    es.push(not(&zx));
    es.push(xor(&zx, &lit(w16, 0xFF)));
    es.push(cast(w16, &shl(&x, 4)));
    es.push(and(&shl(&zx, 4), &lit(w16, 0xFF)));
    es.push(shl(&zx, 4));
    es.push(cast(w16, &rotr(&x, 3)));
    es.push(rotr(&zx, 3));
    // Byte extraction from a concatenation, every shift amount.
    let cat = or(&shl(&zx, 8), &zy);
    for k in 0..16u32 {
        let e = shr(&cat, k);
        es.push(cast(w16, &cast(w8, &e)));
        es.push(and(&e, &lit(w16, 0xFF)));
        es.push(rotr(&cat, k));
        es.push(e);
    }
    es.push(cast(w16, &x));
    es.push(rotr(&cat, 8));
    es.push(or(&shl(&zy, 8), &zx));
    // Random combinations at U16 (and truncations to U8 zero-extended back).
    let pool = dedup(es.clone());
    let mut rng = Rng(16);
    let mut extra = random_combos(&mut rng, &pool, 400, &[0, 1, 3, 4, 7, 8, 9, 12, 15, 16, 17]);
    for _ in 0..80 {
        let e = rng.pick(&pool).clone();
        let t = cast(w8, &e);
        extra.push(cast(w16, &add(&t, rng.pick(&[x.clone(), y.clone()]))));
        extra.push(cast(w16, &xor(&t, &shr(&x, 1))));
    }
    es.extend(extra);
    let es = dedup(es);
    exhaustive(&env, "U16 over U8 x U8", &[w8, w8], &es, byte_pairs());
}

#[test]
fn exhaustive_u16_one_atom() {
    let env = prelude();
    let (w8, w16) = (Width::U8, Width::U16);
    let z = atom(0, w16);
    let (lo, hi) = (cast(w8, &z), cast(w8, &shr(&z, 8)));
    let mut es: Vec<E> = vec![z.clone(), lo.clone(), hi.clone()];
    es.push(or(&shl(&cast(w16, &hi), 8), &cast(w16, &lo)));
    es.push(add(&shl(&cast(w16, &hi), 8), &cast(w16, &lo)));
    es.push(or(&shl(&cast(w16, &lo), 8), &cast(w16, &hi)));
    es.push(rotr(&z, 8));
    for k in 0..17u32 {
        es.push(or(&shr(&z, k), &shl(&z, 16 - k % 16)));
        es.push(xor(&shr(&z, k), &shl(&z, 16 - k % 16)));
        es.push(add(&shr(&z, k), &shl(&z, 16 - k % 16)));
        es.push(rotr(&z, k));
        es.push(shr(&not(&z), k));
        es.push(not(&shr(&z, k)));
        es.push(cast(w16, &cast(w8, &shr(&z, k))));
        es.push(cast(w16, &cast(w8, &rotr(&z, k))));
        es.push(shr(&shl(&z, k), k));
        es.push(and(&z, &lit(w16, 0xFFFF >> (k % 16))));
        es.push(shl(&shr(&z, k), k));
        es.push(and(&z, &lit(w16, (0xFFFF << (k % 16)) & 0xFFFF)));
    }
    es.push(add(&z, &z));
    es.push(shl(&z, 1));
    es.push(cast(w16, &add(&lo, &hi)));
    es.push(and(&add(&cast(w16, &lo), &cast(w16, &hi)), &lit(w16, 0xFF)));
    es.push(add(&cast(w16, &lo), &cast(w16, &hi)));
    let pool = dedup(es.clone());
    let mut rng = Rng(1616);
    es.extend(random_combos(&mut rng, &pool, 300, &[0, 1, 4, 8, 12, 15, 16, 20]));
    let es = dedup(es);
    let inputs: Vec<[u64; 2]> = (0..65536u64).map(|i| [i, 0]).collect();
    exhaustive(&env, "U16 one atom", &[w16], &es, inputs);
}

// ---------------------------------------------------------------------------
// u32 / u64: structured identities with every shift amount.
// ---------------------------------------------------------------------------

/// Agreement on corner and pseudo-random valuations (native).
fn agree(a: &Ex, b: &Ex, natoms: usize, rng: &mut Rng) -> bool {
    let w = width(a);
    let corners = [0u64, mask(w), 1, (mask(w) >> 1) + 1];
    for &c in &corners {
        let env = vec![c; natoms];
        if eval(a, &env) != eval(b, &env) {
            return false;
        }
    }
    for _ in 0..600 {
        let env: Vec<u64> = (0..natoms).map(|_| rng.next()).collect();
        let env: Vec<u64> = env.iter().map(|v| v & mask(w)).collect();
        if eval(a, &env) != eval(b, &env) {
            return false;
        }
    }
    true
}

#[test]
fn structured_u32_u64_every_shift_amount() {
    let env = prelude();
    let mut rng = Rng(3264);
    let (mut proven, mut expected) = (0, 0);
    for w in [Width::U32, Width::U64] {
        let n = bits(w);
        let ctx = ctx_of(&env, &[w, w]);
        let (x, y) = (atom(0, w), atom(1, w));
        let m = mask(w);
        for s in 0..n {
            let t = (n - s) % n;
            // (lhs, rhs, the normalizer is expected to prove it when true)
            let cases: Vec<(E, E, bool)> = vec![
                (or(&shr(&x, s), &shl(&x, t)), rotr(&x, s), true),
                (xor(&shr(&x, s), &shl(&x, t)), rotr(&x, s), true),
                (add(&shr(&x, s), &shl(&x, t)), rotr(&x, s), true),
                (shr(&not(&x), s), not(&shr(&x, s)), true),
                (shr(&not(&x), s), xor(&shr(&x, s), &lit(w, m >> s)), true),
                (shl(&not(&x), s), xor(&shl(&x, s), &lit(w, (m << s) & m)), true),
                (rotr(&not(&x), s), not(&rotr(&x, s)), true),
                (sh(S::Rotl, &x, s), rotr(&x, t), true),
                (shl(&x, s), bin(B::Mul, &x, &lit(w, 1u64 << s)), true),
                (shr(&add(&x, &y), s), add(&shr(&x, s), &shr(&y, s)), true),
                (rotr(&add(&x, &y), s), add(&rotr(&x, s), &rotr(&y, s)), true),
                (shl(&add(&x, &y), s), add(&shl(&x, s), &shl(&y, s)), true),
                (and(&shr(&x, s), &shl(&x, t)), lit(w, 0), true),
                (cast(Width::U8, &shr(&x, s)), cast(Width::U8, &rotr(&x, s)), true),
                (cast(w, &cast(Width::U8, &shr(&x, s))), and(&shr(&x, s), &lit(w, 0xFF)), true),
                (shr(&shl(&x, s), s), and(&x, &lit(w, m >> s)), true),
                (shl(&shr(&x, s), s), and(&x, &lit(w, (m << s) & m)), true),
                (or(&shl(&x, s), &shr(&y, t)), xor(&shl(&x, s), &shr(&y, t)), true),
                (or(&shl(&x, s), &shr(&y, t)), add(&shl(&x, s), &shr(&y, t)), true),
                (cast(w, &cast(Width::U16, &add(&x, &y))), add(&x, &y), false),
                (cast(Width::U16, &add(&x, &y)), add(&cast(Width::U16, &x), &cast(Width::U16, &y)), true),
                (
                    cast(w, &add(&cast(Width::U16, &x), &cast(Width::U16, &y))),
                    add(&cast(w, &cast(Width::U16, &x)), &cast(w, &cast(Width::U16, &y))),
                    true,
                ),
                (rotr(&rotr(&x, s), t), x.clone(), true),
                (shr(&shr(&x, s), 1), shr(&x, s + 1), true),
            ];
            let lt: Vec<Tm> = cases.iter().map(|c| tm(&c.0, 2)).collect();
            let rt: Vec<Tm> = cases.iter().map(|c| tm(&c.1, 2)).collect();
            for (i, (a, b, expect)) in cases.iter().enumerate() {
                let truth = agree(a, b, 2, &mut rng);
                let v = decide(&env, &ctx, &lt[i], &rt[i], BvOptions { tripwire: false }, &mut budget()).unwrap();
                if v == BvVerdict::Equal {
                    assert!(truth, "UNSOUND at {w:?}, s = {s}: {} == {}", show(a), show(b));
                }
                if truth && *expect {
                    expected += 1;
                    assert_eq!(v, BvVerdict::Equal, "incomplete at {w:?}, s = {s}: {} == {}", show(a), show(b));
                    proven += 1;
                }
                // The kernel rule (with the tripwire) agrees with the verdict.
                let t = Rc::new(Term::BvRefl { ty: mk::int_ty(width(a)), lhs: lt[i].clone(), rhs: rt[i].clone() });
                let r = env.infer(&ctx, &t, &mut budget());
                assert_eq!(r.is_ok(), v == BvVerdict::Equal, "{} vs {}: {r:?}", show(a), show(b));
            }
        }
    }
    eprintln!("structured u32/u64: {proven}/{expected} designed identities proven");
}

/// Random expression trees at u32/u64 over three atoms: every normalizer
/// class is cross-checked on random valuations; equal-by-construction
/// variants measure completeness.
#[test]
fn random_trees_u32_u64() {
    let env = prelude();
    let mut rng = Rng(0xB17);
    for w in [Width::U32, Width::U64] {
        let n = bits(w);
        let ctx = ctx_of(&env, &[w, w, w]);
        let atoms = [atom(0, w), atom(1, w), atom(2, w)];
        fn gen_tree(rng: &mut Rng, atoms: &[E], w: Width, n: u32, depth: u32) -> E {
            if depth == 0 || rng.below(5) == 0 {
                return if rng.below(6) == 0 { lit(w, rng.next()) } else { rng.pick(atoms).clone() };
            }
            let a = gen_tree(rng, atoms, w, n, depth - 1);
            match rng.below(10) {
                0 => not(&a),
                1 | 2 => sh(*rng.pick(&[S::Shl, S::Shr, S::Rotr, S::Rotl]), &a, rng.below(2 * n as u64) as u32),
                3 => {
                    let nw = *rng.pick(&[Width::U8, Width::U16, Width::U32]);
                    if bits(nw) < n { cast(w, &cast(nw, &a)) } else { a }
                }
                _ => {
                    let b = gen_tree(rng, atoms, w, n, depth - 1);
                    bin(*rng.pick(&[B::And, B::Or, B::Xor, B::Add, B::Sub, B::Mul, B::Xor, B::Add]), &a, &b)
                }
            }
        }
        // Sound rewrites producing equal-by-construction variants.
        fn variant(rng: &mut Rng, e: &E, atoms: &[E]) -> E {
            let w = width(e);
            let n = bits(w);
            let r = match &**e {
                Ex::Bin(b, x, y) => {
                    let (x, y) = (variant(rng, x, atoms), variant(rng, y, atoms));
                    match (b, rng.below(3)) {
                        (B::And | B::Or | B::Xor | B::Add | B::Mul, 0) => bin(*b, &y, &x),
                        (B::Sub, 0) => add(&x, &un(U::Neg, &y)),
                        _ => bin(*b, &x, &y),
                    }
                }
                Ex::Un(U::Not, a) => {
                    let a = variant(rng, a, atoms);
                    if rng.below(2) == 0 { xor(&a, &lit(w, mask(w))) } else { not(&a) }
                }
                Ex::Un(u, a) => un(*u, &variant(rng, a, atoms)),
                Ex::Sh(s, a, k) => {
                    let a = variant(rng, a, atoms);
                    let k = *k % n;
                    match (s, rng.below(2)) {
                        (S::Shl, 0) => bin(B::Mul, &a, &lit(w, 1u64 << k)),
                        (S::Rotl, 0) => rotr(&a, (n - k) % n),
                        (S::Shr, 0) => and(&rotr(&a, k), &lit(w, mask(w) >> k)),
                        _ => sh(*s, &a, k),
                    }
                }
                Ex::Cast(t, a) => cast(*t, &variant(rng, a, atoms)),
                _ => e.clone(),
            };
            match if width(&r) == width(&atoms[0]) { rng.below(8) } else { 7 } {
                0 => {
                    let b = rng.pick(atoms).clone();
                    xor(&xor(&r, &b), &b)
                }
                1 => {
                    let b = rng.pick(atoms).clone();
                    add(&sub(&r, &b), &b)
                }
                _ => r,
            }
        }
        let exprs: Vec<E> = (0..300).map(|_| gen_tree(&mut rng, &atoms, w, n, 4)).collect();
        let variants: Vec<E> = exprs.iter().map(|e| variant(&mut rng, e, &atoms)).collect();
        let mut all = exprs.clone();
        all.extend(variants.iter().cloned());
        let terms: Vec<Tm> = all.iter().map(|e| tm(e, 3)).collect();
        let classes = classify(&env, &ctx, &terms, &mut budget()).unwrap();
        let mut rep: HashMap<u32, usize> = HashMap::new();
        for (i, e) in all.iter().enumerate() {
            match rep.get(&classes[i]) {
                Some(&j) => assert!(agree(&all[j], e, 3, &mut rng), "UNSOUND at {w:?}: {} == {}", show(&all[j]), show(e)),
                None => {
                    rep.insert(classes[i], i);
                }
            }
        }
        let same = (0..exprs.len()).filter(|&i| classes[i] == classes[exprs.len() + i]).count();
        eprintln!(
            "random trees {w:?}: {} classes for {} expressions; {same}/{} rewritten variants proven equal",
            rep.len(),
            all.len(),
            exprs.len()
        );
    }
}

// ---------------------------------------------------------------------------
// The unsound candidates of docs/review-1.md (hardware lens) and the
// tripwire.
// ---------------------------------------------------------------------------

#[test]
fn review_unsound_candidates_are_rejected() {
    let env = prelude();
    let ctx = ctx_of(&env, &[Width::U8, Width::U8, Width::U8]);
    let names = ["x", "b", "c"];
    for (ty, lhs, rhs) in [
        // Shifts do not distribute over `not` (x = 0: 0x7F vs 0xFF; 0xFE vs 0xFF).
        ("U8", "#wshr_u8(#not_u8(x), 1u32)", "#not_u8(#wshr_u8(x, 1u32))"),
        ("U8", "#wshl_u8(#not_u8(x), 1u32)", "#not_u8(#wshl_u8(x, 1u32))"),
        ("U16", "#wshr_u16(#not_u16(#cast_u8_u16(x)), 3u32)", "#not_u16(#wshr_u16(#cast_u8_u16(x), 3u32))"),
        // Overlapping pieces are not a concatenation (b = 1, c = 0x10).
        (
            "U32",
            "#or_u32(#wshl_u32(#cast_u8_u32(b), 8u32), #wshl_u32(#cast_u8_u32(c), 4u32))",
            "#xor_u32(#wshl_u32(#cast_u8_u32(b), 8u32), #wshl_u32(#cast_u8_u32(c), 4u32))",
        ),
        (
            "U32",
            "#or_u32(#wshl_u32(#cast_u8_u32(b), 8u32), #wshl_u32(#cast_u8_u32(c), 4u32))",
            "#wadd_u32(#wshl_u32(#cast_u8_u32(b), 8u32), #wshl_u32(#cast_u8_u32(c), 4u32))",
        ),
        // `+` is not a concatenation (carries).
        ("U8", "#wadd_u8(x, b)", "#or_u8(x, b)"),
        ("U8", "#wadd_u8(x, b)", "#xor_u8(x, b)"),
        // Zero-extension does not distribute over sums (a = b = 0x80).
        ("U32", "#cast_u8_u32(#wadd_u8(b, c))", "#wadd_u32(#cast_u8_u32(b), #cast_u8_u32(c))"),
        ("U16", "#cast_u8_u16(#wsub_u8(b, c))", "#wsub_u16(#cast_u8_u16(b), #cast_u8_u16(c))"),
        ("U16", "#cast_u8_u16(#wmul_u8(b, 3u8))", "#wmul_u16(#cast_u8_u16(b), 3u16)"),
        // The byte k of a sum is not the sum of the bytes k.
        (
            "U8",
            "#cast_u16_u8(#wshr_u16(#wadd_u16(#cast_u8_u16(b), #cast_u8_u16(c)), 8u32))",
            "#wadd_u8(#cast_u16_u8(#wshr_u16(#cast_u8_u16(b), 8u32)), #cast_u16_u8(#wshr_u16(#cast_u8_u16(c), 8u32)))",
        ),
        // wshr and rotr do not distribute over sums ((a+b)>>1 at a = b = 1).
        ("U8", "#wshr_u8(#wadd_u8(x, b), 1u32)", "#wadd_u8(#wshr_u8(x, 1u32), #wshr_u8(b, 1u32))"),
        ("U8", "#rotr_u8(#wadd_u8(x, b), 3u32)", "#wadd_u8(#rotr_u8(x, 3u32), #rotr_u8(b, 3u32))"),
        // Rotation amounts reduce mod w before rotl → rotr (rotl(x, 8) is x).
        ("U8", "#rotl_u8(x, 8u32)", "#rotr_u8(x, 1u32)"),
        ("U8", "#rotl_u8(x, 0u32)", "#rotr_u8(x, 7u32)"),
        // Truth-table canonicalization must see through cancellation only when exact.
        ("U8", "#xor_u8(#xor_u8(x, x), b)", "#xor_u8(x, b)"),
        ("U8", "#and_u8(x, #or_u8(b, c))", "#or_u8(#and_u8(x, b), c)"),
    ] {
        let lt = env.parse_term(&names, lhs).unwrap();
        let rt = env.parse_term(&names, rhs).unwrap();
        // The normalizer alone (no tripwire) rejects ...
        let v = decide(&env, &ctx, &lt, &rt, BvOptions { tripwire: false }, &mut budget()).unwrap();
        assert!(matches!(v, BvVerdict::Different(_)), "normalizer accepted {lhs} == {rhs}: {v:?}");
        // ... and so does the kernel rule.
        let t = env.parse_term(&names, &format!("bvrefl({ty}, {lhs}, {rhs})")).unwrap();
        let r = env.infer(&ctx, &t, &mut budget());
        assert_eq!(r.map(|_| ()).map_err(|e| e.kind), Err(KernelErrorKind::BvRefl), "{lhs} == {rhs}");
    }
    // The sound versions are accepted.
    for (ty, lhs, rhs) in [
        ("U8", "#wshr_u8(#not_u8(x), 1u32)", "#xor_u8(#wshr_u8(x, 1u32), 127u8)"),
        ("U8", "#cast_u16_u8(#wadd_u16(#cast_u8_u16(b), #cast_u8_u16(c)))", "#wadd_u8(b, c)"),
        (
            "U32",
            "#or_u32(#wshl_u32(#cast_u8_u32(b), 8u32), #cast_u8_u32(c))",
            "#wadd_u32(#wshl_u32(#cast_u8_u32(b), 8u32), #cast_u8_u32(c))",
        ),
        ("U8", "#rotl_u8(x, 8u32)", "x"),
        ("U8", "#rotl_u8(x, 3u32)", "#rotr_u8(x, 5u32)"),
        ("U8", "#xor_u8(#xor_u8(x, x), b)", "b"),
    ] {
        let t = env.parse_term(&names, &format!("bvrefl({ty}, {lhs}, {rhs})")).unwrap();
        env.infer(&ctx, &t, &mut budget()).unwrap_or_else(|e| panic!("{lhs} == {rhs}: {e}"));
    }
}

#[test]
fn tripwire_detects_differences() {
    let env = prelude();
    let names = ["x", "y", "f"];
    let mut ctx = ctx_of(&env, &[Width::U32, Width::U32]);
    let fty = env.eval(&env.ctx_venv(&ctx), ctx.depth(), &env.parse_term(&[], "U32 -> U32").unwrap(), &mut budget()).unwrap();
    ctx = ctx.push(CtxEntry { name: "f".into(), rel: Rel::Rel, ty: fty, def: None });
    let agrees = |l: &str, r: &str| {
        let lt = env.parse_term(&names, l).unwrap();
        let rt = env.parse_term(&names, r).unwrap();
        tripwire_agrees(&env, &ctx, &lt, &rt, &mut budget()).unwrap()
    };
    // Equal sides agree (atoms are consistent across both DAGs, and
    // uninterpreted applications depend on their concrete arguments only).
    assert!(agrees("#wadd_u32(x, y)", "#wadd_u32(y, x)"));
    assert!(agrees("f #wadd_u32(x, y)", "f #wadd_u32(y, x)"));
    assert!(agrees("f (#xor_u32(x, 0u32))", "f x"));
    assert!(agrees("#rotr_u32(x, 7u32)", "#or_u32(#wshr_u32(x, 7u32), #wshl_u32(x, 25u32))"));
    // Different sides are caught by random valuations ...
    assert!(!agrees("#wadd_u32(x, 1u32)", "x"));
    assert!(!agrees("f x", "f y"));
    assert!(!agrees("#wshr_u32(#not_u32(x), 1u32)", "#not_u32(#wshr_u32(x, 1u32))"));
    // ... and by the corner valuations when they differ only there.
    for c in ["0u32", "4294967295u32", "1u32", "2147483648u32"] {
        let l = format!("bool::as_u32 #eq_u32(x, {c})");
        assert!(!agrees(&l, "0u32"), "corner {c}");
        assert!(agrees(&l, &l));
    }
    // A match on a comparison takes the arm selected on each valuation.
    assert!(agrees(
        "match #lt_u32(x, y) : Bool as _ return U32 with | false => x | true => y end",
        "match #lt_u32(x, y) : Bool as _ return U32 with | false => #xor_u32(x, 0u32) | true => #rotr_u32(y, 32u32) end"
    ));
    assert!(!agrees(
        "match #lt_u32(x, y) : Bool as _ return U32 with | false => x | true => y end",
        "match #lt_u32(x, y) : Bool as _ return U32 with | false => y | true => x end"
    ));
}

#[test]
fn bvrefl_in_the_kernel() {
    let mut env = prelude();
    // Word algebra modulo intrinsics (unfolded by BvRefl only) and opaque
    // definitions (unfolded by BvRefl, which evaluates transparently since
    // phase 3; never by conversion).
    load(
        &mut env,
        "def[intrinsic] twice : (x : U32) -> U32 := fun (x : U32) => #wadd_u32(x, x)\n\
         def[intrinsic, opaque] otwice : (x : U32) -> U32 := fun (x : U32) => #wadd_u32(x, x)",
    )
    .unwrap();
    assert!(
        check(&env, "fun (x : U32) => bvrefl(U32, twice x, #wshl_u32(x, 1u32))", "(x : U32) -> Eq(U32, twice x, #wshl_u32(x, 1u32))")
            .is_ok()
    );
    assert!(check(&env, "fun (x : U32) => refl(U32, twice x)", "(x : U32) -> Eq(U32, twice x, #wshl_u32(x, 1u32))").is_err());
    assert!(
        check(&env, "fun (x : U32) => bvrefl(U32, otwice x, #wshl_u32(x, 1u32))", "(x : U32) -> Eq(U32, otwice x, #wshl_u32(x, 1u32))")
            .is_ok()
    );
    assert!(check(&env, "fun (x : U32) => refl(U32, otwice x)", "(x : U32) -> Eq(U32, otwice x, #wshl_u32(x, 1u32))").is_err());
    assert!(
        check(&env, "fun (x : U32) => bvrefl(U32, otwice x, #wshl_u32(x, 2u32))", "(x : U32) -> Eq(U32, otwice x, #wshl_u32(x, 2u32))")
            .is_err()
    );
    // An intrinsic in a let-bound context value (evaluated in the default
    // mode, so still folded) is unfolded by BvRefl.
    assert!(
        check(
            &env,
            "fun (x : U32) => let t : U32 = twice x; bvrefl(U32, t, #wadd_u32(x, x))",
            "(x : U32) -> Eq(U32, twice x, #wadd_u32(x, x))"
        )
        .is_ok()
    );
    // Arrays: element-wise word algebra under array eta.
    let arr = "pair(Array U32 2usize, Cons[U32](#xor_u32(array::index U32 2usize a 0usize .refl(Bool, true), 0u32), \
                 Cons[U32](#rotr_u32(array::index U32 2usize a 1usize .refl(Bool, true), 32u32), Nil[U32])), refl(Int, 2int))";
    assert!(
        check(
            &env,
            &format!("fun (a : Array U32 2usize) => bvrefl(Array U32 2usize, a, {arr})"),
            &format!("(a : Array U32 2usize) -> Eq(Array U32 2usize, a, {arr})")
        )
        .is_ok()
    );
    assert!(
        check(
            &env,
            "fun (a : Array U32 2usize) => refl(Array U32 2usize, a)",
            &format!("(a : Array U32 2usize) -> Eq(Array U32 2usize, a, {arr})")
        )
        .is_err()
    );
    // Functions: compared at a fresh variable.
    assert!(
        check(
            &env,
            "bvrefl(U32 -> U32, fun (x : U32) => #or_u32(#wshr_u32(x, 2u32), #wshl_u32(x, 30u32)), fun (x : U32) => #rotr_u32(x, 2u32))",
            "Eq(U32 -> U32, fun (x : U32) => #or_u32(#wshr_u32(x, 2u32), #wshl_u32(x, 30u32)), fun (x : U32) => #rotr_u32(x, 2u32))"
        )
        .is_ok()
    );
    assert!(
        check(
            &env,
            "bvrefl(U32 -> U32, fun (x : U32) => x, fun (x : U32) => #not_u32(x))",
            "Eq(U32 -> U32, fun (x : U32) => x, fun (x : U32) => x)"
        )
        .is_err()
    );
    // Checked operations are their wrapping forms (they carry domain proofs).
    assert!(
        check(
            &env,
            "fun (x : U8) (.h : Eq(Bool, #le_int(#iadd(#cast_u8_int(x), 1int), 255int), true)) => bvrefl(U8, #add_u8(x, 1u8; h), #wadd_u8(1u8, x))",
            "(x : U8) -> (.h : Eq(Bool, #le_int(#iadd(#cast_u8_int(x), 1int), 255int), true)) -> Eq(U8, #add_u8(x, 1u8; h), #wadd_u8(1u8, x))"
        )
        .is_ok()
    );
    // Comparisons normalize their arguments; a match on a decided comparison
    // takes its arm.
    assert!(
        check(
            &env,
            "fun (x : U32) (y : U32) => bvrefl(Bool, #lt_u32(#wadd_u32(x, y), y), #gt_u32(y, #wadd_u32(y, x)))",
            "(x : U32) -> (y : U32) -> Eq(Bool, #lt_u32(#wadd_u32(x, y), y), #gt_u32(y, #wadd_u32(y, x)))"
        )
        .is_ok()
    );
    assert!(
        check(
            &env,
            "fun (x : U32) => bvrefl(U32, match #eq_u32(#xor_u32(x, x), 0u32) : Bool as _ return U32 with | false => 0u32 | true => x end, x)",
            "(x : U32) -> Eq(U32, match #eq_u32(#xor_u32(x, x), 0u32) : Bool as _ return U32 with | false => 0u32 | true => x end, x)"
        )
        .is_ok()
    );
}
