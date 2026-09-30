//! Axiom schemas (DESIGN.md §5.10): every schema, at every width, is
//! evaluated by the kernel on concrete arguments and compared with an
//! independent native Rust computation of its hypotheses and conclusion.
//! Exhaustive over U8 (all argument tuples), over U16 in each argument
//! (the others over a boundary grid), and at U64/Usize boundaries.
//!
//! K1 (the bit-count definitions, optimizer design §11.4) additionally:
//! exhaustive over U8/U16 with both sides compared to native
//! `count_ones`/`leading_zeros`/`trailing_zeros`; at U32/U64/Usize every
//! single-bit, all-ones-prefix and all-ones-suffix value (and neighbours),
//! 0 and ~0, and 10^7 random values per width (`SANDBLASTER_K1_RANDOM`
//! overrides the count) through a native interpreter of the kernel's
//! statement term, every 1024th value also through the kernel evaluator;
//! the statements are pinned against an independent construction, and the
//! R20 mutations (`lz`/`tz` swapped, off-by-one summand ranges, `<` for
//! `≤`) are rejected by the exhaustive U8/U16 check.

mod common;

use std::rc::Rc;

use num_bigint::BigInt;
use num_traits::ToPrimitive;
use sandblaster_kernel::api::*;
use sandblaster_kernel::axioms::{self, SCHEMAS, Schema};
use sandblaster_kernel::term::*;
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::*;

/// Native meaning of a schema: (hypotheses hold, conclusion holds).
fn native(s: Schema, bits: u32, args: &[u128]) -> (bool, bool) {
    let max: u128 = (1u128 << bits) - 1;
    let m = |x: u128| x & max;
    let rotl = |a: u128, s: u128| {
        let r = (s % bits as u128) as u32;
        if r == 0 { a } else { m((a << r) | (a >> (bits - r))) }
    };
    let rotr = |a: u128, s: u128| {
        let r = (s % bits as u128) as u32;
        if r == 0 { a } else { m((a >> r) | (a << (bits - r))) }
    };
    let (a, b) = (args[0], args.get(1).copied().unwrap_or(0));
    match s {
        Schema::AndLeLeft => (true, (a & b) <= a),
        Schema::AndLeRight => (true, (a & b) <= b),
        Schema::OrGeLeft => (true, a <= (a | b)),
        Schema::OrGeRight => (true, b <= (a | b)),
        Schema::OrLeAdd => (true, (a | b) <= a + b),
        Schema::XorLeOr => (true, (a ^ b) <= (a | b)),
        Schema::ShrLe => (true, (a >> (b % bits as u128)) <= a),
        Schema::MinDefLe => (a <= b, a.min(b) == a),
        Schema::MinDefGt => (a > b, a.min(b) == b),
        Schema::MaxDefLe => (a <= b, a.max(b) == b),
        Schema::MaxDefGt => (a > b, a.max(b) == a),
        Schema::SatSubDefLe => (b <= a, b > a || a.saturating_sub(b) == a - b),
        Schema::SatSubDefGt => (b > a, a.saturating_sub(b) == 0),
        Schema::SatAddDefLe => (a + b <= max, (a + b).min(max) == a + b),
        Schema::SatAddDefGt => (a + b > max, (a + b).min(max) == max),
        Schema::CountOnesLe => (true, a.count_ones() <= bits),
        Schema::RotrRotl => (true, rotr(rotl(a, b), b) == a),
        // Unsigned truncating division/remainder are Euclidean on naturals.
        Schema::DivDef => (b != 0, b == 0 || a / b == (a as i128).div_euclid(b as i128) as u128),
        Schema::RemDef => (b != 0, b == 0 || a % b == (a as i128).rem_euclid(b as i128) as u128),
        Schema::RemLt => (b != 0, b == 0 || a % b < b),
        // K1 statements are definitional identities; their two sides are
        // compared with the native values by `k1_*` below.
        Schema::CountOnesDef | Schema::LeadingZerosDef | Schema::TrailingZerosDef => (true, true),
        _ => unreachable!(),
    }
}

/// Native `leading_zeros` of a `bits`-bit word (independent of the kernel).
fn lz(a: u128, bits: u32) -> u32 {
    (0..bits).take_while(|i| a & (1u128 << (bits - 1 - i)) == 0).count() as u32
}

/// Native `trailing_zeros` of a `bits`-bit word (`bits` for 0).
fn tz(a: u128, bits: u32) -> u32 {
    (0..bits).take_while(|i| a & (1u128 << i) == 0).count() as u32
}

/// Evaluate the axiom's hypotheses and statement at literal data arguments.
/// Returns (all hypotheses hold per the kernel, statement is a true equation).
fn kernel(env: &Env, ax: AxiomId, data: &[BigInt]) -> (bool, bool) {
    let (params, stmt) = axioms::telescope(ax, env.bool_ind()).unwrap();
    let mut entries: Vec<EnvEntry> = Vec::new();
    let mut di = 0;
    let mut hyps = true;
    let mut b = common::budget();
    for (_, rel, ty) in &params {
        let tyv = env.eval(&VEnv(Rc::new(entries.clone())), Lvl(0), ty, &mut b).unwrap();
        match rel {
            Rel::Rel => {
                let w = match &*tyv {
                    Value::IntTy(w) => *w,
                    _ => panic!("data parameter"),
                };
                entries.push(EnvEntry::Rel(Rc::new(Value::Lit { w, n: data[di].clone() })));
                di += 1;
            }
            Rel::Irr => {
                hyps &= eq_holds(env, &tyv);
                entries.push(EnvEntry::Irr(Closure { env: VEnv::default(), body: mk::var(0) }));
            }
        }
    }
    let sv = env.eval(&VEnv(Rc::new(entries)), Lvl(0), &stmt, &mut b).unwrap();
    (hyps, eq_holds(env, &sv))
}

fn eq_holds(env: &Env, v: &V) -> bool {
    match &**v {
        Value::Eq { lhs, rhs, .. } => {
            env.conv(Lvl(0), lhs, rhs, &mut common::budget()).unwrap() && matches!(&**lhs, Value::Lit { .. } | Value::Ctor { .. })
        }
        _ => panic!("statement is not an equation"),
    }
}

fn check_tuple(env: &Env, s: Schema, w: Width, args: &[u128]) {
    let ax = axioms::axiom_id(s, w).unwrap();
    let bits = w.bits().unwrap();
    let (nh, nc) = native(s, bits, args);
    let data: Vec<BigInt> = args.iter().map(|x| BigInt::from(*x)).collect();
    let (kh, kc) = kernel(env, ax, &data);
    assert_eq!(kh, nh, "{} hypotheses at {args:?}", axioms::axiom_name(ax));
    if nh {
        assert!(nc, "native conclusion of {} fails at {args:?}", axioms::axiom_name(ax));
        assert!(kc, "kernel statement of {} is false at {args:?}", axioms::axiom_name(ax));
    }
}

fn arity(s: Schema) -> usize {
    match s {
        Schema::CountOnesLe | Schema::CountOnesDef | Schema::LeadingZerosDef | Schema::TrailingZerosDef => 1,
        Schema::IntToSatDefIn | Schema::IntToSatDefLo | Schema::IntToSatDefHi | Schema::MulMono => 0,
        _ => 2,
    }
}

/// The instantiable machine-width schemas with data arguments (retired
/// schemas are valid at no width).
fn machine_schemas() -> impl Iterator<Item = Schema> {
    SCHEMAS.iter().copied().filter(|s| arity(*s) > 0 && s.valid_at(Width::U8))
}

#[test]
fn u8_exhaustive() {
    let env = Env::new();
    for s in machine_schemas() {
        for a in 0u128..256 {
            if arity(s) == 1 {
                check_tuple(&env, s, Width::U8, &[a]);
                continue;
            }
            for b in 0u128..256 {
                // Shift/rotation amounts are U32: also test amounts ≥ w.
                check_tuple(&env, s, Width::U8, &[a, b]);
            }
        }
    }
}

#[test]
fn u16_each_argument_exhaustive() {
    let env = Env::new();
    let grid: [u128; 3] = [1, 0x8000, 0xffff];
    for s in machine_schemas() {
        for a in 0u128..65536 {
            if arity(s) == 1 {
                check_tuple(&env, s, Width::U16, &[a]);
                continue;
            }
            for &g in &grid {
                check_tuple(&env, s, Width::U16, &[a, g]);
                check_tuple(&env, s, Width::U16, &[g, a]);
            }
        }
    }
}

#[test]
fn u64_and_usize_boundaries() {
    let env = Env::new();
    let vals: Vec<u128> = vec![0, 1, 2, 63, 64, 65, 0xffff_ffff, 1 << 32, (1 << 63) - 1, 1 << 63, (1 << 64) - 2, (1 << 64) - 1];
    for w in [Width::U32, Width::U64, Width::Usize] {
        let max = (1u128 << w.bits().unwrap()) - 1;
        for s in machine_schemas() {
            for &a in &vals {
                let a = a & max;
                if arity(s) == 1 {
                    check_tuple(&env, s, w, &[a]);
                    continue;
                }
                for &b in &vals {
                    let b = if matches!(s, Schema::ShrLe | Schema::RotrRotl) { b & 0xffff_ffff } else { b & max };
                    check_tuple(&env, s, w, &[a, b]);
                }
            }
        }
    }
}

#[test]
fn int_schemas() {
    let env = Env::new();
    // int_to_sat at every machine width.
    for w in [Width::U8, Width::U16, Width::U32, Width::U64, Width::Usize] {
        let max = BigInt::from((1u128 << w.bits().unwrap()) - 1);
        let samples: Vec<BigInt> = vec![
            BigInt::from(-5),
            BigInt::from(-1),
            BigInt::from(0),
            BigInt::from(1),
            max.clone() - 1,
            max.clone(),
            max.clone() + 1,
            max.clone() * 3,
        ];
        for i in &samples {
            for (s, hyp) in [
                (Schema::IntToSatDefIn, *i >= BigInt::from(0) && *i <= max),
                (Schema::IntToSatDefLo, *i < BigInt::from(0)),
                (Schema::IntToSatDefHi, *i > max),
            ] {
                let ax = axioms::axiom_id(s, w).unwrap();
                let (kh, kc) = kernel(&env, ax, std::slice::from_ref(i));
                assert_eq!(kh, hyp, "{} hyps at {i}", axioms::axiom_name(ax));
                if hyp {
                    assert!(kc, "{} at {i}", axioms::axiom_name(ax));
                }
            }
        }
    }
    // mul_mono over a grid of Int values.
    let ax = axioms::axiom_id(Schema::MulMono, Width::Int).unwrap();
    let g: Vec<i64> = vec![-3, -1, 0, 1, 2, 5, 9];
    for &a in &g {
        for &aa in &g {
            for &b in &g {
                for &bb in &g {
                    let data: Vec<BigInt> = [a, aa, b, bb].iter().map(|x| BigInt::from(*x)).collect();
                    let (kh, kc) = kernel(&env, ax, &data);
                    let hyp = 0 <= a && a <= aa && 0 <= b && b <= bb;
                    assert_eq!(kh, hyp);
                    if hyp {
                        assert!(a * b <= aa * bb);
                        assert!(kc, "mul_mono at {a} {aa} {b} {bb}");
                    }
                }
            }
        }
    }
}

#[test]
fn axiom_ids_round_trip() {
    let retired = [Schema::LeadingZerosLe, Schema::TrailingZerosLe, Schema::LeadingZerosLt, Schema::TrailingZerosLt];
    for s in SCHEMAS {
        for w in [Width::U8, Width::U16, Width::U32, Width::U64, Width::Usize, Width::Int] {
            match axioms::axiom_id(s, w) {
                Some(ax) => {
                    assert!(!retired.contains(&s), "retired schema {s:?} is instantiable");
                    assert_eq!(axioms::decode(ax), Some((s, w)));
                    assert_eq!(axioms::axiom_by_name(&axioms::axiom_name(ax)), Some(ax));
                }
                None => assert!(!s.valid_at(w)),
            }
        }
    }
    // Retired schemas keep their slot (the ids of later schemas are
    // unchanged) and are not readable by name any more.
    for s in retired {
        assert!(axioms::axiom_by_name(&format!("{}_u64", s.name())).is_none());
        let slot = SCHEMAS.iter().position(|x| *x == s).unwrap() as u32;
        assert!(axioms::decode(AxiomId(slot * 8 + 3)).is_none());
    }
    // The K1 schemas are appended after every existing one.
    assert_eq!(axioms::axiom_id(Schema::CountOnesDef, Width::U8), Some(AxiomId(28 * 8)));
    assert_eq!(axioms::axiom_id(Schema::TrailingZerosDef, Width::Usize), Some(AxiomId(30 * 8 + 4)));
}

#[test]
fn axioms_typecheck_as_terms() {
    // Every axiom type is a well-formed type, and an application checks.
    let env = Env::new();
    for s in SCHEMAS {
        for w in [Width::U8, Width::U16, Width::U32, Width::U64, Width::Usize, Width::Int] {
            if let Some(ax) = axioms::axiom_id(s, w) {
                let ty = axioms::axiom_type(&env, ax).unwrap();
                env.infer(&Ctx::default(), &ty, &mut common::budget()).unwrap_or_else(|e| panic!("{}: {e}", axioms::axiom_name(ax)));
            }
        }
    }
}

#[test]
fn count_ones_bound_at_every_single_bit_word() {
    // count_ones ≤ w at every width on 0, every single-bit word, its
    // neighbours, and all-ones (its extreme value).
    let env = Env::new();
    for w in [Width::U8, Width::U16, Width::U32, Width::U64, Width::Usize] {
        for a in special_values(w.bits().unwrap()) {
            check_tuple(&env, Schema::CountOnesLe, w, &[a]);
        }
    }
    // 0 has w leading and trailing zeros: the retired strict bounds
    // genuinely needed their hypothesis (the lemmas in bits.core keep it).
    for w in [Width::U8, Width::U64] {
        assert_eq!(lz(0, w.bits().unwrap()), w.bits().unwrap());
        assert_eq!(tz(0, w.bits().unwrap()), w.bits().unwrap());
    }
}

// ---------------------------------------------------------------------------
// K1: count_ones_def, leading_zeros_def, trailing_zeros_def.
// ---------------------------------------------------------------------------

const K1: [Schema; 3] = [Schema::CountOnesDef, Schema::LeadingZerosDef, Schema::TrailingZerosDef];
const MACHINE: [Width; 5] = [Width::U8, Width::U16, Width::U32, Width::U64, Width::Usize];

fn k1_native(s: Schema, bits: u32, a: u128) -> u128 {
    match s {
        Schema::CountOnesDef => a.count_ones() as u128,
        Schema::LeadingZerosDef => lz(a, bits) as u128,
        _ => tz(a, bits) as u128,
    }
}

/// 0, all-ones, every single-bit word, every all-ones prefix (top bits)
/// and suffix (low bits), and their ±1 neighbours.
fn special_values(bits: u32) -> Vec<u128> {
    let max = (1u128 << bits) - 1;
    let mut vals = vec![0u128, max];
    for i in 0..bits {
        let p = 1u128 << i;
        let suffix = (p << 1) - 1;
        let prefix = max ^ (p - 1);
        for x in [p, suffix, prefix, max ^ p] {
            vals.extend([x, x.wrapping_sub(1) & max, (x + 1) & max]);
        }
    }
    vals.sort();
    vals.dedup();
    vals
}

/// A kernel statement compiled to a node list and interpreted natively
/// over machine words (`u128`) and `Int` (`i128`) — an interpreter of the
/// statement term that shares no code with the kernel evaluator. Only the
/// constructs K1 statements use are accepted (anything else panics).
enum Node {
    Arg,
    Lit(i128),
    Prim(PrimOp, Vec<usize>),
    /// `match c : Bool return Int with | false => f | true => t end`.
    Ind(usize, i128, i128),
}

struct Prog {
    nodes: Vec<Node>,
    lhs: usize,
    rhs: usize,
}

fn compile(stmt: &Tm) -> Prog {
    fn go(t: &Tm, nodes: &mut Vec<Node>) -> usize {
        let n = match &**t {
            Term::Var(Idx(0)) => Node::Arg,
            Term::Lit { n, .. } => Node::Lit(n.to_i128().unwrap()),
            Term::Prim { op, args, proofs } if proofs.is_empty() => Node::Prim(*op, args.iter().map(|a| go(a, nodes)).collect()),
            Term::Match { scrut, arms, .. } if arms.len() == 2 && arms.iter().all(|a| a.names.is_empty()) => {
                let lit = |t: &Tm| match &**t {
                    Term::Lit { w: Width::Int, n } => n.to_i128().unwrap(),
                    _ => panic!("match arm is not an Int literal"),
                };
                let c = go(scrut, nodes);
                Node::Ind(c, lit(&arms[0].body), lit(&arms[1].body))
            }
            _ => panic!("unexpected construct in a K1 statement"),
        };
        nodes.push(n);
        nodes.len() - 1
    }
    let Term::Eq { ty, lhs, rhs } = &**stmt else { panic!("statement is not an equation") };
    assert!(matches!(&**ty, Term::IntTy(Width::Int)), "K1 statements are equations in Int");
    let mut nodes = Vec::new();
    let lhs = go(lhs, &mut nodes);
    let rhs = go(rhs, &mut nodes);
    Prog { nodes, lhs, rhs }
}

/// Run a compiled statement at `a`: the values of both sides.
fn run(p: &Prog, a: u128, vals: &mut Vec<i128>) -> (i128, i128) {
    use PrimOp::*;
    vals.clear();
    for n in &p.nodes {
        let v = match n {
            Node::Arg => a as i128,
            Node::Lit(x) => *x,
            Node::Ind(c, f, t) => {
                if vals[*c] != 0 {
                    *t
                } else {
                    *f
                }
            }
            Node::Prim(op, args) => {
                let x = |i: usize| vals[args[i]];
                let bits = |w: Width| w.bits().unwrap() as i128;
                match *op {
                    And(_) => x(0) & x(1),
                    WShr(w) => x(0) >> (x(1) % bits(w)),
                    Lt(_) => (x(0) < x(1)) as i128,
                    Le(_) => (x(0) <= x(1)) as i128,
                    Eq(_) => (x(0) == x(1)) as i128,
                    Cast { to: Width::Int, .. } => x(0),
                    IAdd => x(0) + x(1),
                    CountOnes(_) => (x(0) as u128).count_ones() as i128,
                    LeadingZeros(w) => lz(x(0) as u128, w.bits().unwrap()) as i128,
                    TrailingZeros(w) => tz(x(0) as u128, w.bits().unwrap()) as i128,
                    op => panic!("unexpected primitive {op:?} in a K1 statement"),
                }
            }
        };
        vals.push(v);
    }
    (vals[p.lhs], vals[p.rhs])
}

/// Both sides of the statement at `a`, evaluated by the kernel (must be
/// literals).
fn kernel_sides(env: &Env, stmt: &Tm, w: Width, a: u128, b: &mut Budget) -> (BigInt, BigInt) {
    let venv = VEnv(Rc::new(vec![EnvEntry::Rel(Rc::new(Value::Lit { w, n: BigInt::from(a) }))]));
    let v = env.eval(&venv, Lvl(0), stmt, b).unwrap();
    let Value::Eq { lhs, rhs, .. } = &*v else { panic!("statement is not an equation") };
    match (&**lhs, &**rhs) {
        (Value::Lit { n: l, .. }, Value::Lit { n: r, .. }) => (l.clone(), r.clone()),
        _ => panic!("K1 statement did not evaluate to literals at {a}"),
    }
}

/// A statement under test (the kernel's, or a mutation) with its expected
/// native value.
struct K1Case {
    what: String,
    stmt: Tm,
    prog: Prog,
    s: Schema,
    w: Width,
}

impl K1Case {
    fn kernel(env: &Env, s: Schema, w: Width) -> K1Case {
        let ax = axioms::axiom_id(s, w).unwrap();
        let (params, stmt) = axioms::telescope(ax, env.bool_ind()).unwrap();
        assert_eq!(params.len(), 1);
        let prog = compile(&stmt);
        K1Case { what: axioms::axiom_name(ax), stmt, prog, s, w }
    }

    /// Does the statement hold at `a`: both sides equal the native value
    /// (interpreter; also the kernel evaluator when `with_kernel`)?
    fn holds(&self, env: &Env, a: u128, with_kernel: bool, vals: &mut Vec<i128>) -> bool {
        let bits = self.w.bits().unwrap();
        let n = k1_native(self.s, bits, a) as i128;
        let (l, r) = run(&self.prog, a, vals);
        let ok = l == n && r == n;
        if with_kernel {
            let (kl, kr) = kernel_sides(env, &self.stmt, self.w, a, &mut Budget { steps: 1_000_000 });
            assert_eq!((kl.to_i128().unwrap(), kr.to_i128().unwrap()), (l, r), "{}: kernel and interpreter disagree at {a}", self.what);
        }
        ok
    }
}

#[test]
fn k1_exhaustive_u8_u16() {
    let env = Env::new();
    let mut vals = Vec::new();
    for s in K1 {
        for w in [Width::U8, Width::U16] {
            let c = K1Case::kernel(&env, s, w);
            for a in 0..(1u128 << w.bits().unwrap()) {
                assert!(c.holds(&env, a, true, &mut vals), "{} is false at {a}", c.what);
            }
        }
    }
}

#[test]
fn k1_patterns_at_every_width() {
    let env = Env::new();
    let mut vals = Vec::new();
    for s in K1 {
        for w in MACHINE {
            let c = K1Case::kernel(&env, s, w);
            for a in special_values(w.bits().unwrap()) {
                assert!(c.holds(&env, a, true, &mut vals), "{} is false at {a:#x}", c.what);
            }
        }
    }
}

/// SplitMix64 (deterministic, dependency-free).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

#[test]
fn k1_random_at_u32_u64_usize() {
    let n: u64 = std::env::var("SANDBLASTER_K1_RANDOM").ok().and_then(|s| s.parse().ok()).unwrap_or(10_000_000);
    let env = Env::new();
    let mut vals = Vec::new();
    for w in [Width::U32, Width::U64, Width::Usize] {
        let cases: Vec<K1Case> = K1.iter().map(|s| K1Case::kernel(&env, *s, w)).collect();
        let mut rng = Rng(0x5eed_0000 + w.bits().unwrap() as u64 + if w == Width::Usize { 1 } else { 0 });
        let max = (1u128 << w.bits().unwrap()) - 1;
        for i in 0..n {
            // Mix uniform words with sparse and dense ones (random masks), so
            // the counts cover their whole range.
            let r = rng.next() as u128;
            let a = match i % 4 {
                0 | 1 => r,
                2 => r & rng.next() as u128 & rng.next() as u128,
                _ => r | rng.next() as u128 | rng.next() as u128,
            } & max;
            for c in &cases {
                assert!(c.holds(&env, a, i % 1024 == 0, &mut vals), "{} is false at {a:#x}", c.what);
            }
        }
    }
}

// An independent construction of the K1 statements (and of mutations of
// them), written from the specification in optimizer design §11.4.

#[derive(Clone, Copy)]
enum Summand {
    /// `to_int((a >> i) & 1)`
    Bit,
    /// `[a < 2^m]`
    LtPow,
    /// `[a ≤ 2^m]` (mutation)
    LePow,
    /// `[a & (2^m − 1) = 0]`
    MaskZero,
}

fn k1_stmt(env: &Env, op: PrimOp, w: Width, summand: Summand, range: std::ops::Range<u32>) -> Tm {
    let bi = env.bool_ind();
    let a = || mk::var(0);
    let to_int = |from: Width, t: Tm| mk::prim(PrimOp::Cast { from, to: Width::Int }, vec![t], vec![]);
    let ind = |c: Tm| {
        Rc::new(Term::Match {
            ind: bi,
            params: vec![],
            scrut: c,
            motive: mk::int_ty(Width::Int),
            arms: vec![mk::arm(&[], mk::lit(Width::Int, 0u8)), mk::arm(&[], mk::lit(Width::Int, 1u8))],
        })
    };
    let term = |m: u32| -> Tm {
        match summand {
            Summand::Bit => to_int(
                w,
                mk::prim(
                    PrimOp::And(w),
                    vec![mk::prim(PrimOp::WShr(w), vec![a(), mk::lit(Width::U32, m)], vec![]), mk::lit(w, 1u8)],
                    vec![],
                ),
            ),
            Summand::LtPow => ind(mk::prim(PrimOp::Lt(w), vec![a(), mk::lit(w, 1u128 << m)], vec![])),
            Summand::LePow => ind(mk::prim(PrimOp::Le(w), vec![a(), mk::lit(w, 1u128 << m)], vec![])),
            Summand::MaskZero => ind(mk::prim(
                PrimOp::Eq(w),
                vec![mk::prim(PrimOp::And(w), vec![a(), mk::lit(w, (1u128 << m) - 1)], vec![]), mk::lit(w, 0u8)],
                vec![],
            )),
        }
    };
    let mut it = range.map(term);
    let first = it.next().unwrap();
    let sum = it.fold(first, |acc, t| mk::prim(PrimOp::IAdd, vec![acc, t], vec![]));
    mk::eq(mk::int_ty(Width::Int), to_int(Width::U32, mk::prim(op, vec![a()], vec![])), sum)
}

#[test]
fn k1_statements_match_the_specification() {
    // The kernel's statements, printed, equal the independent construction.
    let env = Env::new();
    for w in MACHINE {
        let n = w.bits().unwrap();
        for (s, op, summand, range) in [
            (Schema::CountOnesDef, PrimOp::CountOnes(w), Summand::Bit, 0..n),
            (Schema::LeadingZerosDef, PrimOp::LeadingZeros(w), Summand::LtPow, 0..n),
            (Schema::TrailingZerosDef, PrimOp::TrailingZeros(w), Summand::MaskZero, 1..n + 1),
        ] {
            let kernel = K1Case::kernel(&env, s, w);
            let spec = k1_stmt(&env, op, w, summand, range);
            let names: Vec<Name> = vec![Rc::from("a")];
            assert_eq!(env.print_term(&names, &kernel.stmt), env.print_term(&names, &spec), "{}", kernel.what);
            // and the statement type-checks as a proposition over `a`
            let ctx = Ctx::default().push(CtxEntry { name: Rc::from("a"), rel: Rel::Rel, ty: Rc::new(Value::IntTy(w)), def: None });
            env.infer(&ctx, &spec, &mut common::budget()).unwrap_or_else(|e| panic!("{}: {e}", kernel.what));
        }
    }
}

#[test]
fn k1_mutations_are_rejected_by_the_exhaustive_tests() {
    // R20 (optimizer design §20): a K1 statement with `lz`/`tz` swapped, an
    // off-by-one summand range or a weakened comparison must fail the
    // exhaustive U8/U16 check.
    let env = Env::new();
    let mut vals = Vec::new();
    for w in [Width::U8, Width::U16] {
        let n = w.bits().unwrap();
        let (co, lzo, tzo) = (PrimOp::CountOnes(w), PrimOp::LeadingZeros(w), PrimOp::TrailingZeros(w));
        let mutations: Vec<(&str, Schema, Tm)> = vec![
            ("lz with the tz sum", Schema::LeadingZerosDef, k1_stmt(&env, lzo, w, Summand::MaskZero, 1..n + 1)),
            ("tz with the lz sum", Schema::TrailingZerosDef, k1_stmt(&env, tzo, w, Summand::LtPow, 0..n)),
            ("lz: m in 1..w", Schema::LeadingZerosDef, k1_stmt(&env, lzo, w, Summand::LtPow, 1..n)),
            ("lz: m in 0..w-1", Schema::LeadingZerosDef, k1_stmt(&env, lzo, w, Summand::LtPow, 0..n - 1)),
            ("lz: ≤ for <", Schema::LeadingZerosDef, k1_stmt(&env, lzo, w, Summand::LePow, 0..n)),
            ("tz: m in 0..w", Schema::TrailingZerosDef, k1_stmt(&env, tzo, w, Summand::MaskZero, 0..n)),
            ("tz: m in 1..w-1", Schema::TrailingZerosDef, k1_stmt(&env, tzo, w, Summand::MaskZero, 1..n)),
            ("tz: m in 2..=w", Schema::TrailingZerosDef, k1_stmt(&env, tzo, w, Summand::MaskZero, 2..n + 1)),
            // (`i in 1..=w` is *not* a mutation: the shift amount is taken
            // mod w, so `(a >> w) & 1` is bit 0.)
            ("count_ones: i in 1..w", Schema::CountOnesDef, k1_stmt(&env, co, w, Summand::Bit, 1..n)),
            ("count_ones: i in 0..=w", Schema::CountOnesDef, k1_stmt(&env, co, w, Summand::Bit, 0..n + 1)),
            ("count_ones: i in 0..w-1", Schema::CountOnesDef, k1_stmt(&env, co, w, Summand::Bit, 0..n - 1)),
        ];
        for (what, s, stmt) in mutations {
            let c = K1Case { what: what.to_string(), prog: compile(&stmt), stmt, s, w };
            let bad = (0..(1u128 << n)).find(|a| !c.holds(&env, *a, true, &mut vals));
            assert!(bad.is_some(), "mutation `{what}` at {w:?} survived the exhaustive test");
        }
    }
}
