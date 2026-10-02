//! Fairness guard (audit of 2026-10-02, J3/J4): the closed-form search of
//! Σ2 takes its constants from the loop under summary, never from a fixed
//! list of a benchmark's constants (it used to carry LEB128's `6`, `7`,
//! `/7`, `128`, `2^14` and the MMR's `2^61`–`2^63`).
//!
//! What may be fixed is what the width gives: the leaves `{0, 1, 2, W − 1,
//! W}` and, for the trace corners, `0` and `2^k − 1`, `2^k`, `2^k + 1` for
//! `k ≤ W`. Everything else must be harvested (`opt::loopsum::pool`):
//!
//! * `harvested_constants_come_from_the_loop`: a loop shifting by 5 gets
//!   divisor 5, thresholds 32 and 1024, leaves 4, 5, 32;
//! * `a_loop_without_literals_gets_only_width_constants`: a loop with no
//!   literal gets none of the audit's target constants in the synthesis
//!   leaves, divisors, guard thresholds or template divisors, and only the
//!   width family in its trace corners;
//! * `the_synthesizer_and_the_template_use_only_the_pool`: the consumers
//!   themselves — the synthesizer's enumeration and the template
//!   (`affine_atom`) — offer no divisor the pool lacks (a fixed divisor put
//!   back inside either one bypasses `Pool` and the checks above; the
//!   fairness re-audit of 2026-10-02 found that gap), and a loop that shifts
//!   by 7 does get `/7` (the positive control);
//! * `the_checks_reject_the_old_fixed_pools` (the negative twin): the same
//!   checks fail on the fixed lists the summarizer used to carry.

use sandblaster_front::opt::loopsum::classify::{ContPath, ExitPath, SVal};
use sandblaster_front::opt::loopsum::expr::{self, CE, E, Ty, Val};
use sandblaster_front::opt::loopsum::guards::{self, candidate_guards};
use sandblaster_front::opt::loopsum::pool::Pool;
use sandblaster_front::opt::loopsum::synth;
use sandblaster_front::opt::loopsum::traces::corners;
use sandblaster_kernel::term::{PrimOp, Width};

/// The constants the audit found hard-coded for benchmark targets.
fn target_constants() -> Vec<u128> {
    vec![6, 7, 128, 1 << 14, 1 << 61, (1 << 61) - 1, (1 << 61) + 1, 1 << 62, (1 << 62) - 1, (1 << 62) + 1, 1 << 63, (1 << 63) - 1, (1 << 63) + 1, 1 << 32]
}

/// The values a width alone gives to the synthesis.
fn width_leaves(w: Width) -> Vec<u128> {
    let b = expr::bits(w) as u128;
    vec![0, 1, 2, b - 1, b]
}

/// `Err` naming the values of `set` that are neither in `allowed` nor
/// harvested from `pool`'s loop (`harvested`).
fn only(set: &[u128], allowed: &[u128], what: &str) -> Result<(), String> {
    let extra: Vec<u128> = set.iter().copied().filter(|x| !allowed.contains(x)).collect();
    if extra.is_empty() { Ok(()) } else { Err(format!("{what}: constants not given by the width or the loop: {extra:?}")) }
}

/// `Err` unless every corner is `0` or `2^k − 1`, `2^k`, `2^k + 1` (k ≤ 64)
/// or harvested (`allowed`).
fn only_width_family(cs: &[u128], allowed: &[u128]) -> Result<(), String> {
    let family = |x: u128| x == 0 || (0..=64u32).any(|k| {
        let p = 1u128 << k;
        x == p || x + 1 == p || x == p + 1
    });
    let extra: Vec<u128> = cs.iter().copied().filter(|x| !family(*x) && !allowed.contains(x)).collect();
    if extra.is_empty() { Ok(()) } else { Err(format!("trace corners outside the width family: {extra:?}")) }
}

/// The literals of a list of guards (`xᵢ < c`, `xᵢ == c`).
fn guard_literals(gs: &[E]) -> Vec<u128> {
    let mut out = Vec::new();
    for g in gs {
        if let CE::Op(_, a) = &**g {
            for x in a {
                if let CE::Lit(_, n) = &**x {
                    out.push(*n);
                }
            }
        }
    }
    out
}

/// A loop `go(x, n) = if x == 0 { n } else { go(x >> 5, n + 1) }` (a
/// base-32 digit count): state `x: u64`, `n: u32`.
fn base32_loop() -> (Vec<ContPath>, Vec<ExitPath>) {
    let x = expr::var(0, Width::U64);
    let n = expr::var(1, Width::U32);
    let zero = expr::op2(PrimOp::Eq(Width::U64), x.clone(), expr::lit(Width::U64, 0));
    let cont = ContPath { guards: vec![(zero.clone(), false)], next: vec![SVal::Ce(expr::op2(PrimOp::WShr(Width::U64), x.clone(), expr::lit(Width::U32, 5))), SVal::Ce(expr::op2(PrimOp::WAdd(Width::U32), n.clone(), expr::lit(Width::U32, 1)))] };
    let exit = ExitPath { guards: vec![(zero, true)], value: SVal::Ce(n) };
    (vec![cont], vec![exit])
}

/// A loop without any literal: `go(x, y) = if x < y { go(x ^ y, y) } else { x }`.
fn literal_free_loop() -> (Vec<ContPath>, Vec<ExitPath>) {
    let x = expr::var(0, Width::U64);
    let y = expr::var(1, Width::U64);
    let lt = expr::op2(PrimOp::Lt(Width::U64), x.clone(), y.clone());
    let cont = ContPath { guards: vec![(lt.clone(), true)], next: vec![SVal::Ce(expr::op2(PrimOp::Xor(Width::U64), x.clone(), y.clone())), SVal::Ce(y.clone())] };
    let exit = ExitPath { guards: vec![(lt, false)], value: SVal::Ce(x) };
    (vec![cont], vec![exit])
}

#[test]
fn harvested_constants_come_from_the_loop() {
    let (c, e) = base32_loop();
    let p = Pool::of_paths(&c, &e);
    assert_eq!(p.shifts, vec![5], "{p:?}");
    assert!(p.divisors().contains(&5), "divisor 5 from the shift: {:?}", p.divisors());
    let th = p.thresholds(Width::U64);
    assert!(th.contains(&32) && th.contains(&1024), "thresholds 2^5 and 2^10: {th:?}");
    let leaves = p.leaves(Width::U64);
    for k in [5u128, 4, 32] {
        assert!(leaves.contains(&k), "leaf {k} (k, k − 1, 2^k): {leaves:?}");
    }
    // the guards tried: the thresholds of this loop
    let gl = guard_literals(&candidate_guards(&[Width::U64], &p));
    assert!(gl.contains(&32) && gl.contains(&1024), "{gl:?}");
    // and none of another radix's constants (`6` is `5 + 1` here, a
    // harvested literal's neighbour)
    for v in [7u128, 128, 1 << 14] {
        assert!(!leaves.contains(&v) && !p.divisors().contains(&v) && !th.contains(&v), "{v} in a base-32 loop's pool");
    }
}

/// The pool of a literal-free loop and every candidate set built from it.
fn literal_free_sets() -> (Vec<u128>, Vec<u128>, Vec<u128>, Vec<u128>, Vec<u128>) {
    let (c, e) = literal_free_loop();
    let p = Pool::of_paths(&c, &e);
    assert_eq!(p, Pool::default(), "no literal, no harvest");
    let mut leaves = p.leaves(Width::U64);
    leaves.extend(p.leaves(Width::U32));
    let gl = guard_literals(&candidate_guards(&[Width::U64, Width::U64], &p));
    let cs = corners(Width::U64, &[], &p.corner_literals());
    (leaves, p.divisors(), p.thresholds(Width::U64), gl, cs)
}

#[test]
fn a_loop_without_literals_gets_only_width_constants() {
    let (leaves, divisors, thresholds, guard_lits, cs) = literal_free_sets();
    let mut allowed = width_leaves(Width::U64);
    allowed.extend(width_leaves(Width::U32));
    only(&leaves, &allowed, "synthesis leaves").unwrap();
    only(&divisors, &[2], "divisors").unwrap();
    only(&thresholds, &[], "guard thresholds").unwrap();
    only(&guard_lits, &[0], "guard literals").unwrap();
    only_width_family(&cs, &[]).unwrap();
    for v in target_constants() {
        assert!(!leaves.contains(&v) && !divisors.contains(&v) && !thresholds.contains(&v) && !guard_lits.contains(&v), "{v} offered to a literal-free loop");
    }
    assert!(!cs.contains(&6), "6 is not a corner of the width");
}

/// Every divisor of the `DivLit`s of a closed form.
fn divisors_in(e: &E, out: &mut Vec<u128>) {
    match &**e {
        CE::DivLit(x, c) => {
            out.push(*c);
            divisors_in(x, out);
        }
        CE::Op(_, a) => a.iter().for_each(|x| divisors_in(x, out)),
        CE::ShrSat(x, k) | CE::ShlSat(x, k) => {
            divisors_in(x, out);
            divisors_in(k, out);
        }
        CE::Ite(c, a, b) => {
            divisors_in(c, out);
            divisors_in(a, out);
            divisors_in(b, out);
        }
        CE::Var(..) | CE::J | CE::Lit(..) | CE::BoolLit(_) => {}
    }
}

/// Samples of one `u32` input with the target `x / 7` (the synthesizer's
/// size-2 `DivLit(x, 7)`; the grammar has no multiplication, so no small
/// expression without `/7` matches it).
fn div7_samples() -> (Vec<Vec<u128>>, Vec<Val>) {
    let mut xs: Vec<u128> = (0..200).collect();
    xs.extend([1000, 4095, 65_535, 1 << 20, 123_456_789, (1 << 31) + 5, u32::MAX as u128]);
    (xs.iter().map(|x| vec![*x]).collect(), xs.iter().map(|x| Val::W(Width::U32, x / 7)).collect())
}

/// Samples of one `u64` input at every bit length with the target
/// `⌊bitlen(x) / 7⌋ = (64 − lz(x)) / 7` (the template's `(c − A) / k` with
/// `k = 7`: a base-128 digit count).
fn digits7_samples() -> (Vec<Vec<u128>>, Vec<Val>) {
    let mut xs = vec![0u128];
    for b in 1..=64u32 {
        xs.push(1u128 << (b - 1));
        xs.push((1u128 << b) - 1);
    }
    (xs.iter().map(|x| vec![*x]).collect(), xs.iter().map(|x| Val::W(Width::U32, u128::from(128 - x.leading_zeros()) / 7)).collect())
}

#[test]
fn the_synthesizer_and_the_template_use_only_the_pool() {
    let empty = Pool::default();
    let shift7 = Pool { shifts: vec![7], ..Pool::default() };
    assert_eq!(shift7.divisors(), vec![2, 7]);
    // the synthesizer: a loop without a 7 gets no `/7` …
    let (inputs, target) = div7_samples();
    if let Some(f) = synth::synthesize(&[Width::U32], &inputs, &target, Ty::W(Width::U32), synth::MAX_SIZE, &empty) {
        let mut ds = Vec::new();
        divisors_in(&f.expr, &mut ds);
        only(&ds, &empty.divisors(), "synthesis divisors").unwrap();
        panic!("x / 7 synthesized without a 7 in the loop: {:?}", f.expr);
    }
    // … a loop that shifts by 7 does
    let f = synth::synthesize(&[Width::U32], &inputs, &target, Ty::W(Width::U32), synth::MAX_SIZE, &shift7).expect("x / 7 from a loop shifting by 7");
    let mut ds = Vec::new();
    divisors_in(&f.expr, &mut ds);
    assert_eq!(ds, vec![7], "{:?}", f.expr);
    // the template: the same for (c − lz(x)) / 7
    let (inputs, target) = digits7_samples();
    assert_eq!(guards::affine_atom(&[Width::U64], &inputs, &target, &empty), None, "the template offered a divisor the loop does not have");
    let e = guards::affine_atom(&[Width::U64], &inputs, &target, &shift7).expect("(64 − lz(x)) / 7 from a loop shifting by 7");
    let mut ds = Vec::new();
    divisors_in(&e, &mut ds);
    assert_eq!(ds, vec![7], "{e:?}");
}

/// The negative twin: the checks above reject the fixed pools the
/// summarizer carried before the audit (synth.rs leaves and divisors,
/// guards.rs thresholds, traces.rs corners at u64).
#[test]
fn the_checks_reject_the_old_fixed_pools() {
    let w = Width::U64;
    let old_leaves: Vec<u128> = vec![0, 1, 2, 6, 7, 63, 64, 63, 64];
    assert!(only(&old_leaves, &width_leaves(w), "synthesis leaves").is_err());
    assert!(only(&[2, 7, 8], &[2], "divisors").is_err());
    assert!(only(&[1, 2, 128, 1 << 14, 1 << 32], &[], "guard thresholds").is_err());
    let m = expr::mask(w);
    let mut old_corners = vec![0, 1, 2, 3, 5, 7, 8, 127, 128, 255, 256, m, m - 1, m >> 1, (m >> 1) + 1];
    for k in [5u32, 7, 16, 31, 32, 33, 61, 62, 63] {
        let p = 1u128 << k;
        old_corners.extend([p - 1, p, p + 1]);
    }
    // (`m − 1` is the one old corner outside the width family; the rest
    // were a hand-picked subset of it, `k ∈ {5, 7, 16, 31, 32, 33, 61, 62,
    // 63}`, which the family check cannot tell from a full one)
    assert!(only_width_family(&old_corners, &[]).is_err());
    // and the old template divisors `2..=8` offered `7` to every loop
    let old_template: Vec<u128> = (2..=8).collect();
    assert!(only(&old_template, &[2], "template divisors").is_err());
}
