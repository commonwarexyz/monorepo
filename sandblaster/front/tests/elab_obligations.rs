//! Obligation generation (DESIGN.md §7.2, SEMANTICS.md §14): each partial
//! construct produces exactly the obligation kinds of the semantics, at the
//! construct's span, and they are proven when the program is correct.

#[path = "elab_util.rs"]
#[macro_use]
#[allow(unused_macros)]
mod util;

use sandblaster_front::driver::ProverSet;
use util::{assert_verified, kinds_of, verify_src};

/// Verifies `src` and returns the obligation kinds of definition `def`.
#[track_caller]
fn kinds(src: &str, def: &str) -> Vec<String> {
    let (c, v) = verify_src(src, ProverSet::Basic);
    assert_verified(&c, &v);
    kinds_of(&v, def)
}

fn count(ks: &[String], k: &str) -> usize {
    ks.iter().filter(|x| *x == k).count()
}

#[test]
fn arithmetic_obligations() {
    let ks = kinds("pub fn f(a: u8, b: u8) -> u32 { let x = a as u32 + b as u32; let y = x - (b as u32); let z = y * 2; let q = z / (b as u32 + 1); q.wrapping_add(z % 7) }", "crate::f");
    // `a + b`, `y * 2`, `b + 1` (each recorded, even when closed by evaluation)
    assert_eq!(count(&ks, "overflow"), 3, "{ks:?}");
    assert_eq!(count(&ks, "underflow"), 1, "{ks:?}");
    assert_eq!(count(&ks, "div-zero"), 2, "{ks:?}");
}

#[test]
fn shift_obligations_use_the_amount_width() {
    let ks = kinds("pub fn f(x: u32, k: u64) -> u32 { if k < 32 { x << k } else { 0 } }", "crate::f");
    assert!(ks.contains(&"shift-width".to_string()), "{ks:?}");
    let ks = kinds("pub fn g(x: u64, k: u8) -> u64 { x >> (k % 64) }", "crate::g");
    assert_eq!(count(&ks, "shift-width"), 1, "{ks:?}");
}

#[test]
fn indexing_and_slicing_obligations() {
    let ks = kinds("pub fn f(xs: &[u8], i: usize) -> u8 { if i < xs.len() { xs[i] } else { 0 } }", "crate::f");
    assert_eq!(count(&ks, "index-bounds"), 1, "{ks:?}");
    let ks = kinds("pub fn g(xs: &[u8]) -> usize { if xs.len() >= 8 { let w = &xs[2..6]; w.len() } else { 0 } }", "crate::g");
    assert!(count(&ks, "slice-range") >= 1, "{ks:?}");
    // array indexing by a literal is decided by evaluation
    let (c, v) = verify_src("pub fn h(a: [u8; 4]) -> u8 { a[3] }", ProverSet::Basic);
    assert_verified(&c, &v);
    assert!(v.obligations.iter().filter(|o| o.def == "crate::h").all(|o| matches!(&o.status, sandblaster_front::elab::OblStatus::Proven { by } if by == "eval")));
}

#[test]
fn callee_requires_and_stack_depth() {
    let src = r#"
#[requires(n <= 10)]
#[decreases(n, max = 10)]
fn depth(n: u32) -> u32 { if n == 0 { 0 } else { depth(n - 1).wrapping_add(1) } }
#[requires(x < 100)]
fn small(x: u32) -> u32 { x + 1 }
pub fn caller(y: u32) -> u32 { if y < 5 { small(y).wrapping_add(depth(y)) } else { 0 } }
"#;
    let (c, v) = verify_src(src, ProverSet::Basic);
    assert_verified(&c, &v);
    let ks = kinds_of(&v, "crate::caller");
    assert_eq!(count(&ks, "callee-requires"), 2, "{ks:?}");
    assert_eq!(count(&ks, "stack-depth"), 1, "{ks:?}");
    let ks = kinds_of(&v, "crate::depth");
    assert!(ks.contains(&"termination".to_string()), "{ks:?}");
}

/// Recursion on the tail of `split_first()` / `split_at_checked()` whose
/// tuple is destructured after the match (`let Some((h, t)) = .. else`,
/// `let (h, t) = ..?`, `let Some(p) = .. else; let (h, t) = p`): the path
/// equation is `call == Some(p)` with the tuple projected, and `auto`'s
/// method facts still fire on it (struct η in rule matching), so the
/// `decreases(xs.len())` obligations and the index into the head chunk are
/// proven. Regression: `redteam_fidelity::tail_recursion_differential`
/// (`early`, `opt_tail`).
#[test]
fn termination_on_a_destructured_split_first() {
    let src = r#"
#[decreases(xs.len())]
pub fn early(xs: &[u8], acc: u32) -> u32 {
    let Some((h, t)) = xs.split_first() else { return acc };
    if *h == 0 {
        return acc.wrapping_add(1000000);
    }
    early(t, acc.wrapping_add(*h as u32))
}
#[decreases(xs.len())]
pub fn opt_tail(xs: &[u8], acc: u16) -> Option<u16> {
    let (h, t) = xs.split_first()?;
    if t.is_empty() { Some(acc ^ *h as u16) } else { opt_tail(t, acc.checked_add(*h as u16)?) }
}
#[decreases(xs.len())]
pub fn pairs(xs: &[u8], acc: u32) -> u32 {
    let Some(p) = xs.split_at_checked(2) else { return acc };
    let (h, t) = p;
    pairs(t, acc.wrapping_add(h[1] as u32))
}
"#;
    let (c, v) = verify_src(src, ProverSet::Standard);
    assert_verified(&c, &v);
    for (def, kind) in [("crate::early", "termination"), ("crate::opt_tail", "termination"), ("crate::pairs", "termination"), ("crate::pairs", "index-bounds")] {
        assert!(kinds_of(&v, def).iter().any(|k| k == kind), "{def}: no {kind} obligation: {:?}", kinds_of(&v, def));
    }
}

/// A linear-arithmetic proof of the basic prover carries only the
/// hypotheses its certificate uses (as `auto`'s): the facts of the context
/// that the goal does not need are dropped from the `Linarith` term, so the
/// re-certification, `add_def` and every later re-check (a clone lemma, a
/// driven residual's elaboration, a motive) never linearize them. QMDB:
/// `merkle::reconstruct_checked`'s `path` obligations carried the unfolded
/// `list_take`/`list_drop` slice facts; their clone lemma took 1.68 s, 19 ms
/// without them.
#[test]
fn linarith_proofs_keep_only_the_hypotheses_they_use() {
    let src = r#"
#[requires(h <= 64)]
fn leaf(h: u32) -> u32 { h }
#[requires(a < 1000)]
#[requires(b < 1000)]
#[requires(c < 1000)]
pub(crate) fn caller(a: u32, b: u32, c: u32, h: u32) -> u32 {
    if h > 64 {
        return 0;
    }
    leaf(h).wrapping_add(a + b + c)
}
"#;
    let (c, v) = verify_src(src, ProverSet::Basic);
    assert_verified(&c, &v);
    util::with_elab(src, ProverSet::Basic, |_, out| {
        use sandblaster_kernel::term::Term;
        let g = out.env.lookup_global("crate::caller").expect("caller");
        let body = out.env.global_body(g).expect("a body");
        let mut hyps: Vec<(String, Vec<String>)> = Vec::new();
        sandblaster_front::elab::tm::any_node(&body, &mut |t| {
            if let Term::Linarith { hyps: hs, goal, .. } = t {
                hyps.push((out.env.print_term(&[], goal), hs.iter().map(|(_, st)| out.env.print_term(&[], st)).collect()));
            }
            false
        });
        // `h <= 64` for `leaf` needs the path fact `h > 64 = false` only,
        // never the three `requires` about `a`, `b`, `c`
        let at_leaf: Vec<_> = hyps.iter().filter(|(goal, _)| goal.contains("64u32")).collect();
        assert!(!at_leaf.is_empty(), "no linarith proof of the `leaf` requires: {hyps:?}");
        for (goal, hs) in &at_leaf {
            assert_eq!(hs.len(), 1, "`{goal}` keeps unused hypotheses: {hs:?}");
            assert!(hs[0].contains("64u32"), "`{goal}`: {hs:?}");
        }
        // the sum still uses the bounds it needs
        assert!(hyps.iter().any(|(_, hs)| hs.len() >= 2), "{hyps:?}");
    });
}

#[test]
fn loop_obligations() {
    let src = r#"
pub fn f(n: u8) -> u32 {
    let mut acc: u32 = 0;
    for i in 0u32..n as u32 {
        proof! { invariant(acc <= i * 255); }
        acc += i;
    }
    acc
}
"#;
    let (c, v) = verify_src(src, ProverSet::Basic);
    assert_verified(&c, &v);
    assert_eq!(count(&kinds_of(&v, "crate::f"), "invariant-entry"), 1);
    let ks = kinds_of(&v, "crate::f::loop#0");
    assert_eq!(count(&ks, "invariant-preserve"), 1, "{ks:?}");
    // the measure proof is a pair: `0 ≤ m(args)` and `m(args) < m(params)`
    assert_eq!(count(&ks, "termination"), 2, "{ks:?}");
    assert!(ks.contains(&"overflow".to_string()), "`i + 1` and `acc + i`: {ks:?}");
}

#[test]
fn unreachable_and_copy_from_slice() {
    let src = r#"
pub fn f(x: u8) -> u8 { match x % 2 { 0 => 1, 1 => 2, _ => unreachable!() } }
pub fn g(src: &[u8]) -> [u8; 8] {
    let mut a = [0u8; 8];
    if src.len() == 4 { a[2..6].copy_from_slice(src); }
    a
}
"#;
    let (c, v) = verify_src(src, ProverSet::Basic);
    assert_verified(&c, &v);
    assert!(kinds_of(&v, "crate::f").contains(&"unreachable".to_string()));
    // `2 ≤ 6`, `6 ≤ 8` and the length match `6 − 2 = len src`
    let ks = kinds_of(&v, "crate::g");
    assert_eq!(count(&ks, "slice-range"), 3, "{ks:?}");
}

#[test]
fn facts_flow_from_requires_path_conditions_and_lets() {
    // every obligation here needs a fact: a `requires`, a path condition, a
    // `let` definition carried into a loop, a slice bound
    let src = r#"
#[requires(off <= xs.len() && xs.len() - off >= 4)]
fn read4(xs: &[u8], off: usize) -> u32 {
    (xs[off] as u32) | ((xs[off + 3] as u32) << 24u32)
}
pub fn sum(xs: &[u8], n: usize) -> u32 {
    let mut acc: u32 = 0;
    let k = n.min(xs.len()).min(64usize);
    for i in 0..k {
        proof! { invariant((acc as Int) <= (i as Int) * 255); }
        acc += xs[i] as u32;
    }
    acc
}
"#;
    let (c, v) = verify_src(src, ProverSet::Basic);
    assert_verified(&c, &v);
}

#[test]
fn obligations_have_source_spans() {
    let (c, v) = verify_src("pub fn f(a: u32, b: u32) -> u32 {\n    let s = a.wrapping_add(b);\n    if s > 3 { s - 3 } else { s }\n}", ProverSet::Basic);
    assert_verified(&c, &v);
    let o = v.obligations.iter().find(|o| o.def == "crate::f" && sandblaster_front::elab::obl::kind_name(&o.kind) == "underflow").expect("the `s - 3` obligation");
    // the span of `s - 3` (line 3 of the source after the 2-line header)
    assert_eq!(o.span.lo.0, 5, "{:?}", o.span);
}
