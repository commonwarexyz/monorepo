//! Prover ergonomics, round 5 (the QMDB law proof on a domain-free stdlib): the automation
//! that proof relies on, each piece as a minimal repro with a negative twin that must still
//! fail (and never through a kernel rejection).
//!
//! * `by_induction(x, ..)`: a closer that splits the named variables by constructor and tries the
//!   induction hypothesis at the recursive fields, also through the lemma's `requires`
//!   (speculative application, the implication fallback); `using(l, ..)` adds lemmas to try at
//!   every arm.
//! * a `bool` test whose two sides a fact equates decides its `if`;
//! * a recursive definition applied to a constructor unfolds even when that does not unblock the
//!   goal at once (lists excepted);
//! * an array of a folded constant length has that length for linear arithmetic;
//! * a `bool` test of one value against itself decides its `if`;
//! * nested concatenations get their length in one round;
//! * a stuck term equated to a variable inside it is rewritten to that variable.

#[path = "spec15_util.rs"]
mod util;

use util::*;

const EXEC_STUB: &str = "//! Exec part.\nuse sandblaster::prelude::*;\n/// A stub.\npub fn probe(x: u8) -> u8 { x }\n";

const SPEC: &str = r#"//! Spec.
use sandblaster::prelude::*;
/// A tree of byte strings.
#[derive(Clone, Copy)]
pub enum T { Leaf(Seq<u8>), Node(T, T) }
/// Its bytes, left to right.
pub fn flat(t: T) -> Seq<u8> {
    match t { T::Leaf(x) => x, T::Node(l, r) => seq![..flat(l), ..flat(r)] }
}
/// Two views of one tree.
pub fn agree(a: T, b: T) -> bool {
    match (a, b) {
        (T::Leaf(x), T::Leaf(y)) => x == y,
        (T::Node(a1, a2), T::Node(b1, b2)) => agree(a1, b1) && agree(a2, b2),
        _ => false,
    }
}
/// One shape: leaves of one length.
pub fn shape(a: T, b: T) -> bool {
    match (a, b) {
        (T::Leaf(x), T::Leaf(y)) => x.len() == y.len(),
        (T::Node(a1, a2), T::Node(b1, b2)) => shape(a1, b1) && shape(a2, b2),
        _ => false,
    }
}
/// Split alike: left parts of one length all the way down.
pub fn fits(a: T, b: T) -> bool {
    match (a, b) {
        (T::Leaf(_), T::Leaf(_)) => true,
        (T::Node(a1, a2), T::Node(b1, b2)) => flat(a1).len() == flat(b1).len() && fits(a1, b1) && fits(a2, b2),
        _ => false,
    }
}
/// A test on two byte strings.
pub fn pick(x: Seq<u8>, y: Seq<u8>) -> Nat { if x == y { 1 } else { 2 } }
/// Unknowns.
#[opaque]
pub fn f(x: Seq<u8>) -> Seq<u8> { x }
#[opaque]
pub fn g(x: Seq<u8>) -> Seq<u8> { x }
#[opaque]
pub fn w(x: Seq<u8>) -> Nat { x.len() }
/// A fixed width.
pub const K: usize = 4;
"#;

fn run_probe(proof: &str) -> Run {
    let root = "mod exec;\n#[cfg(sandblaster)]\n#[spec]\nmod spec;\n#[cfg(sandblaster)]\n#[path = \"PROOF.rs\"]\nmod proof;\npub use exec::probe;\n";
    let proof = format!("//! Probe.\nuse sandblaster::prelude::*;\nuse super::spec::{{T, K, agree, f, fits, flat, g, pick, shape, w}};\n{proof}");
    run_files(&[("r/mod.rs", root), ("r/exec.rs", EXEC_STUB), ("r/spec.rs", SPEC), ("r/PROOF.rs", &proof)])
}

/// The lemma `crate::proof::<name>` checked, with every obligation proven.
#[track_caller]
fn proven(r: &Run, name: &str) {
    let full = format!("crate::proof::{name}");
    assert!(r.front_ok, "front end rejected the probe:\n{}", r.rendered);
    let bad: Vec<String> = r.unproven.iter().filter(|(d, _, _)| *d == full).map(|(_, k, g)| format!("[{k}] {g}")).collect();
    assert!(bad.is_empty(), "`{full}` has unproven obligations:\n{}\n{}", bad.join("\n"), r.rendered);
    assert!(r.checked_defs.iter().any(|d| *d == full), "`{full}` was not checked:\n{}", r.explain());
}

/// The lemma `crate::proof::<name>` is not proven, and nothing was rejected by the kernel.
#[track_caller]
fn refuted(r: &Run, name: &str) {
    let full = format!("crate::proof::{name}");
    assert!(r.front_ok, "front end rejected the probe:\n{}", r.rendered);
    assert!(!r.checked_defs.iter().any(|d| *d == full), "`{full}` was proven, but its goal does not follow:\n{}", r.explain());
    assert!(!r.rendered.contains("rejected by the kernel") && !r.rendered.contains("the kernel rejected"), "a kernel rejection:\n{}", r.explain());
}

#[test]
fn by_induction_and_using() {
    let r = run_probe(
        r#"
/// Agreeing trees have one byte string: the hypothesis holds at the children through `requires`.
#[lemma]
fn agree_flat(a: T, b: T) {
    requires(agree(a, b));
    ensures(flat(a) == flat(b));
    by_induction(a, b);
}
/// Negative twin: a claim the hypothesis does not give.
#[lemma]
fn agree_flat_bad(a: T, b: T) {
    requires(agree(a, b));
    ensures(flat(a) == seq![..flat(b), 0u8]);
    by_induction(a, b);
}
/// Trees of one shape have bytes of one length …
#[lemma]
fn shape_len(a: T, b: T) {
    requires(shape(a, b));
    ensures(flat(a).len() == flat(b).len());
    by_induction(a, b);
}
/// … so they fit: `shape_len` is tried at the children.
#[lemma]
fn shape_fits(a: T, b: T) {
    requires(shape(a, b));
    ensures(fits(a, b));
    using(shape_len);
    by_induction(a, b);
}
/// Negative twin: without the lemma the left lengths are unknown.
#[lemma]
fn shape_fits_bad(a: T, b: T) {
    requires(shape(a, b));
    ensures(fits(a, b));
    by_induction(a, b);
}
"#,
    );
    proven(&r, "agree_flat");
    refuted(&r, "agree_flat_bad");
    proven(&r, "shape_len");
    proven(&r, "shape_fits");
    refuted(&r, "shape_fits_bad");
}

#[test]
fn tests_constructors_and_lengths() {
    let r = run_probe(
        r#"
/// A test whose two sides a fact equates.
#[lemma]
fn equated(a: Seq<u8>, b: Seq<u8>) {
    requires(f(a) == g(b));
    ensures(pick(f(a), g(b)) == 1);
    follows();
}
/// Negative twin: the other branch.
#[lemma]
fn equated_bad(a: Seq<u8>, b: Seq<u8>) {
    requires(f(a) == g(b));
    ensures(pick(f(a), g(b)) == 2);
    follows();
}
/// A recursive definition on constructors unfolds.
#[lemma]
fn node_fits(a1: T, a2: T, b1: T, b2: T) {
    requires(flat(a1).len() == flat(b1).len() && fits(a1, b1) && fits(a2, b2));
    ensures(fits(T::Node(a1, a2), T::Node(b1, b2)));
    follows();
}
/// Negative twin: a child that does not fit.
#[lemma]
fn node_fits_bad(a1: T, a2: T, b1: T, b2: T) {
    requires(flat(a1).len() == flat(b1).len() && fits(a1, b1));
    ensures(fits(T::Node(a1, a2), T::Node(b1, b2)));
    follows();
}
/// An array of a constant width has that length.
#[lemma]
fn width(a: [u8; K]) {
    ensures(seq![..a].len() == 4);
    by_arithmetic();
}
/// Negative twin: another length.
#[lemma]
fn width_bad(a: [u8; K]) {
    ensures(seq![..a].len() == 5);
    by_arithmetic();
}
/// A test of one unknown value against itself.
#[lemma]
fn reflexive(a: Seq<u8>) {
    ensures(pick(f(a), f(a)) == 1);
    follows();
}
/// Negative twin: two unknown values.
#[lemma]
fn reflexive_bad(a: Seq<u8>, b: Seq<u8>) {
    ensures(pick(f(a), f(b)) == 1);
    follows();
}
/// Nested concatenations in one round.
#[lemma]
fn nested_len(a: Seq<u8>, b: Seq<u8>, c: Seq<u8>) {
    ensures(seq![..a, ..seq![..b, ..seq![..c, ..a]]].len() == 2 * a.len() + b.len() + c.len());
    by_arithmetic();
}
/// Negative twin.
#[lemma]
fn nested_len_bad(a: Seq<u8>, b: Seq<u8>, c: Seq<u8>) {
    ensures(seq![..a, ..seq![..b, ..seq![..c, ..a]]].len() == a.len() + b.len() + c.len());
    by_arithmetic();
}
/// A stuck term equated to a variable inside it becomes that variable.
#[lemma]
fn collapse(xs: Seq<u8>) {
    requires(f(xs) == xs);
    ensures(w(g(f(xs))) == w(g(xs)));
    follows();
}
/// Negative twin: the variable is not the one inside.
#[lemma]
fn collapse_bad(xs: Seq<u8>, ys: Seq<u8>) {
    requires(f(xs) == xs);
    ensures(w(g(f(xs))) == w(g(ys)));
    follows();
}
"#,
    );
    proven(&r, "equated");
    refuted(&r, "equated_bad");
    proven(&r, "node_fits");
    refuted(&r, "node_fits_bad");
    proven(&r, "width");
    refuted(&r, "width_bad");
    proven(&r, "reflexive");
    refuted(&r, "reflexive_bad");
    proven(&r, "nested_len");
    refuted(&r, "nested_len_bad");
    proven(&r, "collapse");
    refuted(&r, "collapse_bad");
}
