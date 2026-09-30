//! Prover ergonomics, round 6 (prover defects the QMDB law spikes logged, and the redesign
//! spike's automation): each piece as the minimal repro that failed, written the way an engineer
//! writes it, with a negative twin that must stay unproven (an unproven obligation, never a
//! kernel rejection).
//!
//! * `unfold(f)` unfolds every application written in the goal's logical structure (each
//!   conjunct of a `&&` goal), and no more: calls in the arms of a boolean `&&` and the calls a
//!   recursive body brings in stay folded;
//! * a sequence compared with itself is decided `true`;
//! * an array whose type has a literal size has that length;
//! * a lemma whose whole `ensures` is `implies(a, b)` gives the fact `a -> b` at a call; `a` is
//!   not demanded there;
//! * a disjunction goal whose side is a boolean test splits on that test (`x <= 3 || k(x) == 7`
//!   from `implies(x > 3, k(x) == 7)`; `a != b || c != d` from `(a == b && c == d) == false`);
//! * a `Nat` guard `0 <= e` in the goal is decided by `e`'s own range: a length, or the `Nat`
//!   range lemma of the spec function at `e`'s head (`0 <= mk(i, x).a` for a struct result),
//!   so a spec function with a `Nat` parameter unfolds at such an argument;
//! * argument congruence looks through integer applications (`g(h(p.a, p.b), p.c)` against
//!   `g(h(q.a, q.b), q.c)`), also in a `by_unfolding` view.

#[path = "spec15_util.rs"]
mod util;

use util::*;

/// A probe crate with a spec module next to its PROOF.rs.
fn run_spec_probe(spec: &str, uses: &str, proof: &str) -> Run {
    let root = "mod exec;\n#[cfg(sandblaster)]\n#[spec]\n#[path = \"spec.rs\"]\nmod spec;\n#[cfg(sandblaster)]\n#[path = \"PROOF.rs\"]\nmod proof;\npub use exec::probe;\n".to_string();
    let exec = "use sandblaster::prelude::*;\n/// A stub boundary.\npub fn probe(x: u8) -> u8 { x }\n".to_string();
    let spec = format!("use sandblaster::prelude::*;\n{spec}");
    let uses = if uses.is_empty() { String::new() } else { format!("use super::spec::{{{uses}}};\n") };
    let proof = format!("use sandblaster::prelude::*;\n{uses}{proof}");
    run_files(&[("r/mod.rs", root.as_str()), ("r/exec.rs", exec.as_str()), ("r/spec.rs", spec.as_str()), ("r/PROOF.rs", proof.as_str())])
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

const REDESIGN: &str = r#"
/// 0 for equal byte strings, 1 for different ones.
#[spec]
#[example(pick(seq![1u8], seq![1u8]) == 0u8 && pick(seq![1u8], seq![2u8]) == 1u8)]
fn pick(x: Seq<u8>, y: Seq<u8>) -> u8 { if x == y { 0u8 } else { 1u8 } }
/// One number's bytes are equal to themselves.
#[lemma]
fn be_same(v: u64) {
    ensures(pick(seq![..v.to_be_bytes()], seq![..v.to_be_bytes()]) == 0u8);
    follows();
}
/// Negative twin: two numbers' bytes need not be equal.
#[lemma]
fn be_same_bad(v: u64, w: u64) {
    ensures(pick(seq![..v.to_be_bytes()], seq![..w.to_be_bytes()]) == 0u8);
    follows();
}
/// Four bytes of a number. Opaque in proofs.
#[spec]
#[opaque]
#[example(four(1) == [1u8, 0u8, 0u8, 0u8])]
fn four(x: Nat) -> [u8; 4] { [x as u8, 0u8, 0u8, 0u8] }
/// Two such arrays have eight bytes.
#[lemma]
fn four_len(x: Nat) {
    ensures(seq![..four(x), ..four(x)].len() == 8);
    follows();
}
/// Negative twin: not nine.
#[lemma]
fn four_len_bad(x: Nat) {
    ensures(seq![..four(x), ..four(x)].len() == 9);
    follows();
}
/// Twice a number. Opaque in proofs.
#[spec]
#[opaque]
#[example(two(2) == 4)]
fn two(x: Nat) -> Nat { x + x }
/// `unfold` reaches the second conjunct too.
#[lemma]
fn both(a: Nat, b: Nat) {
    ensures(two(a) == a + a && two(b) == b + b);
    unfold(two);
    follows();
}
/// Negative twin: the second conjunct is false.
#[lemma]
fn both_bad(a: Nat, b: Nat) {
    ensures(two(a) == a + a && two(b) == b + a);
    unfold(two);
    follows();
}
/// The first byte where two lists differ.
#[spec]
#[example(diff(seq![1u8, 2u8], seq![1u8, 3u8]) == Some(2u8) && diff(seq![1u8], seq![1u8]) == None)]
fn diff(a: Seq<u8>, b: Seq<u8>) -> Option<u8> {
    match a {
        [x, ar @ ..] => match b {
            [y, br @ ..] => if x != y { Some(x) } else { diff(ar, br) },
            [] => None,
        },
        [] => None,
    }
}
/// A list does not differ from itself: the recursive call stays folded for the hypothesis.
#[lemma]
#[induction(a)]
fn no_diff(a: Seq<u8>) {
    ensures(diff(a, a) == None);
    match a {
        [x, r @ ..] => {
            ih(r);
            unfold(diff);
            follows();
        }
        [] => by_unfolding(diff),
    }
}
/// Negative twin: two lists may differ.
#[lemma]
fn no_diff_bad(a: Seq<u8>, b: Seq<u8>) {
    ensures(diff(a, b) == None);
    match a {
        [x, r @ ..] => {
            unfold(diff);
            follows();
        }
        [] => by_unfolding(diff),
    }
}
/// `x` is a multiple of 2^e. Opaque in proofs.
#[spec]
#[opaque]
#[example(aligned(12, 2) && !aligned(12, 3))]
#[decreases(e)]
fn aligned(x: Int, e: Int) -> bool {
    if e <= 0 { true } else { x >= 0 && x % 2 == 0 && aligned(x / 2, e - 1) }
}
/// One step: the application in the arm of the right side's `&&` stays folded.
#[lemma]
fn aligned_step(x: Nat, e: Int) {
    requires(e >= 1);
    ensures(aligned(x, e) == (x % 2 == 0 && aligned(x / 2, e - 1)));
    unfold(aligned);
    follows();
}
/// Negative twin: another exponent on the right.
#[lemma]
fn aligned_step_bad(x: Nat, e: Int) {
    requires(e >= 1);
    ensures(aligned(x, e) == (x % 2 == 0 && aligned(x / 2, e)));
    unfold(aligned);
    follows();
}
"#;

#[test]
fn redesign_automation() {
    let r = run_spec_probe("", "", REDESIGN);
    for (good, bad) in [("be_same", "be_same_bad"), ("four_len", "four_len_bad"), ("both", "both_bad"), ("no_diff", "no_diff_bad"), ("aligned_step", "aligned_step_bad")] {
        proven(&r, good);
        refuted(&r, bad);
    }
}

const RECORD: &str = r#"
/// A record of three counts.
#[derive(Clone, Copy)]
pub struct P { pub a: Nat, pub b: Nat, pub c: Nat }
/// Unknown.
#[opaque]
pub fn h(x: Nat, y: Nat) -> Nat { x + y }
/// Unknown.
#[opaque]
pub fn g(x: Nat, y: Nat) -> Nat { x * y }
"#;

const IMPLIES_AND_CONGRUENCE: &str = r#"
/// Seven above 3. Opaque in proofs.
#[spec]
#[opaque]
fn k(x: Int) -> Int { if x > 3 { 7 } else { 0 } }
/// A lemma whose whole claim is an implication.
#[lemma]
fn k_above(x: Int) {
    ensures(implies(x > 3, k(x) == 7));
    by_unfolding(k);
}
/// Applied without its premise: the implication is a fact, the premise holds here.
#[lemma]
fn k_use(x: Int) {
    requires(x > 5);
    ensures(k(x) == 7);
    k_above(x);
    follows();
}
/// Negative twin: without the premise the implication gives nothing.
#[lemma]
fn k_use_bad(x: Int) {
    ensures(k(x) == 7);
    k_above(x);
    follows();
}
/// A disjunction from the implication: split on the test of its left side.
#[lemma]
fn k_or(x: Int) {
    ensures(x <= 3 || k(x) == 7);
    k_above(x);
    follows();
}
/// Negative twin: a wrong value on the right.
#[lemma]
fn k_or_bad(x: Int) {
    ensures(x <= 4 || k(x) == 8);
    k_above(x);
    follows();
}
/// Two counts differ somewhere.
#[lemma]
fn differ(p: P, q: P) {
    requires(p.a != q.a || p.b != q.b);
    ensures(true);
    follows();
}
/// A false conjunction of equalities is a disjunction of disequalities (the goal) …
#[lemma]
fn not_both(p: P, q: P) {
    requires((p.a == q.a && p.b == q.b) == false);
    ensures(p.a != q.a || p.b != q.b);
    follows();
}
/// … and a callee's `requires`.
#[lemma]
fn not_both_call(p: P, q: P) {
    requires((p.a == q.a && p.b == q.b) == false);
    ensures(true);
    differ(p, q);
}
/// Negative twin: another count on the right.
#[lemma]
fn not_both_bad(p: P, q: P) {
    requires((p.a == q.a && p.b == q.b) == false);
    ensures(p.a != q.a || p.c != q.c);
    follows();
}
/// One place: all three counts equal.
#[spec]
fn same(p: P, q: P) -> bool { p.a == q.a && p.b == q.b && p.c == q.c }
/// Unknown functions of the counts. Opaque in proofs.
#[spec]
#[opaque]
fn front(p: P) -> Nat { g(h(p.a, p.b), p.c) }
/// Congruence through a nested integer application.
#[lemma]
fn nested(p: P, q: P) {
    requires(same(p, q));
    ensures(g(h(p.a, p.b), p.c) == g(h(q.a, q.b), q.c));
    by_unfolding(same);
}
/// The same through an opaque definition's view.
#[lemma]
fn nested_view(p: P, q: P) {
    requires(same(p, q));
    ensures(front(p) == front(q));
    by_unfolding(front, same);
}
/// Negative twin: the third count may differ.
#[lemma]
fn nested_bad(p: P, q: P) {
    requires(p.a == q.a && p.b == q.b);
    ensures(g(h(p.a, p.b), p.c) == g(h(q.a, q.b), q.c));
    by_unfolding(same);
}
"#;

const GUARDS: &str = r#"
/// A record built from its arguments. Opaque in proofs.
#[spec]
#[opaque]
fn mk(i: Nat, x: Seq<u8>) -> P { P { a: i, b: x.len(), c: 0 } }
/// A record of one count (a `Nat` parameter: its body is guarded by `0 <= n`).
#[spec]
fn same_three(n: Nat) -> P { P { a: n, b: n, c: n } }
/// Unknown.
#[spec]
#[opaque]
fn keep(s: P) -> bool { s.a > 0 }
/// The guard `0 <= mk(i, x).a` holds by `mk`'s range: the definition unfolds.
#[lemma]
fn guard_range(i: Nat, x: Seq<u8>) {
    requires(keep(P { a: mk(i, x).a, b: mk(i, x).a, c: mk(i, x).a }));
    ensures(keep(same_three(mk(i, x).a)));
    follows();
}
/// Negative twin: another component in the fact.
#[lemma]
fn guard_range_bad(i: Nat, x: Seq<u8>) {
    requires(keep(P { a: mk(i, x).b, b: mk(i, x).a, c: mk(i, x).a }));
    ensures(keep(same_three(mk(i, x).a)));
    follows();
}
"#;

#[test]
fn nat_guards_by_range() {
    let r = run_spec_probe(RECORD, "P, g, h", GUARDS);
    proven(&r, "guard_range");
    refuted(&r, "guard_range_bad");
}

#[test]
fn implications_and_nested_congruence() {
    let r = run_spec_probe(RECORD, "P, g, h", IMPLIES_AND_CONGRUENCE);
    proven(&r, "k_above");
    proven(&r, "k_use");
    refuted(&r, "k_use_bad");
    proven(&r, "k_or");
    refuted(&r, "k_or_bad");
    proven(&r, "not_both");
    proven(&r, "not_both_call");
    refuted(&r, "not_both_bad");
    proven(&r, "nested");
    proven(&r, "nested_view");
    refuted(&r, "nested_bad");
}
