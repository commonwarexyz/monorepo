//! §15 S1 examples (DESIGN.md §15.7): `#[example(e)]` as kernel lemmas
//! (`refl`) or kernel closed evaluation (`Env::eval_closed`, TCB), false
//! examples with both evaluated sides, budget exhaustion as an error,
//! vector files (CAVP and JSON) binding record fields to a checker's
//! parameters by name, provenance, and the coverage records the §15.8
//! examples gate enforces.

#[path = "spec15_util.rs"]
mod util;

use sandblaster_front::diag::DiagKind as K;
use sandblaster_front::elab::examples::ExampleMethod;
use util::*;

#[test]
fn example_by_conversion_is_a_kernel_lemma() {
    let r = verifies(
        r#"
#[cfg(sandblaster)]
#[spec]
#[example(double(2) == 4)]
#[example(double(0) == 0)]
fn double(x: Nat) -> Nat { 2 * x }
"#,
    );
    let ex: Vec<&Ex> = r.examples.iter().filter(|e| e.item == "crate::double").collect();
    assert_eq!(ex.len(), 2);
    assert!(ex.iter().all(|e| e.checked && e.method == Some(ExampleMethod::Conversion)), "{}", r.explain());
    assert!(r.checked_defs.iter().any(|d| d == "crate::double::example#0") && r.checked_defs.iter().any(|d| d == "crate::double::example#1"));
}

#[test]
fn example_on_an_opaque_function_by_closed_evaluation() {
    // a function with a loop is opaque (§5.6): checking-mode conversion
    // keeps it folded, the kernel's closed evaluator computes it
    let r = verifies(
        r#"
#[example(sum_to(4) == 10)]
#[example(sum_to(0) == 0)]
fn sum_to(n: u8) -> u32 {
    let mut acc: u32 = 0;
    for i in 0..n {
        proof! { invariant((acc as Int) <= (i as Int) * 255); }
        acc += (i as u32) + 1;
    }
    acc
}
pub fn api(n: u8) -> u32 { sum_to(n) }
"#,
    );
    let ex: Vec<&Ex> = r.examples.iter().filter(|e| e.item == "crate::sum_to").collect();
    assert_eq!(ex.len(), 2, "{}", r.explain());
    assert!(ex.iter().all(|e| e.checked && e.method == Some(ExampleMethod::EvalClosed)), "{}", r.explain());
}

#[test]
fn a_false_example_fails_with_both_sides() {
    let r = fails(
        r#"
#[cfg(sandblaster)]
#[spec]
#[example(double(2) == 5)]
fn double(x: Nat) -> Nat { 2 * x }
"#,
    );
    assert!(r.has_error(K::Example, "example #0 of `crate::double` is false"), "{}", r.explain());
    // the values in surface syntax (a `Nat` in decimal), not kernel terms
    assert!(r.rendered.contains("left side evaluates to: 4\n") && r.rendered.contains("right side evaluates to: 5\n"), "{}", r.rendered);
    assert!(!r.examples[0].checked);
}

#[test]
fn an_exhausted_budget_is_an_error_never_a_skip() {
    let opts = sandblaster_front::elab::Options { example_budget: 20_000, ..Default::default() };
    let r = run_files_with(
        &[(
            "r/mod.rs",
            r#"
#[example(count(100000) == 100000)]
fn count(n: u32) -> u32 {
    let mut c: u32 = 0;
    for i in 0..n {
        proof! { invariant(c == i); }
        c += 1;
    }
    c
}
pub fn api(n: u32) -> u32 { count(n) }
"#,
        )],
        opts,
    );
    assert!(!r.verified, "{}", r.explain());
    assert!(r.has_error(K::Example, "could not be decided: the kernel's step budget (20000 steps) ran out"), "{}", r.explain());
}

// ---------------------------------------------------------------------
// vector files
// ---------------------------------------------------------------------

const CAVP: &str = "\
#  add8 known answers (CAVP layout)
[W = 8]

A = 0
B = 0
Sum = 0

A = 1
B = 2
Sum = 3

A = 200
B = 100
Sum = 44

A = 255
B = 255
Sum = 254

A = 128
B = 128
Sum = 0

A = 17
B = 25
Sum = 42

A = 250
B = 6
Sum = 0

A = 99
B = 1
Sum = 100

A = 0
B = 255
Sum = 255

A = 31
B = 32
Sum = 63
";

#[test]
fn cavp_vector_file_of_ten_records() {
    let r = verifies_files(&[
        (
            "r/mod.rs",
            r#"
#[cfg(sandblaster)] #[spec] fn add8(a: Nat, b: Nat) -> Nat { (a + b) % 256 }

#[cfg(sandblaster)]
#[spec]
#[examples(file = "add8.rsp", format = "cavp", provenance = independent)]
fn add8_kat(a: Nat, b: Nat, sum: Nat) -> bool { add8(a, b) == sum }
"#,
        ),
        ("r/add8.rsp", CAVP),
    ]);
    let ex: Vec<&Ex> = r.examples.iter().filter(|e| e.item == "crate::add8_kat" && e.file).collect();
    assert_eq!(ex.len(), 10, "{}", r.explain());
    assert!(ex.iter().all(|e| e.checked && e.counts), "{}", r.explain());
}

#[test]
fn json_vector_file_with_bytes() {
    let r = verifies_files(&[
        (
            "r/mod.rs",
            r#"
#[cfg(sandblaster)]
#[spec]
#[examples(file = "rev.json", format = "json", provenance = production)]
fn rev_kat(msg: Seq<u8>, out: Seq<u8>, n: Nat) -> bool { msg.rev() == out && msg.len() == n }
"#,
        ),
        ("r/rev.json", r#"{ "vectors": [ { "msg": "010203", "out": "030201", "n": 3 }, { "msg": "", "out": "", "n": 0 }, { "msg": "ff", "out": "ff", "n": "0x1", "comment": "extra fields are ignored" } ] }"#),
    ]);
    assert_eq!(r.examples.iter().filter(|e| e.file && e.checked).count(), 3, "{}", r.explain());
}

#[test]
fn a_wrong_record_and_a_missing_field_fail() {
    let r = run_files(&[
        (
            "r/mod.rs",
            r#"
#[cfg(sandblaster)] #[spec] fn add8(a: Nat, b: Nat) -> Nat { (a + b) % 256 }

#[cfg(sandblaster)]
#[spec]
#[examples(file = "bad.rsp", format = "cavp", provenance = independent)]
fn add8_kat(a: Nat, b: Nat, sum: Nat) -> bool { add8(a, b) == sum }
"#,
        ),
        ("r/bad.rsp", "A = 1\nB = 2\nSum = 3\n\nA = 1\nB = 2\nSum = 4\n\nA = 1\nSum = 1\n"),
    ]);
    assert!(!r.verified);
    // one error for the file, at the first failing record's line, listing
    // every failing record with its bound fields and the checker's sides
    assert!(r.has_error(K::Example, "vector file `bad.rsp` of `crate::add8_kat`: 2 of 3 record(s) failed (line 5, line 9)"), "{}", r.explain());
    assert!(r.rendered.contains("r/bad.rsp:5:1: error[example]"), "the span is the record's line in the vector file:\n{}", r.rendered);
    assert!(r.rendered.contains("line 5: a = 1, b = 2, sum = 4 (is false)"), "{}", r.rendered);
    assert!(r.rendered.contains("left side evaluates to: 3") && r.rendered.contains("right side evaluates to: 4"), "{}", r.rendered);
    assert!(r.rendered.contains("line 9 has no field `b`"), "{}", r.rendered);
}

#[test]
fn self_derived_vectors_do_not_count() {
    let r = verifies_files(&[
        (
            "r/mod.rs",
            r#"
#[cfg(sandblaster)] #[spec] fn add8(a: Nat, b: Nat) -> Nat { (a + b) % 256 }

#[cfg(sandblaster)]
#[spec]
#[examples(file = "self.rsp", format = "cavp", provenance = self)]
fn add8_kat(a: Nat, b: Nat, sum: Nat) -> bool { add8(a, b) == sum }
"#,
        ),
        ("r/self.rsp", "A = 1\nB = 2\nSum = 3\n"),
    ]);
    assert!(r.examples.iter().all(|e| e.checked && !e.counts), "{}", r.explain());
    let c = r.coverage.iter().find(|c| c.spec == "crate::add8").unwrap();
    assert!(!c.exercised, "self-derived vectors do not exercise the spec: {c:?}");
}

// ---------------------------------------------------------------------
// coverage (recorded; the §15.8 examples gate enforces it)
// ---------------------------------------------------------------------

#[test]
fn outcome_coverage_and_exercised_specs_are_recorded() {
    let r = verifies(
        r#"
#[cfg(sandblaster)] #[spec] fn is_small(x: Nat) -> bool { x < 10 }
#[cfg(sandblaster)] #[spec] fn find(x: Nat) -> Option<Nat> { if x < 10 { Some(x) } else { None } }
#[cfg(sandblaster)] #[spec] fn helper(x: Nat) -> Nat { x + 1 }
#[cfg(sandblaster)] #[spec] fn unused(x: Nat) -> Nat { x }

#[cfg(sandblaster)]
#[spec]
#[example(is_small(3) == true)]
#[example(find(3) == Some(3) && find(30) == None)]
#[example(uses_helper(1) == 2)]
fn examples() -> bool { true }

#[cfg(sandblaster)] #[spec] fn uses_helper(x: Nat) -> Nat { helper(x) }
"#,
    );
    let cov = |n: &str| r.coverage.iter().find(|c| c.spec == n).unwrap_or_else(|| panic!("no coverage for {n}: {:?}", r.coverage)).clone();
    let small = cov("crate::is_small");
    assert!(small.exercised);
    assert_eq!(small.needed, vec!["false", "true"]);
    assert_eq!(small.seen, vec!["true"], "only the `true` outcome has an example");
    let find = cov("crate::find");
    assert_eq!(find.seen, vec!["None", "Some"]);
    assert!(cov("crate::helper").exercised, "reached through `uses_helper`");
    assert!(!cov("crate::unused").exercised);
}

#[test]
fn a_break_predicate_needs_only_its_false_outcome() {
    // the break disjunct of a `#[reduces_to]` law (§15.13): its `true`
    // outcome is a break of the assumption, which no example can show; a
    // `bool` spec that is not a break still needs both outcomes
    let r = run_files(&[
        (
            "r/mod.rs",
            "#[cfg(sandblaster)] #[spec] #[path = \"spec.rs\"] mod spec;\n#[cfg(sandblaster)] #[path = \"LAWS.rs\"] mod laws;\n",
        ),
        (
            "r/spec.rs",
            r#"
/// Two different messages with one stub digest (their length).
#[example(!collision(Some((seq![1u8], seq![1u8]))))]
pub fn collision(c: Option<(Seq<u8>, Seq<u8>)>) -> bool {
    match c { Some((x, y)) => x != y && x.len() == y.len(), None => false }
}

/// The pair of two different messages.
#[example(pair(seq![1u8], seq![1u8]) == None && pair(seq![1u8], seq![2u8]) == Some((seq![1u8], seq![2u8])))]
pub fn pair(a: Seq<u8>, b: Seq<u8>) -> Option<(Seq<u8>, Seq<u8>)> { if a == b { None } else { Some((a, b)) } }

/// Two messages are the same.
#[example(same(seq![1u8], seq![1u8]))]
pub fn same(a: Seq<u8>, b: Seq<u8>) -> bool { a == b }

/// Finding a collision is infeasible.
#[assumption(class = computational, cite = "stub hash collision resistance")]
pub fn collision_resistance() {}
"#,
        ),
        (
            "r/LAWS.rs",
            r#"use sandblaster::prelude::*;
use super::spec::{collision, collision_resistance, pair, same};

/// Two messages of one length are the same, or they collide.
#[law]
#[reduces_to(collision_resistance)]
fn same_or_collide(a: Seq<u8>, b: Seq<u8>) {
    requires(a.len() == b.len());
    ensures(same(a, b) || collision(pair(a, b)));
}
"#,
        ),
    ]);
    assert!(r.front_ok, "{}", r.rendered);
    let cov = |n: &str| r.coverage.iter().find(|c| c.spec == n).unwrap_or_else(|| panic!("no coverage for {n}: {:?}", r.coverage)).clone();
    let brk = cov("crate::spec::collision");
    assert_eq!(brk.needed, vec!["false"], "a break predicate needs only its `false` outcome");
    assert_eq!(brk.seen, vec!["false"]);
    let same = cov("crate::spec::same");
    assert_eq!(same.needed, vec!["false", "true"], "any other `bool` spec needs both");
}

#[test]
fn the_s5_gate_turns_coverage_gaps_into_errors() {
    use sandblaster_front::diag::Diagnostics;
    use sandblaster_front::driver;
    use std::path::Path;
    let src = format!("{HEADER}{}", r#"
#[cfg(sandblaster)] #[spec] #[example(is_small(3) == true)] fn is_small(x: Nat) -> bool { x < 10 }
#[cfg(sandblaster)] #[spec] fn unused(x: Nat) -> Nat { x }
"#);
    let fs = sandblaster_front::loader::MemFs::from_files([("r/mod.rs", src.as_str())]);
    let c = driver::check(Path::new("r/mod.rs"), &fs, &sandblaster_front::target::TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    let msgs = driver::stage::with_elaboration(k, &driver::VerifyOptions { provers: driver::ProverSet::Standard, exec_only: false }, |out| {
        let mut d = Diagnostics::new();
        sandblaster_front::elab::examples::spec15_gate_s1(out, k, &mut d);
        d.list.iter().map(|x| x.msg.clone()).collect::<Vec<_>>()
    });
    assert!(msgs.iter().any(|m| m.contains("no example of `crate::is_small` has the outcome `false`")), "{msgs:?}");
    assert!(msgs.iter().any(|m| m.contains("spec function `crate::unused` is not exercised by any example")), "{msgs:?}");
}

#[test]
fn examples_on_exec_functions_may_mention_them() {
    verifies(
        r#"
#[example(inc(1) == 2 && inc(255) == 0)]
fn inc(x: u8) -> u8 { x.wrapping_add(1) }
pub fn api(x: u8) -> u8 { inc(x) }
"#,
    );
}
