//! Prover ergonomics, round 2 (role `fix2`): the problems the verifiers of
//! the first round found (`docs/prover-ergonomics-reports.md`). Each test
//! is a minimal repro of one problem; every strengthened step has a
//! negative twin that must still fail.

#[path = "spec15_util.rs"]
mod util;

use util::*;

/// A probe crate: `exec.rs` (exec code) and `PROOF.rs` (ghost items).
fn probe(proof: &str, exec: &str) -> Run {
    let root = "mod exec;\n#[cfg(sandblaster)]\n#[path = \"PROOF.rs\"]\nmod proof;\npub use exec::probe;\n";
    let exec = format!("//! Exec part.\nuse sandblaster::prelude::*;\n/// A stub boundary.\npub fn probe(x: u8) -> u8 {{ x }}\n{exec}");
    let proof = format!("//! Ghost part.\nuse sandblaster::prelude::*;\n{proof}");
    run_files(&[("r/mod.rs", root), ("r/exec.rs", &exec), ("r/PROOF.rs", &proof)])
}

/// Asserts that every definition checked.
#[track_caller]
fn proves(proof: &str, exec: &str) -> Run {
    let r = probe(proof, exec);
    assert!(r.front_ok, "front end rejected the program:\n{}", r.rendered);
    assert!(r.failed_defs.is_empty() && r.unproven.is_empty() && r.errors.is_empty(), "not proven:\n{}", r.explain());
    r
}

/// Asserts that the item `name` (of `PROOF.rs`) is not proven, and that
/// nothing was rejected by the kernel.
#[track_caller]
fn refutes(proof: &str, exec: &str, name: &str) -> Run {
    let r = probe(proof, exec);
    assert!(r.front_ok, "front end rejected the program:\n{}", r.rendered);
    let def = format!("crate::proof::{name}");
    assert!(r.unproven.iter().any(|(d, _, _)| *d == def), "expected `{def}` to be unproven:\n{}", r.explain());
    assert!(!r.rendered.contains("rejected"), "a kernel rejection:\n{}", r.explain());
    r
}

// ---------------------------------------------------------------------------
// bv(): a word identity, also when it falls back to linear arithmetic
// ---------------------------------------------------------------------------

#[test]
fn bv_shift_rule_with_its_side_condition() {
    // the fact bounds the shift amount only: the side condition of the
    // shift rule, which bv() may use
    proves(
        "/// A bit of a byte.\n#[lemma]\nfn byte_bit(b: u8, s: u64) {\n    requires(s < 8);\n    ensures(((b >> s) & 1 != 0) == ((b as Nat / pow2(s as Nat)) % 2 == 1));\n    bv();\n}\n\
         /// A shift by a fixed amount.\n#[lemma]\nfn half(x: u8, s: u32) {\n    requires(s == 1);\n    ensures(x >> s == x / 2);\n    bv();\n}\n",
        "",
    );
}

#[test]
fn bv_negative_a_fact_about_the_shifted_value() {
    // `x == 4` is not a bound on a shift amount: bv() does not use it
    let r = refutes("/// .\n#[lemma]\nfn s5(x: u8, s: u32) {\n    requires(x == 4 && s == 1);\n    ensures(x >> s == 2u8);\n    bv();\n}\n", "", "s5");
    assert!(r.rendered.contains("`bv()` uses no other facts"), "{}", r.rendered);
}

#[test]
fn bv_negative_a_fact_about_the_dividend() {
    let r = refutes("/// .\n#[lemma]\nfn s6(x: Nat) {\n    requires(x == 10);\n    ensures(x / 2 == 5);\n    bv();\n}\n", "", "s6");
    assert!(r.rendered.contains("not a machine-word identity") && !r.rendered.contains("`by_arithmetic()`: the goal"), "{}", r.rendered);
}

#[test]
fn bv_negative_a_let_bound_amount() {
    // `s` is `x` (a `let`): the fact `s == 4` fixes the shifted value `x`
    // too, so it is not a bound on a shift amount (before: both steps were
    // proven by `script(bv)`)
    let r = probe(
        "/// .\n#[lemma]\nfn l1(x: u32) {\n    requires(x == 4);\n    ensures(true);\n    let s = x;\n    assert(s == 4u32, { follows(); });\n    assert((x as u8) >> s == 0u8, { bv(); });\n    follows();\n}\n\
         /// .\n#[lemma]\nfn l3(x: u32) {\n    requires(x == 4);\n    ensures(true);\n    let s = x;\n    assert(s == 4u32, { follows(); });\n    assert(x as Nat / pow2(s as Nat) == 0, { bv(); });\n    follows();\n}\n\
         /// A parameter that is only an amount keeps its bound.\n#[lemma]\nfn l2(y: u8, s: u32) {\n    requires(s < 8);\n    ensures((y >> s) as Nat == y as Nat / pow2(s as Nat));\n    bv();\n}\n",
        "",
    );
    assert!(r.front_ok, "{}", r.rendered);
    for name in ["l1", "l3"] {
        assert!(r.unproven.iter().any(|(d, _, _)| *d == format!("crate::proof::{name}")), "`{name}`: bv() used a fact about the shifted value:\n{}", r.explain());
    }
    assert!(!r.unproven.iter().any(|(d, _, _)| d == "crate::proof::l2") && !r.rendered.contains("rejected"), "{}", r.explain());
}

#[test]
fn bv_negative_a_type_invariant() {
    // a type invariant is a hypothesis about the value, not its type: bv()
    // must not use it (before: `self.v as Nat / 2 == 5` was proven by
    // `script(bv)` from `#[invariant(self.v == 10)]`); follows() may
    let exec = "/// Ten, always.\n#[derive(Clone, Copy)]\n#[invariant(self.v == 10)]\npub struct Ten { v: u8 }\nimpl Ten {\n    /// The only value.\n    pub fn new() -> Ten { Ten { v: 10 } }\n\
                /// A bv() step that needs the invariant.\n    pub fn half(self) -> u8 {\n        proof! { assert(self.v as Nat / 2 == 5, { bv(); }); }\n        self.v / 2\n    }\n\
                /// The same step, by follows().\n    pub fn half2(self) -> u8 {\n        proof! { assert(self.v as Nat / 2 == 5, { follows(); }); }\n        self.v / 2\n    }\n}\n";
    let r = probe("", exec);
    assert!(r.front_ok, "front end rejected the program:\n{}", r.rendered);
    assert!(r.unproven.iter().any(|(d, _, _)| d == "crate::exec::Ten::half"), "bv() used the invariant:\n{}", r.explain());
    assert!(!r.unproven.iter().any(|(d, _, _)| d == "crate::exec::Ten::half2"), "{}", r.explain());
    assert!(r.rendered.contains("`bv()` uses no other facts") && !r.rendered.contains("rejected"), "{}", r.rendered);
}

// ---------------------------------------------------------------------------
// Int `/` and `%` by a variable: the well-formedness proofs are in scope
// ---------------------------------------------------------------------------

#[test]
fn int_division_by_a_variable_in_a_spec_function() {
    // before: the kernel rejected `q` (the second and third proofs were
    // proven one and two binders too deep)
    proves(
        "/// Divides Ints.\n#[spec]\nfn q(v: Int, x: Int, y: Int) -> Int {\n    if v != 0 && x >= 0 && y > 0 { x / y } else { 0 }\n}\n\
         /// A lemma that names a division.\n#[lemma]\nfn t3(x: Int, y: Int) {\n    requires(x >= 0 && y > 0);\n    ensures(y > 0);\n    let d = x / y;\n    follows();\n}\n\
         /// A remainder by pow2 of a cast.\n#[lemma]\nfn t4(x: u8, s: u32) {\n    ensures(x as Int % pow2(s as Int) == x as Int % pow2(s as Int));\n    follows();\n}\n",
        "",
    );
}

#[test]
fn int_division_negative_the_divisor_may_be_zero() {
    refutes("/// Divides Ints.\n#[spec]\nfn q(x: Int, y: Int) -> Int {\n    if x >= 0 && y >= 0 { x / y } else { 0 }\n}\n", "", "q");
}

/// The unproven obligations of `crate::proof::{name}`: `(kind, goal)`.
fn unproven_of(r: &Run, name: &str) -> Vec<(String, String)> {
    let def = format!("crate::proof::{name}");
    r.unproven.iter().filter(|(d, _, _)| *d == def).map(|(_, k, g)| (k.clone(), g.clone())).collect()
}

#[test]
fn int_division_obligations_name_the_right_operands() {
    // each well-formedness obligation is stated at its own scope: it names
    // the operand the source divides by, never a neighbouring variable (the
    // old misscoping shifted them onto other binders or the earlier proofs)
    let r = probe(
        "/// The divisor may be zero (`z` is the positive one).\n#[spec]\nfn q1(x: Int, y: Int, z: Int) -> Int { if x >= 0 && y >= 0 && z > 0 { x / y } else { 0 } }\n\
         /// The dividend may be negative (`w` is the non-negative one).\n#[spec]\nfn q2(w: Int, x: Int, y: Int) -> Int { if w >= 0 && y > 0 { x / y } else { 0 } }\n\
         /// A Nat remainder by a Nat that may be zero.\n#[spec]\nfn q4(a: Nat, x: Nat, y: Nat) -> Nat { if a > 0 { x % y } else { 0 } }\n\
         /// An Int remainder by a divisor that may be negative.\n#[spec]\nfn q5(x: Int, y: Int, z: Int) -> Int { if x >= 0 && y != 0 && z > 0 { x % y } else { 0 } }\n\
         /// Control: every operand is in range.\n#[spec]\nfn q6(x: Int, y: Int, z: Int) -> Int { if x >= 0 && y > 0 && z != 0 { x % y + x / y } else { 0 } }\n",
        "",
    );
    assert!(r.front_ok, "{}", r.rendered);
    assert!(!r.rendered.contains("rejected"), "a kernel rejection:\n{}", r.explain());
    let one = |name: &str| -> (String, String) {
        let v = unproven_of(&r, name);
        assert_eq!(v.len(), 1, "`{name}`: expected one unproven obligation:\n{}", r.explain());
        v[0].clone()
    };
    assert_eq!(one("q1"), ("div-zero".to_string(), "Eq(Bool, #ne_int(y, 0int), true)".to_string()));
    assert_eq!(one("q2"), ("well-formed".to_string(), "Eq(Bool, #le_int(0int, x), true)".to_string()));
    assert_eq!(one("q4"), ("div-zero".to_string(), "Eq(Bool, #ne_int(y, 0int), true)".to_string()));
    assert_eq!(one("q5"), ("well-formed".to_string(), "Eq(Bool, #le_int(0int, y), true)".to_string()));
    assert!(unproven_of(&r, "q6").is_empty() && !r.failed_defs.iter().any(|(d, _)| d == "crate::proof::q6"), "{}", r.explain());
}

#[test]
fn int_division_negative_a_zero_divisor() {
    let r = refutes("/// Divides by zero.\n#[spec]\nfn q3(x: Nat) -> Nat { x / 0 }\n", "", "q3");
    assert_eq!(unproven_of(&r, "q3"), vec![("div-zero".to_string(), "Eq(Bool, #ne_int(0int, 0int), true)".to_string())], "{}", r.explain());
    let r = refutes("/// Remainder by zero.\n#[spec]\nfn q3(x: Int) -> Int { if x >= 0 { x % 0 } else { 0 } }\n", "", "q3");
    assert_eq!(unproven_of(&r, "q3"), vec![("div-zero".to_string(), "Eq(Bool, #ne_int(0int, 0int), true)".to_string())], "{}", r.explain());
}

#[test]
fn int_division_in_a_lemma_script() {
    // an Int dividend and a variable divisor in script `let`s: both
    // well-formed at their own scope (before: "`fst` of a non-pair")
    proves("/// .\n#[lemma]\nfn t7(v: Int, x: Int, y: Int) {\n    requires(x >= 0 && y > 0);\n    ensures(v == v);\n    let d = x / y;\n    let m = x % y;\n    follows();\n}\n", "");
}

// ---------------------------------------------------------------------------
// calc!: one error for one failed link
// ---------------------------------------------------------------------------

const WRAP: &str = "/// Wrap a slice.\npub fn wrap(xs: &[u8]) -> Option<(u8, &[u8])> { Some((7u8, xs)) }\n/// Wrap with another tag.\npub fn wrap8(xs: &[u8]) -> Option<(u8, &[u8])> { Some((8u8, xs)) }\n";

#[test]
fn calc_failed_link_is_reported_once() {
    let r = refutes(
        r#"
/// Spec wrap.
#[spec]
fn swrap(ys: Seq<u8>) -> Option<(Nat, Seq<u8>)> { Some((7, ys)) }

/// The view link.
#[lemma]
fn direct(xs: &[u8], ys: Seq<u8>) {
    requires(xs == ys);
    ensures(crate::exec::wrap(xs) == swrap(ys));
    unfold(crate::exec::wrap);
    follows();
}

/// A wrong exec link, then the view link.
#[lemma]
fn c1(xs: &[u8], ys: Seq<u8>) {
    requires(xs == ys);
    ensures(crate::exec::wrap8(xs) == swrap(ys));
    calc! {
        crate::exec::wrap8(xs)
            == crate::exec::wrap(xs) by { follows(); };
            == swrap(ys) by { direct(xs, ys); };
    }
}
"#,
        WRAP,
        "c1",
    );
    assert_eq!(r.unproven.iter().filter(|(d, _, _)| d == "crate::proof::c1").count(), 1, "{}", r.explain());
    assert!(!r.rendered.contains("do not compose") && !r.rendered.contains("Erased"), "{}", r.rendered);
}

// ---------------------------------------------------------------------------
// the `[init @ .., last]` view needs no call
// ---------------------------------------------------------------------------

#[test]
fn take_snoc_applies_by_itself() {
    proves(
        "/// .\n#[lemma]\nfn q2(xs: Seq<u8>, n: Nat) {\n    requires(n + 1 == xs.len());\n    ensures(seq![..xs.take(n), xs[n]] == xs);\n    follows();\n}\n\
         /// The other orientation.\n#[lemma]\nfn q2_rev(xs: Seq<u8>, n: Nat) {\n    requires(n + 1 == xs.len());\n    ensures(xs == seq![..xs.take(n), xs[n]]);\n    follows();\n}\n",
        "",
    );
}

#[test]
fn take_snoc_negative_wrong_length() {
    refutes("/// .\n#[lemma]\nfn q2(xs: Seq<u8>, n: Nat) {\n    requires(n + 2 == xs.len());\n    ensures(seq![..xs.take(n), xs[n]] == xs);\n    follows();\n}\n", "", "q2");
}

// ---------------------------------------------------------------------------
// Nat ranges: recursive calls bound by `let`; a missing range is named
// ---------------------------------------------------------------------------

const PK: &str = "/// A struct of Nats.\n#[derive(Clone, Copy, PartialEq, Eq)]\nstruct Pk { h: Nat, i: Nat }\n\
                  /// Built through a `let` of the recursive call.\n#[spec]\n#[decreases(n)]\nfn pk(n: Nat, i: Nat) -> Pk { if n == 0 { Pk { h: 0, i: i } } else { let p = pk(n - 1, i + 1); Pk { h: p.h + 1, i: p.i } } }\n";

#[test]
fn nat_range_of_a_recursive_struct_builder() {
    proves(&format!("{PK}/// .\n#[lemma]\nfn lp(n: Nat, i: Nat) {{ ensures(pk(n, i).h + pk(n, i).i >= 0); by_arithmetic(); }}\n"), "");
}

#[test]
fn nat_range_negative_not_an_upper_bound() {
    refutes(&format!("{PK}/// .\n#[lemma]\nfn lp(n: Nat, i: Nat) {{ ensures(pk(n, i).h <= n); by_arithmetic(); }}\n"), "", "lp");
}

#[test]
fn nat_range_missing_is_named() {
    // the range proof of `m` fails (nothing says the elements of a
    // `Seq<Nat>` are non-negative): a failing step about `m` says why it
    // has no range fact
    let r = refutes(
        "/// An element.\n#[spec]\nfn m(s: Seq<Nat>) -> Nat { match s.get(0) { Some(v) => v, None => 0 } }\n/// .\n#[lemma]\nfn use_m(s: Seq<Nat>) { ensures(m(s) >= 0); by_arithmetic(); }\n",
        "",
        "use_m",
    );
    assert!(r.rendered.contains("has no automatic Nat range fact"), "{}", r.rendered);
}

const CNT: &str = "/// A Nat through an Option.\n#[spec]\n#[decreases(n)]\nfn cnt(n: Nat) -> Option<Nat> { if n == 0 { Some(0) } else { match cnt(n - 1) { Some(k) => Some(k + 1), None => None } } }\n";

#[test]
fn nat_range_of_an_option_payload_bound_by_a_pattern() {
    // the payload of `cnt(n)`, bound by a script `match` or named by a fact,
    // is non-negative by `cnt`'s range lemma. (A goal that is itself a
    // `match cnt(n) { .. }` is not split by auto: evaluation unrolls the
    // transparent recursive `cnt` there, with or without a range — the
    // PROOF-GUIDE says to write the `match` in the script.)
    proves(
        &format!(
            "{CNT}/// .\n#[lemma]\nfn z3(n: Nat) {{\n    ensures(match cnt(n) {{ Some(k) => k >= 0, None => true }});\n    match cnt(n) {{\n        Some(k) => follows(),\n        None => follows(),\n    }}\n}}\n\
             /// .\n#[lemma]\nfn z3_fact(n: Nat, k: Nat) {{ requires(cnt(n) == Some(k)); ensures(k >= 0); by_arithmetic(); }}\n"
        ),
        "",
    );
}

#[test]
fn nat_range_missing_is_named_for_a_fact() {
    // the range-less function occurs in a fact, not in the goal: the note
    // still names it
    let r = refutes(
        "/// An element.\n#[spec]\nfn m(s: Seq<Nat>) -> Nat { match s.get(0) { Some(v) => v, None => 0 } }\n/// .\n#[lemma]\nfn use_m(s: Seq<Nat>, j: Int) { requires(m(s) as Int == j); ensures(j >= 0); by_arithmetic(); }\n",
        "",
        "use_m",
    );
    assert!(r.rendered.contains("`proof::m` has no automatic Nat range fact"), "{}", r.rendered);
}

#[test]
fn nat_range_of_an_option_payload_negative_upper_bound() {
    // in the script-`match` form, where the positive case proves
    refutes(&format!("{CNT}/// .\n#[lemma]\nfn z3(n: Nat) {{\n    ensures(match cnt(n) {{ Some(k) => k < n, None => true }});\n    match cnt(n) {{\n        Some(k) => follows(),\n        None => follows(),\n    }}\n}}\n"), "", "z3");
}

// ---------------------------------------------------------------------------
// facts are simplified with what the facts say (B1, X3)
// ---------------------------------------------------------------------------

const FLD: &str = "/// The first `n` bytes and the rest.\n#[spec]\n#[opaque]\nfn fld(n: Nat, b: Seq<u8>) -> Option<(Seq<u8>, Seq<u8>)> { if b.len() < n { None } else { Some((b.take(n), b.skip(n))) } }\n";

#[test]
fn unfolded_fact_is_decided_by_its_value() {
    // the fact `if b.len() < n { None } else { Some(..) } == Some((a, r))`:
    // only the `else` arm can be `Some`; `a` is `b.take(n)`, whose length is
    // `n` (the goal's variable is replaced by its definition)
    proves(
        &format!(
            "{FLD}/// .\n#[lemma]\nfn fld_len(n: Nat, b: Seq<u8>, a: Seq<u8>, r: Seq<u8>) {{\n    requires(fld(n, b) == Some((a, r)));\n    ensures(a.len() == n);\n    by_unfolding(fld);\n}}\n\
             /// The split, without a case split or a helper lemma.\n#[lemma]\nfn fld_split(n: Nat, b: Seq<u8>, a: Seq<u8>, r: Seq<u8>) {{\n    requires(fld(n, b) == Some((a, r)));\n    ensures(b == seq![..a, ..r] && a.len() == n);\n    by_unfolding(fld);\n}}\n"
        ),
        "",
    );
}

#[test]
fn unfolded_fact_negative_wrong_part() {
    refutes(&format!("{FLD}/// .\n#[lemma]\nfn fld_len(n: Nat, b: Seq<u8>, a: Seq<u8>, r: Seq<u8>) {{\n    requires(fld(n, b) == Some((a, r)));\n    ensures(r.len() == n);\n    by_unfolding(fld);\n}}\n"), "", "fld_len");
}

const GROUPS: &str = "/// varint\n#[spec]\n#[decreases(x)]\npub fn varint(x: Nat) -> Seq<u8> { if x < 128 { seq![x as u8] } else { seq![(128 + x % 128) as u8, ..varint(x / 128)] } }\n\
    /// groups\n#[spec]\npub(crate) fn groups(b: Seq<u8>, first: bool) -> Option<(Nat, Seq<u8>)> {\n    match b {\n        [g, rest @ ..] if g >= 128 => { let (x, rest) = groups(rest, false)?; Some((g as Nat - 128 + 128 * x, rest)) }\n        [g, rest @ ..] if g != 0 || first => Some((g as Nat, rest)),\n        _ => None,\n    }\n}\n";

#[test]
fn natural_varint_proofs() {
    // the QMDB codec lemmas in their natural form: no one-step lemmas of
    // `varint`/`groups`, no `split_group`, no nonnegativity lemma
    proves(
        &format!(
            "{GROUPS}/// .\n#[lemma]\n#[decreases(x)]\nfn groups_varint(x: Nat, r: Seq<u8>, first: bool) {{\n    requires(first || x > 0);\n    ensures(groups(seq![..varint(x), ..r], first) == Some((x, r)));\n    if x >= 128 {{\n        groups_varint(x / 128, r, false);\n        follows();\n    }} else {{\n        follows();\n    }}\n}}\n\
             /// .\n#[lemma]\nfn groups_nonneg(b: Seq<u8>, first: bool, x: Nat, r: Seq<u8>) {{\n    requires(groups(b, first) == Some((x, r)));\n    ensures(x >= 0);\n    by_arithmetic();\n}}\n\
             /// .\n#[lemma]\n#[induction(b)]\nfn groups_minimal(b: Seq<u8>, first: bool, x: Nat, r: Seq<u8>) {{\n    requires(groups(b, first) == Some((x, r)));\n    ensures(b == seq![..varint(x), ..r] && (first || x > 0));\n    match b {{\n        [g, rest @ ..] => {{\n            if g >= 128 {{\n                match groups(rest, false) {{\n                    None => follows(),\n                    Some((y, s)) => {{\n                        ih(rest, false, y, s);\n                        follows();\n                    }}\n                }}\n            }} else {{\n                follows();\n            }}\n        }}\n        [] => follows(),\n    }}\n}}\n"
        ),
        "",
    );
}

#[test]
fn natural_varint_negative_first_zero_group() {
    // with `first`, a single zero byte reads as 0: `x > 0` does not follow
    refutes(
        &format!("{GROUPS}/// .\n#[lemma]\nfn groups_pos(b: Seq<u8>, first: bool, x: Nat, r: Seq<u8>) {{\n    requires(groups(b, first) == Some((x, r)));\n    ensures(x > 0);\n    match b {{\n        [g, rest @ ..] => follows(),\n        [] => follows(),\n    }}\n}}\n"),
        "",
        "groups_pos",
    );
}

#[test]
fn empty_sequence_from_its_length() {
    proves("/// .\n#[lemma]\nfn app_empty(ys: Seq<u8>, x: u8) {\n    requires(ys.len() == 0);\n    ensures(seq![..ys, x] == seq![x]);\n    follows();\n}\n\
            /// Through a slice view.\n#[lemma]\nfn app_empty_view(xs: &[u8], ys: Seq<u8>, x: u8) {\n    requires(xs == ys && xs.len() == 0usize);\n    ensures(seq![..ys, x] == seq![x]);\n    follows();\n}\n", "");
}

#[test]
fn empty_sequence_negative() {
    refutes("/// .\n#[lemma]\nfn app1(ys: Seq<u8>, x: u8) {\n    requires(ys.len() == 1);\n    ensures(seq![..ys, x] == seq![x]);\n    follows();\n}\n", "", "app1");
}

// ---------------------------------------------------------------------------
// slice patterns in script matches (C2, X1, X2)
// ---------------------------------------------------------------------------

const GO: &str = "/// Fold from the back.\npub(crate) fn go(xs: &[[u8; 4]], acc: [u8; 4]) -> [u8; 4] {\n    match xs {\n        [] => acc,\n        [init @ .., last] => go(init, *last),\n    }\n}\n";

#[test]
fn unfold_in_an_init_last_arm() {
    // before: `unfold` failed to elaborate ("type mismatch for `false`"): the
    // arm's goal had the slice replaced by the length test's `false`
    proves(
        "/// .\n#[lemma]\nfn go_last(xs: &[[u8; 4]], acc: [u8; 4]) {\n    requires(xs.len() > 0usize);\n    ensures(crate::exec::go(xs, acc) == crate::exec::go(&xs[..xs.len() - 1], xs[xs.len() - 1]));\n    match xs {\n        [] => by_contradiction(),\n        [init @ .., last] => {\n            unfold(crate::exec::go);\n            follows();\n        }\n    }\n}\n",
        GO,
    );
}

#[test]
fn slice_pattern_views() {
    proves(
        "/// .\n#[lemma]\nfn views(xs: &[[u8; 4]], ys: Seq<[u8; 4]>) {\n    requires(xs == ys && xs.len() > 0usize);\n    ensures(true);\n    match xs {\n        [] => by_contradiction(),\n        [init @ .., last] => {\n            assert(*last == ys[ys.len() - 1], { follows(); });\n            assert(*init == ys.take(ys.len() - 1), { follows(); });\n            follows();\n        }\n    }\n}\n\
         /// .\n#[lemma]\nfn views_ht(xs: &[[u8; 4]], ys: Seq<[u8; 4]>) {\n    requires(xs == ys && xs.len() > 0usize);\n    ensures(true);\n    match xs {\n        [] => by_contradiction(),\n        [head, tail @ ..] => {\n            assert(*head == ys[0], { follows(); });\n            assert(*tail == ys.skip(1), { follows(); });\n            follows();\n        }\n    }\n}\n",
        GO,
    );
}

#[test]
fn slice_pattern_views_negative() {
    refutes(
        "/// .\n#[lemma]\nfn views(xs: &[u8], ys: Seq<u8>) {\n    requires(xs == ys && xs.len() > 1usize);\n    ensures(true);\n    match xs {\n        [] => by_contradiction(),\n        [init @ .., last] => {\n            assert(*last == ys[0], { follows(); });\n            follows();\n        }\n    }\n}\n",
        "",
        "views",
    );
}

// ---------------------------------------------------------------------------
// unfold finds a call in an arm of the goal (B6)
// ---------------------------------------------------------------------------

const RD: &str = "/// A reader.\npub(crate) fn rd(xs: &[u8]) -> Option<(u8, &[u8])> {\n    match xs {\n        [] => None,\n        [h, t @ ..] => Some((*h, t)),\n    }\n}\n/// A reader with fuel.\npub(crate) fn outer(f: u32, xs: &[u8]) -> Option<(u8, &[u8])> {\n    if f == 0 {\n        return None;\n    }\n    rd(xs)\n}\n";

#[test]
fn unfold_a_call_in_an_arm() {
    proves("/// .\n#[lemma]\nfn outer_empty(f: u32, xs: &[u8]) {\n    requires(f == 1u32 && xs.len() == 0usize);\n    ensures(crate::exec::outer(f, xs) == None);\n    unfold(crate::exec::outer);\n    unfold(crate::exec::rd);\n    follows();\n}\n", RD);
}

#[test]
fn unfold_a_call_in_an_arm_negative() {
    refutes("/// .\n#[lemma]\nfn outer_some(f: u32, xs: &[u8]) {\n    requires(f == 1u32 && xs.len() == 0usize);\n    ensures(crate::exec::outer(f, xs) != None);\n    unfold(crate::exec::outer);\n    unfold(crate::exec::rd);\n    follows();\n}\n", RD, "outer_some");
}

// ---------------------------------------------------------------------------
// one view link in the narrow closers (B10)
// ---------------------------------------------------------------------------

const REC: &str = "/// An exec record.\n#[derive(Clone, Copy)]\npub struct E { pub loc: u64, pub leaves: u64 }\n";
const VIEW: &str = "/// A spec record.\n#[derive(Clone, Copy, PartialEq, Eq)]\nstruct S { loc: Nat, leaves: Nat }\n/// The view.\n#[spec]\nfn view(e: crate::exec::E) -> S { S { loc: e.loc as Nat, leaves: e.leaves as Nat } }\n";

#[test]
fn view_link_in_by_arithmetic() {
    proves(&format!("{VIEW}/// .\n#[lemma]\nfn b10(e: crate::exec::E, q: S) {{\n    requires(q == view(e));\n    requires(q.loc < q.leaves);\n    ensures(e.loc < e.leaves);\n    by_arithmetic();\n}}\n"), REC);
}

#[test]
fn view_link_negative() {
    refutes(&format!("{VIEW}/// .\n#[lemma]\nfn b10(e: crate::exec::E, q: S) {{\n    requires(q == view(e));\n    requires(q.loc <= q.leaves);\n    ensures(e.loc < e.leaves);\n    by_arithmetic();\n}}\n"), REC, "b10");
}
