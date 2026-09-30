//! Red-team round 2 regressions (prover soundness and honesty), one test
//! per finding:
//!
//! * `Nat` inside `Seq`/`Option`/enums is bounded in every binder position
//!   (`Elab::nat_bounds`, SEMANTICS.md §13.5): the false statements that
//!   used to prove (a `forall` over `Seq<Nat>` instantiated at a
//!   `Seq<Int>`, an `exists` over `Seq<Nat>` with a `Seq<Int>` witness)
//!   fail, and their true twins with well-formed witnesses still prove;
//! * `by_arithmetic()` gets the field equations of a view link only for a
//!   type's `#[view]` or the fields a function copies from its arguments;
//! * a `calc!` chain from exec values through a spec value and back is a
//!   script error, never an ill-typed proof for the kernel;
//! * a law or lemma removed by a `cfg` is reported;
//! * a law's header `let`s are not an inline proof, and the statement
//!   printed for it shows them;
//! * a definition checked against a stand-in body is blocked, not checked;
//! * a named lemma call whose value argument contradicts its type argument
//!   is an error;
//! * exceeding the 4096-bit `Int` limit is a user error, not an internal
//!   one.

#[path = "spec15_util.rs"]
mod util;

use sandblaster_front::diag::DiagKind as K;
use util::*;

/// A crate with a spec module, a `LAWS.rs` and a `PROOF.rs` (and a trivial
/// boundary function).
fn crate_of(spec: &str, laws: &str, proof: &str) -> Run {
    let root = "#[cfg(sandblaster)]\n#[spec]\nmod spec;\n#[cfg(sandblaster)]\n#[path = \"LAWS.rs\"]\nmod laws;\n#[cfg(sandblaster)]\n#[path = \"PROOF.rs\"]\nmod proof;\n/// The boundary.\npub fn api(x: u8) -> u8 { x }\n";
    let spec = format!("use sandblaster::prelude::*;\n{spec}");
    // the spec items used, imported by name (no glob imports)
    let names: Vec<&str> = SPEC_NAMES.iter().copied().filter(|n| spec.contains(&format!("pub fn {n}(")) || spec.contains(&format!("pub enum {n} ")) || spec.contains(&format!("pub struct {n} "))).collect();
    let uses = if names.is_empty() { String::new() } else { format!("#[allow(unused_imports)]\nuse crate::spec::{{{}}};\n", names.join(", ")) };
    let laws = format!("use sandblaster::prelude::*;\n{uses}{laws}");
    let proof = format!("use sandblaster::prelude::*;\n{uses}{proof}");
    run_files(&[("r/mod.rs", root), ("r/spec.rs", &spec), ("r/LAWS.rs", &laws), ("r/PROOF.rs", &proof)])
}

/// The spec item names the tests use.
const SPEC_NAMES: &[&str] = &["neg_seq", "sid", "E", "L", "P", "Q", "mk", "cp", "pred"];

/// Whether definition `name` did not check.
fn failed(r: &Run, name: &str) -> bool {
    r.failed_defs.iter().any(|(n, _)| n == name)
}

#[track_caller]
fn assert_failed(r: &Run, names: &[&str]) {
    for n in names {
        assert!(failed(r, n), "`{n}` should not check:\n{}", r.explain());
    }
}

#[track_caller]
fn assert_checked(r: &Run, names: &[&str]) {
    for n in names {
        assert!(r.checked_defs.iter().any(|x| x == n), "`{n}` should check:\n{}", r.explain());
    }
}

#[track_caller]
fn no_kernel_rejection(r: &Run) {
    assert!(!r.errors.iter().any(|(_, m)| m.contains("kernel rejected") || m.contains("internal")), "a kernel rejection or internal error:\n{}", r.explain());
}

// ---------------------------------------------------------------------------
// Nat inside containers (critical)
// ---------------------------------------------------------------------------

const NEG_SPEC: &str = r#"
/// A sequence holding a negative integer.
pub fn neg_seq() -> Seq<Int> { seq![0 - 1] }
/// The identity on naturals.
pub fn sid(x: Nat) -> Nat { x }
/// An enum with a natural payload.
#[derive(Clone, Copy)]
pub enum E { A(Nat), B }
"#;

/// red1 a7: a false law (some `Seq<Nat>` has an element below every
/// natural, false at `n = 0`) proven with the `Seq<Int>` witness
/// `neg_seq()` by unification. The witness now needs its well-formedness.
#[test]
fn exists_over_seq_of_nat_needs_a_well_formed_witness() {
    let laws = r#"
/// Some sequence of naturals has an element below every natural `n`.
#[law]
fn below_every_natural(n: Nat) { ensures(exists(|xs: Seq<Nat>| xs.len() == 1 && xs[0] < sid(n) as Int)); }
"#;
    let proof = r#"
#[lemma]
fn helper(ys: Seq<Int>, n: Nat) {
    requires(ys.len() == 1);
    requires(ys[0] < sid(n) as Int);
    ensures(exists(|xs: Seq<Nat>| xs.len() == 1 && xs[0] < sid(n) as Int));
    follows();
}
#[proof]
fn below_every_natural(n: Nat) { assert(sid(n) == n); helper(neg_seq(), n); follows(); }

/// red1 a6 x4: closed and false.
#[lemma]
fn x4() { ensures(exists(|xs: Seq<Nat>| xs.len() == 1 && xs[0] < 0)); follows(); }

/// TRUE twins: a concrete well-formed witness; a witness that is a
/// parameter of type `Seq<Nat>` (its well-formedness is a hypothesis of a
/// lemma whose contract quantifies over `Seq<Nat>`), and a caller that
/// proves it for a literal.
#[lemma]
fn t_concrete() { ensures(exists(|xs: Seq<Nat>| xs == seq![3, 7])); follows(); }
#[lemma]
fn t_param(ys: Seq<Nat>) {
    requires(ys.len() == 1);
    ensures(exists(|xs: Seq<Nat>| xs == ys && xs.len() == 1));
    follows();
}
#[lemma]
fn t_call() { ensures(exists(|xs: Seq<Nat>| xs == seq![5] && xs.len() == 1)); t_param(seq![5]); }
"#;
    let r = crate_of(NEG_SPEC, laws, proof);
    assert!(r.front_ok, "{}", r.rendered);
    no_kernel_rejection(&r);
    assert_failed(&r, &["crate::laws::below_every_natural", "crate::proof::helper", "crate::proof::x4"]);
    assert_checked(&r, &["crate::proof::t_concrete", "crate::proof::t_param", "crate::proof::t_call"]);
}

/// red1 a2 f1, a3 g4, a5: a `forall` over `Seq<Nat>` (or `Seq<(Nat, u8)>`,
/// an enum payload) in a hypothesis must not be instantiated at a sequence
/// of integers.
#[test]
fn forall_over_seq_of_nat_is_not_instantiated_at_ints() {
    let proof = r#"
/// red1 a2 f1: proves `false`.
#[lemma]
fn f1(ys: Seq<Int>) {
    requires(forall(|xs: Seq<Nat>| implies(xs.len() == 1, xs[0] >= 0)));
    requires(ys.len() == 1 && ys[0] == -1);
    ensures(false);
    assert(implies(ys.len() == 1, ys[0] >= 0));
    assert(ys[0] >= 0);
    follows();
}
/// red1 a3 g4: the tuple form.
#[lemma]
fn g4(ys: Seq<(Int, u8)>) {
    requires(forall(|xs: Seq<(Nat, u8)>| implies(xs.len() == 1, xs[0].0 >= 0)));
    requires(ys.len() == 1 && ys[0].0 == -1);
    ensures(false);
    assert(implies(ys.len() == 1, ys[0].0 >= 0));
    assert(ys[0].0 >= 0);
    follows();
}
/// An `Option<Nat>` witness.
#[lemma]
fn f_opt() { ensures(exists(|o: Option<Nat>| o == Some(0 - 1))); follows(); }
/// TRUE twins: instantiation at a `Seq<Nat>` parameter and at a literal.
#[lemma]
fn t1(ys: Seq<Nat>) {
    requires(forall(|xs: Seq<Nat>| implies(xs.len() == 1, xs[0] >= 5)));
    requires(ys.len() == 1);
    ensures(ys[0] >= 5);
    assert(implies(ys.len() == 1, ys[0] >= 5));
    follows();
}
#[lemma]
fn t2() {
    requires(forall(|xs: Seq<Nat>| implies(xs.len() == 2, xs[0] + xs[1] >= 5)));
    ensures(seq![2, 3][0] + seq![2, 3][1] >= 5);
    assert(implies(seq![2, 3].len() == 2, seq![2, 3][0] + seq![2, 3][1] >= 5));
    follows();
}
#[lemma]
fn t_opt() { ensures(exists(|o: Option<Nat>| o == Some(4))); follows(); }
"#;
    let r = crate_of(NEG_SPEC, "", proof);
    assert!(r.front_ok, "{}", r.rendered);
    no_kernel_rejection(&r);
    assert_failed(&r, &["crate::proof::f1", "crate::proof::g4", "crate::proof::f_opt"]);
    assert_checked(&r, &["crate::proof::t1", "crate::proof::t2", "crate::proof::t_opt"]);
}

/// red1 a5: a law whose hypothesis is true in the source (every `Seq<Nat>`
/// has non-negative elements) but was false in the kernel (instantiated at
/// the `Seq<Int>` parameter).
#[test]
fn law_hypothesis_over_seq_of_nat_keeps_its_source_meaning() {
    let laws = r#"
/// Every sequence of naturals starts non-negative, so a sequence equal to `neg_seq` does too.
#[law]
fn nat_seq_law(ys: Seq<Int>) {
    requires(forall(|xs: Seq<Nat>| implies(xs.len() == ys.len() && xs.len() > 0, xs[0] >= 0)));
    requires(ys == neg_seq());
    ensures(ys[0] >= 0);
}
"#;
    let proof = r#"
#[proof]
fn nat_seq_law(ys: Seq<Int>) {
    assert(ys.len() == 1);
    assert(implies(ys.len() == ys.len() && ys.len() > 0, ys[0] >= 0));
    follows();
}
"#;
    let r = crate_of(NEG_SPEC, laws, proof);
    assert!(r.front_ok, "{}", r.rendered);
    no_kernel_rejection(&r);
    assert_failed(&r, &["crate::laws::nat_seq_law"]);
}

/// A law's `Seq<Nat>`/`Option<Nat>` parameters carry their
/// well-formedness: the law is a witness and an instance of quantifiers
/// over `Seq<Nat>`, and its elements are non-negative.
#[test]
fn law_parameters_carry_container_bounds() {
    let laws = r#"
/// A sequence of naturals is its own witness.
#[law]
fn l_exists(ys: Seq<Nat>) { requires(ys.len() == 1); ensures(exists(|xs: Seq<Nat>| xs == ys && xs.len() == 1)); }
/// A forall over sequences of naturals applies to a parameter.
#[law]
fn l_forall(ys: Seq<Nat>) { requires(forall(|xs: Seq<Nat>| implies(xs.len() == 1, xs[0] >= 5))); requires(ys.len() == 1); ensures(ys[0] >= 5); }
/// An optional natural is non-negative.
#[law]
fn l_elem(o: Option<Nat>) { ensures(match o { Some(n) => n >= 0, None => true }); }
"#;
    let proof = r#"
#[proof]
fn l_exists(ys: Seq<Nat>) { follows(); }
#[proof]
fn l_forall(ys: Seq<Nat>) { assert(implies(ys.len() == 1, ys[0] >= 5)); follows(); }
#[proof]
fn l_elem(o: Option<Nat>) { match o { Some(n) => follows(), None => follows() } }
"#;
    let r = crate_of(NEG_SPEC, laws, proof);
    assert!(r.front_ok, "{}", r.rendered);
    no_kernel_rejection(&r);
    assert_checked(&r, &["crate::laws::l_exists", "crate::laws::l_forall", "crate::laws::l_elem"]);
}

/// A `Nat` inside a recursive type has no finite well-formedness term: a
/// quantifier over it is an error, not an unguarded binder.
#[test]
fn nat_inside_a_recursive_type_is_rejected_in_a_quantifier() {
    let spec = r#"
/// A list of naturals.
#[derive(Clone, Copy)]
pub enum L { Nil, Cons(Nat, L) }
"#;
    let proof = r#"
#[lemma]
fn q() { ensures(exists(|l: L| l == L::Nil)); follows(); }
"#;
    let r = crate_of(spec, "", proof);
    assert!(r.front_ok, "{}", r.rendered);
    assert!(failed(&r, "crate::proof::q"), "{}", r.explain());
    assert!(r.errors.iter().any(|(_, m)| m.contains("recursive type")), "{}", r.explain());
}

// ---------------------------------------------------------------------------
// by_arithmetic() and view links (medium) / built-in rules (low)
// ---------------------------------------------------------------------------

/// red0 p9: the field equations of `s == mk(x)` for a function that
/// computes its fields are not arithmetic; a function that copies them is.
#[test]
fn by_arithmetic_sees_only_copied_fields_of_a_record_builder() {
    let spec = r#"
/// A pair.
#[derive(Clone, Copy)]
pub struct P { pub a: Int, pub b: Int }
/// Another pair.
#[derive(Clone, Copy)]
pub struct Q { pub u: Int, pub v: Int }
/// Computes its fields.
pub fn mk(x: Int) -> P { P { a: x + 7, b: x * 3 } }
/// Copies its fields.
pub fn cp(q: Q) -> P { P { a: q.v, b: q.u } }
"#;
    let proof = r#"
#[lemma]
fn f_arith_field(x: Int, s: P) { requires(s == mk(x)); ensures(s.a == x + 7); by_arithmetic(); }
#[lemma]
fn t_unf_field(x: Int, s: P) { requires(s == mk(x)); ensures(s.a == x + 7); by_unfolding(mk); }
#[lemma]
fn t_copied(q: Q, s: P) { requires(s == cp(q)); ensures(s.a == q.v && s.b == q.u); by_arithmetic(); }
/// The built-in `Seq` rules are part of `by_arithmetic()` (PROOF-GUIDE §3).
#[lemma]
fn t_seq(xs: Seq<u8>) { ensures(xs.skip(1).get(0) == xs.get(1)); by_arithmetic(); }
"#;
    let r = crate_of(spec, "", proof);
    assert!(r.front_ok, "{}", r.rendered);
    assert_failed(&r, &["crate::proof::f_arith_field"]);
    assert_checked(&r, &["crate::proof::t_unf_field", "crate::proof::t_copied", "crate::proof::t_seq"]);
}

// ---------------------------------------------------------------------------
// calc! from exec to spec and back (medium)
// ---------------------------------------------------------------------------

/// red0 p21: a TRUE statement; the chain composes at the view type only.
/// A clear script error, no ill-typed proof for the kernel.
#[test]
fn calc_chain_back_to_exec_values_is_a_script_error() {
    let body = r#"
/// A point with a view.
#[derive(Clone, Copy, PartialEq)]
#[view(|p| p.x as Nat)]
pub struct Q { x: u32 }
/// One.
pub fn mk1() -> Q { Q { x: 1 } }
/// One again.
pub fn mk3() -> Q { Q { x: 1 } }

#[cfg(sandblaster)]
#[spec]
fn one() -> Nat { 1 }

#[cfg(sandblaster)]
#[lemma]
fn t_calc_inj() {
    ensures(mk1() == mk3());
    calc! {
        mk1()
            == one() by { follows(); };
            == mk3() by { follows(); };
    }
}
"#;
    let r = run(body);
    assert!(r.front_ok, "{}", r.rendered);
    no_kernel_rejection(&r);
    assert!(failed(&r, "crate::t_calc_inj"), "{}", r.explain());
    assert!(r.rendered.contains("proves only that their views are equal"), "{}", r.rendered);
}

// ---------------------------------------------------------------------------
// cfg on ghost items (low)
// ---------------------------------------------------------------------------

/// red0 p15 (built for aarch64): a law under a false target `cfg` is an
/// error, `cfg(any())` on any ghost item is an error, a lemma under a
/// false target `cfg` is a warning.
#[test]
fn ghost_items_removed_by_cfg_are_reported() {
    let laws = r#"
#[cfg(any())]
#[law]
fn f_law_any(x: u8) { ensures((x as Int) == 7); }
#[cfg(target_arch = "x86_64")]
#[law]
fn f_law_arch(x: u8) { ensures((x as Int) == 9); }
"#;
    let proof = r#"
#[cfg(any())]
#[lemma]
fn f_lemma_any(x: u8) { ensures(x == 3u8); todo(); }
"#;
    let r = crate_of("", laws, proof);
    assert!(!r.front_ok);
    assert!(r.has_error(K::Attribute, "`f_law_any` is under `#[cfg(any())]`"), "{}", r.rendered);
    assert!(r.has_error(K::Law, "law `f_law_arch` is removed by"), "{}", r.rendered);
    assert!(r.has_error(K::Attribute, "`f_lemma_any` is under"), "{}", r.rendered);

    let proof = r#"
#[cfg(target_arch = "x86_64")]
#[lemma]
fn only_x86(x: u8) { ensures(x == x); follows(); }
"#;
    let r = crate_of("", "", proof);
    assert!(r.front_ok, "{}", r.rendered);
    assert!(r.warnings.iter().any(|(_, m)| m.contains("`#[lemma] only_x86` is removed by")), "{}", r.rendered);
}

// ---------------------------------------------------------------------------
// header lets of laws (low)
// ---------------------------------------------------------------------------

/// red1 b1: a law whose body is only header `let`s and its contract is a
/// claim, proven by its `#[proof]` item.
#[test]
fn a_law_with_header_lets_is_a_claim() {
    let laws = r#"
/// `sid` at a fixed argument.
#[law]
fn let_law(x: Nat) { let k = sid(3); ensures(sid(x) + k == x + 3); }
"#;
    let proof = r#"
#[proof]
fn let_law(x: Nat) { follows(); }
"#;
    let r = crate_of(NEG_SPEC, laws, proof);
    assert!(r.front_ok, "{}", r.rendered);
    assert!(!r.errors.iter().any(|(_, m)| m.contains("already has an inline proof")), "{}", r.rendered);
    assert_checked(&r, &["crate::laws::let_law"]);
    // without the proof item it is an open claim, not proven in LAWS.rs
    let r = crate_of(NEG_SPEC, laws, "");
    assert!(r.errors.iter().any(|(_, m)| m.contains("open claim")), "{}", r.explain());
}

/// red1 b3: the statement printed for a law keeps its header `let`s where
/// they are written.
#[test]
fn law_statement_text_shows_header_lets() {
    let laws = r#"
/// Shadowing.
#[law]
fn shadow2(x: Nat) { let x = 3; ensures(sid(x) == 3); }
"#;
    let r = crate_of(NEG_SPEC, laws, "");
    let k = r.checked.krate.as_ref().expect("front end");
    let it = k.items.iter().find(|i| i.path.to_string() == "crate::laws::shadow2").expect("law");
    let f = k.fn_def(it.id).unwrap();
    let text = f.contract_text(&|sp| r.checked.sm.snippet(sp).unwrap_or_default());
    assert_eq!(text.trim(), "let x = 3; ensures(sid(x) == 3)");
}

// ---------------------------------------------------------------------------
// stand-in bodies (medium)
// ---------------------------------------------------------------------------

/// red2 f_placeholder, m_law: a lemma or law about a function whose own
/// obligations fail is checked against its stand-in body (`0`): it is
/// blocked, never checked, whether the claim is false (`== 0`) or true.
#[test]
fn work_on_a_stand_in_body_is_blocked() {
    let spec = r#"
/// Underflows at 0.
pub fn pred(x: Nat) -> Nat { x - 1 }
"#;
    let laws = r#"
/// `pred` of anything is 0 (false of the written code).
#[law]
fn f_pred_zero(x: Nat) { ensures(pred(x) == 0); }
"#;
    let proof = r#"
#[proof]
fn f_pred_zero(x: Nat) { unfold(pred); follows(); }
#[lemma]
fn f_lemma(x: Nat) { ensures(pred(x) == 0); unfold(pred); follows(); }
"#;
    let r = crate_of(spec, laws, proof);
    assert!(r.front_ok, "{}", r.rendered);
    for n in ["crate::laws::f_pred_zero", "crate::proof::f_lemma"] {
        let st = r.failed_defs.iter().find(|(d, _)| d == n).map(|(_, s)| s.clone()).unwrap_or_default();
        assert!(st.contains("Blocked") && st.contains("stand-in"), "`{n}`: {st}\n{}", r.explain());
    }
}

// ---------------------------------------------------------------------------
// named lemma arguments (low)
// ---------------------------------------------------------------------------

/// red2 i_width: the width argument must agree with the array type.
#[test]
fn named_lemma_value_argument_must_agree_with_its_type_argument() {
    let proof = r#"
#[lemma]
fn f_w16(ds: Seq<[u8; 32]>) { ensures(ds.flatten().chunks_exact::<32>() == ds); sandblaster::lemmas::seq::chunks_arrays_flatten::<u8, [u8; 32]>(16, ds); follows(); }
#[lemma]
fn t_w32(ds: Seq<[u8; 32]>) { ensures(ds.flatten().chunks_exact::<32>() == ds); sandblaster::lemmas::seq::chunks_arrays_flatten::<u8, [u8; 32]>(32, ds); }
"#;
    let r = crate_of("", "", proof);
    assert!(r.front_ok, "{}", r.rendered);
    assert!(r.errors.iter().any(|(k, m)| *k == K::Script && m.contains("argument `ds`") && m.contains("does not have the type")), "{}", r.explain());
    assert_failed(&r, &["crate::proof::f_w16"]);
    assert_checked(&r, &["crate::proof::t_w32"]);
}

// ---------------------------------------------------------------------------
// the Int size limit (low)
// ---------------------------------------------------------------------------

/// red2 o_big: the documented 4096-bit limit is a user error.
#[test]
fn int_limit_is_reported_as_the_limit() {
    let proof = r#"
#[lemma]
fn f_big_lit() { ensures(pow2(5000) == pow2(5001)); by_computation(); }
"#;
    let r = crate_of("", "", proof);
    assert!(failed(&r, "crate::proof::f_big_lit"), "{}", r.explain());
    assert!(r.errors.iter().any(|(_, m)| m.contains("4096 bits")), "{}", r.explain());
    assert!(!r.errors.iter().any(|(_, m)| m.contains("internal")), "{}", r.explain());
}
