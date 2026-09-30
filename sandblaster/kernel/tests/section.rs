//! DESIGN.md §15.1/§15.5: `Env::refs_closure` (spec closure `Refs*`) and
//! `Env::abstract_section` (`complete_p(R)`, built by the kernel).
//!
//! Must reject: partial substitution; a hypothesis reaching `R` through a
//! spec fn body or an opaque spec definition (λ-lifted — and the attack
//! proof that worked before lifting fails), an exec caller, a loop helper,
//! a recursive spec fn, an `::ensures` lemma or an inductive (rejected, never
//! left pointing at the real function nor inlined as a specification);
//! a split requires over an unpublished member; forged conclusions and
//! hypotheses; malformed inputs. Must accept (and the statement is proven
//! against exactly the returned term): a refinement-only section, an exact
//! characterization of a boolean function, a `Kind`-sorted generic section,
//! a requires telescope, views, tuple and function-typed outputs. The twin
//! law reports its dependency; so do lifted spec fns and established
//! callers. Red-team regressions: A1 (split requires), A2 (spec fn in the
//! stop set), A4/A4b (lifted exec caller).

mod common;

use std::rc::Rc;

use common::*;
use sandblaster_kernel::api::*;
use sandblaster_kernel::term::*;
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::*;

const SLOT: &str = "linarith([f::ensures x : Eq(Bool, #le_u8(f x, 7u8), true)]; \
                    Eq(Bool, #le_int(#iadd(#cast_u8_int(f x), #cast_u8_int(1u8)), 255int), true); [])";

const DEC: &str = "pair(Sigma (_ : Eq(Bool, #le_int(0int, #isub(n, 1int)), true)), Eq(Bool, #lt_int(#isub(n, 1int), n), true), \
                   linarith([c : Eq(Bool, #le_int(n, 0int), false)]; Eq(Bool, #le_int(0int, #isub(n, 1int)), true); []), \
                   linarith([]; Eq(Bool, #lt_int(#isub(n, 1int), n), true); []))";

fn src() -> String {
    format!(
        r#"
def[exec] f : (x : U8) -> U8 := fun (x : U8) => #and_u8(x, 7u8)
def[spec] seven : U8 := 7u8
def[exec] g : (x : U8) -> U8 := fun (x : U8) => #and_u8(x, seven)
def[spec] s : (x : U8) -> U8 := fun (x : U8) => #and_u8(x, 7u8)
def[lemma] f::refines : (x : U8) -> Eq(U8, f x, s x) := fun (x : U8) => refl(U8, f x)
def[ensures] f::ensures : (x : U8) -> Eq(Bool, #le_u8(f x, 7u8), true) := fun (x : U8) => axiom[and_le_right_u8](x, 7u8)
def[law] twin : (x : U8) -> Eq(U8, f x, g x) := fun (x : U8) => refl(U8, f x)

def[spec] s_bad : (x : U8) -> U8 := fun (x : U8) => f x
def[law] law_bad : (x : U8) -> Eq(U8, f x, s_bad x) := fun (x : U8) => refl(U8, f x)
def[spec, opaque] s_opq : (x : U8) -> U8 := fun (x : U8) => f x
def[law] law_opq : (x : U8) -> Eq(U8, f x, s_opq x) := fun (x : U8) => eq::sym U8 (s_opq x) (f x) (delta(s_opq; x))
def[exec] caller : (x : U8) -> U8 := fun (x : U8) => f x
def[law] law_caller : (x : U8) -> Eq(U8, f x, caller x) := fun (x : U8) => refl(U8, f x)
def[loop_helper, opaque] lh : (n : Int) -> (acc : U8) -> U8 :=
  fun (n : Int) (acc : U8) =>
    if #le_int(n, 0int) as .c return U8 then acc else rec(#isub(n, 1int), f acc; {DEC})
  measure (n)
def[law] law_lh : (x : U8) -> Eq(U8, lh 1int x, lh 1int x) := fun (x : U8) => refl(U8, lh 1int x)
def[law] law_ens : (x : U8) -> Eq(Eq(Bool, #le_u8(f x, 7u8), true), f::ensures x, f::ensures x) :=
  fun (x : U8) => refl(Eq(Bool, #le_u8(f x, 7u8), true), f::ensures x)
def[law] f::bound : (x : U8) -> Eq(Bool, #le_u8(#add_u8(f x, 1u8; {SLOT}), 8u8), true) :=
  fun (x : U8) => linarith([f::ensures x : Eq(Bool, #le_u8(f x, 7u8), true)]; Eq(Bool, #le_u8(#add_u8(f x, 1u8; {SLOT}), 8u8), true); [])
inductive Wrap {{ | wrap(v : U8, .p : Eq(Bool, #le_u8(f v, 7u8), true)) }}
def[law] law_wrap : (w : Wrap) -> Eq(U8, match w : Wrap as _ return U8 with | wrap(v, .p) => v end, match w : Wrap as _ return U8 with | wrap(v, .p) => v end) :=
  fun (w : Wrap) => refl(U8, match w : Wrap as _ return U8 with | wrap(v, .p) => v end)

def[exec] is_even : (x : U8) -> Bool := fun (x : U8) => #eq_u8(#and_u8(x, 1u8), 0u8)
def[law] is_even::sound : (x : U8) -> (e : Eq(Bool, is_even x, true)) -> Eq(Bool, #eq_u8(#and_u8(x, 1u8), 0u8), true) :=
  fun (x : U8) (e : Eq(Bool, is_even x, true)) => e
def[law] is_even::complete : (x : U8) -> (e : Eq(Bool, #eq_u8(#and_u8(x, 1u8), 0u8), true)) -> Eq(Bool, is_even x, true) :=
  fun (x : U8) (e : Eq(Bool, #eq_u8(#and_u8(x, 1u8), 0u8), true)) => e

def[exec] ident : (A : Type) -> (l : List(A)) -> List(A) := fun (A : Type) (l : List(A)) => l
def[law] ident::law : (A : Type) -> (l : List(A)) -> Eq(List(A), ident A l, l) := fun (A : Type) (l : List(A)) => refl(List(A), l)

def[exec] f1 : (x : U8) -> Bool := fun (x : U8) => #le_u8(x, 100u8)
def[exec] f2 : (x : U8) -> (.h : Eq(Bool, f1 x, true)) -> U8 := fun (x : U8) (.h : Eq(Bool, f1 x, true)) => x
def[law] f2::law : (x : U8) -> (.h : Eq(Bool, f1 x, true)) -> Eq(U8, f2 x .h, x) := fun (x : U8) (.h : Eq(Bool, f1 x, true)) => refl(U8, x)
def[exec] dv : (x : U8) -> (.h : Eq(Bool, #lt_u8(0u8, x), true)) -> U8 := fun (x : U8) (.h : Eq(Bool, #lt_u8(0u8, x), true)) => x

def[exec, arity = 1] adder : (x : U8) -> (y : U8) -> U8 := fun (x : U8) (y : U8) => #wadd_u8(x, y)
def[exec] pairup : (x : U8) -> Tuple2(U8, U16) := fun (x : U8) => tuple2[U8, U16](x, #cast_u8_u16(x))

def[spec] srec : (n : Int) -> (acc : U8) -> U8 :=
  fun (n : Int) (acc : U8) =>
    if #le_int(n, 0int) as .c return U8 then acc else rec(#isub(n, 1int), f acc; {DEC})
  measure (n)
def[law] law_srec : (x : U8) -> Eq(U8, srec 1int x, srec 1int x) := fun (x : U8) => refl(U8, srec 1int x)
def[law] f1::def : (x : U8) -> Eq(Bool, f1 x, #le_u8(x, 100u8)) := fun (x : U8) => refl(Bool, f1 x)

def[exec] f5 : (x : U8) -> U8 := fun (x : U8) => 5u8
def[exec] f5_caller : (x : U8) -> U8 := fun (x : U8) => f5 x
def[law] f5_caller::five : (x : U8) -> Eq(U8, f5_caller x, 5u8) := fun (x : U8) => refl(U8, 5u8)
def[law] f5_mixed : (x : U8) -> Eq(Tuple2(U8, U8), tuple2[U8, U8](f5 x, f5_caller x), tuple2[U8, U8](f5 x, 5u8)) :=
  fun (x : U8) => refl(Tuple2(U8, U8), tuple2[U8, U8](5u8, 5u8))

def[exec] rq : (x : U8) -> Bool := fun (x : U8) => #lt_u8(x, 10u8)
def[exec] rp : (x : U8) -> (.h : Eq(Bool, rq x, true)) -> U8 := fun (x : U8) (.h : Eq(Bool, rq x, true)) => x
def[ensures] rp::ensures : (x : U8) -> (.h : Eq(Bool, rq x, true)) -> (.l : Eq(Bool, #lt_u8(x, 10u8), true)) -> Eq(U8, rp x .h, x) :=
  fun (x : U8) (.h : Eq(Bool, rq x, true)) (.l : Eq(Bool, #lt_u8(x, 10u8), true)) => refl(U8, x)
def[spec] lt10 : (x : U8) -> Bool := fun (x : U8) => #lt_u8(x, 10u8)
def[lemma] rq::refines : (x : U8) -> Eq(Bool, rq x, lt10 x) := fun (x : U8) => refl(Bool, rq x)
"#
    )
}

fn env() -> Env {
    let mut env = prelude();
    load(&mut env, &src()).unwrap_or_else(|e| panic!("{e}"));
    env
}

fn gid(env: &Env, n: &str) -> GlobalId {
    env.lookup_global(n).unwrap_or_else(|| panic!("no global `{n}`"))
}

fn hyp(env: &Env, n: &str) -> SectionHyp {
    SectionHyp { lemma: gid(env, n), restated: None }
}

fn section(env: &Env, members: &[&str], published: &[&str], hyps: Vec<SectionHyp>) -> Result<SectionStatements, KernelError> {
    section_with(env, members, published, hyps, &[], &[])
}

fn section_with(
    env: &Env,
    members: &[&str],
    published: &[&str],
    hyps: Vec<SectionHyp>,
    views: &[SectionView],
    established: &[&str],
) -> Result<SectionStatements, KernelError> {
    let m: Vec<GlobalId> = members.iter().map(|n| gid(env, n)).collect();
    let p: Vec<GlobalId> = published.iter().map(|n| gid(env, n)).collect();
    let e: Vec<GlobalId> = established.iter().map(|n| gid(env, n)).collect();
    env.abstract_section(&Section { members: &m, published: &p, hyps: &hyps, views, established: &e }, &mut budget())
}

fn show(env: &Env, t: &Tm) -> String {
    env.print_term(&[], t)
}

/// The Π binders of a statement.
fn binders(t: &Tm) -> (Vec<(Name, Rel, Tm)>, Tm) {
    let mut out = Vec::new();
    let mut t = t.clone();
    while let Term::Pi { name, rel, dom, cod } = &*t.clone() {
        out.push((name.clone(), *rel, dom.clone()));
        t = cod.clone();
    }
    (out, t)
}

/// `λ` over the statement's binders with the given body.
fn lams(bs: &[(Name, Rel, Tm)], body: Tm) -> Tm {
    bs.iter().rev().fold(body, |acc, (n, r, d)| Rc::new(Term::Lam { name: n.clone(), rel: *r, dom: d.clone(), body: acc }))
}

/// Check `proof` against the closed statement `stmt` (what the front end's
/// proof of `complete_p` is checked against).
fn proves(env: &Env, proof: &Tm, stmt: &Tm) -> Result<(), KernelError> {
    let ty = env.eval(&VEnv::default(), Lvl(0), stmt, &mut budget()).unwrap();
    env.check(&Ctx::default(), proof, &ty, &mut budget())
}

/// The front end's flow: the proof becomes a lemma whose type is exactly the
/// returned statement.
fn add_lemma(env: &mut Env, name: &str, stmt: &Tm, proof: &Tm) -> Result<GlobalId, KernelError> {
    let d = DefDecl {
        name: name.into(),
        kind: DefKind::Lemma,
        ty: stmt.clone(),
        body: proof.clone(),
        recursion: Recursion::None,
        arity: 0,
        opaque: false,
    };
    env.add_def(d, &mut budget())
}

fn sort_of(env: &Env, stmt: &Tm) -> Sort {
    match &*env.infer(&Ctx::default(), stmt, &mut budget()).unwrap() {
        Value::Sort(s) => *s,
        _ => panic!("not a type"),
    }
}

fn err(r: Result<SectionStatements, KernelError>) -> String {
    match r {
        Ok(s) => panic!("accepted: {:?}", s.statements),
        Err(e) => e.message,
    }
}

// ---------------------------------------------------------------------------
// Refs*
// ---------------------------------------------------------------------------

#[test]
fn refs_closure_follows_bodies_types_and_inductives_but_not_proofs() {
    let env = env();
    let refs = |src: &str, stop: &[&str]| {
        let stop: Vec<GlobalId> = stop.iter().map(|n| gid(&env, n)).collect();
        env.refs_closure(&tm(&env, src), &stop).into_iter().map(|g| env.global_name(g).unwrap().to_string()).collect::<Vec<_>>()
    };
    let has = |v: &[String], n: &str| v.iter().any(|x| x == n);
    // A spec fn body, an opaque body, a loop helper's body.
    assert!(has(&refs("s_bad", &[]), "f"));
    assert!(has(&refs("s_opq", &[]), "f"));
    let r = refs("lh 1int 3u8", &[]);
    assert!(has(&r, "lh") && has(&r, "f"), "{r:?}");
    // An ensures lemma's type.
    assert!(has(&refs("f::ensures", &[]), "f"));
    // An inductive's (irrelevant) field type is part of its declaration.
    assert!(has(&refs("fun (w : Wrap) => w", &[]), "f"));
    // The stop set: listed, not explored.
    assert_eq!(refs("caller", &["caller"]), vec!["caller".to_string()]);
    assert!(has(&refs("caller", &[]), "f"));
    let r = refs("g", &[]);
    assert!(has(&r, "seven"));
    assert!(!has(&refs("g", &["g"]), "seven"));
    // Proofs (irrelevant positions) do not count.
    assert!(refs("fun (x : U8) => #add_u8(x, 0u8; f::ensures x)", &[]).is_empty());
    assert!(!has(&refs("fun (x : U8) => eq::promote U8 (s x) (s x) .(twin x)", &[]), "twin"));
}

// ---------------------------------------------------------------------------
// Must accept (and the statement is provable against exactly this term)
// ---------------------------------------------------------------------------

#[test]
fn refinement_only_section() {
    let env = env();
    let st = section(&env, &["f"], &["f"], vec![hyp(&env, "f::refines")]).unwrap();
    assert_eq!(st.members, vec![gid(&env, "f")]);
    let stmt = &st.statements[0];
    assert_eq!(show(&env, stmt), "(f' : U8 -> U8) -> ((x : U8) -> Eq(U8, f' x, s x)) -> (x : U8) -> Eq(U8, f' x, f x)");
    assert_eq!(sort_of(&env, stmt), Sort::Type);
    let proof = tm(&env, "fun (F : U8 -> U8) (h : (x : U8) -> Eq(U8, F x, s x)) (x : U8) => h x");
    proves(&env, &proof, stmt).unwrap();
    assert!(st.deps.contains(&gid(&env, "s")) && !st.deps.contains(&gid(&env, "f")));
    let mut env = env;
    let lemma = add_lemma(&mut env, "f::complete", stmt, &proof).unwrap();
    assert!(Rc::ptr_eq(&env.global_type(lemma).unwrap(), stmt));
}

#[test]
fn exact_characterization_of_a_boolean_function() {
    let env = env();
    let st = section(&env, &["is_even"], &["is_even"], vec![hyp(&env, "is_even::sound"), hyp(&env, "is_even::complete")]).unwrap();
    let stmt = &st.statements[0];
    let p = "fun (F : U8 -> Bool)
          (h0 : (x : U8) -> (e : Eq(Bool, F x, true)) -> Eq(Bool, #eq_u8(#and_u8(x, 1u8), 0u8), true))
          (h1 : (x : U8) -> (e : Eq(Bool, #eq_u8(#and_u8(x, 1u8), 0u8), true)) -> Eq(Bool, F x, true))
          (x : U8) =>
        (match F x : Bool as b return (e : Eq(Bool, F x, b)) -> Eq(Bool, b, is_even x) with
         | false => fun (e : Eq(Bool, F x, false)) =>
             (match is_even x : Bool as c return (d : Eq(Bool, is_even x, c)) -> Eq(Bool, false, c) with
              | false => fun (d : Eq(Bool, is_even x, false)) => refl(Bool, false)
              | true => fun (d : Eq(Bool, is_even x, true)) =>
                  absurd(Eq(Bool, false, true), bool::false_ne_true (eq::trans Bool false (F x) true (eq::sym Bool (F x) false e) (h1 x d)))
              end) refl(Bool, is_even x)
         | true => fun (e : Eq(Bool, F x, true)) => eq::sym Bool (is_even x) true (h0 x e)
         end) refl(Bool, F x)";
    proves(&env, &tm(&env, p), stmt).unwrap();
    // Soundness alone does not determine `is_even` (λ_. false satisfies it):
    // the statement with only `is_even::sound` is not provable this way.
    let st1 = section(&env, &["is_even"], &["is_even"], vec![hyp(&env, "is_even::sound")]).unwrap();
    assert!(proves(&env, &tm(&env, p), &st1.statements[0]).is_err());
}

#[test]
fn kind_sorted_generic_section() {
    let env = env();
    let st = section(&env, &["ident"], &["ident"], vec![hyp(&env, "ident::law")]).unwrap();
    let stmt = &st.statements[0];
    assert_eq!(sort_of(&env, stmt), Sort::Kind);
    assert_eq!(
        show(&env, stmt),
        "(ident' : (A : Type) -> List(A) -> List(A)) -> ((A : Type) (l : List(A)) -> Eq(List(A), ident' A l, l)) -> \
         (A : Type) (l : List(A)) -> Eq(List(A), ident' A l, ident A l)"
    );
    let proof = tm(
        &env,
        "fun (F : (A : Type) -> List(A) -> List(A)) (h : (A : Type) -> (l : List(A)) -> Eq(List(A), F A l, l)) (A : Type) (l : List(A)) => h A l",
    );
    proves(&env, &proof, stmt).unwrap();
    let mut env = env;
    add_lemma(&mut env, "ident::complete", stmt, &proof).unwrap();
}

#[test]
fn requires_telescope_and_irrelevant_binders() {
    let env = env();
    // `f2`'s requires mentions `f1 ∈ R`: `F2'`'s type mentions `F1'`, and the
    // conclusion gets one requires proof per side. The two requires coincide
    // only if `f1` is determined as well: it must be published (red-team A1).
    let m = err(section(&env, &["f1", "f2"], &["f2"], vec![hyp(&env, "f2::law")]));
    assert!(m.contains("of `f2`") && m.contains("`f1`, which must be published"), "{m}");
    let st = section(&env, &["f1", "f2"], &["f1", "f2"], vec![hyp(&env, "f1::def"), hyp(&env, "f2::law")]).unwrap();
    let stmt = &st.statements[1];
    assert_eq!(binders(stmt).0.len(), 7, "{}", show(&env, stmt));
    assert_eq!(
        show(&env, stmt),
        "(f1' : U8 -> Bool) (f2' : (x : U8) (.h : Eq(Bool, f1' x, true)) -> U8) -> \
         ((x : U8) -> Eq(Bool, f1' x, #le_u8(x, 100u8))) -> \
         ((x : U8) (.h : Eq(Bool, f1' x, true)) -> Eq(U8, f2' x .h, x)) -> \
         (x : U8) (.h : Eq(Bool, f1' x, true)) (.h' : Eq(Bool, f1 x, true)) -> Eq(U8, f2' x .h, f2 x .h')"
    );
    let proof = tm(
        &env,
        "fun (F1 : U8 -> Bool) (F2 : (x : U8) -> (.h : Eq(Bool, F1 x, true)) -> U8)
             (d : (x : U8) -> Eq(Bool, F1 x, #le_u8(x, 100u8)))
             (k : (x : U8) -> (.h : Eq(Bool, F1 x, true)) -> Eq(U8, F2 x .h, x))
             (x : U8) (.h : Eq(Bool, F1 x, true)) (.h2 : Eq(Bool, f1 x, true)) => k x .h",
    );
    proves(&env, &proof, stmt).unwrap();
    // `complete_f1`, the statement that makes the two requires coincide.
    let proof1 = tm(
        &env,
        "fun (F1 : U8 -> Bool) (F2 : (x : U8) -> (.h : Eq(Bool, F1 x, true)) -> U8)
             (d : (x : U8) -> Eq(Bool, F1 x, #le_u8(x, 100u8)))
             (k : (x : U8) -> (.h : Eq(Bool, F1 x, true)) -> Eq(U8, F2 x .h, x)) (x : U8) => d x",
    );
    proves(&env, &proof1, &st.statements[0]).unwrap();
    // A requires that does not mention the section: both sides get the same
    // proof (irrelevance: both are constant in it).
    let st = section(&env, &["dv"], &["dv"], vec![]).unwrap();
    assert_eq!(
        show(&env, &st.statements[0]),
        "(dv' : (x : U8) (.h : Eq(Bool, #lt_u8(0u8, x), true)) -> U8) (x : U8) (.h : Eq(Bool, #lt_u8(0u8, x), true)) -> Eq(U8, dv' x .h, dv x .h)"
    );
}

#[test]
fn views_tuples_and_function_outputs() {
    let env = env();
    // Function-typed output: pointwise (there is no funext).
    let st = section(&env, &["adder"], &["adder"], vec![]).unwrap();
    assert_eq!(show(&env, &st.statements[0]), "(adder' : U8 -> U8 -> U8) (x : U8) (y : U8) -> Eq(U8, adder' x y, adder x y)");
    // A tuple without views: plain equality.
    let st = section(&env, &["pairup"], &["pairup"], vec![]).unwrap();
    assert!(show(&env, &st.statements[0]).ends_with("Eq(Tuple2(U8, U16), pairup' x, pairup x)"), "{}", show(&env, &st.statements[0]));
    // A view on one component: componentwise, the view applied by the kernel.
    let view = SectionView { ty: tm(&env, "U16"), target: tm(&env, "U8"), map: tm(&env, "fun (v : U16) => #cast_u16_u8(v)") };
    let st = section_with(&env, &["pairup"], &["pairup"], vec![], std::slice::from_ref(&view), &[]).unwrap();
    let (bs, concl) = binders(&st.statements[0]);
    let text = env.print_term(&bs.iter().map(|b| b.0.clone()).collect::<Vec<_>>(), &concl);
    assert!(text.starts_with("Sigma (_ : Eq(U8, match pairup' x : Tuple2(U8, U16)"), "{text}");
    assert!(text.contains("Eq(U8, (fun (v : U16) => #cast_u16_u8(v)) (match pairup' x"), "{text}");
    assert_eq!(sort_of(&env, &st.statements[0]), Sort::Type);
    // A view whose map does not have the declared type is rejected.
    let bad = SectionView { ty: tm(&env, "U16"), target: tm(&env, "U8"), map: tm(&env, "fun (v : U8) => v") };
    assert!(err(section_with(&env, &["pairup"], &["pairup"], vec![], &[bad], &[])).contains("view 0"));
    // A view mentioning the section is rejected by the Refs* check.
    let bad = SectionView { ty: tm(&env, "U16"), target: tm(&env, "U8"), map: tm(&env, "fun (v : U16) => f #cast_u16_u8(v)") };
    assert!(err(section_with(&env, &["f", "pairup"], &["pairup"], vec![], &[bad], &[])).contains("still depends on section member `f`"));
}

// ---------------------------------------------------------------------------
// Dependencies (well-foundedness is the caller's; the kernel reports Deps)
// ---------------------------------------------------------------------------

#[test]
fn twin_law_reports_its_dependency() {
    let env = env();
    let (f, g, seven) = (gid(&env, "f"), gid(&env, "g"), gid(&env, "seven"));
    // R = {f} with `f x == g x`: complete only relative to exec `g`.
    let st = section(&env, &["f"], &["f"], vec![hyp(&env, "twin")]).unwrap();
    assert!(st.deps.contains(&g) && st.deps.contains(&seven) && !st.deps.contains(&f));
    // `g` established: still listed, not explored.
    let st = section_with(&env, &["f"], &["f"], vec![hyp(&env, "twin")], &[], &["g"]).unwrap();
    assert!(st.deps.contains(&g) && !st.deps.contains(&seven));
    // The merged section abstracts both: the hypothesis no longer pins `F'`.
    let st = section(&env, &["f", "g"], &["f"], vec![hyp(&env, "twin")]).unwrap();
    let stmt = &st.statements[0];
    assert!(show(&env, stmt).contains("((x : U8) -> Eq(U8, f' x, g' x))"), "{}", show(&env, stmt));
    assert!(!st.deps.contains(&f) && !st.deps.contains(&g));
    let (bs, _) = binders(stmt);
    // The proof that works for R = {f} (through `g`'s definition) fails.
    let attack = lams(&bs, mk::app(mk::var(1), mk::var(0)));
    assert!(proves(&env, &attack, stmt).is_err());
}

// ---------------------------------------------------------------------------
// Must reject: reaching the section through a definition, partial
// substitution, forged conclusions and hypotheses
// ---------------------------------------------------------------------------

/// The hand-built statement without lifting (what an elaborator that
/// forgot to λ-lift would produce), which the attack proof proves.
fn unlifted(env: &Env, law_rhs: &str) -> Tm {
    tm(env, &format!("(F : U8 -> U8) -> (h : (x : U8) -> Eq(U8, F x, {law_rhs})) -> (x : U8) -> Eq(U8, F x, f x)"))
}

fn check_lifted(env: &Env, law: &str, law_rhs: &str, via: &str, attack: &str) {
    let st = section(env, &["f"], &["f"], vec![hyp(env, law)]).unwrap();
    let stmt = &st.statements[0];
    let (bs, _) = binders(stmt);
    // The lifted spec fn is reported (DESIGN §15.5 computes `Deps` before
    // lifting); the member is not.
    assert!(st.deps.contains(&gid(env, via)) && !st.deps.contains(&gid(env, "f")), "{:?}", st.deps);
    // The hypothesis no longer refers to the real `f` or to `via`.
    let h = &bs[1].2;
    let refs = env.refs_closure(h, &[]);
    assert!(!refs.contains(&gid(env, "f")) && !refs.contains(&gid(env, via)), "{}", show(env, stmt));
    let text = env.print_term(&[bs[0].0.clone()], h);
    assert!(text.contains("f' x"), "{text}");
    // The attack proves the unlifted statement but not the kernel's.
    let proof = tm(env, attack);
    proves(env, &proof, &unlifted(env, law_rhs)).unwrap();
    assert!(proves(env, &proof, stmt).is_err());
    assert!(proves(env, &lams(&bs, mk::app(mk::var(1), mk::var(0))), stmt).is_err());
}

#[test]
fn reaching_through_a_spec_fn_body_is_lifted() {
    let env = env();
    check_lifted(&env, "law_bad", "s_bad x", "s_bad", "fun (F : U8 -> U8) (h : (x : U8) -> Eq(U8, F x, s_bad x)) (x : U8) => h x");
}

#[test]
fn reaching_through_an_opaque_definition_is_lifted() {
    let env = env();
    let attack =
        "fun (F : U8 -> U8) (h : (x : U8) -> Eq(U8, F x, s_opq x)) (x : U8) => eq::trans U8 (F x) (s_opq x) (f x) (h x) (delta(s_opq; x))";
    check_lifted(&env, "law_opq", "s_opq x", "s_opq", attack);
}

#[test]
fn reaching_through_an_exec_caller_is_rejected() {
    let env = env();
    // An exec function's implementation is not a specification: never lifted.
    let m = err(section(&env, &["f"], &["f"], vec![hyp(&env, "law_caller")]));
    assert!(
        m.contains("hypothesis 0 (`law_caller`)") && m.contains("`caller` (Exec) reaches the section but is not a spec definition"),
        "{m}"
    );
    // Established, the statement is relative to the real `caller` (provable
    // through its body), which is why it is reported ...
    let st = section_with(&env, &["f"], &["f"], vec![hyp(&env, "law_caller")], &[], &["caller"]).unwrap();
    assert!(st.deps.contains(&gid(&env, "caller")));
    let (bs, _) = binders(&st.statements[0]);
    proves(&env, &lams(&bs, mk::app(mk::var(1), mk::var(0))), &st.statements[0]).unwrap();
    // ... and `caller`'s own section depends on `f`: the cycle the caller's
    // well-foundedness check turns into one merged section, where the law no
    // longer pins `f'`.
    let st = section(&env, &["caller"], &["caller"], vec![hyp(&env, "law_caller")]).unwrap();
    assert!(st.deps.contains(&gid(&env, "f")));
    let st = section(&env, &["f", "caller"], &["f"], vec![hyp(&env, "law_caller")]).unwrap();
    let (bs, _) = binders(&st.statements[0]);
    assert!(proves(&env, &lams(&bs, mk::app(mk::var(1), mk::var(0))), &st.statements[0]).is_err());
}

/// Red-team A4/A4b: a law about an exec caller outside `R` (alone, or next to
/// the member). λ-lifting the caller inlined its implementation, so
/// `f5_caller x == 5` became a specification of `f5` while `deps` was empty.
#[test]
fn lifted_exec_caller_does_not_specify_the_member() {
    let env = env();
    let caller = gid(&env, "f5_caller");
    for law in ["f5_caller::five", "f5_mixed"] {
        let m = err(section(&env, &["f5"], &["f5"], vec![hyp(&env, law)]));
        assert!(m.contains("`f5_caller` (Exec) reaches the section but is not a spec definition"), "{law}: {m}");
        // Established: reported, and the law says nothing about `f5'`.
        let st = section_with(&env, &["f5"], &["f5"], vec![hyp(&env, law)], &[], &["f5_caller"]).unwrap();
        assert!(st.deps.contains(&caller), "{law}");
        let text = show(&env, &st.statements[0]);
        assert!(text.contains("f5_caller x") && !text.contains("(fun"), "{text}");
    }
    // The attack proof of the lifted statement proves neither correct setup.
    let attack = tm(&env, "fun (F : U8 -> U8) (h : (x : U8) -> Eq(U8, (fun (x : U8) => F x) x, 5u8)) (x : U8) => h x");
    let st = section_with(&env, &["f5"], &["f5"], vec![hyp(&env, "f5_caller::five")], &[], &["f5_caller"]).unwrap();
    assert!(proves(&env, &attack, &st.statements[0]).is_err());
    let (bs, _) = binders(&st.statements[0]);
    assert!(proves(&env, &lams(&bs, mk::app(mk::var(1), mk::var(0))), &st.statements[0]).is_err());
    let st = section(&env, &["f5", "f5_caller"], &["f5"], vec![hyp(&env, "f5_caller::five")]).unwrap();
    let (bs, _) = binders(&st.statements[0]);
    assert!(proves(&env, &lams(&bs, mk::app(mk::var(1), mk::var(0))), &st.statements[0]).is_err());
}

/// Red-team A1: with `R = {rq, rp}` and only `rp` published, the split
/// requires compared `rp'` with `rp` on the inputs valid for the real `rq`
/// while nothing determined `rq'`: the proof used the real `rq` (δ) through
/// the real-side binder, and `deps` no longer mentioned `rq`.
#[test]
fn split_requires_member_must_be_published_exactly() {
    let env = env();
    // R = {rp}: `rq` is a reported dependency.
    let st = section(&env, &["rp"], &["rp"], vec![hyp(&env, "rp::ensures")]).unwrap();
    assert!(st.deps.contains(&gid(&env, "rq")));
    // Merged, `rq` unpublished: rejected.
    let m = err(section(&env, &["rq", "rp"], &["rp"], vec![hyp(&env, "rp::ensures")]));
    assert!(m.contains("of `rp`") && m.contains("`rq`, which must be published"), "{m}");
    // Published through a view (`obs_eq` is not equality): rejected.
    let view = SectionView { ty: tm(&env, "Bool"), target: tm(&env, "Bool"), map: tm(&env, "fun (b : Bool) => b") };
    let m = err(section_with(&env, &["rq", "rp"], &["rq", "rp"], vec![hyp(&env, "rp::ensures")], &[view], &[]));
    assert!(m.contains("`rq`, which must be published, with an observational equality that uses no view"), "{m}");
    // Published exactly: `complete_rq` is part of the claim, and without a
    // specification of `rq` it is not provable.
    let st = section(&env, &["rq", "rp"], &["rq", "rp"], vec![hyp(&env, "rp::ensures")]).unwrap();
    let (bs, _) = binders(&st.statements[0]);
    assert!(proves(&env, &lams(&bs, tm(&env, "refl(Bool, rq 0u8)")), &st.statements[0]).is_err());
    // With `rq::refines`, both statements are proven and accepted; `rp`'s
    // proof may use the real requires, which `complete_rq` makes equivalent.
    let st = section(&env, &["rq", "rp"], &["rq", "rp"], vec![hyp(&env, "rq::refines"), hyp(&env, "rp::ensures")]).unwrap();
    assert!(!st.deps.contains(&gid(&env, "rq")) && st.deps.contains(&gid(&env, "lt10")), "{:?}", st.deps);
    let pre = "fun (Q : U8 -> Bool) (P : (x : U8) -> (.h : Eq(Bool, Q x, true)) -> U8) (r : (x : U8) -> Eq(Bool, Q x, lt10 x))
                   (k : (x : U8) -> (.h : Eq(Bool, Q x, true)) -> (.l : Eq(Bool, #lt_u8(x, 10u8), true)) -> Eq(U8, P x .h, x))";
    let proof_q = tm(&env, &format!("{pre} (x : U8) => r x"));
    let proof_p = tm(&env, &format!("{pre} (x : U8) (.h : Eq(Bool, Q x, true)) (.h2 : Eq(Bool, rq x, true)) => k x .h .h2"));
    let mut env = env;
    add_lemma(&mut env, "rq::complete", &st.statements[0], &proof_q).unwrap();
    add_lemma(&mut env, "rp::complete", &st.statements[1], &proof_p).unwrap();
}

#[test]
fn reaching_through_a_loop_helper_is_rejected() {
    let env = env();
    let m = err(section(&env, &["f"], &["f"], vec![hyp(&env, "law_lh")]));
    assert!(m.contains("`lh` (LoopHelper) reaches the section but is not a spec definition"), "{m}");
    // A recursive spec fn cannot be inlined either (no fixpoint term).
    let m = err(section(&env, &["f"], &["f"], vec![hyp(&env, "law_srec")]));
    assert!(m.contains("`srec` is recursive and reaches the section"), "{m}");
    // Established, it is not explored (and is reported as a dependency).
    let st = section_with(&env, &["f"], &["f"], vec![hyp(&env, "law_lh")], &[], &["lh"]).unwrap();
    assert!(st.deps.contains(&gid(&env, "lh")));
}

#[test]
fn reaching_through_an_ensures_lemma_is_rejected_or_restated() {
    let env = env();
    // A relevant occurrence of `f::ensures` (a lemma, not a spec definition).
    let m = err(section(&env, &["f"], &["f"], vec![hyp(&env, "law_ens")]));
    assert!(m.contains("hypothesis 0 (`law_ens`)") && m.contains("not a spec definition"), "{m}");
    // A proof slot proven from `f::ensures` (a fact about the real `f`)
    // does not prove the abstracted obligation about `f'`.
    let m = err(section(&env, &["f"], &["f"], vec![hyp(&env, "f::ensures"), hyp(&env, "f::bound")]));
    assert!(m.contains("hypothesis 1 (`f::bound`)"), "{m}");
    // The front end re-proves the slot from the abstracted ensures
    // hypothesis `e`: accepted (only the proof differs).
    let restated = env
        .parse_term(
            &["F", "e"],
            "(x : U8) -> Eq(Bool, #le_u8(#add_u8(F x, 1u8; linarith([e x : Eq(Bool, #le_u8(F x, 7u8), true)]; \
             Eq(Bool, #le_int(#iadd(#cast_u8_int(F x), #cast_u8_int(1u8)), 255int), true); [])), 8u8), true)",
        )
        .unwrap();
    let hyps = vec![hyp(&env, "f::ensures"), SectionHyp { lemma: gid(&env, "f::bound"), restated: Some(restated) }];
    let st = section(&env, &["f"], &["f"], hyps).unwrap();
    assert_eq!(sort_of(&env, &st.statements[0]), Sort::Type);
}

#[test]
fn reaching_through_an_inductive_is_rejected() {
    let env = env();
    let m = err(section(&env, &["f"], &["f"], vec![hyp(&env, "law_wrap")]));
    assert!(m.contains("hypothesis 0 (`law_wrap`) still depends on section member `f`"), "{m}");
}

#[test]
fn partial_substitution_is_rejected() {
    let env = env();
    // A restatement that keeps the real `f` in a relevant position.
    let r = env.parse_term(&["F"], "(x : U8) -> Eq(Bool, #le_u8(f x, 7u8), true)").unwrap();
    let m = err(section(&env, &["f"], &["f"], vec![SectionHyp { lemma: gid(&env, "f::ensures"), restated: Some(r) }]));
    assert!(m.contains("differs from the abstracted statement in a relevant position"), "{m}");
    // With two members, abstracting only one of them.
    let r = env.parse_term(&["F", "G"], "(x : U8) -> Eq(U8, F x, g x)").unwrap();
    let m = err(section(&env, &["f", "g"], &["f"], vec![SectionHyp { lemma: gid(&env, "twin"), restated: Some(r) }]));
    assert!(m.contains("relevant position"), "{m}");
}

#[test]
fn forged_conclusions_and_hypotheses_are_rejected() {
    let env = env();
    // The conclusion is generated: `F' x = f x`, never `f x = f x`.
    let st = section(&env, &["f"], &["f"], vec![hyp(&env, "f::refines")]).unwrap();
    let stmt = &st.statements[0];
    let (bs, concl) = binders(stmt);
    assert_eq!(env.print_term(&bs.iter().map(|b| b.0.clone()).collect::<Vec<_>>(), &concl), "Eq(U8, f' x, f x)");
    let trivial = lams(&bs, tm(&env, "refl(U8, f 0u8)"));
    assert!(proves(&env, &trivial, stmt).is_err());
    let refl_goal = lams(&bs, mk::refl(mk::int_ty(Width::U8), mk::app(mk::global(gid(&env, "f")), mk::var(0))));
    assert!(proves(&env, &refl_goal, stmt).is_err());
    // Hypotheses are statements of lemmas: a restatement cannot add `Empty`,
    // smuggle in the goal, or add a binder.
    for forged in ["Empty", "(x : U8) -> Eq(U8, F x, f x)", "(x : U8) -> (.e : Empty) -> Eq(U8, F x, s x)", "(x : U8) -> Eq(U8, F x, F x)"]
    {
        let r = env.parse_term(&["F"], forged).unwrap();
        let m = err(section(&env, &["f"], &["f"], vec![SectionHyp { lemma: gid(&env, "f::refines"), restated: Some(r) }]));
        assert!(m.contains("relevant position"), "{forged}: {m}");
    }
    // An honest restatement (same relevant structure) is accepted as is.
    let r = env.parse_term(&["F"], "(y : U8) -> Eq(U8, F y, s y)").unwrap();
    section(&env, &["f"], &["f"], vec![SectionHyp { lemma: gid(&env, "f::refines"), restated: Some(r) }]).unwrap();
}

#[test]
fn malformed_sections_are_rejected() {
    let env = env();
    assert!(err(section(&env, &[], &[], vec![])).contains("nonempty"));
    assert!(err(section(&env, &["f", "f"], &["f"], vec![])).contains("distinct"));
    assert!(err(section(&env, &["f"], &["g"], vec![])).contains("published"));
    assert!(err(section(&env, &["f"], &["f", "f"], vec![])).contains("published"));
    assert!(err(section_with(&env, &["f"], &["f"], vec![], &[], &["f"])).contains("established"));
    // Red-team A2: only exec functions can be established; a spec fn in the
    // stop set would hide that its body reaches `f`.
    let m = err(section_with(&env, &["f"], &["f"], vec![hyp(&env, "law_bad")], &[], &["s_bad"]));
    assert!(m.contains("established functions must be known exec functions"), "{m}");
    let bogus = SectionHyp { lemma: GlobalId(u32::MAX), restated: None };
    assert!(err(section(&env, &["f"], &["f"], vec![bogus])).contains("not a known global"));
    // No published function: nothing to state.
    assert!(section(&env, &["f"], &[], vec![hyp(&env, "f::refines")]).unwrap().statements.is_empty());
}
