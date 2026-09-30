//! Opaque definitions (DESIGN.md §5.6): they never unfold under the default
//! (checking) policy, `Delta`/`Unfold` expose their defining equation, the
//! optimizer's transparent mode (`eval_opaque`, `conv_opaque`,
//! `check_residual_equal`) unfolds them, and opacity only loses
//! completeness.

mod common;

use std::rc::Rc;

use common::*;
use sandblaster_kernel::api::*;
use sandblaster_kernel::syntax::parser::{Item, parse_items};
use sandblaster_kernel::term::*;
use sandblaster_kernel::value::*;

const SRC: &str = r#"
def[spec, opaque] f : (x : U8) -> U8 := fun (x : U8) => #wadd_u8(x, 1u8)
def[spec, opaque] g : (x : U8) -> U8 := fun (x : U8) => #wadd_u8(x, 1u8)
def[opaque] K : U32 := 5u32
def[spec] h : (x : U8) -> U8 := fun (x : U8) => f x
def[spec, opaque] osum : (l : List(U8)) -> U8 :=
  fun (l : List(U8)) =>
    match l : List(U8) as _ return U8 with
    | Nil => 0u8
    | Cons(x, t) => #wadd_u8(x, rec(t))
    end
  structural l
def[spec, opaque] P : (x : U8) -> Type := fun (x : U8) => Eq(U8, x, x)
def[intrinsic, opaque] twice : (x : U32) -> U32 := fun (x : U32) => #wadd_u32(x, x)
"#;

fn env() -> Env {
    let mut env = prelude();
    load(&mut env, SRC).unwrap_or_else(|e| panic!("{e}"));
    env
}

#[test]
fn syntax_round_trips_and_rejects_duplicates() {
    let env = env();
    let f = env.lookup_global("f").unwrap();
    assert_eq!(env.global_opaque(f), Some(true));
    assert_eq!(env.global_opaque(env.lookup_global("h").unwrap()), Some(false));
    let items = parse_items(&env, "def[opaque, arity = 1, spec] q : (x : U8) -> U8 := fun (x : U8) => x").unwrap();
    let Item::Def(d) = &items[0] else { panic!("not a def") };
    assert!(d.opaque && d.kind == DefKind::Spec && d.arity == 1);
    let printed = env.print_def_decl(d);
    assert!(printed.starts_with("def[spec, opaque] q"), "{printed}");
    let again = parse_items(&env, &printed).unwrap();
    let Item::Def(d2) = &again[0] else { panic!("not a def") };
    assert!(d2.opaque && d2.kind == DefKind::Spec);
    // Opacity defaults to false and is printed only when set.
    let items = parse_items(&env, "def[spec] q : U8 := 1u8").unwrap();
    let Item::Def(d) = &items[0] else { panic!("not a def") };
    assert!(!d.opaque && !env.print_def_decl(d).contains("opaque"));
    for bad in [
        "def[opaque, opaque] q : U8 := 1u8",
        "def[spec, lemma] q : U8 := 1u8",
        "def[spec, arity = 0, arity = 0] q : U8 := 1u8",
        "def[transparent] q : U8 := 1u8",
    ] {
        assert!(parse_items(&env, bad).is_err(), "{bad}");
    }
}

#[test]
fn default_policy_never_unfolds_opaque_definitions() {
    let env = env();
    assert_eq!(norm(&env, "f 1u8"), "f 1u8");
    assert_eq!(norm(&env, "K"), "K");
    // A transparent definition unfolds to the (folded) opaque call.
    assert_eq!(norm(&env, "h 1u8"), "f 1u8");
    assert_eq!(norm(&env, "osum Cons[U8](1u8, Cons[U8](2u8, Nil[U8]))"), "osum Cons[U8](1u8, Cons[U8](2u8, Nil[U8]))");
    // Opaque intrinsics stay folded even on closed arguments.
    assert_eq!(norm(&env, "twice 21u32"), "twice 21u32");
    // Conversion does not see through opacity: refl proofs are rejected.
    assert!(check(&env, "refl(U8, f 1u8)", "Eq(U8, f 1u8, 2u8)").is_err());
    assert!(check(&env, "refl(U32, K)", "Eq(U32, K, 5u32)").is_err());
    assert!(check(&env, "refl(U8, 3u8)", "P 3u8").is_err());
    // ... but equal opaque applications are convertible.
    assert!(check(&env, "fun (x : U8) => refl(U8, f x)", "(x : U8) -> Eq(U8, f x, f x)").is_ok());
    // Two opaque definitions with the same body are distinct heads.
    assert!(check(&env, "fun (x : U8) => refl(U8, f x)", "(x : U8) -> Eq(U8, f x, g x)").is_err());
}

#[test]
fn delta_and_unfold_expose_the_defining_equation() {
    let mut env = env();
    assert!(check(&env, "delta(f; 1u8)", "Eq(U8, f 1u8, 2u8)").is_ok());
    assert!(check(&env, "delta(K; )", "Eq(U32, K, 5u32)").is_ok());
    assert!(check(&env, "fun (x : U8) => delta(f; x)", "(x : U8) -> Eq(U8, f x, #wadd_u8(x, 1u8))").is_ok());
    // Recursive opaque definitions: one step, recursive calls stay folded.
    assert!(
        check(
            &env,
            "delta(osum; Cons[U8](1u8, Cons[U8](2u8, Nil[U8])))",
            "Eq(U8, osum Cons[U8](1u8, Cons[U8](2u8, Nil[U8])), #wadd_u8(1u8, osum Cons[U8](2u8, Nil[U8])))"
        )
        .is_ok()
    );
    // Proposition-valued opaque definitions: `unfold` casts both ways.
    assert!(check(&env, "unfold(P; 3u8; from_body; refl(U8, 3u8))", "P 3u8").is_ok());
    assert!(check(&env, "fun (p : P 3u8) => unfold(P; 3u8; to_body; p)", "(p : P 3u8) -> Eq(U8, 3u8, 3u8)").is_ok());
    // The equations compose: f x = g x through both deltas.
    load(
        &mut env,
        "def[lemma] f_eq_g : (x : U8) -> Eq(U8, f x, g x) := \
           fun (x : U8) => eq::trans U8 (f x) #wadd_u8(x, 1u8) (g x) delta(f; x) (eq::sym U8 (g x) #wadd_u8(x, 1u8) delta(g; x))",
    )
    .unwrap_or_else(|e| panic!("{e}"));
}

#[test]
fn opacity_only_loses_completeness() {
    let env = env();
    // False equations stay unprovable with and without delta.
    for (t, ty) in [
        ("refl(U8, f 1u8)", "Eq(U8, f 1u8, 3u8)"),
        ("delta(f; 1u8)", "Eq(U8, f 1u8, 3u8)"),
        ("delta(f; 1u8)", "Eq(U8, f 2u8, 2u8)"),
        ("delta(K; )", "Eq(U32, K, 6u32)"),
        ("delta(osum; Nil[U8])", "Eq(U8, osum Nil[U8], 1u8)"),
        ("refl(U8, 3u8)", "P 4u8"),
    ] {
        assert!(check(&env, t, ty).is_err(), "{t} : {ty}");
    }
    // A match on an opaque boolean stays stuck: no branch confusion.
    let mut env = env;
    load(&mut env, "def[opaque] b : Bool := true").unwrap();
    assert!(check(&env, "refl(Bool, b)", "Eq(Bool, b, false)").is_err());
    assert!(check(&env, "refl(Bool, b)", "Eq(Bool, b, true)").is_err());
    assert!(check(&env, "delta(b; )", "Eq(Bool, b, true)").is_ok());
    assert!(check(&env, "delta(b; )", "Eq(Bool, b, false)").is_err());
    let stuck = norm(&env, "match b : Bool as _ return U8 with | false => 0u8 | true => 1u8 end");
    assert!(stuck.starts_with("match b"), "{stuck}");
    // Termination checking is unchanged for opaque definitions.
    assert!(
        load(&mut env, "def[spec, opaque] lp : (x : U8) -> U8 := fun (x : U8) => rec(x) measure (x)").is_err(),
        "measure recursion without a proof"
    );
    // Speculation: a recursive transparent definition whose head test is an
    // opaque boolean stays neutral even on concrete data.
    load(
        &mut env,
        "def[spec] cnt : (l : List(U8)) -> U8 := \
           fun (l : List(U8)) => match l : List(U8) as _ return U8 with \
             | Nil => 0u8 \
             | Cons(x, t) => match b : Bool as _ return U8 with | false => 0u8 | true => #wadd_u8(1u8, rec(t)) end \
           end structural l",
    )
    .unwrap();
    assert_eq!(norm(&env, "cnt Cons[U8](1u8, Nil[U8])"), "cnt Cons[U8](1u8, Nil[U8])");
}

#[test]
fn transparent_mode_unfolds_opaque_definitions() {
    let env = env();
    let ev_t = |src: &str, set: &dyn Fn(GlobalId) -> bool| {
        let v = env.eval_opaque(&VEnv::default(), Lvl(0), &tm(&env, src), set, &mut budget()).unwrap();
        env.print_term(&[], &env.quote(Lvl(0), &v, false))
    };
    let none = |_: GlobalId| false;
    assert_eq!(ev_t("f 1u8", &none), "2u8");
    assert_eq!(ev_t("K", &none), "5u32");
    assert_eq!(ev_t("twice 21u32", &none), "42u32");
    assert_eq!(ev_t("osum Cons[U8](1u8, Cons[U8](2u8, Nil[U8]))", &none), "3u8");
    // `h`'s default-mode value is cached with `f` folded; the transparent
    // mode must not reuse that cache.
    assert_eq!(norm(&env, "h 1u8"), "f 1u8");
    assert_eq!(ev_t("h 1u8", &none), "2u8");
    // Exactly the caller's set stays folded.
    let fid = env.lookup_global("f").unwrap();
    assert_eq!(ev_t("h 1u8", &|g| g == fid), "f 1u8");
    // conv_opaque instantiates closures transparently; conv does not.
    // (Values already computed keep their folded heads: NbE never unfolds a
    // neutral during conversion.)
    let a = ev(&env, &tm(&env, "fun (x : U8) => h x"));
    let b = ev(&env, &tm(&env, "fun (x : U8) => #wadd_u8(x, 1u8)"));
    assert!(!env.conv(Lvl(0), &a, &b, &mut budget()).unwrap());
    assert!(env.conv_opaque(Lvl(0), &a, &b, &none, &mut budget()).unwrap());
    assert!(!env.conv_opaque(Lvl(0), &a, &b, &|g| g == fid, &mut budget()).unwrap());
    // The fully transparent entry points (cached per mode).
    for _ in 0..2 {
        let v = env.eval_transparent(&VEnv::default(), Lvl(0), &tm(&env, "#wadd_u32(K, K)"), &mut budget()).unwrap();
        assert_eq!(env.print_term(&[], &env.quote(Lvl(0), &v, false)), "10u32");
    }
    assert!(env.conv_transparent(Lvl(0), &a, &b, &mut budget()).unwrap());
    assert_eq!(norm(&env, "#wadd_u32(K, K)"), "#wadd_u32(K, K)");
    let folded = ev(&env, &tm(&env, "f 1u8"));
    assert!(!env.conv_opaque(Lvl(0), &folded, &ev(&env, &tm(&env, "2u8")), &none, &mut budget()).unwrap());
}

#[test]
fn residuals_are_compared_transparently() {
    let mut env = env();
    load(&mut env, "def[exec] r : (x : U8) -> U8 := fun (x : U8) => #wadd_u8(f x, K2)\ndef[opaque] K2 : U8 := 2u8").unwrap_err();
    load(&mut env, "def[opaque] K2 : U8 := 2u8\ndef[exec] r : (x : U8) -> U8 := fun (x : U8) => #wadd_u8(f x, K2)").unwrap();
    let r = env.lookup_global("r").unwrap();
    let ty = tm(&env, "(x : U8) -> U8");
    // The optimizer inlines opaque callees (eval_opaque with an empty set).
    let good = tm(&env, "fun (x : U8) => #wadd_u8(x, 3u8)");
    env.check_residual_equal(&ty, &good, r, &mut budget()).unwrap_or_else(|e| panic!("{e}"));
    let bad = tm(&env, "fun (x : U8) => #wadd_u8(x, 4u8)");
    assert!(env.check_residual_equal(&ty, &bad, r, &mut budget()).is_err());
    // The reference itself (or a later global) is still refused.
    let selfref = Rc::new(Term::Lam {
        name: "x".into(),
        rel: Rel::Rel,
        dom: tm(&env, "U8"),
        body: Rc::new(Term::App { rel: Rel::Rel, fun: Rc::new(Term::Global(r)), arg: Rc::new(Term::Var(Idx(0))) }),
    });
    assert!(env.check_residual_equal(&ty, &selfref, r, &mut budget()).is_err());
}
