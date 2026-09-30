//! General kernel behaviour (DESIGN.md §5): sorts, relevance, inductives and
//! matches, η rules, recursion and unfolding, Delta/Unfold, quoting with
//! sharing, α-equivalence, abstraction and residual checks.

mod common;

use std::rc::Rc;

use common::*;
use sandblaster_kernel::api::*;
use sandblaster_kernel::term::*;
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::*;

fn ok(r: Result<(), KernelError>) {
    if let Err(e) = r {
        panic!("{e}");
    }
}

fn err_kind<T: std::fmt::Debug>(r: Result<T, KernelError>) -> KernelErrorKind {
    match r {
        Ok(v) => panic!("expected an error, got {v:?}"),
        Err(e) => e.kind,
    }
}

#[test]
fn sorts_and_formation() {
    let env = Env::new();
    ok(check(&env, "Type", "Kind"));
    assert_eq!(err_kind(infer(&env, "Kind")), KernelErrorKind::IllFormed);
    ok(check(&env, "(A : Type) -> A -> A", "Kind"));
    ok(check(&env, "Bool -> Bool", "Type"));
    ok(check(&env, "Type -> Type", "Kind"));
    // A -> Kind and Kind : Kind are ill-formed.
    assert!(infer(&env, "Bool -> Kind").is_err());
    assert!(check(&env, "Kind", "Kind").is_err());
    // Σ needs components : Type.
    assert!(infer(&env, "Sigma (A : Type), A").is_err());
    ok(check(&env, "Sigma (b : Bool), Eq(Bool, b, true)", "Type"));
    // Eq needs its type : Type; Π(T : Type). T has sort Kind.
    assert!(infer(&env, "Eq(Type, Bool, Bool)").is_err());
    assert!(infer(&env, "fun (f : (T : Type) -> T) => Eq((T : Type) -> T, f, f)").is_err());
    // Literals are range-checked.
    assert!(infer(&env, "256u8").is_err());
    ok(check(&env, "255u8", "U8"));
    ok(check(&env, "-7int", "Int"));
}

#[test]
fn relevance_must_accept() {
    let env = Env::new();
    // λG. refl(Bool, G true@Irr) : Π(G : Π(h :Irr Bool). Bool). Eq(Bool, G true@Irr, G false@Irr)
    ok(check(&env, "fun (G : (.h : Bool) -> Bool) => refl(Bool, G .true)", "(G : (.h : Bool) -> Bool) -> Eq(Bool, G .true, G .false)"));
    // Irrelevant variables are usable in irrelevant positions.
    ok(check(&env, "fun (.h : Bool) (G : (.x : Bool) -> Bool) => G .h", "(.h : Bool) -> (G : (.x : Bool) -> Bool) -> Bool"));
    ok(check(&env, "fun (.h : Eq(Bool, true, true)) => let .k : Eq(Bool, true, true) = h; true", "(.h : Eq(Bool, true, true)) -> Bool"));
}

#[test]
fn inductives_matches_and_iota() {
    let mut env = Env::new();
    ok(load(
        &mut env,
        r#"
inductive Nat { | zero | succ(n : Nat) }
inductive Pair (A : Type) (B : Type) { | mk(a : A, b : B) }
inductive Tagged (A : Type) { | tag(x : A, .p : Eq(A, x, x)) }
def[spec] add : (m : Nat) -> (n : Nat) -> Nat :=
  fun (m : Nat) (n : Nat) => match m : Nat as _ return Nat with | zero => n | succ(k) => succ(rec(k, n)) end
  structural 0
def[lemma] two_plus_one : Eq(Nat, add (succ(succ(zero))) (succ(zero)), succ(succ(succ(zero)))) :=
  refl(Nat, succ(succ(succ(zero))))
def[spec] fst_pair : (A : Type) -> (B : Type) -> (p : Pair(A, B)) -> A :=
  fun (A : Type) (B : Type) (p : Pair(A, B)) => match p : Pair(A, B) as _ return A with | mk(a, b) => a end
"#,
    )
    .map(|_| ()));
    assert_eq!(norm(&env, "add (succ(zero)) (succ(succ(zero)))"), "succ(succ(succ(zero)))");
    // Dependent match typing: the motive at each constructor.
    ok(check(
        &env,
        "fun (b : Bool) => match b : Bool as y return Eq(Bool, y, y) with | false => refl(Bool, false) | true => refl(Bool, true) end",
        "(b : Bool) -> Eq(Bool, b, b)",
    ));
    // Wrong arm type.
    assert!(check(&env, "fun (b : Bool) => match b : Bool as y return Eq(Bool, y, true) with | false => refl(Bool, false) | true => refl(Bool, true) end",
        "(b : Bool) -> Eq(Bool, b, true)").is_err());
    // Irrelevant constructor fields: conversion ignores them.
    ok(check(
        &env,
        "fun (x : Bool) (.p : Eq(Bool, x, x)) (.q : Eq(Bool, x, x)) => refl(Tagged(Bool), tag[Bool](x, .p))",
        "(x : Bool) -> (.p : Eq(Bool, x, x)) -> (.q : Eq(Bool, x, x)) -> Eq(Tagged(Bool), tag[Bool](x, .p), tag[Bool](x, .q))",
    ));
}

#[test]
fn eta_rules() {
    let mut env = Env::new();
    ok(load(&mut env, "inductive Pair (A : Type) (B : Type) { | mk(a : A, b : B) }").map(|_| ()));
    // Function eta.
    ok(check(&env, "fun (f : Bool -> Bool) => refl(Bool -> Bool, f)", "(f : Bool -> Bool) -> Eq(Bool -> Bool, f, fun (x : Bool) => f x)"));
    // Σ eta, including the irrelevant Σ `(fst p, _) ≡ p`.
    ok(check(
        &env,
        "fun (p : Sigma (b : Bool), Bool) => refl(Sigma (b : Bool), Bool, p)",
        "(p : Sigma (b : Bool), Bool) -> Eq(Sigma (b : Bool), Bool, p, pair(Sigma (b : Bool), Bool, fst(p), snd(p)))",
    ));
    ok(check(
        &env,
        "fun (p : Sigma (b : Bool), .Eq(Bool, b, true)) (.q : Eq(Bool, fst(p), true)) => refl(Sigma (b : Bool), .Eq(Bool, b, true), p)",
        "(p : Sigma (b : Bool), .Eq(Bool, b, true)) -> (.q : Eq(Bool, fst(p), true)) -> Eq(Sigma (b : Bool), .Eq(Bool, b, true), p, pair(Sigma (b : Bool), .Eq(Bool, b, true), fst(p), q))",
    ));
    // Struct eta.
    ok(check(
        &env,
        "fun (p : Pair(Bool, U8)) => refl(Pair(Bool, U8), p)",
        "(p : Pair(Bool, U8)) -> Eq(Pair(Bool, U8), p, mk[Bool, U8](match p : Pair(Bool, U8) as _ return Bool with | mk(a, b) => a end, match p : Pair(Bool, U8) as _ return U8 with | mk(a, b) => b end))",
    ));
}

#[test]
fn array_eta_small() {
    let env = prelude();
    // a ≡ [a[0], a[1], a[2]] for a : Array(U8, 3) (by conversion: refl).
    let t = "fun (a : Array U8 3usize) => refl(Array U8 3usize, a)";
    let ty = "(a : Array U8 3usize) -> Eq(Array U8 3usize, a, pair(Array U8 3usize, \
        Cons[U8](array::index U8 3usize a 0usize .refl(Bool, true), Cons[U8](array::index U8 3usize a 1usize .refl(Bool, true), \
        Cons[U8](array::index U8 3usize a 2usize .refl(Bool, true), Nil[U8]))), refl(Int, 3int)))";
    ok(check(&env, t, ty));
    // Updating an array variable with its own element is the identity.
    ok(check(
        &env,
        "fun (a : Array U32 4usize) => refl(Array U32 4usize, a)",
        "(a : Array U32 4usize) -> Eq(Array U32 4usize, array::set U32 4usize a 2usize (array::index U32 4usize a 2usize .refl(Bool, true)) .refl(Bool, true), a)",
    ));
    // But not with a different element.
    assert!(
        check(
            &env,
            "fun (a : Array U32 4usize) => refl(Array U32 4usize, a)",
            "(a : Array U32 4usize) -> Eq(Array U32 4usize, array::set U32 4usize a 2usize 0u32 .refl(Bool, true), a)"
        )
        .is_err()
    );
}

#[test]
fn recursion_policy_and_delta() {
    let env = prelude();
    // A stuck recursive application stays folded (no unbounded unfolding).
    let t = tm(&env, "fun (l : List(U8)) => seq::len U8 l");
    let v = ev(&env, &t);
    let q = env.quote(Lvl(0), &v, false);
    assert_eq!(env.print_term(&[], &q), "fun (l : List(U8)) => seq::len U8 l");
    // Unfolds when the head computes.
    assert_eq!(norm(&env, "fun (l : List(U8)) => seq::len U8 (Cons[U8](1u8, l))"), "fun (l : List(U8)) => #iadd(seq::len U8 l, 1int)");
    // Delta relates a stuck application with its body.
    ok(check(
        &env,
        "fun (l : List(U8)) => delta(seq::len; U8, l)",
        "(l : List(U8)) -> Eq(Int, seq::len U8 l, match l : List(U8) as _ return Int with | Nil => 0int | Cons(h, t) => #iadd(1int, seq::len U8 t) end)",
    ));
    // Delta needs all arguments; R : Type.
    assert!(check(&env, "delta(seq::len; U8)", "Type").is_err());
}

#[test]
fn unfold_for_propositions() {
    let mut env = prelude();
    ok(load(&mut env, r#"
def[spec] AllTrue : (l : List(Bool)) -> Type :=
  fun (l : List(Bool)) => match l : List(Bool) as _ return Type with | Nil => Unit | Cons(h, t) => And (Eq(Bool, h, true)) (rec(t)) end
  structural 0
def[lemma] all_nil : AllTrue Nil[Bool] := tt
def[lemma] all_cons : (t : List(Bool)) -> (p : AllTrue t) -> AllTrue (Cons[Bool](true, t)) :=
  fun (t : List(Bool)) (p : AllTrue t) => pair(And (Eq(Bool, true, true)) (AllTrue t), refl(Bool, true), p)
def[lemma] all_unfold : (l : List(Bool)) -> (p : AllTrue l) -> match l : List(Bool) as _ return Type with | Nil => Unit | Cons(h, t) => And (Eq(Bool, h, true)) (AllTrue t) end :=
  fun (l : List(Bool)) (p : AllTrue l) => unfold(AllTrue; l; to_body; p)
"#).map(|_| ()));
}

#[test]
fn quote_with_sharing() {
    let env = Env::new();
    // x*x computed once, used twice: shared.
    let t = env.parse_term(&["x"], "let y : U32 = #wmul_u32(x, x); #wadd_u32(y, #xor_u32(y, 7u32))").unwrap();
    let venv = VEnv(Rc::new(vec![EnvEntry::Rel(Rc::new(Value::Neu(Neutral { head: Head::Var(Lvl(0)), spine: vec![] })))]));
    let v = env.eval(&venv, Lvl(1), &t, &mut budget()).unwrap();
    let shared = env.quote(Lvl(1), &v, true);
    let s = env.print_term(&[Rc::from("x")], &shared);
    assert_eq!(s, "let s0 : U32 = #wmul_u32(x, x); #wadd_u32(s0, #xor_u32(s0, 7u32))");
    let plain = env.quote(Lvl(1), &v, false);
    assert_eq!(env.print_term(&[Rc::from("x")], &plain), "#wadd_u32(#wmul_u32(x, x), #xor_u32(#wmul_u32(x, x), 7u32))");
    // The shared quote evaluates back to a convertible value.
    let v2 = env.eval(&venv, Lvl(1), &shared, &mut budget()).unwrap();
    assert!(env.conv(Lvl(1), &v, &v2, &mut budget()).unwrap());
}

#[test]
fn alpha_eq_relevant_ignores_names_and_proofs() {
    let env = prelude();
    let same = |_: GlobalId, _: GlobalId| true;
    let eqg = |a: GlobalId, b: GlobalId| a == b;
    let a = tm(&env, "fun (s : Slice U8) (i : Usize) (.h : Eq(Bool, #lt_usize(i, fst(s)), true)) => slice::index U8 s i .h");
    let b = tm(&env, "fun (t : Slice U8) (j : Usize) (.k : Eq(Bool, #lt_usize(j, fst(t)), true)) => slice::index U8 t j ._");
    assert!(env.alpha_eq_relevant(&a, &b, &eqg));
    // Proof slots of prims are ignored.
    let c = tm(&env, "fun (x : U8) (.h : Eq(Bool, #le_int(#iadd(#cast_u8_int(x), 1int), 255int), true)) => #add_u8(x, 1u8; h)");
    let d = tm(&env, "fun (y : U8) (.q : Eq(Bool, #le_int(#iadd(#cast_u8_int(y), 1int), 255int), true)) => #add_u8(y, 1u8; _)");
    assert!(env.alpha_eq_relevant(&c, &d, &eqg));
    // Relevant differences are not ignored (hoisting / different operation).
    let e = tm(&env, "fun (x : U8) => #wadd_u8(x, 1u8)");
    let f = tm(&env, "fun (x : U8) => #wadd_u8(1u8, x)");
    assert!(!env.alpha_eq_relevant(&e, &f, &same));
    let g = tm(&env, "fun (x : U8) => let y : U8 = #wadd_u8(x, 1u8); y");
    assert!(!env.alpha_eq_relevant(&e, &g, &same));
    // Erased only matches in irrelevant positions.
    let h = tm(&env, "fun (x : U8) => _");
    assert!(!env.alpha_eq_relevant(&e, &h, &same));
}

#[test]
fn abstract_occurrences_builds_motives() {
    let env = prelude();
    let names = ["l", "x"];
    let mut ctx = Ctx::default();
    let list_u8 = ev(&env, &tm(&env, "List(U8)"));
    ctx = ctx.push(CtxEntry { name: Rc::from("l"), rel: Rel::Rel, ty: list_u8, def: None });
    ctx = ctx.push(CtxEntry { name: Rc::from("x"), rel: Rel::Rel, ty: ev(&env, &tm(&env, "U8")), def: None });
    let venv = env.ctx_venv(&ctx);
    let goal_t = env.parse_term(&names, "Eq(Int, #iadd(seq::len U8 l, 1int), seq::len U8 (Cons[U8](x, l)))").unwrap();
    let goal = env.eval(&venv, ctx.depth(), &goal_t, &mut budget()).unwrap();
    let target = env.eval(&venv, ctx.depth(), &env.parse_term(&names, "seq::len U8 l").unwrap(), &mut budget()).unwrap();
    let motive = env.abstract_occurrences(&ctx, &goal, &target, &mut budget()).unwrap();
    let printed = env.print_term(&[Rc::from("l"), Rc::from("x"), Rc::from("y")], &motive);
    // len (Cons x l) evaluates to len l + 1, so both occurrences are abstracted.
    assert_eq!(printed, "Eq(Int, #iadd(y, 1int), #iadd(y, 1int))");
}

#[test]
fn residual_candidates() {
    let mut env = prelude();
    ok(load(&mut env, r#"
def[exec] f : (x : U32) -> (y : U32) -> U32 :=
  fun (x : U32) (y : U32) => let z : U32 = #wadd_u32(x, y); #xor_u32(z, #rotr_u32(z, 7u32))
def[exec] g : (a : Array U8 4usize) -> U8 :=
  fun (a : Array U8 4usize) => #wadd_u8(array::index U8 4usize a 0usize .refl(Bool, true), array::index U8 4usize a 3usize .refl(Bool, true))
"#).map(|_| ()));
    let f = env.lookup_global("f").unwrap();
    let ty = tm(&env, "(x : U32) -> (y : U32) -> U32");
    let good = tm(&env, "fun (a : U32) (b : U32) => #xor_u32(#wadd_u32(a, b), #rotr_u32(#wadd_u32(a, b), 7u32))");
    ok(env.check_residual_equal(&ty, &good, f, &mut budget()));
    // Commutativity of neutral additions is not definitional.
    let comm = tm(&env, "fun (a : U32) (b : U32) => #xor_u32(#wadd_u32(a, b), #rotr_u32(#wadd_u32(b, a), 7u32))");
    assert!(env.check_residual_equal(&ty, &comm, f, &mut budget()).is_err());
    ok(env.check_residual_equal(&ty, &good, f, &mut budget()));
    let bad = tm(&env, "fun (a : U32) (b : U32) => #xor_u32(#wadd_u32(a, b), #rotl_u32(#wadd_u32(b, a), 7u32))");
    assert!(env.check_residual_equal(&ty, &bad, f, &mut budget()).is_err());
    // Matches are not straight-line.
    let m = tm(
        &env,
        "fun (a : U32) (b : U32) => match true : Bool as _ return U32 with | false => a | true => #xor_u32(#wadd_u32(a, b), #rotr_u32(#wadd_u32(a, b), 7u32)) end",
    );
    assert!(env.check_residual_equal(&ty, &m, f, &mut budget()).is_err());
    // Erased proofs are accepted in irrelevant positions only; array
    // parameters are compared through array eta.
    let g = env.lookup_global("g").unwrap();
    let gty = tm(&env, "(a : Array U8 4usize) -> U8");
    let gres = tm(&env, "fun (a : Array U8 4usize) => #wadd_u8(seq::index U8 fst(a) 0int ._ ._, seq::index U8 fst(a) 3int ._ ._)");
    ok(env.check_residual_equal(&gty, &gres, g, &mut budget()));
    let gbad = tm(&env, "fun (a : Array U8 4usize) => #wadd_u8(seq::index U8 fst(a) 0int ._ ._, _)");
    assert!(env.check_residual_equal(&gty, &gbad, g, &mut budget()).is_err());
}

#[test]
fn eval_opaque_keeps_heads() {
    let env = prelude();
    let g = env.lookup_global("u32::rotate_right").unwrap();
    let t = env.parse_term(&["x"], "u32::rotate_right x 7u32").unwrap();
    let venv = VEnv(Rc::new(vec![EnvEntry::Rel(Rc::new(Value::Neu(Neutral { head: Head::Var(Lvl(0)), spine: vec![] })))]));
    let v = env.eval_opaque(&venv, Lvl(1), &t, &|h| h == g, &mut budget()).unwrap();
    assert_eq!(env.print_term(&[Rc::from("x")], &env.quote(Lvl(1), &v, false)), "u32::rotate_right x 7u32");
    let v = env.eval(&venv, Lvl(1), &t, &mut budget()).unwrap();
    assert_eq!(env.print_term(&[Rc::from("x")], &env.quote(Lvl(1), &v, false)), "#rotr_u32(x, 7u32)");
}

#[test]
fn intrinsics_unfold_only_on_closed_arguments() {
    let mut env = Env::new();
    ok(load(&mut env, "def[intrinsic] twice : (x : U32) -> U32 := fun (x : U32) => #wadd_u32(x, x)").map(|_| ()));
    assert_eq!(norm(&env, "twice 21u32"), "42u32");
    assert_eq!(norm(&env, "fun (y : U32) => twice y"), "fun (y : U32) => twice y");
}

#[test]
fn budget_exhaustion_is_an_error() {
    big_stack(|| {
        let env = prelude();
        let t = tm(&env, "seq::len U8 (seq::replicate U8 1000int 0u8)");
        let mut b = Budget { steps: 100 };
        assert_eq!(env.eval(&VEnv::default(), Lvl(0), &t, &mut b).unwrap_err(), EvalError::OutOfFuel);
        let v = ev(&env, &t);
        assert!(matches!(&*v, Value::Lit { n, .. } if *n == 1000.into()));
    })
}

#[test]
fn mk_helpers_build_checkable_terms() {
    let env = Env::new();
    let b = env.bool_ind();
    let t = mk::lam("x", Rel::Rel, mk::bool_ty(b), mk::refl(mk::bool_ty(b), mk::var(0)));
    let ty = mk::pi("x", Rel::Rel, mk::bool_ty(b), mk::eq(mk::bool_ty(b), mk::var(0), mk::var(0)));
    let tyv = ev(&env, &ty);
    ok(env.check(&Ctx::default(), &t, &tyv, &mut budget()));
}

#[test]
fn typed_quotes_recheck() {
    let env = prelude();
    // An eta-expanded array variable quotes (typed) to a checkable term,
    // including the proofs inside its index neutrals.
    let aty = ev(&env, &tm(&env, "Array U8 3usize"));
    let ctx = Ctx::default().push(CtxEntry { name: Rc::from("a"), rel: Rel::Rel, ty: aty.clone(), def: None });
    let venv = env.ctx_venv(&ctx);
    let v = match &venv.0[0] {
        EnvEntry::Rel(v) => v.clone(),
        _ => unreachable!(),
    };
    let t = env.quote_typed(&ctx, &v, Some(&aty), false);
    ok(env.check(&ctx, &t, &aty, &mut budget()));
    // A slice built from it, shared quote, re-checks too.
    let s = env.eval(&venv, ctx.depth(), &env.parse_term(&["a"], "array::as_slice U8 3usize a .refl(Bool, true)").unwrap(), &mut budget()).unwrap();
    let sty = ev(&env, &tm(&env, "Slice U8"));
    let t = env.quote_typed(&ctx, &s, Some(&sty), true);
    ok(env.check(&ctx, &t, &sty, &mut budget()));
    // Untyped quoting cannot know the Σ type of a pair (documented).
    let u = env.quote(ctx.depth(), &s, false);
    assert!(env.check(&ctx, &u, &sty, &mut budget()).is_err());
}

#[test]
fn abstraction_motives_are_usable_in_transport() {
    let env = prelude();
    let lty = ev(&env, &tm(&env, "List(U8)"));
    let ctx = Ctx::default().push(CtxEntry { name: Rc::from("l"), rel: Rel::Rel, ty: lty, def: None });
    let names = ["l"];
    let venv = env.ctx_venv(&ctx);
    let evl = |s: &str| env.eval(&venv, ctx.depth(), &env.parse_term(&names, s).unwrap(), &mut budget()).unwrap();
    // Rewrite the goal len(append l Nil) = len l + 0 ... using len_append.
    let goal = evl("Eq(Int, seq::len U8 (seq::append U8 l Nil[U8]), seq::len U8 l)");
    let target = evl("seq::len U8 (seq::append U8 l Nil[U8])");
    let motive = env.abstract_occurrences(&ctx, &goal, &target, &mut budget()).unwrap();
    let ns: Vec<Name> = vec![Rc::from("l"), Rc::from("y")];
    let motive_txt = env.print_term(&ns, &motive);
    assert_eq!(motive_txt, "Eq(Int, y, seq::len U8 l)");
    // transport(Int, len l, len(append l Nil), sym(len_append), y. motive, refl(Int, len l)) : goal
    let proof = format!(
        "transport(Int, seq::len U8 l, seq::len U8 (seq::append U8 l Nil[U8]), \
         eq::sym Int (seq::len U8 (seq::append U8 l Nil[U8])) (seq::len U8 l) (seq::len_append U8 l Nil[U8]), \
         y. {motive_txt}, refl(Int, seq::len U8 l))"
    );
    let p = env.parse_term(&names, &proof).unwrap();
    ok(env.check(&ctx, &p, &goal, &mut budget()));
}
