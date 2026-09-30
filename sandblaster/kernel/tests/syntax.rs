//! Core text syntax (DESIGN.md §5.12): the printer's output parses back to
//! the same term, for every `Term` constructor, relevance markers, literals,
//! declarations, and every definition of the prelude.

mod common;

use std::rc::Rc;

use common::*;
use sandblaster_kernel::api::*;
use sandblaster_kernel::syntax::parser::{Item, parse_items};
use sandblaster_kernel::term::*;
use sandblaster_kernel::util::mk;

/// Structural equality ignoring binder names.
fn same(a: &Tm, b: &Tm) -> bool {
    use Term::*;
    let l = |x: &[Tm], y: &[Tm]| x.len() == y.len() && x.iter().zip(y).all(|(p, q)| same(p, q));
    match (&**a, &**b) {
        (Var(i), Var(j)) => i == j,
        (Global(g), Global(h)) => g == h,
        (Sort(s), Sort(t)) => s == t,
        (Pi { rel: r1, dom: d1, cod: c1, .. }, Pi { rel: r2, dom: d2, cod: c2, .. })
        | (Lam { rel: r1, dom: d1, body: c1, .. }, Lam { rel: r2, dom: d2, body: c2, .. })
        | (Sigma { snd_rel: r1, fst: d1, snd: c1, .. }, Sigma { snd_rel: r2, fst: d2, snd: c2, .. }) => {
            r1 == r2 && same(d1, d2) && same(c1, c2)
        }
        (App { rel: r1, fun: f1, arg: a1 }, App { rel: r2, fun: f2, arg: a2 }) => r1 == r2 && same(f1, f2) && same(a1, a2),
        (Let { rel: r1, ty: t1, val: v1, body: b1, .. }, Let { rel: r2, ty: t2, val: v2, body: b2, .. }) => {
            r1 == r2 && same(t1, t2) && same(v1, v2) && same(b1, b2)
        }
        (Pair { ty: t1, fst: f1, snd: s1 }, Pair { ty: t2, fst: f2, snd: s2 }) => same(t1, t2) && same(f1, f2) && same(s1, s2),
        (Fst(p), Fst(q)) | (Snd(p), Snd(q)) => same(p, q),
        (Eq { ty: t1, lhs: l1, rhs: r1 }, Eq { ty: t2, lhs: l2, rhs: r2 })
        | (BvRefl { ty: t1, lhs: l1, rhs: r1 }, BvRefl { ty: t2, lhs: l2, rhs: r2 }) => same(t1, t2) && same(l1, l2) && same(r1, r2),
        (Refl { ty: t1, val: v1 }, Refl { ty: t2, val: v2 }) | (Absurd { ty: t1, proof: v1 }, Absurd { ty: t2, proof: v2 }) => {
            same(t1, t2) && same(v1, v2)
        }
        (
            Transport { ty: a1, lhs: b1, rhs: c1, eq: d1, motive: e1, val: f1 },
            Transport { ty: a2, lhs: b2, rhs: c2, eq: d2, motive: e2, val: f2 },
        ) => same(a1, a2) && same(b1, b2) && same(c1, c2) && same(d1, d2) && same(e1, e2) && same(f1, f2),
        (Ind { ind: i1, params: p1 }, Ind { ind: i2, params: p2 }) => i1 == i2 && l(p1, p2),
        (Ctor { ind: i1, ctor: c1, params: p1, args: a1 }, Ctor { ind: i2, ctor: c2, params: p2, args: a2 }) => {
            i1 == i2 && c1 == c2 && l(p1, p2) && l(a1, a2)
        }
        (
            Match { ind: i1, params: p1, scrut: s1, motive: m1, arms: a1 },
            Match { ind: i2, params: p2, scrut: s2, motive: m2, arms: a2 },
        ) => {
            i1 == i2
                && l(p1, p2)
                && same(s1, s2)
                && same(m1, m2)
                && a1.len() == a2.len()
                && a1.iter().zip(a2).all(|(x, y)| x.names.len() == y.names.len() && same(&x.body, &y.body))
        }
        (IntTy(w1), IntTy(w2)) => w1 == w2,
        (Lit { w: w1, n: n1 }, Lit { w: w2, n: n2 }) => w1 == w2 && n1 == n2,
        (Prim { op: o1, args: a1, proofs: q1 }, Prim { op: o2, args: a2, proofs: q2 }) => o1 == o2 && l(a1, a2) && l(q1, q2),
        (Rec { args: a1, proof: p1 }, Rec { args: a2, proof: p2 }) => {
            l(a1, a2)
                && match (p1, p2) {
                    (Some(x), Some(y)) => same(x, y),
                    (None, None) => true,
                    _ => false,
                }
        }
        (Delta { def: d1, args: a1 }, Delta { def: d2, args: a2 }) => d1 == d2 && l(a1, a2),
        (Unfold { def: d1, args: a1, to_body: t1, val: v1 }, Unfold { def: d2, args: a2, to_body: t2, val: v2 }) => {
            d1 == d2 && l(a1, a2) && t1 == t2 && same(v1, v2)
        }
        (Linarith { hyps: h1, goal: g1, cert: c1 }, Linarith { hyps: h2, goal: g2, cert: c2 }) => {
            h1.len() == h2.len() && h1.iter().zip(h2).all(|((a, b), (c, d))| same(a, c) && same(b, d)) && same(g1, g2) && c1 == c2
        }
        (Axiom { ax: x1, args: a1 }, Axiom { ax: x2, args: a2 }) => x1 == x2 && l(a1, a2),
        (Erased, Erased) => true,
        _ => false,
    }
}

fn round_trip(env: &Env, names: &[&str], src: &str) {
    let t = env.parse_term(names, src).unwrap_or_else(|e| panic!("parse `{src}`: {e}"));
    let ns: Vec<Name> = names.iter().map(|n| Rc::from(*n)).collect();
    let printed = env.print_term(&ns, &t);
    let t2 = env.parse_term(names, &printed).unwrap_or_else(|e| panic!("reparse `{printed}` (from `{src}`): {e}"));
    assert!(same(&t, &t2), "round trip changed the term:\n  src:     {src}\n  printed: {printed}");
    // Printing is stable.
    assert_eq!(env.print_term(&ns, &t2), printed);
}

#[test]
fn every_constructor_round_trips() {
    let mut env = prelude();
    load(&mut env, "def[lemma] refl_true : Eq(Bool, true, true) := refl(Bool, true)").unwrap();
    let cases = [
        "x",
        "Type",
        "(A : Type) -> A -> A",
        "(.h : Eq(Bool, x, true)) -> Bool",
        "fun (a : Bool) (.h : Eq(Bool, a, true)) => a",
        "f .p x",
        "let y : Bool = x; let .q : Eq(Bool, y, y) = refl(Bool, y); y",
        "Sigma (n : Usize), .Eq(Int, #cast_usize_int(n), 3int)",
        "Sigma (b : Bool), Bool",
        "pair(Sigma (b : Bool), Bool, true, x)",
        "fst(pair(Sigma (b : Bool), Bool, true, x))",
        "snd(pair(Sigma (b : Bool), Bool, true, x))",
        "Eq(Bool, x, true)",
        "refl(Bool, x)",
        "transport(Bool, x, true, p, y. Eq(Bool, y, true), refl(Bool, x))",
        "List(U8)",
        "Cons[U8](7u8, Nil[U8])",
        "Some[Bool](x)",
        "match x : Bool as y return Eq(Bool, y, y) with | false => refl(Bool, false) | true => refl(Bool, true) end",
        "match l : List(U8) as _ return Int with | Nil => 0int | Cons(h, t) => seq::len U8 t end",
        "U8",
        "Int",
        "-12345678901234567890int",
        "18446744073709551615u64",
        "#wadd_u32(3u32, 4u32)",
        "#add_u8(1u8, 2u8; refl(Bool, true))",
        "#of_int_u16(3int; refl(Bool, true), refl(Bool, true))",
        "#cast_u8_int(255u8)",
        "delta(seq::len; U8, l)",
        "unfold(seq::len; U8, l; to_body; p)",
        "unfold(seq::len; U8, l; from_body; p)",
        "linarith([p : Eq(Bool, #lt_u8(1u8, 2u8), true)]; Empty; [1, -3/4, 0])",
        "bvrefl(U32, #wadd_u32(1u32, 2u32), 3u32)",
        "absurd(Bool, p)",
        "axiom[and_le_left_u32](1u32, 2u32)",
        "axiom[min_def_le_u8](1u8, 2u8, .p)",
        "_",
        "@0",
        "slice::index U8 s 0usize .p",
        "fun (Bool1 : Type) (seq : Bool1) => seq",
        "if x as .h return U8 then 1u8 else 0u8",
        "match l : List(U8) as y return U8 using .e with | Nil => 0u8 | Cons(h, t) => h end",
    ];
    for c in cases {
        round_trip(&env, &["x", "f", "p", "l", "s"], c);
    }
}

#[test]
fn clashing_binder_names_are_renamed() {
    let env = prelude();
    // A binder named like a global is renamed; the reference stays local.
    let t = mk::lam("seq::len", Rel::Rel, mk::int_ty(Width::U8), mk::var(0));
    let printed = env.print_term(&[], &t);
    assert!(!printed.contains("seq::len"), "{printed}");
    let t2 = env.parse_term(&[], &printed).unwrap();
    assert!(same(&t, &t2));
    // Shadowed names are disambiguated.
    let t = mk::lam("x", Rel::Rel, mk::int_ty(Width::U8), mk::lam("x", Rel::Rel, mk::int_ty(Width::U8), mk::var(1)));
    let printed = env.print_term(&[], &t);
    let t2 = env.parse_term(&[], &printed).unwrap();
    assert!(same(&t, &t2), "{printed}");
}

#[test]
fn whole_prelude_round_trips() {
    let env = prelude();
    let n = env.num_globals();
    assert!(n > 200, "prelude has {n} globals");
    for i in 0..n {
        let g = GlobalId(i);
        for t in [env.global_type(g).unwrap(), env.global_body(g).unwrap()] {
            let printed = env.print_term(&[], &t);
            let t2 =
                env.parse_term(&[], &printed).unwrap_or_else(|e| panic!("{}: reparse failed: {e}\n{printed}", env.global_name(g).unwrap()));
            assert!(same(&t, &t2), "{}: round trip changed the term:\n{printed}", env.global_name(g).unwrap());
        }
    }
}

#[test]
fn declarations_round_trip() {
    let env = prelude();
    // Inductives print and parse back to the same declaration.
    for name in ["List", "Option", "Tuple3", "Unit", "Either"] {
        let ind = env.lookup_ind(name).unwrap();
        let text = env.print_inductive(ind).unwrap();
        let fresh = if name == "List" { Env::new() } else { prelude_without(name) };
        let items = parse_items(&fresh, &text).unwrap_or_else(|e| panic!("{name}: {e}\n{text}"));
        let Item::Ind(d) = &items[0] else { panic!("expected an inductive") };
        let orig = env.inductive_decl(ind).unwrap();
        assert_eq!(d.ctors.len(), orig.ctors.len());
        for (c1, c2) in d.ctors.iter().zip(&orig.ctors) {
            assert_eq!(c1.name, c2.name);
            assert_eq!(c1.fields.len(), c2.fields.len());
            for (f1, f2) in c1.fields.iter().zip(&c2.fields) {
                assert_eq!(f1.1, f2.1);
            }
        }
    }
    // Definitions with each recursion mode and kind.
    let src = r#"
def[spec] count : (T : Type) -> (l : List(T)) -> Int :=
  fun (T : Type) (l : List(T)) => match l : List(T) as _ return Int with | Nil => 0int | Cons(h, t) => #iadd(1int, rec(T, t)) end
  structural 1
def[loop_helper] down : (n : U8) -> (.h : Eq(Bool, true, true)) -> U8 :=
  fun (n : U8) (.h : Eq(Bool, true, true)) =>
    if #eq_u8(n, 0u8) as .c return U8 then 0u8
    else rec(#wsub_u8(n, 1u8), .h; refl(Bool, true))
  measure (n)
def[intrinsic, arity = 1] k : (x : U32) -> U32 -> U32 := fun (x : U32) => fun (y : U32) => x
"#;
    let items = parse_items(&env, src).unwrap();
    for it in items {
        let Item::Def(d) = it else { panic!() };
        let text = env.print_def_decl(&d);
        let back = parse_items(&env, &text).unwrap_or_else(|e| panic!("{e}\n{text}"));
        let Item::Def(d2) = &back[0] else { panic!() };
        assert_eq!(d.name, d2.name);
        assert_eq!(d.kind, d2.kind);
        assert_eq!(d.arity, d2.arity);
        assert!(same(&d.ty, &d2.ty) && same(&d.body, &d2.body), "{text}");
        match (&d.recursion, &d2.recursion) {
            (Recursion::None, Recursion::None) => {}
            (Recursion::Structural { param: a }, Recursion::Structural { param: b }) => assert_eq!(a, b),
            (Recursion::Measure { measure: a }, Recursion::Measure { measure: b }) => assert!(same(a, b)),
            _ => panic!("recursion mode changed: {text}"),
        }
    }
}

/// A prelude environment is needed to parse field types of most inductives;
/// re-declaring an existing name is fine for parsing (the new name shadows).
fn prelude_without(_name: &str) -> Env {
    prelude()
}

#[test]
fn parse_errors_are_reported() {
    let env = prelude();
    for bad in [
        "3",
        "fun x => x",
        "(",
        "Cons[U8](1u8)",
        "#nope_u8(1u8)",
        "axiom[nope](1u8)",
        "match true : Bool as _ return Bool with | true => true end",
    ] {
        assert!(env.parse_term(&[], bad).is_err(), "`{bad}` should not parse");
    }
    // Relevance markers are validated against declarations.
    assert!(env.parse_term(&[], "slice::mk U8 0usize Nil[U8] refl(Bool, true)").is_ok()); // plain app: marker is on App
    assert!(env.parse_term(&["p"], "axiom[min_def_le_u8](1u8, 2u8, p)").is_err());
}

#[test]
fn documented_examples_check() {
    let mut env = prelude();
    // Items from CORE_SYNTAX.md.
    load(
        &mut env,
        r#"
inductive Tagged (A : Type) { | tag(x : A, .p : Eq(A, x, x)) }
def[spec] replicate : (n : Int) -> List(U8) :=
  fun (n : Int) =>
    if #le_int(n, 0int) as .c return List(U8) then Nil[U8] else
      Cons[U8](0u8, rec(#isub(n, 1int);
        pair(Sigma (_ : Eq(Bool, #le_int(0int, #isub(n, 1int)), true)), Eq(Bool, #lt_int(#isub(n, 1int), n), true),
             linarith([c : Eq(Bool, #le_int(n, 0int), false)]; Eq(Bool, #le_int(0int, #isub(n, 1int)), true); [1, 1]),
             linarith([]; Eq(Bool, #lt_int(#isub(n, 1int), n), true); [1]))))
  measure (n)
def[intrinsic, arity = 1] k : (x : U32) -> U32 -> U32 := fun (x : U32) => fun (y : U32) => x
"#,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    check(&env, "fun (G : (.h : Bool) -> Bool) => refl(Bool, G .true)", "(G : (.h : Bool) -> Bool) -> Eq(Bool, G .true, G .false)")
        .unwrap();
    check(
        &env,
        "fun (s : Slice U8) (i : Usize) => if #lt_usize(i, fst(s)) as .h return U8 then slice::index U8 s i .h else 0u8",
        "Slice U8 -> Usize -> U8",
    )
    .unwrap();
    check(
        &env,
        "fun (x : U64) => linarith([]; Eq(Bool, #lt_u64(#rem_u64(x, 8u64; refl(Bool, true)), 8u64), true); [1, 0, 0, 0, 0, 0, 0, 0, 0, 1])",
        "(x : U64) -> Eq(Bool, #lt_u64(#rem_u64(x, 8u64; refl(Bool, true)), 8u64), true)",
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let text = sandblaster_kernel::expand_templates("%for W in u8 u32\ndef[prelude] t::$w : $W := $MAX$w\n%end\n").unwrap();
    assert_eq!(text, "def[prelude] t::u8 : U8 := 255u8\ndef[prelude] t::u32 : U32 := 4294967295u32\n");
}
