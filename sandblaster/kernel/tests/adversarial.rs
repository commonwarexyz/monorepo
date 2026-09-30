//! Kernel adversarial suite (DESIGN.md §5.3, §10.3; docs/review-1.md,
//! kernel-soundness and hardware lenses): every listed must-accept /
//! must-reject case.

mod common;

use std::rc::Rc;

use common::*;
use num_bigint::BigInt;
use sandblaster_kernel::api::*;
use sandblaster_kernel::term::*;
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::*;

fn rejected<T: std::fmt::Debug>(r: Result<T, KernelError>, kind: Option<KernelErrorKind>, what: &str) {
    match r {
        Ok(v) => panic!("must reject: {what} (accepted: {v:?})"),
        Err(e) => {
            if let Some(k) = kind {
                assert_eq!(e.kind, k, "{what}: {e}");
            }
        }
    }
}

fn accepted<T>(r: Result<T, KernelError>, what: &str) {
    if let Err(e) = r {
        panic!("must accept: {what}: {e}");
    }
}

fn load_err(env: &mut Env, src: &str) -> Result<Vec<Name>, KernelError> {
    load(env, src)
}

// ---------------------------------------------------------------------------
// Relevance (§5.3; review kernel-soundness (a)–(d)).
// ---------------------------------------------------------------------------

#[test]
fn relevance_leaks_are_rejected() {
    let mut env = prelude();
    load(
        &mut env,
        "def[spec] E : (b : Bool) -> Type := fun (b : Bool) => match b : Bool as _ return Type with | false => Empty | true => Unit end",
    )
    .unwrap();
    // An irrelevant constructor field must be a proposition (red-team R1):
    // `IBox` with a `.x : Bool` field (accepted before the fix, used below
    // as a relevance probe) is now rejected at declaration; the probe uses a
    // propositional field instead.
    rejected(load_err(&mut env, "inductive IBox { | ibox(.x : Bool) }"), Some(KernelErrorKind::Relevance), "Irr data field");
    load(&mut env, "inductive PBox { | pbox(.x : Eq(Bool, true, true)) }").unwrap();
    // Must accept: λG. refl(Bool, G true@Irr) : Π(G : Π(h :Irr Bool). Bool). Eq(Bool, G true@Irr, G false@Irr).
    accepted(
        check(&env, "fun (G : (.h : Bool) -> Bool) => refl(Bool, G .true)", "(G : (.h : Bool) -> Bool) -> Eq(Bool, G .true, G .false)"),
        "G true@Irr",
    );
    // (a) an irrelevant let/binder may not flow into a relevant result.
    rejected(
        check(&env, "fun (.h : Bool) => let x : Bool = h; x", "(.h : Bool) -> Bool"),
        Some(KernelErrorKind::Relevance),
        "(a) let x = h",
    );
    rejected(check(&env, "fun (.h : Bool) => h", "(.h : Bool) -> Bool"), Some(KernelErrorKind::Relevance), "λ(h :Irr). h");
    rejected(
        check(&env, "fun (.h : Bool) => let .x : Bool = h; x", "(.h : Bool) -> Bool"),
        Some(KernelErrorKind::Relevance),
        "irrelevant let used relevantly",
    );
    // (b) application annotations must match the Π.
    rejected(infer(&env, "(fun (x : Bool) => x) .true"), Some(KernelErrorKind::Relevance), "(b) relevant λ applied @Irr");
    rejected(infer(&env, "(fun (.x : Bool) => true) true"), Some(KernelErrorKind::Relevance), "irrelevant λ applied relevantly");
    // (d) the domain of an Irr binder / every type position is relevant.
    rejected(
        infer(&env, "fun (.h : Bool) => (.u : E h) -> Empty"),
        Some(KernelErrorKind::Relevance),
        "(d) G0 := λ(h :Irr Bool). Π(u :Irr E h). Empty",
    );
    rejected(infer(&env, "fun (.h : Bool) (x : E h) => x"), Some(KernelErrorKind::Relevance), "irrelevant variable in a binder type");
    rejected(infer(&env, "fun (.h : Bool) => refl(Bool, h)"), Some(KernelErrorKind::Relevance), "irrelevant variable in refl");
    // Matches on irrelevant data in relevant positions.
    rejected(
        infer(&env, "fun (.h : Bool) => match h : Bool as _ return Bool with | false => true | true => false end"),
        Some(KernelErrorKind::Relevance),
        "match on Irr",
    );
    rejected(
        infer(&env, "fun (b : PBox) => match b : PBox as _ return Eq(Bool, true, true) with | pbox(.x) => x end"),
        Some(KernelErrorKind::Relevance),
        "Irr ctor field used relevantly",
    );
    // snd of an Irr Σ only in irrelevant positions (and `Sigma (b : Bool),
    // .Bool` itself is now ill-formed: its irrelevant component is data).
    rejected(infer(&env, "fun (p : Sigma (b : Bool), .Bool) => snd(p)"), Some(KernelErrorKind::Relevance), "snd of Irr Σ (data)");
    rejected(infer(&env, "fun (p : Sigma (b : Bool), .Eq(Bool, b, true)) => snd(p)"), Some(KernelErrorKind::Relevance), "snd of Irr Σ");
    // Transport's value position is relevant.
    rejected(
        infer(&env, "fun (.h : Eq(Bool, true, true)) => transport(Bool, true, true, h, y. Eq(Bool, y, true), h)"),
        Some(KernelErrorKind::Relevance),
        "Irr var as transport value",
    );
    accepted(
        infer(&env, "fun (.h : Eq(Bool, true, true)) => transport(Bool, true, true, h, y. Eq(Bool, y, true), refl(Bool, true))"),
        "Irr var as transport equation",
    );
}

/// Red-team R1 (docs/review-3-redteam.md): inside an irrelevant position only
/// the variables bound *outside* it are resurrected; `Irr` binders, lets and
/// match fields introduced inside stay irrelevant (a nested irrelevant
/// position resurrects them again), `snd` of an `Irr` Σ needs a pair built
/// from outside variables, and irrelevant Σ components / constructor fields
/// must be propositions. Each reproduction is a closed proof of `Empty`
/// that the one-flag checker accepted.
#[test]
fn irrelevant_positions_resurrect_only_outer_variables() {
    let boom = include_str!("redteam/irr_mode_empty.core");
    let r1: [(&str, String); 5] = [
        ("r1a Irr λ built in an irrelevant position", boom.to_string()),
        (
            "r1b snd of an Irr Σ in an irrelevant position",
            "def[lemma] boom : Empty :=
               absurd(Empty,
                 let L : (G : (Sigma (b : Bool), .Bool) -> Bool)
                       -> Eq(Bool, G pair(Sigma (b : Bool), .Bool, true, false), G pair(Sigma (b : Bool), .Bool, true, true)) =
                   fun (G : (Sigma (b : Bool), .Bool) -> Bool) => refl(Bool, G pair(Sigma (b : Bool), .Bool, true, false));
                 bool::false_ne_true (L (fun (p : Sigma (b : Bool), .Bool) => snd(p))))"
                .to_string(),
        ),
        (
            "r1c Irr constructor field in an irrelevant position",
            "inductive IBox { | ibox(.x : Bool) }
             def[lemma] boom : Empty :=
               absurd(Empty,
                 bool::false_ne_true
                   (eq::cong IBox Bool (fun (b : IBox) => match b : IBox as _ return Bool with | ibox(.x) => x end)
                      ibox(.false) ibox(.true) (refl(IBox, ibox(.false)))))"
                .to_string(),
        ),
        (
            "r1d Irr let in an irrelevant position",
            "def[lemma] boom : Empty :=
               absurd(Empty,
                 let L : (G : (.h : Bool) -> Bool) -> Eq(Bool, G .true, G .false) =
                   fun (G : (.h : Bool) -> Bool) => refl(Bool, G .true);
                 bool::false_ne_true (L (fun (.h : Bool) => let .y : Bool = h; bool::not y)))"
                .to_string(),
        ),
        (
            "r1e exec out-of-bounds index justified by boom",
            format!(
                "{boom}\ndef[exec] oob : (s : Slice U8) -> U8 :=
                   fun (s : Slice U8) => slice::index U8 s 1000usize .absurd(Eq(Bool, #lt_usize(1000usize, fst(s)), true), boom)"
            ),
        ),
    ];
    for (what, src) in &r1 {
        let mut env = prelude();
        rejected(load_err(&mut env, src), None, what);
    }
    // The r1a/r1d functions are rejected for the right reason, also without
    // the surrounding lemma.
    let env = prelude();
    rejected(
        check(
            &env,
            "fun (.e : Empty) => absurd(Bool, let f : (.h : Bool) -> Bool = fun (.h : Bool) => bool::not h; e)",
            "(.e : Empty) -> Bool",
        ),
        Some(KernelErrorKind::Relevance),
        "Irr λ binder used relevantly inside the irrelevant position that binds it",
    );
    rejected(
        check(&env, "fun (.e : Empty) => absurd(Bool, let .y : Empty = e; y)", "(.e : Empty) -> Bool"),
        Some(KernelErrorKind::Relevance),
        "Irr let used relevantly inside the irrelevant position that binds it",
    );
    // Must accept: outer variables are resurrected, and a nested irrelevant
    // position resurrects the inner binders.
    accepted(check(&env, "fun (.e : Empty) => absurd(Bool, e)", "(.e : Empty) -> Bool"), "outer Irr variable in absurd's proof");
    accepted(
        check(&env, "fun (.e : Empty) => absurd(Bool, let .y : Empty = e; absurd(Empty, y))", "(.e : Empty) -> Bool"),
        "inner Irr let in a nested irrelevant position",
    );
    accepted(
        check(
            &env,
            "fun (.e : Empty) => absurd(Bool, let f : (.h : Empty) -> Empty = fun (.h : Empty) => absurd(Empty, h); f .e)",
            "(.e : Empty) -> Bool",
        ),
        "inner Irr binder in a nested irrelevant position",
    );
    // snd of an Irr Σ inside an irrelevant position: only of a pair built
    // from variables bound outside it (a nested irrelevant position — e.g. an
    // `eq::promote` argument — resurrects inner pairs too).
    let len1 = "Eq(Int, seq::len U8 fst(a), #cast_usize_int(1usize))";
    rejected(
        check(
            &env,
            &format!(
                "fun (.e : Empty) => absurd(Bool, let f : (a : Array U8 1usize) -> {len1} = fun (a : Array U8 1usize) => eq::trans Int (seq::len U8 fst(a)) (#cast_usize_int(1usize)) (#cast_usize_int(1usize)) snd(a) (refl(Int, #cast_usize_int(1usize))); e)"
            ),
            "(.e : Empty) -> Bool",
        ),
        Some(KernelErrorKind::Relevance),
        "snd of a pair bound inside the irrelevant position",
    );
    accepted(
        check(
            &env,
            &format!(
                "fun (.e : Empty) => absurd(Bool, let f : (a : Array U8 1usize) -> {len1} = fun (a : Array U8 1usize) => eq::promote Int (seq::len U8 fst(a)) (#cast_usize_int(1usize)) .snd(a); e)"
            ),
            "(.e : Empty) -> Bool",
        ),
        "snd of an inner pair in a nested irrelevant position",
    );
    accepted(
        check(
            &env,
            &format!(
                "fun (a : Array U8 1usize) (.e : Empty) => absurd(Bool, let p : {len1} = eq::trans Int (seq::len U8 fst(a)) (#cast_usize_int(1usize)) (#cast_usize_int(1usize)) snd(a) (refl(Int, #cast_usize_int(1usize))); e)"
            ),
            "(a : Array U8 1usize) -> (.e : Empty) -> Bool",
        ),
        "snd of an outer pair used relevantly inside the irrelevant position",
    );
    // linarith inside an irrelevant position does not use inner Irr
    // hypotheses (neither as stated hypotheses nor as context facts).
    let le = "Eq(Bool, #le_u8(1u8, x), true)";
    rejected(
        check(
            &env,
            &format!(
                "fun (x : U8) (.e : Empty) => absurd(Bool, let g : (.h : {le}) -> {le} = fun (.h : {le}) => linarith([]; {le}; []); e)"
            ),
            "(x : U8) -> (.e : Empty) -> Bool",
        ),
        None,
        "linarith fact from an inner Irr binder",
    );
    rejected(
        check(
            &env,
            &format!(
                "fun (x : U8) (.e : Empty) => absurd(Bool, let g : (.h : {le}) -> {le} = fun (.h : {le}) => linarith([h : {le}]; {le}; []); e)"
            ),
            "(x : U8) -> (.e : Empty) -> Bool",
        ),
        None,
        "linarith hypothesis from an inner Irr binder",
    );
    accepted(
        check(
            &env,
            &format!(
                "fun (x : U8) (.e : Empty) => absurd(Bool, let g : (.h : {le}) -> {le} = fun (.h : {le}) => eq::promote Bool (#le_u8(1u8, x)) true .linarith([h : {le}]; {le}; []); e)"
            ),
            "(x : U8) -> (.e : Empty) -> Bool",
        ),
        "linarith with an inner Irr hypothesis in a nested irrelevant position",
    );
    accepted(
        check(
            &env,
            &format!("fun (x : U8) (.hx : {le}) => #sub_u8(x, 1u8; linarith([]; {le}; []))"),
            &format!("(x : U8) -> (.hx : {le}) -> U8"),
        ),
        "linarith fact from an outer Irr binder",
    );
    // The documented must-accept lemma still holds (irrelevant spine
    // arguments are skipped by conversion).
    accepted(
        check(&env, "fun (G : (.h : Bool) -> Bool) => refl(Bool, G .true)", "(G : (.h : Bool) -> Bool) -> Eq(Bool, G .true, G .false)"),
        "G true@Irr",
    );
    // Irrelevant Σ components and constructor fields must be propositions.
    let mut env = prelude();
    for (ty, ok) in [
        ("Sigma (b : Bool), .Bool", false),
        ("Sigma (b : Bool), .U8", false),
        ("Sigma (b : Bool), .Option(Unit)", false),
        ("Sigma (b : Bool), .List(Unit)", false),
        ("Sigma (b : Bool), .Eq(Bool, b, true)", true),
        ("Sigma (b : Bool), .Empty", true),
        ("Sigma (b : Bool), .Unit", true),
        ("Sigma (b : Bool), .(Eq(Bool, b, true) -> Empty)", true),
        ("Sigma (n : Usize), .((i : Usize) -> Eq(Bool, #lt_usize(i, n), true))", true),
        ("Sigma (n : Usize), .((i : Usize) -> Bool)", false),
        ("Sigma (b : Bool), .And (Eq(Bool, b, true)) (Eq(Bool, b, b))", true),
        ("Sigma (b : Bool), .And (Eq(Bool, b, true)) Bool", false),
        ("Sigma (l : List(U8)), .SliceOk U8 3usize l", true),
    ] {
        let r = infer(&env, ty);
        if ok {
            accepted(r, ty);
        } else {
            rejected(r, Some(KernelErrorKind::Relevance), ty);
        }
    }
    rejected(infer(&env, "fun (P : Type) => Sigma (u : Unit), .P"), Some(KernelErrorKind::Relevance), "Irr Σ over a type variable");
    rejected(infer(&env, "Sigma (b : Bool), .Type"), None, "Irr Σ component of sort Kind");
    rejected(load_err(&mut env, "inductive RBox { | rbox(.x : RBox) }"), Some(KernelErrorKind::Relevance), "Irr recursive field");
    rejected(load_err(&mut env, "inductive DBox { | dbox(.x : U64) }"), Some(KernelErrorKind::Relevance), "Irr data field");
    accepted(load_err(&mut env, "inductive QBox (A : Type) { | qbox(a : A, .p : Eq(A, a, a)) }"), "Irr propositional field");
    accepted(load_err(&mut env, "inductive Pf { | pf(.p : Eq(Bool, true, true), .q : Unit -> Empty -> Empty) }"), "Irr Π field");
}

#[test]
fn array_length_confusion_is_rejected() {
    let env = prelude();
    // (c) Array(T, 3) ≢ Array(T, 4): Irr-Σ types are compared fully.
    let a3 = ev(&env, &tm(&env, "Array U8 3usize"));
    let a4 = ev(&env, &tm(&env, "Array U8 4usize"));
    assert!(!env.conv(Lvl(0), &a3, &a4, &mut budget()).unwrap());
    rejected(
        check(&env, "pair(Array U8 4usize, Cons[U8](1u8, Cons[U8](2u8, Cons[U8](3u8, Nil[U8]))), refl(Int, 3int))", "Array U8 4usize"),
        None,
        "3 elements as Array(_, 4)",
    );
    rejected(
        check(&env, "pair(Array U8 4usize, Cons[U8](1u8, Cons[U8](2u8, Cons[U8](3u8, Nil[U8]))), refl(Int, 4int))", "Array U8 4usize"),
        None,
        "forged length proof",
    );
    rejected(
        check(&env, "fun (a : Array U8 3usize) => a", "Array U8 3usize -> Array U8 4usize"),
        Some(KernelErrorKind::TypeMismatch),
        "Array 3 as Array 4",
    );
    rejected(infer(&env, "fun (a : Array U8 3usize) => snd(a)"), Some(KernelErrorKind::Relevance), "array length proof used relevantly");
    // Indexing out of bounds needs an impossible proof.
    rejected(
        check(&env, "fun (a : Array U8 3usize) => array::index U8 3usize a 3usize .refl(Bool, true)", "Array U8 3usize -> U8"),
        None,
        "a[3] on [u8; 3]",
    );
}

// ---------------------------------------------------------------------------
// Sorts and inductive declarations (§5.2, §5.4; Hurkens, Girard).
// ---------------------------------------------------------------------------

#[test]
fn universe_paradoxes_are_rejected() {
    let mut env = prelude();
    rejected(check(&env, "Kind", "Kind"), None, "Kind : Kind");
    rejected(check(&env, "Type", "Type"), None, "Type : Type");
    rejected(infer(&env, "Bool -> Kind"), None, "A -> Kind");
    rejected(infer(&env, "(A : Type) -> Kind"), None, "Π(A : Type). Kind");
    rejected(infer(&env, "Eq(Type, Bool, Bool)"), Some(KernelErrorKind::IllFormed), "Eq at Kind");
    rejected(infer(&env, "fun (A : Kind) => A"), None, "binder of type Kind");
    rejected(infer(&env, "transport(Bool, true, true, refl(Bool, true), y. Type, Bool)"), None, "transport motive : Kind");
    // Hurkens: no constructor field of type Type (or of sort Kind).
    rejected(load_err(&mut env, "inductive U { | box(X : Type) }"), Some(KernelErrorKind::IllFormed), "box(X : Type)");
    rejected(load_err(&mut env, "inductive U2 { | box2(f : Type -> Bool) }"), Some(KernelErrorKind::IllFormed), "box2(f : Type -> Bool)");
    rejected(
        load_err(&mut env, "inductive U3 { | box3(X : (A : Type) -> A) }"),
        Some(KernelErrorKind::IllFormed),
        "box3(X : Π(A : Type). A)",
    );
    // A Type parameter cannot be instantiated with Type.
    load(&mut env, "inductive W (X : Type) { | w(x : X) }").unwrap();
    rejected(infer(&env, "W(Type)"), Some(KernelErrorKind::TypeMismatch), "W(Type)");
    // Strict positivity by syntax.
    rejected(load_err(&mut env, "inductive Neg { | neg(f : Neg -> Bool) }"), Some(KernelErrorKind::IllFormed), "negative occurrence");
    rejected(load_err(&mut env, "inductive Pos { | pos(f : Bool -> Pos) }"), Some(KernelErrorKind::IllFormed), "non-direct occurrence");
    rejected(load_err(&mut env, "inductive Rose { | node(kids : List(Rose)) }"), Some(KernelErrorKind::IllFormed), "nested occurrence");
    rejected(
        load_err(&mut env, "inductive P (A : Type) { | p(x : P(Bool)) }"),
        Some(KernelErrorKind::IllFormed),
        "recursive occurrence with other parameters",
    );
    rejected(load_err(&mut env, "inductive Idx (A : Type) { | mk(e : Eq(Type, A, A)) }"), None, "field mentioning Eq at Kind");
}

// ---------------------------------------------------------------------------
// Recursion and termination (§5.6).
// ---------------------------------------------------------------------------

#[test]
fn nontermination_is_rejected() {
    let mut env = prelude();
    // Global self-reference (only expressible through the API: the parser
    // cannot name an undefined global).
    let id = GlobalId(env.num_globals());
    let bool_ty = mk::bool_ty(env.bool_ind());
    let d = DefDecl {
        name: "selfref".into(),
        kind: DefKind::Spec,
        ty: mk::pi("b", Rel::Rel, bool_ty.clone(), bool_ty.clone()),
        body: mk::lam("b", Rel::Rel, bool_ty.clone(), mk::app(mk::global(id), mk::var(0))),
        recursion: Recursion::None,
        arity: 1,
        opaque: false,
    };
    rejected(env.add_def(d, &mut budget()), Some(KernelErrorKind::Termination), "Global self-reference");
    // References to later globals do not exist (no mutual recursion).
    let d = DefDecl {
        name: "forward".into(),
        kind: DefKind::Spec,
        ty: mk::pi("b", Rel::Rel, bool_ty.clone(), bool_ty.clone()),
        body: mk::lam("b", Rel::Rel, bool_ty.clone(), mk::app(mk::global(GlobalId(id.0 + 1)), mk::var(0))),
        recursion: Recursion::None,
        arity: 1,
        opaque: false,
    };
    rejected(env.add_def(d, &mut budget()), None, "forward reference");
    // rec in a non-recursive definition, in a type, outside a definition.
    rejected(
        load_err(&mut env, "def[spec] r0 : (l : List(U8)) -> Int := fun (l : List(U8)) => rec(l)"),
        Some(KernelErrorKind::Termination),
        "rec without recursion mode",
    );
    rejected(infer(&env, "rec(1u8)"), Some(KernelErrorKind::Termination), "rec outside a definition");
    // Structural: the argument must be a recursive field of a match on the parameter.
    rejected(
        load_err(
            &mut env,
            "def[spec] r1 : (l : List(U8)) -> Int := fun (l : List(U8)) => match l : List(U8) as _ return Int with | Nil => 0int | Cons(h, t) => rec(l) end structural 0",
        ),
        Some(KernelErrorKind::Termination),
        "structural rec on the parameter itself",
    );
    rejected(
        load_err(
            &mut env,
            "def[spec] r2 : (l : List(U8)) -> (k : List(U8)) -> Int := fun (l : List(U8)) (k : List(U8)) => match k : List(U8) as _ return Int with | Nil => 0int | Cons(h, t) => rec(t, t) end structural 0",
        ),
        Some(KernelErrorKind::Termination),
        "structural rec on a field of another variable",
    );
    rejected(
        load_err(&mut env, "def[spec] r3 : (n : U8) -> U8 := fun (n : U8) => rec(n) structural 0"),
        Some(KernelErrorKind::Termination),
        "structural on a non-inductive",
    );
    // Recursion hidden in irrelevant positions is checked too.
    rejected(
        load_err(&mut env, "def[lemma] hidden : (l : List(U8)) -> Empty := fun (l : List(U8)) => absurd(Empty, rec(l)) structural 0"),
        Some(KernelErrorKind::Termination),
        "rec inside absurd's (irrelevant) proof",
    );
    rejected(
        load_err(
            &mut env,
            "def[lemma] hidden2 : (l : List(U8)) -> (.p : Empty) -> Empty := fun (l : List(U8)) (.p : Empty) => absurd(Empty, rec(l, .p)) structural 0",
        ),
        Some(KernelErrorKind::Termination),
        "rec in an irrelevant argument",
    );
    rejected(
        load_err(&mut env, "def[lemma] hidden3 : (n : U8) -> Empty := fun (n : U8) => absurd(Empty, rec(n; refl(Bool, true))) measure (n)"),
        Some(KernelErrorKind::TypeMismatch),
        "measure rec with a bogus decrease proof",
    );
    rejected(
        load_err(&mut env, "def[lemma] hidden4 : (n : U8) -> Empty := fun (n : U8) => absurd(Empty, rec(n)) measure (n)"),
        Some(KernelErrorKind::Termination),
        "measure rec without a proof",
    );
}

#[test]
fn inconsistent_measure_precondition_is_accepted_but_does_not_loop() {
    let mut env = prelude();
    // f(n, h :Irr lt(n, n) = true) := Some(rec(n, h; h)): the decrease proof
    // comes from an inconsistent precondition (review, kernel-soundness).
    accepted(
        load(
            &mut env,
            r#"
def[spec] f : (n : U8) -> (.h : Eq(Bool, #lt_u8(n, n), true)) -> Option(U8) :=
  fun (n : U8) (.h : Eq(Bool, #lt_u8(n, n), true)) => Some[U8](match rec(n, .h; h) : Option(U8) as _ return U8 with | None => 0u8 | Some(x) => x end)
  measure (n)
"#,
        ),
        "f with inconsistent precondition",
    );
    let a = ev(&env, &tm(&env, "fun (x : U8) (.h : Eq(Bool, #lt_u8(x, x), true)) => f x .h"));
    let b = ev(&env, &tm(&env, "fun (y : U8) (.k : Eq(Bool, #lt_u8(y, y), true)) => f y .k"));
    let r = env.conv(Lvl(0), &a, &b, &mut Budget { steps: 2_000_000 });
    assert_eq!(r, Err(EvalError::OutOfFuel), "must terminate with an error, never success");
    // Checking something that forces the unfolding also fails with an error.
    let r = check(
        &env,
        "fun (x : U8) (.h : Eq(Bool, #lt_u8(x, x), true)) => refl(Option(U8), f x .h)",
        "(x : U8) -> (.h : Eq(Bool, #lt_u8(x, x), true)) -> Eq(Option(U8), f x .h, Some[U8](0u8))",
    );
    assert!(r.is_err());
}

#[test]
fn delta_and_unfold_restrictions() {
    let mut env = prelude();
    load(
        &mut env,
        r#"
def[spec] AllTrue : (l : List(Bool)) -> Type :=
  fun (l : List(Bool)) => match l : List(Bool) as _ return Type with | Nil => Unit | Cons(h, t) => And (Eq(Bool, h, true)) (rec(t)) end
  structural 0
"#,
    )
    .unwrap();
    // Delta at R = Type would need Eq at Kind.
    rejected(
        check(&env, "fun (l : List(Bool)) => delta(AllTrue; l)", "(l : List(Bool)) -> Type"),
        Some(KernelErrorKind::IllFormed),
        "delta for a proposition-valued def",
    );
    // Unfold needs a proposition-valued def.
    rejected(
        infer(&env, "fun (l : List(U8)) (p : Int) => unfold(seq::len; U8, l; to_body; p)"),
        Some(KernelErrorKind::IllFormed),
        "unfold of a non-propositional def",
    );
}

// ---------------------------------------------------------------------------
// Linear arithmetic certificates (§5.8).
// ---------------------------------------------------------------------------

#[test]
fn forged_and_overflowing_certificates_are_rejected() {
    let env = prelude();
    let mut ctx = Ctx::default();
    ctx = ctx.push(CtxEntry { name: Rc::from("x"), rel: Rel::Rel, ty: ev(&env, &tm(&env, "U64")), def: None });
    let x = |src: &str| env.parse_term(&["x"], src).unwrap();
    // Goal x < 0 is false (x = 0): constraints −x ≤ 0 (negated goal), −x ≤ 0,
    // x − (2^64−1) ≤ 0. With 128-bit wrapping arithmetic the multipliers
    // (2^128−1, 0, 2^128−1) would make the x coefficient vanish and the
    // constant positive; exact arithmetic rejects them.
    let goal = x("Eq(Bool, #lt_u64(x, 0u64), true)");
    let g = env.eval(&env.ctx_venv(&ctx), ctx.depth(), &goal, &mut budget()).unwrap();
    let big: BigInt = (BigInt::from(1) << 128u32) - 1;
    for cert in [
        vec![big.clone(), BigInt::from(0), big.clone()],
        vec![BigInt::from(1) << 128u32, BigInt::from(0), BigInt::from(0)],
        vec![BigInt::from(0), BigInt::from(0), BigInt::from(0)],
        vec![BigInt::from(1), BigInt::from(-1), BigInt::from(0)],
    ] {
        let t = Rc::new(Term::Linarith {
            hyps: vec![],
            goal: goal.clone(),
            cert: cert.into_iter().map(|n| Rat { num: n, den: BigInt::from(1) }).collect(),
        });
        rejected(env.check(&ctx, &t, &g, &mut budget()), Some(KernelErrorKind::Linarith), "forged certificate");
    }
    // Nonpositive denominators.
    for den in [0, -1] {
        let t = Rc::new(Term::Linarith {
            hyps: vec![],
            goal: goal.clone(),
            cert: vec![Rat { num: BigInt::from(1), den: BigInt::from(den) }; 3],
        });
        rejected(env.check(&ctx, &t, &g, &mut budget()), Some(KernelErrorKind::Linarith), "denominator ≤ 0");
    }
    // Empty from nothing.
    let empty = x("Empty");
    let ev_empty = env.eval(&env.ctx_venv(&ctx), ctx.depth(), &empty, &mut budget()).unwrap();
    for n in 0..4 {
        let t = Rc::new(Term::Linarith {
            hyps: vec![],
            goal: empty.clone(),
            cert: vec![Rat { num: BigInt::from(7), den: BigInt::from(1) }; n],
        });
        rejected(env.check(&ctx, &t, &ev_empty, &mut budget()), None, "Empty from nothing");
    }
    // Erased proofs of hypotheses are rejected.
    let t = x("linarith([_ : Eq(Bool, #lt_u64(x, 0u64), true)]; Empty; [1, 0, 0])");
    rejected(env.check(&ctx, &t, &ev_empty, &mut budget()), Some(KernelErrorKind::Erased), "Erased linarith hypothesis");
}

#[test]
fn false_shift_facts_are_not_derivable() {
    let env = prelude();
    let mut ctx = Ctx::default();
    ctx = ctx.push(CtxEntry { name: Rc::from("a"), rel: Rel::Rel, ty: ev(&env, &tm(&env, "U64")), def: None });
    // to_int(a << 1) = 2·to_int(a) is false at a = 2^63 (the high bit is dropped).
    for goal in [
        "Eq(Int, #cast_u64_int(#shl_u64(a, 1u32; refl(Bool, true))), #imul(#cast_u64_int(a), 2int))",
        "Eq(Int, #cast_u64_int(#wshl_u64(a, 1u32)), #imul(#cast_u64_int(a), 2int))",
        "Eq(Bool, #le_u64(a, #wshl_u64(a, 1u32)), true)",
        "Eq(Bool, #le_u64(a, #shl_u64(a, 3u32; refl(Bool, true))), true)",
    ] {
        let g = env.parse_term(&["a"], goal).unwrap();
        assert!(auto_linarith(&env, &ctx, vec![], g).is_none(), "`{goal}` must not be derivable");
    }
    assert_eq!(norm(&env, "#wshl_u64(9223372036854775808u64, 1u32)"), "0u64");
    // No shl/shr multiplication axiom exists.
    assert!(sandblaster_kernel::axioms::axiom_by_name("shl_mul_u64").is_none());
    assert!(sandblaster_kernel::axioms::axiom_by_name("shr_div_u64").is_none());
    // Axiom hypotheses must hold.
    rejected(
        infer(&env, "axiom[min_def_le_u8](5u8, 3u8, .refl(Bool, true))"),
        Some(KernelErrorKind::TypeMismatch),
        "false axiom hypothesis",
    );
}

// ---------------------------------------------------------------------------
// Word algebra traps (hardware lens): BvRefl (phase 1 = conversion) must
// reject the unsound candidate identities.
// ---------------------------------------------------------------------------

#[test]
fn unsound_word_identities_are_rejected() {
    let env = prelude();
    for (ty, lhs, rhs) in [
        ("U8", "#wshr_u8(#not_u8(x), 1u32)", "#not_u8(#wshr_u8(x, 1u32))"),
        ("U8", "#wshl_u8(#not_u8(x), 1u32)", "#not_u8(#wshl_u8(x, 1u32))"),
        (
            "U32",
            "#or_u32(#wshl_u32(#cast_u8_u32(b), 8u32), #wshl_u32(#cast_u8_u32(c), 4u32))",
            "#xor_u32(#wshl_u32(#cast_u8_u32(b), 8u32), #wshl_u32(#cast_u8_u32(c), 4u32))",
        ),
        ("U32", "#cast_u8_u32(#wadd_u8(b, c))", "#wadd_u32(#cast_u8_u32(b), #cast_u8_u32(c))"),
        ("U8", "#wshr_u8(#wadd_u8(x, b), 1u32)", "#wadd_u8(#wshr_u8(x, 1u32), #wshr_u8(b, 1u32))"),
        ("U8", "#rotr_u8(#wadd_u8(x, b), 3u32)", "#wadd_u8(#rotr_u8(x, 3u32), #rotr_u8(b, 3u32))"),
    ] {
        let t = format!("fun (x : U8) (b : U8) (c : U8) => bvrefl({ty}, {lhs}, {rhs})");
        rejected(infer(&env, &t), Some(KernelErrorKind::BvRefl), &format!("bvrefl {lhs} = {rhs}"));
    }
    // A true identity by conversion is accepted.
    accepted(infer(&env, "fun (x : U8) => bvrefl(U8, #wadd_u8(#wadd_u8(x, 1u8), 2u8), #wadd_u8(x, 3u8))"), "bvrefl by conversion");
}

// ---------------------------------------------------------------------------
// Transport, conversion and the memo (§5.5, §5.9).
// ---------------------------------------------------------------------------

#[test]
fn transport_reduces_only_on_convertible_endpoints() {
    let env = prelude();
    // Under a false equation the transport stays stuck (no Unit/Empty confusion).
    let t = tm(
        &env,
        "fun (e : Eq(Bool, false, true)) => transport(Bool, false, true, e, y. match y : Bool as _ return Type with | false => Unit | true => Empty end, tt)",
    );
    let v = ev(&env, &t);
    let q = env.print_term(&[], &env.quote(Lvl(0), &v, false));
    assert!(q.contains("transport("), "{q}");
    // And it reduces when the endpoints agree.
    assert_eq!(norm(&env, "transport(Bool, true, true, refl(Bool, true), y. U8, 5u8)"), "5u8");
}

#[test]
fn conversion_skips_exactly_the_irrelevant_positions() {
    let env = prelude();
    // Relevant arguments of neutral applications are compared.
    let a = ev(&env, &tm(&env, "fun (f : Bool -> Bool) => f true"));
    let b = ev(&env, &tm(&env, "fun (f : Bool -> Bool) => f false"));
    assert!(!env.conv(Lvl(0), &a, &b, &mut budget()).unwrap());
    // Irrelevant ones are skipped.
    let a = ev(&env, &tm(&env, "fun (f : (.p : Bool) -> Bool) => f .true"));
    let b = ev(&env, &tm(&env, "fun (f : (.p : Bool) -> Bool) => f .false"));
    assert!(env.conv(Lvl(0), &a, &b, &mut budget()).unwrap());
    // Budget exhaustion is never "convertible".
    let a = ev(&env, &tm(&env, "fun (l : List(U8)) => seq::append U8 l (seq::replicate U8 50int 0u8)"));
    let b = ev(&env, &tm(&env, "fun (l : List(U8)) => seq::append U8 l (seq::replicate U8 50int 0u8)"));
    assert_eq!(env.conv(Lvl(0), &a, &b, &mut Budget { steps: 20 }), Err(EvalError::OutOfFuel));
}

#[test]
fn memo_address_reuse_churn() {
    // The memo keeps every compared pair alive for the whole conversion, so a
    // freed temporary's address can never be mistaken for a proven pair.
    // Churn many temporaries (closure instantiations, unfoldings) inside and
    // across conversions and check every answer against the expected one.
    let env = prelude();
    let mut expected_true = 0;
    for i in 0..400u32 {
        let k = i % 7;
        let l = if i % 3 == 0 { k } else { (k + 1) % 7 };
        let a = ev(
            &env,
            &tm(
                &env,
                &format!(
                    "fun (b : Bool) (x : U32) => match b : Bool as _ return U32 with | false => #wadd_u32(x, {k}u32) | true => u32::rotate_right (#xor_u32(x, {k}u32)) {k}u32 end"
                ),
            ),
        );
        let b = ev(
            &env,
            &tm(
                &env,
                &format!(
                    "fun (c : Bool) (y : U32) => match c : Bool as _ return U32 with | false => #wadd_u32(y, {k}u32) | true => u32::rotate_right (#xor_u32(y, {l}u32)) {k}u32 end"
                ),
            ),
        );
        let r = env.conv(Lvl(0), &a, &b, &mut budget()).unwrap();
        assert_eq!(r, k == l, "iteration {i}");
        expected_true += r as u32;
        // Temporaries created and dropped between conversions.
        for j in 0..10u32 {
            let _ = ev(&env, &tm(&env, &format!("seq::len U8 (seq::replicate U8 {j}int 1u8)")));
        }
    }
    assert!(expected_true > 100);
    // One large conversion whose sub-comparisons create and drop many
    // temporaries: two 64-element arrays differing only in the last element.
    let arr = |last: u32| {
        let mut s = format!("Cons[U32](#wadd_u32(x, {last}u32), Nil[U32])");
        for i in (0..63u32).rev() {
            s = format!("Cons[U32](u32::rotate_left (#wmul_u32(x, {i}u32)) {i}u32, {s})");
        }
        format!("fun (x : U32) => {s}")
    };
    let a = ev(&env, &tm(&env, &arr(1)));
    let b = ev(&env, &tm(&env, &arr(2)));
    let c = ev(&env, &tm(&env, &arr(1)));
    assert!(!env.conv(Lvl(0), &a, &b, &mut budget()).unwrap());
    assert!(env.conv(Lvl(0), &a, &c, &mut budget()).unwrap());
}

// ---------------------------------------------------------------------------
// Erased (§5.11): rejected by every checking entry point.
// ---------------------------------------------------------------------------

#[test]
fn erased_is_rejected_everywhere() {
    let mut env = prelude();
    rejected(infer(&env, "_"), Some(KernelErrorKind::Erased), "infer(Erased)");
    rejected(check(&env, "_", "Bool"), Some(KernelErrorKind::Erased), "check(Erased)");
    rejected(
        check(&env, "fun (s : Slice U8) => slice::index U8 s 0usize ._", "Slice U8 -> U8"),
        Some(KernelErrorKind::Erased),
        "Erased in an irrelevant argument",
    );
    rejected(check(&env, "#add_u8(1u8, 2u8; _)", "U8"), Some(KernelErrorKind::Erased), "Erased prim proof");
    rejected(
        check(&env, "pair(Array U8 0usize, Nil[U8], _)", "Array U8 0usize"),
        Some(KernelErrorKind::Erased),
        "Erased Irr pair component",
    );
    rejected(load_err(&mut env, "def[exec] e1 : Bool := _"), Some(KernelErrorKind::Erased), "add_def with Erased body");
    rejected(
        load_err(&mut env, "def[exec] e2 : (s : Slice U8) -> U8 := fun (s : Slice U8) => slice::index U8 s 0usize ._"),
        Some(KernelErrorKind::Erased),
        "add_def with Erased proof",
    );
    rejected(load_err(&mut env, "def[exec] e3 : _ := true"), Some(KernelErrorKind::Erased), "add_def with Erased type");
    rejected(load_err(&mut env, "inductive EI { | ei(.p : _) }"), Some(KernelErrorKind::Erased), "add_inductive with Erased field type");
    rejected(
        load_err(&mut env, "def[lemma] e4 : (h : Empty) -> Bool := fun (h : Empty) => absurd(Bool, _)"),
        Some(KernelErrorKind::Erased),
        "Erased absurd proof",
    );
    rejected(
        infer(&env, "fun (e : Eq(Bool, true, false)) => transport(Bool, true, false, _, y. U8, 1u8)"),
        Some(KernelErrorKind::Erased),
        "Erased transport equation",
    );
    // check_residual_equal accepts Erased only in irrelevant positions and never as an absurd proof.
    load(&mut env, "def[exec] ident : (x : U8) -> U8 := fun (x : U8) => x").unwrap();
    let r = env.lookup_global("ident").unwrap();
    let ty = tm(&env, "(x : U8) -> U8");
    rejected(
        env.check_residual_equal(&ty, &tm(&env, "fun (x : U8) => _"), r, &mut budget()),
        None,
        "Erased in a relevant residual position",
    );
    rejected(
        env.check_residual_equal(&ty, &tm(&env, "fun (x : U8) => absurd(U8, _)"), r, &mut budget()),
        None,
        "Erased absurd proof in a residual",
    );
    accepted(
        env.check_residual_equal(&ty, &tm(&env, "fun (x : U8) => #sub_u8(#add_u8(x, 1u8; _), 1u8; _)"), r, &mut budget()),
        "Erased proof slots in a residual",
    );
    // A candidate may not call the reference itself (it would be emitted as
    // the reference's body and loop).
    rejected(
        env.check_residual_equal(&ty, &tm(&env, "fun (x : U8) => ident x"), r, &mut budget()),
        Some(KernelErrorKind::IllFormed),
        "residual calling its reference",
    );
}

#[test]
fn absurd_needs_a_proof_of_empty() {
    let env = prelude();
    rejected(check(&env, "absurd(Empty, refl(Bool, true))", "Empty"), Some(KernelErrorKind::TypeMismatch), "absurd without Empty");
    rejected(
        check(&env, "fun (h : Eq(Bool, true, false)) => absurd(Empty, h)", "Eq(Bool, true, false) -> Empty"),
        None,
        "absurd from an equation",
    );
    accepted(
        check(&env, "fun (h : Eq(Bool, false, true)) => absurd(Empty, bool::false_ne_true h)", "Eq(Bool, false, true) -> Empty"),
        "no-confusion",
    );
}

// ---------------------------------------------------------------------------
// Round trip (§8.3; review kernel-soundness "round trip compares by
// conversion"): alpha_eq_relevant is syntactic, so the three printer
// mutations — hoisting a checked read out of its guard, `x * 0`, and an unused
// let of an out-of-bounds read — are all detected, although each mutation is
// convertible with the original.
// ---------------------------------------------------------------------------

#[test]
fn round_trip_mutations_are_detected() {
    let env = prelude();
    let eq = |a: GlobalId, b: GlobalId| a == b;
    let orig = tm(&env, "fun (s : Slice U8) (i : Usize) => if #lt_usize(i, fst(s)) as .h return U8 then slice::index U8 s i .h else 0u8");
    let hoisted = tm(
        &env,
        "fun (s : Slice U8) (i : Usize) => let v : U8 = slice::index U8 s i ._; if #lt_usize(i, fst(s)) as .h return U8 then v else 0u8",
    );
    assert!(!env.alpha_eq_relevant(&orig, &hoisted, &eq), "hoisted read");
    let times_zero = tm(&env, "fun (s : Slice U8) (i : Usize) => #wmul_u32(#cast_u8_u32(slice::index U8 s 99usize ._), 0u32)");
    let zero = tm(&env, "fun (s : Slice U8) (i : Usize) => 0u32");
    assert!(!env.alpha_eq_relevant(&times_zero, &zero, &eq), "x * 0");
    let unused = tm(&env, "fun (s : Slice U8) (i : Usize) => let v : U8 = slice::index U8 s 99usize ._; 0u8");
    let plain = tm(&env, "fun (s : Slice U8) (i : Usize) => 0u8");
    assert!(!env.alpha_eq_relevant(&unused, &plain, &eq), "unused let");
    // The mutations are convertible with the originals (which is why the
    // round trip must not use conversion).
    let a = ev(&env, &times_zero);
    let b = ev(&env, &zero);
    assert!(env.conv(Lvl(0), &a, &b, &mut budget()).unwrap());
    let a = ev(&env, &unused);
    let b = ev(&env, &plain);
    assert!(env.conv(Lvl(0), &a, &b, &mut budget()).unwrap());
}

// ---------------------------------------------------------------------------
// BvRefl / bvnorm (DESIGN.md §9.8, §10.3): the word normalizer cannot be used
// to prove false equations, leak relevance, see through opacity, loop, or
// confuse values through its memo. (The review's unsound candidate rules are
// in `unsound_word_identities_are_rejected` above and in tests/bvnorm.rs.)
// ---------------------------------------------------------------------------

#[test]
fn bvrefl_cannot_prove_false_equations() {
    let mut env = prelude();
    for (t, what) in [
        ("fun (x : U8) => bvrefl(U8, x, #wadd_u8(x, 1u8))", "x = x + 1"),
        ("fun (x : U8) (y : U8) => bvrefl(Bool, #lt_u8(x, y), #lt_u8(y, x))", "x < y = y < x"),
        ("fun (x : U32) => bvrefl(U32, #wmul_u32(x, x), #wshl_u32(x, 1u32))", "x * x = x << 1"),
        ("fun (x : U32) => bvrefl(U32, #rotr_u32(x, 1u32), #wshr_u32(x, 1u32))", "rotr = shr"),
        ("fun (x : U64) => bvrefl(U64, #cast_u32_u64(#cast_u64_u32(x)), x)", "truncation is not the identity"),
        ("fun (x : U64) => bvrefl(Usize, #cast_u64_usize(#cast_u32_u64(#cast_u64_u32(x))), #cast_u64_usize(x))", "retyped truncation"),
        (
            "fun (x : U8) (b : Bool) => bvrefl(U8, match b : Bool as _ return U8 with | false => x | true => #not_u8(x) end, x)",
            "a stuck match is not its first arm",
        ),
        (
            "fun (o : Option(U8)) => bvrefl(U8, match o : Option(U8) as _ return U8 with | None => 0u8 | Some(v) => v end, \
                                            match o : Option(U8) as _ return U8 with | None => 0u8 | Some(v) => #not_u8(v) end)",
            "different arms under a neutral scrutinee",
        ),
    ] {
        rejected(infer(&env, t), Some(KernelErrorKind::BvRefl), what);
    }
    // A false bvrefl cannot be turned into a proof of Empty.
    rejected(
        infer(
            &env,
            "transport(U8, 0u8, 1u8, bvrefl(U8, 0u8, 1u8), y. match #eq_u8(y, 0u8) : Bool as _ return Type with | false => Empty | true => Unit end, tt)",
        ),
        None,
        "Empty from bvrefl(0, 1)",
    );
    // Typing and relevance are checked before normalization.
    rejected(infer(&env, "fun (.h : U8) => bvrefl(U8, h, h)"), Some(KernelErrorKind::Relevance), "irrelevant variable in bvrefl");
    rejected(infer(&env, "bvrefl(U8, 0u16, 0u16)"), Some(KernelErrorKind::TypeMismatch), "ill-typed sides");
    rejected(infer(&env, "fun (x : U8) => bvrefl(U8, x, _)"), Some(KernelErrorKind::Erased), "Erased side");
    // BvRefl evaluates transparently (phase 3): an opaque definition is its
    // value there — true equations through opacity are provable, false ones
    // are not — while conversion (refl) still keeps it folded.
    load(&mut env, "def[opaque] ob : Bool := true\ndef[opaque] ow : U32 := 7u32").unwrap();
    accepted(infer(&env, "bvrefl(Bool, ob, true)"), "bvrefl through opacity (true)");
    rejected(infer(&env, "bvrefl(Bool, ob, false)"), Some(KernelErrorKind::BvRefl), "bvrefl through opacity (false)");
    accepted(infer(&env, "bvrefl(U32, #xor_u32(ow, 0u32), 7u32)"), "bvrefl through opacity (word)");
    rejected(infer(&env, "bvrefl(U32, #xor_u32(ow, 0u32), 8u32)"), Some(KernelErrorKind::BvRefl), "bvrefl through opacity (false word)");
    accepted(infer(&env, "bvrefl(U32, #xor_u32(ow, 0u32), ow)"), "opaque atoms");
    rejected(check(&env, "refl(Bool, ob)", "Eq(Bool, ob, true)"), Some(KernelErrorKind::TypeMismatch), "refl through opacity");
    // A false equation cannot be smuggled through BvRefl's transparency into
    // a checking-mode proof of Empty.
    rejected(
        infer(
            &env,
            "transport(Bool, ob, false, bvrefl(Bool, ob, false), y. match y : Bool as _ return Type with | false => Unit | true => Empty end, tt)",
        ),
        None,
        "Empty from a false transparent equation",
    );
    // Budget exhaustion inside bvrefl is an error, never acceptance (the
    // inconsistent-precondition definition of the termination tests).
    load(
        &mut env,
        r#"
def[spec] f : (n : U8) -> (.h : Eq(Bool, #lt_u8(n, n), true)) -> Option(U8) :=
  fun (n : U8) (.h : Eq(Bool, #lt_u8(n, n), true)) => Some[U8](match rec(n, .h; h) : Option(U8) as _ return U8 with | None => 0u8 | Some(x) => x end)
  measure (n)
"#,
    )
    .unwrap();
    let r = env.infer(
        &Ctx::default(),
        &tm(&env, "fun (x : U8) (.h : Eq(Bool, #lt_u8(x, x), true)) => bvrefl(Option(U8), f x .h, Some[U8](0u8))"),
        &mut Budget { steps: 3_000_000 },
    );
    assert!(r.is_err(), "bvrefl on a looping unfolding must fail");
}

#[test]
fn bvnorm_memo_address_reuse_churn() {
    // Every value the normalizer memoizes is kept alive for the whole
    // problem, so temporaries freed during closure instantiation cannot alias
    // (DESIGN.md §5.9). Many closure instances with nearly equal bodies must
    // still be told apart.
    let env = prelude();
    let mut lhs = "x".to_string();
    let mut rhs = "x".to_string();
    for k in 0..60 {
        lhs = format!("(fun (y : U32) => #wadd_u32(#rotr_u32(y, {}u32), {k}u32)) ({lhs})", k % 31 + 1);
        rhs = format!("(fun (y : U32) => #wadd_u32(#rotr_u32(y, {}u32), {k}u32)) ({rhs})", k % 31 + 1);
    }
    let good = format!("fun (x : U32) => bvrefl(U32 -> U32, fun (z : U32) => #xor_u32(z, {lhs}), fun (z : U32) => #xor_u32({rhs}, z))");
    accepted(infer(&env, &good), "equal towers");
    let rhs_bad = rhs.replacen("59u32", "58u32", 1);
    let bad = format!("fun (x : U32) => bvrefl(U32 -> U32, fun (z : U32) => #xor_u32(z, {lhs}), fun (z : U32) => #xor_u32({rhs_bad}, z))");
    rejected(infer(&env, &bad), Some(KernelErrorKind::BvRefl), "towers differing in one constant");
}

// ---------------------------------------------------------------------------
// Opaque definitions (DESIGN.md §5.6): opacity only loses completeness.
// ---------------------------------------------------------------------------

#[test]
fn opacity_cannot_be_exploited() {
    let mut env = prelude();
    load(&mut env, "def[opaque] c : Bool := true\ndef[spec, opaque] inc : (x : U8) -> U8 := fun (x : U8) => #wadd_u8(x, 1u8)").unwrap();
    for (t, ty, what) in [
        ("refl(Bool, c)", "Eq(Bool, c, false)", "refl"),
        ("delta(c; )", "Eq(Bool, c, false)", "delta"),
        ("refl(Bool, c)", "Eq(Bool, c, true)", "refl through opacity"),
        ("fun (x : U8) => delta(inc; x)", "(x : U8) -> Eq(U8, inc x, x)", "wrong delta"),
    ] {
        rejected(check(&env, t, ty), None, what);
    }
    accepted(check(&env, "delta(c; )", "Eq(Bool, c, true)"), "delta exposes the definition");
    // Opaque definitions obey the same termination rules.
    let id = GlobalId(env.num_globals());
    let bool_ty = mk::bool_ty(env.bool_ind());
    let d = DefDecl {
        name: "oself".into(),
        kind: DefKind::Spec,
        ty: mk::pi("b", Rel::Rel, bool_ty.clone(), bool_ty.clone()),
        body: mk::lam("b", Rel::Rel, bool_ty.clone(), mk::app(mk::global(id), mk::var(0))),
        recursion: Recursion::None,
        arity: 1,
        opaque: true,
    };
    rejected(env.add_def(d, &mut budget()), Some(KernelErrorKind::Termination), "opaque self-reference");
    // The transparent residual check is still an equivalence check.
    load(&mut env, "def[exec] r : (x : U8) -> U8 := fun (x : U8) => inc (inc x)").unwrap();
    let r = env.lookup_global("r").unwrap();
    let ty = tm(&env, "(x : U8) -> U8");
    accepted(env.check_residual_equal(&ty, &tm(&env, "fun (x : U8) => #wadd_u8(x, 2u8)"), r, &mut budget()), "transparent residual");
    rejected(env.check_residual_equal(&ty, &tm(&env, "fun (x : U8) => #wadd_u8(x, 1u8)"), r, &mut budget()), None, "wrong residual");
}

// ---------------------------------------------------------------------------
// Phase 3 rules: linarith hints and assumptions, the ground-recursion
// unfolding refinement, the evaluation memo.
// ---------------------------------------------------------------------------

#[test]
fn linarith_hints_and_assumptions_cannot_prove_false_goals() {
    let env = prelude();
    let mut ctx = Ctx::default();
    let mut names: Vec<&str> = Vec::new();
    for (n, rel, ty) in [
        ("x", Rel::Rel, "U8"),
        ("y", Rel::Rel, "U8"),
        ("hx", Rel::Irr, "Eq(Bool, #lt_u8(x, 10u8), true)"),
        ("hy", Rel::Rel, "Eq(Bool, #le_u8(y, x), true)"),
    ] {
        let t = env.parse_term(&names, ty).unwrap();
        let v = env.eval(&env.ctx_venv(&ctx), ctx.depth(), &t, &mut budget()).unwrap();
        ctx = ctx.push(CtxEntry { name: Rc::from(n), rel, ty: v, def: None });
        names.push(n);
    }
    let t = |s: &str| env.parse_term(&names, s).unwrap_or_else(|e| panic!("{s}: {e}"));
    let goal_v = |s: &str| env.eval(&env.ctx_venv(&ctx), ctx.depth(), &t(s), &mut budget()).unwrap();
    // False goals (not implied by x < 10, y ≤ x, the word bounds), with
    // empty, forged and overlong certificates, relevantly and irrelevantly.
    for goal in ["Eq(Bool, #lt_u8(y, 5u8), true)", "Eq(Bool, #lt_u8(x, y), true)", "Eq(U8, x, y)", "Empty"] {
        for cert in ["", "1", "1, 1, 1, 1, 1, 1, 1, 1, 1, 1", "1/2, 1/2, 1/2, 1/2"] {
            let l = t(&format!("linarith([]; {goal}; [{cert}])"));
            rejected(env.check(&ctx, &l, &goal_v(goal), &mut budget()), Some(KernelErrorKind::Linarith), "false goal (relevant)");
            // Irrelevantly: as the proof slot of a checked subtraction whose
            // obligation is false (x − y needs y ≤ x: true; y − x is false).
            let sub = t(&format!("#sub_u8(y, x; linarith([]; Eq(Bool, #le_u8(x, y), true); [{cert}]))"));
            rejected(env.check(&ctx, &sub, &ev(&env, &tm(&env, "U8")), &mut budget()), Some(KernelErrorKind::Linarith), "false obligation");
        }
    }
    // The true facts are provable from the context (irrelevant facts only in
    // irrelevant positions).
    let ok_sub = t("#sub_u8(x, y; linarith([]; Eq(Bool, #le_u8(y, x), true); []))");
    accepted(env.check(&ctx, &ok_sub, &ev(&env, &tm(&env, "U8")), &mut budget()), "y ≤ x from the context");
    let g = "Eq(Bool, #lt_u8(y, 10u8), true)";
    rejected(
        env.check(&ctx, &t(&format!("linarith([]; {g}; [])")), &goal_v(g), &mut budget()),
        None,
        "irrelevant hx in a relevant linarith",
    );
    // A stated hypothesis must be justified: a well-typed proof of another
    // statement is only accepted if an assumption has the stated type.
    let forged = t("linarith([hy : Eq(Bool, #le_u8(y, 3u8), true)]; Eq(Bool, #lt_u8(y, 4u8), true); [])");
    rejected(
        env.check(&ctx, &forged, &goal_v("Eq(Bool, #lt_u8(y, 4u8), true)"), &mut budget()),
        Some(KernelErrorKind::TypeMismatch),
        "unjustified statement",
    );
    let ill = t("linarith([refl(U8, true) : Eq(Bool, #le_u8(y, x), true)]; Eq(Bool, #le_u8(y, x), true); [])");
    rejected(env.check(&ctx, &ill, &goal_v("Eq(Bool, #le_u8(y, x), true)"), &mut budget()), None, "ill-typed hypothesis proof");
}

#[test]
fn ground_recursion_refinement_never_turns_nontermination_into_success() {
    let mut env = prelude();
    // The inconsistent-precondition definition, now applied to a literal
    // (a ground measure): unfolding still cannot produce a value.
    load(
        &mut env,
        r#"
def[spec] f : (n : U8) -> (.h : Eq(Bool, #lt_u8(n, n), true)) -> Option(U8) :=
  fun (n : U8) (.h : Eq(Bool, #lt_u8(n, n), true)) => Some[U8](match rec(n, .h; h) : Option(U8) as _ return U8 with | None => 0u8 | Some(x) => x end)
  measure (n)
def[spec] g : (n : U8) -> (.h : Eq(Bool, #lt_u8(n, n), true)) -> U8 :=
  fun (n : U8) (.h : Eq(Bool, #lt_u8(n, n), true)) => match #eq_u8(rec(n, .h; h), 0u8) : Bool as _ return U8 with | false => 1u8 | true => 2u8 end
  measure (n)
"#,
    )
    .unwrap();
    for (a, b) in [
        ("fun (.h : Eq(Bool, #lt_u8(3u8, 3u8), true)) => f 3u8 .h", "fun (.h : Eq(Bool, #lt_u8(3u8, 3u8), true)) => Some[U8](0u8)"),
        ("fun (.h : Eq(Bool, #lt_u8(3u8, 3u8), true)) => g 3u8 .h", "fun (.h : Eq(Bool, #lt_u8(3u8, 3u8), true)) => 1u8"),
    ] {
        for transparent in [false, true] {
            let mut bud = Budget { steps: 3_000_000 };
            let e = |s: &str, bud: &mut Budget| {
                if transparent {
                    env.eval_transparent(&VEnv::default(), Lvl(0), &tm(&env, s), bud)
                } else {
                    env.eval(&VEnv::default(), Lvl(0), &tm(&env, s), bud)
                }
            };
            let r = match (e(a, &mut bud), e(b, &mut bud)) {
                (Ok(x), Ok(y)) => env.conv(Lvl(0), &x, &y, &mut bud),
                (Err(err), _) | (_, Err(err)) => Err(err),
            };
            assert_ne!(r, Ok(true), "{a} must never be convertible with {b} (transparent: {transparent})");
        }
    }
}

#[test]
fn eval_memo_distinguishes_environments() {
    use sandblaster_kernel::util::mk;
    let env = prelude();
    // One shared node `z + 1` (Var 0 = the innermost let) evaluated under
    // different let-bound values, in registered and derived environments.
    let sh = mk::prim(PrimOp::WAdd(Width::U32), vec![mk::var(0), mk::lit(Width::U32, 1u8)], vec![]);
    let u32t = || mk::int_ty(Width::U32);
    let tup = |a: Tm, b: Tm| {
        let t2 = env.lookup_ind("Tuple2").unwrap();
        mk::ctor(t2, 0, vec![u32t(), u32t()], vec![a, b])
    };
    let lets = |v: u32, body: Tm| mk::let_("z", Rel::Rel, u32t(), mk::lit(Width::U32, v), body);
    let cases = [
        tup(lets(5, sh.clone()), lets(7, sh.clone())),
        lets(5, tup(sh.clone(), lets(7, sh.clone()))),
        lets(5, tup(lets(7, sh.clone()), sh.clone())),
    ];
    let expect = ["tuple2[U32, U32](6u32, 8u32)", "tuple2[U32, U32](6u32, 8u32)", "tuple2[U32, U32](8u32, 6u32)"];
    for (c, want) in cases.iter().zip(expect) {
        let v = env.eval(&VEnv::default(), Lvl(0), c, &mut budget()).unwrap();
        assert_eq!(env.print_term(&[], &env.quote(Lvl(0), &v, false)), want);
        let v = env.eval_transparent(&VEnv::default(), Lvl(0), c, &mut budget()).unwrap();
        assert_eq!(env.print_term(&[], &env.quote(Lvl(0), &v, false)), want);
    }
    // A shared node under a binder: every instantiation sees its own
    // argument (conversion instantiates both closures).
    let f = mk::lam("z", Rel::Rel, u32t(), tup(sh.clone(), sh.clone()));
    let g = mk::lam(
        "z",
        Rel::Rel,
        u32t(),
        tup(sh.clone(), mk::prim(PrimOp::WAdd(Width::U32), vec![mk::var(0), mk::lit(Width::U32, 2u8)], vec![])),
    );
    let fv = env.eval(&VEnv::default(), Lvl(0), &f, &mut budget()).unwrap();
    let gv = env.eval(&VEnv::default(), Lvl(0), &g, &mut budget()).unwrap();
    assert!(!env.conv(Lvl(0), &fv, &gv, &mut budget()).unwrap());
    assert!(env.conv(Lvl(0), &fv, &fv.clone(), &mut budget()).unwrap());
}
