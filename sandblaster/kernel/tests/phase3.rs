//! Phase-3 kernel fixes (docs/phase2-reports.md open issues):
//!
//! * K1 — match arms are instantiated with the same (array-eta-expanded)
//!   field variables by conversion, the checker and the quoter;
//! * §5.6 — a recursive global applied to closed arguments computes even
//!   when its body inspects its own recursive result;
//! * `abstract_occurrences` abstracts neutral heads, spine prefixes
//!   (scrutinees) and occurrences inside irrelevant proof closures;
//! * `linarith` certificates are hints: a certificate that no longer fits
//!   the kernel's linear system (e.g. after substitution) is replaced by the
//!   kernel's own search, whose result is verified by the same exact check;
//! * checking and conversion are DAG-aware (shared term graphs are not
//!   treated as trees);
//! * `BvRefl` evaluates transparently (opaque definitions and intrinsics
//!   unfold);
//! * `leading_zeros` / `trailing_zeros` bounds (now derived from the K1
//!   definitions, optimizer design §11.4).

mod common;

use std::rc::Rc;

use common::*;
use sandblaster_kernel::api::*;
use sandblaster_kernel::term::*;
use sandblaster_kernel::value::*;

fn ctx_of(env: &Env, vars: &[(&str, &str)]) -> Ctx {
    let mut ctx = Ctx::default();
    let mut names: Vec<&str> = Vec::new();
    for (n, ty) in vars {
        let t = env.parse_term(&names, ty).unwrap_or_else(|e| panic!("{ty}: {e}"));
        let v = env.eval(&env.ctx_venv(&ctx), ctx.depth(), &t, &mut budget()).unwrap();
        ctx = ctx.push(CtxEntry { name: Rc::from(*n), rel: Rel::Rel, ty: v, def: None });
        names.push(n);
    }
    ctx
}

fn names(vars: &[(&str, &str)]) -> Vec<&'static str> {
    vars.iter().map(|(n, _)| &*Box::leak(n.to_string().into_boxed_str())).collect()
}

fn eval_in(env: &Env, ctx: &Ctx, t: &Tm) -> V {
    env.eval(&env.ctx_venv(ctx), ctx.depth(), t, &mut budget()).unwrap()
}

// ---------------------------------------------------------------------------
// K1: match arms binding array fields.
// ---------------------------------------------------------------------------

#[test]
fn k1_quoted_stuck_match_with_array_field_is_convertible() {
    let env = prelude();
    let vars = [("c", "Option(Array U8 4usize)")];
    let ctx = ctx_of(&env, &vars);
    let ns = names(&vars);
    for body in [
        // The arm computes on the array field: `len (fst f)` is 4 once `f` is
        // eta-expanded, a neutral `len` on a plain variable.
        "match c : Option(Array U8 4usize) as _ return Int with | None => 0int | Some(f) => seq::len U8 fst(f) end",
        "match c : Option(Array U8 4usize) as _ return Array U8 4usize with | None => array::repeat U8 4usize 0u8 .refl(Int, 4int) | Some(f) => array::rev U8 4usize f end",
        "match c : Option(Array U8 4usize) as _ return U8 with | None => 0u8 | Some(f) => array::index U8 4usize f 2usize .refl(Bool, true) end",
    ] {
        let t = env.parse_term(&ns, body).unwrap();
        let v = eval_in(&env, &ctx, &t);
        let ty = env.infer(&ctx, &t, &mut budget()).unwrap();
        let q = env.quote_typed(&ctx, &v, Some(&ty), false);
        env.check(&ctx, &q, &ty, &mut budget()).unwrap_or_else(|e| panic!("quoted term re-checks: {e}"));
        let v2 = eval_in(&env, &ctx, &q);
        assert!(env.conv(ctx.depth(), &v, &v2, &mut budget()).unwrap(), "quote/eval round trip is convertible: {body}");
        // And the checker agrees: refl proves the round trip.
        let e = Rc::new(Term::Refl { ty: env.quote(ctx.depth(), &ty, false), val: t.clone() });
        let goal = Value::Eq { ty: ty.clone(), lhs: v.clone(), rhs: v2.clone() };
        env.check(&ctx, &e, &Rc::new(goal), &mut budget()).unwrap_or_else(|e| panic!("{e}"));
    }
}

// ---------------------------------------------------------------------------
// §5.6: recursion that inspects its own recursive result, on closed data.
// ---------------------------------------------------------------------------

const REC_SRC: &str = r#"
def[spec] wrap : (l : List(U32)) -> Option(List(U32)) :=
  fun (l : List(U32)) =>
    match l : List(U32) as _ return Option(List(U32)) with
    | Nil => Some[List(U32)](Nil[U32])
    | Cons(x, t) => match rec(t) : Option(List(U32)) as _ return Option(List(U32)) with
        | None => None[List(U32)]
        | Some(r) => Some[List(U32)](Cons[U32](x, r))
        end
    end
  structural l
def[spec] halve : (l : List(U32)) -> U32 :=
  fun (l : List(U32)) =>
    match l : List(U32) as _ return U32 with
    | Nil => 1000u32
    | Cons(x, t) => #div_u32(rec(t), 2u32; refl(Bool, true))
    end
  structural l
def[spec, opaque] op : (x : U32) -> U32 := fun (x : U32) => #wadd_u32(x, 1u32)
def[spec] mixed : (l : List(U32)) -> U32 :=
  fun (l : List(U32)) =>
    match l : List(U32) as _ return U32 with
    | Nil => 0u32
    | Cons(x, t) => let r : U32 = rec(t);
        if #eq_u32(#wadd_u32(r, op x), 0u32) return U32 then 7u32 else #wadd_u32(r, x)
    end
  structural l
def[spec] sum_to : (i : U32) -> (acc : U32) -> U32 :=
  fun (i : U32) (acc : U32) =>
    if #lt_u32(0u32, i) as .h return U32
    then rec(#sub_u32(i, 1u32; linarith([h : Eq(Bool, #lt_u32(0u32, i), true)]; Eq(Bool, #le_u32(1u32, i), true); [])),
             #wadd_u32(acc, i);
             linarith([h : Eq(Bool, #lt_u32(0u32, i), true)];
               Eq(Bool, #lt_u32(#sub_u32(i, 1u32; linarith([h : Eq(Bool, #lt_u32(0u32, i), true)]; Eq(Bool, #le_u32(1u32, i), true); [])), i), true); []))
    else acc
  measure (i)
"#;

fn list_u32(xs: &[u32]) -> String {
    xs.iter().rev().fold("Nil[U32]".to_string(), |acc, x| format!("Cons[U32]({x}u32, {acc})"))
}

fn norm_mode(env: &Env, src: &str, transparent: bool) -> String {
    let t = tm(env, src);
    let v = if transparent {
        env.eval_transparent(&VEnv::default(), Lvl(0), &t, &mut budget()).unwrap()
    } else {
        env.eval(&VEnv::default(), Lvl(0), &t, &mut budget()).unwrap()
    };
    env.print_term(&[], &env.quote(Lvl(0), &v, false))
}

#[test]
fn recursion_inspecting_its_result_computes_on_closed_data() {
    let mut env = prelude();
    load(&mut env, REC_SRC).unwrap_or_else(|e| panic!("{e}"));
    let l = list_u32(&[1, 2, 3, 4, 5]);
    for transparent in [false, true] {
        // A match on the folded recursive result.
        assert_eq!(norm_mode(&env, &format!("wrap ({l})"), transparent), format!("Some[List(U32)]({l})"));
        // A partial checked primitive on the folded recursive result.
        assert_eq!(norm_mode(&env, &format!("halve ({l})"), transparent), "31u32");
        // Symbolic data stays folded exactly where unfolding gets stuck.
        assert_eq!(
            norm_mode(&env, "fun (t : List(U32)) => halve Cons[U32](1u32, t)", transparent),
            "fun (t : List(U32)) => halve Cons[U32](1u32, t)"
        );
        assert_eq!(
            norm_mode(&env, "fun (x : U32) => wrap Cons[U32](x, Nil[U32])", transparent),
            "fun (x : U32) => Some[List(U32)](Cons[U32](x, Nil[U32]))"
        );
    }
    // Blocked by an opaque call in checking mode: stays folded (opacity is
    // respected); the transparent mode computes it.
    let m = list_u32(&[3, 4]);
    assert_eq!(norm_mode(&env, &format!("mixed ({m})"), false), format!("mixed {m}"));
    assert_eq!(norm_mode(&env, &format!("mixed ({m})"), true), "7u32");
    // Tail recursion on closed data still runs in constant Rust stack.
    assert_eq!(norm_mode(&env, "sum_to 200000u32 0u32", false), format!("{}u32", (200000u64 * 200001 / 2) % (1u64 << 32)));
    // A closed application whose one-level body is a long computation (its
    // speculation exceeds the 2^20-step sub-budget): the transparent mode
    // (optimizer, reference evaluator) computes it; the checking mode keeps
    // it folded, as before.
    load(
        &mut env,
        r#"
def[spec] heavy : (l : List(U32)) -> U32 :=
  fun (l : List(U32)) =>
    match l : List(U32) as _ return U32 with
    | Nil => 0u32
    | Cons(x, t) => #wadd_u32(sum_to 300000u32 x, rec(t))
    end
  structural l
"#,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let expect = (0..=300000u64).sum::<u64>().wrapping_add(1) % (1u64 << 32);
    assert_eq!(norm_mode(&env, "heavy Cons[U32](1u32, Nil[U32])", true), format!("{expect}u32"));
    assert_eq!(norm_mode(&env, "heavy Cons[U32](1u32, Nil[U32])", false), "heavy Cons[U32](1u32, Nil[U32])");
    // And the checker sees the computed value.
    assert!(check(&env, "refl(U32, halve Cons[U32](9u32, Nil[U32]))", "Eq(U32, halve Cons[U32](9u32, Nil[U32]), 500u32)").is_ok());
    assert!(check(&env, &format!("refl(U32, halve ({l}))"), &format!("Eq(U32, halve ({l}), 31u32)")).is_ok());
    assert!(check(&env, &format!("refl(U32, halve ({l}))"), &format!("Eq(U32, halve ({l}), 30u32)")).is_err());
}

// ---------------------------------------------------------------------------
// linarith certificates are hints (stable under substitution).
// ---------------------------------------------------------------------------

/// Every `Linarith` subterm of `t` (pre-order).
fn linariths(t: &Tm, out: &mut Vec<Tm>) {
    if let Term::Linarith { .. } = &**t {
        out.push(t.clone());
    }
    let mut kids: Vec<Tm> = Vec::new();
    match &**t {
        Term::Pi { dom, cod, .. } | Term::Lam { dom, body: cod, .. } => kids.extend([dom.clone(), cod.clone()]),
        Term::App { fun, arg, .. } => kids.extend([fun.clone(), arg.clone()]),
        Term::Let { ty, val, body, .. } => kids.extend([ty.clone(), val.clone(), body.clone()]),
        Term::Prim { args, proofs, .. } => kids.extend(args.iter().chain(proofs).cloned()),
        Term::Linarith { hyps, goal, .. } => {
            kids.extend(hyps.iter().flat_map(|(p, s)| [p.clone(), s.clone()]));
            kids.push(goal.clone());
        }
        _ => {}
    }
    for k in &kids {
        linariths(k, out);
    }
}

#[test]
fn linarith_certificates_survive_substitution() {
    let mut env = prelude();
    // x + 1 ≤ 255 from x < 5: hypothesis, negated goal, x ≥ 0, x ≤ 255 —
    // the positional certificate [1, 1, 0, 0].
    load(
        &mut env,
        r#"
def[spec] inc : (x : U8) -> (.h : Eq(Bool, #lt_u8(x, 5u8), true)) -> U8 :=
  fun (x : U8) (.h : Eq(Bool, #lt_u8(x, 5u8), true)) =>
    #add_u8(x, 1u8; linarith([h : Eq(Bool, #lt_u8(x, 5u8), true)]; Eq(Bool, #le_int(#iadd(#cast_u8_int(x), 1int), 255int), true); [1, 1, 0, 0]))
"#,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    // Instantiate x := z & 3 by evaluation and read the value back: the
    // proof inside is instantiated too, and `z & 3` linearizes through a
    // definitional (q, r) pair, so the constraint list changes.
    let vars = [("z", "U8")];
    let ctx = ctx_of(&env, &vars);
    let ns = names(&vars);
    let t = env
        .parse_term(&ns, "inc #and_u8(z, 3u8) .(linarith([]; Eq(Bool, #lt_u8(#and_u8(z, 3u8), 5u8), true); []))")
        .unwrap_or_else(|e| panic!("{e}"));
    let ty = env.infer(&ctx, &t, &mut budget()).unwrap_or_else(|e| panic!("{e}"));
    let v = eval_in(&env, &ctx, &t);
    let q = env.quote_typed(&ctx, &v, Some(&ty), false);
    let mut ls = Vec::new();
    linariths(&q, &mut ls);
    let l = ls.iter().find(|l| matches!(&***l, Term::Linarith { cert, .. } if cert.len() == 4)).expect("the instantiated certificate");
    let Term::Linarith { hyps, goal, cert } = &**l else { unreachable!() };
    let sys = env.linearize(&ctx, hyps, goal, &mut budget()).unwrap();
    assert!(
        sandblaster_kernel::linarith::check_certificate(&sys, cert).is_err(),
        "the positional certificate no longer fits the instantiated system ({} constraints)",
        sys.problems[0].len()
    );
    // The kernel accepts the instantiated term (its own search refutes the
    // system and the exact check verifies that certificate).
    env.check(&ctx, &q, &ty, &mut budget()).unwrap_or_else(|e| panic!("instantiated term re-checks: {e}"));
    // Substituting a literal (atoms disappear, hypotheses become trivial).
    let t3 = tm(&env, "inc 3u8 .refl(Bool, true)");
    let v3 = ev(&env, &t3);
    assert_eq!(env.print_term(&[], &env.quote(Lvl(0), &v3, false)), "4u8");
    // A false instance stays unprovable whatever the certificate: z & 7 < 5
    // does not follow from nothing.
    let bad = env
        .parse_term(&ns, "inc #and_u8(z, 7u8) .(linarith([]; Eq(Bool, #lt_u8(#and_u8(z, 7u8), 5u8), true); [1, 1, 1, 1, 1, 1, 1, 1]))")
        .unwrap();
    assert_eq!(env.infer(&ctx, &bad, &mut budget()).unwrap_err().kind, KernelErrorKind::Linarith);
}

// ---------------------------------------------------------------------------
// abstract_occurrences: neutral heads, scrutinee prefixes, proofs.
// ---------------------------------------------------------------------------

/// Abstract `target` in `goal` (both core text over `vars`) and print the
/// motive body (the abstraction variable is `y`).
fn abstract_txt(env: &Env, vars: &[(&str, &str)], goal: &str, target: &str, in_proofs: bool) -> (Tm, String) {
    let ctx = ctx_of(env, vars);
    let ns = names(vars);
    let g = eval_in(env, &ctx, &env.parse_term(&ns, goal).unwrap());
    let t = eval_in(env, &ctx, &env.parse_term(&ns, target).unwrap());
    let m = env.abstract_occurrences_ext(&ctx, &g, &t, in_proofs, &mut budget()).unwrap_or_else(|e| panic!("{e}"));
    let mut pn: Vec<Name> = ns.iter().map(|n| Rc::from(*n)).collect();
    pn.push(Rc::from("y"));
    let s = env.print_term(&pn, &m);
    (m, s)
}

#[test]
fn abstraction_reaches_neutral_heads_and_scrutinees() {
    let mut env = prelude();
    load(&mut env, "def[spec, opaque] pick : (x : U8) -> Option(U8) := fun (x : U8) => Some[U8](x)").unwrap();
    // A variable scrutinee (the head of a stuck match).
    let vars = [("c", "Option(U8)")];
    let (_, s) =
        abstract_txt(&env, &vars, "Eq(U8, match c : Option(U8) as _ return U8 with | None => 0u8 | Some(v) => v end, 5u8)", "c", false);
    assert!(s.starts_with("Eq(U8, match y : Option(U8) as") && s.ends_with("end, 5u8)"), "{s}");
    // A neutral global application as the scrutinee.
    let vars = [("x", "U8")];
    let (_, s) = abstract_txt(
        &env,
        &vars,
        "Eq(U8, match pick x : Option(U8) as _ return U8 with | None => 0u8 | Some(v) => v end, x)",
        "pick x",
        false,
    );
    assert!(s.starts_with("Eq(U8, match y : Option(U8) as") && s.ends_with("end, x)"), "{s}");
    // A projection prefix (`fst p` under a match).
    let vars = [("p", "Sigma (a : Option(U8)), U8")];
    let (_, s) = abstract_txt(
        &env,
        &vars,
        "Eq(U8, match fst(p) : Option(U8) as _ return U8 with | None => snd(p) | Some(v) => v end, 1u8)",
        "fst(p)",
        false,
    );
    assert!(s.starts_with("Eq(U8, match y : Option(U8)"), "{s}");
    // The motive is usable: transport along an equation for the scrutinee.
    let vars = [("c", "Option(U8)"), ("e", "Eq(Option(U8), c, Some[U8](5u8))")];
    let ctx = ctx_of(&env, &vars);
    let ns = names(&vars);
    let (m, s) =
        abstract_txt(&env, &vars, "Eq(U8, match c : Option(U8) as _ return U8 with | None => 0u8 | Some(v) => v end, 5u8)", "c", false);
    let _ = m;
    let proof = format!("transport(Option(U8), Some[U8](5u8), c, eq::sym (Option(U8)) c (Some[U8](5u8)) e, y. {s}, refl(U8, 5u8))");
    let goal = eval_in(
        &env,
        &ctx,
        &env.parse_term(&ns, "Eq(U8, match c : Option(U8) as _ return U8 with | None => 0u8 | Some(v) => v end, 5u8)").unwrap(),
    );
    env.check(&ctx, &env.parse_term(&ns, &proof).unwrap_or_else(|e| panic!("{e}")), &goal, &mut budget()).unwrap_or_else(|e| panic!("{e}"));
}

#[test]
fn abstraction_in_proofs_keeps_the_path_equation_consistent() {
    let env = prelude();
    let vars = [("x", "U8")];
    // The dependent-match idiom on the compound scrutinee `x < 5`: its path
    // equation `refl(Bool, x < 5)` sits in an irrelevant closure.
    let goal = "Eq(Bool, if #lt_u8(x, 5u8) as .h return Bool then true else false, true)";
    let target = "#lt_u8(x, 5u8)";
    let ctx = ctx_of(&env, &vars);
    let ctx_y = ctx.push(CtxEntry { name: Rc::from("y"), rel: Rel::Rel, ty: ev(&env, &tm(&env, "Bool")), def: None });
    // Relevant positions only (default): the scrutinee and the equation's
    // type are abstracted but the `refl` argument is not — ill-typed.
    let (m0, _) = abstract_txt(&env, &vars, goal, target, false);
    assert!(env.infer(&ctx_y, &m0, &mut budget()).is_err());
    // Every occurrence, proofs included: `refl(Bool, y)` — well-typed, and
    // a usable transport motive.
    let (m1, s1) = abstract_txt(&env, &vars, goal, target, true);
    assert!(s1.contains("refl(Bool, y)"), "{s1}");
    env.infer(&ctx_y, &m1, &mut budget()).unwrap_or_else(|e| panic!("{s1}: {e}"));
}

fn ctx_rel(env: &Env, vars: &[(&str, Rel, &str)]) -> (Ctx, Vec<&'static str>) {
    let mut ctx = Ctx::default();
    let mut ns: Vec<&'static str> = Vec::new();
    for (n, rel, ty) in vars {
        let t = env.parse_term(&ns, ty).unwrap_or_else(|e| panic!("{ty}: {e}"));
        let v = env.eval(&env.ctx_venv(&ctx), ctx.depth(), &t, &mut budget()).unwrap();
        ctx = ctx.push(CtxEntry { name: Rc::from(*n), rel: *rel, ty: v, def: None });
        ns.push(Box::leak(n.to_string().into_boxed_str()));
    }
    (ctx, ns)
}

#[test]
fn linarith_hypotheses_are_justified_by_proof_or_assumption() {
    let env = prelude();
    let obl = "Eq(Bool, #le_int(#iadd(#cast_u8_int(x), 1int), 255int), true)";
    // The path equation of the `true` branch is in the context (irrelevant);
    // the term carries the `refl` the idiom was applied to, which is not a
    // proof of the stated `x < 5 = true` — the assumption `e` justifies it.
    let (ctx, ns) = ctx_rel(&env, &[("x", Rel::Rel, "U8"), ("e", Rel::Irr, "Eq(Bool, #lt_u8(x, 5u8), true)")]);
    let t = |src: &str| env.parse_term(&ns, src).unwrap_or_else(|e| panic!("{src}: {e}"));
    let u8t = ev(&env, &tm(&env, "U8"));
    let with_refl =
        t(&format!("#add_u8(x, 1u8; linarith([refl(Bool, #lt_u8(x, 5u8)) : Eq(Bool, #lt_u8(x, 5u8), true)]; {obl}; [1, 1, 0, 0]))"));
    env.check(&ctx, &with_refl, &u8t, &mut budget()).unwrap_or_else(|e| panic!("{e}"));
    // No hypotheses at all: the context's facts are offered to the search.
    let bare = t(&format!("#add_u8(x, 1u8; linarith([]; {obl}; []))"));
    env.check(&ctx, &bare, &u8t, &mut budget()).unwrap_or_else(|e| panic!("{e}"));
    // Without the assumption, neither is accepted.
    let (ctx0, ns0) = ctx_rel(&env, &[("x", Rel::Rel, "U8")]);
    let t0 = |src: &str| env.parse_term(&ns0, src).unwrap();
    let with_refl0 =
        t0(&format!("#add_u8(x, 1u8; linarith([refl(Bool, #lt_u8(x, 5u8)) : Eq(Bool, #lt_u8(x, 5u8), true)]; {obl}; [1, 1, 0, 0]))"));
    assert_eq!(env.check(&ctx0, &with_refl0, &u8t, &mut budget()).unwrap_err().kind, KernelErrorKind::TypeMismatch);
    let bare0 = t0(&format!("#add_u8(x, 1u8; linarith([]; {obl}; []))"));
    assert_eq!(env.check(&ctx0, &bare0, &u8t, &mut budget()).unwrap_err().kind, KernelErrorKind::Linarith);
    // An ill-typed proof is still rejected even if the statement holds by
    // an assumption (the proof must be well-typed on its own).
    let ill = t(&format!("#add_u8(x, 1u8; linarith([refl(Bool, 3u8) : Eq(Bool, #lt_u8(x, 5u8), true)]; {obl}; []))"));
    assert!(env.check(&ctx, &ill, &u8t, &mut budget()).is_err());
    // Relevance: an irrelevant assumption is not usable by a linarith term
    // in a relevant position (the goal itself, checked relevantly) ...
    let goal = t(obl);
    let gv = env.eval(&env.ctx_venv(&ctx), ctx.depth(), &goal, &mut budget()).unwrap();
    let rel_bare = t(&format!("linarith([]; {obl}; [])"));
    assert_eq!(env.check(&ctx, &rel_bare, &gv, &mut budget()).unwrap_err().kind, KernelErrorKind::Linarith);
    let rel_refl = t(&format!("linarith([refl(Bool, #lt_u8(x, 5u8)) : Eq(Bool, #lt_u8(x, 5u8), true)]; {obl}; [1, 1, 0, 0])"));
    assert!(env.check(&ctx, &rel_refl, &gv, &mut budget()).is_err());
    // ... but a relevant one is.
    let (ctx_r, ns_r) = ctx_rel(&env, &[("x", Rel::Rel, "U8"), ("e", Rel::Rel, "Eq(Bool, #lt_u8(x, 5u8), true)")]);
    let tr = env.parse_term(&ns_r, &format!("linarith([]; {obl}; [])")).unwrap();
    env.check(&ctx_r, &tr, &gv, &mut budget()).unwrap_or_else(|e| panic!("{e}"));
    // A false goal stays unprovable with every fact of the context.
    let false_goal = t("Eq(Bool, #lt_u8(x, 4u8), true)");
    let fv = env.eval(&env.ctx_venv(&ctx), ctx.depth(), &false_goal, &mut budget()).unwrap();
    let f = env.parse_term(&ns_r, "linarith([]; Eq(Bool, #lt_u8(x, 4u8), true); [])").unwrap();
    assert_eq!(env.check(&ctx_r, &f, &fv, &mut budget()).unwrap_err().kind, KernelErrorKind::Linarith);
}

// ---------------------------------------------------------------------------
// DAG-aware checking, evaluation and conversion.
// ---------------------------------------------------------------------------

/// `t_0 = x`, `t_{k+1} = op(t_k, t_k)` with every level shared (a DAG of
/// `depth + 1` nodes whose tree unfolding has `2^depth` leaves), under
/// `fun (x : U32) => ..`.
fn shared_chain(depth: usize, op: PrimOp) -> Tm {
    let mut t: Tm = Rc::new(Term::Var(Idx(0)));
    for _ in 0..depth {
        t = Rc::new(Term::Prim { op, args: vec![t.clone(), t.clone()], proofs: vec![] });
    }
    sandblaster_kernel::util::mk::lam("x", Rel::Rel, sandblaster_kernel::util::mk::int_ty(Width::U32), t)
}

fn dag_timings(depth: usize) -> std::time::Duration {
    let env = prelude();
    let f = shared_chain(depth, PrimOp::WAdd(Width::U32));
    let g = shared_chain(depth, PrimOp::WAdd(Width::U32));
    let ty = ev(&env, &tm(&env, "U32 -> U32"));
    let start = std::time::Instant::now();
    // Type checking.
    env.check(&Ctx::default(), &f, &ty, &mut budget()).unwrap_or_else(|e| panic!("{e}"));
    let t1 = start.elapsed();
    // Evaluation and conversion of two separately built copies.
    let fv = ev(&env, &f);
    let gv = ev(&env, &g);
    let t2 = start.elapsed();
    assert!(env.conv(Lvl(0), &fv, &gv, &mut budget()).unwrap());
    let t3 = start.elapsed();
    if std::env::var("DAG_VERBOSE").is_ok() {
        eprintln!("  check {t1:?} eval {:?} conv {:?}", t2 - t1, t3 - t2);
    }
    // A proof about the shared term: refl at its own type.
    let body = match &*f {
        Term::Lam { body, .. } => body.clone(),
        _ => unreachable!(),
    };
    let e = sandblaster_kernel::util::mk::lam(
        "x",
        Rel::Rel,
        sandblaster_kernel::util::mk::int_ty(Width::U32),
        Rc::new(Term::Refl { ty: sandblaster_kernel::util::mk::int_ty(Width::U32), val: body.clone() }),
    );
    let ety = Rc::new(Term::Pi {
        name: Rc::from("x"),
        rel: Rel::Rel,
        dom: sandblaster_kernel::util::mk::int_ty(Width::U32),
        cod: Rc::new(Term::Eq { ty: sandblaster_kernel::util::mk::int_ty(Width::U32), lhs: body.clone(), rhs: body }),
    });
    env.check(&Ctx::default(), &ety, &ev(&env, &tm(&env, "Type")), &mut budget()).unwrap_or_else(|e| panic!("{e}"));
    let etyv = ev(&env, &ety);
    env.check(&Ctx::default(), &e, &etyv, &mut budget()).unwrap_or_else(|e| panic!("{e}"));
    start.elapsed()
}

#[test]
#[ignore]
fn dag_measure() {
    for d in [12, 14, 16, 18] {
        eprintln!("depth {d}: {:?}", dag_timings(d));
    }
}

/// The shared chain over an arbitrary leaf term (no λ).
fn chain_over(leaf: Tm, depth: usize, op: PrimOp) -> Tm {
    let mut t = leaf;
    for _ in 0..depth {
        t = Rc::new(Term::Prim { op, args: vec![t.clone(), t.clone()], proofs: vec![] });
    }
    t
}

#[test]
fn shared_term_graphs_in_definitions_proofs_and_round_trips() {
    use sandblaster_kernel::util::mk;
    let mut env = prelude();
    let u32t = || mk::int_ty(Width::U32);
    let depth = 64;
    let start = std::time::Instant::now();
    // A structurally recursive definition whose body contains a shared DAG
    // (structural check, typing, commit's `rec` replacement).
    let list = env.lookup_ind("List").unwrap();
    let lty = mk::ind(list, vec![u32t()]);
    let body = mk::lam(
        "l",
        Rel::Rel,
        lty.clone(),
        Rc::new(Term::Match {
            ind: list,
            params: vec![u32t()],
            scrut: mk::var(0),
            motive: u32t(),
            arms: vec![
                mk::arm(&[], mk::lit(Width::U32, 0u8)),
                mk::arm(
                    &["h", "t"],
                    mk::prim(
                        PrimOp::WAdd(Width::U32),
                        vec![
                            chain_over(mk::var(1), depth, PrimOp::Xor(Width::U32)),
                            Rc::new(Term::Rec { args: vec![mk::var(0)], proof: None }),
                        ],
                        vec![],
                    ),
                ),
            ],
        }),
    );
    let d = DefDecl {
        name: Rc::from("dag_sum"),
        kind: DefKind::Spec,
        ty: mk::arrow(lty, u32t()),
        body,
        recursion: Recursion::Structural { param: 0 },
        arity: 1,
        opaque: false,
    };
    env.add_def(d, &mut budget()).unwrap_or_else(|e| panic!("{e}"));
    // (Unfolding evaluates the DAG-shaped body with a scoped memo.)
    assert_eq!(norm(&env, "dag_sum Cons[U32](5u32, Cons[U32](6u32, Nil[U32]))"), "0u32");
    // α-equivalence of two separately built copies (round trip).
    let a = chain_over(mk::var(0), depth, PrimOp::WAdd(Width::U32));
    let b = chain_over(mk::var(0), depth, PrimOp::WAdd(Width::U32));
    assert!(env.alpha_eq_relevant(&a, &b, &|x, y| x == y));
    let c = chain_over(mk::var(0), depth, PrimOp::WSub(Width::U32));
    assert!(!env.alpha_eq_relevant(&a, &c, &|x, y| x == y));
    // A linear-arithmetic proof whose statements contain the DAG.
    let vars = [("x", "U32")];
    let ctx = ctx_of(&env, &vars);
    let bool_t = mk::bool_ty(env.bool_ind());
    let le10 = |t: Tm| mk::eq_bool(env.bool_ind(), mk::prim(PrimOp::Le(Width::U32), vec![t, mk::lit(Width::U32, 10u8)], vec![]), true);
    let _ = bool_t;
    let hyp_ty = le10(a.clone());
    let goal = le10(b.clone());
    let pf = mk::lam(
        "h",
        Rel::Rel,
        hyp_ty.clone(),
        Rc::new(Term::Linarith { hyps: vec![(mk::var(0), shift1(&hyp_ty))], goal: shift1(&goal), cert: vec![] }),
    );
    let pty = Rc::new(Term::Pi { name: Rc::from("h"), rel: Rel::Rel, dom: hyp_ty, cod: shift1(&goal) });
    let ptyv = eval_in(&env, &ctx, &pty);
    env.check(&ctx, &pf, &ptyv, &mut budget()).unwrap_or_else(|e| panic!("{e}"));
    // bvrefl between two copies (conversion prefilter, DAG evaluation).
    let bv = Rc::new(Term::BvRefl { ty: u32t(), lhs: a.clone(), rhs: b.clone() });
    let bvty = eval_in(&env, &ctx, &mk::eq(u32t(), a.clone(), b.clone()));
    env.check(&ctx, &bv, &bvty, &mut budget()).unwrap_or_else(|e| panic!("{e}"));
    eprintln!("shared DAGs in definitions/proofs/round trips (depth {depth}): {:?}", start.elapsed());
}

fn shift1(t: &Tm) -> Tm {
    sandblaster_kernel::util::shift(t, 1)
}

#[test]
fn shared_term_graphs_are_not_treated_as_trees() {
    // Depth 64: the tree unfolding has 2^64 leaves, so any tree traversal
    // would not terminate within the budget.
    let t = dag_timings(64);
    eprintln!("shared chain, depth 64: {t:?}");
    // A deep chain needs a deep Rust stack (the kernel is recursive).
    let t = big_stack(|| dag_timings(2000));
    eprintln!("shared chain, depth 2000: {t:?}");
}

// ---------------------------------------------------------------------------
// BvRefl proves hardware-variant equivalence (DESIGN.md §9.3) against an
// opaque, loop-based portable function (core-text shapes of the elaborated
// `compress` / `compress_sha2` of the former QMDB fixture, removed 2026-10-05).
// ---------------------------------------------------------------------------

const AARCH64_CORE: &str = include_str!("../../targets/core/aarch64.core");
const VARIANT_EQUIV: &str = include_str!("variant_equiv.core");

fn variant_env() -> Env {
    let mut env = prelude();
    load(&mut env, AARCH64_CORE).unwrap_or_else(|e| panic!("aarch64.core: {e}"));
    load(&mut env, VARIANT_EQUIV).unwrap_or_else(|e| panic!("variant_equiv.core: {e}"));
    env
}

fn variant_goal(variant: &str, proof: &str) -> (String, String) {
    let ty = format!(
        "(state : Array U32 8usize) -> (block : Array U8 64usize) -> Eq(Array U32 8usize, {variant} state block, ve::compress state block)"
    );
    let t = format!(
        "fun (state : Array U32 8usize) (block : Array U8 64usize) => {proof}(Array U32 8usize, {variant} state block, ve::compress state block)"
    );
    (t, ty)
}

#[test]
fn variant_equiv_compress_sha2_by_bvrefl() {
    big_stack(|| {
        let env = variant_env();
        // The shapes: the portable side is opaque (and so are its loops).
        for g in ["ve::compress", "ve::compress::loop0", "ve::compress::loop1", "ve::compress::loop2"] {
            assert_eq!(env.global_opaque(env.lookup_global(g).unwrap()), Some(true), "{g}");
        }
        // Both compute SHA-256("abc") on the padded block (transparent
        // evaluation; the first state word is 0xba7816bf).
        let mut block = [0u8; 64];
        block[..3].copy_from_slice(b"abc");
        block[3] = 0x80;
        block[63] = 24;
        let blk = format!(
            "pair(Array U8 64usize, {}, refl(Int, 64int))",
            block.iter().rev().fold("Nil[U8]".to_string(), |acc, b| format!("Cons[U8]({b}u8, {acc})"))
        );
        let init = [0x6a09e667u32, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
        let st = format!(
            "pair(Array U32 8usize, {}, refl(Int, 8int))",
            init.iter().rev().fold("Nil[U32]".to_string(), |acc, w| format!("Cons[U32]({w}u32, {acc})"))
        );
        for f in ["ve::compress", "ve::compress_sha2"] {
            let s = norm_mode(&env, &format!("array::index U32 8usize ({f} ({st}) ({blk})) 0usize .refl(Bool, true)"), true);
            assert_eq!(s, format!("{}u32", 0xba7816bfu32), "{f}");
        }
        // Conversion (checking mode) cannot see through the opaque loops ...
        let (t, ty) = variant_goal("ve::compress_sha2", "refl");
        let t = t.replace(
            "refl(Array U32 8usize, ve::compress_sha2 state block, ve::compress state block)",
            "refl(Array U32 8usize, ve::compress_sha2 state block)",
        );
        assert!(check(&env, &t, &ty).is_err(), "refl must not prove the variant equal (opacity)");
        // ... BvRefl evaluates transparently and proves VariantEquiv.
        let (t, ty) = variant_goal("ve::compress_sha2", "bvrefl");
        let start = std::time::Instant::now();
        check(&env, &t, &ty).unwrap_or_else(|e| panic!("VariantEquiv by bvrefl: {e}"));
        eprintln!("VariantEquiv(compress_sha2, compress) by bvrefl: {:?}", start.elapsed());
        // Wrong variants are rejected.
        for bad in ["ve::compress_sha2_bad_k", "ve::compress_sha2_bad_h2"] {
            let (t, ty) = variant_goal(bad, "bvrefl");
            let e = check(&env, &t, &ty).expect_err(bad);
            assert_eq!(e.kind, KernelErrorKind::BvRefl, "{bad}: {e}");
        }
    });
}

// ---------------------------------------------------------------------------
// leading_zeros / trailing_zeros bounds, derived from the K1 definitions
// (the phase-3 bound axioms are retired; optimizer design §11.4).
// ---------------------------------------------------------------------------

/// `[b] ≤ 1` and `b = false → [b] = 0` for the indicator `[b]` of the K1
/// statements (checked lemmas).
const IND_LEMMAS: &str = "
def[lemma] ind_le_one : (b : Bool) -> Eq(Bool, #le_int(match b : Bool as _ return Int with | false => 0int | true => 1int end, 1int), true) :=
  fun (b : Bool) =>
    match b : Bool as y return Eq(Bool, #le_int(match y : Bool as _ return Int with | false => 0int | true => 1int end, 1int), true) with
    | false => refl(Bool, true)
    | true => refl(Bool, true)
    end

def[lemma] ind_false : (b : Bool) -> (.h : Eq(Bool, b, false)) -> Eq(Int, match b : Bool as _ return Int with | false => 0int | true => 1int end, 0int) :=
  fun (b : Bool) (.h : Eq(Bool, b, false)) =>
    transport(Bool, false, b, eq::sym Bool b false h, y. Eq(Int, match y : Bool as _ return Int with | false => 0int | true => 1int end, 0int), refl(Int, 0int))
";

#[test]
fn bit_count_definitions_discharge_bit_length_obligations() {
    let mut env = prelude();
    env.load_core(IND_LEMMAS, &mut budget()).unwrap_or_else(|e| panic!("{e}"));
    let env = env;
    let u32t = ev(&env, &tm(&env, "U32"));
    // `stated` hypothesis text `proof : type` (the type inferred and printed).
    let hyp = |ctx: &Ctx, ns: &[&str], src: &str| -> String {
        let p = env.parse_term(ns, src).unwrap_or_else(|e| panic!("{src}: {e}"));
        let ty = env.infer(ctx, &p, &mut budget()).unwrap_or_else(|e| panic!("{src}: {e}"));
        let names: Vec<Name> = ns.iter().map(|n| Rc::from(*n)).collect();
        format!("{src} : {}", env.print_term(&names, &env.quote_typed(ctx, &ty, None, false)))
    };
    // `64 - x.leading_zeros()` (the bit length) needs `lz(x) ≤ 64`: the
    // definition sums 64 indicators, each at most 1.
    let (ctx, ns) = ctx_rel(&env, &[("x", Rel::Rel, "U64")]);
    let t = |s: &str| env.parse_term(&ns, s).unwrap_or_else(|e| panic!("{s}: {e}"));
    let mut hs = vec![hyp(&ctx, &ns, "axiom[leading_zeros_def_u64](x)")];
    hs.extend((0..64).map(|m| hyp(&ctx, &ns, &format!("ind_le_one #lt_u64(x, {}u64)", 1u128 << m))));
    let bitlen = t(&format!(
        "#sub_u32(64u32, #leading_zeros_u64(x); linarith([{}]; Eq(Bool, #le_u32(#leading_zeros_u64(x), 64u32), true); []))",
        hs.join(", ")
    ));
    env.check(&ctx, &bitlen, &u32t, &mut budget()).unwrap_or_else(|e| panic!("{e}"));
    // Without the definition the obligation is not linear-provable.
    let bare = t("#sub_u32(64u32, #leading_zeros_u64(x); linarith([]; Eq(Bool, #le_u32(#leading_zeros_u64(x), 64u32), true); []))");
    assert!(env.check(&ctx, &bare, &u32t, &mut budget()).is_err());
    // `63 - x.trailing_zeros()` needs x ≠ 0: the last indicator,
    // `[x & (2^64 − 1) = 0]`, is 0.
    let (ctx2, ns2) = ctx_rel(&env, &[("x", Rel::Rel, "U64"), ("h", Rel::Irr, "Eq(Bool, #lt_u64(0u64, x), true)")]);
    let t2 = |s: &str| env.parse_term(&ns2, s).unwrap_or_else(|e| panic!("{s}: {e}"));
    let mut hs = vec![hyp(&ctx2, &ns2, "axiom[trailing_zeros_def_u64](x)")];
    hs.extend((1..64).map(|m| hyp(&ctx2, &ns2, &format!("ind_le_one #eq_u64(#and_u64(x, {}u64), 0u64)", (1u128 << m) - 1))));
    let all = u64::MAX;
    let last = format!("#eq_u64(#and_u64(x, {all}u64), 0u64)");
    hs.push(hyp(&ctx2, &ns2, &format!("ind_false {last} .linarith([h : Eq(Bool, #lt_u64(0u64, x), true)]; Eq(Bool, {last}, false); [])")));
    let top = |hs: &[String]| {
        format!(
            "#sub_u32(63u32, #trailing_zeros_u64(x); linarith([{}]; Eq(Bool, #le_u32(#trailing_zeros_u64(x), 63u32), true); []))",
            hs.join(", ")
        )
    };
    env.check(&ctx2, &t2(&top(&hs)), &u32t, &mut budget()).unwrap_or_else(|e| panic!("{e}"));
    // Without the last indicator (the one that needs x ≠ 0) it fails.
    assert!(env.check(&ctx2, &t2(&top(&hs[..hs.len() - 1])), &u32t, &mut budget()).is_err());
    // The retired bound axioms are gone.
    assert!(env.parse_term(&ns, "axiom[leading_zeros_le_u64](x)").is_err());
    assert!(env.parse_term(&ns2, "axiom[trailing_zeros_lt_u64](x, .h)").is_err());
}
