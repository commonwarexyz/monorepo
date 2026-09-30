//! Linear arithmetic certificates (DESIGN.md §5.8): linearization, canonical
//! constraint order, accepted forms, definitional atoms, and exact
//! certificate checking. Certificates are found by the reference
//! Fourier–Motzkin search in `tests/common` (tests only).

mod common;

use std::rc::Rc;

use common::*;
use num_bigint::BigInt;
use sandblaster_kernel::api::*;
use sandblaster_kernel::linarith::{ConstraintKind, ConstraintOrigin};
use sandblaster_kernel::term::*;

/// A context of variables with the given names and types (core text).
fn ctx(env: &Env, vars: &[(&str, &str)]) -> (Ctx, Vec<&'static str>) {
    let mut c = Ctx::default();
    let mut names: Vec<&'static str> = Vec::new();
    for (n, t) in vars {
        let ty = env.parse_term(&names, t).unwrap();
        let tyv = env.eval(&env.ctx_venv(&c), c.depth(), &ty, &mut budget()).unwrap();
        let rel = if n.starts_with('.') { Rel::Irr } else { Rel::Rel };
        let name: &'static str = Box::leak(n.trim_start_matches('.').to_string().into_boxed_str());
        c = c.push(CtxEntry { name: Rc::from(name), rel, ty: tyv, def: None });
        names.push(name);
    }
    (c, names)
}

/// Prove `goal` from hypothesis variables (names) with the reference search
/// and check the resulting term with the kernel.
fn prove(env: &Env, vars: &[(&str, &str)], hyps: &[&str], goal: &str) -> Result<(), String> {
    let (c, names) = ctx(env, vars);
    let mut hs = Vec::new();
    for h in hyps {
        let p = env.parse_term(&names, h).unwrap();
        let ty = env.infer(&c, &p, &mut budget()).map_err(|e| e.to_string())?;
        let stated = env.quote_typed(&c, &ty, None, false);
        hs.push((p, stated));
    }
    let g = env.parse_term(&names, goal).unwrap();
    let Some(t) = auto_linarith(env, &c, hs, g.clone()) else { return Err("no certificate".into()) };
    let gv = env.eval(&env.ctx_venv(&c), c.depth(), &g, &mut budget()).unwrap();
    env.check(&c, &t, &gv, &mut budget()).map_err(|e| e.to_string())
}

#[test]
fn canonical_order() {
    let env = prelude();
    let (c, names) = ctx(&env, &[("x", "U8"), ("y", "U8"), ("h", "Eq(Bool, #lt_u8(x, y), true)")]);
    let hyps = vec![(env.parse_term(&names, "h").unwrap(), env.parse_term(&names, "Eq(Bool, #lt_u8(x, y), true)").unwrap())];
    let goal = env.parse_term(&names, "Eq(Bool, #le_u8(x, y), true)").unwrap();
    let sys = env.linearize(&c, &hyps, &goal, &mut budget()).unwrap();
    assert_eq!(sys.atoms.len(), 2);
    assert_eq!(env.print_term(&[Rc::from("x"), Rc::from("y"), Rc::from("h")], &sys.atoms[0]), "x");
    let p = &sys.problems[0];
    assert_eq!(sys.problems.len(), 1);
    // hyp: x − y + 1 ≤ 0; negated goal: y − x + 1 ≤ 0; bounds of x, then y.
    assert_eq!(p[0].origin, ConstraintOrigin::Hyp(0));
    assert_eq!(p[0].coeffs, vec![(0, BigInt::from(1)), (1, BigInt::from(-1))]);
    assert_eq!(p[0].constant, BigInt::from(1));
    assert_eq!(p[1].origin, ConstraintOrigin::NegatedGoal);
    assert_eq!(p[1].coeffs, vec![(0, BigInt::from(-1)), (1, BigInt::from(1))]);
    assert_eq!(p[1].constant, BigInt::from(1));
    assert_eq!(p[2].origin, ConstraintOrigin::AtomBound(0));
    assert_eq!(p[3].origin, ConstraintOrigin::AtomBound(0));
    assert_eq!(p[3].constant, BigInt::from(-255));
    assert_eq!(p[4].origin, ConstraintOrigin::AtomBound(1));
    assert_eq!(p.len(), 6);
    // Equality goals produce two problems.
    let goal = env.parse_term(&names, "Eq(U8, x, y)").unwrap();
    let sys = env.linearize(&c, &hyps, &goal, &mut budget()).unwrap();
    assert_eq!(sys.problems.len(), 2);
    // An Empty goal has no negated-goal constraint.
    let goal = env.parse_term(&names, "Empty").unwrap();
    let sys = env.linearize(&c, &hyps, &goal, &mut budget()).unwrap();
    assert!(sys.problems[0].iter().all(|c| c.origin != ConstraintOrigin::NegatedGoal));
    assert_eq!(sys.problems[0][0].kind, ConstraintKind::Le0);
}

#[test]
fn hypothesis_and_goal_forms() {
    let env = prelude();
    let v = [("x", "U32"), ("y", "U32")];
    // ne … true goal (negation is an equality) and eq … false goal.
    assert!(prove(&env, &[("x", "U32"), ("h", "Eq(Bool, #lt_u32(x, 10u32), true)")], &["h"], "Eq(Bool, #ne_u32(x, 10u32), true)").is_ok());
    assert!(prove(&env, &[("x", "U32"), ("h", "Eq(Bool, #lt_u32(x, 10u32), true)")], &["h"], "Eq(Bool, #eq_u32(x, 10u32), false)").is_ok());
    // Every comparison as a hypothesis.
    for (h, g) in [
        ("Eq(Bool, #gt_u32(x, y), true)", "Eq(Bool, #le_u32(y, x), true)"),
        ("Eq(Bool, #ge_u32(x, y), false)", "Eq(Bool, #lt_u32(x, y), true)"),
        ("Eq(Bool, #le_u32(x, y), false)", "Eq(Bool, #gt_u32(x, y), true)"),
        ("Eq(Bool, #eq_u32(x, y), true)", "Eq(U32, x, y)"),
        ("Eq(Bool, #ne_u32(x, y), false)", "Eq(Bool, #ge_u32(x, y), true)"),
        ("Eq(U32, x, y)", "Eq(Bool, #le_u32(x, y), true)"),
    ] {
        let mut vars = v.to_vec();
        vars.push(("h", h));
        prove(&env, &vars, &["h"], g).unwrap_or_else(|e| panic!("{h} ⊢ {g}: {e}"));
    }
    // Disjunctive hypotheses are rejected.
    let (c, names) = ctx(&env, &[("x", "U32"), ("h", "Eq(Bool, #ne_u32(x, 3u32), true)")]);
    let hyps = vec![(env.parse_term(&names, "h").unwrap(), env.parse_term(&names, "Eq(Bool, #ne_u32(x, 3u32), true)").unwrap())];
    let goal = env.parse_term(&names, "Empty").unwrap();
    assert_eq!(env.linearize(&c, &hyps, &goal, &mut budget()).unwrap_err().kind, KernelErrorKind::Linarith);
}

#[test]
fn definitional_atoms() {
    let env = prelude();
    let x = [("x", "U64")];
    for goal in [
        // rem/div by a literal (QMDB: `location % 8 < 32` for a shift width).
        "Eq(Bool, #lt_u64(#rem_u64(x, 8u64; refl(Bool, true)), 8u64), true)",
        "Eq(Bool, #le_u64(#div_u64(x, 3u64; refl(Bool, true)), x), true)",
        // shifts by literals, masks, truncation.
        "Eq(Bool, #le_u64(#wshr_u64(x, 3u32), x), true)",
        "Eq(Bool, #le_u64(#and_u64(x, 255u64), 255u64), true)",
        "Eq(Bool, #le_u64(#and_u64(15u64, x), x), true)",
        "Eq(Bool, #le_int(#cast_u8_int(#cast_u64_u8(x)), #cast_u64_int(x)), true)",
        "Eq(Bool, #le_u64(#wshl_u64(x, 4u32), 18446744073709551615u64), true)",
        // wrapping add: the carry is 0 or 1.
        "Eq(Bool, #le_int(#cast_u64_int(#wadd_u64(x, 1u64)), #iadd(#cast_u64_int(x), 1int)), true)",
        "Eq(Bool, #le_int(#cast_u64_int(x), #iadd(#cast_u64_int(#wsub_u64(x, 5u64)), 5int)), true)",
    ] {
        prove(&env, &x, &[], goal).unwrap_or_else(|e| panic!("{goal}: {e}"));
    }
    // Shared (q, r) pair: div and rem of the same value.
    prove(&env, &x, &[], "Eq(Int, #iadd(#imul(#cast_u64_int(#div_u64(x, 8u64; refl(Bool, true))), 8int), #cast_u64_int(#rem_u64(x, 8u64; refl(Bool, true)))), #cast_u64_int(x))").unwrap();
    // wshr and and-mask share the pair too.
    prove(
        &env,
        &x,
        &[],
        "Eq(Int, #iadd(#imul(#cast_u64_int(#wshr_u64(x, 3u32)), 8int), #cast_u64_int(#and_u64(x, 7u64))), #cast_u64_int(x))",
    )
    .unwrap();
    // Checked ops are exact; equal-width casts are transparent.
    prove(
        &env,
        &[("x", "U64"), ("h", "Eq(Bool, #lt_u64(x, 100u64), true)")],
        &["h"],
        "Eq(Usize, #cast_u64_usize(#add_u64(x, 1u64; refl(Bool, true))), #add_usize(#cast_u64_usize(x), 1usize; refl(Bool, true)))",
    )
    .ok();
    prove(
        &env,
        &[("x", "U64"), ("h", "Eq(Bool, #lt_u64(x, 100u64), true)")],
        &["h"],
        "Eq(Bool, #lt_usize(#cast_u64_usize(x), 100usize), true)",
    )
    .unwrap();
    // seq::len atoms are nonnegative.
    prove(&env, &[("l", "List(U8)")], &[], "Eq(Bool, #le_int(0int, seq::len U8 l), true)").unwrap();
    // False claims have no certificate.
    for goal in [
        "Eq(Bool, #lt_u64(#rem_u64(x, 8u64; refl(Bool, true)), 7u64), true)",
        "Eq(Bool, #le_u64(x, #wshr_u64(x, 1u32)), true)",
        "Eq(Int, #cast_u64_int(#wadd_u64(x, 1u64)), #iadd(#cast_u64_int(x), 1int))",
        "Eq(Int, #cast_u64_int(#wshl_u64(x, 1u32)), #imul(#cast_u64_int(x), 2int))",
    ] {
        assert!(prove(&env, &x, &[], goal).is_err(), "`{goal}` must not be provable");
    }
}

#[test]
fn stated_props_must_match_proof_types() {
    let env = prelude();
    let (c, names) = ctx(&env, &[("x", "U8"), ("h", "Eq(Bool, #lt_u8(x, 5u8), true)")]);
    // The stated form claims x < 3 but the proof proves x < 5.
    let t = env.parse_term(&names, "linarith([h : Eq(Bool, #lt_u8(x, 3u8), true)]; Eq(Bool, #lt_u8(x, 4u8), true); [1, 1, 0, 0])").unwrap();
    let g =
        env.eval(&env.ctx_venv(&c), c.depth(), &env.parse_term(&names, "Eq(Bool, #lt_u8(x, 4u8), true)").unwrap(), &mut budget()).unwrap();
    assert_eq!(env.check(&c, &t, &g, &mut budget()).unwrap_err().kind, KernelErrorKind::TypeMismatch);
}

#[test]
fn certificates_are_checked_exactly() {
    let env = prelude();
    let (c, names) = ctx(&env, &[("x", "U8"), ("h", "Eq(Bool, #lt_u8(x, 5u8), true)")]);
    let goal = "Eq(Bool, #lt_u8(x, 6u8), true)";
    let g = env.eval(&env.ctx_venv(&c), c.depth(), &env.parse_term(&names, goal).unwrap(), &mut budget()).unwrap();
    let chk = |cert: &str| {
        env.check(
            &c,
            &env.parse_term(&names, &format!("linarith([h : Eq(Bool, #lt_u8(x, 5u8), true)]; {goal}; [{cert}])")).unwrap(),
            &g,
            &mut budget(),
        )
    };
    assert!(chk("1, 1, 0, 0").is_ok());
    assert!(chk("2, 2, 0, 0").is_ok());
    assert!(chk("1/3, 1/3, 0, 0").is_ok());
    // The exact check itself (the trusted part of the rule).
    let sys = env
        .linearize(
            &c,
            &[(env.parse_term(&names, "h").unwrap(), env.parse_term(&names, "Eq(Bool, #lt_u8(x, 5u8), true)").unwrap())],
            &env.parse_term(&names, goal).unwrap(),
            &mut budget(),
        )
        .unwrap();
    let rats = |s: &str| -> Vec<Rat> {
        s.split(", ")
            .map(|x| match x.split_once('/') {
                Some((n, d)) => Rat { num: n.parse().unwrap(), den: d.parse().unwrap() },
                None => Rat { num: x.parse().unwrap(), den: 1.into() },
            })
            .collect()
    };
    assert!(sandblaster_kernel::linarith::check_certificate(&sys, &rats("1, 1, 0, 0")).is_ok());
    for bad in [vec![Rat { num: 1.into(), den: (-1).into() }; 4], vec![Rat { num: 1.into(), den: 0.into() }; 4]] {
        assert!(sandblaster_kernel::linarith::check_certificate(&sys, &bad).is_err(), "nonpositive denominator");
    }
    for bad in ["1, 1, 0", "1, 1, 0, 0, 0", "0, 0, 0, 0", "1, 0, 0, 0", "-1, -1, 0, 0", "1, 1, 0, -1", "1, 2, 0, 0"] {
        assert!(sandblaster_kernel::linarith::check_certificate(&sys, &rats(bad)).is_err(), "cert [{bad}]");
        // The rule treats a certificate as a hint: a true goal is accepted
        // with a wrong certificate (the kernel's search finds one and
        // verifies it with the same exact check) ...
        assert!(chk(bad).is_ok(), "cert [{bad}] (hint)");
    }
    // ... and a false goal is rejected whatever the certificate.
    let false_goal = "Eq(Bool, #lt_u8(x, 4u8), true)";
    let gf = env.eval(&env.ctx_venv(&c), c.depth(), &env.parse_term(&names, false_goal).unwrap(), &mut budget()).unwrap();
    for cert in ["1, 1, 0, 0", "", "1, 1, 0, 0, 0", "7/2, 1, 1, 1"] {
        let t = env.parse_term(&names, &format!("linarith([h : Eq(Bool, #lt_u8(x, 5u8), true)]; {false_goal}; [{cert}])")).unwrap();
        assert_eq!(env.check(&c, &t, &gf, &mut budget()).unwrap_err().kind, KernelErrorKind::Linarith, "false goal, cert [{cert}]");
    }
}
