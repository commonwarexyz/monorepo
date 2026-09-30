//! Definitions, recursion and termination (DESIGN.md §5.6).
//!
//! `add_def`:
//! 1. `ty` must be a type whose first `arity` binders are syntactic Π's (the
//!    parameter telescope); the result type `R` under them has a sort, used
//!    by `Delta` (`R : Type`) and `Unfold` (`R = Type`).
//! 2. The body is checked against `ty` with the definition registered as
//!    *pending*: `Rec` is a neutral that can never unfold, `Global(self)` is
//!    rejected (no self-reference, so no mutual recursion either).
//! 3. Termination:
//!    * `Recursion::None`: `Rec` is rejected by the checker.
//!    * `Recursion::Structural { param }`: `param` must have a recursive
//!      inductive type, and every `Rec` (in any position, including
//!      irrelevant ones) must pass at `param` a variable bound as a recursive
//!      field of a match whose scrutinee is the parameter variable or
//!      (transitively) such a field variable ([`structural_check`]).
//!    * `Recursion::Measure { measure }`: the measure (over the telescope)
//!      must have type `Int` or a machine width; every `Rec` carries a proof
//!      of the §5.6 decrease obligation, checked by the checker in the
//!      call-site context.
//! 4. Commit: every `Rec(args)` in the body is replaced by `g args`
//!    (relevances from the telescope), so evaluation of committed bodies
//!    unfolds `g` through the ordinary §5.6 policy.

use std::rc::Rc;

use crate::api::{Env, KernelErrorKind as K};
use crate::check::{Checker, Cx, KR, kerr};
use crate::env::{DefInfo, Pending};
use crate::term::{DefDecl, GlobalId, Idx, Recursion, Rel, Term, Tm, Width};
use crate::util::{children, map_post, mk};
use crate::value::{Budget, Value};

/// Split `ty` into `arity` syntactic Π binders and the result type.
fn peel_pis(ty: &Tm, arity: u32) -> Option<(crate::axioms::Params, Tm)> {
    let mut out = Vec::with_capacity(arity as usize);
    let mut t = ty.clone();
    for _ in 0..arity {
        let next = match &*t {
            Term::Pi { name, rel, dom, cod } => {
                out.push((name.clone(), *rel, dom.clone()));
                cod.clone()
            }
            _ => return None,
        };
        t = next;
    }
    Some((out, t))
}

/// Strip `n` leading λ binders.
fn strip_lams(t: &Tm, n: u32) -> Option<Tm> {
    let mut t = t.clone();
    for _ in 0..n {
        let next = match &*t {
            Term::Lam { body, .. } => body.clone(),
            _ => return None,
        };
        t = next;
    }
    Some(t)
}

/// Replace every `Rec(args; _)` by `Global(g)` applied to `args`.
pub(crate) fn replace_rec(body: &Tm, g: GlobalId, rels: &[Rel]) -> Tm {
    map_post(body, 0, &mut |n, _| match &*n {
        Term::Rec { args, .. } => {
            mk::apps(mk::global(g), args.iter().enumerate().map(|(i, a)| (rels.get(i).copied().unwrap_or(Rel::Rel), a.clone())))
        }
        _ => n,
    })
}

/// Syntactic structural-recursion check (see module docs).
pub(crate) fn structural_check(env: &Env, body: &Tm, param: u32) -> KR<()> {
    let mut seen = Default::default();
    walk(env, body, 0, param, &[], &mut seen).map_err(|m| kerr(K::Termination, m))
}

/// Shared nodes already accepted, by (address, depth, smaller-set): the
/// check of a node depends only on those, so a term DAG is walked once per
/// node and context (the body is borrowed for the whole walk).
type Seen = crate::util::FxSet<(usize, u32, Vec<u32>)>;

fn walk(env: &Env, t: &Tm, depth: u32, param: u32, smaller: &[u32], seen: &mut Seen) -> Result<(), String> {
    let shared = Rc::strong_count(t) > 1;
    let key = if shared { Some((Rc::as_ptr(t) as *const () as usize, depth, smaller.to_vec())) } else { None };
    if let Some(k) = &key
        && seen.contains(k)
    {
        return Ok(());
    }
    walk_node(env, t, depth, param, smaller, seen)?;
    if let Some(k) = key {
        seen.insert(k);
    }
    Ok(())
}

fn walk_node(env: &Env, t: &Tm, depth: u32, param: u32, smaller: &[u32], seen: &mut Seen) -> Result<(), String> {
    let lvl_of = |t: &Tm| match &**t {
        Term::Var(Idx(i)) if *i < depth => Some(depth - 1 - *i),
        _ => None,
    };
    match &**t {
        Term::Rec { args, proof } => {
            let a = args.get(param as usize).ok_or("`rec` is missing the structural argument")?;
            match lvl_of(a) {
                Some(l) if smaller.contains(&l) => {}
                _ => {
                    return Err(format!(
                        "structural `rec`: argument {param} must be a variable bound as a recursive field of a match on the \
                         parameter (or on such a field)"
                    ));
                }
            }
            for a in args {
                walk(env, a, depth, param, smaller, seen)?;
            }
            if let Some(p) = proof {
                walk(env, p, depth, param, smaller, seen)?;
            }
            Ok(())
        }
        Term::Match { ind, params, scrut, motive, arms } => {
            for p in params {
                walk(env, p, depth, param, smaller, seen)?;
            }
            walk(env, scrut, depth, param, smaller, seen)?;
            walk(env, motive, depth + 1, param, smaller, seen)?;
            let on_param = lvl_of(scrut).is_some_and(|l| l == param || smaller.contains(&l));
            let info = env.inds.get(ind.0 as usize);
            for (k, arm) in arms.iter().enumerate() {
                let nf = arm.names.len() as u32;
                let mut sm = smaller.to_vec();
                if on_param && let Some(flags) = info.and_then(|i| i.rec_fields.get(k)) {
                    for (j, is_rec) in flags.iter().enumerate() {
                        if *is_rec && (j as u32) < nf {
                            sm.push(depth + j as u32);
                        }
                    }
                }
                walk(env, &arm.body, depth + nf, param, &sm, seen)?;
            }
            Ok(())
        }
        _ => {
            for (c, k) in children(t) {
                walk(env, c, depth + k, param, smaller, seen)?;
            }
            Ok(())
        }
    }
}

/// Results of checking a definition's type.
struct TyInfo {
    ty_val: crate::value::V,
    res_ty: Tm,
    res_sort: crate::term::Sort,
    param_rels: Vec<Rel>,
    measure_width: Option<Width>,
}

fn check_type(env: &Env, d: &DefDecl, b: &mut Budget) -> KR<TyInfo> {
    let (pis, res_ty) = peel_pis(&d.ty, d.arity).ok_or_else(|| {
        kerr(K::IllFormed, format!("the type of `{}` must start with {} syntactic Π binders (its parameter telescope)", d.name, d.arity))
    })?;
    let chk = Checker::new(env);
    let cx0 = Cx::default();
    chk.infer_sort(&cx0, &d.ty, crate::check::REL, b)?;
    let ty_val = chk.eval(&cx0, &d.ty, b)?;
    let mut cx = Cx::default();
    for (name, rel, dom) in &pis {
        let dv = chk.eval(&cx, dom, b)?;
        cx = chk.bind(&cx, name, *rel, &dv).0;
    }
    let res_sort = chk.infer_sort(&cx, &res_ty, crate::check::REL, b)?;
    let param_rels: Vec<Rel> = pis.iter().map(|p| p.1).collect();
    let mut measure_width = None;
    match &d.recursion {
        Recursion::None => {}
        Recursion::Structural { param } => {
            let p = *param as usize;
            if p >= pis.len() {
                return Err(kerr(K::Termination, format!("structural parameter {param} of `{}` is out of range", d.name)));
            }
            if param_rels[p] != Rel::Rel {
                return Err(kerr(K::Termination, "the structural parameter must be relevant"));
            }
            let pty = &cx.ctx.entries[p].ty;
            let ok = match &**pty {
                Value::Ind { ind, .. } => env.inds.get(ind.0 as usize).is_some_and(|i| i.recursive),
                _ => false,
            };
            if !ok {
                return Err(kerr(
                    K::Termination,
                    format!("structural parameter {param} of `{}` must have a recursive inductive type", d.name),
                ));
            }
        }
        Recursion::Measure { measure } => {
            let mt = chk.infer(&cx, measure, crate::check::REL, b)?;
            match &*mt {
                Value::IntTy(w) => measure_width = Some(*w),
                _ => return Err(kerr(K::Termination, format!("the measure of `{}` must have type Int or a machine width", d.name))),
            }
        }
    }
    Ok(TyInfo { ty_val, res_ty, res_sort, param_rels, measure_width })
}

pub(crate) fn add_def(env: &mut Env, d: DefDecl, b: &mut Budget) -> KR<GlobalId> {
    let id = GlobalId(env.defs.len() as u32);
    if strip_lams(&d.body, d.arity).is_none() {
        return Err(kerr(K::IllFormed, format!("the body of `{}` must start with {} λ binders", d.name, d.arity)));
    }
    // The type is checked with the definition pending (so `Global(self)` gets
    // a precise error), but without `Rec` (in_body = false).
    env.pending = Some(Pending {
        id,
        ty_val: Rc::new(Value::Sort(crate::term::Sort::Type)),
        arity: d.arity,
        param_rels: vec![],
        recursion: Recursion::None,
        measure_width: None,
    });
    let ti = check_type(env, &d, b);
    let ti = match ti {
        Ok(t) => t,
        Err(e) => {
            env.pending = None;
            return Err(e);
        }
    };
    env.pending = Some(Pending {
        id,
        ty_val: ti.ty_val.clone(),
        arity: d.arity,
        param_rels: ti.param_rels.clone(),
        recursion: d.recursion.clone(),
        measure_width: ti.measure_width,
    });
    let r: KR<()> = (|| {
        let chk = Checker::with_flags(env, false, true);
        chk.check(&Cx::default(), &d.body, &ti.ty_val, crate::check::REL, b)?;
        if let Recursion::Structural { param } = &d.recursion {
            structural_check(env, &d.body, *param)?;
        }
        Ok(())
    })();
    env.pending = None;
    r?;
    let body = replace_rec(&d.body, id, &ti.param_rels);
    let inner = strip_lams(&body, d.arity).expect("checked above");
    let shared = crate::util::is_dag(&inner);
    env.global_names.insert(d.name.clone(), id);
    env.defs.push(DefInfo {
        name: d.name,
        kind: d.kind,
        ty: d.ty,
        ty_val: ti.ty_val,
        body,
        inner,
        recursion: d.recursion,
        arity: d.arity,
        param_rels: ti.param_rels,
        res_ty: ti.res_ty,
        res_sort: ti.res_sort,
        opaque: d.opaque,
        shared,
        cached: Default::default(),
        cached_bv: Default::default(),
        cached_transparent: Default::default(),
    });
    Ok(id)
}
