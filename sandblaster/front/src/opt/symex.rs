//! Symbolic execution in the kernel evaluator (DESIGN.md §8.2.1).
//!
//! [`symex`] evaluates a definition applied to fresh variables in the
//! optimizer's *transparent* mode (`Env::eval_opaque`): every definition
//! unfolds by the §5.6 policy except the caller's opaque set; intrinsics
//! stay neutral on symbolic data and compute on closed data (§5.6, §9.5).
//! Array-typed parameters are introduced eta-expanded (§5.9), so element
//! reads at literal indices are `index(fst p, k)` spines — the entry
//! spine-expansion of §8.2.1.
//!
//! [`analyze`] walks the resulting value DAG (shared `Rc` nodes counted
//! once) and decides the **stuck-free** criterion: the residual may contain
//! only primitive operations, constructors, pairs, literals, element reads
//! `index(fst p, k)` of array-typed neutrals at literal indices, neutral
//! intrinsic / load-store-helper applications and applications of the
//! globals the caller keeps opaque. Any other neutral — a match on a
//! neutral scrutinee, a stuck recursive global, `absurd`, a stuck
//! `transport`, an axiom, a function value — makes the definition
//! unspecializable, and the first such node is reported.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use sandblaster_kernel::api::{Ctx, CtxEntry, Env};
use sandblaster_kernel::term::{DefKind, GlobalId, Lvl, Name, Rel, Term, Tm};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::{Arg, Budget, Elim, EnvEntry, Head, V, VEnv, Value};

/// The parameter telescope of a definition: `arity` Π binders and the
/// result type (terms, as written in the definition's type).
#[derive(Clone, Debug)]
pub struct Telescope {
    pub binders: Vec<(Name, Rel, Tm)>,
    pub ret: Tm,
}

/// Splits the type of `g` into its `arity` parameter binders and result.
pub fn telescope(env: &Env, g: GlobalId) -> Option<Telescope> {
    let arity = env.global_arity(g)?;
    let mut t = env.global_type(g)?;
    let mut binders = Vec::new();
    for _ in 0..arity {
        let next = match &*t {
            Term::Pi { name, rel, dom, cod } => {
                binders.push((name.clone(), *rel, dom.clone()));
                cod.clone()
            }
            _ => return None,
        };
        t = next;
    }
    Some(Telescope { binders, ret: t })
}

thread_local! {
    /// [`is_recursive`]'s answers during one optimizer run, by global, with
    /// the body they were computed from (held, so the entry cannot outlive
    /// its definition's identity; emptied by [`reset_memo`]).
    static RECURSIVE: std::cell::RefCell<HashMap<GlobalId, (Tm, bool)>> = std::cell::RefCell::new(HashMap::new());
}

/// Empties the memo of [`is_recursive`] (at the start and end of each
/// optimizer run).
pub fn reset_memo() {
    RECURSIVE.with(|m| m.borrow_mut().clear());
}

/// Whether the committed body of `g` refers to `g` (self-recursion: the
/// kernel replaces `Rec` by the global at commit). Memoized per run (a
/// committed body never changes; the walk is over the whole body).
pub fn is_recursive(env: &Env, g: GlobalId) -> bool {
    let Some(body) = env.global_body(g) else { return false };
    if let Some(r) = RECURSIVE.with(|m| m.borrow().get(&g).filter(|(b, _)| Rc::ptr_eq(b, &body)).map(|(_, r)| *r)) {
        return r;
    }
    let r = is_recursive_walk(&body, g);
    RECURSIVE.with(|m| m.borrow_mut().insert(g, (body, r)));
    r
}

fn is_recursive_walk(body: &Tm, g: GlobalId) -> bool {
    let body = body.clone();
    let mut found = false;
    let mut seen: HashSet<*const Term> = HashSet::new();
    let mut stack = vec![body];
    while let Some(t) = stack.pop() {
        if found {
            break;
        }
        if !seen.insert(Rc::as_ptr(&t)) {
            continue;
        }
        if let Term::Global(h) = &*t
            && *h == g
        {
            found = true;
        }
        stack.extend(children(&t));
    }
    found
}

/// Direct subterms of a term (every position, relevant or not).
pub fn children(t: &Tm) -> Vec<Tm> {
    use Term::*;
    match &**t {
        Var(_) | Global(_) | Sort(_) | IntTy(_) | Lit { .. } | Erased => vec![],
        Pi { dom, cod, .. } => vec![dom.clone(), cod.clone()],
        Lam { dom, body, .. } => vec![dom.clone(), body.clone()],
        App { fun, arg, .. } => vec![fun.clone(), arg.clone()],
        Let { ty, val, body, .. } => vec![ty.clone(), val.clone(), body.clone()],
        Sigma { fst, snd, .. } => vec![fst.clone(), snd.clone()],
        Pair { ty, fst, snd } => vec![ty.clone(), fst.clone(), snd.clone()],
        Fst(p) | Snd(p) => vec![p.clone()],
        Eq { ty, lhs, rhs } => vec![ty.clone(), lhs.clone(), rhs.clone()],
        Refl { ty, val } => vec![ty.clone(), val.clone()],
        Transport { ty, lhs, rhs, eq, motive, val } => vec![ty.clone(), lhs.clone(), rhs.clone(), eq.clone(), motive.clone(), val.clone()],
        Ind { params, .. } => params.clone(),
        Ctor { params, args, .. } => params.iter().chain(args.iter()).cloned().collect(),
        Match { params, scrut, motive, arms, .. } => {
            let mut v: Vec<Tm> = params.clone();
            v.push(scrut.clone());
            v.push(motive.clone());
            v.extend(arms.iter().map(|a| a.body.clone()));
            v
        }
        Prim { args, proofs, .. } => args.iter().chain(proofs.iter()).cloned().collect(),
        Rec { args, proof } => args.iter().cloned().chain(proof.iter().cloned()).collect(),
        Delta { args, .. } => args.clone(),
        Unfold { args, val, .. } => {
            let mut v = args.clone();
            v.push(val.clone());
            v
        }
        Linarith { hyps, goal, .. } => {
            let mut v: Vec<Tm> = hyps.iter().flat_map(|(a, b)| [a.clone(), b.clone()]).collect();
            v.push(goal.clone());
            v
        }
        BvRefl { ty, lhs, rhs } => vec![ty.clone(), lhs.clone(), rhs.clone()],
        Absurd { ty, proof } => vec![ty.clone(), proof.clone()],
        Axiom { args, .. } => args.clone(),
    }
}

/// A definition evaluated on fresh parameters.
pub struct Symex {
    /// The parameters' context (level `i` = parameter `i`).
    pub ctx: Ctx,
    /// Their values (array parameters eta-expanded).
    pub venv: VEnv,
    pub tele: Telescope,
    /// The value of the body.
    pub value: V,
    /// Evaluation steps used.
    pub steps: u64,
}

/// Evaluates `g` applied to fresh parameters in the transparent mode with
/// the opaque set `opaque` (see the module docs).
pub fn symex(env: &Env, g: GlobalId, opaque: &dyn Fn(GlobalId) -> bool, budget: u64) -> Result<Symex, String> {
    symex_via(env, g, &HashMap::new(), opaque, budget)
}

/// [`symex`] with the callees in `via` unfolded through their straight-line
/// residuals: each call `c ā` of `g`'s body with `c ↦ r` in `via` evaluates
/// `r ā` (a residual admitted by conversion with `c`, so the same value) in
/// place of `c`'s source. A callee's residual is already evaluated: its
/// constant tables are literals and its own inlined callees are unfolded,
/// so the caller does not evaluate them again (a table read `K4[g]` of an
/// inlined SHA-256 compression unfolds `K4` and `K` at every use in the
/// source). The result is a value of `g` only by the callees' admission;
/// whoever uses it checks its residual against `g` itself
/// (`Env::check_residual_equal`). A recursive `g` is evaluated as is.
pub fn symex_via(env: &Env, g: GlobalId, via: &HashMap<GlobalId, GlobalId>, opaque: &dyn Fn(GlobalId) -> bool, budget: u64) -> Result<Symex, String> {
    let tele = telescope(env, g).ok_or("not a definition with a parameter telescope")?;
    let mut b = Budget { steps: budget };
    let mut entries: Vec<CtxEntry> = Vec::new();
    let mut venv: Vec<EnvEntry> = Vec::new();
    for (i, (name, rel, dom)) in tele.binders.iter().enumerate() {
        let env_now = VEnv(Rc::new(venv.clone()));
        let tv = env.eval(&env_now, Lvl(i as u32), dom, &mut b).map_err(|e| format!("evaluating the type of parameter `{name}`: {e:?}"))?;
        let entry = env.fresh_var(Lvl(i as u32), *rel, &tv);
        entries.push(CtxEntry { name: name.clone(), rel: *rel, ty: tv, def: None });
        venv.push(entry);
    }
    let n = tele.binders.len() as u32;
    let head = match env.global_body(g) {
        Some(body) if !via.is_empty() && !is_recursive(env, g) => {
            let mut hit = false;
            let redirected = crate::elab::tm::map_post(&body, 0, &mut |t, _| match &*t {
                Term::Global(c) => Some(match via.get(c) {
                    Some(r) => {
                        hit = true;
                        mk::global(*r)
                    }
                    None => t,
                }),
                _ => Some(t),
            });
            match redirected {
                Some(b) if hit => b,
                _ => mk::global(g),
            }
        }
        _ => mk::global(g),
    };
    let term = mk::apps(head, tele.binders.iter().enumerate().map(|(i, (_, rel, _))| (*rel, mk::var(n - 1 - i as u32))));
    let venv = VEnv(Rc::new(venv));
    let value = env.eval_opaque(&venv, Lvl(n), &term, opaque, &mut b).map_err(|e| format!("symbolic execution: {e:?}"))?;
    Ok(Symex { ctx: Ctx { entries: Rc::new(entries) }, venv, tele, value, steps: budget - b.steps })
}

/// What a residual node is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NodeKind {
    Lit,
    Ctor,
    Pair,
    Prim,
    /// `index(fst x, k)` of an array-typed neutral at a literal index.
    ElemRead,
    /// A parameter (or a projection of one).
    Param,
    /// A neutral intrinsic or load/store helper application.
    Intrinsic,
    /// An application of a global kept opaque by the caller.
    OpaqueCall,
    Type,
}

/// Statistics and the stuck-free verdict of a residual.
#[derive(Clone, Debug, Default)]
pub struct Analysis {
    /// Distinct value nodes (shared nodes counted once).
    pub nodes: usize,
    pub by_kind: HashMap<String, usize>,
    /// The first node violating the stuck-free criterion, described.
    pub stuck: Option<String>,
    /// Globals applied as opaque calls in the residual.
    pub calls: HashSet<GlobalId>,
    /// Intrinsics / helpers applied in the residual.
    pub intrinsics: HashSet<GlobalId>,
}

/// Classifies the value DAG `v` (see the module docs).
pub fn analyze(env: &Env, v: &V, opaque: &dyn Fn(GlobalId) -> bool, index_g: GlobalId) -> Analysis {
    let mut a = Analysis::default();
    let mut seen: HashSet<*const Value> = HashSet::new();
    let mut stack: Vec<V> = vec![v.clone()];
    let kind_count = |a: &mut Analysis, k: NodeKind| *a.by_kind.entry(format!("{k:?}")).or_default() += 1;
    while let Some(v) = stack.pop() {
        if !seen.insert(Rc::as_ptr(&v)) {
            continue;
        }
        a.nodes += 1;
        match &*v {
            Value::Lit { .. } => kind_count(&mut a, NodeKind::Lit),
            Value::Sort(_) | Value::IntTy(_) | Value::Ind { .. } | Value::Eq { .. } => kind_count(&mut a, NodeKind::Type),
            Value::Ctor { args, .. } => {
                // (the parameters are types)
                kind_count(&mut a, NodeKind::Ctor);
                for x in args {
                    if let Arg::Rel(x) = x {
                        stack.push(x.clone());
                    }
                }
            }
            Value::Pair { fst, snd } => {
                kind_count(&mut a, NodeKind::Pair);
                stack.push(fst.clone());
                if let Arg::Rel(x) = snd {
                    stack.push(x.clone());
                }
            }
            Value::Refl { .. } => kind_count(&mut a, NodeKind::Type),
            Value::Lam { .. } | Value::Pi { .. } | Value::Sigma { .. } => {
                if a.stuck.is_none() {
                    a.stuck = Some("a function or type value in the result".into());
                }
            }
            Value::Neu(n) => {
                // matches on neutral scrutinees
                if n.spine.iter().any(|e| matches!(e, Elim::Match { .. })) {
                    if a.stuck.is_none() {
                        a.stuck = Some(format!("a `match` on a neutral scrutinee ({})", describe_head(env, &n.head)));
                    }
                    continue;
                }
                let only_fst_snd = n.spine.iter().all(|e| matches!(e, Elim::Fst | Elim::Snd));
                match &n.head {
                    Head::Var(_) => {
                        if only_fst_snd {
                            kind_count(&mut a, NodeKind::Param);
                        } else if a.stuck.is_none() {
                            a.stuck = Some("an application of a parameter".into());
                        }
                    }
                    Head::Prim { args, .. } => {
                        kind_count(&mut a, NodeKind::Prim);
                        stack.extend(args.iter().cloned());
                        if !n.spine.is_empty() && a.stuck.is_none() {
                            a.stuck = Some("an eliminator on a primitive".into());
                        }
                    }
                    Head::Global { def, args } => {
                        let kind = env.global_kind(*def);
                        let rel_args: Vec<V> = args.iter().filter_map(|x| if let Arg::Rel(x) = x { Some(x.clone()) } else { None }).collect();
                        if *def == index_g {
                            // index(T, fst x, k): an element read at a literal index
                            let ok = rel_args.len() >= 3 && matches!(&*rel_args[2], Value::Lit { .. }) && matches!(&*rel_args[1], Value::Neu(m) if m.spine.last().is_some_and(|e| matches!(e, Elim::Fst)));
                            if ok {
                                kind_count(&mut a, NodeKind::ElemRead);
                                stack.push(rel_args[1].clone());
                            } else if a.stuck.is_none() {
                                a.stuck = Some("a list index that is not an element read at a literal index".into());
                            }
                        } else if kind == Some(DefKind::Intrinsic) {
                            kind_count(&mut a, NodeKind::Intrinsic);
                            a.intrinsics.insert(*def);
                            stack.extend(rel_args);
                        } else if opaque(*def) {
                            kind_count(&mut a, NodeKind::OpaqueCall);
                            a.calls.insert(*def);
                            stack.extend(rel_args);
                        } else if a.stuck.is_none() {
                            a.stuck = Some(format!("a stuck application of `{}`", env.global_name(*def).map(|s| s.to_string()).unwrap_or_default()));
                        }
                        if !only_fst_snd && a.stuck.is_none() {
                            a.stuck = Some("an application of a neutral global".into());
                        }
                    }
                    Head::Absurd { .. } | Head::Transport { .. } | Head::Axiom { .. } => {
                        if a.stuck.is_none() {
                            a.stuck = Some(format!("a stuck {}", describe_head(env, &n.head)));
                        }
                    }
                }
            }
        }
    }
    a
}

/// A short description of a neutral head.
pub fn describe_head(env: &Env, h: &Head) -> String {
    match h {
        Head::Var(l) => format!("variable #{}", l.0),
        Head::Global { def, .. } => format!("`{}`", env.global_name(*def).map(|s| s.to_string()).unwrap_or_default()),
        Head::Prim { op, .. } => format!("primitive {op:?}"),
        Head::Absurd { .. } => "`absurd`".into(),
        Head::Transport { .. } => "`transport`".into(),
        Head::Axiom { .. } => "axiom".into(),
    }
}

/// A debugging rendering of a value DAG: every shared node is printed once
/// as `%n = …` (at most `max` nodes).
pub fn debug_dag(env: &Env, v: &V, max: usize) -> String {
    use std::fmt::Write as _;
    let mut ids: HashMap<*const Value, usize> = HashMap::new();
    let mut out = String::new();
    fn go(env: &Env, v: &V, ids: &mut HashMap<*const Value, usize>, out: &mut String, max: usize) -> String {
        if let Some(i) = ids.get(&Rc::as_ptr(v)) {
            return format!("%{i}");
        }
        if ids.len() >= max {
            return "…".into();
        }
        let arg = |a: &Arg, ids: &mut HashMap<*const Value, usize>, out: &mut String| match a {
            Arg::Rel(x) => go(env, x, ids, out, max),
            Arg::Irr(_) => ".".into(),
        };
        let s = match &**v {
            Value::Lit { w, n } => return format!("{n}{w:?}"),
            Value::Sort(_) | Value::IntTy(_) | Value::Ind { .. } => return "<ty>".into(),
            Value::Ctor { ind, ctor, args, .. } => {
                let name = env.inductive_decl(*ind).map(|d| d.ctors[*ctor as usize].name.to_string()).unwrap_or_default();
                let a: Vec<String> = args.iter().map(|x| arg(x, ids, out)).collect();
                format!("{name}({})", a.join(", "))
            }
            Value::Pair { fst, snd } => format!("<{}, {}>", go(env, fst, ids, out, max), arg(snd, ids, out)),
            Value::Neu(n) => {
                let mut s = match &n.head {
                    Head::Var(l) => format!("x{}", l.0),
                    Head::Prim { op, args, .. } => format!("#{op:?}({})", args.iter().map(|x| go(env, x, ids, out, max)).collect::<Vec<_>>().join(", ")),
                    Head::Global { def, args } => format!("{}({})", env.global_name(*def).map(|x| x.to_string()).unwrap_or_default(), args.iter().map(|x| arg(x, ids, out)).collect::<Vec<_>>().join(", ")),
                    h => describe_head(env, h),
                };
                for e in &n.spine {
                    match e {
                        Elim::Fst => s.push_str(".1"),
                        Elim::Snd => s.push_str(".2"),
                        Elim::App(a) => s = format!("{s} {}", arg(a, ids, out)),
                        Elim::Match { .. } => s = format!("match {s} {{..}}"),
                    }
                }
                s
            }
            other => format!("<{:?}>", std::mem::discriminant(other)),
        };
        if Rc::strong_count(v) > 1 && s.len() > 12 {
            let i = ids.len();
            ids.insert(Rc::as_ptr(v), i);
            let _ = writeln!(out, "%{i} = {s}");
            format!("%{i}")
        } else {
            s
        }
    }
    let r = go(env, v, &mut ids, &mut out, max);
    let _ = writeln!(out, "result = {r}");
    out
}
