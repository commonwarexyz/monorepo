//! Selection among straight-line alternatives: the aegraph (optimizer
//! design §10.1, §10.3; DESIGN §8.2 item 6; plan O8).
//!
//! **Where it runs.** On the straight-line region of a function whose
//! tier-0 residual was admitted by conversion and not replaced by the
//! driver (design §10.1: "straight-line regions only"). The region is the
//! symbolic value of the function quoted as a term tree over its parameters.
//!
//! **What it does.**
//! 1. Builds the region's acyclic e-graph ([`aeg`]; ≤ 10^4 e-nodes).
//! 2. For each rule of the library ([`rules`]: kernel-checked lemmas written
//!    by the offline `sandblaster-rulegen`) whose trigger admits a class, it
//!    proposes instances `σ` (the classes of the rule variable's width that
//!    occur most often below the class) and asks `bvnorm` whether the class
//!    equals the rule's left side at `σ`, all candidates of a class in one
//!    normalizer (`bvnorm::classify` batching). Rules are loaded — and
//!    checked by the kernel — only when a trigger fires.
//! 3. Repeats on the rewritten region, at most [`ROUNDS`] rounds.
//! 4. Extracts the rewrite sets by cost ([`extract`]; the variant set's cost
//!    model) and keeps a set only if the region becomes at least 3% cheaper
//!    (the selection gate); the top three are tried, at most two retries.
//! 5. Prints the rewritten region (`residual::build`), elaborates it (every
//!    proof slot re-proven), proves the link `r::equiv : Π x̄. Eq(R, r x̄,
//!    f x̄)` by the explanation's transport chain ([`explain`]) and commits
//!    it with `add_def` (`Link::Lemma`, rung [`Rung::Rewritten`]).
//!
//! Everything here is untrusted: a wrong match, rule instance or motive is a
//! kernel rejection, and the function keeps its conversion-linked residual.

pub mod aeg;
pub mod explain;
pub mod extract;
pub mod rules;

use std::collections::HashMap;
use std::rc::Rc;

use sandblaster_kernel::term::{DefDecl, DefKind, GlobalId, Lvl, Rel, Term, Tm, Width};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::Budget;

use super::cost::model::{SetModel, beats, fmt_mc};
use super::{BudgetsUsed, Ctx, DriveOut, Outcome, Rung};
use crate::elab::{self, ProverChain};
use crate::hir::*;

/// Rounds of matching (design §17).
pub const ROUNDS: usize = 8;
/// Region tree size above which the aegraph does not run (the quoted tree
/// of a shared DAG can be much larger than the DAG).
pub const MAX_TREE: usize = 2 * aeg::MAX_NODES;
/// Kernel steps of one `bvnorm::classify` batch.
pub const CLASSIFY_STEPS: u64 = 20_000_000;
/// Instances tried per rule and class.
pub const SIGMAS: usize = 3;

/// A rewrite found in one round, with its saving (the cost model).
struct Found {
    class: aeg::Class,
    rewrite: explain::Rewrite,
    saving: u64,
}

/// The matches of one round on region `c` (at depth `n` over the
/// parameters `ctx`). Loads the rule library on the first trigger.
fn round(cx: &mut Ctx<'_>, ctx: &sandblaster_kernel::api::Ctx, c: &Tm, pw: &dyn Fn(u32) -> Option<Width>, model: &SetModel, notes: &mut Vec<String>) -> Option<(aeg::EGraph, Vec<Found>)> {
    let (g, root) = aeg::EGraph::build(&cx.out.env, c, pw)?;
    let index = rules::index(&cx.out.env);
    // (class, rule, σ classes) of every admitted trigger
    let mut probes: Vec<(aeg::Class, usize, Vec<aeg::Class>)> = Vec::new();
    for cl in 0..=root {
        let node = &g.nodes[cl as usize];
        let Some(w) = node.width else { continue };
        for (ri, r) in index.iter().enumerate() {
            if r.ty != w || r.vars.len() != 1 || !r.sig.admits(&node.hist, node.size) {
                continue;
            }
            let mut occ: Vec<(aeg::Class, u32)> = g.occurrences(cl).into_iter().filter(|(k, n)| *k != cl && *n >= 2 && g.nodes[*k as usize].width == Some(r.vars[0])).collect();
            occ.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            let sig: Vec<aeg::Class> = occ.into_iter().take(SIGMAS).map(|(k, _)| k).collect();
            if !sig.is_empty() {
                probes.push((cl, ri, sig));
            }
        }
    }
    if probes.is_empty() {
        return Some((g, vec![]));
    }
    if !rules_loaded(cx) {
        notes.push("the rule library did not load (see the warnings)".into());
        return Some((g, vec![]));
    }
    let env = &cx.out.env;
    let mut found = Vec::new();
    for (cl, ri, sig) in probes {
        let r = &index[ri];
        let Some(lemma) = rules::lemma(env, &r.name) else { continue };
        let target = g.nodes[cl as usize].term.clone();
        let insts: Vec<(Tm, Tm, Tm)> = sig.iter().map(|s| {
            let st = g.nodes[*s as usize].term.clone();
            (st.clone(), elab::tm::subst0(&r.lhs, &st), elab::tm::subst0(&r.rhs, &st))
        }).collect();
        let mut terms = vec![target.clone()];
        terms.extend(insts.iter().map(|(_, l, _)| l.clone()));
        let mut b = Budget { steps: CLASSIFY_STEPS };
        let Ok(classes) = sandblaster_kernel::bvnorm::classify(env, ctx, &terms, &mut b) else { continue };
        for (i, (st, lhs, rhs)) in insts.into_iter().enumerate() {
            if classes[i + 1] != classes[0] {
                continue;
            }
            let before = model.term_cost(&target, &|_| None);
            let after = model.term_cost(&rhs, &|_| None);
            let ty = mk::int_ty(r.ty);
            found.push(Found { class: cl, rewrite: explain::Rewrite { target: target.clone(), ty, rule: r.name.clone(), lemma, sigma: vec![st], lhs, rhs }, saving: before.saturating_sub(after) });
            break;
        }
    }
    Some((g, found))
}

/// Loads the rule library the first time a trigger fires and records the
/// result in the context: a library that fails its kernel check is
/// reported once (a warning, an error in strict mode) and never used for
/// the rest of the build — not even the lemmas that loaded before the
/// failing one.
fn rules_loaded(cx: &mut Ctx<'_>) -> bool {
    if cx.rules.is_none() {
        let files = cx.opts.hooks().and_then(|h| h.rule_files());
        let r = match &files {
            Some(fs) => rules::ensure_files(&mut cx.out.env, fs.iter().map(|(f, t)| (f.as_str(), t.as_str()))),
            None => rules::ensure(&mut cx.out.env),
        };
        if let Err(e) = &r {
            cx.failure(format!("the aegraph's rule library failed its kernel check, so no rule rewrites for the rest of the build: {e}"));
        }
        cx.rules = Some(r);
    }
    matches!(cx.rules, Some(Ok(())))
}

/// The outcome of [`improve`].
pub(super) enum Improved {
    /// Nothing to do (no trigger, no match, not 3% cheaper).
    None(String),
    /// A rewritten residual, admitted by its lemma.
    Admitted(DriveOut),
    /// Every candidate was rejected (the notes say why).
    Rejected(DriveOut),
}

/// The aegraph on one function (see the module docs). `sym` is its tier-0
/// symbolic value; `calls` the opaque calls of the tier-0 residual.
#[allow(clippy::too_many_arguments)]
pub(super) fn improve(cx: &mut Ctx<'_>, ext: &mut Crate, chain: &mut ProverChain, eopts: &elab::Options, id: ItemId, g: GlobalId, sym: &super::symex::Symex, calls: &[String], model: &SetModel, user_globals: &HashMap<GlobalId, ItemId>, growth: &mut usize) -> Improved {
    let n = sym.tele.binders.len() as u32;
    let widths: Vec<Option<Width>> = sym.tele.binders.iter().map(|(_, _, d)| if let Term::IntTy(w) = &**d { Some(*w) } else { None }).collect();
    // Var(i) at the region's root is parameter level n - 1 - i
    let pw = |i: u32| -> Option<Width> { n.checked_sub(1 + i).and_then(|l| widths.get(l as usize).copied().flatten()) };
    // the shared form first (always small): the region's tree size, and a
    // quick exit when no rule's left side could fit
    // the region as a term over the parameters (see `quote_region`); its
    // tree size bounds every later pass
    let (c0, tree) = match quote_region(&cx.out.env, &sym.venv, n, &sym.value, MAX_TREE) {
        Ok(x) => x,
        Err(e) => return Improved::None(e),
    };
    let index = rules::index(&cx.out.env);
    if index.iter().all(|r| (tree as u32) * 2 < r.sig.size) {
        return Improved::None("no rule trigger".into());
    }
    super::trace(|| format!("aegraph {}: region of tree size {tree}", ext.item(id).path));
    let mut notes: Vec<String> = Vec::new();
    let mut c = c0.clone();
    // the rewrites of every round, applied in order
    let mut all: Vec<extract::Scored> = Vec::new();
    let mut graph_nodes = 0usize;
    for _ in 0..ROUNDS {
        let Some((gr, found)) = round(cx, &sym.ctx, &c, &pw, model, &mut notes) else {
            notes.push(format!("the region exceeds {} e-nodes", aeg::MAX_NODES));
            break;
        };
        graph_nodes = graph_nodes.max(gr.nodes.len());
        // (a match, whatever its saving: see `Ctx::aegraph_matched`)
        if !found.is_empty() {
            cx.aegraph_matched.insert(id);
        }
        let scored: Vec<extract::Scored> = found.into_iter().map(|f| extract::Scored { class: f.class, saving: f.saving, rewrite: f.rewrite }).collect();
        let cands = extract::candidates(&gr, scored);
        let Some(best) = cands.into_iter().next() else { break };
        // apply the round's best set to get the next region
        let rws: Vec<explain::Rewrite> = best.iter().map(|s| s.rewrite.clone()).collect();
        let mut ex = explain::Explanations::default();
        let ret = sym.tele.ret.clone();
        let fx = f_applied(g, &sym.tele);
        match explain::chain(&cx.out.env, &mut ex, &c, &rws, &ret, &fx) {
            Ok((_, next)) => c = next,
            Err(e) => {
                notes.push(e);
                break;
            }
        }
        all.extend(best);
    }
    if all.is_empty() {
        return Improved::None(if notes.is_empty() { "no rule matched".into() } else { notes.join("; ") });
    }
    // the candidate sets (top 3): all rounds' rewrites, then the first
    // round's best rewrite alone, then all but the last
    let mut sets: Vec<Vec<extract::Scored>> = vec![all.clone()];
    if all.len() > 1 {
        sets.push(vec![all[0].clone()]);
        let mut v = all.clone();
        v.pop();
        if v.len() > 1 {
            sets.push(v);
        }
    }
    let cost0 = model.term_cost(&c0, &|_| None);
    let name = ext.item(id).path.to_string();
    let orig = ext.item(id).clone();
    let f = ext.fn_def(id).unwrap().clone();
    let mut rejected: Vec<String> = Vec::new();
    let mut rejected_by: Option<String> = None;
    for (attempt, set) in sets.iter().enumerate().take(1 + super::cost::model::RETRIES) {
        let rws: Vec<explain::Rewrite> = set.iter().map(|s| s.rewrite.clone()).collect();
        let rules_used: Vec<String> = {
            let mut v: Vec<String> = rws.iter().map(|r| r.rule.clone()).collect();
            v.dedup();
            v
        };
        let mut ex = explain::Explanations::default();
        let ret = sym.tele.ret.clone();
        let fx = f_applied(g, &sym.tele);
        let (body, ck) = match explain::chain(&cx.out.env, &mut ex, &c0, &rws, &ret, &fx) {
            Ok(x) => x,
            Err(e) => {
                rejected.push(format!("candidate {}: {e}", attempt + 1));
                continue;
            }
        };
        let cost1 = model.term_cost(&ck, &|_| None);
        if !beats(cost1, cost0) {
            rejected.push(format!("candidate {}: not 3% cheaper ({} → {} on {})", attempt + 1, fmt_mc(cost0), fmt_mc(cost1), model.name));
            continue;
        }
        // the rewritten region's value (every user function stays folded:
        // the region only contains the calls the tier-0 value kept)
        let opaque = |h: GlobalId| user_globals.contains_key(&h);
        let mut b = Budget { steps: cx.opts.symex_budget };
        let v1 = match cx.out.env.eval_opaque(&sym.venv, Lvl(n), &ck, &opaque, &mut b) {
            Ok(v) => v,
            Err(e) => {
                rejected.push(format!("candidate {}: its value: {e:?}", attempt + 1));
                continue;
            }
        };
        let r = {
            let maps = match super::residual::Maps::new(&cx.out.env, ext, &cx.out.fn_globals, &cx.out.adts) {
                Ok(m) => m,
                Err(e) => return Improved::None(e),
            };
            match super::residual::build(&cx.out.env, &maps, ext, &f, &v1, orig.span) {
                Ok(r) => r,
                Err(e) => {
                    rejected.push(format!("candidate {}: not printable: {e}", attempt + 1));
                    continue;
                }
            }
        };
        let mut rf = f.clone();
        rf.body = FnBody::Exec(r.body);
        rf.locals = r.locals;
        rf.ensures = None;
        rf.recursion = crate::hir::Recursion::None;
        rf.decreases = None;
        let rid = match super::push_elaborate(cx, ext, chain, eopts, &orig, format!("{}__residual", orig.name), rf, true) {
            Ok(rid) => rid,
            Err((why, rej)) => {
                rejected.push(format!("candidate {}: {why}", attempt + 1));
                rejected_by = rej;
                continue;
            }
        };
        let Some(rg) = cx.out.fn_globals.get(&rid).copied() else {
            super::pop_driven(cx, ext, rid);
            continue;
        };
        let lemma = format!("{name}__residual::equiv");
        let added = (|| -> Result<GlobalId, String> {
            let (ty, arity) = super::link_statement(&cx.out.env, rg, g)?;
            let mut lam = body.clone();
            for (nm, rel, dom) in sym.tele.binders.iter().rev() {
                lam = mk::lam(nm, *rel, dom.clone(), lam);
            }
            let d = DefDecl { name: Rc::from(lemma.as_str()), kind: DefKind::Lemma, ty, body: lam, recursion: sandblaster_kernel::term::Recursion::None, arity, opaque: true };
            let mut bud = Budget { steps: cx.opts.check_budget };
            cx.out.env.add_def(d, &mut bud).map_err(|e| e.to_string().chars().take(600).collect())
        })();
        if let Err(e) = added {
            super::pop_driven(cx, ext, rid);
            let kind = e.split(':').next().unwrap_or("").to_string();
            rejected.push(format!("candidate {}: the kernel rejected the link lemma: {e}", attempt + 1));
            rejected_by = Some(format!("add_def: {kind}"));
            continue;
        }
        if let Err(e) = super::verify_link_lemma(&cx.out.env, &lemma, rg, g) {
            super::pop_driven(cx, ext, rid);
            rejected.push(format!("candidate {}: emission chain: {e}", attempt + 1));
            rejected_by = Some("emission chain".into());
            continue;
        }
        cx.set_aside_obligations(rid);
        *growth += r.nodes;
        let per_table: Vec<String> = model.tables.iter().map(|t| format!("{} {}→{}", t.uarch, fmt_mc(model_one(t, &c0)), fmt_mc(model_one(t, &ck)))).collect();
        let mut reason = format!(
            "admitted: kernel-checked equality lemma (Link::Lemma); aegraph rewrite by {} ({} rewrite(s), {} e-nodes); cost on {} {} → {} ({})",
            rules_used.join(", "),
            rws.len(),
            graph_nodes,
            model.name,
            fmt_mc(cost0),
            fmt_mc(cost1),
            per_table.join(", ")
        );
        if !rejected.is_empty() {
            reason.push_str(&format!("; earlier candidates: {}", rejected.join("; ")));
        }
        let budgets = BudgetsUsed { residual_nodes: r.nodes as u64, ..BudgetsUsed::default() };
        return Improved::Admitted(DriveOut { outcome: Some(Outcome::Specialized { nodes: r.nodes, residual: rg, calls: calls.to_vec() }), lemma: Some(lemma), ritem: Some(rid), reason, rejected_by: None, budgets, trivial: false, failure: false, leaves: 1, expanded_leaves: 1, loop_rung: Some(Rung::Rewritten) });
    }
    let failure = rejected_by.as_deref().is_some_and(|r| r.starts_with("add_def") || r == "elaboration" || r == "emission chain");
    let reason = format!("aegraph: no candidate admitted: {}", rejected.join("; "));
    if !failure {
        return Improved::None(reason);
    }
    Improved::Rejected(DriveOut { outcome: None, lemma: None, ritem: None, reason, rejected_by, budgets: BudgetsUsed::default(), trivial: false, failure, leaves: 0, expanded_leaves: 0, loop_rung: Some(Rung::Rewritten) })
}

/// The cost of a region under one table.
fn model_one(t: &super::cost::tables::Table, c: &Tm) -> u64 {
    SetModel { name: String::new(), level: t.level, tables: vec![t.clone()] }.term_cost(c, &|_| None)
}

/// `f x̄` at the telescope's depth.
fn f_applied(g: GlobalId, tele: &super::symex::Telescope) -> Tm {
    let n = tele.binders.len() as u32;
    mk::apps(mk::global(g), tele.binders.iter().enumerate().map(|(i, (_, rel, _))| (*rel, mk::var(n - 1 - i as u32))))
}

/// The region: the straight-line value `v` (at depth `n`) as a term over
/// the parameters, and its tree size (at most `cap`, else an error).
///
/// Literals, parameters, primitive applications, applications of opaque
/// globals and constructors are rebuilt node by node (shared `V` nodes stay
/// shared `Tm` nodes); any other value refuses the region. A checked
/// primitive's proof is never quoted (the proof closures of an unrolled loop
/// can be arbitrarily large): when its obligation over the rebuilt arguments
/// evaluates to `true` (a shift by a literal, a division by a nonzero
/// literal) the proof is `refl(Bool, true)`; otherwise the region uses the
/// operation's wrapping form (`add`, `sub`, `mul`, `shl`, `shr`; any other
/// refuses the region). The kernel re-checks every term that uses them.
pub fn quote_region(env: &sandblaster_kernel::api::Env, venv: &sandblaster_kernel::value::VEnv, n: u32, v: &sandblaster_kernel::value::V, cap: usize) -> Result<(Tm, usize), String> {
    use sandblaster_kernel::value::{Arg, Head, Value};
    struct Q<'a> {
        env: &'a sandblaster_kernel::api::Env,
        venv: &'a sandblaster_kernel::value::VEnv,
        n: u32,
        cap: usize,
        memo: HashMap<*const Value, (Tm, usize)>,
    }
    impl Q<'_> {
        fn go(&mut self, v: &sandblaster_kernel::value::V) -> Result<(Tm, usize), String> {
            let key = Rc::as_ptr(v);
            if let Some(r) = self.memo.get(&key) {
                return Ok(r.clone());
            }
            let r = match &**v {
                Value::Lit { w, n } => (Rc::new(Term::Lit { w: *w, n: n.clone() }), 1),
                Value::Neu(neu) if neu.spine.is_empty() => match &neu.head {
                    Head::Var(l) => {
                        let i = self.n.checked_sub(1 + l.0).ok_or("a variable outside the parameters")?;
                        (mk::var(i), 1)
                    }
                    Head::Prim { op, args, proofs } => {
                        let mut ts = Vec::with_capacity(args.len());
                        let mut size = 1usize;
                        for a in args {
                            let (t, s) = self.go(a)?;
                            size = size.saturating_add(s);
                            ts.push(t);
                        }
                        let mut ps = Vec::new();
                        let mut op = *op;
                        if !proofs.is_empty() {
                            let mut closed = true;
                            for o in sandblaster_kernel::prim::prim_obligations(op, &ts, self.env.bool_ind()) {
                                let Term::Eq { lhs, .. } = &*o else { return Err("an unexpected obligation".into()) };
                                let mut b = Budget { steps: 100_000 };
                                closed &= self.env.eval(self.venv, Lvl(self.n), lhs, &mut b).ok().is_some_and(|x| matches!(&*x, Value::Ctor { ctor: 1, .. }));
                                ps.push(mk::refl(Rc::new(Term::Ind { ind: self.env.bool_ind(), params: vec![] }), Rc::new(Term::Ctor { ind: self.env.bool_ind(), ctor: 1, params: vec![], args: vec![] })));
                            }
                            if !closed {
                                // the obligation depends on the parameters: the
                                // region uses the wrapping operation, which
                                // agrees with the checked one wherever that is
                                // in its domain (so on every input of `f`);
                                // the region's first step is `BvRefl`, which
                                // reads checked operations as wrapping ones
                                // (§9.8 rule 1), and the kernel re-checks it
                                use sandblaster_kernel::term::PrimOp as P;
                                op = match op {
                                    P::Add(w) => P::WAdd(w),
                                    P::Sub(w) => P::WSub(w),
                                    P::Mul(w) => P::WMul(w),
                                    P::Shl(w) => P::WShl(w),
                                    P::Shr(w) => P::WShr(w),
                                    _ => return Err("a checked operation without a wrapping form whose proof is not closed".into()),
                                };
                                ps.clear();
                            }
                        }
                        (Rc::new(Term::Prim { op, args: ts, proofs: ps }), size)
                    }
                    Head::Global { def, args } if args.iter().all(|a| matches!(a, Arg::Rel(_))) => {
                        let mut t = mk::global(*def);
                        let mut size = 1usize;
                        for a in args {
                            let Arg::Rel(x) = a else { unreachable!() };
                            let (at, s) = self.go(x)?;
                            size = size.saturating_add(s);
                            t = mk::apps(t, [(Rel::Rel, at)]);
                        }
                        (t, size)
                    }
                    _ => return Err("the region has a value the aegraph does not handle".into()),
                },
                Value::Ctor { ind, ctor, params, args } if args.iter().all(|a| matches!(a, Arg::Rel(_))) => {
                    let mut ts = Vec::with_capacity(args.len());
                    let mut size = 1usize;
                    for a in args {
                        let Arg::Rel(x) = a else { unreachable!() };
                        let (t, s) = self.go(x)?;
                        size = size.saturating_add(s);
                        ts.push(t);
                    }
                    // the family parameters are types (small)
                    let ps: Vec<Tm> = params.iter().map(|p| self.env.quote(Lvl(self.n), p, true)).collect();
                    if ps.iter().any(|p| elab::tm::size_capped(p, 257) > 256) {
                        return Err("a constructor with large parameters".into());
                    }
                    (Rc::new(Term::Ctor { ind: *ind, ctor: *ctor, params: ps, args: ts }), size)
                }
                _ => return Err("the region has a value the aegraph does not handle".into()),
            };
            if r.1 > self.cap {
                return Err("the region exceeds the aegraph's budget".into());
            }
            self.memo.insert(key, r.clone());
            Ok(r)
        }
    }
    Q { env, venv, n, cap, memo: HashMap::new() }.go(v)
}

/// The size of `t` as a tree, its `let`s expanded at every use, capped at
/// `cap` (the quoted region without sharing).
pub fn tree_size_capped(t: &Tm, cap: usize) -> usize {
    fn go(t: &Tm, lets: &mut Vec<Option<usize>>, cap: usize) -> usize {
        match &**t {
            Term::Var(sandblaster_kernel::term::Idx(i)) => {
                let k = lets.len().checked_sub(1 + *i as usize);
                k.and_then(|k| lets[k]).unwrap_or(1)
            }
            Term::Let { val, body, ty, .. } => {
                let v = go(val, lets, cap);
                let _ = ty;
                lets.push(Some(v));
                let b = go(body, lets, cap);
                lets.pop();
                b.min(cap)
            }
            _ => {
                let mut n = 1usize;
                crate::elab::tm::children_depth(t, &mut |c, k| {
                    if n > cap {
                        return;
                    }
                    for _ in 0..k {
                        lets.push(None);
                    }
                    n = n.saturating_add(go(c, lets, cap));
                    for _ in 0..k {
                        lets.pop();
                    }
                });
                n.min(cap)
            }
        }
    }
    go(t, &mut Vec::new(), cap)
}
