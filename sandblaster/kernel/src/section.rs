//! Specification closure and section abstraction (DESIGN.md §15.1, §15.5).
//!
//! * [`closure`] computes `Refs*`: the globals referenced from **relevant
//!   positions** of some terms, closed under the declarations (type and body,
//!   opaque or not; parameter and field types of inductives) of the globals
//!   and inductives it contains, not descending into a stop set. Irrelevant
//!   positions (proofs) are skipped: they only assert that a proposition is
//!   inhabited, which type checking already guarantees.
//! * [`abstract_section`] builds `complete_p(R)` for each published `p`:
//!
//!   ```text
//!   Π(F₀' : T₀)(F₁' : T₁[F'])…  Π(h₀ : H₀[F'])…  Π(x̄ : Ā_p[F'])(h̄ :Irr Req_p[F'](x̄)).
//!       obs_eq(Out_p, F_p' x̄ h̄, p x̄ h̄)
//!   ```
//!
//!   Every part except the final `p x̄ h̄` is produced by [`Abs::place`]:
//!   each occurrence of a member of `R` becomes its variable `F'`, and each
//!   occurrence (in a relevant position) of a spec definition whose `Refs*`
//!   meets `R` becomes its body, abstracted the same way (λ-lifting,
//!   inlined); any other global that reaches `R` is an error. Hypotheses are
//!   the statements (types) of lemmas of the environment, optionally
//!   restated with different proofs; the conclusion is generated from `p`'s
//!   type and the views. The result is type-checked and rejected if `Refs*`
//!   of its abstracted parts still meets `R`.

use std::collections::BTreeSet;
use std::rc::Rc;

use crate::api::{Env, KernelErrorKind as K, Section, SectionStatements};
use crate::check::{Checker, Cx, KR, REL, kerr};
use crate::term::{Arm, DefKind, GlobalId, Idx, IndId, Name, Rel, Sort, Term, Tm};
use crate::util::{FxMap, FxSet, any_sub, children, map_post, mk, occurs, rebuild_with, shift};
use crate::value::{Budget, V};

/// For each child of `t` (in the order of `util::children`), whether it is a
/// relevant position of `t` (DESIGN.md §5.3). Irrelevant: an `Irr`
/// application argument or let value, the second component of a pair whose
/// Σ is `Irr`, prim proof slots, the `Rec` proof, `Transport.eq`,
/// `Absurd.proof`, `Irr` constructor fields and the `Irr` arguments of
/// `Delta`, `Unfold` and axioms. Everything else — binder domains, motives,
/// the statements inside proof terms — is relevant.
pub(crate) fn relevant_children(env: &Env, t: &Term) -> Vec<bool> {
    use Term::*;
    let by = |rels: Vec<Rel>, n: usize| (0..n).map(|i| rels.get(i).copied().unwrap_or(Rel::Rel) == Rel::Rel).collect::<Vec<_>>();
    match t {
        App { rel, .. } => vec![true, *rel == Rel::Rel],
        Let { rel, .. } => vec![true, *rel == Rel::Rel, true],
        Pair { ty, .. } => vec![true, true, crate::alpha::pair_snd_rel(env, ty) == Rel::Rel],
        Transport { .. } => vec![true, true, true, false, true, true],
        Absurd { .. } => vec![true, false],
        Prim { args, proofs, .. } => [vec![true; args.len()], vec![false; proofs.len()]].concat(),
        Rec { args, proof } => [vec![true; args.len()], vec![false; proof.is_some() as usize]].concat(),
        Ctor { ind, ctor, params, args } => {
            [vec![true; params.len()], by(env.ctor_rels(*ind, *ctor).unwrap_or_default(), args.len())].concat()
        }
        Delta { def, args } => by(env.global_param_rels(*def).unwrap_or_default(), args.len()),
        Unfold { def, args, .. } => [by(env.global_param_rels(*def).unwrap_or_default(), args.len()), vec![true]].concat(),
        Axiom { ax, args } => by(crate::axioms::axiom_param_rels(*ax), args.len()),
        _ => vec![true; children(t).len()],
    }
}

/// A node of the reference graph.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub(crate) enum Node {
    G(GlobalId),
    I(IndId),
}

/// The globals and inductives referenced from relevant positions of `ts`
/// (linear in the term DAG; iterative, so deep terms cannot overflow).
fn direct_refs(env: &Env, ts: &[&Tm]) -> Vec<Node> {
    let mut out: BTreeSet<Node> = BTreeSet::new();
    let mut seen: FxSet<usize> = FxSet::default();
    let mut stack: Vec<&Tm> = ts.to_vec();
    while let Some(t) = stack.pop() {
        // Every node is owned by `ts` for the whole walk: addresses are stable.
        if !seen.insert(Rc::as_ptr(t) as *const () as usize) {
            continue;
        }
        match &**t {
            Term::Global(g) | Term::Delta { def: g, .. } | Term::Unfold { def: g, .. } => {
                out.insert(Node::G(*g));
            }
            Term::Ind { ind, .. } | Term::Ctor { ind, .. } | Term::Match { ind, .. } => {
                out.insert(Node::I(*ind));
            }
            _ => {}
        }
        let flags = relevant_children(env, t);
        stack.extend(children(t).into_iter().zip(flags).filter(|(_, r)| *r).map(|((c, _), _)| c));
    }
    out.into_iter().collect()
}

/// The terms of a node's declaration: a global's type and body, an
/// inductive's parameter and field types.
fn decl_terms(env: &Env, n: Node) -> Vec<Tm> {
    match n {
        Node::G(g) => env.defs.get(g.0 as usize).map(|d| vec![d.ty.clone(), d.body.clone()]).unwrap_or_default(),
        Node::I(i) => env
            .inds
            .get(i.0 as usize)
            .map(|d| {
                d.params.iter().map(|p| p.1.clone()).chain(d.ctors.iter().flat_map(|c| c.fields.iter().map(|f| f.2.clone()))).collect()
            })
            .unwrap_or_default(),
    }
}

/// `Refs*(roots)` (DESIGN.md §15.1), not descending into globals of `stop`
/// (which are included, but whose declarations are not explored).
pub(crate) fn closure(env: &Env, roots: &[&Tm], stop: &dyn Fn(GlobalId) -> bool) -> BTreeSet<Node> {
    let mut out = BTreeSet::new();
    let mut work = direct_refs(env, roots);
    while let Some(n) = work.pop() {
        if !out.insert(n) || matches!(n, Node::G(g) if stop(g)) {
            continue;
        }
        let ts = decl_terms(env, n);
        work.extend(direct_refs(env, &ts.iter().collect::<Vec<_>>()));
    }
    out
}

/// The abstraction of a section: members `R` (with the level of their `F'`
/// binder), the stop set, and memos.
struct Abs<'e> {
    env: &'e Env,
    level: FxMap<GlobalId, u32>,
    stop: FxSet<GlobalId>,
    /// Does a node's `Refs*` (not descending into `stop`) meet `R`?
    reach: FxMap<Node, bool>,
    kids: FxMap<Node, Rc<Vec<Node>>>,
    /// λ-lifted bodies by (global, depth at which they are placed).
    lifted: FxMap<(GlobalId, u32), Tm>,
}

/// One placement (see [`Abs::place`]).
struct Place<'a> {
    n: u32,
    vars: &'a [u32],
    abstracted: bool,
    memo: FxMap<(usize, u32, bool), Tm>,
}

impl<'e> Abs<'e> {
    fn name(&self, g: GlobalId) -> String {
        self.env.global_name(g).map(|n| n.to_string()).unwrap_or_else(|| format!("@{}", g.0))
    }

    fn member(&self, n: Node) -> bool {
        matches!(n, Node::G(g) if self.level.contains_key(&g))
    }

    fn kids(&mut self, n: Node) -> Rc<Vec<Node>> {
        if let Some(k) = self.kids.get(&n) {
            return k.clone();
        }
        let ts = decl_terms(self.env, n);
        let k = Rc::new(direct_refs(self.env, &ts.iter().collect::<Vec<_>>()));
        self.kids.insert(n, k.clone());
        k
    }

    /// Does `n` reach `R`: some member in `Refs*` of its declaration, not
    /// descending into `stop`? (Memoized, iterative. Only decides what is
    /// lifted; soundness rests on the final `Refs*` check.)
    fn reaches(&mut self, n: Node) -> bool {
        if matches!(n, Node::G(g) if self.stop.contains(&g)) {
            return false;
        }
        let mut stack = vec![(n, false)];
        let mut open: FxSet<Node> = FxSet::default();
        while let Some((m, expanded)) = stack.pop() {
            if self.reach.contains_key(&m) {
                continue;
            }
            let kids = self.kids(m);
            if expanded {
                let r = kids.iter().any(|&c| self.member(c) || self.reach.get(&c) == Some(&true));
                self.reach.insert(m, r);
                continue;
            }
            open.insert(m);
            stack.push((m, true));
            for &c in kids.iter() {
                let stopped = matches!(c, Node::G(g) if self.stop.contains(&g));
                if !self.member(c) && !stopped && !open.contains(&c) && !self.reach.contains_key(&c) {
                    stack.push((c, false));
                }
            }
        }
        self.reach.get(&n) == Some(&true)
    }

    /// Place `t` at depth `n`: its free variables (level order) become the
    /// variables at levels `vars`. In `abstracted` mode every occurrence of a
    /// member `r` becomes its binder `F_r'` (in every position), and every
    /// occurrence in a relevant position of a global that reaches `R` becomes
    /// its λ-lifted body. Linear in the term DAG.
    fn place(&mut self, t: &Tm, n: u32, vars: &[u32], abstracted: bool) -> KR<Tm> {
        let mut p = Place { n, vars, abstracted, memo: FxMap::default() };
        self.go(&mut p, t, 0, true)
    }

    fn go(&mut self, p: &mut Place<'_>, t: &Tm, local: u32, rel: bool) -> KR<Tm> {
        let key = (Rc::as_ptr(t) as *const () as usize, local, rel);
        let shared = Rc::strong_count(t) > 1;
        if shared && let Some(r) = p.memo.get(&key) {
            return Ok(r.clone());
        }
        let depth = p.n + local;
        let r = match &**t {
            Term::Var(Idx(i)) if *i >= local => {
                let j = (*i - local) as usize;
                let lvl = p.vars.len().checked_sub(j + 1).map(|k| p.vars[k]);
                mk::var(depth - 1 - lvl.ok_or_else(|| kerr(K::IllFormed, "abstract_section: unbound variable in a placed term"))?)
            }
            Term::Global(g) if p.abstracted => match self.level.get(g).copied() {
                Some(l) if l < p.n => mk::var(depth - 1 - l),
                Some(_) => return Err(kerr(K::IllFormed, format!("abstract_section: `{}` occurs before its binder", self.name(*g)))),
                None if rel && self.reaches(Node::G(*g)) => self.lifted_at(*g, depth)?,
                None => t.clone(),
            },
            _ => {
                let kids = children(t);
                let flags = relevant_children(self.env, t);
                let mut out = Vec::with_capacity(kids.len());
                for ((c, k), r) in kids.iter().zip(flags) {
                    out.push(self.go(p, c, local + k, rel && r)?);
                }
                if out.iter().zip(&kids).all(|(a, (b, _))| Rc::ptr_eq(a, b)) { t.clone() } else { rebuild_with(t, out) }
            }
        };
        if shared {
            p.memo.insert(key, r.clone());
        }
        Ok(r)
    }

    /// The body of `g` (a λ telescope) abstracted at `depth`: `g` λ-lifted
    /// over the members and applied to them, β-reduced. Only a spec
    /// definition means its body under every interpretation of the exec
    /// functions; any other global (an exec caller, a loop helper, a lemma)
    /// has a meaning of its own, and inlining its implementation would make
    /// it part of the specification (AUDIT.md §19). A recursive definition
    /// cannot be inlined (the kernel has no fixpoint term).
    fn lifted_at(&mut self, g: GlobalId, depth: u32) -> KR<Tm> {
        if let Some(t) = self.lifted.get(&(g, depth)) {
            return Ok(t.clone());
        }
        let env = self.env;
        let d = &env.defs[g.0 as usize];
        if d.kind != DefKind::Spec {
            return Err(kerr(
                K::IllFormed,
                format!(
                    "`{}` ({:?}) reaches the section but is not a spec definition, so it cannot be λ-lifted \
                     (its implementation is not a specification); establish it in an earlier section or merge it into this one",
                    d.name, d.kind
                ),
            ));
        }
        if d.is_recursive() {
            return Err(kerr(
                K::IllFormed,
                format!(
                    "`{}` is recursive and reaches the section, so it cannot be λ-lifted; add it to the section or \
                     state the hypothesis without it",
                    d.name
                ),
            ));
        }
        let t = self.place(&d.body, depth, &[], true)?;
        self.lifted.insert((g, depth), t.clone());
        Ok(t)
    }
}

/// The levels `< k` (the members' `F'`) of the variables that `t`, placed at
/// depth `depth`, mentions.
fn levels_below(t: &Tm, depth: u32, k: u32) -> BTreeSet<u32> {
    let mut out = BTreeSet::new();
    any_sub(t, 0, &mut |n, l| {
        if let Term::Var(Idx(i)) = &**n
            && let Some(lvl) = (depth + l).checked_sub(1 + i).filter(|lvl| *i >= l && *lvl < k)
        {
            out.insert(lvl);
        }
        false
    });
    out
}

/// Replace the free variables `0..args.len()` of `t` (level order: `args[0]`
/// is the outermost) by `args`.
fn instantiate(t: &Tm, args: &[Tm]) -> Tm {
    let n = args.len() as u32;
    map_post(t, 0, &mut |node, local| match &*node {
        Term::Var(Idx(i)) if *i >= local && *i - local < n => shift(&args[(n - 1 - (*i - local)) as usize], local as i64),
        Term::Var(Idx(i)) if *i >= local => mk::var(*i - n),
        _ => node,
    })
}

/// A binder being added to a statement, checked as the Π rule does.
fn bind(chk: &Checker, cx: &mut Cx, binders: &mut Binders, name: Name, rel: Rel, dom: Tm, b: &mut Budget) -> KR<()> {
    chk.infer_sort(cx, &dom, REL, b)?;
    let dv = chk.eval(cx, &dom, b)?;
    *cx = chk.bind(cx, &name, rel, &dv).0;
    binders.push((name, rel, dom));
    Ok(())
}

fn context(what: &str, e: crate::api::KernelError) -> crate::api::KernelError {
    kerr(e.kind.clone(), format!("abstract_section: {what}: {}", e.message))
}

/// `obs_eq` at type `ty` (DESIGN.md §15.5), or `None` for plain `Eq(ty, x, y)`:
/// through a view whose type is convertible with `ty`; pointwise at a Π type
/// (there is no funext); componentwise at a relevant non-dependent Σ and at
/// a struct-like inductive whose fields do not depend on each other, when
/// some component is not plain. Sets `viewed` if a view is applied anywhere
/// (otherwise `obs_eq` is equality in the set model).
#[allow(clippy::too_many_arguments)]
fn obs(chk: &Checker, cx: &Cx, ty: &Tm, x: &Tm, y: &Tm, views: &[(V, Tm, Tm)], viewed: &mut bool, b: &mut Budget) -> KR<Option<Tm>> {
    let env = chk.env;
    let tv = chk.eval(cx, ty, b)?;
    for (vty, target, map) in views {
        if chk.conv(cx, &tv, vty, b)? {
            *viewed = true;
            return Ok(Some(mk::eq(target.clone(), mk::app(map.clone(), x.clone()), mk::app(map.clone(), y.clone()))));
        }
    }
    let nt = crate::quote::Quoter::typed(env, cx.types()).quote_root(cx.depth(), &tv, None, false);
    let comps: Vec<(Tm, Tm, Tm)> = match &*nt {
        Term::Pi { name, rel, dom, cod } => {
            let cx2 = chk.bind(cx, name, *rel, &chk.eval(cx, dom, b)?).0;
            let app = |f: &Tm| mk::apps(shift(f, 1), [(*rel, mk::var(0))]);
            let (x2, y2) = (app(x), app(y));
            let c = obs(chk, &cx2, cod, &x2, &y2, views, viewed, b)?.unwrap_or_else(|| mk::eq(cod.clone(), x2, y2));
            return Ok(Some(mk::pi(name, *rel, dom.clone(), c)));
        }
        Term::Sigma { snd_rel: Rel::Rel, fst, snd, .. } if !occurs(snd, 0) => {
            vec![(fst.clone(), mk::fst(x.clone()), mk::fst(y.clone())), (shift(snd, -1), mk::snd(x.clone()), mk::snd(y.clone()))]
        }
        Term::Ind { ind, params } if env.inds[ind.0 as usize].struct_like() => {
            let c = &env.inds[ind.0 as usize].ctors[0];
            let names: Vec<Name> = c.fields.iter().map(|f| f.0.clone()).collect();
            let nf = c.fields.len() as u32;
            let mut out = Vec::new();
            for (j, (_, frel, fty)) in c.fields.iter().enumerate() {
                if *frel == Rel::Irr {
                    continue;
                }
                if (0..j as u32).any(|i| occurs(fty, i)) {
                    return Ok(None);
                }
                let fty = instantiate(&shift(fty, -(j as i64)), params);
                let proj = |s: &Tm| {
                    let arms = vec![Arm { names: names.clone(), body: mk::var(nf - 1 - j as u32) }];
                    Rc::new(Term::Match { ind: *ind, params: params.clone(), scrut: s.clone(), motive: shift(&fty, 1), arms })
                };
                out.push((fty.clone(), proj(x), proj(y)));
            }
            out
        }
        _ => return Ok(None),
    };
    let mut cs = Vec::with_capacity(comps.len());
    let mut plain = true;
    for (t, a, c) in comps {
        match obs(chk, cx, &t, &a, &c, views, viewed, b)? {
            Some(o) => {
                plain = false;
                cs.push(o);
            }
            None => cs.push(mk::eq(t, a, c)),
        }
    }
    if plain || cs.is_empty() {
        return Ok(None);
    }
    // The conjunction Σ(_ : c₀). Σ(_ : c₁). … cₙ.
    let mut acc = cs.pop().expect("nonempty");
    while let Some(c) = cs.pop() {
        acc = mk::sigma("_", Rel::Rel, c, shift(&acc, 1));
    }
    Ok(Some(acc))
}

/// Π binders of a statement being built (name, relevance, domain).
type Binders = Vec<(Name, Rel, Tm)>;

/// Split the first `n` Π binders of `ty`.
fn peel(ty: &Tm, n: u32) -> KR<(Binders, Tm)> {
    let mut out = Vec::new();
    let mut t = ty.clone();
    for _ in 0..n {
        let Term::Pi { name, rel, dom, cod } = &*t.clone() else {
            return Err(kerr(K::IllFormed, "abstract_section: a member's type does not start with its parameter telescope"));
        };
        out.push((name.clone(), *rel, dom.clone()));
        t = cod.clone();
    }
    Ok((out, t))
}

fn pis(binders: &[(Name, Rel, Tm)], body: Tm) -> Tm {
    binders.iter().rev().fold(body, |acc, (name, rel, dom)| Rc::new(Term::Pi { name: name.clone(), rel: *rel, dom: dom.clone(), cod: acc }))
}

pub(crate) fn abstract_section(env: &Env, s: &Section<'_>, b: &mut Budget) -> KR<SectionStatements> {
    let bad = |m: String| kerr(K::IllFormed, format!("abstract_section: {m}"));
    let known = |g: &GlobalId| (g.0 as usize) < env.defs.len();
    let mut members: Vec<GlobalId> = s.members.to_vec();
    members.sort();
    members.dedup();
    if members.is_empty() || members.len() != s.members.len() || !members.iter().all(known) {
        return Err(bad("the section must be a nonempty set of distinct, known globals".into()));
    }
    if !s.published.iter().all(|p| members.contains(p)) || s.published.iter().collect::<BTreeSet<_>>().len() != s.published.len() {
        return Err(bad("the published functions must be distinct members of the section".into()));
    }
    // Only an exec function can be established (fully specified in an
    // earlier section); stopping `Refs*` at a spec definition would hide
    // what its body reaches.
    let exec = |g: &GlobalId| known(g) && matches!(env.defs[g.0 as usize].kind, DefKind::Exec | DefKind::LoopHelper);
    if !s.established.iter().all(exec) || s.established.iter().any(|g| members.contains(g)) {
        return Err(bad("the established functions must be known exec functions outside the section".into()));
    }
    let k = members.len() as u32;
    let mut abs = Abs {
        env,
        level: members.iter().enumerate().map(|(i, g)| (*g, i as u32)).collect(),
        stop: s.established.iter().copied().collect(),
        reach: FxMap::default(),
        kids: FxMap::default(),
        lifted: FxMap::default(),
    };
    let chk = Checker::new(env);
    let mut cx = Cx::default();
    let mut binders: Binders = Vec::new();
    // The abstracted parts, which must not reach `R` (checked at the end).
    let mut parts: Vec<(String, Tm)> = Vec::new();

    // The functions: F_j' : T_j[F'<j]. Members are ordered by id, and a
    // type mentions only earlier globals, so this order extends the
    // requires-reference DAG.
    for (j, r) in members.iter().enumerate() {
        let what = format!("the type of member `{}`", abs.name(*r));
        let d = &env.defs[r.0 as usize];
        let ty = abs.place(&d.ty, j as u32, &[], true).map_err(|e| context(&what, e))?;
        let short = d.name.rsplit("::").next().unwrap_or("f");
        bind(&chk, &mut cx, &mut binders, Rc::from(format!("{short}'")), Rel::Rel, ty.clone(), b).map_err(|e| context(&what, e))?;
        parts.push((what, ty));
    }
    // The hypotheses: statements of lemmas of the environment, abstracted;
    // a restatement may differ from the abstraction only in irrelevant
    // positions (proofs re-established in the abstracted context).
    for (i, h) in s.hyps.iter().enumerate() {
        if !known(&h.lemma) {
            return Err(bad(format!("hypothesis {i} is not a known global")));
        }
        let what = format!("hypothesis {i} (`{}`)", abs.name(h.lemma));
        let stmt = abs.place(&env.defs[h.lemma.0 as usize].ty, k + i as u32, &[], true).map_err(|e| context(&what, e))?;
        let stmt = match &h.restated {
            None => stmt,
            Some(r) if env.alpha_eq_relevant(r, &stmt, &|a, c| a == c) => r.clone(),
            Some(_) => return Err(bad(format!("{what}: the restatement differs from the abstracted statement in a relevant position"))),
        };
        bind(&chk, &mut cx, &mut binders, Rc::from(format!("h{i}")), Rel::Rel, stmt.clone(), b).map_err(|e| context(&what, e))?;
        parts.push((what, stmt));
    }
    // The views: closed maps `ty -> target` with `target : Type`.
    let mut views = Vec::with_capacity(s.views.len());
    for (i, v) in s.views.iter().enumerate() {
        let what = format!("view {i}");
        let c0 = Cx::default();
        let r: KR<()> = (|| {
            chk.infer_sort(&c0, &v.ty, REL, b)?;
            if chk.infer_sort(&c0, &v.target, REL, b)? != Sort::Type {
                return Err(bad("its target must be a Type".into()));
            }
            chk.check(&c0, &v.map, &chk.eval(&c0, &mk::arrow(v.ty.clone(), v.target.clone()), b)?, REL, b)
        })();
        r.map_err(|e| context(&what, e))?;
        views.push((chk.eval(&c0, &v.ty, b)?, v.target.clone(), v.map.clone()));
        parts.extend([(what.clone(), v.ty.clone()), (what.clone(), v.target.clone()), (what, v.map.clone())]);
    }

    // One statement per published function. `exact`: the published members
    // whose `obs_eq` is equality (no view); `split_on`: the members
    // occurring in a split requires, with where.
    let mut statements = Vec::with_capacity(s.published.len());
    let (mut exact, mut split_on): (FxSet<GlobalId>, Vec<(GlobalId, String)>) = Default::default();
    for p in s.published {
        let pname = abs.name(*p);
        let d = &env.defs[p.0 as usize];
        let (tel, out) = peel(&d.ty, d.arity)?;
        let (mut cxp, mut bs) = (cx.clone(), binders.clone());
        // Levels of the F'-side and real-side versions of each parameter.
        let (mut va, mut vr): (Vec<u32>, Vec<u32>) = (Vec::new(), Vec::new());
        for (name, rel, dom) in &tel {
            let what = format!("parameter `{name}` of `{pname}`");
            let n = bs.len() as u32;
            let da = abs.place(dom, n, &va, true).map_err(|e| context(&what, e))?;
            let in_req = levels_below(&da, n, k);
            let split = !in_req.is_empty();
            if split && *rel == Rel::Rel {
                return Err(bad(format!("{what}: its type depends on the section")));
            }
            bind(&chk, &mut cxp, &mut bs, name.clone(), *rel, da.clone(), b).map_err(|e| context(&what, e))?;
            va.push(n);
            if split {
                // A requires that mentions the section: `F_p'` gets a proof of
                // the abstracted proposition, `p` one of its own.
                let dr = abs.place(dom, n + 1, &vr, false)?;
                bind(&chk, &mut cxp, &mut bs, Rc::from(format!("{name}'")), Rel::Irr, dr, b).map_err(|e| context(&what, e))?;
                split_on.extend(in_req.into_iter().map(|l| (members[l as usize], what.clone())));
            }
            vr.push(bs.len() as u32 - 1);
            parts.push((what, da));
        }
        let n = bs.len() as u32;
        let what = format!("the result type of `{pname}`");
        let out_a = abs.place(&out, n, &va, true).map_err(|e| context(&what, e))?;
        if !levels_below(&out_a, n, k).is_empty() {
            return Err(bad(format!("{what} depends on the section")));
        }
        let args = |levels: &[u32]| tel.iter().zip(levels).map(|((_, rel, _), l)| (*rel, mk::var(n - 1 - l))).collect::<Vec<_>>();
        let lhs = mk::apps(mk::var(n - 1 - abs.level[p]), args(&va));
        let rhs = mk::apps(mk::global(*p), args(&vr));
        let mut viewed = false;
        let concl = obs(&chk, &cxp, &out_a, &lhs, &rhs, &views, &mut viewed, b)
            .map_err(|e| context(&what, e))?
            .unwrap_or_else(|| mk::eq(out_a.clone(), lhs, rhs));
        if !viewed {
            exact.insert(*p);
        }
        chk.infer_sort(&cxp, &concl, REL, b).map_err(|e| context(&format!("the conclusion for `{pname}`"), e))?;
        parts.push((what, out_a));
        statements.push(pis(&bs, concl));
    }

    // A split requires compares `F_p'` and `p` on the inputs valid for both
    // (the abstracted and the real requires). These coincide under the
    // hypotheses only if each member in it is determined exactly, by its
    // own statement: published, with `obs_eq` equality (AUDIT.md §19).
    if let Some((q, what)) = split_on.iter().find(|(q, _)| !exact.contains(q)) {
        return Err(bad(format!(
            "{what}: its requires mentions section member `{}`, which must be published, with an observational equality that uses no view",
            abs.name(*q)
        )));
    }

    // Refs* of the abstracted parts must not meet R (every occurrence
    // abstracted, nothing reachable through a definition either).
    let stop = |g: GlobalId| abs.stop.contains(&g);
    let refs = closure(env, &parts.iter().map(|p| &p.1).collect::<Vec<_>>(), &stop);
    if members.iter().any(|r| refs.contains(&Node::G(*r))) {
        for (what, t) in &parts {
            let one = closure(env, &[t], &stop);
            if let Some(r) = members.iter().find(|r| one.contains(&Node::G(**r))) {
                return Err(bad(format!("{what} still depends on section member `{}`", abs.name(*r))));
            }
        }
        return Err(bad("the statement still depends on the section".into()));
    }
    // `deps`: that `Refs*`, plus the λ-lifted (spec) globals and what their
    // declarations reach outside `R` (DESIGN.md §15.5 computes `Deps(R)` on
    // the hypotheses before lifting).
    let lifted: Vec<Tm> = abs.lifted.keys().map(|(g, _)| *g).collect::<BTreeSet<_>>().into_iter().map(mk::global).collect();
    let stop_or_member = |g: GlobalId| stop(g) || abs.level.contains_key(&g);
    let deps = refs
        .into_iter()
        .chain(closure(env, &lifted.iter().collect::<Vec<_>>(), &stop_or_member))
        .filter_map(|n| if let Node::G(g) = n { Some(g) } else { None })
        .filter(|g| !abs.level.contains_key(g))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Ok(SectionStatements { statements, members, deps })
}
