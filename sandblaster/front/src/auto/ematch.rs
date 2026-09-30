//! Rules: instantiation of lemmas and ∀-facts by matching (DESIGN.md §8.1
//! steps 3–4 and 7; §13.9 E-matching and conditional simp sets).
//!
//! A *rule* is a proof whose type is a Π telescope ending in a proposition:
//! a registered prelude lemma ([`super::lemmas::LemmaDb`], by role), an
//! `eq_sound` lemma of the elaborator, or a ∀-fact of the context. A rule is
//! **opened** by instantiating its binders with metavariables (neutral
//! variables far above the context, [`META_BASE`]); a pattern (the
//! conclusion, one of its sides, a hypothesis, or a subterm) is **matched**
//! against a ground value (structurally, with conversion for meta-free
//! parts); the rule is then **instantiated** with the matched data, its
//! remaining hypotheses proved (bounded search) or taken from facts, and
//! the result's conclusion re-checked by conversion.
//!
//! Roles:
//! * `Backward` — the conclusion matches the target; hypotheses become
//!   subgoals (e.g. `array_eq_sound`, `eq_sound`, extensionality);
//! * `Forward` — the first hypothesis matches a new fact; the conclusion
//!   becomes a fact (e.g. method facts on `split_at_checked(..) = Some(..)`);
//! * `Rewrite` — an equation `lhs = rhs` whose `lhs` matches a subterm of the
//!   target rewrites it (conditional simp lemmas: hypotheses must be
//!   provable);
//! * `Linarith` — an arithmetic conclusion whose subterm matches a linarith
//!   atom is added as a hypothesis (length lemmas, `as_chunks` facts).
//!
//! `exists` targets use the same matcher: the witnesses are metavariables
//! bound by matching the body's conjuncts against facts.

use std::rc::Rc;

use sandblaster_kernel::axioms;
use sandblaster_kernel::term::{Lvl, Rel, Term, Tm};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::{Arg, Closure, Elim, EnvEntry, Head, Neutral, V, VEnv, Value};

use super::arith::Hyp;
use super::lemmas::Role;
use super::search::{Cont, Engine, R};
use super::state::{Fact, Origin, St};
use super::util::*;

/// A rule opened with metavariables.
#[derive(Clone, Debug)]
pub struct Opened {
    pub binders: Vec<OBinder>,
    pub concl: V,
    pub base: u32,
}

#[derive(Clone, Debug)]
pub struct OBinder {
    pub rel: Rel,
    pub ty: V,
    pub prop: bool,
}

/// A rule: its proof head (a term at the state's depth) and type.
#[derive(Clone, Debug)]
pub struct RuleSrc {
    pub head: Tm,
    pub ty: V,
    pub name: String,
}

/// The first metavariable offset of the shared opened linarith rules
/// ([`Engine::lin_rules`]): above any engine's own allocations.
pub const LIN_META_BASE: u32 = 1 << 26;

/// The opened linarith rules shared by the engines of a thread, by
/// (environment address, depth), with the rule set they were opened from.
struct LinRules {
    next: u32,
    rules: std::collections::HashMap<(usize, u32), (Vec<sandblaster_kernel::term::GlobalId>, Rc<Vec<LinRule>>)>,
}

thread_local! {
    static LIN_RULES: std::cell::RefCell<LinRules> = std::cell::RefCell::new(LinRules { next: LIN_META_BASE, rules: std::collections::HashMap::new() });
}

/// Empties the shared opened rules (a new environment: the optimizer's
/// start and end).
pub fn reset_lin_rules() {
    LIN_RULES.with(|m| *m.borrow_mut() = LinRules { next: LIN_META_BASE, rules: std::collections::HashMap::new() });
}

/// A linarith-role rule opened at some depth, with its triggers.
pub struct LinRule {
    pub src: RuleSrc,
    pub op: Opened,
    pub triggers: Vec<V>,
}

impl<'a> Engine<'a> {
    /// Allocate a fresh range of metavariable indices.
    fn meta_base(&mut self, n: u32) -> u32 {
        let b = self.meta_next;
        self.meta_next += n + 1;
        b
    }

    /// Open a Π telescope with metavariables.
    pub fn open(&mut self, ty: &V, depth: u32) -> R<Option<Opened>> {
        let base = self.meta_base(64);
        let mut cur = ty.clone();
        let mut binders = Vec::new();
        let mut i = 0u32;
        while let Value::Pi { rel, dom, cod, .. } = &*cur.clone() {
            if i >= 64 {
                return Ok(None);
            }
            let prop = self.is_prop(dom, depth);
            let meta = neu_var(META_BASE + base + i);
            let entry = match rel {
                Rel::Rel => EnvEntry::Rel(meta),
                Rel::Irr => EnvEntry::Irr(Closure { env: VEnv(Rc::new(vec![EnvEntry::Rel(meta)])), body: mk::var(0) }),
            };
            binders.push(OBinder { rel: *rel, ty: dom.clone(), prop });
            let Some(next) = self.inst(cod, vec![entry], depth)? else { return Ok(None) };
            cur = next;
            i += 1;
        }
        Ok(Some(Opened { binders, concl: cur, base }))
    }

    /// Match a pattern (with metavariables `META_BASE + base + i`) against a
    /// ground value, extending `sub`.
    pub fn pmatch(&mut self, depth: u32, pat: &V, v: &V, base: u32, sub: &mut Vec<Option<V>>) -> R<bool> {
        // E-matching is charged per visited pattern node (auto::meter)
        if !super::meter::spend(1) {
            return Err(super::search::Stop::Budget);
        }
        if let Some(l) = as_var(pat)
            && l >= META_BASE + base
            && ((l - META_BASE - base) as usize) < sub.len()
        {
            let i = (l - META_BASE - base) as usize;
            if self.ground_has_meta(v) {
                return Ok(false);
            }
            return match &sub[i] {
                Some(b) => {
                    let b = b.clone();
                    self.conv(depth, &b, v)
                }
                None => {
                    sub[i] = Some(v.clone());
                    Ok(true)
                }
            };
        }
        if !self.ground_has_meta(pat) {
            return self.conv(depth, pat, v);
        }
        // `to_int(?m)` (a widening cast of a metavariable) against a literal:
        // bind `?m` to the literal at its width.
        if let (Some((sandblaster_kernel::term::PrimOp::Cast { from, to }, args)), Some((_, n))) = (as_prim(pat), lit(v))
            && sandblaster_kernel::prim::prim_sig(sandblaster_kernel::term::PrimOp::Cast { from, to }).is_some()
            && from.bits().is_some_and(|b| to.bits().is_none_or(|t| t >= b))
            && n >= &num_bigint::BigInt::from(0)
            && n <= &sandblaster_kernel::prim::max_of(from)
        {
            let lv = Rc::new(Value::Lit { w: from, n: n.clone() });
            return self.pmatch(depth, &args[0], &lv, base, sub);
        }
        // `fst(?a)` against the list of an eta-expanded array variable `x`
        // (`[index(fst x, 0), .., index(fst x, N-1)]`, DESIGN.md §5.9): bind
        // `?a` to the eta-expanded `x`.
        if let (Value::Neu(p), Value::Ctor { .. }) = (&**pat, &**v)
            && let Head::Var(l) = &p.head
            && l.0 >= META_BASE + base
            && ((l.0 - META_BASE - base) as usize) < sub.len()
            && p.spine.len() == 1
            && matches!(p.spine[0], Elim::Fst)
            && let Some(x) = self.eta_array_of_list(v)
        {
            let mv = neu_var(l.0);
            return self.pmatch(depth, &mv, &x, base, sub);
        }
        // A metavariable head with eliminators (`fst(?s)`): bind it to the
        // matching prefix of the value, then match the eliminators.
        if let (Value::Neu(p), Value::Neu(q)) = (&**pat, &**v)
            && let Head::Var(l) = &p.head
            && l.0 >= META_BASE + base
            && ((l.0 - META_BASE - base) as usize) < sub.len()
            && !p.spine.is_empty()
            && q.spine.len() >= p.spine.len()
        {
            let cut = q.spine.len() - p.spine.len();
            let pre = prefix(q, cut);
            let mv = neu_var(l.0);
            if !self.pmatch(depth, &mv, &pre, base, sub)? {
                return Ok(false);
            }
            for (e1, e2) in p.spine.iter().zip(&q.spine[cut..]) {
                if !self.pmatch_elim(depth, e1, e2, base, sub)? {
                    return Ok(false);
                }
            }
            return Ok(true);
        }
        match (&**pat, &**v) {
            (Value::Neu(p), Value::Neu(q)) => {
                if p.spine.len() != q.spine.len() {
                    return Ok(false);
                }
                let heads = match (&p.head, &q.head) {
                    (Head::Var(a), Head::Var(b)) => a == b,
                    (Head::Global { def: d1, args: a1 }, Head::Global { def: d2, args: a2 }) => {
                        if d1 != d2 || a1.len() != a2.len() {
                            return Ok(false);
                        }
                        for (x, y) in a1.iter().zip(a2) {
                            if let (Arg::Rel(x), Arg::Rel(y)) = (x, y)
                                && !self.pmatch(depth, x, y, base, sub)?
                            {
                                return Ok(false);
                            }
                        }
                        true
                    }
                    (Head::Prim { op: o1, args: a1, .. }, Head::Prim { op: o2, args: a2, .. }) => {
                        if o1 != o2 || a1.len() != a2.len() {
                            return Ok(false);
                        }
                        for (x, y) in a1.iter().zip(a2) {
                            if !self.pmatch(depth, x, y, base, sub)? {
                                return Ok(false);
                            }
                        }
                        true
                    }
                    _ => false,
                };
                if !heads {
                    return Ok(false);
                }
                for (e1, e2) in p.spine.iter().zip(&q.spine) {
                    if !self.pmatch_elim(depth, e1, e2, base, sub)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            (Value::Ctor { ind: i1, ctor: c1, params: p1, args: a1 }, Value::Ctor { ind: i2, ctor: c2, params: p2, args: a2 }) => {
                if i1 != i2 || c1 != c2 || a1.len() != a2.len() {
                    return Ok(false);
                }
                for (x, y) in p1.iter().zip(p2) {
                    if !self.pmatch(depth, x, y, base, sub)? {
                        return Ok(false);
                    }
                }
                for (j, (x, y)) in a1.iter().zip(a2).enumerate() {
                    if let (Arg::Rel(x), Arg::Rel(y)) = (x, y) {
                        // a constructor pattern against a neutral field: its
                        // η-expansion, at the field's type (struct η)
                        let y = if matches!(&**x, Value::Ctor { .. })
                            && matches!(&**y, Value::Neu(_))
                            && let Some(fty) = self.ctor_field_ty(depth, *i2, *c2, p2, a2, j)?
                        {
                            self.eta_struct(depth, x, y, &fty)?.unwrap_or_else(|| y.clone())
                        } else {
                            y.clone()
                        };
                        if !self.pmatch(depth, x, &y, base, sub)? {
                            return Ok(false);
                        }
                    }
                }
                Ok(true)
            }
            (Value::Pair { fst: f1, snd: s1 }, Value::Pair { fst: f2, snd: s2 }) => {
                if !self.pmatch(depth, f1, f2, base, sub)? {
                    return Ok(false);
                }
                match (s1, s2) {
                    (Arg::Rel(x), Arg::Rel(y)) => self.pmatch(depth, x, y, base, sub),
                    _ => Ok(true),
                }
            }
            (Value::Eq { ty: t1, lhs: l1, rhs: r1 }, Value::Eq { ty: t2, lhs: l2, rhs: r2 }) => {
                if !self.pmatch(depth, t1, t2, base, sub)? {
                    return Ok(false);
                }
                // a constructor pattern against a neutral side: its
                // η-expansion at the equation's type (struct η)
                let l2 = self.eta_struct(depth, l1, l2, t2)?.unwrap_or_else(|| l2.clone());
                if !self.pmatch(depth, l1, &l2, base, sub)? {
                    return Ok(false);
                }
                let r2 = self.eta_struct(depth, r1, r2, t2)?.unwrap_or_else(|| r2.clone());
                self.pmatch(depth, r1, &r2, base, sub)
            }
            (Value::Ind { ind: i1, params: p1 }, Value::Ind { ind: i2, params: p2 }) => {
                if i1 != i2 || p1.len() != p2.len() {
                    return Ok(false);
                }
                for (x, y) in p1.iter().zip(p2) {
                    if !self.pmatch(depth, x, y, base, sub)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            (Value::Sigma { fst: f1, snd: s1, snd_rel: r1, .. }, Value::Sigma { fst: f2, snd: s2, snd_rel: r2, .. }) if r1 == r2 => {
                if !self.pmatch(depth, f1, f2, base, sub)? {
                    return Ok(false);
                }
                // Compare the second components under a fresh variable.
                let x = self.env.fresh_var(Lvl(depth), Rel::Rel, f2);
                let (Some(b1), Some(b2)) = (self.inst(s1, vec![x.clone()], depth + 1)?, self.inst(s2, vec![x], depth + 1)?) else {
                    return Ok(false);
                };
                self.pmatch(depth + 1, &b1, &b2, base, sub)
            }
            (Value::Lam { rel: r1, dom: d1, body: b1, .. }, Value::Lam { rel: r2, dom: d2, body: b2, .. })
            | (Value::Pi { rel: r1, dom: d1, cod: b1, .. }, Value::Pi { rel: r2, dom: d2, cod: b2, .. })
                if r1 == r2 =>
            {
                // Binders: domains, then bodies under a fresh variable.
                if !self.pmatch(depth, d1, d2, base, sub)? {
                    return Ok(false);
                }
                let x = self.env.fresh_var(Lvl(depth), *r1, d2);
                let (Some(v1), Some(v2)) = (self.inst(b1, vec![x.clone()], depth + 1)?, self.inst(b2, vec![x], depth + 1)?) else {
                    return Ok(false);
                };
                self.pmatch(depth + 1, &v1, &v2, base, sub)
            }
            _ => Ok(false),
        }
    }

    /// Struct η for patterns: a constructor pattern `C(p̄)` of a struct-like
    /// inductive (one constructor, not recursive, relevant fields) against a
    /// neutral `n : D(ps)` (`ty`) matches as against `C(ps; π₀ n, …, πₖ n)`,
    /// which the kernel's conversion identifies with `n` (struct η) — so an
    /// instance built from it still checks against the original fact (see
    /// [`Engine::instantiate`]). The projections are the elaborator's
    /// (`match n return Tₖ with C(x̄) => xₖ`, `Tₖ` the field's type), so they
    /// read back to the same terms as the program's own projections.
    ///
    /// This is how a path equation `s.split_first() == Some(p)` triggers
    /// `slice::split_first_some` when the tuple is destructured later
    /// (`let Some((h, t)) = s.split_first() else ..`, `let (h, t) =
    /// s.split_first()?`: the pattern compiler projects tuples, so the
    /// equation never mentions `tuple2(h, t)`), with `x := π₀ p`, `rest :=
    /// π₁ p` — the facts `0 < s.len()` and `t.len() == s.len() − 1` then
    /// close a `decreases(s.len())` obligation by linarith.
    /// `None` when `pat` is not such a constructor or `v` is not neutral.
    fn eta_struct(&mut self, depth: u32, pat: &V, v: &V, ty: &V) -> R<Option<V>> {
        let (Value::Ctor { ind: pi, .. }, Value::Neu(n), Value::Ind { ind, params }) = (&**pat, &**v, &**ty) else { return Ok(None) };
        if pi != ind || self.env.inductive_is_recursive(*ind) != Some(false) {
            return Ok(None);
        }
        let Some(decl) = self.env.inductive_decl(*ind) else { return Ok(None) };
        if decl.ctors.len() != 1 || decl.params.len() != params.len() || decl.ctors[0].fields.iter().any(|f| f.1 != Rel::Rel) {
            return Ok(None);
        }
        let fields = &decl.ctors[0].fields;
        let nf = fields.len();
        // field types in the context `params, fields before`: the earlier
        // fields are their projections
        let mut env: Vec<EnvEntry> = params.iter().map(|p| EnvEntry::Rel(p.clone())).collect();
        let mut args = Vec::with_capacity(nf);
        for (k, (_, _, fty)) in fields.iter().enumerate() {
            let c = Closure { env: VEnv(Rc::new(env.clone())), body: fty.clone() };
            let Some(fty_v) = self.inst(&c, vec![], depth)? else { return Ok(None) };
            let proj = Elim::Match {
                ind: *ind,
                params: params.clone(),
                motive: Closure { env: VEnv(Rc::new(vec![EnvEntry::Rel(fty_v)])), body: mk::var(1) },
                arms: vec![Closure { env: VEnv::default(), body: mk::var((nf - 1 - k) as u32) }],
            };
            let mut spine: Vec<Elim> = n.spine.iter().map(clone_elim).collect();
            spine.push(proj);
            let pv: V = Rc::new(Value::Neu(Neutral { head: clone_head(&n.head), spine }));
            env.push(EnvEntry::Rel(pv.clone()));
            args.push(Arg::Rel(pv));
        }
        Ok(Some(Rc::new(Value::Ctor { ind: *ind, ctor: 0, params: params.clone(), args })))
    }

    /// The type of field `j` of the constructor value `ctor(params; args)`
    /// of `ind` (its declared type, in the context of the parameters and
    /// the earlier fields); `None` when an earlier field is irrelevant.
    fn ctor_field_ty(&mut self, depth: u32, ind: sandblaster_kernel::term::IndId, ctor: u32, params: &[V], args: &[Arg], j: usize) -> R<Option<V>> {
        let Some(decl) = self.env.inductive_decl(ind) else { return Ok(None) };
        let Some(c) = decl.ctors.get(ctor as usize) else { return Ok(None) };
        let Some((_, _, fty)) = c.fields.get(j) else { return Ok(None) };
        if decl.params.len() != params.len() || args.len() < j {
            return Ok(None);
        }
        let mut env: Vec<EnvEntry> = params.iter().map(|p| EnvEntry::Rel(p.clone())).collect();
        for a in &args[..j] {
            let Arg::Rel(v) = a else { return Ok(None) };
            env.push(EnvEntry::Rel(v.clone()));
        }
        self.inst(&Closure { env: VEnv(Rc::new(env)), body: fty.clone() }, vec![], depth)
    }

    /// If `v` is the list `[index(T, fst x, 0), .., index(T, fst x, N-1)]`
    /// of an eta-expanded array variable `x` (as the kernel builds it), the
    /// eta-expanded `x` itself: `(v, snd x)`.
    fn eta_array_of_list(&self, v: &V) -> Option<V> {
        let x = self.eta_list_var(v)?;
        let snd = Closure {
            env: VEnv(Rc::new(vec![EnvEntry::Rel(neu_var(x.0))])),
            body: Rc::new(Term::Snd(Rc::new(Term::Var(sandblaster_kernel::term::Idx(0))))),
        };
        Some(Rc::new(Value::Pair { fst: v.clone(), snd: Arg::Irr(snd) }))
    }

    /// The variable `x` if `v` is the list `[index(T, fst x, 0), ..,
    /// index(T, fst x, N-1)]` of its eta expansion.
    pub fn eta_list_var(&self, v: &V) -> Option<Lvl> {
        let index = self.n.seq_index?;
        let list = self.n.list?;
        let mut cur = v.clone();
        let mut k = 0u64;
        let mut var: Option<Lvl> = None;
        loop {
            let next = match &*cur {
                Value::Ctor { ind, args, .. } if *ind == list && args.is_empty() => break,
                Value::Ctor { ind, args, .. } if *ind == list && args.len() == 2 => {
                    let (Arg::Rel(h), Arg::Rel(t)) = (&args[0], &args[1]) else { return None };
                    let Value::Neu(Neutral { head: Head::Global { def, args: ia }, spine }) = &**h else { return None };
                    if *def != index || !spine.is_empty() || ia.len() != 5 {
                        return None;
                    }
                    let (Arg::Rel(lst), Arg::Rel(kv)) = (&ia[1], &ia[2]) else { return None };
                    let Value::Neu(Neutral { head: Head::Var(x), spine: sp }) = &**lst else { return None };
                    if sp.len() != 1 || !matches!(sp[0], Elim::Fst) || var.is_some_and(|y| y != *x) {
                        return None;
                    }
                    var = Some(*x);
                    if lit(kv).and_then(|(_, n)| u64::try_from(n.clone()).ok()) != Some(k) {
                        return None;
                    }
                    k += 1;
                    t.clone()
                }
                _ => return None,
            };
            cur = next;
        }
        var
    }

    /// Match one eliminator of a neutral spine.
    fn pmatch_elim(&mut self, depth: u32, e1: &Elim, e2: &Elim, base: u32, sub: &mut Vec<Option<V>>) -> R<bool> {
        Ok(match (e1, e2) {
            (Elim::App(Arg::Rel(x)), Elim::App(Arg::Rel(y))) => self.pmatch(depth, x, y, base, sub)?,
            (Elim::App(Arg::Irr(_)), Elim::App(Arg::Irr(_))) | (Elim::Fst, Elim::Fst) | (Elim::Snd, Elim::Snd) => true,
            (Elim::Match { ind: i1, params: p1, arms: a1, .. }, Elim::Match { ind: i2, params: p2, arms: a2, .. }) => {
                if i1 != i2 || a1.len() != a2.len() {
                    return Ok(false);
                }
                for (x, y) in p1.iter().zip(p2) {
                    if !self.pmatch(depth, x, y, base, sub)? {
                        return Ok(false);
                    }
                }
                // Arms are matched best-effort: they may differ only in
                // proof components, which structural matching cannot see
                // through. Instances are re-checked by conversion (see
                // `instantiate`), so a failed arm match only forgoes its
                // bindings.
                let snapshot = sub.clone();
                if !self.pmatch_arms(depth, *i1, a1, a2, base, sub)? {
                    *sub = snapshot;
                }
                true
            }
            _ => false,
        })
    }

    /// Match the arms of two stuck matches on `ind`: instantiate both with
    /// the same fresh field variables and match the bodies.
    fn pmatch_arms(
        &mut self,
        depth: u32,
        ind: sandblaster_kernel::term::IndId,
        a1: &[Closure],
        a2: &[Closure],
        base: u32,
        sub: &mut Vec<Option<V>>,
    ) -> R<bool> {
        let Some(decl) = self.env.inductive_decl(ind) else { return Ok(false) };
        for (k, (c1, c2)) in a1.iter().zip(a2).enumerate() {
            let nf = decl.ctors.get(k).map(|c| c.fields.len()).unwrap_or(0) as u32;
            let es: Vec<EnvEntry> = (0..nf).map(|j| EnvEntry::Rel(neu_var(depth + j))).collect();
            let (Some(b1), Some(b2)) = (self.inst(c1, es.clone(), depth + nf)?, self.inst(c2, es, depth + nf)?) else { return Ok(false) };
            if !self.pmatch(depth + nf, &b1, &b2, base, sub)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Instantiate a rule's telescope: data binders from `sub`, hypotheses
    /// from `hyp_proofs` or proved (bounded). Returns the proof and its
    /// conclusion.
    pub fn instantiate(
        &mut self,
        st: &St,
        head: &Tm,
        ty: &V,
        sub: &[Option<V>],
        hyp_proofs: &[Option<Tm>],
        lin: Option<&[Hyp]>,
    ) -> R<Option<(Tm, V)>> {
        let mut cur = ty.clone();
        let mut args = Vec::new();
        let mut i = 0usize;
        let d = st.depth();
        while let Value::Pi { rel, dom, cod, .. } = &*cur.clone() {
            // lemma instantiation: charged per binder
            if !super::meter::spend(1) {
                return Err(super::search::Stop::Budget);
            }
            let prop = self.is_prop(dom, d);
            let (tm, entry) = if !prop {
                let Some(Some(v)) = sub.get(i) else { return Ok(None) };
                let tm = st.quote_at(self.env, v, dom);
                let e = match rel {
                    Rel::Rel => EnvEntry::Rel(v.clone()),
                    Rel::Irr => irr_entry(&st.venv, &tm),
                };
                (tm, e)
            } else {
                let p = match hyp_proofs.get(i).cloned().flatten() {
                    Some(p) => {
                        // A fact matched against the hypothesis pattern:
                        // check that it has the instantiated type.
                        match self.infer_irr(st, &p)? {
                            Some(pt) if self.conv(d, &pt, dom)? => p,
                            _ => return Ok(None),
                        }
                    }
                    None => match self.prove_hyp(st, dom, lin)? {
                        Some(p) => p,
                        None => return Ok(None),
                    },
                };
                // A proof is bound as its term even for a relevant binder
                // (see `Engine::entry_for`): an equation proof evaluates to
                // `refl`, and a statement that passes the hypothesis to an
                // irrelevant argument (`seq::index l i .h0 .h1` in
                // `seq::get_index`) would read back `refl(Bool, c)` where
                // `c == true` is needed (the kernel forces the closure where a
                // relevant position reads it).
                let e = irr_entry(&st.venv, &p);
                (p, e)
            };
            args.push((*rel, tm));
            let Some(next) = self.inst(cod, vec![entry], d)? else { return Ok(None) };
            cur = next;
            i += 1;
        }
        Ok(Some((apps(head.clone(), args), cur)))
    }

    /// Prove a rule hypothesis: linarith with the given hypotheses, else a
    /// shallow search (no case splits, bounded rule nesting).
    fn prove_hyp(&mut self, st: &St, h: &V, lin: Option<&[Hyp]>) -> R<Option<Tm>> {
        // By conversion or a fact.
        if let Some((a, l, r)) = as_eq(h)
            && self.conv(st.depth(), l, r)?
        {
            return Ok(Some(mk::refl(self.quote(st, a), st.quote_at(self.env, l, a))));
        }
        super::meter::spend(st.facts.len() as u64);
        for f in st.facts.iter().rev() {
            if self.conv(st.depth(), &f.ty, h)? {
                return Ok(Some(st.var(f.lvl)));
            }
        }
        if let Some(hs) = lin {
            if self.lin_goal_form(h) {
                return self.lin_with(st, hs, h);
            }
            return Ok(None);
        }
        // an arithmetic hypothesis (the bounds of the `Seq` rewrite rules):
        // linarith, so the instance carries a certificate rather than a
        // searched proof (also below the rule nesting limit)
        if self.lin_goal_form(h)
            && let Some(p) = self.lin_prove(st, h, true)?
        {
            return Ok(Some(p));
        }
        if self.rule_depth >= 2 {
            return Ok(None);
        }
        self.rule_depth += 1;
        let mut c = st.child();
        c.depth_left = 0;
        let r = self.solve(&c, h.clone(), true);
        self.rule_depth -= 1;
        r
    }

    /// Rules of a role: registered lemmas, plus ∀-facts for backward and
    /// forward chaining.
    pub fn rules(&mut self, st: &St, role: Role) -> Vec<RuleSrc> {
        self.rules_where(st, role, &|_| true)
    }

    /// [`Self::rules`] with the registered rules filtered by `keep` before
    /// their types are computed (the trigger gates: a rule whose head the
    /// target lacks costs no evaluation).
    fn rules_where(&mut self, st: &St, role: Role, keep: &dyn Fn(&super::lemmas::RuleEntry) -> bool) -> Vec<RuleSrc> {
        super::meter::spend((self.db.rules.len() + st.facts.len()) as u64);
        let mut out = Vec::new();
        for r in self.db.rules.iter().filter(|r| r.roles.contains(&role) && keep(r)) {
            if let Some(ty) = self.env.global_type_value(r.g) {
                out.push(RuleSrc { head: mk::global(r.g), ty, name: r.name.clone() });
            }
        }
        // `by_arithmetic()` / `by_unfolding(..)`: the built-in theory only,
        // no instantiation of the context's quantified facts
        if matches!(role, Role::Backward | Role::Forward) && self.cfg.mode.allows_forall_facts() {
            for f in &st.facts {
                if matches!(&*f.ty, Value::Pi { .. }) {
                    out.push(RuleSrc { head: st.var(f.lvl), ty: f.ty.clone(), name: format!("∀-fact h{}", f.lvl) });
                }
            }
        }
        out
    }

    /// Bind remaining data metavariables by matching hypotheses against
    /// facts. Returns whether every data binder is bound.
    fn bind_hyps_from_facts(&mut self, st: &St, op: &Opened, sub: &mut Vec<Option<V>>, hp: &mut [Option<Tm>]) -> R<bool> {
        let d = st.depth();
        for _pass in 0..2 {
            for (i, b) in op.binders.iter().enumerate() {
                if !b.prop || hp[i].is_some() {
                    continue;
                }
                // Only hypotheses mentioning unbound metavariables.
                if !self.mentions_unbound(&b.ty, op.base, sub) {
                    continue;
                }
                for f in st.facts.iter().rev() {
                    let mut s2 = sub.clone();
                    if self.pmatch(d, &b.ty, &f.ty, op.base, &mut s2)? {
                        *sub = s2;
                        hp[i] = Some(st.var(f.lvl));
                        break;
                    }
                }
            }
        }
        Ok(op.binders.iter().enumerate().all(|(i, b)| b.prop || sub[i].is_some()))
    }

    /// Whether every hypothesis of `op` not yet in `hp` is a fact in scope
    /// under `sub` (it is then recorded in `hp`).
    fn other_hyps_are_facts(&mut self, st: &St, op: &Opened, sub: &mut Vec<Option<V>>, hp: &mut [Option<Tm>]) -> R<bool> {
        let d = st.depth();
        for (i, b) in op.binders.iter().enumerate() {
            if !b.prop || hp[i].is_some() {
                continue;
            }
            super::meter::spend(st.facts.len() as u64);
            let mut hit = None;
            for f in st.facts.iter().rev() {
                let mut s2 = sub.clone();
                if self.pmatch(d, &b.ty, &f.ty, op.base, &mut s2)? {
                    hit = Some((s2, f.lvl));
                    break;
                }
            }
            match hit {
                Some((s2, lvl)) => {
                    *sub = s2;
                    hp[i] = Some(st.var(lvl));
                }
                None => return Ok(false),
            }
        }
        Ok(true)
    }

    /// Bind type parameters (and other metavariables occurring only in
    /// binder types) by matching each bound value's type against its
    /// binder's type.
    fn bind_types(&mut self, st: &St, op: &Opened, sub: &mut Vec<Option<V>>) -> R<bool> {
        let d = st.depth();
        for (i, b) in op.binders.iter().enumerate() {
            if b.prop || !self.mentions_unbound(&b.ty, op.base, sub) {
                continue;
            }
            let Some(v) = sub[i].clone() else { continue };
            let tm = self.quote(st, &v);
            let Some(vt) = self.infer_irr(st, &tm)? else { continue };
            let mut s2 = sub.clone();
            if self.pmatch(d, &b.ty, &vt, op.base, &mut s2)? {
                *sub = s2;
            }
        }
        Ok(true)
    }

    fn mentions_unbound(&self, v: &V, base: u32, sub: &[Option<V>]) -> bool {
        let mut found = false;
        for_each_var(v, 0, &mut |l| {
            if l >= META_BASE + base && ((l - META_BASE - base) as usize) < sub.len() && sub[(l - META_BASE - base) as usize].is_none() {
                found = true;
            }
        });
        found
    }

    /// Backward chaining: a rule whose conclusion matches the target.
    pub fn backward(&mut self, st: &mut St, t: &V) -> R<Option<Tm>> {
        // one more level for the head-gated rules (`seq::index_eq` under
        // `option::some_eq`): they apply only to a target they head
        if self.rule_depth >= 3 {
            return Ok(None);
        }
        let gated_only = self.rule_depth >= 2;
        let d = st.depth();
        // trigger gate: a rule whose conclusion's left side is headed by a
        // global is opened only for a target whose left side it heads
        let t_head = match as_eq(t).map(|(_, l, _)| &**l) {
            Some(Value::Neu(Neutral { head: Head::Global { def, .. }, .. })) => Some(*def),
            _ => None,
        };
        let gated: Vec<String> = self.db.rules.iter().filter(|e| e.head.is_some()).map(|e| e.name.clone()).collect();
        let rules = self.rules_where(st, Role::Backward, &|e| match e.head {
            Some(h) => Some(h) == t_head,
            None => !gated_only,
        });
        for r in rules {
            // (at the extra level only the head-gated registered rules)
            if gated_only && !gated.contains(&r.name) {
                continue;
            }
            let Some(op) = self.open(&r.ty, d)? else { continue };
            let mut sub = vec![None; op.binders.len()];
            if !self.pmatch(d, &op.concl, t, op.base, &mut sub)? {
                continue;
            }
            if self.trace {
                eprintln!("[auto] backward rule {} matches the target", r.name);
            }
            let mut hp = vec![None; op.binders.len()];
            if !self.bind_types(st, &op, &mut sub)? || !self.bind_hyps_from_facts(st, &op, &mut sub, &mut hp)? {
                if self.trace {
                    eprintln!("[auto]   (unbound parameters)");
                }
                continue;
            }
            self.rule_depth += 1;
            let inst = self.instantiate(st, &r.head, &r.ty, &sub, &hp, None);
            self.rule_depth -= 1;
            match inst? {
                Some((p, concl)) if self.conv(d, &concl, t)? => {
                    self.note(format!("backward rule {}", r.name));
                    // a ∀-fact of the context may be an irrelevant binder (a
                    // lemma's hypothesis, a `using` fact): its instance is
                    // an irrelevant proof, promoted for a relevant target
                    // (an equation: `eq::promote`; the kernel checks it)
                    if r.name.starts_with("∀-fact") {
                        return Ok(Some(self.promote(st, t, p)));
                    }
                    return Ok(Some(p));
                }
                _ => {
                    if self.trace {
                        eprintln!("[auto]   (hypotheses of {} not provable)", r.name);
                    }
                }
            }
        }
        Ok(None)
    }

    /// Conditional rewrite rules on the target.
    pub fn rewrite_rules(&mut self, st: &mut St, t: &V) -> R<Option<(V, Cont)>> {
        let d = st.depth();
        let mut subterms: Vec<V> = Vec::new();
        let mut heads: Vec<sandblaster_kernel::term::GlobalId> = Vec::new();
        walk(t, &mut |x| {
            if matches!(&**x, Value::Neu(_)) && subterms.len() < 256 {
                if let Value::Neu(n @ Neutral { head: Head::Global { def, .. }, spine }) = &**x {
                    if !heads.contains(def) {
                        heads.push(*def);
                    }
                    // a stuck application eliminated further (the
                    // scrutinee of a `match`, a projection): its
                    // application prefix is a subterm too
                    if let Some(cut) = spine.iter().position(|e| !matches!(e, Elim::App(_))) {
                        subterms.push(prefix(n, cut));
                    }
                }
                subterms.push(x.clone());
            }
            true
        });
        // Trigger gate: a registered rule whose left side is headed by a
        // global is opened only when the target mentions that global;
        // last-resort rules come after the others.
        let mut late_names: Vec<String> = Vec::new();
        let rules = self.rules_where(st, Role::Rewrite, &|e| e.head.is_none_or(|h| heads.contains(&h)));
        if rules.is_empty() {
            return Ok(None);
        }
        for e in self.db.rules.iter().filter(|e| e.late) {
            late_names.push(e.name.clone());
        }
        let mut rules: Vec<(RuleSrc, bool)> = rules
            .into_iter()
            .map(|r| {
                let late = late_names.contains(&r.name);
                (r, late)
            })
            .collect();
        rules.sort_by_key(|(_, late)| *late);
        for (r, _) in rules {
            let Some(op) = self.open(&r.ty, d)? else { continue };
            let Some((_, lhs, _)) = as_eq(&op.concl) else { continue };
            let lhs = lhs.clone();
            for u in &subterms {
                let mut sub = vec![None; op.binders.len()];
                if !self.pmatch(d, &lhs, u, op.base, &mut sub)? {
                    continue;
                }
                let mut hp = vec![None; op.binders.len()];
                self.bind_types(st, &op, &mut sub)?;
                if !self.bind_hyps_from_facts(st, &op, &mut sub, &mut hp)? {
                    continue;
                }
                let Some((p, concl)) = self.instantiate(st, &r.head, &r.ty, &sub, &hp, None)? else { continue };
                let Some((a, l, rr)) = as_eq(&concl) else { continue };
                let (a, l, rr) = (a.clone(), l.clone(), rr.clone());
                if self.conv(d, &l, &rr)? {
                    continue;
                }
                if let Some(res) = self.rewrite(st, t, &a, &l, &rr, p)? {
                    self.note(format!("rewrite rule {}", r.name));
                    return Ok(Some(res));
                }
            }
        }
        Ok(None)
    }

    /// Forward rules triggered by a new fact.
    pub fn forward(&mut self, st: &mut St, f: &Fact) -> R<()> {
        if st.instances >= self.cfg.max_instances || self.rule_depth >= 1 {
            return Ok(());
        }
        let d0 = st.depth();
        for mut r in self.rules(st, Role::Forward) {
            if st.instances >= self.cfg.max_instances {
                break;
            }
            // the rules were read at depth `d0`; each instance pushed since
            // is one more binder (a ∀-fact's head is a variable)
            let d = st.depth();
            if d != d0 {
                r.head = sandblaster_kernel::util::shift(&r.head, (d - d0) as i64);
            }
            if matches!((&*r.head, &*st.var(f.lvl)), (Term::Var(a), Term::Var(b)) if a == b) {
                continue;
            }
            let Some(op) = self.open(&r.ty, d)? else { continue };
            // The new fact may be any hypothesis of the rule, not only the
            // first: a hypothesis whose fact arrives after the others (the
            // inner test of a nested branch) still triggers the rule — so
            // forward chaining does not depend on the order facts arrive in.
            // Registered rules keep their trigger (the first hypothesis).
            // Through a later hypothesis the rule fires only when every other
            // hypothesis is already a fact in scope (it "arrived before"):
            // proving them by search from every fact that matches a generic
            // later hypothesis (`?x <= ?y`) made failing searches (the spec
            // classifier's, the gates' counterexample goals) spend their
            // whole budget.
            let ks: Vec<usize> = op.binders.iter().enumerate().filter(|(_, b)| b.prop).map(|(i, _)| i).collect();
            let first = ks.first().copied();
            let ks: Vec<usize> = if matches!(&*r.head, Term::Var(_)) { ks } else { ks.into_iter().take(1).collect() };
            let mut found = None;
            for k in ks {
                let mut sub = vec![None; op.binders.len()];
                if !self.pmatch(d, &op.binders[k].ty, &f.ty, op.base, &mut sub)? {
                    continue;
                }
                if self.trace {
                    eprintln!("[auto] forward rule {} matches fact `{}` (hypothesis {k})", r.name, self.show(st, &f.ty));
                }
                let mut hp = vec![None; op.binders.len()];
                hp[k] = Some(st.var(f.lvl));
                self.bind_types(st, &op, &mut sub)?;
                if !self.bind_hyps_from_facts(st, &op, &mut sub, &mut hp)? {
                    continue;
                }
                if Some(k) != first && !self.other_hyps_are_facts(st, &op, &mut sub, &mut hp)? {
                    continue;
                }
                self.rule_depth += 1;
                let inst = self.instantiate(st, &r.head, &r.ty, &sub, &hp, None);
                self.rule_depth -= 1;
                match inst? {
                    Some(pc) => {
                        found = Some(pc);
                        break;
                    }
                    None => {
                        if self.trace {
                            eprintln!("[auto]   (could not instantiate {})", r.name);
                        }
                    }
                }
            }
            let Some((p, concl)) = found else { continue };
            let mut known = false;
            super::meter::spend(st.facts.len() as u64);
            for g in st.scan_facts() {
                if self.conv(d, &g.ty, &concl)? {
                    known = true;
                    break;
                }
            }
            if !known {
                self.note(format!("forward rule {}", r.name));
                st.instances += 1;
                st.push_fact(self.env, concl, p, Origin::Derived("forward rule"));
            }
        }
        Ok(())
    }

    /// A new implication fact of the context (`Π(h₁ : P₁)…. Q`) used as a
    /// forward rule on the facts already in scope: [`Self::forward`] runs a
    /// rule when a fact arrives, so a rule that arrives after the facts it
    /// needs (the conjunct of a lemma's result, split after the branch
    /// conditions were saturated) is matched here. Any hypothesis may match
    /// an existing fact; the others are proven from the facts in scope.
    pub fn forward_rule_on_facts(&mut self, st: &mut St, f: &Fact) -> R<()> {
        if st.instances >= self.cfg.max_instances || self.rule_depth >= 1 || !self.cfg.mode.allows_forall_facts() {
            return Ok(());
        }
        if !matches!(&*f.ty, Value::Pi { .. }) {
            return Ok(());
        }
        let existing: Vec<Fact> = st.facts.iter().filter(|g| g.lvl != f.lvl && !matches!(&*g.ty, Value::Pi { .. })).cloned().collect();
        super::meter::spend(existing.len() as u64);
        for g in existing {
            if st.instances >= self.cfg.max_instances {
                break;
            }
            let d = st.depth();
            let Some(op) = self.open(&f.ty, d)? else { return Ok(()) };
            let ks: Vec<usize> = op.binders.iter().enumerate().filter(|(_, b)| b.prop).map(|(i, _)| i).collect();
            let mut found = None;
            for k in ks {
                let mut sub = vec![None; op.binders.len()];
                if !self.pmatch(d, &op.binders[k].ty, &g.ty, op.base, &mut sub)? {
                    continue;
                }
                if self.trace {
                    eprintln!("[auto] new implication h{} matches fact `{}` (hypothesis {k})", f.lvl, self.show(st, &g.ty));
                }
                let mut hp = vec![None; op.binders.len()];
                hp[k] = Some(st.var(g.lvl));
                self.bind_types(st, &op, &mut sub)?;
                if !self.bind_hyps_from_facts(st, &op, &mut sub, &mut hp)? {
                    continue;
                }
                self.rule_depth += 1;
                let inst = self.instantiate(st, &st.var(f.lvl), &f.ty, &sub, &hp, None);
                self.rule_depth -= 1;
                if let Some(pc) = inst? {
                    found = Some(pc);
                    break;
                }
            }
            let Some((p, concl)) = found else { continue };
            let mut known = false;
            for h in st.scan_facts() {
                if self.conv(st.depth(), &h.ty, &concl)? {
                    known = true;
                    break;
                }
            }
            if !known {
                self.note(format!("forward rule h{} (new implication)", f.lvl));
                st.instances += 1;
                st.push_fact(self.env, concl, p, Origin::Derived("forward rule"));
            }
            // one instance per implication: its conclusion is the same fact
            break;
        }
        Ok(())
    }

    /// Linarith rules whose conclusion mentions a subterm matching `atom`:
    /// add their instances as hypotheses.
    /// The linarith rules opened at `depth`, with their triggers (cached
    /// per depth: opening a telescope evaluates every binder type).
    fn lin_rules(&mut self, st: &St) -> R<Rc<Vec<LinRule>>> {
        let d = st.depth();
        if let Some(c) = self.lin_rule_cache.get(&d) {
            return Ok(c.clone());
        }
        // the opened rules of this environment's linarith set at this depth,
        // shared by every engine of the thread (their metavariables live in
        // a range of their own, [`LIN_META_BASE`] up, never an engine's)
        let key: Vec<sandblaster_kernel::term::GlobalId> = self.db.rules.iter().filter(|r| r.roles.contains(&Role::Linarith)).map(|r| r.g).collect();
        let env_addr = self.env as *const _ as usize;
        if let Some(c) = LIN_RULES.with(|m| {
            let m = m.borrow();
            m.rules.get(&(env_addr, d)).filter(|(k, _)| *k == key).map(|(_, c)| c.clone())
        }) {
            self.lin_rule_cache.insert(d, c.clone());
            return Ok(c);
        }
        let own_next = self.meta_next;
        self.meta_next = LIN_RULES.with(|m| m.borrow().next);
        let out = self.open_lin_rules(st, d);
        let next = self.meta_next;
        self.meta_next = own_next;
        let out = out?;
        LIN_RULES.with(|m| {
            let mut m = m.borrow_mut();
            m.next = next;
            m.rules.insert((env_addr, d), (key, out.clone()));
        });
        self.lin_rule_cache.insert(d, out.clone());
        Ok(out)
    }

    fn open_lin_rules(&mut self, st: &St, d: u32) -> R<Rc<Vec<LinRule>>> {
        let mut out = Vec::new();
        for r in self.rules(st, Role::Linarith) {
            let Some(op) = self.open(&r.ty, d)? else { continue };
            // Triggers: neutral subterms of the conclusion that mention
            // every data metavariable.
            let data: Vec<u32> = op.binders.iter().enumerate().filter(|(_, b)| !b.prop).map(|(i, _)| i as u32).collect();
            let mut triggers: Vec<V> = Vec::new();
            // Triggers come from the conclusion's left side (for an equation)
            // and must have structure below their head (a pattern whose
            // arguments are all bare metavariables matches everything).
            let src = match as_eq(&op.concl) {
                Some((_, l, _)) => l.clone(),
                None => op.concl.clone(),
            };
            let base = op.base;
            // a bridge's inequality (`count_ones(x) <= x`): a primitive or global
            // application of bare metavariables is trigger enough (its head
            // is specific); other rules need structure below the head
            let bridge = super::lemmas::is_bridge(&r.name);
            let informative = |x: &V| -> bool {
                if bridge && matches!(&**x, Value::Neu(Neutral { head: Head::Prim { .. } | Head::Global { .. }, spine }) if spine.is_empty()) {
                    return true;
                }
                let args: Vec<V> = match &**x {
                    Value::Neu(Neutral { head: Head::Global { args, .. }, spine }) if spine.is_empty() => {
                        args.iter().filter_map(|a| if let Arg::Rel(v) = a { Some(v.clone()) } else { None }).collect()
                    }
                    Value::Neu(Neutral { head: Head::Prim { args, .. }, spine }) if spine.is_empty() => args.clone(),
                    _ => return true,
                };
                args.iter()
                    .any(|a| !matches!(as_var(a), Some(l) if l >= META_BASE + base) && !matches!(&**a, Value::IntTy(_) | Value::Ind { .. }))
            };
            walk(&src, &mut |x| {
                if matches!(&**x, Value::Neu(_)) && as_var(x).is_none() && informative(x) {
                    let mut ms: Vec<u32> = Vec::new();
                    for_each_var(x, 0, &mut |l| {
                        if l >= META_BASE + op.base {
                            ms.push(l - META_BASE - op.base);
                        }
                    });
                    if data.iter().all(|i| ms.contains(i)) {
                        triggers.push(x.clone());
                    }
                }
                true
            });
            if !triggers.is_empty() {
                out.push(LinRule { src: r, op, triggers });
            }
        }
        Ok(Rc::new(out))
    }

    /// Linarith-role rules (§13.9 conditional simp sets) whose trigger
    /// matches `atom`: add their instantiated conclusions as hypotheses.
    pub fn enrich_rules(&mut self, st: &St, atom: &V, hyps: &mut Vec<Hyp>) -> R<()> {
        if self.rule_depth >= 1 {
            return Ok(());
        }
        let d = st.depth();
        let rules = self.lin_rules(st)?;
        for lr in rules.iter() {
            let (r, op, triggers) = (&lr.src, &lr.op, &lr.triggers);
            for tr in triggers {
                let mut sub = vec![None; op.binders.len()];
                if !self.pmatch(d, tr, atom, op.base, &mut sub)? {
                    continue;
                }
                if self.trace {
                    eprintln!("[auto] linarith rule {} matches atom `{}`", r.name, self.show(st, atom));
                }
                let mut hp = vec![None; op.binders.len()];
                self.bind_types(st, op, &mut sub)?;
                if !self.bind_hyps_from_facts(st, op, &mut sub, &mut hp)? {
                    continue;
                }
                self.rule_depth += 1;
                let inst = self.instantiate(st, &r.head, &r.ty, &sub, &hp, Some(&hyps.clone()));
                self.rule_depth -= 1;
                let Some((p, concl)) = inst? else {
                    if self.trace {
                        eprintln!("[auto]   (hypotheses of {} not provable)", r.name);
                    }
                    continue;
                };
                if self.trace {
                    eprintln!("[auto]   added {}", self.show(st, &concl));
                }
                self.push_lin_conclusion(st, p, &concl, hyps, 0)?;
                break;
            }
        }
        Ok(())
    }

    /// [`Self::push_lin_conclusion`] for other modules.
    pub fn push_lin_conclusion_pub(&mut self, st: &St, p: Tm, concl: &V, hyps: &mut Vec<Hyp>) -> R<()> {
        self.push_lin_conclusion(st, p, concl, hyps, 0)
    }

    /// Add a proven conclusion (splitting conjunctions) as linarith
    /// hypotheses.
    fn push_lin_conclusion(&mut self, st: &St, p: Tm, concl: &V, hyps: &mut Vec<Hyp>, n: u32) -> R<()> {
        if n > 8 {
            return Ok(());
        }
        if self.lin_hyp_form(concl) {
            hyps.push((p, self.quote(st, concl)));
            return Ok(());
        }
        if let Value::Sigma { snd_rel: Rel::Rel, fst, snd, .. } = &**concl
            && self.is_prop(fst, st.depth())
        {
            let fst_p = mk::fst(p.clone());
            self.push_lin_conclusion(st, fst_p.clone(), fst, hyps, n + 1)?;
            let Some(fe) = self.entry_for(st, fst, &fst_p)? else { return Ok(()) };
            if let Some(q) = self.inst(snd, vec![fe], st.depth())? {
                self.push_lin_conclusion(st, mk::snd(p), &q, hyps, n + 1)?;
            }
        }
        Ok(())
    }

    /// Witnesses of an `exists` target by matching its conjuncts against
    /// facts.
    pub fn exists_witnesses(&mut self, st: &St, t: &V) -> R<Option<Vec<V>>> {
        let d = st.depth();
        let base = self.meta_base(16);
        let mut cur = t.clone();
        let mut k = 0u32;
        while let Value::Sigma { snd_rel: Rel::Rel, fst, snd, .. } = &*cur.clone() {
            if self.is_prop(fst, d) || k >= 16 {
                break;
            }
            let m = neu_var(META_BASE + base + k);
            let Some(next) = self.inst(snd, vec![EnvEntry::Rel(m)], d)? else { return Ok(None) };
            cur = next;
            k += 1;
        }
        if k == 0 {
            return Ok(None);
        }
        let mut conj = Vec::new();
        self.conjuncts(&cur, d, &mut conj, 0)?;
        let mut sub: Vec<Option<V>> = vec![None; k as usize];
        for _pass in 0..3 {
            for c in &conj {
                if !self.mentions_unbound(c, base, &sub) {
                    continue;
                }
                // `Eq(A, x, p)` with `x` ground: unify `p` with `x` (closed
                // by reflexivity), e.g. `Some(s) == Some(?m)`.
                if let Some((_, l, r)) = as_eq(c) {
                    for (x, y) in [(l, r), (r, l)] {
                        if !has_meta(x) && has_meta(y) {
                            let mut s2 = sub.clone();
                            if self.pmatch(d, y, x, base, &mut s2)? {
                                sub = s2;
                                break;
                            }
                        }
                    }
                }
                for f in st.facts.iter().rev() {
                    let mut s2 = sub.clone();
                    if self.pmatch(d, c, &f.ty, base, &mut s2)? {
                        sub = s2;
                        break;
                    }
                }
            }
        }
        if sub.iter().all(Option::is_some) { Ok(Some(sub.into_iter().map(Option::unwrap).collect())) } else { Ok(None) }
    }

    /// Flatten a conjunction (Σ of propositions) into its conjuncts.
    fn conjuncts(&mut self, v: &V, d: u32, out: &mut Vec<V>, n: u32) -> R<()> {
        if n > 16 {
            return Ok(());
        }
        if let Value::Sigma { fst, snd, .. } = &**v
            && self.is_prop(fst, d)
        {
            self.conjuncts(fst, d, out, n + 1)?;
            let x = self.env.fresh_var(Lvl(d), Rel::Rel, fst);
            if let Some(q) = self.inst(snd, vec![x], d + 1)? {
                self.conjuncts(&q, d, out, n + 1)?;
            }
            return Ok(());
        }
        out.push(v.clone());
        Ok(())
    }

    /// Type of a proof term without checking it (irrelevant variables
    /// allowed): variables, application spines of globals / variables,
    /// projections, axiom instances; otherwise the kernel's `infer`.
    pub fn infer_irr(&mut self, st: &St, tm: &Tm) -> R<Option<V>> {
        let d = st.depth();
        match &**tm {
            Term::Var(i) => {
                let l = d as i64 - 1 - i.0 as i64;
                if l < 0 {
                    return Ok(None);
                }
                Ok(Some(st.ctx.entries[l as usize].ty.clone()))
            }
            Term::App { .. } => {
                let mut args = Vec::new();
                let mut h = tm;
                while let Term::App { rel, fun, arg } = &**h {
                    args.push((*rel, arg.clone()));
                    h = fun;
                }
                args.reverse();
                let head_ty = match &**h {
                    Term::Global(g) => self.env.global_type_value(*g),
                    _ => self.infer_irr(st, h)?,
                };
                let Some(mut cur) = head_ty else { return Ok(None) };
                for (rel, a) in args {
                    let Value::Pi { dom, cod, .. } = &*cur.clone() else { return Ok(None) };
                    let e = match rel {
                        Rel::Rel => match self.entry_for(st, dom, &a)? {
                            Some(e) => e,
                            None => return Ok(None),
                        },
                        Rel::Irr => irr_entry(&st.venv, &a),
                    };
                    let Some(next) = self.inst(cod, vec![e], d)? else { return Ok(None) };
                    cur = next;
                }
                Ok(Some(cur))
            }
            Term::Fst(p) => {
                let Some(pt) = self.infer_irr(st, p)? else { return Ok(None) };
                match &*pt {
                    Value::Sigma { fst, .. } => Ok(Some(fst.clone())),
                    _ => Ok(None),
                }
            }
            Term::Snd(p) => {
                let Some(pt) = self.infer_irr(st, p)? else { return Ok(None) };
                let Value::Sigma { fst, snd, .. } = &*pt else { return Ok(None) };
                let Some(fe) = self.entry_for(st, fst, &mk::fst(p.clone()))? else { return Ok(None) };
                self.inst(snd, vec![fe], d)
            }
            Term::Axiom { ax, args } => {
                let Some((params, stmt)) = axioms::telescope(*ax, self.n.bool_ind) else { return Ok(None) };
                let mut es = Vec::new();
                for ((_, rel, _), a) in params.iter().zip(args) {
                    match rel {
                        Rel::Rel => match self.eval(st, a)? {
                            Some(v) => es.push(EnvEntry::Rel(v)),
                            None => return Ok(None),
                        },
                        Rel::Irr => es.push(irr_entry(&st.venv, a)),
                    }
                }
                let r = self.env.eval(&VEnv(Rc::new(es)), Lvl(d), &stmt, self.b);
                self.ev_err(r)
            }
            // a match's type is its motive at the scrutinee (the kernel's
            // rule, `infer_match`), without checking the arms: a slice
            // produced by a stuck match (a callee's residual) costs one
            // evaluation instead of the inference of every arm
            Term::Match { motive, scrut, .. } => {
                let Some(sv) = self.eval(st, scrut)? else { return Ok(None) };
                let cl = Closure { env: st.venv.clone(), body: motive.clone() };
                self.inst(&cl, vec![EnvEntry::Rel(sv)], d)
            }
            _ => {
                let r = self.env.infer(&st.ctx, tm, self.b);
                self.k_err(r)
            }
        }
    }
}

/// Is `v` a neutral whose head is a global application?
pub fn is_global_neutral(v: &V) -> bool {
    matches!(&**v, Value::Neu(Neutral { head: Head::Global { .. }, .. }))
}
