//! Argument congruence (DESIGN.md §8.1 step 9, extended to structured
//! arguments).
//!
//! A goal `f(a₁..aₙ) == f(b₁..bₙ)` whose sides are applications of the same
//! stuck global (a recursive function folded by the unfolding policy, an
//! opaque function) is closed by proving each differing relevant argument
//! pair equal and chaining one transport per argument position:
//!
//! ```text
//! transport(Dᵢ, aᵢ, bᵢ, pᵢ, z. Eq(A, f(a..), f(b₁..bᵢ₋₁, z, aᵢ₊₁..aₙ)), ..)
//! ```
//!
//! The motive mentions `z` in exactly one argument position, so — unlike a
//! rewrite of the whole goal — it never has to abstract occurrences inside
//! proof terms (the proofs a slice value carries, for instance). Argument
//! equations are proven by conversion, a fact, `linarith` (integers),
//! **list extensionality** for slices and arrays (`slice::ext`, `array::ext`:
//! equal lists suffice, the lengths and proofs follow) with list equations
//! from conversion, facts or an instance of a rewrite rule (`seq::drop_zero`,
//! `seq::take_len`, ..), or recursively by argument congruence.
//!
//! Typical use: a recursive function unfolded one step on a `seq::cons` /
//! `seq::append` slice calls itself on the rest slice `&s[1..]`, whose
//! length term and list term differ from the variable slice of the other
//! side only by `(1 + len t) − 1 = len t` and `drop(t, 0) = t`.

use std::rc::Rc;

use sandblaster_kernel::term::{Rel, Term, Tm};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::{Arg, V, Value};

use super::lemmas::Role;
use super::search::{Engine, R};
use super::state::St;
use super::util::*;

/// Maximal nesting of argument congruence.
const MAX_CONGR_DEPTH: u32 = 3;

/// Maximal nesting of constructor splits (of different data types, see
/// [`Engine::ctor_split`]): an option of a pair of a struct
/// (`Some((P(e), g)) == Some((P(x), g))`) reaches its integer equation
/// `e == x` at the third level.
pub const MAX_CTOR_SPLIT: u32 = 3;

impl Engine<'_> {
    /// Close `f(a..) == f(b..)` by argument congruence (see the module docs).
    pub fn arg_congruence(&mut self, st: &St, t: &V) -> R<Option<Tm>> {
        self.arg_congruence_n(st, t, 0)
    }

    fn arg_congruence_n(&mut self, st: &St, t: &V, n: u32) -> R<Option<Tm>> {
        if n > MAX_CONGR_DEPTH {
            return Ok(None);
        }
        let Some((aty, l, r)) = as_eq(t) else { return Ok(None) };
        let (aty, l, r) = (aty.clone(), l.clone(), r.clone());
        // the same stuck global, or the same variable applied (an unknown
        // function of a restricted view, `elab::closers`)
        let (head, a1, a2): (Result<sandblaster_kernel::term::GlobalId, u32>, Vec<Arg>, Vec<Arg>) = match (as_global_app(&l), as_global_app(&r)) {
            (Some((g1, a1)), Some((g2, a2))) if g1 == g2 => (Ok(g1), a1.to_vec(), a2.to_vec()),
            (Some(_), _) | (_, Some(_)) => return Ok(None),
            _ => match (as_var_app(&l), as_var_app(&r)) {
                (Some((v1, a1)), Some((v2, a2))) if v1 == v2 => (Err(v1), a1, a2),
                _ => return Ok(None),
            },
        };
        if a1.len() != a2.len() || a1.is_empty() {
            return Ok(None);
        }
        self.tick()?;
        let d = st.depth();
        // term forms of both sides (their arguments, in telescope order)
        let l_tm = st.quote_at(self.env, &l, &aty);
        let r_tm = st.quote_at(self.env, &r, &aty);
        let (hl, largs) = crate::elab::items::spine(&l_tm);
        let (_, rargs) = crate::elab::items::spine(&r_tm);
        if largs.len() != a1.len() || rargs.len() != a2.len() {
            return Ok(None);
        }
        let mut rels = Vec::new();
        let mut diffs: Vec<(usize, Tm, Tm)> = Vec::new(); // (position, domain, proof)
        // a variable standing for a global: the global's type term (its
        // domains keep their names, e.g. `slice T`)
        let head = match head {
            Err(v) => match self.hints.iter().find_map(|h| match h {
                crate::prover::Hint::ViewFunction { def, var, .. } if var.0 == v => Some(*def),
                _ => None,
            }) {
                Some(g) => Ok(g),
                None => Err(v),
            },
            h => h,
        };
        match head {
            Ok(g1) => {
                let Some(gty) = self.env.global_type(g1) else { return Ok(None) };
                let mut cur = gty;
                for i in 0..a1.len() {
                    let Term::Pi { rel, dom, cod, .. } = &*cur.clone() else { return Ok(None) };
                    rels.push(*rel);
                    if let (Arg::Rel(x), Arg::Rel(y)) = (&a1[i], &a2[i])
                        && !self.conv(d, x, y)?
                    {
                        let dom_i = crate::elab::tm::subst_closed(dom, &largs[..i]);
                        let Some(p) = self.prove_arg_eq(st, &dom_i, x, y, &largs[i], &rargs[i], n)? else { return Ok(None) };
                        diffs.push((i, dom_i, p));
                    }
                    cur = cod.clone();
                }
            }
            Err(v) => {
                // the variable's type, instantiated with the left arguments
                let Some(entry) = st.ctx.entries.get(v as usize) else { return Ok(None) };
                let mut cur = entry.ty.clone();
                for i in 0..a1.len() {
                    let Value::Pi { rel, dom, cod, .. } = &*cur.clone() else { return Ok(None) };
                    rels.push(*rel);
                    if let (Arg::Rel(x), Arg::Rel(y)) = (&a1[i], &a2[i])
                        && !self.conv(d, x, y)?
                    {
                        let dom_i = self.quote(st, dom);
                        let Some(p) = self.prove_arg_eq(st, &dom_i, x, y, &largs[i], &rargs[i], n)? else { return Ok(None) };
                        diffs.push((i, dom_i, p));
                    }
                    let e = match &a1[i] {
                        Arg::Rel(x) => sandblaster_kernel::value::EnvEntry::Rel(x.clone()),
                        Arg::Irr(c) => sandblaster_kernel::value::EnvEntry::Irr(c.clone()),
                    };
                    let Some(next) = self.inst(cod, vec![e], d)? else { return Ok(None) };
                    cur = next;
                }
            }
        }
        if diffs.is_empty() {
            return Ok(None);
        }
        // chain the transports
        let a_tm = self.quote(st, &aty);
        let mut proof = mk::refl(a_tm.clone(), l_tm.clone());
        let mut current: Vec<Tm> = largs.clone();
        for (i, dom_i, p) in diffs {
            let mut margs: Vec<(Rel, Tm)> = Vec::with_capacity(current.len());
            for (j, a) in current.iter().enumerate() {
                margs.push((rels[j], if j == i { mk::var(0) } else { shift(a, 1) }));
            }
            let motive = mk::eq(shift(&a_tm, 1), shift(&l_tm, 1), mk::apps(shift(&hl, 1), margs));
            proof = Rc::new(Term::Transport { ty: dom_i, lhs: current[i].clone(), rhs: rargs[i].clone(), eq: p, motive, val: proof });
            current[i] = rargs[i].clone();
        }
        // the motive of a dependent argument position may be ill-typed: check
        let mut b = sandblaster_kernel::value::Budget { steps: self.b.steps.min(20_000_000) };
        let start = b.steps;
        let ok = self.env.check(&st.ctx, &proof, t, &mut b).is_ok();
        self.b.steps = self.b.steps.saturating_sub(start - b.steps);
        if !ok {
            return Ok(None);
        }
        self.note(format!("argument congruence ({} positions)", a1.len()));
        Ok(Some(proof))
    }

    /// Close `f(ā) == r` from a fact `f(b̄) == r` (either side of either
    /// equation) by argument congruence: `f(ā) == f(b̄)` with each differing
    /// argument pair proven equal ([`Engine::arg_congruence`]: conversion, a
    /// fact, linarith for integers — `x - 1` against `y` with `y + 1 == x` —,
    /// extensionality), then transitivity with the fact. The fact's other
    /// side must convert with the target's; the applications have one head
    /// (a stuck global, or a restricted view's function variable).
    pub fn fact_congruence(&mut self, st: &St, t: &V) -> R<Option<Tm>> {
        let Some((aty, l, r)) = as_eq(t) else { return Ok(None) };
        let (aty, l, r) = (aty.clone(), l.clone(), r.clone());
        let head = |v: &V| -> Option<Result<sandblaster_kernel::term::GlobalId, u32>> {
            as_global_app(v).map(|(g, _)| Ok(g)).or_else(|| as_var_app(v).filter(|(_, a)| !a.is_empty()).map(|(x, _)| Err(x)))
        };
        let (hl, hr) = (head(&l), head(&r));
        if hl.is_none() && hr.is_none() {
            return Ok(None);
        }
        let d = st.depth();
        for f in st.scan_facts().iter().rev() {
            let Some((fty, x, y)) = as_eq(&f.ty) else { continue };
            let (fty, x, y) = (fty.clone(), x.clone(), y.clone());
            // (application side of the fact, other side, fact oriented app → other)
            for (app, other, rev) in [(&x, &y, false), (&y, &x, true)] {
                let ha = head(app);
                if ha.is_none() {
                    continue;
                }
                // (target side matched by congruence, target side equal to `other`, target reversed)
                for (side, rest, trev) in [(&l, &r, false), (&r, &l, true)] {
                    if head(side) != ha || self.conv(d, side, app)? || !self.conv(d, &fty, &aty)? || !self.conv(d, rest, other)? {
                        continue;
                    }
                    let goal = Rc::new(Value::Eq { ty: aty.clone(), lhs: side.clone(), rhs: app.clone() });
                    let Some(p1) = self.arg_congruence(st, &goal)? else { continue };
                    let a_tm = self.quote(st, &aty);
                    let (s_tm, app_tm, rest_tm) = (st.quote_at(self.env, side, &aty), st.quote_at(self.env, app, &aty), st.quote_at(self.env, rest, &aty));
                    // `app == rest` from the fact
                    let fp = if rev { self.sym(&a_tm, &rest_tm, &app_tm, &st.var(f.lvl)) } else { st.var(f.lvl) };
                    // `side == rest`
                    let p = self.trans(&a_tm, &s_tm, &app_tm, &rest_tm, &p1, &fp);
                    let p = if trev { self.sym(&a_tm, &s_tm, &rest_tm, &p) } else { p };
                    let mut b = sandblaster_kernel::value::Budget { steps: self.b.steps.min(20_000_000) };
                    let start = b.steps;
                    // checked in an irrelevant position (the proof uses the
                    // branch's derived facts; the atomic loop's result is
                    // promoted by its caller)
                    let promoted = self.promote(st, t, p.clone());
                    let ok = self.env.check(&st.ctx, &promoted, t, &mut b).is_ok();
                    self.b.steps = self.b.steps.saturating_sub(start - b.steps);
                    if ok {
                        self.note("congruence with a fact (argument equations)");
                        return Ok(Some(p));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Close `K(ā) == K(b̄)` for two applications of one constructor when
    /// `Irr` constructor fields are involved (a struct's invariant or the
    /// bound of a `Nat` field, DESIGN.md §15.3), here or in a nested
    /// relevant argument: each differing relevant pair is proven equal
    /// (conversion, a fact, `linarith`, list extensionality, argument
    /// congruence, or this rule on nested constructors), then one transport
    /// per position with the `Irr` fields generalized
    /// ([`crate::elab::tm::ctor_congruence_term`]). A rewrite of the whole
    /// goal (the arithmetic congruence step) cannot do this: the `Irr`
    /// proofs' types mention the rewritten fields.
    pub fn irr_ctor_congruence(&mut self, st: &St, t: &V) -> R<Option<Tm>> {
        let Some((_, l, r)) = as_eq(t) else { return Ok(None) };
        if !(matches!(&**l, Value::Ctor { .. }) && matches!(&**r, Value::Ctor { .. }) && (has_irr_ctor(l, 3) || has_irr_ctor(r, 3))) {
            return Ok(None);
        }
        let Some(p) = self.irr_ctor_congruence_n(st, t, 0)? else { return Ok(None) };
        let mut b = sandblaster_kernel::value::Budget { steps: self.b.steps.min(20_000_000) };
        let start = b.steps;
        let ok = self.env.check(&st.ctx, &p, t, &mut b).is_ok();
        self.b.steps = self.b.steps.saturating_sub(start - b.steps);
        if !ok {
            return Ok(None);
        }
        self.note("constructor congruence (`Irr` fields generalized)");
        Ok(Some(p))
    }

    /// Close `K(ā) == K(b̄)` (one constructor of a data type with fields:
    /// `Cons`, `Some`, a tuple, a struct) by proving each differing
    /// relevant pair `aᵢ == bᵢ` with the whole search: by injectivity the
    /// goal *is* those equations, so nothing is lost by the split, and a
    /// pair may need rewriting or unfolding of its own (`varint(y) ++ s`
    /// against `varint(x / 128) ++ r` after `varint(x)` was unfolded one
    /// step), which the argument congruences above do not do. Without it
    /// the search keeps unfolding the sides' recursive functions instead.
    pub fn ctor_split(&mut self, st: &St, t: &V) -> R<Option<Tm>> {
        if self.ctor_split_inds.len() as u32 >= MAX_CTOR_SPLIT {
            return Ok(None);
        }
        let Some((aty, l, r)) = as_eq(t) else { return Ok(None) };
        let (aty, l, r) = (aty.clone(), l.clone(), r.clone());
        let (Value::Ctor { ind, ctor, args: a1, .. }, Value::Ctor { ind: i2, ctor: c2, args: a2, .. }) = (&*l, &*r) else { return Ok(None) };
        if ind != i2 || ctor != c2 || a1.is_empty() || a1.len() != a2.len() || *ind == self.n.bool_ind {
            return Ok(None);
        }
        let (ind, ctor) = (*ind, *ctor);
        // inside a split of the same type (a recursive structure): no
        // nested split
        if self.ctor_split_inds.contains(&ind) {
            return Ok(None);
        }
        // a list of several known elements on either side (a literal list,
        // an eta-expanded array): conversion and the list rules decide it
        // as a whole, not element by element
        if Some(ind) == self.n.list && [a1, a2].iter().any(|a| matches!(a.get(1), Some(Arg::Rel(tl)) if matches!(&**tl, Value::Ctor { ind: i, args, .. } if *i == ind && !args.is_empty()))) {
            return Ok(None);
        }
        let d = st.depth();
        let l_tm = st.quote_at(self.env, &l, &aty);
        let r_tm = st.quote_at(self.env, &r, &aty);
        let (Term::Ctor { params: ps, args: la, .. }, Term::Ctor { args: ra, .. }) = (&*l_tm, &*r_tm) else { return Ok(None) };
        let Some(decl) = self.env.inductive_decl(ind) else { return Ok(None) };
        let Some(c) = decl.ctors.get(ctor as usize) else { return Ok(None) };
        if c.fields.len() != la.len() || la.len() != ra.len() {
            return Ok(None);
        }
        let nrel = c.fields.iter().take_while(|f| f.1 == Rel::Rel).count();
        if c.fields[nrel..].iter().any(|f| f.1 == Rel::Rel) {
            return Ok(None);
        }
        // a field type that depends on earlier fields: not split
        if (0..nrel).any(|j| (0..j as u32).any(|i| occurs(&c.fields[j].2, i))) {
            return Ok(None);
        }
        let mut eqs = Vec::new();
        let mut split = false;
        for j in 0..nrel {
            let dom = crate::elab::tm::subst_closed(&c.fields[j].2, &ps.iter().cloned().chain(la[..j].iter().cloned()).collect::<Vec<_>>());
            let (Arg::Rel(x), Arg::Rel(y)) = (&a1[j], &a2[j]) else { return Ok(None) };
            if self.conv(d, x, y)? {
                eqs.push(mk::refl(dom, la[j].clone()));
                continue;
            }
            let Some(dv) = self.eval(st, &dom)? else { return Ok(None) };
            let g = Rc::new(Value::Eq { ty: dv, lhs: x.clone(), rhs: y.clone() });
            self.ctor_split_inds.push(ind);
            let p = self.solve(st, g, true);
            self.ctor_split_inds.pop();
            let Some(p) = p? else { return Ok(None) };
            eqs.push(p);
            split = true;
        }
        if !split {
            return Ok(None);
        }
        let Some(p) = crate::elab::tm::ctor_congruence_term(self.env, ind, ctor, ps, &la[..nrel], &ra[..nrel], &la[nrel..], &ra[nrel..], &eqs) else { return Ok(None) };
        // checked (a term the kernel cannot check within the goal's budget
        // is no proof: the search goes on without it) at the outermost
        // split, whose term contains the nested splits' — so each nested
        // equation is checked once, not once per level — and wherever the
        // constructor has `Irr` fields (their types, generalized in the
        // motive, may depend on the relevant ones)
        if self.ctor_split_inds.is_empty() || nrel < c.fields.len() {
            let mut b = sandblaster_kernel::value::Budget { steps: self.b.steps.min(20_000_000) };
            let start = b.steps;
            let ok = self.env.check(&st.ctx, &self.promote(st, t, p.clone()), t, &mut b).is_ok();
            self.b.steps = self.b.steps.saturating_sub(start - b.steps);
            if !ok {
                return Ok(None);
            }
        }
        self.note("constructor split (the arguments' equations)");
        Ok(Some(p))
    }

    fn irr_ctor_congruence_n(&mut self, st: &St, t: &V, n: u32) -> R<Option<Tm>> {
        if n > MAX_CONGR_DEPTH + 1 {
            return Ok(None);
        }
        self.tick()?;
        let Some((aty, l, r)) = as_eq(t) else { return Ok(None) };
        let (aty, l, r) = (aty.clone(), l.clone(), r.clone());
        let (Value::Ctor { ind, ctor, args: a1, .. }, Value::Ctor { ind: i2, ctor: c2, args: a2, .. }) = (&*l, &*r) else { return Ok(None) };
        if ind != i2 || ctor != c2 || a1.len() != a2.len() {
            return Ok(None);
        }
        let (ind, ctor) = (*ind, *ctor);
        let d = st.depth();
        let l_tm = st.quote_at(self.env, &l, &aty);
        let r_tm = st.quote_at(self.env, &r, &aty);
        let (Term::Ctor { params: ps, args: la, .. }, Term::Ctor { args: ra, .. }) = (&*l_tm, &*r_tm) else { return Ok(None) };
        let Some(decl) = self.env.inductive_decl(ind) else { return Ok(None) };
        let Some(c) = decl.ctors.get(ctor as usize) else { return Ok(None) };
        if c.fields.len() != la.len() || la.len() != ra.len() {
            return Ok(None);
        }
        let nrel = c.fields.iter().take_while(|f| f.1 == Rel::Rel).count();
        if c.fields[nrel..].iter().any(|f| f.1 == Rel::Rel) {
            return Ok(None);
        }
        let mut eqs = Vec::new();
        for j in 0..nrel {
            let dom = crate::elab::tm::subst_closed(&c.fields[j].2, &ps.iter().cloned().chain(la[..j].iter().cloned()).collect::<Vec<_>>());
            let (Arg::Rel(x), Arg::Rel(y)) = (&a1[j], &a2[j]) else { return Ok(None) };
            if self.conv(d, x, y)? {
                eqs.push(mk::refl(dom, la[j].clone()));
                continue;
            }
            let p = if matches!((&**x, &**y), (Value::Ctor { .. }, Value::Ctor { .. })) {
                let Some(dv) = self.eval(st, &dom)? else { return Ok(None) };
                let g = Rc::new(Value::Eq { ty: dv, lhs: x.clone(), rhs: y.clone() });
                self.irr_ctor_congruence_n(st, &g, n + 1)?
            } else {
                self.prove_arg_eq(st, &dom, x, y, &la[j], &ra[j], n)?
            };
            let Some(p) = p else { return Ok(None) };
            eqs.push(p);
        }
        Ok(crate::elab::tm::ctor_congruence_term(self.env, ind, ctor, ps, &la[..nrel], &ra[..nrel], &la[nrel..], &ra[nrel..], &eqs))
    }

    /// Prove `x == y` at type `dom` (a term at the state's depth); `xt`,
    /// `yt` are the terms of `x`, `y`.
    #[allow(clippy::too_many_arguments)]
    fn prove_arg_eq(&mut self, st: &St, dom: &Tm, x: &V, y: &V, xt: &Tm, yt: &Tm, n: u32) -> R<Option<Tm>> {
        let d = st.depth();
        let Some(dv) = self.eval(st, dom)? else { return Ok(None) };
        let goal = Rc::new(Value::Eq { ty: dv.clone(), lhs: x.clone(), rhs: y.clone() });
        if let Some(p) = self.fact_or_sym(st, &goal, dom, xt, yt)? {
            return Ok(Some(p));
        }
        // integers: linarith (two different literals are never equal: no
        // search, which with enrichment costs a linarith run per atom pair,
        // `l[0]` against `l[1]`, on every enriched linarith call)
        if matches!(&*dv, Value::IntTy(_)) {
            if let (Value::Lit { n: a, .. }, Value::Lit { n: b, .. }) = (&**x, &**y)
                && a != b
            {
                return Ok(None);
            }
            // two sides whose linear forms differ by a nonzero constant
            // (`e - 1` against `e`) are never equal: no search either
            if self.arith_distinct(st, &goal)? {
                return Ok(None);
            }
            // (inside the atom congruence of an enrichment round, the
            // round's facts are enriched already: one linarith round over
            // them, not three enriched ones per atom pair — a pair that does
            // not hold, `popcount(x << g)` against `popcount(y << g)`, would
            // cost that on every enriched linarith call)
            if let Some(p) = self.lin_prove(st, &goal, !self.in_atom_congr)? {
                return Ok(Some(p));
            }
            // integer applications of one function (`h(p.a, p.b)` against
            // `h(q.a, q.b)` inside `g(.., p.c)`): their arguments, below
            return self.arg_congruence_n(st, &goal, n + 1);
        }
        // slices and arrays: extensionality over the lists
        if let Term::App { .. } = &**dom {
            let (h, targs) = crate::elab::items::spine(dom);
            if let Term::Global(g) = &*h {
                let list_ind = self.n.list;
                if Some(*g) == self.n.slice && targs.len() == 1 {
                    let lx = mk::fst(mk::snd(xt.clone()));
                    let ly = mk::fst(mk::snd(yt.clone()));
                    let Some(p) = self.prove_list_eq(st, &targs[0], &lx, &ly, n)? else { return Ok(None) };
                    let Some(ext) = self.env.lookup_global("slice::ext") else { return Ok(None) };
                    let _ = list_ind;
                    return Ok(Some(mk::apps(mk::global(ext), [(Rel::Rel, targs[0].clone()), (Rel::Rel, xt.clone()), (Rel::Rel, yt.clone()), (Rel::Irr, p)])));
                }
                if Some(*g) == self.n.array && targs.len() == 2 {
                    let lx = mk::fst(xt.clone());
                    let ly = mk::fst(yt.clone());
                    let Some(p) = self.prove_list_eq(st, &targs[0], &lx, &ly, n)? else { return Ok(None) };
                    let Some(ext) = self.env.lookup_global("array::ext") else { return Ok(None) };
                    return Ok(Some(mk::apps(
                        mk::global(ext),
                        [(Rel::Rel, targs[0].clone()), (Rel::Rel, targs[1].clone()), (Rel::Rel, xt.clone()), (Rel::Rel, yt.clone()), (Rel::Irr, p)],
                    )));
                }
            }
        }
        // nested applications
        let _ = d;
        self.arg_congruence_n(st, &goal, n + 1)
    }

    /// Whether an integer equation `x == y` is false for every value of its
    /// atoms: the linear forms of `x` and `y` differ by a nonzero constant
    /// (the atoms cancel in the negated goal and one of its refutation
    /// problems holds by its constant alone). A cheap check (no search) that
    /// only ever rejects an attempt; it never proves anything.
    pub fn arith_distinct(&mut self, st: &St, goal: &V) -> R<bool> {
        let goal_tm = self.quote(st, goal);
        let Some(sys) = self.linearize(st, &[], &goal_tm)? else { return Ok(false) };
        let mut any_true = false;
        for p in &sys.problems {
            let neg: Vec<&sandblaster_kernel::linarith::Constraint> =
                p.iter().filter(|c| c.origin == sandblaster_kernel::linarith::ConstraintOrigin::NegatedGoal).collect();
            if neg.is_empty() || neg.iter().any(|c| !c.coeffs.is_empty()) {
                return Ok(false);
            }
            let zero = sandblaster_kernel::term::BigInt::from(0);
            let holds = neg.iter().all(|c| match c.kind {
                sandblaster_kernel::linarith::ConstraintKind::Le0 => c.constant <= zero,
                sandblaster_kernel::linarith::ConstraintKind::Eq0 => c.constant == zero,
            });
            any_true |= holds;
        }
        Ok(any_true)
    }

    /// A fact `x == y` (or `y == x`, through `eq::sym`), or conversion.
    fn fact_or_sym(&mut self, st: &St, goal: &V, dom: &Tm, xt: &Tm, yt: &Tm) -> R<Option<Tm>> {
        let d = st.depth();
        let Some((_, x, y)) = as_eq(goal) else { return Ok(None) };
        let (x, y) = (x.clone(), y.clone());
        if self.conv(d, &x, &y)? {
            return Ok(Some(mk::refl(dom.clone(), xt.clone())));
        }
        for f in st.scan_facts().iter().rev() {
            let Some((_, fl, fr)) = as_eq(&f.ty) else { continue };
            let (fl, fr) = (fl.clone(), fr.clone());
            if self.conv(d, &fl, &x)? && self.conv(d, &fr, &y)? {
                return Ok(Some(st.var(f.lvl)));
            }
            if self.conv(d, &fl, &y)? && self.conv(d, &fr, &x)?
                && let Some(sym) = self.n.eq_sym
            {
                return Ok(Some(mk::apps(mk::global(sym), [(Rel::Rel, dom.clone()), (Rel::Rel, yt.clone()), (Rel::Rel, xt.clone()), (Rel::Rel, st.var(f.lvl))])));
            }
        }
        Ok(None)
    }

    /// Prove `lx == ly` (list terms at the state's depth, element type
    /// `elem`): conversion, a fact, a rewrite-rule instance, or argument
    /// congruence.
    fn prove_list_eq(&mut self, st: &St, elem: &Tm, lx: &Tm, ly: &Tm, n: u32) -> R<Option<Tm>> {
        let Some(list) = self.n.list else { return Ok(None) };
        let lty = mk::ind(list, vec![elem.clone()]);
        let (Some(xv), Some(yv)) = (self.eval(st, lx)?, self.eval(st, ly)?) else { return Ok(None) };
        let Some(ltyv) = self.eval(st, &lty)? else { return Ok(None) };
        let goal = Rc::new(Value::Eq { ty: ltyv, lhs: xv.clone(), rhs: yv.clone() });
        if let Some(p) = self.fact_or_sym(st, &goal, &lty, lx, ly)? {
            return Ok(Some(p));
        }
        // one rewrite-rule step on either side
        if let Some(p) = self.rule_step_eq(st, &lty, &xv, &yv, lx, ly, false)? {
            return Ok(Some(p));
        }
        if let Some(p) = self.rule_step_eq(st, &lty, &yv, &xv, ly, lx, true)? {
            return Ok(Some(p));
        }
        self.arg_congruence_n(st, &goal, n + 1)
    }

    /// `from == to` by one instance of a rewrite rule whose left side
    /// matches `from` and whose right side converts with `to` (with `sym`,
    /// the proof is of `to == from`).
    #[allow(clippy::too_many_arguments)]
    fn rule_step_eq(&mut self, st: &St, ty: &Tm, from: &V, to: &V, from_t: &Tm, to_t: &Tm, sym: bool) -> R<Option<Tm>> {
        let d = st.depth();
        for r in self.rules(st, Role::Rewrite) {
            let Some(op) = self.open(&r.ty, d)? else { continue };
            let Some((_, lhs, _)) = as_eq(&op.concl) else { continue };
            let lhs = lhs.clone();
            let mut sub = vec![None; op.binders.len()];
            if !self.pmatch(d, &lhs, from, op.base, &mut sub)? {
                continue;
            }
            let hp = vec![None; op.binders.len()];
            let Some((p, concl)) = self.instantiate(st, &r.head, &r.ty, &sub, &hp, None)? else { continue };
            let Some((_, l2, r2)) = as_eq(&concl) else { continue };
            let (l2, r2) = (l2.clone(), r2.clone());
            if self.conv(d, &l2, from)? && self.conv(d, &r2, to)? {
                self.note(format!("list congruence by rule {}", r.name));
                if !sym {
                    return Ok(Some(p));
                }
                let Some(eqsym) = self.n.eq_sym else { return Ok(None) };
                return Ok(Some(mk::apps(mk::global(eqsym), [(Rel::Rel, ty.clone()), (Rel::Rel, from_t.clone()), (Rel::Rel, to_t.clone()), (Rel::Rel, p)])));
            }
        }
        Ok(None)
    }
}

/// Whether a constructor value has `Irr` arguments, here or in nested
/// constructor arguments (up to `depth` levels).
fn has_irr_ctor(v: &V, depth: u32) -> bool {
    match &**v {
        Value::Ctor { args, .. } => args.iter().any(|a| match a {
            Arg::Irr(_) => true,
            Arg::Rel(x) => depth > 0 && has_irr_ctor(x, depth - 1),
        }),
        Value::Pair { fst, snd } => depth > 0 && (has_irr_ctor(fst, depth - 1) || matches!(snd, Arg::Rel(x) if has_irr_ctor(x, depth - 1))),
        _ => false,
    }
}
