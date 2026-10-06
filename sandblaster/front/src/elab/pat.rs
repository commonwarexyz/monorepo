//! Pattern compilation (DESIGN.md §3.3, §7.5): nested patterns become
//! nested single-level core matches with **first-match** semantics.
//!
//! Or-patterns are expanded first with the normative expansion of §7.3
//! ([`expand_or_arms`]: consecutive arms `p₁ if g => e; p₂ if
//! g => e; …`, leftmost alternative varying slowest), so a guard is retried
//! per alternative exactly as rustc does. The rows are then compiled as a
//! clause matrix (Maranget-style decision tree):
//!
//! * a row whose patterns are all irrefutable binds its variables and runs
//!   its arm; a guard becomes `if g { arm } else { <remaining rows> }`;
//! * otherwise the first column with a refutable pattern in the first row is
//!   tested:
//!   - single-constructor types (tuples, structs) are **projected** (no
//!     test, no path equation: fields are `πₖ`); in exec and spec bodies a
//!     recursive self-call is bound by a `let` first, so the call is
//!     evaluated once, not once per field;
//!   - `Option`, enums and `bool` get one dependent match (§7.2) with an arm
//!     per constructor, rows specialized per constructor;
//!   - integer literals and ranges are comparisons (`eq`, `le`) in dependent
//!     bool matches; rows are kept, dropped or turned into wildcards by
//!     interval containment;
//!   - slice patterns split on the length `fst s` with `le` tests into the
//!     exact lengths `0..K` and the case `len ≥ K` (K large enough for every
//!     fixed-length pattern), elements are `slice::index` (or
//!     `array::index`) at literal offsets from the start or the end, and
//!     `rest @ ..` bindings are `slice::range` sub-slices (sub-arrays via
//!     `slice::prefix_array` for array patterns); arrays have a single
//!     length case;
//! * no row left means the path is contradictory: `absurd` with an
//!   `Unreachable` obligation (only reachable through integer patterns,
//!   since exhaustiveness is checked by the front end).
//!
//! `let` patterns use the same compiler with one row; `let … else` adds the
//! wildcard row running the diverging `else` block.

use sandblaster_kernel::term::{PrimOp, Rel, Term, Tm, Width};
use sandblaster_kernel::util::mk;

use super::exec::{Answer, K};
use super::{internal, Elab, ElabError, ErrKind, Val, R};
use crate::hir::*;
use crate::prover::ObligationKind;
use crate::span::Span;

/// How a row binds a variable.
#[derive(Clone, Debug)]
enum Bind {
    /// The value of an occurrence.
    Val(Val),
    /// A `rest @ ..` sub-slice / sub-array of the slice occurrence `s`.
    Rest { s: Val, from_start: u64, from_end: u64, exact_len: Option<u64>, elem: Ty, array: Option<u64>, by_ref: bool },
}

#[derive(Clone, Debug)]
struct Row<'a> {
    pats: Vec<Option<&'a Pat>>,
    binds: Vec<(LocalId, Bind)>,
    arm: usize,
}

/// A column occurrence: its term and HIR type.
#[derive(Clone, Debug)]
struct Occ {
    val: Val,
    ty: Ty,
}

impl<'a> Elab<'a> {
    /// Stores expanded or-arms for the rest of the elaboration (they must
    /// live as long as the HIR; leaked, bounded by the program size).
    pub fn arena_arms(&mut self, v: Vec<Arm>) -> &'a [Arm] {
        Box::leak(v.into_boxed_slice())
    }

    /// Stores a synthesized pattern (see [`Elab::arena_arms`]).
    pub fn arena_pat(&mut self, p: Pat) -> &'a Pat {
        Box::leak(Box::new(p))
    }

    /// Or-arms expanded (§7.3), without copying when there is nothing to
    /// expand.
    pub fn expanded_arms(&mut self, arms: &'a [Arm]) -> &'a [Arm] {
        if arms.iter().any(|a| a.pat.has_or()) {
            let v = expand_or_arms(arms);
            self.arena_arms(v)
        } else {
            arms
        }
    }

    /// Compiles `arms` (already or-expanded, no guards used by `on_arm`
    /// other than the arms' own) against a value.
    pub fn match_on(&mut self, v: Val, scrut_ty: &Ty, arms: &'a [Arm], answer: &Answer, span: Span, on_arm: &mut dyn FnMut(&mut Elab<'a>, usize) -> R<Tm>) -> R<Tm> {
        let rows: Vec<Row<'a>> = arms.iter().enumerate().map(|(i, a)| Row { pats: vec![Some(&a.pat)], binds: vec![], arm: i }).collect();
        let occs = vec![Occ { val: v, ty: scrut_ty.clone() }];
        let guards: Vec<Option<&'a Expr>> = arms.iter().map(|a| a.guard.as_ref()).collect();
        self.compile(occs, rows, &guards, answer, span, on_arm)
    }

    /// `match scrut { arms }`.
    pub fn match_expr(&mut self, e: &'a Expr, scrut: &'a Expr, arms: &'a [Arm], k: &mut K<'_, 'a>) -> R<Tm> {
        let span = e.span;
        let expanded: &'a [Arm] = self.expanded_arms(arms);
        let mut body = |s: &mut Elab<'a>, answer: &Answer, leaf: &mut K<'_, 'a>| -> R<Tm> {
            s.expr(scrut, &mut |s, v| {
                let rows: Vec<Row<'a>> = expanded.iter().enumerate().map(|(i, a)| Row { pats: vec![Some(&a.pat)], binds: vec![], arm: i }).collect();
                let occs = vec![Occ { val: v, ty: scrut.ty.clone() }];
                let guards: Vec<Option<&'a Expr>> = expanded.iter().map(|a| a.guard.as_ref()).collect();
                s.compile(occs, rows, &guards, answer, span, &mut |s, i| s.expr(&expanded[i].body, leaf))
            })
        };
        if self.use_cps(e) {
            let answer = Answer::Ty(self.f.answer.clone());
            self.f.cps_depth += 1;
            let r = body(self, &answer, k);
            self.f.cps_depth -= 1;
            return r;
        }
        self.join(e, k, &mut body)
    }

    /// Binds an irrefutable pattern to a value, then runs `k`.
    pub fn bind_irrefutable(&mut self, pat: &'a Pat, v: Val, span: Span, k: &mut dyn FnMut(&mut Elab<'a>) -> R<Tm>) -> R<Tm> {
        // fast path: a plain binding
        if let PatKind::Binding { local, sub: None, .. } = &pat.kind {
            return self.bind_local(*local, v, span, k);
        }
        if let PatKind::Wild = &pat.kind {
            let ty = pat.ty.clone();
            return self.discard_val(&ty, v, span, k);
        }
        let answer = Answer::Ty(self.f.answer.clone());
        let rows: Vec<Row<'a>> = self.alternatives(pat).into_iter().map(|p| Row { pats: vec![Some(p)], binds: vec![], arm: 0 }).collect();
        let occs = vec![Occ { val: v, ty: pat.ty.clone() }];
        self.compile(occs, rows, &[None], &answer, span, &mut |s, _| k(s))
    }

    /// The or-free alternatives of a pattern (§7.3 order).
    fn alternatives(&mut self, pat: &'a Pat) -> Vec<&'a Pat> {
        if !pat.has_or() {
            return vec![pat];
        }
        let alts: &'a [Pat] = Box::leak(expand_pat(pat).into_boxed_slice());
        alts.iter().collect()
    }

    /// `let pat = v else { els };` then `k` (§3.3).
    pub fn let_else(&mut self, pat: &'a Pat, v: Val, els: &'a Block, span: Span, k: &mut dyn FnMut(&mut Elab<'a>) -> R<Tm>) -> R<Tm> {
        let answer = Answer::Ty(self.f.answer.clone());
        let wild: &'a Pat = self.arena_pat(Pat { kind: PatKind::Wild, ty: pat.ty.clone(), span });
        let mut rows: Vec<Row<'a>> = self.alternatives(pat).into_iter().map(|p| Row { pats: vec![Some(p)], binds: vec![], arm: 0 }).collect();
        rows.push(Row { pats: vec![Some(wild)], binds: vec![], arm: 1 });
        let occs = vec![Occ { val: v, ty: pat.ty.clone() }];
        self.compile(occs, rows, &[None, None], &answer, span, &mut |s, i| {
            if i == 0 {
                k(s)
            } else {
                s.block(els, &mut |_, _| Err(ElabError { span, msg: "the `else` block of `let … else` does not diverge".into(), kind: ErrKind::Internal }))
            }
        })
    }

    /// Binds the value of a wildcard-matched expression to `_` if it could
    /// carry proof slots.
    fn discard_val(&mut self, ty: &Ty, v: Val, span: Span, k: &mut dyn FnMut(&mut Elab<'a>) -> R<Tm>) -> R<Tm> {
        if v.is_trivial() || ty.is_unit() || ty.is_never() {
            return k(self);
        }
        let t = self.ty(ty, span)?;
        let d = self.depth();
        self.let_in("_", Rel::Rel, t, v.at(d), &mut |me, _| k(me))
    }

    // ------------------------------------------------------------------
    // the matrix compiler
    // ------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn compile(&mut self, occs: Vec<Occ>, rows: Vec<Row<'a>>, guards: &[Option<&'a Expr>], answer: &Answer, span: Span, on_arm: &mut dyn FnMut(&mut Elab<'a>, usize) -> R<Tm>) -> R<Tm> {
        // normalize: strip derefs, move bindings out of the patterns
        let rows: Vec<Row<'a>> = rows.into_iter().map(|r| normalize_row(r, &occs)).collect();
        let Some(first) = rows.first() else {
            return self.unreachable_answer(answer, span);
        };
        let col = first.pats.iter().position(|p| p.is_some());
        let Some(c) = col else {
            // first row matches: bind and run (guard falls through)
            let row = first.clone();
            let rest: Vec<Row<'a>> = rows[1..].to_vec();
            return self.apply_binds(&row.binds, 0, span, &mut |s| match guards.get(row.arm).copied().flatten() {
                None => on_arm(s, row.arm),
                Some(g) => s.expr(g, &mut |s, vg| {
                    let cond = vg.at(s.depth());
                    let occs2 = occs.clone();
                    let rest2 = rest.clone();
                    s.if_then_else(cond, answer, span, &mut |s, b| if b { on_arm(s, row.arm) } else { s.compile(occs2.clone(), rest2.clone(), guards, answer, span, on_arm) })
                }),
            });
        };
        let pat = first.pats[c].expect("column has a pattern");
        let occ = occs[c].clone();
        match &pat.kind {
            PatKind::Tuple(_) | PatKind::Ctor { .. } | PatKind::Lit(Lit::Bool(_)) => self.compile_ctor(occs, rows, c, &occ, guards, answer, span, on_arm),
            PatKind::Lit(Lit::Int(n)) => self.compile_range(occs, rows, c, &occ, (*n, *n), guards, answer, span, on_arm),
            PatKind::Range { lo, hi } => self.compile_range(occs, rows, c, &occ, (*lo, *hi), guards, answer, span, on_arm),
            PatKind::Slice { .. } if matches!(occ.ty.peel_refs(), Ty::Seq(_)) => self.compile_seq(occs, rows, c, &occ, guards, answer, span, on_arm),
            PatKind::Slice { .. } => self.compile_slice(occs, rows, c, &occ, guards, answer, span, on_arm),
            PatKind::Wild | PatKind::Binding { .. } | PatKind::Deref { .. } => internal(span, "unnormalized pattern"),
            PatKind::Or(_) => internal(span, "or-pattern after expansion"),
        }
    }

    fn unreachable_answer(&mut self, answer: &Answer, span: Span) -> R<Tm> {
        let empty = mk::ind(self.p.empty, vec![]);
        let p = self.prove(ObligationKind::Unreachable, span, &empty, false)?;
        let a = self.answer_tm(answer, span)?;
        Ok(std::rc::Rc::new(sandblaster_kernel::term::Term::Absurd { ty: a, proof: p }))
    }

    /// Applies a row's bindings in order.
    fn apply_binds(&mut self, binds: &[(LocalId, Bind)], i: usize, span: Span, k: &mut dyn FnMut(&mut Elab<'a>) -> R<Tm>) -> R<Tm> {
        let Some((l, b)) = binds.get(i) else { return k(self) };
        let v = match b {
            Bind::Val(v) => v.clone(),
            Bind::Rest { s, from_start, from_end, exact_len, elem, array, by_ref } => {
                let t = self.rest_value(s, *from_start, *from_end, *exact_len, elem, *array, *by_ref, span)?;
                Val::new(t, self.depth())
            }
        };
        let l = *l;
        self.bind_local(l, v, span, &mut |s| s.apply_binds(binds, i + 1, span, k))
    }

    /// Constructor columns: projection for single-constructor types, else a
    /// dependent match.
    #[allow(clippy::too_many_arguments)]
    fn compile_ctor(&mut self, occs: Vec<Occ>, rows: Vec<Row<'a>>, c: usize, occ: &Occ, guards: &[Option<&'a Expr>], answer: &Answer, span: Span, on_arm: &mut dyn FnMut(&mut Elab<'a>, usize) -> R<Tm>) -> R<Tm> {
        let ty = occ.ty.peel_refs().clone();
        let nctors = self.ctor_count(&ty, span)?;
        let (ind, params) = self.ind_of(&ty, span)?;
        if nctors == 1 && self.f.mode == super::Mode::Exec && is_self_call(&occ.val.at(self.depth())) && self.ctor_field_tys(&ty, 0, span)?.len() >= 2 {
            // a recursive self-call (`let (a, b) = f(x);` in `f`) is bound
            // once and projected through its variable: each projection of
            // the term itself would be a copy of the call, which evaluation
            // (the kernel's, the reference evaluator's) computes once per
            // projection — exponentially in the depth of the recursion
            // (`reconstruct_digest`'s state tuple). The `let` is
            // transparent: proofs see the same value.
            let t = occ.val.at(self.depth());
            let tty = self.ty(&ty, span)?;
            return self.let_in("t", Rel::Rel, tty, t, &mut |s, lvl| {
                let mut occs2 = occs.clone();
                occs2[c] = Occ { val: Val::new(s.f.scope.var(lvl), s.depth()), ty: occ.ty.clone() };
                let bound = occs2[c].clone();
                s.compile_ctor(occs2, rows.clone(), c, &bound, guards, answer, span, on_arm)
            });
        }
        if nctors == 1 {
            // a projected struct with an invariant: its facts first, so the
            // field bindings have them (§15.3)
            let occ_v = occ.val.clone();
            let occs1 = occs.clone();
            let rows1 = rows.clone();
            return self.with_inv_facts(&occ_v, &ty, span, &mut |s| {
                let ftys = s.ctor_field_tys(&ty, 0, span)?;
                let d = s.depth();
                let base = occ_v.at(d);
                let mut sub = Vec::new();
                for (k, ft) in ftys.iter().enumerate() {
                    let ftm = s.ty(ft, span)?;
                    sub.push(Occ { val: Val::new(s.proj(ind, params.clone(), base.clone(), k, ftys.len(), ftm), d), ty: ft.clone() });
                }
                let (occs2, rows2) = specialize(&occs1, rows1.clone(), c, 0, ftys.len(), &sub);
                s.compile(occs2, rows2, guards, answer, span, on_arm)
            });
        }
        let scrut = occ.val.at(self.depth());
        let occs_c = occs.clone();
        let rows_c = rows.clone();
        let ty2 = ty.clone();
        self.dep_match(ind, params, scrut, answer, span, &mut |s, ci, lvls| {
            let ftys = s.ctor_field_tys(&ty2, ci, span)?;
            let d = s.depth();
            let sub: Vec<Occ> = lvls.iter().zip(&ftys).map(|(l, t)| Occ { val: Val::new(s.f.scope.var(*l), d), ty: t.clone() }).collect();
            let (occs2, rows2) = specialize(&occs_c, rows_c.clone(), c, ci, ftys.len(), &sub);
            s.compile(occs2, rows2, guards, answer, span, on_arm)
        })
    }

    /// Integer literal/range columns: a comparison test.
    #[allow(clippy::too_many_arguments)]
    fn compile_range(&mut self, occs: Vec<Occ>, rows: Vec<Row<'a>>, c: usize, occ: &Occ, r0: (u128, u128), guards: &[Option<&'a Expr>], answer: &Answer, span: Span, on_arm: &mut dyn FnMut(&mut Elab<'a>, usize) -> R<Tm>) -> R<Tm> {
        let Ty::Uint(u) = occ.ty.peel_refs() else { return internal(span, "integer pattern on a non-integer") };
        let w = u.width();
        let max = u.max_value();
        // rows in the true / false branch
        let (mut rows_t, mut rows_f) = (Vec::new(), Vec::new());
        for r in &rows {
            let iv = match r.pats[c].map(|p| &p.kind) {
                None => None,
                Some(PatKind::Lit(Lit::Int(n))) => Some((*n, *n)),
                Some(PatKind::Range { lo, hi }) => Some((*lo, *hi)),
                Some(_) => return internal(span, "mixed pattern kinds in an integer column"),
            };
            match iv {
                None => {
                    rows_t.push(r.clone());
                    rows_f.push(r.clone());
                }
                Some((lo, hi)) => {
                    // true branch: x ∈ r0
                    if lo <= r0.0 && r0.1 <= hi {
                        let mut r2 = r.clone();
                        r2.pats[c] = None;
                        rows_t.push(r2);
                    } else if !(hi < r0.0 || r0.1 < lo) {
                        rows_t.push(r.clone());
                    }
                    // false branch: x ∉ r0
                    if !(r0.0 <= lo && hi <= r0.1) {
                        rows_f.push(r.clone());
                    }
                }
            }
        }
        let x = occ.val.at(self.depth());
        let lit = |n: u128| mk::lit(w, n);
        let mut tests: Vec<Tm> = Vec::new();
        if r0.0 == r0.1 {
            tests.push(mk::prim(PrimOp::Eq(w), vec![x.clone(), lit(r0.0)], vec![]));
        } else {
            if r0.0 > 0 {
                tests.push(mk::prim(PrimOp::Le(w), vec![lit(r0.0), x.clone()], vec![]));
            }
            if r0.1 < max {
                tests.push(mk::prim(PrimOp::Le(w), vec![x.clone(), lit(r0.1)], vec![]));
            }
        }
        self.range_tests(&tests, 0, &occs, &rows_t, &rows_f, guards, answer, span, on_arm)
    }

    #[allow(clippy::too_many_arguments)]
    fn range_tests(&mut self, tests: &[Tm], i: usize, occs: &[Occ], rows_t: &[Row<'a>], rows_f: &[Row<'a>], guards: &[Option<&'a Expr>], answer: &Answer, span: Span, on_arm: &mut dyn FnMut(&mut Elab<'a>, usize) -> R<Tm>) -> R<Tm> {
        if i == tests.len() {
            return self.compile(occs.to_vec(), rows_t.to_vec(), guards, answer, span, on_arm);
        }
        let d0 = self.depth();
        let t = tests[i].clone();
        let tv = Val::new(t, d0);
        self.if_then_else(tv.at(self.depth()), answer, span, &mut |s, b| {
            if b {
                s.range_tests(tests_shifted(tests, d0, s.depth()).as_slice(), i + 1, occs, rows_t, rows_f, guards, answer, span, on_arm)
            } else {
                s.compile(occs.to_vec(), rows_f.to_vec(), guards, answer, span, on_arm)
            }
        })
    }

    /// Ghost `Seq<T>` pattern columns (§4.1): a match on the list, `Nil`
    /// and `Cons(head, tail)`; a prefix pattern `[p, ps.., rest @ ..]`
    /// becomes `p` on the head and `[ps.., rest @ ..]` on the tail (prefix
    /// patterns only: the typechecker rejects elements after `..`).
    #[allow(clippy::too_many_arguments)]
    fn compile_seq(&mut self, occs: Vec<Occ>, rows: Vec<Row<'a>>, c: usize, occ: &Occ, guards: &[Option<&'a Expr>], answer: &Answer, span: Span, on_arm: &mut dyn FnMut(&mut Elab<'a>, usize) -> R<Tm>) -> R<Tm> {
        let Ty::Seq(elem) = occ.ty.peel_refs().clone() else { return internal(span, "Seq pattern on a non-Seq") };
        let elem = *elem;
        let seq_ty = Ty::Seq(Box::new(elem.clone()));
        let et = self.ty(&elem, span)?;
        let scrut = occ.val.at(self.depth());
        let list = self.p.list;
        let (occs_c, rows_c) = (occs.clone(), rows.clone());
        let occ_c = occ.clone();
        self.dep_match(list, vec![et], scrut, answer, span, &mut |s, ci, lvls| {
            let d = s.depth();
            let mut new_rows = Vec::new();
            let sub: Vec<Occ> = if ci == 0 { vec![] } else { vec![Occ { val: Val::new(s.f.scope.var(lvls[0]), d), ty: elem.clone() }, Occ { val: Val::new(s.f.scope.var(lvls[1]), d), ty: seq_ty.clone() }] };
            for r in &rows_c {
                let mut pats: Vec<Option<&'a Pat>> = r.pats[..c].to_vec();
                let mut binds = r.binds.clone();
                match (ci, r.pats[c].map(|p| &p.kind)) {
                    (0, None) => {}
                    (_, None) => pats.extend([None, None]),
                    (0, Some(PatKind::Slice { prefix, rest, .. })) => {
                        if !prefix.is_empty() {
                            continue;
                        }
                        if let Some(Some(rp)) = rest
                            && let PatKind::Binding { local, .. } = &rp.kind
                        {
                            binds.push((*local, Bind::Val(occ_c.val.clone())));
                        }
                    }
                    (_, Some(PatKind::Slice { prefix, rest, .. })) => match prefix.split_first() {
                        None => {
                            let Some(r) = rest else { continue };
                            if let Some(rp) = r
                                && let PatKind::Binding { local, .. } = &rp.kind
                            {
                                binds.push((*local, Bind::Val(occ_c.val.clone())));
                            }
                            pats.extend([None, None]);
                        }
                        Some((p0, ps)) => {
                            let tail: Option<&'a Pat> = if ps.is_empty() {
                                match rest {
                                    Some(Some(rp)) => Some(&**rp),
                                    Some(None) => None,
                                    None => Some(s.arena_pat(Pat { kind: PatKind::Slice { prefix: vec![], rest: None, suffix: vec![] }, ty: seq_ty.clone(), span })),
                                }
                            } else {
                                Some(s.arena_pat(Pat { kind: PatKind::Slice { prefix: ps.to_vec(), rest: rest.clone(), suffix: vec![] }, ty: seq_ty.clone(), span }))
                            };
                            pats.push(Some(p0));
                            pats.push(tail);
                        }
                    },
                    (_, Some(_)) => return internal(span, "mixed pattern kinds in a `Seq` column"),
                }
                pats.extend_from_slice(&r.pats[c + 1..]);
                new_rows.push(Row { pats, binds, arm: r.arm });
            }
            let mut new_occs: Vec<Occ> = occs_c[..c].to_vec();
            new_occs.extend(sub);
            new_occs.extend_from_slice(&occs_c[c + 1..]);
            s.compile(new_occs, new_rows, guards, answer, span, on_arm)
        })
    }

    /// Slice/array pattern columns: length cases (see the module docs).
    #[allow(clippy::too_many_arguments)]
    fn compile_slice(&mut self, occs: Vec<Occ>, rows: Vec<Row<'a>>, c: usize, occ: &Occ, guards: &[Option<&'a Expr>], answer: &Answer, span: Span, on_arm: &mut dyn FnMut(&mut Elab<'a>, usize) -> R<Tm>) -> R<Tm> {
        let (elem, array) = match occ.ty.peel_refs() {
            Ty::Array(e, n) => ((**e).clone(), Some(*n)),
            Ty::Slice(e) => ((**e).clone(), None),
            other => return internal(span, format!("slice pattern on `{}`", self.krate.ty_str(other))),
        };
        // shapes (prefix, suffix, has_rest) of the slice patterns in the column
        let mut shapes = Vec::new();
        for r in &rows {
            if let Some(PatKind::Slice { prefix, rest, suffix }) = r.pats[c].map(|p| &p.kind) {
                shapes.push((prefix.len() as u64, suffix.len() as u64, rest.is_some()));
            }
        }
        if let Some(n) = array {
            return self.slice_case(occs, rows, c, occ, &elem, array, SliceCase::Exact(n), guards, answer, span, on_arm);
        }
        let f = shapes.iter().filter(|s| !s.2).map(|s| s.0 + s.1).max();
        let r = shapes.iter().filter(|s| s.2).map(|s| s.0 + s.1).max();
        let kk = match (f, r) {
            (Some(f), Some(r)) => (f + 1).max(r),
            (Some(f), None) => f + 1,
            (None, Some(r)) => r,
            (None, None) => 0,
        };
        self.slice_len_chain(occs, rows, c, occ, &elem, 0, kk, guards, answer, span, on_arm)
    }

    /// `if len ≤ ℓ { case ℓ } else { … }` for ℓ < K, then the `len ≥ K` case.
    #[allow(clippy::too_many_arguments)]
    fn slice_len_chain(&mut self, occs: Vec<Occ>, rows: Vec<Row<'a>>, c: usize, occ: &Occ, elem: &Ty, l: u64, kk: u64, guards: &[Option<&'a Expr>], answer: &Answer, span: Span, on_arm: &mut dyn FnMut(&mut Elab<'a>, usize) -> R<Tm>) -> R<Tm> {
        if l >= kk {
            return self.slice_case(occs, rows, c, occ, elem, None, SliceCase::AtLeast, guards, answer, span, on_arm);
        }
        let len = mk::fst(occ.val.at(self.depth()));
        let test = mk::prim(PrimOp::Le(Width::Usize), vec![len, mk::lit(Width::Usize, l)], vec![]);
        let occs2 = occs.clone();
        let rows2 = rows.clone();
        self.if_then_else(test, answer, span, &mut |s, b| {
            if b {
                s.slice_case(occs2.clone(), rows2.clone(), c, occ, elem, None, SliceCase::Exact(l), guards, answer, span, on_arm)
            } else {
                s.slice_len_chain(occs2.clone(), rows2.clone(), c, occ, elem, l + 1, kk, guards, answer, span, on_arm)
            }
        })
    }

    /// One length case: element columns and row-local rest bindings.
    #[allow(clippy::too_many_arguments)]
    fn slice_case(&mut self, occs: Vec<Occ>, rows: Vec<Row<'a>>, c: usize, occ: &Occ, elem: &Ty, array: Option<u64>, case: SliceCase, guards: &[Option<&'a Expr>], answer: &Answer, span: Span, on_arm: &mut dyn FnMut(&mut Elab<'a>, usize) -> R<Tm>) -> R<Tm> {
        // column layout: P prefix columns, Q suffix columns
        let (pp, qq) = match case {
            SliceCase::Exact(l) => (l, 0),
            SliceCase::AtLeast => {
                let mut p = 0;
                let mut q = 0;
                for r in &rows {
                    if let Some(PatKind::Slice { prefix, rest: Some(_), suffix }) = r.pats[c].map(|p| &p.kind) {
                        p = p.max(prefix.len() as u64);
                        q = q.max(suffix.len() as u64);
                    }
                }
                (p, q)
            }
        };
        // element occurrences
        let d = self.depth();
        let s = occ.val.at(d);
        let mut sub = Vec::new();
        for i in 0..pp {
            let t = self.elem_at(&s, elem, array, IndexFrom::Start(i), span)?;
            sub.push(Occ { val: Val::new(t, d), ty: elem.clone() });
        }
        for j in 0..qq {
            // suffix column j is at index len − (Q − j)
            let t = self.elem_at(&s, elem, array, IndexFrom::End(qq - j), span)?;
            sub.push(Occ { val: Val::new(t, d), ty: elem.clone() });
        }
        let width = (pp + qq) as usize;
        // specialize rows
        let mut new_rows = Vec::new();
        for r in rows {
            let mut pats: Vec<Option<&'a Pat>> = Vec::with_capacity(r.pats.len() - 1 + width);
            pats.extend_from_slice(&r.pats[..c]);
            let mut binds = r.binds.clone();
            match r.pats[c].map(|p| &p.kind) {
                None => pats.extend(std::iter::repeat_n(None, width)),
                Some(PatKind::Slice { prefix, rest, suffix }) => {
                    let (p, q) = (prefix.len() as u64, suffix.len() as u64);
                    let matches = match (case, rest.is_some()) {
                        (SliceCase::Exact(l), false) => p + q == l,
                        (SliceCase::Exact(l), true) => p + q <= l,
                        (SliceCase::AtLeast, false) => false,
                        (SliceCase::AtLeast, true) => true,
                    };
                    if !matches {
                        continue;
                    }
                    let mut cols: Vec<Option<&'a Pat>> = vec![None; width];
                    match case {
                        SliceCase::Exact(l) => {
                            for (i, pt) in prefix.iter().enumerate() {
                                cols[i] = Some(pt);
                            }
                            for (j, pt) in suffix.iter().enumerate() {
                                cols[(l - q) as usize + j] = Some(pt);
                            }
                        }
                        SliceCase::AtLeast => {
                            for (i, pt) in prefix.iter().enumerate() {
                                cols[i] = Some(pt);
                            }
                            for (j, pt) in suffix.iter().enumerate() {
                                cols[(pp + (qq - q)) as usize + j] = Some(pt);
                            }
                        }
                    }
                    pats.extend(cols);
                    if let Some(Some(rp)) = rest
                        && let PatKind::Binding { local, mode, .. } = &rp.kind
                    {
                        let exact_len = match case {
                            SliceCase::Exact(l) => Some(l),
                            SliceCase::AtLeast => None,
                        };
                        binds.push((*local, Bind::Rest { s: occ.val.clone(), from_start: p, from_end: q, exact_len, elem: elem.clone(), array, by_ref: *mode == BindingMode::ByRef }));
                    }
                }
                Some(_) => return internal(span, "mixed pattern kinds in a slice column"),
            }
            pats.extend_from_slice(&r.pats[c + 1..]);
            new_rows.push(Row { pats, binds, arm: r.arm });
        }
        let mut new_occs: Vec<Occ> = occs[..c].to_vec();
        new_occs.extend(sub);
        new_occs.extend_from_slice(&occs[c + 1..]);
        self.compile(new_occs, new_rows, guards, answer, span, on_arm)
    }

    /// Element `i` from the start, or `m` from the end, of a slice/array.
    fn elem_at(&mut self, s: &Tm, elem: &Ty, array: Option<u64>, at: IndexFrom, span: Span) -> R<Tm> {
        let len = match array {
            Some(n) => mk::lit(Width::Usize, n),
            None => mk::fst(s.clone()),
        };
        let idx = match (at, array) {
            (IndexFrom::Start(i), _) => mk::lit(Width::Usize, i),
            (IndexFrom::End(m), Some(n)) => mk::lit(Width::Usize, n - m),
            (IndexFrom::End(m), None) => {
                let g = self.holds(mk::prim(PrimOp::Le(Width::Usize), vec![mk::lit(Width::Usize, m), len.clone()], vec![]));
                let p = self.prove(ObligationKind::WellFormed, span, &g, false)?;
                mk::prim(PrimOp::Sub(Width::Usize), vec![len.clone(), mk::lit(Width::Usize, m)], vec![p])
            }
        };
        let ty = match array {
            Some(n) => Ty::Array(Box::new(elem.clone()), n),
            None => Ty::Slice(Box::new(elem.clone())),
        };
        self.index(&ty, s.clone(), idx, span)
    }

    /// The value of a `rest @ ..` binding.
    #[allow(clippy::too_many_arguments)]
    fn rest_value(&mut self, s: &Val, from_start: u64, from_end: u64, exact_len: Option<u64>, elem: &Ty, array: Option<u64>, by_ref: bool, span: Span) -> R<Tm> {
        let d = self.depth();
        let st = s.at(d);
        let _ = by_ref;
        let (slice, len) = match array {
            Some(n) => (self.as_slice(elem, n, st, span)?, mk::lit(Width::Usize, n)),
            None => {
                let len = match exact_len {
                    Some(l) => mk::lit(Width::Usize, l),
                    None => mk::fst(st.clone()),
                };
                (st, len)
            }
        };
        let lo = mk::lit(Width::Usize, from_start);
        let hi = match (array, exact_len) {
            (Some(n), _) => mk::lit(Width::Usize, n - from_end),
            (None, Some(l)) => mk::lit(Width::Usize, l - from_end),
            (None, None) if from_end == 0 => len.clone(),
            (None, None) => {
                let g = self.holds(mk::prim(PrimOp::Le(Width::Usize), vec![mk::lit(Width::Usize, from_end), len.clone()], vec![]));
                let p = self.prove(ObligationKind::WellFormed, span, &g, false)?;
                mk::prim(PrimOp::Sub(Width::Usize), vec![len.clone(), mk::lit(Width::Usize, from_end)], vec![p])
            }
        };
        let sub = self.slice_range(&Ty::Slice(Box::new(elem.clone())), slice, if from_start == 0 { None } else { Some(lo) }, if from_end == 0 { None } else { Some(hi) }, span)?;
        match array {
            Some(n) => {
                // a sub-array `[T; n − p − q]`
                let k = n - from_start - from_end;
                let et = self.ty(elem, span)?;
                let g = self.holds(mk::prim(PrimOp::Le(Width::Usize), vec![mk::lit(Width::Usize, k), mk::fst(sub.clone())], vec![]));
                let p = self.prove(ObligationKind::WellFormed, span, &g, false)?;
                Ok(mk::apps(mk::global(self.p.g("slice::prefix_array")), [(Rel::Rel, et), (Rel::Rel, sub), (Rel::Rel, mk::lit(Width::Usize, k)), (Rel::Irr, p)]))
            }
            None => Ok(sub),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum SliceCase {
    Exact(u64),
    AtLeast,
}

#[derive(Clone, Copy, Debug)]
enum IndexFrom {
    Start(u64),
    End(u64),
}

fn tests_shifted(tests: &[Tm], from: u32, to: u32) -> Vec<Tm> {
    tests.iter().map(|t| sandblaster_kernel::util::shift(t, (to - from) as i64)).collect()
}

/// Strips derefs and moves bindings out of a row's patterns.
fn normalize_row<'a>(mut r: Row<'a>, occs: &[Occ]) -> Row<'a> {
    for (i, slot) in r.pats.iter_mut().enumerate() {
        let mut p = *slot;
        loop {
            match p.map(|x| &x.kind) {
                Some(PatKind::Deref { pat, .. }) => p = Some(pat),
                Some(PatKind::Binding { local, sub, .. }) => {
                    r.binds.push((*local, Bind::Val(occs[i].val.clone())));
                    p = sub.as_deref();
                }
                Some(PatKind::Wild) => p = None,
                _ => break,
            }
        }
        *slot = p;
    }
    r
}

/// Specializes rows on constructor `ci` of column `c` (with `n` fields):
/// the column is replaced by the field columns `sub`.
fn specialize<'a>(occs: &[Occ], rows: Vec<Row<'a>>, c: usize, ci: u32, n: usize, sub: &[Occ]) -> (Vec<Occ>, Vec<Row<'a>>) {
    let mut new_occs: Vec<Occ> = occs[..c].to_vec();
    new_occs.extend_from_slice(sub);
    new_occs.extend_from_slice(&occs[c + 1..]);
    let mut out = Vec::new();
    for r in rows {
        let mut pats: Vec<Option<&'a Pat>> = r.pats[..c].to_vec();
        match r.pats[c].map(|p| &p.kind) {
            None => pats.extend(std::iter::repeat_n(None, n)),
            Some(PatKind::Tuple(ps)) => pats.extend(ps.iter().map(Some)),
            Some(PatKind::Lit(Lit::Bool(b))) => {
                if u32::from(*b) != ci {
                    continue;
                }
            }
            Some(PatKind::Ctor { ctor, fields, .. }) => {
                let idx = match ctor {
                    Ctor::Struct(_) => 0,
                    Ctor::Variant(_, v) => *v,
                    Ctor::None => 0,
                    Ctor::Some => 1,
                };
                if idx != ci {
                    continue;
                }
                let mut cols: Vec<Option<&'a Pat>> = vec![None; n];
                for (fi, fp) in fields {
                    if (*fi as usize) < n {
                        cols[*fi as usize] = Some(fp);
                    }
                }
                pats.extend(cols);
            }
            Some(_) => continue,
        }
        pats.extend_from_slice(&r.pats[c + 1..]);
        out.push(Row { pats, binds: r.binds, arm: r.arm });
    }
    (new_occs, out)
}

/// Whether `t` is the definition's own recursive call (`Rec`), which
/// [`Elab::compile_ctor`] binds once before projecting it: a recursion
/// that destructures its own result would otherwise evaluate the call
/// once per field at every level (exponentially in the depth). Other
/// calls stay in place (a constant factor, and the shape the
/// checked-structuring walker and the provers expect).
fn is_self_call(t: &Tm) -> bool {
    matches!(&**t, Term::Rec { .. })
}

/// Expands or-patterns of match arms into consecutive arms (cross product of
/// nested or-patterns, leftmost alternative varying slowest), keeping guards
/// and bodies — the normative expansion of DESIGN.md §7.3.
pub fn expand_or_arms(arms: &[Arm]) -> Vec<Arm> {
    let mut out = Vec::new();
    for a in arms {
        for p in expand_pat(&a.pat) {
            out.push(Arm { pat: p, guard: a.guard.clone(), body: a.body.clone(), span: a.span });
        }
    }
    out
}

/// All or-free alternatives of a pattern, in rustc's order.
pub fn expand_pat(p: &Pat) -> Vec<Pat> {
    let mk = |kind: PatKind| Pat { kind, ty: p.ty.clone(), span: p.span };
    match &p.kind {
        PatKind::Or(alts) => alts.iter().flat_map(expand_pat).collect(),
        PatKind::Binding { local, mode, sub: Some(s) } => expand_pat(s).into_iter().map(|s| mk(PatKind::Binding { local: *local, mode: *mode, sub: Some(Box::new(s)) })).collect(),
        PatKind::Tuple(ps) => product(ps).into_iter().map(|v| mk(PatKind::Tuple(v))).collect(),
        PatKind::Ctor { ctor, ty_args, fields } => {
            let ps: Vec<Pat> = fields.iter().map(|(_, p)| p.clone()).collect();
            product(&ps).into_iter().map(|v| mk(PatKind::Ctor { ctor: *ctor, ty_args: ty_args.clone(), fields: fields.iter().map(|(i, _)| *i).zip(v).collect() })).collect()
        }
        PatKind::Deref { pat, implicit } => expand_pat(pat).into_iter().map(|s| mk(PatKind::Deref { pat: Box::new(s), implicit: *implicit })).collect(),
        PatKind::Slice { prefix, rest, suffix } => {
            let mut all: Vec<Pat> = prefix.clone();
            let rest_p = match rest {
                Some(Some(r)) => Some((**r).clone()),
                _ => None,
            };
            if let Some(r) = &rest_p {
                all.push(r.clone());
            }
            all.extend(suffix.iter().cloned());
            product(&all)
                .into_iter()
                .map(|mut v| {
                    let suf: Vec<Pat> = v.split_off(prefix.len() + usize::from(rest_p.is_some()));
                    let r = if rest_p.is_some() { Some(Some(Box::new(v.pop().unwrap()))) } else { rest.as_ref().map(|_| None) };
                    mk(PatKind::Slice { prefix: v, rest: r, suffix: suf })
                })
                .collect()
        }
        _ => vec![p.clone()],
    }
}

fn product(ps: &[Pat]) -> Vec<Vec<Pat>> {
    let mut acc: Vec<Vec<Pat>> = vec![vec![]];
    for p in ps {
        let alts = expand_pat(p);
        let mut next = Vec::new();
        for prefix in &acc {
            for a in &alts {
                let mut v = prefix.clone();
                v.push(a.clone());
                next.push(v);
            }
        }
        acc = next;
    }
    acc
}
