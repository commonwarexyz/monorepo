//! Step → kernel term (optimizer design §11.2).
//!
//! The goal at every point of the proof is `Eq(R, L, S)` where `L` is a
//! **term**: a subterm of the residual's committed body, walked in its own
//! binder structure (like `opt::mirror`), and `S` is a **value**: the source
//! side, unfolded along the process tree. Keeping `L` syntactic matters: the
//! residual's value, read back, is exponentially larger than its term (its
//! proofs share subterms), while the source side stays small (one level of
//! each unfolded definition at a time).
//!
//! A source-side step rewrites the goal through a motive built by `auto`'s
//! term-level abstraction ([`crate::auto::abstraction`], which transports
//! proofs whose types mention the abstracted term, and the
//! dependent-match idiom's path equations, along the motive's equation
//! binder):
//!
//! | step | rewrite with |
//! | --- | --- |
//! | `Unfold g ā` | `Delta(g; ā) : Eq(R, g ā, body[ā])` |
//! | `Prune c = b` | the linarith proof of `Eq(Bool, c, b)` (`auto`'s `decide_bool`) |
//! | `Reuse c` | the enclosing split's path equation `e : Eq(D, c, Cₖ(xs))` |
//! | `Specialize g σ` | the helper's lemma `Eq(R, g__σ dyn̄, g(σ, dyn̄))` (reversed) |
//! | `Word` | `word::eq8_or` / `word::eq8_last` per block of eight bytes (`drive::word`) |
//!
//! and yields the continuation
//! `transport(A, to, from, sym(e), y. M, λ(e' :Irr ..). p) .refl(A, from)`
//! (the `λe'` only when the motive has its equation binder; `p`, a proof of
//! `M[to, e]`, also proves `M[to, e']` because `e'` occurs only in
//! irrelevant positions).

use std::collections::BTreeMap;
use std::rc::Rc;

use sandblaster_kernel::term::{Arm, Idx, Rel, Term, Tm};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::V;

use crate::auto::search::Engine;
use crate::auto::state::St;
use crate::auto::util::shift;

/// A goal `Eq(r, l, s)`: terms at the state's depth (`l` a subterm of the
/// residual, `s` a subterm of the source unfolded along the process tree).
#[derive(Clone)]
pub struct Goal {
    pub r: Tm,
    pub l: Tm,
    pub s: Tm,
}

/// How to turn a proof of the rewritten goal into a proof of the goal.
pub struct Wrap {
    /// `transport(ty, lhs, rhs, eq, motive, ·)` at `depth`.
    pub depth: u32,
    pub ty: Tm,
    pub lhs: Tm,
    pub rhs: Tm,
    pub eq: Tm,
    pub motive: Tm,
    /// The motive's equation binder: wrap in `λ(e' :Irr dom).` and apply
    /// the transport to `refl(ty, rhs)`.
    pub e_dom: Option<Tm>,
}

impl Wrap {
    /// [`Wrap::apply`] for a `p` built under the equation binder already
    /// (at `depth + 1` when the wrap has one): no shift.
    pub fn apply_bound(&self, p: Tm) -> Tm {
        let val = match &self.e_dom {
            Some(dom) => mk::lam("e", Rel::Irr, dom.clone(), p),
            None => p,
        };
        let t: Tm = Rc::new(Term::Transport { ty: self.ty.clone(), lhs: self.lhs.clone(), rhs: self.rhs.clone(), eq: self.eq.clone(), motive: self.motive.clone(), val });
        if self.e_dom.is_some() { mk::app_irr(t, mk::refl(self.ty.clone(), self.rhs.clone())) } else { t }
    }

    pub fn apply(&self, p: Tm) -> Tm {
        let val = match &self.e_dom {
            Some(dom) => mk::lam("e", Rel::Irr, dom.clone(), shift(&p, 1)),
            None => p,
        };
        let t: Tm = Rc::new(Term::Transport { ty: self.ty.clone(), lhs: self.lhs.clone(), rhs: self.rhs.clone(), eq: self.eq.clone(), motive: self.motive.clone(), val });
        if self.e_dom.is_some() { mk::app_irr(t, mk::refl(self.ty.clone(), self.rhs.clone())) } else { t }
    }
}

/// Types (terms at the state's depth) of the irrelevant binders of the
/// context, by level (the facts a proof inside the goal may mention).
/// `known`: the type terms of binders the proof builder introduced itself
/// (source and residual `let`s, path equations), each at the depth of its
/// level — used as written, never read back from their values (a value in
/// the definitional view unfolds every `let` it mentions: a slice bound
/// fact over the ninth sub-slice of a case-of-case source reads back as
/// millions of nodes).
pub fn fact_types(e: &Engine<'_>, st: &St, known: &std::collections::HashMap<u32, Tm>) -> BTreeMap<u32, Tm> {
    let mut out = BTreeMap::new();
    let d = st.depth();
    for (l, entry) in st.ctx.entries.iter().enumerate() {
        if entry.rel == Rel::Irr {
            let l = l as u32;
            let t = match known.get(&l) {
                Some(t) => shift(t, (d - l) as i64),
                None => e.quote(st, &entry.ty),
            };
            out.insert(l, t);
        }
    }
    out
}

/// The abstraction of `target : a` (a term and its value) in the goal
/// term `g_tm`: `(body, uses of the equation binder, proofs kept without a
/// readable type)` with `body` at depth `d + 2` (`y` = `Var(1)`, `e` =
/// `Var(0)`), or `None` if the target does not occur. The third component
/// goes to [`check_motive`].
pub fn abstract_goal(e: &mut Engine<'_>, st: &St, g_tm: &Tm, target_tm: &Tm, a_tm: &Tm, target_v: &V, known: &std::collections::HashMap<u32, Tm>) -> Option<(Tm, usize, usize)> {
    let facts = fact_types(e, st, known);
    // semantic matching in the definitional view (`let`s unfolded)
    let venv = e.env.ctx_venv(&st.ctx);
    let ab = crate::auto::abstraction::abstract_prop_loose(e.env, st.depth(), g_tm, target_tm, a_tm, facts, &venv, target_v);
    e.b.steps = e.b.steps.saturating_sub(ab.steps);
    if ab.count == 0 {
        return None;
    }
    Some((ab.body, ab.uses_e, ab.blind))
}

/// [`abstract_goal`] on the source side `s` alone (a term of type `r`):
/// the source's abstraction body at depth `d + 2` and the equation
/// binder's uses. The residual side of the goal is not searched (it does
/// not change under a source-side rewrite or split, and abstracting it
/// would copy it into every motive).
#[allow(clippy::too_many_arguments)]
pub fn abstract_source(e: &mut Engine<'_>, st: &St, r: &Tm, s: &Tm, target_tm: &Tm, a_tm: &Tm, target_v: &V, known: &std::collections::HashMap<u32, Tm>) -> Option<(Tm, usize, usize)> {
    let g = mk::eq(r.clone(), s.clone(), s.clone());
    let (body, uses, blind) = abstract_goal(e, st, &g, target_tm, a_tm, target_v, known)?;
    match &*body {
        Term::Eq { lhs, .. } => Some((lhs.clone(), uses, blind)),
        _ => None,
    }
}

/// The start of the error of a motive the kernel finds ill-typed although
/// its abstraction kept no proof of unknown type: a bug of the proof
/// builder (or of the abstraction), reported as an optimizer fault
/// (`opt::drive_one`), as opposed to the builder giving up.
pub const ILL_TYPED: &str = "the proof builder built an ill-typed term";

/// Type-checks a motive (a term at depth `d + 1` over `y : a`), repairing
/// stale certificates of quoted proofs. `blind`: the proofs its
/// abstraction kept without a readable type ([`abstract_source`]). A
/// typing error is [`ILL_TYPED`] when there were none (a proof of unknown
/// type is the documented way an abstraction may break typing, an
/// incompleteness); a stale certificate that is not repaired, or a budget
/// that runs out, is never one.
pub fn check_motive(e: &mut Engine<'_>, st: &St, a: &V, m: Tm, blind: usize) -> Result<Tm, String> {
    let cy = crate::auto::search::ctx_with(&st.ctx, a);
    e.settle();
    let mut m = m;
    let mut r = e.env.infer(&cy, &m, e.b);
    if let Err(err) = &r
        && ((err.kind == sandblaster_kernel::api::KernelErrorKind::Linarith && crate::auto::repair::has_linarith(&m)) || (err.kind == sandblaster_kernel::api::KernelErrorKind::Erased && crate::auto::repair::has_erased(&m)))
    {
        let mut sb = sandblaster_kernel::value::Budget { steps: e.b.steps.min(20_000_000) };
        let start = sb.steps;
        let (m2, n) = crate::auto::repair::repair(e.env, &cy, &m, &mut sb);
        e.b.steps = e.b.steps.saturating_sub(start - sb.steps);
        if n > 0 {
            m = m2;
            e.settle();
            r = e.env.infer(&cy, &m, e.b);
        }
    }
    match r {
        Ok(s) if crate::auto::search::is_type_sort(&s) => Ok(m),
        Ok(_) => Err("the motive is not a type".into()),
        Err(err) => {
            if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() {
                let mut names = st.names();
                names.push(std::rc::Rc::from("y"));
                eprintln!("opt: proof: ill-typed motive: {}\n  motive: {}", err.to_string().chars().take(3000).collect::<String>(), e.env.print_term(&names, &m).chars().take(4000).collect::<String>());
            }
            use sandblaster_kernel::api::KernelErrorKind as K;
            let typing = matches!(err.kind, K::TypeMismatch | K::NotAType | K::IllFormed | K::Relevance);
            let msg: String = err.to_string().chars().take(300).collect();
            if typing && blind == 0 { Err(format!("{ILL_TYPED} (a motive): {msg}")) } else { Err(format!("an ill-typed motive: {msg}")) }
        }
    }
}

/// `body` (at depth `d + 2`, `y` = `Var(1)`, `e` = `Var(0)`) instantiated
/// with `y := y_tm`, `e := e_tm` (terms at depth `d + extra`), the context
/// variables shifted by `extra` (binders pushed after the motive's
/// context).
pub fn inst2(body: &Tm, y_tm: &Tm, e_tm: &Tm, extra: u32) -> Tm {
    crate::auto::util::map_term(body, 0, &mut |t, k| match &**t {
        Term::Var(Idx(i)) if *i >= k => Some(match i - k {
            0 => shift(e_tm, k as i64),
            1 => shift(y_tm, k as i64),
            j => Rc::new(Term::Var(Idx(j - 2 + extra + k))),
        }),
        _ => None,
    })
}

/// `body` (with `n` innermost binders) instantiated with `args` (terms at
/// the outer depth; `args[0]` for the outermost of the `n`).
pub fn subst_n(body: &Tm, args: &[Tm]) -> Tm {
    let n = args.len() as u32;
    crate::auto::util::map_term(body, 0, &mut |t, k| match &**t {
        Term::Var(Idx(i)) if *i >= k && *i < k + n => Some(shift(&args[(n - 1 - (i - k)) as usize], k as i64)),
        Term::Var(Idx(i)) if *i >= k + n => Some(Rc::new(Term::Var(Idx(i - n)))),
        _ => None,
    })
}

/// Head ι/β-reduction of a residual term: `(match Cₖ(ā) .. with arms) p`
/// becomes arm `k` at `ā` applied to `p`, then `(λe. b) p` becomes
/// `b[e := p]`.
pub fn head_reduce(t: &Tm) -> Tm {
    let mut t = t.clone();
    for _ in 0..8 {
        let next = match &*t {
            Term::App { fun, arg, .. } => match &**fun {
                Term::Match { scrut, arms, .. } => match &**scrut {
                    Term::Ctor { ctor, args, .. } => {
                        let Some(arm) = arms.get(*ctor as usize) else { return t };
                        let b = subst_n(&arm.body, args);
                        Rc::new(Term::App { rel: Rel::Irr, fun: b, arg: arg.clone() })
                    }
                    _ => return t,
                },
                Term::Lam { body, .. } => crate::auto::util::subst0(body, arg),
                _ => return t,
            },
            Term::Match { scrut, arms, .. } => match &**scrut {
                Term::Ctor { ctor, args, .. } => {
                    let Some(arm) = arms.get(*ctor as usize) else { return t };
                    subst_n(&arm.body, args)
                }
                _ => return t,
            },
            _ => return t,
        };
        t = next;
    }
    t
}

/// A residual match at the head of `l`: `(scrut, ind, params, arms, idiom)`
/// where `idiom` is the path-equation argument of the dependent-match
/// idiom.
pub fn as_match(l: &Tm) -> Option<(Tm, sandblaster_kernel::term::IndId, Vec<Tm>, Vec<Arm>, bool)> {
    match &**l {
        Term::App { rel: Rel::Irr, fun, .. } => match &**fun {
            Term::Match { ind, params, scrut, arms, .. } => Some((scrut.clone(), *ind, params.clone(), arms.iter().map(|a| Arm { names: a.names.clone(), body: a.body.clone() }).collect(), true)),
            _ => None,
        },
        Term::Match { ind, params, scrut, arms, .. } => Some((scrut.clone(), *ind, params.clone(), arms.iter().map(|a| Arm { names: a.names.clone(), body: a.body.clone() }).collect(), false)),
        _ => None,
    }
}
