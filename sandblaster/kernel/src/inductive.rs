//! Inductive declarations (DESIGN.md §5.2, §5.4).
//!
//! * Parameters: any type `T` with `T : Type` or `T : Kind` (e.g. `T : Type`),
//!   each in the context of the previous parameters; parameters are
//!   relevant.
//! * Constructor fields (possibly `Irr`) are checked in the context of the
//!   parameters and the previous fields. The type of an `Irr` field must be
//!   a proposition (`Checker::is_prop`; red-team R1), so it is never a
//!   recursive occurrence. Every field type must have sort
//!   exactly `Type` (so `Type` itself and `Π(X : Type). X` are rejected:
//!   Hurkens' paradox), except the direct recursive occurrence
//!   `D(p₁, .., pₙ)` applied to exactly the parameter variables. The
//!   inductive may occur nowhere else in a field type (strict positivity by
//!   syntax; no nested or indexed occurrences).
//! * `D(params) : Type`. Match typing and ι-reduction live in `check`/`eval`.

use std::rc::Rc;

use crate::api::{Env, KernelErrorKind as K};
use crate::check::{Checker, Cx, KR, kerr};
use crate::env::IndInfo;
use crate::term::{IndId, InductiveDecl, Rel, Sort, Term, Tm};
use crate::util::any_sub;
use crate::value::{Budget, EnvEntry, Value};

/// Budget for checking one declaration (declarations are small).
const DECL_BUDGET: u64 = 10_000_000;

/// Is `t` exactly `Ind { ind: id, params: [Var(p₀), .., Var(pₙ₋₁)] }` for the
/// parameter variables, at binder depth `depth` (parameters are the
/// outermost `np` binders)?
fn is_self_occurrence(t: &Tm, id: IndId, np: usize, depth: usize) -> bool {
    match &**t {
        Term::Ind { ind, params } if *ind == id && params.len() == np => {
            params.iter().enumerate().all(|(i, p)| matches!(&**p, Term::Var(crate::term::Idx(k)) if *k as usize == depth - 1 - i))
        }
        _ => false,
    }
}

/// Does `t` mention the inductive `id` at all?
fn mentions(t: &Tm, id: IndId) -> bool {
    any_sub(t, 0, &mut |n, _| match &**n {
        Term::Ind { ind, .. } | Term::Ctor { ind, .. } | Term::Match { ind, .. } => *ind == id,
        _ => false,
    })
}

pub(crate) fn add_inductive(env: &mut Env, d: InductiveDecl) -> KR<IndId> {
    let id = IndId(env.inds.len() as u32);
    let np = d.params.len();
    let mut rec_fields = Vec::with_capacity(d.ctors.len());
    let mut recursive = false;
    {
        let chk = Checker::new(env);
        let mut b = Budget { steps: DECL_BUDGET };
        let mut cx = Cx::default();
        for (name, pty) in &d.params {
            if mentions(pty, id) {
                return Err(kerr(K::IllFormed, format!("parameter `{name}` of `{}` mentions the inductive itself", d.name)));
            }
            chk.infer_sort(&cx, pty, crate::check::REL, &mut b)?;
            let pv = chk.eval(&cx, pty, &mut b)?;
            cx = chk.bind(&cx, name, Rel::Rel, &pv).0;
        }
        let pvals: Vec<_> = cx
            .venv
            .0
            .iter()
            .map(|e| match e {
                EnvEntry::Rel(v) => v.clone(),
                EnvEntry::Irr(_) => unreachable!("parameters are relevant"),
            })
            .collect();
        let self_ty = Rc::new(Value::Ind { ind: id, params: pvals });
        for (ci, c) in d.ctors.iter().enumerate() {
            if d.ctors[..ci].iter().any(|o| o.name == c.name) {
                return Err(kerr(K::IllFormed, format!("duplicate constructor `{}` in `{}`", c.name, d.name)));
            }
            let mut cxf = cx.clone();
            let mut flags = Vec::with_capacity(c.fields.len());
            for (j, (fname, frel, fty)) in c.fields.iter().enumerate() {
                if is_self_occurrence(fty, id, np, np + j) {
                    if *frel == Rel::Irr {
                        return Err(kerr(
                            K::Relevance,
                            format!("irrelevant field `{fname}` of `{}` must be a proposition, not a recursive occurrence", c.name),
                        ));
                    }
                    recursive = true;
                    flags.push(true);
                    cxf = chk.bind(&cxf, fname, *frel, &self_ty).0;
                    continue;
                }
                if mentions(fty, id) {
                    return Err(kerr(
                        K::IllFormed,
                        format!(
                            "field `{fname}` of `{}` mentions `{}` other than as a direct recursive field (strict positivity)",
                            c.name, d.name
                        ),
                    ));
                }
                let s = chk.infer_sort(&cxf, fty, crate::check::REL, &mut b)?;
                if s != Sort::Type {
                    return Err(kerr(
                        K::IllFormed,
                        format!("field `{fname}` of `{}` has a type of sort {s:?}; constructor fields must be `: Type`", c.name),
                    ));
                }
                let fv = chk.eval(&cxf, fty, &mut b)?;
                // An irrelevant field must be a proposition (red-team R1):
                // conversion skips it, which proof irrelevance justifies.
                if *frel == Rel::Irr && !chk.is_prop(cxf.depth(), &fv, crate::check::PROP_DEPTH, &mut b)? {
                    return Err(kerr(
                        K::Relevance,
                        format!(
                            "irrelevant field `{fname}` of `{}` must be a proposition (Eq, Empty, a Π into a proposition, a Σ of \
                             propositions, or a single-constructor type of propositions)",
                            c.name
                        ),
                    ));
                }
                cxf = chk.bind(&cxf, fname, *frel, &fv).0;
                flags.push(false);
            }
            rec_fields.push(flags);
        }
    }
    env.ind_names.insert(d.name.clone(), id);
    for (k, c) in d.ctors.iter().enumerate() {
        env.ctor_names.entry(c.name.clone()).or_default().push((id, k as u32));
    }
    env.inds.push(IndInfo { name: d.name, params: d.params, ctors: d.ctors, rec_fields, recursive });
    Ok(id)
}
