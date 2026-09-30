//! Explanations: the kernel-checked link of a rewritten residual (optimizer
//! design §10.1, §11.2; plan O8).
//!
//! A rewrite replaces an occurrence of the subterm `N` of the region `C`
//! by a rule's instantiated right side `Rσ`. Its justification is the
//! equation `E : Eq(τ, N, Rσ)`: the rule's lemma at `σ`, preceded — when `N`
//! is not syntactically the rule's left side `Lσ` — by `bvrefl(τ, N, Lσ)`
//! (the matcher found them equal modulo word algebra; the kernel's `BvRefl`
//! decides it again):
//!
//! ```text
//! E = transport(τ, Lσ, Rσ, rule σ̄, z. Eq(τ, N, z), bvrefl(τ, N, Lσ))
//! ```
//!
//! The rewrites of a residual `C₀ → C₁ → … → Cₖ` chain into the link lemma
//! `r::equiv : Π x̄. Eq(R, r x̄, f x̄)` by transports along a motive that
//! abstracts the rewritten occurrences:
//!
//! ```text
//! P₀ = bvrefl(R, C₀, f x̄)                            : Eq(R, C₀, f x̄)   (transparent, as tier 0)
//! Pᵢ = transport(τ, N, Rσ, E, y. Eq(R, Dᵢ[y], f x̄), Pᵢ₋₁)   : Eq(R, Cᵢ, f x̄)
//! ```
//!
//! where `Dᵢ[N] = Cᵢ₋₁`. The last type is the lemma's statement by
//! conversion (`r`'s body evaluates to `Cₖ`). Nothing here is trusted: the
//! kernel type-checks every transport (including that each motive is
//! well-formed) and the lemma as a whole. The rule instances are memoized
//! (one term per rule and instance, shared by every rewrite that uses it).

use std::collections::HashMap;
use std::rc::Rc;

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{GlobalId, PrimOp, Rel, Term, Tm, Width};
use sandblaster_kernel::util::mk;

/// One rewrite of a region.
#[derive(Clone, Debug)]
pub struct Rewrite {
    /// The rewritten subterm (at the region's depth).
    pub target: Tm,
    /// Its machine type `IntTy τ`.
    pub ty: Tm,
    pub rule: String,
    pub lemma: GlobalId,
    /// The rule's instance: its arguments, left and right sides.
    pub sigma: Vec<Tm>,
    pub lhs: Tm,
    pub rhs: Tm,
}

/// Memoized rule-instance equations `E : Eq(τ, N, Rσ)`.
#[derive(Default)]
pub struct Explanations {
    memo: HashMap<(u64, u64), Tm>,
}

impl Explanations {
    /// `E` for a rewrite (see the module docs).
    pub fn equation(&mut self, env: &Env, rw: &Rewrite) -> Tm {
        let key = (crate::elab::tm::fingerprint(&rw.target), crate::elab::tm::fingerprint(&rw.lhs) ^ u64::from(rw.lemma.0));
        if let Some(e) = self.memo.get(&key) {
            return e.clone();
        }
        let inst = mk::apps(mk::global(rw.lemma), rw.sigma.iter().map(|s| (Rel::Rel, s.clone())));
        let e = if env.alpha_eq_relevant(&rw.target, &rw.lhs, &|a, b| a == b) {
            inst
        } else {
            // z. Eq(τ, N, z) — under one binder
            let motive = mk::eq(sandblaster_kernel::util::shift(&rw.ty, 1), sandblaster_kernel::util::shift(&rw.target, 1), mk::var(0));
            let bv = Rc::new(Term::BvRefl { ty: rw.ty.clone(), lhs: rw.target.clone(), rhs: rw.lhs.clone() });
            Rc::new(Term::Transport { ty: rw.ty.clone(), lhs: rw.lhs.clone(), rhs: rw.rhs.clone(), eq: inst, motive, val: bv })
        };
        self.memo.insert(key, e.clone());
        e
    }
}

/// Applies `rws` to `c0` in order and builds the transport chain from
/// `bvrefl(R, C₀, f x̄)` (the module docs): returns the proof body (at the
/// region's depth) and the rewritten region. `ret` is the function's
/// result type and `fx` the application `f x̄`, both at the region's depth.
pub fn chain(env: &Env, ex: &mut Explanations, c0: &Tm, rws: &[Rewrite], ret: &Tm, fx: &Tm) -> Result<(Tm, Tm), String> {
    // C₀ = f x̄: `f` may be opaque (a function with loops, §5.6), which
    // conversion keeps folded; `BvRefl` evaluates both sides transparently
    // (as tier 0's admission does) and compares them
    let mut proof: Tm = Rc::new(Term::BvRefl { ty: ret.clone(), lhs: c0.clone(), rhs: fx.clone() });
    let mut c = c0.clone();
    for rw in rws {
        let e0 = ex.equation(env, rw);
        let (rw, e) = lift(env, &c, rw.clone(), e0)?;
        let rw = &rw;
        let d = crate::elab::tm::abstract_syntactic(env, &c, &rw.target).ok_or_else(|| format!("the rewritten subterm of `{}` does not occur in the region", rw.rule))?;
        let motive = mk::eq(sandblaster_kernel::util::shift(ret, 1), d.clone(), sandblaster_kernel::util::shift(fx, 1));
        proof = Rc::new(Term::Transport { ty: rw.ty.clone(), lhs: rw.target.clone(), rhs: rw.rhs.clone(), eq: e, motive, val: proof });
        c = crate::elab::tm::subst0(&d, &rw.rhs);
    }
    Ok((proof, c))
}

/// The operand positions of a checked operation whose proof slot mentions
/// them (`lemmas/cong.core`).
fn cong_sides(op: &PrimOp) -> &'static [usize] {
    use PrimOp::*;
    match op {
        Add(_) | Sub(_) | Mul(_) => &[0, 1],
        Div(_) | Rem(_) | Shl(_) | Shr(_) => &[1],
        _ => &[],
    }
}

fn width_name(w: Width) -> &'static str {
    match w {
        Width::U8 => "u8",
        Width::U16 => "u16",
        Width::U32 => "u32",
        Width::U64 => "u64",
        Width::Usize => "usize",
        Width::Int => "int",
    }
}

fn op_name(op: &PrimOp) -> Option<(&'static str, Width)> {
    use PrimOp::*;
    Some(match op {
        Add(w) => ("add", *w),
        Sub(w) => ("sub", *w),
        Mul(w) => ("mul", *w),
        Div(w) => ("div", *w),
        Rem(w) => ("rem", *w),
        Shl(w) => ("shl", *w),
        Shr(w) => ("shr", *w),
        _ => return None,
    })
}

/// `cong_irr` (design §10.1): while the rewritten subterm occurs as an
/// operand of a checked operation whose proof slot mentions it, the rewrite
/// is lifted to that operation — `op(a, b; p) → op(a', b; p2)`, with
/// `p2 = transport(τ, a, a', E, z. obligation(z, b), p)` and the equation
/// `cong::<op>_<l|r>_<w> a a' b .E .p .p2` — so no motive abstracts an
/// operand under a proof about it.
fn lift(env: &Env, c: &Tm, mut rw: Rewrite, mut e: Tm) -> Result<(Rewrite, Tm), String> {
    for _ in 0..64 {
        // the first checked operation (pre-order) with the target as a
        // proof-mentioned operand
        let mut found: Option<(Tm, usize)> = None;
        crate::elab::tm::any_node_depth(c, &mut |n, depth| {
            if depth != 0 || found.is_some() {
                return found.is_some();
            }
            if let Term::Prim { op, args, proofs } = n
                && !proofs.is_empty()
            {
                for &j in cong_sides(op) {
                    if args.get(j).is_some_and(|a| env.alpha_eq_relevant(a, &rw.target, &|x, y| x == y)) {
                        found = Some((Rc::new(Term::Prim { op: *op, args: args.clone(), proofs: proofs.clone() }), j));
                        return true;
                    }
                }
            }
            false
        });
        let Some((parent, j)) = found else { return Ok((rw, e)) };
        let Term::Prim { op, args, proofs } = &*parent else { unreachable!() };
        let (name, w) = op_name(op).ok_or("not a checked operation")?;
        let lemma_name = match (name, j) {
            ("shl" | "shr", _) => format!("cong::{name}_r_{}", width_name(w)),
            (_, 0) => format!("cong::{name}_l_{}", width_name(w)),
            _ => format!("cong::{name}_r_{}", width_name(w)),
        };
        let lemma = env.lookup_global(&lemma_name).ok_or_else(|| format!("`{lemma_name}` is not loaded"))?;
        let mut new_args = args.clone();
        new_args[j] = rw.rhs.clone();
        // the obligation with the operand abstracted: z. obligation(.., z, ..)
        let mut abs_args: Vec<Tm> = args.iter().map(|a| sandblaster_kernel::util::shift(a, 1)).collect();
        abs_args[j] = mk::var(0);
        let obl = sandblaster_kernel::prim::prim_obligations(*op, &abs_args, env.bool_ind()).into_iter().next().ok_or("no obligation")?;
        let p = proofs[0].clone();
        let p2 = Rc::new(Term::Transport { ty: rw.ty.clone(), lhs: rw.target.clone(), rhs: rw.rhs.clone(), eq: e.clone(), motive: obl, val: p.clone() });
        let other = args[1 - j].clone();
        let eq_p = mk::apps(mk::global(lemma), [(Rel::Rel, rw.target.clone()), (Rel::Rel, rw.rhs.clone()), (Rel::Rel, other), (Rel::Irr, e), (Rel::Irr, p), (Rel::Irr, p2.clone())]);
        let rhs = Rc::new(Term::Prim { op: *op, args: new_args, proofs: vec![p2] });
        rw = Rewrite { target: parent.clone(), ty: mk::int_ty(w), rule: format!("{} (lifted by {lemma_name})", rw.rule), lemma: rw.lemma, sigma: rw.sigma, lhs: rw.lhs, rhs };
        e = eq_p;
    }
    Err("cong_irr: too many nested checked operations".into())
}
