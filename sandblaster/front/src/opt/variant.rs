//! `VariantEquiv` (DESIGN.md §9.3): a hardware variant equals its portable
//! reference on every input, as a **kernel-checked lemma**
//!
//! ```text
//! <variant>::variant_equiv : Π(x₁ : A₁)…(xₙ : Aₙ). Eq(R, variant x̄, portable x̄)
//!                          := λx̄. bvrefl(R, variant x̄, portable x̄)
//! ```
//!
//! `BvRefl` evaluates both sides symbolically (intrinsic models unfolded on
//! symbolic data, array parameters eta-expanded, §5.9) and decides the
//! equality with the word normalizer and its tripwire (§9.8). The kernel
//! checks the lemma like any definition; nothing here is trusted.
//!
//! Portable functions with loops are opaque (§5.6), and `BvRefl` keeps
//! opaque definitions folded. When the kernel's `BvRefl` cannot unfold the
//! portable side, the optimizer proves the lemma against a **transparent
//! copy** `portable__transparent` instead — the same HIR function
//! elaborated again with `opaque = false` (every obligation re-proven, the
//! kernel checks it) — and checks that the copy's kernel body is
//! α-equivalent in all relevant positions to the portable one modulo the
//! renaming of the copy and its loop helpers (`Env::alpha_eq_relevant`):
//! the two definitions are the same term, so they denote the same function
//! (opacity is only an unfolding policy of the checker).

use std::time::Instant;

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{DefDecl, DefKind, GlobalId, Recursion, Rel, Term, Tm};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::Budget;

use super::symex::telescope;

/// A proven `VariantEquiv` lemma.
#[derive(Clone, Debug)]
pub struct Equiv {
    pub lemma: GlobalId,
    /// The right-hand side of the lemma: the portable function itself, or
    /// its transparent copy.
    pub rhs: GlobalId,
    pub millis: u128,
}

/// Name of the lemma of `variant`.
pub fn lemma_name(variant: &str) -> String {
    format!("{variant}::variant_equiv")
}

/// The lemma statement `Π x̄. Eq(R, variant x̄, rhs x̄)` and its proof term
/// `λ x̄. bvrefl(R, variant x̄, rhs x̄)`.
fn statement(env: &Env, variant: GlobalId, rhs: GlobalId) -> Result<(Tm, Tm, u32), String> {
    let tv = telescope(env, variant).ok_or("the variant has no parameter telescope")?;
    let tr = telescope(env, rhs).ok_or("the portable function has no parameter telescope")?;
    if tv.binders.len() != tr.binders.len() {
        return Err("variant and portable function have different arities".into());
    }
    if tv.binders.iter().any(|(_, r, _)| *r == Rel::Irr) || tr.binders.iter().any(|(_, r, _)| *r == Rel::Irr) {
        return Err("variants of functions with `requires` are not supported".into());
    }
    let n = tv.binders.len() as u32;
    let args = |g: GlobalId| mk::apps(mk::global(g), (0..n).map(|i| (Rel::Rel, mk::var(n - 1 - i))));
    let eq = mk::eq(tv.ret.clone(), args(variant), args(rhs));
    let proof = Term::BvRefl { ty: tv.ret.clone(), lhs: args(variant), rhs: args(rhs) };
    let mut ty = eq;
    let mut body: Tm = std::rc::Rc::new(proof);
    for (name, rel, dom) in tv.binders.iter().rev() {
        ty = mk::pi(name, *rel, dom.clone(), ty);
        body = mk::lam(name, *rel, dom.clone(), body);
    }
    Ok((ty, body, n))
}

/// Checks and adds `<variant>::variant_equiv` with right-hand side `rhs`
/// (the portable function or its transparent copy). The two types must be
/// convertible (checked by the kernel through the statement).
pub fn prove(env: &mut Env, variant: GlobalId, rhs: GlobalId, budget: u64) -> Result<Equiv, String> {
    let name = lemma_name(&env.global_name(variant).map(|s| s.to_string()).unwrap_or_default());
    prove_named(env, variant, rhs, &name, budget)
}

/// [`prove`] with an explicit lemma name (also used for the equality of
/// multiversioned clones, `f__<set>::clone_equiv`).
pub fn prove_named(env: &mut Env, variant: GlobalId, rhs: GlobalId, name: &str, budget: u64) -> Result<Equiv, String> {
    let name = name.to_string();
    let (ty, body, arity) = statement(env, variant, rhs)?;
    let t = Instant::now();
    let mut b = Budget { steps: budget };
    let d = DefDecl { name: std::rc::Rc::from(name.as_str()), kind: DefKind::Lemma, ty, body, recursion: Recursion::None, arity, opaque: true };
    let lemma = env.add_def(d, &mut b).map_err(|e| {
        let m = e.to_string();
        m.chars().take(1500).collect::<String>()
    })?;
    Ok(Equiv { lemma, rhs, millis: t.elapsed().as_millis() })
}
