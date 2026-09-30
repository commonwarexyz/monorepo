//! The elaboration context (DESIGN.md §7.2): the kernel typing context of
//! the term being built, its evaluation environment, the facts in scope and
//! the current SSA binding of every HIR local.
//!
//! Every binder the elaborator emits (λ parameters, `let`s, match-arm fields,
//! path equations, facts) is pushed here **at the same time** as it is
//! emitted, so the context of every proof obligation is exactly the context
//! of its proof slot in the final term (the kernel checks that anyway).
//!
//! Conventions:
//! * terms are built at the current depth (de Bruijn indices relative to the
//!   end of the context); a term kept across binder pushes is a [`Val`],
//!   which remembers its depth and is shifted on use;
//! * let-bound entries carry their value (`CtxEntry::def`), so conversion,
//!   the prover and linarith see through them;
//! * facts are ordinary binders listed in [`Scope::facts`] (prover metadata).

use std::collections::HashMap;
use std::rc::Rc;

use sandblaster_kernel::api::{Ctx, CtxEntry};
use sandblaster_kernel::term::{Idx, Lvl, Name, Rel, Term, Tm};
use sandblaster_kernel::util::shift;
use sandblaster_kernel::value::{Arg, Closure, EnvEntry, VEnv, V};

use crate::hir::LocalId;
use crate::prover::FactRef;

/// A term together with the context depth it was built at.
#[derive(Clone, Debug)]
pub struct Val {
    pub tm: Tm,
    pub depth: u32,
}

impl Val {
    pub fn new(tm: Tm, depth: u32) -> Val {
        Val { tm, depth }
    }
    /// The term at a deeper (or equal) depth.
    pub fn at(&self, depth: u32) -> Tm {
        debug_assert!(depth >= self.depth, "Val used above its depth");
        shift(&self.tm, (depth - self.depth) as i64)
    }
    /// Whether the term is a variable or a literal/nullary constructor (no
    /// need to bind it before duplicating it).
    pub fn is_trivial(&self) -> bool {
        match &*self.tm {
            Term::Var(_) | Term::Lit { .. } | Term::Global(_) => true,
            Term::Ctor { args, params, .. } => args.is_empty() && params.iter().all(|p| matches!(&**p, Term::Ind { .. } | Term::IntTy(_))),
            _ => false,
        }
    }
}

/// The elaboration context (cheap to clone: persistent `Rc` data plus a
/// small map).
#[derive(Clone, Default)]
pub struct Scope {
    pub ctx: Ctx,
    pub venv: VEnv,
    pub facts: Vec<FactRef>,
    /// HIR local → level of its current (SSA) binder.
    pub locals: HashMap<LocalId, u32>,
    /// The type term of every fact binder (at the depth of its level), for
    /// carrying facts into loop helpers (§7.4).
    pub fact_tys: HashMap<u32, Tm>,
    /// Fact binders superseded by a refined copy (a refining script match
    /// re-introduced them with the scrutinee replaced, `elab::refine`): they
    /// stay in the kernel context but are not shown to the prover.
    pub hidden: std::collections::BTreeSet<u32>,
    /// Relevant `let` binders: level ↦ (type term, value term, both at the
    /// depth of the level; the value as pushed, to recognize the binder).
    /// `by_arithmetic()` / `by_unfolding(..)` replace a `let` by an equation
    /// between the variable and its value term, so user functions in the
    /// value stay unknown (`elab::closers`). Shared (`Rc`): scopes are
    /// cloned at every branch.
    pub let_tms: Rc<HashMap<u32, (Tm, Tm, V)>>,
    /// The call-site refinement facts `h_ref : α(f ā) = s(α ā)` met by a
    /// body walk (`elab::ensures`), by level, with their type terms (at the
    /// depth of the level): under a path equation `f ā = C(v̄)` the walk
    /// adds `α(C(v̄)) = s(α ā)`, a rewrite rule for the (unfolded) spec call.
    pub ref_facts: Vec<(u32, Tm)>,
    /// The values whose invariant facts are in scope (§15.3, S2), each a
    /// term with the depth it was built at (`Elab::with_inv_facts`): one
    /// set of facts per value.
    pub inv_seen: Vec<(u32, Tm)>,
    /// `#[ghost]` parameters (§15.3, S2): HIR local ↦ its projection of the
    /// ghost bundle (`Elab::ghost_bundle`), with the depth it was built at.
    pub ghost_locals: HashMap<LocalId, Val>,
    /// Facts that are not binders of the term being built, given to the
    /// prover inside each proof slot instead (`Elab::prove_hinted` wraps the
    /// proof in `λ`s applied to their proofs):
    /// * facts whose types mention ghost parameters: an exec body cannot
    ///   bind them — every type position is relevant and the ghost bundle is
    ///   irrelevant (DESIGN.md §5.3) — but the bundle is usable in a proof
    ///   slot;
    /// * the invariant facts (§15.3) of values projected in a pure context
    ///   (`FnState::pure_facts`) and of the parameters of a loop helper: a
    ///   `let` there would change the value or the type being built.
    pub hint_facts: Vec<HintFact>,
}

/// A fact given to the prover in each proof slot (see
/// [`Scope::hint_facts`]).
#[derive(Clone, Debug)]
pub struct HintFact {
    pub ty: Val,
    pub proof: Val,
    /// The binder name in the slot (`h_ghost`, `h_inv`).
    pub name: &'static str,
    pub origin: crate::prover::FactOrigin,
}

impl Scope {
    pub fn depth(&self) -> u32 {
        self.ctx.entries.len() as u32
    }

    /// `Var` for the binder at level `lvl`.
    pub fn var(&self, lvl: u32) -> Tm {
        Rc::new(Term::Var(Idx(self.depth() - 1 - lvl)))
    }

    /// Appends a binder. `entry` is its evaluation-environment entry
    /// (a fresh variable, or the let value).
    pub fn push_entry(&mut self, name: &str, rel: Rel, ty: V, entry: EnvEntry, def: bool) -> u32 {
        let lvl = self.depth();
        let arg = match &entry {
            EnvEntry::Rel(v) => Arg::Rel(v.clone()),
            EnvEntry::Irr(c) => Arg::Irr(c.clone()),
        };
        let name: Name = Rc::from(name);
        let mut entries = (*self.ctx.entries).clone();
        entries.push(CtxEntry { name, rel, ty, def: if def { Some(arg) } else { None } });
        self.ctx = Ctx { entries: Rc::new(entries) };
        let mut v = (*self.venv.0).clone();
        v.push(entry);
        self.venv = VEnv(Rc::new(v));
        lvl
    }

    /// The closure of an irrelevant term in the current environment.
    pub fn closure(&self, t: &Tm) -> Closure {
        Closure { env: self.venv.clone(), body: t.clone() }
    }

    /// The binder names in level order (for printing).
    pub fn names(&self) -> Vec<Name> {
        self.ctx.entries.iter().map(|e| e.name.clone()).collect()
    }

    /// Level of the current binder of a HIR local.
    pub fn local(&self, l: LocalId) -> Option<u32> {
        self.locals.get(&l).copied()
    }

    /// Rebuilds `Lvl` for prover facts.
    pub fn lvl(l: u32) -> Lvl {
        Lvl(l)
    }
}
