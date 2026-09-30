//! Semantic values for normalization by evaluation (FROZEN INTERFACE —
//! DESIGN.md §5.6, §5.9).
//!
//! * Evaluation is call-by-value for relevant arguments; irrelevant arguments
//!   are kept as unevaluated closures ([`Arg::Irr`]) so they can be quoted back
//!   (auto builds motives by quoting) but are never forced.
//! * Sharing matters: symbolically executed code is a DAG. Conversion memoizes
//!   on pairs of values it has already proven equal; the memo keeps the
//!   compared `Rc`s alive for the duration of one top-level `conv` call (it
//!   never keys on raw addresses of values that may be freed).
//! * Neutral terms carry a spine of eliminations.

use std::rc::Rc;

use crate::term::{BigInt, GlobalId, IndId, Lvl, PrimOp, Rel, Sort, Tm, Width};

/// Shared pointer to a value.
pub type V = Rc<Value>;

/// Evaluation environment: values of the free de Bruijn indices of a term
/// (index 0 = last element). Implementation choice: a persistent list or a
/// shared vector; it must be cheap to clone and extend.
#[derive(Clone, Debug, Default)]
pub struct VEnv(pub Rc<Vec<EnvEntry>>);

/// One environment entry.
#[derive(Clone, Debug)]
pub enum EnvEntry {
    Rel(V),
    /// An irrelevant binding: its unevaluated closure (for quoting).
    Irr(Closure),
}

/// A term together with the environment of its free variables.
#[derive(Clone, Debug)]
pub struct Closure {
    pub env: VEnv,
    pub body: Tm,
}

/// An argument in a spine or constructor.
#[derive(Clone, Debug)]
pub enum Arg {
    Rel(V),
    /// Irrelevant argument: never forced; conversion skips it.
    Irr(Closure),
}

#[derive(Debug)]
pub enum Value {
    Sort(Sort),
    IntTy(Width),
    Lit { w: Width, n: BigInt },
    Pi { name: crate::term::Name, rel: Rel, dom: V, cod: Closure },
    Lam { name: crate::term::Name, rel: Rel, dom: V, body: Closure },
    Sigma { name: crate::term::Name, snd_rel: Rel, fst: V, snd: Closure },
    Pair { fst: V, snd: Arg },
    Eq { ty: V, lhs: V, rhs: V },
    /// `refl` (its type and value are recoverable from context; conversion of
    /// proofs of equalities is never needed in relevant positions except for
    /// `Refl` vs `Refl`).
    Refl { ty: V, val: V },
    Ind { ind: IndId, params: Vec<V> },
    Ctor { ind: IndId, ctor: u32, params: Vec<V>, args: Vec<Arg> },
    Neu(Neutral),
}

/// A stuck term: a head and a spine of eliminations.
#[derive(Debug)]
pub struct Neutral {
    pub head: Head,
    pub spine: Vec<Elim>,
}

#[derive(Debug)]
pub enum Head {
    /// A bound variable (de Bruijn level).
    Var(Lvl),
    /// A global applied to its arguments whose unfolding was refused
    /// (recursive and stuck at its head, or opaque for the optimizer).
    Global { def: GlobalId, args: Vec<Arg> },
    /// A primitive whose relevant arguments are not all literals, or that is
    /// out of its domain.
    Prim { op: PrimOp, args: Vec<V>, proofs: Vec<Closure> },
    /// `absurd(ty, proof)`.
    Absurd { ty: V },
    /// `transport` whose endpoints are not convertible.
    Transport { ty: V, lhs: V, rhs: V, motive: Closure, val: V },
    /// An axiom instance (axioms never compute).
    Axiom { ax: crate::term::AxiomId, args: Vec<Arg> },
}

#[derive(Debug)]
pub enum Elim {
    App(Arg),
    Fst,
    Snd,
    Match { ind: IndId, params: Vec<V>, motive: Closure, arms: Vec<Closure> },
}

/// Evaluation fuel. Every evaluation step consumes one unit; exhausting it is
/// an error (never success).
#[derive(Clone, Copy, Debug)]
pub struct Budget {
    pub steps: u64,
}

/// Errors that can arise while evaluating or converting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvalError {
    OutOfFuel,
    /// Ghost `Int` arithmetic exceeded the kernel's implementation limit
    /// (never wraparound).
    IntOverflow,
}
