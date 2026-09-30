//! Core terms of the sandblaster kernel (FROZEN INTERFACE — see DESIGN.md §5).
//!
//! Conventions:
//! * Locals are de Bruijn **indices** in terms (`Idx(0)` = innermost binder)
//!   and de Bruijn **levels** in values (`Lvl(0)` = outermost binder).
//! * Every binder carries a [`Rel`]. An application `App { rel, .. }` is
//!   well-typed only if `rel` equals the relevance of the function's Π type.
//! * Names are for printing only; conversion never looks at them.
//! * `Term`s are immutable and shared through [`Tm`] (`Rc<Term>`).

use std::rc::Rc;

pub use num_bigint::BigInt;

/// Shared pointer to a term.
pub type Tm = Rc<Term>;

/// Binder names (printing only).
pub type Name = Rc<str>;

/// De Bruijn index (terms): 0 is the innermost enclosing binder.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct Idx(pub u32);

/// De Bruijn level (values): 0 is the outermost binder of the context.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct Lvl(pub u32);

/// A global definition (function, spec function, lemma, law, loop helper,
/// prelude definition, axiom).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct GlobalId(pub u32);

/// An inductive type declaration.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct IndId(pub u32);

/// Relevance (DESIGN.md §5.3). `Irr` positions hold proofs that conversion
/// ignores and evaluation never inspects.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Rel {
    Rel,
    Irr,
}

/// The two sorts: `Type : Kind`; `Kind` has no type (DESIGN.md §5.2).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Sort {
    Type,
    Kind,
}

/// Integer widths. `Usize` is 64-bit (the checker requires a 64-bit target).
/// `Int` is the ghost type of mathematical integers.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub enum Width {
    U8,
    U16,
    U32,
    U64,
    Usize,
    Int,
}

impl Width {
    /// Number of bits of a machine width (`None` for `Int`).
    pub fn bits(self) -> Option<u32> {
        match self {
            Width::U8 => Some(8),
            Width::U16 => Some(16),
            Width::U32 => Some(32),
            Width::U64 | Width::Usize => Some(64),
            Width::Int => None,
        }
    }
}

/// Exact rational used in linear-arithmetic certificates (`den > 0`),
/// arbitrary precision (DESIGN.md §5.8).
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Rat {
    pub num: BigInt,
    pub den: BigInt,
}

/// Primitive operations (DESIGN.md §5.7). The width parameter is the width of
/// the operands unless stated otherwise.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum PrimOp {
    // ---- total, machine widths (mod 2^w) ----
    WAdd(Width),
    WSub(Width),
    WMul(Width),
    WNeg(Width),
    And(Width),
    Or(Width),
    Xor(Width),
    Not(Width),
    /// Shift amount is taken mod w (Rust `wrapping_shl`). Second arg is `U32`.
    WShl(Width),
    /// Shift amount is taken mod w (Rust `wrapping_shr`). Second arg is `U32`.
    WShr(Width),
    /// Rotation amount mod w. Second arg is `U32`.
    Rotl(Width),
    Rotr(Width),
    Min(Width),
    Max(Width),
    SatAdd(Width),
    SatSub(Width),
    SatMul(Width),
    /// Result is `U32`.
    CountOnes(Width),
    LeadingZeros(Width),
    TrailingZeros(Width),
    SwapBytes(Width),
    // ---- comparisons (also on Int), result Bool ----
    Eq(Width),
    Ne(Width),
    Lt(Width),
    Le(Width),
    Gt(Width),
    Ge(Width),
    /// Truncating / zero-extending conversion between widths; to `Int` it is
    /// the exact value. From `Int` use [`PrimOp::OfInt`] or [`PrimOp::IntToSat`].
    Cast { from: Width, to: Width },
    /// Clamp an `Int` into `[0, 2^w)`.
    IntToSat(Width),
    // ---- Int only (exact, total; Euclidean division, x/0 = 0, x%0 = x) ----
    IAdd,
    ISub,
    IMul,
    INeg,
    IDiv,
    IMod,
    // ---- checked (carry Irr proof slots; stuck outside their domain) ----
    /// proof: `a + b ≤ MAX`
    Add(Width),
    /// proof: `b ≤ a`
    Sub(Width),
    /// proof: `a · b ≤ MAX`
    Mul(Width),
    /// proof: `b ≠ 0`
    Div(Width),
    /// proof: `b ≠ 0`
    Rem(Width),
    /// proof: `s < w`; evaluates exactly like `WShl` (the evaluator may rewrite it).
    Shl(Width),
    /// proof: `s < w`; evaluates exactly like `WShr`.
    Shr(Width),
    /// proof: `0 ≤ i < 2^w`
    OfInt(Width),
}

/// Core terms (DESIGN.md §5.1).
#[derive(Debug)]
pub enum Term {
    Var(Idx),
    Global(GlobalId),
    Sort(Sort),

    /// `Π(name :rel dom). cod` — `cod` binds one variable.
    Pi { name: Name, rel: Rel, dom: Tm, cod: Tm },
    /// `λ(name :rel dom). body` — `body` binds one variable.
    Lam { name: Name, rel: Rel, dom: Tm, body: Tm },
    /// Application; `rel` must equal the relevance of the function's Π.
    App { rel: Rel, fun: Tm, arg: Tm },
    /// `let name :rel ty = val; body` — `body` binds one variable. `Irr` lets
    /// bind facts (proofs); their value is an irrelevant position.
    Let { name: Name, rel: Rel, ty: Tm, val: Tm, body: Tm },

    /// `Σ(name : fst). snd` — `snd` binds one variable. Relevance is on the
    /// SECOND component: `snd_rel = Irr` means the second component is a proof.
    Sigma { name: Name, snd_rel: Rel, fst: Tm, snd: Tm },
    /// Pair; `ty` is the Σ type (needed to check `snd` against `snd[fst]`).
    Pair { ty: Tm, fst: Tm, snd: Tm },
    Fst(Tm),
    /// Second projection. For an `Irr` Σ it may only occur in irrelevant positions.
    Snd(Tm),

    /// `Eq(ty, lhs, rhs) : Type`, for `ty : Type`.
    Eq { ty: Tm, lhs: Tm, rhs: Tm },
    /// `refl(ty, val) : Eq(ty, val, val)`.
    Refl { ty: Tm, val: Tm },
    /// `transport(ty, lhs, rhs, eq, y. motive, val) : motive[y := rhs]` where
    /// `eq : Eq(ty, lhs, rhs)` (an **irrelevant** position),
    /// `y : ty ⊢ motive : Type`, and `val : motive[y := lhs]`.
    /// Reduces to `val` iff `lhs ≡ rhs`.
    Transport { ty: Tm, lhs: Tm, rhs: Tm, eq: Tm, motive: Tm, val: Tm },

    /// Inductive type applied to all its parameters.
    Ind { ind: IndId, params: Vec<Tm> },
    /// Constructor applied to the family parameters and all fields.
    Ctor { ind: IndId, ctor: u32, params: Vec<Tm>, args: Vec<Tm> },
    /// `match scrut as y return motive with arms` — `motive` binds `y`; arm k
    /// binds the fields of constructor k (in order; the last field is `Idx(0)`)
    /// and has type `motive[y := Ctor_k(params; fields)]`.
    Match { ind: IndId, params: Vec<Tm>, scrut: Tm, motive: Tm, arms: Vec<Arm> },

    IntTy(Width),
    /// Integer literal (arbitrary precision); for machine widths `0 ≤ n < 2^w`.
    Lit { w: Width, n: BigInt },
    /// Primitive application: relevant arguments and (for checked ops)
    /// irrelevant proof arguments.
    Prim { op: PrimOp, args: Vec<Tm>, proofs: Vec<Tm> },

    /// Recursive self-call; only inside the body of the definition being
    /// checked. `args` is a full application (relevance taken from the
    /// definition's telescope). `proof` is required for measure recursion:
    /// a proof of the decrease obligation (an irrelevant position).
    Rec { args: Vec<Tm>, proof: Option<Tm> },
    /// `delta(def; args) : Eq(R, def args, body[args])` where every `Rec` in
    /// the body is replaced by `def`; only when `R : Type`.
    Delta { def: GlobalId, args: Vec<Tm> },
    /// For a definition whose result is a proposition (`R = Type`):
    /// casts `val : def args` to `body[args]` (`to_body = true`) or back.
    Unfold { def: GlobalId, args: Vec<Tm>, to_body: bool, val: Tm },

    /// Linear arithmetic certificate (DESIGN.md §5.8). Each hypothesis is a
    /// proof together with its stated proposition (checked by conversion
    /// against the proof's type); linearization uses the stated form.
    Linarith { hyps: Vec<(Tm, Tm)>, goal: Tm, cert: Vec<Rat> },
    /// Equality by conversion modulo the word normalizer (DESIGN.md §5.8b):
    /// `bvrefl(ty, lhs, rhs) : Eq(ty, lhs, rhs)`.
    BvRefl { ty: Tm, lhs: Tm, rhs: Tm },
    /// `absurd(ty, proof) : ty` for `proof : Empty` (proof is irrelevant).
    Absurd { ty: Tm, proof: Tm },
    /// An instance of a trusted axiom schema (DESIGN.md §5.10).
    Axiom { ax: AxiomId, args: Vec<Tm> },

    /// Placeholder for a proof in an irrelevant position. Rejected by
    /// `add_def`/`check`/`infer`; accepted only by the codegen-only
    /// candidate checks (DESIGN.md §8.3).
    Erased,
}

/// A match arm: binds the constructor fields in order.
#[derive(Debug)]
pub struct Arm {
    pub names: Vec<Name>,
    pub body: Tm,
}

/// Identifier of an axiom schema in `axioms.rs`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct AxiomId(pub u32);

/// Constructor declaration. Field types are in the context of the family
/// parameters followed by the previous fields. `Irr` fields hold proofs
/// (conversion ignores them).
#[derive(Debug, Clone)]
pub struct CtorDecl {
    pub name: Name,
    pub fields: Vec<(Name, Rel, Tm)>,
}

/// Inductive declaration (DESIGN.md §5.4). Parameters may have any type `T`
/// with `T : Type` or `T : Kind` (e.g. `T : Type`); every field type must be
/// `: Type`. The only allowed recursive occurrence is a direct field of type
/// `Ind { self, params }` with the same parameters.
#[derive(Debug, Clone)]
pub struct InductiveDecl {
    pub name: Name,
    pub params: Vec<(Name, Tm)>,
    pub ctors: Vec<CtorDecl>,
}

/// Recursion mode of a definition (DESIGN.md §5.6).
#[derive(Debug, Clone)]
pub enum Recursion {
    None,
    /// Structural on parameter `param` (0-based position in the telescope).
    Structural { param: u32 },
    /// Measure recursion: `measure` is a term over the parameters (in the
    /// context of the telescope) of type `Int` or a machine width.
    Measure { measure: Tm },
}

/// What a definition is, for reporting and for the optimizer (never affects
/// checking).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefKind {
    Exec,
    Spec,
    Lemma,
    Law,
    LoopHelper,
    Ensures,
    Prelude,
    Intrinsic,
}

/// A definition to be checked and added to the environment. `ty` is the
/// full Π telescope; `body` is the matching λ telescope.
#[derive(Debug, Clone)]
pub struct DefDecl {
    pub name: Name,
    pub kind: DefKind,
    pub ty: Tm,
    pub body: Tm,
    pub recursion: Recursion,
    /// Number of leading λ binders that form the parameter telescope.
    pub arity: u32,
    /// Opaque definitions never unfold in checking-mode evaluation or
    /// conversion; `Delta` exposes their defining equation (DESIGN.md §5.6).
    /// The optimizer may still evaluate them (`Env::eval_opaque`).
    pub opaque: bool,
}
