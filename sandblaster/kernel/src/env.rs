//! Private data of the global environment [`Env`](crate::api::Env)
//! (DESIGN.md §5.4, §5.6): checked inductive declarations, committed
//! definitions, the definition currently being checked (so that `Rec` is a
//! neutral while its body is checked), and the prelude items the evaluator
//! and conversion recognize (§5.7 list simplifications, §5.9 array eta).

use std::cell::OnceCell;

use crate::term::{CtorDecl, DefKind, GlobalId, IndId, Name, Recursion, Rel, Sort, Tm, Width};
use crate::value::V;

/// A checked inductive declaration.
#[derive(Debug)]
pub(crate) struct IndInfo {
    pub name: Name,
    /// Parameters and their types (each in the context of the previous ones).
    pub params: Vec<(Name, Tm)>,
    pub ctors: Vec<CtorDecl>,
    /// `rec_fields[k][j]`: field `j` of constructor `k` is a direct recursive
    /// occurrence `D(params)`.
    pub rec_fields: Vec<Vec<bool>>,
    /// Some constructor has a recursive field.
    pub recursive: bool,
}

impl IndInfo {
    /// Non-recursive with exactly one constructor: struct eta applies (§5.4).
    pub fn struct_like(&self) -> bool {
        !self.recursive && self.ctors.len() == 1
    }
}

/// A committed definition.
#[derive(Debug)]
pub(crate) struct DefInfo {
    pub name: Name,
    pub kind: DefKind,
    pub ty: Tm,
    pub ty_val: V,
    /// The body with every `Rec(args)` replaced by `g args` (full λ telescope).
    pub body: Tm,
    /// `body` under its `arity` leading λ binders.
    pub inner: Tm,
    pub recursion: Recursion,
    pub arity: u32,
    /// Relevance of the `arity` parameters.
    pub param_rels: Vec<Rel>,
    /// The result type `R` under the `arity` parameter binders.
    pub res_ty: Tm,
    /// The sort of `R`.
    pub res_sort: Sort,
    /// Opaque definitions (DESIGN.md §5.6) never unfold under the default
    /// policy; `Delta`/`Unfold` expose their defining equation and
    /// `Env::eval_opaque` (optimizer) evaluates them transparently.
    pub opaque: bool,
    /// `inner` is a term DAG (some subterm has several parents): unfoldings
    /// evaluate it with a scoped memo (see `Ev::unfold`) instead of as the
    /// tree it unfolds to.
    pub shared: bool,
    /// Cached value of `body` (non-recursive, non-intrinsic definitions),
    /// default evaluation mode.
    pub cached: OnceCell<V>,
    /// Cached value of `body` in the `BvRefl` evaluation mode (transparent,
    /// intrinsics unfolded on symbolic data, §5.6/§9.8).
    pub cached_bv: OnceCell<V>,
    /// Cached value of `body` in the fully transparent mode
    /// (`Env::eval_transparent`: no global folded).
    pub cached_transparent: OnceCell<V>,
}

impl DefInfo {
    /// Recursive definitions follow the §5.6 speculative unfolding policy.
    pub fn is_recursive(&self) -> bool {
        !matches!(self.recursion, Recursion::None)
    }
}

/// The definition whose body is being checked by `add_def`.
#[derive(Debug, Clone)]
pub(crate) struct Pending {
    /// The id the definition will receive when committed. `Rec` evaluates to
    /// the neutral `Head::Global { def: id, .. }`, which can never unfold
    /// because `id` is not in the environment yet.
    pub id: GlobalId,
    pub ty_val: V,
    pub arity: u32,
    pub param_rels: Vec<Rel>,
    pub recursion: Recursion,
    /// Width of the measure (measure recursion only).
    pub measure_width: Option<Width>,
}

/// Prelude items with kernel-level meaning, registered only by
/// `Env::with_prelude` from the embedded (fixed) prelude text.
#[derive(Debug, Default, Clone)]
pub(crate) struct Known {
    pub list: Option<IndId>,
    pub len: Option<GlobalId>,
    pub index: Option<GlobalId>,
    pub take: Option<GlobalId>,
    pub drop: Option<GlobalId>,
    /// `from_le_bytes` for `U16`, `U32`, `U64`.
    pub from_le: [Option<GlobalId>; 3],
}

impl Known {
    /// The width produced by a known `from_le_bytes` global, if `g` is one.
    pub fn le_bytes_width(&self, g: GlobalId) -> Option<Width> {
        const WS: [Width; 3] = [Width::U16, Width::U32, Width::U64];
        (0..3).find(|&i| self.from_le[i] == Some(g)).map(|i| WS[i])
    }
}
