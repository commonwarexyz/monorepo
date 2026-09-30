//! Residuals with control flow (optimizer design §5, §6.7): the process
//! tree of the driver (`opt::drive::tree`) becomes HIR in the canonical
//! dialect.
//!
//! Beyond the straight-line nodes of the parent module, the residual
//! language has:
//!
//! * **`Match`/`If`**: a split of the tree (in tail position) or a match
//!   left inside a leaf (select-shaped, a merge); booleans print as `if`,
//!   `Option` and user types as `match`, single-constructor types as a
//!   one-arm `match`; arm fields are new locals;
//! * **`Call`** of a user function (a helper or the function kept as a
//!   call) and of the slice builtins the driver keeps folded
//!   (`split_first_chunk`, …);
//! * **`SubSlice`** `&s[a..]`, `&s[..b]` (from `slice::suffix`/`prefix`:
//!   `drop`/`take` of a slice's list), **`Len`** `s.len()`;
//! * **`Index`**: an element read of an array or slice at a symbolic (or,
//!   for slices, literal) index, its bound re-proven in its own scope;
//! * **`Field`**: a projection of a struct or tuple (a single-arm match on
//!   the value whose arm returns one field: the kernel's struct η, DESIGN.md
//!   §5.9);
//! * **`Enum`**: a variant of a user enum;
//! * **`WrapPrim`**: the total (wrapping) primitives print as `wrapping_*`
//!   methods (the parent module's primitive printing).
//!
//! **Scoped emission.** Nodes are hash-consed over the whole residual, but
//! bound per scope: a node is let-bound in a scope when that scope demands
//! it (a split's scrutinee, a leaf's value) and it is used more than once
//! there or also demanded by a nested scope; a node demanded only inside
//! arms is emitted inside each arm. So a partial operation (an index, a
//! sub-slice, a checked operation) is never hoisted above the guard that
//! makes it valid: it appears only where the driver computed it, whose path
//! facts are exactly the residual's (the elaborator re-proves every proof
//! slot there, DESIGN.md §8.2.1).

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use num_traits::ToPrimitive;
use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{GlobalId, IndId, PrimOp, Term, Width};
use sandblaster_kernel::value::{Arg, Budget, Elim, EnvEntry, Head, Neutral, V, Value};

use super::{Maps, PrimOpKey, assemble, prim_result_ty, uint_of};
use crate::builtins::{Builtin, IntMethod, SliceMethod};
use crate::hir::*;
use crate::intrinsics::{self, HelperId, IntrinsicId};
use crate::opt::drive::step::Eval;
use crate::opt::drive::tree::{Node as TNode, NodeKind as TKind};
use crate::span::Span;

type NodeId = usize;

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
enum N {
    Lit(UintTy, u128),
    Bool(bool),
    /// A parameter or an arm-bound variable (by level).
    Var(u32),
    /// Element `k` of an array node (literal index).
    ElemRead(NodeId, u64),
    /// Element read at an index node (array or slice base).
    Index(NodeId, NodeId),
    /// `&s[lo..hi]` (either bound optional).
    SubSlice(NodeId, Option<NodeId>, Option<NodeId>),
    /// `s.len()`.
    Len(NodeId),
    /// Field `i` of a struct or tuple node.
    Field(NodeId, u32),
    ArrayLit(Vec<NodeId>),
    /// An array literal printed as the buffer it was built as (a zeroed
    /// local filled by `copy_from_slice`, `super::assemble`).
    Assemble(Vec<assemble::Piece>),
    Tuple(Vec<NodeId>),
    Some(NodeId),
    /// `None` (its type in the key: two `None`s of different types are
    /// different nodes).
    None(Ty),
    Struct(ItemId, Vec<NodeId>),
    Enum(ItemId, u32, Vec<NodeId>),
    Prim(PrimOpKey, Vec<NodeId>),
    Intrinsic(IntrinsicId, Vec<i64>, Vec<NodeId>),
    Helper(HelperId, Vec<NodeId>),
    FromLe(UintTy, NodeId),
    /// `b as uN` (the prelude's `bool::as_uN`, kept folded by the driver).
    BoolAs(UintTy, NodeId),
    /// `!b` (the prelude's `bool::not`, kept folded by the driver).
    BoolNot(NodeId),
    /// `a.checked_add(b)` / `a.checked_sub(b)` (the prelude's, kept folded
    /// by the driver so a decided one is rewritten by its lemma).
    IntCall(crate::builtins::IntMethod, UintTy, Vec<NodeId>),
    Call(ItemId, Vec<Ty>, Vec<NodeId>),
    /// A slice builtin call (receiver first).
    Builtin(SliceMethod, Ty, Vec<NodeId>),
    /// `a == b` on two arrays (`seq::eq` of their lists with the element
    /// type's primitive equality).
    ArrayEq(NodeId, NodeId),
    /// A match (in-place, or a split of the tree: `split` is the index of
    /// the tree node).
    Match { scrut: NodeId, ind: IndId, arms: Vec<MArm> },
    /// `let v = value; body`: a callee's residual inlined as a value (the
    /// tree's `Bind`, a join point); `var` is the level of `v`, bound in
    /// `body` only.
    Bind { var: u32, value: NodeId, body: NodeId },
    /// The argument of a callee's `#[ghost]` parameter (§15.3): a ghost
    /// `Int` expression over exec values. Never bound by a `let` (it is not
    /// exec code) and erased from the printed code with the parameter.
    Ghost(G),
}

/// A ghost `Int` expression (the value a `#[ghost]` parameter is passed).
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
enum G {
    Lit(sandblaster_kernel::term::BigInt),
    /// An exec value widened: `x as Int`.
    Of(NodeId),
    Add(Box<G>, Box<G>),
    Sub(Box<G>, Box<G>),
    Mul(Box<G>, Box<G>),
}

impl G {
    fn nodes(&self, out: &mut Vec<NodeId>) {
        match self {
            G::Lit(_) => {}
            G::Of(x) => out.push(*x),
            G::Add(a, b) | G::Sub(a, b) | G::Mul(a, b) => {
                a.nodes(out);
                b.nodes(out);
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct MArm {
    ctor: u32,
    /// Levels of the relevant fields (irrelevant ones get no local).
    fields: Vec<Option<u32>>,
    body: Body,
}

/// An arm body.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
enum Body {
    Node(NodeId),
}

struct Node {
    n: N,
    /// HIR value type: references stripped, except that slice values are
    /// `&[T]`.
    ty: Ty,
}

/// What a variable level stands for.
#[derive(Clone, Debug)]
struct VarInfo {
    /// The local (a parameter's binding, or the local an arm pattern binds).
    local: Option<LocalId>,
    /// The declared type (with references).
    decl: Ty,
}

/// The result of [`build_tree`].
pub struct TreeResidual {
    pub body: Expr,
    pub locals: Vec<LocalDecl>,
    /// Distinct residual nodes.
    pub nodes: usize,
    /// User functions called by the residual.
    pub calls: Vec<ItemId>,
}

struct B<'a> {
    env: &'a Env,
    maps: &'a Maps,
    krate: &'a Crate,
    f: &'a FnDef,
    eval: &'a Eval<'a>,
    budget: Budget,
    nodes: Vec<Node>,
    by_key: HashMap<N, NodeId>,
    by_ptr: HashMap<*const Value, NodeId>,
    keep: Vec<V>,
    vars: HashMap<u32, VarInfo>,
    locals: Vec<LocalDecl>,
    /// Owner slice/array node of a list value (by address).
    list_owner: HashMap<*const Value, NodeId>,
    /// The element nodes of each assembled array (to print it as a literal
    /// where it feeds a vector load).
    assembled: HashMap<NodeId, Vec<NodeId>>,
    /// Next free level for in-place match fields.
    next_level: u32,
    span: Span,
    max_nodes: usize,
    slice_ops: SliceOps,
    /// Specialization helpers by key (a static recursive call prints as a
    /// call of its helper with the dynamic arguments).
    specs: &'a std::collections::BTreeMap<crate::opt::drive::tree::SpecKey, ItemId>,
    /// Fold helpers by the recursion they fold (design §6.6): an
    /// application of the recursion prints as a call of its helper with the
    /// same arguments.
    folds: &'a std::collections::BTreeMap<GlobalId, ItemId>,
    /// A simulated fault (the must-reject suite only).
    fault: Option<crate::opt::DriveFault>,
    /// Whether the first boolean split was swapped (fault R4).
    swapped: bool,
}

/// Prelude globals the printer recognizes.
struct SliceOps {
    drop: Option<GlobalId>,
    take: Option<GlobalId>,
    split_first_chunk: Option<GlobalId>,
    first_chunk: Option<GlobalId>,
    seq_eq: Option<GlobalId>,
    list: Option<IndId>,
    /// `bool::as_uN`.
    bool_as: HashMap<GlobalId, UintTy>,
    bool_not: Option<GlobalId>,
    /// `uN::checked_add` / `uN::checked_sub`.
    checked: HashMap<GlobalId, (crate::builtins::IntMethod, UintTy)>,
}

fn rel_args(args: &[Arg]) -> Vec<V> {
    args.iter().filter_map(|a| if let Arg::Rel(v) = a { Some(v.clone()) } else { None }).collect()
}

/// The value type of a declared type: references stripped, except slices.
fn value_ty(t: &Ty) -> Ty {
    match t.peel_refs() {
        Ty::Slice(e) => Ty::slice_ref((**e).clone()),
        other => other.clone(),
    }
}

impl Node {
    /// The pieces of an assembled array node (empty for any other node).
    fn n_pieces(&self) -> Vec<assemble::Piece> {
        match &self.n {
            N::Assemble(ps) => ps.clone(),
            _ => Vec::new(),
        }
    }
}

impl<'a> B<'a> {
    fn add(&mut self, n: N, ty: Ty) -> Result<NodeId, String> {
        if let Some(i) = self.by_key.get(&n) {
            return Ok(*i);
        }
        if self.nodes.len() >= self.max_nodes {
            return Err(format!("the residual exceeds its node budget ({})", self.max_nodes));
        }
        let i = self.nodes.len();
        self.nodes.push(Node { n: n.clone(), ty });
        self.by_key.insert(n, i);
        Ok(i)
    }

    fn ty(&self, i: NodeId) -> Ty {
        self.nodes[i].ty.clone()
    }

    fn global_name(&self, g: GlobalId) -> String {
        self.env.global_name(g).map(|s| s.to_string()).unwrap_or_default()
    }

    fn node(&mut self, v: &V) -> Result<NodeId, String> {
        if let Some(i) = self.by_ptr.get(&Rc::as_ptr(v)) {
            return Ok(*i);
        }
        let id = self.node_uncached(v)?;
        self.by_ptr.insert(Rc::as_ptr(v), id);
        self.keep.push(v.clone());
        Ok(id)
    }

    fn var_node(&mut self, l: u32) -> Result<NodeId, String> {
        let info = self.vars.get(&l).cloned().ok_or_else(|| format!("a variable (level {l}) that is neither a parameter nor an arm field"))?;
        self.add(N::Var(l), value_ty(&info.decl))
    }

    fn node_uncached(&mut self, v: &V) -> Result<NodeId, String> {
        match &**v {
            Value::Lit { w, n } => {
                let u = uint_of(*w).ok_or("a ghost `Int` value in the residual")?;
                let n = n.to_u128().ok_or("literal out of range")?;
                self.add(N::Lit(u, n), Ty::Uint(u))
            }
            Value::Ctor { ind, ctor, params, args } => self.ctor_node(*ind, *ctor, params, args),
            Value::Pair { fst, snd } => self.pair_node(v, fst, snd),
            Value::Neu(n) => self.neu_node(v, n),
            _ => Err("a type or function value in the residual".into()),
        }
    }

    fn ctor_node(&mut self, ind: IndId, ctor: u32, params: &[V], args: &[Arg]) -> Result<NodeId, String> {
        let rel = rel_args(args);
        if ind == self.maps.bool_ {
            return self.add(N::Bool(ctor == 1), Ty::Bool);
        }
        if ind == self.maps.option {
            return match ctor {
                0 => {
                    let t = params.first().map(|p| self.ty_of_type_value(p)).transpose()?.ok_or("`None` without a type")?;
                    self.add(N::None(t.clone()), Ty::option(t))
                }
                _ => {
                    let x = self.node(&rel[0])?;
                    let t = params.first().map(|p| self.ty_of_type_value(p)).transpose()?.unwrap_or_else(|| self.ty(x));
                    self.add(N::Some(x), Ty::option(t))
                }
            };
        }
        if let Some(n) = self.maps.tuples.get(&ind).copied() {
            let ids = rel.iter().map(|x| self.node(x)).collect::<Result<Vec<_>, _>>()?;
            if ids.len() != n {
                return Err("tuple arity mismatch".into());
            }
            let t = match params.iter().map(|p| self.ty_of_type_value(p)).collect::<Result<Vec<_>, _>>() {
                Ok(ts) if ts.len() == n => Ty::Tuple(ts),
                _ => Ty::Tuple(ids.iter().map(|i| self.ty(*i)).collect()),
            };
            return self.add(N::Tuple(ids), t);
        }
        if let Some(item) = self.maps.adts.get(&ind).copied() {
            let ids = rel.iter().map(|x| self.node(x)).collect::<Result<Vec<_>, _>>()?;
            return match &self.krate.item(item).kind {
                ItemKind::Struct(s) if s.generics.is_empty() => self.add(N::Struct(item, ids), Ty::Adt(item, vec![])),
                ItemKind::Enum(e) if e.generics.is_empty() => self.add(N::Enum(item, ctor, ids), Ty::Adt(item, vec![])),
                _ => Err("a generic user type in the residual".into()),
            };
        }
        Err("a list or other inductive value in the residual".into())
    }

    /// An array (`(list, proof)`) or a slice (`(len, (list, proof))`) value.
    fn pair_node(&mut self, v: &V, fst: &V, snd: &Arg) -> Result<NodeId, String> {
        // a slice: (n, (list, _))
        if let Arg::Rel(inner) = snd
            && let Value::Pair { fst: list, .. } = &**inner
        {
            // η of a slice variable
            if let (Some(a), Some(b)) = (proj_base(fst, &[Elim::Fst]), proj_base(list, &[Elim::Snd, Elim::Fst]))
                && Rc::ptr_eq(&a, &b)
            {
                return self.node(&a);
            }
            let s = self.list_as_slice(list)?;
            self.list_owner.insert(Rc::as_ptr(list), s);
            let _ = v;
            return Ok(s);
        }
        // an array: (list, _)
        if let Value::Neu(n) = &**fst
            && matches!(n.spine.last(), Some(Elim::Fst))
        {
            // `(fst x, _)` is `x`
            if let Some(x) = proj_base(fst, &[Elim::Fst]) {
                return self.node(&x);
            }
            return Err("an array passed through as a whole (neutral pair)".into());
        }
        let mut elems = Vec::new();
        let mut cur = fst.clone();
        loop {
            let next = match &*cur {
                Value::Ctor { ind, ctor: 0, .. } if *ind == self.maps.list => break,
                Value::Ctor { ind, ctor: 1, args, .. } if *ind == self.maps.list => {
                    let rel = rel_args(args);
                    elems.push(rel[0].clone());
                    rel[1].clone()
                }
                _ => return Err("an array whose list is not a literal spine".into()),
            };
            cur = next;
        }
        if elems.is_empty() {
            return Err("an empty array in the residual".into());
        }
        // the spine expansion of an array variable is the variable
        if let Some(x) = self.whole_var(&elems) {
            return Ok(x);
        }
        let ids = elems.iter().map(|x| self.node(x)).collect::<Result<Vec<_>, _>>()?;
        let et = self.ty(ids[0]);
        let n = ids.len() as u64;
        let a = match self.assembly(&ids, &et) {
            Some(pieces) => {
                let a = self.add(N::Assemble(pieces), Ty::array(et, n))?;
                self.assembled.insert(a, ids);
                a
            }
            None => self.add(N::ArrayLit(ids), Ty::array(et, n))?,
        };
        self.list_owner.insert(Rc::as_ptr(fst), a);
        Ok(a)
    }

    /// The runs of an array spine, when it prints better as the buffer it
    /// was built as (`super::assemble`).
    fn assembly(&self, ids: &[NodeId], et: &Ty) -> Option<Vec<assemble::Piece>> {
        let shapes: Vec<assemble::Shape> = ids.iter().map(|i| self.elem_shape(*i)).collect();
        assemble::plan(ids, &shapes, matches!(et, Ty::Uint(_)), *et == Ty::u8())
    }

    /// An array passed to an intrinsic or a load/store helper: an
    /// assembled array goes back to its literal (its elements go to a
    /// vector register; building it in memory first would only add stores
    /// and a reload that cannot be forwarded from them).
    fn literal(&mut self, id: NodeId) -> Result<NodeId, String> {
        match self.assembled.get(&id).cloned() {
            Some(ids) if !assemble::has_bytes(&self.nodes[id].n_pieces()) => {
                let t = self.ty(id);
                self.add(N::ArrayLit(ids), t)
            }
            _ => Ok(id),
        }
    }

    fn elem_shape(&self, i: NodeId) -> assemble::Shape {
        use assemble::Shape;
        match &self.nodes[i].n {
            // (of an array variable only: the kernel eta-expands array
            // variables, so a copy from one evaluates to the same spine; a
            // copy from a call's array result would stay a stuck append)
            N::ElemRead(b, k) if matches!(self.nodes[*b].ty, Ty::Array(..)) && matches!(self.nodes[*b].n, N::Var(_)) => Shape::Read { base: *b, k: *k },
            N::Lit(_, 0) => Shape::Zero,
            N::Prim(PrimOpKey(PrimOp::Cast { from, to: Width::U8 }), xs) if xs.len() == 1 => {
                let Some(w) = uint_of(*from).filter(|w| matches!(w, UintTy::U16 | UintTy::U32 | UintTy::U64)) else { return Shape::Other };
                let y = xs[0];
                if let N::Prim(PrimOpKey(PrimOp::WShr(fw) | PrimOp::Shr(fw)), ys) = &self.nodes[y].n
                    && fw == from
                    && ys.len() == 2
                    && let N::Lit(_, s) = self.nodes[ys[1]].n
                    && s < w.bits() as u128
                {
                    return Shape::Byte { x: ys[0], w, shift: s as u32 };
                }
                Shape::Byte { x: y, w, shift: 0 }
            }
            _ => Shape::Other,
        }
    }

    /// `Some(x)` if the elements are exactly `index(fst x, 0..N)` of an
    /// array variable `x` (parameter or arm field) of length `N`.
    fn whole_var(&mut self, elems: &[V]) -> Option<NodeId> {
        let mut which: Option<u32> = None;
        for (i, e) in elems.iter().enumerate() {
            let Value::Neu(n) = &**e else { return None };
            let Head::Global { def, args } = &n.head else { return None };
            if *def != self.maps.index || !n.spine.is_empty() {
                return None;
            }
            let rel = rel_args(args);
            let Value::Lit { n: k, .. } = &*rel.get(2)?.clone() else { return None };
            if k.to_u64()? != i as u64 {
                return None;
            }
            let Value::Neu(m) = &*rel[1] else { return None };
            let (Head::Var(l), [Elim::Fst]) = (&m.head, m.spine.as_slice()) else { return None };
            if which.is_some_and(|w| w != l.0) {
                return None;
            }
            which = Some(l.0);
        }
        let l = which?;
        let info = self.vars.get(&l)?.clone();
        match info.decl.peel_refs() {
            Ty::Array(_, n) if *n as usize == elems.len() => self.var_node(l).ok(),
            Ty::Vector(v) if v.lanes().1 as usize == elems.len() => self.var_node(l).ok(),
            _ => None,
        }
    }

    /// The slice whose list is `list`: `drop`/`take` of a known slice's list
    /// (a sub-slice), or the list of a slice node.
    fn list_as_slice(&mut self, list: &V) -> Result<NodeId, String> {
        if let Some(s) = self.list_owner.get(&Rc::as_ptr(list)).copied() {
            return Ok(s);
        }
        if let Some(x) = proj_base(list, &[Elim::Snd, Elim::Fst]) {
            return self.node(&x);
        }
        let Value::Neu(n) = &**list else { return Err("a slice whose list is not a sub-list of a known slice".into()) };
        let Head::Global { def, args } = &n.head else { return Err("a slice with an unknown list".into()) };
        if !n.spine.is_empty() {
            return Err("a slice with an unknown list".into());
        }
        let rel = rel_args(args);
        let (is_drop, is_take) = (Some(*def) == self.slice_ops.drop, Some(*def) == self.slice_ops.take);
        if !(is_drop || is_take) || rel.len() < 3 {
            return Err(format!("a slice whose list is `{}`", self.global_name(*def)));
        }
        let base = self.list_as_slice(&rel[1])?;
        let k = self.usize_of_int(&rel[2])?;
        let ty = self.ty(base);
        let n = if is_drop { N::SubSlice(base, Some(k), None) } else { N::SubSlice(base, None, Some(k)) };
        let s = self.add(n, ty)?;
        self.list_owner.insert(Rc::as_ptr(list), s);
        Ok(s)
    }

    /// The `usize` node of an `Int` index: `cast_usize_int(i)` or a literal.
    fn usize_of_int(&mut self, v: &V) -> Result<NodeId, String> {
        match &**v {
            Value::Lit { n, .. } => {
                let k = n.to_u128().ok_or("negative index")?;
                self.add(N::Lit(UintTy::Usize, k), Ty::usize())
            }
            Value::Neu(Neutral { head: Head::Prim { op: PrimOp::Cast { from: Width::Usize, to: Width::Int }, args, .. }, spine }) if spine.is_empty() && args.len() == 1 => self.node(&args[0]),
            // `cast_w_int(x)` of a narrower width: `x as usize`
            Value::Neu(Neutral { head: Head::Prim { op: PrimOp::Cast { from, to: Width::Int }, args, .. }, spine }) if spine.is_empty() && args.len() == 1 && *from != Width::Int => {
                let x = self.node(&args[0])?;
                self.add(N::Prim(PrimOpKey(PrimOp::Cast { from: *from, to: Width::Usize }), vec![x]), Ty::usize())
            }
            _ => Err("an index that is not a `usize` value".into()),
        }
    }

    /// The array or slice node whose list is `lv`.
    fn list_base(&mut self, lv: &V) -> Result<NodeId, String> {
        if let Some(s) = self.list_owner.get(&Rc::as_ptr(lv)).copied() {
            return Ok(s);
        }
        if let Some(x) = proj_base(lv, &[Elim::Snd, Elim::Fst]) {
            let s = self.node(&x)?;
            if matches!(self.ty(s), Ty::Ref(_)) {
                return Ok(s);
            }
        }
        if let Some(x) = proj_base(lv, &[Elim::Fst]) {
            let a = self.node(&x)?;
            if matches!(self.ty(a), Ty::Array(..) | Ty::Vector(_)) {
                return Ok(a);
            }
        }
        self.list_as_slice(lv)
    }

    fn neu_node(&mut self, v: &V, n: &Neutral) -> Result<NodeId, String> {
        // the first match of the spine that is not a projection: an in-place match
        let mut base: Option<NodeId> = None;
        let mut i = 0usize;
        // the head
        let head_node = match &n.head {
            Head::Var(l) => Some(self.var_node(l.0)?),
            Head::Prim { op, args, .. } => {
                let ty = prim_result_ty(*op).ok_or_else(|| format!("primitive {op:?} cannot be printed"))?;
                let ids = args.iter().map(|x| self.node(x)).collect::<Result<Vec<_>, _>>()?;
                // fault R15: saturating additions printed as wrapping ones
                let op = match op {
                    PrimOp::SatAdd(w) if self.fault == Some(crate::opt::DriveFault::WrapOps) => PrimOp::WAdd(*w),
                    op => *op,
                };
                Some(self.add(N::Prim(PrimOpKey(op), ids), ty)?)
            }
            Head::Global { def, args } => {
                // projections of a global application's result follow in the spine
                let rel = rel_args(args);
                if *def == self.maps.index {
                    if !n.spine.is_empty() {
                        return Err("a projection of a list element".into());
                    }
                    return self.index_node(&rel);
                }
                Some(self.global_node(*def, &rel, args)?)
            }
            other => return Err(format!("a stuck {} in the residual", crate::opt::symex::describe_head(self.env, other))),
        };
        if let Some(h) = head_node {
            base = Some(h);
        }
        let mut cur = base.ok_or("a neutral without a head")?;
        while i < n.spine.len() {
            match &n.spine[i] {
                Elim::Match { ind, arms, .. } => {
                    // a projection: a single-constructor match whose arm is a field
                    if let Some(k) = self.projection(*ind, arms) {
                        let ty = self.field_ty(cur, k)?;
                        cur = self.add(N::Field(cur, k), ty)?;
                    } else {
                        let rest: Vec<Elim> = n.spine[i + 1..].iter().map(crate::auto::util::clone_elim).collect();
                        let prefix = crate::auto::util::prefix(n, i);
                        cur = self.inplace_match(v, &prefix, *ind, &n.spine[i], &rest)?;
                        return Ok(cur);
                    }
                }
                Elim::Fst | Elim::Snd => {
                    // `fst(s)` of a slice is its length; other projections
                    // are list accesses consumed by their users
                    let rest = &n.spine[i..];
                    if matches!(rest, [Elim::Fst]) && matches!(self.ty(cur), Ty::Ref(ref t) if matches!(**t, Ty::Slice(_))) {
                        return self.add(N::Len(cur), Ty::usize());
                    }
                    return Err("a projection of a pair outside an element read".into());
                }
                Elim::App(_) => return Err("an application of a neutral in the residual".into()),
            }
            i += 1;
        }
        Ok(cur)
    }

    /// `k` if a single-constructor `match` whose arm returns field `k`.
    fn projection(&self, ind: IndId, arms: &[sandblaster_kernel::value::Closure]) -> Option<u32> {
        if arms.len() != 1 {
            return None;
        }
        if !(self.maps.tuples.contains_key(&ind) || self.maps.adts.contains_key(&ind)) {
            return None;
        }
        let nf = self.env.inductive_decl(ind)?.ctors.first()?.fields.len() as u32;
        match &*arms[0].body {
            Term::Var(sandblaster_kernel::term::Idx(j)) if *j < nf => Some(nf - 1 - *j),
            _ => None,
        }
    }

    /// The type of field `k` of a struct or tuple node.
    fn field_ty(&self, base: NodeId, k: u32) -> Result<Ty, String> {
        match self.ty(base) {
            Ty::Tuple(ts) => ts.get(k as usize).map(value_ty).ok_or_else(|| "a tuple field out of range".into()),
            Ty::Adt(item, args) => match &self.krate.item(item).kind {
                ItemKind::Struct(s) => s.fields.get(k as usize).map(|f| value_ty(&f.ty.subst(&args))).ok_or_else(|| "a struct field out of range".into()),
                _ => Err("a projection of an enum".into()),
            },
            t => Err(format!("a projection of a value of type `{}`", self.krate.ty_str(&t))),
        }
    }

    /// `index(T, list, i)`.
    fn index_node(&mut self, rel: &[V]) -> Result<NodeId, String> {
        if rel.len() < 3 {
            return Err("a partial list index".into());
        }
        let base = self.list_base(&rel[1])?;
        let bt = self.ty(base);
        let et = match &bt {
            Ty::Array(e, _) => (**e).clone(),
            Ty::Ref(s) => match &**s {
                Ty::Slice(e) => (**e).clone(),
                _ => return Err("an element read of a non-array".into()),
            },
            Ty::Vector(v) => Ty::Uint(v.lanes().0),
            _ => return Err("an element read of a non-array".into()),
        };
        if matches!(bt, Ty::Array(..) | Ty::Vector(_))
            && let Value::Lit { n: k, .. } = &*rel[2]
        {
            let k = k.to_u64().ok_or("negative index")?;
            return self.add(N::ElemRead(base, k), et);
        }
        let i = self.usize_of_int(&rel[2])?;
        self.add(N::Index(base, i), et)
    }

    /// A match left inside a leaf value: its arms are instantiated with
    /// fresh variables and residualized in place.
    fn inplace_match(&mut self, _v: &V, scrut_v: &V, ind: IndId, m: &Elim, rest: &[Elim]) -> Result<NodeId, String> {
        let Elim::Match { params, arms, .. } = m else { unreachable!() };
        let scrut = self.node(scrut_v)?;
        let decl = self.env.inductive_decl(ind).ok_or("unknown inductive")?;
        let sty = self.ty(scrut);
        let mut out = Vec::new();
        let mut body_ty: Option<Ty> = None;
        for (k, c) in decl.ctors.iter().enumerate() {
            let ftys = self.field_tys(&sty, ind, k as u32, c.fields.len())?;
            let mut es = Vec::new();
            let mut fl = Vec::new();
            let mut fenv: Vec<EnvEntry> = params.iter().map(|x| EnvEntry::Rel(x.clone())).collect();
            for (j, (fname, frel, fty)) in c.fields.iter().enumerate() {
                let l = self.next_level;
                self.next_level += 1;
                let e = match frel {
                    sandblaster_kernel::term::Rel::Irr => EnvEntry::Irr(sandblaster_kernel::value::Closure { env: Default::default(), body: Rc::new(Term::Erased) }),
                    sandblaster_kernel::term::Rel::Rel => {
                        let tv = self.env.eval(&sandblaster_kernel::value::VEnv(Rc::new(fenv.clone())), sandblaster_kernel::term::Lvl(l), fty, &mut self.budget).map_err(|e| format!("{e:?}"))?;
                        self.env.fresh_var(sandblaster_kernel::term::Lvl(l), sandblaster_kernel::term::Rel::Rel, &tv)
                    }
                };
                if *frel == sandblaster_kernel::term::Rel::Rel {
                    let decl_ty = ftys.get(j).cloned().flatten().ok_or("an arm field of unknown type")?;
                    self.new_local(l, fname, decl_ty);
                    fl.push(Some(l));
                } else {
                    fl.push(None);
                }
                fenv.push(e.clone());
                es.push(e);
            }
            let arm = arms.get(k).ok_or("a match without the constructor's arm")?;
            let depth = self.next_level;
            let mut b = std::mem::replace(&mut self.budget, Budget { steps: 0 });
            let w = self.eval.inst(arm, es, depth, &mut b).and_then(|w| self.eval.elims(w, rest, depth, &mut b));
            self.budget = b;
            let w = w?;
            let body = self.node(&w)?;
            body_ty.get_or_insert_with(|| self.ty(body));
            out.push(MArm { ctor: k as u32, fields: fl, body: Body::Node(body) });
        }
        let ty = body_ty.ok_or("a match without arms")?;
        self.add(N::Match { scrut, ind, arms: out }, ty)
    }

    /// Declared (HIR) types of the relevant fields of constructor `k` of a
    /// scrutinee of type `sty`.
    fn field_tys(&self, sty: &Ty, ind: IndId, k: u32, nf: usize) -> Result<Vec<Option<Ty>>, String> {
        if ind == self.maps.bool_ {
            return Ok(vec![]);
        }
        match sty.peel_refs() {
            Ty::Option(t) => Ok(if k == 1 { vec![Some((**t).clone())] } else { vec![] }),
            Ty::Tuple(ts) => Ok(ts.iter().cloned().map(Some).collect()),
            Ty::Adt(item, args) => match &self.krate.item(*item).kind {
                ItemKind::Struct(s) => Ok(s.fields.iter().map(|f| Some(f.ty.subst(args))).collect()),
                ItemKind::Enum(e) => {
                    let v = e.variants.get(k as usize).ok_or("variant out of range")?;
                    Ok(v.fields.iter().map(|f| Some(f.ty.subst(args))).collect())
                }
                _ => Err("a match on a non-ADT item".into()),
            },
            _ => Ok(vec![None; nf]),
        }
    }

    /// A local named exactly `name` for level `level` (a join variable: the
    /// proof builder finds its `let` by this name).
    fn new_local_named(&mut self, level: u32, name: &str, decl: Ty) -> LocalId {
        let l = LocalId(self.locals.len() as u32);
        self.locals.push(LocalDecl { name: name.to_string(), ty: decl.clone(), mutable: false, ghost: false, span: self.span });
        self.vars.insert(level, VarInfo { local: Some(l), decl });
        l
    }

    fn new_local(&mut self, level: u32, name: &str, decl: Ty) -> LocalId {
        let l = LocalId(self.locals.len() as u32);
        let base = name.trim_start_matches('.');
        let nm = if base.is_empty() || base.starts_with('x') && base[1..].chars().all(|c| c.is_ascii_digit()) { format!("r{}", l.0) } else { format!("{base}_{}", l.0) };
        self.locals.push(LocalDecl { name: nm, ty: decl.clone(), mutable: false, ghost: false, span: self.span });
        self.vars.insert(level, VarInfo { local: Some(l), decl });
        l
    }

    /// A neutral application of a global.
    fn global_node(&mut self, def: GlobalId, rel: &[V], args: &[Arg]) -> Result<NodeId, String> {
        if let Some(id) = self.maps.intrinsics.get(&def).copied() {
            let info = intrinsics::get(id);
            let k = info.imms.len();
            if rel.len() != k + info.params.len() {
                return Err(format!("intrinsic `{}` with an unexpected argument count", info.name));
            }
            let mut imms = Vec::new();
            for x in &rel[..k] {
                match &**x {
                    Value::Lit { n, .. } => imms.push(n.to_i64().ok_or("immediate out of range")?),
                    _ => return Err("a symbolic immediate".into()),
                }
            }
            let mut ids = Vec::new();
            for (x, pt) in rel[k..].iter().zip(&info.params) {
                let n = self.node(x)?;
                let n = self.literal(n)?;
                ids.push(self.coerce_vec(n, pt)?);
            }
            return self.add(N::Intrinsic(id, imms, ids), info.ret.clone());
        }
        if let Some(h) = self.maps.helpers.get(&def).copied() {
            let info = intrinsics::helper(h);
            if rel.len() != info.params.len() {
                return Err(format!("helper `{}` with an unexpected argument count", info.name));
            }
            let mut ids = Vec::new();
            for (x, pt) in rel.iter().zip(&info.params) {
                let n = self.node(x)?;
                let n = self.literal(n)?;
                ids.push(self.coerce_vec(n, pt.peel_refs())?);
            }
            return self.add(N::Helper(h, ids), info.ret.clone());
        }
        if let Some(w) = self.maps.from_le.get(&def).copied() {
            let x = self.node(rel.first().ok_or("from_le_bytes without argument")?)?;
            return self.add(N::FromLe(w, x), Ty::Uint(w));
        }
        if Some(def) == self.slice_ops.bool_not {
            let x = self.node(rel.first().ok_or("`bool::not` without argument")?)?;
            return self.add(N::BoolNot(x), Ty::Bool);
        }
        if let Some((m, w)) = self.slice_ops.checked.get(&def).copied() {
            if rel.len() != 2 {
                return Err("a checked arithmetic call with an unexpected argument count".into());
            }
            let ids = rel.iter().map(|x| self.node(x)).collect::<Result<Vec<_>, _>>()?;
            return self.add(N::IntCall(m, w, ids), Ty::option(Ty::Uint(w)));
        }
        if let Some(w) = self.slice_ops.bool_as.get(&def).copied() {
            let x = self.node(rel.first().ok_or("`bool::as_uN` without argument")?)?;
            return self.add(N::BoolAs(w, x), Ty::Uint(w));
        }
        if Some(def) == self.slice_ops.split_first_chunk || Some(def) == self.slice_ops.first_chunk {
            // (T, s, N)
            if rel.len() != 3 {
                return Err("a slice builtin with an unexpected argument count".into());
            }
            let t = self.ty_of_type_value(&rel[0])?;
            let n = match &*rel[2] {
                Value::Lit { n, .. } => n.to_u64().ok_or("chunk length out of range")?,
                _ => return Err("a symbolic chunk length".into()),
            };
            let s = self.node(&rel[1])?;
            let (m, ret) = if Some(def) == self.slice_ops.split_first_chunk {
                (SliceMethod::SplitFirstChunk(n), Ty::option(Ty::Tuple(vec![Ty::reference(Ty::array(t.clone(), n)), Ty::slice_ref(t.clone())])))
            } else {
                (SliceMethod::FirstChunk(n), Ty::option(Ty::reference(Ty::array(t.clone(), n))))
            };
            return self.add(N::Builtin(m, t, vec![s]), ret);
        }
        if Some(def) == self.slice_ops.seq_eq && rel.len() == 4 && is_prim_eq(&rel[1]) {
            // (T, eq, xs, ys) over the lists of two arrays
            let a = self.list_base(&rel[2])?;
            let b = self.list_base(&rel[3])?;
            if matches!(self.ty(a), Ty::Array(..)) && self.ty(a) == self.ty(b) {
                return self.add(N::ArrayEq(a, b), Ty::Bool);
            }
            return Err("`seq::eq` of lists that are not two arrays of one type".into());
        }
        // a Σ2 loop head at the static arguments of a committed loop
        // helper: the helper's call over the dynamic arguments
        if let Some((key, _)) = crate::opt::loopsum::key_of_rel(self.env, def, rel)
            && let Some(lh) = crate::opt::loopsum::helper(&key)
        {
            let hf = self.krate.fn_def(lh.item).ok_or("a loop helper that is not a function")?;
            let stat: Vec<usize> = key.statics.iter().map(|(i, _)| *i).collect();
            let mut ids = Vec::new();
            for (i, x) in rel.iter().enumerate() {
                if !stat.contains(&i) {
                    ids.push(self.node(x)?);
                }
            }
            if ids.len() != hf.params.len() {
                return Err("a loop helper call with an unexpected argument count".into());
            }
            let ret = value_ty(&hf.ret);
            return self.add(N::Call(lh.item, vec![], ids), ret);
        }
        if let Some(h) = self.folds.get(&def).copied() {
            // a fold helper: the same relevant arguments (its parameters are
            // the recursion's)
            let hf = self.krate.fn_def(h).ok_or("a fold helper that is not a function")?;
            if rel.len() != hf.params.len() {
                return Err("a fold helper call with an unexpected argument count".into());
            }
            let mut ids = Vec::new();
            for x in rel.iter() {
                ids.push(self.node(x)?);
            }
            let ret = value_ty(&hf.ret);
            return self.add(N::Call(h, vec![], ids), ret);
        }
        if !self.specs.is_empty() {
            let statics: Vec<(usize, sandblaster_kernel::term::BigInt)> = rel.iter().enumerate().filter_map(|(i, v)| match &**v {
                Value::Lit { n, .. } => Some((i, n.clone())),
                _ => None,
            }).collect();
            let key = crate::opt::drive::tree::SpecKey { def, statics };
            if let Some(h) = self.specs.get(&key).copied() {
                let hf = self.krate.fn_def(h).ok_or("a helper that is not a function")?;
                let stat: Vec<usize> = key.statics.iter().map(|(i, _)| *i).collect();
                let mut ids = Vec::new();
                for (i, x) in rel.iter().enumerate() {
                    if !stat.contains(&i) {
                        ids.push(self.node(x)?);
                    }
                }
                if ids.len() != hf.params.len() {
                    return Err("a helper call with an unexpected argument count".into());
                }
                let ret = value_ty(&hf.ret);
                return self.add(N::Call(h, vec![], ids), ret);
            }
        }
        if let Some(item) = self.maps.items.get(&def).copied() {
            let f = self.krate.fn_def(item).ok_or("callee is not a function")?;
            let ng = f.generics.len();
            // `#[ghost]` parameters (the last ones, §15.3) are one `Irr`
            // binder, the ghost bundle: their arguments are its components
            let nghost = f.params.iter().filter(|p| p.ghost).count();
            if rel.len() != ng + f.params.len() - nghost {
                return Err("callee argument count mismatch".into());
            }
            let ret_ty = f.ret.clone();
            let ptys: Vec<Ty> = f.params.iter().filter(|p| !p.ghost).map(|p| p.ty.clone()).collect();
            let targs = rel[..ng].iter().map(|t| self.ty_of_type_value(t)).collect::<Result<Vec<_>, _>>()?;
            let mut ids = Vec::new();
            for (x, pt) in rel[ng..].iter().zip(&ptys) {
                let n = self.node(x)?;
                ids.push(self.coerce_vec(n, pt.subst(&targs).peel_refs())?);
            }
            if nghost > 0 {
                for g in self.ghost_args(def, args, nghost)? {
                    ids.push(self.add(N::Ghost(g), Ty::Int)?);
                }
            }
            let ret = value_ty(&ret_ty.subst(&targs));
            return self.add(N::Call(item, targs, ids), ret);
        }
        Err(format!("a stuck application of `{}`", self.global_name(def)))
    }

    /// `id` as a value of the hardware vector type `expected` (§9.2: a
    /// vector is an array of lanes in the model, so the driver may have
    /// evaluated a lane array — a literal, say — where an intrinsic, a
    /// helper or a function takes a vector): the array through its load
    /// helper (`load_u32x4(&[..])`), as the straight-line printer does. Any
    /// other type is left as it is.
    fn coerce_vec(&mut self, id: NodeId, expected: &Ty) -> Result<NodeId, String> {
        let Ty::Vector(v) = expected else { return Ok(id) };
        if self.ty(id) == *expected {
            return Ok(id);
        }
        let id = self.literal(id)?;
        let (lane, n) = v.lanes();
        if self.ty(id) != Ty::array(Ty::Uint(lane), n) {
            return Err(format!("a value of type `{}` used as `{}`", self.krate.ty_str(&self.ty(id)), v.rust_name()));
        }
        let arch = v.arch();
        let load = match (lane, n) {
            (UintTy::U8, 16) => "load_u8x16",
            (UintTy::U32, 4) => "load_u32x4",
            (UintTy::U64, 2) => "load_u64x2",
            (UintTy::U8, 8) => "load_u8x8",
            _ => return Err(format!("no load helper for `{}`", v.rust_name())),
        };
        let h = intrinsics::lookup_helper(&arch, load).ok_or_else(|| format!("no load helper `{load}`"))?;
        if intrinsics::helper(h).ret != *expected {
            return Err(format!("load helper `{load}` does not produce `{}`", v.rust_name()));
        }
        self.add(N::Helper(h, vec![id]), expected.clone())
    }

    /// The arguments of the `nghost` `#[ghost]` parameters of the call
    /// `def args`: the components of its ghost bundle (the `Irr` binder
    /// named `ghost`, §15.3), evaluated, as ghost expressions. A bundle
    /// whose values are not known (an erased proof) cannot be printed.
    fn ghost_args(&mut self, def: GlobalId, args: &[Arg], nghost: usize) -> Result<Vec<G>, String> {
        let tele = crate::opt::symex::telescope(self.env, def).ok_or("a callee without a telescope")?;
        let at = tele.binders.iter().position(|(n, r, _)| &**n == "ghost" && *r == sandblaster_kernel::term::Rel::Irr).ok_or("a callee with `#[ghost]` parameters but no ghost bundle")?;
        let Some(Arg::Irr(c)) = args.get(at) else { return Err("the ghost bundle of a call is not an irrelevant argument".into()) };
        let mut out = Vec::with_capacity(nghost);
        for k in 0..nghost {
            // fst(snd^k(bundle))
            let mut t = c.body.clone();
            for _ in 0..k {
                t = Rc::new(Term::Snd(t));
            }
            t = Rc::new(Term::Fst(t));
            let mut b = Budget { steps: 1_000_000 };
            let v = self.env.eval(&c.env, sandblaster_kernel::term::Lvl(1 << 20), &t, &mut b).map_err(|e| format!("a ghost argument: {e:?}"))?;
            out.push(self.ghost_of(&v)?);
        }
        Ok(out)
    }

    /// A ghost `Int` value as a ghost expression over exec nodes.
    fn ghost_of(&mut self, v: &V) -> Result<G, String> {
        match &**v {
            Value::Lit { w: Width::Int, n } => Ok(G::Lit(n.clone())),
            Value::Neu(Neutral { head: Head::Prim { op, args, .. }, spine }) if spine.is_empty() => match (op, &args[..]) {
                (PrimOp::Cast { from, to: Width::Int }, [a]) if *from != Width::Int => Ok(G::Of(self.node(a)?)),
                (PrimOp::IAdd, [a, b]) => Ok(G::Add(Box::new(self.ghost_of(a)?), Box::new(self.ghost_of(b)?))),
                (PrimOp::ISub, [a, b]) => Ok(G::Sub(Box::new(self.ghost_of(a)?), Box::new(self.ghost_of(b)?))),
                (PrimOp::IMul, [a, b]) => Ok(G::Mul(Box::new(self.ghost_of(a)?), Box::new(self.ghost_of(b)?))),
                _ => Err(format!("a ghost argument the residual cannot print (primitive {op:?})")),
            },
            Value::Neu(Neutral { head: Head::Absurd { .. }, .. }) => Err("a ghost argument without its value".into()),
            _ => Err("a ghost argument the residual cannot print".into()),
        }
    }

    /// The HIR type of a type value.
    fn ty_of_type_value(&self, v: &V) -> Result<Ty, String> {
        match &**v {
            Value::IntTy(w) => uint_of(*w).map(Ty::Uint).ok_or_else(|| "a ghost type".to_string()),
            Value::Ind { ind, .. } if *ind == self.maps.bool_ => Ok(Ty::Bool),
            Value::Ind { ind, params } if *ind == self.maps.option => Ok(Ty::option(self.ty_of_type_value(&params[0])?)),
            Value::Ind { ind, params } if self.maps.tuples.contains_key(ind) => Ok(Ty::Tuple(params.iter().map(|p| self.ty_of_type_value(p)).collect::<Result<_, _>>()?)),
            Value::Ind { ind, params } if self.maps.adts.contains_key(ind) => {
                let args = params.iter().map(|p| self.ty_of_type_value(p)).collect::<Result<Vec<_>, _>>()?;
                Ok(Ty::Adt(self.maps.adts[ind], args))
            }
            // Slice T = Σ(n : Usize). Σ(l : List T). SliceOk; Array T N = Σ(l : List T). Eq(len l, N)
            Value::Sigma { fst, snd, .. } => {
                if let Value::IntTy(Width::Usize) = &**fst {
                    // a slice: the element type from the inner Σ's list type
                    let mut b = Budget { steps: 10_000 };
                    let x = self.env.fresh_var(sandblaster_kernel::term::Lvl(1 << 20), sandblaster_kernel::term::Rel::Rel, fst);
                    let inner = self.eval.inst(snd, vec![x], (1 << 20) + 1, &mut b).map_err(|e| e.to_string())?;
                    if let Value::Sigma { fst: l, .. } = &*inner
                        && let Value::Ind { ind, params } = &**l
                        && Some(*ind) == self.slice_ops.list
                    {
                        return Ok(Ty::slice_ref(self.ty_of_type_value(&params[0])?));
                    }
                    return Err("a Σ type the residual printer does not know".into());
                }
                if let Value::Ind { ind, params } = &**fst
                    && Some(*ind) == self.slice_ops.list
                {
                    // the length from `Eq(Int, len l, N)`
                    let mut b = Budget { steps: 10_000 };
                    let x = self.env.fresh_var(sandblaster_kernel::term::Lvl(1 << 20), sandblaster_kernel::term::Rel::Rel, fst);
                    let eq = self.eval.inst(snd, vec![x], (1 << 20) + 1, &mut b).map_err(|e| e.to_string())?;
                    if let Value::Eq { rhs, .. } = &*eq
                        && let Some(n) = crate::opt::drive::step::lit_u64(rhs)
                    {
                        return Ok(Ty::array(self.ty_of_type_value(&params[0])?, n));
                    }
                }
                Err("a Σ type the residual printer does not know".into())
            }
            _ => Err("a type the residual printer does not know".into()),
        }
    }
}

/// `λu v. #eq_w(u, v)`: the primitive equality of a machine width.
fn is_prim_eq(v: &V) -> bool {
    let Value::Lam { body, .. } = &**v else { return false };
    let Term::Lam { body: inner, .. } = &*body.body else { return false };
    matches!(&**inner, Term::Prim { op: PrimOp::Eq(_), args, .. } if args.len() == 2
        && matches!(&*args[0], Term::Var(sandblaster_kernel::term::Idx(1)))
        && matches!(&*args[1], Term::Var(sandblaster_kernel::term::Idx(0))))
}

/// `x` if `v` is `x` eliminated by exactly `elims` (projections).
fn proj_base(v: &V, elims: &[Elim]) -> Option<V> {
    let Value::Neu(n) = &**v else { return None };
    if n.spine.len() < elims.len() {
        return None;
    }
    let k = n.spine.len() - elims.len();
    for (a, b) in n.spine[k..].iter().zip(elims) {
        match (a, b) {
            (Elim::Fst, Elim::Fst) | (Elim::Snd, Elim::Snd) => {}
            _ => return None,
        }
    }
    if k == 0 && matches!(n.head, Head::Var(_)) || k > 0 || matches!(n.head, Head::Global { .. }) {
        return Some(crate::auto::util::prefix(n, k));
    }
    None
}

/// Builds the residual HIR body of `f` from its process tree.
#[allow(clippy::too_many_arguments)]
pub fn build_tree(env: &Env, maps: &Maps, krate: &Crate, f: &FnDef, tree: &TNode, eval: &Eval<'_>, specs: &std::collections::BTreeMap<crate::opt::drive::tree::SpecKey, ItemId>, folds: &std::collections::BTreeMap<GlobalId, ItemId>, max_nodes: usize, span: Span, fault: Option<crate::opt::DriveFault>) -> Result<TreeResidual, String> {
    if !f.generics.is_empty() {
        return Err("generic functions are not driven".into());
    }
    for p in &f.params {
        if !matches!(p.pat.kind, PatKind::Binding { sub: None, .. }) || p.ghost {
            return Err("a parameter with a destructuring pattern or a ghost parameter".into());
        }
    }
    let slice_ops = SliceOps {
        drop: env.lookup_global("seq::drop"),
        take: env.lookup_global("seq::take"),
        split_first_chunk: env.lookup_global("slice::split_first_chunk"),
        first_chunk: env.lookup_global("slice::first_chunk"),
        seq_eq: env.lookup_global("seq::eq"),
        list: env.lookup_ind("List"),
        bool_as: [UintTy::U8, UintTy::U16, UintTy::U32, UintTy::U64, UintTy::Usize].into_iter().filter_map(|w| env.lookup_global(&format!("bool::as_{}", w.name())).map(|g| (g, w))).collect(),
        bool_not: env.lookup_global("bool::not"),
        checked: [UintTy::U8, UintTy::U16, UintTy::U32, UintTy::U64, UintTy::Usize]
            .into_iter()
            .flat_map(|w| [(crate::builtins::IntMethod::CheckedAdd, "checked_add"), (crate::builtins::IntMethod::CheckedSub, "checked_sub")].map(move |(m, n)| (m, w, n)))
            .filter_map(|(m, w, n)| env.lookup_global(&format!("{}::{n}", w.name())).map(|g| (g, (m, w))))
            .collect(),
    };
    let mut vars = HashMap::new();
    for (i, p) in f.params.iter().enumerate() {
        let PatKind::Binding { local, .. } = &p.pat.kind else { unreachable!() };
        vars.insert(i as u32, VarInfo { local: Some(*local), decl: p.ty.clone() });
    }
    let max_depth = max_tree_depth(tree);
    let mut b = B {
        env,
        maps,
        krate,
        f,
        eval,
        budget: Budget { steps: 50_000_000 },
        nodes: Vec::new(),
        by_key: HashMap::new(),
        by_ptr: HashMap::new(),
        keep: Vec::new(),
        vars,
        locals: f.locals.clone(),
        list_owner: HashMap::new(),
        assembled: HashMap::new(),
        next_level: max_depth + 16,
        span,
        max_nodes,
        slice_ops,
        specs,
        folds,
        fault,
        swapped: false,
    };
    let root = b.tree_node(tree)?;
    // emission
    let mut em = Emit { b: &mut b, uses_cache: HashMap::new() };
    let bound: HashMap<NodeId, LocalId> = HashMap::new();
    let body = em.scope(&[root], &bound, &f.ret)?;
    // a function body is a block
    let body = block(body);
    let nodes = b.nodes.len();
    let mut calls: Vec<ItemId> = b.nodes.iter().filter_map(|n| if let N::Call(i, ..) = &n.n { Some(*i) } else { None }).collect();
    calls.sort();
    calls.dedup();
    Ok(TreeResidual { body, locals: b.locals, nodes, calls })
}

fn max_tree_depth(t: &TNode) -> u32 {
    match &t.kind {
        TKind::Leaf(_) => t.depth,
        TKind::Split { arms, .. } => arms.iter().map(|a| max_tree_depth(&a.body)).max().unwrap_or(t.depth).max(t.depth + 64),
        TKind::Bind { value, body, .. } => max_tree_depth(value).max(max_tree_depth(body)).max(t.depth + 1),
    }
}

impl<'a> B<'a> {
    /// The node of a tree node: a leaf's value, or a match for a split.
    fn tree_node(&mut self, t: &TNode) -> Result<NodeId, String> {
        match &t.kind {
            TKind::Leaf(v) => self.node(v),
            // every arm ends in this one value: no split in the residual
            TKind::Split { merged: Some(v), .. } => self.node(v),
            TKind::Bind { lvl, name, ty, value, body } => {
                let v = self.tree_node(value)?;
                let decl = self.ty_of_type_value(ty)?;
                self.new_local_named(*lvl, name, decl);
                let b = self.tree_node(body)?;
                let t = self.ty(b);
                self.add(N::Bind { var: *lvl, value: v, body: b }, t)
            }
            TKind::Split { scrut, ind, arms, .. } => {
                let s = self.node(scrut)?;
                let sty = self.ty(s);
                let decl = self.env.inductive_decl(*ind).ok_or("unknown inductive")?;
                let mut out = Vec::new();
                for a in arms {
                    let c = &decl.ctors[a.ctor as usize];
                    let ftys = self.field_tys(&sty, *ind, a.ctor, c.fields.len())?;
                    let mut fl = Vec::new();
                    for (j, fd) in a.fields.iter().enumerate() {
                        if fd.rel == sandblaster_kernel::term::Rel::Rel {
                            let decl_ty = ftys.get(j).cloned().flatten().ok_or("an arm field of unknown type")?;
                            self.new_local(fd.lvl, &fd.name, decl_ty);
                            fl.push(Some(fd.lvl));
                        } else {
                            fl.push(None);
                        }
                    }
                    let body = self.tree_node(&a.body)?;
                    out.push(MArm { ctor: a.ctor, fields: fl, body: Body::Node(body) });
                }
                // fault R4: the arms of the first boolean split swapped
                if self.fault == Some(crate::opt::DriveFault::SwapArms) && !self.swapped && *ind == self.maps.bool_ && out.len() == 2 {
                    let (b0, b1) = (out[0].body.clone(), out[1].body.clone());
                    out[0].body = b1;
                    out[1].body = b0;
                    self.swapped = true;
                }
                let ty = match out.first().map(|a| a.body.clone()) {
                    Some(Body::Node(n)) => self.ty(n),
                    None => value_ty(&self.f.ret),
                };
                self.add(N::Match { scrut: s, ind: *ind, arms: out }, ty)
            }
        }
    }
}

struct Emit<'b, 'a> {
    b: &'b mut B<'a>,
    uses_cache: HashMap<NodeId, HashSet<NodeId>>,
}

/// Children of a node that are evaluated in the node's own scope (not
/// match arms).
fn strict_children(n: &N) -> Vec<NodeId> {
    match n {
        N::Lit(..) | N::Bool(_) | N::Var(_) | N::None(_) => vec![],
        N::ElemRead(x, _) | N::Some(x) | N::FromLe(_, x) | N::BoolAs(_, x) | N::BoolNot(x) | N::Len(x) | N::Field(x, _) => vec![*x],
        N::IntCall(_, _, xs) => xs.clone(),
        N::Index(a, b) | N::ArrayEq(a, b) => vec![*a, *b],
        N::SubSlice(s, lo, hi) => std::iter::once(*s).chain(*lo).chain(*hi).collect(),
        N::ArrayLit(xs) | N::Tuple(xs) | N::Struct(_, xs) | N::Enum(_, _, xs) | N::Prim(_, xs) | N::Intrinsic(_, _, xs) | N::Helper(_, xs) | N::Call(_, _, xs) | N::Builtin(_, _, xs) => xs.clone(),
        N::Assemble(ps) => ps.iter().filter_map(|p| p.node()).collect(),
        N::Match { scrut, .. } => vec![*scrut],
        N::Bind { value, .. } => vec![*value],
        N::Ghost(g) => {
            let mut out = Vec::new();
            g.nodes(&mut out);
            out
        }
    }
}

/// Arm bodies of a match node.
fn arm_bodies(n: &N) -> Vec<NodeId> {
    match n {
        N::Match { arms, .. } => arms.iter().map(|a| match a.body {
            Body::Node(x) => x,
        }).collect(),
        // the body is evaluated after the `let`, in its own scope
        N::Bind { body, .. } => vec![*body],
        _ => vec![],
    }
}

impl Emit<'_, '_> {
    fn e(&self, kind: ExprKind, ty: Ty) -> Expr {
        Expr::new(kind, ty, self.b.span)
    }

    /// Every node reachable from `i` (through arms too).
    fn all_below(&mut self, i: NodeId) -> HashSet<NodeId> {
        if let Some(s) = self.uses_cache.get(&i) {
            return s.clone();
        }
        let mut seen = HashSet::new();
        let mut stack = vec![i];
        while let Some(x) = stack.pop() {
            if !seen.insert(x) {
                continue;
            }
            stack.extend(strict_children(&self.b.nodes[x].n));
            stack.extend(arm_bodies(&self.b.nodes[x].n));
        }
        self.uses_cache.insert(i, seen.clone());
        seen
    }

    fn trivial(n: &N) -> bool {
        // (a ghost argument is printed where it is passed, never bound)
        matches!(n, N::Lit(..) | N::Bool(_) | N::Var(_) | N::None(_) | N::Len(_) | N::Ghost(_))
    }

    /// Nodes always bound by a `let` where they are computed: calls, and
    /// sub-slices (a chain `&(&(&s[1..])[1..])[1..]` printed inline makes
    /// every slice's bound proof mention the whole chain before it: the
    /// elaborated residual, and every proof that quotes it, grows
    /// quadratically with the chain; bound, each proof mentions the
    /// previous slice only).
    fn must_bind(n: &N) -> bool {
        matches!(n, N::Intrinsic(..) | N::Helper(..) | N::Call(..) | N::Builtin(..) | N::SubSlice(..))
    }

    /// A block computing `roots` (the last one is the tail) in a scope whose
    /// enclosing bindings are `bound`; `expected` is the tail's declared
    /// type.
    fn scope(&mut self, roots: &[NodeId], bound: &HashMap<NodeId, LocalId>, expected: &Ty) -> Result<Expr, String> {
        let tail_root = *roots.last().ok_or("an empty scope")?;
        // nodes evaluated in this scope (not inside arms), with use counts
        let mut uses: HashMap<NodeId, usize> = HashMap::new();
        let mut order: Vec<NodeId> = Vec::new();
        {
            let mut stack: Vec<(NodeId, bool)> = roots.iter().rev().map(|r| (*r, false)).collect();
            let mut done: HashSet<NodeId> = HashSet::new();
            while let Some((x, expanded)) = stack.pop() {
                if bound.contains_key(&x) {
                    continue;
                }
                if expanded {
                    if done.insert(x) {
                        order.push(x);
                    }
                    continue;
                }
                let c = uses.entry(x).or_insert(0);
                *c += 1;
                if *c > 1 {
                    continue;
                }
                stack.push((x, true));
                for ch in strict_children(&self.b.nodes[x].n).into_iter().rev() {
                    stack.push((ch, false));
                }
            }
        }
        // faults R3 / R14 (the must-reject suite): partial operations over
        // the parameters, or the arms of boolean selects, evaluated here,
        // before the guard that makes them defined
        let mut force: HashSet<NodeId> = HashSet::new();
        if let Some(fault) = self.b.fault
            && (fault == crate::opt::DriveFault::HoistPartial || fault == crate::opt::DriveFault::SelectPartial)
            && bound.is_empty()
        {
            let mut hoist: Vec<NodeId> = Vec::new();
            for x in self.all_below(tail_root).into_iter().collect::<std::collections::BTreeSet<_>>() {
                let n = self.b.nodes[x].n.clone();
                match (&n, fault) {
                    (N::Index(..), crate::opt::DriveFault::HoistPartial) | (N::Prim(PrimOpKey(PrimOp::Div(_) | PrimOp::Rem(_) | PrimOp::Add(_) | PrimOp::Sub(_) | PrimOp::Mul(_)), _), crate::opt::DriveFault::HoistPartial) => {
                        if self.only_params(x) {
                            hoist.push(x);
                        }
                    }
                    (N::Match { ind, arms, .. }, crate::opt::DriveFault::SelectPartial) if *ind == self.b.maps.bool_ => {
                        for a in arms {
                            let Body::Node(y) = a.body;
                            if !matches!(self.b.nodes[y].n, N::Match { .. }) && !Self::trivial(&self.b.nodes[y].n) && self.only_params(y) {
                                hoist.push(y);
                            }
                        }
                    }
                    _ => {}
                }
            }
            for x in hoist {
                if !order.contains(&x) {
                    // its operands first
                    let mut pre: Vec<NodeId> = Vec::new();
                    let mut st = strict_children(&self.b.nodes[x].n);
                    while let Some(c) = st.pop() {
                        if !order.contains(&c) && !pre.contains(&c) {
                            pre.push(c);
                            st.extend(strict_children(&self.b.nodes[c].n));
                        }
                    }
                    pre.reverse();
                    let at = 0;
                    for (k, c) in pre.into_iter().chain(std::iter::once(x)).enumerate() {
                        order.insert(at + k, c);
                    }
                    force.insert(x);
                }
            }
        }
        // nodes demanded below (inside arms of matches evaluated here)
        let mut below: HashSet<NodeId> = HashSet::new();
        for &x in &order {
            for a in arm_bodies(&self.b.nodes[x].n) {
                below.extend(self.all_below(a));
            }
        }
        let mut bound2 = bound.clone();
        let mut stmts = Vec::new();
        for &x in &order {
            if x == tail_root {
                continue;
            }
            let n = self.b.nodes[x].n.clone();
            if Self::trivial(&n) {
                continue;
            }
            let bind = Self::must_bind(&n) || uses.get(&x).copied().unwrap_or(0) > 1 || below.contains(&x) || self.is_elem_base(x, &order) || force.contains(&x);
            if !bind {
                continue;
            }
            let e = self.expr(x, &bound2)?;
            let ty = e.ty.clone();
            let l = LocalId(self.b.locals.len() as u32);
            self.b.locals.push(LocalDecl { name: format!("s{}", l.0), ty: ty.clone(), mutable: false, ghost: false, span: self.b.span });
            stmts.push(Stmt { kind: StmtKind::Let { pat: Pat { kind: PatKind::Binding { local: l, mode: BindingMode::ByValue, sub: None }, ty: ty.clone(), span: self.b.span }, init: e, els: None }, span: self.b.span });
            bound2.insert(x, l);
        }
        let tail = self.expr(tail_root, &bound2)?;
        let tail = self.adapt(tail, expected);
        if stmts.is_empty() {
            return Ok(tail);
        }
        let ty = tail.ty.clone();
        Ok(self.e(ExprKind::Block(Block { stmts, tail: Some(Box::new(tail)), span: self.b.span }), ty))
    }

    /// Whether node `x` depends only on the parameters (no arm field, no
    /// match): it can be evaluated at the top of the body.
    fn only_params(&self, x: NodeId) -> bool {
        let nparams = self.b.f.params.len() as u32;
        let mut st = vec![x];
        let mut seen = HashSet::new();
        while let Some(y) = st.pop() {
            if !seen.insert(y) {
                continue;
            }
            match &self.b.nodes[y].n {
                N::Var(l) if *l >= nparams => return false,
                N::Match { .. } => return false,
                n => st.extend(strict_children(n)),
            }
        }
        true
    }

    /// Array literals that are indexed are bound (as the straight-line
    /// residual does).
    fn is_elem_base(&self, x: NodeId, order: &[NodeId]) -> bool {
        matches!(self.b.nodes[x].n, N::ArrayLit(_) | N::Assemble(_)) && order.iter().any(|y| matches!(self.b.nodes[*y].n, N::ElemRead(b, _) | N::Index(b, _) if b == x))
    }

    /// Adapts a value expression to a declared type (`&T` expected: `&e`).
    fn adapt(&self, e: Expr, expected: &Ty) -> Expr {
        match expected {
            Ty::Ref(inner) if e.ty == **inner => {
                let t = expected.clone();
                self.e(ExprKind::Ref(Box::new(e)), t)
            }
            _ => e,
        }
    }

    /// Auto-dereferences a reference expression to its value (place).
    fn deref_all(&self, mut e: Expr) -> Expr {
        while let Ty::Ref(inner) = e.ty.clone() {
            e = self.e(ExprKind::Coerce(Coercion::AutoDeref, Box::new(e)), *inner);
        }
        e
    }

    fn var_expr(&self, l: u32) -> Result<Expr, String> {
        let info = self.b.vars.get(&l).ok_or("an unknown variable")?.clone();
        let local = info.local.ok_or("a variable without a local")?;
        let e = self.e(ExprKind::Local(local), info.decl.clone());
        // references are auto-dereferenced to their value, except slices
        Ok(match info.decl.peel_refs() {
            Ty::Slice(_) => {
                let mut e = e;
                while let Ty::Ref(inner) = e.ty.clone() {
                    if matches!(*inner, Ty::Slice(_)) {
                        break;
                    }
                    e = self.e(ExprKind::Coerce(Coercion::AutoDeref, Box::new(e)), *inner);
                }
                e
            }
            _ => self.deref_all(e),
        })
    }

    fn expr(&mut self, i: NodeId, bound: &HashMap<NodeId, LocalId>) -> Result<Expr, String> {
        if let Some(l) = bound.get(&i) {
            let ty = self.b.locals[l.0 as usize].ty.clone();
            return Ok(self.e(ExprKind::Local(*l), ty));
        }
        let n = self.b.nodes[i].n.clone();
        let ty = self.b.nodes[i].ty.clone();
        Ok(match n {
            N::Lit(_, v) => self.e(ExprKind::Lit(Lit::Int(v)), ty),
            N::Bool(v) => self.e(ExprKind::Lit(Lit::Bool(v)), ty),
            N::Var(l) => self.var_expr(l)?,
            N::ElemRead(x, k) => {
                let base = self.expr(x, bound)?;
                let base = self.deref_all(base);
                let idx = self.e(ExprKind::Lit(Lit::Int(k as u128)), Ty::usize());
                self.e(ExprKind::Index { base: Box::new(base), index: Box::new(idx) }, ty)
            }
            N::Index(x, k) => {
                let base = self.expr(x, bound)?;
                let base = self.deref_all(base);
                let idx = self.expr(k, bound)?;
                self.e(ExprKind::Index { base: Box::new(base), index: Box::new(idx) }, ty)
            }
            N::SubSlice(s, lo, hi) => {
                let base = self.expr(s, bound)?;
                let base = self.deref_all(base);
                let lo = lo.map(|x| self.expr(x, bound)).transpose()?.map(Box::new);
                let hi = hi.map(|x| self.expr(x, bound)).transpose()?.map(Box::new);
                self.e(ExprKind::SliceRange { base: Box::new(base), lo, hi }, ty)
            }
            N::Len(s) => {
                let recv = self.expr(s, bound)?;
                let et = match &recv.ty {
                    Ty::Ref(t) => match &**t {
                        Ty::Slice(e) => (**e).clone(),
                        _ => return Err("`len` of a non-slice".into()),
                    },
                    _ => return Err("`len` of a non-slice".into()),
                };
                self.e(ExprKind::Call { callee: Callee::Builtin(Builtin::Slice(SliceMethod::Len), vec![et]), args: vec![recv] }, ty)
            }
            N::Field(x, k) => {
                let base = self.expr(x, bound)?;
                let base = self.deref_all(base);
                let (fty, name) = match &base.ty {
                    Ty::Tuple(ts) => (ts.get(k as usize).cloned().ok_or("tuple field")?, None),
                    Ty::Adt(item, args) => match &self.b.krate.item(*item).kind {
                        ItemKind::Struct(s) => {
                            let fd = s.fields.get(k as usize).ok_or("struct field")?;
                            (fd.ty.subst(args), fd.name.clone())
                        }
                        _ => return Err("a projection of an enum".into()),
                    },
                    _ => return Err("a projection of a non-struct".into()),
                };
                let e = self.e(ExprKind::Field { base: Box::new(base), index: k, name }, fty.clone());
                match fty.peel_refs() {
                    Ty::Slice(_) => e,
                    _ => self.deref_all(e),
                }
            }
            N::ArrayLit(xs) => {
                let es = xs.iter().map(|x| self.expr(*x, bound)).collect::<Result<Vec<_>, _>>()?;
                self.e(ExprKind::Array(es), ty)
            }
            N::Assemble(ps) => {
                use assemble::{Part, Piece, Src};
                let Ty::Array(et, n) = &ty else { return Err("an assembled array of a non-array type".into()) };
                let (et, n) = ((**et).clone(), *n);
                let mut parts = Vec::new();
                let mut off = 0;
                for p in &ps {
                    let len = p.len();
                    match p {
                        Piece::Copy { base, lo, n: k } => {
                            let v = self.expr(*base, bound)?;
                            let v = self.deref_all(v);
                            let whole = *lo == 0 && matches!(&v.ty, Ty::Array(_, m) if m == k);
                            parts.push((off, len, Part::Slice(if whole { Src::Whole(v) } else { Src::Range(v, *lo, lo + k) })));
                        }
                        Piece::Bytes { x, w, be } => {
                            let v = self.expr(*x, bound)?;
                            parts.push((off, len, Part::Slice(Src::Bytes(v, *w, *be))));
                        }
                        Piece::Elem(x) => {
                            let v = self.expr(*x, bound)?;
                            parts.push((off, len, Part::Elem(v)));
                        }
                        Piece::Zero(_) => {}
                    }
                    off += len;
                }
                assemble::block(self.b.span, &mut self.b.locals, &et, n, parts)
            }
            N::Tuple(xs) => {
                let Ty::Tuple(ts) = &ty else { return Err("a tuple of a non-tuple type".into()) };
                let ts = ts.clone();
                let mut es = Vec::new();
                for (x, t) in xs.iter().zip(&ts) {
                    let e = self.expr(*x, bound)?;
                    es.push(self.adapt(e, t));
                }
                self.e(ExprKind::Tuple(es), ty)
            }
            N::Some(x) => {
                let Ty::Option(t) = &ty else { return Err("`Some` of a non-option type".into()) };
                let t = (**t).clone();
                let inner = self.expr(x, bound)?;
                let inner = self.adapt(inner, &t);
                self.e(ExprKind::Adt { ctor: Ctor::Some, ty_args: vec![t], fields: vec![(0, inner)], base: None }, ty)
            }
            N::None(_) => {
                let Ty::Option(t) = &ty else { return Err("`None` of a non-option type".into()) };
                let t = (**t).clone();
                self.e(ExprKind::Adt { ctor: Ctor::None, ty_args: vec![t], fields: vec![], base: None }, ty)
            }
            N::Struct(item, xs) => {
                let es = xs.iter().map(|x| self.expr(*x, bound)).collect::<Result<Vec<_>, _>>()?;
                let ItemKind::Struct(s) = &self.b.krate.item(item).kind else { return Err("not a struct".into()) };
                let fields = es.into_iter().zip(&s.fields).enumerate().map(|(k, (e, fd))| (k as u32, self.adapt(e, &fd.ty))).collect();
                self.e(ExprKind::Adt { ctor: Ctor::Struct(item), ty_args: vec![], fields, base: None }, ty)
            }
            N::Enum(item, v, xs) => {
                let es = xs.iter().map(|x| self.expr(*x, bound)).collect::<Result<Vec<_>, _>>()?;
                let ItemKind::Enum(en) = &self.b.krate.item(item).kind else { return Err("not an enum".into()) };
                let var = en.variants.get(v as usize).ok_or("variant")?;
                let fields = es.into_iter().zip(&var.fields).enumerate().map(|(k, (e, fd))| (k as u32, self.adapt(e, &fd.ty))).collect();
                self.e(ExprKind::Adt { ctor: Ctor::Variant(item, v), ty_args: vec![], fields, base: None }, ty)
            }
            N::Prim(PrimOpKey(op), xs) => {
                let es = xs.iter().map(|x| self.expr(*x, bound)).collect::<Result<Vec<_>, _>>()?;
                prim_expr(self.b.span, op, es, ty)?
            }
            N::Intrinsic(id, imms, xs) => {
                let info = intrinsics::get(id);
                let es = xs.iter().zip(&info.params).map(|(x, pt)| self.expr(*x, bound).map(|e| self.adapt(e, pt))).collect::<Result<Vec<_>, _>>()?;
                self.e(ExprKind::Call { callee: Callee::Intrinsic(id, imms), args: es }, ty)
            }
            N::Helper(h, xs) => {
                let info = intrinsics::helper(h);
                let es = xs.iter().zip(&info.params).map(|(x, pt)| self.expr(*x, bound).map(|e| self.adapt(e, pt))).collect::<Result<Vec<_>, _>>()?;
                self.e(ExprKind::Call { callee: Callee::Helper(h), args: es }, ty)
            }
            N::BoolAs(w, x) => {
                let a = self.expr(x, bound)?;
                self.e(ExprKind::Cast(Box::new(a), Ty::Uint(w)), ty)
            }
            N::BoolNot(x) => {
                let a = self.expr(x, bound)?;
                self.e(ExprKind::Unary(UnOp::Not, Box::new(a)), ty)
            }
            N::FromLe(w, x) => {
                let a = self.expr(x, bound)?;
                self.e(ExprKind::Call { callee: Callee::Builtin(Builtin::Int(IntMethod::FromLeBytes, w), vec![]), args: vec![a] }, ty)
            }
            N::IntCall(m, w, xs) => {
                let mut args = Vec::new();
                for x in xs {
                    args.push(self.expr(x, bound)?);
                }
                self.e(ExprKind::Call { callee: Callee::Builtin(Builtin::Int(m, w), vec![]), args }, ty)
            }
            N::Ghost(g) => self.ghost_expr(&g, bound)?,
            N::Call(item, targs, xs) => {
                let f = self.b.krate.fn_def(item).ok_or("callee is not a function")?.clone();
                let mut es = Vec::new();
                for (x, p) in xs.iter().zip(&f.params) {
                    let e = self.expr(*x, bound)?;
                    es.push(self.adapt(e, &p.ty.subst(&targs)));
                }
                let ret = f.ret.subst(&targs);
                let call = self.e(ExprKind::Call { callee: Callee::Item(item, targs), args: es }, ret.clone());
                match ret.peel_refs() {
                    Ty::Slice(_) => call,
                    _ => self.deref_all(call),
                }
            }
            N::Builtin(m, t, xs) => {
                let es = xs.iter().map(|x| self.expr(*x, bound)).collect::<Result<Vec<_>, _>>()?;
                self.e(ExprKind::Call { callee: Callee::Builtin(Builtin::Slice(m), vec![t]), args: es }, ty)
            }
            N::ArrayEq(a, b) => {
                let (x, y) = (self.expr(a, bound)?, self.expr(b, bound)?);
                self.e(ExprKind::Binary(BinOp::Eq, Box::new(x), Box::new(y)), ty)
            }
            N::Match { scrut, ind, arms } => self.match_expr(scrut, ind, &arms, &ty, bound)?,
            N::Bind { var, value, body } => {
                let init = self.expr(value, bound)?;
                let info = self.b.vars.get(&var).cloned().ok_or("an unbound join variable")?;
                let local = info.local.ok_or("a join variable without a local")?;
                let decl = info.decl.clone();
                let init = self.adapt(init, &decl);
                let tail = self.scope(&[body], bound, &ty)?;
                let span = self.b.span;
                let stmt = Stmt { kind: StmtKind::Let { pat: Pat { kind: PatKind::Binding { local, mode: BindingMode::ByValue, sub: None }, ty: decl, span }, init, els: None }, span };
                self.e(ExprKind::Block(Block { stmts: vec![stmt], tail: Some(Box::new(tail)), span }), ty)
            }
        })
    }

    /// A ghost argument (§15.3) as a ghost `Int` expression.
    fn ghost_expr(&mut self, g: &G, bound: &HashMap<NodeId, LocalId>) -> Result<Expr, String> {
        let bin = |this: &mut Self, op: BinOp, a: &G, b: &G, bound: &HashMap<NodeId, LocalId>| -> Result<Expr, String> {
            let (x, y) = (this.ghost_expr(a, bound)?, this.ghost_expr(b, bound)?);
            Ok(this.e(ExprKind::Binary(op, Box::new(x), Box::new(y)), Ty::Int))
        };
        Ok(match g {
            G::Lit(n) => {
                let m = n.magnitude().to_u128().ok_or("a ghost literal out of range")?;
                let lit = self.e(ExprKind::Lit(Lit::Int(m)), Ty::Int);
                if n.sign() == num_bigint::Sign::Minus { self.e(ExprKind::Unary(UnOp::Neg, Box::new(lit)), Ty::Int) } else { lit }
            }
            G::Of(x) => {
                let a = self.expr(*x, bound)?;
                self.e(ExprKind::Cast(Box::new(a), Ty::Int), Ty::Int)
            }
            G::Add(a, b) => bin(self, BinOp::Add, a, b, bound)?,
            G::Sub(a, b) => bin(self, BinOp::Sub, a, b, bound)?,
            G::Mul(a, b) => bin(self, BinOp::Mul, a, b, bound)?,
        })
    }

    fn match_expr(&mut self, scrut: NodeId, ind: IndId, arms: &[MArm], ty: &Ty, bound: &HashMap<NodeId, LocalId>) -> Result<Expr, String> {
        let s = self.expr(scrut, bound)?;
        let mut bodies = Vec::new();
        for a in arms {
            let Body::Node(b) = a.body;
            let e = self.scope(&[b], bound, ty)?;
            bodies.push(e);
        }
        if ind == self.b.maps.bool_ {
            // arms in constructor order: false, true
            let (f, t) = (bodies.remove(0), bodies.remove(0));
            return Ok(self.e(ExprKind::If { cond: Box::new(s), then: Box::new(block(t)), els: Some(Box::new(block(f))) }, ty.clone()));
        }
        let sty = s.ty.clone();
        let mut harms = Vec::new();
        for (a, body) in arms.iter().zip(bodies) {
            let pat = self.pattern(&sty, ind, a)?;
            harms.push(Arm { pat, guard: None, body, span: self.b.span });
        }
        Ok(self.e(ExprKind::Match { scrut: Box::new(s), arms: harms, source: MatchSource::Match }, ty.clone()))
    }

    /// The pattern of an arm: the constructor with a binding per relevant
    /// field.
    fn pattern(&mut self, sty: &Ty, ind: IndId, a: &MArm) -> Result<Pat, String> {
        let span = self.b.span;
        let bind = |this: &Self, l: u32| -> Result<Pat, String> {
            let info = this.b.vars.get(&l).ok_or("an unbound field")?;
            Ok(Pat { kind: PatKind::Binding { local: info.local.ok_or("field without local")?, mode: BindingMode::ByValue, sub: None }, ty: info.decl.clone(), span })
        };
        let fields: Vec<Pat> = a.fields.iter().flatten().map(|l| bind(self, *l)).collect::<Result<_, _>>()?;
        let kind = match sty.peel_refs() {
            Ty::Option(t) => {
                if a.ctor == 0 {
                    PatKind::Ctor { ctor: Ctor::None, ty_args: vec![(**t).clone()], fields: vec![] }
                } else {
                    PatKind::Ctor { ctor: Ctor::Some, ty_args: vec![(**t).clone()], fields: fields.into_iter().enumerate().map(|(k, p)| (k as u32, p)).collect() }
                }
            }
            Ty::Tuple(_) => PatKind::Tuple(fields),
            Ty::Adt(item, _) => {
                let ctor = match &self.b.krate.item(*item).kind {
                    ItemKind::Struct(_) => Ctor::Struct(*item),
                    ItemKind::Enum(_) => Ctor::Variant(*item, a.ctor),
                    _ => return Err("a pattern of a non-ADT".into()),
                };
                PatKind::Ctor { ctor, ty_args: vec![], fields: fields.into_iter().enumerate().map(|(k, p)| (k as u32, p)).collect() }
            }
            _ => return Err(format!("a match on a value of type `{}` (inductive {ind:?})", self.b.krate.ty_str(sty))),
        };
        // a reference scrutinee is matched through an implicit dereference
        let inner = Pat { kind, ty: sty.peel_refs().clone(), span };
        Ok(if matches!(sty, Ty::Ref(_)) { Pat { kind: PatKind::Deref { pat: Box::new(inner), implicit: true }, ty: sty.clone(), span } } else { inner })
    }
}

/// A block expression around `e` (the branches of an `if`).
fn block(e: Expr) -> Expr {
    if matches!(e.kind, ExprKind::Block(_)) {
        return e;
    }
    let (ty, span) = (e.ty.clone(), e.span);
    Expr::new(ExprKind::Block(Block { stmts: vec![], tail: Some(Box::new(e)), span }), ty, span)
}

/// A primitive as an operator or method (the parent module's printing).
fn prim_expr(span: Span, op: PrimOp, args: Vec<Expr>, ty: Ty) -> Result<Expr, String> {
    use PrimOp::*;
    let e = |kind: ExprKind, ty: Ty| Expr::new(kind, ty, span);
    let w = |w: Width| uint_of(w).ok_or_else(|| "ghost width".to_string());
    let method = |m: IntMethod, u: UintTy, args: Vec<Expr>, ty: Ty| e(ExprKind::Call { callee: Callee::Builtin(Builtin::Int(m, u), vec![]), args }, ty);
    let bin = |o: BinOp, mut args: Vec<Expr>, ty: Ty| {
        let b = args.pop().unwrap();
        let a = args.pop().unwrap();
        e(ExprKind::Binary(o, Box::new(a), Box::new(b)), ty)
    };
    Ok(match op {
        WAdd(x) => method(IntMethod::WrappingAdd, w(x)?, args, ty),
        WSub(x) => method(IntMethod::WrappingSub, w(x)?, args, ty),
        WMul(x) => method(IntMethod::WrappingMul, w(x)?, args, ty),
        WNeg(x) => method(IntMethod::WrappingNeg, w(x)?, args, ty),
        WShl(x) => method(IntMethod::WrappingShl, w(x)?, args, ty),
        WShr(x) => method(IntMethod::WrappingShr, w(x)?, args, ty),
        Rotl(x) => method(IntMethod::RotateLeft, w(x)?, args, ty),
        Rotr(x) => method(IntMethod::RotateRight, w(x)?, args, ty),
        Min(x) => method(IntMethod::Min, w(x)?, args, ty),
        Max(x) => method(IntMethod::Max, w(x)?, args, ty),
        SatAdd(x) => method(IntMethod::SaturatingAdd, w(x)?, args, ty),
        SatSub(x) => method(IntMethod::SaturatingSub, w(x)?, args, ty),
        SatMul(x) => method(IntMethod::SaturatingMul, w(x)?, args, ty),
        CountOnes(x) => method(IntMethod::CountOnes, w(x)?, args, ty),
        LeadingZeros(x) => method(IntMethod::LeadingZeros, w(x)?, args, ty),
        TrailingZeros(x) => method(IntMethod::TrailingZeros, w(x)?, args, ty),
        SwapBytes(x) => method(IntMethod::SwapBytes, w(x)?, args, ty),
        And(_) => bin(BinOp::BitAnd, args, ty),
        Or(_) => bin(BinOp::BitOr, args, ty),
        Xor(_) => bin(BinOp::BitXor, args, ty),
        Not(_) => {
            let a = args.into_iter().next().unwrap();
            e(ExprKind::Unary(UnOp::Not, Box::new(a)), ty)
        }
        Eq(_) => bin(BinOp::Eq, args, ty),
        Ne(_) => bin(BinOp::Ne, args, ty),
        Lt(_) => bin(BinOp::Lt, args, ty),
        Le(_) => bin(BinOp::Le, args, ty),
        Gt(_) => bin(BinOp::Gt, args, ty),
        Ge(_) => bin(BinOp::Ge, args, ty),
        Add(_) => bin(BinOp::Add, args, ty),
        Sub(_) => bin(BinOp::Sub, args, ty),
        Mul(_) => bin(BinOp::Mul, args, ty),
        Div(_) => bin(BinOp::Div, args, ty),
        Rem(_) => bin(BinOp::Rem, args, ty),
        Shl(_) => bin(BinOp::Shl, args, ty),
        Shr(_) => bin(BinOp::Shr, args, ty),
        Cast { .. } => {
            let a = args.into_iter().next().unwrap();
            e(ExprKind::Cast(Box::new(a), ty.clone()), ty)
        }
        other => return Err(format!("primitive {other:?} cannot be printed")),
    })
}
