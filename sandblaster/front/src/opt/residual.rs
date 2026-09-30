//! Residualization (DESIGN.md §8.2.1): the value DAG of a symbolic
//! execution becomes a straight-line HIR function in the canonical dialect.
//!
//! The DAG is hash-consed structurally (two nodes with the same head and
//! the same children are one node, so a value recomputed by the evaluator —
//! the `W + K` operand of `SHA256H` and `SHA256H2`, the four reads of one
//! `store_u32x4` result — is computed once). Nodes used more than once,
//! intrinsic / helper / call results and arrays that are indexed are bound
//! by `let` in topological order; everything else is inlined. Every node
//! has a HIR type computed from its head (literal widths, primitive result
//! widths, intrinsic and helper signatures, callee return types).
//!
//! The result is ordinary HIR: the optimizer elaborates it with the normal
//! elaborator (every proof slot re-proven by the prover chain in the
//! residual's own context, §8.2.1), admits it with
//! `Env::check_residual_equal`, and the canonical printer prints it. What
//! the printer prints is therefore exactly what was checked, and the round
//! trip (§8.3) re-elaborates the printed text and compares.
//!
//! Supported residual nodes (anything else makes the residual
//! unprintable, and the function stays unspecialized): machine literals,
//! booleans, parameters, element reads `p[k]` at literal indices (of array
//! parameters, spine-expanded, and of let-bound arrays), array literals,
//! tuples, `Some`/`None`, total primitives (as operators or `uN` methods),
//! checked arithmetic (its obligation is re-proven), casts between machine
//! widths, `uN::from_le_bytes`, intrinsic calls (immediates first),
//! load/store helper calls, and calls of user functions kept opaque.

mod assemble;
pub mod tree;

use std::collections::HashMap;
use std::rc::Rc;

use num_traits::ToPrimitive;
use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{GlobalId, IndId, PrimOp, Width};
use sandblaster_kernel::value::{Arg, Elim, Head, V, Value};

use crate::builtins::{Builtin, IntMethod};
use crate::hir::*;
use crate::intrinsics::{self, HelperId, IntrinsicId};
use crate::span::Span;

/// How kernel globals print back (built once per environment).
pub struct Maps {
    pub intrinsics: HashMap<GlobalId, IntrinsicId>,
    pub helpers: HashMap<GlobalId, HelperId>,
    /// User functions (exec items) by their kernel global.
    pub items: HashMap<GlobalId, ItemId>,
    /// `u16/u32/u64::from_le_bytes`.
    pub from_le: HashMap<GlobalId, UintTy>,
    pub index: GlobalId,
    pub bool_: IndId,
    pub option: IndId,
    pub list: IndId,
    /// Tuple inductives and their arity.
    pub tuples: HashMap<IndId, usize>,
    /// User structs.
    pub adts: HashMap<IndId, ItemId>,
}

impl Maps {
    /// Builds the tables for the target architecture of `krate`.
    pub fn new(env: &Env, krate: &Crate, fn_globals: &HashMap<ItemId, GlobalId>, adts: &HashMap<ItemId, IndId>) -> Result<Maps, String> {
        let arch = krate.target.arch.name();
        let mut intr = HashMap::new();
        for info in intrinsics::table() {
            if info.arch.name() != arch || info.pointer_args {
                continue;
            }
            if let Some(g) = env.lookup_global(&format!("{arch}::{}", info.name)) {
                intr.insert(g, info.id);
            }
        }
        let mut helpers = HashMap::new();
        for (i, h) in intrinsics::helpers().iter().enumerate() {
            if h.arch.name() != arch {
                continue;
            }
            let direct = format!("{arch}::{}", h.name);
            let via = h.template.split(&format!("::core::arch::{arch}::")).nth(1).map(|r| r.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect::<String>()).map(|n| format!("{arch}::{n}"));
            let g = env.lookup_global(&direct).or_else(|| via.and_then(|v| env.lookup_global(&v)));
            if let Some(g) = g {
                helpers.entry(g).or_insert(HelperId(i as u32));
            }
        }
        let mut from_le = HashMap::new();
        for w in [UintTy::U16, UintTy::U32, UintTy::U64] {
            if let Some(g) = env.lookup_global(&format!("{}::from_le_bytes", w.name())) {
                from_le.insert(g, w);
            }
        }
        // exec functions, and the lift's buffer model that the driver keeps
        // folded (`drive::KEPT_LIFT_MODEL`: lowered back to buffer calls)
        let items = fn_globals
            .iter()
            .filter(|(id, _)| {
                let it = krate.item(**id);
                match &it.kind {
                    ItemKind::Fn(f) if f.kind == FnKind::Exec => true,
                    ItemKind::Fn(_) => it.path.0.first().is_some_and(|m| m == "__lift_model") && crate::opt::drive::KEPT_LIFT_MODEL.contains(&it.path.to_string().as_str()),
                    _ => false,
                }
            })
            .map(|(id, g)| (*g, *id))
            .collect();
        let look = |n: &str| env.lookup_ind(n).ok_or_else(|| format!("prelude inductive `{n}` is missing"));
        let mut tuples = HashMap::new();
        for n in 1..=12usize {
            if let Some(i) = env.lookup_ind(&format!("Tuple{n}")) {
                tuples.insert(i, n);
            }
        }
        let adts = adts.iter().map(|(id, i)| (*i, *id)).collect();
        Ok(Maps {
            intrinsics: intr,
            helpers,
            items,
            from_le,
            index: env.lookup_global("seq::index").ok_or("prelude `seq::index` is missing")?,
            bool_: env.bool_ind(),
            option: look("Option")?,
            list: look("List")?,
            tuples,
            adts,
        })
    }
}

type NodeId = usize;

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
enum N {
    Lit(UintTy, u128),
    Bool(bool),
    /// A scalar (non-array) parameter, by parameter index.
    Param(usize),
    /// An array parameter as a whole (spine-expanded in the kernel).
    ParamArray(usize),
    ElemRead(NodeId, u64),
    ArrayLit(Vec<NodeId>),
    /// An array literal printed as the buffer it was built as
    /// ([`assemble`]).
    Assemble(Vec<assemble::Piece>),
    Tuple(Vec<NodeId>),
    Some(NodeId),
    None,
    Struct(ItemId, Vec<NodeId>),
    Prim(PrimOpKey, Vec<NodeId>),
    Intrinsic(IntrinsicId, Vec<i64>, Vec<NodeId>),
    Helper(HelperId, Vec<NodeId>),
    FromLe(UintTy, NodeId),
    Call(ItemId, Vec<Ty>, Vec<NodeId>),
    /// The argument of a callee's `#[ghost]` parameter (§15.3): a ghost
    /// `Int` expression over exec nodes, never bound, erased from the
    /// printed code with the parameter.
    Ghost(GArg),
}

/// A ghost `Int` expression (see [`N::Ghost`]).
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
enum GArg {
    Lit(sandblaster_kernel::term::BigInt),
    /// An exec value widened: `x as Int`.
    Of(NodeId),
    Add(Box<GArg>, Box<GArg>),
    Sub(Box<GArg>, Box<GArg>),
    Mul(Box<GArg>, Box<GArg>),
}

impl GArg {
    fn nodes(&self, out: &mut Vec<NodeId>) {
        match self {
            GArg::Lit(_) => {}
            GArg::Of(x) => out.push(*x),
            GArg::Add(a, b) | GArg::Sub(a, b) | GArg::Mul(a, b) => {
                a.nodes(out);
                b.nodes(out);
            }
        }
    }
}

/// `PrimOp` with a hashable, comparable key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct PrimOpKey(PrimOp);

struct Node {
    n: N,
    /// HIR type (references stripped).
    ty: Ty,
    uses: usize,
    /// Let-bound local, once emitted.
    local: Option<LocalId>,
    /// The local holds a reference to the node's value (an unsized value,
    /// a slice, is bound by its reference: `let s: &[T] = f(..)`), read
    /// through an auto-deref.
    by_ref: bool,
}

/// The residual under construction.
struct Builder<'a> {
    env: &'a Env,
    maps: &'a Maps,
    krate: &'a Crate,
    f: &'a FnDef,
    /// Kernel level of each HIR parameter (type parameters come first).
    ngen: usize,
    nodes: Vec<Node>,
    by_key: HashMap<N, NodeId>,
    by_ptr: HashMap<*const Value, NodeId>,
    keep: Vec<V>,
    /// The element nodes of each assembled array (to print it as a literal
    /// where it feeds a vector load).
    assembled: HashMap<NodeId, Vec<NodeId>>,
    /// Element reads of elements of array parameters (`p[l][k]`; the lane
    /// kernels of plan O10 only).
    nested_reads: bool,
}

/// A straight-line residual as HIR.
pub struct Residual {
    pub body: Expr,
    pub locals: Vec<LocalDecl>,
    /// Distinct residual nodes (after hash-consing).
    pub nodes: usize,
}

fn uint_of(w: Width) -> Option<UintTy> {
    Some(match w {
        Width::U8 => UintTy::U8,
        Width::U16 => UintTy::U16,
        Width::U32 => UintTy::U32,
        Width::U64 => UintTy::U64,
        Width::Usize => UintTy::Usize,
        Width::Int => return None,
    })
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

impl<'a> Builder<'a> {
    fn add(&mut self, n: N, ty: Ty) -> NodeId {
        if let Some(i) = self.by_key.get(&n) {
            return *i;
        }
        let i = self.nodes.len();
        self.nodes.push(Node { n: n.clone(), ty, uses: 0, local: None, by_ref: false });
        self.by_key.insert(n, i);
        i
    }

    fn rel_args(args: &[Arg]) -> Vec<V> {
        args.iter().filter_map(|a| if let Arg::Rel(v) = a { Some(v.clone()) } else { None }).collect()
    }

    fn param_ty(&self, p: usize) -> Ty {
        self.f.params[p].ty.peel_refs().clone()
    }

    /// The HIR node of a value (see the module docs).
    fn node(&mut self, v: &V) -> Result<NodeId, String> {
        if let Some(i) = self.by_ptr.get(&Rc::as_ptr(v)) {
            return Ok(*i);
        }
        let id = self.node_uncached(v)?;
        self.by_ptr.insert(Rc::as_ptr(v), id);
        self.keep.push(v.clone());
        Ok(id)
    }

    fn node_uncached(&mut self, v: &V) -> Result<NodeId, String> {
        match &**v {
            Value::Lit { w, n } => {
                let u = uint_of(*w).ok_or("a ghost `Int` value in the residual")?;
                let n = n.to_u128().ok_or("literal out of range")?;
                Ok(self.add(N::Lit(u, n), Ty::Uint(u)))
            }
            Value::Ctor { ind, ctor, params, args } => {
                let rel = Self::rel_args(args);
                if *ind == self.maps.bool_ {
                    return Ok(self.add(N::Bool(*ctor == 1), Ty::Bool));
                }
                if *ind == self.maps.option {
                    return match *ctor {
                        0 => {
                            let t = params.first().map(|p| self.ty_of_type_value(p)).transpose()?.ok_or("`None` without a type")?;
                            Ok(self.add(N::None, Ty::option(t)))
                        }
                        _ => {
                            let x = self.node(&rel[0])?;
                            let t = self.nodes[x].ty.clone();
                            Ok(self.add(N::Some(x), Ty::option(t)))
                        }
                    };
                }
                if let Some(n) = self.maps.tuples.get(ind).copied() {
                    let ids = rel.iter().map(|x| self.node(x)).collect::<Result<Vec<_>, _>>()?;
                    if ids.len() != n {
                        return Err("tuple arity mismatch".into());
                    }
                    let t = Ty::Tuple(ids.iter().map(|i| self.nodes[*i].ty.clone()).collect());
                    return Ok(self.add(N::Tuple(ids), t));
                }
                if let Some(item) = self.maps.adts.get(ind).copied() {
                    let ItemKind::Struct(s) = &self.krate.item(item).kind else { return Err("enum values in residuals are not supported".into()) };
                    if !s.generics.is_empty() {
                        return Err("generic structs in residuals are not supported".into());
                    }
                    let ids = rel.iter().map(|x| self.node(x)).collect::<Result<Vec<_>, _>>()?;
                    return Ok(self.add(N::Struct(item, ids), Ty::Adt(item, vec![])));
                }
                Err("a list or other inductive value in the residual".into())
            }
            Value::Pair { fst, .. } => {
                // an array value: `(list, proof)`; `(fst x, _)` is `x`
                if let Value::Neu(n) = &**fst
                    && matches!(n.spine.last(), Some(Elim::Fst))
                {
                    return Err("an array passed through as a whole (neutral pair)".into());
                }
                let mut elems = Vec::new();
                let mut cur = fst.clone();
                loop {
                    let next = match &*cur {
                        Value::Ctor { ind, ctor: 0, .. } if *ind == self.maps.list => break,
                        Value::Ctor { ind, ctor: 1, args, .. } if *ind == self.maps.list => {
                            let rel = Self::rel_args(args);
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
                // the spine expansion of an array parameter is the parameter
                if let Some(p) = self.whole_param(&elems) {
                    return Ok(self.add(N::ParamArray(p), self.param_ty(p)));
                }
                let ids = elems.iter().map(|x| self.node(x)).collect::<Result<Vec<_>, _>>()?;
                let et = self.nodes[ids[0]].ty.clone();
                let n = ids.len() as u64;
                let shapes: Vec<assemble::Shape> = ids.iter().map(|i| self.elem_shape(*i)).collect();
                if let Some(pieces) = assemble::plan(&ids, &shapes, matches!(et, Ty::Uint(_)), et == Ty::u8()) {
                    let a = self.add(N::Assemble(pieces), Ty::array(et, n));
                    self.assembled.insert(a, ids);
                    return Ok(a);
                }
                Ok(self.add(N::ArrayLit(ids), Ty::array(et, n)))
            }
            Value::Neu(n) => {
                if n.spine.iter().any(|e| !matches!(e, Elim::Fst | Elim::Snd)) {
                    return Err("an eliminator other than a projection in the residual".into());
                }
                match &n.head {
                    Head::Var(l) => {
                        if !n.spine.is_empty() {
                            return Err("a projection of a parameter outside an element read".into());
                        }
                        let p = (l.0 as usize).checked_sub(self.ngen).ok_or("a type parameter as a value")?;
                        if p >= self.f.params.len() {
                            return Err("a variable that is not a parameter".into());
                        }
                        Ok(self.add(N::Param(p), self.param_ty(p)))
                    }
                    Head::Prim { op, args, .. } => {
                        if !n.spine.is_empty() {
                            return Err("a projection of a primitive".into());
                        }
                        let ty = prim_result_ty(*op).ok_or_else(|| format!("primitive {op:?} cannot be printed"))?;
                        let ids = args.iter().map(|x| self.node(x)).collect::<Result<Vec<_>, _>>()?;
                        Ok(self.add(N::Prim(PrimOpKey(*op), ids), ty))
                    }
                    Head::Global { def, args } => {
                        let rel = Self::rel_args(args);
                        if *def == self.maps.index {
                            // index(T, fst x, k)
                            if rel.len() < 3 || !n.spine.is_empty() {
                                return Err("a partial list index".into());
                            }
                            let k = match &*rel[2] {
                                Value::Lit { n, .. } => n.to_u64().ok_or("negative index")?,
                                _ => return Err("an element read at a symbolic index".into()),
                            };
                            let base = self.array_base(&rel[1])?;
                            let et = match &self.nodes[base].ty {
                                Ty::Array(e, _) => (**e).clone(),
                                _ => return Err("an element read of a non-array".into()),
                            };
                            return Ok(self.add(N::ElemRead(base, k), et));
                        }
                        if !n.spine.is_empty() {
                            return Err(format!("a projection of `{}`", self.env.global_name(*def).map(|s| s.to_string()).unwrap_or_default()));
                        }
                        self.global_node(*def, &rel, args)
                    }
                    other => Err(format!("a stuck {} in the residual", super::symex::describe_head(self.env, other))),
                }
            }
            _ => Err("a type or function value in the residual".into()),
        }
    }

    /// An array passed to an intrinsic or a load/store helper: an
    /// assembled array goes back to its literal (its elements go to a
    /// vector register; building it in memory first would only add stores
    /// and a reload that cannot be forwarded from them).
    fn literal(&mut self, id: NodeId) -> NodeId {
        match self.assembled.get(&id).cloned() {
            Some(ids) if !assemble::has_bytes(&self.nodes[id].n_pieces()) => {
                let t = self.nodes[id].ty.clone();
                self.add(N::ArrayLit(ids), t)
            }
            _ => id,
        }
    }

    /// What an element of an array spine is, for [`assemble::plan`].
    fn elem_shape(&self, i: NodeId) -> assemble::Shape {
        use assemble::Shape;
        match &self.nodes[i].n {
            // (of an array parameter only: the kernel eta-expands array
            // variables, so a copy from one evaluates to the same spine; a
            // copy from a call's array result would stay a stuck append)
            N::ElemRead(b, k) if matches!(self.nodes[*b].ty, Ty::Array(..)) && matches!(self.nodes[*b].n, N::ParamArray(_)) => Shape::Read { base: *b, k: *k },
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

    /// `Some(p)` if the elements are exactly `index(fst p, 0..N)` of array
    /// parameter `p`.
    fn whole_param(&self, elems: &[V]) -> Option<usize> {
        let mut which = None;
        for (i, e) in elems.iter().enumerate() {
            let Value::Neu(n) = &**e else { return None };
            let Head::Global { def, args } = &n.head else { return None };
            if *def != self.maps.index || !n.spine.is_empty() {
                return None;
            }
            let rel = Self::rel_args(args);
            let Value::Lit { n: k, .. } = &*rel.get(2)?.clone() else { return None };
            if k.to_u64()? != i as u64 {
                return None;
            }
            let Value::Neu(m) = &*rel[1] else { return None };
            let (Head::Var(l), [Elim::Fst]) = (&m.head, m.spine.as_slice()) else { return None };
            let p = (l.0 as usize).checked_sub(self.ngen)?;
            if which.is_some_and(|w| w != p) {
                return None;
            }
            which = Some(p);
        }
        let p = which?;
        match self.f.params.get(p)?.ty.peel_refs() {
            Ty::Array(_, n) if *n as usize == elems.len() => Some(p),
            // hardware vectors are arrays of lanes (§9.2)
            Ty::Vector(v) if v.lanes().1 as usize == elems.len() => Some(p),
            _ => None,
        }
    }

    /// The array node whose list is `lv` (`fst x` of an array-typed
    /// neutral `x`).
    fn array_base(&mut self, lv: &V) -> Result<NodeId, String> {
        let Value::Neu(n) = &**lv else { return Err("an element read of a literal list".into()) };
        if !matches!(n.spine.last(), Some(Elim::Fst)) || n.spine.len() != 1 {
            return Err("an element read of an unexpected list".into());
        }
        match &n.head {
            Head::Var(l) => {
                let p = (l.0 as usize).checked_sub(self.ngen).ok_or("an element read of a type")?;
                if !matches!(self.f.params.get(p).map(|x| x.ty.peel_refs()), Some(Ty::Array(..))) {
                    return Err("an element read of a non-array parameter".into());
                }
                Ok(self.add(N::ParamArray(p), self.param_ty(p)))
            }
            // an element of an array of arrays (`p[l][k]`: a lane kernel's
            // parameter `&[[u8; 64]; 16]`, plan O10)
            Head::Global { def, args } if self.nested_reads && *def == self.maps.index => {
                let rel = Self::rel_args(args);
                let k = match rel.get(2).map(|v| &**v) {
                    Some(Value::Lit { n, .. }) => n.to_u64().ok_or("negative index")?,
                    _ => return Err("an element read at a symbolic index".into()),
                };
                let base = self.array_base(&rel[1])?;
                let et = match &self.nodes[base].ty {
                    Ty::Array(e, _) => (**e).clone(),
                    _ => return Err("an element read of a non-array".into()),
                };
                Ok(self.add(N::ElemRead(base, k), et))
            }
            Head::Global { def, args } => {
                let rel = Self::rel_args(args);
                self.global_node(*def, &rel, args)
            }
            _ => Err("an element read of an unsupported array".into()),
        }
    }

    /// A neutral application of a global (intrinsic, helper,
    /// `from_le_bytes`, or a user function kept opaque).
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
                let n = self.literal(n);
                ids.push(self.coerce_vec(n, pt)?);
            }
            return Ok(self.add(N::Intrinsic(id, imms, ids), info.ret.clone()));
        }
        if let Some(h) = self.maps.helpers.get(&def).copied() {
            let info = intrinsics::helper(h);
            if rel.len() != info.params.len() {
                return Err(format!("helper `{}` with an unexpected argument count", info.name));
            }
            let mut ids = Vec::new();
            for (x, pt) in rel.iter().zip(&info.params) {
                let n = self.node(x)?;
                let n = self.literal(n);
                ids.push(self.coerce_vec(n, pt.peel_refs())?);
            }
            return Ok(self.add(N::Helper(h, ids), info.ret.clone()));
        }
        if let Some(w) = self.maps.from_le.get(&def).copied() {
            let x = self.node(rel.first().ok_or("from_le_bytes without argument")?)?;
            return Ok(self.add(N::FromLe(w, x), Ty::Uint(w)));
        }
        if let Some(item) = self.maps.items.get(&def).copied() {
            let f = self.krate.fn_def(item).ok_or("callee is not a function")?;
            // type arguments come first (as type values)
            let ng = f.generics.len();
            // `#[ghost]` parameters (the last ones, §15.3) are one `Irr`
            // binder, the ghost bundle: their arguments are its components
            let nghost = f.params.iter().filter(|p| p.ghost).count();
            if rel.len() != ng + f.params.len() - nghost {
                return Err("callee argument count mismatch".into());
            }
            let ptys: Vec<Ty> = f.params.iter().filter(|p| !p.ghost).map(|p| p.ty.clone()).collect();
            let ret = f.ret.clone();
            let targs = rel[..ng].iter().map(|t| self.ty_of_type_value(t)).collect::<Result<Vec<_>, _>>()?;
            let mut ids = Vec::new();
            for (x, pt) in rel[ng..].iter().zip(&ptys) {
                let n = self.node(x)?;
                ids.push(self.coerce_vec(n, pt.subst(&targs).peel_refs())?);
            }
            if nghost > 0 {
                for g in self.ghost_args(def, args, nghost)? {
                    ids.push(self.add(N::Ghost(g), Ty::Int));
                }
            }
            let ret = ret.subst(&targs).peel_refs().clone();
            return Ok(self.add(N::Call(item, targs, ids), ret));
        }
        Err(format!("a stuck application of `{}`", self.env.global_name(def).map(|s| s.to_string()).unwrap_or_default()))
    }

    /// The arguments of the `nghost` `#[ghost]` parameters of the call
    /// `def args`: the components of its ghost bundle (the `Irr` binder
    /// named `ghost`, §15.3), evaluated, as ghost expressions.
    fn ghost_args(&mut self, def: GlobalId, args: &[Arg], nghost: usize) -> Result<Vec<GArg>, String> {
        let tele = super::symex::telescope(self.env, def).ok_or("a callee without a telescope")?;
        let at = tele.binders.iter().position(|(n, r, _)| &**n == "ghost" && *r == sandblaster_kernel::term::Rel::Irr).ok_or("a callee with `#[ghost]` parameters but no ghost bundle")?;
        let Some(Arg::Irr(c)) = args.get(at) else { return Err("the ghost bundle of a call is not an irrelevant argument".into()) };
        let mut out = Vec::with_capacity(nghost);
        for k in 0..nghost {
            // fst(snd^k(bundle))
            let mut t = c.body.clone();
            for _ in 0..k {
                t = std::rc::Rc::new(sandblaster_kernel::term::Term::Snd(t));
            }
            t = std::rc::Rc::new(sandblaster_kernel::term::Term::Fst(t));
            let mut b = sandblaster_kernel::value::Budget { steps: 1_000_000 };
            let v = self.env.eval(&c.env, sandblaster_kernel::term::Lvl(1 << 20), &t, &mut b).map_err(|e| format!("a ghost argument: {e:?}"))?;
            out.push(self.ghost_of(&v)?);
        }
        Ok(out)
    }

    /// A ghost `Int` value as a ghost expression over exec nodes.
    fn ghost_of(&mut self, v: &V) -> Result<GArg, String> {
        match &**v {
            Value::Lit { w: Width::Int, n } => Ok(GArg::Lit(n.clone())),
            Value::Neu(sandblaster_kernel::value::Neutral { head: Head::Prim { op, args, .. }, spine }) if spine.is_empty() => match (op, &args[..]) {
                (PrimOp::Cast { from, to: Width::Int }, [a]) if *from != Width::Int => Ok(GArg::Of(self.node(a)?)),
                (PrimOp::IAdd, [a, b]) => Ok(GArg::Add(Box::new(self.ghost_of(a)?), Box::new(self.ghost_of(b)?))),
                (PrimOp::ISub, [a, b]) => Ok(GArg::Sub(Box::new(self.ghost_of(a)?), Box::new(self.ghost_of(b)?))),
                (PrimOp::IMul, [a, b]) => Ok(GArg::Mul(Box::new(self.ghost_of(a)?), Box::new(self.ghost_of(b)?))),
                _ => Err(format!("a ghost argument the residual cannot print (primitive {op:?})")),
            },
            _ => Err("a ghost argument the residual cannot print".into()),
        }
    }

    /// A node used at a hardware vector type: a lane array (a constant
    /// vector, or lanes assembled from scalars) is loaded with the load
    /// helper of that vector type (§9.2: vector constants print as loads).
    fn coerce_vec(&mut self, id: NodeId, expected: &Ty) -> Result<NodeId, String> {
        let Ty::Vector(v) = expected else { return Ok(id) };
        if self.nodes[id].ty == *expected {
            return Ok(id);
        }
        let id = self.literal(id);
        let (lane, n) = v.lanes();
        if self.nodes[id].ty != Ty::array(Ty::Uint(lane), n) {
            return Err(format!("a value of type `{}` used as `{}`", self.krate.ty_str(&self.nodes[id].ty), v.rust_name()));
        }
        let arch = v.arch();
        // a constant 256/512-bit vector (plan O10, the lane kernels'
        // constants): printed as the load of its little-endian u32 lanes
        if let (UintTy::U8, 32 | 64) = (lane, n)
            && let N::ArrayLit(ids) = self.nodes[id].n.clone()
            && let Some(bytes) = ids.iter().map(|i| if let N::Lit(UintTy::U8, b) = self.nodes[*i].n { Some(b as u32) } else { None }).collect::<Option<Vec<u32>>>()
        {
            let words: Vec<NodeId> = bytes.chunks(4).map(|c| self.add(N::Lit(UintTy::U32, u128::from(c[0] | c[1] << 8 | c[2] << 16 | c[3] << 24)), Ty::u32())).collect();
            let wn = words.len() as u64;
            let arr = self.add(N::ArrayLit(words), Ty::array(Ty::u32(), wn));
            let load = if n == 64 { "load_u32x16" } else { "load_u32x8" };
            let h = intrinsics::lookup_helper(&arch, load).ok_or_else(|| format!("no load helper `{load}`"))?;
            return Ok(self.add(N::Helper(h, vec![arr]), expected.clone()));
        }
        let load = match (lane, n) {
            (UintTy::U8, 16) => "load_u8x16",
            (UintTy::U32, 4) => "load_u32x4",
            (UintTy::U64, 2) => "load_u64x2",
            (UintTy::U8, 8) => "load_u8x8",
            (UintTy::U8, 32) => "load_u8x32",
            (UintTy::U8, 64) => "load_u8x64",
            _ => return Err(format!("no load helper for `{}`", v.rust_name())),
        };
        let h = intrinsics::lookup_helper(&arch, load).ok_or_else(|| format!("no load helper `{load}`"))?;
        if intrinsics::helper(h).ret != *expected {
            return Err(format!("load helper `{load}` does not produce `{}`", v.rust_name()));
        }
        Ok(self.add(N::Helper(h, vec![id]), expected.clone()))
    }

    /// The HIR type of a type value (for `None`).
    fn ty_of_type_value(&self, v: &V) -> Result<Ty, String> {
        match &**v {
            Value::IntTy(w) => uint_of(*w).map(Ty::Uint).ok_or_else(|| "a ghost type".to_string()),
            Value::Ind { ind, params } if *ind == self.maps.bool_ => {
                let _ = params;
                Ok(Ty::Bool)
            }
            Value::Ind { ind, params } if *ind == self.maps.option => Ok(Ty::option(self.ty_of_type_value(&params[0])?)),
            Value::Ind { ind, params } if self.maps.tuples.contains_key(ind) => Ok(Ty::Tuple(params.iter().map(|p| self.ty_of_type_value(p)).collect::<Result<_, _>>()?)),
            Value::Ind { ind, params } if self.maps.adts.contains_key(ind) => {
                let args = params.iter().map(|p| self.ty_of_type_value(p)).collect::<Result<Vec<_>, _>>()?;
                Ok(Ty::Adt(self.maps.adts[ind], args))
            }
            _ => Err("a type the residual printer does not know".into()),
        }
    }
}

/// The HIR result type of a primitive printable in the canonical dialect.
fn prim_result_ty(op: PrimOp) -> Option<Ty> {
    use PrimOp::*;
    let u = |w: Width| uint_of(w).map(Ty::Uint);
    match op {
        WAdd(w) | WSub(w) | WMul(w) | WNeg(w) | And(w) | Or(w) | Xor(w) | Not(w) | WShl(w) | WShr(w) | Rotl(w) | Rotr(w) | Min(w) | Max(w) | SatAdd(w) | SatSub(w) | SatMul(w) | SwapBytes(w) | Add(w) | Sub(w) | Mul(w) | Div(w) | Rem(w) | Shl(w) | Shr(w) => u(w),
        CountOnes(w) | LeadingZeros(w) | TrailingZeros(w) => u(w).map(|_| Ty::u32()),
        Eq(w) | Ne(w) | Lt(w) | Le(w) | Gt(w) | Ge(w) => u(w).map(|_| Ty::Bool),
        Cast { from, to } => {
            u(from)?;
            u(to)
        }
        _ => None,
    }
}

/// Builds the residual of `f` (the HIR of the function whose symbolic
/// execution produced `value`). `ngen` is the number of type-parameter
/// binders before the value parameters (0 for residualized functions).
pub fn build(env: &Env, maps: &Maps, krate: &Crate, f: &FnDef, value: &V, span: Span) -> Result<Residual, String> {
    build_opts(env, maps, krate, f, value, span, true)
}

/// [`build`]; `bind_calls = false` is the lane kernels' mode (plan O10):
/// an intrinsic, helper or call result is bound by `let` only when it is
/// used more than once (thousands of single-use vector operations, printed
/// as nested expressions, keep the elaborated `let` nest short), and
/// elements of elements of array parameters (`p[l][k]`) are printable.
pub fn build_opts(env: &Env, maps: &Maps, krate: &Crate, f: &FnDef, value: &V, span: Span, bind_calls: bool) -> Result<Residual, String> {
    if !f.generics.is_empty() {
        return Err("generic functions are not specialized".into());
    }
    for p in &f.params {
        if !matches!(p.pat.kind, PatKind::Binding { sub: None, .. }) {
            return Err("a parameter with a destructuring pattern".into());
        }
    }
    let mut b = Builder { env, maps, krate, f, ngen: 0, nodes: Vec::new(), by_key: HashMap::new(), by_ptr: HashMap::new(), keep: Vec::new(), assembled: HashMap::new(), nested_reads: !bind_calls };
    let root = b.node(value)?;
    let root = b.coerce_vec(root, f.ret.peel_refs())?;
    // the result must have the function's type
    if &b.nodes[root].ty != f.ret.peel_refs() {
        return Err(format!("residual type `{}` differs from the return type `{}`", krate.ty_str(&b.nodes[root].ty), krate.ty_str(&f.ret)));
    }
    // use counts
    let mut stack = vec![root];
    let mut visited = vec![false; b.nodes.len()];
    while let Some(i) = stack.pop() {
        b.nodes[i].uses += 1;
        if visited[i] {
            continue;
        }
        visited[i] = true;
        stack.extend(children_of(&b.nodes[i].n));
    }
    // array bases of element reads are always bound
    let bases: Vec<NodeId> = b.nodes.iter().filter_map(|n| if let N::ElemRead(x, _) = &n.n { Some(*x) } else { None }).collect();
    let mut locals = f.locals.clone();
    let mut stmts = Vec::new();
    let mut emitted = vec![false; b.nodes.len()];
    let mut must_bind = vec![false; b.nodes.len()];
    for x in bases {
        must_bind[x] = true;
    }
    for (i, n) in b.nodes.iter().enumerate() {
        if bind_calls && matches!(n.n, N::Intrinsic(..) | N::Helper(..) | N::Call(..)) {
            must_bind[i] = true;
        }
        if n.uses > 1 && !matches!(n.n, N::Lit(..) | N::Bool(_) | N::Param(_) | N::ParamArray(_) | N::None) {
            must_bind[i] = true;
        }
        // (a ghost argument is printed where it is passed, never bound)
        if matches!(n.n, N::ParamArray(_) | N::Param(_) | N::Lit(..) | N::Bool(_) | N::Ghost(_)) {
            must_bind[i] = false;
        }
    }
    // post-order emission of bound nodes
    let mut order = Vec::new();
    post_order(&b.nodes, root, &mut emitted, &mut order);
    let mut ctx = Emit { b: &mut b, locals: &mut locals, span };
    for i in order {
        if must_bind[i] && i != root {
            let mut e = ctx.expr(i, &must_bind)?;
            let mut ty = ctx.b.nodes[i].ty.clone();
            // an unsized value (a slice, e.g. a call returning `&[T]`) cannot
            // be a local (rustc E0277): its reference is bound instead and
            // read through an auto-deref, as a reference parameter is
            let by_ref = matches!(ty, Ty::Slice(_));
            if by_ref {
                e = match e.kind {
                    ExprKind::Coerce(Coercion::AutoDeref, inner) if inner.ty == Ty::Ref(Box::new(ty.clone())) => *inner,
                    kind => {
                        let v = Expr::new(kind, ty.clone(), e.span);
                        ctx.e(ExprKind::Ref(Box::new(v)), Ty::Ref(Box::new(ty.clone())))
                    }
                };
                ty = Ty::Ref(Box::new(ty));
            }
            let l = LocalId(ctx.locals.len() as u32);
            ctx.locals.push(LocalDecl { name: format!("s{}", l.0), ty: ty.clone(), mutable: false, ghost: false, span });
            ctx.b.nodes[i].local = Some(l);
            ctx.b.nodes[i].by_ref = by_ref;
            stmts.push(Stmt { kind: StmtKind::Let { pat: Pat { kind: PatKind::Binding { local: l, mode: BindingMode::ByValue, sub: None }, ty: ty.clone(), span }, init: e, els: None }, span });
        }
    }
    let tail = ctx.expr(root, &must_bind)?;
    let tail = ctx.adapt(tail, &f.ret);
    let nodes = b.nodes.len();
    let ret = f.ret.clone();
    let body = Expr::new(ExprKind::Block(Block { stmts, tail: Some(Box::new(tail)), span }), ret, span);
    Ok(Residual { body, locals, nodes })
}

fn children_of(n: &N) -> Vec<NodeId> {
    match n {
        N::Lit(..) | N::Bool(_) | N::Param(_) | N::ParamArray(_) | N::None => vec![],
        N::ElemRead(x, _) | N::Some(x) | N::FromLe(_, x) => vec![*x],
        N::ArrayLit(xs) | N::Tuple(xs) | N::Struct(_, xs) | N::Prim(_, xs) | N::Intrinsic(_, _, xs) | N::Helper(_, xs) | N::Call(_, _, xs) => xs.clone(),
        N::Assemble(ps) => ps.iter().filter_map(|p| p.node()).collect(),
        N::Ghost(g) => {
            let mut out = Vec::new();
            g.nodes(&mut out);
            out
        }
    }
}

fn post_order(nodes: &[Node], root: NodeId, done: &mut [bool], out: &mut Vec<NodeId>) {
    // iterative post-order (deep DAGs)
    let mut stack: Vec<(NodeId, bool)> = vec![(root, false)];
    while let Some((i, expanded)) = stack.pop() {
        if done[i] {
            continue;
        }
        if expanded {
            done[i] = true;
            out.push(i);
            continue;
        }
        stack.push((i, true));
        for c in children_of(&nodes[i].n).into_iter().rev() {
            if !done[c] {
                stack.push((c, false));
            }
        }
    }
}

struct Emit<'b, 'a> {
    b: &'b mut Builder<'a>,
    locals: &'b mut Vec<LocalDecl>,
    span: Span,
}

impl Emit<'_, '_> {
    fn e(&self, kind: ExprKind, ty: Ty) -> Expr {
        Expr::new(kind, ty, self.span)
    }

    /// Adapts a reference-free expression to an expected (declared) type:
    /// `&T` expected ⇒ `&e` (identity in the model).
    fn adapt(&self, e: Expr, expected: &Ty) -> Expr {
        match expected {
            Ty::Ref(inner) if e.ty == **inner => {
                let t = expected.clone();
                self.e(ExprKind::Ref(Box::new(e)), t)
            }
            _ => e,
        }
    }

    fn param_expr(&self, p: usize) -> Expr {
        let param = &self.b.f.params[p];
        let PatKind::Binding { local, .. } = &param.pat.kind else { unreachable!("checked in build") };
        let e = self.e(ExprKind::Local(*local), param.ty.clone());
        // reference parameters are auto-dereferenced to their value
        let mut e = e;
        while let Ty::Ref(inner) = e.ty.clone() {
            e = self.e(ExprKind::Coerce(Coercion::AutoDeref, Box::new(e)), *inner);
        }
        e
    }

    fn expr(&mut self, i: NodeId, bind: &[bool]) -> Result<Expr, String> {
        if let Some(l) = self.b.nodes[i].local {
            let ty = self.b.nodes[i].ty.clone();
            if self.b.nodes[i].by_ref {
                let r = self.e(ExprKind::Local(l), Ty::Ref(Box::new(ty.clone())));
                return Ok(self.e(ExprKind::Coerce(Coercion::AutoDeref, Box::new(r)), ty));
            }
            return Ok(self.e(ExprKind::Local(l), ty));
        }
        let _ = bind;
        let n = self.b.nodes[i].n.clone();
        let ty = self.b.nodes[i].ty.clone();
        Ok(match n {
            N::Lit(_, v) => self.e(ExprKind::Lit(Lit::Int(v)), ty),
            N::Bool(v) => self.e(ExprKind::Lit(Lit::Bool(v)), ty),
            N::Param(p) | N::ParamArray(p) => self.param_expr(p),
            N::ElemRead(x, k) => {
                let base = self.expr(x, bind)?;
                let idx = self.e(ExprKind::Lit(Lit::Int(k as u128)), Ty::usize());
                self.e(ExprKind::Index { base: Box::new(base), index: Box::new(idx) }, ty)
            }
            N::ArrayLit(xs) => {
                let es = xs.iter().map(|x| self.expr(*x, bind)).collect::<Result<Vec<_>, _>>()?;
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
                            let v = self.expr(*base, bind)?;
                            let whole = *lo == 0 && matches!(&v.ty, Ty::Array(_, m) if m == k);
                            parts.push((off, len, Part::Slice(if whole { Src::Whole(v) } else { Src::Range(v, *lo, lo + k) })));
                        }
                        Piece::Bytes { x, w, be } => {
                            let v = self.expr(*x, bind)?;
                            parts.push((off, len, Part::Slice(Src::Bytes(v, *w, *be))));
                        }
                        Piece::Elem(x) => {
                            let v = self.expr(*x, bind)?;
                            parts.push((off, len, Part::Elem(v)));
                        }
                        Piece::Zero(_) => {}
                    }
                    off += len;
                }
                assemble::block(self.span, self.locals, &et, n, parts)
            }
            N::Tuple(xs) => {
                let es = xs.iter().map(|x| self.expr(*x, bind)).collect::<Result<Vec<_>, _>>()?;
                self.e(ExprKind::Tuple(es), ty)
            }
            N::Some(x) => {
                let inner = self.expr(x, bind)?;
                let t = inner.ty.clone();
                self.e(ExprKind::Adt { ctor: Ctor::Some, ty_args: vec![t], fields: vec![(0, inner)], base: None }, ty)
            }
            N::None => {
                let Ty::Option(t) = &ty else { return Err("`None` of a non-option type".into()) };
                let t = (**t).clone();
                self.e(ExprKind::Adt { ctor: Ctor::None, ty_args: vec![t], fields: vec![], base: None }, ty)
            }
            N::Struct(item, xs) => {
                let es = xs.iter().map(|x| self.expr(*x, bind)).collect::<Result<Vec<_>, _>>()?;
                let ItemKind::Struct(s) = &self.b.krate.item(item).kind else { return Err("not a struct".into()) };
                let fields = es.into_iter().zip(&s.fields).enumerate().map(|(k, (e, fd))| (k as u32, self.adapt(e, &fd.ty))).collect();
                self.e(ExprKind::Adt { ctor: Ctor::Struct(item), ty_args: vec![], fields, base: None }, ty)
            }
            N::Prim(PrimOpKey(op), xs) => {
                let es = xs.iter().map(|x| self.expr(*x, bind)).collect::<Result<Vec<_>, _>>()?;
                self.prim(op, es, ty)?
            }
            N::Intrinsic(id, imms, xs) => {
                let info = intrinsics::get(id);
                let es = xs.iter().zip(&info.params).map(|(x, pt)| self.expr(*x, bind).map(|e| self.adapt(e, pt))).collect::<Result<Vec<_>, _>>()?;
                self.e(ExprKind::Call { callee: Callee::Intrinsic(id, imms), args: es }, ty)
            }
            N::Helper(h, xs) => {
                let info = intrinsics::helper(h);
                let es = xs.iter().zip(&info.params).map(|(x, pt)| self.expr(*x, bind).map(|e| self.adapt(e, pt))).collect::<Result<Vec<_>, _>>()?;
                self.e(ExprKind::Call { callee: Callee::Helper(h), args: es }, ty)
            }
            N::FromLe(w, x) => {
                let a = self.expr(x, bind)?;
                self.e(ExprKind::Call { callee: Callee::Builtin(Builtin::Int(IntMethod::FromLeBytes, w), vec![]), args: vec![a] }, ty)
            }
            N::Ghost(g) => self.ghost_expr(&g, bind)?,
            N::Call(item, targs, xs) => {
                let f = self.b.krate.fn_def(item).ok_or("callee is not a function")?.clone();
                let es = xs.iter().zip(&f.params).map(|(x, p)| self.expr(*x, bind).map(|e| self.adapt(e, &p.ty.subst(&targs)))).collect::<Result<Vec<_>, _>>()?;
                let ret = f.ret.subst(&targs);
                let call = self.e(ExprKind::Call { callee: Callee::Item(item, targs), args: es }, ret.clone());
                // a reference result is auto-dereferenced to its value
                if let Ty::Ref(inner) = &ret {
                    self.e(ExprKind::Coerce(Coercion::AutoDeref, Box::new(call)), (**inner).clone())
                } else {
                    call
                }
            }
        })
    }

    /// A ghost argument (§15.3) as a ghost `Int` expression.
    fn ghost_expr(&mut self, g: &GArg, bind: &[bool]) -> Result<Expr, String> {
        Ok(match g {
            GArg::Lit(n) => {
                let m = n.magnitude().to_u128().ok_or("a ghost literal out of range")?;
                let lit = self.e(ExprKind::Lit(Lit::Int(m)), Ty::Int);
                if n.sign() == num_bigint::Sign::Minus { self.e(ExprKind::Unary(UnOp::Neg, Box::new(lit)), Ty::Int) } else { lit }
            }
            GArg::Of(x) => {
                let a = self.expr(*x, bind)?;
                self.e(ExprKind::Cast(Box::new(a), Ty::Int), Ty::Int)
            }
            GArg::Add(a, b) | GArg::Sub(a, b) | GArg::Mul(a, b) => {
                let op = match g {
                    GArg::Add(..) => BinOp::Add,
                    GArg::Sub(..) => BinOp::Sub,
                    _ => BinOp::Mul,
                };
                let (x, y) = (self.ghost_expr(a, bind)?, self.ghost_expr(b, bind)?);
                self.e(ExprKind::Binary(op, Box::new(x), Box::new(y)), Ty::Int)
            }
        })
    }

    fn method(&self, m: IntMethod, w: UintTy, args: Vec<Expr>, ty: Ty) -> Expr {
        self.e(ExprKind::Call { callee: Callee::Builtin(Builtin::Int(m, w), vec![]), args }, ty)
    }

    fn bin(&self, op: BinOp, mut args: Vec<Expr>, ty: Ty) -> Expr {
        let b = args.pop().unwrap();
        let a = args.pop().unwrap();
        self.e(ExprKind::Binary(op, Box::new(a), Box::new(b)), ty)
    }

    fn prim(&self, op: PrimOp, args: Vec<Expr>, ty: Ty) -> Result<Expr, String> {
        use PrimOp::*;
        let w = |w: Width| uint_of(w).ok_or_else(|| "ghost width".to_string());
        Ok(match op {
            WAdd(x) => self.method(IntMethod::WrappingAdd, w(x)?, args, ty),
            WSub(x) => self.method(IntMethod::WrappingSub, w(x)?, args, ty),
            WMul(x) => self.method(IntMethod::WrappingMul, w(x)?, args, ty),
            WNeg(x) => self.method(IntMethod::WrappingNeg, w(x)?, args, ty),
            WShl(x) => self.method(IntMethod::WrappingShl, w(x)?, args, ty),
            WShr(x) => self.method(IntMethod::WrappingShr, w(x)?, args, ty),
            Rotl(x) => self.method(IntMethod::RotateLeft, w(x)?, args, ty),
            Rotr(x) => self.method(IntMethod::RotateRight, w(x)?, args, ty),
            Min(x) => self.method(IntMethod::Min, w(x)?, args, ty),
            Max(x) => self.method(IntMethod::Max, w(x)?, args, ty),
            SatAdd(x) => self.method(IntMethod::SaturatingAdd, w(x)?, args, ty),
            SatSub(x) => self.method(IntMethod::SaturatingSub, w(x)?, args, ty),
            SatMul(x) => self.method(IntMethod::SaturatingMul, w(x)?, args, ty),
            CountOnes(x) => self.method(IntMethod::CountOnes, w(x)?, args, ty),
            LeadingZeros(x) => self.method(IntMethod::LeadingZeros, w(x)?, args, ty),
            TrailingZeros(x) => self.method(IntMethod::TrailingZeros, w(x)?, args, ty),
            SwapBytes(x) => self.method(IntMethod::SwapBytes, w(x)?, args, ty),
            And(_) => self.bin(BinOp::BitAnd, args, ty),
            Or(_) => self.bin(BinOp::BitOr, args, ty),
            Xor(_) => self.bin(BinOp::BitXor, args, ty),
            Not(_) => {
                let a = args.into_iter().next().unwrap();
                self.e(ExprKind::Unary(UnOp::Not, Box::new(a)), ty)
            }
            Eq(_) => self.bin(BinOp::Eq, args, ty),
            Ne(_) => self.bin(BinOp::Ne, args, ty),
            Lt(_) => self.bin(BinOp::Lt, args, ty),
            Le(_) => self.bin(BinOp::Le, args, ty),
            Gt(_) => self.bin(BinOp::Gt, args, ty),
            Ge(_) => self.bin(BinOp::Ge, args, ty),
            Add(_) => self.bin(BinOp::Add, args, ty),
            Sub(_) => self.bin(BinOp::Sub, args, ty),
            Mul(_) => self.bin(BinOp::Mul, args, ty),
            Div(_) => self.bin(BinOp::Div, args, ty),
            Rem(_) => self.bin(BinOp::Rem, args, ty),
            Shl(_) => self.bin(BinOp::Shl, args, ty),
            Shr(_) => self.bin(BinOp::Shr, args, ty),
            Cast { .. } => {
                let a = args.into_iter().next().unwrap();
                self.e(ExprKind::Cast(Box::new(a), ty.clone()), ty)
            }
            other => return Err(format!("primitive {other:?} cannot be printed")),
        })
    }
}
