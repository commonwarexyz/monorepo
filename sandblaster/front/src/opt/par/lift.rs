//! The lane functor Φ (optimizer design §13.3; plan O10).
//!
//! **Input.** A *lane site*: an exec function `s(p̄) = [g(ā₀), …, g(ā_{N−1})]`
//! whose value is `N` calls of one function `g` (the lane arguments `āₗ`
//! are whatever the site passes; usually `pⱼ[l]`), and a lane target with
//! `N` lanes ([`super::tiles`]). `g` must evaluate (transparently, loops
//! unrolled) to a DAG of `u32` word operations — the scalar residual DAG.
//!
//! **Translation.** Every liftable word operation of the DAG becomes a
//! vector operation (a tile: one operation, or a bitwise expression over at
//! most three inputs as one `vpternlogd` / `vbslq_u32`); every maximal
//! non-liftable subterm feeding it (a parameter word, a
//! `u32::from_le_bytes` of parameter bytes) is a *leaf*, computed per lane
//! and loaded (`pack`); every output that is not a lane word (a digest
//! byte) is an *exit*, computed per lane from the stored lanes (`unpack`).
//! The lifted function `s__<target>` has the site's signature; it is
//! printed through the ordinary residual printer and elaborated like any
//! optimizer residual.
//!
//! **Proof** (`s__<target>::lane_equiv : Π p̄. Eq(R, s__<target> p̄, s p̄)`,
//! a `VariantEquiv` lemma): a congruence chain over the vector DAG, one
//! lanewise-lemma instance per node, so the proof costs O(scalar DAG):
//!
//! * per vector node `Vₖ = E(Vₐ, V_b, V_c)`: `let Vₖ`, `let Lₖ := mapK pat
//!   Lₐ L_b L_c` (the lanes, an array literal), and `let .hₖ : Eq(view Vₖ,
//!   Lₖ)` = the tile lemma instance transported along `hₐ`, `h_b`, `h_c`;
//!   leaves: `hₖ` = the load lemma instance;
//! * unpack: `refl` of the lane array transported along `store Vₒ = Lₒ`,
//!   then `s__<target> p̄` by conversion;
//! * lanes: each output lane is `g__dag(āₗ)` by conversion, where
//!   `g__dag` is the quoted scalar DAG (a transparent let chain) linked to
//!   `g` by one `bvrefl` (`g__dag::equiv`), transported per lane; the site
//!   unfolds to its array of `g` calls by conversion.
//!
//! The proof is built as core text and checked by the kernel (`add_def`);
//! nothing here is trusted. A wrong lifting (lanes 3 and 4 swapped, R16)
//! fails the final conversion.

use std::collections::{BTreeSet, HashMap};
use std::fmt::Write as _;
use std::rc::Rc;
use std::time::Instant;

use num_traits::ToPrimitive;
use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{GlobalId, Lvl, Name, PrimOp, Rel, Width};
use sandblaster_kernel::value::{Arg, Budget, Head, V, Value};

use super::cquote::{CQuote, Shape};
use super::tiles::{self, LaneTarget, Op, SExpr, Tile};
use crate::elab::{Options as ElabOptions, Output, ProverChain};
use crate::hir::{Crate, FnBody, Item, ItemId, ItemKind, Vis};
use crate::opt::symex;

/// Steps budget of one lane proof (plan O10: ≤ 2·10⁹).
pub const LANE_PROOF_STEPS: u64 = 2_000_000_000;

/// A lane site: the site's value is `N` calls of `callee`.
#[derive(Clone, Debug)]
pub struct LaneSite {
    pub site: GlobalId,
    pub callee: GlobalId,
    pub lanes: usize,
    /// Per lane, per callee parameter: the argument as core text over the
    /// site's parameters (named [`param_name`]).
    pub args: Vec<Vec<String>>,
}

/// The name of site parameter `i` in the generated core text.
pub fn param_name(i: usize) -> String {
    format!("lp{i}")
}

/// A scalar node of the callee's DAG, lifted: a leaf (per-lane scalar
/// term), a constant, or a tile over earlier nodes.
#[derive(Clone, Debug)]
enum LNode {
    /// A per-lane leaf; the callee-level term text (over `gx0..`).
    Leaf(String),
    Const(u32),
    Tile(Tile, Vec<usize>),
}

/// An exit expression (an output that is not a lane word).
#[derive(Clone, Debug)]
enum Exit {
    Lane(usize),
    Lit(Width, u128),
    Prim(PrimOp, Vec<Exit>),
}

/// The lifted IR of a callee on a target.
#[derive(Clone, Debug)]
pub struct Plan {
    pub target: &'static LaneTarget,
    nodes: Vec<LNode>,
    /// The scalar DAG before fusion (one operation per node): `g__dag`.
    dag_nodes: Vec<LNode>,
    /// Per output position of the callee's result: a lane node or an exit.
    outs: Vec<Exit>,
    /// The callee's result is an array of `outs.len()` words of this width
    /// (`None`: a single word).
    out_array: Option<Width>,
    /// Callee parameter binders `(name, type text)`.
    gparams: Vec<(String, String)>,
    /// The callee's result type text.
    gret: String,
    /// Scalar operations of the callee's DAG (before fusion).
    pub scalar_ops: usize,
    /// Vector operations of the lifted kernel (tiles, by their cost).
    pub vector_ops: usize,
    /// Tiles used (lemma names).
    pub tiles: BTreeSet<String>,
    pub leaves: usize,
    pub consts: usize,
    /// A simulated fault (must-reject R16), `None` in every real build.
    pub fault: Option<LaneFault>,
}

/// A simulated fault of the lane functor (design §20, R16): the pack
/// swaps two lanes, in the kernel **and** in the proof builder's lane
/// arrays (the builder trusts the proposal), so what rejects it is the
/// kernel's check of `lane_equiv`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaneFault {
    SwapLanes(usize, usize),
}

/// Statistics of a proven lifting.
#[derive(Clone, Debug, Default)]
pub struct LaneStats {
    pub scalar_ops: usize,
    pub vector_ops: usize,
    pub leaves: usize,
    pub consts: usize,
    pub tiles: usize,
    /// Kernel steps of the lemmas (tile lemmas newly loaded, `g__dag::equiv`,
    /// `lane_equiv`).
    pub steps: u64,
    /// Peak heap growth during the proof (bytes, memguard): exact when the
    /// proof set a new process peak, `None` when an earlier phase of the
    /// process had a higher peak (then the growth is not observable; run
    /// the proof in a fresh process to measure it).
    pub peak_bytes: Option<u64>,
    pub millis: u128,
    /// Size of the proof text (bytes).
    pub proof_bytes: usize,
    /// Peak heap growth of the whole lift, from finding the site to
    /// `lane_equiv` (symbolic execution, evaluating the kernel, printing
    /// and elaborating it, and the proof), with the same caveat as
    /// `peak_bytes`.
    pub lift_peak_bytes: Option<u64>,
    /// Wall time of the whole lift (milliseconds).
    pub lift_millis: u128,
}

fn wtext(w: Width) -> &'static str {
    match w {
        Width::U8 => "U8",
        Width::U16 => "U16",
        Width::U32 => "U32",
        Width::U64 => "U64",
        Width::Usize => "Usize",
        Width::Int => "Int",
    }
}

fn wsuffix(w: Width) -> &'static str {
    match w {
        Width::U8 => "u8",
        Width::U16 => "u16",
        Width::U32 => "u32",
        Width::U64 => "u64",
        Width::Usize => "usize",
        Width::Int => "int",
    }
}

/// The elements of a closed-shape array value (`pair(Cons…, _)`).
fn array_elems(v: &V) -> Option<Vec<V>> {
    let Value::Pair { fst, .. } = &**v else { return None };
    let mut out = Vec::new();
    let mut cur = fst.clone();
    loop {
        let next = match &*cur {
            Value::Ctor { ctor: 0, args, .. } if args.is_empty() => return Some(out),
            Value::Ctor { ctor: 1, args, .. } if args.len() == 2 => match (&args[0], &args[1]) {
                (Arg::Rel(h), Arg::Rel(t)) => {
                    out.push(h.clone());
                    t.clone()
                }
                _ => return None,
            },
            _ => return None,
        };
        cur = next;
    }
}

/// The width of `Array W n` / `W` in a type term's text.
fn parse_ret(ret: &str) -> Option<(Option<(Width, usize)>, Width)> {
    let w = |s: &str| match s {
        "U8" => Some(Width::U8),
        "U16" => Some(Width::U16),
        "U32" => Some(Width::U32),
        "U64" => Some(Width::U64),
        _ => None,
    };
    let t = ret.trim();
    if let Some(rest) = t.strip_prefix("Array ") {
        let mut it = rest.split_whitespace();
        let lane = w(it.next()?)?;
        let n: usize = it.next()?.strip_suffix("usize")?.parse().ok()?;
        return Some((Some((lane, n)), lane));
    }
    Some((None, w(t)?))
}

/// Finds the lane site shape of `site`: its value (callees opaque) is an
/// array of `N ≥ 2` applications of one global.
pub fn find_site(env: &Env, site: GlobalId, opaque: &dyn Fn(GlobalId) -> bool) -> Result<LaneSite, String> {
    let s = symex::symex(env, site, &|g| g != site && opaque(g), 50_000_000)?;
    let elems = array_elems(&s.value).ok_or("the site's value is not an array literal")?;
    if elems.len() < 2 {
        return Err("fewer than two lanes".into());
    }
    let (binders, _) = site_binders(env, site)?;
    let cq = CQuote { env, vars: binders.iter().map(|(n, t)| Ok((n.clone(), Shape::parse(t).ok_or_else(|| format!("a site parameter of type `{t}`"))?))).collect::<Result<_, String>>()? };
    let mut callee = None;
    let mut args = Vec::new();
    for e in &elems {
        let Value::Neu(n) = &**e else { return Err("a lane that is not a call".into()) };
        let Head::Global { def, args: a } = &n.head else { return Err("a lane that is not a call of a global".into()) };
        if !n.spine.is_empty() {
            return Err("a lane with an elimination".into());
        }
        if callee.is_some_and(|c| c != *def) {
            return Err("lanes call different functions".into());
        }
        callee = Some(*def);
        let mut lane = Vec::new();
        for x in a {
            match x {
                Arg::Rel(v) => lane.push(cq.quote(v)?.0),
                Arg::Irr(_) => return Err("the callee has irrelevant parameters (a `requires`)".into()),
            }
        }
        args.push(lane);
    }
    Ok(LaneSite { site, callee: callee.unwrap(), lanes: elems.len(), args })
}

/// Builds the lifted IR of `site.callee` on `target`.
pub fn plan(env: &Env, site: &LaneSite, target: &'static LaneTarget) -> Result<Plan, String> {
    if site.lanes != target.lanes {
        return Err(format!("{} lanes at the site, {} on {}", site.lanes, target.lanes, target.name));
    }
    let g = site.callee;
    let s = symex::symex(env, g, &|_| false, 200_000_000)?;
    let q = s.tele.binders.len();
    let gnames: Vec<Name> = (0..q).map(|i| Name::from(format!("gx{i}").as_str())).collect();
    let mut gparams = Vec::new();
    for (i, (_, rel, dom)) in s.tele.binders.iter().enumerate() {
        if *rel == Rel::Irr {
            return Err("the callee has irrelevant parameters".into());
        }
        gparams.push((gnames[i].to_string(), env.print_term(&gnames[..i], dom)));
    }
    let gret = env.print_term(&gnames, &s.tele.ret);
    let (arr, lane_w) = parse_ret(&gret).ok_or_else(|| format!("the callee's result type `{gret}` is not a word or an array of words"))?;
    let cq = CQuote { env, vars: gparams.iter().map(|(n, t)| Ok((n.clone(), Shape::parse(t).ok_or_else(|| format!("a callee parameter of type `{t}`"))?))).collect::<Result<_, String>>()? };
    let mut b = Builder { cq, target, nodes: Vec::new(), by_ptr: HashMap::new(), consts: HashMap::new(), keep: Vec::new(), scalar_ops: 0 };
    let outs: Vec<Exit> = match arr {
        Some((w, n)) => {
            let es = array_elems(&s.value).ok_or("the callee's value is not an array literal")?;
            if es.len() != n {
                return Err("the callee's array has an unexpected length".into());
            }
            es.iter().map(|e| b.exit(e, w)).collect::<Result<_, _>>()?
        }
        None => vec![b.exit(&s.value, lane_w)?],
    };
    let scalar_ops = b.scalar_ops;
    let mut nodes = b.nodes;
    let dag_nodes = nodes.clone();
    fuse(target, &mut nodes, &outs);
    let mut tiles_used = BTreeSet::new();
    let mut vector_ops = 0;
    let (mut leaves, mut consts) = (0, 0);
    let alive = live(&nodes, &outs);
    for (i, n) in nodes.iter().enumerate() {
        if !alive[i] {
            continue;
        }
        match n {
            LNode::Tile(t, _) => {
                tiles_used.insert(t.lemma_name(target));
                vector_ops += t.vector_ops(target);
            }
            LNode::Leaf(_) => leaves += 1,
            LNode::Const(_) => consts += 1,
        }
    }
    if tiles_used.is_empty() {
        return Err("no liftable operation".into());
    }
    Ok(Plan { target, nodes, dag_nodes, outs, out_array: arr.map(|(w, _)| w), gparams, gret, scalar_ops, vector_ops, tiles: tiles_used, leaves, consts, fault: None })
}

struct Builder<'a> {
    cq: CQuote<'a>,
    target: &'static LaneTarget,
    nodes: Vec<LNode>,
    by_ptr: HashMap<*const Value, usize>,
    consts: HashMap<u32, usize>,
    keep: Vec<V>,
    scalar_ops: usize,
}

impl Builder<'_> {
    fn push(&mut self, n: LNode) -> usize {
        self.nodes.push(n);
        self.nodes.len() - 1
    }

    /// The literal amount of a shift or rotate.
    fn amount(v: &V) -> Option<u32> {
        match &**v {
            Value::Lit { n, .. } => n.to_u32(),
            _ => None,
        }
    }

    /// The liftable operation of a primitive node.
    fn op_of(&self, op: PrimOp, args: &[V]) -> Option<(Op, usize)> {
        use PrimOp::*;
        let o = match op {
            WAdd(Width::U32) => Op::Add,
            WSub(Width::U32) => Op::Sub,
            Xor(Width::U32) => Op::Xor,
            And(Width::U32) => Op::And,
            Or(Width::U32) => Op::Or,
            Not(Width::U32) => Op::Not,
            Rotr(Width::U32) => Op::Rotr(Self::amount(args.get(1)?)? % 32),
            Rotl(Width::U32) => Op::Rotl(Self::amount(args.get(1)?)? % 32),
            WShr(Width::U32) | Shr(Width::U32) => Op::Shr(Self::amount(args.get(1)?).filter(|k| *k < 32)?),
            WShl(Width::U32) | Shl(Width::U32) => Op::Shl(Self::amount(args.get(1)?).filter(|k| *k < 32)?),
            _ => return None,
        };
        o.available(self.target.isa).then_some((o, o.arity()))
    }

    /// The lane node of a `u32` value.
    fn lane(&mut self, v: &V) -> Result<usize, String> {
        if let Some(i) = self.by_ptr.get(&Rc::as_ptr(v)) {
            return Ok(*i);
        }
        let id = match &**v {
            Value::Lit { w: Width::U32, n } => {
                let c = n.to_u32().ok_or("a u32 literal out of range")?;
                if let Some(i) = self.consts.get(&c) {
                    *i
                } else {
                    let i = self.push(LNode::Const(c));
                    self.consts.insert(c, i);
                    i
                }
            }
            Value::Neu(n) if n.spine.is_empty() => match &n.head {
                Head::Prim { op, args, .. } if self.op_of(*op, args).is_some() => {
                    let (o, arity) = self.op_of(*op, args).unwrap();
                    let kids = args[..arity].iter().map(|a| self.lane(a)).collect::<Result<Vec<_>, _>>()?;
                    self.scalar_ops += 1;
                    self.push(LNode::Tile(Tile::op(o), kids))
                }
                _ => self.leaf(v)?,
            },
            _ => self.leaf(v)?,
        };
        self.by_ptr.insert(Rc::as_ptr(v), id);
        self.keep.push(v.clone());
        Ok(id)
    }

    fn leaf(&mut self, v: &V) -> Result<usize, String> {
        let (text, shape) = self.cq.quote(v).map_err(|e| format!("a lane leaf the functor cannot copy: {e}"))?;
        if shape != Shape::Word(Width::U32) {
            return Err(format!("a lane leaf of type `{}`", shape.text()));
        }
        Ok(self.push(LNode::Leaf(text)))
    }

    /// An output position of width `w`.
    fn exit(&mut self, v: &V, w: Width) -> Result<Exit, String> {
        if w == Width::U32 {
            return Ok(Exit::Lane(self.lane(v)?));
        }
        match &**v {
            Value::Lit { w: lw, n } => Ok(Exit::Lit(*lw, n.to_u128().ok_or("a literal out of range")?)),
            Value::Neu(n) if n.spine.is_empty() => match &n.head {
                Head::Prim { op: op @ PrimOp::Cast { from: Width::U32, .. }, args, .. } => Ok(Exit::Prim(*op, vec![Exit::Lane(self.lane(&args[0])?)])),
                Head::Prim { op, args, proofs } if proofs.is_empty() => {
                    let aw = prim_arg_width(*op).ok_or_else(|| format!("an output primitive the lane functor does not know ({op:?})"))?;
                    let kids = args.iter().enumerate().map(|(i, a)| if is_amount(*op, i) { self.exit(a, Width::U32) } else { self.exit(a, aw) }).collect::<Result<Vec<_>, _>>()?;
                    Ok(Exit::Prim(*op, kids))
                }
                _ => Err("an output that is not a word expression of the lanes".into()),
            },
            _ => Err("an output that is not a word expression of the lanes".into()),
        }
    }
}

/// The operand width of a total primitive (its first argument).
fn prim_arg_width(op: PrimOp) -> Option<Width> {
    use PrimOp::*;
    match op {
        WAdd(w) | WSub(w) | WMul(w) | And(w) | Or(w) | Xor(w) | Not(w) | WShl(w) | WShr(w) | Rotl(w) | Rotr(w) => Some(w),
        Cast { from, .. } => Some(from),
        _ => None,
    }
}

/// Whether argument `i` of `op` is a `U32` shift or rotate amount.
fn is_amount(op: PrimOp, i: usize) -> bool {
    use PrimOp::*;
    i == 1 && matches!(op, WShl(_) | WShr(_) | Rotl(_) | Rotr(_))
}

/// Fuses bitwise nodes into three-input tiles (`vpternlogd` on AVX-512, a
/// short formula or a composite on AVX2 / NEON): a bitwise node absorbs a
/// bitwise child used only by it while the expression has at most three
/// inputs. Absorbed nodes stay in the vector (unused).
fn fuse(t: &LaneTarget, nodes: &mut [LNode], outs: &[Exit]) {
    let mut uses = vec![0usize; nodes.len()];
    for n in nodes.iter() {
        if let LNode::Tile(_, kids) = n {
            for k in kids {
                uses[*k] += 1;
            }
        }
    }
    fn mark(e: &Exit, uses: &mut [usize]) {
        match e {
            Exit::Lane(i) => uses[*i] += 2,
            Exit::Prim(_, xs) => xs.iter().for_each(|x| mark(x, uses)),
            Exit::Lit(..) => {}
        }
    }
    outs.iter().for_each(|o| mark(o, &mut uses));
    // per node: its (expression over inputs, inputs) if bitwise
    let mut expr: Vec<Option<(SExpr, Vec<usize>)>> = vec![None; nodes.len()];
    for i in 0..nodes.len() {
        let LNode::Tile(tile, kids) = &nodes[i] else { continue };
        let SExpr::Op(op, _) = &tile.pat else { continue };
        if !op.bitwise() || tile.pat.ops() != 1 {
            continue;
        }
        // children expressions: inline single-use bitwise children
        let mut inputs: Vec<usize> = Vec::new();
        let mut parts: Vec<SExpr> = Vec::new();
        let mut ok = true;
        for &k in kids {
            if uses[k] == 1
                && let Some((ke, kin)) = &expr[k]
            {
                // re-index the child's inputs into ours
                let mut map = Vec::new();
                for &x in kin {
                    let pos = inputs.iter().position(|y| *y == x).unwrap_or_else(|| {
                        inputs.push(x);
                        inputs.len() - 1
                    });
                    map.push(pos);
                }
                parts.push(reindex(ke, &map));
            } else {
                let pos = inputs.iter().position(|y| *y == k).unwrap_or_else(|| {
                    inputs.push(k);
                    inputs.len() - 1
                });
                parts.push(SExpr::In(pos));
            }
            if inputs.len() > 3 {
                ok = false;
                break;
            }
        }
        if ok {
            expr[i] = Some((SExpr::Op(*op, parts), inputs));
        } else {
            expr[i] = Some((SExpr::Op(*op, (0..kids.len()).map(SExpr::In).collect()), kids.clone()));
        }
    }
    // emit fused tiles for maximal expressions with ≥ 2 operations
    for i in 0..nodes.len() {
        let Some((e, ins)) = expr[i].clone() else { continue };
        if e.ops() < 2 {
            continue;
        }
        let tile = Tile { pat: e, arity: ins.len() };
        let _ = t;
        nodes[i] = LNode::Tile(tile, ins);
    }
}

fn reindex(e: &SExpr, map: &[usize]) -> SExpr {
    match e {
        SExpr::In(i) => SExpr::In(map[*i]),
        SExpr::Op(op, xs) => SExpr::Op(*op, xs.iter().map(|x| reindex(x, map)).collect()),
    }
}

/// The nodes reachable from the outputs (absorbed bitwise children drop
/// out), in topological order.
fn live(nodes: &[LNode], outs: &[Exit]) -> Vec<bool> {
    let mut live = vec![false; nodes.len()];
    fn go(e: &Exit, stack: &mut Vec<usize>) {
        match e {
            Exit::Lane(i) => stack.push(*i),
            Exit::Prim(_, xs) => xs.iter().for_each(|x| go(x, stack)),
            Exit::Lit(..) => {}
        }
    }
    let mut stack = Vec::new();
    outs.iter().for_each(|o| go(o, &mut stack));
    while let Some(i) = stack.pop() {
        if live[i] {
            continue;
        }
        live[i] = true;
        if let LNode::Tile(_, kids) = &nodes[i] {
            stack.extend(kids.iter().copied());
        }
    }
    live
}

/// The lane nodes the exits read.
fn exit_lanes(outs: &[Exit]) -> Vec<usize> {
    fn go(e: &Exit, out: &mut BTreeSet<usize>) {
        match e {
            Exit::Lane(i) => {
                out.insert(*i);
            }
            Exit::Prim(_, xs) => xs.iter().for_each(|x| go(x, out)),
            Exit::Lit(..) => {}
        }
    }
    let mut s = BTreeSet::new();
    outs.iter().for_each(|o| go(o, &mut s));
    s.into_iter().collect()
}

fn prim_name(op: PrimOp) -> Option<String> {
    use PrimOp::*;
    let s = |n: &str, w: Width| format!("{n}_{}", wsuffix(w));
    Some(match op {
        WAdd(w) => s("wadd", w),
        WSub(w) => s("wsub", w),
        WMul(w) => s("wmul", w),
        And(w) => s("and", w),
        Or(w) => s("or", w),
        Xor(w) => s("xor", w),
        Not(w) => s("not", w),
        WShl(w) => s("wshl", w),
        WShr(w) => s("wshr", w),
        Rotl(w) => s("rotl", w),
        Rotr(w) => s("rotr", w),
        Cast { from, to } => format!("cast_{}_{}", wsuffix(from), wsuffix(to)),
        _ => return None,
    })
}

/// An exit as core text, lane nodes read by `lane(i)`.
fn exit_text(e: &Exit, lane: &dyn Fn(usize) -> String) -> String {
    match e {
        Exit::Lane(i) => lane(*i),
        Exit::Lit(w, n) => format!("{n}{}", wsuffix(*w)),
        Exit::Prim(op, xs) => format!("#{}({})", prim_name(*op).unwrap_or_default(), xs.iter().map(|x| exit_text(x, lane)).collect::<Vec<_>>().join(", ")),
    }
}

impl Plan {
    fn lt(&self) -> String {
        format!("Array U32 {}usize", self.target.lanes)
    }

    fn view(&self, x: &str) -> String {
        match self.target.view {
            Some(v) => format!("{v} ({x})"),
            None => x.to_string(),
        }
    }

    /// The per-lane term of leaf `text` (callee-level) for lane `l`.
    fn leaf_lane(&self, site: &LaneSite, text: &str, l: usize) -> String {
        let mut s = String::from("(fun");
        for (n, ty) in &self.gparams {
            let _ = write!(s, " ({n} : {ty})");
        }
        let _ = write!(s, " => {text})");
        for a in &site.args[l] {
            let _ = write!(s, " ({a})");
        }
        s
    }

    /// The lane-array literal of leaf `text`.
    fn leaf_array(&self, site: &LaneSite, text: &str) -> String {
        let mut s = self.target.ctor.to_string();
        for l in 0..self.target.lanes {
            // (R16: a faulty pack swaps two lanes)
            let src = match self.fault {
                Some(LaneFault::SwapLanes(a, b)) if l == a => b,
                Some(LaneFault::SwapLanes(a, b)) if l == b => a,
                _ => l,
            };
            let _ = write!(s, " ({})", self.leaf_lane(site, text, src));
        }
        s
    }

    fn const_array(&self, c: u32) -> String {
        format!("{} {}", self.target.ctor, vec![format!("{c}u32"); self.target.lanes].join(" "))
    }

    /// `array::index U32 N (a) lusize .refl(Bool, true)`.
    fn index(&self, a: &str, l: usize) -> String {
        format!("array::index U32 {}usize ({a}) {l}usize .refl(Bool, true)", self.target.lanes)
    }

    /// The site-shaped result over the stored lanes (`lane(o, l)` reads
    /// lane `l` of output node `o`).
    fn result(&self, site_ret: &str, lane: &dyn Fn(usize, usize) -> String) -> String {
        let n = self.target.lanes;
        let mut lanes = Vec::new();
        for l in 0..n {
            let words: Vec<String> = self.outs.iter().map(|e| exit_text(e, &|o| lane(o, l))).collect();
            lanes.push(match self.out_array {
                Some(w) => array_lit(wtext(w), &words),
                None => words[0].clone(),
            });
        }
        let _ = site_ret;
        array_lit(&self.gret, &lanes)
    }

    /// The lifted kernel's body (core text over the site's parameters):
    /// lets of the vector nodes, the stores, and the site-shaped result.
    pub fn kernel_body(&self, site: &LaneSite, site_ret: &str) -> String {
        let live = live(&self.nodes, &self.outs);
        let vt = self.target.vty;
        let mut s = String::new();
        for (i, n) in self.nodes.iter().enumerate() {
            if !live[i] {
                continue;
            }
            let val = match n {
                LNode::Leaf(t) => format!("{} ({})", self.target.load, self.leaf_array(site, t)),
                LNode::Const(c) => format!("{} ({})", self.target.load, self.const_array(*c)),
                LNode::Tile(t, kids) => t.vexpr(self.target, &kids.iter().map(|k| format!("v{k}")).collect::<Vec<_>>()),
            };
            let _ = writeln!(s, "let v{i} : {vt} = {val};");
        }
        for o in exit_lanes(&self.outs) {
            let _ = writeln!(s, "let s{o} : {} = {} v{o};", self.lt(), self.target.store);
        }
        s.push_str(&self.result(site_ret, &|o, l| self.index(&format!("s{o}"), l)));
        s
    }

    /// The text of `g__dag` and `g__dag::equiv` (see [`ensure_dag`]).
    fn dag_text(&self, gname: &str, dag: &str) -> String {
        let mut body = String::new();
        let nodes = &self.dag_nodes;
        let live = live(nodes, &self.outs);
        // single-use operations are inlined (a short `let` nest: the kernel
        // checks a nest of n lets with O(n²) context copies)
        let mut uses = vec![0usize; nodes.len()];
        for (i, n) in nodes.iter().enumerate() {
            if live[i]
                && let LNode::Tile(_, kids) = n
            {
                kids.iter().for_each(|k| uses[*k] += 1);
            }
        }
        for o in exit_lanes(&self.outs) {
            uses[o] += 2;
        }
        let mut text: Vec<String> = vec![String::new(); nodes.len()];
        for (i, n) in nodes.iter().enumerate() {
            if !live[i] {
                continue;
            }
            let val = match n {
                LNode::Leaf(t) => t.clone(),
                LNode::Const(c) => format!("{c}u32"),
                LNode::Tile(t, kids) => {
                    let SExpr::Op(op, _) = &t.pat else { unreachable!("the DAG is one operation per node") };
                    let a = kids.first().map(|k| text[*k].clone()).unwrap_or_default();
                    let b = kids.get(1).map(|k| text[*k].clone()).unwrap_or_default();
                    op.scalar(&a, &b)
                }
            };
            if uses[i] > 1 && matches!(n, LNode::Tile(..) | LNode::Leaf(_)) {
                let _ = writeln!(body, "    let d{i} : U32 = {val};");
                text[i] = format!("d{i}");
            } else {
                text[i] = val;
            }
        }
        let words: Vec<String> = self.outs.iter().map(|e| exit_text(e, &|o| text[o].clone())).collect();
        let res = match self.out_array {
            Some(w) => array_lit(wtext(w), &words),
            None => words[0].clone(),
        };
        let pis: String = self.gparams.iter().map(|(n, t)| format!("({n} : {t}) -> ")).collect();
        let lams: String = self.gparams.iter().map(|(n, t)| format!("({n} : {t}) ")).collect();
        let args: String = self.gparams.iter().map(|(n, _)| format!(" {n}")).collect();
        format!(
            "-- the scalar DAG of `{gname}` (plan O10, the lane functor)\ndef[spec] {dag} : {pis}{ret} :=\n  fun {lams}=>\n{body}    {res}\n\n\
             def[lemma, opaque] {dag}::equiv : {pis}Eq({ret}, {dag}{args}, {gname}{args}) :=\n  fun {lams}=> bvrefl({ret}, {dag}{args}, {gname}{args})\n",
            ret = self.gret
        )
    }

    /// The proof tiles (cones): see [`Cones`].
    pub fn cones(&self) -> Cones {
        Cones::new(self)
    }

    /// The text of every lemma the proof of this plan uses: the boundary
    /// lemmas, the lane maps and one lemma triple per distinct cone.
    pub fn lemma_texts(&self) -> Vec<(String, String)> {
        let t = self.target;
        let cones = self.cones();
        let mut out = vec![(format!("lanes::{}::load", t.name), tiles::boundary_lemmas(t))];
        let arities: BTreeSet<usize> = cones.by_root.values().map(|c| c.inputs.len()).collect();
        for k in arities {
            out.push((map_name(t, k), map_text(t, k)));
        }
        let mut seen = BTreeSet::new();
        for c in cones.by_root.values() {
            if seen.insert(c.name.clone()) {
                out.push((c.name.clone(), c.lemma_text(t)));
            }
        }
        out
    }

    /// The proof text of `Π p̄. Eq(R, f p̄, s p̄)` (the body; the binders
    /// are the site's parameters): the chain over the cut nodes.
    fn proof_body(&self, site: &LaneSite, f: &str, s_name: &str, dag: &str, site_ret: &str, params: &str, site_params: &[(String, String)], stages: &mut Vec<String>) -> String {
        let cones = self.cones();
        let t = self.target;
        let (vt, lt) = (t.vty, self.lt());
        let n = t.lanes;
        let mut b = String::new();
        // The chain, in stages: each stage is a definition of its own
        // (`<f>::stage<j> : Π p̄ (ins : Array node k). Array node m`, checked
        // by its own `add_def`, so the checker's memos never span the whole
        // chain): it takes the bundles (vector, lanes, fact) it imports from
        // earlier stages and returns the bundles it exports; the Σ type of a
        // bundle makes its fact part of its type. The lemma only applies the
        // stages. Constants are closed: they are passed to the cone lemmas
        // as terms.
        let node_ty = format!("lanes::{}::node", t.name);
        let cuts: Vec<usize> = (0..self.nodes.len()).filter(|i| cones.cut[*i] && !matches!(self.nodes[*i], LNode::Const(_))).collect();
        let outs = exit_lanes(&self.outs);
        let chunks: Vec<&[usize]> = cuts.chunks(STAGE_NODES).collect();
        let mut stage_of: HashMap<usize, usize> = HashMap::new();
        for (j, chunk) in chunks.iter().enumerate() {
            for k in chunk.iter() {
                stage_of.insert(*k, j);
            }
        }
        // per stage: the nodes it imports, and the nodes it exports
        let mut imports: Vec<Vec<usize>> = vec![Vec::new(); chunks.len()];
        let mut exports: Vec<Vec<usize>> = vec![Vec::new(); chunks.len()];
        for (j, chunk) in chunks.iter().enumerate() {
            let mut ins = BTreeSet::new();
            for &k in chunk.iter() {
                if let Some(c) = cones.by_root.get(&k) {
                    for &x in &c.inputs {
                        if stage_of.get(&x).is_some_and(|jx| *jx < j) {
                            ins.insert(x);
                        }
                    }
                }
            }
            for &x in &ins {
                let jx = stage_of[&x];
                if !exports[jx].contains(&x) {
                    exports[jx].push(x);
                }
            }
            imports[j] = ins.into_iter().collect();
        }
        for &o in &outs {
            let jx = stage_of[&o];
            if !exports[jx].contains(&o) {
                exports[jx].push(o);
            }
        }
        for e in exports.iter_mut() {
            e.sort_unstable();
        }
        let sig = |v: &str| format!("Sigma (l : {lt}), .Eq({lt}, {}, l)", self.view(v));
        let (binders, _) = (site_params.to_vec(), ());
        let pis: String = binders.iter().map(|(n, ty)| format!("({n} : {ty}) -> ")).collect();
        let lams: String = binders.iter().map(|(n, ty)| format!("({n} : {ty}) ")).collect();
        for (j, chunk) in chunks.iter().enumerate() {
            let (k_in, m) = (imports[j].len(), exports[j].len());
            let mut d = String::new();
            let _ = writeln!(d, "-- stage {j} of the lane proof of `{f}` ({} chain nodes)", chunk.len());
            let _ = writeln!(d, "def[spec] {f}::stage{j} : {pis}(ins : Array {node_ty} {k_in}usize) -> Array {node_ty} {m}usize :=\n  fun {lams}(ins : Array {node_ty} {k_in}usize) =>");
            for (q, x) in imports[j].iter().enumerate() {
                let _ = writeln!(d, "  let n{x} : {node_ty} = array::index {node_ty} {k_in}usize ins {q}usize .refl(Bool, true);");
            }
            let io = |x: usize| -> (String, String, String) {
                match &self.nodes[x] {
                    LNode::Const(c) => {
                        let arr = self.const_array(*c);
                        (format!("({} ({arr}))", t.load), format!("({arr})"), format!("refl({lt}, {arr})"))
                    }
                    _ if stage_of.get(&x) == Some(&j) => (format!("v{x}"), format!("(fst(snd(n{x})))"), format!("snd(snd(n{x}))")),
                    _ => (format!("(fst(n{x}))"), format!("(fst(snd(n{x})))"), format!("snd(snd(n{x}))")),
                }
            };
            for &k in chunk.iter() {
                let (v, l, h) = match &self.nodes[k] {
                    LNode::Leaf(text) => {
                        let arr = self.leaf_array(site, text);
                        (format!("{} ({arr})", t.load), arr.clone(), format!("lanes::{}::load ({arr})", t.name))
                    }
                    LNode::Tile(..) => {
                        let c = &cones.by_root[&k];
                        let ios: Vec<(String, String, String)> = c.inputs.iter().map(|x| io(*x)).collect();
                        let vs: Vec<String> = ios.iter().map(|x| x.0.clone()).collect();
                        let ls: Vec<String> = ios.iter().map(|x| x.1.clone()).collect();
                        let hs: Vec<String> = ios.iter().map(|x| format!(".({})", x.2)).collect();
                        let l = format!("{} ({}) {}", map_name(t, c.inputs.len()), c.pat_text(), ls.join(" "));
                        (c.vexpr(&vs), l, format!("{}::t {} {} {}", c.name, vs.join(" "), ls.join(" "), hs.join(" ")))
                    }
                    LNode::Const(_) => unreachable!("constants are not chain nodes"),
                };
                let _ = writeln!(d, "  let v{k} : {vt} = {v};");
                let _ = writeln!(d, "  let n{k} : {node_ty} = pair({node_ty}, v{k}, pair({}, {l}, {h}));", sig(&format!("v{k}")));
            }
            let _ = writeln!(d, "  {}", array_lit(&node_ty, &exports[j].iter().map(|k| format!("n{k}")).collect::<Vec<_>>()));
            stages.push(d);
            // the lemma applies the stage to its imports
            let ins: Vec<String> = imports[j]
                .iter()
                .map(|x| {
                    let jx = stage_of[x];
                    let pos = exports[jx].iter().position(|y| y == x).expect("an exported node");
                    format!("array::index {node_ty} {}usize st{jx} {pos}usize .refl(Bool, true)", exports[jx].len())
                })
                .collect();
            let _ = writeln!(b, "let st{j} : Array {node_ty} {m}usize = {f}::stage{j} {params} ({});", array_lit(&node_ty, &ins));
        }
        let import = |k: usize, b: &mut String| {
            let j = stage_of[&k];
            let pos = exports[j].iter().position(|x| *x == k).expect("an exported node");
            let _ = writeln!(b, "let n{k} : {node_ty} = array::index {node_ty} {}usize st{j} {pos}usize .refl(Bool, true);", exports[j].len());
        };
        // the output lanes
        for &o in &outs {
            import(o, &mut b);
            let _ = writeln!(b, "let v{o} : {vt} = fst(n{o});");
            let _ = writeln!(b, "let l{o} : {lt} = fst(snd(n{o}));");
            let _ = writeln!(b, "let .h{o} : Eq({lt}, {}, l{o}) = snd(snd(n{o}));", self.view(&format!("v{o}")));
        }
        // unpack: store v_o = l_o
        for &o in &outs {
            let _ = writeln!(
                b,
                "let .s{o} : Eq({lt}, {st} v{o}, l{o}) = transport({lt}, {vo}, l{o}, h{o}, y. Eq({lt}, {st} v{o}, y), lanes::{nm}::store v{o});",
                st = t.store,
                vo = self.view(&format!("v{o}")),
                nm = t.name
            );
        }
        // X = the result over the lanes
        let x = self.result(site_ret, &|o, l| self.index(&format!("l{o}"), l));
        let _ = writeln!(b, "let x : {site_ret} = {x};");
        // E1: Eq(R, f p̄, x): refl transported along sym(store v_o = l_o)
        let mut e1 = format!("refl({site_ret}, x)");
        for (j, &o) in outs.iter().enumerate() {
            let sym = format!("transport({lt}, {st} v{o}, l{o}, s{o}, z. Eq({lt}, z, {st} v{o}), refl({lt}, {st} v{o}))", st = t.store);
            let u = self.result(site_ret, &|oo, l| {
                let pos = outs.iter().position(|y| *y == oo).unwrap();
                if pos < j {
                    self.index(&format!("{} v{oo}", t.store), l)
                } else if pos == j {
                    self.index("y", l)
                } else {
                    self.index(&format!("l{oo}"), l)
                }
            });
            e1 = format!("transport({lt}, l{o}, {st} v{o}, {sym}, y. Eq({site_ret}, {u}, x), {e1})", st = t.store);
        }
        let _ = writeln!(b, "let e1 : Eq({site_ret}, {f} {params}, x) = {e1};");
        // E2: Eq(R, x, s p̄): per lane, g__dag(ā_l) = g(ā_l)
        let gl = |l: usize| format!("({dag} {})", site.args[l].iter().map(|a| format!("({a})")).collect::<Vec<_>>().join(" "));
        let gc = |l: usize| format!("({} {})", callee_name_marker(), site.args[l].iter().map(|a| format!("({a})")).collect::<Vec<_>>().join(" "));
        for l in 0..n {
            let _ = writeln!(b, "let g{l} : {} = {};", self.gret, gl(l));
        }
        let mut e2 = format!("refl({site_ret}, x)");
        for l in 0..n {
            let lanes: Vec<String> = (0..n).map(|ll| if ll < l { gc(ll) } else if ll == l { "y".to_string() } else { format!("g{ll}") }).collect();
            let eq = format!("{dag}::equiv {}", site.args[l].iter().map(|a| format!("({a})")).collect::<Vec<_>>().join(" "));
            e2 = format!("transport({}, g{l}, {}, {eq}, y. Eq({site_ret}, x, {}), {e2})", self.gret, gc(l), array_lit(&self.gret, &lanes));
        }
        let _ = writeln!(b, "let .e2 : Eq({site_ret}, x, {s_name} {params}) = {e2};");
        let _ = write!(b, "transport({site_ret}, x, {s_name} {params}, e2, y. Eq({site_ret}, {f} {params}, y), e1)");
        b
    }
}

/// Chain nodes per stage of the lane proof (see [`Plan::proof_body`]).
const STAGE_NODES: usize = 48;

/// Most inputs of one proof tile (cone).
const CONE_MAX_INPUTS: usize = 10;
/// Most fine nodes of one proof tile.
const CONE_MAX_NODES: usize = 48;

/// The proof tiles of a plan (the lane functor's congruence chain runs
/// over them, not over single operations, so the chain — the one deep
/// `let` nest the kernel checks — stays short): the **cut** nodes are the
/// leaves, the constants, the lanes the exits read and every node used
/// more than once; each cut tile node's **cone** is the tree of single-use
/// nodes below it, down to cut nodes (its inputs), split further when it
/// would exceed [`CONE_MAX_INPUTS`] inputs or [`CONE_MAX_NODES`] nodes.
/// A cone's lemma depends only on its vector expression, so repeated
/// shapes (SHA-256's 64 rounds) share one lemma.
pub struct Cones {
    pub cut: Vec<bool>,
    pub by_root: std::collections::BTreeMap<usize, Cone>,
}

/// One proof tile.
pub struct Cone {
    pub inputs: Vec<usize>,
    pub pat: SExpr,
    /// The vector expression with inputs `a0 ..`.
    vtmpl: String,
    pub name: String,
    pub nodes: usize,
}

impl Cones {
    fn new(p: &Plan) -> Cones {
        let nodes = &p.nodes;
        let alive = live(nodes, &p.outs);
        let mut uses = vec![0usize; nodes.len()];
        for (i, n) in nodes.iter().enumerate() {
            if alive[i]
                && let LNode::Tile(_, kids) = n
            {
                for k in kids {
                    uses[*k] += 1;
                }
            }
        }
        let exits: BTreeSet<usize> = exit_lanes(&p.outs).into_iter().collect();
        let mut cut: Vec<bool> = (0..nodes.len()).map(|i| alive[i] && (!matches!(nodes[i], LNode::Tile(..)) || uses[i] != 1 || exits.contains(&i))).collect();
        // per node: (inputs, fine nodes) of its cone
        let mut info: Vec<(Vec<usize>, usize)> = vec![(Vec::new(), 0); nodes.len()];
        for i in 0..nodes.len() {
            let LNode::Tile(_, kids) = &nodes[i] else { continue };
            if !alive[i] {
                continue;
            }
            loop {
                let mut ins: Vec<usize> = Vec::new();
                let mut size = 1;
                for &k in kids {
                    if cut[k] {
                        if !ins.contains(&k) {
                            ins.push(k);
                        }
                    } else {
                        for &x in &info[k].0 {
                            if !ins.contains(&x) {
                                ins.push(x);
                            }
                        }
                        size += info[k].1;
                    }
                }
                if ins.len() <= CONE_MAX_INPUTS && size <= CONE_MAX_NODES {
                    info[i] = (ins, size);
                    break;
                }
                // cut the largest non-cut child and retry
                let Some(&big) = kids.iter().filter(|k| !cut[**k]).max_by_key(|k| info[**k].1) else {
                    info[i] = (ins, size);
                    break;
                };
                cut[big] = true;
            }
        }
        let mut by_root = std::collections::BTreeMap::new();
        for i in 0..nodes.len() {
            if !cut[i] || !matches!(nodes[i], LNode::Tile(..)) {
                continue;
            }
            let inputs = info[i].0.clone();
            let pat = cone_expr(nodes, &cut, &inputs, i, true);
            let vt = cone_vexpr(p.target, nodes, &cut, &inputs, i, true);
            let name = format!("lanes::{}::c{:016x}", p.target.name, fnv(&vt));
            by_root.insert(i, Cone { inputs, pat, vtmpl: vt, name, nodes: info[i].1 });
        }
        Cones { cut, by_root }
    }
}

/// The cone expression of node `i` over `inputs` (`root`: `i` itself is
/// expanded even though it is cut).
fn cone_expr(nodes: &[LNode], cut: &[bool], inputs: &[usize], i: usize, root: bool) -> SExpr {
    if !root && cut[i] {
        return SExpr::In(inputs.iter().position(|x| *x == i).expect("a cone input"));
    }
    let LNode::Tile(t, kids) = &nodes[i] else { unreachable!("a non-tile inside a cone") };
    let args: Vec<SExpr> = kids.iter().map(|k| cone_expr(nodes, cut, inputs, *k, false)).collect();
    subst(&t.pat, &args)
}

fn subst(e: &SExpr, args: &[SExpr]) -> SExpr {
    match e {
        SExpr::In(j) => args[*j].clone(),
        SExpr::Op(op, xs) => SExpr::Op(*op, xs.iter().map(|x| subst(x, args)).collect()),
    }
}

/// The cone's vector expression, inputs named `a0 ..`.
fn cone_vexpr(t: &LaneTarget, nodes: &[LNode], cut: &[bool], inputs: &[usize], i: usize, root: bool) -> String {
    if !root && cut[i] {
        return format!("a{}", inputs.iter().position(|x| *x == i).expect("a cone input"));
    }
    let LNode::Tile(tile, kids) = &nodes[i] else { unreachable!("a non-tile inside a cone") };
    let args: Vec<String> = kids.iter().map(|k| cone_vexpr(t, nodes, cut, inputs, *k, false)).collect();
    tile.vexpr(t, &args)
}

/// 64-bit FNV-1a (stable lemma names).
fn fnv(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

impl Cone {
    /// The vector expression on argument texts.
    pub fn vexpr(&self, args: &[String]) -> String {
        // substitute `a<j>` tokens (longest index first: `a10` before `a1`)
        let mut out = String::with_capacity(self.vtmpl.len());
        let bytes = self.vtmpl.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let c = bytes[i];
            let prev_ident = i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_' || bytes[i - 1] == b':');
            if c == b'a' && !prev_ident {
                let mut j = i + 1;
                while j < bytes.len() && bytes[j].is_ascii_digit() {
                    j += 1;
                }
                let next_ident = j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_');
                if j > i + 1 && !next_ident {
                    let k: usize = self.vtmpl[i + 1..j].parse().unwrap();
                    out.push_str(&args[k]);
                    i = j;
                    continue;
                }
            }
            out.push(c as char);
            i += 1;
        }
        out
    }

    /// `fun (x0 : U32) .. => pat`.
    pub fn pat_text(&self) -> String {
        let mut s = String::from("fun");
        for i in 0..self.inputs.len() {
            let _ = write!(s, " (x{i} : U32)");
        }
        let _ = write!(s, " => {}", self.pat.text());
        s
    }

    /// The cone's three lemmas: on lane words (`::w`, by `bvrefl`), on
    /// vectors (its instance at the views), and transported along the
    /// inputs' facts (`::t`, what the chain uses).
    pub fn lemma_text(&self, t: &LaneTarget) -> String {
        let k = self.inputs.len();
        let lt = format!("Array U32 {}usize", t.lanes);
        let vt = t.vty;
        let view = |x: &str| match t.view {
            Some(v) => format!("{v} ({x})"),
            None => x.to_string(),
        };
        let map = map_name(t, k);
        let pat = self.pat_text();
        let a: Vec<String> = (0..k).map(|i| format!("a{i}")).collect();
        let m: Vec<String> = (0..k).map(|i| format!("m{i}")).collect();
        let name = &self.name;
        let mut s = format!("-- {} ({} nodes)\n", self.pat.text(), self.nodes);
        let lhs = view(&self.vexpr(&a));
        let va: String = a.iter().map(|x| format!(" ({})", view(x))).collect();
        let ab: String = a.iter().map(|x| format!("({x} : {vt}) ")).collect();
        let ap: String = a.iter().map(|x| format!("({x} : {vt}) -> ")).collect();
        match t.from {
            Some(from) => {
                let w: Vec<String> = (0..k).map(|i| format!("w{i}")).collect();
                let fw: Vec<String> = w.iter().map(|x| format!("{from} {x}")).collect();
                let wl = view(&self.vexpr(&fw));
                let wr = format!("{map} ({pat}){}", w.iter().map(|x| format!(" {x}")).collect::<String>());
                let wb: String = w.iter().map(|x| format!("({x} : {lt}) ")).collect();
                let wp: String = w.iter().map(|x| format!("({x} : {lt}) -> ")).collect();
                let _ = writeln!(s, "def[lemma, opaque] {name}::w : {wp}Eq({lt}, {wl}, {wr}) :=\n  fun {wb}=> bvrefl({lt}, {wl}, {wr})\n");
                let _ = writeln!(s, "def[lemma, opaque] {name} : {ap}Eq({lt}, {lhs}, {map} ({pat}){va}) :=\n  fun {ab}=> {name}::w{va}\n");
            }
            None => {
                let rhs = format!("{map} ({pat}){va}");
                let _ = writeln!(s, "def[lemma, opaque] {name} : {ap}Eq({lt}, {lhs}, {rhs}) :=\n  fun {ab}=> bvrefl({lt}, {lhs}, {rhs})\n");
            }
        }
        // transported along h_j : view a_j = m_j, position 0 first
        let mut pf = format!("{name}{}", a.iter().map(|x| format!(" {x}")).collect::<String>());
        for j in 0..k {
            let motive: String = (0..k)
                .map(|jj| {
                    if jj < j {
                        format!(" {}", m[jj])
                    } else if jj == j {
                        " y".to_string()
                    } else {
                        format!(" ({})", view(&a[jj]))
                    }
                })
                .collect();
            pf = format!("transport({lt}, {}, {}, h{j}, y. Eq({lt}, {lhs}, {map} ({pat}){motive}), {pf})", view(&a[j]), m[j]);
        }
        let mb: String = m.iter().map(|x| format!("({x} : {lt}) ")).collect();
        let mp: String = m.iter().map(|x| format!("({x} : {lt}) -> ")).collect();
        let hb: String = (0..k).map(|j| format!("(.h{j} : Eq({lt}, {}, {})) ", view(&a[j]), m[j])).collect();
        let hp: String = (0..k).map(|j| format!("(.h{j} : Eq({lt}, {}, {})) -> ", view(&a[j]), m[j])).collect();
        let ms: String = m.iter().map(|x| format!(" {x}")).collect();
        let _ = writeln!(s, "def[lemma, opaque] {name}::t : {ap}{mp}{hp}Eq({lt}, {lhs}, {map} ({pat}){ms}) :=\n  fun {ab}{mb}{hb}=> {pf}");
        s
    }
}

/// The lane map of arity `k` on `t`.
fn map_name(t: &LaneTarget, k: usize) -> String {
    format!("lanes::{}::map{k}", t.name)
}

/// `lanes::<t>::map<k> f a0 .. = ctor (f a0[0] ..) .. (f a0[N−1] ..)`.
fn map_text(t: &LaneTarget, k: usize) -> String {
    let lt = format!("Array U32 {}usize", t.lanes);
    let ft = vec!["U32"; k + 1].join(" -> ");
    let ab: String = (0..k).map(|i| format!("(a{i} : {lt}) ")).collect();
    let ap: String = (0..k).map(|i| format!("(a{i} : {lt}) -> ")).collect();
    let mut lanes = String::new();
    for l in 0..t.lanes {
        let args: String = (0..k).map(|i| format!(" (array::index U32 {}usize a{i} {l}usize .refl(Bool, true))", t.lanes)).collect();
        let _ = write!(lanes, "\n      (f{args})");
    }
    format!("-- the lanes of {k}-input word functions (plan O10)\ndef[prelude] {} : (f : {ft}) -> {ap}{lt} :=\n  fun (f : {ft}) {ab}=>\n    {}{lanes}\n", map_name(t, k), t.ctor)
}


/// Placeholder for the callee's name in [`Plan::proof_body`] (replaced by
/// [`prove`]).
fn callee_name_marker() -> &'static str {
    "@@CALLEE@@"
}

/// `pair(Array T n, Cons[T](x0, … Nil[T]), refl(Int, nint))`.
fn array_lit(t: &str, xs: &[String]) -> String {
    let t = if t.contains(' ') { format!("({t})") } else { t.to_string() };
    let mut list = format!("Nil[{t}]");
    for x in xs.iter().rev() {
        list = format!("Cons[{t}]({x}, {list})");
    }
    format!("pair(Array {t} {}usize, {list}, refl(Int, {}int))", xs.len(), xs.len())
}

/// The site's parameter binders as core text (`(lp0 : T0) (lp1 : T1)`)
/// and their types' texts.
pub fn site_binders(env: &Env, site: GlobalId) -> Result<(Vec<(String, String)>, String), String> {
    let tele = symex::telescope(env, site).ok_or("the site has no parameter telescope")?;
    let names: Vec<Name> = (0..tele.binders.len()).map(|i| Name::from(param_name(i).as_str())).collect();
    let mut out = Vec::new();
    for (i, (_, rel, dom)) in tele.binders.iter().enumerate() {
        if *rel == Rel::Irr {
            return Err("the site has irrelevant parameters (a `requires`)".into());
        }
        out.push((names[i].to_string(), env.print_term(&names[..i], dom)));
    }
    let ret = env.print_term(&names, &tele.ret);
    Ok((out, ret))
}

/// Loads the core models a target's tiles use when the elaboration did
/// not (the elaborator loads `core/x86_64.core` only; the 256/512-bit
/// families of `core/x86_64_avx.core` are loaded here, the first time a lane
/// kernel needs them, so programs without lane sites never pay for them).
pub fn ensure_core(env: &mut Env, target: &LaneTarget) -> Result<(), String> {
    if target.arch == "x86_64" && env.lookup_global("x86_64::_mm512_add_epi32").is_none() {
        let mut b = Budget { steps: 2_000_000_000 };
        env.load_core(sandblaster_targets::coretext::X86_64_CORE_AVX, &mut b).map_err(|e| format!("core/x86_64_avx.core: {e}"))?;
    }
    if env.lookup_global(target.load).is_none() {
        return Err(format!("the core models of {} are not loaded (`{}` is missing)", target.name, target.load));
    }
    Ok(())
}

/// Loads (the kernel checks) every lemma of `plan` not already in `env`.
/// Returns the steps spent.
pub fn ensure_lemmas(env: &mut Env, plan: &Plan) -> Result<u64, String> {
    let mut steps = 0;
    for (name, text) in plan.lemma_texts() {
        if env.lookup_global(&name).is_some() {
            continue;
        }
        let mut b = Budget { steps: LANE_PROOF_STEPS };
        env.load_core(&text, &mut b).map_err(|e| format!("lanewise lemma `{name}` rejected: {e}\n{text}"))?;
        steps += LANE_PROOF_STEPS - b.steps;
    }
    Ok(steps)
}

/// `g__dag` (the callee's scalar DAG as a transparent let chain, one word
/// operation per let) and `g__dag::equiv : Π x̄. Eq(R, g__dag x̄, g x̄)`
/// by `bvrefl` (both sides evaluate to the same DAG). Returns the DAG's
/// name and the steps spent.
pub fn ensure_dag(env: &mut Env, plan: &Plan, callee: GlobalId) -> Result<(String, u64), String> {
    let gname = env.global_name(callee).ok_or("the callee has no name")?.to_string();
    let dag = format!("{gname}__dag");
    if env.lookup_global(&dag).is_some() {
        return Ok((dag, 0));
    }
    let text = plan.dag_text(&gname, &dag);
    if let Some(dir) = std::env::var_os("SANDBLASTER_LANE_DUMP") {
        let _ = std::fs::write(std::path::Path::new(&dir).join(format!("{}.core", dag.replace("::", "__"))), &text);
    }
    let mut b = Budget { steps: LANE_PROOF_STEPS };
    env.load_core(&text, &mut b).map_err(|e| format!("`{dag}` rejected: {}", e.to_string().chars().take(900).collect::<String>()))?;
    Ok((dag, LANE_PROOF_STEPS - b.steps))
}

/// Proves `f::lane_equiv : Π p̄. Eq(R, f p̄, s p̄)` for the elaborated
/// lifted function `f` of `plan` at `site`. Returns the lemma and stats.
pub fn prove(env: &mut Env, site: &LaneSite, plan: &Plan, f: GlobalId, lemma_name: &str) -> Result<(GlobalId, LaneStats), String> {
    let t0 = Instant::now();
    let before = sandblaster_memguard::allocated() as u64;
    let peak_before = sandblaster_memguard::peak() as u64;
    let mut stats = LaneStats { scalar_ops: plan.scalar_ops, vector_ops: plan.vector_ops, leaves: plan.leaves, consts: plan.consts, tiles: plan.tiles.len(), ..Default::default() };
    let trace = std::env::var_os("SANDBLASTER_LANE_TRACE").is_some();
    let mark = |what: &str| {
        if trace {
            eprintln!("lanes: {what}: {:?}, heap {} MiB, peak {} MiB", t0.elapsed(), sandblaster_memguard::allocated() >> 20, sandblaster_memguard::peak() >> 20);
        }
    };
    mark("start");
    stats.steps += ensure_lemmas(env, plan)?;
    mark("tile lemmas");
    let (dag, st) = ensure_dag(env, plan, site.callee)?;
    stats.steps += st;
    mark("dag");
    let fname = env.global_name(f).ok_or("f has no name")?.to_string();
    let sname = env.global_name(site.site).ok_or("the site has no name")?.to_string();
    let gname = env.global_name(site.callee).ok_or("the callee has no name")?.to_string();
    let (binders, ret) = site_binders(env, site.site)?;
    let params: String = binders.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>().join(" ");
    let mut stages = Vec::new();
    let body = plan.proof_body(site, &fname, &sname, &dag, &ret, &params, &binders, &mut stages).replace(callee_name_marker(), &gname);
    for (j, st) in stages.iter().enumerate() {
        let mut b = Budget { steps: LANE_PROOF_STEPS };
        let r = env.load_core(st, &mut b);
        stats.steps += LANE_PROOF_STEPS - b.steps;
        if let Some(dir) = std::env::var_os("SANDBLASTER_LANE_DUMP") {
            let _ = std::fs::write(std::path::Path::new(&dir).join(format!("{}__stage{j}.core", fname.replace("::", "__"))), st);
        }
        r.map_err(|e| format!("lane proof stage {j} rejected by the kernel: {}", e.to_string().chars().take(1500).collect::<String>()))?;
    }
    mark("stages");
    let pis: String = binders.iter().map(|(n, t)| format!("({n} : {t}) -> ")).collect();
    let lams: String = binders.iter().map(|(n, t)| format!("({n} : {t}) ")).collect();
    let text = format!("def[lemma, opaque] {lemma_name} : {pis}Eq({ret}, {fname} {params}, {sname} {params}) :=\n  fun {lams}=>\n{body}\n");
    stats.proof_bytes = text.len();
    if let Some(dir) = std::env::var_os("SANDBLASTER_LANE_DUMP") {
        let _ = std::fs::write(std::path::Path::new(&dir).join(format!("{}.core", lemma_name.replace("::", "__"))), &text);
    }
    let mut b = Budget { steps: LANE_PROOF_STEPS };
    let r = env.load_core(&text, &mut b);
    stats.steps += LANE_PROOF_STEPS - b.steps;
    mark("lane_equiv");
    let peak_after = sandblaster_memguard::peak() as u64;
    stats.peak_bytes = (peak_after > peak_before).then(|| peak_after - before);
    stats.millis = t0.elapsed().as_millis();
    r.map_err(|e| format!("lane_equiv rejected by the kernel: {}", e.to_string().chars().take(1500).collect::<String>()))?;
    let g = env.lookup_global(lemma_name).ok_or("the lemma is missing after loading")?;
    Ok((g, stats))
}

/// A lifted, proven lane kernel.
#[derive(Clone, Debug)]
pub struct Lifted {
    /// The lifted function `s__<target>` (an exec item of the extended crate).
    pub item: ItemId,
    pub global: GlobalId,
    /// `s__<target>::lane_equiv`.
    pub lemma: GlobalId,
    pub site: LaneSite,
    pub plan: Plan,
    pub stats: LaneStats,
}

/// The lane functor end to end on `site_item` for `target`: finds the
/// site's lanes, plans the lifting, builds the kernel's value (over the
/// site's parameters), prints it through the residual printer as the exec
/// item `s__<target>` (elaborated like any optimizer residual: every proof
/// slot re-proven, the kernel checks the definition), and proves its
/// `lane_equiv` lemma. `opaque` keeps the user functions folded when the
/// site is evaluated (the callee must stay a call).
#[allow(clippy::too_many_arguments)]
pub fn lift_site(out: &mut Output, ext: &mut Crate, chain: &mut ProverChain, eopts: &ElabOptions, site_item: ItemId, target: &'static LaneTarget, opaque: &dyn Fn(GlobalId) -> bool) -> Result<Lifted, String> {
    lift_site_with(out, ext, chain, eopts, site_item, target, opaque, None)
}

/// [`lift_site`] with a simulated fault (must-reject tests only).
#[allow(clippy::too_many_arguments)]
pub fn lift_site_with(out: &mut Output, ext: &mut Crate, chain: &mut ProverChain, eopts: &ElabOptions, site_item: ItemId, target: &'static LaneTarget, opaque: &dyn Fn(GlobalId) -> bool, fault: Option<LaneFault>) -> Result<Lifted, String> {
    let sg = *out.fn_globals.get(&site_item).ok_or("the site is not elaborated")?;
    let trace = std::env::var_os("SANDBLASTER_LANE_TRACE").is_some();
    let t0 = Instant::now();
    let mark = |what: &str| {
        if trace {
            eprintln!("lanes: {what}: {:?}, heap {} MiB, peak {} MiB", t0.elapsed(), sandblaster_memguard::allocated() >> 20, sandblaster_memguard::peak() >> 20);
        }
    };
    mark("site");
    let lift_before = sandblaster_memguard::allocated() as u64;
    let lift_peak_before = sandblaster_memguard::peak() as u64;
    ensure_core(&mut out.env, target)?;
    mark("core");
    let site = find_site(&out.env, sg, opaque)?;
    let mut plan = plan(&out.env, &site, target)?;
    plan.fault = fault;
    let (binders, ret) = site_binders(&out.env, sg)?;
    let text = plan.kernel_body(&site, &ret);
    let names: Vec<&str> = binders.iter().map(|(n, _)| n.as_str()).collect();
    let body = out.env.parse_term(&names, &text).map_err(|e| format!("the lifted kernel does not parse: {e}"))?;
    let s = symex::symex(&out.env, sg, &|g| g != sg && opaque(g), 50_000_000)?;
    let mut b = Budget { steps: 500_000_000 };
    let value = out.env.eval_opaque(&s.venv, Lvl(binders.len() as u32), &body, &|_| false, &mut b).map_err(|e| format!("evaluating the lifted kernel: {e:?}"))?;
    let maps = crate::opt::residual::Maps::new(&out.env, ext, &out.fn_globals, &out.adts)?;
    let orig = ext.item(site_item).clone();
    let mut f = ext.fn_def(site_item).ok_or("the site is not a function")?.clone();
    if !f.requires.is_empty() || !f.generics.is_empty() {
        return Err("the site has a precondition or generics".into());
    }
    let features: Vec<String> = target.features.iter().map(|s| s.to_string()).collect();
    f.feature_set = crate::target::feature_closure(&ext.target.arch, &features);
    f.target_features = features;
    f.implements = None;
    f.specialize = false;
    f.ensures = None;
    f.decreases = None;
    f.recursion = crate::hir::Recursion::None;
    mark("kernel value");
    let r = crate::opt::residual::build_opts(&out.env, &maps, ext, &f, &value, orig.span, false)?;
    mark("residual");
    f.body = FnBody::Exec(r.body);
    f.locals = r.locals;
    let name = format!("{}__{}", orig.name, target.name);
    let rid = ItemId(ext.items.len() as u32);
    let mut path = orig.path.clone();
    if let Some(l) = path.0.last_mut() {
        *l = name.clone();
    }
    let cfg = Some(format!("all(target_arch = \"{}\", target_endian = \"little\")", target.arch));
    let docs = vec![format!(" Lane kernel of `{}` on `{}` ({} lanes; plan O10, the lane functor): equal to it by `{name}::lane_equiv`.", orig.path, target.name, target.lanes)];
    ext.items.push(Item { id: rid, name: name.clone(), path, module: orig.module, vis: Vis::Crate, ghost: false, span: orig.span, docs, allow: orig.allow.clone(), cfg, kind: ItemKind::Fn(f) });
    ext.modules[orig.module.0 as usize].items.push(rid);
    let ropts = ElabOptions { check_proofs: false, ..eopts.clone() };
    let diags_before = out.diags.list.len();
    let failed = crate::elab::generated::resume(out, ext, &[rid], chain, &ropts, None);
    let pop = |out: &mut Output, ext: &mut Crate| {
        out.diags.list.truncate(diags_before);
        ext.modules[orig.module.0 as usize].items.retain(|i| *i != rid);
        if ext.items.len() == rid.0 as usize + 1 {
            ext.items.pop();
        }
    };
    match failed {
        Ok(f) if f.is_empty() => {}
        Ok(_) => {
            let why = out.diags.list.get(diags_before..).and_then(|d| d.first()).map(|d| d.msg.clone()).unwrap_or_default();
            pop(out, ext);
            return Err(format!("the lane kernel did not elaborate: {why}"));
        }
        Err(e) => {
            pop(out, ext);
            return Err(format!("the lane kernel did not elaborate: {e}"));
        }
    }
    mark("elaborated");
    let global = *out.fn_globals.get(&rid).ok_or("the lane kernel has no global")?;
    let gname = out.env.global_name(global).map(|n| n.to_string()).unwrap_or(name);
    let (lemma, mut stats) = match prove(&mut out.env, &site, &plan, global, &format!("{gname}::lane_equiv")) {
        Ok(x) => x,
        Err(e) => {
            // not linked: never printed (its kernel definition stays, unused)
            ext.items[rid.0 as usize].ghost = true;
            return Err(e);
        }
    };
    let lift_peak_after = sandblaster_memguard::peak() as u64;
    stats.lift_peak_bytes = (lift_peak_after > lift_peak_before).then(|| lift_peak_after - lift_before);
    stats.lift_millis = t0.elapsed().as_millis();
    Ok(Lifted { item: rid, global, lemma, site, plan, stats })
}

/// Development aid (`SANDBLASTER_OPT_DIFF=1`): the first structural
/// difference of two values (quoted, truncated), for a candidate the kernel
/// found not convertible.
pub fn value_diff(env: &Env, depth: u32, a: &V, b: &V) -> Option<(String, String)> {
    fn args_of(v: &V) -> Vec<V> {
        match &**v {
            Value::Pair { fst, snd } => {
                let mut o = vec![fst.clone()];
                if let Arg::Rel(x) = snd {
                    o.push(x.clone());
                }
                o
            }
            Value::Ctor { args, .. } => args.iter().filter_map(|a| if let Arg::Rel(x) = a { Some(x.clone()) } else { None }).collect(),
            Value::Neu(n) => {
                let mut o: Vec<V> = match &n.head {
                    Head::Global { args, .. } => args.iter().filter_map(|a| if let Arg::Rel(x) = a { Some(x.clone()) } else { None }).collect(),
                    Head::Prim { args, .. } => args.clone(),
                    _ => vec![],
                };
                for e in &n.spine {
                    if let sandblaster_kernel::value::Elim::App(Arg::Rel(x)) = e {
                        o.push(x.clone());
                    }
                }
                o
            }
            _ => vec![],
        }
    }
    fn head(v: &V) -> String {
        match &**v {
            Value::Lit { w, n } => format!("lit {n}{w:?}"),
            Value::Pair { .. } => "pair".into(),
            Value::Ctor { ctor, .. } => format!("ctor {ctor}"),
            Value::Neu(n) => format!(
                "{} / {}",
                match &n.head {
                    Head::Var(l) => format!("var {}", l.0),
                    Head::Global { def, .. } => format!("global {}", def.0),
                    Head::Prim { op, .. } => format!("prim {op:?}"),
                    _ => "other".into(),
                },
                n.spine.len()
            ),
            _ => "other".into(),
        }
    }
    let mut seen = std::collections::HashSet::new();
    let mut stack = vec![(a.clone(), b.clone())];
    while let Some((x, y)) = stack.pop() {
        if Rc::ptr_eq(&x, &y) || !seen.insert((Rc::as_ptr(&x) as usize, Rc::as_ptr(&y) as usize)) {
            continue;
        }
        let (ax, ay) = (args_of(&x), args_of(&y));
        let same_head = match (&*x, &*y) {
            (Value::Neu(n1), Value::Neu(n2)) => match (&n1.head, &n2.head) {
                (Head::Global { def: d1, .. }, Head::Global { def: d2, .. }) => d1 == d2 && n1.spine.len() == n2.spine.len(),
                (Head::Prim { op: o1, .. }, Head::Prim { op: o2, .. }) => format!("{o1:?}").replace("Shr", "WShr").replace("WWShr", "WShr") == format!("{o2:?}").replace("Shr", "WShr").replace("WWShr", "WShr"),
                _ => head(&x) == head(&y),
            },
            _ => head(&x) == head(&y),
        };
        if !same_head || ax.len() != ay.len() {
            let q = |v: &V| sandblaster_kernel::syntax::printer::print_term_bounded(env, &[], &env.quote(Lvl(depth), v, false), 600);
            return Some((format!("{} :: {}", head(&x), q(&x)), format!("{} :: {}", head(&y), q(&y))));
        }
        for (p, q) in ax.into_iter().zip(ay) {
            stack.push((p, q));
        }
    }
    None
}
