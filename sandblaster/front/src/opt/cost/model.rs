//! The target cost model (optimizer design §10.2–10.3; DESIGN §8.2 item 6;
//! plan O8).
//!
//! **What it prices.** A residual — the HIR body the printer emits, or a
//! kernel term DAG (the aegraph's candidates) — under the tables of one
//! variant set ([`SetModel`]: one [`Table`] per microarchitecture the set is
//! dispatched on).
//!
//! **How.** Every operation contributes its reciprocal throughput to `ΣTP`
//! and its latency to the critical path `CP` through the data dependences
//! (locals and lets carry their ready time). The cost is the
//! **critical-path-weighted** mix `(CP + ΣTP) / 2`: an operation on the
//! critical path counts twice as much as one that overlaps (design §10.2
//! "a critical-path weight"). Branches cost their throughput and weight
//! their arms by probability (½ each without a profile; the loop summarizer
//! passes trip counts from `PROFILE.json`, [`LoopRungCosts`]). A call costs
//! the callee's cost when the caller knows it, else a fixed call cost; a
//! `for` loop with literal bounds costs its trip count times its body.
//!
//! A set's cost is the **worst** over its tables: a variant set is
//! dispatched on every CPU that has its features, so a candidate must win on
//! each (the measured Zen 5 and M5 tables and the hypothesis tables alike).
//!
//! **Selection.** [`beats`] is the 3% gate ("a candidate replaces the next
//! rung only if it is ≥ 3% cheaper"); [`top`] keeps the three cheapest
//! candidates, and callers retry at most [`RETRIES`] times after a proof or
//! elaboration failure. Costs are integers (milli-cycles): deterministic.
//!
//! **Validation** (fairness audit of 2026-10-02, J12). The inputs are
//! generic per-CPU data (`cycle_ns`, `op.*`; the tuning file's `sha.*`,
//! `varint.*`, `crossover.*`, `threads.*` rows are validation rows no
//! optimizer code reads, `tests/fairness_lint.rs`). The model has been
//! checked only against three development-set decisions (`tests/opt_cost.rs`:
//! QMDB's NEON SHA lanes and shape rungs, the corpus varint), and its free
//! constants — the `(CP + ΣTP) / 2` weight, `TRY_FAIL`, the 3% gate, the
//! seeded popcount surcharge — against nothing held out. Its accuracy is to
//! be measured on a held-out decision benchmark (candidate pairs from
//! held-out functions, each with a measured winner; plan step 8), and model
//! changes gated on it as well as on the QMDB regression run.

use std::collections::HashMap;

use sandblaster_kernel::term::{PrimOp, Term, Tm};

use super::tables::{Cost, Level, MC, Op, Table};
use super::tuning::Tuning;
use crate::builtins::{Builtin, IntMethod, OptionMethod, SliceMethod};
use crate::hir::*;

/// Candidates kept after ranking (design §10.3: multi-result top-3).
pub const TOP: usize = 3;
/// Retries after a proof or elaboration failure.
pub const RETRIES: usize = 2;

/// `true` when `candidate` is at least 3% cheaper than `incumbent` (the
/// selection gate).
pub fn beats(candidate: u64, incumbent: u64) -> bool {
    candidate.saturating_mul(100) <= incumbent.saturating_mul(97)
}

/// The (stable) cheapest [`TOP`] candidates, cheapest first.
pub fn top<T>(mut cands: Vec<(u64, T)>) -> Vec<(u64, T)> {
    cands.sort_by_key(|(c, _)| *c);
    cands.truncate(TOP);
    cands
}

/// The cost model of one variant set.
#[derive(Clone, Debug)]
pub struct SetModel {
    /// The set's name (`portable`, `v3_scalar`, `sha2`, …).
    pub name: String,
    pub level: Level,
    pub tables: Vec<Table>,
}

impl SetModel {
    /// The model of a set with the (implication-closed) features
    /// `features` on `arch` (`"x86_64"` / `"aarch64"`).
    pub fn new(name: &str, arch: &str, features: &[String], tuning: &Tuning) -> SetModel {
        let level = Level::of(arch, features);
        SetModel { name: name.to_string(), level, tables: tuning.tables(level) }
    }

    /// The portable code's model on `arch`.
    pub fn portable(arch: &str, tuning: &Tuning) -> SetModel {
        SetModel::new("portable", arch, &[], tuning)
    }

    /// The cost of a function body (the worst over the tables).
    pub fn fn_cost(&self, krate: &Crate, f: &FnDef, callee: &dyn Fn(ItemId) -> Option<u64>) -> u64 {
        self.tables.iter().map(|t| Walker::new(t, krate, callee).fn_cost(f)).max().unwrap_or(0)
    }

    /// [`SetModel::fn_cost`] with each loop's **loop-carried chain** on the
    /// critical path: an iteration's longest chain times the trip count (the
    /// plain model charges a loop body's throughput only). The lowering of
    /// lifted code (`driver::lowered`) compares with it; the optimizer's own
    /// choices still use the plain model (moving them needs the QMDB
    /// regression run, DESIGN.md §8.2). Two models thus decide (fairness
    /// audit J12): structural and symmetric (source and replacement priced
    /// by the same tables), but to be unified with the plain model, or its
    /// separate use justified, on the held-out decision benchmark (plan step
    /// 8).
    pub fn fn_cost_carried(&self, krate: &Crate, f: &FnDef, callee: &dyn Fn(ItemId) -> Option<u64>) -> u64 {
        self.tables.iter().map(|t| Walker { carried: true, ..Walker::new(t, krate, callee) }.fn_cost(f)).max().unwrap_or(0)
    }

    /// The cost of an expression (the worst over the tables).
    pub fn expr_cost(&self, krate: &Crate, e: &Expr, callee: &dyn Fn(ItemId) -> Option<u64>) -> u64 {
        self.tables.iter().map(|t| Walker::new(t, krate, callee).cost_of(e)).max().unwrap_or(0)
    }

    /// The cost of a kernel term DAG (shared subterms once; the worst over
    /// the tables).
    pub fn term_cost(&self, t: &Tm, callee: &dyn Fn(&Tm) -> Option<u64>) -> u64 {
        self.tables.iter().map(|tb| term_cost_in(tb, t, callee)).max().unwrap_or(0)
    }

    /// The cost per lane of a **lane candidate** of `f` (design §14.1: the
    /// same scalar DAG lifted to `lanes` messages per 128-bit vector, every
    /// scalar operation one vector operation): what the cost model compares
    /// with the ISA variant before the lane functor (plan O10) builds the
    /// candidate. `callee` prices calls (usually the callees lifted too).
    pub fn lane_cost(&self, krate: &Crate, f: &FnDef, lanes: u32, callee: &dyn Fn(ItemId) -> Option<u64>) -> u64 {
        self.tables.iter().map(|t| Walker { vector: true, ..Walker::new(t, krate, callee) }.fn_cost(f) / u64::from(lanes.max(1))).max().unwrap_or(0)
    }

    /// The lifted cost of a whole function (not divided by the lanes; for
    /// callees of [`SetModel::lane_cost`]).
    pub fn lifted_fn_cost(&self, krate: &Crate, f: &FnDef, callee: &dyn Fn(ItemId) -> Option<u64>) -> u64 {
        self.tables.iter().map(|t| Walker { vector: true, ..Walker::new(t, krate, callee) }.fn_cost(f)).max().unwrap_or(0)
    }

    /// Per table: `(uarch, cost)` of a function body (reports).
    pub fn fn_costs(&self, krate: &Crate, f: &FnDef, callee: &dyn Fn(ItemId) -> Option<u64>) -> Vec<(&'static str, u64)> {
        self.tables.iter().map(|t| (t.uarch, Walker::new(t, krate, callee).fn_cost(f))).collect()
    }
}

/// The locals a block assigns (`x = ..`, `x op= ..`, at any depth).
fn assigned_locals(b: &Block, out: &mut Vec<LocalId>) {
    struct V<'o>(&'o mut Vec<LocalId>);
    impl crate::visit::Visitor for V<'_> {
        fn stmt(&mut self, s: &Stmt) {
            if let StmtKind::Assign { place, .. } | StmtKind::CompoundAssign { place, .. } = &s.kind
                && !self.0.contains(&place.local)
            {
                self.0.push(place.local);
            }
            crate::visit::walk_stmt(self, s);
        }
    }
    let mut v = V(out);
    for s in &b.stmts {
        crate::visit::Visitor::stmt(&mut v, s);
    }
    if let Some(t) = &b.tail {
        crate::visit::Visitor::expr(&mut v, t);
    }
}

/// `(ΣTP, CP)` of a piece of code.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Est {
    pub tp: u64,
    pub cp: u64,
}

/// The critical-path-weighted cost of an estimate.
pub fn combine(e: Est) -> u64 {
    (e.tp + e.cp) / 2
}

struct Walker<'a> {
    t: &'a Table,
    krate: &'a Crate,
    callee: &'a dyn Fn(ItemId) -> Option<u64>,
    ready: HashMap<LocalId, u64>,
    tp: u64,
    /// Price every operation as its 128-bit vector form (lane candidates).
    vector: bool,
    /// Charge each loop's loop-carried chain ([`SetModel::fn_cost_carried`]).
    carried: bool,
    /// The probability that the code being walked runs (fixed point,
    /// [`ONE`] = 1): branches split it between their arms, and an arm that
    /// returns early takes its share out of the code after it.
    w: u64,
    /// Early exits: Σ weight × readiness, and Σ weight.
    ret_cp: u128,
    ret_w: u64,
}

/// Probability 1 (fixed point).
const ONE: u64 = 1024;
/// The probability of a `?` returning early (no profile).
const TRY_FAIL: u64 = ONE / 16;

impl<'a> Walker<'a> {
    fn new(t: &'a Table, krate: &'a Crate, callee: &'a dyn Fn(ItemId) -> Option<u64>) -> Walker<'a> {
        Walker { t, krate, callee, ready: HashMap::new(), tp: 0, vector: false, w: ONE, ret_cp: 0, ret_w: 0, carried: false }
    }

    /// The expected readiness of the result: the early exits and the
    /// fall-through `cp`, each by its probability.
    fn expected_cp(&self, cp: u64) -> u64 {
        let total = u128::from(self.ret_w) + u128::from(self.w);
        if total == 0 {
            return cp;
        }
        ((self.ret_cp + u128::from(cp) * u128::from(self.w)) / total) as u64
    }

    fn fn_cost(mut self, f: &FnDef) -> u64 {
        let FnBody::Exec(b) = &f.body else { return 0 };
        let cp = self.expr(b);
        let cp = self.expected_cp(cp);
        combine(Est { tp: self.tp, cp })
    }

    fn cost_of(mut self, e: &Expr) -> u64 {
        let cp = self.expr(e);
        let cp = self.expected_cp(cp);
        combine(Est { tp: self.tp, cp })
    }

    /// Charges an operation after its operands are ready at `after`;
    /// returns its ready time.
    fn op(&mut self, c: Cost, after: u64) -> u64 {
        self.tp += c.tp * self.w / ONE;
        after + c.lat
    }

    /// Charges a throughput-only cost (a callee, a branch) at this weight.
    fn charge(&mut self, tp: u64) {
        self.tp += tp * self.w / ONE;
    }

    /// Runs `f` on an arm taken with probability `p` (of this code's) and
    /// merges its cost and early exits; returns the arm's readiness and
    /// whether it diverges.
    fn in_arm(&mut self, p: u64, f: &mut dyn FnMut(&mut Walker<'a>) -> u64) -> u64 {
        let mut a = self.arm();
        a.w = self.w * p / ONE;
        let r = f(&mut a);
        self.tp += a.tp;
        self.ret_cp += a.ret_cp;
        self.ret_w += a.ret_w;
        r
    }

    fn opk(&mut self, op: Op, after: u64) -> u64 {
        let c = if self.vector { self.t.vec_op(op) } else { self.t.op(op) };
        self.op(c, after)
    }

    /// A sub-walker for an arm (its locals start as ours).
    fn arm(&self) -> Walker<'a> {
        Walker { t: self.t, krate: self.krate, callee: self.callee, ready: self.ready.clone(), tp: 0, vector: self.vector, w: self.w, ret_cp: 0, ret_w: 0, carried: self.carried }
    }

    fn lit_u32(e: &Expr) -> bool {
        matches!(peel(e).kind, ExprKind::Lit(_))
    }

    fn args(&mut self, args: &[Expr]) -> u64 {
        args.iter().map(|a| self.expr(a)).max().unwrap_or(0)
    }

    fn expr(&mut self, e: &Expr) -> u64 {
        use ExprKind::*;
        match &e.kind {
            Lit(_) | Const(_) | BuiltinConst(_) | Unreachable => 0,
            Local(l) => self.ready.get(l).copied().unwrap_or(0),
            Call { callee, args } => {
                let r = self.args(args);
                match callee {
                    Callee::Item(id, _) => match (self.callee)(*id) {
                        Some(c) => {
                            self.charge(c);
                            r + c
                        }
                        None => self.opk(Op::Call, r),
                    },
                    Callee::Builtin(b, _) => self.builtin(*b, args, r),
                    Callee::Intrinsic(i, _) => {
                        let c = self.t.intrinsic(crate::intrinsics::get(*i).name);
                        self.op(c, r)
                    }
                    Callee::Helper(h) => {
                        let c = self.t.intrinsic(crate::intrinsics::helper(*h).name);
                        self.op(c, r)
                    }
                    Callee::Ghost(..) => r,
                }
            }
            Adt { fields, base, .. } => {
                let mut r = fields.iter().map(|(_, x)| self.expr(x)).max().unwrap_or(0);
                if let Some(b) = base {
                    r = r.max(self.expr(b));
                }
                r
            }
            Tuple(es) | Array(es) => self.args(es),
            Repeat { elem, .. } => self.expr(elem),
            Field { base, .. } | Ref(base) | Deref(base) | Coerce(_, base) => self.expr(base),
            Index { base, index } => {
                let r = self.expr(base).max(self.expr(index));
                self.opk(Op::Load, r)
            }
            SliceRange { base, lo, hi } => {
                let mut r = self.expr(base);
                for x in [lo, hi].into_iter().flatten() {
                    r = r.max(self.expr(x));
                }
                self.opk(Op::Alu, r)
            }
            Unary(_, x) => {
                let r = self.expr(x);
                self.opk(Op::Alu, r)
            }
            Binary(op, a, b) => {
                let r = self.expr(a).max(self.expr(b));
                let k = bin_op(*op, Self::lit_u32(b));
                self.opk(k, r)
            }
            Cast(x, _) => {
                let r = self.expr(x);
                self.opk(Op::Cast, r)
            }
            If { cond, then, els } => {
                let rc = self.expr(cond);
                let bt = self.t.op(Op::Branch).tp;
                self.charge(bt);
                let half = ONE / 2;
                let ra = self.in_arm(half, &mut |a| a.expr(then));
                let rb = match els {
                    Some(x) => self.in_arm(half, &mut |a| a.expr(x)),
                    None => rc,
                };
                // an arm that returns early takes its share out of the rest
                let (dt, de) = (then.ty.is_never(), els.as_ref().is_some_and(|x| x.ty.is_never()));
                let live = u64::from(!dt) + u64::from(!de);
                let r = match (dt, de) {
                    (true, false) => rb,
                    (false, true) => ra,
                    _ => (ra + rb) / 2,
                };
                self.w = self.w * live / 2;
                r.max(rc)
            }
            Match { scrut, arms, .. } => {
                let rs = self.expr(scrut);
                if arms.len() > 1 {
                    let depth = (usize::BITS - (arms.len() - 1).leading_zeros()) as u64;
                    let bt = self.t.op(Op::Branch).tp * depth + self.t.op(Op::Cmp).tp * depth;
                    self.charge(bt);
                }
                let n = arms.len().max(1) as u64;
                let (mut ready, mut live) = (0u64, 0u64);
                for a in arms {
                    let r = self.in_arm(ONE / n, &mut |w| {
                        for l in a.pat.bindings() {
                            w.ready.insert(l, rs);
                        }
                        if let Some(g) = &a.guard {
                            w.expr(g);
                        }
                        w.expr(&a.body)
                    });
                    if !a.body.ty.is_never() {
                        ready += r;
                        live += 1;
                    }
                }
                self.w = self.w * live / n;
                (ready / live.max(1)).max(rs)
            }
            Block(b) => self.block(b),
            Return(x) => {
                let r = x.as_ref().map(|x| self.expr(x)).unwrap_or(0);
                self.ret_cp += u128::from(r) * u128::from(self.w);
                self.ret_w += self.w;
                self.w = 0;
                r
            }
            Try(x) => {
                let r = self.expr(x);
                let bt = self.t.op(Op::Branch).tp;
                self.charge(bt);
                let fail = self.w * TRY_FAIL / ONE;
                self.ret_cp += u128::from(r) * u128::from(fail);
                self.ret_w += fail;
                self.w -= fail;
                r
            }
            Loop(l) => {
                let trips = match &l.kind {
                    LoopKind::ForRange { lo, hi, inclusive, .. } => match (lit_val(lo), lit_val(hi)) {
                        (Some(a), Some(b)) if b >= a => (b - a + u128::from(*inclusive)).min(1 << 20) as u64,
                        _ => 16,
                    },
                    LoopKind::While { .. } => 16,
                };
                if !self.carried {
                    let mut w = self.arm();
                    let r = w.block(&l.body);
                    let per = w.tp + (self.t.op(Op::Branch).tp + self.t.op(Op::Alu).tp) * self.w / ONE;
                    self.tp += per.saturating_mul(trips);
                    return r.saturating_mul(trips);
                }
                // one iteration in steady state: every value the body reads
                // is ready at its start; the locals it writes back are the
                // loop-carried chain, whose latency each iteration adds
                let mut w = self.arm();
                for v in w.ready.values_mut() {
                    *v = 0;
                }
                let r = w.block(&l.body);
                let per = w.tp + (self.t.op(Op::Branch).tp + self.t.op(Op::Alu).tp) * self.w / ONE;
                self.tp += per.saturating_mul(trips);
                // the chain: the longest one the iteration computes (the
                // state it writes back depends on it, directly or through
                // the branch it decides)
                let carried = w.ready.values().copied().max().unwrap_or(0).max(r);
                let mut assigned: Vec<LocalId> = Vec::new();
                assigned_locals(&l.body, &mut assigned);
                let entry = assigned.iter().filter_map(|k| self.ready.get(k).copied()).max().unwrap_or(0);
                let done = entry.saturating_add(carried.saturating_mul(trips));
                for k in assigned {
                    self.ready.insert(k, done);
                }
                done
            }
            PropEq(..) | PropNe(..) | PropAnd(..) | PropOr(..) | PropNot(..) | Implies(..) | Iff(..) | Quant { .. } | Lambda { .. } | Apply { .. } => 0,
        }
    }

    fn block(&mut self, b: &Block) -> u64 {
        let mut last = 0;
        for s in &b.stmts {
            match &s.kind {
                StmtKind::Let { pat, init, els } => {
                    let r = self.expr(init);
                    if let Some(bl) = els {
                        let bt = self.t.op(Op::Branch).tp;
                        self.charge(bt);
                        // the `else` block diverges: a small share returns
                        self.in_arm(TRY_FAIL, &mut |w| w.block(bl));
                        self.w -= self.w * TRY_FAIL / ONE;
                    }
                    for l in pat.bindings() {
                        self.ready.insert(l, r);
                    }
                }
                StmtKind::Expr(x) => last = self.expr(x),
                StmtKind::Assign { place, value } | StmtKind::CompoundAssign { place, value, .. } => {
                    let r = self.expr(value);
                    let r = if place.projs.is_empty() { r } else { self.opk(Op::Store, r) };
                    self.ready.insert(place.local, r);
                }
                StmtKind::CopyFromSlice { dst, src, .. } => {
                    let r = self.expr(src);
                    let r = self.opk(Op::Load, r);
                    let r = self.opk(Op::Store, r);
                    self.ready.insert(*dst, r);
                }
                StmtKind::Proof(_) => {}
            }
        }
        match &b.tail {
            Some(t) => self.expr(t),
            None => last,
        }
    }

    fn builtin(&mut self, b: Builtin, args: &[Expr], r: u64) -> u64 {
        use IntMethod::*;
        match b {
            Builtin::Int(m, _) => match m {
                WrappingAdd | WrappingSub | WrappingNeg => self.opk(Op::Alu, r),
                WrappingMul => self.opk(Op::Mul, r),
                Pow => {
                    let r = self.opk(Op::Mul, r);
                    self.opk(Op::Mul, r)
                }
                WrappingShl | WrappingShr => self.opk(if args.get(1).is_some_and(Self::lit_u32) { Op::ShiftImm } else { Op::ShiftVar }, r),
                RotateLeft | RotateRight => self.opk(Op::Rotate, r),
                CheckedAdd | CheckedSub | SaturatingAdd | SaturatingSub => {
                    let r = self.opk(Op::Alu, r);
                    self.opk(Op::Select, r)
                }
                CheckedMul | SaturatingMul => {
                    let r = self.opk(Op::Mul, r);
                    self.opk(Op::Select, r)
                }
                CheckedDiv | DivCeil => self.opk(Op::Div, r),
                Min | Max => {
                    let r = self.opk(Op::Cmp, r);
                    self.opk(Op::Select, r)
                }
                AbsDiff => {
                    let r = self.opk(Op::Alu, r);
                    self.opk(Op::Select, r)
                }
                CountOnes => self.opk(Op::Popcnt, r),
                LeadingZeros => self.opk(Op::Lzcnt, r),
                TrailingZeros => self.opk(Op::Tzcnt, r),
                IsPowerOfTwo => {
                    let r = self.opk(Op::Alu, r);
                    self.opk(Op::Cmp, r)
                }
                SwapBytes | ToBeBytes | FromBeBytes => self.opk(Op::Bswap, r),
                ToLeBytes | FromLeBytes => r,
            },
            Builtin::Slice(m) => match m {
                SliceMethod::Len => r,
                SliceMethod::IsEmpty => self.opk(Op::Cmp, r),
                SliceMethod::Get | SliceMethod::First | SliceMethod::Last => {
                    let r = self.opk(Op::Cmp, r);
                    self.opk(Op::Load, r)
                }
                _ => {
                    let r = self.opk(Op::Cmp, r);
                    self.opk(Op::Alu, r)
                }
            },
            Builtin::Array(_) => r,
            Builtin::Option(OptionMethod::IsSome | OptionMethod::IsNone) => self.opk(Op::Cmp, r),
            Builtin::Option(OptionMethod::UnwrapOr) => self.opk(Op::Select, r),
            Builtin::Bin(op, _) => self.opk(bin_op(op, args.get(1).is_some_and(Self::lit_u32)), r),
            Builtin::Shift { .. } => self.opk(if args.get(1).is_some_and(Self::lit_u32) { Op::ShiftImm } else { Op::ShiftVar }, r),
            Builtin::Not(_) => self.opk(Op::Alu, r),
            Builtin::Neg => r,
            Builtin::StructEq { .. } => self.opk(Op::Cmp, r),
            Builtin::Cast { .. } => self.opk(Op::Cast, r),
            Builtin::Index { .. } => self.opk(Op::Load, r),
            Builtin::SliceRange { .. } => self.opk(Op::Alu, r),
            Builtin::CopyFromSlice => {
                let r = self.opk(Op::Load, r);
                self.opk(Op::Store, r)
            }
        }
    }
}

fn peel(e: &Expr) -> &Expr {
    match &e.kind {
        ExprKind::Coerce(_, x) | ExprKind::Cast(x, _) => peel(x),
        _ => e,
    }
}

fn lit_val(e: &Expr) -> Option<u128> {
    match &peel(e).kind {
        ExprKind::Lit(Lit::Int(v)) => Some(*v),
        _ => None,
    }
}

fn bin_op(op: BinOp, lit_rhs: bool) -> Op {
    use BinOp::*;
    match op {
        Add | Sub | BitAnd | BitOr | BitXor => Op::Alu,
        Mul => Op::Mul,
        Div | Rem => Op::Div,
        Shl | Shr => {
            if lit_rhs {
                Op::ShiftImm
            } else {
                Op::ShiftVar
            }
        }
        Eq | Ne | Lt | Le | Gt | Ge => Op::Cmp,
        And | Or => Op::Select,
    }
}

/// The operation class of a primitive (`None`: free, e.g. a width change
/// the machine does for nothing is still `Cast`).
pub fn prim_op(op: &PrimOp, lit_amount: bool) -> Op {
    use PrimOp::*;
    match op {
        WAdd(_) | WSub(_) | WNeg(_) | And(_) | Or(_) | Xor(_) | Not(_) | Add(_) | Sub(_) | IAdd | ISub | INeg => Op::Alu,
        WMul(_) | Mul(_) | IMul => Op::Mul,
        Div(_) | Rem(_) | IDiv | IMod => Op::Div,
        WShl(_) | WShr(_) | Shl(_) | Shr(_) => {
            if lit_amount {
                Op::ShiftImm
            } else {
                Op::ShiftVar
            }
        }
        Rotl(_) | Rotr(_) => Op::Rotate,
        Min(_) | Max(_) | SatAdd(_) | SatSub(_) | SatMul(_) => Op::Select,
        CountOnes(_) => Op::Popcnt,
        LeadingZeros(_) => Op::Lzcnt,
        TrailingZeros(_) => Op::Tzcnt,
        SwapBytes(_) => Op::Bswap,
        Eq(_) | Ne(_) | Lt(_) | Le(_) | Gt(_) | Ge(_) => Op::Cmp,
        Cast { .. } | IntToSat(_) | OfInt(_) => Op::Cast,
    }
}

/// The cost of a kernel term DAG under one table: every distinct
/// primitive node once (`ΣTP`), the critical path through the DAG, matches
/// as branches with uniform arms, applications of globals at `callee`'s cost
/// (else a call).
fn term_cost_in(t: &Table, root: &Tm, callee: &dyn Fn(&Tm) -> Option<u64>) -> u64 {
    struct W<'a> {
        t: &'a Table,
        callee: &'a dyn Fn(&Tm) -> Option<u64>,
        memo: HashMap<*const Term, u64>,
        tp: u64,
    }
    impl W<'_> {
        fn go(&mut self, x: &Tm) -> u64 {
            let key = std::rc::Rc::as_ptr(x);
            if let Some(r) = self.memo.get(&key) {
                return *r;
            }
            let r = match &**x {
                Term::Prim { op, args, .. } => {
                    let lit = matches!(args.get(1).map(|a| &**a), Some(Term::Lit { .. }));
                    let r = args.iter().map(|a| self.go(a)).max().unwrap_or(0);
                    let c = self.t.op(prim_op(op, lit));
                    self.tp += c.tp;
                    r + c.lat
                }
                Term::App { .. } => {
                    let (head, args) = spine(x);
                    let r = args.iter().map(|a| self.go(a)).max().unwrap_or(0);
                    if matches!(&*head, Term::Global(_)) {
                        match (self.callee)(&head) {
                            Some(c) => {
                                self.tp += c;
                                r + c
                            }
                            None => {
                                let c = self.t.op(Op::Call);
                                self.tp += c.tp;
                                r + c.lat
                            }
                        }
                    } else {
                        // a match or λ applied (to its path equation): its body
                        r.max(self.go(&head))
                    }
                }
                Term::Let { val, body, .. } => {
                    let a = self.go(val);
                    a.max(self.go(body))
                }
                Term::Match { scrut, arms, .. } => {
                    let rs = self.go(scrut);
                    let n = arms.len().max(1) as u64;
                    let before = self.tp;
                    let mut ready = 0;
                    for a in arms {
                        ready += self.go(&a.body);
                    }
                    let arm_tp = self.tp - before;
                    self.tp = before + arm_tp / n + self.t.op(Op::Branch).tp;
                    (ready / n).max(rs)
                }
                Term::Ctor { args, .. } => args.iter().map(|a| self.go(a)).max().unwrap_or(0),
                // a tail call of the loop itself: its new state, then a jump
                Term::Rec { args, .. } => {
                    let r = args.iter().map(|a| self.go(a)).max().unwrap_or(0);
                    self.tp += self.t.op(Op::Branch).tp;
                    r
                }
                Term::Snd(p) => self.go(p),
                Term::Pair { fst, .. } => self.go(fst),
                Term::Fst(p) => self.go(p),
                Term::Lam { body, .. } => self.go(body),
                _ => 0,
            };
            self.memo.insert(key, r);
            r
        }
    }
    let mut w = W { t, callee, memo: HashMap::new(), tp: 0 };
    let cp = w.go(root);
    combine(Est { tp: w.tp, cp })
}

fn spine(t: &Tm) -> (Tm, Vec<Tm>) {
    let mut args = Vec::new();
    let mut h = t.clone();
    while let Term::App { fun, arg, rel } = &*h {
        if *rel == sandblaster_kernel::term::Rel::Rel {
            args.push(arg.clone());
        }
        let f = fun.clone();
        h = f;
    }
    args.reverse();
    (h, args)
}

/// The costs of a loop's rungs (design §7.6, §10.2): what the loop
/// summarizer compares before building one. Per-iteration costs come from
/// one symbolic iteration, trip counts from the traces (profile samples and
/// corners).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LoopRungCosts {
    /// `(rung, cost)` for each rung that can be priced, in ladder order.
    pub rungs: Vec<(crate::opt::Rung, u64)>,
}

impl LoopRungCosts {
    /// The rungs in the order to try them: the ladder order, except that a
    /// weaker rung goes first when it is ≥ 3% cheaper than every stronger
    /// rung (the selection gate); the top [`TOP`] only.
    pub fn order(&self) -> Vec<crate::opt::Rung> {
        let mut out: Vec<(crate::opt::Rung, u64)> = Vec::new();
        let mut rest = self.rungs.clone();
        while !rest.is_empty() && out.len() < TOP {
            // the strongest remaining rung, unless a weaker one beats it
            let mut pick = 0;
            for i in 1..rest.len() {
                if beats(rest[i].1, rest[pick].1) {
                    pick = i;
                }
            }
            out.push(rest.remove(pick));
        }
        out.into_iter().map(|(r, _)| r).collect()
    }

    /// The report line.
    pub fn describe(&self) -> String {
        self.rungs.iter().map(|(r, c)| format!("{} {}", r.name(), fmt_mc(*c))).collect::<Vec<_>>().join(", ")
    }
}

/// A cost in cycles with three decimals (reports).
pub fn fmt_mc(c: u64) -> String {
    format!("{}.{:03} cycles", c / MC, c % MC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opt::Rung;

    #[test]
    fn the_gate_is_three_percent() {
        assert!(beats(97, 100));
        assert!(!beats(98, 100));
        assert!(beats(0, 0));
        assert!(!beats(1, 0));
    }

    #[test]
    fn rungs_keep_the_ladder_unless_a_weaker_one_is_cheaper() {
        let c = LoopRungCosts { rungs: vec![(Rung::ClosedForm, 10_000), (Rung::EarlyExit, 40_000), (Rung::SetBits, 30_000)] };
        assert_eq!(c.order(), vec![Rung::ClosedForm, Rung::SetBits, Rung::EarlyExit]);
        let c = LoopRungCosts { rungs: vec![(Rung::ClosedForm, 10_000), (Rung::EarlyExit, 9_800)] };
        assert_eq!(c.order(), vec![Rung::ClosedForm, Rung::EarlyExit], "2% is not enough");
        let c = LoopRungCosts { rungs: vec![(Rung::ClosedForm, 10_000), (Rung::EarlyExit, 9_000)] };
        assert_eq!(c.order(), vec![Rung::EarlyExit, Rung::ClosedForm]);
    }
}
