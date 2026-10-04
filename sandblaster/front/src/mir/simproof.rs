//! Simulation proofs between the structured reading and the literal reading
//! (`docs/checked-structuring.md` §5; UNTRUSTED: every term built here is
//! checked by the kernel).
//!
//! The trusted statement of a lifted function `f` ([`super::stmt`]):
//!
//! ```text
//! L::thm::<f> : Π x̄ (.h̄ : pre). Σ (k : Int). Π (n : List(Unit)) (.hle : k ≤ len n).
//!     Eq(Option(Out), L::<f>::run n b0 (Some(init(x̄))), Some(erase(S_f x̄ .h̄)))
//! ```
//!
//! is proven from untrusted intermediate lemmas whose fuel is explicit:
//!
//! * a function: `Π x̄ h̄ (n) (.hle : W(x̄) ≤ len n). Eq(.., run n b0 (Some init), Some(erase(S_f x̄)))`,
//!   where `W` (the **fuel shadow**) is the structured body with every tail
//!   replaced by the fuel it needs (0 for a value, `μ_h(ā) + 1` for a call of a
//!   loop helper `h` with measure `μ_h`), so a fuel-independent function holds
//!   at every fuel;
//! * a loop helper `h` (the structured reading's tail-recursive helper of the
//!   loop with header `H`): `Π p̄ (j̄ : the dead slots) (n) (.hle : μ_h(p̄) ≤ len n).
//!   Eq(.., run n H (Some σ(p̄, j̄)), Some(erase(h p̄)))`, by measure recursion
//!   with `h`'s own measure and **its own decrease proofs** (the induction
//!   hypothesis at each recursive call of `h`).
//!
//! The proof walks the structured reading's body and mirrors its binders:
//! `let`s are bound again, dependent matches split the goal (the literal
//! side is abstracted by evaluation, the structured side at its own match as
//! `f::ensures` does, `M(y) e`), `absurd` leaves reuse their proofs. The
//! literal side is moved with the facts: a test decided by a path equation
//! or by an obligation proof of the structured reading (transport), a
//! wrapping operation moved onto the structured reading's checked one
//! (`bits::w*_exact` with the obligation proof), a call of a lifted
//! function replaced by its callee lemma, a backward jump split on the fuel.

use std::rc::Rc;

use sandblaster_kernel::api::{Ctx, CtxEntry, Env};
use sandblaster_kernel::term::{Arm, GlobalId, Idx, IndId, Name, PrimOp, Rel, Term, Tm, Width};
use sandblaster_kernel::util::{mk, shift, shift_from};
use sandblaster_kernel::value::{Arg, Budget, Elim, EnvEntry, Head, V, Value};

use crate::auto::util::prefix;

/// Statistics of one theorem.
#[derive(Default, Debug, Clone)]
pub struct Stats {
    pub s_splits: usize,
    pub l_splits: usize,
    pub fuel_splits: usize,
    pub eta_splits: usize,
    pub transports: usize,
    pub reused_proofs: usize,
    pub callee_lemmas: usize,
    pub helper_lemmas: usize,
    pub inductions: usize,
    pub absurds: usize,
    pub leaves: usize,
    pub refuted: usize,
    pub literal_etas: usize,
    pub inlined: usize,
    pub unfolds: usize,
    pub bv_repairs: usize,
}

/// A fact available to the walker (a proof term and its type, in the
/// current context).
#[derive(Clone)]
pub struct Fact {
    pub proof: Tm,
    pub ty: Tm,
    /// An obligation proof of the structured reading (reused).
    pub reused: bool,
    /// The checked primitive the proof belongs to: (op, a, b).
    pub bridge: Option<(PrimOp, Tm, Tm)>,
    /// A call of a lifted function in the structured reading: (global, args).
    pub call: Option<(GlobalId, Vec<(Rel, Tm)>)>,
    /// A self-call of the function being proven (non-tail recursion): its
    /// arguments (committed) and the structured reading's decrease proof.
    pub rec_call: Option<(Vec<(Rel, Tm)>, Tm)>,
    /// The induction hypothesis was applied at these arguments.
    pub ih_done: Option<Vec<(Rel, Tm)>>,
    /// A callee lemma was applied at this call (not retried in the branch).
    pub call_done: Option<(GlobalId, Vec<(Rel, Tm)>)>,
    /// A `let` of the structured reading walked: its variable and its value
    /// (the term; the context holds only its value), for rewriting facts.
    pub letdef: Option<(Tm, Tm)>,
}

type Args = Vec<(Rel, Tm)>;

fn shift_args(a: &Args, k: i64) -> Args {
    a.iter().map(|(r, t)| (*r, shift(t, k))).collect()
}

impl Fact {
    fn shifted(&self, k: i64) -> Fact {
        Fact {
            proof: shift(&self.proof, k),
            ty: shift(&self.ty, k),
            reused: self.reused,
            bridge: self.bridge.as_ref().map(|(o, a, b)| (*o, shift(a, k), shift(b, k))),
            call: self.call.as_ref().map(|(g, a)| (*g, shift_args(a, k))),
            rec_call: self.rec_call.as_ref().map(|(a, p)| (shift_args(a, k), shift(p, k))),
            ih_done: self.ih_done.as_ref().map(|a| shift_args(a, k)),
            call_done: self.call_done.as_ref().map(|(g, a)| (*g, shift_args(a, k))),
            letdef: self.letdef.as_ref().map(|(x, v)| (shift(x, k), shift(v, k))),
        }
    }
    pub fn eq(proof: Tm, ty: Tm) -> Fact {
        Fact { proof, ty, reused: false, bridge: None, call: None, rec_call: None, ih_done: None, call_done: None, letdef: None }
    }
    /// A bookkeeping fact (`tt : Unit`).
    fn marker(tt: Tm, unit: Tm) -> Fact {
        Fact::eq(tt, unit)
    }
    /// A bookkeeping fact (a call, a self-call, an applied hypothesis), not a proof.
    fn is_marker(&self) -> bool {
        self.call.is_some() || self.rec_call.is_some() || self.ih_done.is_some() || self.call_done.is_some() || self.letdef.is_some()
    }
}

/// The goal: `run(n, b, os)` (`l`, with `n` a context variable) against the
/// structured term `s`; `ins` are the inputs of the presence conjunct
/// (an `Option<&mut T>` parameter per optional cell, see [`Pres`]).
#[derive(Clone)]
pub struct Goal {
    pub l: Tm,
    pub s: Tm,
    pub ins: Vec<Tm>,
    /// Inside a terminal, the equation's right side once a split has
    /// abstracted a test in it (`None`: `Some(erase(s))`).
    pub rhs: Option<Tm>,
    /// The fuel the calls of the `let`s already walked need (fuel-dependent
    /// callees: their lemmas apply at the terminals, from the premise).
    pub acc: Option<Tm>,
}

impl Goal {
    pub fn new(l: Tm, s: Tm, ins: Vec<Tm>) -> Goal {
        Goal { l, s, ins, rhs: None, acc: None }
    }
    /// The goal with new sides, its inputs (right side, accumulated need)
    /// shifted by `k` binders.
    fn with(&self, l: Tm, s: Tm, k: i64) -> Goal {
        Goal { l, s, ins: self.ins.iter().map(|t| shift(t, k)).collect(), rhs: self.rhs.as_ref().map(|t| shift(t, k)), acc: self.acc.as_ref().map(|t| shift(t, k)) }
    }
    fn shifted(&self, k: i64) -> Goal {
        self.with(shift(&self.l, k), shift(&self.s, k), k)
    }
}

/// The presence conjunct of a function with `Option<&mut T>` parameters:
/// for each, the structured reading's final value is present exactly when
/// the argument is (`Eq(Bool, is_some(x_p), is_some(proj_j(S x̄)))`). The
/// literal reading keeps a present referent present (a write-back never
/// removes it); the conjunct makes that fact available about S's results
/// at calls (the induction hypothesis, callee lemmas).
#[derive(Clone)]
pub struct Pres {
    /// Per optional cell: its component in S's result tuple, the referent's
    /// type (the `T` of `Option(T)`) and the index of its parameter among
    /// the relevant ones.
    pub cells: Vec<(usize, Tm, usize)>,
    /// S's result type (a tuple when it has several components).
    pub r_ty: Tm,
}

impl Pres {
    /// The presence inputs: each cell's argument among the relevant ones.
    pub fn ins(&self, rel_args: &[Tm]) -> Vec<Tm> {
        self.cells.iter().map(|c| rel_args[c.2].clone()).collect()
    }
}

/// A function lemma by measure recursion (non-tail self-calls): the fuel
/// need is `mult · μ(x̄)`, `mult` the number of self-call sites (each one
/// consumes a unit of fuel and calls on a smaller measure).
#[derive(Clone)]
pub struct RecFn {
    /// S's measure over its parameters (arity `nparams`).
    pub measure: Tm,
    pub width: Width,
    pub mult: i64,
    pub nparams: u32,
    pub rels: Vec<Rel>,
    /// `run n b0 (Some init(x̄))` over (relevant x̄, n).
    pub l_of: Tm,
}

/// A lifted callee with its lemma: `Π x̄ h̄ (n) (.hle : W(x̄) ≤ len n).
/// Eq(Opt_g, run_g n b0 (Some init_g(x̄)), Some(erase_g(g x̄ h̄)))` (with the
/// presence conjunct when `g` has optional cells: a `Sigma`).
#[derive(Clone)]
pub struct Callee {
    pub s_global: GlobalId,
    pub lemma: GlobalId,
    /// The callee's telescope relevances.
    pub rels: Vec<Rel>,
    /// `run_g n b0 (Some init_g(x̄))` as a term over (relevant x̄, n).
    pub l_of: Tm,
    pub out_ty: Tm,
    pub erase: Tm,
    /// The fuel the lemma needs over the callee's whole telescope (`None`:
    /// none, the lemma holds at every fuel).
    pub need: Option<Tm>,
    /// The callee's presence conjunct (its optional cells).
    pub pres: Option<Pres>,
    /// A panic-explicit reading's lemma (the panic statement, DESIGN.md
    /// §8.2 item 12): the callee's result is `Option(R)` (this `R`), its
    /// lemma's right side `match g x̄ with None => None | Some(y) => Some(erase_g y)`.
    pub panic: Option<Tm>,
}

/// A loop helper of the structured reading with its lemma.
#[derive(Clone)]
pub struct Helper {
    pub s_global: GlobalId,
    pub lemma: GlobalId,
    /// The helper's measure over its parameters (arity `nparams`).
    pub measure: Tm,
    pub nparams: u32,
    pub rels: Vec<Rel>,
    /// The state slots that are the lemma's junk binders (in order).
    pub junk: Vec<usize>,
    pub nslots: usize,
    /// The header block's constructor index in `Blk`.
    pub header_ctor: u32,
    /// The measure's type (`Int` or a machine width).
    pub width: Width,
    /// Its fuel function (a function with nested loops), else its measure is
    /// the fuel its loop needs.
    pub fuel: Option<Fuel>,
}

/// The fuel function of a loop helper in a function with nested loops:
/// `F(p̄)`, the literal side's fuel the loop needs from its header (one unit
/// per recursive call, the fuel of the inner loops' runs, and `e` at the
/// exit), defined by the helper's own recursion (its measure and decrease
/// proofs, `Walker::shadow_f`), opaque; `nn : Π p̄. 0 ≤ F(p̄)`. `e` is 1 when
/// the loop's exit jumps to an outer loop's header (which consumes fuel).
#[derive(Clone)]
pub struct Fuel {
    pub f: GlobalId,
    pub nn: GlobalId,
    pub e: i64,
}

/// How [`Walker::shadow_f`] reads a helper's recursive calls and exits.
pub struct FuelMode {
    /// The fuel function a recursive call needs, `F(args)`; `None`: the
    /// recursive call itself (the fuel function's own body).
    pub f: Option<GlobalId>,
    pub rels: Vec<Rel>,
    /// The fuel the loop's exit needs.
    pub e: i64,
}

/// A `while` loop's helper of the structured reading (the elaborator's
/// `<f>::loop#k`): it returns the variables the loop assigns, and the
/// function goes on after it. Its lemma ([`ExitMode`]) runs the literal side
/// from the loop header to the loop's exit and hands over to a
/// continuation:
///
/// ```text
/// Π p̄ j̄ (n) (C : Option(Out)) (hC : Π m (.hm : len n − μ(p̄) ≤ len m) k̄.
///     Eq(run m X (Some σ_X(h p̄, w̄)), C)) (.hle : μ(p̄) ≤ len n).
///   Eq(run n H (Some σ(p̄, j̄)), C)
/// ```
///
/// With a fuel function `F` (nested loops) the continuation's fuel is a
/// reserve `R` the caller chooses (the fuel the rest of its body needs):
///
/// ```text
/// Π p̄ j̄ (n) (R : Int) (C) (hC : Π m (.hm : R ≤ len m) k̄. ..) (.hR : 0 ≤ R)
///     (.hle : F(p̄) + R ≤ len n). Eq(run n H (Some σ(p̄, j̄)), C)
/// ```
#[derive(Clone)]
pub struct WhileHelper {
    pub s_global: GlobalId,
    pub lemma: GlobalId,
    pub measure: Tm,
    pub width: Width,
    pub nparams: u32,
    pub rels: Vec<Rel>,
    pub header_ctor: u32,
    /// The state slots that are the lemma's junk binders (in order).
    pub junk: Vec<usize>,
    pub fuel: Option<Fuel>,
}

impl WhileHelper {
    pub fn mu_int(&self, args: &[Tm]) -> Tm {
        let mu = crate::opt::proof::steps::subst_n(&self.measure, args);
        if self.width == Width::Int { mu } else { mk::prim(PrimOp::Cast { from: self.width, to: Width::Int }, vec![mu], vec![]) }
    }

    /// The fuel the loop needs at `args`: its fuel function's, else its measure.
    pub fn need_int(&self, args: &[Tm]) -> Tm {
        match &self.fuel {
            Some(fu) => mk::apps(mk::global(fu.f), self.rels.iter().copied().zip(args.iter().cloned())),
            None => self.mu_int(args),
        }
    }
}

/// The walk of a `while` loop's lemma (see [`WhileHelper`]): its goals are
/// `Π(.eqS : Eq(R, h p̄, S)). Eq(Opt, l, C)` (`S` the helper's body as the
/// walk splits it); an exit hands the literal side, stepped to the exit
/// block, to `hC` (along `eqS`), a recursive call is the induction
/// hypothesis with the continuation moved along `eqS`.
#[derive(Clone)]
pub struct ExitMode {
    /// The exit block's constructor in `Blk`.
    pub x_ctor: u32,
    /// The helper's result type (closed).
    pub r_ty: Tm,
    /// `λ (c̄ : T̄) (w̄ : Option(T)..). Some(st(..))`: the state at the exit
    /// with the loop's variables `c̄` (the components of the helper's
    /// result) and the other slots `w̄` (closed).
    pub sx: Tm,
    /// The types of the result's components (closed), and the result's
    /// tuple type when it has more than one (its inductive and parameters).
    pub comps: Vec<Tm>,
    pub tuple: Option<(IndId, Vec<Tm>)>,
    /// The slots `w̄` per non-carried slot: a term over the lemma's first
    /// `e0` binders (p̄, j̄), or `None` for a slot the loop assigns (the
    /// continuation's binder).
    pub w: Vec<Option<Tm>>,
    /// The slot of each entry of `w`.
    pub w_slots: Vec<usize>,
    pub e0: u32,
    /// The levels of `C` and `hC`.
    pub c_level: u32,
    pub hc_level: u32,
    /// With a fuel function: the levels of the reserve `R` and of `hR`.
    pub r_level: Option<u32>,
    pub hr_level: Option<u32>,
    /// The types of the continuation's binders for the slots the loop
    /// assigns (closed `Option(T)`).
    pub k_tys: Vec<Tm>,
    /// (internal) the level of `eqS` at the current tail.
    pub eqs_level: Option<u32>,
}

impl Helper {
    /// The helper's parameters (the lemma's first binders) at depth `d`.
    pub fn params_at(&self, d: u32) -> Vec<Tm> {
        (0..self.nparams).map(|l| mk::var(d - 1 - l)).collect()
    }

    /// The measure at `args` as an `Int` (a machine-width measure cast).
    pub fn mu_int(&self, args: &[Tm]) -> Tm {
        let mu = crate::opt::proof::steps::subst_n(&self.measure, args);
        if self.width == Width::Int { mu } else { mk::prim(PrimOp::Cast { from: self.width, to: Width::Int }, vec![mu], vec![]) }
    }

    /// The fuel the loop needs at `args`: its fuel function's, else its measure.
    pub fn need_int(&self, args: &[Tm]) -> Tm {
        match &self.fuel {
            Some(fu) => mk::apps(mk::global(fu.f), self.rels.iter().copied().zip(args.iter().cloned())),
            None => self.mu_int(args),
        }
    }
}

/// The recursive lemma being proven (loop lemma mode).
#[derive(Clone)]
pub struct RecCtx {
    pub helper: Helper,
}

impl RecFn {
    /// The measure at `args` as an `Int` (a machine-width measure cast).
    pub fn mu_int(&self, args: &[Tm]) -> Tm {
        let mu = crate::opt::proof::steps::subst_n(&self.measure, args);
        if self.width == Width::Int { mu } else { mk::prim(PrimOp::Cast { from: self.width, to: Width::Int }, vec![mu], vec![]) }
    }
    /// The fuel need at `args`: `mult · μ(args)`.
    pub fn need(&self, args: &[Tm]) -> Tm {
        mk::prim(PrimOp::IMul, vec![mk::lit(Width::Int, self.mult), self.mu_int(args)], vec![])
    }
}

pub struct Walker<'e> {
    pub env: &'e Env,
    pub out_ty: Tm,
    /// `λ (y : R_S). erase(y)`.
    pub erase: Tm,
    pub stats: Stats,
    pub budget: u64,
    pub trace: bool,
    /// The literal reading's runs (unfolded to find a blocking test).
    pub l_runs: Vec<GlobalId>,
    /// Context levels still to split by eta.
    pub eta_vars: Vec<u32>,
    /// Context level of the fuel variable (the literal reading's current
    /// fuel: a fuel split moves it to the tail of the list).
    pub n_level: u32,
    pub callees: Vec<Callee>,
    pub helpers: Vec<Helper>,
    /// Loop lemma mode: the premise is the helper's measure.
    pub rec: Option<RecCtx>,
    /// Function lemma by measure recursion (non-tail self-calls).
    pub rec_fn: Option<RecFn>,
    /// The fuel premise is a hypothesis of the context (introduced before
    /// the walk), not part of the goals.
    pub prem_in_ctx: bool,
    /// The presence conjunct of the function being proven.
    pub pres: Option<Pres>,
    /// The structured function being walked: its recursive calls (`Rec`
    /// in the pre-commit body) are this global in goals.
    pub s_self: Option<(GlobalId, Vec<Rel>)>,
    /// Globals kept folded when the literal side is stepped one block.
    pub opaque: Vec<GlobalId>,
    /// The literal run of the function being proven (never kept folded).
    pub s_self_run: Option<GlobalId>,
    /// (internal) runs of callees whose lemmas wait for the premise (a
    /// terminal): not unfolded meanwhile, so the lemma still finds the call.
    pub frozen: Vec<GlobalId>,
    /// (internal) the literal side is at a loop header: runs stay folded.
    pub at_header: bool,
    /// Diagnostics: the function and where the walk is (S's splits, lets,
    /// tails).
    pub fname: String,
    pub path: Vec<String>,
    /// The per-function budget: a deadline and a number of walk steps.
    pub deadline: Option<std::time::Instant>,
    pub max_steps: usize,
    pub steps: usize,
    /// The `while` helpers with their lemmas.
    pub whiles: Vec<WhileHelper>,
    /// A `while` lemma's walk.
    pub exit: Option<ExitMode>,
    /// The panic statement (DESIGN.md §8.2 item 12): the structured term is
    /// a panic-explicit reading's (`Option(R)`, this `R`), the equation's
    /// right side `match s with None => None | Some(y) => Some(erase(y))`.
    pub panic: Option<Tm>,
}

fn name(s: &str) -> Name {
    Rc::from(s)
}

fn trunc(s: &str, n: usize) -> String {
    if s.len() > n { format!("{}..", &s[..n]) } else { s.to_string() }
}

impl<'e> Walker<'e> {
    fn b(&self) -> Budget {
        Budget { steps: self.budget }
    }

    pub fn eval(&self, ctx: &Ctx, t: &Tm) -> Result<V, String> {
        let mut b = self.b();
        self.env.eval(&self.env.ctx_venv(ctx), ctx.depth(), t, &mut b).map_err(|e| format!("eval: {e:?}"))
    }

    fn quote(&self, ctx: &Ctx, v: &V) -> Tm {
        self.env.quote_typed(ctx, v, None, true)
    }

    fn conv(&self, ctx: &Ctx, a: &V, b: &V) -> bool {
        let mut bu = self.b();
        self.env.conv(ctx.depth(), a, b, &mut bu).unwrap_or(false)
    }

    pub fn push(&self, ctx: &Ctx, n: &str, rel: Rel, ty: &Tm, def: Option<&Tm>) -> Result<Ctx, String> {
        let tyv = self.eval(ctx, ty)?;
        let d = match def {
            Some(v) => Some(match rel {
                Rel::Rel => Arg::Rel(self.eval(ctx, v)?),
                Rel::Irr => Arg::Irr(sandblaster_kernel::value::Closure { env: self.env.ctx_venv(ctx), body: v.clone() }),
            }),
            None => None,
        };
        Ok(ctx.push(CtxEntry { name: name(n), rel, ty: tyv, def: d }))
    }

    fn g(&self, n: &str) -> Result<GlobalId, String> {
        self.env.lookup_global(n).ok_or_else(|| format!("no global `{n}`"))
    }
    fn ind(&self, n: &str) -> IndId {
        self.env.lookup_ind(n).unwrap_or_else(|| panic!("no inductive {n}"))
    }
    fn unit_ty(&self) -> Tm {
        mk::ind(self.ind("Unit"), vec![])
    }
    fn tt(&self) -> Tm {
        Rc::new(Term::Ctor { ind: self.ind("Unit"), ctor: 0, params: vec![], args: vec![] })
    }
    pub fn list_unit(&self) -> Tm {
        mk::ind(self.ind("List"), vec![self.unit_ty()])
    }
    fn opt_out(&self) -> Tm {
        mk::ind(self.ind("Option"), vec![self.out_ty.clone()])
    }
    fn some_out(&self, v: Tm) -> Tm {
        Rc::new(Term::Ctor { ind: self.ind("Option"), ctor: 1, params: vec![self.out_ty.clone()], args: vec![v] })
    }
    pub(crate) fn len_n(&self, depth: u32) -> Tm {
        let ni = depth - 1 - self.n_level;
        mk::apps(mk::global(self.g("seq::len").unwrap()), vec![(Rel::Rel, self.unit_ty()), (Rel::Rel, mk::var(ni))])
    }
    pub(crate) fn int_lit(&self, k: i64) -> Tm {
        mk::lit(Width::Int, k)
    }
    pub(crate) fn le_int(&self, a: Tm, b: Tm) -> Tm {
        mk::eq_bool(self.env.bool_ind(), mk::prim(PrimOp::Le(Width::Int), vec![a, b], vec![]), true)
    }

    /// The structured term in committed form (`Rec` as the helper itself).
    pub fn commit(&self, t: &Tm) -> Tm {
        let Some((h, rels)) = &self.s_self else { return t.clone() };
        let (h, rels) = (*h, rels.clone());
        crate::auto::util::map_term(t, 0, &mut |x, _d| match &**x {
            Term::Rec { args, .. } => Some(mk::apps(mk::global(h), args.iter().enumerate().map(|(i, a)| (rels.get(i).copied().unwrap_or(Rel::Rel), self.commit(a))))),
            _ => None,
        })
    }

    /// The fuel the structured term needs (an `Int` term in the context).
    /// [`Self::need`] with the accumulated need of the `let`s walked.
    pub(crate) fn need_acc(&self, ctx: &Ctx, s: &Tm, acc: Option<&Tm>) -> Tm {
        if let Some(r) = &self.rec {
            // nested loops: the fuel the rest of the body needs from here
            // (`F` at the recursive calls), and a `while` lemma's reserve
            if let Some(fu) = &r.helper.fuel {
                let w = self.shadow_f(s, acc, &FuelMode { f: Some(fu.f), rels: r.helper.rels.clone(), e: fu.e });
                return match self.exit.as_ref().and_then(|x| x.r_level) {
                    Some(rl) => mk::prim(PrimOp::IAdd, vec![w, mk::var(ctx.depth().0 - 1 - rl)], vec![]),
                    None => w,
                };
            }
            // the helper's measure at its own parameters (the outermost binders)
            let args = r.helper.params_at(ctx.depth().0);
            return r.helper.mu_int(&args);
        }
        if let Some(rf) = &self.rec_fn {
            let d = ctx.depth().0;
            let args: Vec<Tm> = (0..rf.nparams).map(|l| mk::var(d - 1 - l)).collect();
            return rf.need(&args);
        }
        self.shadow_acc(s, acc)
    }

    /// The fuel shadow of a structured term: its control structure with the
    /// fuel each tail needs.
    pub fn shadow(&self, t: &Tm) -> Tm {
        self.shadow_acc(t, None)
    }

    /// The fuel shadow with `acc`, the need of the fuel-dependent calls of
    /// the `let`s already walked: a `let`'s calls are added to it under the
    /// `let` (`let x = v; shadow(b, acc + W(v))`, so the walk's `let` step
    /// keeps the premise as it is), a tail needs `acc` plus its own (a loop
    /// helper's `μ + 1`, a fuel-dependent callee's need). The sum
    /// over-approximates (callees run on the same fuel); every summand is a
    /// machine-word measure, a length or a literal, so `linarith` gets each
    /// call's own need back from it.
    pub fn shadow_acc(&self, t: &Tm, acc: Option<&Tm>) -> Tm {
        let plus = |a: Option<&Tm>, b: Option<Tm>| -> Option<Tm> {
            match (a, b) {
                (Some(a), Some(b)) => Some(mk::prim(PrimOp::IAdd, vec![a.clone(), b], vec![])),
                (Some(a), None) => Some(a.clone()),
                (None, b) => b,
            }
        };
        if !self.calls_helper(t) && !self.calls_fuel_callee(t) {
            return acc.cloned().unwrap_or_else(|| self.int_lit(0));
        }
        match &**t {
            // a `while` loop's call: its measure + 1 (entering the loop), then
            // the rest of the function's need
            Term::Let { name: n, rel, ty, val, body } if self.while_of(val).is_some() => {
                let (wh, args) = self.while_of(val).unwrap();
                let all: Vec<Tm> = args.iter().map(|(_, a)| self.commit(a)).collect();
                let w = mk::prim(PrimOp::IAdd, vec![wh.need_int(&all), self.int_lit(1)], vec![]);
                let acc1 = plus(acc.map(|a| shift(a, 1)).as_ref(), Some(shift(&w, 1)));
                Rc::new(Term::Let { name: n.clone(), rel: *rel, ty: self.commit(ty), val: self.commit(val), body: self.shadow_acc_all(body, acc1.as_ref()) })
            }
            Term::Let { name: n, rel, ty, val, body } => {
                let acc1 = plus(acc.map(|a| shift(a, 1)).as_ref(), self.call_needs(val).map(|w| shift(&w, 1)));
                Rc::new(Term::Let { name: n.clone(), rel: *rel, ty: self.commit(ty), val: self.commit(val), body: self.shadow_acc(body, acc1.as_ref()) })
            }
            Term::App { rel: Rel::Irr, fun, arg } if matches!(&**fun, Term::Match { .. }) => {
                let Term::Match { ind, params, scrut, motive, arms } = &**fun else { unreachable!() };
                let Term::Pi { name: en, rel: Rel::Irr, dom, .. } = &**motive else { return acc.cloned().unwrap_or_else(|| self.int_lit(0)) };
                let int = mk::int_ty(Width::Int);
                let m2 = Rc::new(Term::Pi { name: en.clone(), rel: Rel::Irr, dom: self.commit(dom), cod: int });
                let mut arms2: Vec<Arm> = Vec::new();
                for a in arms {
                    let nf = a.names.len() as i64;
                    let body = match &*a.body {
                        Term::Lam { name: ln, rel: Rel::Irr, dom: ld, body: lb } => {
                            let acc_a = acc.map(|x| shift(x, nf + 1));
                            Rc::new(Term::Lam { name: ln.clone(), rel: Rel::Irr, dom: self.commit(ld), body: self.shadow_acc(lb, acc_a.as_ref()) })
                        }
                        _ => acc.map(|x| shift(x, nf)).unwrap_or_else(|| self.int_lit(0)),
                    };
                    arms2.push(Arm { names: a.names.clone(), body });
                }
                Rc::new(Term::App { rel: Rel::Irr, fun: Rc::new(Term::Match { ind: *ind, params: params.clone(), scrut: self.commit(scrut), motive: m2, arms: arms2 }), arg: self.commit(arg) })
            }
            _ => {
                // a call of a loop helper: its measure + 1 (entering the loop)
                if let Some((h, args)) = app_spine(t)
                    && let Some(hi) = self.helpers.iter().find(|x| x.s_global == h)
                {
                    let rel_args: Vec<Tm> = args.iter().map(|(_, a)| self.commit(a)).collect();
                    let mu = hi.need_int(&rel_args);
                    return plus(acc, Some(mk::prim(PrimOp::IAdd, vec![mu, self.int_lit(1)], vec![]))).unwrap();
                }
                // a tail holding fuel-dependent calls: their needs
                plus(acc, self.call_needs(t)).unwrap_or_else(|| self.int_lit(0))
            }
        }
    }

    /// The fuel shadow of a loop helper's body in a function with nested
    /// loops ([`Self::shadow_acc`] for the helper's own recursion): a
    /// recursive call needs one unit (the jump to the header) and the fuel
    /// from there, `F(args)` (with `fm.f`; else the call itself: the fuel
    /// function's own body); an inner loop's call its fuel and one unit; the
    /// loop's exit `fm.e`; the fuel-dependent calls their needs, accumulated
    /// down the `let`s. A tail without any of these needs the accumulated
    /// fuel and the exit's.
    pub fn shadow_f(&self, t: &Tm, acc: Option<&Tm>, fm: &FuelMode) -> Tm {
        let plus = |a: Option<&Tm>, b: Tm| -> Tm {
            match a {
                Some(a) => mk::prim(PrimOp::IAdd, vec![a.clone(), b], vec![]),
                None => b,
            }
        };
        let exit = |a: Option<&Tm>| plus(a, self.int_lit(fm.e));
        if !has_rec(t) && !self.calls_helper(t) && !self.calls_fuel_callee(t) {
            return exit(acc);
        }
        match &**t {
            Term::Let { name: n, rel, ty, val, body } => {
                let w = match self.while_of(val) {
                    Some((wh, args)) => {
                        let all: Vec<Tm> = args.iter().map(|(_, a)| self.commit(a)).collect();
                        Some(mk::prim(PrimOp::IAdd, vec![wh.need_int(&all), self.int_lit(1)], vec![]))
                    }
                    None => self.call_needs(val),
                };
                let acc_up = acc.map(|a| shift(a, 1));
                let acc1 = match w {
                    Some(w) => Some(plus(acc_up.as_ref(), shift(&w, 1))),
                    None => acc_up,
                };
                Rc::new(Term::Let { name: n.clone(), rel: *rel, ty: self.commit(ty), val: self.commit(val), body: self.shadow_f(body, acc1.as_ref(), fm) })
            }
            Term::App { rel: Rel::Irr, fun, arg } if matches!(&**fun, Term::Match { .. }) => {
                let Term::Match { ind, params, scrut, motive, arms } = &**fun else { unreachable!() };
                let Term::Pi { name: en, rel: Rel::Irr, dom, .. } = &**motive else { return exit(acc) };
                let m2 = Rc::new(Term::Pi { name: en.clone(), rel: Rel::Irr, dom: self.commit(dom), cod: mk::int_ty(Width::Int) });
                let mut arms2: Vec<Arm> = Vec::new();
                for a in arms {
                    let nf = a.names.len() as i64;
                    let body = match &*a.body {
                        Term::Lam { name: ln, rel: Rel::Irr, dom: ld, body: lb } => {
                            let acc_a = acc.map(|x| shift(x, nf + 1));
                            Rc::new(Term::Lam { name: ln.clone(), rel: Rel::Irr, dom: self.commit(ld), body: self.shadow_f(lb, acc_a.as_ref(), fm) })
                        }
                        _ => exit(acc.map(|x| shift(x, nf)).as_ref()),
                    };
                    arms2.push(Arm { names: a.names.clone(), body });
                }
                Rc::new(Term::App { rel: Rel::Irr, fun: Rc::new(Term::Match { ind: *ind, params: params.clone(), scrut: self.commit(scrut), motive: m2, arms: arms2 }), arg: self.commit(arg) })
            }
            Term::Match { ind, params, scrut, arms, .. } => {
                let arms2: Vec<Arm> = arms.iter().map(|a| Arm { names: a.names.clone(), body: self.shadow_f(&a.body, acc.map(|x| shift(x, a.names.len() as i64)).as_ref(), fm) }).collect();
                Rc::new(Term::Match { ind: *ind, params: params.clone(), scrut: self.commit(scrut), motive: mk::int_ty(Width::Int), arms: arms2 })
            }
            Term::Rec { args, proof } => {
                let call = match fm.f {
                    Some(f) => mk::apps(mk::global(f), fm.rels.iter().copied().zip(args.iter().map(|a| self.commit(a)))),
                    None => Rc::new(Term::Rec { args: args.clone(), proof: proof.clone() }),
                };
                plus(acc, mk::prim(PrimOp::IAdd, vec![self.int_lit(1), call], vec![]))
            }
            _ => {
                // a loop helper's call (the loops after this one): its fuel and
                // one unit (entering the loop)
                if let Some((h, args)) = app_spine(t)
                    && let Some(hi) = self.helpers.iter().find(|x| x.s_global == h)
                {
                    let all: Vec<Tm> = args.iter().map(|(_, a)| self.commit(a)).collect();
                    return plus(acc, mk::prim(PrimOp::IAdd, vec![hi.need_int(&all), self.int_lit(1)], vec![]));
                }
                match self.call_needs(t) {
                    Some(w) => plus(Some(&exit(acc)), w),
                    None => exit(acc),
                }
            }
        }
    }

    /// The fuel functions this walk knows: each with its arity, its
    /// nonnegativity lemma and its parameters' relevances.
    fn fuels(&self) -> Vec<(GlobalId, usize, GlobalId, Vec<Rel>)> {
        let mut v = Vec::new();
        for h in self.helpers.iter().chain(self.rec.as_ref().map(|r| &r.helper)) {
            if let Some(fu) = &h.fuel {
                v.push((fu.f, h.nparams as usize, fu.nn, h.rels.clone()));
            }
        }
        for w in &self.whiles {
            if let Some(fu) = &w.fuel {
                v.push((fu.f, w.nparams as usize, fu.nn, w.rels.clone()));
            }
        }
        v
    }

    /// `0 ≤ F(args)` for the fuel functions' calls in `ts` (by their
    /// nonnegativity lemmas), as `linarith` hypotheses.
    fn fuel_nn_hyps(&self, ts: &[&Tm]) -> Vec<(Tm, Tm)> {
        let fuels = self.fuels();
        if fuels.is_empty() {
            return Vec::new();
        }
        let fs: Vec<(GlobalId, usize)> = fuels.iter().map(|x| (x.0, x.1)).collect();
        let mut calls = Vec::new();
        for t in ts {
            fuel_calls(self.env, t, &fs, &mut calls);
        }
        calls
            .into_iter()
            .filter_map(|(g, args)| {
                let x = fuels.iter().find(|x| x.0 == g)?;
                Some((mk::apps(mk::global(x.2), args.clone()), self.le_int(self.int_lit(0), mk::apps(mk::global(g), args))))
            })
            .collect()
    }

    /// A proof of `0 ≤ t` at `ctx`, `t` a fuel function's body as
    /// [`Self::shadow_f`] builds it (its recursive calls `Rec`): a `let` as
    /// it is, a match by the same match (each arm's goal its own body), a
    /// tail by `linarith` from the nonnegativity of its calls (a `Rec` is
    /// the lemma's own recursion at the same decrease proof, another fuel
    /// function's call its lemma). Its goals have the calls as `f`'s.
    pub fn fuel_nn(&self, ctx: &Ctx, t: &Tm, f: GlobalId, rels: &[Rel]) -> Result<Tm, String> {
        let commit_f = |x: &Tm| -> Tm {
            crate::auto::util::map_term(x, 0, &mut |y, _| match &**y {
                Term::Rec { args, .. } => Some(mk::apps(mk::global(f), rels.iter().copied().zip(args.iter().cloned()))),
                _ => None,
            })
        };
        let le0 = |x: Tm| self.le_int(self.int_lit(0), x);
        match &**t {
            Term::Let { name: n, rel, ty, val, body } => {
                let c2 = self.push(ctx, n, *rel, ty, Some(val))?;
                Ok(Rc::new(Term::Let { name: n.clone(), rel: *rel, ty: ty.clone(), val: val.clone(), body: self.fuel_nn(&c2, body, f, rels)? }))
            }
            Term::App { rel: Rel::Irr, fun, arg } if matches!(&**fun, Term::Match { .. }) => {
                let Term::Match { ind, params, scrut, motive, arms } = &**fun else { unreachable!() };
                let Term::Pi { name: en, rel: Rel::Irr, dom, .. } = &**motive else { return Err("a fuel function's match without its equation".into()) };
                // Π(e : dom). 0 ≤ (match y with arms)(e)
                let again = Rc::new(Term::App {
                    rel: Rel::Irr,
                    fun: Rc::new(Term::Match {
                        ind: *ind,
                        params: params.iter().map(|p| shift(p, 2)).collect(),
                        scrut: mk::var(1),
                        motive: shift_from(motive, 2, 1),
                        arms: arms.iter().map(|a| Arm { names: a.names.clone(), body: shift_from(&commit_f(&a.body), 2, a.names.len() as u32) }).collect(),
                    }),
                    arg: mk::var(0),
                });
                let m2 = Rc::new(Term::Pi { name: en.clone(), rel: Rel::Irr, dom: dom.clone(), cod: le0(again) });
                let decl = self.env.inductive_decl(*ind).ok_or("no inductive")?;
                let mut arms2 = Vec::new();
                for (k, a) in arms.iter().enumerate() {
                    let Term::Lam { name: ln, rel: Rel::Irr, dom: ld, body: lb } = &*a.body else { return Err("a fuel function's arm without its equation".into()) };
                    let (actx, _) = self.arm_ctx(ctx, *ind, params, &decl.ctors[k], &a.names)?;
                    let ectx = self.push(&actx, ln, Rel::Irr, ld, None)?;
                    arms2.push(Arm { names: a.names.clone(), body: mk::lam(ln, Rel::Irr, ld.clone(), self.fuel_nn(&ectx, lb, f, rels)?) });
                }
                Ok(Rc::new(Term::App { rel: Rel::Irr, fun: Rc::new(Term::Match { ind: *ind, params: params.clone(), scrut: scrut.clone(), motive: m2, arms: arms2 }), arg: arg.clone() }))
            }
            Term::Match { ind, params, scrut, motive, arms } => {
                let again = Rc::new(Term::Match {
                    ind: *ind,
                    params: params.iter().map(|p| shift(p, 1)).collect(),
                    scrut: mk::var(0),
                    motive: shift_from(motive, 1, 1),
                    arms: arms.iter().map(|a| Arm { names: a.names.clone(), body: shift_from(&commit_f(&a.body), 1, a.names.len() as u32) }).collect(),
                });
                let decl = self.env.inductive_decl(*ind).ok_or("no inductive")?;
                let mut arms2 = Vec::new();
                for (k, a) in arms.iter().enumerate() {
                    let (actx, _) = self.arm_ctx(ctx, *ind, params, &decl.ctors[k], &a.names)?;
                    arms2.push(Arm { names: a.names.clone(), body: self.fuel_nn(&actx, &a.body, f, rels)? });
                }
                Ok(Rc::new(Term::Match { ind: *ind, params: params.clone(), scrut: scrut.clone(), motive: le0(again), arms: arms2 }))
            }
            _ => {
                let mut hyps: Vec<(Tm, Tm)> = Vec::new();
                crate::auto::util::map_term(t, 0, &mut |y, d| {
                    if let Term::Rec { args, proof } = &**y
                        && d == 0
                    {
                        let fa = mk::apps(mk::global(f), rels.iter().copied().zip(args.iter().cloned()));
                        hyps.push((Rc::new(Term::Rec { args: args.clone(), proof: proof.clone() }), le0(fa)));
                        return Some(y.clone());
                    }
                    None
                });
                let tc = commit_f(t);
                hyps.extend(self.fuel_nn_hyps(&[&tc]));
                crate::elab::basic::linarith_term(self.env, ctx, hyps, le0(tc)).map_err(|e| format!("a fuel function's nonnegativity: {e}"))
            }
        }
    }

    /// [`Self::shadow_acc`] of the rest of a function after a `while` loop
    /// (its accumulated need kept even where nothing more needs fuel).
    fn shadow_acc_all(&self, t: &Tm, acc: Option<&Tm>) -> Tm {
        self.shadow_acc(t, acc)
    }

    /// The needs of the fuel-dependent callees' calls in `t` (outside
    /// binders), summed; `None` when there are none.
    fn call_needs(&self, t: &Tm) -> Option<Tm> {
        let mut calls = Vec::new();
        collect_calls(t, &self.callees, &mut calls);
        let mut sum: Option<Tm> = None;
        for (g, args) in calls {
            let Some(ci) = self.callees.iter().find(|c| c.s_global == g) else { continue };
            let Some(w) = &ci.need else { continue };
            let all: Vec<Tm> = args.iter().map(|(_, a)| self.commit(a)).collect();
            let wa = crate::opt::proof::steps::subst_n(w, &all);
            sum = Some(match sum {
                None => wa,
                Some(s0) => mk::prim(PrimOp::IAdd, vec![s0, wa], vec![]),
            });
        }
        sum
    }

    /// Whether a structured term calls a fuel-dependent callee (outside binders).
    fn calls_fuel_callee(&self, t: &Tm) -> bool {
        if !self.callees.iter().any(|c| c.need.is_some()) {
            return false;
        }
        let mut found = false;
        crate::auto::util::map_term(t, 0, &mut |x, _d| {
            if !found
                && let Some((h, _)) = app_spine(x)
                && self.callees.iter().any(|c| c.s_global == h && c.need.is_some())
            {
                found = true;
            }
            None
        });
        found
    }

    /// Whether a structured term calls a loop helper (outside proofs).
    fn calls_helper(&self, t: &Tm) -> bool {
        let mut found = false;
        crate::auto::util::map_term(t, 0, &mut |x, _d| {
            if !found
                && let Some((h, _)) = app_spine(x)
                && (self.helpers.iter().any(|hi| hi.s_global == h) || self.whiles.iter().any(|w| w.s_global == h))
            {
                found = true;
            }
            None
        });
        found
    }

    /// A call of a `while` helper: the helper and the call's arguments.
    fn while_of(&self, t: &Tm) -> Option<(WhileHelper, Vec<(Rel, Tm)>)> {
        let (h, args) = app_spine(t)?;
        let wh = self.whiles.iter().find(|w| w.s_global == h)?;
        (args.len() == wh.nparams as usize).then(|| (wh.clone(), args))
    }

    /// The recursive call of a loop's lemma at a tail.
    fn loop_rec<'t>(&self, s: &'t Tm) -> Option<(&'t Vec<Tm>, &'t Option<Tm>)> {
        match &**s {
            Term::Rec { args, proof } => Some((args, proof)),
            _ => None,
        }
    }

    /// `Π(.hle : need ≤ len n). C` (`C`: [`Self::goal_c`]).
    pub fn goal_p(&self, ctx: &Ctx, g: &Goal) -> Tm {
        let need = self.need_acc(ctx, &g.s, g.acc.as_ref());
        let prem = self.le_int(need, self.len_n(ctx.depth().0));
        let c = match &self.exit {
            Some(x) => self.exit_goal(x, ctx.depth().0, g),
            None => self.goal_c(g),
        };
        mk::pi("hle", Rel::Irr, prem, shift(&c, 1))
    }

    /// A `while` lemma's goal at depth `d` (see [`ExitMode`]):
    /// `Π(.eqS : Eq(R, h p̄, S)). Eq(Opt, l, C)`.
    fn exit_goal(&self, x: &ExitMode, d: u32, g: &Goal) -> Tm {
        let h = self.rec.as_ref().map(|r| r.helper.clone()).expect("a `while` lemma's walk");
        let h_app = mk::apps(mk::global(h.s_global), h.rels.iter().copied().zip(h.params_at(d)));
        let eqs = mk::eq(x.r_ty.clone(), h_app, self.commit(&g.s));
        mk::pi("eqS", Rel::Irr, eqs, mk::eq(shift(&self.opt_out(), 1), shift(&g.l, 1), mk::var(d - x.c_level)))
    }

    /// The goal of a walk node: [`Self::goal_p`], or [`Self::goal_c`] when
    /// the fuel premise is a hypothesis of the context.
    pub fn goal(&self, ctx: &Ctx, g: &Goal) -> Tm {
        if self.prem_in_ctx { self.goal_c(g) } else { self.goal_p(ctx, g) }
    }

    /// `Eq(Opt, l, Some(erase(s)))`.
    pub fn goal_e(&self, g: &Goal) -> Tm {
        mk::eq(self.opt_out(), g.l.clone(), self.goal_rhs(g))
    }

    /// The equation's right side: `Some(erase(s))` (for the panic statement
    /// `opt_erase(s)`, [`Self::opt_erase`]), or the abstracted one.
    fn goal_rhs(&self, g: &Goal) -> Tm {
        g.rhs.clone().unwrap_or_else(|| match &self.panic {
            Some(r) => self.opt_erase(r, &self.erase, &self.out_ty, &self.commit(&g.s)),
            None => self.some_out(mk::app(self.erase.clone(), self.commit(&g.s))),
        })
    }

    /// `match s : Option(r) with None => None[out] | Some(y) => Some[out](erase y)`:
    /// the panic statement's right side of a structured value `s` (`None` is
    /// the panic outcome, which the literal reading returns as `None`).
    pub fn opt_erase(&self, r: &Tm, erase: &Tm, out: &Tm, s: &Tm) -> Tm {
        let opt = self.ind("Option");
        let out_opt = mk::ind(opt, vec![out.clone()]);
        let none = Rc::new(Term::Ctor { ind: opt, ctor: 0, params: vec![out.clone()], args: vec![] });
        let some = Rc::new(Term::Ctor { ind: opt, ctor: 1, params: vec![shift(out, 1)], args: vec![mk::app(shift(erase, 1), mk::var(0))] });
        Rc::new(Term::Match { ind: opt, params: vec![r.clone()], scrut: s.clone(), motive: out_opt, arms: vec![Arm { names: vec![], body: none }, Arm { names: vec![name("yy")], body: some }] })
    }

    /// The conclusion: [`Self::goal_e`], with the presence conjunct
    /// `Sigma(_ : Eq(..)). Pres(ins, s)` when the function has optional cells.
    pub fn goal_c(&self, g: &Goal) -> Tm {
        let e = self.goal_e(g);
        match &self.pres {
            None => e,
            Some(p) => mk::sigma("_", Rel::Rel, e, shift(&self.pres_ty(p, &g.ins, &self.commit(&g.s)), 1)),
        }
    }

    /// `is_some(t)` for `t : Option(T)`: a match (no library definition).
    fn is_some(&self, t: &Tm, elem: &Tm) -> Tm {
        let bool_ty = mk::ind(self.env.bool_ind(), vec![]);
        let tru = Rc::new(Term::Ctor { ind: self.env.bool_ind(), ctor: 1, params: vec![], args: vec![] });
        let fls = Rc::new(Term::Ctor { ind: self.env.bool_ind(), ctor: 0, params: vec![], args: vec![] });
        Rc::new(Term::Match { ind: self.ind("Option"), params: vec![elem.clone()], scrut: t.clone(), motive: bool_ty, arms: vec![Arm { names: vec![], body: fls }, Arm { names: vec![name("v")], body: tru }] })
    }

    /// Component `j` of `r : R` (`R` a tuple type; itself when not a tuple).
    fn proj(&self, r: &Tm, r_ty: &Tm, j: usize) -> Tm {
        let Term::Ind { ind, params } = &**r_ty else { return r.clone() };
        let Some(decl) = self.env.inductive_decl(*ind) else { return r.clone() };
        if !decl.name.starts_with("Tuple") || decl.ctors.len() != 1 || params.len() < 2 {
            return r.clone();
        }
        let nf = decl.ctors[0].fields.len() as u32;
        let names: Vec<Name> = (0..nf).map(|i| name(&format!("x{i}"))).collect();
        Rc::new(Term::Match { ind: *ind, params: params.clone(), scrut: r.clone(), motive: shift(&params[j], 1), arms: vec![Arm { names, body: mk::var(nf - 1 - j as u32) }] })
    }

    /// One cell's presence equation `Eq(Bool, is_some(x), is_some(proj_j(r)))`.
    fn pres_eq(&self, p: &Pres, i: usize, x: &Tm, r: &Tm) -> Tm {
        let (j, elem, _) = &p.cells[i];
        let bool_ty = mk::ind(self.env.bool_ind(), vec![]);
        mk::eq(bool_ty, self.is_some(x, elem), self.is_some(&self.proj(r, &p.r_ty, *j), elem))
    }

    /// The presence conjunct: each cell's equation, as a right-nested `Sigma`.
    pub fn pres_ty(&self, p: &Pres, ins: &[Tm], r: &Tm) -> Tm {
        let n = p.cells.len();
        let mut t = self.pres_eq(p, n - 1, &ins[n - 1], r);
        for i in (0..n - 1).rev() {
            t = mk::sigma("_", Rel::Rel, self.pres_eq(p, i, &ins[i], r), shift(&t, 1));
        }
        t
    }

    /// Facts from a presence conjunct's proof `pf` about the result `r` of
    /// a call at inputs `ins`: per cell, `Eq(Bool, is_some(proj_j(r)),
    /// is_some(x))` (the result's side first: a test on it is decided by
    /// the argument's constructor, `refute_eval`).
    fn pres_facts(&self, _ctx: &Ctx, p: &Pres, ins: &[Tm], r: &Tm, pf: &Tm) -> Result<Vec<Fact>, String> {
        let bool_ty = mk::ind(self.env.bool_ind(), vec![]);
        let mut out = Vec::new();
        for (i, part) in self.pres_parts(p, pf).into_iter().enumerate() {
            let (j, elem, _) = &p.cells[i];
            let a = self.is_some(&ins[i], elem);
            let b = self.is_some(&self.proj(r, &p.r_ty, *j), elem);
            let sym = mk::apps(mk::global(self.g("eq::sym")?), vec![(Rel::Rel, bool_ty.clone()), (Rel::Rel, a.clone()), (Rel::Rel, b.clone()), (Rel::Rel, part)]);
            out.push(Fact::eq(sym, mk::eq(bool_ty.clone(), b, a)));
        }
        Ok(out)
    }

    /// The literal side's call `lcall` (a callee's or the function's own
    /// run) moved to `sval = Some(erase(S call))` along `eq : Eq(Opt_g,
    /// lcall, sval)`: the new goal and the transport (its value a hole), or
    /// `None` when the call is not in the literal side (or already
    /// converts).
    #[allow(clippy::too_many_arguments)]
    fn transport_call(&mut self, ctx: &Ctx, g: &Goal, lcall: &Tm, sval: &Tm, out_g: &Tm, eq: Tm, with_prem: bool) -> Result<Option<(Goal, Tm)>, String> {
        self.transport_call_p(ctx, g, lcall, sval, out_g, eq, with_prem, &[])
    }

    /// [`Self::transport_call`]; `pending`: the runs of other callees whose
    /// lemmas are still to apply (kept folded: a callee's run unfolded on
    /// another callee's literal value would hide its own call).
    #[allow(clippy::too_many_arguments)]
    fn transport_call_p(&mut self, ctx: &Ctx, g: &Goal, lcall: &Tm, sval: &Tm, out_g: &Tm, eq: Tm, with_prem: bool, pending: &[GlobalId]) -> Result<Option<(Goal, Tm)>, String> {
        if !pending.is_empty()
            && let Some((r, _)) = app_spine(lcall)
            && self.l_runs.contains(&r)
            && self.s_self_run != Some(r)
        {
            let mut fold: Vec<GlobalId> = self.opaque.iter().copied().filter(|x| Some(*x) != self.s_self_run).collect();
            fold.push(r);
            fold.extend(pending.iter().copied().filter(|p| *p != r));
            let lvf = self.eval_folding(ctx, lcall, &fold)?;
            let l_abs = self.abstract_l_folding(ctx, &g.l, &lvf, &fold)?;
            if count_var(&l_abs, 0) > 0 {
                return self.transport_with(ctx, g, l_abs, lcall, sval, out_g, eq, with_prem).map(Some);
            }
        }
        let lv = self.eval(ctx, lcall)?;
        if self.conv(ctx, &lv, &self.eval(ctx, sval)?) {
            if std::env::var("CS_TRACE_CALLS").is_ok() {
                eprintln!("  call converts already: {}", trunc(&self.env.print_term(&[], lcall), 300));
            }
            return Ok(None);
        }
        // (a stuck call's run must be in the literal side as a folded run:
        // looked for in its value before the costly abstraction)
        let run_head = app_spine(lcall).map(|(r, _)| r);
        let stuck = matches!(&*lv, Value::Neu(_));
        if stuck
            && let Some(r) = run_head
            && !value_mentions_global(&self.eval(ctx, &g.l)?, r)
        {
            return Ok(None);
        }
        let mut l_abs = self.abstract_l(ctx, &g.l, &lv)?;
        // (not found: a callee's run that completes under evaluation leaves
        // only its value in the literal side; its run kept folded instead)
        if count_var(&l_abs, 0) == 0
            && let Some((r, _)) = app_spine(lcall)
            && self.l_runs.contains(&r)
            && self.s_self_run != Some(r)
        {
            // (`eval_opaque` unfolds every global it is not given: S's opaque
            // definitions stay folded as in ordinary evaluation)
            let mut fold: Vec<GlobalId> = self.opaque.iter().copied().filter(|x| Some(*x) != self.s_self_run).collect();
            fold.push(r);
            let lvf = self.eval_folding(ctx, lcall, &fold)?;
            l_abs = self.abstract_l_folding(ctx, &g.l, &lvf, &fold)?;
        }
        if count_var(&l_abs, 0) == 0 {
            if std::env::var("CS_TRACE_CALLS").is_ok() {
                let lt = self.quote(ctx, &self.eval(ctx, &g.l)?);
                eprintln!("  lemma not applicable:\n    call    {}\n    literal {}", trunc(&self.env.print_term(&[], &self.quote(ctx, &lv)), 3000), trunc(&self.env.print_term(&[], &lt), 6000));
            }
            return Ok(None);
        }
        self.transport_with(ctx, g, l_abs, lcall, sval, out_g, eq, with_prem).map(Some)
    }

    /// The transport of the literal side `l_abs[y := lcall]` to `l_abs[y := sval]`.
    #[allow(clippy::too_many_arguments)]
    fn transport_with(&mut self, ctx: &Ctx, g: &Goal, l_abs: Tm, lcall: &Tm, sval: &Tm, out_g: &Tm, eq: Tm, with_prem: bool) -> Result<(Goal, Tm), String> {
        self.stats.transports += 1;
        let opt_g = mk::ind(self.ind("Option"), vec![out_g.clone()]);
        let sym = mk::apps(mk::global(self.g("eq::sym")?), vec![(Rel::Rel, opt_g.clone()), (Rel::Rel, lcall.clone()), (Rel::Rel, sval.clone()), (Rel::Rel, eq)]);
        let gm = g.with(l_abs.clone(), shift(&g.s, 1), 1);
        let ctx_y = self.push(ctx, "y", Rel::Rel, &opt_g, None)?;
        let motive = if with_prem { self.goal(&ctx_y, &gm) } else { self.goal_e(&gm) };
        self.check_motive(ctx, &opt_g, &motive, "callee lemma")?;
        let w = Rc::new(Term::Transport { ty: opt_g, lhs: sval.clone(), rhs: lcall.clone(), eq: sym, motive, val: mk::var(u32::MAX) });
        Ok((g.with(crate::elab::tm::subst0(&l_abs, sval), g.s.clone(), 0), w))
    }

    /// The proofs of each cell's equation from a proof `pf` of the conjunct.
    fn pres_parts(&self, p: &Pres, pf: &Tm) -> Vec<Tm> {
        let n = p.cells.len();
        let mut out = Vec::new();
        let mut cur = pf.clone();
        for _ in 0..n.saturating_sub(1) {
            out.push(Rc::new(Term::Fst(cur.clone())));
            cur = Rc::new(Term::Snd(cur));
        }
        out.push(cur);
        out
    }

    /// Checks a transport's motive is well-formed (`CS_CHECK`: debugging),
    /// naming the step that built it.
    fn check_motive(&self, ctx: &Ctx, ty: &Tm, motive: &Tm, what: &str) -> Result<(), String> {
        if std::env::var("CS_CHECK").is_err() {
            return Ok(());
        }
        let tyv = self.eval(ctx, ty)?;
        let cy = ctx.push(CtxEntry { name: name("y"), rel: Rel::Rel, ty: tyv, def: None });
        let mut b = self.b();
        if let Err(e) = self.env.infer(&cy, motive, &mut b) {
            let mut where_ = String::new();
            crate::auto::util::map_term(motive, 0, &mut |x, _| {
                if where_.len() < 3000 {
                    let kids: Vec<&Tm> = match &**x {
                        Term::App { fun, arg, .. } => vec![fun, arg],
                        Term::Ctor { args, .. } => args.iter().collect(),
                        Term::Fst(a) | Term::Snd(a) => vec![a],
                        Term::Prim { args, .. } => args.iter().collect(),
                        Term::Pair { ty, fst, snd } => vec![ty, fst, snd],
                        Term::Transport { eq, val, lhs, rhs, .. } => vec![eq, val, lhs, rhs],
                        _ => vec![],
                    };
                    let ep = |k: &Tm| matches!(&**k, Term::Pair { ty, .. } if matches!(&**ty, Term::Erased));
                    if kids.iter().any(|k| ep(k)) {
                        let head = match &**x { Term::App { rel, .. } => format!("app {rel:?}"), Term::Ctor { .. } => "ctor".into(), Term::Fst(_) => "fst".into(), Term::Snd(_) => "snd".into(), Term::Prim { .. } => "prim".into(), Term::Pair { .. } => "pair".into(), Term::Transport { .. } => "transport".into(), _ => "?".into() };
                        where_.push_str(&format!("\n    erased pair under a {head}: {}", trunc(&self.env.print_term(&[], x), 300)));
                    }
                }
                None
            });
            if std::env::var("CS_FIND_BAD").is_ok() {
                let names: Vec<Name> = cy.entries.iter().map(|e| e.name.clone()).collect();
                let mut cy = cy.clone();
                for e in Rc::make_mut(&mut cy.entries).iter_mut() {
                    e.rel = Rel::Rel;
                }
                let mut n = 0;
                crate::auto::util::map_term(motive, 0, &mut |x, d| {
                    if d == 0 && n < 3 && matches!(&**x, Term::Linarith { .. } | Term::Prim { .. } | Term::Transport { .. }) {
                        let mut b = self.b();
                        if let Err(e2) = self.env.infer(&cy, x, &mut b) {
                            let inner_bad = { let mut ib = false; crate::auto::util::map_term(x, 0, &mut |z, dz| { if dz == 0 && !Rc::ptr_eq(z, x) && matches!(&**z, Term::Linarith { .. }) { let mut b2 = self.b(); if self.env.infer(&cy, z, &mut b2).is_err() { ib = true; } } None }); ib };
                            if !inner_bad {
                                n += 1;
                                eprintln!("BAD NODE: {}
  because {}", trunc(&self.env.print_term(&names, x), 6000), trunc(&e2.to_string(), 600));
                            }
                        }
                    }
                    None
                });
            }
            if let Ok(f) = std::env::var("CS_DUMP_MOTIVE") {
                let names: Vec<Name> = cy.entries.iter().map(|e| e.name.clone()).collect();
                let _ = std::fs::write(f, self.env.print_term(&names, motive));
            }
            return Err(format!("MOTIVE ill-formed ({what}): {}{where_}", trunc(&e.to_string(), 2000)));
        }
        Ok(())
    }

    /// Checks a proof node against its goal (`CS_CHECK`: debugging).
    fn check_node(&self, ctx: &Ctx, r: &Tm, goal: &Tm, what: &str) -> Result<(), String> {
        if std::env::var("CS_CHECK").is_err() {
            return Ok(());
        }
        // (a recursive call cannot be checked outside its definition)
        let mut has_rec = false;
        crate::auto::util::map_term(r, 0, &mut |x, _| {
            if matches!(&**x, Term::Rec { .. }) {
                has_rec = true;
            }
            None
        });
        if has_rec {
            return Ok(());
        }
        let mut b = self.b();
        if let Err(e) = self.env.infer(ctx, goal, &mut b) {
            let names: Vec<Name> = ctx.entries.iter().map(|e| e.name.clone()).collect();
            return Err(format!("GOAL ill-formed at depth {} ({what}): {}; goal = {}", ctx.entries.len(), trunc(&e.to_string(), 600), trunc(&self.env.print_term(&names, goal), 3000)));
        }
        let gv = self.eval(ctx, goal)?;
        if let Err(e) = self.env.check(ctx, r, &gv, &mut b) {
            let names: Vec<String> = ctx.entries.iter().enumerate().map(|(i, e)| format!("{i}:{}", e.name)).collect();
            let head = match &**r {
                Term::App { fun, .. } => match &**fun { Term::Match { ind, .. } => format!("match on {:?}", self.env.inductive_decl(*ind).map(|d| d.name.clone())), _ => "app".into() },
                Term::Refl { .. } => "refl".into(),
                Term::Absurd { .. } => "absurd".into(),
                Term::Transport { .. } => "transport".into(),
                Term::Rec { .. } => "rec".into(),
                _ => "other".into(),
            };
            return Err(format!("CHECK failed at depth {} ({what}; node {head}; n_level {}): {}\n  ctx {}\n  goal {}", ctx.entries.len(), self.n_level, trunc(&e.to_string(), 6000), names.join(" "), trunc(&self.env.print_term(&ctx.entries.iter().map(|e| e.name.clone()).collect::<Vec<_>>(), goal), 6000)));
        }
        Ok(())
    }

    /// Proves `goal(g)` by walking the structured term.
    pub fn walk(&mut self, ctx: &Ctx, g: &Goal, facts: &[Fact]) -> Result<Tm, String> {
        let r = self.walk0(ctx, g, facts)?;
        let what = match &*g.s {
            Term::Let { name, .. } => format!("let {name}"),
            Term::App { .. } => "split".into(),
            _ => "leaf".into(),
        };
        self.check_node(ctx, &r, &self.goal(ctx, g), &what)?;
        Ok(r)
    }

    /// One step of the per-function budget (a deadline and a number of
    /// walk steps): exceeding it fails the walk where it is.
    fn tick(&mut self) -> Result<(), String> {
        self.steps += 1;
        if self.max_steps > 0 && self.steps > self.max_steps {
            return Err(format!("the walk's budget of {} steps is exhausted", self.max_steps));
        }
        if let Some(d) = self.deadline
            && std::time::Instant::now() > d
        {
            return Err("the walk's time budget is exhausted".into());
        }
        Ok(())
    }

    /// A walk failure with its place: the function, the path of S's splits
    /// and lets to here, and both sides (the literal side evaluated).
    fn fail(&self, ctx: &Ctx, g: &Goal, msg: &str) -> String {
        let names: Vec<Name> = ctx.entries.iter().map(|e| e.name.clone()).collect();
        let lt = self.eval(ctx, &g.l).map(|v| self.env.print_term(&names, &self.quote(ctx, &v))).unwrap_or_else(|e| e);
        let st = self.env.print_term(&names, &self.commit(&g.s));
        let lim = if std::env::var("CS_FULL").is_ok() { 1_000_000 } else { 3000 };
        format!("{msg}\n  in `{}` at {}\n  literal side:    {}\n  structured side: {}", self.fname, if self.path.is_empty() { "the start".to_string() } else { self.path.join(" / ") }, trunc(&lt, lim), trunc(&st, lim))
    }

    fn walk0(&mut self, ctx: &Ctx, g: &Goal, facts: &[Fact]) -> Result<Tm, String> {
        self.tick().map_err(|e| self.fail(ctx, g, &e))?;
        // a path the facts already contradict (the newest path equation
        // against the others): closed before anything is split
        if let Some(pf) = self.refute_last(ctx, facts)? {
            self.stats.refuted += 1;
            return Ok(Rc::new(Term::Absurd { ty: self.goal(ctx, g), proof: pf }));
        }
        if let Some(r) = self.eta(ctx, g, facts)? {
            return Ok(r);
        }
        let t = g.s.clone();
        // a match whose scrutinee is a constructor: its arm (iota)
        if let Some(t2) = self.reduce_head(ctx, &t)? {
            return self.walk0(ctx, &g.with(g.l.clone(), t2, 0), facts);
        }
        // `let x = (let y = v; b); c` is `let y = v; let x = b; c` (zeta on
        // both sides: convertible)
        if let Term::Let { name: xn, rel: xr, ty: xt, val, body } = &*t
            && let Term::Let { name: yn, rel: yr, ty: yt, val: yv, body: yb } = &**val
        {
            let inner = Rc::new(Term::Let { name: xn.clone(), rel: *xr, ty: shift(xt, 1), val: yb.clone(), body: shift_from(body, 1, 1) });
            let t2 = Rc::new(Term::Let { name: yn.clone(), rel: *yr, ty: yt.clone(), val: yv.clone(), body: inner });
            return self.walk0(ctx, &g.with(g.l.clone(), t2, 0), facts);
        }
        // a `while` loop's call: a tail (its lemma runs the loop, the rest of
        // the function is walked in its continuation)
        if matches!(&*t, Term::Let { val, .. } if self.while_of(val).is_some()) {
            self.path.push("tail".into());
            let r = self.tail(ctx, g, facts);
            self.path.pop();
            return r;
        }
        // the first stuck match of the structured term in evaluation order
        // (outside binders: the term itself, a let's value, a constructor's
        // arguments, a scrutinee): the structured reading's own split there
        if let Some(k) = self.stuck_idiom(ctx, &t)? {
            // (calls of lifted functions in the scrutinee: their lemmas)
            let mut fs: Vec<Fact> = facts.to_vec();
            let mut scrut_t = None;
            if let Some(idiom) = nth_idiom(&t, k)
                && let Term::App { fun, .. } = &*idiom
                && let Term::Match { scrut, .. } = &**fun
            {
                self.call_facts(scrut, 0, &mut fs);
                // (the checked primitives of the scrutinee: their proofs are
                // facts, as a `let`'s are; not under its `let`s, whose values
                // substituted into a `linarith` proof would change what it
                // states)
                let mut prims = Vec::new();
                collect_prims_d(self.env, &strip_lets(scrut), &mut prims, 2);
                for (p, ty2, br) in prims {
                    if !fs.iter().any(|f| self.env.alpha_eq_relevant(&f.ty, &ty2, &|a, b| a == b)) {
                        fs.push(Fact { bridge: br, reused: true, ..Fact::eq(p, ty2) });
                    }
                }
                scrut_t = Some(scrut.clone());
            }
            let (g2, wraps, newf) = self.advance(ctx, g, &fs, true)?;
            fs.extend(newf);
            // the literal side does not hold the scrutinee yet: it may wait
            // for a parameter's constructor (split on it first)
            if let Some(sc) = &scrut_t {
                let sv = self.eval(ctx, &self.commit(sc))?;
                if count_var(&self.abstract_l(ctx, &g2.l, &sv)?, 0) == 0
                    && let Some(r) = self.lit_step(ctx, &g2, &fs, false)?
                {
                    return Ok(wrap(wraps, r));
                }
            }
            self.stats.s_splits += 1;
            let inner = self.s_split_at(ctx, &g2, k, &fs)?;
            return Ok(wrap(wraps, inner));
        }
        match &*t {
            Term::Let { name: n, rel, ty, val, body } => {
                // a self-call in the value (non-tail recursion): the literal
                // side is moved to it and the induction hypothesis applied
                if self.rec_fn.is_some() && self.pending_rec(val, facts).is_some() {
                    return self.reach_self_call(ctx, g, facts, val);
                }
                // a value the facts decide (one constructor left): split it
                if let Some(r) = self.let_split(ctx, g, facts)? {
                    return Ok(r);
                }
                let mut fs: Vec<Fact> = facts.iter().map(|f| f.shifted(1)).collect();
                let mut prims = Vec::new();
                collect_prims(self.env, val, &mut prims);
                if std::env::var("CS_TRACE_PRIMS").is_ok() {
                    let names: Vec<Name> = ctx.entries.iter().map(|e| e.name.clone()).collect();
                    eprintln!("  let {n}: {} primitive facts: {}", prims.len(), prims.iter().map(|(_, t, _)| trunc(&self.env.print_term(&names, t), 300)).collect::<Vec<_>>().join(" ; "));
                }
                for (p, ty2, br) in prims {
                    if std::env::var("CS_CHECK_FACTS").is_ok() {
                        let mut b = self.b();
                        if let Ok(tv) = self.eval(ctx, &ty2)
                            && let Err(e) = self.env.check(ctx, &p, &tv, &mut b)
                        {
                            let names: Vec<Name> = ctx.entries.iter().map(|e| e.name.clone()).collect();
                            eprintln!("  FACT PROOF of let {n} does not check: {} : {}\n    {}", trunc(&self.env.print_term(&names, &p), 1500), trunc(&self.env.print_term(&names, &ty2), 300), trunc(&e.to_string(), 300));
                        }
                    }
                    fs.push(Fact { bridge: br.map(|(o, a, b)| (o, shift(&a, 1), shift(&b, 1))), reused: true, ..Fact::eq(shift(&p, 1), shift(&ty2, 1)) });
                }
                self.call_facts(val, 1, &mut fs);
                let cval = self.commit(val);
                let cty = self.commit(ty);
                let ctx2 = self.push(ctx, n, *rel, &cty, Some(&cval))?;
                if *rel == Rel::Irr {
                    fs.push(Fact { reused: true, ..Fact::eq(mk::var(0), shift(&cty, 1)) });
                } else {
                    fs.push(Fact { letdef: Some((mk::var(0), shift(&cval, 1))), ..Fact::marker(self.tt(), self.unit_ty()) });
                }
                let mut g2 = g.with(shift(&g.l, 1), body.clone(), 1);
                if !self.prem_in_ctx
                    && let Some(w) = self.call_needs(val)
                {
                    let w1 = shift(&w, 1);
                    g2.acc = Some(match g2.acc.take() {
                        None => w1,
                        Some(a) => mk::prim(PrimOp::IAdd, vec![a, w1], vec![]),
                    });
                }
                self.path.push(format!("let {n}"));
                let inner = self.walk(&ctx2, &g2, &fs);
                self.path.pop();
                Ok(Rc::new(Term::Let { name: n.clone(), rel: *rel, ty: cty, val: cval, body: inner? }))
            }
            Term::Absurd { proof, .. } => {
                self.stats.absurds += 1;
                Ok(Rc::new(Term::Absurd { ty: self.goal(ctx, g), proof: proof.clone() }))
            }
            _ => {
                self.path.push("tail".into());
                let r = self.tail(ctx, g, facts);
                self.path.pop();
                r
            }
        }
    }

    /// A terminal of the structured term: the fuel premise introduced
    /// (unless it is already a hypothesis), the literal side moved to the
    /// structured value, then the presence conjunct.
    fn tail(&mut self, ctx: &Ctx, g: &Goal, facts: &[Fact]) -> Result<Tm, String> {
        let (hctx, g1, mut fs, prem) = if self.prem_in_ctx {
            (ctx.clone(), g.clone(), facts.to_vec(), None)
        } else {
            let need = self.need_acc(ctx, &g.s, g.acc.as_ref());
            let prem = self.le_int(need, self.len_n(ctx.depth().0));
            let hctx = self.push(ctx, "hle", Rel::Irr, &prem, None)?;
            let mut fs: Vec<Fact> = facts.iter().map(|f| f.shifted(1)).collect();
            fs.push(Fact::eq(mk::var(0), shift(&prem, 1)));
            (hctx, g.shifted(1), fs, Some(prem))
        };
        // (calls of lifted functions in the value: their lemmas; its
        // checked primitives: their obligations and bridges)
        self.call_facts(&g1.s, 0, &mut fs);
        let mut prims = Vec::new();
        collect_prims(self.env, &self.commit(&g1.s), &mut prims);
        for (p, ty2, br) in prims {
            fs.push(Fact { bridge: br, reused: true, ..Fact::eq(p, ty2) });
        }
        if std::env::var("CS_TRACE_TAIL").is_ok() {
            let names: Vec<Name> = hctx.entries.iter().map(|e| e.name.clone()).collect();
            eprintln!("TAIL at {}\n  L = {}\n  S = {}", self.path.join(" / "), self.env.print_term(&names, &self.quote(&hctx, &self.eval(&hctx, &g1.l)?)), self.env.print_term(&names, &self.commit(&g1.s)));
            if std::env::var("CS_TRACE_TAIL_RAW").is_ok() {
                eprintln!("  L (unevaluated) = {}", self.env.print_term(&names, &g1.l));
            }
        }
        // a `while` lemma: `eqS` introduced, the exit handed to the
        // continuation, a recursive call the induction hypothesis
        if let Some(x) = self.exit.clone() {
            let d = hctx.depth().0;
            let h = self.rec.as_ref().map(|r| r.helper.clone()).ok_or("a `while` lemma without its helper")?;
            let h_app = mk::apps(mk::global(h.s_global), h.rels.iter().copied().zip(h.params_at(d)));
            let eqs_ty = mk::eq(x.r_ty.clone(), h_app, self.commit(&g1.s));
            let ectx = self.push(&hctx, "eqS", Rel::Irr, &eqs_ty, None)?;
            let mut g2 = g1.shifted(1);
            g2.rhs = Some(mk::var(d + 1 - 1 - x.c_level));
            let fs2: Vec<Fact> = fs.iter().map(|f| f.shifted(1)).collect();
            if let Some(e) = self.exit.as_mut() {
                e.eqs_level = Some(d);
            }
            let r = if self.loop_rec(&g2.s).is_some() { self.terminal(&ectx, &g2, &fs2, 0) } else { self.exit_close(&ectx, &g2, &fs2) };
            let body = mk::lam("eqS", Rel::Irr, eqs_ty, r?);
            return Ok(match prem {
                Some(prem) => mk::lam("hle", Rel::Irr, prem, body),
                None => body,
            });
        }
        let eq = self.terminal(&hctx, &g1, &fs, 0)?;
        let body = self.with_pres(&hctx, &g1, &fs, eq)?;
        Ok(match prem {
            Some(prem) => mk::lam("hle", Rel::Irr, prem, body),
            None => body,
        })
    }

    /// The conclusion from the equation's proof: with the presence
    /// conjunct, the pair of the two (the conjunct by evaluation, or a fact).
    fn with_pres(&mut self, ctx: &Ctx, g: &Goal, facts: &[Fact], eq: Tm) -> Result<Tm, String> {
        let Some(p) = self.pres.clone() else { return Ok(eq) };
        let s = self.commit(&g.s);
        let n = p.cells.len();
        let mut parts: Vec<Tm> = Vec::new();
        for i in 0..n {
            let want = self.pres_eq(&p, i, &g.ins[i], &s);
            parts.push(self.prove_bool_eq(ctx, &want, facts).map_err(|e| self.fail(ctx, g, &format!("the presence of optional cell {i}: {e}")))?);
        }
        let mut pf = parts[n - 1].clone();
        for i in (0..n - 1).rev() {
            let rest_ty = {
                let ins: Vec<Tm> = g.ins[i + 1..].to_vec();
                let sub = Pres { cells: p.cells[i + 1..].to_vec(), r_ty: p.r_ty.clone() };
                self.pres_ty(&sub, &ins, &s)
            };
            let ty = mk::sigma("_", Rel::Rel, self.pres_eq(&p, i, &g.ins[i], &s), shift(&rest_ty, 1));
            pf = mk::pair(ty, parts[i].clone(), pf);
        }
        Ok(mk::pair(self.goal_c(g), eq, pf))
    }

    /// `Eq(Bool, a, b)`: by evaluation (`refl`), or a fact of that type (or
    /// its symmetric).
    fn prove_bool_eq(&self, ctx: &Ctx, want: &Tm, facts: &[Fact]) -> Result<Tm, String> {
        let Term::Eq { ty, lhs, rhs } = &**want else { return Err("not an equation".into()) };
        let (lv, rv) = (self.eval(ctx, lhs)?, self.eval(ctx, rhs)?);
        if self.conv(ctx, &lv, &rv) {
            return Ok(mk::refl(ty.clone(), lhs.clone()));
        }
        let wv = self.eval(ctx, want)?;
        let sym_t = mk::eq(ty.clone(), rhs.clone(), lhs.clone());
        let sv = self.eval(ctx, &sym_t)?;
        for f in facts.iter().filter(|f| !f.is_marker()) {
            let fv = self.eval(ctx, &f.ty)?;
            if self.conv(ctx, &fv, &wv) {
                return Ok(f.proof.clone());
            }
            if self.conv(ctx, &fv, &sv) {
                return Ok(mk::apps(mk::global(self.g("eq::sym")?), vec![(Rel::Rel, ty.clone()), (Rel::Rel, rhs.clone()), (Rel::Rel, lhs.clone()), (Rel::Rel, f.proof.clone())]));
            }
        }
        let names: Vec<Name> = ctx.entries.iter().map(|e| e.name.clone()).collect();
        Err(format!("no proof of {}", trunc(&self.env.print_term(&names, &self.quote(ctx, &wv)), 600)))
    }

    /// Facts for the calls of lifted functions with lemmas in `t` (outside
    /// binders), shifted by `k` binders; a self-call (`Rec`) is a fact too.
    fn call_facts(&self, t: &Tm, k: i64, fs: &mut Vec<Fact>) {
        let mut calls = Vec::new();
        collect_calls(t, &self.callees, &mut calls);
        for (g2, args) in calls {
            let args_c: Vec<(Rel, Tm)> = args.iter().map(|(r, a)| (*r, shift(&self.commit(a), k))).collect();
            fs.push(Fact { call: Some((g2, args_c)), ..Fact::marker(self.tt(), self.unit_ty()) });
        }
        if let Some(rf) = &self.rec_fn {
            let mut recs = Vec::new();
            collect_recs(t, &mut recs);
            for (args, dp) in recs {
                let args_c: Args = args.iter().enumerate().map(|(i, a)| (rf.rels.get(i).copied().unwrap_or(Rel::Rel), shift(&self.commit(a), k))).collect();
                let dup = fs.iter().any(|f| f.rec_call.as_ref().is_some_and(|(a, _)| self.same_args(a, &args_c)));
                if !dup {
                    fs.push(Fact { rec_call: Some((args_c, shift(&self.commit(&dp), k))), ..Fact::marker(self.tt(), self.unit_ty()) });
                }
            }
        }
        // the proofs a call passes (a callee's preconditions): reused facts
        let mut pre = Vec::new();
        collect_call_proofs(self.env, &self.commit(t), &mut pre);
        for (p, ty) in pre {
            fs.push(Fact { reused: true, ..Fact::eq(shift(&self.commit(&p), k), shift(&self.commit(&ty), k)) });
        }
    }

    /// Whether two argument lists are the same (relevant parts, alpha).
    fn same_args(&self, a: &Args, b: &Args) -> bool {
        a.len() == b.len() && a.iter().zip(b).all(|((r1, x), (r2, y))| r1 == r2 && (*r1 == Rel::Irr || self.env.alpha_eq_relevant(x, y, &|p, q| p == q)))
    }

    /// The first self-call of `val` whose induction hypothesis is not yet
    /// applied (its arguments, committed, at the current depth).
    fn pending_rec(&self, val: &Tm, facts: &[Fact]) -> Option<(Args, Tm)> {
        let rf = self.rec_fn.as_ref()?;
        let mut recs = Vec::new();
        collect_recs(val, &mut recs);
        for (args, dp) in recs {
            let args_c: Args = args.iter().enumerate().map(|(i, a)| (rf.rels.get(i).copied().unwrap_or(Rel::Rel), self.commit(a))).collect();
            if !facts.iter().any(|f| f.ih_done.as_ref().is_some_and(|a| self.same_args(a, &args_c))) {
                return Some((args_c, self.commit(&dp)));
            }
        }
        None
    }

    /// A `let` whose value holds a self-call: the literal side is moved to
    /// the call (splitting the fuel and the parameters it waits for) and
    /// the induction hypothesis applied there; then the `let` is walked.
    fn reach_self_call(&mut self, ctx: &Ctx, g: &Goal, facts: &[Fact], val: &Tm) -> Result<Tm, String> {
        let mut fs = facts.to_vec();
        self.call_facts(val, 0, &mut fs);
        let (g1, wraps, newf) = self.advance(ctx, g, &fs, true)?;
        fs.extend(newf);
        if self.pending_rec(val, &fs).is_none() {
            let inner = self.walk0(ctx, &g1, &fs)?;
            return Ok(wrap(wraps, inner));
        }
        if let Some(r) = self.lit_step(ctx, &g1, &fs, true)? {
            return Ok(wrap(wraps, r));
        }
        let (args, _) = self.pending_rec(val, &fs).unwrap();
        let names: Vec<Name> = ctx.entries.iter().map(|e| e.name.clone()).collect();
        let lcall = self.ih_lcall(ctx, &args).map(|t| self.env.print_term(&names, &t)).unwrap_or_default();
        Err(self.fail(ctx, &g1, &format!("the self-call is not reached in the literal side (the induction hypothesis's literal side: {})", trunc(&lcall, 2000))))
    }

    /// The induction hypothesis's literal side `run n b0 (Some init(ā))` at
    /// the current fuel.
    fn ih_lcall(&self, ctx: &Ctx, args: &Args) -> Result<Tm, String> {
        let rf = self.rec_fn.as_ref().ok_or("no recursion")?;
        let ni = ctx.depth().0 - 1 - self.n_level;
        let mut sub: Vec<Tm> = args.iter().filter(|(r, _)| *r == Rel::Rel).map(|(_, a)| a.clone()).collect();
        sub.push(mk::var(ni));
        Ok(crate::opt::proof::steps::subst_n(&rf.l_of, &sub))
    }

    /// One split the literal side waits for before it can go on: the fuel
    /// (at a self-call, `with_fuel`) or a parameter's constructor (a
    /// variable of the context, split on both sides).
    fn lit_step(&mut self, ctx: &Ctx, g: &Goal, facts: &[Fact], with_fuel: bool) -> Result<Option<Tm>, String> {
        let lv = self.eval(ctx, &g.l)?;
        let Some((block, _, _)) = self.blocker(ctx, &lv) else { return Ok(None) };
        let bt = self.quote(ctx, &block);
        let Term::Var(Idx(i)) = &*bt else { return Ok(None) };
        let d = ctx.depth().0;
        let lvl = d - 1 - *i;
        if lvl == self.n_level {
            if with_fuel && self.prem_in_ctx {
                return self.fuel_split_mid(ctx, g, facts).map(Some);
            }
            return Ok(None);
        }
        let e = &ctx.entries[lvl as usize];
        if e.rel != Rel::Rel || e.def.is_some() {
            return Ok(None);
        }
        let Value::Ind { ind, .. } = &*e.ty else { return Ok(None) };
        if self.env.inductive_decl(*ind).is_none_or(|d| d.ctors.len() < 2) || self.env.inductive_is_recursive(*ind).unwrap_or(true) {
            return Ok(None);
        }
        self.var_split(ctx, g, facts, lvl)
    }

    /// The literal side waits for fuel at a self-call, mid-walk: `n` split,
    /// `Nil` contradicting the premise (with a pending call's decrease), the
    /// walk going on under `Cons(u, n1)` with `n1` the current fuel.
    fn fuel_split_mid(&mut self, ctx: &Ctx, g: &Goal, facts: &[Fact]) -> Result<Tm, String> {
        self.stats.fuel_splits += 1;
        let list = self.ind("List");
        let unit = self.unit_ty();
        let lu = self.list_unit();
        let n_idx = ctx.depth().0 - 1 - self.n_level;
        let nvar = mk::var(n_idx);
        let nv = self.eval(ctx, &nvar)?;
        let l_abs = self.abstract_l(ctx, &g.l, &nv)?;
        let eq_ye = mk::eq(shift(&lu, 1), shift(&nvar, 1), mk::var(0));
        let g_y = g.with(shift(&l_abs, 1), shift(&g.s, 2), 2);
        let motive = mk::pi("e", Rel::Irr, eq_ye, self.goal_c(&g_y));
        let nil_t = Rc::new(Term::Ctor { ind: list, ctor: 0, params: vec![unit.clone()], args: vec![] });
        let nil_eq = mk::eq(lu.clone(), nvar.clone(), nil_t.clone());
        let ectx0 = self.push(ctx, "e", Rel::Irr, &nil_eq, None)?;
        let mut fs0: Vec<Fact> = facts.iter().map(|f| f.shifted(1)).collect();
        fs0.push(Fact::eq(mk::var(0), shift(&nil_eq, 1)));
        // (a pending self-call's decrease: the measure is positive)
        for f in facts.iter() {
            if let Some((args, dp)) = &f.rec_call
                && !facts.iter().any(|h| h.ih_done.as_ref().is_some_and(|a| self.same_args(a, args)))
            {
                let cargs: Vec<Tm> = args.iter().map(|(_, a)| shift(a, 1)).collect();
                fs0.push(self.decrease_rec(&ectx0, &cargs, &shift(dp, 1)));
            }
        }
        if let Some(c) = self.measure_cong(&ectx0, &fs0)? {
            fs0.push(c);
        }
        let empty = mk::ind(self.env.empty_ind(), vec![]);
        let pf0 = self.linarith_fuel(&ectx0, &fs0, &empty).map_err(|e| self.fail(ctx, g, &format!("no fuel at a self-call: {e}")))?;
        let g_nil = g.with(inst0_under(&l_abs, 1, &shift(&nil_t, 1)), shift(&g.s, 1), 1);
        let nil_body = Rc::new(Term::Absurd { ty: self.goal_c(&g_nil), proof: pf0 });
        let cons_decl = self.env.inductive_decl(list).unwrap().ctors[1].clone();
        let (actx, ctor_tm) = self.arm_ctx(ctx, list, std::slice::from_ref(&unit), &cons_decl, &[name("u"), name("n1")])?;
        let cons_eq = mk::eq(shift(&lu, 2), shift(&nvar, 2), ctor_tm.clone());
        let ectx1 = self.push(&actx, "e", Rel::Irr, &cons_eq, None)?;
        let mut fs1: Vec<Fact> = facts.iter().map(|f| f.shifted(3)).collect();
        fs1.push(Fact::eq(mk::var(0), shift(&cons_eq, 1)));
        let g1 = g.with(inst0_under(&l_abs, 3, &shift(&ctor_tm, 1)), shift(&g.s, 3), 3);
        let saved = self.n_level;
        self.n_level = ctx.depth().0 + 1;
        self.path.push("fuel".into());
        let cons_body = self.walk0(&ectx1, &g1, &fs1);
        self.path.pop();
        self.n_level = saved;
        let cons_body = cons_body?;
        let arms = vec![Arm { names: vec![], body: mk::lam("e", Rel::Irr, nil_eq, nil_body) }, Arm { names: vec![name("u"), name("n1")], body: mk::lam("e", Rel::Irr, cons_eq, cons_body) }];
        let m = Rc::new(Term::Match { ind: list, params: vec![unit.clone()], scrut: nvar.clone(), motive, arms });
        Ok(Rc::new(Term::App { rel: Rel::Irr, fun: m, arg: mk::refl(lu, nvar) }))
    }

    /// `let x = v; body` where the facts leave `v` one constructor (a
    /// presence equation about a call's result): split on `v`, the literal
    /// side abstracted over it, `x` that constructor in the body, the other
    /// arms refuted.
    fn let_split(&mut self, ctx: &Ctx, g: &Goal, facts: &[Fact]) -> Result<Option<Tm>, String> {
        let Term::Let { name: xn, rel: Rel::Rel, ty, val, body } = &*g.s else { return Ok(None) };
        let cval = self.commit(val);
        let v = self.eval(ctx, &cval)?;
        if !matches!(&*v, Value::Neu(_)) {
            return Ok(None);
        }
        let tyv = self.eval(ctx, &self.commit(ty))?;
        let Value::Ind { ind, params } = &*tyv else { return Ok(None) };
        let ind = *ind;
        let decl = self.env.inductive_decl(ind).ok_or("no inductive")?;
        // (the facts that can decide it: Bool equations, the presence ones)
        let bool_ind = self.env.bool_ind();
        let deciding: Vec<Fact> = facts.iter().filter(|f| !f.is_marker() && matches!(&*f.ty, Term::Eq { ty, .. } if matches!(&**ty, Term::Ind { ind, .. } if *ind == bool_ind))).cloned().collect();
        if decl.ctors.len() < 2 || !deciding.iter().any(|f| self.mentions(ctx, &f.ty, &v)) {
            return Ok(None);
        }
        let params_t: Vec<Tm> = params.iter().map(|p| self.quote(ctx, p)).collect();
        let mut alive = Vec::new();
        for (ci, c) in decl.ctors.iter().enumerate() {
            let names: Vec<Name> = c.fields.iter().map(|f| f.0.clone()).collect();
            let (actx, ctor_tm) = self.arm_ctx(ctx, ind, &params_t, c, &names)?;
            if !self.refuted_by(&actx, &cval, c.fields.len() as u32, &ctor_tm, &deciding)? {
                alive.push(ci);
            }
        }
        if alive.len() != 1 {
            return Ok(None);
        }
        self.stats.l_splits += 1;
        if self.trace {
            eprintln!("  let-split on {xn} (constructor {})", decl.ctors[alive[0]].name);
        }
        let dty = mk::ind(ind, params_t.clone());
        let l_abs = self.abstract_l(ctx, &g.l, &v)?; // (ctx, y)
        let eq_ye = mk::eq(shift(&dty, 1), shift(&cval, 1), mk::var(0));
        let ctx_y = self.push(ctx, "y", Rel::Rel, &dty, None)?;
        let ctx_ye = self.push(&ctx_y, "e", Rel::Irr, &eq_ye, None)?;
        let g_y = g.with(shift(&l_abs, 1), inst0_under(body, 2, &mk::var(1)), 2);
        let motive = mk::pi("e", Rel::Irr, eq_ye, self.goal(&ctx_ye, &g_y));
        let mut arms = Vec::new();
        for (ci, c) in decl.ctors.clone().iter().enumerate() {
            let names: Vec<Name> = c.fields.iter().map(|f| f.0.clone()).collect();
            let nf = c.fields.len() as u32;
            let (actx, ctor_tm) = self.arm_ctx(ctx, ind, &params_t, c, &names)?;
            let eq_ty = mk::eq(shift(&dty, nf as i64), shift(&cval, nf as i64), ctor_tm.clone());
            let ectx = self.push(&actx, "e", Rel::Irr, &eq_ty, None)?;
            let ctor1 = shift(&ctor_tm, 1);
            let g_arm = g.with(inst0_under(&l_abs, nf + 1, &ctor1), inst0_under(body, nf + 1, &ctor1), nf as i64 + 1);
            let mut fs: Vec<Fact> = facts.iter().map(|f| f.shifted(nf as i64 + 1)).collect();
            fs.push(Fact::eq(mk::var(0), shift(&eq_ty, 1)));
            let body_pf = if ci == alive[0] {
                self.path.push(format!("let {xn} = {}", c.name));
                let r = self.walk(&ectx, &g_arm, &fs);
                self.path.pop();
                r?
            } else {
                let pf = self.refute_eval(&ectx, &fs)?.ok_or_else(|| self.fail(&ectx, &g_arm, &format!("the arm `{}` of `{xn}` is not refuted", c.name)))?;
                self.stats.refuted += 1;
                Rc::new(Term::Absurd { ty: self.goal(&ectx, &g_arm), proof: pf })
            };
            arms.push(Arm { names, body: mk::lam("e", Rel::Irr, eq_ty, body_pf) });
        }
        let m = Rc::new(Term::Match { ind, params: params_t, scrut: cval.clone(), motive, arms });
        Ok(Some(Rc::new(Term::App { rel: Rel::Irr, fun: m, arg: mk::refl(dty, cval) })))
    }

    /// Whether a term mentions (up to conversion, outside binders) the value `v`.
    fn mentions(&self, ctx: &Ctx, t: &Tm, v: &V) -> bool {
        if let Term::Eq { lhs, rhs, .. } = &**t {
            return self.mentions(ctx, lhs, v) || self.mentions(ctx, rhs, v);
        }
        self.abs_syn(ctx, t, v).is_ok_and(|a| count_var(&a, 0) > 0)
    }

    /// Whether some fact `Eq(T, a, b)`, one side a constructor and the other
    /// mentioning `v`, evaluates to two different constructors once `v` is
    /// `ctor_tm` (the arm's constructor, in `actx` = the context with its
    /// `nf` fields).
    fn refuted_by(&self, actx: &Ctx, v_t: &Tm, nf: u32, ctor_tm: &Tm, facts: &[Fact]) -> Result<bool, String> {
        let vt = shift(v_t, nf as i64);
        let vv = self.eval(actx, &vt)?;
        for f in facts.iter().filter(|f| !f.is_marker()) {
            let fty = shift(&f.ty, nf as i64);
            let Term::Eq { lhs, rhs, .. } = &*fty else { continue };
            for (side, other) in [(lhs, rhs), (rhs, lhs)] {
                let ov = self.eval(actx, other)?;
                let Value::Ctor { ctor: oc, .. } = &*ov else { continue };
                let a = self.abs_syn(actx, side, &vv)?;
                if count_var(&a, 0) == 0 {
                    continue;
                }
                let inst = crate::elab::tm::subst0(&a, ctor_tm);
                if let Value::Ctor { ctor: c2, .. } = &*self.eval(actx, &inst)?
                    && c2 != oc
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// A structured term whose head is a match on a constructor: the arm
    /// (convertible by iota).
    fn reduce_head(&self, ctx: &Ctx, t: &Tm) -> Result<Option<Tm>, String> {
        let Term::App { rel: Rel::Irr, fun, arg } = &**t else { return Ok(None) };
        let Term::Match { scrut, arms, .. } = &**fun else { return Ok(None) };
        let sv = self.eval(ctx, &self.commit(scrut))?;
        let Value::Ctor { ctor, args, .. } = &*sv else { return Ok(None) };
        let a = &arms[*ctor as usize];
        let fields: Vec<Tm> = args.iter().map(|x| match x {
            Arg::Rel(v) => self.quote(ctx, v),
            Arg::Irr(_) => mk::refl(self.unit_ty(), self.tt()),
        }).collect();
        if args.iter().any(|x| matches!(x, Arg::Irr(_))) {
            return Ok(None);
        }
        let inst = crate::opt::proof::steps::subst_n(&a.body, &fields);
        let Term::Lam { rel: Rel::Irr, body, .. } = &*inst else { return Ok(None) };
        Ok(Some(crate::elab::tm::subst0(body, arg)))
    }

    /// The index (in evaluation order) of the first match of the dependent
    /// idiom whose scrutinee is stuck.
    fn stuck_idiom(&self, ctx: &Ctx, t: &Tm) -> Result<Option<usize>, String> {
        let mut k = 0usize;
        let mut found: Option<usize> = None;
        let mut err: Option<String> = None;
        idiom_map(t, &mut |node| {
            if found.is_none() && err.is_none() {
                let Term::App { fun, .. } = &**node else { return None };
                let Term::Match { scrut, .. } = &**fun else { return None };
                match self.eval(ctx, &self.commit(scrut)) {
                    Ok(v) => {
                        if !matches!(&*v, Value::Ctor { .. }) {
                            found = Some(k);
                        }
                    }
                    Err(e) => err = Some(e),
                }
            }
            k += 1;
            None
        });
        if let Some(e) = err {
            return Err(e);
        }
        Ok(found)
    }

    /// The structured reading's split at its `k`-th match: the literal side
    /// abstracted by evaluation, the structured side `K[M(y) e]` (the
    /// match on `y`, applied to the path equation; `K` the context of the
    /// match in the term), each arm `K[arm]`.
    fn s_split_at(&mut self, ctx: &Ctx, g: &Goal, k: usize, facts: &[Fact]) -> Result<Tm, String> {
        let t = g.s.clone();
        let idiom = nth_idiom(&t, k).ok_or("no such match")?;
        let Term::App { fun, .. } = &*idiom else { unreachable!() };
        let Term::Match { ind, params, scrut, motive: s_motive, arms } = &**fun else { unreachable!() };
        let ind = *ind;
        let cscrut = self.commit(scrut);
        let sv = self.eval(ctx, &cscrut)?;
        let mut l_abs = self.abstract_l(ctx, &g.l, &sv)?; // (ctx, y)
        // (a dependent test of the literal side on the scrutinee whose proof
        // is used at its old type — a leaf's `if c as .h` handing `h` to
        // `slice::range` — cannot be abstracted: the literal side stays as it
        // is, and the path equation decides its test in each arm)
        if idiom_on(&l_abs, 0) {
            let dty0 = mk::ind(ind, params.to_vec());
            let cy = self.push(ctx, "y", Rel::Rel, &dty0, None)?;
            if self.env.infer(&cy, &mk::eq(shift(&self.opt_out(), 1), l_abs.clone(), l_abs.clone()), &mut self.b()).is_err() {
                l_abs = shift(&g.l, 1);
            }
        }
        let refined = count_var(&l_abs, 0) > 0;
        let names: Vec<Name> = ctx.entries.iter().map(|e| e.name.clone()).collect();
        let scrut_txt = trunc(&self.env.print_term(&names, &self.quote(ctx, &sv)), 140);
        if std::env::var("CS_TRACE_S").is_ok() {
            eprintln!("  S-SPLIT k={k} S = {}", trunc(&self.env.print_term(&names, &self.commit(&t)), 6000));
        }
        if self.trace {
            eprintln!("  S-split on {scrut_txt} ; literal side refined: {refined}");
            if !refined && std::env::var("CS_TRACE_SPLIT").is_ok() {
                let lt = self.quote(ctx, &self.eval(ctx, &g.l)?);
                eprintln!("    scrutinee {}\n    literal   {}", trunc(&self.env.print_term(&[], &self.quote(ctx, &sv)), 4000), trunc(&self.env.print_term(&[], &lt), 12000));
            }
        }
        // (a scrutinee the literal side does not hold, e.g. `ord_lt(pc)` where
        // the literal side tests `pc` itself: both arms are walked; the
        // literal side is split at the terminals and the arm that
        // contradicts the path is refuted by evaluation, `refute_eval`)
        let dty = mk::ind(ind, params.to_vec());
        // the structured side at y: K[M(y) e], in (ctx, y, e)
        let m_y = Rc::new(Term::Match { ind, params: params.iter().map(|p| shift(p, 2)).collect(), scrut: mk::var(1), motive: shift_from(s_motive, 2, 1), arms: arms.iter().map(|a| Arm { names: a.names.clone(), body: shift_from(&a.body, 2, a.names.len() as u32) }).collect() });
        let s_y_hole = Rc::new(Term::App { rel: Rel::Irr, fun: m_y, arg: mk::var(0) });
        let s_y = replace_nth_idiom(&shift(&t, 2), k, &s_y_hole);
        let ctx_y = self.push(ctx, "y", Rel::Rel, &dty, None)?;
        let eq_ye = mk::eq(shift(&dty, 1), shift(&cscrut, 1), mk::var(0));
        let ctx_ye = self.push(&ctx_y, "e", Rel::Irr, &eq_ye, None)?;
        let g_y = g.with(shift(&l_abs, 1), s_y, 2);
        let motive = mk::pi("e", Rel::Irr, eq_ye, self.goal(&ctx_ye, &g_y));
        let decl = self.env.inductive_decl(ind).ok_or("no inductive")?;
        let mut new_arms = Vec::new();
        for (ci, c) in decl.ctors.iter().enumerate() {
            let a = &arms[ci];
            let nf = c.fields.len() as u32;
            let (actx, ctor_tm) = self.arm_ctx(ctx, ind, params, c, &a.names)?;
            let eq_ty = mk::eq(shift(&dty, nf as i64), shift(&cscrut, nf as i64), ctor_tm.clone());
            let ectx = self.push(&actx, "e", Rel::Irr, &eq_ty, None)?;
            let l_arm = inst0_under(&l_abs, nf + 1, &shift(&ctor_tm, 1));
            let Term::Lam { rel: Rel::Irr, body: sbody, .. } = &*a.body else { return Err("an arm without its path equation".into()) };
            let s_arm = replace_nth_idiom(&shift(&t, nf as i64 + 1), k, sbody);
            let g_arm = g.with(l_arm, s_arm, nf as i64 + 1);
            let mut fs: Vec<Fact> = facts.iter().map(|f| f.shifted(nf as i64 + 1)).collect();
            fs.push(Fact::eq(mk::var(0), shift(&eq_ty, 1)));
            self.path.push(format!("S-split on {scrut_txt} = {}", c.name));
            let body = self.walk(&ectx, &g_arm, &fs);
            self.path.pop();
            new_arms.push(Arm { names: a.names.clone(), body: mk::lam("e", Rel::Irr, eq_ty, body?) });
        }
        let m = Rc::new(Term::Match { ind, params: params.to_vec(), scrut: cscrut.clone(), motive, arms: new_arms });
        Ok(Rc::new(Term::App { rel: Rel::Irr, fun: m, arg: mk::refl(dty, cscrut) }))
    }

    /// Splits the first pending struct-typed variable (eta).
    fn eta(&mut self, ctx: &Ctx, g: &Goal, facts: &[Fact]) -> Result<Option<Tm>, String> {
        let n = ctx.entries.len();
        for lvl in 0..n {
            let e = &ctx.entries[lvl];
            if e.rel != Rel::Rel || e.def.is_some() || !self.eta_vars.contains(&(lvl as u32)) {
                continue;
            }
            self.eta_vars.retain(|x| *x != lvl as u32);
            let Value::Ind { ind, .. } = &*e.ty else { continue };
            let Some(decl) = self.env.inductive_decl(*ind) else { continue };
            // (a field-less struct converts with its constructor by eta)
            if decl.ctors.len() != 1 || decl.ctors[0].fields.is_empty() || self.env.inductive_is_recursive(*ind).unwrap_or(true) {
                continue;
            }
            if let Some(r) = self.var_split(ctx, g, facts, lvl as u32)? {
                self.stats.eta_splits += 1;
                return Ok(Some(r));
            }
        }
        Ok(None)
    }

    /// The later entries of the context whose types mention the variable at
    /// `lvl`: `(level, type in the full context)`; `None` when one of them
    /// is relevant (it cannot follow the variable through a split).
    fn dependents(&self, ctx: &Ctx, lvl: u32) -> Option<Vec<(u32, Tm)>> {
        let n = ctx.entries.len() as u32;
        let mut out = Vec::new();
        for j in lvl + 1..n {
            let e = &ctx.entries[j as usize];
            let pre = Ctx { entries: Rc::new(ctx.entries[..j as usize].to_vec()) };
            let ty = self.env.quote_typed(&pre, &e.ty, None, true);
            if count_var(&ty, j - 1 - lvl) == 0 && !out.iter().any(|(h, _)| count_var(&ty, j - 1 - h) > 0) {
                continue;
            }
            // a relevant entry blocks the split; an irrelevant one (a proof,
            // also a `let`-bound one: a lemma applied at the start of the
            // function whose statement mentions a parameter) is transported
            // along the path equation like any proof about the variable
            if e.rel == Rel::Rel {
                return None;
            }
            out.push((j, shift(&ty, (n - j) as i64)));
        }
        Some(out)
    }


    /// Splits the variable at `lvl` (both sides: the literal and the
    /// structured side and the presence inputs, the variable replaced by
    /// each constructor; a proof of the context about it transported along
    /// the path equation). For a struct this is eta (its fields split in
    /// turn, unless an invariant field's type mentions them).
    fn var_split(&mut self, ctx: &Ctx, g: &Goal, facts: &[Fact], lvl: u32) -> Result<Option<Tm>, String> {
        let n = ctx.entries.len() as u32;
        let e = ctx.entries[lvl as usize].clone();
        let Value::Ind { ind, params } = &*e.ty else { return Ok(None) };
        let ind = *ind;
        let Some(decl) = self.env.inductive_decl(ind) else { return Ok(None) };
        let Some(deps) = self.dependents(ctx, lvl) else { return Ok(None) };
        let deps: Vec<(u32, Tm)> = deps.into_iter().map(|(j, t)| (n - 1 - j, t)).collect();
        let k = n - 1 - lvl;
        let params_t: Vec<Tm> = params.iter().map(|p| self.quote(ctx, p)).collect();
        let dty = mk::ind(ind, params_t.clone());
        let single = decl.ctors.len() == 1;
        if !single {
            self.stats.l_splits += 1;
        }
        if self.trace {
            eprintln!("  split of the variable {} ({} constructors, {} dependent proofs)", e.name, decl.ctors.len(), deps.len());
        }
        let ctx_y = self.push(ctx, "y", Rel::Rel, &dty, None)?;
        let eq_ye = mk::eq(shift(&dty, 1), mk::var(k + 1), mk::var(0));
        let ctx_ye = self.push(&ctx_y, "e", Rel::Irr, &eq_ye, None)?;
        let rep = |t: &Tm, c: &Tm, kk: u32| replace_split(&shift(t, kk as i64), k, c, &deps, &dty, kk);
        let gy = Goal { l: rep(&g.l, &mk::var(1), 2), s: rep(&g.s, &mk::var(1), 2), ins: g.ins.iter().map(|t| rep(t, &mk::var(1), 2)).collect(), rhs: g.rhs.as_ref().map(|t| rep(t, &mk::var(1), 2)), acc: g.acc.as_ref().map(|t| rep(t, &mk::var(1), 2)) };
        let motive = mk::pi("e", Rel::Irr, eq_ye, self.goal(&ctx_ye, &gy));
        let mut arms = Vec::new();
        for c in decl.ctors.clone().iter() {
            let nf = c.fields.len() as u32;
            let names: Vec<Name> = c.fields.iter().map(|f| f.0.clone()).collect();
            let (actx, ctor_tm) = self.arm_ctx(ctx, ind, &params_t, c, &names)?;
            let eq_ty = mk::eq(shift(&dty, nf as i64), mk::var(k + nf), ctor_tm.clone());
            let ectx = self.push(&actx, "e", Rel::Irr, &eq_ty, None)?;
            let ctor1 = shift(&ctor_tm, 1);
            let g_arm = Goal { l: rep(&g.l, &ctor1, nf + 1), s: rep(&g.s, &ctor1, nf + 1), ins: g.ins.iter().map(|t| rep(t, &ctor1, nf + 1)).collect(), rhs: g.rhs.as_ref().map(|t| rep(t, &ctor1, nf + 1)), acc: g.acc.as_ref().map(|t| rep(t, &ctor1, nf + 1)) };
            let mut fs: Vec<Fact> = facts.iter().map(|f| f.shifted(nf as i64 + 1)).collect();
            fs.push(Fact::eq(mk::var(0), shift(&eq_ty, 1)));
            // (a struct's fields are split in turn, unless an invariant
            // field's type mentions them: splitting one would not reach it)
            let base = ctx.entries.len() as u32;
            if single && c.fields.iter().all(|f| f.1 == Rel::Rel) {
                for j in 0..nf {
                    self.eta_vars.push(base + j);
                }
            }
            if !single {
                self.path.push(format!("{} = {}", e.name, c.name));
            }
            let body = self.walk(&ectx, &g_arm, &fs);
            if !single {
                self.path.pop();
            }
            arms.push(Arm { names, body: mk::lam("e", Rel::Irr, eq_ty, body?) });
        }
        let m = Rc::new(Term::Match { ind, params: params_t, scrut: mk::var(k), motive, arms });
        Ok(Some(Rc::new(Term::App { rel: Rel::Irr, fun: m, arg: mk::refl(dty, mk::var(k)) })))
    }

    /// [`Self::abstract_l`], well-typed for `y : cty`: the occurrences in
    /// proofs abstracted too when the relevant ones alone leave a proof about
    /// the value ill-typed (a library function's `if c(v) as .h` on it).
    fn abstract_l_typed(&self, ctx: &Ctx, l: &Tm, c: &V, cty: &Tm) -> Result<Tm, String> {
        let r = self.abstract_l(ctx, l, c)?;
        if count_var(&r, 0) == 0 || self.at_header {
            return Ok(r);
        }
        let ctyv = self.eval(ctx, cty)?;
        let cy = ctx.push(CtxEntry { name: name("y"), rel: Rel::Rel, ty: ctyv, def: None });
        let lt = mk::eq(shift(&self.opt_out(), 1), r.clone(), r.clone());
        if self.env.infer(&cy, &lt, &mut self.b()).is_ok() {
            return Ok(r);
        }
        let carrier = mk::eq(self.opt_out(), l.clone(), l.clone());
        let cv = self.eval(ctx, &carrier)?;
        let mut b = self.b();
        let abs = self.env.abstract_occurrences_ext(ctx, &cv, c, true, &mut b).map_err(|e| format!("abstract: {e}"))?;
        let Term::Eq { lhs, .. } = &*abs else { return Ok(r) };
        let r2 = repair_idiom(&self.repair_unit(lhs, 0), 0);
        let r2 = if has_erased_pair(&r2) { self.complete_erased(&cy, &r2) } else { r2 };
        let lt2 = mk::eq(shift(&self.opt_out(), 1), r2.clone(), r2.clone());
        match self.env.infer(&cy, &lt2, &mut self.b()) {
            Ok(_) => Ok(r2),
            Err(e) => {
                if std::env::var("CS_TRACE_ABS").is_ok() {
                    eprintln!("  abstraction ill-typed both ways: {}", trunc(&e.to_string(), 300));
                    let mut shown = 0;
                    crate::auto::util::map_term(&r2, 0, &mut |x, d| {
                        if shown < 2
                            && let Term::App { rel: Rel::Irr, fun, .. } = &**x
                            && let Term::Match { scrut, .. } = &**fun
                            && count_var(scrut, d) > 0
                        {
                            shown += 1;
                            eprintln!("    idiom on the value: {}", trunc(&self.env.print_term(&[], x), 2500));
                        }
                        None
                    });
                }
                Ok(r)
            }
        }
    }

    /// The literal side abstracted over a value `c`: a term in `(ctx, y)`.
    fn abstract_l(&self, ctx: &Ctx, l: &Tm, c: &V) -> Result<Tm, String> {
        self.abstract_l1(ctx, l, c)
    }

    fn abstract_l1(&self, ctx: &Ctx, l: &Tm, c: &V) -> Result<Tm, String> {
        self.abstract_l_folding(ctx, l, c, &[])
    }

    /// `t` evaluated with the globals `fold` kept folded.
    fn eval_folding(&self, ctx: &Ctx, t: &Tm, fold: &[GlobalId]) -> Result<V, String> {
        if fold.is_empty() {
            return self.eval(ctx, t);
        }
        let opq = fold.to_vec();
        let isop = move |g: GlobalId| opq.contains(&g);
        let mut b = self.b();
        self.env.eval_opaque(&self.env.ctx_venv(ctx), ctx.depth(), t, &isop, &mut b).map_err(|e| format!("eval: {e:?}"))
    }

    /// [`Self::abstract_l1`] with the runs `fold` kept folded.
    fn abstract_l_folding(&self, ctx: &Ctx, l: &Tm, c: &V, fold: &[GlobalId]) -> Result<Tm, String> {
        let carrier = mk::eq(self.opt_out(), l.clone(), l.clone());
        // (at a loop header the runs stay folded: the literal side must stay
        // at the header, its state normalized)
        let cv = if self.at_header {
            let mut opq = self.l_runs.clone();
            opq.extend(self.opaque.iter().copied());
            let isop = move |g: GlobalId| opq.contains(&g);
            let mut b = self.b();
            self.env.eval_opaque(&self.env.ctx_venv(ctx), ctx.depth(), &carrier, &isop, &mut b).map_err(|e| format!("eval: {e:?}"))?
        } else {
            self.eval_folding(ctx, &carrier, fold)?
        };
        let mut b = self.b();
        let abs = self.env.abstract_occurrences_ext(ctx, &cv, c, false, &mut b).map_err(|e| format!("abstract: {e}"))?;
        let Term::Eq { lhs, .. } = &*abs else { return Err("abstracted carrier is not an Eq".into()) };
        let r = repair_idiom(&self.repair_unit(lhs, 0), 0);
        // (pairs the quoter could not type, inside proofs quoted by
        // substitution: completed)
        if has_erased_pair(&r) {
            let tyc = {
                let mut b = self.b();
                let ct = self.env.quote_typed(ctx, c, None, true);
                self.env.infer(ctx, &ct, &mut b).ok()
            };
            if let Some(tyc) = tyc {
                let cy = ctx.push(CtxEntry { name: name("y"), rel: Rel::Rel, ty: tyc, def: None });
                return Ok(self.complete_erased(&cy, &r));
            }
        }
        Ok(r)
    }

    /// An erased pair `(fst, snd)` as a prelude slice `Slice T` (`snd` the
    /// pair of an explicit list and its proof) or a prelude array `Array T N`
    /// (`fst` an explicit list of `N` elements), read off the syntax (the
    /// kernel checks it with the proof).
    fn syn_pair(&self, fst: &Tm, snd: &Tm) -> Option<Tm> {
        let list = self.env.lookup_ind("List")?;
        let list_elem = |t: &Tm| -> Option<(Tm, i64)> {
            let mut n = 0i64;
            let mut cur = t.clone();
            let mut elem = None;
            loop {
                match &*cur {
                    Term::Ctor { ind, ctor: 0, params, .. } if *ind == list => {
                        elem = elem.or_else(|| params.first().cloned());
                        break;
                    }
                    Term::Ctor { ind, ctor: 1, params, args } if *ind == list && args.len() == 2 => {
                        elem = elem.or_else(|| params.first().cloned());
                        n += 1;
                        cur = args[1].clone();
                    }
                    _ => return None,
                }
            }
            elem.map(|e| (e, n))
        };
        if let Term::Pair { fst: bl, snd: bp, .. } = &**snd
            && let Some((elem, _)) = list_elem(bl)
        {
            let slice_ok = self.env.lookup_global("SliceOk")?;
            let slice = self.env.lookup_global("Slice")?;
            let inner_ty = Rc::new(Term::Sigma { name: name("l2"), snd_rel: Rel::Irr, fst: mk::ind(list, vec![elem.clone()]), snd: mk::apps(mk::global(slice_ok), vec![(Rel::Rel, shift(&elem, 1)), (Rel::Rel, shift(fst, 1)), (Rel::Rel, mk::var(0))]) });
            let inner = Rc::new(Term::Pair { ty: inner_ty, fst: bl.clone(), snd: bp.clone() });
            return Some(Rc::new(Term::Pair { ty: mk::app(mk::global(slice), elem), fst: fst.clone(), snd: inner }));
        }
        if let Some((elem, n)) = list_elem(fst) {
            let array = self.env.lookup_global("Array")?;
            let aty = mk::apps(mk::global(array), vec![(Rel::Rel, elem), (Rel::Rel, mk::lit(Width::Usize, n))]);
            return Some(Rc::new(Term::Pair { ty: aty, fst: fst.clone(), snd: snd.clone() }));
        }
        None
    }

    /// `t` (in `ctx`) with every pair of an erased type (`pair(_, a, b)`:
    /// the quoter's read-back of a pair captured by a proof quoted by
    /// substitution) given its type: a slice or array by its syntax, else
    /// its Σ type from the types of its components (the second abstracted
    /// over the first); an irrelevant argument holding such a pair replaced
    /// by a proof of its proposition (`refl`, `linarith`). Binders are
    /// followed with their types; shared subterms are completed once.
    fn complete_erased(&self, ctx: &Ctx, t: &Tm) -> Tm {
        let mut memo: std::collections::HashMap<(*const Term, u32), Tm> = Default::default();
        let mut has: std::collections::HashMap<*const Term, bool> = Default::default();
        let t = hashcons(t);
        self.ce(ctx, &t, &mut memo, &mut has)
    }

    fn ce(&self, ctx: &Ctx, t: &Tm, memo: &mut std::collections::HashMap<(*const Term, u32), Tm>, has: &mut std::collections::HashMap<*const Term, bool>) -> Tm {
        if !has_erased_memo(t, has) {
            return t.clone();
        }
        let key = (Rc::as_ptr(t), ctx.depth().0);
        if let Some(r) = memo.get(&key) {
            return r.clone();
        }
        let r = self.ce_node(ctx, t, memo, has);
        memo.insert(key, r.clone());
        r
    }

    fn ce_node(&self, ctx: &Ctx, t: &Tm, memo: &mut std::collections::HashMap<(*const Term, u32), Tm>, has: &mut std::collections::HashMap<*const Term, bool>) -> Tm {
        macro_rules! go {
            ($c:expr, $x:expr) => {
                self.ce($c, $x, memo, has)
            };
        }
        let push = |c: &Ctx, n: &Name, r: Rel, ty: &Tm| self.push(c, n, r, ty, None).ok();
        match &**t {
            Term::Pair { ty, fst, snd } if matches!(&**ty, Term::Erased) => {
                let f2 = go!(ctx, fst);
                let s2 = go!(ctx, snd);
                if let Some(p) = self.syn_pair(&f2, &s2) {
                    return p;
                }
                let mut b = self.b();
                let tr = std::env::var("CS_TRACE_ERASED").is_ok();
                let tf = match self.env.infer(ctx, &f2, &mut b) {
                    Ok(v) => v,
                    Err(e) => {
                        if tr {
                            eprintln!("  complete: fst not typed: {} :: {}", trunc(&e.to_string(), 300), trunc(&self.env.print_term(&[], &f2), 300));
                        }
                        return Rc::new(Term::Pair { ty: ty.clone(), fst: f2, snd: s2 });
                    }
                };
                let ts = match self.env.infer(ctx, &s2, &mut b) {
                    Ok(v) => v,
                    Err(e) => {
                        if tr {
                            eprintln!("  complete: snd not typed: {} :: {}", trunc(&e.to_string(), 300), trunc(&self.env.print_term(&[], &s2), 600));
                        }
                        return Rc::new(Term::Pair { ty: ty.clone(), fst: f2, snd: s2 });
                    }
                };
                let Ok(fv) = self.eval(ctx, &f2) else { return Rc::new(Term::Pair { ty: ty.clone(), fst: f2, snd: s2 }) };
                let Ok(bt) = self.env.abstract_occurrences_ext(ctx, &ts, &fv, true, &mut b) else { return Rc::new(Term::Pair { ty: ty.clone(), fst: f2, snd: s2 }) };
                let ft = self.quote(ctx, &tf);
                for rel in [Rel::Irr, Rel::Rel] {
                    let sig = Rc::new(Term::Sigma { name: name("x"), snd_rel: rel, fst: ft.clone(), snd: bt.clone() });
                    let pr = Rc::new(Term::Pair { ty: sig.clone(), fst: f2.clone(), snd: s2.clone() });
                    let Ok(sv) = self.eval(ctx, &sig) else { continue };
                    let mut b = self.b();
                    if self.env.check(ctx, &pr, &sv, &mut b).is_ok() {
                        return pr;
                    }
                }
                Rc::new(Term::Pair { ty: ty.clone(), fst: f2, snd: s2 })
            }
            Term::Pair { ty, fst, snd } => Rc::new(Term::Pair { ty: go!(ctx, ty), fst: go!(ctx, fst), snd: go!(ctx, snd) }),
            Term::Lam { name: n, rel, dom, body } => {
                let d2 = go!(ctx, dom);
                match push(ctx, n, *rel, &d2) {
                    Some(c2) => Rc::new(Term::Lam { name: n.clone(), rel: *rel, dom: d2, body: go!(&c2, body) }),
                    None => t.clone(),
                }
            }
            Term::Pi { name: n, rel, dom, cod } => {
                let d2 = go!(ctx, dom);
                match push(ctx, n, *rel, &d2) {
                    Some(c2) => Rc::new(Term::Pi { name: n.clone(), rel: *rel, dom: d2, cod: go!(&c2, cod) }),
                    None => t.clone(),
                }
            }
            Term::Sigma { name: n, snd_rel, fst, snd } => {
                let f2 = go!(ctx, fst);
                match push(ctx, n, Rel::Rel, &f2) {
                    Some(c2) => Rc::new(Term::Sigma { name: n.clone(), snd_rel: *snd_rel, fst: f2, snd: go!(&c2, snd) }),
                    None => t.clone(),
                }
            }
            Term::Let { name: n, rel, ty, val, body } => {
                let t2 = go!(ctx, ty);
                let v2 = go!(ctx, val);
                match self.push(ctx, n, *rel, &t2, Some(&v2)).ok() {
                    Some(c2) => Rc::new(Term::Let { name: n.clone(), rel: *rel, ty: t2, val: v2, body: go!(&c2, body) }),
                    None => t.clone(),
                }
            }
            // an irrelevant argument holding such a pair (a proof quoted by
            // substitution): any proof of its proposition will do, by
            // evaluation (`refl`) or arithmetic
            Term::App { rel: Rel::Irr, fun, arg } if has_erased_pair(arg) => {
                let f2 = go!(ctx, fun);
                let mut b = self.b();
                if let Ok(fty) = self.env.infer(ctx, &f2, &mut b)
                    && let Value::Pi { dom, .. } = &*fty
                {
                    let dt = self.quote(ctx, dom);
                    let mut cands: Vec<Tm> = Vec::new();
                    if let Term::Eq { ty, lhs, .. } = &*dt {
                        cands.push(mk::refl(ty.clone(), lhs.clone()));
                    }
                    if let Ok(p) = crate::elab::basic::linarith_term(self.env, ctx, vec![], dt.clone()) {
                        cands.push(p);
                    }
                    for c in cands {
                        let mut b = self.b();
                        if self.env.check(ctx, &c, dom, &mut b).is_ok() {
                            return Rc::new(Term::App { rel: Rel::Irr, fun: f2, arg: c });
                        }
                    }
                }
                Rc::new(Term::App { rel: Rel::Irr, fun: f2, arg: go!(ctx, arg) })
            }
            Term::App { rel, fun, arg } => Rc::new(Term::App { rel: *rel, fun: go!(ctx, fun), arg: go!(ctx, arg) }),
            Term::Fst(x) => Rc::new(Term::Fst(go!(ctx, x))),
            Term::Snd(x) => Rc::new(Term::Snd(go!(ctx, x))),
            Term::Eq { ty, lhs, rhs } => Rc::new(Term::Eq { ty: go!(ctx, ty), lhs: go!(ctx, lhs), rhs: go!(ctx, rhs) }),
            Term::Refl { ty, val } => Rc::new(Term::Refl { ty: go!(ctx, ty), val: go!(ctx, val) }),
            Term::Ctor { ind, ctor, params, args } => Rc::new(Term::Ctor { ind: *ind, ctor: *ctor, params: params.iter().map(|p| go!(ctx, p)).collect(), args: args.iter().map(|a| go!(ctx, a)).collect() }),
            Term::Ind { ind, params } => Rc::new(Term::Ind { ind: *ind, params: params.iter().map(|p| go!(ctx, p)).collect() }),
            Term::Prim { op, args, proofs } => Rc::new(Term::Prim { op: *op, args: args.iter().map(|a| go!(ctx, a)).collect(), proofs: proofs.iter().map(|a| go!(ctx, a)).collect() }),
            Term::Transport { ty, lhs, rhs, eq, motive, val } => {
                let ty2 = go!(ctx, ty);
                let mot = match push(ctx, &name("y"), Rel::Rel, &ty2) {
                    Some(c2) => go!(&c2, motive),
                    None => motive.clone(),
                };
                Rc::new(Term::Transport { ty: ty2, lhs: go!(ctx, lhs), rhs: go!(ctx, rhs), eq: go!(ctx, eq), motive: mot, val: go!(ctx, val) })
            }
            Term::Match { ind, params, scrut, motive, arms } => {
                let params2: Vec<Tm> = params.iter().map(|p| go!(ctx, p)).collect();
                let dty = mk::ind(*ind, params2.clone());
                let mot = match push(ctx, &name("y"), Rel::Rel, &dty) {
                    Some(c2) => go!(&c2, motive),
                    None => motive.clone(),
                };
                let Some(decl) = self.env.inductive_decl(*ind) else { return t.clone() };
                let mut arms2 = Vec::new();
                for (k, a) in arms.iter().enumerate() {
                    let body = match decl.ctors.get(k).and_then(|c| self.arm_ctx(ctx, *ind, &params2, c, &a.names).ok()) {
                        Some((ac, _)) => go!(&ac, &a.body),
                        None => a.body.clone(),
                    };
                    arms2.push(Arm { names: a.names.clone(), body });
                }
                Rc::new(Term::Match { ind: *ind, params: params2, scrut: go!(ctx, scrut), motive: mot, arms: arms2 })
            }
            Term::Linarith { hyps, goal, cert } => Rc::new(Term::Linarith { hyps: hyps.iter().map(|(p, ty)| (go!(ctx, p), go!(ctx, ty))).collect(), goal: go!(ctx, goal), cert: cert.clone() }),
            Term::BvRefl { ty, lhs, rhs } => Rc::new(Term::BvRefl { ty: go!(ctx, ty), lhs: go!(ctx, lhs), rhs: go!(ctx, rhs) }),
            Term::Absurd { ty, proof } => Rc::new(Term::Absurd { ty: go!(ctx, ty), proof: go!(ctx, proof) }),
            Term::Axiom { ax, args } => Rc::new(Term::Axiom { ax: *ax, args: args.iter().map(|a| go!(ctx, a)).collect() }),
            Term::Rec { args, proof } => Rc::new(Term::Rec { args: args.iter().map(|a| go!(ctx, a)).collect(), proof: proof.as_ref().map(|p| go!(ctx, p)) }),
            Term::Delta { def, args } => Rc::new(Term::Delta { def: *def, args: args.iter().map(|a| go!(ctx, a)).collect() }),
            Term::Unfold { def, args, to_body, val } => Rc::new(Term::Unfold { def: *def, args: args.iter().map(|a| go!(ctx, a)).collect(), to_body: *to_body, val: go!(ctx, val) }),
            _ => t.clone(),
        }
    }

    /// The equation's right side abstracted over a value `c` (by
    /// conversion): a term in `(ctx, y)`.
    ///
    /// The structured value holds its own dependent matches on the test
    /// (`(match c as y return Π(.e : Eq(D, c, y)). R ..) .refl(D, c)`), so
    /// the occurrences in proofs are abstracted too when that keeps the
    /// abstraction well-typed (checked); otherwise only the relevant ones.
    fn abstract_rhs(&self, ctx: &Ctx, r: &Tm, c: &V) -> Result<Tm, String> {
        let cty = {
            let mut b = self.b();
            let ct = self.env.quote_typed(ctx, c, None, true);
            self.env.infer(ctx, &ct, &mut b).map_err(|e| format!("abstract: the test's type: {e}"))?
        };
        self.abstract_rhs_ty(ctx, r, c, cty)
    }

    /// [`Self::abstract_rhs`] with the test's type given.
    fn abstract_rhs_ty(&self, ctx: &Ctx, r: &Tm, c: &V, cty: V) -> Result<Tm, String> {
        let carrier = mk::eq(self.opt_out(), r.clone(), r.clone());
        let cv = self.eval(ctx, &carrier)?;
        let ctx_y = ctx.push(CtxEntry { name: name("y"), rel: Rel::Rel, ty: cty, def: None });
        for in_proofs in [false, true] {
            let mut b = self.b();
            let abs = self.env.abstract_occurrences_ext(ctx, &cv, c, in_proofs, &mut b).map_err(|e| format!("abstract: {e}"))?;
            let Term::Eq { lhs, .. } = &*abs else { return Err("abstracted carrier is not an Eq".into()) };
            let r_abs = repair_idiom(&self.repair_unit(lhs, 0), 0);
            if count_var(&r_abs, 0) == 0 {
                return Ok(r_abs);
            }
            let mut b = self.b();
            if self.env.infer(&ctx_y, &r_abs, &mut b).is_ok() {
                return Ok(r_abs);
            }
        }
        // (neither is well-typed: the right side is not abstracted)
        Ok(shift(r, 1))
    }

    /// Whether the structured term is a loop's call (a helper's, or a
    /// recursive one): its own lemma applies to it as it is.
    fn is_loop_tail(&self, s: &Tm) -> bool {
        matches!(&**s, Term::Rec { .. }) || self.loop_rec(s).is_some() || matches!(&**s, Term::Let { val, .. } if self.while_of(val).is_some()) || app_spine(s).is_some_and(|(h, _)| self.helpers.iter().any(|x| x.s_global == h))
    }

    /// `Var(y)` back to the constructor where a field-less struct is
    /// expected (`tt`, `TryGetError`, ..: every neutral converts with such a
    /// constructor by eta, so abstraction by conversion over-abstracts them).
    fn repair_unit(&self, t: &Tm, y: u32) -> Tm {
        // the constructor of a field-less struct type, `None` for any other type
        let unit_of = |ty: &Tm| -> Option<Tm> {
            let Term::Ind { ind, params } = &**ty else { return None };
            let d = self.env.inductive_decl(*ind)?;
            (d.ctors.len() == 1 && d.ctors[0].fields.is_empty()).then(|| Rc::new(Term::Ctor { ind: *ind, ctor: 0, params: params.clone(), args: vec![] }))
        };
        crate::auto::util::map_term(t, 0, &mut |x, d| {
            let is_y = |a: &Tm| matches!(&**a, Term::Var(Idx(i)) if *i == y + d);
            // (typed positions of a proof: a transport's ends, a refl, an equation)
            match &**x {
                Term::Transport { ty, lhs, rhs, eq, motive, val } if is_y(lhs) || is_y(rhs) => {
                    if let Some(u) = unit_of(ty) {
                        let fix = |a: &Tm| if is_y(a) { u.clone() } else { self.repair_unit(a, y + d) };
                        return Some(Rc::new(Term::Transport { ty: ty.clone(), lhs: fix(lhs), rhs: fix(rhs), eq: self.repair_unit(eq, y + d), motive: self.repair_unit(motive, y + d + 1), val: self.repair_unit(val, y + d) }));
                    }
                }
                Term::Refl { ty, val } if is_y(val) => {
                    if let Some(u) = unit_of(ty) {
                        return Some(Rc::new(Term::Refl { ty: ty.clone(), val: u }));
                    }
                }
                Term::Eq { ty, lhs, rhs } if is_y(lhs) || is_y(rhs) => {
                    if let Some(u) = unit_of(ty) {
                        let fix = |a: &Tm| if is_y(a) { u.clone() } else { self.repair_unit(a, y + d) };
                        return Some(Rc::new(Term::Eq { ty: ty.clone(), lhs: fix(lhs), rhs: fix(rhs) }));
                    }
                }
                _ => {}
            }
            let Term::Ctor { ind, ctor, params, args } = &**x else { return None };
            let decl = self.env.inductive_decl(*ind)?;
            let c = decl.ctors.get(*ctor as usize)?;
            let mut changed = false;
            let mut new_args = Vec::with_capacity(args.len());
            for (j, a) in args.iter().enumerate() {
                let is_y = matches!(&**a, Term::Var(Idx(i)) if *i == y + d);
                let unit_like = if is_y {
                    c.fields.get(j).and_then(|(_, _, fty)| {
                        let mut sub: Vec<Tm> = params.clone();
                        sub.extend(args[..j].iter().cloned());
                        let ft = crate::opt::proof::steps::subst_n(fty, &sub);
                        let Term::Ind { ind: i2, params: p2 } = &*ft else { return None };
                        let d2 = self.env.inductive_decl(*i2)?;
                        (d2.ctors.len() == 1 && d2.ctors[0].fields.is_empty()).then(|| Rc::new(Term::Ctor { ind: *i2, ctor: 0, params: p2.clone(), args: vec![] }))
                    })
                } else {
                    None
                };
                match unit_like {
                    Some(u) => {
                        new_args.push(u);
                        changed = true;
                    }
                    None => new_args.push(a.clone()),
                }
            }
            if !changed {
                return None;
            }
            // (the other arguments repaired too: this node is not visited again)
            let new_args = new_args.iter().map(|a| self.repair_unit(a, y + d)).collect();
            let params = params.iter().map(|p| self.repair_unit(p, y + d)).collect();
            Some(Rc::new(Term::Ctor { ind: *ind, ctor: *ctor, params, args: new_args }))
        })
    }

    /// Whether the structured body of `g` mentions `h`.
    fn body_calls(&self, g: GlobalId, h: GlobalId) -> bool {
        let Some(b) = self.env.global_body(g) else { return false };
        let mut found = false;
        crate::auto::util::map_term(&b, 0, &mut |x, _| {
            if !found && matches!(&**x, Term::Global(k) if *k == h) {
                found = true;
            }
            if found { Some(x.clone()) } else { None }
        });
        found
    }

    /// Moves the literal side with the facts. With `with_prem` the motives
    /// carry the fuel premise (the structural walk's goals); otherwise they
    /// are the bare equation (inside a terminal).
    fn advance(&mut self, ctx: &Ctx, g: &Goal, facts: &[Fact], with_prem: bool) -> Result<(Goal, Vec<Tm>, Vec<Fact>), String> {
        let mut g = g.clone();
        let mut wraps: Vec<Tm> = Vec::new();
        let mut newf: Vec<Fact> = Vec::new();
        let d = ctx.depth().0;
        // (outer calls first: a callee whose structured body calls another
        // pending callee is moved before it, so the inner call is not
        // transported inside the outer one's literal run)
        let mut call_facts: Vec<&Fact> = facts.iter().filter(|f| f.call.is_some()).collect();
        let gs: Vec<GlobalId> = call_facts.iter().map(|f| f.call.as_ref().unwrap().0).collect();
        let outer = |g: GlobalId| gs.iter().filter(|h| **h != g && self.body_calls(g, **h)).count();
        call_facts.sort_by_key(|f| std::cmp::Reverse(outer(f.call.as_ref().unwrap().0)));
        for _round in 0..64 {
            let mut moved = false;
            // calls of lifted functions: their lemmas
            for f in call_facts.iter() {
                let Some((cg, args)) = &f.call else { continue };
                if facts.iter().chain(newf.iter()).any(|h| h.call_done.as_ref().is_some_and(|(g2, a2)| g2 == cg && self.same_args(a2, args))) {
                    continue;
                }
                let Some(ci) = self.callees.iter().find(|c| c.s_global == *cg).cloned() else { continue };
                let ni = d - 1 - self.n_level;
                let rel_args: Vec<Tm> = args.iter().filter(|(r, _)| *r == Rel::Rel).map(|(_, a)| a.clone()).collect();
                let mut sub = rel_args.clone();
                sub.push(mk::var(ni));
                let lcall = crate::opt::proof::steps::subst_n(&ci.l_of, &sub);
                let sval = match &ci.panic {
                    Some(r) => self.opt_erase(r, &ci.erase, &ci.out_ty, &mk::apps(mk::global(*cg), args.clone())),
                    None => Rc::new(Term::Ctor { ind: self.ind("Option"), ctor: 1, params: vec![ci.out_ty.clone()], args: vec![mk::app(ci.erase.clone(), mk::apps(mk::global(*cg), args.clone()))] }),
                };
                // the lemma's fuel premise: at every fuel, or the callee's need
                // from the premise (a hypothesis: inside a terminal, or before
                // the walk); otherwise the call waits for the terminal
                let all_args: Vec<Tm> = args.iter().map(|(_, a)| a.clone()).collect();
                let prem_pf = match &ci.need {
                    None => Some(Rc::new(Term::Linarith { hyps: vec![], goal: self.le_int(self.int_lit(0), self.len_n(d)), cert: vec![] })),
                    Some(_) if with_prem && !self.prem_in_ctx => None,
                    Some(w) => {
                        let goal = self.le_int(crate::opt::proof::steps::subst_n(w, &all_args), self.len_n(d));
                        self.linarith_fuel(ctx, facts, &goal).ok()
                    }
                };
                if std::env::var("CS_TRACE_CALLS").is_ok() {
                    eprintln!("  call fact {} (need {:?}, premise {})", self.env.global_name(*cg).map(|n| n.to_string()).unwrap_or_default(), ci.need.as_ref().map(|n| self.env.print_term(&[], n)), prem_pf.is_some());
                }
                let Some(prem_pf) = prem_pf else {
                    if let Some((r, _)) = app_spine(&lcall)
                        && !self.frozen.contains(&r)
                    {
                        self.frozen.push(r);
                    }
                    continue;
                };
                let mut largs: Vec<(Rel, Tm)> = args.clone();
                largs.push((Rel::Rel, mk::var(ni)));
                largs.push((Rel::Irr, prem_pf));
                let lem = mk::apps(mk::global(ci.lemma), largs);
                let (eq_pf, pres_pf) = if ci.pres.is_some() { (Rc::new(Term::Fst(lem.clone())), Some(Rc::new(Term::Snd(lem)))) } else { (lem, None) };
                // (the other callees' runs still waiting for their lemmas)
                let pending: Vec<GlobalId> = call_facts
                    .iter()
                    .filter_map(|f2| f2.call.as_ref())
                    .filter(|(g2, a2)| !(g2 == cg && self.same_args(a2, args)) && !facts.iter().chain(newf.iter()).any(|h| h.call_done.as_ref().is_some_and(|(g3, a3)| g3 == g2 && self.same_args(a3, a2))))
                    .filter_map(|(g2, _)| self.callees.iter().find(|c| c.s_global == *g2).and_then(|c| app_spine(&c.l_of).map(|(r, _)| r)))
                    .collect();
                if let Some((g2, w)) = self.transport_call_p(ctx, &g, &lcall, &sval, &ci.out_ty, eq_pf, with_prem, &pending)? {
                    self.stats.callee_lemmas += 1;
                    wraps.push(w);
                    g = g2;
                    moved = true;
                    newf.push(Fact { call_done: Some((*cg, args.clone())), ..Fact::marker(self.tt(), self.unit_ty()) });
                    if let (Some(p), Some(pp)) = (&ci.pres, pres_pf) {
                        let r = mk::apps(mk::global(*cg), args.clone());
                        let ins = p.ins(&rel_args);
                        newf.extend(self.pres_facts(ctx, p, &ins, &r, &pp)?);
                    }
                }
            }
            // a self-call: the induction hypothesis (`Rec`, with the
            // structured reading's decrease proof), transported like a
            // callee lemma at the current fuel
            if let Some(rf) = self.rec_fn.clone() {
                for f in facts {
                    let Some((args, dp)) = &f.rec_call else { continue };
                    if facts.iter().chain(newf.iter()).any(|h| h.ih_done.as_ref().is_some_and(|a| self.same_args(a, args))) {
                        continue;
                    }
                    let ni = d - 1 - self.n_level;
                    let lcall = self.ih_lcall(ctx, args)?;
                    let s_app = mk::apps(mk::global(self.s_self.as_ref().ok_or("no S")?.0), args.clone());
                    let sval = self.some_out(mk::app(self.erase.clone(), s_app.clone()));
                    // the fuel: mult·μ(args) ≤ len n_cur, from the premise, the
                    // fuel splits and the decrease
                    let cargs: Vec<Tm> = args.iter().map(|(_, a)| a.clone()).collect();
                    let mut fs = facts.to_vec();
                    fs.push(self.decrease_rec(ctx, &cargs, dp));
                    if let Some(c) = self.measure_cong(ctx, facts)? {
                        fs.push(c);
                    }
                    let goal = self.le_int(rf.need(&cargs), self.len_n(d));
                    let fuel_pf = match self.linarith_fuel(ctx, &fs, &goal) {
                        Ok(p) => p,
                        Err(e) => {
                            if self.trace {
                                eprintln!("  IH: no fuel: {}", trunc(&e, 1500));
                            }
                            continue;
                        }
                    };
                    let dec = match self.rec_decrease(ctx, facts, &cargs, dp) {
                        Ok(p) => p,
                        Err(e) => {
                            if self.trace {
                                eprintln!("  IH: no decrease: {}", trunc(&e, 1500));
                            }
                            continue;
                        }
                    };
                    let mut rargs = cargs.clone();
                    rargs.push(mk::var(ni));
                    rargs.push(fuel_pf);
                    let ih = Rc::new(Term::Rec { args: rargs, proof: Some(dec) });
                    let (eq_pf, pres_pf) = if self.pres.is_some() { (Rc::new(Term::Fst(ih.clone())), Some(Rc::new(Term::Snd(ih)))) } else { (ih, None) };
                    let tc = self.transport_call(ctx, &g, &lcall, &sval, &self.out_ty.clone(), eq_pf, with_prem)?;
                    if tc.is_none() && self.trace {
                        eprintln!("  IH: the literal side does not reach the call");
                    }
                    if let Some((g2, w)) = tc {
                        self.stats.inductions += 1;
                        if self.trace {
                            eprintln!("  induction hypothesis applied (a self-call)");
                        }
                        wraps.push(w);
                        g = g2;
                        moved = true;
                        newf.push(Fact { ih_done: Some(args.clone()), ..Fact::marker(self.tt(), self.unit_ty()) });
                        if let (Some(p), Some(pp)) = (self.pres.clone(), pres_pf) {
                            let rel_args: Vec<Tm> = args.iter().filter(|(r, _)| *r == Rel::Rel).map(|(_, a)| a.clone()).collect();
                            let ins = p.ins(&rel_args);
                            newf.extend(self.pres_facts(ctx, &p, &ins, &s_app, &pp)?);
                        }
                    }
                }
            }
            // bridges: a wrapping operation onto the checked one
            for f in facts {
                let Some((op, a, b)) = &f.bridge else { continue };
                let (w, lname, wop) = match op {
                    PrimOp::Add(w) => (*w, "wadd", PrimOp::WAdd(*w)),
                    PrimOp::Sub(w) => (*w, "wsub", PrimOp::WSub(*w)),
                    PrimOp::Mul(w) => (*w, "wmul", PrimOp::WMul(*w)),
                    _ => continue,
                };
                let wt = mk::prim(wop, vec![a.clone(), b.clone()], vec![]);
                let wv = self.eval(ctx, &wt)?;
                // (only a wrapping operation that stays one: `(d + 1) - 1`
                // evaluates to `d`, which every occurrence of `d` would match)
                if !matches!(&*wv, Value::Neu(n) if n.spine.is_empty() && matches!(&n.head, Head::Prim { op, .. } if *op == wop)) {
                    continue;
                }
                let l_abs = self.abstract_l_typed(ctx, &g.l, &wv, &mk::int_ty(w))?;
                if std::env::var("CS_TRACE_BRIDGE").is_ok() {
                    let names: Vec<Name> = ctx.entries.iter().map(|e| e.name.clone()).collect();
                    eprintln!("  bridge {} found {}", trunc(&self.env.print_term(&names, &self.quote(ctx, &wv)), 300), count_var(&l_abs, 0));
                }
                if count_var(&l_abs, 0) == 0 {
                    continue;
                }
                let ct = mk::prim(*op, vec![a.clone(), b.clone()], vec![f.proof.clone()]);
                let bridge = self.g(&format!("bits::{lname}_exact_{}", width_name(w)))?;
                let e = mk::apps(mk::global(bridge), vec![(Rel::Rel, a.clone()), (Rel::Rel, b.clone()), (Rel::Irr, f.proof.clone())]);
                let wty = mk::int_ty(w);
                let sym = mk::apps(mk::global(self.g("eq::sym")?), vec![(Rel::Rel, wty.clone()), (Rel::Rel, wt.clone()), (Rel::Rel, ct.clone()), (Rel::Rel, e)]);
                let gm = g.with(l_abs.clone(), shift(&g.s, 1), 1);
                let ctx_y = self.push(ctx, "y", Rel::Rel, &wty, None)?;
                let motive = if with_prem { self.goal(&ctx_y, &gm) } else { self.goal_e(&gm) };
                self.check_motive(ctx, &wty, &motive, "bridge")?;
                wraps.push(Rc::new(Term::Transport { ty: wty, lhs: ct.clone(), rhs: wt, eq: sym, motive, val: mk::var(u32::MAX) }));
                g = g.with(crate::elab::tm::subst0(&l_abs, &ct), g.s.clone(), 0);
                self.stats.transports += 1;
                self.stats.reused_proofs += 1;
                moved = true;
            }
            // a stuck test decided by a fact
            let lv = self.eval(ctx, &g.l)?;
            for (block, ind, params) in self.blocker_chain(ctx, &lv) {
                if moved {
                    break;
                }
                let bt = self.quote(ctx, &block);
                for f in facts {
                    if f.is_marker() {
                        continue;
                    }
                    let fty = self.eval(ctx, &f.ty)?;
                    if let Value::Eq { lhs: fl, rhs: fr, .. } = &*fty
                        && matches!(&**fr, Value::Ctor { .. })
                        && self.conv(ctx, fl, &block)
                    {
                        let l_abs = self.abstract_l(ctx, &g.l, &block)?;
                        if count_var(&l_abs, 0) == 0 {
                            break;
                        }
                        self.stats.transports += 1;
                        if f.reused {
                            self.stats.reused_proofs += 1;
                        }
                        let params_t: Vec<Tm> = params.iter().map(|p| self.quote(ctx, p)).collect();
                        let dty = mk::ind(ind, params_t);
                        let rhs_c = self.quote(ctx, fr);
                        if std::env::var("CS_TRACE_FACT").is_ok() {
                            let names: Vec<Name> = ctx.entries.iter().map(|e| e.name.clone()).collect();
                            eprintln!("  fact decides {} = {}", trunc(&self.env.print_term(&names, &bt), 600), self.env.print_term(&names, &rhs_c));
                        }
                        // (a dependent idiom on the test, a library function's
                        // `if c as .h`: over the test and its proof)
                        if has_idiom_on(&l_abs, 0) {
                            let l_q = requalify(&shift(&l_abs, 1), 1, &shift(&bt, 2), &mk::var(0));
                            let gm = g.with(l_q.clone(), shift(&g.s, 2), 2);
                            let ctx_y = self.push(ctx, "y", Rel::Rel, &dty, None)?;
                            let qty = mk::eq(shift(&dty, 1), shift(&bt, 1), mk::var(0));
                            let ctx_yq = self.push(&ctx_y, "q", Rel::Irr, &qty, None)?;
                            let inner = if with_prem { self.goal(&ctx_yq, &gm) } else { self.goal_e(&gm) };
                            let motive = mk::pi("q", Rel::Irr, qty, inner);
                            self.check_motive(ctx, &dty, &motive, "fact (idiom)")?;
                            let sym = mk::apps(mk::global(self.g("eq::sym")?), vec![(Rel::Rel, dty.clone()), (Rel::Rel, bt.clone()), (Rel::Rel, rhs_c.clone()), (Rel::Rel, f.proof.clone())]);
                            let lam = mk::lam("q", Rel::Irr, mk::eq(dty.clone(), bt.clone(), rhs_c.clone()), mk::var(u32::MAX));
                            let tr = Rc::new(Term::Transport { ty: dty.clone(), lhs: rhs_c.clone(), rhs: bt.clone(), eq: sym, motive, val: lam });
                            wraps.push(Rc::new(Term::App { rel: Rel::Irr, fun: tr, arg: mk::refl(dty, bt.clone()) }));
                            g = g.with(inst_yq(&l_q, &rhs_c, &f.proof), g.s.clone(), 0);
                            self.stats.transports += 1;
                            moved = true;
                            break;
                        }
                        let gm = g.with(l_abs.clone(), shift(&g.s, 1), 1);
                        let ctx_y = self.push(ctx, "y", Rel::Rel, &dty, None)?;
                        let motive = if with_prem { self.goal(&ctx_y, &gm) } else { self.goal_e(&gm) };
                        let sym = mk::apps(mk::global(self.g("eq::sym")?), vec![(Rel::Rel, dty.clone()), (Rel::Rel, bt.clone()), (Rel::Rel, rhs_c.clone()), (Rel::Rel, f.proof.clone())]);
                        self.check_motive(ctx, &dty, &motive, "fact")?;
                        wraps.push(Rc::new(Term::Transport { ty: dty, lhs: rhs_c.clone(), rhs: bt.clone(), eq: sym, motive, val: mk::var(u32::MAX) }));
                        g = g.with(crate::elab::tm::subst0(&l_abs, &rhs_c), g.s.clone(), 0);
                        moved = true;
                        break;
                    }
                }
            }
            // a match on a neutral struct value (a call's or a leaf's result
            // tuple): eta, so the literal side holds its projections, as the
            // structured reading does
            if !moved
                && let Some((g2, w)) = self.literal_eta(ctx, &g, with_prem)?
            {
                g = g2;
                wraps.push(w);
                moved = true;
            }
            // the test a folded run waits for is inside its body: the run
            // unfolded by its `delta` equation (a folded recursive call does
            // not convert with its unfolding)
            if !moved
                && !self.at_header
                && let Some((g2, w)) = self.unfold_blocking_run(ctx, &g, with_prem)?
            {
                g = g2;
                wraps.push(w);
                moved = true;
            }
            if !moved {
                break;
            }
        }
        Ok((g, wraps, newf))
    }

    /// The innermost folded run whose body holds the test the literal side
    /// waits for, when that test is not in the literal term: unfolded by
    /// `delta(run; args)` (the literal side then evaluated: the block's code
    /// up to its test).
    fn unfold_blocking_run(&mut self, ctx: &Ctx, g: &Goal, with_prem: bool) -> Result<Option<(Goal, Tm)>, String> {
        let lv = self.eval(ctx, &g.l)?;
        let Some((block, _, _)) = self.blocker(ctx, &lv) else { return Ok(None) };
        let n_idx = ctx.depth().0 - 1 - self.n_level;
        let bt = self.quote(ctx, &block);
        if matches!(&*bt, Term::Var(Idx(i)) if *i == n_idx) {
            return Ok(None);
        }
        if count_var(&self.abstract_l1(ctx, &g.l, &block)?, 0) > 0 {
            return Ok(None);
        }
        let mut fuel = 0;
        let Some(rv) = self.blocking_run(ctx, &lv, &mut fuel) else { return Ok(None) };
        let rt = self.quote(ctx, &rv);
        let Some((run_g, args)) = app_spine(&rt) else { return Ok(None) };
        let l_abs = self.abstract_l1(ctx, &g.l, &rv)?;
        if count_var(&l_abs, 0) == 0 {
            return Ok(None);
        }
        let mut body = self.env.global_body(run_g).ok_or("no run body")?;
        let mut rty = self.env.global_type(run_g).ok_or("no run type")?;
        for _ in 0..args.len() {
            let Term::Lam { body: b, .. } = &*body else { return Ok(None) };
            body = b.clone();
            let Term::Pi { cod, .. } = &*rty else { return Ok(None) };
            rty = cod.clone();
        }
        let vals: Vec<Tm> = args.iter().map(|(_, a)| a.clone()).collect();
        let body_t = crate::opt::proof::steps::subst_n(&body, &vals);
        let opt_g = crate::opt::proof::steps::subst_n(&rty, &vals);
        let delta = Rc::new(Term::Delta { def: run_g, args: vals.clone() });
        let sym = mk::apps(mk::global(self.g("eq::sym")?), vec![(Rel::Rel, opt_g.clone()), (Rel::Rel, rt.clone()), (Rel::Rel, body_t.clone()), (Rel::Rel, delta)]);
        let ctx_y = self.push(ctx, "y", Rel::Rel, &opt_g, None)?;
        let gm = g.with(l_abs.clone(), shift(&g.s, 1), 1);
        let motive = if with_prem { self.goal(&ctx_y, &gm) } else { self.goal_e(&gm) };
        self.check_motive(ctx, &opt_g, &motive, "unfold")?;
        let w = Rc::new(Term::Transport { ty: opt_g, lhs: body_t.clone(), rhs: rt, eq: sym, motive, val: mk::var(u32::MAX) });
        let ov = self.eval(ctx, &self.opt_out())?;
        let l_new = self.env.quote_typed(ctx, &self.eval(ctx, &crate::elab::tm::subst0(&l_abs, &body_t))?, Some(&ov), true);
        self.stats.transports += 1;
        self.stats.unfolds += 1;
        if self.trace {
            eprintln!("  unfold {}", self.env.global_name(run_g).map(|n| n.to_string()).unwrap_or_default());
        }
        Ok(Some((g.with(l_new, g.s.clone(), 0), w)))
    }

    /// The innermost folded run on the way to the literal side's test.
    fn blocking_run(&self, ctx: &Ctx, v: &V, fuel: &mut u32) -> Option<V> {
        *fuel += 1;
        if *fuel > 400 {
            return None;
        }
        match &**v {
            Value::Ctor { args, .. } => {
                for a in args {
                    if let Arg::Rel(x) = a
                        && let Some(r) = self.blocking_run(ctx, x, fuel)
                    {
                        return Some(r);
                    }
                }
                None
            }
            Value::Neu(n) => {
                if let Some(i0) = n.spine.iter().position(|e| matches!(e, Elim::Match { .. })) {
                    return self.blocking_run(ctx, &prefix(n, i0), fuel);
                }
                if let Head::Global { def, args } = &n.head
                    && self.l_runs.contains(def)
                    && n.spine.is_empty()
                    && !self.frozen.contains(def)
                {
                    // the test is inside this run's body, or deeper (a run
                    // folded in its state)
                    let inner = self.unfold_run(ctx, *def, args)?;
                    return Some(self.blocking_run(ctx, &inner, fuel).unwrap_or_else(|| v.clone()));
                }
                if let Head::Prim { args, .. } = &n.head {
                    for a in args {
                        if let Some(r) = self.blocking_run(ctx, a, fuel) {
                            return Some(r);
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// `match F with C(x̄) => K(x̄)` on a neutral `F` of a struct type (one
    /// constructor, relevant fields): the literal side with `F` replaced by
    /// `C(proj_0 F, ..)` (equal by a one-arm match on `F`).
    fn literal_eta(&mut self, ctx: &Ctx, g: &Goal, with_prem: bool) -> Result<Option<(Goal, Tm)>, String> {
        let lv = self.eval(ctx, &g.l)?;
        let mut fuel = 0;
        let mut cands = Vec::new();
        self.struct_scruts(ctx, &lv, &mut fuel, &mut cands, 8);
        for (block, ind, params) in cands {
            if let Some(r) = self.literal_eta_on(ctx, g, with_prem, &block, ind, &params)? {
                return Ok(Some(r));
            }
        }
        Ok(None)
    }

    fn literal_eta_on(&mut self, ctx: &Ctx, g: &Goal, with_prem: bool, block: &V, ind: IndId, params: &[V]) -> Result<Option<(Goal, Tm)>, String> {
        let bt = self.quote(ctx, block);
        let decl = self.env.inductive_decl(ind).ok_or("no inductive")?;
        let c = decl.ctors[0].clone();
        let nf = c.fields.len() as u32;
        let params_t: Vec<Tm> = params.iter().map(|p| self.quote(ctx, p)).collect();
        let mut l_abs = self.abstract_l(ctx, &g.l, block)?; // (ctx, y)
        if count_var(&l_abs, 0) == 0 {
            return Ok(None);
        }
        // (the struct value may be the argument of a structured term in the
        // literal side whose proof is about it: then that abstraction is not
        // well-typed, and only the literal side's own matches on it are
        // abstracted, by position)
        {
            let dty = mk::ind(ind, params_t.clone());
            let cy = ctx.push(CtxEntry { name: name("y"), rel: Rel::Rel, ty: self.eval(ctx, &dty)?, def: None });
            let mut b = self.b();
            if self.env.infer(&cy, &l_abs, &mut b).is_err() {
                let lq = self.quote(ctx, &self.eval(ctx, &g.l)?);
                l_abs = abstract_scrutinees(self.env, &lq, &bt, ind);
                let mut b = self.b();
                if count_var(&l_abs, 0) == 0 || self.env.infer(&cy, &l_abs, &mut b).is_err() {
                    if self.trace {
                        eprintln!("  (no eta on {}: not well-typed)", trunc(&self.env.print_term(&[], &bt), 200));
                    }
                    return Ok(None);
                }
            }
        }
        self.stats.transports += 1;
        self.stats.literal_etas += 1;
        if self.trace {
            eprintln!("  eta on {}", trunc(&self.env.print_term(&[], &bt), 200));
        }
        // the projections of y, in (ctx, y)
        let params1: Vec<Tm> = params_t.iter().map(|p| shift(p, 1)).collect();
        let names: Vec<Name> = c.fields.iter().map(|f| f.0.clone()).collect();
        let mut projs: Vec<Tm> = Vec::new();
        for (i, (_, _, fty)) in c.fields.iter().enumerate() {
            let mut sub: Vec<Tm> = params1.clone();
            sub.extend(projs.iter().cloned());
            let fty_i = crate::opt::proof::steps::subst_n(fty, &sub); // (ctx, y)
            projs.push(Rc::new(Term::Match { ind, params: params1.clone(), scrut: mk::var(0), motive: shift(&fty_i, 1), arms: vec![Arm { names: names.clone(), body: mk::var(nf - 1 - i as u32) }] }));
        }
        let cy = Rc::new(Term::Ctor { ind, ctor: 0, params: params1.clone(), args: projs });
        let l_new_y = inst0_under(&l_abs, 1, &cy); // (ctx, y)
        // Eq(Opt, L[F], L[C(proj F)]) by a match on F
        let ctor_a = Rc::new(Term::Ctor { ind, ctor: 0, params: params_t.iter().map(|p| shift(p, nf as i64)).collect(), args: (0..nf).rev().map(mk::var).collect() });
        let l_a = inst0_under(&l_abs, nf, &ctor_a);
        let opt = self.opt_out();
        let motive = mk::eq(shift(&opt, 1), l_abs.clone(), l_new_y.clone());
        let eqp = Rc::new(Term::Match { ind, params: params_t.clone(), scrut: bt.clone(), motive, arms: vec![Arm { names, body: mk::refl(shift(&opt, nf as i64), l_a) }] });
        let l_new = crate::elab::tm::subst0(&l_new_y, &bt);
        let sym = mk::apps(mk::global(self.g("eq::sym")?), vec![(Rel::Rel, opt.clone()), (Rel::Rel, g.l.clone()), (Rel::Rel, l_new.clone()), (Rel::Rel, eqp)]);
        let ctx_y = self.push(ctx, "y", Rel::Rel, &opt, None)?;
        let gm = g.with(mk::var(0), shift(&g.s, 1), 1);
        let mot = if with_prem { self.goal(&ctx_y, &gm) } else { self.goal_e(&gm) };
        self.check_motive(ctx, &opt, &mot, "literal eta")?;
        let w = Rc::new(Term::Transport { ty: opt, lhs: l_new.clone(), rhs: g.l.clone(), eq: sym, motive: mot, val: mk::var(u32::MAX) });
        Ok(Some((g.with(l_new, g.s.clone(), 0), w)))
    }

    fn arm_ctx(&self, ctx: &Ctx, ind: IndId, params: &[Tm], c: &sandblaster_kernel::term::CtorDecl, names: &[Name]) -> Result<(Ctx, Tm), String> {
        let nf = c.fields.len() as u32;
        let mut actx = ctx.clone();
        let mut fvars: Vec<Tm> = Vec::new();
        for (j, (fname, frel, fty)) in c.fields.iter().enumerate() {
            let mut args: Vec<Tm> = params.iter().map(|p| shift(p, j as i64)).collect();
            args.extend(fvars.iter().cloned());
            let fty2 = crate::opt::proof::steps::subst_n(fty, &args);
            let nm = names.get(j).map(|n| n.to_string()).unwrap_or_else(|| fname.to_string());
            actx = self.push(&actx, &nm, *frel, &fty2, None)?;
            fvars = fvars.iter().map(|x| shift(x, 1)).collect();
            fvars.push(mk::var(0));
        }
        let ctor_idx = self.env.inductive_decl(ind).ok_or("no inductive")?.ctors.iter().position(|x| x.name == c.name).ok_or("ctor")? as u32;
        let ctor_tm = Rc::new(Term::Ctor { ind, ctor: ctor_idx, params: params.iter().map(|p| shift(p, nf as i64)).collect(), args: (0..nf).rev().map(mk::var).collect() });
        Ok((actx, ctor_tm))
    }

    /// A split on the literal reading's own test `c` inside a terminal.
    #[allow(clippy::too_many_arguments)]
    fn l_split(&mut self, ctx: &Ctx, g: &Goal, ind: IndId, params: &[Tm], c: &Tm, facts: &[Fact], depth: u32) -> Result<Tm, String> {
        self.split_test(ctx, g, ind, params, c, facts, depth, false, false)
    }

    /// A split on a test `c` inside a terminal: both sides abstracted over
    /// it where they hold it, each arm with its path equation. `force`: a
    /// test neither side holds (its path equation is the point: a fact the
    /// arms' repairs use). `exit`: at a `while` lemma's exit (each arm goes
    /// on to the exit, [`Self::exit_close`]).
    #[allow(clippy::too_many_arguments)]
    fn split_test(&mut self, ctx: &Ctx, g: &Goal, ind: IndId, params: &[Tm], c: &Tm, facts: &[Fact], depth: u32, force: bool, exit: bool) -> Result<Tm, String> {
        let cv = self.eval(ctx, c)?;
        let l_abs = self.abstract_l(ctx, &g.l, &cv)?;
        // (the structured value waiting for the same test, a transparent
        // callee's comparison: abstracted too, unless it is a loop's call)
        let r_abs = if self.is_loop_tail(&g.s) && g.rhs.is_none() { None } else { Some(self.abstract_rhs(ctx, &self.goal_rhs(g), &cv)?) }.filter(|r| count_var(r, 0) > 0);
        if count_var(&l_abs, 0) == 0 && r_abs.is_none() && !force {
            let lt = self.quote(ctx, &self.eval(ctx, &g.l)?);
            return Err(format!("L-split: the test is not in the literal side: test {}\n literal {}", trunc(&self.env.print_term(&[], c), 2000), trunc(&self.env.print_term(&[], &lt), 8000)));
        }
        let dty = mk::ind(ind, params.to_vec());
        let eq_ye = mk::eq(shift(&dty, 1), shift(c, 1), mk::var(0));
        // (a dependent idiom on the test: over the test and the split's equation)
        let idiom = has_idiom_on(&l_abs, 0);
        let l_ye = if idiom { requalify(&shift(&l_abs, 1), 1, &shift(c, 2), &mk::var(0)) } else { shift(&l_abs, 1) };
        let mut g_y = g.with(l_ye.clone(), shift(&g.s, 2), 2);
        if let Some(r) = &r_abs {
            g_y.rhs = Some(shift(r, 1));
        }
        let motive = mk::pi("e", Rel::Irr, eq_ye, self.goal_e(&g_y));
        let decl = self.env.inductive_decl(ind).ok_or("no inductive")?;
        let mut new_arms = Vec::new();
        for c0 in decl.ctors.iter() {
            let names: Vec<Name> = c0.fields.iter().map(|f| f.0.clone()).collect();
            let nf = c0.fields.len() as u32;
            let (actx, ctor_tm) = self.arm_ctx(ctx, ind, params, c0, &names)?;
            let eq_ty = mk::eq(shift(&dty, nf as i64), shift(c, nf as i64), ctor_tm.clone());
            let ectx = self.push(&actx, "e", Rel::Irr, &eq_ty, None)?;
            let l_arm = if idiom { inst_yq_arm(&l_ye, nf, &ctor_tm) } else { inst0_under(&l_abs, nf + 1, &shift(&ctor_tm, 1)) };
            let mut g_arm = g.with(l_arm, shift(&g.s, nf as i64 + 1), nf as i64 + 1);
            if let Some(r) = &r_abs {
                g_arm.rhs = Some(inst0_under(r, nf + 1, &shift(&ctor_tm, 1)));
            }
            let mut fs: Vec<Fact> = facts.iter().map(|f| f.shifted(nf as i64 + 1)).collect();
            fs.push(Fact::eq(mk::var(0), shift(&eq_ty, 1)));
            self.rewrite_facts_by_last(&ectx, &mut fs)?;
            let body = if exit { self.exit_close_d(&ectx, &g_arm, &fs, depth + 1)? } else { self.terminal(&ectx, &g_arm, &fs, depth + 1)? };
            new_arms.push(Arm { names, body: mk::lam("e", Rel::Irr, eq_ty, body) });
        }
        let m = Rc::new(Term::Match { ind, params: params.to_vec(), scrut: c.clone(), motive, arms: new_arms });
        Ok(Rc::new(Term::App { rel: Rel::Irr, fun: m, arg: mk::refl(dty, c.clone()) }))
    }

    /// After a split of the literal side on a test `c` (the newest fact,
    /// `e : Eq(D, c, C)`): every comparison fact of the structured reading
    /// whose value waits for `c` (through its `let`s and transparent calls,
    /// `2 * mid` with `mid = div_ceil(..)`) is rewritten by `e`, and so are
    /// the operands of its bridge. The rewriting is syntactic (the `let`s
    /// and calls unfolded, `c` abstracted, the proofs about `c` transported,
    /// iota and beta): the new facts stay well-typed, so they can enter
    /// motives.
    fn rewrite_facts_by_last(&mut self, ctx: &Ctx, fs: &mut Vec<Fact>) -> Result<(), String> {
        let k = fs.len() - 1;
        let Term::Eq { ty: dty, lhs: c, rhs: ctor } = &*fs[k].ty.clone() else { return Ok(()) };
        let e = fs[k].proof.clone();
        let cv = self.eval(ctx, c)?;
        let defs: Vec<(Tm, Tm)> = fs.iter().filter_map(|f| f.letdef.clone()).collect();
        let bool_ind = self.env.bool_ind();
        let mut more = Vec::new();
        for f in fs[..k].iter() {
            if f.is_marker() {
                continue;
            }
            let Term::Eq { ty: fty, lhs: fl, rhs: fr } = &*f.ty else { continue };
            if !matches!(&*self.eval(ctx, fty)?, Value::Ind { ind, .. } if *ind == bool_ind) || !matches!(&*self.eval(ctx, fr)?, Value::Ctor { .. }) {
                continue;
            }
            let fu = unfold_syn(self.env, fl, &defs, 3);
            let a = self.abs_syn(ctx, &fu, &cv)?;
            if std::env::var("CS_TRACE_RW").is_ok() {
                let names: Vec<Name> = ctx.entries.iter().map(|e| e.name.clone()).collect();
                eprintln!("  rw? {} defs; fact {} ; unfolded {} ; found {}", defs.len(), trunc(&self.env.print_term(&names, fl), 200), trunc(&self.env.print_term(&names, &fu), 400), count_var(&a, 0));
            }
            if count_var(&a, 0) == 0 {
                continue;
            }
            let (p2, t2) = self.rewrite_abs(ctx, &a, &f.proof, fty, fr, c, ctor, dty, &e);
            let mut bridge = None;
            if let Some((op, x, y)) = &f.bridge {
                let rw = |t: &Tm| -> Result<Tm, String> {
                    let tu = unfold_syn(self.env, t, &defs, 3);
                    let ta = self.abs_syn(ctx, &tu, &cv)?;
                    Ok(if count_var(&ta, 0) == 0 { t.clone() } else { iota_syn(&crate::elab::tm::subst0(&replace_proofs_gen(bool_ind, &ta, 0, &shift(&e, 1), &shift(c, 1), &shift(dty, 1)), ctor)) })
                };
                bridge = Some((*op, rw(x)?, rw(y)?));
            }
            more.push(Fact { bridge, reused: f.reused, ..Fact::eq(p2, mk::eq(fty.clone(), t2, fr.clone())) });
        }
        if self.trace && !more.is_empty() {
            eprintln!("  {} facts rewritten by the split", more.len());
        }
        fs.extend(more);
        Ok(())
    }

    /// The fact `p : Eq(fty, t, d)` rewritten along `e : Eq(xty, x, c)`, `a`
    /// being `t` abstracted over `x` (a term in `(ctx, y)`): the proof and the
    /// new side (syntactic: iota and beta, the proofs about `x` transported).
    #[allow(clippy::too_many_arguments)]
    fn rewrite_abs(&self, _ctx: &Ctx, a: &Tm, p: &Tm, fty: &Tm, d: &Tm, x: &Tm, c: &Tm, xty: &Tm, e: &Tm) -> (Tm, Tm) {
        let bi = self.env.bool_ind();
        if !has_proof_mentioning(a, 0) {
            let motive = mk::eq(shift(fty, 1), a.clone(), shift(d, 1));
            let pr = Rc::new(Term::Transport { ty: xty.clone(), lhs: x.clone(), rhs: c.clone(), eq: e.clone(), motive, val: p.clone() });
            return (pr, iota_syn(&crate::elab::tm::subst0(a, c)));
        }
        let a1 = replace_proofs_gen(bi, &shift(a, 1), 1, &mk::var(0), &shift(x, 2), &shift(xty, 2));
        let q_ty = mk::eq(shift(xty, 1), shift(x, 1), mk::var(0));
        let motive = mk::pi("q", Rel::Irr, q_ty, mk::eq(shift(fty, 2), a1, shift(d, 2)));
        let val = mk::lam("q", Rel::Irr, mk::eq(xty.clone(), x.clone(), x.clone()), shift(p, 1));
        let tr = Rc::new(Term::Transport { ty: xty.clone(), lhs: x.clone(), rhs: c.clone(), eq: e.clone(), motive, val });
        let a_e = replace_proofs_gen(bi, a, 0, &shift(e, 1), &shift(x, 1), &shift(xty, 1));
        (Rc::new(Term::App { rel: Rel::Irr, fun: tr, arg: e.clone() }), iota_syn(&crate::elab::tm::subst0(&a_e, c)))
    }

    /// A terminal (a value, a loop helper's call, a recursive call), with the
    /// fuel premise in the context: the bare equation `goal_e(g)`.
    fn terminal(&mut self, ctx: &Ctx, g: &Goal, facts: &[Fact], depth: u32) -> Result<Tm, String> {
        if depth > 48 {
            return Err("too many literal-reading steps at one tail".into());
        }
        // (a loop's call where the literal side is at the loop's header
        // already: an inner loop's exit jumped there)
        if depth == 0 && self.l_at_loop_header(g) {
            return self.after_fuel(ctx, g, facts, depth);
        }
        let (g1, wraps, newf) = self.advance(ctx, g, facts, false)?;
        let mut fs = facts.to_vec();
        fs.extend(newf);
        let inner = self.terminal1(ctx, &g1, &fs, depth)?;
        self.check_node(ctx, &inner, &self.goal_e(&g1), "terminal (inner)")?;
        let r = wrap(wraps, inner);
        self.check_node(ctx, &r, &self.goal_e(g), "terminal")?;
        Ok(r)
    }

    fn terminal1(&mut self, ctx: &Ctx, g: &Goal, facts: &[Fact], depth: u32) -> Result<Tm, String> {
        self.tick().map_err(|e| self.fail(ctx, g, &e))?;
        let lv = self.eval(ctx, &g.l)?;
        let rhs_t = self.goal_rhs(g);
        let rv = self.eval(ctx, &rhs_t)?;
        if self.conv(ctx, &lv, &rv) {
            self.stats.leaves += 1;
            return Ok(mk::refl(self.opt_out(), rhs_t));
        }
        let fails = matches!(&*lv, Value::Ctor { ctor: 0, .. });
        if fails {
            // the literal reading fails (a failed assertion, an overflow):
            // the path contradicts the facts (constructor clash, arithmetic)
            if let Some(pf) = self.refute(ctx, facts)? {
                self.stats.refuted += 1;
                return Ok(Rc::new(Term::Absurd { ty: self.goal_e(g), proof: pf }));
            }
            if let Some(pf) = self.refute_arith(ctx, facts)? {
                self.stats.refuted += 1;
                return Ok(Rc::new(Term::Absurd { ty: self.goal_e(g), proof: pf }));
            }
            if let Some(pf) = self.refute_eval(ctx, facts)? {
                self.stats.refuted += 1;
                return Ok(Rc::new(Term::Absurd { ty: self.goal_e(g), proof: pf }));
            }
        } else if let Some(pf) = self.refute_last(ctx, facts)? {
            // (the newest path equation against the others: each earlier one
            // was checked when it came)
            self.stats.refuted += 1;
            return Ok(Rc::new(Term::Absurd { ty: self.goal_e(g), proof: pf }));
        }
        // two values: an arithmetic contradiction of the path first (the two
        // sides chose arms of tests that agree only arithmetically, `x <
        // 2^15` against `x >> 15 == 0`), before a repair consumes a fact
        if !fails
            && self.blocker(ctx, &lv).is_none()
            && self.blocker(ctx, &rv).is_none()
            && let Some(pf) = self.refute_arith(ctx, facts)?
        {
            self.stats.refuted += 1;
            return Ok(Rc::new(Term::Absurd { ty: self.goal_e(g), proof: pf }));
        }
        // both sides values that differ in machine words the word normalizer
        // equates (`bswap` vs big-endian bytes): rewritten by `bvrefl`
        if self.blocker(ctx, &lv).is_none()
            && let Some(r) = self.bv_repair(ctx, g, &lv, &rv, facts, depth)?
        {
            return Ok(r);
        }
        if self.blocker(ctx, &lv).is_none()
            && let Some(r) = self.inj_repair(ctx, g, facts, depth)?
        {
            return Ok(r);
        }
        if self.blocker(ctx, &lv).is_none()
            && self.blocker(ctx, &rv).is_none()
            && let Some(r) = self.fact_repair(ctx, g, facts, depth)?
        {
            return Ok(r);
        }
        // both sides values that agree once a fixed-length array they share
        // is a variable (the literal side computed under the kernel's array
        // eta, its list spelled out element by element)
        if self.blocker(ctx, &lv).is_none()
            && self.blocker(ctx, &rv).is_none()
            && let Some(r) = self.array_eta_repair(ctx, g, &rv, facts, depth)?
        {
            return Ok(r);
        }
        // a `min`/`max` primitive of the structured side on symbolic words
        // (`usize::max`, which the literal side reads as core's comparison):
        // its definition axiom at the comparison the facts decide, else a
        // split on the comparison
        if self.blocker(ctx, &lv).is_none()
            && self.blocker(ctx, &rv).is_none()
            && let Some(r) = self.minmax_repair(ctx, g, &rv, facts, depth)?
        {
            return Ok(r);
        }
        // the literal side a value, the structured one waiting for a test (a
        // transparent callee's comparison the literal side already made):
        // split on it, both sides abstracted, the facts closing the other arm
        let (block, ind, params) = match self.blocker(ctx, &lv) {
            Some(b) => b,
            None => {
                // (the literal side a value that differs from the structured
                // side: a contradictory path the newest equation alone did
                // not show, before anything else)
                if !fails && let Some(pf) = self.refute_eval(ctx, facts)? {
                    self.stats.refuted += 1;
                    return Ok(Rc::new(Term::Absurd { ty: self.goal_e(g), proof: pf }));
                }
                // (arithmetic: the two sides chose arms of tests that agree
                // only arithmetically, `x < 2^15` against `x >> 15 == 0`)
                if self.blocker(ctx, &rv).is_none()
                    && let Some(pf) = self.refute_arith(ctx, facts)?
                {
                    self.stats.refuted += 1;
                    return Ok(Rc::new(Term::Absurd { ty: self.goal_e(g), proof: pf }));
                }
                match self.blocker(ctx, &rv) {
                Some(b) if !self.is_loop_tail(&g.s) || g.rhs.is_some() => b,
                _ => {
                    let names: Vec<Name> = ctx.entries.iter().map(|e| e.name.clone()).collect();
                    let lt = self.env.print_term(&names, &self.quote(ctx, &lv));
                    let rt = self.env.print_term(&names, &self.quote(ctx, &rv));
                    let fs: Vec<String> = facts.iter().filter(|f| !f.is_marker()).filter_map(|f| self.eval(ctx, &f.ty).ok()).filter(|v| matches!(&**v, Value::Eq { rhs, .. } if matches!(&**rhs, Value::Ctor { .. }))).map(|v| trunc(&self.env.print_term(&names, &self.quote(ctx, &v)), if std::env::var("CS_FULL").is_ok() { 100_000 } else { 300 })).collect();
                    let lim = if std::env::var("CS_FULL").is_ok() { 1_000_000 } else { 1500 };
                    // (`CS_DIFF`: the first subterms where the two sides differ)
                    let diff = if std::env::var("CS_DIFF").is_ok() {
                        let a = self.env.quote_typed(ctx, &lv, None, false);
                        let b = self.env.quote_typed(ctx, &rv, None, false);
                        let mut out = Vec::new();
                        first_diff(self.env, &a, &b, &mut out);
                        out.iter().map(|(x, y)| format!("\n  differs: {}\n      vs: {}", trunc(&self.env.print_term(&names, x), 2000), trunc(&self.env.print_term(&names, y), 2000))).collect::<String>()
                    } else {
                        String::new()
                    };
                    return Err(self.fail(ctx, g, &format!("tail mismatch: literal {} vs structured {}{diff}\n  path equations:\n    {}", trunc(&lt, lim), trunc(&rt, lim), fs.join("\n    "))));
                }
                }
            }
        };
        let bt = self.quote(ctx, &block);
        let n_idx = ctx.depth().0 - 1 - self.n_level;
        if matches!(&*bt, Term::Var(Idx(i)) if *i == n_idx) {
            return self.fuel_split(ctx, g, facts, depth, false);
        }
        // (refutation before splitting: a contradictory path is closed
        // without duplicating the literal side — a constructor clash,
        // arithmetic, a fact rewritten by the others to another constructor)
        if let Some(pf) = self.refute(ctx, facts)? {
            self.stats.refuted += 1;
            return Ok(Rc::new(Term::Absurd { ty: self.goal_e(g), proof: pf }));
        }
        if let Some(pf) = self.refute_arith(ctx, facts)? {
            self.stats.refuted += 1;
            return Ok(Rc::new(Term::Absurd { ty: self.goal_e(g), proof: pf }));
        }
        if !fails && let Some(pf) = self.refute_eval(ctx, facts)? {
            self.stats.refuted += 1;
            return Ok(Rc::new(Term::Absurd { ty: self.goal_e(g), proof: pf }));
        }
        let params_t: Vec<Tm> = params.iter().map(|p| self.quote(ctx, p)).collect();
        self.stats.l_splits += 1;
        if self.trace {
            eprintln!("  L-split on {}", trunc(&self.env.print_term(&[], &bt), 300));
            if std::env::var("CS_TRACE_LSPLIT").is_ok() {
                let names: Vec<Name> = ctx.entries.iter().map(|e| e.name.clone()).collect();
                eprintln!("    test    {}\n    literal {}\n    rhs     {}", self.env.print_term(&names, &bt), self.env.print_term(&names, &self.quote(ctx, &lv)), self.env.print_term(&names, &self.quote(ctx, &rv)));
            }
        }
        self.l_split(ctx, g, ind, &params_t, &bt, facts, depth)
    }

    /// A literal value that differs from the structured one only in
    /// machine-word subterms: each pair equated by `bvrefl` (the kernel's
    /// word normalizer) and the literal side rewritten to the structured
    /// side's subterm.
    fn bv_repair(&mut self, ctx: &Ctx, g: &Goal, lv: &V, rv: &V, facts: &[Fact], depth: u32) -> Result<Option<Tm>, String> {
        let lt = self.env.quote_typed(ctx, lv, None, false);
        let rt = self.env.quote_typed(ctx, rv, None, false);
        let mut pairs: Vec<(Tm, Tm)> = Vec::new();
        if !self.diff_words(ctx, &lt, &rt, 0, &mut pairs) || pairs.is_empty() {
            return Ok(None);
        }
        let (a, b) = pairs[0].clone();
        let mut bu = self.b();
        let Ok(aty) = self.env.infer(ctx, &a, &mut bu) else { return Ok(None) };
        let Value::IntTy(w) = &*aty else { return Ok(None) };
        let ty = mk::int_ty(*w);
        let av = self.eval(ctx, &a)?;
        let l_abs = self.abstract_l(ctx, &g.l, &av)?;
        if count_var(&l_abs, 0) == 0 {
            return Ok(None);
        }
        // Eq(ty, b, a) by the word normalizer (checked first: unequal words
        // are a mismatch, reported, not a proof the kernel would reject)
        // (else by `linarith` from the path: words equal only on this path,
        // `(16 − lz) / 7` against the `1` S's `max` gave where it is 1)
        let bv = Rc::new(Term::BvRefl { ty: ty.clone(), lhs: b.clone(), rhs: a.clone() });
        let eq = {
            let mut bu = self.b();
            if self.env.infer(ctx, &bv, &mut bu).is_ok() {
                bv
            } else {
                match self.linarith_fuel(ctx, facts, &mk::eq(ty.clone(), b.clone(), a.clone())) {
                    Ok(p) => p,
                    Err(_) => return Ok(None),
                }
            }
        };
        let motive = self.goal_e(&g.with(l_abs.clone(), shift(&g.s, 1), 1));
        let g2 = g.with(crate::elab::tm::subst0(&l_abs, &b), g.s.clone(), 0);
        self.stats.transports += 1;
        self.stats.bv_repairs += 1;
        let inner = self.terminal(ctx, &g2, facts, depth + 1)?;
        Ok(Some(Rc::new(Term::Transport { ty, lhs: b, rhs: a, eq, motive, val: inner })))
    }

    /// The structured side's fixed-length array `a` spelled out as the
    /// literal side computed it under the kernel's array eta (§5.9 of its
    /// design: a fresh array variable is its elements): `fst a` rewritten to
    /// `[index(fst a, 0), .., index(fst a, N − 1)]` along `(λ (y : Array T N).
    /// refl(fst y)) a`, checked under the fresh (eta-expanded) variable.
    fn array_eta_repair(&mut self, ctx: &Ctx, g: &Goal, rv: &V, facts: &[Fact], depth: u32) -> Result<Option<Tm>, String> {
        let ov = self.eval(ctx, &self.opt_out())?;
        let rt = self.env.quote_typed(ctx, rv, Some(&ov), false);
        let mut cands: Vec<(Tm, Tm, u32)> = Vec::new();
        let mut budget = 400usize;
        let env = self.env;
        crate::auto::util::map_term(&rt, 0, &mut |x, d| {
            if d > 0 || budget == 0 || cands.len() >= 4 {
                return Some(x.clone());
            }
            if !matches!(&**x, Term::Match { .. } | Term::App { .. } | Term::Var(_) | Term::Fst(_) | Term::Snd(_) | Term::Pair { .. }) {
                return None;
            }
            budget -= 1;
            let Ok(tv) = env.infer(ctx, x, &mut Budget { steps: 200_000 }) else { return None };
            let ty = env.quote_typed(ctx, &tv, None, false);
            if let Some((elem, n)) = array_ty(env, &ty)
                && !cands.iter().any(|c| env.alpha_eq_relevant(&c.0, x, &|p, q| p == q))
            {
                cands.push((x.clone(), elem, n));
            }
            None
        });
        if std::env::var("CS_TRACE_ERASED").is_ok() {
            // where the literal side's quote loses a pair's type
            let ovv = ov.clone();
            let lq = self.env.quote_typed(ctx, &self.eval(ctx, &g.l)?, Some(&ovv), false);
            let mut shown = 0;
            crate::auto::util::map_term(&lq, 0, &mut |x, _| {
                let is_ep = |t: &Tm| matches!(&**t, Term::Pair { ty, .. } if matches!(&**ty, Term::Erased));
                let kids: Vec<Tm> = match &**x {
                    Term::App { fun, arg, .. } => vec![fun.clone(), arg.clone()],
                    Term::Ctor { args, .. } => args.clone(),
                    Term::Match { scrut, .. } => vec![scrut.clone()],
                    Term::Fst(a) | Term::Snd(a) => vec![a.clone()],
                    Term::Prim { args, .. } => args.clone(),
                    Term::Let { val, .. } => vec![val.clone()],
                    _ => vec![],
                };
                if shown < 3 && kids.iter().any(is_ep) {
                    shown += 1;
                    let head = match &**x { Term::App { .. } => "app", Term::Ctor { .. } => "ctor", Term::Match { .. } => "match", Term::Fst(_) => "fst", Term::Snd(_) => "snd", Term::Prim { .. } => "prim", Term::Let { .. } => "let", _ => "?" };
                    eprintln!("  ERASED pair under a {head}: {}", trunc(&self.env.print_term(&[], x), 400));
                }
                None
            });
        }
        if std::env::var("CS_TRACE_ETA").is_ok() {
            eprintln!("  array eta: {} candidate(s): {}", cands.len(), cands.iter().map(|c| trunc(&self.env.print_term(&[], &c.0), 150)).collect::<Vec<_>>().join(" | "));
        }
        let list = self.ind("List");
        for (cand, elem, n) in cands {
            let lty = mk::ind(list, vec![elem.clone()]);
            let fst_c = Rc::new(Term::Fst(cand.clone()));
            let lv_c = self.eval(ctx, &fst_c)?;
            let Ok(ltyv) = self.eval(ctx, &lty) else { continue };
            let r_abs = self.abstract_rhs_ty(ctx, &self.goal_rhs(g), &lv_c, ltyv)?;
            if count_var(&r_abs, 0) == 0 {
                if std::env::var("CS_TRACE_ETA").is_ok() {
                    eprintln!("  array eta: not in the structured side");
                }
                continue;
            }
            // Π (y : Array T N). Eq(List T, fst y, [index(fst y, k) ..]) by refl
            let Ok(tv) = self.env.infer(ctx, &cand, &mut self.b()) else { continue };
            let aty = self.quote(ctx, &tv);
            let eta = self.eta_list(&shift(&elem, 1), n, &mk::var(0));
            let lty1 = shift(&lty, 1);
            let fy = Rc::new(Term::Fst(mk::var(0)));
            let lam = mk::lam("y", Rel::Rel, aty.clone(), mk::refl(lty1.clone(), fy.clone()));
            let pi = mk::pi("y", Rel::Rel, aty, mk::eq(lty1, fy, eta.clone()));
            let Ok(piv) = self.eval(ctx, &pi) else { continue };
            if let Err(e) = self.env.check(ctx, &lam, &piv, &mut self.b()) {
                if std::env::var("CS_TRACE_ETA").is_ok() {
                    eprintln!("  array eta: the equation does not check: {}", trunc(&e.to_string(), 600));
                }
                continue;
            }
            let e_app = mk::app(lam, cand.clone());
            let eta_c = crate::elab::tm::subst0(&eta, &cand);
            let sym = mk::apps(mk::global(self.g("eq::sym")?), vec![(Rel::Rel, lty.clone()), (Rel::Rel, fst_c.clone()), (Rel::Rel, eta_c.clone()), (Rel::Rel, e_app)]);
            let mut gm = g.with(shift(&g.l, 1), shift(&g.s, 1), 1);
            gm.rhs = Some(r_abs.clone());
            let motive = self.goal_e(&gm);
            let mut g2 = g.clone();
            g2.rhs = Some(crate::elab::tm::subst0(&r_abs, &eta_c));
            match self.terminal(ctx, &g2, facts, depth + 1) {
                Ok(inner) => {
                    self.stats.transports += 1;
                    return Ok(Some(Rc::new(Term::Transport { ty: lty, lhs: eta_c, rhs: fst_c, eq: sym, motive, val: inner })));
                }
                Err(e) => {
                    if std::env::var("CS_TRACE_ETA").is_ok() {
                        eprintln!("  array eta: after the rewrite: {}", trunc(&e, 600));
                    }
                }
            }
        }
        Ok(None)
    }

    /// `[index(T, fst y, 0), .., index(T, fst y, N − 1)]` with the kernel's
    /// certificate-free bound proofs (`y : Array T N` a term).
    fn eta_list(&self, elem: &Tm, n: u32, y: &Tm) -> Tm {
        let list = self.ind("List");
        let bi = self.env.bool_ind();
        let int = mk::int_ty(Width::Int);
        let len_g = self.g("seq::len").unwrap();
        let index_g = self.g("seq::index").unwrap();
        let fy = Rc::new(Term::Fst(y.clone()));
        let len_fy = mk::apps(mk::global(len_g), vec![(Rel::Rel, elem.clone()), (Rel::Rel, fy.clone())]);
        let nl = mk::lit(Width::Int, n as i64);
        // sym(snd y) : Eq(Int, N, len T (fst y))
        let sym = Rc::new(Term::Transport { ty: int.clone(), lhs: len_fy.clone(), rhs: nl.clone(), eq: Rc::new(Term::Snd(y.clone())), motive: mk::eq(int.clone(), mk::var(0), shift(&len_fy, 1)), val: mk::refl(int.clone(), len_fy.clone()) });
        let refl_true = mk::refl(mk::ind(bi, vec![]), mk::bool_lit(bi, true));
        let mut out: Tm = Rc::new(Term::Ctor { ind: list, ctor: 0, params: vec![elem.clone()], args: vec![] });
        for k in (0..n).rev() {
            let kl = mk::lit(Width::Int, k as i64);
            let p1 = Rc::new(Term::Transport { ty: int.clone(), lhs: nl.clone(), rhs: len_fy.clone(), eq: sym.clone(), motive: mk::eq_bool(bi, mk::prim(PrimOp::Lt(Width::Int), vec![shift(&kl, 1), mk::var(0)], vec![]), true), val: refl_true.clone() });
            let e = mk::apps(mk::global(index_g), vec![(Rel::Rel, elem.clone()), (Rel::Rel, fy.clone()), (Rel::Rel, kl), (Rel::Irr, refl_true.clone()), (Rel::Irr, p1)]);
            out = Rc::new(Term::Ctor { ind: list, ctor: 1, params: vec![elem.clone()], args: vec![e, out] });
        }
        out
    }

    /// A `min`/`max` of symbolic words in the structured value: rewritten
    /// to the argument the comparison selects, by the primitive's
    /// definition axiom (`max_def_le`, ..) at the comparison's truth value
    /// as `linarith` proves it from the facts; when the facts decide
    /// nothing, the comparison is split (its path equation then decides).
    fn minmax_repair(&mut self, ctx: &Ctx, g: &Goal, rv: &V, facts: &[Fact], depth: u32) -> Result<Option<Tm>, String> {
        use sandblaster_kernel::axioms::{self, Schema};
        let rt = self.env.quote_typed(ctx, rv, None, false);
        let Some((op, a, b)) = find_minmax(&rt) else { return Ok(None) };
        let (w, is_max) = match op {
            PrimOp::Max(w) => (w, true),
            PrimOp::Min(w) => (w, false),
            _ => return Ok(None),
        };
        let bi = self.env.bool_ind();
        let cond = mk::prim(PrimOp::Le(w), vec![a.clone(), b.clone()], vec![]);
        let mm = mk::prim(op, vec![a.clone(), b.clone()], vec![]);
        let mv = self.eval(ctx, &mm)?;
        let r_abs = self.abstract_rhs(ctx, &self.goal_rhs(g), &mv)?;
        if count_var(&r_abs, 0) == 0 {
            return Ok(None);
        }
        let mut last: Option<String> = None;
        for truth in [true, false] {
            let Ok(p) = self.linarith_fuel(ctx, facts, &mk::eq_bool(bi, cond.clone(), truth)) else { continue };
            let schema = match (is_max, truth) {
                (true, true) => Schema::MaxDefLe,
                (true, false) => Schema::MaxDefGt,
                (false, true) => Schema::MinDefLe,
                (false, false) => Schema::MinDefGt,
            };
            let res = if is_max == truth { b.clone() } else { a.clone() };
            let ax = axioms::axiom_id(schema, w).ok_or("no min/max axiom at this width")?;
            let axt = Rc::new(Term::Axiom { ax, args: vec![a.clone(), b.clone(), p] });
            let wty = mk::int_ty(w);
            let eq = mk::apps(mk::global(self.g("eq::sym")?), vec![(Rel::Rel, wty.clone()), (Rel::Rel, mm.clone()), (Rel::Rel, res.clone()), (Rel::Rel, axt)]);
            let mut gm = g.with(shift(&g.l, 1), shift(&g.s, 1), 1);
            gm.rhs = Some(r_abs.clone());
            let motive = self.goal_e(&gm);
            let mut g2 = g.clone();
            g2.rhs = Some(crate::elab::tm::subst0(&r_abs, &res));
            // (both truth values may be provable on a path where the
            // arguments are equal: the one whose argument the literal side
            // computed is kept)
            match self.terminal(ctx, &g2, facts, depth + 1) {
                Ok(inner) => {
                    self.stats.transports += 1;
                    return Ok(Some(Rc::new(Term::Transport { ty: wty, lhs: res, rhs: mm, eq, motive, val: inner })));
                }
                Err(e) => last = Some(e),
            }
        }
        if let Some(e) = last {
            return Err(e);
        }
        // undecided: split on the comparison (once: its path equation decides it)
        if facts.iter().any(|f| matches!(&*f.ty, Term::Eq { lhs, .. } if self.env.alpha_eq_relevant(lhs, &cond, &|x, y| x == y))) {
            return Ok(None);
        }
        self.stats.l_splits += 1;
        self.split_test(ctx, g, bi, &[], &cond, facts, depth, true, false).map(Some)
    }

    /// Two values that agree once a machine word is replaced by the literal a
    /// path fact says it equals (`eq(t, k) = true`: `un_zigzag`'s `-(v & 1)`
    /// against `v & 1` where `v & 1 = 0`): `t` abstracted on both sides and
    /// the goal transported from `k` (the equation by `linarith`); the fact
    /// is used once.
    fn fact_repair(&mut self, ctx: &Ctx, g: &Goal, facts: &[Fact], depth: u32) -> Result<Option<Tm>, String> {
        for (i, f) in facts.iter().enumerate() {
            if f.is_marker() {
                continue;
            }
            let fty = self.eval(ctx, &f.ty)?;
            let Value::Eq { ty, lhs, rhs } = &*fty else { continue };
            if !matches!(&**ty, Value::Ind { ind, .. } if *ind == self.env.bool_ind()) || !matches!(&**rhs, Value::Ctor { ctor: 1, .. }) {
                continue;
            }
            let Term::Prim { op: PrimOp::Eq(w), args, .. } = &*self.quote(ctx, lhs) else { continue };
            if *w == Width::Int || args.len() != 2 {
                continue;
            }
            let (t, k) = match (&*args[0], &*args[1]) {
                (_, Term::Lit { .. }) if !matches!(&*args[0], Term::Lit { .. }) => (args[0].clone(), args[1].clone()),
                (Term::Lit { .. }, _) if !matches!(&*args[1], Term::Lit { .. }) => (args[1].clone(), args[0].clone()),
                _ => continue,
            };
            let tv = self.eval(ctx, &t)?;
            let l_abs = self.abstract_l(ctx, &g.l, &tv)?;
            let Ok(r_abs) = self.abstract_rhs(ctx, &self.goal_rhs(g), &tv) else { continue };
            if count_var(&l_abs, 0) == 0 && count_var(&r_abs, 0) == 0 {
                continue;
            }
            let wty = mk::int_ty(*w);
            let eq_ty = mk::eq(wty.clone(), k.clone(), t.clone());
            let Ok(pf) = self.linarith_fuel(ctx, std::slice::from_ref(f), &eq_ty) else { continue };
            let mut gm = g.with(l_abs.clone(), shift(&g.s, 1), 1);
            gm.rhs = Some(r_abs.clone());
            let motive = self.goal_e(&gm);
            if self.check_motive(ctx, &wty, &motive, "fact repair").is_err() {
                continue;
            }
            let mut g2 = g.with(crate::elab::tm::subst0(&l_abs, &k), g.s.clone(), 0);
            g2.rhs = Some(crate::elab::tm::subst0(&r_abs, &k));
            let rest: Vec<Fact> = facts.iter().enumerate().filter(|(j, _)| *j != i).map(|(_, x)| x.clone()).collect();
            self.stats.transports += 1;
            let inner = self.terminal(ctx, &g2, &rest, depth + 1)?;
            return Ok(Some(Rc::new(Term::Transport { ty: wty, lhs: k, rhs: t, eq: pf, motive, val: inner })));
        }
        Ok(None)
    }

    /// The first differing subterms of two terms of the same shape, when they
    /// are machine words at depth 0 (`false` if the shapes differ elsewhere).
    #[allow(clippy::only_used_in_recursion)]
    fn diff_words(&self, ctx: &Ctx, a: &Tm, b: &Tm, d: u32, out: &mut Vec<(Tm, Tm)>) -> bool {
        if self.env.alpha_eq_relevant(a, b, &|x, y| x == y) {
            return true;
        }
        match (&**a, &**b) {
            (Term::Ctor { ind: i1, ctor: c1, args: a1, .. }, Term::Ctor { ind: i2, ctor: c2, args: a2, .. }) if i1 == i2 && c1 == c2 && a1.len() == a2.len() => a1.iter().zip(a2).all(|(x, y)| self.diff_words(ctx, x, y, d, out)),
            (Term::App { fun: f1, arg: x1, rel: r1 }, Term::App { fun: f2, arg: x2, rel: r2 }) if r1 == r2 => {
                self.diff_words(ctx, f1, f2, d, out) && (*r1 == Rel::Irr || self.diff_words(ctx, x1, x2, d, out))
            }
            _ => {
                let word = |t: &Tm| matches!(&**t, Term::Prim { .. } | Term::App { .. } | Term::Var(_) | Term::Lit { .. });
                if d == 0 && word(a) && word(b) && !(matches!(&**a, Term::Lit { .. }) && matches!(&**b, Term::Lit { .. })) {
                    out.push((a.clone(), b.clone()));
                    true
                } else {
                    false
                }
            }
        }
    }

    /// The literal side waits for fuel: split `n`. `Nil` contradicts the
    /// premise; `Cons(u, n1)`: a loop helper's call (its lemma), a recursive
    /// call (the induction hypothesis), or the walk goes on with `n1`.
    /// `exit`: at a `while` lemma's exit that jumps to an outer loop's
    /// header (the walk goes on to the exit under `Cons(u, n1)`).
    fn fuel_split(&mut self, ctx: &Ctx, g: &Goal, facts: &[Fact], depth: u32, exit: bool) -> Result<Tm, String> {
        self.stats.fuel_splits += 1;
        let list = self.ind("List");
        let unit = self.unit_ty();
        let lu = self.list_unit();
        let n_idx = ctx.depth().0 - 1 - self.n_level;
        let nvar = mk::var(n_idx);
        let nv = self.eval(ctx, &nvar)?;
        let l_abs = self.abstract_l(ctx, &g.l, &nv)?;
        let eq_ye = mk::eq(shift(&lu, 1), shift(&nvar, 1), mk::var(0));
        let g_y = g.with(shift(&l_abs, 1), shift(&g.s, 2), 2);
        let motive = mk::pi("e", Rel::Irr, eq_ye, self.goal_e(&g_y));
        let nil_t = Rc::new(Term::Ctor { ind: list, ctor: 0, params: vec![unit.clone()], args: vec![] });
        let nil_eq = mk::eq(lu.clone(), nvar.clone(), nil_t.clone());
        let ectx0 = self.push(ctx, "e", Rel::Irr, &nil_eq, None)?;
        let mut fs0: Vec<Fact> = facts.iter().map(|f| f.shifted(1)).collect();
        fs0.push(Fact::eq(mk::var(0), shift(&nil_eq, 1)));
        let pf0 = self.fuel_contradiction(&ectx0, &fs0, g)?;
        let nil_body = Rc::new(Term::Absurd { ty: self.goal_e(&g.with(inst0_under(&l_abs, 1, &shift(&nil_t, 1)), shift(&g.s, 1), 1)), proof: pf0 });
        let cons_decl = self.env.inductive_decl(list).unwrap().ctors[1].clone();
        let (actx, ctor_tm) = self.arm_ctx(ctx, list, std::slice::from_ref(&unit), &cons_decl, &[name("u"), name("n1")])?;
        let cons_eq = mk::eq(shift(&lu, 2), shift(&nvar, 2), ctor_tm.clone());
        let ectx1 = self.push(&actx, "e", Rel::Irr, &cons_eq, None)?;
        let mut fs1: Vec<Fact> = facts.iter().map(|f| f.shifted(3)).collect();
        fs1.push(Fact::eq(mk::var(0), shift(&cons_eq, 1)));
        let g1 = g.with(inst0_under(&l_abs, 3, &shift(&ctor_tm, 1)), shift(&g.s, 3), 3);
        let saved = self.n_level;
        self.n_level = ctx.depth().0 + 1;
        let cons_body = if exit { self.exit_close_d(&ectx1, &g1, &fs1, depth + 1) } else { self.after_fuel(&ectx1, &g1, &fs1, depth) };
        self.n_level = saved;
        let cons_body = cons_body?;
        let arms = vec![Arm { names: vec![], body: mk::lam("e", Rel::Irr, nil_eq, nil_body) }, Arm { names: vec![name("u"), name("n1")], body: mk::lam("e", Rel::Irr, cons_eq, cons_body) }];
        let m = Rc::new(Term::Match { ind: list, params: vec![unit.clone()], scrut: nvar.clone(), motive, arms });
        Ok(Rc::new(Term::App { rel: Rel::Irr, fun: m, arg: mk::refl(lu, nvar) }))
    }

    fn after_fuel(&mut self, ctx: &Ctx, g: &Goal, facts: &[Fact], depth: u32) -> Result<Tm, String> {
        let s = g.s.clone();
        if let Term::Let { val, .. } = &*s
            && let Some((wh, args)) = self.while_of(val)
        {
            let at_h = self.step_to(ctx, &g.l, wh.header_ctor)?;
            self.at_header = true;
            let adv = self.advance(ctx, &g.with(at_h, g.s.clone(), 0), facts, false);
            self.at_header = false;
            let (g1, wraps, _) = adv?;
            let inner = self.while_call(ctx, &g1, facts, &args, &wh)?;
            return Ok(wrap(wraps, inner));
        }
        if let Some((args, proof)) = self.loop_rec(&s)
            && let Some(rc) = self.rec.clone()
        {
            // (stepped to the header, the state there decided by the facts;
            // the run kept folded at the header)
            let at_h = self.step_to(ctx, &g.l, rc.helper.header_ctor)?;
            self.at_header = true;
            let adv = self.advance(ctx, &g.with(at_h, g.s.clone(), 0), facts, false);
            self.at_header = false;
            let (g1, wraps, _) = adv?;
            let inner = self.induction(ctx, &g1, facts, args, proof.as_ref(), &rc)?;
            return Ok(wrap(wraps, inner));
        }
        if let Some((h, args)) = app_spine(&s)
            && let Some(hi) = self.helpers.iter().find(|x| x.s_global == h).cloned()
        {
            let at_h = self.step_to(ctx, &g.l, hi.header_ctor)?;
            self.at_header = true;
            let adv = self.advance(ctx, &g.with(at_h, g.s.clone(), 0), facts, false);
            self.at_header = false;
            let (g1, wraps, _) = adv?;
            let inner = self.helper_call(ctx, &g1, facts, &args, &hi)?;
            return Ok(wrap(wraps, inner));
        }
        self.terminal(ctx, g, facts, depth + 1)
    }

    /// Whether the structured side is a loop's call (a recursive call, a
    /// loop helper's or a `while` loop's) and the literal side the function's
    /// run at that loop's header.
    fn l_at_loop_header(&self, g: &Goal) -> bool {
        let want = if self.loop_rec(&g.s).is_some() {
            self.rec.as_ref().map(|r| r.helper.header_ctor)
        } else if let Term::Let { val, .. } = &*g.s
            && let Some((wh, _)) = self.while_of(val)
        {
            Some(wh.header_ctor)
        } else if let Some((h, _)) = app_spine(&g.s)
            && let Some(hi) = self.helpers.iter().find(|x| x.s_global == h)
        {
            Some(hi.header_ctor)
        } else {
            None
        };
        let Some(want) = want else { return false };
        let mut cur = g.l.clone();
        loop {
            match &*cur {
                Term::Let { val, body, .. } => cur = crate::elab::tm::subst0(body, val),
                Term::App { fun, arg, .. } if matches!(&**fun, Term::Lam { .. }) => {
                    let Term::Lam { body, .. } = &**fun else { unreachable!() };
                    cur = crate::elab::tm::subst0(body, arg);
                }
                _ => break,
            }
        }
        let Some((head, args)) = app_spine(&cur) else { return false };
        Some(head) == self.s_self_run && matches!(args.get(1).map(|a| &*a.1), Some(Term::Ctor { ctor, .. }) if *ctor == want)
    }

    /// One block of the literal side with its run kept folded: the folded
    /// call it ends in.
    fn step_once(&self, ctx: &Ctx, l: &Tm) -> Result<Tm, String> {
        let (head, args) = app_spine(l).ok_or("step: not an application")?;
        let body = self.env.global_body(head).ok_or("step: no body")?;
        let term = mk::apps(body, args);
        let opq = self.opaque.clone();
        let isop = move |g: GlobalId| opq.contains(&g);
        let mut b = self.b();
        let v = self.env.eval_opaque(&self.env.ctx_venv(ctx), ctx.depth(), &term, &isop, &mut b).map_err(|e| format!("step: {e:?}"))?;
        let Value::Neu(n) = &*v else { return Err("step: no folded call".into()) };
        let Head::Global { def, .. } = &n.head else { return Err("step: not a folded call".into()) };
        if *def != head || !n.spine.is_empty() {
            return Err(format!("step: the block does not end in a jump: from {} to {}", trunc(&self.env.print_term(&[], l), 1500), trunc(&self.env.print_term(&[], &self.quote(ctx, &v)), 3000)));
        }
        Ok(self.quote(ctx, &v))
    }

    /// Steps the literal side until it is at the block `ctor` (a loop header).
    fn step_to(&self, ctx: &Ctx, l: &Tm, ctor: u32) -> Result<Tm, String> {
        let mut cur = l.clone();
        for _ in 0..64 {
            // (a quoted literal side may share subterms by `let`s: inlined)
            loop {
                match &*cur {
                    Term::Let { val, body, .. } => cur = crate::elab::tm::subst0(body, val),
                    Term::App { fun, arg, .. } if matches!(&**fun, Term::Lam { .. }) => {
                        let Term::Lam { body, .. } = &**fun else { unreachable!() };
                        cur = crate::elab::tm::subst0(body, arg);
                    }
                    _ => break,
                }
            }
            let (_, args) = app_spine(&cur).ok_or_else(|| format!("step_to: the literal side is not a run: {}", trunc(&self.env.print_term(&[], &cur), 3000)))?;
            if let Some((_, b)) = args.get(1)
                && let Term::Ctor { ctor: c, .. } = &**b
                && *c == ctor
            {
                return Ok(cur);
            }
            cur = self.step_once(ctx, &cur)?;
        }
        Err("step_to: the header is not reached".into())
    }

    /// The state slots of `run(n, b, Some(st(v̄)))`.
    fn slots_of(&self, ctx: &Ctx, l: &Tm) -> Result<Vec<Tm>, String> {
        let (_, args) = app_spine(l).ok_or("slots_of")?;
        let os = args.get(2).ok_or("slots_of: no state")?.1.clone();
        let osv = self.eval(ctx, &os)?;
        let Value::Ctor { args: oa, .. } = &*osv else {
            return Err(format!("slots_of: the state is not `Some(..)`: {}", trunc(&self.env.print_term(&ctx.entries.iter().map(|e| e.name.clone()).collect::<Vec<_>>(), &self.quote(ctx, &osv)), 6000)));
        };
        let Some(Arg::Rel(stv)) = oa.first() else { return Err("slots_of".into()) };
        let Value::Ctor { ind, args: sa, .. } = &**stv else { return Err("slots_of: the state is not a constructor".into()) };
        // (typed by the state's field types: an array's pair gets its type)
        let fields: Vec<Tm> = self.env.inductive_decl(*ind).map(|d| d.ctors[0].fields.iter().map(|f| f.2.clone()).collect()).unwrap_or_default();
        let mut out = Vec::new();
        for (i, a) in sa.iter().enumerate() {
            out.push(match a {
                Arg::Rel(x) => match fields.get(i).and_then(|t| self.eval(&Ctx::default(), t).ok()) {
                    Some(tv) => self.env.quote_typed(ctx, x, Some(&tv), true),
                    None => self.quote(ctx, x),
                },
                Arg::Irr(_) => self.tt(),
            });
        }
        Ok(out)
    }

    /// A loop helper's call: step to the header, apply its lemma.
    fn helper_call(&mut self, ctx: &Ctx, g: &Goal, facts: &[Fact], args: &[(Rel, Tm)], hi: &Helper) -> Result<Tm, String> {
        self.stats.helper_lemmas += 1;
        let at_h = self.step_to(ctx, &g.l, hi.header_ctor)?;
        let slots = self.slots_of(ctx, &at_h)?;
        let n1 = mk::var(ctx.depth().0 - 1 - self.n_level);
        let mut largs: Vec<(Rel, Tm)> = args.iter().map(|(r, a)| (*r, self.commit(a))).collect();
        for j in &hi.junk {
            largs.push((Rel::Rel, slots[*j].clone()));
        }
        largs.push((Rel::Rel, n1));
        let all_args: Vec<Tm> = args.iter().map(|(_, a)| self.commit(a)).collect();
        let mu = hi.need_int(&all_args);
        let goal = self.le_int(mu, self.len_n(ctx.depth().0));
        let pf = self.linarith_fuel(ctx, facts, &goal)?;
        largs.push((Rel::Irr, pf));
        Ok(mk::apps(mk::global(hi.lemma), largs))
    }

    /// A `while` loop's call (`let loop = h(ā); rest`), the literal side at
    /// the loop header: the loop's lemma at `ā`, the junk slots, the fuel,
    /// `C` the goal's right side, and the continuation: the rest of the
    /// function walked from the exit block (`Π m (.hm) k̄`, the rest with
    /// `loop` bound to the call), then the premise.
    fn while_call(&mut self, ctx: &Ctx, g: &Goal, facts: &[Fact], args: &[(Rel, Tm)], wh: &WhileHelper) -> Result<Tm, String> {
        let at_h = self.step_to(ctx, &g.l, wh.header_ctor)?;
        let slots = self.slots_of(ctx, &at_h)?;
        let d = ctx.depth().0;
        self.stats.helper_lemmas += 1;
        let cargs: Vec<(Rel, Tm)> = args.iter().map(|(r, a)| (*r, self.commit(a))).collect();
        let mut largs: Vec<(Rel, Tm)> = cargs.clone();
        for j in &wh.junk {
            largs.push((Rel::Rel, slots[*j].clone()));
        }
        let n_cur = mk::var(d - 1 - self.n_level);
        largs.push((Rel::Rel, n_cur));
        // (a loop with a fuel function: the reserve, the fuel the rest needs)
        let reserve = match &wh.fuel {
            Some(_) => Some(self.rest_need(ctx, g)?),
            None => None,
        };
        if let Some(r) = &reserve {
            largs.push((Rel::Rel, r.clone()));
        }
        let c = self.goal_rhs(g);
        largs.push((Rel::Rel, c.clone()));
        // the continuation's type, from the lemma's (with a fuel function:
        // instantiated as it is, its literal side at the exit block even when
        // that is an outer loop's header, whose code evaluation would run)
        let pty = match &wh.fuel {
            Some(_) => {
                let mut ty = self.env.global_type(wh.lemma).ok_or("the `while` lemma's type")?;
                for (_, a) in largs.iter() {
                    let Term::Pi { cod, .. } = &*ty else { return Err("the `while` lemma's telescope".into()) };
                    ty = crate::elab::tm::subst0(cod, a);
                }
                ty
            }
            None => {
                let partial = mk::apps(mk::global(wh.lemma), largs.clone());
                let pty = self.env.infer(ctx, &partial, &mut self.b()).map_err(|e| format!("the `while` lemma's application: {e}"))?;
                self.quote(ctx, &pty)
            }
        };
        let Term::Pi { dom: hc_ty, .. } = &*pty else { return Err("the `while` lemma's continuation".into()) };
        let hc = self.continuation(ctx, g, facts, hc_ty, wh)?;
        largs.push((Rel::Rel, hc));
        let all_args: Vec<Tm> = cargs.iter().map(|(_, a)| a.clone()).collect();
        let mut need = wh.need_int(&all_args);
        if let Some(r) = &reserve {
            let hr = self.linarith_fuel(ctx, facts, &self.le_int(self.int_lit(0), r.clone())).map_err(|e| self.fail(ctx, g, &format!("the `while` loop's reserve: {e}")))?;
            largs.push((Rel::Irr, hr));
            need = mk::prim(PrimOp::IAdd, vec![need, r.clone()], vec![]);
        }
        let goal = self.le_int(need, self.len_n(d));
        let pf = self.linarith_fuel(ctx, facts, &goal).map_err(|e| self.fail(ctx, g, &format!("the `while` loop's fuel: {e}")))?;
        largs.push((Rel::Irr, pf));
        Ok(mk::apps(mk::global(wh.lemma), largs))
    }

    /// The fuel the rest of a `while` loop's call `let x = h(ā); rest`
    /// needs after the loop (the reserve of a loop with a fuel function):
    /// `let x = h(ā); need(rest)`, as the continuation's premise states it.
    fn rest_need(&self, ctx: &Ctx, g: &Goal) -> Result<Tm, String> {
        let Term::Let { name: n, rel, ty, val, body } = &*g.s else { return Err("a `while` call that is not a `let`".into()) };
        let (cval, cty) = (self.commit(val), self.commit(ty));
        let ctx2 = self.push(ctx, n, *rel, &cty, Some(&cval))?;
        let need = self.need_acc(&ctx2, body, g.acc.as_ref().map(|a| shift(a, 1)).as_ref());
        Ok(Rc::new(Term::Let { name: n.clone(), rel: *rel, ty: cty, val: cval, body: need }))
    }

    /// The continuation of a `while` loop's call `let loop = h(ā); rest`:
    /// `λ m (.hm) k̄ c̄ (.ez : h(ā) = tuple(c̄)).` the rest of the function
    /// walked from the exit block (its literal side as the lemma states
    /// it), with `loop` the components `c̄` (fresh variables: both sides
    /// read the loop's arrays through the kernel's array eta alike). The
    /// goal moves from `loop = h(ā)` to `loop = tuple(c̄)` along `ez`; the
    /// rest's fact about the call (`h_loop`, proven at `ā`) is a hypothesis
    /// of that motive, its proof given after the transport.
    fn continuation(&mut self, ctx: &Ctx, g: &Goal, facts: &[Fact], hc_ty: &Tm, wh: &WhileHelper) -> Result<Tm, String> {
        let Term::Let { name: ln, rel: lr, ty: lty, val, body: rest } = &*g.s else { return Err("a `while` call that is not a `let`".into()) };
        let mut binders: Vec<(Name, Rel, Tm)> = Vec::new();
        let mut cur = hc_ty.clone();
        let mut c2 = ctx.clone();
        while let Term::Pi { name, rel, dom, cod } = &*cur {
            binders.push((name.clone(), *rel, dom.clone()));
            c2 = self.push(&c2, name, *rel, dom, None)?;
            cur = cod.clone();
        }
        let Term::Eq { lhs: l_x, .. } = &*cur else { return Err("the `while` lemma's continuation is not an equation".into()) };
        let nb = binders.len() as u32;
        let d = ctx.depth().0;
        let dc = c2.depth().0;
        // binders: m, hm, k̄, c̄, ez
        let Term::Eq { ty: r_ty, rhs: tup, .. } = &*binders[nb as usize - 1].2 else { return Err("the continuation's equation".into()) };
        let r_ty = shift(r_ty, 1);
        let tup = shift(tup, 1);
        let ez = mk::var(0);
        let mut fs: Vec<Fact> = facts.iter().map(|f| f.shifted(nb as i64)).collect();
        fs.push(Fact::eq(mk::var(nb - 2), shift(&binders[1].2, (nb - 1) as i64)));
        // the rest with the call `h(ā)` as `loop`, and its loop fact
        let cval = shift(&self.commit(val), nb as i64);
        let cty = shift(&self.commit(lty), nb as i64);
        let (_, cargs) = app_spine(&cval).ok_or("the `while` call")?;
        // (the rest as it is: a recursive call in it, an outer loop's, keeps
        // its decrease proof for the induction)
        let rest_c = shift_from(rest, nb as i64, 1);
        let env = self.env;
        let sg = wh.s_global;
        let cval_v = self.eval(&c2, &cval)?;
        let rest_l = crate::auto::util::map_term(&rest_c, 0, &mut |x, dd| {
            let (h, xs) = app_spine(x)?;
            if h != sg || xs.len() != cargs.len() {
                return None;
            }
            // (the same call: its arguments as written, or their values: the
            // elaborator's annotations spell the call's `let`s out)
            let same = xs.iter().zip(&cargs).all(|((r1, x1), (r2, x2))| r1 == r2 && (*r1 == Rel::Irr || env.alpha_eq_relevant(x1, &shift(x2, dd as i64 + 1), &|p, q| p == q)));
            if same {
                return Some(mk::var(dd));
            }
            if (0..=dd).any(|k| count_var(x, k) > 0) {
                return None;
            }
            let x_down = shift(x, -(dd as i64 + 1));
            let mut b = Budget { steps: 50_000_000 };
            let xv = env.eval(&env.ctx_venv(&c2), c2.depth(), &x_down, &mut b).ok()?;
            let mut b = Budget { steps: 50_000_000 };
            env.conv(c2.depth(), &xv, &cval_v, &mut b).unwrap_or(false).then(|| mk::var(dd))
        });
        // (the loop fact: the first irrelevant `let` of the rest's chain whose
        // type is about the loop, its proof independent of the chain)
        let mut hl: Option<(usize, Tm, Tm)> = None;
        {
            let mut cur = rest_l.clone();
            let mut b = 0usize;
            while let Term::Let { rel, ty, val: v, body, .. } = &*cur.clone() {
                if *rel == Rel::Irr && count_var(ty, b as u32) > 0 {
                    let n = 1 + b as u32;
                    let free_ok = |t: &Tm| {
                        let mut ok = true;
                        crate::auto::util::map_term(t, 0, &mut |x, dd| {
                            if let Term::Var(Idx(i)) = &**x
                                && *i >= dd
                                && *i < dd + n
                            {
                                ok = false;
                            }
                            None
                        });
                        ok
                    };
                    // its type over (ctx, binders, loop), its proof over (ctx, binders)
                    let mut ty_l = ty.clone();
                    for _ in 0..b {
                        ty_l = shift(&ty_l, -1);
                    }
                    if free_ok(v) && (0..b as u32).all(|k| count_var(ty, k) == 0) {
                        hl = Some((b, ty_l, shift(v, -(n as i64))));
                    }
                    break;
                }
                b += 1;
                cur = body.clone();
            }
        }
        let saved = (self.n_level, self.exit.clone());
        self.n_level = d;
        self.path.push(format!("after the `while` loop `{}`", self.env.global_name(wh.s_global).map(|n| n.to_string()).unwrap_or_default()));
        // the motive over z : R (and the loop fact's proof)
        let set_hl = |r: &Tm, b: usize, v: Tm| -> Tm {
            fn go(t: &Tm, b: usize, v: &Tm, k: u32) -> Tm {
                let Term::Let { name, rel, ty, val, body } = &**t else { return t.clone() };
                if b == 0 {
                    return Rc::new(Term::Let { name: name.clone(), rel: *rel, ty: ty.clone(), val: shift(v, k as i64), body: body.clone() });
                }
                Rc::new(Term::Let { name: name.clone(), rel: *rel, ty: ty.clone(), val: val.clone(), body: go(body, b - 1, v, k + 1) })
            }
            go(r, b, &v, 1)
        };
        let result = (|| -> Result<Tm, String> {
            let ctx_z = self.push(&c2, "z", Rel::Rel, &r_ty, None)?;
            let (motive, walked) = match &hl {
                Some((b, ty_l, _)) => {
                    // T[z] at (ctx, binders, z)
                    let t_z = ty_l.clone();
                    let ctx_zh = self.push(&ctx_z, "hp", Rel::Irr, &t_z, None)?;
                    let body_z = set_hl(&shift_from(&rest_l, 2, 1), *b, mk::var(0));
                    let s_z = Rc::new(Term::Let { name: ln.clone(), rel: *lr, ty: shift(&cty, 2), val: mk::var(1), body: body_z });
                    let g_z = Goal { l: shift(l_x, 2), s: s_z, ins: g.ins.iter().map(|t| shift(t, nb as i64 + 2)).collect(), rhs: None, acc: g.acc.as_ref().map(|t| shift(t, nb as i64 + 2)) };
                    let motive = mk::pi("hp", Rel::Irr, t_z.clone(), self.goal(&ctx_zh, &g_z));
                    // the walk at z := tuple(c̄), hp a hypothesis
                    let t_t = crate::elab::tm::subst0(&t_z, &tup);
                    let ctx_th = self.push(&c2, "hp", Rel::Irr, &t_t, None)?;
                    let body_t = set_hl(&shift_from(&rest_l, 1, 1), *b, mk::var(0));
                    let s_t = Rc::new(Term::Let { name: ln.clone(), rel: *lr, ty: shift(&cty, 1), val: shift(&tup, 1), body: body_t });
                    let g_t = Goal { l: shift(l_x, 1), s: s_t, ins: g.ins.iter().map(|t| shift(t, nb as i64 + 1)).collect(), rhs: None, acc: g.acc.as_ref().map(|t| shift(t, nb as i64 + 1)) };
                    let mut fs_t: Vec<Fact> = fs.iter().map(|f| f.shifted(1)).collect();
                    let mut sf = Vec::new();
                    let hp_ty_ev = self.quote(&ctx_th, &self.eval(&ctx_th, &shift(&t_t, 1))?);
                    sigma_facts_w(mk::var(0), &hp_ty_ev, &mut sf);
                    fs_t.extend(sf);
                    let w = self.walk(&ctx_th, &g_t, &fs_t)?;
                    (motive, mk::lam("hp", Rel::Irr, t_t, w))
                }
                None => {
                    let s_z = Rc::new(Term::Let { name: ln.clone(), rel: *lr, ty: shift(&cty, 1), val: mk::var(0), body: shift_from(&rest_l, 1, 1) });
                    let g_z = Goal { l: shift(l_x, 1), s: s_z, ins: g.ins.iter().map(|t| shift(t, nb as i64 + 1)).collect(), rhs: None, acc: g.acc.as_ref().map(|t| shift(t, nb as i64 + 1)) };
                    let motive = self.goal(&ctx_z, &g_z);
                    let s_t = Rc::new(Term::Let { name: ln.clone(), rel: *lr, ty: cty.clone(), val: tup.clone(), body: rest_l.clone() });
                    let g_t = Goal { l: l_x.clone(), s: s_t, ins: g.ins.iter().map(|t| shift(t, nb as i64)).collect(), rhs: None, acc: g.acc.as_ref().map(|t| shift(t, nb as i64)) };
                    let w = self.walk(&c2, &g_t, &fs)?;
                    (motive, w)
                }
            };
            // along ez⁻¹ : tuple(c̄) = h(ā)
            let sym = mk::apps(mk::global(self.g("eq::sym")?), vec![(Rel::Rel, r_ty.clone()), (Rel::Rel, cval.clone()), (Rel::Rel, tup.clone()), (Rel::Rel, ez.clone())]);
            let tr = Rc::new(Term::Transport { ty: r_ty.clone(), lhs: tup.clone(), rhs: cval.clone(), eq: sym, motive, val: walked });
            let tr = match &hl {
                Some((_, _, v0)) => Rc::new(Term::App { rel: Rel::Irr, fun: tr, arg: v0.clone() }),
                None => tr,
            };
            // its fuel premise (the motive's, at the call), from `hm` and the
            // call's premise
            let s_z = Rc::new(Term::Let { name: ln.clone(), rel: *lr, ty: shift(&cty, 1), val: mk::var(0), body: shift_from(&rest_l, 1, 1) });
            let need_z = self.need_acc(&ctx_z, &s_z, g.acc.as_ref().map(|t| shift(t, nb as i64 + 1)).as_ref());
            let need = crate::elab::tm::subst0(&need_z, &cval);
            let goal = self.le_int(need, self.len_n(dc));
            let pf = self.linarith_fuel(&c2, &fs, &goal).map_err(|e| format!("the fuel after the `while` loop: {e}"))?;
            Ok(Rc::new(Term::App { rel: Rel::Irr, fun: tr, arg: pf }))
        })();
        self.path.pop();
        (self.n_level, self.exit) = saved;
        let mut out = result?;
        for (n, r, t) in binders.into_iter().rev() {
            out = mk::lam(&n, r, t, out);
        }
        Ok(out)
    }

    /// At a `while` lemma's exit (`S` the helper's result `tuple(ā)`): the
    /// literal side stepped to the exit block (runs folded), handed to `hC`
    /// at the current fuel, its slots the loop assigns from the state, the
    /// components `ā` and `eqS : h p̄ = tuple(ā)`.
    fn exit_close(&mut self, ctx: &Ctx, g: &Goal, facts: &[Fact]) -> Result<Tm, String> {
        self.exit_close_d(ctx, g, facts, 0)
    }

    /// [`Self::exit_close`] after `depth` splits of the literal side's tests
    /// on the way to the exit (a condition of several tests, `a | b`, whose
    /// outcome the structured side's path already chose: the arm against the
    /// path is refuted).
    fn exit_close_d(&mut self, ctx: &Ctx, g: &Goal, facts: &[Fact], depth: u32) -> Result<Tm, String> {
        let x = self.exit.clone().ok_or("not a `while` lemma")?;
        if depth > 0 {
            let pf = match self.refute_last(ctx, facts)? {
                Some(pf) => Some(pf),
                None => self.refute_eval(ctx, facts)?,
            };
            if let Some(pf) = pf {
                self.stats.refuted += 1;
                return Ok(Rc::new(Term::Absurd { ty: self.goal_e(g), proof: pf }));
            }
        }
        self.at_header = true;
        let adv = self.advance(ctx, g, facts, false);
        self.at_header = false;
        let (g1, wraps, newf) = adv?;
        let mut fs = facts.to_vec();
        fs.extend(newf);
        // the literal side with every run folded, stepped to the exit
        let mut opq = self.l_runs.clone();
        opq.extend(self.opaque.iter().copied());
        let isop = move |gl: GlobalId| opq.contains(&gl);
        let mut b = self.b();
        let lv = self.env.eval_opaque(&self.env.ctx_venv(ctx), ctx.depth(), &g1.l, &isop, &mut b).map_err(|e| format!("eval: {e:?}"))?;
        let lx = match self.step_to(ctx, &self.quote(ctx, &lv), x.x_ctor) {
            Ok(lx) => lx,
            Err(e) => {
                // (the literal side waits for a test before the exit: split on it)
                if depth < 8
                    && let Some((block, ind, params)) = self.blocker(ctx, &self.eval(ctx, &g1.l)?)
                {
                    let bt = self.quote(ctx, &block);
                    let n_idx = ctx.depth().0 - 1 - self.n_level;
                    if !matches!(&*bt, Term::Var(Idx(i)) if *i == n_idx) {
                        let ps: Vec<Tm> = params.iter().map(|p| self.quote(ctx, p)).collect();
                        let inner = self.split_test(ctx, &g1, ind, &ps, &bt, &fs, depth, true, true)?;
                        return Ok(wrap(wraps, inner));
                    }
                    // (the exit jumps to an outer loop's header: one unit of fuel)
                    if x.r_level.is_some() {
                        let inner = self.fuel_split(ctx, &g1, &fs, depth, true)?;
                        return Ok(wrap(wraps, inner));
                    }
                }
                return Err(self.fail(ctx, &g1, &format!("the `while` loop's exit: {e}")));
            }
        };
        let slots = self.slots_of(ctx, &lx)?;
        let d = ctx.depth().0;
        let h = self.rec.as_ref().map(|r| r.helper.clone()).ok_or("no helper")?;
        let params = h.params_at(d);
        let n_cur = mk::var(d - 1 - self.n_level);
        // hm : len n − μ(p̄) ≤ len n (with a fuel function: R ≤ len n)
        let len_n = self.len_n(d);
        let hm_ty = match x.r_level {
            Some(rl) => self.le_int(mk::var(d - 1 - rl), len_n),
            None => self.le_int(mk::prim(PrimOp::ISub, vec![len_n.clone(), h.mu_int(&params)], vec![]), len_n),
        };
        let hm = self.linarith_fuel(ctx, &fs, &hm_ty).map_err(|e| self.fail(ctx, &g1, &format!("the `while` loop's exit: the continuation's fuel: {e}")))?;
        let mut hc_args: Vec<(Rel, Tm)> = vec![(Rel::Rel, n_cur), (Rel::Irr, hm)];
        for (i, w) in x.w.iter().enumerate() {
            if w.is_none() {
                hc_args.push((Rel::Rel, slots[self.exit_slot_index(&x, i)].clone()));
            }
        }
        // the components of S's result
        let s_val = self.commit(&g1.s);
        let comps: Vec<Tm> = match (&x.tuple, &*s_val) {
            (None, _) => vec![s_val.clone()],
            (Some((ind, _)), Term::Ctor { ind: i2, args, .. }) if ind == i2 => args.clone(),
            _ => return Err(self.fail(ctx, &g1, "the `while` loop's exit value is not its tuple")),
        };
        for c in comps.iter() {
            hc_args.push((Rel::Rel, c.clone()));
        }
        hc_args.push((Rel::Irr, mk::var(d - 1 - x.eqs_level.ok_or("no eqS")?)));
        self.stats.leaves += 1;
        let hc = mk::apps(mk::var(d - 1 - x.hc_level), hc_args);
        if x.r_level.is_none() {
            return Ok(wrap(wraps, hc));
        }
        // (the continuation's state and the literal side's agree as states,
        // not always once the run is unfolded — a slot the walk has split by
        // eta: moved along `refl` of the states)
        let (run_h, largs) = app_spine(&lx).ok_or("the exit's literal side")?;
        let st_goal = largs.get(2).ok_or("the exit's state")?.1.clone();
        let mut st_hc = x.sx.clone();
        for c in comps {
            st_hc = mk::app(st_hc, c);
        }
        for (i, w) in x.w.iter().enumerate() {
            st_hc = mk::app(st_hc, match w {
                Some(t) => shift(t, (d - x.e0) as i64),
                None => slots[self.exit_slot_index(&x, i)].clone(),
            });
        }
        let st_ty = self.quote(ctx, &self.env.infer(ctx, &st_goal, &mut self.b()).map_err(|e| format!("the exit's state: {e}"))?);
        let rhs1 = shift(&self.goal_rhs(&g1), 1);
        let motive = mk::eq(shift(&self.opt_out(), 1), mk::apps(mk::global(run_h), vec![(Rel::Rel, shift(&largs[0].1, 1)), (Rel::Rel, shift(&largs[1].1, 1)), (Rel::Rel, mk::var(0))]), rhs1);
        let tr = Rc::new(Term::Transport { ty: st_ty.clone(), lhs: st_hc, rhs: st_goal.clone(), eq: mk::refl(st_ty, st_goal), motive, val: hc });
        Ok(wrap(wraps, tr))
    }

    /// The slot index of the `i`-th entry of [`ExitMode::w`].
    fn exit_slot_index(&self, x: &ExitMode, i: usize) -> usize {
        x.w_slots[i]
    }

    /// The continuation of the induction hypothesis at a `while` lemma's
    /// recursive call: `λ m (.hm' : len n1 − μ(ā) ≤ len m) k̄ c̄ (.ez' : h ā =
    /// tuple(c̄)).` the lemma's own continuation at `m` (its premise by
    /// `linarith` from `hm'`, the fuel split and the decrease) with `eqS ·
    /// ez' : h p̄ = tuple(c̄)`.
    fn exit_continuation(&self, ctx: &Ctx, facts: &[Fact], x: &ExitMode, cargs: &[Tm], dproof: &Tm, hi: &Helper) -> Result<Tm, String> {
        let d = ctx.depth().0;
        let lu = self.list_unit();
        let seq_len = self.g("seq::len")?;
        let len_of = |t: Tm| mk::apps(mk::global(seq_len), vec![(Rel::Rel, self.unit_ty()), (Rel::Rel, t)]);
        let n1 = mk::var(d - 1 - self.n_level);
        // hm' over (ctx, m)
        let cargs1: Vec<Tm> = cargs.iter().map(|a| shift(a, 1)).collect();
        // (with a fuel function: the same reserve, `hm' : R ≤ len m`)
        let hm_ty = match x.r_level {
            Some(rl) => self.le_int(mk::var(d - rl), len_of(mk::var(0))),
            None => self.le_int(mk::prim(PrimOp::ISub, vec![len_of(shift(&n1, 1)), hi.mu_int(&cargs1)], vec![]), len_of(mk::var(0))),
        };
        let mut c = self.push(ctx, "m", Rel::Rel, &lu, None)?;
        c = self.push(&c, "hm", Rel::Irr, &hm_ty, None)?;
        let nk = x.k_tys.len() as u32;
        for (i, t) in x.k_tys.iter().enumerate() {
            c = self.push(&c, &format!("k{i}"), Rel::Rel, t, None)?;
        }
        let ncomp = x.comps.len() as u32;
        for (i, t) in x.comps.iter().enumerate() {
            c = self.push(&c, &format!("c{i}"), Rel::Rel, t, None)?;
        }
        // ez' : Eq(R, h ā, tuple(c̄)) at depth d + 2 + nk + ncomp
        let comp_vars: Vec<Tm> = (0..ncomp).map(|i| mk::var(ncomp - 1 - i)).collect();
        let tup = match &x.tuple {
            Some((ind, params)) => Rc::new(Term::Ctor { ind: *ind, ctor: 0, params: params.clone(), args: comp_vars.clone() }),
            None => comp_vars[0].clone(),
        };
        let up = (2 + nk + ncomp) as i64;
        let cargs_c: Vec<Tm> = cargs.iter().map(|a| shift(a, up)).collect();
        let h_new = mk::apps(mk::global(hi.s_global), hi.rels.iter().copied().zip(cargs_c.clone()));
        let ez_ty = mk::eq(x.r_ty.clone(), h_new.clone(), tup.clone());
        let c = self.push(&c, "ez", Rel::Irr, &ez_ty, None)?;
        let dd = c.depth().0;
        let up1 = up + 1;
        // hm'' : len n − μ(p̄) ≤ len m
        let mut fs: Vec<Fact> = facts.iter().map(|f| f.shifted(up1)).collect();
        fs.push(Fact::eq(mk::var(nk + ncomp + 1), shift(&hm_ty, (nk + ncomp + 2) as i64)));
        let cargs_d: Vec<Tm> = cargs.iter().map(|a| shift(a, up1)).collect();
        fs.push(self.decrease_fact(hi, &cargs_d, &shift(dproof, up1), &c));
        let params = hi.params_at(dd);
        let m = mk::var(dd - 1 - d);
        let hm2 = if x.r_level.is_some() {
            mk::var(dd - 1 - (d + 1))
        } else {
            let n0 = mk::var(dd - 1 - (x.hc_level - 2));
            let goal = self.le_int(mk::prim(PrimOp::ISub, vec![len_of(n0), hi.mu_int(&params)], vec![]), len_of(m.clone()));
            self.linarith_fuel(&c, &fs, &goal).map_err(|e| format!("the continuation's fuel at a recursive call: {e}"))?
        };
        let mut hc_args: Vec<(Rel, Tm)> = vec![(Rel::Rel, m), (Rel::Irr, hm2)];
        for i in 0..nk {
            hc_args.push((Rel::Rel, mk::var(nk + ncomp - i)));
        }
        for i in 0..ncomp {
            hc_args.push((Rel::Rel, mk::var(ncomp - i)));
        }
        // eqS · ez'
        let h_app = mk::apps(mk::global(hi.s_global), hi.rels.iter().copied().zip(params.clone()));
        let eqs = mk::var(dd - 1 - x.eqs_level.ok_or("no eqS")?);
        let trans = mk::apps(mk::global(self.g("eq::trans")?), vec![(Rel::Rel, x.r_ty.clone()), (Rel::Rel, h_app), (Rel::Rel, shift(&h_new, 1)), (Rel::Rel, shift(&tup, 1)), (Rel::Rel, eqs), (Rel::Rel, mk::var(0))]);
        hc_args.push((Rel::Irr, trans));
        let mut out = mk::apps(mk::var(dd - 1 - x.hc_level), hc_args);
        out = mk::lam("ez", Rel::Irr, ez_ty, out);
        for (i, t) in x.comps.iter().enumerate().rev() {
            out = mk::lam(&format!("c{i}"), Rel::Rel, t.clone(), out);
        }
        for (i, t) in x.k_tys.iter().enumerate().rev() {
            out = mk::lam(&format!("k{i}"), Rel::Rel, t.clone(), out);
        }
        out = mk::lam("hm", Rel::Irr, hm_ty, out);
        out = mk::lam("m", Rel::Rel, lu, out);
        Ok(out)
    }

    /// A recursive call of the helper being proven: the induction hypothesis
    /// (with the structured reading's own decrease proof).
    fn induction(&mut self, ctx: &Ctx, g: &Goal, facts: &[Fact], args: &[Tm], proof: Option<&Tm>, rc: &RecCtx) -> Result<Tm, String> {
        self.stats.inductions += 1;
        let hi = &rc.helper;
        let at_h = self.step_to(ctx, &g.l, hi.header_ctor)?;
        let slots = self.slots_of(ctx, &at_h)?;
        let n1 = mk::var(ctx.depth().0 - 1 - self.n_level);
        let dproof = proof.ok_or("a recursive call without its decrease proof")?.clone();
        let cargs: Vec<Tm> = args.iter().map(|a| self.commit(a)).collect();
        if self.trace {
            let names: Vec<Name> = ctx.entries.iter().map(|e| e.name.clone()).collect();
            for (i, sl) in slots.iter().enumerate() {
                if !hi.junk.contains(&i) {
                    let v = self.quote(ctx, &self.eval(ctx, sl)?);
                    eprintln!("    header slot {i}: {}", trunc(&self.env.print_term(&names, &v), 1500));
                }
            }
            for (i, a) in cargs.iter().enumerate() {
                let v = self.quote(ctx, &self.eval(ctx, a)?);
                eprintln!("    S arg {i}: {}", trunc(&self.env.print_term(&names, &v), 1500));
            }
        }
        let d = ctx.depth().0;
        let mut rargs: Vec<Tm> = cargs.clone();
        for j in &hi.junk {
            rargs.push(slots[*j].clone());
        }
        rargs.push(n1);
        // a `while` lemma: the same `C` (and reserve), and the continuation
        // moved along `eqS`
        let mut need = hi.need_int(&cargs);
        if let Some(x) = self.exit.clone() {
            if let Some(rl) = x.r_level {
                rargs.push(mk::var(d - 1 - rl));
                need = mk::prim(PrimOp::IAdd, vec![need, mk::var(d - 1 - rl)], vec![]);
            }
            rargs.push(mk::var(d - 1 - x.c_level));
            rargs.push(self.exit_continuation(ctx, facts, &x, &cargs, &dproof, hi)?);
            if let Some(hl) = x.hr_level {
                rargs.push(mk::var(d - 1 - hl));
            }
        }
        let goal = self.le_int(need, self.len_n(ctx.depth().0));
        // the decrease proof: μ(args) < μ(params) (its second component for
        // an `Int` measure)
        let mut fs = facts.to_vec();
        fs.push(self.decrease_fact(hi, &cargs, &dproof, ctx));
        let pf = match self.linarith_fuel(ctx, &fs, &goal) {
            Ok(p) => p,
            Err(e) => {
                if std::env::var("CS_TRACE_ARITH").is_ok() {
                    let names: Vec<Name> = ctx.entries.iter().map(|e| e.name.clone()).collect();
                    eprintln!("  induction arithmetic failed: goal {}", self.env.print_term(&names, &goal));
                    for f in fs.iter().filter(|f| !f.is_marker()) {
                        eprintln!("    fact {}", trunc(&self.env.print_term(&names, &self.quote(ctx, &self.eval(ctx, &f.ty)?)), 40000));
                    }
                }
                return Err(e);
            }
        };
        rargs.push(pf);
        Ok(Rc::new(Term::Rec { args: rargs, proof: Some(dproof) }))
    }

    /// The structured reading's decrease proof at a recursive call as a
    /// fact: `μ(args) < μ(params)` (`Int`: the second component; a machine
    /// width: the proof itself, `lt_w`).
    fn decrease_fact(&self, hi: &Helper, cargs: &[Tm], dproof: &Tm, ctx: &Ctx) -> Fact {
        let params: Vec<Tm> = hi.params_at(ctx.depth().0);
        if hi.width == Width::Int {
            let lt_ty = mk::eq_bool(self.env.bool_ind(), mk::prim(PrimOp::Lt(Width::Int), vec![hi.mu_int(cargs), hi.mu_int(&params)], vec![]), true);
            Fact::eq(Rc::new(Term::Snd(dproof.clone())), lt_ty)
        } else {
            let a = crate::opt::proof::steps::subst_n(&hi.measure, cargs);
            let b = crate::opt::proof::steps::subst_n(&hi.measure, &params);
            let lt_ty = mk::eq_bool(self.env.bool_ind(), mk::prim(PrimOp::Lt(hi.width), vec![a, b], vec![]), true);
            Fact::eq(dproof.clone(), lt_ty)
        }
    }

    /// The structured reading's decrease proof at a self-call as a fact:
    /// `μ(args) < μ(params)` (function lemma mode).
    ///
    /// The proof is about the parameters as the walk has split them (eta),
    /// so the fact has the proof's own type; [`Self::measure_cong`] relates
    /// that measure to the lemma's.
    fn decrease_rec(&self, ctx: &Ctx, _cargs: &[Tm], dproof: &Tm) -> Fact {
        let rf = self.rec_fn.as_ref().expect("function lemma mode");
        let pf = if rf.width == Width::Int { Rc::new(Term::Snd(dproof.clone())) } else { dproof.clone() };
        let mut b = self.b();
        let ty = self.env.infer(ctx, &pf, &mut b).map(|v| self.quote(ctx, &v)).unwrap_or_else(|_| mk::ind(self.env.empty_ind(), vec![]));
        Fact::eq(pf, ty)
    }

    /// `Eq(W, μ(x̄'), μ(x̄))`: the lemma's measure at its parameters `x̄`
    /// rewritten by the path equations (the eta splits) to the form the
    /// structured reading's decrease proofs are about.
    fn measure_cong(&self, ctx: &Ctx, facts: &[Fact]) -> Result<Option<Fact>, String> {
        let rf = self.rec_fn.as_ref().ok_or("no recursion")?;
        let d = ctx.depth().0;
        let params: Vec<Tm> = (0..rf.nparams).map(|l| mk::var(d - 1 - l)).collect();
        let mu = crate::opt::proof::steps::subst_n(&rf.measure, &params);
        let wty = mk::int_ty(rf.width);
        let (eqs, _) = self.path_eqs(ctx, facts)?;
        let mut cur_t = mu.clone();
        let mut cur_p = mk::refl(wty.clone(), mu.clone());
        let mut changed = false;
        for _round in 0..8 {
            let mut moved = false;
            for (ej, ety, ex, ec) in eqs.iter() {
                let Some((t2, p2)) = self.rewrite_fact(ctx, &cur_t, &cur_p, &wty, &mu, ex, ec, ety, &facts[*ej].proof)? else { continue };
                cur_t = t2;
                cur_p = p2;
                moved = true;
                changed = true;
            }
            if !moved {
                break;
            }
        }
        Ok(changed.then(|| Fact::eq(cur_p, mk::eq(wty, cur_t, mu))))
    }

    /// The lemma's own decrease obligation at a self-call, `μ(args) <
    /// μ(x̄)` (with `0 ≤ μ(args)` for an `Int` measure), by `linarith` from
    /// the structured reading's decrease proof and the measure's congruence.
    fn rec_decrease(&self, ctx: &Ctx, facts: &[Fact], cargs: &[Tm], dproof: &Tm) -> Result<Tm, String> {
        let rf = self.rec_fn.as_ref().ok_or("no recursion")?;
        let d = ctx.depth().0;
        let params: Vec<Tm> = (0..rf.nparams).map(|l| mk::var(d - 1 - l)).collect();
        let mut fs = facts.to_vec();
        fs.push(self.decrease_rec(ctx, cargs, dproof));
        if let Some(c) = self.measure_cong(ctx, facts)? {
            fs.push(c);
        }
        let a = crate::opt::proof::steps::subst_n(&rf.measure, cargs);
        let b = crate::opt::proof::steps::subst_n(&rf.measure, &params);
        let bi = self.env.bool_ind();
        let lt = mk::eq_bool(bi, mk::prim(PrimOp::Lt(rf.width), vec![a.clone(), b], vec![]), true);
        let lt_pf = self.linarith_fuel(ctx, &fs, &lt)?;
        if rf.width != Width::Int {
            return Ok(lt_pf);
        }
        let le = mk::eq_bool(bi, mk::prim(PrimOp::Le(Width::Int), vec![self.int_lit(0), a], vec![]), true);
        let le_pf = self.linarith_fuel(ctx, &fs, &le)?;
        Ok(mk::pair(mk::sigma("_", Rel::Rel, le.clone(), shift(&lt, 1)), le_pf, lt_pf))
    }

    /// `linarith` over the facts for a fuel goal (a list equation `n =
    /// Cons(u, n1)` contributes `len n = len (Cons(u, n1))`).
    /// `Empty` by arithmetic: `linarith` over the facts; else, for a fact
    /// that two machine words differ (`eq(a, b) = false`, `ne(a, b) = true`,
    /// which `linarith` cannot use: a disjunction), the equality proven by
    /// `linarith` from the others, against the fact (a constructor clash).
    fn refute_arith(&mut self, ctx: &Ctx, facts: &[Fact]) -> Result<Option<Tm>, String> {
        let r = self.refute_arith0(ctx, facts)?;
        self.check_empty(ctx, r.as_ref(), "refute_arith")?;
        Ok(r)
    }

    /// `CS_CHECK`: a refutation's proof checked against `Empty` (debugging).
    fn check_empty(&self, ctx: &Ctx, pf: Option<&Tm>, who: &str) -> Result<(), String> {
        let Some(pf) = pf else { return Ok(()) };
        if std::env::var("CS_CHECK").is_err() {
            return Ok(());
        }
        // (a recursive call cannot be checked outside its definition)
        let mut has_rec = false;
        crate::auto::util::map_term(pf, 0, &mut |x, _| {
            has_rec |= matches!(&**x, Term::Rec { .. });
            None
        });
        if has_rec {
            return Ok(());
        }
        let empty = mk::ind(self.env.empty_ind(), vec![]);
        let ev = self.eval(ctx, &empty)?;
        let mut b = self.b();
        if let Err(e) = self.env.check(ctx, pf, &ev, &mut b) {
            let names: Vec<Name> = ctx.entries.iter().map(|e| e.name.clone()).collect();
            return Err(format!("CHECK of a refutation by {who} failed: {}
  proof: {}", trunc(&e.to_string(), 3000), trunc(&self.env.print_term(&names, pf), 20000)));
        }
        Ok(())
    }

    fn refute_arith0(&mut self, ctx: &Ctx, facts: &[Fact]) -> Result<Option<Tm>, String> {
        let empty = mk::ind(self.env.empty_ind(), vec![]);
        if let Ok(pf) = self.linarith_fuel(ctx, facts, &empty) {
            return Ok(Some(pf));
        }
        for (i, f) in facts.iter().enumerate() {
            if f.is_marker() {
                continue;
            }
            let fty = self.eval(ctx, &f.ty)?;
            let Value::Eq { ty, lhs, rhs } = &*fty else { continue };
            if !matches!(&**ty, Value::Ind { ind, .. } if *ind == self.env.bool_ind()) {
                continue;
            }
            let Value::Ctor { ctor: c, .. } = &**rhs else { continue };
            let lt = peel_lets(&self.quote(ctx, lhs));
            let disequal = matches!(&*lt, Term::Prim { op: PrimOp::Eq(_), .. }) && *c == 0 || matches!(&*lt, Term::Prim { op: PrimOp::Ne(_), .. }) && *c == 1;
            if !disequal {
                continue;
            }
            // the other truth value of the same comparison, by `linarith`
            let other = mk::eq_bool(self.env.bool_ind(), lt.clone(), *c == 0);
            let rest: Vec<Fact> = facts.iter().enumerate().filter(|(j, _)| *j != i).map(|(_, x)| x.clone()).collect();
            let pf = match self.linarith_fuel(ctx, &rest, &other) {
                Ok(pf) => pf,
                Err(e) => {
                    if std::env::var("CS_TRACE_ARITH").is_ok() {
                        let names: Vec<Name> = ctx.entries.iter().map(|e| e.name.clone()).collect();
                        eprintln!("  arith: no refutation of {} = {c}: {e}", trunc(&self.env.print_term(&names, &lt), 2000));
                    }
                    continue;
                }
            };
            // clash: `lt = c` (the fact) and `lt = !c` (proven)
            let bool_t = mk::ind(self.env.bool_ind(), vec![]);
            let (ra, rb) = (mk::bool_lit(self.env.bool_ind(), *c == 1), mk::bool_lit(self.env.bool_ind(), *c == 0));
            let e1s = mk::apps(mk::global(self.g("eq::sym")?), vec![(Rel::Rel, bool_t.clone()), (Rel::Rel, lt.clone()), (Rel::Rel, ra.clone()), (Rel::Rel, f.proof.clone())]);
            let e12 = mk::apps(mk::global(self.g("eq::trans")?), vec![(Rel::Rel, bool_t.clone()), (Rel::Rel, ra.clone()), (Rel::Rel, lt.clone()), (Rel::Rel, rb.clone()), (Rel::Rel, e1s), (Rel::Rel, pf)]);
            let arms = vec![Arm { names: vec![], body: if *c == 0 { self.unit_ty() } else { empty.clone() } }, Arm { names: vec![], body: if *c == 1 { self.unit_ty() } else { empty.clone() } }];
            let motive_body = Rc::new(Term::Match { ind: self.env.bool_ind(), params: vec![], scrut: mk::var(0), motive: mk::ty(), arms });
            return Ok(Some(Rc::new(Term::Transport { ty: bool_t, lhs: ra, rhs: rb, eq: e12, motive: motive_body, val: self.tt() })));
        }
        Ok(None)
    }

    fn linarith_fuel(&self, ctx: &Ctx, facts: &[Fact], goal: &Tm) -> Result<Tm, String> {
        let mut hyps: Vec<(Tm, Tm)> = Vec::new();
        let list = self.env.lookup_ind("List");
        for f in facts {
            if f.is_marker() {
                continue;
            }
            let fty = self.eval(ctx, &f.ty)?;
            let Value::Eq { ty, lhs, rhs } = &*fty else { continue };
            let is_bool = matches!(&**ty, Value::Ind { ind, .. } if *ind == self.env.bool_ind());
            let is_int = matches!(&**ty, Value::IntTy(_));
            if is_bool && matches!(&**rhs, Value::Ctor { .. }) {
                // only comparisons (linear facts); other boolean facts are skipped
                // (`a = b` false and `a ≠ b` true are disjunctive: skipped);
                // the quoter's sharing `let`s around the comparison peeled
                let lt = peel_lets(&self.quote(ctx, lhs));
                let truth = matches!(&**rhs, Value::Ctor { ctor: 1, .. });
                let ok = match &*lt {
                    Term::Prim { op: PrimOp::Le(_) | PrimOp::Lt(_) | PrimOp::Ge(_) | PrimOp::Gt(_), .. } => true,
                    Term::Prim { op: PrimOp::Eq(_), .. } => truth,
                    Term::Prim { op: PrimOp::Ne(_), .. } => !truth,
                    _ => false,
                };
                if ok {
                    hyps.push((f.proof.clone(), f.ty.clone()));
                }
            } else if is_int {
                hyps.push((f.proof.clone(), f.ty.clone()));
            } else if let Value::Ind { ind, params } = &**ty
                && Some(*ind) == list
                && matches!(&**rhs, Value::Ctor { .. })
            {
                let lt = self.quote(ctx, lhs);
                let rt = self.quote(ctx, rhs);
                let elem = self.quote(ctx, &params[0]);
                let lenf = mk::app(mk::global(self.g("seq::len")?), elem.clone());
                let cong = mk::apps(mk::global(self.g("eq::cong")?), vec![(Rel::Rel, mk::ind(*ind, vec![elem])), (Rel::Rel, mk::int_ty(Width::Int)), (Rel::Rel, lenf.clone()), (Rel::Rel, lt.clone()), (Rel::Rel, rt.clone()), (Rel::Rel, f.proof.clone())]);
                let ty2 = mk::eq(mk::int_ty(Width::Int), mk::app(lenf.clone(), lt), mk::app(lenf, rt));
                hyps.push((cong, ty2));
            }
        }
        // (nested loops: the fuel functions' calls are nonnegative)
        let tys: Vec<&Tm> = std::iter::once(goal).chain(facts.iter().filter(|f| !f.is_marker()).map(|f| &f.ty)).collect();
        hyps.extend(self.fuel_nn_hyps(&tys));
        if std::env::var("CS_TRACE_FUEL").is_ok() {
            let names: Vec<Name> = ctx.entries.iter().map(|e| e.name.clone()).collect();
            let r = crate::elab::basic::linarith_term(self.env, ctx, hyps.clone(), goal.clone());
            if r.is_err() {
                eprintln!("FUEL FAILED at {}: goal {}", self.path.join(" / "), trunc(&self.env.print_term(&names, goal), 3000));
                for (_, t) in &hyps {
                    eprintln!("    hyp {}", trunc(&self.env.print_term(&names, t), 3000));
                }
            }
        }
        crate::elab::basic::linarith_term(self.env, ctx, hyps, goal.clone()).map_err(|e| format!("fuel arithmetic: {e}"))
    }

    /// `Empty` from the fuel premise when `n = Nil` (the need is positive:
    /// with the decrease proof at a recursive call).
    fn fuel_contradiction(&self, ctx: &Ctx, facts: &[Fact], g: &Goal) -> Result<Tm, String> {
        let empty = mk::ind(self.env.empty_ind(), vec![]);
        let mut fs = facts.to_vec();
        // at a recursive call, μ(args) < μ(params) and 0 ≤ μ(args) give 1 ≤ need
        let s1 = shift(&g.s, 1);
        if let Some((args, Some(dp))) = self.loop_rec(&s1)
            && let Some(rc) = &self.rec
        {
            let cargs: Vec<Tm> = args.iter().map(|a| self.commit(a)).collect();
            let hi = rc.helper.clone();
            fs.push(self.decrease_fact(&hi, &cargs, dp, ctx));
            if hi.width == Width::Int {
                let mu_args = hi.mu_int(&cargs);
                let le_ty = mk::eq_bool(self.env.bool_ind(), mk::prim(PrimOp::Le(Width::Int), vec![self.int_lit(0), mu_args], vec![]), true);
                fs.push(Fact::eq(Rc::new(Term::Fst(dp.clone())), le_ty));
            }
        }
        self.linarith_fuel(ctx, &fs, &empty)
    }

    /// `Empty` from a fact `Eq(T, t, D)` (`D` a constructor) whose left side,
    /// rewritten with the path equations `Eq(_, x, C)` of the context,
    /// evaluates to another constructor (`ord_lt(pc) = true` with `pc =
    /// Some(v)`, `v = Equal`).
    fn refute_eval(&mut self, ctx: &Ctx, facts: &[Fact]) -> Result<Option<Tm>, String> {
        self.refute_eval_at(ctx, facts, None)
    }

    /// [`Self::refute_eval`]; with `focus`, only refutations that involve that
    /// fact (as the fact rewritten, or as the path equation rewriting).
    fn refute_eval_at(&mut self, ctx: &Ctx, facts: &[Fact], focus: Option<usize>) -> Result<Option<Tm>, String> {
        let r = self.refute_eval_at0(ctx, facts, focus)?;
        self.check_empty(ctx, r.as_ref(), "refute_eval_at")?;
        Ok(r)
    }

    fn refute_eval_at0(&mut self, ctx: &Ctx, facts: &[Fact], focus: Option<usize>) -> Result<Option<Tm>, String> {
        let (eqs, targets) = self.path_eqs_at(ctx, facts, focus)?;
        if eqs.len() < 2 {
            return Ok(None);
        }
        if focus.is_some_and(|k| !eqs.iter().any(|e| e.0 == k)) {
            return Ok(None);
        }
        for (fi, fty, flhs, frhs) in targets.iter() {
            let dv = self.eval(ctx, frhs)?;
            let Value::Ctor { ctor: dc, .. } = &*dv else { continue };
            let dc = *dc;
            let Some((cur_t, cur_p)) = self.rewrite_target(ctx, facts, &eqs, *fi, fty, flhs, frhs, focus)? else { continue };
            let cv = self.eval(ctx, &cur_t)?;
            let Value::Ctor { ctor: cc, .. } = &*cv else { continue };
            if *cc == dc {
                continue;
            }
            // Eq(T, cur_t, D) with cur_t ≡ C' ≠ D: the motive `z. C' ? Unit : Empty`
            let Value::Ind { ind, params } = &*self.eval(ctx, fty)? else { continue };
            let decl = self.env.inductive_decl(*ind).ok_or("no inductive")?;
            let empty_ty = mk::ind(self.env.empty_ind(), vec![]);
            let mut arms = Vec::new();
            for (k, c) in decl.ctors.iter().enumerate() {
                let names: Vec<Name> = c.fields.iter().map(|f| f.0.clone()).collect();
                arms.push(Arm { names, body: if k as u32 == *cc { self.unit_ty() } else { empty_ty.clone() } });
            }
            let params_t: Vec<Tm> = params.iter().map(|p| shift(&self.quote(ctx, p), 1)).collect();
            let motive_body = Rc::new(Term::Match { ind: *ind, params: params_t, scrut: mk::var(0), motive: mk::ty(), arms });
            if facts[*fi].reused {
                self.stats.reused_proofs += 1;
            }
            return Ok(Some(Rc::new(Term::Transport { ty: fty.clone(), lhs: cur_t, rhs: frhs.clone(), eq: cur_p, motive: motive_body, val: self.tt() })));
        }
        Ok(None)
    }

    /// The path equations of the facts, `Eq(T, x, C(..))` (`x` not a
    /// constructor): (index, T, x, C(..)); and the targets to rewrite: the
    /// same, plus each with its side evaluated when that differs (a
    /// let-bound variable's value, or a transparent call's body, holds the
    /// tests the other path equations decide).
    #[allow(clippy::type_complexity)]
    fn path_eqs(&self, ctx: &Ctx, facts: &[Fact]) -> Result<(Vec<(usize, Tm, Tm, Tm)>, Vec<(usize, Tm, Tm, Tm)>), String> {
        self.path_eqs_at(ctx, facts, None)
    }

    /// [`Self::path_eqs`]; with a focus, only the focus gets its evaluated
    /// form as an extra target (the others are rewritten by the focus once).
    #[allow(clippy::type_complexity)]
    fn path_eqs_at(&self, ctx: &Ctx, facts: &[Fact], focus: Option<usize>) -> Result<(Vec<(usize, Tm, Tm, Tm)>, Vec<(usize, Tm, Tm, Tm)>), String> {
        let mut eqs: Vec<(usize, Tm, Tm, Tm)> = Vec::new();
        for (i, f) in facts.iter().enumerate() {
            if f.is_marker() {
                continue;
            }
            let Term::Eq { ty, lhs, rhs } = &*f.ty else { continue };
            let rv = self.eval(ctx, rhs)?;
            if matches!(&*rv, Value::Ctor { .. }) && !matches!(&*self.eval(ctx, lhs)?, Value::Ctor { .. }) {
                eqs.push((i, ty.clone(), lhs.clone(), rhs.clone()));
            }
        }
        let mut targets: Vec<(usize, Tm, Tm, Tm)> = eqs.clone();
        for (fi, fty, flhs, frhs) in eqs.iter() {
            if focus.is_some_and(|k| k != *fi) {
                continue;
            }
            // (a `let`: an S-split's scrutinee committed with its `let`s, the
            // quoter's sharing; its value holds the tests too)
            if matches!(&**flhs, Term::Var(_) | Term::App { .. } | Term::Global(_) | Term::Let { .. }) {
                let ev = self.quote(ctx, &self.eval(ctx, flhs)?);
                if !self.env.alpha_eq_relevant(&ev, flhs, &|a, b| a == b) {
                    targets.push((*fi, fty.clone(), ev, frhs.clone()));
                }
            }
        }
        Ok((eqs, targets))
    }

    /// Fact `fi` (`Eq(fty, flhs, frhs)`) with its side rewritten by the
    /// other path equations (up to four rounds; with a focus on another
    /// fact, once by the focus) until it is a constructor: the new side and
    /// the proof of `Eq(fty, side, frhs)`. `None` when nothing rewrote it.
    #[allow(clippy::too_many_arguments)]
    fn rewrite_target(&self, ctx: &Ctx, facts: &[Fact], eqs: &[(usize, Tm, Tm, Tm)], fi: usize, fty: &Tm, flhs: &Tm, frhs: &Tm, focus: Option<usize>) -> Result<Option<(Tm, Tm)>, String> {
        let mut cur_t = flhs.clone();
        let mut cur_p = facts[fi].proof.clone();
        let mut changed = false;
        let only = focus.filter(|k| *k != fi);
        for _round in 0..(if only.is_some() { 1 } else { 4 }) {
            let mut moved = false;
            for (ej, ety, ex, ec) in eqs.iter() {
                if *ej == fi || only.is_some_and(|k| k != *ej) {
                    continue;
                }
                let Some((t2, p2)) = self.rewrite_fact(ctx, &cur_t, &cur_p, fty, frhs, ex, ec, ety, &facts[*ej].proof)? else { continue };
                cur_t = t2;
                cur_p = p2;
                moved = true;
                changed = true;
                if matches!(&*self.eval(ctx, &cur_t)?, Value::Ctor { .. }) {
                    break;
                }
            }
            if !moved || matches!(&*self.eval(ctx, &cur_t)?, Value::Ctor { .. }) {
                break;
            }
        }
        Ok(changed.then_some((cur_t, cur_p)))
    }

    /// Both sides values that differ where the structured side has the
    /// fields of a split it made without the literal side (`Some(value)`
    /// where the literal side has its own `Some(seq::index ..)`): the split's
    /// path equation, rewritten by the others to the same constructor, gives
    /// each field's equation (injectivity), and the literal side is
    /// rewritten to the structured side's fields.
    fn inj_repair(&mut self, ctx: &Ctx, g: &Goal, facts: &[Fact], depth: u32) -> Result<Option<Tm>, String> {
        let (eqs, targets) = self.path_eqs(ctx, facts)?;
        for (fi, fty, flhs, frhs) in targets.iter() {
            let Term::Ctor { ind, ctor, params, args } = &*self.quote(ctx, &self.eval(ctx, frhs)?) else { continue };
            // (only a split's fields: variables of the context)
            if args.is_empty() || !args.iter().all(|a| matches!(&**a, Term::Var(_))) {
                continue;
            }
            let Some((cur_t, cur_p)) = self.rewrite_target(ctx, facts, &eqs, *fi, fty, flhs, frhs, None)? else { continue };
            let Term::Ctor { ctor: c2, args: args2, .. } = &*self.quote(ctx, &self.eval(ctx, &cur_t)?) else { continue };
            if c2 != ctor || args2.len() != args.len() {
                continue;
            }
            let decl = self.env.inductive_decl(*ind).ok_or("no inductive")?;
            let c = decl.ctors[*ctor as usize].clone();
            for (k, (w, v)) in args2.iter().zip(args.iter()).enumerate() {
                if self.env.alpha_eq_relevant(w, v, &|a, b| a == b) {
                    continue;
                }
                let wv = self.eval(ctx, w)?;
                let l_abs = self.abstract_l(ctx, &g.l, &wv)?;
                if count_var(&l_abs, 0) == 0 {
                    continue;
                }
                // Eq(T_k, w, v) from Eq(fty, C(w̄), C(v̄)) by a transport whose
                // motive projects field k (`match z with C(..) => x_k | _ => w`)
                let mut sub: Vec<Tm> = params.clone();
                sub.extend(args[..k].iter().cloned());
                let tk = crate::opt::proof::steps::subst_n(&c.fields[k].2, &sub);
                let mut marms = Vec::new();
                for (j, cj) in decl.ctors.iter().enumerate() {
                    let nf = cj.fields.len() as u32;
                    let names: Vec<Name> = cj.fields.iter().map(|f| f.0.clone()).collect();
                    let body = if j as u32 == *ctor { mk::var(nf - 1 - k as u32) } else { shift(w, 1 + nf as i64) };
                    marms.push(Arm { names, body });
                }
                let proj = Rc::new(Term::Match { ind: *ind, params: params.iter().map(|p| shift(p, 1)).collect(), scrut: mk::var(0), motive: shift(&tk, 2), arms: marms });
                let motive = mk::eq(shift(&tk, 1), shift(w, 1), proj);
                let inj = Rc::new(Term::Transport { ty: fty.clone(), lhs: cur_t.clone(), rhs: frhs.clone(), eq: cur_p.clone(), motive, val: mk::refl(tk.clone(), w.clone()) });
                // the literal side: w rewritten to v along `inj : Eq(T_k, w, v)`
                let mot = self.goal_e(&g.with(l_abs.clone(), shift(&g.s, 1), 1));
                {
                    let tkv = self.eval(ctx, &tk)?;
                    let cy = ctx.push(CtxEntry { name: name("y"), rel: Rel::Rel, ty: tkv, def: None });
                    let mut b = self.b();
                    if self.env.infer(&cy, &mot, &mut b).is_err() {
                        continue;
                    }
                }
                let g2 = g.with(crate::elab::tm::subst0(&l_abs, v), g.s.clone(), 0);
                self.stats.transports += 1;
                let inner = self.terminal(ctx, &g2, facts, depth + 1)?;
                let sym = mk::apps(mk::global(self.g("eq::sym")?), vec![(Rel::Rel, tk.clone()), (Rel::Rel, w.clone()), (Rel::Rel, v.clone()), (Rel::Rel, inj)]);
                return Ok(Some(Rc::new(Term::Transport { ty: tk, lhs: v.clone(), rhs: w.clone(), eq: sym, motive: mot, val: inner })));
            }
        }
        Ok(None)
    }

    /// The fact `p : Eq(fty, t, d)` rewritten along the path equation `e :
    /// Eq(xty, x, c)`: the occurrences of `x` in `t` (outside binders,
    /// syntactically) replaced by `c`, the new side normalized (a decided
    /// test exposes the next one). A dependent-match idiom on `x`, `(match x
    /// as z return Π(.h : Eq(D, x, z)). R ..) .refl(x)`, keeps its motive and
    /// arms (their proofs are about `x` itself): only its scrutinee follows,
    /// with a bound path equation `q : Eq(D, x, y)` for its proof — `refl(x)`
    /// and `q` agree by proof irrelevance; after the transport the idiom
    /// gets `e` itself (the walker's own S-split, applied to a fact).
    #[allow(clippy::too_many_arguments)]
    fn rewrite_fact(&self, ctx: &Ctx, t: &Tm, p: &Tm, fty: &Tm, d: &Tm, x: &Tm, c: &Tm, xty: &Tm, e: &Tm) -> Result<Option<(Tm, Tm)>, String> {
        let xv = self.eval(ctx, x)?;
        let a = self.abs_syn(ctx, t, &xv)?; // (ctx, y)
        if count_var(&a, 0) == 0 {
            return Ok(None);
        }
        let (new_p, inst) = if !has_proof_mentioning(&a, 0) {
            let motive = mk::eq(shift(fty, 1), a.clone(), shift(d, 1));
            (Rc::new(Term::Transport { ty: xty.clone(), lhs: x.clone(), rhs: c.clone(), eq: e.clone(), motive, val: p.clone() }), crate::elab::tm::subst0(&a, c))
        } else {
            // (ctx, y, q): the idioms on y take q
            let a1 = replace_proofs_gen(self.env.bool_ind(), &shift(&a, 1), 1, &mk::var(0), &shift(x, 2), &shift(xty, 2));
            let q_ty = mk::eq(shift(xty, 1), shift(x, 1), mk::var(0));
            let motive = mk::pi("q", Rel::Irr, q_ty, mk::eq(shift(fty, 2), a1, shift(d, 2)));
            let val = mk::lam("q", Rel::Irr, mk::eq(xty.clone(), x.clone(), x.clone()), shift(p, 1));
            let tr = Rc::new(Term::Transport { ty: xty.clone(), lhs: x.clone(), rhs: c.clone(), eq: e.clone(), motive, val });
            let a_e = replace_proofs_gen(self.env.bool_ind(), &a, 0, &shift(e, 1), &shift(x, 1), &shift(xty, 1));
            (Rc::new(Term::App { rel: Rel::Irr, fun: tr, arg: e.clone() }), crate::elab::tm::subst0(&a_e, c))
        };
        // the new side normalized; when normalizing leaves a checked
        // primitive with a proof about the old operands (evaluation drops the
        // transports of its proofs), the side reduced only by iota and beta
        // (which keep it well-typed)
        let norm = self.quote(ctx, &self.eval(ctx, &inst)?);
        let mut b = self.b();
        let side = if self.env.infer(ctx, &norm, &mut b).is_ok() { norm } else { iota_syn(&inst) };
        Ok(Some((side, new_p)))
    }

    /// `t` (a term of the context, kept folded) with its subterms outside
    /// binders that convert to `c` replaced by a new variable: a term in
    /// `(ctx, y)`.
    fn abs_syn(&self, ctx: &Ctx, t: &Tm, c: &V) -> Result<Tm, String> {
        let candidate = matches!(&**t, Term::App { .. } | Term::Var(_) | Term::Global(_) | Term::Match { .. } | Term::Prim { .. } | Term::Fst(_) | Term::Snd(_));
        if candidate {
            let v = self.eval(ctx, t)?;
            if self.conv(ctx, &v, c) {
                return Ok(mk::var(0));
            }
        }
        Ok(match &**t {
            Term::App { rel, fun, arg } => Rc::new(Term::App { rel: *rel, fun: self.abs_syn(ctx, fun, c)?, arg: if *rel == Rel::Rel { self.abs_syn(ctx, arg, c)? } else { shift(arg, 1) } }),
            Term::Ctor { ind, ctor, params, args } => Rc::new(Term::Ctor { ind: *ind, ctor: *ctor, params: params.iter().map(|p| shift(p, 1)).collect(), args: args.iter().map(|a| self.abs_syn(ctx, a, c)).collect::<Result<_, _>>()? }),
            Term::Prim { op, args, proofs } => Rc::new(Term::Prim { op: *op, args: args.iter().map(|a| self.abs_syn(ctx, a, c)).collect::<Result<_, _>>()?, proofs: proofs.iter().map(|p| shift(p, 1)).collect() }),
            Term::Match { ind, params, scrut, motive, arms } => Rc::new(Term::Match { ind: *ind, params: params.iter().map(|p| shift(p, 1)).collect(), scrut: self.abs_syn(ctx, scrut, c)?, motive: shift_from(motive, 1, 1), arms: arms.iter().map(|a| Arm { names: a.names.clone(), body: shift_from(&a.body, 1, a.names.len() as u32) }).collect() }),
            // (the quoter shares a repeated value by a `let`: its value, and
            // its body with the `let`'s variable a definition of the context
            // — abstracted in `(ctx, x, y)`, then read in `(ctx, y, x)`)
            Term::Let { name, rel: Rel::Rel, ty, val, body } => {
                let body_a = match self.push(ctx, name, Rel::Rel, ty, Some(val)) {
                    Ok(cx) => {
                        let b = self.abs_syn(&cx, body, c)?;
                        if count_var(&b, 0) > 0 { crate::elab::tm::subst0(&shift_from(&b, 1, 2), &mk::var(1)) } else { shift_from(body, 1, 1) }
                    }
                    Err(_) => shift_from(body, 1, 1),
                };
                Rc::new(Term::Let { name: name.clone(), rel: Rel::Rel, ty: shift(ty, 1), val: self.abs_syn(ctx, val, c)?, body: body_a })
            }
            _ => shift(t, 1),
        })
    }

    /// `Empty` from two facts `Eq(D, x, C_i(..))`, `Eq(D, x', C_j(..))`, `x ≡ x'`, `i ≠ j`.
    fn refute(&mut self, ctx: &Ctx, facts: &[Fact]) -> Result<Option<Tm>, String> {
        self.refute_at(ctx, facts, None)
    }

    /// The newest fact, a path equation, against the others (a constructor
    /// clash, a rewriting that evaluates to another constructor): checked
    /// at the start of every walk step, so a contradictory arm is closed
    /// before anything in it is split.
    fn refute_last(&mut self, ctx: &Ctx, facts: &[Fact]) -> Result<Option<Tm>, String> {
        let Some(last) = facts.last() else { return Ok(None) };
        let Term::Eq { ty, .. } = &*last.ty else { return Ok(None) };
        if last.is_marker() {
            return Ok(None);
        }
        // (an equation at a type of one constructor, an eta split's or a
        // fuel split's `n = Cons(u, n1)`, decides no test: nothing to refute)
        if let Ok(tyv) = self.eval(ctx, ty)
            && let Value::Ind { ind, .. } = &*tyv
            && (self.env.inductive_decl(*ind).is_some_and(|d| d.ctors.len() == 1) || Some(*ind) == self.env.lookup_ind("List") && matches!(&*self.eval(ctx, ty)?, Value::Ind { params, .. } if params.first().is_some_and(|p| matches!(&**p, Value::Ind { ind: u, .. } if Some(*u) == self.env.lookup_ind("Unit")))))
        {
            return Ok(None);
        }
        let k = facts.len() - 1;
        if let Some(pf) = self.refute_at(ctx, facts, Some(k))? {
            return Ok(Some(pf));
        }
        self.refute_eval_at(ctx, facts, Some(k))
    }

    /// [`Self::refute`]; with `focus`, only pairs with that fact.
    fn refute_at(&mut self, ctx: &Ctx, facts: &[Fact], focus: Option<usize>) -> Result<Option<Tm>, String> {
        let r = self.refute_at0(ctx, facts, focus)?;
        self.check_empty(ctx, r.as_ref(), "refute_at")?;
        Ok(r)
    }

    fn refute_at0(&mut self, ctx: &Ctx, facts: &[Fact], focus: Option<usize>) -> Result<Option<Tm>, String> {
        let mut evs: Vec<(usize, V, V, V)> = Vec::new();
        for (i, f) in facts.iter().enumerate() {
            if f.is_marker() {
                continue;
            }
            let fty = self.eval(ctx, &f.ty)?;
            if let Value::Eq { ty, lhs, rhs } = &*fty
                && matches!(&**rhs, Value::Ctor { .. })
            {
                evs.push((i, ty.clone(), lhs.clone(), rhs.clone()));
            }
        }
        for a in 0..evs.len() {
            for b2 in (a + 1)..evs.len() {
                let (ia, ta, la, ra) = &evs[a];
                let (ib, _, lb, rb) = &evs[b2];
                if focus.is_some_and(|k| k != *ia && k != *ib) {
                    continue;
                }
                let (Value::Ctor { ctor: ca, .. }, Value::Ctor { ctor: cb, .. }) = (&**ra, &**rb) else { continue };
                if ca == cb || !self.conv(ctx, la, lb) {
                    continue;
                }
                let dty = self.quote(ctx, ta);
                let lhs_t = self.quote(ctx, la);
                let ra_t = self.quote(ctx, ra);
                let rb_t = self.quote(ctx, rb);
                if facts[*ia].reused || facts[*ib].reused {
                    self.stats.reused_proofs += 1;
                }
                let e1s = mk::apps(mk::global(self.g("eq::sym")?), vec![(Rel::Rel, dty.clone()), (Rel::Rel, lhs_t.clone()), (Rel::Rel, ra_t.clone()), (Rel::Rel, facts[*ia].proof.clone())]);
                let e12 = mk::apps(mk::global(self.g("eq::trans")?), vec![(Rel::Rel, dty.clone()), (Rel::Rel, ra_t.clone()), (Rel::Rel, lhs_t.clone()), (Rel::Rel, rb_t.clone()), (Rel::Rel, e1s), (Rel::Rel, facts[*ib].proof.clone())]);
                let Value::Ind { ind, params } = &**ta else { continue };
                let decl = self.env.inductive_decl(*ind).ok_or("no inductive")?;
                let empty_ty = mk::ind(self.env.empty_ind(), vec![]);
                let mut arms = Vec::new();
                for (k, c) in decl.ctors.iter().enumerate() {
                    let names: Vec<Name> = c.fields.iter().map(|f| f.0.clone()).collect();
                    arms.push(Arm { names, body: if k as u32 == *ca { self.unit_ty() } else { empty_ty.clone() } });
                }
                let params_t: Vec<Tm> = params.iter().map(|p| shift(&self.quote(ctx, p), 1)).collect();
                let motive_body = Rc::new(Term::Match { ind: *ind, params: params_t, scrut: mk::var(0), motive: mk::ty(), arms });
                return Ok(Some(Rc::new(Term::Transport { ty: dty, lhs: ra_t, rhs: rb_t, eq: e12, motive: motive_body, val: self.tt() })));
            }
        }
        Ok(None)
    }

    /// Whether `ind` is a struct whose matches the walker eta-expands (one
    /// constructor, not recursive, relevant fields).
    fn is_struct(&self, ind: IndId) -> bool {
        let Some(decl) = self.env.inductive_decl(ind) else { return false };
        decl.ctors.len() == 1 && !self.env.inductive_is_recursive(ind).unwrap_or(true) && decl.ctors[0].fields.iter().all(|f| f.1 == Rel::Rel) && !decl.ctors[0].fields.is_empty()
    }

    /// The innermost stuck match on a struct value that is not a projection
    /// (its arm does more than return a field).
    /// The stuck matches on struct values that are not projections, in the
    /// order [`Self::struct_scrut`] meets them (at most `max`).
    fn struct_scruts(&self, ctx: &Ctx, v: &V, fuel: &mut u32, out: &mut Vec<(V, IndId, Vec<V>)>, max: usize) {
        *fuel += 1;
        if *fuel > 400 || out.len() >= max {
            return;
        }
        let Value::Neu(n) = &**v else {
            if let Value::Ctor { args, .. } = &**v {
                for a in args {
                    if let Arg::Rel(x) = a {
                        self.struct_scruts(ctx, x, fuel, out, max);
                    }
                }
            }
            return;
        };
        if let Head::Global { def, args } = &n.head
            && !self.frozen.contains(def)
        {
            for a in args {
                if let Arg::Rel(x) = a {
                    self.struct_scruts(ctx, x, fuel, out, max);
                }
            }
        }
        for (i, e) in n.spine.iter().enumerate() {
            if out.len() >= max {
                return;
            }
            if let Elim::Match { ind, params, arms, .. } = e {
                let nf = self.env.inductive_decl(*ind).map(|d| d.ctors.first().map(|c| c.fields.len()).unwrap_or(0)).unwrap_or(0) as u32;
                let projection = arms.len() == 1 && matches!(&*arms[0].body, Term::Var(Idx(k)) if *k < nf);
                if self.is_struct(*ind) && !projection {
                    out.push((prefix(n, i), *ind, params.clone()));
                    return;
                }
            }
        }
        if let Head::Global { def, args } = &n.head
            && n.spine.is_empty()
            && self.l_runs.contains(def)
            && !self.frozen.contains(def)
        {
            let Some(body) = self.env.global_body(*def) else { return };
            let Some(arity) = self.env.global_arity(*def) else { return };
            let venv = self.env.ctx_venv(ctx);
            let mut b = self.b();
            let Ok(mut cur) = self.env.eval(&venv, ctx.depth(), &body, &mut b) else { return };
            for a in args.iter().take(arity as usize) {
                let Value::Lam { body: cl, .. } = &*cur else { return };
                let e = match a {
                    Arg::Rel(x) => EnvEntry::Rel(x.clone()),
                    Arg::Irr(c) => EnvEntry::Irr(c.clone()),
                };
                let Ok(c2) = self.inst(cl, e, ctx.depth().0, &mut b) else { return };
                cur = c2;
            }
            self.struct_scruts(ctx, &cur, fuel, out, max);
        }
    }

    fn inst(&self, c: &sandblaster_kernel::value::Closure, e: EnvEntry, depth: u32, b: &mut Budget) -> Result<V, String> {
        let mut v = (*c.env.0).clone();
        v.push(e);
        self.env.eval(&sandblaster_kernel::value::VEnv(Rc::new(v)), sandblaster_kernel::term::Lvl(depth), &c.body, b).map_err(|e| format!("eval: {e:?}"))
    }

    /// The test a stuck value waits for: the innermost stuck match, past
    /// projections of struct values (their scrutinee is the next match's).
    fn blocker(&self, ctx: &Ctx, v: &V) -> Option<(V, IndId, Vec<V>)> {
        let chain = self.blocker_chain(ctx, v);
        // (past structs and projections of one-constructor values: the
        // test is the first match on a value of several constructors)
        chain.iter().find(|(_, ind, _)| self.env.inductive_decl(*ind).is_some_and(|d| d.ctors.len() != 1)).cloned().or_else(|| chain.iter().find(|(_, ind, _)| !self.is_struct(*ind)).cloned()).or_else(|| chain.first().cloned())
    }

    /// The stuck matches of the innermost blocking neutral, innermost first
    /// (each scrutinee contains the previous match).
    fn blocker_chain(&self, ctx: &Ctx, v: &V) -> Vec<(V, IndId, Vec<V>)> {
        let mut fuel = 0;
        self.blocker_in(ctx, v, &mut fuel).unwrap_or_default()
    }

    fn blocker_in(&self, ctx: &Ctx, v: &V, fuel: &mut u32) -> Option<Vec<(V, IndId, Vec<V>)>> {
        *fuel += 1;
        if *fuel > 400 {
            return None;
        }
        let Value::Neu(n) = &**v else {
            if let Value::Ctor { args, .. } = &**v {
                for a in args {
                    if let Arg::Rel(x) = a
                        && let Some(r) = self.blocker_in(ctx, x, fuel)
                    {
                        return Some(r);
                    }
                }
            }
            return None;
        };
        let matches: Vec<usize> = n.spine.iter().enumerate().filter(|(_, e)| matches!(e, Elim::Match { .. })).map(|(i, _)| i).collect();
        if let Some(&i0) = matches.first() {
            let s0 = prefix(n, i0);
            // (the scrutinee waits for an inner test: the inner chain, then
            // this neutral's own matches, which a fact may decide first)
            let mut chain = self.blocker_in(ctx, &s0, fuel).unwrap_or_default();
            for &i in &matches {
                let Elim::Match { ind, params, .. } = &n.spine[i] else { unreachable!() };
                chain.push((prefix(n, i), *ind, params.clone()));
            }
            return Some(chain);
        }
        if let Head::Global { def, args } = &n.head
            && self.l_runs.contains(def)
            && !self.frozen.contains(def)
        {
            // a folded run of the literal reading waits for the test its
            // body is stuck on (its arguments may hold stuck values that
            // nothing waits for yet); another folded global is opaque, not
            // waiting for its arguments
            if let Some(r) = self.unfold_run(ctx, *def, args).and_then(|cur| self.blocker_in(ctx, &cur, fuel)) {
                return Some(r);
            }
            for a in args {
                if let Arg::Rel(x) = a
                    && let Some(r) = self.blocker_in(ctx, x, fuel)
                {
                    return Some(r);
                }
            }
        }
        // a primitive stuck on an argument that waits for a test (a match on
        // a value of several constructors, not a projection) waits for it
        if let Head::Prim { args, .. } = &n.head {
            for a in args {
                if let Some(r) = self.blocker_in(ctx, a, fuel)
                    && r.iter().any(|(_, ind, _)| self.env.inductive_decl(*ind).is_some_and(|d| d.ctors.len() > 1))
                {
                    return Some(r);
                }
            }
        }
        None
    }

    /// The body of a run of the literal reading at its arguments (evaluated).
    fn unfold_run(&self, ctx: &Ctx, def: GlobalId, args: &[Arg]) -> Option<V> {
        let body = self.env.global_body(def)?;
        let arity = self.env.global_arity(def)? as usize;
        let venv = self.env.ctx_venv(ctx);
        let mut b = self.b();
        let mut cur = self.env.eval(&venv, ctx.depth(), &body, &mut b).ok()?;
        for a in args.iter().take(arity) {
            let Value::Lam { body: cl, .. } = &*cur else { return None };
            let e = match a {
                Arg::Rel(x) => EnvEntry::Rel(x.clone()),
                Arg::Irr(c) => EnvEntry::Irr(c.clone()),
            };
            cur = self.inst(cl, e, ctx.depth().0, &mut b).ok()?;
        }
        Some(cur)
    }
}

/// `t` (in `ctx` shifted by `k`: `k` binders pushed after `ctx`, the
/// innermost the path equation `e : Eq(D, x, c)`) with the variable `x`
/// (index `kx` in `ctx`) replaced by `c` and each dependent proof `h`
/// (index `kh` in `ctx`, type `T_h`) by its transport along `e`.
/// The first `min`/`max` primitive on non-literal words in `t` (outside
/// binders, relevant positions): (op, a, b).
fn find_minmax(t: &Tm) -> Option<(PrimOp, Tm, Tm)> {
    match &**t {
        Term::Prim { op: op @ (PrimOp::Min(_) | PrimOp::Max(_)), args, .. } if args.len() == 2 && !(matches!(&*args[0], Term::Lit { .. }) && matches!(&*args[1], Term::Lit { .. })) => {
            // (an inner one first: its rewrite exposes the outer)
            find_minmax(&args[0]).or_else(|| find_minmax(&args[1])).or_else(|| Some((*op, args[0].clone(), args[1].clone())))
        }
        Term::Prim { args, .. } => args.iter().find_map(find_minmax),
        Term::Ctor { args, .. } => args.iter().find_map(find_minmax),
        Term::App { rel: Rel::Rel, fun, arg } => find_minmax(fun).or_else(|| find_minmax(arg)),
        Term::App { fun, .. } => find_minmax(fun),
        Term::Fst(x) | Term::Snd(x) => find_minmax(x),
        _ => None,
    }
}

fn replace_split(t: &Tm, kx: u32, c: &Tm, deps: &[(u32, Tm)], dty: &Tm, k: u32) -> Tm {
    let x_k = mk::var(kx + k);
    let reps: Vec<(u32, Tm)> = deps
        .iter()
        .map(|(kh, th)| {
            // motive: T_h with x as the transport's variable
            let th_k = shift(th, k as i64);
            let mot = replace_var(&shift(&th_k, 1), kx + k + 1, &mk::var(0));
            (kh + k, Rc::new(Term::Transport { ty: shift(dty, k as i64), lhs: x_k.clone(), rhs: c.clone(), eq: mk::var(0), motive: mot, val: mk::var(kh + k) }))
        })
        .collect();
    crate::auto::util::map_term(t, 0, &mut |x, d| match &**x {
        Term::Var(Idx(i)) if *i == kx + k + d => Some(shift(c, d as i64)),
        Term::Var(Idx(i)) if *i >= d && reps.iter().any(|(r, _)| *r + d == *i) => reps.iter().find(|(r, _)| *r + d == *i).map(|(_, rep)| shift(rep, d as i64)),
        _ => None,
    })
}

/// The dependent idiom `(match y as z return Π(.e : Eq(D, y, z)). R ..) .p`
/// whose scrutinee is the abstraction variable `y` (index `y` in `t`): its
/// path equation's proof `p` (a `refl` of the old scrutinee, which
/// abstraction does not enter) becomes `refl(D, y)`, the proof the motive
/// expects at `z := y`.
fn repair_idiom(t: &Tm, y: u32) -> Tm {
    crate::auto::util::map_term(t, 0, &mut |x, d| {
        let Term::App { rel: Rel::Irr, fun, arg } = &**x else { return None };
        let Term::Match { ind, params, scrut, motive, arms } = &**fun else { return None };
        if !matches!(&**scrut, Term::Var(Idx(i)) if *i == y + d) || !matches!(&**motive, Term::Pi { rel: Rel::Irr, .. }) {
            return None;
        }
        let _ = arg;
        let fun2 = Rc::new(Term::Match { ind: *ind, params: params.iter().map(|p| repair_idiom_at(p, y + d)).collect(), scrut: scrut.clone(), motive: repair_idiom_at(motive, y + d + 1), arms: arms.iter().map(|a| Arm { names: a.names.clone(), body: repair_idiom_at(&a.body, y + d + a.names.len() as u32) }).collect() });
        Some(Rc::new(Term::App { rel: Rel::Irr, fun: fun2, arg: mk::refl(mk::ind(*ind, params.clone()), scrut.clone()) }))
    })
}

fn repair_idiom_at(t: &Tm, y: u32) -> Tm {
    repair_idiom(t, y)
}

/// Whether `t` holds a dependent match (an idiom with its path equation)
/// whose scrutinee is the variable `y` (index `y` in `t`).
fn idiom_on(t: &Tm, y: u32) -> bool {
    let mut found = false;
    crate::auto::util::map_term(t, 0, &mut |x, d| {
        if !found
            && let Term::App { rel: Rel::Irr, fun, .. } = &**x
            && let Term::Match { scrut, motive, .. } = &**fun
            && matches!(&**scrut, Term::Var(Idx(i)) if *i == y + d)
            && matches!(&**motive, Term::Pi { rel: Rel::Irr, .. })
        {
            found = true;
        }
        None
    });
    found
}

/// `t` with the `let`-bound variables `defs` (variable, value) replaced by
/// their values and the transparent executable calls unfolded (at most
/// `depth` levels), in relevant positions only: a term convertible with
/// `t` whose proofs are `t`'s own (well-typed), where the tests that `t`'s
/// value waits for are syntactic.
fn unfold_syn(env: &Env, t: &Tm, defs: &[(Tm, Tm)], depth: u32) -> Tm {
    unfold_syn_d(env, t, defs, depth, 0)
}

/// [`unfold_syn`] of a term under `d0` binders.
fn unfold_syn_d(env: &Env, t: &Tm, defs: &[(Tm, Tm)], depth: u32, d0: u32) -> Tm {
    crate::auto::util::map_term(t, d0, &mut |x, d| match &**x {
        Term::Var(Idx(i)) if *i >= d => {
            let v = defs.iter().find(|(var, _)| matches!(&**var, Term::Var(Idx(j)) if *j == *i - d))?;
            Some(shift(&unfold_syn_d(env, &v.1, defs, depth, 0), d as i64))
        }
        Term::Linarith { .. } => Some(x.clone()),
        Term::Prim { op, args, proofs } if !proofs.is_empty() => Some(Rc::new(Term::Prim { op: *op, args: args.iter().map(|a| unfold_syn_d(env, a, defs, depth, d)).collect(), proofs: proofs.clone() })),
        Term::App { rel: Rel::Irr, fun, arg } if !matches!(&**fun, Term::Match { .. }) => {
            if depth > 0
                && let Some(r) = unfold_call(env, x)
            {
                return Some(unfold_syn_d(env, &r, defs, depth - 1, d));
            }
            Some(Rc::new(Term::App { rel: Rel::Irr, fun: unfold_syn_d(env, fun, defs, depth, d), arg: arg.clone() }))
        }
        Term::App { .. } if depth > 0 => {
            let r = unfold_call(env, x)?;
            Some(unfold_syn_d(env, &r, defs, depth - 1, d))
        }
        _ => None,
    })
}

/// A saturated call of a transparent, non-recursive executable global: its
/// body at the arguments (delta and beta).
fn unfold_call(env: &Env, t: &Tm) -> Option<Tm> {
    let (g, args) = app_spine(t)?;
    use sandblaster_kernel::term::DefKind;
    if env.global_opaque(g) != Some(false) || !matches!(env.global_kind(g), Some(DefKind::Exec | DefKind::Prelude)) || env.global_arity(g)? as usize != args.len() || args.is_empty() {
        return None;
    }
    let body = env.global_body(g)?;
    if refers_to(&body, g) {
        return None;
    }
    let mut b = body;
    for _ in 0..args.len() {
        let Term::Lam { body: bb, .. } = &*b.clone() else { return None };
        b = bb.clone();
    }
    let vals: Vec<Tm> = args.iter().map(|(_, a)| a.clone()).collect();
    Some(crate::opt::proof::steps::subst_n(&b, &vals))
}

/// `t` with its redexes on constructors reduced syntactically: a match on a
/// constructor is its arm at the fields, an idiom on a constructor its arm
/// applied to the path equation's proof (iota and beta: they keep `t`
/// well-typed, unlike a round trip through evaluation, which drops proofs'
/// transports).
fn iota_syn(t: &Tm) -> Tm {
    let mut cur = t.clone();
    for _ in 0..16 {
        let mut changed = false;
        let next = crate::auto::util::map_term(&cur, 0, &mut |x, _| {
            let red = |m: &Tm| -> Option<Tm> {
                let Term::Match { scrut, arms, .. } = &**m else { return None };
                let Term::Ctor { ctor, args, .. } = &**scrut else { return None };
                let a = arms.get(*ctor as usize)?;
                Some(crate::opt::proof::steps::subst_n(&a.body, args))
            };
            match &**x {
                // (proofs are left as they are: a `linarith` certificate is
                // about its own statement)
                Term::Linarith { .. } => Some(x.clone()),
                Term::Prim { op, args, proofs } if !proofs.is_empty() => {
                    let args2: Vec<Tm> = args.iter().map(iota_syn).collect();
                    if args2.iter().zip(args).any(|(a, b)| !Rc::ptr_eq(a, b)) {
                        changed = true;
                    }
                    Some(Rc::new(Term::Prim { op: *op, args: args2, proofs: proofs.clone() }))
                }
                Term::App { rel, fun, arg } if matches!(&**fun, Term::Match { .. }) => {
                    let body = red(fun)?;
                    changed = true;
                    Some(match &*body {
                        Term::Lam { body: lb, .. } => crate::elab::tm::subst0(lb, arg),
                        _ => Rc::new(Term::App { rel: *rel, fun: body, arg: arg.clone() }),
                    })
                }
                Term::Match { .. } => {
                    let r = red(x)?;
                    changed = true;
                    Some(r)
                }
                _ => None,
            }
        });
        cur = next;
        if !changed {
            break;
        }
    }
    cur
}

/// Whether `t` has a proof whose type mentions the variable `y`: a
/// dependent-match idiom whose scrutinee is it or holds it (a match on a
/// transparent call's result that holds the abstracted test), or a checked
/// primitive whose operands hold it.
fn has_proof_mentioning(t: &Tm, y: u32) -> bool {
    let mut found = false;
    crate::auto::util::map_term(t, 0, &mut |x, d| {
        if !found
            && let Term::App { rel: Rel::Irr, fun, .. } = &**x
            && let Term::Match { scrut, motive, .. } = &**fun
            && matches!(&**motive, Term::Pi { rel: Rel::Irr, .. })
            && count_var(scrut, y + d) > 0
        {
            found = true;
        }
        // (a checked primitive whose operands hold `y`: its proofs are about them)
        if !found
            && let Term::Prim { args, proofs, .. } = &**x
            && !proofs.is_empty()
            && args.iter().any(|a| count_var(a, y + d) > 0)
        {
            found = true;
        }
        None
    });
    found
}

/// [`replace_idiom_args`] for every idiom whose scrutinee mentions `y`: an
/// idiom on `y` itself takes `rep : Eq(T, x, y)`; one on a term `s(y)` that
/// holds `y` (`(match s(y) as z return Π(.h : Eq(D, s(x), z)). R ..) .p`)
/// takes the proof of `Eq(D, lhs, s(y))` by a transport of `rep` whose
/// motive is generic in the proof (`Π(.q : Eq(T, x, w)). Eq(D, lhs, s(w))`,
/// the idioms on `w` inside `s` taking `q`), from the idiom's own proof of
/// `Eq(D, lhs, s(x))` (at `w = x`, its inner proofs and `q` agree by proof
/// irrelevance). `rep`, `x`, `xty` are terms at `t`'s root.
fn replace_proofs_gen(bi: IndId, t: &Tm, y: u32, rep: &Tm, x: &Tm, xty: &Tm) -> Tm {
    crate::auto::util::map_term(t, 0, &mut |node, d| {
        // a checked primitive whose operands hold `y`: each proof of its
        // obligation at `x` transported to `y` (the same construction as an
        // idiom's, the obligation in place of the idiom's equation)
        if let Term::Prim { op, args, proofs } = &**node
            && !proofs.is_empty()
            && args.iter().any(|a| count_var(a, y + d) > 0)
        {
            let (rep_d, x_d, xty_d) = (shift(rep, d as i64), shift(x, d as i64), shift(xty, d as i64));
            let args2: Vec<Tm> = args.iter().map(|a| replace_proofs_gen(bi, a, y + d, &rep_d, &x_d, &xty_d)).collect();
            // the operands under (w, q): `y` read as `w`, their proofs taking `q`
            let args_wq: Vec<Tm> = args.iter().map(|a| replace_proofs_gen(bi, &replace_var(&shift(a, 2), y + d + 2, &mk::var(1)), 1, &mk::var(0), &shift(&x_d, 2), &shift(&xty_d, 2))).collect();
            let obls = sandblaster_kernel::prim::prim_obligations(*op, &args_wq, bi);
            let q_ty = mk::eq(shift(&xty_d, 1), shift(&x_d, 1), mk::var(0));
            let proofs2: Vec<Tm> = proofs
                .iter()
                .zip(obls)
                .map(|(p_old, obl)| {
                    let mot = mk::pi("q", Rel::Irr, q_ty.clone(), obl);
                    let val = mk::lam("q", Rel::Irr, mk::eq(xty_d.clone(), x_d.clone(), x_d.clone()), shift(p_old, 1));
                    let tr = Rc::new(Term::Transport { ty: xty_d.clone(), lhs: x_d.clone(), rhs: mk::var(y + d), eq: rep_d.clone(), motive: mot, val });
                    Rc::new(Term::App { rel: Rel::Irr, fun: tr, arg: rep_d.clone() })
                })
                .collect();
            return Some(Rc::new(Term::Prim { op: *op, args: args2, proofs: proofs2 }));
        }
        let Term::App { rel: Rel::Irr, fun, arg: old_arg } = &**node else { return None };
        let Term::Match { ind, params, scrut, motive, arms } = &**fun else { return None };
        let Term::Pi { rel: Rel::Irr, dom, .. } = &**motive else { return None };
        let on_y = matches!(&**scrut, Term::Var(Idx(i)) if *i == y + d);
        if !on_y && count_var(scrut, y + d) == 0 {
            return None;
        }
        let rep_d = shift(rep, d as i64);
        let arms2: Vec<Arm> = arms
            .iter()
            .map(|a| {
                let k = d + a.names.len() as u32;
                Arm { names: a.names.clone(), body: replace_proofs_gen(bi, &a.body, y + k, &shift(rep, k as i64), &shift(x, k as i64), &shift(xty, k as i64)) }
            })
            .collect();
        if on_y {
            return Some(Rc::new(Term::App { rel: Rel::Irr, fun: Rc::new(Term::Match { ind: *ind, params: params.clone(), scrut: scrut.clone(), motive: motive.clone(), arms: arms2 }), arg: rep_d }));
        }
        // the idiom's equation `Eq(D, lhs, z)` (under the motive's `z`)
        let Term::Eq { ty: dty, lhs, .. } = &**dom else { return None };
        if count_var(lhs, 0) > 0 || count_var(dty, 0) > 0 {
            return None;
        }
        let (lhs_d, dty_d) = (shift(lhs, -1), shift(dty, -1));
        let (x_d, xty_d) = (shift(x, d as i64), shift(xty, d as i64));
        // the scrutinee under (w, q): `y` read as `w`, the idioms on `w` taking `q`
        let s2 = replace_var(&shift(scrut, 2), y + d + 2, &mk::var(1));
        let s2 = replace_proofs_gen(bi, &s2, 1, &mk::var(0), &shift(&x_d, 2), &shift(&xty_d, 2));
        let q_ty = mk::eq(shift(&xty_d, 1), shift(&x_d, 1), mk::var(0));
        let mot = mk::pi("q", Rel::Irr, q_ty, mk::eq(shift(&dty_d, 2), shift(&lhs_d, 2), s2));
        // (at `w = x`: the idiom's own proof, `Eq(D, lhs, s(x))`; its `lhs`
        // need not be `s(x)` syntactically: an earlier rewriting normalized
        // the scrutinee, not the motive)
        let val = mk::lam("q", Rel::Irr, mk::eq(xty_d.clone(), x_d.clone(), x_d.clone()), shift(old_arg, 1));
        let tr = Rc::new(Term::Transport { ty: xty_d.clone(), lhs: x_d.clone(), rhs: mk::var(y + d), eq: rep_d.clone(), motive: mot, val });
        let arg = Rc::new(Term::App { rel: Rel::Irr, fun: tr, arg: rep_d.clone() });
        let scrut2 = replace_proofs_gen(bi, scrut, y + d, &rep_d, &x_d, &xty_d);
        Some(Rc::new(Term::App { rel: Rel::Irr, fun: Rc::new(Term::Match { ind: *ind, params: params.clone(), scrut: scrut2, motive: motive.clone(), arms: arms2 }), arg }))
    })
}

/// `t` (in `ctx`) with the scrutinees of its non-projection matches on
/// `ind` that are `b` (syntactically, at their depth) replaced by a new
/// variable: a term in `(ctx, y)`. Other occurrences of `b` (arguments of
/// structured terms whose proofs are about it) are kept.
fn abstract_scrutinees(env: &Env, t: &Tm, b: &Tm, ind: IndId) -> Tm {
    let t1 = shift(t, 1);
    let b1 = shift(b, 1);
    crate::auto::util::map_term(&t1, 0, &mut |x, d| {
        let Term::Match { ind: i2, params, scrut, motive, arms } = &**x else { return None };
        if *i2 != ind || !env.alpha_eq_relevant(scrut, &shift(&b1, d as i64), &|p, q| p == q) {
            return None;
        }
        let nf = arms.first().map(|a| a.names.len() as u32).unwrap_or(0);
        let projection = arms.len() == 1 && matches!(&*arms[0].body, Term::Var(Idx(k)) if *k < nf);
        if projection {
            return None;
        }
        Some(Rc::new(Term::Match { ind: *i2, params: params.clone(), scrut: mk::var(d), motive: motive.clone(), arms: arms.iter().map(|a| Arm { names: a.names.clone(), body: a.body.clone() }).collect() }))
    })
}

/// Whether a value may mention the global `g` as a neutral's head (a stuck
/// match, whose arms are closures, counts as a maybe).
fn value_mentions_global(v: &V, g: GlobalId) -> bool {
    fn go(v: &V, g: GlobalId, seen: &mut std::collections::HashSet<*const Value>, fuel: &mut u32) -> bool {
        *fuel += 1;
        if *fuel > 200_000 || !seen.insert(Rc::as_ptr(v)) {
            return *fuel > 200_000;
        }
        match &**v {
            Value::Neu(n) => {
                let head = match &n.head {
                    Head::Global { def, args } => *def == g || args.iter().any(|a| matches!(a, Arg::Rel(x) if go(x, g, seen, fuel))),
                    Head::Prim { args, .. } => args.iter().any(|x| go(x, g, seen, fuel)),
                    _ => false,
                };
                // (a stuck match's arms are closures: the call may be inside)
                head || n.spine.iter().any(|e| match e {
                    Elim::App(Arg::Rel(x)) => go(x, g, seen, fuel),
                    Elim::Match { .. } => true,
                    _ => false,
                })
            }
            Value::Ctor { args, .. } => args.iter().any(|a| matches!(a, Arg::Rel(x) if go(x, g, seen, fuel))),
            _ => true,
        }
    }
    go(v, g, &mut std::collections::HashSet::new(), &mut 0)
}

/// Whether `t` holds a dependent-match idiom whose scrutinee is the variable `y`.
fn has_idiom_on(t: &Tm, y: u32) -> bool {
    let mut found = false;
    crate::auto::util::map_term(t, 0, &mut |x, d| {
        if !found
            && let Term::App { rel: Rel::Irr, fun, .. } = &**x
            && let Term::Match { scrut, motive, .. } = &**fun
            && matches!(&**scrut, Term::Var(Idx(i)) if *i == y + d)
            && matches!(&**motive, Term::Pi { rel: Rel::Irr, .. })
        {
            found = true;
        }
        None
    });
    found
}

/// `t` with every dependent-match idiom on the variable `y` (an abstracted
/// test `c`) requalified: its equation's left side `c` again (its arms'
/// proofs are about `c`, as a callee's precondition), its proof `q`
/// (`c` and `q` terms at `t`'s root). The idiom `(match y as z return
/// Π(.e : Eq(D, c, z)). R ..) .q` is well-typed for `q : Eq(D, c, y)`.
fn requalify(t: &Tm, y: u32, c: &Tm, q: &Tm) -> Tm {
    crate::auto::util::map_term(t, 0, &mut |x, d| {
        let Term::App { rel: Rel::Irr, fun, .. } = &**x else { return None };
        let Term::Match { ind, params, scrut, motive, arms } = &**fun else { return None };
        if !matches!(&**scrut, Term::Var(Idx(i)) if *i == y + d) {
            return None;
        }
        let Term::Pi { name: mn, rel: Rel::Irr, dom, cod } = &**motive else { return None };
        let Term::Eq { ty: ety, rhs: erhs, .. } = &**dom else { return None };
        let motive2 = Rc::new(Term::Pi { name: mn.clone(), rel: Rel::Irr, dom: Rc::new(Term::Eq { ty: ety.clone(), lhs: shift(c, d as i64 + 1), rhs: erhs.clone() }), cod: requalify(cod, y + d + 2, c, &shift(q, d as i64 + 2)) });
        let arms2: Vec<Arm> = arms
            .iter()
            .map(|a| {
                let nf = a.names.len() as u32;
                let body = match &*a.body {
                    Term::Lam { name, rel: Rel::Irr, dom, body } => match &**dom {
                        Term::Eq { ty, rhs, .. } => Rc::new(Term::Lam { name: name.clone(), rel: Rel::Irr, dom: Rc::new(Term::Eq { ty: ty.clone(), lhs: shift(c, (d + nf) as i64), rhs: rhs.clone() }), body: requalify(body, y + d + nf + 1, &shift(c, (d + nf + 1) as i64), &shift(q, (d + nf + 1) as i64)) }),
                        _ => a.body.clone(),
                    },
                    _ => requalify(&a.body, y + d + nf, &shift(c, (d + nf) as i64), &shift(q, (d + nf) as i64)),
                };
                Arm { names: a.names.clone(), body }
            })
            .collect();
        let params2 = params.iter().map(|p| requalify(p, y + d, &shift(c, d as i64), &shift(q, d as i64))).collect();
        Some(Rc::new(Term::App { rel: Rel::Irr, fun: Rc::new(Term::Match { ind: *ind, params: params2, scrut: scrut.clone(), motive: motive2, arms: arms2 }), arg: shift(q, d as i64) }))
    })
}

/// `t` over `(ctx, y, q)` at `y := v`, `q := p` (terms over `ctx`).
fn inst_yq(t: &Tm, v: &Tm, p: &Tm) -> Tm {
    crate::auto::util::map_term(t, 0, &mut |x, d| {
        let Term::Var(Idx(i)) = &**x else { return None };
        if *i < d {
            None
        } else if *i == d {
            Some(shift(p, d as i64))
        } else if *i == d + 1 {
            Some(shift(v, d as i64))
        } else {
            Some(mk::var(*i - 2))
        }
    })
}

/// `t` over `(ctx, y, q)` in an arm `(ctx, f̄ (nf fields), e)`: `y := v` (a
/// term over `(ctx, f̄)`), `q := e`.
fn inst_yq_arm(t: &Tm, nf: u32, v: &Tm) -> Tm {
    crate::auto::util::map_term(t, 0, &mut |x, d| {
        let Term::Var(Idx(i)) = &**x else { return None };
        if *i <= d {
            None
        } else if *i == d + 1 {
            Some(shift(v, d as i64 + 1))
        } else {
            Some(mk::var(*i + nf - 1))
        }
    })
}

/// [`has_erased_pair`], memoized per node.
fn has_erased_memo(t: &Tm, memo: &mut std::collections::HashMap<*const Term, bool>) -> bool {
    if let Some(b) = memo.get(&Rc::as_ptr(t)) {
        return *b;
    }
    let mut h = |x: &Tm| has_erased_memo(x, memo);
    let r = match &**t {
        Term::Pair { ty, fst, snd } => matches!(&**ty, Term::Erased) || h(ty) || h(fst) || h(snd),
        Term::Pi { dom, cod, .. } => h(dom) || h(cod),
        Term::Lam { dom, body, .. } => h(dom) || h(body),
        Term::App { fun, arg, .. } => h(fun) || h(arg),
        Term::Let { ty, val, body, .. } => h(ty) || h(val) || h(body),
        Term::Sigma { fst, snd, .. } => h(fst) || h(snd),
        Term::Fst(x) | Term::Snd(x) => h(x),
        Term::Eq { ty, lhs, rhs } | Term::BvRefl { ty, lhs, rhs } => h(ty) || h(lhs) || h(rhs),
        Term::Refl { ty, val } => h(ty) || h(val),
        Term::Transport { ty, lhs, rhs, eq, motive, val } => h(ty) || h(lhs) || h(rhs) || h(eq) || h(motive) || h(val),
        Term::Ind { params, .. } => params.iter().any(h),
        Term::Ctor { params, args, .. } => params.iter().any(&mut h) || args.iter().any(&mut h),
        Term::Match { params, scrut, motive, arms, .. } => params.iter().any(&mut h) || h(scrut) || h(motive) || arms.iter().any(|a| h(&a.body)),
        Term::Prim { args, proofs, .. } => args.iter().any(&mut h) || proofs.iter().any(&mut h),
        Term::Rec { args, proof } => args.iter().any(&mut h) || proof.as_ref().is_some_and(&mut h),
        Term::Delta { args, .. } | Term::Axiom { args, .. } => args.iter().any(&mut h),
        Term::Unfold { args, val, .. } => args.iter().any(&mut h) || h(val),
        Term::Linarith { hyps, goal, .. } => hyps.iter().any(|(p, ty)| h(p) || h(ty)) || h(goal),
        Term::Absurd { ty, proof } => h(ty) || h(proof),
        _ => false,
    };
    memo.insert(Rc::as_ptr(t), r);
    r
}

/// Whether `t` holds a pair of an erased type.
fn has_erased_pair(t: &Tm) -> bool {
    let mut f = false;
    crate::auto::util::map_term(t, 0, &mut |x, _| {
        if f {
            return Some(x.clone());
        }
        if matches!(&**x, Term::Pair { ty, .. } if matches!(&**ty, Term::Erased)) {
            f = true;
        }
        None
    });
    f
}

/// Whether `t` is a match of the dependent idiom `(match c as y return
/// Π(.e : Eq(D, c, y)). R with ..) .p`.
fn is_idiom(t: &Tm) -> bool {
    matches!(&**t, Term::App { rel: Rel::Irr, fun, .. } if matches!(&**fun, Term::Match { motive, .. } if matches!(&**motive, Term::Pi { rel: Rel::Irr, .. })))
}

/// Rebuilds `t` calling `f` at each match of the dependent idiom outside
/// binders, in evaluation order (a match after the matches of its
/// scrutinee; a let's value, not its body; arguments left to right).
fn idiom_map(t: &Tm, f: &mut dyn FnMut(&Tm) -> Option<Tm>) -> Tm {
    match &**t {
        Term::App { rel: Rel::Irr, fun, arg } if is_idiom(t) => {
            let Term::Match { ind, params, scrut, motive, arms } = &**fun else { unreachable!() };
            let scrut2 = idiom_map(scrut, f);
            let node = if Rc::ptr_eq(&scrut2, scrut) { t.clone() } else { Rc::new(Term::App { rel: Rel::Irr, fun: Rc::new(Term::Match { ind: *ind, params: params.clone(), scrut: scrut2, motive: motive.clone(), arms: clone_arms(arms) }), arg: arg.clone() }) };
            f(&node).unwrap_or(node)
        }
        Term::App { rel, fun, arg } => {
            let fun2 = idiom_map(fun, f);
            let arg2 = if *rel == Rel::Rel { idiom_map(arg, f) } else { arg.clone() };
            if Rc::ptr_eq(&fun2, fun) && Rc::ptr_eq(&arg2, arg) { t.clone() } else { Rc::new(Term::App { rel: *rel, fun: fun2, arg: arg2 }) }
        }
        Term::Ctor { ind, ctor, params, args } => {
            let args2: Vec<Tm> = args.iter().map(|a| idiom_map(a, f)).collect();
            if args2.iter().zip(args).all(|(a, b)| Rc::ptr_eq(a, b)) { t.clone() } else { Rc::new(Term::Ctor { ind: *ind, ctor: *ctor, params: params.clone(), args: args2 }) }
        }
        Term::Prim { op, args, proofs } => {
            let args2: Vec<Tm> = args.iter().map(|a| idiom_map(a, f)).collect();
            if args2.iter().zip(args).all(|(a, b)| Rc::ptr_eq(a, b)) { t.clone() } else { Rc::new(Term::Prim { op: *op, args: args2, proofs: proofs.clone() }) }
        }
        Term::Let { name, rel: Rel::Rel, ty, val, body } => {
            let val2 = idiom_map(val, f);
            if Rc::ptr_eq(&val2, val) { t.clone() } else { Rc::new(Term::Let { name: name.clone(), rel: Rel::Rel, ty: ty.clone(), val: val2, body: body.clone() }) }
        }
        Term::Pair { ty, fst, snd } => {
            let a = idiom_map(fst, f);
            let b = idiom_map(snd, f);
            if Rc::ptr_eq(&a, fst) && Rc::ptr_eq(&b, snd) { t.clone() } else { Rc::new(Term::Pair { ty: ty.clone(), fst: a, snd: b }) }
        }
        Term::Fst(x) => {
            let y = idiom_map(x, f);
            if Rc::ptr_eq(&y, x) { t.clone() } else { Rc::new(Term::Fst(y)) }
        }
        Term::Snd(x) => {
            let y = idiom_map(x, f);
            if Rc::ptr_eq(&y, x) { t.clone() } else { Rc::new(Term::Snd(y)) }
        }
        Term::Match { ind, params, scrut, motive, arms } => {
            let scrut2 = idiom_map(scrut, f);
            if Rc::ptr_eq(&scrut2, scrut) { t.clone() } else { Rc::new(Term::Match { ind: *ind, params: params.clone(), scrut: scrut2, motive: motive.clone(), arms: clone_arms(arms) }) }
        }
        _ => t.clone(),
    }
}

fn clone_arms(arms: &[Arm]) -> Vec<Arm> {
    arms.iter().map(|a| Arm { names: a.names.clone(), body: a.body.clone() }).collect()
}

/// Whether `t` mentions the global `g` (a recursive definition's body).
fn refers_to(t: &Tm, g: GlobalId) -> bool {
    let mut found = false;
    crate::auto::util::map_term(t, 0, &mut |x, _| {
        if matches!(&**x, Term::Global(h) if *h == g) {
            found = true;
        }
        None
    });
    found
}

/// The `k`-th match of the idiom in evaluation order.
fn nth_idiom(t: &Tm, k: usize) -> Option<Tm> {
    let mut i = 0usize;
    let mut out = None;
    idiom_map(t, &mut |n| {
        if i == k {
            out = Some(n.clone());
        }
        i += 1;
        None
    });
    out
}

/// `t` with its `k`-th match of the idiom replaced by `r`.
fn replace_nth_idiom(t: &Tm, k: usize, r: &Tm) -> Tm {
    let mut i = 0usize;
    idiom_map(t, &mut |_| {
        let hit = i == k;
        i += 1;
        if hit { Some(r.clone()) } else { None }
    })
}

/// Wraps the transports of [`Walker::advance`] around a proof.
/// Facts from a proof `p` of `ty`: an equation, or the components of a
/// non-dependent pair of them (recursively).
fn sigma_facts_w(p: Tm, ty: &Tm, out: &mut Vec<Fact>) {
    match &**ty {
        Term::Eq { .. } => out.push(Fact { reused: true, ..Fact::eq(p, ty.clone()) }),
        Term::Sigma { fst, snd, .. } if count_var(snd, 0) == 0 => {
            sigma_facts_w(Rc::new(Term::Fst(p.clone())), fst, out);
            sigma_facts_w(Rc::new(Term::Snd(p)), &shift(snd, -1), out);
        }
        _ => {}
    }
}

/// A fixed-length array type `Σ(l : List T). .Eq(Int, len T l, N)`: (T, N).
fn array_ty(env: &Env, t: &Tm) -> Option<(Tm, u32)> {
    use num_traits::ToPrimitive;
    let Term::Sigma { fst, snd, .. } = &**t else { return None };
    let Term::Ind { ind, params } = &**fst else { return None };
    if Some(*ind) != env.lookup_ind("List") || params.len() != 1 {
        return None;
    }
    let Term::Eq { rhs, .. } = &**snd else { return None };
    let Term::Lit { n, .. } = &**rhs else { return None };
    let n = n.to_u32()?;
    (n <= 256).then(|| (params[0].clone(), n))
}

/// The first differing subterms of two terms (debugging): descends
/// through equal heads (constructors, applications, primitives, matches).
fn first_diff(env: &Env, a: &Tm, b: &Tm, out: &mut Vec<(Tm, Tm)>) {
    if out.len() >= 3 || env.alpha_eq_relevant(a, b, &|x, y| x == y) {
        return;
    }
    match (&**a, &**b) {
        (Term::Ctor { ind: i1, ctor: c1, args: a1, .. }, Term::Ctor { ind: i2, ctor: c2, args: a2, .. }) if i1 == i2 && c1 == c2 && a1.len() == a2.len() => {
            for (x, y) in a1.iter().zip(a2) {
                first_diff(env, x, y, out);
            }
        }
        (Term::App { fun: f1, arg: x1, rel: r1 }, Term::App { fun: f2, arg: x2, rel: r2 }) if r1 == r2 => {
            first_diff(env, f1, f2, out);
            if *r1 == Rel::Rel {
                first_diff(env, x1, x2, out);
            }
        }
        (Term::Prim { op: o1, args: a1, .. }, Term::Prim { op: o2, args: a2, .. }) if o1 == o2 && a1.len() == a2.len() => {
            for (x, y) in a1.iter().zip(a2) {
                first_diff(env, x, y, out);
            }
        }
        (Term::Match { ind: i1, scrut: s1, arms: m1, .. }, Term::Match { ind: i2, scrut: s2, arms: m2, .. }) if i1 == i2 && m1.len() == m2.len() => {
            first_diff(env, s1, s2, out);
            for (x, y) in m1.iter().zip(m2) {
                first_diff(env, &x.body, &y.body, out);
            }
        }
        (Term::Fst(x), Term::Fst(y)) | (Term::Snd(x), Term::Snd(y)) => first_diff(env, x, y, out),
        (Term::Pair { fst: f1, snd: s1, .. }, Term::Pair { fst: f2, snd: s2, .. }) => {
            first_diff(env, f1, f2, out);
            first_diff(env, s1, s2, out);
        }
        _ => out.push((a.clone(), b.clone())),
    }
}

fn wrap(wraps: Vec<Tm>, inner: Tm) -> Tm {
    let mut p = inner;
    for w in wraps.into_iter().rev() {
        p = match &*w {
            Term::Transport { ty, lhs, rhs, eq, motive, .. } => Rc::new(Term::Transport { ty: ty.clone(), lhs: lhs.clone(), rhs: rhs.clone(), eq: eq.clone(), motive: motive.clone(), val: p }),
            // a transport over an idiom's test and its proof `q`: `(transport
            // .. (λ .q. [·])) .refl` (the inner proof does not mention `q`)
            Term::App { rel: Rel::Irr, fun, arg } => {
                let Term::Transport { ty, lhs, rhs, eq, motive, val } = &**fun else { unreachable!() };
                let Term::Lam { name, rel, dom, .. } = &**val else { unreachable!() };
                let lam = Rc::new(Term::Lam { name: name.clone(), rel: *rel, dom: dom.clone(), body: shift(&p, 1) });
                Rc::new(Term::App { rel: Rel::Irr, fun: Rc::new(Term::Transport { ty: ty.clone(), lhs: lhs.clone(), rhs: rhs.clone(), eq: eq.clone(), motive: motive.clone(), val: lam }), arg: arg.clone() })
            }
            _ => unreachable!(),
        };
    }
    p
}

/// `t` (in `(ctx, y)`) at `y := v` with `v` in `(ctx, <k binders>)`.
fn inst0_under(t: &Tm, k: u32, v: &Tm) -> Tm {
    crate::auto::util::map_term(t, 0, &mut |x, d| match &**x {
        Term::Var(Idx(i)) if *i == d => Some(shift(v, d as i64)),
        Term::Var(Idx(i)) if *i > d => Some(mk::var(*i - 1 + k)),
        _ => None,
    })
}

/// `t` without its outer relevant `let`s (each value substituted).
fn peel_lets(t: &Tm) -> Tm {
    let mut cur = t.clone();
    while let Term::Let { rel: Rel::Rel, val, body, .. } = &*cur.clone() {
        cur = crate::elab::tm::subst0(body, val);
    }
    cur
}

/// `t` with every free occurrence of `Var(k)` replaced by `v`.
fn replace_var(t: &Tm, k: u32, v: &Tm) -> Tm {
    crate::auto::util::map_term(t, 0, &mut |x, d| match &**x {
        Term::Var(Idx(i)) if *i == k + d => Some(shift(v, d as i64)),
        _ => None,
    })
}

/// How many times `Var k` occurs free in `t`.
fn count_var(t: &Tm, k: u32) -> usize {
    let mut n = 0;
    crate::auto::util::map_term(t, 0, &mut |x, d| {
        if let Term::Var(Idx(i)) = &**x
            && *i == k + d
        {
            n += 1;
        }
        None
    });
    n
}

/// Whether `t` holds a recursive call (`Rec`).
fn has_rec(t: &Tm) -> bool {
    let mut found = false;
    crate::auto::util::map_term(t, 0, &mut |x, _| {
        if matches!(&**x, Term::Rec { .. }) {
            found = true;
        }
        if found { Some(x.clone()) } else { None }
    });
    found
}

/// The calls of the fuel functions `fs` (each with its arity) in `t` whose
/// arguments mention no binder of `t` (as terms outside `t`), deduplicated.
fn fuel_calls(env: &Env, t: &Tm, fs: &[(GlobalId, usize)], out: &mut Vec<(GlobalId, Vec<(Rel, Tm)>)>) {
    // (`let`s inlined: a need's calls are about its `let`s' values)
    fn zeta(t: &Tm) -> Tm {
        crate::auto::util::map_term(t, 0, &mut |x, _| match &**x {
            Term::Let { val, body, .. } => Some(zeta(&crate::elab::tm::subst0(body, val))),
            _ => None,
        })
    }
    crate::auto::util::map_term(&zeta(t), 0, &mut |x, d| {
        let (g, args) = app_spine(x)?;
        if !fs.iter().any(|(f, n)| *f == g && *n == args.len()) || (0..d).any(|k| count_var(x, k) > 0) {
            return None;
        }
        let args: Vec<(Rel, Tm)> = args.iter().map(|(r, a)| (*r, shift(a, -(d as i64)))).collect();
        if !out.iter().any(|(g2, a2)| *g2 == g && a2.len() == args.len() && a2.iter().zip(&args).all(|(p, q)| p.0 != Rel::Rel || env.alpha_eq_relevant(&p.1, &q.1, &|a, b| a == b))) {
            out.push((g, args));
        }
        Some(x.clone())
    });
}

/// The head global and arguments of an application spine.
pub fn app_spine(t: &Tm) -> Option<(GlobalId, Vec<(Rel, Tm)>)> {
    let mut args = Vec::new();
    let mut cur = t.clone();
    loop {
        let next = match &*cur {
            Term::App { rel, fun, arg } => {
                args.push((*rel, arg.clone()));
                fun.clone()
            }
            Term::Global(g) => {
                args.reverse();
                return Some((*g, args));
            }
            _ => return None,
        };
        cur = next;
    }
}

type PrimFact = (Tm, Tm, Option<(PrimOp, Tm, Tm)>);

/// The checked primitives of `t` outside binders, with their obligations
/// (and, for `+ - *`, the operation: a bridge).
fn collect_prims(env: &Env, t: &Tm, out: &mut Vec<PrimFact>) {
    collect_prims_d(env, t, out, 2);
}

fn collect_prims_d(env: &Env, t: &Tm, out: &mut Vec<PrimFact>, depth: u32) {
    let bi = env.bool_ind();
    // a call of a transparent function: the checked primitives of its body
    // at the call's arguments (their proofs are the callee's, instantiated)
    if depth > 0
        && let Some((g, args)) = app_spine(t)
        && env.global_opaque(g) == Some(false)
        && env.global_kind(g) == Some(sandblaster_kernel::term::DefKind::Exec)
        && env.global_arity(g).is_some_and(|a| a as usize == args.len() && a > 0)
        && let Some(body) = env.global_body(g)
        && !refers_to(&body, g)
    {
        let mut b = body;
        let mut ok = true;
        for _ in 0..args.len() {
            match &*b.clone() {
                Term::Lam { body: bb, .. } => b = bb.clone(),
                _ => {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            let vals: Vec<Tm> = args.iter().map(|(_, a)| a.clone()).collect();
            let inst = crate::opt::proof::steps::subst_n(&b, &vals);
            collect_prims_d(env, &inst, out, depth - 1);
        }
    }
    match &**t {
        Term::Prim { op, args, proofs } => {
            if !proofs.is_empty() {
                let obs = sandblaster_kernel::prim::prim_obligations(*op, args, bi);
                let br = match op {
                    PrimOp::Add(_) | PrimOp::Sub(_) | PrimOp::Mul(_) if args.len() == 2 => Some((*op, args[0].clone(), args[1].clone())),
                    _ => None,
                };
                for (p, o) in proofs.iter().zip(obs) {
                    out.push((p.clone(), o, br.clone()));
                }
            }
            for a in args {
                collect_prims_d(env, a, out, depth);
            }
        }
        Term::App { fun, arg, rel } => {
            collect_prims_d(env, fun, out, depth);
            if *rel == Rel::Rel {
                collect_prims_d(env, arg, out, depth);
            }
        }
        Term::Ctor { args, .. } => args.iter().for_each(|a| collect_prims_d(env, a, out, depth)),
        Term::Pair { fst, snd, .. } => {
            collect_prims_d(env, fst, out, depth);
            collect_prims_d(env, snd, out, depth);
        }
        Term::Fst(x) | Term::Snd(x) => collect_prims_d(env, x, out, depth),
        Term::Match { scrut, .. } => collect_prims_d(env, scrut, out, depth),
        Term::Let { val, body, rel, .. } => {
            collect_prims_d(env, val, out, depth);
            if *rel == Rel::Rel {
                collect_prims_d(env, &crate::elab::tm::subst0(body, val), out, depth);
            }
        }
        _ => {}
    }
}

/// `t` with every `let` replaced by its value alone (the checked
/// primitives outside the `let`s' bodies).
fn strip_lets(t: &Tm) -> Tm {
    crate::auto::util::map_term(t, 0, &mut |x, _| match &**x {
        Term::Let { val, .. } => Some(strip_lets(val)),
        _ => None,
    })
}

/// The calls of lifted functions (with lemmas) in `t`, outside binders.
fn collect_calls(t: &Tm, callees: &[Callee], out: &mut Vec<(GlobalId, Vec<(Rel, Tm)>)>) {
    if let Some((g, args)) = app_spine(t)
        && callees.iter().any(|c| c.s_global == g && c.rels.len() == args.len())
    {
        out.push((g, args.clone()));
        return;
    }
    match &**t {
        Term::App { fun, arg, rel } => {
            collect_calls(fun, callees, out);
            if *rel == Rel::Rel {
                collect_calls(arg, callees, out);
            }
        }
        Term::Ctor { args, .. } => args.iter().for_each(|a| collect_calls(a, callees, out)),
        Term::Match { scrut, .. } => collect_calls(scrut, callees, out),
        Term::Fst(x) | Term::Snd(x) => collect_calls(x, callees, out),
        Term::Prim { args, .. } => args.iter().for_each(|a| collect_calls(a, callees, out)),
        _ => {}
    }
}

/// The self-calls (`Rec`, with their decrease proofs) of a pre-commit term
/// outside binders (a let's value, a scrutinee, arguments).
fn collect_recs(t: &Tm, out: &mut Vec<(Vec<Tm>, Tm)>) {
    match &**t {
        Term::Rec { args, proof: Some(p) } => {
            if !out.iter().any(|(a, _)| a.len() == args.len() && a.iter().zip(args).all(|(x, y)| Rc::ptr_eq(x, y))) {
                out.push((args.clone(), p.clone()));
            }
        }
        Term::App { fun, arg, rel } => {
            collect_recs(fun, out);
            if *rel == Rel::Rel {
                collect_recs(arg, out);
            }
        }
        Term::Ctor { args, .. } | Term::Prim { args, .. } => args.iter().for_each(|a| collect_recs(a, out)),
        Term::Match { scrut, .. } => collect_recs(scrut, out),
        Term::Fst(x) | Term::Snd(x) => collect_recs(x, out),
        Term::Pair { fst, snd, .. } => {
            collect_recs(fst, out);
            collect_recs(snd, out);
        }
        _ => {}
    }
}

/// The proofs passed to calls in `t` (outside binders) with their types
/// (the callee's parameter types at the call's arguments).
fn collect_call_proofs(env: &Env, t: &Tm, out: &mut Vec<(Tm, Tm)>) {
    if let Some((g, args)) = app_spine(t)
        && args.iter().any(|(r, _)| *r == Rel::Irr)
        && let Some(gty) = env.global_type(g)
    {
        let mut cur = gty;
        let mut prev: Vec<Tm> = Vec::new();
        for (r, a) in &args {
            let Term::Pi { dom, cod, .. } = &*cur else { break };
            if *r == Rel::Irr {
                out.push((a.clone(), crate::opt::proof::steps::subst_n(dom, &prev)));
            }
            prev.push(a.clone());
            cur = cod.clone();
        }
    }
    match &**t {
        Term::App { fun, arg, rel } => {
            collect_call_proofs(env, fun, out);
            if *rel == Rel::Rel {
                collect_call_proofs(env, arg, out);
            }
        }
        Term::Ctor { args, .. } => args.iter().for_each(|a| collect_call_proofs(env, a, out)),
        Term::Match { scrut, .. } => collect_call_proofs(env, scrut, out),
        Term::Fst(x) | Term::Snd(x) => collect_call_proofs(env, x, out),
        Term::Prim { args, .. } => args.iter().for_each(|a| collect_call_proofs(env, a, out)),
        Term::Let { val, rel: Rel::Rel, body, .. } => {
            collect_call_proofs(env, val, out);
            // (the body with the value substituted: its calls are the same calls)
            collect_call_proofs(env, &crate::elab::tm::subst0(body, val), out);
        }
        _ => {}
    }
}

fn width_name(w: Width) -> &'static str {
    match w {
        Width::U8 => "u8",
        Width::U16 => "u16",
        Width::U32 => "u32",
        Width::U64 => "u64",
        _ => "usize",
    }
}

/// Where the nodes of a proof are (`CS_PROFILE`, debugging): distinct nodes
/// reachable from transport and match motives, from absurd types, from the
/// rest (counted once each, by pointer); and the number of structurally
/// distinct nodes (after hash-consing).
pub fn profile(t: &Tm) -> String {
    use std::collections::HashSet;
    fn walk(t: &Tm, seen: &mut HashSet<*const Term>, cat: usize, counts: &mut [usize; 3]) {
        if !seen.insert(Rc::as_ptr(t)) {
            return;
        }
        counts[cat] += 1;
        let mut go = |x: &Tm, c: usize| walk(x, seen, c, counts);
        match &**t {
            Term::Var(_) | Term::Global(_) | Term::Sort(_) | Term::IntTy(_) | Term::Lit { .. } | Term::Erased => {}
            Term::Pi { dom, cod, .. } => { go(dom, cat); go(cod, cat); }
            Term::Lam { dom, body, .. } => { go(dom, cat); go(body, cat); }
            Term::App { fun, arg, .. } => { go(fun, cat); go(arg, cat); }
            Term::Let { ty, val, body, .. } => { go(ty, cat); go(val, cat); go(body, cat); }
            Term::Sigma { fst, snd, .. } => { go(fst, cat); go(snd, cat); }
            Term::Pair { ty, fst, snd } => { go(ty, cat); go(fst, cat); go(snd, cat); }
            Term::Fst(x) | Term::Snd(x) => go(x, cat),
            Term::Eq { ty, lhs, rhs } => { go(ty, cat); go(lhs, cat); go(rhs, cat); }
            Term::Refl { ty, val } => { go(ty, cat); go(val, cat); }
            Term::Transport { ty, lhs, rhs, eq, motive, val } => { go(motive, 1); go(ty, cat); go(lhs, cat); go(rhs, cat); go(eq, cat); go(val, cat); }
            Term::Ind { params, .. } => params.iter().for_each(|p| go(p, cat)),
            Term::Ctor { params, args, .. } => { params.iter().for_each(|p| go(p, cat)); args.iter().for_each(|a| go(a, cat)); }
            Term::Match { params, scrut, motive, arms, .. } => { go(motive, 1); params.iter().for_each(|p| go(p, cat)); go(scrut, cat); arms.iter().for_each(|a| go(&a.body, cat)); }
            Term::Prim { args, proofs, .. } => { args.iter().for_each(|a| go(a, cat)); proofs.iter().for_each(|p| go(p, cat)); }
            Term::Rec { args, proof } => { args.iter().for_each(|a| go(a, cat)); if let Some(p) = proof { go(p, cat); } }
            Term::Delta { args, .. } => args.iter().for_each(|a| go(a, cat)),
            Term::Unfold { args, val, .. } => { args.iter().for_each(|a| go(a, cat)); go(val, cat); }
            Term::Linarith { hyps, goal, .. } => { hyps.iter().for_each(|(p, s)| { go(p, cat); go(s, cat); }); go(goal, cat); }
            Term::BvRefl { ty, lhs, rhs } => { go(ty, cat); go(lhs, cat); go(rhs, cat); }
            Term::Absurd { ty, proof } => { go(ty, 2); go(proof, cat); }
            Term::Axiom { args, .. } => args.iter().for_each(|a| go(a, cat)),
        }
    }
    let mut seen = HashSet::new();
    let mut counts = [0usize; 3];
    walk(t, &mut seen, 0, &mut counts);
    let hc = hashcons(t);
    let mut seen2 = HashSet::new();
    let mut c2 = [0usize; 3];
    walk(&hc, &mut seen2, 0, &mut c2);
    format!("distinct nodes {} (motives {}, absurd types {}, rest {}); hash-consed {} (motives {}, absurd types {}, rest {})", counts.iter().sum::<usize>(), counts[1], counts[2], counts[0], c2.iter().sum::<usize>(), c2[1], c2[2], c2[0])
}

/// The term with structurally equal subterms shared (one node each).
pub fn hashcons(t: &Tm) -> Tm {
    use std::collections::HashMap;
    struct H {
        memo: HashMap<*const Term, Tm>,
        table: HashMap<String, Tm>,
    }
    fn p(t: &Tm) -> usize {
        Rc::as_ptr(t) as *const () as usize
    }
    impl H {
        fn go(&mut self, t: &Tm) -> Tm {
            if let Some(r) = self.memo.get(&Rc::as_ptr(t)) {
                return r.clone();
            }
            let mut g = |x: &Tm| self.go(x);
            let node: Term = match &**t {
                Term::Var(_) | Term::Global(_) | Term::Sort(_) | Term::IntTy(_) | Term::Lit { .. } | Term::Erased => {
                    let key = format!("{:?}", t);
                    let r = self.table.entry(key).or_insert_with(|| t.clone()).clone();
                    self.memo.insert(Rc::as_ptr(t), r.clone());
                    return r;
                }
                Term::Pi { name, rel, dom, cod } => Term::Pi { name: name.clone(), rel: *rel, dom: g(dom), cod: g(cod) },
                Term::Lam { name, rel, dom, body } => Term::Lam { name: name.clone(), rel: *rel, dom: g(dom), body: g(body) },
                Term::App { rel, fun, arg } => Term::App { rel: *rel, fun: g(fun), arg: g(arg) },
                Term::Let { name, rel, ty, val, body } => Term::Let { name: name.clone(), rel: *rel, ty: g(ty), val: g(val), body: g(body) },
                Term::Sigma { name, snd_rel, fst, snd } => Term::Sigma { name: name.clone(), snd_rel: *snd_rel, fst: g(fst), snd: g(snd) },
                Term::Pair { ty, fst, snd } => Term::Pair { ty: g(ty), fst: g(fst), snd: g(snd) },
                Term::Fst(x) => Term::Fst(g(x)),
                Term::Snd(x) => Term::Snd(g(x)),
                Term::Eq { ty, lhs, rhs } => Term::Eq { ty: g(ty), lhs: g(lhs), rhs: g(rhs) },
                Term::Refl { ty, val } => Term::Refl { ty: g(ty), val: g(val) },
                Term::Transport { ty, lhs, rhs, eq, motive, val } => Term::Transport { ty: g(ty), lhs: g(lhs), rhs: g(rhs), eq: g(eq), motive: g(motive), val: g(val) },
                Term::Ind { ind, params } => Term::Ind { ind: *ind, params: params.iter().map(&mut g).collect() },
                Term::Ctor { ind, ctor, params, args } => Term::Ctor { ind: *ind, ctor: *ctor, params: params.iter().map(&mut g).collect(), args: args.iter().map(&mut g).collect() },
                Term::Match { ind, params, scrut, motive, arms } => Term::Match { ind: *ind, params: params.iter().map(&mut g).collect(), scrut: g(scrut), motive: g(motive), arms: arms.iter().map(|a| Arm { names: a.names.clone(), body: g(&a.body) }).collect() },
                Term::Prim { op, args, proofs } => Term::Prim { op: *op, args: args.iter().map(&mut g).collect(), proofs: proofs.iter().map(&mut g).collect() },
                Term::Rec { args, proof } => Term::Rec { args: args.iter().map(&mut g).collect(), proof: proof.as_ref().map(&mut g) },
                Term::Delta { def, args } => Term::Delta { def: *def, args: args.iter().map(&mut g).collect() },
                Term::Unfold { def, args, to_body, val } => Term::Unfold { def: *def, args: args.iter().map(&mut g).collect(), to_body: *to_body, val: g(val) },
                Term::Linarith { hyps, goal, cert } => Term::Linarith { hyps: hyps.iter().map(|(a, b)| (g(a), g(b))).collect(), goal: g(goal), cert: cert.clone() },
                Term::BvRefl { ty, lhs, rhs } => Term::BvRefl { ty: g(ty), lhs: g(lhs), rhs: g(rhs) },
                Term::Absurd { ty, proof } => Term::Absurd { ty: g(ty), proof: g(proof) },
                Term::Axiom { ax, args } => Term::Axiom { ax: *ax, args: args.iter().map(&mut g).collect() },
            };
            // the key: the node's own data with its children's (canonical) addresses
            let key = shallow_key(&node);
            let r = match self.table.get(&key) {
                Some(r) => r.clone(),
                None => {
                    let r = Rc::new(node);
                    self.table.insert(key, r.clone());
                    r
                }
            };
            self.memo.insert(Rc::as_ptr(t), r.clone());
            r
        }
    }
    fn shallow_key(n: &Term) -> String {
        use std::fmt::Write;
        let mut k = String::new();
        fn c(k: &mut String, x: &Tm) {
            let _ = write!(k, ",{:x}", p(x));
        }
        let cs = |k: &mut String, xs: &[Tm]| xs.iter().for_each(|x| c(k, x));
        let head = match n {
            Term::Pi { name, rel, dom, cod } => { c(&mut k, dom); c(&mut k, cod); format!("Pi{name}{rel:?}") }
            Term::Lam { name, rel, dom, body } => { c(&mut k, dom); c(&mut k, body); format!("Lam{name}{rel:?}") }
            Term::App { rel, fun, arg } => { c(&mut k, fun); c(&mut k, arg); format!("App{rel:?}") }
            Term::Let { name, rel, ty, val, body } => { c(&mut k, ty); c(&mut k, val); c(&mut k, body); format!("Let{name}{rel:?}") }
            Term::Sigma { name, snd_rel, fst, snd } => { c(&mut k, fst); c(&mut k, snd); format!("Sig{name}{snd_rel:?}") }
            Term::Pair { ty, fst, snd } => { c(&mut k, ty); c(&mut k, fst); c(&mut k, snd); "Pair".into() }
            Term::Fst(x) => { c(&mut k, x); "Fst".into() }
            Term::Snd(x) => { c(&mut k, x); "Snd".into() }
            Term::Eq { ty, lhs, rhs } => { c(&mut k, ty); c(&mut k, lhs); c(&mut k, rhs); "Eq".into() }
            Term::Refl { ty, val } => { c(&mut k, ty); c(&mut k, val); "Refl".into() }
            Term::Transport { ty, lhs, rhs, eq, motive, val } => { for x in [ty, lhs, rhs, eq, motive, val] { c(&mut k, x); } "Tr".into() }
            Term::Ind { ind, params } => { cs(&mut k, params); format!("Ind{ind:?}") }
            Term::Ctor { ind, ctor, params, args } => { cs(&mut k, params); k.push('|'); cs(&mut k, args); format!("Ctor{ind:?}{ctor}") }
            Term::Match { ind, params, scrut, motive, arms } => {
                cs(&mut k, params);
                c(&mut k, scrut);
                c(&mut k, motive);
                let names: Vec<String> = arms.iter().map(|a| a.names.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(" ")).collect();
                arms.iter().for_each(|a| c(&mut k, &a.body));
                format!("Match{ind:?}{names:?}")
            }
            Term::Prim { op, args, proofs } => { cs(&mut k, args); k.push('|'); cs(&mut k, proofs); format!("Prim{op:?}") }
            Term::Rec { args, proof } => { cs(&mut k, args); if let Some(x) = proof { k.push('|'); c(&mut k, x); } "Rec".into() }
            Term::Delta { def, args } => { cs(&mut k, args); format!("Delta{def:?}") }
            Term::Unfold { def, args, to_body, val } => { cs(&mut k, args); c(&mut k, val); format!("Unf{def:?}{to_body}") }
            Term::Linarith { hyps, goal, cert } => { hyps.iter().for_each(|(a, b)| { c(&mut k, a); c(&mut k, b); }); c(&mut k, goal); format!("Lin{cert:?}") }
            Term::BvRefl { ty, lhs, rhs } => { c(&mut k, ty); c(&mut k, lhs); c(&mut k, rhs); "Bv".into() }
            Term::Absurd { ty, proof } => { c(&mut k, ty); c(&mut k, proof); "Abs".into() }
            Term::Axiom { ax, args } => { cs(&mut k, args); format!("Ax{ax:?}") }
            other => return format!("{other:?}"),
        };
        head + &k
    }
    let mut h = H { memo: HashMap::new(), table: HashMap::new() };
    h.go(t)
}
