//! Recurrence classes (optimizer design §7.2).
//!
//! From the one-iteration paths ([`super::onestep`]) at a loop call's
//! static arguments:
//!
//! 1. **Static simulation.** A parameter whose value at the call is closed
//!    and whose update depends only on such parameters, identically on
//!    every path, evolves statically (the fuel, a halving width, an index):
//!    its value at every iteration `j` is computed, and the iteration count
//!    `K` is the first `j` at which no continuing path is feasible.
//! 2. **Dynamic classes**, from the per-path updates: `Const`, `Shift(k)`
//!    (`x >> k` each step), `BitDigit` (`v − w` when `v ≥ w`, else `v`, with
//!    `w` a static halving power of two), `GuardCount` (`c + 1` exactly on
//!    `BitDigit`'s peak paths), linear relations between the deltas (Karr:
//!    `Conserved`, `Linear`), and `FirstMatch` (a non-numeric variable set
//!    once by an in-place select to a payload).
//! 3. **Templates**: each variable's closed form as an expression in the
//!    ghost inputs (the dynamic entry values) and `j`.
//!
//! Values are converted to [`SVal`]s over the **state** (`CE::Var(i)` is
//! parameter `i` at the current iteration). Checked operations become their
//! wrapping forms and saturating subtractions are read as exact: both are
//! only candidates, validated on traces and proven per literal.

use std::rc::Rc;

use num_traits::ToPrimitive;
use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{IndId, PrimOp, Rel, Term, Tm, Width};
use sandblaster_kernel::value::{Arg, Budget, Elim, Head, V, Value};

use super::expr::{self, CE, E, Val};
use super::onestep::{End, OneStep};
use crate::opt::drive::step::Eval;

/// A structured value over the state (see the module docs).
#[derive(Clone, Debug)]
pub enum SVal {
    /// A machine-integer or boolean expression over the state.
    Ce(E),
    /// A constructor (not `Bool`); `params` are its type parameters (kernel
    /// values in the root context).
    Ctor { ind: IndId, ctor: u32, params: Vec<V>, args: Vec<SVal> },
    /// An in-place select.
    Ite(E, Box<SVal>, Box<SVal>),
    /// A non-numeric parameter as it is.
    Param(u32),
}

impl SVal {
    pub fn ce(&self) -> Option<&E> {
        match self {
            SVal::Ce(e) => Some(e),
            _ => None,
        }
    }

    /// State variables that occur.
    pub fn state_vars(&self, out: &mut Vec<u32>) {
        match self {
            SVal::Ce(e) => e.vars(out),
            SVal::Ctor { args, .. } => args.iter().for_each(|a| a.state_vars(out)),
            SVal::Ite(c, a, b) => {
                c.vars(out);
                a.state_vars(out);
                b.state_vars(out);
            }
            SVal::Param(i) => {
                if !out.contains(i) {
                    out.push(*i)
                }
            }
        }
    }
}

/// A concrete value of the native interpreter.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CVal {
    N(Val),
    Ctor { ind: u32, ctor: u32, args: Vec<CVal> },
}

impl CVal {
    pub fn num(&self) -> Option<u128> {
        match self {
            CVal::N(v) => v.as_u128(),
            _ => None,
        }
    }
}

/// Evaluates an [`SVal`] natively on a concrete state.
pub fn eval_sval(s: &SVal, state: &[CVal]) -> Option<CVal> {
    let nums: Vec<u128> = state.iter().map(|c| c.num().unwrap_or(0)).collect();
    eval_sval_in(s, state, &nums)
}

fn eval_sval_in(s: &SVal, state: &[CVal], nums: &[u128]) -> Option<CVal> {
    Some(match s {
        SVal::Ce(e) => CVal::N(e.eval(nums, None)?),
        SVal::Ctor { ind, ctor, args, .. } => CVal::Ctor { ind: ind.0, ctor: *ctor, args: args.iter().map(|a| eval_sval_in(a, state, nums)).collect::<Option<_>>()? },
        SVal::Ite(c, a, b) => {
            if c.eval(nums, None)?.as_bool()? {
                eval_sval_in(a, state, nums)?
            } else {
                eval_sval_in(b, state, nums)?
            }
        }
        SVal::Param(i) => state.get(*i as usize)?.clone(),
    })
}

/// The machine width of a type value.
pub fn width_of(v: &V) -> Option<Width> {
    match &**v {
        Value::IntTy(w) => Some(*w),
        _ => None,
    }
}

/// Converts kernel values of the root context into [`SVal`]s.
pub struct Conv<'a> {
    pub env: &'a Env,
    pub ev: Eval<'a>,
    pub nparams: u32,
    /// Machine width of each relevant parameter (`None`: not an integer).
    pub widths: Vec<Option<Width>>,
    pub bool_ind: IndId,
    pub depth: u32,
    pub budget: Budget,
}

impl Conv<'_> {
    pub fn sval(&mut self, v: &V) -> Option<SVal> {
        match &**v {
            Value::Lit { w, n } => Some(SVal::Ce(expr::lit(*w, n.to_u128()?))),
            Value::Ctor { ind, ctor, .. } if *ind == self.bool_ind => Some(SVal::Ce(Rc::new(CE::BoolLit(*ctor == 1)))),
            Value::Ctor { ind, ctor, params, args } => {
                let mut out = Vec::new();
                for a in args {
                    if let Arg::Rel(x) = a {
                        out.push(self.sval(x)?);
                    }
                }
                Some(SVal::Ctor { ind: *ind, ctor: *ctor, params: params.clone(), args: out })
            }
            Value::Neu(n) => {
                if let Some(i) = n.spine.iter().position(|e| matches!(e, Elim::Match { .. })) {
                    let Elim::Match { ind, arms, .. } = &n.spine[i] else { return None };
                    if *ind != self.bool_ind || arms.len() != 2 {
                        return None;
                    }
                    let scrut = crate::auto::util::prefix(n, i);
                    let c = self.sval(&scrut)?.ce()?.clone();
                    let rest: Vec<Elim> = n.spine[i + 1..].iter().map(crate::auto::util::clone_elim).collect();
                    let mut br = Vec::new();
                    for k in 0..2 {
                        let w = self.ev.inst(&arms[k], vec![], self.depth, &mut self.budget).and_then(|w| self.ev.elims(w, &rest, self.depth, &mut self.budget)).ok()?;
                        br.push(self.sval(&w)?);
                    }
                    let (f, t) = (br.remove(0), br.remove(0));
                    return Some(match (&t, &f) {
                        (SVal::Ce(a), SVal::Ce(b)) => SVal::Ce(expr::ite(c, a.clone(), b.clone())),
                        _ => SVal::Ite(c, Box::new(t), Box::new(f)),
                    });
                }
                if !n.spine.is_empty() {
                    return None;
                }
                match &n.head {
                    Head::Var(l) if l.0 < self.nparams => match self.widths.get(l.0 as usize).copied().flatten() {
                        Some(w) => Some(SVal::Ce(expr::var(l.0, w))),
                        None => Some(SVal::Param(l.0)),
                    },
                    Head::Prim { op, args, .. } => {
                        let mut xs = Vec::new();
                        for a in args {
                            xs.push(self.sval(a)?.ce()?.clone());
                        }
                        Some(SVal::Ce(total(*op, xs)?))
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }
}

/// The total form of a primitive application (checked operations become
/// wrapping ones; division by a literal stays exact).
fn total(op: PrimOp, xs: Vec<E>) -> Option<E> {
    use PrimOp::*;
    let o = match op {
        Add(w) => WAdd(w),
        Sub(w) => WSub(w),
        Mul(w) => WMul(w),
        Shl(w) => WShl(w),
        Shr(w) => WShr(w),
        Div(_) => {
            let c = match &*xs[1] {
                CE::Lit(_, c) if *c > 0 => *c,
                _ => return None,
            };
            return Some(Rc::new(CE::DivLit(xs[0].clone(), c)));
        }
        o if expr::total_op(o) => o,
        _ => return None,
    };
    Some(expr::op(o, xs))
}

// ---------------------------------------------------------------------------
// Linear forms (for the delta analysis).
// ---------------------------------------------------------------------------

/// `Σ cᵢ·atomᵢ + c` over integer coefficients; atoms are non-linear
/// sub-expressions (compared structurally).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Lin {
    pub terms: Vec<(E, i128)>,
    pub c: i128,
}

impl Lin {
    fn add(mut self, other: &Lin, k: i128) -> Lin {
        for (a, x) in &other.terms {
            match self.terms.iter_mut().find(|(b, _)| b == a) {
                Some((_, y)) => *y += x * k,
                None => self.terms.push((a.clone(), x * k)),
            }
        }
        self.c += other.c * k;
        self.terms.retain(|(_, x)| *x != 0);
        self
    }
    fn scale(self, k: i128) -> Lin {
        Lin::default().add(&self, k)
    }
    pub fn coeff(&self, a: &E) -> i128 {
        self.terms.iter().find(|(b, _)| b == a).map(|(_, x)| *x).unwrap_or(0)
    }
}

/// The linear form of `e`, reading wrapping and saturating arithmetic as
/// exact (a candidate, validated later).
pub fn lin(e: &E) -> Lin {
    use PrimOp::*;
    match &**e {
        CE::Lit(_, n) => Lin { terms: vec![], c: *n as i128 },
        CE::Op(WAdd(_) | IAdd | SatAdd(_), a) => lin(&a[0]).add(&lin(&a[1]), 1),
        CE::Op(WSub(_) | ISub | SatSub(_), a) => lin(&a[0]).add(&lin(&a[1]), -1),
        CE::Op(WMul(_) | IMul, a) => match (&*a[0], &*a[1]) {
            (CE::Lit(_, k), _) => lin(&a[1]).scale(*k as i128),
            (_, CE::Lit(_, k)) => lin(&a[0]).scale(*k as i128),
            _ => Lin { terms: vec![(e.clone(), 1)], c: 0 },
        },
        CE::Op(WShl(_), a) => match &*a[1] {
            CE::Lit(_, k) if *k < 64 => lin(&a[0]).scale(1i128 << k),
            _ => Lin { terms: vec![(e.clone(), 1)], c: 0 },
        },
        CE::Op(Cast { from, to }, a) if from.bits() <= to.bits() || *to == Width::Int => lin(&a[0]),
        _ => Lin { terms: vec![(e.clone(), 1)], c: 0 },
    }
}

// ---------------------------------------------------------------------------
// The loop and its classes.
// ---------------------------------------------------------------------------

/// One parameter of the loop.
#[derive(Clone, Debug)]
pub struct Param {
    pub name: String,
    /// Kernel argument index (relevant parameters only are listed).
    pub index: u32,
    pub width: Option<Width>,
    /// Its type as a kernel term (in the telescope, over earlier binders).
    pub ty: Tm,
}

/// The class of a parameter (design §7.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Class {
    /// Evolves statically: its value at every iteration is known.
    Static,
    /// Unchanged.
    Const,
    /// `x >> k` every iteration.
    Shift(u32),
    /// `v − w` when `v ≥ w`, else `v`; `w` (parameter `wp`) a static halving
    /// power of two, `2^e` at the call.
    BitDigit { wp: u32, e: u32 },
    /// `c + 1` exactly on the peak paths of the `BitDigit` `v`. (Structural,
    /// but built for one development shape, the MMR/QMDB peak walk;
    /// fairness audit J14: its hit count on the held-out set is to be
    /// reported, plan step 8.)
    GuardCount { v: u32 },
    /// Determined by a linear relation `Σ cᵢ·xᵢ = const` over classified
    /// parameters, with coefficient `±1` on this one.
    Linear { rel: Vec<(u32, i128)> },
    /// Set once, to a payload, by an in-place select; unchanged otherwise.
    FirstMatch,
    /// `c + 1` exactly when the static index `idx` (`0, 1, …` at the
    /// iterations, one bit position each, `w` of them) passes the threshold
    /// `thr` (a `Const` parameter: `idx > thr`, or `idx ≥ thr` when not
    /// `strict`) and bit `idx` of the `Const` parameter `src` is set; `c`
    /// otherwise (plan O6: corpus P13, "set bits above position k").
    /// Structural, but built for that one program (fairness audit J14: its
    /// held-out hit count is to be reported, plan step 8).
    MaskedCount { idx: u32, src: u32, thr: u32, strict: bool },
    Unknown(String),
}

/// A continuing path: its guards (over the state) and the next state.
#[derive(Clone, Debug)]
pub struct ContPath {
    pub guards: Vec<(E, bool)>,
    pub next: Vec<SVal>,
}

/// An exit path: its guards and the exit value.
#[derive(Clone, Debug)]
pub struct ExitPath {
    pub guards: Vec<(E, bool)>,
    pub value: SVal,
}

/// A loop call at static arguments, classified.
pub struct Loop {
    pub one: OneStep,
    pub params: Vec<Param>,
    /// The call's static arguments, per parameter (a closed kernel term).
    pub statics: Vec<Option<Tm>>,
    pub cont: Vec<ContPath>,
    pub exits: Vec<ExitPath>,
    /// Iterations before the static exhaustion.
    pub k: u32,
    /// Values of the static parameters at every iteration `0..=K`.
    pub static_seq: Vec<Vec<Option<CVal>>>,
    pub classes: Vec<Class>,
    /// Linear relations over the numeric dynamic parameters (coefficient
    /// vectors indexed by parameter).
    pub relations: Vec<Vec<(u32, i128)>>,
}

/// Iterations are capped (the per-literal lemmas are `K + 1`).
pub const MAX_K: u32 = 64;

impl Loop {
    /// The parameters' concrete state at the call for the dynamic values
    /// `dyn_vals` (in dynamic-parameter order).
    pub fn entry_state(&self, env: &Env, dyn_vals: &[CVal]) -> Option<Vec<CVal>> {
        let mut di = 0;
        let mut out = Vec::new();
        for (i, _) in self.params.iter().enumerate() {
            match &self.statics[i] {
                Some(t) => out.push(closed_cval(env, t)?),
                None => {
                    out.push(dyn_vals.get(di)?.clone());
                    di += 1;
                }
            }
        }
        Some(out)
    }

    /// Indices of the dynamic parameters.
    pub fn dynamic(&self) -> Vec<u32> {
        (0..self.params.len() as u32).filter(|i| self.statics[*i as usize].is_none()).collect()
    }
}

/// The concrete value of a closed kernel term (a literal or a constructor
/// of literals).
pub fn closed_cval(env: &Env, t: &Tm) -> Option<CVal> {
    match &**t {
        Term::Lit { w, n } if *w != Width::Int => Some(CVal::N(Val::W(*w, n.to_u128()?))),
        Term::Ctor { ind, ctor, args, .. } if *ind == env.bool_ind() => {
            let _ = args;
            Some(CVal::N(Val::B(*ctor == 1)))
        }
        Term::Ctor { ind, ctor, args, .. } => Some(CVal::Ctor { ind: ind.0, ctor: *ctor, args: args.iter().map(|a| closed_cval(env, a)).collect::<Option<_>>()? }),
        _ => None,
    }
}

/// Classifies the loop head `one` at the static arguments `statics` (one
/// entry per relevant parameter).
pub fn classify(env: &Env, one: OneStep, statics: Vec<Option<Tm>>) -> Result<Loop, String> {
    let def = one.def;
    let tele = crate::opt::symex::telescope(env, def).ok_or("no telescope")?;
    // the relevant parameters (all leading: the requires binders follow)
    let mut params = Vec::new();
    for (i, (name, rel, dom)) in tele.binders.iter().enumerate() {
        if *rel != Rel::Rel {
            continue;
        }
        let ty = one.root.ctx.entries[i].ty.clone();
        params.push(Param { name: name.to_string(), index: i as u32, width: width_of(&ty), ty: dom.clone() });
    }
    if params.len() as u32 != one.nparams || params.iter().enumerate().any(|(i, p)| p.index != i as u32) {
        return Err("the relevant parameters are not the leading binders".into());
    }
    if statics.len() != params.len() {
        return Err("a static argument vector of the wrong length".into());
    }
    let widths: Vec<Option<Width>> = params.iter().map(|p| p.width).collect();
    let opaque = move |g: sandblaster_kernel::term::GlobalId| g == def;
    let mut cv = Conv { env, ev: Eval { env, opaque: &opaque }, nparams: one.nparams, widths, bool_ind: one.bool_ind, depth: one.root.depth(), budget: Budget { steps: 20_000_000 } };
    let mut cont = Vec::new();
    let mut exits = Vec::new();
    for p in &one.paths {
        let mut guards = Vec::new();
        for (g, b) in &p.guards {
            let e = cv.sval(g).and_then(|s| s.ce().cloned()).ok_or("a guard outside the closed-form language")?;
            guards.push((e, *b));
        }
        match &p.end {
            End::Continue(args) => {
                let next: Vec<SVal> = OneStep::next_state(args).iter().map(|v| cv.sval(v)).collect::<Option<_>>().ok_or("an update outside the closed-form language")?;
                cont.push(ContPath { guards, next });
            }
            End::Exit(v) => {
                let value = cv.sval(v).ok_or("an exit value outside the closed-form language")?;
                exits.push(ExitPath { guards, value });
            }
        }
    }
    if cont.is_empty() {
        return Err("no continuing path".into());
    }
    let n = params.len();
    // 1. static simulation
    let mut is_static: Vec<bool> = statics.iter().map(|s| s.is_some()).collect();
    loop {
        let mut changed = false;
        for i in 0..n {
            if !is_static[i] {
                continue;
            }
            let first = &cont[0].next[i];
            let ok = cont.iter().all(|c| {
                let u = &c.next[i];
                let mut vs = Vec::new();
                u.state_vars(&mut vs);
                vs.iter().all(|v| is_static[*v as usize]) && same(u, first)
            });
            if !ok {
                is_static[i] = false;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mut seq: Vec<Vec<Option<CVal>>> = Vec::new();
    let mut cur: Vec<Option<CVal>> = (0..n).map(|i| if is_static[i] { statics[i].as_ref().and_then(|t| closed_cval(env, t)) } else { None }).collect();
    if (0..n).any(|i| is_static[i] && cur[i].is_none()) {
        return Err("a static argument that is not a closed value".into());
    }
    let mut k = None;
    for jj in 0..=MAX_K {
        seq.push(cur.clone());
        // a continuing path feasible at this iteration?
        let st: Vec<CVal> = cur.iter().map(|c| c.clone().unwrap_or(CVal::N(Val::W(Width::U64, 0)))).collect();
        let feasible = |guards: &[(E, bool)]| {
            guards.iter().all(|(g, b)| {
                let mut vs = Vec::new();
                g.vars(&mut vs);
                if vs.iter().any(|v| !is_static[*v as usize]) {
                    return true;
                }
                match eval_sval(&SVal::Ce(g.clone()), &st) {
                    Some(CVal::N(Val::B(x))) => x == *b,
                    _ => true,
                }
            })
        };
        let live: Vec<&ContPath> = cont.iter().filter(|c| feasible(&c.guards)).collect();
        if live.is_empty() {
            k = Some(jj);
            break;
        }
        // the next static state (the same on every path)
        let mut next = cur.clone();
        for i in 0..n {
            if is_static[i] {
                next[i] = eval_sval(&live[0].next[i], &st);
                if next[i].is_none() {
                    return Err(format!("the static parameter `{}` does not evaluate", params[i].name));
                }
            }
        }
        cur = next;
    }
    let k = k.ok_or_else(|| format!("no static exhaustion within {MAX_K} iterations"))?;
    if k == 0 {
        return Err("the loop exits at once".into());
    }
    // 2. dynamic classes
    let mut classes: Vec<Class> = vec![Class::Unknown("unclassified".into()); n];
    for i in 0..n {
        if is_static[i] {
            classes[i] = Class::Static;
            continue;
        }
        let me_num = params[i].width.map(|w| expr::var(i as u32, w));
        let unchanged = |u: &SVal| match (u, &me_num) {
            (SVal::Ce(e), Some(m)) => e == m,
            (SVal::Param(p), None) => *p == i as u32,
            _ => false,
        };
        if cont.iter().all(|c| unchanged(&c.next[i])) {
            classes[i] = Class::Const;
            continue;
        }
        if let Some(m) = &me_num {
            // x >> k
            let shift = |u: &SVal| -> Option<u32> {
                if let SVal::Ce(e) = u
                    && let CE::Op(PrimOp::WShr(_), a) = &**e
                    && &a[0] == m
                    && let CE::Lit(_, kk) = &*a[1]
                {
                    return Some(*kk as u32);
                }
                None
            };
            if let Some(kk) = shift(&cont[0].next[i])
                && cont.iter().all(|c| shift(&c.next[i]) == Some(kk))
                && kk > 0
            {
                classes[i] = Class::Shift(kk);
                continue;
            }
        } else if first_match_shape(&cont, i as u32) {
            classes[i] = Class::FirstMatch;
            continue;
        }
    }
    // BitDigit: `v − w` under `!(v < w)`, `v` under `v < w`
    for i in 0..n {
        if classes[i] != Class::Unknown("unclassified".into()) {
            continue;
        }
        let Some(w) = params[i].width else { continue };
        let me = expr::var(i as u32, w);
        let mut wp: Option<u32> = None;
        let mut ok = true;
        for c in &cont {
            // the guard `lt(me, wv)` with its value
            let g = c.guards.iter().find_map(|(g, b)| match &**g {
                CE::Op(PrimOp::Lt(_), a) if a[0] == me => match &*a[1] {
                    CE::Var(x, _) if is_static[*x as usize] => Some((*x, *b)),
                    _ => None,
                },
                _ => None,
            });
            let Some((x, below)) = g else {
                ok = false;
                break;
            };
            if wp.is_some_and(|y| y != x) {
                ok = false;
                break;
            }
            wp = Some(x);
            let u = c.next[i].ce();
            let expect = if below { me.clone() } else { expr::op2(PrimOp::WSub(w), me.clone(), expr::var(x, w)) };
            if u != Some(&expect) {
                ok = false;
                break;
            }
        }
        let Some(wp) = wp.filter(|_| ok) else { continue };
        // w halves, a power of two at the call
        let ws: Vec<Option<u128>> = seq.iter().map(|s| s[wp as usize].as_ref().and_then(|c| c.num())).collect();
        let Some(w0) = ws[0] else { continue };
        if w0 == 0 || !w0.is_power_of_two() {
            continue;
        }
        let e = w0.trailing_zeros();
        if (0..seq.len()).all(|jj| ws[jj] == Some(if (jj as u32) <= e { w0 >> jj } else { 0 })) {
            classes[i] = Class::BitDigit { wp, e };
        }
    }
    // GuardCount: `c + 1` on BitDigit's peak paths, `c` on its idle paths
    for i in 0..n {
        if classes[i] != Class::Unknown("unclassified".into()) {
            continue;
        }
        let Some(w) = params[i].width else { continue };
        let me = expr::var(i as u32, w);
        for v in 0..n {
            let Class::BitDigit { wp, .. } = classes[v] else { continue };
            let vw = params[v].width.unwrap_or(Width::U64);
            let peak = |c: &ContPath| c.guards.iter().find_map(|(g, b)| match &**g {
                CE::Op(PrimOp::Lt(_), a) if a[0] == expr::var(v as u32, vw) && a[1] == expr::var(wp, vw) => Some(!*b),
                _ => None,
            });
            let ok = cont.iter().all(|c| {
                let u = c.next[i].ce();
                match peak(c) {
                    Some(true) => u == Some(&expr::op2(PrimOp::WAdd(w), me.clone(), expr::lit(w, 1))),
                    Some(false) => u == Some(&me),
                    None => false,
                }
            });
            if ok {
                classes[i] = Class::GuardCount { v: v as u32 };
                break;
            }
        }
    }
    // MaskedCount: `c + 1` exactly on the paths where the static index
    // passes a Const threshold and indexes a set bit of a Const value
    for i in 0..n {
        if classes[i] != Class::Unknown("unclassified".into()) {
            continue;
        }
        if let Some(cl) = masked_count(&params, &classes, &cont, &seq, k, i as u32) {
            classes[i] = cl;
        }
    }
    // linear relations over the numeric dynamic parameters
    let num_dyn: Vec<u32> = (0..n as u32).filter(|i| !is_static[*i as usize] && params[*i as usize].width.is_some() && classes[*i as usize] != Class::Const).collect();
    let mut deltas: Vec<Vec<Lin>> = Vec::new(); // per path, per num_dyn var
    for c in &cont {
        let mut row = Vec::new();
        for &i in &num_dyn {
            let w = params[i as usize].width.unwrap();
            let Some(u) = c.next[i as usize].ce() else {
                row.push(None);
                continue;
            };
            let d = lin(u).add(&lin(&expr::var(i, w)), -1);
            row.push(Some(d));
        }
        deltas.push(row.into_iter().collect::<Option<Vec<Lin>>>().unwrap_or_default());
    }
    let relations = if deltas.iter().all(|r| r.len() == num_dyn.len()) { nullspace(&num_dyn, &deltas) } else { Vec::new() };
    // parameters determined by a relation (coefficient ±1) over classified ones
    loop {
        let mut changed = false;
        for i in 0..n {
            if classes[i] != Class::Unknown("unclassified".into()) || params[i].width.is_none() {
                continue;
            }
            for r in &relations {
                let ci = r.iter().find(|(v, _)| *v == i as u32).map(|x| x.1).unwrap_or(0);
                if ci.abs() != 1 {
                    continue;
                }
                let others_ok = r.iter().all(|(v, c)| *v == i as u32 || *c == 0 || !matches!(classes[*v as usize], Class::Unknown(_)));
                if others_ok {
                    classes[i] = Class::Linear { rel: r.clone() };
                    changed = true;
                    break;
                }
            }
        }
        if !changed {
            break;
        }
    }
    for i in 0..n {
        if classes[i] == Class::Unknown("unclassified".into()) {
            classes[i] = Class::Unknown(format!("`{}`: no recurrence class fits its updates", params[i].name));
        }
    }
    let static_seq = seq;
    Ok(Loop { one, params, statics, cont, exits, k, static_seq, classes, relations })
}

/// The [`Class::MaskedCount`] of parameter `c`, if its updates have that
/// shape: the static index takes the values `0, 1, …, K` (one bit position
/// per iteration, all `w` positions of the source) and every continuing
/// path increments `c` exactly when its threshold and bit guards hold.
fn masked_count(params: &[Param], classes: &[Class], cont: &[ContPath], seq: &[Vec<Option<CVal>>], k: u32, c: u32) -> Option<Class> {
    let cw = params[c as usize].width?;
    let me = expr::var(c, cw);
    let inc = expr::op2(PrimOp::WAdd(cw), me.clone(), expr::lit(cw, 1));
    // the threshold guard `idx ⋈ thr` (normalized: `(idx, thr, strict, holds)`)
    let thr_of = |g: &E, b: bool| -> Option<(u32, u32, bool, bool)> {
        let CE::Op(op, a) = &**g else { return None };
        let (CE::Var(x, _), CE::Var(y, _)) = (&*a[0], &*a[1]) else { return None };
        let (x, y) = (*x, *y);
        let st = |v: u32| classes[v as usize] == Class::Static;
        let cst = |v: u32| classes[v as usize] == Class::Const;
        // (idx on the left, thr on the right)
        let (idx, thr, strict, flip) = match op {
            PrimOp::Gt(_) if st(x) && cst(y) => (x, y, true, false),
            PrimOp::Ge(_) if st(x) && cst(y) => (x, y, false, false),
            PrimOp::Lt(_) if cst(x) && st(y) => (y, x, true, false),
            PrimOp::Le(_) if cst(x) && st(y) => (y, x, false, false),
            _ => return None,
        };
        let _ = flip;
        Some((idx, thr, strict, b))
    };
    // the bit guard `(src >> idx) & 1 == 1` (or `!= 0`): `(src, idx, set)`
    let bit_of = |g: &E, b: bool| -> Option<(u32, u32, bool)> {
        let CE::Op(op, a) = &**g else { return None };
        let (lhs, lit) = (&a[0], &a[1]);
        let CE::Lit(_, cv) = &**lit else { return None };
        let CE::Op(PrimOp::And(_), m) = &**lhs else { return None };
        if !matches!(&*m[1], CE::Lit(_, 1)) {
            return None;
        }
        let CE::Op(PrimOp::WShr(_), sh) = &*m[0] else { return None };
        let (CE::Var(src, _), CE::Var(idx, _)) = (&*sh[0], &*sh[1]) else { return None };
        if classes[*src as usize] != Class::Const || classes[*idx as usize] != Class::Static {
            return None;
        }
        let set = match (op, *cv) {
            (PrimOp::Eq(_), 1) => b,
            (PrimOp::Eq(_), 0) | (PrimOp::Ne(_), 1) => !b,
            (PrimOp::Ne(_), 0) => b,
            _ => return None,
        };
        Some((*src, *idx, set))
    };
    let mut shape: Option<(u32, u32, u32, bool)> = None; // idx, src, thr, strict
    for p in cont {
        let mut thr_holds: Option<bool> = None;
        let mut bit_set: Option<bool> = None;
        for (g, b) in &p.guards {
            if let Some((idx, thr, strict, holds)) = thr_of(g, *b) {
                match &mut shape {
                    Some((i2, _, t2, s2)) if *i2 != idx || *t2 != thr || *s2 != strict => return None,
                    Some(_) => {}
                    None => shape = Some((idx, u32::MAX, thr, strict)),
                }
                thr_holds = Some(holds);
                continue;
            }
            if let Some((src, idx, set)) = bit_of(g, *b) {
                match &mut shape {
                    Some((i2, s2, _, _)) if *i2 != idx || (*s2 != u32::MAX && *s2 != src) => return None,
                    Some((_, s2, _, _)) => *s2 = src,
                    None => return None,
                }
                bit_set = Some(set);
                continue;
            }
            // other guards must be static (the index's bound)
            let mut vs = Vec::new();
            g.vars(&mut vs);
            if !vs.iter().all(|v| classes[*v as usize] == Class::Static) {
                return None;
            }
        }
        let u = p.next[c as usize].ce()?;
        let incremented = thr_holds == Some(true) && bit_set == Some(true);
        if (incremented && u != &inc) || (!incremented && u != &me) {
            return None;
        }
    }
    let (idx, src, thr, strict) = shape?;
    if src == u32::MAX {
        return None;
    }
    // the index visits every bit position of the source: 0, 1, …, K = w − 1
    let w = params[src as usize].width?;
    if k + 1 != expr::bits(w) {
        return None;
    }
    for (jj, s) in seq.iter().enumerate().take(k as usize + 1) {
        if s.get(idx as usize).and_then(|x| x.as_ref()).and_then(|x| x.num()) != Some(jj as u128) {
            return None;
        }
    }
    Some(Class::MaskedCount { idx, src, thr, strict })
}

/// Structural equality of two structured values.
fn same(a: &SVal, b: &SVal) -> bool {
    match (a, b) {
        (SVal::Ce(x), SVal::Ce(y)) => x == y,
        (SVal::Param(x), SVal::Param(y)) => x == y,
        _ => false,
    }
}

/// Whether parameter `i`'s updates are `FirstMatch`-shaped: unchanged, or a
/// select tree whose leaves are the parameter itself or constructors.
fn first_match_shape(cont: &[ContPath], i: u32) -> bool {
    fn leaves_ok(s: &SVal, i: u32, found_ctor: &mut bool) -> bool {
        match s {
            SVal::Param(p) => *p == i,
            SVal::Ctor { .. } => {
                *found_ctor = true;
                true
            }
            SVal::Ite(_, a, b) => leaves_ok(a, i, found_ctor) && leaves_ok(b, i, found_ctor),
            SVal::Ce(_) => false,
        }
    }
    let mut any = false;
    cont.iter().all(|c| leaves_ok(&c.next[i as usize], i, &mut any)) && any
}

/// Integer vectors `c` over `vars` with `Σ cᵥ·Δᵥ = 0` on every path (the
/// deltas are linear forms over atoms): a basis of the null space, by
/// fraction-free Gaussian elimination.
fn nullspace(vars: &[u32], deltas: &[Vec<Lin>]) -> Vec<Vec<(u32, i128)>> {
    // rows: (path, atom) incl. the constant; columns: vars
    let mut atoms: Vec<Option<E>> = vec![None]; // None = the constant
    for row in deltas {
        for d in row {
            for (a, _) in &d.terms {
                if !atoms.iter().any(|x| x.as_ref() == Some(a)) {
                    atoms.push(Some(a.clone()));
                }
            }
        }
    }
    let mut m: Vec<Vec<i128>> = Vec::new();
    for row in deltas {
        for a in &atoms {
            let r: Vec<i128> = row.iter().map(|d| match a {
                None => d.c,
                Some(a) => d.coeff(a),
            }).collect();
            if r.iter().any(|x| *x != 0) {
                m.push(r);
            }
        }
    }
    let ncols = vars.len();
    // reduced row echelon form over the rationals, kept integral
    let mut pivots: Vec<usize> = Vec::new();
    let mut r = 0;
    for col in 0..ncols {
        let Some(p) = (r..m.len()).find(|&i| m[i][col] != 0) else { continue };
        m.swap(r, p);
        for i in 0..m.len() {
            if i != r && m[i][col] != 0 {
                let (a, b) = (m[r][col], m[i][col]);
                for c in 0..ncols {
                    m[i][c] = m[i][c] * a - m[r][c] * b;
                }
                let g = m[i].iter().fold(0i128, |g, x| gcd(g, x.abs()));
                if g > 1 {
                    for c in 0..ncols {
                        m[i][c] /= g;
                    }
                }
            }
        }
        pivots.push(col);
        r += 1;
        if r == m.len() {
            break;
        }
    }
    let free: Vec<usize> = (0..ncols).filter(|c| !pivots.contains(c)).collect();
    let mut out = Vec::new();
    for &f in &free {
        // x_f = L (a common multiple of the pivots), pivots solved
        let l = pivots.iter().enumerate().fold(1i128, |acc, (ri, &pc)| lcm(acc, m[ri][pc].abs()));
        let mut x = vec![0i128; ncols];
        x[f] = l;
        for (ri, &pc) in pivots.iter().enumerate() {
            // m[ri][pc]·x_pc + m[ri][f]·x_f = 0
            x[pc] = -(m[ri][f] * l) / m[ri][pc];
        }
        let g = x.iter().fold(0i128, |g, v| gcd(g, v.abs()));
        let g = if g == 0 { 1 } else { g };
        let v: Vec<(u32, i128)> = vars.iter().zip(&x).filter(|(_, c)| **c != 0).map(|(v, c)| (*v, c / g)).collect();
        if !v.is_empty() {
            out.push(v);
        }
    }
    out
}

fn gcd(a: i128, b: i128) -> i128 {
    if b == 0 { a } else { gcd(b, a % b) }
}

fn lcm(a: i128, b: i128) -> i128 {
    if a == 0 || b == 0 { a.max(b) } else { a / gcd(a, b) * b }
}
