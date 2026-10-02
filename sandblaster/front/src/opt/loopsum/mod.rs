//! Σ2, loop summaries (optimizer design §7; plan O6).
//!
//! A call of a tail-recursive user function whose measure is a literal the
//! driver will not unroll (`shape_go(63, t, L, 2^62, 0, 0, 0, None)`) is a
//! **loop head at static arguments** ([`LoopKey`]). The summarizer turns it
//! into a **closed form**:
//!
//! 1. one iteration on symbolic state ([`onestep`]);
//! 2. recurrence classes and per-parameter closed forms ([`classify`],
//!    [`invariant`]);
//! 3. traces on profile and corner inputs ([`traces`]) and enumerative
//!    synthesis of the witness iteration ([`synth`]), every constant of
//!    either harvested from the loop itself ([`pool`]);
//! 4. the `K + 1` per-literal lemmas ([`lemmas`]) — each `lemma_j` states
//!    that the loop at iteration `j` (the invariant holding) returns the
//!    closed-form result, and is checked by the kernel;
//! 5. a **loop helper** `H` (an exec function over the dynamic arguments,
//!    its body the closed form printed by the residual printer, its
//!    `requires` the loop's at the static arguments) linked by the lemma
//!    `H::equiv : Π d̄ h̄. Eq(R, H d̄ h̄, loop(statics, d̄) h̄)`: `lemma_0` at
//!    the entry state, whose invariant the call's `requires` establish.
//!
//! The driver (Σ1) keeps such a call as a `Step::LoopSum`: the residual
//! calls `H` (printed `#[inline]`), and the caller's equality lemma rewrites
//! the call through `H::equiv` with `H`'s `requires` proven at the call.
//! When the closed form fails, the fallback rungs ([`rungs`]) are tried; a
//! failure of every rung keeps the loop (the source), with the reason in
//! the report. Nothing here is trusted: every link is a kernel-checked
//! equality, and the helper, its lemma and its callers are elaborated.
//!
//! **Registry.** The summaries built so far live in a per-thread registry
//! ([`with_registry`]), which the driver's policy, the residual printer and
//! the proof builder consult by key; `opt::optimize` resets it per crate.

pub mod classify;
pub mod enumerate;
pub mod expr;
pub mod facts;
pub mod guards;
pub mod invariant;
pub mod lemmas;
pub mod onestep;
pub mod pool;
pub mod rungs;
pub mod setbits;
pub mod synth;
pub mod traces;

use std::cell::RefCell;
use std::collections::BTreeMap;

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{GlobalId, IndId, Lvl, Rel, Term, Tm, Width};
use sandblaster_kernel::value::{Arg, Budget, V, Value};

use crate::hir::*;

/// The key of a loop summary: the loop head and its static arguments
/// (relevant argument index → the closed argument's core text).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LoopKey {
    pub def: GlobalId,
    pub statics: Vec<(usize, String)>,
}

/// A committed loop helper.
#[derive(Clone, Debug)]
pub struct LoopHelper {
    pub item: ItemId,
    pub global: GlobalId,
    /// `H::equiv : Π d̄ h̄. Eq(R, H d̄ h̄, loop(statics, d̄) h̄)`.
    pub lemma: GlobalId,
    pub rung: crate::opt::Rung,
    /// Kernel-checked facts about the loop's result (exported for callers).
    pub facts: Vec<crate::opt::summary::FactLemma>,
    /// The closed form's exported facts (`facts`; the driven caller lifts
    /// them to its own result, `opt::facts`).
    pub loop_facts: Option<facts::LoopFacts>,
    /// The stable name of the summary lemma (`<loop>::summary`).
    pub summary_lemma: String,
    /// What the summary is (the report).
    pub describe: String,
    /// Deterministic resource use: kernel steps of the lemma chain.
    pub steps: u64,
}

/// A simulated fault of a loop summary (design §20; the must-reject suite
/// only, through `OptTestHooks::loop_faults`): the summarizer proposes a
/// wrong closed form or invariant, skips the trace validation, and the
/// lemma builder *trusts* every obligation it cannot prove (a
/// certificate-free `linarith` claim), so what rejects it is the kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoopFault {
    /// R7: the witness off by one (for `shape_go`: `h = 64 − lz(L ⊕ t)`).
    WitnessPlusOne,
    /// R8: the `GuardCount` invariant one bit off (`before =
    /// popcnt(L >> (f − 1))`).
    GuardCountShift,
    /// R6: an early exit whose stop test is "the payload is set" (on a
    /// find-*last* loop that test is not final: the stability lemma's
    /// invariant preservation fails). Skips the closed form.
    EarlyExitPayloadSet,
    /// R28: a symbolic-fuel enumeration lemma whose arm `c` claims the
    /// fuel is `c + 1` (the set-bit rung's idle-run lemma). Skips the
    /// closed form and the early exit.
    EnumArmMisstated,
    /// R29: a set-bit iteration whose jump goes one fuel too far (a set bit
    /// skipped). Skips the closed form and the early exit.
    SetBitsWrongJump,
}

/// Why a loop was not summarized, and the steps spent.
#[derive(Clone, Debug)]
pub struct LoopFailure {
    pub reason: String,
    pub steps: u64,
}

/// Summarizer settings (budgets are steps; design §17).
#[derive(Clone, Debug)]
pub struct LoopConfig {
    /// Synthesis (tests may switch it off: the fallback rungs are then
    /// tried; plan O6, "with synthesis disabled through a hook").
    pub synthesis: bool,
    /// A simulated fault (set per loop from the test hooks).
    pub fault: Option<LoopFault>,
    /// Kernel steps per loop summary (all lemmas; design: ≤ 5·10^8).
    pub steps_per_loop: u64,
    pub synth_max_size: usize,
    /// Profile inputs per loop head (by the loop's global name): the loop
    /// call's relevant arguments (`None` where not an integer), from the
    /// crate's `PROFILE.json` (`opt::cost::profile`).
    pub profile: BTreeMap<String, Vec<Vec<Option<u128>>>>,
    /// When no closed form is found, try the set-bit iteration before the
    /// early exit (tests; the cost model, plan O8, is to choose).
    pub prefer_set_bits: bool,
}

impl Default for LoopConfig {
    fn default() -> LoopConfig {
        // a test-build hook (plan O6: "with synthesis disabled through a
        // hook"): `SANDBLASTER_TEST_LOOPSUM_SYNTHESIS=0` switches synthesis off
        // in builds with the test hooks (never in a production build, whose
        // output depends on no environment variable)
        #[cfg(any(test, feature = "opt-test-hooks"))]
        let synthesis = std::env::var("SANDBLASTER_TEST_LOOPSUM_SYNTHESIS").as_deref() != Ok("0");
        #[cfg(not(any(test, feature = "opt-test-hooks")))]
        let synthesis = true;
        LoopConfig { synthesis, fault: None, steps_per_loop: 500_000_000, synth_max_size: synth::MAX_SIZE, profile: BTreeMap::new(), prefer_set_bits: false }
    }
}

/// The per-thread registry of loop summaries (see the module docs).
#[derive(Default)]
pub struct Registry {
    pub helpers: BTreeMap<LoopKey, LoopHelper>,
    pub failed: BTreeMap<LoopKey, LoopFailure>,
    pub config: LoopConfig,
    /// Summaries per loop head (the name index of the next one).
    pub count: BTreeMap<GlobalId, u32>,
}

thread_local! {
    static REGISTRY: RefCell<Registry> = RefCell::new(Registry::default());
}

/// Runs `f` on the registry.
pub fn with_registry<T>(f: impl FnOnce(&mut Registry) -> T) -> T {
    REGISTRY.with(|r| f(&mut r.borrow_mut()))
}

/// Resets the registry (one crate's optimization).
pub fn reset(config: LoopConfig) {
    with_registry(|r| *r = Registry { config, ..Registry::default() });
    meter::reset();
}

/// The step meter of the loop summary being built: `steps_per_loop`
/// (design §17: ≤ 5·10^8 kernel steps per loop) over the whole summary —
/// the analysis, the lemma chain, the helper's links, the exported facts
/// and the fallback rungs. Every search and kernel check of a summary
/// takes its budget through [`meter::cap`] (its own limit, capped by what
/// is left) and pays with [`meter::charge`]; a summary that exhausts the
/// meter fails (the loop is kept). Steps only: deterministic. Outside a
/// summary the meter is off (`cap` is the identity, `charge` a no-op).
pub mod meter {
    use std::cell::Cell;

    #[derive(Clone, Copy, Default)]
    struct State {
        on: bool,
        limit: u64,
        used: u64,
        /// Steps of every summary metered in this crate's optimization.
        total: u64,
    }

    thread_local! {
        static METER: Cell<State> = const { Cell::new(State { on: false, limit: 0, used: 0, total: 0 }) };
    }

    pub(super) fn reset() {
        METER.with(|m| m.set(State::default()));
    }

    /// Starts metering one summary with `limit` steps.
    pub(super) fn start(limit: u64) {
        METER.with(|m| {
            let s = m.get();
            m.set(State { on: true, limit, used: 0, total: s.total });
        });
    }

    /// Stops metering: the summary's steps (added to the crate's total).
    pub(super) fn stop() -> u64 {
        METER.with(|m| {
            let s = m.get();
            m.set(State { on: false, limit: 0, used: 0, total: s.total + s.used });
            s.used
        })
    }

    /// The budget of a search or check whose own limit is `n`: `n`, capped
    /// by the steps left.
    pub fn cap(n: u64) -> u64 {
        METER.with(|m| {
            let s = m.get();
            if s.on { n.min(s.limit.saturating_sub(s.used)) } else { n }
        })
    }

    /// Takes back `n` steps charged to the summary being built (a cached
    /// proof's cost charged in place of what its hit took, `lemmas`).
    pub fn refund(n: u64) {
        METER.with(|m| {
            let mut s = m.get();
            if s.on {
                s.used = s.used.saturating_sub(n);
                m.set(s);
            }
        });
    }

    /// Charges `recorded` steps in place of the `actual` ones already
    /// charged (a cached proof's recorded cost, `lemmas`).
    pub fn recharge(actual: u64, recorded: u64) {
        if recorded >= actual {
            charge(recorded - actual);
        } else {
            refund(actual - recorded);
        }
    }

    /// Charges `n` steps to the summary being built.
    pub fn charge(n: u64) {
        METER.with(|m| {
            let mut s = m.get();
            if s.on {
                s.used = s.used.saturating_add(n);
                m.set(s);
            }
        });
    }

    /// Whether the summary being built has spent its steps.
    pub fn exhausted() -> bool {
        METER.with(|m| {
            let s = m.get();
            s.on && s.used >= s.limit
        })
    }

    /// The steps of every summary metered so far in this crate's
    /// optimization (the report's `budgets_used.loopsum_steps` is its
    /// growth over one function's optimization).
    pub fn total() -> u64 {
        METER.with(|m| {
            let s = m.get();
            s.total + if s.on { s.used } else { 0 }
        })
    }
}

/// The committed helper of `key`, if any.
pub fn helper(key: &LoopKey) -> Option<LoopHelper> {
    with_registry(|r| r.helpers.get(key).cloned())
}

/// The core text of a closed argument value (a literal or a constructor of
/// closed arguments), if it is one.
fn closed_text(env: &Env, v: &V) -> Option<(String, Tm)> {
    match &**v {
        Value::Lit { .. } | Value::Ctor { .. } => {
            let mut fuel = 1usize << 12;
            if !crate::opt::drive::step::closed_below(v, 0, &mut fuel) {
                return None;
            }
            let t = env.quote(Lvl(0), v, false);
            let mut free = false;
            crate::elab::tm::any_node(&t, &mut |n| {
                if matches!(n, Term::Var(_)) {
                    free = true;
                }
                free
            });
            if free {
                return None;
            }
            Some((env.print_term(&[], &t), t))
        }
        _ => None,
    }
}

/// The key of the application `def args` (its closed relevant arguments are
/// static), with the static terms per relevant parameter.
pub fn key_of(env: &Env, def: GlobalId, args: &[Arg]) -> Option<(LoopKey, Vec<Option<Tm>>)> {
    let mut statics = Vec::new();
    let mut terms = Vec::new();
    let mut ri = 0usize;
    for a in args {
        if let Arg::Rel(v) = a {
            match closed_text(env, v) {
                Some((s, t)) => {
                    statics.push((ri, s));
                    terms.push(Some(t));
                }
                None => terms.push(None),
            }
            ri += 1;
        }
    }
    if statics.is_empty() || statics.len() == terms.len() {
        return None;
    }
    Some((LoopKey { def, statics }, terms))
}

/// Whether the loop application `def args` goes to Σ2 (the driver's
/// policy): a user recursion (tail-recursive, a literal measure of at least
/// two trips — when Σ2 fails, the driver unrolls it or builds per-level
/// helpers where the cost model says unrolling pays, `drive::unroll_pays`,
/// and keeps the loop otherwise), at least one dynamic argument, not failed
/// before.
pub fn candidate(env: &Env, is_user_recursion: bool, trips: Option<u32>, def: GlobalId, args: &[Arg]) -> Option<LoopKey> {
    if !is_user_recursion {
        return None;
    }
    let trips = trips?;
    if trips < 2 || trips > classify::MAX_K {
        return None;
    }
    let (key, _) = key_of(env, def, args)?;
    // the closed-form language is over machine integers: every dynamic
    // argument must be one (a slice or array state is not summarized)
    let tele = crate::opt::symex::telescope(env, def)?;
    let rel_doms: Vec<&Tm> = tele.binders.iter().filter(|(_, r, _)| *r == sandblaster_kernel::term::Rel::Rel).map(|(_, _, d)| d).collect();
    for (i, d) in rel_doms.iter().enumerate() {
        let dynamic = !key.statics.iter().any(|(j, _)| *j == i);
        if dynamic && !matches!(&***d, Term::IntTy(w) if *w != sandblaster_kernel::term::Width::Int) {
            return None;
        }
    }
    let failed = with_registry(|r| r.failed.contains_key(&key));
    (!failed).then_some(key)
}

/// The user function a generated loop helper (`f::loop#k`, DESIGN.md
/// §7.4) belongs to.
pub fn enclosing_fn(env: &Env, def: GlobalId) -> Option<GlobalId> {
    if env.global_kind(def) != Some(sandblaster_kernel::term::DefKind::LoopHelper) {
        return None;
    }
    let name = env.global_name(def)?;
    let (f, _) = name.rsplit_once("::loop#")?;
    env.lookup_global(f)
}

/// The HIR type of a closed kernel type (machine integers and `bool`).
fn hir_ty(env: &Env, t: &Tm) -> Option<Ty> {
    match &**t {
        Term::IntTy(w) => Some(Ty::Uint(match w {
            Width::U8 => UintTy::U8,
            Width::U16 => UintTy::U16,
            Width::U32 => UintTy::U32,
            Width::U64 => UintTy::U64,
            Width::Usize => UintTy::Usize,
            Width::Int => return None,
        })),
        Term::Ind { ind, params } if *ind == env.bool_ind() && params.is_empty() => Some(Ty::Bool),
        _ => None,
    }
}

/// A function definition standing for a generated loop helper `def` (no
/// HIR item of its own): the enclosing function's, with the helper's
/// relevant parameters (machine integers or `bool`, named by the kernel's
/// binders) and result, and no `requires` — every `requires` of the
/// helper must hold at the key's static arguments (checked by
/// evaluation). Returns the enclosing item and the definition.
fn loop_helper_fn(env: &Env, ext: &Crate, key: &LoopKey, user_globals: &std::collections::HashMap<GlobalId, ItemId>) -> Result<(ItemId, FnDef), String> {
    let f = enclosing_fn(env, key.def).ok_or("not a generated loop helper")?;
    let fid = *user_globals.get(&f).ok_or("the loop's function is not a user function")?;
    let base = ext.fn_def(fid).cloned().ok_or("the loop's function is not a function")?;
    let tele = crate::opt::symex::telescope(env, key.def).ok_or("the loop has no telescope")?;
    let span = ext.item(fid).span;
    let mut fd = base.clone();
    fd.params = Vec::new();
    fd.locals = Vec::new();
    fd.requires = Vec::new();
    fd.generics = Vec::new();
    fd.receiver = None;
    let mut closed = true;
    for (nm, rel, dom) in &tele.binders {
        if *rel != Rel::Rel {
            continue;
        }
        crate::elab::tm::any_node(dom, &mut |n| {
            if matches!(n, Term::Var(_)) {
                closed = false;
            }
            !closed
        });
        let ty = hir_ty(env, dom).ok_or("a loop state that is not machine integers")?;
        let local = LocalId(fd.locals.len() as u32);
        fd.locals.push(LocalDecl { name: invariant::sanitize(nm), ty: ty.clone(), mutable: false, ghost: false, span });
        fd.params.push(Param { pat: Pat { kind: PatKind::Binding { local, mode: BindingMode::ByValue, sub: None }, ty: ty.clone(), span }, ty, lts: Lifetimes(vec![]), span, ghost: false });
    }
    if !closed {
        return Err("a dependent loop state".into());
    }
    fd.ret = hir_ty(env, &tele.ret).ok_or("a loop result that is not a machine integer")?;
    fd.ret_lts = Lifetimes(vec![]);
    // every requires holds at the static arguments (for any dynamic ones)
    let (root, _, np) = crate::opt::drive::root(env, key.def)?;
    let statics = statics_of(env, key, np as usize)?;
    let mut vals: Vec<sandblaster_kernel::value::EnvEntry> = Vec::new();
    let mut b = Budget { steps: 10_000_000 };
    for (i, (_, rel, dom)) in tele.binders.iter().enumerate() {
        match rel {
            Rel::Rel => match &statics[i] {
                Some(t) => vals.push(sandblaster_kernel::value::EnvEntry::Rel(env.eval(&sandblaster_kernel::value::VEnv::default(), Lvl(0), t, &mut b).map_err(|e| format!("{e:?}"))?)),
                None => vals.push(root.venv.0[i].clone()),
            },
            Rel::Irr => {
                let ty = env.eval(&sandblaster_kernel::value::VEnv(std::rc::Rc::new(vals.clone())), Lvl(root.depth()), dom, &mut b).map_err(|e| format!("{e:?}"))?;
                let holds = match &*ty {
                    Value::Eq { lhs, rhs, .. } => env.conv(Lvl(root.depth()), lhs, rhs, &mut b).unwrap_or(false),
                    _ => false,
                };
                if !holds {
                    return Err("a loop requires over its dynamic state".into());
                }
                vals.push(root.venv.0[i].clone());
            }
        }
    }
    Ok((fid, fd))
}

/// The static terms of a key (parsed back from their text).
pub(super) fn statics_of(env: &Env, key: &LoopKey, nparams: usize) -> Result<Vec<Option<Tm>>, String> {
    let mut out = vec![None; nparams];
    for (i, s) in &key.statics {
        let t = env.parse_term(&[], s).map_err(|e| format!("a static argument `{s}`: {e}"))?;
        *out.get_mut(*i).ok_or("a static argument index out of range")? = Some(t);
    }
    Ok(out)
}

/// The analysis of a loop call: the classified loop and its plan.
pub struct Analysis {
    pub plan: invariant::Plan,
    pub steps: u64,
}

/// Steps 1–3 (see the module docs) for `key`.
pub fn analyze(env: &Env, key: &LoopKey, cfg: &LoopConfig) -> Result<Analysis, String> {
    let timing = std::env::var_os("SANDBLASTER_LOOPSUM_TIMING").is_some();
    let t0 = std::time::Instant::now();
    let one = onestep::one_step(env, key.def, 20_000_000)?;
    let mut steps = one.steps;
    let statics = statics_of(env, key, one.nparams as usize)?;
    let lp = classify::classify(env, one, statics)?;
    let t1 = t0.elapsed();
    let name = env.global_name(key.def).map(|s| s.to_string()).unwrap_or_default();
    let profile = project_profile(&lp, cfg.profile.get(&name).map(|v| &v[..]).unwrap_or(&[]));
    let samples = traces::samples(env, &lp, &profile)?;
    let t2 = t0.elapsed();
    let tr = traces::run(env, &lp, &samples, KERNEL_CHECKED_TRACES, 10_000_000)?;
    steps += tr.steps;
    let t3 = t0.elapsed();
    if !cfg.synthesis {
        return Err("synthesis is disabled".into());
    }
    let plan = invariant::plan(env, lp, tr, cfg.synth_max_size, cfg.fault)?;
    if timing {
        eprintln!("[loopsum] timing: classify {t1:?}, samples {:?}, traces {:?}, plan {:?}", t2 - t1, t3 - t2, t0.elapsed() - t3);
    }
    Ok(Analysis { plan, steps })
}

/// The profile samples of this call: those whose integer arguments agree
/// with the key's static integer arguments, projected to the dynamic
/// positions (samples with a non-integer dynamic argument are dropped).
pub(super) fn project_profile(lp: &classify::Loop, profile: &[Vec<Option<u128>>]) -> Vec<Vec<u128>> {
    let dy = lp.dynamic();
    let stat: Vec<(usize, u128)> = lp.statics.iter().enumerate().filter_map(|(i, t)| match &**t.as_ref()? {
            sandblaster_kernel::term::Term::Lit { n, .. } => num_traits::ToPrimitive::to_u128(n).map(|v| (i, v)),
            _ => None,
        }).collect();
    profile
        .iter()
        .filter(|s| s.len() == lp.params.len() && stat.iter().all(|(i, v)| s[*i].is_none_or(|x| x == *v)))
        .filter_map(|s| dy.iter().map(|i| s[*i as usize]).collect::<Option<Vec<u128>>>())
        .collect()
}

/// Traces whose result is also computed by the kernel (the native
/// interpreter is checked against it).
pub const KERNEL_CHECKED_TRACES: usize = 16;

/// The lemma chain's specification rendered from a plan, and the
/// kernel-only closed-form definitions it refers to (committed here):
/// `<prefix>::payload` (a `FirstMatch` payload) and `<prefix>::res`.
pub fn spec_of(env: &mut Env, p: &invariant::Plan, prefix: &str) -> Result<lemmas::Spec, String> {
    use invariant::{Kind, Render};
    let lp = &p.lp;
    let func_text = env.global_name(lp.one.def).map(|s| s.to_string()).ok_or("the loop has no name")?;
    let r = Render { env: &*env };
    // the result type (closed)
    let tele = crate::opt::symex::telescope(env, lp.one.def).ok_or("no telescope")?;
    let ret_tm = &tele.ret;
    let mut closed = true;
    crate::elab::tm::any_node(ret_tm, &mut |n| {
        if matches!(n, Term::Var(_)) {
            closed = false;
        }
        !closed
    });
    if !closed {
        return Err("the loop's result type depends on its parameters".into());
    }
    let ret = env.print_term(&[], ret_tm);
    // state binders: the non-static parameters
    let mut state = Vec::new();
    let mut state_names: Vec<String> = Vec::new(); // per parameter (static: literal at j)
    for (i, prm) in lp.params.iter().enumerate() {
        let nm = invariant::sanitize(&prm.name);
        state_names.push(nm.clone());
        if lp.classes[i] != classify::Class::Static {
            let tyv = lp.one.root.ctx.entries[i].ty.clone();
            state.push((nm, r.ty(&tyv), i as u32));
        }
    }
    let ghost_names: Vec<String> = p.ghosts.iter().map(|g| g.name.clone()).collect();
    let ghosts: Vec<(String, String)> = p.ghosts.iter().filter(|g| !g.shared).map(|g| (g.name.clone(), expr::ty_text(expr::Ty::W(g.width)))).collect();
    // the call's requires at the ghosts (dynamic-at-call parameters are the
    // ghosts; the others their static values)
    let dyn_call: Vec<u32> = lp.dynamic();
    let gnames_for_req: Vec<String> = dyn_call.iter().map(|i| p.ghosts.iter().find(|g| g.param == *i).map(|g| g.name.clone()).unwrap()).collect();
    let ghost_facts = invariant::requires_text(env, lp, None, &gnames_for_req)?;
    // kernel-only definitions
    let gbind: String = p.ghosts.iter().map(|g| format!("({} : {}) -> ", g.name, expr::ty_text(expr::Ty::W(g.width)))).collect();
    let glam: String = p.ghosts.iter().map(|g| format!("({} : {})", g.name, expr::ty_text(expr::Ty::W(g.width)))).collect::<Vec<_>>().join(" ");
    let gapp: String = ghost_names.join(" ");
    let fun = |body: &str| if p.ghosts.is_empty() { body.to_string() } else { format!("fun {glam} => {body}") };
    let mut payload_binder = None;
    let mut payload_src: Option<String> = None;
    let res_text = match &p.kind {
        Kind::FirstMatch { param, payload, unset, .. } => {
            let pty = r.sval_ty(payload);
            let ptext = r.sval(payload, &ghost_names, None);
            payload_src = Some(format!("def[spec] {prefix}::payload : {gbind}{pty} :=\n  {}\n", fun(&ptext)));
            payload_binder = Some(state_names[*param as usize].clone());
            // the result: `match G | false => unset | true => payload ḡ`
            match &p.result {
                classify::SVal::Ite(c, _, _) => format!(
                    "match {} : Bool as _ return {ret} with | false => {} | true => {prefix}::payload {gapp} end",
                    c.text(&ghost_names, None),
                    r.sval(unset, &ghost_names, None)
                ),
                other => r.sval(other, &ghost_names, None),
            }
        }
        Kind::Search => r.sval(&p.result, &ghost_names, None),
    };
    let res_src = format!("def[spec] {prefix}::res : {gbind}{ret} :=\n  {}\n", fun(&res_text));
    let res = if p.ghosts.is_empty() { format!("{prefix}::res") } else { format!("{prefix}::res {gapp}") };
    // per j: requires, invariant, lhs
    let dyn_state_names: Vec<String> = state.iter().map(|(n, _, _)| n.clone()).collect();
    let mut reqs = Vec::new();
    let mut inv = Vec::new();
    let mut lhs = Vec::new();
    for jj in 0..=lp.k {
        reqs.push(invariant::requires_text(env, lp, Some(jj), &dyn_state_names)?);
        // names at j: statics as their literal text
        let names_j: Vec<String> = (0..lp.params.len())
            .map(|i| {
                if lp.classes[i] == classify::Class::Static {
                    match &lp.static_seq[jj as usize][i] {
                        Some(classify::CVal::N(expr::Val::W(w, n))) => expr::lit_text(*w, *n),
                        Some(classify::CVal::N(expr::Val::B(b))) => b.to_string(),
                        _ => state_names[i].clone(),
                    }
                } else {
                    state_names[i].clone()
                }
            })
            .collect();
        let mut conj = Vec::new();
        for (i, c) in lp.classes.iter().enumerate() {
            let nm = &state_names[i];
            match c {
                classify::Class::Shift(_) | classify::Class::BitDigit { .. } | classify::Class::GuardCount { .. } => {
                    let t = p.templates[i].as_ref().ok_or("a template")?;
                    let tj = invariant::simp(t, Some(jj as u128));
                    let w = lp.params[i].width.unwrap();
                    conj.push((format!(".i_{nm}"), format!("Eq({}, {nm}, {})", expr::ty_text(expr::Ty::W(w)), tj.text(&ghost_names, None))));
                }
                classify::Class::Linear { rel } => {
                    let text = relation_text(env, lp, &p.ghosts, rel, &names_j)?;
                    conj.push((format!(".i_{nm}"), text));
                }
                classify::Class::MaskedCount { .. } => {
                    // in `Int` (no carries), split by the threshold's regime
                    let t = invariant::masked_template(env, lp, &p.ghosts, i as u32, true).ok_or("a MaskedCount template")?;
                    let tj = invariant::simp(&t, Some(jj as u128));
                    let w = lp.params[i].width.unwrap();
                    conj.push((format!(".i_{nm}"), format!("Eq(Int, #cast_{}_int({nm}), {})", sandblaster_kernel::prim::width_suffix(w), tj.text(&ghost_names, None))));
                }
                classify::Class::FirstMatch => {
                    let Kind::FirstMatch { pr, unset, .. } = &p.kind else { return Err("a FirstMatch parameter in a search".into()) };
                    let pty = r.sval_ty(unset);
                    conj.push((
                        format!(".i_{nm}"),
                        format!(
                            "Eq({pty}, {nm}, match {} : Bool as _ return {pty} with | false => {} | true => {prefix}::payload {gapp} end)",
                            pr.text(&names_j, None),
                            r.sval(unset, &ghost_names, None)
                        ),
                    ));
                }
                _ => {}
            }
        }
        // alive (a search): no earlier iteration's exit condition held,
        // compressed into linear bounds and masks per ghost
        if matches!(p.kind, Kind::Search) && invariant::has_dynamic_exit(lp) {
            let mut stays: Vec<(expr::E, bool)> = Vec::new();
            for i in 0..jj {
                for (g, b) in exit_condition(lp, i)? {
                    let gi = invariant::to_ghost(&classify::SVal::Ce(g), &p.templates, None, &expr::lit(Width::U32, i as u128)).ok_or("the exit condition has no closed form")?;
                    let classify::SVal::Ce(gi) = gi else { unreachable!() };
                    stays.push((invariant::simp(&gi, None), b));
                }
            }
            conj.extend(alive_facts(&stays, jj, &ghost_names));
        }
        inv.push(conj);
        // the loop call
        let mut args: Vec<String> = Vec::new();
        for (i, prm) in lp.params.iter().enumerate() {
            let _ = prm;
            args.push(if lp.classes[i] == classify::Class::Static { names_j[i].clone() } else { state_names[i].clone() });
        }
        for ri in 0..reqs[jj as usize].len() {
            args.push(format!(".r{ri}"));
        }
        lhs.push(format!("{func_text} {}", args.join(" ")));
    }
    // families the proofs may use
    let mut families = vec![bitfam::MaskSplit, bitfam::PopcntStep];
    let mut word = Width::U64;
    {
        let mut atoms = Vec::new();
        witness_atoms(&p.witness, &mut atoms);
        for a in atoms {
            if let expr::CE::Op(o, args) = &*a {
                match o {
                    sandblaster_kernel::term::PrimOp::LeadingZeros(w) => {
                        word = *w;
                        if matches!(&*args[0], expr::CE::Op(sandblaster_kernel::term::PrimOp::Xor(_), _)) {
                            families.push(bitfam::ClzXorPrefix);
                        }
                        families.push(bitfam::LzRange);
                    }
                    sandblaster_kernel::term::PrimOp::TrailingZeros(w) => {
                        word = *w;
                        families.push(bitfam::TzRange);
                    }
                    _ => {}
                }
            }
        }
    }
    families.sort_by_key(|f| f.stem());
    families.dedup();
    let _ = r;
    if let Some(src) = payload_src {
        env.load_core(&src, &mut Budget { steps: 50_000_000 }).map_err(|e| format!("the payload definition: {e}\n{src}"))?;
    }
    env.load_core(&res_src, &mut Budget { steps: 50_000_000 }).map_err(|e| format!("the result definition: {e}\n{res_src}"))?;
    let unset_ctor = match &p.kind {
        Kind::FirstMatch { unset: classify::SVal::Ctor { ctor, .. }, .. } => Some(*ctor),
        _ => None,
    };
    Ok(lemmas::Spec { func: lp.one.def, func_text, ret, k: lp.k, state, ghosts, ghost_names, ghost_facts, reqs, inv, lhs, res, payload_binder, witness: p.witness.clone(), families, word, unset_ctor })
}

use crate::auto::bitlib::Family as bitfam;

/// The bit-count atoms of a witness expression.
fn witness_atoms(e: &expr::E, out: &mut Vec<expr::E>) {
    match &**e {
        expr::CE::Op(sandblaster_kernel::term::PrimOp::LeadingZeros(_) | sandblaster_kernel::term::PrimOp::TrailingZeros(_), _) => out.push(e.clone()),
        expr::CE::Op(_, a) => a.iter().for_each(|x| witness_atoms(x, out)),
        expr::CE::Ite(c, a, b) => {
            witness_atoms(c, out);
            witness_atoms(a, out);
            witness_atoms(b, out);
        }
        expr::CE::ShrSat(a, b) | expr::CE::ShlSat(a, b) => {
            witness_atoms(a, out);
            witness_atoms(b, out);
        }
        expr::CE::DivLit(a, _) => witness_atoms(a, out),
        _ => {}
    }
}

/// The facts that no earlier exit happened (`stays`: each exit guard at
/// its iteration with the value that exits), compressed: a comparison of a
/// ghost (or of its literal shift) with a literal becomes a bound on the
/// ghost, and only the tightest lower and upper bound per ghost is kept; bit
/// tests `(y >> k) & 1` become the mask `y & (2^m − 1) = 0` for the
/// consecutive zero bits from 0; anything else is kept as it is (named by
/// its distance back).
fn alive_facts(stays: &[(expr::E, bool)], jj: u32, names: &[String]) -> Vec<(String, String)> {
    use sandblaster_kernel::term::PrimOp;
    let mut lo: BTreeMap<u32, (Width, u128)> = BTreeMap::new(); // y ≥ c
    let mut hi: BTreeMap<u32, (Width, u128)> = BTreeMap::new(); // y < c
    let mut zero_bits: BTreeMap<u32, (Width, Vec<u32>)> = BTreeMap::new();
    let mut raw: Vec<(String, String)> = Vec::new();
    let var_shift = |e: &expr::E| -> Option<(u32, Width, u32)> {
        match &**e {
            expr::CE::Var(v, w) => Some((*v, *w, 0)),
            expr::CE::Op(PrimOp::WShr(w), a) => match (&*a[0], &*a[1]) {
                (expr::CE::Var(v, _), expr::CE::Lit(_, k)) if (*k as u32) < expr::bits(*w) => Some((*v, *w, *k as u32)),
                _ => None,
            },
            _ => None,
        }
    };
    for (d, (g, b)) in stays.iter().enumerate() {
        let dist = jj as usize - d;
        let mut done = false;
        if let expr::CE::Op(op, a) = &**g
            && a.len() == 2
        {
            // bit tests
            if let (PrimOp::Eq(w), expr::CE::Op(PrimOp::And(_), m)) = (op, &*a[0])
                && matches!(&*m[1], expr::CE::Lit(_, 1))
                && let expr::CE::Lit(_, c) = &*a[1]
                && *c <= 1
                && let Some((v, _, k)) = var_shift(&m[0])
            {
                let stay = if *b { 1 - *c } else { *c };
                if stay == 0 {
                    zero_bits.entry(v).or_insert((*w, Vec::new())).1.push(k);
                    done = true;
                }
            }
            // comparisons with a literal: y >> k ⋈ c
            if !done
                && let (Some((v, w, k)), expr::CE::Lit(_, c)) = (var_shift(&a[0]), &*a[1])
            {
                // the relation that holds when staying
                let rel = match (op, b) {
                    (PrimOp::Lt(_), true) | (PrimOp::Ge(_), false) => Some(">="),
                    (PrimOp::Lt(_), false) | (PrimOp::Ge(_), true) => Some("<"),
                    (PrimOp::Le(_), true) | (PrimOp::Gt(_), false) => Some(">"),
                    (PrimOp::Le(_), false) | (PrimOp::Gt(_), true) => Some("<="),
                    (PrimOp::Eq(_), true) if *c == 0 => Some(">"),
                    _ => None,
                };
                // (y >> k) ≥ c ⇔ y ≥ c·2^k; (y >> k) < c ⇔ y < c·2^k
                let scale = |c: u128| c.checked_mul(1u128 << k);
                match rel {
                    Some(">=") | Some(">") => {
                        let c2 = if rel == Some(">") { c + 1 } else { *c };
                        if let Some(x) = scale(c2).filter(|x| *x <= expr::mask(w)) {
                            let e = lo.entry(v).or_insert((w, 0));
                            e.1 = e.1.max(x);
                            done = true;
                        }
                    }
                    Some("<") | Some("<=") => {
                        let c2 = if rel == Some("<=") { c + 1 } else { *c };
                        if let Some(x) = scale(c2) {
                            let e = hi.entry(v).or_insert((w, u128::MAX));
                            e.1 = e.1.min(x);
                            done = true;
                        }
                    }
                    _ => {}
                }
            }
        }
        if !done {
            raw.push((format!(".a{dist}"), negated_guard_text(g, *b, names)));
        }
    }
    let mut out = Vec::new();
    let nm = |v: &u32| names.get(*v as usize).cloned().unwrap_or_else(|| "?".into());
    for (v, (w, c)) in &lo {
        if *c > 0 {
            out.push((format!(".alo_{}", nm(v)), format!("Eq(Bool, #le_{}({}, {}), true)", sandblaster_kernel::prim::width_suffix(*w), expr::lit_text(*w, *c), nm(v))));
        }
    }
    for (v, (w, c)) in &hi {
        if *c <= expr::mask(*w) {
            out.push((format!(".ahi_{}", nm(v)), format!("Eq(Bool, #lt_{}({}, {}), true)", sandblaster_kernel::prim::width_suffix(*w), nm(v), expr::lit_text(*w, *c))));
        } else if *c == expr::mask(*w) + 1 {
            // y < 2^w always
        }
    }
    for (v, (w, mut ks)) in zero_bits {
        ks.sort();
        ks.dedup();
        let m = ks.iter().enumerate().take_while(|(i, k)| *i as u32 == **k).count() as u32;
        let ws = sandblaster_kernel::prim::width_suffix(w);
        if m > 0 {
            let mask = if m >= expr::bits(w) { expr::mask(w) } else { (1u128 << m) - 1 };
            let lhs = if mask == expr::mask(w) { nm(&v) } else { format!("#and_{ws}({}, {})", nm(&v), expr::lit_text(w, mask)) };
            out.push((format!(".amask_{}", nm(&v)), format!("Eq({}, {lhs}, 0{ws})", expr::ty_text(expr::Ty::W(w)))));
        }
        for k in ks.into_iter().skip(m as usize) {
            out.push((format!(".abit_{}_{k}", nm(&v)), format!("Eq({}, #and_{ws}(#wshr_{ws}({}, {k}u32), 1{ws}), 0{ws})", expr::ty_text(expr::Ty::W(w)), nm(&v))));
        }
    }
    out.extend(raw);
    out
}

/// The statement that a guard does not take its exit value `b`: for a bit
/// test `(y & 1) == c` (`c ∈ {0, 1}`) the other bit value as an equation
/// (linear arithmetic needs no split for it), else `Eq(Bool, g, !b)`.
fn negated_guard_text(g: &expr::E, b: bool, names: &[String]) -> String {
    use sandblaster_kernel::term::PrimOp;
    if let expr::CE::Op(PrimOp::Eq(w), a) = &**g
        && let expr::CE::Op(PrimOp::And(_), m) = &*a[0]
        && matches!(&*m[1], expr::CE::Lit(_, 1))
        && let expr::CE::Lit(_, c) = &*a[1]
        && *c <= 1
    {
        // exit when bit == c (b) or bit != c (!b); stay otherwise
        let stay = if b { 1 - *c } else { *c };
        return format!("Eq({}, {}, {})", expr::ty_text(expr::Ty::W(*w)), a[0].text(names, None), expr::lit_text(*w, stay));
    }
    format!("Eq(Bool, {}, {})", g.text(names, None), if b { "false" } else { "true" })
}

/// The exit condition at iteration `jj` of a search: the dynamic guards of
/// the one exit path feasible there (static guards evaluated), as
/// `(guard, value)`; more than one path or guard is refused.
fn exit_condition(lp: &classify::Loop, jj: u32) -> Result<Vec<(expr::E, bool)>, String> {
    let feasible: Vec<&classify::ExitPath> = lp.exits.iter().filter(|e| invariant::exit_feasible_at(lp, e, jj) && !invariant::exit_static(lp, e)).collect();
    if feasible.len() != 1 {
        return Err(format!("{} dynamic exit paths at iteration {jj}", feasible.len()));
    }
    let dynamic: Vec<(expr::E, bool)> = feasible[0]
        .guards
        .iter()
        .filter(|(g, _)| {
            let mut vs = Vec::new();
            g.vars(&mut vs);
            vs.iter().any(|v| lp.classes[*v as usize] != classify::Class::Static)
        })
        .cloned()
        .collect();
    if dynamic.len() != 1 {
        return Err(format!("an exit with {} dynamic guards", dynamic.len()));
    }
    Ok(dynamic)
}

/// A linear relation `Σ cᵢ·xᵢ = Σ cᵢ·xᵢ(0)` as an `Int` equation over the
/// state binders (negative coefficients on the other side).
fn relation_text(env: &Env, lp: &classify::Loop, ghosts: &[invariant::Ghost], rel: &[(u32, i128)], names: &[String]) -> Result<String, String> {
    let cast = |w: Width, x: &str| format!("#cast_{}_int({x})", sandblaster_kernel::prim::width_suffix(w));
    let term = |c: i128, x: String| if c.abs() == 1 { x } else { format!("#imul({}int, {x})", c.abs()) };
    let sum = |ts: Vec<String>| -> String {
        let mut it = ts.into_iter();
        let first = it.next().unwrap_or_else(|| "0int".into());
        it.fold(first, |acc, t| format!("#iadd({acc}, {t})"))
    };
    let (mut lhs, mut rhs) = (Vec::new(), Vec::new());
    // the constant: Σ cᵢ·xᵢ(0), split by sign as well
    let (mut klhs, mut krhs) = (Vec::new(), Vec::new());
    for (v, c) in rel {
        let w = lp.params[*v as usize].width.ok_or("a relation over a non-integer")?;
        let x = cast(w, &names[*v as usize]);
        if *c > 0 {
            lhs.push(term(*c, x));
        } else {
            rhs.push(term(*c, x));
        }
        // entry value
        let e0 = match &lp.statics[*v as usize] {
            Some(t) => match classify::closed_cval(env, t) {
                Some(classify::CVal::N(expr::Val::W(_, n))) => format!("{n}int"),
                _ => return Err("a relation over a non-numeric entry".into()),
            },
            None => {
                let g = ghosts.iter().find(|g| g.param == *v).ok_or("a ghost")?;
                cast(w, &g.name)
            }
        };
        if *c > 0 {
            krhs.push(term(*c, e0));
        } else {
            klhs.push(term(*c, e0));
        }
    }
    lhs.extend(klhs);
    rhs.extend(krhs);
    Ok(format!("Eq(Int, {}, {})", sum(lhs), sum(rhs)))
}

// ---------------------------------------------------------------------------
// The loop helper: printing, elaboration, links (called by the optimizer).
// ---------------------------------------------------------------------------

/// `e` with the locals of `map` replaced by their expressions (`None` when
/// `e` has a construct the substitution does not handle and mentions one).
pub(super) fn subst_locals(e: &Expr, map: &std::collections::HashMap<LocalId, Expr>) -> Option<Expr> {
    let go = |x: &Expr| subst_locals(x, map);
    let bx = |x: &Expr| go(x).map(Box::new);
    let kind = match &e.kind {
        ExprKind::Local(l) => return Some(map.get(l).cloned().unwrap_or_else(|| e.clone())),
        ExprKind::Lit(_) | ExprKind::Const(_) | ExprKind::BuiltinConst(_) => e.kind.clone(),
        ExprKind::Unary(o, x) => ExprKind::Unary(*o, bx(x)?),
        ExprKind::Binary(o, a, b) => ExprKind::Binary(*o, bx(a)?, bx(b)?),
        ExprKind::Cast(x, t) => ExprKind::Cast(bx(x)?, t.clone()),
        ExprKind::Coerce(c, x) => ExprKind::Coerce(*c, bx(x)?),
        ExprKind::Ref(x) => ExprKind::Ref(bx(x)?),
        ExprKind::Deref(x) => ExprKind::Deref(bx(x)?),
        ExprKind::PropEq(a, b) => ExprKind::PropEq(bx(a)?, bx(b)?),
        ExprKind::PropNe(a, b) => ExprKind::PropNe(bx(a)?, bx(b)?),
        ExprKind::PropAnd(a, b) => ExprKind::PropAnd(bx(a)?, bx(b)?),
        ExprKind::PropOr(a, b) => ExprKind::PropOr(bx(a)?, bx(b)?),
        ExprKind::PropNot(x) => ExprKind::PropNot(bx(x)?),
        ExprKind::Implies(a, b) => ExprKind::Implies(bx(a)?, bx(b)?),
        ExprKind::Iff(a, b) => ExprKind::Iff(bx(a)?, bx(b)?),
        ExprKind::Call { callee, args } => ExprKind::Call { callee: callee.clone(), args: args.iter().map(go).collect::<Option<_>>()? },
        ExprKind::Field { base, index, name } => ExprKind::Field { base: bx(base)?, index: *index, name: name.clone() },
        ExprKind::Tuple(xs) => ExprKind::Tuple(xs.iter().map(go).collect::<Option<_>>()?),
        ExprKind::If { cond, then, els } => ExprKind::If { cond: bx(cond)?, then: bx(then)?, els: match els {
            Some(x) => Some(bx(x)?),
            None => None,
        } },
        _ => {
            // any other construct: only when it mentions no mapped local
            struct V<'m>(&'m std::collections::HashMap<LocalId, Expr>, bool);
            impl crate::visit::Visitor for V<'_> {
                fn expr(&mut self, e: &Expr) {
                    if let ExprKind::Local(l) = &e.kind
                        && self.0.contains_key(l)
                    {
                        self.1 = true;
                    }
                    crate::visit::walk_expr(self, e);
                }
            }
            let mut v = V(map, false);
            crate::visit::Visitor::expr(&mut v, e);
            if v.1 {
                return None;
            }
            e.kind.clone()
        }
    };
    Some(Expr::new(kind, e.ty.clone(), e.span))
}

/// A `requires` of the loop with the static arguments of `map` substituted
/// ([`subst_locals`]). When it mentions one of them its source text no
/// longer describes it (it names parameters the helper does not have): its
/// span is dropped, so the printer's `# Safety` doc prints the substituted
/// expression instead of the source snippet.
pub(super) fn subst_requires(r: &Expr, map: &std::collections::HashMap<LocalId, Expr>) -> Option<Expr> {
    let mut out = subst_locals(r, map)?;
    struct V<'m>(&'m std::collections::HashMap<LocalId, Expr>, bool);
    impl crate::visit::Visitor for V<'_> {
        fn expr(&mut self, e: &Expr) {
            if let ExprKind::Local(l) = &e.kind
                && self.0.contains_key(l)
            {
                self.1 = true;
            }
            crate::visit::walk_expr(self, e);
        }
    }
    let mut v = V(map, false);
    crate::visit::Visitor::expr(&mut v, r);
    if v.1 {
        out.span = crate::span::Span::DUMMY;
    }
    Some(out)
}

/// Builds the helpers of `keys` that are not built yet (see the module
/// docs); a key that fails is recorded (`Registry::failed`) and its reason
/// returned.
#[allow(clippy::too_many_arguments)]
pub(super) fn ensure_loops(cx: &mut super::Ctx<'_>, ext: &mut Crate, chain: &mut crate::elab::ProverChain, eopts: &crate::elab::Options, keys: &[LoopKey], user_globals: &std::collections::HashMap<GlobalId, ItemId>) -> Result<(), String> {
    // every key is attempted (each failure recorded, so one re-drive keeps
    // all failed loops); the first failure is returned
    let mut first: Option<String> = None;
    for key in keys {
        if with_registry(|r| r.helpers.contains_key(key)) {
            continue;
        }
        if let Some(f) = with_registry(|r| r.failed.get(key).cloned()) {
            first.get_or_insert(f.reason);
            continue;
        }
        let t0 = std::time::Instant::now();
        let limit = with_registry(|r| r.config.steps_per_loop);
        meter::start(limit);
        let r = build(cx, ext, chain, eopts, key, user_globals);
        lemmas::reset_shared();
        let exhausted = meter::exhausted();
        let used = meter::stop();
        // the summary's steps are what the meter charged (every search and
        // check of it, whatever rung); the caps keep it within the limit
        // (up to the fixed evaluation budgets of the analysis), and a
        // search or check the meter starved fails the summary
        let r = match r {
            Ok(mut h) => {
                h.steps = used;
                Ok(h)
            }
            Err(mut f) => {
                if exhausted {
                    f.reason = format!("the loop summary's step budget ({limit}) is exhausted: {}", f.reason);
                }
                f.steps = used;
                Err(f)
            }
        };
        if std::env::var_os("SANDBLASTER_OPT_TIMING").is_some() {
            eprintln!("opt: timing loop summary of {} at {:?}: {:?} ({})", cx.out.env.global_name(key.def).unwrap_or_default(), key.statics, t0.elapsed(), match &r { Ok(_) => "ok".to_string(), Err(f) => format!("failed: {}", f.reason.chars().take(300).collect::<String>()) });
        }
        match r {
            Ok(h) => with_registry(|reg| {
                reg.helpers.insert(key.clone(), h);
            }),
            Err(f) => {
                let reason = f.reason.clone();
                if std::env::var_os("SANDBLASTER_LOOPSUM_TRACE").is_some() {
                    eprintln!("[loopsum] no summary of `{}`: {reason}", cx.out.env.global_name(key.def).unwrap_or_default());
                }
                // a lemma the kernel rejected is an optimizer fault (a
                // warning, a build error under strict options); the loop stays
                if reason.contains("kernel rejected") && !exhausted {
                    cx.failure(format!("the loop summary of `{}` was rejected: {}", cx.out.env.global_name(key.def).unwrap_or_default(), reason.chars().take(400).collect::<String>()));
                }
                with_registry(|reg| {
                    reg.failed.insert(key.clone(), f);
                });
                first.get_or_insert(reason);
            }
        }
    }
    match first {
        Some(r) => Err(r),
        None => Ok(()),
    }
}

fn build(cx: &mut super::Ctx<'_>, ext: &mut Crate, chain: &mut crate::elab::ProverChain, eopts: &crate::elab::Options, key: &LoopKey, user_globals: &std::collections::HashMap<GlobalId, ItemId>) -> Result<LoopHelper, LoopFailure> {
    let fail = |reason: String, steps: u64| LoopFailure { reason, steps };
    let mut cfg = with_registry(|r| r.config.clone());
    // a user recursion, or a generated loop helper (plan O6: `for` loops)
    let generated = enclosing_fn(&cx.out.env, key.def).is_some();
    let (fid, fd) = if generated {
        loop_helper_fn(&cx.out.env, ext, key, user_globals).map_err(|e| fail(e, 0))?
    } else {
        let fid = *user_globals.get(&key.def).ok_or_else(|| fail("the loop is not a user function".into(), 0))?;
        (fid, ext.fn_def(fid).cloned().ok_or_else(|| fail("the loop is not a function".into(), 0))?)
    };
    let loop_name = cx.out.env.global_name(key.def).map(|s| s.to_string()).unwrap_or_default();
    cfg.fault = cx.opts.hooks().and_then(|h| h.loop_fault(&loop_name));
    // R6: the early-exit rung with a wrong stop test (the kernel judges)
    if cfg.fault == Some(LoopFault::EarlyExitPayloadSet) {
        return rungs::build_early(cx, ext, chain, eopts, key, user_globals, true, "a simulated fault");
    }
    // R28, R29: the set-bit rung's enumeration lemma or jump wrong (the
    // kernel judges)
    if matches!(cfg.fault, Some(LoopFault::EnumArmMisstated | LoopFault::SetBitsWrongJump)) {
        return setbits::build_set_bits(cx, ext, chain, eopts, key, user_globals, cfg.fault, "a simulated fault");
    }
    // 1–3: analysis (no closed form: the fallback rungs, design §7.6)
    let an = match analyze(&cx.out.env, key, &cfg) {
        Ok(an) => {
            meter::charge(an.steps);
            an
        }
        Err(e) if generated => return Err(fail(format!("no closed form ({e})"), 0)),
        Err(e) => return fallback(cx, ext, chain, eopts, key, user_globals, &cfg, &e),
    };
    let plan = an.plan;
    let describe = invariant::describe(&plan, &cx.out.env);
    let n = with_registry(|r| {
        let c = r.count.entry(key.def).or_insert(0);
        let n = *c;
        *c += 1;
        n
    });
    // (a generated loop's name, `f::loop#k`, is not a core identifier: the
    // result definition is parsed)
    let prefix = format!("{}::sum{n}", loop_name.replace('#', "_"));
    // 4: the lemma chain
    let spec = spec_of(&mut cx.out.env, &plan, &prefix).map_err(|e| fail(format!("the lemma statements: {e}"), an.steps))?;
    // the rungs by cost (plan O8, design §7.6, §10.2): a weaker rung goes
    // first only when it is ≥ 3% cheaper than the closed form on the
    // traces (profile samples and corners)
    let costs = rung_costs(cx, ext, key, &plan, &prefix);
    let order = costs.order();
    let costs_note = format!("; rung costs (portable, traces): {}", costs.describe());
    if cfg.fault.is_none() && !generated && order.first().is_some_and(|r| *r != crate::opt::Rung::ClosedForm) {
        let why = format!("a cheaper rung than the closed form{costs_note}");
        let mut cfg2 = cfg.clone();
        cfg2.prefer_set_bits = order.first() == Some(&crate::opt::Rung::SetBits);
        if let Ok(mut h) = fallback(cx, ext, chain, eopts, key, user_globals, &cfg2, &why) {
            h.describe.push_str(&costs_note);
            return Ok(h);
        }
    }
    let cache = if cfg.fault.is_some() { None } else { cx.cache.as_ref() };
    let (lemmas, stats) = lemmas::build_chain_trusting(&mut cx.out.env, &spec, &prefix, cfg.steps_per_loop, cache, cfg.fault.is_some()).map_err(|e| fail(format!("the lemma chain: {e}"), an.steps))?;
    let steps = an.steps + stats.total();
    let Some(Some(lemma0)) = lemmas.first().cloned() else {
        let why = format!("the per-literal lemmas did not close ({}/{}): {}", lemmas.iter().filter(|x| x.is_some()).count(), lemmas.len(), stats.first_failure.clone().unwrap_or_default());
        // a simulated closed-form fault is judged by the kernel, not rescued
        if cfg.fault.is_some() || generated {
            return Err(fail(why, steps));
        }
        return fallback(cx, ext, chain, eopts, key, user_globals, &cfg, &why).map_err(|mut f| {
            f.steps += steps;
            f
        });
    };
    // 5: the helper — the loop's dynamic parameters, its requires at the
    // static arguments, the closed form printed by the residual printer
    let lp = &plan.lp;
    let dy: Vec<u32> = lp.dynamic();
    let mut hf = fd.clone();
    let mut smap: std::collections::HashMap<LocalId, Expr> = std::collections::HashMap::new();
    for (i, p) in fd.params.iter().enumerate() {
        if let Some(t) = &lp.statics[i]
            && let PatKind::Binding { local, .. } = &p.pat.kind
            && let Term::Lit { n: v, .. } = &**t
            && let Some(v) = num_traits::ToPrimitive::to_u128(v)
        {
            smap.insert(*local, Expr::new(ExprKind::Lit(Lit::Int(v)), p.ty.clone(), p.span));
        }
    }
    hf.params = dy.iter().map(|i| fd.params[*i as usize].clone()).collect();
    hf.requires = fd.requires.iter().map(|r| subst_requires(r, &smap)).collect::<Option<Vec<_>>>().ok_or_else(|| fail("a requires over a non-integer static argument".into(), steps))?;
    hf.ensures = None;
    hf.decreases = None;
    hf.recursion = Recursion::None;
    hf.specialize = false;
    hf.implements = None;
    hf.inline = Some(Inline::Always);
    let (body, locals, nodes) = {
        let env = &cx.out.env;
        let mut st = crate::auto::state::St::new(env, &sandblaster_kernel::api::Ctx::default(), 0);
        for i in &dy {
            let ty = lp.one.root.ctx.entries[*i as usize].ty.clone();
            st.push_raw(env, std::rc::Rc::from(invariant::sanitize(&lp.params[*i as usize].name).as_str()), sandblaster_kernel::term::Rel::Rel, ty);
        }
        let names: Vec<String> = st.ctx.entries.iter().map(|e| e.name.to_string()).collect();
        let res_text = if names.is_empty() { format!("{prefix}::res") } else { format!("{prefix}::res {}", names.join(" ")) };
        let ns: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
        let t = env.parse_term(&ns, &res_text).map_err(|e| fail(format!("the closed form's application: {e}"), steps))?;
        let v = st.eval(env, &t, &mut Budget { steps: 20_000_000 }).map_err(|e| fail(format!("the closed form's value: {e:?}"), steps))?;
        let node = crate::opt::drive::tree::Node { depth: st.depth() + hf.requires.len() as u32, steps: vec![], kind: crate::opt::drive::tree::NodeKind::Leaf(v) };
        let maps = crate::opt::residual::Maps::new(env, ext, &cx.out.fn_globals, &cx.out.adts).map_err(|e| fail(e, steps))?;
        let op = |_g: GlobalId| false;
        let ev = crate::opt::drive::step::Eval { env, opaque: &op };
        let r = crate::opt::residual::tree::build_tree(env, &maps, ext, &hf, &node, &ev, &BTreeMap::new(), &BTreeMap::new(), 20_000, ext.item(fid).span, None).map_err(|e| fail(format!("the closed form is not printable: {e}"), steps))?;
        (r.body, r.locals, r.nodes)
    };
    hf.body = FnBody::Exec(body);
    hf.locals = locals;
    let orig = ext.item(fid).clone();
    let mut hname = match loop_name.rsplit_once("::loop#") {
        Some((_, k)) if generated => format!("{}__loop{k}__closed", orig.name),
        _ => format!("{}__closed", orig.name),
    };
    if n > 0 {
        hname = format!("{hname}{n}");
    }
    let hid = super::push_elaborate(cx, ext, chain, eopts, &orig, hname.clone(), hf, false).map_err(|(why, _)| fail(format!("the helper `{hname}` did not elaborate: {why}"), steps))?;
    let hg = match cx.out.fn_globals.get(&hid).copied() {
        Some(g) => g,
        None => {
            super::pop_driven(cx, ext, hid);
            return Err(fail("the helper has no global".into(), steps));
        }
    };
    // 6: the summary lemma `loop(statics, d̄) = res d̄` and the link
    // `H d̄ = loop(statics, d̄)`, over the helper's telescope
    let links = link_lemmas(&mut cx.out.env, lp, &spec, &plan, key, &prefix, hg, lemma0);
    let (summary_name, lemma) = match links {
        Ok(x) => x,
        Err(e) => {
            ext.items[hid.0 as usize].ghost = true;
            super::pop_driven(cx, ext, hid);
            return Err(fail(format!("the helper's link: {e}"), steps));
        }
    };
    cx.set_aside_obligations(hid);
    // 7: the facts it exports (design §6.4; a failure only loses them)
    let mut steps = steps;
    let mut fact_note = String::new();
    let loop_facts = if cfg.fault.is_some() {
        None
    } else {
        let t0 = std::time::Instant::now();
        let adts: Vec<(IndId, ItemId)> = cx.out.adts.iter().map(|(i, d)| (*d, *i)).collect();
        let names = |ind: IndId| -> Option<Vec<String>> {
            let id = adts.iter().find(|(d, _)| *d == ind)?.1;
            match &ext.item(id).kind {
                ItemKind::Struct(sd) => sd.fields.iter().map(|f| f.name.clone()).collect(),
                _ => None,
            }
        };
        let r = facts::build(&mut cx.out.env, &plan, &spec, &prefix, hg, key, &names, cx.cache.as_ref(), false);
        if std::env::var_os("SANDBLASTER_OPT_TIMING").is_some() {
            eprintln!("opt: timing loop facts of {loop_name}: {:?} ({})", t0.elapsed(), match &r { Ok(Some(f)) => format!("{} facts", f.conjuncts.len()), Ok(None) => "none".into(), Err(e) => format!("failed: {}", e.chars().take(300).collect::<String>()) });
        }
        match r {
            Ok(Some(f)) => {
                steps += f.steps;
                fact_note = format!("; exported facts {}", f.conjuncts.iter().map(|(_, s)| format!("`{s}`")).collect::<Vec<_>>().join(", "));
                Some(f)
            }
            Ok(None) => None,
            Err(e) => {
                if e.contains("kernel rejected") && !meter::exhausted() {
                    cx.failure(format!("the facts of the loop summary of `{loop_name}` were rejected: {}", e.chars().take(400).collect::<String>()));
                }
                fact_note = format!("; no exported facts ({})", e.chars().take(200).collect::<String>());
                None
            }
        }
    };
    Ok(LoopHelper { item: hid, global: hg, lemma, rung: crate::opt::Rung::ClosedForm, facts: Vec::new(), loop_facts, summary_lemma: summary_name, describe: format!("{describe}; helper {hname} ({nodes} nodes){fact_note}{costs_note}"), steps })
}

/// The costs of a loop's rungs on the crate's portable tables (design
/// §10.2; plan O8): the closed form is its `res` definition; an early exit
/// runs the loop body until the payload is found; a set-bit iteration runs
/// it once per active iteration (one where a dynamic parameter changes)
/// plus the jump (`leading_zeros` and a variable shift). Trip counts are the
/// means over the traces (the `PROFILE.json` samples and the seeded
/// corners); each loop exit costs one mispredicted branch.
fn rung_costs(cx: &super::Ctx<'_>, ext: &Crate, key: &LoopKey, plan: &invariant::Plan, prefix: &str) -> crate::opt::cost::model::LoopRungCosts {
    use crate::opt::Rung;
    use crate::opt::cost::tables::Op;
    let env = &cx.out.env;
    let model = crate::opt::cost::model::SetModel::portable(ext.target.arch.name(), &cx.opts.tuning);
    let t = &model.tables;
    // the closed form's own definitions (`<prefix>::payload`, …) are part
    // of it: an application of one costs its body
    fn expand(env: &sandblaster_kernel::api::Env, model: &crate::opt::cost::model::SetModel, prefix: &str, head: &sandblaster_kernel::term::Tm, depth: u32) -> Option<u64> {
        let sandblaster_kernel::term::Term::Global(g) = &**head else { return None };
        if depth > 4 || !env.global_name(*g).is_some_and(|n| n.starts_with(prefix)) {
            return None;
        }
        let b = env.global_body(*g)?;
        Some(model.term_cost(&b, &|h| expand(env, model, prefix, h, depth + 1)))
    }
    let term = |g: Option<GlobalId>| g.and_then(|g| env.global_body(g)).map(|b| model.term_cost(&b, &|h| expand(env, &model, prefix, h, 0)));
    let Some(closed) = term(env.lookup_global(&format!("{prefix}::res"))) else { return Default::default() };
    let body = term(Some(key.def)).unwrap_or(0);
    let worst = |f: &dyn Fn(&crate::opt::cost::tables::Table) -> u64| t.iter().map(f).max().unwrap_or(0);
    let miss = worst(&|tb| tb.branch_miss.0);
    let jump = worst(&|tb| tb.op(Op::Lzcnt).lat + tb.op(Op::ShiftVar).lat + tb.op(Op::Branch).tp);
    let lp = &plan.lp;
    let dy = lp.dynamic();
    let payload = rungs::early_exit_param(lp);
    let n = plan.traces.traces.len().max(1) as u64;
    let (mut early, mut active) = (0u64, 0u64);
    for tr in &plan.traces.traces {
        let found = payload.and_then(|p| tr.states.iter().position(|st| st.get(p as usize) != tr.states.first().and_then(|s0| s0.get(p as usize))));
        early += found.map(|i| i as u64).unwrap_or(u64::from(tr.exit_iter)) + 1;
        active += tr.states.windows(2).filter(|w| dy.iter().any(|p| w[0].get(*p as usize) != w[1].get(*p as usize))).count() as u64 + 1;
    }
    let mut rungs = vec![(Rung::ClosedForm, closed)];
    if payload.is_some() {
        rungs.push((Rung::EarlyExit, body.saturating_mul(early) / n + miss));
    }
    rungs.push((Rung::SetBits, (body + jump).saturating_mul(active) / n + miss));
    crate::opt::cost::model::LoopRungCosts { rungs }
}

/// The fallback rungs (design §7.6) when no closed form is found: the
/// early exit, then the set-bit iteration (or the other way round with
/// `LoopConfig::prefer_set_bits`).
#[allow(clippy::too_many_arguments)]
fn fallback(cx: &mut super::Ctx<'_>, ext: &mut Crate, chain: &mut crate::elab::ProverChain, eopts: &crate::elab::Options, key: &LoopKey, user_globals: &std::collections::HashMap<GlobalId, ItemId>, cfg: &LoopConfig, why: &str) -> Result<LoopHelper, LoopFailure> {
    if cfg.prefer_set_bits {
        return match setbits::build_set_bits(cx, ext, chain, eopts, key, user_globals, None, &format!("no closed form ({why})")) {
            Ok(h) => Ok(h),
            Err(f) => {
                if std::env::var_os("SANDBLASTER_LOOPSUM_TRACE").is_some() {
                    eprintln!("[loopsum] {}", f.reason.chars().take(1500).collect::<String>());
                }
                rungs::build_early(cx, ext, chain, eopts, key, user_globals, false, &f.reason)
            }
        };
    }
    match rungs::build_early(cx, ext, chain, eopts, key, user_globals, false, why) {
        Ok(h) => Ok(h),
        Err(f) => setbits::build_set_bits(cx, ext, chain, eopts, key, user_globals, None, &f.reason).map_err(|mut g| {
            g.steps += f.steps;
            g
        }),
    }
}

/// The summary lemma and the helper's link (see [`build`]).
#[allow(clippy::too_many_arguments)]
fn link_lemmas(env: &mut Env, lp: &classify::Loop, spec: &lemmas::Spec, plan: &invariant::Plan, key: &LoopKey, prefix: &str, hg: GlobalId, lemma0: GlobalId) -> Result<(String, GlobalId), String> {
    use sandblaster_kernel::term::Rel;
    use sandblaster_kernel::util::mk;
    let tele_h = crate::opt::symex::telescope(env, hg).ok_or("the helper has no telescope")?;
    let tele_l = crate::opt::symex::telescope(env, key.def).ok_or("the loop has no telescope")?;
    let n = tele_h.binders.len();
    let np = tele_h.binders.iter().filter(|(_, r, _)| *r == Rel::Rel).count();
    let var = |b: usize| mk::var((n - 1 - b) as u32);
    let dy = lp.dynamic();
    let statics = statics_of(env, key, lp.params.len())?;
    // a generated loop's requires hold at its static arguments (checked by
    // `loop_helper_fn`; its helper has none): closed proofs
    let closed_reqs = if n == np && tele_l.binders.iter().any(|(_, r, _)| *r == Rel::Irr) { Some(closed_requires(env, &tele_h, &tele_l, &statics, &dy)?) } else { None };
    let mut largs = Vec::new();
    let mut ri = 0usize;
    for (i, (_, rel, _)) in tele_l.binders.iter().enumerate() {
        match rel {
            Rel::Rel => largs.push((Rel::Rel, match &statics[i] {
                Some(t) => t.clone(),
                None => var(dy.iter().position(|d| *d as usize == i).ok_or("a dynamic parameter")?),
            })),
            Rel::Irr => {
                largs.push((Rel::Irr, match &closed_reqs {
                    Some(ps) => ps[ri].clone(),
                    None => var(np + ri),
                }));
                ri += 1;
            }
        }
    }
    if closed_reqs.is_none() && np + ri != n {
        return Err("the helper's requires are not the loop's".into());
    }
    let loop_app = mk::apps(mk::global(key.def), largs);
    let res_g = env.lookup_global(&format!("{prefix}::res")).ok_or("the result definition")?;
    let res_app = mk::apps(mk::global(res_g), (0..np).map(|b| (Rel::Rel, var(b))));
    let h_app = mk::apps(mk::global(hg), tele_h.binders.iter().enumerate().map(|(b, (_, r, _))| (*r, var(b))));
    let ret = tele_h.ret.clone();
    let close = |body: sandblaster_kernel::term::Tm| {
        let mut t = body;
        for (nm, rel, dom) in tele_h.binders.iter().rev() {
            t = mk::pi(nm, *rel, dom.clone(), t);
        }
        t
    };
    let summary_ty = close(mk::eq(ret.clone(), loop_app.clone(), res_app.clone()));
    let link_ty = close(mk::eq(ret.clone(), h_app.clone(), loop_app.clone()));
    let loop_name = env.global_name(key.def).map(|s| s.to_string()).unwrap_or_default();
    // the summary: lemma_0 at the entry state
    let summary_name = if key.statics.is_empty() || prefix.ends_with("sum0") { format!("{loop_name}::summary") } else { format!("{prefix}::summary") };
    let cfg = crate::auto::AutoConfig { self_check: false, goal_timeout: Some(std::time::Duration::from_secs(3600)), deep_enrich: true, lin_rounds: 4, ..crate::auto::AutoConfig::default() };
    let lim = meter::cap(200_000_000);
    let mut sb = Budget { steps: lim };
    let summary_body = (|| -> Result<sandblaster_kernel::term::Tm, String> {
        let envr: &Env = env;
        let mut db = crate::auto::lemmas::LemmaDb::default();
        db.refresh(envr);
        let mut e = crate::auto::search::Engine::new(envr, &mut sb, &cfg, &db, vec![], 0);
        let mut st = crate::auto::state::St::new(envr, &sandblaster_kernel::api::Ctx::default(), 64);
        let _goal = lemmas::open(&mut e, &mut st, &summary_ty)?;
        let mut b = lemmas::Builder::new(spec);
        b.j = 0;
        // the state binders at the entry, then the ghosts
        let mut rel_vals = Vec::new();
        for (_, _, pi) in &spec.state {
            let v = match &statics[*pi as usize] {
                Some(t) => st.eval(envr, t, &mut Budget { steps: 1_000_000 }).map_err(|e| format!("{e:?}"))?,
                None => {
                    let b = dy.iter().position(|d| d == pi).ok_or("a dynamic parameter")?;
                    match &st.venv.0[b] {
                        sandblaster_kernel::value::EnvEntry::Rel(v) => v.clone(),
                        _ => return Err("an irrelevant parameter".into()),
                    }
                }
            };
            rel_vals.push(v);
        }
        for g in plan.ghosts.iter().filter(|g| !g.shared) {
            let b = dy.iter().position(|d| *d == g.param).ok_or("a ghost's parameter")?;
            match &st.venv.0[b] {
                sandblaster_kernel::value::EnvEntry::Rel(v) => rel_vals.push(v.clone()),
                _ => return Err("an irrelevant parameter".into()),
            }
        }
        let p = b.apply_with(&mut e, &mut st, lemma0, rel_vals).map_err(|s| format!("{s:?}"))?.ok_or_else(|| format!("the entry invariant is not proven ({})", b.stats.first_failure.clone().unwrap_or_default()))?;
        Ok(st.finish(p))
    })();
    meter::charge(lim - sb.steps);
    let summary_body = summary_body?;
    let (summary_g, _) = lemmas::add_lemma(env, &summary_name, summary_ty, summary_body, 400_000_000)?;
    // the link: H d̄ = res d̄ (the printed closed form), then the summary
    let link_name = format!("{}::equiv", env.global_name(hg).map(|s| s.to_string()).unwrap_or_default());
    let lim = meter::cap(200_000_000);
    let mut sb = Budget { steps: lim };
    let link_body = (|| -> Result<sandblaster_kernel::term::Tm, String> {
        let envr: &Env = env;
        let mut db = crate::auto::lemmas::LemmaDb::default();
        db.refresh(envr);
        let mut e = crate::auto::search::Engine::new(envr, &mut sb, &cfg, &db, vec![], 0);
        let mut st = crate::auto::state::St::new(envr, &sandblaster_kernel::api::Ctx::default(), 64);
        let _ = lemmas::open(&mut e, &mut st, &link_ty)?;
        let d = st.depth();
        let v = |b: usize| mk::var(d - 1 - b as u32);
        let h_app_s = mk::apps(mk::global(hg), tele_h.binders.iter().enumerate().map(|(b, (_, r, _))| (*r, v(b))));
        let res_app_s = mk::apps(mk::global(res_g), (0..np).map(|b| (Rel::Rel, v(b))));
        let mut largs_s = Vec::new();
        let mut ri = 0usize;
        for (i, (_, rel, _)) in tele_l.binders.iter().enumerate() {
            match rel {
                Rel::Rel => largs_s.push((Rel::Rel, match &statics[i] {
                    Some(t) => t.clone(),
                    None => v(dy.iter().position(|dd| *dd as usize == i).unwrap()),
                })),
                Rel::Irr => {
                    largs_s.push((Rel::Irr, match &closed_reqs {
                        Some(ps) => crate::auto::util::shift(&ps[ri], d as i64 - n as i64),
                        None => v(np + ri),
                    }));
                    ri += 1;
                }
            }
        }
        let loop_app_s = mk::apps(mk::global(key.def), largs_s);
        let ret_s = ret.clone();
        let bridge_goal = st.eval(envr, &mk::eq(ret_s.clone(), h_app_s.clone(), res_app_s.clone()), &mut Budget { steps: 20_000_000 }).map_err(|e| format!("{e:?}"))?;
        let mut b = lemmas::Builder::new(spec);
        let p1 = match lemmas::trivial(envr, &st.ctx, &bridge_goal, &mut Budget { steps: 50_000_000 }) {
            Some(p) => p,
            None => b.align(&mut e, &mut st, &bridge_goal, 6).map_err(|s| format!("{s:?}"))?.ok_or_else(|| format!("the printed closed form is not the result definition ({})", b.stats.first_failure.clone().unwrap_or_default()))?,
        };
        let inst = mk::apps(mk::global(summary_g), (0..n).map(|b| (tele_h.binders[b].1, v(b))));
        let sym = e.sym(&ret_s, &loop_app_s, &res_app_s, &inst);
        let p = e.trans(&ret_s, &h_app_s, &res_app_s, &loop_app_s, &p1, &sym);
        Ok(st.finish(p))
    })();
    meter::charge(lim - sb.steps);
    let link_body = link_body?;
    let (link_g, _) = lemmas::add_lemma(env, &link_name, link_ty, link_body, 400_000_000)?;
    Ok((summary_name, link_g))
}

/// The loop's requires at its static arguments and the helper's
/// parameters (dynamic): `refl` proofs (terms over the helper's binders),
/// each requires' two sides convertible there.
fn closed_requires(env: &Env, tele_h: &crate::opt::symex::Telescope, tele_l: &crate::opt::symex::Telescope, statics: &[Option<sandblaster_kernel::term::Tm>], dy: &[u32]) -> Result<Vec<sandblaster_kernel::term::Tm>, String> {
    use sandblaster_kernel::api::{Ctx, CtxEntry};
    use sandblaster_kernel::term::Rel;
    use sandblaster_kernel::util::mk;
    use sandblaster_kernel::value::{EnvEntry, VEnv};
    let mut b = Budget { steps: 20_000_000 };
    let mut ctx = Ctx::default();
    for (nm, rel, dom) in &tele_h.binders {
        let ty = env.eval(&env.ctx_venv(&ctx), ctx.depth(), dom, &mut b).map_err(|e| format!("{e:?}"))?;
        ctx = ctx.push(CtxEntry { name: nm.clone(), rel: *rel, ty, def: None });
    }
    let venv = env.ctx_venv(&ctx);
    let depth = ctx.depth();
    let mut vals: Vec<EnvEntry> = Vec::new();
    let mut out = Vec::new();
    for (i, (_, rel, dom)) in tele_l.binders.iter().enumerate() {
        match rel {
            Rel::Rel => match &statics[i] {
                Some(t) => vals.push(EnvEntry::Rel(env.eval(&VEnv::default(), Lvl(0), t, &mut b).map_err(|e| format!("{e:?}"))?)),
                None => {
                    let k = dy.iter().position(|d| *d as usize == i).ok_or("a dynamic parameter")?;
                    vals.push(venv.0[k].clone());
                }
            },
            Rel::Irr => {
                let ty = env.eval(&VEnv(std::rc::Rc::new(vals.clone())), depth, dom, &mut b).map_err(|e| format!("{e:?}"))?;
                let Value::Eq { ty: t, lhs, rhs } = &*ty else { return Err("a loop requires that is not an equation".into()) };
                if !env.conv(depth, lhs, rhs, &mut b).unwrap_or(false) {
                    return Err("a loop requires that does not hold at its static arguments".into());
                }
                let p = mk::refl(env.quote(depth, t, false), env.quote(depth, rhs, false));
                vals.push(crate::auto::util::irr_entry(&venv, &p));
                out.push(p);
            }
        }
    }
    Ok(out)
}

/// [`key_of`] over the relevant arguments only.
pub fn key_of_rel(env: &Env, def: GlobalId, rel: &[V]) -> Option<(LoopKey, Vec<Option<Tm>>)> {
    let args: Vec<Arg> = rel.iter().map(|v| Arg::Rel(v.clone())).collect();
    key_of(env, def, &args)
}
