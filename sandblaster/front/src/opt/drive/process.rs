//! The driving loop (optimizer design §6.1–§6.3): builds the process tree
//! ([`super::tree`]) of one function.
//!
//! The driver starts from `f x̄ h̄` (the parameters fresh, fixed-length
//! arrays eta-expanded, the `requires` binders as facts) and repeatedly
//! looks at the **head** of the current value:
//!
//! * a static-length byte comparison (`seq::eq` of two byte spines of
//!   length `8m`): `Word`, its word form (design §12.4, [`super::word`]);
//! * a folded application `g ā` that the policy unfolds (the function
//!   itself, a static-measure or static-structure recursion, a small
//!   callee): `Unfold`, continue with `g`'s body at `ā` (and the rest of
//!   the spine);
//! * a match stuck on a scrutinee `c`, tried in order (design §6.3):
//!   1. **Reuse**: an enclosing split fixed a convertible scrutinee;
//!   2. **Prune**: `c` is boolean and linear arithmetic decides it from the
//!      facts in scope (`auto`'s `decide_bool`, with its integer cuts and
//!      on-demand disequality splits: the fact normalization of design
//!      §6.3);
//!   3. **Split**: a residual match; each arm continues with the
//!      constructor's fields and the path equation as new binders (the
//!      equation is a new fact, the decision is cached);
//! * anything else is a leaf: a straight-line residual value. Matches left
//!   inside it (not at the head) are residualized in place, select-shaped
//!   (the **merge** of design §6.3: both arms are values, nothing is
//!   duplicated).
//!
//! Every decision is logged as a [`Step`] at its node; the proof builder
//! replays them.

use std::rc::Rc;

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{GlobalId, IndId, Lvl, Rel};
use sandblaster_kernel::value::{Arg, Budget, EnvEntry, V, VEnv, Value};

use super::config::DriveConfig;
use super::facts::{Decided, Facts};
use super::step::{Eval, HeadKind, head_of, stuck_after_head};
use super::tree::{Arm, Field, Node, NodeKind, Step};
use crate::auto::AutoConfig;
use crate::auto::lemmas::LemmaDb;
use crate::auto::search::Engine;
use crate::auto::state::{Origin, St};
use crate::auto::util::entry_arg;

/// Linear-arithmetic enrichment rounds of the driver's decisions (and of
/// the proof builder's replay of them): one per nesting level of the atoms
/// a decision reads.
pub const LIN_ROUNDS: u32 = 3;

/// The folded application `g args` as a value.
fn global_app(g: GlobalId, args: &[Arg]) -> V {
    Rc::new(Value::Neu(sandblaster_kernel::value::Neutral { head: sandblaster_kernel::value::Head::Global { def: g, args: args.to_vec() }, spine: vec![] }))
}

/// A closure standing for the value of an environment entry (an
/// irrelevant binder: `Var(0)` in an environment holding just it).
fn var_closure(e: EnvEntry) -> sandblaster_kernel::value::Closure {
    sandblaster_kernel::value::Closure { env: VEnv(Rc::new(vec![e])), body: Rc::new(sandblaster_kernel::term::Term::Var(sandblaster_kernel::term::Idx(0))) }
}

/// What the driver does with a folded application at the head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unfold {
    /// Keep the call (a residual call, or a split on its result).
    Keep,
    /// Unfold a non-recursive definition.
    Inline,
    /// Unfold one step of a recursion whose measure or structure is static;
    /// `trips` is the static measure (the number of unfoldings to expect).
    Unroll { trips: u32 },
    /// Keep the call as a call of the polyvariant specialization at these
    /// static arguments (design §6.5), driven separately.
    Specialize { key: super::tree::SpecKey },
    /// Instantiate the callee's summary (design §6.4): replace the call by
    /// the same application of its admitted residual `res` (through its
    /// equality lemma `lemma`) and continue driving through the residual's
    /// body — the caller's continuation reaches every leaf (case-of-case).
    Link { res: GlobalId, lemma: GlobalId },
    /// Inline the callee's residual through its link as a value (a join
    /// point): the residual's body at the arguments, bound to a new
    /// variable over which the continuation is driven once. `lemma: None`:
    /// `res` is the callee itself (a specialization helper), unfolded
    /// directly.
    Bind { res: GlobalId, lemma: Option<GlobalId> },
    /// Driving a fold helper of this recursion (design §6.6, folding under
    /// the same-global rule): its first application on a path is unfolded
    /// (the helper's entry); a later one, in tail position, is the
    /// back-edge — the helper's own recursive call (`Step::Fold`, a leaf).
    FoldBack,
    /// Keep the call as a call of the recursion's fold helper (a loop
    /// helper with a carried bound invariant, design §6.6), built
    /// separately; the residual calls the helper.
    FoldCall,
    /// Keep the call as a call of its Σ2 loop helper (design §7,
    /// `opt::loopsum`), built separately.
    LoopSum { key: crate::opt::loopsum::LoopKey },
    /// Driving a Σ3 segment specialization of this function (design §8.2,
    /// `opt::seqsum`): its first application on a path (the entry's body)
    /// is unfolded; a later one is kept (a leaf, where the segment normal
    /// form decides what it becomes: the specialization's back-edge, a call
    /// of the function itself, or another specialization).
    SegEntry,
}

/// A driving failure; `budget` marks an exhausted budget (the driver may
/// back off: keep a recursion instead of unrolling it, design §6.2).
#[derive(Clone, Debug)]
pub struct DErr {
    pub budget: bool,
    pub msg: String,
}

impl From<String> for DErr {
    fn from(msg: String) -> DErr {
        DErr { budget: false, msg }
    }
}

impl From<&str> for DErr {
    fn from(msg: &str) -> DErr {
        DErr { budget: false, msg: msg.to_string() }
    }
}

fn budget_err(msg: String) -> DErr {
    DErr { budget: true, msg }
}

/// The driver's unfolding policy (built from the crate by `drive::run`).
pub trait Policy {
    /// The driver's opaque set: globals its evaluation keeps folded.
    fn folded(&self, g: GlobalId) -> bool;
    /// The decision for a folded application `def args` at the head;
    /// `cont`: the relevant size of the matches eliminating its result
    /// (`None`: no match, the call is in tail position).
    /// `cont_globals`: the globals the continuation applies (calls it
    /// would carry into every leaf of an instantiated callee).
    fn unfold(&self, env: &Env, def: GlobalId, args: &[Arg], cont: Option<usize>, cont_globals: &[GlobalId]) -> Unfold;
    /// An application the residual could not print that driving `root`
    /// would keep: `(function whose body applies it, the global applied)`.
    /// Checked before driving, so a function whose residual cannot be
    /// printed is refused at once rather than after its whole evaluation.
    fn unprintable_use(&self, _root: GlobalId) -> Option<(GlobalId, GlobalId)> {
        None
    }
    /// The polyvariant call-site specializations of applications inside a
    /// leaf value (not at its head): `(callee, key)`, distinct.
    fn leaf_specializations(&self, _v: &V) -> Vec<(GlobalId, super::tree::SpecKey)> {
        Vec::new()
    }
    /// Fact-directed unfolding (plan O6, `opt::facts`): a kept call `def
    /// args` whose arguments include a kept call with exported facts, or a
    /// payload the path's imported facts are about (levels `imported`),
    /// unfolded (its summary instantiated, or its source) so the facts
    /// reach its tests.
    fn fact_directed(&self, _env: &Env, _def: GlobalId, _args: &[Arg], _imported: &[u32]) -> Option<Unfold> {
        None
    }
    /// Whether a kept call of `def` in tail position may become a guard
    /// specialization (`opt::guardspec`).
    fn guard_candidate(&self, _def: GlobalId) -> bool {
        false
    }
    /// The Σ3 segment specializations of the crate (`opt::seqsum`; `None`:
    /// no consumer driving over segments).
    fn seg_registry(&self) -> Option<&crate::opt::seqsum::drive::Registry> {
        None
    }
    /// Whether `g` is a function Σ3 may specialize on a segment argument.
    fn seg_consumer(&self, _g: GlobalId) -> bool {
        false
    }
    /// The consumer whose segment helper is being driven (its calls are the
    /// helper's back-edges).
    fn seg_root(&self) -> Option<GlobalId> {
        None
    }
}

/// Per-path state.
#[derive(Clone)]
pub struct Path {
    pub st: St,
    pub facts: Facts,
    pub splits: u32,
    pub unrolls: u32,
    /// Recursions being unrolled on this path (their chain heads carry a
    /// checkpoint).
    pub unrolled: Vec<GlobalId>,
    /// Applications the driver backed off from unrolling (kept as calls).
    pub kept: Vec<V>,
}

/// One function's driving.
pub struct Driver<'a> {
    pub env: &'a Env,
    pub cfg: &'a DriveConfig,
    pub policy: &'a dyn Policy,
    /// The function being driven (unfolded once, at the root).
    pub root: GlobalId,
    pub budget: Budget,
    /// Process-graph nodes built so far (reset when the driver backs off
    /// from an unrolling).
    pub nodes: usize,
    /// The current node limit (a chain head's checkpoint lowers it).
    pub limit: usize,
    /// Every node ever built, including backed-off attempts (bounded by
    /// four times the node budget).
    pub work: usize,
    pub auto_cfg: AutoConfig,
    pub db: LemmaDb,
    pub bool_ind: IndId,
    /// The `Word` step's globals (absent without the word lemmas).
    pub word: Option<super::word::WordIds>,
    /// A simulated fault (the must-reject suite only).
    pub fault: Option<crate::opt::DriveFault>,
    pub trace: bool,
    /// Nesting of fact-directed trials ([`Driver::fact_trial`]): their
    /// decisions are speculative and get an eighth of the usual cap.
    pub trials: u32,
}

impl<'a> Driver<'a> {
    pub fn new(env: &'a Env, cfg: &'a DriveConfig, policy: &'a dyn Policy, root: GlobalId) -> Driver<'a> {
        let mut db = LemmaDb::default();
        db.refresh(env);
        // enrichment rounds: one per nesting level of the atoms a decision
        // reads (a varint's accumulated value is an `or` of up to ten
        // shifted groups)
        let auto_cfg = AutoConfig { self_check: false, max_split_depth: 0, lin_rounds: LIN_ROUNDS, deep_enrich: true, goal_timeout: Some(std::time::Duration::from_secs(600)), ..AutoConfig::default() };
        Driver { env, cfg, policy, root, budget: Budget { steps: cfg.steps }, nodes: 0, limit: cfg.max_nodes, work: 0, auto_cfg, db, bool_ind: env.bool_ind(), word: super::word::WordIds::new(env), fault: None, trace: std::env::var_os("SANDBLASTER_OPT_TRACE").is_some(), trials: 0 }
    }

    /// Runs `f` with the driver's evaluator and its budget.
    fn with_eval<R>(&mut self, f: impl FnOnce(&Eval<'_>, &mut Budget) -> R) -> R {
        let mut b = std::mem::replace(&mut self.budget, Budget { steps: 0 });
        let policy = self.policy;
        let op = move |g: GlobalId| policy.folded(g);
        let r = f(&Eval { env: self.env, opaque: &op }, &mut b);
        self.budget = b;
        r
    }

    fn tick(&mut self) -> Result<(), DErr> {
        self.nodes += 1;
        self.work += 1;
        if self.work > 4 * self.cfg.max_nodes {
            return Err(DErr { budget: false, msg: format!("the driver's work budget ({} nodes) is exhausted", 4 * self.cfg.max_nodes) });
        }
        if self.nodes > self.limit {
            return Err(budget_err(format!("the process graph exceeds its node budget ({})", self.limit)));
        }
        if self.budget.steps == 0 {
            return Err(DErr { budget: false, msg: format!("the driver's step budget ({}) is exhausted", self.cfg.steps) });
        }
        Ok(())
    }

    fn name(&self, g: GlobalId) -> String {
        self.env.global_name(g).map(|s| s.to_string()).unwrap_or_default()
    }

    /// The process tree of the root function driven from `v` (its folded
    /// application to the parameters) in `path`.
    pub fn run(&mut self, path: Path, v: V) -> Result<Node, String> {
        let _scope = crate::auto::meter::Scope::enter(Some(std::time::Duration::from_secs(600)), &self.budget);
        self.drive(path, v, true, Vec::new()).map_err(|e| e.msg)
    }

    /// Whether `app` is one the driver backed off from.
    fn is_kept(&mut self, path: &Path, app: &V) -> bool {
        let depth = path.st.depth();
        let kept = path.kept.clone();
        self.with_eval(|ev, b| kept.iter().any(|k| Rc::ptr_eq(k, app) || ev.env.conv_opaque(Lvl(depth), k, app, ev.opaque, b).unwrap_or(false)))
    }

    fn drive(&mut self, mut path: Path, mut v: V, mut at_root: bool, mut steps: Vec<Step>) -> Result<Node, DErr> {
        let depth = path.st.depth();
        loop {
            self.tick()?;
            // a checked arithmetic call at the head of a match whose
            // overflow condition the facts decide: rewritten by its lemma
            // (`Step::Checked`), not unfolded into a nested dependent `if`
            let checked_call = match head_of(&v) {
                HeadKind::Folded { def, args, elims, .. } if !elims.is_empty() && self.checked_lemma(def, true).is_some() => Some((def, args.to_vec(), elims.iter().map(crate::auto::util::clone_elim).collect::<Vec<_>>())),
                _ => None,
            };
            if let Some((def, args, el)) = checked_call {
                let body = self.with_eval(|ev, b| ev.unfold(def, &args, depth, b).and_then(|w| ev.elims(w, &el, depth, b)))?;
                let stuck = match head_of(&body) {
                    HeadKind::Stuck { scrut, arms, rest, .. } => Some((scrut.clone(), arms.to_vec(), rest.iter().map(crate::auto::util::clone_elim).collect::<Vec<_>>())),
                    _ => None,
                };
                if let Some((scrut, arms, rest)) = stuck
                    && let Some((b, cert)) = self.decide_filtered(&path.st, &scrut)
                {
                    if self.trace {
                        eprintln!("opt: drive: checked {} decided ({b}) at depth {depth}", self.name(def));
                    }
                    let pf = sandblaster_kernel::value::Closure { env: path.st.venv.clone(), body: cert };
                    v = self.arm_value(&arms, b as u32, vec![], &rest, depth, Some(pf))?;
                    steps.push(Step::Checked { def, value: b });
                    at_root = false;
                    continue;
                }
            }
            let decision = match head_of(&v) {
                HeadKind::Folded { def, args, app, elims } if self.word.is_some_and(|w| w.detect(def, args).is_some()) => {
                    // a static-length byte comparison: its word form (design
                    // §12.4), evaluated over the two lists' elements
                    let w = self.word.unwrap();
                    let (xs, ys) = w.detect(def, args).unwrap();
                    let n = xs.len();
                    let tm = w.form(&super::word::env_elem(n), n / 8);
                    let es: Vec<EnvEntry> = xs.into_iter().chain(ys).map(EnvEntry::Rel).collect();
                    let elims: Vec<_> = elims.iter().map(crate::auto::util::clone_elim).collect();
                    let nv = self.with_eval(|ev, b| {
                        ev.env.eval_opaque(&VEnv(Rc::new(es)), Lvl(depth), &tm, ev.opaque, b).map_err(|e| format!("the word form: {e:?}")).and_then(|w| ev.elims(w, &elims, depth, b))
                    })?;
                    if self.trace {
                        eprintln!("opt: drive: word form ({n} bytes) at depth {depth}");
                    }
                    steps.push(Step::Word { app, blocks: (n / 8) as u32 });
                    at_root = false;
                    Some(nv)
                }
                HeadKind::Folded { def, args, app, elims } => {
                    let cont = super::step::cont_nodes(elims, 1 << 16);
                    let cont_globals = if cont.is_some() { super::step::cont_globals(elims) } else { Vec::new() };
                    let mut d = if at_root && def == self.root { Unfold::Inline } else { self.policy.unfold(self.env, def, args, cont, &cont_globals) };
                    if self.trace && matches!(d, Unfold::Link { .. } | Unfold::Bind { .. } | Unfold::Keep) {
                        eprintln!("opt: drive: call of {} (continuation {cont:?} nodes, calling {:?}): {d:?}", self.name(def), cont_globals.iter().map(|g| self.name(*g)).collect::<Vec<_>>());
                    }
                    if d != Unfold::Keep && !at_root && self.is_kept(&path, &app) {
                        d = Unfold::Keep;
                    }
                    // plan O6: facts of a kept call reach the callee
                    if d == Unfold::Keep && !at_root {
                        let payloads = crate::opt::facts::imported_payloads(&path.st);
                        let imported = !payloads.is_empty();
                        let mut trial_kept = false;
                        if let Some(d2) = self.policy.fact_directed(self.env, def, args, &payloads)
                            && !self.is_kept(&path, &app)
                        {
                            if self.trace {
                                eprintln!("opt: drive: fact-directed {d2:?} of {} at depth {depth}", self.name(def));
                            }
                            // a trial: the unfolding is kept only if the
                            // subtree it opens decides something (below)
                            let elims: Vec<_> = elims.iter().map(crate::auto::util::clone_elim).collect();
                            if let Some(node) = self.fact_trial(&path, &steps, def, &args.to_vec(), &elims, &app, &d2, depth)? {
                                return Ok(node);
                            }
                            trial_kept = true;
                        }
                        if !trial_kept
                            && imported
                            && elims.is_empty()
                            && self.policy.guard_candidate(def)
                            && let Some(key) = self.guard_spec(&path, def, args)
                        {
                            if self.trace {
                                eprintln!("opt: drive: guard specialization of {} ({:?}) at depth {depth}", self.name(def), key.guards);
                            }
                            steps.push(Step::GuardSpec { def, key });
                        }
                    }
                    match d {
                        Unfold::Keep => None,
                        Unfold::Link { res, lemma } => {
                            if self.trace {
                                eprintln!("opt: drive: instantiate {} through its link at depth {depth}", self.name(def));
                            }
                            let args: Vec<Arg> = args.to_vec();
                            let elims: Vec<_> = elims.iter().map(crate::auto::util::clone_elim).collect();
                            let body = self.with_eval(|ev, b| ev.unfold(res, &args, depth, b).and_then(|w| ev.elims(w, &elims, depth, b)))?;
                            steps.push(Step::Link { def, res, lemma, app });
                            steps.push(Step::Unfold { def: res, app: global_app(res, &args) });
                            at_root = false;
                            Some(body)
                        }
                        Unfold::Bind { res, lemma } => {
                            if self.trace {
                                eprintln!("opt: drive: inline {} through its link (a value) at depth {depth}", self.name(def));
                            }
                            let args: Vec<Arg> = args.to_vec();
                            let elims: Vec<_> = elims.iter().map(crate::auto::util::clone_elim).collect();
                            return self.bind(path, steps, def, res, lemma, args, app, elims);
                        }
                        Unfold::Specialize { key } => {
                            if self.trace {
                                eprintln!("opt: drive: specialize {} at depth {depth}", self.name(def));
                            }
                            steps.push(Step::Specialize { def, key });
                            None
                        }
                        Unfold::FoldCall => {
                            if self.trace {
                                eprintln!("opt: drive: call the fold helper of {} at depth {depth}", self.name(def));
                            }
                            steps.push(Step::FoldCall { def });
                            None
                        }
                        Unfold::LoopSum { key } => {
                            if self.trace {
                                eprintln!("opt: drive: summarize the loop {} at depth {depth}", self.name(def));
                            }
                            steps.push(Step::LoopSum { def, key });
                            None
                        }
                        Unfold::FoldBack if path.unrolled.contains(&def) => {
                            // the back-edge: only a tail call folds (its
                            // proof is the induction hypothesis as is)
                            if !elims.is_empty() {
                                return Err(DErr::from(format!("a recursive call of `{}` not in tail position (no fold)", self.name(def))));
                            }
                            if self.trace {
                                eprintln!("opt: drive: fold {} at depth {depth}", self.name(def));
                            }
                            steps.push(Step::Fold { def, app: app.clone() });
                            return Ok(Node { depth, steps, kind: NodeKind::Leaf(app) });
                        }
                        Unfold::SegEntry if path.unrolled.contains(&def) => None,
                        Unfold::SegEntry => {
                            // a segment specialization's entry: one unfolding
                            path.unrolled.push(def);
                            if self.trace {
                                eprintln!("opt: drive: enter {} (segment specialization) at depth {depth}", self.name(def));
                            }
                            let args: Vec<Arg> = args.to_vec();
                            let elims: Vec<_> = elims.iter().map(crate::auto::util::clone_elim).collect();
                            let body = self.with_eval(|ev, b| ev.unfold(def, &args, depth, b).and_then(|w| ev.elims(w, &elims, depth, b)))?;
                            steps.push(Step::Unfold { def, app });
                            at_root = false;
                            Some(body)
                        }
                        Unfold::FoldBack => {
                            // the helper's entry: one unfolding
                            path.unrolled.push(def);
                            if self.trace {
                                eprintln!("opt: drive: enter {} (fold helper) at depth {depth}", self.name(def));
                            }
                            let args: Vec<Arg> = args.to_vec();
                            let elims: Vec<_> = elims.iter().map(crate::auto::util::clone_elim).collect();
                            let body = self.with_eval(|ev, b| ev.unfold(def, &args, depth, b).and_then(|w| ev.elims(w, &elims, depth, b)))?;
                            steps.push(Step::Unfold { def, app });
                            at_root = false;
                            Some(body)
                        }
                        Unfold::Inline | Unfold::Unroll { .. } => {
                            if let Unfold::Unroll { .. } = d {
                                path.unrolls += 1;
                                if path.unrolls > self.cfg.max_unroll {
                                    return Err(budget_err(format!("unrolling `{}` exceeds the unroll budget ({})", self.name(def), self.cfg.max_unroll)));
                                }
                            }
                            if self.trace {
                                eprintln!("opt: drive: unfold {} at depth {depth}", self.name(def));
                            }
                            let args: Vec<Arg> = args.to_vec();
                            let elims: Vec<_> = elims.iter().map(crate::auto::util::clone_elim).collect();
                            let body = self.with_eval(|ev, b| ev.unfold(def, &args, depth, b).and_then(|w| ev.elims(w, &elims, depth, b)))?;
                            // the head of an unrolled chain carries a
                            // checkpoint: if the unrolled tree outgrows its
                            // allowance, the recursion is kept (design §6.2:
                            // the loop head is left for Σ2)
                            if let Unfold::Unroll { trips } = d.clone()
                                && !path.unrolled.contains(&def)
                            {
                                let allowance = 64 + 16 * trips as usize;
                                let (saved_nodes, saved_limit) = (self.nodes, self.limit);
                                self.limit = self.limit.min(self.nodes + allowance);
                                let mut p2 = path.clone();
                                p2.unrolled.push(def);
                                let mut s2 = steps.clone();
                                s2.push(Step::Unfold { def, app: app.clone() });
                                match self.drive(p2, body, false, s2) {
                                    Ok(node) => {
                                        self.limit = saved_limit;
                                        return Ok(node);
                                    }
                                    Err(e) if e.budget => {
                                        if self.trace {
                                            eprintln!("opt: drive: back off from unrolling {} ({})", self.name(def), e.msg);
                                        }
                                        self.nodes = saved_nodes;
                                        self.limit = saved_limit;
                                        path.unrolls -= 1;
                                        path.kept.push(app);
                                        continue;
                                    }
                                    Err(e) => return Err(e),
                                }
                            }
                            steps.push(Step::Unfold { def, app });
                            at_root = false;
                            Some(body)
                        }
                    }
                }
                _ => None,
            };
            if let Some(nv) = decision {
                v = nv;
                continue;
            }
            // a stuck match at the head (after a kept call, if any)
            let stuck = match head_of(&v) {
                HeadKind::Stuck { scrut, ind, params, arms, rest } => Some((scrut, ind, params.to_vec(), arms.to_vec(), rest.iter().map(crate::auto::util::clone_elim).collect::<Vec<_>>())),
                HeadKind::Folded { .. } => stuck_after_head(&v).map(|(scrut, ind, params, arms, rest)| (scrut, ind, params.to_vec(), arms.to_vec(), rest.iter().map(crate::auto::util::clone_elim).collect())),
                HeadKind::Other => None,
            };
            let Some((scrut, ind, params, arms, rest)) = stuck else {
                // Σ3: a leaf reading or passing on an assembled buffer
                // (design §8.2, `opt::seqsum::drive`)
                match crate::opt::seqsum::drive::leaf(self, &path, &v) {
                    crate::opt::seqsum::drive::LeafOut::Keep => {}
                    crate::opt::seqsum::drive::LeafOut::Rewrite(nv) => {
                        drop_guard_spec(&mut steps, &v);
                        steps.push(Step::Seq);
                        return Ok(Node { depth, steps, kind: NodeKind::Leaf(nv) });
                    }
                    crate::opt::seqsum::drive::LeafOut::Demand(c) => {
                        drop_guard_spec(&mut steps, &v);
                        return self.demand_split(path, v, steps, c);
                    }
                }
                for (def, key) in self.policy.leaf_specializations(&v) {
                    if self.trace {
                        eprintln!("opt: drive: specialize {} in a leaf at {:?}", self.name(def), key.statics);
                    }
                    steps.push(Step::SpecializeIn { def, key });
                }
                return Ok(Node { depth, steps, kind: NodeKind::Leaf(v) });
            };
            // 1. Reuse
            let reuse = {
                let facts = &path.facts;
                let env = self.env;
                self.with_eval(|ev, b| facts.lookup(env, depth, &scrut, ind, ev.opaque, b))
            };
            if let Some(d) = reuse {
                let es: Vec<EnvEntry> = d.fields.iter().map(crate::auto::util::arg_entry).collect();
                let pf = path.st.venv.0.get(d.eq_lvl as usize).cloned().map(var_closure);
                // fault R13: the sibling arm's decision
                let flip = self.fault == Some(crate::opt::DriveFault::CrossArmReuse) && ind == self.bool_ind;
                let ctor = if flip { 1 - d.ctor } else { d.ctor };
                v = self.arm_value(&arms, ctor, es, &rest, depth, pf)?;
                steps.push(Step::Reuse { scrut, eq: d.eq_lvl, flip });
                continue;
            }
            // 2. Prune (boolean scrutinees decided by linear arithmetic),
            // asked only where the facts can decide (an untrusted interval
            // pre-check: a query the facts cannot answer fails, at the
            // price of the whole search)
            if ind == self.bool_ind
                && let Some((b, cert)) = self.decide_filtered(&path.st, &scrut)
            {
                // fault R1: the live arm is pruned
                let b = if self.fault == Some(crate::opt::DriveFault::FlipPrune) { !b } else { b };
                if self.trace {
                    eprintln!("opt: drive: prune ({b}) at depth {depth}");
                }
                let pf = sandblaster_kernel::value::Closure { env: path.st.venv.clone(), body: cert };
                v = self.arm_value(&arms, b as u32, vec![], &rest, depth, Some(pf))?;
                steps.push(Step::Prune { cond: scrut, value: b });
                continue;
            }
            // fault R2: an undecided range check claimed dead (its `true`
            // arm kept, "proven" by a certificate-free claim)
            if self.fault == Some(crate::opt::DriveFault::RangeCheckDead) && ind == self.bool_ind && is_u64_range_check(&scrut) {
                let cert: sandblaster_kernel::term::Tm = Rc::new(sandblaster_kernel::term::Term::Erased);
                let pf = sandblaster_kernel::value::Closure { env: path.st.venv.clone(), body: cert };
                v = self.arm_value(&arms, 1, vec![], &rest, depth, Some(pf))?;
                steps.push(Step::Prune { cond: scrut, value: true });
                continue;
            }
            // 3. Split
            if path.splits >= self.cfg.max_split_depth {
                return Err(budget_err(format!("the process graph exceeds its split depth ({})", self.cfg.max_split_depth)));
            }
            if self.trace {
                let shown = if std::env::var_os("SANDBLASTER_OPT_TRACE_SPLITS").is_some() {
                    let eng = Engine::new(self.env, &mut self.budget, &self.auto_cfg, &self.db, vec![], depth);
                    eng.show(&path.st, &scrut).chars().take(400).collect::<String>()
                } else {
                    String::new()
                };
                eprintln!("opt: drive: split at depth {depth} {shown}");
            }
            let decl = self.env.inductive_decl(ind).ok_or("unknown inductive")?;
            let mut out_arms = Vec::new();
            for (k, c) in decl.ctors.iter().enumerate() {
                let mut p = path.clone();
                p.splits += 1;
                let mut fenv: Vec<EnvEntry> = params.iter().map(|x| EnvEntry::Rel(x.clone())).collect();
                let mut fields = Vec::new();
                let mut fargs = Vec::new();
                let mut fes = Vec::new();
                for (fname, frel, fty) in &c.fields {
                    let lvl = p.st.depth();
                    let ftv = self.env.eval(&VEnv(Rc::new(fenv.clone())), Lvl(lvl), fty, &mut self.budget).map_err(|e| format!("a field type: {e:?}"))?;
                    let e = p.st.push_raw(self.env, fname.clone(), *frel, ftv.clone());
                    fields.push(Field { name: fname.clone(), rel: *frel, ty: ftv, lvl });
                    fargs.push(entry_arg(&e));
                    fes.push(e.clone());
                    fenv.push(e);
                }
                let cval = Rc::new(Value::Ctor { ind, ctor: k as u32, params: params.clone(), args: fargs.clone() });
                let dty = Rc::new(Value::Ind { ind, params: params.clone() });
                let eq_ty = Rc::new(Value::Eq { ty: dty, lhs: scrut.clone(), rhs: cval });
                let eq_lvl = p.st.depth();
                let e_entry = p.st.push_raw(self.env, Rc::from("e"), Rel::Irr, eq_ty.clone());
                p.st.add_ctx_fact(eq_lvl, eq_ty, Origin::Split);
                p.facts.decided.push(Decided { scrut: scrut.clone(), ind, ctor: k as u32, fields: fargs, eq_lvl });
                let dk = p.st.depth();
                let vk = self.arm_value(&arms, k as u32, fes, &rest, dk, Some(var_closure(e_entry)))?;
                let body = self.drive(p, vk, false, Vec::new())?;
                out_arms.push(Arm { ctor: k as u32, fields, eq_lvl, body });
            }
            let merged = self.merged_value(depth, &out_arms);
            if merged.is_some() && self.trace {
                eprintln!("opt: drive: merge the arms of the split at depth {depth} (one value)");
            }
            return Ok(Node { depth, steps, kind: NodeKind::Split { scrut, ind, params, arms: out_arms, merged } });
        }
    }

    /// A Σ3 demand split (design §8.2): the residual splits on the boolean
    /// `c` (the emptiness of a piece that a read depends on), which the
    /// source does not test; each arm drives the same value with the path
    /// equation `c = b` as a fact (so the normal form decides the read).
    fn demand_split(&mut self, path: Path, v: V, mut steps: Vec<Step>, c: V) -> Result<Node, DErr> {
        let depth = path.st.depth();
        if path.splits >= self.cfg.max_split_depth {
            return Err(budget_err(format!("the process graph exceeds its split depth ({})", self.cfg.max_split_depth)));
        }
        if self.trace {
            eprintln!("opt: drive: demand split at depth {depth}");
        }
        let ind = self.bool_ind;
        let mut out_arms = Vec::new();
        for k in 0..2u32 {
            let mut p = path.clone();
            p.splits += 1;
            let cval = Rc::new(Value::Ctor { ind, ctor: k, params: vec![], args: vec![] });
            let dty = Rc::new(Value::Ind { ind, params: vec![] });
            let eq_ty = Rc::new(Value::Eq { ty: dty, lhs: c.clone(), rhs: cval });
            let eq_lvl = p.st.depth();
            p.st.push_raw(self.env, Rc::from("e"), Rel::Irr, eq_ty.clone());
            p.st.add_ctx_fact(eq_lvl, eq_ty, Origin::Split);
            p.facts.decided.push(Decided { scrut: c.clone(), ind, ctor: k, fields: vec![], eq_lvl });
            let body = self.drive(p, v.clone(), false, Vec::new())?;
            out_arms.push(Arm { ctor: k, fields: vec![], eq_lvl, body });
        }
        steps.push(Step::Demand);
        Ok(Node { depth, steps, kind: NodeKind::Split { scrut: c, ind, params: vec![], arms: out_arms, merged: None } })
    }

    /// `t` (a term in `st`'s context) evaluated in the driver's mode.
    pub(crate) fn eval_tm(&mut self, st: &St, t: &sandblaster_kernel::term::Tm) -> Result<V, String> {
        let venv = st.venv.clone();
        let depth = st.depth();
        self.with_eval(|ev, b| ev.env.eval_opaque(&venv, Lvl(depth), t, ev.opaque, b).map_err(|e| format!("evaluation: {e:?}")))
    }

    /// The value every arm ends in, when they all end in one value that
    /// does not depend on the arm (design §6.3 Merge, for equal arms): the
    /// residual then prints that value without the split.
    fn merged_value(&mut self, depth: u32, arms: &[Arm]) -> Option<V> {
        let first = arms.first()?.body.leaf_value()?.clone();
        let mut fuel = 1usize << 16;
        if !super::step::closed_below(&first, depth, &mut fuel) {
            return None;
        }
        for a in &arms[1..] {
            let v = a.body.leaf_value()?.clone();
            if !super::step::closed_below(&v, depth, &mut fuel) {
                return None;
            }
            let same = Rc::ptr_eq(&v, &first) || self.with_eval(|ev, b| ev.env.conv_opaque(Lvl(depth), &first, &v, ev.opaque, b).unwrap_or(false));
            if !same {
                return None;
            }
        }
        Some(first)
    }

    /// The callee's residual inlined as a value (see [`Unfold::Bind`]): the
    /// value subtree (`Link`, `Unfold` of the residual, its body at the
    /// arguments as a leaf), a new variable of the call's result type, and
    /// the continuation driven over it.
    #[allow(clippy::too_many_arguments)]
    fn bind(&mut self, mut path: Path, steps: Vec<Step>, def: GlobalId, res: GlobalId, lemma: Option<GlobalId>, args: Vec<Arg>, app: V, elims: Vec<sandblaster_kernel::value::Elim>) -> Result<Node, DErr> {
        let depth = path.st.depth();
        let body = self.with_eval(|ev, b| ev.unfold(res, &args, depth, b))?;
        let vsteps = match lemma {
            Some(lemma) => vec![Step::Link { def, res, lemma, app }, Step::Unfold { def: res, app: global_app(res, &args) }],
            None => vec![Step::Unfold { def: res, app }],
        };
        let value = Node { depth, steps: vsteps, kind: NodeKind::Leaf(body) };
        // the call's result type: the callee's result at the arguments
        let tele = super::super::symex::telescope(self.env, def).ok_or("a callee without a telescope")?;
        let es: Vec<EnvEntry> = args.iter().map(crate::auto::util::arg_entry).collect();
        let ty = self.env.eval(&VEnv(Rc::new(es)), Lvl(depth), &tele.ret, &mut self.budget).map_err(|e| format!("the result type of an inlined call: {e:?}"))?;
        let lvl = depth;
        let name: sandblaster_kernel::term::Name = Rc::from(format!("j{lvl}").as_str());
        let e = path.st.push_raw(self.env, name.clone(), Rel::Rel, ty.clone());
        let Arg::Rel(rv) = entry_arg(&e) else { return Err("an irrelevant join variable".into()) };
        let cont = self.with_eval(|ev, b| ev.elims(rv, &elims, depth + 1, b))?;
        let body_node = self.drive(path, cont, false, Vec::new())?;
        Ok(Node { depth, steps, kind: NodeKind::Bind { lvl, name, ty, value: Box::new(value), body: Box::new(body_node) } })
    }

    /// Arm `k` of a stuck match instantiated with `fields`, then the rest
    /// of the spine. The dependent-match idiom's path-equation argument (a
    /// leading irrelevant application, `refl(D, c)`) is replaced by `proof`
    /// (the split's equation binder, the decision's certificate, the reused
    /// equation), so the arm's proofs have the types the proof builder's
    /// context gives them.
    fn arm_value(&mut self, arms: &[sandblaster_kernel::value::Closure], k: u32, fields: Vec<EnvEntry>, rest: &[sandblaster_kernel::value::Elim], depth: u32, proof: Option<sandblaster_kernel::value::Closure>) -> Result<V, DErr> {
        let arm = arms.get(k as usize).ok_or("a match without the constructor's arm")?;
        let mut rest: Vec<sandblaster_kernel::value::Elim> = rest.iter().map(crate::auto::util::clone_elim).collect();
        if let (Some(p), Some(sandblaster_kernel::value::Elim::App(Arg::Irr(_)))) = (proof, rest.first()) {
            rest[0] = sandblaster_kernel::value::Elim::App(Arg::Irr(p));
        }
        Ok(self.with_eval(|ev, b| ev.inst(arm, fields, depth, b).and_then(|w| ev.elims(w, &rest, depth, b)))?)
    }

    /// [`Self::decide`] where the interval pre-check allows it
    /// ([`super::facts::decidable_with`]): with only the facts whose bounds
    /// decide it when intervals do, with every fact when a fact relates
    /// several of its atoms, never otherwise.
    /// The lemma rewriting a decided checked arithmetic call of `def`
    /// (`w::checked_add` / `w::checked_sub`): `w::checked_{op}_some`
    /// (`some`) or `_none`, when `def` is one and the lemma is loaded.
    pub fn checked_lemma(&self, def: GlobalId, some: bool) -> Option<GlobalId> {
        let name = self.env.global_name(def)?;
        let (w, op) = name.split_once("::")?;
        if !matches!(w, "u8" | "u16" | "u32" | "u64" | "usize") || !matches!(op, "checked_add" | "checked_sub") {
            return None;
        }
        self.env.lookup_global(&format!("{name}_{}", if some { "some" } else { "none" }))
    }

    /// A fact-directed unfolding (plan O6) as a trial: the subtree from the
    /// callee's residual (`Unfold::Link`) or source (`Unfold::Inline`) on,
    /// kept only when it decides something the kept call could not —
    /// a test pruned or reused, a checked call decided, a guard
    /// specialized, a split merged, a leaf by the segment normal form
    /// ([`Node::decisions`]). Otherwise the unfolding bought nothing but a
    /// larger residual to elaborate and prove (QMDB: `reconstruct_finish`
    /// pasted into `reconstruct` with every check it has, about 7 s of
    /// re-proof per caller), so it is undone (`None`: the call is kept):
    /// the nodes it built and the segment requests it made are dropped;
    /// its steps stay spent (a step-budget decision, deterministic). Its
    /// decisions are speculative: an eighth of the usual cap each
    /// ([`Driver::trials`]).
    #[allow(clippy::too_many_arguments)]
    fn fact_trial(&mut self, path: &Path, steps: &[Step], def: GlobalId, args: &[Arg], elims: &[sandblaster_kernel::value::Elim], app: &V, d: &Unfold, depth: u32) -> Result<Option<Node>, DErr> {
        let mut s2 = steps.to_vec();
        let body = match d {
            Unfold::Link { res, lemma } => {
                let (res, lemma) = (*res, *lemma);
                let body = self.with_eval(|ev, b| ev.unfold(res, args, depth, b).and_then(|w| ev.elims(w, elims, depth, b)))?;
                s2.push(Step::Link { def, res, lemma, app: app.clone() });
                s2.push(Step::Unfold { def: res, app: global_app(res, args) });
                body
            }
            Unfold::Inline => {
                let body = self.with_eval(|ev, b| ev.unfold(def, args, depth, b).and_then(|w| ev.elims(w, elims, depth, b)))?;
                s2.push(Step::Unfold { def, app: app.clone() });
                body
            }
            _ => return Ok(None),
        };
        let before = Node::step_decisions(steps);
        let saved_nodes = self.nodes;
        let saved_requests = self.policy.seg_registry().map(|r| r.requested.borrow().clone());
        self.trials += 1;
        let node = self.drive(path.clone(), body, false, s2);
        self.trials -= 1;
        let node = node?;
        if node.decisions() > before {
            return Ok(Some(node));
        }
        if self.trace {
            eprintln!("opt: drive: the fact-directed unfolding of {} decided nothing; the call is kept", self.name(def));
        }
        self.nodes = saved_nodes;
        if let (Some(r), Some(s)) = (self.policy.seg_registry(), saved_requests) {
            *r.requested.borrow_mut() = s;
        }
        Ok(None)
    }

    /// The guard specialization of the kept tail call `def args` (see
    /// `opt::guardspec`): the guards of its body the path's facts decide.
    fn guard_spec(&mut self, path: &Path, def: GlobalId, args: &[Arg]) -> Option<crate::opt::guardspec::GuardKey> {
        let depth = path.st.depth();
        let args = args.to_vec();
        let body = self.with_eval(|ev, b| ev.unfold(def, &args, depth, b)).ok()?;
        let env = self.env;
        let guards = self.with_eval(|ev, _| crate::opt::guardspec::walk(env, ev, body, depth, 8));
        if guards.is_empty() {
            if self.trace {
                eprintln!("opt: drive: no guards of {} at depth {depth}", self.name(def));
            }
            return None;
        }
        let st2 = crate::opt::facts::with_imports(env, &path.st).unwrap_or_else(|| path.st.clone());
        let mut idx = Vec::new();
        for (i, g) in guards.iter().enumerate() {
            // (the untrusted interval pre-check of the prunes first: a guard
            // over atoms no fact bounds costs no query)
            let decided = g.closed && !matches!(super::facts::decidable_with(&st2, &g.cond).0, super::facts::Decidable::No) && crate::opt::guardspec::decide(env, &st2, &g.cond, !g.exit_on, 20_000_000).is_some();
            if self.trace {
                eprintln!("opt: drive: guard {i} of {} (closed {}): {}", self.name(def), g.closed, if decided { "decided" } else { "not decided" });
            }
            if decided {
                idx.push(i as u32);
            }
        }
        if idx.is_empty() {
            return None;
        }
        let key = crate::opt::guardspec::GuardKey { def, guards: idx };
        crate::opt::guardspec::failed(&key).is_none().then_some(key)
    }

    fn decide_filtered(&mut self, st: &St, c: &V) -> Option<(bool, sandblaster_kernel::term::Tm)> {
        // plan O6: the facts of the path's kept calls (`let` facts of a
        // child state; the decision's proof closes over them)
        // and §15 S2: the invariants of the values it tests
        if let Some(st2) = crate::opt::facts::with_decision_facts(self.env, st, c, &|_| None) {
            return self.decide_filtered_in(&st2, c).map(|(b, p)| (b, crate::opt::facts::close(&st2, p)));
        }
        self.decide_filtered_in(st, c)
    }

    fn decide_filtered_in(&mut self, st: &St, c: &V) -> Option<(bool, sandblaster_kernel::term::Tm)> {
        // (a decision inside a fact-directed trial is speculative: an
        // eighth of the cap; QMDB's hopeless `len(before) + len(after) >=
        // 62` in `reconstruct_finish` spent the whole 2M twice per caller;
        // calibrated on QMDB only, until held-out numbers replace it)
        let div = if self.trials > 0 { 8 } else { 1 };
        match super::facts::decidable_with(st, c) {
            (super::facts::Decidable::No, _) => None,
            (super::facts::Decidable::Relational, _) => self.decide(st, c, None, 2_000_000 / div),
            (super::facts::Decidable::ByIntervals, used) => self.decide(st, c, Some(&used), 8_000_000 / div),
        }
    }

    /// Decides a boolean scrutinee from the facts of `st` by linear
    /// arithmetic (`auto`'s step 8, with its integer cuts and disequality
    /// splits), within `cap` steps.
    /// `facts`: decide over generalized leaves with only these facts (by
    /// level; [`super::facts::decide_generalized`]), else with every fact.
    /// Σ3: decides the comparison `c` (its term `c_tm`) by
    /// [`crate::opt::seqsum::segments::lin_decide`] (the same procedure the
    /// leaf proofs use, so that what the driver decides, they prove).
    pub(crate) fn decide_lin(&mut self, st: &St, c_tm: &sandblaster_kernel::term::Tm, c: &V) -> Option<bool> {
        let ids = crate::opt::seqsum::segments::Ids::new(self.env)?;
        let mut sub = Budget { steps: self.budget.steps.min(2_000_000) };
        let start = sub.steps;
        let r = {
            let _scope = crate::auto::meter::Scope::enter(None, &sub);
            let mut eng = Engine::new(self.env, &mut sub, &self.auto_cfg, &self.db, vec![], st.depth());
            let r = crate::opt::seqsum::segments::lin_decide(&mut eng, &ids, st, c_tm, c).map(|(b, _)| b);
            crate::auto::meter::settle(&mut sub);
            r
        };
        self.budget.steps = self.budget.steps.saturating_sub(start - sub.steps);
        r
    }

    pub(crate) fn decide(&mut self, st: &St, c: &V, facts: Option<&[u32]>, cap: u64) -> Option<(bool, sandblaster_kernel::term::Tm)> {
        // bounded per decision: a failed attempt costs at most this much
        let mut sub = Budget { steps: self.budget.steps.min(cap) };
        let start = sub.steps;
        let r = {
            // its own meter scope: the search's charges and a limit it hits
            // (sticky within a scope) end with this decision, never the
            // driver's later ones
            let _scope = crate::auto::meter::Scope::enter(None, &sub);
            let mut eng = Engine::new(self.env, &mut sub, &self.auto_cfg, &self.db, vec![], st.depth());
            // over generalized leaves when it has the shape, else as it is
            let r = match facts.and_then(|fs| super::facts::decide_generalized(&mut eng, st, c, fs, false)) {
                Some(d) => Ok(Some(d)),
                None => match facts {
                    Some(fs) => {
                        let mut st2 = st.clone();
                        st2.facts.retain(|f| fs.contains(&f.lvl));
                        eng.decide_bool(&st2, c)
                    }
                    None => eng.decide_bool(st, c),
                },
            };
            crate::auto::meter::settle(&mut sub);
            r
        };
        self.budget.steps = self.budget.steps.saturating_sub(start - sub.steps);
        if std::env::var_os("SANDBLASTER_OPT_TRACE_SPLITS").is_some() {
            eprintln!("opt: drive: decide: {:?} ({} steps, {} facts; meter {:?}, available {})", r.as_ref().map(|x| x.as_ref().map(|(b, _)| *b)).map_err(|e| format!("{e:?}").chars().take(200).collect::<String>()), start - sub.steps, st.facts.len(), crate::auto::meter::exhausted(), crate::auto::meter::available());
        }
        match r {
            Ok(Some((b, p))) => Some((b, p)),
            _ => None,
        }
    }
}

/// A comparison of a `u64` value with a literal (a range check; the R2
/// fault's target).
fn is_u64_range_check(v: &V) -> bool {
    use sandblaster_kernel::term::{PrimOp, Width};
    let Some((op, args)) = crate::auto::util::as_prim(v) else { return false };
    matches!(op, PrimOp::Le(Width::U64) | PrimOp::Lt(Width::U64) | PrimOp::Ge(Width::U64) | PrimOp::Gt(Width::U64)) && args.iter().any(|a| matches!(&**a, Value::Lit { .. }))
}

/// A kept call that the Σ3 leaf hook rewrites on its segments (or splits on
/// a piece's emptiness) loses the guard specialization pushed for it just
/// before (plan O6, `Step::GuardSpec`, the last step): the call is no longer
/// the source call the guard helper's lemma rewrites, and the proof builder
/// would rewrite the leaf twice. The segment rewrite is preferred; when its
/// helper fails, the key is recorded as failed and the function is driven
/// again, and the guard specialization then stands (`opt::drive_one`).
fn drop_guard_spec(steps: &mut Vec<Step>, v: &V) {
    if let Some(Step::GuardSpec { def, .. }) = steps.last()
        && let Value::Neu(sandblaster_kernel::value::Neutral { head: sandblaster_kernel::value::Head::Global { def: d, .. }, .. }) = &**v
        && d == def
    {
        steps.pop();
    }
}
