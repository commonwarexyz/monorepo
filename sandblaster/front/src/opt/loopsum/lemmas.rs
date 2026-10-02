//! The per-literal lemmas of a loop summary (optimizer design §7.5).
//!
//! For a loop call at literal fuel with `K` iterations, the summarizer
//! proves `K + 1` non-recursive lemmas, from the exhaustion back to the
//! entry (`j` iterations done, `f = K − j` remaining):
//!
//! ```text
//! lemma_j : Π s̄ ḡ (.r : Req_h(j, s̄)) (.h : Req_H(ḡ)) (.i : inv(j, s̄, ḡ)) (.a : alive(j, ḡ)).
//!           Eq(R, h(j, s̄) .r, res ḡ)
//! ```
//!
//! where `s̄` are the dynamic parameters (the static ones are literals at
//! `j`), `ḡ` the ghost inputs, `inv` the per-parameter closed forms of the
//! plan ([`super::invariant`]) and `res` the closed-form result (a
//! kernel-only definition). `lemma_K` is the exhaustion: `Delta` and the
//! exit. `lemma_j` for `j < K` is `Delta` one step, a case split on the
//! body's guards, and in each arm either the exit (a search loop: the
//! witness is pinned to `j` by a bit-count library lemma and rewritten, so
//! the result's shifts become literal) or an application of `lemma_{j+1}`
//! to the next state whose irrelevant arguments — the invariant and
//! `alive` at the next state — are the obligations. Inside a lemma every
//! `2^j`, shift and mask is a literal: the fragment of `BvRefl` and linear
//! arithmetic (with integer cuts). The `FirstMatch` payload's obligation is
//! split on the update's in-place selects; its hit leaf pins the witness
//! and proves the payload field by field.
//!
//! **Obligations** are proven by a focused route first — conversion or an
//! assumption; linear arithmetic over the context's facts plus the
//! library instances the goal's atoms call for (`mask_split`,
//! `popcnt_step`, shift links, conditional instances whose hypotheses
//! linear arithmetic proves), with integer cuts; `BvRefl` — and by `auto`
//! with the same hints when that fails. Every lemma is hash-consed and
//! committed with `Env::add_def`: the kernel checks it.

use std::collections::BTreeMap;
use std::rc::Rc;

use num_traits::ToPrimitive;
use sandblaster_kernel::api::{Ctx, Env};
use sandblaster_kernel::term::{DefDecl, DefKind, GlobalId, Lvl, PrimOp, Recursion, Rel, Term, Tm, Width};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::{Arg, Budget, Elim, EnvEntry, Head, Neutral, V, Value};

use crate::auto::bitlib::{self, Family};
use crate::auto::lemmas::LemmaDb;
use crate::auto::search::{Engine, R};
use crate::auto::state::St;
use crate::auto::util::{apps, as_eq, irr_entry, prefix, venv_push};
use crate::auto::{Auto, AutoConfig};
use crate::prover::{Goal, Hint, ObligationId, ObligationKind, Prover};
use crate::span::Span;

use super::expr::{self, CE, E};

/// Step budget of one obligation.
pub const OBLIGATION_STEPS: u64 = 20_000_000;
/// Step budget of `auto`, the obligation's last resort (the focused route
/// closes every obligation of the corpus and QMDB loops; a wrong candidate
/// must fail fast). Calibrated on the corpus and QMDB only (fairness audit
/// J13) until the held-out set re-checks it.
pub const AUTO_STEPS: u64 = 2_000_000;
/// Budget of one lemma (design §17: ≤ 5·10^6 per literal lemma is the
/// target; the hard cap is higher so a slow lemma still closes).
pub const LEMMA_STEPS: u64 = 60_000_000;

// ---------------------------------------------------------------------------
// The specification of the lemma chain.
// ---------------------------------------------------------------------------

/// What the builder needs to know about the loop (rendered from the plan).
pub struct Spec {
    pub func: GlobalId,
    /// Core name of the loop global.
    pub func_text: String,
    /// The loop's result type (core text).
    pub ret: String,
    pub k: u32,
    /// Dynamic parameters: (binder name, type text, parameter index).
    pub state: Vec<(String, String, u32)>,
    /// Ghost binders (not shared with a state binder): (name, type text).
    pub ghosts: Vec<(String, String)>,
    /// Every ghost's name, in ghost order (shared ones are state names).
    pub ghost_names: Vec<String>,
    /// The call's `requires` at the ghosts (`.h<i>`).
    pub ghost_facts: Vec<String>,
    /// Per `j`: the loop's `requires` at the state (`.r<i>`).
    pub reqs: Vec<Vec<String>>,
    /// Per `j`: the invariant conjuncts (name, statement).
    pub inv: Vec<Vec<(String, String)>>,
    /// Per `j`: the loop call over the binders.
    pub lhs: Vec<String>,
    /// The closed-form result applied to the ghosts.
    pub res: String,
    /// `FirstMatch`: the payload parameter's state binder name.
    pub payload_binder: Option<String>,
    /// The witness `E(ḡ)` (ghost space).
    pub witness: E,
    /// Families of bit lemmas the proofs may instantiate.
    pub families: Vec<Family>,
    /// The machine width of the witness atoms' operands.
    pub word: Width,
    /// `FirstMatch`: the constructor of the unset payload value (`None`).
    pub unset_ctor: Option<u32>,
}

impl Spec {
    /// The binders of `lemma_j`: (name, type text).
    pub fn binders(&self, j: u32) -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = self.state.iter().map(|(n, t, _)| (n.clone(), t.clone())).collect();
        v.extend(self.ghosts.iter().cloned());
        for (i, r) in self.reqs[j as usize].iter().enumerate() {
            v.push((format!(".r{i}"), r.clone()));
        }
        for (i, h) in self.ghost_facts.iter().enumerate() {
            v.push((format!(".gf{i}"), h.clone()));
        }
        v.extend(self.inv[j as usize].iter().cloned());
        v
    }

    /// `lemma_j`'s statement (a closed Π term).
    pub fn statement(&self, env: &Env, j: u32) -> Result<Tm, String> {
        let pis: String = self.binders(j).iter().map(|(n, t)| format!("({n} : {t}) -> ")).collect();
        let src = format!("{pis}Eq({}, {}, {})", self.ret, self.lhs[j as usize], self.res);
        self.parse_closed(env, &src).map_err(|e| format!("lemma_{j} statement: {e}\n{src}"))
    }

    /// A closed statement mentioning the loop by `func_text`: a generated
    /// loop's name (`f::loop#k`) is not a core identifier, so it is parsed
    /// as a bound name and the loop's global substituted for it.
    pub fn parse_closed(&self, env: &Env, src: &str) -> Result<Tm, sandblaster_kernel::api::KernelError> {
        if !self.func_text.contains('#') {
            return env.parse_term(&[], src);
        }
        const FN: &str = "loop__fn";
        let t = env.parse_term(&[FN], &src.replace(&self.func_text, FN))?;
        Ok(crate::auto::util::subst0(&t, &mk::global(self.func)))
    }
}

// ---------------------------------------------------------------------------
// Statistics.
// ---------------------------------------------------------------------------

/// Steps and outcomes per obligation class.
#[derive(Default, Clone, Debug)]
pub struct Stats {
    pub classes: BTreeMap<String, (u32, u32, u64, u64)>, // n, ok, steps, max
    pub lemma_steps: Vec<u64>,
    pub check_steps: u64,
    pub fast: u32,
    pub auto: u32,
    /// Focused proofs found with the class's remembered selection, and the
    /// ones that needed every fact and hint.
    pub memo_hits: u32,
    pub memo_misses: u32,
    /// Obligations closed by the summary chain's proof, and how many of
    /// those the kernel checked first ([`Builder::obligation`]).
    pub shared: u32,
    pub shared_checked: u32,
    pub first_failure: Option<String>,
}

impl Stats {
    fn record(&mut self, class: &str, steps: u64, ok: bool) {
        let c = self.classes.entry(class.to_string()).or_insert((0, 0, 0, 0));
        c.0 += 1;
        if ok {
            c.1 += 1;
        }
        c.2 += steps;
        c.3 = c.3.max(steps);
    }

    pub fn total(&self) -> u64 {
        self.lemma_steps.iter().sum::<u64>() + self.check_steps
    }

    pub fn report(&self) -> String {
        let mut s = String::new();
        for (k, (n, ok, st, mx)) in &self.classes {
            s.push_str(&format!("{k:<24} {n:>4} {ok:>4} {st:>12} {mx:>10}\n"));
        }
        s.push_str(&format!("fast {} / auto {} (memo {} hits, {} misses); shared {} ({} kernel-checked); lemma steps {}; kernel check steps {}\n", self.fast, self.auto, self.memo_hits, self.memo_misses, self.shared, self.shared_checked, self.lemma_steps.iter().sum::<u64>(), self.check_steps));
        s
    }
}

// ---------------------------------------------------------------------------
// Term helpers (as in the D1 prototype, tests/opt_obligations_shape.rs).
// ---------------------------------------------------------------------------

fn names_of(ctx: &Ctx) -> Vec<String> {
    ctx.entries.iter().map(|e| e.name.to_string()).collect()
}

pub fn parse_in(env: &Env, ctx: &Ctx, src: &str) -> Result<Tm, String> {
    let names = names_of(ctx);
    let ns: Vec<&str> = names.iter().map(|n| n.as_str()).collect();
    env.parse_term(&ns, src).map_err(|e| format!("parse `{}`: {e}", src.chars().take(200).collect::<String>()))
}

fn eval_in(env: &Env, ctx: &Ctx, t: &Tm) -> Result<V, String> {
    env.eval(&env.ctx_venv(ctx), ctx.depth(), t, &mut Budget { steps: 50_000_000 }).map_err(|e| format!("eval: {e:?}"))
}

/// `refl` when the sides of an equation convert, or an assumption of the
/// context (promoted, so the proof is valid in any position).
pub(crate) fn trivial(env: &Env, ctx: &Ctx, target: &V, b: &mut Budget) -> Option<Tm> {
    let d = ctx.depth();
    let (ty, l, r) = as_eq(target)?;
    let ty_tm = env.quote_typed(ctx, ty, None, false);
    if env.conv(d, l, r, b).ok()? {
        return Some(mk::refl(ty_tm, env.quote_typed(ctx, l, Some(ty), false)));
    }
    for (i, e) in ctx.entries.iter().enumerate().rev() {
        if matches!(&*e.ty, Value::Eq { .. }) && env.conv(d, &e.ty, target, b).ok()? {
            let promote = env.lookup_global("eq::promote")?;
            let v = mk::var(d.0 - 1 - i as u32);
            return Some(if e.rel == Rel::Irr {
                apps(
                    mk::global(promote),
                    [
                        (Rel::Rel, ty_tm.clone()),
                        (Rel::Rel, env.quote_typed(ctx, l, Some(ty), false)),
                        (Rel::Rel, env.quote_typed(ctx, r, Some(ty), false)),
                        (Rel::Irr, v),
                    ],
                )
            } else {
                v
            });
        }
    }
    None
}

/// The scrutinee of the first stuck match of a value.
fn first_scrut(v: &V) -> Option<V> {
    let Value::Neu(n) = &**v else { return None };
    let i = n.spine.iter().position(|e| matches!(e, Elim::Match { .. }))?;
    Some(prefix(n, i))
}

/// The global application `func args` a value is, if any.
fn call_args(v: &V, func: GlobalId) -> Option<Vec<Arg>> {
    match &**v {
        Value::Neu(Neutral { head: Head::Global { def, args }, spine }) if *def == func && spine.is_empty() => Some(args.clone()),
        _ => None,
    }
}

/// Rewrite `target` (a value in `arm`) with `eq : Eq(ty, lit, t)`:
/// occurrences of `t` become `lit`. Returns the new target and the wrapper
/// turning its proof into one of `target` (a transport).
pub(crate) type Wrap = Box<dyn FnOnce(Tm) -> Tm>;

pub(crate) fn rewrite(env: &Env, arm: &St, target: &V, t: &Tm, lit: &Tm, ty: Tm, eq: Tm) -> Option<(V, Wrap)> {
    let tv = eval_in(env, &arm.ctx, t).ok()?;
    let litv = eval_in(env, &arm.ctx, lit).ok()?;
    let motive = env.abstract_occurrences(&arm.ctx, target, &tv, &mut Budget { steps: 100_000_000 }).ok()?;
    let t2 = env.eval(&venv_push(&arm.venv, EnvEntry::Rel(litv)), Lvl(arm.ctx.depth().0 + 1), &motive, &mut Budget { steps: 100_000_000 }).ok()?;
    let (t, lit) = (t.clone(), lit.clone());
    Some((t2, Box::new(move |p: Tm| Rc::new(Term::Transport { ty, lhs: lit, rhs: t, eq, motive, val: p }))))
}

/// Open a Π type into a state (binders as λ wrappers); returns the body.
pub(crate) fn open(e: &mut Engine<'_>, st: &mut St, ty: &Tm) -> Result<V, String> {
    let env = e.env;
    let mut cur = eval_in(env, &st.ctx, ty)?;
    while let Value::Pi { name, rel, dom, cod } = &*cur.clone() {
        let is_prop = e.is_prop(dom, st.depth());
        let entry = st.push_lam(env, name.clone(), *rel, dom.clone(), is_prop);
        cur = e.inst(cod, vec![entry], st.depth()).ok().flatten().ok_or("opening a lemma statement")?;
    }
    Ok(cur)
}

/// `op(a)` for a bit-count primitive `op`.
fn unary_bitcount(v: &V) -> Option<(PrimOp, V)> {
    match &**v {
        Value::Neu(Neutral { head: Head::Prim { op, args, .. }, spine }) if spine.is_empty() && matches!(op, PrimOp::CountOnes(_) | PrimOp::LeadingZeros(_) | PrimOp::TrailingZeros(_)) => {
            Some((*op, args[0].clone()))
        }
        _ => None,
    }
}

/// Proofs of the summary chain's obligations, by (loop, literal, class
/// without its chain prefix, occurrence), with their context and goal
/// ([`Builder::obligation`]); emptied per loop summary ([`reset_shared`]).
type SharedKey = (GlobalId, u32, String, u32);

thread_local! {
    static SHARED: std::cell::RefCell<std::collections::HashMap<SharedKey, (Tm, Ctx, Tm)>> = std::cell::RefCell::new(std::collections::HashMap::new());
}

thread_local! {
    /// The loop body with its proofs outlined, as the summary chain uses it
    /// (the fact chain's goals then read the same outlined lemmas).
    static SHARED_BODY: std::cell::RefCell<Option<(GlobalId, Tm)>> = const { std::cell::RefCell::new(None) };
}

/// Empties the shared obligation proofs (a loop summary's start and end).
pub fn reset_shared() {
    SHARED.with(|m| m.borrow_mut().clear());
    SHARED_BODY.with(|m| *m.borrow_mut() = None);
}

/// The summary chain's outlined body of the loop `func`, if it built one.
pub fn shared_body(func: GlobalId) -> Option<Tm> {
    SHARED_BODY.with(|m| m.borrow().as_ref().filter(|(f, _)| *f == func).map(|(_, t)| t.clone()))
}

/// The shared proof under `key`, its free variables renamed to the entries
/// of `st` with the same names (each name unique in both contexts), if the
/// kernel accepts it as a proof of `target` in `st`.
fn shared_proof(env: &Env, st: &St, target: &V, key: &SharedKey) -> Option<(Tm, bool)> {
    let (p, src, goal_s) = SHARED.with(|m| m.borrow().get(key).cloned())?;
    let names = names_of(&src);
    let here = names_of(&st.ctx);
    let unique = |ns: &[String], n: &str| ns.iter().filter(|x| x.as_str() == n).count() == 1;
    let mut map: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();
    for (l, n) in names.iter().enumerate() {
        if unique(&names, n)
            && unique(&here, n)
            && let Some(l2) = here.iter().position(|x| x == n)
        {
            map.insert(l as u32, l2);
        }
    }
    let same_up_to_renaming = |t_src: &Tm, d_src: usize, t_tgt: &Tm, d_tgt: usize| -> bool {
        crate::elab::tm::rename_levels(t_src, d_src as u32, &map, d_tgt as u32).is_some_and(|r| env.alpha_eq_relevant(&r, t_tgt, &|a, b| a == b))
    };
    // the same goal, up to the renaming
    let goal_t = st.quote(env, target);
    if !same_up_to_renaming(&goal_s, names.len(), &goal_t, here.len()) {
        return None;
    }
    let p2 = crate::elab::tm::rename_levels(&p, names.len() as u32, &map, here.len() as u32)?;
    // the entries it uses have the same types here up to the renaming and
    // none is a definition: the renaming then maps a proof to a proof (the
    // kernel checks the fact lemma it becomes part of); otherwise the
    // kernel checks it now
    let mut used: Vec<u32> = Vec::new();
    crate::elab::tm::any_node_depth(&p, &mut |n, d| {
        if let Term::Var(i) = n
            && i.0 >= d
            && ((i.0 - d) as usize) < names.len()
        {
            used.push(names.len() as u32 - 1 - (i.0 - d));
        }
        false
    });
    used.sort();
    used.dedup();
    let entry_type = |ctx: &Ctx, l: usize| -> Option<Tm> {
        let e = ctx.entries.get(l)?;
        if e.def.is_some() {
            return None;
        }
        let pre = Ctx { entries: Rc::new(ctx.entries[..l].to_vec()) };
        Some(env.quote_typed(&pre, &e.ty, None, false))
    };
    let same = used.iter().all(|l| {
        let Some(&l2) = map.get(l) else { return false };
        match (entry_type(&src, *l as usize), entry_type(&st.ctx, l2)) {
            (Some(a), Some(b)) => same_up_to_renaming(&a, *l as usize, &b, l2),
            _ => false,
        }
    });
    if same {
        return Some((p2, false));
    }
    let mut b = Budget { steps: OBLIGATION_STEPS };
    let ty = env.infer(&st.ctx, &p2, &mut b).ok()?;
    env.conv(st.ctx.depth(), &ty, target, &mut b).ok()?.then_some((p2, true))
}

/// Structural hash-consing of a proof term: identical subterms become one
/// shared node (the proofs repeat the quoted loop body and requires proofs
/// heavily; without sharing a lemma is ~25× larger). A node's key is its
/// head (the variant and its non-term fields) and its children's canonical
/// nodes (by address); the maps hash with a multiplicative hasher (the keys
/// are addresses and small integers, never attacker-chosen).
pub fn hashcons(t: &Tm) -> Tm {
    use sandblaster_kernel::term::{AxiomId, BigInt, IndId, Name, Rat, Sort};
    use crate::auto::util::FxMap;
    /// A node's head: its variant and non-term fields.
    #[derive(PartialEq, Eq, Hash)]
    enum Head {
        Var(u32),
        Global(GlobalId),
        Sort(Sort),
        Pi(Name, Rel),
        Lam(Name, Rel),
        App(Rel),
        Let(Name, Rel),
        Sigma(Name, Rel),
        Pair,
        Fst,
        Snd,
        Eq,
        Refl,
        Transport,
        Ind(IndId),
        Ctor(IndId, u32, usize),
        Match(IndId, usize, Vec<Vec<Name>>),
        IntTy(Width),
        Lit(Width, BigInt),
        Prim(PrimOp, usize),
        Rec(bool),
        Delta(GlobalId),
        Unfold(GlobalId, bool),
        Linarith(usize, Vec<Rat>),
        BvRefl,
        Absurd,
        Axiom(AxiomId),
        Erased,
    }
    struct H {
        canon: FxMap<(Head, Vec<usize>), Tm>,
        seen: FxMap<usize, Tm>,
        keep: Vec<Tm>,
    }
    fn p(t: &Tm) -> usize {
        Rc::as_ptr(t) as *const () as usize
    }
    impl H {
        fn go(&mut self, t: &Tm) -> Tm {
            if let Some(c) = self.seen.get(&p(t)) {
                return c.clone();
            }
            let mut kids: Vec<usize> = Vec::new();
            let mut sub = |this: &mut H, x: &Tm| {
                let c = this.go(x);
                kids.push(p(&c));
                c
            };
            let (head, rebuilt): (Head, Term) = match &**t {
                Term::Var(i) => (Head::Var(i.0), Term::Var(*i)),
                Term::Global(g) => (Head::Global(*g), Term::Global(*g)),
                Term::Sort(s) => (Head::Sort(*s), Term::Sort(*s)),
                Term::Pi { name, rel, dom, cod } => (Head::Pi(name.clone(), *rel), Term::Pi { name: name.clone(), rel: *rel, dom: sub(self, dom), cod: sub(self, cod) }),
                Term::Lam { name, rel, dom, body } => (Head::Lam(name.clone(), *rel), Term::Lam { name: name.clone(), rel: *rel, dom: sub(self, dom), body: sub(self, body) }),
                Term::App { rel, fun, arg } => (Head::App(*rel), Term::App { rel: *rel, fun: sub(self, fun), arg: sub(self, arg) }),
                Term::Let { name, rel, ty, val, body } => (Head::Let(name.clone(), *rel), Term::Let { name: name.clone(), rel: *rel, ty: sub(self, ty), val: sub(self, val), body: sub(self, body) }),
                Term::Sigma { name, snd_rel, fst, snd } => (Head::Sigma(name.clone(), *snd_rel), Term::Sigma { name: name.clone(), snd_rel: *snd_rel, fst: sub(self, fst), snd: sub(self, snd) }),
                Term::Pair { ty, fst, snd } => (Head::Pair, Term::Pair { ty: sub(self, ty), fst: sub(self, fst), snd: sub(self, snd) }),
                Term::Fst(x) => (Head::Fst, Term::Fst(sub(self, x))),
                Term::Snd(x) => (Head::Snd, Term::Snd(sub(self, x))),
                Term::Eq { ty, lhs, rhs } => (Head::Eq, Term::Eq { ty: sub(self, ty), lhs: sub(self, lhs), rhs: sub(self, rhs) }),
                Term::Refl { ty, val } => (Head::Refl, Term::Refl { ty: sub(self, ty), val: sub(self, val) }),
                Term::Transport { ty, lhs, rhs, eq, motive, val } => (Head::Transport, Term::Transport { ty: sub(self, ty), lhs: sub(self, lhs), rhs: sub(self, rhs), eq: sub(self, eq), motive: sub(self, motive), val: sub(self, val) }),
                Term::Ind { ind, params } => (Head::Ind(*ind), Term::Ind { ind: *ind, params: params.iter().map(|x| sub(self, x)).collect() }),
                Term::Ctor { ind, ctor, params, args } => (Head::Ctor(*ind, *ctor, params.len()), Term::Ctor { ind: *ind, ctor: *ctor, params: params.iter().map(|x| sub(self, x)).collect(), args: args.iter().map(|x| sub(self, x)).collect() }),
                Term::Match { ind, params, scrut, motive, arms } => (
                    Head::Match(*ind, params.len(), arms.iter().map(|a| a.names.clone()).collect()),
                    Term::Match {
                        ind: *ind,
                        params: params.iter().map(|x| sub(self, x)).collect(),
                        scrut: sub(self, scrut),
                        motive: sub(self, motive),
                        arms: arms.iter().map(|a| sandblaster_kernel::term::Arm { names: a.names.clone(), body: sub(self, &a.body) }).collect(),
                    },
                ),
                Term::IntTy(w) => (Head::IntTy(*w), Term::IntTy(*w)),
                Term::Lit { w, n } => (Head::Lit(*w, n.clone()), Term::Lit { w: *w, n: n.clone() }),
                Term::Prim { op, args, proofs } => (Head::Prim(*op, args.len()), Term::Prim { op: *op, args: args.iter().map(|x| sub(self, x)).collect(), proofs: proofs.iter().map(|x| sub(self, x)).collect() }),
                Term::Rec { args, proof } => (Head::Rec(proof.is_some()), Term::Rec { args: args.iter().map(|x| sub(self, x)).collect(), proof: proof.as_ref().map(|x| sub(self, x)) }),
                Term::Delta { def, args } => (Head::Delta(*def), Term::Delta { def: *def, args: args.iter().map(|x| sub(self, x)).collect() }),
                Term::Unfold { def, args, to_body, val } => (Head::Unfold(*def, *to_body), Term::Unfold { def: *def, args: args.iter().map(|x| sub(self, x)).collect(), to_body: *to_body, val: sub(self, val) }),
                Term::Linarith { hyps, goal, cert } => (Head::Linarith(hyps.len(), cert.clone()), Term::Linarith { hyps: hyps.iter().map(|(a, b)| (sub(self, a), sub(self, b))).collect(), goal: sub(self, goal), cert: cert.clone() }),
                Term::BvRefl { ty, lhs, rhs } => (Head::BvRefl, Term::BvRefl { ty: sub(self, ty), lhs: sub(self, lhs), rhs: sub(self, rhs) }),
                Term::Absurd { ty, proof } => (Head::Absurd, Term::Absurd { ty: sub(self, ty), proof: sub(self, proof) }),
                Term::Axiom { ax, args } => (Head::Axiom(*ax), Term::Axiom { ax: *ax, args: args.iter().map(|x| sub(self, x)).collect() }),
                Term::Erased => (Head::Erased, Term::Erased),
            };
            let c = match self.canon.entry((head, kids)) {
                std::collections::hash_map::Entry::Occupied(o) => o.get().clone(),
                std::collections::hash_map::Entry::Vacant(v) => v.insert(Rc::new(rebuilt)).clone(),
            };
            self.seen.insert(p(t), c.clone());
            self.keep.push(t.clone());
            c
        }
    }
    let mut h = H { canon: FxMap::default(), seen: FxMap::default(), keep: Vec::new() };
    h.go(t)
}

/// Commits a lemma (hash-consed) with `Env::add_def`; returns the global
/// and the kernel's check steps.
pub fn add_lemma(env: &mut Env, name: &str, ty: Tm, body: Tm, budget: u64) -> Result<(GlobalId, u64), String> {
    add_consed(env, name, ty, hashcons(&body), budget)
}

/// [`add_lemma`] of a body already hash-consed ([`hashcons`]; the chains
/// hash-cons once for the kernel and the proof cache).
pub fn add_consed(env: &mut Env, name: &str, ty: Tm, body: Tm, budget: u64) -> Result<(GlobalId, u64), String> {
    let mut arity = 0;
    let mut t = &ty;
    while let Term::Pi { cod, .. } = &**t {
        arity += 1;
        t = cod;
    }
    // (within a loop summary: capped by its step meter, `super::meter`)
    let budget = super::meter::cap(budget);
    let mut b = Budget { steps: budget };
    let r = env.add_def(DefDecl { name: Rc::from(name), kind: DefKind::Lemma, ty, body, recursion: Recursion::None, arity, opaque: true }, &mut b);
    super::meter::charge(budget - b.steps);
    let g = r.map_err(|e| {
        if std::env::var_os("SANDBLASTER_LOOPSUM_TRACE").is_some() {
            eprintln!("[loopsum] {name} rejected: {e}");
        }
        format!("{name}: {}", e.to_string().chars().take(600).collect::<String>())
    })?;
    Ok((g, budget - b.steps))
}

// ---------------------------------------------------------------------------
// Hints: library instances the goal's atoms call for.
// ---------------------------------------------------------------------------

fn lit_of(v: &V) -> Option<u128> {
    match &**v {
        Value::Lit { n, .. } => n.to_u128(),
        _ => None,
    }
}

fn prim(v: &V) -> Option<(PrimOp, &[V])> {
    crate::auto::util::as_prim(v)
}

/// The machine width's type text.
fn wty(w: Width) -> Tm {
    mk::int_ty(w)
}

/// Library instances for the atoms of `vals` (see the module docs):
/// `(proof term, conditions)` where conditions are hypotheses the instance
/// still needs (discharged by the caller). Deterministic order.
fn atom_hints(env: &Env, st: &St, vals: &[V]) -> Vec<Tm> {
    let mut out: Vec<Tm> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut push = |t: Tm, out: &mut Vec<Tm>| {
        let k = format!("{t:?}");
        if seen.insert(k) {
            out.push(t);
        }
    };
    for v in vals {
        crate::auto::util::walk(v, &mut |x| {
            if let Some((op, args)) = prim(x) {
                match op {
                    PrimOp::And(w) if args.len() == 2 => {
                        if let Some(m) = lit_of(&args[1]) {
                            let k1 = (m + 1).trailing_zeros();
                            // x & (2^k − 1): mask_split_{k−1}
                            if m > 0 && (m + 1).is_power_of_two() && k1 >= 1 && k1 <= expr::bits(w)
                                && let Some(g) = env.lookup_global(&bitlib::lemma_name(Family::MaskSplit, w, k1 - 1))
                            {
                                push(apps(mk::global(g), [(Rel::Rel, st.quote(env, &args[0]))]), &mut out);
                            }
                            // (x >> k) & 1: mask_split_k
                            if m == 1
                                && let Some((PrimOp::WShr(w2), a2)) = prim(&args[0])
                                && w2 == w
                                && let Some(k) = lit_of(&a2[1])
                                && (k as u32) < expr::bits(w)
                                && let Some(g) = env.lookup_global(&bitlib::lemma_name(Family::MaskSplit, w, k as u32))
                            {
                                push(apps(mk::global(g), [(Rel::Rel, st.quote(env, &a2[0]))]), &mut out);
                            }
                        }
                    }
                    PrimOp::CountOnes(w) if args.len() == 1 => {
                        if let Some((PrimOp::WShr(w2), a2)) = prim(&args[0])
                            && w2 == w
                            && let Some(m) = lit_of(&a2[1])
                            && (m as u32) < expr::bits(w)
                        {
                            for k in [m as u32, (m as u32).wrapping_sub(1)] {
                                if k < expr::bits(w)
                                    && let Some(g) = env.lookup_global(&bitlib::lemma_name(Family::PopcntStep, w, k))
                                {
                                    push(apps(mk::global(g), [(Rel::Rel, st.quote(env, &a2[0]))]), &mut out);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            true
        });
    }
    out
}

/// Shift links: for nested literal shifts `(x >> a) >> b` in the values,
/// `bvrefl((x >> a) >> b, x >> (a + b))` (or `= 0`), and the same under
/// `count_ones` by congruence.
fn shift_links(env: &Env, st: &St, vals: &[V]) -> Vec<Tm> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let cong = env.lookup_global("eq::cong");
    for v in vals {
        crate::auto::util::walk(v, &mut |x| {
            let under_cnt = matches!(prim(x), Some((PrimOp::CountOnes(_), _)));
            let inner = if under_cnt { prim(x).map(|(_, a)| a[0].clone()) } else { Some(x.clone()) };
            if let Some(y) = inner
                && let Some((PrimOp::WShr(w), a)) = prim(&y)
                && let Some(b) = lit_of(&a[1])
                && let Some((PrimOp::WShr(w2), a2)) = prim(&a[0])
                && w2 == w
                && let Some(aa) = lit_of(&a2[1])
            {
                let lhs = st.quote(env, &y);
                let base = st.quote(env, &a2[0]);
                let rhs = if aa + b < expr::bits(w) as u128 { sandblaster_kernel::prim::prim0(PrimOp::WShr(w), vec![base, mk::lit(Width::U32, aa + b)]) } else { mk::lit(w, 0u32) };
                let key = format!("{lhs:?}{under_cnt}");
                if seen.insert(key) {
                    let bv = Rc::new(Term::BvRefl { ty: wty(w), lhs: lhs.clone(), rhs: rhs.clone() });
                    out.push(bv.clone());
                    if under_cnt && let Some(c) = cong {
                        let f = mk::lam("y", Rel::Rel, wty(w), mk::prim(PrimOp::CountOnes(w), vec![mk::var(0)], vec![]));
                        out.push(apps(mk::global(c), [(Rel::Rel, wty(w)), (Rel::Rel, mk::int_ty(Width::U32)), (Rel::Rel, f), (Rel::Rel, lhs), (Rel::Rel, rhs), (Rel::Rel, bv)]));
                    }
                }
            }
            true
        });
    }
    out
}

// ---------------------------------------------------------------------------
// The builder.
// ---------------------------------------------------------------------------

/// Builds the lemma chain of one loop summary.
pub struct Builder<'s> {
    pub spec: &'s Spec,
    pub stats: Stats,
    pub j: u32,
    auto: Auto,
    pub trace: bool,
    /// Hints that failed their kernel type check (skipped).
    bad_hints: usize,
    /// Facts proven while pinning a witness (for the leaf's obligations).
    pin_facts: Vec<Tm>,
    /// A simulated fault: unproven obligations are claimed (see
    /// [`build_chain_trusting`]).
    pub trust: bool,
    /// Per obligation class: the facts (binder names) and hints (keys) the
    /// last proof of the class used — the next literal's obligation of the
    /// class is tried over just those first (a small linear system).
    /// Per obligation class: the facts and hint keys its last proof used,
    /// and the linear-arithmetic round that found it (`Engine::lin_round`).
    memo: std::collections::HashMap<String, (Vec<String>, Vec<String>, u32)>,
    /// Wall-clock split of the obligations (development timing only).
    pub t_hints: std::time::Duration,
    pub t_lin: std::time::Duration,
    pub t_other: std::time::Duration,
    /// The loop's body with its `linarith` proofs outlined into lemmas
    /// (`opt::outline`: convertible with the committed body, so `Delta`'s
    /// equation holds for it; every copy of it in a motive then costs the
    /// kernel an application instead of the proofs).
    pub body: Option<Tm>,
    /// During a magnitude split on `y` for an `lz(y | 1)` witness: the lz
    /// argument and the texts of `y | 1` and `y` (see `exit_by_range`).
    range_arg: Option<(Tm, (String, String))>,
    /// Nesting of the threshold-regime route ([`Builder::regime`]).
    regime_depth: u32,
    /// Obligations so far per (literal, class without its chain prefix):
    /// the key of the proofs shared between the chains ([`SHARED`]).
    occurrences: std::collections::HashMap<(u32, String), u32>,
}

impl<'s> Builder<'s> {
    pub fn new(spec: &'s Spec) -> Builder<'s> {
        let auto = Auto::with_config(AutoConfig { self_check: false, goal_timeout: Some(std::time::Duration::from_secs(10)), ..AutoConfig::default() });
        Builder { spec, stats: Stats::default(), j: 0, auto, trace: std::env::var_os("SANDBLASTER_LOOPSUM_TRACE").is_some(), bad_hints: 0, pin_facts: Vec::new(), trust: false, memo: std::collections::HashMap::new(), t_hints: std::time::Duration::ZERO, t_lin: std::time::Duration::ZERO, t_other: std::time::Duration::ZERO, body: None, range_arg: None, regime_depth: 0, occurrences: std::collections::HashMap::new() }
    }

    /// Typed hint instances as linarith hypotheses (their statements by
    /// kernel inference in the arm's context).
    fn hint_hyp(&mut self, env: &Env, ctx: &Ctx, h: &Tm) -> Option<(Tm, Tm)> {
        let mut b = Budget { steps: 2_000_000 };
        match env.infer(ctx, h, &mut b) {
            Ok(ty) => Some((h.clone(), env.quote_typed(ctx, &ty, None, false))),
            Err(_) => {
                self.bad_hints += 1;
                None
            }
        }
    }

    /// Conditional library instances whose hypothesis linear arithmetic
    /// proves from the facts: `popcnt_shr_zero_k x h : cnt(x >> k) = 0`
    /// for a `cnt(x >> k)` atom with `x < 2^k` provable.
    fn conditional_hints(&mut self, e: &mut Engine<'_>, st: &St, vals: &[V]) -> Vec<Tm> {
        let env = e.env;
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut cands: Vec<(Width, V, u32)> = Vec::new();
        for v in vals {
            crate::auto::util::walk(v, &mut |x| {
                if let Some((PrimOp::CountOnes(w), a)) = prim(x)
                    && let Some((PrimOp::WShr(w2), a2)) = prim(&a[0])
                    && w2 == w
                    && let Some(k) = lit_of(&a2[1])
                    && k >= 1
                    && (k as u32) < expr::bits(w)
                    && seen.insert(format!("{:?}{k}", Rc::as_ptr(&a2[0])))
                {
                    cands.push((w, a2[0].clone(), k as u32));
                }
                true
            });
        }
        for (w, x, k) in cands {
            let Some(g) = env.lookup_global(&bitlib::lemma_name(Family::PopcntShrZero, w, k)) else { continue };
            let xt = st.quote(env, &x);
            let ws = sandblaster_kernel::prim::width_suffix(w);
            let goal = mk::eq(mk::bool_ty(env.bool_ind()), sandblaster_kernel::prim::prim0(PrimOp::Lt(w), vec![xt.clone(), mk::lit(w, 1u128 << k)]), mk::bool_lit(env.bool_ind(), true));
            let Ok(gv) = eval_in(env, &st.ctx, &goal) else { continue };
            let hyps = e.lin_hyps(st);
            if let Ok(Some(p)) = e.lin_with(st, &hyps, &gv) {
                let _ = ws;
                out.push(apps(mk::global(g), [(Rel::Rel, xt), (Rel::Irr, p)]));
            }
        }
        out
    }

    /// Prove `target` in `st` (see the module docs), recording the steps
    /// under `class`. `extra`: more hint terms.
    ///
    /// The fact chain (`facts`) repeats the summary chain's obligations at
    /// the recursive call (the invariant at the next state, the loop's
    /// requires): the summary chain's proof of the obligation of the same
    /// class at the same literal and occurrence ([`SHARED`]) is carried over
    /// by the names of the context entries it uses, when the goal and the
    /// types of those entries are the same up to that renaming (else the
    /// kernel checks it first); otherwise the obligation is proven as usual.
    pub fn obligation(&mut self, e: &mut Engine<'_>, st: &St, target: &V, class: &str, extra: &[Tm]) -> Option<Tm> {
        let share = class.split_once('.').filter(|(pre, _)| *pre == "step" || *pre == "fact");
        let key = share.map(|(_, suffix)| {
            let n = self.occurrences.entry((self.j, suffix.to_string())).or_insert(0);
            *n += 1;
            (self.spec.func, self.j, suffix.to_string(), *n)
        });
        if let (Some(("fact", _)), Some(k)) = (share, &key)
            && let Some((p, checked)) = shared_proof(e.env, st, target, k)
        {
            self.stats.record(class, 0, true);
            self.stats.shared += 1;
            self.stats.shared_checked += checked as u32;
            if self.trace {
                eprintln!("[loopsum] j={} {class}: the summary chain's proof", self.j);
            }
            return Some(p);
        }
        let r = self.obligation_search(e, st, target, class, extra);
        // (never a simulated fault's certificate-free claim)
        if let (Some(("step", _)), Some(k), Some(p), false) = (share, key, &r, self.trust) {
            let goal = st.quote(e.env, target);
            SHARED.with(|m| m.borrow_mut().insert(k, (p.clone(), st.ctx.clone(), goal)));
        }
        r
    }

    fn obligation_search(&mut self, e: &mut Engine<'_>, st: &St, target: &V, class: &str, extra: &[Tm]) -> Option<Tm> {
        let env = e.env;
        let ctx = &st.ctx;
        let mut cb = Budget { steps: OBLIGATION_STEPS };
        if let Some(p) = trivial(env, ctx, target, &mut cb) {
            self.stats.record(class, OBLIGATION_STEPS - cb.steps, true);
            return Some(p);
        }
        // the hints: atoms of the goal and of the facts (and of the facts
        // with each state variable replaced by its closed form)
        let th = std::time::Instant::now();
        let derived = subst_facts(env, st);
        let mut vals = vec![target.clone()];
        for f in &st.facts {
            vals.push(f.ty.clone());
        }
        for (_, ty) in &derived {
            vals.push(ty.clone());
        }
        let mut hints = atom_hints(env, st, &vals);
        hints.extend(shift_links(env, st, &vals));
        hints.extend(extra.iter().cloned());
        hints.extend(derived.iter().map(|(p, _)| p.clone()));
        hints.extend(self.conditional_hints(e, st, &vals));
        // focused route: linear arithmetic over the facts and the hint
        // instances (as `let` facts), with enrichment and integer cuts —
        // first over what the class's last proof used, then over everything
        let before = e.b.steps;
        let f_now = self.spec.k as i64 - self.j as i64;
        let keys: Vec<String> = hints.iter().map(|h| hint_key(env, h, f_now)).collect();
        // the hints' statements, computed when first given (the class's
        // last proof usually needs few of them); a hint whose statement
        // does not infer is left out
        let mut hh: Vec<Option<Option<(Tm, Tm)>>> = vec![None; hints.len()];
        self.t_hints += th.elapsed();
        let tl = std::time::Instant::now();
        let memo = self.memo.get(class).cloned();
        let mut fast = None;
        for attempt in 0..2 {
            let (fact_sel, hint_sel, skip): (Option<&Vec<String>>, Option<&Vec<String>>, u32) = match (&memo, attempt) {
                (Some((fs, hs, round)), 0) => (Some(fs), Some(hs), *round),
                (None, 0) => continue,
                _ => (None, None, 0),
            };
            let mut st2 = st.child();
            if let Some(fs) = fact_sel {
                st2.facts.retain(|f| fs.iter().any(|n| st.ctx.entries.get(f.lvl as usize).is_some_and(|x| &*x.name == n.as_str())));
            }
            for i in 0..hints.len() {
                // (only library instances are filtered; the others — the
                // leaf's known facts, shift links — carry literals in their
                // keys and are always given)
                if let Some(hs) = hint_sel
                    && keys.get(i).is_some_and(|k| k.contains('@') && !hs.contains(k))
                {
                    continue;
                }
                if hh[i].is_none() {
                    hh[i] = Some(self.hint_hyp(env, ctx, &hints[i]));
                }
                let Some(Some((h, stated))) = &hh[i] else { continue };
                if let Ok(tv) = eval_in(env, ctx, stated) {
                    let d = st2.depth() - st.depth();
                    st2.push_fact(env, tv, crate::auto::util::shift(h, d as i64), crate::auto::state::Origin::Hint);
                }
            }
            // (the rounds before the one the class's last proof needed are
            // not searched: `Engine::lin_skip_rounds`)
            e.lin_skip_rounds = if skip == u32::MAX { u32::MAX } else { skip };
            let saved_trace = e.trace;
            if std::env::var("SANDBLASTER_LOOPSUM_TRACE_CLASS").is_ok_and(|c| class.starts_with(&c)) {
                e.trace = true;
                for f in &st2.facts {
                    eprintln!("[loopsum]   fact {}: {}", st2.ctx.entries[f.lvl as usize].name, show(env, &st2, &f.ty));
                }
            }
            let r0 = e.lin_prove(&st2, target, true);
            e.lin_skip_rounds = 0;
            e.trace = saved_trace;
            if let Ok(Some(p)) = r0 {
                let p = zeta_lets(&st2.finish(p));
                // remember what it used, and the round that found it
                let (fs, hs) = used_of(env, &st.ctx, &p, &hints, &keys);
                self.memo.insert(class.to_string(), (fs, hs, e.lin_round.unwrap_or(0)));
                if attempt == 0 {
                    self.stats.memo_hits += 1;
                } else if memo.is_some() {
                    self.stats.memo_misses += 1;
                }
                fast = Some(p);
                break;
            }
        }
        self.t_lin += tl.elapsed();
        if fast.is_none() {
            fast = match e.try_bvrefl(st, target, false) {
                Ok(Some(p)) => Some(p),
                _ => None,
            };
        }
        let used = before.saturating_sub(e.b.steps);
        if let Some(p) = fast {
            self.stats.fast += 1;
            self.stats.record(class, used, true);
            if self.trace {
                eprintln!("[loopsum] j={} {class}: fast ({used} steps)", self.j);
            }
            let p = e.promote(st, target, p);
            if std::env::var_os("SANDBLASTER_LOOPSUM_CHECK").is_some()
                && let Err(err) = env.infer(ctx, &p, &mut Budget { steps: 50_000_000 })
            {
                eprintln!("[loopsum] j={} {class}: the fast proof does not check: {err}", self.j);
                eprintln!("[loopsum]   term: {}", env.print_term(&ctx.entries.iter().map(|x| x.name.clone()).collect::<Vec<_>>(), &p).chars().take(3000).collect::<String>());
            }
            return Some(p);
        }
        // a threshold regime (plan O6: a `MaskedCount`'s split closed
        // form): tests of the goal and the facts decided or split, a
        // variable pinned to a literal where the facts force it
        if self.regime_depth < 3
            && (has_stuck_bool(target) || st.facts.iter().any(|f| has_stuck_bool(&f.ty)))
        {
            self.regime_depth += 1;
            let r = self.regime(e, st, target, class, 3);
            self.regime_depth -= 1;
            if let Ok(Some(p)) = r {
                return Some(p);
            }
        }
        // auto with the same hints
        let goal = Goal {
            id: ObligationId(0),
            kind: ObligationKind::LawGoal,
            span: Span::DUMMY,
            ctx: ctx.clone(),
            facts: vec![],
            target: target.clone(),
            hints: hints.into_iter().map(Hint::Lemma).collect(),
        };
        let mut b = Budget { steps: AUTO_STEPS };
        let r = self.auto.prove(env, &goal, &mut b);
        let steps = AUTO_STEPS - b.steps;
        self.stats.auto += 1;
        self.stats.record(class, used + steps, r.is_ok());
        if self.trace {
            eprintln!("[loopsum] j={} {class}: auto {} ({steps} steps)", self.j, if r.is_ok() { "ok" } else { "FAILED" });
        }
        if r.is_err() && self.stats.first_failure.is_none() {
            let names: Vec<sandblaster_kernel::term::Name> = ctx.entries.iter().map(|e| e.name.clone()).collect();
            self.stats.first_failure = Some(format!("lemma j={} {class}: {}", self.j, crate::elab::show::value(env, &names, target, 800)));
        }
        if r.is_err() && self.trust {
            // a simulated fault's claim: the kernel's linarith check judges it
            return Some(Rc::new(Term::Linarith { hyps: vec![], goal: env.quote_typed(ctx, target, None, false), cert: vec![] }));
        }
        r.ok()
    }

    /// The threshold-regime route of [`Self::obligation`]: facts whose
    /// stuck tests the other facts decide are restated with the decided
    /// values (transports, in a child state); the goal's first stuck test
    /// is decided and rewritten, or split (each arm recursing, `depth`); a
    /// machine-integer variable the facts pin to a literal is rewritten to
    /// it (a symbolic shift amount becomes literal); then the obligation's
    /// fast route in the child.
    fn regime(&mut self, e: &mut Engine<'_>, st: &St, target: &V, class: &str, depth: u32) -> R<Option<Tm>> {
        let env = e.env;
        let mut st2 = st.child();
        let bi = env.bool_ind();
        let bt = mk::bool_ty(bi);
        // facts restated with their decided tests
        let facts: Vec<crate::auto::state::Fact> = st.facts.clone();
        for f in facts {
            let mut ty = f.ty.clone();
            let mut pf = st2.var(f.lvl);
            if st2.ctx.entries.get(f.lvl as usize).is_some_and(|x| x.rel == Rel::Irr)
                && let Some((a, l, r)) = as_eq(&ty)
                && let Some(promote) = env.lookup_global("eq::promote")
            {
                let (at, lt, rt) = (st2.quote(env, a), st2.quote(env, l), st2.quote(env, r));
                pf = apps(mk::global(promote), [(Rel::Rel, at), (Rel::Rel, lt), (Rel::Rel, rt), (Rel::Irr, pf)]);
            }
            let mut changed = false;
            for _ in 0..3 {
                let Some(c) = stuck_bool_in(&ty) else { break };
                let Some((lit, _, eq)) = self.decided(e, &st2, &c) else { break };
                let c_tm = st2.quote(env, &c);
                let Ok(motive) = env.abstract_occurrences(&st2.ctx, &ty, &c, &mut Budget { steps: 20_000_000 }) else { break };
                let Ok(ty2) = env.eval(&venv_push(&st2.venv, EnvEntry::Rel(eval_in(env, &st2.ctx, &lit).ok().unwrap_or_else(|| c.clone()))), Lvl(st2.depth() + 1), &motive, &mut Budget { steps: 20_000_000 }) else { break };
                pf = Rc::new(Term::Transport { ty: bt.clone(), lhs: c_tm, rhs: lit, eq, motive, val: pf });
                ty = ty2;
                changed = true;
            }
            if changed {
                st2.push_fact(env, ty, pf, crate::auto::state::Origin::Derived("regime"));
            }
        }
        // the goal's first stuck test
        let Some((_, _, _)) = as_eq(target) else { return Ok(None) };
        if let Some(c) = stuck_bool_in(target) {
            if let Some((lit, eq, _)) = self.decided(e, &st2, &c) {
                let c_tm = st2.quote(env, &c);
                let Some((t2, w)) = rewrite(env, &st2, target, &c_tm, &lit, bt, eq) else { return Ok(None) };
                let p = self.regime(e, &st2, &t2, class, depth)?;
                return Ok(p.map(|p| st2.finish(w(p))));
            }
            if depth == 0 {
                return Ok(None);
            }
            let d = st2.depth_left;
            let mut arm_fn = |e2: &mut Engine<'_>, a2: &mut St, tk: V, _k: u32| -> R<Option<Tm>> {
                let mut ch = a2.child();
                if let Ok(Some(p)) = e2.contradiction(&mut ch) {
                    return Ok(Some(e2.absurd(a2, &tk, ch.finish(p))));
                }
                self.regime(e2, a2, &tk, class, depth - 1)
            };
            let p = e.case_split_with(&st2, &c, bi, &[], target, true, d, &mut arm_fn)?;
            return Ok(p.map(|p| st2.finish(p)));
        }
        // a variable pinned to a literal by the facts (in a non-literal
        // shift amount of the goal or of a fact): the facts restated and
        // the goal rewritten with the literal
        let mut cands = shift_amount_vars(target);
        for f in &st2.facts {
            for (y, w) in shift_amount_vars(&f.ty) {
                if !cands.iter().any(|(z, _)| same_var(z, &y)) {
                    cands.push((y, w));
                }
            }
        }
        for (x, w) in cands {
            let Some(n) = self.pinned(e, &st2, &x, w) else { continue };
            let lit = mk::lit(w, n);
            let g = Rc::new(Value::Eq { ty: Rc::new(Value::IntTy(w)), lhs: x.clone(), rhs: Rc::new(Value::Lit { w, n: sandblaster_kernel::term::BigInt::from(n) }) });
            let Ok(Some(p)) = e.lin_prove(&st2, &g, true) else { continue };
            let p = e.promote(&st2, &g, p);
            // facts: transported along `x = lit`
            let st3 = crate::opt::loopsum::enumerate::restate(env, &st2, &x, &lit, w, &p);
            let sh = (st3.depth() - st2.depth()) as i64;
            let (x3, p3) = (st3.quote(env, &x), crate::auto::util::shift(&p, sh));
            let sym = env.lookup_global("eq::sym").expect("eq::sym");
            let eq = apps(mk::global(sym), [(Rel::Rel, wty(w)), (Rel::Rel, x3.clone()), (Rel::Rel, lit.clone()), (Rel::Rel, p3)]);
            let (t2, wr): (V, Option<Wrap>) = match rewrite(env, &st3, target, &x3, &lit, wty(w), eq) {
                Some((t2, wr)) => (t2, Some(wr)),
                None if sh > 0 => (target.clone(), None),
                None => continue,
            };
            let saved = self.regime_depth;
            self.regime_depth = 3;
            let q = self.obligation(e, &st3, &t2, class, &[]);
            self.regime_depth = saved;
            if let Some(q) = q {
                let q = match wr {
                    Some(wr) => wr(q),
                    None => q,
                };
                return Ok(Some(st2.finish(st3.finish(q))));
            }
        }
        let saved = self.regime_depth;
        self.regime_depth = 3;
        let p = self.obligation(e, &st2, target, class, &[]);
        self.regime_depth = saved;
        Ok(p.map(|p| st2.finish(p)))
    }

    /// A stuck boolean test `c` decided by linear arithmetic over `st`'s
    /// facts: its literal, `Eq(Bool, lit, c)` and `Eq(Bool, c, lit)`.
    fn decided(&mut self, e: &mut Engine<'_>, st: &St, c: &V) -> Option<(Tm, Tm, Tm)> {
        let env = e.env;
        let bi = env.bool_ind();
        let bt = mk::bool_ty(bi);
        let c_tm = st.quote(env, c);
        for b in [true, false] {
            let lit = mk::bool_lit(bi, b);
            let g = eval_in(env, &st.ctx, &mk::eq(bt.clone(), c_tm.clone(), lit.clone())).ok()?;
            let p = match e.lin_prove(st, &g, true) {
                Ok(Some(p)) => Some(e.promote(st, &g, p)),
                _ => None,
            };
            if let Some(p) = p {
                let sym = env.lookup_global("eq::sym")?;
                let back = apps(mk::global(sym), [(Rel::Rel, bt.clone()), (Rel::Rel, c_tm.clone()), (Rel::Rel, lit.clone()), (Rel::Rel, p.clone())]);
                return Some((lit, back, p));
            }
        }
        None
    }

    /// The literal a variable is pinned to by `st`'s facts (its lower and
    /// upper bounds meet), if any.
    fn pinned(&mut self, e: &mut Engine<'_>, st: &St, x: &V, w: Width) -> Option<u128> {
        let env = e.env;
        let bi = env.bool_ind();
        let x_tm = st.quote(env, x);
        let bits = expr::bits(w).min(64);
        let max = if bits >= 64 { u64::MAX as u128 } else { (1u128 << bits) - 1 };
        let proves = |e: &mut Engine<'_>, op: PrimOp, a: Tm, b: Tm| -> bool {
            let g = mk::eq(mk::bool_ty(bi), Rc::new(Term::Prim { op, args: vec![a, b], proofs: vec![] }), mk::bool_lit(bi, true));
            match eval_in(env, &st.ctx, &g) {
                Ok(gv) => matches!(e.lin_prove(st, &gv, false), Ok(Some(_))),
                Err(_) => false,
            }
        };
        // the smallest upper bound, by bisection
        let (mut lo, mut hi) = (0u128, max);
        if !proves(e, PrimOp::Le(w), x_tm.clone(), mk::lit(w, 64u32)) {
            return None;
        }
        hi = hi.min(64);
        while lo < hi {
            let m = (lo + hi) / 2;
            if proves(e, PrimOp::Le(w), x_tm.clone(), mk::lit(w, m)) {
                hi = m;
            } else {
                lo = m + 1;
            }
        }
        let ub = lo;
        (ub == 0 || proves(e, PrimOp::Le(w), mk::lit(w, ub), x_tm.clone())).then_some(ub)
    }

    /// Applies `prev` (lemma_{j+1}) to the recursive call's arguments:
    /// relevant binders from the call (dynamic positions) and the ghosts,
    /// `.r` from the call's own proof arguments, `.h` from this lemma's,
    /// and the invariant at the next state as obligations.
    fn apply_prev(&mut self, e: &mut Engine<'_>, arm: &mut St, prev: GlobalId, call: &[Arg]) -> R<Option<Tm>> {
        let env = e.env;
        let spec = self.spec;
        // the call's relevant args at the dynamic positions, then the ghosts
        let rel_args: Vec<V> = call.iter().filter_map(|a| if let Arg::Rel(v) = a { Some(v.clone()) } else { None }).collect();
        let mut rel_vals: Vec<V> = spec.state.iter().map(|(_, _, i)| rel_args[*i as usize].clone()).collect();
        for (g, _) in &spec.ghosts {
            match parse_in(env, &arm.ctx, g).and_then(|t| eval_in(env, &arm.ctx, &t)) {
                Ok(v) => rel_vals.push(v),
                Err(_) => return Ok(None),
            }
        }
        self.apply_with(e, arm, prev, rel_vals)
    }

    /// Applies a lemma of the chain to the relevant values `rel_vals` (its
    /// state binders, then its ghost binders), proving its irrelevant
    /// binders: `.r`/`.gf` by conversion or an assumption, the payload
    /// invariant by [`Self::found`], the others as obligations.
    pub fn apply_with(&mut self, e: &mut Engine<'_>, arm: &mut St, prev: GlobalId, rel_vals: Vec<V>) -> R<Option<Tm>> {
        let env = e.env;
        let spec = self.spec;
        let Some(mut cur) = env.global_type_value(prev) else { return Ok(None) };
        let mut ri = 0;
        let mut args: Vec<(Rel, Tm)> = Vec::new();
        while let Value::Pi { name, rel, dom, cod } = &*cur.clone() {
            let entry = match rel {
                Rel::Rel => {
                    let v = rel_vals[ri].clone();
                    ri += 1;
                    args.push((Rel::Rel, arm.quote(env, &v)));
                    EnvEntry::Rel(v)
                }
                Rel::Irr => {
                    let nm = name.to_string();
                    let p = if nm.starts_with('r') || nm.starts_with("gf") {
                        let mut b = Budget { steps: 5_000_000 };
                        trivial(env, &arm.ctx, dom, &mut b)
                    } else if spec.payload_binder.as_deref().is_some_and(|pb| nm == format!("i_{pb}")) {
                        self.found(e, arm, dom)?
                    } else {
                        self.obligation(e, arm, dom, &format!("step.{nm}"), &[])
                    };
                    let p = match p {
                        Some(p) => p,
                        None => {
                            // a requires proof that did not quote: prove it
                            match self.obligation(e, arm, dom, &format!("step.{nm}"), &[]) {
                                Some(p) => p,
                                None => return Ok(None),
                            }
                        }
                    };
                    args.push((Rel::Irr, p.clone()));
                    irr_entry(&arm.venv, &p)
                }
            };
            let Some(next) = e.inst(cod, vec![entry], arm.depth())? else { return Ok(None) };
            cur = next;
        }
        Ok(Some(apps(mk::global(prev), args)))
    }

    /// The payload parameter's obligation at the next state: split on the
    /// outermost stuck test of the new value until it is the payload
    /// constructor (the hit) or the old value (a miss).
    fn found(&mut self, e: &mut Engine<'_>, arm: &mut St, target: &V) -> R<Option<Tm>> {
        let env = e.env;
        if self.trace {
            eprintln!("[loopsum] found: {}", show(env, arm, target));
        }
        let Some((_, lhs, _)) = as_eq(target) else { return Ok(None) };
        if let Value::Ctor { ctor, .. } = &**lhs {
            // the unset value (the static entry's constructor) is a miss
            if Some(*ctor) == self.spec.unset_ctor {
                return self.miss(e, arm, target);
            }
            return self.hit(e, arm, target);
        }
        // the innermost test first (a `&&`'s left operand: its arms reduce
        // the outer select)
        let Some(c) = first_scrut(lhs) else {
            return self.miss(e, arm, target);
        };
        let bi = env.bool_ind();
        let depth = arm.depth_left;
        let mut arm_fn = |e2: &mut Engine<'_>, arm2: &mut St, tk: V, _k: u32| -> R<Option<Tm>> { self.found(e2, arm2, &tk) };
        e.case_split_with(arm, &c, bi, &[], target, true, depth, &mut arm_fn)
    }

    /// A miss leaf: the payload is unchanged; its invariant carries over
    /// (the old value rewritten by its invariant, then the two selects
    /// aligned).
    fn miss(&mut self, e: &mut Engine<'_>, arm: &mut St, target: &V) -> R<Option<Tm>> {
        if let Some(p) = trivial(e.env, &arm.ctx, target, &mut Budget { steps: 20_000_000 }) {
            return Ok(Some(p));
        }
        let Some(pb) = self.spec.payload_binder.clone() else { return Ok(self.obligation(e, arm, target, "found.miss", &[])) };
        match self.rewrite_by_inv(e, arm, target, &pb) {
            Some((t, w)) => match self.align(e, arm, &t, 3)? {
                Some(p) => Ok(Some(w(p))),
                None => Ok(self.obligation(e, arm, target, "found.miss", &[])),
            },
            None => Ok(self.obligation(e, arm, target, "found.miss", &[])),
        }
    }

    /// Rewrites the state binder `name` in `target` by its invariant
    /// hypothesis `.i_<name> : Eq(T, name, M)`.
    fn rewrite_by_inv(&mut self, e: &mut Engine<'_>, arm: &St, target: &V, name: &str) -> Option<(V, Wrap)> {
        let env = e.env;
        let d = arm.ctx.depth().0;
        let hname = format!("i_{name}");
        let (hi, h) = arm.ctx.entries.iter().enumerate().rev().find(|(_, x)| &*x.name == hname.as_str())?;
        let (ty, l, r) = as_eq(&h.ty)?;
        let (ty_tm, l_tm, r_tm) = (arm.quote(env, ty), arm.quote(env, l), arm.quote(env, r));
        let var = mk::var(d - 1 - hi as u32);
        let promote = env.lookup_global("eq::promote")?;
        let p = apps(mk::global(promote), [(Rel::Rel, ty_tm.clone()), (Rel::Rel, l_tm.clone()), (Rel::Rel, r_tm.clone()), (Rel::Irr, var)]);
        let sym = env.lookup_global("eq::sym")?;
        let eq = apps(mk::global(sym), [(Rel::Rel, ty_tm.clone()), (Rel::Rel, l_tm.clone()), (Rel::Rel, r_tm.clone()), (Rel::Rel, p)]);
        rewrite(env, arm, target, &l_tm, &r_tm, ty_tm, eq)
    }

    /// Aligns two sides built of boolean selects: decides a side's test by
    /// linear arithmetic where the facts allow (rewriting it), else splits
    /// on the left side's test; closes by conversion.
    pub fn align(&mut self, e: &mut Engine<'_>, arm: &mut St, target: &V, depth: u32) -> R<Option<Tm>> {
        let env = e.env;
        if self.trace {
            eprintln!("[loopsum] align (depth {depth}): {}", show(env, arm, target));
        }
        if let Some(p) = trivial(env, &arm.ctx, target, &mut Budget { steps: 20_000_000 }) {
            return Ok(Some(p));
        }
        let Some((_, l, r)) = as_eq(target) else { return Ok(None) };
        let (l, r) = (l.clone(), r.clone());
        for side in [&r, &l] {
            if let Some(c) = first_scrut(side)
                && let Some((t2, w)) = self.decide_rewrite(e, arm, target, &c, "align.decide")
            {
                return Ok(self.align(e, arm, &t2, depth)?.map(w));
            }
        }
        if depth > 0
            && let Some(c) = first_scrut(&l)
        {
            let bi = env.bool_ind();
            let d = arm.depth_left;
            let mut arm_fn = |e2: &mut Engine<'_>, a2: &mut St, tk: V, _k: u32| -> R<Option<Tm>> { self.align(e2, a2, &tk, depth - 1) };
            return e.case_split_with(arm, &c, bi, &[], target, true, d, &mut arm_fn);
        }
        Ok(self.fields(e, arm, target))
    }

    /// Decides the stuck boolean scrutinee `c` (a value in `arm`) by
    /// linear arithmetic and rewrites it in `target` to its literal.
    fn decide_rewrite(&mut self, e: &mut Engine<'_>, arm: &St, target: &V, c: &V, class: &str) -> Option<(V, Wrap)> {
        let env = e.env;
        let bt = mk::bool_ty(env.bool_ind());
        let c_tm = arm.quote(env, c);
        for b in [true, false] {
            let lit = mk::bool_lit(env.bool_ind(), b);
            let g = eval_in(env, &arm.ctx, &mk::eq(bt.clone(), c_tm.clone(), lit.clone())).ok()?;
            let before = e.b.steps;
            let hyps = e.lin_hyps(arm);
            let p = match e.lin_with(arm, &hyps, &g) {
                Ok(Some(p)) => Some(p),
                _ => e.lin_cut(arm, &g, &hyps, 2).ok().flatten(),
            };
            let used = before.saturating_sub(e.b.steps);
            if let Some(p) = p {
                self.stats.record(class, used, true);
                let p = e.promote(arm, &g, p);
                let sym = env.lookup_global("eq::sym")?;
                let eq = apps(mk::global(sym), [(Rel::Rel, bt.clone()), (Rel::Rel, c_tm.clone()), (Rel::Rel, lit.clone()), (Rel::Rel, p)]);
                return rewrite(env, arm, target, &c_tm, &lit, bt, eq);
            }
        }
        None
    }

    /// The hit leaf: the new payload is the constructor over the state; the
    /// invariant's side (`match pr(next) … | true => payload ḡ`) is decided,
    /// the witness pinned to `j` and rewritten, then field by field.
    fn hit(&mut self, e: &mut Engine<'_>, arm: &mut St, target: &V) -> R<Option<Tm>> {
        let env = e.env;
        if self.trace {
            eprintln!("[loopsum] hit: {}", show(env, arm, target));
        }
        let mut t = target.clone();
        let mut wraps: Vec<Wrap> = Vec::new();
        // decide the invariant side's tests
        for _ in 0..4 {
            let Some((_, _, rhs)) = as_eq(&t) else { return Ok(None) };
            let Some(c) = first_scrut(rhs) else { break };
            let Some((t2, w)) = self.decide_rewrite(e, arm, &t, &c, "hit.guard") else { return Ok(None) };
            t = t2;
            wraps.push(w);
        }
        // pin the witness to this iteration
        let Some((t3, w3, facts)) = self.pin(e, arm, &t, self.j)? else { return Ok(None) };
        wraps.push(w3);
        t = t3;
        // the facts proven while pinning, for the fields
        let mut st2 = arm.child();
        for f in &facts {
            if let Ok(ty) = env.infer(&st2.ctx, f, &mut Budget { steps: 5_000_000 }) {
                let d = st2.depth() - arm.depth();
                st2.push_fact(env, ty, crate::auto::util::shift(f, d as i64), crate::auto::state::Origin::Derived("pin"));
            }
        }
        let arm = &mut st2;
        let Some((_, _, rhs)) = as_eq(&t) else { return Ok(None) };
        if first_scrut(rhs).is_some() {
            // a test left in the payload (e.g. a select): decide it
            for _ in 0..4 {
                let Some((_, _, rhs)) = as_eq(&t) else { return Ok(None) };
                let Some(c) = first_scrut(rhs) else { break };
                let Some((t2, w)) = self.decide_rewrite(e, arm, &t, &c, "hit.select") else { return Ok(None) };
                t = t2;
                wraps.push(w);
            }
        }
        let Some(p) = self.fields(e, arm, &t) else { return Ok(None) };
        let mut p = zeta_lets(&arm.finish(p));
        while let Some(w) = wraps.pop() {
            p = w(p);
        }
        Ok(Some(p))
    }

    /// Pins the witness `E(ḡ)` to the literal `j` in `target`: solves `E = j`
    /// for its bit-count atom (`lz(x ⊕ y)`, `lz(x)`, `tz(x)`, possibly under
    /// `c − ·`, `· − c`, `· + c`, casts), proves the atom's value from the
    /// context with the matching library lemma, and rewrites the atom.
    fn pin(&mut self, e: &mut Engine<'_>, arm: &St, target: &V, j: u32) -> R<Option<(V, Wrap, Vec<Tm>)>> {
        self.pin_facts.clear();
        let r = self.pin_inner(e, arm, target, j);
        let facts = std::mem::take(&mut self.pin_facts);
        Ok(r.map(|(v, w)| (v, w, facts)))
    }

    fn pin_inner(&mut self, e: &mut Engine<'_>, arm: &St, target: &V, j: u32) -> Option<(V, Wrap)> {
        let env = e.env;
        let spec = self.spec;
        let Some((atom, val)) = solve_atom(&spec.witness, j as i128) else { return None };
        let CE::Op(op, a) = &*atom else { return None };
        let w = match op {
            PrimOp::LeadingZeros(w) | PrimOp::TrailingZeros(w) => *w,
            _ => return None,
        };
        let bits = expr::bits(w) as i128;
        if val < 0 || val > bits {
            return None;
        }
        let gn = &spec.ghost_names;
        let arg_text = a[0].text(gn, None);
        let atom_text = atom.text(gn, None);
        let atom_tm = parse_in(env, &arm.ctx, &atom_text).ok();
        let arg_tm = parse_in(env, &arm.ctx, &arg_text).ok();
        let (Some(atom_tm), Some(arg_tm)) = (atom_tm, arg_tm) else { return None };
        let ev = |s: &str| parse_in(env, &arm.ctx, s).and_then(|t| eval_in(env, &arm.ctx, &t)).ok();
        let ws = sandblaster_kernel::prim::width_suffix(w);
        let sym = env.lookup_global("eq::sym").unwrap();
        if val == bits {
            // the argument is 0: prove it and rewrite it
            let g = ev(&format!("Eq({}, {arg_text}, 0{ws})", expr::ty_text(expr::Ty::W(w))))?;
            let Some(p) = self.obligation(e, arm, &g, "pin.zero", &[]) else { return None };
            let z = mk::lit(w, 0u32);
            let eq = apps(mk::global(sym), [(Rel::Rel, wty(w)), (Rel::Rel, arg_tm.clone()), (Rel::Rel, z.clone()), (Rel::Rel, p)]);
            return rewrite(env, arm, target, &arg_tm, &z, wty(w), eq);
        }
        let val = val as u32;
        let proof: Option<Tm> = match (op, &*a[0]) {
            (PrimOp::LeadingZeros(_), CE::Op(PrimOp::Xor(_), xy)) => {
                // clz_xor_prefix_k: lz(x ^ y) = w − 1 − k from x >> (k+1) = y >> (k+1), bit k of x = 1, of y = 0
                let k = expr::bits(w) - 1 - val;
                let (x, y) = (xy[0].text(gn, None), xy[1].text(gn, None));
                let lem = env.lookup_global(&bitlib::lemma_name(Family::ClzXorPrefix, w, k));
                match lem {
                    None => None,
                    Some(lem) => {
                        let mut cargs = vec![(Rel::Rel, parse_in(env, &arm.ctx, &x).ok()?), (Rel::Rel, parse_in(env, &arm.ctx, &y).ok()?)];
                        let mut ok = true;
                        let mut known: Vec<Tm> = Vec::new();
                        if k + 1 < expr::bits(w) {
                            let g = ev(&format!("Eq({t}, #wshr_{ws}({x}, {}u32), #wshr_{ws}({y}, {}u32))", k + 1, k + 1, t = expr::ty_text(expr::Ty::W(w))))?;
                            match self.obligation(e, arm, &g, "pin.prefix", &[]) {
                                Some(p) => {
                                    cargs.push((Rel::Irr, p.clone()));
                                    known.push(p.clone());
                                    self.pin_facts.push(p);
                                }
                                None => ok = false,
                            }
                        }
                        let g2 = ev(&format!("Eq({t}, #and_{ws}(#wshr_{ws}({x}, {k}u32), 1{ws}), 1{ws})", t = expr::ty_text(expr::Ty::W(w))))?;
                        let g3 = ev(&format!("Eq({t}, #and_{ws}(#wshr_{ws}({y}, {k}u32), 1{ws}), 0{ws})", t = expr::ty_text(expr::Ty::W(w))))?;
                        if ok {
                            match (self.obligation(e, arm, &g2, "pin.bit1", &known), self.obligation(e, arm, &g3, "pin.bit0", &known)) {
                                (Some(p2), Some(p3)) => {
                                    self.pin_facts.push(p2.clone());
                                    self.pin_facts.push(p3.clone());
                                    cargs.push((Rel::Irr, p2));
                                    cargs.push((Rel::Irr, p3));
                                    Some(apps(mk::global(lem), cargs))
                                }
                                _ => None,
                            }
                        } else {
                            None
                        }
                    }
                }
            }
            (PrimOp::LeadingZeros(_), _) => {
                // lz_range_k: 2^k ≤ x (< 2^(k+1)) ⇒ lz(x) = w − 1 − k
                let k = expr::bits(w) - 1 - val;
                let lem = env.lookup_global(&bitlib::lemma_name(Family::LzRange, w, k));
                match lem {
                    None => None,
                    Some(lem) => {
                        let lo = ev(&format!("Eq(Bool, #le_{ws}({}, {arg_text}), true)", expr::lit_text(w, 1u128 << k)))?;
                        let mut cargs = vec![(Rel::Rel, arg_tm.clone())];
                        let mut ok = match self.obligation(e, arm, &lo, "pin.lo", &[]) {
                            Some(p) => {
                                self.pin_facts.push(p.clone());
                                cargs.push((Rel::Irr, p));
                                true
                            }
                            None => false,
                        };
                        if ok && k + 1 < expr::bits(w) {
                            let hi = ev(&format!("Eq(Bool, #lt_{ws}({arg_text}, {}), true)", expr::lit_text(w, 1u128 << (k + 1))))?;
                            match self.obligation(e, arm, &hi, "pin.hi", &[]) {
                                Some(p) => {
                                    self.pin_facts.push(p.clone());
                                    cargs.push((Rel::Irr, p))
                                }
                                None => ok = false,
                            }
                        }
                        ok.then(|| apps(mk::global(lem), cargs))
                    }
                }
            }
            (PrimOp::TrailingZeros(_), _) => {
                // tz_range_k: x & (2^(k+1) − 1) = 2^k ⇒ tz(x) = k
                let k = val;
                let lem = env.lookup_global(&bitlib::lemma_name(Family::TzRange, w, k));
                match lem {
                    None => None,
                    Some(lem) => {
                        let m = if k + 1 >= expr::bits(w) { expr::mask(w) } else { (1u128 << (k + 1)) - 1 };
                        let g = ev(&format!("Eq({t}, #and_{ws}({arg_text}, {}), {})", expr::lit_text(w, m), expr::lit_text(w, 1u128 << k), t = expr::ty_text(expr::Ty::W(w))))?;
                        self.obligation(e, arm, &g, "pin.tz", &[]).map(|p| apps(mk::global(lem), [(Rel::Rel, arg_tm.clone()), (Rel::Irr, p)]))
                    }
                }
            }
            _ => None,
        };
        let Some(p) = proof else {
            if self.trace {
                eprintln!("[loopsum] pin: no proof of the atom's value");
            }
            return None;
        };
        let mut kb = Budget { steps: 20_000_000 };
        if let Err(err) = env.infer(&arm.ctx, &p, &mut kb) {
            if self.trace {
                eprintln!("[loopsum] pin: the atom lemma instance does not check: {err}");
            }
            return None;
        }
        // p : Eq(U32, atom, val); rewrite atom := val
        let lit = mk::lit(Width::U32, val);
        let eq = apps(mk::global(sym), [(Rel::Rel, mk::int_ty(Width::U32)), (Rel::Rel, atom_tm.clone()), (Rel::Rel, lit.clone()), (Rel::Rel, p)]);
        let r = rewrite(env, arm, target, &atom_tm, &lit, mk::int_ty(Width::U32), eq);
        if self.trace {
            match &r {
                Some((t, _)) => eprintln!("[loopsum] pin: rewritten to {}", show(env, arm, t)),
                None => eprintln!("[loopsum] pin: the rewrite failed"),
            }
        }
        r
    }

    /// Constructor congruence for `Eq(T, C(x̄), C(ȳ))` (nested through
    /// single-constructor wrappers such as `Some`): each differing field
    /// `xᵢ = yᵢ` is an obligation `field.<i>`, assembled by transports.
    fn fields(&mut self, e: &mut Engine<'_>, arm: &St, target: &V) -> Option<Tm> {
        let env = e.env;
        let (ty, l, r) = as_eq(target)?;
        let ty_tm = arm.quote(env, ty);
        if let Some(p) = trivial(env, &arm.ctx, target, &mut Budget { steps: 20_000_000 }) {
            return Some(p);
        }
        let (Value::Ctor { ind, ctor, params, args: la }, Value::Ctor { ind: i2, ctor: c2, args: ra, .. }) = (&**l, &**r) else {
            return self.obligation(e, arm, target, "field.value", &[]);
        };
        if ind != i2 || ctor != c2 {
            return None;
        }
        let decl = env.inductive_decl(*ind)?;
        let p_tms: Vec<Tm> = params.iter().map(|p| arm.quote(env, p)).collect();
        let xv: Vec<V> = la.iter().filter_map(|a| if let Arg::Rel(v) = a { Some(v.clone()) } else { None }).collect();
        let yv: Vec<V> = ra.iter().filter_map(|a| if let Arg::Rel(v) = a { Some(v.clone()) } else { None }).collect();
        if xv.len() != la.len() || yv.len() != ra.len() || xv.len() != yv.len() {
            return None;
        }
        // field types
        let mut fenv: Vec<EnvEntry> = params.iter().map(|p| EnvEntry::Rel(p.clone())).collect();
        let mut ftys = Vec::new();
        for (i, (_, _, fty)) in decl.ctors[*ctor as usize].fields.iter().enumerate() {
            let ftv = env.eval(&sandblaster_kernel::value::VEnv(Rc::new(fenv.clone())), arm.ctx.depth(), fty, &mut Budget { steps: 1_000_000 }).ok()?;
            ftys.push(ftv);
            fenv.push(EnvEntry::Rel(xv[i].clone()));
        }
        let xt: Vec<Tm> = xv.iter().zip(&ftys).map(|(v, t)| arm.quote_at(env, v, t)).collect();
        let yt: Vec<Tm> = yv.iter().zip(&ftys).map(|(v, t)| arm.quote_at(env, v, t)).collect();
        let lhs_tm = mk::ctor(*ind, *ctor, p_tms.clone(), xt.clone());
        let mut proof = mk::refl(ty_tm.clone(), lhs_tm.clone());
        for i in 0..xt.len() {
            let ftv = &ftys[i];
            let goal = Rc::new(Value::Eq { ty: ftv.clone(), lhs: xv[i].clone(), rhs: yv[i].clone() });
            let pi = if let (Some((op, a)), Some((op2, b2))) = (unary_bitcount(&xv[i]), unary_bitcount(&yv[i]))
                && op == op2
            {
                // `cnt(a) = cnt(b)` through `a = b`
                let w = match op {
                    PrimOp::CountOnes(w) | PrimOp::LeadingZeros(w) | PrimOp::TrailingZeros(w) => w,
                    _ => unreachable!(),
                };
                let wt = Rc::new(Value::IntTy(w));
                let g = Rc::new(Value::Eq { ty: wt.clone(), lhs: a.clone(), rhs: b2.clone() });
                match trivial(env, &arm.ctx, &goal, &mut Budget { steps: 20_000_000 }) {
                    Some(p) => p,
                    None => {
                        let p = match self.obligation(e, arm, &g, &format!("field.{i}"), &[]) {
                            Some(p) => p,
                            None => self.obligation(e, arm, &goal, &format!("field.{i}"), &[])?,
                        };
                        if env.infer(&arm.ctx, &p, &mut Budget { steps: 10_000_000 }).ok().and_then(|t| as_eq(&t).map(|(_, x, _)| env.conv(arm.ctx.depth(), x, &a, &mut Budget { steps: 1_000_000 }).unwrap_or(false))).unwrap_or(false) {
                            let cong = env.lookup_global("eq::cong")?;
                            let f = mk::lam("y", Rel::Rel, mk::int_ty(w), mk::prim(op, vec![mk::var(0)], vec![]));
                            let (at, bt) = (arm.quote_at(env, &a, &wt), arm.quote_at(env, &b2, &wt));
                            apps(mk::global(cong), [(Rel::Rel, mk::int_ty(w)), (Rel::Rel, arm.quote(env, ftv)), (Rel::Rel, f), (Rel::Rel, at), (Rel::Rel, bt), (Rel::Rel, p)])
                        } else {
                            p
                        }
                    }
                }
            } else if matches!(&*xv[i], Value::Ctor { .. }) && matches!(&*yv[i], Value::Ctor { .. }) {
                self.fields(e, arm, &goal)?
            } else {
                self.obligation(e, arm, &goal, &format!("field.{i}"), &[])?
            };
            let sh = |t: &Tm| crate::auto::util::shift(t, 1);
            let mut mid: Vec<Tm> = (0..xt.len()).map(|jx| if jx < i { sh(&yt[jx]) } else { sh(&xt[jx]) }).collect();
            mid[i] = mk::var(0);
            let motive = mk::eq(sh(&ty_tm), sh(&lhs_tm), mk::ctor(*ind, *ctor, p_tms.iter().map(sh).collect(), mid));
            let fty_tm = arm.quote(env, ftv);
            proof = Rc::new(Term::Transport { ty: fty_tm, lhs: xt[i].clone(), rhs: yt[i].clone(), eq: pi, motive, val: proof });
        }
        Some(proof)
    }

    /// A search exit at iteration `j`: pin the witness, then the exit value
    /// against the result.
    fn exit(&mut self, e: &mut Engine<'_>, arm: &mut St, target: &V) -> R<Option<Tm>> {
        if let Some(p) = trivial(e.env, &arm.ctx, target, &mut Budget { steps: 20_000_000 }) {
            return Ok(Some(p));
        }
        // a FirstMatch loop exits only at the exhaustion, with the payload
        if self.spec.payload_binder.is_some() {
            return self.miss(e, arm, target);
        }
        // the exit of this iteration — or of the next, when the kernel's
        // evaluation unfolded the recursive call at the exhaustion (its body
        // is not stuck there)
        let pinned = match self.pin(e, arm, target, self.j)? {
            Some(x) => Some(x),
            None if self.j < self.spec.k => self.pin(e, arm, target, self.j + 1)?,
            None => None,
        };
        let Some((t, w, facts)) = pinned else {
            if let Some((lw, x)) = div_lz_atom(&self.spec.witness) {
                // `lz(y | 1)`: split on `y` (the `| 1` only matters below 2)
                let y = match &*x {
                    CE::Op(PrimOp::Or(_), a) if matches!(&*a[1], CE::Lit(_, 1)) => a[0].clone(),
                    _ => x.clone(),
                };
                let (xt, yt) = (x.text(&self.spec.ghost_names, None), y.text(&self.spec.ghost_names, None));
                if let (Ok(x_tm), Ok(y_tm)) = (parse_in(e.env, &arm.ctx, &xt), parse_in(e.env, &arm.ctx, &yt))
                    && let Some((lo, hi)) = self.magnitude_window(e, arm, lw, &y_tm)
                {
                    self.range_arg = Some((x_tm, (xt, yt)));
                    let r = self.exit_by_range(e, arm, target, lw, &y_tm, lo, hi);
                    self.range_arg = None;
                    if let Some(p) = r? {
                        return Ok(Some(p));
                    }
                }
            }
            // the result's own tests (a reduction's threshold) decided by
            // the path's facts, then the value
            let mut t = target.clone();
            let mut wraps: Vec<Wrap> = Vec::new();
            for _ in 0..4 {
                let Some((_, _, rhs)) = as_eq(&t) else { break };
                let Some(c) = first_scrut(rhs) else { break };
                let Some((t2, w2)) = self.decide_rewrite(e, arm, &t, &c, "exit.select") else { break };
                t = t2;
                wraps.push(w2);
            }
            let Some(mut p) = self.obligation(e, arm, &t, "exit.value", &[]) else { return Ok(None) };
            while let Some(w) = wraps.pop() {
                p = w(p);
            }
            return Ok(Some(p));
        };
        let mut st2 = arm.child();
        for f in &facts {
            if let Ok(ty) = e.env.infer(&st2.ctx, f, &mut Budget { steps: 5_000_000 }) {
                let d = st2.depth() - arm.depth();
                st2.push_fact(e.env, ty, crate::auto::util::shift(f, d as i64), crate::auto::state::Origin::Derived("pin"));
            }
        }
        let arm = &mut st2;
        let mut t = t;
        let mut wraps: Vec<Wrap> = vec![w];
        for _ in 0..4 {
            let Some((_, _, rhs)) = as_eq(&t) else { break };
            let Some(c) = first_scrut(rhs) else { break };
            let Some((t2, w2)) = self.decide_rewrite(e, arm, &t, &c, "exit.select") else { break };
            t = t2;
            wraps.push(w2);
        }
        let Some(p) = self.fields(e, arm, &t) else { return Ok(None) };
        let mut p = zeta_lets(&arm.finish(p));
        while let Some(w) = wraps.pop() {
            p = w(p);
        }
        Ok(Some(p))
    }

    /// A search exit whose witness divides a bit count (`(c − lz(x)) / k`):
    /// split on the magnitude of `x` (`x < 2^(k+1)` for `k = 0, 1, …`); an arm
    /// the facts contradict closes by `absurd`, a feasible one pins `lz(x)`
    /// with `lz_range_k` and closes on the literal result.
    fn exit_by_range(&mut self, e: &mut Engine<'_>, arm: &mut St, target: &V, w: Width, x: &Tm, k: u32, hi: u32) -> R<Option<Tm>> {
        let env = e.env;
        let d0 = arm.depth();
        if self.trace {
            eprintln!("[loopsum] magnitude split at k={k} (window up to {hi}), budget {}", e.b.steps);
        }
        if k >= hi {
            return Ok(self.pin_range(e, arm, target, w, x, k));
        }
        let bi = env.bool_ind();
        let test = Rc::new(Term::Prim { op: PrimOp::Lt(w), args: vec![x.clone(), mk::lit(w, 1u128 << (k + 1))], proofs: vec![] });
        let Ok(tv) = eval_in(env, &arm.ctx, &test) else { return Ok(None) };
        let d = arm.depth_left;
        let x0 = x.clone();
        let mut arm_fn = |e2: &mut Engine<'_>, a2: &mut St, tk: V, c: u32| -> R<Option<Tm>> {
            let x2 = crate::auto::util::shift(&x0, (a2.depth() - d0) as i64);
            // an infeasible window
            let mut ch = a2.child();
            if let Ok(Some(p)) = e2.contradiction(&mut ch) {
                return Ok(Some(e2.absurd(a2, &tk, ch.finish(p))));
            }
            if c == 0 {
                return self.exit_by_range(e2, a2, &tk, w, &x2, k + 1, hi);
            }
            Ok(self.pin_range(e2, a2, &tk, w, &x2, k))
        };
        e.case_split_with(arm, &tv, bi, &[], target, true, d, &mut arm_fn)
    }

    /// The magnitude window of `x` the facts allow: the largest `lo` with
    /// `2^lo ≤ x` and the smallest `hi` with `x < 2^(hi+1)` that linear
    /// arithmetic proves (binary searches: both are monotone).
    fn magnitude_window(&mut self, e: &mut Engine<'_>, arm: &St, w: Width, x: &Tm) -> Option<(u32, u32)> {
        let env = e.env;
        let bits = expr::bits(w);
        let bi = env.bool_ind();
        let proves = |e: &mut Engine<'_>, op: PrimOp, a: Tm, b: Tm| -> bool {
            let g = mk::eq(mk::bool_ty(bi), Rc::new(Term::Prim { op, args: vec![a, b], proofs: vec![] }), mk::bool_lit(bi, true));
            match eval_in(env, &arm.ctx, &g) {
                // (with enrichment: `x ≤ x | c`, the shifts' quotients)
                Ok(gv) => matches!(e.lin_prove(arm, &gv, true), Ok(Some(_))),
                Err(_) => false,
            }
        };
        // lo: 2^lo ≤ x (0 when nothing better: x ≥ 1 is needed by the pin)
        let (mut a, mut b) = (0u32, bits - 1);
        while a < b {
            let m = (a + b).div_ceil(2);
            if proves(e, PrimOp::Le(w), mk::lit(w, 1u128 << m), x.clone()) {
                a = m;
            } else {
                b = m - 1;
            }
        }
        let lo = a;
        // hi: x < 2^(hi+1) (bits − 1 when nothing better)
        let (mut a, mut b) = (lo, bits - 1);
        while a < b {
            let m = (a + b) / 2;
            if proves(e, PrimOp::Lt(w), x.clone(), mk::lit(w, 1u128 << (m + 1))) {
                b = m;
            } else {
                a = m + 1;
            }
        }
        Some((lo, a))
    }

    /// `2^k ≤ x (< 2^(k+1))`: `lz(x) = w − 1 − k` by `lz_range_k`, rewritten
    /// in the target, which then closes on literals.
    fn pin_range(&mut self, e: &mut Engine<'_>, arm: &mut St, target: &V, w: Width, y: &Tm, k: u32) -> Option<Tm> {
        let env = e.env;
        let bits = expr::bits(w);
        let lem = env.lookup_global(&bitlib::lemma_name(Family::LzRange, w, k))?;
        let bi = env.bool_ind();
        // the lz argument (`y | 1` for a split on `y`) and its link to `y`'s
        // magnitude: `(y | 1) >> m = y >> m` (m ≥ 1, by BvRefl)
        let (x, links) = match &self.range_arg {
            Some((x_tm, (xt, yt))) if xt != yt => {
                let ws = sandblaster_kernel::prim::width_suffix(w);
                let t = expr::ty_text(expr::Ty::W(w));
                let mut hs = Vec::new();
                for m in [k, k + 1] {
                    if m >= 1 && m < bits
                        && let Ok(h) = parse_in(env, &arm.ctx, &format!("bvrefl({t}, #wshr_{ws}({xt}, {m}u32), #wshr_{ws}({yt}, {m}u32))"))
                    {
                        hs.push(h);
                    }
                }
                let x_now = parse_in(env, &arm.ctx, xt).unwrap_or_else(|_| x_tm.clone());
                (x_now, hs)
            }
            _ => (y.clone(), Vec::new()),
        };
        let lo = eval_in(env, &arm.ctx, &mk::eq(mk::bool_ty(bi), Rc::new(Term::Prim { op: PrimOp::Le(w), args: vec![mk::lit(w, 1u128 << k), x.clone()], proofs: vec![] }), mk::bool_lit(bi, true))).ok()?;
        let p_lo = self.obligation(e, arm, &lo, "range.lo", &links)?;
        let mut args = vec![(Rel::Rel, x.clone()), (Rel::Irr, p_lo)];
        if k + 1 < bits {
            let hi = eval_in(env, &arm.ctx, &mk::eq(mk::bool_ty(bi), Rc::new(Term::Prim { op: PrimOp::Lt(w), args: vec![x.clone(), mk::lit(w, 1u128 << (k + 1))], proofs: vec![] }), mk::bool_lit(bi, true))).ok()?;
            args.push((Rel::Irr, self.obligation(e, arm, &hi, "range.hi", &links)?));
        }
        let p = apps(mk::global(lem), args);
        let atom = Rc::new(Term::Prim { op: PrimOp::LeadingZeros(w), args: vec![x.clone()], proofs: vec![] });
        let _ = y;
        let lit = mk::lit(Width::U32, bits - 1 - k);
        let sym = env.lookup_global("eq::sym")?;
        let eq = apps(mk::global(sym), [(Rel::Rel, mk::int_ty(Width::U32)), (Rel::Rel, atom.clone()), (Rel::Rel, lit.clone()), (Rel::Rel, p)]);
        let rw = rewrite(env, arm, target, &atom, &lit, mk::int_ty(Width::U32), eq);
        if self.trace {
            match &rw {
                Some((t2, _)) => eprintln!("[loopsum] range pin k={k}: {}", show(env, arm, t2)),
                None => eprintln!("[loopsum] range pin k={k}: the rewrite failed"),
            }
        }
        let (t2, wrap) = rw?;
        let p = match trivial(env, &arm.ctx, &t2, &mut Budget { steps: 20_000_000 }) {
            Some(p) => p,
            None => self.fields(e, arm, &t2)?,
        };
        Some(wrap(p))
    }

    /// Splits the goal's left side on its stuck boolean tests until it is
    /// the recursive call or an exit value, then `leaf`.
    fn split_lhs(&mut self, e: &mut Engine<'_>, st: &mut St, goal: &V, prev: Option<GlobalId>, depth_guard: u32) -> R<Option<Tm>> {
        let env = e.env;
        let Some((_, lhs, _)) = as_eq(goal) else { return Ok(None) };
        if let Some(call) = call_args(lhs, self.spec.func) {
            let Some(prev) = prev else { return Ok(None) };
            return self.apply_prev(e, st, prev, &call);
        }
        if let Some(c) = first_scrut(lhs)
            && depth_guard > 0
        {
            let bi = env.bool_ind();
            let d = st.depth_left;
            let mut arm_fn = |e2: &mut Engine<'_>, arm: &mut St, tk: V, _k: u32| -> R<Option<Tm>> { self.split_lhs(e2, arm, &tk, prev, depth_guard - 1) };
            return e.case_split_with(st, &c, bi, &[], goal, true, d, &mut arm_fn);
        }
        self.exit(e, st, goal)
    }

    /// Proves `lemma_j` (see the module docs): its body in the statement's
    /// telescope.
    pub fn lemma(&mut self, e: &mut Engine<'_>, ty: &Tm, prev: Option<GlobalId>) -> Result<Option<Tm>, String> {
        let env = e.env;
        let mut st = St::new(env, &Ctx::default(), 64);
        let goal = open(e, &mut st, ty)?;
        let Some((rty, lhs, rhs)) = as_eq(&goal) else { return Err("a lemma statement that is not an equation".into()) };
        let (rty, lhs, rhs) = (rty.clone(), lhs.clone(), rhs.clone());
        let func = self.spec.func;
        if call_args(&lhs, func).is_none() {
            // the kernel's evaluation already unfolded the call (its body is
            // not stuck at these arguments: the exhaustion)
            if self.trace {
                eprintln!("[loopsum] lemma j={} goal (evaluated): {}", self.j, show(env, &st, &goal));
            }
            let pf = self.split_lhs(e, &mut st, &goal, prev, 8).map_err(|s| format!("{s:?}"))?;
            return Ok(pf.map(|p| st.finish(p)));
        }
        let lhs_tm = st.quote(env, &lhs);
        let (ty_tm, rhs_tm) = (st.quote(env, &rty), st.quote(env, &rhs));
        let mut args = Vec::new();
        let mut h = &lhs_tm;
        while let Term::App { rel, fun, arg } = &**h {
            args.push((*rel, arg.clone()));
            h = fun;
        }
        args.reverse();
        let body = apps(self.body.clone().or_else(|| env.global_body(func)).ok_or("the loop has no body")?, args.clone());
        let delta = Rc::new(Term::Delta { def: func, args: args.into_iter().map(|(_, a)| a).collect() });
        let g1 = eval_in(env, &st.ctx, &mk::eq(ty_tm.clone(), body.clone(), rhs_tm.clone()))?;
        if self.trace {
            eprintln!("[loopsum] lemma j={} goal after Delta: {}", self.j, show(env, &st, &g1));
        }
        let pf = self.split_lhs(e, &mut st, &g1, prev, 8).map_err(|s| format!("{s:?}"))?;
        let Some(pf) = pf else { return Ok(None) };
        let trans = env.lookup_global("eq::trans").ok_or("eq::trans")?;
        let p = apps(mk::global(trans), [(Rel::Rel, ty_tm), (Rel::Rel, lhs_tm), (Rel::Rel, body), (Rel::Rel, rhs_tm), (Rel::Rel, delta), (Rel::Rel, pf)]);
        Ok(Some(st.finish(p)))
    }
}

/// Whether a value has a stuck match on a boolean test anywhere.
fn has_stuck_bool(v: &V) -> bool {
    stuck_bool_in(v).is_some()
}

/// The first stuck boolean test inside a value (its relevant parts).
fn stuck_bool_in(v: &V) -> Option<V> {
    let mut found = None;
    crate::auto::util::walk(v, &mut |x| {
        if found.is_some() {
            return false;
        }
        if let Value::Neu(n) = &**x
            && let Some(i) = n.spine.iter().position(|e| matches!(e, Elim::Match { .. }))
            && let Elim::Match { arms, .. } = &n.spine[i]
            && arms.len() == 2
        {
            let s = prefix(n, i);
            if crate::auto::util::as_prim(&s).is_some_and(|(op, _)| matches!(op, PrimOp::Lt(_) | PrimOp::Le(_) | PrimOp::Gt(_) | PrimOp::Ge(_) | PrimOp::Eq(_) | PrimOp::Ne(_))) {
                found = Some(s);
                return false;
            }
        }
        true
    });
    found
}

/// Whether two values are the same bound variable.
fn same_var(a: &V, b: &V) -> bool {
    Rc::ptr_eq(a, b) || matches!((crate::auto::util::as_var(a), crate::auto::util::as_var(b)), (Some(p), Some(q)) if p == q)
}

/// The variables occurring in a non-literal shift amount of a value, with
/// their width.
fn shift_amount_vars(v: &V) -> Vec<(V, Width)> {
    let mut out: Vec<(V, Width)> = Vec::new();
    crate::auto::util::walk(v, &mut |x| {
        if let Some((PrimOp::WShr(_) | PrimOp::WShl(_) | PrimOp::Shr(_) | PrimOp::Shl(_), a)) = crate::auto::util::as_prim(x)
            && lit_of(&a[1]).is_none()
        {
            crate::auto::util::walk(&a[1], &mut |y| {
                if let Value::Neu(Neutral { head: Head::Var(_), spine }) = &**y
                    && spine.is_empty()
                    && !out.iter().any(|(z, _)| Rc::ptr_eq(z, y))
                {
                    out.push((y.clone(), Width::U32));
                }
                true
            });
        }
        true
    });
    out
}

/// Facts with a state variable replaced by its closed form: for every
/// invariant equation `.i_v : Eq(W, v, CF)` of the context (`v` a binder,
/// `CF` over the ghosts), each other fact `F(v)` transported to `F(CF)`
/// (the path equations of the loop's guards are over the state; the
/// library's instances are over the ghosts).
fn subst_facts(env: &Env, st: &St) -> Vec<(Tm, V)> {
    let mut out = Vec::new();
    let d = st.ctx.depth().0;
    let entries = &st.ctx.entries;
    for (hi, h) in entries.iter().enumerate() {
        if !h.name.starts_with("i_") {
            continue;
        }
        let Some((ty, l, r)) = as_eq(&h.ty) else { continue };
        let Some(vl) = crate::auto::util::as_var(l) else { continue };
        // CF must not mention another state binder than the ghosts: it
        // mentions no binder at or after the lemma's first requires
        let mut ok = true;
        crate::auto::util::for_each_var(r, 0, &mut |x| {
            if x == vl {
                ok = false;
            }
        });
        if !ok || !matches!(&**ty, Value::IntTy(_)) {
            continue;
        }
        let ty_tm = st.quote(env, ty);
        let (l_tm, r_tm) = (st.quote(env, l), st.quote(env, r));
        let promote = match env.lookup_global("eq::promote") {
            Some(g) => g,
            None => continue,
        };
        let eqp = apps(mk::global(promote), [(Rel::Rel, ty_tm.clone()), (Rel::Rel, l_tm.clone()), (Rel::Rel, r_tm.clone()), (Rel::Irr, mk::var(d - 1 - hi as u32))]);
        for f in &st.facts {
            let fi = f.lvl as usize;
            // only the path equations of the guards (named `e`)
            if fi == hi || &*entries[fi].name != "e" {
                continue;
            }
            let mut mentions = false;
            crate::auto::util::for_each_var(&f.ty, 0, &mut |x| {
                if x == vl {
                    mentions = true;
                }
            });
            if !mentions {
                continue;
            }
            let Ok(motive) = env.abstract_occurrences(&st.ctx, &f.ty, l, &mut Budget { steps: 2_000_000 }) else { continue };
            let Ok(new_ty) = env.eval(&venv_push(&st.venv, EnvEntry::Rel(r.clone())), Lvl(d + 1), &motive, &mut Budget { steps: 2_000_000 }) else { continue };
            let pf = mk::var(d - 1 - fi as u32);
            let pf = if entries[fi].rel == Rel::Irr {
                match as_eq(&f.ty) {
                    Some((fty, fl, fr)) => apps(mk::global(promote), [(Rel::Rel, st.quote(env, fty)), (Rel::Rel, st.quote(env, fl)), (Rel::Rel, st.quote(env, fr)), (Rel::Irr, pf)]),
                    None => continue,
                }
            } else {
                pf
            };
            let t = Rc::new(Term::Transport { ty: ty_tm.clone(), lhs: l_tm.clone(), rhs: r_tm.clone(), eq: eqp.clone(), motive, val: pf });
            out.push((t, new_ty));
        }
    }
    out
}

/// The key of a hint term for the class memo: a family instance by its
/// family, its literal's offset from the remaining fuel `f`, and its
/// argument; anything else by its printed form.
fn hint_key(env: &Env, h: &Tm, f: i64) -> String {
    if let Term::App { fun, arg, .. } = &**h
        && let Term::Global(g) = &**fun
        && let Some(name) = env.global_name(*g)
        && let Some(rest) = name.strip_prefix("bits::")
        && let Some((stem, k)) = rest.rsplit_once('_')
        && let Ok(k) = k.parse::<i64>()
    {
        return format!("{stem}@{}:{}", k - f, env.print_term(&[], arg).chars().take(80).collect::<String>());
    }
    format!("{h:?}").chars().take(200).collect()
}

/// The context facts (binder names) and hints (keys) a proof uses: the
/// hypotheses of its `linarith` nodes.
fn used_of(env: &Env, ctx: &Ctx, p: &Tm, hints: &[Tm], keys: &[String]) -> (Vec<String>, Vec<String>) {
    let mut facts: Vec<String> = Vec::new();
    let mut hs: Vec<String> = Vec::new();
    let d0 = ctx.depth().0;
    fn strip(t: &Tm) -> &Tm {
        // `eq::promote T l r .p` → p
        if let Term::App { arg, rel: Rel::Irr, .. } = &**t {
            return strip(arg);
        }
        t
    }
    crate::elab::tm::any_node_depth(p, &mut |n, k| {
        if let Term::Linarith { hyps, .. } = n {
            for (pf, _) in hyps {
                let q = strip(pf);
                match &**q {
                    Term::Var(i) if (i.0 as u32) >= k => {
                        let lvl = d0 as i64 - 1 - (i.0 as i64 - k as i64);
                        if lvl >= 0
                            && let Some(e) = ctx.entries.get(lvl as usize)
                            && !facts.contains(&e.name.to_string())
                        {
                            facts.push(e.name.to_string());
                        }
                    }
                    _ => {
                        for (h, key) in hints.iter().zip(keys) {
                            if env.alpha_eq_relevant(h, q, &|x, y| x == y) || env.alpha_eq_relevant(&crate::auto::util::shift(h, k as i64), q, &|x, y| x == y) {
                                if !hs.contains(key) {
                                    hs.push(key.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    });
    // path equations share one name: all of them
    facts.push("e".into());
    (facts, hs)
}

/// The outer `let`s of a proof substituted into its body (the facts a
/// focused proof bound are `Irr` lets; bound inside an irrelevant position
/// they could only be used irrelevantly, and linarith hypotheses are not).
fn zeta_lets(t: &Tm) -> Tm {
    let mut t = t.clone();
    while let Term::Let { val, body, .. } = &*t.clone() {
        t = crate::auto::util::subst0(body, val);
    }
    t
}

/// A value shown in a state's names (tracing).
fn show(env: &Env, st: &St, v: &V) -> String {
    let names: Vec<sandblaster_kernel::term::Name> = st.ctx.entries.iter().map(|e| e.name.clone()).collect();
    crate::elab::show::value(env, &names, v, 1500)
}

/// The `lz(x)` atom of a witness with a literal division over it (`(c −
/// lz(x)) / k`, possibly offset): the witness is not solvable for the atom
/// (a range of atom values maps to one iteration), so it is pinned by
/// magnitude instead ([`Builder::exit_by_range`]).
pub fn div_lz_atom(e: &E) -> Option<(Width, E)> {
    fn has_div(e: &E) -> bool {
        match &**e {
            CE::DivLit(..) => true,
            CE::Op(_, a) => a.iter().any(has_div),
            _ => false,
        }
    }
    fn lz(e: &E) -> Option<(Width, E)> {
        match &**e {
            CE::Op(PrimOp::LeadingZeros(w), a) => Some((*w, a[0].clone())),
            CE::Op(_, a) => a.iter().find_map(lz),
            CE::DivLit(x, _) => lz(x),
            _ => None,
        }
    }
    if solve_atom(e, 0).is_some() || !has_div(e) {
        return None;
    }
    lz(e)
}

/// Solves `E = j` for the bit-count atom of `E`: `(atom, value)`.
pub fn solve_atom(e: &E, j: i128) -> Option<(E, i128)> {
    use PrimOp::*;
    match &**e {
        CE::Op(LeadingZeros(_) | TrailingZeros(_), _) => Some((e.clone(), j)),
        CE::Op(Cast { .. }, a) => solve_atom(&a[0], j),
        CE::Op(WSub(_), a) => match (&*a[0], &*a[1]) {
            (_, CE::Lit(_, c)) => solve_atom(&a[0], j + *c as i128),
            (CE::Lit(_, c), _) => solve_atom(&a[1], *c as i128 - j),
            _ => None,
        },
        CE::Op(WAdd(_), a) => match (&*a[0], &*a[1]) {
            (_, CE::Lit(_, c)) => solve_atom(&a[0], j - *c as i128),
            (CE::Lit(_, c), _) => solve_atom(&a[1], j - *c as i128),
            _ => None,
        },
        _ => None,
    }
}

/// The family members the chain's proofs use at iteration `j` (ensured
/// before the lemma is built: generated and kernel-checked once).
pub fn families_at(spec: &Spec, j: u32) -> Vec<(Family, Width, u32)> {
    let w = spec.word;
    let b = expr::bits(w);
    let mut out = Vec::new();
    let mut ks: Vec<u32> = Vec::new();
    for d in [-2i64, -1, 0, 1, 2] {
        let k = spec.k as i64 - j as i64 + d;
        if k >= 0 && (k as u32) < b {
            ks.push(k as u32);
        }
        let k2 = j as i64 + d;
        if k2 >= 0 && (k2 as u32) < b {
            ks.push(k2 as u32);
        }
        let k3 = b as i64 - 1 - (spec.k as i64 - j as i64) + d;
        if k3 >= 0 && (k3 as u32) < b {
            ks.push(k3 as u32);
        }
    }
    ks.sort();
    ks.dedup();
    for f in &spec.families {
        for &k in &ks {
            if f.valid(w, k) {
                out.push((*f, w, k));
            }
        }
    }
    // a witness `(c − lz(x)) / k`: pinned by magnitude (every `lz_range_k`)
    if let Some((lw, _)) = div_lz_atom(&spec.witness) {
        for k in 0..expr::bits(lw) {
            if Family::LzRange.valid(lw, k) {
                out.push((Family::LzRange, lw, k));
            }
        }
    }
    // the entry's `cnt(x >> k) = 0` facts (the top shift)
    if j == 0 && spec.families.contains(&Family::PopcntStep) {
        for k in [b - 1, b - 2] {
            if Family::PopcntShrZero.valid(w, k) {
                out.push((Family::PopcntShrZero, w, k));
            }
        }
    }
    out
}

/// Runs the chain: `lemma_K … lemma_0` (committed as `<prefix>::lemma_<j>`),
/// returning the globals by `j` (`None` where a lemma failed: the chain
/// stops) and the statistics.
pub fn build_chain(env: &mut Env, spec: &Spec, prefix: &str, budget_total: u64, cache: Option<&crate::opt::cache::Cache>) -> Result<(Vec<Option<GlobalId>>, Stats), String> {
    build_chain_trusting(env, spec, prefix, budget_total, cache, false)
}

/// [`build_chain`]; `trust`: a simulated fault — obligations the builder
/// cannot prove are claimed (certificate-free `linarith`) for the kernel to
/// judge.
pub fn build_chain_trusting(env: &mut Env, spec: &Spec, prefix: &str, budget_total: u64, cache: Option<&crate::opt::cache::Cache>, trust: bool) -> Result<(Vec<Option<GlobalId>>, Stats), String> {
    // (the fact chain that may follow reuses this chain's obligation proofs)
    reset_shared();
    let mut out: Vec<Option<GlobalId>> = vec![None; spec.k as usize + 1];
    let mut b = Builder::new(spec);
    b.trust = trust;
    let mut outl = crate::opt::outline::Outlines::default();
    outl.ensure(env, spec.func);
    b.body = outl.get(spec.func).map(|o| o.1.clone());
    SHARED_BODY.with(|m| *m.borrow_mut() = b.body.clone().map(|t| (spec.func, t)));
    let cfg = AutoConfig { self_check: false, goal_timeout: Some(std::time::Duration::from_secs(3600)), deep_enrich: true, lin_rounds: 4, ..AutoConfig::default() };
    let mut prev: Option<GlobalId> = None;
    let mut spent = 0u64;
    let timing = std::env::var_os("SANDBLASTER_LOOPSUM_TIMING").is_some();
    let mut db = LemmaDb::default();
    let (mut t_fam, mut t_build, mut t_check, mut t_stmt) = (std::time::Duration::ZERO, std::time::Duration::ZERO, std::time::Duration::ZERO, std::time::Duration::ZERO);
    let mut fam_times: BTreeMap<&str, std::time::Duration> = BTreeMap::new();
    let mut fam_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for j in (0..=spec.k).rev() {
        let t0 = std::time::Instant::now();
        for (f, w, k) in families_at(spec, j) {
            let lim = super::meter::cap(400_000_000);
            let mut fb = Budget { steps: lim };
            let tf = std::time::Instant::now();
            let fresh = env.lookup_global(&bitlib::lemma_name(f, w, k)).is_none();
            let _ = bitlib::ensure(env, f, w, k, &mut fb);
            super::meter::charge(lim - fb.steps);
            if timing && fresh {
                *fam_times.entry(f.stem()).or_insert(std::time::Duration::ZERO) += tf.elapsed();
                *fam_counts.entry(f.stem()).or_insert(0usize) += 1;
            }
        }
        t_fam += t0.elapsed();
        if timing && j == 0 {
            eprintln!("[loopsum] timing: families {t_fam:?} ({:?}), statements {t_stmt:?}, build {t_build:?} (hints {:?}, linarith {:?}), check {t_check:?}", fam_times.iter().map(|(k, v)| format!("{k} {} {v:?}", fam_counts[k])).collect::<Vec<_>>(), b.t_hints, b.t_lin);
        }
        b.j = j;
        let t1 = std::time::Instant::now();
        let ty = spec.statement(env, j)?;
        t_stmt += t1.elapsed();
        let name = format!("{prefix}::lemma_{j}");
        // a cached proof (a hint: the kernel checks it), charged the steps
        // its build and check took in the build that stored it, in place of
        // what the hit takes (the meter, the budget and the report do not
        // depend on the cache); an entry costing more than the steps left
        // is not used (the build here would run out)
        let mut hit = false;
        // (one key per lemma: the statement's globals do not change)
        let key = cache.map(|c| c.key(env, &name, &ty));
        if let (Some(c), Some(key)) = (cache, &key) {
            if let Some((body, cost)) = c.load_costed(env, key)
                && cost.build.saturating_add(cost.check) <= super::meter::cap(u64::MAX)
            {
                super::meter::charge(cost.build);
                match add_lemma(env, &name, ty.clone(), body, LEMMA_STEPS) {
                    Ok((g, s)) => {
                        super::meter::recharge(s, cost.check);
                        b.stats.check_steps += cost.check;
                        b.stats.lemma_steps.push(cost.build);
                        spent += cost.build + cost.check;
                        out[j as usize] = Some(g);
                        prev = Some(g);
                        hit = true;
                    }
                    Err(e) => {
                        super::meter::refund(cost.build);
                        c.reject(key, &name, &e);
                    }
                }
            }
        }
        if hit {
            if spent > budget_total {
                b.stats.first_failure = Some(format!("the loop's step budget ({budget_total}) is exhausted at lemma_{j}"));
                return Ok((out, b.stats));
            }
            continue;
        }
        let t2 = std::time::Instant::now();
        db.refresh(env);
        let lim = super::meter::cap(LEMMA_STEPS);
        let mut sb = Budget { steps: lim };
        let proof = {
            let envr: &Env = env;
            let mut e = Engine::new(envr, &mut sb, &cfg, &db, vec![], 0);
            b.lemma(&mut e, &ty, if j == spec.k { None } else { prev })
        };
        super::meter::charge(lim - sb.steps);
        let proof = proof?;
        t_build += t2.elapsed();
        let used = lim - sb.steps;
        let obligation_steps: u64 = 0;
        b.stats.lemma_steps.push(used + obligation_steps);
        spent += used;
        let Some(p) = proof else {
            if let Some(f) = &b.stats.first_failure {
                b.stats.first_failure = Some(format!("lemma_{j} not built; {f}"));
            }
            return Ok((out, b.stats));
        };
        if std::env::var_os("SANDBLASTER_LOOPSUM_DUMP").is_some() {
            eprintln!("[loopsum] lemma_{j} proof: {}", env.print_term(&[], &p).chars().take(20000).collect::<String>());
        }
        let t3 = std::time::Instant::now();
        let p = hashcons(&p);
        let added = add_consed(env, &name, ty.clone(), p.clone(), LEMMA_STEPS);
        t_check += t3.elapsed();
        match added {
            Ok((g, s)) => {
                b.stats.check_steps += s;
                spent += s;
                out[j as usize] = Some(g);
                prev = Some(g);
                if let (Some(c), Some(key)) = (cache, &key) {
                    c.store_lemma(env, key, &p, g, crate::opt::cache::Cost { build: used, check: s });
                }
            }
            Err(e) => {
                // (a kernel rejection outranks an obligation failure the
                // builder recovered from)
                b.stats.first_failure = Some(format!("kernel rejected lemma_{j}: {e}"));
                return Ok((out, b.stats));
            }
        }
        if spent > budget_total {
            if b.stats.first_failure.is_none() {
                b.stats.first_failure = Some(format!("the loop's step budget ({budget_total}) is exhausted at lemma_{j}"));
            }
            return Ok((out, b.stats));
        }
    }
    Ok((out, b.stats))
}
