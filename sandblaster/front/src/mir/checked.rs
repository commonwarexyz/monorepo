//! Checked structuring (`docs/checked-structuring.md`): the literal reading
//! of a module's MIR loaded into the kernel environment of its structured
//! reading, and the per-function theorems proven by the walker
//! ([`super::simproof`]). UNTRUSTED: this module only drives — planning,
//! dependency order, the loop and model lemmas, the theorems' construction,
//! the verdict cache (whose entries are declarations the kernel re-checks
//! on replay) and the reports. Whether a function has its theorem is
//! decided by the trusted check [`super::gate`] against what the kernel
//! holds.

use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::Instant;

use sandblaster_kernel::api::{Ctx, Env};
use sandblaster_kernel::term::{DefDecl, DefKind, GlobalId, Name, PrimOp, Recursion, Rel, Term, Tm, Width};
use sandblaster_kernel::util::{mk, shift};
use sandblaster_kernel::value::{Budget, Value};

use super::gate::{Ledger, Verdict};
use super::ir::{Sbmir, Ty};
use super::literal::{Gen, GenState, KNames, LFn};
use super::simproof::{Callee, ExitMode, Fact, Goal, Helper, Pres, RecCtx, RecFn, Walker, WhileHelper};
use super::stmt::{self, StmtSpec};
use super::ModuleNames;
use crate::lift::MirContract;

/// A telescope: (name, relevance, type) per binder.
type Tele = Vec<(Name, Rel, Tm)>;

/// The literal reading of a module, loaded.
pub struct Literal {
    pub state: GenState,
    /// Functions that could not be read at all, and why.
    pub refused: Vec<(String, String)>,
    pub items: usize,
    pub lines: usize,
    pub bytes: usize,
    pub check_secs: f64,
}

impl Literal {
    pub fn lfn(&self, key: &str) -> Option<&LFn> {
        self.state.fns.get(key)
    }
}

/// Generates the literal reading of `keys` (and of what they call) and
/// loads it, with its library, into `env` (whose structured reading names
/// the types). `keys` empty: every MIR instance with a body. `dump`: where
/// to write the generated text first.
pub fn load_literal(env: &mut Env, m: &Sbmir, names: &ModuleNames, keys: &[String], dump: Option<&std::path::Path>) -> Result<Literal, String> {
    load_into(&mut Ledger::default(), env, m, names, keys, dump)
}

/// [`load_literal`] through `ledger` (the trusted loader: continuing the
/// module's reading when it has one).
pub fn load_into(ledger: &mut Ledger, env: &mut Env, m: &Sbmir, names: &ModuleNames, keys: &[String], dump: Option<&std::path::Path>) -> Result<Literal, String> {
    let all: Vec<String> = if keys.is_empty() { m.fns.iter().filter(|(_, f)| f.has_body).map(|(k, _)| k.clone()).collect() } else { keys.to_vec() };
    let l = ledger.load(env, m, names, &all, dump)?;
    let state = ledger.state(&m.module).cloned().unwrap_or_default();
    Ok(Literal { state, refused: l.refused, items: l.items, lines: l.lines, bytes: l.bytes, check_secs: l.secs })
}

/// A theorem to prove (in dependency order: callees, loop helpers, functions).
#[derive(Clone, Debug)]
pub enum Entry {
    /// The trusted theorem of a lifted function: its MIR instance and `S_f`.
    Fn { key: String, s_global: String },
    /// The (untrusted) lemma of a loop helper of `S`: the instance, the
    /// helper's global, the loop header block, and the helper's parameters'
    /// slots at the header (`l<i>`/`c<j>` = `p<k>`, or `code` for a `&mut`
    /// parameter's code).
    Helper { key: String, s_global: String, header: usize, slots: Vec<(String, String)> },
    /// The (untrusted) lemma of a `while` loop's helper (the elaborator's
    /// `<f>::loop#k`): the instance, the helper's global, the loop header,
    /// and the reading's names of the instance's locals.
    While { key: String, s_global: String, header: usize, local_names: Vec<String> },
    /// The (untrusted) model lemma of a library function the lift prelude
    /// models (`core::num::<impl u64>::div_ceil` against `u64::div_ceil`):
    /// a callee lemma for the walks of the functions that call it, so that
    /// both readings hold the model's call.
    Model { key: String, s_global: String },
}

/// Library functions with MIR that the lift prelude models (`elab/lift.core`,
/// read by `read::builtin_leaf`): the MIR instance and the model. Their
/// model lemmas are untrusted (callee lemmas inside proofs).
const MODELS: &[(&str, &str)] = &[
    ("core::num::<impl u8>::div_ceil", "u8::div_ceil"),
    ("core::num::<impl u16>::div_ceil", "u16::div_ceil"),
    ("core::num::<impl u32>::div_ceil", "u32::div_ceil"),
    ("core::num::<impl u64>::div_ceil", "u64::div_ceil"),
    ("core::num::<impl usize>::div_ceil", "usize::div_ceil"),
];

/// One proven theorem.
#[derive(Clone, Debug)]
pub struct Proven {
    pub s_global: String,
    pub kind: &'static str,
    pub walk_secs: f64,
    pub check_secs: f64,
    pub nodes: usize,
    pub stats: String,
}

/// The theorems' prover over one loaded module.
pub struct Prover<'a> {
    pub env: &'a mut Env,
    pub m: &'a Sbmir,
    pub names: &'a ModuleNames,
    pub lit: &'a Literal,
    pub pre_commit: &'a std::collections::HashMap<GlobalId, crate::elab::PreCommit>,
    pub contracts: &'a [MirContract],
    pub trace: bool,
    /// Writes the statements and lemma types here when set (debugging).
    pub dump: Option<std::path::PathBuf>,
    /// The per-function budget of the walk: seconds and steps.
    pub budget_secs: f64,
    pub max_steps: usize,
    callees: Vec<Callee>,
    /// A callee lemma proven now replaces an earlier one of the same
    /// structured definition (the round trip: a helper's own MIR).
    replace_callees: bool,
    /// The structured side is the call of the definition, not its body (a
    /// copy whose body delegates to it: the round trip checked exactly that).
    delegate: bool,
    helpers: Vec<Helper>,
    /// The `while` loops' helpers with their lemmas.
    whiles: Vec<WhileHelper>,
    /// Every declaration added since the last take (a verdict-cache entry).
    pub added: Vec<DefDecl>,
}

impl<'a> Prover<'a> {
    pub fn new(env: &'a mut Env, m: &'a Sbmir, names: &'a ModuleNames, lit: &'a Literal, pre_commit: &'a std::collections::HashMap<GlobalId, crate::elab::PreCommit>, contracts: &'a [MirContract]) -> Self {
        Prover { env, m, names, lit, pre_commit, contracts, trace: false, dump: None, budget_secs: 300.0, max_steps: 2_000_000, callees: Vec::new(), replace_callees: false, delegate: false, helpers: Vec::new(), whiles: Vec::new(), added: Vec::new() }
    }

    /// Adds `d` to the environment (the kernel checks it) and to the log.
    fn add(&mut self, d: DefDecl, steps: u64) -> Result<GlobalId, sandblaster_kernel::api::KernelError> {
        self.added.push(d.clone());
        self.env.add_def(d, &mut Budget { steps })
    }

    fn dump(&self, file: &str, text: &str) {
        if let Some(d) = &self.dump {
            let _ = std::fs::write(d.join(file), text);
        }
    }

    pub fn prove(&mut self, e: &Entry) -> Result<Proven, String> {
        match e {
            Entry::Fn { key, s_global } => self.prove_fn(key, s_global),
            Entry::Helper { key, s_global, header, slots } => self.prove_helper(key, s_global, *header, slots),
            Entry::While { key, s_global, header, local_names } => self.prove_while(key, s_global, *header, local_names),
            Entry::Model { key, s_global } => self.prove_fn_as(key, s_global, true),
        }
    }

    fn opaque(&self, run: GlobalId) -> Vec<GlobalId> {
        let mut o: Vec<GlobalId> = (0..self.env.num_globals()).map(GlobalId).filter(|g| self.env.global_opaque(*g) == Some(true)).collect();
        o.push(run);
        o
    }

    fn l_runs(&self) -> Vec<GlobalId> {
        (0..self.env.num_globals()).map(GlobalId).filter(|g| self.env.global_name(*g).is_some_and(|n| n.starts_with("L::f") && n.ends_with("::run"))).collect()
    }

    #[allow(clippy::too_many_arguments)]
    fn walker(&self, out_tm: Tm, erase: Tm, eta: Vec<u32>, n_level: u32, rec: Option<RecCtx>, s_self: Option<(GlobalId, Vec<Rel>)>, opaque: Vec<GlobalId>) -> Walker<'_> {
        Walker {
            env: self.env,
            out_ty: out_tm,
            erase,
            stats: Default::default(),
            budget: 4_000_000_000,
            trace: self.trace,
            l_runs: self.l_runs(),
            eta_vars: eta,
            n_level,
            callees: self.callees.clone(),
            helpers: self.helpers.clone(),
            rec,
            rec_fn: None,
            prem_in_ctx: false,
            pres: None,
            s_self,
            s_self_run: opaque.last().copied(),
            frozen: Vec::new(),
            opaque,
            at_header: false,
            fname: String::new(),
            path: Vec::new(),
            deadline: Some(Instant::now() + std::time::Duration::from_secs_f64(self.budget_secs)),
            max_steps: self.max_steps,
            steps: 0,
            whiles: self.whiles.clone(),
            exit: None,
        }
    }

    /// The presence conjunct of `S_f` (its `Option<&mut T>` parameters):
    /// per optional cell, its component in S's result, `T` (S's), and its
    /// parameter's index among the relevant ones.
    fn pres_of(&self, lf: &LFn, tele: &Tele, r_ty: &Tm) -> Result<Option<Pres>, String> {
        let rel_tys: Vec<&Tm> = tele.iter().filter(|t| t.1 == Rel::Rel).map(|t| &t.2).collect();
        let mut cells = Vec::new();
        for (j, c) in lf.cells.iter().enumerate() {
            if !c.optional || c.parent.is_some() {
                continue;
            }
            let pi = c.param - 1;
            let Some(Term::Ind { params, .. }) = rel_tys.get(pi).map(|t| &***t) else { return Err(format!("the `Option<&mut T>` parameter {pi} has no `Option` type in S")) };
            let elem = params.first().cloned().ok_or("an `Option` without its parameter")?;
            if !closed(&elem) {
                return Err("an optional cell whose referent type depends on the parameters".into());
            }
            cells.push((j, elem, pi));
        }
        if cells.is_empty() {
            return Ok(None);
        }
        if !closed(r_ty) {
            return Err("a result type that depends on the parameters".into());
        }
        Ok(Some(Pres { cells, r_ty: r_ty.clone() }))
    }

    /// `S_f`'s telescope as terms (names `x<i>`), and its result type.
    fn tele(&self, sg: GlobalId) -> Result<(Tele, Tm), String> {
        let (mut cur, arity) = (self.env.global_type(sg).ok_or("no type")?, self.env.global_arity(sg).ok_or("no arity")?);
        let mut tele = Vec::new();
        for i in 0..arity {
            let Term::Pi { rel, dom, cod, .. } = &*cur else { return Err("telescope".into()) };
            tele.push((Rc::from(format!("x{i}").as_str()), *rel, dom.clone()));
            cur = cod.clone();
        }
        Ok((tele, cur))
    }

    fn statement(&self, lf: &LFn, key: &str, s_global: &str) -> Result<StmtSpec, String> {
        // (every lifted function read from MIR is listed with its instance)
        self.contracts.iter().find(|c| c.global == s_global && c.key == key).ok_or_else(|| format!("`{s_global}` is not a lifted function read from the MIR instance `{key}`"))?;
        let k = KNames { names: self.names, env: self.env };
        let mut g = Gen::resume(self.m, &k, self.lit.state.clone());
        let f = self.m.fns.get(key).ok_or("no MIR")?;
        stmt::statement(self.env, &mut g, lf, f, s_global)
    }

    /// The theorem of a lifted function, from its (untrusted) function
    /// lemma `Π x̄ (n) (.hle : W(x̄) ≤ len n). C`, `C` the equation (with the
    /// presence conjunct when `f` has optional cells). A measure-recursive
    /// `S_f` (non-tail self-calls) gets its lemma by measure recursion with
    /// S's measure, `W = mult·μ`, the premise a hypothesis of the walk;
    /// otherwise `W` is the fuel shadow, refined along the walk.
    fn prove_fn(&mut self, key: &str, s_global: &str) -> Result<Proven, String> {
        self.prove_fn_as(key, s_global, false)
    }

    /// [`Self::prove_fn`]; `model`: a library function's model lemma (its
    /// statement against the prelude's model, no theorem).
    fn prove_fn_as(&mut self, key: &str, s_global: &str, model: bool) -> Result<Proven, String> {
        let t3 = Instant::now();
        let lf = self.lit.lfn(key).cloned().ok_or_else(|| format!("no literal reading of `{key}`"))?;
        let f = self.m.fns.get(key).cloned().ok_or("no MIR")?;
        let st = if model {
            let k = KNames { names: self.names, env: self.env };
            let mut g = Gen::resume(self.m, &k, self.lit.state.clone());
            stmt::statement(self.env, &mut g, &lf, &f, s_global)?
        } else {
            self.statement(&lf, key, s_global)?
        };
        let sg = self.env.lookup_global(s_global).ok_or("no S global")?;
        let (tele, r_ty0) = self.tele(sg)?;
        let arity = tele.len() as u32;
        let rels = self.env.global_param_rels(sg).ok_or("rels")?;
        let out_tm = self.env.parse_term(&[], &lf.out_ty).map_err(|e| format!("out type: {e}"))?;
        let run_g = self.env.lookup_global(&lf.run).ok_or("no run")?;
        let erase_tm = self.env.parse_term(&[], &st.erase_fn()).map_err(|e| format!("erase: {e}"))?;
        let names: Vec<&str> = st.params.iter().map(|p| p.0.as_str()).collect();
        let mut names_n = names.clone();
        names_n.push("n");
        let l_tm = self.env.parse_term(&names_n, &st.l_of()).map_err(|e| format!("l: {e}"))?;
        let mut rn: Vec<&str> = st.params.iter().filter(|p| p.1 == Rel::Rel).map(|p| p.0.as_str()).collect();
        rn.push("n");
        let l_rel = self.env.parse_term(&rn, &st.l_of()).map_err(|e| format!("l_of: {e}"))?;
        let pres = self.pres_of(&lf, &tele, &r_ty0)?;
        let rel_idx: Vec<u32> = (0..arity).filter(|i| tele[*i as usize].1 == Rel::Rel).collect();
        // a measure-recursive S: its pre-commit body (self-calls `Rec` with
        // their decrease proofs) and measure
        let pc = self.pre_commit.get(&sg).cloned();
        let nself = f.blocks.iter().filter(|b| matches!(&b.term, super::ir::Term::Call(super::ir::Callee::Fn(k2), ..) if k2 == key)).count() as i64;
        let rec_fn = match &pc {
            Some(pc) => {
                if !lf.headers.is_empty() {
                    return Err(format!("`{s_global}` is recursive and has a loop (not supported yet)"));
                }
                let mut c = Ctx::default();
                let wtmp = self.walker(out_tm.clone(), erase_tm.clone(), vec![], 0, None, None, vec![]);
                for (nm, r, d) in tele.iter() {
                    c = wtmp.push(&c, nm, *r, d, None)?;
                }
                let width = match &*self.env.infer(&c, &pc.measure, &mut Budget { steps: 1_000_000 }).map_err(|e| e.to_string())? {
                    Value::IntTy(w) => *w,
                    _ => return Err("the measure's type".into()),
                };
                Some(RecFn { measure: pc.measure.clone(), width, mult: nself.max(1), nparams: arity, rels: rels.clone(), l_of: l_rel.clone() })
            }
            None => None,
        };
        let body = match &pc {
            Some(pc) => pc.body.clone(),
            None => self.env.global_body(sg).ok_or("no body")?,
        };
        let mut inner = body.clone();
        for _ in 0..arity {
            let Term::Lam { body, .. } = &*inner else { return Err("body".into()) };
            inner = body.clone();
        }
        if self.delegate {
            if pc.is_some() {
                return Err(format!("a delegation to the recursive `{s_global}`"));
            }
            inner = mk::apps(mk::global(sg), (0..arity).map(|i| (tele[i as usize].1, mk::var(arity - 1 - i))).collect::<Vec<_>>());
        }
        // (the lift prelude's exec helpers, `i16_neg` and the like, unfolded
        // in place: their tests are then S's own splits)
        inner = inline_prelude(self.env, &inner, 4);
        // (S's body shared once: the walk shifts and commits it at every step)
        if std::env::var("CS_NO_HASHCONS").is_err() {
            inner = super::simproof::hashcons(&inner);
        }
        let opaque = self.opaque(run_g);
        let s_self = rec_fn.as_ref().map(|_| (sg, rels.clone()));
        let mut w = self.walker(out_tm.clone(), erase_tm.clone(), (0..arity).collect(), arity, None, s_self, opaque);
        w.fname = s_global.to_string();
        w.pres = pres.clone();
        w.rec_fn = rec_fn.clone();
        w.prem_in_ctx = rec_fn.is_some();
        let params_at = |depth: u32| -> Vec<Tm> { (0..arity).map(|l| mk::var(depth - 1 - l)).collect() };
        let need_tm = match &rec_fn {
            Some(rf) => rf.need(&params_at(arity)),
            None => w.shadow(&inner),
        };
        let fuel_free = matches!(&*need_tm, Term::Lit { n, .. } if n == &num_bigint::BigInt::from(0));
        let mut ctx = Ctx::default();
        for (nm, r, d) in tele.iter() {
            ctx = w.push(&ctx, nm, *r, d, None)?;
        }
        let lu = w.list_unit();
        let nctx = w.push(&ctx, "n", Rel::Rel, &lu, None)?;
        let ins_at = |depth: u32| -> Vec<Tm> { pres.as_ref().map(|p| p.cells.iter().map(|c| mk::var(depth - 1 - rel_idx[c.2])).collect()).unwrap_or_default() };
        let len_at = |env: &Env, v: u32| mk::apps(mk::global(env.lookup_global("seq::len").unwrap()), vec![(Rel::Rel, mk::ind(env.lookup_ind("Unit").unwrap(), vec![])), (Rel::Rel, mk::var(v))]);
        // the premise over (x̄, n)
        let prem_n = le_int(self.env, shift(&need_tm, 1), len_at(self.env, 0));
        let args_x = |k: u32| -> Vec<(Rel, Tm)> { (0..arity).map(|i| (tele[i as usize].1, mk::var(arity - 1 - i + k))).collect() };
        let (proof, lem_ty, lem_arity, recursion) = if let Some(rf) = &rec_fn {
            // (x̄, n, hle): the walk with the premise as a hypothesis
            let hctx = w.push(&nctx, "hle", Rel::Irr, &prem_n, None)?;
            let inner_h = shift(&inner, 2);
            let g0 = Goal { l: shift(&l_tm, 1), s: inner_h.clone(), ins: ins_at(arity + 2), rhs: None, acc: None };
            let walked = w.walk(&hctx, &g0, &[Fact::eq(mk::var(0), shift(&prem_n, 1))]).map_err(|e| format!("walk of `{s_global}`: {e}"))?;
            // transport along delta(S; x̄)
            let s_app = mk::apps(mk::global(sg), args_x(2));
            let r_ty = shift(&r_ty0, 2);
            let committed = w.commit(&inner_h);
            let delta = Rc::new(Term::Delta { def: sg, args: args_x(2).iter().map(|a| a.1.clone()).collect() });
            let sym = mk::apps(mk::global(self.env.lookup_global("eq::sym").ok_or("eq::sym")?), vec![(Rel::Rel, r_ty.clone()), (Rel::Rel, s_app.clone()), (Rel::Rel, committed.clone()), (Rel::Rel, delta)]);
            let ctx_y = w.push(&hctx, "y", Rel::Rel, &r_ty, None)?;
            let _ = ctx_y;
            let motive = w.goal_c(&Goal { l: shift(&l_tm, 2), s: mk::var(0), ins: ins_at(arity + 3), rhs: None, acc: None });
            let tr = Rc::new(Term::Transport { ty: r_ty, lhs: committed, rhs: s_app, eq: sym, motive, val: walked });
            let mut proof = mk::lam("n", Rel::Rel, lu.clone(), mk::lam("hle", Rel::Irr, prem_n.clone(), tr));
            for (nm, r, d) in tele.iter().rev() {
                proof = mk::lam(nm, *r, d.clone(), proof);
            }
            let concl = w.goal_c(&Goal { l: shift(&l_tm, 1), s: mk::apps(mk::global(sg), args_x(2)), ins: ins_at(arity + 2), rhs: None, acc: None });
            let mut lem_ty = mk::pi("n", Rel::Rel, lu.clone(), mk::pi("hle", Rel::Irr, prem_n.clone(), concl));
            for (nm, r, d) in tele.iter().rev() {
                lem_ty = mk::pi(nm, *r, d.clone(), lem_ty);
            }
            (proof, lem_ty, arity + 2, Recursion::Measure { measure: sandblaster_kernel::util::shift_from(&rf.measure, 2, 0) })
        } else {
            let inner_n = shift(&inner, 1);
            let walked = w.walk(&nctx, &Goal { l: l_tm.clone(), s: inner_n.clone(), ins: ins_at(arity + 1), rhs: None, acc: None }, &[]).map_err(|e| format!("walk of `{s_global}`: {e}"))?;
            // transport along delta(S; x̄)
            let s_app_n = mk::apps(mk::global(sg), args_x(1));
            let r_ty_n = shift(&r_ty0, 1);
            let delta = Rc::new(Term::Delta { def: sg, args: args_x(1).iter().map(|a| a.1.clone()).collect() });
            let sym = if self.delegate { mk::refl(r_ty_n.clone(), s_app_n.clone()) } else { mk::apps(mk::global(self.env.lookup_global("eq::sym").ok_or("eq::sym")?), vec![(Rel::Rel, r_ty_n.clone()), (Rel::Rel, s_app_n.clone()), (Rel::Rel, inner_n.clone()), (Rel::Rel, delta)]) };
            let ctx_y = w.push(&nctx, "y", Rel::Rel, &r_ty_n, None)?;
            let motive = w.goal_p(&ctx_y, &Goal { l: shift(&l_tm, 1), s: mk::var(0), ins: ins_at(arity + 2), rhs: None, acc: None });
            let prem_y = le_int(self.env, shift(&need_tm, 2), len_at(self.env, 1));
            let motive = match &*motive {
                Term::Pi { name, rel, cod, .. } => Rc::new(Term::Pi { name: name.clone(), rel: *rel, dom: prem_y, cod: cod.clone() }),
                _ => return Err("motive".into()),
            };
            let proof_n = Rc::new(Term::Transport { ty: r_ty_n.clone(), lhs: inner_n.clone(), rhs: s_app_n.clone(), eq: sym, motive, val: walked });
            let proof_nh = mk::lam("hle", Rel::Irr, prem_n.clone(), Rc::new(Term::App { rel: Rel::Irr, fun: shift(&proof_n, 1), arg: mk::var(0) }));
            let mut proof = mk::lam("n", Rel::Rel, lu.clone(), proof_nh);
            for (nm, r, d) in tele.iter().rev() {
                proof = mk::lam(nm, *r, d.clone(), proof);
            }
            let concl = w.goal_c(&Goal { l: l_tm.clone(), s: s_app_n.clone(), ins: ins_at(arity + 1), rhs: None, acc: None });
            let mut lem_ty = mk::pi("n", Rel::Rel, lu.clone(), mk::pi("hle", Rel::Irr, prem_n.clone(), shift(&concl, 1)));
            for (nm, r, d) in tele.iter().rev() {
                lem_ty = mk::pi(nm, *r, d.clone(), lem_ty);
            }
            (proof, lem_ty, arity + 2, Recursion::None)
        };
        let stats = format!("{:?}", w.stats);
        drop(w);
        if std::env::var("CS_PROFILE").is_ok() {
            eprintln!("PROFILE `{s_global}`: {}", super::simproof::profile(&proof));
        }
        // (the walker quotes the literal side afresh at every step: shared
        // subterms are made one node each before the kernel sees the proof)
        let raw_nodes = crate::elab::tm::size(&proof);
        let proof = if std::env::var("CS_NO_HASHCONS").is_ok() { proof } else { super::simproof::hashcons(&proof) };
        let walk_secs = t3.elapsed().as_secs_f64();
        let nodes = crate::elab::tm::size(&proof);
        let stats = format!("{stats}; {raw_nodes} nodes before sharing");
        self.dump(&format!("lem_{}.core", lf.id), &self.env.print_term(&[], &lem_ty));
        let t4 = Instant::now();
        let decl = DefDecl { name: Rc::from(format!("L::lem::{}", lf.id).as_str()), kind: DefKind::Lemma, ty: lem_ty, body: proof, recursion, arity: lem_arity, opaque: false };
        let lem_g = self.add(decl, 40_000_000_000).map_err(|e| format!("the kernel rejected the lemma of `{s_global}`: {}", trunc(&e.to_string(), 3000)))?;
        if model {
            let check_secs = t4.elapsed().as_secs_f64();
            self.callees.push(Callee { s_global: sg, lemma: lem_g, rels, l_of: l_rel, out_ty: out_tm, erase: erase_tm, need: (!fuel_free).then(|| need_tm.clone()), pres });
            return Ok(Proven { s_global: s_global.into(), kind: "model lemma", walk_secs, check_secs, nodes, stats });
        }
        // the trusted theorem from the lemma: pair(need, λ n .hle. lem x̄ n .hle)
        let thm_text = st.theorem_ty();
        self.dump(&format!("thm_{}.core", lf.id), &thm_text);
        let thm_ty = self.env.parse_term(&[], &thm_text).map_err(|e| format!("theorem type: {e}"))?;
        let mut sig = thm_ty.clone();
        for _ in 0..arity {
            let Term::Pi { cod, .. } = &*sig else { return Err("theorem".into()) };
            sig = cod.clone();
        }
        let mut lem_args: Vec<(Rel, Tm)> = (0..arity).map(|i| (tele[i as usize].1, mk::var(arity + 1 - i))).collect();
        lem_args.push((Rel::Rel, mk::var(1)));
        lem_args.push((Rel::Irr, mk::var(0)));
        let lem_app = mk::apps(mk::global(lem_g), lem_args);
        let lem_eq = if pres.is_some() { Rc::new(Term::Fst(lem_app)) } else { lem_app };
        let snd = mk::lam("n", Rel::Rel, lu.clone(), mk::lam("hle", Rel::Irr, prem_n.clone(), lem_eq));
        let mut tproof: Tm = Rc::new(Term::Pair { ty: sig, fst: need_tm.clone(), snd });
        for (nm, r, d) in tele.iter().rev() {
            tproof = mk::lam(nm, *r, d.clone(), tproof);
        }
        let decl = DefDecl { name: Rc::from(format!("L::thm::{}", lf.id).as_str()), kind: DefKind::Lemma, ty: thm_ty, body: tproof, recursion: Recursion::None, arity, opaque: false };
        self.add(decl, 4_000_000_000).map_err(|e| format!("the kernel rejected the theorem of `{s_global}`: {}", trunc(&e.to_string(), 2000)))?;
        let check_secs = t4.elapsed().as_secs_f64();
        // callers use the lemma: at any fuel, or at its need
        if self.replace_callees {
            self.callees.retain(|c| c.s_global != sg);
        }
        self.callees.push(Callee { s_global: sg, lemma: lem_g, rels, l_of: l_rel, out_ty: out_tm, erase: erase_tm, need: (!fuel_free).then(|| need_tm.clone()), pres });
        Ok(Proven { s_global: s_global.into(), kind: "theorem", walk_secs, check_secs, nodes, stats })
    }

    /// The shipped code's theorem of a function the optimizer replaced
    /// (step 8, the lifted round trip): from `L::thm::<id>` of the copy's
    /// MIR instance `key` against the replacement `target`, the theorem
    /// against the source function `source` — the trusted statement of
    /// [`stmt::statement`] of `source` — by a
    /// transport along the optimizer's kernel-checked link `equiv : Π x̄
    /// h̄. Eq(R, source x̄ h̄, target x̄ h̄)` (`None`: the same definition).
    /// Named `L::shipped::<id>`.
    pub fn compose(&mut self, key: &str, source: &str, target: &str, equiv: Option<&str>) -> Result<Proven, String> {
        let t0 = Instant::now();
        let lf = self.lit.lfn(key).cloned().ok_or_else(|| format!("no literal reading of `{key}`"))?;
        let st_f = self.statement(&lf, key, source)?;
        let st_g = self.statement(&lf, key, target)?;
        if st_f.params.iter().map(|p| p.1).collect::<Vec<_>>() != st_g.params.iter().map(|p| p.1).collect::<Vec<_>>() {
            return Err(format!("`{source}` and `{target}` do not have the same parameters"));
        }
        let thm_g = self.env.lookup_global(&format!("L::thm::{}", lf.id)).ok_or("the copy's theorem against the replacement is missing")?;
        let names: Vec<&str> = st_f.params.iter().map(|p| p.0.as_str()).collect();
        let parse = |env: &Env, ns: &[&str], t: &str, what: &str| env.parse_term(ns, t).map_err(|e| format!("{what}: {e}"));
        let thm_ty = parse(self.env, &[], &st_f.theorem_ty(), "theorem type")?;
        let r_ty = parse(self.env, &names, &st_f.s_ret, "result type")?;
        let f_app = parse(self.env, &names, &st_f.app(), "source call")?;
        let g_app = parse(self.env, &names, &st_g.app(), "replacement call")?;
        let mut ny = names.clone();
        ny.push("yy");
        let er = st_f.erase_ret.replace("@Y@", "yy");
        let motive_txt = format!("Sigma (k : Int), ((n : List(Unit)) -> (.hle : Eq(Bool, #le_int(k, seq::len Unit n), true)) -> Eq(Option({out}), {}, Some[{out}]({er})))", st_f.l_of(), out = st_f.l_out);
        let motive = parse(self.env, &ny, &motive_txt, "motive")?;
        let arity = st_f.params.len() as u32;
        let var_of = |i: usize| mk::var(arity - 1 - i as u32);
        let eq = match equiv {
            None => mk::refl(r_ty.clone(), g_app.clone()),
            Some(e) => {
                let eg = self.env.lookup_global(e).ok_or_else(|| format!("no link `{e}`"))?;
                let erels = self.env.global_param_rels(eg).ok_or("the link's telescope")?;
                // (the link binds the parameters, and the preconditions or not)
                if erels.len() > st_f.params.len() {
                    return Err(format!("the link `{e}` has {} parameters, the source function {}", erels.len(), st_f.params.len()));
                }
                // its direction: `Eq(R, f.., g..)` (a rewrite's) or `Eq(R, g.., f..)` (a residual's)
                let mut lty = self.env.global_type(eg).ok_or("the link's type")?;
                while let Term::Pi { cod, .. } = &*lty.clone() {
                    lty = cod.clone();
                }
                let sg = self.env.lookup_global(source).ok_or("no source global")?;
                let forward = match &*lty {
                    Term::Eq { lhs, .. } => super::simproof::app_spine(lhs).is_some_and(|(h, _)| h == sg),
                    _ => return Err(format!("the link `{e}` is no equation")),
                };
                let mut args = Vec::new();
                for (i, (p, er)) in st_f.params.iter().zip(&erels).enumerate().take(erels.len()) {
                    // (a precondition the link binds as relevant: promoted)
                    let a = if p.1 == Rel::Irr && *er == Rel::Rel {
                        let pty = parse(self.env, &names[..i], &p.2, "precondition")?;
                        let Term::Eq { ty, lhs, rhs } = &*pty else { return Err(format!("the precondition `{}` is no equation", p.2)) };
                        let sh = |t: &Tm| shift(t, (arity - i as u32) as i64);
                        mk::apps(mk::global(self.env.lookup_global("eq::promote").ok_or("eq::promote")?), vec![(Rel::Rel, sh(ty)), (Rel::Rel, sh(lhs)), (Rel::Rel, sh(rhs)), (Rel::Irr, var_of(i))])
                    } else {
                        var_of(i)
                    };
                    args.push((*er, a));
                }
                let link = mk::apps(mk::global(eg), args);
                if forward { mk::apps(mk::global(self.env.lookup_global("eq::sym").ok_or("eq::sym")?), vec![(Rel::Rel, r_ty.clone()), (Rel::Rel, f_app.clone()), (Rel::Rel, g_app.clone()), (Rel::Rel, link)]) } else { link }
            }
        };
        let val = mk::apps(mk::global(thm_g), (0..st_f.params.len()).map(|i| (st_f.params[i].1, var_of(i))).collect::<Vec<_>>());
        let mut proof: Tm = Rc::new(Term::Transport { ty: r_ty, lhs: g_app, rhs: f_app, eq, motive, val });
        let tele: Vec<(String, Rel, Tm)> = st_f.params.iter().enumerate().map(|(i, p)| Ok((p.0.clone(), p.1, parse(self.env, &names[..i], &p.2, "parameter")?))).collect::<Result<_, String>>()?;
        for (nm, r, d) in tele.iter().rev() {
            proof = mk::lam(nm, *r, d.clone(), proof);
        }
        let nodes = crate::elab::tm::size(&proof);
        let decl = DefDecl { name: Rc::from(format!("L::shipped::{}", lf.id).as_str()), kind: DefKind::Lemma, ty: thm_ty, body: proof, recursion: Recursion::None, arity, opaque: false };
        self.add(decl, 4_000_000_000).map_err(|e| format!("the kernel rejected the shipped code's theorem of `{source}`: {}", trunc(&e.to_string(), 2000)))?;
        Ok(Proven { s_global: source.into(), kind: "shipped theorem", walk_secs: 0.0, check_secs: t0.elapsed().as_secs_f64(), nodes, stats: format!("from `L::thm::{}` along {}", lf.id, equiv.unwrap_or("the same definition")) })
    }

    fn prove_helper(&mut self, key: &str, s_global: &str, header: usize, slotmap: &[(String, String)]) -> Result<Proven, String> {
        let t3 = Instant::now();
        let lf = self.lit.lfn(key).cloned().ok_or_else(|| format!("no literal reading of `{key}`"))?;
        let f = self.m.fns.get(key).ok_or("no MIR")?.clone();
        let sg = self.env.lookup_global(s_global).ok_or("no S global")?;
        let (tele, r_ty0) = self.tele(sg)?;
        let arity = tele.len() as u32;
        let rels = self.env.global_param_rels(sg).ok_or("rels")?;
        let pnames: Vec<Name> = tele.iter().map(|t| t.0.clone()).collect();
        let params: Vec<(String, Rel, String)> = tele.iter().enumerate().map(|(i, (n, r, d))| (n.to_string(), *r, self.env.print_term(&pnames[..i], d))).collect();
        let s_ret = self.env.print_term(&pnames, &r_ty0);
        let rc = format!("Tuple2(L::{}::Root, List(mir::Proj))", lf.id);
        let nl = lf.local_tys.len();
        let nslots = nl + lf.cells.len();
        let slot_ty = |i: usize| if i < nl { lf.local_tys[i].replace("@RC@", &rc) } else { lf.cells[i - nl].ty.replace("@RC@", &rc) };
        let (erase_ret, slots_txt) = {
            let k = KNames { names: self.names, env: self.env };
            let mut g = Gen::resume(self.m, &k, self.lit.state.clone());
            let mut assigned: Vec<Option<String>> = vec![None; nslots];
            for (sl, v) in slotmap {
                let i = if let Some(r) = sl.strip_prefix('l') { r.parse::<usize>().map_err(|e| e.to_string())? } else { nl + sl[1..].parse::<usize>().map_err(|e| e.to_string())? };
                let val = if v == "code" {
                    let j = lf.cells.iter().position(|c| c.param == i).ok_or("code of a non-`&mut` parameter")?;
                    format!("tuple2[L::{id}::Root, List(mir::Proj)](L::{id}::Root::rc{j}, Nil[mir::Proj])", id = lf.id)
                } else {
                    let pi: usize = v.strip_prefix('p').and_then(|x| x.parse().ok()).ok_or("slot value")?;
                    let x = &params[pi].0;
                    let mt = if i >= nl { lf.cells[i - nl].mir_ty.clone() } else { f.locals[i].0.clone() };
                    if i >= nl && slot_ty(i) == "List(U8)" { x.clone() } else { stmt::erase(&mut g, self.env, &mt, x)? }
                };
                assigned[i] = Some(format!("Some[{}]({val})", slot_ty(i)));
            }
            let er = erase_out(&mut g, self.env, &f, &lf)?.replace("@SRET@", &s_ret);
            (er, assigned)
        };
        let junk: Vec<usize> = (0..nslots).filter(|i| slots_txt[*i].is_none()).collect();
        let slots: Vec<String> = (0..nslots).map(|i| slots_txt[i].clone().unwrap_or_else(|| format!("j{i}"))).collect();
        let pc = self.pre_commit.get(&sg).ok_or_else(|| format!("no pre-commit body for `{s_global}`"))?;
        let (pre_body, measure) = (pc.body.clone(), pc.measure.clone());
        let st_text = format!("Some[{st}]({st}::st({}))", slots.join(", "), st = lf.st);
        let mut tele_txt: String = params.iter().map(|(n, r, t)| format!("({}{n} : {t}) -> ", if *r == Rel::Irr { "." } else { "" })).collect();
        for i in &junk {
            tele_txt.push_str(&format!("(j{i} : Option({})) -> ", slot_ty(*i)));
        }
        let app = params.iter().fold(s_global.to_string(), |a, (n, r, _)| format!("{a} {}{n}", if *r == Rel::Irr { "." } else { "" }));
        let er = erase_ret.replace("@Y@", &format!("({app})"));
        let width = {
            let mut c = Ctx::default();
            let out_tm = self.env.parse_term(&[], &lf.out_ty).map_err(|e| e.to_string())?;
            let wtmp = self.walker(out_tm.clone(), out_tm, vec![], 0, None, None, vec![]);
            for (nm, r, d) in tele.iter() {
                c = wtmp.push(&c, nm, *r, d, None)?;
            }
            match &*self.env.infer(&c, &measure, &mut Budget { steps: 1_000_000 }).map_err(|e| e.to_string())? {
                Value::IntTy(w) => *w,
                _ => return Err("the measure's type".into()),
            }
        };
        let mu_raw = self.env.print_term(&pnames, &measure);
        let mu_txt = if width == Width::Int { mu_raw } else { format!("#cast_{}_int({mu_raw})", format!("{width:?}").to_lowercase()) };
        let lem_ty_text = format!("{tele_txt}(n : List(Unit)) -> (.hle : Eq(Bool, #le_int({mu_txt}, seq::len Unit n), true)) -> Eq(Option({out}), {run} n {blk}::b{header} ({st_text}), Some[{out}]({er}))", out = lf.out_ty, run = lf.run, blk = lf.blk);
        self.dump(&format!("hlem_{}.core", lf.id), &lem_ty_text);
        let lem_ty = self.env.parse_term(&[], &lem_ty_text).map_err(|e| format!("helper lemma type: {e}"))?;
        let nj = junk.len() as u32;
        let lem_arity = arity + nj + 2;
        let hinfo = Helper { s_global: sg, lemma: GlobalId(u32::MAX), measure: measure.clone(), nparams: arity, rels: rels.clone(), junk: junk.clone(), nslots, header_ctor: (2 * header) as u32, width };
        let out_tm = self.env.parse_term(&[], &lf.out_ty).map_err(|e| e.to_string())?;
        let erase_tm = self.env.parse_term(&[], &format!("fun (yy : {s_ret}) => {}", erase_ret.replace("@Y@", "yy"))).map_err(|e| format!("erase: {e}"))?;
        let run_g = self.env.lookup_global(&lf.run).ok_or("no run")?;
        let opaque = self.opaque(run_g);
        let mut w = self.walker(out_tm, erase_tm, vec![], arity + nj, Some(RecCtx { helper: hinfo.clone() }), Some((sg, rels.clone())), opaque);
        w.fname = format!("{s_global} (loop lemma)");
        let mut ltele: Vec<(Name, Rel, Tm)> = Vec::new();
        let mut c2 = lem_ty.clone();
        for _ in 0..lem_arity {
            let Term::Pi { name, rel, dom, cod } = &*c2 else { return Err("lemma telescope".into()) };
            ltele.push((name.clone(), *rel, dom.clone()));
            c2 = cod.clone();
        }
        let Term::Eq { lhs: l_at_h, .. } = &*c2 else { return Err("lemma type body".into()) };
        let l_tm = shift(l_at_h, -1);
        let mut ctx = Ctx::default();
        for (nm, r, d) in ltele.iter().take(lem_arity as usize - 1) {
            ctx = w.push(&ctx, nm, *r, d, None)?;
        }
        let mut inner = pre_body.clone();
        for _ in 0..arity {
            let Term::Lam { body, .. } = &*inner else { return Err("pre-commit body".into()) };
            inner = body.clone();
        }
        let inner_j = shift(&inner, nj as i64 + 1);
        let walked = w.walk(&ctx, &Goal { l: l_tm.clone(), s: inner_j.clone(), ins: vec![], rhs: None, acc: None }, &[]).map_err(|e| format!("walk of helper `{s_global}`: {e}"))?;
        let stats = format!("{:?}", w.stats);
        let depth = ctx.depth().0;
        let pargs: Vec<(Rel, Tm)> = (0..arity).map(|i| (rels[i as usize], mk::var(depth - 1 - i))).collect();
        let h_app = mk::apps(mk::global(sg), pargs.clone());
        let r_ty = shift(&r_ty0, nj as i64 + 1);
        let committed = w.commit(&inner_j);
        let delta = Rc::new(Term::Delta { def: sg, args: pargs.iter().map(|a| a.1.clone()).collect() });
        let sym = mk::apps(mk::global(self.env.lookup_global("eq::sym").ok_or("eq::sym")?), vec![(Rel::Rel, r_ty.clone()), (Rel::Rel, h_app.clone()), (Rel::Rel, committed.clone()), (Rel::Rel, delta)]);
        let ctx_y = w.push(&ctx, "y", Rel::Rel, &r_ty, None)?;
        let mot = w.goal_p(&ctx_y, &Goal { l: shift(&l_tm, 1), s: mk::var(0), ins: vec![], rhs: None, acc: None });
        let tr = Rc::new(Term::Transport { ty: r_ty, lhs: committed, rhs: h_app, eq: sym, motive: mot, val: walked });
        drop(w);
        let (hn, hr, hd) = ltele[lem_arity as usize - 1].clone();
        let mut proof = mk::lam(&hn, hr, hd, Rc::new(Term::App { rel: Rel::Irr, fun: shift(&tr, 1), arg: mk::var(0) }));
        for (nm, r, d) in ltele.iter().take(lem_arity as usize - 1).rev() {
            proof = mk::lam(nm, *r, d.clone(), proof);
        }
        let raw_nodes = crate::elab::tm::size(&proof);
        let proof = if std::env::var("CS_NO_HASHCONS").is_ok() { proof } else { super::simproof::hashcons(&proof) };
        let walk_secs = t3.elapsed().as_secs_f64();
        let nodes = crate::elab::tm::size(&proof);
        let stats = format!("{stats}; {raw_nodes} nodes before sharing");
        let mshift = sandblaster_kernel::util::shift_from(&measure, nj as i64 + 2, 0);
        let t4 = Instant::now();
        let decl = DefDecl { name: Rc::from(format!("L::hlem::{}", lf.id).as_str()), kind: DefKind::Lemma, ty: lem_ty, body: proof, recursion: Recursion::Measure { measure: mshift }, arity: lem_arity, opaque: false };
        let g2 = self.add(decl, 40_000_000_000).map_err(|e| format!("the kernel rejected the loop lemma of `{s_global}`: {}", trunc(&e.to_string(), 3000)))?;
        self.helpers.push(Helper { lemma: g2, ..hinfo });
        Ok(Proven { s_global: s_global.into(), kind: "loop lemma", walk_secs, check_secs: t4.elapsed().as_secs_f64(), nodes, stats })
    }
}

impl Prover<'_> {
    /// The lemma of a `while` loop's helper `h` (the elaborator's
    /// `<f>::loop#k`, its loop header `H`), by measure recursion with the
    /// helper's measure and its own decrease proofs (see
    /// [`super::simproof::WhileHelper`]):
    ///
    /// ```text
    /// Π p̄ j̄ (n) (C : Option(Out)) (hC : Π m (.hm : len n − μ(p̄) ≤ len m) k̄.
    ///     Eq(run m X (Some σ_X(h p̄, w̄)), C)) (.hle : μ(p̄) ≤ len n).
    ///   Eq(run n H (Some σ(p̄, j̄)), C)
    /// ```
    ///
    /// `σ`: the helper's parameters in their slots (by the reading's names of
    /// the locals), junk `j̄` elsewhere; `X` the loop's exit; `σ_X`: the
    /// loop's variables (the parameters a recursive call changes) from the
    /// helper's result, the other parameters as they are, the slots the loop
    /// assigns from `k̄` and the others `j̄`. The walk splits the helper's body
    /// with `eqS : h p̄ = S` in its goals: an exit hands the literal side,
    /// stepped to `X`, to `hC`; a recursive call is the induction hypothesis
    /// with `hC` moved along `eqS`.
    fn prove_while(&mut self, key: &str, h_global: &str, header: usize, local_names: &[String]) -> Result<Proven, String> {
        let t0 = Instant::now();
        let lf = self.lit.lfn(key).cloned().ok_or_else(|| format!("no literal reading of `{key}`"))?;
        let f = self.m.fns.get(key).cloned().ok_or("no MIR")?;
        let sg = self.env.lookup_global(h_global).ok_or_else(|| format!("no helper `{h_global}`"))?;
        let (htele, r_h) = self.tele(sg)?;
        let arity = htele.len() as u32;
        let rels = self.env.global_param_rels(sg).ok_or("rels")?;
        if !closed(&r_h) {
            return Err(format!("`{h_global}`: a result type that depends on the parameters"));
        }
        let hnames: Vec<String> = {
            let mut cur = self.env.global_type(sg).ok_or("no type")?;
            let mut v = Vec::new();
            for _ in 0..arity {
                let Term::Pi { name, cod, .. } = &*cur else { return Err("telescope".into()) };
                v.push(name.to_string());
                cur = cod.clone();
            }
            v
        };
        let pc = self.pre_commit.get(&sg).cloned().ok_or_else(|| format!("no pre-commit body for `{h_global}`"))?;
        let width = {
            let mut c = Ctx::default();
            let out_tm = self.env.parse_term(&[], &lf.out_ty).map_err(|e| e.to_string())?;
            let wtmp = self.walker(out_tm.clone(), out_tm, vec![], 0, None, None, vec![]);
            for (nm, r, d) in htele.iter() {
                c = wtmp.push(&c, nm, *r, d, None)?;
            }
            match &*self.env.infer(&c, &pc.measure, &mut Budget { steps: 1_000_000 }).map_err(|e| e.to_string())? {
                Value::IntTy(w) => *w,
                _ => return Err("the measure's type".into()),
            }
        };
        let mut inner0 = pc.body.clone();
        for _ in 0..arity {
            let Term::Lam { body, .. } = &*inner0 else { return Err("pre-commit body".into()) };
            inner0 = body.clone();
        }
        // the loop's variables: the relevant parameters a recursive call changes
        let mut unchanged = vec![true; arity as usize];
        crate::auto::util::map_term(&inner0, 0, &mut |x, d| {
            if let Term::Rec { args, .. } = &**x {
                for (k, a) in args.iter().enumerate().take(arity as usize) {
                    if !matches!(&**a, Term::Var(sandblaster_kernel::term::Idx(i)) if *i == arity - 1 - k as u32 + d) {
                        unchanged[k] = false;
                    }
                }
            }
            None
        });
        let carried: Vec<usize> = (0..arity as usize).filter(|k| rels[*k] == Rel::Rel && !unchanged[*k]).collect();
        // the parameters' slots, by the reading's names of the locals
        let rc = format!("Tuple2(L::{}::Root, List(mir::Proj))", lf.id);
        let nl = lf.local_tys.len();
        let nslots = nl + lf.cells.len();
        let slot_ty = |i: usize| if i < nl { lf.local_tys[i].replace("@RC@", &rc) } else { lf.cells[i - nl].ty.replace("@RC@", &rc) };
        let mut pslot: Vec<Option<(usize, Ty)>> = vec![None; arity as usize];
        for k in 0..arity as usize {
            if rels[k] != Rel::Rel {
                continue;
            }
            let nm = &hnames[k];
            let locals: Vec<usize> = local_names.iter().enumerate().filter(|(_, n)| *n == nm).map(|(i, _)| i).collect();
            let [l] = locals[..] else { return Err(format!("the `while` helper's parameter `{nm}` names {} MIR locals", locals.len())) };
            pslot[k] = Some(match lf.cells.iter().position(|c| c.param == l && c.parent.is_none()) {
                Some(j) => (nl + j, lf.cells[j].mir_ty.clone()),
                None => (l, f.locals[l].0.clone()),
            });
        }
        let occupied: Vec<usize> = pslot.iter().flatten().map(|(i, _)| *i).collect();
        let junk: Vec<usize> = (0..nslots).filter(|i| !occupied.contains(i)).collect();
        let nj = junk.len() as u32;
        let e0 = arity + nj;
        let assigned = loop_assigned(&f, header, &lf);
        // a parameter's slot value `Some(erase(p_k))` over the parameters
        let pnames: Vec<String> = (0..arity).map(|k| format!("p{k}")).collect();
        let pn: Vec<&str> = pnames.iter().map(|x| x.as_str()).collect();
        let kn = KNames { names: self.names, env: self.env };
        let mut g = Gen::resume(self.m, &kn, self.lit.state.clone());
        let erase_txt = |g: &mut Gen<'_>, i: usize, mt: &Ty, x: &str| -> Result<String, String> { if i >= nl && slot_ty(i) == "List(U8)" { Ok(x.to_string()) } else { stmt::erase(g, self.env, mt, x) } };
        let mut param_slot_tm: Vec<Option<Tm>> = vec![None; nslots];
        for k in 0..arity as usize {
            let Some((i, mt)) = &pslot[k] else { continue };
            let txt = erase_txt(&mut g, *i, mt, &pnames[k])?;
            let t = self.env.parse_term(&pn, &format!("Some[{}]({txt})", slot_ty(*i))).map_err(|e| format!("a slot of the `while` lemma: {e}"))?;
            param_slot_tm[*i] = Some(t);
        }
        // σ_X: the loop's variables the components `c̄` of the result, the
        // other slots `w̄`
        let r_txt = self.env.print_term(&[], &r_h);
        let (comp_tys, tuple): (Vec<Tm>, Option<(sandblaster_kernel::term::IndId, Vec<Tm>)>) = match &*r_h {
            Term::Ind { ind, params } if carried.len() > 1 => (params.clone(), Some((*ind, params.clone()))),
            _ => (vec![r_h.clone()], None),
        };
        if carried.is_empty() {
            return Err(format!("`{h_global}`: a loop that changes no variable"));
        }
        let _ = &r_txt;
        let mut w: Vec<Option<Tm>> = Vec::new();
        let mut w_slots: Vec<usize> = Vec::new();
        let mut k_tys: Vec<Tm> = Vec::new();
        let mut sx_slots: Vec<String> = Vec::new();
        let mut sx_bind: String = comp_tys.iter().enumerate().map(|(c, t)| format!(" (c{c} : {})", self.env.print_term(&[], t))).collect();
        #[allow(clippy::needless_range_loop)]
        for i in 0..nslots {
            if let Some(c) = carried.iter().position(|k| pslot[*k].as_ref().is_some_and(|p| p.0 == i)) {
                let mt = pslot[carried[c]].as_ref().unwrap().1.clone();
                sx_slots.push(format!("Some[{}]({})", slot_ty(i), erase_txt(&mut g, i, &mt, &format!("c{c}"))?));
                continue;
            }
            let wi = w.len();
            sx_slots.push(format!("w{wi}"));
            sx_bind.push_str(&format!(" (w{wi} : Option({}))", slot_ty(i)));
            w_slots.push(i);
            if let Some(t) = &param_slot_tm[i] {
                // a parameter the loop does not change, over (p̄, j̄)
                w.push(Some(shift(t, nj as i64)));
            } else if assigned.contains(&i) {
                w.push(None);
                k_tys.push(self.env.parse_term(&[], &format!("Option({})", slot_ty(i))).map_err(|e| e.to_string())?);
            } else {
                let m = junk.iter().position(|j| *j == i).ok_or("a slot that is neither a parameter's nor junk")? as u32;
                w.push(Some(mk::var(nj - 1 - m)));
            }
        }
        let sx_txt = format!("fun{sx_bind} => Some[{st}]({st}::st({}))", sx_slots.join(", "), st = lf.st);
        let sx = self.env.parse_term(&[], &sx_txt).map_err(|e| format!("the state at the `while` loop's exit: {e}"))?;
        drop(g);
        // the exit block: the header's successor outside the loop
        let x_blk = loop_exit(&f, header).ok_or_else(|| format!("`{h_global}`: the loop at block {header} has not exactly one exit"))?;
        let x_ctor = (2 * x_blk) as u32;
        // the telescope p̄ j̄ n C hC (then hle)
        let out_tm = self.env.parse_term(&[], &lf.out_ty).map_err(|e| format!("out type: {e}"))?;
        let opt = self.env.lookup_ind("Option").unwrap();
        let opt_out = mk::ind(opt, vec![out_tm.clone()]);
        let lu = mk::ind(self.env.lookup_ind("List").unwrap(), vec![mk::ind(self.env.lookup_ind("Unit").unwrap(), vec![])]);
        let seq_len = self.env.lookup_global("seq::len").ok_or("seq::len")?;
        let len_of = |t: Tm| mk::apps(mk::global(seq_len), vec![(Rel::Rel, mk::ind(self.env.lookup_ind("Unit").unwrap(), vec![])), (Rel::Rel, t)]);
        let hinfo = Helper { s_global: sg, lemma: GlobalId(u32::MAX), measure: pc.measure.clone(), nparams: arity, rels: rels.clone(), junk: junk.clone(), nslots, header_ctor: (2 * header) as u32, width };
        let run_g = self.env.lookup_global(&lf.run).ok_or("no run")?;
        let st_ind = self.env.lookup_ind(&lf.st).ok_or("no St")?;
        let blk_ind = self.env.lookup_ind(&lf.blk).ok_or("no Blk")?;
        let blk = |c: u32| Rc::new(Term::Ctor { ind: blk_ind, ctor: c, params: vec![], args: vec![] });
        let h_app_at = |d: u32| mk::apps(mk::global(sg), rels.iter().copied().zip(hinfo.params_at(d)));
        let mut ltele: Vec<(Name, Rel, Tm)> = Vec::new();
        for (k, (_, r, d)) in htele.iter().enumerate() {
            ltele.push((Rc::from(pnames[k].as_str()), *r, d.clone()));
        }
        for i in &junk {
            let t = self.env.parse_term(&[], &format!("Option({})", slot_ty(*i))).map_err(|e| e.to_string())?;
            ltele.push((Rc::from(format!("j{i}").as_str()), Rel::Rel, t));
        }
        ltele.push((Rc::from("n"), Rel::Rel, lu.clone()));
        ltele.push((Rc::from("C"), Rel::Rel, opt_out.clone()));
        // hC's type at depth e0 + 2: Π m (.hm) k̄ c̄ (.ez : h p̄ = tuple(c̄)). Eq(run m X (sx c̄ w̄), C)
        let ncomp = comp_tys.len() as u32;
        let hc_ty = {
            let d_m = e0 + 2; // m bound here
            let hm_ty = le_int(self.env, mk::prim(PrimOp::ISub, vec![len_of(mk::var(d_m - e0)), hinfo.mu_int(&hinfo.params_at(d_m + 1))], vec![]), len_of(mk::var(0)));
            let nk = k_tys.len() as u32;
            let d_c = d_m + 2 + nk; // the first component's level
            let d_ez = d_c + ncomp;
            let comps_at = |dd: u32| -> Vec<Tm> { (0..ncomp).map(|i| mk::var(dd - 1 - (d_c + i))).collect() };
            let tup_at = |dd: u32| -> Tm {
                match &tuple {
                    Some((ind, params)) => Rc::new(Term::Ctor { ind: *ind, ctor: 0, params: params.clone(), args: comps_at(dd) }),
                    None => comps_at(dd)[0].clone(),
                }
            };
            let ez_ty = mk::eq(r_h.clone(), h_app_at(d_ez), tup_at(d_ez));
            let eb = d_ez + 1;
            let ks: Vec<Tm> = (0..nk).map(|i| mk::var(eb - 1 - (d_m + 2 + i))).collect();
            let mut st = sx.clone();
            for c in comps_at(eb) {
                st = mk::app(st, c);
            }
            let mut kk = 0;
            for wi in &w {
                st = mk::app(st, match wi {
                    Some(t) => shift(t, (eb - e0) as i64),
                    None => {
                        kk += 1;
                        ks[kk - 1].clone()
                    }
                });
            }
            let run_x = mk::apps(mk::global(run_g), vec![(Rel::Rel, mk::var(eb - 1 - d_m)), (Rel::Rel, blk(x_ctor)), (Rel::Rel, st)]);
            let mut body = mk::eq(opt_out.clone(), run_x, mk::var(eb - 1 - (e0 + 1)));
            body = mk::pi("ez", Rel::Irr, ez_ty, body);
            for (i, t) in comp_tys.iter().enumerate().rev() {
                body = mk::pi(&format!("c{i}"), Rel::Rel, t.clone(), body);
            }
            for (i, t) in k_tys.iter().enumerate().rev() {
                body = mk::pi(&format!("k{i}"), Rel::Rel, t.clone(), body);
            }
            body = mk::pi("hm", Rel::Irr, hm_ty, body);
            mk::pi("m", Rel::Rel, lu.clone(), body)
        };
        ltele.push((Rc::from("hC"), Rel::Rel, hc_ty));
        // the conclusion over (p̄, j̄, n, C, hC): depth e0 + 3
        let e3 = e0 + 3;
        let mut slots_h: Vec<Tm> = Vec::new();
        for (i, pt) in param_slot_tm.iter().enumerate() {
            slots_h.push(match pt {
                Some(t) => shift(t, (e3 - arity) as i64),
                None => {
                    let m = junk.iter().position(|j| *j == i).unwrap() as u32;
                    mk::var(e3 - 1 - (arity + m))
                }
            });
        }
        let st_h = Rc::new(Term::Ctor { ind: st_ind, ctor: 0, params: vec![], args: slots_h });
        let os = Rc::new(Term::Ctor { ind: opt, ctor: 1, params: vec![mk::ind(st_ind, vec![])], args: vec![st_h] });
        let l_tm = mk::apps(mk::global(run_g), vec![(Rel::Rel, mk::var(2)), (Rel::Rel, blk((2 * header) as u32)), (Rel::Rel, os)]);
        let prem = le_int(self.env, hinfo.mu_int(&hinfo.params_at(e3)), len_of(mk::var(2)));
        let concl = mk::eq(opt_out.clone(), shift(&l_tm, 1), mk::var(1 + 1));
        let mut lem_ty = mk::pi("hle", Rel::Irr, prem.clone(), concl);
        for (nm, r, d) in ltele.iter().rev() {
            lem_ty = mk::pi(nm, *r, d.clone(), lem_ty);
        }
        self.dump(&format!("wlem_{}_{header}.core", lf.id), &self.env.print_term(&[], &lem_ty));
        // the walk
        let erase_id = self.env.parse_term(&[], &format!("fun (yy : {}) => yy", lf.out_ty)).map_err(|e| e.to_string())?;
        let opaque = self.opaque(run_g);
        let mut wk = self.walker(out_tm.clone(), erase_id, vec![], e0, Some(RecCtx { helper: hinfo.clone() }), Some((sg, rels.clone())), opaque);
        wk.exit = Some(ExitMode { x_ctor, r_ty: r_h.clone(), sx: sx.clone(), comps: comp_tys.clone(), tuple: tuple.clone(), w: w.clone(), w_slots, e0, c_level: e0 + 1, hc_level: e0 + 2, k_tys: k_tys.clone(), eqs_level: None });
        wk.fname = format!("{h_global} (the `while` loop's lemma)");
        let mut ctx = Ctx::default();
        for (nm, r, d) in ltele.iter() {
            ctx = wk.push(&ctx, nm, *r, d, None)?;
        }
        let mut facts: Vec<Fact> = Vec::new();
        for lv in 0..arity {
            let en = &ctx.entries[lv as usize];
            if en.rel != Rel::Irr {
                continue;
            }
            let pre = Ctx { entries: Rc::new(ctx.entries[..lv as usize].to_vec()) };
            let ty = shift(&self.env.quote_typed(&pre, &en.ty, None, true), (e3 - lv) as i64);
            sigma_facts(mk::var(e3 - 1 - lv), &ty, &mut facts);
        }
        let inner = super::simproof::hashcons(&inline_prelude(self.env, &shift(&inner0, (e3 - arity) as i64), 4));
        let walked = wk.walk(&ctx, &Goal { l: l_tm.clone(), s: inner.clone(), ins: vec![], rhs: None, acc: None }, &facts).map_err(|e| format!("walk of `{h_global}` (the `while` loop's lemma): {e}"))?;
        let stats = format!("{:?}", wk.stats);
        drop(wk);
        // λ hle. walked hle (delta(h; p̄))
        let delta = Rc::new(Term::Delta { def: sg, args: hinfo.params_at(e3 + 1) });
        let mut proof = mk::lam("hle", Rel::Irr, prem, Rc::new(Term::App { rel: Rel::Irr, fun: Rc::new(Term::App { rel: Rel::Irr, fun: shift(&walked, 1), arg: mk::var(0) }), arg: delta }));
        for (nm, r, d) in ltele.iter().rev() {
            proof = mk::lam(nm, *r, d.clone(), proof);
        }
        let raw = crate::elab::tm::size(&proof);
        let proof = super::simproof::hashcons(&proof);
        let nodes = crate::elab::tm::size(&proof);
        let walk_secs = t0.elapsed().as_secs_f64();
        let t1 = Instant::now();
        let decl = DefDecl { name: Rc::from(format!("L::wlem::{}_{header}", lf.id).as_str()), kind: DefKind::Lemma, ty: lem_ty, body: proof, recursion: Recursion::Measure { measure: shift(&pc.measure, (nj + 4) as i64) }, arity: e0 + 4, opaque: false };
        let lem = self.add(decl, 40_000_000_000).map_err(|e| format!("the kernel rejected the `while` loop's lemma of `{h_global}`: {}", trunc(&e.to_string(), 3000)))?;
        self.whiles.push(WhileHelper { s_global: sg, lemma: lem, measure: pc.measure.clone(), width, nparams: arity, rels, header_ctor: (2 * header) as u32, junk });
        Ok(Proven { s_global: h_global.into(), kind: "loop lemma", walk_secs, check_secs: t1.elapsed().as_secs_f64(), nodes, stats: format!("{stats}; {raw} nodes before sharing") })
    }
}

/// The block a loop leaves to: the one successor of the loop's blocks (the
/// natural loop of `header`) outside it.
fn loop_exit(f: &super::ir::Fn, header: usize) -> Option<usize> {
    let n = f.blocks.len();
    let succ: Vec<Vec<usize>> = f.blocks.iter().map(|b| super::cfg::succs(&b.term)).collect();
    let mut reach = vec![false; n];
    let mut work = vec![header];
    while let Some(b) = work.pop() {
        if b < n && !reach[b] {
            reach[b] = true;
            work.extend(succ[b].iter().copied());
        }
    }
    let mut body = vec![false; n];
    body[header] = true;
    let mut work: Vec<usize> = (0..n).filter(|b| reach[*b] && succ[*b].contains(&header)).collect();
    while let Some(b) = work.pop() {
        if body[b] {
            continue;
        }
        body[b] = true;
        for (p, s) in succ.iter().enumerate() {
            if s.contains(&b) && !body[p] {
                work.push(p);
            }
        }
    }
    let mut exits: Vec<usize> = (0..n).filter(|b| body[*b]).flat_map(|b| succ[b].iter().copied()).filter(|s| !body[*s]).collect();
    // (a panic path is not an exit: blocks every path from which panics)
    exits.retain(|s| !panics_only(f, *s));
    exits.sort();
    exits.dedup();
    (exits.len() == 1).then(|| exits[0])
}

/// Whether every path from block `b` ends in a panic (or unreachable).
fn panics_only(f: &super::ir::Fn, b: usize) -> bool {
    use super::ir::{Callee, Term as T};
    let mut seen = vec![false; f.blocks.len()];
    fn go(f: &super::ir::Fn, b: usize, seen: &mut Vec<bool>) -> bool {
        if b >= f.blocks.len() || seen[b] {
            return true;
        }
        seen[b] = true;
        match &f.blocks[b].term {
            T::Return => false,
            T::Unreachable | T::Abort | T::Resume => true,
            T::Call(Callee::Diverge(_), ..) => true,
            t => super::cfg::succs(t).iter().all(|s| go(f, *s, seen)),
        }
    }
    let _ = &mut seen;
    go(f, b, &mut seen)
}

/// Facts from a proof `p` of `ty`: an equation, or the components of a
/// non-dependent pair of them (recursively).
fn sigma_facts(p: Tm, ty: &Tm, out: &mut Vec<Fact>) {
    match &**ty {
        Term::Eq { .. } => out.push(Fact { reused: true, ..Fact::eq(p, ty.clone()) }),
        Term::Sigma { fst, snd, .. } if count_free0(snd) => {
            sigma_facts(Rc::new(Term::Fst(p.clone())), fst, out);
            sigma_facts(Rc::new(Term::Snd(p)), &shift(snd, -1), out);
        }
        Term::Let { val, body, .. } => sigma_facts(p, &crate::elab::tm::subst0(body, val), out),
        _ => {}
    }
}

/// Whether a `Sigma`'s second component does not depend on the first.
fn count_free0(cod: &Tm) -> bool {
    let mut uses = false;
    crate::auto::util::map_term(cod, 0, &mut |x, d| {
        if matches!(&**x, Term::Var(sandblaster_kernel::term::Idx(i)) if *i == d) {
            uses = true;
        }
        None
    });
    !uses
}

/// The slots a loop's body assigns (the natural loop of `header`): locals
/// written by its statements or calls, and every cell when the body writes
/// through, or passes to a call, a reference derived from a `&mut`
/// parameter (conservatively: any cell).
fn loop_assigned(f: &super::ir::Fn, header: usize, lf: &LFn) -> std::collections::BTreeSet<usize> {
    use super::ir::{Operand, Proj, Rvalue, Stmt, Term as T, Ty};
    let n = f.blocks.len();
    let succ: Vec<Vec<usize>> = f.blocks.iter().map(|b| super::cfg::succs(&b.term)).collect();
    // reachable from the header
    let mut reach = vec![false; n];
    let mut work = vec![header];
    while let Some(b) = work.pop() {
        if b < n && !reach[b] {
            reach[b] = true;
            work.extend(succ[b].iter().copied());
        }
    }
    // the natural loop: the header and what reaches a back edge's source without it
    let mut body = vec![false; n];
    body[header] = true;
    let mut work: Vec<usize> = (0..n).filter(|b| reach[*b] && succ[*b].contains(&header)).collect();
    while let Some(b) = work.pop() {
        if body[b] {
            continue;
        }
        body[b] = true;
        for (p, s) in succ.iter().enumerate() {
            if s.contains(&b) && !body[p] {
                work.push(p);
            }
        }
    }
    let nl = lf.local_tys.len();
    // the locals that may hold a code of a cell: the `&mut` parameters and
    // what is copied or reborrowed from them
    let mut derived: std::collections::BTreeSet<usize> = lf.cells.iter().map(|c| c.param).collect();
    loop {
        let before = derived.len();
        for bl in &f.blocks {
            for st in &bl.stmts {
                if let Stmt::Assign(pl, rv, _) = st {
                    let from = match rv {
                        Rvalue::Ref(_, q) => Some(q.local),
                        Rvalue::Use(Operand::Copy(q) | Operand::Move(q)) => Some(q.local),
                        _ => None,
                    };
                    if from.is_some_and(|l| derived.contains(&l)) {
                        derived.insert(pl.local);
                    }
                }
            }
        }
        if derived.len() == before {
            break;
        }
    }
    let mut out = std::collections::BTreeSet::new();
    let mut cells = false;
    for (b, bl) in f.blocks.iter().enumerate() {
        if !body[b] {
            continue;
        }
        for st in &bl.stmts {
            if let Stmt::Assign(pl, rv, _) = st {
                out.insert(pl.local);
                if pl.proj.iter().any(|p| matches!(p, Proj::Deref)) && derived.contains(&pl.local) {
                    cells = true;
                }
                if let Rvalue::Ref(k, q) = rv
                    && k == "mut"
                {
                    out.insert(q.local);
                }
            }
        }
        if let T::Call(_, args, d, _) = &bl.term {
            out.insert(d.local);
            if d.proj.iter().any(|p| matches!(p, Proj::Deref)) && derived.contains(&d.local) {
                cells = true;
            }
            for a in args {
                if let Operand::Copy(p) | Operand::Move(p) = a
                    && matches!(f.locals.get(p.local).map(|l| &l.0), Some(Ty::Ref(true, _)))
                    && derived.contains(&p.local)
                {
                    cells = true;
                }
            }
        }
    }
    if cells {
        out.extend(nl..nl + lf.cells.len());
    }
    out
}

/// `t` with every full application of a transparent, non-recursive exec
/// function of the lift prelude (`crate::__lift::i16_neg`, `i16_shr`, ..)
/// replaced by its body (definitionally equal: a delta step and beta), so
/// that the walker splits on the tests inside it like on S's own; `let j =
/// v; j` is `v` (zeta). `depth` bounds nested unfolding.
fn inline_prelude(env: &Env, t: &Tm, depth: u32) -> Tm {
    if depth == 0 {
        return t.clone();
    }
    let mut changed = false;
    let r = crate::auto::util::map_term(t, 0, &mut |x, _| {
        let mut args: Vec<Tm> = Vec::new();
        let mut cur = x.clone();
        while let Term::App { fun, arg, .. } = &*cur {
            args.push(arg.clone());
            cur = fun.clone();
        }
        let Term::Global(g) = &*cur else { return None };
        if args.is_empty() || !env.global_name(*g).is_some_and(|n| n.starts_with("crate::__lift::")) || env.global_opaque(*g) != Some(false) || env.global_kind(*g) != Some(DefKind::Exec) || env.global_arity(*g) != Some(args.len() as u32) {
            return None;
        }
        let body = env.global_body(*g)?;
        let mut recursive = false;
        crate::auto::util::map_term(&body, 0, &mut |y, _| {
            if matches!(&**y, Term::Rec { .. }) {
                recursive = true;
            }
            None
        });
        if recursive {
            return None;
        }
        // (a helper that cases on an argument of several constructors, the
        // lift's `ord_le` on an `Option`, is kept a call: inlined, its match
        // would scrutinize the caller's own split value inside S's idioms)
        let nargs = args.len() as u32;
        let mut inner = body.clone();
        for _ in 0..nargs {
            let Term::Lam { body: b, .. } = &*inner else { break };
            inner = b.clone();
        }
        let mut cases_on_arg = false;
        crate::auto::util::map_term(&inner, 0, &mut |y, d| {
            if let Term::Match { ind, scrut, .. } = &**y
                && matches!(&**scrut, Term::Var(sandblaster_kernel::term::Idx(i)) if *i >= d && *i < d + nargs)
                && env.inductive_decl(*ind).is_some_and(|dc| dc.ctors.len() > 1)
            {
                cases_on_arg = true;
            }
            None
        });
        if cases_on_arg {
            return None;
        }
        args.reverse();
        let mut b = body;
        for a in &args {
            let Term::Lam { body: inner, .. } = &*b else { return None };
            b = crate::elab::tm::subst0(inner, a);
        }
        if let Term::Let { val, body, .. } = &*b
            && matches!(&**body, Term::Var(sandblaster_kernel::term::Idx(0)))
        {
            b = val.clone();
        }
        changed = true;
        Some(b)
    });
    if changed { inline_prelude(env, &r, depth - 1) } else { r }
}

fn trunc(s: &str, n: usize) -> String {
    if s.len() > n { format!("{}..", &s[..s.char_indices().nth(n).map(|c| c.0).unwrap_or(s.len())]) } else { s.to_string() }
}

/// Whether `t` has no free variables.
fn closed(t: &Tm) -> bool {
    let mut free = false;
    crate::auto::util::map_term(t, 0, &mut |x, d| {
        if let Term::Var(sandblaster_kernel::term::Idx(i)) = &**x
            && *i >= d
        {
            free = true;
        }
        None
    });
    !free
}

fn le_int(env: &Env, a: Tm, b: Tm) -> Tm {
    mk::eq_bool(env.bool_ind(), mk::prim(PrimOp::Le(Width::Int), vec![a, b], vec![]), true)
}

/// `erase` of a helper's structured result (states.., ret) over `@Y@` (the
/// same component-wise erasure as the statement's).
fn erase_out(g: &mut Gen<'_>, env: &Env, f: &super::ir::Fn, lf: &LFn) -> Result<String, String> {
    let mut tys: Vec<Ty> = lf.cells.iter().filter(|c| c.parent.is_none()).map(|c| c.mir_ty.clone()).collect();
    if !matches!(f.locals[0].0, Ty::Unit) && !matches!(&f.locals[0].0, Ty::Tuple(v) if v.is_empty()) {
        tys.push(f.locals[0].0.clone());
    }
    let parts = &lf.out_parts;
    Ok(match tys.len() {
        0 => "tt".to_string(),
        1 => stmt::erase(g, env, &tys[0], "@Y@")?,
        n => {
            let ys: Vec<String> = (0..n).map(|i| format!("y{i}")).collect();
            let es: Vec<String> = tys.iter().enumerate().map(|(i, t)| stmt::erase(g, env, t, &ys[i])).collect::<Result<_, _>>()?;
            format!("(match @Y@ : @SRET@ as _ return {} with | tuple{n}({}) => tuple{n}[{}]({}) end)", lf.out_ty, ys.join(", "), parts.join(", "), es.join(", "))
        }
    })
}

/// Elaborates only what the literal reading names (the type declarations,
/// the lift's models and preludes, the host models): enough to load the
/// literal reading of every instance (`items`: more items to include).
pub fn elaborate_names(krate: &crate::hir::Crate, extra: &[String]) -> crate::elab::Output {
    let mut filter = std::collections::BTreeSet::new();
    let mut work = Vec::new();
    for it in &krate.items {
        let full = it.path.0.join("::");
        let keep = matches!(it.kind, crate::hir::ItemKind::Struct(_) | crate::hir::ItemKind::Enum(_))
            || full.starts_with("__lift")
            || full.split("::").any(|s| s == "host")
            || extra.iter().any(|n| match n.strip_prefix('^') { Some(pre) => full.starts_with(pre), None => full.ends_with(n.as_str()) });
        if keep {
            work.push(it.id);
        }
    }
    while let Some(x) = work.pop() {
        if filter.insert(x) {
            work.extend(crate::elab::order::refs(krate, x));
        }
    }
    let opts = crate::elab::Options { items: Some(std::sync::Arc::new(filter)), ..crate::elab::Options::default() };
    let mut chain = crate::elab::ProverChain::standard();
    crate::elab::elaborate(krate, &mut chain, &opts)
}

/// Per-function summary of a literal reading (constructs read as `None`).
pub fn faults(lit: &Literal) -> BTreeMap<String, Vec<String>> {
    lit.state.fns.iter().filter(|(_, f)| !f.faults.is_empty()).map(|(k, f)| (k.clone(), f.faults.clone())).collect()
}

// ----- the module's theorems (the gate, amendment (e)) -----------------------

/// One theorem to prove for a module, with what it needs proven first.
#[derive(Clone, Debug)]
pub struct Planned {
    pub entry: Entry,
    /// The lifted function (or loop helper) it is about.
    pub global: String,
    /// Its MIR instance.
    pub key: String,
    /// The entries (indices into the plan) whose lemmas its walk uses: the
    /// lifted functions its MIR calls (directly or through library code),
    /// and its own loop helpers.
    pub needs: Vec<usize>,
    /// A function's theorem (the gate's subject); else a loop lemma.
    pub is_fn: bool,
}

impl Planned {
    /// `theorem`, `loop lemma` or `model lemma`.
    pub fn kind(&self) -> &'static str {
        match self.entry {
            _ if self.is_fn => "theorem",
            Entry::Model { .. } => "model lemma",
            _ => "loop lemma",
        }
    }
}

/// The lifted functions a MIR instance calls, directly or through
/// functions that are not lifted (whose literal reading is unfolded).
fn lifted_callees(m: &Sbmir, key: &str, lifted: &std::collections::BTreeSet<String>) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut work = vec![key.to_string()];
    while let Some(k) = work.pop() {
        let Some(f) = m.fns.get(&k) else { continue };
        for b in &f.blocks {
            if let super::ir::Term::Call(super::ir::Callee::Fn(k2), ..) = &b.term {
                if k2 == key || !seen.insert(k2.clone()) {
                    continue;
                }
                if lifted.contains(k2) {
                    out.push(k2.clone());
                } else {
                    work.push(k2.clone());
                }
            }
        }
    }
    out.sort();
    out
}

/// The theorems of every lifted function of `m` read from MIR (and the loop
/// lemmas of their helpers), in dependency order: callees, then a
/// function's loop helpers (innermost first), then the function. Errors:
/// lifted functions that cannot be planned (mutual recursion), and why.
pub fn plan(m: &Sbmir, lit: &Literal, contracts: &[MirContract], helpers: &[crate::lift::MirHelper]) -> (Vec<Planned>, Vec<(String, String, String)>) {
    let ours: Vec<&MirContract> = contracts.iter().filter(|c| m.fns.contains_key(&c.key)).collect();
    let lifted: std::collections::BTreeSet<String> = ours.iter().map(|c| c.key.clone()).collect();
    let deps: BTreeMap<String, Vec<String>> = lifted.iter().map(|k| (k.clone(), lifted_callees(m, k, &lifted))).collect();
    // post-order DFS (0 new, 1 on the stack, 2 done)
    let mut state: BTreeMap<String, u8> = BTreeMap::new();
    let mut order: Vec<String> = Vec::new();
    let mut errors = Vec::new();
    fn visit(k: &str, deps: &BTreeMap<String, Vec<String>>, state: &mut BTreeMap<String, u8>, order: &mut Vec<String>, cyc: &mut Vec<String>) {
        match state.get(k).copied().unwrap_or(0) {
            2 => return,
            1 => {
                cyc.push(k.to_string());
                return;
            }
            _ => {}
        }
        state.insert(k.to_string(), 1);
        for d in deps.get(k).into_iter().flatten() {
            visit(d, deps, state, order, cyc);
        }
        state.insert(k.to_string(), 2);
        order.push(k.to_string());
    }
    let mut cyc = Vec::new();
    for k in &lifted {
        visit(k, &deps, &mut state, &mut order, &mut cyc);
    }
    let cyclic: std::collections::BTreeSet<String> = cyc.into_iter().collect();
    let mut out: Vec<Planned> = Vec::new();
    let mut fn_idx: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    // the model lemmas of the library functions the lifted functions run
    let mut model_idx: BTreeMap<String, usize> = BTreeMap::new();
    for k in &order {
        for k2 in mir_closure(m, k) {
            if let Some((_, g)) = MODELS.iter().find(|(mk, _)| *mk == k2)
                && lit.lfn(&k2).is_some()
                && !model_idx.contains_key(&k2)
            {
                out.push(Planned { entry: Entry::Model { key: k2.clone(), s_global: g.to_string() }, global: g.to_string(), key: k2.clone(), needs: vec![], is_fn: false });
                model_idx.insert(k2.clone(), out.len() - 1);
            }
        }
    }
    for k in &order {
        let cs: Vec<&&MirContract> = ours.iter().filter(|c| &c.key == k).collect();
        if cyclic.contains(k) {
            for c in cs {
                errors.push((c.global.clone(), k.clone(), "its MIR is mutually recursive with another lifted function's (the literal reading does not read mutual recursion)".to_string()));
            }
            continue;
        }
        let mut dep_idx: Vec<usize> = deps[k].iter().flat_map(|d| fn_idx.get(d).cloned().unwrap_or_default()).collect();
        dep_idx.extend(mir_closure(m, k).iter().filter_map(|k2| model_idx.get(k2).copied()));
        let mut own: Vec<usize> = Vec::new();
        // (a `while` loop's lemma: its helper's, independent of the rest of the function)
        for h in helpers.iter().filter(|h| &h.key == k && h.while_loop) {
            let mut needs = dep_idx.clone();
            needs.extend(own.iter().copied());
            out.push(Planned { entry: Entry::While { key: k.clone(), s_global: h.global.clone(), header: h.header, local_names: h.local_names.clone() }, global: h.global.clone(), key: k.clone(), needs, is_fn: false });
            own.push(out.len() - 1);
        }
        for h in helpers.iter().filter(|h| &h.key == k && !h.while_loop) {
            let slots = match lit.lfn(k) {
                Some(lf) => helper_slots(lf, &h.params),
                None => vec![],
            };
            let mut needs = dep_idx.clone();
            needs.extend(own.iter().copied());
            out.push(Planned { entry: Entry::Helper { key: k.clone(), s_global: h.global.clone(), header: h.header, slots }, global: h.global.clone(), key: k.clone(), needs, is_fn: false });
            own.push(out.len() - 1);
        }
        for c in cs {
            let mut needs = dep_idx.clone();
            needs.extend(own.iter().copied());
            out.push(Planned { entry: Entry::Fn { key: k.clone(), s_global: c.global.clone() }, global: c.global.clone(), key: k.clone(), needs, is_fn: true });
            fn_idx.entry(k.clone()).or_default().push(out.len() - 1);
        }
    }
    (out, errors)
}

/// The slots a loop helper's parameters occupy at the header: a `&mut`
/// parameter's referent is its cell (`c<j>`) and the parameter's own slot
/// holds the cell's code; any other is the local's slot.
fn helper_slots(lf: &LFn, params: &[usize]) -> Vec<(String, String)> {
    let mut slots = Vec::new();
    for (i, l) in params.iter().enumerate() {
        match lf.cells.iter().position(|c| c.param == *l && c.parent.is_none()) {
            Some(j) => {
                slots.push((format!("c{j}"), format!("p{i}")));
                slots.push((format!("l{l}"), "code".to_string()));
            }
            None => slots.push((format!("l{l}"), format!("p{i}"))),
        }
    }
    slots
}

/// The outcome of one planned theorem.
#[derive(Clone, Debug)]
pub struct Outcome {
    pub global: String,
    pub key: String,
    pub is_fn: bool,
    /// `theorem`, `loop lemma` or `model lemma`.
    pub kind: &'static str,
    /// Proven now (`Ok`), or why not.
    pub result: Result<Proven, String>,
    /// Accepted from the verdict cache (not walked or checked again).
    pub cached: bool,
}

/// The theorems of one lifted MIR module.
#[derive(Clone, Debug, Default)]
pub struct ModuleTheorems {
    /// The DSL module (`crate::varint`).
    pub dsl: String,
    pub outcomes: Vec<Outcome>,
    /// Lifted functions without a theorem, and why (planning, the literal
    /// reading, or their walk).
    pub missing: Vec<(String, String)>,
    /// The literal reading: functions, kernel items, its generation and
    /// check time.
    pub literal_fns: usize,
    pub literal_items: usize,
    pub literal_secs: f64,
    pub secs: f64,
    /// Verdict-cache entries whose declarations the kernel did not accept
    /// (the module was then walked without the cache), and why.
    pub rejected: Vec<(String, String)>,
}

impl ModuleTheorems {
    /// The lifted functions whose theorem is kernel-checked (now or cached).
    pub fn proven(&self) -> usize {
        self.outcomes.iter().filter(|o| o.is_fn && o.result.is_ok()).count()
    }
    pub fn functions(&self) -> usize {
        self.outcomes.iter().filter(|o| o.is_fn).count() + self.missing.iter().filter(|(g, _)| !self.outcomes.iter().any(|o| o.is_fn && &o.global == g)).count()
    }
    pub fn cached(&self) -> usize {
        self.outcomes.iter().filter(|o| o.is_fn && o.cached).count()
    }
}

/// How the gate proves: the per-function budget, and the verdict cache.
pub struct GateOptions<'a> {
    pub budget_secs: f64,
    pub max_steps: usize,
    pub cache: Option<&'a crate::driver::cache::VerdictCache>,
    /// Trace the walks (debugging).
    pub trace: bool,
    /// Prove only the planned entries whose global contains this text, and
    /// what their walks need (debugging; the others are reported as skipped).
    pub only: Option<String>,
    /// MIR instances whose lemmas a later step needs (the lifted round
    /// trip's copies call them): walked even when their theorem is cached.
    pub keep_keys: Vec<String>,
    /// Read and prove only these instances (the round trip's lemmas when no
    /// gate ran before it; every other theorem is skipped, not proven).
    pub restrict_keys: Option<Vec<String>>,
    /// Test hook: theorem cache keys leave out the MIR, so an entry stored
    /// for another MIR is served (a stale entry, which the kernel and the
    /// trusted check must refuse).
    pub key_ignores_mir: bool,
}

impl Default for GateOptions<'_> {
    fn default() -> Self {
        GateOptions { budget_secs: 120.0, max_steps: 2_000_000, cache: None, trace: false, only: None, keep_keys: Vec::new(), restrict_keys: None, key_ignores_mir: false }
    }
}

/// The identity of the literal reading's generator and library (amendment
/// (g)): the trusted generator, the statement generator, the names and the
/// parse it reads, `literal.core`, and `cfg.rs` (the untrusted shape facts
/// the generator places fuel by: a change there changes L's text).
pub(crate) fn generator_hash() -> String {
    let mut t = String::from("sandblaster-mir-theorem-generator/1\n");
    for (n, s) in [("literal.rs", include_str!("literal.rs")), ("stmt.rs", include_str!("stmt.rs")), ("mod.rs", include_str!("mod.rs")), ("ir.rs", include_str!("ir.rs")), ("sexp.rs", include_str!("sexp.rs")), ("literal.core", super::literal::LIBRARY), ("cfg.rs", include_str!("cfg.rs"))] {
        t.push_str(&format!("{n} {}\n", crate::surface::hex(&crate::surface::sha256(s.as_bytes()))));
    }
    crate::surface::hex(&crate::surface::sha256(t.as_bytes()))
}

/// Content hashes of definitions (the structured reading and what it refers
/// to), memoized per global.
struct Hasher<'e> {
    env: &'e Env,
    memo: std::collections::HashMap<GlobalId, String>,
}

impl Hasher<'_> {
    /// The hash of `g`'s definition and every definition and inductive it
    /// reaches (types and bodies, `Env::refs_closure`).
    fn closure(&mut self, g: GlobalId) -> String {
        let mut closure = self.env.refs_closure(&mk::global(g), &[]);
        if !closure.contains(&g) {
            closure.push(g);
        }
        closure.sort();
        let mut t = String::new();
        for h in closure {
            let d = self.one(h);
            t.push_str(&d);
            t.push('\n');
        }
        crate::surface::hex(&crate::surface::sha256(t.as_bytes()))
    }

    fn one(&mut self, g: GlobalId) -> String {
        if let Some(h) = self.memo.get(&g) {
            return h.clone();
        }
        let env = self.env;
        let mut t = format!("{} {:?} {:?}\n", env.global_name(g).map(|n| n.to_string()).unwrap_or_default(), env.global_kind(g), env.global_opaque(g));
        let mut inds = std::collections::BTreeSet::new();
        for x in [env.global_type(g), env.global_body(g)].into_iter().flatten() {
            t.push_str(&env.print_term(&[], &x));
            t.push('\n');
            crate::auto::util::map_term(&x, 0, &mut |y, _| {
                if let Term::Ind { ind, .. } | Term::Ctor { ind, .. } | Term::Match { ind, .. } = &**y {
                    inds.insert(ind.0);
                }
                None
            });
        }
        for i in inds {
            t.push_str(&env.print_inductive(sandblaster_kernel::term::IndId(i)).unwrap_or_default());
            t.push('\n');
        }
        let h = crate::surface::hex(&crate::surface::sha256(t.as_bytes()));
        self.memo.insert(g, h.clone());
        h
    }
}

/// The MIR instances a function's literal reading runs (itself and what it
/// calls, transitively).
pub(crate) use super::gate::closure as mir_closure;

/// The verdict-cache key of a planned theorem (amendment (g)): the
/// toolchain, the generator and library, the statement's inputs (the
/// structured reading of the function and of everything it refers to; its
/// type carries the declared contract), the MIR text of the instance and of every instance
/// its literal reading runs with the names L gave them, the names the
/// reading uses, and for a loop lemma the header and the slots. (Untrusted:
/// a wrong key replays declarations the kernel and the trusted check refuse.)
fn cache_key(vc: &crate::driver::cache::VerdictCache, gen_id: &str, h: &mut Hasher<'_>, (m, names, lit): (&Sbmir, &ModuleNames, &Literal), p: &Planned, with_mir: bool) -> Option<String> {
    let g = h.env.lookup_global(&p.global)?;
    let mut t = format!("sandblaster-mir-theorem/2\ntoolchain {}\ngenerator {gen_id}\n", vc.toolchain);
    t.push_str(&format!("entry {:?}\n", p.entry));
    t.push_str(&format!("structured {}\n", h.closure(g)));
    for k in mir_closure(m, &p.key) {
        let text = m.fns.get(&k).filter(|_| with_mir).map(|f| format!("{f:?}")).unwrap_or_else(|| "absent".into());
        let id = lit.lfn(&k).map(|f| f.id.as_str()).unwrap_or("-");
        t.push_str(&format!("mir {k} {id} {}\n", crate::surface::hex(&crate::surface::sha256(text.as_bytes()))));
    }
    let adts = format!("{:?}", m.adts);
    t.push_str(&format!("adts {}\n", crate::surface::hex(&crate::surface::sha256(adts.as_bytes()))));
    let nm = format!("{names:?}");
    t.push_str(&format!("names {}\n", crate::surface::hex(&crate::surface::sha256(nm.as_bytes()))));
    Some(crate::surface::hex(&crate::surface::sha256(t.as_bytes())))
}

/// The namespace of theorem entries in the verdict cache: each holds the
/// declarations a proof added (`proof`, [`crate::opt::cache::encode_decls`]).
pub const CACHE_NS: &str = "theorem";

/// The stored declarations under `key`, if any.
fn cached_entry(cache: Option<&crate::driver::cache::VerdictCache>, key: Option<&str>) -> Option<Vec<u8>> {
    let crate::driver::cache::Lookup::Hit(files) = cache?.store.get(CACHE_NS, key?) else { return None };
    let hex = files.into_iter().find(|f| f.0 == "proof")?.1;
    (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok()).collect()
}

/// A cache entry of the declarations `decls`.
fn cache_entry(env: &Env, key: &str, decls: &[DefDecl]) -> (String, Vec<(String, String)>) {
    (key.to_string(), vec![("proof".to_string(), crate::surface::hex(&crate::opt::cache::encode_decls(env, decls)))])
}

/// What the theorem gate read and proved in an environment: the trusted
/// record of its literal readings ([`super::gate::Ledger`]) and, per MIR
/// module (by its `.sbmir` name), the callee lemmas the lifted round trip's
/// theorems continue from ([`prove_roundtrip`]).
#[derive(Default)]
pub struct GateMemory {
    pub ledger: Ledger,
    pub callees: BTreeMap<String, Vec<Callee>>,
    /// The lifted round trip's theorems of the shipped code, as notes
    /// (`driver::lowered`).
    pub shipped: Vec<String>,
}

/// [`prove_lifted`], then the trusted check ([`Ledger::verdicts`]) folded
/// into the reports ([`annotate`]).
pub fn prove_and_check(out: &mut crate::elab::Output, krate: &crate::hir::Crate, facts: &crate::lift::LiftFacts, opts: &GateOptions<'_>) -> Vec<ModuleTheorems> {
    let mut reps = prove_lifted(out, facts, opts);
    let verdicts = out.mir_gate.ledger.verdicts(&out.env, krate, facts);
    annotate(&mut reps, &verdicts);
    reps
}

/// Reports a theorem the walk proved but the trusted check refused as
/// missing, with the check's reason.
pub fn annotate(reps: &mut [ModuleTheorems], verdicts: &[Verdict]) {
    for v in verdicts {
        let Err(e) = &v.result else { continue };
        let why = format!("refused by the trusted check: {e}");
        for r in reps.iter_mut() {
            if let Some(o) = r.outcomes.iter_mut().find(|o| o.is_fn && o.global == v.global && o.key == v.key && o.result.is_ok()) {
                o.result = Err(why.clone());
                r.missing.push((v.global.clone(), why.clone()));
            }
        }
    }
}

/// Proves the theorem of every lifted exec function read from MIR, per
/// lifted MIR module, into `out`'s environment (the very structured reading
/// the laws and proofs are about): the literal reading is generated and
/// kernel-checked through the trusted loader, then each planned theorem is
/// walked and kernel-checked in dependency order, or replayed from the
/// verdict cache (its declarations checked by the kernel again) when no
/// walk needs its lemma. What was proven is decided by the trusted check
/// ([`prove_and_check`], `driver::gates::theorem_gate`).
pub fn prove_lifted(out: &mut crate::elab::Output, facts: &crate::lift::LiftFacts, opts: &GateOptions<'_>) -> Vec<ModuleTheorems> {
    let mut reports = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let gen_id = generator_hash();
    for mm in &facts.mir_loaded {
        // (several lifted modules of one extraction share its MIR)
        if !seen.insert(mm.loaded.m.module.clone()) {
            continue;
        }
        let t0 = Instant::now();
        let (m, names) = (&mm.loaded.m, &mm.loaded.names);
        let mut rep = ModuleTheorems { dsl: mm.dsl.clone(), ..Default::default() };
        let ours: Vec<&MirContract> = facts.mir_contracts.iter().filter(|c| m.fns.contains_key(&c.key)).collect();
        if ours.is_empty() {
            continue;
        }
        let keys: Vec<String> = ours.iter().map(|c| c.key.clone()).filter(|k| opts.restrict_keys.as_ref().is_none_or(|r| r.contains(k))).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
        // (restricted to nothing: nothing to read or prove here)
        if keys.is_empty() {
            out.mir_gate.callees.insert(m.module.clone(), Vec::new());
            continue;
        }
        let lit = match load_into(&mut out.mir_gate.ledger, &mut out.env, m, names, &keys, None) {
            Ok(l) => l,
            Err(e) => {
                for c in &ours {
                    rep.missing.push((c.global.clone(), format!("the literal reading of the module was not accepted: {e}")));
                }
                rep.secs = t0.elapsed().as_secs_f64();
                reports.push(rep);
                continue;
            }
        };
        rep.literal_fns = lit.state.fns.len();
        rep.literal_items = lit.items;
        rep.literal_secs = lit.check_secs;
        let (plan, errors) = plan(m, &lit, &facts.mir_contracts, &facts.mir_helpers);
        let keys_c: Vec<Option<String>> = match opts.cache {
            Some(vc) => {
                let mut h = Hasher { env: &out.env, memo: Default::default() };
                plan.iter().map(|p| cache_key(vc, &gen_id, &mut h, (m, names, &lit), p, !opts.key_ignores_mir)).collect()
            }
            None => vec![None; plan.len()],
        };
        let stored: Vec<Option<Vec<u8>>> = keys_c.iter().map(|k| cached_entry(opts.cache, k.as_deref())).collect();
        let (mut outcomes, mut callees, rejected) = prove_module(out, (m, names, &lit, facts), opts, &plan, &stored, &keys_c);
        // (a stored entry the kernel did not accept: the module again, walked)
        if rejected {
            rep.rejected = outcomes.iter().filter_map(|o| o.result.as_ref().err().filter(|e| e.starts_with("its verdict-cache entry")).map(|e| (o.global.clone(), e.clone()))).collect();
            (outcomes, callees, _) = prove_module(out, (m, names, &lit, facts), opts, &plan, &vec![None; plan.len()], &keys_c);
        }
        out.mir_gate.callees.insert(m.module.clone(), callees);
        rep.missing.extend(errors.into_iter().map(|(g, _, why)| (g, why)));
        rep.missing.extend(outcomes.iter().filter(|o| o.is_fn).filter_map(|o| o.result.as_ref().err().map(|e| (o.global.clone(), e.clone()))));
        rep.outcomes = outcomes;
        rep.secs = t0.elapsed().as_secs_f64();
        reports.push(rep);
    }
    reports
}

/// One pass over a module's plan: an entry selected (by `opts.only` and
/// `opts.restrict_keys`) is replayed from `stored` unless a walk needs its
/// lemma (the walker's own record of it), else walked; the others are
/// skipped. The outcomes, the callee lemmas, and whether a stored entry
/// was not accepted.
fn prove_module(out: &mut crate::elab::Output, (m, names, lit, facts): (&Sbmir, &ModuleNames, &Literal, &crate::lift::LiftFacts), opts: &GateOptions<'_>, plan: &[Planned], stored: &[Option<Vec<u8>>], keys_c: &[Option<String>]) -> (Vec<Outcome>, Vec<Callee>, bool) {
    let n = plan.len();
    let selected: Vec<bool> = plan
        .iter()
        .map(|p| match (&opts.only, &opts.restrict_keys) {
            (Some(o), _) => p.global.contains(o.as_str()),
            (None, Some(r)) => r.contains(&p.key),
            (None, None) => true,
        })
        .collect();
    let mut walk: Vec<bool> = (0..n).map(|i| (selected[i] && stored[i].is_none()) || opts.keep_keys.contains(&plan[i].key)).collect();
    for i in (0..n).rev() {
        if walk[i] {
            for &j in &plan[i].needs {
                walk[j] = true;
            }
        }
    }
    let mut pv = Prover::new(&mut out.env, m, names, lit, &out.pre_commit, &facts.mir_contracts);
    pv.budget_secs = opts.budget_secs;
    pv.max_steps = opts.max_steps;
    pv.trace = opts.trace;
    let (mut failed, mut outcomes, mut stores, mut rejected) = (vec![false; n], Vec::new(), Vec::new(), false);
    for (i, p) in plan.iter().enumerate() {
        let replay = !walk[i] && selected[i] && stored[i].is_some();
        if !walk[i] && !replay {
            continue;
        }
        let t = Instant::now();
        // a theorem whose walk needs a lemma that failed is not attempted
        // (a model lemma that failed blocks nothing: the walk then reads
        // the library function's literal run as it is)
        let result = match p.needs.iter().find(|&&j| failed[j] && !matches!(plan[j].entry, Entry::Model { .. })) {
            Some(&j) => Err(format!("not attempted: its walk needs the {} of `{}`, which was not proven", plan[j].kind(), plan[j].global)),
            None if replay => match crate::opt::cache::replay_decls(pv.env, stored[i].as_deref().unwrap_or_default()) {
                Ok(()) => Ok(Proven { s_global: p.global.clone(), kind: p.kind(), walk_secs: 0.0, check_secs: t.elapsed().as_secs_f64(), nodes: 0, stats: "cached".into() }),
                Err(e) => {
                    rejected = true;
                    Err(format!("its verdict-cache entry was not accepted: {e}"))
                }
            },
            None if lit.lfn(&p.key).is_none() => Err(lit.refused.iter().find(|(k, _)| k == &p.key).map(|(_, e)| format!("the literal reading refused its MIR: {e}")).unwrap_or_else(|| "no literal reading of its MIR".into())),
            None => pv.prove(&p.entry),
        };
        let decls = std::mem::take(&mut pv.added);
        failed[i] = result.is_err();
        if let (Ok(_), false, Some(k)) = (&result, replay, &keys_c[i]) {
            stores.push(cache_entry(pv.env, k, &decls));
        }
        outcomes.push(Outcome { global: p.global.clone(), key: p.key.clone(), is_fn: p.is_fn, kind: p.kind(), result, cached: replay });
    }
    let callees = pv.callees.clone();
    if let Some(vc) = opts.cache
        && !stores.is_empty()
    {
        let _ = vc.store.put_many(CACHE_NS, &stores);
    }
    (outcomes, callees, rejected)
}

/// One function the optimizer replaced in a lifted file whose MIR the
/// build ships (the lifted round trip's copy, step 8 of
/// `docs/checked-structuring.md`).
#[derive(Clone, Debug)]
pub struct RoundTripFn {
    /// The source function and its replacement (kernel names).
    pub source: String,
    pub target: String,
    /// The check copy's MIR instance in the round trip's extraction (its
    /// text is what the emitted file holds under the source's name).
    pub copy_key: String,
    /// A per-type dispatch: the MIR instance of the dispatch impl method at
    /// this instance's type, which the copy calls and which delegates to
    /// the replacement.
    pub dispatch_key: Option<String>,
    /// The helpers' MIR instances and the verified definitions the round
    /// trip compared them with.
    pub helpers: Vec<(String, String)>,
    /// The optimizer's link `Π x̄ h̄. Eq(R, source x̄ h̄, target x̄ h̄)`
    /// (`None`: the replacement is the source function's own definition).
    pub equiv: Option<String>,
}

/// The theorems of one replaced function: its helpers', its copy's, and the
/// shipped code's theorem against the source function.
#[derive(Clone, Debug)]
pub struct RoundTripOutcome {
    pub source: String,
    pub result: Result<Vec<(String, Proven)>, String>,
}

/// The theorems of the shipped code of the replaced functions `fns`
/// (step 8): the literal reading of the round trip's MIR `rt` continues the
/// gate's reading of `main_module` (through the trusted loader), every
/// helper gets its theorem against the definition the round trip compared
/// it with, each copy its theorem against the replacement, and from it,
/// along the optimizer's link, the theorem against the source function
/// ([`Prover::compose`]). A function whose declarations the verdict cache
/// holds is replayed (the kernel checks them again). Whether the shipped
/// theorem holds is decided by [`Ledger::accept_shipped`]
/// (`driver::lowered`).
pub fn prove_roundtrip(out: &mut crate::elab::Output, facts: &crate::lift::LiftFacts, main_module: &str, rt: &Sbmir, fns: &[RoundTripFn], opts: &GateOptions<'_>) -> Vec<RoundTripOutcome> {
    let fail_all = |e: String| fns.iter().map(|f| RoundTripOutcome { source: f.source.clone(), result: Err(e.clone()) }).collect::<Vec<_>>();
    let Some(mm) = facts.mir_loaded.iter().find(|mm| mm.loaded.m.module == main_module) else { return fail_all(format!("no MIR module `{main_module}` was loaded")) };
    // (the gate runs before the lowering in every build; a lowering on its
    // own runs it here first)
    let mut why_not = String::new();
    if !out.mir_gate.callees.contains_key(main_module) {
        let keep: Vec<String> = fns.iter().flat_map(|f| mir_closure(rt, &f.copy_key)).collect();
        let reps = prove_lifted(out, facts, &GateOptions { keep_keys: keep.clone(), restrict_keys: Some(keep), ..GateOptions::default() });
        why_not = match reps.iter().find_map(|r| r.missing.first()) {
            Some((g, e)) => format!(" (`{g}`: {})", trunc(e, 300)),
            None if reps.is_empty() => " (no lifted function of the module is read from MIR)".into(),
            None => String::new(),
        };
    }
    let Some(callees) = out.mir_gate.callees.get(main_module).cloned() else { return fail_all(format!("the theorem gate did not read this module's MIR{why_not}")) };
    let mut keys: Vec<String> = fns.iter().flat_map(|f| f.helpers.iter().map(|h| h.0.clone()).chain(f.dispatch_key.clone()).chain(std::iter::once(f.copy_key.clone()))).collect();
    keys.sort();
    keys.dedup();
    let lit = match load_into(&mut out.mir_gate.ledger, &mut out.env, rt, &mm.loaded.names, &keys, None) {
        Ok(l) => l,
        Err(e) => return fail_all(format!("the literal reading of the round trip's MIR: {e}")),
    };
    let keys_c: Vec<Option<String>> = match opts.cache {
        Some(vc) => {
            let mut h = Hasher { env: &out.env, memo: Default::default() };
            fns.iter().map(|f| roundtrip_key(vc, &generator_hash(), &mut h, rt, f)).collect()
        }
        None => vec![None; fns.len()],
    };
    let mut outs: Vec<Option<RoundTripOutcome>> = vec![None; fns.len()];
    for (i, f) in fns.iter().enumerate() {
        if let Some(b) = cached_entry(opts.cache, keys_c[i].as_deref())
            && crate::opt::cache::replay_decls(&mut out.env, &b).is_ok()
        {
            outs[i] = Some(RoundTripOutcome { source: f.source.clone(), result: Ok(vec![(f.copy_key.clone(), Proven { s_global: f.source.clone(), kind: "shipped theorem", walk_secs: 0.0, check_secs: 0.0, nodes: 0, stats: "cached".into() })]) });
        }
    }
    let todo: Vec<RoundTripFn> = fns.iter().zip(&outs).filter(|(_, o)| o.is_none()).map(|(f, _)| f.clone()).collect();
    let mut proven = if todo.is_empty() { Vec::new() } else { prove_roundtrip_now(out, facts, &mm.loaded.names, rt, &lit, callees, &todo, opts) }.into_iter();
    let mut stores = Vec::new();
    for (i, f) in fns.iter().enumerate() {
        if outs[i].is_some() {
            continue;
        }
        let (o, decls) = proven.next().unwrap_or_else(|| (RoundTripOutcome { source: f.source.clone(), result: Err("not proven".into()) }, Vec::new()));
        if let (Ok(_), Some(k)) = (&o.result, &keys_c[i]) {
            stores.push(cache_entry(&out.env, k, &decls));
        }
        outs[i] = Some(o);
    }
    if let Some(vc) = opts.cache
        && !stores.is_empty()
    {
        let _ = vc.store.put_many(CACHE_NS, &stores);
    }
    outs.into_iter().flatten().collect()
}

/// The verdict-cache key of a function's shipped theorems: the generator,
/// the structured readings of the source, the replacement and the helpers'
/// definitions (their types carry the declared contracts), the link, and the round trip's MIR
/// of every instance the copy's, the dispatch method's and the helpers'
/// literal readings run.
fn roundtrip_key(vc: &crate::driver::cache::VerdictCache, gen_id: &str, h: &mut Hasher<'_>, rt: &Sbmir, f: &RoundTripFn) -> Option<String> {
    let mut t = format!("sandblaster-shipped-theorem/1\ntoolchain {}\ngenerator {gen_id}\n{f:?}\n", vc.toolchain);
    let mut globals: Vec<&str> = vec![f.source.as_str(), f.target.as_str()];
    globals.extend(f.helpers.iter().map(|x| x.1.as_str()));
    globals.extend(f.equiv.iter().map(|x| x.as_str()));
    for g in globals {
        let gid = h.env.lookup_global(g)?;
        t.push_str(&format!("structured {g} {}\n", h.closure(gid)));
    }
    let mut keys: Vec<String> = f.helpers.iter().map(|x| x.0.clone()).chain(f.dispatch_key.clone()).chain(std::iter::once(f.copy_key.clone())).flat_map(|k| mir_closure(rt, &k)).collect();
    keys.sort();
    keys.dedup();
    for k in keys {
        let text = rt.fns.get(&k).map(|x| format!("{x:?}")).unwrap_or_else(|| "absent".into());
        t.push_str(&format!("mir {k} {}\n", crate::surface::hex(&crate::surface::sha256(text.as_bytes()))));
    }
    t.push_str(&format!("adts {}\n", crate::surface::hex(&crate::surface::sha256(format!("{:?}", rt.adts).as_bytes()))));
    Some(crate::surface::hex(&crate::surface::sha256(t.as_bytes())))
}


/// [`prove_roundtrip`] without the cache, on the loaded reading `lit`: per
/// function its outcome and the declarations its theorems added.
#[allow(clippy::too_many_arguments)]
fn prove_roundtrip_now(out: &mut crate::elab::Output, facts: &crate::lift::LiftFacts, names: &ModuleNames, rt: &Sbmir, lit: &Literal, callees: Vec<Callee>, fns: &[RoundTripFn], opts: &GateOptions<'_>) -> Vec<(RoundTripOutcome, Vec<DefDecl>)> {
    // the instances each definition is read against: a helper's and a
    // copy's instance is listed under the definition it is read against
    // (a replacement that is the optimizer's residual under the source's)
    let mut contracts: Vec<MirContract> = facts.mir_contracts.clone();
    let contract_of = |g: &str| facts.mir_contracts.iter().find(|c| c.global == g).cloned();
    for f in fns {
        let src_c = contract_of(&f.source);
        for (k, g) in &f.helpers {
            if let Some(c) = contract_of(g).or_else(|| src_c.clone().map(|c| MirContract { global: g.clone(), ..c })) {
                contracts.push(MirContract { key: k.clone(), ..c });
            }
        }
        let tgt_c = contract_of(&f.target).or_else(|| src_c.clone().map(|c| MirContract { global: f.target.clone(), ..c }));
        for k in f.dispatch_key.iter().chain(std::iter::once(&f.copy_key)) {
            for c in [&tgt_c, &src_c].into_iter().flatten() {
                contracts.push(MirContract { key: k.clone(), ..c.clone() });
            }
        }
    }
    let mut pv = Prover::new(&mut out.env, rt, names, lit, &out.pre_commit, &contracts);
    pv.budget_secs = opts.budget_secs;
    pv.max_steps = opts.max_steps;
    pv.trace = opts.trace;
    pv.callees = callees;
    pv.replace_callees = true;
    // the helpers callee-first (by the round trip's MIR), once each
    let helpers: Vec<(String, String)> = {
        let mut all: Vec<(String, String)> = Vec::new();
        for f in fns {
            for h in &f.helpers {
                if !all.contains(h) {
                    all.push(h.clone());
                }
            }
        }
        let mut order: Vec<(String, String)> = Vec::new();
        fn visit(k: &str, all: &[(String, String)], rt: &Sbmir, seen: &mut std::collections::BTreeSet<String>, order: &mut Vec<(String, String)>) {
            if !seen.insert(k.to_string()) {
                return;
            }
            for k2 in mir_closure(rt, k) {
                if k2 != k && all.iter().any(|h| h.0 == k2) {
                    visit(&k2, all, rt, seen, order);
                }
            }
            if let Some(h) = all.iter().find(|h| h.0 == k) {
                order.push(h.clone());
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        for h in &all {
            visit(&h.0, &all, rt, &mut seen, &mut order);
        }
        order
    };
    let mut done: BTreeMap<String, (Result<Proven, String>, Vec<DefDecl>)> = BTreeMap::new();
    for (k, g) in &helpers {
        let r = if lit.lfn(k).is_none() { Err(format!("no literal reading of `{k}`")) } else { pv.prove(&Entry::Fn { key: k.clone(), s_global: g.clone() }) };
        done.insert(k.clone(), (r, std::mem::take(&mut pv.added)));
    }
    let mut outs = Vec::new();
    for f in fns {
        let mut got: Vec<(String, Proven)> = Vec::new();
        let mut decls: Vec<DefDecl> = Vec::new();
        let mut err = None;
        for (k, g) in &f.helpers {
            match done.get(k) {
                Some((Ok(p), ds)) => {
                    got.push((k.clone(), p.clone()));
                    decls.extend(ds.iter().cloned());
                }
                Some((Err(e), _)) => {
                    err = Some(format!("the helper `{k}` against `{g}`: {e}"));
                    break;
                }
                None => {
                    err = Some(format!("the helper `{k}` was not proven"));
                    break;
                }
            }
        }
        // (a dispatch impl method, then the copy, each against the
        // replacement's call: the delegation the round trip checked)
        for k in f.dispatch_key.iter().chain(std::iter::once(&f.copy_key)) {
            if err.is_some() {
                break;
            }
            pv.delegate = true;
            let r = if lit.lfn(k).is_none() { Err(format!("no literal reading of `{k}`")) } else { pv.prove(&Entry::Fn { key: k.clone(), s_global: f.target.clone() }) };
            pv.delegate = false;
            match r {
                Ok(p) => got.push((k.clone(), p)),
                Err(e) => err = Some(format!("`{k}` against `{}`: {e}", f.target)),
            }
        }
        if err.is_none() {
            match pv.compose(&f.copy_key, &f.source, &f.target, f.equiv.as_deref()) {
                Ok(p) => got.push((f.copy_key.clone(), p)),
                Err(e) => err = Some(e),
            }
        }
        decls.append(&mut pv.added);
        outs.push((RoundTripOutcome { source: f.source.clone(), result: match err { Some(e) => Err(e), None => Ok(got) } }, decls));
    }
    outs
}
