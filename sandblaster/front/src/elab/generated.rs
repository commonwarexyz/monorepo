//! Elaboration of optimizer-produced items (DESIGN.md §8.2, §8.3). Owned
//! by the optimizer work; the hooks in the rest of the elaborator are
//! `Elab::generated` (checked first thing in `Elab::add_definition`) and
//! nothing else.
//!
//! * [`resume`] elaborates **additional** items — multiversioned clones
//!   (§9.3) and specialization residuals (§8.2.1) — into the environment of
//!   a finished elaboration ([`super::Output`]), with the normal prover
//!   chain and kernel checks (optionally capturing the pre-commit
//!   definitions, [`SinkMode::Capture`]): they are ordinary exec functions of an
//!   extended crate whose first items are the original crate's (same
//!   [`ItemId`]s, so the output's maps stay valid).
//! * [`generated`] is the round trip's **generated mode** (§8.3): the
//!   lowered crate (the printed file read back) is elaborated with every
//!   proof slot `Erased` (the [`ErasedProver`]), and definitions are
//!   recorded in a [`Sink`] instead of being added to the kernel. Each
//!   definition name maps to the global the rest of the elaboration should
//!   refer to (its counterpart in the optimized environment, matched by the
//!   deterministic name) and to the global whose body it must equal.

use std::collections::{HashMap, HashSet};

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{DefKind, GlobalId, Recursion, Tm};
use sandblaster_kernel::value::Budget;

use super::{eqs::EqGlobals, items::FnInfo, prelude::Prelude, semantics::Semantics, Elab, FnState, ItemGlobal, Options, Output, ProverChain, R};
use crate::hir::{Crate, ItemId, ItemKind};
use crate::prover::{AutoFailure, Goal, Prover};
use crate::span::Span;

/// A definition recorded in generated mode.
#[derive(Clone, Debug)]
pub struct GenDef {
    pub name: String,
    pub kind: DefKind,
    pub item: Option<ItemId>,
    pub ty: Tm,
    /// The body as elaborated (self-calls are `Rec`).
    pub body: Tm,
    pub arity: u32,
    pub recursion: Recursion,
    pub opaque: bool,
    /// The global the elaboration refers to for this definition.
    pub global: GlobalId,
    /// The global whose committed body this definition must equal.
    pub compare: GlobalId,
}

/// What the elaborator does with definitions while [`Elab::generated`] is
/// set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SinkMode {
    /// Generated mode: record the definition, never add it.
    #[default]
    Record,
    /// Normal elaboration (definitions are added as usual), and every
    /// definition is also recorded with its pre-commit body (self-calls as
    /// `Rec` with their measure proofs), so the optimizer can add
    /// transparent twins (see `opt::variant`).
    Capture,
}

/// Where optimizer-produced definitions go.
#[derive(Default)]
pub struct Sink {
    pub mode: SinkMode,
    /// Record mode: kernel name → (global to refer to, global to compare
    /// with).
    pub targets: HashMap<String, (GlobalId, GlobalId)>,
    pub defs: Vec<GenDef>,
    /// Definitions with no counterpart in the optimized environment.
    pub unmatched: Vec<String>,
}

impl<'a> Elab<'a> {
    /// `add_definition` while [`Elab::generated`] is set (see [`SinkMode`]).
    #[allow(clippy::too_many_arguments)]
    pub fn generated_define(&mut self, name: &str, kind: DefKind, item: Option<ItemId>, ty: Tm, body: Tm, recursion: Recursion, arity: u32, opaque: bool, failed: bool, span: Span) -> R<GlobalId> {
        let mut sink = self.generated.take().unwrap_or_default();
        let r = match sink.mode {
            SinkMode::Record => match sink.targets.get(name).copied() {
                Some((global, compare)) => {
                    sink.defs.push(GenDef { name: name.to_string(), kind, item, ty, body, arity, recursion, opaque, global, compare });
                    Ok(global)
                }
                None => {
                    sink.unmatched.push(name.to_string());
                    Err(super::ElabError { span, msg: format!("generated code defines `{name}`, which has no counterpart in the optimized core"), kind: super::ErrKind::Internal })
                }
            },
            SinkMode::Capture => {
                let r = self.add_definition_plain(name, kind, item, ty.clone(), body.clone(), recursion.clone(), arity, opaque, failed, span);
                if let Ok(g) = &r {
                    sink.defs.push(GenDef { name: name.to_string(), kind, item, ty, body, arity, recursion, opaque, global: *g, compare: *g });
                }
                r
            }
        };
        self.generated = Some(sink);
        r
    }

    /// `add_definition` without the hook.
    #[allow(clippy::too_many_arguments)]
    fn add_definition_plain(&mut self, name: &str, kind: DefKind, item: Option<ItemId>, ty: Tm, body: Tm, recursion: Recursion, arity: u32, opaque: bool, failed: bool, span: Span) -> R<GlobalId> {
        let saved = self.generated.take();
        let r = self.add_definition(name, kind, item, ty, body, recursion, arity, opaque, failed, span);
        self.generated = saved;
        r
    }
}

/// The prover of generated mode: every proof slot is `Erased` (DESIGN.md
/// §8.3; the comparison skips irrelevant positions and the kernel-checked
/// proofs of the optimized core justify the printed code).
pub struct ErasedProver;

impl Prover for ErasedProver {
    fn prove(&mut self, _env: &Env, _g: &Goal, _b: &mut Budget) -> Result<Tm, AutoFailure> {
        Ok(std::rc::Rc::new(sandblaster_kernel::term::Term::Erased))
    }
}

/// The elaboration-semantics ids of an environment built by
/// [`super::elaborate`] (looked up again by name).
fn semantics_of(env: &Env, arch: &str) -> Result<Semantics, String> {
    let tuple1 = env.lookup_ind("Tuple1").ok_or("`Tuple1` is missing")?;
    let copy_range = env.lookup_global("array::copy_range").ok_or("`array::copy_range` is missing")?;
    let prefix = format!("{arch}::");
    let mut intrinsics = HashMap::new();
    for i in 0..env.num_globals() {
        let g = GlobalId(i);
        if let Some(n) = env.global_name(g)
            && n.starts_with(&prefix)
        {
            intrinsics.insert(n.to_string(), g);
        }
    }
    Ok(Semantics { tuple1, copy_range, intrinsics, hw: vec![] })
}

/// Derived-equality globals of the crate's types, looked up by name.
fn eq_fns_of(env: &Env, krate: &Crate) -> HashMap<ItemId, EqGlobals> {
    let mut out = HashMap::new();
    for it in &krate.items {
        let derives = match &it.kind {
            ItemKind::Struct(s) => s.derives,
            ItemKind::Enum(e) => e.derives,
            _ => continue,
        };
        if !derives.partial_eq {
            continue;
        }
        let p = it.path.to_string();
        if let Some(eq) = env.lookup_global(&format!("{p}::eq")) {
            out.insert(it.id, EqGlobals { eq, sound: env.lookup_global(&format!("{p}::eq_sound")), complete: env.lookup_global(&format!("{p}::eq_complete")) });
        }
    }
    out
}

/// Per-function call-site facts (the stack-depth `requires` index).
fn fn_info_of(krate: &Crate) -> HashMap<ItemId, FnInfo> {
    krate
        .items
        .iter()
        .filter_map(|it| match &it.kind {
            ItemKind::Fn(f) => Some((it.id, FnInfo { depth_req: f.decreases.as_ref().and_then(|d| d.max).map(|_| f.requires.len()) })),
            _ => None,
        })
        .collect()
}

/// An elaborator over `krate` continuing from `out` (whose environment is
/// moved in; [`finish`] moves it back).
fn rebuild<'a>(out: &mut Output, krate: &'a Crate, prover: &'a mut ProverChain, opts: &Options) -> Result<Elab<'a>, String> {
    let env = std::mem::take(&mut out.env);
    let p = match Prelude::new(&env) {
        Ok(p) => p,
        Err(e) => {
            out.env = env;
            return Err(e);
        }
    };
    let sem = match semantics_of(&env, krate.target.arch.name()) {
        Ok(s) => s,
        Err(e) => {
            out.env = env;
            return Err(e);
        }
    };
    let globals = out.fn_globals.iter().map(|(k, g)| (*k, ItemGlobal::Def(*g))).collect();
    let eq_fns = eq_fns_of(&env, krate);
    let hw_items: HashSet<ItemId> = super::order::hardware_items(krate, &sem);
    Ok(Elab {
        krate,
        env,
        p,
        sem,
        prover,
        opts: opts.clone(),
        adts: out.adts.clone(),
        globals,
        eq_fns,
        defs: std::mem::take(&mut out.defs),
        obligations: std::mem::take(&mut out.obligations),
        laws: std::mem::take(&mut out.laws),
        diags: std::mem::take(&mut out.diags),
        deferred: std::mem::take(&mut out.deferred),
        hw_items,
        helper_kinds: HashMap::new(),
        fn_info: fn_info_of(krate),
        ens_rec: None,
        nat_ranges: HashMap::new(),
        nat_range_missing: HashMap::new(),
        generated: None,
        // the §15 S1 stages run only in the main elaboration
        s1: super::views::S1State::default(),
        s3: super::complete::S3State::default(),
        f: FnState::new(String::new(), None, &[], Span::DUMMY),
    })
}

/// Moves the state of `el` back into `out`.
fn finish(el: Elab<'_>, out: &mut Output) {
    out.env = el.env;
    out.defs = el.defs;
    out.obligations = el.obligations;
    out.laws = el.laws;
    out.diags = el.diags;
    out.deferred = el.deferred;
    for (k, v) in el.globals {
        if let ItemGlobal::Def(g) = v {
            out.fn_globals.insert(k, g);
        }
    }
    out.adts.extend(el.adts);
}

/// Elaborates `items` of `krate` (an extension of the crate `out` was
/// elaborated from: same first items) into `out`, in the given order
/// (callees first), with `prover`. Returns the items whose elaboration
/// failed (their diagnostics are in `out.diags`).
pub fn resume(out: &mut Output, krate: &Crate, items: &[ItemId], prover: &mut ProverChain, opts: &Options, capture: Option<&mut Vec<GenDef>>) -> Result<Vec<ItemId>, String> {
    let mut el = rebuild(out, krate, prover, opts)?;
    let capturing = capture.is_some();
    if capturing {
        el.generated = Some(Sink { mode: SinkMode::Capture, ..Default::default() });
    }
    let mut failed = Vec::new();
    for &id in items {
        let before = el.defs.len();
        el.item(id);
        let ok = el.defs[before..].iter().all(|d| d.status == super::DefStatus::Checked) && matches!(el.globals.get(&id), Some(ItemGlobal::Def(_)));
        if !ok {
            failed.push(id);
        }
    }
    let sink = el.generated.take();
    if let (Some(c), Some(sink)) = (capture, sink) {
        c.extend(sink.defs);
    }
    finish(el, out);
    Ok(failed)
}

/// The recorded definitions of a generated-mode run and its errors
/// (`(item, message)`).
pub type Generated = (Vec<GenDef>, Vec<(ItemId, String)>);

/// Generated mode (see the module docs): elaborates `items` of the lowered
/// crate `krate` against `out`'s environment with every proof `Erased`,
/// recording definitions in a [`Sink`] with the given `targets`. The
/// environment is not changed. Returns the recorded definitions and the
/// elaboration errors (`(item, message)`).
pub fn generated(out: &mut Output, krate: &Crate, items: &[ItemId], targets: HashMap<String, (GlobalId, GlobalId)>) -> Result<Generated, String> {
    let mut chain = ProverChain::new(vec![("generated".into(), Box::new(ErasedProver))]);
    let opts = Options { check_proofs: false, load_lemmas: false, ..Options::default() };
    let mut el = rebuild(out, krate, &mut chain, &opts)?;
    // the lowered crate's items keep their ids: refer to the optimized
    // environment's globals
    el.generated = Some(Sink { mode: SinkMode::Record, targets, ..Default::default() });
    let ndefs = el.defs.len();
    let nobl = el.obligations.len();
    let ndiag = el.diags.list.len();
    let mut errors = Vec::new();
    for &id in items {
        let krate = el.krate;
        let it = krate.item(id);
        let res = match &it.kind {
            ItemKind::Fn(_) | ItemKind::Const(_) => {
                el.item(id);
                Ok(())
            }
            _ => Err("only functions and constants are elaborated in generated mode".to_string()),
        };
        if let Err(e) = res {
            errors.push((id, e));
        }
    }
    let sink = el.generated.take().unwrap_or_default();
    // generated-mode records never reach the report
    let new_diags: Vec<_> = el.diags.list.drain(ndiag..).collect();
    for d in new_diags {
        errors.push((ItemId(u32::MAX), d.msg.clone()));
    }
    el.defs.truncate(ndefs);
    el.obligations.truncate(nobl);
    for n in &sink.unmatched {
        errors.push((ItemId(u32::MAX), format!("no counterpart for `{n}`")));
    }
    // the globals map must not leak generated-mode entries
    finish_generated(el, out);
    Ok((sink.defs, errors))
}

/// Moves the environment and records back without taking generated-mode
/// globals.
fn finish_generated(el: Elab<'_>, out: &mut Output) {
    out.env = el.env;
    out.defs = el.defs;
    out.obligations = el.obligations;
    out.laws = el.laws;
    out.diags = el.diags;
    out.deferred = el.deferred;
}
