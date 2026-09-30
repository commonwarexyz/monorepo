//! Σ3, sequence summaries (optimizer design §8, plan O7).
//!
//! A list-, slice- or array-valued term built from `seq::{take, drop,
//! append, update, replicate}`, `array::copy_range`, `array::repeat`, range
//! slices and constructor spines is rewritten into its **segment normal
//! form** ([`segments`]): a list of pieces — a contiguous range of a list
//! (`Seg`), one element (`Elem`), or `n` copies of a value (`Rep`) — every
//! rewrite an instance of a checked lemma of `lemmas/seq.core`, lengths
//! decided by linear arithmetic over the path's facts.
//!
//! **Consumer driving** ([`drive`]): where the Σ1 driver reaches a call of a
//! user function whose slice argument is not a slice of the program (a
//! buffer assembled from pieces), the call becomes a call of a
//! **segment specialization** `f__seg<k>`: `f` with that slice replaced by
//! its pieces' parameters (a slice per `Seg`, a value per `Elem`),
//! defined by its entry `E(x̄, s̄) = f(x̄, mk(s₁ ++ [e₁] ++ s₂ …))` and driven
//! like any function. Element reads and sub-slices of the pieces resolve by
//! the normal form (forwarding); where a read's piece is not decided by the
//! facts, the residual splits on the piece's emptiness (a **demand split**:
//! it is the residual's own test, the source has none). A recursive call of
//! `f` on the same shape is the helper's back-edge (its lemma is measure
//! recursive, the back-edges its induction hypothesis), a call on a single
//! piece is a call of `f` itself on a sub-slice, another shape another
//! helper. So the buffer disappears: one residual loop per `Seg` piece over
//! the original slice (design §8.2, supercompilation subsuming
//! deforestation).
//!
//! **Demand** ([`demand`]): pieces a consumer never reads (a zero tail past
//! the consumed length) are dropped by the normal form — `take` of the
//! consumed length — and a `replicate` fill that is never read is never
//! materialized; a read at a known offset becomes the written value; a
//! piece the facts do not decide is the residual's own test.
//!
//! **No fast templates.** The design's SP1/SP2 (`foldl_append` /
//! `foldr_append` instances for fold-shaped consumers, §8.2) would avoid
//! driving; a segment helper's loop costs what the consumer's own loop
//! costs (the source's emptiness test becomes the helper's demand test, a
//! call on the last piece is the consumer itself), so they would only save
//! helper code. The lemmas are in `seq.core` (with `index_scanl`, the scan
//! demand of corpus P8) for a later template or demand pass.
//!
//! Nothing here is trusted: every helper carries its kernel-checked lemma
//! `Π x̄ s̄ h̄. Eq(R, f__seg x̄ s̄ h̄, E x̄ s̄ h̄)`, and every leaf of a driven
//! residual that uses the normal form is closed by the proof builder from
//! the seq lemmas ([`segments::Norm`] with proofs).

pub mod demand;
pub mod drive;
pub mod segments;

use sandblaster_kernel::api::Env;
use sandblaster_kernel::value::Budget;

/// The lemma file (checked when loaded; untrusted).
pub const SEQ_CORE: &str = include_str!("../../../lemmas/seq.core");

/// Loads `lemmas/seq.core` into `env` once (the optimizer's lemma library,
/// on demand: the elaborator's library does not need it). It builds on the
/// automation's library ([`crate::auto::lemmas::FILES`]: `slice::ext`,
/// `seq::append_assoc`), and none of its names is defined there (the
/// elaborator's generic `Seq` library is `lemmas/seq_lib.core`). A name
/// of this file that is already defined before it loads is an error, not
/// a silent shadowing: the optimizer resolves its lemmas by name.
pub fn ensure_lemmas(env: &mut Env) -> Result<(), String> {
    let names: Vec<&str> = SEQ_CORE.lines().filter_map(|l| l.strip_prefix("def")).filter_map(|r| r.split_once(' ')).filter_map(|(_, r)| r.split_once(" : ")).map(|(n, _)| n).collect();
    let present: Vec<&str> = names.iter().copied().filter(|n| env.lookup_global(n).is_some()).collect();
    if !names.is_empty() && present.len() == names.len() {
        return Ok(());
    }
    if !present.is_empty() {
        return Err(format!("lemmas/seq.core: {} of its {} names are already defined (`{}`): a name clash or a load that failed part way", present.len(), names.len(), present[0]));
    }
    let text = sandblaster_kernel::expand_templates(SEQ_CORE).map_err(|e| format!("lemmas/seq.core: {e}"))?;
    let mut b = Budget { steps: 4_000_000_000 };
    env.load_core(&text, &mut b).map_err(|e| format!("lemmas/seq.core: {e}"))?;
    Ok(())
}

pub mod prove;

thread_local! {
    /// The Σ3 fault of the must-reject suite active for the function being
    /// driven (driver and proof builder alike): R5 `SegTakeShort`, R9
    /// `SegFoldSwap`.
    static FAULT: std::cell::Cell<Option<DriveFault>> = const { std::cell::Cell::new(None) };
}

/// Activates a Σ3 fault while alive (the must-reject suite only; other
/// faults are ignored).
pub struct FaultScope(Option<DriveFault>);

impl FaultScope {
    pub fn enter(fault: Option<DriveFault>) -> FaultScope {
        let f = fault.filter(|f| matches!(f, DriveFault::SegTakeShort | DriveFault::SegFoldSwap));
        FaultScope(FAULT.with(|c| c.replace(f)))
    }
}

impl Drop for FaultScope {
    fn drop(&mut self) {
        FAULT.with(|c| c.set(self.0));
    }
}

/// Dead-helper elimination in the print view: the optimizer's helpers
/// (`helpers`: specializations, folds, segment helpers) that no printed
/// function reaches — from the user's functions, the variants and the
/// dispatchers' targets (`roots`) — are not printed (ghost) and leave the
/// round trip's targets. A helper built for an attempt that failed later is
/// one. User items are never dropped. Returns the dropped items' paths.
pub fn eliminate_dead_helpers(print: &mut Crate, targets: &mut HashMap<ItemId, (GlobalId, GlobalId)>, helpers: &[ItemId], roots: &[ItemId]) -> Vec<String> {
    let hs: HashSet<ItemId> = helpers.iter().copied().collect();
    let mut reach: HashSet<ItemId> = HashSet::new();
    let mut stack: Vec<ItemId> = print
        .items
        .iter()
        .filter(|it| !it.ghost && !hs.contains(&it.id) && matches!(&it.kind, ItemKind::Fn(f) if f.kind == FnKind::Exec))
        .map(|it| it.id)
        .chain(roots.iter().copied())
        .collect();
    while let Some(id) = stack.pop() {
        if !reach.insert(id) {
            continue;
        }
        if let Some(ItemKind::Fn(f)) = print.items.get(id.0 as usize).map(|it| &it.kind) {
            stack.extend(super::multiversion::callees(f));
        }
    }
    let mut dropped = Vec::new();
    for h in hs {
        if reach.contains(&h) || print.items[h.0 as usize].ghost {
            continue;
        }
        print.items[h.0 as usize].ghost = true;
        targets.remove(&h);
        dropped.push(print.items[h.0 as usize].path.to_string());
    }
    dropped.sort();
    dropped
}

/// Whether a Σ3 fault of the must-reject suite is active (the builder
/// trusts its claims; the kernel judges them).
pub(crate) fn fault_active() -> bool {
    FAULT.with(|c| c.get()).is_some()
}

/// Whether the R5 fault is active.
pub(crate) fn fault_take_short() -> bool {
    FAULT.with(|c| c.get()) == Some(DriveFault::SegTakeShort)
}

/// Whether the R9 fault is active.
pub(crate) fn fault_fold_swap() -> bool {
    FAULT.with(|c| c.get()) == Some(DriveFault::SegFoldSwap)
}

/// The kernel's rejection kind (`add_def: <Kind>`) of a helper lemma in a
/// segment specialization's failure, or `elaboration` for a helper whose
/// elaboration shows it is wrong, for the candidate report (`None`: not an
/// optimizer fault).
pub(super) fn rejection_kind(e: &str) -> Option<String> {
    // a helper that did not elaborate for a reason other than obligations
    // not re-proven (a counterexample, a type error): an internal
    // inconsistency, like a lemma the kernel rejects (`opt::push_elaborate`)
    if e.contains("rejected by elaboration") {
        return Some("elaboration".into());
    }
    let rest = e.split("its lemma was not proven: ").nth(1)?;
    let kind = rest.split(':').next()?;
    (!kind.is_empty() && kind.chars().all(|c| c.is_ascii_alphabetic())).then(|| format!("add_def: {kind}"))
}

use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;

use sandblaster_kernel::term::{DefDecl, DefKind, GlobalId, PrimOp, Recursion, Rel, Term, Tm, Width};
use sandblaster_kernel::util::mk;

use self::drive::{PK, SegEntry, SegHelper, SegKey};
use super::{Ctx, DriveFault};
use crate::elab::{self, ProverChain};
use crate::hir::*;
use crate::auto::util::shift;
use crate::opt::drive::tree::{Node, NodeKind};

/// `ISIZE_MAX`, the bound of a slice's length.
const ISIZE_MAX: u64 = 9_223_372_036_854_775_807;

/// Rounds of "drive, create the entries it asked for, drive again".
const MAX_ENTRY_ROUNDS: u32 = 4;

/// Segment specializations built per crate.
const MAX_SEG_HELPERS: usize = 32;

/// The bound of each `Seg` piece's length for a shape: the pieces' lengths
/// (and one per element) sum to at most `ISIZE_MAX`.
fn piece_bound(shape: &[PK]) -> u64 {
    let segs = shape.iter().filter(|p| **p == PK::Seg).count().max(1) as u64;
    let elems = shape.iter().filter(|p| **p == PK::Elem).count() as u64;
    (ISIZE_MAX - elems) / segs
}

/// Creates the entry of `key` (a transparent kernel definition):
///
/// `E x̄ s₁ e₁ s₂ … (.h₁ : len s₁ ≤ K) … := f x̄ (mk(n, s₁ ++ (e₁ :: s₂) …))`
///
/// with `n` the pieces' total length (checked `usize` additions) and the
/// slice's well-formedness proof from the bounds (`linarith`).
pub fn create_entry(env: &mut sandblaster_kernel::api::Env, key: &SegKey, index: u32, name: &str) -> Result<SegEntry, String> {
    let ids = segments::Ids::new(env).ok_or("the seq lemmas are not loaded")?;
    let tele = crate::opt::symex::telescope(env, key.def).ok_or("not a definition with a parameter telescope")?;
    if tele.binders.iter().any(|(_, rel, _)| *rel == Rel::Irr) {
        return Err("a consumer with a precondition".into());
    }
    let (sname, _, sdom) = tele.binders.get(key.pos).ok_or("no such parameter")?.clone();
    let (g, targs) = segments::head_app(&sdom).ok_or("the parameter is not a slice")?;
    if env.global_name(g).as_deref() != Some("Slice") || targs.len() != 1 {
        return Err("the parameter is not a slice".into());
    }
    let t = targs[0].1.clone();
    let slice_g = g;
    let bool_ind = env.bool_ind();
    let bound = piece_bound(&key.shape);
    let m = key.shape.len();
    let nrel = tele.binders.len() - 1 + m;
    let nseg = key.shape.iter().filter(|p| **p == PK::Seg).count();
    let arity = nrel + nseg;
    // the telescope: the consumer's parameters with the slice replaced by
    // the pieces, then the bounds (closed parameter types)
    let mut binders: Vec<(String, Rel, Tm)> = Vec::new();
    for (j, (nm, rel, dom)) in tele.binders.iter().enumerate() {
        if j == key.pos {
            for (k, p) in key.shape.iter().enumerate() {
                match p {
                    PK::Seg => binders.push((format!("{sname}{k}"), Rel::Rel, sdom.clone())),
                    PK::Elem => binders.push((format!("x{k}"), Rel::Rel, t.clone())),
                }
            }
        } else {
            binders.push((nm.to_string(), *rel, dom.clone()));
        }
    }
    // variables at the depth `arity` (inside the whole telescope)
    let var = |lvl: usize| mk::var((arity - 1 - lvl) as u32);
    let seg_lvls: Vec<usize> = key.shape.iter().enumerate().filter(|(_, p)| **p == PK::Seg).map(|(k, _)| key.pos + k).collect();
    for (k, lvl) in seg_lvls.iter().enumerate() {
        // at depth nrel + k
        let depth = nrel + k;
        let v = mk::var((depth - 1 - lvl) as u32);
        let c = mk::prim(PrimOp::Le(Width::Usize), vec![mk::fst(v), mk::lit(Width::Usize, bound)], vec![]);
        binders.push((format!("hb{k}"), Rel::Irr, mk::eq_bool(bool_ind, c, true)));
    }
    let g_ = |x: GlobalId, args: Vec<Tm>| mk::apps(mk::global(x), args.into_iter().map(|a| (Rel::Rel, a)));
    let list_of = |s: Tm| mk::fst(mk::snd(s));
    // the list and the total length
    let mut list: Option<Tm> = None;
    for (k, p) in key.shape.iter().enumerate().rev() {
        let lvl = key.pos + k;
        list = Some(match (p, list) {
            (PK::Seg, None) => list_of(var(lvl)),
            (PK::Seg, Some(r)) => g_(ids.append, vec![t.clone(), list_of(var(lvl)), r]),
            (PK::Elem, None) => mk::ctor(ids.list, 1, vec![t.clone()], vec![var(lvl), mk::ctor(ids.list, 0, vec![t.clone()], vec![])]),
            (PK::Elem, Some(r)) => mk::ctor(ids.list, 1, vec![t.clone()], vec![var(lvl), r]),
        });
    }
    let list = list.ok_or("an empty shape")?;
    let bounds: Vec<(Tm, Tm)> = seg_lvls
        .iter()
        .enumerate()
        .map(|(k, lvl)| (var(nrel + k), mk::eq_bool(bool_ind, mk::prim(PrimOp::Le(Width::Usize), vec![mk::fst(var(*lvl)), mk::lit(Width::Usize, bound)], vec![]), true)))
        .collect();
    let cast = |u: Tm| mk::prim(PrimOp::Cast { from: Width::Usize, to: Width::Int }, vec![u], vec![]);
    let lin = |hyps: Vec<(Tm, Tm)>, goal: Tm| -> Tm { Rc::new(Term::Linarith { hyps, goal, cert: vec![] }) };
    let mut total: Option<Tm> = None;
    for (k, p) in key.shape.iter().enumerate() {
        let part = match p {
            PK::Seg => mk::fst(var(key.pos + k)),
            PK::Elem => mk::lit(Width::Usize, 1),
        };
        total = Some(match total {
            None => part,
            Some(acc) => {
                let ob = mk::eq_bool(bool_ind, mk::prim(PrimOp::Le(Width::Int), vec![mk::prim(PrimOp::IAdd, vec![cast(acc.clone()), cast(part.clone())], vec![]), mk::lit(Width::Int, u64::MAX)], vec![]), true);
                mk::prim(PrimOp::Add(Width::Usize), vec![acc, part], vec![lin(bounds.clone(), ob)])
            }
        });
    }
    let total = total.ok_or("an empty shape")?;
    // the well-formedness proof: len(list) = cast(total), cast(total) ≤ ISIZE_MAX
    let len = |l: Tm| g_(ids.len, vec![t.clone(), l]);
    let int = mk::int_ty(Width::Int);
    let mut hyps: Vec<(Tm, Tm)> = bounds.clone();
    for lvl in &seg_lvls {
        let s = var(*lvl);
        hyps.push((g_(ids.slice_ok_len, vec![t.clone(), s.clone()]), mk::eq(int.clone(), len(list_of(s.clone())), cast(mk::fst(s)))));
    }
    // the len_append instances along the list
    let mut cur = list.clone();
    loop {
        match segments::head_app(&cur) {
            Some((g, args)) if g == ids.append && args.len() == 3 => {
                let (a, b) = (args[1].1.clone(), args[2].1.clone());
                let inst = g_(env.lookup_global("seq::len_append").ok_or("seq::len_append")?, vec![t.clone(), a.clone(), b.clone()]);
                let ty = mk::eq(int.clone(), len(cur.clone()), mk::prim(PrimOp::IAdd, vec![len(a), len(b.clone())], vec![]));
                hyps.push((inst, ty));
                cur = b;
            }
            _ => match &*cur {
                Term::Ctor { ctor: 1, args, .. } => cur = args[1].clone(),
                _ => break,
            },
        }
    }
    let p_len = lin(hyps, mk::eq(int.clone(), len(list.clone()), cast(total.clone())));
    let isize_max = mk::lit(Width::Int, ISIZE_MAX);
    let p_bnd = lin(bounds.clone(), mk::eq_bool(bool_ind, mk::prim(PrimOp::Le(Width::Int), vec![cast(total.clone()), isize_max], vec![]), true));
    let slice_ok = env.lookup_global("SliceOk").ok_or("SliceOk")?;
    let ok = mk::pair(g_(slice_ok, vec![t.clone(), total.clone(), list.clone()]), p_len, p_bnd);
    let _ = slice_g;
    let slice = mk::apps(mk::global(ids.slice_mk), [(Rel::Rel, t.clone()), (Rel::Rel, total), (Rel::Rel, list), (Rel::Irr, ok)]);
    let mut args: Vec<(Rel, Tm)> = Vec::new();
    let mut lvl = 0usize;
    for (j, (_, rel, _)) in tele.binders.iter().enumerate() {
        if j == key.pos {
            args.push((Rel::Rel, slice.clone()));
            lvl += m;
        } else {
            args.push((*rel, var(lvl)));
            lvl += 1;
        }
    }
    let body_inner = mk::apps(mk::global(key.def), args);
    // Π / λ telescopes
    let mut ty = shift(&tele.ret, (arity as i64) - (tele.binders.len() as i64));
    let mut body = body_inner;
    for (nm, rel, dom) in binders.iter().rev() {
        ty = mk::pi(nm, *rel, dom.clone(), ty);
        body = mk::lam(nm, *rel, dom.clone(), body);
    }
    let d = DefDecl { name: Rc::from(name), kind: DefKind::Spec, ty, body, recursion: Recursion::None, arity: arity as u32, opaque: false };
    let mut b = sandblaster_kernel::value::Budget { steps: 200_000_000 };
    let entry = env.add_def(d, &mut b).map_err(|e| format!("the segment entry `{name}`: {}", e.to_string().chars().take(400).collect::<String>()))?;
    Ok(SegEntry { entry, bound, index, helper: None })
}

/// The entries (and so the helpers) a process tree's leaves call.
pub fn entries_in(tree: &Node, reg: &drive::Registry) -> Vec<SegKey> {
    fn go(n: &Node, reg: &drive::Registry, out: &mut Vec<SegKey>) {
        match &n.kind {
            NodeKind::Leaf(v) => {
                let mut seen: HashSet<*const sandblaster_kernel::value::Value> = HashSet::new();
                let mut stack = vec![v.clone()];
                while let Some(x) = stack.pop() {
                    if !seen.insert(Rc::as_ptr(&x)) || seen.len() > 200_000 {
                        continue;
                    }
                    use sandblaster_kernel::value::{Arg, Elim, Head, Value};
                    let rel = |a: &Arg| match a {
                        Arg::Rel(v) => Some(v.clone()),
                        Arg::Irr(_) => None,
                    };
                    match &*x {
                        Value::Ctor { args, .. } => stack.extend(args.iter().filter_map(rel)),
                        Value::Pair { fst, snd } => {
                            stack.push(fst.clone());
                            stack.extend(rel(snd));
                        }
                        Value::Neu(nn) => {
                            match &nn.head {
                                Head::Global { def, args } => {
                                    if let Some((k, _)) = reg.by_entry(*def)
                                        && !out.contains(k)
                                    {
                                        out.push(k.clone());
                                    }
                                    stack.extend(args.iter().filter_map(rel));
                                }
                                Head::Prim { args, .. } => stack.extend(args.iter().cloned()),
                                _ => {}
                            }
                            for e in &nn.spine {
                                if let Elim::App(a) = e {
                                    stack.extend(rel(a));
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            NodeKind::Split { arms, merged, .. } => {
                if let Some(v) = merged {
                    go(&Node { depth: n.depth, steps: vec![], kind: NodeKind::Leaf(v.clone()) }, reg, out);
                }
                for a in arms {
                    go(&a.body, reg, out);
                }
            }
            NodeKind::Bind { value, body, .. } => {
                go(value, reg, out);
                go(body, reg, out);
            }
        }
    }
    let mut out = Vec::new();
    go(tree, reg, &mut out);
    out
}

/// After a driving: creates the entries it asked for (`Ok(true)`: drive
/// again), else builds the helpers of the entries its tree calls.
#[allow(clippy::too_many_arguments)]
pub(super) fn after_drive(cx: &mut Ctx<'_>, ext: &mut Crate, chain: &mut ProverChain, eopts: &elab::Options, tree: &Node, user_globals: &HashMap<GlobalId, ItemId>, inline: &HashSet<GlobalId>, rounds: &mut u32, fault: Option<DriveFault>) -> Result<bool, String> {
    let requested: Vec<SegKey> = std::mem::take(&mut *cx.summaries.seg.requested.borrow_mut()).into_iter().collect();
    // the lemmas of the proofs, loaded on the first use (every optimizer run
    // without a segment site skips them)
    if !requested.is_empty() || tree.counts().seq > 0 {
        ensure_lemmas(&mut cx.out.env)?;
    }
    let mut created = false;
    for key in requested {
        if cx.summaries.seg.entries.contains_key(&key) || cx.summaries.seg.failed.contains(&key) {
            continue;
        }
        if cx.summaries.seg.entries.len() >= MAX_SEG_HELPERS {
            cx.summaries.seg.failed.insert(key);
            continue;
        }
        match commit_entry(cx, &key) {
            Ok(()) => created = true,
            Err(why) => {
                super::trace(|| format!("seq: entry of {}: {why}", cx.global_name(key.def)));
                cx.summaries.seg.failed.insert(key);
            }
        }
    }
    if created {
        *rounds += 1;
        if *rounds > MAX_ENTRY_ROUNDS {
            return Err("the segment specializations did not settle".into());
        }
        return Ok(true);
    }
    for key in entries_in(tree, &cx.summaries.seg) {
        ensure_helper(cx, ext, chain, eopts, &key, user_globals, inline, &mut Vec::new(), fault)?;
    }
    Ok(false)
}

/// Creates the entry of `key` and registers it: `f__seg<k>::entry` with `k`
/// a fresh number of the consumer `f` (its helper is `f__seg<k>`).
fn commit_entry(cx: &mut Ctx<'_>, key: &SegKey) -> Result<(), String> {
    let index = cx.summaries.seg.reserve(key.def);
    let name = format!("{}__seg{index}::entry", cx.global_name(key.def));
    let e = create_entry(&mut cx.out.env, key, index, &name)?;
    cx.summaries.seg.entries.insert(key.clone(), e);
    Ok(())
}

/// Builds the helper of `key` (and first the helpers it calls); `stack`:
/// helpers being built (a cycle between two is refused).
#[allow(clippy::too_many_arguments)]
fn ensure_helper(cx: &mut Ctx<'_>, ext: &mut Crate, chain: &mut ProverChain, eopts: &elab::Options, key: &SegKey, user_globals: &HashMap<GlobalId, ItemId>, inline: &HashSet<GlobalId>, stack: &mut Vec<SegKey>, fault: Option<DriveFault>) -> Result<(), String> {
    if cx.summaries.seg.entries.get(key).is_some_and(|e| e.helper.is_some()) {
        return Ok(());
    }
    if cx.summaries.seg.failed.contains(key) {
        return Err("a segment specialization that failed".into());
    }
    if stack.contains(key) {
        return Err("segment specializations calling each other".into());
    }
    stack.push(key.clone());
    let r = build_helper(cx, ext, chain, eopts, key, user_globals, inline, stack, fault);
    stack.pop();
    match r {
        Ok(h) => {
            if let Some(e) = cx.summaries.seg.entries.get_mut(key) {
                e.helper = Some(h);
            }
            Ok(())
        }
        Err(why) => {
            super::trace(|| format!("seq: helper of {}: {why}", cx.global_name(key.def)));
            cx.summaries.seg.failed.insert(key.clone());
            Err(why)
        }
    }
}

/// One segment helper: drive its entry (the consumer's first application
/// unfolded, later ones leaves), print it (a loop when its tree has
/// back-edges), elaborate it, and prove `Π x̄ s̄ h̄. Eq(R, H x̄ s̄ h̄, E x̄ s̄
/// h̄)` (measure recursive when it loops).
#[allow(clippy::too_many_arguments)]
fn build_helper(cx: &mut Ctx<'_>, ext: &mut Crate, chain: &mut ProverChain, eopts: &elab::Options, key: &SegKey, user_globals: &HashMap<GlobalId, ItemId>, inline: &HashSet<GlobalId>, stack: &mut Vec<SegKey>, fault: Option<DriveFault>) -> Result<SegHelper, String> {
    let dcfg = crate::opt::drive::DriveConfig::default();
    let (entry, bound, index) = cx.summaries.seg.entries.get(key).map(|e| (e.entry, e.bound, e.index)).ok_or("no entry")?;
    let fid = *user_globals.get(&key.def).ok_or("not a user function")?;
    let fd = ext.fn_def(fid).ok_or("not a function")?.clone();
    if !fd.generics.is_empty() || fd.has_requires() {
        return Err("a generic consumer or one with a precondition".into());
    }
    let orig = ext.item(fid).clone();
    let timing = std::env::var_os("SANDBLASTER_OPT_TIMING").is_some();
    let t0 = std::time::Instant::now();
    // 1. drive the entry
    let mut rounds = 0u32;
    let driven = loop {
        let d = {
            let env = &cx.out.env;
            let policy = crate::opt::drive::CratePolicy::new(env, ext, &dcfg, entry, user_globals, inline).with_summaries(&cx.summaries).with_seg_root(key.def);
            crate::opt::drive::run(env, &dcfg, &policy, entry, None)?
        };
        if !cx.summaries.seg.requested.borrow().is_empty() {
            let reqs: Vec<SegKey> = std::mem::take(&mut *cx.summaries.seg.requested.borrow_mut()).into_iter().collect();
            let mut created = false;
            for k in reqs {
                if cx.summaries.seg.entries.contains_key(&k) || cx.summaries.seg.failed.contains(&k) || cx.summaries.seg.entries.len() >= MAX_SEG_HELPERS {
                    continue;
                }
                if commit_entry(cx, &k).is_ok() {
                    created = true;
                }
            }
            rounds += 1;
            if created && rounds <= MAX_ENTRY_ROUNDS {
                continue;
            }
        }
        break d;
    };
    if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() {
        eprintln!("opt: seq helper of {}: {} process nodes, {:?}", orig.name, driven.nodes, driven.tree.counts());
    }
    // the helpers it calls, then its polyvariant and fold helpers
    let nested = entries_in(&driven.tree, &cx.summaries.seg);
    for k in &nested {
        if k != key {
            ensure_helper(cx, ext, chain, eopts, k, user_globals, inline, stack, fault)?;
        }
    }
    let spec_keys = driven.tree.spec_keys();
    super::ensure_helpers(cx, ext, chain, eopts, &spec_keys, user_globals, inline, 1, None)?;
    let recursive = nested.contains(key);
    // 2. the helper: the consumer with its slice replaced by the pieces
    let hf = helper_def(&fd, fid, key, bound, recursive, &orig)?;
    let own = ItemId(ext.items.len() as u32);
    let r = {
        let env = &cx.out.env;
        let policy = crate::opt::drive::CratePolicy::new(env, ext, &dcfg, entry, user_globals, inline).with_summaries(&cx.summaries).with_seg_root(key.def);
        let maps = crate::opt::residual::Maps::new(env, ext, &cx.out.fn_globals, &cx.out.adts)?;
        let op = |h: GlobalId| crate::opt::drive::Policy::folded(&policy, h);
        let ev = crate::opt::drive::step::Eval { env, opaque: &op };
        let spec_items: BTreeMap<crate::opt::drive::tree::SpecKey, ItemId> = cx.helpers.iter().map(|(k, h)| (k.clone(), h.item)).collect();
        let mut fold_items: BTreeMap<GlobalId, ItemId> = cx.summaries.folds.iter().map(|(d, h)| (*d, h.item)).collect();
        fold_items.extend(cx.summaries.seg.items());
        fold_items.insert(entry, own);
        let mut ext2 = ext.clone();
        ext2.items.push(Item { id: own, kind: ItemKind::Fn(hf.clone()), ghost: true, ..orig.clone() });
        crate::opt::residual::tree::build_tree(env, &maps, &ext2, &hf, &driven.tree, &ev, &spec_items, &fold_items, dcfg.max_residual_nodes, orig.span, None).map_err(|e| format!("the segment helper of `{}` is not printable: {e}", orig.name))?
    };
    let t_print = t0.elapsed();
    let mut hf = hf;
    hf.body = FnBody::Exec(r.body);
    hf.locals = r.locals;
    let hname = format!("{}__seg{index}", orig.name);
    // a helper of a clone consumer may take its link through the original
    // consumer's helper (`opt::derive`; a recursive one's mirror needs its
    // pre-commit self-calls)
    let of_clone = cx.clone_of.contains_key(&fid);
    let mut captured: Vec<crate::elab::generated::GenDef> = Vec::new();
    let hid = super::push_elaborate_capture(cx, ext, chain, eopts, &orig, hname.clone(), hf, false, (of_clone && recursive).then_some(&mut captured)).map_err(|(why, rej)| if rej.as_deref() == Some(super::NOT_REPROVEN) { format!("the segment helper `{hname}` not re-proven: {why}") } else { format!("the segment helper `{hname}` rejected by elaboration: {why}") })?;
    if hid != own {
        return Err("the segment helper's item moved".into());
    }
    let hg = *cx.out.fn_globals.get(&hid).ok_or("the segment helper has no global")?;
    let t_elab = t0.elapsed();
    // 3. the lemma
    let measure = if recursive { Some(entry_measure(&cx.out.env, fid, &fd, key, hg)?) } else { None };
    let specs: crate::opt::proof::Specs = cx.helpers.iter().map(|(k, h)| (k.clone(), crate::opt::proof::SpecLemma { helper: h.global, lemma: h.lemma })).collect();
    let mut folds: crate::opt::proof::Folds = cx.summaries.folds.iter().map(|(d, h)| (*d, (h.global, h.lemma))).collect();
    folds.extend(cx.summaries.seg.lemmas());
    let folded = crate::opt::drive::CratePolicy::new(&cx.out.env, ext, &dcfg, entry, user_globals, inline).with_summaries(&cx.summaries).folded_set();
    let lemma_name = format!("{}::equiv", ext.item(hid).path);
    let derived = if of_clone && fault.is_none() {
        match crate::opt::derive::seg_helper_link(cx, key, hg, entry, &lemma_name, &captured) {
            Some(Ok(l)) => Some(l),
            Some(Err(e)) => {
                super::trace(|| format!("derive {hname}: {}", e.chars().take(400).collect::<String>()));
                None
            }
            None => None,
        }
    } else {
        None
    };
    let proven = match derived {
        Some(l) => Ok(l),
        None => prove_helper(&mut cx.out.env, hg, entry, measure, &driven, &specs, &folds, &folded, crate::opt::proof::Budgets::of(&dcfg), &lemma_name, &mut cx.outlines, fault),
    };
    if timing {
        eprintln!("opt: timing seg helper {hname}: drive+print {:?} (nested helpers included), elaborate {:?}, prove {:?} ({})", t_print, t_elab - t_print, t0.elapsed() - t_elab, if proven.is_ok() { "ok" } else { "failed" });
    }
    match proven {
        Ok(lemma) => {
            cx.set_aside_obligations(hid);
            Ok(SegHelper { item: hid, global: hg, lemma })
        }
        Err(e) => {
            ext.items[hid.0 as usize].ghost = true;
            super::pop_driven(cx, ext, hid);
            Err(format!("the segment helper `{hname}`: its lemma was not proven: {}", e.chars().take(600).collect::<String>()))
        }
    }
}

/// The helper's HIR signature: `fd` with its slice parameter replaced by
/// the pieces (`s_k: &[T]`, `x_k: T`) and a `requires` bounding each slice
/// piece's length.
fn helper_def(fd: &FnDef, fid: ItemId, key: &SegKey, bound: u64, recursive: bool, orig: &Item) -> Result<FnDef, String> {
    let sp = orig.span;
    let j = key.pos;
    let sparam = fd.params.get(j).ok_or("no such parameter")?.clone();
    let elem = match sparam.ty.peel_refs() {
        Ty::Slice(t) => (**t).clone(),
        _ => return Err("the parameter is not a slice".into()),
    };
    let mut hf = fd.clone();
    let mut params: Vec<Param> = fd.params[..j].to_vec();
    let mut requires: Vec<Expr> = Vec::new();
    let mut seg_lens: Vec<Expr> = Vec::new();
    let sname = match &sparam.pat.kind {
        PatKind::Binding { local, .. } => fd.local(*local).name.clone(),
        _ => "s".into(),
    };
    for (k, p) in key.shape.iter().enumerate() {
        let local = LocalId(hf.locals.len() as u32);
        let (name, ty, lts) = match p {
            PK::Seg => (format!("{sname}{k}"), sparam.ty.clone(), sparam.lts.clone()),
            PK::Elem => (format!("x{k}"), elem.clone(), Lifetimes(vec![])),
        };
        hf.locals.push(LocalDecl { name, ty: ty.clone(), mutable: false, ghost: false, span: sp });
        params.push(Param { pat: Pat { kind: PatKind::Binding { local, mode: BindingMode::ByValue, sub: None }, ty: ty.clone(), span: sp }, ty: ty.clone(), lts, span: sp, ghost: false });
        if *p == PK::Seg {
            let len = Expr::new(ExprKind::Call { callee: Callee::Builtin(crate::builtins::Builtin::Slice(crate::builtins::SliceMethod::Len), vec![elem.clone()]), args: vec![Expr::new(ExprKind::Local(local), ty.clone(), sp)] }, Ty::usize(), sp);
            seg_lens.push(len.clone());
            let le = Expr::new(ExprKind::Binary(BinOp::Le, Box::new(len), Box::new(Expr::new(ExprKind::Lit(Lit::Int(bound as u128)), Ty::usize(), sp))), Ty::Bool, sp);
            // (no source span: the printer writes the expression)
            requires.push(Expr::new(ExprKind::Coerce(Coercion::BoolToProp, Box::new(le)), Ty::Prop, crate::span::Span::DUMMY));
        }
    }
    params.extend(fd.params[j + 1..].iter().cloned());
    hf.params = params;
    hf.requires = requires;
    hf.ensures = None;
    // the termination measure of a looping helper: the consumer's, at the
    // pieces (their total length for the segment parameter's length)
    hf.decreases = None;
    if recursive {
        let local_of = |p: &Param| match &p.pat.kind {
            PatKind::Binding { local, .. } => Some(*local),
            _ => None,
        };
        let measure = match crate::opt::drive::measure_of(fid, fd).ok_or("a consumer without a measure")? {
            crate::opt::drive::Measure::Param(i) if i != j => {
                let p = fd.params.get(i).ok_or("a measure parameter out of range")?;
                Expr::new(ExprKind::Local(local_of(p).ok_or("a measure parameter without a binding")?), p.ty.clone(), sp)
            }
            crate::opt::drive::Measure::SliceLen(i) if i != j => {
                let p = fd.params.get(i).ok_or("a measure parameter out of range")?;
                let t = match p.ty.peel_refs() {
                    Ty::Slice(t) => (**t).clone(),
                    _ => return Err("a slice measure on a non-slice".into()),
                };
                let s = Expr::new(ExprKind::Local(local_of(p).ok_or("a measure parameter without a binding")?), p.ty.clone(), sp);
                Expr::new(ExprKind::Call { callee: Callee::Builtin(crate::builtins::Builtin::Slice(crate::builtins::SliceMethod::Len), vec![t]), args: vec![s] }, Ty::usize(), sp)
            }
            crate::opt::drive::Measure::SliceLen(_) => {
                let mut it = seg_lens.into_iter();
                let mut acc = it.next().ok_or("a shape without a slice piece")?;
                for x in it {
                    acc = Expr::new(ExprKind::Binary(BinOp::Add, Box::new(acc), Box::new(x)), Ty::usize(), sp);
                }
                acc
            }
            crate::opt::drive::Measure::Param(_) => return Err("a measure on the segment parameter that is not its length".into()),
        };
        hf.decreases = Some(Decreases { measure, max: None });
    }
    hf.recursion = if recursive { crate::hir::Recursion::Tail } else { crate::hir::Recursion::None };
    hf.specialize = false;
    hf.implements = None;
    // (`#[inline(always)]` cannot go with `#[target_feature]`: a variant's
    // helper is a hint)
    hf.inline = Some(if recursive || !fd.target_features.is_empty() { Inline::Hint } else { Inline::Always });
    Ok(hf)
}

/// The helper's lemma measure over its telescope: the consumer's measure
/// at the entry's arguments (the pieces' total length, in `Int`, for a
/// slice measure on the segment parameter).
fn entry_measure(env: &sandblaster_kernel::api::Env, fid: ItemId, fd: &FnDef, key: &SegKey, hg: GlobalId) -> Result<Tm, String> {
    let n = crate::opt::symex::telescope(env, hg).ok_or("no telescope")?.binders.len();
    let m = key.shape.len();
    let var = |lvl: usize| mk::var((n - 1 - lvl) as u32);
    let lvl_of = |i: usize| if i < key.pos { i } else { i + m - 1 };
    match crate::opt::drive::measure_of(fid, fd).ok_or("a consumer without a measure")? {
        crate::opt::drive::Measure::Param(i) if i != key.pos => Ok(var(lvl_of(i))),
        crate::opt::drive::Measure::SliceLen(i) if i != key.pos => Ok(mk::fst(var(lvl_of(i)))),
        crate::opt::drive::Measure::SliceLen(_) => {
            let cast = |u: Tm| mk::prim(PrimOp::Cast { from: Width::Usize, to: Width::Int }, vec![u], vec![]);
            let mut acc: Option<Tm> = None;
            for (k, p) in key.shape.iter().enumerate() {
                let part = match p {
                    PK::Seg => cast(mk::fst(var(key.pos + k))),
                    PK::Elem => mk::lit(Width::Int, 1),
                };
                acc = Some(match acc {
                    None => part,
                    Some(a) => mk::prim(PrimOp::IAdd, vec![a, part], vec![]),
                });
            }
            acc.ok_or_else(|| "an empty shape".into())
        }
        crate::opt::drive::Measure::Param(_) => Err("a measure on the segment parameter that is not its length".into()),
    }
}

/// The lemma `Π x̄ s̄ h̄. Eq(R, H x̄ s̄ h̄, E x̄ s̄ h̄)` from the entry's process
/// tree (measure recursive when `measure` is given: the tree's back-edges
/// are its induction hypothesis). `fault`: a simulated fault (R5) — the
/// proof trusts the driver's claims so the kernel must reject them.
#[allow(clippy::too_many_arguments)]
fn prove_helper(env: &mut sandblaster_kernel::api::Env, h: GlobalId, entry: GlobalId, measure: Option<Tm>, driven: &crate::opt::drive::Driven, specs: &crate::opt::proof::Specs, folds: &crate::opt::proof::Folds, folded: &HashSet<GlobalId>, budgets: crate::opt::proof::Budgets, name: &str, outl: &mut super::outline::Outlines, fault: Option<DriveFault>) -> Result<GlobalId, String> {
    let mut stats = crate::opt::proof::ProofStats::default();
    let tele = crate::opt::symex::telescope(env, h).ok_or("no telescope")?;
    let n = tele.binders.len();
    let args: Vec<(Rel, Tm)> = tele.binders.iter().enumerate().map(|(i, (_, rel, _))| (*rel, mk::var((n - 1 - i) as u32))).collect();
    let src_app = mk::apps(mk::global(entry), args.clone());
    let mut ty = mk::eq(tele.ret.clone(), mk::apps(mk::global(h), args), src_app.clone());
    for (nm, rel, dom) in tele.binders.iter().rev() {
        ty = mk::pi(nm, *rel, dom.clone(), ty);
    }
    let t0 = std::time::Instant::now();
    let outlined = outl.table(env, crate::opt::proof::unfolded_defs(&driven.tree, h));
    let t_outl = t0.elapsed();
    let own = measure.clone().map(|m| crate::opt::proof::build::OwnFold { def: entry, measure: m, arity: n as u32 });
    let body = {
        let envr: &sandblaster_kernel::api::Env = env;
        crate::opt::proof::build_body(envr, h, &src_app, &driven.tree, &driven.root, specs, folded, fault.is_some(), budgets, &mut stats, &outlined, folds, own)?
    };
    let mut lam = body;
    for (nm, rel, dom) in tele.binders.iter().rev() {
        lam = mk::lam(nm, *rel, dom.clone(), lam);
    }
    let recursion = match measure {
        Some(m) => Recursion::Measure { measure: m },
        None => Recursion::None,
    };
    let d = DefDecl { name: Rc::from(name), kind: DefKind::Lemma, ty, body: lam, recursion, arity: n as u32, opaque: true };
    let t_built = t0.elapsed();
    let mut bud = sandblaster_kernel::value::Budget { steps: budgets.steps };
    let r = env.add_def(d, &mut bud).map_err(|e| e.to_string().chars().take(900).collect::<String>());
    if std::env::var_os("SANDBLASTER_OPT_TIMING").is_some() {
        eprintln!("opt: timing {name}: outlined {t_outl:?}, proof built {:?}, committed {:?} ({} steps)", t_built - t_outl, t0.elapsed() - t_built, budgets.steps - bud.steps);
    }
    r
}
