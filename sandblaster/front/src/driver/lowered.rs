//! The optimizer on lifted code (DESIGN.md §2.1 "lifted modules", §8.2;
//! SEMANTICS.md §19): lowering residuals back into the source file, and
//! the **lifted round trip** that checks them.
//!
//! A lifted module is verified as written, and the always-on optimizer
//! runs on its lifted meaning like on any crate: every function gets its
//! kernel-checked residual (`opt::optimize`). Printing the whole lifted
//! model is no use to the host (it is state passing over the buffer
//! model), so instead each **source function** whose residual is cheaper is
//! rewritten in place, in the source's own dialect:
//!
//! 1. **Candidates.** A top-level free function of the lifted file that is
//!    not generic, takes no `&mut`/`impl` parameter except at most one
//!    `buf: &mut impl BufMut` (then without a result: the lift reads it as
//!    a `Seq<u8>` returned as the value), and whose lifted item was
//!    specialized. Its residual must be at least 3%
//!    cheaper than the source under the portable cost model (the
//!    optimizer's selection gate, `cost::model::beats`), else the source
//!    text stays.
//! 2. **Lowering** ([`crate::lower`], untrusted): the residual body becomes
//!    a private helper `__sandblaster_opt_<f>` (and each optimizer helper it
//!    calls, `__sandblaster_opt_<helper>`), appended to the file (a `BufMut`
//!    state as `buf.put_u8(..)` / `buf.put_slice(..)` calls); the source
//!    function keeps its signature text and its body becomes the call
//!    `{ __sandblaster_opt_<f>(params..) }`.
//! 3. **The lifted round trip.** The source file plus, for each candidate, a
//!    copy of the rewritten function under the name `__sandblaster_check__<f>`
//!    (same signature text, the new body) plus the helpers is read back by
//!    the same front end and **lift** that read the source (TCB,
//!    SEMANTICS.md §19), and the new items are elaborated in generated mode
//!    (every proof slot `Erased`, nothing added to the kernel) against the
//!    verified environment. Then, in all relevant positions
//!    (`Env::alpha_eq_relevant` after erasing irrelevant binders, the
//!    codegen round trip's comparison, modulo only `let x = v; x` ≡ `v`,
//!    the lift's reading of a last state update): every helper equals its residual
//!    (`__sandblaster_opt_<f>` the residual of `f`, the others their
//!    optimizer helper); the copy's type equals the source function's type;
//!    and the copy's body is exactly the delegation `λ x̄. r_f x̄` to the
//!    residual. A function failing any of it keeps its source text (and the
//!    check runs again on the rest; a second failure lowers nothing).
//! 4. **Emission.** The rewritten function in the emitted file is the copy's
//!    text under the source name (the body never names the function: no
//!    lowered function is recursive), in the same module scope, so it means
//!    what the copy means: `r_f`, which the optimizer's kernel-checked link
//!    (`Link::Conversion` or `r_f::equiv`) proves equal to the source
//!    function's lifted meaning.
//!
//! When nothing qualifies the emitted file is the source as-is: the
//! optimizer never makes a lifted module slower or different without a
//! cheaper, checked residual.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use sandblaster_kernel::term::{GlobalId, Term};

use crate::elab::Output;
use crate::hir::{Crate, ItemId};
use crate::lift::LiftedInfo;
use crate::loader::MemFs;
use crate::lower::{self, Names};
use crate::opt::{OptOptions, Optimized, Outcome};

use super::Checked;

/// The prefix of every helper the lowering adds to a lifted file.
pub const HELPER_PREFIX: &str = "__sandblaster_opt_";
/// The prefix of the round trip's copies (never emitted).
pub const CHECK_PREFIX: &str = "__sandblaster_check__";

/// What became of one source function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LowerOutcome {
    /// Rewritten: the rung of the residual, its cost and the source's
    /// (portable model, milli-cycles), and the helpers added.
    Lowered { rung: String, cost_source: u64, cost_residual: u64, helpers: Vec<String> },
    /// The source text stays, and why.
    Kept(String),
}

/// One source function of the lifted file and its outcome.
#[derive(Clone, Debug)]
pub struct LowerRecord {
    pub function: String,
    pub outcome: LowerOutcome,
}

/// The result of [`lower_lifted`].
#[derive(Clone, Debug, Default)]
pub struct LoweredModule {
    /// The emitted source text after its leading `//!` lines (the source
    /// as-is when nothing was lowered).
    pub body: String,
    pub records: Vec<LowerRecord>,
    /// Definitions compared by the lifted round trip.
    pub compared: usize,
    /// A failure of the whole step (front end of the round trip, generated
    /// mode): nothing is lowered, the source is emitted as-is.
    pub note: Option<String>,
    /// Wall-clock milliseconds of the optimizer and of the lowering with
    /// its round trip (set by the build; `*-timing.json` only).
    pub optimizer_ms: u128,
    pub lowering_ms: u128,
}

impl LoweredModule {
    /// The `lifted_optimizer` record of the build report (deterministic:
    /// no timings).
    pub fn json(&self) -> crate::json::Json {
        use crate::json::Json;
        let mut j = Json::obj();
        j.num("rewritten", self.lowered() as i64);
        j.num("round_trip_compared", self.compared as i64);
        if let Some(n) = &self.note {
            j.str("note", n);
        }
        let fns = self
            .records
            .iter()
            .map(|r| {
                let mut o = Json::obj();
                o.str("function", &r.function);
                match &r.outcome {
                    LowerOutcome::Lowered { rung, cost_source, cost_residual, helpers } => {
                        o.str("outcome", "rewritten");
                        o.str("rung", rung);
                        o.num("cost_source_mc", *cost_source as i64);
                        o.num("cost_residual_mc", *cost_residual as i64);
                        o.put("helpers", Json::Arr(helpers.iter().map(|h| Json::string(h)).collect()));
                    }
                    LowerOutcome::Kept(why) => {
                        o.str("outcome", "source kept");
                        o.str("reason", why);
                    }
                }
                o
            })
            .collect();
        j.put("functions", Json::Arr(fns));
        j
    }

    /// The number of rewritten functions.
    pub fn lowered(&self) -> usize {
        self.records.iter().filter(|r| matches!(r.outcome, LowerOutcome::Lowered { .. })).count()
    }
}

/// A top-level function of the source file.
#[derive(Clone, Debug)]
struct SourceFn {
    name: String,
    /// Byte offsets: end of the name, start and end of the body block.
    ident_end: usize,
    body: (usize, usize),
    params: Vec<String>,
    /// The index of its one `buf: &mut impl BufMut` parameter (state
    /// passing, SEMANTICS.md §19.1), if any.
    state: Option<usize>,
    /// Why it cannot be rewritten (generic, state parameters, ...).
    refused: Option<String>,
}

/// Byte offset of a `proc_macro2` line/column position in `text`.
fn offset(text: &str, line_starts: &[usize], lc: proc_macro2::LineColumn) -> Option<usize> {
    let ls = *line_starts.get(lc.line.checked_sub(1)?)?;
    let line = &text[ls..];
    let mut chars = line.char_indices();
    let mut at = 0usize;
    for _ in 0..lc.column {
        let (_, c) = chars.next()?;
        at += c.len_utf8();
    }
    Some(ls + at)
}

fn line_starts(text: &str) -> Vec<usize> {
    let mut v = vec![0];
    for (i, b) in text.bytes().enumerate() {
        if b == b'\n' {
            v.push(i + 1);
        }
    }
    v
}

/// The top-level functions of the source file with their positions.
fn source_fns(text: &str) -> Result<Vec<SourceFn>, String> {
    let file = syn::parse_file(text).map_err(|e| format!("the lifted source does not parse: {e}"))?;
    let ls = line_starts(text);
    let mut out = Vec::new();
    for it in &file.items {
        let syn::Item::Fn(f) = it else { continue };
        let pos = |s: proc_macro2::Span| (offset(text, &ls, s.start()), offset(text, &ls, s.end()));
        let (Some(_), Some(ident_end)) = pos(f.sig.ident.span()) else { continue };
        let (Some(b0), Some(b1)) = pos(f.block.brace_token.span.join()) else { continue };
        if !text[b0..].starts_with('{') || !text[..b1].ends_with('}') {
            continue;
        }
        let mut params = Vec::new();
        let mut refused = None;
        if !f.sig.generics.params.is_empty() || f.sig.generics.where_clause.is_some() {
            refused = refused.or(Some("a generic source function (its instances would need a type dispatch the lift reads; FRICTION)".to_string()));
        }
        if f.sig.constness.is_some() || f.sig.asyncness.is_some() || f.sig.unsafety.is_some() || f.sig.abi.is_some() || f.sig.variadic.is_some() {
            refused = refused.or(Some("a `const`, `async`, `unsafe` or `extern` function".into()));
        }
        let mut state = None;
        for (k, a) in f.sig.inputs.iter().enumerate() {
            match a {
                syn::FnArg::Receiver(_) => refused = refused.or(Some("a method".into())),
                syn::FnArg::Typed(pt) => {
                    let ty = quote::ToTokens::to_token_stream(&*pt.ty).to_string();
                    if ty == "& mut impl BufMut" && state.is_none() && f.sig.output == syn::ReturnType::Default {
                        state = Some(k);
                    } else if ty.contains("impl") || ty.contains("mut") || ty.contains("dyn") {
                        refused = refused.or(Some("a parameter with state other than one `&mut impl BufMut` of a function without a result (`&mut self`, `impl Buf`, a returned value beside the state): lowering of that state passing is not built yet".into()));
                    }
                    match &*pt.pat {
                        syn::Pat::Ident(pi) if pi.by_ref.is_none() && pi.subpat.is_none() => params.push(pi.ident.to_string()),
                        _ => refused = refused.or(Some("a parameter with a pattern".into())),
                    }
                }
            }
        }
        if f.sig.output != syn::ReturnType::Default && quote::ToTokens::to_token_stream(&f.sig.output).to_string().contains("impl") {
            refused = refused.or(Some("an `impl Trait` return type".into()));
        }
        out.push(SourceFn { name: f.sig.ident.to_string(), ident_end, body: (b0, b1), params, state, refused });
    }
    Ok(out)
}

/// The module path (`crate::m`) of the lifted module read from `file`.
fn module_path(pv: &Crate, info: &LiftedInfo) -> Option<String> {
    pv.modules.iter().find(|m| m.file == info.file && !m.ghost).map(|m| m.path.to_string())
}

/// Portable costs of printed functions (callees at their own cost).
struct Costs<'a> {
    krate: &'a Crate,
    model: crate::opt::cost::model::SetModel,
    memo: std::cell::RefCell<HashMap<ItemId, u64>>,
    active: std::cell::RefCell<HashSet<ItemId>>,
}

impl Costs<'_> {
    fn of(&self, id: ItemId) -> u64 {
        if let Some(c) = self.memo.borrow().get(&id) {
            return *c;
        }
        let call = self.model.tables.first().map(|t| t.op(crate::opt::cost::tables::Op::Call).lat).unwrap_or(0);
        // a host buffer operation: a call on both sides (its model, a ghost
        // sequence operation, is not what runs)
        if crate::opt::drive::KEPT_LIFT_MODEL.contains(&self.krate.item(id).path.to_string().as_str()) {
            return call;
        }
        if !self.active.borrow_mut().insert(id) {
            return call;
        }
        let c = match self.krate.fn_def(id) {
            Some(f) => self.model.fn_cost(self.krate, f, &|cid| Some(self.of(cid))),
            None => 0,
        };
        self.active.borrow_mut().remove(&id);
        self.memo.borrow_mut().insert(id, c);
        c
    }
}

/// One candidate after lowering (before the round trip).
struct Candidate {
    src: SourceFn,
    /// The lifted item (print view id = source id).
    item: ItemId,
    orig_global: GlobalId,
    residual_global: GlobalId,
    rung: String,
    cost_source: u64,
    cost_residual: u64,
    /// `(print-view item, emitted helper name)`, the entry first.
    helpers: Vec<(ItemId, String)>,
    /// The rewritten body: `{ __sandblaster_opt_<f>(params..) }`.
    entry: String,
}

/// Lowers the cheaper residuals of the lifted module `info` into its source
/// text and checks them by the lifted round trip (module docs). `root` is
/// the DSL root the front end read. Never fails: a function that does not
/// qualify or does not pass keeps its source text (the reason is recorded).
pub fn lower_lifted(c: &Checked, root: &Path, out: &mut Output, o: &Optimized, opts: &OptOptions, info: &LiftedInfo) -> LoweredModule {
    lower_lifted_impl(c, root, out, o, opts, info, None)
}

/// A simulated fault of the (untrusted) lowering printer, for the
/// must-reject suite: the lifted round trip must reject every one, so the
/// function keeps its source text. Production builds have no way to inject
/// one (the entry point is compiled only with the `opt-test-hooks`
/// feature).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LowerFault {
    /// The first `<` of a helper becomes `<=`.
    FlipComparison,
    /// The rewritten body passes its parameters in reverse order.
    SwapArgs,
    /// The first `1u32` literal of a helper becomes `2u32`.
    WrongConstant,
    /// The first `.wrapping_add(..)` of a helper is dropped (its receiver
    /// stays).
    DropOperation,
    /// The rewritten body of the first candidate calls the entry helper of
    /// the second one.
    CrossEntry,
    /// The first two consecutive buffer calls of a state helper are
    /// swapped (the bytes go out in the other order).
    SwapBufferCalls,
    /// The last buffer call of a state helper is dropped.
    DropBufferCall,
}

/// [`lower_lifted`] with a simulated printer fault (tests only).
#[cfg(any(test, feature = "opt-test-hooks"))]
pub fn lower_lifted_with_fault(c: &Checked, root: &Path, out: &mut Output, o: &Optimized, opts: &OptOptions, info: &LiftedInfo, fault: LowerFault) -> LoweredModule {
    lower_lifted_impl(c, root, out, o, opts, info, Some(fault))
}

/// Applies a printer fault to the printed candidates.
fn inject(fault: LowerFault, printed: &mut [(Candidate, Vec<(ItemId, String, String)>)]) {
    fn first_in_helpers(printed: &mut [(Candidate, Vec<(ItemId, String, String)>)], from: &str, to: &str) {
        for (_, texts) in printed.iter_mut() {
            for (_, _, t) in texts.iter_mut() {
                if let Some(at) = t.find(from) {
                    t.replace_range(at..at + from.len(), to);
                    return;
                }
            }
        }
    }
    match fault {
        LowerFault::FlipComparison => first_in_helpers(printed, " < ", " <= "),
        LowerFault::WrongConstant => first_in_helpers(printed, "1u32", "2u32"),
        LowerFault::DropOperation => {
            for (_, texts) in printed.iter_mut() {
                for (_, _, t) in texts.iter_mut() {
                    if let Some(at) = t.find(".wrapping_add(") {
                        let rest = &t[at + ".wrapping_add(".len()..];
                        let mut depth = 1;
                        let mut end = None;
                        for (i, ch) in rest.char_indices() {
                            match ch {
                                '(' => depth += 1,
                                ')' => {
                                    depth -= 1;
                                    if depth == 0 {
                                        end = Some(i);
                                        break;
                                    }
                                }
                                _ => {}
                            }
                        }
                        if let Some(e) = end {
                            t.replace_range(at..at + ".wrapping_add(".len() + e + 1, "");
                            return;
                        }
                    }
                }
            }
        }
        LowerFault::SwapArgs => {
            if let Some((cd, _)) = printed.first_mut() {
                let mut ps = cd.src.params.clone();
                ps.reverse();
                cd.entry = format!("{{\n    {HELPER_PREFIX}{}({})\n}}", cd.src.name, ps.join(", "));
            }
        }
        LowerFault::SwapBufferCalls | LowerFault::DropBufferCall => {
            let is_call = |l: &str| l.trim_start().starts_with("l") && (l.contains(".put_u8(") || l.contains(".put_slice("));
            for (_, texts) in printed.iter_mut() {
                for (_, _, t) in texts.iter_mut() {
                    let mut lines: Vec<String> = t.lines().map(String::from).collect();
                    let calls: Vec<usize> = (0..lines.len()).filter(|&i| is_call(&lines[i])).collect();
                    let done = match fault {
                        LowerFault::SwapBufferCalls => match calls.windows(2).find(|w| w[1] == w[0] + 1) {
                            Some(w) => {
                                lines.swap(w[0], w[1]);
                                true
                            }
                            None => false,
                        },
                        _ => match calls.last() {
                            Some(&i) => {
                                lines.remove(i);
                                true
                            }
                            None => false,
                        },
                    };
                    if done {
                        *t = lines.join("\n") + "\n";
                        return;
                    }
                }
            }
        }
        LowerFault::CrossEntry => {
            if printed.len() >= 2 {
                let other = printed[1].0.src.name.clone();
                let cd = &mut printed[0].0;
                cd.entry = format!("{{\n    {HELPER_PREFIX}{other}({})\n}}", cd.src.params.join(", "));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn lower_lifted_impl(c: &Checked, root: &Path, out: &mut Output, o: &Optimized, opts: &OptOptions, info: &LiftedInfo, fault: Option<LowerFault>) -> LoweredModule {
    let Some(src) = c.sm.get(info.file) else {
        return LoweredModule { note: Some("the lifted source is not in the source map".into()), ..Default::default() };
    };
    let text = src.text.clone();
    let (docs, _) = super::lifted::split_docs(&text);
    let docs_len = docs.len();
    let as_is = |note: Option<String>, records: Vec<LowerRecord>| LoweredModule { body: text[docs_len..].to_string(), records, compared: 0, note, ..Default::default() };
    let (Some(krate), pv) = (c.krate.as_ref(), &o.print) else {
        return as_is(Some("no crate".into()), vec![]);
    };
    let fns = match source_fns(&text) {
        Ok(f) => f,
        Err(e) => return as_is(Some(e), vec![]),
    };
    let Some(mpath) = module_path(pv, info) else {
        return as_is(Some("the lifted module has no module in the crate".into()), vec![]);
    };
    let source_names: HashSet<String> = fns.iter().map(|f| f.name.clone()).collect();
    let by_path: HashMap<String, ItemId> = pv.items.iter().map(|it| (it.path.to_string(), it.id)).collect();
    let src_costs = Costs { krate, model: crate::opt::cost::model::SetModel::portable(krate.target.arch.name(), &opts.tuning), memo: Default::default(), active: Default::default() };
    let res_costs = Costs { krate: pv, model: crate::opt::cost::model::SetModel::portable(krate.target.arch.name(), &opts.tuning), memo: Default::default(), active: Default::default() };
    let mut records: Vec<LowerRecord> = Vec::new();
    let mut cands: Vec<Candidate> = Vec::new();
    for sf in &fns {
        let path = format!("{mpath}::{}", sf.name);
        let mut keep = |why: String| records.push(LowerRecord { function: path.clone(), outcome: LowerOutcome::Kept(why) });
        if let Some(r) = &sf.refused {
            keep(r.clone());
            continue;
        }
        let Some(&id) = by_path.get(&path) else {
            keep("no lifted item of this name (dropped by the lift)".into());
            continue;
        };
        if id.0 as usize >= krate.items.len() || krate.item(id).path.to_string() != path {
            keep("the lifted item is not a source item".into());
            continue;
        }
        let Some(rep) = o.fns.iter().find(|f| f.item == id && f.set.is_none()) else {
            keep("the optimizer has no result for it".into());
            continue;
        };
        let residual_global = match &rep.outcome {
            Outcome::Specialized { .. } => match o.targets.get(&id) {
                Some((_, r)) => *r,
                None => {
                    keep("specialized, but not printed".into());
                    continue;
                }
            },
            Outcome::Unspecialized { reason, .. } => {
                keep(format!("not specialized: {reason}"));
                continue;
            }
        };
        let Some(&orig_global) = out.fn_globals.get(&id) else {
            keep("not kernel-checked".into());
            continue;
        };
        let (cs, cr) = (src_costs.of(id), res_costs.of(id));
        if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() {
            let names = source_fn_names(&by_path, &mpath, &source_names, krate);
            let t = match sf.state {
                Some(k) => lower::lower_fn_state(pv, id, "trace", &names, k),
                None => lower::lower_fn(pv, id, "trace", &names),
            };
            eprintln!("lower: `{path}` costs {cr} (source {cs}); residual as Rust: {}", t.map(|l| l.text).unwrap_or_else(|e| format!("not printable: {e}")));
        }
        if !crate::opt::cost::model::beats(cr, cs) {
            keep(format!("the residual is not 3% cheaper than the source (portable model: {} vs {} milli-cycles)", cr, cs));
            continue;
        }
        // the helper closure and the names the lowered code uses
        let names = source_fn_names(&by_path, &mpath, &source_names, krate);
        let mut helpers: Vec<(ItemId, String)> = vec![(id, format!("{HELPER_PREFIX}{}", sf.name))];
        let mut queue = vec![id];
        let mut bad: Option<String> = None;
        while let Some(h) = queue.pop() {
            for cid in lower::callees(pv, h) {
                if names.fns.contains_key(&cid) && cid != id {
                    continue;
                }
                // the buffer model: printed as `BufMut` calls in state mode
                if sf.state.is_some() && crate::opt::drive::KEPT_LIFT_MODEL.contains(&pv.item(cid).path.to_string().as_str()) {
                    continue;
                }
                if (cid.0 as usize) < krate.items.len() {
                    bad = Some(format!("the residual calls `{}`, which the lowered code cannot name", pv.item(cid).path));
                    break;
                }
                if helpers.iter().any(|(x, _)| *x == cid) {
                    continue;
                }
                helpers.push((cid, format!("{HELPER_PREFIX}{}", pv.item(cid).name)));
                queue.push(cid);
            }
        }
        if let Some(b) = bad {
            keep(b);
            continue;
        }
        let entry = format!("{{\n    {HELPER_PREFIX}{}({})\n}}", sf.name, sf.params.join(", "));
        cands.push(Candidate { src: sf.clone(), item: id, orig_global, residual_global, rung: rep.rung.map(|r| r.name().to_string()).unwrap_or_default(), cost_source: cs, cost_residual: cr, helpers, entry });
    }
    // print every candidate's helpers
    let mut printed: Vec<(Candidate, Vec<(ItemId, String, String)>)> = Vec::new();
    for cd in cands {
        let mut names = source_fn_names(&by_path, &mpath, &source_names, krate);
        for (h, n) in &cd.helpers {
            if *h != cd.item {
                names.fns.insert(*h, n.clone());
            }
        }
        let mut texts = Vec::new();
        let mut err = self_reference(&cd.src.name, &cd.entry);
        for (h, n) in &cd.helpers {
            if err.is_some() {
                break;
            }
            if text.contains(n.as_str()) {
                err = Some(format!("the source already uses the name `{n}`"));
                break;
            }
            let printed = match cd.src.state {
                Some(k) if *h == cd.item => lower::lower_fn_state(pv, *h, n, &names, k),
                _ => lower::lower_fn(pv, *h, n, &names),
            };
            match printed {
                Ok(l) => texts.push((*h, n.clone(), l.text)),
                Err(e) => {
                    err = Some(format!("the residual cannot be printed as Rust: {e}"));
                    break;
                }
            }
        }
        match err {
            Some(e) => records.push(LowerRecord { function: format!("{mpath}::{}", cd.src.name), outcome: LowerOutcome::Kept(e) }),
            None => printed.push((cd, texts)),
        }
    }
    if printed.is_empty() {
        return as_is(None, sorted(records));
    }
    if let Some(f) = fault {
        inject(f, &mut printed);
    }
    // the lifted round trip, then once more on the functions that passed
    let mut compared = 0;
    let mut note = None;
    for round in 0..2 {
        match round_trip(c, root, out, o, &text, &mpath, info, &printed) {
            Err(e) => {
                note = Some(format!("lifted round trip: {e}"));
                for (cd, _) in printed.drain(..) {
                    records.push(LowerRecord { function: format!("{mpath}::{}", cd.src.name), outcome: LowerOutcome::Kept(format!("the lifted round trip failed: {e}")) });
                }
                break;
            }
            Ok((verdicts, n)) => {
                let all_ok = verdicts.values().all(|v| v.is_ok());
                if all_ok {
                    compared = n;
                    break;
                }
                let mut keep = Vec::new();
                for (cd, texts) in printed.drain(..) {
                    match verdicts.get(&cd.src.name) {
                        Some(Ok(_)) => keep.push((cd, texts)),
                        Some(Err(e)) => records.push(LowerRecord { function: format!("{mpath}::{}", cd.src.name), outcome: LowerOutcome::Kept(format!("the lifted round trip rejected the lowered code: {e}")) }),
                        None => records.push(LowerRecord { function: format!("{mpath}::{}", cd.src.name), outcome: LowerOutcome::Kept("the lifted round trip did not compare it".into()) }),
                    }
                }
                if round == 1 {
                    // a second failure: nothing is lowered
                    for (cd, _) in keep.drain(..) {
                        records.push(LowerRecord { function: format!("{mpath}::{}", cd.src.name), outcome: LowerOutcome::Kept("the lifted round trip failed twice; nothing is lowered".into()) });
                    }
                }
                printed = keep;
                if printed.is_empty() {
                    break;
                }
            }
        }
    }
    if printed.is_empty() {
        return LoweredModule { compared: 0, ..as_is(note, sorted(records)) };
    }
    // emission: the rewritten bodies (last first) and the helpers
    let mut body = text.clone();
    let mut edits: Vec<(usize, usize, String)> = printed.iter().map(|(cd, _)| (cd.src.body.0, cd.src.body.1, entry_body(cd))).collect();
    edits.sort_by_key(|e| std::cmp::Reverse(e.0));
    for (a, b, t) in edits {
        body.replace_range(a..b, &t);
    }
    if !body.ends_with('\n') {
        body.push('\n');
    }
    body.push_str(&helpers_section(&printed));
    for (cd, texts) in &printed {
        records.push(LowerRecord {
            function: format!("{mpath}::{}", cd.src.name),
            outcome: LowerOutcome::Lowered { rung: cd.rung.clone(), cost_source: cd.cost_source, cost_residual: cd.cost_residual, helpers: texts.iter().map(|(_, n, _)| n.clone()).collect() },
        });
    }
    LoweredModule { body: body[docs_len..].to_string(), records: sorted(records), compared, note, ..Default::default() }
}

/// The source functions of the lifted module by their names in the file
/// (the lowered code calls them by these names).
fn source_fn_names(by_path: &HashMap<String, ItemId>, mpath: &str, source_names: &HashSet<String>, krate: &Crate) -> Names {
    let mut names = Names::default();
    let prefix = format!("{mpath}::");
    for (n, &i) in by_path {
        if let Some(f) = n.strip_prefix(&prefix)
            && source_names.contains(f)
            && (i.0 as usize) < krate.items.len()
        {
            names.fns.insert(i, f.to_string());
        }
    }
    names
}

fn sorted(mut v: Vec<LowerRecord>) -> Vec<LowerRecord> {
    v.sort_by(|a, b| a.function.cmp(&b.function));
    v
}

/// Why the rewritten body `entry` of `name` could mean something else in
/// the emitted file than in the round trip's copy: it names the function
/// itself (the copy has another name) or a copy. `None`: it names neither,
/// so, with the same signature text in the same module, the emitted
/// function and the copy read back the same (DESIGN.md §2.1).
fn self_reference(name: &str, entry: &str) -> Option<String> {
    let block: syn::Block = match syn::parse_str(entry) {
        Ok(b) => b,
        Err(e) => return Some(format!("the rewritten body does not parse: {e}")),
    };
    let mut ids: Vec<String> = Vec::new();
    fn walk(ts: proc_macro2::TokenStream, ids: &mut Vec<String>) {
        for t in ts {
            match t {
                proc_macro2::TokenTree::Ident(i) => ids.push(i.to_string()),
                proc_macro2::TokenTree::Group(g) => walk(g.stream(), ids),
                _ => {}
            }
        }
    }
    walk(quote::ToTokens::to_token_stream(&block), &mut ids);
    if ids.iter().any(|i| i == name) {
        return Some(format!("the rewritten body names `{name}` itself"));
    }
    if ids.iter().any(|i| i.starts_with(CHECK_PREFIX)) {
        return Some("the rewritten body names a round-trip copy".into());
    }
    None
}

/// The rewritten body of a source function: the call of its entry helper.
fn entry_body(cd: &Candidate) -> String {
    cd.entry.clone()
}

/// The appended helpers (each once, in candidate order).
fn helpers_section(printed: &[(Candidate, Vec<(ItemId, String, String)>)]) -> String {
    let mut s = String::from("\n// sandblaster: the optimizer's residuals of the functions above whose bodies call them, lowered to\n// Rust and checked by the lifted round trip (DESIGN.md §2.1).\n");
    let mut seen: HashSet<String> = HashSet::new();
    for (_, texts) in printed {
        for (_, n, t) in texts {
            if seen.insert(n.clone()) {
                s.push('\n');
                s.push_str(t);
            }
        }
    }
    s
}

/// The check copy of a candidate: the source item from `fn` with the name
/// `__sandblaster_check__<f>` and the rewritten body.
fn check_copy(text: &str, cd: &Candidate) -> String {
    format!("fn {CHECK_PREFIX}{}{} {}\n", cd.src.name, &text[cd.src.ident_end..cd.src.body.0].trim_end(), entry_body(cd))
}

/// Runs the lifted round trip on `printed`; per source function name, `Ok`
/// or the first failure. `Err` fails the whole step.
#[allow(clippy::too_many_arguments)]
fn round_trip(c: &Checked, root: &Path, out: &mut Output, o: &Optimized, text: &str, mpath: &str, info: &LiftedInfo, printed: &[(Candidate, Vec<(ItemId, String, String)>)]) -> Result<(BTreeMap<String, Result<(), String>>, usize), String> {
    // 1. the source, the copies and the helpers, read by the same front end
    let mut check_text = text.to_string();
    if !check_text.ends_with('\n') {
        check_text.push('\n');
    }
    for (cd, _) in printed {
        check_text.push('\n');
        check_text.push_str(&check_copy(text, cd));
    }
    check_text.push_str(&helpers_section(printed));
    let lifted_path = c.sm.path(info.file).to_path_buf();
    let mut fs = MemFs::new();
    for (_, f) in c.sm.files() {
        fs.insert(&f.path, f.text.clone());
    }
    fs.insert(&lifted_path, check_text);
    let krate = c.krate.as_ref().ok_or("no crate")?;
    let c2 = super::check(root, &fs, &krate.target);
    if !c2.ok() {
        let first = c2.diags.list.iter().find(|d| d.severity == crate::diag::Severity::Error).map(|d| d.render(&c2.sm)).unwrap_or_default();
        return Err(format!("the front end rejects the lowered code: {}", first.lines().next().unwrap_or("")));
    }
    let k2 = c2.krate.as_ref().ok_or("no crate")?;
    // 2. the ids of the read-back crate, mapped to the verified environment
    // by path (the new items have no counterpart)
    let pv = &o.print;
    let by_path: HashMap<String, ItemId> = pv.items.iter().map(|it| (it.path.to_string(), it.id)).collect();
    let mut fn_globals = HashMap::new();
    let mut adts = HashMap::new();
    for it in &k2.items {
        let p = it.path.to_string();
        if let Some(pid) = by_path.get(&p) {
            if std::mem::discriminant(&pv.item(*pid).kind) != std::mem::discriminant(&it.kind) {
                return Err(format!("`{p}` is a different kind of item when read back"));
            }
            if let Some(g) = out.fn_globals.get(pid) {
                fn_globals.insert(it.id, *g);
            }
            if let Some(i) = out.adts.get(pid) {
                adts.insert(it.id, *i);
            }
        }
    }
    // 3. targets and elaboration order: helpers callee-first, then copies
    let mut targets: HashMap<String, (GlobalId, GlobalId)> = HashMap::new();
    let mut order: Vec<ItemId> = Vec::new();
    let mut owner: HashMap<String, String> = HashMap::new(); // kernel name → source function
    let mut expect: Vec<(String, GlobalId, String)> = Vec::new(); // helper kernel name, compare global, function
    let mut copies: Vec<(String, &Candidate)> = Vec::new();
    for (cd, texts) in printed {
        for (h, n, _) in texts.iter().rev() {
            let kname = format!("{mpath}::{n}");
            let Some(id2) = k2.find(&kname) else { return Err(format!("the helper `{kname}` is not in the read-back crate")) };
            let (refer, compare) = if *h == cd.item { (cd.residual_global, cd.residual_global) } else { *o.targets.get(h).ok_or_else(|| format!("the helper `{}` has no optimized definition", pv.item(*h).path))? };
            if targets.insert(kname.clone(), (refer, compare)).is_none() {
                order.push(id2);
                expect.push((kname.clone(), compare, cd.src.name.clone()));
            }
            owner.entry(kname).or_insert_with(|| cd.src.name.clone());
        }
    }
    for (cd, _) in printed {
        let kname = format!("{mpath}::{CHECK_PREFIX}{}", cd.src.name);
        let Some(id2) = k2.find(&kname) else { return Err(format!("the copy `{kname}` is not in the read-back crate")) };
        targets.insert(kname.clone(), (cd.orig_global, cd.orig_global));
        order.push(id2);
        owner.insert(kname.clone(), cd.src.name.clone());
        copies.push((kname, cd));
    }
    // helpers must come callee-first: sort by the read-back call graph
    order = callee_first(k2, &order);
    // 4. generated mode against the verified environment
    let saved_globals = std::mem::replace(&mut out.fn_globals, fn_globals);
    let saved_adts = std::mem::replace(&mut out.adts, adts);
    let r = crate::elab::generated::generated(out, k2, &order, targets);
    out.fn_globals = saved_globals;
    out.adts = saved_adts;
    let (defs, errors) = r.map_err(|e| format!("generated-mode elaboration: {e}"))?;
    let mut verdicts: BTreeMap<String, Result<(), String>> = printed.iter().map(|(cd, _)| (cd.src.name.clone(), Ok(()))).collect();
    let fail = |v: &mut BTreeMap<String, Result<(), String>>, f: &str, e: String| {
        if let Some(x) = v.get_mut(f)
            && x.is_ok()
        {
            *x = Err(e);
        }
    };
    for (id, e) in errors {
        if id.0 == u32::MAX {
            return Err(format!("generated-mode elaboration: {e}"));
        }
        let n = k2.item(id).path.to_string();
        match owner.get(&n) {
            Some(f) => fail(&mut verdicts, f, format!("`{n}`: {e}")),
            None => return Err(format!("generated-mode elaboration of `{n}`: {e}")),
        }
    }
    let got: HashMap<&str, &crate::elab::generated::GenDef> = defs.iter().map(|d| (d.name.as_str(), d)).collect();
    for (kname, compare, f) in &expect {
        match got.get(kname.as_str()) {
            None => fail(&mut verdicts, f, format!("`{kname}` was not elaborated")),
            Some(d) => {
                if let Err(e) = crate::roundtrip::compare_with(out, d, *compare, &let_var_elim) {
                    fail(&mut verdicts, f, format!("`{kname}` does not match its residual: {e}"));
                }
            }
        }
    }
    for (kname, cd) in &copies {
        match got.get(kname.as_str()) {
            None => fail(&mut verdicts, &cd.src.name, format!("`{kname}` was not elaborated")),
            Some(d) => {
                if let Err(e) = is_delegation(out, d, cd) {
                    fail(&mut verdicts, &cd.src.name, format!("the rewritten `{}`: {e}", cd.src.name));
                }
            }
        }
    }
    Ok((verdicts, expect.len() + copies.len()))
}

/// `t` with every relevant `let x = v; x` replaced by `v` (bottom-up): the
/// lift reads a last state update `buf.put_u8(e);` of a state-passing
/// function as `{ let buf' = put(buf, e); buf' }` where the residual has
/// `put(buf, e)`. Evaluating `v` once and returning it is the same program
/// either way (nothing moves across another operation), so the lifted
/// round trip compares modulo this rule and nothing else.
fn let_var_elim(t: &sandblaster_kernel::term::Tm) -> sandblaster_kernel::term::Tm {
    crate::elab::tm::map_post(t, 0, &mut |n, _| match &*n {
        Term::Let { val, body, .. } if matches!(&**body, Term::Var(i) if i.0 == 0) => Some(val.clone()),
        _ => Some(n),
    })
    .unwrap_or_else(|| t.clone())
}

/// `order` sorted callee-first by the calls between its items (a cycle
/// keeps the given order; generated mode then reports the missing callee).
fn callee_first(k: &Crate, order: &[ItemId]) -> Vec<ItemId> {
    let set: HashSet<ItemId> = order.iter().copied().collect();
    let mut done: Vec<ItemId> = Vec::new();
    let mut active: HashSet<ItemId> = HashSet::new();
    fn visit(k: &Crate, id: ItemId, set: &HashSet<ItemId>, done: &mut Vec<ItemId>, active: &mut HashSet<ItemId>) {
        if done.contains(&id) || !active.insert(id) {
            return;
        }
        for c in lower::callees(k, id) {
            if set.contains(&c) {
                visit(k, c, set, done, active);
            }
        }
        done.push(id);
    }
    for &id in order {
        visit(k, id, &set, &mut done, &mut active);
    }
    done
}

/// Whether the read-back copy `d` of a rewritten function has the source
/// function's type and is exactly `λ x̄. r_f x̄` (after erasing irrelevant
/// binders): the delegation to the residual.
fn is_delegation(out: &Output, d: &crate::elab::generated::GenDef, cd: &Candidate) -> Result<(), String> {
    use crate::roundtrip::strip;
    let env = &out.env;
    let ty = env.global_type(cd.orig_global).ok_or("the source function has no type")?;
    if !env.alpha_eq_relevant(&strip(&d.ty), &strip(&ty), &|a, b| a == b) {
        return Err("its type differs from the source function's".into());
    }
    let mut b = strip(&d.body);
    let mut k = 0u32;
    while let Term::Lam { body, .. } = &*b {
        b = body.clone();
        k += 1;
    }
    // the lift's state passing around a call (`let s = r(..); buf = s;
    // buf`): `let x = v; x` is `v`, and a `let` of a variable renames it
    b = let_var_elim(&b);
    loop {
        let next = match &*b {
            Term::Let { val, body, .. } if matches!(&**body, Term::Var(i) if i.0 == 0) => val.clone(),
            Term::Let { val, body, .. } if matches!(&**val, Term::Var(_)) => crate::elab::tm::subst0(body, val),
            _ => break,
        };
        b = next;
    }
    let mut args = Vec::new();
    let mut h = b;
    while let Term::App { fun, arg, .. } = &*h {
        args.push(arg.clone());
        h = fun.clone();
    }
    args.reverse();
    match &*h {
        Term::Global(g) if *g == cd.residual_global => {}
        _ => return Err(format!("its body is not the call of the residual: {}", sandblaster_kernel::syntax::printer::print_term_bounded(env, &[], &strip(&d.body), 600))),
    }
    if args.len() as u32 != k {
        return Err(format!("its body passes {} argument(s) to the residual for {k} parameter(s)", args.len()));
    }
    for (j, a) in args.iter().enumerate() {
        match &**a {
            Term::Var(ix) if ix.0 == k - 1 - j as u32 => {}
            _ => return Err(format!("argument {j} of the residual call is not parameter {j}")),
        }
    }
    Ok(())
}
