//! The optimizer on lifted code (DESIGN.md §2.1 "lifted modules", §8.2;
//! SEMANTICS.md §19): lowering residuals back into the source file, and
//! the **lifted round trip** that checks them.
//!
//! A lifted module is verified as written, and the always-on optimizer
//! runs on its lifted meaning like on any crate: every function gets its
//! kernel-checked residual (`opt::optimize`). Printing the whole lifted
//! model is no use to the host (it is state passing over the buffer
//! model), so instead each **source function** whose replacement is cheaper
//! is rewritten in place, in the source's own dialect:
//!
//! 1. **Candidates.** A function of the lifted file — top level, or an
//!    associated function of an inherent or trait impl — without a
//!    receiver, whose parameters are plain values plus at most one buffer
//!    state (`buf: &mut impl BufMut` without a result, or `buf: &mut impl
//!    Buf` with or without one: the lift reads either as a `Seq<u8>`
//!    returned beside the value). Its replacement is one of:
//!    * **its residual** (`opt::optimize`), for a non-generic function;
//!    * **one residual per verified instance** for a generic function over
//!      one sealed trait (`fn size<T: UPrim>(value: T)`, instances
//!      `size__u16`, ...): a **per-type dispatch** the lift itself reads —
//!      a sealed trait `__sandblaster_dispatch_UPrim` (declared next to
//!      `UPrim` and made its supertrait, so every `T: UPrim` has it) with
//!      one method per rewritten function, implemented for every impl type
//!      of `UPrim`: a verified instance calls its lowered residual, a type
//!      declared `#[lift(unverified = ..)]` calls the original generic code
//!      (a renamed copy `__sandblaster_orig_<f>`, unchanged). The rewritten
//!      body is the method call on the by-value parameter of type `T`
//!      (`value.__sandblaster_opt_size()`), which the lift reads as that
//!      instance's impl method. All verified instances must qualify, or the
//!      function keeps its source text;
//!    * **a user-supplied alternative** named by a `#[rewrite]` lemma
//!      `f(x̄) == g(x̄)` (proven like any lemma; `g` a function of a
//!      `#[lift(opt)]` module, written by hand in the host's dialect over
//!      the original API): `g`'s own source text (and that of the
//!      alternatives it calls), renamed, is the replacement. The link `f =
//!      g` is a new kernel-checked definition `<f>::rewrite_equiv : Π x̄ (h̄
//!      : Req_f). Eq(R, f x̄ h̄, g x̄ h̄)` whose proof is the lemma applied to
//!      the binders — the kernel checks it has exactly this statement. This
//!      is **user code, not optimizer output**: its record carries
//!      [`LowerOrigin::UserRewrite`], every summary, index and report counts
//!      it apart from the optimizer's residuals, and the optimizer's own
//!      residual for `f` is still built and recorded
//!      ([`LowerRecord::optimizer_residual`]). An alternative is tried before
//!      the residual; `OptOptions::exclude_user_rewrites` (evaluation only)
//!      leaves every alternative out, the optimizer still running.
//!
//!    The replacement must be at least 3% cheaper than the source under the
//!    portable cost model (the optimizer's selection gate,
//!    `cost::model::beats`), else the source text stays. The model prices
//!    the source as rustc compiles it: the buffer model's operations and
//!    the lift prelude's functions (`crate::__lift::*`: the signed
//!    shifts/negation the lift spells out, core's methods as templates) as
//!    what they stand for (a call, one operation), never their model
//!    bodies, and a loop at its `decreases(max = N)` bound or
//!    [`LOOP_TRIPS`] iterations with its loop-carried chain on the critical
//!    path (`SetModel::fn_cost_carried`).
//! 2. **Lowering** ([`crate::lower`], untrusted): a residual body becomes a
//!    private helper `__sandblaster_opt_<f>` (and each optimizer helper it
//!    calls, `__sandblaster_opt_<helper>`), appended to the file (buffer
//!    states as `buf.put_u8(..)` / `buf.put_slice(..)` / `buf.try_get_u8()`
//!    calls); the source function keeps its signature text and its body
//!    becomes the call `{ __sandblaster_opt_<f>(params..) }` (or the
//!    dispatch call).
//! 3. **The lifted round trip.** The source file (with the dispatch
//!    declarations) plus, for each candidate, a copy of the rewritten
//!    function under the name `__sandblaster_check__<f>` (same signature
//!    text, the new body) plus the helpers and dispatch impls is read back
//!    by the same front end and **lift** that read the source (TCB,
//!    SEMANTICS.md §19), with rustc's MIR of that copy
//!    (`<stem>.roundtrip__<module>.sbmir`, checked against the copy's text
//!    by its SHA-256 like any extraction). What decides each function is the
//!    **shipped code's theorems** (`shipped_theorems`,
//!    docs/checked-structuring.md §5.13): every helper's MIR against the
//!    definition it replaces, the copy's (and a dispatch method's) MIR
//!    against the call of the replacement, and from them, along the
//!    optimizer's kernel-checked link, `L::shipped::<id>`: the literal
//!    reading of the copy's MIR returns, at sufficient fuel, exactly the
//!    source function's value (for a function that can panic, its two panic
//!    theorems), accepted by the trusted check (`mir::gate`). The copy's
//!    structured reading is not compared with the residual: it is
//!    untrusted, and the theorems are about the MIR rustc compiles, so a
//!    syntactic comparison (which refused code reading back as the same
//!    operations in another form: temporaries bound by `let`, `?` read as a
//!    test of `is_none`) adds nothing they do not decide. Only a module
//!    without MIR — none since the lift refuses a lifted exec module
//!    without `mir = ".."` — would be checked by the syntactic comparison
//!    (`compare_read_back`: the new items elaborated in generated mode, every
//!    printed helper equal to its residual in all relevant positions modulo
//!    `let x = v; x` ≡ `v` and the reader normal form, every copy the
//!    delegation `λ x̄. r x̄`). A function failing any of it keeps its source
//!    text (and the check runs again on the rest; a second failure lowers
//!    nothing).
//! 4. **Emission.** The rewritten function in the emitted file is the copy's
//!    text under the source name (the body never names the function: no
//!    lowered function is recursive), in the same module scope, so it means
//!    what the copy means: `r_f` (per instance), which the optimizer's
//!    kernel-checked link (`Link::Conversion`, `r_f::equiv` or
//!    `<f>::rewrite_equiv`) proves equal to the source function's lifted
//!    meaning.
//!
//! When nothing qualifies the emitted file is the source as-is: the
//! optimizer never makes a lifted module slower or different without a
//! cheaper, checked replacement. In place (`#[lift(in_place)]`,
//! [`lower_in_place`]) the same steps run per host file; the lowered copies
//! are written beside the record, and rustc compiles a copy where the host
//! declares the module by its lowered declaration (`driver::in_place`).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use sandblaster_kernel::term::{DefDecl, DefKind, GlobalId, Recursion as KRecursion, Rel, Term};
use sandblaster_kernel::util::mk;

use crate::elab::Output;
use crate::hir::{Crate, ExprKind, FnKind, ItemId, Recursion};
use crate::lift::LiftedInfo;
use crate::loader::MemFs;
use crate::lower::{self, Names};
use crate::opt::{OptOptions, Optimized, Outcome};

use super::Checked;

/// The prefix of every helper the lowering adds to a lifted file (and of
/// every dispatch method).
pub const HELPER_PREFIX: &str = "__sandblaster_opt_";
/// The prefix of the round trip's copies (never emitted).
pub const CHECK_PREFIX: &str = "__sandblaster_check__";
/// The prefix of the per-type dispatch trait of a sealed trait.
pub const DISPATCH_PREFIX: &str = "__sandblaster_dispatch_";
/// The prefix of the copy of a generic function's original code that the
/// dispatch calls for the instances declared unverified.
pub const ORIG_PREFIX: &str = "__sandblaster_orig_";
/// The iterations a loop is priced at when its measure has no literal
/// bound (`decreases(.., max = N)`): the cost model's default for a
/// `while` loop (`opt::cost::model`).
pub const LOOP_TRIPS: u64 = 16;

/// The start of every [`LowerOutcome::Kept`] reason of a function whose
/// lowering the lifted round trip rejected (or did not reach): a host that
/// compiles the lowered copy fails the build on it (`driver::in_place`).
pub const ROUND_TRIP_REJECTED: &str = "the lifted round trip";

/// Where the replacement of a rewritten function comes from. Only
/// [`LowerOrigin::Optimizer`] is optimizer output; a user alternative is
/// hand-written code (proven equal, but never counted as the optimizer's
/// speed: DESIGN.md principle 3, §2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LowerOrigin {
    /// The optimizer's residual (one per instance for a per-type dispatch).
    Optimizer,
    /// A user-supplied alternative named by a `#[rewrite]` lemma (a function
    /// of a `#[lift(opt)]` module).
    UserRewrite,
}

impl LowerOrigin {
    /// The name in the report JSON (`origin`).
    pub fn name(self) -> &'static str {
        match self {
            LowerOrigin::Optimizer => "optimizer",
            LowerOrigin::UserRewrite => "user_rewrite",
        }
    }
}

/// What became of one source function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LowerOutcome {
    /// Rewritten: where the replacement comes from, the rung of the
    /// residual (`Rewrite` for a user alternative), the replacement's cost
    /// and the source's (portable model, milli-cycles, summed over the
    /// instances of a generic function; `cost_residual` is the user
    /// alternative's cost for [`LowerOrigin::UserRewrite`]), the helpers
    /// added, and how (`via`: the instances of a dispatch, the lemma of a
    /// rewrite; empty for a plain residual).
    Lowered { origin: LowerOrigin, rung: String, cost_source: u64, cost_residual: u64, helpers: Vec<String>, via: String },
    /// The source text stays, and why.
    Kept(String),
}

/// One source function of the lifted file and its outcome.
#[derive(Clone, Debug)]
pub struct LowerRecord {
    pub function: String,
    pub outcome: LowerOutcome,
    /// For a function with a user `#[rewrite]` alternative: what the
    /// optimizer's own residual for it came to (built whether or not the
    /// alternative is used or excluded), so the optimizer's share stays
    /// visible beside the user code. `None` for every other function.
    pub optimizer_residual: Option<String>,
}

/// The result of [`lower_lifted`].
#[derive(Clone, Debug, Default)]
pub struct LoweredModule {
    /// The lowered source file (as displayed).
    pub file: String,
    /// The emitted source text after its leading `//!` lines (the source
    /// as-is when nothing was lowered).
    pub body: String,
    /// The source's leading `//!` lines.
    pub docs: String,
    pub records: Vec<LowerRecord>,
    /// Definitions compared by the lifted round trip.
    pub compared: usize,
    /// A failure of the whole step (front end of the round trip, generated
    /// mode): nothing is lowered, the source is emitted as-is.
    pub note: Option<String>,
    /// `#[rewrite]` lemmas of the crate that name no usable replacement,
    /// and why (the report lists them: a `#[rewrite]` lemma that is never
    /// used is a mistake worth seeing).
    pub unused_rewrites: Vec<String>,
    /// The build left every user `#[rewrite]` alternative out
    /// (`OptOptions::exclude_user_rewrites`, an evaluation-only build of
    /// the optimizer's own output).
    pub user_rewrites_excluded: bool,
    /// Wall-clock milliseconds of the optimizer and of the lowering with
    /// its round trip (set by the build; `*-timing.json` only).
    pub optimizer_ms: u128,
    pub lowering_ms: u128,
    /// A module whose bodies are read from rustc's MIR: the lifted round
    /// trip's copy of the file (the text whose MIR the round trip reads,
    /// extracted into `<stem>.roundtrip__<module>.sbmir`) and that file's
    /// name; the build writes it to `OUT_DIR/<name>-roundtrip__<module>.rs`
    /// for the extraction (`sandblaster/mirx/extract.sh --replace`).
    pub roundtrip_copy: Option<(String, String)>,
    /// A module read from MIR: the theorems of the shipped code (the
    /// copies' and helpers' MIR) the round trip proved, one note per
    /// rewritten function.
    pub shipped: Vec<String>,
    /// Tests only ([`LowerFault::CompareStructurally`]): what the syntactic
    /// comparison of a module without MIR would have refused in this module
    /// read from MIR, where it decides nothing.
    pub structural: Vec<String>,
}

impl LoweredModule {
    /// The `lifted_optimizer` record of the build report (deterministic:
    /// no timings).
    pub fn json(&self) -> crate::json::Json {
        use crate::json::Json;
        let mut j = Json::obj();
        if !self.file.is_empty() {
            j.str("file", &self.file);
        }
        j.num("rewritten", self.lowered() as i64);
        j.num("rewritten_by_optimizer", self.lowered_by(LowerOrigin::Optimizer) as i64);
        j.num("rewritten_by_user_rewrite", self.lowered_by(LowerOrigin::UserRewrite) as i64);
        if self.user_rewrites_excluded {
            j.str("user_rewrites", "excluded (evaluation-only build: OptOptions::exclude_user_rewrites)");
        }
        j.num("round_trip_compared", self.compared as i64);
        if let Some(n) = &self.note {
            j.str("note", n);
        }
        if !self.shipped.is_empty() {
            j.put("shipped_theorems", Json::Arr(self.shipped.iter().map(|n| Json::string(n)).collect()));
        }
        if !self.unused_rewrites.is_empty() {
            j.put("unused_rewrite_lemmas", Json::Arr(self.unused_rewrites.iter().map(|n| Json::string(n)).collect()));
        }
        let fns = self
            .records
            .iter()
            .map(|r| {
                let mut o = Json::obj();
                o.str("function", &r.function);
                match &r.outcome {
                    LowerOutcome::Lowered { origin, rung, cost_source, cost_residual, helpers, via } => {
                        o.str("outcome", "rewritten");
                        o.str("origin", origin.name());
                        o.str("rung", rung);
                        o.num("cost_source_mc", *cost_source as i64);
                        o.num("cost_residual_mc", *cost_residual as i64);
                        o.put("helpers", Json::Arr(helpers.iter().map(|h| Json::string(h)).collect()));
                        if !via.is_empty() {
                            o.str("via", via);
                        }
                    }
                    LowerOutcome::Kept(why) => {
                        o.str("outcome", "source kept");
                        o.str("reason", why);
                    }
                }
                if let Some(r) = &r.optimizer_residual {
                    o.str("optimizer_residual", r);
                }
                o
            })
            .collect();
        j.put("functions", Json::Arr(fns));
        j
    }

    /// The number of rewritten functions (both origins).
    pub fn lowered(&self) -> usize {
        self.records.iter().filter(|r| matches!(r.outcome, LowerOutcome::Lowered { .. })).count()
    }

    /// The number of functions rewritten with a replacement of `origin`.
    pub fn lowered_by(&self, origin: LowerOrigin) -> usize {
        self.rewritten_by(origin).len()
    }

    /// The functions rewritten with a replacement of `origin`.
    pub fn rewritten_by(&self, origin: LowerOrigin) -> Vec<&str> {
        self.records.iter().filter(|r| matches!(&r.outcome, LowerOutcome::Lowered { origin: o, .. } if *o == origin)).map(|r| r.function.as_str()).collect()
    }

    /// The whole lowered file: docs and body.
    pub fn text(&self) -> String {
        format!("{}{}", self.docs, self.body)
    }
}

/// The two origins of the rewritten functions of `lows`, counted and named
/// apart (the in-place build summary, the lowered-copy index header):
/// `optimizer residuals: 0; user-supplied `#[rewrite]` alternatives (user
/// code, not optimizer output): 1 (`crate::m::f`)`, and whether user
/// alternatives were excluded (evaluation only).
pub fn origin_counts(lows: &[LoweredModule]) -> String {
    let names = |o: LowerOrigin| -> (usize, String) {
        let fns: Vec<String> = lows.iter().flat_map(|l| l.rewritten_by(o)).map(|f| format!("`{f}`")).collect();
        let listed = if fns.is_empty() { String::new() } else { format!(" ({})", fns.join(", ")) };
        (fns.len(), listed)
    };
    let (k_opt, opt_names) = names(LowerOrigin::Optimizer);
    let (k_user, user_names) = names(LowerOrigin::UserRewrite);
    let mut s = format!("optimizer residuals: {k_opt}{opt_names}; user-supplied `#[rewrite]` alternatives (user code, not optimizer output): {k_user}{user_names}");
    if lows.iter().any(|l| l.user_rewrites_excluded) {
        s.push_str(" (user alternatives excluded: evaluation-only build)");
    }
    s
}

/// The buffer state of a source function (state passing, SEMANTICS.md
/// §19.1): the index of its one buffer parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// `buf: &mut impl BufMut`, no result: the lifted function returns the
    /// bytes put.
    BufMut(usize),
    /// `buf: &mut impl Buf`: the lifted function returns the bytes left
    /// (and then its result, if any).
    Buf(usize),
}

/// The one sealed-trait type parameter of a generic source function.
#[derive(Clone, Debug)]
struct Generic {
    param: String,
    bound: String,
    /// The by-value parameter of type `param` (the dispatch's receiver).
    recv: Option<usize>,
}

/// A function of the source file.
#[derive(Clone, Debug)]
struct SourceFn {
    name: String,
    /// The self type of its impl block (an associated function).
    owner: Option<String>,
    /// Byte offsets: start of the item (its first attribute or keyword),
    /// end of the name, start and end of the body block.
    item_start: usize,
    ident_end: usize,
    body: (usize, usize),
    params: Vec<String>,
    /// Byte ranges of the `mut` of by-value parameter bindings (`mut x:
    /// u32`), with the whitespace after it: a rewritten body (a call of the
    /// replacement) mutates no parameter, so the rewritten function and its
    /// round-trip copy leave them out (rustc's `unused_mut` otherwise; a
    /// binding mode, not part of the signature's type).
    param_muts: Vec<(usize, usize)>,
    /// Parameter types (source text) and the return type (`None`: unit).
    param_tys: Vec<String>,
    ret: Option<String>,
    state: Option<State>,
    has_result: bool,
    generic: Option<Generic>,
    is_const: bool,
    /// Why it cannot be rewritten (state parameters, a receiver, ...).
    refused: Option<String>,
}

impl SourceFn {
    /// A name for the helpers and copies (`Owner_f` for an associated
    /// function).
    fn key(&self) -> String {
        match &self.owner {
            Some(o) => format!("{o}_{}", self.name),
            None => self.name.clone(),
        }
    }

    /// The lifted item's path in module `mpath`.
    fn path(&self, mpath: &str) -> String {
        match &self.owner {
            Some(o) => format!("{mpath}::{o}::{}", self.name),
            None => format!("{mpath}::{}", self.name),
        }
    }
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

fn toks(t: &impl quote::ToTokens) -> String {
    quote::ToTokens::to_token_stream(t).to_string()
}

/// Whether a token stream names the identifier `id`.
fn names_ident(ts: proc_macro2::TokenStream, id: &str) -> bool {
    ts.into_iter().any(|t| match t {
        proc_macro2::TokenTree::Ident(i) => i == id,
        proc_macro2::TokenTree::Group(g) => names_ident(g.stream(), id),
        _ => false,
    })
}

/// The functions of the source file (top level and associated functions
/// of impl blocks) with their positions.
fn source_fns(text: &str) -> Result<Vec<SourceFn>, String> {
    let file = syn::parse_file(text).map_err(|e| format!("the lifted source does not parse: {e}"))?;
    let ls = line_starts(text);
    let mut out = Vec::new();
    for it in &file.items {
        match it {
            syn::Item::Fn(f) => {
                let start = f.attrs.first().map(|a| a.pound_token.span).unwrap_or_else(|| syn::spanned::Spanned::span(&f.vis));
                let start = if f.attrs.is_empty() && matches!(f.vis, syn::Visibility::Inherited) { f.sig.fn_token.span } else { start };
                if let Some(sf) = source_fn(text, &ls, &f.sig, &f.block, start, None) {
                    out.push(sf);
                }
            }
            syn::Item::Impl(im) => {
                let owner = match &*im.self_ty {
                    syn::Type::Path(p) if p.qself.is_none() && p.path.segments.len() == 1 && p.path.segments[0].arguments.is_empty() => p.path.segments[0].ident.to_string(),
                    _ => continue,
                };
                let generic_impl = !im.generics.params.is_empty();
                for ii in &im.items {
                    let syn::ImplItem::Fn(f) = ii else { continue };
                    let start = f.attrs.first().map(|a| a.pound_token.span).unwrap_or(f.sig.fn_token.span);
                    if let Some(mut sf) = source_fn(text, &ls, &f.sig, &f.block, start, Some(owner.clone())) {
                        if generic_impl {
                            sf.refused = sf.refused.or(Some("an associated function of a generic impl".into()));
                        }
                        out.push(sf);
                    }
                }
            }
            _ => {}
        }
    }
    // two functions reading as the same lifted path (a method name in two
    // trait impls of one type) are left alone
    let mut seen: HashMap<String, usize> = HashMap::new();
    for f in &out {
        *seen.entry(f.path("")).or_default() += 1;
    }
    for f in out.iter_mut() {
        if seen.get(&f.path("")).copied().unwrap_or(0) > 1 {
            f.refused = f.refused.clone().or(Some("two functions of the file read as the same lifted item".into()));
        }
    }
    Ok(out)
}

fn source_fn(text: &str, ls: &[usize], sig: &syn::Signature, block: &syn::Block, start: proc_macro2::Span, owner: Option<String>) -> Option<SourceFn> {
    let pos = |s: proc_macro2::Span| (offset(text, ls, s.start()), offset(text, ls, s.end()));
    let (Some(item_start), _) = pos(start) else { return None };
    let (Some(_), Some(ident_end)) = pos(sig.ident.span()) else { return None };
    let (Some(b0), Some(b1)) = pos(block.brace_token.span.join()) else { return None };
    if !text[b0..].starts_with('{') || !text[..b1].ends_with('}') {
        return None;
    }
    let mut params = Vec::new();
    let mut param_muts = Vec::new();
    let mut param_tys = Vec::new();
    let mut refused = None;
    let mut generic = None;
    let has_result = sig.output != syn::ReturnType::Default;
    if !sig.generics.params.is_empty() || sig.generics.where_clause.is_some() {
        let tps: Vec<&syn::TypeParam> = sig.generics.type_params().collect();
        match (tps.as_slice(), sig.generics.params.len(), &sig.generics.where_clause) {
            ([tp], 1, None) if tp.bounds.len() == 1 && tp.default.is_none() => match &tp.bounds[0] {
                syn::TypeParamBound::Trait(tb) if tb.path.get_ident().is_some() && tb.lifetimes.is_none() && matches!(tb.modifier, syn::TraitBoundModifier::None) => {
                    generic = Some(Generic { param: tp.ident.to_string(), bound: tb.path.get_ident().unwrap().to_string(), recv: None });
                }
                _ => refused = Some("a generic function whose parameter is not bounded by one trait".to_string()),
            },
            _ => refused = Some("a generic function with other than one type parameter bounded by one trait".to_string()),
        }
    }
    if sig.asyncness.is_some() || sig.unsafety.is_some() || sig.abi.is_some() || sig.variadic.is_some() {
        refused = refused.or(Some("an `async`, `unsafe` or `extern` function".into()));
    }
    let mut state = None;
    for (k, a) in sig.inputs.iter().enumerate() {
        match a {
            syn::FnArg::Receiver(_) => refused = refused.or(Some("a method with a receiver (lowering of `self` state passing is not built yet)".into())),
            syn::FnArg::Typed(pt) => {
                let ty = toks(&*pt.ty);
                param_tys.push(ty.clone());
                if ty == "& mut impl BufMut" && state.is_none() && !has_result {
                    state = Some(State::BufMut(k));
                } else if ty == "& mut impl Buf" && state.is_none() {
                    state = Some(State::Buf(k));
                } else if ty.contains("impl") || ty.contains("mut") || ty.contains("dyn") {
                    refused = refused.or(Some("a parameter with state other than one `&mut impl Buf`, or one `&mut impl BufMut` of a function without a result: lowering of that state passing is not built yet".into()));
                }
                if let Some(g) = generic.as_mut()
                    && g.recv.is_none()
                    && matches!(&*pt.ty, syn::Type::Path(p) if p.qself.is_none() && p.path.is_ident(&g.param))
                {
                    g.recv = Some(k);
                }
                match &*pt.pat {
                    syn::Pat::Ident(pi) if pi.by_ref.is_none() && pi.subpat.is_none() => {
                        params.push(pi.ident.to_string());
                        if let Some(m) = &pi.mutability
                            && let (Some(a), Some(b)) = pos(m.span)
                            && text.get(a..b) == Some("mut")
                        {
                            let ws = text[b..].len() - text[b..].trim_start().len();
                            param_muts.push((a, b + ws));
                        }
                    }
                    _ => refused = refused.or(Some("a parameter with a pattern".into())),
                }
            }
        }
    }
    let ret = match &sig.output {
        syn::ReturnType::Default => None,
        syn::ReturnType::Type(_, t) => Some(toks(&**t)),
    };
    if ret.as_deref().is_some_and(|r| r.contains("impl")) {
        refused = refused.or(Some("an `impl Trait` return type".into()));
    }
    if owner.is_some() && names_ident(toks(&sig.inputs).parse().unwrap_or_default(), "Self") || owner.is_some() && names_ident(toks(&sig.output).parse().unwrap_or_default(), "Self") {
        refused = refused.or(Some("its signature names `Self` (the round trip's copy is a free function)".into()));
    }
    if let Some(g) = &generic {
        if state.is_some() {
            refused = refused.or(Some("a generic function with buffer state (the dispatch call does not thread the state yet; FRICTION)".into()));
        } else if g.recv.is_none() {
            refused = refused.or(Some(format!("a generic function without a by-value parameter of type `{}` (the dispatch needs one as its receiver; FRICTION)", g.param)));
        }
    }
    Some(SourceFn { name: sig.ident.to_string(), owner, item_start, ident_end, body: (b0, b1), params, param_muts, param_tys, ret, state, has_result, generic, is_const: sig.constness.is_some(), refused })
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
    fn new<'k>(krate: &'k Crate, arch: &str, opts: &OptOptions) -> Costs<'k> {
        Costs { krate, model: crate::opt::cost::model::SetModel::portable(arch, &opts.tuning), memo: Default::default(), active: Default::default() }
    }

    fn op(&self, op: crate::opt::cost::tables::Op) -> u64 {
        self.model.tables.iter().map(|t| t.op(op).lat).max().unwrap_or(0)
    }

    fn of(&self, id: ItemId) -> u64 {
        use crate::opt::cost::tables::Op;
        if let Some(c) = self.memo.borrow().get(&id) {
            return *c;
        }
        let call = self.op(Op::Call);
        let path = self.krate.item(id).path.to_string();
        // a host buffer operation: a call on both sides (its model, a ghost
        // sequence operation, is not what runs)
        if crate::opt::drive::KEPT_LIFT_MODEL.contains(&path.as_str()) {
            return call;
        }
        // the lift prelude (`crate::__lift::*`, and the optimizer's
        // specializations of it): what rustc compiles is the one operation
        // it spells out (a signed shift or negation, core's method), not
        // its model body
        if path.starts_with("crate::__lift::") && self.krate.fn_def(id).is_some_and(|f| f.kind == FnKind::Exec) {
            return self.op(Op::Alu);
        }
        if !self.active.borrow_mut().insert(id) {
            return call;
        }
        let c = match self.krate.fn_def(id) {
            Some(f) => {
                let body = self.model.fn_cost_carried(self.krate, f, &|cid| Some(self.of(cid)));
                // a loop (a recursive helper): its body per iteration, at
                // the literal bound of its measure or `LOOP_TRIPS`
                if f.recursion != Recursion::None {
                    let trips = f.decreases.as_ref().and_then(|d| d.max).unwrap_or(LOOP_TRIPS).clamp(1, 1 << 16);
                    body.saturating_mul(trips)
                } else {
                    body
                }
            }
            None => 0,
        };
        self.active.borrow_mut().remove(&id);
        self.memo.borrow_mut().insert(id, c);
        c
    }
}

/// One emitted helper: its name in the file, its text, and the kernel
/// globals the round trip reads it as (`refer`) and compares it with.
#[derive(Clone, Debug)]
struct Helper {
    name: String,
    text: String,
    refer: GlobalId,
    compare: GlobalId,
}

/// One instance of a candidate (the only one of a non-generic function).
#[derive(Clone, Debug)]
struct Inst {
    /// The instance type of a generic function.
    ty: Option<String>,
    /// The source function's kernel global and its replacement's (the
    /// residual, or the rewrite's alternative).
    orig_global: GlobalId,
    target: GlobalId,
    /// The entry helper (called by the rewritten body or the dispatch).
    entry: String,
    rung: String,
    cost_source: u64,
    cost_residual: u64,
    /// The optimizer's link between the source function and the
    /// replacement: a lemma's name (`None`: by conversion).
    link: Option<String>,
    /// A source function that can panic, replaced through its
    /// panic-explicit reading (DESIGN.md §8.2 item 12): the source
    /// function's kernel name (`orig_global` is then the reading's).
    panic: Option<String>,
}

/// A candidate after lowering (before the round trip).
#[derive(Clone, Debug)]
struct Candidate {
    src: SourceFn,
    insts: Vec<Inst>,
    helpers: Vec<Helper>,
    /// The rewritten body.
    entry: String,
    /// A generic function: its dispatch method.
    dispatch: Option<Dispatch>,
    /// How (`LowerOutcome::Lowered::via`).
    via: String,
    /// Where the replacement comes from.
    origin: LowerOrigin,
}

/// The dispatch of a generic candidate: the method declared in the
/// sealed trait's dispatch trait and its impl per impl type.
#[derive(Clone, Debug)]
struct Dispatch {
    bound: String,
    /// `fn __sandblaster_opt_f(self, ..) -> R;`
    decl: String,
    /// Per impl type (source order): the impl method's text.
    impls: Vec<(String, String)>,
    /// The copy of the original generic code (for unverified instances).
    orig: Option<String>,
}

/// Lowers the cheaper replacements of the lifted module `info` into its
/// source text and checks them by the lifted round trip (module docs).
/// `root` is the DSL root the front end read. Never fails: a function that
/// does not qualify or does not pass keeps its source text (the reason is
/// recorded).
pub fn lower_lifted(c: &Checked, root: &Path, out: &mut Output, o: &Optimized, opts: &OptOptions, info: &LiftedInfo) -> LoweredModule {
    lower_lifted_impl(c, root, out, o, opts, info, None)
}

/// [`lower_lifted`] for every in-place lifted module of the crate (one
/// lowered file per host file, DESIGN.md §2.1 "in place").
pub fn lower_in_place(c: &Checked, root: &Path, out: &mut Output, o: &Optimized, opts: &OptOptions) -> Vec<LoweredModule> {
    let infos: Vec<LiftedInfo> = c.lifted.iter().filter(|l| l.in_place && !l.ghost).cloned().collect();
    #[cfg(any(test, feature = "opt-test-hooks"))]
    let fault = in_place_fault::get();
    #[cfg(not(any(test, feature = "opt-test-hooks")))]
    let fault = None;
    infos.iter().map(|info| lower_lifted_impl(c, root, out, o, opts, info, fault)).collect()
}

/// A printer fault injected into every in-place lowering of this process,
/// for the must-reject suite of the lowered declaration
/// (`tests/lowered_use.rs`: a host file compiled from its lowered copy
/// whose rewrite the lifted round trip rejects fails the build). Compiled
/// only with `cfg(test)` or the `opt-test-hooks` feature (never in a build
/// script, `opt::hooks`). Process-wide (the lowering runs on the
/// elaborator's big-stack thread), so its users serialize.
#[cfg(any(test, feature = "opt-test-hooks"))]
pub mod in_place_fault {
    use std::sync::Mutex;

    static FAULT: Mutex<Option<super::LowerFault>> = Mutex::new(None);

    /// Sets (or clears) the fault.
    pub fn set(f: Option<super::LowerFault>) {
        *FAULT.lock().unwrap_or_else(|e| e.into_inner()) = f;
    }

    pub(crate) fn get() -> Option<super::LowerFault> {
        *FAULT.lock().unwrap_or_else(|e| e.into_inner())
    }
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
    /// The dispatch impl of the first two verified instance types call
    /// each other's helper.
    SwapDispatch,
    /// The MIR the build ships is not the MIR the round trip read: the
    /// first integer constant of the first helper's MIR changes by one in
    /// the literal reading only (the shipped code's theorem must fail).
    ShippedMir,
    /// The dispatch impl of the first verified instance type calls the
    /// original generic code (equal in meaning, but not the checked
    /// delegation to its residual).
    DispatchToOrig,
    /// The dispatch impl of the second impl type is left out.
    DropDispatchImpl,
    /// The first `wrapping_sub(1)` of a copied alternative becomes
    /// `wrapping_sub(2)`.
    WrongAlternative,
    /// The first `try_get_u8()` of a reader is done twice (one byte more
    /// is consumed).
    ReadTwice,
    /// Not a fault: on a module read from MIR, the syntactic comparison of
    /// a module without MIR (`compare_read_back`) runs too, and what it
    /// would have refused is recorded in `LoweredModule::structural`; it
    /// decides nothing (the shipped code's theorems do).
    CompareStructurally,
}

/// [`lower_lifted`] with a simulated printer fault (tests only).
#[cfg(any(test, feature = "opt-test-hooks"))]
pub fn lower_lifted_with_fault(c: &Checked, root: &Path, out: &mut Output, o: &Optimized, opts: &OptOptions, info: &LiftedInfo, fault: LowerFault) -> LoweredModule {
    lower_lifted_impl(c, root, out, o, opts, info, Some(fault))
}

/// Applies a printer fault to the candidates.
fn inject(fault: LowerFault, cands: &mut [Candidate]) {
    fn first_in_helpers(cands: &mut [Candidate], from: &str, to: &str) {
        for cd in cands.iter_mut() {
            for h in cd.helpers.iter_mut() {
                if let Some(at) = h.text.find(from) {
                    h.text.replace_range(at..at + from.len(), to);
                    return;
                }
            }
        }
    }
    match fault {
        // (the copies' text is right: the fault is in the MIR the round trip
        // reads, or the hook is in the round trip itself, `round_trip`)
        LowerFault::ShippedMir | LowerFault::CompareStructurally => {}
        LowerFault::FlipComparison => first_in_helpers(cands, " < ", " <= "),
        LowerFault::WrongConstant => first_in_helpers(cands, "1u32", "2u32"),
        LowerFault::WrongAlternative => first_in_helpers(cands, "wrapping_sub(1)", "wrapping_sub(2)"),
        LowerFault::ReadTwice => {
            for cd in cands.iter_mut() {
                for h in cd.helpers.iter_mut() {
                    if let Some(at) = h.text.find(".try_get_u8();") {
                        let ls = h.text[..at].rfind('\n').map(|i| i + 1).unwrap_or(0);
                        let indent: String = h.text[ls..].chars().take_while(|c| *c == ' ').collect();
                        let recv_start = h.text[ls..at].rfind(' ').map(|i| ls + i + 1).unwrap_or(ls);
                        let recv = h.text[recv_start..at].to_string();
                        h.text.insert_str(ls, &format!("{indent}let _ = {recv}.try_get_u8();\n"));
                        return;
                    }
                }
            }
        }
        LowerFault::DispatchToOrig | LowerFault::DropDispatchImpl => {
            for cd in cands.iter_mut() {
                let key = cd.src.key();
                let first = cd.insts.first().cloned();
                let Some(d) = cd.dispatch.as_mut() else { continue };
                if fault == LowerFault::DropDispatchImpl {
                    if d.impls.len() >= 2 {
                        d.impls.remove(1);
                    }
                } else if let Some(inst) = first {
                    let ty = inst.ty.clone().unwrap_or_default();
                    for (t, m) in d.impls.iter_mut() {
                        if *t == ty {
                            *m = m.replace(&format!("{}(", inst.entry), &format!("{ORIG_PREFIX}{key}::<{ty}>("));
                        }
                    }
                }
                return;
            }
        }
        LowerFault::DropOperation => {
            for cd in cands.iter_mut() {
                for h in cd.helpers.iter_mut() {
                    let t = &mut h.text;
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
            if let Some(cd) = cands.first_mut() {
                let mut ps = cd.src.params.clone();
                ps.reverse();
                cd.entry = format!("{{\n    {}({})\n}}", cd.insts[0].entry, ps.join(", "));
            }
        }
        LowerFault::SwapBufferCalls | LowerFault::DropBufferCall => {
            let is_call = |l: &str| l.trim_start().starts_with("l") && (l.contains(".put_u8(") || l.contains(".put_slice(") || l.contains(".try_get_u8("));
            for cd in cands.iter_mut() {
                for h in cd.helpers.iter_mut() {
                    let mut lines: Vec<String> = h.text.lines().map(String::from).collect();
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
                        h.text = lines.join("\n") + "\n";
                        return;
                    }
                }
            }
        }
        LowerFault::CrossEntry => {
            if cands.len() >= 2 {
                let other = cands[1].insts[0].entry.clone();
                let cd = &mut cands[0];
                cd.entry = format!("{{\n    {other}({})\n}}", cd.src.params.join(", "));
            }
        }
        LowerFault::SwapDispatch => {
            for cd in cands.iter_mut() {
                let Some(d) = cd.dispatch.as_mut() else { continue };
                let verified: Vec<&Inst> = cd.insts.iter().collect();
                if verified.len() < 2 {
                    continue;
                }
                let (a, b) = (verified[0].entry.clone(), verified[1].entry.clone());
                for (_, t) in d.impls.iter_mut() {
                    if t.contains(&a) {
                        *t = t.replace(&a, "\u{0}").replace(&b, &a).replace('\u{0}', &b);
                    } else if t.contains(&b) {
                        *t = t.replace(&b, &a);
                    }
                }
                return;
            }
        }
    }
}

/// A `#[rewrite]` lemma: source function `f` is equal to alternative `g`.
#[derive(Clone, Debug)]
struct Rewrite {
    lemma: ItemId,
    alt: ItemId,
}

/// The `#[rewrite]` lemmas of the crate, by the source function they
/// rewrite: lemmas whose `ensures` is `f(x̄) == g(x̄)` with `x̄` exactly the
/// lemma's parameters, `f` an exec function of a lifted module that is not
/// an alternative and `g` an exec function of a `#[lift(opt)]` module.
/// Other `#[rewrite]` lemmas are listed with why they are not used.
fn rewrites(c: &Checked, krate: &Crate) -> (HashMap<ItemId, Rewrite>, Vec<String>) {
    let opt_files: HashSet<crate::span::FileId> = c.lifted.iter().filter(|l| l.opt).map(|l| l.file).collect();
    let opt_mods: HashSet<crate::hir::ModId> = krate.modules.iter().enumerate().filter(|(_, m)| opt_files.contains(&m.file)).map(|(i, _)| crate::hir::ModId(i as u32)).collect();
    let mut out = HashMap::new();
    let mut notes = Vec::new();
    for it in &krate.items {
        let Some(f) = krate.fn_def(it.id) else { continue };
        if f.kind != FnKind::Lemma || !f.rewrite {
            continue;
        }
        let why = (|| -> Result<(ItemId, ItemId), String> {
            let e = f.ensures.as_ref().ok_or("it has no `ensures`")?;
            fn strip(mut x: &crate::hir::Expr) -> &crate::hir::Expr {
                while let ExprKind::Coerce(_, inner) = &x.kind {
                    x = inner;
                }
                x
            }
            let (a, b) = match &strip(&e.prop).kind {
                ExprKind::PropEq(a, b) | ExprKind::Binary(crate::hir::BinOp::Eq, a, b) => (a.as_ref(), b.as_ref()),
                ExprKind::Call { callee: crate::hir::Callee::Builtin(crate::builtins::Builtin::StructEq { ne: false }, _), args } if args.len() == 2 => (&args[0], &args[1]),
                other => return Err(format!("its `ensures` is not `f(x̄) == g(x̄)` ({})", format!("{other:?}").chars().take(400).collect::<String>())),
            };
            let call = |x: &crate::hir::Expr| -> Option<(ItemId, Vec<crate::hir::LocalId>)> {
                let ExprKind::Call { callee: crate::hir::Callee::Item(id, tys), args } = &strip(x).kind else { return None };
                if !tys.is_empty() {
                    return None;
                }
                let ls: Option<Vec<_>> = args.iter().map(|a| match &strip(a).kind {
                    ExprKind::Local(l) => Some(*l),
                    _ => None,
                }).collect();
                Some((*id, ls?))
            };
            let ((fid, fa), (gid, ga)) = (call(a).ok_or("the left side is not a call of a function on the parameters")?, call(b).ok_or("the right side is not a call of a function on the parameters")?);
            let params: Vec<crate::hir::LocalId> = f.params.iter().filter_map(|p| match &p.pat.kind {
                crate::hir::PatKind::Binding { local, .. } => Some(*local),
                _ => None,
            }).collect();
            if fa != params || ga != params {
                return Err("both sides must pass exactly the lemma's parameters, in order".into());
            }
            let is_exec = |id: ItemId| krate.fn_def(id).is_some_and(|d| d.kind == FnKind::Exec);
            if !is_exec(fid) || !is_exec(gid) {
                return Err("both sides must be exec functions".into());
            }
            if !opt_mods.contains(&krate.item(gid).module) {
                return Err(format!("`{}` is not a function of a `#[lift(opt)]` module", krate.item(gid).path));
            }
            if opt_mods.contains(&krate.item(fid).module) {
                return Err(format!("`{}` is itself an alternative", krate.item(fid).path));
            }
            Ok((fid, gid))
        })();
        match why {
            Ok((fid, gid)) => {
                if out.insert(fid, Rewrite { lemma: it.id, alt: gid }).is_some() {
                    notes.push(format!("`{}`: more than one `#[rewrite]` lemma for `{}`; the last is used", it.path, krate.item(fid).path));
                }
            }
            Err(e) => notes.push(format!("`#[rewrite]` lemma `{}` is not used: {e}", it.path)),
        }
    }
    (out, notes)
}

/// Adds `<f>::rewrite_equiv : Π x̄ (h̄ : Req_f). Eq(R, f x̄ h̄, g x̄ h̄)`
/// with proof `λ x̄ h̄. lemma x̄ h̄` — the kernel checks that the lemma has
/// exactly this statement (the alternative's parameters, preconditions
/// included, are the source function's).
fn rewrite_link(out: &mut Output, f: GlobalId, g: GlobalId, lemma: GlobalId) -> Result<GlobalId, String> {
    use crate::opt::symex::telescope;
    let name = format!("{}::rewrite_equiv", out.env.global_name(f).map(|s| s.to_string()).unwrap_or_default());
    if let Some(done) = out.env.lookup_global(&name) {
        return Ok(done);
    }
    let tf = telescope(&out.env, f).ok_or("the source function has no parameter telescope")?;
    let tg = telescope(&out.env, g).ok_or("the alternative has no parameter telescope")?;
    let tl = telescope(&out.env, lemma).ok_or("the lemma has no parameter telescope")?;
    let rels: Vec<Rel> = tf.binders.iter().map(|(_, r, _)| *r).collect();
    let rels_of = |t: &crate::opt::symex::Telescope| t.binders.iter().map(|(_, r, _)| *r).collect::<Vec<_>>();
    // the lemma binds the preconditions as relevant hypotheses (a proof
    // is a value of a lemma's statement); the statement below binds them as
    // the lemma does and passes them to `f` and `g` in their irrelevant
    // positions — the same proposition
    let lrels = rels_of(&tl);
    let same_shape = rels_of(&tg) == rels && lrels.len() == rels.len() && rels.iter().zip(&lrels).all(|(a, b)| a == b || (*a == Rel::Irr && *b == Rel::Rel));
    if !same_shape {
        return Err(format!("the source function, the alternative and the lemma do not have the same parameters and preconditions (relevances {:?}, {:?}, {:?})", rels, rels_of(&tg), lrels));
    }
    let n = rels.len() as u32;
    let args = |h: GlobalId, rs: &[Rel]| mk::apps(mk::global(h), (0..n).map(|i| (rs[i as usize], mk::var(n - 1 - i))));
    let mut ty = mk::eq(tf.ret.clone(), args(f, &rels), args(g, &rels));
    let mut body = args(lemma, &lrels);
    for ((nm, _, dom), rel) in tf.binders.iter().zip(&lrels).rev() {
        ty = mk::pi(nm, *rel, dom.clone(), ty);
        body = mk::lam(nm, *rel, dom.clone(), body);
    }
    let mut b = sandblaster_kernel::value::Budget { steps: 10_000_000 };
    let d = DefDecl { name: std::rc::Rc::from(name.as_str()), kind: DefKind::Lemma, ty, body, recursion: KRecursion::None, arity: n, opaque: true };
    out.env.add_def(d, &mut b).map_err(|e| format!("the kernel rejects `{name}`: {}", e.to_string().chars().take(600).collect::<String>()))
}

/// The text of a function item of an alternatives file, private, renamed
/// by `rename` (every identifier token in the item that `rename` maps).
fn alt_text(text: &str, name: &str, rename: &HashMap<String, String>) -> Result<(String, bool), String> {
    let file = syn::parse_file(text).map_err(|e| format!("the alternatives file does not parse: {e}"))?;
    let ls = line_starts(text);
    let f = file
        .items
        .iter()
        .find_map(|it| match it {
            syn::Item::Fn(f) if f.sig.ident == name => Some(f),
            _ => None,
        })
        .ok_or_else(|| format!("no top-level `fn {name}` in the alternatives file"))?;
    if !f.sig.generics.params.is_empty() {
        return Err(format!("the alternative `{name}` is generic"));
    }
    let pos = |s: proc_macro2::Span| (offset(text, &ls, s.start()), offset(text, &ls, s.end()));
    let start = match f.attrs.first() {
        Some(a) => pos(a.pound_token.span).0,
        None => match &f.vis {
            syn::Visibility::Inherited => pos(f.sig.fn_token.span).0,
            v => pos(syn::spanned::Spanned::span(v)).0,
        },
    }
    .ok_or("a position outside the file")?;
    let end = pos(f.block.brace_token.span.join()).1.ok_or("a position outside the file")?;
    // replacements: the visibility (removed), renamed identifiers
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    if !matches!(f.vis, syn::Visibility::Inherited) {
        let s = syn::spanned::Spanned::span(&f.vis);
        let (Some(a), Some(b)) = pos(s) else { return Err("a position outside the file".into()) };
        let b = if text[b..].starts_with(' ') { b + 1 } else { b };
        edits.push((a, b, String::new()));
    }
    fn walk(ts: proc_macro2::TokenStream, rename: &HashMap<String, String>, out: &mut Vec<(proc_macro2::Span, String)>) {
        for t in ts {
            match t {
                proc_macro2::TokenTree::Ident(i) => {
                    if let Some(n) = rename.get(&i.to_string()) {
                        out.push((i.span(), n.clone()));
                    }
                }
                proc_macro2::TokenTree::Group(g) => walk(g.stream(), rename, out),
                _ => {}
            }
        }
    }
    let mut ids = Vec::new();
    walk(quote::ToTokens::to_token_stream(&f.sig), rename, &mut ids);
    walk(quote::ToTokens::to_token_stream(&f.block), rename, &mut ids);
    for (s, n) in ids {
        let (Some(a), Some(b)) = pos(s) else { return Err("a position outside the file".into()) };
        edits.push((a, b, n));
    }
    edits.sort_by_key(|e| std::cmp::Reverse(e.0));
    let mut t = text[start..end].to_string();
    for (a, b, n) in edits {
        if a < start || b > end {
            return Err("an identifier outside the item".into());
        }
        t.replace_range(a - start..b - start, &n);
    }
    Ok((format!("{t}\n"), f.sig.constness.is_some()))
}

/// [`lower_lifted_body`], with the optimizer's own residual outcome of
/// every function that has a user `#[rewrite]` alternative recorded on its
/// record ([`LowerRecord::optimizer_residual`]).
fn lower_lifted_impl(c: &Checked, root: &Path, out: &mut Output, o: &Optimized, opts: &OptOptions, info: &LiftedInfo, fault: Option<LowerFault>) -> LoweredModule {
    let mut residuals: HashMap<String, String> = HashMap::new();
    let mut low = lower_lifted_body(c, root, out, o, opts, info, fault, &mut residuals);
    for r in low.records.iter_mut() {
        r.optimizer_residual = residuals.remove(&r.function);
    }
    low.user_rewrites_excluded = opts.exclude_user_rewrites;
    low
}

/// The optimizer residual's outcome as recorded beside a user alternative.
fn residual_note(r: &Result<Candidate, String>) -> String {
    match r {
        Ok(cd) => {
            let i = &cd.insts[0];
            format!("cheaper and printable (rung {}; portable cost {} -> {} milli-cycles)", i.rung, i.cost_source, i.cost_residual)
        }
        Err(e) => format!("not used: {e}"),
    }
}

#[allow(clippy::too_many_arguments)]
fn lower_lifted_body(c: &Checked, root: &Path, out: &mut Output, o: &Optimized, opts: &OptOptions, info: &LiftedInfo, fault: Option<LowerFault>, residuals: &mut HashMap<String, String>) -> LoweredModule {
    let Some(src) = c.sm.get(info.file) else {
        return LoweredModule { note: Some("the lifted source is not in the source map".into()), ..Default::default() };
    };
    let text = src.text.clone();
    let file = crate::loader::normalize(&src.path).display().to_string();
    let (docs, _) = super::lifted::split_docs(&text);
    let docs = docs.to_string();
    let docs_len = docs.len();
    let unused = std::cell::RefCell::new(Vec::<String>::new());
    let as_is = |note: Option<String>, records: Vec<LowerRecord>| LoweredModule { file: file.clone(), body: text[docs_len..].to_string(), docs: docs.clone(), records, compared: 0, note, unused_rewrites: unused.borrow().clone(), ..Default::default() };
    let Some(krate) = c.krate.as_ref() else {
        return as_is(Some("no crate".into()), vec![]);
    };
    // the print view, with the panic-explicit readings in their Rust form
    let pv_conv;
    let pv: &Crate = if o.panics.iter().any(|r| r.item.is_some()) {
        pv_conv = panic_view(&o.print, o);
        &pv_conv
    } else {
        &o.print
    };
    let fns = match source_fns(&text) {
        Ok(f) => f,
        Err(e) => return as_is(Some(e), vec![]),
    };
    let Some(mpath) = module_path(pv, info) else {
        return as_is(Some("the lifted module has no module in the crate".into()), vec![]);
    };
    let by_path: HashMap<String, ItemId> = pv.items.iter().map(|it| (it.path.to_string(), it.id)).collect();
    let arch = krate.target.arch.name();
    let src_costs = Costs::new(krate, arch, opts);
    let res_costs = Costs::new(pv, arch, opts);
    let names_base = source_fn_names(&by_path, &mpath, &fns, krate);
    let (rw, rw_notes) = rewrites(c, krate);
    *unused.borrow_mut() = rw_notes.clone();
    let mut records: Vec<LowerRecord> = Vec::new();
    let mut cands: Vec<Candidate> = Vec::new();
    let probe = std::env::var_os("SANDBLASTER_LOWER_PROBE").is_some();
    if probe {
        for n in &rw_notes {
            eprintln!("PROBE rewrite: {n}");
        }
    }
    for sf in &fns {
        let path = sf.path(&mpath);
        let mut keep = |why: String| records.push(LowerRecord { function: path.clone(), outcome: LowerOutcome::Kept(why), optimizer_residual: None });
        if let Some(r) = &sf.refused {
            keep(r.clone());
            continue;
        }
        let r = if let Some(g) = &sf.generic {
            dispatch_candidate(c, krate, pv, out, o, &src_costs, &res_costs, &names_base, &by_path, &mpath, info, sf, g, &text)
        } else {
            let Some(&id) = by_path.get(&path) else {
                keep("no lifted item of this name (dropped by the lift)".into());
                continue;
            };
            if id.0 as usize >= krate.items.len() || krate.item(id).path.to_string() != path {
                keep("the lifted item is not a source item".into());
                continue;
            }
            // the optimizer's residual, always built (and recorded beside a
            // user alternative); a user-supplied alternative named by a
            // `#[rewrite]` lemma is tried first unless the build excludes
            // user alternatives (evaluation only)
            let residual = residual_candidate(krate, pv, out, o, &src_costs, &res_costs, &names_base, &mpath, sf, id);
            if rw.contains_key(&id) {
                residuals.insert(path.clone(), residual_note(&residual));
            }
            let alt = if opts.exclude_user_rewrites { None } else { rw.get(&id).map(|r| rewrite_candidate(c, krate, out, &src_costs, &mpath, sf, id, r, &text)) };
            match alt {
                Some(Ok(cd)) => Ok(cd),
                Some(Err(e_alt)) => residual.map_err(|e| format!("{e_alt}; and its residual: {e}")),
                None => residual,
            }
        };
        match r {
            Ok(cd) => {
                // a helper name the source already uses
                if let Some(h) = cd.helpers.iter().find(|h| text.contains(h.name.as_str())) {
                    keep(format!("the source already uses the name `{}`", h.name));
                    continue;
                }
                if let Some(e) = self_reference(&sf.name, &cd.entry) {
                    keep(e);
                    continue;
                }
                cands.push(cd);
            }
            Err(e) => keep(e),
        }
    }
    if probe {
        for cd in &cands {
            eprintln!("PROBE candidate `{}` via {}: {} helper(s)\n{}", cd.src.path(&mpath), cd.via, cd.helpers.len(), cd.helpers.iter().map(|h| h.text.clone()).collect::<String>());
        }
    }
    if cands.is_empty() {
        return as_is(None, sorted(records));
    }
    if let Some(f) = fault {
        inject(f, &mut cands);
    }
    // the lifted round trip, then once more on the functions that passed
    let mut compared = 0;
    let mut note = None;
    let mut rt_copy: Option<(String, String)> = None;
    let mut structural: Vec<String> = Vec::new();
    for round in 0..2 {
        if info.mir.is_some() {
            rt_copy = Some((mpath.trim_start_matches("crate::").replace("::", "__"), assemble(&text, &cands, true)));
        }
        match round_trip(c, root, out, &text, &mpath, info, &cands, fault) {
            Err(e) => {
                note = Some(format!("lifted round trip: {e}"));
                for cd in cands.drain(..) {
                    records.push(LowerRecord { function: cd.src.path(&mpath), outcome: LowerOutcome::Kept(format!("{ROUND_TRIP_REJECTED} failed: {e}")), optimizer_residual: None });
                }
                break;
            }
            Ok((verdicts, n, said)) => {
                structural.extend(said);
                let all_ok = verdicts.values().all(|v| v.is_ok());
                if all_ok {
                    compared = n;
                    break;
                }
                let mut keep = Vec::new();
                for cd in cands.drain(..) {
                    match verdicts.get(&cd.src.key()) {
                        Some(Ok(_)) => keep.push(cd),
                        Some(Err(e)) => records.push(LowerRecord { function: cd.src.path(&mpath), outcome: LowerOutcome::Kept(format!("{ROUND_TRIP_REJECTED} rejected the lowered code: {e}")), optimizer_residual: None }),
                        None => records.push(LowerRecord { function: cd.src.path(&mpath), outcome: LowerOutcome::Kept(format!("{ROUND_TRIP_REJECTED} did not compare it")), optimizer_residual: None }),
                    }
                }
                if round == 1 {
                    // a second failure: nothing is lowered
                    for cd in keep.drain(..) {
                        records.push(LowerRecord { function: cd.src.path(&mpath), outcome: LowerOutcome::Kept(format!("{ROUND_TRIP_REJECTED} failed twice; nothing is lowered")), optimizer_residual: None });
                    }
                }
                cands = keep;
                if cands.is_empty() {
                    break;
                }
            }
        }
    }
    if cands.is_empty() {
        return LoweredModule { compared: 0, roundtrip_copy: rt_copy, structural, ..as_is(note, sorted(records)) };
    }
    let body = assemble(&text, &cands, false);
    for cd in &cands {
        records.push(LowerRecord {
            function: cd.src.path(&mpath),
            outcome: LowerOutcome::Lowered {
                origin: cd.origin,
                rung: cd.insts[0].rung.clone(),
                cost_source: cd.insts.iter().map(|i| i.cost_source).sum(),
                cost_residual: cd.insts.iter().map(|i| i.cost_residual).sum(),
                helpers: cd.helpers.iter().map(|h| h.name.clone()).collect(),
                via: cd.via.clone(),
            },
            optimizer_residual: None,
        });
    }
    let shipped = std::mem::take(&mut out.mir_gate.shipped);
    LoweredModule { file: file.clone(), body: body[docs_len..].to_string(), docs: docs.clone(), records: sorted(records), compared, note, unused_rewrites: unused.borrow().clone(), roundtrip_copy: rt_copy, shipped, structural, ..Default::default() }
}

/// The residual of lifted item `id` lowered: its entry helper `name` and
/// every optimizer helper it calls, or why not.
#[allow(clippy::too_many_arguments)]
fn lower_residual(krate: &Crate, pv: &Crate, out: &Output, o: &Optimized, src_costs: &Costs<'_>, res_costs: &Costs<'_>, names_base: &Names, id: ItemId, name: &str, state: Option<State>, has_result: bool, konst: bool) -> Result<(Inst, Vec<Helper>), String> {
    let mut rep = o.fns.iter().find(|f| f.item == id && f.set.is_none()).ok_or("the optimizer has no result for it")?;
    // a source function that can panic (exec-only code): its panic-explicit
    // reading's residual (DESIGN.md §8.2 item 12), printed in its Rust form
    // (the print view holds it, `panic_view`), shipped only with the round
    // trip's panic theorems
    let mut subject = id;
    let mut panic_source = None;
    if matches!(rep.outcome, Outcome::Unspecialized { .. })
        && let Some(pid) = o.panics.iter().find(|r| r.source == id).and_then(|r| r.item)
    {
        rep = o.fns.iter().find(|f| f.item == pid && f.set.is_none()).ok_or("the optimizer has no result for its panic-explicit reading")?;
        subject = pid;
        panic_source = Some(krate.item(id).path.to_string());
        if state.is_some() {
            return Err("a function with buffer state that can panic (its panic-explicit reading is not lowered with state yet)".into());
        }
    }
    let panic = panic_source.is_some();
    let residual_global = match &rep.outcome {
        Outcome::Specialized { .. } => match o.targets.get(&subject) {
            Some((_, r)) => *r,
            None => return Err("specialized, but not printed".into()),
        },
        Outcome::Unspecialized { reason, .. } if panic => return Err(format!("its panic-explicit reading is not specialized: {reason}")),
        Outcome::Unspecialized { reason, .. } => return Err(format!("not specialized: {reason}")),
    };
    if panic
        && let Some(Err(e)) = o.print.fn_def(subject).map(lower::panic_rust_form)
    {
        // (`panic_view` converted every reading it could)
        return Err(format!("its panic-explicit reading's residual has no Rust form: {e}"));
    }
    let orig_global = *out.fn_globals.get(&subject).ok_or("not kernel-checked")?;
    if let Some(p) = std::env::var_os("SANDBLASTER_LOWER_DUMP")
        && let Some(f) = pv.fn_def(id)
    {
        let _ = std::fs::write(std::path::Path::new(&p).join(format!("{}.txt", pv.item(id).name)), format!("{:#?}", f.body));
    }
    let (cs, cr) = (src_costs.of(id), res_costs.of(subject));
    if !crate::opt::cost::model::beats(cr, cs) {
        let why = not_cheaper(out, residual_global, orig_global, cr, cs);
        return Err(if panic { format!("{why} (its panic-explicit reading's residual, in its Rust form)") } else { why });
    }
    // the helper closure and the names the lowered code uses
    let mut helpers: Vec<(ItemId, String)> = vec![(subject, name.to_string())];
    let mut queue = vec![subject];
    while let Some(h) = queue.pop() {
        for cid in lower::callees(pv, h) {
            if names_base.fns.contains_key(&cid) && cid != subject {
                continue;
            }
            // (a reading's residual calling an optimizer helper: the helper's
            // panic outcome would need its own Rust form)
            if panic {
                return Err(format!("its panic-explicit reading's residual calls `{}` (a reading's helpers are not lowered yet)", pv.item(cid).path));
            }
            // the buffer model: printed as buffer calls in state mode
            if state.is_some() && crate::opt::drive::KEPT_LIFT_MODEL.contains(&pv.item(cid).path.to_string().as_str()) {
                continue;
            }
            if (cid.0 as usize) < krate.items.len() {
                return Err(format!("the residual calls `{}`, which the lowered code cannot name", pv.item(cid).path));
            }
            if helpers.iter().any(|(x, _)| *x == cid) {
                continue;
            }
            helpers.push((cid, format!("{HELPER_PREFIX}{}", pv.item(cid).name)));
            queue.push(cid);
        }
    }
    let mut names = names_base.clone();
    for (h, n) in &helpers {
        if *h != subject {
            names.fns.insert(*h, n.clone());
        }
    }
    let mut out_helpers = Vec::new();
    for (h, n) in &helpers {
        let mut printed = match state {
            Some(State::BufMut(k)) if *h == subject => lower::lower_fn_state(pv, *h, n, &names, k),
            Some(State::Buf(k)) if *h == subject => lower::lower_fn_reader(pv, *h, n, &names, k, has_result),
            _ if panic && *h == subject => lower::lower_fn_panic(pv, *h, n, &names),
            _ => lower::lower_fn(pv, *h, n, &names),
        }
        .map_err(|e| format!("the residual cannot be printed as Rust: {e}"))?;
        // the replacement of a `const fn` is called where the source is, in
        // const contexts too: every helper is a `const fn`, and its printed
        // body must be one
        if konst {
            lower::const_compatible(pv, *h).map_err(|e| format!("a `const fn` whose residual is {e}"))?;
            printed = lower::as_const(printed);
        }
        let (refer, compare) = if *h == subject { (residual_global, residual_global) } else { *o.targets.get(h).ok_or_else(|| format!("the helper `{}` has no optimized definition", pv.item(*h).path))? };
        out_helpers.push(Helper { name: n.clone(), text: printed.text, refer, compare });
    }
    let link = match &rep.link {
        Some(crate::opt::Link::Lemma(l)) => Some(l.clone()),
        _ => None,
    };
    let inst = Inst { ty: None, orig_global, target: residual_global, entry: name.to_string(), rung: rep.rung.map(|r| r.name().to_string()).unwrap_or_default(), cost_source: cs, cost_residual: cr, link, panic: panic_source };
    Ok((inst, out_helpers))
}

/// The print view with every panic-explicit reading in its Rust form
/// (`lower::panic_rust_form`, DESIGN.md §8.2 item 12): what the lowering
/// prices and prints for a source function that can panic. A reading whose
/// residual has no Rust form keeps its `Option` result (and is refused,
/// with the reason, when its source is considered).
fn panic_view(pv: &Crate, o: &Optimized) -> Crate {
    let mut v = pv.clone();
    for r in o.panics.iter().filter_map(|r| r.item) {
        if let Some(f) = pv.fn_def(r)
            && let Ok(rf) = lower::panic_rust_form(f)
            && let crate::hir::ItemKind::Fn(slot) = &mut v.items[r.0 as usize].kind
        {
            *slot = rf;
        }
    }
    v
}

/// Why a residual costing `cr` keeps the source costing `cs` (the selection
/// gate, `cost::model::beats`): not 3% cheaper, and, where it is so, that
/// the residual is the source itself (its kernel body is the source's in
/// every relevant position: the optimizer found nothing to change) or
/// costs exactly the same (the tie rule: a tie keeps the source).
fn not_cheaper(out: &Output, residual: GlobalId, source: GlobalId, cr: u64, cs: u64) -> String {
    let same = match (out.env.global_body(residual), out.env.global_body(source)) {
        (Some(a), Some(b)) => out.env.alpha_eq_relevant(&a, &b, &|x: GlobalId, y: GlobalId| x == y),
        _ => false,
    };
    let why = if same {
        "; the residual is the source itself: the optimizer found nothing cheaper"
    } else if cr == cs {
        "; a tie keeps the source"
    } else {
        ""
    };
    format!("the residual is not 3% cheaper than the source (portable model: {cr} vs {cs} milli-cycles){why}")
}

#[allow(clippy::too_many_arguments)]
fn residual_candidate(krate: &Crate, pv: &Crate, out: &Output, o: &Optimized, src_costs: &Costs<'_>, res_costs: &Costs<'_>, names_base: &Names, mpath: &str, sf: &SourceFn, id: ItemId) -> Result<Candidate, String> {
    let name = format!("{HELPER_PREFIX}{}", sf.key());
    if std::env::var_os("SANDBLASTER_OPT_TRACE").is_some() {
        let t = match sf.state {
            Some(State::BufMut(k)) => lower::lower_fn_state(pv, id, "trace", names_base, k),
            Some(State::Buf(k)) => lower::lower_fn_reader(pv, id, "trace", names_base, k, sf.has_result),
            None => lower::lower_fn(pv, id, "trace", names_base),
        };
        eprintln!("lower: `{}` costs {} (source {}); residual as Rust: {}", sf.path(mpath), res_costs.of(id), src_costs.of(id), t.map(|l| l.text).unwrap_or_else(|e| format!("not printable: {e}")));
        if sf.state.is_none() {
            let st = lower::lower_fn(krate, id, "source", names_base);
            eprintln!("lower: `{}`'s structured reading as Rust: {}", sf.path(mpath), st.map(|l| l.text).unwrap_or_else(|e| format!("not printable: {e}")));
        }
        if let Some(pid) = o.panics.iter().find(|r| r.source == id).and_then(|r| r.item) {
            let pt = lower::lower_fn_panic(pv, pid, "panic_reading_residual", names_base);
            eprintln!("lower: `{}`'s panic-explicit reading's residual costs {} in its Rust form: {}", sf.path(mpath), res_costs.of(pid), pt.map(|l| l.text).unwrap_or_else(|e| format!("not printable: {e}")));
        }
    }
    let (inst, helpers) = lower_residual(krate, pv, out, o, src_costs, res_costs, names_base, id, &name, sf.state, sf.has_result, sf.is_const)?;
    let entry = format!("{{\n    {name}({})\n}}", sf.params.join(", "));
    let via = if inst.panic.is_some() { format!("the residual of its panic-explicit reading `{}` (it can panic; its panics are preserved, by the lifted round trip's panic theorems)", out.env.global_name(inst.orig_global).unwrap_or_default()) } else { String::new() };
    Ok(Candidate { src: sf.clone(), insts: vec![inst], helpers, entry, dispatch: None, via, origin: LowerOrigin::Optimizer })
}

/// A `#[rewrite]` candidate (user code, [`LowerOrigin::UserRewrite`]): the
/// alternative's text and the alternatives it calls, renamed, with the
/// kernel-checked link.
#[allow(clippy::too_many_arguments)]
fn rewrite_candidate(c: &Checked, krate: &Crate, out: &mut Output, src_costs: &Costs<'_>, mpath: &str, sf: &SourceFn, id: ItemId, r: &Rewrite, _text: &str) -> Result<Candidate, String> {
    let lemma_path = krate.item(r.lemma).path.to_string();
    let alt_path = krate.item(r.alt).path.to_string();
    let lemma = *out.fn_globals.get(&r.lemma).ok_or_else(|| format!("the `#[rewrite]` lemma `{lemma_path}` is not kernel-checked"))?;
    let orig = *out.fn_globals.get(&id).ok_or("not kernel-checked")?;
    let g = *out.fn_globals.get(&r.alt).ok_or_else(|| format!("the alternative `{alt_path}` is not kernel-checked"))?;
    let (cs, cg) = (src_costs.of(id), src_costs.of(r.alt));
    if std::env::var_os("SANDBLASTER_LOWER_PROBE").is_some() {
        fn show(k: &Crate, c: &Costs<'_>, id: ItemId, depth: usize, seen: &mut HashSet<ItemId>) {
            if !seen.insert(id) || depth > 3 {
                return;
            }
            let f = k.fn_def(id);
            eprintln!("PROBE cost {}{} = {} (recursion {:?}, decreases max {:?})", "  ".repeat(depth), k.item(id).path, c.of(id), f.map(|f| f.recursion), f.and_then(|f| f.decreases.as_ref().map(|d| d.max)));
            for cid in lower::callees(k, id) {
                show(k, c, cid, depth + 1, seen);
            }
        }
        show(krate, src_costs, id, 0, &mut HashSet::new());
        show(krate, src_costs, r.alt, 0, &mut HashSet::new());
    }
    if !crate::opt::cost::model::beats(cg, cs) {
        return Err(format!("the alternative `{alt_path}` of `#[rewrite]` lemma `{lemma_path}` is not 3% cheaper than the source (portable model: {cg} vs {cs} milli-cycles)"));
    }
    // the alternatives `g` calls (functions of the same `#[lift(opt)]` file)
    let alt_mod = krate.item(r.alt).module;
    let alt_file = krate.modules[alt_mod.0 as usize].file;
    let alt_text_src = c.sm.get(alt_file).map(|f| f.text.clone()).ok_or("the alternatives file is not in the source map")?;
    let mut closure: Vec<ItemId> = vec![r.alt];
    let mut queue = vec![r.alt];
    while let Some(h) = queue.pop() {
        for cid in lower::callees(krate, h) {
            if krate.item(cid).module == alt_mod && !closure.contains(&cid) {
                closure.push(cid);
                queue.push(cid);
            }
        }
    }
    let rename: HashMap<String, String> = closure.iter().map(|&i| (krate.item(i).name.clone(), format!("{HELPER_PREFIX}{}", krate.item(i).name))).collect();
    let mut helpers = Vec::new();
    for &h in &closure {
        let hn = krate.item(h).name.clone();
        let hg = *out.fn_globals.get(&h).ok_or_else(|| format!("the alternative `{}` is not kernel-checked", krate.item(h).path))?;
        let (t, is_const) = alt_text(&alt_text_src, &hn, &rename)?;
        if sf.is_const && !is_const {
            return Err(format!("`{}` is a `const fn`, but its alternative `{}` is not", sf.path(mpath), krate.item(h).path));
        }
        helpers.push(Helper { name: rename[&hn].clone(), text: t, refer: hg, compare: hg });
    }
    let link = rewrite_link(out, orig, g, lemma)?;
    let entry_name = rename[&krate.item(r.alt).name].clone();
    let entry = format!("{{\n    {entry_name}({})\n}}", sf.params.join(", "));
    let link_name = out.env.global_name(link).map(|s| s.to_string()).unwrap_or_default();
    let inst = Inst { ty: None, orig_global: orig, target: g, entry: entry_name, rung: "Rewrite".into(), cost_source: cs, cost_residual: cg, link: Some(link_name.clone()), panic: None };
    Ok(Candidate { src: sf.clone(), insts: vec![inst], helpers, entry, dispatch: None, via: format!("user-supplied alternative `{alt_path}`, `#[rewrite]` lemma `{lemma_path}` (`{link_name}`)"), origin: LowerOrigin::UserRewrite })
}

/// A generic candidate: one lowered residual per verified instance, and
/// the per-type dispatch (module docs).
#[allow(clippy::too_many_arguments)]
fn dispatch_candidate(c: &Checked, krate: &Crate, pv: &Crate, out: &Output, o: &Optimized, src_costs: &Costs<'_>, res_costs: &Costs<'_>, names_base: &Names, by_path: &HashMap<String, ItemId>, mpath: &str, info: &LiftedInfo, sf: &SourceFn, g: &Generic, text: &str) -> Result<Candidate, String> {
    if sf.is_const {
        return Err("a generic `const fn`".into());
    }
    let tys = c.lift_facts.sealed_impls.get(&g.bound).ok_or_else(|| format!("`{}` is not a trait the lifted file implements for primitive types (the dispatch needs its impl types)", g.bound))?;
    if find_trait(text, &g.bound).is_none() {
        return Err(format!("the trait `{}` is not declared in an inline module of the file", g.bound));
    }
    let key = sf.key();
    let method = format!("{HELPER_PREFIX}{key}");
    let recv = g.recv.ok_or("no receiver")?;
    let others: Vec<(usize, &String)> = sf.params.iter().enumerate().filter(|(k, _)| *k != recv).collect();
    let subst = |t: &str| subst_ident(t, &g.param, "Self");
    let decl_params: String = others.iter().map(|(k, p)| format!(", {p}: {}", subst(&sf.param_tys[*k]))).collect();
    let ret = sf.ret.as_ref().map(|r| format!(" -> {}", subst(r))).unwrap_or_default();
    let decl = format!("fn {method}(self{decl_params}){ret};");
    let call_args = |recv_name: &str| sf.params.iter().enumerate().map(|(k, p)| if k == recv { recv_name.to_string() } else { p.clone() }).collect::<Vec<_>>().join(", ");
    let mut insts = Vec::new();
    let mut helpers: Vec<Helper> = Vec::new();
    let mut impls = Vec::new();
    let mut orig = None;
    for ty in tys {
        let inst_path = match &sf.owner {
            Some(o) => format!("{mpath}::{o}::{}__{ty}", sf.name),
            None => format!("{mpath}::{}__{ty}", sf.name),
        };
        let lifted_ty = if info.unverified.contains(ty) { None } else { by_path.get(&inst_path).copied() };
        let body = match lifted_ty {
            Some(id) => {
                let name = format!("{HELPER_PREFIX}{key}_for_{ty}");
                let (mut inst, hs) = lower_residual(krate, pv, out, o, src_costs, res_costs, names_base, id, &name, None, sf.has_result, false).map_err(|e| format!("instance `{ty}`: {e}"))?;
                inst.ty = Some(ty.clone());
                insts.push(inst);
                for h in hs {
                    if !helpers.iter().any(|x| x.name == h.name) {
                        helpers.push(h);
                    }
                }
                format!("{name}({})", call_args("self"))
            }
            None if info.unverified.contains(ty) => {
                if orig.is_none() {
                    let mut t = text[sf.item_start..sf.body.1].to_string();
                    // the copy: the same item, private, under another name
                    let head = &text[sf.item_start..sf.ident_end];
                    let fn_at = head.rfind(&format!("fn {}", sf.name)).ok_or("the function's name is not after `fn`")?;
                    t.replace_range(0..fn_at + 3 + sf.name.len(), &format!("fn {ORIG_PREFIX}{key}"));
                    orig = Some(format!("#[allow(dead_code)]\n{t}\n"));
                }
                format!("{ORIG_PREFIX}{key}::<{ty}>({})", call_args("self"))
            }
            None => return Err(format!("the instance `{inst_path}` was not lifted")),
        };
        let params: String = others.iter().map(|(k, p)| format!(", {p}: {}", subst(&sf.param_tys[*k]))).collect();
        impls.push((ty.clone(), format!("    #[inline(always)]\n    fn {method}(self{params}){ret} {{\n        {body}\n    }}\n")));
    }
    if insts.is_empty() {
        return Err("no verified instance".into());
    }
    let entry = format!("{{\n    {}.{method}({})\n}}", sf.params[recv], others.iter().map(|(_, p)| p.as_str()).collect::<Vec<_>>().join(", "));
    let via = format!("per-type dispatch `{DISPATCH_PREFIX}{}` over {}", g.bound, insts.iter().filter_map(|i| i.ty.clone()).collect::<Vec<_>>().join(", "));
    Ok(Candidate { src: sf.clone(), insts, helpers, entry, dispatch: Some(Dispatch { bound: g.bound.clone(), decl, impls, orig }), via, origin: LowerOrigin::Optimizer })
}

/// `t` (Rust tokens as text) with the identifier `from` replaced by `to`.
fn subst_ident(t: &str, from: &str, to: &str) -> String {
    let Ok(ts) = t.parse::<proc_macro2::TokenStream>() else { return t.to_string() };
    fn go(ts: proc_macro2::TokenStream, from: &str, to: &str) -> proc_macro2::TokenStream {
        ts.into_iter()
            .map(|t| match t {
                proc_macro2::TokenTree::Ident(i) if i == from => proc_macro2::TokenTree::Ident(proc_macro2::Ident::new(to, i.span())),
                proc_macro2::TokenTree::Group(g) => {
                    let mut ng = proc_macro2::Group::new(g.delimiter(), go(g.stream(), from, to));
                    ng.set_span(g.span());
                    proc_macro2::TokenTree::Group(ng)
                }
                o => o,
            })
            .collect()
    }
    go(ts, from, to).to_string()
}

/// A trait declared in an inline module of the file: the offsets of its
/// item start and of the end of its supertrait list (or of its name, when
/// it has none), and whether it has supertraits.
fn find_trait(text: &str, name: &str) -> Option<(usize, usize, bool)> {
    let file = syn::parse_file(text).ok()?;
    let ls = line_starts(text);
    fn search<'a>(items: &'a [syn::Item], name: &str, inline: bool) -> Option<&'a syn::ItemTrait> {
        for it in items {
            match it {
                syn::Item::Trait(t) if inline && t.ident == name => return Some(t),
                syn::Item::Mod(m) => {
                    if let Some((_, items)) = &m.content
                        && let Some(t) = search(items, name, true)
                    {
                        return Some(t);
                    }
                }
                _ => {}
            }
        }
        None
    }
    let t = search(&file.items, name, false)?;
    if !t.generics.params.is_empty() {
        return None;
    }
    let start_span = t.attrs.first().map(|a| a.pound_token.span).unwrap_or_else(|| syn::spanned::Spanned::span(&t.vis));
    let start = offset(text, &ls, start_span.start())?;
    let (end, has) = match t.supertraits.last() {
        Some(b) => (offset(text, &ls, syn::spanned::Spanned::span(b).end())?, true),
        None => (offset(text, &ls, t.ident.span().end())?, false),
    };
    Some((start, end, has))
}

/// The source functions of the lifted module by their names in the file
/// (the lowered code calls the top-level ones by these names).
fn source_fn_names(by_path: &HashMap<String, ItemId>, mpath: &str, fns: &[SourceFn], krate: &Crate) -> Names {
    let mut names = Names::default();
    for f in fns.iter().filter(|f| f.owner.is_none() && f.generic.is_none()) {
        if let Some(&i) = by_path.get(&f.path(mpath))
            && (i.0 as usize) < krate.items.len()
        {
            names.fns.insert(i, f.name.clone());
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
    let ts = quote::ToTokens::to_token_stream(&block);
    if names_ident(ts.clone(), name) {
        return Some(format!("the rewritten body names `{name}` itself"));
    }
    fn any_prefixed(ts: proc_macro2::TokenStream, p: &str) -> bool {
        ts.into_iter().any(|t| match t {
            proc_macro2::TokenTree::Ident(i) => i.to_string().starts_with(p),
            proc_macro2::TokenTree::Group(g) => any_prefixed(g.stream(), p),
            _ => false,
        })
    }
    if any_prefixed(ts, CHECK_PREFIX) {
        return Some("the rewritten body names a round-trip copy".into());
    }
    None
}

/// The file with the candidates applied: the dispatch declarations, the
/// rewritten bodies (emission) or the round trip's copies (`check`), and
/// the appended helpers, dispatch impls and original copies.
fn assemble(text: &str, cands: &[Candidate], check: bool) -> String {
    // edits at source offsets (applied last first)
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    if !check {
        for cd in cands {
            // the body at the indentation of its item (an impl's function
            // is indented)
            let ls = text[..cd.src.body.0].rfind('\n').map(|i| i + 1).unwrap_or(0);
            let indent: String = text[ls..].chars().take_while(|c| *c == ' ').collect();
            let entry = cd.entry.lines().enumerate().map(|(k, l)| if k == 0 { l.to_string() } else { format!("{indent}{l}") }).collect::<Vec<_>>().join("\n");
            edits.push((cd.src.body.0, cd.src.body.1, entry));
            // (no parameter is mutated by the call of the replacement)
            for &(a, b) in &cd.src.param_muts {
                edits.push((a, b, String::new()));
            }
        }
    }
    // the dispatch traits, one per sealed trait (methods in candidate order)
    let mut by_bound: BTreeMap<String, Vec<&Candidate>> = BTreeMap::new();
    for cd in cands {
        if let Some(d) = &cd.dispatch {
            by_bound.entry(d.bound.clone()).or_default().push(cd);
        }
    }
    let mut impls_text = String::new();
    let mut origs = String::new();
    for (bound, cds) in &by_bound {
        let Some((start, sup_end, has_sup)) = find_trait(text, bound) else { continue };
        let tn = format!("{DISPATCH_PREFIX}{bound}");
        let methods: String = cds.iter().map(|cd| format!("        {}\n", cd.dispatch.as_ref().unwrap().decl)).collect();
        edits.push((start, start, format!("/// sandblaster: the per-type dispatch of the optimized generic functions over `{bound}` (DESIGN.md §2.1).\n    #[doc(hidden)]\n    #[allow(non_camel_case_types)]\n    pub trait {tn}: Sized {{\n{methods}    }}\n\n    ")));
        edits.push((sup_end, sup_end, if has_sup { format!(" + {tn}") } else { format!(": {tn}") }));
        // impls per type (the order of the first candidate's types)
        let tys: Vec<String> = cds[0].dispatch.as_ref().unwrap().impls.iter().map(|(t, _)| t.clone()).collect();
        let sealed_mod = sealed_module_path(text, bound).unwrap_or_default();
        for ty in tys {
            let mut ms = String::new();
            for cd in cds {
                if let Some((_, m)) = cd.dispatch.as_ref().unwrap().impls.iter().find(|(t, _)| *t == ty) {
                    ms.push_str(m);
                }
            }
            impls_text.push_str(&format!("\nimpl {sealed_mod}{tn} for {ty} {{\n{ms}}}\n"));
        }
        for cd in cds {
            if let Some(o) = &cd.dispatch.as_ref().unwrap().orig {
                origs.push('\n');
                origs.push_str(o);
            }
        }
    }
    edits.sort_by_key(|e| std::cmp::Reverse(e.0));
    let mut body = text.to_string();
    for (a, b, t) in edits {
        body.replace_range(a..b, &t);
    }
    if !body.ends_with('\n') {
        body.push('\n');
    }
    if check {
        for cd in cands {
            body.push('\n');
            body.push_str(&check_copy(text, cd));
        }
    }
    body.push_str(&helpers_section(cands));
    body.push_str(&impls_text);
    body.push_str(&origs);
    body
}

/// The inline-module path (`sealed::`) of the trait `name`, from the file's
/// top level.
fn sealed_module_path(text: &str, name: &str) -> Option<String> {
    let file = syn::parse_file(text).ok()?;
    fn search(items: &[syn::Item], name: &str, path: &mut Vec<String>) -> bool {
        for it in items {
            match it {
                syn::Item::Trait(t) if t.ident == name && !path.is_empty() => return true,
                syn::Item::Mod(m) => {
                    if let Some((_, items)) = &m.content {
                        path.push(m.ident.to_string());
                        if search(items, name, path) {
                            return true;
                        }
                        path.pop();
                    }
                }
                _ => {}
            }
        }
        false
    }
    let mut p = Vec::new();
    search(&file.items, name, &mut p).then(|| p.iter().map(|s| format!("{s}::")).collect())
}

/// The appended helpers (each once, in candidate order).
fn helpers_section(cands: &[Candidate]) -> String {
    let mut s = String::from("\n// sandblaster: the optimizer's replacements of the functions above whose bodies call them, lowered to\n// Rust and checked by the lifted round trip (DESIGN.md §2.1).\n");
    let mut seen: HashSet<String> = HashSet::new();
    for cd in cands {
        for h in &cd.helpers {
            if seen.insert(h.name.clone()) {
                s.push('\n');
                s.push_str(&h.text);
            }
        }
    }
    s
}

/// The names of the top-level items `new` declares and `old` does not (the
/// round trip's copies and helpers); empty when either does not parse.
fn new_items(old: &str, new: &str) -> Vec<String> {
    let names = |t: &str| -> Option<Vec<String>> {
        let f = syn::parse_file(t).ok()?;
        Some(
            f.items
                .iter()
                .filter_map(|it| match it {
                    syn::Item::Fn(x) => Some(x.sig.ident.to_string()),
                    syn::Item::Struct(x) => Some(x.ident.to_string()),
                    syn::Item::Enum(x) => Some(x.ident.to_string()),
                    syn::Item::Trait(x) => Some(x.ident.to_string()),
                    syn::Item::Const(x) => Some(x.ident.to_string()),
                    syn::Item::Type(x) => Some(x.ident.to_string()),
                    _ => None,
                })
                .collect(),
        )
    };
    let (Some(o), Some(n)) = (names(old), names(new)) else { return vec![] };
    n.into_iter().filter(|x| !o.contains(x)).collect()
}

/// `text` with the `items = ".."` of the `#[lift(..)]` attribute on the
/// declaration `mod <name>` extended by `added`; `None` when `text` has no
/// such declaration or its attribute names no `items`.
fn with_items(text: &str, name: &str, added: &[String]) -> Option<String> {
    let b = text.as_bytes();
    // the index after the `]` closing the attribute that starts at `i` (`#[`)
    let attr_end = |i: usize| -> Option<usize> {
        let (mut depth, mut j, mut in_str) = (0i32, i + 1, false);
        while j < b.len() {
            match b[j] {
                b'"' if j == 0 || b[j - 1] != b'\\' => in_str = !in_str,
                b'[' | b'(' if !in_str => depth += 1,
                b']' | b')' if !in_str => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(j + 1);
                    }
                }
                _ => {}
            }
            j += 1;
        }
        None
    };
    let mut from = 0;
    while let Some(i) = text[from..].find("#[lift(").map(|k| k + from) {
        let end = attr_end(i)?;
        // the item the attribute is on: past the other attributes and the visibility
        let mut k = end;
        loop {
            while k < b.len() && b[k].is_ascii_whitespace() {
                k += 1;
            }
            if text[k..].starts_with("#[") {
                k = attr_end(k)?;
            } else if text[k..].starts_with("pub(") {
                k += text[k..].find(')')? + 1;
            } else if text[k..].starts_with("pub ") {
                k += 4;
            } else {
                break;
            }
        }
        let decl = format!("mod {name}");
        let on_it = text[k..].starts_with(&decl) && text[k + decl.len()..].starts_with(|c: char| !(c.is_alphanumeric() || c == '_'));
        let attr = &text[i..end];
        let key = attr.match_indices("items").map(|(p, _)| p).find(|p| {
            let before = attr[..*p].chars().next_back();
            matches!(before, Some('(' | ',' | ' ' | '\t' | '\n')) && attr[p + 5..].trim_start().starts_with('=')
        });
        if on_it && let Some(p) = key {
            let q1 = i + p + attr[p..].find('"')? + 1;
            let q2 = q1 + text[q1..].find('"')?;
            let list = text[q1..q2].trim();
            let ext = if list.is_empty() { added.join(", ") } else { format!("{list}, {}", added.join(", ")) };
            return Some(format!("{}{ext}{}", &text[..q1], &text[q2..]));
        }
        from = end;
    }
    None
}

/// The check copy of a candidate: the source item from `fn` with the name
/// `__sandblaster_check__<f>` and the rewritten body.
fn check_copy(text: &str, cd: &Candidate) -> String {
    // the signature tail as the rewritten function has it (without the
    // parameters' `mut`)
    let mut tail = text[cd.src.ident_end..cd.src.body.0].to_string();
    for &(a, b) in cd.src.param_muts.iter().rev() {
        tail.replace_range(a - cd.src.ident_end..b - cd.src.ident_end, "");
    }
    format!("fn {CHECK_PREFIX}{}{} {}\n", cd.src.key(), tail.trim_end(), cd.entry)
}

/// Per source function key, `Ok` or the first failure; the number of
/// definitions compared structurally (0 for a module read from MIR, whose
/// shipped code is checked by its theorems instead); and, with the test hook
/// [`LowerFault::CompareStructurally`] only, what the structural comparison
/// would have refused.
type Verdicts = (BTreeMap<String, Result<(), String>>, usize, Vec<String>);

/// Records the first failure of source function `f`.
fn fail(v: &mut BTreeMap<String, Result<(), String>>, f: &str, e: String) {
    if let Some(x) = v.get_mut(f)
        && x.is_ok()
    {
        *x = Err(e);
    }
}

/// Runs the lifted round trip on `cands`; per source function key, `Ok`
/// or the first failure. `Err` fails the whole step.
///
/// The copy is read back by the same front end in every case. What decides
/// a function then depends on what checks its shipped code:
/// * **a module read from rustc's MIR** (every lifted exec module since the
///   source lift's reading of bodies was retired): the shipped code's
///   theorems (`L::shipped::<id>`, and for a function that can panic
///   `L::pthm::<id>` with `L::pshipped::<id>`), proven against the copy's
///   own MIR and accepted by the trusted check (`mir::gate`). The copy's
///   structured reading is not elaborated or compared: it is untrusted, and
///   the theorems are about the literal reading of the MIR rustc compiles,
///   so a syntactic comparison of the structured reading with the residual
///   adds nothing they do not decide (DESIGN.md §2.1, docs/mir-lift.md
///   §20.7);
/// * **a module without MIR** (none since the lift refuses a lifted exec
///   module without `mir = ".."`; kept for a reading of bodies without MIR):
///   the syntactic comparison of [`compare_read_back`].
#[allow(clippy::too_many_arguments)]
fn round_trip(c: &Checked, root: &Path, out: &mut Output, text: &str, mpath: &str, info: &LiftedInfo, cands: &[Candidate], fault: Option<LowerFault>) -> Result<Verdicts, String> {
    // 1. the source (with the dispatch declarations), the copies, the
    // helpers and dispatch impls, read by the same front end (for a module
    // read from MIR, with the copy's MIR: the load checks that MIR against
    // the copy's text, every source by its SHA-256, so the theorems below
    // are about the copy the build emits)
    let check_text = assemble(text, cands, true);
    let lifted_path = c.sm.path(info.file).to_path_buf();
    let mut fs = MemFs::new();
    for (_, f) in c.sm.files() {
        fs.insert(&f.path, f.text.clone());
    }
    // a module read from rustc's MIR: the copy's bodies are rustc's MIR of
    // the copy (extracted from this text; the load checks its SHA-256), which
    // every module sharing the MIR file then reads
    let mut rt_text: Option<String> = None;
    if let Some(mir) = &info.mir {
        let want = crate::lift::roundtrip_mir_path(mir, mpath);
        let found = info.mir_roundtrip.as_ref().and_then(|p| c.sm.files().find(|(_, f)| f.path == *p).map(|(_, f)| f.text.clone()));
        rt_text = found.clone();
        let Some(rt) = found else {
            return Err(format!("no MIR of the round trip's copy: extract `{}` from this build's copy `OUT_DIR/<name>-roundtrip__{}.rs` (`sandblaster/mirx/extract.sh .. --replace <the source>=<that file>`, docs/mir-lift.md §20.1)", want.display(), mpath.trim_start_matches("crate::").replace("::", "__")));
        };
        fs.insert(mir, rt);
    }
    // a lifted file of which `items = ".."` selects some items: the read-back
    // lifts the round trip's new items too (the copies and the helpers), so
    // its declaration lists them there (the declaring file read back with
    // the extended list; nothing else changes)
    let added = new_items(text, &check_text);
    fs.insert(&lifted_path, check_text);
    if !added.is_empty() {
        for (_, f) in c.sm.files() {
            if f.path != lifted_path
                && let Some(t) = with_items(&f.text, &info.name, &added)
            {
                fs.insert(&f.path, t);
            }
        }
    }
    let krate = c.krate.as_ref().ok_or("no crate")?;
    let c2 = super::check(root, &fs, &krate.target);
    if !c2.ok() {
        let first = c2.diags.list.iter().find(|d| d.severity == crate::diag::Severity::Error).map(|d| d.render(&c2.sm)).unwrap_or_default();
        return Err(format!("the front end rejects the lowered code: {}", first.lines().next().unwrap_or("")));
    }
    let k2 = c2.krate.as_ref().ok_or("no crate")?;
    let mut verdicts: BTreeMap<String, Result<(), String>> = cands.iter().map(|cd| (cd.src.key(), Ok(()))).collect();
    // 2.–4. a module without MIR: the structural comparison; a module read
    // from MIR: its shipped code's theorems decide (5.)
    let compared = if rt_text.is_some() { 0 } else { compare_read_back(out, krate, k2, mpath, cands, &mut verdicts)? };
    // (tests only: what the syntactic comparison would have said here)
    let mut structural = Vec::new();
    if fault == Some(LowerFault::CompareStructurally) && rt_text.is_some() {
        let mut v2 = verdicts.clone();
        structural = match compare_read_back(out, krate, k2, mpath, cands, &mut v2) {
            Ok(_) => v2.into_iter().filter_map(|(f, r)| r.err().map(|e| format!("`{f}`: {e}"))).collect(),
            Err(e) => vec![format!("the whole step: {e}")],
        };
    }
    // (a panic-explicit reading is shipped only with its panic theorems,
    // which are about rustc's MIR of the printed code)
    if rt_text.is_none() {
        for cd in cands.iter().filter(|cd| cd.insts.iter().any(|i| i.panic.is_some())) {
            fail(&mut verdicts, &cd.src.key(), "a source that can panic is replaced only with the panic theorems of rustc's MIR of its replacement (a lifted module read from MIR)".to_string());
        }
    }
    // 5. a module read from MIR: the shipped code's theorems (the copies'
    // and helpers' MIR, the code rustc compiles, against what the laws are
    // about; docs/checked-structuring.md §5.13) decide — a function without
    // them keeps its source text
    if let Some(rt) = &rt_text {
        shipped_theorems(c, out, krate, rt, mpath, cands, fault, &mut verdicts)?;
    }
    Ok((verdicts, compared, structural))
}

/// The syntactic round trip of a lifted module without MIR (steps 2–4 of
/// the module docs' step 3): the read-back's new items elaborated in
/// generated mode against the verified environment; every printed helper
/// must equal its replacement in all relevant positions (modulo `let x = v;
/// x` and the reader normal form) and every copy and dispatch method be the
/// delegation to it. Returns the number of definitions compared.
fn compare_read_back(out: &mut Output, krate: &Crate, k2: &Crate, mpath: &str, cands: &[Candidate], verdicts: &mut BTreeMap<String, Result<(), String>>) -> Result<usize, String> {
    // 2. the ids of the read-back crate, mapped to the verified environment
    // by path (the new items have no counterpart)
    let by_path: HashMap<String, ItemId> = krate.items.iter().map(|it| (it.path.to_string(), it.id)).collect();
    let mut fn_globals = HashMap::new();
    let mut adts = HashMap::new();
    for it in &k2.items {
        let p = it.path.to_string();
        if let Some(pid) = by_path.get(&p) {
            if std::mem::discriminant(&krate.item(*pid).kind) != std::mem::discriminant(&it.kind) {
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
    // 3. targets and elaboration order
    let mut targets: HashMap<String, (GlobalId, GlobalId)> = HashMap::new();
    let mut order: Vec<ItemId> = Vec::new();
    let mut owner: HashMap<String, String> = HashMap::new(); // kernel name → source function key
    let mut expect: Vec<(String, GlobalId, String)> = Vec::new(); // helper kernel name, compare global, function
    // (kernel name, type of, delegation target, function)
    let mut delegations: Vec<(String, GlobalId, GlobalId, String)> = Vec::new();
    let mut add = |kname: String, refer: GlobalId, compare: GlobalId, f: &str, order: &mut Vec<ItemId>| -> Result<bool, String> {
        let Some(id2) = k2.find(&kname) else { return Err(format!("`{kname}` is not in the read-back crate")) };
        owner.entry(kname.clone()).or_insert_with(|| f.to_string());
        if targets.insert(kname, (refer, compare)).is_none() {
            order.push(id2);
            return Ok(true);
        }
        Ok(false)
    };
    for cd in cands {
        let key = cd.src.key();
        // a source that can panic, replaced through its panic-explicit
        // reading: its printed code is checked by the panic theorems
        // against rustc's MIR of it (below), not by a comparison with its
        // structured reading (an `Option` against the code that panics)
        if cd.insts.iter().any(|i| i.panic.is_some()) {
            continue;
        }
        for h in &cd.helpers {
            let kname = format!("{mpath}::{}", h.name);
            if add(kname.clone(), h.refer, h.compare, &key, &mut order)? {
                expect.push((kname, h.compare, key.clone()));
            }
        }
        match &cd.dispatch {
            None => {
                let kname = format!("{mpath}::{CHECK_PREFIX}{key}");
                add(kname.clone(), cd.insts[0].orig_global, cd.insts[0].orig_global, &key, &mut order)?;
                delegations.push((kname, cd.insts[0].orig_global, cd.insts[0].target, key.clone()));
            }
            Some(d) => {
                for inst in &cd.insts {
                    let ty = inst.ty.clone().unwrap_or_default();
                    // the dispatch impl method (the lift's `Trait__Ty__m`)
                    let m = format!("{mpath}::{DISPATCH_PREFIX}{}__{ty}__{HELPER_PREFIX}{key}", d.bound);
                    add(m.clone(), inst.target, inst.target, &key, &mut order)?;
                    delegations.push((m, inst.orig_global, inst.target, key.clone()));
                    let copy = format!("{mpath}::{CHECK_PREFIX}{key}__{ty}");
                    add(copy.clone(), inst.orig_global, inst.orig_global, &key, &mut order)?;
                    delegations.push((copy, inst.orig_global, inst.target, key.clone()));
                }
            }
        }
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
    for (id, e) in errors {
        if id.0 == u32::MAX {
            return Err(format!("generated-mode elaboration: {e}"));
        }
        let n = k2.item(id).path.to_string();
        match owner.get(&n) {
            Some(f) => fail(verdicts, f, format!("`{n}`: {e}")),
            None => return Err(format!("generated-mode elaboration of `{n}`: {e}")),
        }
    }
    let got: HashMap<&str, &crate::elab::generated::GenDef> = defs.iter().map(|d| (d.name.as_str(), d)).collect();
    for (kname, compare, f) in &expect {
        match got.get(kname.as_str()) {
            None => fail(verdicts, f, format!("`{kname}` was not elaborated")),
            Some(d) => {
                let try_get = out.env.lookup_global("crate::__lift_model::buf_try_get_u8");
                let norm = |t: &sandblaster_kernel::term::Tm| read_norm(&let_var_elim(t), try_get);
                if let Some(p) = std::env::var_os("SANDBLASTER_LOWER_DUMP") {
                    use crate::roundtrip::strip;
                    let pr = |t: &sandblaster_kernel::term::Tm| sandblaster_kernel::syntax::printer::print_term_bounded(&out.env, &[], &norm(&strip(t)), 200_000);
                    let cb = out.env.global_body(*compare).map(|b| pr(&b)).unwrap_or_default();
                    let _ = std::fs::write(std::path::Path::new(&p).join(format!("{}.rt.txt", kname.rsplit("::").next().unwrap_or("x"))), format!("PRINTED\n{}\n\nOPTIMIZED\n{cb}\n", pr(&d.body)));
                }
                if let Err(e) = crate::roundtrip::compare_with(out, d, *compare, &norm) {
                    fail(verdicts, f, format!("`{kname}` does not match its replacement: {e}"));
                }
            }
        }
    }
    for (kname, ty_of, target, f) in &delegations {
        match got.get(kname.as_str()) {
            None => fail(verdicts, f, format!("`{kname}` was not elaborated")),
            Some(d) => {
                if let Err(e) = is_delegation(out, d, *ty_of, *target) {
                    fail(verdicts, f, format!("`{kname}`: {e}"));
                }
            }
        }
    }
    Ok(expect.len() + delegations.len())
}

/// Step 5 of the lifted round trip of a module read from rustc's MIR
/// (docs/checked-structuring.md §5.13, docs/mir-lift.md §20.7): per
/// candidate still passing, the theorems of its shipped code — every
/// helper's MIR against the definition it replaces, the copy's (and a
/// dispatch method's) MIR against the replacement's call, and from them,
/// along the optimizer's kernel-checked link, `L::shipped::<id>` of the
/// copy's MIR against the source function (for a function that can panic,
/// `L::pthm::<id>` and `L::pshipped::<id>` against its panic-explicit
/// reading). A function is replaced only when the trusted check
/// (`mir::gate`) accepts them; these theorems are what decides it (no
/// structural comparison of the copy's structured reading runs).
#[allow(clippy::too_many_arguments)]
fn shipped_theorems(c: &Checked, out: &mut Output, krate: &Crate, rt: &str, mpath: &str, cands: &[Candidate], fault: Option<LowerFault>, verdicts: &mut BTreeMap<String, Result<(), String>>) -> Result<(), String> {
    let mut rt_m = crate::mir::ir::parse(rt).map_err(|e| format!("the round trip's MIR: {e}"))?;
    let mir_mpath = format!("{}{}", rt_m.krate, mpath.strip_prefix("crate").unwrap_or(mpath));
    if fault == Some(LowerFault::ShippedMir)
        && let Some(h) = cands.first().and_then(|cd| cd.helpers.first())
    {
        shipped_mir_fault(&mut rt_m, &format!("{mir_mpath}::{}", h.name));
    }
    let name = |g: GlobalId| out.env.global_name(g).map(|n| n.to_string()).unwrap_or_default();
    let mut rfs = Vec::new();
    let mut keys = Vec::new();
    let passing: Vec<&Candidate> = cands.iter().filter(|cd| verdicts.get(&cd.src.key()).is_some_and(|v| v.is_ok())).collect();
    for cd in passing {
        let key = cd.src.key();
        let helpers: Vec<(String, String)> = cd.helpers.iter().map(|h| (format!("{mir_mpath}::{}", h.name), name(h.compare))).collect();
        for inst in &cd.insts {
            let (source, target) = (name(inst.orig_global), name(inst.target));
            let equiv = inst.link.clone().filter(|l| out.env.lookup_global(l).is_some());
            let (copy_key, dispatch_key) = match (&cd.dispatch, &inst.ty) {
                (None, _) => (format!("{mir_mpath}::{CHECK_PREFIX}{key}"), None),
                // the copy at the instance type calls the dispatch impl method of that type
                (Some(d), Some(ty)) => {
                    let m = rt_m.fns.keys().find(|k| k.contains(&format!("{DISPATCH_PREFIX}{} for {ty}>::{HELPER_PREFIX}{key}", d.bound))).cloned();
                    (format!("{mir_mpath}::{CHECK_PREFIX}{key}::<{ty}>"), m)
                }
                (Some(_), None) => {
                    fail(verdicts, &key, "a dispatch instance without its type".to_string());
                    continue;
                }
            };
            if cd.dispatch.is_some() && dispatch_key.is_none() {
                fail(verdicts, &key, format!("no MIR of the dispatch impl method of `{key}` in the round trip's extraction"));
                continue;
            }
            rfs.push(crate::mir::checked::RoundTripFn { source, target, copy_key, dispatch_key, helpers: helpers.clone(), equiv, panic: inst.panic.clone() });
            keys.push(key.clone());
        }
    }
    if !rfs.is_empty() {
        let opts = crate::mir::checked::GateOptions { cache: c.cache.as_deref(), ..Default::default() };
        let outs = crate::mir::checked::prove_roundtrip(out, &c.lift_facts, &rt_m.module, &rt_m, &rfs, &opts);
        // (per source function: every instance's theorems)
        let mut per: BTreeMap<String, (usize, usize, usize, String)> = BTreeMap::new();
        for (o, key) in outs.into_iter().zip(keys.iter().cloned()) {
            match o.result {
                Ok(ps) => {
                    let e = per.entry(key).or_insert((0, 0, 0, o.source.clone()));
                    let cached = ps.iter().any(|(_, p)| p.stats == "cached");
                    if cached {
                        e.2 += 1;
                    } else {
                        e.0 += ps.len();
                        e.1 += ps.iter().filter(|(_, p)| p.kind == "shipped theorem").count();
                    }
                }
                Err(e) => fail(verdicts, &key, format!("the shipped code's theorem: {e}")),
            }
        }
        // a function is replaced only when the trusted check finds the
        // shipped code's theorem in the kernel (crate::mir::gate)
        for (rf, key) in rfs.iter().zip(&keys) {
            let accepted = match &rf.panic {
                // the panic theorems of the source's MIR and of the copy's, each against the reading
                Some(src) => out.mir_gate.ledger.accept_shipped_panic(&out.env, krate, &rt_m, &c.lift_facts, &rf.copy_key, src, &rf.source),
                None => out.mir_gate.ledger.accept_shipped(&out.env, krate, &rt_m, &c.lift_facts, &rf.copy_key, &rf.source),
            };
            if let Err(e) = accepted {
                fail(verdicts, key, format!("the shipped code's theorem: {e}"));
            }
        }
        for (key, (n, shipped, cached, source)) in per {
            if verdicts.get(&key).is_some_and(|v| v.is_ok()) {
                let src = cands.iter().find(|cd| cd.src.key() == key).map(|cd| cd.src.path(mpath)).unwrap_or(source);
                let from_cache = if cached > 0 { format!("; {cached} instance(s) from the verdict cache") } else { String::new() };
                out_notes_push(out, format!("`{src}`: {n} theorem(s) of the shipped MIR ({shipped} against the source function{from_cache})"));
            }
        }
    }
    Ok(())
}

/// [`LowerFault::ShippedMir`]: the first integer constant of `key`'s MIR
/// statements changes by one.
fn shipped_mir_fault(m: &mut crate::mir::ir::Sbmir, key: &str) {
    use crate::mir::ir::{Const, Operand, Rvalue, Stmt};
    let Some(f) = m.fns.get_mut(key) else { return };
    for st in f.blocks.iter_mut().flat_map(|b| b.stmts.iter_mut()) {
        let Stmt::Assign(_, rv, _) = st else { continue };
        let ops: Vec<&mut Operand> = match rv {
            Rvalue::Bin(_, a, b) | Rvalue::Checked(_, a, b) => vec![a, b],
            Rvalue::Use(a) => vec![a],
            _ => vec![],
        };
        for o in ops {
            if let Operand::Const(c) = o
                && let Const::Int(t, x) = c.value().clone()
                && !matches!(t, crate::mir::ir::Ty::Bool)
            {
                *c = Const::Int(t, x + 1);
                return;
            }
        }
    }
}

/// Records a note of the round trip's theorems on the environment's
/// gate memory (read into the lowering record).
fn out_notes_push(out: &mut Output, note: String) {
    out.mir_gate.shipped.push(note);
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

/// A pure read: a variable, the buffer model's `try_get_u8` of a pure read,
/// or a field of a pure read (a single-arm `match` returning a field).
fn pure_read(t: &sandblaster_kernel::term::Tm, try_get: Option<GlobalId>) -> bool {
    match &**t {
        Term::Var(_) => true,
        Term::App { fun, arg, rel: Rel::Rel } => matches!(&**fun, Term::Global(g) if Some(*g) == try_get) && pure_read(arg, try_get),
        Term::Match { scrut, arms, .. } => arms.len() == 1 && matches!(&*arms[0].body, Term::Var(i) if (i.0 as usize) < arms[0].names.len()) && pure_read(scrut, try_get),
        _ => false,
    }
}

/// `t` in the reader normal form the lifted round trip compares readers in
/// (both sides): a relevant `let` of a pure read is substituted into its
/// body, and a single-arm `match` of a pure read on a tuple becomes the
/// tuple's projections. The lift reads `buf.try_get_u8()` as `let (t, r) =
/// try_get(buf)` — two projections of one pure, total model call — where
/// the residual shares the call in a `let` and matches it once; a pure,
/// total term evaluated once or twice, and a tuple matched or projected,
/// are the same value (β for `let`, η for the one-constructor tuple), so
/// nothing is reordered past an effect.
fn read_norm(t: &sandblaster_kernel::term::Tm, try_get: Option<GlobalId>) -> sandblaster_kernel::term::Tm {
    use sandblaster_kernel::term::Arm;
    let Some(tg) = try_get else { return t.clone() };
    fn step(n: sandblaster_kernel::term::Tm, tg: GlobalId, fuel: &mut u32) -> sandblaster_kernel::term::Tm {
        if *fuel == 0 {
            return n;
        }
        match &*n {
            Term::Let { rel: Rel::Rel, val, body, .. } if pure_read(val, Some(tg)) => {
                *fuel -= 1;
                let b = crate::elab::tm::subst0(body, val);
                go(&b, tg, fuel)
            }
            Term::Match { ind, params, scrut, arms, .. }
                if arms.len() == 1 && params.len() == arms[0].names.len() && !arms[0].names.is_empty() && pure_read(scrut, Some(tg)) && !matches!(&*arms[0].body, Term::Var(i) if (i.0 as usize) < arms[0].names.len()) =>
            {
                *fuel -= 1;
                let k = arms[0].names.len();
                let proj = |i: usize| -> sandblaster_kernel::term::Tm {
                    std::rc::Rc::new(Term::Match {
                        ind: *ind,
                        params: params.clone(),
                        scrut: scrut.clone(),
                        motive: sandblaster_kernel::util::shift(&params[i], 1),
                        arms: vec![Arm { names: arms[0].names.clone(), body: mk::var((k - 1 - i) as u32) }],
                    })
                };
                // the arm binds the fields in order (the last is `Var(0)`)
                let mut b = arms[0].body.clone();
                for j in (0..k).rev() {
                    b = crate::elab::tm::subst0(&b, &sandblaster_kernel::util::shift(&proj(j), j as i64));
                }
                go(&b, tg, fuel)
            }
            // `let j = V; C(.., j, ..)` with the constructor's other
            // arguments pure reads: the constructor goes to `V`'s tails
            // (into the arms of a `match`, under a `let`), the lift's state
            // wrapping `(buf, value)` of a block's value
            Term::Let { rel: Rel::Rel, val, body, .. } => {
                let Term::Ctor { ind, ctor, params, args } = &**body else { return n };
                let holes: Vec<usize> = args.iter().enumerate().filter(|(_, a)| matches!(&***a, Term::Var(i) if i.0 == 0)).map(|(k, _)| k).collect();
                let [h] = holes.as_slice() else { return n };
                let others_ok = args.iter().enumerate().all(|(k, a)| k == *h || (!sandblaster_kernel::util::occurs(a, 0) && pure_read(a, Some(tg))));
                if !others_ok || params.iter().any(|p| sandblaster_kernel::util::occurs(p, 0)) {
                    return n;
                }
                *fuel -= 1;
                let down = |t: &sandblaster_kernel::term::Tm| sandblaster_kernel::util::shift(t, -1);
                let cont = (*ind, *ctor, params.iter().map(down).collect::<Vec<_>>(), args.iter().map(down).collect::<Vec<_>>(), *h);
                let pushed = push(&cont, val);
                go(&pushed, tg, fuel)
            }
            _ => n,
        }
    }
    type Cont = (sandblaster_kernel::term::IndId, u32, Vec<sandblaster_kernel::term::Tm>, Vec<sandblaster_kernel::term::Tm>, usize);
    fn shift_cont(c: &Cont, d: i64) -> Cont {
        (c.0, c.1, c.2.iter().map(|t| sandblaster_kernel::util::shift(t, d)).collect(), c.3.iter().map(|t| sandblaster_kernel::util::shift(t, d)).collect(), c.4)
    }
    /// `C[b]` with `C` pushed to `b`'s tails.
    fn push(c: &Cont, b: &sandblaster_kernel::term::Tm) -> sandblaster_kernel::term::Tm {
        match &**b {
            Term::Match { ind, params, scrut, arms, .. } => std::rc::Rc::new(Term::Match {
                ind: *ind,
                params: params.clone(),
                scrut: scrut.clone(),
                motive: sandblaster_kernel::util::shift(&std::rc::Rc::new(Term::Ind { ind: c.0, params: c.2.clone() }), 1),
                arms: arms.iter().map(|a| Arm { names: a.names.clone(), body: push(&shift_cont(c, a.names.len() as i64), &a.body) }).collect(),
            }),
            Term::Let { name, rel, ty, val, body } => std::rc::Rc::new(Term::Let { name: name.clone(), rel: *rel, ty: ty.clone(), val: val.clone(), body: push(&shift_cont(c, 1), body) }),
            _ => {
                let mut args = c.3.clone();
                args[c.4] = b.clone();
                std::rc::Rc::new(Term::Ctor { ind: c.0, ctor: c.1, params: c.2.clone(), args })
            }
        }
    }
    fn go(t: &sandblaster_kernel::term::Tm, tg: GlobalId, fuel: &mut u32) -> sandblaster_kernel::term::Tm {
        crate::elab::tm::map_post(t, 0, &mut |n, _| Some(step(n, tg, fuel))).unwrap_or_else(|| t.clone())
    }
    let mut fuel = 10_000;
    go(t, tg, &mut fuel)
}

/// A call `target x̄` on variables, or a field of one.
fn call_or_field(t: &sandblaster_kernel::term::Tm, target: GlobalId) -> Option<(sandblaster_kernel::term::Tm, Option<usize>)> {
    fn is_call(t: &sandblaster_kernel::term::Tm, target: GlobalId) -> bool {
        match &**t {
            Term::App { fun, arg, .. } => (matches!(&**arg, Term::Var(_)) || matches!(&**arg, Term::Erased)) && is_call(fun, target),
            Term::Global(g) => *g == target,
            _ => false,
        }
    }
    match &**t {
        Term::Match { scrut, arms, .. } if arms.len() == 1 && is_call(scrut, target) => match &*arms[0].body {
            Term::Var(i) if (i.0 as usize) < arms[0].names.len() => Some((scrut.clone(), Some(arms[0].names.len() - 1 - i.0 as usize))),
            _ => None,
        },
        _ if is_call(t, target) => Some((t.clone(), None)),
        _ => None,
    }
}

/// `t` with relevant `let`s of a variable, a call `target x̄` or a field of
/// one substituted, and a tuple of every field of one call, in order,
/// contracted to the call (the lifted round trip's delegation check of a
/// reader, [`is_delegation`]).
fn pair_eta(t: &sandblaster_kernel::term::Tm, target: GlobalId) -> sandblaster_kernel::term::Tm {
    let mut b = t.clone();
    for _ in 0..64 {
        let next = match &*b {
            Term::Let { rel: Rel::Rel, val, body, .. } if matches!(&**val, Term::Var(_)) || call_or_field(val, target).is_some() => crate::elab::tm::subst0(body, val),
            Term::Ctor { args, .. } if !args.is_empty() => {
                let fields: Option<Vec<(sandblaster_kernel::term::Tm, Option<usize>)>> = args.iter().map(|a| call_or_field(a, target)).collect();
                match fields {
                    Some(fs) if fs.len() == args.len() && fs.iter().enumerate().all(|(k, (c, f))| *f == Some(k) && format!("{c:?}") == format!("{:?}", fs[0].0)) => fs[0].0.clone(),
                    _ => break,
                }
            }
            _ => break,
        };
        b = next;
    }
    b
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

/// Whether the read-back definition `d` has the type of `ty_of` and is
/// exactly `λ x̄. target x̄` (after erasing irrelevant binders): the
/// delegation to the replacement.
fn is_delegation(out: &Output, d: &crate::elab::generated::GenDef, ty_of: GlobalId, target: GlobalId) -> Result<(), String> {
    use crate::roundtrip::strip;
    let env = &out.env;
    let ty = env.global_type(ty_of).ok_or("the source function has no type")?;
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
    // a reader's call (`let (s, r) = f(..); buf = s; (buf, r)`): the
    // projections of the one call, paired again, are the call (η for the
    // one-constructor tuple; the replacement is total and pure, so reading
    // it twice is reading it once)
    b = pair_eta(&b, target);
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
        Term::Global(g) if *g == target => {}
        _ => return Err(format!("its body is not the call of the replacement: {}", sandblaster_kernel::syntax::printer::print_term_bounded(env, &[], &strip(&d.body), 600))),
    }
    if args.len() as u32 != k {
        return Err(format!("its body passes {} argument(s) to the replacement for {k} parameter(s)", args.len()));
    }
    for (j, a) in args.iter().enumerate() {
        match &**a {
            Term::Var(ix) if ix.0 == k - 1 - j as u32 => {}
            _ => return Err(format!("argument {j} of the replacement call is not parameter {j}")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The read-back of a file lifted with `items = ".."` lists the round
    /// trip's new items (`round_trip`).
    #[test]
    fn the_read_back_lists_the_new_items() {
        let old = "pub fn f(x: u8) -> u8 { x }\npub fn g() {}\n";
        let new = "pub fn f(x: u8) -> u8 { __sandblaster_opt_f(x) }\npub fn g() {}\nfn __sandblaster_check__f(x: u8) -> u8 { x }\nfn __sandblaster_opt_f(l0_x: u8) -> u8 { l0_x }\n";
        let added = new_items(old, new);
        assert_eq!(added, vec!["__sandblaster_check__f".to_string(), "__sandblaster_opt_f".to_string()]);
        let root = "//! Root.\n#[lift(mir = \"h1.sbmir\", in_place, items = \"f\")]\n#[path = \"../h1/src/lib.rs\"]\npub mod h1;\n\npub use h1::f;\n";
        let got = with_items(root, "h1", &added).expect("the declaration");
        assert!(got.contains("items = \"f, __sandblaster_check__f, __sandblaster_opt_f\")"), "{got}");
        assert_eq!(got.replace(", __sandblaster_check__f, __sandblaster_opt_f", ""), root);
        // another module's declaration, or one without `items`, is left alone
        assert!(with_items(root, "h2", &added).is_none());
        assert!(with_items("#[lift(mir = \"a.sbmir\", in_place)]\nmod h1;\n", "h1", &added).is_none());
        assert!(new_items("fn f( {", new).is_empty());
    }

    fn one(text: &str, name: &str) -> SourceFn {
        source_fns(text).unwrap().into_iter().find(|f| f.name == name).unwrap_or_else(|| panic!("no `{name}`"))
    }

    /// The source scan: what it takes (top-level and associated functions,
    /// one buffer state, one sealed-trait parameter) and, for each refusal,
    /// a twin that it refuses with the reason.
    #[test]
    fn the_source_scan_takes_and_refuses() {
        let t = "fn a(x: u8) -> u8 { x }\nstruct S;\nimpl S {\n    fn b(x: u8) -> u8 { x }\n    fn c(&self) -> u8 { 0 }\n    fn d(x: u8) -> Self { S }\n}\nfn e(x: u8, buf: &mut impl BufMut) { }\nfn f(x: u8, buf: &mut impl BufMut) -> u8 { x }\nfn g(buf: &mut impl Buf) -> Option<u8> { None }\nfn h<T: P>(x: T) -> u8 { 0 }\nfn i<T: P>(x: &T) -> u8 { 0 }\nfn j<T: P + Q>(x: T) -> u8 { 0 }\nfn k<T: P>(x: T, buf: &mut impl BufMut) { }\nconst fn l(x: u8) -> u8 { x }\nfn m((a, b): (u8, u8)) -> u8 { a }\nfn n(x: u8) -> impl Copy { x }\n";
        assert!(one(t, "a").refused.is_none() && one(t, "a").owner.is_none());
        let b = one(t, "b");
        assert!(b.refused.is_none() && b.owner.as_deref() == Some("S") && b.key() == "S_b" && b.path("crate::m") == "crate::m::S::b");
        assert!(one(t, "c").refused.as_deref().unwrap().contains("a method with a receiver"));
        assert!(one(t, "d").refused.as_deref().unwrap().contains("names `Self`"));
        assert_eq!(one(t, "e").state, Some(State::BufMut(1)));
        assert!(one(t, "f").refused.as_deref().unwrap().contains("one `&mut impl BufMut` of a function without a result"));
        let g = one(t, "g");
        assert!(g.refused.is_none() && g.state == Some(State::Buf(0)) && g.has_result);
        let h = one(t, "h");
        assert!(h.refused.is_none() && h.generic.as_ref().is_some_and(|g| g.bound == "P" && g.recv == Some(0)));
        assert!(one(t, "i").refused.as_deref().unwrap().contains("without a by-value parameter of type `T`"));
        assert!(one(t, "j").refused.as_deref().unwrap().contains("bounded by one trait"));
        assert!(one(t, "k").refused.as_deref().unwrap().contains("generic function with buffer state"));
        assert!(one(t, "l").is_const && one(t, "l").refused.is_none());
        assert!(one(t, "m").refused.as_deref().unwrap().contains("pattern"));
        assert!(one(t, "n").refused.as_deref().unwrap().contains("`impl Trait` return type"));
    }

    /// The per-type dispatch finds the sealed trait in an inline module
    /// (and only there) and its supertrait list.
    #[test]
    fn the_dispatch_finds_the_sealed_trait() {
        let t = "mod sealed {\n    /// Docs.\n    pub trait P: Copy + Clone {\n        fn m(self) -> u8;\n    }\n    pub trait Q {}\n}\npub trait R {}\n";
        let (start, end, has) = find_trait(t, "P").unwrap();
        assert!(t[start..].starts_with("/// Docs.") && t[..end].ends_with("Copy + Clone") && has);
        let (_, end, has) = find_trait(t, "Q").unwrap();
        assert!(t[..end].ends_with("pub trait Q") && !has);
        // negative twin: a trait at the top level is not sealed
        assert!(find_trait(t, "R").is_none());
        assert_eq!(sealed_module_path(t, "P").as_deref(), Some("sealed::"));
        assert!(sealed_module_path(t, "R").is_none());
        assert_eq!(subst_ident("Option < T >", "T", "Self"), "Option < Self >");
    }

    /// An alternative's text: private, renamed where it names alternatives,
    /// its docs kept; a generic alternative is refused.
    #[test]
    fn alternative_texts_are_private_and_renamed() {
        let t = "use x::Y;\n/// Docs.\npub fn fast(a: u8) -> u8 {\n    step(a) + step(1)\n}\npub(crate) const fn step(a: u8) -> u8 { a }\npub fn gen<T>(a: T) -> T { a }\n";
        let ren: HashMap<String, String> = [("fast", "__o_fast"), ("step", "__o_step")].iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
        let (f, c) = alt_text(t, "fast", &ren).unwrap();
        assert_eq!(f, "/// Docs.\nfn __o_fast(a: u8) -> u8 {\n    __o_step(a) + __o_step(1)\n}\n");
        assert!(!c);
        let (s, c) = alt_text(t, "step", &ren).unwrap();
        assert_eq!(s, "const fn __o_step(a: u8) -> u8 { a }\n");
        assert!(c);
        assert!(alt_text(t, "gen", &ren).unwrap_err().contains("generic"));
        assert!(alt_text(t, "none", &ren).is_err());
    }
}
