//! Validating specifications (DESIGN.md §15.7, §15.1; stage **S1**).
//!
//! * **Examples.** `#[example(e)]` (a closed `bool` spec expression) is
//!   the kernel lemma `X::example#k : Eq(Bool, e, true)` proven by `refl`
//!   when checking-mode conversion decides it; otherwise the kernel's closed
//!   evaluator `Env::eval_closed` (TCB, AUDIT.md §20) must return `true`.
//!   The front end's reference evaluator is never consulted. A false
//!   example is an error showing both evaluated sides of a top-level `==`;
//!   an exhausted budget is an error, never a skip.
//! * **Vector files.** `#[examples(file = "..", format = cavp | json,
//!   provenance = ..)]` on a checker spec function `c(p₁: T₁, …) -> bool`:
//!   every record binds the parameters by name (case-insensitive; extra
//!   record fields are ignored, a missing one is an error) and `c(v̄)` is
//!   checked like an example (`c::example#fileJ#k`). Integers are decimal
//!   (or `0x` hex); byte sequences (`Seq<u8>`, `[u8; N]`, `&[u8]`) are hex;
//!   a struct is a JSON object with exactly its fields (by name,
//!   case-insensitively; its invariant and `Nat` bounds are obligations), a
//!   tuple an array of its components, an `Option` `null` or its value, and
//!   a `Seq` of anything else an array (§15 S5).
//!   The file is a build input (`loader.rs`); self-derived vectors
//!   (`provenance = self`) are checked but do not count for coverage.
//! * **Coverage** ([`CoverageRecord`]; errors through the §15.8 gate
//!   [`spec15_gate_s1`]): every spec function exercised by a counting
//!   example (reached by its term, `Refs*`), and each outcome of a
//!   `bool`/`Option` spec function seen at least once (the closed calls
//!   of such functions in an example — or in a checker's body instantiated
//!   with a record — evaluated by `eval_closed`). A vector-file checker
//!   needs no outcomes (it is true on every record by construction).
//! * **Spec closure** (§15.1, [`Elab::spec_closure_check`]): `Refs*` of a
//!   spec item (the kernel's `Env::refs_closure`, not descending into
//!   established functions) may contain no exec function or exec constant
//!   other than established ones (and derived `PartialEq`, which the type
//!   determines): `error[spec-depends-on-impl]`. Enforced now for the S1
//!   surface — spec functions of `#[spec]` modules, `#[refines]` targets
//!   and their explicit argument maps, views, representation relations and
//!   examples — and recorded ([`ClosureRecord`]) for the other spec items
//!   (legacy `#[spec] fn`s), which the §15.8 gate turns into errors.
//! * **Fuel** (§15.1): a spec function whose recursion is driven by a fuel
//!   parameter (a `Nat`/`uN` parameter used only to count down and to test
//!   for exhaustion, next to another base case) needs a checked
//!   `#[fuel_sufficient]` lemma naming it (or mentioning it).
//! * **Mirrors** (§15.1): a spec function whose kernel body is
//!   `alpha_eq_relevant` (after inlining non-recursive helpers) to the body
//!   of the exec function refining it needs `#[mirrors_impl(justification =
//!   "..")]` plus an independent example or law; otherwise
//!   `error[spec-mirrors-impl]`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use num_bigint::BigInt;
use sandblaster_kernel::term::{DefKind, GlobalId, Lvl, Recursion, Rel, Term, Tm, Width};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::Budget;

use super::{DefStatus, Elab, FnState, ItemGlobal, R};
use crate::diag::{DiagKind, Diagnostic, Diagnostics};
use crate::hir::*;
use crate::prover::ObligationKind;
use crate::span::{FileId, Span};

/// Kernel steps for deciding one example (conversion is tried with a
/// small share first).
pub const EXAMPLE_BUDGET: u64 = 4_000_000_000;
const CONV_BUDGET: u64 = 50_000_000;

/// Where an example comes from.
#[derive(Clone, Debug)]
pub enum ExampleSource {
    /// The `index`-th `#[example]` of the item.
    Attr { index: u32 },
    /// Record `record` of a vector file.
    File { file: FileId, record: u32 },
}

/// How an example was decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExampleMethod {
    /// The kernel lemma `refl` (checking-mode conversion).
    Conversion,
    /// `Env::eval_closed` returned `true` (TCB).
    EvalClosed,
}

/// One checked example (for the report, coverage and the surface).
#[derive(Clone, Debug)]
pub struct ExampleRecord {
    pub item: ItemId,
    pub source: ExampleSource,
    pub status: DefStatus,
    pub method: Option<ExampleMethod>,
    /// The kernel lemma (conversion only).
    pub lemma: Option<GlobalId>,
    /// Counts for coverage (not `provenance = self`).
    pub counts: bool,
    /// The failure, printed.
    pub detail: String,
    /// The closed kernel term of a checked example (`None` otherwise): the
    /// statement `SPEC.lock` hashes (DESIGN.md §15.6, `crate::surface`).
    pub term: Option<Tm>,
}

/// Example coverage of one spec function (§15.7).
#[derive(Clone, Debug)]
pub struct CoverageRecord {
    pub spec: ItemId,
    /// Reached by some counting example.
    pub exercised: bool,
    /// Outcomes a `bool`/`Option` spec function must show (`true`/`false`,
    /// `None`/`Some`), and those seen.
    pub outcomes_needed: Vec<String>,
    pub outcomes_seen: Vec<String>,
}

/// What a [`ClosureRecord`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClosureKind {
    /// `spec-depends-on-impl` (§15.1).
    DependsOnImpl,
    /// A fuel-bounded spec function without `#[fuel_sufficient]`.
    Fuel,
    /// `spec-mirrors-impl`.
    Mirror,
}

/// A §15.1 finding on a spec item outside the S1 surface (legacy `#[spec]
/// fn`s): recorded, an error of the §15.8 gate ([`spec15_gate_s1`]).
#[derive(Clone, Debug)]
pub struct ClosureRecord {
    pub item: ItemId,
    pub kind: ClosureKind,
    pub span: Span,
    pub msg: String,
    pub note: String,
}

/// A value of a vector-file record field.
#[derive(Clone, Debug)]
enum RecVal {
    Str(String),
    Num(String),
    Bool(bool),
    Arr(Vec<RecVal>),
    /// A JSON object: a struct value, fields by name (§15 S5).
    Obj(Vec<(String, RecVal)>),
    /// JSON `null`: `None` at an `Option` type.
    Null,
}

/// The kernel's verdict on one example term.
enum Verdict {
    /// Checked by conversion (the lemma) or by `eval_closed`.
    True { method: ExampleMethod, lemma: Option<GlobalId> },
    /// Conversion decided it but the kernel rejected the lemma.
    Rejected,
    /// `eval_closed` returned `false` (its value).
    False(Tm),
    /// The evaluation failed or ran out of budget.
    Error { #[allow(dead_code)] out_of_fuel: bool, msg: String },
    /// The term reaches the placeholder of a definition that did not
    /// verify (its name): not checked.
    Blocked(String),
}

/// The evaluated sides of a false `l == r`, printed.
struct Sides {
    left: String,
    right: String,
    diff: Option<String>,
}

/// A record field value as written (shortened).
fn show_rec(v: &RecVal) -> String {
    let s = match v {
        RecVal::Str(s) | RecVal::Num(s) => s.clone(),
        RecVal::Bool(b) => b.to_string(),
        RecVal::Arr(xs) => format!("[{}]", xs.iter().map(show_rec).collect::<Vec<_>>().join(", ")),
        RecVal::Obj(fs) => format!("{{{}}}", fs.iter().map(|(k, v)| format!("{k}: {}", show_rec(v))).collect::<Vec<_>>().join(", ")),
        RecVal::Null => "null".into(),
    };
    if s.chars().count() > 72 { format!("{}… ({} chars)", s.chars().take(72).collect::<String>(), s.chars().count()) } else { s }
}

/// The records of a vector file: `(fields, line)` each.
type Records = Vec<(Vec<(String, RecVal)>, usize)>;

/// Parses a NIST CAVP response file: `Key = Value` lines grouped into
/// records by blank lines; `#` comments and `[..]` headers skipped. A key
/// that repeats inside one record (compared case-insensitively, as fields
/// bind parameters) is an error: records not separated by a blank line
/// would otherwise merge, and every record after the first would be
/// silently dropped (only the first value of a key is bound).
fn parse_cavp(text: &str) -> Result<Records, String> {
    let mut out = Vec::new();
    let mut cur: Vec<(String, RecVal)> = Vec::new();
    let mut start = 0usize;
    for (ln, line) in text.lines().enumerate() {
        let l = line.trim();
        if l.is_empty() {
            if !cur.is_empty() {
                out.push((std::mem::take(&mut cur), start));
            }
            continue;
        }
        if l.starts_with('#') || l.starts_with('[') {
            continue;
        }
        let Some((k, v)) = l.split_once('=') else { return Err(format!("line {}: expected `Key = Value`", ln + 1)) };
        if cur.is_empty() {
            start = ln + 1;
        }
        let k = k.trim().to_string();
        if let Some((prev, _)) = cur.iter().find(|(p, _)| p.eq_ignore_ascii_case(&k)) {
            return Err(format!("line {}: the key `{k}` repeats in the record that starts on line {start} (as `{prev}`); separate records with a blank line", ln + 1));
        }
        cur.push((k, RecVal::Str(v.trim().to_string())));
    }
    if !cur.is_empty() {
        out.push((cur, start));
    }
    Ok(out)
}

/// Parses a JSON vector file: an array of objects, or an object whose
/// only array-valued field holds them.
fn parse_json(text: &str) -> Result<Records, String> {
    use super::value::J;
    let j = J::parse(text)?;
    let arr = match j {
        J::Arr(a) => a,
        J::Obj(fs) => {
            let arrs: Vec<Vec<J>> = fs.into_iter().filter_map(|(_, v)| if let J::Arr(a) = v { Some(a) } else { None }).collect();
            match <[Vec<J>; 1]>::try_from(arrs) {
                Ok([a]) => a,
                Err(_) => return Err("expected an array of records, or an object with exactly one array field".into()),
            }
        }
        _ => return Err("expected an array of records".into()),
    };
    fn conv(j: J) -> Result<RecVal, String> {
        Ok(match j {
            J::Str(s) => RecVal::Str(s),
            J::Num(n) => RecVal::Num(n),
            J::Bool(b) => RecVal::Bool(b),
            J::Arr(a) => RecVal::Arr(a.into_iter().map(conv).collect::<Result<_, _>>()?),
            J::Null => RecVal::Null,
            J::Obj(fs) => {
                let mut out: Vec<(String, RecVal)> = Vec::new();
                for (k, v) in fs {
                    if let Some((prev, _)) = out.iter().find(|(p, _)| p.eq_ignore_ascii_case(&k)) {
                        return Err(format!("the keys `{prev}` and `{k}` of a nested object collide (struct fields bind by name, case-insensitively)"));
                    }
                    out.push((k, conv(v)?));
                }
                RecVal::Obj(out)
            }
        })
    }
    let mut out = Vec::new();
    for (i, r) in arr.into_iter().enumerate() {
        let J::Obj(fs) = r else { return Err(format!("record {i} is not an object")) };
        let mut rec: Vec<(String, RecVal)> = Vec::new();
        for (k, v) in fs {
            // fields bind parameters case-insensitively: a duplicate or
            // case-colliding key would bind only its first value
            if let Some((prev, _)) = rec.iter().find(|(p, _)| p.eq_ignore_ascii_case(&k)) {
                return Err(format!("record {i}: the keys `{prev}` and `{k}` collide (fields bind parameters by name, case-insensitively)"));
            }
            rec.push((k, conv(v)?));
        }
        out.push((rec, i));
    }
    Ok(out)
}

fn parse_int(v: &RecVal) -> Result<BigInt, String> {
    let s = match v {
        RecVal::Str(s) | RecVal::Num(s) => s.trim().replace('_', ""),
        _ => return Err("expected an integer".into()),
    };
    let r = if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) { BigInt::parse_bytes(h.as_bytes(), 16) } else { BigInt::parse_bytes(s.as_bytes(), 10) };
    r.ok_or_else(|| format!("`{s}` is not an integer"))
}

fn parse_hex(v: &RecVal) -> Result<Vec<u8>, String> {
    match v {
        RecVal::Str(s) => {
            let d: String = s.chars().filter(|c| !c.is_whitespace()).collect();
            let d = d.strip_prefix("0x").unwrap_or(&d);
            if !d.len().is_multiple_of(2) || !d.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!("`{s}` is not hex bytes"));
            }
            Ok((0..d.len() / 2).map(|i| u8::from_str_radix(&d[2 * i..2 * i + 2], 16).unwrap()).collect())
        }
        RecVal::Arr(xs) => xs.iter().map(|x| parse_int(x).and_then(|n| u8::try_from(n).map_err(|_| "byte out of range".to_string()))).collect(),
        _ => Err("expected hex bytes".into()),
    }
}

impl<'a> Elab<'a> {
    // ------------------------------------------------------------------
    // spec closure (§15.1)
    // ------------------------------------------------------------------

    /// Whether spec item `id` belongs to the S1 surface, where spec closure,
    /// fuel and mirrors are enforced now: a function of a `#[spec]` module
    /// or a `#[refines]` target (see the module docs). A function of a
    /// `#[model]` module is proof text shaped like the code, not a
    /// specification (its fuel is the code's), so it is not on the surface;
    /// its spec closure is enforced all the same ([`Elab::spec_item_closure`]).
    pub fn s1_surface(&self, id: ItemId) -> bool {
        if self.krate.in_model_module(id) {
            return false;
        }
        self.krate.in_spec_module(id) || self.krate.items.iter().any(|it| matches!(&it.kind, ItemKind::Fn(f) if f.spec.refines.as_ref().is_some_and(|r| r.spec == id)))
    }

    /// The kernel item behind a global (reverse of `Elab::globals`).
    fn item_of_global(&self, g: GlobalId) -> Option<ItemId> {
        self.globals.iter().find_map(|(k, v)| if matches!(v, ItemGlobal::Def(x) if *x == g) { Some(*k) } else { None })
    }

    /// Checks that `terms` (a spec item's statement or body) reach no
    /// unestablished exec function or constant (see the module docs);
    /// `extra_stop` adds functions the item may mention (an example on an
    /// exec function mentions it). Returns whether the item is closed.
    /// The first unestablished exec function or constant that `terms` reach
    /// (see [`Elab::spec_closure_check`]), if any.
    pub fn closure_violation(&self, terms: &[Tm], extra_stop: &[GlobalId]) -> Option<GlobalId> {
        let mut stop: Vec<GlobalId> = self.s1.established.iter().copied().collect();
        stop.extend_from_slice(extra_stop);
        let eqs: HashSet<GlobalId> = self.eq_fns.values().map(|e| e.eq).collect();
        for t in terms {
            for g in self.env.refs_closure(t, &stop) {
                if stop.contains(&g) || eqs.contains(&g) {
                    continue;
                }
                if matches!(self.env.global_kind(g), Some(DefKind::Exec | DefKind::LoopHelper)) {
                    return Some(g);
                }
            }
        }
        None
    }

    #[allow(clippy::too_many_arguments)]
    pub fn spec_closure_check(&mut self, item: ItemId, what: &str, terms: &[Tm], extra_stop: &[GlobalId], surface: bool, span: Span) -> bool {
        let Some(g) = self.closure_violation(terms, extra_stop) else { return true };
        let gname = self.env.global_name(g).map(|n| n.to_string()).unwrap_or_else(|| format!("@{}", g.0));
        let (kind, shown) = match self.item_of_global(g).map(|i| &self.krate.item(i).kind) {
            Some(ItemKind::Const(_)) => ("exec constant", gname.clone()),
            _ if self.env.global_kind(g) == Some(DefKind::LoopHelper) => ("loop of the exec function", gname.split("::loop#").next().unwrap_or(&gname).to_string()),
            _ => ("exec function", gname.clone()),
        };
        let path = self.krate.item(item).path.to_string();
        let msg = format!("{what} `{path}` depends on the {kind} `{shown}`");
        let note = "a specification may use spec functions, spec constants and established exec functions only (refined, with an injective view, by a proven `#[refines]` earlier in the crate, or a lifted function whose laws-file contract is an equation `ret == E` with `E` spec-closed); otherwise any implementation would \"refine\" a spec written in terms of itself — transcribe the definition into `spec::` (DESIGN.md §15.1)".to_string();
        if surface {
            self.diag(Diagnostic::error(DiagKind::SpecDependsOnImpl, span, msg).note(note));
        } else if !self.s1.closure.iter().any(|c| c.item == item && c.kind == ClosureKind::DependsOnImpl) {
            self.s1.closure.push(ClosureRecord { item, kind: ClosureKind::DependsOnImpl, span, msg, note });
        }
        false
    }

    /// Spec closure of a spec function or spec constant just elaborated
    /// (global `g`).
    pub fn spec_item_closure(&mut self, id: ItemId, g: GlobalId) {
        if !self.s1.on {
            return;
        }
        let what = match &self.krate.item(id).kind {
            ItemKind::Const(_) => "spec constant",
            _ => "spec function",
        };
        // a model (layered proofs) never depends on exec code either: the
        // code refines it, so it must not be written in terms of the code
        let surface = self.s1_surface(id) || self.krate.in_model_module(id);
        let span = self.krate.item(id).span;
        self.spec_closure_check(id, what, &[mk::global(g)], &[], surface, span);
    }

    // ------------------------------------------------------------------
    // examples (§15.7)
    // ------------------------------------------------------------------

    /// The `#[example]`s and vector files of item `id` (after every item).
    pub fn examples_hook(&mut self, id: ItemId, examples: &'a [Example], files: &'a [ExampleFile]) {
        if !self.s1.on {
            return;
        }
        let krate = self.krate;
        let it = krate.item(id);
        let own = match self.globals.get(&id) {
            Some(ItemGlobal::Def(g)) => Some(*g),
            _ => None,
        };
        if own.is_none() {
            for e in examples {
                self.diag(Diagnostic::error(DiagKind::Example, e.span, format!("the example cannot be checked: `{}` was not elaborated", it.path)));
            }
            for f in files {
                self.diag(Diagnostic::error(DiagKind::Example, f.span, format!("the vector file cannot be checked: `{}` was not elaborated", it.path)));
            }
            return;
        }
        let exec_self: Vec<GlobalId> = match krate.fn_def(id) {
            Some(f) if f.kind == FnKind::Exec => own.into_iter().collect(),
            _ => vec![],
        };
        for (k, ex) in examples.iter().enumerate() {
            let name = format!("{}::example#{k}", it.path);
            let src = ExampleSource::Attr { index: k as u32 };
            match self.example_term(&name, id, ex) {
                Ok(Some(t)) => {
                    self.spec_closure_check(id, &format!("example #{k} of"), std::slice::from_ref(&t), &exec_self, true, ex.span);
                    self.decide_example(&name, id, t, src, true, ex.span, Some(ex));
                }
                Ok(None) => self.s1.examples.push(ExampleRecord { item: id, source: src, status: DefStatus::Unproven, method: None, lemma: None, counts: true, detail: "an obligation of the example failed".into(), term: None }),
                Err(e) => {
                    self.diag(Diagnostic::error(DiagKind::Example, ex.span, format!("example #{k} of `{}` could not be elaborated: {}", it.path, e.msg)));
                    self.s1.examples.push(ExampleRecord { item: id, source: src, status: DefStatus::Unsupported(e.msg), method: None, lemma: None, counts: true, detail: String::new(), term: None });
                }
            }
        }
        if let Some(f) = krate.fn_def(id) {
            for (j, file) in files.iter().enumerate() {
                self.example_file(id, f, j, file);
            }
        }
    }

    /// The closed term of an `#[example]` (`None`: an obligation inside it
    /// failed, already reported).
    fn example_term(&mut self, name: &str, id: ItemId, ex: &'a Example) -> R<Option<Tm>> {
        self.f = FnState::new(name.to_string(), Some(id), &ex.locals, ex.span);
        self.f.answer = Ty::Bool;
        self.f.ret = Ty::Bool;
        let t = self.expr(&ex.expr, &mut |s, v| Ok(v.at(s.depth())))?;
        Ok(if self.f.failed { None } else { Some(t) })
    }

    /// The first definition that did not verify (a placeholder: an opaque
    /// default body, `Elab::placeholder`) that `t` reaches, by name. An
    /// example evaluated through it would be judged against the default
    /// (`0`, `None`), not against the specification.
    pub fn placeholder_reached(&self, t: &Tm) -> Option<String> {
        if self.s1.placeholders.is_empty() {
            return None;
        }
        self.env.refs_closure(t, &[]).into_iter().find_map(|g| self.s1.placeholders.get(&g).cloned())
    }

    /// The kernel's verdict on one closed `bool` example term (see the
    /// module docs); a conversion proof is added as the lemma `name`.
    fn verdict(&mut self, name: &str, item: ItemId, t: &Tm, span: Span, blocked: Option<String>) -> Verdict {
        self.verdict_in(name, item, t, span, blocked, false)
    }

    /// [`Self::verdict`]; with `closed_first` (a vector-file record: a
    /// checker applied to closed data, §15 S5 G8) the kernel's closed
    /// evaluator decides it directly — checking-mode conversion would
    /// evaluate the same closed term under the checking policy (speculation
    /// on every recursive call) before giving up on large data. A record
    /// `eval_closed` cannot decide still gets the conversion attempt.
    fn verdict_in(&mut self, name: &str, item: ItemId, t: &Tm, span: Span, blocked: Option<String>, closed_first: bool) -> Verdict {
        if let Some(p) = blocked {
            return Verdict::Blocked(p);
        }
        let bool_ = self.p.bool_;
        if closed_first {
            let mut b = Budget { steps: self.opts.example_budget };
            match self.env.eval_closed(t, &mut b) {
                Ok(r) if is_bool(&r, bool_, true) => return Verdict::True { method: ExampleMethod::EvalClosed, lemma: None },
                Ok(r) if is_bool(&r, bool_, false) => return Verdict::False(r),
                _ => {}
            }
        }
        let goal = mk::eq_bool(bool_, t.clone(), true);
        // 1. checking-mode conversion: the kernel lemma
        let mut b = Budget { steps: CONV_BUDGET };
        let converts = match self.env.eval(&Default::default(), Lvl(0), t, &mut b) {
            Ok(v) => {
                let tv = mk::bool_lit(bool_, true);
                let mut b2 = Budget { steps: CONV_BUDGET };
                match self.env.eval(&Default::default(), Lvl(0), &tv, &mut b2) {
                    Ok(tr) => self.env.conv(Lvl(0), &v, &tr, &mut b).unwrap_or(false),
                    Err(_) => false,
                }
            }
            Err(_) => false,
        };
        if converts {
            let refl = mk::refl(mk::bool_ty(bool_), mk::bool_lit(bool_, true));
            let g = self.add_definition(name, DefKind::Lemma, Some(item), goal, refl, Recursion::None, 0, false, false, span);
            let ok = g.is_ok() && self.defs.last().is_some_and(|d| d.name == name && d.status == DefStatus::Checked);
            return if ok { Verdict::True { method: ExampleMethod::Conversion, lemma: g.ok() } } else { Verdict::Rejected };
        }
        // 2. the kernel's closed evaluator (TCB)
        let budget = self.opts.example_budget;
        let mut b = Budget { steps: budget };
        match self.env.eval_closed(t, &mut b) {
            Ok(r) if is_bool(&r, bool_, true) => Verdict::True { method: ExampleMethod::EvalClosed, lemma: None },
            Ok(r) => Verdict::False(r),
            Err(e) => {
                let out_of_fuel = e.to_string().contains("OutOfFuel");
                let msg = if out_of_fuel { format!("the kernel's step budget ({budget} steps) ran out") } else { format!("the kernel could not evaluate it: {e}") };
                Verdict::Error { out_of_fuel, msg }
            }
        }
    }

    /// Records a verdict (an accepted example's term counts for coverage).
    fn record_verdict(&mut self, item: ItemId, source: ExampleSource, counts: bool, t: &Tm, v: &Verdict, detail: String) {
        let (status, method, lemma, term) = match v {
            Verdict::True { method, lemma } => {
                self.s1.example_terms.push((t.clone(), counts));
                (DefStatus::Checked, Some(*method), *lemma, Some(t.clone()))
            }
            Verdict::Rejected => (DefStatus::Rejected("the kernel rejected the example lemma".into()), Some(ExampleMethod::Conversion), None, None),
            Verdict::Blocked(p) => (DefStatus::Blocked(format!("depends on `{p}`, which did not verify")), None, None, None),
            Verdict::False(_) | Verdict::Error { .. } => (DefStatus::Unproven, None, None, None),
        };
        self.s1.examples.push(ExampleRecord { item, source, status, method, lemma, counts, detail, term });
    }

    /// Decides one closed `bool` example term (see the module docs) and
    /// records it.
    #[allow(clippy::too_many_arguments)]
    fn decide_example(&mut self, name: &str, item: ItemId, t: Tm, source: ExampleSource, counts: bool, span: Span, ex: Option<&'a Example>) -> bool {
        let blocked = self.placeholder_reached(&t);
        let v = self.verdict(name, item, &t, span, blocked);
        let detail = match &v {
            Verdict::True { .. } | Verdict::Rejected => String::new(),
            Verdict::Blocked(p) => {
                self.diag(
                    Diagnostic::error(DiagKind::Example, span, format!("{} was not checked: it depends on `{p}`, which did not verify", example_label(name)))
                        .note("the definition was replaced by a placeholder (a default value) so that the rest of the crate could be checked; evaluating the example through it would judge the placeholder, not the specification — fix the errors above first"),
                );
                format!("depends on `{p}`, which did not verify")
            }
            Verdict::False(r) => {
                let mut d = Diagnostic::error(DiagKind::Example, span, format!("{} is false", example_label(name)));
                let mut detail = format!("evaluates to {}", self.show_tm(r));
                if let Some(sd) = ex.and_then(|e| self.example_sides(item, e)) {
                    d = d.note(format!("left side evaluates to: {}", sd.left)).note(format!("right side evaluates to: {}", sd.right));
                    if let Some(diff) = &sd.diff {
                        d = d.note(format!("first difference: {diff}"));
                    }
                    detail = format!("left: {}; right: {}", sd.left, sd.right);
                }
                d = d.note("an example is a known answer of the specification: fix the example if it is wrong, else the specification (DESIGN.md §15.7)");
                self.diag(d);
                detail
            }
            Verdict::Error { msg, .. } => {
                self.diag(Diagnostic::error(DiagKind::Example, span, format!("{} could not be decided: {msg}", example_label(name))).note("an exhausted budget or an evaluation error fails the build; it is never a skip (DESIGN.md §15.7)"));
                msg.clone()
            }
        };
        let ok = matches!(v, Verdict::True { .. });
        self.record_verdict(item, source, counts, &t, &v, detail);
        ok
    }

    /// Both sides of a top-level `l == r` example, evaluated by the kernel
    /// and printed in surface syntax (for the diagnostic of a false
    /// example).
    fn example_sides(&mut self, item: ItemId, ex: &'a Example) -> Option<Sides> {
        let ExprKind::Binary(BinOp::Eq, l, r) = &Self::peel(&ex.expr).kind else { return None };
        let side = |me: &mut Self, e: &'a Expr| -> Option<Tm> {
            me.f = FnState::new("example side".into(), Some(item), &ex.locals, ex.span);
            me.f.answer = e.ty.clone();
            me.f.ret = e.ty.clone();
            let t = me.expr(e, &mut |s, v| Ok(v.at(s.depth()))).ok()?;
            let mut b = Budget { steps: me.opts.example_budget };
            me.env.eval_closed(&t, &mut b).ok()
        };
        let (n_obl, n_diag) = (self.obligations.len(), self.diags.list.len());
        let a = side(self, l);
        let b = side(self, r);
        self.obligations.truncate(n_obl);
        self.diags.list.truncate(n_diag);
        Some(self.sides(&a?, &l.ty, &b?, &r.ty))
    }

    /// Two evaluated sides printed (surface syntax when the shape is known)
    /// with their first difference.
    fn sides(&self, a: &Tm, aty: &Ty, b: &Tm, bty: &Ty) -> Sides {
        let show = |t: &Tm, ty: &Ty| self.show_value(t, ty).unwrap_or_else(|| self.show_tm(t));
        let diff = if aty.peel_refs() == bty.peel_refs() { self.first_difference(a, b, aty, String::new()) } else { None };
        Sides { left: show(a, aty), right: show(b, bty), diff }
    }

    /// The elements of a closed `List` value.
    fn list_elems(&self, t: &Tm) -> Option<Vec<Tm>> {
        let mut out = Vec::new();
        let mut cur = t.clone();
        loop {
            match &*cur.clone() {
                Term::Ctor { ind, ctor: 0, .. } if *ind == self.p.list => return Some(out),
                Term::Ctor { ind, ctor: 1, args, .. } if *ind == self.p.list && args.len() == 2 => {
                    out.push(args[0].clone());
                    cur = args[1].clone();
                }
                _ => return None,
            }
        }
    }

    /// The list of a closed `Seq`, array or slice value.
    fn seq_elems(&self, t: &Tm, ty: &Ty) -> Option<Vec<Tm>> {
        match ty.peel_refs() {
            Ty::Seq(_) => self.list_elems(t),
            Ty::Array(..) => match &**t {
                Term::Pair { fst, .. } => self.list_elems(fst),
                _ => None,
            },
            Ty::Slice(_) => match &**t {
                Term::Pair { snd, .. } => match &**snd {
                    Term::Pair { fst, .. } => self.list_elems(fst),
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        }
    }

    /// A closed first-order value of HIR type `ty` in surface syntax:
    /// byte sequences as `hex!(..)`, numbers in decimal with their type,
    /// `Option`s and tuples structurally; `None` for an unknown shape.
    fn show_value(&self, t: &Tm, ty: &Ty) -> Option<String> {
        let lit = |t: &Tm| match &**t {
            Term::Lit { n, .. } => Some(n.clone()),
            _ => None,
        };
        match ty.peel_refs() {
            Ty::Bool => match &**t {
                Term::Ctor { ind, ctor, .. } if *ind == self.p.bool_ => Some((*ctor == 1).to_string()),
                _ => None,
            },
            Ty::Uint(u) => lit(t).map(|n| format!("{n}{}", u.name())),
            Ty::Nat | Ty::Int => lit(t).map(|n| n.to_string()),
            e @ (Ty::Seq(_) | Ty::Array(..) | Ty::Slice(_)) => {
                let et = match e {
                    Ty::Seq(x) | Ty::Array(x, _) | Ty::Slice(x) => (**x).clone(),
                    _ => return None,
                };
                let xs = self.seq_elems(t, ty)?;
                if et == Ty::u8() {
                    let bytes: Vec<u8> = xs.iter().map(|x| lit(x).and_then(|n| u8::try_from(n).ok())).collect::<Option<_>>()?;
                    let shown: String = bytes.iter().take(64).map(|b| format!("{b:02x}")).collect();
                    Some(format!("hex!(\"{shown}{}\") ({} bytes)", if bytes.len() > 64 { "…" } else { "" }, bytes.len()))
                } else {
                    let items: Vec<String> = xs.iter().take(16).map(|x| self.show_value(x, &et).unwrap_or_else(|| self.show_tm(x))).collect();
                    Some(format!("seq![{}{}] ({} elements)", items.join(", "), if xs.len() > 16 { ", …" } else { "" }, xs.len()))
                }
            }
            Ty::Option(e) => match &**t {
                Term::Ctor { ind, ctor: 0, .. } if *ind == self.p.option => Some("None".into()),
                Term::Ctor { ind, ctor: 1, args, .. } if *ind == self.p.option && args.len() == 1 => Some(format!("Some({})", self.show_value(&args[0], e)?)),
                _ => None,
            },
            Ty::Tuple(ts) => match &**t {
                Term::Ctor { args, .. } if args.len() == ts.len() => Some(format!("({})", args.iter().zip(ts).map(|(a, t)| self.show_value(a, t)).collect::<Option<Vec<_>>>()?.join(", "))),
                _ => None,
            },
            _ => None,
        }
    }

    /// Where two closed values of type `ty` first differ (`[i]` indexes a
    /// sequence, `.k` a tuple component, `Some(..)` an option's payload).
    fn first_difference(&self, a: &Tm, b: &Tm, ty: &Ty, path: String) -> Option<String> {
        if self.env.alpha_eq_relevant(a, b, &|x, y| x == y) {
            return None;
        }
        let show = |t: &Tm, ty: &Ty| self.show_value(t, ty).unwrap_or_else(|| self.show_tm(t));
        let here = if path.is_empty() { "the whole value".to_string() } else { format!("at `{path}`") };
        match ty.peel_refs() {
            Ty::Seq(e) | Ty::Array(e, _) | Ty::Slice(e) => {
                let (xs, ys) = (self.seq_elems(a, ty)?, self.seq_elems(b, ty)?);
                for (i, (x, y)) in xs.iter().zip(&ys).enumerate() {
                    if let Some(d) = self.first_difference(x, y, e, format!("{path}[{i}]")) {
                        return Some(d);
                    }
                }
                (xs.len() != ys.len()).then(|| format!("{here}: the lengths differ ({} vs {})", xs.len(), ys.len()))
            }
            Ty::Option(e) => match (&**a, &**b) {
                (Term::Ctor { ctor: 1, args: x, .. }, Term::Ctor { ctor: 1, args: y, .. }) if x.len() == 1 && y.len() == 1 => self.first_difference(&x[0], &y[0], e, format!("{path}.unwrap()")),
                _ => Some(format!("{here}: {} vs {}", show(a, ty), show(b, ty))),
            },
            Ty::Tuple(ts) => match (&**a, &**b) {
                (Term::Ctor { args: x, .. }, Term::Ctor { args: y, .. }) if x.len() == ts.len() && y.len() == ts.len() => (0..ts.len()).find_map(|k| self.first_difference(&x[k], &y[k], &ts[k], format!("{path}.{k}"))),
                _ => None,
            },
            // two different scalars: the sides above say it all
            _ if path.is_empty() => None,
            _ => Some(format!("{here}: {} vs {}", show(a, ty), show(b, ty))),
        }
    }

    /// The records of vector file `j` of checker `id` (see the module
    /// docs). Failing records are collected into one error that points at
    /// the first one's line and lists every failure with its bound fields
    /// and the checker's evaluated `==` sides.
    fn example_file(&mut self, id: ItemId, f: &'a FnDef, j: usize, file: &'a ExampleFile) {
        let krate = self.krate;
        let path = krate.item(id).path.to_string();
        let parsed = match file.format {
            ExampleFormat::Cavp => parse_cavp(&file.text),
            ExampleFormat::Json => parse_json(&file.text),
        };
        let records = match parsed {
            Ok(r) => r,
            Err(e) => {
                self.diag(Diagnostic::error(DiagKind::Example, file.span, format!("vector file `{}` is malformed: {e}", file.path)));
                return;
            }
        };
        if records.is_empty() {
            self.diag(Diagnostic::error(DiagKind::Example, file.span, format!("vector file `{}` has no records", file.path)));
            return;
        }
        let names: Vec<String> = f.params.iter().map(|p| match &p.pat.kind {
            PatKind::Binding { local, .. } => f.locals[local.0 as usize].name.clone(),
            _ => String::new(),
        }).collect();
        let counts = file.provenance != Provenance::SelfDerived;
        // a checker that reaches a definition that did not verify is judged
        // against its placeholder: nothing is checked
        let blocked = self.globals.get(&id).and_then(|g| match g {
            ItemGlobal::Def(g) => self.placeholder_reached(&mk::global(*g)),
            _ => None,
        });
        if let Some(p) = &blocked {
            self.diag(
                Diagnostic::error(DiagKind::Example, file.span, format!("vector file `{}` of `{path}` was not checked: `{path}` depends on `{p}`, which did not verify", file.path))
                    .note("fix the errors above first: the definition was replaced by a placeholder (a default value), and records evaluated through it would judge the placeholder, not the specification"),
            );
            for k in 0..records.len() {
                let src = ExampleSource::File { file: file.file, record: k as u32 };
                self.s1.examples.push(ExampleRecord { item: id, source: src, status: DefStatus::Blocked(format!("depends on `{p}`, which did not verify")), method: None, lemma: None, counts, detail: String::new(), term: None });
            }
            return;
        }
        let line_span = |line: usize| -> Span {
            if file.format != ExampleFormat::Cavp || line == 0 {
                return file.span;
            }
            let len = file.text.lines().nth(line - 1).map(|l| l.chars().count()).unwrap_or(0) as u32;
            Span { file: file.file, lo: (line as u32, 0), hi: (line as u32, len) }
        };
        let at = |line: usize, k: usize| if file.format == ExampleFormat::Cavp { format!("line {line}") } else { format!("record {k}") };
        let mut failures: Vec<(usize, Span, String, Vec<String>)> = Vec::new();
        let mut stopped = false;
        for (k, (rec, line)) in records.iter().enumerate() {
            let name = format!("{path}::example#file{j}#{k}");
            let src = ExampleSource::File { file: file.file, record: k as u32 };
            let mut vals = Vec::new();
            let mut err = None;
            for (pi, n) in names.iter().enumerate() {
                match rec.iter().find(|(key, _)| key.eq_ignore_ascii_case(n)) {
                    Some((_, v)) => vals.push((f.params[pi].ty.clone(), v.clone())),
                    None => {
                        err = Some(format!("{} has no field `{n}` (fields bind the checker's parameters by name)", at(*line, k)));
                        break;
                    }
                }
            }
            let fields: Vec<String> = names.iter().zip(&vals).map(|(n, (_, v))| format!("{n} = {}", show_rec(v))).collect();
            let t = match err {
                Some(e) => Err(e),
                None => self.record_app(&name, id, &vals, file.span),
            };
            let failure: Option<(String, Vec<String>)> = match t {
                Ok(Some((t, args))) => {
                    let v = self.verdict_in(&name, id, &t, file.span, None, true);
                    let (why, notes) = match &v {
                        Verdict::True { .. } => (None, vec![]),
                        Verdict::Rejected => (Some("the kernel rejected its lemma".to_string()), vec![]),
                        Verdict::Blocked(p) => (Some(format!("depends on `{p}`, which did not verify")), vec![]),
                        Verdict::Error { msg, .. } => (Some(format!("could not be decided: {msg}")), vec![]),
                        Verdict::False(_) => {
                            let mut notes = Vec::new();
                            if let Some(sd) = self.record_sides(id, f, &args, file.span) {
                                notes.push(format!("left side evaluates to: {}", sd.left));
                                notes.push(format!("right side evaluates to: {}", sd.right));
                                if let Some(d) = sd.diff {
                                    notes.push(format!("first difference: {d}"));
                                }
                            }
                            (Some("is false".to_string()), notes)
                        }
                    };
                    let detail = why.clone().unwrap_or_default();
                    self.record_verdict(id, src, counts, &t, &v, detail);
                    why.map(|w| (w, notes))
                }
                Ok(None) => {
                    self.s1.examples.push(ExampleRecord { item: id, source: src, status: DefStatus::Unproven, method: None, lemma: None, counts, detail: "an obligation of the record failed".into(), term: None });
                    Some(("an obligation of its checker application failed (see above)".to_string(), vec![]))
                }
                Err(e) => {
                    self.s1.examples.push(ExampleRecord { item: id, source: src, status: DefStatus::Unsupported(e.clone()), method: None, lemma: None, counts, detail: e.clone(), term: None });
                    Some((e, vec![]))
                }
            };
            if let Some((why, mut notes)) = failure {
                let mut all = vec![format!("{}: {}", at(*line, k), if fields.is_empty() { "(no fields bound)".to_string() } else { fields.join(", ") })];
                all.append(&mut notes);
                failures.push((*line, line_span(*line), why, all));
                // the mutation gate's filtered elaboration (`Options::items`)
                // needs one definite failure (it kills the mutant); a build
                // reports up to ten
                let enough = if self.opts.items.is_some() { failures.last().is_some_and(|x| x.2 == "is false") } else { failures.len() >= 10 };
                if enough {
                    stopped = k + 1 < records.len();
                    break;
                }
            }
        }
        if failures.is_empty() {
            return;
        }
        let total = records.len();
        let whys: BTreeSet<&str> = failures.iter().map(|f| f.2.as_str()).collect();
        let what = match whys.iter().next().copied() {
            Some("is false") if whys.len() == 1 => if failures.len() == 1 { "is false".to_string() } else { "are false".to_string() },
            Some(w) if whys.len() == 1 => format!("failed: {w}"),
            _ => "failed".to_string(),
        };
        let places: Vec<String> = failures.iter().enumerate().map(|(i, (line, ..))| at(*line, i)).collect();
        let places = if file.format == ExampleFormat::Cavp { places.join(", ") } else { format!("{} failing record(s)", failures.len()) };
        let mut d = Diagnostic::error(
            DiagKind::Example,
            failures[0].1,
            format!("vector file `{}` of `{path}`: {} of {total} record(s) {what}{} ({places})", file.path, failures.len(), if stopped { " before checking stopped" } else { "" }),
        );
        for (i, (_, _, why, notes)) in failures.iter().enumerate().take(3) {
            for (n, note) in notes.iter().enumerate() {
                d = d.note(if n == 0 && whys.len() > 1 { format!("{note} ({why})") } else { note.clone() });
            }
            if i == 2 && failures.len() > 3 {
                d = d.note(format!("… and {} more failing record(s)", failures.len() - 3));
            }
        }
        if stopped {
            d = d.note(format!("checking stopped after {} failing records", failures.len()));
        }
        d = d.note("a vector record is a known answer of the specification: fix the record if it is wrong, else the specification (DESIGN.md §15.7)");
        self.diag(d);
    }

    /// Both sides of the checker's top-level `==` for one record (its
    /// parameters bound to the record's values), evaluated by the kernel.
    fn record_sides(&mut self, id: ItemId, f: &'a FnDef, args: &[Tm], span: Span) -> Option<Sides> {
        let FnBody::Spec(body) = &f.body else { return None };
        if !f.generics.is_empty() || args.len() != f.params.len() {
            return None;
        }
        let mut e = Self::peel(body);
        while let ExprKind::Block(b) = &e.kind {
            if !b.stmts.is_empty() {
                return None;
            }
            e = Self::peel(b.tail.as_ref()?);
        }
        let ExprKind::Binary(BinOp::Eq, l, r) = &e.kind else { return None };
        let (n_obl, n_diag) = (self.obligations.len(), self.diags.list.len());
        let a = self.record_side(id, f, args, l, span);
        let b = self.record_side(id, f, args, r, span);
        self.obligations.truncate(n_obl);
        self.diags.list.truncate(n_diag);
        Some(self.sides(&a?, &l.ty, &b?, &r.ty))
    }

    fn record_side(&mut self, id: ItemId, f: &'a FnDef, args: &[Tm], e: &'a Expr, span: Span) -> Option<Tm> {
        self.f = FnState::new("record side".into(), Some(id), &f.locals, span);
        self.f.answer = e.ty.clone();
        self.f.ret = e.ty.clone();
        let mut lets = Vec::new();
        for (p, a) in f.params.iter().zip(args) {
            let PatKind::Binding { local, .. } = &p.pat.kind else { return None };
            let name = f.locals[local.0 as usize].name.clone();
            let ty = self.ty(&p.ty, span).ok()?;
            let lvl = self.push(&name, Rel::Rel, &ty, Some(a)).ok()?;
            self.f.scope.locals.insert(*local, lvl);
            lets.push((name, ty, a.clone()));
        }
        let mut t = self.expr(e, &mut |s, v| Ok(v.at(s.depth()))).ok()?;
        // the values are closed: close the term over the `let`s
        for (n, ty, v) in lets.into_iter().rev() {
            t = mk::let_(&n, Rel::Rel, ty, v, t);
        }
        let mut b = Budget { steps: self.opts.example_budget };
        self.env.eval_closed(&t, &mut b).ok()
    }

    /// `c(v̄)` for one record: the checker applied to the field values
    /// (its `Nat` bounds and `requires` proven as obligations), and the
    /// argument values. `None`: an obligation failed (reported).
    fn record_app(&mut self, name: &str, id: ItemId, vals: &[(Ty, RecVal)], span: Span) -> Result<Option<(Tm, Vec<Tm>)>, String> {
        self.f = FnState::new(name.to_string(), Some(id), &[], span);
        let mut args = Vec::new();
        for (ty, v) in vals {
            args.push(self.record_value(ty, v, span).map_err(|e| format!("{e} (parameter of type `{}`)", self.krate.ty_str(ty)))?);
        }
        let g = self.item_global(id, span).map_err(|e| e.msg)?;
        let ty = self.env.global_type(g).ok_or_else(|| "the checker has no type".to_string())?;
        let (app, _, _) = self.apply_tele(&ty, args.clone(), Some(mk::global(g)), None, &|_| ObligationKind::CalleeRequires(g), span).map_err(|e| e.msg)?;
        Ok(if self.f.failed { None } else { Some((app, args)) })
    }

    /// The closed term of a record field at a parameter type.
    fn record_value(&mut self, ty: &Ty, v: &RecVal, span: Span) -> Result<Tm, String> {
        let bytes_list = |me: &Self, bs: &[u8]| {
            let et = mk::int_ty(Width::U8);
            let mut l = mk::ctor(me.p.list, 0, vec![et.clone()], vec![]);
            for b in bs.iter().rev() {
                l = mk::ctor(me.p.list, 1, vec![et.clone()], vec![mk::lit(Width::U8, *b), l]);
            }
            l
        };
        Ok(match ty.peel_refs() {
            Ty::Bool => match v {
                RecVal::Bool(b) => self.bool_lit(*b),
                RecVal::Str(s) if s == "true" || s == "false" => self.bool_lit(s == "true"),
                _ => return Err("expected a boolean".into()),
            },
            Ty::Uint(u) => {
                let n = parse_int(v)?;
                if n < BigInt::from(0u8) || n > BigInt::from(u.max_value()) {
                    return Err(format!("`{n}` is out of range for `{}`", u.name()));
                }
                mk::lit(u.width(), n)
            }
            Ty::Nat | Ty::Int => {
                let n = parse_int(v)?;
                if *ty.peel_refs() == Ty::Nat && n < BigInt::from(0u8) {
                    return Err(format!("`{n}` is negative"));
                }
                mk::lit(Width::Int, n)
            }
            Ty::Seq(e) if **e == Ty::u8() => bytes_list(self, &parse_hex(v)?),
            Ty::Array(e, n) if **e == Ty::u8() => {
                let bs = parse_hex(v)?;
                if bs.len() as u64 != *n {
                    return Err(format!("expected {n} bytes, found {}", bs.len()));
                }
                mk::pair(self.array_ty(mk::int_ty(Width::U8), *n), bytes_list(self, &bs), mk::refl(mk::int_ty(Width::Int), mk::lit(Width::Int, *n)))
            }
            Ty::Slice(e) if **e == Ty::u8() => {
                let bs = parse_hex(v)?;
                let l = bytes_list(self, &bs);
                self.slice_of_list(mk::int_ty(Width::U8), l, span).map_err(|e| e.msg)?
            }
            Ty::Seq(e) => {
                let RecVal::Arr(xs) = v else { return Err("expected an array".into()) };
                let et = self.ty(e, span).map_err(|e| e.msg)?;
                let mut l = mk::ctor(self.p.list, 0, vec![et.clone()], vec![]);
                for x in xs.iter().rev() {
                    let xv = self.record_value(e, x, span)?;
                    l = mk::ctor(self.p.list, 1, vec![et.clone()], vec![xv, l]);
                }
                l
            }
            // a tuple: a JSON array with one entry per component
            Ty::Tuple(ts) => {
                let RecVal::Arr(xs) = v else { return Err(format!("expected an array of {} values (a tuple)", ts.len())) };
                if xs.len() != ts.len() {
                    return Err(format!("expected a tuple of {} values, found {}", ts.len(), xs.len()));
                }
                let mut tys = Vec::new();
                let mut vals = Vec::new();
                for (t, x) in ts.iter().zip(xs) {
                    tys.push(self.ty(t, span).map_err(|e| e.msg)?);
                    vals.push(self.record_value(t, x, span)?);
                }
                self.tuple_val(tys, vals, span).map_err(|e| e.msg)?
            }
            // `null` is `None`, anything else `Some(v)`
            Ty::Option(e) => {
                let et = self.ty(e, span).map_err(|e| e.msg)?;
                match v {
                    RecVal::Null => mk::ctor(self.p.option, 0, vec![et], vec![]),
                    _ => {
                        let x = self.record_value(e, v, span)?;
                        mk::ctor(self.p.option, 1, vec![et], vec![x])
                    }
                }
            }
            // a struct: a JSON object with exactly its fields, by name
            // (case-insensitively); its invariant and `Nat` bounds are
            // obligations, like at any construction (§15.3)
            Ty::Adt(id, targs) if matches!(self.krate.item(*id).kind, ItemKind::Struct(_)) => {
                let ItemKind::Struct(sd) = &self.krate.item(*id).kind else { unreachable!() };
                let RecVal::Obj(fs) = v else { return Err(format!("expected an object with the fields of `{}`", self.krate.item(*id).name)) };
                for (k, _) in fs {
                    if !sd.fields.iter().any(|f| f.name.as_deref().is_some_and(|n| n.eq_ignore_ascii_case(k))) {
                        return Err(format!("`{}` has no field `{k}`", self.krate.item(*id).name));
                    }
                }
                let mut vals = Vec::new();
                for (j, f) in sd.fields.iter().enumerate() {
                    let n = f.name.clone().unwrap_or_else(|| j.to_string());
                    let Some((_, x)) = fs.iter().find(|(k, _)| k.eq_ignore_ascii_case(&n)) else { return Err(format!("the object has no field `{n}` of `{}`", self.krate.item(*id).name)) };
                    let ft = f.ty.subst(targs);
                    vals.push(self.record_value(&ft, x, span).map_err(|e| format!("field `{n}`: {e}"))?);
                }
                let (ind, params) = self.ind_of(ty, span).map_err(|e| e.msg)?;
                self.ctor_with_invariants(ind, 0, params, vals, Some(*id), span).map_err(|e| e.msg)?
            }
            other => return Err(format!("record fields cannot give a value of type `{}`", self.krate.ty_str(other))),
        })
    }

    // ------------------------------------------------------------------
    // mirrors, fuel (§15.1)
    // ------------------------------------------------------------------

    /// `#[mirrors_impl]` on spec fn `id`: a locked claim; checked against
    /// the refinements in [`Elab::s1_post_pass`].
    pub fn mirrors_hook(&mut self, _id: ItemId, _j: &Justified) {}

    /// `#[fuel_sufficient]` on lemma `id`: it must be proven (its own
    /// obligations) and name a spec function; recorded for the fuel check.
    pub fn fuel_hook(&mut self, id: ItemId, fs: &FuelSufficient) {
        if !self.s1.on {
            return;
        }
        let krate = self.krate;
        let it = krate.item(id);
        let checked = self.defs.iter().any(|d| d.item == Some(id) && d.name == it.path.to_string() && d.status == DefStatus::Checked);
        let covers: Vec<ItemId> = match fs.spec {
            Some(s) => vec![s],
            None => super::order::refs(krate, id).into_iter().filter(|r| krate.fn_def(*r).is_some_and(|f| f.kind == FnKind::Spec)).collect(),
        };
        if covers.is_empty() {
            self.diag(Diagnostic::error(DiagKind::FuelSufficient, fs.span, format!("`#[fuel_sufficient]` lemma `{}` mentions no spec function", it.path)).note("name the fuel-bounded spec function: `#[fuel_sufficient(spec::f)]` (DESIGN.md §15.1)"));
            return;
        }
        for s in covers {
            if let Some(sf) = krate.fn_def(s)
                && fs.spec.is_some()
                && fuel_param(s, sf).is_none()
            {
                self.diag(Diagnostic::warning(DiagKind::FuelSufficient, fs.span, format!("`{}` is not fuel-bounded (no parameter is used only to count down to an exhaustion default)", krate.item(s).path)));
            }
            if checked {
                self.s1.fuel_ok.insert(s);
            }
        }
    }

    /// The cross-item checks of S1, after every item: mirrors, fuel,
    /// coverage (see the module docs).
    pub fn s1_post_pass(&mut self) {
        if !self.s1.on {
            return;
        }
        self.mirror_checks();
        self.fuel_checks();
        self.coverage();
    }

    fn mirror_checks(&mut self) {
        let krate = self.krate;
        let recs: Vec<(ItemId, ItemId)> = self.s1.refinements.iter().filter(|r| r.status == DefStatus::Checked && r.form == super::refines::RefinesForm::Plain).map(|r| (r.item, r.spec)).collect();
        for (fid, sid) in recs {
            let (Some(ItemGlobal::Def(gf)), Some(ItemGlobal::Def(gs))) = (self.globals.get(&fid).cloned(), self.globals.get(&sid).cloned()) else { continue };
            if !self.mirrors(gf, gs) {
                continue;
            }
            let sf = krate.fn_def(sid);
            let justified = sf.is_some_and(|f| f.spec.mirrors_impl.is_some());
            let independent = self.independent_evidence(sid);
            if justified && independent {
                continue;
            }
            let span = sf.and_then(|f| f.spec.mirrors_impl.as_ref().map(|j| j.span)).unwrap_or(krate.item(sid).span);
            let mut d = Diagnostic::error(DiagKind::SpecMirrorsImpl, span, format!("spec function `{}` is a copy of the exec function `{}` that refines it", krate.item(sid).path, krate.item(fid).path));
            if !justified {
                d = d.note("a tiny function may legitimately coincide with its spec: say so with `#[mirrors_impl(justification = \"..\")]` on the spec (a locked claim)");
            }
            if !independent {
                d = d.note("and back the spec with an independent description: an `#[example]` or an independent vector file on it, or a law about it (DESIGN.md §15.1, §15.7)");
            }
            self.diag(d);
        }
    }

    /// Whether the bodies of `gf` (exec) and `gs` (spec) coincide in every
    /// relevant position after inlining non-recursive helpers (recursive
    /// calls of `gf` corresponding to those of `gs`).
    fn mirrors(&self, gf: GlobalId, gs: GlobalId) -> bool {
        let (Some(bf), Some(bs)) = (self.env.global_body(gf), self.env.global_body(gs)) else { return false };
        let bf = self.inline_helpers(&bf, &[gf, gs], 3);
        let bs = self.inline_helpers(&bs, &[gf, gs], 3);
        let corr = |a: GlobalId, b: GlobalId| a == b || (a == gf && b == gs) || (a == gs && b == gf);
        self.env.alpha_eq_relevant(&bf, &bs, &corr)
    }

    /// Inlines applications of non-recursive, transparent user
    /// definitions (not in `keep`), `fuel` levels deep.
    pub(super) fn inline_helpers(&self, t: &Tm, keep: &[GlobalId], fuel: u32) -> Tm {
        self.inline_helpers_prep(t, keep, fuel, &|b: &Tm| b.clone())
    }

    /// [`Elab::inline_helpers`] with each inlined body passed through `prep`
    /// first (LR5 erases proofs, whose terms can dwarf the code: a DAG that
    /// is small when shared becomes huge once it is inlined at many binder
    /// depths).
    pub(super) fn inline_helpers_prep(&self, t: &Tm, keep: &[GlobalId], fuel: u32, prep: &dyn Fn(&Tm) -> Tm) -> Tm {
        if fuel == 0 {
            return t.clone();
        }
        let user: HashSet<GlobalId> = self.globals.values().filter_map(|v| if let ItemGlobal::Def(g) = v { Some(*g) } else { None }).collect();
        let mut changed = false;
        let out = super::tm::map_post(t, 0, &mut |node, _b| {
            let (head, args) = super::items::spine(&node);
            let Term::Global(h) = &*head else { return Some(node) };
            if keep.contains(h) || !user.contains(h) || self.env.global_opaque(*h) == Some(true) {
                return Some(node);
            }
            let Some(ar) = self.env.global_arity(*h) else { return Some(node) };
            if args.len() != ar as usize || ar == 0 {
                return Some(node);
            }
            let Some(body) = self.env.global_body(*h) else { return Some(node) };
            if super::tm::any_node(&body, &mut |n| matches!(n, Term::Global(x) if x == h)) {
                return Some(node);
            }
            changed = true;
            Some(super::tm::subst_closed(&super::ensures::strip_lams(&prep(&body), ar), &args))
        })
        .unwrap_or_else(|| t.clone());
        if changed { self.inline_helpers_prep(&out, keep, fuel - 1, prep) } else { out }
    }

    /// An example on spec `sid` that counts, or a law that mentions it.
    pub(super) fn independent_evidence(&self, sid: ItemId) -> bool {
        let krate = self.krate;
        let example = self.s1.examples.iter().any(|e| e.counts && e.status == DefStatus::Checked && (e.item == sid || krate.examples_of(e.item).iter().any(|x| mentions(&x.expr, sid))));
        let law = krate.items.iter().any(|it| matches!(&it.kind, ItemKind::Fn(f) if f.kind == FnKind::Law) && super::order::refs(krate, it.id).contains(&sid));
        example || law
    }

    fn fuel_checks(&mut self) {
        let krate = self.krate;
        for it in &krate.items {
            let ItemKind::Fn(f) = &it.kind else { continue };
            if f.kind != FnKind::Spec {
                continue;
            }
            let Some(p) = fuel_param(it.id, f) else { continue };
            if self.s1.fuel_ok.contains(&it.id) {
                continue;
            }
            let pname = match &f.params[p].pat.kind {
                PatKind::Binding { local, .. } => f.locals[local.0 as usize].name.clone(),
                _ => format!("#{p}"),
            };
            let msg = format!("spec function `{}` is fuel-bounded (parameter `{pname}`) and has no proven `#[fuel_sufficient]` lemma", it.path);
            let note = format!("a fuel parameter returns a default when it runs out, which silently truncates the specification: prove that the fuel suffices on the declared domain with a `#[fuel_sufficient({})]` lemma, or recurse on a measure instead (DESIGN.md §15.1)", it.path);
            if self.s1_surface(it.id) {
                self.diag(Diagnostic::error(DiagKind::FuelSufficient, f.sig_span, msg).note(note));
            } else {
                self.s1.closure.push(ClosureRecord { item: it.id, kind: ClosureKind::Fuel, span: f.sig_span, msg, note });
            }
        }
    }

    // ------------------------------------------------------------------
    // coverage (§15.7)
    // ------------------------------------------------------------------

    fn coverage(&mut self) {
        let krate = self.krate;
        // The break predicates of `#[reduces_to]` laws (LR4, §15.13): their
        // `true` outcome is a break of a computational assumption (say, a
        // SHA-256 collision), which no example can exhibit; the `false`
        // outcome is still required.
        let mut breaks: HashSet<ItemId> = HashSet::new();
        for it in &krate.items {
            let ItemKind::Fn(f) = &it.kind else { continue };
            let (Some(_), Some(en)) = (&f.spec.reduces_to, &f.ensures) else { continue };
            let (mut hyps, mut disj) = (Vec::new(), Vec::new());
            super::law_rules::conclusion_parts(&en.prop, &mut hyps, &mut disj);
            if disj.len() >= 2
                && let Some(last) = disj.last()
                && let ExprKind::Call { callee: Callee::Item(b, _), .. } = &super::law_rules::peel(last).kind
            {
                breaks.insert(*b);
            }
        }
        // spec functions by global, with their outcome kind
        let mut specs: BTreeMap<ItemId, (GlobalId, Vec<String>)> = BTreeMap::new();
        for it in &krate.items {
            let ItemKind::Fn(f) = &it.kind else { continue };
            // an `#[assumption]` has no logical content (§15.13): nothing to exercise
            // a model function (layered proofs) is proof text, not a
            // specification: the code refines it and a lemma relates it to the
            // spec, whose examples are the ones that count
            if f.kind != FnKind::Spec || f.ret == Ty::Prop || f.spec.assumption.is_some() || krate.in_model_module(it.id) {
                continue;
            }
            let Some(ItemGlobal::Def(g)) = self.globals.get(&it.id) else { continue };
            // a vector-file checker is a validation predicate (true on
            // every record by construction), not behaviour: exercised only
            let needed = match &f.ret {
                _ if !f.spec.example_files.is_empty() => vec![],
                Ty::Bool if breaks.contains(&it.id) => vec!["false".to_string()],
                Ty::Bool => vec!["false".to_string(), "true".to_string()],
                Ty::Option(_) => vec!["None".to_string(), "Some".to_string()],
                _ => vec![],
            };
            specs.insert(it.id, (*g, needed));
        }
        // the calls evaluated for outcomes: only of functions that need
        // outcomes (evaluating every closed spec call — a checker, a whole
        // hash — again would double the cost of known-answer vectors)
        let by_global: HashMap<GlobalId, ItemId> = specs.iter().filter(|(_, (_, needed))| !needed.is_empty()).map(|(i, (g, _))| (*g, *i)).collect();
        let mut reached: HashSet<GlobalId> = HashSet::new();
        let mut seen: HashMap<GlobalId, BTreeSet<String>> = HashMap::new();
        let terms = std::mem::take(&mut self.s1.example_terms);
        for (t, counts) in &terms {
            if !counts {
                continue;
            }
            reached.extend(self.env.refs_closure(t, &[]));
            // outcomes: closed calls of `bool`/`Option` spec functions, in
            // the term and in the bodies of the spec functions it applies
            let mut calls = Vec::new();
            self.closed_calls(t, &by_global, &mut calls, 2);
            for (g, call) in calls {
                let mut b = Budget { steps: self.opts.example_budget / 16 };
                if let Ok(r) = self.env.eval_closed(&call, &mut b)
                    && let Term::Ctor { ind, ctor, .. } = &*r
                {
                    let o = if *ind == self.p.bool_ {
                        if *ctor == 1 { "true" } else { "false" }
                    } else if *ind == self.p.option {
                        if *ctor == 1 { "Some" } else { "None" }
                    } else {
                        continue;
                    };
                    seen.entry(g).or_default().insert(o.to_string());
                }
            }
        }
        self.s1.example_terms = terms;
        for (id, (g, needed)) in specs {
            let outcomes_seen: Vec<String> = seen.get(&g).map(|s| s.iter().cloned().collect()).unwrap_or_default();
            self.s1.coverage.push(CoverageRecord { spec: id, exercised: reached.contains(&g), outcomes_needed: needed, outcomes_seen });
        }
    }

    /// The closed applications `g ā` (no free variable) of the spec
    /// functions of `by_global` in `t`, and — `depth` levels deep — in the
    /// instantiated bodies of the spec functions `t` applies to closed
    /// arguments.
    fn closed_calls(&self, t: &Tm, by_global: &HashMap<GlobalId, ItemId>, out: &mut Vec<(GlobalId, Tm)>, depth: u32) {
        let closed = |x: &Tm| !super::tm::any_node_depth(x, &mut |n, d| matches!(n, Term::Var(sandblaster_kernel::term::Idx(i)) if *i >= d));
        let mut apps: Vec<(GlobalId, Tm, Vec<Tm>)> = Vec::new();
        let mut budget = 20_000u32;
        let _ = super::tm::map_post(t, 0, &mut |node, _b| {
            if budget == 0 {
                return Some(node);
            }
            budget -= 1;
            let (head, args) = super::items::spine(&node);
            if let Term::Global(g) = &*head {
                let ar = self.env.global_arity(*g).unwrap_or(0) as usize;
                if ar > 0 && args.len() == ar && self.env.global_kind(*g) == Some(DefKind::Spec) && closed(&node) {
                    apps.push((*g, node.clone(), args));
                }
            }
            Some(node)
        });
        for (g, node, args) in apps {
            if by_global.contains_key(&g) && !out.iter().any(|(h, c)| *h == g && self.env.alpha_eq_relevant(c, &node, &|a, b| a == b)) {
                out.push((g, node.clone()));
            }
            if depth > 0
                && let Some(body) = self.env.global_body(g)
            {
                let inst = super::tm::subst_closed(&super::ensures::strip_lams(&body, args.len() as u32), &args);
                self.closed_calls(&inst, by_global, out, depth - 1);
            }
        }
    }
}

/// `#[example]`, `#[examples]` record name for diagnostics.
fn example_label(name: &str) -> String {
    match name.rsplit_once("::example#") {
        Some((item, k)) if k.starts_with("file") => format!("vector record {} of `{item}`", k.trim_start_matches("file")),
        Some((item, k)) => format!("example #{k} of `{item}`"),
        None => format!("example `{name}`"),
    }
}

fn is_bool(t: &Tm, bool_: sandblaster_kernel::term::IndId, v: bool) -> bool {
    matches!(&**t, Term::Ctor { ind, ctor, .. } if *ind == bool_ && *ctor == v as u32)
}

/// Whether `e` calls item `id`.
fn mentions(e: &Expr, id: ItemId) -> bool {
    struct V(ItemId, bool);
    impl crate::visit::Visitor for V {
        fn expr(&mut self, e: &Expr) {
            if matches!(&e.kind, ExprKind::Call { callee: Callee::Item(x, _), .. } if *x == self.0) {
                self.1 = true;
            }
            crate::visit::walk_expr(self, e);
        }
    }
    let mut v = V(id, false);
    crate::visit::Visitor::expr(&mut v, e);
    v.1
}

/// The fuel parameter of a spec function (DESIGN.md §15.1), detected
/// syntactically: a `Nat`/`uN` parameter `p` that every recursive call
/// passes as `p - k`, that is otherwise only compared with literals (or
/// matched against literal patterns), with a non-recursive tail under a
/// test of `p` (the exhaustion default) and another non-recursive tail
/// under a condition not about `p` (the real base case).
///
/// A `#[decreases(m)]` exempts the function only when `m` does not read
/// the detected parameter (it recurses on a real measure); a measure that
/// *is* the fuel (`#[decreases(fuel)]`) proves termination, not that the
/// fuel suffices, so the exhaustion default still needs a
/// `#[fuel_sufficient]` lemma.
pub fn fuel_param(id: ItemId, f: &FnDef) -> Option<usize> {
    if f.kind != FnKind::Spec || f.recursion == crate::hir::Recursion::None {
        return None;
    }
    let FnBody::Spec(body) = &f.body else { return None };
    for (j, p) in f.params.iter().enumerate() {
        if !matches!(p.ty.peel_refs(), Ty::Nat | Ty::Uint(_)) {
            continue;
        }
        let PatKind::Binding { local, .. } = &p.pat.kind else { continue };
        let l = *local;
        let mut u = Uses { id, j, l, total: 0, allowed: 0, calls: 0, ok_calls: true };
        u.walk(body);
        if u.calls == 0 || !u.ok_calls || u.total != u.allowed {
            continue;
        }
        let mut leaves = Vec::new();
        tails(body, &mut vec![], id, &mut leaves);
        let exhaustion = leaves.iter().any(|(rec, conds)| !rec && conds.iter().any(|c| uses_local(c, l)));
        let base = leaves.iter().any(|(rec, conds)| !rec && conds.iter().any(|c| !uses_local(c, l)));
        if exhaustion && base {
            if let Some(d) = &f.decreases
                && !uses_local(&d.measure, l)
            {
                // recursion on a real measure: the countdown is not fuel
                continue;
            }
            return Some(j);
        }
    }
    None
}

struct Uses {
    id: ItemId,
    j: usize,
    l: LocalId,
    total: u32,
    allowed: u32,
    calls: u32,
    ok_calls: bool,
}

impl Uses {
    fn is_p(&self, e: &Expr) -> bool {
        matches!(&Elab::peel(e).kind, ExprKind::Local(x) if *x == self.l)
    }
    fn is_lit(e: &Expr) -> bool {
        matches!(&Elab::peel(e).kind, ExprKind::Lit(_))
    }
    fn walk(&mut self, e: &Expr) {
        match &e.kind {
            ExprKind::Local(x) if *x == self.l => self.total += 1,
            ExprKind::Call { callee: Callee::Item(c, _), args } if *c == self.id => {
                self.calls += 1;
                match args.get(self.j).map(Elab::peel) {
                    Some(Expr { kind: ExprKind::Binary(BinOp::Sub, a, b), .. }) if self.is_p(a) && Self::is_lit(b) => self.allowed += 1,
                    _ => self.ok_calls = false,
                }
                args.iter().for_each(|a| self.walk(a));
            }
            ExprKind::Binary(op, a, b) if op.is_comparison() && ((self.is_p(a) && Self::is_lit(b)) || (Self::is_lit(a) && self.is_p(b))) => {
                self.allowed += 1;
                self.walk(a);
                self.walk(b);
            }
            ExprKind::Match { scrut, arms, .. } if self.is_p(scrut) && arms.iter().all(|a| matches!(a.pat.kind, PatKind::Lit(_) | PatKind::Wild | PatKind::Range { .. })) => {
                self.allowed += 1;
                self.walk(scrut);
                for a in arms {
                    self.walk(&a.body);
                }
            }
            _ => crate::elab::items::walk_children_pub(e, &mut |x| self.walk(x)),
        }
    }
}

/// Whether `e` reads local `l`.
fn uses_local(e: &Expr, l: LocalId) -> bool {
    let mut found = false;
    fn go(e: &Expr, l: LocalId, found: &mut bool) {
        if matches!(&e.kind, ExprKind::Local(x) if *x == l) {
            *found = true;
            return;
        }
        crate::elab::items::walk_children_pub(e, &mut |x| go(x, l, found));
    }
    go(e, l, &mut found);
    found
}

/// The tails of a spec body with the conditions on their paths:
/// `(contains a recursive call, conditions)`.
fn tails<'e>(e: &'e Expr, conds: &mut Vec<&'e Expr>, id: ItemId, out: &mut Vec<(bool, Vec<&'e Expr>)>) {
    match &e.kind {
        ExprKind::If { cond, then, els } => {
            conds.push(cond);
            tails(then, conds, id, out);
            if let Some(x) = els {
                tails(x, conds, id, out);
            }
            conds.pop();
        }
        ExprKind::Match { scrut, arms, .. } => {
            conds.push(scrut);
            for a in arms {
                tails(&a.body, conds, id, out);
            }
            conds.pop();
        }
        ExprKind::Block(b) => match &b.tail {
            Some(t) => tails(t, conds, id, out),
            None => out.push((false, conds.clone())),
        },
        _ => {
            let mut rec = false;
            fn go(e: &Expr, id: ItemId, rec: &mut bool) {
                if matches!(&e.kind, ExprKind::Call { callee: Callee::Item(c, _), .. } if *c == id) {
                    *rec = true;
                    return;
                }
                crate::elab::items::walk_children_pub(e, &mut |x| go(x, id, rec));
            }
            go(e, id, &mut rec);
            out.push((rec, conds.clone()));
        }
    }
}

/// The §15.8 gate for the S1 records (run by the crate path
/// `driver::gates`, like `validate::spec15_gate`): every spec function exercised by a
/// counting example with each `bool`/`Option` outcome, and every recorded
/// spec-closure, fuel and mirror finding an error.
pub fn spec15_gate_s1(out: &super::Output, krate: &Crate, diags: &mut Diagnostics) {
    for c in &out.coverage {
        let it = krate.item(c.spec);
        if !c.exercised {
            diags.push(Diagnostic::error(DiagKind::Example, it.span, format!("spec function `{}` is not exercised by any example", it.path)).note("every spec function needs a known-answer example or an independent vector record reaching it (DESIGN.md §15.7)"));
        }
        let missing: Vec<&String> = c.outcomes_needed.iter().filter(|o| !c.outcomes_seen.contains(o)).collect();
        if !missing.is_empty() {
            diags.push(Diagnostic::error(DiagKind::Example, it.span, format!("no example of `{}` has the outcome {}", it.path, missing.iter().map(|o| format!("`{o}`")).collect::<Vec<_>>().join(", "))).note("a `bool`/`Option` specification needs each outcome at least once, so a spec that rejects everything cannot pass (DESIGN.md §15.7)"));
        }
    }
    for c in &out.spec_closure {
        let kind = match c.kind {
            ClosureKind::DependsOnImpl => DiagKind::SpecDependsOnImpl,
            ClosureKind::Fuel => DiagKind::FuelSufficient,
            ClosureKind::Mirror => DiagKind::SpecMirrorsImpl,
        };
        diags.push(Diagnostic::error(kind, c.span, c.msg.clone()).note(c.note.clone()));
    }
}
