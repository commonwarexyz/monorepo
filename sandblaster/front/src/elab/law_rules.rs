//! The law rules (DESIGN.md §15.1 "Laws state guarantees, not code",
//! LR1–LR10; stage **S3**, LR8 is S4's mutation engine).
//!
//! A law is a claim a reviewer reads *instead of* the implementation, so its
//! statement must mean something without it. [`Elab::law_rules_pass`] checks
//! every `#[law]` (and, for LR4, every contract) after the other §15 stages
//! and returns one [`LawRuleRecord`] per finding:
//!
//! | rule | kind | check |
//! | --- | --- | --- |
//! | LR1 | error `law-mentions-internal` | the statement (binder types, `requires`, `ensures`, `#[reduces_to]`) mentions an exec function that is not exported ([`crate::validate::exported_functions`]: the root's `pub use` list and the `pub` methods of every type reachable from it through public signatures), a plain `fn` of a ghost module (neither a spec item nor exported), or an exec constant; or reaches an *established* internal function through the `Refs*` of a spec item (spec closure allows it, the law vocabulary does not); or reads a field of an exec type with a `#[view]` or `#[represents]` (exec types are read through their views) |
//! | LR2 | error `spec-depends-on-impl` | through the `Refs*` of a spec item (not descending into exported functions, nor into the exec functions reached, each listed once) the law reaches an unestablished exec function or constant, or another exec global (a lemma, a loop helper): the spec item is not spec-closed; reported once, as LR2 (the fix is to transcribe the spec item), although LR1 forbids the function too |
//! | LR3 | warning `law-bypasses-refinement` | the law mentions an exported function that carries `#[refines(s)]` |
//! | LR4 | error `vacuous-reduction` | a conjunct of a hypothesis or a disjunct of a conclusion (of a law, or of a contract: `requires`/`ensures` of an exec or spec function) mentions no binder; a `#[reduces_to(a)]` law does not conclude `P ∨ B(t̄)` with `B` a `bool` spec function and `t̄` spec-closed terms with no `exists` or `Prop` in them; or it is vacuous: `B` ignores its arguments, bounded `auto` ([`REDUCTION_BUDGET`]) proves `requires ⇒ B(t̄)` (true of any specification) or `requires ⇒ P` (the break is dead) |
//! | LR5 | error `spec-mirrors-impl` | a spec function's kernel body (non-recursive helpers inlined, modulo view coercions, compared by its `SPEC.lock` canonical hash) equals the body of an exec function other than its refiner (the refiner is S1's check, `examples`), without `#[mirrors_impl(of = f, justification = "..")]` and independent evidence |
//! | LR6 (a) | error `law-restates-impl` | the statement is proven by unfolding each function it mentions once (non-recursive spec functions δ-unfolded first) and propositional reasoning: the restricted view of a closing statement ([`Elab::echo_attempt`]) and `auto` without arithmetic, induction or lemmas, within [`ECHO_BUDGET`] steps (recursive or opaque propositions stay unknown); a law the check cannot decide (its statement does not re-elaborate, the view cannot be built) is a finding too, never passed; `#[definitional(reason)]` exempts the law (it is never a guarantee, nor a hypothesis of a determinacy section) |
//! | LR6 (b) | warning `law-resembles-impl` | a subterm of at least [`RESEMBLANCE_MIN_NODES`] relevant kernel nodes of the unfolded statement also occurs (variables anonymized, view coercions stripped) in an exec body; not reported for a law LR6 (a) caught |
//! | LR7 | warning `law-corollary` | the law's proof applies other laws and only propositional steps (no unfolding, case analysis, induction or other lemma); `#[corollary]` exempts it |
//! | LR9 | error `law-undocumented` | no doc comment whose first sentence states the guarantee in words ([`GUARANTEE_RULE`]; abbreviations such as `i.e.` do not end the sentence); a `#[reduces_to]` naming something that is not an `#[assumption]` |
//! | LR10 | warning `one-directional-laws` | a `bool`-valued exported function (or its refinement target) occurs in the laws only in hypotheses, or only in conclusions |
//!
//! **Enforcement (no opt-out).** The rules are errors for every crate: the
//! build records the findings ([`crate::elab::Output::law_rules`], the
//! report's `law_rules` array) and [`spec15_gate_laws`], a gate of the crate
//! path (`driver::gates`, with `validate::spec15_gate`,
//! `examples::spec15_gate_s1` and `complete::spec15_gate_s3`), turns them
//! into diagnostics. There is no marker, attribute or option that exempts a
//! crate or a law from a rule. Misuse of the law-rule annotations themselves
//! (`#[assumption]` with content) is an error of the elaboration.
//!
//! **The law table** (LR9, [`law_table`]): per law, the first sentence of its
//! doc comment (the guarantee) and the assumptions it relies on; definitional
//! laws under their own heading, corollaries under the laws they follow
//! from. The spec sheet and the report print it.
//!
//! Everything here is untrusted and diagnostic: a finding fails the build,
//! never makes anything pass. The echo attempt is decided by its
//! step budget; a resource safety net that trips during it is a resource
//! failure of the build (`driver::resource_gate`, §15.8).

use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::hash::{Hash as _, Hasher};
use std::rc::Rc;

use sandblaster_kernel::term::{GlobalId, PrimOp, Rel, Term, Tm, Width};
use sandblaster_kernel::util::mk;

use super::{Elab, FnState, ItemGlobal, Mode, R};
use crate::diag::{DiagKind, Diagnostic, Diagnostics};
use crate::hir::*;
use crate::span::Span;

/// Step budget of one echo attempt (LR6 (a)): an echo is one unfolding and
/// propositional reasoning, so it is found quickly or not at all.
pub const ECHO_BUDGET: u64 = 400_000;

/// Smallest subterm (relevant kernel nodes) that counts as resembling an
/// exec body (LR6 (b)).
pub const RESEMBLANCE_MIN_NODES: usize = 12;

/// Step budget of each vacuity attempt of a `#[reduces_to]` law (LR4):
/// `requires ⇒ B(t̄)` and `requires ⇒ P`, by `auto` (with arithmetic).
pub const REDUCTION_BUDGET: u64 = 1_000_000;

/// A law rule of DESIGN.md §15.1.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum LawRule {
    /// Vocabulary.
    Lr1,
    /// Closure.
    Lr2,
    /// State it over the spec.
    Lr3,
    /// No closed disjuncts; extraction form.
    Lr4,
    /// Mirrors against every function.
    Lr5,
    /// Echo.
    Lr6Echo,
    /// Resemblance.
    Lr6Resemblance,
    /// Corollaries.
    Lr7,
    /// Readable.
    Lr9,
    /// Both directions.
    Lr10,
}

impl LawRule {
    pub const ALL: [LawRule; 10] = [LawRule::Lr1, LawRule::Lr2, LawRule::Lr3, LawRule::Lr4, LawRule::Lr5, LawRule::Lr6Echo, LawRule::Lr6Resemblance, LawRule::Lr7, LawRule::Lr9, LawRule::Lr10];

    /// `LR1` … `LR10` (`LR6a`, `LR6b`).
    pub fn code(self) -> &'static str {
        match self {
            LawRule::Lr1 => "LR1",
            LawRule::Lr2 => "LR2",
            LawRule::Lr3 => "LR3",
            LawRule::Lr4 => "LR4",
            LawRule::Lr5 => "LR5",
            LawRule::Lr6Echo => "LR6a",
            LawRule::Lr6Resemblance => "LR6b",
            LawRule::Lr7 => "LR7",
            LawRule::Lr9 => "LR9",
            LawRule::Lr10 => "LR10",
        }
    }

    /// A hard rule (an error once the gate is on) or a warning.
    pub fn hard(self) -> bool {
        !matches!(self, LawRule::Lr3 | LawRule::Lr6Resemblance | LawRule::Lr7 | LawRule::Lr10)
    }

    pub fn kind(self) -> DiagKind {
        match self {
            LawRule::Lr1 => DiagKind::LawMentionsInternal,
            LawRule::Lr2 => DiagKind::SpecDependsOnImpl,
            LawRule::Lr3 => DiagKind::LawBypassesRefinement,
            LawRule::Lr4 => DiagKind::VacuousReduction,
            LawRule::Lr5 => DiagKind::SpecMirrorsImpl,
            LawRule::Lr6Echo => DiagKind::LawRestatesImpl,
            LawRule::Lr6Resemblance => DiagKind::LawResemblesImpl,
            LawRule::Lr7 => DiagKind::LawCorollary,
            LawRule::Lr9 => DiagKind::LawUndocumented,
            LawRule::Lr10 => DiagKind::OneDirectionalLaws,
        }
    }
}

/// One finding of the law rules (see the module docs).
#[derive(Clone, Debug)]
pub struct LawRuleRecord {
    pub rule: LawRule,
    /// What the finding is about: the law (LR1–LR4, LR6, LR7, LR9), the
    /// function whose contract it is (LR4), the spec function (LR5), the
    /// exported function (LR10).
    pub item: ItemId,
    pub span: Span,
    pub msg: String,
    pub notes: Vec<(Option<Span>, String)>,
}

impl LawRuleRecord {
    fn new(rule: LawRule, item: ItemId, span: Span, msg: impl Into<String>) -> LawRuleRecord {
        LawRuleRecord { rule, item, span, msg: msg.into(), notes: vec![] }
    }
    fn note(mut self, n: impl Into<String>) -> LawRuleRecord {
        self.notes.push((None, n.into()));
        self
    }
    fn note_at(mut self, sp: Span, n: impl Into<String>) -> LawRuleRecord {
        self.notes.push((Some(sp), n.into()));
        self
    }
    /// An error for a hard rule, a warning otherwise.
    pub fn diagnostic(&self) -> Diagnostic {
        let mut d = if self.rule.hard() { Diagnostic::error(self.rule.kind(), self.span, self.msg.clone()) } else { Diagnostic::warning(self.rule.kind(), self.span, self.msg.clone()) };
        d.notes = self.notes.clone();
        d
    }
}

/// The outcome of [`Elab::echo_attempt`] (LR6 (a)).
#[derive(Clone, Debug)]
pub struct EchoOutcome {
    /// The restricted prover proved the law and the kernel checked the
    /// proof in the restricted view.
    pub proven: bool,
    /// The definitions that unfold (once), by source path.
    pub unfolded: Vec<String>,
    /// The functions that stayed unknown, by source path.
    pub unknown: Vec<String>,
    /// The hypotheses and the goal after the unfolding, printed (bounded).
    pub reads: String,
    /// The check could not be run (the statement did not re-elaborate, the
    /// restricted view could not be built): why. A hard rule never passes
    /// a law it could not check — this is reported as an LR6 (a) finding.
    pub undecided: Option<String>,
}

/// The §15.8 gate of the law rules (run by the crate path, like
/// `validate::spec15_gate`): every recorded finding of a
/// hard rule is an error, every other one a warning.
pub fn spec15_gate_laws(out: &super::Output, _krate: &Crate, diags: &mut Diagnostics) {
    for r in &out.law_rules {
        diags.push(r.diagnostic());
    }
}

// ----------------------------------------------------------------------
// the law table (LR9)
// ----------------------------------------------------------------------

/// Where a law is printed on the spec sheet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LawHeading {
    /// A guarantee (the table *law | guarantee | assumes*).
    Guarantee,
    /// `#[definitional(reason)]`: its own heading, never a guarantee.
    Definitional(String),
    /// `#[corollary]`: printed under the laws its proof applies.
    Corollary(Vec<String>),
}

/// One law of the law table (DESIGN.md §15.1 LR9).
#[derive(Clone, Debug)]
pub struct LawRow {
    pub law: ItemId,
    pub path: String,
    /// The first sentence of the doc comment (`None`: no doc comment).
    pub guarantee: Option<String>,
    /// The assumptions (`#[reduces_to]`): path, and the class and citation
    /// of the `#[assumption]` (`None` when it is not one).
    pub assumes: Vec<(String, Option<(String, String)>)>,
    pub heading: LawHeading,
}

/// Abbreviations whose period never ends a sentence (`etc.` ends one only
/// before a capital letter).
const ABBREVIATIONS: [&str; 7] = ["i.e.", "e.g.", "cf.", "vs.", "resp.", "viz.", "etc."];

/// The first sentence of the first paragraph of a doc comment: up to the
/// first `.`, `!` or `?` followed by a space or the end, outside code
/// spans, not counting the period of an abbreviation (`i.e.`, `e.g.`, …).
/// `None` when there is no doc text.
pub fn guarantee_sentence(docs: &[String]) -> Option<String> {
    let mut para = String::new();
    for l in docs {
        let t = l.trim();
        if t.is_empty() {
            if para.is_empty() {
                continue;
            }
            break;
        }
        if !para.is_empty() {
            para.push(' ');
        }
        para.push_str(t);
    }
    if para.is_empty() {
        return None;
    }
    let chars: Vec<char> = para.chars().collect();
    let mut tick = false;
    let mut end = chars.len();
    for i in 0..chars.len() {
        let c = chars[i];
        if c == '`' {
            tick = !tick;
            continue;
        }
        if !tick && matches!(c, '.' | '!' | '?') && (i + 1 == chars.len() || chars[i + 1].is_whitespace()) {
            if c == '.' && i + 1 < chars.len() {
                // the word the period ends (letters and periods, after a
                // space or an opening parenthesis)
                let mut j = i;
                while j > 0 && (chars[j - 1].is_alphabetic() || chars[j - 1] == '.') {
                    j -= 1;
                }
                let word: String = chars[j..=i].iter().collect::<String>().to_lowercase();
                let next_upper = chars[i + 1..].iter().find(|c| !c.is_whitespace()).is_some_and(|c| c.is_uppercase());
                if ABBREVIATIONS.contains(&word.as_str()) && !(word == "etc." && next_upper) {
                    continue;
                }
            }
            end = i + 1;
            break;
        }
    }
    Some(chars[..end].iter().collect::<String>().trim().to_string())
}

/// What [`states_guarantee`] requires, for the diagnostic.
pub const GUARANTEE_RULE: &str = "the first sentence needs at least three words, a code span counting as one word and at least one word (of two or more letters) outside code spans, and must be more than the law's name";

/// Whether a first sentence states something in words: at least three
/// words, where a code span counts as one word and at least one word (two
/// or more letters) is outside code spans, and more than the law's own
/// name ([`GUARANTEE_RULE`]).
pub fn states_guarantee(sentence: &str, name: &str) -> bool {
    let mut prose = String::new();
    let mut tick = false;
    let mut spans = 0usize;
    for c in sentence.chars() {
        if c == '`' {
            if !tick {
                spans += 1;
            }
            tick = !tick;
            prose.push(' ');
            continue;
        }
        if !tick {
            prose.push(c);
        }
    }
    let words: Vec<String> = prose.split(|c: char| !c.is_alphanumeric() && c != '_').filter(|w| w.chars().filter(|c| c.is_alphabetic()).count() >= 2).map(|w| w.to_lowercase()).collect();
    if words.is_empty() || words.len() + spans < 3 {
        return false;
    }
    let spoken: Vec<String> = name.split('_').filter(|w| !w.is_empty()).map(|w| w.to_lowercase()).collect();
    spans > 0 || words != spoken
}

/// The laws a proof script applies, and whether it does anything else than
/// applying laws and propositional steps (LR7).
fn script_uses(krate: &Crate, steps: &[ScriptStmt], law: ItemId, proof_item: Option<ItemId>, laws: &mut BTreeSet<ItemId>, other: &mut bool) {
    let app = |x: ItemId, laws: &mut BTreeSet<ItemId>, other: &mut bool| {
        // a proof item stands for its law (validate rewrites applications)
        let x = krate.fn_def(x).and_then(|g| g.proves).unwrap_or(x);
        if x == law || Some(x) == proof_item {
            // an induction hypothesis
            *other = true;
        } else if krate.fn_def(x).is_some_and(|g| g.kind == FnKind::Law) {
            laws.insert(x);
        } else if krate.fn_def(x).is_some_and(|g| matches!(g.kind, FnKind::Lemma | FnKind::Proof)) {
            *other = true;
        }
    };
    for st in steps {
        match &st.kind {
            ScriptKind::Apply { app: a, .. } => match &a.kind {
                ExprKind::Call { callee: Callee::Item(x, _), .. } => app(*x, laws, other),
                _ => *other = true,
            },
            ScriptKind::Assert { steps: Some(sub), prop } => {
                let _ = prop;
                script_uses(krate, sub, law, proof_item, laws, other);
            }
            ScriptKind::Exact(e) | ScriptKind::Rewrite { eq: e, .. } => {
                let mut refs = Vec::new();
                item_refs(e, &mut refs);
                for (x, _) in refs {
                    if krate.fn_def(x).is_some_and(|g| matches!(g.kind, FnKind::Law | FnKind::Lemma | FnKind::Proof)) {
                        app(x, laws, other);
                    }
                }
            }
            ScriptKind::Calc { links, .. } => {
                for l in links {
                    if let Some(s) = &l.steps {
                        script_uses(krate, s, law, proof_item, laws, other);
                    }
                }
            }
            ScriptKind::Assert { steps: None, .. } | ScriptKind::Let { .. } | ScriptKind::Show | ScriptKind::Contradiction | ScriptKind::Follows => {}
            // case analysis on program values, witnesses, unfolding,
            // evaluation, arithmetic, bit-blasting, open goals
            _ => *other = true,
        }
    }
}

/// The proof script of a law and its `#[proof]` item (if any).
fn law_proof(krate: &Crate, f: &FnDef) -> Option<(Vec<ScriptStmt>, Option<ItemId>, bool)> {
    match f.law_proof {
        Some(LawProof::Inline) => match &f.body {
            FnBody::Script(s) => Some((s.clone(), None, f.induction.is_some())),
            _ => None,
        },
        Some(LawProof::Item(p)) => match krate.fn_def(p).map(|pf| (&pf.body, pf.induction.is_some())) {
            Some((FnBody::Script(s), ind)) => Some((s.clone(), Some(p), ind)),
            _ => None,
        },
        _ => None,
    }
}

/// The laws the proof of law `id` applies, and whether it does more than
/// that (LR7).
fn corollary_of(krate: &Crate, id: ItemId, f: &FnDef) -> Option<(BTreeSet<ItemId>, bool)> {
    let (steps, pitem, induction) = law_proof(krate, f)?;
    let mut laws = BTreeSet::new();
    let mut other = induction;
    script_uses(krate, &steps, id, pitem, &mut laws, &mut other);
    Some((laws, other))
}

/// The law table of a crate (LR9; see the module docs), in item order.
pub fn law_table(krate: &Crate) -> Vec<LawRow> {
    let mut out = Vec::new();
    for it in &krate.items {
        let ItemKind::Fn(f) = &it.kind else { continue };
        if f.kind != FnKind::Law {
            continue;
        }
        let assumes = f
            .spec
            .reduces_to
            .iter()
            .map(|(a, _)| {
                let info = krate.fn_def(*a).and_then(|g| g.spec.assumption.as_ref()).map(|x| (x.class.name().to_string(), x.cite.clone()));
                (krate.item(*a).path.to_string(), info)
            })
            .collect();
        let heading = if let Some(d) = &f.spec.definitional {
            LawHeading::Definitional(d.justification.clone())
        } else if f.spec.corollary.is_some() {
            let of = corollary_of(krate, it.id, f).map(|(l, _)| l.into_iter().map(|x| krate.item(x).path.to_string()).collect()).unwrap_or_default();
            LawHeading::Corollary(of)
        } else {
            LawHeading::Guarantee
        };
        out.push(LawRow { law: it.id, path: it.path.to_string(), guarantee: guarantee_sentence(&it.docs), assumes, heading });
    }
    out
}

/// The law table as text lines (spec sheet, CLI): the guarantees with
/// their assumptions, each followed by its corollaries, then the
/// definitional laws.
pub fn table_lines(rows: &[LawRow]) -> Vec<String> {
    let mut out = Vec::new();
    let short = |p: &str| p.strip_prefix("crate::").unwrap_or(p).to_string();
    let assumes = |r: &LawRow| {
        if r.assumes.is_empty() {
            "nothing".to_string()
        } else {
            r.assumes
                .iter()
                .map(|(p, info)| match info {
                    Some((class, cite)) => format!("`{}` ({class}: {cite})", short(p)),
                    None => format!("`{}` (not an `#[assumption]`)", short(p)),
                })
                .collect::<Vec<_>>()
                .join(", ")
        }
    };
    let text = |r: &LawRow| r.guarantee.clone().unwrap_or_else(|| "(no doc comment)".into()).replace('|', "\\|");
    let guarantees: Vec<&LawRow> = rows.iter().filter(|r| r.heading == LawHeading::Guarantee).collect();
    let corollaries: Vec<&LawRow> = rows.iter().filter(|r| matches!(r.heading, LawHeading::Corollary(_))).collect();
    out.push("| law | guarantee | assumes |".to_string());
    out.push("| --- | --- | --- |".to_string());
    let mut placed: BTreeSet<ItemId> = BTreeSet::new();
    for r in &guarantees {
        out.push(format!("| `{}` | {} | {} |", short(&r.path), text(r), assumes(r)));
        for c in &corollaries {
            if let LawHeading::Corollary(of) = &c.heading
                && of.contains(&r.path)
                && placed.insert(c.law)
            {
                out.push(format!("| ↳ corollary `{}` | {} | {} |", short(&c.path), text(c), assumes(c)));
            }
        }
    }
    for c in &corollaries {
        if placed.insert(c.law) {
            let of = match &c.heading {
                LawHeading::Corollary(of) if !of.is_empty() => format!(" (of {})", of.iter().map(|p| format!("`{}`", short(p))).collect::<Vec<_>>().join(", ")),
                _ => String::new(),
            };
            out.push(format!("| ↳ corollary `{}`{of} | {} | {} |", short(&c.path), text(c), assumes(c)));
        }
    }
    let defs: Vec<&LawRow> = rows.iter().filter(|r| matches!(r.heading, LawHeading::Definitional(_))).collect();
    if !defs.is_empty() {
        out.push(String::new());
        out.push("Definitional laws (restate a definition; not guarantees):".to_string());
        for r in defs {
            if let LawHeading::Definitional(reason) = &r.heading {
                out.push(format!("  `{}`: {} — reason: {reason}", short(&r.path), text(r)));
            }
        }
    }
    out
}

// ----------------------------------------------------------------------
// HIR helpers
// ----------------------------------------------------------------------

/// `e` without coercions, references and dereferences.
pub(crate) fn peel(e: &Expr) -> &Expr {
    match &e.kind {
        ExprKind::Coerce(_, x) | ExprKind::Ref(x) | ExprKind::Deref(x) => peel(x),
        _ => e,
    }
}

/// The conjuncts of a hypothesis.
fn conjuncts<'e>(e: &'e Expr, out: &mut Vec<&'e Expr>) {
    let p = peel(e);
    match &p.kind {
        ExprKind::PropAnd(a, b) | ExprKind::Binary(BinOp::And, a, b) => {
            conjuncts(a, out);
            conjuncts(b, out);
        }
        _ => out.push(e),
    }
}

/// The hypotheses (conjuncts of implication antecedents) and disjuncts of
/// a conclusion.
pub(crate) fn conclusion_parts<'e>(e: &'e Expr, hyps: &mut Vec<&'e Expr>, disj: &mut Vec<&'e Expr>) {
    let p = peel(e);
    match &p.kind {
        ExprKind::PropOr(a, b) | ExprKind::Binary(BinOp::Or, a, b) => {
            conclusion_parts(a, hyps, disj);
            conclusion_parts(b, hyps, disj);
        }
        ExprKind::Implies(a, b) => {
            conjuncts(a, hyps);
            conclusion_parts(b, hyps, disj);
        }
        _ => disj.push(e),
    }
}

/// Whether `e` reads one of `locals`.
fn mentions_local(e: &Expr, locals: &HashSet<LocalId>) -> bool {
    struct V<'s>(&'s HashSet<LocalId>, bool);
    impl crate::visit::Visitor for V<'_> {
        fn expr(&mut self, e: &Expr) {
            if matches!(&e.kind, ExprKind::Local(l) if self.0.contains(l)) {
                self.1 = true;
                return;
            }
            crate::visit::walk_expr(self, e);
        }
    }
    let mut v = V(locals, false);
    crate::visit::Visitor::expr(&mut v, e);
    v.1
}

/// The user items `e` calls or reads (functions and constants), with the
/// span of the first mention.
fn item_refs(e: &Expr, out: &mut Vec<(ItemId, Span)>) {
    struct V<'o>(&'o mut Vec<(ItemId, Span)>);
    impl crate::visit::Visitor for V<'_> {
        fn expr(&mut self, e: &Expr) {
            let id = match &e.kind {
                ExprKind::Call { callee: Callee::Item(id, _), .. } | ExprKind::Const(id) => Some(*id),
                _ => None,
            };
            if let Some(id) = id
                && !self.0.iter().any(|(x, _)| *x == id)
            {
                self.0.push((id, e.span));
            }
            crate::visit::walk_expr(self, e);
        }
    }
    crate::visit::Visitor::expr(&mut V(out), e);
}

/// The fields `e` reads of exec types with a `#[view]` or `#[represents]`:
/// `(type, field, span)`, each field once.
fn viewed_fields(krate: &Crate, e: &Expr) -> Vec<(ItemId, String, Span)> {
    struct V<'k>(&'k Crate, Vec<(ItemId, String, Span)>);
    impl crate::visit::Visitor for V<'_> {
        fn expr(&mut self, e: &Expr) {
            if let ExprKind::Field { base, index, name } = &e.kind
                && let Ty::Adt(id, _) = base.ty.peel_refs()
            {
                let it = self.0.item(*id);
                let viewed = !it.ghost && matches!(&it.kind, ItemKind::Struct(s) if s.view.is_some() || s.represents.is_some());
                let field = name.clone().unwrap_or_else(|| index.to_string());
                if viewed && !self.1.iter().any(|(t, f, _)| t == id && *f == field) {
                    self.1.push((*id, field, e.span));
                }
            }
            crate::visit::walk_expr(self, e);
        }
    }
    let mut v = V(krate, Vec::new());
    crate::visit::Visitor::expr(&mut v, e);
    v.1
}

/// A quantifier or a `Prop`-typed subexpression of `e` (its span).
fn quant_or_prop(e: &Expr) -> Option<Span> {
    struct V(Option<Span>);
    impl crate::visit::Visitor for V {
        fn expr(&mut self, e: &Expr) {
            if self.0.is_some() {
                return;
            }
            if matches!(e.kind, ExprKind::Quant { .. }) || e.ty == Ty::Prop {
                self.0 = Some(e.span);
                return;
            }
            crate::visit::walk_expr(self, e);
        }
    }
    let mut v = V(None);
    crate::visit::Visitor::expr(&mut v, e);
    v.0
}

/// The expressions of a law's or function's statement.
fn statement_exprs(f: &FnDef) -> Vec<&Expr> {
    let mut v: Vec<&Expr> = f.requires.iter().collect();
    if let Some(en) = &f.ensures {
        v.push(&en.prop);
    }
    v
}

/// The binders of a statement: the parameters' locals (and the `ensures`
/// binder of a contract).
fn binders(f: &FnDef, with_ret: bool) -> HashSet<LocalId> {
    let mut s: HashSet<LocalId> = f.params.iter().flat_map(|p| p.pat.bindings()).collect();
    if with_ret && let Some(en) = &f.ensures {
        s.extend(en.binder.bindings());
    }
    s
}

/// Occurrence polarity (LR10).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pol {
    /// In a conclusion.
    Pos,
    /// In a hypothesis.
    Neg,
    /// Both (an equation between booleans, an argument, a condition).
    Both,
}

impl Pol {
    fn flip(self) -> Pol {
        match self {
            Pol::Pos => Pol::Neg,
            Pol::Neg => Pol::Pos,
            Pol::Both => Pol::Both,
        }
    }
}

fn bool_lit(e: &Expr) -> Option<bool> {
    match &peel(e).kind {
        ExprKind::Lit(Lit::Bool(b)) => Some(*b),
        _ => None,
    }
}

/// Counts the occurrences of `targets` in `e` at polarity `pol`: `(in
/// hypotheses, in conclusions)`.
fn polarity(e: &Expr, pol: Pol, targets: &HashSet<ItemId>, out: &mut (usize, usize)) {
    let count = |pol: Pol, out: &mut (usize, usize)| match pol {
        Pol::Pos => out.1 += 1,
        Pol::Neg => out.0 += 1,
        Pol::Both => {
            out.0 += 1;
            out.1 += 1;
        }
    };
    let p = peel(e);
    match &p.kind {
        ExprKind::PropNot(a) | ExprKind::Unary(UnOp::Not, a) => polarity(a, pol.flip(), targets, out),
        ExprKind::PropAnd(a, b) | ExprKind::PropOr(a, b) | ExprKind::Binary(BinOp::And | BinOp::Or, a, b) => {
            polarity(a, pol, targets, out);
            polarity(b, pol, targets, out);
        }
        ExprKind::Implies(a, b) => {
            polarity(a, pol.flip(), targets, out);
            polarity(b, pol, targets, out);
        }
        ExprKind::Iff(a, b) => {
            polarity(a, Pol::Both, targets, out);
            polarity(b, Pol::Both, targets, out);
        }
        ExprKind::PropEq(a, b) | ExprKind::Binary(BinOp::Eq, a, b) | ExprKind::PropNe(a, b) | ExprKind::Binary(BinOp::Ne, a, b) => {
            let ne = matches!(p.kind, ExprKind::PropNe(..) | ExprKind::Binary(BinOp::Ne, ..));
            match (bool_lit(a), bool_lit(b)) {
                (_, Some(v)) => polarity(a, if v != ne { pol } else { pol.flip() }, targets, out),
                (Some(v), _) => polarity(b, if v != ne { pol } else { pol.flip() }, targets, out),
                _ => {
                    polarity(a, Pol::Both, targets, out);
                    polarity(b, Pol::Both, targets, out);
                }
            }
        }
        ExprKind::Quant { body, .. } => polarity(body, pol, targets, out),
        ExprKind::Call { callee: Callee::Item(id, _), args } if targets.contains(id) => {
            count(pol, out);
            for a in args {
                polarity(a, Pol::Both, targets, out);
            }
        }
        _ => super::items::walk_children_pub(p, &mut |x| polarity(x, Pol::Both, targets, out)),
    }
}

/// The globals of `set` occurring anywhere in `t`.
fn globals_in(t: &Tm, set: &HashSet<GlobalId>, out: &mut BTreeSet<GlobalId>) {
    super::tm::any_node(t, &mut |n| {
        if let Term::Global(g) = n
            && set.contains(g)
        {
            out.insert(*g);
        }
        false
    });
}

/// The shape hash and size of every node of a term (LR6 (b)): variables
/// anonymized, globals by name, irrelevant children skipped, view
/// coercions (`uN → Int` casts, `T::view`, `ghost::seq_map`) stripped;
/// memoized by node.
struct Shapes<'e> {
    env: &'e sandblaster_kernel::api::Env,
    memo: HashMap<usize, (Tm, u64, usize)>,
    names: HashMap<GlobalId, String>,
}

impl<'e> Shapes<'e> {
    fn new(env: &'e sandblaster_kernel::api::Env) -> Shapes<'e> {
        Shapes { env, memo: HashMap::new(), names: HashMap::new() }
    }

    fn name(&mut self, g: GlobalId) -> String {
        if let Some(n) = self.names.get(&g) {
            return n.clone();
        }
        let n = self.env.global_name(g).map(|n| n.to_string()).unwrap_or_else(|| format!("@{}", g.0));
        self.names.insert(g, n.clone());
        n
    }

    /// The view coercion `t` wraps (its operand), if any.
    fn coercion_operand(&mut self, t: &Tm) -> Option<Tm> {
        match &**t {
            Term::Prim { op: PrimOp::Cast { to: Width::Int, .. }, args, .. } if args.len() == 1 => Some(args[0].clone()),
            Term::App { .. } => {
                let (head, args) = super::items::spine(t);
                let Term::Global(g) = &*head else { return None };
                let n = self.name(*g);
                if (n.ends_with("::view") || n == "ghost::seq_map") && !args.is_empty() {
                    args.last().cloned()
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// `(hash, size)` of `t`.
    fn shape(&mut self, t: &Tm) -> (u64, usize) {
        let key = Rc::as_ptr(t) as *const () as usize;
        if let Some((_, h, n)) = self.memo.get(&key) {
            return (*h, *n);
        }
        if let Some(x) = self.coercion_operand(t) {
            let r = self.shape(&x);
            self.memo.insert(key, (t.clone(), r.0, r.1));
            return r;
        }
        let mut h = DefaultHasher::new();
        let mut size = 1usize;
        let child = |s: &mut Shapes<'e>, c: &Tm, h: &mut DefaultHasher, size: &mut usize| {
            let (ch, cn) = s.shape(c);
            ch.hash(h);
            *size = size.saturating_add(cn).min(1 << 24);
        };
        match &**t {
            Term::Var(_) => "v".hash(&mut h),
            Term::Global(g) => {
                "g".hash(&mut h);
                self.name(*g).hash(&mut h);
            }
            Term::Sort(s) => format!("sort{s:?}").hash(&mut h),
            Term::Pi { rel, dom, cod, .. } => {
                ("pi", *rel == Rel::Rel).hash(&mut h);
                child(self, dom, &mut h, &mut size);
                child(self, cod, &mut h, &mut size);
            }
            Term::Lam { rel, dom, body, .. } => {
                ("lam", *rel == Rel::Rel).hash(&mut h);
                child(self, dom, &mut h, &mut size);
                child(self, body, &mut h, &mut size);
            }
            Term::App { rel, fun, arg } => {
                "app".hash(&mut h);
                child(self, fun, &mut h, &mut size);
                if *rel == Rel::Rel {
                    child(self, arg, &mut h, &mut size);
                }
            }
            Term::Let { rel, val, body, .. } => {
                "let".hash(&mut h);
                if *rel == Rel::Rel {
                    child(self, val, &mut h, &mut size);
                }
                child(self, body, &mut h, &mut size);
            }
            Term::Sigma { fst, snd, .. } => {
                "sigma".hash(&mut h);
                child(self, fst, &mut h, &mut size);
                child(self, snd, &mut h, &mut size);
            }
            Term::Pair { fst, snd, .. } => {
                "pair".hash(&mut h);
                child(self, fst, &mut h, &mut size);
                child(self, snd, &mut h, &mut size);
            }
            Term::Fst(p) => {
                "fst".hash(&mut h);
                child(self, p, &mut h, &mut size);
            }
            Term::Snd(p) => {
                "snd".hash(&mut h);
                child(self, p, &mut h, &mut size);
            }
            Term::Eq { ty, lhs, rhs } => {
                "eq".hash(&mut h);
                child(self, ty, &mut h, &mut size);
                child(self, lhs, &mut h, &mut size);
                child(self, rhs, &mut h, &mut size);
            }
            Term::Ind { ind, params } => {
                ("ind", ind.0).hash(&mut h);
                for p in params {
                    child(self, p, &mut h, &mut size);
                }
            }
            Term::Ctor { ind, ctor, args, .. } => {
                ("ctor", ind.0, *ctor).hash(&mut h);
                for a in args {
                    child(self, a, &mut h, &mut size);
                }
            }
            Term::Match { ind, scrut, arms, .. } => {
                ("match", ind.0, arms.len()).hash(&mut h);
                child(self, scrut, &mut h, &mut size);
                for a in arms {
                    child(self, &a.body, &mut h, &mut size);
                }
            }
            Term::IntTy(w) => format!("int{w:?}").hash(&mut h),
            Term::Lit { w, n } => format!("lit{w:?}{n}").hash(&mut h),
            Term::Prim { op, args, .. } => {
                format!("prim{op:?}").hash(&mut h);
                for a in args {
                    child(self, a, &mut h, &mut size);
                }
            }
            Term::Rec { args, .. } => {
                "rec".hash(&mut h);
                for a in args {
                    child(self, a, &mut h, &mut size);
                }
            }
            // proofs and proof-only constructs: not compared
            _ => {
                "proof".hash(&mut h);
                size = 1;
            }
        }
        let r = (h.finish(), size);
        self.memo.insert(key, (t.clone(), r.0, r.1));
        r
    }

    /// Every node of `t` with its shape (pre-order, each shared node once).
    fn nodes(&mut self, t: &Tm, out: &mut Vec<(u64, usize)>, seen: &mut HashSet<usize>) {
        let key = Rc::as_ptr(t) as *const () as usize;
        if !seen.insert(key) {
            return;
        }
        let r = self.shape(t);
        out.push(r);
        let t2 = self.coercion_operand(t).unwrap_or_else(|| t.clone());
        let kids: Vec<Tm> = match &*t2 {
            Term::Pi { dom, cod, .. } => vec![dom.clone(), cod.clone()],
            Term::Lam { dom, body, .. } => vec![dom.clone(), body.clone()],
            Term::App { rel, fun, arg } => {
                if *rel == Rel::Rel {
                    vec![fun.clone(), arg.clone()]
                } else {
                    vec![fun.clone()]
                }
            }
            Term::Let { rel, val, body, .. } => {
                if *rel == Rel::Rel {
                    vec![val.clone(), body.clone()]
                } else {
                    vec![body.clone()]
                }
            }
            Term::Sigma { fst, snd, .. } | Term::Pair { fst, snd, .. } => vec![fst.clone(), snd.clone()],
            Term::Fst(p) | Term::Snd(p) => vec![p.clone()],
            Term::Eq { ty, lhs, rhs } => vec![ty.clone(), lhs.clone(), rhs.clone()],
            Term::Ind { params, .. } => params.clone(),
            Term::Ctor { args, .. } => args.clone(),
            Term::Match { scrut, arms, .. } => {
                let mut v = vec![scrut.clone()];
                v.extend(arms.iter().map(|a| a.body.clone()));
                v
            }
            Term::Prim { args, .. } | Term::Rec { args, .. } => args.clone(),
            _ => vec![],
        };
        for k in kids {
            self.nodes(&k, out, seen);
        }
    }
}

/// The echo prover (LR6 (a)): `auto` with case splits on program values
/// (propositional reasoning on stuck scrutinees), congruence and rewriting
/// with the hypotheses, evaluation — and no linear arithmetic, no integer
/// enumeration, no `BvRefl`; the view hides every definition but the named
/// ones, and each of those unfolds at most `deltas` times in all.
fn echo_config(deltas: u32) -> crate::auto::AutoConfig {
    crate::auto::AutoConfig {
        mode: crate::auto::Mode::Full,
        max_split_depth: 2,
        max_rewrites: 16,
        max_deltas: deltas,
        max_nodes: 300,
        enum_limit: 0,
        lin_rounds: 1,
        int_cuts: 0,
        cut_width: 1,
        max_fact_rewrites: 16,
        max_instances: 8,
        self_check: true,
        goal_timeout: None,
        deep_enrich: false,
        auto_bvrefl: false,
        arith: false,
    }
}

impl<'a> Elab<'a> {
    /// The law rules (see the module docs): every finding, in rule order.
    /// Run once after the other §15 stages (main elaboration only).
    pub fn law_rules_pass(&mut self) -> Vec<LawRuleRecord> {
        let krate: &'a Crate = self.krate;
        let mut out = Vec::new();
        let exported: BTreeSet<ItemId> = crate::validate::exported_functions(krate).into_iter().filter(|id| krate.fn_def(*id).is_some_and(|f| f.kind == FnKind::Exec) && !krate.item(*id).ghost).collect();
        let laws: Vec<ItemId> = krate.items.iter().filter(|it| matches!(&it.kind, ItemKind::Fn(f) if f.kind == FnKind::Law)).map(|it| it.id).collect();
        self.assumption_shapes();
        for &l in &laws {
            let f = krate.fn_def(l).expect("law");
            self.lr_vocabulary(l, f, &exported, &mut out);
            lr_closed(krate, l, f, true, &mut out);
            if f.spec.reduces_to.is_some() {
                self.lr_extraction(l, f, &mut out);
            }
            lr_documented(krate, l, f, &mut out);
            lr_corollary(krate, l, f, &mut out);
        }
        for it in &krate.items {
            if let ItemKind::Fn(f) = &it.kind
                && matches!(f.kind, FnKind::Exec | FnKind::Spec)
                && (!f.requires.is_empty() || f.ensures.is_some())
            {
                lr_closed(krate, it.id, f, false, &mut out);
            }
        }
        lr_directions(krate, &laws, &exported, &mut out);
        let t = std::time::Instant::now();
        self.lr_mirrors(&mut out);
        let t_mirrors = t.elapsed();
        self.lr_echo_resemblance(&laws, &mut out);
        if std::env::var_os("SANDBLASTER_TRACE_LAW_RULES").is_some() {
            eprintln!("law rules: {} law(s), {} finding(s); mirrors {t_mirrors:?}, echo and resemblance {:?}", laws.len(), out.len(), t.elapsed() - t_mirrors);
        }
        out.sort_by_key(|r| r.rule);
        out
    }

    /// An `#[assumption]` has no logical content: `fn name() {}` (its
    /// signature is checked by the typechecker). An error now: the
    /// annotation is new, no crate relies on another shape.
    fn assumption_shapes(&mut self) {
        let krate = self.krate;
        for it in &krate.items {
            let ItemKind::Fn(f) = &it.kind else { continue };
            let Some(a) = &f.spec.assumption else { continue };
            let empty = matches!(&f.body, FnBody::Spec(Expr { kind: ExprKind::Block(b), .. }) if b.stmts.is_empty() && b.tail.is_none());
            if !empty || !f.requires.is_empty() {
                self.diag(
                    Diagnostic::error(DiagKind::Attribute, a.span, format!("`#[assumption]` `{}` has a body or a `requires`: an assumption has no logical content", it.path))
                        .note("write it as `fn name() {}`; laws that rely on it are stated in extraction form and name it with `#[reduces_to(name)]` (DESIGN.md §15.13)"),
                );
            }
        }
    }

    /// The kernel global of a user item.
    fn def_global(&self, id: ItemId) -> Option<GlobalId> {
        match self.globals.get(&id) {
            Some(ItemGlobal::Def(g)) => Some(*g),
            _ => None,
        }
    }

    /// LR1 (vocabulary), LR2 (closure), LR3 (state it over the spec).
    fn lr_vocabulary(&self, l: ItemId, f: &FnDef, exported: &BTreeSet<ItemId>, out: &mut Vec<LawRuleRecord>) {
        let krate = self.krate;
        let lit = krate.item(l);
        let lpath = lit.path.to_string();
        let mut refs: Vec<(ItemId, Span)> = Vec::new();
        for e in statement_exprs(f) {
            item_refs(e, &mut refs);
        }
        if let Some((a, sp)) = f.spec.reduces_to
            && !refs.iter().any(|(x, _)| *x == a)
        {
            refs.push((a, sp));
        }
        // exec types are read through their views: a field of a type with a
        // `#[view]` or `#[represents]` is its representation
        let mut fields: Vec<(ItemId, String, Span)> = Vec::new();
        for e in statement_exprs(f) {
            for x in viewed_fields(krate, e) {
                if !fields.iter().any(|(t, n, _)| *t == x.0 && *n == x.1) {
                    fields.push(x);
                }
            }
        }
        for (ty, name, sp) in fields {
            out.push(
                LawRuleRecord::new(LawRule::Lr1, l, sp, format!("law `{lpath}` reads the field `{name}` of the exec type `{}`, whose meaning is its view", krate.item(ty).path))
                    .note("a law may mention exec types only through their views (DESIGN.md §15.1 LR1): a field of a type with a `#[view]` or `#[represents]` is its representation, which the law must not depend on")
                    .note("state the law over the view (the type-directed coercion into the spec type, or the spec function the view calls)"),
            );
        }
        let exported_g: Vec<GlobalId> = exported.iter().filter_map(|id| self.def_global(*id)).collect();
        let back: HashMap<GlobalId, ItemId> = self.globals.iter().filter_map(|(k, v)| if let ItemGlobal::Def(g) = v { Some((*g, *k)) } else { None }).collect();
        let eqs: HashSet<GlobalId> = self.eq_fns.values().flat_map(|e| [Some(e.eq), e.sound, e.complete]).flatten().collect();
        const VOCAB: &str = "a law may mention only spec items, exec types (through their views) and exported functions: the root's `pub use` list and the `pub` methods of exported types (DESIGN.md §15.1 LR1)";
        let suggest = |name: &str| format!("an internal function is specified where it is defined: put `#[refines(spec::…)]` (or `#[ensures]`) on `{name}`, or move the claim to a `#[lemma]` in PROOF.rs that connects it to the laws");
        let mut reported: BTreeSet<ItemId> = BTreeSet::new();
        let mut lr2: BTreeSet<GlobalId> = BTreeSet::new();
        for (id, span) in refs {
            let it = krate.item(id);
            match &it.kind {
                ItemKind::Fn(g) if g.kind == FnKind::Exec && !it.ghost => {
                    if exported.contains(&id) {
                        if let Some(r) = &g.spec.refines {
                            let s = krate.item(r.spec).path.to_string();
                            out.push(
                                LawRuleRecord::new(LawRule::Lr3, l, span, format!("law `{lpath}` mentions `{}`, which refines `{s}`: state it over `{s}`", it.path))
                                    .note(format!("the two statements are equivalent once `{}::refines` is proven; the spec form does not tie the guarantee to the function's signature and adds no determinacy obligation (DESIGN.md §15.1 LR3)", it.path)),
                            );
                        }
                    } else if reported.insert(id) {
                        out.push(LawRuleRecord::new(LawRule::Lr1, l, span, format!("law `{lpath}` mentions the internal exec function `{}`", it.path)).note(VOCAB).note(suggest(&it.path.to_string())));
                    }
                }
                // a plain `fn` of a ghost module (`LAWS.rs`, `PROOF.rs`): exec
                // code that is neither a spec item (spec closure, the mirrors
                // check) nor exported — a copy of the implementation would
                // pass every other rule
                ItemKind::Fn(g) if g.kind == FnKind::Exec => {
                    if reported.insert(id) {
                        out.push(
                            LawRuleRecord::new(LawRule::Lr1, l, span, format!("law `{lpath}` mentions `{}`, a plain `fn` of a ghost module: neither a spec item nor an exported function", it.path))
                                .note(VOCAB)
                                .note(format!("declare `{}` in a `#[spec]` module, where spec closure and the mirrors check (LR5) apply to it, or state the law without it", it.name)),
                        );
                    }
                }
                ItemKind::Const(_) if !it.ghost => {
                    if reported.insert(id) {
                        out.push(LawRuleRecord::new(LawRule::Lr1, l, span, format!("law `{lpath}` mentions the exec constant `{}`", it.path)).note(VOCAB).note("state the value as a spec constant (`spec::…`), written from the standard, and relate it to the code in a lemma if needed"));
                    }
                }
                ItemKind::Fn(g) if g.kind == FnKind::Spec => self.lr_through(l, &lpath, id, span, &exported_g, &back, &eqs, &mut reported, &mut lr2, out),
                ItemKind::Const(_) => self.lr_through(l, &lpath, id, span, &exported_g, &back, &eqs, &mut reported, &mut lr2, out),
                _ => {}
            }
        }
    }

    /// LR1/LR2 through the `Refs*` of spec item `s`, not descending into
    /// exported functions nor into the exec functions and constants it
    /// reaches (each is listed once: its own callees are its business). An
    /// established function is allowed by spec closure but not by the law
    /// vocabulary (LR1); any other exec global violates spec closure
    /// itself (LR2, reported once, not also as LR1: the spec item is what
    /// must be transcribed).
    #[allow(clippy::too_many_arguments)]
    fn lr_through(&self, l: ItemId, lpath: &str, s: ItemId, span: Span, exported_g: &[GlobalId], back: &HashMap<GlobalId, ItemId>, eqs: &HashSet<GlobalId>, reported: &mut BTreeSet<ItemId>, lr2: &mut BTreeSet<GlobalId>, out: &mut Vec<LawRuleRecord>) {
        let krate = self.krate;
        let Some(gs) = self.def_global(s) else { return };
        let spath = krate.item(s).path.to_string();
        // exec functions, ghost ones (plain `fn`s of ghost modules) included,
        // and exec constants
        let is_exec = |i: ItemId| {
            let it = krate.item(i);
            (!it.ghost && matches!(&it.kind, ItemKind::Const(_))) || matches!(&it.kind, ItemKind::Fn(f) if f.kind == FnKind::Exec)
        };
        let mut stop: Vec<GlobalId> = exported_g.to_vec();
        stop.extend(back.iter().filter(|(_, i)| is_exec(**i)).map(|(g, _)| *g));
        for h in self.env.refs_closure(&mk::global(gs), &stop) {
            if exported_g.contains(&h) || eqs.contains(&h) {
                continue;
            }
            match back.get(&h) {
                Some(i) => {
                    let hi = krate.item(*i);
                    let what = if matches!(hi.kind, ItemKind::Const(_)) { "exec constant" } else { "exec function" };
                    match &hi.kind {
                        _ if is_exec(*i) && self.s1.established.contains(&h) => {
                            if reported.insert(*i) {
                                out.push(
                                    LawRuleRecord::new(LawRule::Lr1, l, span, format!("law `{lpath}` depends on the internal {what} `{}` through the spec item `{spath}`", hi.path))
                                        .note("spec closure allows established functions in specifications, but a law may mention only spec items, exec types (through their views) and exported functions, directly or through the `Refs*` of a spec item (DESIGN.md §15.1 LR1)")
                                        .note(format!("state the law over the spec function `{}` refines, or move it to a `#[lemma]` in PROOF.rs", hi.path)),
                                );
                            }
                        }
                        _ if is_exec(*i) => {
                            if reported.insert(*i) {
                                out.push(
                                    LawRuleRecord::new(LawRule::Lr2, l, span, format!("law `{lpath}` depends on the {what} `{}` through the spec item `{spath}`, which is not spec-closed", hi.path))
                                        .note("for spec closure a law is a spec item: its `Refs*` may reach spec items, established functions and the exported functions it constrains only; the law vocabulary (LR1) forbids the internal function as well (DESIGN.md §15.1 LR1, LR2)")
                                        .note(format!("transcribe what `{spath}` needs into `spec::` — a specification written in terms of the implementation proves nothing about it")),
                                );
                            }
                        }
                        ItemKind::Fn(hf) if matches!(hf.kind, FnKind::Lemma | FnKind::Law | FnKind::Proof) && lr2.insert(h) => {
                            out.push(LawRuleRecord::new(LawRule::Lr2, l, span, format!("law `{lpath}` depends on the {} `{}` through the spec item `{spath}`", hf.kind.name(), hi.path)).note("for spec closure a law is a spec item: its `Refs*` may reach spec items, established functions and the exported functions it constrains only (DESIGN.md §15.1 LR2)"));
                        }
                        _ => {}
                    }
                }
                None => {
                    if matches!(self.env.global_kind(h), Some(sandblaster_kernel::term::DefKind::LoopHelper | sandblaster_kernel::term::DefKind::Ensures | sandblaster_kernel::term::DefKind::Exec)) && lr2.insert(h) {
                        let name = self.env.global_name(h).map(|n| n.to_string()).unwrap_or_default();
                        out.push(LawRuleRecord::new(LawRule::Lr2, l, span, format!("law `{lpath}` depends on the exec global `{name}` through the spec item `{spath}`")).note("for spec closure a law is a spec item: its `Refs*` may reach spec items, established functions and the exported functions it constrains only (DESIGN.md §15.1 LR2)"));
                    }
                }
            }
        }
    }

    /// LR4, the extraction form of a `#[reduces_to]` law.
    fn lr_extraction(&mut self, l: ItemId, f: &'a FnDef, out: &mut Vec<LawRuleRecord>) {
        let before = out.len();
        self.lr_extraction_form(l, f, out);
        if out.len() == before {
            self.lr_reduction_vacuity(l, f, out);
        }
    }

    /// LR4, the vacuity of a well-formed `#[reduces_to]` law `requires ⇒ P ∨
    /// B(t̄)`: a break predicate that ignores its arguments, or that
    /// follows from the hypotheses (bounded `auto`), makes the law true of
    /// any specification; a guarantee `P` that follows from the hypotheses
    /// alone makes the break disjunct (and the assumption) dead. A closed
    /// truth disguised by arguments is as vacuous as a closed disjunct.
    fn lr_reduction_vacuity(&mut self, l: ItemId, f: &'a FnDef, out: &mut Vec<LawRuleRecord>) {
        let krate = self.krate;
        let lit = krate.item(l);
        let lpath = lit.path.to_string();
        let Some(en) = &f.ensures else { return };
        let (mut hyps, mut disj) = (Vec::new(), Vec::new());
        conclusion_parts(&en.prop, &mut hyps, &mut disj);
        let Some((brk, rest)) = disj.split_last() else { return };
        const NOTE: &str = "a law in extraction form (`#[reduces_to(a)]`) says: the guarantee `P` holds, or the inputs exhibit a break `B(t̄)` of the assumption; it means something only if the break can fail when `P` does (DESIGN.md §15.1 LR4, §15.13)";
        // the break predicate must read its arguments
        if let ExprKind::Call { callee: Callee::Item(bid, _), .. } = &peel(brk).kind
            && let Some(bf) = krate.fn_def(*bid)
            && let FnBody::Spec(body) = &bf.body
        {
            let params: HashSet<LocalId> = bf.params.iter().flat_map(|p| p.pat.bindings()).collect();
            if !params.is_empty() && !mentions_local(body, &params) {
                out.push(
                    LawRuleRecord::new(LawRule::Lr4, l, brk.span, format!("the break predicate `{}` of law `{lpath}` ignores its arguments: the break disjunct is a closed claim", krate.item(*bid).path))
                        .note(NOTE)
                        .note("a break predicate decides whether its arguments break the assumption (e.g. two different messages with one digest): it must depend on them"),
                );
                return;
            }
        }
        let (n_obl, n_diag, n_defs, n_laws) = (self.obligations.len(), self.diags.list.len(), self.defs.len(), self.laws.len());
        let saved = std::mem::replace(&mut self.f, FnState::new(format!("{}::law-rules", lit.path), Some(l), &f.locals, lit.span));
        self.f.fdef = Some(f);
        self.f.mode = Mode::Proof;
        let r = (|| -> R<(bool, bool)> {
            let (mut binders, _pending) = self.fn_params(f, lit.span)?;
            self.fn_requires(f, &mut binders, Rel::Rel)?;
            for h in &hyps {
                let t = self.prop_of(h)?;
                self.push_fact_rel("h_ante", Rel::Rel, &t, None, crate::prover::FactOrigin::LemmaHyp, h.span)?;
            }
            let b = self.prop_of(brk)?;
            let vacuous = self.bounded_attempt(&b, REDUCTION_BUDGET, brk.span);
            let mut p: Option<Tm> = None;
            for d in rest {
                let t = self.prop_of(d)?;
                p = Some(match p {
                    None => t,
                    Some(q) => mk::apps(mk::global(self.p.g("Or")), [(Rel::Rel, q), (Rel::Rel, t)]),
                });
            }
            let dead = !vacuous && p.is_some_and(|p| self.bounded_attempt(&p, REDUCTION_BUDGET, en.prop.span));
            Ok((vacuous, dead))
        })();
        self.obligations.truncate(n_obl);
        self.diags.list.truncate(n_diag);
        self.defs.truncate(n_defs);
        self.laws.truncate(n_laws);
        self.f = saved;
        match r {
            Ok((true, _)) => out.push(
                LawRuleRecord::new(LawRule::Lr4, l, brk.span, format!("the break disjunct of law `{lpath}` follows from its hypotheses: the law holds of any specification, whatever `P` says"))
                    .note(NOTE)
                    .note("`auto` proves `requires ⇒ B(t̄)` on its own: a break predicate implied by the hypotheses is a closed truth disguised by arguments; write a break predicate that decides the assumption's break (e.g. `collision(..)` over the hash specification) on terms computed from the binders"),
            ),
            Ok((false, true)) => out.push(
                LawRuleRecord::new(LawRule::Lr4, l, brk.span, format!("the break disjunct of law `{lpath}` is dead: its guarantee follows from the hypotheses alone"))
                    .note(NOTE)
                    .note("`auto` proves `requires ⇒ P` without the break: the law does not rely on the assumption — drop `#[reduces_to]` and the break disjunct"),
            ),
            Ok(_) => {}
            Err(e) => out.push(
                LawRuleRecord::new(LawRule::Lr4, l, lit.span, format!("the vacuity of the extraction form of law `{lpath}` could not be checked: {}", e.msg))
                    .note("LR4 is a hard rule: a law it cannot check is reported, never passed (DESIGN.md §15.1)"),
            ),
        }
    }

    /// `e` (a `bool` or a proposition) as a proposition at the current depth.
    fn prop_of(&mut self, e: &'a Expr) -> R<Tm> {
        if e.ty == Ty::Prop {
            self.prop(e)
        } else {
            self.in_pure(|s| s.expr(e, &mut |s, v| Ok(s.holds(v.at(s.depth())))))
        }
    }

    /// Whether `auto` (default configuration) proves `target` (a term at the
    /// current depth) from the facts in scope within `budget` steps, with a
    /// proof the kernel checks. Diagnostic: nothing is recorded.
    fn bounded_attempt(&mut self, target: &Tm, budget: u64, sp: Span) -> bool {
        let Ok(tv) = self.eval(target) else { return false };
        let g = crate::prover::Goal { id: crate::prover::ObligationId(u32::MAX - 3), kind: crate::prover::ObligationKind::LawGoal, span: sp, ctx: self.f.scope.ctx.clone(), facts: self.f.scope.facts.clone(), target: tv.clone(), hints: vec![] };
        let mut prover = crate::auto::Auto::with_config(crate::auto::AutoConfig::default());
        let mut b = sandblaster_kernel::value::Budget { steps: budget };
        super::set_hidden_facts(self.f.scope.hidden.iter().copied().collect());
        let res = crate::prover::Prover::prove(&mut prover, &self.env, &g, &mut b);
        super::set_hidden_facts(Vec::new());
        match res {
            Ok(p) => {
                let p = super::recert::recertify(&self.env, &self.f.scope.ctx, &p);
                !super::tm::has_erased(target) && self.check_proof_in(&self.f.scope.ctx, &p, target, &tv, false).is_ok()
            }
            Err(_) => false,
        }
    }

    /// LR4, the form `P ∨ B(t̄)` of a `#[reduces_to]` law.
    fn lr_extraction_form(&mut self, l: ItemId, f: &FnDef, out: &mut Vec<LawRuleRecord>) {
        let krate = self.krate;
        let lpath = krate.item(l).path.to_string();
        let span = f.spec.reduces_to.map(|(_, s)| s).unwrap_or(krate.item(l).span);
        const FORM: &str = "a law tagged `#[reduces_to(a)]` concludes `P ∨ B(t̄)`: `B` a `bool`-valued spec function (the break predicate, e.g. `spec::sha256::collision`) and `t̄` spec-closed terms computed from the law's binders, so that when `P` fails the law computes the break itself (DESIGN.md §15.1 LR4, §15.13)";
        let Some(en) = &f.ensures else {
            out.push(LawRuleRecord::new(LawRule::Lr4, l, span, format!("law `{lpath}` is tagged `#[reduces_to]` but has no conclusion")).note(FORM));
            return;
        };
        let (mut hyps, mut disj) = (Vec::new(), Vec::new());
        conclusion_parts(&en.prop, &mut hyps, &mut disj);
        if disj.len() < 2 {
            out.push(LawRuleRecord::new(LawRule::Lr4, l, en.prop.span, format!("law `{lpath}` is tagged `#[reduces_to]` but its conclusion has no break disjunct")).note(FORM));
            return;
        }
        let brk = *disj.last().expect("two disjuncts");
        let b = peel(brk);
        let bad = |msg: String, sp: Span| LawRuleRecord::new(LawRule::Lr4, l, sp, msg).note(FORM);
        match &b.kind {
            ExprKind::Quant { quant: Quant::Exists, .. } => out.push(bad(format!("the break disjunct of law `{lpath}` is an `exists`: the mere existence of a break (say, a SHA-256 collision) is provable by pigeonhole, so the law would say nothing"), b.span)),
            ExprKind::Quant { .. } => out.push(bad(format!("the break disjunct of law `{lpath}` is a quantified proposition, not a computed break"), b.span)),
            ExprKind::Call { callee: Callee::Item(bid, _), args } => {
                let bf = krate.fn_def(*bid);
                let bpath = krate.item(*bid).path.to_string();
                match bf {
                    Some(g) if g.kind == FnKind::Spec && g.ret == Ty::Bool => {
                        for a in args {
                            if let Some(sp) = quant_or_prop(a) {
                                out.push(bad(format!("the break disjunct of law `{lpath}` has an `exists` or a proposition in the arguments of `{bpath}`: the break must be computed from the binders"), sp));
                                continue;
                            }
                            let mut refs = Vec::new();
                            item_refs(a, &mut refs);
                            for (x, sp) in refs {
                                let xi = krate.item(x);
                                let exec = match &xi.kind {
                                    ItemKind::Fn(xf) => xf.kind == FnKind::Exec,
                                    ItemKind::Const(_) => !xi.ghost,
                                    _ => false,
                                };
                                if exec {
                                    let established = self.def_global(x).is_some_and(|g| self.s1.established.contains(&g));
                                    if !established {
                                        out.push(bad(format!("the break terms of law `{lpath}` are not spec-closed: they use the exec item `{}`", xi.path), sp));
                                    }
                                } else if let Some(g) = self.def_global(x)
                                    && let Some(v) = self.closure_violation(&[mk::global(g)], &[])
                                {
                                    let vn = self.env.global_name(v).map(|n| n.to_string()).unwrap_or_default();
                                    out.push(bad(format!("the break terms of law `{lpath}` are not spec-closed: `{}` depends on the exec global `{vn}`", xi.path), sp));
                                }
                            }
                        }
                    }
                    Some(g) if g.kind == FnKind::Spec && g.ret == Ty::Prop => out.push(bad(format!("the break predicate `{bpath}` of law `{lpath}` is a proposition (`-> Prop`): it must be a `bool`-valued spec function, so the break is computed, not asserted"), b.span)),
                    _ => out.push(bad(format!("the break disjunct of law `{lpath}` calls `{bpath}`, which is not a `bool`-valued spec function"), b.span)),
                }
            }
            _ => out.push(bad(format!("the break disjunct of law `{lpath}` is not a call `B(t̄)` of a `bool`-valued spec function"), b.span)),
        }
    }

    /// LR5: every spec function against every exec function (the refiner
    /// is S1's check).
    fn lr_mirrors(&mut self, out: &mut Vec<LawRuleRecord>) {
        let krate = self.krate;
        if !krate.items.iter().any(|it| matches!(&it.kind, ItemKind::Fn(f) if f.kind == FnKind::Spec)) {
            return;
        }
        let mut canon = crate::surface::Canon::new(&self.env);
        let mut exec: HashMap<crate::surface::Hash, Vec<ItemId>> = HashMap::new();
        for it in &krate.items {
            let ItemKind::Fn(f) = &it.kind else { continue };
            if f.kind != FnKind::Exec || it.ghost {
                continue;
            }
            let Some(g) = self.def_global(it.id) else { continue };
            if let Some(k) = self.mirror_key(&mut canon, g) {
                exec.entry(k).or_default().push(it.id);
            }
        }
        for it in &krate.items {
            let ItemKind::Fn(f) = &it.kind else { continue };
            if f.kind != FnKind::Spec || f.ret == Ty::Prop || f.spec.assumption.is_some() {
                continue;
            }
            let Some(g) = self.def_global(it.id) else { continue };
            let Some(k) = self.mirror_key(&mut canon, g) else { continue };
            let Some(hits) = exec.get(&k) else { continue };
            for &e in hits {
                let ef = krate.fn_def(e).expect("exec fn");
                if ef.spec.refines.as_ref().is_some_and(|r| r.spec == it.id) {
                    continue;
                }
                let justified = f.spec.mirrors_impl.is_some() && f.spec.mirrors_of == Some(e);
                let independent = self.independent_evidence(it.id);
                if justified && independent {
                    continue;
                }
                let span = f.spec.mirrors_impl.as_ref().map(|j| j.span).unwrap_or(f.sig_span);
                let epath = krate.item(e).path.to_string();
                let mut r = LawRuleRecord::new(LawRule::Lr5, it.id, span, format!("spec function `{}` is a copy of the exec function `{epath}`", it.path))
                    .note_at(krate.item(e).span, format!("the exec function `{epath}`"))
                    .note("the mirrors check compares every spec function with every exec function: bodies as kernel terms after inlining non-recursive helpers, modulo view coercions, by their canonical hashes (DESIGN.md §15.1 LR5)");
                if !justified {
                    r = r.note(format!("if they legitimately coincide (a tiny function), say so with `#[mirrors_impl(of = {epath}, justification = \"..\")]` on the spec: a locked claim"));
                }
                if !independent {
                    r = r.note("and back the spec with an independent description: an `#[example]`, an independent vector file, or a law about it (DESIGN.md §15.7)");
                }
                out.push(r);
            }
        }
    }

    /// The canonical hash of a definition's body for LR5: proofs erased
    /// ([`erase_proofs`]), non-recursive helpers inlined, self-references
    /// replaced by a marker, view coercions stripped.
    fn mirror_key(&self, canon: &mut crate::surface::Canon<'_>, g: GlobalId) -> Option<crate::surface::Hash> {
        let body = erase_proofs(&self.env.global_body(g)?);
        let body = self.inline_helpers_prep(&body, &[g], 3, &erase_proofs);
        let marker: Tm = Rc::new(Term::Sort(sandblaster_kernel::term::Sort::Kind));
        let mut shapes = Shapes::new(&self.env);
        let norm = super::tm::map_post(&body, 0, &mut |n, _b| match &*n {
            Term::Global(h) if *h == g => Some(marker.clone()),
            _ => match shapes.coercion_operand(&n) {
                Some(x) => Some(x),
                None => Some(n),
            },
        })
        .unwrap_or(body);
        Some(canon.hash(&norm))
    }

    /// LR6 (a) echo and (b) resemblance.
    fn lr_echo_resemblance(&mut self, laws: &[ItemId], out: &mut Vec<LawRuleRecord>) {
        let krate: &'a Crate = self.krate;
        if laws.is_empty() {
            return;
        }
        let mut user: HashSet<GlobalId> = HashSet::new();
        let mut spec_nonrec: HashSet<GlobalId> = HashSet::new();
        for it in &krate.items {
            let ItemKind::Fn(f) = &it.kind else { continue };
            if !matches!(f.kind, FnKind::Exec | FnKind::Spec) {
                continue;
            }
            let Some(g) = self.def_global(it.id) else { continue };
            user.insert(g);
            if f.kind == FnKind::Spec && self.nonrec_transparent(g) {
                spec_nonrec.insert(g);
            }
        }
        // the statements (and the echo attempts, LR6 (a))
        let mut stmts: Vec<(ItemId, Tm)> = Vec::new();
        for &l in laws {
            let f = krate.fn_def(l).expect("law");
            let definitional = f.spec.definitional.is_some();
            let lit = krate.item(l);
            let lpath = lit.path.to_string();
            let (stmt, echo) = match self.law_statement_and_echo(l, f, !definitional, &user, &spec_nonrec) {
                Ok(x) => x,
                Err(why) => {
                    // never silently passed: a law the check cannot read is
                    // reported (its own elaboration error, if any, is a
                    // build error already)
                    if !definitional {
                        out.push(
                            LawRuleRecord::new(LawRule::Lr6Echo, l, lit.span, format!("the echo check could not be decided for law `{lpath}`: its statement did not elaborate again ({why})"))
                                .note("LR6 (a) is a hard rule: a law it cannot check is reported, never passed (DESIGN.md §15.1)"),
                        );
                    }
                    continue;
                }
            };
            match echo {
                Some(e) if e.proven => {
                    let how = if e.unfolded.is_empty() { "nothing needs unfolding: the law holds by evaluation and propositional reasoning alone".to_string() } else { format!("unfolded once: {}", e.unfolded.iter().map(|x| format!("`{x}`")).collect::<Vec<_>>().join(", ")) };
                    let what = if e.unfolded.is_empty() {
                        "the law holds of its statement's own evaluation, whatever the functions it names compute".to_string()
                    } else {
                        format!("the law is a consequence of the bodies of {} as written, checked by one unfolding each — it restates them instead of saying what they guarantee", e.unfolded.iter().map(|x| format!("`{x}`")).collect::<Vec<_>>().join(", "))
                    };
                    let unknown = if e.unknown.is_empty() { String::new() } else { format!(" (not unfolded, treated as unknown: {})", e.unknown.iter().map(|x| format!("`{x}`")).collect::<Vec<_>>().join(", ")) };
                    out.push(
                        LawRuleRecord::new(LawRule::Lr6Echo, l, lit.span, format!("law `{lpath}` restates its definitions: it follows by unfolding what it mentions once and propositional reasoning"))
                            .note(format!("{how}{unknown}"))
                            .note(format!("after the unfolding the law reads: {}", e.reads))
                            .note(format!("{what}; a law is read instead of the code, so state what the function guarantees in terms of `spec::` items written from the standard (DESIGN.md §15.1 LR6)"))
                            .note("the check has no arithmetic beyond evaluation, so a round trip through code without arithmetic (a tag byte, a copy) is an echo while one through shifts and masks is not: specify such a codec by its wire format — `#[refines(spec::encode)]` and `#[refines(spec::decode)]` with the format transcribed into `spec::` from the standard (each determined at once) — and keep the round trip as a `#[lemma]` in PROOF.rs")
                            .note("a law that is meant as a definition carries `#[definitional(reason = \"..\")]`: the spec sheet prints it under its own heading, never counts it as a guarantee, and it is no hypothesis of a determinacy section"),
                    );
                    // the resemblance warning would report the same law again
                    continue;
                }
                Some(e) if e.undecided.is_some() => {
                    out.push(
                        LawRuleRecord::new(LawRule::Lr6Echo, l, lit.span, format!("the echo check could not be decided for law `{lpath}`: {}", e.undecided.clone().unwrap_or_default()))
                            .note("LR6 (a) is a hard rule: a law it cannot check is reported, never passed (DESIGN.md §15.1)"),
                    );
                }
                _ => {}
            }
            if !definitional {
                stmts.push((l, stmt));
            }
        }
        // the exec bodies' subterms (LR6 (b))
        let mut shapes = Shapes::new(&self.env);
        let mut table: HashMap<u64, (ItemId, usize)> = HashMap::new();
        let exec_items: Vec<(ItemId, GlobalId)> = krate.items.iter().filter(|it| !it.ghost && matches!(&it.kind, ItemKind::Fn(f) if f.kind == FnKind::Exec)).filter_map(|it| self.def_global(it.id).map(|g| (it.id, g))).collect();
        let exec_names: Vec<(String, ItemId)> = exec_items.iter().map(|(i, _)| (krate.item(*i).path.to_string(), *i)).collect();
        let mut bodies: Vec<(ItemId, Tm)> = exec_items.iter().filter_map(|(i, g)| self.env.global_body(*g).map(|b| (*i, b))).collect();
        // loop helpers belong to their exec function
        for gi in 0..self.env.num_globals() {
            let h = GlobalId(gi);
            if self.env.global_kind(h) != Some(sandblaster_kernel::term::DefKind::LoopHelper) {
                continue;
            }
            let name = self.env.global_name(h).map(|n| n.to_string()).unwrap_or_default();
            if let Some((_, owner)) = exec_names.iter().find(|(p, _)| name.starts_with(&format!("{p}::loop")))
                && let Some(b) = self.env.global_body(h)
            {
                bodies.push((*owner, b));
            }
        }
        for (owner, b) in &bodies {
            let mut nodes = Vec::new();
            shapes.nodes(b, &mut nodes, &mut HashSet::new());
            for (h, n) in nodes {
                if n >= RESEMBLANCE_MIN_NODES {
                    table.entry(h).or_insert((*owner, n));
                }
            }
        }
        for (l, stmt) in stmts {
            let lit = krate.item(l);
            let lpath = lit.path.to_string();
            // U: the statement with its non-recursive spec functions unfolded
            let u = self.inline_only(&stmt, &spec_nonrec, 4);
            let mut nodes = Vec::new();
            shapes.nodes(&u, &mut nodes, &mut HashSet::new());
            let mut best: BTreeMap<ItemId, usize> = BTreeMap::new();
            for (h, n) in nodes {
                if n < RESEMBLANCE_MIN_NODES {
                    continue;
                }
                if let Some((e, _)) = table.get(&h) {
                    let b = best.entry(*e).or_insert(0);
                    *b = (*b).max(n);
                }
            }
            for (e, n) in best {
                let epath = krate.item(e).path.to_string();
                out.push(
                    LawRuleRecord::new(LawRule::Lr6Resemblance, l, lit.span, format!("law `{lpath}` resembles the implementation: a subterm of {n} kernel nodes of its statement also occurs in the body of `{epath}`"))
                        .note_at(krate.item(e).span, format!("the exec function `{epath}`"))
                        .note("a law that transcribes the code is true of whatever the code does: state the guarantee in terms of `spec::` items written from the standard (DESIGN.md §15.1 LR6 (b))"),
                );
            }
        }
    }

    /// Whether `g` is a transparent, non-recursive definition.
    fn nonrec_transparent(&self, g: GlobalId) -> bool {
        self.env.global_opaque(g) == Some(false) && self.env.global_body(g).is_some_and(|b| !super::tm::any_node(&b, &mut |n| matches!(n, Term::Global(x) if *x == g) || matches!(n, Term::Rec { .. })))
    }

    /// `t` with the applications of the definitions in `set` replaced by
    /// their instantiated bodies, `fuel` levels deep.
    fn inline_only(&self, t: &Tm, set: &HashSet<GlobalId>, fuel: u32) -> Tm {
        if fuel == 0 || set.is_empty() {
            return t.clone();
        }
        let mut changed = false;
        let out = super::tm::map_post(t, 0, &mut |node, _b| {
            let (head, args) = super::items::spine(&node);
            let Term::Global(h) = &*head else { return Some(node) };
            if !set.contains(h) {
                return Some(node);
            }
            let Some(ar) = self.env.global_arity(*h) else { return Some(node) };
            if args.len() != ar as usize {
                return Some(node);
            }
            let Some(body) = self.env.global_body(*h) else { return Some(node) };
            changed = true;
            Some(super::tm::subst_closed(&super::ensures::strip_lams(&body, ar), &args))
        })
        .unwrap_or_else(|| t.clone());
        if changed { self.inline_only(&out, set, fuel - 1) } else { out }
    }

    /// The statement of law `l` (its kernel type, elaborated again in a
    /// fresh context) and, with `echo`, the echo attempt (LR6 (a)) in that
    /// context. Nothing it elaborates is recorded (obligations, diagnostics
    /// and definitions are rolled back); `None` if the statement cannot be
    /// elaborated.
    fn law_statement_and_echo(&mut self, l: ItemId, f: &'a FnDef, echo: bool, user: &HashSet<GlobalId>, spec_nonrec: &HashSet<GlobalId>) -> Result<(Tm, Option<EchoOutcome>), String> {
        let it = self.krate.item(l);
        let (n_obl, n_diag, n_defs, n_laws) = (self.obligations.len(), self.diags.list.len(), self.defs.len(), self.laws.len());
        let saved = std::mem::replace(&mut self.f, FnState::new(format!("{}::law-rules", it.path), Some(l), &f.locals, it.span));
        self.f.fdef = Some(f);
        self.f.mode = Mode::Proof;
        let r = self.law_statement_in(f, echo, user, spec_nonrec, it.span);
        self.obligations.truncate(n_obl);
        self.diags.list.truncate(n_diag);
        self.defs.truncate(n_defs);
        self.laws.truncate(n_laws);
        self.f = saved;
        r.map_err(|e| e.msg)
    }

    fn law_statement_in(&mut self, f: &'a FnDef, echo: bool, user: &HashSet<GlobalId>, spec_nonrec: &HashSet<GlobalId>, span: Span) -> R<(Tm, Option<EchoOutcome>)> {
        let (mut binders, _pending) = self.fn_params(f, span)?;
        self.fn_requires(f, &mut binders, Rel::Rel)?;
        let goal = match &f.ensures {
            Some(en) => self.prop(&en.prop)?,
            None => mk::ind(self.p.unit, vec![]),
        };
        let ty = super::items::pi_tele(&binders, goal.clone());
        if !echo {
            return Ok((ty, None));
        }
        let undecided = |why: String| EchoOutcome { proven: false, unfolded: vec![], unknown: vec![], reads: String::new(), undecided: Some(why) };
        if self.f.failed {
            return Ok((ty, Some(undecided("a proof slot of the statement did not re-check when the statement was elaborated again".into()))));
        }
        // the functions U mentions: the statement's, and those of the
        // non-recursive spec functions it unfolds into (transitively)
        let mut keep = BTreeSet::new();
        globals_in(&ty, user, &mut keep);
        let mut work: Vec<GlobalId> = keep.iter().copied().collect();
        while let Some(g) = work.pop() {
            if !spec_nonrec.contains(&g) {
                continue;
            }
            let Some(b) = self.env.global_body(g) else { continue };
            let mut more = BTreeSet::new();
            globals_in(&b, user, &mut more);
            for h in more {
                if keep.insert(h) {
                    work.push(h);
                }
            }
        }
        // a recursive or opaque proposition has no defining equation: it
        // stays unknown (the view is still built, the echo still attempted)
        let keep: Vec<GlobalId> = keep.into_iter().filter(|g| self.unfolds_by_evaluation(*g) || self.defining_equation(*g).is_some()).collect();
        let deltas = keep.iter().filter(|g| !self.nonrec_transparent(**g)).count() as u32;
        let mut prover = crate::auto::Auto::with_config(echo_config(deltas + 2));
        // a view that cannot be built: the law is reported as undecided,
        // never passed (recursive or opaque propositions stay unknown in
        // the view, so this is not expected)
        let mut o = match self.echo_attempt(&goal, &keep, &mut prover, ECHO_BUDGET, span) {
            Ok(o) => o,
            Err(e) => return Ok((ty, Some(undecided(format!("the restricted view could not be built: {}", e.msg))))),
        };
        if o.proven {
            o.reads = self.unfolded_text(&goal, &keep, spec_nonrec);
        }
        Ok((ty, Some(o)))
    }

    /// The law in the current scope after the unfolding of the echo check,
    /// in surface syntax: its hypotheses (the facts in scope) and `goal`
    /// with the non-recursive spec functions unfolded, then every other
    /// function of `keep` unfolded once. Bounded.
    fn unfolded_text(&self, goal: &Tm, keep: &[GlobalId], spec_nonrec: &HashSet<GlobalId>) -> String {
        let once: HashSet<GlobalId> = keep.iter().copied().filter(|g| !spec_nonrec.contains(g)).collect();
        let unfold = |t: &Tm| self.inline_only(&self.inline_only(t, spec_nonrec, 4), &once, 1);
        let d = self.depth();
        let mut parts = Vec::new();
        let mut seen = HashSet::new();
        for fr in &self.f.scope.facts {
            let l = fr.lvl.0;
            if !seen.insert(l) || !matches!(fr.origin, crate::prover::FactOrigin::LemmaHyp) {
                continue;
            }
            if let Some(t) = self.f.scope.fact_tys.get(&l) {
                parts.push(self.surface(&unfold(&sandblaster_kernel::util::shift(t, (d - l) as i64))));
            }
        }
        let g = self.surface(&unfold(goal));
        let s = if parts.is_empty() { g } else { format!("{} ⊢ {g}", parts.join("; ")) };
        if s.chars().count() > 900 { format!("{}…", s.chars().take(900).collect::<String>()) } else { s }
    }
}

/// LR4: every conjunct of a hypothesis and every disjunct of a conclusion
/// mentions a binder (of a law, `is_law`, or of a contract).
fn lr_closed(krate: &Crate, id: ItemId, f: &FnDef, is_law: bool, out: &mut Vec<LawRuleRecord>) {
    let path = krate.item(id).path.to_string();
    let bs = binders(f, !is_law);
    let what = if is_law { format!("law `{path}`") } else { format!("the contract of `{path}`") };
    let note = "a closed subformula is either provable (then the statement is vacuous) or refutable (then it is dead weight); a closed law is an `#[example]` (DESIGN.md §15.1 LR4)";
    let mut hyps = Vec::new();
    for r in &f.requires {
        conjuncts(r, &mut hyps);
    }
    let mut disj = Vec::new();
    if let Some(en) = &f.ensures {
        conclusion_parts(&en.prop, &mut hyps, &mut disj);
    }
    for h in hyps {
        // a contract's literal `true` is a placeholder (a function annotation
        // that carries `#[ghost]` parameters, a trusted extern's `ensures`),
        // not a claim
        if !is_law && h.is_true_lit() {
            continue;
        }
        if !mentions_local(h, &bs) {
            out.push(LawRuleRecord::new(LawRule::Lr4, id, h.span, format!("a hypothesis of {what} mentions none of its binders")).note(note));
        }
    }
    if f.ensures.is_some() && !(disj.len() == 1 && disj[0].is_true_lit() && !is_law) {
        for d in disj {
            if !mentions_local(d, &bs) {
                out.push(LawRuleRecord::new(LawRule::Lr4, id, d.span, format!("a disjunct of the conclusion of {what} mentions none of its binders")).note(note));
            }
        }
    }
}

/// LR9: a doc sentence stating the guarantee; `#[reduces_to]` names an
/// `#[assumption]`.
fn lr_documented(krate: &Crate, l: ItemId, f: &FnDef, out: &mut Vec<LawRuleRecord>) {
    let it = krate.item(l);
    let path = it.path.to_string();
    const NOTE: &str = "every law has a doc comment whose first sentence states, in words, the guarantee a reviewer reads instead of the code; `sandblaster spec` prints it in the table *law | guarantee | assumes* (DESIGN.md §15.1 LR9)";
    match guarantee_sentence(&it.docs) {
        None => out.push(LawRuleRecord::new(LawRule::Lr9, l, f.sig_span, format!("law `{path}` has no doc comment stating its guarantee")).note(NOTE)),
        Some(s) if !states_guarantee(&s, &it.name) => out.push(LawRuleRecord::new(LawRule::Lr9, l, f.sig_span, format!("the first sentence of the doc comment of law `{path}` does not state a guarantee in words: \"{s}\"")).note(format!("{GUARANTEE_RULE} (the sentence ends at the first `.`, `!` or `?` followed by a space, outside code spans and abbreviations such as `i.e.`)")).note(NOTE)),
        Some(_) => {}
    }
    if let Some((a, sp)) = f.spec.reduces_to
        && krate.fn_def(a).is_none_or(|g| g.spec.assumption.is_none())
    {
        out.push(
            LawRuleRecord::new(LawRule::Lr9, l, sp, format!("`#[reduces_to]` on law `{path}` names `{}`, which is not an `#[assumption]`", krate.item(a).path))
                .note("an assumption is a spec function `#[assumption(class = computational | statistical | environmental, cite = \"..\")] fn name() {}`; the spec sheet lists it next to every law that relies on it (DESIGN.md §15.1 LR9, §15.13)"),
        );
    }
}

/// LR7: a law proven from other laws alone.
fn lr_corollary(krate: &Crate, l: ItemId, f: &FnDef, out: &mut Vec<LawRuleRecord>) {
    if f.spec.corollary.is_some() || f.spec.definitional.is_some() {
        return;
    }
    let Some((laws, other)) = corollary_of(krate, l, f) else { return };
    if other || laws.is_empty() {
        return;
    }
    let path = krate.item(l).path.to_string();
    let from = laws.iter().map(|x| format!("`{}`", krate.item(*x).path)).collect::<Vec<_>>().join(", ");
    out.push(
        LawRuleRecord::new(LawRule::Lr7, l, krate.item(l).span, format!("law `{path}` follows from the laws {from} alone"))
            .note("its proof applies other laws with propositional steps only: no unfolding, case analysis, induction or other lemma (DESIGN.md §15.1 LR7)")
            .note("demote it to a `#[lemma]`, or mark it `#[corollary]` so the spec sheet prints it under the laws it follows from"),
    );
}

/// LR10: a `bool`-valued exported function (or its refinement target)
/// occurs in the laws only in hypotheses or only in conclusions.
fn lr_directions(krate: &Crate, laws: &[ItemId], exported: &BTreeSet<ItemId>, out: &mut Vec<LawRuleRecord>) {
    for &f in exported {
        let fd = krate.fn_def(f).expect("exported fn");
        if fd.ret != Ty::Bool {
            continue;
        }
        let mut targets: HashSet<ItemId> = HashSet::from([f]);
        if let Some(r) = &fd.spec.refines {
            targets.insert(r.spec);
        }
        let mut hyp_laws = Vec::new();
        let mut concl_laws = Vec::new();
        for &l in laws {
            let lf = krate.fn_def(l).expect("law");
            let mut c = (0usize, 0usize);
            for r in &lf.requires {
                polarity(r, Pol::Neg, &targets, &mut c);
            }
            if let Some(en) = &lf.ensures {
                polarity(&en.prop, Pol::Pos, &targets, &mut c);
            }
            if c.0 > 0 {
                hyp_laws.push(krate.item(l).path.to_string());
            }
            if c.1 > 0 {
                concl_laws.push(krate.item(l).path.to_string());
            }
        }
        if hyp_laws.is_empty() == concl_laws.is_empty() {
            continue;
        }
        let fpath = krate.item(f).path.to_string();
        let also = fd.spec.refines.as_ref().map(|r| format!(" (or its refinement target `{}`)", krate.item(r.spec).path)).unwrap_or_default();
        let (msg, which) = if concl_laws.is_empty() {
            (format!("the laws mention `{fpath}`{also} only in hypotheses: nothing states when it is true"), &hyp_laws)
        } else {
            (format!("the laws mention `{fpath}`{also} only in conclusions: nothing states when it is false"), &concl_laws)
        };
        out.push(
            LawRuleRecord::new(LawRule::Lr10, f, fd.sig_span, msg)
                .note(format!("laws: {}", which.iter().map(|p| format!("`{p}`")).collect::<Vec<_>>().join(", ")))
                .note("a verdict needs both directions: \"accepted inputs are honest\" alone holds of a function that returns `false` on every input, \"honest inputs are accepted\" alone of one that returns `true` (DESIGN.md §15.1 LR10)"),
        );
    }
}

/// A body's computational content for LR5's mirror comparison: the proof
/// arguments of primitives and recursive calls, irrelevant applications and
/// `let` values, arithmetic certificates and transports (their value kept)
/// erased. Two functions that compute the same way hash equal whatever their
/// proofs; and a body's proof terms, which can be far larger than its code,
/// are not walked once per binder depth (LR5 inlines helpers).
fn erase_proofs(t: &Tm) -> Tm {
    // post-order (children first, memoized per node and binder depth): one
    // walk of the body, as LR5's own normalization makes
    super::tm::map_post(t, 0, &mut |x, _| {
        Some(match &*x {
            Term::Prim { op, args, proofs } if !proofs.is_empty() => Rc::new(Term::Prim { op: *op, args: args.clone(), proofs: vec![] }),
            Term::Rec { args, proof: Some(_) } => Rc::new(Term::Rec { args: args.clone(), proof: None }),
            Term::App { rel: Rel::Irr, fun, .. } => fun.clone(),
            Term::Let { name, rel: Rel::Irr, body, .. } => Rc::new(Term::Let { name: name.clone(), rel: Rel::Irr, ty: Rc::new(Term::Erased), val: Rc::new(Term::Erased), body: body.clone() }),
            Term::Linarith { .. } => Rc::new(Term::Erased),
            Term::Transport { val, .. } => val.clone(),
            _ => x,
        })
    })
    .unwrap_or_else(|| t.clone())
}
