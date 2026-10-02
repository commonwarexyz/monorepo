//! Diagnostics (DESIGN.md §10.4).
//!
//! A [`Diagnostic`] has a primary [`Span`], a [`DiagKind`] (a stable,
//! machine-checkable category; tests match on it), a message, optional notes
//! (each with an optional span) and an optional pretty-printed goal (used by
//! later phases for unproven obligations).
//!
//! Rendering follows `file:line:col: error[kind]: message`, followed by a
//! source snippet with a caret line and the notes:
//!
//! ```text
//! src/a.rs:3:17: error[literal]: unsuffixed literal in the operand of `as`
//!   |
//! 3 |     let y = (1 << k) as u64;
//!   |              ^
//!   = note: rustc would type this literal as `i32`; write `1u64`
//! ```

use std::fmt::Write as _;

use crate::span::{SourceMap, Span};

/// Severity of a diagnostic.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Severity {
    Error,
    Warning,
}

/// Stable diagnostic categories. The rendered code is [`DiagKind::code`].
///
/// Each subset rule of DESIGN.md §3 has its own kind so tests can check that
/// the *right* rule fired.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum DiagKind {
    /// `syn` could not parse a file or a `proof!`/attribute payload.
    Parse,
    /// Module loading (missing files, `#[path]` misuse, cycles).
    Load,
    /// Name resolution failures, ambiguities, duplicate definitions.
    Resolve,
    /// Privacy violations (rustc would reject).
    Privacy,
    /// Surface type errors.
    Type,
    /// Literal typing: unannotated literals, `as` operand / shift RHS rule,
    /// out-of-range literals (§3.6).
    Literal,
    /// A syntactic construct outside the subset without a more specific kind.
    Unsupported,
    /// Traits, trait impls, `dyn`, `impl Trait` (§3.1).
    Trait,
    /// `static` items (§3.1).
    Static,
    /// Closures and fn pointers (§3.1).
    Closure,
    /// Floating point types and literals (§3.1).
    Float,
    /// Signed integer types and literals (§3.1; i32 immediates excepted).
    Signed,
    /// `u128`/`i128` (§3.1).
    Wide,
    /// Raw pointers (§3.1).
    RawPointer,
    /// `&mut` (§3.1; `copy_from_slice` statement excepted).
    MutRef,
    /// `loop`, `break`, `continue`, labels (§3.1).
    Loop,
    /// `return`/`?` inside loops (§3.1, §3.3).
    ControlInLoop,
    /// Macros other than `proof!` and `unreachable!()` (§3.1).
    Macro,
    /// Attribute not allowed (including the `#[allow]` whitelist and
    /// `#[inline(always)]` with `#[target_feature]`) (§3.1).
    Attribute,
    /// Missing `#![forbid(unsafe_code)]` at the DSL root (§3.1).
    ForbidUnsafe,
    /// Slices of zero-sized element types (§3.2).
    ZstSlice,
    /// A `pub` function with `requires` reachable from the DSL root (§3.1).
    Boundary,
    /// An identifier pattern naming a const, unit struct or unit variant (§3.3).
    IdentPattern,
    /// Mutual recursion, unbounded non-tail recursion, bad `max` (§3.7).
    Recursion,
    /// Target features / intrinsic availability (§9.3).
    Feature,
    /// Ghost/exec separation (exec code referring to ghost items, ghost
    /// annotations on non-ghost items).
    Ghost,
    /// Non-exhaustive or refutable patterns.
    Exhaustive,
    /// Malformed contracts (`requires`, `ensures`, `decreases`, `implements`).
    Contract,
    /// Malformed proof scripts (§4.4).
    Script,
    /// Laws and proofs (§4.5): missing or mismatched `#[proof]`.
    Law,
    /// Build integration (`src/lib.rs` shape, environment).
    Build,
    /// Refusal to emit phase-1 code without the unverified opt-in.
    Unverified,
    /// An unproven proof obligation or open law (phase 2 elaboration;
    /// added by the elaborator agent, additive).
    Obligation,
    /// A construct the elaborator cannot give a core meaning to yet, or a
    /// definition the kernel rejected (phase 2; additive).
    Elab,
    /// A spec item that depends on an unestablished exec function or
    /// constant (DESIGN.md §15.1; §15 S1, additive).
    SpecDependsOnImpl,
    /// A spec function that copies the exec function refining it without
    /// `#[mirrors_impl]` and independent evidence (§15.1; S1, additive).
    SpecMirrorsImpl,
    /// A false, undecided or malformed `#[example]` / vector record (§15.7;
    /// S1, additive).
    Example,
    /// A fuel-bounded spec function without a proven `#[fuel_sufficient]`
    /// lemma (§15.1; S1, additive).
    FuelSufficient,
    /// `SPEC.lock` is missing, malformed or differs from the computed
    /// specification surface (§15.6; S1 agent D, additive; the lock gate
    /// of the crate path, §15.8).
    SpecLock,
    /// A `#[refines]` lemma that did not prove (§15.10 `refines-unproven`):
    /// one error per lemma, its unproven branches as notes in surface
    /// syntax, and a suggestion chosen by what blocked them (additive).
    RefinesUnproven,
    /// A type invariant that is not a proposition the kernel accepts, is
    /// circular, or a type with an invariant, representation relation or
    /// non-identity view with a non-private field (§15.3; S2, additive).
    Invariant,
    /// A non-identity view of a public, non-`Abstract` type that is not
    /// proven injective (`view_inj_T`, §15.2, §15.3; S2, additive).
    ViewInjective,
    /// A computed section that is not well founded or cannot be stated, or
    /// a misused `#[section(with = ..)]` (§15.5; S3, additive).
    Section,
    /// An unproven `complete_p(R)` (a function not determined by its
    /// specification), or a failing `#[proof(complete = ..)]` (§15.5; S3,
    /// additive).
    Completeness,
    /// A resource safety net (the wall-clock deadline or a memory limit)
    /// tripped: a failure of the build, never a proof result (§15.8; S3,
    /// additive).
    Resource,
    /// §15.1 LR1: a law mentions an internal exec function or an exec
    /// constant, directly or through a spec item (S3, additive).
    LawMentionsInternal,
    /// §15.1 LR3 (warning): a law mentions an exported function that
    /// carries `#[refines(s)]` instead of `s` (S3, additive).
    LawBypassesRefinement,
    /// §15.1 LR4: a closed disjunct of a conclusion or conjunct of a
    /// hypothesis, or a `#[reduces_to]` law not in extraction form (S3,
    /// additive).
    VacuousReduction,
    /// §15.1 LR6 (a): a law proven by unfolding what it mentions once and
    /// propositional reasoning (S3, additive).
    LawRestatesImpl,
    /// §15.1 LR6 (b) (warning): a law with a large subterm of an exec body
    /// (S3, additive).
    LawResemblesImpl,
    /// §15.1 LR7 (warning): a law proven from other laws alone (S3,
    /// additive).
    LawCorollary,
    /// §15.1 LR9: a law without a doc sentence stating its guarantee, or a
    /// `#[reduces_to]` that names no `#[assumption]` (S3, additive).
    LawUndocumented,
    /// §15.1 LR10 (warning): the laws mention a `bool`-valued exported
    /// function (or its refinement target) in one direction only (S3,
    /// additive).
    OneDirectionalLaws,
    /// §15.9/§15.10 `spec-incomplete`: a definite counterexample to an
    /// unproven `complete_p(R)` — a mutant that satisfies the whole
    /// specification yet differs on an input (the diff, the input and both
    /// outputs; S4, additive).
    SpecIncomplete,
    /// §15.7: a spec mutant that no example and no law kills, with an
    /// input where it differs from the specification (S4, additive).
    SpecMutantSurvived,
    /// §15.1 LR8 (warning): a law that kills none of the spec mutants of
    /// the spec functions it uses (S4, additive).
    LawInsensitive,
    /// The counterexample engine did not finish (caps, memory, mutants
    /// killed only by budget): its verdict is incomplete, never a pass
    /// (§15.9; S4, additive).
    MutationIncomplete,
    /// A lifted function read from rustc's MIR without a kernel-checked
    /// theorem relating the literal reading of its MIR to its structured
    /// reading (`docs/checked-structuring.md`, amendment (e); additive).
    MirTheorem,
}

impl DiagKind {
    /// The short code printed inside `error[..]`.
    pub fn code(self) -> &'static str {
        use DiagKind::*;
        match self {
            Parse => "parse",
            Load => "load",
            Resolve => "resolve",
            Privacy => "privacy",
            Type => "type",
            Literal => "literal",
            Unsupported => "unsupported",
            Trait => "trait",
            Static => "static",
            Closure => "closure",
            Float => "float",
            Signed => "signed",
            Wide => "wide-int",
            RawPointer => "raw-pointer",
            MutRef => "mut-ref",
            Loop => "loop",
            ControlInLoop => "control-in-loop",
            Macro => "macro",
            Attribute => "attribute",
            ForbidUnsafe => "forbid-unsafe",
            ZstSlice => "zst-slice",
            Boundary => "boundary",
            IdentPattern => "ident-pattern",
            Recursion => "recursion",
            Feature => "feature",
            Ghost => "ghost",
            Exhaustive => "exhaustive",
            Contract => "contract",
            Script => "script",
            Law => "law",
            Build => "build",
            Unverified => "unverified",
            Obligation => "obligation",
            Elab => "elab",
            SpecDependsOnImpl => "spec-depends-on-impl",
            SpecMirrorsImpl => "spec-mirrors-impl",
            Example => "example",
            FuelSufficient => "fuel-sufficient",
            SpecLock => "spec-lock",
            RefinesUnproven => "refines-unproven",
            Invariant => "invariant",
            ViewInjective => "view-injective",
            Section => "section",
            Completeness => "completeness",
            Resource => "resource",
            LawMentionsInternal => "law-mentions-internal",
            LawBypassesRefinement => "law-bypasses-refinement",
            VacuousReduction => "vacuous-reduction",
            LawRestatesImpl => "law-restates-impl",
            LawResemblesImpl => "law-resembles-impl",
            LawCorollary => "law-corollary",
            LawUndocumented => "law-undocumented",
            OneDirectionalLaws => "one-directional-laws",
            SpecIncomplete => "spec-incomplete",
            SpecMutantSurvived => "spec-mutant-survived",
            LawInsensitive => "law-insensitive",
            MutationIncomplete => "mutation-incomplete",
            MirTheorem => "mir-theorem",
        }
    }
}

/// One diagnostic.
#[derive(Clone, Debug)]
pub struct Diagnostic {
    pub severity: Severity,
    pub span: Span,
    pub kind: DiagKind,
    pub msg: String,
    /// Additional notes; a note with a span prints its location.
    pub notes: Vec<(Option<Span>, String)>,
    /// Pretty-printed goal and facts (unproven obligations, `show()`).
    pub goal: Option<String>,
}

impl Diagnostic {
    pub fn error(kind: DiagKind, span: Span, msg: impl Into<String>) -> Diagnostic {
        Diagnostic { severity: Severity::Error, span, kind, msg: msg.into(), notes: vec![], goal: None }
    }

    pub fn warning(kind: DiagKind, span: Span, msg: impl Into<String>) -> Diagnostic {
        Diagnostic { severity: Severity::Warning, span, kind, msg: msg.into(), notes: vec![], goal: None }
    }

    /// Adds a note without a location.
    pub fn note(mut self, msg: impl Into<String>) -> Diagnostic {
        self.notes.push((None, msg.into()));
        self
    }

    /// Adds a note pointing at another location.
    pub fn note_at(mut self, span: Span, msg: impl Into<String>) -> Diagnostic {
        self.notes.push((Some(span), msg.into()));
        self
    }

    pub fn is_error(&self) -> bool {
        self.severity == Severity::Error
    }

    /// Renders the diagnostic with a source snippet.
    pub fn render(&self, sm: &SourceMap) -> String {
        let mut out = String::new();
        let sev = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        let loc = location(sm, self.span);
        let _ = writeln!(out, "{loc}{sev}[{}]: {}", self.kind.code(), self.msg);
        snippet(&mut out, sm, self.span);
        for (span, note) in &self.notes {
            match span {
                Some(s) if !s.is_dummy() => {
                    let _ = writeln!(out, "  = note: {}{note}", location(sm, *s));
                }
                _ => {
                    let _ = writeln!(out, "  = note: {note}");
                }
            }
        }
        if let Some(goal) = &self.goal {
            for line in goal.lines() {
                let _ = writeln!(out, "  | {line}");
            }
        }
        out
    }
}

fn location(sm: &SourceMap, span: Span) -> String {
    if span.is_dummy() {
        return String::new();
    }
    format!("{}:{}:{}: ", sm.path(span.file).display(), span.lo.0, span.lo.1 + 1)
}

fn snippet(out: &mut String, sm: &SourceMap, span: Span) {
    if span.is_dummy() {
        return;
    }
    let Some(file) = sm.get(span.file) else { return };
    let Some(line) = file.line(span.lo.0) else { return };
    let num = span.lo.0.to_string();
    let pad = " ".repeat(num.len());
    let _ = writeln!(out, "{pad} |");
    let _ = writeln!(out, "{num} | {line}");
    let start = span.lo.1 as usize;
    let len = if span.hi.0 == span.lo.0 { (span.hi.1 as usize).saturating_sub(start).max(1) } else { line.chars().count().saturating_sub(start).max(1) };
    let _ = writeln!(out, "{pad} | {}{}", " ".repeat(start), "^".repeat(len));
}

/// A sink for diagnostics.
#[derive(Clone, Debug, Default)]
pub struct Diagnostics {
    pub list: Vec<Diagnostic>,
}

impl Diagnostics {
    pub fn new() -> Diagnostics {
        Diagnostics::default()
    }

    pub fn push(&mut self, d: Diagnostic) {
        self.list.push(d);
    }

    /// Shorthand for pushing an error.
    pub fn error(&mut self, kind: DiagKind, span: Span, msg: impl Into<String>) {
        self.push(Diagnostic::error(kind, span, msg));
    }

    pub fn has_errors(&self) -> bool {
        self.list.iter().any(Diagnostic::is_error)
    }

    pub fn error_count(&self) -> usize {
        self.list.iter().filter(|d| d.is_error()).count()
    }

    /// Renders every diagnostic, errors and warnings in emission order.
    pub fn render(&self, sm: &SourceMap) -> String {
        self.list.iter().map(|d| d.render(sm)).collect::<Vec<_>>().join("\n")
    }

    pub fn extend(&mut self, other: Diagnostics) {
        self.list.extend(other.list);
    }
}
