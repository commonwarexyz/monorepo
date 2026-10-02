//! The specification surface (DESIGN.md §15.6; stage **S1**, agent D):
//! exactly what a reviewer must read to trust the crate, enumerated from a
//! verified elaboration, each item with its statement, its dependencies and
//! its Merkle hash — the input of `SPEC.lock` ([`crate::lock`]) and of the
//! spec sheet (`sandblaster spec`).
//!
//! # The items ([`SurfaceKind`])
//!
//! | kind | key | statement (kernel) |
//! | --- | --- | --- |
//! | spec fn | `spec-fn:path` | its type and body (a spec means its body) |
//! | spec constant | `spec-const:path` | type and value |
//! | spec type | `spec-type:path` | the inductive declaration (a ghost type a statement mentions) |
//! | view / representation relation | `view:T`, `represents:S` | `T::view` / `S::represents` (type and body) |
//! | invariant (evidence types included) | `invariant:S` | the definition of each conjunct `S::invariant#k` (type and body; an `Irr` constructor field of `S`, S2) and the spec functions the invariant calls; an evidence type (a certified property as the invariant, §15.3) has the same key, so rewriting the invariant with or without a spec function changes its statement, never its key (`evidence-type:` is reserved) |
//! | law | `law:path` | the proven statement (its type; never its proof) |
//! | fuel sufficiency | `fuel-sufficient:path` | the statement of a `#[fuel_sufficient]` lemma (the domain on which a fuel-bounded spec is exact) |
//! | contract | `contract:path` | the function's type (parameters, `requires`, result) and its `f::ensures` / `f::refines` statements — of every exec function a surface statement mentions, and of every `#[refines]` function |
//! | boundary signature | `boundary-fn:path` | the same, for a `pub` function reachable from the root |
//! | boundary type | `boundary-type:path` | the inductive declaration, shape, field visibilities and derives |
//! | type | `type:path` | a non-boundary exec type a statement mentions |
//! | constant | `constant:path` | an exec constant a statement mentions, or a boundary constant: type and value |
//! | trusted extern | `trusted-extern:path` | the signature and the justification (§13; S5) |
//! | mirrors | `mirrors-impl:path` | the justification of `#[mirrors_impl]` |
//! | target model | `target-model:arch:name` | the model's source and core hashes and its hardware evidence (record and verdict) |
//! | example | `example:path#k` | the checked closed `bool` term |
//! | vector file | `vector-file:path#j` | path, format, provenance and content hash |
//! | section | `section:p` | a computed section (`R`, `P(R)`, `Deps(R)`, the `complete_p` outcomes; none until S3) |
//!
//! Exec function *bodies* are never part of the surface: an implementation
//! change that leaves every statement alone changes no hash (§15.6).
//!
//! # What is locked: the review surface
//!
//! [`compute`] enumerates every item above (the gates and the spec sheet's
//! internals need them) but returns, in [`Surface::items`], only the
//! **review surface** — what a human must read to trust the crate — and
//! lists the rest by key in [`Surface::internal`]. `SPEC.lock` holds
//! exactly [`Surface::items`]. The rule ([`review_surface`]) is:
//!
//! 1. **Roots**: every law; every boundary signature, boundary type and
//!    boundary constant; every `#[refines]` contract (a functional spec
//!    stated as a type); every trusted extern and target model (trusted
//!    items); every section (what the laws determine, §15.5); every vector
//!    file (external known answers, with their provenance); every
//!    `#[assumption]` spec function (an explicit hypothesis, §15.13).
//! 2. **Vocabulary**: the closure of the roots under statement
//!    dependencies (`Refs₁` and the explicit dependencies: the `dep` and
//!    `dep-cycle` lines) — the spec functions, spec constants, spec types,
//!    views, representation relations, contracts, types and constants the
//!    statements mention. A type's invariant is in the same strongly
//!    connected component as the type, so the invariant of every type on
//!    the surface is on it.
//! 3. **Validation of the vocabulary**: the `#[example]`s, vector files and
//!    `#[mirrors_impl]` of a spec function, spec constant or function on
//!    the surface, and every `#[fuel_sufficient]` lemma about a spec
//!    function on it — closed again under dependencies, to a fixpoint.
//!
//! Everything else is a **proof internal** and never locked: helper spec
//! functions that only proofs use and their examples, invariants (e.g. a
//! `#[lift_attach]` invariant) of types no statement mentions, contracts of
//! functions no statement mentions, lemmas and proofs. So a proof refactor
//! — renaming, adding or deleting a helper spec function or its examples,
//! attaching an invariant to an internal type, rewriting a lemma — does not
//! change the lock, while a change of any law, of the vocabulary it uses, of
//! an example of that vocabulary or of a boundary signature does. The kept
//! set is closed under dependencies, so filtering changes no kept item's
//! hash. Proof internals are still checked by the other gates (spec
//! closure, examples and coverage): they are left out of the lock, not out
//! of the build. Spec mutation mutates the review surface only
//! (`crate::mutate::review_scope`; DESIGN.md §15.9): no locked statement
//! depends on a proof internal's definition. The rule is deterministic: it reads only the
//! computed items, the boundary and the HIR's `#[refines]`/`#[assumption]`.
//! (Behavior snapshots and the unconstrained-behavior report, when they
//! exist, are roots too.)
//!
//! # The hash (§15.6)
//!
//! `H(i) = hash(kind, key, canon(stmt), src(stmt), ⟨(name g, Hdep g) | g ∈ Refs₁(stmt)⟩)`
//! (the key is the kind and the stable path; [`item_local`], [`item_l`]):
//!
//! * `canon` ([`Canon`]) is a hash of the kernel statement: de Bruijn
//!   indices (the kernel's own), binder names dropped, every irrelevant
//!   subterm (proofs; the kernel's relevance table, AUDIT.md §19) replaced
//!   by `•`, globals and inductives named by their stable path, memoized by
//!   `Rc` sharing so a shared DAG is hashed in linear time;
//! * `src` is the item's source text (whitespace collapsed; the signature,
//!   `requires`, `ensures` and `#[refines]` of a contract — never its body
//!   — and the claim of a law — never its proof);
//! * `Refs₁` are the globals and inductives in relevant positions of the
//!   statement. `Hdep(g)` is `H(g)` for a surface item (an exec function a
//!   statement mentions *is* one: its contract; an established function's
//!   contract is its spec surface), the file hash for prelude, ghost-library,
//!   elaboration-semantics and target-model globals, and an **error** for an
//!   exec function or loop helper that a *value* statement (a spec fn, spec
//!   constant, view, representation relation, invariant) reaches without it
//!   being established (spec closure, §15.1) — [`Surface::errors`].
//!
//! Mutually dependent items (a contract whose `ensures` mentions another
//! function whose contract mentions the first) are hashed per strongly
//! connected component: every member's hash covers every member's local
//! content, so a change of one changes all.
//!
//! This module is untrusted: `SPEC.lock` is a review aid and a change
//! detector; the kernel checks every statement it hashes.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::rc::Rc;

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{DefKind, GlobalId, IndId, Lvl, Rel, Term, Tm};
use sandblaster_kernel::value::{Budget, EnvEntry, Head, Neutral, VEnv, Value};

use crate::deelab::{self, DeElab};
use crate::elab::Output;
use crate::hir::*;
use crate::span::{SourceMap, Span};

/// A SHA-256 hash.
pub type Hash = [u8; 32];

/// SHA-256 (the targets crate's FIPS 180-4 reference implementation).
pub fn sha256(b: &[u8]) -> Hash {
    sandblaster_targets::fips::sha256(b)
}

/// Lower-case hex.
pub fn hex(h: &[u8]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parses 64 hex digits.
pub fn parse_hex(s: &str) -> Option<Hash> {
    let s = s.trim();
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut h = [0u8; 32];
    for (i, x) in h.iter_mut().enumerate() {
        *x = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(h)
}

/// An incremental length-prefixed encoder (every field is framed, so no two
/// field sequences share an encoding).
#[derive(Default)]
struct Enc(Vec<u8>);

impl Enc {
    fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(&(b.len() as u64).to_le_bytes());
        self.0.extend_from_slice(b);
        self
    }
    fn s(&mut self, s: &str) -> &mut Self {
        self.bytes(s.as_bytes())
    }
    fn h(&mut self, h: &Hash) -> &mut Self {
        self.bytes(h)
    }
    fn done(&self) -> Hash {
        sha256(&self.0)
    }
}

/// The kind of a surface item (one `SPEC.lock` entry each).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub enum SurfaceKind {
    SpecFn,
    SpecConst,
    /// A type declared in ghost code (a `#[spec]` module) that a statement
    /// mentions.
    SpecType,
    View,
    Represents,
    Invariant,
    /// An invariant type whose invariant is a certified property: it calls
    /// a spec function (S2).
    EvidenceType,
    Law,
    /// A `#[fuel_sufficient]` lemma: its statement is the domain claim of a
    /// fuel-bounded spec function (§15.1).
    FuelSufficient,
    /// The contract (`requires`/`ensures`/`#[refines]`) of a function
    /// reachable from the surface, or of a `#[refines]` function.
    Contract,
    BoundarySignature,
    BoundaryType,
    /// A non-boundary exec type a statement mentions (its definition is part
    /// of the statement's meaning).
    Type,
    /// An exec constant a statement mentions, or a boundary constant.
    Constant,
    TrustedExtern,
    MirrorsImpl,
    TargetModel,
    Example,
    VectorFile,
    /// A computed section and its `complete_p` statements (S3).
    Section,
}

impl SurfaceKind {
    pub const ALL: [SurfaceKind; 20] = [
        SurfaceKind::SpecFn,
        SurfaceKind::SpecConst,
        SurfaceKind::SpecType,
        SurfaceKind::View,
        SurfaceKind::Represents,
        SurfaceKind::Invariant,
        SurfaceKind::EvidenceType,
        SurfaceKind::Law,
        SurfaceKind::FuelSufficient,
        SurfaceKind::Contract,
        SurfaceKind::BoundarySignature,
        SurfaceKind::BoundaryType,
        SurfaceKind::Type,
        SurfaceKind::Constant,
        SurfaceKind::TrustedExtern,
        SurfaceKind::MirrorsImpl,
        SurfaceKind::TargetModel,
        SurfaceKind::Example,
        SurfaceKind::VectorFile,
        SurfaceKind::Section,
    ];

    /// The key prefix (and the lock's `kind` line).
    pub fn tag(self) -> &'static str {
        match self {
            SurfaceKind::SpecFn => "spec-fn",
            SurfaceKind::SpecConst => "spec-const",
            SurfaceKind::SpecType => "spec-type",
            SurfaceKind::View => "view",
            SurfaceKind::Represents => "represents",
            SurfaceKind::Invariant => "invariant",
            SurfaceKind::EvidenceType => "evidence-type",
            SurfaceKind::Law => "law",
            SurfaceKind::FuelSufficient => "fuel-sufficient",
            SurfaceKind::Contract => "contract",
            SurfaceKind::BoundarySignature => "boundary-fn",
            SurfaceKind::BoundaryType => "boundary-type",
            SurfaceKind::Type => "type",
            SurfaceKind::Constant => "constant",
            SurfaceKind::TrustedExtern => "trusted-extern",
            SurfaceKind::MirrorsImpl => "mirrors-impl",
            SurfaceKind::TargetModel => "target-model",
            SurfaceKind::Example => "example",
            SurfaceKind::VectorFile => "vector-file",
            SurfaceKind::Section => "section",
        }
    }

    pub fn from_tag(s: &str) -> Option<SurfaceKind> {
        SurfaceKind::ALL.into_iter().find(|k| k.tag() == s)
    }

    /// A heading for the spec sheet.
    pub fn heading(self) -> &'static str {
        match self {
            SurfaceKind::SpecFn => "Spec functions",
            SurfaceKind::SpecConst => "Spec constants",
            SurfaceKind::SpecType => "Spec types",
            SurfaceKind::View => "Views",
            SurfaceKind::Represents => "Representation relations",
            SurfaceKind::Invariant => "Invariants",
            SurfaceKind::EvidenceType => "Evidence types",
            SurfaceKind::Law => "Laws",
            SurfaceKind::FuelSufficient => "Fuel sufficiency (`#[fuel_sufficient]`)",
            SurfaceKind::Contract => "Contracts",
            SurfaceKind::BoundarySignature => "Boundary functions",
            SurfaceKind::BoundaryType => "Boundary types",
            SurfaceKind::Type => "Types mentioned by statements",
            SurfaceKind::Constant => "Constants",
            SurfaceKind::TrustedExtern => "Trusted externs",
            SurfaceKind::MirrorsImpl => "Mirrors (`#[mirrors_impl]`)",
            SurfaceKind::TargetModel => "Target-intrinsic models",
            SurfaceKind::Example => "Examples",
            SurfaceKind::VectorFile => "Vector files",
            SurfaceKind::Section => "Sections",
        }
    }

    /// A *value* statement means its definition: an exec function or
    /// constant it reaches must be established (spec closure, §15.1), not
    /// merely have a contract.
    fn is_value(self) -> bool {
        matches!(self, SurfaceKind::SpecFn | SurfaceKind::SpecConst | SurfaceKind::View | SurfaceKind::Represents | SurfaceKind::Invariant | SurfaceKind::EvidenceType)
    }

    /// Whether the kernel statement is a proposition or definition that
    /// `sandblaster spec --diff` compares in the kernel (the lock stores its
    /// core text for that).
    pub fn has_kernel_text(self) -> bool {
        matches!(
            self,
            SurfaceKind::SpecFn | SurfaceKind::SpecConst | SurfaceKind::View | SurfaceKind::Represents | SurfaceKind::Law | SurfaceKind::FuelSufficient | SurfaceKind::Contract | SurfaceKind::BoundarySignature | SurfaceKind::Constant | SurfaceKind::TrustedExtern | SurfaceKind::Invariant | SurfaceKind::EvidenceType | SurfaceKind::Section
        )
    }
}

/// The trusted computing base and assumptions of a verified build
/// (DESIGN.md §1.1): printed on the spec sheet, recorded in the lock header
/// and in the report.
pub const TCB: &[&str] = &[
    "1 sandblaster-kernel: checker, evaluator, conversion, termination, linear-arithmetic certificates, bvnorm, the fixed axiom list, bignum Int, the section abstraction and the closed evaluator",
    "2 the elaboration semantics of the canonical dialect (SEMANTICS.md)",
    "3 the prelude definitions (sandblaster/kernel/prelude/*.core)",
    "4 the target semantics library (intrinsic models, load/store helpers) and the dispatch glue",
    "5 rustc/LLVM",
    "6 the elaboration of the ghost language (SEMANTICS.md §13): the kernel statement of a spec item, law, contract or invariant means what its source says; and Env::abstract_section",
    "7 assumptions: num-bigint/num-integer; the rustc that compiled the kernel; syn agreeing with rustc on the canonical dialect; the §3.7 stack assumption; runtime feature detection; a process free of undefined behaviour",
];

/// What the toolchain contributes to the lock: the header hashes and the
/// file hashes of the globals it defines.
#[derive(Clone, Debug)]
pub struct Toolchain {
    /// The kernel's source files ([`crate::lock::KERNEL_SOURCES`]).
    pub kernel: Hash,
    /// Every prelude file.
    pub prelude: Hash,
    /// Each prelude file (`base.core`, …).
    pub prelude_files: BTreeMap<String, Hash>,
    /// `SEMANTICS.md`.
    pub semantics: Hash,
    /// The builtins table, the elaboration-semantics definitions, the ghost
    /// library and the intrinsic table.
    pub builtins: Hash,
    /// The lift prelude ([`crate::lock::LIFT_SOURCES`]: `lift/prelude.rs`,
    /// `lift/model.rs`), the definitions a lifted crate's contracts use
    /// (`ord_lt`, `range_inclusive_u32`, the buffer model): the `lift`
    /// line of a lifted crate's lock header.
    pub lift: Hash,
    /// The ghost-language library `elab/ghost.core`.
    pub ghost: Hash,
    /// The elaboration-semantics definitions (`elab/semantics.rs`).
    pub semantics_defs: Hash,
    /// The target semantics library of each architecture.
    pub target: BTreeMap<String, Hash>,
    /// Global and inductive name → dependency name (`prelude:list.core`,
    /// `ghost:ghost.core`, `target:aarch64`).
    pub names: HashMap<String, String>,
}

/// Names declared by core text (`def[..] name`, `def name`, `inductive name`).
fn core_names(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim_start();
        let rest = if let Some(r) = l.strip_prefix("def[") {
            r.split_once(']').map(|x| x.1)
        } else if let Some(r) = l.strip_prefix("def ") {
            Some(r)
        } else {
            l.strip_prefix("inductive ")
        };
        if let Some(r) = rest {
            // `seq::len : ..`: names contain `::`, a type annotation follows
            // a space (a trailing `:` of `name: ..` is dropped)
            let name: String = r.trim_start().chars().take_while(|c| !c.is_whitespace() && *c != '(' && *c != '{').collect();
            let name = name.trim_end_matches(':');
            if !name.is_empty() {
                out.push(name.to_string());
            }
        }
    }
    out
}

static TOOLCHAIN: std::sync::OnceLock<Toolchain> = std::sync::OnceLock::new();

impl Toolchain {
    /// The toolchain this binary was built from (computed once).
    pub fn current() -> &'static Toolchain {
        TOOLCHAIN.get_or_init(|| {
            let mut kernel = Enc::default();
            for (name, text) in crate::lock::KERNEL_SOURCES {
                kernel.s(name).s(text);
            }
            let mut names = HashMap::new();
            let mut prelude_files = BTreeMap::new();
            let mut prelude = Enc::default();
            for (name, text) in sandblaster_kernel::PRELUDE_FILES {
                let h = sha256(text.as_bytes());
                prelude.s(name).h(&h);
                prelude_files.insert(name.to_string(), h);
                let expanded = sandblaster_kernel::expand_templates(text).unwrap_or_else(|_| text.to_string());
                for n in core_names(&expanded) {
                    names.entry(n).or_insert_with(|| format!("prelude:{name}"));
                }
            }
            let ghost_text = crate::elab::semantics::GHOST_CORE;
            for n in core_names(ghost_text) {
                names.entry(n).or_insert_with(|| "ghost:ghost.core".to_string());
            }
            let mut target = BTreeMap::new();
            for arch in [sandblaster_targets::registry::Arch::Aarch64, sandblaster_targets::registry::Arch::X86_64] {
                let mut e = Enc::default();
                for (name, text) in sandblaster_targets::coretext::core_files(arch) {
                    e.s(name).s(text);
                    for n in core_names(text) {
                        names.entry(n).or_insert_with(|| format!("target:{}", arch.name()));
                    }
                }
                target.insert(arch.name().to_string(), e.done());
            }
            names.insert("Tuple1".into(), "semantics:semantics.rs".into());
            names.insert("array::copy_range".into(), "semantics:semantics.rs".into());
            let mut builtins = Enc::default();
            for (name, text) in crate::lock::BUILTIN_SOURCES {
                builtins.s(name).s(text);
            }
            let mut lift = Enc::default();
            for (name, text) in crate::lock::LIFT_SOURCES {
                lift.s(name).s(text);
            }
            Toolchain {
                kernel: kernel.done(),
                prelude: prelude.done(),
                prelude_files,
                semantics: sha256(crate::lock::SEMANTICS_MD.as_bytes()),
                builtins: builtins.done(),
                lift: lift.done(),
                ghost: sha256(ghost_text.as_bytes()),
                semantics_defs: sha256(crate::lock::SEMANTICS_RS.as_bytes()),
                target,
                names,
            }
        })
    }

    /// The dependency name and hash of a toolchain global or inductive.
    fn dep(&self, name: &str) -> (String, Hash) {
        match self.names.get(name).map(String::as_str) {
            Some(d) if d.starts_with("prelude:") => {
                let f = &d["prelude:".len()..];
                (d.to_string(), self.prelude_files.get(f).copied().unwrap_or(self.prelude))
            }
            Some("ghost:ghost.core") => ("ghost:ghost.core".into(), self.ghost),
            Some("semantics:semantics.rs") => ("semantics:semantics.rs".into(), self.semantics_defs),
            Some(d) if d.starts_with("target:") => {
                let a = &d["target:".len()..];
                (d.to_string(), self.target.get(a).copied().unwrap_or([0; 32]))
            }
            _ if name == "Bool" || name == "Empty" => ("kernel:builtin-inductives".into(), sha256(b"sandblaster kernel builtin inductives: Bool (false, true), Empty")),
            // any other toolchain global (automation lemma files, …): the
            // builtins hash, named after the global
            _ => (format!("builtins:{name}"), self.builtins),
        }
    }
}

/// One dependency of an item: another item (by key) or a toolchain file.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Dep {
    /// An item key, or a toolchain dependency name (`prelude:list.core`).
    pub name: String,
    /// Whether `name` is an item key.
    pub item: bool,
    /// An item in the same strongly connected component (its key, not its
    /// hash, enters `L(i)`).
    pub cycle: bool,
    /// `Hdep`: the item's hash, or the file hash.
    pub hash: Hash,
}

/// One surface item.
#[derive(Clone, Debug)]
pub struct SurfaceItem {
    /// Stable key (`kind:path[#k]`), the sort key of `SPEC.lock`.
    pub key: String,
    pub kind: SurfaceKind,
    /// The display path of the item it comes from.
    pub path: String,
    /// The item it comes from (`None` for target models).
    pub item: Option<ItemId>,
    pub span: Span,
    /// `src(stmt)`: the source text, whitespace collapsed.
    pub source: String,
    /// The de-elaborated statement ([`crate::deelab`]), one line per part.
    pub statement: Vec<String>,
    /// The kernel statement in core text (`(part, text)`), for the spec
    /// sheet and for kernel comparison (`sandblaster spec --diff`); only parts
    /// that print completely (and parse back).
    pub kernel: Vec<(String, String)>,
    /// Parts whose core text is not stored (too large, or naming a global
    /// that has no stable name).
    pub kernel_omitted: Vec<String>,
    pub canon: Hash,
    pub src: Hash,
    /// `⟨(name g, Hdep g)⟩`, sorted.
    pub deps: Vec<Dep>,
    /// `H(i)`.
    pub hash: Hash,
    /// Build results shown on the spec sheet next to the item and never
    /// hashed or locked (a section's status: whether each `complete_p` was
    /// proven is a result of the build, not part of the specification).
    pub notes: Vec<String>,
}

/// A dependency that §15.6 makes an error.
#[derive(Clone, Debug)]
pub struct SurfaceError {
    pub key: String,
    pub span: Span,
    pub msg: String,
    pub note: String,
}

/// The surface of a crate for one target.
#[derive(Clone, Debug)]
pub struct Surface {
    /// The target architecture (`aarch64`, `x86_64`).
    pub target: String,
    pub kernel: Hash,
    pub prelude: Hash,
    pub semantics: Hash,
    pub builtins: Hash,
    /// The lift prelude's hash ([`Toolchain::lift`]) when the crate is
    /// lifted (it loads the lift prelude, `crate::__lift`): its contracts
    /// read the prelude's definitions, so the lock pins them. `None` for a
    /// crate written in the DSL, whose lock has no `lift` line.
    pub lift: Option<Hash>,
    /// The target semantics library of [`Surface::target`].
    pub target_model: Hash,
    /// Every item, sorted by key.
    pub items: Vec<SurfaceItem>,
    pub errors: Vec<SurfaceError>,
    /// The law table (DESIGN.md §15.1 LR9): per law its guarantee (the
    /// first sentence of its doc comment) and assumptions, printed on the
    /// spec sheet; not hashed (the laws' own entries are).
    pub laws: Vec<crate::elab::law_rules::LawRow>,
    /// The keys of the computed items that are **not** on the review
    /// surface (proof internals: helper spec functions and their examples,
    /// invariants of types no statement mentions, …; module docs, *What is
    /// locked*), sorted. Never locked and never mutated; the other gates
    /// check them all the same.
    pub internal: Vec<String>,
}

impl Surface {
    pub fn get(&self, key: &str) -> Option<&SurfaceItem> {
        self.items.binary_search_by(|i| i.key.as_str().cmp(key)).ok().map(|i| &self.items[i])
    }
}

/// The kernel statement of an item (on the elaboration thread; for
/// `crate::specdiff`).
#[derive(Clone, Debug)]
pub struct Stmt {
    pub parts: Vec<(String, Tm)>,
    /// Leading parameter binders of the statement (type parameters and
    /// parameters of a law or function; the arity of a definition).
    pub np: usize,
    /// The definition is recursive (its body has `rec`): it cannot be
    /// re-stated as a closed term.
    pub recursive: bool,
}

/// Options of [`compute`].
#[derive(Clone, Debug)]
pub struct SurfaceOptions {
    /// Print the kernel statements (core text) of the items (the lock and
    /// the spec sheet need them; the build's status check does not).
    pub kernel_text: bool,
    /// The largest core text stored per part (bytes).
    pub kernel_text_limit: usize,
    /// Tests: a modified toolchain (e.g. a changed prelude file hash).
    pub toolchain: Option<Toolchain>,
}

impl Default for SurfaceOptions {
    fn default() -> SurfaceOptions {
        SurfaceOptions { kernel_text: true, kernel_text_limit: 1 << 16, toolchain: None }
    }
}

// ---------------------------------------------------------------------------
// canon (de Bruijn, names dropped, • for irrelevant subterms, memoized)
// ---------------------------------------------------------------------------

/// Hashes of kernel terms modulo binder names and irrelevant subterms, and
/// their `Refs₁` (see the module docs).
pub struct Canon<'e> {
    env: &'e Env,
    /// Node address → (the node, its hash); the node is kept alive, so the
    /// address is never reused while the memo lives.
    memo: HashMap<usize, (Tm, Hash)>,
    ind_names: HashMap<IndId, String>,
    ctor_rels: HashMap<(IndId, u32), Vec<Rel>>,
    param_rels: HashMap<GlobalId, Vec<Rel>>,
    pair_rel: HashMap<usize, (Tm, Rel)>,
}

/// A node of the reference graph.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Node {
    G(GlobalId),
    I(IndId),
}

fn rel_byte(r: Rel) -> &'static str {
    match r {
        Rel::Rel => "r",
        Rel::Irr => "i",
    }
}

fn rel_at(v: &[Rel], i: usize) -> bool {
    v.get(i).copied().unwrap_or(Rel::Rel) == Rel::Rel
}

impl<'e> Canon<'e> {
    pub fn new(env: &'e Env) -> Canon<'e> {
        Canon { env, memo: HashMap::new(), ind_names: HashMap::new(), ctor_rels: HashMap::new(), param_rels: HashMap::new(), pair_rel: HashMap::new() }
    }

    fn gname(&self, g: GlobalId) -> String {
        self.env.global_name(g).map(|n| n.to_string()).unwrap_or_else(|| format!("@{}", g.0))
    }

    pub fn ind_name(&mut self, i: IndId) -> String {
        if let Some(n) = self.ind_names.get(&i) {
            return n.clone();
        }
        let n = self.env.inductive_decl(i).map(|d| d.name.to_string()).unwrap_or_else(|| format!("@ind{}", i.0));
        self.ind_names.insert(i, n.clone());
        n
    }

    fn ctor_rels(&mut self, i: IndId, c: u32) -> Vec<Rel> {
        if let Some(v) = self.ctor_rels.get(&(i, c)) {
            return v.clone();
        }
        let v: Vec<Rel> = self.env.inductive_decl(i).and_then(|d| d.ctors.get(c as usize).map(|c| c.fields.iter().map(|f| f.1).collect())).unwrap_or_default();
        self.ctor_rels.insert((i, c), v.clone());
        v
    }

    fn param_rels(&mut self, g: GlobalId) -> Vec<Rel> {
        if let Some(v) = self.param_rels.get(&g) {
            return v.clone();
        }
        let v = self.env.global_param_rels(g).unwrap_or_default();
        self.param_rels.insert(g, v.clone());
        v
    }

    /// The relevance of the second component of a pair of Σ type `ty`
    /// (evaluated when `ty` is not syntactically a Σ; relevant when unsure,
    /// which can only add churn, never hide a change).
    fn pair_snd_rel(&mut self, ty: &Tm) -> Rel {
        if let Term::Sigma { snd_rel, .. } = &**ty {
            return *snd_rel;
        }
        let key = Rc::as_ptr(ty) as *const () as usize;
        if let Some((_, r)) = self.pair_rel.get(&key) {
            return *r;
        }
        let n = free_extent(ty);
        let venv = VEnv(Rc::new((0..n).map(|l| EnvEntry::Rel(Rc::new(Value::Neu(Neutral { head: Head::Var(Lvl(l)), spine: vec![] })))).collect()));
        let mut b = Budget { steps: 100_000 };
        let r = match self.env.eval(&venv, Lvl(n), ty, &mut b) {
            Ok(v) => match &*v {
                Value::Sigma { snd_rel, .. } => *snd_rel,
                _ => Rel::Rel,
            },
            Err(_) => Rel::Rel,
        };
        self.pair_rel.insert(key, (ty.clone(), r));
        r
    }

    /// The node's own bytes and its children with their relevance (the
    /// kernel's `relevant_children`, AUDIT.md §19).
    fn pieces<'t>(&mut self, t: &'t Tm) -> (Enc, Vec<(&'t Tm, bool)>) {
        let mut e = Enc::default();
        let mut ch: Vec<(&'t Tm, bool)> = Vec::new();
        match &**t {
            Term::Var(i) => {
                e.s("var").s(&i.0.to_string());
            }
            Term::Global(g) => {
                e.s("global").s(&self.gname(*g));
            }
            Term::Sort(s) => {
                e.s("sort").s(&format!("{s:?}"));
            }
            Term::Pi { rel, dom, cod, .. } => {
                e.s("pi").s(rel_byte(*rel));
                ch.extend([(dom, true), (cod, true)]);
            }
            Term::Lam { rel, dom, body, .. } => {
                e.s("lam").s(rel_byte(*rel));
                ch.extend([(dom, true), (body, true)]);
            }
            Term::App { rel, fun, arg } => {
                e.s("app").s(rel_byte(*rel));
                ch.extend([(fun, true), (arg, *rel == Rel::Rel)]);
            }
            Term::Let { rel, ty, val, body, .. } => {
                e.s("let").s(rel_byte(*rel));
                ch.extend([(ty, true), (val, *rel == Rel::Rel), (body, true)]);
            }
            Term::Sigma { snd_rel, fst, snd, .. } => {
                e.s("sigma").s(rel_byte(*snd_rel));
                ch.extend([(fst, true), (snd, true)]);
            }
            Term::Pair { ty, fst, snd } => {
                let r = self.pair_snd_rel(ty);
                e.s("pair");
                ch.extend([(ty, true), (fst, true), (snd, r == Rel::Rel)]);
            }
            Term::Fst(p) => {
                e.s("fst");
                ch.push((p, true));
            }
            Term::Snd(p) => {
                e.s("snd");
                ch.push((p, true));
            }
            Term::Eq { ty, lhs, rhs } => {
                e.s("eq");
                ch.extend([(ty, true), (lhs, true), (rhs, true)]);
            }
            Term::Refl { ty, val } => {
                e.s("refl");
                ch.extend([(ty, true), (val, true)]);
            }
            Term::Transport { ty, lhs, rhs, eq, motive, val } => {
                e.s("transport");
                ch.extend([(ty, true), (lhs, true), (rhs, true), (eq, false), (motive, true), (val, true)]);
            }
            Term::Ind { ind, params } => {
                e.s("ind").s(&self.ind_name(*ind));
                ch.extend(params.iter().map(|p| (p, true)));
            }
            Term::Ctor { ind, ctor, params, args } => {
                e.s("ctor").s(&self.ind_name(*ind)).s(&ctor.to_string());
                let rels = self.ctor_rels(*ind, *ctor);
                ch.extend(params.iter().map(|p| (p, true)));
                ch.extend(args.iter().enumerate().map(|(i, a)| (a, rel_at(&rels, i))));
            }
            Term::Match { ind, params, scrut, motive, arms } => {
                e.s("match").s(&self.ind_name(*ind)).s(&arms.len().to_string());
                for a in arms {
                    e.s(&a.names.len().to_string());
                }
                ch.extend(params.iter().map(|p| (p, true)));
                ch.extend([(scrut, true), (motive, true)]);
                ch.extend(arms.iter().map(|a| (&a.body, true)));
            }
            Term::IntTy(w) => {
                e.s("intty").s(&format!("{w:?}"));
            }
            Term::Lit { w, n } => {
                e.s("lit").s(&format!("{w:?}")).s(&n.to_string());
            }
            Term::Prim { op, args, proofs } => {
                e.s("prim").s(&format!("{op:?}")).s(&args.len().to_string()).s(&proofs.len().to_string());
                ch.extend(args.iter().map(|a| (a, true)));
                ch.extend(proofs.iter().map(|p| (p, false)));
            }
            Term::Rec { args, proof } => {
                e.s("rec").s(&args.len().to_string());
                ch.extend(args.iter().map(|a| (a, true)));
                if let Some(p) = proof {
                    ch.push((p, false));
                }
            }
            Term::Delta { def, args } => {
                e.s("delta").s(&self.gname(*def));
                let rels = self.param_rels(*def);
                ch.extend(args.iter().enumerate().map(|(i, a)| (a, rel_at(&rels, i))));
            }
            Term::Unfold { def, args, to_body, val } => {
                e.s("unfold").s(&self.gname(*def)).s(if *to_body { "to" } else { "from" });
                let rels = self.param_rels(*def);
                ch.extend(args.iter().enumerate().map(|(i, a)| (a, rel_at(&rels, i))));
                ch.push((val, true));
            }
            Term::Linarith { hyps, goal, cert } => {
                e.s("linarith").s(&hyps.len().to_string());
                for r in cert {
                    e.s(&format!("{}/{}", r.num, r.den));
                }
                for (p, q) in hyps {
                    ch.extend([(p, true), (q, true)]);
                }
                ch.push((goal, true));
            }
            Term::BvRefl { ty, lhs, rhs } => {
                e.s("bvrefl");
                ch.extend([(ty, true), (lhs, true), (rhs, true)]);
            }
            Term::Absurd { ty, proof } => {
                e.s("absurd");
                ch.extend([(ty, true), (proof, false)]);
            }
            Term::Axiom { ax, args } => {
                e.s("axiom").s(&sandblaster_kernel::axioms::axiom_name(*ax));
                let rels = sandblaster_kernel::axioms::axiom_param_rels(*ax);
                ch.extend(args.iter().enumerate().map(|(i, a)| (a, rel_at(&rels, i))));
            }
            Term::Erased => {
                e.s("erased");
            }
        }
        (e, ch)
    }

    /// `canon(t)`.
    pub fn hash(&mut self, t: &Tm) -> Hash {
        let key = Rc::as_ptr(t) as *const () as usize;
        if let Some((_, h)) = self.memo.get(&key) {
            return *h;
        }
        let (mut e, ch) = self.pieces(t);
        for (c, rel) in ch {
            if rel {
                let h = self.hash(c);
                e.h(&h);
            } else {
                e.s("•");
            }
        }
        let h = e.done();
        self.memo.insert(key, (t.clone(), h));
        h
    }

    /// `Refs₁(ts)`: the globals and inductives in relevant positions (linear
    /// in the DAG).
    pub fn refs(&mut self, ts: &[&Tm]) -> BTreeSet<Node> {
        let mut out = BTreeSet::new();
        let mut seen: HashSet<usize> = HashSet::new();
        let mut stack: Vec<Tm> = ts.iter().map(|t| (*t).clone()).collect();
        while let Some(t) = stack.pop() {
            if !seen.insert(Rc::as_ptr(&t) as *const () as usize) {
                continue;
            }
            match &*t {
                Term::Global(g) | Term::Delta { def: g, .. } | Term::Unfold { def: g, .. } => {
                    out.insert(Node::G(*g));
                }
                Term::Ind { ind, .. } | Term::Ctor { ind, .. } | Term::Match { ind, .. } => {
                    out.insert(Node::I(*ind));
                }
                _ => {}
            }
            let (_, ch) = self.pieces(&t);
            stack.extend(ch.into_iter().filter(|(_, r)| *r).map(|(c, _)| c.clone()));
        }
        out
    }
}

/// `canon` of a statement: its parts (name, [`Canon::hash`]) and the
/// item's extra local content.
pub fn statement_canon(c: &mut Canon, parts: &[(String, Tm)], extra: &[u8]) -> Hash {
    let mut e = Enc::default();
    e.s("canon/1");
    for (name, t) in parts {
        let h = c.hash(t);
        e.s(name).h(&h);
    }
    e.bytes(extra);
    e.done()
}

/// Whether `t` has no free variable.
pub fn is_closed(t: &Tm) -> bool {
    free_extent(t) == 0
}

/// One more than the largest free de Bruijn index of `t` (0 if closed).
fn free_extent(t: &Tm) -> u32 {
    fn go(t: &Tm, d: u32, m: &mut u32, seen: &mut HashSet<(usize, u32)>) {
        if !seen.insert((Rc::as_ptr(t) as *const () as usize, d)) {
            return;
        }
        if let Term::Var(i) = &**t
            && i.0 >= d
        {
            *m = (*m).max(i.0 - d + 1);
        }
        crate::elab::tm::children_depth(t, &mut |c, k| go(c, d + k, m, seen));
    }
    let mut m = 0;
    go(t, 0, &mut m, &mut HashSet::new());
    m
}

// ---------------------------------------------------------------------------
// Merkle hashing over the item graph (strongly connected components)
// ---------------------------------------------------------------------------

/// The input of [`merkle`]: an item's local content and its dependencies.
struct MNode {
    key: String,
    local: Hash,
    /// Item dependencies (keys; must be nodes).
    items: BTreeSet<String>,
    /// Toolchain dependencies.
    ext: BTreeMap<String, Hash>,
}

/// An item's local content: its kind, key, `canon` and `src` hashes.
pub fn item_local(kind: SurfaceKind, key: &str, canon: &Hash, src: &Hash) -> Hash {
    let mut e = Enc::default();
    e.s(kind.tag()).s(key).h(canon).h(src);
    e.done()
}

/// `L(i)`: the local content, the toolchain dependencies (sorted by name)
/// and the item dependencies (sorted by key; `None` for a dependency in the
/// item's own strongly connected component, which contributes its key only).
pub fn item_l(local: &Hash, ext: &[(&str, &Hash)], items: &[(&str, Option<&Hash>)]) -> Hash {
    let mut e = Enc::default();
    e.s("sandblaster-spec-item/1").h(local);
    for (name, hash) in ext {
        e.s("ext").s(name).h(hash);
    }
    for (k, h) in items {
        match h {
            Some(h) => e.s("item").s(k).h(h),
            None => e.s("cycle").s(k),
        };
    }
    e.done()
}

/// `H(i)` of a member of a cyclic component with `L(i) = l`, whose members'
/// `(key, L)` are `members`.
pub fn scc_member_hash(l: &Hash, members: &[(String, Hash)]) -> Hash {
    let mut m: Vec<&(String, Hash)> = members.iter().collect();
    m.sort();
    let mut s = Enc::default();
    s.s("sandblaster-spec-scc/1");
    for (k, x) in m {
        s.s(k).h(x);
    }
    let sh = s.done();
    let mut e = Enc::default();
    e.s("sandblaster-spec-scc-member/1").h(l).h(&sh);
    e.done()
}

/// `H(i)` for every node (see the module docs), and each node's item
/// dependencies inside its own strongly connected component: Tarjan's SCCs
/// (emitted dependencies first), [`item_l`], and [`scc_member_hash`] for the
/// members of a cyclic component.
fn merkle(nodes: &[MNode]) -> (Vec<Hash>, Vec<BTreeSet<String>>) {
    let index: HashMap<&str, usize> = nodes.iter().enumerate().map(|(i, n)| (n.key.as_str(), i)).collect();
    let adj: Vec<Vec<usize>> = nodes.iter().map(|n| n.items.iter().filter_map(|k| index.get(k.as_str()).copied()).collect()).collect();
    // Tarjan, iterative
    let n = nodes.len();
    let mut idx = vec![usize::MAX; n];
    let mut low = vec![0usize; n];
    let mut on = vec![false; n];
    let mut stack: Vec<usize> = Vec::new();
    let mut sccs: Vec<Vec<usize>> = Vec::new();
    let mut counter = 0usize;
    for root in 0..n {
        if idx[root] != usize::MAX {
            continue;
        }
        let mut call: Vec<(usize, usize)> = vec![(root, 0)];
        idx[root] = counter;
        low[root] = counter;
        counter += 1;
        stack.push(root);
        on[root] = true;
        while let Some(&mut (v, ref mut i)) = call.last_mut() {
            if *i < adj[v].len() {
                let w = adj[v][*i];
                *i += 1;
                if idx[w] == usize::MAX {
                    idx[w] = counter;
                    low[w] = counter;
                    counter += 1;
                    stack.push(w);
                    on[w] = true;
                    call.push((w, 0));
                } else if on[w] {
                    low[v] = low[v].min(idx[w]);
                }
            } else {
                call.pop();
                if let Some(&(u, _)) = call.last() {
                    low[u] = low[u].min(low[v]);
                }
                if low[v] == idx[v] {
                    let mut comp = Vec::new();
                    loop {
                        let w = stack.pop().unwrap();
                        on[w] = false;
                        comp.push(w);
                        if w == v {
                            break;
                        }
                    }
                    sccs.push(comp);
                }
            }
        }
    }
    let mut comp_of = vec![0usize; n];
    for (c, comp) in sccs.iter().enumerate() {
        for &v in comp {
            comp_of[v] = c;
        }
    }
    let mut h: Vec<Option<Hash>> = vec![None; n];
    let mut cycles: Vec<BTreeSet<String>> = vec![BTreeSet::new(); n];
    for (c, comp) in sccs.iter().enumerate() {
        let mut locals: Vec<(String, Hash)> = Vec::new();
        for &v in comp {
            let nd = &nodes[v];
            let ext: Vec<(&str, &Hash)> = nd.ext.iter().map(|(k, x)| (k.as_str(), x)).collect();
            let mut items: Vec<(&str, Option<&Hash>)> = Vec::new();
            for k in &nd.items {
                match index.get(k.as_str()) {
                    Some(&w) if comp_of[w] != c => items.push((k.as_str(), Some(h[w].as_ref().expect("dependencies are hashed first")))),
                    Some(_) => {
                        items.push((k.as_str(), None));
                        cycles[v].insert(k.clone());
                    }
                    // unreachable: every dependency is a node
                    None => items.push((k.as_str(), Some(&[0; 32]))),
                }
            }
            locals.push((nd.key.clone(), item_l(&nd.local, &ext, &items)));
        }
        if comp.len() == 1 {
            h[comp[0]] = Some(locals[0].1);
            continue;
        }
        for &v in comp {
            let l = locals.iter().find(|(k, _)| *k == nodes[v].key).unwrap().1;
            h[v] = Some(scc_member_hash(&l, &locals));
        }
    }
    (h.into_iter().map(|x| x.unwrap_or([0; 32])).collect(), cycles)
}

// ---------------------------------------------------------------------------
// enumeration
// ---------------------------------------------------------------------------

/// What a user global of the elaboration is.
#[derive(Clone, Copy, Debug)]
enum Role {
    /// The item's own definition.
    Item(ItemId),
    /// The derived `PartialEq` of a type (determined by the type).
    Eq(ItemId),
    View(ItemId),
    Represents(ItemId),
    /// `f::ensures`, `f::contract`, `f::refines`, `f::loop#k::ensures`:
    /// part of `f`'s contract (a proof file's summaries in `f::ensures`
    /// are not: the surface states `f::contract` then).
    FnLemma(ItemId),
    LoopHelper(ItemId),
    /// `S::invariant#k`, `S::holds#k`, `S::inv#k` (S2): the invariant of `S`.
    Invariant(ItemId),
    Other(ItemId),
}

/// The pieces of an item before hashing.
struct Pending {
    key: String,
    kind: SurfaceKind,
    path: String,
    item: Option<ItemId>,
    span: Span,
    source: String,
    statement: Vec<String>,
    stmt: Stmt,
    /// Extra bytes of the local content (HIR facts, file hashes, evidence).
    extra: Enc,
    /// Explicit item dependencies (besides `Refs₁`).
    extra_items: Vec<String>,
    /// Build results for the sheet (not hashed; [`SurfaceItem::notes`]).
    notes: Vec<String>,
}

struct Builder<'a> {
    out: &'a Output,
    krate: &'a Crate,
    sm: &'a SourceMap,
    tc: &'a Toolchain,
    canon: Canon<'a>,
    roles: HashMap<GlobalId, Role>,
    ind_items: HashMap<IndId, ItemId>,
    boundary: HashSet<ItemId>,
    established: HashSet<GlobalId>,
    arch: String,
    pending: BTreeMap<String, Pending>,
    queue: Vec<String>,
    deps: BTreeMap<String, (BTreeSet<String>, BTreeMap<String, Hash>)>,
    errors: Vec<SurfaceError>,
    /// Target-model entries by core global name (`aarch64::vaddq_u32`).
    models: HashMap<String, String>,
}

fn snippet(sm: &SourceMap, sp: Span) -> String {
    sm.snippet(sp).map(|s| deelab::flat(&s)).unwrap_or_default()
}

impl<'a> Builder<'a> {
    fn path(&self, id: ItemId) -> String {
        self.krate.item(id).path.to_string()
    }

    fn global_of(&self, id: ItemId) -> Option<GlobalId> {
        self.out.fn_globals.get(&id).copied()
    }

    /// The checked definition `name` (e.g. `crate::f::ensures`).
    fn def_named(&self, name: &str) -> Option<GlobalId> {
        self.out.defs.iter().find(|d| d.name == name && d.status == crate::elab::DefStatus::Checked).and_then(|d| d.global)
    }

    fn fn_key(&self, id: ItemId) -> String {
        let f = self.krate.fn_def(id);
        let tag = if self.boundary.contains(&id) {
            SurfaceKind::BoundarySignature
        } else if f.is_some_and(|f| f.spec.trusted_extern.is_some()) {
            SurfaceKind::TrustedExtern
        } else {
            SurfaceKind::Contract
        };
        format!("{}:{}", tag.tag(), self.path(id))
    }

    fn type_key(&self, id: ItemId) -> String {
        let it = self.krate.item(id);
        let kind = if self.boundary.contains(&id) {
            SurfaceKind::BoundaryType
        } else if it.ghost || self.krate.in_spec_module(id) {
            SurfaceKind::SpecType
        } else {
            SurfaceKind::Type
        };
        format!("{}:{}", kind.tag(), it.path)
    }

    fn const_key(&self, id: ItemId) -> String {
        let it = self.krate.item(id);
        let kind = if it.ghost { SurfaceKind::SpecConst } else { SurfaceKind::Constant };
        format!("{}:{}", kind.tag(), it.path)
    }

    fn push(&mut self, p: Pending) {
        if self.pending.contains_key(&p.key) {
            return;
        }
        self.queue.push(p.key.clone());
        self.pending.insert(p.key.clone(), p);
    }

    fn pending(&self, key: String, kind: SurfaceKind, id: Option<ItemId>, source: String, statement: Vec<String>, stmt: Stmt) -> Pending {
        let (path, span) = match id {
            Some(i) => (self.path(i), self.krate.item(i).span),
            None => (String::new(), Span::DUMMY),
        };
        Pending { key, kind, path, item: id, span, source, statement, stmt, extra: Enc::default(), extra_items: vec![], notes: vec![] }
    }

    fn def_parts(&self, g: GlobalId) -> Stmt {
        let env = &self.out.env;
        let mut parts = Vec::new();
        if let Some(t) = env.global_type(g) {
            parts.push(("type".to_string(), t));
        }
        let mut recursive = false;
        if let Some(b) = env.global_body(g) {
            recursive = crate::elab::tm::any_node(&b, &mut |n| matches!(n, Term::Rec { .. }));
            parts.push(("body".to_string(), b));
        }
        Stmt { parts, np: env.global_arity(g).unwrap_or(0) as usize, recursive }
    }

    /// The contract of exec function `id` (creating its entry).
    fn add_fn(&mut self, id: ItemId) -> Option<String> {
        let key = self.fn_key(id);
        if self.pending.contains_key(&key) {
            return Some(key);
        }
        let g = self.global_of(id)?;
        let it = self.krate.item(id);
        let f = self.krate.fn_def(id)?;
        let env = &self.out.env;
        let mut parts = vec![("fn".to_string(), env.global_type(g)?)];
        // the contract's `ensures`: the laws file's, never a proof file's
        // summaries (`f::contract` when it has any; DESIGN.md §15.6)
        if f.contract_ensures().is_some()
            && let Some(e) = self.def_named(&format!("{}::{}", it.path, f.contract_lemma()))
        {
            parts.push(("ensures".to_string(), env.global_type(e)?));
        }
        if let Some(r) = self.def_named(&format!("{}::refines", it.path)) {
            parts.push(("refines".to_string(), env.global_type(r)?));
        }
        // the signature's text: as written, or, for a function of a `#[lift]`
        // source, the lifted signature (its rewritten tokens keep spans from
        // elsewhere in the host file, so its span covers no contiguous text)
        let lifted = self.krate.modules.get(it.module.0 as usize).is_some_and(|m| m.lift_source);
        let mut src = if lifted { f.sig_text.clone() } else { snippet(self.sm, f.sig_span) };
        if f.spec.attached.is_empty() {
            for r in &f.requires {
                src.push_str(&format!(" requires({})", snippet(self.sm, r.span)));
            }
            if let Some(en) = f.contract_ensures() {
                src.push_str(&format!(" ensures({})", snippet(self.sm, en.prop.span)));
            }
            if let Some(d) = &f.decreases {
                src.push_str(&format!(" decreases({}{})", snippet(self.sm, d.measure.span), d.max.map(|m| format!(", max = {m}")).unwrap_or_default()));
            }
        } else {
            // a lifted function's contract is attached from a ghost
            // `#[lift]` module: its statements as written there (the spliced
            // tokens' positions are that file's, not the host file's), the
            // `ensures` of the laws file only (DESIGN.md §15.6)
            src.push_str(&attached_src(&f.spec.attached));
        }
        if let Some(r) = &f.spec.refines {
            src.push_str(&format!(" {}", snippet(self.sm, r.span)));
        }
        let kind = SurfaceKind::from_tag(key.split(':').next().unwrap_or("")).unwrap_or(SurfaceKind::Contract);
        let word = match kind {
            SurfaceKind::BoundarySignature => "pub fn",
            SurfaceKind::TrustedExtern => "trusted_extern fn",
            _ => "fn",
        };
        // the refinement's form and determinacy come from the elaborator's
        // record (a simulation form is printed as its implication)
        let rec = self.out.refinements.iter().find(|r| r.item == id);
        let mut statement = DeElab::new(self.krate, &f.locals).contract_with(word, it, f, rec);
        let mut p = self.pending(key.clone(), kind, Some(id), src, Vec::new(), Stmt { parts, np: f.generics.len() + f.params.len(), recursive: false });
        if let Some(j) = &f.spec.trusted_extern {
            statement.push(format!("  justification {:?}", j.justification));
            p.extra.s("justification").s(&j.justification);
            p.source.push_str(&format!(" {}", snippet(self.sm, j.span)));
        }
        p.statement = statement;
        self.push(p);
        Some(key)
    }

    fn add_type(&mut self, id: ItemId) -> String {
        let key = self.type_key(id);
        if self.pending.contains_key(&key) {
            return key;
        }
        let it = self.krate.item(id);
        let kind = SurfaceKind::from_tag(key.split(':').next().unwrap_or("")).unwrap_or(SurfaceKind::Type);
        let statement = deelab::type_def(self.krate, it);
        let mut p = self.pending(key.clone(), kind, Some(id), snippet(self.sm, it.span), statement.clone(), Stmt { parts: vec![], np: 0, recursive: false });
        // the HIR facts the kernel declaration does not carry (field names
        // and visibilities, derives), then the declaration itself
        p.extra.s("hir").s(&statement.join("\n"));
        if let Some(&ind) = self.out.adts.get(&id)
            && let Some(decl) = self.out.env.inductive_decl(ind)
        {
            let mut terms: Vec<Tm> = Vec::new();
            p.extra.s("inductive").s(&decl.name).s(&decl.params.len().to_string());
            for (_, t) in &decl.params {
                let h = self.canon.hash(t);
                p.extra.h(&h);
                terms.push(t.clone());
            }
            for c in &decl.ctors {
                p.extra.s("ctor").s(&c.fields.len().to_string());
                for (_, r, t) in &c.fields {
                    let h = self.canon.hash(t);
                    p.extra.s(rel_byte(*r)).h(&h);
                    terms.push(t.clone());
                }
            }
            p.stmt.parts = terms.into_iter().map(|t| ("decl".to_string(), t)).collect();
        } else if let ItemKind::TypeAlias(a) = &it.kind {
            // an alias has no kernel declaration: the types it names
            let mut adts = Vec::new();
            a.ty.walk(&mut |t| {
                if let Ty::Adt(i, _) = t {
                    adts.push(*i);
                }
            });
            for i in adts {
                let k = self.add_type(i);
                p.extra_items.push(k);
            }
        }
        self.push(p);
        key
    }

    fn add_const(&mut self, id: ItemId) -> Option<String> {
        let key = self.const_key(id);
        if self.pending.contains_key(&key) {
            return Some(key);
        }
        let g = self.global_of(id)?;
        let it = self.krate.item(id);
        let ItemKind::Const(c) = &it.kind else { return None };
        let kind = if it.ghost { SurfaceKind::SpecConst } else { SurfaceKind::Constant };
        let stmt = self.def_parts(g);
        let p = self.pending(key.clone(), kind, Some(id), snippet(self.sm, it.span), deelab::constant(self.krate, it, c), stmt);
        self.push(p);
        Some(key)
    }

    fn roles(out: &Output, krate: &Crate) -> HashMap<GlobalId, Role> {
        let mut roles = HashMap::new();
        for d in &out.defs {
            let (Some(g), Some(id)) = (d.global, d.item) else { continue };
            let base = krate.item(id).path.to_string();
            let role = if d.name == base {
                Role::Item(id)
            } else if let Some(rest) = d.name.strip_prefix(&format!("{base}::")) {
                match rest {
                    "eq" => Role::Eq(id),
                    "view" => Role::View(id),
                    "represents" => Role::Represents(id),
                    "ensures" | "refines" | "contract" => Role::FnLemma(id),
                    "view_inj" | "view_inj_fields" => Role::View(id),
                    r if r.starts_with("invariant#") || r.starts_with("holds#") || r.starts_with("inv#") => Role::Invariant(id),
                    "eq_sound" | "eq_complete" => Role::Eq(id),
                    r if r.starts_with("loop#") && r.ends_with("::ensures") => Role::FnLemma(id),
                    r if r.starts_with("loop#") => Role::LoopHelper(id),
                    _ => Role::Other(id),
                }
            } else {
                Role::Other(id)
            };
            roles.insert(g, role);
        }
        roles
    }

    /// Resolves `Refs₁` of item `key` into dependencies (creating the items
    /// they name).
    fn resolve(&mut self, key: &str) {
        let (kind, terms, extra_items) = {
            let p = &self.pending[key];
            (p.kind, p.stmt.parts.iter().map(|(_, t)| t.clone()).collect::<Vec<Tm>>(), p.extra_items.clone())
        };
        let refs = self.canon.refs(&terms.iter().collect::<Vec<_>>());
        let mut items: BTreeSet<String> = extra_items.into_iter().collect();
        let mut ext: BTreeMap<String, Hash> = BTreeMap::new();
        let span = self.pending[key].span;
        for n in refs {
            match n {
                Node::I(ind) => match self.ind_items.get(&ind).copied() {
                    Some(id) => {
                        items.insert(self.add_type(id));
                    }
                    None => {
                        let name = self.canon.ind_name(ind);
                        let (d, h) = self.tc.dep(&name);
                        ext.insert(d, h);
                    }
                },
                Node::G(g) => match self.roles.get(&g).copied() {
                    Some(role) => {
                        if let Some(k) = self.resolve_user(key, kind, g, role, span) {
                            items.insert(k);
                        }
                    }
                    None => {
                        let name = self.out.env.global_name(g).map(|n| n.to_string()).unwrap_or_default();
                        if (self.out.env.global_kind(g) == Some(DefKind::Intrinsic) || name.starts_with(&format!("{}::", self.arch)))
                            && let Some(k) = self.models.get(&name)
                        {
                            items.insert(k.clone());
                            continue;
                        }
                        let (d, h) = self.tc.dep(&name);
                        ext.insert(d, h);
                    }
                },
            }
        }
        items.remove(key);
        self.deps.insert(key.to_string(), (items, ext));
    }

    fn error(&mut self, key: &str, span: Span, msg: String, note: &str) {
        if !self.errors.iter().any(|e| e.key == key && e.msg == msg) {
            self.errors.push(SurfaceError { key: key.to_string(), span, msg, note: note.to_string() });
        }
    }

    fn resolve_user(&mut self, key: &str, kind: SurfaceKind, g: GlobalId, role: Role, span: Span) -> Option<String> {
        let closure_note = "a specification may use spec functions, spec constants and established exec functions only (DESIGN.md §15.1); `Hdep` of any other exec global is an error (§15.6): transcribe the definition into `spec::` or establish the function (`#[refines]` with an injective view)";
        match role {
            Role::Item(id) => match &self.krate.item(id).kind {
                ItemKind::Fn(f) => match f.kind {
                    FnKind::Spec => Some(format!("{}:{}", SurfaceKind::SpecFn.tag(), self.path(id))),
                    FnKind::Law => Some(format!("{}:{}", SurfaceKind::Law.tag(), self.path(id))),
                    FnKind::Exec => {
                        if kind.is_value() && !self.established.contains(&g) {
                            self.error(key, span, format!("`{key}` depends on the exec function `{}`, which is not established", self.path(id)), closure_note);
                            return None;
                        }
                        self.add_fn(id)
                    }
                    FnKind::Lemma | FnKind::Proof => {
                        self.error(key, span, format!("`{key}` mentions the lemma `{}` in a relevant position", self.path(id)), "a statement may mention spec items and the functions it constrains; lemmas are proofs");
                        None
                    }
                },
                ItemKind::Const(_) => {
                    let it = self.krate.item(id);
                    // the free variables of an invariant include constants
                    // (DESIGN.md §15.3)
                    if kind.is_value() && !it.ghost && !matches!(kind, SurfaceKind::Invariant | SurfaceKind::EvidenceType) {
                        self.error(key, span, format!("`{key}` depends on the exec constant `{}`", it.path), closure_note);
                        return None;
                    }
                    self.add_const(id)
                }
                _ => None,
            },
            Role::Eq(id) => Some(self.add_type(id)),
            Role::View(id) => Some(format!("{}:{}", SurfaceKind::View.tag(), self.path(id))),
            Role::Represents(id) => Some(format!("{}:{}", SurfaceKind::Represents.tag(), self.path(id))),
            Role::Invariant(id) => Some(format!("{}:{}", SurfaceKind::Invariant.tag(), self.path(id))),
            Role::FnLemma(id) => {
                if kind.is_value() {
                    self.error(key, span, format!("`{key}` mentions a lemma of the exec function `{}`", self.path(id)), closure_note);
                    return None;
                }
                self.add_fn(id)
            }
            Role::LoopHelper(id) => {
                self.error(key, span, format!("`{key}` depends on a loop of the exec function `{}`", self.path(id)), closure_note);
                None
            }
            Role::Other(id) => {
                self.error(key, span, format!("`{key}` depends on `{}`, which is not a surface item", self.out.env.global_name(g).map(|n| n.to_string()).unwrap_or_else(|| self.path(id))), closure_note);
                None
            }
        }
    }
}

/// The models of the target-intrinsic calls in `f`'s body (`helper` calls
/// by the intrinsic their fixed template calls).
fn models_of(f: &FnDef) -> Vec<String> {
    struct V(Vec<String>);
    impl crate::visit::Visitor for V {
        fn expr(&mut self, e: &Expr) {
            match &e.kind {
                ExprKind::Call { callee: Callee::Intrinsic(i, _), .. } => self.0.push(crate::intrinsics::get(*i).name.to_string()),
                ExprKind::Call { callee: Callee::Helper(h), .. } => {
                    let info = crate::intrinsics::helper(*h);
                    let arch = info.arch.name();
                    let via = info.template.split(&format!("::core::arch::{arch}::")).nth(1).map(|r| r.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect::<String>());
                    self.0.push(via.unwrap_or_else(|| info.name.to_string()));
                }
                _ => {}
            }
            crate::visit::walk_expr(self, e);
        }
    }
    let mut v = V(vec![]);
    if let FnBody::Exec(b) = &f.body {
        crate::visit::Visitor::expr(&mut v, b);
    }
    v.0
}

/// The identity of a target model (model source hash, core hash, the
/// evidence record and the fail-closed verdict), and whether it is
/// registered.
pub fn model_identity(arch: &str, name: &str) -> String {
    use sandblaster_targets::evidence;
    use sandblaster_targets::registry::Arch;
    let Some(a) = Arch::from_name(arch) else { return format!("unknown architecture {arch}") };
    let mut s = String::new();
    match sandblaster_targets::registry::find(a, name) {
        Some(m) => s.push_str(&format!("model {}\n", evidence::model_hash(m))),
        None => s.push_str("model unregistered\n"),
    }
    match sandblaster_targets::coretext::find(a, name) {
        Some(c) => s.push_str(&format!("core {}\n", c.hash())),
        None => s.push_str("core none\n"),
    }
    match evidence::load(a) {
        Ok(file) => match file.records.iter().find(|r| r.name == name) {
            Some(r) => {
                s.push_str(&format!("record {} {} random {} corner {} mismatches {}\n", r.source_hash, r.status.as_str(), r.random_cases, r.corner_cases, r.mismatches));
                if let Some(c) = &r.core {
                    s.push_str(&format!("core-record {c:?}\n"));
                }
                let mut hosts: Vec<String> = r.hosts.iter().map(|h| format!("host {} {} {} {} random {} mismatches {}", h.cpu_key, h.executor, h.source_hash, h.status.as_str(), h.random_cases, h.mismatches)).collect();
                hosts.sort();
                for h in hosts {
                    s.push_str(&h);
                    s.push('\n');
                }
            }
            None => s.push_str("record none\n"),
        },
        Err(e) => s.push_str(&format!("evidence unavailable: {e}\n")),
    }
    s.push_str(&format!("verdict {:?}\n", evidence::validation(a, name)));
    s
}

/// Computes the surface of a verified elaboration (see the module docs).
pub fn compute(out: &Output, krate: &Crate, sm: &SourceMap, opts: &SurfaceOptions) -> Surface {
    compute_with_terms(out, krate, sm, opts).0
}

/// [`compute`], also returning every item's kernel statement (for
/// `crate::specdiff`, on the elaboration thread).
pub fn compute_with_terms(out: &Output, krate: &Crate, sm: &SourceMap, opts: &SurfaceOptions) -> (Surface, HashMap<String, Stmt>) {
    let tc = opts.toolchain.as_ref().unwrap_or_else(|| Toolchain::current());
    let arch = krate.target.arch.name().to_string();
    let reachable: HashSet<ItemId> = krate.reachable.iter().copied().collect();
    // the reachable items host code can call or name (`pub`, and the
    // non-private free functions of an in-place module)
    let boundary: HashSet<ItemId> = krate.items.iter().filter(|it| !it.ghost && crate::validate::host_visible(krate, it) && reachable.contains(&it.id)).map(|it| it.id).collect();
    let mut b = Builder {
        out,
        krate,
        sm,
        tc,
        canon: Canon::new(&out.env),
        roles: Builder::roles(out, krate),
        ind_items: out.adts.iter().map(|(i, x)| (*x, *i)).collect(),
        boundary,
        established: out.established.iter().copied().collect(),
        arch: arch.clone(),
        pending: BTreeMap::new(),
        queue: Vec::new(),
        deps: BTreeMap::new(),
        errors: Vec::new(),
        models: HashMap::new(),
    };
    // ---- roots ----
    // target models first (intrinsic globals resolve to them)
    let mut models: BTreeSet<String> = BTreeSet::new();
    for it in &krate.items {
        if let ItemKind::Fn(f) = &it.kind
            && f.kind == FnKind::Exec
            && !it.ghost
        {
            models.extend(models_of(f));
        }
    }
    for m in models {
        let key = format!("{}:{arch}:{m}", SurfaceKind::TargetModel.tag());
        let ident = model_identity(&arch, &m);
        let mut p = b.pending(key.clone(), SurfaceKind::TargetModel, None, String::new(), vec![format!("target model {arch}::{m}")], Stmt { parts: vec![], np: 0, recursive: false });
        p.path = format!("{arch}::{m}");
        p.statement.extend(ident.lines().map(|l| format!("  {l}")));
        p.extra.s("model").s(&ident);
        b.models.insert(format!("{arch}::{m}"), key);
        b.push(p);
    }
    for it in &krate.items {
        let id = it.id;
        match &it.kind {
            ItemKind::Fn(f) => match f.kind {
                FnKind::Spec => {
                    let Some(g) = b.global_of(id) else { continue };
                    let stmt = b.def_parts(g);
                    // the function itself (from `fn` to its end): its own
                    // attributes are other items (examples, vector files,
                    // `#[mirrors_impl]`) or not part of the meaning (docs)
                    let own = Span { lo: f.sig_span.lo, ..it.span };
                    let mut p = b.pending(format!("{}:{}", SurfaceKind::SpecFn.tag(), it.path), SurfaceKind::SpecFn, Some(id), snippet(sm, own), DeElab::new(krate, &f.locals).spec_fn(it, f), stmt);
                    p.span = f.sig_span;
                    // an `#[assumption]` (§15.13): its class and citation
                    // are what it means
                    if let Some(a) = &f.spec.assumption {
                        p.extra.s("assumption").s(a.class.name()).s(&a.cite);
                        p.statement.push(format!("  assumption ({}): {}", a.class.name(), a.cite));
                    }
                    b.push(p);
                    if let Some(j) = &f.spec.mirrors_impl {
                        let key = format!("{}:{}", SurfaceKind::MirrorsImpl.tag(), it.path);
                        let mut p = b.pending(key, SurfaceKind::MirrorsImpl, Some(id), snippet(sm, j.span), vec![format!("mirrors_impl on {}: {:?}", it.path, j.justification)], Stmt { parts: vec![], np: 0, recursive: false });
                        p.span = j.span;
                        p.extra.s("justification").s(&j.justification);
                        p.extra_items.push(format!("{}:{}", SurfaceKind::SpecFn.tag(), it.path));
                        // `#[mirrors_impl(of = f, ..)]` (§15.1 LR5): the
                        // exec function it is claimed to coincide with
                        if let Some(of) = f.spec.mirrors_of {
                            p.extra.s("of").s(&krate.item(of).path.to_string());
                            if let Some(k) = b.add_fn(of) {
                                p.extra_items.push(k);
                            }
                        }
                        // the exec functions refining it
                        let refiners: Vec<ItemId> = krate.items.iter().filter(|x| matches!(&x.kind, ItemKind::Fn(g) if g.spec.refines.as_ref().is_some_and(|r| r.spec == id))).map(|x| x.id).collect();
                        for r in refiners {
                            if let Some(k) = b.add_fn(r) {
                                p.extra_items.push(k);
                            }
                        }
                        b.push(p);
                    }
                }
                FnKind::Law | FnKind::Lemma if f.kind == FnKind::Law || f.spec.fuel_sufficient.is_some() => {
                    let kind = if f.kind == FnKind::Law { SurfaceKind::Law } else { SurfaceKind::FuelSufficient };
                    let Some(g) = b.def_named(&it.path.to_string()) else { continue };
                    let Some(ty) = out.env.global_type(g) else { continue };
                    let mut src = snippet(sm, f.sig_span);
                    // with the header `let`s where they are written
                    src.push_str(&f.contract_text(&|sp| snippet(sm, sp)));
                    // the law-rule annotations are part of the claim (what
                    // it assumes, whether it is a guarantee; §15.1 LR6, LR7,
                    // LR9): present only when written, so other laws keep
                    // their entries
                    if let Some((a, _)) = f.spec.reduces_to {
                        src.push_str(&format!(" #[reduces_to({})]", krate.item(a).path));
                    }
                    if let Some(d) = &f.spec.definitional {
                        src.push_str(&format!(" #[definitional(reason = {:?})]", d.justification));
                    }
                    if f.spec.corollary.is_some() {
                        src.push_str(" #[corollary]");
                    }
                    let stmt = Stmt { parts: vec![("type".into(), ty)], np: f.generics.len() + f.params.len(), recursive: false };
                    let mut st = DeElab::new(krate, &f.locals).law(it, f);
                    if kind == SurfaceKind::FuelSufficient {
                        st[0] = st[0].replacen("law ", "fuel_sufficient lemma ", 1);
                    }
                    let p = b.pending(format!("{}:{}", kind.tag(), it.path), kind, Some(id), src, st, stmt);
                    b.push(p);
                }
                FnKind::Exec if !it.ghost && (b.boundary.contains(&id) || f.spec.refines.is_some() || f.spec.trusted_extern.is_some()) => {
                    b.add_fn(id);
                }
                _ => {}
            },
            ItemKind::Const(_) => {
                if it.ghost || b.boundary.contains(&id) {
                    b.add_const(id);
                }
            }
            ItemKind::Struct(s) => {
                if b.boundary.contains(&id) {
                    b.add_type(id);
                }
                if let Some(v) = &s.view {
                    add_view(&mut b, it, v);
                }
                if let Some(r) = &s.represents
                    && let Some(g) = b.def_named(&format!("{}::represents", it.path))
                {
                    let stmt = b.def_parts(g);
                    let mut p = b.pending(format!("{}:{}", SurfaceKind::Represents.tag(), it.path), SurfaceKind::Represents, Some(id), snippet(sm, r.span), deelab::represents(krate, it, r), stmt);
                    p.span = r.span;
                    b.push(p);
                }
                if let Some(inv) = &s.invariant {
                    // the invariant's kernel meaning (S2): the definition of
                    // each conjunct `S::invariant#k` (an `Irr` constructor
                    // field of the type). Evidence types (a certified
                    // property as the invariant, §15.3) are invariant types
                    // too: one key, `invariant:S`, whatever the invariant is
                    // written with (a refactor into a spec function keeps the
                    // key); the spec functions it calls are recorded
                    let st = deelab::invariant(krate, it, inv);
                    // (an invariant attached from a ghost `#[lift]` module: as
                    // written there, `hir::Attached`)
                    let src: Vec<String> = match &krate.item(id).kind {
                        ItemKind::Struct(sd) if !sd.attached.is_empty() => sd.attached.iter().filter(|a| a.kind == "invariant").map(|a| a.text.clone()).collect(),
                        _ => inv.props.iter().map(|(_, sp)| snippet(sm, *sp)).collect(),
                    };
                    let mut parts = Vec::new();
                    let mut np = 0;
                    for k in 0.. {
                        let Some(g) = b.def_named(&format!("{}::invariant#{k}", it.path)) else { break };
                        let dp = b.def_parts(g);
                        np = dp.np;
                        parts.extend(dp.parts.into_iter().map(|(n, t)| (format!("invariant#{k} {n}"), t)));
                    }
                    let calls: Vec<String> = inv.props.iter().flat_map(|(e, _)| spec_fns_called(krate, e)).collect();
                    let kind = SurfaceKind::Invariant;
                    let mut p = b.pending(format!("{}:{}", kind.tag(), it.path), kind, Some(id), src.join(" "), st.clone(), Stmt { parts, np, recursive: false });
                    p.extra.s("invariant").s(&st.join("\n"));
                    if !calls.is_empty() {
                        p.extra.s("calls").s(&calls.join(" "));
                    }
                    p.extra_items.push(b.type_key(id));
                    b.add_type(id);
                    b.push(p);
                }
            }
            ItemKind::Enum(e) => {
                if b.boundary.contains(&id) {
                    b.add_type(id);
                }
                if let Some(v) = &e.view {
                    add_view(&mut b, it, v);
                }
            }
            ItemKind::TypeAlias(_) => {
                if b.boundary.contains(&id) {
                    b.add_type(id);
                }
            }
        }
        // vector files (on any item)
        if let ItemKind::Fn(f) = &it.kind {
            for (j, file) in f.spec.example_files.iter().enumerate() {
                let key = format!("{}:{}#{j}", SurfaceKind::VectorFile.tag(), it.path);
                let content = sha256(file.text.as_bytes());
                let fmt = match file.format {
                    ExampleFormat::Cavp => "cavp",
                    ExampleFormat::Json => "json",
                };
                let prov = match file.provenance {
                    Provenance::Independent => "independent",
                    Provenance::Production => "production",
                    Provenance::SelfDerived => "self",
                };
                // the records the kernel checked (every record of a verified
                // crate): locked with the content, so a file whose records
                // stop being read (merged, dropped) changes the entry
                let checked = out.examples.iter().filter(|e| e.item == id && e.status == crate::elab::DefStatus::Checked && matches!(e.source, crate::elab::examples::ExampleSource::File { file: x, .. } if x == file.file)).count();
                let st = vec![format!("vectors #{j} of {}: file {:?}, format {fmt}, provenance {prov}, {checked} record(s) checked, {} line(s), sha256 {}", it.path, file.path, file.text.lines().count(), hex(&content))];
                let mut p = b.pending(key, SurfaceKind::VectorFile, Some(id), snippet(sm, file.span), st, Stmt { parts: vec![], np: 0, recursive: false });
                p.span = file.span;
                p.extra.s("file").s(&file.path).s(fmt).s(prov).h(&content).s(&checked.to_string());
                let owner = match f.kind {
                    FnKind::Spec => Some(format!("{}:{}", SurfaceKind::SpecFn.tag(), it.path)),
                    FnKind::Exec => b.add_fn(id),
                    _ => None,
                };
                p.extra_items.extend(owner);
                b.push(p);
            }
        }
    }
    // examples (the checked closed terms)
    for ex in &out.examples {
        let crate::elab::examples::ExampleSource::Attr { index } = ex.source else { continue };
        let Some(t) = &ex.term else { continue };
        let it = krate.item(ex.item);
        let Some(src) = krate.examples_of(ex.item).get(index as usize) else { continue };
        let key = format!("{}:{}#{index}", SurfaceKind::Example.tag(), it.path);
        // its text: as written, or, in a ghost `#[lift]` module (the laws
        // file), its tokens (the lift re-emits the attribute without spans)
        let text = if krate.module(it.module).lift_ghost { src.text.clone() } else { snippet(sm, src.span) };
        let mut p = b.pending(key, SurfaceKind::Example, Some(ex.item), text, deelab::example(krate, it, index as usize, src), Stmt { parts: vec![("term".into(), t.clone())], np: 0, recursive: false });
        p.span = src.span;
        b.push(p);
    }
    // computed sections (§15.5, S3): `R`, `P(R)`, `H(R)`, `Deps(R)` and the
    // kernel's `complete_p` statements (hashed; their proof status is a
    // build result, not part of the specification, and is not locked)
    for sec in &out.sections {
        let Some(&first) = sec.published.first().or(sec.members.first()) else { continue };
        let key = format!("{}:{}", SurfaceKind::Section.tag(), krate.item(first).path);
        let st = section_statement(krate, sec);
        let parts: Vec<(String, Tm)> = sec.statements.iter().map(|c| (format!("complete:{}", krate.item(c.item).path), c.statement.clone())).collect();
        let mut p = b.pending(key, SurfaceKind::Section, Some(first), String::new(), st.clone(), Stmt { parts, np: 0, recursive: false });
        p.span = sec.span;
        p.extra.s("section").s(&st.join("\n"));
        p.notes.push(format!("status (this build, not locked): {} — position {} in the well-founded order", sec.status.word(), sec.index));
        for c in &sec.statements {
            p.notes.push(format!("complete_{}: {}{}", krate.item(c.item).path, crate::driver::def_status_str(&c.status), if c.proof.is_empty() { String::new() } else { format!(" ({})", c.proof) }));
        }
        p.notes.extend(sec.problems.iter().cloned());
        for m in sec.members.iter().chain(&sec.deps) {
            let k = match &krate.item(*m).kind {
                ItemKind::Const(_) => b.add_const(*m),
                _ => b.add_fn(*m),
            };
            p.extra_items.extend(k);
        }
        // its laws (the other hypotheses are the members' contracts)
        for (kind, name) in &sec.hyps {
            let key = format!("{}:{name}", SurfaceKind::Law.tag());
            if kind == "law" && b.pending.contains_key(&key) {
                p.extra_items.push(key);
            }
        }
        b.push(p);
    }
    // ---- close under Refs₁ ----
    while let Some(k) = b.queue.pop() {
        b.resolve(&k);
    }
    // ---- hash ----
    let keys: Vec<String> = b.pending.keys().cloned().collect();
    let mut locals: HashMap<String, (Hash, Hash)> = HashMap::new();
    let mut nodes = Vec::new();
    for k in &keys {
        let p = &b.pending[k];
        let canon = statement_canon(&mut b.canon, &p.stmt.parts, &p.extra.0);
        let src = sha256(p.source.as_bytes());
        let local = item_local(p.kind, k, &canon, &src);
        locals.insert(k.clone(), (canon, src));
        let (items, ext) = b.deps.get(k).cloned().unwrap_or_default();
        nodes.push(MNode { key: k.clone(), local, items, ext });
    }
    let (hashes, cycles) = merkle(&nodes);
    let hash_of: HashMap<String, Hash> = keys.iter().cloned().zip(hashes.iter().copied()).collect();
    let mut items = Vec::new();
    let mut terms = HashMap::new();
    let limit = opts.kernel_text_limit;
    for ((k, n), cyc) in keys.iter().zip(&nodes).zip(&cycles) {
        let p = b.pending.remove(k).unwrap();
        let (canon, src) = locals[k];
        let mut deps: Vec<Dep> = n.items.iter().map(|d| Dep { name: d.clone(), item: true, cycle: cyc.contains(d), hash: hash_of.get(d).copied().unwrap_or([0; 32]) }).collect();
        deps.extend(n.ext.iter().map(|(d, h)| Dep { name: d.clone(), item: false, cycle: false, hash: *h }));
        deps.sort();
        let mut kernel = Vec::new();
        let mut omitted = Vec::new();
        if opts.kernel_text && p.kind.has_kernel_text() {
            for (name, t) in &p.stmt.parts {
                let text = sandblaster_kernel::syntax::printer::print_term_bounded(&out.env, &[], t, limit);
                if text.len() > limit || text.contains('@') {
                    omitted.push(name.clone());
                } else {
                    kernel.push((name.clone(), text));
                }
            }
        }
        terms.insert(k.clone(), p.stmt.clone());
        items.push(SurfaceItem { key: k.clone(), kind: p.kind, path: p.path, item: p.item, span: p.span, source: p.source, statement: p.statement, kernel, kernel_omitted: omitted, canon, src, deps, hash: hash_of[k], notes: p.notes });
    }
    let target_model = tc.target.get(&arch).copied().unwrap_or([0; 32]);
    // the review surface (module docs, *What is locked*): proof internals
    // are hashed like everything else but never locked
    let (items, internal) = review_surface(items, krate, &b.boundary);
    let kept: HashSet<String> = items.iter().map(|i| i.key.clone()).collect();
    terms.retain(|k, _| kept.contains(k));
    let mut errors: Vec<SurfaceError> = b.errors.into_iter().filter(|e| kept.contains(&e.key)).collect();
    errors.extend(proof_file_errors(&items, krate));
    errors.extend(attached_proof_file_errors(&items, krate, &b.boundary));
    // a lifted crate loads the lift prelude (`crate::__lift`, `loader.rs`)
    let lift = krate.modules.iter().any(|m| m.parent == Some(krate.root) && m.name == "__lift").then_some(tc.lift);
    let surface = Surface { target: arch, kernel: tc.kernel, prelude: tc.prelude, semantics: tc.semantics, builtins: tc.builtins, lift, target_model, items, errors, laws: crate::elab::law_rules::law_table(krate), internal };
    (surface, terms)
}

/// The kept items that a lifted crate's proof file defines (an item of a
/// ghost `#[lift]` module other than the laws file, `crate::proof::*`):
/// proof internals that a locked statement reaches. A reviewer reads the
/// laws file and the vocabulary it needs, never the proof file, so each is
/// an error (DESIGN.md §15.6) — the lock would hold an agent artifact.
fn proof_file_errors(items: &[SurfaceItem], krate: &Crate) -> Vec<SurfaceError> {
    let mut out = Vec::new();
    for i in items {
        let Some(id) = i.item else { continue };
        let Some(m) = krate.lift_proof_file(id) else { continue };
        let users: Vec<&str> = items.iter().filter(|u| u.deps.iter().any(|d| d.item && d.name == i.key)).map(|u| u.key.as_str()).take(3).collect();
        out.push(SurfaceError {
            key: i.key.clone(),
            span: i.span,
            msg: format!("`{}` is a proof internal (it is defined in the proof file `{}`), but the review surface reaches it{}", i.path, krate.module(m).path, if users.is_empty() { String::new() } else { format!(" through {}", users.iter().map(|u| format!("`{u}`")).collect::<Vec<_>>().join(", ")) }),
            note: "a locked statement may use only the laws file's vocabulary: state what the reviewer needs in the laws file (LAWS.rs), or keep the statement that uses it a proof-internal summary or lemma in the proof file (DESIGN.md §15.6)".into(),
        });
    }
    out
}

/// The source text of a lifted function's attached contract
/// ([`crate::hir::Attached`]): the laws file's `requires`, `decreases` and
/// `ensures`, in file order. Nothing a proof file attaches: its `ensures`
/// is a proof-internal summary, its plain termination measure
/// (`decreases(e)`) is proof text, and a `requires` or depth bound from it
/// on a locked item is refused ([`attached_proof_file_errors`]).
fn attached_src(attached: &[crate::hir::Attached]) -> String {
    let mut out = String::new();
    for a in attached {
        if !a.in_laws {
            continue;
        }
        out.push_str(&format!(" {}({})", a.kind, a.text));
    }
    out
}

/// The statements a proof file attached to a locked item (DESIGN.md
/// §15.6): a `requires` or a depth bound (`decreases(.., max = ..)`) of a
/// function whose contract or signature is locked — part of its type,
/// whether it is a boundary function or a function a law or contract
/// mentions — or an invariant of a locked type (a boundary type, a type
/// the vocabulary mentions, or the invariant item itself). The lock holds
/// only what the laws file states, so each is an error naming the item and
/// the proof file; the same statement in the laws file is not.
fn attached_proof_file_errors(items: &[SurfaceItem], krate: &Crate, boundary: &HashSet<ItemId>) -> Vec<SurfaceError> {
    let mut out = Vec::new();
    let mut seen: HashSet<ItemId> = HashSet::new();
    for i in items {
        let Some(id) = i.item else { continue };
        let locks_it = matches!(i.kind, SurfaceKind::BoundarySignature | SurfaceKind::Contract | SurfaceKind::TrustedExtern | SurfaceKind::BoundaryType | SurfaceKind::Type | SurfaceKind::Invariant);
        if !locks_it || !seen.insert(id) {
            continue;
        }
        let it = krate.item(id);
        let what_item = if boundary.contains(&id) { "boundary item" } else { "locked item" };
        let attached: Vec<(&crate::hir::Attached, &str)> = match &it.kind {
            ItemKind::Fn(f) => f
                .spec
                .attached
                .iter()
                .filter_map(|a| match a.kind.as_str() {
                    "requires" => Some((a, "precondition")),
                    "decreases" if f.decreases.as_ref().is_some_and(|d| d.max.is_some()) => Some((a, "recursion depth bound")),
                    _ => None,
                })
                .collect(),
            ItemKind::Struct(sd) => sd.attached.iter().filter(|a| a.kind == "invariant").map(|a| (a, "invariant")).collect(),
            _ => vec![],
        };
        for (a, what) in attached {
            if a.in_laws {
                continue;
            }
            out.push(SurfaceError {
                key: i.key.clone(),
                span: i.span,
                msg: format!("the {what_item} `{}` has a {what} attached from the proof file `{}` (`{}({})`): the lock would hold a proof file's statement", it.path, a.module, a.kind, a.text),
                note: "a locked item's preconditions, depth bound and invariant are part of the locked surface, which is the laws file's: move the attachment to the laws file (LAWS.rs), where the reviewer reads it (DESIGN.md §15.6)".into(),
            });
        }
    }
    out
}

/// Whether an item is a **root** of the review surface (module docs, *What
/// is locked*): a law, a boundary signature, type or constant, a
/// `#[refines]` contract, a trusted extern, a target model, a section, a
/// vector file (external known answers) or an `#[assumption]`.
fn review_root(i: &SurfaceItem, krate: &Crate, boundary: &HashSet<ItemId>) -> bool {
    let f = || i.item.and_then(|id| krate.fn_def(id));
    match i.kind {
        SurfaceKind::Law | SurfaceKind::BoundarySignature | SurfaceKind::BoundaryType | SurfaceKind::TrustedExtern | SurfaceKind::TargetModel | SurfaceKind::Section | SurfaceKind::VectorFile => true,
        SurfaceKind::Constant => i.item.is_some_and(|id| boundary.contains(&id)),
        SurfaceKind::Contract => f().is_some_and(|f| f.spec.refines.is_some()),
        SurfaceKind::SpecFn => f().is_some_and(|f| f.spec.assumption.is_some()),
        _ => false,
    }
}

/// The review surface of the computed items (module docs, *What is
/// locked*): the roots, closed under statement dependencies, with the
/// validation items (examples, vector files, `#[mirrors_impl]`,
/// `#[fuel_sufficient]`) of the items in it, closed again, to a fixpoint.
/// Returns the kept items (sorted, as given) and the keys of the others
/// (the proof internals), sorted. The kept set is closed under `deps`, so
/// every kept item's hash is unchanged by the filter.
pub fn review_surface(items: Vec<SurfaceItem>, krate: &Crate, boundary: &HashSet<ItemId>) -> (Vec<SurfaceItem>, Vec<String>) {
    let by_key: HashMap<&str, &SurfaceItem> = items.iter().map(|i| (i.key.as_str(), i)).collect();
    let mut kept: BTreeSet<String> = BTreeSet::new();
    let mut work: Vec<String> = items.iter().filter(|i| review_root(i, krate, boundary)).map(|i| i.key.clone()).collect();
    loop {
        while let Some(k) = work.pop() {
            if !kept.insert(k.clone()) {
                continue;
            }
            if let Some(i) = by_key.get(k.as_str()) {
                work.extend(i.deps.iter().filter(|d| d.item && !kept.contains(&d.name)).map(|d| d.name.clone()));
            }
        }
        // the items whose meaning is on the surface: examples, vector files
        // and mirrors of theirs, and the fuel claims about its spec functions
        let owners: HashSet<ItemId> = kept
            .iter()
            .filter_map(|k| by_key.get(k.as_str()))
            .filter(|i| matches!(i.kind, SurfaceKind::SpecFn | SurfaceKind::SpecConst | SurfaceKind::Contract | SurfaceKind::BoundarySignature | SurfaceKind::TrustedExtern))
            .filter_map(|i| i.item)
            .collect();
        for i in &items {
            if kept.contains(&i.key) {
                continue;
            }
            let attached = match i.kind {
                SurfaceKind::Example | SurfaceKind::VectorFile | SurfaceKind::MirrorsImpl => i.item.is_some_and(|id| owners.contains(&id)),
                SurfaceKind::FuelSufficient => i.deps.iter().any(|d| d.item && d.name.starts_with("spec-fn:") && kept.contains(&d.name)),
                _ => false,
            };
            if attached {
                work.push(i.key.clone());
            }
        }
        if work.is_empty() {
            break;
        }
    }
    let (keep, drop): (Vec<SurfaceItem>, Vec<SurfaceItem>) = items.into_iter().partition(|i| kept.contains(&i.key));
    (keep, drop.into_iter().map(|i| i.key).collect())
}

/// The statement lines of a section entry (the lock's `|` lines; the
/// header's `section` lines are derived from the first four).
pub fn section_statement(krate: &Crate, sec: &crate::elab::complete::SectionRecord) -> Vec<String> {
    let names = |ids: &[ItemId]| ids.iter().map(|i| krate.item(*i).path.to_string()).collect::<Vec<_>>().join(", ");
    let hyps = sec.hyps.iter().map(|(k, n)| format!("{k} {n}")).collect::<Vec<_>>().join(", ");
    let mut st = vec![
        format!("section R = {{{}}}", names(&sec.members)),
        format!("  P(R) = {{{}}}", names(&sec.published)),
        format!("  Deps(R) = {{{}}}", names(&sec.deps)),
        format!("  H(R) = {{{hyps}}}"),
    ];
    if sec.merged {
        st.push("  merged by #[section(with = ..)]".to_string());
    }
    for c in &sec.statements {
        st.push(format!("  complete_{}(R) : {}", krate.item(c.item).path, c.surface));
    }
    if sec.statements.is_empty() {
        st.push("  (no completeness statement: the kernel could not state the section)".to_string());
    }
    st
}

fn add_view(b: &mut Builder, it: &Item, v: &View) {
    let Some(g) = b.def_named(&format!("{}::view", it.path)) else { return };
    let stmt = b.def_parts(g);
    let mut p = b.pending(format!("{}:{}", SurfaceKind::View.tag(), it.path), SurfaceKind::View, Some(it.id), snippet(b.sm, v.span()), deelab::view(b.krate, it, v), stmt);
    p.span = v.span();
    b.push(p);
}

/// The spec functions an invariant calls, by path, sorted (recorded with
/// its entry: DESIGN.md §15.3 evidence types).
fn spec_fns_called(krate: &Crate, e: &Expr) -> Vec<String> {
    struct V<'k>(&'k Crate, std::collections::BTreeSet<String>);
    impl crate::visit::Visitor for V<'_> {
        fn expr(&mut self, e: &Expr) {
            if let ExprKind::Call { callee: Callee::Item(id, _), .. } = &e.kind
                && self.0.fn_def(*id).is_some_and(|f| f.kind == FnKind::Spec)
            {
                self.1.insert(self.0.item(*id).path.to_string());
            }
            crate::visit::walk_expr(self, e);
        }
    }
    let mut v = V(krate, Default::default());
    crate::visit::Visitor::expr(&mut v, e);
    v.1.into_iter().collect()
}
