//! Item collection and name resolution (DESIGN.md §3.1, §3.6).
//!
//! The [`Resolver`] is built from the loaded module tree:
//!
//! 1. **Collection** — every item gets an [`ItemId`] (modules in load order,
//!    items in source order; inherent-impl functions at the impl's position)
//!    and is entered into its module's namespaces (type namespace: modules,
//!    structs, enums, aliases; value namespace: functions, consts, tuple/unit
//!    struct constructors). Items outside the subset (traits, trait impls,
//!    statics, macros, unions, extern blocks) are rejected here.
//! 2. **Imports** — `use` trees (explicit paths via `crate::`, `super::`,
//!    `self::`, local names, `core::`, `sandblaster::`; renames; groups; `self`
//!    in groups) are resolved to a fixpoint. Glob imports are only allowed
//!    from `sandblaster::prelude`, `core::arch::aarch64` and `core::arch::x86_64`
//!    (resolved against the target table, §9.2).
//! 3. **Lookup** — [`Resolver::lookup`] implements Rust's module-level
//!    scoping: explicit items and imports of the module, then glob imports,
//!    then (for single-segment paths) the standard prelude (`Option`, `Some`,
//!    `None`; primitive types are handled by the type lowering) and, in ghost
//!    code, the ghost prelude (`Int`, `Prop`, `forall`, `exists`, `implies`,
//!    `iff`, `eqb`, `seq`, `ISIZE_MAX`). Items of parent modules are **not**
//!    visible in child modules (Rust semantics). Locals are handled by the
//!    type checker's lexical scopes and shadow items in the value namespace.
//!
//! Privacy is checked like rustc (private items are visible in their module
//! and its descendants; `pub(super)`; `pub(crate)`/`pub`), so the checker
//! never accepts a program rustc rejects for privacy reasons.
//!
//! **Prelude lemmas** (DESIGN.md §4.5) are addressable from ghost code as
//! `sandblaster::lemmas::<module>::<name>`, mirroring their kernel names
//! (`slice::first_chunk_exact` ↦ `sandblaster::lemmas::slice::first_chunk_exact`),
//! or through `use sandblaster::lemmas::*;` in ghost modules. The signature
//! table comes from the loaded core lemma files
//! ([`crate::auto::surface::table`]); every lemma whose name occurs in the
//! crate's sources becomes a synthetic ghost `#[lemma]` item (path
//! `{prelude}::lemmas::..`, never printed, not in any module's namespace)
//! that the type checker treats like a user lemma and the elaborator maps to
//! the kernel lemma. Through the glob, lemma modules named like primitive
//! types (`bool`, `u8`, ..) are not visible (they would shadow the types);
//! `seq::*` names that are not lemmas fall back to the ghost `seq` functions.
//!
//! The identifier-pattern rule of §3.3 uses [`Resolver::pattern_hazard`]:
//! the set of every const, unit struct and unit variant name anywhere in the
//! crate (ghost items included) and the prelude.
//!
//! An inherent associated function named like a variant of its enum is
//! rejected once impl owners are resolved: rustc reads `E::name` and
//! `<E>::name` as the variant (`check_variant_named_fns`).

use std::collections::{HashMap, HashSet};

use syn::spanned::Spanned;

use crate::builtins::GhostFn;
use crate::diag::{DiagKind, Diagnostic, Diagnostics};
use crate::hir::{DefPath, ItemId, ModId, Shape, Ty, Vis};
use crate::intrinsics::{self, HelperId, IntrinsicId, VecTy};
use crate::loader::Loaded;
use crate::span::{FileId, Span};
use crate::target::{Arch, TargetInfo};

/// sandblaster annotations (attribute macros and `proof!`), §4 and §15.
///
/// Every variant but [`Annot::ProofMacro`] is an attribute exported by the
/// facade (`sandblaster::prelude`, and `sandblaster::ghost` for `#[proof]`) as an
/// erasing macro of `sandblaster-macros`, under [`Annot::name`]; a test checks
/// that the three lists agree.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Annot {
    Requires,
    Ensures,
    Decreases,
    Implements,
    Specialize,
    /// `#[spec]` on a function, or on a module declaration (§15.1).
    Spec,
    Lemma,
    Law,
    /// `#[proof]`, `#[proof(refines = f)]`, `#[proof(complete = f)]`.
    Proof,
    /// `#[rewrite]` on a law (optimizer rewrite, later milestone, §4.5).
    Rewrite,
    /// `#[induction(x)]` on a `#[lemma]`/`#[proof]`/inline `#[law]`: the
    /// proof recurses on `x` (its `ih(..)` steps, §4.4).
    Induction,
    /// `#[refines(s)]` / `#[refines(s(args..))]` / `#[refines(s, domain =
    /// P)]` on an exec function (§15.2). Never on a type (§9.6: types use
    /// `#[view]` and `#[invariant]`).
    Refines,
    /// `#[example(e)]` (§15.7).
    Example,
    /// `#[examples(file = "..", format = .., provenance = ..)]` (§15.7).
    Examples,
    /// `#[invariant(p)]` on a struct (§15.3).
    Invariant,
    /// `#[view(spec::T)]` / `#[view(|s| e)]` on a type (§15.3).
    View,
    /// `#[represents(|s, a| P)]` on a struct (§15.3).
    Represents,
    /// `#[ghost]` on an exec function parameter (§15.3).
    Ghost,
    /// `#[section(with = [..])]` on an exec function (§15.5).
    Section,
    /// `#[mirrors_impl(justification = "..")]` on a spec fn (§15.1).
    MirrorsImpl,
    /// `#[fuel_sufficient]` on a lemma (§15.1).
    FuelSufficient,
    /// `#[trusted_extern(justification = "..")]` on an exec function
    /// (§15.8).
    TrustedExtern,
    /// `#[reduces_to(a)]` on a law in extraction form: `a` names an
    /// `#[assumption]` (§15.1 LR4, LR9; §15.13).
    ReducesTo,
    /// `#[assumption(class = .., cite = "..")]` on a spec function without
    /// logical content (§15.13).
    Assumption,
    /// `#[definitional(reason = "..")]` on a law that is intentionally one
    /// unfolding of a definition (§15.1 LR6).
    Definitional,
    /// `#[corollary]` on a law proven from other laws (§15.1 LR7).
    Corollary,
    /// `#[opaque]` on a spec function (DESIGN.md §5.6, §15 S5): the kernel
    /// definition is opaque in proofs (used through `unfold`/`by_unfolding`),
    /// e.g. a hash that must not be unrolled during proof search.
    Opaque,
    /// The `proof!` macro.
    ProofMacro,
}

impl Annot {
    /// Every attribute annotation (all variants but [`Annot::ProofMacro`]).
    pub const ALL: &'static [Annot] = &[
        Annot::Requires,
        Annot::Ensures,
        Annot::Decreases,
        Annot::Implements,
        Annot::Specialize,
        Annot::Spec,
        Annot::Lemma,
        Annot::Law,
        Annot::Proof,
        Annot::Rewrite,
        Annot::Induction,
        Annot::Refines,
        Annot::Example,
        Annot::Examples,
        Annot::Invariant,
        Annot::View,
        Annot::Represents,
        Annot::Ghost,
        Annot::Section,
        Annot::MirrorsImpl,
        Annot::FuelSufficient,
        Annot::TrustedExtern,
        Annot::ReducesTo,
        Annot::Assumption,
        Annot::Definitional,
        Annot::Corollary,
        Annot::Opaque,
    ];

    /// The attribute name (`proof` for the macro).
    pub fn name(self) -> &'static str {
        match self {
            Annot::Requires => "requires",
            Annot::Ensures => "ensures",
            Annot::Decreases => "decreases",
            Annot::Implements => "implements",
            Annot::Specialize => "specialize",
            Annot::Spec => "spec",
            Annot::Lemma => "lemma",
            Annot::Law => "law",
            Annot::Proof | Annot::ProofMacro => "proof",
            Annot::Rewrite => "rewrite",
            Annot::Induction => "induction",
            Annot::Refines => "refines",
            Annot::Example => "example",
            Annot::Examples => "examples",
            Annot::Invariant => "invariant",
            Annot::View => "view",
            Annot::Represents => "represents",
            Annot::Ghost => "ghost",
            Annot::Section => "section",
            Annot::MirrorsImpl => "mirrors_impl",
            Annot::FuelSufficient => "fuel_sufficient",
            Annot::TrustedExtern => "trusted_extern",
            Annot::ReducesTo => "reduces_to",
            Annot::Assumption => "assumption",
            Annot::Definitional => "definitional",
            Annot::Corollary => "corollary",
            Annot::Opaque => "opaque",
        }
    }

    pub fn from_name(s: &str) -> Option<Annot> {
        Annot::ALL.iter().copied().find(|a| a.name() == s)
    }

    /// Whether this is one of the §15 annotations (DESIGN.md §15).
    pub fn is_spec15(self) -> bool {
        matches!(self, Annot::Refines | Annot::Example | Annot::Examples | Annot::Invariant | Annot::View | Annot::Represents | Annot::Ghost | Annot::Section | Annot::MirrorsImpl | Annot::FuelSufficient | Annot::TrustedExtern | Annot::ReducesTo | Annot::Assumption | Annot::Definitional | Annot::Corollary)
    }
}

/// The diagnostic for any form of `sandblaster::critical` (DESIGN.md §15.8:
/// there is no profile, attribute, `cfg`, feature, environment variable or
/// build option that switches §15 on or off; it is always on).
pub fn critical_diagnostic(span: Span) -> Diagnostic {
    Diagnostic::error(DiagKind::Attribute, span, "`sandblaster::critical` does not exist: all of §15 (correct by construction) is mandatory for every sandblaster crate, so there is no profile to select")
        .note("remove it; nothing needs to be switched on (DESIGN.md §15, §15.8)")
}

/// Whether a token stream mentions `critical` as `sandblaster::critical` (or
/// `sandblaster::prelude::critical`, ..) or as a bare attribute name.
pub fn mentions_critical(ts: proc_macro2::TokenStream) -> bool {
    ts.into_iter().any(|t| match t {
        proc_macro2::TokenTree::Ident(id) => id == "critical",
        proc_macro2::TokenTree::Group(g) => mentions_critical(g.stream()),
        _ => false,
    })
}

/// Whether an attribute path is `critical` / `sandblaster::critical` /
/// `sandblaster::{prelude,ghost}::critical`.
pub fn is_critical_path(p: &syn::Path) -> bool {
    let segs: Vec<String> = p.segments.iter().map(|s| s.ident.to_string()).collect();
    match segs.as_slice() {
        [n] => n == "critical",
        [r, .., n] => r == "sandblaster" && n == "critical",
        _ => false,
    }
}

/// Whether an attribute is any form of `sandblaster::critical`, including
/// `cfg_attr(.., sandblaster::critical)`.
pub fn is_critical_attr(a: &syn::Attribute) -> bool {
    if is_critical_path(a.path()) {
        return true;
    }
    match &a.meta {
        syn::Meta::List(l) if a.path().is_ident("cfg_attr") => mentions_critical(l.tokens.clone()),
        _ => false,
    }
}

/// Ghost prelude keywords that are expression forms rather than functions.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum GhostKw {
    Forall,
    Exists,
    Implies,
    Iff,
}

/// Definitions outside the DSL crate (core, sandblaster facade, preludes).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Ext {
    /// The `core` (or `std`) crate root.
    Core,
    /// `core::arch`
    CoreArch,
    /// `core::arch::aarch64` / `core::arch::x86_64`
    ArchMod(ArchTag),
    Intrinsic(IntrinsicId),
    VecType(VecTy),
    /// `__mmask8` (u8) / `__mmask16` (u16)
    MaskType(u8),
    /// `core::option`
    CoreOption,
    /// `Option`
    OptionEnum,
    SomeCtor,
    NoneCtor,
    /// The `sandblaster` crate.
    Sandblaster,
    /// `sandblaster::prelude`
    SandblasterPrelude,
    /// `sandblaster::ghost` (ghost-item attributes, including `#[proof]`)
    SandblasterGhost,
    /// `sandblaster::arch`
    SandblasterArch,
    /// `sandblaster::arch::aarch64` / `x86_64`
    HelperMod(ArchTag),
    Helper(HelperId),
    Annotation(Annot),
    /// Ghost type `Int`.
    IntTy,
    /// Ghost type `Prop`.
    PropTy,
    /// Ghost type `Nat` (§4.1, S1).
    NatTy,
    /// Ghost type `Seq<T>` (§4.1, S1); as a path prefix, `Seq::repeat` etc.
    SeqTy,
    /// Ghost module `seq`.
    SeqMod,
    GhostFn(GhostFn),
    GhostKw(GhostKw),
    /// Ghost constant `ISIZE_MAX`.
    IsizeMax,
    /// `sandblaster::lemmas` (prelude lemmas, DESIGN.md §4.5).
    Lemmas,
    /// A module below `sandblaster::lemmas` (index into
    /// [`Resolver::lemma_mods`]), e.g. `sandblaster::lemmas::slice`.
    LemmaMod(u32),
}

/// Copyable architecture tag.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ArchTag {
    Aarch64,
    X86_64,
}

impl ArchTag {
    pub fn arch(self) -> Arch {
        match self {
            ArchTag::Aarch64 => Arch::Aarch64,
            ArchTag::X86_64 => Arch::X86_64,
        }
    }
    fn from_name(s: &str) -> Option<ArchTag> {
        match s {
            "aarch64" => Some(ArchTag::Aarch64),
            "x86_64" => Some(ArchTag::X86_64),
            _ => None,
        }
    }
}

/// What a name resolves to.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Def {
    Mod(ModId),
    Item(ItemId),
    Variant(ItemId, u32),
    Ext(Ext),
}

/// A binding found by a lookup inside a container.
#[derive(Clone, Copy, Debug)]
pub struct Found {
    pub def: Def,
    pub vis: Vis,
    pub ghost: bool,
    /// Module whose namespace holds the binding (`None` for external
    /// definitions and enum variants, which are as visible as their enum).
    pub home: Option<ModId>,
}

/// Namespaces.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Ns {
    Type,
    Value,
    Macro,
}

#[derive(Clone, Debug)]
struct Binding {
    def: Def,
    vis: Vis,
    span: Span,
    ghost: bool,
    /// Introduced by a `use` (not an item or `mod` declared here).
    import: bool,
}

#[derive(Clone, Debug, Default)]
struct Scope {
    types: HashMap<String, Binding>,
    values: HashMap<String, Binding>,
    macros: HashMap<String, Binding>,
    /// Glob sources: `sandblaster::prelude`, `core::arch::<arch>`.
    globs: Vec<(Ext, bool)>,
}

impl Scope {
    fn ns(&self, ns: Ns) -> &HashMap<String, Binding> {
        match ns {
            Ns::Type => &self.types,
            Ns::Value => &self.values,
            Ns::Macro => &self.macros,
        }
    }
    fn ns_mut(&mut self, ns: Ns) -> &mut HashMap<String, Binding> {
        match ns {
            Ns::Type => &mut self.types,
            Ns::Value => &mut self.values,
            Ns::Macro => &mut self.macros,
        }
    }
}

/// Syntactic source of an item, kept for signature/body lowering.
#[derive(Clone)]
pub enum ItemSrc {
    Struct(syn::ItemStruct),
    Enum(syn::ItemEnum),
    Const(syn::ItemConst),
    Type(syn::ItemType),
    Fn(syn::ItemFn),
    /// A function of an inherent impl; `impl_idx` indexes [`Resolver::impls`].
    ImplFn { impl_idx: usize, f: syn::ImplItemFn },
}

/// Coarse item kind for resolution.
#[derive(Clone, Debug, PartialEq)]
pub enum ItemTag {
    Struct { shape: Shape, generics: usize },
    Enum { variants: Vec<(String, Shape)>, generics: usize },
    Const,
    Fn,
    Alias,
}

/// Collected information about an item.
#[derive(Clone)]
pub struct ItemInfo {
    pub id: ItemId,
    pub name: String,
    pub path: DefPath,
    pub module: ModId,
    pub vis: Vis,
    pub ghost: bool,
    pub span: Span,
    pub cfg: Option<String>,
    pub tag: ItemTag,
    pub src: ItemSrc,
    /// For inherent functions: the type they belong to (after resolution).
    pub owner: Option<ItemId>,
}

/// Collected information about a module.
#[derive(Clone)]
pub struct ModInfo {
    pub id: ModId,
    pub name: String,
    pub parent: Option<ModId>,
    pub ghost: bool,
    pub vis: Vis,
    pub file: FileId,
    pub span: Span,
    pub path: DefPath,
    pub children: Vec<ModId>,
    pub items: Vec<ItemId>,
    pub inner_attrs: Vec<syn::Attribute>,
    pub decl_attrs: Vec<syn::Attribute>,
    pub cfg: Option<String>,
    /// A `#[spec]` module or a module inside one (§15.1).
    pub spec: bool,
    /// A `#[model]` module or a module inside one (layered proofs): its
    /// functions are spec functions, but it is proof, not specification.
    pub model: bool,
    /// A `#[bridges]` module (layered proofs): its lemmas are rules of
    /// `auto`.
    pub bridges: bool,
    /// Data files read for `#[examples(file = "..")]` attributes of this
    /// module's items, by the path as written (§15.7).
    pub data_files: HashMap<String, FileId>,
    /// A lifted module (`#[lift]`, [`crate::lift`]) or a lift prelude module.
    pub lifted: bool,
}

/// Whether a module declaration carries `#[spec]` (§15.1).
pub fn decl_is_spec(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        let segs: Vec<String> = a.path().segments.iter().map(|s| s.ident.to_string()).collect();
        matches!(segs.as_slice(), [n] if n == "spec") || matches!(segs.as_slice(), [r, n] if r == "sandblaster" && n == "spec") || matches!(segs.as_slice(), [r, p, n] if r == "sandblaster" && (p == "prelude" || p == "ghost") && n == "spec")
    })
}

/// Whether a module declaration carries `#[model]` (layered proofs): the
/// model layer of a crate, `#[cfg(sandblaster)] #[model] mod model;`. Its
/// functions are spec functions (ghost, total, kernel-evaluated) written in
/// the shape of the code, over numbers and sequences; exec functions refine
/// them by the lockstep (`elab::lockstep`). A model is proof text: it is not
/// on the specification surface (no examples, no lock entry of its own).
pub fn decl_is_model(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        let segs: Vec<String> = a.path().segments.iter().map(|s| s.ident.to_string()).collect();
        matches!(segs.as_slice(), [n] if n == "model") || matches!(segs.as_slice(), [r, n] if r == "sandblaster" && n == "model")
    })
}

/// Whether a module declaration carries `#[bridges]` (layered proofs):
/// every lemma of the module is a checked equation between an operation of
/// the code's machine types (words, slices, arrays, `Option`) and the
/// matching operation on numbers and sequences, and becomes a rule of
/// `auto` (`auto::lemmas::register_bridge`): the lockstep's atoms meet the
/// model's operations through them. A crate's standard library declares
/// its bridges this way (`#[bridges] pub mod bridges;`).
pub fn decl_is_bridges(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        let segs: Vec<String> = a.path().segments.iter().map(|s| s.ident.to_string()).collect();
        matches!(segs.as_slice(), [n] if n == "bridges") || matches!(segs.as_slice(), [r, n] if r == "sandblaster" && n == "bridges")
    })
}

/// An inherent impl block.
#[derive(Clone)]
pub struct ImplInfo {
    pub module: ModId,
    pub ghost: bool,
    pub cfg: Option<String>,
    pub item: syn::ItemImpl,
    pub span: Span,
    /// Resolved self type.
    pub owner: Option<ItemId>,
    pub fns: Vec<ItemId>,
}

/// One flattened `use` directive.
#[derive(Clone, Debug)]
struct UseDirective {
    module: ModId,
    segs: Vec<(String, Span)>,
    /// Name to bind (`None` for globs; `"_"` binds nothing).
    bind: Option<String>,
    glob: bool,
    vis: Vis,
    ghost: bool,
    span: Span,
}

/// The resolver: modules, items, scopes.
pub struct Resolver {
    pub mods: Vec<ModInfo>,
    pub items: Vec<ItemInfo>,
    pub impls: Vec<ImplInfo>,
    pub target: TargetInfo,
    scopes: Vec<Scope>,
    /// Names of every const, unit struct and unit variant (crate, ghost
    /// included, and prelude) — the §3.3 identifier-pattern hazard set.
    hazard: HashSet<String>,
    /// Module paths below `sandblaster::lemmas` (`["slice"]`, ..).
    pub lemma_mods: Vec<Vec<String>>,
    /// Synthetic prelude-lemma items by surface path below
    /// `sandblaster::lemmas`, and their kernel names.
    pub lemma_items: HashMap<Vec<String>, (ItemId, String)>,
}

/// First path segment of synthetic prelude-lemma items (not a Rust
/// identifier, so no user item can have it).
pub const PRELUDE_LEMMA_SEGMENT: &str = "{prelude}";

/// The kernel name of a synthetic prelude-lemma item, from its path.
pub fn prelude_lemma_kernel_name(path: &DefPath) -> Option<String> {
    match path.0.as_slice() {
        [p, l, rest @ ..] if p == PRELUDE_LEMMA_SEGMENT && l == "lemmas" && !rest.is_empty() => Some(rest.join("::")),
        _ => None,
    }
}

fn is_prim_type_name(n: &str) -> bool {
    matches!(n, "bool" | "u8" | "u16" | "u32" | "u64" | "u128" | "usize" | "i8" | "i16" | "i32" | "i64" | "i128" | "isize" | "char" | "str" | "f32" | "f64")
}

/// Identifiers occurring in a token stream.
fn collect_idents(ts: proc_macro2::TokenStream, out: &mut HashSet<String>) {
    for tt in ts {
        match tt {
            proc_macro2::TokenTree::Ident(i) => {
                out.insert(i.to_string());
            }
            proc_macro2::TokenTree::Group(g) => collect_idents(g.stream(), out),
            _ => {}
        }
    }
}

/// Converts `syn` visibility; `pub(in path)` is reported by the caller.
pub fn vis_of(v: &syn::Visibility) -> Option<Vis> {
    match v {
        syn::Visibility::Public(_) => Some(Vis::Public),
        syn::Visibility::Inherited => Some(Vis::Private),
        syn::Visibility::Restricted(r) => {
            if r.in_token.is_some() {
                return None;
            }
            if r.path.is_ident("crate") {
                Some(Vis::Crate)
            } else if r.path.is_ident("super") {
                Some(Vis::Super)
            } else if r.path.is_ident("self") {
                Some(Vis::Private)
            } else {
                None
            }
        }
    }
}

impl Resolver {
    /// Collects items and resolves imports.
    pub fn new(loaded: &Loaded, target: &TargetInfo, diags: &mut Diagnostics) -> Resolver {
        let mut r = Resolver { mods: vec![], items: vec![], impls: vec![], target: target.clone(), scopes: vec![], hazard: HashSet::new(), lemma_mods: vec![], lemma_items: HashMap::new() };
        r.hazard.insert("None".into());
        r.hazard.insert("ISIZE_MAX".into());
        let mut directives = Vec::new();
        // modules first (ids = loader indices)
        for (i, m) in loaded.modules.iter().enumerate() {
            let parent = m.parent.map(|p| ModId(p as u32));
            let path = match parent {
                None => DefPath::default(),
                Some(p) => r.mods[p.0 as usize].path.child(&m.name),
            };
            let vis = vis_of(&m.vis).unwrap_or(Vis::Private);
            let spec = decl_is_spec(&m.decl_attrs) || parent.is_some_and(|p| r.mods[p.0 as usize].spec);
            let model = decl_is_model(&m.decl_attrs) || parent.is_some_and(|p| r.mods[p.0 as usize].model);
            let bridges = decl_is_bridges(&m.decl_attrs);
            r.mods.push(ModInfo {
                id: ModId(i as u32),
                name: m.name.clone(),
                parent,
                ghost: m.ghost,
                vis,
                file: m.file,
                span: m.decl_span,
                path,
                children: vec![],
                items: vec![],
                inner_attrs: m.inner_attrs.clone(),
                decl_attrs: m.decl_attrs.clone(),
                cfg: m.cfg.clone(),
                spec,
                model,
                bridges,
                data_files: m.data_files.clone(),
                lifted: m.lifted,
            });
            r.scopes.push(Scope::default());
            if let Some(p) = parent {
                r.mods[p.0 as usize].children.push(ModId(i as u32));
            }
        }
        for (i, m) in loaded.modules.iter().enumerate() {
            let mid = ModId(i as u32);
            for li in &m.items {
                r.collect_item(mid, m.file, li, &mut directives, diags);
            }
        }
        r.inject_prelude_lemmas(loaded);
        r.resolve_imports(directives, diags);
        r.resolve_impl_owners(diags);
        r.check_variant_named_fns(diags);
        r
    }

    /// An inherent associated function of an enum named like one of its
    /// variants: rustc resolves the type-relative paths `E::A` and `<E>::A` to
    /// the variant (variants come first), so in the source `E::A(x)` is the
    /// constructor, and the canonical dialect's method calls `<E>::A(e, x)`
    /// (UFCS) would construct the variant instead of calling the function (red
    /// team: a variant `r#A`/`A\u{e9}` next to `fn A`/`fn Ae\u{301}`, a method
    /// `fn A(self, ..)` next to a variant `A`). Rejected, ghost functions
    /// included (the source must read as rustc reads it).
    fn check_variant_named_fns(&self, diags: &mut Diagnostics) {
        for it in &self.items {
            let (ItemTag::Fn, Some(owner)) = (&it.tag, it.owner) else { continue };
            let ItemTag::Enum { variants, .. } = &self.items[owner.0 as usize].tag else { continue };
            if let Some((v, _)) = variants.iter().find(|(v, _)| *v == it.name) {
                diags.push(
                    Diagnostic::error(DiagKind::Resolve, it.span, format!("the associated function `{}` has the name of the variant `{}::{}`", it.path, self.items[owner.0 as usize].path, v))
                        .note("in rustc the paths `E::name` and `<E>::name` name the variant, not the function (the canonical code calls methods as `<E>::name(..)`, DESIGN.md §8.3); rename the function"),
                );
            }
        }
    }

    /// Adds a synthetic ghost `#[lemma]` item for every prelude lemma whose
    /// name occurs in the sources (see the module docs).
    fn inject_prelude_lemmas(&mut self, loaded: &Loaded) {
        let mut idents = HashSet::new();
        for m in &loaded.modules {
            for li in &m.items {
                collect_idents(quote::ToTokens::to_token_stream(&li.item), &mut idents);
            }
        }
        if !idents.contains("lemmas") {
            return;
        }
        let root = ModId(0);
        // per-literal bit-family lemmas (`lz_ge_u16_9`), generated on demand
        let fam_names: Vec<String> = idents.iter().filter(|n| crate::auto::bitlib::parse_lemma_name(n).is_some()).cloned().collect();
        let families = crate::auto::surface::family_lemmas(&fam_names);
        for l in crate::auto::surface::table().iter().chain(families.iter()) {
            let name = l.path.last().cloned().unwrap_or_default();
            if !idents.contains(&name) {
                continue;
            }
            let Ok(f) = syn::parse_str::<syn::ItemFn>(&l.src) else { continue };
            for k in 1..l.path.len() {
                let mp = l.path[..k].to_vec();
                if !self.lemma_mods.contains(&mp) {
                    self.lemma_mods.push(mp);
                }
            }
            let id = ItemId(self.items.len() as u32);
            let mut path = vec![PRELUDE_LEMMA_SEGMENT.to_string(), "lemmas".to_string()];
            path.extend(l.path.iter().cloned());
            self.items.push(ItemInfo {
                id,
                name,
                path: DefPath(path),
                module: root,
                vis: Vis::Public,
                ghost: true,
                span: Span::DUMMY,
                cfg: None,
                tag: ItemTag::Fn,
                src: ItemSrc::Fn(f),
                owner: None,
            });
            self.lemma_items.insert(l.path.clone(), (id, l.kernel.clone()));
        }
    }

    /// `sandblaster::lemmas::<prefix>::<name>` in namespace `ns`.
    fn lemma_lookup(&self, prefix: &[String], name: &str, ns: Ns) -> Option<Def> {
        let mut p = prefix.to_vec();
        p.push(name.to_string());
        match ns {
            Ns::Type => self.lemma_mods.iter().position(|m| *m == p).map(|i| Def::Ext(Ext::LemmaMod(i as u32))),
            Ns::Value => match self.lemma_items.get(&p) {
                Some((id, _)) => Some(Def::Item(*id)),
                // `seq::append` etc. next to the `seq::*` lemmas
                None if prefix == ["seq"] => GhostFn::seq(name).map(|g| Def::Ext(Ext::GhostFn(g))),
                None => None,
            },
            Ns::Macro => None,
        }
    }

    fn file_of(&self, m: ModId) -> FileId {
        self.mods[m.0 as usize].file
    }

    fn define(&mut self, m: ModId, ns: Ns, name: &str, b: Binding, diags: &mut Diagnostics) {
        let scope = &mut self.scopes[m.0 as usize];
        if let Some(prev) = scope.ns(ns).get(name) {
            if prev.def == b.def {
                return;
            }
            diags.push(Diagnostic::error(DiagKind::Resolve, b.span, format!("the name `{name}` is defined multiple times")).note_at(prev.span, "previous definition here"));
            return;
        }
        scope.ns_mut(ns).insert(name.to_string(), b);
    }

    fn collect_item(&mut self, m: ModId, file: FileId, li: &crate::loader::LoadedItem, directives: &mut Vec<UseDirective>, diags: &mut Diagnostics) {
        let item = &li.item;
        let span = Span::from_pm2(file, item.span());
        let ghost = li.ghost;
        let vis_check = |v: &syn::Visibility, diags: &mut Diagnostics| -> Vis {
            vis_of(v).unwrap_or_else(|| {
                diags.error(DiagKind::Unsupported, Span::from_pm2(file, v.span()), "`pub(in path)` visibility is not supported");
                Vis::Private
            })
        };
        let mpath = self.mods[m.0 as usize].path.clone();
        let new_item = |this: &mut Resolver, name: String, vis: Vis, tag: ItemTag, src: ItemSrc, span: Span| -> ItemId {
            let id = ItemId(this.items.len() as u32);
            let path = mpath.child(&name);
            this.items.push(ItemInfo { id, name, path, module: m, vis, ghost, span, cfg: li.cfg.clone(), tag, src, owner: None });
            this.mods[m.0 as usize].items.push(id);
            id
        };
        match item {
            syn::Item::Struct(s) => {
                let vis = vis_check(&s.vis, diags);
                let shape = match &s.fields {
                    syn::Fields::Named(_) => Shape::Named,
                    syn::Fields::Unnamed(_) => Shape::Tuple,
                    syn::Fields::Unit => Shape::Unit,
                };
                let name = s.ident.to_string();
                check_item_name(&name, span, diags);
                let id = new_item(self, name.clone(), vis, ItemTag::Struct { shape, generics: s.generics.type_params().count() }, ItemSrc::Struct(s.clone()), span);
                let b = Binding { def: Def::Item(id), vis, span, ghost, import: false };
                self.define(m, Ns::Type, &name, b.clone(), diags);
                if shape != Shape::Named {
                    self.define(m, Ns::Value, &name, b, diags);
                }
                if shape == Shape::Unit {
                    self.hazard.insert(name);
                }
            }
            syn::Item::Enum(e) => {
                let vis = vis_check(&e.vis, diags);
                let variants: Vec<(String, Shape)> = e
                    .variants
                    .iter()
                    .map(|v| {
                        let shape = match &v.fields {
                            syn::Fields::Named(_) => Shape::Named,
                            syn::Fields::Unnamed(_) => Shape::Tuple,
                            syn::Fields::Unit => Shape::Unit,
                        };
                        (v.ident.to_string(), shape)
                    })
                    .collect();
                for (n, s) in &variants {
                    if *s == Shape::Unit {
                        self.hazard.insert(n.clone());
                    }
                }
                let name = e.ident.to_string();
                check_item_name(&name, span, diags);
                let id = new_item(self, name.clone(), vis, ItemTag::Enum { variants, generics: e.generics.type_params().count() }, ItemSrc::Enum(e.clone()), span);
                self.define(m, Ns::Type, &name, Binding { def: Def::Item(id), vis, span, ghost, import: false }, diags);
            }
            syn::Item::Const(c) => {
                let vis = vis_check(&c.vis, diags);
                let name = c.ident.to_string();
                self.hazard.insert(name.clone());
                let id = new_item(self, name.clone(), vis, ItemTag::Const, ItemSrc::Const(c.clone()), span);
                self.define(m, Ns::Value, &name, Binding { def: Def::Item(id), vis, span, ghost, import: false }, diags);
            }
            syn::Item::Type(t) => {
                let vis = vis_check(&t.vis, diags);
                let name = t.ident.to_string();
                check_item_name(&name, span, diags);
                let id = new_item(self, name.clone(), vis, ItemTag::Alias, ItemSrc::Type(t.clone()), span);
                self.define(m, Ns::Type, &name, Binding { def: Def::Item(id), vis, span, ghost, import: false }, diags);
            }
            syn::Item::Fn(f) => {
                let vis = vis_check(&f.vis, diags);
                let name = f.sig.ident.to_string();
                let id = new_item(self, name.clone(), vis, ItemTag::Fn, ItemSrc::Fn(f.clone()), span);
                self.define(m, Ns::Value, &name, Binding { def: Def::Item(id), vis, span, ghost, import: false }, diags);
            }
            syn::Item::Mod(md) => {
                if let Some(child) = li.child {
                    let cid = ModId(child as u32);
                    let vis = vis_check(&md.vis, diags);
                    self.define(m, Ns::Type, &md.ident.to_string(), Binding { def: Def::Mod(cid), vis, span, ghost, import: false }, diags);
                }
            }
            syn::Item::Use(u) => {
                // §15 annotations never apply to a `use` (the erasing macros
                // would pass it through silently in the baseline build)
                for a in &u.attrs {
                    let aspan = Span::from_pm2(file, a.span());
                    if is_critical_path(a.path()) {
                        diags.push(critical_diagnostic(aspan));
                    } else if let Some((an, _)) = crate::typeck::annotation_of(a.path()) {
                        let site = crate::typeck::spec15::Site::Use;
                        diags.push(Diagnostic::error(DiagKind::Attribute, aspan, format!("`#[{}]` is not allowed on {}", an.name(), site.text())).note(crate::typeck::spec15::placement_note(an, site)));
                    }
                }
                let vis = vis_check(&u.vis, diags);
                let mut prefix = Vec::new();
                if u.leading_colon.is_some() {
                    prefix.push(("::".to_string(), span));
                }
                flatten_use(&u.tree, &mut prefix, m, vis, ghost, file, directives);
            }
            syn::Item::Impl(im) => {
                if let Some((_, path, _)) = &im.trait_ {
                    let t = quote::ToTokens::to_token_stream(path).to_string().replace(' ', "");
                    diags.push(Diagnostic::error(DiagKind::Trait, span, format!("trait impls are not supported (`impl {t} for ..`)")).note("use `#[derive(Clone, Copy, PartialEq, Eq, Debug)]` for the supported traits (DESIGN.md §3.1)"));
                    return;
                }
                if im.unsafety.is_some() {
                    diags.error(DiagKind::Unsupported, span, "`unsafe impl` is not supported");
                    return;
                }
                let impl_idx = self.impls.len();
                self.impls.push(ImplInfo { module: m, ghost, cfg: li.cfg.clone(), item: im.clone(), span, owner: None, fns: vec![] });
                let tyname = match &*im.self_ty {
                    syn::Type::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default(),
                    _ => String::new(),
                };
                for ii in &im.items {
                    match ii {
                        syn::ImplItem::Fn(f) => {
                            let vis = vis_check(&f.vis, diags);
                            let fspan = Span::from_pm2(file, f.span());
                            let id = ItemId(self.items.len() as u32);
                            let path = mpath.child(&tyname).child(&f.sig.ident.to_string());
                            self.items.push(ItemInfo { id, name: f.sig.ident.to_string(), path, module: m, vis, ghost, span: fspan, cfg: li.cfg.clone(), tag: ItemTag::Fn, src: ItemSrc::ImplFn { impl_idx, f: f.clone() }, owner: None });
                            self.mods[m.0 as usize].items.push(id);
                            self.impls[impl_idx].fns.push(id);
                        }
                        syn::ImplItem::Const(c) => diags.error(DiagKind::Unsupported, Span::from_pm2(file, c.span()), "associated consts are not supported; use a module-level `const`"),
                        syn::ImplItem::Type(t) => diags.error(DiagKind::Trait, Span::from_pm2(file, t.span()), "associated types are not supported"),
                        other => diags.error(DiagKind::Macro, Span::from_pm2(file, other.span()), "macros are not supported in impl blocks"),
                    }
                }
            }
            syn::Item::Trait(_) | syn::Item::TraitAlias(_) => {
                diags.push(Diagnostic::error(DiagKind::Trait, span, "traits are not supported").note("the subset is first-order and trait-free (DESIGN.md §3.1)"));
            }
            syn::Item::Static(_) => {
                diags.push(Diagnostic::error(DiagKind::Static, span, "`static` items are not supported; use `const`"));
            }
            syn::Item::Macro(mac) => {
                let name = quote::ToTokens::to_token_stream(&mac.mac.path).to_string();
                diags.error(DiagKind::Macro, span, format!("item macros are not supported (`{name}!`)"));
            }
            syn::Item::Union(_) => diags.error(DiagKind::Unsupported, span, "unions are not supported"),
            syn::Item::ExternCrate(_) => diags.error(DiagKind::Unsupported, span, "`extern crate` is not supported"),
            syn::Item::ForeignMod(_) => diags.error(DiagKind::Unsupported, span, "`extern` blocks are not supported"),
            _ => diags.error(DiagKind::Unsupported, span, "unsupported item"),
        }
    }

    // ------------------------------------------------------------------
    // imports
    // ------------------------------------------------------------------

    fn resolve_imports(&mut self, directives: Vec<UseDirective>, diags: &mut Diagnostics) {
        let mut pending: Vec<UseDirective> = directives;
        loop {
            let before = pending.len();
            let mut next = Vec::new();
            for d in pending {
                match self.try_import(&d, false) {
                    Ok(()) => {}
                    Err(_) => next.push(d),
                }
            }
            pending = next;
            if pending.is_empty() || pending.len() == before {
                break;
            }
        }
        for d in pending {
            if let Err(e) = self.try_import(&d, true) {
                diags.push(e);
            }
        }
    }

    /// Tries to resolve one import; `Err` if not (yet) resolvable. With
    /// `final_try`, the error is a user-facing diagnostic.
    fn try_import(&mut self, d: &UseDirective, final_try: bool) -> Result<(), Diagnostic> {
        let n = d.segs.len();
        if d.glob {
            let container = self.resolve_use_prefix(d.module, &d.segs, d.span)?;
            match container {
                Def::Ext(e @ (Ext::SandblasterPrelude | Ext::SandblasterGhost | Ext::ArchMod(_) | Ext::Lemmas | Ext::LemmaMod(_))) => {
                    self.scopes[d.module.0 as usize].globs.push((e, d.ghost));
                    Ok(())
                }
                _ => Err(Diagnostic::error(DiagKind::Resolve, d.span, "glob imports are only allowed from `sandblaster::prelude` (and `sandblaster::ghost`, `sandblaster::lemmas` in ghost modules), `core::arch::aarch64` and `core::arch::x86_64`")),
            }
        } else {
            let (last, lspan) = d.segs[n - 1].clone();
            let found: Vec<(Ns, Found)> = if last == "self" {
                let c = self.resolve_use_prefix(d.module, &d.segs[..n - 1], d.span)?;
                vec![(Ns::Type, Found { def: c, vis: Vis::Public, ghost: false, home: None })]
            } else {
                let container = if n == 1 { None } else { Some(self.resolve_use_prefix(d.module, &d.segs[..n - 1], d.span)?) };
                let mut found = Vec::new();
                for ns in [Ns::Type, Ns::Value, Ns::Macro] {
                    let r = match container {
                        None => self.lookup_first_use_segment(d.module, &last, ns),
                        Some(c) => self.lookup_in(c, &last, ns),
                    };
                    if let Some(f) = r {
                        found.push((ns, f));
                    }
                }
                found
            };
            if found.is_empty() {
                let e = Diagnostic::error(DiagKind::Resolve, lspan, format!("unresolved import `{}`", d.segs.iter().map(|s| s.0.as_str()).collect::<Vec<_>>().join("::")));
                return Err(if final_try { self.explain_missing(e, d) } else { e });
            }
            for (_, f) in &found {
                if let Some(v) = self.privacy_violation(f, d.module) {
                    return Err(Diagnostic::error(DiagKind::Privacy, lspan, format!("`{last}` is private")).note(v));
                }
            }
            let bind = d.bind.clone().unwrap_or(last.clone());
            let bind = if last == "self" { d.segs.get(n.wrapping_sub(2)).map(|s| s.0.clone()).unwrap_or(bind) } else { bind };
            if bind == "_" {
                return Ok(());
            }
            let bind = if let Some(b) = &d.bind { b.clone() } else { bind };
            for (ns, f) in found {
                let def = f.def;
                let b = Binding { def, vis: d.vis, span: d.span, ghost: d.ghost || f.ghost, import: true };
                let scope = &mut self.scopes[d.module.0 as usize];
                if let Some(prev) = scope.ns(ns).get(&bind) {
                    if prev.def != def {
                        return Err(Diagnostic::error(DiagKind::Resolve, d.span, format!("the name `{bind}` is defined multiple times")).note_at(prev.span, "previous definition here"));
                    }
                    continue;
                }
                scope.ns_mut(ns).insert(bind.clone(), b);
            }
            Ok(())
        }
    }

    fn explain_missing(&self, e: Diagnostic, d: &UseDirective) -> Diagnostic {
        if d.segs.first().is_some_and(|s| s.0 == "sandblaster" || s.0 == "::") && d.segs.last().is_some_and(|s| s.0 == "critical") {
            return critical_diagnostic(d.span);
        }
        if d.segs.len() >= 3 && d.segs[0].0 == "core" && d.segs[1].0 == "arch" {
            return e.note("only intrinsics of sandblaster's target library can be imported (DESIGN.md §9.2)");
        }
        e
    }

    /// Resolves a `use` path prefix to a container.
    fn resolve_use_prefix(&self, m: ModId, segs: &[(String, Span)], span: Span) -> Result<Def, Diagnostic> {
        let mut it = segs.iter();
        let Some((first, fspan)) = it.next() else {
            return Err(Diagnostic::error(DiagKind::Resolve, span, "empty import path"));
        };
        let mut cur = if first == "::" {
            let (n, s) = it.next().ok_or_else(|| Diagnostic::error(DiagKind::Resolve, span, "bad path"))?;
            self.extern_crate(n).ok_or_else(|| Diagnostic::error(DiagKind::Resolve, *s, format!("unknown crate `{n}` (only `core` and `sandblaster` are available)")))?
        } else {
            match self.lookup_first_use_segment(m, first, Ns::Type) {
                Some(f) => f.def,
                None => return Err(Diagnostic::error(DiagKind::Resolve, *fspan, format!("unresolved path segment `{first}`"))),
            }
        };
        for (seg, sspan) in it {
            cur = match self.lookup_in(cur, seg, Ns::Type) {
                Some(f) => {
                    if let Some(v) = self.privacy_violation(&f, m) {
                        return Err(Diagnostic::error(DiagKind::Privacy, *sspan, format!("`{seg}` is private")).note(v));
                    }
                    f.def
                }
                None => return Err(self.missing_segment(cur, seg, *sspan)),
            };
        }
        Ok(cur)
    }

    fn missing_segment(&self, container: Def, seg: &str, span: Span) -> Diagnostic {
        match container {
            Def::Ext(Ext::CoreArch) => Diagnostic::error(DiagKind::Feature, span, format!("`core::arch::{seg}` is not available for target architecture `{}`", self.target.arch.name())).note("gate the item with `#[cfg(target_arch = \"..\")]`"),
            Def::Ext(Ext::SandblasterArch) => Diagnostic::error(DiagKind::Feature, span, format!("`sandblaster::arch::{seg}` is not available for target architecture `{}`", self.target.arch.name())),
            Def::Ext(Ext::ArchMod(a)) => Diagnostic::error(DiagKind::Feature, span, format!("`{seg}` is not in sandblaster's target library for {}", a.arch().name())).note("DESIGN.md §9.2 lists the modeled intrinsics"),
            _ => Diagnostic::error(DiagKind::Resolve, span, format!("cannot find `{seg}` in this path")),
        }
    }

    fn extern_crate(&self, name: &str) -> Option<Def> {
        match name {
            "core" | "std" => Some(Def::Ext(Ext::Core)),
            "sandblaster" => Some(Def::Ext(Ext::Sandblaster)),
            _ => None,
        }
    }

    /// The first segment of a `use` path: `crate`, `self`, `super`, a local
    /// name, or an extern crate.
    fn lookup_first_use_segment(&self, m: ModId, name: &str, ns: Ns) -> Option<Found> {
        let plain = |def| Some(Found { def, vis: Vis::Public, ghost: false, home: None });
        match name {
            "crate" => return if ns == Ns::Type { plain(Def::Mod(ModId(0))) } else { None },
            "self" => return if ns == Ns::Type { plain(Def::Mod(m)) } else { None },
            "super" => return self.mods[m.0 as usize].parent.filter(|_| ns == Ns::Type).and_then(|p| plain(Def::Mod(p))),
            _ => {}
        }
        if let Some(b) = self.scopes[m.0 as usize].ns(ns).get(name) {
            return Some(Found { def: b.def, vis: b.vis, ghost: b.ghost, home: Some(m) });
        }
        if ns == Ns::Type
            && let Some(d) = self.extern_crate(name) {
                return plain(d);
            }
        None
    }

    /// Looks `name` up inside a container definition.
    pub fn lookup_in(&self, container: Def, name: &str, ns: Ns) -> Option<Found> {
        match container {
            Def::Mod(cm) => {
                if name == "super" && ns == Ns::Type {
                    return self.mods[cm.0 as usize].parent.map(|p| Found { def: Def::Mod(p), vis: Vis::Public, ghost: false, home: None });
                }
                let b = self.scopes[cm.0 as usize].ns(ns).get(name)?;
                Some(Found { def: b.def, vis: b.vis, ghost: b.ghost, home: Some(cm) })
            }
            Def::Item(id) => {
                if ns != Ns::Value && ns != Ns::Type {
                    return None;
                }
                if let ItemTag::Enum { variants, .. } = &self.items[id.0 as usize].tag {
                    let idx = variants.iter().position(|(n, _)| n == name)?;
                    let shape = variants[idx].1;
                    if ns == Ns::Value && shape == Shape::Named {
                        // struct variants live in the type namespace only
                        return None;
                    }
                    let it = &self.items[id.0 as usize];
                    return Some(Found { def: Def::Variant(id, idx as u32), vis: Vis::Public, ghost: it.ghost, home: None });
                }
                None
            }
            Def::Variant(..) => None,
            Def::Ext(e) => self.lookup_ext(e, name, ns).map(|d| Found { def: d, vis: Vis::Public, ghost: false, home: None }),
        }
    }

    fn lookup_ext(&self, e: Ext, name: &str, ns: Ns) -> Option<Def> {
        let ext = |x: Ext| Some(Def::Ext(x));
        match (e, ns) {
            (Ext::Core, Ns::Type) => match name {
                "arch" => ext(Ext::CoreArch),
                "option" => ext(Ext::CoreOption),
                _ => None,
            },
            (Ext::CoreArch, Ns::Type) => {
                let a = ArchTag::from_name(name)?;
                (a.arch() == self.target.arch).then_some(Def::Ext(Ext::ArchMod(a)))
            }
            (Ext::ArchMod(a), Ns::Value) => intrinsics::lookup(&a.arch(), name).map(|i| Def::Ext(Ext::Intrinsic(i.id))),
            (Ext::ArchMod(a), Ns::Type) => {
                if let Some(v) = VecTy::from_name(&a.arch(), name) {
                    return ext(Ext::VecType(v));
                }
                match intrinsics::arch_type_alias(&a.arch(), name) {
                    Some(Ty::Uint(crate::hir::UintTy::U8)) => ext(Ext::MaskType(8)),
                    Some(Ty::Uint(crate::hir::UintTy::U16)) => ext(Ext::MaskType(16)),
                    _ => None,
                }
            }
            (Ext::CoreOption, Ns::Type) if name == "Option" => ext(Ext::OptionEnum),
            (Ext::OptionEnum, Ns::Value) => match name {
                "Some" => ext(Ext::SomeCtor),
                "None" => ext(Ext::NoneCtor),
                _ => None,
            },
            (Ext::Sandblaster, Ns::Type) => match name {
                "prelude" => ext(Ext::SandblasterPrelude),
                "ghost" => ext(Ext::SandblasterGhost),
                "arch" => ext(Ext::SandblasterArch),
                "lemmas" => ext(Ext::Lemmas),
                _ => self.prelude_name(name, ns).map(Def::Ext),
            },
            (Ext::Lemmas, _) => self.lemma_lookup(&[], name, ns),
            (Ext::LemmaMod(i), _) => {
                let prefix = self.lemma_mods.get(i as usize)?.clone();
                self.lemma_lookup(&prefix, name, ns)
            }
            (Ext::Sandblaster | Ext::SandblasterPrelude | Ext::SandblasterGhost, _) => self.prelude_name(name, ns).map(Def::Ext),
            (Ext::SandblasterArch, Ns::Type) => {
                let a = ArchTag::from_name(name)?;
                (a.arch() == self.target.arch).then_some(Def::Ext(Ext::HelperMod(a)))
            }
            (Ext::HelperMod(a), Ns::Value) => intrinsics::lookup_helper(&a.arch(), name).map(|h| Def::Ext(Ext::Helper(h))),
            (Ext::SeqMod, Ns::Value) => GhostFn::seq(name).map(|g| Def::Ext(Ext::GhostFn(g))),
            (Ext::SeqTy, Ns::Value) => GhostFn::seq_assoc(name).map(|g| Def::Ext(Ext::GhostFn(g))),
            _ => None,
        }
    }

    /// Names exported by `sandblaster::prelude` (annotations + ghost prelude).
    fn prelude_name(&self, name: &str, ns: Ns) -> Option<Ext> {
        match ns {
            Ns::Macro => {
                if name == "proof" {
                    // both the `proof!` macro and the `#[proof]` attribute
                    return Some(Ext::Annotation(Annot::Proof));
                }
                Annot::from_name(name).map(Ext::Annotation)
            }
            Ns::Type => match name {
                "Int" => Some(Ext::IntTy),
                "Prop" => Some(Ext::PropTy),
                "Nat" => Some(Ext::NatTy),
                "Seq" => Some(Ext::SeqTy),
                "seq" => Some(Ext::SeqMod),
                _ => None,
            },
            Ns::Value => match name {
                "forall" => Some(Ext::GhostKw(GhostKw::Forall)),
                "exists" => Some(Ext::GhostKw(GhostKw::Exists)),
                "implies" => Some(Ext::GhostKw(GhostKw::Implies)),
                "iff" => Some(Ext::GhostKw(GhostKw::Iff)),
                "eqb" => Some(Ext::GhostFn(GhostFn::Eqb)),
                "ISIZE_MAX" => Some(Ext::IsizeMax),
                _ => GhostFn::prelude_fn(name).map(Ext::GhostFn),
            },
        }
    }

    fn resolve_impl_owners(&mut self, diags: &mut Diagnostics) {
        for i in 0..self.impls.len() {
            let (m, ty) = (self.impls[i].module, (*self.impls[i].item.self_ty).clone());
            let file = self.file_of(m);
            let span = Span::from_pm2(file, ty.span());
            let owner = match &ty {
                syn::Type::Path(p) if p.qself.is_none() => {
                    let segs: Vec<(String, Span)> = p.path.segments.iter().map(|s| (s.ident.to_string(), Span::from_pm2(file, s.ident.span()))).collect();
                    match self.resolve_path_defs(m, &segs, Ns::Type, p.path.leading_colon.is_some(), false) {
                        Ok(Def::Item(id)) if matches!(self.items[id.0 as usize].tag, ItemTag::Struct { .. } | ItemTag::Enum { .. }) => {
                            if self.items[id.0 as usize].module != m {
                                // rustc allows this; we keep it too.
                            }
                            Some(id)
                        }
                        Ok(_) => {
                            diags.push(Diagnostic::error(DiagKind::Trait, span, "inherent impls are only allowed for structs and enums of this crate"));
                            None
                        }
                        Err(e) => {
                            diags.push(e);
                            None
                        }
                    }
                }
                _ => {
                    diags.error(DiagKind::Unsupported, span, "inherent impls are only allowed for structs and enums of this crate");
                    None
                }
            };
            self.impls[i].owner = owner;
            for f in self.impls[i].fns.clone() {
                self.items[f.0 as usize].owner = owner;
                if let Some(o) = owner {
                    // rename the path to the owner's module path
                    let op = self.items[o.0 as usize].path.clone();
                    let name = self.items[f.0 as usize].name.clone();
                    self.items[f.0 as usize].path = op.child(&name);
                }
            }
        }
        // duplicate inherent functions
        let mut seen: HashMap<(ItemId, String), Span> = HashMap::new();
        for it in &self.items {
            if let (Some(o), ItemTag::Fn) = (it.owner, &it.tag)
                && let Some(prev) = seen.insert((o, it.name.clone()), it.span) {
                    diags.push(Diagnostic::error(DiagKind::Resolve, it.span, format!("duplicate definitions with name `{}`", it.name)).note_at(prev, "previous definition here"));
                }
        }
    }

    // ------------------------------------------------------------------
    // lookup API
    // ------------------------------------------------------------------

    /// Looks up a single name in module `m` (items + imports, then globs,
    /// then the std prelude, then — if `ghost_ctx` — the ghost prelude).
    /// Returns the definition and whether the binding is ghost.
    pub fn lookup(&self, m: ModId, name: &str, ns: Ns, ghost_ctx: bool) -> Option<(Def, bool)> {
        let scope = &self.scopes[m.0 as usize];
        if let Some(b) = scope.ns(ns).get(name) {
            return Some((b.def, b.ghost));
        }
        let mut glob_hits: Vec<(Def, bool)> = Vec::new();
        for (g, gghost) in &scope.globs {
            if matches!(g, Ext::Lemmas) && ns == Ns::Type && is_prim_type_name(name) {
                continue;
            }
            if let Some(d) = self.lookup_ext(*g, name, ns)
                && !glob_hits.iter().any(|(x, _)| *x == d) {
                    glob_hits.push((d, *gghost));
                }
        }
        if let Some(h) = glob_hits.first() {
            return Some(*h);
        }
        // std prelude
        match (ns, name) {
            (Ns::Type, "Option") => return Some((Def::Ext(Ext::OptionEnum), false)),
            (Ns::Value, "Some") => return Some((Def::Ext(Ext::SomeCtor), false)),
            (Ns::Value, "None") => return Some((Def::Ext(Ext::NoneCtor), false)),
            _ => {}
        }
        if ghost_ctx
            && let Some(e) = self.prelude_name(name, ns)
                && !matches!(e, Ext::Annotation(_)) {
                    return Some((Def::Ext(e), true));
                }
        None
    }

    /// Resolves a multi-segment path to a definition (no generic args).
    /// `leading_colon` is `::a::b`. The last segment is looked up in `ns`,
    /// the others in the type namespace.
    pub fn resolve_path_defs(&self, m: ModId, segs: &[(String, Span)], ns: Ns, leading_colon: bool, ghost_ctx: bool) -> Result<Def, Diagnostic> {
        self.resolve_path_defs_vis(m, segs, ns, leading_colon, ghost_ctx, true)
    }

    /// [`Resolver::resolve_path_defs`] without the privacy check (for a
    /// lemma named in a `proof!` block: ghost code, which rustc never sees).
    pub fn resolve_path_defs_ghost(&self, m: ModId, segs: &[(String, Span)], ns: Ns, leading_colon: bool) -> Result<Def, Diagnostic> {
        self.resolve_path_defs_vis(m, segs, ns, leading_colon, true, false)
    }

    fn resolve_path_defs_vis(&self, m: ModId, segs: &[(String, Span)], ns: Ns, leading_colon: bool, ghost_ctx: bool, privacy: bool) -> Result<Def, Diagnostic> {
        let n = segs.len();
        let (first, fspan) = &segs[0];
        let first_ns = if n == 1 { ns } else { Ns::Type };
        let mut cur = if leading_colon {
            self.extern_crate(first).ok_or_else(|| Diagnostic::error(DiagKind::Resolve, *fspan, format!("unknown crate `{first}`")))?
        } else {
            match first.as_str() {
                "crate" if n > 1 => Def::Mod(ModId(0)),
                "self" if n > 1 => Def::Mod(m),
                "super" if n > 1 => Def::Mod(self.mods[m.0 as usize].parent.ok_or_else(|| Diagnostic::error(DiagKind::Resolve, *fspan, "there are too many leading `super` keywords"))?),
                _ => match self.lookup(m, first, first_ns, ghost_ctx) {
                    Some((d, _)) => d,
                    None => match (n > 1).then(|| self.extern_crate(first)).flatten() {
                        Some(d) => d,
                        None => return Err(Diagnostic::error(DiagKind::Resolve, *fspan, format!("cannot find `{first}` in this scope"))),
                    },
                },
            }
        };
        for (i, (seg, sspan)) in segs.iter().enumerate().skip(1) {
            let sns = if i == n - 1 { ns } else { Ns::Type };
            cur = match self.lookup_in(cur, seg, sns) {
                Some(f) => {
                    if privacy && let Some(v) = self.privacy_violation(&f, m) {
                        return Err(Diagnostic::error(DiagKind::Privacy, *sspan, format!("`{seg}` is private")).note(v));
                    }
                    f.def
                }
                None => return Err(self.missing_segment(cur, seg, *sspan)),
            };
        }
        Ok(cur)
    }

    /// If `def` (reached with binding visibility `vis`) is not visible from
    /// module `from`, returns an explanation.
    /// If the binding `f` (found in module `f.home`) is not visible from
    /// module `from`, returns an explanation. For re-exports the binding's
    /// visibility is the `use`'s and its home the importing module, exactly
    /// as in rustc.
    pub fn privacy_violation(&self, f: &Found, from: ModId) -> Option<String> {
        let home = f.home?;
        if self.visible(f.vis, home, from) || self.lifted_proof_sees(home, from) {
            None
        } else {
            Some(format!("it is only visible inside `{}`", self.mods[home.0 as usize].path))
        }
    }

    /// Whether a ghost lifted module (a lifted module's `PROOF.rs`,
    /// [`crate::lift`]) looks into a lifted exec module: its proofs see the
    /// private items of the code they are about (the lift's loop helpers,
    /// private functions). Privacy never changes what code means, and ghost
    /// modules are never emitted; exec code keeps Rust's privacy.
    fn lifted_proof_sees(&self, home: ModId, from: ModId) -> bool {
        let (h, f) = (&self.mods[home.0 as usize], &self.mods[from.0 as usize]);
        h.lifted && !h.ghost && f.lifted && f.ghost
    }

    /// Whether an item with visibility `vis` defined in `defining` is visible
    /// from `from`.
    pub fn visible(&self, vis: Vis, defining: ModId, from: ModId) -> bool {
        match vis {
            Vis::Public | Vis::Crate => true,
            Vis::Private => self.is_ancestor(defining, from),
            Vis::Super => match self.mods[defining.0 as usize].parent {
                Some(p) => self.is_ancestor(p, from),
                None => true,
            },
        }
    }

    /// Whether `anc` is `m` or one of its ancestors.
    pub fn is_ancestor(&self, anc: ModId, mut m: ModId) -> bool {
        loop {
            if m == anc {
                return true;
            }
            match self.mods[m.0 as usize].parent {
                Some(p) => m = p,
                None => return false,
            }
        }
    }

    /// The §3.3 hazard set: const, unit struct and unit variant names.
    pub fn pattern_hazard(&self, name: &str) -> bool {
        self.hazard.contains(name)
    }

    /// Whether module `m` makes the annotation `name` available (explicit
    /// import or `sandblaster::prelude::*` glob).
    pub fn annotation_in_scope(&self, m: ModId, name: &str) -> bool {
        let scope = &self.scopes[m.0 as usize];
        if let Some(b) = scope.macros.get(name) {
            return matches!(b.def, Def::Ext(Ext::Annotation(_)));
        }
        scope.globs.iter().any(|(g, _)| *g == Ext::SandblasterPrelude)
    }

    /// Public names of module `m` (for boundary computation): every `pub`
    /// binding in the type and value namespaces, sorted by name.
    pub fn public_names(&self, m: ModId) -> Vec<PublicName> {
        let scope = &self.scopes[m.0 as usize];
        let mut out: Vec<PublicName> = Vec::new();
        for ns in [Ns::Type, Ns::Value] {
            for (name, b) in scope.ns(ns) {
                if b.vis == Vis::Public && !out.iter().any(|p| p.name == *name && p.def == b.def) {
                    out.push(PublicName { name: name.clone(), def: b.def, span: b.span, ghost: b.ghost, import: b.import });
                }
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }
}

/// A `pub` binding of a module ([`Resolver::public_names`]).
#[derive(Clone, Debug)]
pub struct PublicName {
    pub name: String,
    pub def: Def,
    pub span: Span,
    pub ghost: bool,
    /// Introduced by a `pub use` (not a `pub` item or `pub mod` declared in
    /// the module).
    pub import: bool,
}

/// Rejects user items named like primitive types (the canonical printer
/// relies on primitive names never being shadowed).
fn check_item_name(name: &str, span: Span, diags: &mut Diagnostics) {
    const PRIMS: &[&str] = &["bool", "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize", "char", "str", "f32", "f64", "Option", "Some", "None", "Int", "Prop", "Nat", "Seq"];
    if PRIMS.contains(&name) {
        diags.error(DiagKind::Resolve, span, format!("item name `{name}` shadows a primitive or prelude type"));
    }
}

#[allow(clippy::too_many_arguments)]
fn flatten_use(tree: &syn::UseTree, prefix: &mut Vec<(String, Span)>, m: ModId, vis: Vis, ghost: bool, file: FileId, out: &mut Vec<UseDirective>) {
    let span = Span::from_pm2(file, tree.span());
    match tree {
        syn::UseTree::Path(p) => {
            prefix.push((p.ident.to_string(), Span::from_pm2(file, p.ident.span())));
            flatten_use(&p.tree, prefix, m, vis, ghost, file, out);
            prefix.pop();
        }
        syn::UseTree::Name(n) => {
            let mut segs = prefix.clone();
            segs.push((n.ident.to_string(), Span::from_pm2(file, n.ident.span())));
            out.push(UseDirective { module: m, segs, bind: None, glob: false, vis, ghost, span });
        }
        syn::UseTree::Rename(r) => {
            let mut segs = prefix.clone();
            segs.push((r.ident.to_string(), Span::from_pm2(file, r.ident.span())));
            out.push(UseDirective { module: m, segs, bind: Some(r.rename.to_string()), glob: false, vis, ghost, span });
        }
        syn::UseTree::Glob(_) => {
            out.push(UseDirective { module: m, segs: prefix.clone(), bind: None, glob: true, vis, ghost, span });
        }
        syn::UseTree::Group(g) => {
            for t in &g.items {
                flatten_use(t, prefix, m, vis, ghost, file, out);
            }
        }
    }
}
