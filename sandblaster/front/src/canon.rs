//! The canonical printer (DESIGN.md §2 generated-code shape, §8.3 canonical
//! dialect), phase-1 version: prints from the HIR (no proofs, no optimizer).
//!
//! # Output shape (§2)
//!
//! ```text
//! // header (UNVERIFIED (phase 1) marker)
//! #[cfg(not(target_pointer_width = "64"))] compile_error!("sandblaster requires a 64-bit target");
//! #[deny(unsafe_code, overflowing_literals, unconditional_recursion)]
//! #[allow(arithmetic_overflow, unconditional_panic, <harmless lints>)]
//! mod __sandblaster { /* every non-ghost DSL module, inline */ }
//! mod __rt { /* checked-arithmetic helpers (phase 3, when used) */ }
//! pub use __sandblaster::<path> as <name>;   // one per boundary export
//! ```
//!
//! Every `pub use` of the source is printed ([`ReExport`]): the root's items
//! and modules are the boundary exports above (after the checked-arithmetic
//! glue module `mod __rt { .. }` when the code uses its helpers, see
//! *Canonical dialect*); every other re-export (of a
//! non-root module, or the root's re-exports of enum variants and `::core`
//! definitions) is printed where the source has it, as
//! `pub use crate::__sandblaster::<path> as <name>;` (the root's at the top
//! level), so the generated crate's public API is the source's. A re-export
//! the generated crate cannot have (a definition of the `sandblaster` crate, a
//! name that would shadow a primitive, a re-export rustc rejects) is not
//! printed and the round trip reports it as a failure; one whose target is
//! not emitted (the §9.2 evidence gate) follows its target and is reported
//! as an API difference.
//!
//! No inner attributes are emitted (the file is `include!`d). Ghost items,
//! ghost modules and `proof!` blocks are omitted.
//!
//! # Canonical dialect (§8.3)
//!
//! * absolute paths: items as `crate::__sandblaster::m::f`, `Option` as
//!   `::core::option::Option::<T>::None`, intrinsics as
//!   `::core::arch::aarch64::vaddq_u32`;
//! * every local renamed `l{id}_{name}`, every temporary `t{n}__{what}`,
//!   every tail-loop / dispatcher argument `a{k}__arg` (see *Generated
//!   names* below: never a name in scope);
//! * every integer literal suffixed (`7u32`), array lengths as `32usize`;
//! * methods in UFCS (`<u32>::rotate_right(x, 7u32)`, `<[u8]>::len(s)`,
//!   `<u32 as ::core::cmp::Ord>::min(a, b)`);
//! * explicit `&`/`*` (every [`Coercion`] is printed: auto-deref as `(*e)`,
//!   auto-ref as `(&e)`, unsizing as `(e as &[T])`) and fully explicit
//!   reference patterns (`&p`, `ref x`; no default binding modes);
//! * or-patterns expanded into consecutive arms, left to right
//!   ([`expand_or_arms`]); guards desugared into `if` with a fall-through
//!   `match` over the remaining arms (rustc's semantics: the guard is tried
//!   for each matching alternative in order); an inner fall-through match that
//!   is not syntactically exhaustive gets a final `_ => unreachable!()` arm;
//! * `if let` printed as `match`; `?` printed as a `match` with an early
//!   `return None`; `let` with or-patterns printed through a `match`;
//! * loops printed as `for x in a..b` / `for x in a..=b` / `while c`;
//! * tail-recursive free functions ([`Recursion::Tail`]) printed as the
//!   canonical `loop { … continue … return … }` (parameters are rebound at the
//!   top of each iteration);
//! * functions with non-trivial `requires` printed as `unsafe fn` with a
//!   `# Safety` doc stating the precondition; every call site is wrapped in
//!   `unsafe { /* SAFETY: .. */ .. }`. `#[allow(unsafe_code)]` is emitted
//!   exactly on such functions, their callers and the load/store helpers;
//! * index operations print as ordinary checked indexing (`get_unchecked`
//!   comes with proofs in phase 3);
//! * phase 3 (E0, design §11.5, SEMANTICS.md §3.1): every checked
//!   `+ - * << >>` of unsigned integers — a checked primitive of the core
//!   whose proof slot is kernel-checked — prints as a call of the helper
//!   `crate::__rt::chk::<op>_<w>(a, b)` ([`ChkHelper`]; `b` is the shift
//!   amount as `u32`, the core primitive's amount, printed `b as u32` when
//!   the source's amount has another width), and a checked compound
//!   assignment `P op= v` as `P = { let tN__v: T = v; crate::__rt::chk::<op>_<w>(P, tN__v) };`
//!   (the value first, then the place: rustc's order for integers, the
//!   elaboration's). The helpers are the fixed templates of the top-level
//!   glue module `__rt` ([`rt_module`]): wrapping without debug assertions
//!   (no check can fail: the proof slot holds), the checked operator with
//!   them (the debug-profile oracle, DESIGN.md §10.3). Division and
//!   remainder keep their operators (rustc checks division by zero in every
//!   profile), and so do `const` initializers (evaluated by rustc at compile
//!   time). Functions the print view marks `Inline::Hint` (the optimizer's
//!   residual helpers below its inline threshold, from plan O4 on) print
//!   `#[inline]`, a semantics-free attribute the round trip ignores.
//!
//! Visibility: boundary items (reachable through public paths) keep `pub`,
//! other `pub` items become `pub(crate)`; modules are `pub(crate)` (or `pub`
//! when exported, including through a re-export) so every canonical absolute
//! path is accessible wherever the item itself is visible. A re-export is
//! `pub` in an exported module and `pub(crate)` elsewhere, like the items
//! next to it.
//!
//! # Generated names
//!
//! **Invariant.** Every identifier the printer invents inside a function
//! (locals `l{id}_{name}`, temporaries `t{n}__{what}`, tail-loop and
//! dispatcher arguments `a{k}__arg`) is distinct from every name that can be
//! in scope, unqualified, anywhere in the generated file: every name
//! declared at module level in any printed module (items of every kind,
//! methods, enum variants, generic parameters, submodules, the source's
//! re-exports — `pub use … as name`, renames included —, boundary exports,
//! the glue items `__sandblaster` / `__arch` / `__dispatch`, boundary
//! dispatchers, multiversioned clones and specialized residuals, which are
//! items of the print view) and every name of rustc's std/core and extern
//! preludes and the primitive types ([`PRELUDE_NAMES`]). The allocator
//! ([`GenNames`]) guarantees it by construction: it starts from the form
//! above and appends `_` while the candidate is in that set (the reserved
//! set is computed from the same crate, re-exports and dispatchers the
//! printer prints, so nothing printed is missing from it). A printed local
//! is therefore always a fresh binding in rustc — never a constant, unit
//! struct or unit variant pattern (a *capture*: `l1_y if l1_y > 3` with a
//! constant `l1_y` in scope silently matches only that constant) — and in
//! expressions it is the innermost binding of that name. Distinct locals of
//! a function get distinct names (`l{id}_` fixes the id; temporaries and
//! arguments have other first letters). The fixed glue templates' own
//! bindings (`a` and `out` in the `__arch` helpers, `yes` in `__dispatch`,
//! `a` and `b` in `__rt::chk`) live in modules that declare only the
//! helpers (`load_*`, `store_*`, `m128i_from_u32x4`, `<op>_<w>`) and
//! `STATE_*` / `has_*`.
//!
//! The round trip does not rely on this: it resolves every identifier
//! pattern of the printed text the way rustc does, from the module scopes it
//! reads back (items, `use`s, the prelude), and rejects any local that
//! shadows or is shadowed by a module-scope name (`roundtrip`, *Name
//! resolution*).
//!
//! Name equality is spelling equality: the front end admits only ASCII,
//! non-raw identifiers (`loader::check_identifiers`: rustc NFC-normalizes
//! identifiers and reads `r#x` as `x`), rejects source names spelled like
//! the glue (`__sandblaster`, `__arch`, `__dispatch`) and associated
//! functions named like a variant of their enum (`<E>::A(..)` would name the
//! variant), and reports a source name spelled like an optimizer-generated
//! item (`f__<set>`, `f__portable`, a dispatcher `f`) in the same scope
//! (`driver::printed_name_collisions`); the round trip checks all of it
//! again on the printed text.

use std::collections::{BTreeSet, HashSet};
use std::fmt::Write as _;

use crate::builtins::{ArrayMethod, Builtin};
use crate::hir::*;
use crate::intrinsics::{self, HelperId};
use crate::resolve::{Def, Ext, Resolver};
use crate::span::{SourceMap, Span};

/// Marker placed in the header of phase-1 output.
pub const UNVERIFIED: &str = "UNVERIFIED (phase 1)";

/// Marker placed in the header of **stage output** (`driver::stage`): the
/// toolchain's own runs, whose proofs may have checked, but not a crate
/// verdict — the §15 gates did not run. Every consumer of crate output
/// (the `include!` glue, the bench and oracle `build.rs` files, `cgen`)
/// rejects it: they accept only [`OPTIMIZED`].
pub const STAGE: &str = "STAGE OUTPUT (not a crate verdict: the §15 gates did not run)";

/// The status of a stage run whose proofs checked (`driver::status_str`).
pub const STAGE_RUN: &str = "PROOFS CHECKED (stage run, no crate verdict: the §15 gates did not run)";

/// Marker placed in the header of a crate verdict (`driver::gates`, the
/// only printer call that holds a `GatesPassed`): verified, every §15 gate
/// passed, optimized, round-tripped.
pub const OPTIMIZED: &str = "VERIFIED + OPTIMIZED (phase 3)";

/// The first two lines of a crate verdict's file (what consumers check).
pub fn verdict_header_first_lines(root_display: &str) -> String {
    format!("// @generated by sandblaster from `{root_display}`. Do not edit.\n// STATUS: {OPTIMIZED}:")
}

/// What the phase-3 printer needs besides the print view.
pub struct OptPrint<'a> {
    pub dispatchers: &'a [crate::opt::Dispatcher],
    pub sets: &'a [crate::opt::multiversion::VariantSet],
    /// For every printed exec function, the kernel definition whose proven
    /// obligations justify its unchecked operations (its residual for a
    /// specialized function).
    pub kernel_def: std::collections::HashMap<ItemId, String>,
    /// Source span → `(definition, obligation kind, obligation id)`.
    pub obligations: std::collections::HashMap<crate::span::Span, Vec<(String, &'static str, u32)>>,
    /// Test-only exec-only elaboration (ghost items not elaborated): the
    /// header says so and never claims a verified build.
    pub exec_only: bool,
    /// The source's re-exports outside the boundary ([`source_reexports`]).
    pub reexports: &'a [ReExport],
    /// The Merkle root of `SPEC.lock` (all zero when the specification is
    /// not locked), exported as [`SPEC_ROOT_NAME`] ([`spec_root_item`]).
    pub spec_root: [u8; 32],
    /// The crate gate's seal: with it the header is the verdict's
    /// ([`OPTIMIZED`]); without it (every stage run) the stage header
    /// ([`STAGE`]). Only `driver::gates` can make one.
    pub verdict: Option<&'a crate::driver::gates::GatesPassed>,
}

/// The name of the constant the generated crate exports with the Merkle
/// root of its `SPEC.lock` (DESIGN.md §15.6).
pub const SPEC_ROOT_NAME: &str = "SANDBLASTER_SPEC_ROOT";

/// The last top-level item of optimized output (trusted glue, a fixed
/// template compared token for token by the round trip): the root of the
/// crate's `SPEC.lock` when the lock matches the computed specification
/// surface (always, in a crate verdict: the lock gate fails the build
/// otherwise), all zero otherwise (stage output of a crate without a
/// matching lock). A consumer pins the
/// specification it reviewed by comparing it, in a `const` assertion, with
/// the `root` line of the reviewed `SPEC.lock`.
pub fn spec_root_item(root: &[u8; 32]) -> String {
    let bytes: Vec<String> = root.iter().map(|b| format!("0x{b:02x}u8")).collect();
    format!(
        "/// The Merkle root of this crate's SPEC.lock (DESIGN.md §15.6); all zero when the specification is not locked.\npub const {SPEC_ROOT_NAME}: [u8; 32] = [{}];\n",
        bytes.join(", ")
    )
}

/// Prints the optimized crate (marked [`OPTIMIZED`] with the crate gate's
/// seal, [`STAGE`] otherwise): the print
/// view of the optimizer (specialized residuals, multiversioned clones,
/// renamed portable functions), with proven bounds checks printed as
/// `get_unchecked` forms (each with a `SAFETY:` comment naming its
/// obligation), boundary dispatchers and the runtime-detection module
/// (trusted glue, fixed templates). `note` is added to the header.
pub fn print_crate_optimized(krate: &Crate, sm: &SourceMap, root_display: &str, note: &str, opt: OptPrint<'_>) -> String {
    let mut p = Printer::with_context(krate, sm, opt.reexports, opt.dispatchers);
    p.verified = Some(note.to_string());
    p.opt = Some(opt);
    p.run(root_display)
}

/// Prints the whole crate (phase-1 flavour, marked [`UNVERIFIED`]);
/// `reexports` are the source's re-exports outside the boundary
/// ([`source_reexports`]).
pub fn print_crate(krate: &Crate, sm: &SourceMap, root_display: &str, reexports: &[ReExport]) -> String {
    let mut p = Printer::with_context(krate, sm, reexports, &[]);
    p.run(root_display)
}

/// Prints the whole (unoptimized) crate after its proofs checked: same
/// code as [`print_crate`], but the `# Safety` docs and the `SAFETY:`
/// comments state that the obligations were discharged by the kernel. It
/// is stage output (marked [`STAGE`]): no crate verdict. `note` is an
/// extra header line. Only `driver::stage` calls this.
pub fn print_crate_stage(krate: &Crate, sm: &SourceMap, root_display: &str, note: &str, reexports: &[ReExport]) -> String {
    let mut p = Printer::with_context(krate, sm, reexports, &[]);
    p.verified = Some(note.to_string());
    p.run(root_display)
}

// ---------------------------------------------------------------------------
// re-exports
// ---------------------------------------------------------------------------

/// A `pub use` of the source that the boundary exports (`Crate::boundary`:
/// the root's items and modules) do not cover: every public re-export of a
/// non-root module, and the root's re-exports of enum variants and external
/// definitions. The HIR has no place for them, so the driver collects them
/// from the resolver ([`source_reexports`]) and hands them to the printer
/// and the round trip, which checks that each is printed exactly once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReExport {
    /// The module of the `pub use`.
    pub module: ModId,
    /// The name it binds (the `as` name, or the target's).
    pub name: String,
    pub target: ReExportTarget,
    /// The `use` declaration.
    pub span: Span,
}

/// What a [`ReExport`] names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReExportTarget {
    Item(ItemId),
    Module(ModId),
    /// Variant `k` of an enum item.
    Variant(ItemId, u32),
    /// A definition outside the DSL crate, by its absolute path (`::core::..`),
    /// and the architecture it exists on (intrinsics and vector types).
    External { path: String, arch: Option<String> },
    /// The generated crate cannot have this re-export (the reason). It is not
    /// printed; the round trip reports it as a failure (never dropped
    /// silently).
    Unsupported(String),
}

/// Names a re-export may not bind in the type namespace of a generated
/// module: the printer writes primitive types unqualified (`u8`, `bool`), so
/// such a binding would change what the module's code means. (Everything
/// else it writes is an absolute path.)
const PRIMITIVE_TYPES: &[&str] = &["bool", "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize", "char", "str", "f32", "f64"];

/// Names in scope in every generated module without being declared there:
/// rustc's std/core prelude (editions 2021 and 2024, every namespace but
/// macros: the unit variant `None`, the constructors `Some`/`Ok`/`Err`, the
/// prelude functions, types and traits), the extern prelude crates the
/// generated file can rely on (`core`, `std`, `alloc`), the primitive types
/// ([`PRIMITIVE_TYPES`]) and the path keywords. Generated names avoid them
/// ([`GenNames`]; none has the generated forms anyway).
pub const PRELUDE_NAMES: &[&str] = &[
    // value namespace
    "None", "Some", "Ok", "Err", "drop", "size_of", "size_of_val", "align_of", "align_of_val",
    // type namespace
    "Option", "Result", "Vec", "String", "Box", "ToOwned", "ToString", "Clone", "Copy", "Send", "Sized", "Sync", "Unpin", "Drop", "Fn", "FnMut", "FnOnce", "AsyncFn", "AsyncFnMut", "AsyncFnOnce", "AsRef", "AsMut", "Into", "From", "Default", "Iterator", "Extend", "IntoIterator", "DoubleEndedIterator", "ExactSizeIterator", "Eq", "PartialEq", "Ord", "PartialOrd", "TryFrom", "TryInto", "FromIterator", "Future", "IntoFuture",
    // extern prelude and path keywords
    "core", "std", "alloc", "crate", "self", "super", "Self",
];

/// The generated-name allocator of the canonical dialect (see *Generated
/// names* in the module docs): a generated name is its form (`l{id}_{name}`,
/// `t{n}__{what}`, `a{k}__arg`) extended with `_` until it is none of the
/// reserved names — every name declared at module level anywhere in the
/// printed crate and every prelude name. The printer and the round trip's
/// spelling check share it (the canonical form); the round trip's
/// resolution check does not ([`crate::roundtrip`]).
#[derive(Clone, Debug, Default)]
pub struct GenNames {
    reserved: HashSet<String>,
}

impl GenNames {
    /// The allocator of the crate printed from `krate` with the source's
    /// re-exports `reexports` and the boundary dispatchers `dispatchers`.
    pub fn new(krate: &Crate, reexports: &[ReExport], dispatchers: &[crate::opt::Dispatcher]) -> GenNames {
        let mut reserved: HashSet<String> = HashSet::new();
        let mut add = |s: &str| {
            reserved.insert(s.to_string());
            reserved.insert(clean_ident(s).to_string());
        };
        for n in PRELUDE_NAMES.iter().chain(PRIMITIVE_TYPES) {
            add(n);
        }
        for n in ["__sandblaster", "__arch", "__dispatch", "__rt"] {
            add(n);
        }
        for m in &krate.modules {
            add(&m.name);
        }
        for it in &krate.items {
            add(&it.name);
            match &it.kind {
                ItemKind::Enum(e) => {
                    e.variants.iter().for_each(|v| add(&v.name));
                    e.generics.iter().for_each(|g| add(&g.name));
                }
                ItemKind::Struct(s) => s.generics.iter().for_each(|g| add(&g.name)),
                ItemKind::Fn(f) => f.generics.iter().for_each(|g| add(&g.name)),
                _ => {}
            }
        }
        for e in &krate.boundary {
            add(&e.name);
        }
        for r in reexports {
            add(&r.name);
        }
        for d in dispatchers {
            add(&d.name);
        }
        GenNames { reserved }
    }

    fn fresh(&self, mut n: String) -> String {
        while self.reserved.contains(&n) {
            n.push('_');
        }
        n
    }

    /// The printed name of local `id` of the current function, named `orig`
    /// in the source (`self` stays `self`).
    pub fn local(&self, id: usize, orig: &str) -> String {
        let orig = clean_ident(orig);
        if orig == "self" {
            return "self".into();
        }
        self.fresh(format!("l{id}_{orig}"))
    }

    /// The `n`-th temporary of the current function (`t{n}__{what}`).
    pub fn temp(&self, n: u32, what: &str) -> String {
        self.fresh(format!("t{n}__{what}"))
    }

    /// The name of argument `k` of a tail loop or a dispatcher
    /// (`a{k}__arg`).
    pub fn arg(&self, k: usize) -> String {
        self.fresh(format!("a{k}__arg"))
    }

    /// Whether `name` is reserved (a module-level or prelude name).
    pub fn is_reserved(&self, name: &str) -> bool {
        self.reserved.contains(name)
    }
}

/// Whether re-exporting `target` binds a name in the type namespace
/// (modules, types, variants; external paths conservatively).
fn binds_type_ns(krate: &Crate, target: &ReExportTarget) -> bool {
    match target {
        ReExportTarget::Item(id) => matches!(krate.item(*id).kind, ItemKind::Struct(_) | ItemKind::Enum(_) | ItemKind::TypeAlias(_)),
        ReExportTarget::Module(_) | ReExportTarget::Variant(..) | ReExportTarget::External { .. } => true,
        ReExportTarget::Unsupported(_) => false,
    }
}

/// The source's re-exports outside the boundary (see [`ReExport`]), from the
/// resolver's public bindings: every non-ghost public binding of a non-ghost
/// module that is not the definition it names (an item defined in that
/// module under that name, a submodule declared there), in module order and
/// then by name. The root's item and module re-exports are left out: they
/// are boundary exports.
pub fn source_reexports(res: &Resolver, krate: &Crate) -> Vec<ReExport> {
    let mut out = Vec::new();
    for module in &krate.modules {
        if module.ghost {
            continue;
        }
        let m = module.id;
        let root = m == krate.root;
        for crate::resolve::PublicName { name, def, span, ghost, .. } in res.public_names(m) {
            if ghost {
                continue;
            }
            let not_pub = |what: &str, code: &str| ReExportTarget::Unsupported(format!("{what} is not `pub`: rustc rejects re-exporting it ({code})"));
            let target = match def {
                Def::Item(id) => {
                    let it = krate.item(id);
                    if it.ghost || root || (it.module == m && it.name == name) {
                        continue;
                    }
                    if it.vis == Vis::Public { ReExportTarget::Item(id) } else { not_pub(&format!("`{}`", it.path), "E0364") }
                }
                Def::Mod(c) => {
                    let cm = krate.module(c);
                    if cm.ghost || root || (cm.parent == Some(m) && cm.name == name) {
                        continue;
                    }
                    if cm.vis == Vis::Public { ReExportTarget::Module(c) } else { not_pub(&format!("module `{}`", cm.path), "E0365") }
                }
                Def::Variant(e, k) => {
                    let it = krate.item(e);
                    if it.ghost {
                        continue;
                    }
                    if it.vis == Vis::Public { ReExportTarget::Variant(e, k) } else { not_pub(&format!("`{}`", it.path), "E0364") }
                }
                Def::Ext(x) => external_target(x),
            };
            let target = if PRIMITIVE_TYPES.contains(&name.as_str()) && binds_type_ns(krate, &target) {
                ReExportTarget::Unsupported(format!("the name `{name}` would shadow the primitive type in the generated module, whose code names primitive types unqualified"))
            } else {
                target
            };
            out.push(ReExport { module: m, name, target, span });
        }
    }
    out
}

/// The target of a re-export of a definition outside the DSL crate.
fn external_target(x: Ext) -> ReExportTarget {
    let ext = |path: String, arch: Option<&str>| ReExportTarget::External { path, arch: arch.map(str::to_string) };
    match x {
        Ext::Core => ext("::core".into(), None),
        Ext::CoreOption => ext("::core::option".into(), None),
        Ext::OptionEnum => ext("::core::option::Option".into(), None),
        Ext::SomeCtor => ext("::core::option::Option::Some".into(), None),
        Ext::NoneCtor => ext("::core::option::Option::None".into(), None),
        Ext::CoreArch => ext("::core::arch".into(), None),
        Ext::ArchMod(t) => {
            let a = t.arch();
            ext(format!("::core::arch::{}", a.name()), Some(a.name()))
        }
        Ext::Intrinsic(id) => {
            let info = intrinsics::get(id);
            ext(info.path(), Some(info.arch.name()))
        }
        Ext::VecType(v) => ext(v.path(), Some(v.arch().name())),
        Ext::MaskType(bits) => ext(format!("::core::arch::x86_64::__mmask{bits}"), Some("x86_64")),
        Ext::Helper(h) => ReExportTarget::Unsupported(format!("it names the trusted load/store helper `{}`, which generated code keeps private (`__arch`, DESIGN.md §9.2)", intrinsics::helper(h).name)),
        other => ReExportTarget::Unsupported(format!("it names `{other:?}` of the `sandblaster` crate, which generated code does not depend on")),
    }
}

/// Where a re-export is printed: the path of its module (`crate::a::b`).
pub fn reexport_site(krate: &Crate, r: &ReExport) -> String {
    format!("{}::{}", krate.module(r.module).path, r.name)
}

/// What a re-export names, as a path of the source (`crate::m::f`,
/// `::core::option::Option`), or why the generated crate cannot have it.
pub fn reexport_target(krate: &Crate, r: &ReExport) -> Result<String, String> {
    match &r.target {
        ReExportTarget::Item(id) => Ok(krate.item(*id).path.to_string()),
        ReExportTarget::Module(m) => Ok(krate.module(*m).path.to_string()),
        ReExportTarget::Variant(e, k) => {
            let it = krate.item(*e);
            let v = match &it.kind {
                ItemKind::Enum(en) => en.variants.get(*k as usize).map(|v| v.name.clone()).unwrap_or_default(),
                _ => String::new(),
            };
            Ok(format!("{}::{v}", it.path))
        }
        ReExportTarget::External { path, .. } => Ok(path.clone()),
        ReExportTarget::Unsupported(why) => Err(why.clone()),
    }
}

/// The text of re-export `r` as printed (its `#[cfg]` line and the `use`
/// item, at indentation `i`), or `None` when it is not printed: unsupported,
/// or its target is not emitted (a ghost item of the print view). The root's
/// re-exports are printed at the top level (`__sandblaster::..` paths, like
/// the boundary exports), the others inside their module, `pub` when the
/// module is exported and `pub(crate)` otherwise. A multiversioned
/// function is re-exported through its boundary dispatcher.
pub fn reexport_text(krate: &Crate, dispatchers: &[crate::opt::Dispatcher], exported_mods: &HashSet<ModId>, r: &ReExport, i: usize) -> Option<String> {
    let (path, cfg) = match &r.target {
        ReExportTarget::Item(id) => {
            let it = krate.item(*id);
            if it.ghost {
                return None;
            }
            let path = match dispatchers.iter().find(|d| d.portable == *id) {
                Some(d) => format!("{}::{}", abs_mod_path(krate, d.module), clean_ident(&d.name)),
                None => abs_item_path(krate, *id),
            };
            (path, it.cfg.clone())
        }
        ReExportTarget::Module(c) => {
            let cm = krate.module(*c);
            if cm.ghost {
                return None;
            }
            (abs_mod_path(krate, *c), cm.cfg.clone())
        }
        ReExportTarget::Variant(e, k) => {
            let it = krate.item(*e);
            let ItemKind::Enum(en) = &it.kind else { return None };
            if it.ghost {
                return None;
            }
            (format!("{}::{}", abs_item_path(krate, *e), clean_ident(&en.variants.get(*k as usize)?.name)), it.cfg.clone())
        }
        ReExportTarget::External { path, arch } => (path.clone(), arch.as_ref().map(|a| format!("target_arch = {a:?}"))),
        ReExportTarget::Unsupported(_) => return None,
    };
    let top = r.module == krate.root;
    let path = if top { path.strip_prefix("crate::").map(str::to_string).unwrap_or(path) } else { path };
    let vis = if top || exported_mods.contains(&r.module) { "pub" } else { "pub(crate)" };
    let mut out = String::new();
    Printer::cfg(&mut out, &cfg, i);
    let _ = writeln!(out, "{}{vis} use {path} as {};", ind(i), clean_ident(&r.name));
    Some(out)
}

/// Expands or-patterns of match arms into consecutive arms (cross product of
/// nested or-patterns, leftmost alternative varying slowest), keeping guards
/// and bodies — the normative expansion of DESIGN.md §7.3.
pub fn expand_or_arms(arms: &[Arm]) -> Vec<Arm> {
    let mut out = Vec::new();
    for a in arms {
        for p in expand_pat(&a.pat) {
            out.push(Arm { pat: p, guard: a.guard.clone(), body: a.body.clone(), span: a.span });
        }
    }
    out
}

/// All or-free alternatives of a pattern, in rustc's order.
pub fn expand_pat(p: &Pat) -> Vec<Pat> {
    let mk = |kind: PatKind| Pat { kind, ty: p.ty.clone(), span: p.span };
    match &p.kind {
        PatKind::Or(alts) => alts.iter().flat_map(expand_pat).collect(),
        PatKind::Binding { local, mode, sub: Some(s) } => expand_pat(s).into_iter().map(|s| mk(PatKind::Binding { local: *local, mode: *mode, sub: Some(Box::new(s)) })).collect(),
        PatKind::Tuple(ps) => product(ps).into_iter().map(|v| mk(PatKind::Tuple(v))).collect(),
        PatKind::Ctor { ctor, ty_args, fields } => {
            let ps: Vec<Pat> = fields.iter().map(|(_, p)| p.clone()).collect();
            product(&ps).into_iter().map(|v| mk(PatKind::Ctor { ctor: *ctor, ty_args: ty_args.clone(), fields: fields.iter().map(|(i, _)| *i).zip(v).collect() })).collect()
        }
        PatKind::Deref { pat, implicit } => expand_pat(pat).into_iter().map(|s| mk(PatKind::Deref { pat: Box::new(s), implicit: *implicit })).collect(),
        PatKind::Slice { prefix, rest, suffix } => {
            let mut all: Vec<Pat> = prefix.clone();
            let rest_p = match rest {
                Some(Some(r)) => Some((**r).clone()),
                _ => None,
            };
            if let Some(r) = &rest_p {
                all.push(r.clone());
            }
            all.extend(suffix.iter().cloned());
            product(&all)
                .into_iter()
                .map(|mut v| {
                    let suf: Vec<Pat> = v.split_off(prefix.len() + usize::from(rest_p.is_some()));
                    let r = if rest_p.is_some() { Some(Some(Box::new(v.pop().unwrap()))) } else { rest.as_ref().map(|_| None) };
                    mk(PatKind::Slice { prefix: v, rest: r, suffix: suf })
                })
                .collect()
        }
        _ => vec![p.clone()],
    }
}

fn product(ps: &[Pat]) -> Vec<Vec<Pat>> {
    let mut acc: Vec<Vec<Pat>> = vec![vec![]];
    for p in ps {
        let alts = expand_pat(p);
        let mut next = Vec::new();
        for prefix in &acc {
            for a in &alts {
                let mut v = prefix.clone();
                v.push(a.clone());
                next.push(v);
            }
        }
        acc = next;
    }
    acc
}

/// The trusted load/store helper `h` as printed in `__arch` (DESIGN.md
/// §9.2; fixed template, compared verbatim by the round trip).
pub fn helper_fn_text(krate: &Crate, h: HelperId, i: usize) -> String {
    let sm = SourceMap::new();
    let p = Printer::new(krate, &sm);
    let info = intrinsics::helper(h);
    let pt = info.params.first().map(|t| p.ty(t)).unwrap_or_default();
    let mut out = String::new();
    let _ = writeln!(out, "{}#[target_feature(enable = {:?})]", ind(i), info.features.join(","));
    let _ = writeln!(out, "{}#[inline]", ind(i));
    let _ = writeln!(out, "{}#[allow(unsafe_code)]", ind(i));
    let _ = writeln!(out, "{}pub(crate) fn {}(a: {pt}) -> {} {{ {} }}", ind(i), info.name, p.ty(&info.ret), intrinsics::helper_template(h));
    out
}

/// A lane kernel as the optimized printer prints it (plan O10): the item's
/// text, and the load/store helpers and checked-arithmetic helpers it
/// calls (their text is [`helper_fn_text`] and [`rt_module`], compared
/// verbatim by the round trip).
pub struct LaneKernelText {
    pub item: String,
    pub helpers: Vec<HelperId>,
    pub chk: BTreeSet<ChkHelper>,
}

/// Prints the function `id` of `krate` as phase-3 printing does (proven
/// bounds checks as `get_unchecked` forms, tail loops, …), without the
/// crate around it. Only the `SAFETY:` comments differ from the emitted
/// text (the obligation tables are the driver's), and generated local
/// names could only differ if a later stage added a module-level name
/// spelled like one of them: the round trip compares the emitted kernel's
/// tokens against this print (`roundtrip`, lane kernels), so any
/// difference is a build error, never a silent mismatch.
pub fn lane_kernel_text(krate: &Crate, id: ItemId) -> LaneKernelText {
    let sm = SourceMap::new();
    let mut p = Printer::new(krate, &sm);
    p.verified = Some(String::new());
    p.opt = Some(OptPrint { dispatchers: &[], sets: &[], kernel_def: Default::default(), obligations: Default::default(), exec_only: false, reexports: &[], spec_root: [0; 32], verdict: None });
    let item = p.item(id, 0);
    LaneKernelText { item, helpers: p.helpers.iter().copied().collect(), chk: p.chk.clone() }
}

/// The fixed items and attributes around `mod __sandblaster` (§2), as
/// printed (the round trip compares them verbatim).
pub const GUARD_ITEM: &str = "#[cfg(not(target_pointer_width = \"64\"))]\ncompile_error!(\"sandblaster requires a 64-bit target\");";
/// The lint attributes of `mod __sandblaster`.
///
/// `arithmetic_overflow` and `unconditional_panic` (rustc's const-propagation
/// lints, deny-by-default) are allowed: they fire on operations rustc can
/// evaluate statically whether or not they are reachable, and every
/// reachable operation's overflow / division / bounds obligation is proven
/// — a hit is necessarily in code that is dead under the proven facts (a
/// branch whose guard is provably false), which verification accepts
/// vacuously (red team: `if x > 5 && x < 3 { x / 0 } else { x }`).
pub const MOD_ATTRS: &str = "#[deny(unsafe_code, overflowing_literals, unconditional_recursion)]\n#[allow(arithmetic_overflow, unconditional_panic, dead_code, unused_variables, unused_mut, unused_assignments, unused_parens, unused_braces, unused_unsafe, unreachable_patterns, unreachable_code, irrefutable_let_patterns, non_snake_case, non_camel_case_types, non_upper_case_globals, clippy::all)]";

// ---------------------------------------------------------------------------
// checked arithmetic (E0, design §11.5)
// ---------------------------------------------------------------------------

/// The operation of a checked-arithmetic helper.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChkOp {
    Add,
    Sub,
    Mul,
    Shl,
    Shr,
}

/// A checked-arithmetic helper `crate::__rt::chk::<op>_<w>` (E0, design
/// §11.5, SEMANTICS.md §3.1): the printing of the core's checked primitive
/// `#<op>_<w>(a, b; p)` in phase 3. Its meaning is that primitive's: the
/// machine operation, whenever the proof slot's proposition holds — which
/// the kernel checked for every printed occurrence. The template ([`rt_module`])
/// computes it by wrapping without debug assertions (equal to the exact
/// result when the slot holds; never undefined behaviour otherwise) and by
/// the checked operator with them (rustc's overflow check, the debug-profile
/// oracle). The round trip lowers a call back to the checked primitive with
/// an `Erased` slot, operand order and width included (`roundtrip`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChkHelper {
    pub op: ChkOp,
    /// The width of the result and of the first operand.
    pub w: UintTy,
}

/// The module path of the checked-arithmetic helpers.
pub const CHK_PATH: &str = "crate::__rt::chk";

impl ChkHelper {
    /// The helper of `a op b` with `a: w`; `None` for an operator without
    /// one (`/` and `%` keep their operators: rustc checks division by zero
    /// in every profile; the other operators have no proof slot).
    pub fn of(op: BinOp, w: UintTy) -> Option<ChkHelper> {
        let op = match op {
            BinOp::Add => ChkOp::Add,
            BinOp::Sub => ChkOp::Sub,
            BinOp::Mul => ChkOp::Mul,
            BinOp::Shl => ChkOp::Shl,
            BinOp::Shr => ChkOp::Shr,
            _ => return None,
        };
        Some(ChkHelper { op, w })
    }

    /// The HIR operator the helper prints.
    pub fn bin_op(self) -> BinOp {
        match self.op {
            ChkOp::Add => BinOp::Add,
            ChkOp::Sub => BinOp::Sub,
            ChkOp::Mul => BinOp::Mul,
            ChkOp::Shl => BinOp::Shl,
            ChkOp::Shr => BinOp::Shr,
        }
    }

    fn op_name(self) -> &'static str {
        match self.op {
            ChkOp::Add => "add",
            ChkOp::Sub => "sub",
            ChkOp::Mul => "mul",
            ChkOp::Shl => "shl",
            ChkOp::Shr => "shr",
        }
    }

    /// Whether the helper is a shift (its second operand is the amount).
    pub fn is_shift(self) -> bool {
        matches!(self.op, ChkOp::Shl | ChkOp::Shr)
    }

    /// The type of the second operand: `w`, or `u32` for a shift amount
    /// (the core primitive's amount, SEMANTICS.md §3).
    pub fn rhs(self) -> UintTy {
        if self.is_shift() { UintTy::U32 } else { self.w }
    }

    /// The helper's name, `<op>_<w>` (`add_u64`, `shr_usize`).
    pub fn name(self) -> String {
        format!("{}_{}", self.op_name(), self.w.name())
    }

    /// The helper named `name` (the inverse of [`ChkHelper::name`]).
    pub fn parse(name: &str) -> Option<ChkHelper> {
        let (op, w) = name.split_once('_')?;
        let w = UintTy::from_name(w)?;
        let h = [ChkOp::Add, ChkOp::Sub, ChkOp::Mul, ChkOp::Shl, ChkOp::Shr].into_iter().map(|op| ChkHelper { op, w }).find(|h| h.op_name() == op)?;
        Some(h)
    }

    /// The helper's definition in the profile with (`debug`) or without
    /// debug assertions (a fixed template).
    fn text(self, i: usize, debug: bool) -> String {
        let (w, r) = (self.w.name(), self.rhs().name());
        let body = if debug { format!("a {} b", self.bin_op().symbol()) } else { format!("<{w}>::wrapping_{}(a, b)", self.op_name()) };
        format!("{}#[inline(always)]\n{}pub(crate) fn {}(a: {w}, b: {r}) -> {w} {{ {body} }}\n", ind(i), ind(i), self.name())
    }
}

/// The checked-arithmetic glue module (trusted glue, design §11.5; fixed
/// template, compared verbatim by the round trip): printed at the top level
/// of the generated file, after `mod __sandblaster`, when the code calls a
/// helper; it defines exactly the helpers `helpers` the code calls, in two
/// `chk` modules, one per profile.
pub fn rt_module(helpers: &BTreeSet<ChkHelper>) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "// Trusted glue (DESIGN.md §8.3, SEMANTICS.md §3.1): the checked operations whose obligation");
    let _ = writeln!(out, "// (overflow, underflow, shift width) is proven and kernel-checked. Without debug assertions");
    let _ = writeln!(out, "// they wrap, which gives the exact result because the obligation holds; with debug");
    let _ = writeln!(out, "// assertions they are the checked operators (the debug-profile oracle, DESIGN.md §10.3).");
    let _ = writeln!(out, "mod __rt {{");
    for debug in [false, true] {
        let _ = writeln!(out, "    #[cfg({})]", if debug { "debug_assertions" } else { "not(debug_assertions)" });
        let _ = writeln!(out, "    pub(crate) mod chk {{");
        for h in helpers {
            out.push_str(&h.text(2, debug));
        }
        let _ = writeln!(out, "    }}");
    }
    let _ = writeln!(out, "}}");
    out
}

/// The `pub use` export lines of the optimized output of `krate`: the
/// boundary exports, then the root's other re-exports (`reexports` of the
/// root module, [`reexport_text`]).
pub fn export_lines(krate: &Crate, dispatchers: &[crate::opt::Dispatcher], reexports: &[ReExport]) -> Vec<String> {
    let sm = SourceMap::new();
    let p = Printer::new(krate, &sm);
    let mut v = Vec::new();
    for e in &krate.boundary {
        let path = match e.target {
            ExportTarget::Item(i) => match dispatchers.iter().find(|d| d.portable == i) {
                Some(d) => {
                    let mut v: Vec<String> = krate.module(d.module).path.0.iter().map(|s| clean_ident(s).to_string()).collect();
                    v.push(clean_ident(&d.name).to_string());
                    v.join("::")
                }
                None => p.item_rel_path(i),
            },
            ExportTarget::Module(m) => krate.module(m).path.0.join("::"),
        };
        v.push(format!("pub use __sandblaster::{path} as {};", clean_ident(&e.name)));
    }
    let mods = exported_modules_with(krate, reexports);
    v.extend(reexports.iter().filter(|r| r.module == krate.root).filter_map(|r| reexport_text(krate, dispatchers, &mods, r, 0)));
    v
}

/// A type as the canonical printer prints it (body position).
pub fn type_text(krate: &Crate, t: &Ty) -> String {
    let sm = SourceMap::new();
    Printer::new(krate, &sm).ty(t)
}

/// Whether a place has an index projection.
fn place_has_index(p: &Place) -> bool {
    p.projs.iter().any(|x| matches!(x, Proj::Index(_)))
}

/// Whether a function body has an index, range or indexed assignment
/// (printed unchecked in phase 3).
fn has_unchecked_ops(f: &FnDef) -> bool {
    struct V(bool);
    impl crate::visit::Visitor for V {
        fn expr(&mut self, e: &Expr) {
            if matches!(e.kind, ExprKind::Index { .. } | ExprKind::SliceRange { .. }) {
                self.0 = true;
            }
            crate::visit::walk_expr(self, e);
        }
        fn stmt(&mut self, s: &Stmt) {
            match &s.kind {
                StmtKind::Assign { place, .. } | StmtKind::CompoundAssign { place, .. } if place_has_index(place) => self.0 = true,
                StmtKind::CopyFromSlice { range: Some(_), .. } => self.0 = true,
                _ => {}
            }
            crate::visit::walk_stmt(self, s);
        }
    }
    let mut v = V(false);
    if let FnBody::Exec(b) = &f.body {
        crate::visit::Visitor::expr(&mut v, b);
    }
    v.0
}

/// The `cfg` predicate under which a variant set's features are statically
/// enabled (and its complement for runtime detection).
fn set_static_cfg(set: &crate::opt::multiversion::VariantSet, arch: &str, negate: bool) -> String {
    let feats: Vec<String> = set.features.iter().map(|f| format!("target_feature = {f:?}")).collect();
    let fe = if feats.len() == 1 { feats[0].clone() } else { format!("all({})", feats.join(", ")) };
    let fe = if negate { format!("not({fe})") } else { fe };
    format!("all(target_arch = {arch:?}, target_endian = \"little\", {fe})")
}

/// Architecture of a variant set (from its feature names).
fn set_arch(set: &crate::opt::multiversion::VariantSet) -> &'static str {
    let x86 = ["sha", "sse2", "ssse3", "sse4.1", "sse4.2", "avx", "avx2", "avx512f", "aes", "pclmulqdq", "popcnt", "lzcnt", "bmi1", "bmi2"];
    if set.features.iter().any(|f| x86.contains(&f.as_str())) { "x86_64" } else { "aarch64" }
}

/// The name of the runtime-detection function of a set.
fn has_fn(set: &crate::opt::multiversion::VariantSet) -> String {
    format!("has_{}", set.name)
}

/// A deterministic known-answer argument of type `t` for parameter `k`
/// (integers and arrays of them; `None` for other types).
fn kat_value(t: &Ty, k: usize, j: &mut u64) -> Option<String> {
    Some(match t {
        Ty::Uint(u) => {
            *j += 1;
            let bits = u.bits();
            let v = (j.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ ((k as u64 + 1).wrapping_mul(0xbf58_476d_1ce4_e5b9))).rotate_left(17);
            let v = if bits >= 64 { v } else { v & ((1u64 << bits) - 1) };
            format!("{v}{}", u.name())
        }
        Ty::Bool => {
            *j += 1;
            (if j.is_multiple_of(2) { "true" } else { "false" }).to_string()
        }
        Ty::Array(e, n) if *n <= 256 => {
            let items: Option<Vec<String>> = (0..*n).map(|_| kat_value(e, k, j)).collect();
            format!("[{}]", items?.join(", "))
        }
        Ty::Ref(inner) => format!("&{}", kat_value(inner, k, j)?),
        _ => return None,
    })
}

/// Whether values of type `t` compare with `==` in the known-answer test.
fn kat_comparable(t: &Ty) -> bool {
    match t {
        Ty::Uint(_) | Ty::Bool => true,
        Ty::Array(e, _) => kat_comparable(e),
        Ty::Tuple(ts) => ts.iter().all(kat_comparable),
        _ => false,
    }
}

/// The known-answer self-test of a set (trusted glue, DESIGN.md §15.13
/// "Hardware self-test", optimizer design §13.2): a `#[target_feature]`
/// function run once, when the set's features are first detected.
///
/// * For the feature-only features: `lzcnt`, `tzcnt`, `popcnt`, `bzhi`,
///   `shlx`/`shrx` (and `pext` in `v4`) on fixed constants, including 0
///   and single bits. On a CPU without LZCNT/BMI1 the `lzcnt`/`tzcnt`
///   encodings run as `bsr`/`bsf` and compute other values; the test
///   catches that. POPCNT and BMI2 fault (`#UD`) where they are missing.
/// * For every `#[implements]` variant of the set (for example SHA-NI
///   `compress`): the variant against its portable function on fixed
///   inputs. The bit-count clones are not compared one by one: they use
///   the instructions the constant checks cover, and each is kernel-proven
///   equal to its original.
///
/// Every result and every argument goes through `black_box`, so the
/// compiler cannot fold a check into a comparison that no longer runs the
/// instruction (LLVM rewrites `lzcnt(z) == 64` into `z == 0`, and a
/// variant call on literal arguments into `true`). `bsr`/`bsf` leave the
/// destination unchanged for a zero source, so the zero cases run as
/// `asm!` with the destination cleared first. `None` when there is
/// nothing to test.
fn kat_fn(krate: &Crate, set: &crate::opt::multiversion::VariantSet, arch: &str, i: usize) -> Option<String> {
    let mut checks: Vec<String> = Vec::new();
    let mut pre: Vec<String> = Vec::new();
    let bb = |e: &str| format!("::core::hint::black_box({e})");
    if arch == "x86_64" && set.feature_only() {
        for (v, c) in [("z", "0u64"), ("one", "1u64"), ("top", "9223372036854775808u64"), ("x", "81985529216486895u64")] {
            pre.push(format!("let {v}: u64 = {};", bb(c)));
        }
        pre.push(format!("let four: u32 = {};", bb("4u32")));
        pre.push("let lz0: u64;".into());
        pre.push("let tz0: u64;".into());
        pre.push("// `bsr`/`bsf` leave the destination unchanged for a zero source: clear it first".into());
        pre.push("unsafe {".into());
        for (d, op) in [("lz0", "lzcnt"), ("tz0", "tzcnt")] {
            pre.push(format!("    ::core::arch::asm!(\"xor {{d:e}}, {{d:e}}\", \"{op} {{d}}, {{s}}\", d = out(reg) {d}, s = in(reg) z, options(pure, nomem, nostack));"));
        }
        pre.push("}".into());
        checks.push("lz0 == 64u64".into());
        for (v, want) in [("one", "63u64"), ("top", "0u64"), ("x", "7u64")] {
            checks.push(format!("{} == {want}", bb(&format!("::core::arch::x86_64::_lzcnt_u64({v})"))));
        }
        checks.push("tz0 == 64u64".into());
        for (v, want) in [("one", "0u64"), ("top", "63u64"), ("x", "0u64")] {
            checks.push(format!("{} == {want}", bb(&format!("::core::arch::x86_64::_tzcnt_u64({v})"))));
        }
        for (v, want) in [("z", "0i32"), ("x", "32i32"), ("top", "1i32")] {
            checks.push(format!("{} == {want}", bb(&format!("::core::arch::x86_64::_popcnt64({v} as i64)"))));
        }
        for (n, want) in [("8u32", "239u64"), ("0u32", "0u64"), ("64u32", "x")] {
            checks.push(format!("{} == {want}", bb(&format!("::core::arch::x86_64::_bzhi_u64(x, {})", bb(n)))));
        }
        checks.push(format!("{} == 1311768467463790320u64", bb("x << four")));
        checks.push(format!("{} == 5124095576030430u64", bb("x >> four")));
        if set.feature_set.iter().any(|f| f == "avx512f") {
            checks.push(format!("{} == 205u64", bb(&format!("::core::arch::x86_64::_pext_u64(x, {})", bb("65280u64")))));
        }
    }
    let mut maps: Vec<(ItemId, ItemId)> = set.map.iter().map(|(p, v)| (*p, *v)).collect();
    maps.sort();
    for (p, v) in maps {
        let Some(f) = krate.fn_def(v) else { continue };
        if !kat_comparable(&f.ret) {
            continue;
        }
        let mut j = 0u64;
        let args: Option<Vec<String>> = f.params.iter().enumerate().map(|(k, pa)| kat_value(&pa.ty, k, &mut j)).collect();
        let Some(args) = args else { continue };
        let a = args.iter().map(|x| bb(x)).collect::<Vec<_>>().join(", ");
        checks.push(format!("{} == {}", bb(&format!("{}({a})", abs_item_path(krate, v))), bb(&format!("{}({a})", abs_item_path(krate, p)))));
    }
    if checks.is_empty() {
        return None;
    }
    let mut out = String::new();
    let feats = set.features.join(",");
    let _ = writeln!(out, "{}// Known-answer self-test of `{{{}}}` (DESIGN.md §15.13): run once, when the features are", ind(i), set.name);
    let _ = writeln!(out, "{}// first detected; a mismatch pins the process to the portable code.", ind(i));
    let _ = writeln!(out, "{}#[cfg({})]", ind(i), set_static_cfg(set, arch, true));
    let _ = writeln!(out, "{}#[allow(unused_unsafe)]", ind(i));
    let _ = writeln!(out, "{}#[cold]", ind(i));
    let _ = writeln!(out, "{}#[inline(never)]", ind(i));
    let _ = writeln!(out, "{}#[target_feature(enable = {feats:?})]", ind(i));
    let _ = writeln!(out, "{}unsafe fn kat_{}() -> bool {{", ind(i), set.name);
    for l in &pre {
        let _ = writeln!(out, "{}{l}", ind(i + 1));
    }
    let _ = writeln!(out, "{}unsafe {{", ind(i + 1));
    let _ = writeln!(out, "{}{}", ind(i + 2), checks.join(&format!("\n{}&& ", ind(i + 2))));
    let _ = writeln!(out, "{}}}", ind(i + 1));
    let _ = writeln!(out, "{}}}", ind(i));
    Some(out)
}

/// The runtime-detection module (trusted glue, DESIGN.md §9.3): one cached
/// detection per variant set whose features are not statically enabled.
/// The state starts at 0 ("not yet detected", never a variant), becomes 1
/// (absent) or 2 (present). With plan O8 a set is present only if its
/// known-answer self-test also passes ([`kat_fn`]): it runs once, inside
/// the detection, so the hot path (one relaxed load and a branch per
/// boundary call) is unchanged. A set whose features are statically
/// enabled (`cfg(target_feature)`) has no run-time decision: every
/// function of the binary may use the features, so there is no portable
/// code to fall back to, and its dispatcher calls the clone directly.
pub fn dispatch_module(krate: &Crate, sets: &[crate::opt::multiversion::VariantSet], i: usize) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{}// Trusted glue (DESIGN.md §9.3): cached runtime feature detection.", ind(i));
    let _ = writeln!(out, "{}#[allow(unsafe_code)]", ind(i));
    let _ = writeln!(out, "{}pub(crate) mod __dispatch {{", ind(i));
    for set in sets {
        let arch = set_arch(set);
        let cfg = set_static_cfg(set, arch, true);
        let st = format!("STATE_{}", set.name.to_uppercase());
        let mut detect = set
            .features
            .iter()
            .map(|f| if arch == "x86_64" { format!("::std::arch::is_x86_feature_detected!({f:?})") } else { format!("::std::arch::is_aarch64_feature_detected!({f:?})") })
            .collect::<Vec<_>>()
            .join(" && ");
        if set.kat_fault.is_some() {
            // a simulated CPU (test hook, R21): detection reports the set
            detect = "true".into();
        }
        let kat = kat_fn(krate, set, arch, i + 1);
        if kat.is_some() {
            detect = format!("{detect} && unsafe {{ kat_{}() }}", set.name);
        }
        let _ = writeln!(out, "{}#[cfg({cfg})]", ind(i + 1));
        let _ = writeln!(out, "{}static {st}: ::core::sync::atomic::AtomicU8 = ::core::sync::atomic::AtomicU8::new(0u8);", ind(i + 1));
        let _ = writeln!(out, "{}#[cfg({cfg})]", ind(i + 1));
        let _ = writeln!(out, "{}#[inline]", ind(i + 1));
        let _ = writeln!(out, "{}pub(crate) fn {}() -> bool {{", ind(i + 1), has_fn(set));
        let _ = writeln!(out, "{}match {st}.load(::core::sync::atomic::Ordering::Relaxed) {{", ind(i + 2));
        let _ = writeln!(out, "{}1u8 => false,", ind(i + 3));
        let _ = writeln!(out, "{}2u8 => true,", ind(i + 3));
        let _ = writeln!(out, "{}_ => {{", ind(i + 3));
        let _ = writeln!(out, "{}let yes: bool = {detect};", ind(i + 4));
        let _ = writeln!(out, "{}{st}.store(if yes {{ 2u8 }} else {{ 1u8 }}, ::core::sync::atomic::Ordering::Relaxed);", ind(i + 4));
        let _ = writeln!(out, "{}yes", ind(i + 4));
        let _ = writeln!(out, "{}}}", ind(i + 3));
        let _ = writeln!(out, "{}}}", ind(i + 2));
        let _ = writeln!(out, "{}}}", ind(i + 1));
        if let Some(k) = kat {
            out.push_str(&k);
        }
    }
    let _ = writeln!(out, "{}}}", ind(i));
    out
}

/// A boundary dispatcher (trusted glue, DESIGN.md §9.3): the variant of the
/// first set whose features are enabled — statically (`cfg`) or detected at
/// run time — else the portable function.
fn dispatcher_text(p: &Printer<'_>, d: &crate::opt::Dispatcher, i: usize) -> String {
    let krate = p.krate;
    let f = krate.fn_def(d.portable).expect("dispatcher of a function");
    let mut out = String::new();
    let _ = writeln!(out, "{}#[doc = \" Boundary dispatcher (trusted glue, DESIGN.md §9.3): runs a kernel-proven hardware variant\"]", ind(i));
    let _ = writeln!(out, "{}#[doc = \" when its target features are enabled, the portable function otherwise.\"]", ind(i));
    let _ = writeln!(out, "{}#[allow(unsafe_code, unreachable_code)]", ind(i));
    let _ = writeln!(out, "{}#[inline]", ind(i));
    let gens = if f.lifetimes.is_empty() { String::new() } else { format!("<{}>", f.lifetimes.join(", ")) };
    let params: Vec<String> = f.params.iter().enumerate().map(|(k, pa)| format!("{}: {}", p.genn.arg(k), p.decl_ty(&pa.ty, &pa.lts))).collect();
    let args: Vec<String> = (0..f.params.len()).map(|k| p.genn.arg(k)).collect();
    let args = args.join(", ");
    let ret = if f.ret.is_unit() { String::new() } else { format!(" -> {}", p.decl_ty(&f.ret, &f.ret_lts)) };
    let _ = writeln!(out, "{}pub fn {}{gens}({}){ret} {{", ind(i), clean_ident(&d.name), params.join(", "));
    for (set, target) in &d.variants {
        let arch = set_arch(set);
        let path = p.item_path(*target);
        let _ = writeln!(out, "{}#[cfg({})]", ind(i + 1), set_static_cfg(set, arch, false));
        let _ = writeln!(out, "{}{{", ind(i + 1));
        let _ = writeln!(out, "{}// SAFETY: the features of `{{{}}}` are statically enabled for this target, so every CPU the binary", ind(i + 2), set.name);
        let _ = writeln!(out, "{}// runs on implements them; the variant is kernel-proven equal to the portable function.", ind(i + 2));
        let _ = writeln!(out, "{}return unsafe {{ {path}({args}) }};", ind(i + 2));
        let _ = writeln!(out, "{}}}", ind(i + 1));
        let _ = writeln!(out, "{}#[cfg({})]", ind(i + 1), set_static_cfg(set, arch, true));
        let _ = writeln!(out, "{}{{", ind(i + 1));
        let _ = writeln!(out, "{}if crate::__sandblaster::__dispatch::{}() {{", ind(i + 2), has_fn(set));
        let _ = writeln!(out, "{}// SAFETY: the CPU implements the features of `{{{}}}` (detected at run time).", ind(i + 3), set.name);
        let _ = writeln!(out, "{}return unsafe {{ {path}({args}) }};", ind(i + 3));
        let _ = writeln!(out, "{}}}", ind(i + 2));
        let _ = writeln!(out, "{}}}", ind(i + 1));
    }
    let _ = writeln!(out, "{}{}({args})", ind(i + 1), p.item_path(d.portable));
    let _ = writeln!(out, "{}}}", ind(i));
    out
}

/// The text of one dispatcher as printed in the optimized output of
/// `krate` with the source's re-exports `reexports` and the dispatchers
/// `dispatchers` (its argument names are generated names, [`GenNames`]; the
/// round trip compares printed dispatchers against it).
pub fn dispatcher_item_text(krate: &Crate, sm: &SourceMap, d: &crate::opt::Dispatcher, reexports: &[ReExport], dispatchers: &[crate::opt::Dispatcher]) -> String {
    let p = Printer::with_context(krate, sm, reexports, dispatchers);
    dispatcher_text(&p, d, 0)
}

struct TailCtx {
    fid: ItemId,
    args: Vec<String>,
}

struct Printer<'a> {
    krate: &'a Crate,
    sm: &'a SourceMap,
    exported: HashSet<ItemId>,
    exported_mods: HashSet<ModId>,
    /// The source's re-exports outside the boundary ([`source_reexports`]).
    reexports: &'a [ReExport],
    /// The generated-name allocator (every module-level and prelude name
    /// reserved, *Generated names*).
    genn: GenNames,
    helpers: BTreeSet<HelperId>,
    /// The checked-arithmetic helpers the printed code calls (E0).
    chk: BTreeSet<ChkHelper>,
    names: Vec<String>,
    /// Locals of the function (or constant) being printed.
    locals: Vec<LocalDecl>,
    /// Suppresses `mut` on bindings (inner patterns of `let_or`).
    no_mut: std::cell::Cell<bool>,
    fresh: u32,
    tail: Option<TailCtx>,
    ret: Ty,
    /// `Some(note)` when printing a verified build (see
    /// [`print_crate_verified`]).
    verified: Option<String>,
    /// Phase-3 printing (see [`print_crate_optimized`]).
    opt: Option<OptPrint<'a>>,
    /// The item being printed (for `SAFETY:` comments).
    cur_item: Option<ItemId>,
    /// Printing a `const` initializer (indexing stays checked: rustc
    /// evaluates it at compile time).
    in_const: bool,
    /// `SAFETY:` obligations already named in the current function, per
    /// (span, kind): several unchecked operations can share a span (the
    /// nodes of a residual, the arms of an expanded or-pattern), and each
    /// names the next obligation in elaboration order.
    safety_used: std::cell::RefCell<std::collections::HashMap<(crate::span::Span, &'static str), usize>>,
    /// Printing a doc comment's expression (a `# Safety` precondition with
    /// no source text): ghost types by their specification names (`Int`),
    /// not the erased `()`.
    doc_text: std::cell::Cell<bool>,
}

fn ind(n: usize) -> String {
    "    ".repeat(n)
}

fn clean_ident(s: &str) -> &str {
    s.strip_prefix("r#").unwrap_or(s)
}

/// `crate::__sandblaster::<module path>`: the canonical path of module `m`.
fn abs_mod_path(krate: &Crate, m: ModId) -> String {
    let mut s = "crate::__sandblaster".to_string();
    for seg in &krate.module(m).path.0 {
        s.push_str("::");
        s.push_str(clean_ident(seg));
    }
    s
}

/// The canonical path of item `id` (its defining module and name).
fn abs_item_path(krate: &Crate, id: ItemId) -> String {
    let it = krate.item(id);
    format!("{}::{}", abs_mod_path(krate, it.module), clean_ident(&it.name))
}

/// Modules exported by the DSL root (`pub mod` chains from boundary
/// module exports), without the modules exported only through re-exports
/// of other modules ([`exported_modules_with`]).
pub fn exported_modules(krate: &Crate) -> HashSet<ModId> {
    exported_modules_with(krate, &[])
}

/// Modules exported by the DSL root: the boundary's module exports, their
/// `pub mod`s and the modules they re-export (`reexports`), transitively.
/// These are printed `pub`.
pub fn exported_modules_with(krate: &Crate, reexports: &[ReExport]) -> HashSet<ModId> {
    let mut exported_mods = HashSet::new();
    let mut work: Vec<ModId> = krate.boundary.iter().filter_map(|e| match e.target {
        ExportTarget::Module(m) => Some(m),
        _ => None,
    }).collect();
    while let Some(m) = work.pop() {
        if exported_mods.insert(m) {
            for c in &krate.module(m).submodules {
                if krate.module(*c).vis == Vis::Public {
                    work.push(*c);
                }
            }
            for r in reexports.iter().filter(|r| r.module == m) {
                if let ReExportTarget::Module(c) = r.target {
                    work.push(c);
                }
            }
        }
    }
    exported_mods
}

/// Items printed `pub` (reachable through public paths from the DSL root,
/// §2): the boundary of the generated crate.
pub fn exported_items(krate: &Crate) -> HashSet<ItemId> {
    exported_items_in(krate, &exported_modules(krate))
}

/// [`exported_items`], with the modules exported through re-exports
/// ([`exported_modules_with`]).
pub fn exported_items_with(krate: &Crate, reexports: &[ReExport]) -> HashSet<ItemId> {
    exported_items_in(krate, &exported_modules_with(krate, reexports))
}

fn exported_items_in(krate: &Crate, exported_mods: &HashSet<ModId>) -> HashSet<ItemId> {
    let mut exported: HashSet<ItemId> = krate.reachable.iter().copied().filter(|i| krate.item(*i).vis == Vis::Public).collect();
    for e in &krate.boundary {
        if let ExportTarget::Item(i) = e.target {
            exported.insert(i);
        }
    }
    for it in &krate.items {
        if exported_mods.contains(&it.module) && it.vis == Vis::Public {
            exported.insert(it.id);
        }
    }
    exported
}

impl<'a> Printer<'a> {
    /// A printer for fixed templates and types (no generated names).
    fn new(krate: &'a Crate, sm: &'a SourceMap) -> Printer<'a> {
        Printer::with_context(krate, sm, &[], &[])
    }

    /// A printer of the crate `krate` with the source's re-exports and the
    /// boundary dispatchers it prints (both reserve their names for
    /// [`GenNames`]).
    fn with_context(krate: &'a Crate, sm: &'a SourceMap, reexports: &'a [ReExport], dispatchers: &[crate::opt::Dispatcher]) -> Printer<'a> {
        let exported_mods = exported_modules_with(krate, reexports);
        let exported = exported_items_in(krate, &exported_mods);
        let genn = GenNames::new(krate, reexports, dispatchers);
        Printer { krate, sm, exported, exported_mods, reexports, genn, helpers: BTreeSet::new(), chk: BTreeSet::new(), names: vec![], locals: vec![], no_mut: std::cell::Cell::new(false), fresh: 0, tail: None, ret: Ty::unit(), verified: None, opt: None, cur_item: None, in_const: false, safety_used: Default::default(), doc_text: std::cell::Cell::new(false) }
    }

    fn run(&mut self, root_display: &str) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "// @generated by sandblaster from `{root_display}`. Do not edit.");
        let verdict = self.opt.as_ref().is_some_and(|o| o.verdict.is_some());
        match &self.verified {
            None => {
                let _ = writeln!(out, "// STATUS: {UNVERIFIED}: proofs, obligations and the optimizer have NOT run.");
                let _ = writeln!(out, "// This code was only type checked and validated against the sandblaster subset.");
            }
            Some(note) if verdict => {
                let _ = writeln!(out, "// STATUS: {OPTIMIZED}: every definition was elaborated to core and checked by the");
                let _ = writeln!(out, "// sandblaster kernel with every obligation and law proven, and every §15 gate passed (DESIGN.md");
                let _ = writeln!(out, "// §15.8: boundary, examples, sections, law rules, SPEC.lock, spec mutation); the optimizer's results");
                let _ = writeln!(out, "// are kernel-checked equal to them, and this file was read back and compared with the optimized");
                let _ = writeln!(out, "// core (round trip). See sandblaster-report.json.");
                for l in note.lines() {
                    let _ = writeln!(out, "// {l}");
                }
            }
            Some(note) => {
                let _ = writeln!(out, "// STATUS: {STAGE}");
                let exec_only = self.opt.as_ref().is_some_and(|o| o.exec_only);
                if exec_only {
                    let _ = writeln!(out, "// Test-only exec-only elaboration: the exec code was kernel-checked with every obligation proven,");
                    let _ = writeln!(out, "// but spec functions, lemmas and laws were NOT elaborated.");
                } else {
                    let _ = writeln!(out, "// Toolchain stage output: the definitions were kernel-checked with every obligation proven, but");
                    let _ = writeln!(out, "// the crate gates (DESIGN.md §15.8) did not run. No consumer of crate output accepts this file.");
                }
                if self.opt.is_some() {
                    let _ = writeln!(out, "// The optimizer's results are kernel-checked and this file passed the round trip.");
                }
                for l in note.lines() {
                    let _ = writeln!(out, "// {l}");
                }
            }
        }
        let _ = writeln!(out, "{GUARD_ITEM}");
        let _ = writeln!(out, "{MOD_ATTRS}");
        let _ = writeln!(out, "mod __sandblaster {{");
        let body = self.module_body(self.krate.root, 1);
        out.push_str(&body);
        if !self.helpers.is_empty() {
            out.push_str(&self.helper_module(1));
        }
        if let Some(o) = &self.opt
            && !o.dispatchers.is_empty()
        {
            out.push_str(&dispatch_module(self.krate, o.sets, 1));
        }
        let _ = writeln!(out, "}}");
        if !self.chk.is_empty() {
            out.push_str(&rt_module(&self.chk));
        }
        for e in &self.krate.boundary {
            let path = match e.target {
                ExportTarget::Item(i) if self.dispatcher_of(i).is_some() => {
                    let d = self.dispatcher_of(i).unwrap();
                    let mut v: Vec<String> = self.krate.module(d.module).path.0.iter().map(|s| clean_ident(s).to_string()).collect();
                    v.push(clean_ident(&d.name).to_string());
                    v.join("::")
                }
                ExportTarget::Item(i) => self.item_rel_path(i),
                ExportTarget::Module(m) => self.krate.module(m).path.0.join("::"),
            };
            let _ = writeln!(out, "pub use __sandblaster::{path} as {};", clean_ident(&e.name));
        }
        for r in self.reexports.iter().filter(|r| r.module == self.krate.root) {
            if let Some(s) = reexport_text(self.krate, self.dispatchers(), &self.exported_mods, r, 0) {
                out.push_str(&s);
            }
        }
        if let Some(o) = &self.opt {
            out.push_str(&spec_root_item(&o.spec_root));
        }
        out
    }

    /// The boundary dispatchers of phase-3 printing (none otherwise).
    fn dispatchers(&self) -> &[crate::opt::Dispatcher] {
        self.opt.as_ref().map(|o| o.dispatchers).unwrap_or(&[])
    }

    // ------------------------------------------------------------------
    // paths and types
    // ------------------------------------------------------------------

    /// Path of an item relative to `__sandblaster` (defining module).
    fn item_rel_path(&self, id: ItemId) -> String {
        let it = self.krate.item(id);
        let mut v: Vec<String> = self.krate.module(it.module).path.0.clone();
        v.push(it.name.clone());
        v.iter().map(|s| clean_ident(s).to_string()).collect::<Vec<_>>().join("::")
    }

    fn item_path(&self, id: ItemId) -> String {
        abs_item_path(self.krate, id)
    }

    fn adt_lifetimes(&self, id: ItemId) -> usize {
        match &self.krate.item(id).kind {
            ItemKind::Struct(s) => s.lifetimes.len(),
            ItemKind::Enum(e) => e.lifetimes.len(),
            _ => 0,
        }
    }

    /// A type in body position (no lifetimes).
    fn ty(&self, t: &Ty) -> String {
        self.ty_lt(t, &mut None)
    }

    /// A type in declaration position, consuming recorded lifetimes.
    fn decl_ty(&self, t: &Ty, lts: &Lifetimes) -> String {
        let mut it = Some(lts.0.iter());
        self.ty_lt(t, &mut it)
    }

    fn ty_lt(&self, t: &Ty, lts: &mut Option<std::slice::Iter<'_, String>>) -> String {
        match t {
            Ty::Bool => "bool".into(),
            Ty::Uint(u) => u.name().into(),
            Ty::I32 => "i32".into(),
            Ty::Tuple(ts) if ts.len() == 1 => format!("({},)", self.ty_lt(&ts[0], lts)),
            Ty::Tuple(ts) => format!("({})", ts.iter().map(|t| self.ty_lt(t, lts)).collect::<Vec<_>>().join(", ")),
            Ty::Array(e, n) => format!("[{}; {n}usize]", self.ty_lt(e, lts)),
            Ty::Slice(e) => format!("[{}]", self.ty_lt(e, lts)),
            Ty::Ref(e) => {
                let lt = lts.as_mut().and_then(|i| i.next()).cloned().unwrap_or_default();
                let inner = self.ty_lt(e, lts);
                if lt.is_empty() { format!("&{inner}") } else { format!("&{lt} {inner}") }
            }
            Ty::Option(e) => format!("::core::option::Option<{}>", self.ty_lt(e, lts)),
            Ty::Adt(id, args) => {
                let n = self.adt_lifetimes(*id);
                let mut parts: Vec<String> = Vec::new();
                if lts.is_some() && n > 0 {
                    for _ in 0..n {
                        let lt = lts.as_mut().and_then(|i| i.next()).cloned().unwrap_or_default();
                        parts.push(if lt.is_empty() { "'_".into() } else { lt });
                    }
                }
                for a in args {
                    parts.push(self.ty_lt(a, lts));
                }
                if parts.is_empty() { self.item_path(*id) } else { format!("{}<{}>", self.item_path(*id), parts.join(", ")) }
            }
            Ty::Param(_, n) => n.clone(),
            Ty::Vector(v) => v.path(),
            Ty::Int if self.doc_text.get() => "Int".into(),
            Ty::Nat if self.doc_text.get() => "Nat".into(),
            Ty::Int | Ty::Nat | Ty::Seq(_) | Ty::Fn(..) | Ty::Prop | Ty::Proof | Ty::Never | Ty::Error => "()".into(),
        }
    }

    fn lit_suffix(t: &Ty) -> &'static str {
        match t {
            Ty::Uint(u) => u.name(),
            Ty::I32 => "i32",
            _ => "",
        }
    }

    // ------------------------------------------------------------------
    // items
    // ------------------------------------------------------------------

    fn vis(&self, v: Vis, exported: bool) -> &'static str {
        match v {
            Vis::Public if exported => "pub ",
            Vis::Public | Vis::Crate => "pub(crate) ",
            Vis::Super => "pub(super) ",
            Vis::Private => "",
        }
    }

    fn dispatcher_of(&self, item: ItemId) -> Option<&crate::opt::Dispatcher> {
        self.opt.as_ref()?.dispatchers.iter().find(|d| d.portable == item)
    }

    /// Whether proven bounds checks print as `get_unchecked` forms.
    fn unchecked(&self) -> bool {
        self.opt.is_some()
    }

    /// The `SAFETY:` comment of an unchecked operation at `span` (the
    /// obligation of `kind` discharged in the current item's definition).
    fn safety(&self, span: crate::span::Span, kind: &'static str, what: &str) -> String {
        self.safety_n(span, kind, what, false)
    }

    /// The `SAFETY:` comment of an unchecked operation justified by the
    /// obligations of `kind` at `span` in the current function's kernel
    /// definition (or its loop helpers): the next unused one, or all of
    /// them (`all`: a statement with several, e.g. the three range facts of
    /// `copy_from_slice`).
    fn safety_n(&self, span: crate::span::Span, kind: &'static str, what: &str, all: bool) -> String {
        let loc = if span.is_dummy() { String::new() } else { format!(" at {}:{}:{}", self.sm.path(span.file).file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default(), span.lo.0, span.lo.1 + 1) };
        let def = self.cur_item.and_then(|i| self.opt.as_ref()?.kernel_def.get(&i).cloned()).unwrap_or_default();
        let mut cands: Vec<(String, u32)> = self
            .opt
            .as_ref()
            .and_then(|o| o.obligations.get(&span))
            .map(|v| v.iter().filter(|(d, k, _)| *k == kind && (*d == def || d.starts_with(&format!("{def}::loop#")))).map(|(d, _, id)| (d.clone(), *id)).collect())
            .unwrap_or_default();
        cands.sort_by_key(|c| c.1);
        let picked: Vec<(String, u32)> = if all {
            cands
        } else {
            let mut used = self.safety_used.borrow_mut();
            let n = used.entry((span, kind)).or_insert(0);
            let c = cands.get(*n).or(cands.last()).cloned();
            *n += 1;
            c.into_iter().collect()
        };
        let ids = match picked.as_slice() {
            [] => String::new(),
            [(d, id)] => format!(" #{id} of `{d}`"),
            many => format!("s {} of `{}`", many.iter().map(|(_, id)| format!("#{id}")).collect::<Vec<_>>().join(", "), many[0].0),
        };
        format!("/* SAFETY: {what}: {kind} obligation{ids}{loc}, proven and kernel-checked */")
    }

    fn docs(out: &mut String, docs: &[String], i: usize) {
        for d in docs {
            let _ = writeln!(out, "{}#[doc = {:?}]", ind(i), d);
        }
    }

    fn cfg(out: &mut String, cfg: &Option<String>, i: usize) {
        if let Some(c) = cfg {
            let _ = writeln!(out, "{}#[cfg({c})]", ind(i));
        }
    }

    fn module_body(&mut self, m: ModId, i: usize) -> String {
        let mut out = String::new();
        let module = self.krate.module(m).clone();
        // the module's re-exports (the root's are printed at the top level)
        if m != self.krate.root {
            for r in self.reexports.iter().filter(|r| r.module == m) {
                if let Some(s) = reexport_text(self.krate, self.dispatchers(), &self.exported_mods, r, i) {
                    out.push_str(&s);
                }
            }
        }
        let mut done_impls: HashSet<u32> = HashSet::new();
        for &id in &module.items {
            let it = self.krate.item(id);
            if it.ghost {
                continue;
            }
            match &it.kind {
                ItemKind::Fn(f) if f.impl_block.is_some() => {
                    let b = f.impl_block.unwrap();
                    if done_impls.insert(b) {
                        let fns: Vec<ItemId> = module.items.iter().copied().filter(|x| {
                            let xi = self.krate.item(*x);
                            !xi.ghost && matches!(&xi.kind, ItemKind::Fn(g) if g.impl_block == Some(b))
                        }).collect();
                        out.push_str(&self.impl_block(&fns, i));
                    }
                }
                _ => out.push_str(&self.item(id, i)),
            }
        }
        if let Some(o) = &self.opt {
            for d in o.dispatchers.iter().filter(|d| d.module == m) {
                out.push_str(&dispatcher_text(self, d, i));
            }
        }
        for &c in &module.submodules {
            let cm = self.krate.module(c).clone();
            if cm.ghost {
                continue;
            }
            Self::docs(&mut out, &cm.docs, i);
            Self::cfg(&mut out, &cm.cfg, i);
            let v = if self.exported_mods.contains(&c) { "pub " } else { "pub(crate) " };
            let _ = writeln!(out, "{}{v}mod {} {{", ind(i), clean_ident(&cm.name));
            let body = self.module_body(c, i + 1);
            out.push_str(&body);
            let _ = writeln!(out, "{}}}", ind(i));
        }
        out
    }

    fn item(&mut self, id: ItemId, i: usize) -> String {
        let it = self.krate.item(id).clone();
        let mut out = String::new();
        Self::docs(&mut out, &it.docs, i);
        Self::cfg(&mut out, &it.cfg, i);
        for a in &it.allow {
            let _ = writeln!(out, "{}#[allow({a})]", ind(i));
        }
        let exported = self.exported.contains(&id);
        let v = self.vis(it.vis, exported);
        let name = clean_ident(&it.name).to_string();
        match &it.kind {
            ItemKind::TypeAlias(a) => {
                let _ = writeln!(out, "{}{v}type {name} = {};", ind(i), self.decl_ty(&a.ty, &a.lts));
            }
            ItemKind::Const(c) => {
                self.names = c.locals.iter().enumerate().map(|(k, l)| self.local_name(k, &l.name)).collect();
                self.locals = c.locals.clone();
                self.in_const = true;
                let init = self.expr(&c.init, i);
                self.in_const = false;
                let _ = writeln!(out, "{}{v}const {name}: {} = {init};", ind(i), self.decl_ty(&c.ty, &c.ty_lts));
            }
            ItemKind::Struct(s) => {
                self.derives(&mut out, &s.derives, i);
                let gens = self.adt_generics(&s.lifetimes, &s.generics);
                match s.shape {
                    Shape::Unit => {
                        let _ = writeln!(out, "{}{v}struct {name}{gens};", ind(i));
                    }
                    Shape::Tuple => {
                        let fs: Vec<String> = s.fields.iter().map(|f| format!("{}{}", self.vis(f.vis, exported), self.decl_ty(&f.ty, &f.lts))).collect();
                        let _ = writeln!(out, "{}{v}struct {name}{gens}({});", ind(i), fs.join(", "));
                    }
                    Shape::Named => {
                        let _ = writeln!(out, "{}{v}struct {name}{gens} {{", ind(i));
                        for f in &s.fields {
                            Self::docs(&mut out, &f.docs, i + 1);
                            let _ = writeln!(out, "{}{}{}: {},", ind(i + 1), self.vis(f.vis, exported), clean_ident(f.name.as_deref().unwrap_or("_")), self.decl_ty(&f.ty, &f.lts));
                        }
                        let _ = writeln!(out, "{}}}", ind(i));
                    }
                }
            }
            ItemKind::Enum(e) => {
                self.derives(&mut out, &e.derives, i);
                let gens = self.adt_generics(&e.lifetimes, &e.generics);
                let _ = writeln!(out, "{}{v}enum {name}{gens} {{", ind(i));
                for var in &e.variants {
                    Self::docs(&mut out, &var.docs, i + 1);
                    let vn = clean_ident(&var.name);
                    match var.shape {
                        Shape::Unit => {
                            let _ = writeln!(out, "{}{vn},", ind(i + 1));
                        }
                        Shape::Tuple => {
                            let fs: Vec<String> = var.fields.iter().map(|f| self.decl_ty(&f.ty, &f.lts)).collect();
                            let _ = writeln!(out, "{}{vn}({}),", ind(i + 1), fs.join(", "));
                        }
                        Shape::Named => {
                            let fs: Vec<String> = var.fields.iter().map(|f| format!("{}: {}", clean_ident(f.name.as_deref().unwrap_or("_")), self.decl_ty(&f.ty, &f.lts))).collect();
                            let _ = writeln!(out, "{}{vn} {{ {} }},", ind(i + 1), fs.join(", "));
                        }
                    }
                }
                let _ = writeln!(out, "{}}}", ind(i));
            }
            ItemKind::Fn(f) => {
                if f.kind == FnKind::Exec {
                    out.push_str(&self.function(id, f, v, i));
                }
            }
        }
        out
    }

    fn derives(&self, out: &mut String, d: &Derives, i: usize) {
        let mut v = Vec::new();
        if d.clone {
            v.push("::core::clone::Clone");
        }
        if d.copy {
            v.push("::core::marker::Copy");
        }
        if d.partial_eq {
            v.push("::core::cmp::PartialEq");
        }
        if d.eq {
            v.push("::core::cmp::Eq");
        }
        if d.debug {
            v.push("::core::fmt::Debug");
        }
        if !v.is_empty() {
            let _ = writeln!(out, "{}#[derive({})]", ind(i), v.join(", "));
        }
    }

    fn adt_generics(&self, lts: &[String], gens: &[TyParam]) -> String {
        let mut parts: Vec<String> = lts.to_vec();
        parts.extend(gens.iter().map(|g| format!("{}: ::core::marker::Copy", g.name)));
        if parts.is_empty() { String::new() } else { format!("<{}>", parts.join(", ")) }
    }

    fn impl_block(&mut self, fns: &[ItemId], i: usize) -> String {
        let mut out = String::new();
        let Some(first) = fns.first() else { return out };
        let f0 = self.krate.fn_def(*first).unwrap().clone();
        let Some(owner) = f0.owner else { return out };
        let n_impl = match &self.krate.item(owner).kind {
            ItemKind::Struct(s) => s.generics.len(),
            ItemKind::Enum(e) => e.generics.len(),
            _ => 0,
        };
        let mut gparts: Vec<String> = f0.impl_lifetimes.clone();
        gparts.extend(f0.generics.iter().take(n_impl).map(|g| format!("{}: ::core::marker::Copy", g.name)));
        let gens = if gparts.is_empty() { String::new() } else { format!("<{}>", gparts.join(", ")) };
        let mut targs: Vec<String> = f0.impl_self_lts.clone();
        targs.extend(f0.generics.iter().take(n_impl).map(|g| g.name.clone()));
        let self_ty = if targs.is_empty() { self.item_path(owner) } else { format!("{}<{}>", self.item_path(owner), targs.join(", ")) };
        Self::cfg(&mut out, &self.krate.item(*first).cfg, i);
        let _ = writeln!(out, "{}impl{gens} {self_ty} {{", ind(i));
        for &f in fns {
            let it = self.krate.item(f).clone();
            let def = self.krate.fn_def(f).unwrap().clone();
            if def.kind != FnKind::Exec {
                continue;
            }
            let mut s = String::new();
            Self::docs(&mut s, &it.docs, i + 1);
            for a in &it.allow {
                let _ = writeln!(s, "{}#[allow({a})]", ind(i + 1));
            }
            let exported = self.exported.contains(&f);
            let v = self.vis(it.vis, exported);
            s.push_str(&self.function_with_skip(f, &def, v, i + 1, n_impl));
            out.push_str(&s);
        }
        let _ = writeln!(out, "{}}}", ind(i));
        out
    }

    /// The printed name of local `id` ([`GenNames::local`]).
    fn local_name(&self, id: usize, orig: &str) -> String {
        self.genn.local(id, orig)
    }

    /// The next temporary of the current function ([`GenNames::temp`]).
    fn fresh(&mut self, what: &str) -> String {
        self.fresh += 1;
        self.genn.temp(self.fresh, what)
    }

    fn function(&mut self, id: ItemId, f: &FnDef, v: &str, i: usize) -> String {
        self.function_with_skip(id, f, v, i, 0)
    }

    /// Prints a function; `skip` impl generics are declared on the impl.
    fn function_with_skip(&mut self, id: ItemId, f: &FnDef, v: &str, i: usize, skip: usize) -> String {
        let mut out = String::new();
        self.names = f.locals.iter().enumerate().map(|(k, l)| self.local_name(k, &l.name)).collect();
        self.locals = f.locals.clone();
        self.fresh = 0;
        self.ret = f.ret.clone();
        let unsafe_fn = f.has_requires();
        if unsafe_fn {
            let _ = writeln!(out, "{}#[doc = \"\"]", ind(i));
            let _ = writeln!(out, "{}#[doc = \" # Safety\"]", ind(i));
            let _ = writeln!(out, "{}#[doc = \"\"]", ind(i));
            if self.verified.is_some() {
                let _ = writeln!(out, "{}#[doc = \" The caller must establish the precondition (proven at every sandblaster call site):\"]", ind(i));
            } else {
                let _ = writeln!(out, "{}#[doc = \" The caller must establish the precondition ({UNVERIFIED}: not machine-checked):\"]", ind(i));
            }
            for r in &f.requires {
                // (a synthesized precondition has no source text: printed)
                // (a precondition with its static arguments substituted, a
                // loop helper's, has no source text either)
                let text = match self.sm.snippet(r.span) {
                    Some(t) => t,
                    None => {
                        self.doc_text.set(true);
                        let t = self.expr(r, 0);
                        self.doc_text.set(false);
                        t
                    }
                };
                let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
                let _ = writeln!(out, "{}#[doc = {:?}]", ind(i), format!(" `{text}`"));
            }
        }
        let calls_unsafe = self.calls_requires_fn(f);
        self.cur_item = Some(id);
        self.safety_used.borrow_mut().clear();
        let unchecked_ops = self.unchecked() && has_unchecked_ops(f);
        if unsafe_fn || calls_unsafe || unchecked_ops {
            let _ = writeln!(out, "{}#[allow(unsafe_code)]", ind(i));
        }
        match f.inline {
            // rustc rejects `#[inline(always)]` on a `#[target_feature]`
            // function (rust-lang/rust#145574): a multiversioned clone and
            // the helpers built for it print the plain hint
            Some(Inline::Always) if f.target_features.is_empty() => {
                let _ = writeln!(out, "{}#[inline(always)]", ind(i));
            }
            Some(Inline::Always) => {
                let _ = writeln!(out, "{}#[inline]", ind(i));
            }
            Some(Inline::Hint) => {
                let _ = writeln!(out, "{}#[inline]", ind(i));
            }
            None => {}
        }
        if f.must_use {
            let _ = writeln!(out, "{}#[must_use]", ind(i));
        }
        if !f.target_features.is_empty() {
            let _ = writeln!(out, "{}#[target_feature(enable = {:?})]", ind(i), f.target_features.join(","));
        }
        let mut gparts: Vec<String> = f.lifetimes.clone();
        gparts.extend(f.generics.iter().skip(skip).map(|g| format!("{}: ::core::marker::Copy", g.name)));
        let gens = if gparts.is_empty() { String::new() } else { format!("<{}>", gparts.join(", ")) };
        let name = clean_ident(&self.krate.item(id).name).to_string();
        let tail_loop = f.recursion == Recursion::Tail && f.receiver.is_none() && self.tail_args_ok(id, f);
        let mut params = Vec::new();
        let mut arg_names = Vec::new();
        for (k, p) in f.params.iter().enumerate() {
            if k == 0 && f.receiver.is_some() {
                params.push(match f.receiver {
                    Some(Receiver::ByRef) => "&self".to_string(),
                    _ => "self".to_string(),
                });
                continue;
            }
            // a `#[ghost]` parameter is an `Irr` binder: not printed
            // (DESIGN.md §15.3)
            if p.ghost {
                continue;
            }
            let ty = self.decl_ty(&p.ty, &p.lts);
            if tail_loop {
                let a = self.genn.arg(k);
                params.push(format!("mut {a}: {ty}"));
                arg_names.push(a);
            } else {
                params.push(format!("{}: {ty}", self.pat(&p.pat)));
            }
        }
        let ret = if f.ret.is_unit() { String::new() } else { format!(" -> {}", self.decl_ty(&f.ret, &f.ret_lts)) };
        let uns = if unsafe_fn { "unsafe " } else { "" };
        let _ = writeln!(out, "{}{v}{uns}fn {name}{gens}({}){ret} {{", ind(i), params.join(", "));
        let FnBody::Exec(body) = &f.body else { return String::new() };
        if tail_loop && self.opt.is_some() {
            // phase 3: `loop { <rebind parameters>; return <body>; }`, every
            // self-call in the body a `{ …; continue; }` block (§8.3)
            let _ = writeln!(out, "{}loop {{", ind(i + 1));
            for (k, p) in f.params.iter().enumerate() {
                let _ = writeln!(out, "{}let {}: {} = {};", ind(i + 2), self.pat(&p.pat), self.ty(&p.ty), arg_names[k]);
            }
            self.tail = Some(TailCtx { fid: id, args: arg_names });
            let b = self.expr_raw(body, i + 2);
            self.tail = None;
            let _ = writeln!(out, "{}return {b};", ind(i + 2));
            let _ = writeln!(out, "{}}}", ind(i + 1));
        } else if tail_loop {
            let _ = writeln!(out, "{}loop {{", ind(i + 1));
            for (k, p) in f.params.iter().enumerate() {
                let _ = writeln!(out, "{}let {}: {} = {};", ind(i + 2), self.pat(&p.pat), self.ty(&p.ty), arg_names[k]);
            }
            self.tail = Some(TailCtx { fid: id, args: arg_names });
            let t = self.tail_expr(body, i + 2);
            self.tail = None;
            let _ = writeln!(out, "{}{t}", ind(i + 2));
            let _ = writeln!(out, "{}}}", ind(i + 1));
        } else {
            match &body.kind {
                ExprKind::Block(b) => out.push_str(&self.block_inner(b, i + 1)),
                _ => {
                    let e = self.expr(body, i + 1);
                    let _ = writeln!(out, "{}{e}", ind(i + 1));
                }
            }
        }
        let _ = writeln!(out, "{}}}", ind(i));
        out
    }

    /// Whether every self-call passes the function's own type parameters.
    fn tail_args_ok(&self, id: ItemId, f: &FnDef) -> bool {
        struct V {
            id: ItemId,
            own: Vec<Ty>,
            ok: bool,
        }
        impl crate::visit::Visitor for V {
            fn expr(&mut self, e: &Expr) {
                if let ExprKind::Call { callee: Callee::Item(c, targs), .. } = &e.kind
                    && *c == self.id && *targs != self.own {
                        self.ok = false;
                    }
                crate::visit::walk_expr(self, e);
            }
        }
        let own: Vec<Ty> = f.generics.iter().enumerate().map(|(i, g)| Ty::Param(i as u32, g.name.clone())).collect();
        let mut v = V { id, own, ok: true };
        crate::visit::walk_fn(&mut v, f);
        v.ok
    }

    fn calls_requires_fn(&self, f: &FnDef) -> bool {
        struct V<'k> {
            krate: &'k Crate,
            found: bool,
        }
        impl crate::visit::Visitor for V<'_> {
            fn expr(&mut self, e: &Expr) {
                if let ExprKind::Call { callee: Callee::Item(c, _), .. } = &e.kind
                    && self.krate.fn_def(*c).is_some_and(|d| d.kind == FnKind::Exec && d.has_requires()) {
                        self.found = true;
                    }
                crate::visit::walk_expr(self, e);
            }
        }
        let mut v = V { krate: self.krate, found: false };
        if let FnBody::Exec(b) = &f.body {
            crate::visit::Visitor::expr(&mut v, b);
        }
        v.found
    }

    fn helper_module(&self, i: usize) -> String {
        let mut out = String::new();
        let arch = intrinsics::helper(*self.helpers.iter().next().unwrap()).arch.clone();
        let _ = writeln!(out, "{}#[cfg(target_arch = {:?})]", ind(i), arch.name());
        let _ = writeln!(out, "{}pub(crate) mod __arch {{", ind(i));
        let _ = writeln!(out, "{}// Trusted glue (DESIGN.md §9.2): safe unaligned load/store helpers.", ind(i + 1));
        for h in &self.helpers {
            out.push_str(&helper_fn_text(self.krate, *h, i + 1));
        }
        let _ = writeln!(out, "{}}}", ind(i));
        out
    }

    // ------------------------------------------------------------------
    // patterns
    // ------------------------------------------------------------------

    fn pat(&self, p: &Pat) -> String {
        match &p.kind {
            PatKind::Wild => "_".into(),
            PatKind::Binding { local, mode, sub } => {
                let l = &self.names[local.0 as usize];
                let decl_mut = self.cur_local_mut(*local);
                let mut s = String::new();
                if *mode == BindingMode::ByRef {
                    s.push_str("ref ");
                } else if decl_mut {
                    s.push_str("mut ");
                }
                s.push_str(l);
                if let Some(sub) = sub {
                    s.push_str(" @ ");
                    s.push_str(&self.pat(sub));
                }
                s
            }
            PatKind::Lit(Lit::Bool(b)) => b.to_string(),
            PatKind::Lit(Lit::Int(v)) => format!("{v}{}", Self::lit_suffix(&p.ty)),
            PatKind::Range { lo, hi } => {
                let s = Self::lit_suffix(&p.ty);
                format!("{lo}{s}..={hi}{s}")
            }
            PatKind::Tuple(ps) if ps.len() == 1 => format!("({},)", self.pat(&ps[0])),
            PatKind::Tuple(ps) => format!("({})", ps.iter().map(|x| self.pat(x)).collect::<Vec<_>>().join(", ")),
            PatKind::Ctor { ctor, fields, .. } => {
                let (path, shape, names): (String, Shape, Vec<Option<String>>) = match ctor {
                    Ctor::Struct(id) => match &self.krate.item(*id).kind {
                        ItemKind::Struct(s) => (self.item_path(*id), s.shape, s.fields.iter().map(|f| f.name.clone()).collect()),
                        _ => (String::new(), Shape::Unit, vec![]),
                    },
                    Ctor::Variant(id, i) => match &self.krate.item(*id).kind {
                        ItemKind::Enum(e) => {
                            let v = &e.variants[*i as usize];
                            (format!("{}::{}", self.item_path(*id), clean_ident(&v.name)), v.shape, v.fields.iter().map(|f| f.name.clone()).collect())
                        }
                        _ => (String::new(), Shape::Unit, vec![]),
                    },
                    Ctor::Some => ("::core::option::Option::Some".into(), Shape::Tuple, vec![None]),
                    Ctor::None => ("::core::option::Option::None".into(), Shape::Unit, vec![]),
                };
                match shape {
                    Shape::Unit => path,
                    Shape::Tuple => {
                        let mut ps: Vec<String> = vec!["_".into(); names.len()];
                        for (i, fp) in fields {
                            if let Some(slot) = ps.get_mut(*i as usize) {
                                *slot = self.pat(fp);
                            }
                        }
                        format!("{path}({})", ps.join(", "))
                    }
                    Shape::Named => {
                        let mut ps: Vec<String> = fields.iter().map(|(i, fp)| format!("{}: {}", clean_ident(names[*i as usize].as_deref().unwrap_or("_")), self.pat(fp))).collect();
                        if fields.len() < names.len() {
                            ps.push("..".into());
                        }
                        format!("{path} {{ {} }}", ps.join(", "))
                    }
                }
            }
            PatKind::Deref { pat, .. } => format!("&{}", self.pat_atom(pat)),
            PatKind::Slice { prefix, rest, suffix } => {
                let mut parts: Vec<String> = prefix.iter().map(|x| self.pat(x)).collect();
                match rest {
                    None => {}
                    Some(None) => parts.push("..".into()),
                    Some(Some(r)) => parts.push(format!("{} @ ..", self.pat(r))),
                }
                parts.extend(suffix.iter().map(|x| self.pat(x)));
                format!("[{}]", parts.join(", "))
            }
            PatKind::Or(alts) => format!("({})", alts.iter().map(|x| self.pat(x)).collect::<Vec<_>>().join(" | ")),
        }
    }

    /// Patterns under `&` that would bind ambiguously get parentheses.
    fn pat_atom(&self, p: &Pat) -> String {
        let s = self.pat(p);
        match &p.kind {
            PatKind::Binding { .. } | PatKind::Range { .. } => format!("({s})"),
            _ => s,
        }
    }

    fn cur_local_mut(&self, l: LocalId) -> bool {
        !self.no_mut.get() && self.locals.get(l.0 as usize).is_some_and(|d| d.mutable)
    }

    fn cur_local_ty(&self, l: LocalId) -> Ty {
        self.locals.get(l.0 as usize).map(|d| d.ty.clone()).unwrap_or(Ty::Error)
    }

    // ------------------------------------------------------------------
    // expressions
    // ------------------------------------------------------------------

    fn is_atomic(e: &Expr) -> bool {
        matches!(
            e.kind,
            ExprKind::Lit(_) | ExprKind::Local(_) | ExprKind::Const(_) | ExprKind::BuiltinConst(_) | ExprKind::Adt { .. } | ExprKind::Tuple(_) | ExprKind::Array(_) | ExprKind::Repeat { .. } | ExprKind::Field { .. } | ExprKind::Index { .. } | ExprKind::Unreachable
        ) || matches!(&e.kind, ExprKind::Call { .. }) && !Self::is_unsafe_call_static(e)
    }

    fn is_unsafe_call_static(_e: &Expr) -> bool {
        // conservatively parenthesize every call that may print as an
        // `unsafe { .. }` block; decided at print time
        false
    }

    /// Whether `e` prints as an atomic operand (a checked operation printed
    /// as a helper call is one).
    fn atomic(&self, e: &Expr) -> bool {
        Self::is_atomic(e) || self.chk_of(e).is_some()
    }

    /// The checked-arithmetic helper the operation `e` prints as (E0,
    /// [`ChkHelper`]): in phase 3, outside `const` initializers, an `add`,
    /// `sub`, `mul`, `shl` or `shr` of unsigned integers — a checked
    /// primitive of the core, every occurrence of which carries a
    /// kernel-checked proof slot in the optimized core.
    fn chk_of(&self, e: &Expr) -> Option<ChkHelper> {
        match &e.kind {
            ExprKind::Binary(op, a, b) => self.chk_bin(*op, &a.ty, &b.ty),
            _ => None,
        }
    }

    /// [`Printer::chk_of`] for `a op b` with `a: lt`, `b: rt`.
    fn chk_bin(&self, op: BinOp, lt: &Ty, rt: &Ty) -> Option<ChkHelper> {
        if self.opt.is_none() || self.in_const {
            return None;
        }
        let (Ty::Uint(w), Ty::Uint(w2)) = (lt, rt) else { return None };
        let h = ChkHelper::of(op, *w)?;
        (h.is_shift() || w2 == w).then_some(h)
    }

    /// The second argument of a helper call: `b`, or a shift amount of
    /// another width than `u32` converted (`b as u32`: the core primitive's
    /// amount, exact for narrower amounts and, for wider ones, equal to `b`
    /// by the proven `b < bits`).
    fn chk_rhs(&mut self, h: ChkHelper, b: &Expr, i: usize) -> String {
        if h.is_shift() && b.ty != Ty::u32() { format!("{} as u32", self.expr(b, i)) } else { self.expr_raw(b, i) }
    }

    /// Operand-safe printing.
    fn expr(&mut self, e: &Expr, i: usize) -> String {
        let raw = self.expr_raw(e, i);
        if self.atomic(e) && !raw.starts_with("unsafe") { raw } else { format!("({raw})") }
    }

    fn args(&mut self, args: &[Expr], i: usize) -> String {
        args.iter().map(|a| self.expr_raw_arg(a, i)).collect::<Vec<_>>().join(", ")
    }

    fn expr_raw_arg(&mut self, e: &Expr, i: usize) -> String {
        self.expr_raw(e, i)
    }

    fn expr_raw(&mut self, e: &Expr, i: usize) -> String {
        match &e.kind {
            ExprKind::Lit(Lit::Bool(b)) => b.to_string(),
            ExprKind::Lit(Lit::Int(v)) => format!("{v}{}", Self::lit_suffix(&e.ty)),
            ExprKind::Local(l) => self.names[l.0 as usize].clone(),
            ExprKind::Const(id) => self.item_path(*id),
            ExprKind::BuiltinConst(c) => match c {
                BuiltinConst::Max(w) => format!("{}::MAX", w.name()),
                BuiltinConst::Min(w) => format!("{}::MIN", w.name()),
                BuiltinConst::Bits(w) => format!("{}::BITS", w.name()),
                BuiltinConst::IsizeMax => "()".into(),
            },
            ExprKind::Call { callee, args } => self.call(callee, args, &e.ty, i),
            ExprKind::Adt { ctor, ty_args, fields, base } => self.adt(*ctor, ty_args, fields, base.as_deref(), i),
            ExprKind::Tuple(es) if es.len() == 1 => format!("({},)", self.expr(&es[0], i)),
            ExprKind::Tuple(es) => format!("({})", self.args(es, i)),
            ExprKind::Array(es) => format!("[{}]", self.args(es, i)),
            ExprKind::Repeat { elem, count } => format!("[{}; {count}usize]", self.expr(elem, i)),
            ExprKind::Field { base, index, name } => {
                let b = self.expr(base, i);
                match name {
                    Some(n) => format!("{b}.{}", clean_ident(n)),
                    None => format!("{b}.{index}"),
                }
            }
            ExprKind::Index { base, index } if self.unchecked() && !self.in_const && matches!(base.ty, Ty::Array(..) | Ty::Slice(_)) => {
                let (et, x) = self.unchecked_base(base, i);
                let idx = self.expr_raw(index, i);
                format!("unsafe {{ {} *<[{et}]>::get_unchecked({x}, {idx}) }}", self.safety(e.span, "index-bounds", "the index is in bounds"))
            }
            ExprKind::SliceRange { base, lo, hi } if self.unchecked() && !self.in_const && matches!(base.ty, Ty::Array(..) | Ty::Slice(_)) => {
                let (et, x) = self.unchecked_base(base, i);
                let lo = lo.as_ref().map(|x| self.expr(x, i)).unwrap_or_default();
                let hi = hi.as_ref().map(|x| self.expr(x, i)).unwrap_or_default();
                format!("unsafe {{ {} <[{et}]>::get_unchecked({x}, {lo}..{hi}) }}", self.safety(e.span, "slice-range", "the range is in bounds"))
            }
            ExprKind::Index { base, index } => format!("{}[{}]", self.expr(base, i), self.expr_raw(index, i)),
            ExprKind::SliceRange { base, lo, hi } => {
                let lo = lo.as_ref().map(|x| self.expr(x, i)).unwrap_or_default();
                let hi = hi.as_ref().map(|x| self.expr(x, i)).unwrap_or_default();
                format!("&{}[{lo}..{hi}]", self.expr(base, i))
            }
            ExprKind::Unary(UnOp::Not, x) => format!("!{}", self.expr(x, i)),
            ExprKind::Unary(UnOp::Neg, x) => format!("-{}", self.expr(x, i)),
            ExprKind::Binary(op, a, b) => match self.chk_bin(*op, &a.ty, &b.ty) {
                Some(h) => {
                    // E0: `crate::__rt::chk::<op>_<w>(a, b)`, operands in order
                    self.chk.insert(h);
                    let x = self.expr_raw(a, i);
                    let y = self.chk_rhs(h, b, i);
                    format!("{CHK_PATH}::{}({x}, {y})", h.name())
                }
                None => format!("{} {} {}", self.expr(a, i), op.symbol(), self.expr(b, i)),
            },
            ExprKind::Cast(x, t) => format!("{} as {}", self.expr(x, i), self.ty(t)),
            ExprKind::Ref(x) | ExprKind::Coerce(Coercion::AutoRef, x) => format!("&{}", self.expr(x, i)),
            ExprKind::Deref(x) | ExprKind::Coerce(Coercion::AutoDeref, x) => format!("*{}", self.expr(x, i)),
            ExprKind::Coerce(Coercion::Unsize, x) => format!("{} as {}", self.expr(x, i), self.ty(&e.ty)),
            ExprKind::Coerce(Coercion::BoolToProp, x) => self.expr_raw(x, i),
            ExprKind::If { cond, then, els } => {
                let c = self.expr_raw(cond, i);
                let t = self.as_block(then, i);
                match els {
                    None => format!("if {c} {t}"),
                    Some(x) => {
                        let el = match &x.kind {
                            ExprKind::If { .. } => self.expr_raw(x, i),
                            _ => self.as_block(x, i),
                        };
                        format!("if {c} {t} else {el}")
                    }
                }
            }
            ExprKind::Match { scrut, arms, .. } => self.match_(scrut, arms, &e.ty, i, false),
            ExprKind::Block(b) => format!("{{\n{}{}}}", self.block_inner(b, i + 1), ind(i)),
            // every `return` is a tail position: in a loop-converted
            // function a returned self-call becomes rebinding + `continue`
            ExprKind::Return(Some(x)) if self.tail.is_some() && self.opt.is_none() => self.tail_expr(x, i),
            ExprKind::Return(x) => match x {
                Some(x) => format!("return {}", self.expr(x, i)),
                None => "return".into(),
            },
            // the canonical dialect of phase 3 keeps `?` (on `Option`, in a
            // function returning `Option`: rustc's desugaring is exactly the
            // elaboration's, SEMANTICS.md §6)
            ExprKind::Try(x) if self.opt.is_some() => format!("({})?", self.expr_raw(x, i)),
            ExprKind::Try(x) => {
                let t = self.fresh("v");
                let inner = self.expr_raw(x, i);
                let none = format!("::core::option::Option::<{}>::None", match &self.ret {
                    Ty::Option(u) => self.ty(u),
                    _ => "_".into(),
                });
                format!("match {inner} {{ ::core::option::Option::Some({t}) => {t}, ::core::option::Option::None => return {none} }}")
            }
            ExprKind::Unreachable => "::core::unreachable!()".into(),
            ExprKind::Loop(l) => self.loop_(l, i),
            // ghost-only forms never reach exec code
            _ => "()".into(),
        }
    }

    fn as_block(&mut self, e: &Expr, i: usize) -> String {
        match &e.kind {
            ExprKind::Block(b) => format!("{{\n{}{}}}", self.block_inner(b, i + 1), ind(i)),
            _ => format!("{{ {} }}", self.expr_raw(e, i)),
        }
    }

    fn call(&mut self, callee: &Callee, args: &[Expr], _ty: &Ty, i: usize) -> String {
        if let Callee::Item(c, _) = callee
            && self.opt.is_some()
            && self.tail.as_ref().is_some_and(|t| t.fid == *c)
        {
            // a self-call of a tail loop: evaluate the arguments, rebind,
            // next iteration
            let names = self.tail.as_ref().unwrap().args.clone();
            // each temporary is allocated before its value is printed: fresh
            // names follow the text (a value may hold a checked compound
            // assignment's temporary), as the round trip reads them back
            let mut temps: Vec<String> = Vec::new();
            let mut vals: Vec<String> = Vec::new();
            for a in args {
                temps.push(self.fresh("next"));
                vals.push(self.expr_raw(a, i + 1));
            }
            let mut s = String::from("{ ");
            for (t, v) in temps.iter().zip(&vals) {
                let _ = write!(s, "let {t} = {v}; ");
            }
            for (n, t) in names.iter().zip(&temps) {
                let _ = write!(s, "{n} = {t}; ");
            }
            s.push_str("continue; }");
            return s;
        }
        match callee {
            Callee::Item(id, targs) => {
                let f = self.krate.fn_def(*id).cloned();
                // the arguments of `#[ghost]` parameters are not printed
                // (DESIGN.md §15.3)
                let printed: Vec<Expr> = match &f {
                    Some(fd) if fd.params.iter().any(|p| p.ghost) && args.len() == fd.params.len() => args.iter().zip(&fd.params).filter(|(_, p)| !p.ghost).map(|(a, _)| a.clone()).collect(),
                    _ => args.to_vec(),
                };
                let a = self.args(&printed, i);
                let path = match f.as_ref().and_then(|f| f.owner) {
                    Some(owner) => {
                        let n_impl = match &self.krate.item(owner).kind {
                            ItemKind::Struct(s) => s.generics.len(),
                            ItemKind::Enum(e) => e.generics.len(),
                            _ => 0,
                        };
                        let owner_ty = self.ty(&Ty::Adt(owner, targs.iter().take(n_impl).cloned().collect()));
                        let own: Vec<String> = targs.iter().skip(n_impl).map(|t| self.ty(t)).collect();
                        let turbo = if own.is_empty() { String::new() } else { format!("::<{}>", own.join(", ")) };
                        format!("<{owner_ty}>::{}{turbo}", clean_ident(&self.krate.item(*id).name))
                    }
                    None => {
                        let turbo = if targs.is_empty() { String::new() } else { format!("::<{}>", targs.iter().map(|t| self.ty(t)).collect::<Vec<_>>().join(", ")) };
                        format!("{}{turbo}", self.item_path(*id))
                    }
                };
                let call = format!("{path}({a})");
                if f.as_ref().is_some_and(|f| f.has_requires()) {
                    let name = self.krate.item(*id).path.to_string();
                    if self.verified.is_some() {
                        format!("unsafe {{ /* SAFETY: obligation CalleeRequires({name}) — discharged, kernel-checked */ {call} }}")
                    } else {
                        format!("unsafe {{ /* SAFETY: obligation CalleeRequires({name}) — {UNVERIFIED}: not discharged */ {call} }}")
                    }
                } else {
                    call
                }
            }
            Callee::Builtin(b, targs) => {
                let pt = |t: &Ty| self.ty(t);
                let path = b.path(targs, &pt).unwrap_or_else(|| "()".into());
                // `as_slice` receives `&[T; N]`
                let _ = matches!(b, Builtin::Array(ArrayMethod::AsSlice(_)));
                format!("{path}({})", self.args(args, i))
            }
            Callee::Intrinsic(id, imms) => {
                let info = intrinsics::get(*id);
                let turbo = if imms.is_empty() { String::new() } else { format!("::<{}>", imms.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(", ")) };
                format!("{}{turbo}({})", info.path(), self.args(args, i))
            }
            Callee::Helper(h) => {
                self.helpers.insert(*h);
                format!("crate::__sandblaster::__arch::{}({})", intrinsics::helper(*h).name, self.args(args, i))
            }
            Callee::Ghost(..) => "()".into(),
        }
    }

    fn adt(&mut self, ctor: Ctor, ty_args: &[Ty], fields: &[(u32, Expr)], base: Option<&Expr>, i: usize) -> String {
        let targs = if ty_args.is_empty() { String::new() } else { format!("::<{}>", ty_args.iter().map(|t| self.ty(t)).collect::<Vec<_>>().join(", ")) };
        match ctor {
            Ctor::Some => format!("::core::option::Option{targs}::Some({})", fields.first().map(|f| self.expr_raw(&f.1, i)).unwrap_or_default()),
            Ctor::None => format!("::core::option::Option{targs}::None"),
            Ctor::Struct(id) | Ctor::Variant(id, _) => {
                let (path, shape, names) = match (ctor, &self.krate.item(id).kind) {
                    (Ctor::Struct(_), ItemKind::Struct(s)) => (format!("{}{targs}", self.item_path(id)), s.shape, s.fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>()),
                    (Ctor::Variant(_, vi), ItemKind::Enum(e)) => {
                        let v = &e.variants[vi as usize];
                        (format!("{}{targs}::{}", self.item_path(id), clean_ident(&v.name)), v.shape, v.fields.iter().map(|f| f.name.clone()).collect())
                    }
                    _ => ("()".into(), Shape::Unit, vec![]),
                };
                match shape {
                    Shape::Unit => path,
                    Shape::Tuple => {
                        let mut sorted: Vec<&(u32, Expr)> = fields.iter().collect();
                        sorted.sort_by_key(|f| f.0);
                        let a: Vec<String> = sorted.iter().map(|f| self.expr_raw(&f.1, i)).collect();
                        format!("{path}({})", a.join(", "))
                    }
                    Shape::Named => {
                        let mut parts: Vec<String> = fields.iter().map(|(k, e)| format!("{}: {}", clean_ident(names[*k as usize].as_deref().unwrap_or("_")), self.expr_raw(e, i))).collect();
                        if let Some(b) = base {
                            parts.push(format!("..{}", self.expr(b, i)));
                        }
                        format!("{path} {{ {} }}", parts.join(", "))
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // match: or-pattern expansion, guard desugaring
    // ------------------------------------------------------------------

    fn place_like(e: &Expr) -> bool {
        match &e.kind {
            ExprKind::Local(_) => true,
            ExprKind::Field { base, .. } | ExprKind::Deref(base) | ExprKind::Coerce(Coercion::AutoDeref, base) => Self::place_like(base),
            _ => false,
        }
    }

    fn match_(&mut self, scrut: &Expr, arms: &[Arm], _ty: &Ty, i: usize, tail: bool) -> String {
        let arms = expand_or_arms(arms);
        let has_guard = arms.iter().any(|a| a.guard.is_some());
        if self.opt.is_some() {
            // phase 3: guards stay guards — after or-pattern expansion every
            // arm has one pattern, and rustc's `p if g => e` (try `g` once `p`
            // matched, else the next arms) is exactly the elaboration's rule
            // (SEMANTICS.md §7)
            let s = self.expr_raw(scrut, i);
            let mut out = format!("match {s} {{\n");
            for a in &arms {
                let pat = self.pat(&a.pat);
                let body = self.arm_body(&a.body, i + 1, tail);
                match &a.guard {
                    None => {
                        let _ = writeln!(out, "{}{pat} => {body},", ind(i + 1));
                    }
                    Some(g) => {
                        let gs = self.expr_raw(g, i + 1);
                        let _ = writeln!(out, "{}{pat} if {gs} => {body},", ind(i + 1));
                    }
                }
            }
            let _ = write!(out, "{}}}", ind(i));
            return out;
        }
        if !has_guard {
            let s = self.expr_raw(scrut, i);
            return self.match_arms(&s, &scrut.ty, &arms, i, tail);
        }
        if Self::place_like(scrut) || matches!(scrut.ty, Ty::Slice(_)) {
            let s = self.expr_raw(scrut, i);
            return self.chain(&s, &scrut.ty, &arms, i, tail);
        }
        let t = self.fresh("scrut");
        let s = self.expr_raw(scrut, i);
        let c = self.chain(&t, &scrut.ty, &arms, i + 1, tail);
        format!("{{\n{}let {t}: {} = {s};\n{}{c}\n{}}}", ind(i + 1), self.ty(&scrut.ty), ind(i + 1), ind(i))
    }

    /// Guard desugaring: `p if g => e` followed by arms R becomes
    /// `p => if g { e } else { match s { R } }`, then R.
    fn chain(&mut self, s: &str, sty: &Ty, arms: &[Arm], i: usize, tail: bool) -> String {
        let mut out = format!("match {s} {{\n");
        for (k, a) in arms.iter().enumerate() {
            let pat = self.pat(&a.pat);
            let body = self.arm_body(&a.body, i + 1, tail);
            match &a.guard {
                None => {
                    let _ = writeln!(out, "{}{pat} => {body},", ind(i + 1));
                }
                Some(g) => {
                    let gs = self.expr_raw(g, i + 1);
                    let rest = self.chain(s, sty, &arms[k + 1..], i + 2, tail);
                    let _ = writeln!(out, "{}{pat} => if {gs} {{ {body} }} else {{\n{}{rest}\n{}}},", ind(i + 1), ind(i + 2), ind(i + 1));
                }
            }
        }
        if !self.exhaustive(sty, arms) {
            let _ = writeln!(out, "{}_ => ::core::unreachable!(),", ind(i + 1));
        }
        let _ = write!(out, "{}}}", ind(i));
        out
    }

    fn match_arms(&mut self, s: &str, sty: &Ty, arms: &[Arm], i: usize, tail: bool) -> String {
        let mut out = format!("match {s} {{\n");
        for a in arms {
            let pat = self.pat(&a.pat);
            let body = self.arm_body(&a.body, i + 1, tail);
            let _ = writeln!(out, "{}{pat} => {body},", ind(i + 1));
        }
        if arms.is_empty() || !self.exhaustive(sty, arms) {
            let _ = writeln!(out, "{}_ => ::core::unreachable!(),", ind(i + 1));
        }
        let _ = write!(out, "{}}}", ind(i));
        out
    }

    fn exhaustive(&self, ty: &Ty, arms: &[Arm]) -> bool {
        let pats: Vec<&Pat> = arms.iter().filter(|a| a.guard.is_none()).map(|a| &a.pat).collect();
        let lookup = |id: ItemId| self.krate.items.get(id.0 as usize).map(|i| i.kind.clone());
        let names = |id: ItemId| self.krate.item(id).name.clone();
        crate::exhaust::missing(ty, &pats, &lookup, &names).is_none()
    }

    fn arm_body(&mut self, e: &Expr, i: usize, tail: bool) -> String {
        if tail {
            return self.tail_expr(e, i);
        }
        match &e.kind {
            ExprKind::Block(_) => self.expr_raw(e, i),
            _ => self.expr(e, i),
        }
    }

    // ------------------------------------------------------------------
    // tail-recursion loops
    // ------------------------------------------------------------------

    /// Prints `e` in tail position of a loop-converted function: a
    /// diverging expression (`return v`, or rebinding + `continue`).
    fn tail_expr(&mut self, e: &Expr, i: usize) -> String {
        let fid = self.tail.as_ref().map(|t| t.fid);
        match &e.kind {
            ExprKind::Call { callee: Callee::Item(c, _), args } if Some(*c) == fid => {
                let names = self.tail.as_ref().unwrap().args.clone();
                let vals: Vec<String> = args.iter().map(|a| self.expr_raw(a, i + 1)).collect();
                let mut s = String::from("{ ");
                // evaluate all arguments before rebinding
                let temps: Vec<String> = (0..vals.len()).map(|_| self.fresh("next")).collect();
                for (t, v) in temps.iter().zip(&vals) {
                    let _ = write!(s, "let {t} = {v}; ");
                }
                for (n, t) in names.iter().zip(&temps) {
                    let _ = write!(s, "{n} = {t}; ");
                }
                s.push_str("continue; }");
                s
            }
            ExprKind::Block(b) => {
                let mut s = String::from("{\n");
                for st in &b.stmts {
                    s.push_str(&self.stmt(st, i + 1));
                }
                match &b.tail {
                    Some(t) => {
                        let tt = self.tail_expr(t, i + 1);
                        let _ = writeln!(s, "{}{tt}", ind(i + 1));
                    }
                    None => {
                        let diverges = b.stmts.last().is_some_and(|st| matches!(&st.kind, StmtKind::Expr(x) if x.ty.is_never()));
                        if !diverges {
                            let _ = writeln!(s, "{}return;", ind(i + 1));
                        }
                    }
                }
                let _ = write!(s, "{}}}", ind(i));
                s
            }
            ExprKind::If { cond, then, els } => {
                let c = self.expr_raw(cond, i);
                let t = self.tail_expr(then, i);
                let el = match els {
                    Some(x) => self.tail_expr(x, i),
                    None => "{ return; }".into(),
                };
                format!("if {c} {t} else {el}")
            }
            ExprKind::Match { scrut, arms, .. } => self.match_(scrut, arms, &e.ty, i, true),
            ExprKind::Return(Some(x)) => self.tail_expr(x, i),
            ExprKind::Return(None) => "{ return; }".into(),
            _ if e.ty.is_never() => format!("{{ {} }}", self.expr_raw(e, i)),
            _ => format!("{{ return {}; }}", self.expr_raw(e, i)),
        }
    }

    // ------------------------------------------------------------------
    // statements and loops
    // ------------------------------------------------------------------

    fn block_inner(&mut self, b: &Block, i: usize) -> String {
        let mut s = String::new();
        for st in &b.stmts {
            s.push_str(&self.stmt(st, i));
        }
        if let Some(t) = &b.tail {
            let e = self.stmt_expr(t, i);
            let _ = writeln!(s, "{}{e}", ind(i));
        }
        s
    }

    /// An expression in statement position (no outer parentheses for
    /// block-like expressions).
    fn stmt_expr(&mut self, e: &Expr, i: usize) -> String {
        match &e.kind {
            ExprKind::If { .. } | ExprKind::Match { .. } | ExprKind::Block(_) | ExprKind::Loop(_) => self.expr_raw(e, i),
            ExprKind::Return(_) => self.expr_raw(e, i),
            _ => {
                let r = self.expr_raw(e, i);
                if r.starts_with("unsafe") || self.atomic(e) { r } else { format!("({r})") }
            }
        }
    }

    fn stmt(&mut self, s: &Stmt, i: usize) -> String {
        match &s.kind {
            StmtKind::Let { pat, init, els } => {
                if pat.has_or() && self.opt.is_none() {
                    return self.let_or(pat, init, els.as_ref(), i);
                }
                let p = self.pat(pat);
                let v = self.expr_raw(init, i);
                match els {
                    None => format!("{}let {p}: {} = {v};\n", ind(i), self.ty(&pat.ty)),
                    Some(b) => format!("{}let {p}: {} = {v} else {{\n{}{}}};\n", ind(i), self.ty(&pat.ty), self.block_inner(b, i + 1), ind(i)),
                }
            }
            StmtKind::Expr(e) => format!("{}{};\n", ind(i), self.stmt_expr(e, i)),
            // (the elaborator proves a store's bounds at the statement)
            StmtKind::Assign { place, value } if self.unchecked() && place_has_index(place) => {
                let v = self.expr_raw(value, i);
                let pl = self.place_unchecked(place, i);
                format!("{}unsafe {{ {} {pl} = {v}; }}\n", ind(i), self.safety_n(s.span, "index-bounds", "every index of the place is in bounds", place.projs.iter().filter(|p| matches!(p, Proj::Index(_))).count() > 1))
            }
            // E0: `P = { let tN__v: T = v; crate::__rt::chk::<op>_<w>(P, tN__v) };`
            // — the value first, then the place's value, as rustc evaluates
            // `P op= v` on integers and as the elaboration does
            StmtKind::CompoundAssign { op, place, value } if self.chk_bin(*op, &place.ty, &value.ty).is_some() => {
                let h = self.chk_bin(*op, &place.ty, &value.ty).unwrap();
                self.chk.insert(h);
                let t = self.fresh("v");
                let v = self.expr_raw(value, i);
                let vt = self.ty(&value.ty);
                let arg = if h.is_shift() && value.ty != Ty::u32() { format!("{t} as u32") } else { t.clone() };
                if self.unchecked() && place_has_index(place) {
                    let pl = self.place_unchecked(place, i);
                    format!("{}unsafe {{ {} {pl} = {{ let {t}: {vt} = {v}; {CHK_PATH}::{}({pl}, {arg}) }}; }}\n", ind(i), self.safety_n(s.span, "index-bounds", "every index of the place is in bounds (read and write)", true), h.name())
                } else {
                    let pl = self.place(place, i);
                    format!("{}{pl} = {{ let {t}: {vt} = {v}; {CHK_PATH}::{}({pl}, {arg}) }};\n", ind(i), h.name())
                }
            }
            StmtKind::CompoundAssign { op, place, value } if self.unchecked() && place_has_index(place) => {
                let v = self.expr_raw(value, i);
                let pl = self.place_unchecked(place, i);
                format!("{}unsafe {{ {} {pl} {}= {v}; }}\n", ind(i), self.safety_n(s.span, "index-bounds", "every index of the place is in bounds (read and write)", true), op.symbol())
            }
            StmtKind::Assign { place, value } => format!("{}{} = {};\n", ind(i), self.place(place, i), self.expr_raw(value, i)),
            StmtKind::CompoundAssign { op, place, value } => format!("{}{} {}= {};\n", ind(i), self.place(place, i), op.symbol(), self.expr_raw(value, i)),
            StmtKind::CopyFromSlice { dst, range, src } => {
                let d = self.names[dst.0 as usize].clone();
                let elem = match &self.cur_local_ty(*dst) {
                    Ty::Array(t, _) => self.ty(t),
                    _ => "_".into(),
                };
                let target = match range {
                    None => format!("&mut {d}"),
                    Some((a, b)) if self.unchecked() => {
                        let a = a.as_ref().map(|x| self.expr(x, i)).unwrap_or_default();
                        let b = b.as_ref().map(|x| self.expr(x, i)).unwrap_or_default();
                        format!("unsafe {{ {} <[{elem}]>::get_unchecked_mut((&mut {d} as &mut [{elem}]), {a}..{b}) }}", self.safety_n(s.span, "slice-range", "the range is in bounds and as long as the source", true))
                    }
                    Some((a, b)) => {
                        let a = a.as_ref().map(|x| self.expr(x, i)).unwrap_or_default();
                        let b = b.as_ref().map(|x| self.expr(x, i)).unwrap_or_default();
                        format!("&mut {d}[{a}..{b}]")
                    }
                };
                format!("{}<[{elem}]>::copy_from_slice({target}, {});\n", ind(i), self.expr_raw(src, i))
            }
            StmtKind::Proof(_) => String::new(),
        }
    }

    /// `let` with an or-pattern: `let (b..) = match init { alt => (b..), .. };`
    fn let_or(&mut self, pat: &Pat, init: &Expr, els: Option<&Block>, i: usize) -> String {
        let binds = pat.bindings();
        let tuple_vals: Vec<String> = binds.iter().map(|l| self.names[l.0 as usize].clone()).collect();
        let tuple_tys: Vec<String> = binds.iter().map(|l| self.ty(&self.cur_local_ty(*l))).collect();
        let tv = if tuple_vals.len() == 1 { tuple_vals[0].clone() } else { format!("({})", tuple_vals.join(", ")) };
        let tt = if tuple_tys.len() == 1 { tuple_tys[0].clone() } else { format!("({})", tuple_tys.join(", ")) };
        let lhs = if binds.len() == 1 {
            let m = if self.cur_local_mut(binds[0]) { "mut " } else { "" };
            format!("{m}{}", tuple_vals[0])
        } else {
            format!("({})", binds.iter().map(|l| format!("{}{}", if self.cur_local_mut(*l) { "mut " } else { "" }, self.names[l.0 as usize])).collect::<Vec<_>>().join(", "))
        };
        let mut arms = String::new();
        for alt in expand_pat(pat) {
            let _ = writeln!(arms, "{}{} => {tv},", ind(i + 1), self.pat_immut(&alt));
        }
        if let Some(b) = els {
            let _ = writeln!(arms, "{}_ => {{\n{}{}}}", ind(i + 1), self.block_inner(b, i + 2), ind(i + 1));
        }
        format!("{}let {lhs}: {tt} = match {} {{\n{arms}{}}};\n", ind(i), self.expr_raw(init, i), ind(i))
    }

    /// A pattern printed without `mut` (inner bindings of `let_or`).
    fn pat_immut(&self, p: &Pat) -> String {
        self.no_mut.set(true);
        let s = self.pat(p);
        self.no_mut.set(false);
        s
    }

    fn place(&mut self, p: &Place, i: usize) -> String {
        let mut s = self.names[p.local.0 as usize].clone();
        for pr in &p.projs {
            match pr {
                Proj::Field { index, name } => match name {
                    Some(n) => {
                        let _ = write!(s, ".{}", clean_ident(n));
                    }
                    None => {
                        let _ = write!(s, ".{index}");
                    }
                },
                Proj::Index(e) => {
                    let x = self.expr_raw(e, i);
                    let _ = write!(s, "[{x}]");
                }
            }
        }
        s
    }

    /// Element type and `&[T]` operand of an unchecked index/range on
    /// `base` (a `[T; N]` or `[T]` place).
    fn unchecked_base(&mut self, base: &Expr, i: usize) -> (String, String) {
        let b = self.expr(base, i);
        match &base.ty {
            Ty::Array(t, _) => {
                let et = self.ty(t);
                (et.clone(), format!("(&{b} as &[{et}])"))
            }
            Ty::Slice(t) => (self.ty(t), format!("&{b}")),
            _ => ("_".into(), format!("&{b}")),
        }
    }

    /// A place with index projections, as unchecked mutable accesses.
    fn place_unchecked(&mut self, p: &Place, i: usize) -> String {
        let mut s = self.names[p.local.0 as usize].clone();
        let mut ty = self.cur_local_ty(p.local);
        for pr in &p.projs {
            match pr {
                Proj::Field { index, name } => {
                    match name {
                        Some(n) => {
                            let _ = write!(s, ".{}", clean_ident(n));
                        }
                        None => {
                            let _ = write!(s, ".{index}");
                        }
                    }
                    ty = self.field_ty(&ty, *index as usize);
                }
                Proj::Index(e) => {
                    let (et, next) = match &ty {
                        Ty::Array(t, _) => (self.ty(t), (**t).clone()),
                        _ => ("_".into(), Ty::Error),
                    };
                    let x = self.expr_raw(e, i);
                    s = format!("(*<[{et}]>::get_unchecked_mut((&mut {s} as &mut [{et}]), {x}))");
                    ty = next;
                }
            }
        }
        s
    }

    /// Type of field `k` of a struct or tuple type.
    fn field_ty(&self, t: &Ty, k: usize) -> Ty {
        match t {
            Ty::Tuple(ts) => ts.get(k).cloned().unwrap_or(Ty::Error),
            Ty::Adt(id, args) => match &self.krate.item(*id).kind {
                ItemKind::Struct(s) => s.fields.get(k).map(|f| f.ty.subst(args)).unwrap_or(Ty::Error),
                _ => Ty::Error,
            },
            _ => Ty::Error,
        }
    }

    fn loop_(&mut self, l: &Loop, i: usize) -> String {
        let body = format!("{{\n{}{}}}", self.block_inner(&l.body, i + 1), ind(i));
        match &l.kind {
            LoopKind::ForRange { var, lo, hi, inclusive } => {
                let v = var.map(|v| self.names[v.0 as usize].clone()).unwrap_or_else(|| "_".into());
                let op = if *inclusive { "..=" } else { ".." };
                format!("for {v} in {}{op}{} {body}", self.expr(lo, i), self.expr(hi, i))
            }
            LoopKind::While { cond } => format!("while {} {body}", self.expr_raw(cond, i)),
        }
    }
}
