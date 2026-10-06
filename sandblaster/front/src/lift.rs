//! Lifting existing Rust into the verified subset ("as-is" modules).
//!
//! A module declared `#[lift(mir = "m.sbmir")] mod m;` is ordinary Rust
//! copied verbatim from an existing crate (or the host's own file, in
//! place). The lift translates it, at load time, into the exec subset the
//! rest of the pipeline checks. The source file is never edited: the
//! translation is the toolchain's reading of the code (part of the
//! elaboration semantics, TCB; SEMANTICS.md §19, `docs/mir-lift.md` §20),
//! and every construct it does not know is an error, never a guess the
//! type checker cannot catch.
//!
//! **Function bodies are read from rustc's MIR only** ([`crate::mir`]):
//! macros, `?`, closures, operators, iterators, loops and constants in
//! bodies are what rustc lowered them to. A `#[lift]` module of exec code
//! without `mir = ".."` is refused (extract it with
//! `sandblaster/mirx/extract.sh`). This file reads the **item skeleton**
//! from the source and the **ghost language** of the lifted ghost modules
//! (laws, proofs, attachments):
//!
//! | Rust | lifted |
//! | --- | --- |
//! | `macro_rules!` + item-position invocations | expanded (`$x:ty`/`ident`/`expr`/`tt`/`literal`, `$(..)sep*`/`+`/`?`) |
//! | inline `mod m { .. }` (not `cfg(test)`) | flattened into the parent (`use super::*;` dropped) |
//! | `#[cfg(test)]` (or `all(.., test, ..)`) items; items behind a `cfg` naming a feature or `test` otherwise (`feature = ..`, `not(test)`, `any(test, ..)`) | dropped, listed (test code, or host-only code compiled outside tests: a module behind such a `cfg` is a host child module, §15.5); not part of the lifted meaning |
//! | a **sealed** trait (declared in a private inline module) with impls for concrete types | the trait disappears; each impl method becomes a free function `Trait__Ty__m(self_: Ty, ..)` |
//! | generic items whose parameters are bounded by sealed traits | one monomorphic instance per impl type (`write` → `write__u16`, `Decoder<U>` → `Decoder__u16`) |
//! | `&mut self`, `&mut impl Buf`, `&mut impl BufMut` parameters (and §19.10's states) | state passing: the function takes the state by value and returns it (`(state.., value)`) |
//! | `#[lift(unverified = "u128, ..")]` on the declaration | those impl types' instances are not lifted (reported) |
//! | derives `PartialOrd`, `Ord`, `Hash` | dropped (rustc-derived, not used by the lifted code) and listed; `Copy` added (the model is by value; rustc already checked moves) |
//! | impls of host traits (`Default`, `Write`, `Read`, `EncodeSize`, `From`) | inherent methods / free functions of the instance |
//! | `i16`/`i32`/`i64` in types | two's complement bits `crate::__lift::I16(u16)`..; ghost `as Int` / `as iN` through `int_of_iN` / `iN_of_int` (SEMANTICS.md §19.3) |
//! | `#[lift(host)]` on a declaration | a host model (enums): proven against, never emitted; the emitted module checks each variant against the host |
//! | `const` items, associated constants of open-trait impls | their initializer, read by the expression reading below (constants only: literals, `size_of`, constants, calls of lifted functions) |
//!
//! **Attachments.** Proof annotations never go into the lifted file. A
//! ghost `#[lift]` module (PROOF.rs) attaches them from outside:
//!
//! ```text
//! #[lift_attach(crate::varint::Decoder)]
//! fn decoder_state<U: UPrim>() { invariant(self.bits_read < U::SIZE * 8); }
//! #[lift_attach(crate::varint::write, loop_nr = 0)]
//! fn write_loop<T: UPrim>() { invariant(..); decreases(..); }
//! ```
//!
//! A function attachment may also say `opaque();`: the lifted function is
//! then opaque in proofs (DESIGN.md §5.6), so its callers are proven from
//! its `ensures` alone, like the exec functions with loops or buffers.
//!
//! The statements are moved (monomorphized like everything else) into the
//! lifted item: a struct `#[invariant]`, a function's contract, or the
//! `k`-th loop of rustc's MIR (`loop_nr = k`; the MIR reading places it on
//! the `while` or the loop helper it reads, `mir::read::LoopAttach`).
//!
//! A function's `ensures(..)` from the laws file (`LAWS.rs`, the module
//! [`LAWS_MODULE`]) are its contract; those from a proof file are
//! proof-internal summaries: all are conjoined into `#[ensures]` (proven,
//! the fact at call sites) and, when a proof file attached any,
//! `#[contract_ensures(..)]` names the laws file's part — what the lock
//! holds and §15.5 determines (DESIGN.md §15.6; `ensures_attrs`). An
//! attachment names its target by its full path (`crate::m::f`,
//! `crate::m::S::f` with `S` declared in `crate::m`, `crate::m::S`): a path
//! whose module does not hold the item is refused, naming where it is, and
//! same-named functions of two modules get separate attachments. A
//! function of an impl on a primitive is attached to by its lifted name
//! (`crate::m::u64__from__Pos`); its bare method name (`crate::m::from`)
//! still works when nothing else in the module answers to it, and is
//! refused when several impls do. Each attached `requires`, `ensures`,
//! `decreases` and `invariant` is also recorded as written
//! (`#[lift_src(..)]`, [`crate::hir::Attached`]): the spliced tokens keep
//! their own file's line and column, so `SPEC.lock`'s source text and the
//! surface's refusal of a proof file's statement on a boundary item read
//! that record, never the host file at those positions.

use std::collections::{BTreeMap, HashMap, HashSet};

use proc_macro2::{Delimiter, Group, Ident, Span as PSpan, TokenStream, TokenTree};
use quote::{format_ident, quote, ToTokens};
use syn::parse::{ParseStream, Parser};
use syn::spanned::Spanned;
use syn::visit_mut::VisitMut;

use crate::diag::{DiagKind, Diagnostic, Diagnostics};
use crate::span::{FileId, Span};

/// In-place lifting, open traits, operator impls, state parameters.
#[path = "lift_open.rs"]
pub mod open;

/// Host traits the lift knows (their meaning is the model below).
const HOST_TRAITS: &[&str] = &["Buf", "BufMut", "EncodeSize", "FixedSize", "Read", "Write", "Debug", "Default"];

/// Sealed-trait supertraits that only restate operators of the impl types.
const OPERATOR_SUPERTRAITS: &[&str] = &["Copy", "Sized", "FixedSize", "ShrAssign", "Shl", "BitOrAssign", "PartialOrd", "Debug", "From"];

/// A source module to lift.
pub struct LiftSource {
    pub module_index: usize,
    pub file: FileId,
    pub ast: syn::File,
    pub ghost: bool,
    pub name: String,
    /// `#[lift(unverified = "u128, i16")]` on the declaration: impl types of
    /// sealed traits whose instances this build does not lift (their code is
    /// not verified; each is reported). Empty: every instance is lifted.
    pub unverified: Vec<String>,
    /// The declaration's span (for the report of unverified instances).
    pub decl_span: Span,
    /// Declared `#[lift(host)]`: a model of host items the lifted code uses
    /// (for example `crate::Error`), proven against but never emitted; the
    /// emitted module checks each enum variant against the host
    /// ([`LiftFacts::host_checks`]).
    pub host: bool,
    /// Every option of the declaration ([`open::LiftOpts`]).
    pub opts: open::LiftOpts,
    /// Out-of-line child modules lifted with this one (`children = ".."`):
    /// name and loader module index.
    pub children: Vec<(String, usize)>,
    /// The module's DSL path (`crate::merkle::mmr`).
    pub module_path: String,
    /// `#[lift(mir = "..")]`: the `.sbmir` file's text ([`crate::mir`]).
    pub mir: Option<String>,
    /// The source file's path and text (the `.sbmir` names its sources by
    /// their SHA-256).
    pub path_display: String,
    pub text: String,
    /// Other files of the host crate the `.sbmir` names (callees in modules
    /// not lifted, read as library code): paths and texts, for its source
    /// check.
    pub mir_extra: Vec<(String, Vec<u8>)>,
}

/// What a lifted module is, for module-mode emission (`driver::gates`,
/// DESIGN.md §2.1 "lifted modules").
#[derive(Clone, Debug)]
pub struct LiftedInfo {
    pub name: String,
    pub file: FileId,
    pub ghost: bool,
    pub host: bool,
    pub unverified: Vec<String>,
    /// `#[lift(in_place)]`: the host's own file, verified where rustc
    /// compiles it (never emitted).
    pub in_place: bool,
    /// `#[lift(mir = ..)]`: the `.sbmir` file (absolute).
    pub mir: Option<std::path::PathBuf>,
}

/// Host facts the lift's reading assumed and what it left out, for the
/// emitted module's header and its rustc-checked tail.
#[derive(Clone, Debug, Default)]
pub struct LiftFacts {
    /// `T::SIZE` (host `FixedSize`) read as `size_of::<T>()`: `(T, n)`.
    pub sizes: std::collections::BTreeSet<(String, u64)>,
    /// Items the lift dropped (host-only code, never verified).
    pub dropped: Vec<Dropped>,
    /// One Rust item per host-model enum variant that rustc checks against
    /// the host in the emitted module: `const _: Error = Error::EndOfBuffer;`,
    /// `const _: fn(usize) -> Error = Error::InvalidVarint;`.
    pub host_checks: Vec<String>,
    /// Every lifted exec function of the emitted module and how to call
    /// the original (the lift conformance check, [`crate::conform`]).
    pub conform: Vec<ConformEntry>,
    /// Generic struct instances: lifted name → (source name, type
    /// arguments as the source writes them): `Decoder__u16` →
    /// (`Decoder`, [`u16`]).
    pub instances: BTreeMap<String, (String, Vec<String>)>,
    /// The test hook that was active while lifting (never set outside
    /// the toolchain's own tests; [`test_hook`]).
    pub test_hook: Option<test_hook::WrongRule>,
    /// Lifted functions with a `requires` attachment: at the boundary a
    /// precondition the host must meet (`(function, requires)`).
    pub host_obligations: Vec<(String, String)>,
    /// Lifted functions with a recursion depth bound (`decreases(e, max =
    /// C)`, DESIGN.md §3.7): at the boundary a stack-depth bound the host
    /// must meet (`(function, "e <= C")`).
    pub host_depth_bounds: Vec<(String, String)>,
    /// Lifted functions with a panic contract (`panics_when(p);`, DESIGN.md
    /// §16.5): on the domain the function panics exactly when `p` holds
    /// (`(function, p)`), proven by its panic theorem.
    pub panic_contracts: Vec<(String, String)>,
    /// Open traits at their verified instance (`(trait, instance)`).
    pub open_instances: Vec<(String, String)>,
    /// The host models of a crate lifted in place (`#[lift(host)]` type
    /// aliases, unit structs and open-trait impls whose methods are spec
    /// models): trusted, listed in the record (`host_checks`).
    pub host_models: Vec<String>,
    /// Declared unverified instances of open traits.
    pub unverified_instances: Vec<(String, String)>,
    /// Lifted functions the conformance check does not call directly, and
    /// why (loop helpers, `impl Trait` returns, constant functions): the
    /// check reports each one ([`crate::conform`]).
    pub conform_skipped: Vec<ConformSkip>,
    /// Functions whose bodies were read from rustc's MIR ([`crate::mir`]):
    /// `(lifted function, MIR instance, loops as (number, form))`.
    pub mir_read: Vec<(String, String, Vec<(usize, String)>)>,
    /// The compiler the MIR was extracted with (`rustc 1.98.0-nightly (..)`).
    pub mir_rustc: Option<String>,
    /// The library types rustc's MIR has for host models
    /// (`crate::mir::HostModels`): `(model's DSL path, the type's Rust path,
    /// the field a newtype is read as)`. The in-place conformance harness
    /// spells and converts host-model values with them.
    pub mir_host_types: Vec<(String, String, Option<String>)>,
    /// Every `#[lift(mir = ..)]` module's MIR as the lift loaded it (with
    /// its names): the input of the literal reading (`crate::mir::literal`)
    /// and of the per-function theorems (docs/checked-structuring.md).
    pub mir_loaded: Vec<MirModule>,
    /// The declared contract of every lifted function whose body was read
    /// from MIR (`crate::mir::stmt`): a theorem's preconditions come from
    /// here, never from the reading of the body.
    pub mir_contracts: Vec<MirContract>,
    /// The loop helpers the (untrusted) reading of the bodies built, with
    /// what their loop lemmas are stated over (`crate::mir::checked`).
    pub mir_helpers: Vec<MirHelper>,
    /// The panic lemmas a proof file attaches to a function with a panic
    /// contract (`panic_lemma(path);`): `(function, lemma)`. An untrusted
    /// hint for its panic theorem's walk (`crate::mir::checked`), which
    /// applies the lemma to the function's parameters and the hypotheses
    /// its `requires` name and walks with its `ensures` as facts; never
    /// part of a statement.
    pub panic_lemmas: Vec<(String, String)>,
    /// Per in-place lifted source file: what host code the lift leaves out
    /// can call of it besides its non-private functions (DESIGN.md §15.5;
    /// [`crate::hir::HostAccess`], read by `validate::in_place_host_fns`).
    pub host_access: Vec<(FileId, crate::hir::HostAccess)>,
}

/// A loop helper of a lifted function read from MIR: a hint for its
/// (untrusted) loop lemma, never part of a trusted statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MirHelper {
    /// The helper's kernel name (`crate::varint::read__u32__loop0`).
    pub global: String,
    /// The MIR instance of the function it was split from.
    pub key: String,
    /// The loop header's block.
    pub header: usize,
    /// The MIR locals its parameters carry, in order.
    pub params: Vec<usize>,
    /// A `while` loop: the elaborator's helper (`<f>::loop#k`), whose
    /// parameters are named by the source names; `local_names` names each
    /// MIR local of the function as the reading did.
    pub while_loop: bool,
    pub local_names: Vec<String>,
    /// A loop inside another loop's body, read as a helper that returns
    /// (`crate::mir::read::HelperInfo::returns`): the positions of the
    /// parameters it returns; its lemma is a `while` loop's.
    pub returns: Option<Vec<usize>>,
}

/// One `#[lift(mir = ..)]` module's loaded MIR.
#[derive(Clone, Debug)]
pub struct MirModule {
    /// The DSL path of the module (`crate::varint`).
    pub dsl: String,
    pub loaded: std::sync::Arc<crate::mir::Loaded>,
}

/// A lifted function whose body was read from MIR. Its declared contract
/// (the `requires(..)` clauses and depth bound of its skeleton and its
/// attachments: what a human or agent wrote and a reviewer reads) is carried
/// to the elaborator as `#[mir_contract(..)]` (`hir::FnDef::declared`), which
/// refuses the function unless its preconditions are the elaboration of
/// exactly those clauses: the theorem's preconditions (`crate::mir::stmt`)
/// are `S_f`'s.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MirContract {
    /// The lifted function's kernel name (`crate::varint::Decoder__u32::feed`).
    pub global: String,
    /// Its MIR instance.
    pub key: String,
    /// A declared panic contract (`panics_when(p);` in the laws file): the
    /// index of its no-panic clause `!(p)` among the preconditions (after
    /// every `requires`, before the depth bound). The gate then wants the
    /// panic theorem too (`crate::mir::stmt::statement_panic`).
    pub panic: Option<usize>,
}

/// How the original function takes one parameter (receiver included), for
/// the conformance harness ([`crate::conform`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParamPass {
    /// By value (`x: T`, `self`).
    Value,
    /// `&T`, `&self`.
    Ref,
    /// `&mut self`: state passing.
    MutRef,
    /// `&mut impl BufMut`: the bytes put so far.
    BufMut,
    /// `&mut impl Buf`: the bytes not yet read.
    Buf,
    /// `&mut T` of a value (an integer, `bool`, a named type, a tuple or an
    /// array; SEMANTICS.md §19.10): the state `T`.
    StateMut,
    /// `&mut Vec<T>`: the state `Seq<T>`.
    VecMut,
    /// `Option<&mut Vec<T>>`: the state `Option<Seq<T>>`.
    OptVec,
    /// `&mut E` of a byte-string iterator: the byte strings not yet yielded.
    BytesIter,
}

/// The original item a lifted function stands for, as the conformance
/// harness calls it (types are written as the source writes them, generic
/// parameters substituted; `modpath` is the inline module the item is in).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConformCallee {
    /// `name::<generics..>` (a free function).
    Free { modpath: Vec<String>, name: String, generics: Vec<String> },
    /// `Base::<generics..>::method` (an inherent method).
    Inherent { modpath: Vec<String>, base: String, generics: Vec<String>, method: String },
    /// `<self_ty as trait_path>::method` (`trait_path` as the impl writes
    /// it, resolved in `modpath`).
    Trait { modpath: Vec<String>, self_ty: String, trait_path: String, method: String },
}

/// One lifted exec function and how to call the original.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConformEntry {
    /// The lifted module.
    pub module: String,
    /// The lifted function's display path (`crate::varint::write__u16`,
    /// `crate::varint::Decoder__u16::feed`).
    pub lifted: String,
    pub callee: ConformCallee,
    /// One per original parameter, receiver first (the lifted function has
    /// the same parameters in the same order; buffers become `Seq<u8>`).
    pub params: Vec<ParamPass>,
    /// The original returns a value (the lifted function returns the
    /// states, in parameter order, then that value).
    pub has_ret: bool,
    /// The original returns `impl Trait`: an opaque value the harness
    /// cannot compare. Such a function is compared only on its panic
    /// contract's panic region, where rustc must panic before returning
    /// (in place; without a panic contract it is skipped, compared through
    /// its callers).
    pub opaque_ret: bool,
}

/// A lifted exec function with no conformance entry of its own, and why:
/// it is compared through the functions that call it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConformSkip {
    /// The lifted module.
    pub module: String,
    /// The lifted function's display path.
    pub lifted: String,
    pub why: String,
}

/// A deliberately wrong reading of rustc's MIR (`mir::read`), for the
/// toolchain's own tests of the conformance check (never set by a build: the
/// check must catch it).
#[doc(hidden)]
pub mod test_hook {
    use std::cell::Cell;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum WrongRule {
        /// A signed `Shr` read as the logical shift of the bits.
        SignedShrLogical,
        /// An index by `RangeToInclusive` (`&a[..=j]`) read as `&a[..j]`.
        InclusiveRangeAsExclusive,
        /// Historical structuring bug 1 (`docs/mir-lift.md` §6 step 5): before
        /// a variable changes in place (a field or element written), its own
        /// entry is snapshotted with the values that read it, so later reads
        /// of the variable restore its value from before the write.
        SnapshotOwnValue,
        /// Historical structuring bug 2: an enum whose matched field is
        /// written through a `&mut` (`if let Some(v) = &mut collected {
        /// v.push(..) }`) is snapshotted before the field changes and written
        /// back from that copy, losing the pushes.
        WritebackSnapshot,
        /// A structured reading that adds a precondition (`requires(true)`)
        /// to every private free function it reads: the elaborator must
        /// refuse it, the declared contract not stating it (amendment (b)).
        ExtraRequires,
        /// The first precondition of every function read from MIR replaced
        /// by `requires(true)` after its declared contract was carried: the
        /// same number of clauses (the same binder names), another clause;
        /// the elaborator must refuse it.
        ChangedRequires,
    }

    thread_local! {
        static HOOK: Cell<Option<WrongRule>> = const { Cell::new(None) };
    }

    /// Sets (or clears) the wrong rule for lifts on this thread.
    pub fn set(r: Option<WrongRule>) {
        HOOK.with(|h| h.set(r));
    }

    /// The wrong rule in effect on this thread.
    pub fn get() -> Option<WrongRule> {
        HOOK.with(|h| h.get())
    }
}

impl LiftFacts {
    /// The rustc-checked tail of an emitted lifted module (one item per
    /// line): the `SIZE` constants the lift read and the host-model enums.
    pub fn tail_items(&self) -> Vec<String> {
        let mut v: Vec<String> = self.sizes.iter().map(|(t, n)| format!("const _: () = assert!(<{t} as FixedSize>::SIZE == {n}usize);")).collect();
        v.extend(self.host_checks.iter().cloned());
        v
    }
}

/// The rustc-checked items of a host-model module (`#[lift(host)]`): every
/// item must be an enum (with unit or tuple variants), each variant checked
/// by one `const _` item that names it through the lifted code's own scope.
/// In a crate lifted in place (`in_place`: nothing is emitted, so there is
/// no tail to check against) a host module may also model host types and
/// functions: `pub type T = <exec type>;` (a host type read as that type), a
/// unit struct, and an impl of an open trait for it at its instance whose
/// methods are the models (their bodies call spec functions; the lift reads
/// the host's calls of the instance's methods as these). Each is a trusted
/// host model, returned in `models` for the record.
pub fn host_checks(file: &syn::File, fid: FileId, in_place: bool, models: &mut Vec<String>, diags: &mut Diagnostics) -> Vec<String> {
    let mut out = Vec::new();
    for it in &file.items {
        match it {
            syn::Item::Type(t) if in_place && t.generics.params.is_empty() => models.push(format!("type `{}` = `{}`", t.ident, ty_key(&t.ty))),
            syn::Item::Struct(st) if in_place && st.generics.params.is_empty() && matches!(st.fields, syn::Fields::Unit) => models.push(format!("unit struct `{}`", st.ident)),
            syn::Item::Impl(im) if in_place && im.trait_.is_some() && im.generics.params.is_empty() => {
                let tn = im.trait_.as_ref().map(|(_, p, _)| path_key(p)).unwrap_or_default();
                for ii in &im.items {
                    match ii {
                        syn::ImplItem::Fn(f) => models.push(format!("`<{} as {tn}>::{}` modeled as `{}`", ty_key(&im.self_ty), f.sig.ident, f.block.to_token_stream().to_string())),
                        syn::ImplItem::Type(ty) => models.push(format!("`<{} as {tn}>::{}` = `{}`", ty_key(&im.self_ty), ty.ident, ty_key(&ty.ty))),
                        other => diags.push(Diagnostic::error(DiagKind::Unsupported, Span::from_pm2(fid, other.span()), "lift: a host model impl holds methods and associated types only")),
                    }
                }
            }
            syn::Item::Enum(e) if e.generics.params.is_empty() => {
                let en = e.ident.to_string();
                for v in &e.variants {
                    let vn = v.ident.to_string();
                    match &v.fields {
                        syn::Fields::Unit => out.push(format!("const _: {en} = {en}::{vn};")),
                        syn::Fields::Unnamed(f) => {
                            let tys: Vec<String> = f.unnamed.iter().map(|x| x.ty.to_token_stream().to_string().replace(' ', "")).collect();
                            out.push(format!("const _: fn({}) -> {en} = {en}::{vn};", tys.join(", ")));
                        }
                        syn::Fields::Named(_) => diags.push(Diagnostic::error(DiagKind::Unsupported, Span::from_pm2(fid, v.ident.span()), format!("lift: the host model variant `{en}::{vn}` has named fields; a `#[lift(host)]` module models enums with unit or tuple variants (each is checked against the host)"))),
                    }
                }
            }
            other => diags.push(Diagnostic::error(DiagKind::Unsupported, Span::from_pm2(fid, other.span()), if in_place { "lift: a `#[lift(host)]` module holds only non-generic enums, type aliases, unit structs and their open-trait impls (host models)" } else { "lift: a `#[lift(host)]` module holds only non-generic enums (each variant is checked against the host in the emitted module)" })),
        }
    }
    out
}

/// The lifted items of a module.
pub struct LiftResult {
    pub module_index: usize,
    pub items: Vec<syn::Item>,
}

/// One item the lift left out, and why (printed as a warning: nothing is
/// dropped silently).
#[derive(Clone, Debug)]
pub struct Dropped {
    pub span: Span,
    pub what: String,
    pub why: String,
}

// ---------------------------------------------------------------------------
// entry point
// ---------------------------------------------------------------------------

/// The generic families the lift monomorphized: name → instance names.
pub type Families = HashMap<String, Vec<String>>;

pub fn lift(sources: Vec<LiftSource>, diags: &mut Diagnostics) -> (Vec<LiftResult>, Families, LiftFacts) {
    let mut cx = Ctx::default();
    let mut facts = LiftFacts::default();
    for src in sources.iter().filter(|s| s.host) {
        if src.ghost {
            diags.push(Diagnostic::error(DiagKind::Unsupported, src.decl_span, "lift: `#[lift(host)]` models host exec items; a ghost module cannot be one"));
        }
    }
    // open traits at their verified instance (crate-wide; every declaration agrees)
    let mut unverified_instances: Vec<(String, String)> = Vec::new();
    let in_place_crate = sources.iter().any(|s| s.opts.in_place);
    for src in &sources {
        for (t, p) in &src.opts.instances {
            let Ok(path) = syn::parse_str::<syn::Path>(p) else {
                diags.push(Diagnostic::error(DiagKind::Unsupported, src.decl_span, format!("lift: `instance = \"{t}: {p}\"`: `{p}` is not a path")));
                continue;
            };
            match cx.open.instances.get(t) {
                Some(q) if path_key(q) != path_key(&path) => diags.push(Diagnostic::error(DiagKind::Unsupported, src.decl_span, format!("lift: the open trait `{t}` is declared at two instances (`{}`, `{p}`); one verified instance per open trait is supported", path_key(q)))),
                Some(_) => {}
                None => {
                    cx.open.instances.insert(t.clone(), path);
                }
            }
        }
        for (t, p) in &src.opts.unverified_instances {
            if !unverified_instances.contains(&(t.clone(), p.clone())) {
                unverified_instances.push((t.clone(), p.clone()));
            }
            diags.push(Diagnostic::warning(DiagKind::Unsupported, src.decl_span, format!("lift: the instance `{p}` of the open trait `{t}` is declared unverified: the lifted items are checked at `{}` only; at `{p}` they stay unchecked host code", cx.open.instances.get(t).map(path_key).unwrap_or_else(|| "(no verified instance)".into()))));
        }
        cx.open.module_paths.insert(src.name.clone(), src.module_path.clone());
    }
    // exec code is read from rustc's MIR only (`docs/mir-lift.md` §20): a
    // lifted exec module without its extraction is refused, never read
    // from its surface syntax
    for src in sources.iter().filter(|s| !s.ghost && !s.host && s.mir.is_none()) {
        diags.push(
            Diagnostic::error(DiagKind::Unsupported, src.decl_span, format!("lift: the lifted module `{}` has no `mir = \"..\"`: function bodies are read only from rustc's MIR", src.name))
                .note("extract it with `sandblaster/mirx/extract.sh` (see `sandblaster/mirx/README.md`) and declare `#[lift(mir = \"<file>.sbmir\", ..)]`"),
        );
    }
    // the generic items whose open-trait parameters erasure drops
    {
        let instances = cx.open.instances.clone();
        let mut erased = HashMap::new();
        for src in &sources {
            open::collect_erased_params(&src.ast.items, &instances, &mut erased);
        }
        cx.open.erased_params = erased;
    }
    for src in &sources {
        for t in &src.unverified {
            if cx.unverified.insert(t.clone()) {
                diags.push(Diagnostic::warning(DiagKind::Unsupported, src.decl_span, format!("lift: the `{t}` instances of `{}` are declared unverified (`#[lift(unverified = ..)]`): not lifted, so the verified module has none and they stay unchecked host code", src.name)));
            }
        }
    }
    // 1. preprocess: drop host-only items, expand macros, flatten modules
    let mut pre: Vec<(usize, FileId, bool, bool, String, Vec<syn::Item>)> = Vec::new();
    let mut in_place: HashSet<usize> = HashSet::new();
    // `#[lift(mir = ..)]` modules (name, DSL path without `crate::`, text,
    // declaration) and the lifted source files the MIR must match
    let mut mir_texts: Vec<(String, String, String, Span)> = Vec::new();
    let dsl_modules: Vec<String> = sources.iter().filter(|s| !s.ghost && !s.host).map(|s| s.module_path.clone()).collect();
    let mir_files: Vec<(String, Vec<u8>)> = sources.iter().filter(|s| !s.ghost && !s.host).map(|s| (s.path_display.clone(), s.text.clone().into_bytes())).chain(sources.iter().flat_map(|s| s.mir_extra.clone())).collect();
    for s in &sources {
        if let Some(t) = &s.mir {
            mir_texts.push((s.name.clone(), s.module_path.trim_start_matches("crate::").to_string(), t.clone(), s.decl_span));
        }
    }
    // host models other than enums, for the MIR reading (`crate::mir::HostModels`)
    let mut mir_host = crate::mir::HostModels::default();
    for s in &sources {
        let mut starts = vec![0usize];
        starts.extend(s.text.match_indices('\n').map(|(i, _)| i + 1));
        cx.texts.insert(s.file, (s.text.clone(), starts));
    }
    let ghost_paths: HashMap<String, String> = sources.iter().filter(|s| s.ghost).map(|s| (s.name.clone(), s.module_path.clone())).collect();
    for s in sources {
        cx.file = s.file;
        cx.pre_ghost = s.ghost || s.host;
        if s.host {
            for it in &s.ast.items {
                match it {
                    syn::Item::Type(t) => {
                        mir_host.types.insert(t.ident.to_string(), (format!("{}::{}", s.module_path, t.ident), t.ty.to_token_stream().to_string()));
                    }
                    syn::Item::Struct(st) if matches!(st.fields, syn::Fields::Unit) => {
                        mir_host.structs.insert(st.ident.to_string(), format!("{}::{}", s.module_path, st.ident));
                    }
                    syn::Item::Enum(e) => {
                        mir_host.enums.insert(e.ident.to_string(), format!("{}::{}", s.module_path, e.ident));
                    }
                    _ => {}
                }
            }
        }
        cx.host_called.clear();
        let children: Vec<String> = s.children.iter().map(|(n, _)| n.clone()).collect();
        let access = (s.opts.in_place && !s.ghost && !s.host).then(|| host_access_of(&s.ast.items, &children));
        let items = cx.preprocess(s.ast.items, 0);
        let mut items = cx.host_filter(items, &s.opts, &children);
        cx.erase_open_generics(&mut items);
        if let Some(mut a) = access {
            a.called = std::mem::take(&mut cx.host_called);
            facts.host_access.push((s.file, a));
        }
        for it in items.iter_mut() {
            open::CorePaths.visit_item_mut(it);
        }
        if s.host {
            let f = syn::File { shebang: None, attrs: vec![], items: items.clone() };
            facts.host_checks.extend(host_checks(&f, s.file, in_place_crate, &mut facts.host_models, diags));
        }
        if s.opts.in_place {
            in_place.insert(s.module_index);
        }
        pre.push((s.module_index, s.file, s.ghost, s.host, s.name, items));
    }
    // 2. declarations
    for (_, file, _, _, modname, items) in &pre {
        cx.file = *file;
        cx.collect(modname, items);
    }
    cx.check_sealed();
    // 3. attachments (ghost modules)
    for (_, file, ghost, _, modname, items) in &mut pre {
        if *ghost {
            cx.file = *file;
            let in_laws = modname == LAWS_MODULE;
            let module = ghost_paths.get(modname.as_str()).cloned().unwrap_or_else(|| format!("crate::{modname}"));
            cx.take_attachments(items, in_laws, &module);
        }
    }
    // 3b. `#[lift(mir = ..)]`: rustc's MIR of the module's bodies
    {
        let sealed: std::collections::BTreeSet<String> = cx.traits.iter().filter(|(_, t)| t.sealed).map(|(n, _)| n.clone()).collect();
        let mut host_enums: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (_, _, _, _, _, items) in &pre {
            for it in items {
                if let syn::Item::Enum(e) = it {
                    host_enums.entry(e.ident.to_string()).or_insert_with(|| e.variants.iter().map(|v| v.ident.to_string()).collect());
                }
            }
        }
        let files: Vec<(String, Vec<u8>)> = mir_files.clone();
        for (modname, suffix, text, span) in &mir_texts {
            let requires: std::collections::BTreeSet<String> = cx.attach_fn.iter().filter(|(_, a)| a.stmts.iter().any(|st| attach_call(st, "requires").is_some())).map(|(n, _)| n.clone()).collect();
            let open: BTreeMap<String, String> = cx.open.instances.iter().map(|(t, p)| (t.clone(), path_key(p).trim_start_matches("crate::").to_string())).collect();
            let consts: BTreeMap<(String, String), bool> = cx.open.assoc_consts.iter().map(|(t, c)| ((t.clone(), c.clone()), cx.open.const_fns.contains(&open::const_name(t, c)))).collect();
            let invariant_types = cx.attach_ty.keys().map(|k| k.rsplit("::").next().unwrap_or(k).to_string()).collect();
            let names = crate::mir::ModuleNames { module: String::new(), sealed: sealed.clone(), host_enums: host_enums.clone(), requires, open, dsl_modules: dsl_modules.clone(), current: Default::default(), consts, invariant_types, host: mir_host.clone() };
            let lookup = |p: &str| -> Option<Vec<u8>> { files.iter().find(|(f, _)| f.ends_with(&format!("/{p}")) || f == p).map(|(_, b)| b.clone()) };
            match crate::mir::load(text, &lookup, names, suffix) {
                Ok(l) => {
                    facts.mir_rustc = Some(l.m.rustc.clone());
                    facts.mir_loaded.push(MirModule { dsl: format!("crate::{suffix}"), loaded: std::sync::Arc::new(l.clone()) });
                    for t in l.names.host_types(&l.m) {
                        if !facts.mir_host_types.contains(&t) {
                            facts.mir_host_types.push(t);
                        }
                    }
                    cx.mir_modules.insert(modname.clone(), std::rc::Rc::new(l));
                }
                Err(e) => diags.push(Diagnostic::error(DiagKind::Unsupported, *span, format!("lift: `mir = ..`: {e}"))),
            }
        }
    }
    // 4. emit
    let mut out = Vec::new();
    for (idx, file, ghost, host, modname, items) in pre {
        cx.file = file;
        cx.open.cur_in_place = in_place.contains(&idx);
        cx.cur_mir = if ghost { None } else { cx.mir_modules.get(&modname).cloned() };
        cx.cur_host = host;
        let mir_module = cx.cur_mir.is_some();
        let mut lifted = cx.emit_module(&modname, ghost, items);
        cx.cur_mir = None;
        cx.cur_host = false;
        cx.open.cur_in_place = false;
        // (a MIR module's bodies need none of its imports: `use Trait as _`
        // only steered rustc's method resolution)
        if in_place.contains(&idx) || mir_module {
            cx.prune_unused(&mut lifted);
        }
        out.push(LiftResult { module_index: idx, items: lifted });
    }
    cx.ambiguous_attachments();
    // an attachment that attached to nothing is an error, never dropped
    // silently (its author relies on the contract it states)
    let mut unused: Vec<(String, Span)> = Vec::new();
    for (k, a) in &cx.attach_ty {
        if !cx.attach_used.contains(&format!("type {k}")) {
            unused.push((k.clone(), a.span));
        }
    }
    for (k, a) in &cx.attach_fn {
        if !cx.attach_used.contains(&format!("fn {k}")) {
            // a function of that name elsewhere: the path names the wrong module
            let name = k.rsplit("::").next().unwrap_or(k);
            match cx.lifted_paths.get(name).filter(|ps| !ps.contains(k)) {
                Some(ps) => {
                    let list: Vec<String> = ps.iter().map(|p| format!("`{p}`")).collect();
                    cx.errors.push((a.span, format!("attachment to `{k}`: the module `{}` holds no lifted `{name}`; it is {}", k.rsplit_once("::").map(|x| x.0).unwrap_or(""), list.join(", ")), vec![format!("attach to it by its full path, e.g. `#[lift_attach({})]`", ps.iter().next().cloned().unwrap_or_default())]));
                }
                None => unused.push((k.clone(), a.span)),
            }
        }
    }
    for ((f, n), a) in &cx.attach_loop {
        if !cx.attach_used.contains(&format!("loop {f}#{n}")) {
            unused.push((format!("{f}, loop {n}"), a.span));
        }
    }
    unused.sort_by(|a, b| a.0.cmp(&b.0));
    cx.unused_attachments.extend(unused);
    for (sp, msg, notes) in cx.errors.drain(..) {
        let mut d = Diagnostic::error(DiagKind::Unsupported, sp, format!("lift: {msg}"));
        for n in notes {
            d = d.note(n);
        }
        diags.push(d);
    }
    for d in &cx.dropped {
        diags.push(Diagnostic::warning(DiagKind::Unsupported, d.span, format!("lift: {} not lifted: {}", d.what, d.why)));
    }
    for (un, sp) in &cx.unused_attachments {
        diags.push(Diagnostic::error(DiagKind::Unsupported, *sp, format!("lift: attachment to `{un}` matches no lifted item")));
    }
    let mut fams = Families::new();
    let names: Vec<String> = cx.fns.keys().chain(cx.structs.keys()).cloned().collect();
    for n in names {
        if let Some(v) = cx.family_instances(&n) {
            fams.insert(n, v);
        }
    }
    facts.sizes = std::mem::take(&mut cx.sizes);
    facts.dropped = std::mem::take(&mut cx.dropped);
    facts.conform = std::mem::take(&mut cx.conform);
    facts.mir_read = std::mem::take(&mut cx.mir_read);
    facts.mir_contracts = std::mem::take(&mut cx.mir_contracts);
    facts.mir_helpers = std::mem::take(&mut cx.mir_helpers);
    facts.panic_lemmas = std::mem::take(&mut cx.panic_lemmas);
    facts.instances = std::mem::take(&mut cx.instances);
    facts.test_hook = test_hook::get();
    facts.conform_skipped = std::mem::take(&mut cx.conform_skipped);
    facts.host_obligations = std::mem::take(&mut cx.open.host_obligations);
    facts.host_depth_bounds = std::mem::take(&mut cx.open.host_depth_bounds);
    facts.panic_contracts = std::mem::take(&mut cx.open.panic_contracts);
    let mut inst: Vec<(String, String)> = cx.open.instances.iter().map(|(t, p)| (t.clone(), path_key(p))).collect();
    inst.sort();
    facts.open_instances = inst;
    facts.unverified_instances = unverified_instances;
    (out, fams, facts)
}

/// Rewrites a `use` tree of a non-lifted module (the crate root's `pub use`
/// list) so that a generic family name imports every instance.
pub fn expand_use_families(t: &mut syn::UseTree, fams: &Families) {
    match t {
        syn::UseTree::Path(p) => expand_use_families(&mut p.tree, fams),
        syn::UseTree::Group(g) => {
            let mut new = syn::punctuated::Punctuated::new();
            for mut x in std::mem::take(&mut g.items) {
                if let syn::UseTree::Name(n) = &x
                    && let Some(names) = fams.get(&n.ident.to_string())
                {
                    for nm in names {
                        new.push(syn::UseTree::Name(syn::UseName { ident: Ident::new(nm, n.ident.span()) }));
                    }
                    continue;
                }
                expand_use_families(&mut x, fams);
                new.push(x);
            }
            g.items = new;
        }
        syn::UseTree::Name(n) => {
            if let Some(names) = fams.get(&n.ident.to_string()) {
                let items: syn::punctuated::Punctuated<syn::UseTree, syn::Token![,]> = names.iter().map(|nm| syn::UseTree::Name(syn::UseName { ident: Ident::new(nm, n.ident.span()) })).collect();
                *t = syn::UseTree::Group(syn::UseGroup { brace_token: Default::default(), items });
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// context
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct TraitInfo {
    /// `From<X>` supertrait: `X`.
    from: Option<syn::Type>,
    /// Supertraits `Shl<usize>`, `ShrAssign<usize>`: the amount type (a
    /// ghost shift's literal amount, [`FnRw::shift_amount_ty`]).
    shift_amount: Option<syn::Type>,
    methods: BTreeMap<String, syn::Signature>,
    /// Declared inside a private inline module (the impl set is closed).
    sealed: bool,
    span: Span,
}

#[derive(Clone)]
struct ImplInfo {
    trait_name: String,
    /// The lifted module the impl is in (its method functions live there).
    module: String,
    self_ty: syn::Type,
    fns: Vec<syn::ImplItemFn>,
    assoc: HashMap<String, syn::Type>,
}

#[derive(Clone)]
struct GenericParam {
    name: String,
    /// Sealed trait bounds.
    bounds: Vec<String>,
}

#[derive(Clone)]
struct StructInfo {
    module: String,
    def: syn::ItemStruct,
    params: Vec<GenericParam>,
}

#[derive(Clone)]
struct FnInfo {
    params: Vec<GenericParam>,
    sig: syn::Signature,
}

#[derive(Clone, Default)]
struct MethodInfo {
    /// `&mut self`.
    mut_self: bool,
    /// Indices (in the signature, receiver excluded) of state parameters.
    state_params: Vec<usize>,
    sig: Option<syn::Signature>,
}

#[derive(Clone)]
struct Attach {
    /// Generic params of the attachment function (names substituted like the target's).
    params: Vec<String>,
    stmts: Vec<syn::Stmt>,
    /// Per statement: written in the laws file (the ghost `#[lift]` module
    /// `laws`, [`LAWS_MODULE`]). A function's contract — what the lock
    /// holds and §15.5 determines — is its laws-file `ensures` only; an
    /// `ensures` from any other ghost module (PROOF.rs) is a proof-internal
    /// summary: proven, and a fact at call sites, never locked (DESIGN.md
    /// §15.6).
    in_laws: Vec<bool>,
    /// Per statement: the DSL path of the ghost module that wrote it
    /// (`crate::laws`, `crate::proof`).
    modules: Vec<String>,
    /// Per statement: the arguments of a `requires(..)`, `ensures(..)`,
    /// `decreases(..)` or `invariant(..)` call as written in its own file,
    /// whitespace collapsed (empty for other statements). The spliced
    /// tokens keep their own file's line and column but are read as the
    /// host file's, so the item records this text (`#[lift_src]`,
    /// [`crate::hir::Attached`]): `SPEC.lock`'s source text of the item.
    srcs: Vec<String>,
    /// Per statement: its span in its own file (for errors).
    spans: Vec<Span>,
    span: Span,
}

impl Attach {
    /// Appends a later attachment to the same item (file order).
    fn extend(&mut self, other: Attach) {
        self.stmts.extend(other.stmts);
        self.in_laws.extend(other.in_laws);
        self.modules.extend(other.modules);
        self.srcs.extend(other.srcs);
        self.spans.extend(other.spans);
    }

    /// `#[lift_src(..)]` for statement `i` of kind `kind` (`requires`,
    /// `ensures`, `decreases`, `invariant`): the statement as written.
    fn src_attr(&self, i: usize, kind: &str) -> syn::Attribute {
        let k = syn::LitStr::new(kind, PSpan::call_site());
        let m = syn::LitStr::new(&self.modules[i], PSpan::call_site());
        let l = syn::LitBool::new(self.in_laws[i], PSpan::call_site());
        let t = syn::LitStr::new(&self.srcs[i], PSpan::call_site());
        syn::parse_quote!(#[lift_src(#k, #m, #l, #t)])
    }
}

/// The ghost `#[lift]` module that holds the laws and the contracts a
/// reviewer reads (`#[cfg(sandblaster)] #[lift] #[path = "LAWS.rs"] mod
/// laws;`). Every other ghost `#[lift]` module is a proof file: its items
/// and the `ensures` it attaches are proof internals, never locked
/// (DESIGN.md §15.6).
pub const LAWS_MODULE: &str = "laws";

#[derive(Default)]
struct Ctx {
    file: FileId,
    /// Impl types declared unverified (`#[lift(unverified = ..)]`).
    unverified: HashSet<String>,
    traits: HashMap<String, TraitInfo>,
    impls: Vec<ImplInfo>,
    structs: HashMap<String, StructInfo>,
    /// Generic fns and fns with state parameters, by name.
    fns: HashMap<String, FnInfo>,
    /// Inherent methods of lifted structs: (struct, method).
    methods: HashMap<(String, String), MethodInfo>,
    /// Consts and their types.
    consts: HashMap<String, syn::Type>,
    macros: HashMap<String, Vec<MacroRule>>,
    attach_ty: HashMap<String, Attach>,
    attach_loop: HashMap<(String, usize), Attach>,
    /// Function attachments (`ensures(..)`), by source name.
    attach_fn: HashMap<String, Attach>,
    attach_used: HashSet<String>,
    /// The functions a bare attachment name reaches: name → (the item it
    /// is a method or function of, the lifted path). A function of an impl
    /// on a primitive answers to its lifted name (`u64__from__Position`)
    /// and, when nothing else does, to its bare method name (`from`); a
    /// bare name that reaches several impls on primitives is refused.
    bare_candidates: BTreeMap<String, std::collections::BTreeSet<(String, String)>>,
    unused_attachments: Vec<(String, Span)>,
    attach_sigma: HashMap<String, syn::Type>,
    attach_bounds: HashMap<String, Vec<String>>,
    dropped: Vec<Dropped>,
    errors: Vec<(Span, String, Vec<String>)>,
    /// `T::SIZE` read as `size_of::<T>()` ([`LiftFacts::sizes`]).
    sizes: std::collections::BTreeSet<(String, u64)>,
    /// Preprocessing a ghost module (no conformance markers).
    pre_ghost: bool,
    /// The module being emitted.
    cur_module: String,
    /// The trait impl whose methods are being lifted: (trait path as
    /// written, the impl's inline module path, the self type as written
    /// with the instance's arguments).
    cur_impl: Option<(Option<String>, Vec<String>, String)>,
    /// [`LiftFacts::conform`].
    conform: Vec<ConformEntry>,
    /// [`LiftFacts::instances`].
    instances: BTreeMap<String, (String, Vec<String>)>,
    /// [`LiftFacts::conform_skipped`].
    conform_skipped: Vec<ConformSkip>,
    /// The source name of the method being lifted when the lift renames
    /// it (an operator impl's `add` lifted as `add__u64`): the name the
    /// conformance harness calls.
    conform_src_method: Option<String>,
    /// The inline module path of each struct of the lifted sources (for
    /// the conformance entry of a derived `default()`).
    struct_mods: HashMap<String, Vec<String>>,
    /// The tables of [`open`].
    open: open::OpenCtx,
    /// `#[lift(mir = ..)]` modules: module name → rustc's MIR ([`crate::mir`]).
    mir_modules: HashMap<String, std::rc::Rc<crate::mir::Loaded>>,
    /// The MIR of the module being emitted.
    cur_mir: Option<std::rc::Rc<crate::mir::Loaded>>,
    /// The module being emitted is a host model (`#[lift(host)]`): its
    /// functions' bodies (calls of spec functions) are read by the
    /// expression reading, like constants.
    cur_host: bool,
    /// [`LiftFacts::mir_read`].
    mir_read: Vec<(String, String, Vec<(usize, String)>)>,
    /// [`LiftFacts::mir_contracts`].
    mir_contracts: Vec<MirContract>,
    /// [`LiftFacts::mir_helpers`].
    mir_helpers: Vec<MirHelper>,
    /// [`LiftFacts::panic_lemmas`].
    panic_lemmas: Vec<(String, String)>,
    /// The text of every lifted source file and its line starts (an
    /// attachment's statements are read from their own file's text).
    texts: HashMap<FileId, (String, Vec<usize>)>,
    /// Every lifted exec function by its name (source, `S::m` or lifted
    /// name): the full paths attachments reach it by (an attachment whose
    /// path names the wrong module is refused, naming where it is).
    lifted_paths: BTreeMap<String, std::collections::BTreeSet<String>>,
    /// The names the code the lift leaves out of the current source calls
    /// ([`crate::hir::HostAccess::called`]; [`Ctx::note_left_out`]).
    host_called: std::collections::BTreeSet<String>,
}

impl Ctx {
    fn sp(&self, s: PSpan) -> Span {
        Span::from_pm2(self.file, s)
    }

    fn err(&mut self, s: PSpan, msg: impl Into<String>) {
        let sp = self.sp(s);
        self.errors.push((sp, msg.into(), vec![]));
    }

    fn err_note(&mut self, s: PSpan, msg: impl Into<String>, note: impl Into<String>) {
        let sp = self.sp(s);
        self.errors.push((sp, msg.into(), vec![note.into()]));
    }

    fn drop_item(&mut self, s: PSpan, what: String, why: &str) {
        let span = self.sp(s);
        self.dropped.push(Dropped { span, what, why: why.to_string() });
    }

    /// Records the names that code the lift leaves out calls (host code of
    /// the lifted file: [`crate::hir::HostAccess::called`]).
    fn note_left_out(&mut self, t: &impl ToTokens) {
        host_called_names(t.to_token_stream(), false, &mut self.host_called);
    }

    // -----------------------------------------------------------------------
    // 1. preprocessing
    // -----------------------------------------------------------------------

    fn preprocess(&mut self, items: Vec<syn::Item>, depth: usize) -> Vec<syn::Item> {
        // macros first (they may be used before their textual definition only
        // in the order rustc allows: definitions precede uses textually)
        let mut out = Vec::new();
        for item in items {
            if let Some(why) = host_only(item_attrs_of(&item)) {
                let what = describe(&item);
                // feature-gated code is host code of the build; tests are not
                if !is_test_only(item_attrs_of(&item)) {
                    self.note_left_out(&item);
                }
                self.drop_item(item.span(), what, why);
                continue;
            }
            match item {
                syn::Item::Macro(m) if m.mac.path.is_ident("macro_rules") => {
                    let Some(name) = m.ident.as_ref().map(|i| i.to_string()) else { continue };
                    match parse_macro_rules(m.mac.tokens.clone()) {
                        Ok(rules) => {
                            self.macros.insert(name, rules);
                        }
                        Err(e) => self.err(m.span(), format!("cannot read `macro_rules! {name}`: {e}")),
                    }
                }
                syn::Item::Macro(m) if m.mac.path.segments.len() >= 2 => {
                    // a macro of another crate (`cfg_if::cfg_if!`): host code
                    self.note_left_out(&m);
                    let name = m.mac.path.to_token_stream().to_string().replace(' ', "");
                    self.drop_item(m.span(), format!("item macro `{name}!`"), "a macro of another crate (host code; the items it expands to are not part of the lifted meaning)");
                }
                syn::Item::Macro(m) => {
                    let name = m.mac.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
                    let Some(rules) = self.macros.get(&name).cloned() else {
                        self.err(m.span(), format!("macro `{name}!` is not defined by `macro_rules!` in the lifted source"));
                        continue;
                    };
                    match expand(&rules, m.mac.tokens.clone()) {
                        Ok(ts) => match parse_items(ts) {
                            Ok(new) => {
                                if depth > 32 {
                                    self.err(m.span(), "macro expansion too deep");
                                    continue;
                                }
                                out.extend(self.preprocess(new, depth + 1));
                            }
                            Err(e) => self.err(m.span(), format!("expansion of `{name}!` is not a list of items: {e}")),
                        },
                        Err(e) => self.err(m.span(), format!("no rule of `{name}!` matches: {e}")),
                    }
                }
                syn::Item::Mod(m) if m.content.is_some() => {
                    let (_, items) = m.content.unwrap();
                    let items: Vec<syn::Item> = items
                        .into_iter()
                        .filter(|i| !matches!(i, syn::Item::Use(u) if is_use_super_glob(u)))
                        .map(|mut i| {
                            // items of a private inline module: remember they are sealed
                            if let syn::Item::Trait(t) = &mut i {
                                t.attrs.push(syn::parse_quote!(#[lift_sealed]));
                            }
                            i
                        })
                        .collect();
                    let mname = m.ident.clone();
                    for mut i in self.preprocess(items, depth + 1) {
                        // the inline module an exec impl or function is in
                        // (the conformance harness names the original there)
                        if !self.pre_ghost {
                            match &mut i {
                                syn::Item::Impl(im) => im.attrs.insert(0, syn::parse_quote!(#[lift_in_mod(#mname)])),
                                syn::Item::Fn(f) => f.attrs.insert(0, syn::parse_quote!(#[lift_in_mod(#mname)])),
                                syn::Item::Struct(st) => self.struct_mods.entry(st.ident.to_string()).or_default().insert(0, mname.to_string()),
                                _ => {}
                            }
                        }
                        out.push(i);
                    }
                }
                other => out.push(other),
            }
        }
        out
    }

    // -----------------------------------------------------------------------
    // 2. declarations
    // -----------------------------------------------------------------------

    fn collect(&mut self, modname: &str, items: &[syn::Item]) {
        for item in items {
            if let syn::Item::Enum(e) = item
                && e.generics.params.is_empty()
            {
                self.open.enums.insert(e.ident.to_string());
            }
            match item {
                syn::Item::Trait(t) => {
                    let name = t.ident.to_string();
                    let sealed = t.attrs.iter().any(|a| a.path().is_ident("lift_sealed"));
                    // an open trait declared in a lifted file, read at its instance
                    let open_decl = !sealed && self.open.instances.contains_key(&name);
                    let mut from = None;
                    let mut shift_amount = None;
                    for b in &t.supertraits {
                        if let syn::TypeParamBound::Trait(tb) = b {
                            let seg = tb.path.segments.last().unwrap();
                            let sname = seg.ident.to_string();
                            // (an open trait's `Clone`/`Send`/`Sync` bounds constrain its
                            // impls, never the meaning of a call at the instance)
                            if !OPERATOR_SUPERTRAITS.contains(&sname.as_str()) && !self.traits.contains_key(&sname) && !(open_decl && open::OPEN_MARKER_SUPERTRAITS.contains(&sname.as_str())) {
                                self.err(tb.span(), format!("supertrait `{sname}` of `{name}` is not known to the lift"));
                            }
                            if let syn::PathArguments::AngleBracketed(a) = &seg.arguments
                                && let Some(syn::GenericArgument::Type(ty)) = a.args.first()
                            {
                                match sname.as_str() {
                                    "From" => from = Some(ty.clone()),
                                    "Shl" | "ShrAssign" => shift_amount = Some(ty.clone()),
                                    _ => {}
                                }
                            }
                        }
                    }
                    let mut methods = BTreeMap::new();
                    for ti in &t.items {
                        match ti {
                            syn::TraitItem::Fn(f) => {
                                if f.default.is_some() {
                                    if open_decl {
                                        // lifted at the instance, unless its impl overrides it
                                        self.open.trait_defaults.entry(name.clone()).or_default().push(f.clone());
                                    } else {
                                        self.err(f.span(), "trait methods with default bodies are not lifted yet (except provided methods of an open trait declared in the file, read at its instance)");
                                    }
                                }
                                methods.insert(f.sig.ident.to_string(), f.sig.clone());
                            }
                            syn::TraitItem::Type(_) => {}
                            other => self.err(other.span(), "only methods and associated types are lifted in traits"),
                        }
                    }
                    let span = self.sp(t.span());
                    self.traits.insert(name, TraitInfo { from, shift_amount, methods, sealed, span });
                }
                syn::Item::Impl(im) => {
                    if self.collect_open_impl(im) {
                        continue;
                    }
                    let Some((_, tpath, _)) = &im.trait_ else {
                        // inherent impl of a (generic) struct
                        if let Some(sname) = type_name(&im.self_ty) {
                            for ii in &im.items {
                                if let syn::ImplItem::Fn(f) = ii {
                                    self.open.inherent_fns.insert((sname.clone(), f.sig.ident.to_string()), f.clone());
                                    let mi = method_info(&f.sig);
                                    self.methods.insert((sname.clone(), f.sig.ident.to_string()), mi);
                                }
                            }
                        }
                        continue;
                    };
                    let tname = tpath.segments.last().unwrap().ident.to_string();
                    if self.unverified.contains(&ty_key(&im.self_ty)) {
                        continue;
                    }
                    if im.generics.params.is_empty() && !self.is_generic_struct_ty(&im.self_ty) && type_name(&im.self_ty).is_some_and(|n| is_prim(&n)) && !HOST_TRAITS.contains(&tname.as_str()) && tname != "From" {
                        let mut fns = Vec::new();
                        let mut assoc = HashMap::new();
                        for ii in &im.items {
                            match ii {
                                syn::ImplItem::Fn(f) => fns.push(f.clone()),
                                syn::ImplItem::Type(t) => {
                                    assoc.insert(t.ident.to_string(), t.ty.clone());
                                }
                                other => self.err(other.span(), "only methods and associated types are lifted in trait impls"),
                            }
                        }
                        self.impls.push(ImplInfo { trait_name: tname, module: modname.to_string(), self_ty: (*im.self_ty).clone(), fns, assoc });
                    } else if let Some(sname) = type_name(&im.self_ty) {
                        // an impl of a trait the lift does not know (not sealed or
                        // declared here, not an open trait at its instance, not an
                        // operator, method, host or dropped trait): an error, never
                        // a guess at how its calls resolve (declare it `unverified_impls`)
                        if !HOST_TRAITS.contains(&tname.as_str()) && tname != "From" && !self.traits.contains_key(&tname) {
                            self.err(tpath.span(), format!("impl of the trait `{tname}`, which the lift does not know: declare it host code with `unverified_impls = \"{tname}\"`"));
                            continue;
                        }
                        // host-trait impl of a lifted struct: its methods become inherent
                        for ii in &im.items {
                            if let syn::ImplItem::Fn(f) = ii {
                                let mi = method_info(&f.sig);
                                self.methods.insert((sname.clone(), f.sig.ident.to_string()), mi);
                            }
                        }
                    }
                }
                syn::Item::Struct(s) => {
                    let params = self.generic_params(&s.generics);
                    self.structs.insert(s.ident.to_string(), StructInfo { module: modname.to_string(), def: s.clone(), params });
                    if derives_of(&s.attrs).iter().any(|d| d == "Default") {
                        let sn = s.ident.to_string();
                        self.open.derive_default.insert(sn.clone());
                        let sig: syn::Signature = syn::parse_quote!(fn default() -> Self);
                        self.methods.insert((sn, "default".into()), method_info(&sig));
                    }
                }
                syn::Item::Fn(f) => {
                    let iters = open::byte_iter_params(&f.sig.generics);
                    let params: Vec<GenericParam> = self.generic_params(&f.sig.generics).into_iter().filter(|p| !iters.contains(&p.name)).collect();
                    self.fns.insert(f.sig.ident.to_string(), FnInfo { params, sig: f.sig.clone() });
                }
                syn::Item::Const(c) => {
                    self.consts.insert(c.ident.to_string(), (*c.ty).clone());
                }
                _ => {}
            }
        }
    }

    fn is_generic_struct_ty(&self, t: &syn::Type) -> bool {
        type_name(t).is_some_and(|n| self.structs.contains_key(&n))
    }

    fn generic_params(&mut self, g: &syn::Generics) -> Vec<GenericParam> {
        let mut out = Vec::new();
        for p in &g.params {
            match p {
                syn::GenericParam::Type(tp) => {
                    let mut bounds = Vec::new();
                    for b in &tp.bounds {
                        if let syn::TypeParamBound::Trait(tb) = b {
                            bounds.push(tb.path.segments.last().unwrap().ident.to_string());
                        }
                    }
                    out.push(GenericParam { name: tp.ident.to_string(), bounds });
                }
                syn::GenericParam::Lifetime(_) => {}
                syn::GenericParam::Const(c) => self.err(c.span(), "const generics are not lifted"),
            }
        }
        if let Some(w) = &g.where_clause {
            for pred in &w.predicates {
                if let syn::WherePredicate::Type(pt) = pred
                    && let Some(n) = type_name(&pt.bounded_ty)
                    && let Some(gp) = out.iter_mut().find(|p| p.name == n)
                {
                    for b in &pt.bounds {
                        if let syn::TypeParamBound::Trait(tb) = b {
                            gp.bounds.push(tb.path.segments.last().unwrap().ident.to_string());
                        }
                    }
                }
            }
        }
        out
    }

    /// Checks the sealed-trait conditions: every trait the lift
    /// monomorphizes over is sealed, and a method whose name is also an
    /// inherent integer method is a pure delegation in every impl.
    fn check_sealed(&mut self) {
        let names: Vec<String> = self.traits.keys().cloned().collect();
        for n in names {
            let t = self.traits[&n].clone();
            // an open trait declared in the file is read at its instance (its
            // parameters were erased; `open::open_impl_items`)
            if !t.sealed && self.open.instances.contains_key(&n) {
                continue;
            }
            if !t.sealed {
                self.errors.push((t.span, format!("trait `{n}` is not sealed (declared outside a private module): its impl set is open, so its generic users cannot be monomorphized"), vec![]));
                continue;
            }
            for m in t.methods.keys() {
                if !INHERENT_INT_METHODS.contains(&m.as_str()) {
                    continue;
                }
                for im in self.impls.iter().filter(|i| i.trait_name == n) {
                    if let Some(f) = im.fns.iter().find(|f| f.sig.ident == m.as_str())
                        && !is_delegation(f, m)
                    {
                        let sp = self.sp(f.span());
                        self.errors.push((sp, format!("`{n}::{m}` shares its name with an inherent integer method, but this impl is not the delegation `self.{m}(..)`: the generic and the monomorphic resolution would differ"), vec![]));
                    }
                }
            }
        }
    }

    /// The impl types of a sealed trait (in declaration order).
    fn impl_types(&self, trait_name: &str) -> Vec<syn::Type> {
        self.impls.iter().filter(|i| i.trait_name == trait_name).map(|i| i.self_ty.clone()).collect()
    }

    fn impl_of(&self, trait_name: &str, ty: &syn::Type) -> Option<&ImplInfo> {
        let k = ty_key(ty);
        self.impls.iter().find(|i| i.trait_name == trait_name && ty_key(&i.self_ty) == k)
    }

    /// Instances of a generic parameter list: every combination of impl
    /// types of the parameters' sealed bounds.
    fn instances(&self, params: &[GenericParam]) -> Result<Vec<Vec<syn::Type>>, String> {
        let mut acc: Vec<Vec<syn::Type>> = vec![vec![]];
        for p in params {
            let sealed: Vec<&String> = p.bounds.iter().filter(|b| self.traits.get(*b).is_some_and(|t| t.sealed)).collect();
            if sealed.is_empty() {
                return Err(format!("type parameter `{}` has no sealed-trait bound (only sealed-trait generics are monomorphized)", p.name));
            }
            let mut tys = self.impl_types(sealed[0]);
            for b in &sealed[1..] {
                let other: HashSet<String> = self.impl_types(b).iter().map(ty_key).collect();
                tys.retain(|t| other.contains(&ty_key(t)));
            }
            let mut next = Vec::new();
            for a in &acc {
                for t in &tys {
                    let mut v = a.clone();
                    v.push(t.clone());
                    next.push(v);
                }
            }
            acc = next;
        }
        Ok(acc)
    }

    // -----------------------------------------------------------------------
    // 3. attachments
    // -----------------------------------------------------------------------

    fn take_attachments(&mut self, items: &mut Vec<syn::Item>, in_laws: bool, module: &str) {
        let mut keep = Vec::new();
        for item in items.drain(..) {
            let syn::Item::Fn(f) = &item else {
                keep.push(item);
                continue;
            };
            let Some(a) = f.attrs.iter().find(|a| a.path().is_ident("lift_attach")) else {
                keep.push(item);
                continue;
            };
            let span = self.sp(a.span());
            // `#[lift_attach(path)]` / `#[lift_attach(path, loop_nr = k)]`
            let args = match a.parse_args_with(syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated) {
                Ok(v) => v,
                Err(e) => {
                    self.err(a.span(), format!("malformed `#[lift_attach(..)]`: {e}"));
                    continue;
                }
            };
            let mut segs: Vec<String> = Vec::new();
            let mut lp = None;
            for (i, x) in args.iter().enumerate() {
                match x {
                    syn::Expr::Path(p) if i == 0 => segs = p.path.segments.iter().map(|s| s.ident.to_string()).collect(),
                    syn::Expr::Assign(asg) if matches!(&*asg.left, syn::Expr::Path(p) if p.path.is_ident("loop_nr")) => lp = expr_usize(&asg.right),
                    other => self.err(other.span(), "`#[lift_attach(path)]` or `#[lift_attach(path, loop_nr = k)]`"),
                }
            }
            // the target, by its full path: a struct (`crate::m::S`), a
            // method of a lifted struct (`crate::m::S::f`, `S` declared in
            // `crate::m`) or a function of the module `crate::m`
            // (`crate::m::f`; checked against the lifted functions at the
            // end, [`lift`]); a path whose module does not hold the struct
            // is refused, naming where it is
            let n = segs.len();
            let written = segs.join("::");
            let struct_at = |cx: &Ctx, ty: &str, wmod: &[String]| -> Result<String, String> {
                let decl = cx.struct_module_path(ty);
                let wmod = wmod.join("::");
                if wmod == decl {
                    Ok(decl)
                } else {
                    Err(format!("attachment to `{written}`: the module `{wmod}` holds no lifted `{ty}`; it is `{decl}::{ty}`"))
                }
            };
            let (target_ty, target_fn) = if n == 0 {
                (None, None)
            } else if lp.is_none() && self.structs.contains_key(&segs[n - 1]) {
                match struct_at(self, &segs[n - 1], &segs[..n - 1]) {
                    Ok(decl) => (Some(format!("{decl}::{}", segs[n - 1])), None),
                    Err(msg) => {
                        self.errors.push((span, msg, vec![]));
                        continue;
                    }
                }
            } else if n >= 2 && self.structs.contains_key(&segs[n - 2]) {
                match struct_at(self, &segs[n - 2], &segs[..n - 2]) {
                    Ok(decl) => (None, Some(format!("{decl}::{}::{}", segs[n - 2], segs[n - 1]))),
                    Err(msg) => {
                        self.errors.push((span, msg, vec![]));
                        continue;
                    }
                }
            } else {
                (None, Some(written.clone()))
            };
            let params = f.sig.generics.params.iter().filter_map(|p| match p {
                syn::GenericParam::Type(t) => Some(t.ident.to_string()),
                _ => None,
            }).collect();
            let k = f.block.stmts.len();
            let srcs: Vec<String> = f.block.stmts.iter().map(|st| self.stmt_args_text(st)).collect();
            let spans: Vec<Span> = f.block.stmts.iter().map(|st| self.sp(st.span())).collect();
            let at = Attach { params, stmts: f.block.stmts.clone(), in_laws: vec![in_laws; k], modules: vec![module.to_string(); k], srcs, spans, span };
            match (target_ty, target_fn, lp) {
                (Some(t), None, None) => {
                    // several attachments to one item (a law file's precondition, a
                    // proof file's summary) are one attachment, in file order
                    match self.attach_ty.get_mut(&t) {
                        Some(prev) => prev.extend(at),
                        None => {
                            self.attach_ty.insert(t, at);
                        }
                    }
                }
                (None, Some(fname), Some(k)) => {
                    // several attachments to one item (a law file's precondition, a
                    // proof file's summary) are one attachment, in file order
                    match self.attach_loop.get_mut(&(fname.clone(), k)) {
                        Some(prev) => prev.extend(at),
                        None => {
                            self.attach_loop.insert((fname, k), at);
                        }
                    }
                }
                (None, Some(fname), None) => {
                    // several attachments to one item (a law file's precondition, a
                    // proof file's summary) are one attachment, in file order
                    match self.attach_fn.get_mut(&fname) {
                        Some(prev) => prev.extend(at),
                        None => {
                            self.attach_fn.insert(fname, at);
                        }
                    }
                }
                _ => self.err(a.span(), "`#[lift_attach(path)]` or `#[lift_attach(path, loop_nr = k)]`"),
            }
        }
        *items = keep;
    }

    /// The DSL path of the module that declares the lifted struct `ty`.
    fn struct_module_path(&self, ty: &str) -> String {
        match self.structs.get(ty) {
            Some(si) => self.open.module_paths.get(&si.module).cloned().unwrap_or_else(|| format!("crate::{}", si.module)),
            None => self.conform_module_path(),
        }
    }

    /// The full path attachments reach a lifted function by, from the name
    /// [`Ctx::attach_key`] gives it: `crate::m::S::f` for a method `S::f`
    /// of a lifted struct (`crate::m` declares `S`), else `crate::m::f`
    /// for the module `crate::m` being emitted. Recorded for the refusal
    /// of a misdirected attachment ([`Ctx::lifted_paths`]).
    fn attach_path(&mut self, name: &str) -> String {
        let full = match name.split_once("::") {
            Some((ty, _)) if self.structs.contains_key(ty) => format!("{}::{name}", self.struct_module_path(ty)),
            _ => format!("{}::{name}", self.conform_module_path()),
        };
        let last = name.rsplit("::").next().unwrap_or(name).to_string();
        self.lifted_paths.entry(last).or_default().insert(full.clone());
        full
    }

    /// The arguments of an attachment statement `requires(..)`,
    /// `ensures(..)`, `decreases(..)` or `invariant(..)` as written in the
    /// attachment's file (whitespace collapsed); empty for any other
    /// statement. Read while [`Ctx::file`] is the attachment's file.
    fn stmt_args_text(&self, st: &syn::Stmt) -> String {
        let syn::Stmt::Expr(syn::Expr::Call(c), _) = st else { return String::new() };
        let syn::Expr::Path(p) = &*c.func else { return String::new() };
        if !["requires", "ensures", "decreases", "invariant"].iter().any(|k| p.path.is_ident(k)) {
            return String::new();
        }
        let g = c.paren_token.span.join();
        let Some((text, starts)) = self.texts.get(&self.file) else { return String::new() };
        let byte = |lc: proc_macro2::LineColumn| -> Option<usize> {
            let start = *starts.get(lc.line.checked_sub(1)?)?;
            let line = &text[start..];
            Some(start + line.chars().take(lc.column).map(char::len_utf8).sum::<usize>())
        };
        match (byte(g.start()), byte(g.end())) {
            // without the parentheses
            (Some(a), Some(b)) if a < b && b <= text.len() => crate::deelab::flat(&text[a + 1..b - 1]),
            _ => String::new(),
        }
    }

    // -----------------------------------------------------------------------
    // 4. emission
    // -----------------------------------------------------------------------

    fn emit_module(&mut self, modname: &str, ghost: bool, items: Vec<syn::Item>) -> Vec<syn::Item> {
        self.cur_module = modname.to_string();
        let mut out: Vec<syn::Item> = Vec::new();
        let user_fns: HashSet<String> = items.iter().filter_map(|i| match i {
            syn::Item::Fn(f) if f.sig.generics.params.is_empty() => Some(f.sig.ident.to_string()),
            _ => None,
        }).collect();
        // the annotations (attachments put `#[invariant]`, `#[decreases]`, `proof!` into lifted items)
        if !items.iter().any(|i| matches!(i, syn::Item::Use(u) if u.to_token_stream().to_string().replace(' ', "") == "usesandblaster::prelude::*;")) {
            out.push(syn::parse_quote!(#[allow(unused_imports)] use sandblaster::prelude::*;));
        }
        // the lift prelude: `Result` (and `TryGetError`) for every lifted module
        out.push(syn::parse_quote!(#[allow(unused_imports)] use crate::__lift::Result;));
        out.push(syn::parse_quote!(#[allow(unused_imports)] use crate::__lift::Result::{Ok, Err};));
        out.push(syn::parse_quote!(#[allow(unused_imports)] use crate::__lift::TryGetError;));
        for item in items {
            match item {
                syn::Item::Use(u) => {
                    if let Some(u) = self.lift_use(u, ghost) {
                        out.push(syn::Item::Use(u));
                    }
                }
                syn::Item::Const(mut c) => {
                    // the model's items are crate-visible, so proofs can name them
                    if matches!(c.vis, syn::Visibility::Inherited) {
                        c.vis = syn::parse_quote!(pub(crate));
                    }
                    // the initializer: the expression reading (literals,
                    // `size_of`, other constants, calls of lifted functions)
                    let mut rw = FnRw::new(self, HashMap::new(), ghost);
                    rw.expr(&mut c.expr, Some(&c.ty.clone()));
                    drop(rw);
                    out.push(syn::Item::Const(c));
                }
                syn::Item::Trait(_) => {}
                syn::Item::Fn(f) if f.sig.constness.is_some() && f.block.stmts.iter().all(|s| matches!(s, syn::Stmt::Expr(syn::Expr::Macro(m), _) if m.mac.path.is_ident("assert")) || matches!(s, syn::Stmt::Macro(m) if m.mac.path.is_ident("assert"))) => {
                    // `const fn` compile-time assertions, used only in `const { .. }`
                    // blocks (rustc evaluates them; MIR has no trace of them)
                }
                syn::Item::Fn(f) => {
                    // byte-string iterator parameters are states, not instances (`open::state_param`)
                    let iters = open::byte_iter_params(&f.sig.generics);
                    let params: Vec<GenericParam> = self.generic_params(&f.sig.generics).into_iter().filter(|p| !iters.contains(&p.name)).collect();
                    if params.is_empty() {
                        let lifted = self.lift_fn(f, HashMap::new(), None, ghost, None);
                        out.extend(lifted);
                    } else {
                        let insts = match self.instances(&params) {
                            Ok(i) => i,
                            Err(e) => {
                                self.err(f.sig.ident.span(), format!("cannot monomorphize `{}`: {e}", f.sig.ident));
                                continue;
                            }
                        };
                        for inst in insts {
                            let sigma: HashMap<String, syn::Type> = params.iter().map(|p| p.name.clone()).zip(inst.iter().cloned()).collect();
                            let name = mangle(&f.sig.ident.to_string(), &inst);
                            // a ghost instance written out by hand (`fn lemma__u16`) replaces the
                            // generated one: a statement proven per width by different steps
                            if ghost && user_fns.contains(&name) {
                                continue;
                            }
                            let lifted = self.lift_fn(f.clone(), sigma, None, ghost, Some(name));
                            out.extend(lifted);
                        }
                    }
                }
                syn::Item::Struct(s) => {
                    let params = self.generic_params(&s.generics);
                    let sname = s.ident.to_string();
                    let insts = if params.is_empty() { Ok(vec![vec![]]) } else { self.instances(&params) };
                    let insts = match insts {
                        Ok(i) => i,
                        Err(e) => {
                            self.err(s.ident.span(), format!("cannot monomorphize `{sname}`: {e}"));
                            continue;
                        }
                    };
                    for inst in insts {
                        let sigma: HashMap<String, syn::Type> = params.iter().map(|p| p.name.clone()).zip(inst.iter().cloned()).collect();
                        let mut s2 = s.clone();
                        s2.generics = syn::Generics::default();
                        if !inst.is_empty() {
                            s2.ident = format_ident!("{}", mangle(&sname, &inst), span = s.ident.span());
                            if !ghost {
                                self.instances.insert(mangle(&sname, &inst), (sname.clone(), inst.iter().map(ty_key).collect()));
                            }
                        }
                        s2.attrs = self.lift_derives(&s2.attrs, s.span());
                        let mut rw = FnRw::new(self, sigma.clone(), ghost);
                        for fld in s2.fields.iter_mut() {
                            rw.ty(&mut fld.ty);
                        }
                        drop(rw);
                        // attached invariant
                        let tkey = format!("{}::{sname}", self.conform_module_path());
                        if let Some(at) = self.attach_ty.get(&tkey).cloned() {
                            self.attach_used.insert(format!("type {tkey}"));
                            for (i, st) in at.stmts.iter().enumerate() {
                                let Some(mut e) = attach_call(st, "invariant") else {
                                    self.errors.push((at.spans[i], "a type attachment holds `invariant(..);` statements only".into(), vec![]));
                                    continue;
                                };
                                let asig: HashMap<String, syn::Type> = at.params.iter().zip(params.iter()).filter_map(|(a, p)| sigma.get(&p.name).map(|t| (a.clone(), t.clone()))).collect();
                                let abounds: HashMap<String, Vec<String>> = at.params.iter().zip(params.iter()).map(|(a, p)| (a.clone(), p.bounds.clone())).collect();
                                let mut rw = FnRw::new(self, asig, true);
                                rw.bounds = abounds;
                                rw.expr(&mut e, None);
                                drop(rw);
                                // in place, host code builds values of the type too (unchecked):
                                // the invariant is an obligation of host code, listed like a
                                // `requires` (the record's preconditions)
                                if self.open.cur_in_place && !ghost {
                                    self.open.host_obligations.push((format!("type {}", s2.ident), e.to_token_stream().to_string()));
                                }
                                s2.attrs.push(syn::parse_quote!(#[invariant(#e)]));
                                // as written, for `SPEC.lock` and the proof-file refusal
                                if !ghost {
                                    s2.attrs.push(at.src_attr(i, "invariant"));
                                }
                            }
                        }
                        let dd = if self.open.derive_default.contains(&sname) { self.derived_default(&s, &s2, ghost) } else { None };
                        out.push(syn::Item::Struct(s2));
                        out.extend(dd);
                    }
                }
                syn::Item::Impl(im) if im.trait_.is_some() && self.unverified.contains(&ty_key(&im.self_ty)) => {}
                syn::Item::Impl(im) => {
                    let lifted = self.lift_impl(im, ghost);
                    out.extend(lifted);
                }
                syn::Item::Enum(e) => {
                    let mut e = e;
                    // `#[derive(thiserror::Error)]`'s `#[error("..")]` on variants: the
                    // `Display` text (formatting, host code; the derive is dropped below)
                    let thiserror = e.attrs.iter().any(|a| a.path().is_ident("derive") && a.to_token_stream().to_string().replace(' ', "").contains("Error"));
                    if thiserror {
                        for v in e.variants.iter_mut() {
                            v.attrs.retain(|a| !a.path().is_ident("error"));
                        }
                    }
                    e.attrs = self.lift_derives(&e.attrs, e.span());
                    out.push(syn::Item::Enum(e));
                }
                other => out.push(other),
            }
        }
        let _ = modname;
        for it in out.iter_mut() {
            SignedTypes.visit_item_mut(it);
        }
        out
    }

    fn lift_derives(&mut self, attrs: &[syn::Attribute], span: PSpan) -> Vec<syn::Attribute> {
        let mut out = Vec::new();
        let mut derives: Vec<String> = Vec::new();
        for a in attrs {
            if a.path().is_ident("derive") {
                let list = a.parse_args_with(syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated).map(|p| p.into_iter().map(|x| x.to_token_stream().to_string().replace(' ', "")).collect::<Vec<_>>()).unwrap_or_default();
                derives.extend(list);
            } else if a.path().is_ident("doc") || a.path().is_ident("allow") || a.path().is_ident("invariant") {
                out.push(a.clone());
            }
        }
        let mut kept: Vec<syn::Path> = Vec::new();
        let mut dropped = Vec::new();
        for d in &derives {
            match d.as_str() {
                "Clone" | "Copy" | "PartialEq" | "Eq" | "Debug" => kept.push(syn::parse_str(d).unwrap()),
                // synthesized as `fn default()` (`open::derived_default`)
                "Default" => {}
                other => dropped.push(other.to_string()),
            }
        }
        {
            // every lifted type is a value (`Copy` added: rustc already checked moves);
            // in an in-place module also `PartialEq`, `Eq`: ghost `==` is structural
            // equality, and exec `==` on a lifted type is always its host impl's
            // `eq` (`open::operator_rewrite`) or rejected by rustc, never the derive
            let needs: &[&str] = if self.open.cur_in_place { &["Clone", "Copy", "PartialEq", "Eq"] } else { &["Clone", "Copy"] };
            for need in needs.iter().copied() {
                if !kept.iter().any(|p| p.is_ident(need)) {
                    kept.push(syn::parse_str(need).unwrap());
                }
            }
            out.push(syn::parse_quote!(#[derive(#(#kept),*)]));
        }
        if !dropped.is_empty() {
            self.drop_item(span, format!("derive({})", dropped.join(", ")), "rustc-derived impls the lifted code does not use (trusted as rustc's derive)");
        }
        out
    }

    fn lift_use(&mut self, mut u: syn::ItemUse, ghost: bool) -> Option<syn::ItemUse> {
        fn filter(cx: &Ctx, t: &mut syn::UseTree, ghost: bool) -> bool {
            match t {
                syn::UseTree::Path(p) => {
                    let first = p.ident.to_string();
                    if matches!(first.as_str(), "bytes" | "core" | "std" | "alloc" | "sealed") {
                        return false;
                    }
                    filter(cx, &mut p.tree, ghost)
                }
                syn::UseTree::Name(n) => {
                    let s = n.ident.to_string();
                    if HOST_TRAITS.contains(&s.as_str()) || cx.traits.contains_key(&s) {
                        return false;
                    }
                    if s == "Result" {
                        return false;
                    }
                    true
                }
                syn::UseTree::Rename(r) => !HOST_TRAITS.contains(&r.ident.to_string().as_str()),
                syn::UseTree::Glob(_) => true,
                syn::UseTree::Group(g) => {
                    let items: Vec<syn::UseTree> = std::mem::take(&mut g.items).into_iter().filter_map(|mut x| if filter(cx, &mut x, ghost) { Some(x) } else { None }).collect();
                    g.items = items.into_iter().collect();
                    !g.items.is_empty()
                }
            }
        }
        if !filter(self, &mut u.tree, ghost) {
            return None;
        }
        // generic families: import every instance
        fn expand_families(cx: &Ctx, t: &mut syn::UseTree) {
            match t {
                syn::UseTree::Path(p) => expand_families(cx, &mut p.tree),
                syn::UseTree::Group(g) => {
                    let mut new = syn::punctuated::Punctuated::new();
                    for mut x in std::mem::take(&mut g.items) {
                        if let syn::UseTree::Name(n) = &x
                            && let Some(names) = cx.family_instances(&n.ident.to_string())
                        {
                            for nm in names {
                                new.push(syn::UseTree::Name(syn::UseName { ident: Ident::new(&nm, n.ident.span()) }));
                            }
                            continue;
                        }
                        expand_families(cx, &mut x);
                        new.push(x);
                    }
                    g.items = new;
                }
                syn::UseTree::Name(n) if !cx.const_names_of(&n.ident.to_string()).is_empty() => {
                    let mut items: syn::punctuated::Punctuated<syn::UseTree, syn::Token![,]> = syn::punctuated::Punctuated::new();
                    items.push(syn::UseTree::Name(n.clone()));
                    for c in cx.const_names_of(&n.ident.to_string()) {
                        items.push(syn::UseTree::Name(syn::UseName { ident: Ident::new(&c, n.ident.span()) }));
                    }
                    *t = syn::UseTree::Group(syn::UseGroup { brace_token: Default::default(), items });
                }
                syn::UseTree::Name(n) => {
                    if let Some(names) = cx.family_instances(&n.ident.to_string()) {
                        let items: syn::punctuated::Punctuated<syn::UseTree, syn::Token![,]> = names.iter().map(|nm| syn::UseTree::Name(syn::UseName { ident: Ident::new(nm, n.ident.span()) })).collect();
                        *t = syn::UseTree::Group(syn::UseGroup { brace_token: Default::default(), items });
                    }
                }
                _ => {}
            }
        }
        expand_families(self, &mut u.tree);
        Some(u)
    }

    /// The instance names of a generic family (fn or struct), if generic.
    fn family_instances(&self, name: &str) -> Option<Vec<String>> {
        let params = if let Some(f) = self.fns.get(name) {
            f.params.clone()
        } else if let Some(s) = self.structs.get(name) {
            s.params.clone()
        } else {
            return None;
        };
        if params.is_empty() {
            return None;
        }
        let insts = self.instances(&params).ok()?;
        Some(insts.iter().map(|i| mangle(name, i)).collect())
    }

    fn lift_impl(&mut self, im: syn::ItemImpl, ghost: bool) -> Vec<syn::Item> {
        let tname = im.trait_.as_ref().map(|(_, p, _)| p.segments.last().unwrap().ident.to_string());
        // sealed-trait impl on a concrete type: free functions
        let modpath = in_mod_path(&im.attrs);
        let trait_written = im.trait_.as_ref().map(|(_, p, _)| p.to_token_stream().to_string().replace(' ', ""));
        if let Some(t) = &tname
            && self.traits.get(t).is_some_and(|ti| ti.sealed)
        {
            let self_ty = (*im.self_ty).clone();
            let mut out = Vec::new();
            self.cur_impl = Some((trait_written.clone(), modpath.clone(), ty_key(&self_ty)));
            for ii in &im.items {
                if let syn::ImplItem::Fn(f) = ii {
                    let name = trait_fn_name(t, &self_ty, &f.sig.ident.to_string());
                    let item_fn = syn::ItemFn { attrs: keep_fn_attrs(&f.attrs), vis: syn::parse_quote!(pub(crate)), sig: f.sig.clone(), block: Box::new(f.block.clone()) };
                    out.extend(self.lift_fn(item_fn, HashMap::new(), Some(self_ty.clone()), ghost, Some(name)));
                }
            }
            self.cur_impl = None;
            return out;
        }
        // `impl From<A> for Prim` (host trait on a primitive): a free function
        if tname.as_deref() == Some("From") && type_name(&im.self_ty).is_some_and(|n| is_prim(&n)) {
            let self_ty = (*im.self_ty).clone();
            let mut out = Vec::new();
            self.cur_impl = Some((trait_written.clone(), modpath.clone(), ty_key(&self_ty)));
            for ii in &im.items {
                if let syn::ImplItem::Fn(f) = ii {
                    let arg = f.sig.inputs.first().and_then(|a| match a {
                        syn::FnArg::Typed(pt) => Some((*pt.ty).clone()),
                        _ => None,
                    });
                    let arg_s = arg.as_ref().map(|t| ty_key(&self.subst_ty(t, &HashMap::new()))).unwrap_or_default();
                    let name = format!("{}__from__{}", ty_key(&self_ty), sanitize(&arg_s));
                    let item_fn = syn::ItemFn { attrs: keep_fn_attrs(&f.attrs), vis: syn::Visibility::Public(Default::default()), sig: f.sig.clone(), block: Box::new(f.block.clone()) };
                    out.extend(self.lift_fn(item_fn, HashMap::new(), Some(self_ty.clone()), ghost, Some(name)));
                }
            }
            self.cur_impl = None;
            return out;
        }
        // an operator impl on a primitive (`impl PartialEq<S> for u64`): free functions
        if let Some(t) = &tname
            && open::OP_TRAITS.contains(&t.as_str())
            && type_name(&im.self_ty).is_some_and(|n| is_prim(&n))
        {
            return self.lift_prim_op_impl(&im, t, ghost);
        }
        let Some(sname) = type_name(&im.self_ty) else {
            self.err(im.self_ty.span(), "impl of a type the lift does not know");
            return vec![];
        };
        // the impl's associated types (`Self::Output`, `Self::Target`, `Self::Item`)
        let assoc: HashMap<String, syn::Type> = im.items.iter().filter_map(|ii| match ii {
            syn::ImplItem::Type(t) => Some((t.ident.to_string(), t.ty.clone())),
            _ => None,
        }).collect();
        let op_arg = match (&tname, &im.trait_) {
            (Some(t), Some((_, p, _))) if open::OP_TRAITS.contains(&t.as_str()) => Some(open::trait_arg(p, &im.self_ty)),
            _ => None,
        };
        let params = self.generic_params(&im.generics);
        let insts = if params.is_empty() { Ok(vec![vec![]]) } else { self.instances(&params) };
        let insts = match insts {
            Ok(i) => i,
            Err(e) => {
                self.err(im.span(), format!("cannot monomorphize this impl: {e}"));
                return vec![];
            }
        };
        let mut out = Vec::new();
        for inst in insts {
            let sigma: HashMap<String, syn::Type> = params.iter().map(|p| p.name.clone()).zip(inst.iter().cloned()).collect();
            let mut self_ty = (*im.self_ty).clone();
            {
                let mut rw = FnRw::new(self, sigma.clone(), ghost);
                rw.ty(&mut self_ty);
            }
            let mut fns = Vec::new();
            self.cur_impl = Some((trait_written.clone(), modpath.clone(), ty_key(&subst_names(&im.self_ty, &sigma))));
            self.open.cur_impl_assoc = assoc.clone();
            // an open trait's impl at its instance: its methods and the trait's provided ones
            let impl_items: Vec<syn::ImplItem> = match &tname {
                Some(t) if self.open.instances.contains_key(t) => self.open_impl_items(&sname, t, &im),
                _ => im.items.clone(),
            };
            for ii in &impl_items {
                match ii {
                    syn::ImplItem::Fn(f) => {
                        let mut sig = f.sig.clone();
                        if let Some(arg) = &op_arg {
                            sig.ident = format_ident!("{}", open::op_method_name(&f.sig.ident.to_string(), arg), span = f.sig.ident.span());
                            // the harness calls the trait's method by its own name
                            self.conform_src_method = Some(f.sig.ident.to_string());
                        }
                        // in place, a private method is crate-visible in the model (rustc
                        // enforces privacy on the host's own files; proofs may name it)
                        let vis = if tname.is_some() {
                            syn::Visibility::Public(Default::default())
                        } else if self.open.cur_in_place && matches!(f.vis, syn::Visibility::Inherited) && !ghost {
                            syn::parse_quote!(pub(crate))
                        } else {
                            f.vis.clone()
                        };
                        let item_fn = syn::ItemFn { attrs: keep_fn_attrs(&f.attrs), vis, sig, block: Box::new(f.block.clone()) };
                        let mut lifted = self.lift_fn_b(item_fn, sigma.clone(), Some(self_ty.clone()), ghost, None, &params);
                        // the first item is the method; helpers (loop functions) go outside
                        // the impl, except method helpers (`#[lift_method]`: they take `self`)
                        let m = lifted.remove(0);
                        if let syn::Item::Fn(f) = m {
                            fns.push(syn::ImplItem::Fn(syn::ImplItemFn { attrs: f.attrs, vis: f.vis, defaultness: None, sig: f.sig, block: *f.block }));
                        }
                        for h in lifted {
                            match h {
                                syn::Item::Fn(mut hf) if hf.attrs.iter().any(|a| a.path().is_ident("lift_method")) => {
                                    hf.attrs.retain(|a| !a.path().is_ident("lift_method"));
                                    fns.push(syn::ImplItem::Fn(syn::ImplItemFn { attrs: hf.attrs, vis: syn::Visibility::Inherited, defaultness: None, sig: hf.sig, block: *hf.block }));
                                }
                                other => out.push(other),
                            }
                        }
                    }
                    syn::ImplItem::Type(_) => {}
                    // an associated constant of an open-trait impl: the module constant `S__C`
                    syn::ImplItem::Const(c) if tname.as_ref().is_some_and(|t| self.open.instances.contains_key(t)) => {
                        let name = format_ident!("{}", open::const_name(&sname, &c.ident.to_string()), span = c.ident.span());
                        let mut ty = c.ty.clone();
                        let mut e = c.expr.clone();
                        let mut rw = FnRw::new(self, sigma.clone(), ghost);
                        rw.self_ty = Some(self_ty.clone());
                        rw.ty(&mut ty);
                        rw.expr(&mut e, Some(&ty.clone()));
                        drop(rw);
                        let attrs: Vec<syn::Attribute> = c.attrs.iter().filter(|a| a.path().is_ident("doc")).cloned().collect();
                        if self.open.const_fns.contains(&name.to_string()) {
                            // a DSL constant cannot call a function: the constant function `S__C()`
                            if !ghost {
                                let lifted = format!("{}::{name}", self.conform_module_path());
                                self.conform_skipped.push(ConformSkip { module: self.cur_module.clone(), lifted, why: format!("the associated constant `{sname}::{}` lifted as a constant function (a constant, not a function of the source: compared through the functions that read it)", c.ident) });
                            }
                            // its contract, attached like any function's (the
                            // value host code reads: on the boundary of an
                            // in-place module, `validate::in_place_host_fns`)
                            let contract = if ghost { vec![] } else { self.const_fn_contract(&name.to_string(), &sigma, &self_ty) };
                            out.push(syn::parse_quote!(#(#attrs)* #(#contract)* #[allow(non_snake_case)] pub fn #name() -> #ty { #e }));
                        } else {
                            out.push(syn::parse_quote!(#(#attrs)* pub const #name: #ty = #e;));
                        }
                    }
                    other => self.err(other.span(), "only methods and associated types are lifted in impls"),
                }
            }
            self.cur_impl = None;
            self.open.cur_impl_assoc.clear();
            let _ = &sname;
            let new: syn::ItemImpl = syn::parse_quote!(impl #self_ty { #(#fns)* });
            out.push(syn::Item::Impl(new));
        }
        out
    }

    /// Lifts one function (a method when `self_ty` is set). The result's
    /// first item is the function; loop helpers follow.
    fn lift_fn(&mut self, f: syn::ItemFn, sigma: HashMap<String, syn::Type>, self_ty: Option<syn::Type>, ghost: bool, rename: Option<String>) -> Vec<syn::Item> {
        self.lift_fn_b(f, sigma, self_ty, ghost, rename, &[])
    }

    fn lift_fn_b(&mut self, mut f: syn::ItemFn, sigma: HashMap<String, syn::Type>, self_ty: Option<syn::Type>, ghost: bool, rename: Option<String>, outer: &[GenericParam]) -> Vec<syn::Item> {
        let orig_name = match self_ty.as_ref().and_then(type_name).and_then(|n| {
            let base = n.split("__").next().unwrap_or(&n).to_string();
            self.structs.contains_key(&base).then_some(base)
        }) {
            Some(owner) => format!("{owner}::{}", f.sig.ident),
            None => f.sig.ident.to_string(),
        };
        // `akey`: the full path attachments name it by
        let (orig_name, akey) = self.attach_key(&orig_name, self_ty.as_ref(), rename.as_deref(), ghost);
        let mut bounds: HashMap<String, Vec<String>> = outer.iter().map(|p| (p.name.clone(), p.bounds.clone())).collect();
        for p in self.generic_params(&f.sig.generics) {
            bounds.insert(p.name, p.bounds);
        }
        if !ghost {
            let lifted_name = rename.clone().unwrap_or_else(|| f.sig.ident.to_string());
            self.record_conform(&f, &sigma, self_ty.as_ref(), outer, &lifted_name);
        } else {
            self.conform_src_method = None;
        }
        if let Some(n) = rename {
            f.sig.ident = Ident::new(&n, f.sig.ident.span());
        }
        // type parameters read as the byte-string iterator model (`open::state_param`)
        let byte_iters = open::byte_iter_params(&f.sig.generics);
        f.sig.generics = syn::Generics::default();
        // `const fn`: the same function (constness only allows compile-time calls)
        f.sig.constness = None;
        // `-> impl Trait`: rustc's concrete type, the type of the
        // instance's return place
        if let syn::ReturnType::Type(_, t) = &f.sig.output
            && matches!(&**t, syn::Type::ImplTrait(_))
            && !ghost
            && let Some(ct) = self.mir_ret_ty(&f.sig.ident.to_string(), self_ty.as_ref())
        {
            f.sig.output = syn::parse_quote!(-> #ct);
        }
        // exec items keep docs and lint allowances (their other attributes are
        // host-only: `#[inline]`); ghost items keep their annotations
        f.attrs = if ghost { f.attrs.iter().filter(|a| !a.path().is_ident("lift_attach")).cloned().collect() } else { keep_fn_attrs(&f.attrs) };
        self.attach_sigma = sigma.clone();
        self.attach_bounds = bounds.clone();
        let impl_assoc = self.open.cur_impl_assoc.clone();
        let mut rw = FnRw::new(self, sigma, ghost);
        rw.bounds = bounds;
        rw.impl_assoc = impl_assoc;
        rw.self_ty = self_ty.clone();
        // parameters: types, states
        let mut new_inputs: syn::punctuated::Punctuated<syn::FnArg, syn::Token![,]> = syn::punctuated::Punctuated::new();
        rw.push_scope();
        for input in f.sig.inputs.iter() {
            match input {
                syn::FnArg::Receiver(r) => {
                    let st = self_ty.clone().unwrap_or_else(|| syn::parse_quote!(Self));
                    rw.recv_ref = r.reference.is_some();
                    if r.reference.is_some() && r.mutability.is_some() {
                        rw.states.push(("self".into(), st.clone()));
                        new_inputs.push(syn::parse_quote!(mut self));
                    } else if self_ty.as_ref().is_some_and(|t| type_name(t).is_some_and(|n| is_prim(&n))) {
                        // a sealed-trait method on a primitive: `self_` parameter
                        new_inputs.push(syn::parse_quote!(self_: #st));
                        rw.bind("self_", st.clone());
                    } else {
                        new_inputs.push(syn::parse_quote!(self));
                    }
                    // `&self` of a struct: `self` is a reference (`*self` is the builtin deref)
                    if r.reference.is_some() && r.mutability.is_none() && !rw.cx.open.instances.is_empty() && !self_ty.as_ref().is_some_and(|t| type_name(t).is_some_and(|n| is_prim(&n))) {
                        rw.bind("self", syn::parse_quote!(&#st));
                    } else {
                        rw.bind("self", st);
                    }
                }
                syn::FnArg::Typed(pt) => {
                    let mut pt = pt.clone();
                    let name = pat_ident(&pt.pat);
                    if let Some((mut sty, mut bty, marker)) = open::state_param(&pt.ty, &byte_iters) {
                        if !marker {
                            rw.ty(&mut sty);
                            rw.ty(&mut bty);
                        }
                        if let Some(n) = &name {
                            rw.states.push((n.clone(), sty.clone()));
                            rw.bind(n, bty);
                        }
                        let id = format_ident!("{}", name.clone().unwrap_or_else(|| "buf".into()));
                        new_inputs.push(syn::parse_quote!(mut #id: #sty));
                        continue;
                    }
                    rw.ty(&mut pt.ty);
                    if let Some(n) = &name {
                        rw.bind(n, (*pt.ty).clone());
                    }
                    new_inputs.push(syn::FnArg::Typed(pt));
                }
            }
        }
        f.sig.inputs = new_inputs;
        // return type
        let ret_ty: Option<syn::Type> = match &f.sig.output {
            syn::ReturnType::Default => None,
            syn::ReturnType::Type(_, t) => {
                let mut t = (**t).clone();
                rw.ty(&mut t);
                Some(t)
            }
        };
        rw.ret = ret_ty.clone();
        if !rw.states.is_empty() {
            let mut parts: Vec<syn::Type> = rw.states.iter().map(|(_, t)| t.clone()).collect();
            if let Some(r) = &ret_ty {
                parts.push(r.clone());
            }
            let t: syn::Type = if parts.len() == 1 { parts.remove(0) } else { syn::parse_quote!((#(#parts),*)) };
            f.sig.output = syn::parse_quote!(-> #t);
        } else if let Some(r) = &ret_ty {
            f.sig.output = syn::parse_quote!(-> #r);
        }
        // body: exec code from rustc's MIR (below); a ghost function's and a
        // host model's by the expression reading
        let use_mir = !ghost && !rw.cx.cur_host;
        let state_names: Vec<String> = rw.states.iter().map(|(n, _)| n.clone()).collect();
        let state_tys: Vec<(String, syn::Type)> = rw.states.clone();
        let mut block = (*f.block).clone();
        if !use_mir {
            annotate_index_literals(&mut block);
            rw.fn_body(&mut block);
        }
        // a ghost instance's expression attributes (`#[example(..)]`,
        // `#[decreases(..)]`) name the generic parameters too: rewrite them
        // like the body (else `T` would be unbound in every instance)
        if ghost {
            for a in f.attrs.iter_mut() {
                let is_expr_attr = a.path().is_ident("example") || a.path().is_ident("decreases") || a.path().is_ident("requires");
                if !is_expr_attr {
                    continue;
                }
                let syn::Meta::List(ml) = &a.meta else { continue };
                match syn::parse2::<syn::Expr>(ml.tokens.clone()) {
                    Ok(mut e) => {
                        rw.expr(&mut e, None);
                        let path = a.path().clone();
                        *a = syn::parse_quote!(#[#path(#e)]);
                    }
                    Err(err) => rw.cx.err(a.span(), format!("malformed attribute: {err}")),
                }
            }
        }
        rw.pop_scope();
        f.block = Box::new(block);
        drop(rw);
        let mut helpers = Vec::new();
        let mut mir_key: Option<String> = None;
        // the declared contract: the skeleton's attributes now, the
        // attachments' below (never what the reading of the body adds)
        let n_skeleton = f.attrs.len();
        if use_mir {
            // verified code is safe Rust (DESIGN.md §2, "No `unsafe`, for
            // good"): a body read from MIR is refused with an `unsafe` in it
            // (a block, an `unsafe fn` or `impl` inside, a macro's argument),
            // as the expression reading refuses an `unsafe` block
            if let Some(sp) = first_unsafe(f.block.to_token_stream()) {
                self.err(sp, "`unsafe` in a lifted function: verified code is safe Rust (DESIGN.md §2); code that needs `unsafe` stays unverified host code");
            }
            let n = self.mir_read.len();
            let (b, h) = self.mir_body(&mut f.sig, &akey, self_ty.as_ref(), &state_names, &state_tys);
            f.block = Box::new(b);
            helpers = h;
            mir_key = self.mir_read.get(n).map(|r| r.1.clone());
            // (`test_hook`: a structured reading that adds a precondition, which
            // the reading cannot do — it sees the signature only — so that the
            // statement's refusal of a precondition the contract lacks is tested)
            // (a private free function: a public one with a precondition is
            // refused at the boundary before any theorem)
            if test_hook::get() == Some(test_hook::WrongRule::ExtraRequires) && self.cur_impl.is_none() && matches!(f.vis, syn::Visibility::Inherited) {
                f.attrs.push(syn::parse_quote!(#[requires(true)]));
            }
        }
        let n_read = f.attrs.len();
        // `panic_lemma(path);` of a proof file: the panic walk's hints
        let mut panic_lemmas: Vec<(String, Span)> = Vec::new();
        if let Some(at) = self.attach_fn.get(&akey).cloned() {
            self.attach_used.insert(format!("fn {akey}"));
            let sigma2: HashMap<String, syn::Type> = self.attach_sigma.clone();
            // several `ensures(..)` (a law file's contract, a proof file's
            // summary) are proven as one: their conjunction, in file order,
            // is the `#[ensures]` (call sites get all of it); the contract —
            // what the lock holds and §15.5 determines — is the laws file's
            // part alone (`#[contract_ensures]`, DESIGN.md §15.6)
            let mut ensures: Vec<(syn::Expr, bool)> = Vec::new();
            // each statement as written (`#[lift_src]`: `SPEC.lock`'s source
            // text of the function, and the proof-file refusal)
            let mut srcs: Vec<syn::Attribute> = Vec::new();
            for (i, (st, &in_laws)) in at.stmts.iter().zip(&at.in_laws).enumerate() {
                // `at_start! { .. }`: proof steps before the body (facts about the parameters)
                if let syn::Stmt::Macro(m) = st
                    && m.mac.path.is_ident("at_start")
                {
                    let steps = match m.mac.parse_body_with(syn::Block::parse_within) {
                        Ok(v) => v,
                        Err(e) => {
                            self.err(m.span(), format!("malformed `at_start!`: {e}"));
                            continue;
                        }
                    };
                    let ab = self.attach_bounds.clone();
                    let mut rw = FnRw::new(self, sigma2.clone(), true);
                    rw.bounds = ab;
                    rw.self_ty = self_ty.clone();
                    let mut steps = steps;
                    for s2 in steps.iter_mut() {
                        rw.ghost_stmt(s2);
                    }
                    drop(rw);
                    let pf: syn::Stmt = syn::parse_quote!(proof! { #(#steps)* });
                    f.block.stmts.insert(0, pf);
                    continue;
                }
                // `opaque();`: callers are proven from the `ensures` only (the
                // function is opaque in proofs, DESIGN.md §5.6; `unfold(f)`
                // still reveals it). Hiding a definition never proves more.
                if attach_call0(st, "opaque") {
                    if f.attrs.iter().any(|a| a.path().is_ident("opaque")) {
                        self.err(st.span(), "`opaque();` twice for the same function");
                    }
                    f.attrs.push(syn::parse_quote!(#[opaque]));
                    continue;
                }
                // `requires(..);`: a precondition of the lifted function (at the
                // boundary a host obligation, listed; proven at every lifted call)
                if let Some(mut e) = attach_call(st, "requires") {
                    let ab = self.attach_bounds.clone();
                    let mut rw = FnRw::new(self, sigma2.clone(), true);
                    rw.bounds = ab;
                    rw.self_ty = self_ty.clone();
                    rw.expr(&mut e, None);
                    drop(rw);
                    self.open.host_obligations.push((orig_name.clone(), attach_call(st, "requires").map(|x| x.to_token_stream().to_string()).unwrap_or_default()));
                    f.attrs.push(syn::parse_quote!(#[requires(#e)]));
                    srcs.push(at.src_attr(i, "requires"));
                    continue;
                }
                // `panic_lemma(path);`: a lemma of the proof files whose
                // `ensures` the panic theorem's walk uses as facts (an
                // untrusted hint, `LiftFacts::panic_lemmas`): what the panic
                // condition means in the code's own terms (`1 << h` for
                // `2^h`), proven like any lemma
                if let Some(e) = attach_call(st, "panic_lemma") {
                    if in_laws {
                        self.err(st.span(), "`panic_lemma(..);` is a proof step: attach it from a proof file (the laws file states the panic contract, `panics_when(..);`)");
                        continue;
                    }
                    let syn::Expr::Path(p) = &e else {
                        self.err(st.span(), "`panic_lemma(..);` names a lemma by its path (`panic_lemma(crate::proof::f_panics);`)");
                        continue;
                    };
                    let path = p.path.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().join("::");
                    panic_lemmas.push((path, at.spans[i]));
                    continue;
                }
                // `panics_when(p);`: the panic contract (DESIGN.md §16.5,
                // docs/mir-lift.md §20.5): on the domain the function panics
                // exactly when `p` holds. Its no-panic clause `!(p)` becomes
                // the last precondition (`typeck`); the gate wants the panic
                // theorem too. Only the laws file states one (it is locked),
                // and only of a function read from MIR
                if let Some(mut e) = attach_call(st, "panics_when") {
                    if !in_laws {
                        self.err(st.span(), "`panics_when(..);` is attached from a proof file: a panic contract is part of the locked contract, which only the laws file states (DESIGN.md §15.6)");
                        continue;
                    }
                    if !use_mir {
                        self.err(st.span(), "`panics_when(..);` is a contract of a lifted function read from rustc's MIR: the panic theorem is about its MIR (docs/mir-lift.md §20.5)");
                        continue;
                    }
                    if f.attrs.iter().any(|a| a.path().is_ident("panics_when")) {
                        self.err(st.span(), "`panics_when(..);` twice for the same function (state one condition, joined with `||`)");
                        continue;
                    }
                    let ab = self.attach_bounds.clone();
                    let mut rw = FnRw::new(self, sigma2.clone(), true);
                    rw.bounds = ab;
                    rw.self_ty = self_ty.clone();
                    rw.expr(&mut e, None);
                    drop(rw);
                    self.open.panic_contracts.push((orig_name.clone(), attach_call(st, "panics_when").map(|x| x.to_token_stream().to_string()).unwrap_or_default()));
                    f.attrs.push(syn::parse_quote!(#[panics_when(#e)]));
                    srcs.push(at.src_attr(i, "panics_when"));
                    continue;
                }
                // `decreases(e, max = C);`: the measure and depth bound of a
                // non-tail recursive function (DESIGN.md §3.7; checked like any)
                if let syn::Stmt::Expr(syn::Expr::Call(c), _) = st
                    && matches!(&*c.func, syn::Expr::Path(p) if p.path.is_ident("decreases"))
                    && !c.args.is_empty()
                {
                    let mut args: Vec<syn::Expr> = c.args.iter().cloned().collect();
                    let ab = self.attach_bounds.clone();
                    let mut rw = FnRw::new(self, sigma2.clone(), true);
                    rw.bounds = ab;
                    rw.self_ty = self_ty.clone();
                    rw.expr(&mut args[0], None);
                    drop(rw);
                    if f.attrs.iter().any(|a| a.path().is_ident("decreases")) {
                        self.errors.push((at.spans[i], "`decreases(..);` twice for the same function".into(), vec![]));
                    }
                    // a depth bound (`max = C`): at the boundary a stack-depth
                    // bound the host must meet (listed, like a precondition)
                    if let Some(max) = c.args.iter().skip(1).find_map(|a| match a {
                        syn::Expr::Assign(x) if matches!(&*x.left, syn::Expr::Path(p) if p.path.is_ident("max")) => Some(x.right.to_token_stream().to_string()),
                        _ => None,
                    }) {
                        self.open.host_depth_bounds.push((orig_name.clone(), format!("{} <= {max}", c.args[0].to_token_stream())));
                    }
                    f.attrs.push(syn::parse_quote!(#[decreases(#(#args),*)]));
                    srcs.push(at.src_attr(i, "decreases"));
                    continue;
                }
                let Some(mut e) = attach_call(st, "ensures") else {
                    self.errors.push((at.spans[i], "a function attachment holds `requires(..);`, `ensures(..);`, `panics_when(..);`, `decreases(..);`, `opaque();`, `panic_lemma(..);` and `at_start! { .. }` only".into(), vec![]));
                    continue;
                };
                let ab = self.attach_bounds.clone();
                let mut rw = FnRw::new(self, sigma2.clone(), true);
                rw.bounds = ab;
                rw.self_ty = self_ty.clone();
                rw.expr(&mut e, None);
                drop(rw);
                ensures.push((e, in_laws));
                srcs.push(at.src_attr(i, "ensures"));
            }
            match ensures_attrs(ensures) {
                Ok(attrs) => f.attrs.extend(attrs),
                Err(msg) => self.errors.push((at.span, msg, vec![])),
            }
            if !ghost {
                f.attrs.extend(srcs);
            }
        }
        // the declared contract (skeleton and attachments: the reading of
        // the body adds no attribute), carried apart (`hir::FnDef::declared`):
        // the elaborator refuses the function unless its preconditions are it
        if let Some(key) = mir_key {
            let declared: Vec<syn::Meta> = f.attrs[..n_skeleton].iter().chain(&f.attrs[n_read..]).filter(|a| a.path().is_ident("requires") || a.path().is_ident("decreases") || a.path().is_ident("panics_when")).map(|a| a.meta.clone()).collect();
            // (a panic contract's no-panic clause follows the `requires`:
            // its index among the preconditions)
            let n_requires = declared.iter().filter(|m| m.path().is_ident("requires")).count();
            let panic = declared.iter().any(|m| m.path().is_ident("panics_when")).then_some(n_requires);
            f.attrs.push(syn::parse_quote!(#[mir_contract(#(#declared),*)]));
            // (`test_hook`: a precondition changed after its declaration was carried)
            if test_hook::get() == Some(test_hook::WrongRule::ChangedRequires)
                && let Some(a) = f.attrs.iter_mut().find(|a| a.path().is_ident("requires"))
            {
                *a = syn::parse_quote!(#[requires(true)]);
            }
            let mp = self.conform_module_path();
            let global = match self_ty.as_ref().and_then(type_name) {
                Some(st) if !is_prim(&st) => format!("{mp}::{st}::{}", f.sig.ident),
                _ => format!("{mp}::{}", f.sig.ident),
            };
            if !panic_lemmas.is_empty() && panic.is_none() {
                self.errors.push((panic_lemmas[0].1, format!("`panic_lemma(..);` attached to `{global}`, which has no panic contract (`panics_when(..);` in the laws file)"), vec![]));
            }
            self.panic_lemmas.extend(panic_lemmas.drain(..).map(|(p, _)| (global.clone(), p)));
            self.mir_contracts.push(MirContract { global, key, panic });
        }
        if let Some((_, sp)) = panic_lemmas.first() {
            self.errors.push((*sp, "`panic_lemma(..);` is a hint for the panic theorem of a function read from rustc's MIR (docs/mir-lift.md §20.6)".into(), vec![]));
        }
        if !ghost {
            // loop helpers have no original: they are compared through the
            // function they were split from
            let mp = self.conform_module_path();
            for h in &helpers {
                if let syn::Item::Fn(hf) = h {
                    let method = hf.attrs.iter().any(|a| a.path().is_ident("lift_method"));
                    let lifted = match self_ty.as_ref() {
                        Some(t) if method => format!("{mp}::{}::{}", ty_key(t), hf.sig.ident),
                        _ => format!("{mp}::{}", hf.sig.ident),
                    };
                    self.conform_skipped.push(ConformSkip { module: self.cur_module.clone(), lifted, why: format!("a loop helper the lift split from `{orig_name}` (no original of its own: compared through `{orig_name}`)") });
                }
            }
        }
        let mut out = vec![syn::Item::Fn(f)];
        out.extend(helpers);
        out
    }

    /// The contract attributes of the constant function `name` (an
    /// associated constant the lift reads as `S__C()`) from its attachment:
    /// `ensures(..)` only (it has no parameters and no body to annotate).
    fn const_fn_contract(&mut self, name: &str, sigma: &HashMap<String, syn::Type>, self_ty: &syn::Type) -> Vec<syn::Attribute> {
        let key = self.attach_path(name);
        let Some(at) = self.attach_fn.get(&key).cloned() else { return vec![] };
        self.attach_used.insert(format!("fn {key}"));
        let mut ens = Vec::new();
        let mut srcs = Vec::new();
        for (i, (st, &in_laws)) in at.stmts.iter().zip(&at.in_laws).enumerate() {
            let Some(mut e) = attach_call(st, "ensures") else {
                self.errors.push((at.spans[i], "an attachment to a constant function (an associated constant) holds `ensures(..);` only".into(), vec![]));
                continue;
            };
            srcs.push(at.src_attr(i, "ensures"));
            let mut rw = FnRw::new(self, sigma.clone(), true);
            rw.self_ty = Some(self_ty.clone());
            rw.expr(&mut e, None);
            drop(rw);
            ens.push((e, in_laws));
        }
        match ensures_attrs(ens) {
            Ok(mut a) => {
                a.extend(srcs);
                a
            }
            Err(msg) => {
                self.errors.push((at.span, msg, vec![]));
                vec![]
            }
        }
    }

    /// The name attachments reach the function being lifted by
    /// (`orig_name`: `S::m` for a method of a lifted struct, else the source
    /// name). A function of an impl on a primitive (`impl From<Position> for
    /// u64`, `impl PartialEq<Location> for u64`, a sealed trait's method on
    /// `u16`) is keyed by its lifted name (`u64__from__Position`), so two
    /// such impls get separate contracts; its bare method name (`from`)
    /// still reaches it when nothing else answers to that name (refused
    /// otherwise, at the end of the lift: [`Ctx::ambiguous_attachments`]).
    /// Returns the name and the full path attachments name it by
    /// ([`Ctx::attach_path`]: `crate::m::u64__from__Position`).
    fn attach_key(&mut self, orig_name: &str, self_ty: Option<&syn::Type>, rename: Option<&str>, ghost: bool) -> (String, String) {
        if ghost {
            return (orig_name.to_string(), format!("{}::{orig_name}", self.conform_module_path()));
        }
        let prim = self_ty.and_then(type_name).is_some_and(|n| is_prim(&n));
        let lifted = rename.map(str::to_string).unwrap_or_else(|| orig_name.to_string());
        let lifted_full = self.attach_path(&lifted);
        if prim && rename.is_some() && (self.attach_fn.contains_key(&lifted_full) || self.attach_loop.keys().any(|(f, _)| *f == lifted_full)) {
            return (lifted, lifted_full);
        }
        let full = self.attach_path(orig_name);
        if prim || self_ty.is_none() {
            // the impl as written, trait arguments included: `impl
            // From<Position<F>>` and `impl From<Location<F>>` are two (a
            // bare `from` would give both one contract), while one trait's
            // impls on several primitives (a sealed `impl SPrim for i16`,
            // `for i32`, ..) are instances of one method, like a generic
            // function's, and share its attachment
            let owner = match (&self.cur_impl, prim) {
                (Some((t, _, ty)), true) => format!("impl {}", t.clone().unwrap_or_else(|| ty.clone())),
                _ => format!("fn {}::{orig_name}", self.conform_module_path()),
            };
            let path = format!("{}::{lifted}", self.conform_module_path());
            self.bare_candidates.entry(full.clone()).or_default().insert((owner, path));
        }
        (orig_name.to_string(), full)
    }

    /// A bare attachment name (`eq`) that reaches the functions of several
    /// impls on primitives (`u64 == Position`, `u64 == Location`): the
    /// attachment would give both one contract. Refused, naming them.
    fn ambiguous_attachments(&mut self) {
        let mut errs = Vec::new();
        for (k, cands) in &self.bare_candidates {
            let owners: std::collections::BTreeSet<&String> = cands.iter().map(|(o, _)| o).collect();
            if owners.len() < 2 || !owners.iter().any(|o| o.starts_with("impl ")) {
                continue;
            }
            let span = match (self.attach_fn.get(k), self.attach_loop.iter().find(|((f, _), _)| f == k)) {
                (Some(a), _) => a.span,
                (None, Some((_, a))) => a.span,
                (None, None) => continue,
            };
            let list: Vec<String> = cands.iter().map(|(o, p)| format!("`{p}` (`{o}`)")).collect();
            let first = cands.iter().find(|(o, _)| o.starts_with("impl ")).map(|(_, p)| p.clone()).unwrap_or_default();
            errs.push((
                span,
                format!("the attachment to `{k}` is ambiguous: `{k}` is a function of several impls on primitives, which get separate contracts: {}", list.join(", ")),
                vec![format!("attach to one by its lifted name, e.g. `#[lift_attach({first})]`")],
            ));
        }
        self.errors.extend(errs);
    }

    /// The DSL path of the module being emitted (`crate::varint`,
    /// `crate::merkle::mmr` for an in-place module).
    fn conform_module_path(&self) -> String {
        self.open.module_paths.get(&self.cur_module).cloned().unwrap_or_else(|| format!("crate::{}", self.cur_module))
    }

    /// The return type of a lifted function of a `#[lift(mir = ..)]` module
    /// as rustc has it (the instance's return place: the concrete type of an
    /// `impl Trait` result).
    fn mir_ret_ty(&self, ident: &str, self_ty: Option<&syn::Type>) -> Option<syn::Type> {
        let ld = self.cur_mir.clone()?;
        let lifted = match self_ty.and_then(type_name) {
            Some(st) if !is_prim(&st) => format!("{st}::{ident}"),
            _ => ident.to_string(),
        };
        let f = ld.m.fns.get(ld.by_lifted.get(&lifted)?)?;
        ld.names.current.replace(self.conform_module_path());
        crate::mir::read::Names::ty(&ld.names, &ld.m, &f.locals.first()?.0).ok()
    }

    /// The body of a lifted function of a `#[lift(mir = ..)]` module, read
    /// from rustc's MIR ([`crate::mir::read`]), with its loop helpers. `sig`
    /// is the lifted signature; parameters bound by `_` get a name. The
    /// structured reading sees the signature only, never the function's
    /// attributes: it cannot add to or change the declared contract, which
    /// alone states the theorem's preconditions (`mir::stmt`).
    fn mir_body(&mut self, sig: &mut syn::Signature, akey: &str, self_ty: Option<&syn::Type>, state_names: &[String], state_tys: &[(String, syn::Type)]) -> (syn::Block, Vec<syn::Item>) {
        let empty: syn::Block = syn::parse_quote!({ unreachable!() });
        let Some(ld) = self.cur_mir.clone() else { return (empty, vec![]) };
        let lifted = match self_ty.and_then(type_name) {
            Some(st) if !is_prim(&st) => format!("{st}::{}", sig.ident),
            _ => sig.ident.to_string(),
        };
        let Some(key) = ld.by_lifted.get(&lifted).cloned() else {
            self.err(sig.ident.span(), format!("MIR: rustc's MIR has no instance for the lifted function `{lifted}` (re-run the extraction, or the item is not extracted)"));
            return (empty, vec![]);
        };
        let mut params: Vec<String> = Vec::new();
        let mut states: Vec<usize> = Vec::new();
        for (i, a) in sig.inputs.iter_mut().enumerate() {
            match a {
                syn::FnArg::Receiver(_) => {
                    if state_names.iter().any(|n| n == "self") {
                        states.push(i);
                    }
                    params.push("self".into());
                }
                syn::FnArg::Typed(pt) => {
                    // a parameter bound by `_` keeps its pattern (the reading
                    // refuses to read it unless it is zero-sized)
                    let n = pat_ident(&pt.pat).unwrap_or_else(|| "_".to_string());
                    if state_names.contains(&n) {
                        states.push(i);
                    }
                    params.push(n);
                }
            }
        }
        let has_ret = {
            let out_parts = match &sig.output {
                syn::ReturnType::Default => 0,
                syn::ReturnType::Type(_, t) => match &**t {
                    syn::Type::Tuple(tt) if tt.elems.is_empty() => 0,
                    syn::Type::Tuple(tt) if !states.is_empty() => tt.elems.len(),
                    _ => 1,
                },
            };
            out_parts > states.len()
        };
        let out_ty: syn::Type = match &sig.output {
            syn::ReturnType::Default => syn::parse_quote!(()),
            syn::ReturnType::Type(_, t) => (**t).clone(),
        };
        // loop attachments, read by the lift's ghost reading with the MIR's locals typed
        ld.names.current.replace(self.conform_module_path());
        let locals = match crate::mir::read::root_locals(&ld.m, &ld.names, &key, &params) {
            Ok(l) => l,
            Err(e) => {
                self.err(sig.ident.span(), format!("MIR: {e}"));
                return (empty, vec![]);
            }
        };
        let mut loops: HashMap<usize, crate::mir::read::LoopAttach> = HashMap::new();
        // (loop attachments name the function by its full path, `akey`)
        let keys: Vec<usize> = self.attach_loop.keys().filter(|(fnm, _)| fnm == akey).map(|(_, k)| *k).collect();
        // a source name in a loop attachment denotes the variable in scope
        // at the loop (`let size = *size;` shadows the parameter)
        let scopes = crate::mir::read::loop_scopes(&ld.m, &key, &params).unwrap_or_default();
        for k in keys {
            let mut at = self.attach_loop[&(akey.to_string(), k)].clone();
            self.attach_used.insert(format!("loop {akey}#{k}"));
            if let Some(map) = scopes.get(k).filter(|m| !m.is_empty()) {
                at.stmts = at.stmts.iter().map(|st| rename_vars(st, map)).collect();
            }
            let la = self.mir_loop_attach(&at, &locals, self_ty, state_tys);
            loops.insert(k, la);
        }
        let ref_params: Vec<usize> = sig.inputs.iter().enumerate().filter(|(_, a)| matches!(a, syn::FnArg::Typed(pt) if matches!(&*pt.ty, syn::Type::Reference(_)))).map(|(i, _)| i).collect();
        let spec = crate::mir::read::Spec { key: &key, lifted_name: &lifted, params: params.clone(), states, has_ret, out_ty, loops, ref_params };
        match crate::mir::read::read(&ld.m, &ld.names, &spec) {
            Ok(o) => {
                // a parameter the body assigns is `mut` (it changes no meaning)
                for i in &o.assigned_params {
                    if let Some(syn::FnArg::Typed(pt)) = sig.inputs.iter_mut().nth(*i)
                        && let syn::Pat::Ident(pi) = &mut *pt.pat
                    {
                        pi.mutability = Some(Default::default());
                    }
                }
                self.mir_read.push((lifted.clone(), key.clone(), o.loops.clone()));
                let mp = self.conform_module_path();
                for h in &o.helper_info {
                    // a helper's global: in the impl (a method helper) or the module;
                    // a `while` loop's: under the function whose body holds it
                    let helper_global = |name: &str, method: bool| match self_ty.and_then(type_name) {
                        Some(st) if method && !is_prim(&st) => format!("{mp}::{st}::{name}"),
                        _ => format!("{mp}::{name}"),
                    };
                    let global = match &h.owner {
                        Some((o, m)) if h.while_loop => format!("{}::{}", helper_global(o, *m), h.name),
                        None if h.while_loop => format!("{mp}::{lifted}::{}", h.name),
                        _ => helper_global(&h.name, h.method),
                    };
                    self.mir_helpers.push(MirHelper { global, key: key.clone(), header: h.header, params: h.params.clone(), while_loop: h.while_loop, local_names: h.local_names.clone(), returns: h.returns.clone() });
                }
                (o.body, o.helpers)
            }
            Err(e) => {
                self.err(sig.ident.span(), e);
                (empty, vec![])
            }
        }
    }

    /// A loop attachment read by the lift's ghost reading (monomorphized
    /// like the function), for the MIR reading to place.
    fn mir_loop_attach(&mut self, at: &Attach, locals: &[(String, Option<syn::Type>)], self_ty: Option<&syn::Type>, state_tys: &[(String, syn::Type)]) -> crate::mir::read::LoopAttach {
        let sigma2 = self.attach_sigma.clone();
        let ab = self.attach_bounds.clone();
        let mut rw = FnRw::new(self, sigma2, true);
        rw.bounds = ab;
        rw.self_ty = self_ty.cloned();
        rw.push_scope();
        for (n, t) in locals {
            if let Some(t) = t {
                rw.bind(n, t.clone());
            }
        }
        for (n, t) in state_tys {
            let t2: syn::Type = if n == "self" { t.clone() } else { syn::parse_quote!(Seq<u8>) };
            rw.bind(n, t2);
        }
        let mut la = crate::mir::read::LoopAttach::default();
        for st in &at.stmts {
            if let Some(mut e) = attach_call(st, "decreases") {
                rw.expr(&mut e, None);
                la.decreases = Some(e);
            } else if let Some(mut e) = attach_call(st, "invariant") {
                rw.expr(&mut e, None);
                la.invariants.push(e);
            } else if let Some(mut e) = attach_call(st, "ensures") {
                rw.expr(&mut e, None);
                la.ensures.push(e);
            } else if let syn::Stmt::Macro(m) = st
                && (m.mac.path.is_ident("at_start") || m.mac.path.is_ident("at_end") || m.mac.path.is_ident("after_loop"))
            {
                match m.mac.parse_body_with(syn::Block::parse_within) {
                    Ok(mut v) => {
                        for s2 in v.iter_mut() {
                            rw.ghost_stmt(s2);
                        }
                        if m.mac.path.is_ident("at_start") {
                            la.at_start.extend(v);
                        } else if m.mac.path.is_ident("at_end") {
                            la.at_end.extend(v);
                        } else {
                            la.after.extend(v);
                        }
                    }
                    Err(e) => rw.cx.err(m.span(), format!("malformed `{}!`: {e}", m.mac.path.to_token_stream())),
                }
            } else {
                let mut s2 = st.clone();
                rw.ghost_stmt(&mut s2);
                la.steps.push(s2);
            }
        }
        rw.pop_scope();
        la
    }

    /// Records how the conformance harness calls the original of a lifted
    /// exec function ([`ConformEntry`]); `f` is the source function (before
    /// its signature is rewritten).
    fn record_conform(&mut self, f: &syn::ItemFn, sigma: &HashMap<String, syn::Type>, self_ty: Option<&syn::Type>, outer: &[GenericParam], lifted_name: &str) {
        let generic_args = |ps: &[GenericParam]| -> Vec<String> { ps.iter().filter_map(|p| sigma.get(&p.name)).map(ty_key).collect() };
        let own: Vec<GenericParam> = f.sig.generics.params.iter().filter_map(|p| match p {
            syn::GenericParam::Type(tp) => Some(GenericParam { name: tp.ident.to_string(), bounds: vec![] }),
            _ => None,
        }).collect();
        let method = self.conform_src_method.take().unwrap_or_else(|| f.sig.ident.to_string());
        let mp = self.conform_module_path();
        let (callee, lifted) = match (&self.cur_impl, self_ty) {
            // a sealed-trait, `From` or operator impl on a primitive: a free function of the module
            (Some((Some(tp), modpath, st)), Some(t)) if type_name(t).is_some_and(|n| is_prim(&n)) => (ConformCallee::Trait { modpath: modpath.clone(), self_ty: st.clone(), trait_path: tp.clone(), method }, format!("{mp}::{lifted_name}")),
            (Some((tp, modpath, st)), Some(t)) => {
                let inst = ty_key(t);
                let lifted = format!("{mp}::{inst}::{lifted_name}");
                match tp {
                    Some(tp) => (ConformCallee::Trait { modpath: modpath.clone(), self_ty: st.clone(), trait_path: tp.clone(), method }, lifted),
                    None => {
                        let base = type_name(t).map(|n| n.split("__").next().unwrap_or(&n).to_string()).unwrap_or_default();
                        (ConformCallee::Inherent { modpath: modpath.clone(), base, generics: generic_args(outer), method }, lifted)
                    }
                }
            }
            _ => (ConformCallee::Free { modpath: in_mod_path(&f.attrs), name: method, generics: generic_args(&own) }, format!("{mp}::{lifted_name}")),
        };
        // `-> impl Trait`: the original's result is opaque (the lifted
        // function returns its concrete type): only a panic region is
        // compared ([`ConformEntry::opaque_ret`])
        let opaque_ret = matches!(&f.sig.output, syn::ReturnType::Type(_, t) if matches!(&**t, syn::Type::ImplTrait(_)));
        // the state parameters of §19.10's table (`open::state_param`)
        let iters = open::byte_iter_params(&f.sig.generics);
        let state_pass = |t: &syn::Type| -> Option<ParamPass> {
            if state_kind(t).is_some() {
                return None;
            }
            let (st, _, marker) = open::state_param(t, &iters)?;
            Some(if marker {
                ParamPass::BytesIter
            } else if matches!(t, syn::Type::Path(_)) {
                ParamPass::OptVec
            } else if matches!(&st, syn::Type::Path(p) if p.path.segments.last().is_some_and(|x| x.ident == "Seq")) {
                ParamPass::VecMut
            } else {
                ParamPass::StateMut
            })
        };
        let params = f.sig.inputs.iter().map(|i| match i {
            syn::FnArg::Receiver(r) => match (&r.reference, r.mutability) {
                (Some(_), Some(_)) => ParamPass::MutRef,
                (Some(_), None) => ParamPass::Ref,
                (None, _) => ParamPass::Value,
            },
            syn::FnArg::Typed(pt) => match state_kind(&pt.ty).as_ref().and_then(type_name).as_deref() {
                Some("__Buf") => ParamPass::Buf,
                Some("__BufMut") => ParamPass::BufMut,
                _ if state_pass(&pt.ty).is_some() => state_pass(&pt.ty).unwrap_or(ParamPass::StateMut),
                _ if matches!(&*pt.ty, syn::Type::Reference(r) if r.mutability.is_some()) => ParamPass::MutRef,
                _ if matches!(&*pt.ty, syn::Type::Reference(_)) => ParamPass::Ref,
                _ => ParamPass::Value,
            },
        }).collect();
        let has_ret = !matches!(f.sig.output, syn::ReturnType::Default);
        self.conform.push(ConformEntry { module: self.cur_module.clone(), lifted, callee, params, has_ret, opaque_ret });
    }

    fn subst_ty(&self, t: &syn::Type, sigma: &HashMap<String, syn::Type>) -> syn::Type {
        let mut t = t.clone();
        let mut s = TySubst { sigma, cx: self };
        s.visit_type_mut(&mut t);
        t
    }
}

// ---------------------------------------------------------------------------
// function rewriting
// ---------------------------------------------------------------------------

/// The expression reading: the ghost language (laws, proofs, specs,
/// attachments; `ghost`), and the bodies that are not exec code read from
/// MIR — constant initializers and host models' functions. Generic
/// parameters are substituted by the instance (`sigma`), sealed-trait and
/// generic-family calls named by their lifted instances, state arguments
/// of calls (`v.write(&mut b)` in a law) passed and assigned back. It keeps
/// every reading the ghost language shared with the deleted body reading
/// (`docs/mir-lift.md` §20): `unwrap`, `checked_*().unwrap()`, `&a[..=j]`,
/// signed operations and casts, shift amounts and index literals typed,
/// `S::C`, `prim::m(a, ..)`, `as_ref` of a byte slice, a generic call's
/// instance from the enclosing one.
struct FnRw<'c> {
    cx: &'c mut Ctx,
    sigma: HashMap<String, syn::Type>,
    self_ty: Option<syn::Type>,
    ghost: bool,
    /// State parameters of the function's signature (`self` for `&mut
    /// self`, `&mut impl Buf(Mut)` params) and their lifted types.
    states: Vec<(String, syn::Type)>,
    ret: Option<syn::Type>,
    scopes: Vec<HashMap<String, syn::Type>>,
    fresh: usize,
    /// Sealed-trait bounds of the current item's generic parameters (source names).
    bounds: HashMap<String, Vec<String>>,
    /// The associated types of the enclosing impl (`Self::Item` ..).
    impl_assoc: HashMap<String, syn::Type>,
    /// The function's receiver is `&self`/`&mut self` (`*self` is then the
    /// builtin dereference of the reference: the lifted `self` itself).
    recv_ref: bool,
}

impl<'c> FnRw<'c> {
    fn new(cx: &'c mut Ctx, sigma: HashMap<String, syn::Type>, ghost: bool) -> FnRw<'c> {
        FnRw { cx, sigma, self_ty: None, ghost, states: vec![], ret: None, scopes: vec![HashMap::new()], fresh: 0, bounds: HashMap::new(), impl_assoc: HashMap::new(), recv_ref: false }
    }

    fn push_scope(&mut self) {
        self.scopes.push(HashMap::new());
    }
    fn pop_scope(&mut self) {
        self.scopes.pop();
    }
    fn bind(&mut self, n: &str, t: syn::Type) {
        self.scopes.last_mut().unwrap().insert(n.to_string(), t);
    }
    fn local_ty(&self, n: &str) -> Option<syn::Type> {
        self.scopes.iter().rev().find_map(|s| s.get(n).cloned())
    }
    fn fresh(&mut self, base: &str) -> Ident {
        self.fresh += 1;
        format_ident!("__{}{}", base, self.fresh)
    }

    // ----- types --------------------------------------------------------

    fn ty(&mut self, t: &mut syn::Type) {
        // `Self::Item`, `Self::Target`, `Self::Error`: the impl's associated types
        if !self.impl_assoc.is_empty() {
            let mut a = ReplaceSelfAssoc { assoc: &self.impl_assoc };
            a.visit_type_mut(t);
        }
        let mut s = TySubst { sigma: &self.sigma, cx: self.cx };
        s.visit_type_mut(t);
        // `S::X` for an associated type of an open trait's impl at its instance `S`
        if !self.cx.open.assoc_types.is_empty() {
            open::resolve_instance_assoc(t, &self.cx.open.assoc_types);
        }
        // `&mut impl Buf` etc. are handled at parameters; `Self` in a method on a primitive
        if let Some(st) = &self.self_ty {
            let mut r = ReplaceSelfTy { ty: st.clone() };
            r.visit_type_mut(t);
        }
    }

    // ----- statements and blocks -----------------------------------------

    /// A ghost function's or a host model's body (never exec code: that is
    /// read from MIR).
    fn fn_body(&mut self, b: &mut syn::Block) {
        self.push_scope();
        let n = b.stmts.len();
        for (i, st) in b.stmts.iter_mut().enumerate() {
            if i + 1 == n
                && let syn::Stmt::Expr(e, None) = st
            {
                let ret = self.ret.clone();
                self.expr(e, ret.as_ref());
                continue;
            }
            self.stmt(st);
        }
        self.pop_scope();
    }

    fn stmt(&mut self, st: &mut syn::Stmt) {
        match st {
            syn::Stmt::Local(l) => {
                // `let x = a.checked_sub(b).unwrap();` → `let x = a - b;`: both panic exactly
                // when `b > a` (the `Underflow` obligation), and are equal otherwise
                // (likewise `checked_add` → `+`, `checked_mul` → `*`: `Overflow`)
                if let Some(init) = &mut l.init
                    && init.diverge.is_none()
                    && let syn::Expr::MethodCall(mc) = &*init.expr
                    && mc.method == "unwrap"
                    && mc.args.is_empty()
                    && let syn::Expr::MethodCall(inner) = &*mc.receiver
                    && matches!(inner.method.to_string().as_str(), "checked_sub" | "checked_add" | "checked_mul")
                    && inner.args.len() == 1
                    && self.ty_of(&inner.receiver).is_some_and(|t| type_name(&t).is_some_and(|n| n.starts_with('u')))
                {
                    let src_ty = self.ty_of(&inner.receiver);
                    let mut a = (*inner.receiver).clone();
                    let mut b = inner.args[0].clone();
                    self.expr(&mut a, None);
                    self.expr(&mut b, None);
                    let e: syn::Expr = match inner.method.to_string().as_str() {
                        "checked_sub" => syn::parse_quote!(#a - #b),
                        "checked_add" => syn::parse_quote!(#a + #b),
                        _ => syn::parse_quote!(#a * #b),
                    };
                    init.expr = Box::new(e);
                    if let (Some(n), Some(t)) = (pat_ident(&l.pat), src_ty) {
                        self.bind(&n, t);
                    }
                    return;
                }
                // `let x = e.unwrap();` → `let Some(x) = e else { unreachable!() };` (the same
                // panic as an obligation; the rest of the block sees `e == Some(x)`)
                if let Some(init) = &mut l.init
                    && init.diverge.is_none()
                    && let syn::Expr::MethodCall(mc) = &*init.expr
                    && mc.method == "unwrap"
                    && mc.args.is_empty()
                    && matches!(l.pat, syn::Pat::Ident(_))
                {
                    let src_ty = self.ty_of(&init.expr);
                    let mut inner = (*mc.receiver).clone();
                    self.expr(&mut inner, None);
                    let pat = l.pat.clone();
                    let new: syn::Stmt = syn::parse_quote!(let Some(#pat) = #inner else { unreachable!() };);
                    *st = new;
                    if let (Some(n), Some(t)) = (pat_ident(&pat), src_ty) {
                        self.bind(&n, t);
                    }
                    return;
                }
                // the binding's type, read off the source initializer (before rewriting)
                let src_ty = l.init.as_ref().and_then(|i| self.ty_of(&i.expr));
                if let Some(init) = &mut l.init {
                    let annot = match &l.pat {
                        syn::Pat::Type(pt) => Some((*pt.ty).clone()),
                        _ => None,
                    };
                    self.expr(&mut init.expr, annot.as_ref());
                    if let Some((_, e)) = &mut init.diverge {
                        self.expr(e, None);
                    }
                }
                // types of bindings
                let ty = match &mut l.pat {
                    syn::Pat::Type(pt) => {
                        self.ty(&mut pt.ty);
                        Some((*pt.ty).clone())
                    }
                    _ => src_ty,
                };
                // a tuple (or tuple-struct) pattern: each binding gets its component's type
                if pat_ident(&l.pat).is_none() {
                    self.bind_pat(&l.pat, ty.as_ref());
                }
                if let (Some(n), Some(t)) = (pat_ident(&l.pat), ty) {
                    self.bind(&n, t);
                }
            }
            syn::Stmt::Expr(e, _) => self.expr(e, None),
            syn::Stmt::Item(i) => self.cx.err(i.span(), "items inside function bodies are not lifted"),
            syn::Stmt::Macro(m) => {
                let e: syn::Expr = syn::Expr::Macro(syn::ExprMacro { attrs: m.attrs.clone(), mac: m.mac.clone() });
                let mut e2 = e;
                self.expr(&mut e2, None);
                if let syn::Expr::Macro(em) = e2 {
                    m.mac = em.mac;
                } else {
                    *st = syn::Stmt::Expr(e2, Some(Default::default()));
                }
            }
        }
    }

    fn block(&mut self, b: &mut syn::Block) {
        self.push_scope();
        for st in b.stmts.iter_mut() {
            self.stmt(st);
        }
        self.pop_scope();
    }

    // ----- expressions ----------------------------------------------------

    fn expr(&mut self, e: &mut syn::Expr, expected: Option<&syn::Type>) {
        // operations on signed integers (two's complement bits, SEMANTICS.md §19.3)
        if let Some(new) = self.signed_rewrite(e) {
            *e = new;
            return;
        }
        // `*self` of a `&self` method: the lifted `self` (by value)
        if self.recv_ref
            && let syn::Expr::Unary(u) = &*e
            && matches!(u.op, syn::UnOp::Deref(_))
            && matches!(&*u.expr, syn::Expr::Path(p) if p.path.is_ident("self"))
        {
            *e = syn::parse_quote!(self);
            return;
        }
        // shapes rewritten as a whole first
        if let Some(new) = self.rewrite(e, expected) {
            *e = new;
            return;
        }
        match e {
            syn::Expr::Block(b) => self.block(&mut b.block),
            syn::Expr::Unsafe(u) => self.cx.err(u.span(), "`unsafe` blocks are not lifted"),
            syn::Expr::If(i) => {
                self.expr(&mut i.cond, None);
                self.block(&mut i.then_branch);
                if let Some((_, eb)) = &mut i.else_branch {
                    self.expr(eb, expected);
                }
            }
            syn::Expr::Let(l) => {
                // the scrutinee's type in source terms (a rewritten call may name
                // an instance the local typing does not know)
                let t0 = self.ty_of(&l.expr);
                self.expr(&mut l.expr, None);
                let t = t0.or_else(|| self.ty_of(&l.expr));
                self.bind_pat(&l.pat, t.as_ref());
            }
            syn::Expr::Match(m) => {
                let t0 = self.ty_of(&m.expr);
                self.expr(&mut m.expr, None);
                let t = t0.or_else(|| self.ty_of(&m.expr));
                for arm in m.arms.iter_mut() {
                    self.push_scope();
                    self.bind_pat(&arm.pat, t.as_ref());
                    if let Some((_, g)) = &mut arm.guard {
                        self.expr(g, None);
                    }
                    self.expr(&mut arm.body, expected);
                    self.pop_scope();
                }
            }
            syn::Expr::Assign(a) => {
                self.expr(&mut a.right, None);
                self.expr(&mut a.left, None);
            }
            syn::Expr::Binary(b) if self.ghost && matches!(b.op, syn::BinOp::Mul(_) | syn::BinOp::Add(_)) => {
                // ghost code: fold `2usize * 8` (a width after substitution) into a literal,
                // so a proof's case split names the same term as a normalized specification
                self.expr(&mut b.left, None);
                self.expr(&mut b.right, None);
                if let (Some((x, sx)), Some((y, sy))) = (lit_usize(&b.left), lit_usize(&b.right))
                    && (sx == "usize" || sy == "usize")
                    && (sx == "usize" || sx.is_empty())
                    && (sy == "usize" || sy.is_empty())
                {
                    let v = match b.op {
                        syn::BinOp::Mul(_) => x.checked_mul(y),
                        _ => x.checked_add(y),
                    };
                    if let Some(v) = v {
                        let lit = syn::LitInt::new(&format!("{v}usize"), b.span());
                        *e = syn::parse_quote!(#lit);
                    }
                }
            }
            syn::Expr::Binary(b) => {
                self.expr(&mut b.left, None);
                // a shift amount literal typed by the operand's sealed-trait bound (`Shl<usize>`)
                if matches!(b.op, syn::BinOp::Shl(_) | syn::BinOp::Shr(_) | syn::BinOp::ShlAssign(_) | syn::BinOp::ShrAssign(_))
                    && is_unsuffixed_int(&b.right)
                {
                    // Rust types an unsuffixed amount by inference (`i32` by
                    // default); a shift means the same for any amount type,
                    // so the lift gives it `u32` unless a sealed bound says
                    // otherwise
                    let amt = self.shift_amount_ty(&b.left).unwrap_or_else(|| syn::parse_quote!(u32));
                    suffix_literal(&mut b.right, &amt);
                }
                self.expr(&mut b.right, None);
            }
            syn::Expr::Index(i) => {
                self.expr(&mut i.expr, None);
                self.expr(&mut i.index, None);
            }
            syn::Expr::Macro(m) => self.macro_expr(m),
            _ => {
                // generic traversal of the children
                let mut v = ChildVisitor { rw: self };
                syn::visit_mut::visit_expr_mut(&mut v, e);
            }
        }
    }

    /// Signed integers in the expression reading (SEMANTICS.md §19.3): an
    /// `iN` value is its two's complement bits, the prelude type
    /// `crate::__lift::IN(uN)` (the final [`SignedTypes`] pass renames the
    /// types). Exec code's signed operations are rustc's MIR, read by
    /// `mir::read`; here the ghost language's (and constants') are
    /// translated, and an operation on `IN` values that is not fails to
    /// type check (never a silent unsigned reading):
    ///
    /// | Rust (`x`, `y`: `iN`) | lifted |
    /// | --- | --- |
    /// | `5iN`, `-5iN` | `IN(5uN)`, `IN(<2^N - 5>uN)` |
    /// | `x << k` | `IN(x.0 << k)` (`k` an `iM`: its bits, so a negative amount is an overflow like Rust's) |
    /// | `x >> k` | `iN_shr(x, k as usize)` (arithmetic; `requires(k < N)`) |
    /// | `x ^ y`, `x & y`, `x \| y`, `!x` | the same on the bits |
    /// | `-x` | `iN_neg(x)` (`requires(x != MIN)`: Rust's panic) |
    /// | `x as uM` / `x as iM` (`M <= N`) | `x.0` / `(x.0 as uM)` / `IM(x.0 as uM)` |
    /// | `u as iN` (`u` unsigned, or an unsuffixed literal) | `IN(u as uN)` |
    /// | `x as Int` (ghost) | `int_of_iN(x)` |
    /// | `e as iN` (ghost, `e` an integer that is not unsigned) | `iN_of_int(e as Int)` |
    /// | `x == y`, `x != y` | structural (unchanged) |
    ///
    /// Refused: signed `+ - * / %`, comparisons, compound assignment,
    /// widening casts from a signed type (sign extension), and `as iN` of an
    /// operand the lift cannot type.
    fn signed_rewrite(&mut self, e: &mut syn::Expr) -> Option<syn::Expr> {
        let span = e.span();
        match e {
            syn::Expr::Lit(l) => {
                let syn::Lit::Int(i) = &l.lit else { return None };
                let n = signed_name_bits(i.suffix())?;
                let v: u128 = i.base10_parse().ok()?;
                Some(signed_lit(n, v, false, span, self))
            }
            syn::Expr::Unary(u) if matches!(u.op, syn::UnOp::Neg(_)) => {
                let t = self.ty_of(&u.expr)?;
                let n = signed_bits(&t)?;
                if let syn::Expr::Lit(l) = &*u.expr
                    && let syn::Lit::Int(i) = &l.lit
                    && let Ok(v) = i.base10_parse::<u128>()
                {
                    return Some(signed_lit(n, v, true, span, self));
                }
                let mut x = (*u.expr).clone();
                self.expr(&mut x, None);
                let f = format_ident!("i{}_neg", n);
                Some(syn::parse_quote_spanned!(span=> crate::__lift::#f(#x)))
            }
            syn::Expr::Unary(u) if matches!(u.op, syn::UnOp::Not(_)) => {
                let t = self.ty_of(&u.expr)?;
                let n = signed_bits(&t)?;
                let mut x = (*u.expr).clone();
                self.expr(&mut x, None);
                let c = signed_ctor(n);
                Some(syn::parse_quote_spanned!(span=> #c(!((#x).0))))
            }
            syn::Expr::Binary(b) => {
                let lt = self.ty_of(&b.left).and_then(|t| signed_bits(&t));
                let rt = self.ty_of(&b.right).and_then(|t| signed_bits(&t));
                if lt.is_none() && rt.is_none() {
                    return None;
                }
                use syn::BinOp as B;
                let (mut l, mut r) = ((*b.left).clone(), (*b.right).clone());
                match b.op {
                    B::Eq(_) | B::Ne(_) => None,
                    B::Shl(_) | B::Shr(_) => {
                        let unsuffixed = is_unsuffixed_int(&r);
                        self.expr(&mut l, None);
                        self.expr(&mut r, None);
                        // the amount: its bits when signed (a negative amount overflows, as in Rust)
                        let amt: syn::Expr = if rt.is_some() { syn::parse_quote!((#r).0) } else if unsuffixed { let mut r2 = r.clone(); suffix_literal(&mut r2, &syn::parse_quote!(u32)); r2 } else { r };
                        let Some(n) = lt else {
                            // an unsigned value shifted by a signed amount
                            return Some(match b.op {
                                B::Shl(_) => syn::parse_quote_spanned!(span=> (#l) << (#amt)),
                                _ => syn::parse_quote_spanned!(span=> (#l) >> (#amt)),
                            });
                        };
                        let c = signed_ctor(n);
                        Some(match b.op {
                            B::Shl(_) => syn::parse_quote_spanned!(span=> #c((#l).0 << (#amt))),
                            _ => {
                                let f = format_ident!("i{}_shr", n);
                                // a literal amount is written as a `usize` literal
                                // (the front end types a cast literal by its suffix)
                                let k: syn::Expr = match lit_usize(&amt) {
                                    Some((v, _)) => {
                                        let lit = syn::LitInt::new(&format!("{v}usize"), span);
                                        syn::parse_quote!(#lit)
                                    }
                                    None => syn::parse_quote!((#amt) as usize),
                                };
                                syn::parse_quote_spanned!(span=> crate::__lift::#f(#l, #k))
                            }
                        })
                    }
                    B::BitXor(_) | B::BitAnd(_) | B::BitOr(_) => {
                        let n = lt.or(rt)?;
                        if lt.is_some() && rt.is_some() && lt != rt {
                            self.cx.err(span, "a bit operation on signed integers of different widths is not lifted");
                            return None;
                        }
                        self.expr(&mut l, None);
                        self.expr(&mut r, None);
                        // an unsuffixed literal operand is a value of the other operand's type
                        let bits = |x: syn::Expr, known: bool| -> syn::Expr { if known { syn::parse_quote!((#x).0) } else { x } };
                        let (lb, rb) = (bits(l, lt.is_some()), bits(r, rt.is_some()));
                        let c = signed_ctor(n);
                        Some(match b.op {
                            B::BitXor(_) => syn::parse_quote_spanned!(span=> #c(#lb ^ #rb)),
                            B::BitAnd(_) => syn::parse_quote_spanned!(span=> #c(#lb & #rb)),
                            _ => syn::parse_quote_spanned!(span=> #c(#lb | #rb)),
                        })
                    }
                    ref op => {
                        self.cx.err(span, format!("the signed operation `{}` is not lifted (only `<< >> ^ & | ! ==` and unary `-` on signed integers, SEMANTICS.md §19.3)", op.to_token_stream()));
                        None
                    }
                }
            }
            syn::Expr::Cast(c) => {
                let dst = self.cx.subst_ty(&c.ty, &self.sigma);
                let src = self.ty_of(&c.expr);
                let sn = src.as_ref().and_then(signed_bits);
                let dn = signed_bits(&dst);
                if sn.is_none() && dn.is_none() {
                    return None;
                }
                let mut x = (*c.expr).clone();
                // ghost code: `e as iN` of an integer (an `Int`, a `Nat`, an
                // unsigned value, or an operand the lift does not type) is the
                // `iN` congruent to its value mod 2^N, as Rust's casts are
                // (a signed operand of unknown type fails to type check at
                // `as Int`, never read as unsigned)
                if let (None, Some(m)) = (sn, dn)
                    && self.ghost
                    && !src.as_ref().and_then(type_name).is_some_and(|t| uint_name_bits(&t).is_some())
                {
                    self.expr(&mut x, None);
                    let f = format_ident!("i{}_of_int", m);
                    return Some(syn::parse_quote_spanned!(span=> crate::__lift_model::#f((#x) as Int)));
                }
                self.expr(&mut x, None);
                let dname = type_name(&dst);
                match (sn, dname.as_deref()) {
                    (Some(n), Some("Int")) if self.ghost => {
                        let f = format_ident!("int_of_i{}", n);
                        Some(syn::parse_quote_spanned!(span=> crate::__lift_model::#f(#x)))
                    }
                    (Some(n), Some(d)) if uint_name_bits(d) == Some(n) => Some(syn::parse_quote_spanned!(span=> (#x).0)),
                    (Some(n), Some(d)) if uint_name_bits(d).is_some_and(|m| m < n) => Some(syn::parse_quote_spanned!(span=> ((#x).0 as #dst))),
                    // `x as iM` of a signed value, `M <= N`: its (low) bits
                    (Some(n), _) if dn.is_some_and(|m| m <= n) => {
                        let m = dn.unwrap_or(n);
                        let (um, cm) = (format_ident!("u{}", m), signed_ctor(m));
                        Some(if m == n { x } else { syn::parse_quote_spanned!(span=> #cm((#x).0 as #um)) })
                    }
                    // `u as iN` of an unsigned value: its bits (`IN(u as uN)`)
                    (None, _) if src.as_ref().and_then(type_name).is_some_and(|t| uint_name_bits(&t).is_some()) || is_unsuffixed_int(&x) => {
                        let m = dn.unwrap_or(0);
                        let (um, cm) = (format_ident!("u{}", m), signed_ctor(m));
                        Some(syn::parse_quote_spanned!(span=> #cm((#x) as #um)))
                    }
                    _ => {
                        self.cx.err(span, format!("the cast `as {}` of a signed integer is not lifted here (exec code's casts are rustc's MIR; SEMANTICS.md §19.3)", dst.to_token_stream()));
                        None
                    }
                }
            }
            _ => None,
        }
    }

    fn ghost_stmt(&mut self, st: &mut syn::Stmt) {
        if let syn::Stmt::Macro(m) = st
            && (m.mac.path.is_ident("at_start") || m.mac.path.is_ident("at_end") || m.mac.path.is_ident("after_loop"))
            && let Ok(mut v) = m.mac.parse_body_with(syn::Block::parse_within)
        {
            for s2 in v.iter_mut() {
                self.ghost_stmt(s2);
            }
            m.mac.tokens = quote!(#(#v)*);
            return;
        }
        match st {
            syn::Stmt::Expr(e, _) => self.expr(e, None),
            syn::Stmt::Local(l) => {
                if let Some(i) = &mut l.init {
                    self.expr(&mut i.expr, None);
                }
            }
            _ => {}
        }
    }

    fn macro_expr(&mut self, m: &mut syn::ExprMacro) {
        let name = m.mac.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
        match name.as_str() {
            "unreachable" | "proof" => {}
            "seq" | "hex" if self.ghost => {
                // rewrite the element expressions
                if let Ok(mut args) = m.mac.parse_body_with(syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated) {
                    for a in args.iter_mut() {
                        self.expr(a, None);
                    }
                    m.mac.tokens = args.to_token_stream();
                }
            }
            // proof syntax (`calc!`, ...) in ghost code: passed through unchanged
            _ if self.ghost => {}
            _ => self.cx.err(m.span(), format!("macro `{name}!` in a function body is not lifted")),
        }
    }

    fn bind_pat(&mut self, p: &syn::Pat, t: Option<&syn::Type>) {
        match p {
            syn::Pat::Ident(i) => {
                if let Some(t) = t {
                    self.bind(&i.ident.to_string(), t.clone());
                }
            }
            syn::Pat::TupleStruct(ts) => {
                let last = ts.path.segments.last().map(|s| s.ident.to_string()).unwrap_or_default();
                let inner = t.and_then(|t| match last.as_str() {
                    "Some" => generic_arg(t, "Option", 0),
                    "Ok" => generic_arg(t, "Result", 0),
                    "Err" => generic_arg(t, "Result", 1),
                    _ => None,
                });
                if ts.elems.len() == 1 {
                    self.bind_pat(&ts.elems[0], inner.as_ref());
                }
            }
            syn::Pat::Tuple(tp) => {
                if let Some(syn::Type::Tuple(tt)) = t {
                    for (p, t) in tp.elems.iter().zip(tt.elems.iter()) {
                        self.bind_pat(p, Some(t));
                    }
                }
            }
            syn::Pat::Type(pt) => self.bind_pat(&pt.pat, Some(&pt.ty)),
            _ => {}
        }
    }

    /// The amount type a sealed-trait bound forces on a shift of `lhs`.
    fn shift_amount_ty(&self, lhs: &syn::Expr) -> Option<syn::Type> {
        let t = self.ty_of(lhs)?;
        // `lhs` has the type of a generic parameter bounded by a sealed trait with `Shl<X>`/`ShrAssign<X>`
        // (the amount type of a literal changes no value, only which impl rustc selects)
        let k = ty_key(&t);
        let params: Vec<String> = self.sigma.iter().filter(|(_, v)| ty_key(v) == k).map(|(n, _)| n.clone()).collect();
        for n in params {
            let bounds = self.param_bounds(&n)?;
            if let Some(a) = bounds.iter().find_map(|b| self.cx.traits.get(b).and_then(|ti| ti.shift_amount.clone())) {
                return Some(a);
            }
        }
        None
    }

    /// Bounds of a generic parameter of the current item (by its source name).
    fn param_bounds(&self, n: &str) -> Option<Vec<String>> {
        if !self.sigma.contains_key(n) {
            return None;
        }
        self.bounds.get(n).cloned()
    }

    /// Whole-expression rewrites. Returns the replacement (already rewritten).
    fn rewrite(&mut self, e: &mut syn::Expr, expected: Option<&syn::Type>) -> Option<syn::Expr> {
        match e {
            syn::Expr::MethodCall(mc) => self.rewrite_method(mc, expected),
            syn::Expr::Call(c) => self.rewrite_call(c, expected),
            syn::Expr::Path(p) => self.rewrite_path(p),
            syn::Expr::Reference(r) => {
                // `&a[..=j]` → `&a[..j + 1]` (both panic exactly when `j + 1 > len`)
                if let syn::Expr::Index(ix) = &*r.expr
                    && let syn::Expr::Range(rg) = &*ix.index
                    && matches!(rg.limits, syn::RangeLimits::Closed(_))
                {
                    let mut base = (*ix.expr).clone();
                    self.expr(&mut base, None);
                    let mut from = rg.start.clone();
                    if let Some(f) = &mut from {
                        self.expr(f, None);
                    }
                    let mut end = rg.end.clone()?;
                    self.expr(&mut end, None);
                    return Some(match from {
                        Some(f) => syn::parse_quote!(&#base[#f..#end + 1]),
                        None => syn::parse_quote!(&#base[..#end + 1]),
                    });
                }
                None
            }
            _ => None,
        }
    }

    fn rewrite_path(&mut self, p: &syn::ExprPath) -> Option<syn::Expr> {
        let segs: Vec<String> = p.path.segments.iter().map(|s| s.ident.to_string()).collect();
        // `S::C` for an associated constant of an open-trait impl: `S__C` (`open`)
        if segs.len() >= 2 {
            let n = segs.len();
            let owner = if segs[n - 2] == "Self" { self.self_ty.as_ref().and_then(type_name).unwrap_or_default() } else { segs[n - 2].clone() };
            if self.cx.open.assoc_consts.contains(&(owner.clone(), segs[n - 1].clone())) {
                let mut path = p.path.clone();
                let last = path.segments.pop().unwrap().into_value();
                let mut prev = path.segments.pop().unwrap().into_value();
                let cname = open::const_name(&owner, &last.ident.to_string());
                prev.ident = Ident::new(&cname, last.ident.span());
                prev.arguments = syn::PathArguments::None;
                path.segments.push(prev);
                let pe = syn::Expr::Path(syn::ExprPath { attrs: p.attrs.clone(), qself: None, path });
                if self.cx.open.const_fns.contains(&cname) {
                    return Some(syn::parse_quote!(#pe()));
                }
                return Some(pe);
            }
        }
        // `T::SIZE` for a generic parameter (host `FixedSize`: `size_of::<T>()`, codec/src/types/primitives.rs)
        if segs.len() == 2 && segs[1] == "SIZE" && let Some(t) = self.sigma.get(&segs[0]) {
            let n = prim_size(t)?;
            if let Some(tn) = type_name(t) {
                self.cx.sizes.insert((tn, n));
            }
            let lit = syn::LitInt::new(&format!("{n}usize"), p.span());
            return Some(syn::parse_quote!(#lit));
        }
        // `self` in a sealed-trait method on a primitive
        None
    }

    fn rewrite_call(&mut self, c: &mut syn::ExprCall, expected: Option<&syn::Type>) -> Option<syn::Expr> {
        let syn::Expr::Path(fp) = &*c.func else { return None };
        let segs: Vec<(String, syn::PathArguments)> = fp.path.segments.iter().map(|s| (s.ident.to_string(), s.arguments.clone())).collect();
        let span = c.span();
        // size_of::<T>()
        if segs.last().is_some_and(|s| s.0 == "size_of") && c.args.is_empty() {
            if let syn::PathArguments::AngleBracketed(a) = &segs.last().unwrap().1
                && let Some(syn::GenericArgument::Type(t)) = a.args.first()
            {
                let t = self.cx.subst_ty(t, &self.sigma);
                if let Some(n) = prim_size(&t) {
                    let lit = syn::LitInt::new(&format!("{n}usize"), span);
                    return Some(syn::parse_quote!(#lit));
                }
            }
            self.cx.err(span, "`size_of` of a type the lift cannot size");
            return None;
        }
        // `P::m(a, ..)` with `P` a generic parameter
        if segs.len() == 2 && let Some(pt) = self.sigma.get(&segs[0].0).cloned() {
            let m = segs[1].0.clone();
            let p0 = segs[0].0.clone();
            // `T::from(x)` through the sealed trait's `From<X>` supertrait
            if m == "from" {
                let bounds = self.param_bounds(&p0).unwrap_or_default();
                let from = bounds.iter().find_map(|b| self.cx.traits.get(b).and_then(|t| t.from.clone()));
                let Some(x) = from else {
                    self.cx.err(span, format!("`{p0}::from` without a `From<..>` supertrait bound"));
                    return None;
                };
                let mut arg = c.args.first()?.clone();
                self.expr(&mut arg, Some(&x));
                if is_unsuffixed_int(&arg) {
                    suffix_literal(&mut arg, &x);
                }
                // `From<X> for Ty` on the primitive impl types is the lossless widening cast;
                // the typed `let` keeps typeck checking that the argument is an `X`
                if prim_size(&x).is_some_and(|a| prim_size(&pt).is_some_and(|b| a <= b)) && type_name(&x).is_some_and(|n| n.starts_with('u')) && type_name(&pt).is_some_and(|n| n.starts_with('u')) {
                    let f = self.fresh("f");
                    return Some(syn::parse_quote!({ let #f: #x = #arg; #f as #pt }));
                }
                self.cx.err(span, format!("`From<{}>` for `{}` is not a widening the lift knows", ty_key(&x), ty_key(&pt)));
                return Some(syn::parse_quote!(#pt::from(#arg)));
            }
            // a sealed-trait associated function `S::m(..)`
            if let Some(tr) = self.trait_with_method(&p0, &m) {
                let name = self.cx.trait_fn_path(&tr, &pt, &m, span);
                let sig = self.cx.traits[&tr].methods[&m].clone();
                let mut args: Vec<syn::Expr> = c.args.iter().cloned().collect();
                let ptys: Vec<Option<syn::Type>> = sig.inputs.iter().map(|i| match i {
                    syn::FnArg::Typed(t) => Some(self.assoc_subst(&t.ty, &tr, &pt)),
                    _ => None,
                }).collect();
                for (i, a) in args.iter_mut().enumerate() {
                    let exp = ptys.get(i).cloned().flatten();
                    self.expr(a, exp.as_ref());
                }
                return Some(syn::parse_quote!(#name(#(#args),*)));
            }
            self.cx.err(span, format!("`{p0}::{m}` is not a method of the parameter's sealed traits"));
            return None;
        }
        // a sealed-trait associated function of a primitive impl type, called
        // by its concrete type (per-width proofs): `i32::un_zigzag(v)`
        if segs.len() == 2
            && is_prim(&segs[0].0)
            && let Ok(pt) = syn::parse_str::<syn::Type>(&segs[0].0)
            && let Some(tr) = self.cx.traits.iter().find(|(tn, ti)| ti.sealed && ti.methods.contains_key(&segs[1].0) && self.cx.impl_of(tn, &pt).is_some()).map(|(tn, _)| tn.clone())
        {
            let m = segs[1].0.clone();
            let name = self.cx.trait_fn_path(&tr, &pt, &m, span);
            let sig = self.cx.traits[&tr].methods[&m].clone();
            let mut args: Vec<syn::Expr> = c.args.iter().cloned().collect();
            let ptys: Vec<Option<syn::Type>> = sig.inputs.iter().map(|i| match i {
                syn::FnArg::Typed(t) => Some(self.assoc_subst(&t.ty, &tr, &pt)),
                _ => None,
            }).collect();
            for (i, a) in args.iter_mut().enumerate() {
                let exp = ptys.get(i).cloned().flatten();
                self.expr(a, exp.as_ref());
            }
            return Some(syn::parse_quote!(#name(#(#args),*)));
        }
        // a primitive's method called as a path: `usize::max(a, b)` → `a.max(b)`
        if segs.len() == 2 && is_prim(&segs[0].0) && INHERENT_INT_METHODS.contains(&segs[1].0.as_str()) && !c.args.is_empty() {
            let prim: syn::Type = syn::parse_str(&segs[0].0).ok()?;
            let mut args: Vec<syn::Expr> = c.args.iter().cloned().collect();
            for a in args.iter_mut() {
                self.expr(a, Some(&prim));
                if is_unsuffixed_int(a) {
                    suffix_literal(a, &prim);
                }
            }
            let recv = args.remove(0);
            let m = format_ident!("{}", segs[1].0, span = span);
            return Some(syn::parse_quote!((#recv).#m(#(#args),*)));
        }
        // `UInt(x)`: a generic tuple struct's constructor, instance by its argument's type
        if segs.len() == 1
            && let Some(si) = self.cx.structs.get(&segs[0].0).cloned()
            && si.params.len() == 1
            && c.args.len() == 1
            && matches!(si.def.fields, syn::Fields::Unnamed(_))
        {
            let at = self.ty_of(&c.args[0]);
            let mut arg = c.args[0].clone();
            self.expr(&mut arg, None);
            let Some(at) = at else {
                self.cx.err(span, format!("cannot tell which instance of `{}` this constructor builds", segs[0].0));
                return None;
            };
            let inst = format_ident!("{}", mangle(&segs[0].0, &[at]), span = span);
            return Some(syn::parse_quote!(#inst(#arg)));
        }
        // a generic function (instance by turbofish, argument types or the expectation)
        let name = segs.last()?.0.clone();
        if let Some(fi) = self.cx.fns.get(&name).cloned() {
            if !fi.params.is_empty() || fn_states(&fi.sig).iter().any(|_| true) {
                return Some(self.call_family(fp, &fi, &segs, c.args.iter().cloned().collect(), expected, span));
            }
        }
        // `Type::<A>::m(..)` for a generic struct: rename the type
        if segs.len() >= 2 {
            let sname = segs[segs.len() - 2].0.clone();
            if let Some(si) = self.cx.structs.get(&sname).cloned()
                && !si.params.is_empty()
            {
                let targs = match &segs[segs.len() - 2].1 {
                    syn::PathArguments::AngleBracketed(a) => a.args.iter().filter_map(|x| match x {
                        syn::GenericArgument::Type(t) => Some(self.cx.subst_ty(t, &self.sigma)),
                        _ => None,
                    }).collect::<Vec<_>>(),
                    _ => vec![],
                };
                if targs.len() == si.params.len() {
                    let inst = format_ident!("{}", mangle(&sname, &targs), span = span);
                    let mname = segs.last().unwrap().0.clone();
                    let m = format_ident!("{}", mname, span = span);
                    let mut prefix: Vec<Ident> = fp.path.segments.iter().take(segs.len() - 2).map(|s| s.ident.clone()).collect();
                    prefix.push(inst);
                    prefix.push(m);
                    let mi = self.cx.methods.get(&(sname.clone(), mname)).cloned().unwrap_or_default();
                    let mut args: Vec<syn::Expr> = c.args.iter().cloned().collect();
                    let mut places = Vec::new();
                    let mut pre: Vec<syn::Stmt> = Vec::new();
                    for (i, a) in args.iter_mut().enumerate() {
                        if mi.state_params.contains(&i) {
                            let sty = mi.sig.clone().and_then(|sg| self.state_param_ty(&sg, i));
                            let place = self.state_arg_place_ty(a, &mut pre, sty);
                            places.push(place.clone());
                            *a = place;
                        } else {
                            self.expr(a, None);
                        }
                    }
                    let lead = fp.path.leading_colon;
                    let call: syn::Expr = syn::parse_quote!(#lead #(#prefix)::*(#(#args),*));
                    if places.is_empty() {
                        return Some(call);
                    }
                    let tmps: Vec<Ident> = places.iter().map(|_| self.fresh("s")).collect();
                    let has_ret = mi.sig.as_ref().is_some_and(|s| !matches!(s.output, syn::ReturnType::Default));
                    if has_ret {
                        let r = self.fresh("r");
                        return Some(syn::parse_quote!({ #(#pre)* let (#(#tmps,)* #r) = #call; #(#places = #tmps;)* #r }));
                    }
                    let t0 = &tmps[0];
                    let p0 = &places[0];
                    return Some(syn::parse_quote!({ #(#pre)* let #t0 = #call; #p0 = #t0; }));
                }
                self.cx.err(span, format!("`{sname}::..` needs its type arguments written (`{sname}::<T>::..`)"));
            }
        }
        None
    }

    /// The sealed trait (among `param`'s bounds) that declares method `m`.
    fn trait_with_method(&self, param: &str, m: &str) -> Option<String> {
        let bounds = self.param_bounds(param)?;
        bounds.into_iter().find(|b| self.cx.traits.get(b).is_some_and(|t| t.sealed && t.methods.contains_key(m)))
    }

    /// A trait method's parameter/result type at impl type `ty`: `Self` → `ty`,
    /// `Self::Assoc` → the impl's associated type.
    fn assoc_subst(&self, t: &syn::Type, tr: &str, ty: &syn::Type) -> syn::Type {
        let mut t = t.clone();
        let im = self.cx.impl_of(tr, ty).cloned();
        struct A<'a> {
            ty: &'a syn::Type,
            im: Option<ImplInfo>,
        }
        impl VisitMut for A<'_> {
            fn visit_type_mut(&mut self, t: &mut syn::Type) {
                if let syn::Type::Path(p) = t {
                    let segs: Vec<String> = p.path.segments.iter().map(|s| s.ident.to_string()).collect();
                    if segs.len() == 1 && segs[0] == "Self" {
                        *t = self.ty.clone();
                        return;
                    }
                    if segs.len() == 2 && segs[0] == "Self"
                        && let Some(im) = &self.im
                        && let Some(a) = im.assoc.get(&segs[1])
                    {
                        *t = a.clone();
                        return;
                    }
                }
                if let syn::Type::Reference(r) = t {
                    // `&self`-style shared references are values
                    let inner = (*r.elem).clone();
                    *t = inner;
                    self.visit_type_mut(t);
                    return;
                }
                syn::visit_mut::visit_type_mut(self, t);
            }
        }
        A { ty, im }.visit_type_mut(&mut t);
        t
    }

    /// A call of a generic family / a function with state parameters.
    fn call_family(&mut self, fp: &syn::ExprPath, fi: &FnInfo, segs: &[(String, syn::PathArguments)], mut args: Vec<syn::Expr>, expected: Option<&syn::Type>, span: PSpan) -> syn::Expr {
        let name = segs.last().unwrap().0.clone();
        let states = fn_states(&fi.sig);
        // instance
        let mut targs: Vec<Option<syn::Type>> = vec![None; fi.params.len()];
        if let syn::PathArguments::AngleBracketed(a) = &segs.last().unwrap().1 {
            for (i, x) in a.args.iter().enumerate() {
                if let syn::GenericArgument::Type(t) = x
                    && i < targs.len()
                {
                    targs[i] = Some(self.cx.subst_ty(t, &self.sigma));
                }
            }
        }
        let param_tys: Vec<Option<syn::Type>> = fi.sig.inputs.iter().map(|i| match i {
            syn::FnArg::Typed(t) => Some((*t.ty).clone()),
            _ => None,
        }).collect();
        let pnames: Vec<String> = fi.params.iter().map(|p| p.name.clone()).collect();
        // from argument types
        for (i, a) in args.iter().enumerate() {
            if states.contains(&i) {
                continue;
            }
            if let (Some(Some(pt)), Some(at)) = (param_tys.get(i), self.ty_of(a)) {
                unify_names(pt, &at, &pnames, &mut targs);
            }
        }
        // from the expected result
        if targs.iter().any(|t| t.is_none())
            && let (Some(exp), syn::ReturnType::Type(_, rt)) = (expected, &fi.sig.output)
        {
            unify_names(rt, exp, &pnames, &mut targs);
        }
        // from the enclosing instance: a parameter with the same sealed bound
        for (i, p) in fi.params.iter().enumerate() {
            if targs[i].is_some() {
                continue;
            }
            let cands: Vec<syn::Type> = self.sigma.iter().filter(|(n, t)| {
                self.param_bounds(n).is_some_and(|bs| bs.iter().any(|b| p.bounds.contains(b))) && self.cx.impl_types(&p.bounds[0]).iter().any(|x| ty_key(x) == ty_key(t))
            }).map(|(_, t)| t.clone()).collect();
            if cands.len() == 1 {
                targs[i] = Some(cands[0].clone());
            }
        }
        let inst_name = if fi.params.is_empty() {
            name.clone()
        } else if targs.iter().all(|t| t.is_some()) {
            let ts: Vec<syn::Type> = targs.iter().map(|t| t.clone().unwrap()).collect();
            mangle(&name, &ts)
        } else {
            self.cx.err_note(span, format!("cannot tell which instance of `{name}` this call uses"), "write the type arguments (`f::<T>(..)`)");
            name.clone()
        };
        let sigma_callee: HashMap<String, syn::Type> = pnames.iter().cloned().zip(targs.iter().map(|t| t.clone().unwrap_or_else(|| syn::parse_quote!(()))) ).collect();
        // rewrite value arguments; state arguments are places
        let mut state_places: Vec<syn::Expr> = Vec::new();
        let mut pre: Vec<syn::Stmt> = Vec::new();
        for (i, a) in args.iter_mut().enumerate() {
            if states.contains(&i) {
                let sty = self.state_param_ty(&fi.sig, i);
                let place = self.state_arg_place_ty(a, &mut pre, sty);
                state_places.push(place.clone());
                *a = place;
                continue;
            }
            let exp = param_tys.get(i).cloned().flatten().map(|t| self.cx.subst_ty(&t, &sigma_callee));
            self.expr(a, exp.as_ref());
        }
        let mut path = fp.path.clone();
        if let Some(last) = path.segments.last_mut() {
            last.ident = Ident::new(&inst_name, last.ident.span());
            last.arguments = syn::PathArguments::None;
        }
        let lead = &path;
        if states.is_empty() {
            return syn::parse_quote!(#lead(#(#args),*));
        }
        let has_ret = !matches!(fi.sig.output, syn::ReturnType::Default);
        let tmps: Vec<Ident> = state_places.iter().map(|_| self.fresh("s")).collect();
        let places = &state_places;
        if has_ret {
            let r = self.fresh("r");
            syn::parse_quote!({ #(#pre)* let (#(#tmps,)* #r) = #lead(#(#args),*); #(#places = #tmps;)* #r })
        } else if tmps.len() == 1 {
            let t = &tmps[0];
            let p = &places[0];
            syn::parse_quote!({ #(#pre)* let #t = #lead(#(#args),*); #p = #t; })
        } else {
            syn::parse_quote!({ #(#pre)* let (#(#tmps),*) = #lead(#(#args),*); #(#places = #tmps;)* })
        }
    }

    /// The model type of the `i`-th state parameter of `sig` (`open::state_param`).
    fn state_param_ty(&mut self, sig: &syn::Signature, i: usize) -> Option<syn::Type> {
        let iters = open::byte_iter_params(&sig.generics);
        let pt = sig.inputs.iter().filter_map(|x| match x {
            syn::FnArg::Typed(pt) => Some((*pt.ty).clone()),
            _ => None,
        }).nth(i)?;
        let (mut sty, _, marker) = open::state_param(&pt, &iters)?;
        if !marker {
            self.ty(&mut sty);
        }
        Some(sty)
    }

    fn state_arg_place_ty(&mut self, a: &syn::Expr, pre: &mut Vec<syn::Stmt>, ty: Option<syn::Type>) -> syn::Expr {
        let place = open::state_place(a);
        // a variable (or a field of one) is a place, whether or not the lift's
        // local typing knows its type (a copy would lose the write-back);
        // only `None`, a constant, a literal or another non-place expression
        // is a value, which Rust passes as `&mut <temporary>` too
        let is_place = matches!(&place, syn::Expr::Path(p) if p.qself.is_none() && p.path.get_ident().is_some_and(|i| i != "None" && !self.cx.consts.contains_key(&i.to_string()))) || matches!(&place, syn::Expr::Field(_));
        if is_place {
            return place;
        }
        let mut v = place;
        self.expr(&mut v, ty.as_ref());
        let t = self.fresh("tmp");
        match ty {
            Some(ty) => pre.push(syn::parse_quote!(let mut #t: #ty = #v;)),
            None => pre.push(syn::parse_quote!(let mut #t = #v;)),
        }
        syn::parse_quote!(#t)
    }

    fn rewrite_method(&mut self, mc: &mut syn::ExprMethodCall, expected: Option<&syn::Type>) -> Option<syn::Expr> {
        let m = mc.method.to_string();
        let span = mc.span();
        let recv_name = match &*mc.receiver {
            syn::Expr::Path(p) => p.path.get_ident().map(|i| i.to_string()),
            _ => None,
        };
        let recv_ty = self.ty_of(&mc.receiver);
        // `b.as_ref()` of a byte slice (`<[u8] as AsRef<[u8]>>::as_ref`,
        // through the reference): the slice itself
        if m == "as_ref"
            && mc.args.is_empty()
            && recv_ty.as_ref().is_some_and(is_byte_slice)
        {
            let mut r = (*mc.receiver).clone();
            self.expr(&mut r, None);
            return Some(r);
        }
        // `x.unwrap()` on `Option`: its panic is an obligation
        if m == "unwrap" && mc.args.is_empty() {
            let mut r = (*mc.receiver).clone();
            self.expr(&mut r, None);
            let v = self.fresh("v");
            return Some(syn::parse_quote!(match #r { Some(#v) => #v, None => unreachable!() }));
        }
        // a `&mut self` method of a lifted struct
        if let Some(t) = &recv_ty
            && let Some(sn) = type_name(t)
            && let Some(base) = self.struct_base_of(&sn)
            && let Some(mi) = self.cx.methods.get(&(base.clone(), m.clone())).cloned()
            && mi.mut_self
        {
            let Some(rn) = recv_name.clone() else {
                self.cx.err(span, "a `&mut self` method is lifted only on a local variable receiver");
                return None;
            };
            let recv = format_ident!("{}", rn);
            let mut args: Vec<syn::Expr> = mc.args.iter().cloned().collect();
            for a in args.iter_mut() {
                self.expr(a, None);
            }
            let tn: syn::Path = syn::parse_str(&sn).unwrap();
            let mid = &mc.method;
            let s = self.fresh("s");
            let has_ret = mi.sig.as_ref().is_some_and(|s| !matches!(s.output, syn::ReturnType::Default));
            if has_ret {
                let r = self.fresh("r");
                return Some(syn::parse_quote!({ let (#s, #r) = #tn::#mid(#recv, #(#args),*); #recv = #s; #r }));
            }
            return Some(syn::parse_quote!({ let #s = #tn::#mid(#recv, #(#args),*); #recv = #s; }));
        }
        // a sealed-trait method on a receiver of a parameter's type
        if let Some(t) = &recv_ty {
            let tk = ty_key(t);
            let owning: Vec<String> = self.cx.traits.iter().filter(|(_, ti)| ti.sealed && ti.methods.contains_key(&m)).map(|(n, _)| n.clone()).collect();
            for tr in owning {
                if self.cx.impl_of(&tr, t).is_some() && !INHERENT_INT_METHODS.contains(&m.as_str()) {
                    let name = self.cx.trait_fn_path(&tr, t, &m, span);
                    let mut r = (*mc.receiver).clone();
                    self.expr(&mut r, None);
                    let mut args: Vec<syn::Expr> = mc.args.iter().cloned().collect();
                    for a in args.iter_mut() {
                        self.expr(a, None);
                    }
                    return Some(syn::parse_quote!(#name(#r, #(#args),*)));
                }
            }
            let _ = tk;
        } else if self.cx.traits.values().any(|ti| ti.sealed && ti.methods.contains_key(&m)) && !INHERENT_INT_METHODS.contains(&m.as_str()) {
            self.cx.err(span, format!("cannot tell the receiver type of `.{m}()` (a sealed-trait method)"));
        }
        // host-trait methods of lifted structs with state parameters (`UInt(x).write(&mut buf)`)
        if let Some(t) = &recv_ty
            && let Some(sn) = type_name(t)
            && let Some(base) = self.struct_base_of(&sn)
            && let Some(mi) = self.cx.methods.get(&(base, m.clone())).cloned()
            && !mi.state_params.is_empty()
        {
            let mut r = (*mc.receiver).clone();
            self.expr(&mut r, None);
            let mut args: Vec<syn::Expr> = mc.args.iter().cloned().collect();
            let mut places = Vec::new();
            let mut pre: Vec<syn::Stmt> = Vec::new();
            for (i, a) in args.iter_mut().enumerate() {
                if mi.state_params.contains(&i) {
                    let sty = mi.sig.clone().and_then(|sg| self.state_param_ty(&sg, i));
                    let place = self.state_arg_place_ty(a, &mut pre, sty);
                    places.push(place.clone());
                    *a = place;
                } else {
                    self.expr(a, None);
                }
            }
            let mid = &mc.method;
            let tmps: Vec<Ident> = places.iter().map(|_| self.fresh("s")).collect();
            let has_ret = mi.sig.as_ref().is_some_and(|s| !matches!(s.output, syn::ReturnType::Default));
            if has_ret {
                let rr = self.fresh("r");
                return Some(syn::parse_quote!({ #(#pre)* let (#(#tmps,)* #rr) = (#r).#mid(#(#args),*); #(#places = #tmps;)* #rr }));
            }
            if tmps.len() == 1 {
                let t0 = &tmps[0];
                let p0 = &places[0];
                return Some(syn::parse_quote!({ #(#pre)* let #t0 = (#r).#mid(#(#args),*); #p0 = #t0; }));
            }
        }
        let _ = expected;
        None
    }

    /// The generic struct an instance name belongs to (`Decoder__u16` → `Decoder`).
    fn struct_base_of(&self, inst: &str) -> Option<String> {
        if self.cx.structs.contains_key(inst) {
            return Some(inst.to_string());
        }
        let base = inst.split("__").next()?;
        self.cx.structs.contains_key(base).then(|| base.to_string())
    }

    // ----- local typing -----------------------------------------------------

    /// The (lifted) type of an expression, when the lift can tell.
    fn ty_of(&self, e: &syn::Expr) -> Option<syn::Type> {
        let t = self.ty_of_src(e)?;
        Some(self.cx.subst_ty(&t, &self.sigma))
    }

    /// The type of an expression in source terms (generic parameters kept
    /// where the source has them; `ty_of` substitutes).
    fn ty_of_src(&self, e: &syn::Expr) -> Option<syn::Type> {
        match e {
            syn::Expr::Paren(p) => self.ty_of_src(&p.expr),
            syn::Expr::Group(g) => self.ty_of_src(&g.expr),
            syn::Expr::Path(p) => {
                if let Some(id) = p.path.get_ident() {
                    let n = id.to_string();
                    if let Some(t) = self.local_ty(&n) {
                        return Some(t);
                    }
                    if let Some(t) = self.cx.consts.get(&n) {
                        return Some(t.clone());
                    }
                }
                let segs: Vec<String> = p.path.segments.iter().map(|s| s.ident.to_string()).collect();
                if segs.len() == 2 && segs[1] == "SIZE" {
                    return Some(syn::parse_quote!(usize));
                }
                // `u64::MAX`, `u64::MIN`, `u64::BITS`
                if segs.len() == 2 && is_prim(&segs[0]) {
                    match segs[1].as_str() {
                        "MAX" | "MIN" => return syn::parse_str(&segs[0]).ok(),
                        "BITS" => return Some(syn::parse_quote!(u32)),
                        _ => {}
                    }
                }
                // an associated constant of an open-trait impl (`S::C`, `S__C`; `open`)
                if segs.len() >= 2 {
                    let n = segs.len();
                    let owner = if segs[n - 2] == "Self" { self.self_ty.as_ref().and_then(type_name).unwrap_or_default() } else { segs[n - 2].clone() };
                    if let Some(t) = self.cx.consts.get(&open::const_name(&owner, &segs[n - 1])) {
                        return Some(t.clone());
                    }
                }
                if let Some(id) = segs.last()
                    && self.cx.open.assoc_consts.iter().any(|(o, c)| &open::const_name(o, c) == id)
                {
                    return self.cx.consts.get(id).cloned();
                }
                // `E::V`, a unit variant of a non-generic enum of the lifted sources
                if segs.len() >= 2 && self.cx.open.enums.contains(&segs[segs.len() - 2]) {
                    let id = format_ident!("{}", segs[segs.len() - 2]);
                    return Some(syn::parse_quote!(#id));
                }
                None
            }
            syn::Expr::Lit(l) => match &l.lit {
                syn::Lit::Int(i) if !i.suffix().is_empty() => syn::parse_str(i.suffix()).ok(),
                syn::Lit::Bool(_) => Some(syn::parse_quote!(bool)),
                _ => None,
            },
            syn::Expr::Cast(c) => Some((*c.ty).clone()),
            syn::Expr::Unary(u) => match u.op {
                syn::UnOp::Neg(_) | syn::UnOp::Not(_) => self.ty_of_src(&u.expr),
                syn::UnOp::Deref(_) => {
                    let t = self.ty_of_src(&u.expr)?;
                    // `*x` of a struct with a `Deref` impl: its target (`open`)
                    if !matches!(t, syn::Type::Reference(_))
                        && let Some(sn) = type_name(&t)
                        && let Some(target) = self.cx.open.deref.get(&sn)
                    {
                        return Some(target.clone());
                    }
                    Some(strip_refs(&t))
                }
                _ => None,
            },
            syn::Expr::Tuple(t) => {
                let tys: Option<Vec<syn::Type>> = t.elems.iter().map(|e| self.ty_of_src(e)).collect();
                let tys = tys?;
                Some(syn::parse_quote!((#(#tys),*)))
            }
            syn::Expr::Reference(r) => self.ty_of_src(&r.expr),
            // a block: its tail expression (a `let` inside it is not typed here)
            syn::Expr::Block(b) => match b.block.stmts.last() {
                Some(syn::Stmt::Expr(e, None)) => self.ty_of_src(e),
                _ => None,
            },
            syn::Expr::Field(f) => {
                let bt = self.ty_of(&f.base)?;
                // `range.start`, `range.end` of the prelude's `Range<T>` (`open`)
                if let syn::Member::Named(n) = &f.member
                    && (n == "start" || n == "end")
                    && type_name(&strip_refs(&bt)).as_deref() == Some("Range")
                    && let Some(t) = generic_arg(&strip_refs(&bt), "Range", 0)
                {
                    return Some(t);
                }
                let sn = type_name(&bt)?;
                let base = self.struct_base_of(&sn)?;
                let si = self.cx.structs.get(&base)?.clone();
                // the instance's arguments: from the mangled name's suffixes
                let args = instance_args(&sn, &base);
                let sigma: HashMap<String, syn::Type> = si.params.iter().map(|p| p.name.clone()).zip(args).collect();
                let fty = match &f.member {
                    syn::Member::Named(n) => si.def.fields.iter().find(|x| x.ident.as_ref() == Some(n)).map(|x| x.ty.clone()),
                    syn::Member::Unnamed(i) => si.def.fields.iter().nth(i.index as usize).map(|x| x.ty.clone()),
                }?;
                Some(self.cx.subst_ty(&fty, &sigma))
            }
            syn::Expr::Try(t) => {
                let it = self.ty_of(&t.expr)?;
                generic_arg(&it, "Result", 0).or_else(|| generic_arg(&it, "Option", 0))
            }
            syn::Expr::Binary(b) => match b.op {
                syn::BinOp::Eq(_) | syn::BinOp::Ne(_) | syn::BinOp::Lt(_) | syn::BinOp::Le(_) | syn::BinOp::Gt(_) | syn::BinOp::Ge(_) | syn::BinOp::And(_) | syn::BinOp::Or(_) => Some(syn::parse_quote!(bool)),
                // a shift has its left operand's type (never the amount's)
                syn::BinOp::Shl(_) | syn::BinOp::Shr(_) if !self.cx.open.instances.is_empty() => self.ty_of_src(&b.left),
                _ => self.ty_of_src(&b.left).or_else(|| self.ty_of_src(&b.right)),
            },
            syn::Expr::MethodCall(mc) => {
                let m = mc.method.to_string();
                let rt = self.ty_of(&mc.receiver);
                match m.as_str() {
                    "leading_zeros" | "trailing_zeros" | "count_ones" => return Some(syn::parse_quote!(u32)),
                    "checked_sub" | "checked_add" | "checked_mul" => {
                        let t = rt?;
                        return Some(syn::parse_quote!(Option<#t>));
                    }
                    "unwrap" => return rt.and_then(|t| generic_arg(&t, "Option", 0)),
                    // `b.as_ref()` of a byte slice: the slice
                    "as_ref" if mc.args.is_empty() && rt.as_ref().is_some_and(|t| is_byte_slice(t)) => return Some(syn::parse_quote!(&[u8])),
                    "div_ceil" | "max" | "min" | "wrapping_add" | "wrapping_sub" => return rt,
                    // `s.get(i)` of a slice: `Option<&T>`
                    "get" if mc.args.len() == 1 && rt.as_ref().is_some_and(|t| matches!(strip_refs(t), syn::Type::Slice(_))) => {
                        let syn::Type::Slice(sl) = strip_refs(rt.as_ref()?) else { return None };
                        let el = &*sl.elem;
                        return Some(syn::parse_quote!(Option<&#el>));
                    }
                    _ => {}
                }
                let t = rt?;
                // sealed-trait method
                for (tn, ti) in &self.cx.traits {
                    if let Some(sig) = ti.methods.get(&m)
                        && self.cx.impl_of(tn, &t).is_some()
                        && let syn::ReturnType::Type(_, r) = &sig.output
                    {
                        return Some(self.assoc_subst(r, tn, &t));
                    }
                }
                // lifted struct method
                let sn = type_name(&t)?;
                let base = self.struct_base_of(&sn)?;
                let mi = self.cx.methods.get(&(base.clone(), m))?;
                let sig = mi.sig.as_ref()?;
                let syn::ReturnType::Type(_, r) = &sig.output else { return Some(syn::parse_quote!(())) };
                let si = self.cx.structs.get(&base)?;
                let sigma: HashMap<String, syn::Type> = si.params.iter().map(|p| p.name.clone()).zip(instance_args(&sn, &base)).collect();
                let mut r = self.cx.subst_ty(r, &sigma);
                ReplaceSelfTy { ty: t.clone() }.visit_type_mut(&mut r);
                if !self.cx.open.instances.is_empty() {
                    ReplaceSelfAny { ty: strip_refs(&t) }.visit_type_mut(&mut r);
                }
                Some(r)
            }
            syn::Expr::Call(c) => {
                let syn::Expr::Path(fp) = &*c.func else { return None };
                let segs: Vec<(String, syn::PathArguments)> = fp.path.segments.iter().map(|s| (s.ident.to_string(), s.arguments.clone())).collect();
                // `UInt(x)`: a generic tuple struct's constructor, its argument's type
                if segs.len() == 1
                    && let Some(si) = self.cx.structs.get(&segs[0].0)
                    && si.params.len() == 1
                    && c.args.len() == 1
                {
                    let id = format_ident!("{}", segs[0].0);
                    if let Some(t) = self.ty_of_src(&c.args[0]) {
                        return Some(syn::parse_quote!(#id<#t>));
                    }
                }
                // `T::from(..)`
                if segs.len() == 2 && segs[1].0 == "from" {
                    return syn::parse_str(&segs[0].0).ok();
                }
                // a sealed-trait associated function `S::m(..)` / `i32::m(..)`: its declared result
                if segs.len() == 2 {
                    let pt: Option<syn::Type> = self.sigma.get(&segs[0].0).cloned().or_else(|| if is_prim(&segs[0].0) { syn::parse_str(&segs[0].0).ok() } else { None });
                    if let Some(pt) = pt
                        && let Some((tr, sig)) = self.cx.traits.iter().find(|(tn, ti)| ti.sealed && ti.methods.contains_key(&segs[1].0) && self.cx.impl_of(tn, &pt).is_some()).map(|(tn, ti)| (tn.clone(), ti.methods[&segs[1].0].clone()))
                        && let syn::ReturnType::Type(_, r) = &sig.output
                    {
                        let mut r = self.assoc_subst(r, &tr, &pt);
                        ReplaceSelfTy { ty: pt.clone() }.visit_type_mut(&mut r);
                        return Some(r);
                    }
                }
                // `Self::new()` / `Type::<A>::new()`
                if segs.len() >= 2 {
                    let tseg = &segs[segs.len() - 2];
                    let m = &segs[segs.len() - 1].0;
                    let (sname, targs): (String, Vec<syn::Type>) = if tseg.0 == "Self" {
                        let st = self.self_ty.clone()?;
                        let sn = type_name(&st)?;
                        let base = self.struct_base_of(&sn)?;
                        (base.clone(), instance_args(&sn, &base))
                    } else {
                        let targs = match &tseg.1 {
                            syn::PathArguments::AngleBracketed(a) => a.args.iter().filter_map(|x| match x {
                                syn::GenericArgument::Type(t) => Some(t.clone()),
                                _ => None,
                            }).collect(),
                            _ => vec![],
                        };
                        (tseg.0.clone(), targs)
                    };
                    let si = self.cx.structs.get(&sname)?;
                    let mi = self.cx.methods.get(&(sname.clone(), m.clone()))?;
                    let sig = mi.sig.as_ref()?;
                    let syn::ReturnType::Type(_, r) = &sig.output else { return None };
                    let r = (**r).clone();
                    if type_name(&r).as_deref() == Some("Self") {
                        if targs.is_empty() {
                            return syn::parse_str(&sname).ok();
                        }
                        return Some(syn::parse_quote!(#(#targs)*)).and_then(|_: syn::Type| {
                            let args = &targs;
                            let id = format_ident!("{}", sname);
                            Some(syn::parse_quote!(#id<#(#args),*>))
                        });
                    }
                    // `Self` inside the result (`Result<Self, Error>`): the instance
                    let mut r = r;
                    if !targs.is_empty() {
                        let id = format_ident!("{}", sname);
                        let inst: syn::Type = syn::parse_quote!(#id<#(#targs),*>);
                        ReplaceSelfAny { ty: inst }.visit_type_mut(&mut r);
                    }
                    let sigma: HashMap<String, syn::Type> = si.params.iter().map(|p| p.name.clone()).zip(targs).collect();
                    return Some(self.cx.subst_ty(&r, &sigma));
                }
                // a lifted fn: its declared result (generic parameters unsubstituted: heads only)
                let name = segs.last()?.0.clone();
                let fi = self.cx.fns.get(&name)?;
                match &fi.sig.output {
                    syn::ReturnType::Type(_, r) => Some((**r).clone()),
                    syn::ReturnType::Default => Some(syn::parse_quote!(())),
                }
            }
            _ => None,
        }
    }

}

/// Generic traversal that routes every child expression back through
/// [`FnRw::expr`].
struct ChildVisitor<'a, 'c> {
    rw: &'a mut FnRw<'c>,
}

impl VisitMut for ChildVisitor<'_, '_> {
    fn visit_expr_mut(&mut self, e: &mut syn::Expr) {
        self.rw.expr(e, None);
    }
    fn visit_block_mut(&mut self, b: &mut syn::Block) {
        self.rw.block(b);
    }
    fn visit_type_mut(&mut self, t: &mut syn::Type) {
        self.rw.ty(t);
    }
    fn visit_path_mut(&mut self, p: &mut syn::Path) {
        rename_generic_path(self.rw, p);
        syn::visit_mut::visit_path_mut(self, p);
    }
}

/// `Decoder::<T>` in expression/pattern paths → `Decoder__u16`; `UInt(..)` constructor calls keep their name
/// (their instance comes from the expected type) — handled at `map`.
fn rename_generic_path(rw: &mut FnRw<'_>, p: &mut syn::Path) {
    let n = p.segments.len();
    // a generic function named with its type arguments (`unfold(f::<T>)`): its instance
    if let Some(last) = p.segments.last_mut()
        && let Some(fi) = rw.cx.fns.get(&last.ident.to_string()).cloned()
        && !fi.params.is_empty()
        && let syn::PathArguments::AngleBracketed(a) = &last.arguments
    {
        let targs: Vec<syn::Type> = a.args.iter().filter_map(|x| match x {
            syn::GenericArgument::Type(t) => Some(rw.cx.subst_ty(t, &rw.sigma)),
            _ => None,
        }).collect();
        if targs.len() == fi.params.len() {
            last.ident = Ident::new(&mangle(&last.ident.to_string(), &targs), last.ident.span());
            last.arguments = syn::PathArguments::None;
        }
    }
    for i in 0..n {
        let name = p.segments[i].ident.to_string();
        let Some(si) = rw.cx.structs.get(&name).cloned() else { continue };
        if si.params.is_empty() {
            continue;
        }
        if let syn::PathArguments::AngleBracketed(a) = &p.segments[i].arguments {
            let targs: Vec<syn::Type> = a.args.iter().filter_map(|x| match x {
                syn::GenericArgument::Type(t) => Some(rw.cx.subst_ty(t, &rw.sigma)),
                _ => None,
            }).collect();
            if targs.len() == si.params.len() {
                p.segments[i].ident = Ident::new(&mangle(&name, &targs), p.segments[i].ident.span());
                p.segments[i].arguments = syn::PathArguments::None;
            }
        } else if n == 1 {
            // a bare constructor/type name: the instance of the enclosing substitution when unique
            let cands: Vec<syn::Type> = si.params.iter().filter_map(|pp| rw.sigma.get(&pp.name).cloned()).collect();
            if cands.len() == si.params.len() && !cands.is_empty() {
                p.segments[i].ident = Ident::new(&mangle(&name, &cands), p.segments[i].ident.span());
            }
        }
    }
}

/// Type substitution: generic parameters, generic struct instances,
/// associated types of sealed traits (`S::UnsignedEquivalent`), `&mut impl Buf(Mut)`.
struct TySubst<'a> {
    sigma: &'a HashMap<String, syn::Type>,
    cx: &'a Ctx,
}

impl VisitMut for TySubst<'_> {
    fn visit_type_mut(&mut self, t: &mut syn::Type) {
        match t {
            syn::Type::Path(p) if p.qself.is_none() => {
                let segs: Vec<String> = p.path.segments.iter().map(|s| s.ident.to_string()).collect();
                if segs.len() == 1 && let Some(c) = self.sigma.get(&segs[0]) {
                    *t = c.clone();
                    return;
                }
                if segs.len() == 2 && let Some(c) = self.sigma.get(&segs[0]).cloned() {
                    // an associated type of a sealed trait
                    for im in self.cx.impls.iter().filter(|i| ty_key(&i.self_ty) == ty_key(&c)) {
                        if let Some(a) = im.assoc.get(&segs[1]) {
                            *t = a.clone();
                            return;
                        }
                    }
                }
                // a generic struct instance
                syn::visit_mut::visit_type_mut(self, t);
                if let syn::Type::Path(p) = t
                    && let Some(last) = p.path.segments.last_mut()
                    && let Some(si) = self.cx.structs.get(&last.ident.to_string())
                    && !si.params.is_empty()
                    && let syn::PathArguments::AngleBracketed(a) = &last.arguments
                {
                    let targs: Vec<syn::Type> = a.args.iter().filter_map(|x| match x {
                        syn::GenericArgument::Type(t) => Some(t.clone()),
                        _ => None,
                    }).collect();
                    if targs.len() == si.params.len() {
                        last.ident = Ident::new(&mangle(&last.ident.to_string(), &targs), last.ident.span());
                        last.arguments = syn::PathArguments::None;
                    }
                }
            }
            syn::Type::Reference(r) if r.mutability.is_some() => {
                if let Some(k) = state_kind(t) {
                    let _ = k;
                    *t = syn::parse_quote!(Seq<u8>);
                } else {
                    syn::visit_mut::visit_type_mut(self, t);
                }
            }
            _ => syn::visit_mut::visit_type_mut(self, t),
        }
    }
}

/// `Self::A` → the enclosing impl's associated type `A`.
struct ReplaceSelfAssoc<'a> {
    assoc: &'a HashMap<String, syn::Type>,
}
impl VisitMut for ReplaceSelfAssoc<'_> {
    fn visit_type_mut(&mut self, t: &mut syn::Type) {
        if let syn::Type::Path(p) = t
            && p.qself.is_none()
            && p.path.segments.len() == 2
            && p.path.segments[0].ident == "Self"
            && let Some(a) = self.assoc.get(&p.path.segments[1].ident.to_string())
        {
            *t = a.clone();
            self.visit_type_mut(t);
            return;
        }
        syn::visit_mut::visit_type_mut(self, t);
    }
}

struct ReplaceSelfTy {
    ty: syn::Type,
}
impl VisitMut for ReplaceSelfTy {
    fn visit_type_mut(&mut self, t: &mut syn::Type) {
        if let syn::Type::Path(p) = t
            && p.path.is_ident("Self")
            && type_name(&self.ty).is_some_and(|n| is_prim(&n))
        {
            *t = self.ty.clone();
            return;
        }
        syn::visit_mut::visit_type_mut(self, t);
    }
}

/// `Self` → the given type (a lifted struct instance in a method's result).
struct ReplaceSelfAny {
    ty: syn::Type,
}
impl VisitMut for ReplaceSelfAny {
    fn visit_type_mut(&mut self, t: &mut syn::Type) {
        if let syn::Type::Path(p) = t
            && p.path.is_ident("Self")
        {
            *t = self.ty.clone();
            return;
        }
        syn::visit_mut::visit_type_mut(self, t);
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Inherent integer methods (rustc resolves these before trait methods).
const INHERENT_INT_METHODS: &[&str] = &[
    "leading_zeros", "trailing_zeros", "count_ones", "count_zeros", "max", "min", "checked_sub", "checked_add", "checked_mul", "checked_div",
    "wrapping_add", "wrapping_sub", "wrapping_mul", "wrapping_neg", "wrapping_shl", "wrapping_shr", "saturating_add", "saturating_sub", "saturating_mul",
    "rotate_left", "rotate_right", "swap_bytes", "to_be_bytes", "to_le_bytes", "pow", "is_power_of_two", "abs_diff", "div_ceil",
];

/// The width of a signed integer type the lift reads as bits (`i16`,
/// `i32`, `i64`, or the prelude's `crate::__lift::I16`.. after
/// [`SignedTypes`]), references stripped. `i8`, `i128` and `isize` are not
/// read (they stay signed, which the front end refuses).
fn signed_bits(t: &syn::Type) -> Option<u32> {
    match strip_refs(t) {
        syn::Type::Path(p) if p.qself.is_none() => {
            let segs: Vec<String> = p.path.segments.iter().map(|s| s.ident.to_string()).collect();
            match segs.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
                [n] => signed_name_bits(n),
                ["crate", "__lift", n] => match *n {
                    "I16" => Some(16),
                    "I32" => Some(32),
                    "I64" => Some(64),
                    _ => None,
                },
                _ => None,
            }
        }
        _ => None,
    }
}

fn signed_name_bits(n: &str) -> Option<u32> {
    match n {
        "i16" => Some(16),
        "i32" => Some(32),
        "i64" => Some(64),
        _ => None,
    }
}

fn uint_name_bits(n: &str) -> Option<u32> {
    match n {
        "u8" => Some(8),
        "u16" => Some(16),
        "u32" => Some(32),
        "u64" | "usize" => Some(64),
        _ => None,
    }
}

fn strip_refs(t: &syn::Type) -> syn::Type {
    match t {
        syn::Type::Reference(r) => strip_refs(&r.elem),
        syn::Type::Paren(p) => strip_refs(&p.elem),
        syn::Type::Group(g) => strip_refs(&g.elem),
        other => other.clone(),
    }
}

/// `crate::__lift::IN`.
fn signed_ctor(n: u32) -> syn::Path {
    let id = format_ident!("I{}", n);
    syn::parse_quote!(crate::__lift::#id)
}

/// The literal `v` (negated when `neg`) of `iN`: its bits.
fn signed_lit(n: u32, v: u128, neg: bool, span: PSpan, rw: &mut FnRw<'_>) -> syn::Expr {
    let half = 1u128 << (n - 1);
    if (!neg && v >= half) || (neg && v > half) {
        rw.cx.err(span, format!("the literal is out of range for `i{n}`"));
    }
    let bits = if neg && v != 0 { (1u128 << n) - v } else { v };
    let lit = syn::LitInt::new(&format!("{bits}u{n}"), span);
    let c = signed_ctor(n);
    syn::parse_quote_spanned!(span=> #c(#lit))
}

/// The final pass of a lifted module (SEMANTICS.md §19.3): `i16`/`i32`/`i64`
/// in types become the prelude's bit types `crate::__lift::I16`.. (every
/// operation on them was translated by `FnRw::signed_rewrite`; any other
/// fails to type check).
struct SignedTypes;
impl VisitMut for SignedTypes {
    fn visit_type_mut(&mut self, t: &mut syn::Type) {
        if let syn::Type::Path(p) = t
            && p.qself.is_none()
            && let Some(id) = p.path.get_ident()
            && let Some(n) = signed_name_bits(&id.to_string())
        {
            let c = signed_ctor(n);
            *t = syn::parse_quote!(#c);
            return;
        }
        syn::visit_mut::visit_type_mut(self, t);
    }
}

fn is_prim(n: &str) -> bool {
    matches!(n, "u8" | "u16" | "u32" | "u64" | "u128" | "usize" | "i8" | "i16" | "i32" | "i64" | "i128" | "isize" | "bool")
}

fn prim_size(t: &syn::Type) -> Option<u64> {
    Some(match type_name(t)?.as_str() {
        "u8" | "i8" | "bool" => 1,
        "u16" | "i16" => 2,
        "u32" | "i32" => 4,
        "u64" | "i64" | "usize" | "isize" => 8,
        "u128" | "i128" => 16,
        _ => return None,
    })
}

/// The inline module path of a `#[lift_in_mod(m)]`-marked item (outermost
/// first; empty at the top of the lifted file).
pub(super) fn in_mod_path(attrs: &[syn::Attribute]) -> Vec<String> {
    attrs.iter().filter(|a| a.path().is_ident("lift_in_mod")).filter_map(|a| a.parse_args::<Ident>().ok()).map(|i| i.to_string()).collect()
}

/// `t` with the generic parameter names of `sigma` replaced (no other
/// rewriting: the type as the source writes it for that instance).
fn subst_names(t: &syn::Type, sigma: &HashMap<String, syn::Type>) -> syn::Type {
    struct S<'a>(&'a HashMap<String, syn::Type>);
    impl VisitMut for S<'_> {
        fn visit_type_mut(&mut self, t: &mut syn::Type) {
            if let syn::Type::Path(p) = t
                && p.qself.is_none()
                && let Some(id) = p.path.get_ident()
                && let Some(r) = self.0.get(&id.to_string())
            {
                *t = r.clone();
                return;
            }
            syn::visit_mut::visit_type_mut(self, t);
        }
    }
    let mut t = t.clone();
    S(sigma).visit_type_mut(&mut t);
    t
}

/// `[u8]` or `&[u8]` (any number of references).
fn is_byte_slice(t: &syn::Type) -> bool {
    matches!(strip_refs(t), syn::Type::Slice(sl) if matches!(&*sl.elem, syn::Type::Path(p) if p.path.is_ident("u8")))
}

fn type_name(t: &syn::Type) -> Option<String> {
    match t {
        syn::Type::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()),
        syn::Type::Reference(r) => type_name(&r.elem),
        syn::Type::Paren(p) => type_name(&p.elem),
        syn::Type::Group(g) => type_name(&g.elem),
        _ => None,
    }
}

fn ty_key(t: &syn::Type) -> String {
    t.to_token_stream().to_string().replace(' ', "")
}

fn path_key(p: &syn::Path) -> String {
    p.to_token_stream().to_string().replace(' ', "")
}

fn sanitize(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect()
}

fn mangle(name: &str, args: &[syn::Type]) -> String {
    let mut s = name.to_string();
    for a in args {
        s.push_str("__");
        s.push_str(&sanitize(&ty_key(a)));
    }
    s
}

fn instance_args(inst: &str, base: &str) -> Vec<syn::Type> {
    let rest = inst.strip_prefix(base).unwrap_or("");
    rest.split("__").filter(|s| !s.is_empty()).filter_map(|s| syn::parse_str(s).ok()).collect()
}

fn trait_fn_name(tr: &str, ty: &syn::Type, m: &str) -> String {
    format!("{}__{}__{}", tr, sanitize(&ty_key(ty)), m)
}

impl Ctx {
    /// `crate::<module>::Trait__Ty__m`: the lifted function of a sealed-trait method.
    fn trait_fn_path(&self, tr: &str, ty: &syn::Type, m: &str, span: PSpan) -> syn::Path {
        let name = format_ident!("{}", trait_fn_name(tr, ty, m), span = span);
        match self.impl_of(tr, ty) {
            Some(im) => {
                let md = format_ident!("{}", im.module);
                syn::parse_quote!(crate::#md::#name)
            }
            None => syn::parse_quote!(#name),
        }
    }
}

fn generic_arg(t: &syn::Type, name: &str, i: usize) -> Option<syn::Type> {
    let syn::Type::Path(p) = t else { return None };
    let last = p.path.segments.last()?;
    if last.ident != name {
        return None;
    }
    let syn::PathArguments::AngleBracketed(a) = &last.arguments else { return None };
    a.args.iter().filter_map(|x| match x {
        syn::GenericArgument::Type(t) => Some(t.clone()),
        _ => None,
    }).nth(i)
}

fn unify_names(pat: &syn::Type, act: &syn::Type, names: &[String], out: &mut [Option<syn::Type>]) {
    match (pat, act) {
        (syn::Type::Path(p), _) if p.path.segments.len() == 1 && names.contains(&p.path.segments[0].ident.to_string()) && matches!(p.path.segments[0].arguments, syn::PathArguments::None) => {
            let i = names.iter().position(|n| p.path.segments[0].ident == n.as_str()).unwrap();
            if out[i].is_none() {
                out[i] = Some(act.clone());
            }
        }
        (syn::Type::Path(p), syn::Type::Path(q)) => {
            let (Some(a), Some(b)) = (p.path.segments.last(), q.path.segments.last()) else { return };
            if a.ident != b.ident {
                return;
            }
            if let (syn::PathArguments::AngleBracketed(x), syn::PathArguments::AngleBracketed(y)) = (&a.arguments, &b.arguments) {
                for (u, v) in x.args.iter().zip(y.args.iter()) {
                    if let (syn::GenericArgument::Type(u), syn::GenericArgument::Type(v)) = (u, v) {
                        unify_names(u, v, names, out);
                    }
                }
            }
        }
        (syn::Type::Reference(a), b) => unify_names(&a.elem, b, names, out),
        (syn::Type::Tuple(a), syn::Type::Tuple(b)) => {
            for (u, v) in a.elems.iter().zip(b.elems.iter()) {
                unify_names(u, v, names, out);
            }
        }
        _ => {}
    }
}

/// `&mut impl Buf` / `&mut impl BufMut`: the model marker type.
fn state_kind(t: &syn::Type) -> Option<syn::Type> {
    let syn::Type::Reference(r) = t else { return None };
    r.mutability?;
    let syn::Type::ImplTrait(it) = &*r.elem else { return None };
    for b in &it.bounds {
        if let syn::TypeParamBound::Trait(tb) = b {
            let n = tb.path.segments.last()?.ident.to_string();
            return match n.as_str() {
                "Buf" => Some(syn::parse_quote!(__Buf)),
                "BufMut" => Some(syn::parse_quote!(__BufMut)),
                _ => None,
            };
        }
    }
    None
}

/// Indices (receiver excluded) of the state parameters of a signature.
fn fn_states(sig: &syn::Signature) -> Vec<usize> {
    let iters = open::byte_iter_params(&sig.generics);
    let mut out = Vec::new();
    let mut i = 0;
    for input in &sig.inputs {
        match input {
            syn::FnArg::Receiver(_) => {}
            syn::FnArg::Typed(pt) => {
                if open::state_param(&pt.ty, &iters).is_some() {
                    out.push(i);
                }
                i += 1;
            }
        }
    }
    out
}

fn method_info(sig: &syn::Signature) -> MethodInfo {
    let mut_self = sig.inputs.iter().any(|i| matches!(i, syn::FnArg::Receiver(r) if r.reference.is_some() && r.mutability.is_some()));
    MethodInfo { mut_self, state_params: fn_states(sig), sig: Some(sig.clone()) }
}

fn pat_ident(p: &syn::Pat) -> Option<String> {
    match p {
        syn::Pat::Ident(i) => Some(i.ident.to_string()),
        syn::Pat::Type(t) => pat_ident(&t.pat),
        _ => None,
    }
}

fn is_unsuffixed_int(e: &syn::Expr) -> bool {
    matches!(e, syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(i), .. }) if i.suffix().is_empty())
}

fn suffix_literal(e: &mut syn::Expr, t: &syn::Type) {
    if let syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(i), .. }) = e
        && i.suffix().is_empty()
        && let Some(n) = type_name(t)
        && is_prim(&n)
    {
        *i = syn::LitInt::new(&format!("{}{}", i.base10_digits(), n), i.span());
    }
}

fn is_use_super_glob(u: &syn::ItemUse) -> bool {
    matches!(&u.tree, syn::UseTree::Path(p) if p.ident == "super" && matches!(&*p.tree, syn::UseTree::Glob(_)))
}

/// The derives of an item (`#[derive(A, B)]` → `["A", "B"]`).
fn derives_of(attrs: &[syn::Attribute]) -> Vec<String> {
    let mut out = Vec::new();
    for a in attrs.iter().filter(|a| a.path().is_ident("derive")) {
        if let Ok(list) = a.parse_args_with(syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated) {
            out.extend(list.iter().map(|p| p.segments.last().map(|s| s.ident.to_string()).unwrap_or_default()));
        }
    }
    out
}

fn keep_fn_attrs(attrs: &[syn::Attribute]) -> Vec<syn::Attribute> {
    attrs.iter().filter(|a| a.path().is_ident("doc") || a.path().is_ident("allow")).cloned().collect()
}

fn is_delegation(f: &syn::ImplItemFn, m: &str) -> bool {
    let [syn::Stmt::Expr(syn::Expr::MethodCall(mc), None)] = f.block.stmts.as_slice() else { return false };
    mc.method == m && matches!(&*mc.receiver, syn::Expr::Path(p) if p.path.is_ident("self")) && mc.args.is_empty() && f.sig.inputs.len() == 1
}

/// The contract attributes of a lifted function from its attached
/// `ensures(..)` (each with whether the laws file wrote it): `#[ensures(E)]`,
/// the conjunction of all of them in file order (proven; the fact at call
/// sites), and, when a proof file attached any, `#[contract_ensures(L)]` —
/// the conjunction of the laws file's alone — or `#[contract_ensures]` when
/// the laws file attached none. The contract (what `SPEC.lock` holds and
/// §15.5 determines) is `L`; the rest are proof-internal summaries
/// (DESIGN.md §15.6).
pub(crate) fn ensures_attrs(es: Vec<(syn::Expr, bool)>) -> Result<Vec<syn::Attribute>, String> {
    let summaries = es.iter().any(|(_, in_laws)| !in_laws);
    let laws: Vec<syn::Expr> = es.iter().filter(|(_, l)| *l).map(|(e, _)| e.clone()).collect();
    let mut out = Vec::new();
    if let Some(e) = conjoin_ensures(es.into_iter().map(|(e, _)| e).collect())? {
        out.push(syn::parse_quote!(#[ensures(#e)]));
    }
    if summaries {
        match conjoin_ensures(laws)? {
            Some(l) => out.push(syn::parse_quote!(#[contract_ensures(#l)])),
            None => out.push(syn::parse_quote!(#[contract_ensures])),
        }
    }
    Ok(out)
}

/// The conjunction of several attached `ensures(..)` of one function: the
/// same closure `|ret: T| a && b` when each binds the result with the same
/// pattern and type, `a && b` when none does (no result); anything else is
/// refused (the contracts are about different things).
fn conjoin_ensures(es: Vec<syn::Expr>) -> Result<Option<syn::Expr>, String> {
    let mut it = es.into_iter();
    let Some(first) = it.next() else { return Ok(None) };
    let rest: Vec<syn::Expr> = it.collect();
    if rest.is_empty() {
        return Ok(Some(first));
    }
    let binder = |e: &syn::Expr| -> Option<(String, syn::Expr)> {
        match e {
            syn::Expr::Closure(c) if c.inputs.len() == 1 => Some((c.inputs[0].to_token_stream().to_string(), (*c.body).clone())),
            _ => None,
        }
    };
    match binder(&first) {
        Some((pat, body)) => {
            let mut bodies = vec![body];
            for e in &rest {
                match binder(e) {
                    Some((p, b)) if p == pat => bodies.push(b),
                    _ => return Err(format!("the attached `ensures(..)` of one function must bind the result alike (`{pat}`) to be conjoined")),
                }
            }
            let syn::Expr::Closure(mut c) = first else { return Err("internal: not a closure".into()) };
            c.body = Box::new(syn::parse_quote!(#((#bodies))&&*));
            Ok(Some(syn::Expr::Closure(c)))
        }
        None => {
            if rest.iter().any(|e| binder(e).is_some()) {
                return Err("the attached `ensures(..)` of one function must all bind the result, or none".into());
            }
            let all: Vec<syn::Expr> = std::iter::once(first).chain(rest).collect();
            Ok(Some(syn::parse_quote!(#((#all))&&*)))
        }
    }
}

/// The span of the first `unsafe` written in `ts` (a function's body; a
/// raw identifier `r#unsafe` is no keyword).
fn first_unsafe(ts: TokenStream) -> Option<PSpan> {
    ts.into_iter().find_map(|t| match t {
        TokenTree::Ident(i) if i == "unsafe" => Some(i.span()),
        TokenTree::Group(g) => first_unsafe(g.stream()),
        _ => None,
    })
}

/// Whether `st` is the argument-less attachment statement `name();`.
fn attach_call0(st: &syn::Stmt, name: &str) -> bool {
    let syn::Stmt::Expr(syn::Expr::Call(c), _) = st else { return false };
    matches!(&*c.func, syn::Expr::Path(p) if p.path.is_ident(name)) && c.args.is_empty()
}

fn attach_call(st: &syn::Stmt, name: &str) -> Option<syn::Expr> {
    let syn::Stmt::Expr(syn::Expr::Call(c), _) = st else { return None };
    let syn::Expr::Path(p) = &*c.func else { return None };
    if !p.path.is_ident(name) || c.args.len() != 1 {
        return None;
    }
    Some(c.args[0].clone())
}

fn expr_usize(e: &syn::Expr) -> Option<usize> {
    match e {
        syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(i), .. }) => i.base10_parse().ok(),
        _ => None,
    }
}

fn item_attrs_of(item: &syn::Item) -> &[syn::Attribute] {
    match item {
        syn::Item::Const(i) => &i.attrs,
        syn::Item::Enum(i) => &i.attrs,
        syn::Item::Fn(i) => &i.attrs,
        syn::Item::Impl(i) => &i.attrs,
        syn::Item::Macro(i) => &i.attrs,
        syn::Item::Mod(i) => &i.attrs,
        syn::Item::Struct(i) => &i.attrs,
        syn::Item::Trait(i) => &i.attrs,
        syn::Item::Use(i) => &i.attrs,
        syn::Item::Type(i) => &i.attrs,
        _ => &[],
    }
}

/// Code the lift leaves out, by its `#[cfg(..)]`: test-only code
/// ([`is_test_only`]), and code behind a predicate that names a cargo
/// feature or `test` (`cfg(feature = "std")`, `cfg(any(test, feature =
/// ".."))`, `cfg(not(test))`): host code, compiled outside the crate's
/// tests in some build (DESIGN.md §15.5).
fn host_only(attrs: &[syn::Attribute]) -> Option<&'static str> {
    if is_test_only(attrs) {
        return Some("`#[cfg(test)]` (the crate's tests run against the emitted module)");
    }
    let preds: Vec<syn::Meta> = attrs.iter().filter_map(cfg_predicate).collect();
    if preds.iter().any(|p| cfg_names(p, "feature")) {
        return Some("behind a cargo feature (host-only support code, e.g. `arbitrary` fuzzing impls)");
    }
    if preds.iter().any(|p| cfg_names(p, "test")) {
        return Some("behind a `cfg` on `test` that builds outside the crate's tests also compile (host code)");
    }
    None
}

/// Compiled only for the crate's tests: a `#[cfg(test)]` or
/// `#[cfg(all(.., test, ..))]` (nested `all` included). Any other predicate
/// that mentions `test` — `not(test)`, `any(test, ..)` — or a feature named
/// like one (`feature = "test-utils"`) is compiled outside tests too.
fn is_test_only(attrs: &[syn::Attribute]) -> bool {
    fn implies_test(p: &syn::Meta) -> bool {
        match p {
            syn::Meta::Path(x) => x.is_ident("test"),
            syn::Meta::List(l) if l.path.is_ident("all") => cfg_args(l).iter().any(implies_test),
            _ => false,
        }
    }
    attrs.iter().filter_map(cfg_predicate).any(|p| implies_test(&p))
}

/// The predicate of a `#[cfg(..)]` attribute (`None` for another attribute;
/// rustc rejects a malformed one).
fn cfg_predicate(a: &syn::Attribute) -> Option<syn::Meta> {
    a.path().is_ident("cfg").then(|| a.parse_args::<syn::Meta>().ok()).flatten()
}

/// The arguments of `all(..)`, `any(..)`, `not(..)`.
fn cfg_args(l: &syn::MetaList) -> Vec<syn::Meta> {
    l.parse_args_with(syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated).map(|p| p.into_iter().collect()).unwrap_or_default()
}

/// The cfg predicate `p` names the option `key` (`test`, `feature = ".."`)
/// anywhere, under `all`, `any` or `not`.
fn cfg_names(p: &syn::Meta, key: &str) -> bool {
    match p {
        syn::Meta::Path(x) => x.is_ident(key),
        syn::Meta::NameValue(nv) => nv.path.is_ident(key),
        syn::Meta::List(l) => cfg_args(l).iter().any(|q| cfg_names(q, key)),
    }
}

/// What the host source of an in-place module declares that host code the
/// lift leaves out can call ([`crate::hir::HostAccess`], DESIGN.md §15.5):
/// its host child modules — the modules the lift leaves out (a `mod m;`
/// that is not a lifted child, a feature-gated module, a module an item
/// macro of another crate declares, `cfg_if!`), not `#[cfg(test)]` ones —
/// and its private free functions and private inherent methods, also those
/// of the inline modules the lift flattens into it. (`called` is filled
/// while the lift drops the left-out code, [`Ctx::note_left_out`].)
fn host_access_of(items: &[syn::Item], children: &[String]) -> crate::hir::HostAccess {
    fn walk(items: &[syn::Item], children: &[String], top: bool, a: &mut crate::hir::HostAccess) {
        for item in items {
            if is_test_only(item_attrs_of(item)) {
                continue;
            }
            let gated = host_only(item_attrs_of(item)).is_some();
            match item {
                syn::Item::Mod(m) if m.content.is_none() => {
                    if !(top && children.iter().any(|c| m.ident == c.as_str())) {
                        a.host_children.push(m.ident.to_string());
                    }
                }
                syn::Item::Mod(m) if gated => a.host_children.push(m.ident.to_string()),
                syn::Item::Mod(m) => {
                    if let Some((_, inner)) = &m.content {
                        walk(inner, children, false, a);
                    }
                }
                syn::Item::Macro(m) if m.mac.path.segments.len() >= 2 => {
                    // `cfg_if::cfg_if! { if #[cfg(feature = "std")] { pub mod full; } }`
                    fn mods(ts: TokenStream, out: &mut Vec<String>) {
                        let toks: Vec<proc_macro2::TokenTree> = ts.into_iter().collect();
                        for (i, t) in toks.iter().enumerate() {
                            match t {
                                proc_macro2::TokenTree::Ident(id) if id == "mod" => {
                                    if let Some(proc_macro2::TokenTree::Ident(n)) = toks.get(i + 1) {
                                        out.push(n.to_string());
                                    }
                                }
                                proc_macro2::TokenTree::Group(g) => mods(g.stream(), out),
                                _ => {}
                            }
                        }
                    }
                    mods(m.mac.tokens.clone(), &mut a.host_children);
                }
                syn::Item::Fn(f) if !gated && matches!(f.vis, syn::Visibility::Inherited) => {
                    a.private_fns.insert(f.sig.ident.to_string());
                }
                syn::Item::Impl(im) if !gated && im.trait_.is_none() => {
                    if let Some(tn) = type_name(&im.self_ty) {
                        for ii in &im.items {
                            if let syn::ImplItem::Fn(f) = ii
                                && matches!(f.vis, syn::Visibility::Inherited)
                            {
                                a.private_methods.insert(format!("{tn}::{}", f.sig.ident));
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    let mut a = crate::hir::HostAccess::default();
    walk(items, children, true, &mut a);
    a.host_children.sort();
    a.host_children.dedup();
    a
}

/// The names `ts` (code the lift leaves out) calls, for
/// [`crate::hir::HostAccess::called`]: an identifier applied to arguments
/// (`f(..)`, `x.m(..)`, `T::m(..)`), the segment after `::` or `.` (a path
/// or method used as a value, `map(Self::m)`), and every identifier inside
/// a macro call (`assert!(x.m())`): by name, an over-approximation.
fn host_called_names(ts: TokenStream, in_macro: bool, out: &mut std::collections::BTreeSet<String>) {
    let toks: Vec<proc_macro2::TokenTree> = ts.into_iter().collect();
    let punct = |i: usize, c: char| matches!(toks.get(i), Some(proc_macro2::TokenTree::Punct(p)) if p.as_char() == c);
    for (i, t) in toks.iter().enumerate() {
        match t {
            proc_macro2::TokenTree::Ident(id) => {
                let applied = matches!(toks.get(i + 1), Some(proc_macro2::TokenTree::Group(g)) if g.delimiter() == proc_macro2::Delimiter::Parenthesis);
                let after_sep = i >= 1 && (punct(i - 1, '.') || (i >= 2 && punct(i - 1, ':') && punct(i - 2, ':')));
                if in_macro || applied || after_sep {
                    out.insert(id.to_string());
                }
            }
            proc_macro2::TokenTree::Group(g) => {
                let macro_args = i >= 1 && punct(i - 1, '!');
                host_called_names(g.stream(), in_macro || macro_args, out);
            }
            _ => {}
        }
    }
}

fn describe(item: &syn::Item) -> String {
    match item {
        syn::Item::Mod(m) => format!("module `{}`", m.ident),
        syn::Item::Impl(im) => format!("impl for `{}`", im.self_ty.to_token_stream().to_string().replace(' ', "")),
        syn::Item::Fn(f) => format!("fn `{}`", f.sig.ident),
        other => format!("item at {:?}", other.span().start()),
    }
}

fn parse_items(ts: TokenStream) -> syn::Result<Vec<syn::Item>> {
    let p = |input: ParseStream| {
        let mut v = Vec::new();
        while !input.is_empty() {
            v.push(input.parse::<syn::Item>()?);
        }
        Ok(v)
    };
    p.parse2(ts)
}

// ---------------------------------------------------------------------------
// macro_rules (the subset used by item-generating macros)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum Matcher {
    Tok(TokenTree),
    Group(Delimiter, Vec<Matcher>),
    Var(String, String),
    Rep(Vec<Matcher>, Option<TokenTree>, char),
}

#[derive(Clone, Debug)]
struct MacroRule {
    matcher: Vec<Matcher>,
    body: TokenStream,
}

fn parse_macro_rules(ts: TokenStream) -> Result<Vec<MacroRule>, String> {
    let toks: Vec<TokenTree> = ts.into_iter().collect();
    let mut rules = Vec::new();
    let mut i = 0;
    while i < toks.len() {
        let TokenTree::Group(m) = &toks[i] else { return Err("expected a matcher group".into()) };
        i += 1;
        // `=>`
        match (&toks.get(i), &toks.get(i + 1)) {
            (Some(TokenTree::Punct(a)), Some(TokenTree::Punct(b))) if a.as_char() == '=' && b.as_char() == '>' => i += 2,
            _ => return Err("expected `=>`".into()),
        }
        let TokenTree::Group(body) = &toks[i] else { return Err("expected a transcriber group".into()) };
        i += 1;
        if let Some(TokenTree::Punct(p)) = toks.get(i)
            && p.as_char() == ';'
        {
            i += 1;
        }
        rules.push(MacroRule { matcher: parse_matcher(m.stream())?, body: body.stream() });
    }
    Ok(rules)
}

fn parse_matcher(ts: TokenStream) -> Result<Vec<Matcher>, String> {
    let toks: Vec<TokenTree> = ts.into_iter().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < toks.len() {
        match &toks[i] {
            TokenTree::Punct(p) if p.as_char() == '$' => {
                match toks.get(i + 1) {
                    Some(TokenTree::Ident(id)) => {
                        // `$x:frag`
                        let frag = match (toks.get(i + 2), toks.get(i + 3)) {
                            (Some(TokenTree::Punct(c)), Some(TokenTree::Ident(f))) if c.as_char() == ':' => f.to_string(),
                            _ => return Err(format!("`${id}` without a fragment specifier")),
                        };
                        out.push(Matcher::Var(id.to_string(), frag));
                        i += 4;
                    }
                    Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Parenthesis => {
                        let sub = parse_matcher(g.stream())?;
                        // separator and operator
                        let (sep, op, adv) = match (toks.get(i + 2), toks.get(i + 3)) {
                            (Some(TokenTree::Punct(o)), _) if matches!(o.as_char(), '*' | '+' | '?') => (None, o.as_char(), 3),
                            (Some(s), Some(TokenTree::Punct(o))) if matches!(o.as_char(), '*' | '+' | '?') => (Some(s.clone()), o.as_char(), 4),
                            _ => return Err("malformed repetition".into()),
                        };
                        out.push(Matcher::Rep(sub, sep, op));
                        i += adv;
                    }
                    _ => return Err("stray `$`".into()),
                }
            }
            TokenTree::Group(g) => {
                out.push(Matcher::Group(g.delimiter(), parse_matcher(g.stream())?));
                i += 1;
            }
            t => {
                out.push(Matcher::Tok(t.clone()));
                i += 1;
            }
        }
    }
    Ok(out)
}

#[derive(Clone, Debug)]
enum Binding {
    One(TokenStream),
    Many(Vec<HashMap<String, Binding>>),
}

fn expand(rules: &[MacroRule], input: TokenStream) -> Result<TokenStream, String> {
    let mut last_err = String::from("no rules");
    for r in rules {
        let mut b = HashMap::new();
        match match_seq(&r.matcher, input.clone(), &mut b) {
            Ok(()) => return transcribe(r.body.clone(), &b),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

fn match_seq(ms: &[Matcher], input: TokenStream, b: &mut HashMap<String, Binding>) -> Result<(), String> {
    let p = |stream: ParseStream| -> syn::Result<HashMap<String, Binding>> {
        let mut b = HashMap::new();
        match_in(ms, stream, &mut b)?;
        if !stream.is_empty() {
            return Err(stream.error("unexpected tokens after the matcher"));
        }
        Ok(b)
    };
    let got = p.parse2(input).map_err(|e| e.to_string())?;
    b.extend(got);
    Ok(())
}

fn match_in(ms: &[Matcher], input: ParseStream, b: &mut HashMap<String, Binding>) -> syn::Result<()> {
    for m in ms {
        match m {
            Matcher::Tok(t) => {
                let got: TokenTree = input.parse()?;
                if got.to_string() != t.to_string() {
                    return Err(syn::Error::new(got.span(), format!("expected `{t}`")));
                }
            }
            Matcher::Group(d, sub) => {
                let got: TokenTree = input.parse()?;
                let TokenTree::Group(g) = got else { return Err(input.error("expected a group")) };
                if g.delimiter() != *d {
                    return Err(syn::Error::new(g.span(), "wrong delimiter"));
                }
                let mut inner = HashMap::new();
                let sub = sub.clone();
                let p = move |s: ParseStream| -> syn::Result<HashMap<String, Binding>> {
                    let mut bb = HashMap::new();
                    match_in(&sub, s, &mut bb)?;
                    Ok(bb)
                };
                inner.extend(p.parse2(g.stream())?);
                b.extend(inner);
            }
            Matcher::Var(n, frag) => {
                let ts: TokenStream = match frag.as_str() {
                    "ty" => {
                        let t: syn::Type = input.parse()?;
                        let g = Group::new(Delimiter::None, t.to_token_stream());
                        TokenTree::Group(g).into()
                    }
                    "ident" => input.parse::<Ident>()?.to_token_stream(),
                    "expr" => {
                        let e: syn::Expr = input.parse()?;
                        TokenTree::Group(Group::new(Delimiter::None, e.to_token_stream())).into()
                    }
                    "literal" => input.parse::<syn::Lit>()?.to_token_stream(),
                    "tt" => input.parse::<TokenTree>()?.into(),
                    "path" => input.parse::<syn::Path>()?.to_token_stream(),
                    other => return Err(input.error(format!("fragment `{other}` is not supported by the lift"))),
                };
                b.insert(n.clone(), Binding::One(ts));
            }
            Matcher::Rep(sub, sep, op) => {
                let mut reps = Vec::new();
                loop {
                    if input.is_empty() {
                        break;
                    }
                    let fork = input.fork();
                    let mut bb = HashMap::new();
                    if match_in(sub, &fork, &mut bb).is_err() {
                        break;
                    }
                    syn::parse::discouraged::Speculative::advance_to(input, &fork);
                    reps.push(bb);
                    if *op == '?' {
                        break;
                    }
                    if let Some(s) = sep {
                        if input.peek(syn::Token![,]) && s.to_string() == "," {
                            let _: syn::Token![,] = input.parse()?;
                        } else if input.is_empty() {
                            break;
                        } else {
                            let got: TokenTree = input.parse()?;
                            if got.to_string() != s.to_string() {
                                return Err(syn::Error::new(got.span(), "expected the repetition separator"));
                            }
                        }
                    }
                }
                if *op == '+' && reps.is_empty() {
                    return Err(input.error("expected at least one repetition"));
                }
                // every variable of the repetition gets a `Many`
                let mut names = Vec::new();
                matcher_vars(sub, &mut names);
                for n in names {
                    b.insert(n, Binding::Many(reps.clone()));
                }
            }
        }
    }
    Ok(())
}

fn matcher_vars(ms: &[Matcher], out: &mut Vec<String>) {
    for m in ms {
        match m {
            Matcher::Var(n, _) => out.push(n.clone()),
            Matcher::Group(_, s) | Matcher::Rep(s, _, _) => matcher_vars(s, out),
            Matcher::Tok(_) => {}
        }
    }
}

fn transcribe(body: TokenStream, b: &HashMap<String, Binding>) -> Result<TokenStream, String> {
    let toks: Vec<TokenTree> = body.into_iter().collect();
    let mut out = TokenStream::new();
    let mut i = 0;
    while i < toks.len() {
        match &toks[i] {
            TokenTree::Punct(p) if p.as_char() == '$' => match toks.get(i + 1) {
                Some(TokenTree::Ident(id)) => {
                    match b.get(&id.to_string()) {
                        Some(Binding::One(ts)) => out.extend(ts.clone()),
                        Some(Binding::Many(_)) => return Err(format!("`${id}` used outside its repetition")),
                        None => {
                            // `$crate` and friends
                            out.extend([toks[i].clone(), toks[i + 1].clone()]);
                        }
                    }
                    i += 2;
                }
                Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Parenthesis => {
                    // `$( .. ) sep? op`
                    let (sep, adv) = match (toks.get(i + 2), toks.get(i + 3)) {
                        (Some(TokenTree::Punct(o)), _) if matches!(o.as_char(), '*' | '+' | '?') => (None, 3),
                        (Some(s), Some(TokenTree::Punct(o))) if matches!(o.as_char(), '*' | '+' | '?') => (Some(s.clone()), 4),
                        _ => return Err("malformed transcriber repetition".into()),
                    };
                    // the repetition count: from the first `Many` variable used inside
                    let mut used = Vec::new();
                    stream_vars(g.stream(), &mut used);
                    let reps = used.iter().find_map(|n| match b.get(n) {
                        Some(Binding::Many(v)) => Some(v.clone()),
                        _ => None,
                    });
                    let Some(reps) = reps else { return Err("repetition without a repeated variable".into()) };
                    for (k, rb) in reps.iter().enumerate() {
                        if k > 0
                            && let Some(s) = &sep
                        {
                            out.extend([s.clone()]);
                        }
                        let mut inner = b.clone();
                        inner.extend(rb.clone());
                        out.extend(transcribe(g.stream(), &inner)?);
                    }
                    i += adv;
                }
                _ => {
                    out.extend([toks[i].clone()]);
                    i += 1;
                }
            },
            TokenTree::Group(g) => {
                let inner = transcribe(g.stream(), b)?;
                let mut ng = Group::new(g.delimiter(), inner);
                ng.set_span(g.span());
                out.extend([TokenTree::Group(ng)]);
                i += 1;
            }
            t => {
                out.extend([t.clone()]);
                i += 1;
            }
        }
    }
    Ok(out)
}

fn stream_vars(ts: TokenStream, out: &mut Vec<String>) {
    let toks: Vec<TokenTree> = ts.into_iter().collect();
    for (i, t) in toks.iter().enumerate() {
        match t {
            TokenTree::Punct(p) if p.as_char() == '$' => {
                if let Some(TokenTree::Ident(id)) = toks.get(i + 1) {
                    out.push(id.to_string());
                }
            }
            TokenTree::Group(g) => stream_vars(g.stream(), out),
            _ => {}
        }
    }
}

/// `let mut x = 0;` where `x` indexes an array (`a[x]`, `a[..x]`, `a[..=x]`):
/// rustc types the literal `usize`; the lift writes the annotation (typeck
/// re-checks it).
fn annotate_index_literals(b: &mut syn::Block) {
    struct Idx(HashSet<String>);
    impl<'ast> syn::visit::Visit<'ast> for Idx {
        fn visit_expr_index(&mut self, i: &'ast syn::ExprIndex) {
            let mut add = |e: &syn::Expr| {
                if let syn::Expr::Path(p) = e
                    && let Some(id) = p.path.get_ident()
                {
                    self.0.insert(id.to_string());
                }
            };
            match &*i.index {
                syn::Expr::Range(r) => {
                    if let Some(s) = &r.start {
                        add(s);
                    }
                    if let Some(e) = &r.end {
                        add(e);
                    }
                }
                other => add(other),
            }
            syn::visit::visit_expr_index(self, i);
        }
    }
    let mut v = Idx(HashSet::new());
    syn::visit::Visit::visit_block(&mut v, b);
    struct Ann<'a>(&'a HashSet<String>);
    impl VisitMut for Ann<'_> {
        fn visit_local_mut(&mut self, l: &mut syn::Local) {
            if let syn::Pat::Ident(pi) = &l.pat
                && self.0.contains(&pi.ident.to_string())
                && l.init.as_ref().is_some_and(|i| is_unsuffixed_int(&i.expr))
            {
                let pat = l.pat.clone();
                l.pat = syn::Pat::Type(syn::PatType { attrs: vec![], pat: Box::new(pat), colon_token: Default::default(), ty: Box::new(syn::parse_quote!(usize)) });
            }
            syn::visit_mut::visit_local_mut(self, l);
        }
    }
    Ann(&v.0).visit_block_mut(b);
}

/// The exec part of the lift prelude (`crate::__lift`).
pub const PRELUDE_EXEC: &str = include_str!("../lift/prelude.rs");
/// The model part of the lift prelude (`crate::__lift_model`).
pub const PRELUDE_MODEL: &str = include_str!("../lift/model.rs");


/// An integer literal and its suffix.
fn lit_usize(e: &syn::Expr) -> Option<(u64, String)> {
    match e {
        syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(i), .. }) => Some((i.base10_parse().ok()?, i.suffix().to_string())),
        syn::Expr::Paren(p) => lit_usize(&p.expr),
        syn::Expr::Group(g) => lit_usize(&g.expr),
        _ => None,
    }
}

/// `st` with the variables of `map` renamed (identifiers that are not a
/// field, a method or a path segment after `.`/`::`), inside macro bodies
/// too (`at_start! { .. }`).
fn rename_vars(st: &syn::Stmt, map: &HashMap<String, String>) -> syn::Stmt {
    fn walk(ts: proc_macro2::TokenStream, map: &HashMap<String, String>) -> proc_macro2::TokenStream {
        let mut out = Vec::new();
        let mut prev_sep = false;
        for t in ts {
            let sep = matches!(&t, proc_macro2::TokenTree::Punct(p) if p.as_char() == '.' || p.as_char() == ':');
            let t2 = match t {
                proc_macro2::TokenTree::Ident(i) if !prev_sep && map.contains_key(&i.to_string()) => proc_macro2::TokenTree::Ident(syn::Ident::new(&map[&i.to_string()], i.span())),
                proc_macro2::TokenTree::Group(g) => {
                    let mut g2 = proc_macro2::Group::new(g.delimiter(), walk(g.stream(), map));
                    g2.set_span(g.span());
                    proc_macro2::TokenTree::Group(g2)
                }
                other => other,
            };
            prev_sep = sep;
            out.push(t2);
        }
        out.into_iter().collect()
    }
    syn::parse2(walk(st.to_token_stream(), map)).unwrap_or_else(|_| st.clone())
}

#[cfg(test)]
mod cfg_tests {
    //! Which `#[cfg(..)]` code is test-only (DESIGN.md §15.5: only a
    //! `#[cfg(test)]` module is not a host child module), with its twin.

    use super::{host_access_of, host_only, is_test_only, item_attrs_of};

    fn items(src: &str) -> Vec<syn::Item> {
        syn::parse_file(src).unwrap().items
    }

    #[test]
    fn a_cfg_that_mentions_test_but_compiles_outside_tests_is_host_code() {
        // `not(test)`, `any(test, ..)`, a feature named like `test`: compiled
        // outside the crate's tests, so host code — still left out, but a
        // module behind it is a host child module
        let src = "#[cfg(not(test))] mod a;\n#[cfg(any(test, feature = \"fuzzing\"))] mod b;\n#[cfg(feature = \"test-utils\")] mod c;\n#[cfg(any(feature = \"std\", test))] mod d {}\n#[cfg(not(all(test, feature = \"std\")))] mod e;\n";
        for it in items(src) {
            let attrs = item_attrs_of(&it);
            assert!(!is_test_only(attrs), "test-only: {}", quote::ToTokens::to_token_stream(&it));
            let why = host_only(attrs).unwrap_or_else(|| panic!("not left out: {}", quote::ToTokens::to_token_stream(&it)));
            assert!(!why.contains("#[cfg(test)]"), "{why}");
        }
        let a = host_access_of(&items(&format!("{src}fn private() {{}}\n")), &[]);
        assert_eq!(a.host_children, ["a", "b", "c", "d", "e"]);
        assert!(a.private_callable("private"), "{a:?}");
    }

    #[test]
    fn only_cfg_test_and_cfg_all_test_are_test_only() {
        // the twin: `test`, `all(.., test, ..)` (nested too) are compiled for
        // the crate's tests alone, and their modules are no host children
        let src = "#[cfg(test)] mod a;\n#[cfg(all(test, feature = \"std\"))] mod b {}\n#[cfg(all(feature = \"std\", all(test, unix)))] mod c;\n#[cfg(unix)] #[cfg(test)] mod d;\n";
        for it in items(src) {
            let attrs = item_attrs_of(&it);
            assert!(is_test_only(attrs), "not test-only: {}", quote::ToTokens::to_token_stream(&it));
            assert!(host_only(attrs).is_some_and(|why| why.contains("#[cfg(test)]")));
        }
        let a = host_access_of(&items(&format!("{src}fn private() {{}}\n")), &[]);
        assert!(a.host_children.is_empty(), "{a:?}");
        assert!(!a.private_callable("private"), "{a:?}");
        // and a predicate on neither tests nor features is lifted
        assert!(host_only(item_attrs_of(&items("#[cfg(unix)] fn f() {}")[0])).is_none());
    }
}
