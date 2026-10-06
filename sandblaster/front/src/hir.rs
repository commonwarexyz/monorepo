//! The typed, resolved high-level IR (HIR) produced by the front end
//! (DESIGN.md §1 "front end: load → resolve → surface typecheck → subset
//! validation → HIR", §3, §4).
//!
//! This is the interface between the phase-1 front end and the phase-2
//! elaborator and the report. Everything in it
//! is **fully resolved and fully typed**:
//!
//! * every name is resolved: items by [`ItemId`], locals by [`LocalId`],
//!   builtins by [`Builtin`](crate::builtins::Builtin), intrinsics by
//!   [`IntrinsicId`](crate::intrinsics::IntrinsicId);
//! * every [`Expr`] carries its [`Ty`]; there are no inference variables;
//! * every implicit conversion rustc performs is an explicit
//!   [`ExprKind::Coerce`] node ([`Coercion`]): unsizing `&[T; N] → &[T]`,
//!   auto-ref / auto-deref of method receivers, field-access and index bases,
//!   and reference operands of arithmetic operators, plus `BoolToProp` in
//!   proposition positions;
//! * every pattern is explicit: matching a reference against a non-reference
//!   pattern inserts an implicit [`PatKind::Deref`] and switches bindings to
//!   [`BindingMode::ByRef`] (rustc's default binding modes), so a pattern's
//!   [`Pat::ty`] is always the type of the value it is matched against;
//! * every function-like item is normalized to [`FnDef`] (§4.2):
//!   `requires`, `ensures`, `decreases (+ max)`, body, target features;
//! * loops carry [`LoopInfo`] (mutated/read variables, invariants,
//!   decreases) as needed by the normative desugaring (§7.4).
//!
//! # Identity and ordering
//!
//! * [`ItemId`]s index [`Crate::items`]; they are assigned in a deterministic
//!   order (modules in load order, items in source order; inherent-impl
//!   functions right after the impl's position). [`ItemId`]s are stable for a
//!   given source tree; [`DefPath`]s (`crate::m::f`, `crate::m::Type::method`)
//!   are stable across edits and are what the elaborator should use for
//!   `GlobalName::Item(Path)` (§7.1).
//! * [`LocalId`]s index [`FnDef::locals`] (per function, or per const
//!   initializer in [`ConstDef::locals`]); they are allocated in source order,
//!   so a local declared before a loop has a smaller id than every local
//!   declared inside it.
//! * Loops are numbered per function in source order ([`LoopInfo::index`]),
//!   which gives the deterministic loop-helper names of §7.1.
//!
//! # Ghost code
//!
//! Items with [`Item::ghost`] set come from `#[cfg(sandblaster)]` items or
//! ghost modules; they are never printed. Ghost-only types are [`Ty::Int`],
//! [`Ty::Nat`], [`Ty::Seq`], [`Ty::Prop`] and [`Ty::Proof`]. Spec expressions reuse [`Expr`]; the
//! proposition connectives of §4.1 are the `Prop*` / [`ExprKind::Quant`]
//! variants, and script statements (§4.4) are [`ScriptStmt`].
//!
//! # Semantics notes for the elaborator
//!
//! * `a && b` / `a || b` on `bool` are **short-circuit** ([`BinOp::And`],
//!   [`BinOp::Or`]); `&`, `|`, `^` on `bool` are strict.
//! * [`ExprKind::Match`] arms keep their source order; or-patterns
//!   ([`PatKind::Or`]) and guards are kept as written — the or-pattern/guard
//!   expansion of §7.3 is a separate, normative step
//!   ([`crate::elab::pat::expand_or_arms`]).
//! * [`ExprKind::Index`] and [`ExprKind::SliceRange`] have as `base` a place of
//!   type `[T; N]` or `[T]` (reference bases are auto-dereferenced by an
//!   explicit `Coerce(AutoDeref)`); `SliceRange` has type `&[T]`.
//! * `usize` is 64-bit (enforced by the generated `compile_error!` guard).
//!
//! # Invariants of an error-free HIR
//!
//! When [`crate::driver::check`] reports no errors:
//!
//! * no type is [`Ty::Error`]; integer literals have a machine type, `Int`
//!   or (immediates only) `I32`, and fit in it;
//! * the operands of arithmetic/bitwise operators and of comparisons of
//!   scalars are plain values of the same type (reference operands carry an
//!   explicit `AutoDeref`); shift operands may have different widths;
//! * every `match` is exhaustive over its unguarded arms; `let` patterns are
//!   irrefutable unless the `let` has an `else` block (of type `Never`);
//! * no identifier pattern names a const, unit struct or unit variant (§3.3);
//!   `None` in patterns is [`Ctor::None`];
//! * [`ExprKind::Return`] and [`ExprKind::Try`] never occur inside a loop,
//!   and only in exec functions; `Try` is applied to `Option` values in
//!   functions returning `Option`;
//! * `while` loops have [`LoopInfo::decreases`];
//! * the reference graph has no cycle other than self-recursion;
//!   [`FnDef::recursion`] classifies self-recursive functions, and non-tail
//!   exec recursion carries `decreases(.., max = C)` with `C ≤ 4096` and a call tree within the 1 MiB stack budget (`validate::check_stack`);
//! * every intrinsic call's features are in the calling exec function's
//!   [`FnDef::feature_set`]; exec code never refers to ghost items;
//! * no slice type has a zero-sized element type, and no type parameter is
//!   instantiated with a zero-sized type;
//! * `pub` functions reachable from the root ([`Crate::reachable`]) have no
//!   `Irr` binder in their kernel type (no `requires`, no
//!   `#[decreases(.., max = C)]` depth hypothesis, no `#[ghost]` parameter,
//!   no `#[refines(.., domain = P)]`), and no type parameter of theirs
//!   occurs inside a slice element type (§3.1);
//! * `#[proof]` items are paired with their laws ([`FnDef::law_proof`],
//!   [`FnDef::proves`]); script applications of another proof item are
//!   rewritten to the law it proves (a proof's own recursive calls stay:
//!   they are its induction hypotheses). `#[proof(refines = f)]` /
//!   `#[proof(complete = f)]` items are paired with `f` instead
//!   ([`SpecAnnots::proof_of`], [`SpecAnnots::refines_proof`],
//!   [`SpecAnnots::complete_proof`]).
//!
//! # §15 annotations (DESIGN.md §15)
//!
//! The front end parses, resolves, types and places every §15 annotation
//! and records it here; the later stages give them meaning (S1: spec
//! modules' defaults, `#[refines]`, views, `#[represents]`, examples,
//! mirrors, fuel; S2: invariants, ghost parameters; S3: sections and
//! completeness). Until a stage lands, the elaborator reports every
//! recorded annotation of that stage as "not implemented yet" (an error),
//! so nothing gives false assurance. The records:
//!
//! * [`Module::spec`] — `#[cfg(sandblaster)] #[spec] mod m;` and its
//!   submodules; every `fn` in it is a spec fn unless it says otherwise;
//! * [`FnDef::spec`] ([`SpecAnnots`]) — `#[refines]`, `#[proof(refines |
//!   complete = ..)]`, `#[example]`, `#[examples(file = ..)]`,
//!   `#[section(with = [..])]`, `#[mirrors_impl]`, `#[fuel_sufficient]`,
//!   `#[trusted_extern]`, and the law-rule annotations `#[reduces_to]`,
//!   `#[assumption]`, `#[definitional]`, `#[corollary]` (§15.1, §15.13);
//! * [`Param::ghost`] — `#[ghost]` exec function parameters;
//! * [`StructDef::invariant`], [`StructDef::view`], [`EnumDef::view`],
//!   [`StructDef::represents`] — `#[invariant]`, `#[view]`, `#[represents]`.
//!
//! # Lifetimes
//!
//! Lifetimes are accepted and ignored by the semantics (§3.2). Declarations
//! keep them only for printing ([`Lifetimes`]): struct/enum lifetime
//! parameters, function lifetime parameters, and, for every declared type
//! (fields, parameters, return types, constants, aliases), the lifetimes
//! written in it in pre-order.

use std::fmt;

use crate::builtins::{Builtin, GhostFn};
use crate::intrinsics::{IntrinsicId, VecTy};
use crate::span::Span;
use crate::target::TargetInfo;

/// A module of the DSL crate (index into [`Crate::modules`]).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct ModId(pub u32);

/// An item (struct, enum, const, type alias, function) — index into
/// [`Crate::items`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct ItemId(pub u32);

/// A local variable of one function body (index into [`FnDef::locals`]).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct LocalId(pub u32);

/// Path of a definition relative to the DSL root: `["sha256", "compress"]`
/// displays as `crate::sha256::compress`. Inherent functions include the
/// type name: `["codec", "Reader", "new"]`.
#[derive(Clone, PartialEq, Eq, Hash, Debug, PartialOrd, Ord, Default)]
pub struct DefPath(pub Vec<String>);

impl DefPath {
    pub fn child(&self, name: &str) -> DefPath {
        let mut v = self.0.clone();
        v.push(name.to_string());
        DefPath(v)
    }
    pub fn last(&self) -> &str {
        self.0.last().map(String::as_str).unwrap_or("crate")
    }
}

impl fmt::Display for DefPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "crate")?;
        for s in &self.0 {
            write!(f, "::{s}")?;
        }
        Ok(())
    }
}

/// Unsigned machine integer types (§3.2). `Usize` is 64-bit.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub enum UintTy {
    U8,
    U16,
    U32,
    U64,
    Usize,
}

impl UintTy {
    pub const ALL: [UintTy; 5] = [UintTy::U8, UintTy::U16, UintTy::U32, UintTy::U64, UintTy::Usize];

    pub fn bits(self) -> u32 {
        match self {
            UintTy::U8 => 8,
            UintTy::U16 => 16,
            UintTy::U32 => 32,
            UintTy::U64 | UintTy::Usize => 64,
        }
    }
    /// Largest value.
    pub fn max_value(self) -> u128 {
        (1u128 << self.bits()) - 1
    }
    /// Rust spelling (`u32`, `usize`, ...).
    pub fn name(self) -> &'static str {
        match self {
            UintTy::U8 => "u8",
            UintTy::U16 => "u16",
            UintTy::U32 => "u32",
            UintTy::U64 => "u64",
            UintTy::Usize => "usize",
        }
    }
    pub fn from_name(s: &str) -> Option<UintTy> {
        Some(match s {
            "u8" => UintTy::U8,
            "u16" => UintTy::U16,
            "u32" => UintTy::U32,
            "u64" => UintTy::U64,
            "usize" => UintTy::Usize,
            _ => return None,
        })
    }
    /// The kernel width.
    pub fn width(self) -> sandblaster_kernel::term::Width {
        use sandblaster_kernel::term::Width;
        match self {
            UintTy::U8 => Width::U8,
            UintTy::U16 => Width::U16,
            UintTy::U32 => Width::U32,
            UintTy::U64 => Width::U64,
            UintTy::Usize => Width::Usize,
        }
    }
}

/// Surface types (§3.2, §4.1, §9.2).
///
/// * `()` is `Tuple(vec![])`.
/// * `&[T]` is `Ref(Slice(T))`; `Slice` only occurs directly under `Ref`,
///   except as the type of an auto-dereferenced place (index/range base).
/// * Array lengths are evaluated constants (`[u8; DIGEST_LEN]` becomes
///   `Array(U8, 32)`).
/// * Type aliases are expanded.
/// * `Param(i, name)`: the `i`-th generic parameter of the enclosing item
///   (for inherent functions: impl parameters first, then the function's own).
/// * `I32` is only the type of intrinsic immediates (never of a value).
/// * `Never` is the type of `return`, `unreachable!()` and diverging blocks; it
///   is accepted at every expected type without a coercion node.
/// * `Int`, `Prop`, `Proof` are ghost-only. `Proof` is the type of a lemma/law
///   application in scripts (`let h = lemma(..);`).
/// * `Error` appears only after a reported error (never in a successful HIR).
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum Ty {
    Bool,
    Uint(UintTy),
    I32,
    Tuple(Vec<Ty>),
    Array(Box<Ty>, u64),
    Slice(Box<Ty>),
    Ref(Box<Ty>),
    Option(Box<Ty>),
    Adt(ItemId, Vec<Ty>),
    Param(u32, String),
    Vector(VecTy),
    Int,
    /// Ghost `Nat` (§4.1): an `Int` with the type bound `0 ≤ n` (kernel
    /// `Int`; the bound is an obligation at each partial construction and a
    /// hypothesis of each ghost parameter, SEMANTICS.md §13.5).
    Nat,
    /// Ghost `Seq<T>` (§4.1): the prelude `List ⟦T⟧`, unbounded.
    Seq(Box<Ty>),
    /// Ghost `fn(A, ..) -> B` (DESIGN.md §13.2's `spec_fn`): a total function of
    /// ghost code, the kernel's curried `Π(_ : ⟦A⟧). .. ⟦B⟧`. Only the
    /// type of a ghost parameter, a ghost `let` or a lambda, never inside
    /// data (sequences, options, tuples, structs), never `Nat` (write `Int`)
    /// or `Prop` (write `bool`) inside; erased, it never reaches exec code.
    Fn(Vec<Ty>, Box<Ty>),
    Prop,
    Proof,
    Never,
    Error,
}

impl Ty {
    pub fn unit() -> Ty {
        Ty::Tuple(vec![])
    }
    pub fn usize() -> Ty {
        Ty::Uint(UintTy::Usize)
    }
    pub fn u32() -> Ty {
        Ty::Uint(UintTy::U32)
    }
    pub fn u8() -> Ty {
        Ty::Uint(UintTy::U8)
    }
    pub fn slice_ref(t: Ty) -> Ty {
        Ty::Ref(Box::new(Ty::Slice(Box::new(t))))
    }
    pub fn reference(t: Ty) -> Ty {
        Ty::Ref(Box::new(t))
    }
    pub fn array(t: Ty, n: u64) -> Ty {
        Ty::Array(Box::new(t), n)
    }
    pub fn option(t: Ty) -> Ty {
        Ty::Option(Box::new(t))
    }
    pub fn is_unit(&self) -> bool {
        matches!(self, Ty::Tuple(v) if v.is_empty())
    }
    pub fn is_never(&self) -> bool {
        matches!(self, Ty::Never)
    }
    pub fn is_error(&self) -> bool {
        matches!(self, Ty::Error)
    }
    pub fn as_uint(&self) -> Option<UintTy> {
        match self {
            Ty::Uint(u) => Some(*u),
            _ => None,
        }
    }
    /// Strips all outer references.
    pub fn peel_refs(&self) -> &Ty {
        let mut t = self;
        while let Ty::Ref(inner) = t {
            t = inner;
        }
        t
    }
    /// Number of outer references.
    pub fn ref_depth(&self) -> usize {
        let mut t = self;
        let mut n = 0;
        while let Ty::Ref(inner) = t {
            t = inner;
            n += 1;
        }
        n
    }
    /// Whether this type (transitively) mentions a ghost-only type.
    pub fn is_ghost_only(&self) -> bool {
        let mut ghost = false;
        self.walk(&mut |t| ghost |= matches!(t, Ty::Int | Ty::Nat | Ty::Seq(_) | Ty::Fn(..) | Ty::Prop | Ty::Proof));
        ghost
    }
    /// Pre-order walk over this type and its components.
    pub fn walk(&self, f: &mut dyn FnMut(&Ty)) {
        f(self);
        match self {
            Ty::Tuple(ts) | Ty::Adt(_, ts) => ts.iter().for_each(|t| t.walk(f)),
            Ty::Array(t, _) | Ty::Slice(t) | Ty::Ref(t) | Ty::Option(t) | Ty::Seq(t) => t.walk(f),
            Ty::Fn(ps, r) => {
                ps.iter().for_each(|t| t.walk(f));
                r.walk(f)
            }
            _ => {}
        }
    }
    /// Substitutes `Param(i, _)` by `args[i]`.
    pub fn subst(&self, args: &[Ty]) -> Ty {
        match self {
            Ty::Param(i, _) => args.get(*i as usize).cloned().unwrap_or_else(|| self.clone()),
            Ty::Tuple(ts) => Ty::Tuple(ts.iter().map(|t| t.subst(args)).collect()),
            Ty::Adt(id, ts) => Ty::Adt(*id, ts.iter().map(|t| t.subst(args)).collect()),
            Ty::Array(t, n) => Ty::Array(Box::new(t.subst(args)), *n),
            Ty::Slice(t) => Ty::Slice(Box::new(t.subst(args))),
            Ty::Ref(t) => Ty::Ref(Box::new(t.subst(args))),
            Ty::Option(t) => Ty::Option(Box::new(t.subst(args))),
            Ty::Seq(t) => Ty::Seq(Box::new(t.subst(args))),
            Ty::Fn(ps, r) => Ty::Fn(ps.iter().map(|t| t.subst(args)).collect(), Box::new(r.subst(args))),
            _ => self.clone(),
        }
    }
    /// Displays the type in Rust syntax, naming ADTs with `name`.
    pub fn display<'a>(&'a self, name: &'a dyn Fn(ItemId) -> String) -> TyDisplay<'a> {
        TyDisplay { ty: self, name }
    }
}

/// Helper returned by [`Ty::display`].
pub struct TyDisplay<'a> {
    ty: &'a Ty,
    name: &'a dyn Fn(ItemId) -> String,
}

impl fmt::Display for TyDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let d = |t: &'_ Ty| TyDisplay { ty: t, name: self.name }.to_string();
        match self.ty {
            Ty::Bool => write!(f, "bool"),
            Ty::Uint(u) => write!(f, "{}", u.name()),
            Ty::I32 => write!(f, "i32"),
            Ty::Tuple(ts) if ts.len() == 1 => write!(f, "({},)", d(&ts[0])),
            Ty::Tuple(ts) => write!(f, "({})", ts.iter().map(d).collect::<Vec<_>>().join(", ")),
            Ty::Array(t, n) => write!(f, "[{}; {n}]", d(t)),
            Ty::Slice(t) => write!(f, "[{}]", d(t)),
            Ty::Ref(t) => write!(f, "&{}", d(t)),
            Ty::Option(t) => write!(f, "Option<{}>", d(t)),
            Ty::Adt(id, args) if args.is_empty() => write!(f, "{}", (self.name)(*id)),
            Ty::Adt(id, args) => {
                write!(f, "{}<{}>", (self.name)(*id), args.iter().map(d).collect::<Vec<_>>().join(", "))
            }
            Ty::Param(_, n) => write!(f, "{n}"),
            Ty::Vector(v) => write!(f, "{}", v.rust_name()),
            Ty::Int => write!(f, "Int"),
            Ty::Nat => write!(f, "Nat"),
            Ty::Seq(t) => write!(f, "Seq<{}>", d(t)),
            Ty::Fn(ps, r) => write!(f, "fn({}) -> {}", ps.iter().map(d).collect::<Vec<_>>().join(", "), d(r)),
            Ty::Prop => write!(f, "Prop"),
            Ty::Proof => write!(f, "<proof>"),
            Ty::Never => write!(f, "!"),
            Ty::Error => write!(f, "{{error}}"),
        }
    }
}

/// Visibility as written (§3.1). `pub(in path)` is rejected.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Vis {
    Private,
    /// `pub(super)`
    Super,
    /// `pub(crate)`
    Crate,
    /// `pub`
    Public,
}

/// The whole checked crate.
#[derive(Clone, Debug)]
pub struct Crate {
    /// The DSL root module (`sandblaster/mod.rs`).
    pub root: ModId,
    pub modules: Vec<Module>,
    pub items: Vec<Item>,
    /// Target the crate was checked for (item `cfg`s were evaluated for it).
    pub target: TargetInfo,
    /// Names exported by the DSL root (`pub` items, `pub mod`s and `pub use`
    /// re-exports of the root module, non-ghost). These become
    /// `pub use __sandblaster::{..}` (§2). The §15.8 gate
    /// ([`crate::validate::spec15_gate`], in the crate path) restricts it to
    /// the root's `pub use` list of items.
    pub boundary: Vec<Export>,
    /// Non-ghost items reachable from the DSL root through public paths, and
    /// (transitively) the types of their public signatures/fields and the
    /// public inherent functions of those types — the verified boundary of
    /// §3.1 (its functions must be total).
    pub reachable: Vec<ItemId>,
}

impl Crate {
    pub fn item(&self, id: ItemId) -> &Item {
        &self.items[id.0 as usize]
    }
    pub fn module(&self, id: ModId) -> &Module {
        &self.modules[id.0 as usize]
    }
    pub fn fn_def(&self, id: ItemId) -> Option<&FnDef> {
        match &self.item(id).kind {
            ItemKind::Fn(f) => Some(f),
            _ => None,
        }
    }
    /// Looks an item up by its display path (`crate::m::f`).
    pub fn find(&self, path: &str) -> Option<ItemId> {
        self.items.iter().find(|i| i.path.to_string() == path).map(|i| i.id)
    }
    /// Whether item `id` is declared in a `#[bridges]` module.
    pub fn in_bridges_module(&self, id: ItemId) -> bool {
        self.module(self.item(id).module).bridges
    }
    /// Whether item `id` is declared in a `#[model]` module (layered proofs).
    pub fn in_model_module(&self, id: ItemId) -> bool {
        self.module(self.item(id).module).model
    }
    /// The proof file of a lifted crate that declares item `id`, if any
    /// ([`Module::proof_file`], or a module inside one). Its items and the
    /// `ensures` it attaches are proof internals, never locked (DESIGN.md
    /// §15.6).
    pub fn lift_proof_file(&self, id: ItemId) -> Option<ModId> {
        let mut m = Some(self.item(id).module);
        while let Some(mid) = m {
            let md = self.module(mid);
            if md.proof_file {
                return Some(mid);
            }
            m = md.parent;
        }
        None
    }

    /// Whether item `id` is declared in a `#[spec]` module (§15.1).
    pub fn in_spec_module(&self, id: ItemId) -> bool {
        self.module(self.item(id).module).spec
    }
    /// Whether `id` is a recursive spec type (§15 S5, SEMANTICS.md §13.9):
    /// an enum of a `#[spec]` module with a field of its own type. The
    /// type checker admits only direct recursive fields there, so a field
    /// type equal to `Ty::Adt(id, _)` is the whole test.
    pub fn is_recursive_adt(&self, id: ItemId) -> bool {
        let fields: Vec<&Ty> = match &self.item(id).kind {
            ItemKind::Enum(e) => e.variants.iter().flat_map(|v| v.fields.iter().map(|f| &f.ty)).collect(),
            ItemKind::Struct(s) => s.fields.iter().map(|f| &f.ty).collect(),
            _ => return false,
        };
        fields.iter().any(|t| matches!(t, Ty::Adt(c, _) if *c == id))
    }
    /// The `#[example(e)]`s of an item: a function's, or a ghost
    /// constant's (§15.7).
    pub fn examples_of(&self, id: ItemId) -> &[Example] {
        match &self.item(id).kind {
            ItemKind::Fn(f) => &f.spec.examples,
            ItemKind::Const(c) => &c.examples,
            _ => &[],
        }
    }
    /// Displays a type with ADT names as paths.
    pub fn ty_str(&self, t: &Ty) -> String {
        let name = |id: ItemId| self.item(id).name.clone();
        t.display(&name).to_string()
    }
}

/// A name exported by the DSL root.
#[derive(Clone, Debug)]
pub struct Export {
    pub name: String,
    pub target: ExportTarget,
    pub span: Span,
    /// Exported by a `pub use` of the root (not a `pub` item or `pub mod`
    /// declared there). The §15.8 boundary is exactly the root's `pub use`
    /// list of items.
    pub via_use: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExportTarget {
    Item(ItemId),
    Module(ModId),
}

/// A module (file module or ghost module).
#[derive(Clone, Debug)]
pub struct Module {
    pub id: ModId,
    /// Module name (`"crate"` for the root).
    pub name: String,
    pub parent: Option<ModId>,
    pub path: DefPath,
    pub file: crate::span::FileId,
    /// Declared `#[cfg(sandblaster)]` (or inside such a module).
    pub ghost: bool,
    pub vis: Vis,
    /// Items defined in this module, in source order (including inherent fns).
    pub items: Vec<ItemId>,
    pub submodules: Vec<ModId>,
    /// Span of the `mod name;` declaration (root: start of file).
    pub span: Span,
    /// Outer doc comments on the declaration plus inner `//!` docs.
    pub docs: Vec<String>,
    /// Target `cfg` predicate on the declaration (evaluated true), printed
    /// back as `#[cfg(..)]`.
    pub cfg: Option<String>,
    /// A specification module (§15.1): declared
    /// `#[cfg(sandblaster)] #[spec] mod m;`, or inside such a module. Every
    /// `fn` in it is a spec fn unless it is marked `#[lemma]`, `#[law]` or
    /// `#[proof]`; its items are on the S1 surface (spec closure, fuel and
    /// mirrors are enforced for them, `elab::examples`).
    pub spec: bool,
    /// A model module (layered proofs, `resolve::decl_is_model`): declared
    /// `#[cfg(sandblaster)] #[model] mod m;`, or inside such a module. Every
    /// `fn` in it is a spec fn (as in a `#[spec]` module) and its structs
    /// may be the targets of structural views; it is proof text, not on the
    /// specification surface.
    pub model: bool,
    /// A `#[bridges]` module (`resolve::decl_is_bridges`): its lemmas are
    /// rules of `auto`.
    pub bridges: bool,
    /// An in-place lifted module (`#[lift(in_place)]`, SEMANTICS.md §19.5):
    /// the host's own file read as-is. A `pub` function with `requires` is
    /// allowed there: the precondition is a host obligation, listed in the
    /// record (`driver::lifted::in_place_record`). Host code calls its
    /// `pub` functions directly — free functions and the impls on
    /// primitives (`u64 == Position`) included — so they are on the
    /// boundary ([`crate::validate::in_place_host_fns`]).
    pub lifted: bool,
    /// A lifted crate's proof file: a ghost `#[lift]` module other than the
    /// laws file (`crate::lift::LAWS_MODULE`), e.g. `PROOF.rs`. Its items
    /// and the `ensures` it attaches are proof internals, never on the
    /// review surface (DESIGN.md §15.6).
    pub proof_file: bool,
    /// A non-ghost `#[lift]` source (in place or copied, not the lift
    /// prelude): its functions' signatures are the lift's rewriting of the
    /// source's ([`FnDef::sig_text`]).
    pub lift_source: bool,
    /// A ghost `#[lift]` module (the laws file or a proof file) or a module
    /// inside one: the lift re-emits its items, their attributes without
    /// spans, so an `#[example]`'s text is its tokens ([`Example::text`]).
    pub lift_ghost: bool,
    /// For an in-place lifted module: what host code the lift leaves out
    /// can call of it besides its non-private functions (DESIGN.md §15.5,
    /// `validate::in_place_host_fns`).
    pub host_access: HostAccess,
}

/// The private functions of an in-place lifted module that host code the
/// lift leaves out can call (DESIGN.md §15.5, *Every host-callable
/// function*): Rust lets a module's descendants call its private items, so
/// every private function the host source declares is host-callable when
/// the module has a **host child module** — one the lift leaves out that
/// is compiled outside tests (not `#[cfg(test)]`). The module's own
/// left-out code (an `unverified_fns` method, an `unverified_impls` impl,
/// an item not among `items = ..`, a feature-gated item) may call a
/// private function too: those calls are recorded (`called`), and every
/// private function it calls by name is host-callable as well
/// (`validate::left_out_callers`). Filled by the lift
/// ([`crate::lift::LiftFacts::host_access`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostAccess {
    /// The host child modules (by name).
    pub host_children: Vec<String>,
    /// The private free functions the host source declares (by name).
    pub private_fns: std::collections::BTreeSet<String>,
    /// The private inherent methods the host source declares, as
    /// `Type::method` (the lift makes them `pub(crate)` in the model, so
    /// that proofs may name them; host code still sees them private).
    pub private_methods: std::collections::BTreeSet<String>,
    /// The names the left-out code calls: method names (`x.m(..)`), the last
    /// segment of a qualified path (`Self::m`, `T::m`) and single-segment
    /// paths (`f(..)`), and every identifier inside a macro call. A private
    /// function the host source declares under one of these names is
    /// host-callable (by name: an over-approximation within the module).
    pub called: std::collections::BTreeSet<String>,
}

impl HostAccess {
    /// Whether host code can call the private function or method `name`
    /// (`Type::method` for a method) the host source declares: the module
    /// has a host child module.
    pub fn private_callable(&self, name: &str) -> bool {
        (self.private_fns.contains(name) || self.private_methods.contains(name)) && !self.host_children.is_empty()
    }
}

/// An item.
#[derive(Clone, Debug)]
pub struct Item {
    pub id: ItemId,
    pub name: String,
    pub path: DefPath,
    pub module: ModId,
    pub vis: Vis,
    /// Ghost items are never compiled by rustc (§2).
    pub ghost: bool,
    pub span: Span,
    pub docs: Vec<String>,
    /// Whitelisted `#[allow(..)]` lints (printed back).
    pub allow: Vec<String>,
    /// Target `cfg` predicate (evaluated true for [`Crate::target`]).
    pub cfg: Option<String>,
    pub kind: ItemKind,
}

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ItemKind {
    Struct(StructDef),
    Enum(EnumDef),
    Const(ConstDef),
    TypeAlias(TypeAliasDef),
    Fn(FnDef),
}

/// Lifetimes written in a declared type, in pre-order of the type's
/// structure: one entry per [`Ty::Ref`] (`""` when elided) and, for every
/// [`Ty::Adt`] whose definition has lifetime parameters, one entry per
/// lifetime argument (`""` when elided). Printing only.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Lifetimes(pub Vec<String>);

/// A generic type parameter (bound `Copy`, §3.1).
#[derive(Clone, Debug)]
pub struct TyParam {
    pub name: String,
    pub span: Span,
}

/// Derived traits (§3.1: `Clone, Copy` required, `PartialEq, Eq, Debug` optional).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Derives {
    pub clone: bool,
    pub copy: bool,
    pub partial_eq: bool,
    pub eq: bool,
    pub debug: bool,
}

/// Shape of a struct or variant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Shape {
    /// `S { a: T }`
    Named,
    /// `S(T)`
    Tuple,
    /// `S`
    Unit,
}

#[derive(Clone, Debug)]
pub struct FieldDef {
    /// `None` for tuple fields (named by index).
    pub name: Option<String>,
    pub vis: Vis,
    pub ty: Ty,
    pub lts: Lifetimes,
    pub span: Span,
    pub docs: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct StructDef {
    /// Lifetime parameters (printing only).
    pub lifetimes: Vec<String>,
    pub generics: Vec<TyParam>,
    pub shape: Shape,
    pub fields: Vec<FieldDef>,
    pub derives: Derives,
    /// Inherent functions defined in `impl` blocks for this type.
    pub methods: Vec<ItemId>,
    /// `#[invariant(p)]` (several are conjoined; §15.3, S2).
    pub invariant: Option<TypeInvariant>,
    /// `#[view(..)]` (§15.3, S1).
    pub view: Option<View>,
    /// `#[represents(|s, a| P)]` (§15.3, S1).
    pub represents: Option<Represents>,
    /// The invariants a ghost `#[lift]` module attached to this lifted
    /// struct, as written there ([`Attached`]).
    pub attached: Vec<Attached>,
}

/// A statement a ghost `#[lift]` module (the laws file or a proof file)
/// attached to a lifted item with `#[lift_attach]` (`crate::lift`), as
/// written there: the lift records it on the item (`#[lift_src(..)]`)
/// because the spliced tokens carry their own file's line and column but
/// are read as the host file's. `SPEC.lock`'s source text of the item is
/// built from these (an edit elsewhere in the laws file changes no hash),
/// and the surface refuses a proof file's precondition, depth bound or
/// invariant on a boundary item (DESIGN.md §15.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attached {
    /// `requires`, `ensures`, `decreases` or `invariant`.
    pub kind: String,
    /// The DSL path of the ghost module that wrote it (`crate::laws`,
    /// `crate::proof`).
    pub module: String,
    /// Written in the laws file (`crate::lift::LAWS_MODULE`).
    pub in_laws: bool,
    /// The statement's arguments as written, whitespace collapsed.
    pub text: String,
}

/// `#[invariant(p)]` on a struct (DESIGN.md §15.3): the invariants of one
/// struct, typed in proposition position over one ghost binder per field.
/// `self.f` (and `self.0`) in `p` is rewritten to the binder of field `f`;
/// bare `self` and methods of the struct are rejected. The elaborator (S2)
/// makes the conjunction an `Irr` constructor field.
#[derive(Clone, Debug)]
pub struct TypeInvariant {
    /// The binder of each field, in declaration order (locals of
    /// [`TypeInvariant::locals`], named `self.f` / `self.0`).
    pub fields: Vec<LocalId>,
    /// Each invariant as written (a proposition; a `bool` expression
    /// carries [`Coercion::BoolToProp`]), with its attribute's span.
    pub props: Vec<(Expr, Span)>,
    pub locals: Vec<LocalDecl>,
}

/// An abstraction function of a type (DESIGN.md §15.3).
#[derive(Clone, Debug)]
pub enum View {
    /// `#[view(spec::T)]`: structural, every field onto the same-named field
    /// of the spec struct `target` (declared in a `#[spec]` module); the
    /// field names are checked to match exactly, the field views are S1's.
    Struct { target: ItemId, span: Span },
    /// `#[view(|s| e)]`: `body` over the binder `binder` (of the type
    /// itself); the view type is `body.ty`.
    Fn { binder: LocalId, body: Expr, locals: Vec<LocalDecl>, span: Span },
}

impl View {
    pub fn span(&self) -> Span {
        match self {
            View::Struct { span, .. } | View::Fn { span, .. } => *span,
        }
    }
}

/// `#[represents(|s: &S, a: spec::A| P)]` (DESIGN.md §15.3): a
/// representation relation between a value `repr` of the struct (by
/// reference when `by_ref`) and an abstract state `abs : abs_ty`.
#[derive(Clone, Debug)]
pub struct Represents {
    pub repr: LocalId,
    pub by_ref: bool,
    pub abs: LocalId,
    pub abs_ty: Ty,
    pub prop: Expr,
    pub locals: Vec<LocalDecl>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct VariantDef {
    pub name: String,
    pub shape: Shape,
    pub fields: Vec<FieldDef>,
    pub span: Span,
    pub docs: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct EnumDef {
    /// Lifetime parameters (printing only).
    pub lifetimes: Vec<String>,
    pub generics: Vec<TyParam>,
    pub variants: Vec<VariantDef>,
    pub derives: Derives,
    pub methods: Vec<ItemId>,
    /// `#[view(|s| e)]` (§15.3, S1; the structural form is struct-only).
    pub view: Option<View>,
}

/// `const NAME: T = expr;` (§3.1). The initializer is typed like an exec
/// expression; `value` is the front end's evaluation when the initializer is
/// an integer/bool expression (used for array lengths and immediates).
#[derive(Clone, Debug)]
pub struct ConstDef {
    pub ty: Ty,
    pub ty_lts: Lifetimes,
    pub init: Expr,
    pub locals: Vec<LocalDecl>,
    pub value: Option<u128>,
    /// `#[example(e)]` on a ghost constant (§15.7, S5): closed `bool` facts
    /// about it, checked like a function's examples.
    pub examples: Vec<Example>,
}

/// `type Name = T;` (non-generic; expanded everywhere in HIR types).
#[derive(Clone, Debug)]
pub struct TypeAliasDef {
    pub ty: Ty,
    pub lts: Lifetimes,
}

/// Kinds of function-like items (§4.2, §4.5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FnKind {
    /// Executable code (printed).
    Exec,
    /// `#[spec] fn` — ghost function (value or `-> Prop`).
    Spec,
    /// `#[lemma] fn` — `requires(..); ensures(..);` + script.
    Lemma,
    /// `#[law] fn` — a claim (`requires/ensures`), optionally with an inline proof.
    Law,
    /// `#[proof] fn` — the proof of the law with the same name.
    Proof,
}

impl FnKind {
    pub fn is_ghost(self) -> bool {
        self != FnKind::Exec
    }
    pub fn name(self) -> &'static str {
        match self {
            FnKind::Exec => "fn",
            FnKind::Spec => "spec",
            FnKind::Lemma => "lemma",
            FnKind::Law => "law",
            FnKind::Proof => "proof",
        }
    }
}

/// `self` receivers (§3.1: `self`, `&self`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Receiver {
    ByValue,
    ByRef,
}

/// `#[inline]` attributes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Inline {
    Hint,
    Always,
}

/// Recursion classification (§3.7), computed by the validator from the call
/// graph (mutual recursion is rejected).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Recursion {
    #[default]
    None,
    /// Self-recursive and every recursive call is in tail position
    /// (elaborated as a loop).
    Tail,
    /// Self-recursive with at least one non-tail call: needs
    /// `#[decreases(e, max = C)]` for exec functions.
    NonTail,
}

/// How a law is proven (§4.5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LawProof {
    /// Script statements follow `requires/ensures` in the law itself.
    Inline,
    /// The `#[proof]` item with the same name.
    Item(ItemId),
    /// Open claim (the build fails once proofs are checked).
    Missing,
}

/// A function parameter. The receiver (if any) is `params[0]` with a
/// binding pattern named `self`.
#[derive(Clone, Debug)]
pub struct Param {
    pub pat: Pat,
    pub ty: Ty,
    pub lts: Lifetimes,
    pub span: Span,
    /// `#[ghost] x: T` on an exec function parameter (DESIGN.md §15.3, S2):
    /// an `Irr` Π binder, never printed; its bindings are ghost locals and
    /// its type is a ghost type. Makes the function non-boundary.
    pub ghost: bool,
}

/// `#[ensures(|ret| p)]` / `ensures(p)`. `binder` binds the return value
/// (a wildcard of type `()` for the unit form).
#[derive(Clone, Debug)]
pub struct Ensures {
    pub binder: Pat,
    pub prop: Expr,
}

/// `#[decreases(e)]` / `#[decreases(e, max = C)]`.
#[derive(Clone, Debug)]
pub struct Decreases {
    pub measure: Expr,
    pub max: Option<u64>,
}

/// Body of a function-like item.
#[derive(Clone, Debug)]
pub enum FnBody {
    /// Exec function: a block expression.
    Exec(Expr),
    /// Spec function: a block expression in spec mode (type `Prop` for
    /// `-> Prop` functions).
    Spec(Expr),
    /// Lemma / proof / law with inline proof: script statements (§4.4)
    /// following the `requires(..); ensures(..);` header.
    Script(Vec<ScriptStmt>),
    /// A law without inline proof.
    Claim,
}

/// A local variable declaration.
#[derive(Clone, Debug)]
pub struct LocalDecl {
    pub name: String,
    pub ty: Ty,
    /// Declared `mut` (only `let mut`/`mut x` locals may be assigned).
    pub mutable: bool,
    /// Introduced by ghost code (script `let`, quantifier binders, ensures
    /// binders, ghost parameters).
    pub ghost: bool,
    pub span: Span,
}

/// The normalized form of every function-like item (§4.2).
#[derive(Clone, Debug)]
pub struct FnDef {
    pub kind: FnKind,
    /// The type of the inherent `impl` this function belongs to.
    pub owner: Option<ItemId>,
    pub receiver: Option<Receiver>,
    /// Impl generics first, then the function's own.
    pub generics: Vec<TyParam>,
    /// The function's own lifetime parameters (printing only).
    pub lifetimes: Vec<String>,
    /// Index of the inherent `impl` block this function was written in
    /// (functions of one block are printed together).
    pub impl_block: Option<u32>,
    /// Lifetime parameters of that impl block and the lifetime arguments of
    /// its self type (printing only).
    pub impl_lifetimes: Vec<String>,
    pub impl_self_lts: Vec<String>,
    pub params: Vec<Param>,
    pub ret: Ty,
    pub ret_lts: Lifetimes,
    /// Conjoined preconditions (each a separate irrelevant binder, §4.2).
    pub requires: Vec<Expr>,
    pub ensures: Option<Ensures>,
    pub decreases: Option<Decreases>,
    /// A lifted function read from MIR: its declared contract (`requires`
    /// clauses and depth bound, `lift::MirContract`), carried by the lift
    /// apart from the attributes above; the elaborator refuses the function
    /// unless its preconditions are the elaboration of exactly these.
    pub declared: Option<(Vec<Expr>, Option<Decreases>)>,
    pub body: FnBody,
    /// `#[target_feature(enable = "..")]` features as written.
    pub target_features: Vec<String>,
    /// Implication closure of `target_features` (§9.3), sorted.
    pub feature_set: Vec<String>,
    pub inline: Option<Inline>,
    pub must_use: bool,
    pub recursion: Recursion,
    /// For laws: where the proof is.
    pub law_proof: Option<LawProof>,
    /// For `#[proof]` items: the law they prove.
    pub proves: Option<ItemId>,
    /// `#[induction(x)]` on a lemma/proof/inline law: the parameter `x`
    /// (§4.4).
    pub induction: Option<LocalId>,
    /// The §15 annotations (DESIGN.md §15).
    pub spec: SpecAnnots,
    pub locals: Vec<LocalDecl>,
    /// Span of the signature (`fn name(..) -> T`).
    pub sig_span: Span,
    /// The signature's text (`fn name(..) -> T`, its tokens as the front end
    /// read them, flattened): for a function of a `#[lift]` source the
    /// lifted signature, whose rewritten tokens (`Self::Output` read as the
    /// type it names) keep spans from elsewhere in the host file, so its
    /// span covers no contiguous text (`crate::surface`: the lock's `src`
    /// of such a function).
    pub sig_text: String,
}

impl FnDef {
    /// The contract as written, for the reports and the spec sheet: `
    /// requires(p) .. ensures(q)` (each piece's text from `snip`), with the
    /// header `let`s of a lemma or law (`let x = e;` before a `requires` or
    /// `ensures`, which abbreviates the later statements as `{ let x = e;
    /// p }`) in their source position, so the text says what the kernel
    /// statement says. Without header `let`s: the `requires` in order, then
    /// the `ensures`.
    pub fn contract_text(&self, snip: &dyn Fn(Span) -> String) -> String {
        let mut parts: Vec<(Span, String)> = Vec::new();
        for r in &self.requires {
            parts.push((r.span, format!("requires({})", snip(r.span))));
        }
        if let Some(en) = &self.ensures {
            parts.push((en.prop.span, format!("ensures({})", snip(en.prop.span))));
        }
        let mut lets: Vec<Span> = Vec::new();
        let mut header = |e: &Expr| {
            // a header abbreviation is a block whose `let`s end before the
            // block's own span (the proposition's); a block written in the
            // proposition has its `let`s inside
            if let ExprKind::Block(b) = &e.kind {
                for st in &b.stmts {
                    if matches!(st.kind, StmtKind::Let { .. }) && st.span.file == e.span.file && st.span.hi <= e.span.lo && !lets.contains(&st.span) {
                        lets.push(st.span);
                    }
                }
            }
        };
        self.requires.iter().for_each(&mut header);
        if let Some(en) = &self.ensures {
            header(&en.prop);
        }
        lets.sort_by_key(|s| s.lo);
        for l in lets {
            let mut t = snip(l);
            if !t.trim_end().ends_with(';') {
                t.push(';');
            }
            let at = parts.iter().position(|(sp, _)| sp.file == l.file && sp.lo > l.lo).unwrap_or(parts.len());
            parts.insert(at, (l, t));
        }
        parts.into_iter().map(|(_, t)| format!(" {t}")).collect()
    }

    /// The `ensures` of the function's contract (DESIGN.md §15.6): the
    /// laws file's part when a proof file attached summaries
    /// ([`SpecAnnots::contract_ensures`]), else the `ensures`.
    pub fn contract_ensures(&self) -> Option<&Ensures> {
        self.ensures.as_ref()?;
        match &self.spec.contract_ensures {
            Some(c) => c.as_ref(),
            None => self.ensures.as_ref(),
        }
    }

    /// The name of the lemma that states the contract's `ensures`:
    /// `f::contract` (projected from `f::ensures`) when a proof file attached
    /// summaries, else `f::ensures`.
    pub fn contract_lemma(&self) -> &'static str {
        if self.spec.contract_ensures.is_some() { "contract" } else { "ensures" }
    }

    /// Whether the function has a precondition other than literal `true`
    /// (such functions are printed as `unsafe fn`, §3.1).
    pub fn has_requires(&self) -> bool {
        self.requires.iter().any(|r| !r.is_true_lit())
    }
    pub fn local(&self, id: LocalId) -> &LocalDecl {
        &self.locals[id.0 as usize]
    }
    /// The sources of `Irr` binders in the kernel type of this exec
    /// function (DESIGN.md §3.1, §15.5): a `requires` (any, even `true`),
    /// the `h_depth` hypothesis of `#[decreases(e, max = C)]`, a `#[ghost]`
    /// parameter. Boundary functions have none.
    pub fn irr_binders(&self) -> Vec<IrrBinder> {
        let mut out = Vec::new();
        if !self.requires.is_empty() {
            out.push(IrrBinder::Requires);
        }
        if self.decreases.as_ref().is_some_and(|d| d.max.is_some()) {
            out.push(IrrBinder::DepthBound);
        }
        if self.params.iter().any(|p| p.ghost) {
            out.push(IrrBinder::GhostParam);
        }
        out
    }
}

/// A source of an `Irr` binder in the kernel type of an exec function
/// ([`FnDef::irr_binders`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IrrBinder {
    Requires,
    DepthBound,
    GhostParam,
}

/// The §15 annotations of a function-like item (DESIGN.md §15), recorded by
/// the front end for the later stages. Each field names the stage that
/// gives it its meaning; until then the elaborator reports it as "not
/// implemented yet".
#[derive(Clone, Debug, Default)]
pub struct SpecAnnots {
    /// `#[refines(..)]` on an exec function (§15.2, S1).
    pub refines: Option<Refines>,
    /// On a `#[proof(refines = f)]` / `#[proof(complete = f)]` item: what it
    /// proves (§15.2 S1, §15.5 S3).
    pub proof_of: Option<ProofOf>,
    /// A `#[proof(refines = f)]` / `#[proof(complete = f)]` whose `f` did
    /// not resolve, or a `#[proof(..)]` with malformed arguments (both
    /// reported): the item is not paired with a `#[law]` by name either.
    pub proof_of_unresolved: bool,
    /// On an exec function: its `#[proof(refines = ..)]` item (paired by the
    /// validator).
    pub refines_proof: Option<ItemId>,
    /// On an exec function: its `#[proof(complete = ..)]` item.
    pub complete_proof: Option<ItemId>,
    /// `#[example(e)]` (§15.7, S1), in source order.
    pub examples: Vec<Example>,
    /// `#[examples(file = "..", format = .., provenance = ..)]` (§15.7, S1).
    pub example_files: Vec<ExampleFile>,
    /// `#[section(with = [..])]` (§15.5, S3): merge this function's section
    /// with those of the named exec functions (merge only).
    pub section_with: Vec<(ItemId, Span)>,
    /// The span of the `#[section(..)]` attribute.
    pub section_span: Option<Span>,
    /// `#[mirrors_impl(justification = "..")]` on a spec fn (§15.1, S1).
    pub mirrors_impl: Option<Justified>,
    /// `#[fuel_sufficient]` / `#[fuel_sufficient(spec_fn)]` on a lemma
    /// (§15.1, S1).
    pub fuel_sufficient: Option<FuelSufficient>,
    /// `#[trusted_extern(justification = "..")]` on an exec function
    /// (§15.8; §13 runtime primitives).
    pub trusted_extern: Option<Justified>,
    /// `#[mirrors_impl(of = path, justification = "..")]`: the exec
    /// function the spec function is claimed to coincide with (§15.1 LR5;
    /// without `of`, the claim is about the exec function refining it).
    pub mirrors_of: Option<ItemId>,
    /// `#[reduces_to(a)]` on a law (§15.1 LR4, LR9; §15.13): the spec
    /// function `a` (checked to be an `#[assumption]` by the law rules,
    /// `elab::law_rules`) and the attribute's span.
    pub reduces_to: Option<(ItemId, Span)>,
    /// `#[assumption(class = .., cite = "..")]` on a spec function (§15.13).
    pub assumption: Option<Assumption>,
    /// `#[definitional(reason = "..")]` on a law (§15.1 LR6): the reason.
    pub definitional: Option<Justified>,
    /// `#[corollary]` on a law (§15.1 LR7): the attribute's span.
    pub corollary: Option<Span>,
    /// `#[opaque]` on a spec function (DESIGN.md §5.6, §15 S5): its kernel
    /// definition is opaque in proofs. Not part of its meaning.
    pub opaque: Option<Span>,
    /// `#[contract_ensures(..)]` / `#[contract_ensures]` on a lifted exec
    /// function (put there by the lift, `crate::lift::ensures_attrs`): a
    /// proof file attached summaries to its `ensures`, so its contract —
    /// what `SPEC.lock` holds and §15.5 determines — is only the laws
    /// file's part: `Some(Some(e))`, or `Some(None)` when the laws file
    /// states none. The full `ensures` stays the proven postcondition and
    /// the fact at call sites. `None`: the contract is the `ensures`
    /// (DESIGN.md §15.6). Read it through [`FnDef::contract_ensures`].
    pub contract_ensures: Option<Option<Ensures>>,
    /// On a lifted exec function: the `requires`, `ensures` and
    /// `decreases` ghost `#[lift]` modules attached to it, as written there
    /// ([`Attached`]).
    pub attached: Vec<Attached>,
}

impl SpecAnnots {
    /// Whether any §15 annotation is present.
    pub fn is_empty(&self) -> bool {
        self.refines.is_none()
            && self.proof_of.is_none()
            && self.examples.is_empty()
            && self.example_files.is_empty()
            && self.section_span.is_none()
            && self.mirrors_impl.is_none()
            && self.fuel_sufficient.is_none()
            && self.trusted_extern.is_none()
            && self.mirrors_of.is_none()
            && self.reduces_to.is_none()
            && self.assumption.is_none()
            && self.definitional.is_none()
            && self.corollary.is_none()
    }
}

/// `#[refines(s)]`, `#[refines(s(e₁, …, eₙ))]`, `#[refines(s, domain = P)]`
/// (DESIGN.md §15.2).
#[derive(Clone, Debug)]
pub struct Refines {
    /// The spec function (`#[spec]`, or a `fn` of a `#[spec]` module).
    pub spec: ItemId,
    /// The explicit argument map `s(e₁, …, eₙ)`: ghost expressions over the
    /// parameters, checked against (and view-coerced to) the spec's
    /// parameter types. Its length is the spec's arity. `None` for the
    /// bare-path form (arity and coercibility checked by the typechecker,
    /// `typeck::spec15`).
    pub args: Option<Vec<Expr>>,
    /// `domain = P`: a proposition over the parameters (internal functions
    /// only; an `Irr` hypothesis of `f::refines`).
    pub domain: Option<Expr>,
    pub span: Span,
}

/// What a `#[proof(..)]` item with a target proves.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProofKind {
    /// `#[proof(refines = f)]`: `f::refines` (§15.2).
    Refines,
    /// `#[proof(complete = f)]`: `complete_f(R)` of `f`'s section (§15.5).
    Complete,
    /// `#[proof(view_inj = T)]` (S2): `T::view_inj` for the `#[view(|s| e)]`
    /// of struct `T` (§15.2): the item's two parameters `(a: T, b: T)`, its
    /// steps prove every `a.f == b.f` from `view(a) == view(b)`.
    ViewInj,
}

#[derive(Clone, Copy, Debug)]
pub struct ProofOf {
    pub kind: ProofKind,
    /// The exec function (resolved); the struct for
    /// [`ProofKind::ViewInj`].
    pub target: ItemId,
    pub span: Span,
}

/// `#[example(e)]`: a closed `bool` spec expression (no parameters in
/// scope), with its own locals (quantifier binders).
#[derive(Clone, Debug)]
pub struct Example {
    pub expr: Expr,
    pub locals: Vec<LocalDecl>,
    pub span: Span,
    /// The expression's tokens as the front end read them, flattened: the
    /// lock's `src` of an example of a ghost `#[lift]` module
    /// ([`Module::lift_ghost`]), whose attributes the lift re-emits without
    /// spans, so its span covers no text (`crate::surface`).
    pub text: String,
}

/// Record format of a vector file.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExampleFormat {
    /// NIST CAVP response files (`.rsp`).
    Cavp,
    Json,
}

/// Where test vectors come from (DESIGN.md §15.7); self-derived vectors do
/// not count as validation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Provenance {
    Independent,
    Production,
    /// `provenance = self`
    SelfDerived,
}

/// `#[examples(file = "..", format = .., provenance = ..)]` on a ghost
/// checker function. The file is read by the loader through its file
/// provider and registered in the source map (a build input).
#[derive(Clone, Debug)]
pub struct ExampleFile {
    /// The path as written (relative to the declaring file's directory).
    pub path: String,
    pub file: crate::span::FileId,
    pub format: ExampleFormat,
    pub provenance: Provenance,
    pub span: Span,
    /// The file's text (from the source map, filled by `driver::check`;
    /// the elaborator parses the records, S1).
    pub text: String,
}

/// An annotation with a mandatory `justification = ".."`.
#[derive(Clone, Debug)]
pub struct Justified {
    pub justification: String,
    pub span: Span,
}

/// The class of an `#[assumption]` (DESIGN.md §15.13).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AssumptionClass {
    Computational,
    Statistical,
    Environmental,
}

impl AssumptionClass {
    pub fn name(self) -> &'static str {
        match self {
            AssumptionClass::Computational => "computational",
            AssumptionClass::Statistical => "statistical",
            AssumptionClass::Environmental => "environmental",
        }
    }
}

/// `#[assumption(class = computational | statistical | environmental, cite
/// = "..")]` on a spec function (DESIGN.md §15.13): a named assumption with
/// no logical content (`fn a() {}`), which `#[reduces_to(a)]` laws name.
#[derive(Clone, Debug)]
pub struct Assumption {
    pub class: AssumptionClass,
    pub cite: String,
    pub span: Span,
}

/// `#[fuel_sufficient]` (optionally naming the spec fn it covers).
#[derive(Clone, Debug)]
pub struct FuelSufficient {
    pub spec: Option<ItemId>,
    pub span: Span,
}

/// Literal values. Integer literals carry their type in [`Expr::ty`]
/// (a machine type, `Int` or `I32` for immediates).
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum Lit {
    Int(u128),
    Bool(bool),
}

/// Built-in constants.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum BuiltinConst {
    /// `uN::MAX`
    Max(UintTy),
    /// `uN::MIN`
    Min(UintTy),
    /// `uN::BITS` (a `u32`)
    Bits(UintTy),
    /// Ghost `ISIZE_MAX : Int` (§3.5).
    IsizeMax,
}

/// Constructors of algebraic values.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Ctor {
    /// A struct (any shape).
    Struct(ItemId),
    /// Variant `index` of an enum.
    Variant(ItemId, u32),
    /// `Option::Some`
    Some,
    /// `Option::None`
    None,
}

/// What is called.
#[derive(Clone, PartialEq, Debug)]
pub enum Callee {
    /// A user function (exec, spec, lemma or law) with its type arguments
    /// (impl generics first).
    Item(ItemId, Vec<Ty>),
    /// A whitelisted method / associated function (§3.4) with its type
    /// arguments (element type for slice/array/option methods; empty for
    /// integer methods, whose width is in the [`Builtin`]).
    Builtin(Builtin, Vec<Ty>),
    /// A target intrinsic with its literal `i32` immediates (§9.2).
    Intrinsic(IntrinsicId, Vec<i64>),
    /// A ghost prelude function (`seq::*`, `eqb`) with type arguments.
    Ghost(GhostFn, Vec<Ty>),
}

/// Implicit adjustments made explicit (§3.6).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Coercion {
    /// `&[T; N] → &[T]` where a slice is expected.
    Unsize,
    /// `T → &T` (method receivers).
    AutoRef,
    /// `&T → T` (method receivers, field access, index bases, reference
    /// operands of arithmetic/bitwise operators, `&&T → &T` arguments).
    AutoDeref,
    /// `b : bool` used as a proposition means `b == true` (§4.1).
    BoolToProp,
    /// Ghost code only (DESIGN.md §15.3, S1): the type-directed view
    /// coercion from the operand's type to the node's type — `Nat → Int`
    /// (identity), `uN → Nat | Int`, `&[T]`/`[T; N]` (and references to
    /// them) → `Seq<α(T)>`, `[T; N] → [α(T); N]`, `Option`/tuples
    /// componentwise, a struct with a `#[view]` to its view type. The
    /// elaborator builds the abstraction term `α` (`elab::views`).
    View,
}

/// Unary operators.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum UnOp {
    /// `!` — boolean negation or bitwise complement.
    Not,
    /// `-` — ghost `Int` negation only.
    Neg,
}

/// Binary operators on values. Comparisons return `bool`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    /// Short-circuit `&&` on `bool`.
    And,
    /// Short-circuit `||` on `bool`.
    Or,
}

impl BinOp {
    pub fn symbol(self) -> &'static str {
        use BinOp::*;
        match self {
            Add => "+",
            Sub => "-",
            Mul => "*",
            Div => "/",
            Rem => "%",
            BitAnd => "&",
            BitOr => "|",
            BitXor => "^",
            Shl => "<<",
            Shr => ">>",
            Eq => "==",
            Ne => "!=",
            Lt => "<",
            Le => "<=",
            Gt => ">",
            Ge => ">=",
            And => "&&",
            Or => "||",
        }
    }
    pub fn is_comparison(self) -> bool {
        matches!(self, BinOp::Eq | BinOp::Ne | BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge)
    }
    pub fn is_shift(self) -> bool {
        matches!(self, BinOp::Shl | BinOp::Shr)
    }
}

/// Quantifiers (§4.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Quant {
    Forall,
    Exists,
}

/// Origin of a match (for printing/diagnostics only).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MatchSource {
    Match,
    /// `if let P = e { a } else { b }` ≡ `match e { P => a, _ => b }`.
    IfLet,
}

/// An expression with its type.
#[derive(Clone, Debug)]
pub struct Expr {
    pub kind: ExprKind,
    pub ty: Ty,
    pub span: Span,
}

impl Expr {
    pub fn new(kind: ExprKind, ty: Ty, span: Span) -> Expr {
        Expr { kind, ty, span }
    }
    /// Literal `true`.
    pub fn is_true_lit(&self) -> bool {
        match &self.kind {
            ExprKind::Lit(Lit::Bool(true)) => true,
            ExprKind::Coerce(Coercion::BoolToProp, e) => e.is_true_lit(),
            _ => false,
        }
    }
}

#[derive(Clone, Debug)]
pub enum ExprKind {
    Lit(Lit),
    Local(LocalId),
    /// A user `const`.
    Const(ItemId),
    BuiltinConst(BuiltinConst),
    /// Function / method / intrinsic call. Method calls are in UFCS form:
    /// the (adjusted) receiver is `args[0]`.
    Call { callee: Callee, args: Vec<Expr> },
    /// Constructor application: struct literals (`fields` in declaration
    /// order of the ones written, by index, plus optional `..base`),
    /// tuple-struct/variant calls, unit structs/variants, `Some(e)`, `None`.
    Adt { ctor: Ctor, ty_args: Vec<Ty>, fields: Vec<(u32, Expr)>, base: Option<Box<Expr>> },
    Tuple(Vec<Expr>),
    Array(Vec<Expr>),
    /// `[elem; count]`
    Repeat { elem: Box<Expr>, count: u64 },
    /// Field `index` of a struct (named or tuple) or tuple element. `base`
    /// has an ADT or tuple type (references are auto-dereferenced).
    Field { base: Box<Expr>, index: u32, name: Option<String> },
    /// `base[index]`; `base : [T; N]` or `[T]` (a place), `index : usize`.
    Index { base: Box<Expr>, index: Box<Expr> },
    /// `&base[lo..hi]` (any bound optional); type `&[T]`.
    SliceRange { base: Box<Expr>, lo: Option<Box<Expr>>, hi: Option<Box<Expr>> },
    Unary(UnOp, Box<Expr>),
    Binary(BinOp, Box<Expr>, Box<Expr>),
    /// `e as T` (T unsigned or ghost `Int`).
    Cast(Box<Expr>, Ty),
    /// User-written `&e` (identity in the model).
    Ref(Box<Expr>),
    /// User-written `*e` (identity in the model).
    Deref(Box<Expr>),
    Coerce(Coercion, Box<Expr>),
    /// `if cond { then } else { els }`; `then`/`els` are block (or `if`)
    /// expressions; without `else` the type is `()`.
    If { cond: Box<Expr>, then: Box<Expr>, els: Option<Box<Expr>> },
    Match { scrut: Box<Expr>, arms: Vec<Arm>, source: MatchSource },
    Block(Block),
    /// `return e` (outside loops only).
    Return(Option<Box<Expr>>),
    /// `e?` on `Option` (outside loops only).
    Try(Box<Expr>),
    /// `unreachable!()`.
    Unreachable,
    Loop(Box<Loop>),
    // ---- ghost / propositions (§4.1) ----
    /// Propositional equality `a == b` in a proposition position.
    PropEq(Box<Expr>, Box<Expr>),
    /// Propositional disequality.
    PropNe(Box<Expr>, Box<Expr>),
    /// Dependent conjunction `p && q`.
    PropAnd(Box<Expr>, Box<Expr>),
    PropOr(Box<Expr>, Box<Expr>),
    PropNot(Box<Expr>),
    Implies(Box<Expr>, Box<Expr>),
    Iff(Box<Expr>, Box<Expr>),
    /// `forall(|x: T, ..| p)` / `exists(|x: T| p)`.
    Quant { quant: Quant, binders: Vec<LocalId>, body: Box<Expr> },
    /// Ghost lambda `|x: A, ..| e` of type `fn(A, ..) -> B` (the kernel's
    /// curried `λ`); its body may read the enclosing locals, never assign them.
    Lambda { params: Vec<LocalId>, body: Box<Expr> },
    /// Ghost application `f(a, ..)` of a ghost function value (the kernel's `App`).
    Apply { fun: Box<Expr>, args: Vec<Expr> },
}

/// A match arm.
#[derive(Clone, Debug)]
pub struct Arm {
    pub pat: Pat,
    pub guard: Option<Expr>,
    pub body: Expr,
    pub span: Span,
}

/// A block `{ stmts; tail }`. Its type is the enclosing [`Expr::ty`]: the
/// tail's type, `()` without tail, or `Never` when the last statement
/// diverges.
#[derive(Clone, Debug)]
pub struct Block {
    pub stmts: Vec<Stmt>,
    pub tail: Option<Box<Expr>>,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct Stmt {
    pub kind: StmtKind,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub enum StmtKind {
    /// `let pat = init;` or `let pat = init else { els };` (`els` has type
    /// `Never`). `pat.ty` is the declared (or inferred) type.
    Let { pat: Pat, init: Expr, els: Option<Block> },
    /// Expression statement.
    Expr(Expr),
    /// `place = value;`
    Assign { place: Place, value: Expr },
    /// `place op= value;` (op arithmetic, bitwise or shift).
    CompoundAssign { op: BinOp, place: Place, value: Expr },
    /// `dst.copy_from_slice(src)` / `dst[lo..hi].copy_from_slice(src)` on a
    /// `let mut` array local (§3.3). `range` is `None` for the whole array.
    CopyFromSlice { dst: LocalId, range: Option<(Option<Expr>, Option<Expr>)>, src: Expr },
    /// A `proof! { .. }` block (ghost; never printed).
    Proof(Vec<ScriptStmt>),
}

/// An assignable place: a `mut` local with field/index projections.
#[derive(Clone, Debug)]
pub struct Place {
    pub local: LocalId,
    pub projs: Vec<Proj>,
    pub ty: Ty,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub enum Proj {
    Field { index: u32, name: Option<String> },
    Index(Expr),
}

/// A loop (§3.3, normative desugaring §7.4). Type `()`.
#[derive(Clone, Debug)]
pub struct Loop {
    pub kind: LoopKind,
    pub body: Block,
    pub info: LoopInfo,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub enum LoopKind {
    /// `for var in lo..hi` / `lo..=hi`; `var` is `None` for `_`. The loop
    /// variable has the (unsigned) type of `lo`/`hi`.
    ForRange { var: Option<LocalId>, lo: Expr, hi: Expr, inclusive: bool },
    /// `while cond` (needs `decreases`).
    While { cond: Expr },
}

/// Information the elaborator needs to build the loop helper (§7.4).
#[derive(Clone, Debug, Default)]
pub struct LoopInfo {
    /// Per-function source-order index (loop helper `k`).
    pub index: u32,
    /// Locals declared outside the loop that the loop assigns (including
    /// nested loops and `copy_from_slice`), sorted by id.
    pub mutated: Vec<LocalId>,
    /// Locals declared outside the loop that the loop (body, condition,
    /// invariants, decreases, proof blocks) reads but does not assign,
    /// sorted by id. The loop variable is excluded.
    pub read: Vec<LocalId>,
    /// `invariant(p);` from the leading `proof!` block.
    pub invariants: Vec<Expr>,
    /// `decreases(e);` from the leading `proof!` block.
    pub decreases: Option<Expr>,
}

/// A pattern. `ty` is the type of the value matched.
#[derive(Clone, Debug)]
pub struct Pat {
    pub kind: PatKind,
    pub ty: Ty,
    pub span: Span,
}

/// How a binding binds (after default binding modes are made explicit).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BindingMode {
    /// Binds the matched value (type `pat.ty`).
    ByValue,
    /// Binds a reference to it (type `&pat.ty`); produced under implicit
    /// dereference of a reference scrutinee.
    ByRef,
}

#[derive(Clone, Debug)]
pub enum PatKind {
    Wild,
    /// `x`, `mut x` (mutability on the [`LocalDecl`]), `x @ sub`.
    Binding { local: LocalId, mode: BindingMode, sub: Option<Box<Pat>> },
    /// Integer or bool literal.
    Lit(Lit),
    /// Inclusive range `lo..=hi` of integers.
    Range { lo: u128, hi: u128 },
    Tuple(Vec<Pat>),
    /// Struct, tuple-struct, unit struct, variant, `Some(p)`, `None`.
    /// `fields` lists the written fields by index; omitted fields (`..`) are
    /// wildcards.
    Ctor { ctor: Ctor, ty_args: Vec<Ty>, fields: Vec<(u32, Pat)> },
    /// Dereference of a reference value: `&p` written by the user
    /// (`implicit == false`) or inserted by default binding modes.
    Deref { pat: Box<Pat>, implicit: bool },
    /// Slice/array pattern `[prefix.., rest, suffix..]`. `rest` is `None`
    /// without `..`, `Some(None)` for `..`, `Some(Some(p))` for `t @ ..`
    /// (`p` is a binding whose type is the sub-slice `[T]`/`[T; k]` or, by
    /// reference, `&[T]`).
    Slice { prefix: Vec<Pat>, rest: Option<Option<Box<Pat>>>, suffix: Vec<Pat> },
    /// Or-pattern; every alternative binds the same locals.
    Or(Vec<Pat>),
}

impl Pat {
    /// Every local bound by this pattern, in order of first occurrence.
    pub fn bindings(&self) -> Vec<LocalId> {
        let mut out = Vec::new();
        self.collect_bindings(&mut out);
        out
    }
    fn collect_bindings(&self, out: &mut Vec<LocalId>) {
        match &self.kind {
            PatKind::Binding { local, sub, .. } => {
                if !out.contains(local) {
                    out.push(*local);
                }
                if let Some(s) = sub {
                    s.collect_bindings(out);
                }
            }
            PatKind::Tuple(ps) => ps.iter().for_each(|p| p.collect_bindings(out)),
            PatKind::Ctor { fields, .. } => fields.iter().for_each(|(_, p)| p.collect_bindings(out)),
            PatKind::Deref { pat, .. } => pat.collect_bindings(out),
            PatKind::Slice { prefix, rest, suffix } => {
                prefix.iter().for_each(|p| p.collect_bindings(out));
                if let Some(Some(r)) = rest {
                    r.collect_bindings(out);
                }
                suffix.iter().for_each(|p| p.collect_bindings(out));
            }
            PatKind::Or(alts) => alts.iter().for_each(|p| p.collect_bindings(out)),
            PatKind::Wild | PatKind::Lit(_) | PatKind::Range { .. } => {}
        }
    }
    /// Whether the pattern contains an or-pattern.
    pub fn has_or(&self) -> bool {
        match &self.kind {
            PatKind::Or(_) => true,
            PatKind::Binding { sub: Some(s), .. } => s.has_or(),
            PatKind::Tuple(ps) => ps.iter().any(Pat::has_or),
            PatKind::Ctor { fields, .. } => fields.iter().any(|(_, p)| p.has_or()),
            PatKind::Deref { pat, .. } => pat.has_or(),
            PatKind::Slice { prefix, rest, suffix } => {
                prefix.iter().any(Pat::has_or)
                    || suffix.iter().any(Pat::has_or)
                    || matches!(rest, Some(Some(r)) if r.has_or())
            }
            _ => false,
        }
    }
}

/// A script statement (§4.4).
#[derive(Clone, Debug)]
pub struct ScriptStmt {
    pub kind: ScriptKind,
    pub span: Span,
}

#[derive(Clone, Debug)]
pub struct ScriptArm {
    pub pat: Pat,
    pub steps: Vec<ScriptStmt>,
    pub span: Span,
}

/// The relation of a `calc!` link (and of its conclusion: `<` if some
/// link is `<`, else `<=` if some link is `<=`, else `==`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CalcRel {
    Eq,
    Le,
    Lt,
}

impl CalcRel {
    pub fn text(self) -> &'static str {
        match self {
            CalcRel::Eq => "==",
            CalcRel::Le => "<=",
            CalcRel::Lt => "<",
        }
    }
    /// The relation of a chain `a R1 b R2 c`.
    pub fn compose(self, other: CalcRel) -> CalcRel {
        match (self, other) {
            (CalcRel::Lt, _) | (_, CalcRel::Lt) => CalcRel::Lt,
            (CalcRel::Le, _) | (_, CalcRel::Le) => CalcRel::Le,
            _ => CalcRel::Eq,
        }
    }
}

/// One link `e_i R e_(i+1) by { steps }` of a `calc!` chain; `prop` is the
/// typed proposition of the link.
#[derive(Clone, Debug)]
pub struct CalcLink {
    pub prop: Expr,
    pub rel: CalcRel,
    /// `None`: no `by` block (the prover proves the link).
    pub steps: Option<Vec<ScriptStmt>>,
    pub span: Span,
}

/// What `unfold(f)` names.
#[derive(Clone, PartialEq, Debug)]
pub enum UnfoldTarget {
    Item(ItemId),
    Builtin(Builtin),
    /// A `Nat` prelude function of ghost code (`pow2`, `log2`, `popcount`;
    /// §15 S5): its ghost-library definition.
    Ghost(crate::builtins::GhostFn),
}

#[derive(Clone, Debug)]
pub enum ScriptKind {
    /// `assert(p);` / `assert(p, { steps });`
    Assert { prop: Expr, steps: Option<Vec<ScriptStmt>> },
    /// `lemma(args);` / `let h = lemma(args);` — `app` is a
    /// [`ExprKind::Call`] of a lemma or law with type [`Ty::Proof`]
    /// (a recursive call of the enclosing lemma is the induction hypothesis;
    /// `ih(args)` is sugar for it).
    ///
    /// With `infer`, the statement is `apply(lemma);` / `let h =
    /// apply(lemma);`: `app` is a call **without** arguments (and without
    /// type arguments), and the elaborator infers them by matching the
    /// lemma's `requires` against the facts in scope (and its `ensures`
    /// against the goal).
    ///
    /// With `optional` (the induction hypotheses `by_induction(..)` generates),
    /// the application is attempted: when a hypothesis of the lemma is not
    /// proven, the statement adds no fact and leaves no obligation.
    Apply { binder: Option<LocalId>, app: Expr, infer: bool, optional: bool },
    /// `match e { pat => { steps } .. }` (terminal).
    Match { scrut: Expr, arms: Vec<ScriptArm> },
    /// `if c { steps } else { steps }` (terminal).
    If { cond: Expr, then: Vec<ScriptStmt>, els: Vec<ScriptStmt> },
    /// `cases(k in a..b) { steps }` (terminal): `var` is the enumerated
    /// integer variable (already in scope); each case adds `var == v`.
    Cases { var: LocalId, lo: Expr, hi: Expr, inclusive: bool, steps: Vec<ScriptStmt> },
    /// `witness(e1, .., en);`
    Witness(Vec<Expr>),
    /// `use_hyp(i, e1, .., en);` (a `#[proof(complete = ..)]` script only):
    /// the `i`-th hypothesis of the completeness statement (`h{i}`: a law
    /// or contract about the hypothetical implementation) instantiated at
    /// `e1, .., en`, its `requires` proven, as a fact. What E-matching
    /// cannot find (a quantified hypothesis whose conclusion auto splits
    /// before matching it) is written out.
    /// `use_real(i, e1, .., en);` is the same instance of the hypothesis's
    /// statement about the real functions (the fact `l{i}`).
    UseHyp { index: u32, args: Vec<Expr>, real: bool },
    /// `unfold(f);`
    Unfold(UnfoldTarget),
    /// `f::step(args);` — the one-step unfolding of a spec or exec function
    /// `f` at `args` as a fact: `f(args) == body(args)` (the body with its
    /// recursive calls kept), proven by `delta` (DESIGN.md §5.7). `call` is
    /// the typed call `f(args)`.
    Step { call: Expr },
    /// `rewrite(h)`, `rewrite_rev(h)`, `rewrite(h, |x: T| p)`.
    Rewrite { eq: Expr, rev: bool, motive: Option<(LocalId, Expr)> },
    /// `exact(term);`
    Exact(Expr),
    /// `bv();`
    Bv,
    /// `follows();` (terminal): the goal follows from the facts in scope by
    /// the automation's general reasoning (the full prover chain).
    Follows,
    /// `by_computation();` (terminal): the goal holds by evaluation and
    /// conversion alone (no proof search).
    Compute,
    /// `by_lockstep();` (terminal, layered proofs): the goal `f(ā) == R`
    /// holds by one step of `f` — its body walked (tests split with their
    /// path equations) and each outcome met with `R` by the lockstep
    /// (`elab::refines`: induction hypotheses and facts modulo arithmetic,
    /// the same function or constructor argument by argument, `let`-bound
    /// choices walked).
    Lockstep,
    /// `by_arithmetic();` (terminal): the goal follows from the facts by
    /// arithmetic and equality reasoning alone — user functions are treated
    /// as unknown, nothing is unfolded, no case analysis on program values
    /// (linear integer arithmetic may split on arithmetic atoms), no lemmas.
    Arithmetic,
    /// `by_unfolding(f, g, ..);` (terminal): like [`ScriptKind::Arithmetic`],
    /// but exactly the named definitions are unfolded (opaque ones too).
    Unfolding(Vec<UnfoldTarget>),
    /// `by_contradiction();` (terminal): the facts in scope are
    /// contradictory (the prover must derive `Empty` from them alone).
    Contradiction,
    /// `calc! { e0 == e1 by { steps }; == e2; .. }`: `links[i]` proves
    /// `e_i R e_(i+1)` (with its steps, or the prover); the chain proves
    /// `concl` (`e0 R en`, by transitivity). With `goal` (the `calc!` is the
    /// last statement of its block), `concl` must be the goal; otherwise it
    /// becomes a fact for the following statements.
    Calc { links: Vec<CalcLink>, concl: Expr, rel: CalcRel, goal: bool },
    /// Ghost `let x = e;` (`pat` is a binding pattern).
    Let { pat: Pat, value: Expr },
    /// `using(f, g, ..);`: the lemmas (or laws) `f, g` as quantified facts of
    /// the statements after it: `follows()` (and `by_induction`) may
    /// instantiate them (DESIGN.md §8.1 step 7, ∀-facts of the context).
    Using(Vec<ItemId>),
    /// `show();`
    Show,
    /// `todo();`
    Todo,
}
