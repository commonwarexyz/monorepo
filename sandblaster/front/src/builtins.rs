//! The builtin table (DESIGN.md §3.4, §6 "Builtin table").
//!
//! [`Builtin`] enumerates every whitelisted method / associated function of
//! §3.4, every operator at every operand type and every conversion, with
//!
//! * its **HIR signature** ([`Builtin::sig`], receiver first for methods),
//! * its **canonical Rust spelling** in UFCS ([`Builtin::path`]):
//!   `<u32>::rotate_right`, `<[T]>::len`, `<[T]>::split_first_chunk::<4>`,
//!   `<u32 as ::core::cmp::Ord>::min` (`min`/`max` are `Ord` methods, not
//!   inherent), `<::core::option::Option<T>>::unwrap_or`; operators print
//!   infix ([`Builtin::infix`]),
//! * whether rustc can evaluate it in a `const` initializer
//!   ([`Builtin::is_const_fn`]).
//!
//! The mapping `Builtin ↔ prelude GlobalId` is added in phase 2 (the
//! elaborator looks the prelude definition up by [`Builtin::prelude_name`]).
//!
//! [`GhostFn`] are the ghost prelude functions (`seq::*`, `eqb`, §4.1).

use crate::hir::{BinOp, Ty, UintTy};

/// Integer methods (§3.4), instantiated at the receiver width.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum IntMethod {
    WrappingAdd,
    WrappingSub,
    WrappingMul,
    WrappingNeg,
    WrappingShl,
    WrappingShr,
    CheckedAdd,
    CheckedSub,
    CheckedMul,
    CheckedDiv,
    SaturatingAdd,
    SaturatingSub,
    SaturatingMul,
    RotateLeft,
    RotateRight,
    CountOnes,
    LeadingZeros,
    TrailingZeros,
    SwapBytes,
    ToBeBytes,
    ToLeBytes,
    /// Associated function `uN::from_be_bytes([u8; N/8])`.
    FromBeBytes,
    /// Associated function `uN::from_le_bytes([u8; N/8])`.
    FromLeBytes,
    Min,
    Max,
    /// Proof: no overflow.
    Pow,
    IsPowerOfTwo,
    AbsDiff,
    /// Proof: divisor ≠ 0.
    DivCeil,
}

impl IntMethod {
    pub const ALL: [IntMethod; 29] = {
        use IntMethod::*;
        [
            WrappingAdd, WrappingSub, WrappingMul, WrappingNeg, WrappingShl, WrappingShr, CheckedAdd, CheckedSub, CheckedMul, CheckedDiv, SaturatingAdd, SaturatingSub, SaturatingMul, RotateLeft, RotateRight, CountOnes, LeadingZeros, TrailingZeros, SwapBytes, ToBeBytes, ToLeBytes, FromBeBytes, FromLeBytes, Min, Max, Pow, IsPowerOfTwo, AbsDiff, DivCeil,
        ]
    };

    pub fn name(self) -> &'static str {
        use IntMethod::*;
        match self {
            WrappingAdd => "wrapping_add",
            WrappingSub => "wrapping_sub",
            WrappingMul => "wrapping_mul",
            WrappingNeg => "wrapping_neg",
            WrappingShl => "wrapping_shl",
            WrappingShr => "wrapping_shr",
            CheckedAdd => "checked_add",
            CheckedSub => "checked_sub",
            CheckedMul => "checked_mul",
            CheckedDiv => "checked_div",
            SaturatingAdd => "saturating_add",
            SaturatingSub => "saturating_sub",
            SaturatingMul => "saturating_mul",
            RotateLeft => "rotate_left",
            RotateRight => "rotate_right",
            CountOnes => "count_ones",
            LeadingZeros => "leading_zeros",
            TrailingZeros => "trailing_zeros",
            SwapBytes => "swap_bytes",
            ToBeBytes => "to_be_bytes",
            ToLeBytes => "to_le_bytes",
            FromBeBytes => "from_be_bytes",
            FromLeBytes => "from_le_bytes",
            Min => "min",
            Max => "max",
            Pow => "pow",
            IsPowerOfTwo => "is_power_of_two",
            AbsDiff => "abs_diff",
            DivCeil => "div_ceil",
        }
    }

    pub fn from_name(s: &str) -> Option<IntMethod> {
        IntMethod::ALL.into_iter().find(|m| m.name() == s)
    }

    /// Associated functions (no receiver).
    pub fn is_assoc(self) -> bool {
        matches!(self, IntMethod::FromBeBytes | IntMethod::FromLeBytes)
    }
}

/// Slice methods (§3.4); receiver `&[T]`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum SliceMethod {
    Len,
    IsEmpty,
    First,
    Last,
    Get,
    /// Proof `mid ≤ len`.
    SplitAt,
    SplitAtChecked,
    SplitFirst,
    SplitLast,
    SplitFirstChunk(u64),
    SplitLastChunk(u64),
    FirstChunk(u64),
    /// `N > 0` (checked by the front end, like rustc's const assertion).
    AsChunks(u64),
}

impl SliceMethod {
    pub fn name(self) -> &'static str {
        use SliceMethod::*;
        match self {
            Len => "len",
            IsEmpty => "is_empty",
            First => "first",
            Last => "last",
            Get => "get",
            SplitAt => "split_at",
            SplitAtChecked => "split_at_checked",
            SplitFirst => "split_first",
            SplitLast => "split_last",
            SplitFirstChunk(_) => "split_first_chunk",
            SplitLastChunk(_) => "split_last_chunk",
            FirstChunk(_) => "first_chunk",
            AsChunks(_) => "as_chunks",
        }
    }
    /// Resolves a method name; chunk methods need their const argument.
    pub fn from_name(s: &str, n: Option<u64>) -> Option<SliceMethod> {
        use SliceMethod::*;
        Some(match (s, n) {
            ("len", None) => Len,
            ("is_empty", None) => IsEmpty,
            ("first", None) => First,
            ("last", None) => Last,
            ("get", None) => Get,
            ("split_at", None) => SplitAt,
            ("split_at_checked", None) => SplitAtChecked,
            ("split_first", None) => SplitFirst,
            ("split_last", None) => SplitLast,
            ("split_first_chunk", Some(n)) => SplitFirstChunk(n),
            ("split_last_chunk", Some(n)) => SplitLastChunk(n),
            ("first_chunk", Some(n)) => FirstChunk(n),
            ("as_chunks", Some(n)) => AsChunks(n),
            _ => return None,
        })
    }
    /// Whether the method takes a const generic `N`.
    pub fn takes_const(s: &str) -> bool {
        matches!(s, "split_first_chunk" | "split_last_chunk" | "first_chunk" | "as_chunks")
    }
    pub fn is_slice_method_name(s: &str) -> bool {
        matches!(s, "len" | "is_empty" | "first" | "last" | "get" | "split_at" | "split_at_checked" | "split_first" | "split_last") || SliceMethod::takes_const(s)
    }
}

/// Array methods (§3.4). `a.len()` on an array resolves (as in rustc) to
/// the slice `len` through unsizing.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ArrayMethod {
    /// `<[T; N]>::as_slice(&a)`
    AsSlice(u64),
}

/// `Option` methods (§3.4).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum OptionMethod {
    /// receiver `&Option<T>`
    IsSome,
    /// receiver `&Option<T>`
    IsNone,
    /// receiver `Option<T>`, default `T`
    UnwrapOr,
}

impl OptionMethod {
    pub fn from_name(s: &str) -> Option<OptionMethod> {
        Some(match s {
            "is_some" => OptionMethod::IsSome,
            "is_none" => OptionMethod::IsNone,
            "unwrap_or" => OptionMethod::UnwrapOr,
            _ => return None,
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            OptionMethod::IsSome => "is_some",
            OptionMethod::IsNone => "is_none",
            OptionMethod::UnwrapOr => "unwrap_or",
        }
    }
}

/// Operand type of a scalar operator.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum OpTy {
    Bool,
    Uint(UintTy),
    /// Ghost mathematical integers.
    Int,
}

impl OpTy {
    pub fn ty(self) -> Ty {
        match self {
            OpTy::Bool => Ty::Bool,
            OpTy::Uint(u) => Ty::Uint(u),
            OpTy::Int => Ty::Int,
        }
    }
    pub fn of(t: &Ty) -> Option<OpTy> {
        match t {
            Ty::Bool => Some(OpTy::Bool),
            Ty::Uint(u) => Some(OpTy::Uint(*u)),
            Ty::Int => Some(OpTy::Int),
            _ => None,
        }
    }
}

/// Source type of an `as` cast.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum CastSrc {
    Bool,
    Uint(UintTy),
    Int,
}

/// Every builtin operation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Builtin {
    Int(IntMethod, UintTy),
    Slice(SliceMethod),
    Array(ArrayMethod),
    Option(OptionMethod),
    /// A non-shift binary operator on scalars (arithmetic, bitwise,
    /// comparison, short-circuit `&&`/`||` on bool).
    Bin(BinOp, OpTy),
    /// `<<` / `>>` with independent operand widths (rustc allows any mix).
    Shift { op: BinOp, lhs: UintTy, rhs: UintTy },
    /// `!` on bool or unsigned.
    Not(OpTy),
    /// Ghost `-x` on `Int`.
    Neg,
    /// `==`/`!=` at a structured type (derived `PartialEq`, arrays, slices,
    /// tuples, `Option`); type argument: the compared type.
    StructEq { ne: bool },
    /// `e as T`.
    Cast { from: CastSrc, to: CastDst },
    /// `a[i]` on an array (`N`) or slice (`None`); type argument `T`.
    Index { array: Option<u64> },
    /// `&s[a..b]` (bounds optional) on an array or slice; type argument `T`.
    SliceRange { array: Option<u64>, lo: bool, hi: bool },
    /// `dst[..].copy_from_slice(src)`; type argument `T`.
    CopyFromSlice,
}

/// Target type of an `as` cast.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum CastDst {
    Uint(UintTy),
    Int,
}

/// A builtin's signature (receiver first).
#[derive(Clone, Debug, PartialEq)]
pub struct Sig {
    pub params: Vec<Ty>,
    pub ret: Ty,
}

fn u(w: UintTy) -> Ty {
    Ty::Uint(w)
}

impl Builtin {
    /// HIR signature given the type arguments (element type `T` for slice,
    /// array, option, index and range builtins; compared type for
    /// `StructEq`).
    pub fn sig(&self, ty_args: &[Ty]) -> Sig {
        let t = || ty_args.first().cloned().unwrap_or(Ty::Error);
        let sl = || Ty::slice_ref(t());
        match *self {
            Builtin::Int(m, w) => {
                use IntMethod::*;
                let (params, ret) = match m {
                    WrappingAdd | WrappingSub | WrappingMul | SaturatingAdd | SaturatingSub | SaturatingMul | Min | Max | AbsDiff | DivCeil => (vec![u(w), u(w)], u(w)),
                    CheckedAdd | CheckedSub | CheckedMul | CheckedDiv => (vec![u(w), u(w)], Ty::option(u(w))),
                    WrappingNeg | SwapBytes => (vec![u(w)], u(w)),
                    WrappingShl | WrappingShr | RotateLeft | RotateRight | Pow => (vec![u(w), Ty::u32()], u(w)),
                    CountOnes | LeadingZeros | TrailingZeros => (vec![u(w)], Ty::u32()),
                    IsPowerOfTwo => (vec![u(w)], Ty::Bool),
                    ToBeBytes | ToLeBytes => (vec![u(w)], Ty::array(Ty::u8(), (w.bits() / 8) as u64)),
                    FromBeBytes | FromLeBytes => (vec![Ty::array(Ty::u8(), (w.bits() / 8) as u64)], u(w)),
                };
                Sig { params, ret }
            }
            Builtin::Slice(m) => {
                use SliceMethod::*;
                let r = |x: Ty| Ty::reference(x);
                let (params, ret) = match m {
                    Len => (vec![sl()], Ty::usize()),
                    IsEmpty => (vec![sl()], Ty::Bool),
                    First | Last => (vec![sl()], Ty::option(r(t()))),
                    Get => (vec![sl(), Ty::usize()], Ty::option(r(t()))),
                    SplitAt => (vec![sl(), Ty::usize()], Ty::Tuple(vec![sl(), sl()])),
                    SplitAtChecked => (vec![sl(), Ty::usize()], Ty::option(Ty::Tuple(vec![sl(), sl()]))),
                    SplitFirst | SplitLast => (vec![sl()], Ty::option(Ty::Tuple(vec![r(t()), sl()]))),
                    SplitFirstChunk(n) => (vec![sl()], Ty::option(Ty::Tuple(vec![r(Ty::array(t(), n)), sl()]))),
                    SplitLastChunk(n) => (vec![sl()], Ty::option(Ty::Tuple(vec![sl(), r(Ty::array(t(), n))]))),
                    FirstChunk(n) => (vec![sl()], Ty::option(r(Ty::array(t(), n)))),
                    AsChunks(n) => (vec![sl()], Ty::Tuple(vec![Ty::slice_ref(Ty::array(t(), n)), sl()])),
                };
                Sig { params, ret }
            }
            Builtin::Array(ArrayMethod::AsSlice(n)) => Sig { params: vec![Ty::reference(Ty::array(t(), n))], ret: sl() },
            Builtin::Option(m) => match m {
                OptionMethod::IsSome | OptionMethod::IsNone => Sig { params: vec![Ty::reference(Ty::option(t()))], ret: Ty::Bool },
                OptionMethod::UnwrapOr => Sig { params: vec![Ty::option(t()), t()], ret: t() },
            },
            Builtin::Bin(op, o) => {
                let ret = if op.is_comparison() { Ty::Bool } else { o.ty() };
                Sig { params: vec![o.ty(), o.ty()], ret }
            }
            Builtin::Shift { lhs, rhs, .. } => Sig { params: vec![u(lhs), u(rhs)], ret: u(lhs) },
            Builtin::Not(o) => Sig { params: vec![o.ty()], ret: o.ty() },
            Builtin::Neg => Sig { params: vec![Ty::Int], ret: Ty::Int },
            Builtin::StructEq { .. } => Sig { params: vec![t(), t()], ret: Ty::Bool },
            Builtin::Cast { from, to } => {
                let p = match from {
                    CastSrc::Bool => Ty::Bool,
                    CastSrc::Uint(w) => u(w),
                    CastSrc::Int => Ty::Int,
                };
                let r = match to {
                    CastDst::Uint(w) => u(w),
                    CastDst::Int => Ty::Int,
                };
                Sig { params: vec![p], ret: r }
            }
            Builtin::Index { array } => {
                let base = match array {
                    Some(n) => Ty::array(t(), n),
                    None => Ty::Slice(Box::new(t())),
                };
                Sig { params: vec![base, Ty::usize()], ret: t() }
            }
            Builtin::SliceRange { array, lo, hi } => {
                let base = match array {
                    Some(n) => Ty::array(t(), n),
                    None => Ty::Slice(Box::new(t())),
                };
                let mut params = vec![base];
                if lo {
                    params.push(Ty::usize());
                }
                if hi {
                    params.push(Ty::usize());
                }
                Sig { params, ret: sl() }
            }
            Builtin::CopyFromSlice => Sig { params: vec![sl(), sl()], ret: Ty::unit() },
        }
    }

    /// Operators and indexing print as Rust syntax rather than a path.
    pub fn infix(&self) -> Option<&'static str> {
        match self {
            Builtin::Bin(op, _) | Builtin::Shift { op, .. } => Some(op.symbol()),
            Builtin::Not(_) => Some("!"),
            Builtin::Neg => Some("-"),
            Builtin::StructEq { ne: false } => Some("=="),
            Builtin::StructEq { ne: true } => Some("!="),
            Builtin::Cast { .. } => Some("as"),
            Builtin::Index { .. } | Builtin::SliceRange { .. } => Some("[]"),
            _ => None,
        }
    }

    /// Canonical UFCS path of a method/associated-function builtin, given a
    /// printer for type arguments. `None` for operators (see [`Builtin::infix`]).
    pub fn path(&self, ty_args: &[Ty], print_ty: &dyn Fn(&Ty) -> String) -> Option<String> {
        let t = || ty_args.first().map(print_ty).unwrap_or_else(|| "_".into());
        Some(match *self {
            Builtin::Int(IntMethod::Min, w) => format!("<{} as ::core::cmp::Ord>::min", w.name()),
            Builtin::Int(IntMethod::Max, w) => format!("<{} as ::core::cmp::Ord>::max", w.name()),
            Builtin::Int(m, w) => format!("<{}>::{}", w.name(), m.name()),
            Builtin::Slice(SliceMethod::Get) => format!("<[{}]>::get::<usize>", t()),
            Builtin::Slice(m @ (SliceMethod::SplitFirstChunk(n) | SliceMethod::SplitLastChunk(n) | SliceMethod::FirstChunk(n) | SliceMethod::AsChunks(n))) => {
                format!("<[{}]>::{}::<{n}>", t(), m.name())
            }
            Builtin::Slice(m) => format!("<[{}]>::{}", t(), m.name()),
            Builtin::Array(ArrayMethod::AsSlice(n)) => format!("<[{}; {n}]>::as_slice", t()),
            Builtin::Option(m) => format!("<::core::option::Option<{}>>::{}", t(), m.name()),
            Builtin::CopyFromSlice => format!("<[{}]>::copy_from_slice", t()),
            _ => return None,
        })
    }

    /// Whether rustc accepts the builtin in a `const` initializer.
    pub fn is_const_fn(&self) -> bool {
        match self {
            Builtin::Int(IntMethod::Min | IntMethod::Max, _) => false,
            Builtin::Int(..) => true,
            Builtin::Slice(SliceMethod::Get) => false,
            Builtin::Slice(_) => true,
            Builtin::Array(_) => true,
            Builtin::Option(OptionMethod::UnwrapOr) => false,
            Builtin::Option(_) => true,
            Builtin::StructEq { .. } => false,
            Builtin::CopyFromSlice => false,
            _ => true,
        }
    }

    /// Name of the prelude definition giving this builtin its meaning (the
    /// phase-2 `GlobalId` is looked up by this name).
    pub fn prelude_name(&self) -> String {
        match *self {
            Builtin::Int(m, w) => format!("{}::{}", w.name(), m.name()),
            Builtin::Slice(m) => match m {
                SliceMethod::SplitFirstChunk(n) | SliceMethod::SplitLastChunk(n) | SliceMethod::FirstChunk(n) | SliceMethod::AsChunks(n) => format!("slice::{}<{n}>", m.name()),
                _ => format!("slice::{}", m.name()),
            },
            Builtin::Array(ArrayMethod::AsSlice(_)) => "array::as_slice".into(),
            Builtin::Option(m) => format!("option::{}", m.name()),
            Builtin::Bin(op, o) => format!("op::{:?}::{:?}", op, o),
            Builtin::Shift { op, lhs, rhs } => format!("op::{:?}::{}::{}", op, lhs.name(), rhs.name()),
            Builtin::Not(o) => format!("op::Not::{o:?}"),
            Builtin::Neg => "op::Neg::Int".into(),
            Builtin::StructEq { ne } => if ne { "eq::ne".into() } else { "eq::eq".into() },
            Builtin::Cast { from, to } => format!("cast::{from:?}::{to:?}"),
            Builtin::Index { array } => if array.is_some() { "array::index".into() } else { "slice::index".into() },
            Builtin::SliceRange { array, lo, hi } => format!("{}::range::{lo}::{hi}", if array.is_some() { "array" } else { "slice" }),
            Builtin::CopyFromSlice => "array::copy_from_slice".into(),
        }
    }
}

// ----------------------------------------------------------------------
// mapping HIR operator nodes to builtins
// ----------------------------------------------------------------------

/// The builtin of a HIR [`ExprKind::Binary`](crate::hir::ExprKind::Binary)
/// with operand types `l`, `r` (as stored on the operand expressions).
/// Scalar `==`/`!=` map to [`Builtin::Bin`], structured ones to
/// [`Builtin::StructEq`] (type argument: `l`).
pub fn of_binary(op: BinOp, l: &Ty, r: &Ty) -> Option<Builtin> {
    if op.is_shift() {
        return match (l, r) {
            (Ty::Uint(a), Ty::Uint(b)) => Some(Builtin::Shift { op, lhs: *a, rhs: *b }),
            _ => None,
        };
    }
    match OpTy::of(l) {
        Some(o) if l == r => Some(Builtin::Bin(op, o)),
        _ if matches!(op, BinOp::Eq | BinOp::Ne) => Some(Builtin::StructEq { ne: op == BinOp::Ne }),
        _ => None,
    }
}

/// The builtin of a HIR unary operator on an operand of type `t`.
pub fn of_unary(op: crate::hir::UnOp, t: &Ty) -> Option<Builtin> {
    match op {
        crate::hir::UnOp::Not => OpTy::of(t).filter(|o| *o != OpTy::Int).map(Builtin::Not),
        crate::hir::UnOp::Neg => (*t == Ty::Int).then_some(Builtin::Neg),
    }
}

/// The builtin of a HIR cast `e as to` with `e : from`.
pub fn of_cast(from: &Ty, to: &Ty) -> Option<Builtin> {
    let from = match from {
        Ty::Bool => CastSrc::Bool,
        Ty::Uint(w) => CastSrc::Uint(*w),
        Ty::Int => CastSrc::Int,
        _ => return None,
    };
    let to = match to {
        Ty::Uint(w) => CastDst::Uint(*w),
        Ty::Int => CastDst::Int,
        _ => return None,
    };
    Some(Builtin::Cast { from, to })
}

/// The builtin of a HIR index `base[i]` (`base : [T; N]` or `[T]`) and its
/// type argument `T`.
pub fn of_index(base: &Ty) -> Option<(Builtin, Ty)> {
    match base {
        Ty::Array(t, n) => Some((Builtin::Index { array: Some(*n) }, (**t).clone())),
        Ty::Slice(t) => Some((Builtin::Index { array: None }, (**t).clone())),
        _ => None,
    }
}

/// The builtin of a HIR range index `&base[lo..hi]` and its type argument.
pub fn of_slice_range(base: &Ty, lo: bool, hi: bool) -> Option<(Builtin, Ty)> {
    match base {
        Ty::Array(t, n) => Some((Builtin::SliceRange { array: Some(*n), lo, hi }, (**t).clone())),
        Ty::Slice(t) => Some((Builtin::SliceRange { array: None, lo, hi }, (**t).clone())),
        _ => None,
    }
}

/// Ghost prelude functions (§4.1). All are generic over one element type
/// `T` (except [`GhostFn::Eqb`], generic over the compared type).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum GhostFn {
    /// `seq::len(xs: &[T]) -> Int`
    SeqLen,
    /// `seq::append(xs: &[T], ys: &[T]) -> &[T]`
    SeqAppend,
    /// `seq::cons(x: T, xs: &[T]) -> &[T]`
    SeqCons,
    /// `seq::take(xs: &[T], n: Int) -> &[T]`
    SeqTake,
    /// `seq::drop(xs: &[T], n: Int) -> &[T]`
    SeqDrop,
    /// `seq::index(xs: &[T], i: Int) -> T`
    SeqIndex,
    /// `seq::update(xs: &[T], i: Int, x: T) -> &[T]`
    SeqUpdate,
    /// `seq::rev(xs: &[T]) -> &[T]`
    SeqRev,
    /// `seq::replicate(n: Int, x: T) -> &[T]`
    SeqReplicate,
    /// `seq::empty::<T>() -> &[T]`
    SeqEmpty,
    /// `eqb(a: T, b: T) -> bool` (boolean equality, §4.1)
    Eqb,
    // ---- `Seq<T>` (§4.1, S1): the prelude `List`, unbounded ----
    /// `xs.len() -> Nat`
    SLen,
    /// `xs.get(i: Nat) -> Option<T>`
    SGet,
    /// `xs[i]` with `i: Nat` (obligation `i < xs.len()`)
    SIndex,
    /// `xs.take(n: Nat) -> Seq<T>` (all of `xs` when `n ≥ len`)
    STake,
    /// `xs.skip(n: Nat) -> Seq<T>` (empty when `n ≥ len`)
    SSkip,
    /// `xs.chunks_exact::<N>() -> Seq<[T; N]>` (drops the remainder)
    SChunks(u64),
    /// `xs.flatten()`: `Seq<[T; N]> -> Seq<T>` (`Some(N)`) or
    /// `Seq<Seq<T>> -> Seq<T>` (`None`)
    SFlatten(Option<u64>),
    /// `xs.to_array::<N>() -> [T; N]` (obligation `xs.len() == N`)
    SToArray(u64),
    /// `Seq::repeat(x: T, n: Nat) -> Seq<T>`
    SRepeat,
    /// `Seq::empty() -> Seq<T>` (`seq![]`)
    SEmpty,
    /// `Seq::cons(x: T, xs: Seq<T>)` (`seq![x, ..xs]`)
    SCons,
    /// `xs.append(ys) -> Seq<T>` (`seq![..xs, ..ys]`)
    SAppend,
    /// `xs.update(i: Nat, x: T) -> Seq<T>` (unchanged when `i ≥ len`)
    SUpdate,
    /// `xs.rev() -> Seq<T>`
    SRev,
    // ---- `Nat` / `Int` methods (§4.1, S1); `T` is `Nat` or `Int` ----
    /// `a.min(b)`, `a.max(b)`
    NMin,
    NMax,
    /// `a.saturating_sub(b)` on `Nat` (Bend's `Nat.sub`)
    NSatSub,
    /// `a.div_euclid(b)`, `a.rem_euclid(b)` on `Int` (obligation `b ≠ 0`)
    IDivEuclid,
    IRemEuclid,
    // ---- `Nat` prelude functions (§15 S5; SEMANTICS.md §13.10) ----
    /// `pow2(n: Int) -> Nat`: 2^n (1 for `n ≤ 0`)
    Pow2,
    /// `log2(n: Int) -> Nat`: the highest set bit (0 for `n < 2`)
    Log2,
    /// `popcount(n: Int) -> Nat`: the number of set bits (0 for `n ≤ 0`)
    Popcount,
}

impl GhostFn {
    /// Resolves `seq::name`.
    pub fn seq(name: &str) -> Option<GhostFn> {
        Some(match name {
            "len" => GhostFn::SeqLen,
            "append" => GhostFn::SeqAppend,
            "cons" => GhostFn::SeqCons,
            "take" => GhostFn::SeqTake,
            "drop" => GhostFn::SeqDrop,
            "index" => GhostFn::SeqIndex,
            "update" => GhostFn::SeqUpdate,
            "rev" => GhostFn::SeqRev,
            "replicate" => GhostFn::SeqReplicate,
            "empty" => GhostFn::SeqEmpty,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            GhostFn::SeqLen => "seq::len",
            GhostFn::SeqAppend => "seq::append",
            GhostFn::SeqCons => "seq::cons",
            GhostFn::SeqTake => "seq::take",
            GhostFn::SeqDrop => "seq::drop",
            GhostFn::SeqIndex => "seq::index",
            GhostFn::SeqUpdate => "seq::update",
            GhostFn::SeqRev => "seq::rev",
            GhostFn::SeqReplicate => "seq::replicate",
            GhostFn::SeqEmpty => "seq::empty",
            GhostFn::Eqb => "eqb",
            GhostFn::SLen => "Seq::len",
            GhostFn::SGet => "Seq::get",
            GhostFn::SIndex => "Seq::index",
            GhostFn::STake => "Seq::take",
            GhostFn::SSkip => "Seq::skip",
            GhostFn::SChunks(_) => "Seq::chunks_exact",
            GhostFn::SFlatten(_) => "Seq::flatten",
            GhostFn::SToArray(_) => "Seq::to_array",
            GhostFn::SRepeat => "Seq::repeat",
            GhostFn::SEmpty => "Seq::empty",
            GhostFn::SCons => "Seq::cons",
            GhostFn::SAppend => "Seq::append",
            GhostFn::SUpdate => "Seq::update",
            GhostFn::SRev => "Seq::rev",
            GhostFn::NMin => "min",
            GhostFn::NMax => "max",
            GhostFn::NSatSub => "Nat::saturating_sub",
            GhostFn::IDivEuclid => "Int::div_euclid",
            GhostFn::IRemEuclid => "Int::rem_euclid",
            GhostFn::Pow2 => "pow2",
            GhostFn::Log2 => "log2",
            GhostFn::Popcount => "popcount",
        }
    }

    /// The prelude free function `name` of ghost code (§15 S5).
    pub fn prelude_fn(name: &str) -> Option<GhostFn> {
        Some(match name {
            "pow2" => GhostFn::Pow2,
            "log2" => GhostFn::Log2,
            "popcount" => GhostFn::Popcount,
            _ => return None,
        })
    }

    /// The ghost-library definition (`elab/ghost.core`) of a `Nat`
    /// prelude function.
    pub fn nat_def(self) -> Option<&'static str> {
        Some(match self {
            GhostFn::Pow2 => "ghost::pow2",
            GhostFn::Log2 => "ghost::log2",
            GhostFn::Popcount => "ghost::popcount",
            _ => return None,
        })
    }

    /// The `Seq<T>` operation named by method `name` (receiver `Seq<T>`;
    /// `n` is the turbofish length of `chunks_exact`/`to_array`).
    pub fn seq_method(name: &str, n: Option<u64>) -> Option<GhostFn> {
        Some(match name {
            "len" => GhostFn::SLen,
            "get" => GhostFn::SGet,
            "take" => GhostFn::STake,
            "skip" => GhostFn::SSkip,
            "chunks_exact" => GhostFn::SChunks(n?),
            "to_array" => GhostFn::SToArray(n?),
            "append" => GhostFn::SAppend,
            "update" => GhostFn::SUpdate,
            "rev" => GhostFn::SRev,
            _ => return None,
        })
    }

    /// Whether a `Seq` method takes its length as a turbofish.
    pub fn seq_method_takes_const(name: &str) -> bool {
        matches!(name, "chunks_exact" | "to_array")
    }

    /// `Seq::name` (associated functions).
    pub fn seq_assoc(name: &str) -> Option<GhostFn> {
        Some(match name {
            "repeat" => GhostFn::SRepeat,
            "empty" => GhostFn::SEmpty,
            "cons" => GhostFn::SCons,
            _ => return None,
        })
    }

    /// Signature with the type parameter as `Param(0, "T")`.
    pub fn sig(self) -> Sig {
        let t = || Ty::Param(0, "T".into());
        let s = || Ty::slice_ref(t());
        let q = || Ty::Seq(Box::new(t()));
        let (params, ret) = match self {
            GhostFn::SeqLen => (vec![s()], Ty::Int),
            GhostFn::SeqAppend => (vec![s(), s()], s()),
            GhostFn::SeqCons => (vec![t(), s()], s()),
            GhostFn::SeqTake | GhostFn::SeqDrop => (vec![s(), Ty::Int], s()),
            GhostFn::SeqIndex => (vec![s(), Ty::Int], t()),
            GhostFn::SeqUpdate => (vec![s(), Ty::Int, t()], s()),
            GhostFn::SeqRev => (vec![s()], s()),
            GhostFn::SeqReplicate => (vec![Ty::Int, t()], s()),
            GhostFn::SeqEmpty => (vec![], s()),
            GhostFn::Eqb => (vec![t(), t()], Ty::Bool),
            GhostFn::SLen => (vec![q()], Ty::Nat),
            GhostFn::SGet => (vec![q(), Ty::Nat], Ty::option(t())),
            GhostFn::SIndex => (vec![q(), Ty::Nat], t()),
            GhostFn::STake | GhostFn::SSkip => (vec![q(), Ty::Nat], q()),
            GhostFn::SChunks(n) => (vec![q()], Ty::Seq(Box::new(Ty::array(t(), n)))),
            GhostFn::SFlatten(Some(n)) => (vec![Ty::Seq(Box::new(Ty::array(t(), n)))], q()),
            GhostFn::SFlatten(None) => (vec![Ty::Seq(Box::new(q()))], q()),
            GhostFn::SToArray(n) => (vec![q()], Ty::array(t(), n)),
            GhostFn::SRepeat => (vec![t(), Ty::Nat], q()),
            GhostFn::SEmpty => (vec![], q()),
            GhostFn::SCons => (vec![t(), q()], q()),
            GhostFn::SAppend => (vec![q(), q()], q()),
            GhostFn::SUpdate => (vec![q(), Ty::Nat, t()], q()),
            GhostFn::SRev => (vec![q()], q()),
            GhostFn::NMin | GhostFn::NMax => (vec![t(), t()], t()),
            GhostFn::NSatSub => (vec![Ty::Nat, Ty::Nat], Ty::Nat),
            GhostFn::IDivEuclid | GhostFn::IRemEuclid => (vec![Ty::Int, Ty::Int], Ty::Int),
            // defined on every `Int` (1, 0, 0 for `n ≤ 0`), so a `Nat`
            // argument coerces and an `Int` one needs no bound
            GhostFn::Pow2 | GhostFn::Log2 | GhostFn::Popcount => (vec![Ty::Int], Ty::Nat),
        };
        Sig { params, ret }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_mapping() {
        use crate::hir::UintTy::*;
        assert_eq!(of_binary(BinOp::Add, &Ty::Uint(U32), &Ty::Uint(U32)), Some(Builtin::Bin(BinOp::Add, OpTy::Uint(U32))));
        assert_eq!(of_binary(BinOp::Shl, &Ty::Uint(U64), &Ty::Uint(U8)), Some(Builtin::Shift { op: BinOp::Shl, lhs: U64, rhs: U8 }));
        assert_eq!(of_binary(BinOp::Eq, &Ty::array(Ty::u8(), 4), &Ty::array(Ty::u8(), 4)), Some(Builtin::StructEq { ne: false }));
        assert_eq!(of_cast(&Ty::Bool, &Ty::Uint(U8)), Some(Builtin::Cast { from: CastSrc::Bool, to: CastDst::Uint(U8) }));
        assert_eq!(of_index(&Ty::Slice(Box::new(Ty::u8()))).map(|x| x.0), Some(Builtin::Index { array: None }));
    }

    #[test]
    fn spellings() {
        let p = |t: &Ty| match t {
            Ty::Uint(w) => w.name().to_string(),
            _ => "T".into(),
        };
        assert_eq!(Builtin::Int(IntMethod::RotateRight, UintTy::U32).path(&[], &p).unwrap(), "<u32>::rotate_right");
        assert_eq!(Builtin::Int(IntMethod::Min, UintTy::U64).path(&[], &p).unwrap(), "<u64 as ::core::cmp::Ord>::min");
        assert_eq!(Builtin::Slice(SliceMethod::Len).path(&[Ty::u8()], &p).unwrap(), "<[u8]>::len");
        assert_eq!(Builtin::Slice(SliceMethod::SplitFirstChunk(4)).path(&[Ty::u8()], &p).unwrap(), "<[u8]>::split_first_chunk::<4>");
        let s = Builtin::Slice(SliceMethod::SplitFirstChunk(4)).sig(&[Ty::u8()]);
        assert_eq!(s.ret, Ty::option(Ty::Tuple(vec![Ty::reference(Ty::array(Ty::u8(), 4)), Ty::slice_ref(Ty::u8())])));
        assert_eq!(Builtin::Int(IntMethod::ToBeBytes, UintTy::U64).sig(&[]).ret, Ty::array(Ty::u8(), 8));
    }
}
