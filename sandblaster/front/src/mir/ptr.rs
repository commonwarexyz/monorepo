//! Raw pointers in crate code: the narrow reading of existing `unsafe`
//! (docs/DESIGN-UNSAFE-SIMD.md §1–§2 with its amendments A-S5..A-S9;
//! docs/mir-lift.md §20.10). TRUSTED: it decides which library pointer
//! helpers and which `core::arch` loads and stores the literal reading reads,
//! on which types, and how a value of an admitted type is a byte string.
//! Everything not admitted here stays refused, by name.
//!
//! * **Helpers** ([`helper`], amendment A-S7): the library functions that
//!   form a pointer from a reference, cast one or move one, matched by the
//!   exact path of their definition **and** the instance's exact signature
//!   (parameter and result types, and whether it is a declared `unsafe fn`),
//!   never by name: a same-named function elsewhere, or one of another
//!   signature, is no helper.
//! * **Types** ([`plain`], amendment A-S6): the pointee and base types whose
//!   every byte string of the right length is a value — unsigned integers
//!   (a `u128` as its two 64-bit words, low word first: C4's slice, held,
//!   moved and read through its bytes only), `core::arch` vectors with a
//!   model representation, and arrays of them. They are checked structurally, so they hold no
//!   `UnsafeCell` (a shared pointer's snapshot equals memory at every use,
//!   given the window rule's W3) and no niche (a store cannot forge an
//!   invalid value, and a panic between a load and a store, with a `&mut`
//!   referent partly written, leaves a valid value behind: unwinding is
//!   safe). `bool`, `char`, signed integers, structs, enums, references and
//!   pointers are refused, named.
//! * **Loads and stores** ([`MEM_INTRINSICS`], amendments A-S5 and A-S9):
//!   the `core::arch` intrinsics that read or write memory through a
//!   pointer, each with its byte count and the alignment its contract needs
//!   (every current row: 1, read from stdarch's implementation at the pinned
//!   nightly, re-checked by `tests/unsafe_simd.rs` at every toolchain
//!   bump), and the condition that its validated model is a **pure byte
//!   reinterpretation**: the model's memory type is its vector type and the
//!   model is the identity on it ([`pure_reinterpretation`], checked by the
//!   kernel). That is why the instruction's model and the stdarch
//!   implementation (a byte copy, `read_unaligned`/`write_unaligned`) agree;
//!   a masked, broadcasting, gathering or converting load has no row.

use std::collections::BTreeMap;
use std::rc::Rc;

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{Lvl, Rel};
use sandblaster_kernel::value::{Budget, EnvEntry, VEnv};
use sandblaster_targets::coretext::{CoreModel, CoreTy, Lane};

use super::ir::{Fn, Sbmir, Ty};

/// What an admitted pointer helper does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Helper {
    /// A formation from a reference: `<[T]>::as_ptr` / `as_mut_ptr` of a
    /// slice reference (`slice`), `ptr::from_ref` / `from_mut` of a `&T`.
    Form { mutable: bool, slice: bool },
    /// `cast::<U>()`, `cast_mut()`, `cast_const()`: the same pointer.
    Cast,
    /// `add(k)` (`neg`: `sub(k)`) by a `usize` count, `offset(k)` (`signed`)
    /// by an `isize`: `k · size_of::<T>()` bytes.
    Move { neg: bool, signed: bool },
}

/// The admitted helpers, by the path of their definition (`std::` where a
/// crate with `std` sees it, `core::` in a `no_std` crate): the helper, the
/// parameters' and the result's shapes (`*` a pointer of the helper's
/// mutability, `&` a reference, `[]` a slice reference, `us` `usize`, `is`
/// `isize`), the pointers' mutability (`Some(true)` `*mut`; `None`: the
/// result's is the other), and whether it is a declared `unsafe fn`.
#[allow(clippy::type_complexity)]
const HELPERS: &[(&str, Helper, &str, Option<bool>, bool)] = &[
    ("core::slice::<impl [T]>::as_ptr", Helper::Form { mutable: false, slice: true }, "[] -> *", Some(false), false),
    ("core::slice::<impl [T]>::as_mut_ptr", Helper::Form { mutable: true, slice: true }, "[] -> *", Some(true), false),
    ("std::ptr::from_ref", Helper::Form { mutable: false, slice: false }, "& -> *", Some(false), false),
    ("core::ptr::from_ref", Helper::Form { mutable: false, slice: false }, "& -> *", Some(false), false),
    ("std::ptr::from_mut", Helper::Form { mutable: true, slice: false }, "& -> *", Some(true), false),
    ("core::ptr::from_mut", Helper::Form { mutable: true, slice: false }, "& -> *", Some(true), false),
    ("std::ptr::const_ptr::<impl *const T>::cast", Helper::Cast, "* -> *U", Some(false), false),
    ("core::ptr::const_ptr::<impl *const T>::cast", Helper::Cast, "* -> *U", Some(false), false),
    ("std::ptr::mut_ptr::<impl *mut T>::cast", Helper::Cast, "* -> *U", Some(true), false),
    ("core::ptr::mut_ptr::<impl *mut T>::cast", Helper::Cast, "* -> *U", Some(true), false),
    ("std::ptr::const_ptr::<impl *const T>::cast_mut", Helper::Cast, "* -> *", None, false),
    ("core::ptr::const_ptr::<impl *const T>::cast_mut", Helper::Cast, "* -> *", None, false),
    ("std::ptr::mut_ptr::<impl *mut T>::cast_const", Helper::Cast, "* -> *", None, false),
    ("core::ptr::mut_ptr::<impl *mut T>::cast_const", Helper::Cast, "* -> *", None, false),
    ("std::ptr::const_ptr::<impl *const T>::add", Helper::Move { neg: false, signed: false }, "* us -> *", Some(false), true),
    ("core::ptr::const_ptr::<impl *const T>::add", Helper::Move { neg: false, signed: false }, "* us -> *", Some(false), true),
    ("std::ptr::mut_ptr::<impl *mut T>::add", Helper::Move { neg: false, signed: false }, "* us -> *", Some(true), true),
    ("core::ptr::mut_ptr::<impl *mut T>::add", Helper::Move { neg: false, signed: false }, "* us -> *", Some(true), true),
    ("std::ptr::const_ptr::<impl *const T>::sub", Helper::Move { neg: true, signed: false }, "* us -> *", Some(false), true),
    ("core::ptr::const_ptr::<impl *const T>::sub", Helper::Move { neg: true, signed: false }, "* us -> *", Some(false), true),
    ("std::ptr::mut_ptr::<impl *mut T>::sub", Helper::Move { neg: true, signed: false }, "* us -> *", Some(true), true),
    ("core::ptr::mut_ptr::<impl *mut T>::sub", Helper::Move { neg: true, signed: false }, "* us -> *", Some(true), true),
    ("std::ptr::const_ptr::<impl *const T>::offset", Helper::Move { neg: false, signed: true }, "* is -> *", Some(false), true),
    ("core::ptr::const_ptr::<impl *const T>::offset", Helper::Move { neg: false, signed: true }, "* is -> *", Some(false), true),
    ("std::ptr::mut_ptr::<impl *mut T>::offset", Helper::Move { neg: false, signed: true }, "* is -> *", Some(true), true),
    ("core::ptr::mut_ptr::<impl *mut T>::offset", Helper::Move { neg: false, signed: true }, "* is -> *", Some(true), true),
];

/// The admitted helpers' definition paths (printed on the record).
pub fn helper_paths() -> Vec<&'static str> {
    HELPERS.iter().map(|h| h.0).collect()
}

/// An admitted helper `f` (an instance whose definition is in the table):
/// `None` when `f` is no helper; `Some(Err)` when its definition is in the
/// table but the instance's signature is not the admitted one, or a type it
/// moves through is not admitted (refused, named); `Some(Ok((helper,
/// pointee)))` else, `pointee` the type of the pointer it returns.
pub fn helper(f: &Fn) -> Option<Result<(Helper, Ty), String>> {
    let (path, h, shape, mutability, unsafe_fn) = HELPERS.iter().find(|r| r.0 == f.def)?;
    Some((|| {
        let bad = |why: &str| Err(format!("`{path}` at {:?}: {why} (an admitted pointer helper is matched by its exact path and signature, docs/DESIGN-UNSAFE-SIMD.md A-S7)", f.args));
        if f.unsafe_fn != *unsafe_fn {
            return bad(if *unsafe_fn { "not a declared `unsafe fn`" } else { "a declared `unsafe fn`" });
        }
        let (params, ret) = shape.split_once(" -> ").unwrap_or((shape, ""));
        let params: Vec<&str> = params.split(' ').collect();
        if f.argc != params.len() || f.locals.len() <= f.argc {
            return bad("another number of parameters");
        }
        let ty = |i: usize| &f.locals[i].0;
        let (rm, rp) = match ty(0) {
            Ty::Ptr(m, p) => (*m, (**p).clone()),
            other => return bad(&format!("returns {other:?}, not a pointer")),
        };
        let ptr_mut = mutability.unwrap_or(!rm);
        if mutability.is_some() && rm != ptr_mut {
            return bad("returns a pointer of the other mutability");
        }
        if mutability.is_none() && rm == ptr_mut {
            return bad("returns a pointer of the same mutability");
        }
        let mut pointee: Option<Ty> = None;
        for (i, p) in params.iter().enumerate() {
            let t = ty(i + 1);
            let ok = match (*p, t) {
                ("[]", Ty::Ref(m, s)) if *m == ptr_mut => match &**s {
                    Ty::Slice(e) => {
                        pointee = Some((**e).clone());
                        true
                    }
                    _ => false,
                },
                ("&", Ty::Ref(m, e)) if *m == ptr_mut => {
                    pointee = Some((**e).clone());
                    true
                }
                ("*", Ty::Ptr(m, e)) if *m == ptr_mut => {
                    pointee = Some((**e).clone());
                    true
                }
                ("us", Ty::Int(false, 0)) | ("is", Ty::Int(true, 0)) => true,
                _ => false,
            };
            if !ok {
                return bad(&format!("parameter {} of type {t:?}, not the admitted `{p}`", i + 1));
            }
        }
        let pointee = pointee.ok_or("no pointer parameter")?;
        // the result points to the same type, but for `cast::<U>()`
        if ret != "*U" && rp != pointee {
            return bad(&format!("returns a pointer to {rp:?}, not to {pointee:?}"));
        }
        plain(&pointee).map_err(|e| format!("`{path}` on {pointee:?}: {e}"))?;
        plain(&rp).map_err(|e| format!("`{path}` to {rp:?}: {e}"))?;
        Ok((*h, rp))
    })())
}

/// Whether every byte string of a value of `t`'s size is a value of `t`, and
/// `t` holds no interior mutability (amendment A-S6): the admitted pointee
/// and base types. A reason when not.
pub fn plain(t: &Ty) -> Result<(), String> {
    match t {
        Ty::Int(false, 8 | 16 | 32 | 64 | 0) => Ok(()),
        // (C4's slice: a `u128` is held as its two 64-bit words, every byte
        // string of 16 bytes is one, `bytes_text`)
        Ty::Int(false, 128) => Ok(()),
        Ty::Int(true, _) => Err("a signed integer is not admitted as a pointee (docs/DESIGN-UNSAFE-SIMD.md §1.2)".into()),
        Ty::Bool => Err("`bool` has a niche (only the bytes 0 and 1 are values): its bytes are no plain reinterpretation, and a store could forge an invalid value (A-S6)".into()),
        Ty::Char => Err("`char` has a niche: its bytes are no plain reinterpretation (A-S6)".into()),
        Ty::Simd(p, l, n) => super::arch::vector(p, l, *n).map(|_| ()),
        Ty::Array(e, _) => plain(e),
        Ty::Adt(k) if k.contains("UnsafeCell") || k.contains("Cell<") => Err(format!("`{k}` has interior mutability: a shared pointer's snapshot would not equal memory (A-S6)")),
        Ty::Adt(k) => Err(format!("`{k}`: structs and enums are not admitted as pointees (their niches and padding are not checked)")),
        Ty::Ref(..) | Ty::Ptr(..) => Err("a reference or pointer is not admitted as a pointee".into()),
        other => Err(format!("{other:?} is not admitted as a pointee")),
    }
}

/// The size in bytes of an admitted type (`None` for a slice).
pub fn size_of(t: &Ty) -> Option<u64> {
    Some(match t {
        Ty::Int(false, 0) => 8,
        Ty::Int(false, b) if matches!(b, 8 | 16 | 32 | 64 | 128) => *b as u64 / 8,
        Ty::Simd(p, l, n) => match super::arch::vector(p, l, *n).ok()? {
            CoreTy::Vector(lane, k) => lane.bits() as u64 / 8 * k as u64,
            CoreTy::Word(_) => return None,
        },
        Ty::Array(e, n) => size_of(e)? * n,
        _ => return None,
    })
}

/// The kernel type of a word (`U8`..`U64`, `Usize`).
fn word(t: &Ty) -> Option<&'static str> {
    Some(match t {
        Ty::Int(false, 8) => "U8",
        Ty::Int(false, 16) => "U16",
        Ty::Int(false, 32) => "U32",
        Ty::Int(false, 64) => "U64",
        Ty::Int(false, 0) => "Usize",
        _ => return None,
    })
}

/// The element type and length of an admitted array or vector (a vector is
/// its model representation, `Array lane n`), as MIR types.
fn elems(t: &Ty) -> Option<(Ty, u64)> {
    match t {
        Ty::Array(e, n) => Some(((**e).clone(), *n)),
        Ty::Simd(p, l, n) => match super::arch::vector(p, l, *n).ok()? {
            CoreTy::Vector(lane, k) => Some((Ty::Int(false, lane.bits()), k as u64)),
            CoreTy::Word(_) => None,
        },
        _ => None,
    }
}

/// The kernel type text of an admitted type (`ty` of `literal.rs` agrees).
pub fn ty_text(t: &Ty) -> Result<String, String> {
    if let Some(w) = word(t) {
        return Ok(w.into());
    }
    if *t == Ty::Int(false, 128) {
        return Ok(super::literal::U128_PAIR.into());
    }
    if let Some((e, n)) = elems(t) {
        return Ok(format!("(Array {} {n}usize)", ty_text(&e)?));
    }
    match t {
        Ty::Slice(e) => Ok(format!("(Slice {})", ty_text(e)?)),
        other => Err(format!("{other:?} has no byte view")),
    }
}

/// `bytes_T(x)`: the little-endian bytes of `x : T` as a `List(U8)` term
/// (docs/DESIGN-UNSAFE-SIMD.md §2.2): a byte itself; a word's
/// `to_le_bytes`; an array's (a vector's lanes') elements in order, element
/// 0 first, through the array's eta-expansion `mem::elems`; a slice's
/// elements in order.
pub fn bytes_text(t: &Ty, x: &str) -> Result<String, String> {
    plain_or_slice(t)?;
    Ok(match t {
        Ty::Int(false, 8) => format!("Cons[U8]({x}, Nil[U8])"),
        Ty::Int(false, b @ (16 | 32 | 64)) => format!("fst(u{b}::to_le_bytes {x})"),
        Ty::Int(false, 0) => format!("fst(u64::to_le_bytes (#cast_usize_u64({x})))"),
        // a `u128`'s low word's bytes, then its high word's (`u128::to_le_bytes`);
        // each word projected inside (`to_le_bytes` of it is the list of its
        // eight bytes, whatever the word: a spine of sixteen)
        Ty::Int(false, 128) => {
            let word = |k: usize| format!("fst(u64::to_le_bytes (match {x} : Tuple2(U64, U64) as _ return U64 with | tuple2(lo, hi) => {} end))", ["lo", "hi"][k]);
            format!("seq::append U8 ({}) ({})", word(0), word(1))
        }
        Ty::Slice(e) => {
            let et = ty_text(e)?;
            format!("mem::slice_elems {et} U8 (fun (y : {et}) => {}) {x} 0usize (#cast_usize_int(fst({x})))", bytes_text(e, "y")?)
        }
        _ => {
            let (e, n) = elems(t).ok_or_else(|| format!("{t:?} has no byte view"))?;
            let et = ty_text(&e)?;
            format!("mem::elems {et} {n}usize U8 (fun (y : {et}) => {}) {x} 0usize {n}int", bytes_text(&e, "y")?)
        }
    })
}

/// `of_bytes_T(bs)`: the value of `T` whose bytes are `bs`, an `Option(T)`
/// term (`None` unless `bs` has the type's size; every byte string of that
/// size is a value of an admitted type). A slice's length is `len`'s (a
/// write keeps a slice's length).
pub fn of_bytes_text(t: &Ty, bs: &str, len: Option<&str>) -> Result<String, String> {
    plain_or_slice(t)?;
    Ok(match t {
        Ty::Int(false, 8) => format!("mem::one U8 ({bs})"),
        Ty::Int(false, b @ (16 | 32 | 64)) => {
            let n = b / 8;
            format!("mir::map (Array U8 {n}usize) U{b} (mem::arr_of_list U8 {n}usize ({bs})) (fun (a : Array U8 {n}usize) => u{b}::from_le_bytes a)")
        }
        Ty::Int(false, 0) => format!("mir::map (Array U8 8usize) Usize (mem::arr_of_list U8 8usize ({bs})) (fun (a : Array U8 8usize) => #cast_u64_usize(u64::from_le_bytes a))"),
        // the low word from the first 8 bytes, the high word from exactly 8 more
        Ty::Int(false, 128) => format!("mir::bind (Array U8 8usize) (Tuple2(U64, U64)) (mem::arr_of_list U8 8usize (seq::take U8 ({bs}) 8int)) (fun (a : Array U8 8usize) => mir::map (Array U8 8usize) (Tuple2(U64, U64)) (mem::arr_of_list U8 8usize (seq::drop U8 ({bs}) 8int)) (fun (b : Array U8 8usize) => tuple2[U64, U64](u64::from_le_bytes a, u64::from_le_bytes b)))"),
        Ty::Slice(e) => {
            let et = ty_text(e)?;
            let k = size_of(e).ok_or("a slice of slices")?;
            let len = len.ok_or("a slice's length")?;
            let l = format!("mem::pieces {et} {k}int (fun (b : List(U8)) => {}) (#cast_usize_int({len})) ({bs})", of_bytes_text(e, "b", None)?);
            format!("mir::bind (List({et})) (Slice {et}) ({l}) (fun (l : List({et})) => mem::slice_of_list {et} {len} l)")
        }
        _ => {
            let (e, n) = elems(t).ok_or_else(|| format!("{t:?} has no byte view"))?;
            let et = ty_text(&e)?;
            if e == Ty::Int(false, 8) {
                // (a byte array is its own list: the terms stay small)
                format!("mem::arr_of_list U8 {n}usize ({bs})")
            } else {
                let k = size_of(&e).ok_or("an element without a size")?;
                let l = format!("mem::pieces {et} {k}int (fun (b : List(U8)) => {}) {n}int ({bs})", of_bytes_text(&e, "b", None)?);
                format!("mir::bind (List({et})) (Array {et} {n}usize) ({l}) (fun (l : List({et})) => mem::arr_of_list {et} {n}usize l)")
            }
        }
    })
}

fn plain_or_slice(t: &Ty) -> Result<(), String> {
    match t {
        Ty::Slice(e) => plain(e),
        t => plain(t),
    }
}

/// A `core::arch` intrinsic that reads or writes memory through a pointer
/// (amendments A-S5, A-S9).
#[derive(Clone, Copy, Debug)]
pub struct MemIntrinsic {
    /// Its public path.
    pub path: &'static str,
    /// A store (its arguments: the pointer, then the vector); else a load
    /// (the pointer; its result the vector).
    pub store: bool,
    /// The bytes it reads or writes.
    pub bytes: u64,
    /// The alignment its pointer needs (1: unaligned).
    pub align: u64,
    /// Where the alignment was read: stdarch's implementation at the pinned
    /// nightly (`tests/unsafe_simd.rs` re-reads it at every toolchain bump).
    pub source: &'static str,
}

/// The admitted loads and stores. Aligned, masked, broadcasting, gathering,
/// scattering, non-temporal and interleaving forms have no row (refused).
pub const MEM_INTRINSICS: &[MemIntrinsic] = &[
    MemIntrinsic { path: "core::arch::aarch64::vld1q_u8", store: false, bytes: 16, align: 1, source: "aarch64/neon/generated.rs: read_unaligned" },
    MemIntrinsic { path: "core::arch::aarch64::vst1q_u8", store: true, bytes: 16, align: 1, source: "aarch64/neon/generated.rs: write_unaligned" },
    MemIntrinsic { path: "core::arch::aarch64::vld1q_u32", store: false, bytes: 16, align: 1, source: "aarch64/neon/generated.rs: read_unaligned" },
    MemIntrinsic { path: "core::arch::aarch64::vst1q_u32", store: true, bytes: 16, align: 1, source: "aarch64/neon/generated.rs: write_unaligned" },
    MemIntrinsic { path: "core::arch::aarch64::vld1q_u64", store: false, bytes: 16, align: 1, source: "aarch64/neon/generated.rs: read_unaligned" },
    MemIntrinsic { path: "core::arch::aarch64::vst1q_u64", store: true, bytes: 16, align: 1, source: "aarch64/neon/generated.rs: write_unaligned" },
    MemIntrinsic { path: "core::arch::aarch64::vld1_u8", store: false, bytes: 8, align: 1, source: "aarch64/neon/generated.rs: read_unaligned" },
    MemIntrinsic { path: "core::arch::x86_64::_mm_loadu_si128", store: false, bytes: 16, align: 1, source: "x86/sse2.rs: copy_nonoverlapping of bytes" },
    MemIntrinsic { path: "core::arch::x86_64::_mm_storeu_si128", store: true, bytes: 16, align: 1, source: "x86/sse2.rs: write_unaligned" },
    MemIntrinsic { path: "core::arch::x86_64::_mm256_loadu_si256", store: false, bytes: 32, align: 1, source: "x86/avx.rs: copy_nonoverlapping of bytes" },
    MemIntrinsic { path: "core::arch::x86_64::_mm256_storeu_si256", store: true, bytes: 32, align: 1, source: "x86/avx.rs: write_unaligned" },
    MemIntrinsic { path: "core::arch::x86_64::_mm512_loadu_si512", store: false, bytes: 64, align: 1, source: "x86/avx512f.rs: read_unaligned" },
    MemIntrinsic { path: "core::arch::x86_64::_mm512_storeu_si512", store: true, bytes: 64, align: 1, source: "x86/avx512f.rs: write_unaligned" },
];

/// The admitted load or store of a path.
pub fn mem_intrinsic(path: &str) -> Option<&'static MemIntrinsic> {
    MEM_INTRINSICS.iter().find(|r| r.path == path)
}

/// The memory type of a load or store row as its validated model takes it
/// (a load's parameter, a store's result: the bytes it reads or writes, as
/// the model's lanes), when the model is a **pure byte reinterpretation**
/// (amendment A-S9): its memory type is its vector type, of the row's byte
/// count, and the model is the identity on it — the kernel checks that the
/// model's body, applied to a fresh variable, is that variable. So the
/// validated instruction model and stdarch's byte-copy implementation agree:
/// both give the bytes at the address, reinterpreted.
pub fn pure_reinterpretation(env: &Env, cm: &CoreModel, row: &MemIntrinsic) -> Result<(Lane, u32), String> {
    let (mem, vec) = match (row.store, cm.params) {
        (false, [(_, m)]) => (*m, cm.ret),
        (true, [(_, v)]) => (cm.ret, *v),
        _ => return Err(format!("the model of `{}` does not take one {}", row.path, if row.store { "vector" } else { "memory argument" })),
    };
    let CoreTy::Vector(lane, n) = mem else { return Err(format!("the model of `{}` takes a word, not memory", row.path)) };
    if mem != vec {
        return Err(format!("the model of `{}` changes the type of the bytes ({} to {}): not a pure byte reinterpretation (A-S9)", row.path, mem.text(), vec.text()));
    }
    if lane.bits() as u64 / 8 * n as u64 != row.bytes {
        return Err(format!("the model of `{}` reads {} bytes, its row {}", row.path, lane.bits() as u64 / 8 * n as u64, row.bytes));
    }
    // the identity: `model x ≡ x` for a fresh `x` of the memory type
    let g = env.lookup_global(cm.global).ok_or_else(|| format!("the model `{}` is not loaded", cm.global))?;
    let body = env.global_body(g).ok_or_else(|| format!("the model `{}` has no body", cm.global))?;
    let mty = env.parse_term(&[], &mem.text()).map_err(|e| format!("{}: {e}", mem.text()))?;
    let mut b = Budget { steps: 50_000_000 };
    let mtv = env.eval(&VEnv::default(), Lvl(0), &mty, &mut b).map_err(|e| format!("{e:?}"))?;
    let x = env.fresh_var(Lvl(0), Rel::Rel, &mtv);
    let xv = match &x {
        EnvEntry::Rel(v) => v.clone(),
        _ => return Err("a fresh variable".into()),
    };
    let app = sandblaster_kernel::util::mk::app(body, sandblaster_kernel::util::mk::var(0));
    let got = env.eval(&VEnv(Rc::new(vec![x])), Lvl(1), &app, &mut b).map_err(|e| format!("the model of `{}` applied: {e:?}", row.path))?;
    if !env.conv(Lvl(1), &got, &xv, &mut b).map_err(|e| format!("{e:?}"))? {
        return Err(format!("the model of `{}` is not the identity on its {} bytes: not a pure byte reinterpretation (A-S9)", row.path, row.bytes));
    }
    Ok((lane, n))
}

/// The admitted pointer derivation at a point of `f` (a statement `i <
/// stmts.len()` of block `b`, or its terminator): `(source local,
/// destination local)` — a copy or move of a pointer into a pointer local, a
/// `PtrToPtr` cast, an `Offset`, a call of an admitted `cast`/`add`/`sub`/
/// `offset` helper.
pub fn derivation(m: &Sbmir, f: &Fn, b: usize, i: usize) -> Option<(usize, usize)> {
    use super::ir::{Callee, Operand, Rvalue, Stmt, Term};
    let bl = f.blocks.get(b)?;
    let plain_local = |o: &Operand| match o {
        Operand::Copy(q) | Operand::Move(q) if q.proj.is_empty() => Some(q.local),
        _ => None,
    };
    let is_ptr = |l: usize| matches!(f.locals.get(l), Some((Ty::Ptr(..), _)));
    if i < bl.stmts.len() {
        let Stmt::Assign(d, rv, _) = &bl.stmts[i] else { return None };
        if !d.proj.is_empty() || !is_ptr(d.local) {
            return None;
        }
        let src = match rv {
            Rvalue::Use(o) => plain_local(o),
            Rvalue::Cast(k, o, _) if k == "ptr-to-ptr" => plain_local(o),
            Rvalue::Bin(op, a, _) if op == "offset" => plain_local(a),
            _ => None,
        }?;
        return is_ptr(src).then_some((src, d.local));
    }
    if let Term::Call(Callee::Fn(k), args, d, _) = &bl.term
        && d.proj.is_empty()
        && let Some(g) = m.fns.get(k)
        && let Some(Ok((Helper::Cast | Helper::Move { .. }, _))) = helper(g)
        && let Some(src) = args.first().and_then(plain_local)
    {
        return is_ptr(src).then_some((src, d.local));
    }
    None
}

/// A pointer local's base, as its family's one formation gives it (the
/// window rule refuses a local of two families): the base's type (an
/// array's when the reference was an array's, looked through one `unsize`)
/// and whether the formation is mutable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Base {
    pub ty: Ty,
    pub mutable: bool,
}

/// The base of every pointer local of `f` reached from a formation (none for
/// a pointer local reached from none, such as a parameter; a reason for one
/// reached from two bases).
pub fn bases(m: &Sbmir, f: &Fn) -> BTreeMap<usize, Result<Base, String>> {
    use super::ir::{Callee, Operand, Rvalue, Stmt, Term};
    let mut out: BTreeMap<usize, Result<Base, String>> = BTreeMap::new();
    let put = |out: &mut BTreeMap<usize, Result<Base, String>>, l: usize, b: Result<Base, String>| match out.get(&l) {
        Some(Ok(old)) if b.as_ref().is_ok_and(|n| n != old) => {
            out.insert(l, Err(format!("the pointer local `_{l}` has two bases")));
        }
        Some(Err(_)) => {}
        _ => {
            out.insert(l, b);
        }
    };
    // a reference local's array type when every assignment of it is an
    // `unsize` of a reference to `[T; N]` (the same `N`)
    let unsized_from = |a: usize| -> Option<Ty> {
        let mut found: Option<Ty> = None;
        for bl in &f.blocks {
            for s in &bl.stmts {
                if let Stmt::Assign(d, rv, _) = s
                    && d.local == a
                {
                    let src = match rv {
                        Rvalue::Cast(k, Operand::Copy(q) | Operand::Move(q), _) if k == "unsize" && q.proj.is_empty() => q.local,
                        _ => return None,
                    };
                    let Some((Ty::Ref(_, inner), _)) = f.locals.get(src) else { return None };
                    let Ty::Array(..) = &**inner else { return None };
                    if found.as_ref().is_some_and(|t| t != &**inner) {
                        return None;
                    }
                    found = Some((**inner).clone());
                }
            }
            if let Term::Call(_, _, d, _) = &bl.term
                && d.local == a
            {
                return None;
            }
        }
        found
    };
    let ty_of = |p: &super::ir::Place| -> Option<Ty> {
        let mut t = f.locals.get(p.local)?.0.clone();
        for pr in &p.proj {
            t = match (pr, t) {
                (super::ir::Proj::Deref, Ty::Ref(_, inner)) => *inner,
                (super::ir::Proj::Field(_, ft), _) => ft.clone(),
                (super::ir::Proj::Index(_), Ty::Array(e, _) | Ty::Slice(e)) => *e,
                (super::ir::Proj::Downcast(_), t) => t,
                _ => return None,
            };
        }
        Some(t)
    };
    for (b, bl) in f.blocks.iter().enumerate() {
        for s in &bl.stmts {
            if let Stmt::Assign(d, Rvalue::AddrOf(mt, pl), _) = s
                && d.proj.is_empty()
            {
                let base = ty_of(pl).ok_or_else(|| "the type of the place whose address is taken".to_string()).and_then(|t| plain_or_slice(&t).map(|_| t));
                put(&mut out, d.local, base.map(|ty| Base { ty, mutable: *mt }));
            }
        }
        if let Term::Call(Callee::Fn(k), args, d, _) = &bl.term
            && d.proj.is_empty()
            && let Some(g) = m.fns.get(k)
            && let Some(h) = helper(g)
        {
            let base = match h {
                Ok((Helper::Form { mutable, slice }, pointee)) => {
                    let a = match args.first() {
                        Some(Operand::Copy(q) | Operand::Move(q)) if q.proj.is_empty() => Some(q.local),
                        _ => None,
                    };
                    let ty = match (slice, a.and_then(unsized_from)) {
                        (true, Some(arr)) => arr,
                        (true, None) => Ty::Slice(Box::new(pointee)),
                        (false, _) => pointee,
                    };
                    Some(Ok(Base { ty, mutable }))
                }
                Ok(_) => None,
                Err(e) => Some(Err(e)),
            };
            if let Some(base) = base {
                put(&mut out, d.local, base);
            }
        }
        let _ = b;
    }
    // derivations carry the base on
    loop {
        let mut changed = false;
        for b in 0..f.blocks.len() {
            for i in 0..=f.blocks[b].stmts.len() {
                if let Some((src, dst)) = derivation(m, f, b, i)
                    && let Some(base) = out.get(&src).cloned()
                {
                    let before = out.get(&dst).cloned();
                    put(&mut out, dst, base);
                    changed |= out.get(&dst) != before.as_ref();
                }
            }
        }
        if !changed {
            break;
        }
    }
    out
}
