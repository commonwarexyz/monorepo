//! The lift prelude, exec part (`crate::__lift`; SEMANTICS.md §19). Lifted
//! modules name these instead of `core`'s: the lifted code is checked, never
//! printed, so these types only give `core::result::Result` and
//! `bytes::TryGetError` their meaning in the kernel.

use sandblaster::prelude::*;

/// `core::result::Result`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Result<T: Copy, E: Copy> {
    Ok(T),
    Err(E),
}

/// `bytes::TryGetError`. Lifted code only matches it with `_`, so its fields
/// (the requested and available byte counts) are not modeled.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TryGetError;

// ---------------------------------------------------------------------------
// Signed integers (SEMANTICS.md §19.3): lifted code reads an `iN` as its
// two's complement bits, a distinct type, so that every operation whose
// meaning depends on the sign goes through one of the functions below (or
// is refused by the lift); an operation the lift does not translate does not
// type check.
// ---------------------------------------------------------------------------

/// `i16`: the two's complement bits of the value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct I16(pub u16);

/// `i32`: the two's complement bits of the value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct I32(pub u32);

/// `i64`: the two's complement bits of the value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct I64(pub u64);

/// `x >> k` on `i16`: the arithmetic shift (copies of the sign bit shift
/// in). Rust panics for `k >= 16`: the caller's obligation.
#[requires(k < 16usize)]
pub fn i16_shr(x: I16, k: usize) -> I16 {
    if x.0 >> 15usize == 0u16 { I16(x.0 >> k) } else { I16(!((!x.0) >> k)) }
}

/// `x >> k` on `i32` (see `i16_shr`).
#[requires(k < 32usize)]
pub fn i32_shr(x: I32, k: usize) -> I32 {
    if x.0 >> 31usize == 0u32 { I32(x.0 >> k) } else { I32(!((!x.0) >> k)) }
}

/// `x >> k` on `i64` (see `i16_shr`).
#[requires(k < 64usize)]
pub fn i64_shr(x: I64, k: usize) -> I64 {
    if x.0 >> 63usize == 0u64 { I64(x.0 >> k) } else { I64(!((!x.0) >> k)) }
}

/// `-x` on `i16`: `2^16 - x` (`!x + 1`) for `x != 0`. Rust panics on
/// `i16::MIN`: the caller's obligation.
#[requires(x.0 != 0x8000u16)]
pub fn i16_neg(x: I16) -> I16 {
    if x.0 == 0u16 { x } else { I16((65535u16 - x.0) + 1u16) }
}

/// `-x` on `i32` (see `i16_neg`).
#[requires(x.0 != 0x8000_0000u32)]
pub fn i32_neg(x: I32) -> I32 {
    if x.0 == 0u32 { x } else { I32((4294967295u32 - x.0) + 1u32) }
}

/// `-x` on `i64` (see `i16_neg`).
#[requires(x.0 != 0x8000_0000_0000_0000u64)]
pub fn i64_neg(x: I64) -> I64 {
    if x.0 == 0u64 { x } else { I64((18446744073709551615u64 - x.0) + 1u64) }
}

// ---------------------------------------------------------------------------
// Core items lifted code names (SEMANTICS.md §19.5–§19.9, `docs/mir-lift.md`
// §20.2): markers, the ordering of comparisons, and the iterators the MIR
// reading builds for `RangeInclusive::new` and `core::iter::once` (stepped by
// core's own `next`, whose MIR is read). Each transcribes core's definition.
// ---------------------------------------------------------------------------

/// `core::marker::PhantomData<T>`: a zero-sized marker (the lift erases
/// its type argument; it carries no value).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PhantomData;

/// `core::cmp::Ordering`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ordering {
    Less,
    Equal,
    Greater,
}

/// `PartialOrd::lt`'s definition: `matches!(self.partial_cmp(other), Some(Less))`.
pub fn ord_lt(o: Option<Ordering>) -> bool {
    match o {
        Some(Ordering::Less) => true,
        _ => false,
    }
}

/// `PartialOrd::le`: `matches!(self.partial_cmp(other), Some(Less | Equal))`.
pub fn ord_le(o: Option<Ordering>) -> bool {
    match o {
        Some(Ordering::Less) => true,
        Some(Ordering::Equal) => true,
        _ => false,
    }
}

/// `PartialOrd::gt`: `matches!(self.partial_cmp(other), Some(Greater))`.
pub fn ord_gt(o: Option<Ordering>) -> bool {
    match o {
        Some(Ordering::Greater) => true,
        _ => false,
    }
}

/// `PartialOrd::ge`: `matches!(self.partial_cmp(other), Some(Greater | Equal))`.
pub fn ord_ge(o: Option<Ordering>) -> bool {
    match o {
        Some(Ordering::Greater) => true,
        Some(Ordering::Equal) => true,
        _ => false,
    }
}

/// `core::ops::RangeInclusive<u32>` as an iterator, with core's
/// `exhausted` flag (set by the step that yields `end`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RangeInclusiveU32 {
    pub start: u32,
    pub end: u32,
    pub exhausted: bool,
}

/// `RangeInclusive::new(start, end)`.
pub fn range_inclusive_u32(start: u32, end: u32) -> RangeInclusiveU32 {
    RangeInclusiveU32 { start, end, exhausted: false }
}

/// `core::ops::RangeInclusive<u64>` as an iterator.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RangeInclusiveU64 {
    pub start: u64,
    pub end: u64,
    pub exhausted: bool,
}

/// `RangeInclusive::new(start, end)`.
pub fn range_inclusive_u64(start: u64, end: u64) -> RangeInclusiveU64 {
    RangeInclusiveU64 { start, end, exhausted: false }
}

/// `core::iter::Once<T>`: the value not yet yielded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Once<T: Copy> {
    pub v: Option<T>,
}

/// `core::iter::once(v)`.
pub fn once<T: Copy>(v: T) -> Once<T> {
    Once { v: Some(v) }
}

/// `core::ops::Range<T>` (`start..end`): lifted code reads its fields (and
/// steps it by core's `next`, read from MIR).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Range<T: Copy> {
    pub start: T,
    pub end: T,
}

/// `Iterator::next` of an iterator of byte strings (`E: Iterator<Item:
/// AsRef<[u8]>>` taken as `&mut E`), read as the items not yet yielded, each
/// as the bytes its `as_ref()` returns: the first item, and the rest.
pub fn bytes_iter_next<'a>(it: &'a [&'a [u8]]) -> (&'a [&'a [u8]], Option<&'a [u8]>) {
    match it.split_first() {
        Some((h, t)) => (t, Some(*h)),
        None => (it, None),
    }
}
