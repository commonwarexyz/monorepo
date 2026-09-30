//! Bounded, canonical readers — the sandblaster port of `codec.bend`.
//!
//! Every reader takes the unconsumed input and returns the decoded value
//! together with the rest, so the verifier can reject trailing bytes.
//!
//! # Mapping from the Bend source
//!
//! | `codec.bend` | here | note |
//! | --- | --- | --- |
//! | `Parsed<A>` = `Invalid` \| `Parsed{value, rest}` | `Option<(A, &[u8])>` | `None` is `Invalid` |
//! | `bind`, `guard` (continuation combinators) | `?`, `let … else`, `if` | the subset has no closures (§3.1) |
//! | `exact` | [`exact`] | `Some(value)` only when `rest` is empty |
//! | `byte` | [`byte`] | |
//! | `fixed_bytes(n, xs)` | `xs.len() == n` (in `verifier::verify`) | inputs are `u8`, so Bend's `≤ 255` checks hold by type |
//! | `bytes_valid(fuel, xs)` | `xs.len() <= fuel` (in `verifier::verify`) | likewise |
//! | `append` | fixed-size preimage arrays built with `copy_from_slice` | no heap (§3.1) |
//! | `uint.finish`, `uint.go`, `uint` | [`uint_go`], [`uint`] | canonical LEB128 capped at `u32::MAX`: Commonware's `UInt<u32>` (the `usize` codec), used for the digest count; the groups are combined from the last one back, as the spec's `groups` reads them |
//! | — | [`uint64_go`], [`uint64`] | canonical LEB128 `UInt<u64>` (Bend caps every varint at `u32::MAX`; Commonware does not) |
//! | — | [`location`] | Commonware `Location::read`: `UInt<u64>` at most `MAX_LEAVES = 2^62` |
//! | `be64.go`, `be64` | [`be64`] (= `u64::to_be_bytes`) | |
//! | `digest` | [`digest`] | |
//!
//! # Varint rules (Commonware codec/src/varint.rs:118-154 at 6e15fe7c)
//!
//! Little-endian 7-bit groups, `0x80` is the continuation bit. A byte after
//! the first may not be `0x00` (every value has exactly one encoding), and
//! the last byte a type allows may only carry the bits that remain: for
//! `u32` the 5th byte is below 16, for `u64` the 10th byte is exactly `0x01`
//! (one bit; `0x00` is excluded by the previous rule, and a continuation bit
//! would be an eleventh byte). Running out of input rejects.
//!
//! # Obligations
//!
//! [`uint_go`] and [`uint64_go`] are the only functions with a precondition,
//! `fuel <= 5` (resp. `fuel <= 10`), which bounds their recursion depth.
//! `x * 128 + (h - 0x80)` cannot overflow: `x < 2^25 = 0x0200_0000` (resp. `2^57`) and
//! `h - 0x80 < 128` under `h >= 0x80`.

use sandblaster::prelude::*;

use super::merkle::MAX_LEAVES;
use super::sha256::Digest;

/// Keep a decoded value only if the reader consumed its whole input.
/// Bend: `exact`.
pub fn exact<A: Copy>(got: Option<(A, &[u8])>) -> Option<A> {
    match got {
        None => None,
        Some((value, [])) => Some(value),
        Some((_, [_, ..])) => None,
    }
}

/// Read one byte. Bend: `byte`.
pub fn byte(xs: &[u8]) -> Option<(u8, &[u8])> {
    match xs {
        [] => None,
        [head, tail @ ..] => Some((*head, tail)),
    }
}

/// A continuation byte `h` in front of the rest's reading: `h - 0x80 + 128 · x`
/// when the rest read `x < 2^25`, so that the whole fits in 32 bits.
#[requires(h >= 0x80)]
pub(crate) fn uint_more(h: u8, rest: Option<(u32, &[u8])>) -> Option<(u32, &[u8])> {
    match rest {
        None => None,
        Some((x, r)) => {
            if x >= 0x0200_0000 { None } else { Some((x * 128 + (h - 0x80) as u32, r)) }
        }
    }
}

/// Read the groups of a canonical unsigned LEB128 varint whose value fits
/// in a `u32`. Bend: `uint.go`.
///
/// `fuel` is the number of bytes still allowed (5 in total) and `first`
/// whether this is the first byte. A byte `h ≥ 0x80` carries the low seven
/// bits `h - 0x80` and continues: the value is `h - 0x80 + 128 · x` for the
/// value `x` of the rest, which must be below `2^25` for the whole to fit in
/// 32 bits. A byte `h < 0x80` ends the varint with value `h`; it may be zero
/// only as the first byte (minimal encoding). This reads the groups from the
/// last one back, like the spec's `groups`; the check `x < 2^25` is
/// Commonware's "the fifth byte is below 16" (varint.rs:118-154).
#[requires(fuel <= 5)]
#[decreases(fuel, max = 5)]
pub(crate) fn uint_go(fuel: u32, xs: &[u8], first: bool) -> Option<(u32, &[u8])> {
    if fuel == 0 {
        return None;
    }
    match byte(xs) {
        None => None,
        Some((h, rest)) => {
            if h >= 0x80 {
                uint_more(h, uint_go(fuel - 1, rest, false))
            } else if h != 0 || first {
                Some((h as u32, rest))
            } else {
                None
            }
        }
    }
}

/// Read a canonical unsigned LEB128 varint of at most 5 bytes whose value
/// fits in a `u32` (Commonware `UInt<u32>`, the codec of `usize` lengths;
/// capped at `2^32 - 1`). Bend: `uint`. The verifier uses it for the digest
/// count only.
pub fn uint(xs: &[u8]) -> Option<(u32, &[u8])> {
    uint_go(5, xs, true)
}

/// A continuation byte `h` in front of the rest's reading: `h - 0x80 + 128 · x`
/// when the rest read `x < 2^57`, so that the whole fits in 64 bits.
#[requires(h >= 0x80)]
pub(crate) fn uint64_more(h: u8, rest: Option<(u64, &[u8])>) -> Option<(u64, &[u8])> {
    match rest {
        None => None,
        Some((x, r)) => {
            if x >= 0x0200_0000_0000_0000 { None } else { Some((x * 128 + (h - 0x80) as u64, r)) }
        }
    }
}

/// Read the groups of a canonical `UInt<u64>` varint: [`uint_go`] with 10
/// bytes of fuel and 64 bits. The rest's value must be below `2^57`, which is
/// Commonware's "the tenth byte is at most 1".
#[requires(fuel <= 10)]
#[decreases(fuel, max = 10)]
pub(crate) fn uint64_go(fuel: u32, xs: &[u8], first: bool) -> Option<(u64, &[u8])> {
    if fuel == 0 {
        return None;
    }
    match byte(xs) {
        None => None,
        Some((h, rest)) => {
            if h >= 0x80 {
                uint64_more(h, uint64_go(fuel - 1, rest, false))
            } else if h != 0 || first {
                Some((h as u64, rest))
            } else {
                None
            }
        }
    }
}

/// Read a canonical unsigned LEB128 varint of at most 10 bytes (Commonware
/// `UInt<u64>`, any `u64`). Used for the inactive-peak count.
pub fn uint64(xs: &[u8]) -> Option<(u64, &[u8])> {
    uint64_go(10, xs, true)
}

/// Read a tree coordinate: a `UInt<u64>` of at most [`MAX_LEAVES`] = `2^62`
/// (Commonware `Location::read_cfg`, storage/src/merkle/location.rs:200-215).
/// Used for the queried location and the leaf count, which Commonware both
/// decodes as a `Location`.
pub fn location(xs: &[u8]) -> Option<(u64, &[u8])> {
    let (value, rest) = uint64(xs)?;
    if value <= MAX_LEAVES { Some((value, rest)) } else { None }
}

/// The 8-byte big-endian encoding of `value`. Bend: `be64`.
pub fn be64(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

/// Read a 32-byte digest. Bend: `digest` (which also assembles the eight
/// big-endian words).
pub fn digest(xs: &[u8]) -> Option<(Digest, &[u8])> {
    let (head, rest) = xs.split_first_chunk::<32>()?;
    Some((*head, rest))
}
