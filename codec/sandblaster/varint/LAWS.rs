//! What commonware-codec's varint guarantees, for `varint.rs` exactly as
//! written. Claims only; PROOF.rs proves them at every width the sealed
//! trait admits.
//!
//! `UInt(x).write(buf)` appends `x` in LEB128; `UInt::read_cfg(buf)` takes
//! one LEB128 value off the front of `buf`; `encode_size` says how many
//! bytes `write` appends.

use sandblaster::prelude::*;
use crate::varint::{SInt, SPrim, UInt, UPrim};
use crate::Error;

/// LEB128: seven bits per byte, least significant group first, 0x80 set on
/// every byte but the last.
#[spec]
#[decreases(x)]
#[example(varint(0) == seq![0u8] && varint(127) == seq![0x7Fu8] && varint(128) == seq![0x80u8, 0x01u8])]
#[example(varint(300) == seq![0xACu8, 0x02u8] && varint(16384) == seq![0x80u8, 0x80u8, 0x01u8])]
pub fn varint(x: Nat) -> Seq<u8> {
    if x < 128 { seq![x as u8] } else { seq![(128 + x % 128) as u8, ..varint(x / 128)] }
}

/// The wire format: `write` appends the LEB128 encoding of the value.
#[law]
fn write_appends_leb128<T: UPrim>(v: UInt<T>, buf: Seq<u8>) {
    ensures({ let mut b = buf; v.write(&mut b); b } == seq![..buf, ..varint(v.0 as Nat)]);
}

/// `encode_size` is the number of bytes `write` appends, at most ⌈bits/7⌉.
#[law]
fn encode_size_counts_bytes<T: UPrim>(v: UInt<T>) {
    ensures(v.encode_size() as Nat == varint(v.0 as Nat).len() && v.encode_size() as Nat <= (8 * T::SIZE as Nat + 6) / 7);
}

/// Round trip: reading the encoding of a value of the type (a number below
/// 2^bits), followed by anything, returns the value and leaves exactly the
/// bytes after it.
#[law]
fn read_round_trips<T: UPrim>(x: Nat, rest: Seq<u8>) {
    requires((x as Int) < pow2(8 * (T::SIZE as Int)));
    ensures({ let mut b = seq![..varint(x), ..rest]; let r = UInt::<T>::read_cfg(&mut b, &()); (r, b) } == (Ok(UInt(x as T)), rest));
}

/// Canonicity: a read succeeds only on the encoding of the value it returns,
/// followed by the bytes it leaves. So every value has exactly one
/// encoding, and no other bytes decode.
#[law]
fn read_accepts_only_encodings<T: UPrim>(bytes: Seq<u8>, x: T, rest: Seq<u8>) {
    requires({ let mut b = bytes; let r = UInt::<T>::read_cfg(&mut b, &()); (r, b) } == (Ok(UInt(x)), rest));
    ensures(bytes == seq![..varint(x as Nat), ..rest]);
}

/// A read runs out of input (`EndOfBuffer`) on every proper prefix of an
/// encoding: bytes that more bytes would complete to the encoding of a
/// value of the type.
#[law]
fn read_end_of_buffer_on_prefixes<T: UPrim>(bytes: Seq<u8>, x: Nat, more: Seq<u8>) {
    requires((x as Int) < pow2(8 * (T::SIZE as Int)));
    requires(more.len() > 0);
    requires(seq![..bytes, ..more] == varint(x));
    ensures({ let mut b = bytes; UInt::<T>::read_cfg(&mut b, &()) } == Err(Error::EndOfBuffer));
}

/// A read runs out of input only on a proper prefix of an encoding: it has
/// then consumed all of its input, and one more byte (1) would complete the
/// bytes to the encoding of a value of the type.
#[law]
fn read_end_of_buffer_only_on_prefixes<T: UPrim>(bytes: Seq<u8>) {
    requires({ let mut b = bytes; UInt::<T>::read_cfg(&mut b, &()) } == Err(Error::EndOfBuffer));
    ensures({ let mut b = bytes; let r = UInt::<T>::read_cfg(&mut b, &()); b } == seq![]
        && exists(|x: Nat| (x as Int) < pow2(8 * (T::SIZE as Int)) && seq![..bytes, 1u8] == varint(x)));
}

/// A read stops at the first byte that makes its input invalid: when some
/// bytes `p` are an incomplete encoding (a read of them runs out of input)
/// and one more byte `d` makes them invalid, a read of any bytes that start
/// with `p` and `d` fails there with the same error and leaves everything
/// after `d`.
#[law]
fn read_invalid_stops_at_the_deciding_byte<T: UPrim>(bytes: Seq<u8>, p: Seq<u8>, d: u8, rest: Seq<u8>, n: usize) {
    requires(bytes == seq![..p, d, ..rest]);
    requires({ let mut q = p; UInt::<T>::read_cfg(&mut q, &()) } == Err(Error::EndOfBuffer));
    requires({ let mut q = seq![..p, d]; UInt::<T>::read_cfg(&mut q, &()) } == Err(Error::InvalidVarint(n)));
    ensures({ let mut b = bytes; let r = UInt::<T>::read_cfg(&mut b, &()); (r, b) } == (Err(Error::InvalidVarint(n)), rest));
}

/// Any other failure is `InvalidVarint` with the type's byte width.
#[law]
fn read_errors_are_classified<T: UPrim>(bytes: Seq<u8>, e: Error) {
    requires({ let mut b = bytes; UInt::<T>::read_cfg(&mut b, &()) } == Err(e));
    ensures(e == Error::EndOfBuffer || e == Error::InvalidVarint(T::SIZE));
}

// ---------------------------------------------------------------------------
// Signed integers: ZigZag, then LEB128
// ---------------------------------------------------------------------------

/// ZigZag: 0, -1, 1, -2, 2, .. to 0, 1, 2, 3, 4, ..: a non-negative `i` to
/// `2i`, a negative `i` to `-2i - 1`.
#[spec]
#[opaque]
#[example(zigzag(0) == 0 && zigzag(-1) == 1 && zigzag(1) == 2 && zigzag(-2) == 3 && zigzag(2) == 4)]
#[example(zigzag(32767) == 65534 && zigzag(-32768) == 65535 && zigzag(-2147483648) == 4294967295)]
pub fn zigzag(i: Int) -> Nat {
    if i >= 0 { (2 * i) as Nat } else { (-2 * i - 1) as Nat }
}

/// The wire format of a signed value: `SInt(x).write(buf)` appends the
/// LEB128 encoding of the ZigZag of `x`.
#[law]
fn write_signed_appends_zigzag<S: SPrim>(v: SInt<S>, buf: Seq<u8>) {
    ensures({ let mut b = buf; v.write(&mut b); b } == seq![..buf, ..varint(zigzag(v.0 as Int))]);
}

/// `encode_size` of a signed value is the number of bytes `write` appends,
/// at most ⌈bits/7⌉.
#[law]
fn encode_size_signed_counts_bytes<S: SPrim>(v: SInt<S>) {
    ensures(v.encode_size() as Nat == varint(zigzag(v.0 as Int)).len() && v.encode_size() as Nat <= (8 * S::SIZE as Nat + 6) / 7);
}

/// Round trip: reading the encoding of the ZigZag of a value, followed by
/// anything, returns the value and leaves exactly the bytes after it.
#[law]
fn read_signed_round_trips<S: SPrim>(x: S, rest: Seq<u8>) {
    ensures({ let mut b = seq![..varint(zigzag(x as Int)), ..rest]; let r = SInt::<S>::read_cfg(&mut b, &()); (r, b) } == (Ok(SInt(x)), rest));
}

/// Canonicity: a read succeeds only on the encoding of the ZigZag of the
/// value it returns, followed by the bytes it leaves.
#[law]
fn read_signed_accepts_only_encodings<S: SPrim>(bytes: Seq<u8>, x: S, rest: Seq<u8>) {
    requires({ let mut b = bytes; let r = SInt::<S>::read_cfg(&mut b, &()); (r, b) } == (Ok(SInt(x)), rest));
    ensures(bytes == seq![..varint(zigzag(x as Int)), ..rest]);
}

/// A read runs out of input on every proper prefix of an encoding of a
/// number of the type's width (every such number is the ZigZag of a value).
#[law]
fn read_signed_end_of_buffer_on_prefixes<S: SPrim>(bytes: Seq<u8>, x: Nat, more: Seq<u8>) {
    requires((x as Int) < pow2(8 * (S::SIZE as Int)));
    requires(more.len() > 0);
    requires(seq![..bytes, ..more] == varint(x));
    ensures({ let mut b = bytes; SInt::<S>::read_cfg(&mut b, &()) } == Err(Error::EndOfBuffer));
}

/// A read runs out of input only on a proper prefix of an encoding: it has
/// then consumed all of its input, and one more byte (1) would complete it.
#[law]
fn read_signed_end_of_buffer_only_on_prefixes<S: SPrim>(bytes: Seq<u8>) {
    requires({ let mut b = bytes; SInt::<S>::read_cfg(&mut b, &()) } == Err(Error::EndOfBuffer));
    ensures({ let mut b = bytes; let r = SInt::<S>::read_cfg(&mut b, &()); b } == seq![]
        && exists(|x: Nat| (x as Int) < pow2(8 * (S::SIZE as Int)) && seq![..bytes, 1u8] == varint(x)));
}

/// A read stops at the first byte that makes its input invalid, leaving
/// everything after it.
#[law]
fn read_signed_invalid_stops_at_the_deciding_byte<S: SPrim>(bytes: Seq<u8>, p: Seq<u8>, d: u8, rest: Seq<u8>, n: usize) {
    requires(bytes == seq![..p, d, ..rest]);
    requires({ let mut q = p; SInt::<S>::read_cfg(&mut q, &()) } == Err(Error::EndOfBuffer));
    requires({ let mut q = seq![..p, d]; SInt::<S>::read_cfg(&mut q, &()) } == Err(Error::InvalidVarint(n)));
    ensures({ let mut b = bytes; let r = SInt::<S>::read_cfg(&mut b, &()); (r, b) } == (Err(Error::InvalidVarint(n)), rest));
}

/// Any other failure is `InvalidVarint` with the type's byte width.
#[law]
fn read_signed_errors_are_classified<S: SPrim>(bytes: Seq<u8>, e: Error) {
    requires({ let mut b = bytes; SInt::<S>::read_cfg(&mut b, &()) } == Err(e));
    ensures(e == Error::EndOfBuffer || e == Error::InvalidVarint(S::SIZE));
}
