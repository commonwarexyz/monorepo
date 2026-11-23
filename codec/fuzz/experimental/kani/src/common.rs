//! Helpers shared by the proofs.

use commonware_codec::Write;

/// The continuation bit of a varint byte (codec/src/varint.rs:55).
pub const CONT: u8 = 0x80;

/// An implementation-consistency check: an assertion that is STRONGER than the documented
/// contract.
///
/// It is compiled into the proof only with `--features consistency`. The default build (the
/// contract gate) does not assert it, so a valid change of the implementation cannot fail the
/// gate through one of these.
macro_rules! consistency {
    ($($arg:tt)*) => {
        if cfg!(feature = "consistency") {
            assert!($($arg)*);
        }
    };
}
pub(crate) use consistency;

/// A `kani::cover!` check for a result arm that only some instances of a generic proof can
/// reach.
///
/// The first argument is the name of the predicate that says which inputs take the arm. For
/// the predicate `never` no check is emitted: for such a type no input takes the arm, and a
/// cover check that cannot be satisfied would say nothing. For any other name the check is
/// emitted, so that an arm that is no longer reached is seen.
macro_rules! cover_unless_never {
    (never, $($arg:tt)*) => {};
    ($predicate:ident, $($arg:tt)*) => {
        kani::cover!($($arg)*);
    };
}
pub(crate) use cover_unless_never;

/// Writes `value` into `out` and returns the number of bytes written.
///
/// `&mut [u8]` is a `bytes::BufMut` that panics when it is full, so a harness that calls this
/// with an `out` of the documented maximum size also proves the encoding never exceeds it.
pub fn write_into<T: Write>(value: &T, out: &mut [u8]) -> usize {
    let cap = out.len();
    let mut writer: &mut [u8] = out;
    value.write(&mut writer);
    cap - writer.len()
}

/// Returns `true` when `a` and `b` have the same length and hold the same bytes.
///
/// A plain loop, so that a proof does not depend on how the compiler lowers a slice
/// comparison. A harness that calls it needs an unwind bound above the slice length.
pub fn same_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// The value of `bytes` read as one big-endian unsigned integer (at most 16 bytes).
///
/// An independent model of "big-endian": the first byte is the most significant one. A harness
/// that calls it needs an unwind bound above the slice length.
pub fn big_endian(bytes: &[u8]) -> u128 {
    let mut value: u128 = 0;
    let mut i = 0;
    while i < bytes.len() {
        value = (value << 8) | bytes[i] as u128;
        i += 1;
    }
    value
}

/// A buffer model that reports `0` remaining bytes or any other count, with no content.
///
/// The length checks in `commonware_codec::util` (`at_least`, `at_least_items`) only call
/// `remaining()`. This model lets a proof range over every `usize` count, which no real
/// buffer can hold.
pub struct Remaining(pub usize);

impl bytes::Buf for Remaining {
    fn remaining(&self) -> usize {
        self.0
    }

    fn chunk(&self) -> &[u8] {
        panic!("the length checks must not read content")
    }

    fn advance(&mut self, _: usize) {
        panic!("the length checks must not consume content")
    }
}

impl commonware_codec::Buf for Remaining {}
