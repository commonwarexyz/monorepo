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
