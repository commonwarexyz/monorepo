//! Helpers shared by the proofs.

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
/// with an `out` of a known maximum size also proves the encoding never exceeds it.
pub fn write_into<T: commonware_codec::Write>(value: &T, out: &mut [u8]) -> usize {
    let cap = out.len();
    let mut writer: &mut [u8] = out;
    value.write(&mut writer);
    cap - writer.len()
}

/// The value of `bytes[0..8]` read as one big-endian `u64`, by a plain loop.
pub fn big_endian_u64(bytes: &[u8]) -> u64 {
    let mut value: u64 = 0;
    let mut i = 0;
    while i < 8 {
        value = (value << 8) | bytes[i] as u64;
        i += 1;
    }
    value
}
