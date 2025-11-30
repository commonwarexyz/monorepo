use bytes::Buf;
use commonware_codec::{Error as CodecError, ReadExt};

pub mod ordered;
pub mod unordered;

/// Ensures the next `size` bytes are all zeroes in the provided buffer, returning a [CodecError]
/// otherwise.
#[inline]
fn ensure_zeros(buf: &mut impl Buf, size: usize) -> Result<(), CodecError> {
    for _ in 0..size {
        if u8::read(buf)? != 0 {
            return Err(CodecError::Invalid(
                "storage::adb::operation",
                "non-zero bytes",
            ));
        }
    }
    Ok(())
}
