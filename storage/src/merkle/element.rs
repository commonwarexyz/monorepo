//! Byte-like elements and lazy encodings used by proof verification.

use alloc::vec::Vec;
use commonware_codec::Write;

/// An element whose bytes can be hashed at a Merkle leaf.
///
/// Use [`Encoded`] to supply the codec encoding of a value.
pub trait Element {
    /// Return the element's bytes, using `scratch` for temporary storage if needed.
    ///
    /// The returned bytes must not depend on the previous contents of `scratch`.
    fn as_bytes<'a>(&'a self, scratch: &'a mut Vec<u8>) -> &'a [u8];
}

impl<T: AsRef<[u8]>> Element for T {
    fn as_bytes<'a>(&'a self, _scratch: &'a mut Vec<u8>) -> &'a [u8] {
        self.as_ref()
    }
}

/// Lazily encode a borrowed value during proof verification.
///
/// Pass `operations.iter().map(Encoded)` to a range verifier to encode and hash each operation
/// in turn. Temporary encoding storage is proportional to the largest encoded operation.
pub struct Encoded<'a, T>(pub &'a T);

impl<T: Write> Element for Encoded<'_, T> {
    fn as_bytes<'a>(&'a self, scratch: &'a mut Vec<u8>) -> &'a [u8] {
        scratch.clear();
        self.0.write(scratch);
        scratch
    }
}
