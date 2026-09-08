//! Input buffers that preserve ownership while decoding.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};
use bytes::{
    Bytes, BytesMut,
    buf::{Chain, Take},
};

/// A buffer accepted by codec readers.
///
/// Use this bound for generic readers of serialized values and their decoding helpers,
/// including fixed-size reads and length or padding validation.
///
/// Implementations backed by shared storage must preserve that ownership in
/// [`bytes::Buf::copy_to_bytes`] whenever the requested range can be represented without copying.
/// This lets decoded byte fields retain views of the input allocation. Implement this trait
/// for custom buffers that meet this contract.
///
/// Borrowed slices require an explicit [`Copying`] adapter. The adapter leaves ordinary
/// scalar and byte-array reads allocation-free and copies fields that retain their input bytes.
///
/// Slices cannot accidentally reach a reader through aliases or helper functions:
///
/// ```compile_fail,E0277
/// use bytes::Bytes;
/// use commonware_codec::Read;
///
/// fn read(mut input: &[u8]) {
///     let alias = &mut input;
///     let _ = Bytes::read_cfg(alias, &(..).into());
/// }
/// ```
pub trait Buf: bytes::Buf {}

impl Buf for Bytes {}
impl Buf for BytesMut {}
impl<B: Buf + ?Sized> Buf for &mut B {}
impl<B: Buf + ?Sized> Buf for Box<B> {}
impl<B: Buf> Buf for Take<B> {}
impl<A: Buf, B: Buf> Buf for Chain<A, B> {}

/// An input that can be consumed by a decoder.
///
/// [`Buf`] inputs pass through unchanged. A [`Vec<u8>`] transfers its allocation to
/// [`Bytes`] without copying its payload. Custom inputs can convert into a [`Buf`].
///
/// Borrowing an owned buffer as a slice discards its ability to share decoded byte fields,
/// so slices require an explicit [`Copying`] adapter:
///
/// ```compile_fail,E0277
/// use bytes::Bytes;
/// use commonware_codec::{Decode, Encode};
///
/// let encoded = Bytes::from_static(b"hello").encode();
/// let _ = Bytes::decode_cfg(encoded.as_ref(), &(..).into());
/// ```
///
/// The same requirement applies after passing a slice through helpers:
///
/// ```compile_fail,E0277
/// use bytes::Bytes;
/// use commonware_codec::Decode;
///
/// fn alias(input: &[u8]) -> &[u8] {
///     let first = input;
///     let second = first;
///     second
/// }
///
/// fn decode(input: &[u8]) {
///     let _ = Bytes::decode_cfg(alias(input), &(..).into());
/// }
/// ```
///
/// Owning storage is insufficient if the buffer's byte extraction copies it:
///
/// ```compile_fail,E0277
/// use bytes::Bytes;
/// use commonware_codec::{Decode, Encode};
/// use std::io::Cursor;
///
/// let encoded = Bytes::from_static(b"hello").encode();
/// let _ = Bytes::decode_cfg(Cursor::new(encoded), &(..).into());
/// ```
pub trait DecodeInput {
    /// The buffer used by the decoder.
    type Buf: Buf;

    /// Converts this input into its readable buffer.
    fn into_buf(self) -> Self::Buf;
}

impl<B: Buf> DecodeInput for B {
    type Buf = B;

    #[inline]
    fn into_buf(self) -> Self::Buf {
        self
    }
}

impl DecodeInput for Vec<u8> {
    type Buf = Bytes;

    #[inline]
    fn into_buf(self) -> Self::Buf {
        self.into()
    }
}

/// Explicitly decodes from a borrowed slice, copying any retained byte fields.
///
/// Construction does not allocate or copy. Reads of scalar values or byte arrays consume
/// the slice directly, so scratch buffers can be reused without allocating. Decoded [`Bytes`]
/// fields allocate and copy their contents.
///
/// # Examples
///
/// ```
/// use commonware_codec::{Copying, DecodeExt, ReadExt};
///
/// let scratch = [0, 0, 0, 7];
/// assert_eq!(u32::decode(Copying(&scratch)).unwrap(), 7);
///
/// let mut input = Copying(&scratch);
/// assert_eq!(u32::read(&mut input).unwrap(), 7);
/// assert!(input.0.is_empty());
/// ```
///
/// Fixed-size values also require the explicit adapter:
///
/// ```compile_fail,E0277
/// use commonware_codec::DecodeExt;
///
/// let scratch = [0, 0, 0, 7];
/// let _ = u32::decode(&scratch[..]);
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Copying<'a>(
    /// The remaining borrowed input.
    pub &'a [u8],
);

impl bytes::Buf for Copying<'_> {
    #[inline]
    fn remaining(&self) -> usize {
        self.0.remaining()
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        self.0.chunk()
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        self.0.advance(cnt);
    }

    #[inline]
    fn copy_to_slice(&mut self, dst: &mut [u8]) {
        self.0.copy_to_slice(dst);
    }
}

impl Buf for Copying<'_> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Decode, DecodeExt, Encode, Read, ReadExt};
    use bytes::Buf as _;

    #[test]
    fn test_vec_preserves_payload() {
        let encoded = Bytes::from_static(b"hello").encode().to_vec();
        let payload = encoded[1..].as_ptr();
        let decoded = Bytes::decode_cfg(encoded, &(..).into()).unwrap();
        assert_eq!(decoded, b"hello"[..]);
        assert_eq!(decoded.as_ptr(), payload);
    }

    #[test]
    fn test_owned_buffers_preserve_payload() {
        let encoded = Bytes::from_static(b"hello").encode();
        let payload = encoded[1..].as_ptr();
        let cfg = (..).into();
        assert_eq!(
            Bytes::decode_cfg(encoded.clone(), &cfg).unwrap().as_ptr(),
            payload
        );
        assert_eq!(
            Bytes::decode_cfg(Box::new(encoded.clone()), &cfg)
                .unwrap()
                .as_ptr(),
            payload
        );
        assert_eq!(
            Bytes::decode_cfg(encoded.clone().take(encoded.len()), &cfg)
                .unwrap()
                .as_ptr(),
            payload
        );
        assert_eq!(
            Bytes::decode_cfg(encoded.clone().chain(Bytes::new()), &cfg)
                .unwrap()
                .as_ptr(),
            payload
        );
        let mut input = encoded;
        assert_eq!(Bytes::read_cfg(&mut input, &cfg).unwrap().as_ptr(), payload);
        assert_eq!(input.remaining(), 0);

        let encoded = BytesMut::from(&b"\x05hello"[..]);
        let payload = encoded[1..].as_ptr();
        assert_eq!(Bytes::decode_cfg(encoded, &cfg).unwrap().as_ptr(), payload);
    }

    #[test]
    fn test_copying_scratch() {
        let scratch = [0, 0, 0, 7];
        let mut input = Copying(&scratch);
        assert_eq!(input.chunk().as_ptr(), scratch.as_ptr());
        assert_eq!(u32::read(&mut input).unwrap(), 7);
        assert_eq!(input.remaining(), 0);
        assert_eq!(u32::decode(Copying(&scratch)).unwrap(), 7);
    }

    #[test]
    fn test_copying_payload() {
        let encoded = Bytes::from_static(b"hello").encode();
        let decoded = Bytes::decode_cfg(Copying(&encoded), &(..).into()).unwrap();
        assert_eq!(decoded, b"hello"[..]);
        assert_ne!(decoded.as_ptr(), encoded[1..].as_ptr());
    }
}
