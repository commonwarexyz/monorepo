//! Input buffers that preserve ownership while decoding.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bytes::{
    Buf as _, Bytes, BytesMut, TryGetError,
    buf::{Chain, Take},
};
use core::any::Any;

/// A buffer accepted by codec readers.
///
/// Use this bound for generic readers of serialized values and their decoding helpers,
/// including fixed-size reads and length or padding validation.
///
/// Implementations backed by shared storage must preserve that ownership in
/// [`bytes::Buf::copy_to_bytes`] whenever the requested range can be represented without copying.
/// This lets decoded byte fields retain views of the input allocation. Implement this trait
/// for custom buffers that meet this contract. Implementations whose storage is an
/// [`OwnedBytes`] type must also offer it through [`Buf::take_owned`], passing the view to
/// [`OwnedBytes::claim`] and building `T` from its bytes when it comes back, so fields of that
/// type decode as views of the input. Adapters over another [`Buf`] forward [`Buf::take_owned`]
/// so a view is not lost behind them.
///
/// Borrowed slices require an explicit [`Copying`] adapter. Ordinary scalar and byte-array reads
/// remain allocation-free, while retained byte fields are copied. Borrow [`Bytes`] through
/// [`Viewing`] to share storage for retained fields.
pub trait Buf: bytes::Buf {
    /// Takes the next `len` bytes as `T`.
    ///
    /// A buffer whose storage is an [`OwnedBytes`] type returns a view of that storage when `T`
    /// is that type. Any other `T` is built from the bytes.
    ///
    /// # Panics
    ///
    /// Panics if fewer than `len` bytes remain.
    fn take_owned<T: OwnedBytes>(&mut self, len: usize) -> T {
        T::from_bytes(self.copy_to_bytes(len))
    }

    /// Takes the next `len` bytes as `T`, as [`Buf::take_owned`] does.
    ///
    /// # Errors
    ///
    /// Returns the shortfall and leaves the buffer unchanged if fewer than `len` bytes remain.
    fn try_take_owned<T: OwnedBytes>(&mut self, len: usize) -> Result<T, TryGetError> {
        let available = self.remaining();
        if available < len {
            return Err(TryGetError {
                requested: len,
                available,
            });
        }
        Ok(self.take_owned(len))
    }
}

/// An owned byte container a decoded field can be built in.
///
/// Every container can be built from shared [`Bytes`]. A container that is the storage type of
/// a [`Buf`] also claims the views that buffer offers, so a field of that type decodes as a
/// view of the input.
pub trait OwnedBytes: Sized + 'static {
    /// Builds the container from shared bytes.
    fn from_bytes(bytes: Bytes) -> Self;

    /// Claims a view a buffer offers in its own storage type, or returns it unchanged.
    ///
    /// A container claims exactly the views of its own type unless it overrides this.
    fn claim<V: Any>(view: V) -> Result<Self, V> {
        // Moving a value out through `dyn Any` needs a slot to take it from.
        let mut slot = Some(view);
        let any: &mut dyn Any = &mut slot;
        let claimed = any.downcast_mut::<Option<Self>>().and_then(Option::take);
        claimed.ok_or_else(|| slot.expect("the slot must hold the view"))
    }
}

impl OwnedBytes for Bytes {
    #[inline]
    fn from_bytes(bytes: Bytes) -> Self {
        bytes
    }
}

impl Buf for Bytes {}
impl Buf for BytesMut {}
impl<B: Buf + ?Sized> Buf for &mut B {
    #[inline]
    fn take_owned<T: OwnedBytes>(&mut self, len: usize) -> T {
        (**self).take_owned(len)
    }
}

impl<B: Buf> Buf for Take<B> {
    /// Returns what the limited buffer returns, and shortens the limit by `len`.
    #[inline]
    fn take_owned<T: OwnedBytes>(&mut self, len: usize) -> T {
        let remaining = self.remaining();
        assert!(
            len <= remaining,
            "len must not exceed the remaining bytes: {len} > {remaining}"
        );
        let taken = self.get_mut().take_owned(len);
        self.set_limit(self.limit() - len);
        taken
    }
}

impl<A: Buf, B: Buf> Buf for Chain<A, B> {
    /// Returns what the buffer holding the whole range returns, and builds `T` from the bytes
    /// when the range spans both.
    #[inline]
    fn take_owned<T: OwnedBytes>(&mut self, len: usize) -> T {
        let first = self.first_ref().remaining();
        if first >= len {
            self.first_mut().take_owned(len)
        } else if first == 0 {
            self.last_mut().take_owned(len)
        } else {
            T::from_bytes(self.copy_to_bytes(len))
        }
    }
}

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
pub trait Input: Into<Self::Buf> {
    /// The buffer used by the decoder.
    type Buf: Buf;
}

impl<B: Buf> Input for B {
    type Buf = B;
}

impl Input for Vec<u8> {
    type Buf = Bytes;
}

/// An adapter for decoding from a borrowed byte slice.
///
/// Construction does not copy or allocate. Scalar and byte-array reads consume the slice
/// directly without allocating, so scratch buffers can be reused.
///
/// The copying applies to fields that retain input bytes, such as [`Bytes`]. These fields
/// copy their contents into owned storage so they can outlive the borrow. To share an existing
/// allocation, pass an owned [`Bytes`] or [`BytesMut`] directly to the decoder, or borrow [`Bytes`]
/// through [`Viewing`].
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
/// A retained [`Bytes`] value owns its contents after the scratch buffer is dropped:
///
/// ```
/// use bytes::Bytes;
/// use commonware_codec::{Copying, Decode};
///
/// let value = {
///     let scratch = *b"\x05hello";
///     Bytes::decode_cfg(Copying(&scratch), &(..).into()).unwrap()
/// };
/// assert_eq!(value, b"hello"[..]);
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

/// An adapter for decoding from borrowed [`Bytes`].
///
/// Keeps an independent cursor without cloning the input handle. Scalar and byte-array reads do not
/// allocate. Retained [`Bytes`] fields share the input allocation and can outlive the borrow.
///
/// For borrowed byte slices, use [`Copying`].
///
/// # Examples
///
/// ```
/// use bytes::Bytes;
/// use commonware_codec::{Decode, Encode, Viewing};
///
/// let decoded = {
///     let encoded = Bytes::from_static(b"hello").encode();
///     Bytes::decode_cfg(Viewing::new(&encoded), &(..).into()).unwrap()
/// };
/// assert_eq!(decoded, b"hello"[..]);
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Viewing<'a> {
    bytes: &'a Bytes,
    pos: usize,
}

impl<'a> Viewing<'a> {
    /// Starts an independent cursor at the beginning of `bytes`.
    pub const fn new(bytes: &'a Bytes) -> Self {
        Self { bytes, pos: 0 }
    }
}

impl bytes::Buf for Viewing<'_> {
    #[inline]
    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        &self.bytes[self.pos..]
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        assert!(
            cnt <= self.remaining(),
            "advance must not exceed the remaining bytes"
        );
        self.pos += cnt;
    }

    #[inline]
    fn copy_to_bytes(&mut self, len: usize) -> Bytes {
        assert!(
            len <= self.remaining(),
            "length must not exceed the remaining bytes"
        );
        let bytes = self.bytes.slice(self.pos..self.pos + len);
        self.pos += len;
        bytes
    }
}

impl Buf for Viewing<'_> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Decode, DecodeExt, Encode, Read, ReadExt};

    /// A buffer with its own owned storage type offers views of that type through
    /// `take_owned`; a field of that type claims the view, and any other field gets the bytes.
    #[test]
    fn test_take_owned_claims_matching_views() {
        /// A reader whose storage type is `Owned`.
        struct Reader(Bytes);

        /// The reader's storage type: shared bytes plus a marker that only a claimed view carries.
        #[derive(Debug, PartialEq)]
        struct Owned {
            bytes: Bytes,
            claimed: bool,
        }

        impl bytes::Buf for Reader {
            fn remaining(&self) -> usize {
                self.0.remaining()
            }
            fn chunk(&self) -> &[u8] {
                self.0.chunk()
            }
            fn advance(&mut self, cnt: usize) {
                self.0.advance(cnt);
            }
        }

        impl Buf for Reader {
            fn take_owned<T: OwnedBytes>(&mut self, len: usize) -> T {
                let view = Owned {
                    bytes: self.0.split_to(len),
                    claimed: true,
                };
                T::claim(view).unwrap_or_else(|view| T::from_bytes(view.bytes))
            }
        }

        impl OwnedBytes for Owned {
            fn from_bytes(bytes: Bytes) -> Self {
                Self {
                    bytes,
                    claimed: false,
                }
            }
        }

        let mut reader = Reader(Bytes::from_static(b"hello world"));
        let claimed: Owned = reader.take_owned(5);
        assert_eq!(claimed.bytes, &b"hello"[..]);
        assert!(claimed.claimed);
        let bytes: Bytes = reader.take_owned(6);
        assert_eq!(bytes, &b" world"[..]);

        // A buffer without its own storage type builds every container from bytes.
        let mut plain = Bytes::from_static(b"hello");
        let built: Owned = plain.take_owned(5);
        assert_eq!(built.bytes, &b"hello"[..]);
        assert!(!built.claimed);
    }

    /// Adapters pass a view through: a reborrowed, a limited, and a chained reader all yield what
    /// the underlying buffer offers, and the limit still shrinks by what was taken.
    #[test]
    fn test_take_owned_through_adapters() {
        struct Reader(Bytes);

        #[derive(Debug, PartialEq)]
        struct Owned(Bytes, bool);

        impl bytes::Buf for Reader {
            fn remaining(&self) -> usize {
                self.0.remaining()
            }
            fn chunk(&self) -> &[u8] {
                self.0.chunk()
            }
            fn advance(&mut self, cnt: usize) {
                self.0.advance(cnt);
            }
        }

        impl Buf for Reader {
            fn take_owned<T: OwnedBytes>(&mut self, len: usize) -> T {
                T::claim(Owned(self.0.split_to(len), true))
                    .unwrap_or_else(|view| T::from_bytes(view.0))
            }
        }

        impl OwnedBytes for Owned {
            fn from_bytes(bytes: Bytes) -> Self {
                Self(bytes, false)
            }
        }

        let mut reader = Reader(Bytes::from_static(b"hello world"));
        let claimed: Owned = (&mut &mut reader).take_owned(5);
        assert_eq!(claimed, Owned(Bytes::from_static(b"hello"), true));

        let mut limited = bytes::Buf::take(&mut reader, 4);
        let claimed: Owned = limited.take_owned(3);
        assert_eq!(claimed, Owned(Bytes::from_static(b" wo"), true));
        assert_eq!(limited.limit(), 1);
        assert_eq!(limited.remaining(), 1);
        let claimed: Owned = limited.try_take_owned(1).unwrap();
        assert_eq!(claimed, Owned(Bytes::from_static(b"r"), true));
        assert_eq!(limited.limit(), 0);

        // A chain yields the view of whichever side holds the whole range and builds the
        // container from bytes when the range spans both.
        let mut chained =
            Reader(Bytes::from_static(b"ab")).chain(Reader(Bytes::from_static(b"cd")));
        let claimed: Owned = chained.take_owned(1);
        assert_eq!(claimed, Owned(Bytes::from_static(b"a"), true));
        let spanning: Owned = chained.take_owned(2);
        assert_eq!(spanning, Owned(Bytes::from_static(b"bc"), false));
        let claimed: Owned = chained.take_owned(1);
        assert_eq!(claimed, Owned(Bytes::from_static(b"d"), true));
        assert!(!chained.has_remaining());
    }

    /// `try_take_owned` reports how many bytes were available on a short input and leaves the
    /// buffer untouched. Otherwise it hands out the same view as `take_owned`. A limit counts as
    /// available bytes only up to what its inner buffer holds.
    #[test]
    fn test_try_take_owned_reports_shortfall() {
        let mut input = Bytes::from_static(b"hello");
        let payload = input.as_ptr();
        let err = input.try_take_owned::<Bytes>(6).unwrap_err();
        assert_eq!((err.requested, err.available), (6, 5));
        assert_eq!(input.remaining(), 5);
        let taken: Bytes = input.try_take_owned(5).unwrap();
        assert_eq!(taken.as_ptr(), payload);
        assert!(!input.has_remaining());

        // A limit looser than the inner buffer reports the inner buffer's bytes.
        let mut inner = Bytes::from_static(b"abc");
        let mut limited = bytes::Buf::take(&mut inner, 10);
        let err = limited.try_take_owned::<Bytes>(5).unwrap_err();
        assert_eq!((err.requested, err.available), (5, 3));
        assert_eq!(limited.remaining(), 3);
        assert_eq!(limited.limit(), 10);

        // A limit tighter than the inner buffer reports the limit.
        let mut inner = Bytes::from_static(b"abcdefgh");
        let mut limited = bytes::Buf::take(&mut inner, 4);
        let err = limited.try_take_owned::<Bytes>(5).unwrap_err();
        assert_eq!((err.requested, err.available), (5, 4));
        assert_eq!(limited.remaining(), 4);
        assert_eq!(inner.remaining(), 8);
    }

    /// A limited reader refuses a range its inner buffer cannot fill, even when the limit alone
    /// would allow it.
    #[test]
    #[should_panic(expected = "len must not exceed the remaining bytes: 5 > 3")]
    fn test_take_owned_past_inner_end() {
        let mut inner = Bytes::from_static(b"abc");
        let mut limited = bytes::Buf::take(&mut inner, 10);
        let _: Bytes = limited.take_owned(5);
    }

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

    /// Scalar and byte-array reads advance an independent cursor without cloning the input handle.
    #[test]
    fn test_viewing_scalar_reads() {
        let encoded = Bytes::copy_from_slice(b"\x00\x00\x00\x07ab");
        let mut input = Viewing::new(&encoded);
        assert!(encoded.is_unique());
        assert_eq!(input.chunk().as_ptr(), encoded.as_ptr());
        assert_eq!(u32::read(&mut input).unwrap(), 7);

        let mut other = input;
        assert_eq!(<[u8; 2]>::read(&mut input).unwrap(), *b"ab");
        assert_eq!(other.remaining(), 2);
        assert_eq!(<[u8; 2]>::read(&mut other).unwrap(), *b"ab");
        assert!(!input.has_remaining());
        assert!(input.chunk().is_empty());
        assert_eq!(encoded.as_ref(), b"\x00\x00\x00\x07ab");
        assert!(encoded.is_unique());
    }

    /// Retained fields share storage through a limited cursor and outlive the source handle.
    #[test]
    fn test_viewing_retained_fields() {
        let (first, second) = {
            let encoded = Bytes::copy_from_slice(b"\x05hello\x05world");
            let mut input = Viewing::new(&encoded);
            let mut limited = (&mut input).take(6);
            let first = Bytes::read_cfg(&mut limited, &(..).into()).unwrap();
            assert_eq!(first.as_ptr(), encoded[1..].as_ptr());
            assert!(!limited.has_remaining());

            let second = Bytes::decode_cfg(input, &(..).into()).unwrap();
            assert_eq!(second.as_ptr(), encoded[7..].as_ptr());
            (first, second)
        };
        assert_eq!(first, b"hello"[..]);
        assert_eq!(second, b"world"[..]);
    }

    /// Empty ranges are valid both within the input and at its end.
    #[test]
    fn test_viewing_empty_ranges() {
        for encoded in [Bytes::new(), Bytes::from_static(b"hello")] {
            let mut input = Viewing::new(&encoded);
            input.advance(0);
            assert!(input.copy_to_bytes(0).is_empty());
            assert_eq!(input.remaining(), encoded.len());
            input.advance(encoded.len());
            input.advance(0);
            assert!(input.copy_to_bytes(0).is_empty());
            assert!(!input.has_remaining());
            assert!(input.chunk().is_empty());
        }
    }

    /// Decoders reject truncated and trailing input when reading through a borrowed cursor.
    #[test]
    fn test_viewing_invalid_input() {
        for bytes in [&b""[..], b"\x05hi", b"\x01ab", b"\x80"] {
            let encoded = Bytes::copy_from_slice(bytes);
            assert!(Bytes::decode_cfg(Viewing::new(&encoded), &(..).into()).is_err());
        }
        let encoded = Bytes::from_static(b"\x00");
        assert!(
            Bytes::decode_cfg(Viewing::new(&encoded), &(..).into())
                .unwrap()
                .is_empty()
        );
    }

    /// Oversized advances are rejected before adding to the cursor position.
    #[test]
    #[should_panic(expected = "advance must not exceed the remaining bytes")]
    fn test_viewing_advance_past_end() {
        let encoded = Bytes::from_static(b"a");
        let mut input = Viewing::new(&encoded);
        input.advance(1);
        input.advance(usize::MAX);
    }

    /// Oversized retained ranges are rejected before computing their end.
    #[test]
    #[should_panic(expected = "length must not exceed the remaining bytes")]
    fn test_viewing_copy_past_end() {
        let encoded = Bytes::from_static(b"a");
        let mut input = Viewing::new(&encoded);
        input.advance(1);
        input.copy_to_bytes(usize::MAX);
    }
}
