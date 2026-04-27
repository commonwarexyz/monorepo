//! Codec implementations for Rust primitive types.
//!
//! # Fixed-size vs Variable-size
//!
//! Most primitives therefore have a compile-time constant `SIZE` and can be
//! encoded/decoded without any configuration.
//!
//! `usize` is the lone exception: since most values refer to a length or size
//! of an object in memory, values are biased towards smaller values. Therefore,
//! it uses variable-length (varint) encoding to save space.  This means that
//! it **does not implement [FixedSize]**.  When decoding a `usize`, callers
//! must supply a [RangeCfg] to bound the allowable value — this protects
//! against denial-of-service attacks that would allocate oversized buffers.
//!
//! ## Safety & portability
//! * `usize` is restricted to values that fit in a `u32` to keep the on-wire
//!   format identical across 32-bit and 64-bit architectures.
//! * All fixed-size integers and floats are written big-endian to avoid host-
//!   endian ambiguity.

use crate::{
    util::at_least, varint::UInt, BufsMut, EncodeSize, Error, FixedSize, RangeCfg, Read, ReadExt,
    Write,
};
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use bytes::{Buf, BufMut};
use core::num::{NonZeroU16, NonZeroU32, NonZeroU64};
#[cfg(feature = "std")]
use std::vec::Vec;

// Numeric types implementation
macro_rules! impl_numeric {
    ($type:ty, $read_method:ident, $write_method:ident) => {
        impl Write for $type {
            #[inline]
            fn write(&self, buf: &mut impl BufMut) {
                buf.$write_method(*self);
            }
        }

        impl Read for $type {
            type Cfg = ();
            #[inline]
            fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
                at_least(buf, core::mem::size_of::<$type>())?;
                Ok(buf.$read_method())
            }
        }

        impl FixedSize for $type {
            const SIZE: usize = core::mem::size_of::<$type>();
        }
    };
}

impl_numeric!(u16, get_u16, put_u16);
impl_numeric!(u32, get_u32, put_u32);
impl_numeric!(u64, get_u64, put_u64);
impl_numeric!(u128, get_u128, put_u128);
impl_numeric!(i8, get_i8, put_i8);
impl_numeric!(i16, get_i16, put_i16);
impl_numeric!(i32, get_i32, put_i32);
impl_numeric!(i64, get_i64, put_i64);
impl_numeric!(i128, get_i128, put_i128);
impl_numeric!(f32, get_f32, put_f32);
impl_numeric!(f64, get_f64, put_f64);

impl Write for u8 {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_u8(*self);
    }

    #[inline]
    fn write_slice(values: &[Self], buf: &mut impl BufMut) {
        buf.put_slice(values);
    }

    #[inline]
    fn write_slice_bufs(values: &[Self], buf: &mut impl BufsMut) {
        buf.put_slice(values);
    }
}

impl Read for u8 {
    type Cfg = ();

    #[inline]
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        at_least(buf, 1)?;
        Ok(buf.get_u8())
    }

    #[inline]
    fn read_vec(buf: &mut impl Buf, len: usize, _: &()) -> Result<Vec<Self>, Error> {
        at_least(buf, len)?;
        let mut values = vec![0; len];
        buf.copy_to_slice(&mut values);
        Ok(values)
    }

    #[inline]
    fn read_array<const N: usize>(buf: &mut impl Buf, _: &()) -> Result<[Self; N], Error> {
        at_least(buf, N)?;
        let mut values = [0; N];
        buf.copy_to_slice(&mut values);
        Ok(values)
    }
}

impl FixedSize for u8 {
    const SIZE: usize = 1;
}

macro_rules! impl_nonzero {
    ($nz:ty, $inner:ty, $name:expr) => {
        impl Write for $nz {
            #[inline]
            fn write(&self, buf: &mut impl BufMut) {
                self.get().write(buf);
            }
        }

        impl Read for $nz {
            type Cfg = ();
            #[inline]
            fn read_cfg(buf: &mut impl Buf, cfg: &()) -> Result<Self, Error> {
                let v = <$inner>::read_cfg(buf, cfg)?;
                <$nz>::new(v).ok_or(Error::Invalid($name, "value must not be zero"))
            }
        }

        impl FixedSize for $nz {
            const SIZE: usize = <$inner as FixedSize>::SIZE;
        }
    };
}

impl_nonzero!(NonZeroU16, u16, "NonZeroU16");
impl_nonzero!(NonZeroU32, u32, "NonZeroU32");
impl_nonzero!(NonZeroU64, u64, "NonZeroU64");

// Usize implementation
impl Write for usize {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        let self_as_u32 = u32::try_from(*self).expect("write: usize value is larger than u32");
        UInt(self_as_u32).write(buf);
    }
}

impl Read for usize {
    type Cfg = RangeCfg<Self>;

    #[inline]
    fn read_cfg(buf: &mut impl Buf, range: &Self::Cfg) -> Result<Self, Error> {
        let self_as_u32: u32 = UInt::read(buf)?.into();
        let result = Self::try_from(self_as_u32).map_err(|_| Error::InvalidUsize)?;
        if !range.contains(&result) {
            return Err(Error::InvalidLength(result));
        }
        Ok(result)
    }
}

impl EncodeSize for usize {
    #[inline]
    fn encode_size(&self) -> usize {
        let self_as_u32 =
            u32::try_from(*self).expect("encode_size: usize value is larger than u32");
        UInt(self_as_u32).encode_size()
    }
}

// Bool implementation
impl Write for bool {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_u8(if *self { 1 } else { 0 });
    }
}

impl Read for bool {
    type Cfg = ();
    #[inline]
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::InvalidBool),
        }
    }
}

impl FixedSize for bool {
    const SIZE: usize = 1;
}

// Arrays can always be written and read when their element can. This gives arrays
// with variable-size elements `Write`, `Read`, and therefore `Decode`, but not
// `Encode`. A generic `EncodeSize for [T; N]` would overlap with the blanket
// `EncodeSize` implementation for all `FixedSize` types, so only arrays whose
// elements are fixed-size become `FixedSize` and therefore `Encode`/`Codec`.
impl<T: Write, const N: usize> Write for [T; N] {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        T::write_slice(self, buf);
    }
}

impl<T: Read, const N: usize> Read for [T; N] {
    type Cfg = T::Cfg;

    #[inline]
    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        T::read_array(buf, cfg)
    }
}

impl<T: FixedSize, const N: usize> FixedSize for [T; N] {
    const SIZE: usize = T::SIZE * N;
}

impl Write for () {
    #[inline]
    fn write(&self, _buf: &mut impl BufMut) {}
}

impl Read for () {
    type Cfg = ();

    #[inline]
    fn read_cfg(_buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        Ok(())
    }
}

impl FixedSize for () {
    const SIZE: usize = 0;
}

// Option implementation
impl<T: Write> Write for Option<T> {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        self.is_some().write(buf);
        if let Some(inner) = self {
            inner.write(buf);
        }
    }

    #[inline]
    fn write_bufs(&self, buf: &mut impl BufsMut) {
        self.is_some().write(buf);
        if let Some(inner) = self {
            inner.write_bufs(buf);
        }
    }
}

impl<T: EncodeSize> EncodeSize for Option<T> {
    #[inline]
    fn encode_size(&self) -> usize {
        self.as_ref().map_or(1, |inner| 1 + inner.encode_size())
    }

    #[inline]
    fn encode_inline_size(&self) -> usize {
        self.as_ref()
            .map_or(1, |inner| 1 + inner.encode_inline_size())
    }
}

impl<T: Read> Read for Option<T> {
    type Cfg = T::Cfg;

    #[inline]
    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        if bool::read(buf)? {
            Ok(Some(T::read_cfg(buf, cfg)?))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::tests::{Byte, TrackingReadBuf, TrackingWriteBuf},
        *,
    };
    use crate::{CodecFixed, Decode, DecodeExt, Encode, EncodeFixed};
    use bytes::{Buf, Bytes, BytesMut};
    use paste::paste;

    // Float tests
    macro_rules! impl_num_test {
        ($type:ty, $size:expr) => {
            paste! {
                #[test]
                fn [<test_ $type>]() {
                    let expected_len = core::mem::size_of::<$type>();
                    let values: [$type; 5] =
                        [0 as $type, 1 as $type, 42 as $type, <$type>::MAX, <$type>::MIN];
                    for value in values.iter() {
                        let encoded = value.encode();
                        assert_eq!(encoded.len(), expected_len);
                        let decoded = <$type>::decode(encoded).unwrap();
                        assert_eq!(*value, decoded);
                        assert_eq!(value.encode_size(), expected_len);

                        let fixed: [u8; $size] = value.encode_fixed();
                        assert_eq!(fixed.len(), expected_len);
                        let decoded = <$type>::decode(Bytes::copy_from_slice(&fixed)).unwrap();
                        assert_eq!(*value, decoded);
                    }
                }
            }
        };
    }
    impl_num_test!(u8, 1);
    impl_num_test!(u16, 2);
    impl_num_test!(u32, 4);
    impl_num_test!(u64, 8);
    impl_num_test!(u128, 16);
    impl_num_test!(i8, 1);
    impl_num_test!(i16, 2);
    impl_num_test!(i32, 4);
    impl_num_test!(i64, 8);
    impl_num_test!(i128, 16);
    impl_num_test!(f32, 4);
    impl_num_test!(f64, 8);

    #[test]
    fn test_endianness() {
        // u16
        let encoded = 0x0102u16.encode();
        assert_eq!(encoded, Bytes::from_static(&[0x01, 0x02]));

        // u32
        let encoded = 0x01020304u32.encode();
        assert_eq!(encoded, Bytes::from_static(&[0x01, 0x02, 0x03, 0x04]));

        // f32
        let encoded = 1.0f32.encode();
        assert_eq!(encoded, Bytes::from_static(&[0x3F, 0x80, 0x00, 0x00])); // Big-endian IEEE 754
    }

    #[test]
    fn test_bool() {
        let values = [true, false];
        for value in values.iter() {
            let encoded = value.encode();
            assert_eq!(encoded.len(), 1);
            let decoded = bool::decode(encoded).unwrap();
            assert_eq!(*value, decoded);
            assert_eq!(value.encode_size(), 1);
        }
    }

    #[test]
    fn test_usize() {
        let values = [0usize, 1, 42, u32::MAX as usize];
        for value in values.iter() {
            let encoded = value.encode();
            assert_eq!(value.encode_size(), UInt(*value as u32).encode_size());
            let decoded = usize::decode_cfg(encoded, &(..).into()).unwrap();
            assert_eq!(*value, decoded);
        }
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    #[should_panic(expected = "encode_size: usize value is larger than u32")]
    fn test_usize_encode_panic() {
        let value: usize = usize::MAX;
        let _ = value.encode();
    }

    #[test]
    #[should_panic(expected = "write: usize value is larger than u32")]
    fn test_usize_write_panic() {
        let mut buf = &mut BytesMut::new();
        let value: usize = usize::MAX;
        value.write(&mut buf);
    }

    #[test]
    fn test_array() {
        // Arrays whose elements are fixed-size get the full `Codec` stack.
        fn assert_codec_fixed<T: CodecFixed<Cfg = ()>>() {}
        assert_codec_fixed::<[u8; 3]>();
        assert_codec_fixed::<[u16; 3]>();

        // `[u8; N]` encodes exactly N payload bytes, with no length prefix.
        let bytes = [1u8, 2, 3];
        let encoded = bytes.encode();
        let decoded = <[u8; 3]>::decode(encoded).unwrap();
        assert_eq!(bytes, decoded);
        assert_eq!(<[u8; 3] as FixedSize>::SIZE, 3);

        // Fixed-size array decoding must reject both truncated payloads and trailing data.
        assert!(matches!(
            <[u8; 3]>::decode([0x01, 0x02].as_slice()),
            Err(Error::EndOfBuffer)
        ));
        assert!(matches!(
            <[u8; 3]>::decode([0x01, 0x02, 0x03, 0x04].as_slice()),
            Err(Error::ExtraData(1))
        ));

        // Larger fixed-size elements compose normally and preserve big-endian encoding.
        let words = [0x0102u16, 0x0304u16, 0x0506u16];
        let encoded = words.encode();
        assert_eq!(encoded, &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06][..]);
        let decoded = <[u16; 3]>::decode(encoded).unwrap();
        assert_eq!(words, decoded);
        assert_eq!(words.encode_size(), 6);
        assert_eq!(<[u16; 3] as FixedSize>::SIZE, 6);

        // Nested arrays inherit the same fixed-size encoding from their elements.
        let nested = [[0x0102u16, 0x0304u16], [0x0506u16, 0x0708u16]];
        let encoded = nested.encode();
        assert_eq!(
            encoded,
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08][..]
        );
        let decoded = <[[u16; 2]; 2]>::decode(encoded).unwrap();
        assert_eq!(nested, decoded);

        // Arrays of configurable elements pass the element config through each read.
        let decoded =
            <[usize; 2]>::decode_cfg(Bytes::from_static(&[0x01, 0x02]), &(..).into()).unwrap();
        assert_eq!(decoded, [1, 2]);

        // Arrays with variable-size elements can still be written and read, even though
        // they cannot use `Encode` because they do not have a generic `EncodeSize` impl.
        let variable = [vec![1u8, 2], vec![3u8, 4, 5]];
        let mut encoded = BytesMut::new();
        variable.write(&mut encoded);
        assert_eq!(encoded, &[0x02, 0x01, 0x02, 0x03, 0x03, 0x04, 0x05][..]);

        let mut encoded = encoded.freeze();
        let decoded = <[Vec<u8>; 2]>::read_cfg(&mut encoded, &((..).into(), ())).unwrap();
        assert_eq!(variable, decoded);
        assert_eq!(encoded.remaining(), 0);
    }

    #[test]
    fn test_array_specialization_selection() {
        // `[u8; N]` has no length prefix, so the entire write is one bulk payload write.
        let mut buf = TrackingWriteBuf::new();
        [1u8, 2, 3].write(&mut buf);
        assert_eq!(buf.put_slice_calls, 1);
        assert_eq!(buf.put_u8_calls, 0);

        // Other array element types keep the generic per-element write path.
        let mut buf = TrackingWriteBuf::new();
        [Byte(1), Byte(2), Byte(3)].write(&mut buf);
        assert_eq!(buf.put_slice_calls, 0);
        assert_eq!(buf.put_u8_calls, 3);

        // `[u8; N]` reads the fixed-size payload with one bulk copy.
        let mut buf = TrackingReadBuf::new(&[0x01, 0x02, 0x03]);
        let value = <[u8; 3]>::read_cfg(&mut buf, &()).unwrap();
        assert_eq!(value, [1, 2, 3]);
        assert_eq!(buf.copy_to_slice_calls, 1);
        assert_eq!(buf.get_u8_calls, 0);

        // Other array element types still read one element at a time.
        let mut buf = TrackingReadBuf::new(&[0x01, 0x02, 0x03]);
        let value = <[Byte; 3]>::read_cfg(&mut buf, &()).unwrap();
        assert_eq!(value, [Byte(1), Byte(2), Byte(3)]);
        assert_eq!(buf.copy_to_slice_calls, 0);
        assert_eq!(buf.get_u8_calls, 3);
    }

    #[test]
    fn test_option() {
        let option_values = [Some(42u32), None];
        for value in option_values {
            let encoded = value.encode();
            let decoded = Option::<u32>::decode(encoded).unwrap();
            assert_eq!(value, decoded);
        }
    }

    #[test]
    fn test_option_length() {
        let some = Some(42u32);
        assert_eq!(some.encode_size(), 1 + 4);
        assert_eq!(some.encode().len(), 1 + 4);
        let none: Option<u32> = None;
        assert_eq!(none.encode_size(), 1);
        assert_eq!(none.encode().len(), 1);
    }

    #[test]
    fn test_unit() {
        let x = ();
        // Not using an equality check, since that will always pass.
        assert!(<()>::decode(x.encode()).is_ok());
    }

    #[test]
    fn test_nonzero_u16() {
        let values = [
            NonZeroU16::new(1).unwrap(),
            NonZeroU16::new(42).unwrap(),
            NonZeroU16::new(u16::MAX).unwrap(),
        ];
        for value in values {
            let encoded = value.encode();
            assert_eq!(encoded.len(), 2);
            let decoded = NonZeroU16::decode(encoded).unwrap();
            assert_eq!(value, decoded);
        }
        assert!(NonZeroU16::decode(0u16.encode()).is_err());
    }

    #[test]
    fn test_nonzero_u32() {
        let values = [
            NonZeroU32::new(1).unwrap(),
            NonZeroU32::new(u32::MAX).unwrap(),
        ];
        for value in values {
            let encoded = value.encode();
            assert_eq!(encoded.len(), 4);
            let decoded = NonZeroU32::decode(encoded).unwrap();
            assert_eq!(value, decoded);
        }
        assert!(NonZeroU32::decode(0u32.encode()).is_err());
    }

    #[test]
    fn test_nonzero_u64() {
        let values = [
            NonZeroU64::new(1).unwrap(),
            NonZeroU64::new(u64::MAX).unwrap(),
        ];
        for value in values {
            let encoded = value.encode();
            assert_eq!(encoded.len(), 8);
            let decoded = NonZeroU64::decode(encoded).unwrap();
            assert_eq!(value, decoded);
        }
        assert!(NonZeroU64::decode(0u64.encode()).is_err());
    }

    #[test]
    fn test_conformity() {
        // Bool
        assert_eq!(true.encode(), &[0x01][..]);
        assert_eq!(false.encode(), &[0x00][..]);

        // 8-bit integers
        assert_eq!(0u8.encode(), &[0x00][..]);
        assert_eq!(255u8.encode(), &[0xFF][..]);
        assert_eq!(0i8.encode(), &[0x00][..]);
        assert_eq!((-1i8).encode(), &[0xFF][..]);
        assert_eq!(127i8.encode(), &[0x7F][..]);
        assert_eq!((-128i8).encode(), &[0x80][..]);

        // 16-bit integers
        assert_eq!(0u16.encode(), &[0x00, 0x00][..]);
        assert_eq!(0xABCDu16.encode(), &[0xAB, 0xCD][..]);
        assert_eq!(u16::MAX.encode(), &[0xFF, 0xFF][..]);
        assert_eq!(0i16.encode(), &[0x00, 0x00][..]);
        assert_eq!((-1i16).encode(), &[0xFF, 0xFF][..]);
        assert_eq!(0x1234i16.encode(), &[0x12, 0x34][..]);

        // 32-bit integers
        assert_eq!(0u32.encode(), &[0x00, 0x00, 0x00, 0x00][..]);
        assert_eq!(0xABCDEF01u32.encode(), &[0xAB, 0xCD, 0xEF, 0x01][..]);
        assert_eq!(u32::MAX.encode(), &[0xFF, 0xFF, 0xFF, 0xFF][..]);
        assert_eq!(0i32.encode(), &[0x00, 0x00, 0x00, 0x00][..]);
        assert_eq!((-1i32).encode(), &[0xFF, 0xFF, 0xFF, 0xFF][..]);
        assert_eq!(0x12345678i32.encode(), &[0x12, 0x34, 0x56, 0x78][..]);

        // 64-bit integers
        assert_eq!(
            0u64.encode(),
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00][..]
        );
        assert_eq!(
            0x0123456789ABCDEFu64.encode(),
            &[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF][..]
        );
        assert_eq!(
            u64::MAX.encode(),
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF][..]
        );
        assert_eq!(
            0i64.encode(),
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00][..]
        );
        assert_eq!(
            (-1i64).encode(),
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF][..]
        );

        // 128-bit integers
        let u128_val = 0x0123456789ABCDEF0123456789ABCDEFu128;
        let u128_bytes = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF,
        ];
        assert_eq!(u128_val.encode(), &u128_bytes[..]);
        assert_eq!(u128::MAX.encode(), &[0xFF; 16][..]);
        assert_eq!((-1i128).encode(), &[0xFF; 16][..]);

        assert_eq!(0.0f32.encode(), 0.0f32.to_be_bytes()[..]);
        assert_eq!(1.0f32.encode(), 1.0f32.to_be_bytes()[..]);
        assert_eq!((-1.0f32).encode(), (-1.0f32).to_be_bytes()[..]);
        assert_eq!(f32::MAX.encode(), f32::MAX.to_be_bytes()[..]);
        assert_eq!(f32::MIN.encode(), f32::MIN.to_be_bytes()[..]);
        assert_eq!(f32::NAN.encode(), f32::NAN.to_be_bytes()[..]);
        assert_eq!(f32::INFINITY.encode(), f32::INFINITY.to_be_bytes()[..]);
        assert_eq!(
            f32::NEG_INFINITY.encode(),
            f32::NEG_INFINITY.to_be_bytes()[..]
        );

        // 32-bit floats
        assert_eq!(1.0f32.encode(), &[0x3F, 0x80, 0x00, 0x00][..]);
        assert_eq!((-1.0f32).encode(), &[0xBF, 0x80, 0x00, 0x00][..]);

        // 64-bit floats
        assert_eq!(0.0f64.encode(), 0.0f64.to_be_bytes()[..]);
        assert_eq!(1.0f64.encode(), 1.0f64.to_be_bytes()[..]);
        assert_eq!((-1.0f64).encode(), (-1.0f64).to_be_bytes()[..]);
        assert_eq!(f64::MAX.encode(), f64::MAX.to_be_bytes()[..]);
        assert_eq!(f64::MIN.encode(), f64::MIN.to_be_bytes()[..]);
        assert_eq!(f64::NAN.encode(), f64::NAN.to_be_bytes()[..]);
        assert_eq!(f64::INFINITY.encode(), f64::INFINITY.to_be_bytes()[..]);
        assert_eq!(
            f64::NEG_INFINITY.encode(),
            f64::NEG_INFINITY.to_be_bytes()[..]
        );
        assert_eq!(
            1.0f64.encode(),
            &[0x3F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00][..]
        );
        assert_eq!(
            (-1.0f64).encode(),
            &[0xBF, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00][..]
        );

        // Fixed-size array
        assert_eq!([1u8, 2, 3].encode(), &[0x01, 0x02, 0x03][..]);
        assert_eq!([0u8; 0].encode(), &[][..]);

        // Option
        assert_eq!(Some(42u32).encode(), &[0x01, 0x00, 0x00, 0x00, 0x2A][..]);
        assert_eq!(None::<u32>.encode(), &[0][..]);

        // Usize
        assert_eq!(0usize.encode(), &[0x00][..]);
        assert_eq!(1usize.encode(), &[0x01][..]);
        assert_eq!(127usize.encode(), &[0x7F][..]);
        assert_eq!(128usize.encode(), &[0x80, 0x01][..]);
        assert_eq!(
            (u32::MAX as usize).encode(),
            &[0xFF, 0xFF, 0xFF, 0xFF, 0x0F][..]
        );
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use crate::conformance::CodecConformance;
        use core::num::{NonZeroU16, NonZeroU32, NonZeroU64};

        commonware_conformance::conformance_tests! {
            CodecConformance<u8>,
            CodecConformance<u16>,
            CodecConformance<u32>,
            CodecConformance<u64>,
            CodecConformance<u128>,
            CodecConformance<i8>,
            CodecConformance<i16>,
            CodecConformance<i32>,
            CodecConformance<i64>,
            CodecConformance<i128>,
            CodecConformance<f32>,
            CodecConformance<f64>,
            CodecConformance<bool>,
            CodecConformance<[u8; 32]>,
            CodecConformance<Option<u64>>,
            CodecConformance<()>,
            CodecConformance<NonZeroU16>,
            CodecConformance<NonZeroU32>,
            CodecConformance<NonZeroU64>,
        }
    }
}
