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
//! it **does not implement [`FixedSize`]**.  When decoding a `usize`, callers
//! must supply a [`RangeCfg`] to bound the allowable value — this protects
//! against denial-of-service attacks that would allocate oversized buffers.
//!
//! ## Safety & portability
//! * `usize` is restricted to values that fit in a `u32` to keep the on-wire
//!   format identical across 32-bit and 64-bit architectures.
//! * All fixed-size integers and floats are written big-endian to avoid host-
//!   endian ambiguity.

use crate::{
    util::at_least, varint::UInt, EncodeSize, Error, FixedSize, RangeCfg, Read, ReadExt, Write,
};
use bytes::{Buf, BufMut};

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
                at_least(buf, std::mem::size_of::<$type>())?;
                Ok(buf.$read_method())
            }
        }

        impl FixedSize for $type {
            const SIZE: usize = std::mem::size_of::<$type>();
        }
    };
}

impl_numeric!(u8, get_u8, put_u8);
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

// Usize implementation
impl Write for usize {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        let self_as_u32 = u32::try_from(*self).expect("write: usize value is larger than u32");
        UInt(self_as_u32).write(buf);
    }
}

impl Read for usize {
    type Cfg = RangeCfg;

    #[inline]
    fn read_cfg(buf: &mut impl Buf, range: &Self::Cfg) -> Result<Self, Error> {
        let self_as_u32: u32 = UInt::read(buf)?.into();
        let result = usize::try_from(self_as_u32).map_err(|_| Error::InvalidUsize)?;
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

// Constant-size array implementation
impl<const N: usize> Write for [u8; N] {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        buf.put(&self[..]);
    }
}

impl<const N: usize> Read for [u8; N] {
    type Cfg = ();
    #[inline]
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        at_least(buf, N)?;
        let mut dst = [0; N];
        buf.copy_to_slice(&mut dst);
        Ok(dst)
    }
}

impl<const N: usize> FixedSize for [u8; N] {
    const SIZE: usize = N;
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
}

impl<T: EncodeSize> EncodeSize for Option<T> {
    #[inline]
    fn encode_size(&self) -> usize {
        match self {
            Some(inner) => 1 + inner.encode_size(),
            None => 1,
        }
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
    use super::*;
    use crate::{Decode, DecodeExt, Encode, EncodeFixed};
    use bytes::{Bytes, BytesMut};
    use paste::paste;

    // Float tests
    macro_rules! impl_num_test {
        ($type:ty, $size:expr) => {
            paste! {
                #[test]
                fn [<test_ $type>]() {
                    let expected_len = std::mem::size_of::<$type>();
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
        let values = [1u8, 2, 3];
        let encoded = values.encode();
        let decoded = <[u8; 3]>::decode(encoded).unwrap();
        assert_eq!(values, decoded);
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
        assert_eq!([1, 2, 3].encode(), &[0x01, 0x02, 0x03][..]);
        assert_eq!([].encode(), &[][..]);

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
}
