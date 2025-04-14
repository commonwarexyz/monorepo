//! Implementations of Codec for primitive types.

use crate::{util::at_least, Config, EncodeSize, Error, FixedSize, Read, ReadExt, Write};
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
            #[inline]
            fn read_cfg(buf: &mut impl Buf, _: ()) -> Result<Self, Error> {
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

// Bool implementation
impl Write for bool {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_u8(if *self { 1 } else { 0 });
    }
}

impl Read for bool {
    #[inline]
    fn read_cfg(buf: &mut impl Buf, _: ()) -> Result<Self, Error> {
        at_least(buf, 1)?;
        match buf.get_u8() {
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
    #[inline]
    fn read_cfg(buf: &mut impl Buf, _: ()) -> Result<Self, Error> {
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

impl<Cfg: Config, T: Read<Cfg>> Read<Cfg> for Option<T> {
    #[inline]
    fn read_cfg(buf: &mut impl Buf, cfg: Cfg) -> Result<Self, Error> {
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
    use crate::{DecodeExt, Encode, EncodeFixed};
    use bytes::Bytes;
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
}
