//! Implementations of Codec for common types

use crate::{util::at_least, varint, Codec, Error, SizedCodec};
use bytes::{Buf, BufMut, Bytes};
use paste::paste;

// Numeric types implementation
macro_rules! impl_numeric {
    ($type:ty, $read_method:ident, $write_method:ident) => {
        impl Codec for $type {
            #[inline]
            fn write<B: BufMut>(&self, buf: &mut B) {
                buf.$write_method(*self);
            }

            #[inline]
            fn len_encoded(&self) -> usize {
                Self::LEN_ENCODED
            }

            #[inline]
            fn read<B: Buf>(buf: &mut B) -> Result<Self, Error> {
                at_least(buf, std::mem::size_of::<$type>())?;
                Ok(buf.$read_method())
            }
        }

        impl SizedCodec for $type {
            const LEN_ENCODED: usize = std::mem::size_of::<$type>();
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
impl Codec for usize {
    #[inline]
    fn write<B: BufMut>(&self, buf: &mut B) {
        varint::write(*self, buf);
    }

    #[inline]
    fn len_encoded(&self) -> usize {
        varint::size(*self as u64)
    }

    #[inline]
    fn read<B: Buf>(buf: &mut B) -> Result<Self, Error> {
        varint::read(buf)
    }
}

// Bool implementation
impl Codec for bool {
    #[inline]
    fn write<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(if *self { 1 } else { 0 });
    }

    #[inline]
    fn len_encoded(&self) -> usize {
        Self::LEN_ENCODED
    }

    #[inline]
    fn read<B: Buf>(buf: &mut B) -> Result<Self, Error> {
        at_least(buf, 1)?;
        match buf.get_u8() {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::InvalidBool),
        }
    }
}

impl SizedCodec for bool {
    const LEN_ENCODED: usize = 1;
}

// Bytes implementation
impl Codec for Bytes {
    #[inline]
    fn write<B: BufMut>(&self, buf: &mut B) {
        self.len().write(buf);
        buf.put_slice(self);
    }

    #[inline]
    fn len_encoded(&self) -> usize {
        self.len() + varint::size(self.len() as u64)
    }

    #[inline]
    fn read<B: Buf>(buf: &mut B) -> Result<Self, Error> {
        let len = <usize>::read(buf)?;
        at_least(buf, len)?;
        Ok(buf.copy_to_bytes(len))
    }
}

// Constant-size array implementation
impl<const N: usize> Codec for [u8; N] {
    #[inline]
    fn write<B: BufMut>(&self, buf: &mut B) {
        buf.put(&self[..]);
    }

    #[inline]
    fn len_encoded(&self) -> usize {
        N
    }

    #[inline]
    fn read<B: Buf>(buf: &mut B) -> Result<Self, Error> {
        at_least(buf, N)?;
        let mut dst = [0; N];
        buf.copy_to_slice(&mut dst);
        Ok(dst)
    }
}

impl<const N: usize> SizedCodec for [u8; N] {
    const LEN_ENCODED: usize = N;
}

// Option implementation
impl<T: Codec> Codec for Option<T> {
    #[inline]
    fn write<B: BufMut>(&self, buf: &mut B) {
        self.is_some().write(buf);
        if let Some(inner) = self {
            inner.write(buf);
        }
    }

    #[inline]
    fn len_encoded(&self) -> usize {
        match self {
            Some(inner) => 1 + inner.len_encoded(),
            None => 1,
        }
    }

    #[inline]
    fn read<B: Buf>(buf: &mut B) -> Result<Self, Error> {
        if bool::read(buf)? {
            Ok(Some(T::read(buf)?))
        } else {
            Ok(None)
        }
    }
}

// Tuple implementation
macro_rules! impl_codec_for_tuple {
    ($($index:literal),*) => {
        paste! {
            impl<$( [<T $index>]: Codec ),*> Codec for ( $( [<T $index>], )* ) {
                fn write<B: BufMut>(&self, buf: &mut B) {
                    $( self.$index.write(buf); )*
                }

                fn len_encoded(&self) -> usize {
                    0 $( + self.$index.len_encoded() )*
                }

                fn read<B: Buf>(buf: &mut B) -> Result<Self, Error> {
                    Ok(( $( [<T $index>]::read(buf)?, )* ))
                }
            }
        }
    };
}

// Generate implementations for tuple sizes 1 through 12
impl_codec_for_tuple!(0);
impl_codec_for_tuple!(0, 1);
impl_codec_for_tuple!(0, 1, 2);
impl_codec_for_tuple!(0, 1, 2, 3);
impl_codec_for_tuple!(0, 1, 2, 3, 4);
impl_codec_for_tuple!(0, 1, 2, 3, 4, 5);
impl_codec_for_tuple!(0, 1, 2, 3, 4, 5, 6);
impl_codec_for_tuple!(0, 1, 2, 3, 4, 5, 6, 7);
impl_codec_for_tuple!(0, 1, 2, 3, 4, 5, 6, 7, 8);
impl_codec_for_tuple!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9);
impl_codec_for_tuple!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
impl_codec_for_tuple!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11);

// Vec implementation
impl<T: Codec> Codec for Vec<T> {
    #[inline]
    fn write<B: BufMut>(&self, buf: &mut B) {
        self.len().write(buf);
        for item in self {
            item.write(buf);
        }
    }

    #[inline]
    fn len_encoded(&self) -> usize {
        let len = varint::size(self.len() as u64);
        self.iter().map(Codec::len_encoded).sum::<usize>() + len
    }

    #[inline]
    fn read<B: Buf>(buf: &mut B) -> Result<Self, Error> {
        let len = <usize>::read(buf)?;
        let mut vec = Vec::with_capacity(len);
        for _ in 0..len {
            vec.push(T::read(buf)?);
        }
        Ok(vec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{Codec, SizedCodec};
    use bytes::Bytes;

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
                        assert_eq!(Codec::len_encoded(value), expected_len);
                        assert_eq!(SizedCodec::len_encoded(value), expected_len);

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
            assert_eq!(Codec::len_encoded(value), 1);
            assert_eq!(SizedCodec::len_encoded(value), 1);
        }
    }

    #[test]
    fn test_bytes() {
        let values = [
            Bytes::new(),
            Bytes::from_static(&[1, 2, 3]),
            Bytes::from(vec![0; 300]),
        ];
        for value in values {
            let encoded = value.encode();
            assert_eq!(
                encoded.len(),
                varint::size(value.len() as u64) + value.len()
            );
            let decoded = Bytes::decode(encoded).unwrap();
            assert_eq!(value, decoded);
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
        assert_eq!(Codec::len_encoded(&some), 1 + 4);
        assert_eq!(some.encode().len(), 1 + 4);
        let none: Option<u32> = None;
        assert_eq!(Codec::len_encoded(&none), 1);
        assert_eq!(none.encode().len(), 1);
    }

    #[test]
    fn test_tuple() {
        let tuple_values = [(1u16, None), (1u16, Some(2u32))];
        for value in tuple_values {
            let encoded = value.encode();
            let decoded = <(u16, Option<u32>)>::decode(encoded).unwrap();
            assert_eq!(value, decoded);
        }
    }

    #[test]
    fn test_vec() {
        let vec_values = [vec![], vec![1u8], vec![1u8, 2u8, 3u8]];
        for value in vec_values {
            let encoded = value.encode();
            assert_eq!(encoded.len(), value.len() * std::mem::size_of::<u8>() + 1);
            let decoded = Vec::<u8>::decode(encoded).unwrap();
            assert_eq!(value, decoded);
        }
    }
}
