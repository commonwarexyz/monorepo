//! Implementations of Codec for common types

use crate::{
    codec::{Codec, Reader, Writer},
    varint, Error, SizedCodec,
};
use bytes::Bytes;
use paste::paste;

macro_rules! impl_primitive {
    ($type:ty, $read_method:ident, $write_method:ident, $size:expr) => {
        impl Codec for $type {
            #[inline]
            fn write(&self, writer: &mut impl Writer) {
                writer.$write_method(*self);
            }

            #[inline]
            fn len_encoded(&self) -> usize {
                std::mem::size_of::<$type>()
            }

            #[inline]
            fn read(reader: &mut impl Reader) -> Result<Self, Error> {
                reader.$read_method()
            }
        }

        impl SizedCodec<$size> for $type {}
    };
}

impl_primitive!(u8, read_u8, write_u8, 1);
impl_primitive!(u16, read_u16, write_u16, 2);
impl_primitive!(u32, read_u32, write_u32, 4);
impl_primitive!(u64, read_u64, write_u64, 8);
impl_primitive!(u128, read_u128, write_u128, 16);
impl_primitive!(i8, read_i8, write_i8, 1);
impl_primitive!(i16, read_i16, write_i16, 2);
impl_primitive!(i32, read_i32, write_i32, 4);
impl_primitive!(i64, read_i64, write_i64, 8);
impl_primitive!(i128, read_i128, write_i128, 16);
impl_primitive!(f32, read_f32, write_f32, 4);
impl_primitive!(f64, read_f64, write_f64, 8);
impl_primitive!(bool, read_bool, write_bool, 1);

// Bytes implementation
impl Codec for Bytes {
    #[inline]
    fn write(&self, writer: &mut impl Writer) {
        writer.write_bytes(self);
    }

    #[inline]
    fn len_encoded(&self) -> usize {
        self.len() + varint::varint_size(self.len() as u64)
    }

    #[inline]
    fn read(reader: &mut impl Reader) -> Result<Self, Error> {
        reader.read_bytes()
    }
}

// Constant-size array implementation
impl<const N: usize> Codec for [u8; N] {
    #[inline]
    fn write(&self, writer: &mut impl Writer) {
        writer.write_fixed(self);
    }

    #[inline]
    fn len_encoded(&self) -> usize {
        N
    }

    #[inline]
    fn read(reader: &mut impl Reader) -> Result<Self, Error> {
        reader.read_fixed()
    }
}

impl<const N: usize> SizedCodec<N> for [u8; N] {}

// Option implementation
impl<T: Codec> Codec for Option<T> {
    #[inline]
    fn write(&self, writer: &mut impl Writer) {
        writer.write_option(self);
    }

    #[inline]
    fn len_encoded(&self) -> usize {
        match self {
            Some(inner) => 1 + inner.len_encoded(),
            None => 1,
        }
    }

    #[inline]
    fn read(reader: &mut impl Reader) -> Result<Self, Error> {
        reader.read_option()
    }
}

// Tuple implementation
macro_rules! impl_codec_for_tuple {
    ($($index:literal),*) => {
        paste! {
            impl<$( [<T $index>]: Codec ),*> Codec for ( $( [<T $index>], )* ) {
                fn write(&self, writer: &mut impl Writer) {
                    $( writer.write(&self.$index); )*
                }

                fn len_encoded(&self) -> usize {
                    0 $( + self.$index.len_encoded() )*
                }

                fn read(reader: &mut impl Reader) -> Result<Self, Error> {
                    Ok(( $( reader.read::<[<T $index>]>()? , )* ))
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
    fn write(&self, writer: &mut impl Writer) {
        writer.write_vec(self);
    }

    #[inline]
    fn len_encoded(&self) -> usize {
        let len = varint::varint_size(self.len() as u64);
        self.iter().map(Codec::len_encoded).sum::<usize>() + len
    }

    #[inline]
    fn read(reader: &mut impl Reader) -> Result<Self, Error> {
        reader.read_vec()
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
                varint::varint_size(value.len() as u64) + value.len()
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
