//! Implementations of Codec for common types

use crate::{
    codec::{Codec, Reader, Writer},
    varint, Error, SizedCodec,
};
use bytes::Bytes;
use paste::paste;

// ===== Primitive implementations =====

macro_rules! impl_primitive {
    ($type:ty, $read_method:ident, $write_method:ident) => {
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

        impl SizedCodec for $type {
            const LEN_CODEC: usize = std::mem::size_of::<$type>();
        }
    };
}

impl_primitive!(u8, read_u8, write_u8);
impl_primitive!(u16, read_u16, write_u16);
impl_primitive!(u32, read_u32, write_u32);
impl_primitive!(u64, read_u64, write_u64);
impl_primitive!(u128, read_u128, write_u128);
impl_primitive!(i8, read_i8, write_i8);
impl_primitive!(i16, read_i16, write_i16);
impl_primitive!(i32, read_i32, write_i32);
impl_primitive!(i64, read_i64, write_i64);
impl_primitive!(i128, read_i128, write_i128);
impl_primitive!(f32, read_f32, write_f32);
impl_primitive!(f64, read_f64, write_f64);
impl_primitive!(bool, read_bool, write_bool);

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
        reader.read_var_bytes()
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

impl<const N: usize> SizedCodec for [u8; N] {
    const LEN_CODEC: usize = N;
}

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

impl<T: SizedCodec> SizedCodec for Option<T> {
    const LEN_CODEC: usize = 1 + T::LEN_CODEC;
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

            impl<$( [<T $index>]: SizedCodec ),*> SizedCodec for ( $( [<T $index>], )* ) {
                const LEN_CODEC: usize = 0 $( + [<T $index>]::LEN_CODEC )*;
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
