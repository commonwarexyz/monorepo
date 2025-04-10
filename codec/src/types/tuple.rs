//! Implementations of Codec for common types

use crate::{Config, EncodeSize, Error, Read, Write};
use bytes::{Buf, BufMut};
use paste::paste;

// Tuple implementation
// Each type must have the same configuration type for reading.
macro_rules! impl_codec_for_tuple {
    ($($index:literal),*) => {
        paste! {
            impl<$( [<T $index>]: EncodeSize ),*> EncodeSize for ( $( [<T $index>], )* ) {
                #[inline]
                fn encode_size(&self) -> usize {
                    0 $( + self.$index.encode_size() )*
                }
            }

            impl<$( [<T $index>]: Write ),*> Write for ( $( [<T $index>], )* ) {
                #[inline]
                fn write(&self, buf: &mut impl BufMut) {
                    $( self.$index.write(buf); )*
                }
            }

            impl <Cfg: Config, $( [<T $index>]: Read<Cfg> ),*> Read<Cfg> for ( $( [<T $index>], )* ) {
                #[inline]
                fn read_cfg(buf: &mut impl Buf, cfg: &Cfg) -> Result<Self, Error> {
                    Ok(( $( [<T $index>]::read_cfg(buf, cfg)?, )* ))
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

#[cfg(test)]
mod tests {
    use crate::{DecodeExt, Encode};

    #[test]
    fn test_tuple() {
        let tuple_values = [(1u16, None), (1u16, Some(2u32))];
        for value in tuple_values {
            let encoded = value.encode();
            let decoded = <(u16, Option<u32>)>::decode(encoded).unwrap();
            assert_eq!(value, decoded);
        }
    }
}
