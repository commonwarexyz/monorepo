//! Codec implementation for tuples.

use crate::{EncodeSize, Error, Read, Write};
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

            impl <$( [<T $index>]: Read ),*> Read for ( $( [<T $index>], )* ) {
                type Cfg = ( $( [<T $index>]::Cfg, )* );
                #[inline]
                fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
                    Ok(( $( [<T $index>]::read_cfg(buf, &cfg.$index)?, )* ))
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

    #[test]
    fn test_conformity() {
        let t1 = (true, 0x42u8);
        assert_eq!(t1.encode(), &[0x01, 0x42][..]);

        let t2 = (0xABCDu16, false, 0xDEADBEEFu32);
        assert_eq!(t2.encode(), &[0xAB, 0xCD, 0x00, 0xDE, 0xAD, 0xBE, 0xEF][..]);

        let t3 = ((0x01u8, 0x02u8), 0x03u8); // Nested tuple
        assert_eq!(t3.encode(), &[0x01, 0x02, 0x03][..]);

        let t_option_some = (Some(0x1234u16), 0xFFu8);
        // Some -> 0x01
        // 0x1234u16 -> 0x12, 0x34
        // 0xFFu8 -> 0xFF
        assert_eq!(t_option_some.encode(), &[0x01, 0x12, 0x34, 0xFF][..]);

        let t_option_none = (0xFFu8, Option::<u16>::None);
        // 0xFFu8 -> 0xFF
        // None -> 0x00
        assert_eq!(t_option_none.encode(), &[0xFF, 0x00][..]);
    }
}
