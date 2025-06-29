//! Debug test for macro issues

use commonware_codec_derive::{Read, Write, EncodeSize};

#[derive(Debug, Clone, PartialEq, Read, Write, EncodeSize)]
enum SimpleEnum {
    Unit,
    Tuple(u32),
    Struct { field: u16 },
}

// Manual implementation for comparison
enum ManualEnum {
    Tuple(u32),
}

impl crate::Write for ManualEnum {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Tuple(field_0) => {
                bytes::BufMut::put_u8(buf, 0);
                crate::Write::write(&field_0, buf);
            }
        }
    }
}