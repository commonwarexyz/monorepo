//! Manual implementation to understand the issue

use crate::{Write, EncodeSize};
use bytes::BufMut;

enum TestEnum {
    Tuple(u32),
}

impl Write for TestEnum {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Tuple(ref field_0) => {
                buf.put_u8(0);
                // Try both approaches:
                // field_0.write(buf);                // Method syntax
                Write::write(field_0, buf);    // Static syntax with ref
            }
        }
    }
}

impl EncodeSize for TestEnum {
    fn encode_size(&self) -> usize {
        match self {
            Self::Tuple(field_0) => {
                1 + field_0.encode_size()  // Method syntax
                // 1 + EncodeSize::encode_size(&field_0)  // Static syntax
            }
        }
    }
}