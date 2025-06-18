//! Integration tests for derive macros.

use bytes::BytesMut;
use commonware_codec::{codec::*, extensions::*, EncodeSize, Read, Write};

#[derive(Debug, Clone, PartialEq, Read, Write, EncodeSize)]
struct SimpleStruct {
    a: u32,
    b: u64,
    c: bool,
}

#[derive(Debug, Clone, PartialEq, Read, Write, EncodeSize)]
struct TupleStruct(u32, u64, bool);

#[derive(Debug, Clone, PartialEq, Read, Write, EncodeSize)]
struct UnitStruct;

#[derive(Debug, Clone, PartialEq, Read, Write, EncodeSize)]
struct NestedStruct {
    simple: SimpleStruct,
    value: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_struct_derive() {
        let original = SimpleStruct {
            a: 42,
            b: 1337,
            c: true,
        };

        // Test encode size
        let expected_size = 4 + 8 + 1; // u32 + u64 + bool
        assert_eq!(original.encode_size(), expected_size);

        // Test encode/decode
        let encoded = original.encode();
        assert_eq!(encoded.len(), expected_size);

        let decoded = SimpleStruct::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_tuple_struct_derive() {
        let original = TupleStruct(42, 1337, true);

        // Test encode size
        let expected_size = 4 + 8 + 1; // u32 + u64 + bool
        assert_eq!(original.encode_size(), expected_size);

        // Test encode/decode
        let encoded = original.encode();
        assert_eq!(encoded.len(), expected_size);

        let decoded = TupleStruct::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_unit_struct_derive() {
        let original = UnitStruct;

        // Test encode size
        assert_eq!(original.encode_size(), 0);

        // Test encode/decode
        let encoded = original.encode();
        assert_eq!(encoded.len(), 0);

        let decoded = UnitStruct::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_nested_struct_derive() {
        let original = NestedStruct {
            simple: SimpleStruct {
                a: 42,
                b: 1337,
                c: true,
            },
            value: 256,
        };

        // Test encode size
        let expected_size = (4 + 8 + 1) + 2; // SimpleStruct + u16
        assert_eq!(original.encode_size(), expected_size);

        // Test encode/decode
        let encoded = original.encode();
        assert_eq!(encoded.len(), expected_size);

        let decoded = NestedStruct::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_write_implementation() {
        let value = SimpleStruct {
            a: 42,
            b: 1337,
            c: true,
        };

        let mut buf = BytesMut::with_capacity(value.encode_size());
        value.write(&mut buf);

        // Verify the buffer has the expected length
        assert_eq!(buf.len(), value.encode_size());
    }

    #[test]
    fn test_read_implementation() {
        let original = SimpleStruct {
            a: 42,
            b: 1337,
            c: true,
        };

        let encoded = original.encode();
        let mut buf = &encoded[..];

        let decoded = SimpleStruct::read_cfg(&mut buf, &()).unwrap();
        assert_eq!(original, decoded);
        assert_eq!(buf.len(), 0); // All bytes should be consumed
    }
}
