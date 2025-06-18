//! Integration tests for derive macros.

use bytes::BytesMut;
use commonware_codec::{
    codec::*,
    extensions::*,
    varint::{SInt, UInt},
    EncodeSize, Read, Write,
};

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

#[derive(Debug, Clone, PartialEq, Read, Write, EncodeSize)]
struct VarintStruct {
    #[codec(varint)]
    a: u32,
    #[codec(varint)]
    b: i32,
    c: bool,
}

#[derive(Debug, Clone, PartialEq, Read, Write, EncodeSize)]
struct TupleVarintStruct(#[codec(varint)] u64, #[codec(varint)] i64, bool);

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

    #[test]
    fn test_varint_struct_derive() {
        let original = VarintStruct {
            a: 300,  // Will be encoded as varint
            b: -150, // Will be encoded as signed varint
            c: true,
        };

        // Compare with manual varint encoding
        let expected_a_size = UInt(original.a).encode_size();
        let expected_b_size = SInt(original.b).encode_size();
        let expected_size = expected_a_size + expected_b_size + 1; // +1 for bool

        assert_eq!(original.encode_size(), expected_size);

        // Test encode/decode
        let encoded = original.encode();
        assert_eq!(encoded.len(), expected_size);

        let decoded = VarintStruct::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_tuple_varint_struct_derive() {
        let original = TupleVarintStruct(1000000, -500000, false);

        // Compare with manual varint encoding
        let expected_0_size = UInt(original.0).encode_size();
        let expected_1_size = SInt(original.1).encode_size();
        let expected_size = expected_0_size + expected_1_size + 1; // +1 for bool

        assert_eq!(original.encode_size(), expected_size);

        // Test encode/decode
        let encoded = original.encode();
        assert_eq!(encoded.len(), expected_size);

        let decoded = TupleVarintStruct::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_varint_encoding_efficiency() {
        // Test that varint encoding is actually more efficient for small values
        let small_varint = VarintStruct {
            a: 127, // Should fit in 1 byte as varint
            b: -64, // Should fit in 1 byte as signed varint
            c: true,
        };

        let varint_size = small_varint.encode_size();
        // Should be much smaller than fixed-width encoding (4 + 4 + 1 = 9)
        assert!(
            varint_size < 5,
            "Varint encoding should be efficient for small values"
        );

        // Test large values still work
        let large_varint = VarintStruct {
            a: u32::MAX,
            b: i32::MIN,
            c: false,
        };

        let encoded = large_varint.encode();
        let decoded = VarintStruct::decode(encoded).unwrap();
        assert_eq!(large_varint, decoded);
    }
}
