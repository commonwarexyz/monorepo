//! Integration tests for derive macros.

use bytes::BytesMut;
use commonware_codec::{
    codec::*,
    extensions::*,
    varint::{SInt, UInt},
    EncodeSize, Error, FixedSize, Read, Write,
};
use commonware_codec_derive::FixedSize;

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

#[derive(Debug, Clone, PartialEq, Read, Write, EncodeSize)]
struct SimpleTest {
    count: u32,
}

#[derive(Debug, Clone, PartialEq, Read, Write, EncodeSize)]
struct ExplicitVecStruct {
    #[config(default)] // Uses Default::default() for Vec<u8>::Cfg = (RangeCfg, ())
    data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Read, Write, EncodeSize)]
struct DefaultConfigStruct {
    #[config(default)]
    default_data: Vec<u8>, // Uses Default::default() for (RangeCfg, ())
    count: u32, // Uses () (no config needed)
}
// Cfg type should be () since default_data is excluded and count needs no config

#[derive(Debug, Clone, PartialEq, Read, Write, EncodeSize)]
enum SimpleEnum {
    Unit,
    Tuple(u32),
    Struct { field: u16 },
}

#[derive(Debug, Clone, PartialEq, Read, Write, EncodeSize)]
enum VarintEnum {
    None,
    Value(#[codec(varint)] u32),
    Signed(#[codec(varint)] i32),
}

#[derive(Debug, Clone, PartialEq, Read, Write, EncodeSize)]
enum ComplexEnum {
    Empty,
    Single(bool),
    Double(u16, u32),
    Named {
        id: u8,
        #[codec(varint)]
        count: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Read, Write, EncodeSize)]
enum NestedEnum {
    Simple(SimpleEnum),
    WithStruct { point: SimpleStruct, tag: u8 },
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

    #[test]
    fn test_explicit_vec_struct() {
        let original = ExplicitVecStruct {
            data: vec![1, 2, 3, 4],
        };

        // ExplicitVecStruct uses #[config(default)] so cfg type is ()
        let cfg = ();

        let encoded = original.encode();
        let decoded = ExplicitVecStruct::read_cfg(&mut encoded.as_ref(), &cfg).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_default_config_struct() {
        let original = DefaultConfigStruct {
            default_data: vec![4, 5, 6, 7],
            count: 42,
        };

        // DefaultConfigStruct should have Cfg = () since all fields either use default or need no config
        let cfg = ();

        let encoded = original.encode();
        let decoded = DefaultConfigStruct::read_cfg(&mut encoded.as_ref(), &cfg).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_default_config_struct_default_field_uses_default() {
        let original = DefaultConfigStruct {
            default_data: vec![4; 1000], // Large vector that uses default config (unbounded)
            count: 42,
        };

        // Since default_data uses Default::default(), it should allow any size
        let cfg = ();

        let encoded = original.encode();
        let decoded = DefaultConfigStruct::read_cfg(&mut encoded.as_ref(), &cfg).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_simple_enum_unit() {
        let original = SimpleEnum::Unit;

        // Test encode size
        assert_eq!(original.encode_size(), 1); // Just discriminant

        // Test encode/decode
        let encoded = original.encode();
        assert_eq!(encoded.len(), 1);
        assert_eq!(encoded[0], 0); // First variant = discriminant 0

        let decoded = SimpleEnum::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_simple_enum_tuple() {
        let original = SimpleEnum::Tuple(42);

        // Test encode size
        assert_eq!(original.encode_size(), 1 + 4); // discriminant + u32

        // Test encode/decode
        let encoded = original.encode();
        assert_eq!(encoded.len(), 5);
        assert_eq!(encoded[0], 1); // Second variant = discriminant 1

        let decoded = SimpleEnum::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_simple_enum_struct() {
        let original = SimpleEnum::Struct { field: 1337 };

        // Test encode size
        assert_eq!(original.encode_size(), 1 + 2); // discriminant + u16

        // Test encode/decode
        let encoded = original.encode();
        assert_eq!(encoded.len(), 3);
        assert_eq!(encoded[0], 2); // Third variant = discriminant 2

        let decoded = SimpleEnum::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_varint_enum() {
        let test_cases = [
            VarintEnum::None,
            VarintEnum::Value(127), // Single byte varint
            VarintEnum::Value(300), // Multi-byte varint
            VarintEnum::Signed(-1),
            VarintEnum::Signed(-64),
        ];

        for original in test_cases {
            let encoded = original.encode();
            let decoded = VarintEnum::decode(encoded.clone()).unwrap();
            assert_eq!(original, decoded);

            // Verify that encode_size matches actual encoded length
            assert_eq!(original.encode_size(), encoded.len());
        }
    }

    #[test]
    fn test_varint_enum_efficiency() {
        // Test that varint encoding is more efficient for small values
        let small_value = VarintEnum::Value(127);
        let large_value = VarintEnum::Value(u32::MAX);

        // Small value should use fewer bytes than large value
        assert!(small_value.encode_size() < large_value.encode_size());

        // Small signed value should be efficient
        let small_signed = VarintEnum::Signed(-1);
        assert_eq!(small_signed.encode_size(), 2); // 1 discriminant + 1 varint byte
    }

    #[test]
    fn test_complex_enum() {
        let test_cases = [
            ComplexEnum::Empty,
            ComplexEnum::Single(true),
            ComplexEnum::Single(false),
            ComplexEnum::Double(0x1234, 0xABCDEF01),
            ComplexEnum::Named {
                id: 42,
                count: 1000000,
            },
        ];

        for original in test_cases {
            let encoded = original.encode();
            let decoded = ComplexEnum::decode(encoded.clone()).unwrap();
            assert_eq!(original, decoded);

            // Verify that encode_size matches actual encoded length
            assert_eq!(original.encode_size(), encoded.len());
        }
    }

    #[test]
    fn test_nested_enum() {
        let test_cases = [
            NestedEnum::Simple(SimpleEnum::Unit),
            NestedEnum::Simple(SimpleEnum::Tuple(123)),
            NestedEnum::Simple(SimpleEnum::Struct { field: 456 }),
            NestedEnum::WithStruct {
                point: SimpleStruct {
                    a: 1,
                    b: 2,
                    c: true,
                },
                tag: 99,
            },
        ];

        for original in test_cases {
            let encoded = original.encode();
            let decoded = NestedEnum::decode(encoded.clone()).unwrap();
            assert_eq!(original, decoded);

            // Verify that encode_size matches actual encoded length
            assert_eq!(original.encode_size(), encoded.len());
        }
    }

    #[test]
    fn test_enum_discriminant_values() {
        // Test that discriminants are assigned correctly (0, 1, 2, ...)
        let unit = SimpleEnum::Unit.encode();
        let tuple = SimpleEnum::Tuple(0).encode();
        let struct_variant = SimpleEnum::Struct { field: 0 }.encode();

        assert_eq!(unit[0], 0);
        assert_eq!(tuple[0], 1);
        assert_eq!(struct_variant[0], 2);
    }

    #[test]
    fn test_enum_invalid_discriminant() {
        // Test that invalid discriminants return InvalidEnum error
        let invalid_data = vec![255u8]; // Invalid discriminant for SimpleEnum
        let result = SimpleEnum::decode(&mut invalid_data.as_slice());

        assert!(matches!(result, Err(Error::InvalidEnum(255))));
    }

    #[test]
    fn test_enum_write_implementation() {
        let value = ComplexEnum::Named {
            id: 42,
            count: 1000,
        };

        let mut buf = BytesMut::with_capacity(value.encode_size());
        value.write(&mut buf);

        // Verify the buffer has the expected length
        assert_eq!(buf.len(), value.encode_size());
    }

    #[test]
    fn test_enum_read_implementation() {
        let original = ComplexEnum::Double(0x1234, 0xABCDEF01);

        let encoded = original.encode();
        let mut buf = &encoded[..];

        let decoded = ComplexEnum::read_cfg(&mut buf, &()).unwrap();
        assert_eq!(original, decoded);
        assert_eq!(buf.len(), 0); // All bytes should be consumed
    }

    #[test]
    fn test_enum_conformity() {
        // Test specific wire format expectations

        // Unit variant: just discriminant
        assert_eq!(SimpleEnum::Unit.encode().as_ref(), &[0]);

        // Tuple variant: discriminant + data
        assert_eq!(
            SimpleEnum::Tuple(0x1234).encode().as_ref(),
            &[1, 0x00, 0x00, 0x12, 0x34]
        );

        // Struct variant: discriminant + field data
        assert_eq!(
            SimpleEnum::Struct { field: 0xABCD }.encode().as_ref(),
            &[2, 0xAB, 0xCD]
        );

        // Complex enum with varints
        assert_eq!(VarintEnum::None.encode().as_ref(), &[0]);
        assert_eq!(VarintEnum::Value(127).encode().as_ref(), &[1, 0x7F]);
        assert_eq!(VarintEnum::Signed(-1).encode().as_ref(), &[2, 0x01]); // ZigZag encoding
    }
}

// FixedSize derive tests
#[derive(Debug, Clone, PartialEq, FixedSize)]
struct FixedSimpleStruct {
    a: u32,
    b: u64,
    c: bool,
}

#[derive(Debug, Clone, PartialEq, FixedSize)]
struct FixedTupleStruct(u32, u64, bool);

#[derive(Debug, Clone, PartialEq, FixedSize)]
struct FixedUnitStruct;

#[derive(Debug, Clone, PartialEq, FixedSize)]
struct FixedArrayStruct {
    header: [u8; 4],
    version: u16,
    flags: u8,
}

#[derive(Debug, Clone, PartialEq, FixedSize)]
struct FixedNestedStruct {
    point: FixedSimpleStruct,
    value: u16,
}

#[derive(Debug, Clone, PartialEq, FixedSize)]
struct FixedFloatStruct {
    x: f32,
    y: f64,
}

#[cfg(test)]
mod fixed_size_tests {
    use super::*;

    #[test]
    fn test_fixed_simple_struct() {
        // u32 (4) + u64 (8) + bool (1) = 13 bytes
        assert_eq!(FixedSimpleStruct::SIZE, 13);
    }

    #[test]
    fn test_fixed_tuple_struct() {
        // u32 (4) + u64 (8) + bool (1) = 13 bytes
        assert_eq!(FixedTupleStruct::SIZE, 13);
    }

    #[test]
    fn test_fixed_unit_struct() {
        // No fields = 0 bytes
        assert_eq!(FixedUnitStruct::SIZE, 0);
    }

    #[test]
    fn test_fixed_array_struct() {
        // [u8; 4] (4) + u16 (2) + u8 (1) = 7 bytes
        assert_eq!(FixedArrayStruct::SIZE, 7);
    }

    #[test]
    fn test_fixed_nested_struct() {
        // FixedSimpleStruct (13) + u16 (2) = 15 bytes
        assert_eq!(FixedNestedStruct::SIZE, 15);
    }

    #[test]
    fn test_fixed_float_struct() {
        // f32 (4) + f64 (8) = 12 bytes
        assert_eq!(FixedFloatStruct::SIZE, 12);
    }

    #[test]
    fn test_fixed_size_automatic_encode_size() {
        // FixedSize types should automatically implement EncodeSize
        let instance = FixedSimpleStruct {
            a: 42,
            b: 1337,
            c: true,
        };
        assert_eq!(instance.encode_size(), FixedSimpleStruct::SIZE);
        assert_eq!(instance.encode_size(), 13);
    }

    #[test]
    fn test_primitives_are_fixed_size() {
        // Verify that our primitive types have the expected sizes
        assert_eq!(u8::SIZE, 1);
        assert_eq!(u16::SIZE, 2);
        assert_eq!(u32::SIZE, 4);
        assert_eq!(u64::SIZE, 8);
        assert_eq!(i8::SIZE, 1);
        assert_eq!(i16::SIZE, 2);
        assert_eq!(i32::SIZE, 4);
        assert_eq!(i64::SIZE, 8);
        assert_eq!(f32::SIZE, 4);
        assert_eq!(f64::SIZE, 8);
        assert_eq!(bool::SIZE, 1);
    }

    #[test]
    fn test_array_fixed_size() {
        // Arrays should have fixed size equal to their length
        assert_eq!(<[u8; 10]>::SIZE, 10);
        assert_eq!(<[u8; 256]>::SIZE, 256);
    }
}
