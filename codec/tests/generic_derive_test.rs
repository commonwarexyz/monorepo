//! Integration tests for derive macros with generic types.

use bytes::BytesMut;
use commonware_codec::{codec::*, extensions::*, varint::UInt, EncodeSize, Error, Read, Write};

// Basic generic struct
#[derive(Debug, Clone, PartialEq, Read, Write, EncodeSize)]
struct GenericStruct<T>
where
    T: Read<Cfg = ()> + Write + EncodeSize,
{
    value: T,
}

// Generic struct with multiple fields
#[derive(Debug, Clone, PartialEq, Read, Write, EncodeSize)]
struct MultiFieldGeneric<T>
where
    T: Read<Cfg = ()> + Write + EncodeSize,
{
    first: T,
    second: u32,
    third: bool,
}

// Generic tuple struct
#[derive(Debug, Clone, PartialEq, Read, Write, EncodeSize)]
struct GenericTuple<T>(T, u16)
where
    T: Read<Cfg = ()> + Write + EncodeSize;

// Generic struct with bounds
#[derive(Debug, Clone, PartialEq, Read, Write, EncodeSize)]
struct BoundedGeneric<T>
where
    T: Clone + Read<Cfg = ()> + Write + EncodeSize,
{
    data: T,
}

// Multiple type parameters
#[derive(Debug, Clone, PartialEq, Read, Write, EncodeSize)]
struct MultiGeneric<T, U>
where
    T: Read<Cfg = ()> + Write + EncodeSize,
    U: Read<Cfg = ()> + Write + EncodeSize,
{
    first: T,
    second: U,
}

// Generic with varint attributes
#[derive(Debug, Clone, PartialEq, Read, Write, EncodeSize)]
struct GenericVarint<T>
where
    T: Read<Cfg = ()> + Write + EncodeSize,
{
    #[codec(varint)]
    count: u32,
    value: T,
}

// Generic enum
#[derive(Debug, Clone, PartialEq, Read, Write, EncodeSize)]
enum GenericEnum<T>
where
    T: Read<Cfg = ()> + Write + EncodeSize,
{
    None,
    Some(T),
    Pair(T, T),
    Named { value: T, tag: u8 },
}

// Generic enum with multiple type parameters
#[derive(Debug, Clone, PartialEq, Read, Write, EncodeSize)]
enum MultiGenericEnum<T, U>
where
    T: Read<Cfg = ()> + Write + EncodeSize,
    U: Read<Cfg = ()> + Write + EncodeSize,
{
    First(T),
    Second(U),
    Both(T, U),
}

// Nested generic types
#[derive(Debug, Clone, PartialEq, Read, Write, EncodeSize)]
struct NestedGeneric<T>
where
    T: Read<Cfg = ()> + Write + EncodeSize,
{
    inner: GenericStruct<T>,
    outer: u32,
}

// Generic with Option
#[derive(Debug, Clone, PartialEq, Read, Write, EncodeSize)]
struct GenericOption<T>
where
    T: Read<Cfg = ()> + Write + EncodeSize,
{
    maybe_value: Option<T>,
    always_present: u64,
}

// Generic with Vec (requires config handling)
#[derive(Debug, Clone, PartialEq, Read, Write, EncodeSize)]
struct GenericVec<T>
where
    T: Read<Cfg = ()> + Write + EncodeSize,
{
    #[config(default)]
    items: Vec<T>,
    count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generic_struct_u32() {
        let original = GenericStruct { value: 42u32 };

        let expected_size = 4; // u32
        assert_eq!(original.encode_size(), expected_size);

        let encoded = original.encode();
        assert_eq!(encoded.len(), expected_size);

        let decoded = GenericStruct::<u32>::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_generic_struct_bool() {
        let original = GenericStruct { value: true };

        let expected_size = 1; // bool
        assert_eq!(original.encode_size(), expected_size);

        let encoded = original.encode();
        assert_eq!(encoded.len(), expected_size);

        let decoded = GenericStruct::<bool>::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_generic_struct_nested() {
        let original = GenericStruct {
            value: GenericStruct { value: 123u64 },
        };

        let expected_size = 8; // u64
        assert_eq!(original.encode_size(), expected_size);

        let encoded = original.encode();
        assert_eq!(encoded.len(), expected_size);

        let decoded = GenericStruct::<GenericStruct<u64>>::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_multi_field_generic() {
        let original = MultiFieldGeneric {
            first: 1337u64,
            second: 42u32,
            third: false,
        };

        let expected_size = 8 + 4 + 1; // u64 + u32 + bool
        assert_eq!(original.encode_size(), expected_size);

        let encoded = original.encode();
        assert_eq!(encoded.len(), expected_size);

        let decoded = MultiFieldGeneric::<u64>::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_generic_tuple() {
        let original = GenericTuple(42u32, 1337u16);

        let expected_size = 4 + 2; // u32 + u16
        assert_eq!(original.encode_size(), expected_size);

        let encoded = original.encode();
        assert_eq!(encoded.len(), expected_size);

        let decoded = GenericTuple::<u32>::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_bounded_generic() {
        let original = BoundedGeneric { data: 999u32 };

        let expected_size = 4; // u32
        assert_eq!(original.encode_size(), expected_size);

        let encoded = original.encode();
        assert_eq!(encoded.len(), expected_size);

        let decoded = BoundedGeneric::<u32>::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_multi_generic() {
        let original = MultiGeneric {
            first: 42u32,
            second: true,
        };

        let expected_size = 4 + 1; // u32 + bool
        assert_eq!(original.encode_size(), expected_size);

        let encoded = original.encode();
        assert_eq!(encoded.len(), expected_size);

        let decoded = MultiGeneric::<u32, bool>::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_generic_varint() {
        let original = GenericVarint {
            count: 1000,
            value: std::f32::consts::PI,
        };

        let expected_count_size = UInt(original.count).encode_size();
        let expected_size = expected_count_size + 4; // varint + f32
        assert_eq!(original.encode_size(), expected_size);

        let encoded = original.encode();
        assert_eq!(encoded.len(), expected_size);

        let decoded = GenericVarint::<f32>::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_generic_enum_none() {
        let original = GenericEnum::<u32>::None;

        let expected_size = 1; // discriminant only
        assert_eq!(original.encode_size(), expected_size);

        let encoded = original.encode();
        assert_eq!(encoded.len(), expected_size);
        assert_eq!(encoded[0], 0); // First variant

        let decoded = GenericEnum::<u32>::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_generic_enum_some() {
        let original = GenericEnum::Some(42u32);

        let expected_size = 1 + 4; // discriminant + u32
        assert_eq!(original.encode_size(), expected_size);

        let encoded = original.encode();
        assert_eq!(encoded.len(), expected_size);
        assert_eq!(encoded[0], 1); // Second variant

        let decoded = GenericEnum::<u32>::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_generic_enum_pair() {
        let original = GenericEnum::Pair(10u16, 20u16);

        let expected_size = 1 + 2 + 2; // discriminant + u16 + u16
        assert_eq!(original.encode_size(), expected_size);

        let encoded = original.encode();
        assert_eq!(encoded.len(), expected_size);
        assert_eq!(encoded[0], 2); // Third variant

        let decoded = GenericEnum::<u16>::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_generic_enum_named() {
        let original = GenericEnum::Named {
            value: 123u64,
            tag: 99u8,
        };

        let expected_size = 1 + 8 + 1; // discriminant + u64 + u8
        assert_eq!(original.encode_size(), expected_size);

        let encoded = original.encode();
        assert_eq!(encoded.len(), expected_size);
        assert_eq!(encoded[0], 3); // Fourth variant

        let decoded = GenericEnum::<u64>::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_multi_generic_enum() {
        let test_cases = [
            MultiGenericEnum::First(42u32),
            MultiGenericEnum::Second(true),
            MultiGenericEnum::Both(100u32, false),
        ];

        for original in test_cases {
            let encoded = original.encode();
            let decoded = MultiGenericEnum::<u32, bool>::decode(encoded.clone()).unwrap();
            assert_eq!(original, decoded);

            // Verify that encode_size matches actual encoded length
            assert_eq!(original.encode_size(), encoded.len());
        }
    }

    #[test]
    fn test_nested_generic() {
        let original = NestedGeneric {
            inner: GenericStruct { value: 999u32 },
            outer: 777u32,
        };

        let expected_size = 4 + 4; // inner u32 + outer u32
        assert_eq!(original.encode_size(), expected_size);

        let encoded = original.encode();
        assert_eq!(encoded.len(), expected_size);

        let decoded = NestedGeneric::<u32>::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_generic_option_some() {
        let original = GenericOption {
            maybe_value: Some(42u32),
            always_present: 1337u64,
        };

        let expected_size = 1 + 4 + 8; // Option discriminant + u32 + u64
        assert_eq!(original.encode_size(), expected_size);

        let encoded = original.encode();
        assert_eq!(encoded.len(), expected_size);

        let decoded = GenericOption::<u32>::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_generic_option_none() {
        let original = GenericOption::<u32> {
            maybe_value: None,
            always_present: 1337u64,
        };

        let expected_size = 1 + 8; // Option discriminant + u64 (no u32 for None)
        assert_eq!(original.encode_size(), expected_size);

        let encoded = original.encode();
        assert_eq!(encoded.len(), expected_size);

        let decoded = GenericOption::<u32>::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_generic_vec() {
        let original = GenericVec {
            items: vec![1u32, 2u32, 3u32],
            count: 42u32,
        };

        // Vec uses default config, so Cfg should be ()
        let cfg = ();

        let encoded = original.encode();
        let decoded = GenericVec::<u32>::read_cfg(&mut encoded.as_ref(), &cfg).unwrap();
        assert_eq!(original, decoded);

        // Verify encode_size matches
        assert_eq!(original.encode_size(), encoded.len());
    }

    #[test]
    fn test_generic_write_implementation() {
        let value = MultiGeneric {
            first: 42u32,
            second: true,
        };

        let mut buf = BytesMut::with_capacity(value.encode_size());
        value.write(&mut buf);

        // Verify the buffer has the expected length
        assert_eq!(buf.len(), value.encode_size());
    }

    #[test]
    fn test_generic_read_implementation() {
        let original = GenericStruct { value: 1337u64 };

        let encoded = original.encode();
        let mut buf = &encoded[..];

        let decoded = GenericStruct::<u64>::read_cfg(&mut buf, &()).unwrap();
        assert_eq!(original, decoded);
        assert_eq!(buf.len(), 0); // All bytes should be consumed
    }

    #[test]
    fn test_complex_generic_combination() {
        // Test a complex combination of nested generics
        type ComplexType = GenericStruct<MultiGeneric<GenericEnum<u32>, GenericOption<bool>>>;

        let original = GenericStruct {
            value: MultiGeneric {
                first: GenericEnum::Some(999u32),
                second: GenericOption {
                    maybe_value: Some(true),
                    always_present: 12345u64,
                },
            },
        };

        let encoded = original.encode();
        let decoded = ComplexType::decode(encoded.clone()).unwrap();
        assert_eq!(original, decoded);

        // Verify that encode_size matches actual encoded length
        assert_eq!(original.encode_size(), encoded.len());
    }

    #[test]
    fn test_generic_enum_invalid_discriminant() {
        // Test that invalid discriminants return InvalidEnum error for generic enums
        let invalid_data = vec![255u8]; // Invalid discriminant for GenericEnum<u32>
        let result = GenericEnum::<u32>::decode(&mut invalid_data.as_slice());

        assert!(matches!(result, Err(Error::InvalidEnum(255))));
    }
}
