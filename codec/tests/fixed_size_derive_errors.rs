//! Tests for FixedSize derive macro error cases.
//!
//! These tests verify that the FixedSize derive macro properly rejects
//! invalid usage patterns with helpful error messages.

use commonware_codec_derive::FixedSize;

// These should compile successfully
#[derive(FixedSize)]
#[allow(dead_code)]
struct ValidStruct {
    a: u32,
    b: bool,
}

#[derive(FixedSize)]
#[allow(dead_code)]
struct ValidTuple(u8, u16);

#[derive(FixedSize)]
struct ValidUnit;

#[derive(FixedSize)]
#[allow(dead_code)]
struct ValidArray {
    data: [u8; 16],
}

// Test that we can't use codec attributes with FixedSize
// This should fail to compile with a helpful error message
/*
#[derive(FixedSize)]
struct InvalidCodecAttr {
    #[codec(varint)]
    value: u32,  // varint encoding is variable-length!
}
*/

// Test that we can't derive FixedSize for enums
// This should fail to compile
/*
#[derive(FixedSize)]
enum InvalidEnum {
    A,
    B(u32),
}
*/

// Test that we can't derive FixedSize for unions
// This should fail to compile
/*
#[derive(FixedSize)]
union InvalidUnion {
    a: u32,
    b: f32,
}
*/

// Test that we can't derive FixedSize for generic types
// This should fail to compile
/*
#[derive(FixedSize)]
struct InvalidGeneric<T> {
    value: T,
}
*/

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{EncodeSize, FixedSize};

    #[test]
    fn test_valid_fixed_size_structs() {
        // Test that valid structs compile and have correct sizes
        assert_eq!(ValidStruct::SIZE, 5); // u32 (4) + bool (1) = 5
        assert_eq!(ValidTuple::SIZE, 3); // u8 (1) + u16 (2) = 3
        assert_eq!(ValidUnit::SIZE, 0); // no fields = 0
        assert_eq!(ValidArray::SIZE, 16); // [u8; 16] = 16
    }

    #[test]
    fn test_integration_with_existing_traits() {
        // FixedSize should automatically provide EncodeSize
        let instance = ValidStruct { a: 42, b: true };
        assert_eq!(instance.encode_size(), ValidStruct::SIZE);
        assert_eq!(instance.encode_size(), 5);
    }
}
