#![no_main]

use commonware_storage::translator::{EightCap, FourCap, OneCap, Translator, TwoCap};
use libfuzzer_sys::{
    arbitrary::{Arbitrary, Unstructured},
    fuzz_target,
};
use std::hash::{BuildHasher, Hasher};

const MAX_KEY_LENGTH: usize = 1024;
const MAX_OPERATIONS: usize = 100;

#[derive(Clone, Debug)]
enum TranslatorType {
    One,
    Two,
    Four,
    Eight,
}

#[derive(Clone, Debug)]
enum Operation {
    Transform { key: Vec<u8> },
    BuildHasher,
    HashValue { value_type: ValueType },
}

#[derive(Clone, Debug)]
enum ValueType {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
}

#[derive(Clone, Debug)]
struct FuzzInput {
    translator_type: TranslatorType,
    operations: Vec<Operation>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self, arbitrary::Error> {
        let translator_type = match u8::arbitrary(u)? % 4 {
            0 => TranslatorType::One,
            1 => TranslatorType::Two,
            2 => TranslatorType::Four,
            _ => TranslatorType::Eight,
        };

        let num_operations = (u8::arbitrary(u)? as usize) % MAX_OPERATIONS + 1;
        let mut operations = Vec::with_capacity(num_operations);

        for _ in 0..num_operations {
            let op = match u8::arbitrary(u)? % 3 {
                0 => {
                    let key_len = (u16::arbitrary(u)? as usize) % MAX_KEY_LENGTH;
                    let mut key = vec![0u8; key_len];
                    for byte in &mut key {
                        *byte = u8::arbitrary(u)?;
                    }
                    Operation::Transform { key }
                }
                1 => Operation::BuildHasher,
                _ => {
                    let value_type = match u8::arbitrary(u)? % 4 {
                        0 => ValueType::U8(u8::arbitrary(u)?),
                        1 => ValueType::U16(u16::arbitrary(u)?),
                        2 => ValueType::U32(u32::arbitrary(u)?),
                        _ => ValueType::U64(u64::arbitrary(u)?),
                    };
                    Operation::HashValue { value_type }
                }
            };
            operations.push(op);
        }

        Ok(FuzzInput {
            translator_type,
            operations,
        })
    }
}

fn test_one_cap(operations: &[Operation]) {
    let translator = OneCap;

    for op in operations {
        match op {
            Operation::Transform { key } => {
                let result = translator.transform(key);
                let bytes = result.to_le_bytes();

                if key.is_empty() {
                    assert_eq!(bytes[0], 0);
                } else {
                    assert_eq!(bytes[0], key[0]);
                }

                let expected = if key.is_empty() { 0 } else { key[0] };
                assert_eq!(result, expected);
            }
            Operation::BuildHasher => {
                let hasher = translator.build_hasher();
                let _ = hasher;
            }
            Operation::HashValue { value_type } => {
                let mut hasher = translator.build_hasher();
                match value_type {
                    ValueType::U8(v) => {
                        hasher.write_u8(*v);
                        assert_eq!(hasher.finish(), *v as u64);
                    }
                    ValueType::U16(v) => {
                        hasher.write_u16(*v);
                        assert_eq!(hasher.finish(), *v as u64);
                    }
                    ValueType::U32(v) => {
                        hasher.write_u32(*v);
                        assert_eq!(hasher.finish(), *v as u64);
                    }
                    ValueType::U64(v) => {
                        hasher.write_u64(*v);
                        assert_eq!(hasher.finish(), *v);
                    }
                }
            }
        }
    }
}

fn test_two_cap(operations: &[Operation]) {
    let translator = TwoCap;

    for op in operations {
        match op {
            Operation::Transform { key } => {
                let result = translator.transform(key);
                let bytes = result.to_le_bytes();

                match key.len() {
                    0 => assert_eq!(bytes, [0, 0]),
                    1 => assert_eq!(bytes, [key[0], 0]),
                    _ => assert_eq!(bytes, [key[0], key[1]]),
                }
            }
            Operation::BuildHasher => {
                let hasher = translator.build_hasher();
                let _ = hasher;
            }
            Operation::HashValue { value_type } => {
                let mut hasher = translator.build_hasher();
                match value_type {
                    ValueType::U8(v) => {
                        hasher.write_u8(*v);
                        assert_eq!(hasher.finish(), *v as u64);
                    }
                    ValueType::U16(v) => {
                        hasher.write_u16(*v);
                        assert_eq!(hasher.finish(), *v as u64);
                    }
                    ValueType::U32(v) => {
                        hasher.write_u32(*v);
                        assert_eq!(hasher.finish(), *v as u64);
                    }
                    ValueType::U64(v) => {
                        hasher.write_u64(*v);
                        assert_eq!(hasher.finish(), *v);
                    }
                }
            }
        }
    }
}

fn test_four_cap(operations: &[Operation]) {
    let translator = FourCap;

    for op in operations {
        match op {
            Operation::Transform { key } => {
                let result = translator.transform(key);
                let bytes = result.to_le_bytes();

                let mut expected = [0u8; 4];
                let len = key.len().min(4);
                expected[..len].copy_from_slice(&key[..len]);
                assert_eq!(bytes, expected);
            }
            Operation::BuildHasher => {
                let hasher = translator.build_hasher();
                let _ = hasher;
            }
            Operation::HashValue { value_type } => {
                let mut hasher = translator.build_hasher();
                match value_type {
                    ValueType::U8(v) => {
                        hasher.write_u8(*v);
                        assert_eq!(hasher.finish(), *v as u64);
                    }
                    ValueType::U16(v) => {
                        hasher.write_u16(*v);
                        assert_eq!(hasher.finish(), *v as u64);
                    }
                    ValueType::U32(v) => {
                        hasher.write_u32(*v);
                        assert_eq!(hasher.finish(), *v as u64);
                    }
                    ValueType::U64(v) => {
                        hasher.write_u64(*v);
                        assert_eq!(hasher.finish(), *v);
                    }
                }
            }
        }
    }
}

fn test_eight_cap(operations: &[Operation]) {
    let translator = EightCap;

    for op in operations {
        match op {
            Operation::Transform { key } => {
                let result = translator.transform(key);
                let bytes = result.to_le_bytes();

                let mut expected = [0u8; 8];
                let len = key.len().min(8);
                expected[..len].copy_from_slice(&key[..len]);
                assert_eq!(bytes, expected);
            }
            Operation::BuildHasher => {
                let hasher = translator.build_hasher();
                let _ = hasher;
            }
            Operation::HashValue { value_type } => {
                let mut hasher = translator.build_hasher();
                match value_type {
                    ValueType::U8(v) => {
                        hasher.write_u8(*v);
                        assert_eq!(hasher.finish(), *v as u64);
                    }
                    ValueType::U16(v) => {
                        hasher.write_u16(*v);
                        assert_eq!(hasher.finish(), *v as u64);
                    }
                    ValueType::U32(v) => {
                        hasher.write_u32(*v);
                        assert_eq!(hasher.finish(), *v as u64);
                    }
                    ValueType::U64(v) => {
                        hasher.write_u64(*v);
                        assert_eq!(hasher.finish(), *v);
                    }
                }
            }
        }
    }
}

fn fuzz(input: FuzzInput) {
    match input.translator_type {
        TranslatorType::One => test_one_cap(&input.operations),
        TranslatorType::Two => test_two_cap(&input.operations),
        TranslatorType::Four => test_four_cap(&input.operations),
        TranslatorType::Eight => test_eight_cap(&input.operations),
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
