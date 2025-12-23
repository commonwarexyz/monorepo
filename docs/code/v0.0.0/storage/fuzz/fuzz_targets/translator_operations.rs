#![no_main]

use commonware_storage::translator::{EightCap, FourCap, OneCap, Translator, TwoCap};
use libfuzzer_sys::{
    arbitrary::{Arbitrary, Unstructured},
    fuzz_target,
};
use std::hash::Hasher;

const MAX_KEY_LENGTH: usize = 1024;
const MAX_OPERATIONS: usize = 50;

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
        let translator_type = match u8::arbitrary(u)? % 3 {
            0 => TranslatorType::One,
            1 => TranslatorType::Two,
            2 => TranslatorType::Four,
            _ => TranslatorType::Eight,
        };

        let num_operations = u.int_in_range(1..=MAX_OPERATIONS)?;
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

fn test_cap<T: Translator>(translator: T, cap: usize, operations: &[Operation]) {
    for op in operations {
        match op {
            Operation::Transform { key } => {
                let result = translator.transform(key);
                assert_eq!(size_of_val(&result), cap);
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
        TranslatorType::One => {
            let t = OneCap;
            test_cap(t, 1, &input.operations)
        }
        TranslatorType::Two => {
            let t = TwoCap;
            test_cap(t, 2, &input.operations)
        }
        TranslatorType::Four => {
            let t = FourCap;
            test_cap(t, 4, &input.operations)
        }
        TranslatorType::Eight => {
            let t = EightCap;
            test_cap(t, 8, &input.operations)
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
