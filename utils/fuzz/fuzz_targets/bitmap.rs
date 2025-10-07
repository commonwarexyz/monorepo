#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_codec::codec::{EncodeSize, Read, Write};
use libfuzzer_sys::fuzz_target;

const MAX_SIZE: usize = 100_000;

// Alias to avoid having to specify the chunk size in every test case.
type BitMap = commonware_utils::bitmap::BitMap;

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    New,
    WithCapacity(usize),
    Zeroes(u64),
    Ones(u64),
    FromBools(Vec<bool>),
    Push(Vec<bool>, bool),
    Pop(Vec<bool>),
    Iter(Vec<bool>),
    Get(Vec<bool>, u64),
    Set(Vec<bool>, u64),
    Clear(Vec<bool>, u64),
    Flip(Vec<bool>, u64),
    FlipAll(Vec<bool>),
    SetTo(Vec<bool>, u64, bool),
    SetAll(Vec<bool>, bool),
    And(Vec<bool>, Vec<bool>),
    Or(Vec<bool>, Vec<bool>),
    Xor(Vec<bool>, Vec<bool>),
    Default,
    FromSliceBool(Vec<bool>),
    FromVecBool(Vec<bool>),
    BoolInto(Vec<bool>),
    FromArrayBool(FixedBoolArray),
    FromRefArrayBool(FixedBoolArray),
    ToVecBool(Vec<bool>),
    Debug(Vec<bool>),
    Index(Vec<bool>, u64),
    BitAndOp(Vec<bool>, Vec<bool>),
    BitOrOp(Vec<bool>, Vec<bool>),
    BitXorOp(Vec<bool>, Vec<bool>),
    Codec(Vec<bool>),
    IteratorOps(Vec<bool>),
}

#[derive(Debug)]
enum FixedBoolArray {
    V0([bool; 0]),
    V1([bool; 1]),
    V2([bool; 2]),
    V7([bool; 7]),
    V8([bool; 8]),
    V9([bool; 9]),
    V15([bool; 15]),
    V16([bool; 16]),
    V17([bool; 17]),
    V31([bool; 31]),
    V32([bool; 32]),
    V33([bool; 33]),
    V63([bool; 63]),
    V64([bool; 64]),
    V65([bool; 65]),
    V127([bool; 127]),
    V128([bool; 128]),
    V129([bool; 129]),
    V255([bool; 255]),
    V256([bool; 256]),
    V257([bool; 257]),
}

fn gen_array<const N: usize>(u: &mut Unstructured) -> arbitrary::Result<[bool; N]> {
    let mut arr = [false; N];
    for e in &mut arr {
        let b: u8 = Arbitrary::arbitrary(u)?;
        *e = (b & 1) != 0;
    }
    Ok(arr)
}

impl<'a> Arbitrary<'a> for FixedBoolArray {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        const COUNT: usize = 21;
        let idx = u.choose_index(COUNT)?;
        Ok(match idx {
            0 => Self::V0(gen_array::<0>(u)?),
            1 => Self::V1(gen_array::<1>(u)?),
            2 => Self::V2(gen_array::<2>(u)?),
            3 => Self::V7(gen_array::<7>(u)?),
            4 => Self::V8(gen_array::<8>(u)?),
            5 => Self::V9(gen_array::<9>(u)?),
            6 => Self::V15(gen_array::<15>(u)?),
            7 => Self::V16(gen_array::<16>(u)?),
            8 => Self::V17(gen_array::<17>(u)?),
            9 => Self::V31(gen_array::<31>(u)?),
            10 => Self::V32(gen_array::<32>(u)?),
            11 => Self::V33(gen_array::<33>(u)?),
            12 => Self::V63(gen_array::<63>(u)?),
            13 => Self::V64(gen_array::<64>(u)?),
            14 => Self::V65(gen_array::<65>(u)?),
            15 => Self::V127(gen_array::<127>(u)?),
            16 => Self::V128(gen_array::<128>(u)?),
            17 => Self::V129(gen_array::<129>(u)?),
            18 => Self::V255(gen_array::<255>(u)?),
            19 => Self::V256(gen_array::<256>(u)?),
            20 => Self::V257(gen_array::<257>(u)?),
            _ => unreachable!(),
        })
    }
}

fn check_from_array<const N: usize>(arr: [bool; N]) {
    let bv_a: BitMap = arr.into();
    let bv_b: BitMap = <BitMap as From<&[bool; N]>>::from(&arr);
    let bv_c = BitMap::from(&arr);
    assert_eq!(bv_a.len(), N as u64);
    assert_eq!(bv_a, bv_b);
    assert_eq!(bv_a, bv_c);

    for (i, &b) in arr.iter().enumerate() {
        let i = i as u64;
        assert_eq!(bv_a.get(i), b);
        assert_eq!(bv_b.get(i), b);
    }

    let round_a: Vec<bool> = bv_a.into();
    assert_eq!(round_a.as_slice(), &arr);

    let round_b: Vec<bool> = bv_b.into();
    assert_eq!(round_b.as_slice(), &arr);
}

fn fuzz(input: Vec<FuzzInput>) {
    for op in input {
        match op {
            FuzzInput::New => {
                let v = BitMap::new();
                assert!(v.is_empty());
                assert_eq!(v.len(), 0);
            }

            FuzzInput::WithCapacity(cap) => {
                let bv = BitMap::with_capacity(cap.min(MAX_SIZE) as u64);
                assert!(bv.is_empty());
                assert_eq!(bv.len(), 0);
            }

            FuzzInput::Zeroes(size) => {
                let size = size.min(MAX_SIZE as u64);
                let v = BitMap::zeroes(size);
                assert_eq!(v.len(), size);
                assert_eq!(v.count_zeros(), size);
                assert_eq!(v.count_ones(), 0);

                for i in 0..size {
                    assert!(!v.get(i));
                }
            }

            FuzzInput::Ones(size) => {
                let size = size.min(MAX_SIZE as u64);
                let v = BitMap::ones(size);
                assert_eq!(v.len(), size);
                assert_eq!(v.count_ones(), size);
                assert_eq!(v.count_zeros(), 0);

                for i in 0..size {
                    assert!(v.get(i));
                }
            }

            FuzzInput::FromBools(bools) => {
                let v = BitMap::from(&bools);
                assert_eq!(v.len(), bools.len() as u64);

                for (i, &b) in bools.iter().enumerate() {
                    assert_eq!(v.get(i as u64), b);
                }
            }

            FuzzInput::Push(bools, value) => {
                let mut v = BitMap::from(&bools);
                let old_len = v.len();
                v.push(value);
                assert_eq!(v.len(), old_len + 1);
                assert_eq!(v.get(old_len), value);
            }

            FuzzInput::Pop(bools) => {
                let mut v = BitMap::from(&bools);
                let old_len = v.len();
                if old_len == 0 {
                    return;
                }
                let popped = v.pop();
                assert_eq!(v.len(), old_len - 1);
                assert_eq!(popped, bools[old_len as usize - 1]);
            }

            FuzzInput::Iter(bools) => {
                let v = BitMap::from(&bools);
                let i = v.iter();
                assert_eq!(v.len(), i.len() as u64);
            }

            FuzzInput::Get(bools, bit) => {
                let v = BitMap::from(&bools);
                let v_len = v.len();

                if bit >= v_len {
                    return;
                }

                let result = v.get(bit);
                assert_eq!(result, bools[bit as usize]);
            }

            FuzzInput::Set(bools, bit) => {
                let mut v = BitMap::from(&bools);
                if bit < v.len() {
                    v.set(bit, true);
                    assert!(v.get(bit));
                }
            }

            FuzzInput::Clear(bools, bit) => {
                let mut v = BitMap::from(&bools);
                if bit < v.len() {
                    v.set(bit, false);
                    assert!(!v.get(bit));
                }
            }

            FuzzInput::Flip(bools, bit) => {
                let mut v = BitMap::from(&bools);
                if bit < v.len() {
                    let old_value = v.get(bit);
                    v.flip(bit);
                    assert_eq!(v.get(bit), !old_value);
                }
            }

            FuzzInput::SetTo(bools, bit, value) => {
                let mut v = BitMap::from(&bools);
                if bit < v.len() {
                    v.set(bit, value);
                    assert_eq!(v.get(bit), value);
                }
            }

            FuzzInput::SetAll(bools, value) => {
                let mut v = BitMap::from(&bools);
                v.set_all(value);
                assert_eq!(v.count_zeros(), if value { 0 } else { v.len() });
                assert_eq!(v.count_ones(), if value { v.len() } else { 0 });
            }

            FuzzInput::And(bools1, bools2) => {
                if bools1.len() != bools2.len() {
                    return;
                }
                let mut v1 = BitMap::from(&bools1);
                let v2 = BitMap::from(&bools2);
                let old_len = v1.len();
                v1.and(&v2);

                assert_eq!(v1.len(), old_len);
            }

            FuzzInput::Or(bools1, bools2) => {
                if bools1.len() != bools2.len() {
                    return;
                }
                let mut v1 = BitMap::from(&bools1);
                let v2 = BitMap::from(&bools2);
                let old_len = v1.len();
                v1.or(&v2);

                assert_eq!(v1.len(), old_len);
            }

            FuzzInput::Xor(bools1, bools2) => {
                if bools1.len() != bools2.len() {
                    return;
                }
                let mut v1 = BitMap::from(&bools1);
                let v2 = BitMap::from(&bools2);
                let old_len = v1.len();
                v1.xor(&v2);

                assert_eq!(v1.len(), old_len);
            }

            FuzzInput::FlipAll(bools) => {
                let mut v = BitMap::from(&bools);
                let old_ones = v.count_ones();
                let old_zeros = v.count_zeros();
                let old_len = v.len();
                v.flip_all();

                assert_eq!(v.len(), old_len);
                assert_eq!(v.count_ones(), old_zeros);
                assert_eq!(v.count_zeros(), old_ones);
            }

            FuzzInput::Default => {
                let v = BitMap::default();
                assert!(v.is_empty());
                assert_eq!(v.len(), 0);
            }

            FuzzInput::FromSliceBool(bools) => {
                let v: BitMap = bools.as_slice().into();
                assert_eq!(v.len(), bools.len() as u64);
                for (i, &b) in bools.iter().enumerate() {
                    assert_eq!(v.get(i as u64), b);
                }
            }

            FuzzInput::FromVecBool(bools) => {
                let ln = bools.len();
                let v = BitMap::from(bools);
                assert_eq!(v.len(), ln as u64);
            }

            FuzzInput::BoolInto(bools) => {
                let v: BitMap = bools.clone().into();
                assert_eq!(v.len(), bools.len() as u64);
                for (i, &b) in bools.iter().enumerate() {
                    assert_eq!(v.get(i as u64), b);
                }
            }

            FuzzInput::FromArrayBool(case) => match case {
                FixedBoolArray::V0(arr) => check_from_array::<0>(arr),
                FixedBoolArray::V1(arr) => check_from_array::<1>(arr),
                FixedBoolArray::V2(arr) => check_from_array::<2>(arr),
                FixedBoolArray::V7(arr) => check_from_array::<7>(arr),
                FixedBoolArray::V8(arr) => check_from_array::<8>(arr),
                FixedBoolArray::V9(arr) => check_from_array::<9>(arr),
                FixedBoolArray::V15(arr) => check_from_array::<15>(arr),
                FixedBoolArray::V16(arr) => check_from_array::<16>(arr),
                FixedBoolArray::V17(arr) => check_from_array::<17>(arr),
                FixedBoolArray::V31(arr) => check_from_array::<31>(arr),
                FixedBoolArray::V32(arr) => check_from_array::<32>(arr),
                FixedBoolArray::V33(arr) => check_from_array::<33>(arr),
                FixedBoolArray::V63(arr) => check_from_array::<63>(arr),
                FixedBoolArray::V64(arr) => check_from_array::<64>(arr),
                FixedBoolArray::V65(arr) => check_from_array::<65>(arr),
                FixedBoolArray::V127(arr) => check_from_array::<127>(arr),
                FixedBoolArray::V128(arr) => check_from_array::<128>(arr),
                FixedBoolArray::V129(arr) => check_from_array::<129>(arr),
                FixedBoolArray::V255(arr) => check_from_array::<255>(arr),
                FixedBoolArray::V256(arr) => check_from_array::<256>(arr),
                FixedBoolArray::V257(arr) => check_from_array::<257>(arr),
            },

            FuzzInput::FromRefArrayBool(case) => match case {
                FixedBoolArray::V0(arr) => check_from_array::<0>(arr),
                FixedBoolArray::V1(arr) => check_from_array::<1>(arr),
                FixedBoolArray::V2(arr) => check_from_array::<2>(arr),
                FixedBoolArray::V7(arr) => check_from_array::<7>(arr),
                FixedBoolArray::V8(arr) => check_from_array::<8>(arr),
                FixedBoolArray::V9(arr) => check_from_array::<9>(arr),
                FixedBoolArray::V15(arr) => check_from_array::<15>(arr),
                FixedBoolArray::V16(arr) => check_from_array::<16>(arr),
                FixedBoolArray::V17(arr) => check_from_array::<17>(arr),
                FixedBoolArray::V31(arr) => check_from_array::<31>(arr),
                FixedBoolArray::V32(arr) => check_from_array::<32>(arr),
                FixedBoolArray::V33(arr) => check_from_array::<33>(arr),
                FixedBoolArray::V63(arr) => check_from_array::<63>(arr),
                FixedBoolArray::V64(arr) => check_from_array::<64>(arr),
                FixedBoolArray::V65(arr) => check_from_array::<65>(arr),
                FixedBoolArray::V127(arr) => check_from_array::<127>(arr),
                FixedBoolArray::V128(arr) => check_from_array::<128>(arr),
                FixedBoolArray::V129(arr) => check_from_array::<129>(arr),
                FixedBoolArray::V255(arr) => check_from_array::<255>(arr),
                FixedBoolArray::V256(arr) => check_from_array::<256>(arr),
                FixedBoolArray::V257(arr) => check_from_array::<257>(arr),
            },

            FuzzInput::ToVecBool(bools) => {
                let v = BitMap::from(&bools);
                let converted: Vec<bool> = v.into();
                assert_eq!(converted.len(), bools.len());
                assert_eq!(converted, bools);
            }

            FuzzInput::Debug(bools) => {
                let v = BitMap::from(&bools);
                let debug_str = format!("{v:?}");
                assert!(debug_str.starts_with("BitMap["));
                assert!(debug_str.ends_with("]"));
            }

            FuzzInput::Index(bools, bit) => {
                let v = BitMap::from(&bools);
                if bit < v.len() {
                    assert_eq!(v[bit], v.get(bit));
                }
            }

            FuzzInput::BitAndOp(bools1, bools2) => {
                if bools1.len() != bools2.len() {
                    return;
                }
                let v1 = BitMap::from(&bools1);
                let v2 = BitMap::from(&bools2);
                let result = &v1 & &v2;
                assert_eq!(result.len(), v1.len());

                for i in 0..result.len() as usize {
                    let expected = bools1[i] && bools2[i];
                    assert_eq!(result.get(i as u64), expected);
                }
            }

            FuzzInput::BitOrOp(bools1, bools2) => {
                if bools1.len() != bools2.len() {
                    return;
                }
                let v1 = BitMap::from(&bools1);
                let v2 = BitMap::from(&bools2);
                let result = &v1 | &v2;
                assert_eq!(result.len(), v1.len());

                for i in 0..result.len() as usize {
                    let expected = bools1[i] || bools2[i];
                    assert_eq!(result.get(i as u64), expected);
                }
            }

            FuzzInput::BitXorOp(bools1, bools2) => {
                if bools1.len() != bools2.len() {
                    return;
                }
                let v1 = BitMap::from(&bools1);
                let v2 = BitMap::from(&bools2);
                let result = &v1 ^ &v2;
                assert_eq!(result.len(), v1.len());

                for i in 0..result.len() as usize {
                    let expected = bools1[i] ^ bools2[i];
                    assert_eq!(result.get(i as u64), expected);
                }
            }

            FuzzInput::Codec(bools) => {
                let v = BitMap::from(&bools);

                let encoded_size = v.encode_size();
                assert!(encoded_size > 0);

                let mut buf = Vec::new();
                v.write(&mut buf);
                assert!(!buf.is_empty());

                let mut cursor = std::io::Cursor::new(buf);
                if let Ok(decoded) = BitMap::read_cfg(&mut cursor, &(MAX_SIZE as u64)) {
                    assert_eq!(decoded.len(), v.len());
                    for i in 0..decoded.len() {
                        assert_eq!(decoded.get(i), v.get(i));
                    }
                }
            }

            FuzzInput::IteratorOps(bools) => {
                let v = BitMap::from(&bools);
                let iter = v.iter();

                let (lower, upper) = iter.size_hint();
                assert_eq!(lower as u64, v.len());
                assert_eq!(upper, Some(v.len() as usize));

                let collected: Vec<bool> = iter.collect();
                assert_eq!(collected.len(), bools.len());
                assert_eq!(collected, bools);

                let mut iter2 = v.iter();
                for (i, expected) in bools.iter().enumerate() {
                    if let Some(actual) = iter2.next() {
                        assert_eq!(actual, *expected);

                        let (remaining_lower, remaining_upper) = iter2.size_hint();
                        assert_eq!(remaining_lower, bools.len() - i - 1);
                        assert_eq!(remaining_upper, Some(bools.len() - i - 1));
                    }
                }
                assert_eq!(iter2.next(), None);
            }
        }
    }
}

fuzz_target!(|input: Vec<FuzzInput>| {
    fuzz(input);
});
