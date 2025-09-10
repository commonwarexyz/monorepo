#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_codec::{
    codec::{EncodeSize, Read, Write},
    RangeCfg,
};
use libfuzzer_sys::fuzz_target;

const MAX_SIZE: u64 = 100_000;
const BITMAP_CHUNK_SIZE: usize = 1;
type BitMap = commonware_utils::bitmap::BitMap<BITMAP_CHUNK_SIZE>;

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    New,
    WithCapacity(u64),
    Zeroes(u64),
    Ones(u64),
    FromBools(Vec<bool>),
    Push(Vec<bool>, bool),
    Pop(Vec<bool>),
    Iter(Vec<bool>),
    Get(Vec<bool>, usize),
    Set(Vec<bool>, u64),
    Clear(Vec<bool>, u64),
    Toggle(Vec<bool>, u64),
    SetTo(Vec<bool>, u64, bool),
    ClearAll(Vec<bool>),
    SetAll(Vec<bool>),
    And(Vec<bool>, Vec<bool>),
    Or(Vec<bool>, Vec<bool>),
    Xor(Vec<bool>, Vec<bool>),
    Invert(Vec<bool>),
    Default,
    FromSliceBool(Vec<bool>),
    FromVecBool(Vec<bool>),
    BoolInto(Vec<bool>),
    FromArrayBool(FixedBoolArray),
    FromRefArrayBool(FixedBoolArray),
    ToVecBool(Vec<bool>),
    Debug(Vec<bool>),
    Index(Vec<bool>, usize),
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
        assert_eq!(bv_a.get_bit(i as u64), b);
        assert_eq!(bv_b.get_bit(i as u64), b);
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
                let bv = BitMap::with_capacity(cap.min(MAX_SIZE));
                assert!(bv.is_empty());
                assert_eq!(bv.len(), 0);
            }

            FuzzInput::Zeroes(size) => {
                let size = size.min(MAX_SIZE);
                let v = BitMap::zeroes(size);
                assert_eq!(v.len(), size);
                assert_eq!(v.count_zeros(), size);
                assert_eq!(v.count_ones(), 0);

                for i in 0..size {
                    assert!(!v.get_bit(i));
                }
            }

            FuzzInput::Ones(size) => {
                let size = size.min(MAX_SIZE);
                let v = BitMap::ones(size);
                assert_eq!(v.len(), size);
                assert_eq!(v.count_ones(), size);
                assert_eq!(v.count_zeros(), 0);

                for i in 0..size {
                    assert!(v.get_bit(i));
                }
            }

            FuzzInput::FromBools(bools) => {
                let v = BitMap::from(&bools);
                assert_eq!(v.len(), bools.len() as u64);

                for (i, &b) in bools.iter().enumerate() {
                    assert_eq!(v.get_bit(i as u64), b);
                }
            }

            FuzzInput::Push(bools, value) => {
                let mut v = BitMap::from(&bools);
                let old_len = v.len();
                v.push(value);
                assert_eq!(v.len(), old_len + 1);
                assert_eq!(v.get_bit(old_len), value);
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

            FuzzInput::Get(bools, index) => {
                let v = BitMap::from(&bools);
                let v_len = v.len();

                if index as u64 >= v_len {
                    return;
                }

                let result = v.get_bit(index as u64);
                assert_eq!(result, bools[index]);
            }

            FuzzInput::Set(bools, index) => {
                let mut v = BitMap::from(&bools);
                if index < v.len() {
                    v.set(index, true);
                    assert!(v.get_bit(index));
                }
            }

            FuzzInput::Clear(bools, index) => {
                let mut v = BitMap::from(&bools);
                if index < v.len() {
                    v.set(index, false);
                    assert!(!v.get_bit(index));
                }
            }

            FuzzInput::Toggle(bools, index) => {
                let mut v = BitMap::from(&bools);
                if index < v.len() {
                    let old_value = v.get_bit(index);
                    v.toggle(index);
                    assert_eq!(v.get_bit(index), !old_value);
                }
            }

            FuzzInput::SetTo(bools, index, value) => {
                let mut v = BitMap::from(&bools);
                if index < v.len() {
                    v.set(index, value);
                    assert_eq!(v.get_bit(index), value);
                }
            }

            FuzzInput::ClearAll(bools) => {
                let mut v = BitMap::from(&bools);
                v.clear_all();
                assert_eq!(v.count_ones(), 0);
                assert_eq!(v.count_zeros(), v.len());
            }

            FuzzInput::SetAll(bools) => {
                let mut v = BitMap::from(&bools);
                v.set_all();
                assert_eq!(v.count_zeros(), 0);
                assert_eq!(v.count_ones(), v.len());
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

            FuzzInput::Invert(bools) => {
                let mut v = BitMap::from(&bools);
                let old_ones = v.count_ones();
                let old_zeros = v.count_zeros();
                v.invert();

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
                    assert_eq!(v.get_bit(i as u64), b);
                }
            }

            FuzzInput::FromVecBool(bools) => {
                let ln = bools.len() as u64;
                let v = BitMap::from(bools);
                assert_eq!(v.len(), ln);
            }

            FuzzInput::BoolInto(bools) => {
                let v: BitMap = bools.clone().into();
                assert_eq!(v.len(), bools.len() as u64);
                for (i, &b) in bools.iter().enumerate() {
                    assert_eq!(v.get_bit(i as u64), b);
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

            FuzzInput::Index(bools, index) => {
                let v = BitMap::from(&bools);
                if (index as u64) < v.len() {
                    let indexed_value = v[index];
                    assert_eq!(indexed_value, v.get_bit(index as u64));
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

                for i in 0..result.len() {
                    let expected = bools1[i as usize] && bools2[i as usize];
                    assert_eq!(result.get_bit(i), expected);
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

                for i in 0..result.len() {
                    let expected = bools1[i as usize] || bools2[i as usize];
                    assert_eq!(result.get_bit(i), expected);
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

                for i in 0..result.len() {
                    let expected = bools1[i as usize] ^ bools2[i as usize];
                    assert_eq!(result.get_bit(i), expected);
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
                let range_cfg: RangeCfg = (0..MAX_SIZE as usize).into();
                if let Ok(decoded) = BitMap::read_cfg(&mut cursor, &range_cfg) {
                    assert_eq!(decoded.len(), v.len());
                    for i in 0..decoded.len() {
                        assert_eq!(decoded.get_bit(i), v.get_bit(i));
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
