#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{
    codec::{EncodeSize, Read, Write},
    RangeCfg,
};
use commonware_utils::BitVec;
use libfuzzer_sys::fuzz_target;

const MAX_SIZE: usize = 100_000;

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    New,
    WithCapacity(usize),
    Zeroes(usize),
    Ones(usize),
    FromBools(Vec<bool>),
    Push(Vec<bool>, bool),
    Pop(Vec<bool>),
    Iter(Vec<bool>),
    Get(Vec<bool>, usize),
    GetUnchecked(Vec<bool>, usize),
    Set(Vec<bool>, usize),
    Clear(Vec<bool>, usize),
    Toggle(Vec<bool>, usize),
    SetTo(Vec<bool>, usize, bool),
    ClearAll(Vec<bool>),
    SetAll(Vec<bool>),
    And(Vec<bool>, Vec<bool>),
    Or(Vec<bool>, Vec<bool>),
    Xor(Vec<bool>, Vec<bool>),
    Invert(Vec<bool>),
    Default,
    FromVecBool(Vec<bool>),
    FromSliceBool(Vec<bool>),
    FromArrayBool(Vec<bool>),
    FromRefArrayBool(Vec<bool>),
    ToVecBool(Vec<bool>),
    Debug(Vec<bool>),
    Index(Vec<bool>, usize),
    BitAndOp(Vec<bool>, Vec<bool>),
    BitOrOp(Vec<bool>, Vec<bool>),
    BitXorOp(Vec<bool>, Vec<bool>),
    Codec(Vec<bool>),
    IteratorOps(Vec<bool>),
}

fn fuzz(input: Vec<FuzzInput>) {
    for op in input {
        match op {
            FuzzInput::New => {
                let v = BitVec::new();
                assert!(v.is_empty());
                assert_eq!(v.len(), 0);
            }

            FuzzInput::WithCapacity(cap) => {
                let bv = BitVec::with_capacity(cap.min(MAX_SIZE));
                assert!(bv.is_empty());
                assert_eq!(bv.len(), 0);
            }

            FuzzInput::Zeroes(size) => {
                let size = size.min(MAX_SIZE);
                let v = BitVec::zeroes(size);
                assert_eq!(v.len(), size);
                assert_eq!(v.count_zeros(), size);
                assert_eq!(v.count_ones(), 0);

                for i in 0..size {
                    assert_eq!(v.get(i), Some(false));
                }
            }

            FuzzInput::Ones(size) => {
                let size = size.min(MAX_SIZE);
                let v = BitVec::ones(size);
                assert_eq!(v.len(), size);
                assert_eq!(v.count_ones(), size);
                assert_eq!(v.count_zeros(), 0);

                for i in 0..size {
                    assert_eq!(v.get(i), Some(true));
                }
            }

            FuzzInput::FromBools(bools) => {
                let v = BitVec::from_bools(&bools);
                assert_eq!(v.len(), bools.len());

                for (i, &b) in bools.iter().enumerate() {
                    assert_eq!(v.get(i), Some(b));
                }
            }

            FuzzInput::Push(bools, value) => {
                let mut v = BitVec::from_bools(&bools);
                let old_len = v.len();
                v.push(value);
                assert_eq!(v.len(), old_len + 1);
                assert_eq!(v.get(old_len), Some(value));
            }

            FuzzInput::Pop(bools) => {
                let mut v = BitVec::from_bools(&bools);
                let old_len = v.len();
                let popped = v.pop();

                if old_len > 0 {
                    assert!(popped.is_some());
                    assert_eq!(v.len(), old_len - 1);
                } else {
                    assert!(popped.is_none());
                    assert_eq!(v.len(), 0);
                }
            }

            FuzzInput::Iter(bools) => {
                let v = BitVec::from_bools(&bools);
                let i = v.iter();
                assert_eq!(v.len(), i.len());
            }

            FuzzInput::Get(bools, index) => {
                let v = BitVec::from_bools(&bools);
                let result = v.get(index);
                if index < v.len() {
                    assert!(result.is_some());
                } else {
                    assert!(result.is_none());
                }
            }

            FuzzInput::GetUnchecked(bools, index) => {
                let v = BitVec::from_bools(&bools);
                if index >= v.len() {
                    return;
                }
                let result = v.get(index);
                if index < v.len() {
                    assert!(result.is_some());
                } else {
                    assert!(result.is_none());
                }
            }

            FuzzInput::Set(bools, index) => {
                let mut v = BitVec::from_bools(&bools);
                if index < v.len() {
                    v.set(index);
                    assert_eq!(v.get(index), Some(true));
                }
            }

            FuzzInput::Clear(bools, index) => {
                let mut v = BitVec::from_bools(&bools);
                if index < v.len() {
                    v.clear(index);
                    assert_eq!(v.get(index), Some(false));
                }
            }

            FuzzInput::Toggle(bools, index) => {
                let mut v = BitVec::from_bools(&bools);
                if index < v.len() {
                    let old_value = v.get(index).unwrap();
                    v.toggle(index);
                    assert_eq!(v.get(index), Some(!old_value));
                }
            }

            FuzzInput::SetTo(bools, index, value) => {
                let mut v = BitVec::from_bools(&bools);
                if index < v.len() {
                    v.set_to(index, value);
                    assert_eq!(v.get(index), Some(value));
                }
            }

            FuzzInput::ClearAll(bools) => {
                let mut v = BitVec::from_bools(&bools);
                v.clear_all();
                assert_eq!(v.count_ones(), 0);
                assert_eq!(v.count_zeros(), v.len());
            }

            FuzzInput::SetAll(bools) => {
                let mut v = BitVec::from_bools(&bools);
                v.set_all();
                assert_eq!(v.count_zeros(), 0);
                assert_eq!(v.count_ones(), v.len());
            }

            FuzzInput::And(bools1, bools2) => {
                if bools1.len() != bools2.len() {
                    return;
                }
                let mut v1 = BitVec::from_bools(&bools1);
                let v2 = BitVec::from_bools(&bools2);
                let old_len = v1.len();
                v1.and(&v2);

                assert_eq!(v1.len(), old_len);
            }

            FuzzInput::Or(bools1, bools2) => {
                if bools1.len() != bools2.len() {
                    return;
                }
                let mut v1 = BitVec::from_bools(&bools1);
                let v2 = BitVec::from_bools(&bools2);
                let old_len = v1.len();
                v1.or(&v2);

                assert_eq!(v1.len(), old_len);
            }

            FuzzInput::Xor(bools1, bools2) => {
                if bools1.len() != bools2.len() {
                    return;
                }
                let mut v1 = BitVec::from_bools(&bools1);
                let v2 = BitVec::from_bools(&bools2);
                let old_len = v1.len();
                v1.xor(&v2);

                assert_eq!(v1.len(), old_len);
            }

            FuzzInput::Invert(bools) => {
                let mut v = BitVec::from_bools(&bools);
                let old_ones = v.count_ones();
                let old_zeros = v.count_zeros();
                v.invert();

                assert_eq!(v.count_ones(), old_zeros);
                assert_eq!(v.count_zeros(), old_ones);
            }

            FuzzInput::Default => {
                let v = BitVec::default();
                assert!(v.is_empty());
                assert_eq!(v.len(), 0);
            }

            FuzzInput::FromVecBool(bools) => {
                let v: BitVec = bools.clone().into();
                assert_eq!(v.len(), bools.len());
                for (i, &b) in bools.iter().enumerate() {
                    assert_eq!(v.get(i), Some(b));
                }
            }

            FuzzInput::FromSliceBool(bools) => {
                let v: BitVec = bools.as_slice().into();
                assert_eq!(v.len(), bools.len());
                for (i, &b) in bools.iter().enumerate() {
                    assert_eq!(v.get(i), Some(b));
                }
            }

            FuzzInput::FromArrayBool(bools) => {
                let ln = bools.len();
                if ln <= MAX_SIZE {
                    let v: BitVec = bools.into();
                    assert_eq!(v.len(), ln);
                }
            }

            FuzzInput::FromRefArrayBool(bools) => {
                let ln = bools.len();
                if ln <= MAX_SIZE {
                    let arr = bools;
                    let v: BitVec = (&(*arr)).into();
                    assert_eq!(v.len(), arr.len());
                }
            }

            FuzzInput::ToVecBool(bools) => {
                let v = BitVec::from_bools(&bools);
                let converted: Vec<bool> = v.into();
                assert_eq!(converted.len(), bools.len());
                assert_eq!(converted, bools);
            }

            FuzzInput::Debug(bools) => {
                let v = BitVec::from_bools(&bools);
                let debug_str = format!("{v:?}");
                assert!(debug_str.starts_with("BitVec["));
                assert!(debug_str.ends_with("]"));
            }

            FuzzInput::Index(bools, index) => {
                let v = BitVec::from_bools(&bools);
                if index < v.len() {
                    let indexed_value = v[index];
                    assert_eq!(Some(indexed_value), v.get(index));
                }
            }

            FuzzInput::BitAndOp(bools1, bools2) => {
                if bools1.len() != bools2.len() {
                    return;
                }
                let v1 = BitVec::from_bools(&bools1);
                let v2 = BitVec::from_bools(&bools2);
                let result = &v1 & &v2;
                assert_eq!(result.len(), v1.len());

                for i in 0..result.len() {
                    let expected = bools1[i] && bools2[i];
                    assert_eq!(result.get(i), Some(expected));
                }
            }

            FuzzInput::BitOrOp(bools1, bools2) => {
                if bools1.len() != bools2.len() {
                    return;
                }
                let v1 = BitVec::from_bools(&bools1);
                let v2 = BitVec::from_bools(&bools2);
                let result = &v1 | &v2;
                assert_eq!(result.len(), v1.len());

                for i in 0..result.len() {
                    let expected = bools1[i] || bools2[i];
                    assert_eq!(result.get(i), Some(expected));
                }
            }

            FuzzInput::BitXorOp(bools1, bools2) => {
                if bools1.len() != bools2.len() {
                    return;
                }
                let v1 = BitVec::from_bools(&bools1);
                let v2 = BitVec::from_bools(&bools2);
                let result = &v1 ^ &v2;
                assert_eq!(result.len(), v1.len());

                for i in 0..result.len() {
                    let expected = bools1[i] ^ bools2[i];
                    assert_eq!(result.get(i), Some(expected));
                }
            }

            FuzzInput::Codec(bools) => {
                let v = BitVec::from_bools(&bools);

                let encoded_size = v.encode_size();
                assert!(encoded_size > 0);

                let mut buf = Vec::new();
                v.write(&mut buf);
                assert!(!buf.is_empty());

                let mut cursor = std::io::Cursor::new(buf);
                let range_cfg: RangeCfg = (0..MAX_SIZE).into();
                if let Ok(decoded) = BitVec::read_cfg(&mut cursor, &range_cfg) {
                    assert_eq!(decoded.len(), v.len());
                    for i in 0..decoded.len() {
                        assert_eq!(decoded.get(i), v.get(i));
                    }
                }
            }

            FuzzInput::IteratorOps(bools) => {
                let v = BitVec::from_bools(&bools);
                let iter = v.iter();

                let (lower, upper) = iter.size_hint();
                assert_eq!(lower, v.len());
                assert_eq!(upper, Some(v.len()));

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
