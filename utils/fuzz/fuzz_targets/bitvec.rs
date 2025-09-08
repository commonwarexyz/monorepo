#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{
    codec::{EncodeSize, Read, Write},
    RangeCfg,
};
use libfuzzer_sys::fuzz_target;

const MAX_SIZE: usize = 100_000;
const BITVEC_CHUNK_SIZE: usize = 1;
type BitVec = commonware_utils::BitVec<BITVEC_CHUNK_SIZE>;

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
                assert_eq!(v.bit_count(), 0);
            }

            FuzzInput::WithCapacity(cap) => {
                let bv = BitVec::with_capacity(cap.min(MAX_SIZE));
                assert!(bv.is_empty());
                assert_eq!(bv.len(), 0);
            }

            FuzzInput::Zeroes(size) => {
                let size = size.min(MAX_SIZE);
                let v = BitVec::zeroes(size);
                assert_eq!(v.bit_count(), size as u64);
                assert_eq!(v.count_zeros(), size);
                assert_eq!(v.count_ones(), 0);

                for i in 0..size {
                    assert_eq!(v.get_bit(i as u64), false);
                }
            }

            FuzzInput::Ones(size) => {
                let size = size.min(MAX_SIZE);
                let v = BitVec::ones(size);
                assert_eq!(v.bit_count(), size as u64);
                assert_eq!(v.count_ones(), size);
                assert_eq!(v.count_zeros(), 0);

                for i in 0..size {
                    assert_eq!(v.get_bit(i as u64), true);
                }
            }

            FuzzInput::FromBools(bools) => {
                let v = BitVec::from(&bools);
                assert_eq!(v.bit_count(), bools.len() as u64);

                for (i, &b) in bools.iter().enumerate() {
                    assert_eq!(v.get_bit(i as u64), b);
                }
            }

            FuzzInput::Push(bools, value) => {
                let mut v = BitVec::from(&bools);
                let old_len = v.bit_count();
                v.append(value);
                assert_eq!(v.bit_count(), old_len + 1);
                assert_eq!(v.get_bit(old_len), value);
            }

            FuzzInput::Pop(bools) => {
                // TODO uncomment
                // let mut v = BitVec::from(&bools);
                // let old_len = v.bit_count();
                // let popped = v.pop();

                // if old_len > 0 {
                //     assert!(popped.is_some());
                //     assert_eq!(v.bit_count(), old_len - 1);
                // } else {
                //     assert!(popped.is_none());
                //     assert_eq!(v.bit_count(), 0);
                // }
            }

            FuzzInput::Iter(bools) => {
                let v = BitVec::from(&bools);
                let i = v.iter();
                assert_eq!(v.bit_count(), i.len() as u64);
            }

            FuzzInput::Get(bools, index) => {
                // let v = BitVec::from(&bools);
                // let result = v.get_bit(index as u64);
                // if index as u64 < v.bit_count() {
                //     assert!(result.is_some());
                // } else {
                //     assert!(result.is_none());
                // }
            }

            FuzzInput::GetUnchecked(bools, index) => {
                let v = BitVec::from(&bools);
                // Caller must ensure `index` is less than the length of the BitVec.
                if index as u64 >= v.bit_count() {
                    return;
                }
                v.get_bit(index as u64);
            }

            FuzzInput::Set(bools, index) => {
                let mut v = BitVec::from(&bools);
                if (index as u64) < v.bit_count() {
                    v.set_bit(index as u64, true);
                    assert_eq!(v.get_bit(index as u64), true);
                }
            }

            FuzzInput::Clear(bools, index) => {
                let mut v = BitVec::from(&bools);
                if (index as u64) < v.bit_count() {
                    v.set_bit(index as u64, false);
                    assert_eq!(v.get_bit(index as u64), false);
                }
            }

            FuzzInput::Toggle(bools, index) => {
                let mut v = BitVec::from(&bools);
                if (index as u64) < v.bit_count() {
                    let old_value = v.get_bit(index as u64);
                    v.toggle(index as u64);
                    assert_eq!(v.get_bit(index as u64), !old_value);
                }
            }

            FuzzInput::SetTo(bools, index, value) => {
                let mut v = BitVec::from(&bools);
                if (index as u64) < v.bit_count() {
                    v.set_bit(index as u64, value);
                    assert_eq!(v.get_bit(index as u64), value);
                }
            }

            FuzzInput::ClearAll(bools) => {
                let mut v = BitVec::from(&bools);
                v.clear_all();
                assert_eq!(v.count_ones(), 0);
                assert_eq!(v.count_zeros(), v.bit_count() as usize);
            }

            FuzzInput::SetAll(bools) => {
                let mut v = BitVec::from(&bools);
                v.set_all();
                assert_eq!(v.count_zeros(), 0);
                assert_eq!(v.count_ones(), v.bit_count() as usize);
            }

            FuzzInput::And(bools1, bools2) => {
                if bools1.len() != bools2.len() {
                    return;
                }
                let mut v1 = BitVec::from(&bools1);
                let v2 = BitVec::from(&bools2);
                let old_len = v1.bit_count();
                v1.and(&v2);

                assert_eq!(v1.bit_count(), old_len);
            }

            FuzzInput::Or(bools1, bools2) => {
                if bools1.len() != bools2.len() {
                    return;
                }
                let mut v1 = BitVec::from(&bools1);
                let v2 = BitVec::from(&bools2);
                let old_len = v1.bit_count();
                v1.or(&v2);

                assert_eq!(v1.bit_count(), old_len);
            }

            FuzzInput::Xor(bools1, bools2) => {
                if bools1.len() != bools2.len() {
                    return;
                }
                let mut v1 = BitVec::from(&bools1);
                let v2 = BitVec::from(&bools2);
                let old_len = v1.bit_count();
                v1.xor(&v2);

                assert_eq!(v1.bit_count(), old_len);
            }

            FuzzInput::Invert(bools) => {
                let mut v = BitVec::from(&bools);
                let old_ones = v.count_ones();
                let old_zeros = v.count_zeros();
                v.invert();

                assert_eq!(v.count_ones(), old_zeros);
                assert_eq!(v.count_zeros(), old_ones);
            }

            FuzzInput::Default => {
                let v = BitVec::default();
                assert!(v.is_empty());
                assert_eq!(v.bit_count(), 0);
            }

            FuzzInput::FromVecBool(bools) => {
                let v: BitVec = bools.clone().into();
                assert_eq!(v.bit_count(), bools.len() as u64);
                for (i, &b) in bools.iter().enumerate() {
                    assert_eq!(v.get_bit(i as u64), b);
                }
            }

            FuzzInput::FromSliceBool(bools) => {
                let v: BitVec = bools.as_slice().into();
                assert_eq!(v.bit_count(), bools.len() as u64);
                for (i, &b) in bools.iter().enumerate() {
                    assert_eq!(v.get_bit(i as u64), b);
                }
            }

            FuzzInput::FromArrayBool(bools) => {
                let ln = bools.len();
                if ln <= MAX_SIZE {
                    let v: BitVec = bools.into();
                    assert_eq!(v.bit_count(), ln as u64);
                }
            }

            FuzzInput::FromRefArrayBool(bools) => {
                let ln = bools.len();
                if ln <= MAX_SIZE {
                    let arr = bools;
                    let v: BitVec = (&(*arr)).into();
                    assert_eq!(v.bit_count(), arr.len() as u64);
                }
            }

            FuzzInput::ToVecBool(bools) => {
                let v = BitVec::from(&bools);
                let converted: Vec<bool> = v.into();
                assert_eq!(converted.len(), bools.len());
                assert_eq!(converted, bools);
            }

            FuzzInput::Debug(bools) => {
                let v = BitVec::from(&bools);
                let debug_str = format!("{v:?}");
                assert!(debug_str.starts_with("BitVec["));
                assert!(debug_str.ends_with("]"));
            }

            FuzzInput::Index(bools, index) => {
                let v = BitVec::from(&bools);
                if index < v.bit_count() as usize {
                    let indexed_value = v[index];
                    assert_eq!(indexed_value, v.get_bit(index as u64));
                }
            }

            FuzzInput::BitAndOp(bools1, bools2) => {
                if bools1.len() != bools2.len() {
                    return;
                }
                let v1 = BitVec::from(&bools1);
                let v2 = BitVec::from(&bools2);
                let result = &v1 & &v2;
                assert_eq!(result.bit_count(), v1.bit_count() as u64);

                for i in 0..result.bit_count() as usize {
                    let expected = bools1[i] && bools2[i];
                    assert_eq!(result.get_bit(i as u64), expected);
                }
            }

            FuzzInput::BitOrOp(bools1, bools2) => {
                if bools1.len() != bools2.len() {
                    return;
                }
                let v1 = BitVec::from(&bools1);
                let v2 = BitVec::from(&bools2);
                let result = &v1 | &v2;
                assert_eq!(result.bit_count(), v1.bit_count());

                for i in 0..result.bit_count() as usize {
                    let expected = bools1[i] || bools2[i];
                    assert_eq!(result.get_bit(i as u64), expected);
                }
            }

            FuzzInput::BitXorOp(bools1, bools2) => {
                if bools1.len() != bools2.len() {
                    return;
                }
                let v1 = BitVec::from(&bools1);
                let v2 = BitVec::from(&bools2);
                let result = &v1 ^ &v2;
                assert_eq!(result.bit_count(), v1.bit_count());

                for i in 0..result.bit_count() as usize {
                    let expected = bools1[i] ^ bools2[i];
                    assert_eq!(result.get_bit(i as u64), expected);
                }
            }

            FuzzInput::Codec(bools) => {
                let v = BitVec::from(&bools);

                let encoded_size = v.encode_size();
                assert!(encoded_size > 0);

                let mut buf = Vec::new();
                v.write(&mut buf);
                assert!(!buf.is_empty());

                let mut cursor = std::io::Cursor::new(buf);
                let range_cfg: RangeCfg = (0..MAX_SIZE).into();
                if let Ok(decoded) = BitVec::read_cfg(&mut cursor, &range_cfg) {
                    assert_eq!(decoded.bit_count(), v.bit_count());
                    for i in 0..decoded.bit_count() {
                        assert_eq!(decoded.get_bit(i as u64), v.get_bit(i as u64));
                    }
                }
            }

            FuzzInput::IteratorOps(bools) => {
                let v = BitVec::from(&bools);
                let iter = v.iter();

                let (lower, upper) = iter.size_hint();
                assert_eq!(lower as u64, v.bit_count());
                assert_eq!(upper, Some(v.bit_count() as usize));

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
