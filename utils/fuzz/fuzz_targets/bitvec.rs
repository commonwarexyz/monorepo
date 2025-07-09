#![no_main]

use arbitrary::Arbitrary;
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
    Get(Vec<bool>, usize),
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

            FuzzInput::Get(bools, index) => {
                let v = BitVec::from_bools(&bools);
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
        }
    }
}

fuzz_target!(|input: Vec<FuzzInput>| {
    fuzz(input);
});
