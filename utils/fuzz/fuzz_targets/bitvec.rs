#![no_main]

use arbitrary::Arbitrary;
use commonware_utils::BitVec;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum BitVecOperation {
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

fn fuzz(ops: Vec<BitVecOperation>) {
    for op in ops {
        match op {
            BitVecOperation::New => {
                let v = BitVec::new();
                assert!(v.is_empty());
                assert_eq!(v.len(), 0);
            }

            BitVecOperation::WithCapacity(cap) => {
                let bv = BitVec::with_capacity(cap.min(1_000_000));
                assert!(bv.is_empty());
                assert_eq!(bv.len(), 0);
            }

            BitVecOperation::Zeroes(size) => {
                let size = size.min(100_000);
                let v = BitVec::zeroes(size);
                assert_eq!(v.len(), size);
                assert_eq!(v.count_zeros(), size);
                assert_eq!(v.count_ones(), 0);

                for i in 0..size {
                    assert_eq!(v.get(i), Some(false));
                }
            }

            BitVecOperation::Ones(size) => {
                let size = size.min(100_000);
                let v = BitVec::ones(size);
                assert_eq!(v.len(), size);
                assert_eq!(v.count_ones(), size);
                assert_eq!(v.count_zeros(), 0);

                for i in 0..size.min(1000) {
                    assert_eq!(v.get(i), Some(true));
                }
            }

            BitVecOperation::FromBools(bools) => {
                let bools = if bools.len() > 100_000 {
                    &bools[..100_000]
                } else {
                    &bools
                };

                let v = BitVec::from_bools(bools);
                assert_eq!(v.len(), bools.len());

                for (i, &b) in bools.iter().enumerate() {
                    assert_eq!(v.get(i), Some(b));
                }
            }

            BitVecOperation::Push(bools, value) => {
                let mut v = BitVec::from_bools(&bools);
                if v.len() < 100_000 {
                    let old_len = v.len();
                    v.push(value);
                    assert_eq!(v.len(), old_len + 1);
                    assert_eq!(v.get(old_len), Some(value));
                }
            }

            BitVecOperation::Pop(bools) => {
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

            BitVecOperation::Get(bools, index) => {
                let v = BitVec::from_bools(&bools);
                let result = v.get(index);
                if index < v.len() {
                    assert!(result.is_some());
                } else {
                    assert!(result.is_none());
                }
            }

            BitVecOperation::Set(bools, index) => {
                let mut v = BitVec::from_bools(&bools);
                if index < v.len() {
                    v.set(index);
                    assert_eq!(v.get(index), Some(true));
                }
            }

            BitVecOperation::Clear(bools, index) => {
                let mut v = BitVec::from_bools(&bools);
                if index < v.len() {
                    v.clear(index);
                    assert_eq!(v.get(index), Some(false));
                }
            }

            BitVecOperation::Toggle(bools, index) => {
                let mut v = BitVec::from_bools(&bools);
                if index < v.len() {
                    let old_value = v.get(index).unwrap();
                    v.toggle(index);
                    assert_eq!(v.get(index), Some(!old_value));
                }
            }

            BitVecOperation::SetTo(bools, index, value) => {
                let mut v = BitVec::from_bools(&bools);
                if index < v.len() {
                    v.set_to(index, value);
                    assert_eq!(v.get(index), Some(value));
                }
            }

            BitVecOperation::ClearAll(bools) => {
                let mut v = BitVec::from_bools(&bools);
                v.clear_all();
                assert_eq!(v.count_ones(), 0);
                assert_eq!(v.count_zeros(), v.len());
            }

            BitVecOperation::SetAll(bools) => {
                let mut v = BitVec::from_bools(&bools);
                v.set_all();
                assert_eq!(v.count_zeros(), 0);
                assert_eq!(v.count_ones(), v.len());
            }

            BitVecOperation::And(bools1, bools2) => {
                if bools1.len() != bools2.len() {
                    return;
                }
                let mut v1 = BitVec::from_bools(&bools1);
                let v2 = BitVec::from_bools(&bools2);
                let old_len = v1.len();
                v1.and(&v2);

                assert_eq!(v1.len(), old_len);
            }

            BitVecOperation::Or(bools1, bools2) => {
                if bools1.len() != bools2.len() {
                    return;
                }
                let mut v1 = BitVec::from_bools(&bools1);
                let v2 = BitVec::from_bools(&bools2);
                let old_len = v1.len();
                v1.or(&v2);

                assert_eq!(v1.len(), old_len);
            }

            BitVecOperation::Xor(bools1, bools2) => {
                if bools1.len() != bools2.len() {
                    return;
                }
                let mut v1 = BitVec::from_bools(&bools1);
                let v2 = BitVec::from_bools(&bools2);
                let old_len = v1.len();
                v1.xor(&v2);

                assert_eq!(v1.len(), old_len);
            }

            BitVecOperation::Invert(bools) => {
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

fuzz_target!(|ops: Vec<BitVecOperation>| {
    fuzz(ops);
});
