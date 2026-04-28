#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{Encode, Error as CodecError, RangeCfg, Read, Write};
use commonware_utils::{vec::NonEmptyVec, NZUsize, TryFromIterator};
use libfuzzer_sys::fuzz_target;
use std::num::NonZeroUsize;

const MAX_OPS: usize = 32;
const MAX_LEN: usize = 256;

#[derive(Arbitrary, Debug)]
enum Op {
    Push(u8),
    Insert { index: usize, value: u8 },
    Extend(Vec<u8>),
    Pop,
    Remove { index: usize },
    Resize { new_len: u8, value: u8 },
    Mutate { swap_a: usize, swap_b: usize },
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    init: Vec<u8>,
    ops: Vec<Op>,
}

fn check_invariants(nev: &NonEmptyVec<u8>, model: &[u8]) {
    assert!(!model.is_empty(), "model must remain non-empty");
    assert_eq!(nev.len().get(), model.len());
    assert!(nev.len().get() >= 1);
    assert_eq!(nev.first(), &model[0]);
    assert_eq!(nev.last(), model.last().unwrap());
    assert_eq!(nev.is_singleton(), model.len() == 1);
    assert_eq!(&**nev, model);
}

fn apply(op: Op, nev: &mut NonEmptyVec<u8>, model: &mut Vec<u8>) {
    match op {
        Op::Push(v) => {
            if model.len() >= MAX_LEN {
                return;
            }
            nev.push(v);
            model.push(v);
        }
        Op::Insert { index, value } => {
            let idx = if model.is_empty() {
                0
            } else {
                index % (model.len() + 1)
            };
            if model.len() >= MAX_LEN {
                return;
            }
            nev.insert(idx, value);
            model.insert(idx, value);
        }
        Op::Extend(items) => {
            let take = items.len().min(MAX_LEN.saturating_sub(model.len()));
            let slice = &items[..take];
            nev.extend(slice.iter().copied());
            model.extend_from_slice(slice);
        }
        Op::Pop => {
            // NonEmptyVec::pop returns None iff len == 1, leaving the vector unchanged.
            let popped = nev.pop();
            if model.len() > 1 {
                let expected = model.pop();
                assert_eq!(popped, expected);
            } else {
                assert_eq!(popped, None);
                assert_eq!(model.len(), 1);
            }
        }
        Op::Remove { index } => {
            let idx = index % model.len();
            let removed = nev.remove(idx);
            if model.len() > 1 {
                let expected = model.remove(idx);
                assert_eq!(removed, Some(expected));
            } else {
                assert_eq!(removed, None);
                assert_eq!(model.len(), 1);
            }
        }
        Op::Resize { new_len, value } => {
            // Clamp to [1, MAX_LEN] to preserve the non-empty invariant.
            let target = (new_len as usize).clamp(1, MAX_LEN);
            let nz = NonZeroUsize::new(target).unwrap();
            nev.resize(nz, value);
            model.resize(target, value);
        }
        Op::Mutate { swap_a, swap_b } => {
            let a = swap_a % model.len();
            let b = swap_b % model.len();
            nev.mutate(|v| v.swap(a, b));
            model.swap(a, b);
        }
    }
}

fn fuzz(input: FuzzInput) {
    if input.init.is_empty() {
        let err = NonEmptyVec::<u8>::try_from(Vec::<u8>::new()).unwrap_err();
        assert_eq!(err, commonware_utils::vec::Error::Empty);

        let err: commonware_utils::vec::Error =
            <NonEmptyVec<u8> as TryFromIterator<u8>>::try_from_iter(core::iter::empty())
                .unwrap_err();
        assert_eq!(err, commonware_utils::vec::Error::Empty);

        let empty: Vec<u8> = Vec::new();
        let mut buf = Vec::new();
        empty.write(&mut buf);
        let result = NonEmptyVec::<u8>::read_cfg(&mut buf.as_slice(), &(RangeCfg::from(..), ()));
        assert!(matches!(
            result,
            Err(CodecError::Invalid(
                "NonEmptyVec",
                "cannot decode empty vector"
            ))
        ));
        return;
    }

    let mut init = input.init;
    init.truncate(MAX_LEN);

    let mut nev = NonEmptyVec::<u8>::try_from(init.clone()).expect("non-empty input");
    let from_unchecked = NonEmptyVec::from_unchecked(init.clone());
    assert_eq!(nev, from_unchecked);

    let mut model = init;
    check_invariants(&nev, &model);

    for op in input.ops.into_iter().take(MAX_OPS) {
        apply(op, &mut nev, &mut model);
        check_invariants(&nev, &model);
    }

    let encoded = nev.encode();
    let decoded = NonEmptyVec::<u8>::read_cfg(
        &mut encoded.as_ref(),
        &(RangeCfg::from(NZUsize!(1)..=NZUsize!(MAX_LEN)), ()),
    )
    .expect("valid encoding decodes");
    assert_eq!(decoded, nev);

    assert_eq!(nev.clone().into_vec(), model);
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
