#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{Encode, Error as CodecError, RangeCfg, Read, Write};
use commonware_utils::{sync::Once, vec::NonEmptyVec, NZUsize, TryFromIterator};
use libfuzzer_sys::fuzz_target;
use std::num::NonZeroUsize;

const MAX_OPS: usize = 32;
const MAX_LEN: usize = 256;

static ADDITIONAL_METHODS: Once = Once::new();

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

#[derive(Debug)]
struct FuzzInput {
    init: Vec<u8>,
    ops: Vec<Op>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let discriminant: u8 = u.arbitrary()?;
        let init = if discriminant == 0 {
            Vec::new()
        } else {
            let first: u8 = u.arbitrary()?;
            let rest: Vec<u8> = u.arbitrary()?;
            let mut v = Vec::with_capacity(1 + rest.len());
            v.push(first);
            v.extend(rest);
            v
        };
        let ops: Vec<Op> = u.arbitrary()?;
        Ok(Self { init, ops })
    }
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

fn exercise_additional_methods(seed: u8) {
    let mut nev = NonEmptyVec::try_from(vec![seed, seed.wrapping_add(1)]).unwrap();
    *nev.first_mut() = seed.wrapping_add(2);
    *nev.last_mut() = seed.wrapping_add(3);
    let actual: &[u8] = nev.as_ref();
    assert_eq!(actual, &[seed.wrapping_add(2), seed.wrapping_add(3)]);

    nev.insert(1, seed.wrapping_add(4));
    let actual: &[u8] = nev.as_ref();
    assert_eq!(
        actual,
        &[
            seed.wrapping_add(2),
            seed.wrapping_add(4),
            seed.wrapping_add(3)
        ]
    );

    let mut next = seed;
    nev.resize_with(NZUsize!(5), || {
        next = next.wrapping_add(1);
        next
    });
    assert_eq!(nev.len().get(), 5);
    nev.resize_with(NZUsize!(2), || 0);
    assert_eq!(nev.len().get(), 2);

    assert!(nev.pop().is_some());
    assert_eq!(nev.pop(), None);
    assert_eq!(nev.remove(0), None);

    nev.push(seed.wrapping_add(5));
    let removed = nev.remove(0);
    assert_eq!(removed, Some(seed.wrapping_add(2)));

    let len = nev.mutate(|items| {
        items.push(seed.wrapping_add(6));
        items.reverse();
        items.len()
    });
    assert_eq!(len, nev.len().get());

    let as_slice: &[u8] = nev.as_ref();
    assert_eq!(as_slice.len(), nev.len().get());
    let as_vec: &Vec<u8> = nev.as_ref();
    assert_eq!(as_vec.as_slice(), as_slice);
    let as_vec_len = as_vec.len();

    let from_vec: Vec<u8> = nev.clone().into();
    assert_eq!(from_vec, nev.clone().into_vec());

    let slice = [seed, seed.wrapping_add(1)];
    let from_slice = NonEmptyVec::<u8>::try_from(&slice[..]).unwrap();
    let from_slice: &[u8] = from_slice.as_ref();
    assert_eq!(from_slice, &slice);
    let from_array = NonEmptyVec::<u8>::try_from(slice).unwrap();
    let from_array: &[u8] = from_array.as_ref();
    assert_eq!(from_array, &[seed, seed.wrapping_add(1)]);
    let from_array_ref = NonEmptyVec::<u8>::try_from(&slice).unwrap();
    let from_array_ref: &[u8] = from_array_ref.as_ref();
    assert_eq!(from_array_ref, &[seed, seed.wrapping_add(1)]);

    let empty_slice: &[u8] = &[];
    assert_eq!(
        NonEmptyVec::<u8>::try_from(empty_slice),
        Err(commonware_utils::vec::Error::Empty)
    );
    let empty_array: [u8; 0] = [];
    assert_eq!(
        NonEmptyVec::<u8>::try_from(empty_array),
        Err(commonware_utils::vec::Error::Empty)
    );
    assert_eq!(
        NonEmptyVec::<u8>::try_from(&empty_array),
        Err(commonware_utils::vec::Error::Empty)
    );

    let owned_sum: u16 = nev.clone().into_iter().map(u16::from).sum();
    // Use (&nev).into_iter() to hit IntoIterator for &NonEmptyVec, not slice::iter via Deref.
    let ref_sum: u16 = (&nev).into_iter().copied().map(u16::from).sum();
    assert_eq!(owned_sum, ref_sum);
    for item in &mut nev {
        *item = item.wrapping_add(1);
    }
    assert_eq!(nev.len().get(), as_vec_len);

    let arbitrary_bytes = [seed, seed.wrapping_add(1), 0, 1];
    let mut unstructured = arbitrary::Unstructured::new(&arbitrary_bytes);
    let arbitrary = NonEmptyVec::<u8>::arbitrary(&mut unstructured);
    assert!(arbitrary.is_ok() || matches!(arbitrary, Err(arbitrary::Error::NotEnoughData)));
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
    ADDITIONAL_METHODS.call_once(|| exercise_additional_methods(0));

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
