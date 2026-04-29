#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{Encode, Error as CodecError, RangeCfg, Read, Write};
use commonware_utils::{
    vec::{Error as NonEmptyVecError, NonEmptyVec},
    TryFromIterator,
};
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
    ResizeWith { new_len: u8, seed: u8 },
    Mutate { swap_a: usize, swap_b: usize },
}

#[derive(Debug)]
enum FuzzInput {
    Construct { items: Vec<u8>, array: [u8; 3] },
    Mutate { init: Vec<u8>, ops: Vec<Op> },
    Codec { items: Vec<u8> },
    Arbitrary { bytes: Vec<u8> },
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=3)? {
            0 => Ok(Self::Construct {
                items: arbitrary_vec_low_empty(u)?,
                array: u.arbitrary()?,
            }),
            1 => Ok(Self::Mutate {
                init: arbitrary_vec_low_empty(u)?,
                ops: u.arbitrary()?,
            }),
            2 => Ok(Self::Codec {
                items: arbitrary_vec_low_empty(u)?,
            }),
            _ => Ok(Self::Arbitrary {
                bytes: arbitrary_vec_low_empty(u)?,
            }),
        }
    }
}

fn arbitrary_vec_low_empty<'a, T: Arbitrary<'a>>(
    u: &mut arbitrary::Unstructured<'a>,
) -> arbitrary::Result<Vec<T>> {
    if u.ratio(1, 16)? {
        return Ok(Vec::new());
    }

    let first = T::arbitrary(u)?;
    let mut rest = Vec::<T>::arbitrary(u)?;
    let mut items = Vec::with_capacity(1 + rest.len());
    items.push(first);
    items.append(&mut rest);
    Ok(items)
}

fn check_invariants(nev: &NonEmptyVec<u8>, model: &[u8]) {
    assert!(!model.is_empty());
    assert_eq!(nev.len().get(), model.len());
    assert_eq!(nev.is_singleton(), model.len() == 1);
    assert_eq!(nev.first(), &model[0]);
    assert_eq!(nev.last(), model.last().unwrap());
    assert_eq!(&**nev, model);
}

fn exercise_construct(mut items: Vec<u8>, array: [u8; 3]) {
    items.truncate(MAX_LEN);

    if items.is_empty() {
        assert_eq!(
            NonEmptyVec::<u8>::try_from(Vec::<u8>::new()),
            Err(NonEmptyVecError::Empty)
        );
        assert_eq!(
            NonEmptyVec::<u8>::try_from(&[][..]),
            Err(NonEmptyVecError::Empty)
        );
        assert_eq!(
            NonEmptyVec::<u8>::try_from([]),
            Err(NonEmptyVecError::Empty)
        );
        assert_eq!(
            NonEmptyVec::<u8>::try_from(&[]),
            Err(NonEmptyVecError::Empty)
        );
        assert_eq!(
            <NonEmptyVec<u8> as TryFromIterator<u8>>::try_from_iter(core::iter::empty()),
            Err(NonEmptyVecError::Empty)
        );
        return;
    }

    let mut nev = NonEmptyVec::<u8>::try_from(items.clone()).unwrap();
    assert_eq!(NonEmptyVec::from_unchecked(items.clone()), nev);
    assert_eq!(
        <NonEmptyVec<u8> as TryFromIterator<u8>>::try_from_iter(items.iter().copied()).unwrap(),
        nev
    );
    assert_eq!(NonEmptyVec::<u8>::try_from(items.as_slice()).unwrap(), nev);
    let from_array = NonEmptyVec::<u8>::try_from(array).unwrap();
    assert_eq!(NonEmptyVec::<u8>::try_from(&array).unwrap(), from_array);

    *nev.first_mut() = nev.first().wrapping_add(1);
    *nev.last_mut() = nev.last().wrapping_add(1);

    let as_slice: &[u8] = nev.as_ref();
    let as_vec: &Vec<u8> = nev.as_ref();
    assert_eq!(as_slice, as_vec.as_slice());

    let mapped = nev.map(|item| item.wrapping_add(1));
    assert_eq!(mapped.len(), nev.len());
    let mapped = nev.clone().map_into(|item| item.wrapping_add(1));
    assert_eq!(mapped.len(), nev.len());

    let owned: Vec<u8> = nev.clone().into();
    assert_eq!(owned, nev.clone().into_vec());
    let owned_sum: u16 = nev.clone().into_iter().map(u16::from).sum();
    let ref_sum: u16 = (&nev).into_iter().copied().map(u16::from).sum();
    assert_eq!(owned_sum, ref_sum);
    for item in &mut nev {
        *item = item.wrapping_add(1);
    }
    assert_eq!(nev.len().get(), owned.len());
}

fn apply(op: Op, nev: &mut NonEmptyVec<u8>, model: &mut Vec<u8>) {
    match op {
        Op::Push(value) => {
            if model.len() >= MAX_LEN {
                return;
            }
            nev.push(value);
            model.push(value);
        }
        Op::Insert { index, value } => {
            if model.len() >= MAX_LEN {
                return;
            }
            let index = index % (model.len() + 1);
            nev.insert(index, value);
            model.insert(index, value);
        }
        Op::Extend(items) => {
            let take = items.len().min(MAX_LEN.saturating_sub(model.len()));
            nev.extend(items.iter().take(take).copied());
            model.extend_from_slice(&items[..take]);
        }
        Op::Pop => {
            let actual = nev.pop();
            let expected = if model.len() > 1 { model.pop() } else { None };
            assert_eq!(actual, expected);
        }
        Op::Remove { index } => {
            let index = index % model.len();
            let actual = nev.remove(index);
            let expected = if model.len() > 1 {
                Some(model.remove(index))
            } else {
                None
            };
            assert_eq!(actual, expected);
        }
        Op::Resize { new_len, value } => {
            let target = (new_len as usize).clamp(1, MAX_LEN);
            let target = NonZeroUsize::new(target).unwrap();
            nev.resize(target, value);
            model.resize(target.get(), value);
        }
        Op::ResizeWith { new_len, seed } => {
            let target = (new_len as usize).clamp(1, MAX_LEN);
            let target = NonZeroUsize::new(target).unwrap();
            let mut next = seed;
            nev.resize_with(target, || {
                next = next.wrapping_add(1);
                next
            });
            while model.len() < target.get() {
                next = next.wrapping_add(1);
                model.push(next);
            }
            model.truncate(target.get());
        }
        Op::Mutate { swap_a, swap_b } => {
            let a = swap_a % model.len();
            let b = swap_b % model.len();
            let len = nev.mutate(|items| {
                items.swap(a, b);
                items.len()
            });
            model.swap(a, b);
            assert_eq!(len, model.len());
        }
    }
}

fn exercise_mutate(mut init: Vec<u8>, ops: Vec<Op>) {
    init.truncate(MAX_LEN);
    let Ok(mut nev) = NonEmptyVec::<u8>::try_from(init.clone()) else {
        return;
    };

    let mut model = init;
    check_invariants(&nev, &model);
    for op in ops.into_iter().take(MAX_OPS) {
        apply(op, &mut nev, &mut model);
        check_invariants(&nev, &model);
    }
}

fn exercise_codec(mut items: Vec<u8>) {
    items.truncate(MAX_LEN);

    if items.is_empty() {
        let mut buf = Vec::new();
        Vec::<u8>::new().write(&mut buf);
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

    let nev = NonEmptyVec::<u8>::try_from(items.clone()).unwrap();
    let encoded = nev.encode();
    let decoded = NonEmptyVec::<u8>::read_cfg(
        &mut encoded.as_ref(),
        &(
            RangeCfg::from(NonZeroUsize::new(1).unwrap()..=NonZeroUsize::new(MAX_LEN).unwrap()),
            (),
        ),
    )
    .expect("valid encoding decodes");
    assert_eq!(decoded, nev);
    assert_eq!(decoded.into_vec(), items);
}

fn exercise_arbitrary(bytes: &[u8]) {
    let mut unstructured = arbitrary::Unstructured::new(bytes);
    match NonEmptyVec::<u8>::arbitrary(&mut unstructured) {
        Ok(nev) => assert!(!nev.is_empty()),
        Err(arbitrary::Error::NotEnoughData) => {}
        Err(e) => panic!("unexpected arbitrary error: {e:?}"),
    }
}

fn fuzz(input: FuzzInput) {
    match input {
        FuzzInput::Construct { items, array } => exercise_construct(items, array),
        FuzzInput::Mutate { init, ops } => exercise_mutate(init, ops),
        FuzzInput::Codec { items } => exercise_codec(items),
        FuzzInput::Arbitrary { bytes } => exercise_arbitrary(&bytes),
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
