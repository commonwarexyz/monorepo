#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use bytes::{Bytes, BytesMut};
use commonware_codec::{DecodeExt, Encode, EncodeSize, Write};
use commonware_utils::{
    FuzzRng,
    range::{EmptyRange, NonEmptyRange, contains_cyclic},
};
use libfuzzer_sys::fuzz_target;
use rand_core::Rng as _;
use std::ops::{Bound, Range};

const MAX_ITER: u32 = 1024;

/// Bytes of the stream an input is sampled from, and of the input's head that seeds it.
const STREAM_BYTES: usize = 1 << 12;
const SEED_BYTES: usize = 8;

/// Fewest and most operations one input runs. The minimum makes a plan from a short input
/// likely to hold every operation kind.
const MIN_OPS: usize = 8;
const MAX_OPS: usize = 16;

/// Largest endpoint and key of a cyclic span, small so that equal endpoints are common.
const CYCLIC_MAX: u8 = 7;

#[derive(Debug)]
enum Op {
    Construct {
        start: u32,
        end: u32,
    },
    Codec {
        start: u32,
        end: u32,
    },
    Iterate {
        start: u32,
        end: u32,
        limit: u16,
    },
    Arbitrary {
        bytes: Vec<u8>,
    },
    ContainsCyclic {
        start: Bound<u8>,
        end: Bound<u8>,
        key: u8,
    },
}

#[derive(Debug)]
struct FuzzInput {
    ops: Vec<Op>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // The input's head seeds a fixed-size stream that the rest of the input overwrites from
        // its start, so even the empty input samples a whole list of operations.
        let seed = u.bytes(u.len().min(SEED_BYTES))?.to_vec();
        let mut stream = vec![0; STREAM_BYTES.max(u.len())];
        FuzzRng::new(seed).fill_bytes(&mut stream);
        let literal = u.bytes(u.len())?;
        stream[..literal.len()].copy_from_slice(literal);
        let u = &mut Unstructured::new(&stream);

        Ok(Self {
            ops: (0..u.int_in_range(MIN_OPS..=MAX_OPS)?)
                .map(|_| u.arbitrary())
                .collect::<arbitrary::Result<_>>()?,
        })
    }
}

fn cyclic_bound(u: &mut Unstructured<'_>) -> arbitrary::Result<Bound<u8>> {
    let value = u.int_in_range(0..=CYCLIC_MAX)?;
    Ok(match u.int_in_range(0..=2)? {
        0 => Bound::Included(value),
        1 => Bound::Excluded(value),
        _ => Bound::Unbounded,
    })
}

impl<'a> Arbitrary<'a> for Op {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=4)? {
            0 => Ok(Self::Construct {
                start: u.arbitrary()?,
                end: u.arbitrary()?,
            }),
            1 => Ok(Self::Codec {
                start: u.arbitrary()?,
                end: u.arbitrary()?,
            }),
            2 => Ok(Self::Iterate {
                start: u.arbitrary()?,
                end: u.arbitrary()?,
                limit: u.arbitrary()?,
            }),
            3 => Ok(Self::Arbitrary {
                bytes: arbitrary_bytes_low_empty(u)?,
            }),
            _ => Ok(Self::ContainsCyclic {
                start: cyclic_bound(u)?,
                end: cyclic_bound(u)?,
                key: u.int_in_range(0..=CYCLIC_MAX)?,
            }),
        }
    }
}

fn arbitrary_bytes_low_empty(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    if u.ratio(1, 16)? {
        return Ok(Vec::new());
    }

    let first = u.arbitrary()?;
    let mut rest = Vec::<u8>::arbitrary(u)?;
    let mut bytes = Vec::with_capacity(1 + rest.len());
    bytes.push(first);
    bytes.append(&mut rest);
    Ok(bytes)
}

fn exercise_construct(start: u32, end: u32) {
    let range = start..end;
    let result = NonEmptyRange::new(range.clone());
    if start < end {
        let r = result.expect("non-empty range accepted when start < end");
        assert_eq!(r.start(), start);
        assert_eq!(r.end(), end);
        assert!(r.start() < r.end());
        assert!(format!("{r:?}").contains(".."));

        let plain: Range<u32> = r.into();
        assert_eq!(plain, range);
    } else {
        assert_eq!(result, Err(EmptyRange));
        assert_eq!(NonEmptyRange::try_from(range), Err(EmptyRange));
        assert_eq!(EmptyRange.to_string(), "range is empty");
    }
}

fn exercise_codec(start: u32, end: u32) {
    if start < end {
        let r = NonEmptyRange::new(start..end).unwrap();

        let encoded = r.encode();
        let decoded = NonEmptyRange::<u32>::decode(encoded).expect("valid encoding decodes");
        assert_eq!(decoded, r);

        let mut written = BytesMut::with_capacity(r.encode_size());
        r.write(&mut written);
        assert_eq!(written.len(), r.encode_size());
        let decoded = NonEmptyRange::<u32>::decode(written.freeze()).expect("write decodes");
        assert_eq!(decoded, r);
    }

    let mut bytes = Vec::with_capacity(8);
    bytes.extend_from_slice(&start.to_be_bytes());
    bytes.extend_from_slice(&end.to_be_bytes());
    let decoded = NonEmptyRange::<u32>::decode(Bytes::from(bytes));
    if start < end {
        let r = decoded.expect("manual encoding of start < end decodes");
        assert_eq!(r.start(), start);
        assert_eq!(r.end(), end);
    } else {
        assert!(
            decoded.is_err(),
            "manual encoding of start >= end must be rejected by decode"
        );
    }
}

fn exercise_iterate(start: u32, end: u32, limit: u16) {
    let Ok(r) = NonEmptyRange::new(start..end) else {
        return;
    };

    let count = u64::from(end) - u64::from(start);
    let take = count.min(u64::from(MAX_ITER)).min(u64::from(limit)) as usize;
    let prefix: Vec<u32> = r.into_iter().take(take).collect();
    assert_eq!(prefix.len(), take);
    for (i, value) in prefix.iter().enumerate() {
        assert_eq!(*value, start + i as u32);
    }
}

fn exercise_arbitrary(bytes: &[u8]) {
    let mut unstructured = arbitrary::Unstructured::new(bytes);
    match NonEmptyRange::<u32>::arbitrary(&mut unstructured) {
        Ok(r) => assert!(r.start() < r.end()),
        Err(arbitrary::Error::IncorrectFormat | arbitrary::Error::NotEnoughData) => {}
        Err(e) => panic!("unexpected arbitrary error: {e:?}"),
    }
}

/// Checks [contains_cyclic] against a model written from its documentation.
fn exercise_contains_cyclic(start: Bound<u8>, end: Bound<u8>, key: u8) {
    let after_start = match start {
        Bound::Included(s) => key >= s,
        Bound::Excluded(s) => key > s,
        Bound::Unbounded => true,
    };
    let before_end = match end {
        Bound::Included(e) => key <= e,
        Bound::Excluded(e) => key < e,
        Bound::Unbounded => true,
    };
    let expected = match (start, end) {
        (Bound::Included(s) | Bound::Excluded(s), Bound::Included(e) | Bound::Excluded(e))
            if s == e =>
        {
            !matches!((start, end), (Bound::Excluded(_), Bound::Excluded(_))) || key != s
        }
        (Bound::Included(s) | Bound::Excluded(s), Bound::Included(e) | Bound::Excluded(e))
            if s > e =>
        {
            after_start || before_end
        }
        _ => after_start && before_end,
    };
    assert_eq!(contains_cyclic((start, end), &key), expected);
}

fn fuzz(input: FuzzInput) {
    for op in input.ops {
        match op {
            Op::Construct { start, end } => exercise_construct(start, end),
            Op::Codec { start, end } => exercise_codec(start, end),
            Op::Iterate { start, end, limit } => exercise_iterate(start, end, limit),
            Op::Arbitrary { bytes } => exercise_arbitrary(&bytes),
            Op::ContainsCyclic { start, end, key } => exercise_contains_cyclic(start, end, key),
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
