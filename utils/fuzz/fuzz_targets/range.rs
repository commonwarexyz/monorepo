#![no_main]

use arbitrary::Arbitrary;
use bytes::{Bytes, BytesMut};
use commonware_codec::{DecodeExt, Encode, EncodeSize, Write};
use commonware_utils::range::{EmptyRange, NonEmptyRange};
use libfuzzer_sys::fuzz_target;
use std::ops::Range;

const MAX_ITER: u32 = 1024;

#[derive(Debug)]
enum FuzzInput {
    Construct { start: u32, end: u32 },
    Codec { start: u32, end: u32 },
    Iterate { start: u32, end: u32, limit: u16 },
    Arbitrary { bytes: Vec<u8> },
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=3)? {
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
            _ => Ok(Self::Arbitrary {
                bytes: arbitrary_bytes_low_empty(u)?,
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

fn fuzz(input: FuzzInput) {
    match input {
        FuzzInput::Construct { start, end } => exercise_construct(start, end),
        FuzzInput::Codec { start, end } => exercise_codec(start, end),
        FuzzInput::Iterate { start, end, limit } => exercise_iterate(start, end, limit),
        FuzzInput::Arbitrary { bytes } => exercise_arbitrary(&bytes),
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
