#![no_main]

use arbitrary::Arbitrary;
use bytes::BytesMut;
use commonware_codec::{Encode, EncodeSize, FixedSize, Read, Write};
use commonware_utils::sequence::Unit;
use libfuzzer_sys::fuzz_target;

#[derive(Debug)]
enum FuzzInput {
    Codec { extra: Vec<u8> },
    Format,
    Slice,
    Arbitrary { bytes: Vec<u8> },
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=3)? {
            0 => Ok(Self::Codec {
                extra: arbitrary_bytes_low_empty(u)?,
            }),
            1 => Ok(Self::Format),
            2 => Ok(Self::Slice),
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

fn exercise_codec(extra: Vec<u8>) {
    assert_eq!(<Unit as FixedSize>::SIZE, 0);
    assert_eq!(Unit.encode_size(), 0);
    assert!(Unit.encode().is_empty());

    let mut buf = BytesMut::new();
    Unit.write(&mut buf);
    assert!(buf.is_empty());

    let mut bytes = BytesMut::from(extra.as_slice()).freeze();
    let len_before = bytes.len();
    let decoded = Unit::read_cfg(&mut bytes, &()).expect("Unit decode is infallible");
    assert_eq!(decoded, Unit);
    assert_eq!(bytes.len(), len_before);
}

fn exercise_format() {
    let unit = Unit;
    assert_eq!(format!("{unit}"), "()");
    assert_eq!(format!("{unit:?}"), "()");
}

fn exercise_slice() {
    let unit = Unit;
    let deref: &[u8] = &unit;
    let as_ref: &[u8] = unit.as_ref();
    assert!(deref.is_empty());
    assert!(as_ref.is_empty());
}

fn exercise_arbitrary(bytes: &[u8]) {
    let mut unstructured = arbitrary::Unstructured::new(bytes);
    let unit = Unit::arbitrary(&mut unstructured).expect("Unit arbitrary is infallible");
    assert_eq!(unit, Unit);
}

fn fuzz(input: FuzzInput) {
    match input {
        FuzzInput::Codec { extra } => exercise_codec(extra),
        FuzzInput::Format => exercise_format(),
        FuzzInput::Slice => exercise_slice(),
        FuzzInput::Arbitrary { bytes } => exercise_arbitrary(&bytes),
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
