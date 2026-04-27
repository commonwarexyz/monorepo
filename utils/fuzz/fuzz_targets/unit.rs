#![no_main]

use arbitrary::Arbitrary;
use bytes::BytesMut;
use commonware_codec::{EncodeSize, FixedSize, Read, Write};
use commonware_utils::sequence::Unit;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    extra: Vec<u8>,
}

fn fuzz(input: FuzzInput) {
    assert_eq!(<Unit as FixedSize>::SIZE, 0);
    assert_eq!(Unit.encode_size(), 0);

    let mut buf = BytesMut::new();
    Unit.write(&mut buf);
    assert_eq!(buf.len(), 0);

    let mut bytes = BytesMut::from(input.extra.as_slice()).freeze();
    let len_before = bytes.len();
    let decoded = Unit::read_cfg(&mut bytes, &()).expect("Unit decode is infallible");
    assert_eq!(decoded, Unit);
    assert_eq!(
        bytes.len(),
        len_before,
        "Unit decode must not consume bytes"
    );

    assert_eq!(format!("{decoded}"), "()");
    assert_eq!(format!("{decoded:?}"), "()");

    let as_ref: &[u8] = decoded.as_ref();
    assert!(as_ref.is_empty());
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
