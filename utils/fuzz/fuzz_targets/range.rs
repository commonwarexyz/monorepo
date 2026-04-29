#![no_main]

use arbitrary::Arbitrary;
use bytes::Bytes;
use commonware_codec::{DecodeExt, Encode};
use commonware_utils::range::{EmptyRange, NonEmptyRange};
use libfuzzer_sys::fuzz_target;
use std::ops::Range;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    a: u32,
    b: u32,
}

fn exercise_arbitrary_impl(a: u32, b: u32) {
    let mut seed = [0u8; 8];
    seed[..4].copy_from_slice(&a.to_le_bytes());
    seed[4..].copy_from_slice(&b.to_le_bytes());
    let mut u = arbitrary::Unstructured::new(&seed);
    match NonEmptyRange::<u32>::arbitrary(&mut u) {
        Ok(r) => assert!(r.start() < r.end()),
        Err(arbitrary::Error::IncorrectFormat | arbitrary::Error::NotEnoughData) => {}
        Err(e) => panic!("unexpected arbitrary error: {e:?}"),
    }
}

fn fuzz(input: FuzzInput) {
    let FuzzInput { a, b } = input;
    exercise_arbitrary_impl(a, b);
    let range = a..b;

    let result = NonEmptyRange::new(range.clone());
    if a < b {
        let r = result.expect("non-empty range accepted when start < end");

        // Accessors agree with the underlying range.
        assert_eq!(r.start(), a);
        assert_eq!(r.end(), b);
        assert!(r.start() < r.end());

        // Round-trip through Range.
        let plain: Range<u32> = r.clone().into();
        assert_eq!(plain, range);

        // Codec round-trip.
        let encoded = r.encode();
        let decoded = NonEmptyRange::<u32>::decode(encoded).expect("valid encoding decodes");
        assert_eq!(decoded, r);

        // Iterator yields the expected items in order. Cap the prefix so a
        // wide range (e.g. 0..u32::MAX) cannot OOM the fuzzer; the values we
        // actually inspect are enough to catch off-by-one errors.
        const MAX_ITER: u32 = 1024;
        let count = u64::from(b) - u64::from(a);
        let take = (count as u32).min(MAX_ITER);
        let prefix: Vec<u32> = r.into_iter().take(take as usize).collect();
        assert_eq!(prefix.len() as u32, take);
        for (i, v) in prefix.iter().enumerate() {
            assert_eq!(*v, a + i as u32);
        }
    } else {
        // a >= b must be rejected by the constructor and TryFrom.
        assert_eq!(result, Err(EmptyRange));
        assert_eq!(NonEmptyRange::try_from(range), Err(EmptyRange));
    }

    // Manually construct the wire form `a || b` (8 bytes big-endian) and feed it
    // to NonEmptyRange::decode. Decode must succeed iff a < b. This exercises
    // the codec rejection path documented at utils/src/range.rs:88.
    let mut bytes = Vec::with_capacity(8);
    bytes.extend_from_slice(&a.to_be_bytes());
    bytes.extend_from_slice(&b.to_be_bytes());
    let decoded = NonEmptyRange::<u32>::decode(Bytes::from(bytes));
    if a < b {
        let r = decoded.expect("manual encoding of a < b decodes");
        assert_eq!(r.start(), a);
        assert_eq!(r.end(), b);
    } else {
        assert!(
            decoded.is_err(),
            "manual encoding of a >= b must be rejected by decode"
        );
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
