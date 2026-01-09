#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use bytes::Bytes;
use commonware_codec::{Decode, Encode, EncodeSize, Read, Write};
use commonware_utils::bitmap::roaring::{difference, intersection, union, RoaringBitmap};
use libfuzzer_sys::fuzz_target;

const MAX_VALUES: usize = 10_000;
const MAX_CONTAINERS: usize = 100;

/// Maximum value that keeps us within MAX_CONTAINERS containers.
/// Each container covers 65536 values (2^16), so we limit to MAX_CONTAINERS * 65536.
const MAX_VALUE: u64 = (MAX_CONTAINERS as u64) << 16;

/// A u64 value constrained to stay within MAX_CONTAINERS containers.
#[derive(Debug, Clone, Copy)]
struct BoundedU64(u64);

impl<'a> Arbitrary<'a> for BoundedU64 {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let v: u64 = u.arbitrary()?;
        Ok(Self(v % MAX_VALUE))
    }
}

impl From<BoundedU64> for u64 {
    fn from(v: BoundedU64) -> u64 {
        v.0
    }
}

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    Insert {
        values: Vec<BoundedU64>,
    },
    InsertRange {
        start: BoundedU64,
        len: u16,
    },
    Contains {
        values: Vec<BoundedU64>,
        query: BoundedU64,
    },
    Codec {
        values: Vec<BoundedU64>,
    },
    CodecRange {
        start: BoundedU64,
        len: u16,
    },
    Union {
        values_a: Vec<BoundedU64>,
        values_b: Vec<BoundedU64>,
        limit: u64,
    },
    Intersection {
        values_a: Vec<BoundedU64>,
        values_b: Vec<BoundedU64>,
        limit: u64,
    },
    Difference {
        values_a: Vec<BoundedU64>,
        values_b: Vec<BoundedU64>,
        limit: u64,
    },
    Iterator {
        values: Vec<BoundedU64>,
    },
    IterRange {
        values: Vec<BoundedU64>,
        start: BoundedU64,
        end: BoundedU64,
    },
    MinMax {
        values: Vec<BoundedU64>,
    },
    MultipleRanges {
        ranges: Vec<(BoundedU64, u16)>,
    },
    MixedOperations {
        ops: Vec<MixedOp>,
    },
}

#[derive(Arbitrary, Debug)]
enum MixedOp {
    Insert(BoundedU64),
    InsertRange { start: BoundedU64, len: u8 },
    Contains(BoundedU64),
}

fn build_bitmap(values: &[BoundedU64]) -> RoaringBitmap {
    let mut bitmap = RoaringBitmap::new();
    for v in values.iter().take(MAX_VALUES) {
        bitmap.insert(v.0);
    }
    bitmap
}

fn fuzz(input: FuzzInput) {
    match input {
        FuzzInput::Insert { values } => {
            let mut bitmap = RoaringBitmap::new();
            let mut expected_len = 0u64;

            for v in values.iter().take(MAX_VALUES) {
                let v = v.0;
                let was_new = bitmap.insert(v);
                if was_new {
                    expected_len += 1;
                }
                assert!(bitmap.contains(v));
            }

            assert_eq!(bitmap.len(), expected_len);
        }

        FuzzInput::InsertRange { start, len } => {
            if len == 0 {
                return;
            }

            let start = start.0;
            let end = start.saturating_add(len as u64).min(MAX_VALUE);
            let expected_len = end - start;

            if expected_len == 0 {
                return;
            }

            let mut bitmap = RoaringBitmap::new();
            let inserted = bitmap.insert_range(start, end);

            assert_eq!(inserted, expected_len);
            assert_eq!(bitmap.len(), expected_len);

            for i in start..end {
                assert!(bitmap.contains(i), "missing value {}", i);
            }

            if start > 0 {
                assert!(!bitmap.contains(start - 1));
            }
            if end < MAX_VALUE {
                assert!(!bitmap.contains(end));
            }
        }

        FuzzInput::Contains { values, query } => {
            let bitmap = build_bitmap(&values);
            let query = query.0;

            let expected = values.iter().take(MAX_VALUES).any(|v| v.0 == query);
            assert_eq!(bitmap.contains(query), expected);
        }

        FuzzInput::Codec { values } => {
            let bitmap = build_bitmap(&values);

            let encoded_size = bitmap.encode_size();
            assert!(encoded_size > 0 || bitmap.is_empty());

            let mut buf = Vec::new();
            bitmap.write(&mut buf);

            let mut cursor = std::io::Cursor::new(buf.clone());
            let decoded =
                RoaringBitmap::read_cfg(&mut cursor, &(..=MAX_CONTAINERS).into()).unwrap();

            assert_eq!(bitmap.len(), decoded.len());
            assert_eq!(bitmap, decoded);

            let decoded2 =
                RoaringBitmap::decode_cfg(Bytes::from(buf), &(..=MAX_CONTAINERS).into()).unwrap();
            assert_eq!(bitmap, decoded2);

            let encoded2 = decoded.encode();
            let encoded1 = bitmap.encode();
            assert_eq!(encoded1, encoded2);
        }

        FuzzInput::CodecRange { start, len } => {
            if len == 0 {
                return;
            }

            let start = start.0;
            let end = start.saturating_add(len as u64).min(MAX_VALUE);

            if start >= end {
                return;
            }

            let mut bitmap = RoaringBitmap::new();
            bitmap.insert_range(start, end);

            let encoded = bitmap.encode();
            let decoded =
                RoaringBitmap::decode_cfg(encoded.clone(), &(..=MAX_CONTAINERS).into()).unwrap();

            assert_eq!(bitmap.len(), decoded.len());
            assert_eq!(bitmap, decoded);

            for i in start..end {
                assert!(decoded.contains(i), "decoded missing value {}", i);
            }

            let re_encoded = decoded.encode();
            assert_eq!(encoded, re_encoded);
        }

        FuzzInput::Union {
            values_a,
            values_b,
            limit,
        } => {
            let a = build_bitmap(&values_a);
            let b = build_bitmap(&values_b);

            let result = union(&a, &b, limit);

            if limit == u64::MAX {
                for v in a.iter() {
                    assert!(result.contains(v), "union missing value from a: {}", v);
                }
                for v in b.iter() {
                    assert!(result.contains(v), "union missing value from b: {}", v);
                }
            }

            assert!(result.len() <= limit);

            let values: Vec<_> = result.iter().collect();
            for window in values.windows(2) {
                assert!(window[0] < window[1], "union not sorted");
            }
        }

        FuzzInput::Intersection {
            values_a,
            values_b,
            limit,
        } => {
            let a = build_bitmap(&values_a);
            let b = build_bitmap(&values_b);

            let result = intersection(&a, &b, limit);

            for v in result.iter() {
                assert!(a.contains(v), "intersection contains value not in a: {}", v);
                assert!(b.contains(v), "intersection contains value not in b: {}", v);
            }

            assert!(result.len() <= limit);

            let values: Vec<_> = result.iter().collect();
            for window in values.windows(2) {
                assert!(window[0] < window[1], "intersection not sorted");
            }
        }

        FuzzInput::Difference {
            values_a,
            values_b,
            limit,
        } => {
            let a = build_bitmap(&values_a);
            let b = build_bitmap(&values_b);

            let result = difference(&a, &b, limit);

            for v in result.iter() {
                assert!(a.contains(v), "difference contains value not in a: {}", v);
                assert!(!b.contains(v), "difference contains value in b: {}", v);
            }

            assert!(result.len() <= limit);

            let values: Vec<_> = result.iter().collect();
            for window in values.windows(2) {
                assert!(window[0] < window[1], "difference not sorted");
            }
        }

        FuzzInput::Iterator { values } => {
            let bitmap = build_bitmap(&values);

            let collected: Vec<_> = bitmap.iter().collect();
            assert_eq!(collected.len() as u64, bitmap.len());

            for window in collected.windows(2) {
                assert!(window[0] < window[1], "iterator not sorted");
            }

            for &v in &collected {
                assert!(bitmap.contains(v));
            }
        }

        FuzzInput::IterRange { values, start, end } => {
            let start = start.0;
            let end = end.0;

            if start >= end {
                return;
            }

            let bitmap = build_bitmap(&values);
            let collected: Vec<_> = bitmap.iter_range(start, end).collect();

            for &v in &collected {
                assert!(
                    v >= start && v < end,
                    "value {} out of range [{}, {})",
                    v,
                    start,
                    end
                );
                assert!(bitmap.contains(v));
            }

            for window in collected.windows(2) {
                assert!(window[0] < window[1], "iter_range not sorted");
            }
        }

        FuzzInput::MinMax { values } => {
            let bitmap = build_bitmap(&values);

            if bitmap.is_empty() {
                assert_eq!(bitmap.min(), None);
                assert_eq!(bitmap.max(), None);
            } else {
                let min = bitmap.min().unwrap();
                let max = bitmap.max().unwrap();

                assert!(bitmap.contains(min));
                assert!(bitmap.contains(max));
                assert!(min <= max);

                for v in bitmap.iter() {
                    assert!(v >= min);
                    assert!(v <= max);
                }
            }
        }

        FuzzInput::MultipleRanges { ranges } => {
            let mut bitmap = RoaringBitmap::new();

            for (start, len) in ranges.iter().take(100) {
                if *len == 0 {
                    continue;
                }
                let start = start.0;
                let end = start.saturating_add(*len as u64).min(MAX_VALUE);
                if start < end {
                    bitmap.insert_range(start, end);
                }
            }

            let encoded = bitmap.encode();
            let decoded = RoaringBitmap::decode_cfg(encoded, &(..=MAX_CONTAINERS).into()).unwrap();

            assert_eq!(bitmap.len(), decoded.len());
            assert_eq!(bitmap, decoded);
        }

        FuzzInput::MixedOperations { ops } => {
            let mut bitmap = RoaringBitmap::new();

            for op in ops.iter().take(1000) {
                match op {
                    MixedOp::Insert(v) => {
                        let v = v.0;
                        bitmap.insert(v);
                        assert!(bitmap.contains(v));
                    }
                    MixedOp::InsertRange { start, len } => {
                        if *len > 0 {
                            let start = start.0;
                            let end = start.saturating_add(*len as u64).min(MAX_VALUE);
                            if start < end {
                                bitmap.insert_range(start, end);
                            }
                        }
                    }
                    MixedOp::Contains(v) => {
                        let _ = bitmap.contains(v.0);
                    }
                }
            }

            let encoded = bitmap.encode();
            let decoded = RoaringBitmap::decode_cfg(encoded, &(..=MAX_CONTAINERS).into()).unwrap();

            assert_eq!(bitmap.len(), decoded.len());
            assert_eq!(bitmap, decoded);
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
