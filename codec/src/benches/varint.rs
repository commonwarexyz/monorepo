use bytes::{Bytes, BytesMut};
use commonware_codec::{EncodeSize as _, ReadExt as _, Write as _, varint::UInt};
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

const VALUES: usize = 1_000;

macro_rules! bench_case {
    ($c:expr, $ty:ty, $len:expr, $value:expr) => {{
        let value: $ty = $value;
        let len: usize = $len;
        let bits = <$ty>::BITS;
        assert_eq!(UInt(value).encode_size(), len);
        let mut encoded = Vec::with_capacity(VALUES * len);
        for _ in 0..VALUES {
            UInt(value).write(&mut encoded);
        }
        let encoded = Bytes::from(encoded);

        $c.bench_function(
            &format!(
                "{}/op=write bits={bits} len={len} values={VALUES}",
                module_path!()
            ),
            |b| {
                let mut out = Vec::with_capacity(VALUES * len);
                b.iter(|| {
                    out.clear();
                    for _ in 0..VALUES {
                        UInt(black_box(value)).write(&mut out);
                    }
                    black_box(&out);
                });
            },
        );
        $c.bench_function(
            &format!(
                "{}/op=write_bytes_mut bits={bits} len={len} values={VALUES}",
                module_path!()
            ),
            |b| {
                b.iter(|| {
                    let mut out = BytesMut::with_capacity(VALUES * len);
                    for _ in 0..VALUES {
                        UInt(black_box(value)).write(&mut out);
                    }
                    black_box(out);
                });
            },
        );
        $c.bench_function(
            &format!(
                "{}/op=read bits={bits} len={len} values={VALUES}",
                module_path!()
            ),
            |b| {
                b.iter(|| {
                    let mut buf = encoded.clone();
                    for _ in 0..VALUES {
                        let v: $ty = UInt::<$ty>::read(&mut buf).unwrap().into();
                        black_box(v);
                    }
                });
            },
        );
    }};
}

fn bench_varint(c: &mut Criterion) {
    bench_case!(c, u32, 1, 100);
    bench_case!(c, u32, 2, 300);
    bench_case!(c, u32, 5, u32::MAX);
    bench_case!(c, u64, 3, 20_000);
    bench_case!(c, u64, 10, u64::MAX);
}

criterion_group!(benches, bench_varint);
