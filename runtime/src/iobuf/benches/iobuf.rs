//! `IoBuf` overhead compared to `Bytes`.
//!
//! This module compares `IoBuf`, `Bytes`, and `Vec<u8>` when decoding a
//! fixed-size value. Inputs are prebuilt, then cloned or wrapped inside the
//! measurement loop.
//!
//! `FixedBytes<N>::decode` is used because it reads into a fixed array via
//! `Buf::copy_to_slice`. That path checks `remaining`, copies from `chunk`, and
//! advances the cursor, making it a compact test of the whole `Buf`
//! implementation rather than one accessor in isolation.
//!
//! The `Vec<u8>` modes are included as a deep-clone baseline. Comparing them
//! with `Bytes` and `IoBuf` shows where shared backing storage and atomic
//! reference counts pay off relative to simply cloning the bytes.

use bytes::{BufMut, Bytes};
use commonware_codec::DecodeExt as _;
use commonware_runtime::{IoBuf, IoBufMut};
use commonware_utils::sequence::FixedBytes;
use criterion::Criterion;
use std::{hint::black_box, io::Cursor, num::NonZeroUsize};

macro_rules! bench_sizes {
    ($c:expr, $($size:literal),+ $(,)?) => {
        $(
            let vec = payload($size);
            let bytes = Bytes::from(vec.clone());
            let iobuf_bytes = IoBuf::from(bytes.clone());
            let iobuf_aligned = {
                let mut buffer = IoBufMut::with_alignment(vec.len(), NonZeroUsize::new(1).unwrap());
                buffer.put_slice(&vec);
                buffer.freeze()
            };

            bench_decode_fixed::<$size, _>($c, "bytes", || {
                FixedBytes::<$size>::decode(bytes.clone()).unwrap()
            });

            bench_decode_fixed::<$size, _>($c, "bytes_ref", || {
                let mut bytes = bytes.clone();
                FixedBytes::<$size>::decode(&mut bytes).unwrap()
            });

            bench_decode_fixed::<$size, _>($c, "iobuf_bytes", || {
                FixedBytes::<$size>::decode(iobuf_bytes.clone()).unwrap()
            });

            bench_decode_fixed::<$size, _>($c, "iobuf_bytes_ref", || {
                let mut iobuf_bytes = iobuf_bytes.clone();
                FixedBytes::<$size>::decode(&mut iobuf_bytes).unwrap()
            });

            bench_decode_fixed::<$size, _>($c, "iobuf_aligned", || {
                FixedBytes::<$size>::decode(iobuf_aligned.clone()).unwrap()
            });

            bench_decode_fixed::<$size, _>($c, "iobuf_aligned_ref", || {
                let mut iobuf_aligned = iobuf_aligned.clone();
                FixedBytes::<$size>::decode(&mut iobuf_aligned).unwrap()
            });

            bench_decode_fixed::<$size, _>($c, "vec_cursor", || {
                FixedBytes::<$size>::decode(Cursor::new(vec.clone())).unwrap()
            });

            bench_decode_fixed::<$size, _>($c, "vec_slice", || {
                let vec = black_box(vec.clone());
                FixedBytes::<$size>::decode(vec.as_slice()).unwrap()
            });

            bench_decode_fixed::<$size, _>($c, "slice", || {
                FixedBytes::<$size>::decode(vec.as_slice()).unwrap()
            });
        )+
    };
}

pub fn bench(c: &mut Criterion) {
    bench_sizes!(c, 32, 128, 512, 1024, 4096);
}

fn bench_decode_fixed<const N: usize, F>(c: &mut Criterion, mode: &'static str, decode: F)
where
    F: Fn() -> FixedBytes<N>,
{
    let name = format!("{}::decode_fixed/mode={mode} size={N}", module_path!());

    c.bench_function(&name, |b| {
        b.iter(|| {
            black_box(decode());
        });
    });
}

fn payload(size: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(size);
    for i in 0..size {
        bytes.push((i as u8).wrapping_mul(37).wrapping_add(11));
    }
    bytes
}
