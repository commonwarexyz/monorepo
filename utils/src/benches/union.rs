use bytes::{BufMut, BytesMut};
use criterion::{black_box, criterion_group, BenchmarkId, Criterion};
use std::convert::TryFrom;

mod method_1_extend {
    use super::*;

    pub fn union(a: &[u8], b: &[u8]) -> Vec<u8> {
        let mut union = Vec::with_capacity(a.len() + b.len());
        union.extend_from_slice(a);
        union.extend_from_slice(b);
        union
    }

    pub fn union_unique(namespace: &[u8], msg: &[u8]) -> Vec<u8> {
        let namespace_len = namespace.len();
        let len = u32::try_from(namespace_len).expect("namespace length too large");
        let mut buf = BytesMut::with_capacity(varint::size(len) + namespace_len + msg.len());
        varint::write(len, &mut buf);
        buf.put_slice(namespace);
        buf.put_slice(msg);
        buf.into()
    }
}

mod method_2 {
    use super::*;

    pub fn concat(a: &[u8], b: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(a.len() + b.len());

        unsafe {
            std::ptr::copy_nonoverlapping(a.as_ptr(), result.as_mut_ptr(), a.len());
            std::ptr::copy_nonoverlapping(b.as_ptr(), result.as_mut_ptr().add(a.len()), b.len());
            result.set_len(a.len() + b.len());
        }

        result
    }

    pub fn union_unique(namespace: &[u8], msg: &[u8]) -> Vec<u8> {
        let namespace_len = namespace.len();
        let len = u32::try_from(namespace_len).expect("namespace length too large");

        let mut varint_bytes = [0u8; 5];
        let varint_size = varint::write_to_array(len, &mut varint_bytes);

        let total_size = varint_size + namespace_len + msg.len();
        let mut result = Vec::with_capacity(total_size);

        unsafe {
            let mut offset = 0;

            std::ptr::copy_nonoverlapping(varint_bytes.as_ptr(), result.as_mut_ptr(), varint_size);
            offset += varint_size;

            std::ptr::copy_nonoverlapping(
                namespace.as_ptr(),
                result.as_mut_ptr().add(offset),
                namespace_len,
            );
            offset += namespace_len;

            std::ptr::copy_nonoverlapping(msg.as_ptr(), result.as_mut_ptr().add(offset), msg.len());

            result.set_len(total_size);
        }

        result
    }
}

mod varint {
    use bytes::{BufMut as _, BytesMut};

    pub fn size(v: u32) -> usize {
        match v {
            0..=127 => 1,
            128..=16383 => 2,
            16384..=2097151 => 3,
            2097152..=268435455 => 4,
            _ => 5,
        }
    }

    pub fn write(v: u32, buf: &mut BytesMut) {
        let mut value = v;
        while value >= 0x80 {
            buf.put_u8(((value & 0x7F) | 0x80) as u8);
            value >>= 7;
        }
        buf.put_u8(value as u8);
    }

    pub fn write_to_array(v: u32, buf: &mut [u8]) -> usize {
        let mut value = v;
        let mut pos = 0;

        while value >= 0x80 {
            buf[pos] = ((value & 0x7F) | 0x80) as u8;
            value >>= 7;
            pos += 1;
        }

        buf[pos] = value as u8;
        pos + 1
    }
}

fn bench_concat(c: &mut Criterion) {
    let mut group = c.benchmark_group("Concat");

    for size in [10, 100, 1000, 10000, 100000].iter() {
        let a = vec![1u8; *size];
        let b = vec![2u8; *size];

        group.bench_with_input(
            BenchmarkId::new("one", size),
            &(a.as_slice(), b.as_slice()),
            |bench, (a, b)| {
                bench.iter(|| method_1_extend::union(black_box(a), black_box(b)));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("two", size),
            &(a.as_slice(), b.as_slice()),
            |bench, (a, b)| {
                bench.iter(|| method_2::concat(black_box(a), black_box(b)));
            },
        );
    }

    group.finish();
}

fn bench_union_unique(c: &mut Criterion) {
    let mut group = c.benchmark_group("UnionUnique");

    for size in [10, 100, 1000, 10000].iter() {
        let namespace = vec![1u8; *size];
        let msg = vec![2u8; *size];

        group.bench_with_input(
            BenchmarkId::new("one", size),
            &(namespace.as_slice(), msg.as_slice()),
            |bench, (namespace, msg)| {
                bench.iter(|| method_1_extend::union_unique(black_box(namespace), black_box(msg)));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("two", size),
            &(namespace.as_slice(), msg.as_slice()),
            |bench, (namespace, msg)| {
                bench.iter(|| method_2::union_unique(black_box(namespace), black_box(msg)));
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_concat, bench_union_unique);
