//! Benchmarks for encode/decode operations.
//!
//! These benchmarks measure the performance of encoding and decoding various
//! integer types. The codec uses little-endian encoding which matches the native
//! byte order on most modern hardware (x86, ARM, RISC-V), enabling efficient
//! zero-copy decoding without byte swapping.

use bytes::BytesMut;
use commonware_codec::{FixedSize, Read, ReadExt, Write};
use criterion::{criterion_group, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

/// Benchmark encoding a single value of type T.
fn bench_encode_single<T>(c: &mut Criterion, name: &str, value: T)
where
    T: Write + Copy,
{
    c.bench_function(&format!("encode_single/{}", name), |b| {
        b.iter(|| {
            let mut buf = BytesMut::with_capacity(128);
            black_box(value).write(&mut buf);
            black_box(buf)
        })
    });
}

/// Benchmark decoding a single value of type T.
fn bench_decode_single<T>(c: &mut Criterion, name: &str, value: T)
where
    T: Read<Cfg = ()> + Write + FixedSize + Copy,
{
    // Pre-encode the value
    let mut buf = BytesMut::with_capacity(T::SIZE);
    value.write(&mut buf);
    let encoded = buf.freeze();

    c.bench_function(&format!("decode_single/{}", name), |b| {
        b.iter(|| {
            let mut slice = encoded.clone();
            let decoded = T::read(&mut slice).unwrap();
            black_box(decoded)
        })
    });
}

/// Benchmark encoding an array of values (measures throughput).
fn bench_encode_array<T>(c: &mut Criterion, name: &str, values: &[T])
where
    T: Write + FixedSize + Copy,
{
    let count = values.len();
    let mut group = c.benchmark_group(format!("encode_array/{}", name));
    group.throughput(Throughput::Bytes((count * T::SIZE) as u64));

    group.bench_with_input(BenchmarkId::from_parameter(count), &values, |b, values| {
        b.iter(|| {
            let mut buf = BytesMut::with_capacity(count * T::SIZE);
            for v in *values {
                v.write(&mut buf);
            }
            black_box(buf)
        })
    });

    group.finish();
}

/// Benchmark decoding an array of values (measures throughput).
fn bench_decode_array<T>(c: &mut Criterion, name: &str, values: &[T])
where
    T: Read<Cfg = ()> + Write + FixedSize + Copy,
{
    let count = values.len();

    // Pre-encode all values
    let mut buf = BytesMut::with_capacity(count * T::SIZE);
    for v in values {
        v.write(&mut buf);
    }
    let encoded = buf.freeze();

    let mut group = c.benchmark_group(format!("decode_array/{}", name));
    group.throughput(Throughput::Bytes((count * T::SIZE) as u64));

    group.bench_with_input(BenchmarkId::from_parameter(count), &encoded, |b, encoded| {
        b.iter(|| {
            let mut slice = encoded.clone();
            let mut decoded = Vec::with_capacity(count);
            for _ in 0..count {
                decoded.push(T::read(&mut slice).unwrap());
            }
            black_box(decoded)
        })
    });

    group.finish();
}

/// Benchmark round-trip encode then decode.
fn bench_roundtrip<T>(c: &mut Criterion, name: &str, values: &[T])
where
    T: Write + Read<Cfg = ()> + FixedSize + Copy,
{
    let count = values.len();
    let mut group = c.benchmark_group(format!("roundtrip/{}", name));
    group.throughput(Throughput::Bytes((count * T::SIZE) as u64));

    group.bench_with_input(BenchmarkId::from_parameter(count), &values, |b, values| {
        b.iter(|| {
            // Encode
            let mut buf = BytesMut::with_capacity(count * T::SIZE);
            for v in *values {
                v.write(&mut buf);
            }
            let encoded = buf.freeze();

            // Decode
            let mut slice = encoded;
            let mut decoded = Vec::with_capacity(count);
            for _ in 0..count {
                decoded.push(T::read(&mut slice).unwrap());
            }
            black_box(decoded)
        })
    });

    group.finish();
}

/// Compare little-endian vs big-endian decoding performance.
/// This demonstrates the advantage of LE encoding on LE hardware (x86, ARM, RISC-V).
fn bench_le_vs_be(c: &mut Criterion) {
    let mut rng = ChaCha8Rng::seed_from_u64(42);
    let count = 10000;

    // Generate random u64 values
    let values: Vec<u64> = (0..count).map(|_| rng.r#gen()).collect();

    // Pre-encode in little-endian (current codec)
    let mut le_buf = BytesMut::with_capacity(count * 8);
    for v in &values {
        v.write(&mut le_buf);
    }
    let le_encoded = le_buf.freeze();

    // Pre-encode in big-endian (old codec format)
    let mut be_buf = BytesMut::with_capacity(count * 8);
    for v in &values {
        be_buf.extend_from_slice(&v.to_be_bytes());
    }
    let be_encoded = be_buf.freeze();

    // Decode benchmarks
    let mut group = c.benchmark_group("le_vs_be_decode/u64");
    group.throughput(Throughput::Bytes((count * 8) as u64));

    // Little-endian decode (current codec)
    group.bench_function("little_endian", |b| {
        b.iter(|| {
            let mut slice = le_encoded.clone();
            let mut sum: u64 = 0;
            for _ in 0..count {
                sum = sum.wrapping_add(u64::read(&mut slice).unwrap());
            }
            black_box(sum)
        })
    });

    // Big-endian decode (simulating old codec)
    group.bench_function("big_endian", |b| {
        b.iter(|| {
            let data = be_encoded.as_ref();
            let mut sum: u64 = 0;
            for i in 0..count {
                let bytes: [u8; 8] = data[i * 8..(i + 1) * 8].try_into().unwrap();
                sum = sum.wrapping_add(u64::from_be_bytes(bytes));
            }
            black_box(sum)
        })
    });

    group.finish();

    // Encode benchmarks (using codec's write method for both)
    let mut group = c.benchmark_group("le_vs_be_encode/u64");
    group.throughput(Throughput::Bytes((count * 8) as u64));

    // Little-endian encode (current codec)
    group.bench_function("little_endian", |b| {
        b.iter(|| {
            let mut buf = BytesMut::with_capacity(count * 8);
            for v in &values {
                v.write(&mut buf);
            }
            black_box(buf)
        })
    });

    // Big-endian encode (simulating old codec using bytes crate)
    group.bench_function("big_endian", |b| {
        use bytes::BufMut;
        b.iter(|| {
            let mut buf = BytesMut::with_capacity(count * 8);
            for v in &values {
                buf.put_u64(*v); // put_u64 is big-endian by default
            }
            black_box(buf)
        })
    });

    group.finish();

    // Direct encode comparison (raw byte operations)
    let mut group = c.benchmark_group("le_vs_be_direct_encode/u64");
    group.throughput(Throughput::Bytes((count * 8) as u64));

    // Direct LE encode
    group.bench_function("little_endian", |b| {
        b.iter(|| {
            let mut buf = BytesMut::with_capacity(count * 8);
            for v in &values {
                buf.extend_from_slice(&v.to_le_bytes());
            }
            black_box(buf)
        })
    });

    // Direct BE encode
    group.bench_function("big_endian", |b| {
        b.iter(|| {
            let mut buf = BytesMut::with_capacity(count * 8);
            for v in &values {
                buf.extend_from_slice(&v.to_be_bytes());
            }
            black_box(buf)
        })
    });

    group.finish();

    // Direct memory read comparison (most relevant for zero-copy scenarios)
    let mut group = c.benchmark_group("le_vs_be_direct_read/u64");
    group.throughput(Throughput::Bytes((count * 8) as u64));

    // Direct LE read (optimal on LE hardware - no byte swap needed)
    group.bench_function("little_endian", |b| {
        b.iter(|| {
            let data = le_encoded.as_ref();
            let mut sum: u64 = 0;
            for i in 0..count {
                let bytes: [u8; 8] = data[i * 8..(i + 1) * 8].try_into().unwrap();
                sum = sum.wrapping_add(u64::from_le_bytes(bytes));
            }
            black_box(sum)
        })
    });

    // Direct BE read (requires byte swap on LE hardware)
    group.bench_function("big_endian", |b| {
        b.iter(|| {
            let data = be_encoded.as_ref();
            let mut sum: u64 = 0;
            for i in 0..count {
                let bytes: [u8; 8] = data[i * 8..(i + 1) * 8].try_into().unwrap();
                sum = sum.wrapping_add(u64::from_be_bytes(bytes));
            }
            black_box(sum)
        })
    });

    group.finish();
}

/// Benchmark zero-copy access pattern (simulates reading integers from a buffer
/// without copying). This is the key benefit of little-endian encoding on LE hardware.
fn bench_zero_copy_read(c: &mut Criterion) {
    let mut rng = ChaCha8Rng::seed_from_u64(42);
    let count = 10000;

    // Pre-encode u64 values
    let values: Vec<u64> = (0..count).map(|_| rng.r#gen()).collect();
    let mut buf = BytesMut::with_capacity(count * 8);
    for v in &values {
        v.write(&mut buf);
    }
    let encoded = buf.freeze();

    let mut group = c.benchmark_group("zero_copy_read");
    group.throughput(Throughput::Bytes((count * 8) as u64));

    // Standard decode (creates new values)
    group.bench_function("standard_decode", |b| {
        b.iter(|| {
            let mut slice = encoded.clone();
            let mut sum: u64 = 0;
            for _ in 0..count {
                sum = sum.wrapping_add(u64::read(&mut slice).unwrap());
            }
            black_box(sum)
        })
    });

    // Direct memory read (simulates zero-copy, only works on LE hardware)
    // This demonstrates the theoretical best-case performance
    group.bench_function("direct_read_le", |b| {
        b.iter(|| {
            let data = encoded.as_ref();
            let mut sum: u64 = 0;
            for i in 0..count {
                // Direct read without going through the codec
                let bytes: [u8; 8] = data[i * 8..(i + 1) * 8].try_into().unwrap();
                sum = sum.wrapping_add(u64::from_le_bytes(bytes));
            }
            black_box(sum)
        })
    });

    group.finish();
}

fn benchmark_integers(c: &mut Criterion) {
    let mut rng = ChaCha8Rng::seed_from_u64(42);

    // Single value benchmarks
    bench_encode_single(c, "u16", rng.r#gen::<u16>());
    bench_encode_single(c, "u32", rng.r#gen::<u32>());
    bench_encode_single(c, "u64", rng.r#gen::<u64>());
    bench_encode_single(c, "u128", rng.r#gen::<u128>());

    bench_decode_single(c, "u16", rng.r#gen::<u16>());
    bench_decode_single(c, "u32", rng.r#gen::<u32>());
    bench_decode_single(c, "u64", rng.r#gen::<u64>());
    bench_decode_single(c, "u128", rng.r#gen::<u128>());

    // Array benchmarks (throughput-focused)
    let count = 10000;
    let u16_values: Vec<u16> = (0..count).map(|_| rng.r#gen()).collect();
    let u32_values: Vec<u32> = (0..count).map(|_| rng.r#gen()).collect();
    let u64_values: Vec<u64> = (0..count).map(|_| rng.r#gen()).collect();
    let u128_values: Vec<u128> = (0..count).map(|_| rng.r#gen()).collect();

    bench_encode_array(c, "u16", &u16_values);
    bench_encode_array(c, "u32", &u32_values);
    bench_encode_array(c, "u64", &u64_values);
    bench_encode_array(c, "u128", &u128_values);

    bench_decode_array(c, "u16", &u16_values);
    bench_decode_array(c, "u32", &u32_values);
    bench_decode_array(c, "u64", &u64_values);
    bench_decode_array(c, "u128", &u128_values);

    // Round-trip benchmarks
    bench_roundtrip(c, "u64", &u64_values);
}

criterion_group!(benches, benchmark_integers, bench_le_vs_be, bench_zero_copy_read);
