use crc::{Crc, CRC_32_ISCSI};
use criterion::{criterion_group, BenchmarkId, Criterion, Throughput};
use rand::{rngs::StdRng, RngCore, SeedableRng};

/// CRC-32/ISCSI implementation from the `crc` crate.
const CRC_ISCSI: Crc<u32> = Crc::<u32>::new(&CRC_32_ISCSI);

fn benchmark_crc32_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("crc32");

    // Test various data sizes
    let sizes: Vec<usize> = vec![
        32,       // Small: typical hash/key size
        256,      // Medium: small record
        1024,     // 1KB
        4096,     // 4KB: typical page size
        16384,    // 16KB: larger page size
        65536,    // 64KB
        262144,   // 256KB
        1048576,  // 1MB
    ];

    let mut rng = StdRng::seed_from_u64(42);

    for size in sizes {
        let mut data = vec![0u8; size];
        rng.fill_bytes(&mut data);

        group.throughput(Throughput::Bytes(size as u64));

        // Benchmark crc32fast::hash (one-shot)
        group.bench_with_input(
            BenchmarkId::new("crc32fast", size),
            &data,
            |b, data| {
                b.iter(|| crc32fast::hash(data));
            },
        );

        // Benchmark crc32fast::Hasher (streaming API)
        group.bench_with_input(
            BenchmarkId::new("crc32fast_hasher", size),
            &data,
            |b, data| {
                b.iter(|| {
                    let mut hasher = crc32fast::Hasher::new();
                    hasher.update(data);
                    hasher.finalize()
                });
            },
        );

        // Benchmark crc crate with CRC_32_ISCSI
        group.bench_with_input(
            BenchmarkId::new("crc_iscsi", size),
            &data,
            |b, data| {
                b.iter(|| CRC_ISCSI.checksum(data));
            },
        );
    }

    group.finish();
}

fn benchmark_crc32_incremental(c: &mut Criterion) {
    let mut group = c.benchmark_group("crc32_incremental");

    // Test incremental hashing with multiple chunks
    let chunk_sizes: Vec<usize> = vec![64, 256, 1024, 4096];
    let num_chunks = 16;

    let mut rng = StdRng::seed_from_u64(42);

    for chunk_size in chunk_sizes {
        let total_size = chunk_size * num_chunks;
        let mut data = vec![0u8; total_size];
        rng.fill_bytes(&mut data);

        let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();

        group.throughput(Throughput::Bytes(total_size as u64));

        // Benchmark crc32fast::Hasher with multiple updates
        group.bench_with_input(
            BenchmarkId::new("crc32fast_hasher", format!("{}x{}", num_chunks, chunk_size)),
            &chunks,
            |b, chunks| {
                b.iter(|| {
                    let mut hasher = crc32fast::Hasher::new();
                    for chunk in chunks.iter() {
                        hasher.update(chunk);
                    }
                    hasher.finalize()
                });
            },
        );

        // Benchmark crc crate with CRC_32_ISCSI using digest API
        group.bench_with_input(
            BenchmarkId::new("crc_iscsi_digest", format!("{}x{}", num_chunks, chunk_size)),
            &chunks,
            |b, chunks| {
                b.iter(|| {
                    let mut digest = CRC_ISCSI.digest();
                    for chunk in chunks.iter() {
                        digest.update(chunk);
                    }
                    digest.finalize()
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, benchmark_crc32_hash, benchmark_crc32_incremental);
