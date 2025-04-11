#[cfg(feature = "iouring")]
use commonware_runtime::tokio::blob_linux::Blob as BlobImpl;

#[cfg(not(feature = "iouring"))]
use commonware_runtime::tokio::blob_non_linux::Blob as BlobImpl;

use commonware_runtime::Blob;
use criterion::{criterion_group, criterion_main, Criterion};
use rand::{thread_rng, Rng, RngCore};
use tokio::runtime::Runtime;

fn bench_blob_write_at(c: &mut Criterion) {
    // Example: Replace this with your actual Blob implementation.
    for max_write_size in [32, 256, 512, 2048] {
        // Create a new blob for each benchmark iteration.
        let blob = create_test_blob();
        bench_blob_write_at_driver(c, blob, max_write_size);
    }
}

fn bench_blob_write_at_driver<B: Blob>(c: &mut Criterion, blob: B, max_write_size: usize) {
    let runtime = Runtime::new().unwrap();

    c.bench_function(&format!("Blob::write_at {:?}", max_write_size), |b| {
        b.to_async(&runtime).iter(|| async {
            let mut rng = thread_rng(); // Create a random number generator.
            let buffer_size = rng.gen_range(1..=max_write_size); // Random buffer size between 1 and 128 bytes.
            let mut buffer = vec![0u8; buffer_size]; // Create a buffer of size 1024 bytes.
            rng.fill_bytes(&mut buffer); // Read random bytes into the buffer.

            let len = blob.len().await.unwrap();

            let offset = rng.gen_range(0..=len);

            blob.write_at(&buffer, offset)
                .await
                .expect("Failed to write to blob");
        });
    });
}

fn bench_blob_read_at(c: &mut Criterion) {
    let mib = 1024 * 1024;

    // Example: Replace this with your actual Blob implementation.
    for (max_read_size, file_size) in [
        (32, 8 * mib),
        (256, 32 * mib),
        (512, 64 * mib),
        (2048, 64 * mib),
    ] {
        // Create a new blob for each benchmark iteration.
        let blob = create_test_blob();
        bench_blob_read_at_driver(c, blob, file_size, max_read_size);
    }
}

fn bench_blob_read_at_driver<B: Blob>(
    c: &mut Criterion,
    blob: B,
    file_size: usize,
    max_read_size: usize,
) {
    let runtime = Runtime::new().unwrap();

    // Write `file_size` bytes of random data to the blob.
    let mut written = 0;
    let mut buffer = vec![0u8; 1024];
    let mut rng = thread_rng();
    while written < file_size {
        rng.fill_bytes(&mut buffer); // Read random bytes into the buffer.

        runtime.block_on(async {
            blob.write_at(&buffer, written as u64)
                .await
                .expect("Failed to write to blob")
        });
        written += buffer.len();
    }

    c.bench_function(&format!("Blob::read_at {:?}", max_read_size), |b| {
        b.to_async(&runtime).iter(|| async {
            let mut rng = thread_rng();

            let len = blob.len().await.unwrap();

            let buffer_size = rng.gen_range(1..=max_read_size);
            let buffer_size = buffer_size.min(len as usize); // Ensure the buffer size does not exceed the blob length.
            let mut buffer = vec![0u8; buffer_size]; // Create a buffer of size 1024 bytes.
            rng.fill_bytes(&mut buffer); // Read random bytes into the buffer.

            let offset = rng.gen_range(0..=len);

            let offset = if offset + buffer_size as u64 > len {
                len - buffer_size as u64
            } else {
                offset
            };

            blob.read_at(&mut buffer, offset)
                .await
                .expect("Failed to read from blob");
        });
    });
}

#[cfg(feature = "iouring")]
fn create_test_blob() -> impl Blob {
    let partition = "test_partition";
    let name = b"test_name";

    let temp_file = tempfile::tempfile().unwrap();

    BlobImpl::new(partition.into(), name, temp_file, 0)
}

#[cfg(not(feature = "iouring"))]
fn create_test_blob() -> impl Blob {
    use prometheus_client::registry::Registry;
    use tempfile::tempfile;

    let partition = "test_partition";
    let name = b"test_name";

    let temp_file = tempfile().unwrap();

    let metrics = commonware_runtime::tokio::Metrics::init(&mut Registry::default());

    BlobImpl::new(metrics.into(), partition.into(), name, temp_file.into(), 0)
}

criterion_group!(benches, bench_blob_write_at, bench_blob_read_at);
criterion_main!(benches);
