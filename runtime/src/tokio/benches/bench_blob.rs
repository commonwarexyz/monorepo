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
    let blob = create_test_blob();

    bench_blob_write_at_driver(c, blob);
}

fn bench_blob_write_at_driver<B: Blob>(c: &mut Criterion, blob: B) {
    let runtime = Runtime::new().unwrap();

    c.bench_function("Blob::write_at", |b| {
        b.to_async(&runtime).iter(|| async {
            let mut rng = thread_rng(); // Create a random number generator.
            let buffer_size = rng.gen_range(1..=128); // Random buffer size between 1 and 128 bytes.
            let mut buffer = vec![0u8; buffer_size]; // Create a buffer of size 1024 bytes.
            rng.fill_bytes(&mut buffer); // Read random bytes into the buffer.

            let len = blob.len().await.unwrap();

            let offset = if len == 0 { 0 } else { rng.gen_range(0..len) }; // Random offset between 0 and 1024 bytes.

            blob.write_at(&buffer, offset)
                .await
                .expect("Failed to write to blob");
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

criterion_group!(benches, bench_blob_write_at);
criterion_main!(benches);
