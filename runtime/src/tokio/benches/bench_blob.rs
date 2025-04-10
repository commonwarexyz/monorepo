#[cfg(feature = "iouring")]
use commonware_runtime::tokio::blob_linux::Blob as BlobImpl;

#[cfg(not(feature = "iouring"))]
use commonware_runtime::tokio::blob_non_linux::Blob as BlobImpl;

use commonware_runtime::Blob;
use criterion::{criterion_group, criterion_main, Criterion};
use rand::{thread_rng, Rng, RngCore};
use tokio::runtime::Runtime;

/// Helper function to benchmark `write_at` and `read_at` for any Blob implementation.
///
/// This function takes a `Blob` instance and benchmarks its `write_at` and `read_at` methods
/// with varying offsets and buffer sizes.
///
/// # Arguments
/// * `c` - The Criterion benchmark context.
/// * `blob` - The Blob instance to benchmark.
/// * `runtime` - A Tokio runtime to execute asynchronous operations.
fn benchmark_blob<B: Blob>(c: &mut Criterion, blob: B, runtime: &Runtime) {
    // Benchmark `write_at`
    c.bench_function("Blob::write_at", |b| {
        b.to_async(runtime).iter(|| async {
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

/// Criterion benchmark entry point.
///
/// This function sets up the benchmarks for the `Blob` trait.
fn bench_blob(c: &mut Criterion) {
    let runtime = Runtime::new().unwrap();

    // Example: Replace this with your actual Blob implementation.
    let blob = create_test_blob();

    benchmark_blob(c, blob, &runtime);
}

/// Helper function to create a test Blob instance.
///
/// Replace this with your actual Blob implementation or a mock for testing.
#[cfg(feature = "iouring")]
fn create_test_blob() -> impl Blob {
    // Create a new LinuxBlob instance with a test partition and name.
    use tempfile::tempfile;

    let partition = "test_partition";
    let name = b"test_name";

    let temp_file = tempfile().unwrap();

    BlobImpl::new(partition.into(), name, temp_file, 0)
}

/// Helper function to create a test Blob instance.
///
/// Replace this with your actual Blob implementation or a mock for testing.
#[cfg(not(feature = "iouring"))]
fn create_test_blob() -> impl Blob {
    use prometheus_client::registry::Registry;
    // Create a new LinuxBlob instance with a test partition and name.
    use tempfile::tempfile;

    let partition = "test_partition";
    let name = b"test_name";

    let temp_file = tempfile().unwrap();
    // let temp_file = tokio::fs::File::from_std(temp_file);

    let metrics = commonware_runtime::tokio::Metrics::init(&mut Registry::default());

    BlobImpl::new(metrics.into(), partition.into(), name, temp_file.into(), 0)
}

// Define the benchmark group.
criterion_group!(benches, bench_blob);
criterion_main!(benches);
