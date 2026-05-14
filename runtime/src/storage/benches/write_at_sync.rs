//! Compare durable positioned writes.

use bytes::Bytes;
use commonware_runtime::{tokio, Blob as _, Runner as _, Storage as _};
use criterion::{criterion_group, Criterion};
use std::{
    fs, io,
    path::{Path, PathBuf},
    process,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const PARTITION: &str = "storage-sync-bench";
const BLOB_NAME: &[u8] = b"blob";

#[derive(Clone, Copy)]
enum Method {
    WriteThenSync,
    WriteAtSync,
}

impl Method {
    const fn name(self) -> &'static str {
        match self {
            Self::WriteThenSync => "write_then_sync",
            Self::WriteAtSync => "write_at_sync",
        }
    }
}

fn root(method: Method) -> io::Result<PathBuf> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "commonware-storage-sync-bench-{}-{}-{timestamp}",
        process::id(),
        method.name()
    ));
    fs::create_dir(&root)?;
    Ok(root)
}

fn cleanup_root(root: &Path) {
    let _ = fs::remove_dir_all(root);
}

fn run(method: Method, io_size: usize, iters: u64) -> Duration {
    let root = root(method).expect("unable to create benchmark root");
    let payload = Bytes::from(vec![0xAB; io_size]);
    let cfg = tokio::Config::default()
        .with_worker_threads(2)
        .with_storage_directory(root.clone());

    let elapsed = tokio::Runner::new(cfg).start(|context| async move {
        let (blob, _) = context
            .open(PARTITION, BLOB_NAME)
            .await
            .expect("unable to open blob");

        let start = Instant::now();
        for _ in 0..iters {
            match method {
                Method::WriteThenSync => {
                    blob.write_at(0, payload.clone())
                        .await
                        .expect("unable to write");
                    blob.sync().await.expect("unable to sync");
                }
                Method::WriteAtSync => {
                    blob.write_at_sync(0, payload.clone())
                        .await
                        .expect("unable to write and sync");
                }
            }
        }
        let elapsed = start.elapsed();
        drop(blob);
        context
            .remove(PARTITION, None)
            .await
            .expect("unable to clean benchmark partition");
        elapsed
    });

    cleanup_root(&root);
    elapsed
}

fn bench_write_at_sync(c: &mut Criterion) {
    let io_size = 4096;
    let mut group = c.benchmark_group(module_path!());

    for method in [Method::WriteThenSync, Method::WriteAtSync] {
        group.bench_function(
            &format!("method={} io_size={io_size}", method.name()),
            |b| b.iter_custom(|iters| run(method, io_size, iters)),
        );
    }

    group.finish();
}

criterion_group!(benches, bench_write_at_sync);
