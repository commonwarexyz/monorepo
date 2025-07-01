use commonware_runtime::tokio::Context;
use commonware_storage::ordinal;
use commonware_utils::array::FixedBytes;
use rand::{rngs::StdRng, RngCore, SeedableRng};

/// Number of bytes that can be buffered before being written to disk.
const WRITE_BUFFER: usize = 1024;

/// Number of bytes to buffer when replaying.
const REPLAY_BUFFER: usize = 1024 * 1024; // 1MB

/// Partition for [Ordinal] store benchmarks.
pub const PARTITION: &str = "ordinal_bench_partition";

/// Configuration constants for [Ordinal] store.
const ITEMS_PER_BLOB: u64 = 10000;

/// Concrete ordinal store type for benchmarks.
pub type Ordinal = ordinal::Ordinal<Context, FixedBytes<128>>;

/// Open (or create) an ordinal store.
pub async fn init(ctx: Context) -> Ordinal {
    let cfg = ordinal::Config {
        partition: PARTITION.into(),
        items_per_blob: ITEMS_PER_BLOB,
        write_buffer: WRITE_BUFFER,
        replay_buffer: REPLAY_BUFFER,
    };
    ordinal::Ordinal::init(ctx, cfg).await.unwrap()
}

/// Append `count` sequential entries with random values to ordinal store and sync once.
pub async fn append_random(store: &mut Ordinal, count: u64) -> Vec<u64> {
    let mut rng = StdRng::seed_from_u64(0);
    let mut val_buf = [0u8; 128];

    let mut indices = Vec::with_capacity(count as usize);
    for i in 0..count {
        indices.push(i);
        rng.fill_bytes(&mut val_buf);
        store.put(i, FixedBytes::new(val_buf)).await.unwrap();
    }
    store.sync().await.unwrap();
    indices
}
