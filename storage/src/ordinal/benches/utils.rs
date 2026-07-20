use commonware_runtime::tokio::Context;
use commonware_storage::{ordinal, rmap::RMap};
use commonware_utils::{sequence::FixedBytes, test_rng, NZUsize};
use rand::Rng;

/// Number of bytes that can be buffered before being written to disk.
const WRITE_BUFFER: usize = 1024;

/// Number of bytes to buffer when replaying.
const REPLAY_BUFFER: usize = 1024 * 1024; // 1MB

/// Partition for [Ordinal] store benchmarks.
pub const PARTITION: &str = "ordinal-bench-partition";

/// Concrete ordinal store type for benchmarks.
pub type Ordinal = ordinal::Ordinal<Context, FixedBytes<128>>;

/// Open (or create) an ordinal store.
pub async fn init(ctx: Context, committed: Option<RMap>) -> Ordinal {
    let cfg = ordinal::Config {
        partition: PARTITION.into(),
        write_buffer: NZUsize!(WRITE_BUFFER),
        replay_buffer: NZUsize!(REPLAY_BUFFER),
    };
    ordinal::Ordinal::init(ctx, cfg, committed).await.unwrap()
}

/// Append `count` sequential entries with random values to ordinal store and sync once.
pub async fn append_random(store: &mut Ordinal, count: u64) -> std::ops::Range<u64> {
    let mut rng = test_rng();
    let mut val_buf = [0u8; 128];

    for i in 0..count {
        rng.fill_bytes(&mut val_buf);
        store.put(i, FixedBytes::new(val_buf)).await.unwrap();
    }
    store.sync().await.unwrap();
    0..count
}
