//! Helpers shared by the Metadata benchmarks.

use commonware_runtime::tokio::Context;
use commonware_storage::metadata::{Config, Metadata};
use commonware_utils::array::U64;
use rand::{rngs::StdRng, Rng, SeedableRng};

/// Partition used across all metadata benchmarks.
pub const PARTITION: &str = "metadata_bench_partition";

/// Concrete metadata type reused by every benchmark.
pub type MetadataType = Metadata<Context, U64, Vec<u8>>;
pub type Key = U64;
pub type Val = Vec<u8>;

/// Open (or create) a fresh metadata store.
///
/// The caller is responsible for closing or destroying it.
pub async fn get_metadata(ctx: Context) -> MetadataType {
    let cfg = Config {
        partition: PARTITION.into(),
        codec_config: ((0..).into(), ()),
    };
    Metadata::init(ctx, cfg).await.unwrap()
}

/// Put `count` random key-value pairs into the metadata store.
/// Returns the generated keys and values.
pub fn get_random_kvs(count: usize, seed_offset: u64) -> Vec<(Key, Val)> {
    let mut rng = StdRng::seed_from_u64(42 + seed_offset);
    let mut kvs = Vec::with_capacity(count);
    for i in 0..count {
        let key = U64::new(i as u64 + seed_offset);
        let mut val = vec![0u8; 100];
        rng.fill(&mut val[..]);
        kvs.push((key, val));
    }
    kvs
}
