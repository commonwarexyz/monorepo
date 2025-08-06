use commonware_runtime::tokio::Context;
use commonware_storage::metadata::{Config, Metadata};
use commonware_utils::sequence::U64;
use rand::{rngs::StdRng, seq::SliceRandom, Rng, SeedableRng};

/// Partition used across all metadata benchmarks.
pub const PARTITION: &str = "metadata_bench_partition";

/// Concrete metadata type reused by every benchmark.
pub type MetadataType = Metadata<Context, U64, Vec<u8>>;
pub type Key = U64;
pub type Val = Vec<u8>;

/// Open (or create) a fresh metadata store.
///
/// The caller is responsible for closing or destroying it.
pub async fn init(ctx: Context) -> MetadataType {
    let cfg = Config {
        partition: PARTITION.into(),
        codec_config: ((0..).into(), ()),
    };
    Metadata::init(ctx, cfg).await.unwrap()
}

/// Generate `count` random key-value pairs.
pub fn get_random_kvs(count: usize) -> Vec<(Key, Val)> {
    let mut rng = StdRng::seed_from_u64(0);
    let mut kvs = Vec::with_capacity(count);
    for i in 0..(count as u64) {
        let key = U64::new(i);
        let mut val = vec![0u8; 100];
        rng.fill(&mut val[..]);
        kvs.push((key, val));
    }
    kvs
}

/// Modify `modified` of keys and emit a new set of keys.
pub fn get_modified_kvs(kvs: &[(Key, Val)], modified: usize) -> Vec<(Key, Val)> {
    let mut rng = StdRng::seed_from_u64(0);
    let mut modified_kvs = Vec::with_capacity(kvs.len());
    let mut indices: Vec<usize> = (0..kvs.len()).collect();
    indices.shuffle(&mut rng);
    for &idx in indices.iter().take(modified) {
        let mut val = vec![0; 100];
        rng.fill(&mut val[..]);
        modified_kvs.push((kvs[idx].0.clone(), val));
    }
    modified_kvs
}
