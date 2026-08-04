//! Cache storage conformance tests.

use crate::cache::{Cache, Config, Error};
use commonware_codec::RangeCfg;
use commonware_conformance::conformance_tests;
use commonware_runtime::{
    Supervisor as _,
    buffer::paged::CacheRef,
    conformance::{StorageConformance, StorageWorkload},
};
use commonware_utils::{NZU16, NZU64, NZUsize};
use rand::RngExt as _;

struct CacheWorkload;

impl StorageWorkload for CacheWorkload {
    type Error = Error;

    async fn run(
        mut context: commonware_runtime::deterministic::Context,
        seed: u64,
    ) -> Result<(), Self::Error> {
        let cfg = Config {
            partition: format!("cache-conformance-{seed}"),
            compression: None,
            codec_config: (RangeCfg::new(0..256), ()),
            items_per_blob: NZU64!(16),
            write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
            page_cache: CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(10)),
        };
        let mut cache = Cache::<_, Vec<u8>>::init(context.child("cache"), cfg).await?;

        let items = context.random_range(16..80);
        for i in 0..items {
            let index = i as u64 * 2 + (seed % 2);
            let mut value = vec![0; context.random_range(0..256)];
            context.fill(value.as_mut_slice());
            cache = cache.put(index, value).await?;
        }
        cache = cache.sync().await?;

        if items > 32 {
            cache = cache.prune(32).await?;
            cache.sync().await?;
        }

        Ok(())
    }
}

conformance_tests! {
    StorageConformance<CacheWorkload> => 256,
}
