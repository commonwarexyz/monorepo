//! Freezer conformance tests

use crate::freezer::{Config, Error};
use commonware_conformance::conformance_tests;
use commonware_runtime::{
    buffer::paged::CacheRef,
    conformance::{StorageConformance, StorageWorkload},
    Supervisor as _,
};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU16};
use core::num::{NonZeroU16, NonZeroUsize};
use rand::RngExt as _;

const WRITE_BUFFER: NonZeroUsize = NZUsize!(1024);
const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

struct FreezerWorkload;

impl StorageWorkload for FreezerWorkload {
    type Error = Error;

    async fn run(
        mut context: commonware_runtime::deterministic::Context,
        seed: u64,
    ) -> Result<(), Self::Error> {
        let config = Config {
            key_partition: format!("freezer-key-conformance-{seed}"),
            key_write_buffer: WRITE_BUFFER,
            key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            value_partition: format!("freezer-value-conformance-{seed}"),
            value_compression: None,
            value_write_buffer: WRITE_BUFFER,
            value_target_size: 128,
            table_partition: format!("freezer-table-conformance-{seed}"),
            table_initial_size: 4,
            table_resize_frequency: 1,
            table_resize_chunk_size: 4,
            table_replay_buffer: WRITE_BUFFER,
            codec_config: (),
        };
        let mut freezer =
            super::Freezer::<_, FixedBytes<64>, i32>::init(context.child("freezer"), config, None)
                .await?;

        for i in 0..64 {
            let mut key = [0u8; 64];
            context.fill(&mut key);
            freezer.put(FixedBytes::new(key), i).await?;

            if i % 8 == 0 {
                freezer.sync().await?;
            }
        }
        freezer.close().await?;
        Ok(())
    }
}

conformance_tests! {
    StorageConformance<FreezerWorkload> => 512,
}
