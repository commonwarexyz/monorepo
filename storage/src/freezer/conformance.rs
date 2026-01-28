//! Freezer conformance tests

use crate::freezer::Config;
use commonware_conformance::{conformance_tests, Conformance};
use commonware_runtime::{buffer::PoolRef, deterministic, Metrics, Runner};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU16};
use core::num::{NonZeroU16, NonZeroUsize};
use rand::Rng;

const WRITE_BUFFER: NonZeroUsize = NZUsize!(1024);
const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

struct Freezer;

impl Conformance for Freezer {
    async fn commit(seed: u64) -> Vec<u8> {
        let runner = deterministic::Runner::seeded(seed);
        runner.start(|mut context| async move {
            let config = Config {
                key_partition: format!("freezer-key-conformance-{seed}"),
                key_write_buffer: WRITE_BUFFER,
                key_buffer_pool: PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
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
            let mut freezer = super::Freezer::<_, FixedBytes<64>, i32>::init(
                context.with_label("freezer"),
                config,
            )
            .await
            .unwrap();

            // Insert random key-value pairs to trigger resizes
            for i in 0..64 {
                let mut key = [0u8; 64];
                context.fill(&mut key);
                freezer.put(FixedBytes::new(key), i).await.unwrap();

                // Sync periodically to trigger resize chunks
                if i % 8 == 0 {
                    freezer.sync().await.unwrap();
                }
            }

            // Close to complete any pending resize
            freezer.close().await.unwrap();

            context.storage_audit().to_vec()
        })
    }
}

conformance_tests! {
    Freezer => 512,
}
