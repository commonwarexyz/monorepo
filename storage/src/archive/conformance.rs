//! Archive conformance tests

use crate::{
    archive::{immutable, prunable, Archive as _},
    translator::TwoCap,
};
use commonware_codec::DecodeExt;
use commonware_conformance::{conformance_tests, Conformance};
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Metrics, Runner};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU16, NZU64};
use core::num::{NonZeroU16, NonZeroU64, NonZeroUsize};
use rand::Rng;

const WRITE_BUFFER: NonZeroUsize = NZUsize!(1024);
const ITEMS_PER_SECTION: NonZeroU64 = NZU64!(1024);
const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

struct ArchivePrunable;

impl Conformance for ArchivePrunable {
    async fn commit(seed: u64) -> Vec<u8> {
        let runner = deterministic::Runner::seeded(seed);
        runner.start(|mut context| async move {
            let config = prunable::Config {
                translator: TwoCap,
                key_partition: format!("archive-prunable-key-{seed}"),
                key_page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                value_partition: format!("archive-prunable-value-{seed}"),
                compression: None,
                codec_config: (),
                items_per_section: ITEMS_PER_SECTION,
                key_write_buffer: WRITE_BUFFER,
                value_write_buffer: WRITE_BUFFER,
                replay_buffer: WRITE_BUFFER,
            };
            let mut archive = prunable::Archive::<_, _, FixedBytes<64>, i32>::init(
                context.with_label("archive"),
                config,
            )
            .await
            .unwrap();

            // Write random items
            let items_count = context.gen_range(100..500);
            for i in 0..items_count {
                let mut key_bytes = [0u8; 64];
                context.fill(&mut key_bytes);
                let key = FixedBytes::<64>::decode(key_bytes.as_ref()).unwrap();
                let value: i32 = context.gen();
                archive.put(i as u64, key, value).await.unwrap();
            }
            archive.sync().await.unwrap();

            context.storage_audit().to_vec()
        })
    }
}

struct ArchiveImmutable;

impl Conformance for ArchiveImmutable {
    async fn commit(seed: u64) -> Vec<u8> {
        let runner = deterministic::Runner::seeded(seed);
        runner.start(|mut context| async move {
            let config = immutable::Config {
                metadata_partition: format!("archive-immutable-metadata-{seed}"),
                freezer_table_partition: format!("archive-immutable-table-{seed}"),
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 2,
                freezer_table_resize_chunk_size: 32,
                freezer_key_partition: format!("archive-immutable-key-{seed}"),
                freezer_key_page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                freezer_value_partition: format!("archive-immutable-value-{seed}"),
                freezer_value_target_size: 1024 * 1024,
                freezer_value_compression: None,
                ordinal_partition: format!("archive-immutable-ordinal-{seed}"),
                items_per_section: ITEMS_PER_SECTION,
                freezer_key_write_buffer: WRITE_BUFFER,
                freezer_value_write_buffer: WRITE_BUFFER,
                ordinal_write_buffer: WRITE_BUFFER,
                replay_buffer: WRITE_BUFFER,
                codec_config: (),
            };
            let mut archive = immutable::Archive::<_, FixedBytes<64>, i32>::init(
                context.with_label("archive"),
                config,
            )
            .await
            .unwrap();

            // Write random items
            let items_count = context.gen_range(100..500);
            for i in 0..items_count {
                let mut key_bytes = [0u8; 64];
                context.fill(&mut key_bytes);
                let key = FixedBytes::<64>::decode(key_bytes.as_ref()).unwrap();
                let value: i32 = context.gen();
                archive.put(i as u64, key, value).await.unwrap();
            }
            archive.sync().await.unwrap();

            context.storage_audit().to_vec()
        })
    }
}

conformance_tests! {
    ArchivePrunable => 128,
    ArchiveImmutable => 128,
}
