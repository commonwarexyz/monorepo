//! Archive conformance tests

use crate::{
    archive::{Archive as _, Error, immutable, prunable},
    translator::TwoCap,
};
use commonware_codec::DecodeExt;
use commonware_conformance::conformance_tests;
use commonware_runtime::{
    Supervisor as _,
    buffer::paged::CacheRef,
    conformance::{StorageConformance, StorageWorkload},
};
use commonware_utils::{NZU16, NZU64, NZUsize, sequence::FixedBytes};
use core::num::{NonZeroU16, NonZeroU64, NonZeroUsize};
use rand::RngExt as _;

const WRITE_BUFFER: NonZeroUsize = NZUsize!(1024);
const ITEMS_PER_SECTION: NonZeroU64 = NZU64!(1024);
const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

struct ArchivePrunableWorkload;

impl StorageWorkload for ArchivePrunableWorkload {
    type Error = Error;

    async fn run(
        mut context: commonware_runtime::deterministic::Context,
        seed: u64,
    ) -> Result<(), Self::Error> {
        let config = prunable::Config {
            translator: TwoCap,
            key_partition: format!("archive-prunable-key-{seed}"),
            key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            value_partition: format!("archive-prunable-value-{seed}"),
            compression: None,
            codec_config: (),
            items_per_section: ITEMS_PER_SECTION,
            key_write_buffer: WRITE_BUFFER,
            value_write_buffer: WRITE_BUFFER,
            replay_buffer: WRITE_BUFFER,
        };
        let mut archive =
            prunable::Archive::<_, _, FixedBytes<64>, i32>::init(context.child("archive"), config)
                .await?;

        let items_count = context.random_range(100..500);
        for i in 0..items_count {
            let mut key_bytes = [0u8; 64];
            context.fill(&mut key_bytes);
            let key = FixedBytes::<64>::decode(key_bytes.as_ref()).expect("key should decode");
            let value: i32 = context.random();
            archive = archive.put(i as u64, key, value).await?;
        }
        archive.sync().await?;
        Ok(())
    }
}

struct ArchiveImmutableWorkload;

impl StorageWorkload for ArchiveImmutableWorkload {
    type Error = Error;

    async fn run(
        mut context: commonware_runtime::deterministic::Context,
        seed: u64,
    ) -> Result<(), Self::Error> {
        let config = immutable::Config {
            metadata_partition: format!("archive-immutable-metadata-{seed}"),
            freezer_table_partition: format!("archive-immutable-freezer-table-{seed}"),
            freezer_table_initial_size: 64,
            freezer_table_resize_frequency: 2,
            freezer_table_resize_chunk_size: 32,
            freezer_key_partition: format!("archive-immutable-freezer-key-{seed}"),
            freezer_key_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            freezer_value_partition: format!("archive-immutable-freezer-value-{seed}"),
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
        let mut archive =
            immutable::Archive::<_, FixedBytes<64>, i32>::init(context.child("archive"), config)
                .await?;

        let items_count = context.random_range(100..500);
        for i in 0..items_count {
            let mut key_bytes = [0u8; 64];
            context.fill(&mut key_bytes);
            let key = FixedBytes::<64>::decode(key_bytes.as_ref()).expect("key should decode");
            let value: i32 = context.random();
            archive = archive.put(i as u64, key, value).await?;
        }
        archive.sync().await?;
        Ok(())
    }
}

conformance_tests! {
    StorageConformance<ArchivePrunableWorkload> => 128,
    StorageConformance<ArchiveImmutableWorkload> => 128,
}
