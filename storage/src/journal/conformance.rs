//! Journal conformance tests

use crate::journal::{
    contiguous::{fixed, variable},
    segmented::{fixed as segmented_fixed, glob, oversized, variable as segmented_variable},
};
use commonware_codec::{FixedSize, RangeCfg, Read, ReadExt, Write};
use commonware_conformance::{conformance_tests, Conformance};
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Buf, BufMut, Metrics, Runner};
use commonware_utils::{NZUsize, NZU16, NZU64};
use core::num::{NonZeroU16, NonZeroU64, NonZeroUsize};
use oversized::Record;
use rand::Rng;

const WRITE_BUFFER: NonZeroUsize = NZUsize!(1024);
const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(4096);
const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

struct ContiguousFixed;

impl Conformance for ContiguousFixed {
    async fn commit(seed: u64) -> Vec<u8> {
        let runner = deterministic::Runner::seeded(seed);
        runner.start(|mut context| async move {
            let config = fixed::Config {
                partition: format!("contiguous-fixed-conformance-{seed}"),
                items_per_blob: ITEMS_PER_BLOB,
                page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: WRITE_BUFFER,
            };
            let mut journal = fixed::Journal::<_, u64>::init(context.with_label("journal"), config)
                .await
                .unwrap();

            let mut data_to_write =
                vec![0u64; context.gen_range(0..(ITEMS_PER_BLOB.get() as usize) * 4)];
            context.fill(&mut data_to_write[..]);

            for item in data_to_write.iter() {
                journal.append(*item).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            context.storage_audit().to_vec()
        })
    }
}

struct ContiguousVariable;

impl Conformance for ContiguousVariable {
    async fn commit(seed: u64) -> Vec<u8> {
        let runner = deterministic::Runner::seeded(seed);
        runner.start(|mut context| async move {
            let config = variable::Config {
                partition: format!("contiguous-variable-conformance-{seed}"),
                items_per_section: ITEMS_PER_BLOB,
                page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: WRITE_BUFFER,
                compression: None,
                codec_config: (RangeCfg::new(0..256), ()),
            };
            let mut journal =
                variable::Journal::<_, Vec<u8>>::init(context.with_label("journal"), config)
                    .await
                    .unwrap();

            let mut data_to_write =
                vec![Vec::new(); context.gen_range(0..(ITEMS_PER_BLOB.get() as usize) * 4)];
            for item in data_to_write.iter_mut() {
                let size = context.gen_range(0..256);
                item.resize(size, 0);
                context.fill(item.as_mut_slice());
            }

            for item in data_to_write {
                journal.append(item).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            context.storage_audit().to_vec()
        })
    }
}

struct SegmentedFixed;

impl Conformance for SegmentedFixed {
    async fn commit(seed: u64) -> Vec<u8> {
        let runner = deterministic::Runner::seeded(seed);
        runner.start(|mut context| async move {
            let config = segmented_fixed::Config {
                partition: format!("segmented-fixed-conformance-{seed}"),
                page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: WRITE_BUFFER,
            };
            let mut journal =
                segmented_fixed::Journal::<_, u64>::init(context.with_label("journal"), config)
                    .await
                    .unwrap();

            // Write items across multiple sections
            let items_count = context.gen_range(0..(ITEMS_PER_BLOB.get() as usize) * 4);
            let mut data_to_write = vec![0u64; items_count];
            context.fill(&mut data_to_write[..]);

            // Distribute items across sections 0, 1, 2
            for (i, item) in data_to_write.iter().enumerate() {
                let section = (i % 3) as u64;
                journal.append(section, *item).await.unwrap();
            }

            // Sync all sections
            for section in 0..3 {
                journal.sync(section).await.unwrap();
            }
            drop(journal);

            context.storage_audit().to_vec()
        })
    }
}

struct SegmentedGlob;

impl Conformance for SegmentedGlob {
    async fn commit(seed: u64) -> Vec<u8> {
        let runner = deterministic::Runner::seeded(seed);
        runner.start(|mut context| async move {
            let config = glob::Config {
                partition: format!("segmented-glob-conformance-{seed}"),
                compression: None,
                codec_config: (RangeCfg::new(0..256), ()),
                write_buffer: WRITE_BUFFER,
            };
            let mut journal = glob::Glob::<_, Vec<u8>>::init(context.with_label("journal"), config)
                .await
                .unwrap();

            // Write variable-size items across multiple sections
            let items_count = context.gen_range(0..(ITEMS_PER_BLOB.get() as usize) * 4);
            let mut data_to_write = vec![Vec::new(); items_count];
            for item in data_to_write.iter_mut() {
                let size = context.gen_range(0..256);
                item.resize(size, 0);
                context.fill(item.as_mut_slice());
            }

            // Distribute items across sections 0, 1, 2
            for (i, item) in data_to_write.iter().enumerate() {
                let section = (i % 3) as u64;
                journal.append(section, item).await.unwrap();
            }

            // Sync all sections
            for section in 0..3 {
                journal.sync(section).await.unwrap();
            }
            drop(journal);

            context.storage_audit().to_vec()
        })
    }
}

struct SegmentedVariable;

impl Conformance for SegmentedVariable {
    async fn commit(seed: u64) -> Vec<u8> {
        let runner = deterministic::Runner::seeded(seed);
        runner.start(|mut context| async move {
            let config = segmented_variable::Config {
                partition: format!("segmented-variable-conformance-{seed}"),
                page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: WRITE_BUFFER,
                compression: None,
                codec_config: (RangeCfg::new(0..256), ()),
            };
            let mut journal = segmented_variable::Journal::<_, Vec<u8>>::init(
                context.with_label("journal"),
                config,
            )
            .await
            .unwrap();

            // Write variable-size items across multiple sections
            let items_count = context.gen_range(0..(ITEMS_PER_BLOB.get() as usize) * 4);
            let mut data_to_write = vec![Vec::new(); items_count];
            for item in data_to_write.iter_mut() {
                let size = context.gen_range(0..256);
                item.resize(size, 0);
                context.fill(item.as_mut_slice());
            }

            // Distribute items across sections 0, 1, 2
            for (i, item) in data_to_write.iter().enumerate() {
                let section = (i % 3) as u64;
                journal.append(section, item.clone()).await.unwrap();
            }

            // Sync all sections
            for section in 0..3 {
                journal.sync(section).await.unwrap();
            }
            drop(journal);

            context.storage_audit().to_vec()
        })
    }
}

/// Test entry for SegmentedOversized conformance.
#[derive(Clone)]
struct TestEntry {
    id: u64,
    value_offset: u64,
    value_size: u32,
}

impl Write for TestEntry {
    fn write(&self, buf: &mut impl BufMut) {
        self.id.write(buf);
        self.value_offset.write(buf);
        self.value_size.write(buf);
    }
}

impl Read for TestEntry {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let id = u64::read(buf)?;
        let value_offset = u64::read(buf)?;
        let value_size = u32::read(buf)?;
        Ok(Self {
            id,
            value_offset,
            value_size,
        })
    }
}

impl FixedSize for TestEntry {
    const SIZE: usize = u64::SIZE + u64::SIZE + u32::SIZE;
}

impl Record for TestEntry {
    fn value_location(&self) -> (u64, u32) {
        (self.value_offset, self.value_size)
    }

    fn with_location(mut self, offset: u64, size: u32) -> Self {
        self.value_offset = offset;
        self.value_size = size;
        self
    }
}

struct SegmentedOversized;

impl Conformance for SegmentedOversized {
    async fn commit(seed: u64) -> Vec<u8> {
        let runner = deterministic::Runner::seeded(seed);
        runner.start(|mut context| async move {
            let config = oversized::Config {
                index_partition: format!("segmented-oversized-index-conformance-{seed}"),
                value_partition: format!("segmented-oversized-value-conformance-{seed}"),
                index_page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                index_write_buffer: WRITE_BUFFER,
                value_write_buffer: WRITE_BUFFER,
                compression: None,
                codec_config: (RangeCfg::new(0..256), ()),
            };
            let mut journal = oversized::Oversized::<_, TestEntry, Vec<u8>>::init(
                context.with_label("journal"),
                config,
            )
            .await
            .unwrap();

            // Write variable-size items across multiple sections
            let items_count = context.gen_range(0..(ITEMS_PER_BLOB.get() as usize) * 4);
            let mut data_to_write = vec![Vec::new(); items_count];
            for item in data_to_write.iter_mut() {
                let size = context.gen_range(0..256);
                item.resize(size, 0);
                context.fill(item.as_mut_slice());
            }

            // Distribute items across sections 0, 1, 2
            for (i, item) in data_to_write.iter().enumerate() {
                let section = (i % 3) as u64;
                let entry = TestEntry {
                    id: i as u64,
                    value_offset: 0,
                    value_size: 0,
                };
                journal.append(section, entry, item).await.unwrap();
            }

            // Sync all sections
            for section in 0..3 {
                journal.sync(section).await.unwrap();
            }
            drop(journal);

            context.storage_audit().to_vec()
        })
    }
}

conformance_tests! {
    ContiguousFixed => 512,
    ContiguousVariable => 512,
    SegmentedFixed => 512,
    SegmentedGlob => 512,
    SegmentedVariable => 512,
    SegmentedOversized => 512,
}
