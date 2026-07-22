//! Journal conformance tests

use crate::journal::{
    authenticated,
    contiguous::{fixed, variable},
    segmented::{fixed as segmented_fixed, glob, oversized, variable as segmented_variable},
};
use commonware_codec::{FixedSize, RangeCfg, Read, ReadExt, Write};
use commonware_conformance::conformance_tests;
use commonware_cryptography::Sha256;
use commonware_parallel::Sequential;
use commonware_runtime::{
    Buf, BufMut, BufferPooler, Supervisor as _,
    buffer::paged::CacheRef,
    conformance::{StorageConformance, StorageWorkload},
};
use commonware_utils::{NZU16, NZU64, NZUsize};
use core::num::{NonZeroU16, NonZeroU64, NonZeroUsize};
use oversized::Record;
use rand::RngExt as _;

const WRITE_BUFFER: NonZeroUsize = NZUsize!(1024);
const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(4096);
const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

fn authenticated_merkle_config(
    prefix: &str,
    pooler: &impl BufferPooler,
) -> crate::merkle::full::Config<Sequential> {
    crate::merkle::full::Config {
        journal_partition: format!("{prefix}-merkle-journal"),
        metadata_partition: format!("{prefix}-merkle-metadata"),
        items_per_blob: NZU64!(11),
        write_buffer: WRITE_BUFFER,
        strategy: Sequential,
        page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
    }
}

fn authenticated_journal_config(prefix: &str, pooler: &impl BufferPooler) -> fixed::Config {
    fixed::Config {
        partition: format!("{prefix}-journal"),
        items_per_blob: NZU64!(11),
        page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
        write_buffer: WRITE_BUFFER,
    }
}

async fn run_authenticated_journal<F>(
    mut context: commonware_runtime::deterministic::Context,
    seed: u64,
    prefix: &'static str,
) -> Result<(), authenticated::Error<F>>
where
    F: crate::merkle::Family,
{
    let prefix = format!("{prefix}-{seed}");
    let mut journal =
        authenticated::Journal::<F, _, fixed::Journal<_, u64>, Sha256, Sequential>::new(
            context.child("authenticated"),
            authenticated_merkle_config(&prefix, &context),
            authenticated_journal_config(&prefix, &context),
            |_| true,
            crate::merkle::Bagging::ForwardFold,
        )
        .await?;

    let items = context.random_range(16..96);
    for i in 0..items {
        let item = seed.wrapping_add(i as u64);
        (journal, _) = journal.append(&item).await?;
    }
    let journal = journal.sync().await?;

    if items > 32 {
        let (journal, _) = journal
            .prune(crate::merkle::Location::new(items as u64 / 3))
            .await?;
        journal.sync().await?;
    }

    Ok(())
}

struct ContiguousFixedWorkload;

impl StorageWorkload for ContiguousFixedWorkload {
    type Error = crate::journal::Error;

    async fn run(
        mut context: commonware_runtime::deterministic::Context,
        seed: u64,
    ) -> Result<(), Self::Error> {
        let config = fixed::Config {
            partition: format!("contiguous-fixed-conformance-{seed}"),
            items_per_blob: ITEMS_PER_BLOB,
            page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            write_buffer: WRITE_BUFFER,
        };
        let mut journal = fixed::Journal::<_, u64>::init(context.child("journal"), config).await?;

        let mut data_to_write =
            vec![0u64; context.random_range(0..(ITEMS_PER_BLOB.get() as usize) * 4)];
        context.fill(&mut data_to_write[..]);

        for item in data_to_write.iter() {
            (journal, _) = journal.append(item).await?;
        }
        journal.sync().await?;
        Ok(())
    }
}

struct ContiguousVariableWorkload;

impl StorageWorkload for ContiguousVariableWorkload {
    type Error = crate::journal::Error;

    async fn run(
        mut context: commonware_runtime::deterministic::Context,
        seed: u64,
    ) -> Result<(), Self::Error> {
        let config = variable::Config {
            partition: format!("contiguous-variable-conformance-{seed}"),
            items_per_section: ITEMS_PER_BLOB,
            page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            write_buffer: WRITE_BUFFER,
            compression: None,
            codec_config: (RangeCfg::new(0..256), ()),
        };
        let mut journal =
            variable::Journal::<_, Vec<u8>>::init(context.child("journal"), config).await?;

        let mut data_to_write =
            vec![Vec::new(); context.random_range(0..(ITEMS_PER_BLOB.get() as usize) * 4)];
        for item in data_to_write.iter_mut() {
            let size = context.random_range(0..256);
            item.resize(size, 0);
            context.fill(item.as_mut_slice());
        }

        for item in data_to_write {
            (journal, _) = journal.append(&item).await?;
        }
        journal.sync().await?;
        Ok(())
    }
}

struct SegmentedFixedWorkload;

impl StorageWorkload for SegmentedFixedWorkload {
    type Error = crate::journal::Error;

    async fn run(
        mut context: commonware_runtime::deterministic::Context,
        seed: u64,
    ) -> Result<(), Self::Error> {
        let config = segmented_fixed::Config {
            partition: format!("segmented-fixed-conformance-{seed}"),
            page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            write_buffer: WRITE_BUFFER,
        };
        let mut journal =
            segmented_fixed::Journal::<_, u64>::init(context.child("journal"), config).await?;

        let items_count = context.random_range(0..(ITEMS_PER_BLOB.get() as usize) * 4);
        let mut data_to_write = vec![0u64; items_count];
        context.fill(&mut data_to_write[..]);

        for (i, item) in data_to_write.iter().enumerate() {
            let section = (i % 3) as u64;
            journal.append(section, item).await?;
        }

        journal.sync([0, 1, 2]).await
    }
}

struct SegmentedGlobWorkload;

impl StorageWorkload for SegmentedGlobWorkload {
    type Error = crate::journal::Error;

    async fn run(
        mut context: commonware_runtime::deterministic::Context,
        seed: u64,
    ) -> Result<(), Self::Error> {
        let config = glob::Config {
            partition: format!("segmented-glob-conformance-{seed}"),
            compression: None,
            codec_config: (RangeCfg::new(0..256), ()),
            write_buffer: WRITE_BUFFER,
        };
        let mut journal = glob::Glob::<_, Vec<u8>>::init(context.child("journal"), config).await?;

        let items_count = context.random_range(0..(ITEMS_PER_BLOB.get() as usize) * 4);
        let mut data_to_write = vec![Vec::new(); items_count];
        for item in data_to_write.iter_mut() {
            let size = context.random_range(0..256);
            item.resize(size, 0);
            context.fill(item.as_mut_slice());
        }

        for (i, item) in data_to_write.iter().enumerate() {
            let section = (i % 3) as u64;
            journal.append(section, item).await?;
        }

        journal.sync([0, 1, 2]).await
    }
}

struct SegmentedVariableWorkload;

impl StorageWorkload for SegmentedVariableWorkload {
    type Error = crate::journal::Error;

    async fn run(
        mut context: commonware_runtime::deterministic::Context,
        seed: u64,
    ) -> Result<(), Self::Error> {
        let config = segmented_variable::Config {
            partition: format!("segmented-variable-conformance-{seed}"),
            page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            write_buffer: WRITE_BUFFER,
            compression: None,
            codec_config: (RangeCfg::new(0..256), ()),
        };
        let mut journal =
            segmented_variable::Journal::<_, Vec<u8>>::init(context.child("journal"), config)
                .await?;

        let items_count = context.random_range(0..(ITEMS_PER_BLOB.get() as usize) * 4);
        let mut data_to_write = vec![Vec::new(); items_count];
        for item in data_to_write.iter_mut() {
            let size = context.random_range(0..256);
            item.resize(size, 0);
            context.fill(item.as_mut_slice());
        }

        for (i, item) in data_to_write.iter().enumerate() {
            let section = (i % 3) as u64;
            journal.append(section, item).await?;
        }

        journal.sync([0, 1, 2]).await
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

struct SegmentedOversizedWorkload;

impl StorageWorkload for SegmentedOversizedWorkload {
    type Error = crate::journal::Error;

    async fn run(
        mut context: commonware_runtime::deterministic::Context,
        seed: u64,
    ) -> Result<(), Self::Error> {
        let config = oversized::Config {
            index_partition: format!("segmented-oversized-index-conformance-{seed}"),
            value_partition: format!("segmented-oversized-value-conformance-{seed}"),
            index_page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            index_write_buffer: WRITE_BUFFER,
            value_write_buffer: WRITE_BUFFER,
            compression: None,
            codec_config: (RangeCfg::new(0..256), ()),
        };
        let mut journal = oversized::Oversized::<_, TestEntry, Vec<u8>>::init(
            context.child("journal"),
            config,
            None,
        )
        .await?;

        let items_count = context.random_range(0..(ITEMS_PER_BLOB.get() as usize) * 4);
        let mut data_to_write = vec![Vec::new(); items_count];
        for item in data_to_write.iter_mut() {
            let size = context.random_range(0..256);
            item.resize(size, 0);
            context.fill(item.as_mut_slice());
        }

        for (i, item) in data_to_write.iter().enumerate() {
            let section = (i % 3) as u64;
            let entry = TestEntry {
                id: i as u64,
                value_offset: 0,
                value_size: 0,
            };
            journal.append(section, entry, item).await?;
        }

        journal.sync([0, 1, 2]).await
    }
}

struct AuthenticatedMmrWorkload;

impl StorageWorkload for AuthenticatedMmrWorkload {
    type Error = authenticated::Error<crate::mmr::Family>;

    async fn run(
        context: commonware_runtime::deterministic::Context,
        seed: u64,
    ) -> Result<(), Self::Error> {
        run_authenticated_journal::<crate::mmr::Family>(
            context,
            seed,
            "authenticated-mmr-conformance",
        )
        .await
    }
}

struct AuthenticatedMmbWorkload;

impl StorageWorkload for AuthenticatedMmbWorkload {
    type Error = authenticated::Error<crate::mmb::Family>;

    async fn run(
        context: commonware_runtime::deterministic::Context,
        seed: u64,
    ) -> Result<(), Self::Error> {
        run_authenticated_journal::<crate::mmb::Family>(
            context,
            seed,
            "authenticated-mmb-conformance",
        )
        .await
    }
}

conformance_tests! {
    StorageConformance<ContiguousFixedWorkload> => 512,
    StorageConformance<ContiguousVariableWorkload> => 512,
    StorageConformance<SegmentedFixedWorkload> => 512,
    StorageConformance<SegmentedGlobWorkload> => 512,
    StorageConformance<SegmentedVariableWorkload> => 512,
    StorageConformance<SegmentedOversizedWorkload> => 512,
    StorageConformance<AuthenticatedMmrWorkload> => 256,
    StorageConformance<AuthenticatedMmbWorkload> => 256,
}
