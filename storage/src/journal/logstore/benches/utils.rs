//! Shared workload pieces: one entry type and one journal constructor per
//! backend, so every bench measures identical logical writes.

use commonware_codec::{FixedSize, Read, ReadExt as _, Write};
use commonware_runtime::{Buf, BufMut, Supervisor as _, buffer::paged::CacheRef, tokio::Context};
use commonware_storage::journal::{
    logstore::{Config as SegmentConfig, Oversized as SegmentOversized},
    segmented::oversized::{Config as FileConfig, Oversized as FileOversized, Record},
};
use commonware_utils::{NZU16, NZUsize, sequence::FixedBytes, test_rng};
use rand::Rng as _;

/// Index entry: a u64 id plus the value location every [Record] carries.
#[derive(Debug, Clone)]
pub struct Entry {
    pub id: u64,
    value_offset: u64,
    value_size: u32,
}

impl Entry {
    pub const fn new(id: u64) -> Self {
        Self {
            id,
            value_offset: 0,
            value_size: 0,
        }
    }
}

impl Write for Entry {
    fn write(&self, buf: &mut impl BufMut) {
        self.id.write(buf);
        self.value_offset.write(buf);
        self.value_size.write(buf);
    }
}

impl Read for Entry {
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

impl FixedSize for Entry {
    const SIZE: usize = u64::SIZE + u64::SIZE + u32::SIZE;
}

impl Record for Entry {
    fn value_location(&self) -> (u64, u32) {
        (self.value_offset, self.value_size)
    }

    fn with_location(mut self, offset: u64, size: u32) -> Self {
        self.value_offset = offset;
        self.value_size = size;
        self
    }
}

/// A random value of `N` bytes.
pub fn random_value<const N: usize>() -> FixedBytes<N> {
    let mut arr = [0u8; N];
    test_rng().fill_bytes(&mut arr);
    FixedBytes::new(arr)
}

/// The per-file journal under bench.
pub type FileJournal<const N: usize> = FileOversized<Context, Entry, FixedBytes<N>>;

/// The log-storage adapter under bench.
pub type SegmentJournal<const N: usize> = SegmentOversized<Context, Entry, FixedBytes<N>>;

/// Open a fresh per-file journal.
pub async fn init_file<const N: usize>(context: &Context) -> FileJournal<N> {
    let cfg = FileConfig {
        index_partition: "bench-oversized-index".into(),
        value_partition: "bench-oversized-values".into(),
        index_page_cache: CacheRef::from_pooler(context, NZU16!(8_192), NZUsize!(1_000)),
        index_write_buffer: NZUsize!(1_024 * 1_024),
        value_write_buffer: NZUsize!(1_024 * 1_024),
        compression: None,
        codec_config: (),
    };
    FileJournal::init(context.child("file"), cfg, None)
        .await
        .expect("failed to init per-file journal")
}

/// Open a fresh log-storage journal.
pub async fn init_segment<const N: usize>(context: &Context) -> SegmentJournal<N> {
    let cfg = SegmentConfig {
        family: "bench-oversized".into(),
        compression: None,
        codec_config: (),
    };
    SegmentJournal::init(context.child("segment"), cfg)
        .await
        .expect("failed to init log-storage journal")
}
