use crate::{
    archive::{immutable::Config, Error, Identifier},
    freezer::{self, Checkpoint, Cursor, Freezer, Reader as FreezerReader},
    metadata::{self, Metadata},
    ordinal::{self, Ordinal, Reader as OrdinalReader},
    Context,
};
use commonware_codec::{CodecShared, EncodeSize, FixedSize, Read, ReadExt, Write};
use commonware_macros::boxed;
use commonware_runtime::{
    telemetry::metrics::{Counter, MetricsExt as _},
    Buf, BufMut, BufferPooler,
};
use commonware_utils::{bitmap::BitMap, sequence::prefixed_u64::U64, Array};
use futures::join;
use std::collections::BTreeMap;
use tracing::debug;

/// Prefix for [Freezer] records.
const FREEZER_PREFIX: u8 = 0;

/// Prefix for [Ordinal] records.
const ORDINAL_PREFIX: u8 = 1;

/// Item stored in [Metadata] to ensure [Freezer] and [Ordinal] remain consistent.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
enum Record {
    Freezer(Checkpoint),
    Ordinal(Option<BitMap>),
}

impl Record {
    /// Get the [Freezer] [Checkpoint] from the [Record].
    fn freezer(&self) -> &Checkpoint {
        match self {
            Self::Freezer(checkpoint) => checkpoint,
            _ => panic!("incorrect record"),
        }
    }

    /// Get the [Ordinal] [BitMap] from the [Record].
    fn ordinal(&self) -> &Option<BitMap> {
        match self {
            Self::Ordinal(indices) => indices,
            _ => panic!("incorrect record"),
        }
    }
}

impl Write for Record {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Freezer(checkpoint) => {
                buf.put_u8(0);
                checkpoint.write(buf);
            }
            Self::Ordinal(indices) => {
                buf.put_u8(1);
                indices.write(buf);
            }
        }
    }
}

impl Read for Record {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let tag = u8::read(buf)?;
        match tag {
            0 => Ok(Self::Freezer(Checkpoint::read(buf)?)),
            1 => Ok(Self::Ordinal(Option::<BitMap>::read_cfg(
                buf,
                &(usize::MAX as u64),
            )?)),
            _ => Err(commonware_codec::Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for Record {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Freezer(_) => Checkpoint::SIZE,
            Self::Ordinal(indices) => indices.encode_size(),
        }
    }
}

/// An immutable key-value store for ordered data with a minimal memory footprint.
pub struct Archive<E: BufferPooler + Context, K: Array, V: CodecShared> {
    /// Number of items per section.
    items_per_section: u64,

    /// Metadata for the archive.
    metadata: Metadata<E, U64, Record>,

    /// Freezer for the archive.
    freezer: Freezer<E, K, V>,

    /// Ordinal for the archive.
    ordinal: Ordinal<E, Cursor>,

    // Metrics
    gets: Counter,
    has: Counter,
    syncs: Counter,
}

/// Cheap read handle for an immutable archive.
pub struct Reader<E: BufferPooler + Context, K: Array, V: CodecShared> {
    freezer: FreezerReader<E, K, V>,
    ordinal: OrdinalReader<E, Cursor>,
    gets: Counter,
    has: Counter,
    _phantom: std::marker::PhantomData<V>,
}

impl<E: BufferPooler + Context, K: Array, V: CodecShared> Clone for Reader<E, K, V> {
    fn clone(&self) -> Self {
        Self {
            freezer: self.freezer.clone(),
            ordinal: self.ordinal.clone(),
            gets: self.gets.clone(),
            has: self.has.clone(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<E: BufferPooler + Context, K: Array, V: CodecShared> Archive<E, K, V> {
    /// Initialize a new [Archive] with the given [Config].
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        // Initialize metadata
        let metadata = Metadata::<E, U64, Record>::init(
            context.child("metadata"),
            metadata::Config {
                partition: cfg.metadata_partition,
                codec_config: (),
            },
        )
        .await?;

        // Metadata is the commit record for lower-layer storage. If no checkpoint was committed,
        // Freezer::init treats existing freezer blobs as uncommitted and starts empty.
        let freezer_key = U64::new(FREEZER_PREFIX, 0);
        let checkpoint = metadata.get(&freezer_key).map(|freezer| *freezer.freezer());

        // Initialize table
        //
        // TODO (#1227): Use sharded metadata to provide consistency
        let freezer = Freezer::init(
            context.child("freezer"),
            freezer::Config {
                key_partition: cfg.freezer_key_partition,
                key_write_buffer: cfg.freezer_key_write_buffer,
                key_page_cache: cfg.freezer_key_page_cache,
                value_partition: cfg.freezer_value_partition,
                value_compression: cfg.freezer_value_compression,
                value_write_buffer: cfg.freezer_value_write_buffer,
                value_target_size: cfg.freezer_value_target_size,
                table_partition: cfg.freezer_table_partition,
                table_initial_size: cfg.freezer_table_initial_size,
                table_resize_frequency: cfg.freezer_table_resize_frequency,
                table_resize_chunk_size: cfg.freezer_table_resize_chunk_size,
                table_replay_buffer: cfg.replay_buffer,
                codec_config: cfg.codec_config,
            },
            checkpoint,
        )
        .await?;

        // Collect committed ordinal sections. Ordinal::init removes stored sections that are not
        // present in this map, so an empty map represents a committed empty ordinal.
        let sections = metadata
            .keys()
            .filter(|k| k.prefix() == ORDINAL_PREFIX)
            .collect::<Vec<_>>();
        let mut section_bits = BTreeMap::new();
        for section in sections {
            // Get record
            let bits = metadata.get(section).unwrap().ordinal();

            // Get section
            let section = section.value();
            section_bits.insert(section, bits);
        }

        // Initialize ordinal
        //
        // TODO (#1227): Use sharded metadata to provide consistency
        let ordinal = Ordinal::init(
            context.child("ordinal"),
            ordinal::Config {
                partition: cfg.ordinal_partition,
                items_per_blob: cfg.items_per_section,
                write_buffer: cfg.ordinal_write_buffer,
                replay_buffer: cfg.replay_buffer,
            },
            Some(section_bits),
        )
        .await?;

        // Initialize metrics
        let gets = context.counter("gets", "Number of gets performed");
        let has = context.counter("has", "Number of has performed");
        let syncs = context.counter("syncs", "Number of syncs called");

        Ok(Self {
            items_per_section: cfg.items_per_section.get(),
            metadata,
            freezer,
            ordinal,
            gets,
            has,
            syncs,
        })
    }

    /// Initialize the section.
    fn initialize_section(&mut self, section: u64) {
        // Create active bit vector
        let bits = BitMap::zeroes(self.items_per_section);

        // Store record
        let key = U64::new(ORDINAL_PREFIX, section);
        self.metadata.put(key, Record::Ordinal(Some(bits)));
        debug!(section, "initialized section");
    }

    /// Return a cheap read handle.
    pub fn reader(&self) -> Reader<E, K, V> {
        Reader {
            freezer: self.freezer.reader(),
            ordinal: self.ordinal.reader(),
            gets: self.gets.clone(),
            has: self.has.clone(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<E: BufferPooler + Context, K: Array, V: CodecShared> Reader<E, K, V> {
    /// Get the value for the given index.
    pub async fn get_index(&self, index: u64) -> Result<Option<V>, Error> {
        let Some(cursor) = self.ordinal.get(index).await? else {
            return Ok(None);
        };
        self.freezer
            .get(freezer::Identifier::Cursor(cursor))
            .await
            .map_err(Into::into)
    }

    /// Get the value for the given key.
    pub async fn get_key(&self, key: &K) -> Result<Option<V>, Error> {
        self.freezer
            .get(freezer::Identifier::Key(key))
            .await
            .map_err(Into::into)
    }

    /// Retrieve an item from [Archive].
    pub async fn get(&self, identifier: Identifier<'_, K>) -> Result<Option<V>, Error> {
        self.gets.inc();
        match identifier {
            Identifier::Index(index) => self.get_index(index).await,
            Identifier::Key(key) => self.get_key(key).await,
        }
    }

    /// Check if an item exists in [Archive].
    pub async fn has(&self, identifier: Identifier<'_, K>) -> Result<bool, Error> {
        self.has.inc();
        match identifier {
            Identifier::Index(index) => Ok(self.ordinal.has(index)),
            Identifier::Key(key) => self.get_key(key).await.map(|result| result.is_some()),
        }
    }

    /// Retrieve the end of the current range and the start of the next range.
    pub fn next_gap(&self, index: u64) -> (Option<u64>, Option<u64>) {
        self.ordinal.next_gap(index)
    }

    /// Returns up to `max` missing items starting from `index`.
    pub fn missing_items(&self, index: u64, max: usize) -> Vec<u64> {
        self.ordinal.missing_items(index, max)
    }

    /// Retrieve an iterator over all populated ranges.
    pub fn ranges(&self) -> impl Iterator<Item = (u64, u64)> {
        self.ordinal.ranges()
    }

    /// Retrieve an iterator over ranges that overlap or follow `from`.
    pub fn ranges_from(&self, from: u64) -> impl Iterator<Item = (u64, u64)> {
        self.ordinal.ranges_from(from)
    }

    /// Retrieve the first index in the archive.
    pub fn first_index(&self) -> Option<u64> {
        self.ordinal.first_index()
    }

    /// Retrieve the last index in the archive.
    pub fn last_index(&self) -> Option<u64> {
        self.ordinal.last_index()
    }
}

impl<E: BufferPooler + Context, K: Array, V: CodecShared> crate::archive::Archive
    for Archive<E, K, V>
{
    type Key = K;
    type Value = V;

    async fn put(&mut self, index: u64, key: K, data: V) -> Result<(), Error> {
        // Ignore duplicates
        if self.ordinal.has(index) {
            return Ok(());
        }

        // Initialize section if it doesn't exist
        let section = index / self.items_per_section;
        let ordinal_key = U64::new(ORDINAL_PREFIX, section);
        if self.metadata.get(&ordinal_key).is_none() {
            self.initialize_section(section);
        }
        let record = self.metadata.get_mut(&ordinal_key).unwrap();

        // Update active bits
        let done = if let Record::Ordinal(Some(bits)) = record {
            bits.set(index % self.items_per_section, true);
            bits.count_ones() == self.items_per_section
        } else {
            false
        };
        if done {
            *record = Record::Ordinal(None);
        }

        // Put in table
        let cursor = self.freezer.put(key, data).await?;

        // Put section and offset in ordinal
        self.ordinal.put(index, cursor).await?;

        Ok(())
    }

    async fn get(&self, identifier: Identifier<'_, K>) -> Result<Option<V>, Error> {
        self.reader().get(identifier).await
    }

    async fn has(&self, identifier: Identifier<'_, K>) -> Result<bool, Error> {
        self.reader().has(identifier).await
    }

    async fn sync(&mut self) -> Result<(), Error> {
        self.syncs.inc();

        // Sync journal and ordinal
        let (freezer_result, ordinal_result) = join!(self.freezer.sync(), self.ordinal.sync());
        let checkpoint = freezer_result?;
        ordinal_result?;

        // Publish the freezer checkpoint with a single metadata sync after the
        // freezer and ordinal state are durable.
        let freezer_key = U64::new(FREEZER_PREFIX, 0);
        self.metadata
            .put_sync(freezer_key, Record::Freezer(checkpoint))
            .await?;

        Ok(())
    }

    fn next_gap(&self, index: u64) -> (Option<u64>, Option<u64>) {
        self.reader().next_gap(index)
    }

    fn missing_items(&self, index: u64, max: usize) -> Vec<u64> {
        self.reader().missing_items(index, max)
    }

    fn ranges(&self) -> impl Iterator<Item = (u64, u64)> {
        self.reader().ranges()
    }

    fn ranges_from(&self, from: u64) -> impl Iterator<Item = (u64, u64)> {
        self.reader().ranges_from(from)
    }

    fn first_index(&self) -> Option<u64> {
        self.reader().first_index()
    }

    fn last_index(&self) -> Option<u64> {
        self.reader().last_index()
    }

    #[boxed]
    async fn destroy(self) -> Result<(), Error> {
        // Destroy ordinal
        self.ordinal.destroy().await?;

        // Destroy freezer
        self.freezer.destroy().await?;

        // Destroy metadata
        self.metadata.destroy().await?;

        Ok(())
    }
}

#[cfg(all(test, feature = "arbitrary"))]
mod conformance {
    use super::*;
    use commonware_codec::conformance::CodecConformance;

    commonware_conformance::conformance_tests! {
        CodecConformance<Record>
    }
}
