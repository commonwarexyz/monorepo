use crate::{
    archive::{immutable::Config, Error, Identifier},
    metadata::{self, Metadata},
    ordinal::{self, Ordinal},
    table::{self, Cursor, Table},
};
use bytes::{Buf, BufMut};
use commonware_codec::{Codec, EncodeSize, FixedSize, Read, ReadExt, Write};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::{array::prefixed_u64::U64, Array, BitVec};
use futures::join;
use prometheus_client::metrics::counter::Counter;
use std::{collections::HashMap, ops::Deref};
use tracing::debug;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
#[repr(transparent)]
pub struct OrdinalRecord([u8; u64::SIZE + u32::SIZE]);

impl OrdinalRecord {
    fn new(index: u64, offset: u32) -> Self {
        let mut buf = [0u8; u64::SIZE + u32::SIZE];
        buf[..u64::SIZE].copy_from_slice(&index.to_be_bytes());
        buf[u64::SIZE..].copy_from_slice(&offset.to_be_bytes());
        Self(buf)
    }

    fn index(&self) -> u64 {
        u64::from_be_bytes(self.0[..u64::SIZE].try_into().unwrap())
    }

    fn offset(&self) -> u32 {
        u32::from_be_bytes(self.0[u64::SIZE..].try_into().unwrap())
    }
}

impl Write for OrdinalRecord {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl Read for OrdinalRecord {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        <[u8; u64::SIZE + u32::SIZE]>::read(buf).map(Self)
    }
}

impl FixedSize for OrdinalRecord {
    const SIZE: usize = u64::SIZE + u32::SIZE;
}

impl Array for OrdinalRecord {}

impl Deref for OrdinalRecord {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for OrdinalRecord {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for OrdinalRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "OrdinalRecord(section={}, offset={})",
            u64::from_be_bytes(self.0[..u64::SIZE].try_into().unwrap()),
            u32::from_be_bytes(self.0[u64::SIZE..].try_into().unwrap())
        )
    }
}

impl std::fmt::Display for OrdinalRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "OrdinalRecord(section={}, offset={})",
            u64::from_be_bytes(self.0[..u64::SIZE].try_into().unwrap()),
            u32::from_be_bytes(self.0[u64::SIZE..].try_into().unwrap())
        )
    }
}

enum MetadataRecord {
    Cursor(Cursor),
    Indices(Option<BitVec>),
}

impl MetadataRecord {
    fn cursor(&self) -> &Cursor {
        match self {
            Self::Cursor(cursor) => cursor,
            _ => panic!("incorrect record"),
        }
    }

    fn indices(&self) -> &Option<BitVec> {
        match self {
            Self::Indices(indices) => indices,
            _ => panic!("incorrect record"),
        }
    }
}

impl Write for MetadataRecord {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Cursor(cursor) => {
                buf.put_u8(0);
                cursor.write(buf);
            }
            Self::Indices(indices) => {
                buf.put_u8(1);
                indices.write(buf);
            }
        }
    }
}

impl Read for MetadataRecord {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let tag = buf.get_u8();
        match tag {
            0 => Ok(Self::Cursor(Cursor::read(buf)?)),
            1 => Ok(Self::Indices(Option::<BitVec>::read_cfg(
                buf,
                &(0..=usize::MAX).into(),
            )?)),
            _ => Err(commonware_codec::Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for MetadataRecord {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Cursor(_) => Cursor::SIZE,
            Self::Indices(indices) => indices.encode_size(),
        }
    }
}

const CURSOR_PREFIX: u8 = 0;
const INDICES_PREFIX: u8 = 1;

pub struct Archive<E: Storage + Metrics + Clock, K: Array, V: Codec> {
    items_per_section: u64,

    metadata: Metadata<E, U64, MetadataRecord>,
    table: Table<E, K, V>,
    ordinal: Ordinal<E, OrdinalRecord>,

    // Metrics
    gets: Counter,
    has: Counter,
    syncs: Counter,
}

impl<E: Storage + Metrics + Clock, K: Array, V: Codec> Archive<E, K, V> {
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        // Initialize metadata
        let mut metadata = Metadata::<E, U64, MetadataRecord>::init(
            context.with_label("metadata"),
            metadata::Config {
                partition: cfg.metadata_partition,
                codec_config: (),
            },
        )
        .await?;

        // Get cursor
        let cursor_key = U64::new(CURSOR_PREFIX, 0);
        let cursor = match metadata.get(&cursor_key) {
            Some(cursor) => cursor.cursor(),
            None => {
                metadata.put(
                    cursor_key.clone(),
                    MetadataRecord::Cursor(Cursor::default()),
                );
                metadata.get(&cursor_key).unwrap().cursor()
            }
        };

        // Initialize table
        let table = Table::init(
            context.with_label("table"),
            table::Config {
                journal_partition: cfg.journal_partition,
                journal_compression: cfg.compression,
                table_partition: cfg.table_partition,
                table_size: cfg.table_size,
                codec_config: cfg.codec_config,
                write_buffer: cfg.write_buffer,
                target_journal_size: cfg.target_journal_size,
            },
            *cursor,
        )
        .await?;

        // Collect sections
        let sections = metadata.keys(Some(&[INDICES_PREFIX])).collect::<Vec<_>>();
        let mut section_bits = HashMap::new();
        for section in sections {
            // Get record
            let indices = metadata.get(section).unwrap().indices();

            // Get indices
            let section = section.to_u64();
            section_bits.insert(section, indices);
        }

        // Initialize ordinal
        let ordinal = Ordinal::init_align(
            context.with_label("ordinal"),
            ordinal::Config {
                partition: cfg.ordinal_partition,
                items_per_blob: cfg.items_per_section,
                write_buffer: cfg.write_buffer,
                replay_buffer: cfg.replay_buffer,
            },
            Some(section_bits),
        )
        .await?;

        // Initialize metrics
        let gets = Counter::default();
        let has = Counter::default();
        let syncs = Counter::default();
        context.register("gets", "Number of gets performed", gets.clone());
        context.register("has", "Number of has performed", has.clone());
        context.register("syncs", "Number of syncs called", syncs.clone());

        Ok(Self {
            items_per_section: cfg.items_per_section,
            metadata,
            table,
            ordinal,
            gets,
            has,
            syncs,
        })
    }

    async fn get_index(&self, index: u64) -> Result<Option<V>, Error> {
        // Get ordinal
        let Some(record) = self.ordinal.get(index).await? else {
            return Ok(None);
        };

        // Get journal entry
        let result = self
            .table
            .get_location(record.index(), record.offset())
            .await?;

        // Get value
        Ok(result)
    }

    async fn get_key(&self, key: &K) -> Result<Option<V>, Error> {
        // Get table entry
        let result = self.table.get(key).await?;

        // Get value
        Ok(result)
    }

    async fn initialize_section(&mut self, section: u64) {
        // Create active bit vector
        let indices = BitVec::zeroes(self.items_per_section as usize);

        // Store record
        let key = U64::new(INDICES_PREFIX, section);
        self.metadata
            .put(key, MetadataRecord::Indices(Some(indices)));
        debug!(section, "initialized section");
    }
}

impl<E: Storage + Metrics + Clock, K: Array, V: Codec> crate::archive::Archive
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
        let k = U64::new(INDICES_PREFIX, section);
        if self.metadata.get(&k).is_none() {
            self.initialize_section(section).await;
        }
        let record = self.metadata.get_mut(&k).unwrap();

        // Update active bits
        let done = if let MetadataRecord::Indices(Some(record)) = record {
            record.set((index % self.items_per_section) as usize);
            record.count_ones() == self.items_per_section as usize
        } else {
            false
        };
        if done {
            *record = MetadataRecord::Indices(None);
        }

        // Put in table
        let (section, offset) = self.table.put(key, data).await?;

        // Put section and offset in ordinal
        self.ordinal
            .put(index, OrdinalRecord::new(section, offset))
            .await?;

        Ok(())
    }

    async fn get(&self, identifier: Identifier<'_, K>) -> Result<Option<V>, Error> {
        self.gets.inc();

        match identifier {
            Identifier::Index(index) => self.get_index(index).await,
            Identifier::Key(key) => self.get_key(key).await,
        }
    }

    async fn has(&self, identifier: Identifier<'_, K>) -> Result<bool, Error> {
        self.has.inc();

        match identifier {
            Identifier::Index(index) => Ok(self.ordinal.has(index)),
            Identifier::Key(key) => self.get_key(key).await.map(|result| result.is_some()),
        }
    }

    async fn sync(&mut self) -> Result<(), Error> {
        self.syncs.inc();

        // Sync journal and ordinal
        let (table_result, ordinal_result) = join!(self.table.sync(), self.ordinal.sync());
        let (table_epoch, table_section, table_size) = table_result?;
        ordinal_result?;

        // Update cursor
        let cursor_key = U64::new(CURSOR_PREFIX, 0);
        self.metadata.put(
            cursor_key.clone(),
            MetadataRecord::Cursor(table_epoch, table_section, table_size),
        );

        // Sync metadata once underlying are synced
        self.metadata.sync().await?;

        Ok(())
    }

    fn next_gap(&self, index: u64) -> (Option<u64>, Option<u64>) {
        self.ordinal.next_gap(index)
    }

    async fn close(mut self) -> Result<(), Error> {
        // Close ordinal
        self.ordinal.close().await?;

        // Close table
        let (table_epoch, table_section, table_size) = self.table.close().await?;

        // Update cursor
        let cursor_key = U64::new(CURSOR_PREFIX, 0);
        self.metadata.put(
            cursor_key.clone(),
            MetadataRecord::Cursor(table_epoch, table_section, table_size),
        );

        // Close metadata
        self.metadata.close().await?;

        Ok(())
    }

    async fn destroy(self) -> Result<(), Error> {
        // Destroy ordinal
        self.ordinal.destroy().await?;

        // Destroy table
        self.table.destroy().await?;

        // Destroy metadata
        self.metadata.destroy().await?;

        Ok(())
    }
}
