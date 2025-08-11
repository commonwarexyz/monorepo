use crate::{
    archive::{immutable::Config, Error, Identifier},
    freezer::{self, Checkpoint, Cursor, Freezer},
    metadata::{self, Metadata},
    ordinal::{self, Ordinal},
};
use bytes::{Buf, BufMut};
use commonware_codec::{Codec, EncodeSize, FixedSize, Read, ReadExt, Write};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::{sequence::prefixed_u64::U64, Array, BitVec};
use futures::join;
use prometheus_client::metrics::counter::Counter;
use std::collections::BTreeMap;
use tracing::debug;

/// Prefix for [Freezer] records.
const FREEZER_PREFIX: u8 = 0;

/// Prefix for [Ordinal] records.
const ORDINAL_PREFIX: u8 = 1;

/// Item stored in [Metadata] to ensure [Freezer] and [Ordinal] remain consistent.
enum Record {
    Freezer(Checkpoint),
    Ordinal(Option<BitVec>),
}

impl Record {
    /// Get the [Freezer] [Checkpoint] from the [Record].
    fn freezer(&self) -> &Checkpoint {
        match self {
            Self::Freezer(checkpoint) => checkpoint,
            _ => panic!("incorrect record"),
        }
    }

    /// Get the [Ordinal] [BitVec] from the [Record].
    fn ordinal(&self) -> &Option<BitVec> {
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
            1 => Ok(Self::Ordinal(Option::<BitVec>::read_cfg(
                buf,
                &(0..=usize::MAX).into(),
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
pub struct Archive<E: Storage + Metrics + Clock, K: Array, V: Codec> {
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

impl<E: Storage + Metrics + Clock, K: Array, V: Codec> Archive<E, K, V> {
    /// Initialize a new [Archive] with the given [Config].
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        // Initialize metadata
        let metadata = Metadata::<E, U64, Record>::init(
            context.with_label("metadata"),
            metadata::Config {
                partition: cfg.metadata_partition,
                codec_config: (),
            },
        )
        .await?;

        // Get checkpoint
        let freezer_key = U64::new(FREEZER_PREFIX, 0);
        let checkpoint = metadata.get(&freezer_key).map(|freezer| *freezer.freezer());

        // Initialize table
        //
        // TODO (#1227): Use sharded metadata to provide consistency
        let freezer = Freezer::init_with_checkpoint(
            context.with_label("freezer"),
            freezer::Config {
                journal_partition: cfg.freezer_journal_partition,
                journal_compression: cfg.freezer_journal_compression,
                journal_write_buffer: cfg.write_buffer,
                journal_target_size: cfg.freezer_journal_target_size,
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

        // Collect sections
        let sections = metadata.keys(Some(&[ORDINAL_PREFIX])).collect::<Vec<_>>();
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
        let ordinal = Ordinal::init_with_bits(
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
            freezer,
            ordinal,
            gets,
            has,
            syncs,
        })
    }

    /// Get the value for the given index.
    async fn get_index(&self, index: u64) -> Result<Option<V>, Error> {
        // Get ordinal
        let Some(cursor) = self.ordinal.get(index).await? else {
            return Ok(None);
        };

        // Get journal entry
        let result = self
            .freezer
            .get(freezer::Identifier::Cursor(cursor))
            .await?;

        // Get value
        Ok(result)
    }

    /// Get the value for the given key.
    async fn get_key(&self, key: &K) -> Result<Option<V>, Error> {
        // Get table entry
        let result = self.freezer.get(freezer::Identifier::Key(key)).await?;

        // Get value
        Ok(result)
    }

    /// Initialize the section.
    async fn initialize_section(&mut self, section: u64) {
        // Create active bit vector
        let bits = BitVec::zeroes(self.items_per_section as usize);

        // Store record
        let key = U64::new(ORDINAL_PREFIX, section);
        self.metadata.put(key, Record::Ordinal(Some(bits)));
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
        let ordinal_key = U64::new(ORDINAL_PREFIX, section);
        if self.metadata.get(&ordinal_key).is_none() {
            self.initialize_section(section).await;
        }
        let record = self.metadata.get_mut(&ordinal_key).unwrap();

        // Update active bits
        let done = if let Record::Ordinal(Some(bits)) = record {
            bits.set((index % self.items_per_section) as usize);
            bits.count_ones() == self.items_per_section as usize
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
        let (freezer_result, ordinal_result) = join!(self.freezer.sync(), self.ordinal.sync());
        let checkpoint = freezer_result?;
        ordinal_result?;

        // Update checkpoint
        let freezer_key = U64::new(FREEZER_PREFIX, 0);
        self.metadata.put(freezer_key, Record::Freezer(checkpoint));

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
        let checkpoint = self.freezer.close().await?;

        // Update checkpoint
        let freezer_key = U64::new(FREEZER_PREFIX, 0);
        self.metadata.put(freezer_key, Record::Freezer(checkpoint));

        // Close metadata
        self.metadata.close().await?;

        Ok(())
    }

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
