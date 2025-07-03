use crate::{
    archive::{immutable::Config, Error, Identifier},
    metadata::{self, Metadata},
    ordinal::{self, Ordinal},
    table::{self, Checkpoint, Cursor, Table},
};
use bytes::{Buf, BufMut};
use commonware_codec::{Codec, EncodeSize, FixedSize, Read, ReadExt, Write};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::{array::prefixed_u64::U64, Array, BitVec};
use futures::join;
use prometheus_client::metrics::counter::Counter;
use std::collections::HashMap;
use tracing::debug;

const CHECKPOINT_PREFIX: u8 = 0;
const INDICES_PREFIX: u8 = 1;

enum Record {
    Checkpoint(Checkpoint),
    Indices(Option<BitVec>),
}

impl Record {
    fn checkpoint(&self) -> &Checkpoint {
        match self {
            Self::Checkpoint(checkpoint) => checkpoint,
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

impl Write for Record {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Checkpoint(checkpoint) => {
                buf.put_u8(0);
                checkpoint.write(buf);
            }
            Self::Indices(indices) => {
                buf.put_u8(1);
                indices.write(buf);
            }
        }
    }
}

impl Read for Record {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let tag = buf.get_u8();
        match tag {
            0 => Ok(Self::Checkpoint(Checkpoint::read(buf)?)),
            1 => Ok(Self::Indices(Option::<BitVec>::read_cfg(
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
            Self::Checkpoint(_) => Checkpoint::SIZE,
            Self::Indices(indices) => indices.encode_size(),
        }
    }
}

pub struct Archive<E: Storage + Metrics + Clock, K: Array, V: Codec> {
    items_per_section: u64,

    metadata: Metadata<E, U64, Record>,
    table: Table<E, K, V>,
    ordinal: Ordinal<E, Cursor>,

    // Metrics
    gets: Counter,
    has: Counter,
    syncs: Counter,
}

impl<E: Storage + Metrics + Clock, K: Array, V: Codec> Archive<E, K, V> {
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        // Initialize metadata
        let mut metadata = Metadata::<E, U64, Record>::init(
            context.with_label("metadata"),
            metadata::Config {
                partition: cfg.metadata_partition,
                codec_config: (),
            },
        )
        .await?;

        // Get checkpoint
        let checkpoint_key = U64::new(CHECKPOINT_PREFIX, 0);
        let checkpoint = match metadata.get(&checkpoint_key) {
            Some(checkpoint) => *checkpoint.checkpoint(),
            None => {
                metadata.put(
                    checkpoint_key.clone(),
                    Record::Checkpoint(Checkpoint::default()),
                );
                *metadata.get(&checkpoint_key).unwrap().checkpoint()
            }
        };

        // Initialize table
        let table = Table::init_with_checkpoint(
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
            Some(checkpoint),
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
        let Some(cursor) = self.ordinal.get(index).await? else {
            return Ok(None);
        };

        // Get journal entry
        let result = self.table.get_cursor(cursor).await?;

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
        self.metadata.put(key, Record::Indices(Some(indices)));
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
        let done = if let Record::Indices(Some(record)) = record {
            record.set((index % self.items_per_section) as usize);
            record.count_ones() == self.items_per_section as usize
        } else {
            false
        };
        if done {
            *record = Record::Indices(None);
        }

        // Put in table
        let cursor = self.table.put(key, data).await?;

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
        let (table_result, ordinal_result) = join!(self.table.sync(), self.ordinal.sync());
        let checkpoint = table_result?;
        ordinal_result?;

        // Update checkpoint
        let checkpoint_key = U64::new(CHECKPOINT_PREFIX, 0);
        self.metadata
            .put(checkpoint_key.clone(), Record::Checkpoint(checkpoint));

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
        let checkpoint = self.table.close().await?;

        // Update checkpoint
        let checkpoint_key = U64::new(CHECKPOINT_PREFIX, 0);
        self.metadata
            .put(checkpoint_key.clone(), Record::Checkpoint(checkpoint));

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
