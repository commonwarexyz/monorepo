use crate::{
    archive::{immutable::Config, Error, Identifier},
    freezer::{self, Cursor, Freezer},
    ordinal::{self, Ordinal},
    rmap::RMap,
    Context,
};
use commonware_codec::{CodecShared, EncodeSize, RangeCfg, Read, Write as CodecWrite};
use commonware_macros::boxed;
use commonware_runtime::{
    telemetry::metrics::{Counter, MetricsExt as _},
    Blob, Buf, BufferPooler, WriteBatch as _,
};
use commonware_utils::{bitmap::BitMap, Array};
use std::collections::BTreeMap;
use tracing::debug;

/// Name of the commit record blob.
const COMMIT_BLOB_NAME: &[u8] = b"commit";

/// Commit-record encoding of the ordinal indices committed by each sync, sharded into
/// per-section bitmaps of `items_per_section` bits (the shard granularity, nothing more:
/// the ordinal itself is a single flat blob keyed by absolute index).
///
/// `None` marks a fully-populated section (every record available). The bitmaps are
/// translated to absolute indices at the [Ordinal::init] boundary.
type SectionBits = BTreeMap<u64, Option<BitMap>>;

/// Codec configuration for reading [SectionBits].
fn section_bits_cfg() -> (RangeCfg<usize>, ((), u64)) {
    (RangeCfg::new(..), ((), usize::MAX as u64))
}

/// An immutable key-value store for ordered data with a minimal memory footprint.
pub struct Archive<E: BufferPooler + Context, K: Array, V: CodecShared> {
    /// Context for storage operations.
    context: E,

    /// Number of items per section.
    items_per_section: u64,

    /// Partition holding the commit record blob.
    partition: String,

    /// Commit record blob for the archive.
    ///
    /// The record is the encoded [SectionBits], rewritten wholesale and staged in the
    /// same batch as the freezer and ordinal data, so every sync commits the bitmaps
    /// atomically with the records they describe.
    commit: E::Blob,

    /// Ordinal section bitmaps to publish with the next commit record.
    sections: SectionBits,

    /// Freezer for the archive.
    freezer: Freezer<E, K, V>,

    /// Ordinal for the archive.
    ordinal: Ordinal<E, Cursor>,

    // Metrics
    gets: Counter,
    has: Counter,
    syncs: Counter,
}

impl<E: BufferPooler + Context, K: Array, V: CodecShared> Archive<E, K, V> {
    /// Initialize a new [Archive] with the given [Config].
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        // Read the commit record. It names the ordinal records committed by the last
        // sync (each sync commits it atomically with the freezer and ordinal data).
        let (commit, commit_len) = context
            .open(&cfg.metadata_partition, COMMIT_BLOB_NAME)
            .await?;
        let sections = if commit_len == 0 {
            SectionBits::new()
        } else {
            let mut buf = commit.read_at(0, commit_len as usize).await?;
            let sections = SectionBits::read_cfg(&mut buf, &section_bits_cfg())
                .map_err(|_| Error::RecordCorrupted)?;
            if buf.remaining() != 0 {
                return Err(Error::RecordCorrupted);
            }
            sections
        };

        // Initialize freezer (recovers from its own committed state)
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
        )
        .await?;

        // Translate the committed section bitmaps to absolute indices. The commit record is
        // externally stored, so a section or bitmap naming unaddressable indices is corruption
        // (such indices can never have been written).
        let items_per_section = cfg.items_per_section.get();
        let mut committed = RMap::new();
        for (&section, bits) in &sections {
            let start = section.checked_mul(items_per_section);
            if start
                .and_then(|start| start.checked_add(items_per_section))
                .is_none()
            {
                return Err(Error::RecordCorrupted);
            }
            let start = start.expect("checked above");
            match bits {
                Some(bits) => {
                    // A stored bitmap shards exactly one section.
                    if bits.len() != items_per_section {
                        return Err(Error::RecordCorrupted);
                    }
                    for bit in bits.ones_iter() {
                        committed.insert(start + bit);
                    }
                }
                None => {
                    for index in start..start + items_per_section {
                        committed.insert(index);
                    }
                }
            }
        }

        // Initialize ordinal. Records outside the committed set are unreachable, so an empty
        // map represents a committed empty ordinal.
        let ordinal = Ordinal::init(
            context.child("ordinal"),
            ordinal::Config {
                partition: cfg.ordinal_partition,
                write_buffer: cfg.ordinal_write_buffer,
                replay_buffer: cfg.replay_buffer,
            },
            Some(committed),
        )
        .await?;

        // Initialize metrics
        let gets = context.counter("gets", "Number of gets performed");
        let has = context.counter("has", "Number of has performed");
        let syncs = context.counter("syncs", "Number of syncs called");

        Ok(Self {
            context,
            items_per_section,
            partition: cfg.metadata_partition,
            commit,
            sections,
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

        // Update the section's pending bitmap, initializing it if needed
        let section = index / self.items_per_section;
        let items_per_section = self.items_per_section;
        let bits = self.sections.entry(section).or_insert_with(|| {
            debug!(section, "initialized section");
            Some(BitMap::zeroes(items_per_section))
        });
        if let Some(active) = bits {
            active.set(index % items_per_section, true);
            if active.count_ones() == items_per_section {
                *bits = None;
            }
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
            Identifier::Key(key) => Ok(self.freezer.has(key).await?),
        }
    }

    async fn sync(&mut self) -> Result<(), Error> {
        self.syncs.inc();

        // ONE batch stages everything: freezer table writes and journal
        // appends, ordinal writes, and the commit record. The whole sync is
        // a single commit with a single fsync. The record is still staged
        // last, so a sequentially replayed batch (the test-only mock
        // fallback) syncs it last (the pre-batch ordering).
        let mut batch = self.context.batch().await?;
        self.freezer.sync_into(&mut batch).await?;
        self.ordinal.sync_into(&mut batch).await?;

        let size = self.sections.encode_size();
        let mut buf = self.context.storage_buffer_pool().alloc(size);
        self.sections.write(&mut buf);
        batch.write_at(&self.commit, 0, buf.freeze()).await?;
        batch.resize(&self.commit, size as u64).await?;
        batch.apply_sync().await?;

        Ok(())
    }

    fn next_gap(&self, index: u64) -> (Option<u64>, Option<u64>) {
        self.ordinal.next_gap(index)
    }

    fn missing_items(&self, index: u64, max: usize) -> Vec<u64> {
        self.ordinal.missing_items(index, max)
    }

    fn ranges(&self) -> impl Iterator<Item = (u64, u64)> {
        self.ordinal.ranges()
    }

    fn ranges_from(&self, from: u64) -> impl Iterator<Item = (u64, u64)> {
        self.ordinal.ranges_from(from)
    }

    fn first_index(&self) -> Option<u64> {
        self.ordinal.first_index()
    }

    fn last_index(&self) -> Option<u64> {
        self.ordinal.last_index()
    }

    #[boxed]
    async fn destroy(self) -> Result<(), Error> {
        // ONE batch stages every partition removal (ordinal, freezer, and the commit
        // record's), so destruction is all-or-nothing.
        let mut batch = self.context.batch().await?;

        // Stage the ordinal's destruction
        self.ordinal.destroy_into(&mut batch);

        // Stage the freezer's destruction
        self.freezer.destroy_into(&mut batch).await?;

        // Stage the commit record's destruction (its partition always exists: the blob is
        // created at initialization)
        drop(self.commit);
        batch.remove(&self.partition, None);

        batch.apply_sync().await?;
        Ok(())
    }
}
