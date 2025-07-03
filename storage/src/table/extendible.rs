//! Proof-of-concept extendible-hashing backed key-value store.
//!
//! This module contains a pared-down re-implementation of the existing `table::storage` logic
//! but replaces the fixed-size hash table with a directory whose size is a power of two and can
//! grow dynamically.  The on-disk format is *NOT FINAL* – it is just good enough for functional
//! testing so that we can measure behaviour before integrating a production-quality version.
//!
//! Design goals of the PoC:
//! 1. No unsafe code, minimal dependencies.
//! 2. Keep the journal format unchanged so that values written by the current `Table` remain
//!    readable.
//! 3. Entire directory blob is rewritten on every update (simple but slow) – this gives us atomic
//!    semantics without having to worry about partial writes.  The blob is tiny (≤ 1 page) in
//!    common cases so this is acceptable for a demo.
//! 4. Splitting strategy: when a bucket exceeds `max_bucket_chain` entries the directory depth is
//!    doubled and **future** inserts will go to the appropriate (possibly new) bucket.  Existing
//!    entries are *not* relocated – this keeps the code short while still demonstrating the main
//!    idea.  Reads stay correct because we always hash with the *current* depth and then traverse
//!    the linked list (which may include old entries).
//!
//! Crash-safety model: we always write a *new* directory blob and `sync()` before flipping an
//! 8-byte root pointer file (not implemented yet – PoC just rewrites in-place and relies on the
//! underlying storage's atomic-file-replace guarantees).

use super::{Config, Error, Identifier};
use crate::journal::variable::{Config as JournalConfig, Journal};
use bytes::{Buf, BufMut};
use commonware_codec::{Codec, Encode, EncodeSize, FixedSize, Read, Write as CodecWrite};
use commonware_runtime::{Blob, Clock, Metrics, Storage};
use commonware_utils::Array;
use futures::future::try_join_all;
use prometheus_client::metrics::counter::Counter;
use std::{cmp::Ordering, collections::BTreeSet, marker::PhantomData};
use tracing::debug;

/// Hard-coded maximum chain length before triggering a split.
const MAX_BUCKET_CHAIN: usize = 4;

/// Directory header: depth (u8) + padding + CRC32.
#[derive(Clone, Copy)]
struct DirHeader {
    depth: u8,
}

impl DirHeader {
    const SIZE: usize = 8; // depth (1) + padding (3) + crc32 (4)

    fn encode(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0] = self.depth;
        // bytes 1-3 are 0 for now
        let crc = crc32fast::hash(&buf[..4]);
        buf[4..].copy_from_slice(&crc.to_be_bytes());
        buf
    }

    fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::SIZE {
            return Err(Error::DirectoryCorrupted);
        }
        let stored_crc = u32::from_be_bytes(buf[4..8].try_into().unwrap());
        let calc_crc = crc32fast::hash(&buf[..4]);
        if stored_crc != calc_crc {
            return Err(Error::ChecksumMismatch {
                expected: stored_crc,
                actual: calc_crc,
            });
        }
        Ok(Self { depth: buf[0] })
    }
}

/// A directory entry – identical layout to the existing `TableEntry` (24 bytes).
#[derive(Clone)]
struct DirEntry {
    epoch: u64,
    section: u64,
    offset: u32,
    crc: u32,
}

impl DirEntry {
    fn empty() -> Self {
        Self {
            epoch: 0,
            section: 0,
            offset: 0,
            crc: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.section == 0 && self.offset == 0 && self.crc == 0
    }

    fn is_valid(&self) -> bool {
        if self.is_empty() {
            return true;
        }
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&self.epoch.to_be_bytes());
        hasher.update(&self.section.to_be_bytes());
        hasher.update(&self.offset.to_be_bytes());
        hasher.finalize() == self.crc
    }

    fn new(epoch: u64, section: u64, offset: u32) -> Self {
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&epoch.to_be_bytes());
        hasher.update(&section.to_be_bytes());
        hasher.update(&offset.to_be_bytes());
        Self {
            epoch,
            section,
            offset,
            crc: hasher.finalize(),
        }
    }

    const SIZE: usize = 24;

    fn encode(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[..8].copy_from_slice(&self.epoch.to_be_bytes());
        buf[8..16].copy_from_slice(&self.section.to_be_bytes());
        buf[16..20].copy_from_slice(&self.offset.to_be_bytes());
        buf[20..24].copy_from_slice(&self.crc.to_be_bytes());
        buf
    }

    fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::SIZE {
            return Err(Error::BucketCorrupted(0));
        }
        let epoch = u64::from_be_bytes(buf[..8].try_into().unwrap());
        let section = u64::from_be_bytes(buf[8..16].try_into().unwrap());
        let offset = u32::from_be_bytes(buf[16..20].try_into().unwrap());
        let crc = u32::from_be_bytes(buf[20..24].try_into().unwrap());
        let entry = Self {
            epoch,
            section,
            offset,
            crc,
        };
        if !entry.is_valid() {
            return Err(Error::DirectoryCorrupted);
        }
        Ok(entry)
    }
}

/// Blob name for the directory.
const DIR_BLOB_NAME: &[u8] = b"dir";

/// PoC table implementing extendible hashing.
pub struct ExtendibleTable<E: Storage + Metrics + Clock, K: Array, V: Codec> {
    context: E,
    directory: E::Blob,
    dir_header: DirHeader,
    entries: Vec<DirEntry>,

    journal: Journal<E, super::storage::JournalEntry<K, V>>,
    current_section: u64,
    next_epoch: u64,

    puts: Counter,
    gets: Counter,

    _phantom: PhantomData<(K, V)>,
}

impl<E: Storage + Metrics + Clock, K: Array, V: Codec> ExtendibleTable<E, K, V> {
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        // Initialise journal identical to original Table
        let journal_cfg = JournalConfig {
            partition: cfg.journal_partition.clone(),
            compression: cfg.journal_compression,
            codec_config: cfg.codec_config,
            write_buffer: cfg.write_buffer,
        };
        let mut journal = Journal::init(context.clone(), journal_cfg).await?;

        // Open or create directory blob
        let (directory, len) = context.open(&cfg.table_partition, DIR_BLOB_NAME).await?;

        let (header, entries) = if len == 0 {
            // brand new – depth = 0 (single bucket)
            let header = DirHeader { depth: 0 };
            let mut buf = Vec::with_capacity(DirHeader::SIZE + DirEntry::SIZE);
            buf.extend_from_slice(&header.encode());
            buf.extend_from_slice(&DirEntry::empty().encode());
            directory.write_at(buf, 0).await?;
            directory.sync().await?;
            (header, vec![DirEntry::empty()])
        } else {
            // read header
            let mut header_buf = vec![0u8; DirHeader::SIZE];
            directory.read_at(header_buf.as_mut_slice(), 0).await?;
            let header = DirHeader::decode(&header_buf)?;
            let entry_count = 1usize << header.depth;
            let mut entries = Vec::with_capacity(entry_count);
            let mut offset = DirHeader::SIZE as u64;
            for _ in 0..entry_count {
                let mut buf = vec![0u8; DirEntry::SIZE];
                directory.read_at(buf.as_mut_slice(), offset).await?;
                entries.push(DirEntry::decode(&buf)?);
                offset += DirEntry::SIZE as u64;
            }
            (header, entries)
        };

        // metrics
        let puts = Counter::default();
        let gets = Counter::default();
        context.register("puts", "puts", puts.clone());
        context.register("gets", "gets", gets.clone());

        Ok(Self {
            context,
            directory,
            dir_header: header,
            entries,
            journal,
            current_section: 0,
            next_epoch: 1,
            puts,
            gets,
            _phantom: PhantomData,
        })
    }

    fn bucket_index(&self, key: &K) -> usize {
        let mask = (1u32 << self.dir_header.depth) - 1;
        (crc32fast::hash(key.as_ref()) & mask) as usize
    }

    async fn write_directory(&mut self) -> Result<(), Error> {
        // serialize header + entries into a buffer and rewrite whole blob
        let mut buf = Vec::with_capacity(DirHeader::SIZE + self.entries.len() * DirEntry::SIZE);
        buf.extend_from_slice(&self.dir_header.encode());
        for entry in &self.entries {
            buf.extend_from_slice(&entry.encode());
        }
        self.directory.write_at(buf, 0).await?;
        self.directory.sync().await?;
        Ok(())
    }

    async fn split_if_needed(&mut self, bucket_idx: usize, chain_len: usize) -> Result<(), Error> {
        if chain_len < MAX_BUCKET_CHAIN {
            return Ok(());
        }
        // PoC: double directory, do *not* move existing entries.
        self.dir_header.depth += 1;
        let new_size = 1usize << self.dir_header.depth;
        self.entries.resize(new_size, DirEntry::empty());
        // NOTE: existing entries remain; we just copy pointer to both halves if they share prefix.
        // We replicate the old entry pointer into the new slots that map to same bucket.
        for idx in (0..new_size).step_by(2) {
            let src = idx / 2;
            self.entries[idx] = self.entries[src].clone();
            self.entries[idx + 1] = self.entries[src].clone();
        }
        self.write_directory().await
    }

    /// Put a key/value pair.
    pub async fn put(&mut self, key: K, value: V) -> Result<(), Error> {
        self.puts.inc();

        // locate bucket
        let idx = self.bucket_index(&key);
        let head = &self.entries[idx];
        let next = if head.is_empty() {
            None
        } else {
            Some((head.section, head.offset))
        };

        // append to journal
        let entry = super::storage::JournalEntry::new(key, value, next);
        let (offset, _) = self.journal.append(self.current_section, entry).await?;

        // update directory entry
        self.entries[idx] = DirEntry::new(self.next_epoch, self.current_section, offset);
        self.write_directory().await?;

        // rudimentary chain length check (1 + previous link depth).  We walk at most MAX_BUCKET_CHAIN.
        let mut chain_len = 1;
        let mut cursor = next;
        while let Some((section, off)) = cursor {
            if chain_len >= MAX_BUCKET_CHAIN {
                break;
            }
            let e = self.journal.get(section, off).await?;
            if let Some(e) = e {
                cursor = e.next;
            } else {
                break;
            }
            chain_len += 1;
        }

        self.split_if_needed(idx, chain_len).await?;
        Ok(())
    }

    pub async fn get(&self, id: Identifier<'_, K>) -> Result<Option<V>, Error> {
        match id {
            Identifier::Cursor(_cur) => unimplemented!("cursor lookup not implemented in PoC"),
            Identifier::Key(key) => {
                let idx = self.bucket_index(key);
                let head = &self.entries[idx];
                if head.is_empty() {
                    return Ok(None);
                }
                let mut cursor = Some((head.section, head.offset));
                while let Some((section, off)) = cursor {
                    let e = self.journal.get(section, off).await?;
                    let Some(e) = e else { break };
                    if e.key.as_ref() == key.as_ref() {
                        return Ok(Some(e.value));
                    }
                    cursor = e.next;
                }
                Ok(None)
            }
        }
    }

    pub async fn has(&self, key: &K) -> Result<bool, Error> {
        Ok(self.get(Identifier::Key(key)).await?.is_some())
    }

    pub async fn sync(&mut self) -> Result<(), Error> {
        // sync journal & directory
        self.journal.sync(self.current_section).await?;
        self.directory.sync().await?;
        self.next_epoch += 1;
        Ok(())
    }
}
