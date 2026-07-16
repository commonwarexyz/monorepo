//! Recovery: adopt the newest verifiable commit, repair, rebuild state.
//!
//! Runs once, lazily, before the first storage operation (single-flight,
//! never re-entering the commit path). The exhaustive `model` module (compiled with tests)
//! is the specification for every decision here:
//!
//! - Candidate = valid superblock slot with the higher seq. Its table must
//!   match the superblock's stored CRC (content binding — load-bearing
//!   against recycled-extent aliasing and seq reuse, not just bit rot) and
//!   its delta manifest must verify against the disk (with shadow splicing
//!   for partial frontier chunks).
//! - A failed candidate falls back to the other slot — always a confirmed
//!   commit, because commits serialize and never write the sacred slot. The
//!   losing slot is zeroed so a later crash cannot resurrect it. On crash
//!   histories the rejected candidate is always an unacknowledged torn
//!   commit (model I1-I3). Media corruption (bit rot) inside the NEWEST
//!   commit's table, checksum extents, or delta-manifested chunks is
//!   indistinguishable from such tearing, so recovery silently rolls back
//!   that one commit instead of failing loudly — a warn-level event is the
//!   only signal, emitted before zeroing destroys the evidence. Corruption
//!   in any OLDER commit's state has no such window: it surfaces as a loud
//!   [`crate::Error::BlobCorrupt`] at hydration or read.
//! - Repairs (shadow splices + slot zeroing) are idempotent and re-run on a
//!   crash during recovery.

use super::{
    alloc::{block_align, Allocator, Extent},
    core::{chunk_of, read_blocks, write_blocks, BlobInner, Ready, RunMeta, State},
    layout::{Entry, Superblock, Table},
    Config, BLOCK,
};
use crate::{Blob as _, BufferPool, Error};
use commonware_cryptography::Crc32;
use commonware_utils::sync::{AsyncMutex, Mutex};
use std::collections::BTreeMap;

/// Read one superblock slot, if valid.
async fn read_slot<B: crate::Blob>(
    file: &B,
    len: u64,
    slot: u8,
) -> Result<Option<Superblock>, Error> {
    let offset = Superblock::slot_offset(slot);
    if offset + BLOCK > len {
        return Ok(None);
    }
    let bytes = read_blocks(file, offset, Superblock::SIZE).await?;
    Ok(Superblock::decode(bytes.as_ref()))
}

/// Read and bind a superblock's table.
async fn read_table<B: crate::Blob>(
    file: &B,
    len: u64,
    sb: &Superblock,
) -> Result<Option<Table>, Error> {
    // Table extents are block-aligned allocations; an unaligned offset is
    // as invalid as an unbound one.
    if !sb.table_offset.is_multiple_of(BLOCK) {
        return Ok(None);
    }
    let end = sb
        .table_offset
        .checked_add(block_align(sb.table_len as u64));
    match end {
        Some(end) if end <= len => {}
        _ => return Ok(None),
    }
    let bytes = read_blocks(file, sb.table_offset, sb.table_len as usize).await?;
    if Crc32::checksum(bytes.as_ref()) != sb.table_crc {
        return Ok(None);
    }
    Ok(Table::decode(bytes.as_ref()))
}

/// Locate the backed span of `chunk` in a table entry.
fn entry_chunk_span(entry: &Entry, chunk: u64) -> Option<(u64, u64)> {
    let chunk_start = chunk * BLOCK;
    let run = entry
        .runs
        .iter()
        .rev()
        .find(|r| r.logical <= chunk_start && chunk_start < r.logical + r.len)?;
    let span = (run.logical + run.len - chunk_start).min(BLOCK);
    Some((run.physical + (chunk_start - run.logical), span))
}

/// The last backed chunk of an entry.
fn entry_last_chunk(entry: &Entry) -> Option<u64> {
    entry.runs.last().map(|r| chunk_of(r.logical + r.len - 1))
}

/// Look up the expected CRC of `chunk` from an entry's checksum extents
/// (loading + verifying the covering extent), with the frontier chunk served
/// from `tail_crc`.
struct ChecksumIndex {
    /// (first_chunk, crcs) per loaded extent.
    loaded: Vec<(u64, Vec<u32>)>,
}

impl ChecksumIndex {
    /// `len` bounds candidate verification: an extent that is unaligned or
    /// reaches past the file end never landed (`Ok(None)`). Pass `u64::MAX`
    /// for committed entries, whose extents are known in bounds.
    async fn load<B: crate::Blob>(
        file: &B,
        entry: &Entry,
        len: u64,
    ) -> Result<Option<Self>, Error> {
        let mut loaded = Vec::new();
        for r in &entry.checksums {
            let end = r
                .offset
                .checked_add(block_align(r.count as u64 * 4))
                .filter(|_| r.offset.is_multiple_of(BLOCK));
            match end {
                Some(end) if end <= len => {}
                _ => return Ok(None),
            }
            let bytes = read_blocks(file, r.offset, r.count as usize * 4).await?;
            if Crc32::checksum(bytes.as_ref()) != r.crc {
                return Ok(None);
            }
            let crcs = bytes
                .as_ref()
                .chunks_exact(4)
                .map(|c| u32::from_be_bytes(c.try_into().unwrap()))
                .collect();
            loaded.push((r.first_chunk, crcs));
        }
        Ok(Some(Self { loaded }))
    }

    fn get(&self, chunk: u64) -> Option<u32> {
        for (first, crcs) in &self.loaded {
            if chunk >= *first && chunk < first + crcs.len() as u64 {
                return Some(crcs[(chunk - first) as usize]);
            }
        }
        None
    }
}

/// Verify a candidate table's delta manifest against the disk.
async fn verify_manifest<B: crate::Blob>(file: &B, len: u64, table: &Table) -> Result<bool, Error> {
    // Load + verify the checksum extents of every manifested blob up front.
    let mut indexes: BTreeMap<u64, ChecksumIndex> = BTreeMap::new();
    for &(id, _) in &table.manifest {
        let Some(entry) = table.blobs.iter().find(|e| e.id == id) else {
            continue; // blob removed by this commit
        };
        if indexes.contains_key(&id) {
            continue;
        }
        let Some(loaded) = ChecksumIndex::load(file, entry, len).await? else {
            return Ok(false); // torn checksum extent
        };
        indexes.insert(id, loaded);
    }

    for &(id, chunk) in &table.manifest {
        let Some(entry) = table.blobs.iter().find(|e| e.id == id) else {
            continue; // blob removed by this commit
        };
        let Some((phys, span)) = entry_chunk_span(entry, chunk) else {
            continue; // became a hole
        };
        if !phys.is_multiple_of(BLOCK) || phys + BLOCK > len {
            return Ok(false); // backing never landed (or is unaligned)
        }
        let frontier = entry_last_chunk(entry) == Some(chunk) && span < BLOCK;

        // Expected CRC: frontier partial chunks come from the entry itself;
        // others from the checksum extents.
        let expected = if frontier {
            entry.tail_crc
        } else {
            match indexes.get(&id).expect("preloaded").get(chunk) {
                Some(crc) => crc,
                None => return Ok(false),
            }
        };

        // Frontier chunks with a shadow: the shadow is authoritative for the
        // frozen span (the on-disk block may be torn by post-snapshot
        // appends; recovery splices it afterwards).
        if frontier {
            if let Some(shadow) = entry.shadow {
                if !shadow.is_multiple_of(BLOCK) || shadow + BLOCK > len {
                    return Ok(false);
                }
                let bytes = read_blocks(file, shadow, span as usize).await?;
                if Crc32::checksum(bytes.as_ref()) != expected {
                    return Ok(false);
                }
                continue;
            }
        }

        let bytes = read_blocks(file, phys, span as usize).await?;
        if Crc32::checksum(bytes.as_ref()) != expected {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Run recovery over the volume file and build the ready state.
pub(super) async fn recover<S: crate::Storage>(
    inner: &S,
    pool: &BufferPool,
    cfg: &Config,
) -> Result<Ready<S>, Error> {
    let (file, mut len) = inner.open(&cfg.partition, &cfg.name).await?;

    // Slot selection.
    let slot_a = read_slot(&file, len, 0).await?;
    let slot_b = read_slot(&file, len, 1).await?;

    // Fresh volume: no valid slot and nothing beyond the init table block
    // could have been written (see module docs: any volume that ever
    // confirmed a commit has a valid sacred slot; a torn first init leaves
    // at most the init table block populated).
    if slot_a.is_none() && slot_b.is_none() {
        if len > 3 * BLOCK {
            return Err(Error::PartitionCorrupt(format!(
                "{}: no valid volume superblock",
                cfg.partition
            )));
        }
        return init_fresh(inner, pool, cfg).await;
    }

    // Candidate order: higher seq first.
    let mut slots: Vec<(u8, Superblock)> = [(0u8, slot_a), (1u8, slot_b)]
        .into_iter()
        .filter_map(|(s, sb)| sb.map(|sb| (s, sb)))
        .collect();
    slots.sort_by_key(|(_, sb)| std::cmp::Reverse(sb.seq));

    let mut adopted: Option<(u8, Superblock, Table)> = None;
    let mut losing_slot: Option<(u8, u64)> = None;
    for (idx, (slot, sb)) in slots.iter().enumerate() {
        let is_candidate = idx == 0 && slots.len() == 2;
        let table = match read_table(&file, len, sb).await? {
            Some(table) if verify_manifest(&file, len, &table).await? => Some(table),
            _ => None,
        };
        match table {
            Some(table) => {
                adopted = Some((*slot, sb.clone(), table));
                break;
            }
            None if is_candidate => {
                // Torn newest commit: fall back; zero this slot afterwards.
                losing_slot = Some((*slot, sb.seq));
            }
            None => {
                return Err(Error::PartitionCorrupt(format!(
                    "{}: volume commit {} unrecoverable",
                    cfg.partition, sb.seq
                )));
            }
        }
    }
    let Some((slot, sb, table)) = adopted else {
        return Err(Error::PartitionCorrupt(format!(
            "{}: no adoptable volume commit",
            cfg.partition
        )));
    };

    // Repairs: zero the losing slot, splice every partial frontier chunk
    // from its shadow. Idempotent; one sync.
    let mut repaired = false;
    if let Some((losing, losing_seq)) = losing_slot {
        // The one signal an operator gets that the newest commit was
        // discarded: an unacknowledged torn commit is the normal case, but
        // bit rot in the newest commit's metadata looks identical and is
        // rolled back the same way (see the module docs). Zeroing the slot
        // below destroys the on-disk evidence.
        tracing::warn!(
            partition = cfg.partition,
            rejected_seq = losing_seq,
            adopted_seq = sb.seq,
            "newest volume commit failed verification: falling back one commit"
        );
        write_blocks(
            &file,
            pool,
            Superblock::slot_offset(losing),
            &[0u8; Superblock::SIZE],
        )
        .await?;
        repaired = true;
    }
    for entry in &table.blobs {
        let Some(last) = entry_last_chunk(entry) else {
            continue;
        };
        let Some((phys, span)) = entry_chunk_span(entry, last) else {
            continue;
        };
        let Some(shadow) = entry.shadow else { continue };
        if span == BLOCK {
            continue;
        }
        let bytes = read_blocks(&file, shadow, span as usize).await?;
        write_blocks(&file, pool, phys, bytes.as_ref()).await?;
        repaired = true;
        len = len.max(phys + BLOCK);
    }
    if repaired {
        file.sync().await?;
    }

    // Rebuild RAM state from the adopted table.
    let mut used: Vec<Extent> = vec![Extent {
        offset: sb.table_offset,
        len: block_align(sb.table_len as u64),
    }];
    let mut partitions: BTreeMap<String, BTreeMap<Vec<u8>, u64>> = BTreeMap::new();
    for p in &table.partitions {
        partitions.insert(p.clone(), BTreeMap::new());
    }
    let mut dormant = BTreeMap::new();
    let mut committed_meta = BTreeMap::new();
    for entry in &table.blobs {
        let partition = table
            .partitions
            .get(entry.partition as usize)
            .ok_or_else(|| {
                Error::PartitionCorrupt(format!("{}: bad partition index", cfg.partition))
            })?;
        partitions
            .get_mut(partition)
            .expect("partition exists")
            .insert(entry.name.clone(), entry.id);
        let mut meta = Vec::new();
        for r in &entry.runs {
            used.push(Extent {
                offset: r.physical,
                len: block_align(r.len),
            });
        }
        for c in &entry.checksums {
            let extent = Extent {
                offset: c.offset,
                len: block_align(c.count as u64 * 4),
            };
            used.push(extent);
            meta.push(extent);
        }
        if let Some(shadow) = entry.shadow {
            let extent = Extent {
                offset: shadow,
                len: BLOCK,
            };
            used.push(extent);
            meta.push(extent);
        }
        committed_meta.insert(entry.id, meta);
        dormant.insert(entry.id, (partition.clone(), entry.clone()));
    }

    let state = State {
        partitions,
        open: BTreeMap::new(),
        handles: BTreeMap::new(),
        dormant,
        alloc: Allocator::rebuild(2 * BLOCK, used),
        pending_free: Vec::new(),
        seq: table.seq + 1,
        snapshot_seq: table.seq,
        confirmed_seq: table.seq,
        sacred_slot: slot,
        table_extent: Some(Extent {
            offset: sb.table_offset,
            len: block_align(sb.table_len as u64),
        }),
        committed_meta,
        next_id: table.next_id,
        dirty: Default::default(),
        meta_dirty: false,
        groups: Vec::new(),
        encoded: Default::default(),
        partition_epoch: 0,
        encoded_epoch: 0,
        provisioned: len,
    };

    Ok(Ready {
        file,
        state: Mutex::new(state),
        commit_lock: AsyncMutex::new(()),
        poisoned: Default::default(),
        pool: pool.clone(),
        growth_quantum: cfg.growth_quantum,
        provision_lock: AsyncMutex::new(()),
    })
}

/// First init: write the empty table, sync, then the seq-0 superblock, sync.
/// Two syncs so a valid slot always implies a readable table (a single-sync
/// init could land the superblock while tearing the table, and with one slot
/// there is no fallback).
async fn init_fresh<S: crate::Storage>(
    inner: &S,
    pool: &BufferPool,
    cfg: &Config,
) -> Result<Ready<S>, Error> {
    let (file, _) = inner.open(&cfg.partition, &cfg.name).await?;
    let table = Table::default();
    let bytes = table.encode();
    let table_offset = 2 * BLOCK;
    write_blocks(&file, pool, table_offset, &bytes).await?;
    file.sync().await?;
    let sb = Superblock {
        seq: 0,
        table_offset,
        table_len: bytes.len() as u32,
        table_crc: Crc32::checksum(&bytes),
    };
    write_blocks(&file, pool, Superblock::slot_offset(0), &sb.encode()).await?;
    file.sync().await?;

    let table_extent = Extent {
        offset: table_offset,
        len: block_align(bytes.len() as u64),
    };
    let state = State {
        partitions: BTreeMap::new(),
        open: BTreeMap::new(),
        handles: BTreeMap::new(),
        dormant: BTreeMap::new(),
        alloc: Allocator::rebuild(2 * BLOCK, [table_extent]),
        pending_free: Vec::new(),
        seq: 1,
        snapshot_seq: 0,
        confirmed_seq: 0,
        sacred_slot: 0,
        table_extent: Some(table_extent),
        committed_meta: BTreeMap::new(),
        next_id: 0,
        dirty: Default::default(),
        meta_dirty: false,
        groups: Vec::new(),
        encoded: Default::default(),
        partition_epoch: 0,
        encoded_epoch: 0,
        provisioned: 2 * BLOCK + block_align(bytes.len() as u64),
    };
    Ok(Ready {
        file,
        state: Mutex::new(state),
        commit_lock: AsyncMutex::new(()),
        poisoned: Default::default(),
        pool: pool.clone(),
        growth_quantum: cfg.growth_quantum,
        provision_lock: AsyncMutex::new(()),
    })
}

/// Hydrate a dormant entry into live blob state (chunk CRCs + tail buffer),
/// verifying what it loads.
pub(super) async fn hydrate<S: crate::Storage>(
    ready: &Ready<S>,
    entry: &Entry,
    partition: &str,
) -> Result<BlobInner, Error> {
    let mut inner = BlobInner {
        size: entry.size,
        freeze_size: entry.size,
        shadow: entry.shadow,
        committed_entry: Some(entry.clone()),
        ..Default::default()
    };
    for r in &entry.runs {
        inner.runs.insert(
            r.logical,
            RunMeta {
                physical: r.physical,
                len: r.len,
                capacity: block_align(r.len),
                born: 0,
            },
        );
    }
    // Load + verify chunk CRCs (committed extents: no length bound).
    let index = ChecksumIndex::load(&ready.file, entry, u64::MAX)
        .await?
        .ok_or_else(|| {
            Error::BlobCorrupt(
                partition.into(),
                commonware_formatting::hex(&entry.name),
                "checksum extent mismatch".into(),
            )
        })?;
    if let Some(last) = entry_last_chunk(entry) {
        for chunk in 0..=last {
            let Some((_, span)) = entry_chunk_span(entry, chunk) else {
                continue; // hole
            };
            let crc = if chunk == last && span < BLOCK {
                entry.tail_crc
            } else {
                index.get(chunk).ok_or_else(|| {
                    Error::BlobCorrupt(
                        partition.into(),
                        commonware_formatting::hex(&entry.name),
                        format!("missing checksum for chunk {chunk}"),
                    )
                })?
            };
            inner.crcs.insert(chunk, crc);
        }
        // Load + verify the frontier span into the tail buffer.
        let (phys, span) = entry_chunk_span(entry, last).unwrap();
        let bytes = read_blocks(&ready.file, phys, span as usize).await?;
        let expected = inner.crcs.get(&last).copied().unwrap();
        if Crc32::checksum(bytes.as_ref()) != expected {
            return Err(Error::BlobCorrupt(
                partition.into(),
                commonware_formatting::hex(&entry.name),
                "frontier chunk checksum mismatch".into(),
            ));
        }
        inner.tail_chunk = last;
        inner.tail = bytes.as_ref().to_vec();
    }
    Ok(inner)
}
