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
//!   commit's table or the extents its manifest verification reads — the
//!   manifested chunks, their shadow and checksum extents, plus each
//!   manifested entry's LAST checksum ref, which is loaded unconditionally
//!   even when it predates the candidate — is indistinguishable from such
//!   tearing, so recovery silently rolls back that one commit instead of
//!   failing loudly — a warn-level event is the only signal, emitted
//!   before zeroing destroys the evidence. The fallback itself needs the
//!   older slot's table extent unrecycled (it is freed when superseded, so
//!   a post-confirmation data write may legally reuse it): otherwise rot
//!   in the newest table surfaces as a loud
//!   [`crate::Error::PartitionCorrupt`]. Corruption in any OLDER commit's
//!   state that the manifest does not consult has no such window: it
//!   surfaces as a loud [`crate::Error::BlobCorrupt`] at hydration or
//!   read.
//! - Repairs (shadow splices + slot zeroing) are idempotent and re-run on a
//!   crash during recovery.

use super::{
    alloc::{block_align, Allocator, Extent},
    chunk::{chunk_of, merge_frozen_runs, ChunkCrc, ChunkState, RunMeta},
    layout::{ChecksumRef, Entry, Superblock, Table},
    paging::{decode_crcs, window_value},
    state::{BlobInner, CommittedMeta, Ready, State},
    Config, BLOCK,
};
use crate::{telemetry::metrics::GaugeExt as _, Blob as _, BufferPool, Error, IoBuf};
use commonware_cryptography::{Crc32, Hasher as _};
use commonware_utils::sync::{AsyncMutex, Mutex};
use futures::{stream, StreamExt as _};
use std::collections::BTreeMap;

/// Read one superblock slot, if valid.
async fn read_slot<B: crate::Blob>(
    file: &B,
    len: u64,
    slot: u8,
) -> Result<Option<Superblock>, Error> {
    let offset = Superblock::slot_offset(slot);
    if offset + Superblock::SIZE as u64 > len {
        return Ok(None);
    }
    let bytes = file.read_at(offset, Superblock::SIZE).await?.coalesce();
    Ok(Superblock::decode(bytes.as_ref()))
}

/// Read and bind a superblock's table.
async fn read_table<B: crate::Blob>(
    file: &B,
    len: u64,
    sb: &Superblock,
) -> Result<Option<Table>, Error> {
    let end = sb.table_offset.checked_add(sb.table_len as u64);
    match end {
        Some(end) if end <= len => {}
        _ => return Ok(None),
    }
    let bytes = file
        .read_at(sb.table_offset, sb.table_len as usize)
        .await?
        .coalesce();
    if Crc32::checksum(bytes.as_ref()) != sb.table_crc {
        return Ok(None);
    }
    Ok(Table::decode(bytes.as_ref()))
}

/// Locate the backed span of `chunk` in a table entry.
///
/// Runs are disjoint and sorted by logical start, so the only candidate is
/// the last run at or below the chunk. Binary search: manifest
/// verification resolves every manifested chunk through this, and a
/// hole-heavy blob (one run per isolated block) would otherwise make
/// startup O(runs x manifested chunks).
fn entry_chunk_span(entry: &Entry, chunk: u64) -> Option<(u64, u64)> {
    let chunk_start = chunk * BLOCK;
    let i = entry.runs.partition_point(|r| r.logical <= chunk_start);
    let run = &entry.runs[i.checked_sub(1)?];
    if chunk_start >= run.logical + run.len {
        return None;
    }
    let span = (run.logical + run.len - chunk_start).min(BLOCK);
    Some((run.physical + (chunk_start - run.logical), span))
}

/// The last backed chunk of an entry.
fn entry_last_chunk(entry: &Entry) -> Option<u64> {
    entry.runs.last().map(|r| chunk_of(r.logical + r.len - 1))
}

/// Bound on concurrently in-flight manifest-verification reads.
const VERIFY_CONCURRENCY: usize = 16;

/// Cap on one coalesced manifest-verification read.
const VERIFY_READ_SPAN: u64 = 1 << 20;

/// Load the value windows of committed checksum extent `r` named by
/// `windows` (`[w0, w1)` value-index ranges within the ref, ascending and
/// disjoint), verifying the extent's guard CRC by streaming its bytes once
/// in bounded steps. `None` means the guard did not match (torn extent).
///
/// The guard must hold over the WHOLE extent even though the manifest
/// consults only the windows: a torn full-rewrite extent would otherwise
/// pass verification wherever the manifest does not reach, adopting a
/// table that vouches for values that never landed — and a pure power-loss
/// history would then surface as read-time corruption (first reads
/// re-check the guard, see `paging::load_committed_page`) instead of the
/// mandated one-commit rollback.
async fn load_ref_windows<B: crate::Blob>(
    file: &B,
    r: &ChecksumRef,
    windows: &[(u64, u64)],
) -> Result<Option<Vec<(u64, Vec<u32>)>>, Error> {
    /// Streaming step for guard verification of large extents.
    const STEP: u64 = 1 << 22;
    let mut hasher = Crc32::new();
    let mut out: Vec<(u64, Vec<u32>)> = windows
        .iter()
        .map(|&(w0, w1)| (r.first_chunk + w0, Vec::with_capacity((w1 - w0) as usize)))
        .collect();
    let total = r.count as u64 * 4;
    let mut pos = 0;
    while pos < total {
        let step = STEP.min(total - pos);
        let bytes = file
            .read_at(r.offset + pos, step as usize)
            .await?
            .coalesce();
        hasher.update(bytes.as_ref());
        // Capture each window's intersection with this step.
        for (&(w0, w1), (_, values)) in windows.iter().zip(out.iter_mut()) {
            let lo = (w0 * 4).max(pos);
            let hi = (w1 * 4).min(pos + step);
            if hi > lo {
                values.extend(decode_crcs(
                    &bytes.as_ref()[(lo - pos) as usize..(hi - pos) as usize],
                ));
            }
        }
        pos += step;
    }
    Ok((hasher.finalize().as_u32() == r.crc).then_some(out))
}

/// One chunk's CRC check within a coalesced verification read.
struct Check {
    /// Span offset within the read.
    at: usize,
    /// Span length in bytes.
    span: u64,
    /// Expected CRC32C over the span.
    expected: u32,
    /// (blob id, chunk) to seed as recovery-verified when the check passes.
    /// `None` for frontier chunks, which hydration re-verifies itself.
    seed: Option<(u64, u64)>,
}

/// One coalesced verification read: physically contiguous manifested spans
/// checked from a single inner read.
struct VerifyRead {
    physical: u64,
    len: u64,
    checks: Vec<Check>,
}

/// Verify a candidate table's delta manifest against the disk.
///
/// On success, returns the non-frontier chunks whose ON-DISK bytes this
/// verification CRC-checked, as (blob id, chunk) pairs: hydration seeds
/// their verified bits so first reads skip re-verification (frontier chunks
/// are excluded — hydration re-verifies the frontier itself when it loads
/// the tail buffer). `None` means the manifest failed to verify.
///
/// A manifested frontier chunk with a shadow is checked by reading the
/// SHADOW's bytes against `tail_crc` — and every capture that writes a
/// fresh shadow manifests its frontier chunk, so a commit whose shadow
/// write tore is rejected here rather than spliced (the repair splice
/// below is a raw byte copy that cannot tell a torn shadow from a valid
/// one). Uncaptured entries' shadows are old durable extents and always
/// pass on crash histories.
///
/// Expected CRCs load lazily: only the value windows covering manifested
/// chunks are retained (not whole checksum arrays), and the only refs
/// read are those covering a manifested chunk plus each entry's LAST ref
/// (the one extent the candidate commit may have written, hence torn).
/// Every skipped ref was already referenced by the previous confirmed
/// commit, whose fsync made it durable — tearing strikes only blocks the
/// candidate commit wrote — so skipping its guard check trades nothing on
/// crash histories (bit rot in it surfaces loudly at first read instead
/// of rolling back the newest commit, see the module docs). The LAST ref
/// can itself predate the candidate (a capture whose dirt is confined to
/// the partial frontier appends no ref): its guard check cannot fail on
/// crash histories either, but rot in it rolls the candidate back — the
/// documented exception covers each manifested entry's last ref even when
/// an older commit wrote it. Adjacent manifested chunks coalesce into
/// single reads, issued with bounded concurrency so CRC work overlaps
/// I/O.
async fn verify_manifest<B: crate::Blob>(
    file: &B,
    len: u64,
    table: &Table,
) -> Result<Option<Vec<(u64, u64)>>, Error> {
    // The manifest's order is untrusted input: sort per (blob, chunk) so
    // window and read coalescing below see ascending chunks.
    let mut manifest = table.manifest.clone();
    manifest.sort_unstable();
    manifest.dedup();

    // Table entries are written in id order, but decode does not enforce
    // it: index by id once so the per-group lookup below stays cheap after
    // a large coalesced commit (a scan per group is O(manifested blobs x
    // total blobs) on the open path).
    let entries: BTreeMap<u64, &Entry> = table.blobs.iter().map(|e| (e.id, e)).collect();

    // Plan the verification reads per blob: resolve every manifested chunk
    // to its backed span and expected CRC, coalescing physically contiguous
    // spans into single reads.
    let mut reads: Vec<VerifyRead> = Vec::new();
    for group in manifest.chunk_by(|a, b| a.0 == b.0) {
        let id = group[0].0;
        let Some(&entry) = entries.get(&id) else {
            continue; // blob removed by this commit
        };
        // An extent that reaches past the file end never landed (arithmetic
        // only; unread refs cost no I/O).
        for r in &entry.checksums {
            match r.offset.checked_add(r.count as u64 * 4) {
                Some(end) if end <= len => {}
                _ => return Ok(None),
            }
        }

        // Resolve each chunk's span; frontier partial chunks are served by
        // `tail_crc`, everything else needs its committed value.
        let last_chunk = entry_last_chunk(entry);
        let mut spans: Vec<(u64, u64, u64, bool)> = Vec::with_capacity(group.len());
        let mut need_value: Vec<u64> = Vec::new();
        for &(_, chunk) in group {
            let Some((phys, span)) = entry_chunk_span(entry, chunk) else {
                continue; // became a hole
            };
            // Backing past the file end never landed: reject. For a
            // manifested frontier chunk with a shadow this is deliberately
            // stricter than the abstract model, which adopts (the shadow
            // is authoritative for a missing tail block). Rejecting rolls
            // back one unacknowledged commit, which is always legal.
            if phys + span > len {
                return Ok(None);
            }
            let frontier = last_chunk == Some(chunk) && span < BLOCK;
            if !frontier {
                need_value.push(chunk);
            }
            spans.push((chunk, phys, span, frontier));
        }

        // Group the needed value windows by covering ref (coalescing
        // contiguous chunks: manifests from bulk loads are dense ranges).
        // A chunk outside every ref's coverage means the refs never landed.
        let mut per_ref: Vec<Vec<(u64, u64)>> = vec![Vec::new(); entry.checksums.len()];
        let mut ref_idx = 0;
        for &chunk in &need_value {
            while entry
                .checksums
                .get(ref_idx)
                .is_some_and(|r| chunk >= r.first_chunk + r.count as u64)
            {
                ref_idx += 1;
            }
            let covering = entry
                .checksums
                .get(ref_idx)
                .filter(|r| r.first_chunk <= chunk && chunk < r.first_chunk + r.count as u64);
            let Some(r) = covering else {
                return Ok(None); // manifested chunk without a committed CRC
            };
            let w = chunk - r.first_chunk;
            let windows = &mut per_ref[ref_idx];
            match windows.last_mut() {
                Some((_, w1)) if *w1 == w => *w1 = w + 1,
                _ => windows.push((w, w + 1)),
            }
        }

        // Load every ref a manifested chunk needs, plus the LAST ref
        // unconditionally: a commit adds at most one new checksum ref and
        // always as the entry's last (delta commits append one, a full
        // rewrite is the sole ref), so the last ref is exactly the extent
        // this commit may have torn — and it may cover no manifested chunk
        // at all (dirt confined to the partial frontier, or delta coverage
        // over holes).
        let mut loaded: Vec<(u64, Vec<u32>)> = Vec::new();
        for (i, windows) in per_ref.iter().enumerate() {
            if windows.is_empty() && i + 1 != entry.checksums.len() {
                continue;
            }
            let r = &entry.checksums[i];
            let Some(mut got) = load_ref_windows(file, r, windows).await? else {
                return Ok(None); // torn checksum extent
            };
            loaded.append(&mut got);
        }

        for (chunk, phys, span, frontier) in spans {
            let expected = if frontier {
                entry.tail_crc
            } else {
                window_value(&loaded, chunk).expect("loaded above")
            };
            // Frontier chunks with a shadow: the shadow is authoritative
            // for the frozen span (the on-disk block may be torn by
            // post-snapshot appends; recovery splices it afterwards).
            let physical = if frontier {
                match entry.shadow {
                    Some(shadow) => {
                        if shadow + span > len {
                            return Ok(None);
                        }
                        shadow
                    }
                    None => phys,
                }
            } else {
                phys
            };
            let check = Check {
                at: 0,
                span,
                expected,
                seed: (!frontier).then_some((id, chunk)),
            };
            match reads.last_mut() {
                Some(read)
                    if read.physical + read.len == physical
                        && read.len + span <= VERIFY_READ_SPAN =>
                {
                    read.checks.push(Check {
                        at: read.len as usize,
                        ..check
                    });
                    read.len += span;
                }
                _ => reads.push(VerifyRead {
                    physical,
                    len: span,
                    checks: vec![check],
                }),
            }
        }
    }

    // Execute the reads with bounded concurrency, overlapping CRC work
    // with in-flight I/O. `buffered` keeps results in plan order, so the
    // returned chunk list is schedule-independent.
    let mut verified = Vec::new();
    let mut outcomes = stream::iter(reads.into_iter().map(|read| async move {
        let bytes = file
            .read_at(read.physical, read.len as usize)
            .await?
            .coalesce();
        for check in &read.checks {
            let span = &bytes.as_ref()[check.at..check.at + check.span as usize];
            if Crc32::checksum(span) != check.expected {
                return Ok(None);
            }
        }
        Ok::<_, Error>(Some(read.checks))
    }))
    .buffered(VERIFY_CONCURRENCY);
    while let Some(outcome) = outcomes.next().await {
        let Some(checks) = outcome? else {
            return Ok(None);
        };
        verified.extend(checks.into_iter().filter_map(|check| check.seed));
    }
    Ok(Some(verified))
}

/// Run recovery over the volume file and build the ready state.
pub(super) async fn recover<S: crate::Storage>(
    inner: &S,
    pool: &BufferPool,
    cfg: &Config,
    driver: super::Driver,
    metrics: std::sync::Arc<super::metrics::Metrics>,
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
        return init_fresh(inner, pool, cfg, driver, metrics).await;
    }

    // Candidate order: higher seq first.
    let mut slots: Vec<(u8, Superblock)> = [(0u8, slot_a), (1u8, slot_b)]
        .into_iter()
        .filter_map(|(s, sb)| sb.map(|sb| (s, sb)))
        .collect();
    slots.sort_by_key(|(_, sb)| std::cmp::Reverse(sb.seq));

    let mut adopted: Option<(u8, Superblock, Table)> = None;
    let mut losing_slot: Option<(u8, u64)> = None;
    // Chunks the adopted slot's manifest verification CRC-checked on disk,
    // seeded into hydration so first reads skip re-verification.
    let mut recovery_verified: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for (idx, (slot, sb)) in slots.iter().enumerate() {
        let is_candidate = idx == 0 && slots.len() == 2;
        let table = match read_table(&file, len, sb).await? {
            Some(table) => verify_manifest(&file, len, &table)
                .await?
                .map(|verified| (table, verified)),
            None => None,
        };
        match table {
            Some((table, verified)) => {
                for (id, chunk) in verified {
                    recovery_verified.entry(id).or_default().push(chunk);
                }
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
    let mut spliced_shadows = 0usize;
    if let Some((losing, losing_seq)) = losing_slot {
        // The one signal an operator gets that the newest commit was
        // discarded: an unacknowledged torn commit is the normal case, but
        // bit rot in the newest commit's metadata looks identical and is
        // rolled back the same way (see the module docs). Zeroing the slot
        // below destroys the on-disk evidence.
        metrics.recovery_fallbacks.inc();
        let _ = metrics.rolled_back_seq.try_set(losing_seq);
        tracing::warn!(
            partition = cfg.partition,
            rejected_seq = losing_seq,
            adopted_seq = sb.seq,
            "newest volume commit failed verification: falling back one commit"
        );
        file.write_at(
            Superblock::slot_offset(losing),
            IoBuf::copy_from_slice(&[0u8; Superblock::SIZE]),
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
        let bytes = file.read_at(shadow, span as usize).await?.coalesce();
        file.write_at(phys, bytes).await?;
        repaired = true;
        spliced_shadows += 1;
        len = len.max(phys + span);
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
        let mut meta = CommittedMeta::default();
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
            meta.checksums.push(extent);
        }
        if let Some(shadow) = entry.shadow {
            let extent = Extent {
                offset: shadow,
                len: BLOCK,
            };
            used.push(extent);
            meta.shadow = Some(extent);
        }
        committed_meta.insert(entry.id, meta);
        dormant.insert(entry.id, (partition.clone(), entry.clone()));
    }

    metrics.recoveries.inc();
    tracing::info!(
        partition = cfg.partition,
        adopted_seq = sb.seq,
        blobs = table.blobs.len(),
        verified_chunks = recovery_verified.values().map(Vec::len).sum::<usize>(),
        spliced_shadows,
        fell_back = losing_slot.is_some(),
        "volume recovered"
    );
    let mut state = State {
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
        recovery_verified,
        next_id: table.next_id,
        dirty: Default::default(),
        meta_dirty: false,
        groups: Vec::new(),
        encoded: Default::default(),
        partition_epoch: 0,
        encoded_epoch: 0,
        provisioned: len,
        file_high_water: 0,
    };
    metrics.observe_state(&mut state);

    Ok(Ready {
        file,
        driver,
        metrics,
        state: Mutex::new(state),
        commit_lock: AsyncMutex::new(()),
        pending: Default::default(),
        poisoned: Default::default(),
        pool: pool.clone(),
        // Deliver the Config doc's promise: round the configured step
        // up to whole blocks.
        growth_quantum: block_align(cfg.growth_quantum),
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
    driver: super::Driver,
    metrics: std::sync::Arc<super::metrics::Metrics>,
) -> Result<Ready<S>, Error> {
    let (file, _) = inner.open(&cfg.partition, &cfg.name).await?;
    let table = Table::default();
    let bytes = table.encode();
    let table_offset = 2 * BLOCK;
    file.write_at(table_offset, IoBuf::copy_from_slice(&bytes))
        .await?;
    file.sync().await?;
    let sb = Superblock {
        seq: 0,
        table_offset,
        table_len: bytes.len() as u32,
        table_crc: Crc32::checksum(&bytes),
    };
    file.write_at(
        Superblock::slot_offset(0),
        IoBuf::copy_from_slice(&sb.encode()),
    )
    .await?;
    file.sync().await?;

    let table_extent = Extent {
        offset: table_offset,
        len: block_align(bytes.len() as u64),
    };
    let mut state = State {
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
        recovery_verified: BTreeMap::new(),
        next_id: 0,
        dirty: Default::default(),
        meta_dirty: false,
        groups: Vec::new(),
        encoded: Default::default(),
        partition_epoch: 0,
        encoded_epoch: 0,
        provisioned: 2 * BLOCK + block_align(bytes.len() as u64),
        file_high_water: 0,
    };
    metrics.recoveries.inc();
    metrics.observe_state(&mut state);
    Ok(Ready {
        file,
        driver,
        metrics,
        state: Mutex::new(state),
        commit_lock: AsyncMutex::new(()),
        pending: Default::default(),
        poisoned: Default::default(),
        pool: pool.clone(),
        // Deliver the Config doc's promise: round the configured step
        // up to whole blocks.
        growth_quantum: block_align(cfg.growth_quantum),
        provision_lock: AsyncMutex::new(()),
    })
}

/// Hydrate a dormant entry into live blob state (dense chunk state + tail
/// buffer), verifying what it loads.
///
/// Hydration is O(runs + chunks/64): it seeds the dense chunk state (all
/// unverified, CRCs left on disk) and reads only the frontier span. CRC
/// values are loaded on demand from the committed checksum extents when a
/// read first verifies a chunk (see `paging::load_committed_page`), so an
/// open multi-TiB blob holds bitmaps, not its checksum array.
pub(super) async fn hydrate<S: crate::Storage>(
    ready: &Ready<S>,
    entry: &Entry,
    partition: &str,
) -> Result<BlobInner, Error> {
    let corrupt = |msg: &str| {
        Error::BlobCorrupt(
            partition.into(),
            commonware_formatting::hex(&entry.name),
            msg.into(),
        )
    };
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
    // Recovered runs are all frozen (born 0): coalesce contiguous
    // neighbors. A no-op for entries captured after a merging pass, but an
    // entry captured while a batch held staged state for its blob (which
    // gates capture-time merging) can still carry mergeable runs.
    merge_frozen_runs(&mut inner.runs);
    // Seed the dense chunk state from the merged runs: every backed chunk
    // unverified with its CRC left on disk.
    inner.crcs.seed(&inner.runs);

    if let Some(last) = entry_last_chunk(entry) {
        let (phys, span) = entry_chunk_span(entry, last).expect("last chunk is backed");
        // The refs must cover every backed chunk below the frontier (plus
        // a full frontier chunk) contiguously from chunk 0 — the invariant
        // capture maintains and the committed-CRC loader relies on.
        // Validating it here keeps a corrupt-but-CRC-bound table a loud
        // open error instead of a read-path panic.
        let covered_end = if span == BLOCK { last + 1 } else { last };
        let mut next = 0;
        for r in &entry.checksums {
            if r.first_chunk != next {
                return Err(corrupt("checksum refs not contiguous"));
            }
            next += r.count as u64;
        }
        if next != covered_end {
            return Err(corrupt("checksum coverage mismatch"));
        }

        // Chunks recovery itself CRC-checked while verifying the adopted
        // commit's delta manifest hydrate verified: their on-disk bytes are
        // known to match the committed CRCs (nothing can write a dormant
        // blob between recovery and hydration), so first reads skip
        // re-verification.
        let seeded = ready.state.lock().recovery_verified.remove(&entry.id);
        for chunk in seeded.into_iter().flatten() {
            inner.crcs.set_verified(chunk);
        }

        // Load + verify the frontier span into the tail buffer. Capture
        // records the final backed chunk's CRC in `tail_crc` whether the
        // chunk is full or partial, so the check touches no checksum
        // extent.
        let bytes = ready.file.read_at(phys, span as usize).await?.coalesce();
        if Crc32::checksum(bytes.as_ref()) != entry.tail_crc {
            ready.metrics.corruptions.inc();
            return Err(corrupt(&format!(
                "frontier chunk {last} checksum mismatch ({span} bytes at offset {phys})"
            )));
        }
        // Hydration itself verified the frontier chunk (and holds its CRC).
        inner.crcs.insert(
            last,
            ChunkState {
                crc: ChunkCrc::Ready(entry.tail_crc),
                verified: true,
            },
        );
        inner.tail_chunk = last;
        inner.tail = bytes.as_ref().to_vec();
    } else if !entry.checksums.is_empty() {
        // No backed chunks: capture emits no refs.
        return Err(corrupt("checksum refs without backed chunks"));
    }
    Ok(inner)
}
