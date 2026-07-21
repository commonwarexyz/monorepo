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
    alloc::{block_align, checked_block_align, Allocator, Extent},
    chunk::{chunk_of, ChunkCrc, ChunkState},
    layout::{ChecksumRef, Entry, Slot, Superblock, Table},
    paging::{stream_ref_windows, window_value},
    state::{BlobInner, Genesis, Ready, State},
    Config, BLOCK,
};
use crate::{telemetry::metrics::GaugeExt as _, Blob as _, BufferPool, Error, IoBuf};
use commonware_cryptography::Crc32;
use commonware_utils::sync::{AsyncMutex, Mutex};
use futures::{stream, StreamExt as _};
use std::collections::{BTreeMap, BTreeSet};

/// Read one superblock slot, if valid.
async fn read_slot<B: crate::Blob>(
    file: &B,
    len: u64,
    slot: Slot,
) -> Result<Option<Superblock>, Error> {
    let offset = slot.offset();
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
    partition: &str,
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
    Table::decode(bytes.as_ref()).map(Some).ok_or_else(|| {
        Error::PartitionCorrupt(format!(
            "{partition}: volume commit {} has an invalid table encoding",
            sb.seq
        ))
    })
}

/// A CRC-bound table whose complete semantic and extent geometry has passed
/// [`validate_table`]. Manifest verification accepts only this state, so
/// hostile decoded bytes cannot bypass validation on the path to adoption.
struct ValidatedTable(Table);

impl ValidatedTable {
    const fn as_table(&self) -> &Table {
        &self.0
    }

    fn into_inner(self) -> Table {
        self.0
    }
}

/// A validated table whose manifest and newly referenced checksum metadata
/// were verified against disk, making it eligible for adoption.
struct AdoptableTable {
    table: Table,
    verified_chunks: Vec<(u64, u64)>,
}

/// Validate every semantic invariant recovery and allocator rebuilding rely
/// on before manifest I/O or repair writes. The table CRC authenticates bytes,
/// not their meaning: a CRC-valid hostile table must be rejected as corruption
/// instead of reaching unchecked address arithmetic or allocator assertions.
fn validate_table(
    partition: &str,
    len: u64,
    sb: &Superblock,
    table: Table,
) -> Result<ValidatedTable, Error> {
    let corrupt = |message: String| {
        Error::PartitionCorrupt(format!("{partition}: volume commit {} {message}", sb.seq))
    };
    let invalid = |message: &str| Err(corrupt(message.into()));

    if sb.seq == u64::MAX {
        return invalid("has exhausted its sequence space");
    }
    if table.seq != sb.seq {
        return invalid("has a table sequence mismatch");
    }
    if table.next_id == u64::MAX {
        return invalid("has exhausted its blob id space");
    }

    let table_len = sb.table_len as u64;
    let Some(table_alloc_len) = checked_block_align(table_len) else {
        return invalid("has an overflowing table extent");
    };
    if table_len == 0 || sb.table_offset < 2 * BLOCK || !sb.table_offset.is_multiple_of(BLOCK) {
        return invalid("has an invalid table extent");
    }
    let Some(table_data_end) = sb.table_offset.checked_add(table_len) else {
        return invalid("has an overflowing table extent");
    };
    if table_data_end > len {
        return invalid("has a table extent past the volume end");
    }
    let Some(table_alloc_end) = sb.table_offset.checked_add(table_alloc_len) else {
        return invalid("has an overflowing table extent");
    };

    if table.partitions.windows(2).any(|pair| pair[0] >= pair[1]) {
        return invalid("has duplicate or unordered partitions");
    }
    for name in &table.partitions {
        if super::super::validate_partition_name(name).is_err() {
            return invalid("has an invalid partition name");
        }
    }
    if table.blobs.windows(2).any(|pair| pair[0].id >= pair[1].id) {
        return invalid("has duplicate or unordered blob ids");
    }
    if table
        .blobs
        .last()
        .is_some_and(|entry| entry.id >= table.next_id)
    {
        return invalid("has a blob id outside the allocated id space");
    }
    if table.manifest.windows(2).any(|pair| pair[0] >= pair[1]) {
        return invalid("has duplicate or unordered manifest entries");
    }

    // Allocated extents, including their block-rounded slack. Exact payload
    // bounds are checked as each extent is registered; sorting this list once
    // proves that no run, checksum, shadow, or table allocation aliases any
    // other allocation.
    let mut extents = vec![(sb.table_offset, table_alloc_end, "table".to_string())];
    let mut names = BTreeSet::new();
    for entry in &table.blobs {
        if entry.partition as usize >= table.partitions.len() {
            return invalid("has a blob with an invalid partition index");
        }
        if !names.insert((entry.partition, entry.name.clone())) {
            return invalid("has duplicate blob names in one partition");
        }
        if entry.floor > entry.size {
            return invalid("has a blob floor past its size");
        }
        if entry.checksums.len() > super::commit::MAX_CHECKSUM_REFS {
            return invalid("has too many checksum refs");
        }

        let floor_block = (entry.floor / BLOCK) * BLOCK;
        let mut logical_end = 0u64;
        for (index, run) in entry.runs.iter().enumerate() {
            if run.len == 0
                || !run.logical.is_multiple_of(BLOCK)
                || !run.physical.is_multiple_of(BLOCK)
                || run.physical < 2 * BLOCK
            {
                return invalid("has an invalid run extent");
            }
            let Some(run_logical_end) = run.logical.checked_add(run.len) else {
                return invalid("has an overflowing logical run");
            };
            if run.logical < logical_end
                || run.logical < floor_block
                || run_logical_end > entry.size
            {
                return invalid("has invalid or overlapping logical runs");
            }
            logical_end = run_logical_end;

            let Some(allocated) = checked_block_align(run.len) else {
                return invalid("has an overflowing run extent");
            };
            let Some(end) = run.physical.checked_add(allocated) else {
                return invalid("has an overflowing run extent");
            };
            if run
                .physical
                .checked_add(run.len)
                .is_none_or(|data_end| data_end > len)
            {
                return invalid("has a run extent past the volume end");
            }
            extents.push((run.physical, end, format!("blob {} run {index}", entry.id)));
        }

        let last = entry.runs.last().map(|run| {
            let end = run.logical + run.len; // checked above
            let chunk = (end - 1) / BLOCK;
            let span = end - chunk * BLOCK;
            (chunk, span)
        });
        let floor_chunk = entry.floor / BLOCK;
        let covered_end = last.map_or(
            0,
            |(chunk, span)| {
                if span == BLOCK {
                    chunk + 1
                } else {
                    chunk
                }
            },
        );
        match entry.checksums.first() {
            None if covered_end > floor_chunk => {
                return invalid("has incomplete checksum coverage");
            }
            Some(first) => {
                if first.first_chunk > floor_chunk {
                    return invalid("has checksum coverage above its floor");
                }
                let mut next = first.first_chunk;
                for checksum in &entry.checksums {
                    if checksum.count == 0 || checksum.first_chunk != next {
                        return invalid("has invalid checksum coverage");
                    }
                    let Some(end) = checksum.first_chunk.checked_add(checksum.count as u64) else {
                        return invalid("has overflowing checksum coverage");
                    };
                    next = end;
                    if next <= floor_chunk {
                        return invalid("has checksum coverage wholly below its floor");
                    }
                }
                if next != covered_end {
                    return invalid("has incomplete checksum coverage");
                }
            }
            None => {}
        }
        for (index, checksum) in entry.checksums.iter().enumerate() {
            if !checksum.offset.is_multiple_of(BLOCK) || checksum.offset < 2 * BLOCK {
                return invalid("has an invalid checksum extent");
            }
            let bytes = (checksum.count as u64) * 4;
            let Some(allocated) = checked_block_align(bytes) else {
                return invalid("has an overflowing checksum extent");
            };
            let Some(end) = checksum.offset.checked_add(allocated) else {
                return invalid("has an overflowing checksum extent");
            };
            if checksum
                .offset
                .checked_add(bytes)
                .is_none_or(|data_end| data_end > len)
            {
                return invalid("has a checksum extent past the volume end");
            }
            extents.push((
                checksum.offset,
                end,
                format!("blob {} checksum {index}", entry.id),
            ));
        }

        match last {
            None => {
                if entry.shadow.is_some() {
                    return invalid("has a shadow without backed content");
                }
                if entry.tail_crc != 0 || !entry.checksums.is_empty() {
                    return invalid("has metadata without backed content");
                }
            }
            Some((_, BLOCK)) => {
                if entry.shadow.is_some() {
                    return invalid("has a shadow for a full frontier");
                }
            }
            Some((_, span)) => {
                let Some(shadow) = entry.shadow else {
                    return invalid("has a partial frontier without a shadow");
                };
                if !shadow.is_multiple_of(BLOCK) || shadow < 2 * BLOCK {
                    return invalid("has an invalid shadow extent");
                }
                let Some(end) = shadow.checked_add(BLOCK) else {
                    return invalid("has an overflowing shadow extent");
                };
                if shadow
                    .checked_add(span)
                    .is_none_or(|data_end| data_end > len)
                {
                    return invalid("has a shadow extent past the volume end");
                }
                extents.push((shadow, end, format!("blob {} shadow", entry.id)));
            }
        }
    }

    for &(id, chunk) in &table.manifest {
        if id >= table.next_id || chunk > u64::MAX / BLOCK {
            return invalid("has an invalid manifest entry");
        }
        let Ok(index) = table.blobs.binary_search_by_key(&id, |entry| entry.id) else {
            return invalid("has a manifest entry for an absent blob");
        };
        if chunk >= table.blobs[index].size.div_ceil(BLOCK) {
            return invalid("has a manifest entry past the blob end");
        }
    }

    extents.sort_unstable_by_key(|extent| extent.0);
    for pair in extents.windows(2) {
        if pair[1].0 < pair[0].1 {
            return Err(corrupt(format!(
                "has overlapping {} and {} extents",
                pair[0].2, pair[1].2
            )));
        }
    }
    Ok(ValidatedTable(table))
}

/// Whether one slot's table allocation aliases content retained by the other
/// slot. A legal commit keeps every fallback extent owned until its successor
/// confirms, so table storage can never overlap the other slot's runs,
/// checksum arrays, or shadow. Non-table content may be shared unchanged
/// across consecutive tables and is deliberately not compared here.
fn table_overlaps_content(sb: &Superblock, other: &Table) -> bool {
    let Some(table_end) = checked_block_align(sb.table_len as u64)
        .and_then(|allocated| sb.table_offset.checked_add(allocated))
    else {
        return true;
    };
    let overlaps = |start: u64, end: u64| sb.table_offset < end && start < table_end;

    other.blobs.iter().any(|entry| {
        entry.runs.iter().any(|run| {
            checked_block_align(run.len)
                .and_then(|allocated| run.physical.checked_add(allocated))
                .is_none_or(|end| overlaps(run.physical, end))
        }) || entry.checksums.iter().any(|checksum| {
            checked_block_align((checksum.count as u64) * 4)
                .and_then(|allocated| checksum.offset.checked_add(allocated))
                .is_none_or(|end| overlaps(checksum.offset, end))
        }) || entry.shadow.is_some_and(|shadow| {
            shadow
                .checked_add(BLOCK)
                .is_none_or(|end| overlaps(shadow, end))
        })
    })
}

/// Locate the backed span of `chunk` in a table entry.
///
/// Runs are disjoint and sorted by logical start, so the only candidate is
/// the last run at or below the chunk. Binary search: manifest
/// verification resolves every manifested chunk through this, and a
/// hole-heavy blob (one run per isolated block) would otherwise make
/// startup O(runs x manifested chunks).
fn entry_chunk_span(entry: &Entry, chunk: u64) -> Option<(u64, u64)> {
    let chunk_start = chunk.checked_mul(BLOCK)?;
    let i = entry.runs.partition_point(|r| r.logical <= chunk_start);
    let run = &entry.runs[i.checked_sub(1)?];
    let run_end = run.logical.checked_add(run.len)?;
    if chunk_start >= run_end {
        return None;
    }
    let offset = chunk_start.checked_sub(run.logical)?;
    let physical = run.physical.checked_add(offset)?;
    let span = run_end.checked_sub(chunk_start)?.min(BLOCK);
    Some((physical, span))
}

/// The last backed chunk of an entry.
fn entry_last_chunk(entry: &Entry) -> Option<u64> {
    entry
        .runs
        .last()
        .and_then(|r| r.logical.checked_add(r.len)?.checked_sub(1))
        .map(chunk_of)
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
    let (values, guard) = stream_ref_windows(file, r, windows).await?;
    Ok((guard == r.crc).then(|| {
        windows
            .iter()
            .zip(values)
            .map(|(&(w0, _), v)| (r.first_chunk + w0, v))
            .collect()
    }))
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
    validated: ValidatedTable,
) -> Result<Option<AdoptableTable>, Error> {
    let table = validated.as_table();
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
    Ok(Some(AdoptableTable {
        table: validated.into_inner(),
        verified_chunks: verified,
    }))
}

/// Run recovery over the volume file and build the ready state.
pub(super) async fn recover<S: crate::Storage>(
    inner: &S,
    pool: &BufferPool,
    cfg: &Config,
    driver: super::Driver,
    metrics: std::sync::Arc<super::metrics::Metrics>,
) -> Result<Ready<S>, Error> {
    let growth_quantum = checked_block_align(cfg.growth_quantum).ok_or(Error::OffsetOverflow)?;
    let (file, mut len) = inner.open(&cfg.partition, &cfg.name).await?;

    // Slot selection.
    let slot_a = read_slot(&file, len, Slot::A).await?;
    let slot_b = read_slot(&file, len, Slot::B).await?;

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
        return init_fresh(inner, pool, cfg, driver, metrics, growth_quantum).await;
    }

    // Candidate order: higher seq first.
    let mut slots: Vec<(Slot, Superblock)> = [(Slot::A, slot_a), (Slot::B, slot_b)]
        .into_iter()
        .filter_map(|(s, sb)| sb.map(|sb| (s, sb)))
        .collect();
    slots.sort_by_key(|(_, sb)| std::cmp::Reverse(sb.seq));

    // Decode and semantically validate every CRC-bound table before any
    // manifest read. A malformed fallback must not remain latent merely
    // because verification starts with the newer slot.
    let mut bound = Vec::with_capacity(slots.len());
    for (slot, sb) in slots {
        let table = read_table(&file, len, &sb, &cfg.partition)
            .await?
            .map(|table| validate_table(&cfg.partition, len, &sb, table))
            .transpose()?;
        bound.push((slot, sb, table));
    }
    if let [(_, newer, newer_table), (_, older, older_table)] = bound.as_slice() {
        if older.seq.checked_add(1) != Some(newer.seq) {
            return Err(Error::PartitionCorrupt(format!(
                "{}: non-consecutive volume commit slots",
                cfg.partition
            )));
        }
        let newer_end = newer
            .table_offset
            .checked_add(checked_block_align(newer.table_len as u64).ok_or_else(|| {
                Error::PartitionCorrupt(format!(
                    "{}: overflowing newer table extent",
                    cfg.partition
                ))
            })?)
            .ok_or_else(|| {
                Error::PartitionCorrupt(format!(
                    "{}: overflowing newer table extent",
                    cfg.partition
                ))
            })?;
        let older_end = older
            .table_offset
            .checked_add(checked_block_align(older.table_len as u64).ok_or_else(|| {
                Error::PartitionCorrupt(format!(
                    "{}: overflowing older table extent",
                    cfg.partition
                ))
            })?)
            .ok_or_else(|| {
                Error::PartitionCorrupt(format!(
                    "{}: overflowing older table extent",
                    cfg.partition
                ))
            })?;
        if newer.table_offset < older_end && older.table_offset < newer_end {
            return Err(Error::PartitionCorrupt(format!(
                "{}: overlapping volume table extents",
                cfg.partition
            )));
        }
        if older_table
            .as_ref()
            .is_some_and(|table| table_overlaps_content(newer, table.as_table()))
            || newer_table
                .as_ref()
                .is_some_and(|table| table_overlaps_content(older, table.as_table()))
        {
            return Err(Error::PartitionCorrupt(format!(
                "{}: volume table extent overlaps fallback content",
                cfg.partition
            )));
        }
    }

    let mut adopted: Option<(Slot, Superblock, AdoptableTable)> = None;
    let mut losing_slot: Option<(Slot, u64)> = None;
    let bound_len = bound.len();
    for (idx, (slot, sb, bound_table)) in bound.into_iter().enumerate() {
        let is_candidate = idx == 0 && bound_len == 2;
        let table = match bound_table {
            Some(table) => verify_manifest(&file, len, table).await?,
            None => None,
        };
        match table {
            Some(table) => {
                adopted = Some((slot, sb, table));
                break;
            }
            None if is_candidate => {
                // Torn newest commit: fall back; zero this slot afterwards.
                losing_slot = Some((slot, sb.seq));
            }
            None => {
                return Err(Error::PartitionCorrupt(format!(
                    "{}: volume commit {} unrecoverable",
                    cfg.partition, sb.seq
                )));
            }
        }
    }
    let Some((slot, sb, adoptable)) = adopted else {
        return Err(Error::PartitionCorrupt(format!(
            "{}: no adoptable volume commit",
            cfg.partition
        )));
    };
    let AdoptableTable {
        table,
        verified_chunks,
    } = adoptable;
    // Chunks the adopted slot's manifest verification CRC-checked on disk,
    // seeded into hydration so first reads skip re-verification.
    let mut recovery_verified: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for (id, chunk) in verified_chunks {
        recovery_verified.entry(id).or_default().push(chunk);
    }

    // Repairs: zero the losing slot, splice every partial frontier chunk
    // from its shadow. The final sync is unconditional: after a process
    // crash, the adopted bytes themselves may still exist only in the OS or
    // device cache, and a clean logical sync would otherwise issue no I/O.
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
            losing.offset(),
            IoBuf::copy_from_slice(&[0u8; Superblock::SIZE]),
        )
        .await?;
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
        spliced_shadows += 1;
        len = len.max(phys + span);
    }
    file.sync().await?;

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
        for r in &entry.runs {
            used.push(r.extent());
        }
        for extent in entry.metadata_extents() {
            used.push(extent);
        }
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
    let mut state = State::boot(Genesis {
        partitions,
        dormant,
        recovery_verified,
        alloc: Allocator::rebuild(2 * BLOCK, used),
        adopted_seq: table.seq,
        sacred_slot: slot,
        table_extent: Extent {
            offset: sb.table_offset,
            len: block_align(sb.table_len as u64),
        },
        next_id: table.next_id,
        provisioned: len,
    });
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
        growth_quantum,
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
    growth_quantum: u64,
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
    file.write_at(Slot::A.offset(), IoBuf::copy_from_slice(&sb.encode()))
        .await?;
    file.sync().await?;

    let table_extent = Extent {
        offset: table_offset,
        len: block_align(bytes.len() as u64),
    };
    let mut state = State::boot(Genesis {
        partitions: BTreeMap::new(),
        dormant: BTreeMap::new(),
        recovery_verified: BTreeMap::new(),
        alloc: Allocator::rebuild(2 * BLOCK, [table_extent]),
        adopted_seq: 0,
        sacred_slot: Slot::A,
        table_extent,
        next_id: 0,
        provisioned: 2 * BLOCK + block_align(bytes.len() as u64),
    });
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
        growth_quantum,
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
    // Pruned-floor sanity: within the size, no run below its chunk (the
    // floor is byte-exact; its own chunk stays backed).
    if entry.floor > entry.size {
        return Err(corrupt("pruned floor out of range"));
    }
    let floor_chunk_start = chunk_of(entry.floor) * BLOCK;
    if entry
        .runs
        .first()
        .is_some_and(|r| r.logical < floor_chunk_start)
    {
        return Err(corrupt("run below the pruned floor"));
    }
    let mut inner = BlobInner::from_entry(entry);

    if let Some(last) = entry_last_chunk(entry) {
        let (phys, span) = entry_chunk_span(entry, last).expect("last chunk is backed");
        // The refs must cover every backed chunk below the frontier (plus
        // a full frontier chunk) contiguously from chunk 0 — the invariant
        // capture maintains and the committed-CRC loader relies on.
        // Validating it here keeps a corrupt-but-CRC-bound table a loud
        // open error instead of a read-path panic.
        let covered_end = if span == BLOCK { last + 1 } else { last };
        let floor_chunk = chunk_of(entry.floor);
        match entry.checksums.first() {
            // No refs: legal only when nothing above the floor needs one
            // (the sole backed chunk is the partial frontier at the floor).
            None => {
                if covered_end > floor_chunk {
                    return Err(corrupt("checksum coverage mismatch"));
                }
            }
            // Refs cover [first ref, covered_end) contiguously, starting at
            // or below the floor chunk (a straddling ref keeps serving with
            // its low values unused), with no ref wholly below the floor
            // (capture drops those with their extents).
            Some(first) => {
                if first.first_chunk > floor_chunk {
                    return Err(corrupt("checksum refs start above the floor"));
                }
                let mut next = first.first_chunk;
                for r in &entry.checksums {
                    if r.first_chunk != next {
                        return Err(corrupt("checksum refs not contiguous"));
                    }
                    next += r.count as u64;
                    if next <= floor_chunk {
                        return Err(corrupt("checksum ref wholly below the floor"));
                    }
                }
                if next != covered_end {
                    return Err(corrupt("checksum coverage mismatch"));
                }
            }
        }

        // Chunks recovery itself CRC-checked while verifying the adopted
        // commit's delta manifest hydrate verified: their on-disk bytes are
        // known to match the committed CRCs (nothing can write a dormant
        // blob between recovery and hydration), so first reads skip
        // re-verification.
        let seeded = ready.state.lock().take_recovery_verified(entry.id);
        for chunk in seeded.into_iter().flatten() {
            inner.crcs_mut().set_verified(chunk);
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
        inner.crcs_mut().insert(
            last,
            ChunkState {
                crc: ChunkCrc::Ready(entry.tail_crc),
                verified: true,
            },
        );
        inner.set_tail(last, bytes.as_ref().to_vec());
    } else if !entry.checksums.is_empty() {
        // No backed chunks: capture emits no refs.
        return Err(corrupt("checksum refs without backed chunks"));
    }
    Ok(inner)
}

// Recovery consumes CRC-valid but otherwise hostile table fields. These
// bounded proofs establish that the address-geometry helpers are total over
// arbitrary integers and preserve the bounds expected by manifest reads.
#[cfg(kani)]
mod verification {
    use super::{super::layout::Run, *};

    #[kani::proof]
    fn recovery_block_alignment_total() {
        let len: u64 = kani::any();
        match checked_block_align(len) {
            Some(aligned) => {
                assert!(aligned >= len);
                assert!(aligned.is_multiple_of(BLOCK));
                assert!(aligned - len < BLOCK);
            }
            None => assert!(len > u64::MAX - (BLOCK - 1)),
        }
    }

    fn valid_run(run: &Run) -> bool {
        run.len > 0
            && run.logical.is_multiple_of(BLOCK)
            && run.physical.is_multiple_of(BLOCK)
            && run.logical.checked_add(run.len).is_some()
            && checked_block_align(run.len)
                .and_then(|len| run.physical.checked_add(len))
                .is_some()
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn recovery_chunk_span_bounded() {
        let first = Run {
            logical: kani::any(),
            physical: kani::any(),
            len: kani::any(),
        };
        let second = Run {
            logical: kani::any(),
            physical: kani::any(),
            len: kani::any(),
        };
        kani::assume(valid_run(&first));
        kani::assume(valid_run(&second));
        kani::assume(first.logical + first.len <= second.logical);

        let entry = Entry {
            id: 0,
            partition: 0,
            name: Vec::new(),
            version: 0,
            size: u64::MAX,
            floor: 0,
            runs: vec![first, second],
            checksums: Vec::new(),
            tail_crc: 0,
            shadow: None,
        };

        if let Some((physical, span)) = entry_chunk_span(&entry, kani::any()) {
            assert!(span > 0 && span <= BLOCK);
            assert!(physical.is_multiple_of(BLOCK));
            assert!(physical.checked_add(span).is_some());
        }
    }
}

#[cfg(test)]
mod validation_tests {
    use super::{
        super::{
            layout::{Run, Superblock},
            tests::{test_driver, test_pool},
            Storage as Volume,
        },
        *,
    };
    use crate::{storage::memory, Storage as _};
    use commonware_cryptography::Crc32;

    const IMAGE_LEN: u64 = 8 * BLOCK;
    const TABLE_AT: u64 = 2 * BLOCK;
    const DATA_AT: u64 = 4 * BLOCK;
    const CHECKSUM_AT: u64 = 5 * BLOCK;
    const SHADOW_AT: u64 = 6 * BLOCK;

    fn full_table() -> Table {
        let data_crc = Crc32::checksum(&vec![7; BLOCK as usize]);
        let checksum = data_crc.to_be_bytes();
        Table {
            seq: 1,
            next_id: 1,
            partitions: vec!["p".into()],
            blobs: vec![Entry {
                id: 0,
                partition: 0,
                name: b"blob".to_vec(),
                version: 0,
                size: BLOCK,
                floor: 0,
                runs: vec![Run {
                    logical: 0,
                    physical: DATA_AT,
                    len: BLOCK,
                }],
                checksums: vec![ChecksumRef {
                    first_chunk: 0,
                    count: 1,
                    offset: CHECKSUM_AT,
                    crc: Crc32::checksum(&checksum),
                }],
                tail_crc: data_crc,
                shadow: None,
            }],
            manifest: Vec::new(),
        }
    }

    fn partial_table() -> Table {
        let mut table = full_table();
        let entry = &mut table.blobs[0];
        entry.size = 100;
        entry.runs[0].len = 100;
        entry.checksums.clear();
        entry.tail_crc = Crc32::checksum(&[7; 100]);
        entry.shadow = Some(SHADOW_AT);
        table.manifest = Vec::new();
        table
    }

    fn place(image: &mut [u8], offset: u64, bytes: &[u8]) {
        let Some(end) = offset.checked_add(bytes.len() as u64) else {
            return;
        };
        if end <= image.len() as u64 {
            image[offset as usize..end as usize].copy_from_slice(bytes);
        }
    }

    async fn assert_open_rejects_without_repair(
        case: &str,
        table: Table,
        table_offset: u64,
        image_len: u64,
    ) {
        let pool = test_pool();
        let inner = memory::Storage::new(pool.clone());
        let cfg = Config::default();
        let mut image = vec![0u8; image_len as usize];

        let data = vec![7u8; BLOCK as usize];
        place(&mut image, DATA_AT, &data);
        let crc = Crc32::checksum(&data).to_be_bytes();
        place(&mut image, CHECKSUM_AT, &crc);
        place(&mut image, SHADOW_AT, &[7u8; 100]);

        let table_bytes = table.encode();
        place(&mut image, table_offset, &table_bytes);
        let sb = Superblock {
            seq: 1,
            table_offset,
            table_len: table_bytes.len() as u32,
            table_crc: Crc32::checksum(&table_bytes),
        };
        place(&mut image, Superblock::slot_offset(0), &sb.encode());

        let (file, _) = inner.open(&cfg.partition, &cfg.name).await.unwrap();
        file.write_at(0, IoBuf::copy_from_slice(&image))
            .await
            .unwrap();
        file.sync().await.unwrap();

        let result = Volume::init(inner.clone(), pool, cfg.clone(), test_driver()).await;
        assert!(
            matches!(result, Err(Error::PartitionCorrupt(_))),
            "{case}: hostile table was not reported as partition corruption"
        );

        let (file, after_len) = inner.open(&cfg.partition, &cfg.name).await.unwrap();
        assert_eq!(after_len, image_len, "{case}: recovery changed file length");
        let after = file
            .read_at(0, image_len as usize)
            .await
            .unwrap()
            .coalesce();
        assert_eq!(
            after.as_ref(),
            &image,
            "{case}: recovery wrote a repair before semantic validation"
        );
    }

    /// Missing or outer-CRC-mismatched bytes in the newest table are an
    /// ordinary torn candidate: recovery may adopt the consecutive older
    /// slot, then zero the rejected slot. This stays distinct from a readable,
    /// CRC-bound table whose semantics are corrupt.
    #[tokio::test]
    async fn torn_newest_table_still_falls_back() {
        for missing in [false, true] {
            let pool = test_pool();
            let inner = memory::Storage::new(pool.clone());
            let cfg = Config::default();
            let mut image = vec![0u8; (4 * BLOCK) as usize];

            let older = Table::default().encode();
            place(&mut image, TABLE_AT, &older);
            let older_sb = Superblock {
                seq: 0,
                table_offset: TABLE_AT,
                table_len: older.len() as u32,
                table_crc: Crc32::checksum(&older),
            };
            place(&mut image, Superblock::slot_offset(0), &older_sb.encode());

            let newer = Table {
                seq: 1,
                ..Table::default()
            }
            .encode();
            let newer_offset = if missing { 4 * BLOCK } else { 3 * BLOCK };
            place(&mut image, newer_offset, &newer);
            let newer_sb = Superblock {
                seq: 1,
                table_offset: newer_offset,
                table_len: newer.len() as u32,
                table_crc: Crc32::checksum(&newer) ^ u32::from(!missing),
            };
            place(&mut image, Superblock::slot_offset(1), &newer_sb.encode());

            let (file, _) = inner.open(&cfg.partition, &cfg.name).await.unwrap();
            file.write_at(0, IoBuf::copy_from_slice(&image))
                .await
                .unwrap();
            file.sync().await.unwrap();

            let recovered = Volume::init(inner.clone(), pool, cfg.clone(), test_driver())
                .await
                .unwrap_or_else(|error| panic!("missing={missing}: fallback failed: {error}"));
            assert!(recovered.scan("p").await.is_err());
            let (file, _) = inner.open(&cfg.partition, &cfg.name).await.unwrap();
            let slot = file
                .read_at(Superblock::slot_offset(1), Superblock::SIZE)
                .await
                .unwrap()
                .coalesce();
            assert_eq!(slot.as_ref(), &[0u8; Superblock::SIZE]);
        }
    }

    /// A readable newest table whose outer binding is valid but whose extent
    /// geometry is hostile is authenticated corruption, not a torn write. A
    /// valid older slot must not turn it into a silent rollback.
    #[tokio::test]
    async fn crc_bound_semantic_corruption_does_not_fall_back() {
        let pool = test_pool();
        let inner = memory::Storage::new(pool.clone());
        let cfg = Config::default();
        let mut image = vec![0u8; IMAGE_LEN as usize];

        let older = Table::default().encode();
        place(&mut image, 3 * BLOCK, &older);
        let older_sb = Superblock {
            seq: 0,
            table_offset: 3 * BLOCK,
            table_len: older.len() as u32,
            table_crc: Crc32::checksum(&older),
        };
        place(&mut image, Superblock::slot_offset(0), &older_sb.encode());

        let mut hostile = full_table();
        hostile.blobs[0].runs[0].physical = BLOCK;
        let hostile = hostile.encode();
        place(&mut image, TABLE_AT, &hostile);
        let hostile_sb = Superblock {
            seq: 1,
            table_offset: TABLE_AT,
            table_len: hostile.len() as u32,
            table_crc: Crc32::checksum(&hostile),
        };
        let encoded_slot = hostile_sb.encode();
        place(&mut image, Superblock::slot_offset(1), &encoded_slot);

        let (file, _) = inner.open(&cfg.partition, &cfg.name).await.unwrap();
        file.write_at(0, IoBuf::copy_from_slice(&image))
            .await
            .unwrap();
        file.sync().await.unwrap();
        let result = Volume::init(inner.clone(), pool, cfg.clone(), test_driver()).await;
        assert!(matches!(result, Err(Error::PartitionCorrupt(_))));

        let (file, _) = inner.open(&cfg.partition, &cfg.name).await.unwrap();
        let slot = file
            .read_at(Superblock::slot_offset(1), Superblock::SIZE)
            .await
            .unwrap()
            .coalesce();
        assert_eq!(slot.as_ref(), encoded_slot);
    }

    /// A legal successor cannot allocate its table over content retained by
    /// the fallback slot. Reject this cross-slot Frankenstate before trying
    /// the candidate manifest or writing fallback repairs, even when the
    /// candidate table's outer CRC was torn and fallback would be allowed.
    #[tokio::test]
    async fn candidate_table_over_fallback_data_is_rejected_before_repair() {
        let mut image = vec![0u8; IMAGE_LEN as usize];

        let mut older = full_table();
        older.seq = 0;
        older.blobs[0].checksums[0].offset = 7 * BLOCK;
        let older = older.encode();
        place(&mut image, TABLE_AT, &older);
        let older_sb = Superblock {
            seq: 0,
            table_offset: TABLE_AT,
            table_len: older.len() as u32,
            table_crc: Crc32::checksum(&older),
        };
        place(&mut image, Superblock::slot_offset(0), &older_sb.encode());
        place(
            &mut image,
            7 * BLOCK,
            &Crc32::checksum(&vec![7; BLOCK as usize]).to_be_bytes(),
        );

        let mut candidate = partial_table();
        candidate.blobs[0].runs[0].physical = CHECKSUM_AT;
        candidate.blobs[0].shadow = Some(SHADOW_AT);
        candidate.manifest = vec![(0, 0)];
        candidate.blobs[0].tail_crc = Crc32::checksum(&[9; 100]);
        let candidate = candidate.encode();
        // This overwrites the fallback's DATA_AT allocation. The candidate's
        // own run and shadow are elsewhere and pass local geometry checks.
        place(&mut image, DATA_AT, &candidate);
        place(&mut image, CHECKSUM_AT, &[8; 100]);
        place(&mut image, SHADOW_AT, &[8; 100]);
        for torn_outer_crc in [false, true] {
            let pool = test_pool();
            let inner = memory::Storage::new(pool.clone());
            let cfg = Config::default();
            let mut case = image.clone();
            let candidate_sb = Superblock {
                seq: 1,
                table_offset: DATA_AT,
                table_len: candidate.len() as u32,
                table_crc: Crc32::checksum(&candidate) ^ u32::from(torn_outer_crc),
            };
            place(
                &mut case,
                Superblock::slot_offset(1),
                &candidate_sb.encode(),
            );

            let (file, _) = inner.open(&cfg.partition, &cfg.name).await.unwrap();
            file.write_at(0, IoBuf::copy_from_slice(&case))
                .await
                .unwrap();
            file.sync().await.unwrap();

            let result = Volume::init(inner.clone(), pool, cfg.clone(), test_driver()).await;
            assert!(
                matches!(result, Err(Error::PartitionCorrupt(_))),
                "torn_outer_crc={torn_outer_crc}"
            );

            let (file, after_len) = inner.open(&cfg.partition, &cfg.name).await.unwrap();
            assert_eq!(after_len, IMAGE_LEN);
            let after = file
                .read_at(0, IMAGE_LEN as usize)
                .await
                .unwrap()
                .coalesce();
            assert_eq!(after.as_ref(), &case, "recovery repaired a hostile image");
        }
    }

    /// A table's two CRCs authenticate hostile bytes without validating
    /// their meaning. Every malformed allocation must fail open loudly,
    /// without panicking or reaching shadow/slot repair writes.
    #[tokio::test]
    async fn crc_valid_hostile_extents_are_rejected_before_repair() {
        let max_aligned = u64::MAX - (BLOCK - 1);
        let mut cases = Vec::new();

        let mut table = full_table();
        table.blobs[0].runs[0].physical = BLOCK;
        cases.push(("reserved run", table, TABLE_AT, IMAGE_LEN));
        let mut table = full_table();
        table.blobs[0].runs[0].physical = DATA_AT + 1;
        cases.push(("unaligned run", table, TABLE_AT, IMAGE_LEN));
        let mut table = full_table();
        table.blobs[0].runs[0].physical = CHECKSUM_AT;
        cases.push(("overlapping run", table, TABLE_AT, IMAGE_LEN));
        let mut table = full_table();
        table.blobs[0].runs[0].physical = max_aligned;
        cases.push(("overflowing run", table, TABLE_AT, IMAGE_LEN));
        let mut table = full_table();
        table.blobs[0].runs[0].physical = IMAGE_LEN;
        cases.push(("out-of-file run", table, TABLE_AT, IMAGE_LEN));

        let mut table = full_table();
        table.blobs[0].checksums[0].offset = BLOCK;
        cases.push(("reserved checksum", table, TABLE_AT, IMAGE_LEN));
        let mut table = full_table();
        table.blobs[0].checksums[0].offset = CHECKSUM_AT + 1;
        cases.push(("unaligned checksum", table, TABLE_AT, IMAGE_LEN));
        let mut table = full_table();
        table.blobs[0].checksums[0].offset = DATA_AT;
        cases.push(("overlapping checksum", table, TABLE_AT, IMAGE_LEN));
        let mut table = full_table();
        table.blobs[0].checksums[0].offset = max_aligned;
        cases.push(("overflowing checksum", table, TABLE_AT, IMAGE_LEN));
        let mut table = full_table();
        table.blobs[0].checksums[0].offset = IMAGE_LEN;
        cases.push(("out-of-file checksum", table, TABLE_AT, IMAGE_LEN));

        let mut table = partial_table();
        table.blobs[0].shadow = Some(BLOCK);
        cases.push(("reserved shadow", table, TABLE_AT, IMAGE_LEN));
        let mut table = partial_table();
        table.blobs[0].shadow = Some(SHADOW_AT + 1);
        cases.push(("unaligned shadow", table, TABLE_AT, IMAGE_LEN));
        let mut table = partial_table();
        table.blobs[0].shadow = Some(DATA_AT);
        cases.push(("overlapping shadow", table, TABLE_AT, IMAGE_LEN));
        let mut table = partial_table();
        table.blobs[0].shadow = Some(max_aligned);
        cases.push(("overflowing shadow", table, TABLE_AT, IMAGE_LEN));
        let mut table = partial_table();
        table.blobs[0].shadow = Some(IMAGE_LEN);
        cases.push(("out-of-file shadow", table, TABLE_AT, IMAGE_LEN));

        cases.push(("reserved table", full_table(), BLOCK, IMAGE_LEN));
        cases.push(("unaligned table", full_table(), TABLE_AT + 1, IMAGE_LEN));
        cases.push(("overlapping table", full_table(), DATA_AT, IMAGE_LEN));
        cases.push(("overflowing table", full_table(), max_aligned, IMAGE_LEN));
        cases.push(("out-of-file table", full_table(), IMAGE_LEN, IMAGE_LEN));

        for (case, table, table_offset, image_len) in cases {
            assert_open_rejects_without_repair(case, table, table_offset, image_len).await;
        }
    }

    /// Namespace and identity corruption is rejected at the same boundary,
    /// before BTree reconstruction can silently overwrite duplicate keys.
    #[tokio::test]
    async fn crc_valid_hostile_namespace_is_rejected_before_repair() {
        let mut cases = Vec::new();

        let mut table = full_table();
        table.partitions.push("p".into());
        cases.push(("duplicate partition", table));
        let mut table = full_table();
        table.partitions[0] = "bad/name".into();
        cases.push(("invalid partition", table));
        let mut table = full_table();
        table.blobs[0].partition = 1;
        cases.push(("partition index", table));
        let mut table = full_table();
        table.blobs.push(table.blobs[0].clone());
        cases.push(("duplicate id", table));
        let mut table = full_table();
        let mut duplicate = Entry::empty(1, b"blob".to_vec(), 0);
        duplicate.partition = 0;
        table.blobs.push(duplicate);
        table.next_id = 2;
        cases.push(("duplicate name", table));
        let mut table = full_table();
        table.next_id = 0;
        cases.push(("id outside next id", table));
        let mut table = full_table();
        table.seq = 2;
        cases.push(("sequence mismatch", table));
        let mut table = full_table();
        table.next_id = 2;
        table.manifest = vec![(1, 0)];
        cases.push(("manifest id", table));
        let mut table = full_table();
        table.manifest = vec![(0, 1)];
        cases.push(("manifest past blob", table));
        let mut table = full_table();
        table.manifest = vec![(0, u64::MAX)];
        cases.push(("manifest chunk", table));

        for (case, table) in cases {
            assert_open_rejects_without_repair(case, table, TABLE_AT, IMAGE_LEN).await;
        }
    }
}
