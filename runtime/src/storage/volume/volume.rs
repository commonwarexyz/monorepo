//! One open volume: its shared context, creation, and recovery.
//!
//! # Creation
//!
//! A fresh volume file is initialized in two barriers:
//!
//! 1. Write the superblock and zero the initial journal extent; sync.
//! 2. Write roots with sequences 1 and 2 (both naming the initial extent); sync.
//!
//! `open` returns only after both barriers, so recovery can discriminate exactly: an
//! invalid superblock, or a valid superblock with no valid root, is provably an
//! interrupted creation (no user data can exist) and is recreated from scratch. Writing
//! both parity slots at creation means every later state has at least one valid root (a
//! root flip only overwrites one slot), so "no valid root" can never be media damage on a
//! volume that was live.
//!
//! # Recovery
//!
//! Read the superblock and roots, pick the highest-sequence valid root, replay its extent
//! record by record, and derive chunk ownership. Replay stops at the first torn frame;
//! everything beyond belonged to unacknowledged batches. The tail past the stop point is
//! then rewritten with zeros so that appending resumes into clean territory: without this,
//! a fully intact record from a lost batch could sit past the stop point and splice itself
//! onto records appended after recovery. The zero-write needs no barrier of its own; the
//! next commit's barrier covers it, and until then replay just stops at the same point.

use super::{
    format::{
        self, Extent, Frame, MAX_EXTENT_BYTES, PAGE, ROOT_OFFSETS, Record, Root, SUPERBLOCK_OFFSET,
        Superblock,
    },
    state::{Allocator, Catalog, Core, Geometry, HighWater, Pins},
};
use crate::{Blob as _, Error, IoBuf, WriteOptions};
use commonware_formatting::hex;
use commonware_utils::{channel::mpsc, sync::Mutex};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64},
    },
};

/// The blob name of the volume file within its inner partition.
pub(super) const VOLUME_NAME: &[u8] = b"volume";

/// Writes `len` zero bytes at `offset` in bounded slices.
pub(super) async fn write_zeros<B: crate::Blob>(
    file: &B,
    mut offset: u64,
    mut len: u64,
) -> Result<(), Error> {
    const SLICE: u64 = 4 << 20;
    let zeros = IoBuf::from(vec![0u8; SLICE.min(len) as usize]);
    while len > 0 {
        let step = SLICE.min(len);
        let slice = zeros.slice(..step as usize);
        file.write_at(offset, slice, WriteOptions::default())
            .await?;
        offset += step;
        len -= step;
    }
    Ok(())
}

/// Version stamped into the inner blob's header; the volume layout revision.
pub(super) const VOLUME_VERSION: u16 = 1;

/// Chunks in a fresh volume's initial journal extent.
const INITIAL_EXTENT_CHUNKS: u32 = 1;

/// State shared by handles, the storage front end, and the committer task.
///
/// The committer holds this without the request sender, so dropping every handle and the
/// storage closes the channel and lets the task exit.
pub(super) struct Shared<S: crate::Storage> {
    pub partition: String,
    /// The volume file. All I/O goes through clones of this handle.
    pub file: S::Blob,
    pub geometry: Geometry,
    pub catalog: Mutex<Catalog>,
    pub allocator: Mutex<Allocator>,
    pub pins: Arc<Pins>,
    pub high_water: HighWater,
    /// Highest batch number whose barrier has completed.
    pub durable_batch: AtomicU64,
    /// Set on any record-write or barrier failure: the file's page-cache state is
    /// unknowable afterwards, so every subsequent operation fails until reopen.
    pub poisoned: AtomicBool,
}

impl<S: crate::Storage> Shared<S> {
    /// The error every operation returns once the volume is poisoned.
    pub fn poisoned_error(&self) -> Error {
        Error::BlobSyncFailed(
            self.partition.clone(),
            hex(VOLUME_NAME),
            Arc::new(std::io::Error::other(
                "volume poisoned by an earlier commit failure",
            )),
        )
    }
}

/// A handle to an open volume: the shared context plus the committer's request channel.
pub(super) struct Volume<S: crate::Storage> {
    pub shared: Arc<Shared<S>>,
    pub requests: mpsc::UnboundedSender<super::committer::Request>,
}

impl<S: crate::Storage> Clone for Volume<S> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
            requests: self.requests.clone(),
        }
    }
}

/// The committer's private journal position.
pub(super) struct Journal {
    /// Sequence of the live root.
    pub root_seq: u64,
    /// Epoch of the live extent; salts record checksums.
    pub epoch: u64,
    /// The live extent.
    pub extent: Extent,
    /// Bytes of the extent already holding records.
    pub used: u64,
    /// Number of the last batch started. Batch numbers restart at every open; grave
    /// entries and creation acknowledgments only compare batches within one process.
    pub batch: u64,
}

/// Opens (or creates) the volume for `partition`, returning the shared context and the
/// committer's starting position.
pub(super) async fn open<S: crate::Storage>(
    inner: &S,
    partition: &str,
    chunk_size: u32,
) -> Result<(Arc<Shared<S>>, Journal), Error> {
    let (file, size, _) = inner
        .open_versioned(partition, VOLUME_NAME, VOLUME_VERSION..=VOLUME_VERSION)
        .await?;

    let corrupt =
        |reason: String| Error::BlobCorrupt(partition.to_string(), hex(VOLUME_NAME), reason);

    // Read the header pages (padded with zeros if the file is shorter, which only a
    // creation crash can leave behind).
    let mut pages = vec![0u8; 3 * PAGE];
    // Widened before the cast: on 32-bit targets a large file size must not truncate.
    let readable = size.min(3 * PAGE as u64) as usize;
    if readable > 0 {
        let read = file.read_at(0, readable).await?.coalesce();
        pages[..readable].copy_from_slice(read.as_ref());
    }

    let superblock = Superblock::decode(&pages[..PAGE]).map_err(&corrupt)?;
    let roots = [
        Root::decode(&pages[PAGE..2 * PAGE], 0).map_err(&corrupt)?,
        Root::decode(&pages[2 * PAGE..], 1).map_err(&corrupt)?,
    ];
    let root = roots.into_iter().flatten().max_by_key(|root| root.seq);

    let (superblock, root) = match (superblock, root) {
        (Some(superblock), Some(root)) => (superblock, root),
        // A valid root without a valid superblock is unreachable by crash: creation
        // syncs the superblock before any root is written.
        (None, Some(_)) => return Err(corrupt("valid root under invalid superblock".into())),
        // No valid root means creation never completed (a flip overwrites only one
        // slot), so no user data exists and recreating from scratch is safe.
        (_, None) => return create(partition, file, size, chunk_size).await,
    };

    recover(partition, file, size, superblock, root).await
}

/// Initializes a fresh (or interrupted-creation) volume file.
async fn create<S: crate::Storage>(
    partition: &str,
    file: S::Blob,
    size: u64,
    chunk_size: u32,
) -> Result<(Arc<Shared<S>>, Journal), Error> {
    let geometry = Geometry { chunk_size };
    let extent = Extent {
        first_chunk: 1,
        chunks: INITIAL_EXTENT_CHUNKS,
    };

    // Barrier 1: identity plus a durably zeroed initial extent. An interrupted attempt
    // may have left arbitrary bytes anywhere in this footprint; overwrite all of it.
    let superblock = Superblock { chunk_size };
    file.write_at(
        SUPERBLOCK_OFFSET,
        superblock.encode(),
        WriteOptions::default(),
    )
    .await?;
    for offset in ROOT_OFFSETS {
        file.write_at(offset, vec![0u8; PAGE], WriteOptions::default())
            .await?;
    }
    write_zeros(&file, extent.offset(chunk_size), extent.len(chunk_size)).await?;
    file.sync().await?;

    // Barrier 2: both parity slots, so every post-creation state has a valid root.
    for seq in [1u64, 2] {
        let root = Root {
            seq,
            epoch: 1,
            extent,
        };
        file.write_at(
            ROOT_OFFSETS[(seq & 1) as usize],
            root.encode(),
            WriteOptions::default(),
        )
        .await?;
    }
    file.sync().await?;

    let end = extent.end(chunk_size);
    let shared = Arc::new(Shared {
        partition: partition.to_string(),
        file,
        geometry,
        catalog: Mutex::new(Catalog::default()),
        allocator: Mutex::new(Allocator::new(extent.first_chunk + extent.chunks)),
        pins: Arc::new(Pins::default()),
        high_water: HighWater::new(end.max(size)),
        durable_batch: AtomicU64::new(0),
        poisoned: AtomicBool::new(false),
    });
    let journal = Journal {
        root_seq: 2,
        epoch: 1,
        extent,
        used: 0,
        batch: 0,
    };
    Ok((shared, journal))
}

/// Rebuilds a live volume's state from its journal.
async fn recover<S: crate::Storage>(
    partition: &str,
    file: S::Blob,
    size: u64,
    superblock: Superblock,
    root: Root,
) -> Result<(Arc<Shared<S>>, Journal), Error> {
    let corrupt =
        |reason: String| Error::BlobCorrupt(partition.to_string(), hex(VOLUME_NAME), reason);
    let geometry = Geometry {
        chunk_size: superblock.chunk_size,
    };

    // The extent was durably zero before the root named it, so it can never extend past
    // the file: a shorter file is external damage, not a crash artifact. Its size is
    // also bounded (the writer sizes extents from the snapshot, far below this cap), so
    // hostile roots cannot turn recovery into unbounded work.
    let extent_offset = root.extent.offset(geometry.chunk_size);
    let extent_len = root.extent.len(geometry.chunk_size);
    if extent_offset + extent_len > size {
        return Err(corrupt(format!(
            "journal extent ends at {} but file has {size} bytes",
            extent_offset + extent_len
        )));
    }
    if extent_len > MAX_EXTENT_BYTES {
        return Err(corrupt(format!(
            "journal extent of {extent_len} bytes exceeds bound"
        )));
    }

    // Replay through a bounded window: the extent's length must never size an
    // allocation. The window holds at most one maximum record plus one read step; once
    // it holds enough for any legal frame and still reads as end-of-log, the log ended.
    const REPLAY_READ: u64 = 1 << 20;
    let frame_bound = u64::from(format::MAX_RECORD_LEN) + 16;
    let size_chunks = size.div_ceil(u64::from(geometry.chunk_size)) as u32;
    let mut replayer = Replayer::new(geometry, root.extent, size_chunks);
    let mut window: Vec<u8> = Vec::new();
    let mut used = 0u64;
    let mut window_start = 0u64;
    let mut fetched = 0u64;
    loop {
        let at = (used - window_start) as usize;
        match Record::decode(&window[at..], root.epoch) {
            Frame::Record(record, consumed) => {
                replayer.apply(record).map_err(&corrupt)?;
                used += consumed as u64;
            }
            Frame::Corrupt(reason) => return Err(corrupt(reason)),
            // Either the true end of the log or a frame straddling the window's edge:
            // fetch more and retry, unless no legal frame could need more than the
            // window already holds.
            Frame::End if fetched < extent_len && (window.len() - at) as u64 <= frame_bound => {
                window.drain(..at);
                window_start = used;
                let step = REPLAY_READ.min(extent_len - fetched);
                let read = file
                    .read_at(extent_offset + fetched, step as usize)
                    .await?
                    .coalesce();
                window.extend_from_slice(read.as_ref());
                fetched += step;
            }
            Frame::End => break,
        }
    }
    drop(window);

    // Zero the whole extent tail past the stop point, so records appended after
    // recovery can never splice replay onto an intact remnant of a lost batch, no
    // matter how far appends advance before the next checkpoint. Read first: on a
    // clean open the tail is already zero and nothing is written.
    let mut wrote_zeros = false;
    let mut pos = used;
    while pos < extent_len {
        let step = REPLAY_READ.min(extent_len - pos);
        let read = file
            .read_at(extent_offset + pos, step as usize)
            .await?
            .coalesce();
        if read.as_ref().iter().any(|&b| b != 0) {
            write_zeros(&file, extent_offset + pos, step).await?;
            wrote_zeros = true;
        }
        pos += step;
    }

    let (catalog, allocator) = replayer.finish();

    // Re-establish the invariant that a mapped chunk's bytes at or beyond its blob's
    // length are zero. Runtime writes preserve it (allocations come durably zeroed and
    // a shrink replaces its boundary chunk), but a crash can leave an unacknowledged
    // write's remnants above the recovered length, and a later grow would expose them
    // where the contract requires zeros. Only the boundary chunk can be affected: no
    // mapped slot lies wholly beyond a blob's length. Reading first keeps clean opens
    // write-free; regions past the file are already zeros.
    let mut tail_zeroes = Vec::new();
    for core in catalog.blobs.values() {
        let state = core.state.lock();
        let within = state.len % u64::from(geometry.chunk_size);
        if within == 0 {
            continue;
        }
        if let Some(&chunk) = state.map.get(&(geometry.slot_of(state.len) as u32)) {
            let phys = geometry.chunk_offset(chunk) + within;
            let tail = u64::from(geometry.chunk_size) - within;
            let readable = tail.min(size.saturating_sub(phys)) as usize;
            if readable > 0 {
                tail_zeroes.push((phys, readable));
            }
        }
    }
    for (phys, tail) in tail_zeroes {
        let current = file.read_at(phys, tail).await?.coalesce();
        if current.as_ref().iter().any(|&b| b != 0) {
            file.write_at(phys, IoBuf::from(vec![0u8; tail]), WriteOptions::default())
                .await?;
            wrote_zeros = true;
        }
    }

    // The zero-writes must be durable before any post-recovery record can survive a
    // crash: a record write can outlive an incomplete barrier, and replay must never
    // walk past it onto un-zeroed remnants this recovery already stepped over.
    if wrote_zeros {
        file.sync().await?;
    }

    let shared = Arc::new(Shared {
        partition: partition.to_string(),
        file,
        geometry,
        catalog: Mutex::new(catalog),
        allocator: Mutex::new(allocator),
        pins: Arc::new(Pins::default()),
        high_water: HighWater::new(size),
        durable_batch: AtomicU64::new(0),
        poisoned: AtomicBool::new(false),
    });
    let journal = Journal {
        root_seq: root.seq,
        epoch: root.epoch,
        extent: root.extent,
        used,
        batch: 0,
    };
    Ok((shared, journal))
}

/// Applies replayed records to build the catalog and derive chunk ownership.
struct Replayer {
    geometry: Geometry,
    /// Chunk ids minted at open: everything at or beyond reads as zeros.
    size_chunks: u32,
    blobs: BTreeMap<u64, ReplayBlob>,
    names: BTreeMap<Vec<u8>, u64>,
    /// Every owned chunk (journal extent included): the double-assignment tripwire.
    owned: std::collections::HashSet<u32>,
    /// Creates must mint strictly increasing ids within an epoch.
    last_created: Option<u64>,
}

struct ReplayBlob {
    version: u16,
    name: Vec<u8>,
    len: u64,
    map: BTreeMap<u32, u32>,
}

impl Replayer {
    fn new(geometry: Geometry, extent: Extent, size_chunks: u32) -> Self {
        let owned = (extent.first_chunk..extent.first_chunk + extent.chunks).collect();
        Self {
            geometry,
            size_chunks,
            blobs: BTreeMap::new(),
            names: BTreeMap::new(),
            owned,
            last_created: None,
        }
    }

    fn apply(&mut self, record: Record) -> Result<(), String> {
        match record {
            Record::Create {
                id,
                version,
                name,
                len,
                mappings,
            } => {
                if self.last_created.is_some_and(|last| id <= last) {
                    return Err(format!("create id {id} not increasing"));
                }
                self.last_created = Some(id);
                if self.names.contains_key(&name) {
                    return Err(format!("create of live name {}", hex(&name)));
                }
                let mut blob = ReplayBlob {
                    version,
                    name: name.clone(),
                    len: 0,
                    map: BTreeMap::new(),
                };
                self.extend(&mut blob, len, mappings)?;
                self.names.insert(name, id);
                self.blobs.insert(id, blob);
            }
            Record::Delete { id } => {
                // A delete of an id the epoch does not know is a no-op, not corruption:
                // a removal can race a checkpoint so that the snapshot already excludes
                // the row while the delete record lands just after it in the new epoch.
                let Some(blob) = self.blobs.remove(&id) else {
                    return Ok(());
                };
                self.names.remove(&blob.name);
                for chunk in blob.map.values() {
                    self.owned.remove(chunk);
                }
            }
            Record::Update {
                id,
                trunc_floor,
                len,
                mappings,
            } => {
                let mut blob = self
                    .blobs
                    .remove(&id)
                    .ok_or_else(|| format!("update of unknown id {id}"))?;
                // Truncate to the trajectory floor: unmap slots wholly beyond it (a
                // cut past u32 means nothing is wholly beyond).
                if let Ok(cut) = u32::try_from(self.geometry.slots_of_len(trunc_floor)) {
                    for (_, chunk) in blob.map.split_off(&cut) {
                        self.owned.remove(&chunk);
                    }
                }
                // A shrink that keeps part of a mapped boundary chunk replaces that
                // chunk; the replacement mapping arrives in this same record and is
                // the only case where a mapping may target an occupied slot.
                if trunc_floor % u64::from(self.geometry.chunk_size) != 0 {
                    let boundary = self.geometry.slot_of(trunc_floor) as u32;
                    if mappings.iter().any(|(slot, _)| *slot == boundary)
                        && let Some(chunk) = blob.map.remove(&boundary)
                    {
                        self.owned.remove(&chunk);
                    }
                }
                blob.len = trunc_floor;
                self.extend(&mut blob, len, mappings)?;
                self.blobs.insert(id, blob);
            }
        }
        Ok(())
    }

    /// Grows `blob` to `len` and applies `mappings`, enforcing ownership and bounds.
    fn extend(
        &mut self,
        blob: &mut ReplayBlob,
        len: u64,
        mappings: Vec<(u32, u32)>,
    ) -> Result<(), String> {
        blob.len = len;
        let slots = self.geometry.slots_of_len(len);
        // The writer never journals lengths whose slots exceed u32; runtime reads rely
        // on that bound.
        if slots > u64::from(u32::MAX) + 1 {
            return Err(format!("length {len} exceeds slot bound"));
        }
        for (slot, chunk) in mappings {
            if u64::from(slot) >= slots {
                return Err(format!("mapping slot {slot} beyond length {len}"));
            }
            if !self.owned.insert(chunk) {
                return Err(format!("chunk {chunk} assigned twice"));
            }
            if blob.map.insert(slot, chunk).is_some() {
                return Err(format!("slot {slot} mapped twice"));
            }
        }
        Ok(())
    }

    /// Builds the final catalog and allocator.
    fn finish(self) -> (Catalog, Allocator) {
        let next_id = self.last_created.map_or(0, |id| id + 1);
        let mut catalog = Catalog {
            blobs: BTreeMap::new(),
            next_id,
        };
        for (id, blob) in self.blobs {
            let core = Arc::new(Core::recovered(
                id,
                blob.version,
                blob.name.clone(),
                blob.len,
                blob.map,
            ));
            catalog.blobs.insert(blob.name, core);
        }

        // Mappings may point past the end of the file (their record survived a crash
        // but the payload and the growth under it did not); they read zeros through the
        // high-water clamp, exactly like the unmapped slot they logically are. They
        // stay mapped and owned so the mint counter can never re-issue their chunk ids:
        // re-minting would let this epoch's still-live records collide with a new
        // owner's on the next replay.
        let size_chunks = self
            .owned
            .iter()
            .map(|&chunk| chunk + 1)
            .max()
            .unwrap_or(0)
            .max(self.size_chunks);
        let mut allocator = Allocator::new(size_chunks);
        let free = (1..size_chunks).filter(|chunk| !self.owned.contains(chunk));
        allocator.recovered(free);
        (catalog, allocator)
    }
}
