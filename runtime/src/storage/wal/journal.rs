//! One family's open journal: creation, recovery, appends, and checkpoints.
//!
//! # Creation
//!
//! A WAL file is staged under a temporary name (header, one root, a zeroed initial
//! extent), synced, renamed into place, and its directories synced. Any visible WAL
//! file is therefore complete: recovery treats every validation failure as damage,
//! never as an interrupted creation. A leftover staging file is swept by the next
//! creation.
//!
//! # Recovery
//!
//! Read the header and both root slots; the highest-sequence valid root governs (a
//! valid root in the wrong parity slot is damage). Replay the extent it names through
//! a bounded window, folding records into a [Catalog], and stop at a clean end or torn
//! tail. Then scrub: the bytes past the stop point must be zero before new records are
//! appended, or a fragment of a lost batch could splice onto a later append. Tearing
//! is confined to the last unacknowledged batch, so the scrub window is one maximum
//! drain, read first so clean recoveries write nothing.
//!
//! # Checkpoint
//!
//! When the live extent cannot hold the next batch, the whole catalog is re-stated as
//! records at the head of a fresh extent and a new root names it:
//!
//! ```text
//! K1  place the extent (first fit outside both live extents), zero it, sync
//! K2  write the snapshot records at its head, sync
//! K3  write the next root (seq+1, epoch+1), sync
//! ```
//!
//! A crash before K3's barrier leaves the old root governing an intact old extent; a
//! torn root write loses at worst the flip (parity: the previous root's slot was not
//! touched). Placement needs no allocator: only the two roots' extents are ever live,
//! so free space is everything else in the record space.

use super::{
    catalog::Catalog,
    format::{
        Extent, Frame, Header, MAX_EXTENT_BYTES, MAX_RECORD_LEN, PAGE, RECORD_SPACE, ROOT_OFFSETS,
        Record, Root, Salt,
    },
    medium::{File as _, Medium},
};
use crate::Error;

/// Size of a fresh WAL's initial extent.
const INITIAL_EXTENT_BYTES: u64 = 64 << 10;

/// Capacity floor for a checkpoint's fresh extent.
const MIN_EXTENT_BYTES: u64 = 64 << 10;

/// A fresh extent holds this multiple of its snapshot, bounding both checkpoint
/// frequency (amortization) and replay cost at open.
const EXTENT_SLACK: u64 = 4;

/// Most bytes one committer batch may append. Tearing is confined to the last
/// unacknowledged batch, so this also bounds recovery's scrub window.
pub(super) const MAX_DRAIN_BYTES: u64 = 1 << 20;

/// Replay's read window. Refilled whenever less than one maximum frame remains.
const WINDOW_BYTES: usize = 256 << 10;

/// Suffix of the staging name used during creation.
const STAGING_SUFFIX: &str = ".staging";

/// One family's open journal.
pub(super) struct Journal<M: Medium> {
    file: M::File,
    /// For error messages.
    label: String,
    incarnation: [u8; 16],
    /// The live root; its extent is where appends go.
    root: Root,
    /// The other slot's extent, if that root was valid: still reachable by parity
    /// fallback until the next flip, so placement must avoid it.
    prev_extent: Option<Extent>,
    /// Absolute offset of the next append.
    tail: u64,
    /// Checksum salt for the live epoch.
    salt: Salt,
}

impl<M: Medium> Journal<M> {
    /// Opens `dir/name`, creating it if absent, and replays it into a catalog.
    pub async fn open(
        medium: &M,
        dir: &str,
        name: &str,
        incarnation: [u8; 16],
    ) -> Result<(Self, Catalog), Error> {
        let file = match medium.open(dir, name).await? {
            Some(file) => file,
            None => create(medium, dir, name, incarnation).await?,
        };
        recover(file, format!("{dir}/{name}")).await
    }

    /// True if `len` more bytes of records fit the live extent.
    pub const fn fits(&self, len: u64) -> bool {
        self.tail + len <= self.root.extent.end()
    }

    /// The salt records must be encoded under to land in the live extent.
    pub const fn salt(&self) -> &Salt {
        &self.salt
    }

    /// Appends pre-encoded frames at the tail. The caller syncs.
    pub async fn append(&mut self, frames: Vec<u8>) -> Result<(), Error> {
        debug_assert!(self.fits(frames.len() as u64));
        let len = frames.len() as u64;
        self.file.write_at(self.tail, frames).await?;
        self.tail += len;
        Ok(())
    }

    /// The barrier making every prior append durable.
    pub async fn sync(&self) -> Result<(), Error> {
        self.file.sync().await
    }

    /// Writes a catalog snapshot (from [Catalog::snapshot], with its id floor) into a
    /// fresh extent and flips the root to it. Taken as records rather than `&Catalog`
    /// so the caller never holds a catalog lock across this I/O.
    pub async fn checkpoint(&mut self, records: &[Record], next_blob_id: u64) -> Result<(), Error> {
        // Encode the snapshot under the new epoch: these records live in the new
        // extent and must never validate in the old one, or vice versa.
        let epoch = self.root.epoch + 1;
        let salt = Salt::new(&self.incarnation, epoch);
        let mut snapshot = Vec::new();
        for record in records {
            record.encode(&salt, &mut snapshot);
        }

        // Size the extent for the snapshot plus slack, and place it in the lowest
        // gap not covered by either root's extent.
        let len = (snapshot.len() as u64 * EXTENT_SLACK + MAX_DRAIN_BYTES)
            .clamp(MIN_EXTENT_BYTES, MAX_EXTENT_BYTES)
            .next_multiple_of(PAGE as u64);
        if snapshot.len() as u64 > len {
            return Err(self.corrupt("catalog snapshot exceeds the maximum extent"));
        }
        let extent = self.place(len);

        // K1: the extent must be durably zero before the root names it. That is what
        // makes the first zero byte an exact end-of-log, and what kills any stale
        // bytes a previously failed checkpoint attempt left in reused space.
        write_zeros(&self.file, extent.offset, extent.len).await?;
        self.file.sync().await?;

        // K2: the complete snapshot, durable before the root that names it exists.
        let snapshot_len = snapshot.len() as u64;
        self.file.write_at(extent.offset, snapshot).await?;
        self.file.sync().await?;

        // K3: the flip. Only after this barrier does recovery see the new extent.
        let root = Root {
            seq: self.root.seq + 1,
            epoch,
            extent,
            next_blob_id,
        };
        let page = root.encode(&self.incarnation);
        self.file
            .write_at(ROOT_OFFSETS[(root.seq & 1) as usize], page)
            .await?;
        self.file.sync().await?;

        self.prev_extent = Some(self.root.extent);
        self.root = root;
        self.salt = salt;
        self.tail = extent.offset + snapshot_len;
        Ok(())
    }

    /// Lowest page-aligned gap of `len` bytes not covered by either live extent.
    fn place(&self, len: u64) -> Extent {
        let mut obstacles = vec![self.root.extent];
        if let Some(prev) = self.prev_extent {
            obstacles.push(prev);
        }
        obstacles.sort_by_key(|extent| extent.offset);
        let mut offset = RECORD_SPACE;
        for obstacle in obstacles {
            if offset + len <= obstacle.offset {
                break;
            }
            offset = offset.max(obstacle.end());
        }
        Extent { offset, len }
    }

    fn corrupt(&self, reason: &str) -> Error {
        Error::PartitionCorrupt(format!("{}: {reason}", self.label))
    }
}

/// Stages a fresh WAL file and renames it into place, durably.
async fn create<M: Medium>(
    medium: &M,
    dir: &str,
    name: &str,
    incarnation: [u8; 16],
) -> Result<M::File, Error> {
    // Sweep a staging file a crashed prior creation left behind.
    let staging = format!("{name}{STAGING_SUFFIX}");
    let _ = medium.remove(dir, &staging).await;

    let file = medium.create(dir, &staging).await?;
    file.write_at(0, Header { incarnation }.encode()).await?;
    let root = Root {
        seq: 1,
        epoch: 1,
        extent: Extent {
            offset: RECORD_SPACE,
            len: INITIAL_EXTENT_BYTES,
        },
        next_blob_id: 0,
    };
    file.write_at(
        ROOT_OFFSETS[(root.seq & 1) as usize],
        root.encode(&incarnation),
    )
    .await?;
    // The initial extent must physically exist (recovery treats end-of-file inside an
    // extent as damage) and be durably zero (exact end-of-log).
    write_zeros(&file, RECORD_SPACE, INITIAL_EXTENT_BYTES).await?;
    file.sync().await?;

    // Only a complete file ever becomes visible under the real name.
    medium.rename(dir, &staging, name).await?;
    medium.sync_dir(dir).await?;
    medium.sync_root().await?;
    Ok(file)
}

/// Recovers an existing WAL file: validates identity, picks the live root, replays
/// its extent, and scrubs the tail.
async fn recover<M: Medium>(file: M::File, label: String) -> Result<(Journal<M>, Catalog), Error> {
    let corrupt = |reason: &str| Error::PartitionCorrupt(format!("{label}: {reason}"));

    // Identity and roots. Staged creation means a visible file is complete, so every
    // validation failure here is damage, never a crash artifact.
    let size = file.size().await?;
    if size < RECORD_SPACE {
        return Err(corrupt("file shorter than its header pages"));
    }
    let pages = file.read_at(0, RECORD_SPACE as usize).await?;
    let header = Header::decode(&pages[..PAGE]).map_err(|e| corrupt(&e))?;
    let mut roots = [None, None];
    for (slot, root) in roots.iter_mut().enumerate() {
        let page = &pages[(slot + 1) * PAGE..(slot + 2) * PAGE];
        *root = Root::decode(page, &header.incarnation).map_err(|e| corrupt(&e))?;
        if let Some(decoded) = root
            && decoded.seq & 1 != slot as u64
        {
            return Err(corrupt("valid root in the wrong parity slot"));
        }
    }
    let [a, b] = roots;
    let (root, prev) = match (a, b) {
        (Some(a), Some(b)) if a.seq > b.seq => (a, Some(b)),
        (Some(a), Some(b)) => (b, Some(a)),
        (Some(a), None) => (a, None),
        (None, Some(b)) => (b, None),
        (None, None) => return Err(corrupt("no valid root")),
    };
    if root.extent.end() > size {
        // The extent was durably zeroed before the root named it, so a shorter file
        // is damage, not a crash artifact.
        return Err(corrupt("file shorter than the live extent"));
    }

    // Replay the live extent through a bounded window.
    let salt = Salt::new(&header.incarnation, root.epoch);
    let mut catalog = Catalog::new(root.next_blob_id);
    let extent = root.extent;
    let mut window: Vec<u8> = Vec::new();
    let mut window_start = extent.offset; // absolute offset of window[0]
    let mut cursor = 0usize; // consumed prefix of the window
    loop {
        // Refill whenever less than one maximum frame remains buffered.
        let buffered = window.len() - cursor;
        let fetched = window_start + window.len() as u64;
        if buffered < MAX_RECORD_LEN as usize + 8 && fetched < extent.end() {
            window.drain(..cursor);
            window_start += cursor as u64;
            cursor = 0;
            let chunk = (extent.end() - fetched).min(WINDOW_BYTES as u64) as usize;
            window.extend_from_slice(&file.read_at(fetched, chunk).await?);
            continue;
        }
        match Record::decode(&window[cursor..], &salt) {
            Frame::Record(record, consumed) => {
                catalog.apply(&record).map_err(|e| corrupt(&e))?;
                cursor += consumed;
            }
            Frame::CleanEnd | Frame::TornTail => break,
            Frame::Corrupt(reason) => return Err(corrupt(&reason)),
        }
    }
    let tail = window_start + cursor as u64;

    // Scrub: everything past the stop point within one drain of it must be zero, or
    // a fragment of a lost batch could splice onto records appended after recovery.
    // Read first, so clean recoveries write nothing; barrier only if zeros were
    // written, so replay can never walk past a post-recovery record onto remnants.
    let scrub_end = extent.end().min(tail + MAX_DRAIN_BYTES);
    let scrub = file.read_at(tail, (scrub_end - tail) as usize).await?;
    if scrub.iter().any(|&b| b != 0) {
        write_zeros(&file, tail, scrub_end - tail).await?;
        file.sync().await?;
    }

    Ok((
        Journal {
            file,
            label,
            incarnation: header.incarnation,
            root,
            prev_extent: prev.map(|p| p.extent),
            tail,
            salt,
        },
        catalog,
    ))
}

/// Writes `len` zero bytes at `offset`, in bounded chunks.
async fn write_zeros<F: super::medium::File>(file: &F, offset: u64, len: u64) -> Result<(), Error> {
    const CHUNK: u64 = 1 << 20;
    let mut written = 0;
    while written < len {
        let chunk = (len - written).min(CHUNK);
        file.write_at(offset + written, vec![0u8; chunk as usize])
            .await?;
        written += chunk;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::wal::{format::Kind, medium::Sim};

    const INCARNATION: [u8; 16] = *b"test-incarnation";

    fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
        futures::executor::block_on(future)
    }

    async fn open(sim: &Sim) -> (Journal<Sim>, Catalog) {
        Journal::open(sim, ".wal", "family.cww", INCARNATION)
            .await
            .unwrap()
    }

    fn create_record(id: u64, name: &[u8]) -> Record {
        Record::Create {
            id,
            kind: Kind::Ordinary,
            version: 1,
            partition: "p".into(),
            name: name.to_vec(),
        }
    }

    /// Encodes and appends records, then syncs (one acknowledged batch).
    async fn commit(journal: &mut Journal<Sim>, records: &[Record]) {
        let mut frames = Vec::new();
        for record in records {
            record.encode(journal.salt(), &mut frames);
        }
        assert!(journal.fits(frames.len() as u64));
        journal.append(frames).await.unwrap();
        journal.sync().await.unwrap();
    }

    #[test]
    fn fresh_journal_is_empty_and_reopens() {
        block_on(async {
            let sim = Sim::new(1);
            let (_, catalog) = open(&sim).await;
            assert!(catalog.scan("p").is_none());

            sim.crash();
            let (_, catalog) = open(&sim).await;
            assert!(catalog.scan("p").is_none());
        });
    }

    #[test]
    fn interrupted_creation_is_invisible_and_swept() {
        block_on(async {
            // Crash mid-creation, before the rename: nothing visible.
            let sim = Sim::new(2);
            let file = sim.create(".wal", "family.cww.staging").await.unwrap();
            file.write_at(0, vec![0xAB; 100]).await.unwrap();
            sim.sync_dir(".wal").await.unwrap();
            sim.sync_root().await.unwrap();
            sim.crash();
            assert!(sim.open(".wal", "family.cww").await.unwrap().is_none());

            // The next open sweeps the leftover staging file and creates cleanly.
            let (mut journal, _) = open(&sim).await;
            commit(&mut journal, &[create_record(0, b"a")]).await;
            sim.crash();
            let (_, catalog) = open(&sim).await;
            assert_eq!(catalog.scan("p").unwrap(), vec![b"a".to_vec()]);
        });
    }

    #[test]
    fn acknowledged_records_survive_any_crash() {
        for seed in 0..32 {
            block_on(async {
                let sim = Sim::new(seed);
                let (mut journal, _) = open(&sim).await;
                commit(
                    &mut journal,
                    &[create_record(0, b"a"), create_record(1, b"b")],
                )
                .await;

                // A third record is appended but never synced.
                let mut frames = Vec::new();
                create_record(2, b"c").encode(journal.salt(), &mut frames);
                journal.append(frames).await.unwrap();

                sim.crash();
                let (_, catalog) = open(&sim).await;
                // Acknowledged records always survive; the unacknowledged one is
                // indeterminate: fully applied or fully absent, never partial.
                let names = catalog.scan("p").unwrap();
                assert!(
                    names == vec![b"a".to_vec(), b"b".to_vec()]
                        || names == vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()],
                    "seed {seed}: {names:?}"
                );
            });
        }
    }

    #[test]
    fn scrub_prevents_splicing_lost_batches() {
        for seed in 0..32 {
            block_on(async {
                let sim = Sim::new(seed);
                let (mut journal, _) = open(&sim).await;
                commit(&mut journal, &[create_record(0, b"a")]).await;

                // Two unsynced batches, lost in a crash (possibly partially torn).
                let mut frames = Vec::new();
                create_record(1, b"lost-1").encode(journal.salt(), &mut frames);
                journal.append(frames).await.unwrap();
                let mut frames = Vec::new();
                create_record(2, b"lost-2").encode(journal.salt(), &mut frames);
                journal.append(frames).await.unwrap();
                sim.crash();

                // Recover, then append and acknowledge a new record.
                let (mut journal, catalog) = open(&sim).await;
                let next = catalog.next_blob_id();
                commit(&mut journal, &[create_record(next, b"new")]).await;

                // Crash again and recover: the new record must be present, and no
                // record may appear after it. Without the scrub, a surviving
                // fragment of "lost-2" could sit past "new" and splice back in.
                sim.crash();
                let (_, catalog) = open(&sim).await;
                let names = catalog.scan("p").unwrap();
                assert!(names.contains(&b"new".to_vec()), "seed {seed}: {names:?}");
                assert!(
                    !names.contains(&b"lost-2".to_vec()) || names.contains(&b"lost-1".to_vec()),
                    "seed {seed}: lost-2 cannot exist without lost-1 (prefix rule): {names:?}"
                );
            });
        }
    }

    #[test]
    fn checkpoint_round_trips_catalog() {
        block_on(async {
            let sim = Sim::new(5);
            let (mut journal, mut catalog) = open(&sim).await;
            let records = vec![
                create_record(0, b"a"),
                create_record(1, b"b"),
                Record::Partition {
                    partition: "empty".into(),
                },
            ];
            for record in &records {
                catalog.apply(record).unwrap();
            }
            commit(&mut journal, &records).await;

            journal
                .checkpoint(&catalog.snapshot(), catalog.next_blob_id())
                .await
                .unwrap();

            // Records after the checkpoint land in the new extent.
            let record = create_record(catalog.mint_id(), b"post");
            catalog.apply(&record).unwrap();
            commit(&mut journal, &[record]).await;

            sim.crash();
            let (_, recovered) = open(&sim).await;
            assert_eq!(
                recovered.scan("p").unwrap(),
                vec![b"a".to_vec(), b"b".to_vec(), b"post".to_vec()]
            );
            assert_eq!(recovered.scan("empty").unwrap(), Vec::<Vec<u8>>::new());
            assert_eq!(recovered.next_blob_id(), catalog.next_blob_id());
        });
    }

    #[test]
    fn repeated_checkpoints_reuse_space() {
        block_on(async {
            let sim = Sim::new(6);
            let (mut journal, mut catalog) = open(&sim).await;
            let record = create_record(catalog.mint_id(), b"a");
            catalog.apply(&record).unwrap();
            commit(&mut journal, &[record]).await;

            // Many flips: placement must cycle through gaps, not grow the file
            // unboundedly. With only two live extents, the file stays small.
            for _ in 0..16 {
                journal
                    .checkpoint(&catalog.snapshot(), catalog.next_blob_id())
                    .await
                    .unwrap();
            }
            let file = sim.open(".wal", "family.cww").await.unwrap().unwrap();
            let size = file.size().await.unwrap();
            assert!(size < 4 << 20, "file grew to {size}");

            sim.crash();
            let (_, recovered) = open(&sim).await;
            assert_eq!(recovered.scan("p").unwrap(), vec![b"a".to_vec()]);
        });
    }

    #[test]
    fn crash_at_any_checkpoint_step_preserves_catalog() {
        // The checkpoint's own barriers partition it into windows; crash in each.
        // Whatever survives, recovery must reproduce the acknowledged catalog: the
        // old root and extent are untouched until the flip completes, and the flip
        // is atomic through root parity.
        for fuse in 0..3u64 {
            for seed in 0..16 {
                block_on(async {
                    let sim = Sim::new(seed * 31 + fuse);
                    let (mut journal, mut catalog) = open(&sim).await;
                    let records = vec![create_record(0, b"a"), create_record(1, b"b")];
                    for record in &records {
                        catalog.apply(record).unwrap();
                    }
                    commit(&mut journal, &records).await;

                    sim.fail_syncs_after(fuse);
                    let result = journal
                        .checkpoint(&catalog.snapshot(), catalog.next_blob_id())
                        .await;
                    sim.crash();

                    let (_, recovered) = open(&sim).await;
                    assert_eq!(
                        recovered.scan("p").unwrap(),
                        vec![b"a".to_vec(), b"b".to_vec()],
                        "fuse {fuse} seed {seed} (checkpoint result: {result:?})"
                    );
                });
            }
        }
    }
}
