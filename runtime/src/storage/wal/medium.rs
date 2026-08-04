//! The I/O seam under the WAL backend: files, directory entries, and barriers.
//!
//! The WAL's correctness argument is about per-file barriers and directory durability,
//! neither of which [crate::Blob] exposes, so the backend is generic over this trait
//! instead of composing over another [crate::Storage]. The protocol is written once
//! against [Medium]; per-platform differences live in implementations below the seam.
//!
//! # Crash model
//!
//! A completed [File::sync] is a barrier for that file only: every write completed
//! through any clone of the handle before the sync began is durable. Between barriers,
//! any subset of issued writes may survive a crash, torn at arbitrary byte granularity.
//! There is no cross-file ordering. A directory entry (a file's name in its directory,
//! or a directory's name in the root) is durable only after [Medium::sync_dir] (or
//! [Medium::sync_root]) completes; until then a crash may orphan the referenced bytes.
//! Regions extended by [File::set_len] or never written read as zeros.
//!
//! # Implementations
//!
//! - [Sim]: a deterministic in-memory medium that implements the crash model exactly,
//!   for crash tests that interrupt the protocol at any point.
//! - [Checked]: a wrapper over any medium that tracks what each completed barrier
//!   covered, so tests can verify no record is admitted whose durability claims are
//!   uncovered (rule M).
//!
//! A real-filesystem medium lands with the `Storage` implementation; recovery and the
//! committer are testable entirely over [Sim].

use crate::{Error, IoBufs};
use commonware_utils::sync::Mutex;
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

/// One open file of a [Medium]. Clones share the same underlying file.
pub trait File: Clone + Send + Sync + 'static {
    /// Returns the file's current length in bytes.
    fn size(&self) -> impl Future<Output = Result<u64, Error>> + Send;

    /// Reads exactly `len` bytes at `offset`. Fails if the range extends past the
    /// file's length; holes within the length read as zeros.
    fn read_at(
        &self,
        offset: u64,
        len: usize,
    ) -> impl Future<Output = Result<Vec<u8>, Error>> + Send;

    /// Writes `data` at `offset`, extending the file as needed.
    fn write_at(
        &self,
        offset: u64,
        data: impl Into<IoBufs> + Send,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// A barrier: all writes completed through any clone before this call began are
    /// durable when it returns Ok (fdatasync semantics).
    fn sync(&self) -> impl Future<Output = Result<(), Error>> + Send;

    /// Truncates or zero-extends the file to `len`.
    fn set_len(&self, len: u64) -> impl Future<Output = Result<(), Error>> + Send;
}

/// A flat two-level file namespace with explicit durability: directories under one
/// root, files under directories.
pub trait Medium: Clone + Send + Sync + 'static {
    type File: File;

    /// Creates an empty file, and its directory if absent. Fails if the file exists.
    fn create(
        &self,
        dir: &str,
        name: &str,
    ) -> impl Future<Output = Result<Self::File, Error>> + Send;

    /// Opens an existing file, or returns None.
    fn open(
        &self,
        dir: &str,
        name: &str,
    ) -> impl Future<Output = Result<Option<Self::File>, Error>> + Send;

    /// Renames `from` to `to` within `dir`, replacing `to` if it exists.
    fn rename(
        &self,
        dir: &str,
        from: &str,
        to: &str,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Unlinks a file. Open handles keep reading the unlinked bytes.
    fn remove(&self, dir: &str, name: &str) -> impl Future<Output = Result<(), Error>> + Send;

    /// Lists file names in a directory, or None if the directory does not exist.
    fn list(&self, dir: &str) -> impl Future<Output = Result<Option<Vec<String>>, Error>> + Send;

    /// A barrier for `dir`'s entries: names created, renamed, or removed before this
    /// call began are durable when it returns Ok.
    fn sync_dir(&self, dir: &str) -> impl Future<Output = Result<(), Error>> + Send;

    /// A barrier for the root's entries (the directories themselves).
    fn sync_root(&self) -> impl Future<Output = Result<(), Error>> + Send;

    /// Reports whether a durability claim is known to hold. The default is
    /// unconditionally true; [Checked] overrides it with real tracking. Callers use
    /// this in debug assertions only, never for control flow.
    fn covered(&self, _claim: &Claim<'_>) -> bool {
        true
    }
}

/// A durability claim a WAL record makes about state outside the WAL (rule M): the
/// claimed state must have been covered by a completed barrier before the record that
/// asserts it is written.
#[derive(Debug)]
pub enum Claim<'a> {
    /// Bytes `[start, end)` of `dir/name`, as last written, are durable.
    FileBytes {
        dir: &'a str,
        name: &'a str,
        start: u64,
        end: u64,
    },
    /// The entry `dir/name` is durable in its directory.
    Dentry { dir: &'a str, name: &'a str },
    /// The directory itself is durable in the root.
    Directory { dir: &'a str },
}

fn io_error(kind: std::io::ErrorKind, message: &str) -> Error {
    Error::Io(Arc::new(std::io::Error::new(kind, message.to_string())))
}

fn missing(what: &str) -> Error {
    io_error(std::io::ErrorKind::NotFound, what)
}

/// A deterministic in-memory [Medium] implementing the crash model exactly.
///
/// [Sim::crash] replaces the state with one a real crash could produce: for every file,
/// each write since its last completed barrier independently survives, vanishes, or
/// tears at byte granularity (seeded, reproducible); every directory reverts to its
/// last-synced entries. Handles from before a crash fail all operations, forcing tests
/// through recovery.
#[derive(Clone)]
pub struct Sim {
    state: Arc<Mutex<SimState>>,
}

/// One issued-but-possibly-unsynced file mutation.
enum SimOp {
    Write { offset: u64, data: Vec<u8> },
    SetLen { len: u64 },
}

#[derive(Default)]
struct SimFile {
    /// Contents as of the last completed barrier.
    durable: Vec<u8>,
    /// Contents including all issued writes.
    live: Vec<u8>,
    /// Mutations issued since the last completed barrier, in order.
    pending: Vec<SimOp>,
}

#[derive(Default)]
struct SimDir {
    /// Entries as of the last completed directory barrier.
    durable: BTreeMap<String, u64>,
    /// Entries including all issued namespace operations.
    live: BTreeMap<String, u64>,
}

struct SimState {
    rng: u64,
    /// Completed file barriers, for tests asserting group commit collapses them.
    syncs: u64,
    /// Post-crash handle invalidation: handles remember the epoch they were opened in.
    epoch: u64,
    /// Barriers left before every barrier fails (fault injection); None = never fail.
    sync_fuse: Option<u64>,
    next_file: u64,
    files: BTreeMap<u64, SimFile>,
    dirs: BTreeMap<String, SimDir>,
    /// Directory names as of the last completed root barrier.
    root_durable: BTreeMap<String, ()>,
}

impl SimState {
    /// Burns one barrier off the fuse; errors once it is spent. A failed barrier
    /// makes nothing durable.
    fn burn_fuse(&mut self) -> Result<(), Error> {
        match &mut self.sync_fuse {
            None => Ok(()),
            Some(0) => Err(io_error(
                std::io::ErrorKind::Other,
                "simulated barrier failure",
            )),
            Some(n) => {
                *n -= 1;
                Ok(())
            }
        }
    }

    /// SplitMix64: deterministic, dependency-free.
    const fn next_rand(&mut self) -> u64 {
        self.rng = self.rng.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
}

impl Sim {
    /// Creates an empty simulated medium whose crash outcomes derive from `seed`.
    pub fn new(seed: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(SimState {
                rng: seed,
                syncs: 0,
                epoch: 0,
                sync_fuse: None,
                next_file: 0,
                files: BTreeMap::new(),
                dirs: BTreeMap::new(),
                root_durable: BTreeMap::new(),
            })),
        }
    }

    /// Completed file barriers so far.
    pub fn sync_count(&self) -> u64 {
        self.state.lock().syncs
    }

    /// After `n` more successful barriers, every barrier (file, directory, or root)
    /// fails, making nothing durable: fault injection for crash-window tests.
    pub fn fail_syncs_after(&self, n: u64) {
        self.state.lock().sync_fuse = Some(n);
    }

    /// Simulates a crash: every unsynced mutation independently survives, vanishes, or
    /// tears; unsynced namespace operations revert. Existing handles become unusable;
    /// reopen everything, as recovery would. Clears any barrier fuse (a fresh process
    /// starts with a healthy device).
    pub fn crash(&self) {
        let mut state = self.state.lock();
        state.epoch += 1;
        state.sync_fuse = None;

        // Settle each file: replay pending ops onto the durable image with a random
        // per-op fate. A torn write keeps a random subset of its bytes, in runs, which
        // is the arbitrary-granularity tearing the crash model allows.
        let ids: Vec<u64> = state.files.keys().copied().collect();
        for id in ids {
            let mut file = state.files.remove(&id).unwrap();
            let ops = std::mem::take(&mut file.pending);
            let mut image = std::mem::take(&mut file.durable);
            for op in ops {
                match op {
                    SimOp::Write { offset, data } => {
                        match state.next_rand() % 3 {
                            0 => {}                                     // lost entirely
                            1 => write_into(&mut image, offset, &data), // fully survived
                            _ => {
                                // Torn: keep random runs of bytes.
                                let mut pos = 0usize;
                                while pos < data.len() {
                                    let run = 1 + (state.next_rand() as usize % 64);
                                    let end = (pos + run).min(data.len());
                                    if state.next_rand().is_multiple_of(2) {
                                        write_into(
                                            &mut image,
                                            offset + pos as u64,
                                            &data[pos..end],
                                        );
                                    }
                                    pos = end;
                                }
                            }
                        }
                    }
                    // Length changes are atomic in the model: survive whole or not.
                    SimOp::SetLen { len } => {
                        if state.next_rand().is_multiple_of(2) {
                            image.resize(len as usize, 0);
                        }
                    }
                }
            }
            state.files.insert(
                id,
                SimFile {
                    live: image.clone(),
                    durable: image,
                    pending: Vec::new(),
                },
            );
        }

        // Directories revert to their durable entries; the root reverts too, dropping
        // directories (and orphaning their files) whose creation was never synced.
        let root_durable = state.root_durable.clone();
        state.dirs.retain(|name, _| root_durable.contains_key(name));
        for dir in state.dirs.values_mut() {
            dir.live = dir.durable.clone();
        }
    }

    /// Returns the durable length of `dir/name` right now, for test assertions.
    #[cfg(test)]
    fn durable_len(&self, dir: &str, name: &str) -> Option<u64> {
        let state = self.state.lock();
        let id = *state.dirs.get(dir)?.durable.get(name)?;
        Some(state.files.get(&id)?.durable.len() as u64)
    }
}

/// Writes `data` into `image` at `offset`, zero-extending any gap.
fn write_into(image: &mut Vec<u8>, offset: u64, data: &[u8]) {
    let offset = offset as usize;
    let end = offset + data.len();
    if image.len() < end {
        image.resize(end, 0);
    }
    image[offset..end].copy_from_slice(data);
}

/// A handle to one simulated file.
#[derive(Clone)]
pub struct SimFileHandle {
    state: Arc<Mutex<SimState>>,
    id: u64,
    epoch: u64,
}

impl SimFileHandle {
    /// Fails the operation if the handle predates a crash.
    fn check_epoch(&self, state: &SimState) -> Result<(), Error> {
        if state.epoch != self.epoch {
            return Err(io_error(
                std::io::ErrorKind::Other,
                "handle predates a simulated crash",
            ));
        }
        Ok(())
    }
}

impl File for SimFileHandle {
    async fn size(&self) -> Result<u64, Error> {
        let state = self.state.lock();
        self.check_epoch(&state)?;
        let file = state.files.get(&self.id).ok_or_else(|| missing("file"))?;
        Ok(file.live.len() as u64)
    }

    async fn read_at(&self, offset: u64, len: usize) -> Result<Vec<u8>, Error> {
        let state = self.state.lock();
        self.check_epoch(&state)?;
        let file = state.files.get(&self.id).ok_or_else(|| missing("file"))?;
        let end = offset
            .checked_add(len as u64)
            .ok_or(Error::OffsetOverflow)?;
        if end > file.live.len() as u64 {
            return Err(Error::BlobInsufficientLength);
        }
        Ok(file.live[offset as usize..end as usize].to_vec())
    }

    async fn write_at(&self, offset: u64, data: impl Into<IoBufs> + Send) -> Result<(), Error> {
        let data: Vec<u8> = data.into().coalesce().as_ref().to_vec();
        // An empty write changes nothing, not even the length.
        if data.is_empty() {
            return Ok(());
        }
        let mut state = self.state.lock();
        self.check_epoch(&state)?;
        offset
            .checked_add(data.len() as u64)
            .ok_or(Error::OffsetOverflow)?;
        let file = state
            .files
            .get_mut(&self.id)
            .ok_or_else(|| missing("file"))?;
        write_into(&mut file.live, offset, &data);
        file.pending.push(SimOp::Write { offset, data });
        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
        let mut state = self.state.lock();
        self.check_epoch(&state)?;
        state.burn_fuse()?;
        state.syncs += 1;
        let file = state
            .files
            .get_mut(&self.id)
            .ok_or_else(|| missing("file"))?;
        file.durable = file.live.clone();
        file.pending.clear();
        Ok(())
    }

    async fn set_len(&self, len: u64) -> Result<(), Error> {
        let mut state = self.state.lock();
        self.check_epoch(&state)?;
        let file = state
            .files
            .get_mut(&self.id)
            .ok_or_else(|| missing("file"))?;
        file.live.resize(len as usize, 0);
        file.pending.push(SimOp::SetLen { len });
        Ok(())
    }
}

impl Medium for Sim {
    type File = SimFileHandle;

    async fn create(&self, dir: &str, name: &str) -> Result<Self::File, Error> {
        let mut state = self.state.lock();
        let epoch = state.epoch;
        let id = state.next_file;
        let entry = state.dirs.entry(dir.to_string()).or_default();
        if entry.live.contains_key(name) {
            return Err(io_error(std::io::ErrorKind::AlreadyExists, "file exists"));
        }
        entry.live.insert(name.to_string(), id);
        state.next_file += 1;
        state.files.insert(id, SimFile::default());
        Ok(SimFileHandle {
            state: self.state.clone(),
            id,
            epoch,
        })
    }

    async fn open(&self, dir: &str, name: &str) -> Result<Option<Self::File>, Error> {
        let state = self.state.lock();
        let Some(entry) = state.dirs.get(dir) else {
            return Ok(None);
        };
        let Some(&id) = entry.live.get(name) else {
            return Ok(None);
        };
        Ok(Some(SimFileHandle {
            state: self.state.clone(),
            id,
            epoch: state.epoch,
        }))
    }

    async fn rename(&self, dir: &str, from: &str, to: &str) -> Result<(), Error> {
        let mut state = self.state.lock();
        let entry = state
            .dirs
            .get_mut(dir)
            .ok_or_else(|| missing("directory"))?;
        let id = entry.live.remove(from).ok_or_else(|| missing("file"))?;
        entry.live.insert(to.to_string(), id);
        Ok(())
    }

    async fn remove(&self, dir: &str, name: &str) -> Result<(), Error> {
        let mut state = self.state.lock();
        let entry = state
            .dirs
            .get_mut(dir)
            .ok_or_else(|| missing("directory"))?;
        entry.live.remove(name).ok_or_else(|| missing("file"))?;
        Ok(())
    }

    async fn list(&self, dir: &str) -> Result<Option<Vec<String>>, Error> {
        let state = self.state.lock();
        Ok(state
            .dirs
            .get(dir)
            .map(|entry| entry.live.keys().cloned().collect()))
    }

    async fn sync_dir(&self, dir: &str) -> Result<(), Error> {
        let mut state = self.state.lock();
        state.burn_fuse()?;
        let entry = state
            .dirs
            .get_mut(dir)
            .ok_or_else(|| missing("directory"))?;
        entry.durable = entry.live.clone();
        Ok(())
    }

    async fn sync_root(&self) -> Result<(), Error> {
        let mut state = self.state.lock();
        state.burn_fuse()?;
        let names: Vec<String> = state.dirs.keys().cloned().collect();
        for name in names {
            state.root_durable.insert(name, ());
        }
        Ok(())
    }
}

/// A [Medium] wrapper that tracks what every completed barrier covered, making rule M
/// machine-checkable: [Medium::covered] answers whether a claim's state was durable, at
/// the content generation the claimant last wrote, when the last barrier completed.
///
/// Composes over [Sim] in crash tests and over a real filesystem in integration tests.
#[derive(Clone)]
pub struct Checked<M: Medium> {
    inner: M,
    tracker: Arc<Tracker>,
}

struct Tracker {
    /// Monotonic mutation stamps, shared by files and directories.
    next_gen: AtomicU64,
    state: Mutex<TrackState>,
}

#[derive(Default)]
struct TrackState {
    next_file: u64,
    files: BTreeMap<u64, FileTrack>,
    dirs: BTreeMap<String, DirTrack>,
    /// Directory name -> creation generation; covered once root_synced_gen passes it.
    root_entries: BTreeMap<String, u64>,
    root_synced_gen: u64,
}

#[derive(Default)]
struct FileTrack {
    /// Written intervals: start -> (end, generation of last write).
    writes: BTreeMap<u64, (u64, u64)>,
    /// Live length and the generation that last changed it.
    len: u64,
    len_gen: u64,
    /// Highest generation covered by a completed barrier, and the length then.
    synced_gen: u64,
    synced_len: u64,
}

#[derive(Default)]
struct DirTrack {
    /// Entry name -> (file id, generation the entry last changed).
    entries: BTreeMap<String, (u64, u64)>,
    synced_gen: u64,
}

impl FileTrack {
    /// Stamps `[start, end)` as written at `stamp`, splitting overlapped intervals.
    fn record_write(&mut self, start: u64, end: u64, stamp: u64) {
        // Every interval starting below `end` that also reaches past `start` overlaps.
        let overlapping: Vec<u64> = self
            .writes
            .range(..end)
            .filter(|&(_, &(e, _))| e > start)
            .map(|(&s, _)| s)
            .collect();
        for s in overlapping {
            let (e, g) = self.writes.remove(&s).unwrap();
            if s < start {
                self.writes.insert(s, (start, g));
            }
            if e > end {
                self.writes.insert(end, (e, g));
            }
        }
        self.writes.insert(start, (end, stamp));
        if end > self.len {
            self.len = end;
            self.len_gen = stamp;
        }
    }

    /// True if every byte of `[start, end)` exists now and was durable, as last
    /// written, at the last completed barrier: within both the live and synced lengths
    /// (a truncated range no longer exists; an unsynced extension is not durable), and
    /// with no overlapping write newer than the barrier. Unwritten bytes within those
    /// lengths are durable zeros.
    fn covers(&self, start: u64, end: u64) -> bool {
        if end > self.len.min(self.synced_len) {
            return false;
        }
        self.writes
            .range(..end)
            .filter(|&(&s, &(e, _))| s < end && e > start)
            .all(|(_, &(_, stamp))| stamp <= self.synced_gen)
    }
}

impl<M: Medium> Checked<M> {
    /// Wraps `inner` with rule-M coverage tracking.
    pub fn new(inner: M) -> Self {
        Self {
            inner,
            tracker: Arc::new(Tracker {
                next_gen: AtomicU64::new(1),
                state: Mutex::new(TrackState::default()),
            }),
        }
    }
}

impl Tracker {
    fn stamp(&self) -> u64 {
        self.next_gen.fetch_add(1, Ordering::Relaxed)
    }

    /// Resolves a (dir, name) entry to its tracked file id.
    fn resolve(state: &TrackState, dir: &str, name: &str) -> Option<u64> {
        Some(state.dirs.get(dir)?.entries.get(name)?.0)
    }
}

/// A handle to one file of a [Checked] medium.
#[derive(Clone)]
pub struct CheckedFile<M: Medium> {
    inner: M::File,
    tracker: Arc<Tracker>,
    id: u64,
}

impl<M: Medium> File for CheckedFile<M> {
    async fn size(&self) -> Result<u64, Error> {
        self.inner.size().await
    }

    async fn read_at(&self, offset: u64, len: usize) -> Result<Vec<u8>, Error> {
        self.inner.read_at(offset, len).await
    }

    async fn write_at(&self, offset: u64, data: impl Into<IoBufs> + Send) -> Result<(), Error> {
        let data = data.into();
        let len = data.len() as u64;
        self.inner.write_at(offset, data).await?;
        let stamp = self.tracker.stamp();
        let mut state = self.tracker.state.lock();
        if let Some(track) = state.files.get_mut(&self.id) {
            track.record_write(offset, offset + len, stamp);
        }
        Ok(())
    }

    async fn sync(&self) -> Result<(), Error> {
        // Snapshot the generation counter before issuing: a write racing this barrier
        // is not guaranteed covered, so it must not be marked covered.
        let stamp = self.tracker.next_gen.load(Ordering::Relaxed) - 1;
        self.inner.sync().await?;
        let mut state = self.tracker.state.lock();
        if let Some(track) = state.files.get_mut(&self.id) {
            track.synced_gen = track.synced_gen.max(stamp);
            if track.len_gen <= stamp {
                track.synced_len = track.len;
            }
        }
        Ok(())
    }

    async fn set_len(&self, len: u64) -> Result<(), Error> {
        self.inner.set_len(len).await?;
        let stamp = self.tracker.stamp();
        let mut state = self.tracker.state.lock();
        if let Some(track) = state.files.get_mut(&self.id) {
            // Truncation invalidates written intervals beyond the new length.
            if len < track.len {
                let cut: Vec<u64> = track
                    .writes
                    .range(..)
                    .filter(|&(&s, &(e, _))| e > len && s >= len)
                    .map(|(&s, _)| s)
                    .collect();
                for s in cut {
                    track.writes.remove(&s);
                }
                let straddling: Vec<u64> = track
                    .writes
                    .range(..len)
                    .filter(|&(_, &(e, _))| e > len)
                    .map(|(&s, _)| s)
                    .collect();
                for s in straddling {
                    let (_, g) = track.writes.remove(&s).unwrap();
                    track.writes.insert(s, (len, g));
                }
            }
            track.len = len;
            track.len_gen = stamp;
        }
        Ok(())
    }
}

impl<M: Medium> Medium for Checked<M> {
    type File = CheckedFile<M>;

    async fn create(&self, dir: &str, name: &str) -> Result<Self::File, Error> {
        let inner = self.inner.create(dir, name).await?;
        let stamp = self.tracker.stamp();
        let mut state = self.tracker.state.lock();
        let id = state.next_file;
        state.next_file += 1;
        state.files.insert(id, FileTrack::default());
        let root_gen = self.tracker.next_gen.fetch_add(1, Ordering::Relaxed);
        state
            .root_entries
            .entry(dir.to_string())
            .or_insert(root_gen);
        state
            .dirs
            .entry(dir.to_string())
            .or_default()
            .entries
            .insert(name.to_string(), (id, stamp));
        Ok(CheckedFile {
            inner,
            tracker: self.tracker.clone(),
            id,
        })
    }

    async fn open(&self, dir: &str, name: &str) -> Result<Option<Self::File>, Error> {
        let Some(inner) = self.inner.open(dir, name).await? else {
            return Ok(None);
        };
        let size = inner.size().await?;
        let mut state = self.tracker.state.lock();
        // A file the wrapper never saw created predates the wrapper: its existing
        // content counts as covered (the wrapper can only judge what it observed).
        let resolved = Tracker::resolve(&state, dir, name);
        let id = resolved.unwrap_or_else(|| {
            let id = state.next_file;
            state.next_file += 1;
            state.files.insert(
                id,
                FileTrack {
                    len: size,
                    synced_len: size,
                    ..FileTrack::default()
                },
            );
            state
                .dirs
                .entry(dir.to_string())
                .or_default()
                .entries
                .insert(name.to_string(), (id, 0));
            id
        });
        Ok(Some(CheckedFile {
            inner,
            tracker: self.tracker.clone(),
            id,
        }))
    }

    async fn rename(&self, dir: &str, from: &str, to: &str) -> Result<(), Error> {
        self.inner.rename(dir, from, to).await?;
        let stamp = self.tracker.stamp();
        let mut state = self.tracker.state.lock();
        if let Some(track) = state.dirs.get_mut(dir)
            && let Some((id, _)) = track.entries.remove(from)
        {
            // The destination entry is new until the next directory barrier; the
            // file's content coverage travels with it (same inode).
            track.entries.insert(to.to_string(), (id, stamp));
        }
        Ok(())
    }

    async fn remove(&self, dir: &str, name: &str) -> Result<(), Error> {
        self.inner.remove(dir, name).await?;
        let mut state = self.tracker.state.lock();
        if let Some(track) = state.dirs.get_mut(dir) {
            track.entries.remove(name);
        }
        Ok(())
    }

    async fn list(&self, dir: &str) -> Result<Option<Vec<String>>, Error> {
        self.inner.list(dir).await
    }

    async fn sync_dir(&self, dir: &str) -> Result<(), Error> {
        let stamp = self.tracker.next_gen.load(Ordering::Relaxed) - 1;
        self.inner.sync_dir(dir).await?;
        let mut state = self.tracker.state.lock();
        if let Some(track) = state.dirs.get_mut(dir) {
            track.synced_gen = track.synced_gen.max(stamp);
        }
        Ok(())
    }

    async fn sync_root(&self) -> Result<(), Error> {
        let stamp = self.tracker.next_gen.load(Ordering::Relaxed) - 1;
        self.inner.sync_root().await?;
        let mut state = self.tracker.state.lock();
        state.root_synced_gen = state.root_synced_gen.max(stamp);
        Ok(())
    }

    fn covered(&self, claim: &Claim<'_>) -> bool {
        let state = self.tracker.state.lock();
        match claim {
            Claim::FileBytes {
                dir,
                name,
                start,
                end,
            } => {
                let Some(id) = Tracker::resolve(&state, dir, name) else {
                    return false;
                };
                state
                    .files
                    .get(&id)
                    .is_some_and(|track| track.covers(*start, *end))
            }
            Claim::Dentry { dir, name } => state.dirs.get(*dir).is_some_and(|track| {
                track
                    .entries
                    .get(*name)
                    .is_some_and(|&(_, stamp)| stamp <= track.synced_gen)
            }),
            Claim::Directory { dir } => state
                .root_entries
                .get(*dir)
                .is_some_and(|&stamp| stamp <= state.root_synced_gen),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block_on<F: Future>(future: F) -> F::Output {
        futures::executor::block_on(future)
    }

    #[test]
    fn sim_barrier_makes_writes_durable() {
        block_on(async {
            let sim = Sim::new(7);
            let file = sim.create("dir", "a").await.unwrap();
            file.write_at(0, vec![1u8; 100]).await.unwrap();
            file.sync().await.unwrap();
            sim.sync_dir("dir").await.unwrap();
            sim.sync_root().await.unwrap();
            file.write_at(100, vec![2u8; 100]).await.unwrap();

            sim.crash();
            let file = sim.open("dir", "a").await.unwrap().unwrap();
            let bytes = file.read_at(0, 100).await.unwrap();
            assert_eq!(bytes, vec![1u8; 100]);
            // The unsynced write may or may not have (partially) survived, but the
            // synced prefix is intact under every outcome.
        });
    }

    #[test]
    fn sim_unsynced_writes_can_tear() {
        // Across seeds, unsynced writes must produce at least one full survival, one
        // full loss, and one tear: the model spans the whole outcome space.
        let (mut survived, mut lost, mut torn) = (false, false, false);
        for seed in 0..64 {
            block_on(async {
                let sim = Sim::new(seed);
                let file = sim.create("dir", "a").await.unwrap();
                file.sync().await.unwrap();
                sim.sync_dir("dir").await.unwrap();
                sim.sync_root().await.unwrap();
                file.write_at(0, vec![0xAA; 256]).await.unwrap();
                sim.crash();
                let file = sim.open("dir", "a").await.unwrap().unwrap();
                let size = file.size().await.unwrap();
                let bytes = if size == 0 {
                    Vec::new()
                } else {
                    file.read_at(0, size as usize).await.unwrap()
                };
                let written = bytes.iter().filter(|&&b| b == 0xAA).count();
                match written {
                    0 => lost = true,
                    256 => survived = true,
                    _ => torn = true,
                }
            });
        }
        assert!(survived && lost && torn);
    }

    #[test]
    fn sim_unsynced_dentry_reverts() {
        block_on(async {
            let sim = Sim::new(3);
            let file = sim.create("dir", "synced").await.unwrap();
            file.sync().await.unwrap();
            sim.sync_dir("dir").await.unwrap();
            sim.sync_root().await.unwrap();
            sim.create("dir", "unsynced").await.unwrap();

            sim.crash();
            assert!(sim.open("dir", "synced").await.unwrap().is_some());
            assert!(sim.open("dir", "unsynced").await.unwrap().is_none());
        });
    }

    #[test]
    fn sim_unsynced_directory_orphans_contents() {
        block_on(async {
            let sim = Sim::new(3);
            let file = sim.create("dir", "a").await.unwrap();
            file.sync().await.unwrap();
            sim.sync_dir("dir").await.unwrap();
            // Root never synced: the directory itself is not durable.
            sim.crash();
            assert!(sim.open("dir", "a").await.unwrap().is_none());
            assert!(sim.list("dir").await.unwrap().is_none());
        });
    }

    #[test]
    fn sim_stale_handles_fail_after_crash() {
        block_on(async {
            let sim = Sim::new(1);
            let file = sim.create("dir", "a").await.unwrap();
            sim.crash();
            assert!(file.read_at(0, 0).await.is_err());
            assert!(file.write_at(0, vec![1]).await.is_err());
            assert!(file.sync().await.is_err());
        });
    }

    #[test]
    fn sim_rename_replaces_destination() {
        block_on(async {
            let sim = Sim::new(1);
            let a = sim.create("dir", "a").await.unwrap();
            a.write_at(0, vec![1u8; 4]).await.unwrap();
            let b = sim.create("dir", "b").await.unwrap();
            b.write_at(0, vec![2u8; 4]).await.unwrap();
            sim.rename("dir", "a", "b").await.unwrap();
            let opened = sim.open("dir", "b").await.unwrap().unwrap();
            assert_eq!(opened.read_at(0, 4).await.unwrap(), vec![1u8; 4]);
            assert!(sim.open("dir", "a").await.unwrap().is_none());
        });
    }

    #[test]
    fn sim_durable_len_tracks_barriers() {
        block_on(async {
            let sim = Sim::new(1);
            let file = sim.create("dir", "a").await.unwrap();
            file.write_at(0, vec![1u8; 10]).await.unwrap();
            assert_eq!(sim.durable_len("dir", "a"), None); // dentry not durable yet
            file.sync().await.unwrap();
            sim.sync_dir("dir").await.unwrap();
            assert_eq!(sim.durable_len("dir", "a"), Some(10));
            file.write_at(10, vec![2u8; 10]).await.unwrap();
            assert_eq!(sim.durable_len("dir", "a"), Some(10));
        });
    }

    #[test]
    fn sim_failed_barrier_makes_nothing_durable() {
        block_on(async {
            let sim = Sim::new(4);
            let file = sim.create("dir", "a").await.unwrap();
            file.sync().await.unwrap();
            sim.sync_dir("dir").await.unwrap();
            sim.sync_root().await.unwrap();

            file.write_at(0, vec![7u8; 10]).await.unwrap();
            sim.fail_syncs_after(0);
            assert!(file.sync().await.is_err());
            sim.crash();
            // The failed barrier conferred nothing; the write may still have torn
            // through, but the file must exist and never exceed the written range.
            let file = sim.open("dir", "a").await.unwrap().unwrap();
            assert!(file.size().await.unwrap() <= 10);
        });
    }

    #[test]
    fn checked_uncovered_until_barrier() {
        block_on(async {
            let medium = Checked::new(Sim::new(1));
            let file = medium.create("dir", "a").await.unwrap();
            file.write_at(0, vec![1u8; 100]).await.unwrap();

            let bytes = Claim::FileBytes {
                dir: "dir",
                name: "a",
                start: 0,
                end: 100,
            };
            assert!(!medium.covered(&bytes));
            file.sync().await.unwrap();
            assert!(medium.covered(&bytes));
        });
    }

    #[test]
    fn checked_rewrite_invalidates_coverage() {
        block_on(async {
            let medium = Checked::new(Sim::new(1));
            let file = medium.create("dir", "a").await.unwrap();
            file.write_at(0, vec![1u8; 100]).await.unwrap();
            file.sync().await.unwrap();

            // Rewriting a covered range at a newer generation uncovers it: this is
            // exactly the staleness an offset-only tracker would miss.
            file.write_at(40, vec![2u8; 10]).await.unwrap();
            let stale = Claim::FileBytes {
                dir: "dir",
                name: "a",
                start: 0,
                end: 100,
            };
            let untouched = Claim::FileBytes {
                dir: "dir",
                name: "a",
                start: 0,
                end: 40,
            };
            assert!(!medium.covered(&stale));
            assert!(medium.covered(&untouched));
            file.sync().await.unwrap();
            assert!(medium.covered(&stale));
        });
    }

    #[test]
    fn checked_holes_within_synced_length_are_covered() {
        block_on(async {
            let medium = Checked::new(Sim::new(1));
            let file = medium.create("dir", "a").await.unwrap();
            file.set_len(100).await.unwrap();
            file.write_at(90, vec![1u8; 10]).await.unwrap();
            file.sync().await.unwrap();
            // Bytes [0, 90) were never written: durable zeros within the length.
            assert!(medium.covered(&Claim::FileBytes {
                dir: "dir",
                name: "a",
                start: 0,
                end: 100,
            }));
            // Beyond the synced length is never covered.
            assert!(!medium.covered(&Claim::FileBytes {
                dir: "dir",
                name: "a",
                start: 0,
                end: 101,
            }));
        });
    }

    #[test]
    fn checked_dentry_and_directory_claims() {
        block_on(async {
            let medium = Checked::new(Sim::new(1));
            medium.create("dir", "a").await.unwrap();

            let dentry = Claim::Dentry {
                dir: "dir",
                name: "a",
            };
            let directory = Claim::Directory { dir: "dir" };
            assert!(!medium.covered(&dentry));
            assert!(!medium.covered(&directory));
            medium.sync_dir("dir").await.unwrap();
            assert!(medium.covered(&dentry));
            medium.sync_root().await.unwrap();
            assert!(medium.covered(&directory));
        });
    }

    #[test]
    fn checked_rename_moves_content_coverage_resets_dentry() {
        block_on(async {
            let medium = Checked::new(Sim::new(1));
            let file = medium.create("dir", "tmp").await.unwrap();
            file.write_at(0, vec![1u8; 50]).await.unwrap();
            file.sync().await.unwrap();
            medium.sync_dir("dir").await.unwrap();

            medium.rename("dir", "tmp", "final").await.unwrap();
            // Content coverage travels with the inode; the new dentry does not.
            assert!(medium.covered(&Claim::FileBytes {
                dir: "dir",
                name: "final",
                start: 0,
                end: 50,
            }));
            assert!(!medium.covered(&Claim::Dentry {
                dir: "dir",
                name: "final",
            }));
            medium.sync_dir("dir").await.unwrap();
            assert!(medium.covered(&Claim::Dentry {
                dir: "dir",
                name: "final",
            }));
        });
    }

    #[test]
    fn checked_truncate_uncovers_tail() {
        block_on(async {
            let medium = Checked::new(Sim::new(1));
            let file = medium.create("dir", "a").await.unwrap();
            file.write_at(0, vec![1u8; 100]).await.unwrap();
            file.sync().await.unwrap();
            file.set_len(50).await.unwrap();
            // The old full range is no longer within the durable length story.
            assert!(!medium.covered(&Claim::FileBytes {
                dir: "dir",
                name: "a",
                start: 0,
                end: 100,
            }));
            file.sync().await.unwrap();
            assert!(medium.covered(&Claim::FileBytes {
                dir: "dir",
                name: "a",
                start: 0,
                end: 50,
            }));
        });
    }
}
