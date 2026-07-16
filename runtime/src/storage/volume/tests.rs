//! Volume tests: the generic storage contract suite, plus a torn-write
//! power-loss harness that exercises the recovery protocol end-to-end (the
//! runtime-level counterpart of the exhaustive `model` module).

use super::{Config, Storage as Volume, BLOCK};
use crate::{
    storage::{memory, tests::run_storage_tests},
    telemetry::metrics::Registry,
    Blob as _, BufferPool, BufferPoolConfig, Error, IoBuf, IoBufMut, IoBufs, IoBufsMut,
    Storage as _,
};
use bytes::Buf as _;
use commonware_utils::{sync::Mutex, TestRng};
use rand::{Rng as _, RngExt as _};
use std::{collections::BTreeMap, sync::Arc};

fn test_pool() -> BufferPool {
    let mut registry = Registry::default();
    BufferPool::new(BufferPoolConfig::for_storage(), &mut registry)
}

fn volume_over_memory() -> Volume<memory::Storage> {
    let pool = test_pool();
    Volume::new(memory::Storage::new(pool.clone()), pool, Config::default())
}

#[tokio::test]
async fn test_volume_storage_contract() {
    run_storage_tests(volume_over_memory()).await;
}

/// Log of inner blob I/O: (write?, offset, len).
type IoLog = Arc<Mutex<Vec<(bool, u64, usize)>>>;

/// An inner storage wrapper recording every read and write the volume issues
/// to the volume file, plus the buffer address of every `read_at_buf` (to
/// pin that caller buffers reach the inner blob directly, without a pool
/// scratch buffer in between).
#[derive(Clone)]
struct Recording {
    inner: memory::Storage,
    log: IoLog,
    buf_ptrs: Arc<Mutex<Vec<usize>>>,
}

impl Recording {
    fn new(pool: BufferPool) -> Self {
        Self {
            inner: memory::Storage::new(pool),
            log: Arc::new(Mutex::new(Vec::new())),
            buf_ptrs: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl crate::Storage for Recording {
    type Blob = RecordingBlob;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: std::ops::RangeInclusive<u16>,
    ) -> Result<(Self::Blob, u64, u16), Error> {
        let (blob, len, version) = self.inner.open_versioned(partition, name, versions).await?;
        Ok((
            RecordingBlob {
                inner: blob,
                log: self.log.clone(),
                buf_ptrs: self.buf_ptrs.clone(),
            },
            len,
            version,
        ))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        self.inner.remove(partition, name).await
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        self.inner.scan(partition).await
    }
}

#[derive(Clone)]
struct RecordingBlob {
    inner: memory::Blob,
    log: IoLog,
    buf_ptrs: Arc<Mutex<Vec<usize>>>,
}

impl crate::Blob for RecordingBlob {
    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        self.log.lock().push((false, offset, len));
        self.inner.read_at(offset, len).await
    }

    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        self.log.lock().push((false, offset, len));
        let bufs = bufs.into();
        self.buf_ptrs.lock().push(bufs.chunk().as_ptr() as usize);
        self.inner.read_at_buf(offset, len, bufs).await
    }

    async fn write_at(&self, offset: u64, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        let buf = bufs.into().coalesce();
        self.log.lock().push((true, offset, buf.len()));
        self.inner.write_at(offset, buf).await
    }

    async fn write_at_sync(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        self.write_at(offset, bufs).await?;
        self.sync().await
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        self.inner.resize(len).await
    }

    async fn sync(&self) -> Result<(), Error> {
        self.inner.sync().await
    }

    async fn start_sync(&self) -> crate::Handle<()> {
        crate::Handle::ready(self.sync().await)
    }
}

/// A physically contiguous committed span is served by ONE coalesced inner
/// read of exactly the requested bytes, not one read per chunk.
#[tokio::test]
async fn test_volume_read_coalescing() {
    let pool = test_pool();
    let recording = Recording::new(pool.clone());
    let volume = Volume::new(recording.clone(), pool.clone(), Config::default());

    let span = 16 * BLOCK as usize;
    let (big, _) = volume.open("p", b"big").await.unwrap();
    big.write_at(0, IoBuf::copy_from_slice(&vec![3u8; span]))
        .await
        .unwrap();
    big.sync().await.unwrap();

    let reads_before = recording.log.lock().iter().filter(|(w, _, _)| !*w).count();
    let got = big.read_at(0, span).await.unwrap().coalesce();
    assert_eq!(got.as_ref(), &vec![3u8; span][..]);
    let log = recording.log.lock();
    let new_reads: Vec<_> = log
        .iter()
        .filter(|(w, _, _)| !*w)
        .skip(reads_before)
        .collect();
    assert_eq!(
        new_reads.len(),
        1,
        "contiguous chunks must coalesce into one inner read: {new_reads:?}"
    );
    assert_eq!(new_reads[0].2, span, "coalesced read length");
}

/// A growth quantum provisions the volume file in coarse steps; growth stays
/// automatic and unbounded, and provisioning survives reopen.
#[tokio::test]
async fn test_volume_growth_quantum() {
    let pool = test_pool();
    let inner = memory::Storage::new(pool.clone());
    let quantum = 16 * BLOCK;
    let cfg = Config {
        growth_quantum: quantum,
        ..Config::default()
    };
    let volume = Volume::new(inner.clone(), pool.clone(), cfg.clone());

    // One tiny write provisions a whole quantum (growth is physical: the
    // file grows with allocated extents, not logical offsets).
    let (blob, _) = volume.open("p", b"b").await.unwrap();
    blob.write_at(0, IoBuf::copy_from_slice(b"x"))
        .await
        .unwrap();
    blob.sync().await.unwrap();
    let (_, len) = inner.open(&cfg.partition, &cfg.name).await.unwrap();
    assert_eq!(len, quantum);

    // Exceeding a quantum of physical data provisions the next one.
    blob.write_at(1, IoBuf::copy_from_slice(&vec![7u8; quantum as usize]))
        .await
        .unwrap();
    blob.sync().await.unwrap();
    let (_, len) = inner.open(&cfg.partition, &cfg.name).await.unwrap();
    assert_eq!(len, 2 * quantum);
    drop(blob);
    drop(volume);

    // Reopen: the provisioned tail is not mistaken for data, and content
    // survives.
    let volume = Volume::new(inner, pool, cfg);
    let (blob, size) = volume.open("p", b"b").await.unwrap();
    assert_eq!(size, quantum + 1);
    let got = blob.read_at(0, 2).await.unwrap().coalesce();
    assert_eq!(got.as_ref(), &[b'x', 7]);
    let got = blob.read_at(quantum, 1).await.unwrap().coalesce();
    assert_eq!(got.as_ref(), &[7]);
}

/// Eager init runs recovery up front and round-trips across reopen.
#[tokio::test]
async fn test_volume_eager_init() {
    let pool = test_pool();
    let inner = memory::Storage::new(pool.clone());
    let volume = Volume::init(inner.clone(), pool.clone(), Config::default())
        .await
        .unwrap();
    let (blob, _) = volume.open("p", b"b").await.unwrap();
    blob.write_at(0, IoBuf::copy_from_slice(b"hello"))
        .await
        .unwrap();
    blob.sync().await.unwrap();
    drop(blob);
    drop(volume);

    let volume = Volume::init(inner, pool, Config::default()).await.unwrap();
    let (blob, size) = volume.open("p", b"b").await.unwrap();
    assert_eq!(size, 5);
    let got = blob.read_at(0, 5).await.unwrap().coalesce();
    assert_eq!(got.as_ref(), b"hello");
}

/// (offset, bytes) writes since the last sync, in order.
type Unsynced = Arc<Mutex<Vec<(u64, Vec<u8>)>>>;

/// An inner storage wrapper that records unsynced writes to the volume file
/// and can materialize power-loss outcomes: each unsynced BLOCK-granular
/// piece independently lands, vanishes, or tears (block filled with
/// garbage).
#[derive(Clone)]
struct Tearing {
    inner: memory::Storage,
    unsynced: Unsynced,
    /// Durable content of the volume file at the last sync.
    durable: Arc<Mutex<Vec<u8>>>,
}

impl Tearing {
    fn new(pool: BufferPool) -> Self {
        Self {
            inner: memory::Storage::new(pool),
            unsynced: Arc::new(Mutex::new(Vec::new())),
            durable: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Materialize a crash as the post-crash volume-file image: durable
    /// content plus a seeded subset of the unsynced writes, torn at BLOCK
    /// granularity.
    fn crash(&self, rng: &mut TestRng) -> Vec<u8> {
        let mut disk = self.durable.lock().clone();
        for (offset, bytes) in self.unsynced.lock().iter() {
            // Split the write into block-granular pieces; each piece
            // independently lands, vanishes, or tears.
            let mut cursor = 0usize;
            while cursor < bytes.len() {
                let block_end = (((*offset as usize + cursor) / BLOCK as usize) + 1)
                    * BLOCK as usize
                    - *offset as usize;
                let piece_end = bytes.len().min(block_end);
                let at = *offset as usize + cursor;
                match rng.random_range(0..3u8) {
                    0 => {} // vanished
                    1 => {
                        // landed
                        if disk.len() < at + (piece_end - cursor) {
                            disk.resize(at + (piece_end - cursor), 0);
                        }
                        disk[at..at + (piece_end - cursor)]
                            .copy_from_slice(&bytes[cursor..piece_end]);
                    }
                    _ => {
                        // torn: the whole containing block becomes garbage
                        let block_start = (at / BLOCK as usize) * BLOCK as usize;
                        let block_stop = block_start + BLOCK as usize;
                        if disk.len() < block_stop {
                            disk.resize(block_stop, 0);
                        }
                        for b in &mut disk[block_start..block_stop] {
                            *b = !*b ^ 0x5a;
                        }
                    }
                }
                cursor = piece_end;
            }
        }
        disk
    }

    /// Build a wrapper whose durable state is `image` (a post-crash disk).
    async fn from_image(pool: BufferPool, image: Vec<u8>) -> Self {
        let tearing = Self::new(pool);
        let cfg = Config::default();
        let (file, _) = tearing.inner.open(&cfg.partition, &cfg.name).await.unwrap();
        if !image.is_empty() {
            file.write_at(0, IoBuf::copy_from_slice(&image))
                .await
                .unwrap();
        }
        file.sync().await.unwrap();
        *tearing.durable.lock() = image;
        tearing
    }
}

impl crate::Storage for Tearing {
    type Blob = TearingBlob;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: std::ops::RangeInclusive<u16>,
    ) -> Result<(Self::Blob, u64, u16), Error> {
        let (blob, len, version) = self.inner.open_versioned(partition, name, versions).await?;
        Ok((
            TearingBlob {
                inner: blob,
                unsynced: self.unsynced.clone(),
                durable: self.durable.clone(),
            },
            len,
            version,
        ))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        self.inner.remove(partition, name).await
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        self.inner.scan(partition).await
    }
}

#[derive(Clone)]
struct TearingBlob {
    inner: memory::Blob,
    unsynced: Unsynced,
    durable: Arc<Mutex<Vec<u8>>>,
}

impl crate::Blob for TearingBlob {
    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        self.inner.read_at(offset, len).await
    }

    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        self.inner.read_at_buf(offset, len, bufs).await
    }

    async fn write_at(&self, offset: u64, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        let buf = bufs.into().coalesce();
        self.unsynced.lock().push((offset, buf.as_ref().to_vec()));
        self.inner.write_at(offset, buf).await
    }

    async fn write_at_sync(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        self.write_at(offset, bufs).await?;
        self.sync().await
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        // The volume never shrinks its file; growth happens via write_at.
        self.inner.resize(len).await
    }

    async fn sync(&self) -> Result<(), Error> {
        self.inner.sync().await?;
        // Everything pending is now durable: rebuild the durable image.
        let writes = std::mem::take(&mut *self.unsynced.lock());
        let mut durable = self.durable.lock();
        for (offset, bytes) in writes {
            let at = offset as usize;
            if durable.len() < at + bytes.len() {
                durable.resize(at + bytes.len(), 0);
            }
            durable[at..at + bytes.len()].copy_from_slice(&bytes);
        }
        Ok(())
    }

    async fn start_sync(&self) -> crate::Handle<()> {
        crate::Handle::ready(self.sync().await)
    }
}

/// Randomized power-loss soak: drive a workload over `Volume<Tearing>`,
/// tracking the exact committed state; at random points, crash (keeping an
/// arbitrary subset of unsynced volume-file writes, torn at block
/// granularity), reopen, and assert every blob reads back exactly its
/// last-committed content.
///
/// Commits are SELECTIVE: a sync commits only the synced blob plus its
/// applied-batch group (never split), so the ledger tracks committed
/// content per blob and pending groups explicitly. Batches interleave with
/// direct writes, syncs, and crashes; a batch dropped (or crashed) before
/// apply must be fully invisible.
#[tokio::test]
async fn test_volume_power_loss_soak() {
    for seed in 0..32u64 {
        power_loss_round(seed).await;
    }
}

/// Commit `name` plus the transitive closure of pending groups touching it
/// in the soak's ledger (mirrors the never-split rule).
fn ledger_commit(
    name: &'static str,
    committed: &mut BTreeMap<&'static str, Vec<u8>>,
    current: &BTreeMap<&'static str, Vec<u8>>,
    groups: &mut Vec<std::collections::BTreeSet<&'static str>>,
) {
    let mut capture: std::collections::BTreeSet<&'static str> = [name].into();
    groups.retain(|group| {
        if group.contains(name) {
            capture.extend(group.iter().copied());
            false
        } else {
            true
        }
    });
    for member in capture {
        committed.insert(member, current[member].clone());
    }
}

async fn power_loss_round(seed: u64) {
    let mut rng = TestRng::new(seed);
    let pool = test_pool();
    let mut tearing = Tearing::new(pool.clone());
    let mut volume = Volume::new(tearing.clone(), pool.clone(), Config::default());

    // The ledger: exactly-committed content per blob name, the current
    // (possibly uncommitted) content, and applied-but-uncommitted batch
    // groups.
    let mut committed: BTreeMap<&'static str, Vec<u8>> = BTreeMap::new();
    let mut current: BTreeMap<&'static str, Vec<u8>> = BTreeMap::new();
    let mut groups: Vec<std::collections::BTreeSet<&'static str>> = Vec::new();
    const NAMES: [&str; 3] = ["alpha", "beta", "gamma"];

    // Open all blobs (creation commits them empty).
    let mut blobs = BTreeMap::new();
    for name in NAMES {
        let (blob, size) = volume.open("p", name.as_bytes()).await.unwrap();
        assert_eq!(size, 0, "seed {seed}: fresh blob");
        blobs.insert(name, blob);
        committed.insert(name, Vec::new());
        current.insert(name, Vec::new());
    }

    for step in 0..200u32 {
        let name = NAMES[rng.random_range(0..NAMES.len())];
        match rng.random_range(0..13u8) {
            // Append a random amount (small through multi-block).
            0..=4 => {
                let len = match rng.random_range(0..3u8) {
                    0 => rng.random_range(1..64),
                    1 => rng.random_range(64..BLOCK as usize),
                    _ => rng.random_range(BLOCK as usize..3 * BLOCK as usize),
                };
                let mut data = vec![0u8; len];
                rng.fill_bytes(&mut data);
                let cur = current.get_mut(name).unwrap();
                let offset = cur.len() as u64;
                blobs[name]
                    .write_at(offset, IoBuf::copy_from_slice(&data))
                    .await
                    .unwrap();
                cur.extend_from_slice(&data);
            }
            // Overwrite a random committed range (exercises COW).
            5 => {
                let cur = current.get_mut(name).unwrap();
                if cur.is_empty() {
                    continue;
                }
                let at = rng.random_range(0..cur.len());
                let len = rng.random_range(1..=(cur.len() - at).min(2 * BLOCK as usize));
                let mut data = vec![0u8; len];
                rng.fill_bytes(&mut data);
                blobs[name]
                    .write_at(at as u64, IoBuf::copy_from_slice(&data))
                    .await
                    .unwrap();
                cur[at..at + len].copy_from_slice(&data);
            }
            // Rewind (resize down).
            6 => {
                let cur = current.get_mut(name).unwrap();
                if cur.is_empty() {
                    continue;
                }
                let to = rng.random_range(0..cur.len());
                blobs[name].resize(to as u64).await.unwrap();
                cur.truncate(to);
            }
            // Zero-extend (resize up).
            7 => {
                let grow = rng.random_range(1..2 * BLOCK as usize);
                let cur = current.get_mut(name).unwrap();
                blobs[name].resize((cur.len() + grow) as u64).await.unwrap();
                cur.resize(cur.len() + grow, 0);
            }
            // Sync: the synced blob (plus its applied-batch group) becomes
            // committed; other blobs' dirty state stays pending.
            8 => {
                blobs[name].sync().await.unwrap();
                ledger_commit(name, &mut committed, &current, &mut groups);
            }
            // Batch: stage appends on two blobs, then apply / apply_sync /
            // drop / crash mid-stage. Staged state must be invisible until
            // apply, and applied state must commit all-or-nothing.
            9..=11 => {
                let other = NAMES[rng.random_range(0..NAMES.len())];
                let mut batch = volume.batch().await.unwrap();
                let mut ends: BTreeMap<&'static str, u64> = NAMES
                    .iter()
                    .map(|&n| (n, current[n].len() as u64))
                    .collect();
                let mut staged: Vec<(&'static str, Vec<u8>)> = Vec::new();
                for pick in [name, other] {
                    let len = rng.random_range(1..2 * BLOCK as usize);
                    let mut data = vec![0u8; len];
                    rng.fill_bytes(&mut data);
                    batch
                        .write_at(&blobs[pick], ends[pick], IoBuf::copy_from_slice(&data))
                        .await
                        .unwrap();
                    *ends.get_mut(pick).unwrap() += len as u64;
                    staged.push((pick, data));
                }
                match rng.random_range(0..3u8) {
                    // Publish; the two blobs form one atomic group.
                    0 => {
                        batch.apply().await.unwrap();
                        for (pick, data) in staged {
                            current.get_mut(pick).unwrap().extend_from_slice(&data);
                        }
                        let mut group: std::collections::BTreeSet<&'static str> =
                            [name, other].into();
                        groups.retain(|g| {
                            if g.iter().any(|m| group.contains(m)) {
                                group.extend(g.iter().copied());
                                false
                            } else {
                                true
                            }
                        });
                        groups.push(group);
                    }
                    // Publish and commit in one shot.
                    1 => {
                        batch.apply_sync().await.unwrap();
                        for (pick, data) in staged {
                            current.get_mut(pick).unwrap().extend_from_slice(&data);
                        }
                        ledger_commit(name, &mut committed, &current, &mut groups);
                        ledger_commit(other, &mut committed, &current, &mut groups);
                    }
                    // Dropped without apply: the batch never happened.
                    _ => drop(batch),
                }
            }
            // Record rewrite through a batch: staged resize + staged write,
            // committed atomically (the wholesale-rewrite shape).
            12 => {
                let len = rng.random_range(1..2 * BLOCK as usize);
                let mut data = vec![0u8; len];
                rng.fill_bytes(&mut data);
                let mut batch = volume.batch().await.unwrap();
                batch.resize(&blobs[name], len as u64).await.unwrap();
                batch
                    .write_at(&blobs[name], 0, IoBuf::copy_from_slice(&data))
                    .await
                    .unwrap();
                batch.apply_sync().await.unwrap();
                current.insert(name, data);
                ledger_commit(name, &mut committed, &current, &mut groups);
            }
            // Crash + recover.
            _ => {
                let image = tearing.crash(&mut rng);
                drop(blobs);
                tearing = Tearing::from_image(pool.clone(), image).await;
                volume = Volume::new(tearing.clone(), pool.clone(), Config::default());

                // Reopen and verify EXACTLY the committed state.
                blobs = BTreeMap::new();
                for name in NAMES {
                    let (blob, size) = volume
                        .open("p", name.as_bytes())
                        .await
                        .unwrap_or_else(|e| panic!("seed {seed} step {step}: reopen {name}: {e}"));
                    let expect = committed.get(name).unwrap();
                    assert_eq!(
                        size,
                        expect.len() as u64,
                        "seed {seed} step {step}: {name} size"
                    );
                    if !expect.is_empty() {
                        let got = blob
                            .read_at(0, expect.len())
                            .await
                            .unwrap_or_else(|e| panic!("seed {seed} step {step}: read {name}: {e}"))
                            .coalesce();
                        assert_eq!(
                            got.as_ref(),
                            expect.as_slice(),
                            "seed {seed} step {step}: {name} content"
                        );
                    }
                    blobs.insert(name, blob);
                }
                current.clone_from(&committed);
                groups.clear();
            }
        }
    }
}

/// A crash while a batch is still STAGED (never applied) must leave the
/// batch fully invisible: both the in-place shared-tail staging and the
/// fresh-extent staging die with the crash, whatever lands or tears.
#[tokio::test]
async fn test_volume_batch_crash_mid_stage() {
    let pool = test_pool();
    let tearing = Tearing::new(pool.clone());
    let volume = Volume::new(tearing.clone(), pool.clone(), Config::default());

    // Commit a partial-tail baseline on `a` (staging appends into its
    // shared tail block) and an empty baseline on `b` (staging allocates a
    // fresh extent).
    let (a, _) = volume.open("p", b"a").await.unwrap();
    let (b, _) = volume.open("p", b"b").await.unwrap();
    a.write_at(0, IoBuf::copy_from_slice(b"base"))
        .await
        .unwrap();
    a.sync().await.unwrap();

    let mut batch = volume.batch().await.unwrap();
    batch
        .write_at(&a, 4, IoBuf::copy_from_slice(&vec![7u8; 6000]))
        .await
        .unwrap();
    batch
        .write_at(&b, 0, IoBuf::copy_from_slice(&vec![9u8; 5000]))
        .await
        .unwrap();

    for seed in 0..8u64 {
        let mut rng = TestRng::new(seed);
        let image = tearing.crash(&mut rng);
        let post = Tearing::from_image(pool.clone(), image).await;
        let recovered = Volume::new(post, pool.clone(), Config::default());
        let (a, size) = recovered.open("p", b"a").await.unwrap();
        assert_eq!(size, 4, "seed {seed}: staged append leaked into a");
        let got = a.read_at(0, 4).await.unwrap().coalesce();
        assert_eq!(got.as_ref(), b"base", "seed {seed}");
        let (_, size) = recovered.open("p", b"b").await.unwrap();
        assert_eq!(size, 0, "seed {seed}: staged fresh extent leaked into b");
    }
    drop(batch);
}

/// An applied-but-uncommitted batch either vanishes wholesale (a crash, or
/// a commit rooted at an UNRELATED blob) or commits wholesale (a commit
/// rooted at any group member) — never partially.
#[tokio::test]
async fn test_volume_batch_never_split() {
    for commit_member in [false, true] {
        let pool = test_pool();
        let tearing = Tearing::new(pool.clone());
        let volume = Volume::new(tearing.clone(), pool.clone(), Config::default());

        let (a, _) = volume.open("p", b"a").await.unwrap();
        let (b, _) = volume.open("p", b"b").await.unwrap();
        let (c, _) = volume.open("p", b"c").await.unwrap();

        let mut batch = volume.batch().await.unwrap();
        batch
            .write_at(&a, 0, IoBuf::copy_from_slice(b"batch-a"))
            .await
            .unwrap();
        batch
            .write_at(&b, 0, IoBuf::copy_from_slice(b"batch-b"))
            .await
            .unwrap();
        batch.apply().await.unwrap();

        // Dirty an unrelated blob and sync either it (must NOT commit the
        // batch) or a group member (must commit the WHOLE batch).
        c.write_at(0, IoBuf::copy_from_slice(b"c")).await.unwrap();
        if commit_member {
            a.sync().await.unwrap();
        } else {
            c.sync().await.unwrap();
        }

        for seed in 0..8u64 {
            let mut rng = TestRng::new(seed);
            let image = tearing.crash(&mut rng);
            let post = Tearing::from_image(pool.clone(), image).await;
            let recovered = Volume::new(post, pool.clone(), Config::default());
            let (a, a_size) = recovered.open("p", b"a").await.unwrap();
            let (b, b_size) = recovered.open("p", b"b").await.unwrap();
            if commit_member {
                assert_eq!((a_size, b_size), (7, 7), "seed {seed}: batch must commit");
                let got = a.read_at(0, 7).await.unwrap().coalesce();
                assert_eq!(got.as_ref(), b"batch-a", "seed {seed}");
                let got = b.read_at(0, 7).await.unwrap().coalesce();
                assert_eq!(got.as_ref(), b"batch-b", "seed {seed}");
            } else {
                assert_eq!(
                    (a_size, b_size),
                    (0, 0),
                    "seed {seed}: batch must vanish wholesale"
                );
                // The unrelated sync itself must be durable.
                let (_, c_size) = recovered.open("p", b"c").await.unwrap();
                assert_eq!(c_size, 1, "seed {seed}: synced blob must survive");
            }
        }
    }
}

/// A staged creation is invisible until `apply_sync` and then atomic with
/// the batch: after a crash, either the created blob exists AND the batch's
/// write landed, or neither did.
#[tokio::test]
async fn test_volume_batch_create_atomic() {
    let pool = test_pool();
    let tearing = Tearing::new(pool.clone());
    let volume = Volume::new(tearing.clone(), pool.clone(), Config::default());

    let (a, _) = volume.open("p", b"a").await.unwrap();
    a.write_at(0, IoBuf::copy_from_slice(b"base"))
        .await
        .unwrap();
    a.sync().await.unwrap();

    // Stage a write plus a creation. Before apply, the creation must be
    // invisible to the namespace and vanish wholesale across a crash.
    let mut batch = volume.batch().await.unwrap();
    batch
        .write_at(&a, 4, IoBuf::copy_from_slice(b"-more"))
        .await
        .unwrap();
    let created = batch.create("p", b"n").unwrap();
    assert!(!volume.scan("p").await.unwrap().contains(&b"n".to_vec()));
    for seed in 0..4u64 {
        let mut rng = TestRng::new(seed);
        let image = tearing.crash(&mut rng);
        let post = Tearing::from_image(pool.clone(), image).await;
        let recovered = Volume::new(post, pool.clone(), Config::default());
        let names = recovered.scan("p").await.unwrap();
        assert!(
            !names.contains(&b"n".to_vec()),
            "seed {seed}: creation leaked"
        );
        let (_, size) = recovered.open("p", b"a").await.unwrap();
        assert_eq!(size, 4, "seed {seed}: staged write leaked");
    }

    // Apply: one commit covers the write, the creation, and bytes written
    // to the created blob afterwards only once THEY are synced.
    batch.apply_sync().await.unwrap();
    created
        .write_at(0, IoBuf::copy_from_slice(b"n-data"))
        .await
        .unwrap();
    for seed in 0..4u64 {
        let mut rng = TestRng::new(seed);
        let image = tearing.crash(&mut rng);
        let post = Tearing::from_image(pool.clone(), image).await;
        let recovered = Volume::new(post, pool.clone(), Config::default());
        let names = recovered.scan("p").await.unwrap();
        assert!(names.contains(&b"n".to_vec()), "seed {seed}: creation lost");
        let (a, a_size) = recovered.open("p", b"a").await.unwrap();
        assert_eq!(a_size, 9, "seed {seed}: batch write must commit");
        let got = a.read_at(0, 9).await.unwrap().coalesce();
        assert_eq!(got.as_ref(), b"base-more", "seed {seed}");
        let (_, n_size) = recovered.open("p", b"n").await.unwrap();
        assert_eq!(n_size, 0, "seed {seed}: unsynced post-create write leaked");
    }

    // A conflicting creation fails the apply loudly, applying nothing.
    let mut batch = volume.batch().await.unwrap();
    let _dup = batch.create("p", b"n").unwrap();
    batch
        .write_at(&a, 9, IoBuf::copy_from_slice(b"!"))
        .await
        .unwrap();
    match batch.apply_sync().await {
        Err(Error::BlobExists(partition, _)) => assert_eq!(partition, "p"),
        other => panic!("expected BlobExists, got {other:?}"),
    }
    let (_, size) = volume.open("p", b"a").await.unwrap();
    assert_eq!(size, 9, "failed batch must publish nothing");
}

/// A selective commit persists exactly the synced blob: an unrelated dirty
/// blob's unsynced data vanishes with the crash, and a later sync of that
/// blob commits everything it accumulated.
#[tokio::test]
async fn test_volume_selective_commit_crash() {
    let pool = test_pool();
    let tearing = Tearing::new(pool.clone());
    let volume = Volume::new(tearing.clone(), pool.clone(), Config::default());

    let (a, _) = volume.open("p", b"a").await.unwrap();
    let (b, _) = volume.open("p", b"b").await.unwrap();
    a.write_at(0, IoBuf::copy_from_slice(b"a-data"))
        .await
        .unwrap();
    b.write_at(0, IoBuf::copy_from_slice(&vec![3u8; 9000]))
        .await
        .unwrap();
    a.sync().await.unwrap();

    for seed in 0..8u64 {
        let mut rng = TestRng::new(seed);
        let image = tearing.crash(&mut rng);
        let post = Tearing::from_image(pool.clone(), image).await;
        let recovered = Volume::new(post, pool.clone(), Config::default());
        let (a, a_size) = recovered.open("p", b"a").await.unwrap();
        assert_eq!(a_size, 6, "seed {seed}: synced blob durable exactly");
        let got = a.read_at(0, 6).await.unwrap().coalesce();
        assert_eq!(got.as_ref(), b"a-data", "seed {seed}");
        let (_, b_size) = recovered.open("p", b"b").await.unwrap();
        assert_eq!(b_size, 0, "seed {seed}: unsynced blob data must vanish");
    }
}

/// Committed bytes must survive a crash that tears every unsynced write.
#[tokio::test]
async fn test_volume_committed_survives_full_tear() {
    let pool = test_pool();
    let tearing = Tearing::new(pool.clone());
    let volume = Volume::new(tearing.clone(), pool.clone(), Config::default());

    let (blob, _) = volume.open("p", b"wal").await.unwrap();
    blob.write_at(0, IoBuf::copy_from_slice(b"committed-data"))
        .await
        .unwrap();
    blob.sync().await.unwrap();

    // Unsynced appends into the shared tail block + a fresh block.
    blob.write_at(14, IoBuf::copy_from_slice(&vec![7u8; 8000]))
        .await
        .unwrap();

    // Crash under several seeds (different subsets of unsynced pieces
    // landing/vanishing/tearing) and assert recovery is exact regardless.
    for seed in 0..8u64 {
        let mut rng = TestRng::new(seed);
        let image = tearing.crash(&mut rng);
        let post = Tearing::from_image(pool.clone(), image).await;
        let recovered = Volume::new(post, pool.clone(), Config::default());
        let (blob, size) = recovered.open("p", b"wal").await.unwrap();
        assert_eq!(size, 14, "seed {seed}");
        let got = blob.read_at(0, 14).await.unwrap().coalesce();
        assert_eq!(got.as_ref(), b"committed-data", "seed {seed}");
    }
}

/// A bit flip in committed data must surface as loud corruption on read.
#[tokio::test]
async fn test_volume_detects_bit_rot() {
    let pool = test_pool();
    let inner = memory::Storage::new(pool.clone());
    let volume = Volume::new(inner.clone(), pool.clone(), Config::default());

    let (blob, _) = volume.open("p", b"data").await.unwrap();
    blob.write_at(0, IoBuf::copy_from_slice(&vec![42u8; 3 * BLOCK as usize]))
        .await
        .unwrap();
    blob.sync().await.unwrap();
    // A second commit, so the 42-blocks leave the newest commit's delta
    // manifest (rot inside the newest delta is indistinguishable from a torn
    // commit and rolls back instead — the documented trade-off).
    let (other, _) = volume.open("p", b"other").await.unwrap();
    other
        .write_at(0, IoBuf::copy_from_slice(b"x"))
        .await
        .unwrap();
    other.sync().await.unwrap();
    drop(other);
    drop(blob);
    drop(volume);

    // Flip one committed DATA byte in the volume file. Metadata bytes may
    // coincidentally be 42, and corrupting the newest superblock/table is a
    // (documented) fallback, not a read error — so locate a data block by
    // finding a full BLOCK of 42s and flip its middle.
    let cfg = Config::default();
    let (file, len) = inner.open(&cfg.partition, &cfg.name).await.unwrap();
    let image = file.read_at(0, len as usize).await.unwrap().coalesce();
    let target = image
        .as_ref()
        .windows(BLOCK as usize)
        .position(|w| w.iter().all(|&b| b == 42))
        .expect("data block present")
        + BLOCK as usize / 2;
    file.write_at(target as u64, IoBuf::copy_from_slice(&[43u8]))
        .await
        .unwrap();
    file.sync().await.unwrap();
    drop(file);

    // The flip is caught either at open (hydration verifies the frontier
    // chunk and checksum extents) or at read — loud either way.
    let volume = Volume::new(inner, pool, Config::default());
    match volume.open("p", b"data").await {
        Err(Error::BlobCorrupt(_, _, _)) => {}
        Err(e) => panic!("unexpected open error: {e:?}"),
        Ok((blob, _)) => {
            let result = blob.read_at(0, 3 * BLOCK as usize).await;
            assert!(
                matches!(result, Err(Error::BlobCorrupt(_, _, _))),
                "bit rot must be loud: {result:?}"
            );
        }
    }
}

/// Captures a clone of the last inner blob it opened, letting a test mutate
/// the SAME shared content the volume reads (memory blob clones share
/// content, while independent opens copy it).
#[derive(Clone)]
struct Capturing {
    inner: memory::Storage,
    handle: Arc<Mutex<Option<(memory::Blob, u64)>>>,
}

impl crate::Storage for Capturing {
    type Blob = memory::Blob;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: std::ops::RangeInclusive<u16>,
    ) -> Result<(Self::Blob, u64, u16), Error> {
        let (blob, len, version) = self.inner.open_versioned(partition, name, versions).await?;
        *self.handle.lock() = Some((blob.clone(), len));
        Ok((blob, len, version))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        self.inner.remove(partition, name).await
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        self.inner.scan(partition).await
    }
}

/// Chunks are verified once per process lifetime: corruption landing AFTER
/// a chunk was verified is served without error by later reads in the same
/// process (pinned deliberately — re-verifying kernel-cached bytes has near
/// zero detection value), while a reopen starts unverified and must catch
/// it loudly.
#[tokio::test]
async fn test_volume_stale_verified_read_caught_on_reopen() {
    let pool = test_pool();
    let capturing = Capturing {
        inner: memory::Storage::new(pool.clone()),
        handle: Arc::new(Mutex::new(None)),
    };
    let volume = Volume::new(capturing.clone(), pool.clone(), Config::default());

    let (blob, _) = volume.open("p", b"data").await.unwrap();
    blob.write_at(0, IoBuf::copy_from_slice(&vec![42u8; 3 * BLOCK as usize]))
        .await
        .unwrap();
    blob.sync().await.unwrap();
    // A second commit, so the 42-blocks leave the newest commit's delta
    // manifest (rot inside the newest delta rolls back at recovery instead
    // of surfacing as an error — the documented trade-off).
    let (other, _) = volume.open("p", b"other").await.unwrap();
    other
        .write_at(0, IoBuf::copy_from_slice(b"x"))
        .await
        .unwrap();
    other.sync().await.unwrap();
    drop(other);
    drop(blob);
    drop(volume);

    // Reopen: every chunk starts unverified, so this process's first read
    // runs (and records) the full verification.
    let volume = Volume::new(capturing.clone(), pool.clone(), Config::default());
    let (blob, _) = volume.open("p", b"data").await.unwrap();
    let got = blob
        .read_at(0, 3 * BLOCK as usize)
        .await
        .unwrap()
        .coalesce();
    assert!(got.as_ref().iter().all(|&b| b == 42));

    // Flip one byte in the middle 42-block of the volume file while the
    // volume is open, through the volume's own (shared-content) inner
    // handle. Locate the data extent as test_volume_detects_bit_rot does.
    let (file, len) = capturing.handle.lock().clone().expect("volume file open");
    let image = file.read_at(0, len as usize).await.unwrap().coalesce();
    let target = image
        .as_ref()
        .windows(2 * BLOCK as usize)
        .position(|w| w.iter().all(|&b| b == 42))
        .expect("data blocks present")
        + BLOCK as usize
        + BLOCK as usize / 2;
    file.write_at(target as u64, IoBuf::copy_from_slice(&[43u8]))
        .await
        .unwrap();
    file.sync().await.unwrap();
    drop(file);

    // The chunk is already verified: reads skip the CRC pass and serve the
    // stale-verified (now corrupt) bytes without error.
    let got = blob
        .read_at(0, 3 * BLOCK as usize)
        .await
        .unwrap()
        .coalesce();
    assert_eq!(
        got.as_ref().iter().filter(|&&b| b == 43).count(),
        1,
        "verified chunks must be served without re-verification"
    );
    drop(blob);
    drop(volume);

    // A new process starts unverified: the corruption is loud.
    let volume = Volume::new(capturing, pool, Config::default());
    match volume.open("p", b"data").await {
        Err(Error::BlobCorrupt(_, _, _)) => {}
        Err(e) => panic!("unexpected open error: {e:?}"),
        Ok((blob, _)) => {
            let result = blob.read_at(0, 3 * BLOCK as usize).await;
            assert!(
                matches!(result, Err(Error::BlobCorrupt(_, _, _))),
                "bit rot must be loud after reopen: {result:?}"
            );
        }
    }
}

/// Freshly written chunks are verified by construction: reading them back
/// issues exactly the requested byte range against the inner blob (no
/// widened span read, no whole-block read).
#[tokio::test]
async fn test_volume_written_chunks_read_exact_range() {
    let pool = test_pool();
    let recording = Recording::new(pool.clone());
    let volume = Volume::new(recording.clone(), pool.clone(), Config::default());

    // A partial chunk and a multi-block value.
    let (blob, _) = volume.open("p", b"b").await.unwrap();
    blob.write_at(0, IoBuf::copy_from_slice(&vec![7u8; 300]))
        .await
        .unwrap();
    blob.write_at(
        BLOCK,
        IoBuf::copy_from_slice(&vec![8u8; 2 * BLOCK as usize]),
    )
    .await
    .unwrap();
    blob.sync().await.unwrap();

    // Sub-range of the partial chunk: exactly 100 bytes, not the 300-byte
    // written span, not a whole block.
    let before = recording.log.lock().iter().filter(|(w, _, _)| !*w).count();
    let got = blob.read_at(50, 100).await.unwrap().coalesce();
    assert_eq!(got.as_ref(), &[7u8; 100][..]);
    {
        let log = recording.log.lock();
        let new: Vec<_> = log.iter().filter(|(w, _, _)| !*w).skip(before).collect();
        assert_eq!(new.len(), 1, "one exact inner read: {new:?}");
        assert_eq!(new[0].2, 100, "read must not be widened: {new:?}");
    }

    // Sub-range of the multi-block value, crossing a chunk boundary.
    let before = recording.log.lock().iter().filter(|(w, _, _)| !*w).count();
    let got = blob
        .read_at(BLOCK + 500, BLOCK as usize)
        .await
        .unwrap()
        .coalesce();
    assert_eq!(got.as_ref(), &vec![8u8; BLOCK as usize][..]);
    {
        let log = recording.log.lock();
        let new: Vec<_> = log.iter().filter(|(w, _, _)| !*w).skip(before).collect();
        assert_eq!(new.len(), 1, "one exact inner read: {new:?}");
        assert_eq!(
            new[0].2, BLOCK as usize,
            "read must not be widened: {new:?}"
        );
    }

    // read_at_buf takes the same fast path: exactly one exact-range inner
    // read, issued WITH the caller's buffer (the inner blob fills it
    // directly — no pool scratch, no copy), and the caller's buffer is
    // returned.
    let before = recording.log.lock().iter().filter(|(w, _, _)| !*w).count();
    let buf = IoBufMut::zeroed(100);
    let caller_ptr = buf.as_ref().as_ptr() as usize;
    let got = blob.read_at_buf(50, 100, buf).await.unwrap().coalesce();
    assert_eq!(got.as_ref(), &[7u8; 100][..]);
    assert_eq!(
        got.as_ref().as_ptr() as usize,
        caller_ptr,
        "the caller's buffer must be returned"
    );
    {
        let log = recording.log.lock();
        let new: Vec<_> = log.iter().filter(|(w, _, _)| !*w).skip(before).collect();
        assert_eq!(new.len(), 1, "one exact inner read: {new:?}");
        assert_eq!(new[0].2, 100, "read must not be widened: {new:?}");
    }
    assert_eq!(
        recording.buf_ptrs.lock().last().copied(),
        Some(caller_ptr),
        "the inner read must fill the caller's buffer directly"
    );
}

/// A one-shot pause point for inner I/O: while armed, the next matching
/// operation signals `reached` and blocks until released. Later operations
/// pass through untouched.
#[derive(Clone, Default)]
struct Gate {
    armed: Arc<std::sync::atomic::AtomicBool>,
    reached: Arc<std::sync::atomic::AtomicBool>,
    released: Arc<std::sync::atomic::AtomicBool>,
}

impl Gate {
    fn arm(&self) {
        use std::sync::atomic::Ordering::SeqCst;
        self.released.store(false, SeqCst);
        self.reached.store(false, SeqCst);
        self.armed.store(true, SeqCst);
    }

    /// Pause here (once) while armed.
    async fn pass(&self) {
        use std::sync::atomic::Ordering::SeqCst;
        if self.armed.swap(false, SeqCst) {
            self.reached.store(true, SeqCst);
            while !self.released.load(SeqCst) {
                tokio::task::yield_now().await;
            }
        }
    }

    async fn wait_reached(&self) {
        use std::sync::atomic::Ordering::SeqCst;
        while !self.reached.load(SeqCst) {
            tokio::task::yield_now().await;
        }
    }

    fn release(&self) {
        use std::sync::atomic::Ordering::SeqCst;
        self.released.store(true, SeqCst);
    }
}

/// An inner storage wrapper with one-shot read/write gates, for pinning
/// cross-task interleavings inside the volume (a task parked at a gate
/// holds whatever volume locks it acquired on the way in).
#[derive(Clone)]
struct Gated<S: crate::Storage> {
    inner: S,
    read_gate: Gate,
    write_gate: Gate,
}

impl<S: crate::Storage> Gated<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            read_gate: Gate::default(),
            write_gate: Gate::default(),
        }
    }
}

impl<S: crate::Storage> crate::Storage for Gated<S> {
    type Blob = GatedBlob<S::Blob>;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: std::ops::RangeInclusive<u16>,
    ) -> Result<(Self::Blob, u64, u16), Error> {
        let (blob, len, version) = self.inner.open_versioned(partition, name, versions).await?;
        Ok((
            GatedBlob {
                inner: blob,
                read_gate: self.read_gate.clone(),
                write_gate: self.write_gate.clone(),
            },
            len,
            version,
        ))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        self.inner.remove(partition, name).await
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        self.inner.scan(partition).await
    }
}

#[derive(Clone)]
struct GatedBlob<B: crate::Blob> {
    inner: B,
    read_gate: Gate,
    write_gate: Gate,
}

impl<B: crate::Blob> crate::Blob for GatedBlob<B> {
    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        self.read_gate.pass().await;
        self.inner.read_at(offset, len).await
    }

    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        self.read_gate.pass().await;
        self.inner.read_at_buf(offset, len, bufs).await
    }

    async fn write_at(&self, offset: u64, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        self.write_gate.pass().await;
        self.inner.write_at(offset, bufs).await
    }

    async fn write_at_sync(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        self.write_at(offset, bufs).await?;
        self.sync().await
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        self.inner.resize(len).await
    }

    async fn sync(&self) -> Result<(), Error> {
        self.inner.sync().await
    }

    async fn start_sync(&self) -> crate::Handle<()> {
        crate::Handle::ready(self.sync().await)
    }
}

/// A run created AFTER a commit's snapshot-seq bump but BEFORE its blob's
/// capture is referenced by that commit's table, checksum extent, and delta
/// manifest: the capture must freeze it. An in-place overwrite of such a
/// chunk after the commit confirms would invalidate the manifested chunk
/// and roll the CONFIRMED commit back at recovery.
#[tokio::test]
async fn test_volume_capture_freezes_racing_extents() {
    let pool = test_pool();
    let tearing = Tearing::new(pool.clone());
    let gated = Gated::new(tearing.clone());
    let volume = Volume::new(gated.clone(), pool.clone(), Config::default());

    // `a` (lower id) and `b` form one applied-batch group, so a commit
    // rooted at `a` captures both, in id order: parking the snapshotter at
    // `a` (a paused writer holds its write lock) opens a window before
    // `b`'s capture.
    let (a, _) = volume.open("p", b"a").await.unwrap();
    let (b, _) = volume.open("p", b"b").await.unwrap();
    let mut batch = volume.batch().await.unwrap();
    batch
        .write_at(&a, 0, IoBuf::copy_from_slice(b"A0"))
        .await
        .unwrap();
    batch
        .write_at(&b, 0, IoBuf::copy_from_slice(b"B0"))
        .await
        .unwrap();
    batch.apply().await.unwrap();

    gated.write_gate.arm();
    let a_writer = {
        let a = a.clone();
        tokio::spawn(async move {
            a.write_at(2, IoBuf::copy_from_slice(&[0xAA]))
                .await
                .unwrap();
        })
    };
    gated.write_gate.wait_reached().await;

    // The commit bumps the snapshot seq, then parks on `a`'s write lock.
    let commit = {
        let a = a.clone();
        tokio::spawn(async move { a.sync().await.unwrap() })
    };
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }

    // In the bump-to-capture window: a fresh-extent full-block write on
    // `b`. Its run is born after the snapshot seq, yet `b`'s capture will
    // reference it.
    let w1 = vec![0x11u8; BLOCK as usize];
    b.write_at(BLOCK, IoBuf::copy_from_slice(&w1))
        .await
        .unwrap();

    // Unblock `a`: the commit captures `a`, then `b` (including w1), and
    // confirms.
    gated.write_gate.release();
    a_writer.await.unwrap();
    commit.await.unwrap();

    // Post-confirm overwrite of w1's chunk: the captured extent must have
    // been frozen (copy-on-write), never rewritten in place.
    b.write_at(BLOCK + 8, IoBuf::copy_from_slice(&[0x77u8; 16]))
        .await
        .unwrap();

    // Crash without committing the overwrite: whatever lands, vanishes, or
    // tears, recovery must adopt the confirmed commit.
    for seed in 0..8u64 {
        let mut rng = TestRng::new(seed);
        let image = tearing.crash(&mut rng);
        let post = Tearing::from_image(pool.clone(), image).await;
        let recovered = Volume::new(post, pool.clone(), Config::default());
        let (a, a_size) = recovered.open("p", b"a").await.unwrap();
        assert_eq!(a_size, 3, "seed {seed}: confirmed commit rolled back");
        let got = a.read_at(0, 3).await.unwrap().coalesce();
        assert_eq!(got.as_ref(), &[b'A', b'0', 0xAA], "seed {seed}");
        let (b, b_size) = recovered.open("p", b"b").await.unwrap();
        assert_eq!(
            b_size,
            2 * BLOCK,
            "seed {seed}: confirmed commit rolled back"
        );
        let got = b.read_at(0, 2).await.unwrap().coalesce();
        assert_eq!(got.as_ref(), b"B0", "seed {seed}");
        let got = b.read_at(BLOCK, BLOCK as usize).await.unwrap().coalesce();
        assert_eq!(got.as_ref(), w1.as_slice(), "seed {seed}");
    }
}

/// A concurrent reader racing a legal in-place overwrite of the same chunk
/// (uncommitted bytes move no relocation generation) must retry against the
/// quiesced writer state, never report false corruption.
#[tokio::test]
async fn test_volume_read_races_in_place_overwrite() {
    let pool = test_pool();
    let gated = Gated::new(memory::Storage::new(pool.clone()));
    let volume = Volume::new(gated.clone(), pool.clone(), Config::default());

    // A fully-written, uncommitted chunk: overwrites land in place.
    let (blob, _) = volume.open("p", b"d").await.unwrap();
    blob.write_at(0, IoBuf::copy_from_slice(&[0x11u8; BLOCK as usize]))
        .await
        .unwrap();

    // The reader snapshots the chunk's expected CRC, then parks on the
    // inner read.
    gated.read_gate.arm();
    let reader = {
        let blob = blob.clone();
        tokio::spawn(async move { blob.read_at(0, 100).await })
    };
    gated.read_gate.wait_reached().await;

    // A disjoint-range in-place overwrite of the same chunk publishes a new
    // CRC while the reader is in flight.
    blob.write_at(200, IoBuf::copy_from_slice(&[0x22u8; 50]))
        .await
        .unwrap();

    gated.read_gate.release();
    let got = reader
        .await
        .unwrap()
        .expect("in-place overwrite must never surface as corruption")
        .coalesce();
    assert_eq!(got.as_ref(), &[0x11u8; 100]);
}

/// The quiesce-retry protocol is preserved for UNVERIFIED chunks: a partial
/// in-place overwrite that read back disk bytes for its CRC assembly leaves
/// its chunk unverified, so a reader racing a second in-place overwrite of
/// that chunk takes the full verification path and must re-verify against
/// the quiesced writer state, never report false corruption.
#[tokio::test]
async fn test_volume_unverified_read_races_in_place_overwrite() {
    let pool = test_pool();
    let gated = Gated::new(memory::Storage::new(pool.clone()));
    let volume = Volume::new(gated.clone(), pool.clone(), Config::default());

    // Three fresh chunks (verified by construction), then a partial
    // overwrite of chunk 0: its prefix and suffix are disk read-backs (the
    // tail buffer describes chunk 2), leaving chunk 0 unverified.
    let (blob, _) = volume.open("p", b"d").await.unwrap();
    blob.write_at(0, IoBuf::copy_from_slice(&[0x11u8; 3 * BLOCK as usize]))
        .await
        .unwrap();
    blob.write_at(100, IoBuf::copy_from_slice(&[0x33u8; 100]))
        .await
        .unwrap();

    // The reader snapshots chunk 0's expected CRC, then parks on the inner
    // (widened, whole-span) read.
    gated.read_gate.arm();
    let reader = {
        let blob = blob.clone();
        tokio::spawn(async move { blob.read_at(0, 100).await })
    };
    gated.read_gate.wait_reached().await;

    // A disjoint-range in-place overwrite of chunk 0 publishes a new CRC
    // while the reader is in flight.
    blob.write_at(300, IoBuf::copy_from_slice(&[0x22u8; 50]))
        .await
        .unwrap();

    gated.read_gate.release();
    let got = reader
        .await
        .unwrap()
        .expect("in-place overwrite must never surface as corruption")
        .coalesce();
    assert_eq!(got.as_ref(), &[0x11u8; 100]);
}

/// A relocation generation bump landing between a fast-path `read_at_buf`'s
/// snapshot and its post-read verification forces a retry that re-derives
/// the read plan. Both retry outcomes must fill the caller's buffers with
/// the correct (post-relocation) bytes: a COW keeps the chunk verified (the
/// retry stays on the direct-fill path), while a resize-down leaves the
/// boundary chunk unverified (the retry falls back to the scratch-and-copy
/// path).
#[tokio::test]
async fn test_volume_read_at_buf_retries_on_relocation() {
    let pool = test_pool();
    let gated = Gated::new(memory::Storage::new(pool.clone()));
    let volume = Volume::new(gated.clone(), pool.clone(), Config::default());

    // COW bump: a committed chunk (verified by construction, frozen by the
    // commit) relocates on overwrite.
    let (blob, _) = volume.open("p", b"cow").await.unwrap();
    blob.write_at(0, IoBuf::copy_from_slice(&[0x11u8; BLOCK as usize]))
        .await
        .unwrap();
    blob.sync().await.unwrap();

    // The reader derives the fast-path plan, then parks on the inner read
    // (already carrying the caller's buffer).
    gated.read_gate.arm();
    let reader = {
        let blob = blob.clone();
        tokio::spawn(async move {
            let buf = IoBufMut::zeroed(100);
            let ptr = buf.as_ref().as_ptr() as usize;
            let got = blob.read_at_buf(0, 100, buf).await.unwrap().coalesce();
            (ptr, got)
        })
    };
    gated.read_gate.wait_reached().await;

    // Overwriting frozen bytes relocates the chunk (COW): the generation
    // moves while the read is in flight, so the parked read returns the OLD
    // extent's bytes and must retry against the relocated (still verified)
    // chunk.
    blob.write_at(0, IoBuf::copy_from_slice(&[0x22u8; 100]))
        .await
        .unwrap();

    gated.read_gate.release();
    let (ptr, got) = reader.await.unwrap();
    assert_eq!(
        got.as_ref(),
        &[0x22u8; 100][..],
        "retry must serve the relocated bytes"
    );
    assert_eq!(
        got.as_ref().as_ptr() as usize,
        ptr,
        "the caller's buffer must be returned"
    );

    // Resize-down bump: the boundary chunk's CRC is recomputed from an
    // unchecked read-back, leaving it UNVERIFIED — the retry no longer
    // qualifies for the direct-fill path and must fall back to scratch.
    let (blob, _) = volume.open("p", b"shrink").await.unwrap();
    blob.write_at(0, IoBuf::copy_from_slice(&[0x33u8; 300]))
        .await
        .unwrap();

    gated.read_gate.arm();
    let reader = {
        let blob = blob.clone();
        tokio::spawn(async move {
            let buf = IoBufMut::zeroed(100);
            let ptr = buf.as_ref().as_ptr() as usize;
            let got = blob.read_at_buf(0, 100, buf).await.unwrap().coalesce();
            (ptr, got)
        })
    };
    gated.read_gate.wait_reached().await;

    blob.resize(150).await.unwrap();

    gated.read_gate.release();
    let (ptr, got) = reader.await.unwrap();
    assert_eq!(
        got.as_ref(),
        &[0x33u8; 100][..],
        "scratch fallback must serve the surviving bytes"
    );
    assert_eq!(
        got.as_ref().as_ptr() as usize,
        ptr,
        "the caller's buffer must be returned"
    );
}

/// A removal racing an in-flight commit on an unrelated blob must not let
/// that commit resolve the removal without the removed blob's applied-batch
/// group (never-split through removals): the namespace edit and the
/// removal's own commit are atomic under the commit lock.
#[tokio::test]
async fn test_volume_remove_never_splits_group() {
    use std::future::Future as _;

    let pool = test_pool();
    let tearing = Tearing::new(pool.clone());
    let gated = Gated::new(tearing.clone());
    let volume = Volume::new(gated.clone(), pool.clone(), Config::default());

    // A committed baseline on `a` distinguishes "entry dropped by a foreign
    // commit" from "entry never captured".
    let (a, _) = volume.open("p", b"a").await.unwrap();
    let (b, _) = volume.open("p", b"b").await.unwrap();
    let (c, _) = volume.open("p", b"c").await.unwrap();
    a.write_at(0, IoBuf::copy_from_slice(b"a-base"))
        .await
        .unwrap();
    a.sync().await.unwrap();

    // Applied-but-uncommitted group {a, b}.
    let mut batch = volume.batch().await.unwrap();
    batch
        .write_at(&a, 6, IoBuf::copy_from_slice(b"batch-a"))
        .await
        .unwrap();
    batch
        .write_at(&b, 0, IoBuf::copy_from_slice(b"batch-b"))
        .await
        .unwrap();
    batch.apply().await.unwrap();

    // Dirty `c`, then park a commit rooted at `c` inside its snapshot,
    // before table assembly (a paused writer holds `c`'s write lock).
    c.write_at(0, IoBuf::copy_from_slice(b"c-data"))
        .await
        .unwrap();
    gated.write_gate.arm();
    let c_writer = {
        let c = c.clone();
        tokio::spawn(async move {
            c.write_at(6, IoBuf::copy_from_slice(b"!")).await.unwrap();
        })
    };
    gated.write_gate.wait_reached().await;
    let c_sync = {
        let c = c.clone();
        tokio::spawn(async move { c.sync().await.unwrap() })
    };
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }

    // Start removing `a` while that commit is in flight, and abandon the
    // call while it waits: its namespace edit must not become observable to
    // the in-flight commit, which captures only {c} and would otherwise
    // drop `a`'s entry while leaving group-sibling `b` unresolved.
    {
        let mut remove = std::pin::pin!(volume.remove("p", Some(b"a")));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        for _ in 0..16 {
            assert!(
                remove.as_mut().poll(&mut cx).is_pending(),
                "remove must wait for the in-flight commit"
            );
        }
    }

    gated.write_gate.release();
    c_writer.await.unwrap();
    c_sync.await.unwrap();

    // Crash: exactly what the `c` commit made durable.
    let mut rng = TestRng::new(0);
    let image = tearing.crash(&mut rng);
    let post = Tearing::from_image(pool.clone(), image).await;
    let recovered = Volume::new(post, pool.clone(), Config::default());

    // The removal never resolved (`remove` never returned): `a` keeps its
    // committed baseline, `b` stays pre-batch, and `c`'s sync is durable.
    let (a, a_size) = recovered.open("p", b"a").await.unwrap();
    assert_eq!(a_size, 6, "removal leaked into a foreign commit");
    let got = a.read_at(0, 6).await.unwrap().coalesce();
    assert_eq!(got.as_ref(), b"a-base");
    let (_, b_size) = recovered.open("p", b"b").await.unwrap();
    assert_eq!(b_size, 0, "applied group must resolve all-or-nothing");
    let (c, c_size) = recovered.open("p", b"c").await.unwrap();
    assert_eq!(c_size, 7);
    let got = c.read_at(0, 7).await.unwrap().coalesce();
    assert_eq!(got.as_ref(), b"c-data!");
}

/// Crash recovery with a growth quantum: the provisioned zero tail —
/// surviving in full or truncated with the file-length metadata — must
/// never confuse recovery, and provisioning must resume after reopening
/// with the same or a different quantum.
#[tokio::test]
async fn test_volume_growth_quantum_crash_recovery() {
    let quantum = 16 * BLOCK;
    for (seed, reopen_quantum) in [
        (0u64, quantum),
        (1, quantum),
        (2, 4 * BLOCK),
        (3, 64 * BLOCK),
    ] {
        let pool = test_pool();
        let tearing = Tearing::new(pool.clone());
        let cfg = Config {
            growth_quantum: quantum,
            ..Config::default()
        };
        let volume = Volume::new(tearing.clone(), pool.clone(), cfg.clone());

        // Several commits, then unsynced writes racing the crash.
        let (blob, _) = volume.open("p", b"q").await.unwrap();
        blob.write_at(0, IoBuf::copy_from_slice(&[7u8; 2 * BLOCK as usize]))
            .await
            .unwrap();
        blob.sync().await.unwrap();
        blob.write_at(2 * BLOCK, IoBuf::copy_from_slice(&[8u8; 100]))
            .await
            .unwrap();
        blob.sync().await.unwrap();
        blob.write_at(
            2 * BLOCK + 100,
            IoBuf::copy_from_slice(&[9u8; BLOCK as usize]),
        )
        .await
        .unwrap();

        // The file is provisioned in whole quanta beyond the data.
        let (_, provisioned) = tearing.inner.open(&cfg.partition, &cfg.name).await.unwrap();
        assert!(provisioned >= quantum && provisioned.is_multiple_of(quantum));

        let mut rng = TestRng::new(seed);
        let mut image = tearing.crash(&mut rng);
        // File length is metadata: alternate between the provisioned tail
        // surviving the crash intact and vanishing with it.
        if seed % 2 == 0 {
            image.resize(provisioned as usize, 0);
        }

        let post = Tearing::from_image(pool.clone(), image).await;
        let reopen_cfg = Config {
            growth_quantum: reopen_quantum,
            ..Config::default()
        };
        let recovered = Volume::init(post.clone(), pool.clone(), reopen_cfg)
            .await
            .unwrap_or_else(|e| panic!("seed {seed}: recovery with provisioned tail: {e}"));
        let (blob, size) = recovered.open("p", b"q").await.unwrap();
        assert_eq!(size, 2 * BLOCK + 100, "seed {seed}");
        let got = blob.read_at(0, size as usize).await.unwrap().coalesce();
        assert_eq!(
            &got.as_ref()[..2 * BLOCK as usize],
            &[7u8; 2 * BLOCK as usize][..],
            "seed {seed}"
        );
        assert_eq!(
            &got.as_ref()[2 * BLOCK as usize..],
            &[8u8; 100][..],
            "seed {seed}"
        );

        // Provisioning resumes: the re-derived high-water covers the whole
        // file (growth never shrinks it) and new growth provisions in whole
        // quanta of the reopened config.
        let (_, len_before) = post.inner.open(&cfg.partition, &cfg.name).await.unwrap();
        blob.write_at(
            size,
            IoBuf::copy_from_slice(&vec![5u8; 2 * quantum as usize]),
        )
        .await
        .unwrap();
        blob.sync().await.unwrap();
        let (_, len_after) = post.inner.open(&cfg.partition, &cfg.name).await.unwrap();
        assert!(len_after >= len_before, "seed {seed}: file shrank");
        assert!(
            len_after.is_multiple_of(reopen_quantum),
            "seed {seed}: growth ignored the reopened quantum ({len_after})"
        );
        let got = blob
            .read_at(size, 2 * quantum as usize)
            .await
            .unwrap()
            .coalesce();
        assert!(got.as_ref().iter().all(|&x| x == 5), "seed {seed}");
    }
}
