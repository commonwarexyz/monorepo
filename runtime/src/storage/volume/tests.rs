//! Volume tests: the generic storage contract suite, plus a torn-write
//! power-loss harness that exercises the recovery protocol end-to-end (the
//! runtime-level counterpart of the exhaustive model in [`super::model`]).

use super::{Config, Storage as Volume, BLOCK};
use crate::{
    storage::{memory, tests::run_storage_tests},
    telemetry::metrics::Registry,
    Blob as _, BufferPool, BufferPoolConfig, Error, IoBuf, IoBufs, IoBufsMut, Storage as _,
};
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
