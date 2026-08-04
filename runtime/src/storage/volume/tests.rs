//! Conformance and crash-recovery tests.
//!
//! Crash tests run over [sim::Storage], a deterministic inner backend implementing the
//! volume's crash model: a barrier (`sync`) makes everything issued before it durable; at
//! a crash, each write since the last barrier independently survives whole, torn to a
//! prefix, sparsely (arbitrary byte subsets), or not at all. `fail_next_sync` models a
//! failed barrier (the volume must poison itself and refuse further work).

use super::{Config, Spawn, Storage, format};
use crate::{Blob as _, Error, Storage as _, WriteOptions};
use commonware_utils::{TestRng, sync::Mutex};
use rand::RngExt as _;
use std::{collections::BTreeMap, sync::Arc};

mod sim {
    use crate::{Error, Handle, IoBufMut, IoBufs, IoBufsMut, WriteOptions};
    use bytes::Buf as _;
    use commonware_formatting::hex;
    use commonware_utils::sync::Mutex;
    use rand::{Rng, RngExt as _};
    use std::{
        collections::BTreeMap,
        ops::RangeInclusive,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };

    /// One write issued since the last completed barrier.
    struct Pending {
        offset: u64,
        data: Vec<u8>,
        /// `WriteOptions::SYNC` writes are durable the moment they return.
        sticky: bool,
    }

    struct BlobData {
        version: u16,
        /// Contents guaranteed to survive a crash.
        durable: Vec<u8>,
        /// Contents as the process sees them (page-cache view).
        visible: Vec<u8>,
        pending: Vec<Pending>,
    }

    impl BlobData {
        fn apply(buf: &mut Vec<u8>, offset: u64, data: &[u8]) {
            let end = offset as usize + data.len();
            if end > buf.len() {
                buf.resize(end, 0);
            }
            buf[offset as usize..end].copy_from_slice(data);
        }
    }

    #[derive(Default)]
    struct State {
        partitions: BTreeMap<String, BTreeMap<Vec<u8>, Arc<Mutex<BlobData>>>>,
    }

    /// A crash-simulating in-memory storage.
    #[derive(Clone, Default)]
    pub struct Storage {
        state: Arc<Mutex<State>>,
        fail_next_sync: Arc<AtomicBool>,
    }

    impl Storage {
        /// Makes the next `sync` on any blob fail (a torn barrier: none of its pending
        /// writes become durable; the crash decides which survive).
        pub fn fail_next_sync(&self) {
            self.fail_next_sync.store(true, Ordering::Release);
        }

        /// Crashes the process: every write since each blob's last completed barrier
        /// independently survives whole, as a prefix, sparsely, or not at all.
        pub fn crash(&self, rng: &mut impl Rng) {
            let state = self.state.lock();
            for partition in state.partitions.values() {
                for blob in partition.values() {
                    let mut blob = blob.lock();
                    let pending = std::mem::take(&mut blob.pending);
                    for write in pending {
                        if write.sticky {
                            BlobData::apply(&mut blob.durable, write.offset, &write.data);
                            continue;
                        }
                        match rng.random_range(0..4u8) {
                            // Lost entirely.
                            0 => {}
                            // Survived whole.
                            1 => BlobData::apply(&mut blob.durable, write.offset, &write.data),
                            // Torn to a prefix.
                            2 => {
                                let keep = rng.random_range(0..=write.data.len());
                                BlobData::apply(
                                    &mut blob.durable,
                                    write.offset,
                                    &write.data[..keep],
                                );
                            }
                            // Sparse byte subset.
                            _ => {
                                for (i, &byte) in write.data.iter().enumerate() {
                                    if rng.random_bool(0.5) {
                                        BlobData::apply(
                                            &mut blob.durable,
                                            write.offset + i as u64,
                                            &[byte],
                                        );
                                    }
                                }
                            }
                        }
                    }
                    blob.visible = blob.durable.clone();
                }
            }
        }
    }

    impl crate::Storage for Storage {
        type Blob = Blob;

        async fn open_versioned(
            &self,
            partition: &str,
            name: &[u8],
            versions: RangeInclusive<u16>,
        ) -> Result<(Self::Blob, u64, u16), Error> {
            let mut state = self.state.lock();
            let partition_entry = state.partitions.entry(partition.to_string()).or_default();
            let data = partition_entry
                .entry(name.to_vec())
                .or_insert_with(|| {
                    Arc::new(Mutex::new(BlobData {
                        version: *versions.end(),
                        durable: Vec::new(),
                        visible: Vec::new(),
                        pending: Vec::new(),
                    }))
                })
                .clone();
            let (len, version) = {
                let data = data.lock();
                (data.visible.len() as u64, data.version)
            };
            if !versions.contains(&version) {
                return Err(Error::BlobVersionMismatch {
                    expected: versions,
                    found: version,
                });
            }
            Ok((
                Blob {
                    data,
                    fail_next_sync: self.fail_next_sync.clone(),
                },
                len,
                version,
            ))
        }

        async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
            let mut state = self.state.lock();
            match name {
                Some(name) => {
                    state
                        .partitions
                        .get_mut(partition)
                        .ok_or_else(|| Error::PartitionMissing(partition.to_string()))?
                        .remove(name)
                        .ok_or_else(|| Error::BlobMissing(partition.to_string(), hex(name)))?;
                }
                None => {
                    state
                        .partitions
                        .remove(partition)
                        .ok_or_else(|| Error::PartitionMissing(partition.to_string()))?;
                }
            }
            Ok(())
        }

        async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
            let state = self.state.lock();
            let partition = state
                .partitions
                .get(partition)
                .ok_or_else(|| Error::PartitionMissing(partition.to_string()))?;
            Ok(partition.keys().cloned().collect())
        }
    }

    #[derive(Clone)]
    pub struct Blob {
        data: Arc<Mutex<BlobData>>,
        fail_next_sync: Arc<AtomicBool>,
    }

    impl crate::Blob for Blob {
        async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
            self.read_at_buf(offset, len, IoBufMut::with_capacity(len))
                .await
        }

        async fn read_at_buf(
            &self,
            offset: u64,
            len: usize,
            bufs: impl Into<IoBufsMut> + Send,
        ) -> Result<IoBufsMut, Error> {
            let mut bufs = bufs.into();
            let data = self.data.lock();
            let end = offset as usize + len;
            if end > data.visible.len() {
                return Err(Error::BlobInsufficientLength);
            }
            // SAFETY: `copy_from_slice` fills exactly `len` bytes below.
            unsafe { bufs.set_len(len) };
            bufs.copy_from_slice(&data.visible[offset as usize..end]);
            Ok(bufs)
        }

        async fn write_at(
            &self,
            offset: u64,
            bufs: impl Into<IoBufs> + Send,
            options: WriteOptions,
        ) -> Result<(), Error> {
            let bufs = bufs.into();
            if !bufs.has_remaining() {
                return Ok(());
            }
            let data_bytes = bufs.coalesce();
            let sticky = options.contains(WriteOptions::SYNC);
            let mut data = self.data.lock();
            BlobData::apply(&mut data.visible, offset, data_bytes.as_ref());
            if sticky {
                BlobData::apply(&mut data.durable, offset, data_bytes.as_ref());
            }
            data.pending.push(Pending {
                offset,
                data: data_bytes.as_ref().to_vec(),
                sticky,
            });
            Ok(())
        }

        async fn resize(&self, _len: u64) -> Result<(), Error> {
            // The volume grows its file with positional writes and never truncates it.
            unreachable!("the volume never resizes its file");
        }

        async fn sync(&self) -> Result<(), Error> {
            if self.fail_next_sync.swap(false, Ordering::AcqRel) {
                return Err(Error::Io(Arc::new(std::io::Error::other(
                    "simulated barrier failure",
                ))));
            }
            let mut data = self.data.lock();
            let pending = std::mem::take(&mut data.pending);
            for write in pending {
                BlobData::apply(&mut data.durable, write.offset, &write.data);
            }
            Ok(())
        }

        async fn start_sync(&self) -> Handle<()> {
            Handle::ready(self.sync().await)
        }
    }
}

/// Collects committer tasks so tests can wait for them to finish before crashing (a real
/// crash stops the process; here the committer must quiesce before the simulator rewinds
/// durability under it).
#[derive(Clone, Default)]
struct Tasks(Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>);

impl Tasks {
    fn spawn(&self) -> Spawn {
        let tasks = self.0.clone();
        Arc::new(move |future| {
            tasks.lock().push(tokio::spawn(future));
        })
    }

    async fn quiesce(&self) {
        let tasks = std::mem::take(&mut *self.0.lock());
        for task in tasks {
            task.await.unwrap();
        }
    }
}

fn volume_storage(inner: sim::Storage, tasks: &Tasks, chunk_size: u32) -> Storage<sim::Storage> {
    Storage::new(inner, tasks.spawn(), Config { chunk_size })
}

const PARTITION: &str = "crash";

/// What the test knows about one blob's durable fate.
#[derive(Clone)]
struct ModelBlob {
    /// Every byte this blob ever contains is this value (or zero), so any foreign byte
    /// after recovery is a cross-blob leak.
    tag: u8,
    /// Content as the process sees it (all operations applied).
    current: Vec<u8>,
    /// Content at the last acknowledged sync.
    acked: Vec<u8>,
    /// Whether operations were staged (or failed) after the last acknowledged sync.
    /// Clean blobs must recover exactly; dirty blobs may recover intermediate states.
    dirty: bool,
}

/// A workload's ground truth. Namespace operations acknowledge before returning, so a
/// blob whose create or remove returned `Ok` has certain existence. An operation that
/// returned an error (a failed barrier) leaves its target indeterminate: the record may
/// have reached the journal and legally survive the crash despite the error.
#[derive(Default)]
struct Model {
    blobs: BTreeMap<Vec<u8>, ModelBlob>,
    /// Names whose existence is indeterminate (a create or remove errored), with their
    /// tags. Recovery may surface them or not; if it does, their bytes must still be
    /// tag-pure.
    unknown: BTreeMap<Vec<u8>, u8>,
    partition_exists: bool,
}

impl Model {
    /// Verifies a reopened volume against the model, then adopts what recovery produced
    /// as the new baseline: the reopened view is durable by the storage contract, and a
    /// dirty blob's exact content legitimately depends on which unacknowledged writes
    /// survived.
    async fn verify(&mut self, storage: &Storage<sim::Storage>, context: &str) {
        if !self.partition_exists && self.unknown.is_empty() {
            assert!(
                matches!(
                    storage.scan(PARTITION).await,
                    Err(Error::PartitionMissing(_))
                ),
                "{context}: partition should not exist"
            );
            return;
        }
        let names = match storage.scan(PARTITION).await {
            Ok(names) => names,
            // Legal only when every create was indeterminate.
            Err(Error::PartitionMissing(_)) if !self.partition_exists => Vec::new(),
            Err(error) => panic!("{context}: scan failed: {error}"),
        };
        for name in &names {
            assert!(
                self.blobs.contains_key(name) || self.unknown.contains_key(name),
                "{context}: unexpected blob {name:?} recovered"
            );
        }
        for name in self.blobs.keys() {
            assert!(
                names.contains(name),
                "{context}: certain blob {name:?} missing after recovery"
            );
        }

        // Indeterminate blobs that recovery surfaced become certain (adopted below);
        // the rest are certainly absent now.
        let unknown = std::mem::take(&mut self.unknown);
        for (name, tag) in unknown {
            if names.contains(&name) {
                self.blobs.entry(name).or_insert(ModelBlob {
                    tag,
                    current: Vec::new(),
                    acked: Vec::new(),
                    dirty: true,
                });
                self.partition_exists = true;
            }
        }

        for (name, model) in &mut self.blobs {
            let (blob, len) = storage.open(PARTITION, name).await.unwrap();
            if !model.dirty {
                assert_eq!(
                    len,
                    model.acked.len() as u64,
                    "{context}: clean blob {name:?} length"
                );
            }
            let mut recovered = Vec::new();
            if len > 0 {
                let read = blob.read_at(0, len as usize).await.unwrap().coalesce();
                for (i, &byte) in read.as_ref().iter().enumerate() {
                    assert!(
                        byte == 0 || byte == model.tag,
                        "{context}: blob {name:?} byte {i} is {byte:#x}, \
                         expected 0 or tag {:#x} (cross-blob leak?)",
                        model.tag
                    );
                }
                if !model.dirty {
                    assert_eq!(
                        read.as_ref(),
                        model.acked.as_slice(),
                        "{context}: clean blob {name:?} content"
                    );
                }
                recovered = read.as_ref().to_vec();
            }
            model.current = recovered.clone();
            model.acked = recovered;
            model.dirty = false;
        }
    }
}

/// Runs a randomized workload, returning early once the volume poisons itself.
async fn run_workload(
    storage: &Storage<sim::Storage>,
    inner: &sim::Storage,
    model: &mut Model,
    rng: &mut TestRng,
    ops: usize,
    chunk_size: u32,
    inject_barrier_failure: bool,
) {
    let fail_at = inject_barrier_failure.then(|| rng.random_range(0..ops));
    for op in 0..ops {
        if Some(op) == fail_at {
            inner.fail_next_sync();
        }
        // Weighted operation mix over a small set of names.
        let name = vec![b'b', rng.random_range(0..6u8)];
        let tag = 0x10 + name[1];
        match rng.random_range(0..10u8) {
            // Create (or reopen) and write, usually syncing.
            0..=5 => {
                let (blob, len) = match storage.open(PARTITION, &name).await {
                    Ok(opened) => opened,
                    Err(_) => {
                        // A failed create is indeterminate: its record may survive the
                        // crash. A failed reopen changes nothing certain.
                        if !model.blobs.contains_key(&name) {
                            model.unknown.insert(name, tag);
                        }
                        return; // poisoned
                    }
                };
                model.partition_exists = true;
                let entry = model.blobs.entry(name.clone()).or_insert(ModelBlob {
                    tag,
                    current: Vec::new(),
                    acked: Vec::new(),
                    dirty: false,
                });
                assert_eq!(
                    entry.current.len() as u64,
                    len,
                    "visible length diverged from model"
                );
                // Random write, sometimes spanning chunks, sometimes leaving a gap.
                let offset = if rng.random_bool(0.7) {
                    len
                } else {
                    rng.random_range(0..=len + chunk_size as u64)
                };
                let write_len = rng.random_range(1..=(chunk_size as usize * 2).min(8192));
                let data = vec![tag; write_len];
                entry.dirty = true;
                if blob
                    .write_at(offset, data.clone(), WriteOptions::default())
                    .await
                    .is_err()
                {
                    return;
                }
                let end = offset as usize + write_len;
                if end > entry.current.len() {
                    entry.current.resize(end, 0);
                }
                entry.current[offset as usize..end].copy_from_slice(&data);
                if rng.random_bool(0.8) {
                    if blob.sync().await.is_err() {
                        return;
                    }
                    entry.acked = entry.current.clone();
                    entry.dirty = false;
                }
            }
            // Resize.
            6..=7 => {
                let Some(entry) = model.blobs.get_mut(&name) else {
                    continue;
                };
                let Ok((blob, len)) = storage.open(PARTITION, &name).await else {
                    return;
                };
                assert_eq!(entry.current.len() as u64, len);
                let target = rng.random_range(0..=len + chunk_size as u64 / 2);
                entry.dirty = true;
                if blob.resize(target).await.is_err() {
                    return;
                }
                entry.current.resize(target as usize, 0);
                if rng.random_bool(0.5) {
                    if blob.sync().await.is_err() {
                        return;
                    }
                    entry.acked = entry.current.clone();
                    entry.dirty = false;
                }
            }
            // Remove.
            8 => {
                if model.blobs.contains_key(&name) {
                    if storage.remove(PARTITION, Some(&name)).await.is_err() {
                        // Indeterminate: the delete record may or may not survive.
                        model.blobs.remove(&name);
                        model.unknown.insert(name, tag);
                        return;
                    }
                    model.blobs.remove(&name);
                }
            }
            // Bare sync: acknowledges everything staged so far.
            _ => {
                let Some(entry) = model.blobs.get_mut(&name) else {
                    continue;
                };
                let Ok((blob, _)) = storage.open(PARTITION, &name).await else {
                    return;
                };
                if blob.sync().await.is_err() {
                    return;
                }
                entry.acked = entry.current.clone();
                entry.dirty = false;
            }
        }
    }
}

/// Randomized workloads with mid-batch crashes, torn barriers, and multi-generation
/// reopen cycles. Every generation verifies the recovered state against the model.
#[tokio::test]
async fn test_crash_recovery_randomized() {
    for seed in 0..30u64 {
        let mut rng = TestRng::new(seed);
        let inner = sim::Storage::default();
        let mut model = Model::default();
        // Small chunks plus long-ish workloads force journal growth and checkpoints.
        let chunk_size = format::MIN_CHUNK_SIZE;

        for generation in 0..3 {
            let tasks = Tasks::default();
            let storage = volume_storage(inner.clone(), &tasks, chunk_size);
            let context = format!("seed {seed} generation {generation}");
            model.verify(&storage, &context).await;

            run_workload(
                &storage,
                &inner,
                &mut model,
                &mut rng,
                40,
                chunk_size,
                generation == 1,
            )
            .await;

            // Crash: drop the storage, wait for committers to exit, then let the
            // simulator decide which unbarriered writes survive.
            drop(storage);
            tasks.quiesce().await;
            inner.crash(&mut rng);
            // Whatever survived, every blob's model state must now be treated as the
            // last acknowledged one; dirty blobs stay dirty (unknown content).
        }
    }
}

/// A scripted workload crashed cleanly (everything synced) must recover exactly, across
/// multiple checkpoint cycles.
#[tokio::test]
async fn test_clean_crash_exact_recovery() {
    let mut rng = TestRng::new(7);
    let inner = sim::Storage::default();
    let chunk_size = format::MIN_CHUNK_SIZE;
    let mut expected: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();

    for generation in 0..5u8 {
        let tasks = Tasks::default();
        let storage = volume_storage(inner.clone(), &tasks, chunk_size);

        // Verify prior generation's state recovered exactly.
        for (name, content) in &expected {
            let (blob, len) = storage.open(PARTITION, name).await.unwrap();
            assert_eq!(len, content.len() as u64, "generation {generation}");
            if !content.is_empty() {
                let read = blob.read_at(0, content.len()).await.unwrap().coalesce();
                assert_eq!(read.as_ref(), content.as_slice(), "generation {generation}");
            }
        }

        // Long names make records large enough that a few dozen operations roll the
        // journal through several checkpoints.
        for i in 0..40u8 {
            let mut name = vec![b'n'; 1024];
            name[0] = generation;
            name[1] = i % 8;
            let tag = 0x20 + (i % 8);
            let (blob, len) = storage.open(PARTITION, &name).await.unwrap();
            let data = vec![tag; rng.random_range(1..4096)];
            blob.write_at(len, data.clone(), WriteOptions::default())
                .await
                .unwrap();
            blob.sync().await.unwrap();
            let content = expected.entry(name).or_default();
            content.extend_from_slice(&data);

            // Shrink some blobs to exercise trajectory floors across checkpoints.
            if i % 5 == 4 {
                let target = (content.len() / 2) as u64;
                blob.resize(target).await.unwrap();
                blob.sync().await.unwrap();
                content.truncate(target as usize);
            }
        }

        drop(storage);
        tasks.quiesce().await;
        // Everything was synced; the crash has nothing to tear.
        inner.crash(&mut rng);
    }
}

/// A failed barrier must poison the volume: the failing operation and everything after
/// it errors, and a reopen recovers a consistent state.
#[tokio::test]
async fn test_barrier_failure_poisons() {
    let mut rng = TestRng::new(11);
    let inner = sim::Storage::default();
    let tasks = Tasks::default();
    let storage = volume_storage(inner.clone(), &tasks, format::MIN_CHUNK_SIZE);

    let (blob, _) = storage.open(PARTITION, b"a").await.unwrap();
    blob.write_at(0, vec![0x11; 100], WriteOptions::default())
        .await
        .unwrap();
    blob.sync().await.unwrap();

    // The next barrier fails; the sync must error and the volume must refuse all
    // further work.
    blob.write_at(100, vec![0x11; 100], WriteOptions::default())
        .await
        .unwrap();
    inner.fail_next_sync();
    assert!(blob.sync().await.is_err());
    assert!(blob.sync().await.is_err(), "volume must stay poisoned");
    assert!(
        blob.write_at(200, vec![0x11; 8], WriteOptions::default())
            .await
            .is_err(),
        "writes must fail on a poisoned volume"
    );
    assert!(storage.open(PARTITION, b"b").await.is_err());

    // Reads still work: they promise nothing about durability.
    let read = blob.read_at(0, 200).await.unwrap().coalesce();
    assert!(read.as_ref().iter().all(|&b| b == 0x11));

    // A reopen after the crash recovers the acknowledged prefix exactly.
    drop(blob);
    drop(storage);
    tasks.quiesce().await;
    inner.crash(&mut rng);

    let tasks = Tasks::default();
    let storage = volume_storage(inner.clone(), &tasks, format::MIN_CHUNK_SIZE);
    let (blob, len) = storage.open(PARTITION, b"a").await.unwrap();
    assert!(len >= 100, "acknowledged bytes must survive");
    let read = blob.read_at(0, 100).await.unwrap().coalesce();
    assert_eq!(read.as_ref(), vec![0x11; 100].as_slice());
}

/// Deleting a blob and writing new blobs afterwards must never resurrect the deleted
/// blob or leak its bytes into others, under crashes at every point.
#[tokio::test]
async fn test_delete_reuse_isolation() {
    for seed in 0..20u64 {
        let mut rng = TestRng::new(seed);
        let inner = sim::Storage::default();
        let chunk_size = format::MIN_CHUNK_SIZE;
        let tasks = Tasks::default();
        let storage = volume_storage(inner.clone(), &tasks, chunk_size);

        // Fill a blob with a distinctive tag across several chunks and sync it.
        let (victim, _) = storage.open(PARTITION, b"victim").await.unwrap();
        victim
            .write_at(
                0,
                vec![0xAA; chunk_size as usize * 3],
                WriteOptions::default(),
            )
            .await
            .unwrap();
        victim.sync().await.unwrap();
        drop(victim);
        storage.remove(PARTITION, Some(b"victim")).await.unwrap();

        // Churn new blobs over the freed space, syncing some of them.
        for i in 0..6u8 {
            let name = vec![b'n', i];
            let (blob, _) = storage.open(PARTITION, &name).await.unwrap();
            let len = rng.random_range(1..=chunk_size as usize * 2);
            blob.write_at(0, vec![0x30 + i; len], WriteOptions::default())
                .await
                .unwrap();
            if rng.random_bool(0.5) {
                blob.sync().await.unwrap();
            }
        }

        drop(storage);
        tasks.quiesce().await;
        inner.crash(&mut rng);

        // The victim must be gone, and every survivor must hold only its own tag.
        let tasks = Tasks::default();
        let storage = volume_storage(inner.clone(), &tasks, chunk_size);
        let names = storage.scan(PARTITION).await.unwrap();
        assert!(
            !names.contains(&b"victim".to_vec()),
            "seed {seed}: deleted blob resurrected"
        );
        for name in names {
            let (blob, len) = storage.open(PARTITION, &name).await.unwrap();
            if len == 0 {
                continue;
            }
            let tag = 0x30 + name[1];
            let read = blob.read_at(0, len as usize).await.unwrap().coalesce();
            for &byte in read.as_ref().iter() {
                assert!(
                    byte == 0 || byte == tag,
                    "seed {seed}: blob {name:?} leaked byte {byte:#x}"
                );
            }
        }
    }
}

/// A mid-chunk shrink whose record survives a crash must never lose the retained
/// prefix: the shrink copies it into a fresh chunk, and that copy is barriered before
/// the record can be journaled. Whatever subset of unbarriered writes survives, the
/// recovered content is either the pre-shrink or the post-shrink acknowledged bytes.
#[tokio::test]
async fn test_shrink_survives_lost_writes() {
    for seed in 0..20u64 {
        let mut rng = TestRng::new(seed);
        let inner = sim::Storage::default();
        let chunk_size = format::MIN_CHUNK_SIZE;
        let tasks = Tasks::default();
        let storage = volume_storage(inner.clone(), &tasks, chunk_size);

        // Acknowledge 100k of content, then shrink mid-chunk and sync (also acked).
        let (blob, _) = storage.open(PARTITION, b"x").await.unwrap();
        blob.write_at(0, vec![0x42; 100_000], WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();
        blob.resize(40_000).await.unwrap();
        blob.sync().await.unwrap();

        drop(blob);
        drop(storage);
        tasks.quiesce().await;
        inner.crash(&mut rng);

        let tasks = Tasks::default();
        let storage = volume_storage(inner.clone(), &tasks, chunk_size);
        let (blob, len) = storage.open(PARTITION, b"x").await.unwrap();
        assert_eq!(len, 40_000, "seed {seed}: acknowledged shrink lost");
        let read = blob.read_at(0, 40_000).await.unwrap().coalesce();
        assert!(
            read.as_ref().iter().all(|&b| b == 0x42),
            "seed {seed}: acknowledged bytes lost after shrink"
        );
    }
}

/// A surviving mapping whose payload (and file growth) was lost must stay owned across
/// recovery: re-minting its chunk id would let the old record collide with a new owner
/// on the next replay, or leak the new owner's bytes into the old blob.
#[tokio::test]
async fn test_phantom_mapping_reuse() {
    for seed in 0..30u64 {
        let mut rng = TestRng::new(seed);
        let inner = sim::Storage::default();
        let chunk_size = format::MIN_CHUNK_SIZE;

        // Write two chunks and sync; the crash decides which of the record and payload
        // writes survive (the interesting case: record kept, payload and growth lost).
        {
            let tasks = Tasks::default();
            let storage = volume_storage(inner.clone(), &tasks, chunk_size);
            let (blob, _) = storage.open(PARTITION, b"x").await.unwrap();
            let (other, _) = storage.open(PARTITION, b"y").await.unwrap();
            other.sync().await.unwrap();
            blob.write_at(
                0,
                vec![0x42; 2 * chunk_size as usize],
                WriteOptions::default(),
            )
            .await
            .unwrap();
            let _ = blob.sync().await;
            drop((blob, other));
            drop(storage);
            tasks.quiesce().await;
            inner.crash(&mut rng);
        }

        // Rewrite (the normal post-crash pattern) and also grow the sibling blob so
        // any re-minted chunk id would collide or cross-leak.
        {
            let tasks = Tasks::default();
            let storage = volume_storage(inner.clone(), &tasks, chunk_size);
            let (blob, len) = storage.open(PARTITION, b"x").await.unwrap();
            blob.write_at(
                len,
                vec![0x42; chunk_size as usize],
                WriteOptions::default(),
            )
            .await
            .unwrap();
            blob.sync().await.unwrap();
            let (other, _) = storage.open(PARTITION, b"y").await.unwrap();
            other
                .write_at(0, vec![0x43; chunk_size as usize], WriteOptions::default())
                .await
                .unwrap();
            other.sync().await.unwrap();
            drop((blob, other));
            drop(storage);
            tasks.quiesce().await;
            inner.crash(&mut rng);
        }

        // Every open from here must succeed, and neither blob may hold the other's tag.
        let tasks = Tasks::default();
        let storage = volume_storage(inner.clone(), &tasks, chunk_size);
        for (name, tag) in [(b"x", 0x42u8), (b"y", 0x43)] {
            let (blob, len) = storage
                .open(PARTITION, name)
                .await
                .unwrap_or_else(|e| panic!("seed {seed}: reopen failed: {e}"));
            if len > 0 {
                let read = blob.read_at(0, len as usize).await.unwrap().coalesce();
                for &byte in read.as_ref().iter() {
                    assert!(
                        byte == 0 || byte == tag,
                        "seed {seed}: blob {name:?} leaked byte {byte:#x}"
                    );
                }
            }
        }
    }
}

/// A partition holding foreign files (another backend's layout) is rejected, never
/// silently shadowed.
#[tokio::test]
async fn test_foreign_files_rejected() {
    let inner = sim::Storage::default();
    {
        use crate::Storage as _;
        let (foreign, _) = inner.open(PARTITION, b"legacy").await.unwrap();
        foreign
            .write_at(0, b"data".to_vec(), WriteOptions::default())
            .await
            .unwrap();
        foreign.sync().await.unwrap();
    }
    let tasks = Tasks::default();
    let storage = volume_storage(inner, &tasks, format::MIN_CHUNK_SIZE);
    assert!(matches!(
        storage.open(PARTITION, b"x").await,
        Err(Error::PartitionCorrupt(_))
    ));
    assert!(matches!(
        storage.scan(PARTITION).await,
        Err(Error::PartitionCorrupt(_))
    ));
}

/// Inputs the record format cannot carry are rejected at the API, not written and then
/// refused by replay (which would make the partition unopenable).
#[tokio::test]
async fn test_rejects_unjournalable_inputs() {
    let inner = sim::Storage::default();
    let tasks = Tasks::default();
    let storage = volume_storage(inner.clone(), &tasks, format::MIN_CHUNK_SIZE);

    // A name too long for a record.
    let long_name = vec![b'x'; format::MAX_NAME_LEN + 1];
    assert!(matches!(
        storage.open(PARTITION, &long_name).await,
        Err(Error::BlobOpenFailed(..))
    ));

    // A resize whose slots exceed the u32 bound.
    let (blob, _) = storage.open(PARTITION, b"a").await.unwrap();
    let over = (u64::from(u32::MAX) + 1) * u64::from(format::MIN_CHUNK_SIZE) + 1;
    assert!(matches!(
        blob.resize(over).await,
        Err(Error::OffsetOverflow)
    ));

    // The partition remains fully usable and reopens cleanly.
    blob.write_at(0, b"ok".to_vec(), WriteOptions::default())
        .await
        .unwrap();
    blob.sync().await.unwrap();
    drop(blob);
    drop(storage);
    tasks.quiesce().await;

    let tasks = Tasks::default();
    let storage = volume_storage(inner, &tasks, format::MIN_CHUNK_SIZE);
    let (blob, len) = storage.open(PARTITION, b"a").await.unwrap();
    assert_eq!(len, 2);
    assert_eq!(blob.read_at(0, 2).await.unwrap().coalesce().as_ref(), b"ok");
}

mod suite {
    use super::*;
    use crate::{
        BufferPool, BufferPoolConfig,
        storage::{memory, tests::run_storage_tests},
        telemetry::metrics::Registry,
    };

    fn test_spawn() -> Spawn {
        Arc::new(|future| {
            tokio::spawn(future);
        })
    }

    fn test_storage(chunk_size: u32) -> Storage<memory::Storage> {
        let mut registry = Registry::default();
        let pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut registry);
        Storage::new(
            memory::Storage::new(pool),
            test_spawn(),
            Config { chunk_size },
        )
    }

    #[tokio::test]
    async fn test_storage_suite() {
        run_storage_tests(test_storage(Config::default().chunk_size)).await;
    }

    /// The suite again at the smallest chunk size, so multi-chunk blobs, chunk-seam
    /// writes, and multi-span reads are all exercised.
    #[tokio::test]
    async fn test_storage_suite_small_chunks() {
        run_storage_tests(test_storage(format::MIN_CHUNK_SIZE)).await;
    }
}
