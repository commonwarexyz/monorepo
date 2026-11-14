use super::{Layout, Pending, create_header, hold::Hold, resolve_header, sync_dir};
use crate::{BlobVersion, Error, Handle, Removal};
use commonware_formatting::{from_hex, hex};
use commonware_utils::{
    channel::oneshot,
    sync::{AsyncMutex, Mutex, OwnedAsyncMutexGuard},
};
#[cfg(not(target_os = "linux"))]
use std::collections::HashSet;
use std::{
    collections::HashMap,
    fs,
    future::Future as _,
    io::ErrorKind,
    ops::RangeInclusive,
    path::{Path, PathBuf},
    sync::{Arc, Weak},
    task::{Context, Poll, Waker},
};

mod blob;

#[derive(Clone)]
pub struct Config {
    pub storage_directory: PathBuf,
    pub blob_layouts: RangeInclusive<Layout>,
}

impl Config {
    pub const fn new(storage_directory: PathBuf, blob_layouts: RangeInclusive<Layout>) -> Self {
        Self {
            storage_directory,
            blob_layouts,
        }
    }
}

/// Filesystem storage with one logical open per blob.
///
/// Failed durability barriers during content sync remain errors on later opens through this
/// instance until the blob is removed or recreated. Creation failures are retained only when
/// the header is complete.
///
/// On Linux, reads with [crate::ReadOptions::DONT_CACHE] use direct I/O where they can. An open's
/// first such read opens a second, read-only `O_DIRECT` descriptor on the blob's file. The open
/// keeps the descriptor until it is dropped, so every open that served an uncached read holds two
/// descriptors. [crate::Blob::read_at] returns the requested bytes as a view of an allocation that
/// holds their superset aligned to 4096 bytes, so a caller that retains them retains the whole
/// allocation.
///
/// A read that cannot use direct I/O falls back to a buffered read with the `RWF_DONTCACHE` hint.
/// An open stops trying direct I/O once its filesystem rejects `O_DIRECT`. While opening the
/// descriptor fails for another reason, such as the descriptor limit, uncached reads keep retrying
/// the open on their blocking threads before reading buffered.
///
/// Directory operations are ordered within each partition and run concurrently across
/// partitions, the order [crate::Storage::start_remove_many] promises. A removal batch takes a
/// place in the queue of every partition it names before the call returns, and two batches take
/// the same relative order in every partition they share. A batch runs once it has reached its
/// turn in all of them and keeps every turn until its last removal is durable. An open, scan, or
/// remove therefore queues only behind batches that name its partition. It waits for each of
/// them as a whole, including the time that batch waits for its turn in its other partitions.
/// An empty batch names no partition, so it takes no place and completes with its `after`, or
/// at once without one. An awaited operation other than a removal batch is submitted at its
/// first poll that has cooperative budget.
///
/// A removal batch waits for its `after` while holding its places, so later directory
/// operations on the partitions it names wait until `after` resolves (see
/// [crate::Storage::start_remove_many]). Every context of a runtime shares one storage instance,
/// so a stalled `after` stalls those partitions for every journal and actor in the runtime, and
/// keeps the directory held against a successor [Storage::new]. A panic while a batch runs is
/// reported through its [Removal] as [Error::Closed], and its payload is not resumed.
///
/// The tokio runtime takes one turn of every partition's queue after its tasks finish, so every
/// batch that holds a place and was submitted before then completes before shutdown.
#[derive(Clone)]
pub struct Storage {
    /// Orders each partition's namespace operations and records partition durability.
    partitions: Arc<Partitions>,
    /// Filesystem root and permitted on-disk header layouts.
    cfg: Config,
    /// Directory exclusion also retained by opened files and dispatched blocking operations.
    hold: Arc<Hold>,
    /// The live open of each blob and the debt its dropped handles left behind.
    pending: Arc<Pending>,
}

/// The exclusive use of one partition's directory, held by the operation at the head of the
/// partition's queue until it has finished.
type Turn = OwnedAsyncMutexGuard<Queue>;

/// One partition's queue of directory operations, which serves them in the order they joined.
///
/// It lives while an operation waits or runs on the partition and retires its entry in
/// [Partitions::queues] with the last of them.
struct Queue {
    /// The partition's key in [Partitions::queues].
    partition: String,
    /// The registry holding this queue's entry.
    partitions: Arc<Partitions>,
}

impl Drop for Queue {
    fn drop(&mut self) {
        // An operation that joined the partition after this queue emptied has replaced the
        // entry with a live one, which stays.
        let mut queues = self.partitions.queues.lock();
        if queues
            .get(&self.partition)
            .is_some_and(|queue| queue.strong_count() == 0)
        {
            queues.remove(&self.partition);
        }
    }
}

/// The directory operation queues and directory durability of this storage instance's
/// partitions.
#[derive(Default)]
struct Partitions {
    /// The queue of each partition with a waiting or running directory operation. A removal
    /// batch joins every queue it needs under one acquisition of this lock, so any two batches
    /// take the same relative order in every partition they share and never wait for each
    /// other.
    queues: Mutex<HashMap<String, Weak<AsyncMutex<Queue>>>>,
    /// Partitions whose inherited directory changes are durable. Only the operation holding a
    /// partition's [Turn] reads or changes its entry. Removal retires the entry before
    /// unlinking, and a blob removal restores it once the partition directory is synced.
    #[cfg(not(target_os = "linux"))]
    synced: Mutex<HashSet<PathBuf>>,
    #[cfg(test)]
    sync_hook: Mutex<tests::SyncHook>,
}

impl Partitions {
    /// Return `partition`'s queue from `queues`, starting one if no operation waits or runs on
    /// the partition.
    fn queue(
        self: &Arc<Self>,
        queues: &mut HashMap<String, Weak<AsyncMutex<Queue>>>,
        partition: &str,
    ) -> Arc<AsyncMutex<Queue>> {
        if let Some(queue) = queues.get(partition).and_then(Weak::upgrade) {
            return queue;
        }
        let queue = Arc::new(AsyncMutex::new(Queue {
            partition: partition.to_string(),
            partitions: self.clone(),
        }));
        queues.insert(partition.to_string(), Arc::downgrade(&queue));
        queue
    }

    /// Makes storage root entry changes durable, with test hooks to pause or fail
    /// before the filesystem sync.
    fn sync_root(&self, root: &Path) -> Result<(), Error> {
        #[cfg(test)]
        tests::SyncHook::run(&self.sync_hook)?;
        sync_dir(root)
    }

    /// Make a partition's directory entries durable before caching it. Supply
    /// `root` during blob creation to persist the partition's directory entry too.
    fn sync(
        &self,
        path: impl AsRef<Path> + Into<PathBuf>,
        root: Option<&Path>,
    ) -> Result<(), Error> {
        #[cfg(test)]
        tests::SyncHook::run(&self.sync_hook)?;
        sync_dir(path.as_ref())?;
        if let Some(root) = root {
            self.sync_root(root)?;
        }

        #[cfg(not(target_os = "linux"))]
        self.synced.lock().insert(path.into());
        Ok(())
    }

    /// Retire a partition's durability record before changing its directory entries.
    #[allow(clippy::missing_const_for_fn)]
    fn invalidate(&self, _path: &Path) {
        #[cfg(not(target_os = "linux"))]
        self.synced.lock().remove(_path);
    }

    /// Unlink one blob and make its removal durable in its partition directory.
    fn remove_blob(
        &self,
        pending: &Pending,
        directory: &Path,
        partition: &str,
        name: &[u8],
    ) -> Result<(), Error> {
        // Invalidate before unlinking so a failed removal cannot leave the partition marked
        // durable. Only a surviving partition regains its cache entry after a successful sync.
        let path = directory.join(partition);
        self.invalidate(&path);
        fs::remove_file(path.join(hex(name)))
            .map_err(|_| Error::BlobMissing(partition.to_string(), hex(name)))?;
        pending.forget(partition, Some(name));
        self.sync(path, None)
    }

    /// Make a partition's inherited directory entries durable on first access.
    #[allow(clippy::missing_const_for_fn)]
    fn sync_once(&self, _path: &Path) -> Result<(), Error> {
        #[cfg(not(target_os = "linux"))]
        {
            if self.synced.lock().contains(_path) {
                return Ok(());
            }

            self.sync(_path, None)?;
        }
        Ok(())
    }
}

impl Storage {
    /// Create a storage instance rooted at `cfg.storage_directory`, creating the
    /// directory if missing and holding it until every operation of this
    /// instance has finished. Blocks while a previous instance still holds it.
    ///
    /// # Panics
    ///
    /// Panics if the directory cannot be created or its hold cannot be acquired.
    pub fn new(cfg: Config) -> Self {
        let hold = Hold::acquire(&cfg.storage_directory).unwrap_or_else(|e| {
            panic!(
                "failed to acquire storage directory hold ({}): {e}",
                cfg.storage_directory.display()
            )
        });
        Self {
            partitions: Arc::new(Partitions::default()),
            cfg,
            hold,
            pending: Arc::new(Pending::default()),
        }
    }

    /// Return `partition`'s queue, starting one if no operation waits or runs on the partition.
    fn queue(&self, partition: &str) -> Arc<AsyncMutex<Queue>> {
        self.partitions
            .queue(&mut self.partitions.queues.lock(), partition)
    }

    /// Run `f` to completion on the blocking pool while owning a turn of
    /// `queue` and the directory hold, so dropping the returned future neither
    /// abandons `f` mid-sequence nor lets a successor storage instance
    /// initialize before `f` has finished. Results are delivered or dropped before
    /// releasing the turn. A closure dropped unstarted at runtime
    /// shutdown yields [Error::Closed].
    async fn dispatch<T: Send + 'static>(
        &self,
        queue: Arc<AsyncMutex<Queue>>,
        f: impl FnOnce(&Partitions) -> Result<T, Error> + Send + 'static,
    ) -> Result<T, Error> {
        let turn = queue.lock_owned().await;
        let partitions = self.partitions.clone();
        let hold = self.hold.clone();
        let (sender, receiver) = oneshot::channel();
        #[cfg(test)]
        let after_dispatch = self.pending.test.after_dispatch.lock().take();
        let task = tokio::task::spawn_blocking(move || {
            {
                let _hold = hold;
                let _turn = turn;
                let _ = sender.send(f(&partitions));
            }
            #[cfg(test)]
            if let Some((entered, released)) = after_dispatch {
                let _ = entered.send(());
                let _ = released.recv();
            }
        });
        match task.await {
            Ok(()) => receiver.await.map_err(|_| Error::Closed)?,
            Err(err) if err.is_panic() => std::panic::resume_unwind(err.into_panic()),
            Err(_) => Err(Error::Closed),
        }
    }

    /// Wait for every directory operation submitted before this call, including queued removal
    /// batches, by taking one turn of every partition's queue.
    pub(crate) async fn drain(&self) {
        let queues: Vec<_> = self
            .partitions
            .queues
            .lock()
            .values()
            .filter_map(Weak::upgrade)
            .collect();
        for queue in queues {
            drop(queue.lock().await);
        }
    }

    /// Like [Self::dispatch] for the distinct `partitions`, but queue `f` in each of them before
    /// returning, so it runs whether or not the returned handle is polled, after every operation
    /// on them submitted earlier and before every operation on them submitted later. With
    /// `after`, `f` runs only once `after` has succeeded in its turn, and the handle otherwise
    /// reports `after`'s failure. A queued closure dropped unstarted at runtime shutdown completes
    /// the handle with [Error::Closed].
    fn submit<T: Send + 'static>(
        &self,
        partitions: &[String],
        after: Option<Removal>,
        f: impl FnOnce(&Partitions) -> Result<T, Error> + Send + 'static,
    ) -> Handle<T> {
        let hold = self.hold.clone();
        let records = self.partitions.clone();
        let (sender, receiver) = oneshot::channel();

        // Run `f` on the blocking pool with every turn, or report `after`'s failure, delivering
        // the result before any turn is released.
        let run = move |turns: Vec<Turn>, after: Result<(), Error>| match after {
            Ok(()) => {
                tokio::task::spawn_blocking(move || {
                    let _hold = hold;
                    let _turns = turns;
                    let _ = sender.send(f(&records));
                });
            }
            Err(err) => {
                let _ = sender.send(Err(err));
                drop(turns);
            }
        };

        // A queue serves waiters in the order they join it, so the first poll of each
        // acquisition takes the operation's place in that partition. The polls are exempt from
        // the task's cooperative budget, which could otherwise return before joining, and all
        // happen under the registry lock so no other batch joins between them. Waiting for a
        // turn or for `after` continues on its own task.
        let mut turns = Vec::with_capacity(partitions.len());
        let mut waiting = Vec::new();
        {
            let mut queues = self.partitions.queues.lock();
            let mut context = Context::from_waker(Waker::noop());
            for partition in partitions {
                let queue = self.partitions.queue(&mut queues, partition);
                let mut acquire = Box::pin(tokio::task::unconstrained(queue.lock_owned()));
                match acquire.as_mut().poll(&mut context) {
                    Poll::Ready(turn) => turns.push(turn),
                    Poll::Pending => waiting.push(acquire),
                }
            }
        }
        match (waiting.is_empty(), after) {
            (true, None) => run(turns, Ok(())),
            (_, after) => {
                tokio::spawn(async move {
                    for acquire in waiting {
                        turns.push(acquire.await);
                    }
                    let after = match after {
                        Some(after) => after.await,
                        None => Ok(()),
                    };
                    run(turns, after);
                });
            }
        }
        Handle::from_receiver(receiver)
    }
}

impl crate::Storage for Storage {
    type Blob = blob::Blob;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<BlobVersion>,
    ) -> Result<(Self::Blob, u64, BlobVersion), Error> {
        super::validate_partition_name(partition)?;

        // Construct the full path
        let queue = self.queue(partition);
        let path = self.cfg.storage_directory.join(partition).join(hex(name));
        let storage_directory = self.cfg.storage_directory.clone();
        let partition = partition.to_string();
        let name = name.to_vec();
        let blob_layouts = self.cfg.blob_layouts.clone();
        let hold = self.hold.clone();
        let pending = self.pending.clone();

        // Run the open to completion: it mutates the partition directory and the
        // blob (create, truncate, header write, syncs), and dropping this future
        // must not abandon that sequence half-done (a straggling truncate could
        // clobber a successor's blob) or leave a later open trusting a header
        // whose syncs never ran.
        let (blob, mut logical_size, blob_version, wait, owed) = self
            .dispatch(queue, move |partitions| {
                let parent = match path.parent() {
                    Some(parent) => parent,
                    None => return Err(Error::PartitionCreationFailed(partition)),
                };

                // Create the partition directory, if it does not exist
                fs::create_dir_all(parent)
                    .map_err(|_| Error::PartitionCreationFailed(partition.clone()))?;

                // Open the file, creating it if it doesn't exist
                let mut file = fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(&path)
                    .map_err(|e| Error::BlobOpenFailed(partition.clone(), hex(&name), e.into()))?;
                let raw_len = file.metadata().map_err(|_| Error::ReadFailed)?.len();

                // Handle the header. Existing blobs have their header read. New blobs and blobs
                // left torn by an interrupted creation get a fresh header written.
                let existing = resolve_header(
                    &mut file,
                    raw_len,
                    &blob_layouts,
                    &versions,
                    &partition,
                    &name,
                )?;

                // Claim the name for this open. A fresh header starts a new incarnation.
                let (generation, wait, owed) =
                    pending.admit(&partition, &name, existing.is_some())?;

                // Existing headers retain their layout. New headers become visible only after
                // their namespace entries are durable.
                let (mut logical_size, blob_version, data_offset) = match existing {
                    Some(resolved) => {
                        // Make inherited directory entries durable before exposing the blob.
                        partitions.sync_once(parent)?;
                        resolved
                    }
                    None => {
                        // Make the blob name and its partition durable before writing a parseable
                        // header. A visible partition directory does not establish its durability.
                        partitions.sync(parent, Some(&storage_directory))?;

                        // Retain a creation failure until the blob is removed or recreated.
                        create_header(&mut file, &blob_layouts, &versions, &generation)
                            .inspect_err(|error| pending.fail(&generation, error.clone()))?
                    }
                };

                // With no predecessor work or debt, the captured file's length is final. Otherwise,
                // it is read below once outstanding work settles and any debt is flushed.
                if !owed {
                    logical_size =
                        file.metadata().map_err(|_| Error::ReadFailed)?.len() - data_offset;
                }

                // Construct the blob while still holding the partition's turn.
                let blob = Self::Blob::new(file, data_offset, hold, generation);
                Ok((blob, logical_size, blob_version, wait, owed))
            })
            .await?;

        // Outside the partition's turn, wait for any outstanding work, then flush any debt and read
        // the final file length.
        if owed {
            Pending::wait(wait).await?;
            logical_size = blob.complete().await?;
        }
        Ok((blob, logical_size, blob_version))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        super::validate_partition_name(partition)?;

        let queue = self.queue(partition);
        let path = self.cfg.storage_directory.join(partition);
        let storage_directory = self.cfg.storage_directory.clone();
        let partition = partition.to_string();
        let name = name.map(<[u8]>::to_vec);
        let pending = self.pending.clone();

        // Run the removal to completion: dropping this future must not abandon
        // the sequence between an unlink and the directory sync that makes it
        // durable.
        self.dispatch(queue, move |partitions| {
            if let Some(name) = &name {
                return partitions.remove_blob(&pending, &storage_directory, &partition, name);
            }

            // Invalidate before removing so a failed removal cannot leave the partition marked
            // durable.
            partitions.invalidate(&path);

            // Distinguish missing partitions from other filesystem failures.
            fs::remove_dir_all(&path).map_err(|error| match error.kind() {
                ErrorKind::NotFound => Error::PartitionMissing(partition.clone()),
                _ => Error::Io(error.into()),
            })?;

            pending.forget(&partition, None);

            // Sync the storage directory to ensure the removal is durable.
            partitions.sync_root(&storage_directory)
        })
        .await
    }

    async fn start_remove_many(
        &self,
        removals: Vec<(String, Vec<u8>)>,
        after: Option<Removal>,
    ) -> Removal {
        if let Some(err) = removals
            .iter()
            .find_map(|(partition, _)| super::validate_partition_name(partition).err())
        {
            return Removal::ready(Err(err));
        }

        // An empty batch names no partition, so it has no turn to wait for.
        if removals.is_empty() {
            return after.unwrap_or_else(|| Removal::ready(Ok(())));
        }

        // A batch takes one place in each partition, however many of its blobs it removes there.
        let mut partitions: Vec<_> = removals
            .iter()
            .map(|(partition, _)| partition.clone())
            .collect();
        partitions.sort_unstable();
        partitions.dedup();

        let storage_directory = self.cfg.storage_directory.clone();
        let pending = self.pending.clone();
        let batch = self.submit(&partitions, after, move |partitions| {
            for (partition, name) in &removals {
                partitions.remove_blob(&pending, &storage_directory, partition, name)?;
            }
            Ok(())
        });
        Removal::submitted(batch)
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        super::validate_partition_name(partition)?;

        let queue = self.queue(partition);
        let path = self.cfg.storage_directory.join(partition);
        let partition = partition.to_string();
        self.dispatch(queue, move |partitions| {
            // Distinguish missing partitions from other filesystem failures.
            let entries = fs::read_dir(&path).map_err(|error| match error.kind() {
                ErrorKind::NotFound => Error::PartitionMissing(partition.clone()),
                _ => Error::ReadFailed,
            })?;

            // Make inherited directory entries durable before exposing their blob names.
            partitions.sync_once(&path)?;
            let mut blobs = Vec::new();
            for entry in entries {
                let entry = entry.map_err(|_| Error::ReadFailed)?;
                let file_type = entry.file_type().map_err(|_| Error::ReadFailed)?;
                if !file_type.is_file() {
                    return Err(Error::PartitionCorrupt(partition));
                }
                if let Some(name) = entry.file_name().to_str() {
                    // Reject anything that isn't canonical lowercase hex (no `0x`
                    // prefix, no whitespace) since `from_hex` is lenient and
                    // storage only ever writes the canonical form via `hex()`.
                    let decoded =
                        from_hex(name).ok_or_else(|| Error::PartitionCorrupt(partition.clone()))?;
                    if hex(&decoded) != name {
                        return Err(Error::PartitionCorrupt(partition));
                    }

                    blobs.push(decoded);
                }
            }
            Ok(blobs)
        })
        .await
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::{
        BLOB_PAGE_SIZE, Blob, ReadOptions, Runner as _, Storage as _, WriteOptions,
        storage::{Header, Layout, shared, tests::run_storage_tests},
        tokio::Runner,
    };
    use commonware_utils::{Widen, sys_rng};
    use futures::FutureExt as _;
    use rand::RngExt as _;
    use std::{
        env,
        future::Future,
        pin::Pin,
        sync::mpsc::{self, RecvTimeoutError},
        task::{Context, Poll},
    };

    /// One-shot pause and failure controls applied before a directory sync.
    #[derive(Default)]
    pub(super) struct SyncHook {
        /// Announces entry and waits for release before the filesystem sync.
        pause: Option<(oneshot::Sender<()>, mpsc::Receiver<()>)>,
        /// Error returned in place of the next filesystem sync.
        fail: Option<Error>,
    }

    impl SyncHook {
        /// Apply the controls armed in `hook`, which stays unlocked during a pause so syncs in
        /// other partitions can run.
        pub(super) fn run(hook: &Mutex<Self>) -> Result<(), Error> {
            let pause = hook.lock().pause.take();
            if let Some((entered, released)) = pause {
                let _ = entered.send(());
                let _ = released.recv();
            }
            let fail = hook.lock().fail.take();
            if let Some(error) = fail {
                return Err(error);
            }
            Ok(())
        }
    }

    /// Pause the next directory sync, returning the receiver that reports its arrival and the
    /// sender that releases it by sending or dropping. A removal's first sync follows its
    /// unlink, so this holds a batch between unlinking a blob and making the removal durable.
    fn pause_sync(storage: &Storage) -> (oneshot::Receiver<()>, mpsc::Sender<()>) {
        let (entered, entering) = oneshot::channel();
        let (release, gate) = mpsc::channel();
        storage.partitions.sync_hook.lock().pause = Some((entered, gate));
        (entering, release)
    }

    fn random_suffix() -> u64 {
        let mut rng = sys_rng();
        rng.random()
    }

    #[tokio::test]
    async fn test_hold_waits_for_straggling_remove() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_hold_remove_{}", random_suffix()));
        let config = Config::new(storage_directory.clone(), Layout::ALL);
        let storage = Storage::new(config.clone());

        // Fill the partition with enough blobs that its removal takes a while,
        // so a successor that failed to wait would observe it mid-flight.
        let partition_path = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_path).unwrap();
        for i in 0..5_000u64 {
            std::fs::write(partition_path.join(hex(&i.to_be_bytes())), b"x").unwrap();
        }

        // Dispatch the partition's removal and drop its future mid-flight,
        // leaving the removal to finish on the blocking pool as a straggler.
        {
            let mut remove = Box::pin(storage.remove("partition", None));
            assert!(
                (&mut remove).now_or_never().is_none(),
                "removal completed before it could straggle"
            );
        }
        drop(storage);

        // A successor cannot initialize until the straggler finishes, so the
        // partition is guaranteed gone by the time it scans.
        let storage = Storage::new(config);
        let result = storage.scan("partition").await;
        assert!(
            matches!(result, Err(Error::PartitionMissing(_))),
            "{result:?}"
        );

        drop(storage);
        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_hold_retained_by_open_blob() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_hold_blob_{}", random_suffix()));
        let config = Config::new(storage_directory.clone(), Layout::ALL);
        let storage = Storage::new(config.clone());

        // An open blob holds a clone of the directory hold, since a write or
        // resize through it can still straggle. Dropping the storage while the
        // blob lives must not release the hold.
        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        drop(storage);

        let config_second = config.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let second = Storage::new(config_second);
            tx.send(()).unwrap();
            drop(second);
        });
        match rx.recv_timeout(std::time::Duration::from_millis(200)) {
            Err(RecvTimeoutError::Timeout) => {}
            other => panic!("second instance did not stay blocked on the hold: {other:?}"),
        }
        drop(blob);
        rx.recv_timeout(std::time::Duration::from_secs(10))
            .expect("second instance did not acquire the hold after the blob dropped");
        handle.join().unwrap();

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[test]
    fn test_hold_blocks_second_instance() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_hold_block_{}", random_suffix()));
        let config = Config::new(storage_directory.clone(), Layout::ALL);
        let first = Storage::new(config.clone());

        // A second instance on the same directory cannot acquire the hold
        // until the first releases it.
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let second = Storage::new(config);
            tx.send(()).unwrap();
            drop(second);
        });
        match rx.recv_timeout(std::time::Duration::from_millis(200)) {
            Err(RecvTimeoutError::Timeout) => {}
            other => panic!("second instance did not stay blocked on the hold: {other:?}"),
        }
        drop(first);
        rx.recv_timeout(std::time::Duration::from_secs(10))
            .expect("second instance did not acquire the hold after the first released it");
        handle.join().unwrap();

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[test]
    fn test_storage() {
        Runner::default().start(|context| async move {
            let mut rng = sys_rng();
            let storage_directory =
                env::temp_dir().join(format!("storage_tokio_{}", rng.random::<u64>()));
            let config = Config::new(storage_directory, Layout::ALL);
            let storage = Storage::new(config);
            run_storage_tests(context, storage).await;
        });
    }

    /// Removals submitted while their partition is held take their place in submission order.
    /// Dropping the handle does not cancel them, and a scan submitted afterwards observes them.
    #[tokio::test]
    async fn test_start_remove_many_runs_in_submission_order() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_remove_many_{}", random_suffix()));
        let storage = Storage::new(Config::new(storage_directory.clone(), Layout::ALL));
        for name in [b"a", b"b", b"c"] {
            drop(storage.open("partition", name).await.unwrap());
        }

        // Hold the partition so every operation below queues behind it.
        let turn = storage.queue("partition").lock_owned().await;
        let removal = |name: &[u8]| ("partition".to_string(), name.to_vec());
        drop(storage.start_remove_many(vec![removal(b"a")], None).await);
        let second = storage.start_remove_many(vec![removal(b"b")], None).await;
        let mut scan = Box::pin(storage.scan("partition"));
        assert!((&mut scan).now_or_never().is_none());
        drop(turn);

        assert_eq!(scan.await.unwrap(), vec![b"c".to_vec()]);
        second.await.unwrap();
        drop(storage);
        fs::remove_dir_all(storage_directory).unwrap();
    }

    /// An operation on a batch's partition submitted after the batch runs after every removal in
    /// it.
    #[tokio::test]
    async fn test_start_remove_many_precedes_later_operations() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_remove_later_{}", random_suffix()));
        let storage = Storage::new(Config::new(storage_directory.clone(), Layout::ALL));
        for name in [b"a", b"b"] {
            drop(storage.open("partition", name).await.unwrap());
        }

        // Hold the partition so the batch and the later open queue behind it.
        let turn = storage.queue("partition").lock_owned().await;
        let removal = |name: &[u8]| ("partition".to_string(), name.to_vec());
        let removed = storage
            .start_remove_many(vec![removal(b"a"), removal(b"b")], None)
            .await;
        let mut open = Box::pin(storage.open("partition", b"x"));
        assert!((&mut open).now_or_never().is_none());
        drop(turn);

        drop(open.await.unwrap());

        // The batch sends its result before releasing its turn, so its completion is decided
        // before the later open runs.
        assert!(matches!(removed.peek(), Some(Ok(()))));
        assert!(!storage_directory.join("partition").join(hex(b"b")).exists());
        removed.await.unwrap();
        drop(storage);
        fs::remove_dir_all(storage_directory).unwrap();
    }

    /// A batch held inside a removal leaves other partitions free to open, scan, and remove,
    /// while operations on its own partition wait for the whole batch.
    #[tokio::test]
    async fn test_start_remove_many_holds_only_its_partition() {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let storage_directory =
                env::temp_dir().join(format!("storage_tokio_remove_held_{}", random_suffix()));
            let storage = Storage::new(Config::new(storage_directory.clone(), Layout::ALL));
            let removal = |partition: &str, name: &[u8]| (partition.to_string(), name.to_vec());
            for name in [b"a", b"b"] {
                drop(storage.open("removing", name).await.unwrap());
            }
            drop(storage.open("other", b"x").await.unwrap());

            // Hold the batch after its first unlink.
            let (entering, release) = pause_sync(&storage);
            let removed = storage
                .start_remove_many(
                    vec![removal("removing", b"a"), removal("removing", b"b")],
                    None,
                )
                .await;
            entering.await.unwrap();
            assert!(!storage_directory.join("removing").join(hex(b"a")).exists());

            // Creating a blob, creating a partition, scanning, and removing a blob, a batch,
            // and a partition all finish elsewhere while the batch is held.
            drop(storage.open("other", b"y").await.unwrap());
            drop(storage.open("fresh", b"z").await.unwrap());
            let mut names = storage.scan("other").await.unwrap();
            names.sort();
            assert_eq!(names, vec![b"x".to_vec(), b"y".to_vec()]);
            storage.remove("other", Some(b"x")).await.unwrap();
            storage
                .start_remove_many(vec![removal("other", b"y")], None)
                .await
                .await
                .unwrap();
            storage.remove("fresh", None).await.unwrap();
            assert!(removed.peek().is_none());

            // An open, a scan, and a removal in the batch's partition wait behind it.
            let mut open = Box::pin(storage.open("removing", b"c"));
            let mut scan = Box::pin(storage.scan("removing"));
            let mut remove = Box::pin(storage.remove("removing", Some(b"b")));
            assert!((&mut open).now_or_never().is_none());
            assert!((&mut scan).now_or_never().is_none());
            assert!((&mut remove).now_or_never().is_none());
            assert!(storage_directory.join("removing").join(hex(b"b")).exists());
            release.send(()).unwrap();

            // They run in submission order after the batch's last removal.
            drop(open.await.unwrap());
            assert!(matches!(removed.peek(), Some(Ok(()))));
            assert_eq!(scan.await.unwrap(), vec![b"c".to_vec()]);
            assert!(matches!(remove.await, Err(Error::BlobMissing(_, _))));
            drop(storage);
            fs::remove_dir_all(storage_directory).unwrap();
        })
        .await
        .unwrap();
    }

    /// A batch naming several partitions holds each of them until its last removal, including
    /// one whose removal has not started, and leaves the partitions it does not name free.
    #[tokio::test]
    async fn test_start_remove_many_orders_every_named_partition() {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let storage_directory =
                env::temp_dir().join(format!("storage_tokio_remove_named_{}", random_suffix()));
            let storage = Storage::new(Config::new(storage_directory.clone(), Layout::ALL));
            let removal = |partition: &str, name: &[u8]| (partition.to_string(), name.to_vec());
            for partition in ["first", "second", "third"] {
                drop(storage.open(partition, b"a").await.unwrap());
            }

            // Hold the batch inside its removal from the first partition.
            let (entering, release) = pause_sync(&storage);
            let removed = storage
                .start_remove_many(vec![removal("first", b"a"), removal("second", b"a")], None)
                .await;
            entering.await.unwrap();
            assert!(storage_directory.join("second").join(hex(b"a")).exists());

            // Scans of both named partitions wait, and a scan of another partition does not.
            let mut first = Box::pin(storage.scan("first"));
            let mut second = Box::pin(storage.scan("second"));
            assert!((&mut first).now_or_never().is_none());
            assert!((&mut second).now_or_never().is_none());
            assert_eq!(storage.scan("third").await.unwrap(), vec![b"a".to_vec()]);
            release.send(()).unwrap();

            // Both scans observe the whole batch.
            assert!(second.await.unwrap().is_empty());
            assert!(matches!(removed.peek(), Some(Ok(()))));
            assert!(first.await.unwrap().is_empty());
            drop(storage);
            fs::remove_dir_all(storage_directory).unwrap();
        })
        .await
        .unwrap();
    }

    /// A batch waiting for its turn in one partition already holds its place in the others, so
    /// batches naming the same partitions in opposite orders run one after the other and a
    /// later scan observes both.
    #[tokio::test]
    async fn test_start_remove_many_reserves_every_partition_while_waiting() {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let storage_directory =
                env::temp_dir().join(format!("storage_tokio_remove_reserve_{}", random_suffix()));
            let storage = Storage::new(Config::new(storage_directory.clone(), Layout::ALL));
            let removal = |partition: &str, name: &[u8]| (partition.to_string(), name.to_vec());
            for partition in ["left", "right"] {
                for name in [b"a", b"b"] {
                    drop(storage.open(partition, name).await.unwrap());
                }
            }

            // Hold one partition so both batches wait there.
            let turn = storage.queue("left").lock_owned().await;
            let forward = storage
                .start_remove_many(vec![removal("left", b"a"), removal("right", b"a")], None)
                .await;
            let backward = storage
                .start_remove_many(vec![removal("right", b"b"), removal("left", b"b")], None)
                .await;

            // A scan of the other partition queues behind both batches, which have removed
            // nothing yet.
            let mut scan = Box::pin(storage.scan("right"));
            assert!((&mut scan).now_or_never().is_none());
            tokio::task::yield_now().await;
            assert!((&mut scan).now_or_never().is_none());
            for name in [b"a", b"b"] {
                assert!(storage_directory.join("right").join(hex(name)).exists());
            }
            drop(turn);

            assert!(scan.await.unwrap().is_empty());
            assert!(matches!(forward.peek(), Some(Ok(()))));
            assert!(matches!(backward.peek(), Some(Ok(()))));
            assert!(storage.scan("left").await.unwrap().is_empty());
            drop(storage);
            fs::remove_dir_all(storage_directory).unwrap();
        })
        .await
        .unwrap();
    }

    /// A batch whose `after` is running in another partition holds its own partition until
    /// `after` resolves, leaves other partitions free, and removes nothing if `after` failed.
    #[tokio::test]
    async fn test_start_remove_many_waits_for_after_in_another_partition() {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let storage_directory =
                env::temp_dir().join(format!("storage_tokio_remove_lineage_{}", random_suffix()));
            let storage = Storage::new(Config::new(storage_directory.clone(), Layout::ALL));
            let removal = |partition: &str, name: &[u8]| (partition.to_string(), name.to_vec());
            drop(storage.open("unrelated", b"a").await.unwrap());
            for failed in [false, true] {
                let (first, second) = (format!("first_{failed}"), format!("second_{failed}"));
                for partition in [&first, &second] {
                    drop(storage.open(partition, b"a").await.unwrap());
                }

                // Hold the predecessor inside its only successful removal.
                let mut removals = vec![removal(&first, b"a")];
                if failed {
                    removals.push(removal(&first, b"missing"));
                }
                let (entering, release) = pause_sync(&storage);
                let predecessor = storage.start_remove_many(removals, None).await;
                entering.await.unwrap();
                let removed = storage
                    .start_remove_many(vec![removal(&second, b"a")], Some(predecessor.clone()))
                    .await;

                // A later scan of the waiting batch's partition queues behind it, and a scan of
                // an unrelated partition does not.
                let mut scan = Box::pin(storage.scan(&second));
                assert!((&mut scan).now_or_never().is_none());
                tokio::task::yield_now().await;
                assert!((&mut scan).now_or_never().is_none());
                assert_eq!(
                    storage.scan("unrelated").await.unwrap(),
                    vec![b"a".to_vec()]
                );
                assert!(removed.peek().is_none());
                release.send(()).unwrap();

                assert_eq!(scan.await.unwrap().is_empty(), !failed);
                assert_eq!(predecessor.await.is_err(), failed);
                assert_eq!(
                    matches!(removed.await, Err(Error::BlobMissing(_, _))),
                    failed
                );
            }
            drop(storage);
            fs::remove_dir_all(storage_directory).unwrap();
        })
        .await
        .unwrap();
    }

    /// Draining waits for the batches queued in every partition, whichever finishes first.
    #[tokio::test]
    async fn test_drain_waits_for_every_partition() {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let storage_directory =
                env::temp_dir().join(format!("storage_tokio_drain_{}", random_suffix()));
            let storage = Storage::new(Config::new(storage_directory.clone(), Layout::ALL));
            for (early, late) in [("left", "right"), ("right", "left")] {
                for partition in [early, late] {
                    drop(storage.open(partition, b"a").await.unwrap());
                }

                // Queue a batch behind a held turn in each partition, then let the drain take
                // its first place.
                let early_turn = storage.queue(early).lock_owned().await;
                let late_turn = storage.queue(late).lock_owned().await;
                for partition in [early, late] {
                    let batch = vec![(partition.to_string(), b"a".to_vec())];
                    drop(storage.start_remove_many(batch, None).await);
                }
                let drain = tokio::spawn({
                    let storage = storage.clone();
                    async move { storage.drain().await }
                });
                tokio::task::yield_now().await;

                // One partition's batch finishing does not finish the drain. The scan queues
                // behind any turn the drain takes in that partition.
                drop(early_turn);
                assert!(storage.scan(early).await.unwrap().is_empty());
                assert!(!drain.is_finished());
                drop(late_turn);
                drain.await.unwrap();
                assert!(!storage_directory.join(late).join(hex(b"a")).exists());
            }
            drop(storage);
            fs::remove_dir_all(storage_directory).unwrap();
        })
        .await
        .unwrap();
    }

    /// A partition's queue is retired once nothing waits or runs on it, whether its last
    /// operation finished or was dropped while waiting.
    #[tokio::test]
    async fn test_idle_partition_queue_is_retired() {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let storage_directory =
                env::temp_dir().join(format!("storage_tokio_queue_idle_{}", random_suffix()));
            let storage = Storage::new(Config::new(storage_directory.clone(), Layout::ALL));
            for partition in ["left", "right"] {
                drop(storage.open(partition, b"a").await.unwrap());
            }
            let batch = vec![
                ("left".to_string(), b"a".to_vec()),
                ("right".to_string(), b"a".to_vec()),
            ];
            storage.start_remove_many(batch, None).await.await.unwrap();
            assert!(matches!(
                storage.scan("missing").await,
                Err(Error::PartitionMissing(_))
            ));

            // Drop a scan that queued behind a held turn.
            let turn = storage.queue("left").lock_owned().await;
            let mut scan = Box::pin(storage.scan("left"));
            assert!((&mut scan).now_or_never().is_none());
            drop(scan);
            drop(turn);

            // A finished operation releases its queue on its blocking thread, shortly after its
            // result is delivered.
            while !storage.partitions.queues.lock().is_empty() {
                tokio::task::yield_now().await;
            }
            drop(storage);
            fs::remove_dir_all(storage_directory).unwrap();
        })
        .await
        .unwrap();
    }

    /// A batch submitted by a task that has exhausted its cooperative budget still takes its
    /// place ahead of operations submitted after it.
    #[tokio::test]
    async fn test_start_remove_many_with_exhausted_budget_precedes_scan() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_remove_budget_{}", random_suffix()));
        let storage = Storage::new(Config::new(storage_directory.clone(), Layout::ALL));
        drop(storage.open("partition", b"a").await.unwrap());
        while tokio::task::coop::has_budget_remaining() {
            tokio::task::consume_budget().await;
        }
        let removed = storage
            .start_remove_many(vec![("partition".into(), b"a".to_vec())], None)
            .await;
        let names = tokio::task::unconstrained(storage.scan("partition"))
            .await
            .unwrap();
        removed.await.unwrap();
        drop(storage);
        fs::remove_dir_all(storage_directory).unwrap();
        assert!(names.is_empty(), "{names:?}");
    }

    /// A batch whose predecessor's shared completion is mid-poll on another task, as when a caller
    /// awaits an earlier removal, waits for that poll and then runs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_start_remove_many_waits_for_shared_after_polled_elsewhere() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_remove_shared_{}", random_suffix()));
        let storage = Storage::new(Config::new(storage_directory.clone(), Layout::ALL));
        drop(storage.open("partition", b"a").await.unwrap());

        // A completion whose first poll after it resolves lingers, as when the polling task is
        // preempted.
        let (resolve, resolved) = oneshot::channel::<Result<(), Error>>();
        let (entered, polling) = mpsc::channel();
        let completion = async move {
            let result = resolved.await.unwrap_or(Err(Error::Closed));
            entered.send(()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(100));
            result
        }
        .boxed()
        .shared();

        // Another task holds the completion mid-poll while the batch runs.
        let observer = tokio::spawn(completion.clone());
        resolve.send(Ok(())).unwrap();
        tokio::task::spawn_blocking(move || polling.recv().unwrap())
            .await
            .unwrap();
        let removed = storage
            .start_remove_many(
                vec![("partition".into(), b"a".to_vec())],
                Some(Removal::submitted(Handle::from_future(completion))),
            )
            .await;
        removed.await.unwrap();
        observer.await.unwrap().unwrap();
        assert!(storage.scan("partition").await.unwrap().is_empty());
        drop(storage);
        fs::remove_dir_all(storage_directory).unwrap();
    }

    /// A batch whose `after` has not resolved holds its place, and every later operation, until
    /// `after` resolves. It then runs if `after` succeeded, and otherwise fails with its error
    /// without removing anything.
    #[tokio::test]
    async fn test_start_remove_many_waits_for_after() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_remove_after_{}", random_suffix()));
        let storage = Storage::new(Config::new(storage_directory.clone(), Layout::ALL));
        for (outcome, survivors) in [
            (Ok(()), vec![b"b".to_vec()]),
            (Err(Error::Closed), vec![b"a".to_vec(), b"b".to_vec()]),
        ] {
            let failed = outcome.is_err();
            let partition = format!("partition_{failed}");
            for name in [b"a", b"b"] {
                drop(storage.open(&partition, name).await.unwrap());
            }
            let (resolve, resolved) = oneshot::channel();
            let removed = storage
                .start_remove_many(
                    vec![(partition.clone(), b"a".to_vec())],
                    Some(Removal::submitted(Handle::from_receiver(resolved))),
                )
                .await;

            // A later scan waits behind the batch until its predecessor resolves.
            let mut scan = Box::pin(storage.scan(&partition));
            assert!((&mut scan).now_or_never().is_none());
            tokio::task::yield_now().await;
            assert!((&mut scan).now_or_never().is_none());
            resolve.send(outcome).unwrap();

            let mut names = scan.await.unwrap();
            names.sort();
            assert_eq!(names, survivors);
            assert_eq!(removed.await.is_err(), failed);
        }
        drop(storage);
        fs::remove_dir_all(storage_directory).unwrap();
    }

    /// A removal still queued when the runtime shuts down completes as closed.
    #[test]
    fn test_start_remove_many_closed_at_shutdown() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_remove_shutdown_{}", random_suffix()));
        let runtime = tokio::runtime::Builder::new_multi_thread().build().unwrap();
        let (storage, guard, handle) = runtime.block_on(async {
            let storage = Storage::new(Config::new(storage_directory.clone(), Layout::ALL));
            drop(storage.open("partition", b"a").await.unwrap());
            let guard = storage.queue("partition").lock_owned().await;
            let handle = storage
                .start_remove_many(vec![("partition".to_string(), b"a".to_vec())], None)
                .await;
            (storage, guard, handle)
        });
        drop(runtime);
        assert!(matches!(
            futures::executor::block_on(handle),
            Err(Error::Closed)
        ));
        drop(guard);
        drop(storage);
        fs::remove_dir_all(storage_directory).unwrap();
    }

    /// Dropping the `start_sync` receiver must not break the blob: the handle stays
    /// usable and a later sync still persists data.
    #[tokio::test]
    async fn test_start_sync_dropped_receiver() {
        let mut rng = sys_rng();
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_start_sync_{}", rng.random::<u64>()));
        let config = Config::new(storage_directory, Layout::ALL);
        let storage = Storage::new(config);

        let (blob, _) = storage.open("partition", b"test_blob").await.unwrap();
        blob.write_at(0, b"hello world", WriteOptions::default())
            .await
            .unwrap();

        // Drop the completion receiver immediately.
        drop(blob.start_sync().await);

        // The blob remains usable, and a subsequent sync persists the data.
        blob.start_sync().await.await.unwrap();
        drop(blob);

        let (blob, len) = storage.open("partition", b"test_blob").await.unwrap();
        assert_eq!(len, 11);
        let read = blob
            .read_at(0, 11, ReadOptions::default())
            .await
            .unwrap()
            .coalesce();
        assert_eq!(read.as_ref(), b"hello world");
    }

    #[tokio::test]
    async fn test_blob_header_handling() {
        let mut rng = sys_rng();
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_header_{}", rng.random::<u64>()));
        let config = Config::new(storage_directory.clone(), Layout::ALL);
        let storage = Storage::new(config);

        // Test 1: New blob (V1 by default) returns logical size 0 and correct app version
        let (blob, size) = storage.open("partition", b"test").await.unwrap();
        assert_eq!(size, 0, "new blob should have logical size 0");

        // Verify raw file holds one header page
        let data_offset = Layout::V1.data_offset();
        let file_path = storage_directory.join("partition").join(hex(b"test"));
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(
            metadata.len(),
            data_offset,
            "raw file should have a full header page"
        );

        // Test 2: Write at logical offset 0 stores at the data offset
        let data = b"hello world";
        blob.write_at(0, data, WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();

        // Verify raw file size
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(metadata.len(), data_offset + data.len() as u64);

        // Verify raw file layout
        let raw_content = std::fs::read(&file_path).unwrap();
        assert_eq!(&raw_content[..Header::MAGIC_LENGTH], &Layout::V1.magic());
        // Header version (bytes 4-5) and App version (bytes 6-7)
        assert_eq!(
            &raw_content[4..6],
            &Layout::V1.layout_version().to_be_bytes()
        );
        // Data should start at the data offset
        assert_eq!(&raw_content[data_offset as usize..], data);

        // Test 3: Read at logical offset 0 returns data from the data offset
        let read_buf = blob
            .read_at(0, data.len(), ReadOptions::default())
            .await
            .unwrap();
        assert_eq!(read_buf.coalesce(), data);

        // Test 4: Resize with logical length
        blob.resize(5).await.unwrap();
        blob.sync().await.unwrap();
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(
            metadata.len(),
            data_offset + 5,
            "resize(5) should leave 5 raw bytes past the header page"
        );

        // resize(0) should leave only the header page
        blob.resize(0).await.unwrap();
        blob.sync().await.unwrap();
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(
            metadata.len(),
            data_offset,
            "resize(0) should leave only the header page"
        );

        // Test 5: Reopen existing blob preserves header and returns correct logical size
        blob.write_at(0, b"test data", WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        let (blob2, size2) = storage.open("partition", b"test").await.unwrap();
        assert_eq!(size2, 9, "reopened blob should have logical size 9");
        let read_buf = blob2.read_at(0, 9, ReadOptions::default()).await.unwrap();
        assert_eq!(read_buf.coalesce(), b"test data");
        drop(blob2);

        // Test 6: Corrupted blob recovery (0 < raw_size < 8)
        // Manually create a corrupted file with only 4 bytes
        let corrupted_path = storage_directory.join("partition").join(hex(b"corrupted"));
        std::fs::write(&corrupted_path, vec![0u8; 4]).unwrap();

        // Opening should truncate and write fresh header
        let (blob3, size3) = storage.open("partition", b"corrupted").await.unwrap();
        assert_eq!(size3, 0, "corrupted blob should return logical size 0");

        // Verify raw file now has a proper header page
        let metadata = std::fs::metadata(&corrupted_path).unwrap();
        assert_eq!(
            metadata.len(),
            Layout::V1.data_offset(),
            "corrupted blob should be reset to header-only"
        );

        // Cleanup
        drop(blob3);
        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    /// Verify the end-to-end blob-page alignment invariant: paged data written to a V1 blob with a
    /// 4096-byte physical page size occupies exactly one aligned 4096-byte disk page per physical
    /// page (header page included), so page reads never straddle a page boundary.
    #[tokio::test]
    async fn test_v1_paged_alignment() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_aligned_{}", random_suffix()));
        let config = Config::new(storage_directory.clone(), Layout::ALL);
        let storage = Storage::new(config);

        // A logical page size whose physical page is exactly one blob page.
        let logical = crate::buffer::paged::page_size(BLOB_PAGE_SIZE);
        let cache =
            crate::buffer::paged::CacheRef::new(logical, std::num::NonZeroUsize::new(16).unwrap());

        // Write several pages of patterned data through the paged writer (V1 blob via open()).
        let (blob, size) = storage.open("partition", b"aligned").await.unwrap();
        let mut writer = crate::buffer::paged::Writer::new(blob, size, 1024, cache)
            .await
            .unwrap();
        let item: Vec<u8> = (0..1000u32).flat_map(|i| i.to_be_bytes()).collect();
        for _ in 0..12 {
            (writer, _) = writer.append(&item).await.unwrap();
        }
        let logical_size = writer.size();
        writer.sync().await.unwrap();

        // The raw file is a whole number of 4096-byte pages: one header page plus one page per
        // physical page of data (the partial tail page is zero-padded to a full physical page).
        let file_path = storage_directory.join("partition").join(hex(b"aligned"));
        let raw = std::fs::read(&file_path).unwrap();
        let raw_len: u64 = Widen::widen(raw.len());
        let pages = logical_size.div_ceil(logical.widen());
        assert_eq!(raw_len % u64::from(BLOB_PAGE_SIZE), 0);
        assert_eq!(
            raw_len,
            Layout::V1.data_offset() + pages * u64::from(BLOB_PAGE_SIZE)
        );

        // Every physical page sits exactly within one aligned 4096-byte disk page, with a valid
        // CRC record in its final 12 bytes.
        let data = &raw[usize::try_from(Layout::V1.data_offset()).unwrap()..];
        for (page, physical) in data.chunks_exact(Widen::widen(BLOB_PAGE_SIZE)).enumerate() {
            assert!(
                crate::buffer::paged::validate_page_for_tests(physical),
                "page {page} failed CRC validation at aligned boundary"
            );
        }

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_torn_creation_recovers() {
        let storage_directory =
            env::temp_dir().join(format!("test_torn_creation_{}", random_suffix()));
        let storage = Storage::new(Config::new(storage_directory.clone(), Layout::ALL));

        // Create a durable V1 blob to obtain the canonical header region bytes.
        let (blob, _) = storage.open("partition", b"torn").await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);
        let path = storage_directory.join("partition").join(hex(b"torn"));
        let region = std::fs::read(&path).unwrap();

        // Simulate torn creations (the full state enumeration lives in the
        // Layout::interrupted_creation unit tables): a file truncated mid-CRC and the same
        // prefix at a persisted full length.
        let mut torn_content = vec![0u8; region.len()];
        torn_content[..10].copy_from_slice(&region[..10]);
        let states = [region[..10].to_vec(), torn_content];
        for state in states {
            std::fs::write(&path, &state).unwrap();
            let (blob, size) = storage.open("partition", b"torn").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(0, b"data".to_vec(), WriteOptions::default())
                .await
                .unwrap();
            blob.sync().await.unwrap();
            drop(blob);

            // The healed blob round-trips through a reopen with its data intact.
            let (blob, size) = storage.open("partition", b"torn").await.unwrap();
            assert_eq!(size, 4);
            let read = blob.read_at(0, 4, ReadOptions::default()).await.unwrap();
            assert_eq!(read.coalesce(), b"data");
            drop(blob);
        }

        // Foreign bytes are corruption, not a torn creation: nonzero padding behind a
        // torn (unparseable) prefix proves the file was never a canonical prefix of a
        // header region.
        let mut corrupt = vec![0u8; region.len()];
        corrupt[..10].copy_from_slice(&region[..10]);
        corrupt[100] = 0xFF;
        std::fs::write(&path, &corrupt).unwrap();
        let result = storage.open("partition", b"torn").await;
        assert!(matches!(result, Err(crate::Error::BlobCorrupt(_, _, _))));

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_canceled_open_retires_result_before_retry() {
        // Exercise cancellation after dispatch for both header layouts and for new and
        // existing blobs, whose successful open results carry different contents.
        let directory = env::temp_dir().join(format!("storage_tokio_delivery_{}", random_suffix()));
        for layout in [Layout::V0, Layout::V1] {
            for seeded in [false, true] {
                let storage = Storage::new(Config::new(directory.clone(), layout..=layout));
                let expected = if seeded { b"saved".as_slice() } else { &[] };
                if seeded {
                    let (blob, _) = storage.open("partition", b"blob").await.unwrap();
                    blob.write_at(0, expected, WriteOptions::default())
                        .await
                        .unwrap();
                    blob.sync().await.unwrap();
                }

                // Pause after dispatch has produced a blob, while the caller still owns
                // only the future that will receive it.
                let (entered, entering) = oneshot::channel();
                let (release, released) = std::sync::mpsc::channel();
                *storage.pending.test.after_dispatch.lock() = Some((entered, released));
                let mut first = Box::pin(storage.open("partition", b"blob"));
                assert!(futures::poll!(&mut first).is_pending());
                entering.await.unwrap();

                // A completed filesystem operation must release its partition even while
                // its caller has not polled the result.
                let independent = storage.open("partition", b"independent").await;

                // Canceling delivery must drop the unclaimed blob and release its name
                // before the paused dispatch task returns.
                drop(first);
                let retry = std::panic::AssertUnwindSafe(storage.open("partition", b"blob"))
                    .catch_unwind()
                    .await;
                drop(release);

                // The independent open and the retry both succeed. The retry sees the seeded
                // contents, or an empty blob when unseeded.
                drop(independent.unwrap());
                let (blob, size) = retry
                    .expect("retry panicked")
                    .expect("canceled output retained the name");
                assert_eq!(size, expected.len() as u64);
                if !expected.is_empty() {
                    assert_eq!(
                        blob.read_at(0, expected.len(), ReadOptions::default())
                            .await
                            .unwrap()
                            .coalesce(),
                        expected,
                    );
                }

                // The retry must own a usable blob whose new contents survive another reopen.
                blob.write_at(0, b"next", WriteOptions::default())
                    .await
                    .unwrap();
                blob.sync().await.unwrap();
                drop(blob);
                let (blob, size) = storage.open("partition", b"blob").await.unwrap();
                assert_eq!(size, expected.len().max(4) as u64);
                assert_eq!(
                    blob.read_at(0, 4, ReadOptions::default())
                        .await
                        .unwrap()
                        .coalesce(),
                    b"next"
                );
                drop(blob);
                storage.remove("partition", None).await.unwrap();
                drop(storage);
                std::fs::remove_dir_all(&directory).unwrap();
            }
        }
    }

    /// Dropping an open future at any await point must leave the blob openable: creation
    /// runs to completion on a task that owns the partition's turn, so a retry serializes
    /// behind it and never observes (or clobbers) a half-created blob.
    #[tokio::test]
    async fn test_open_dropped_mid_creation() {
        /// Polls the wrapped future normally, but drops it after a fixed number of polls.
        struct DropAfter<F: Future + Unpin> {
            inner: Option<F>,
            remaining: usize,
        }

        impl<F: Future + Unpin> Future for DropAfter<F> {
            type Output = Option<F::Output>;

            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                if self.remaining == 0 {
                    self.inner = None;
                    return Poll::Ready(None);
                }
                self.remaining -= 1;
                match self.inner.as_mut().unwrap().poll_unpin(cx) {
                    Poll::Ready(output) => Poll::Ready(Some(output)),
                    Poll::Pending => Poll::Pending,
                }
            }
        }

        let storage_directory =
            env::temp_dir().join(format!("test_dropped_open_{}", random_suffix()));
        let storage = Storage::new(Config::new(storage_directory.clone(), Layout::ALL));

        for depth in 0..64 {
            let name = format!("blob{depth}");
            let name = name.as_bytes();
            let dropped = DropAfter {
                inner: Some(Box::pin(storage.open("partition", name))),
                remaining: depth,
            }
            .await;
            let completed = dropped.is_some();
            drop(dropped);

            // Retry, write data, and confirm it survives reopen.
            let (blob, size) = storage.open("partition", name).await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(0, b"data".to_vec(), WriteOptions::default())
                .await
                .unwrap();
            blob.sync().await.unwrap();
            drop(blob);
            let (blob, size) = storage.open("partition", name).await.unwrap();
            assert_eq!(size, 4);
            let read = blob.read_at(0, 4, ReadOptions::default()).await.unwrap();
            assert_eq!(read.coalesce(), b"data");
            drop(blob);

            // Once the first open completes within the poll budget, deeper drops add nothing.
            if completed {
                let _ = std::fs::remove_dir_all(&storage_directory);
                return;
            }
        }
        panic!("open never completed within the poll budget");
    }

    #[tokio::test]
    async fn test_blob_v1_rejects_nonzero_header_padding() {
        let storage_directory =
            env::temp_dir().join(format!("test_v1_header_padding_{}", random_suffix()));
        let storage = Storage::new(Config::new(storage_directory.clone(), Layout::ALL));

        let partition_dir = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_dir).unwrap();
        let path = partition_dir.join(hex(b"dirty_padding"));
        let mut raw = crate::storage::header::tests::v1_blob_bytes(0, b"payload");
        raw[Header::PARSE_LEN] = 0xFF;
        std::fs::write(&path, raw).unwrap();

        let result = storage.open("partition", b"dirty_padding").await;
        assert!(
            matches!(result, Err(crate::Error::BlobCorrupt(_, _, reason)) if reason.contains("header padding"))
        );

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_v0_legacy_read() {
        let storage_directory =
            env::temp_dir().join(format!("test_v0_legacy_read_{}", random_suffix()));
        let storage = Storage::new(Config::new(storage_directory.clone(), Layout::ALL));

        // Fabricate a legacy V0 blob on disk (creation here produces V1): an 8-byte header
        // followed immediately by the payload.
        let payload = b"hello world";
        let partition_dir = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_dir).unwrap();
        let file_path = partition_dir.join(hex(b"v0"));
        std::fs::write(&file_path, crate::storage::tests::v0_blob_bytes(0, payload)).unwrap();

        // The blob opens with its data intact and remains readable and writable in place.
        let (blob, size) = storage.open("partition", b"v0").await.unwrap();
        assert_eq!(size, payload.len() as u64);
        assert_eq!(
            blob.read_at(0, payload.len(), ReadOptions::default())
                .await
                .unwrap()
                .coalesce(),
            payload
        );
        blob.write_at(size, b"!".to_vec(), WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        // On disk the payload still sits immediately after the 8-byte V0 header.
        let raw_content = std::fs::read(&file_path).unwrap();
        assert_eq!(raw_content.len(), Header::PRELUDE_SIZE + payload.len() + 1);
        assert_eq!(&raw_content[..Header::MAGIC_LENGTH], &Layout::V0.magic());
        assert_eq!(&raw_content[Header::PRELUDE_SIZE..], b"hello world!");

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_blob_magic_mismatch() {
        let storage_directory =
            env::temp_dir().join(format!("test_magic_mismatch_{}", random_suffix()));
        let storage = Storage::new(Config::new(storage_directory.clone(), Layout::ALL));

        // Create the partition directory and a file whose magic bytes are foreign (not a
        // prefix of any canonical header, so not a torn creation)
        let partition_path = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_path).unwrap();
        let bad_magic_path = partition_path.join(hex(b"bad_magic"));
        std::fs::write(&bad_magic_path, b"XXXXXXXX").unwrap();

        // Opening should fail with corrupt error
        let result = storage.open("partition", b"bad_magic").await;
        assert!(
            matches!(result, Err(crate::Error::BlobCorrupt(_, _, reason)) if reason.contains("invalid magic"))
        );

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    /// Any file shorter than a header prelude must reset to a valid, empty blob on open
    /// rather than fail as corrupt.
    #[tokio::test]
    async fn test_blob_partial_header_reset() {
        let storage_directory =
            env::temp_dir().join(format!("test_partial_header_reset_{}", random_suffix()));
        let storage = Storage::new(Config::new(storage_directory.clone(), Layout::ALL));
        let partition_path = storage_directory.join("partition");
        std::fs::create_dir_all(&partition_path).unwrap();

        for prefix_len in 0..Header::PRELUDE_SIZE {
            let name = format!("short_{prefix_len}");
            let path = partition_path.join(hex(name.as_bytes()));
            // Seed a file shorter than a full header.
            std::fs::write(&path, vec![0u8; prefix_len]).unwrap();

            let (blob, size) = storage
                .open("partition", name.as_bytes())
                .await
                .expect("interrupted create should recover, not fail");
            assert_eq!(size, 0, "recovered blob should be empty");
            drop(blob);

            // The recovered blob is a valid header-only file and reopens cleanly.
            let raw = std::fs::read(&path).unwrap();
            assert_eq!(
                raw.len(),
                Layout::V1.data_offset() as usize,
                "recovered blob should be header-only"
            );
            assert_eq!(&raw[..Header::MAGIC_LENGTH], &Layout::V1.magic());
            storage
                .open("partition", name.as_bytes())
                .await
                .expect("reopen after recovery should succeed");
        }

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_scan_rejects_non_canonical_hex_file_names() {
        // `commonware_formatting::from_hex` is lenient (strips `0x`/`0X` prefixes
        // and ASCII whitespace), but storage only ever writes filenames in the
        // canonical lowercase hex form produced by `hex()`. Verify that scans
        // reject any filename that decodes successfully but doesn't round-trip
        // to its canonical form.
        for bad_name in ["0x626c6f62", "0X626C6F62", " 626c6f62", "626C6F62"] {
            let storage_directory = env::temp_dir().join(format!(
                "test_scan_non_canonical_{}_{}",
                bad_name.replace([' ', '0', 'x', 'X'], "_"),
                random_suffix()
            ));
            let storage = Storage::new(Config::new(storage_directory.clone(), Layout::ALL));

            let partition_path = storage_directory.join("partition");
            std::fs::create_dir_all(&partition_path).unwrap();
            std::fs::write(partition_path.join(bad_name), []).unwrap();

            let err = match storage.scan("partition").await {
                Ok(_) => panic!("scan should have failed for filename {bad_name:?}"),
                Err(err) => err,
            };
            assert_eq!(
                err.to_string(),
                "partition corrupt: partition",
                "filename {bad_name:?} should be rejected as corrupt",
            );

            let _ = std::fs::remove_dir_all(&storage_directory);
        }
    }

    /// Scan and removal distinguish missing partitions from existing non-directory paths.
    #[tokio::test]
    async fn test_partition_failures_are_not_absence() {
        let directory = env::temp_dir().join(format!("storage_tokio_enotdir_{}", random_suffix()));
        fs::create_dir_all(&directory).unwrap();
        let partition = directory.join("partition");
        fs::write(&partition, b"not a directory").unwrap();
        let storage = Storage::new(Config::new(directory.clone(), Layout::ALL));

        assert!(matches!(
            storage.scan("partition").await,
            Err(Error::ReadFailed)
        ));
        assert!(matches!(
            storage.scan("missing").await,
            Err(Error::PartitionMissing(_))
        ));

        assert!(matches!(
            storage.remove("partition", None).await,
            Err(Error::Io(_))
        ));
        assert!(partition.exists());
        assert!(matches!(
            storage.remove("missing", None).await,
            Err(Error::PartitionMissing(_))
        ));

        drop(storage);
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(not(target_os = "linux"))]
    #[rstest::rstest]
    #[case(false)]
    #[case(true)]
    #[tokio::test]
    async fn test_partition_scan_waits_for_sync(#[case] cancel: bool) {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let directory =
                env::temp_dir().join(format!("storage_tokio_scan_sync_{}", random_suffix()));
            let partition = directory.join("partition");
            let other = directory.join("other");
            fs::create_dir_all(&partition).unwrap();
            fs::create_dir_all(&other).unwrap();
            let storage = Storage::new(Config::new(directory.clone(), Layout::ALL));
            crate::storage::sync(&directory).unwrap();

            // Pause the first directory barrier while it owns the partition's turn.
            let (entered, entering) = oneshot::channel();
            let (release, gate) = mpsc::channel();
            storage.partitions.sync_hook.lock().pause = Some((entered, gate));
            {
                let mut scan = Box::pin(storage.scan("partition"));
                assert!((&mut scan).now_or_never().is_none());
                entering.await.unwrap();
                assert!((&mut scan).now_or_never().is_none());

                // A queued scan must wait even if the initiating future is dropped.
                let mut next = Box::pin(storage.scan("partition"));
                assert!((&mut next).now_or_never().is_none());
                let scan = if cancel {
                    drop(scan);
                    None
                } else {
                    Some(scan)
                };
                release.send(()).unwrap();
                if let Some(scan) = scan {
                    assert!(scan.await.unwrap().is_empty());
                }
                assert!(next.await.unwrap().is_empty());
            }
            assert!(storage.partitions.synced.lock().contains(&partition));

            // A cached scan leaves the failure armed for the other partition's first barrier.
            storage.partitions.sync_hook.lock().fail = Some(Error::WriteFailed);
            assert!(storage.scan("partition").await.unwrap().is_empty());
            assert!(matches!(
                storage.scan("other").await,
                Err(Error::WriteFailed)
            ));
            assert!(storage.scan("other").await.unwrap().is_empty());
            assert!(matches!(
                storage.scan("missing").await,
                Err(Error::PartitionMissing(_))
            ));
            assert_eq!(storage.partitions.synced.lock().len(), 2);

            drop(storage);
            fs::remove_dir_all(directory).unwrap();
        })
        .await
        .unwrap();
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn test_partition_scan_sync_failure() {
        let directory =
            env::temp_dir().join(format!("storage_tokio_scan_fail_{}", random_suffix()));
        let partition = directory.join("partition");
        fs::create_dir_all(&partition).unwrap();
        let storage = Storage::new(Config::new(directory.clone(), Layout::ALL));
        crate::storage::sync(&directory).unwrap();
        storage.partitions.sync_hook.lock().fail = Some(Error::WriteFailed);

        assert!(matches!(
            storage.scan("partition").await,
            Err(Error::WriteFailed)
        ));
        assert!(!storage.partitions.synced.lock().contains(&partition));

        assert!(storage.scan("partition").await.unwrap().is_empty());
        assert!(storage.partitions.synced.lock().contains(&partition));

        drop(storage);
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn test_partition_open_syncs_once() {
        let directory =
            env::temp_dir().join(format!("storage_tokio_open_dir_sync_{}", random_suffix()));
        let partition = directory.join("partition");
        let config = Config::new(directory.clone(), Layout::ALL);

        // A fresh storage instance must synchronize the inherited blob's partition on first open.
        {
            let storage = Storage::new(config.clone());
            drop(storage.open("partition", b"blob").await.unwrap());
        }

        let storage = Storage::new(config);
        crate::storage::sync(&directory).unwrap();
        let (blob, size) = storage.open("partition", b"blob").await.unwrap();
        assert_eq!(size, 0);
        assert!(storage.partitions.synced.lock().contains(&partition));
        drop(blob);

        // A cached reopen must leave the sync failure armed.
        storage.partitions.sync_hook.lock().fail = Some(Error::WriteFailed);
        drop(storage.open("partition", b"blob").await.unwrap());
        assert!(storage.partitions.sync_hook.lock().fail.is_some());

        drop(storage);
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn test_partition_sync_creation_and_removal() {
        let directory =
            env::temp_dir().join(format!("storage_tokio_dir_lifecycle_{}", random_suffix()));
        let created = directory.join("created");
        let inherited = directory.join("inherited");
        let retired = directory.join("retired");
        let missing = directory.join("missing");
        let config = Config::new(directory.clone(), Layout::ALL);
        {
            let storage = Storage::new(config.clone());
            for partition in ["inherited", "retired"] {
                drop(storage.open(partition, b"blob").await.unwrap());
            }
        }

        let storage = Storage::new(config);
        crate::storage::sync(&directory).unwrap();

        // Creation synchronizes the partition, so its first scan can use the cache.
        drop(storage.open("created", b"blob").await.unwrap());
        assert!(storage.partitions.synced.lock().contains(&created));
        assert_eq!(
            storage.scan("created").await.unwrap(),
            vec![b"blob".to_vec()]
        );

        // Removing an inherited blob also synchronizes its partition before caching it.
        storage.remove("inherited", Some(b"blob")).await.unwrap();
        assert!(storage.partitions.synced.lock().contains(&inherited));
        assert!(storage.scan("inherited").await.unwrap().is_empty());

        // Removing a partition retires its cache entry before the name is reused.
        assert_eq!(
            storage.scan("retired").await.unwrap(),
            vec![b"blob".to_vec()]
        );
        storage.remove("retired", None).await.unwrap();
        assert!(matches!(
            storage.scan("retired").await,
            Err(Error::PartitionMissing(_))
        ));
        assert!(!storage.partitions.synced.lock().contains(&retired));
        drop(storage.open("retired", b"new").await.unwrap());
        assert!(storage.partitions.synced.lock().contains(&retired));
        assert_eq!(
            storage.scan("retired").await.unwrap(),
            vec![b"new".to_vec()]
        );

        assert!(matches!(
            storage.remove("missing", Some(b"blob")).await,
            Err(Error::BlobMissing(_, _))
        ));
        assert!(!storage.partitions.synced.lock().contains(&missing));
        drop(storage);
        fs::remove_dir_all(directory).unwrap();
    }

    /// A failed blob-removal directory sync leaves the partition uncached so the next scan
    /// completes that barrier before reporting the removal.
    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn test_blob_remove_sync_failure_retires_partition() {
        let directory =
            env::temp_dir().join(format!("storage_tokio_remove_fail_{}", random_suffix()));
        let partition = directory.join("partition");
        let config = Config::new(directory.clone(), Layout::ALL);
        {
            let storage = Storage::new(config.clone());
            drop(storage.open("partition", b"blob").await.unwrap());
        }

        let storage = Storage::new(config);
        crate::storage::sync(&directory).unwrap();
        assert_eq!(
            storage.scan("partition").await.unwrap(),
            vec![b"blob".to_vec()]
        );
        assert!(storage.partitions.synced.lock().contains(&partition));

        // The unlink lands, then the directory sync fails.
        storage.partitions.sync_hook.lock().fail = Some(Error::WriteFailed);
        assert!(matches!(
            storage.remove("partition", Some(b"blob")).await,
            Err(Error::WriteFailed)
        ));
        assert!(!partition.join(hex(b"blob")).exists());
        assert!(!storage.partitions.synced.lock().contains(&partition));

        // A later scan must finish the missing barrier before caching the empty partition.
        assert!(storage.scan("partition").await.unwrap().is_empty());
        assert!(storage.partitions.synced.lock().contains(&partition));

        drop(storage);
        fs::remove_dir_all(directory).unwrap();
    }

    /// Wait for every settling open to finish.
    async fn settle(storage: &Storage) {
        while storage.pending.outstanding() > 0 {
            tokio::task::yield_now().await;
        }
    }

    /// Dropping the last handle with unsynced writes leaves debt, and the next open flushes it
    /// before returning.
    #[tokio::test]
    async fn test_reopen_flushes_dirty_predecessor() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_reopen_flush_{}", random_suffix()));
        let config = Config::new(storage_directory.clone(), Layout::ALL);
        let storage = Storage::new(config);

        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        blob.write_at(0, b"hello", WriteOptions::default())
            .await
            .unwrap();
        drop(blob);
        assert!(storage.pending.owes("partition", b"blob"));
        assert_eq!(storage.pending.completions(), 0);

        let (blob, len) = storage.open("partition", b"blob").await.unwrap();
        assert!(!storage.pending.owes("partition", b"blob"));
        assert_eq!(storage.pending.completions(), 1);
        assert_eq!(len, 5);
        let read = blob
            .read_at(0, 5, ReadOptions::default())
            .await
            .unwrap()
            .coalesce();
        assert_eq!(read.as_ref(), b"hello");

        // The untouched handle drops clean and the next open owes nothing.
        drop(blob);
        settle(&storage).await;
        assert!(!storage.pending.owes("partition", b"blob"));
        drop(storage.open("partition", b"blob").await.unwrap());
        assert_eq!(storage.pending.completions(), 1);

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    /// Outside Linux there is no filesystem-wide startup flush, so the first open of an existing
    /// blob through a `Storage` flushes it. Later opens through that instance, and blobs it
    /// created, owe nothing.
    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn test_first_open_flushes_existing_blob() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_first_open_{}", random_suffix()));
        let config = Config::new(storage_directory.clone(), Layout::ALL);

        // A previous instance leaves a durable blob behind.
        {
            let storage = Storage::new(config.clone());
            let (blob, _) = storage.open("partition", b"blob").await.unwrap();
            blob.write_at(0, b"hello", WriteOptions::SYNC)
                .await
                .unwrap();
            drop(blob);
            settle(&storage).await;
            assert_eq!(storage.pending.completions(), 0);
        }

        let storage = Storage::new(config);
        let (blob, len) = storage.open("partition", b"blob").await.unwrap();
        assert_eq!(len, 5);
        assert_eq!(storage.pending.completions(), 1);
        drop(blob);
        settle(&storage).await;
        drop(storage.open("partition", b"blob").await.unwrap());
        assert_eq!(storage.pending.completions(), 1);

        drop(storage.open("partition", b"fresh").await.unwrap());
        settle(&storage).await;
        drop(storage.open("partition", b"fresh").await.unwrap());
        assert_eq!(storage.pending.completions(), 1);
        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn test_partition_open_sync_failure_keeps_content_debt() {
        let directory =
            env::temp_dir().join(format!("storage_tokio_open_dir_fail_{}", random_suffix()));
        let config = Config::new(directory.clone(), Layout::ALL);
        {
            let storage = Storage::new(config.clone());
            drop(storage.open("partition", b"blob").await.unwrap());
            settle(&storage).await;
        }

        let storage = Storage::new(config);
        crate::storage::sync(&directory).unwrap();
        storage.partitions.sync_hook.lock().fail = Some(Error::WriteFailed);
        assert!(matches!(
            storage.open("partition", b"blob").await,
            Err(Error::WriteFailed)
        ));
        assert!(storage.partitions.synced.lock().is_empty());
        assert_eq!(storage.pending.completions(), 0);
        assert!(storage.pending.owes("partition", b"blob"));

        // A retry must synchronize both the directory and the inherited file contents.
        let (blob, size) = storage.open("partition", b"blob").await.unwrap();
        assert_eq!(size, 0);
        assert!(
            storage
                .partitions
                .synced
                .lock()
                .contains(&directory.join("partition"))
        );
        assert_eq!(storage.pending.completions(), 1);
        assert!(!storage.pending.owes("partition", b"blob"));
        drop(blob);
        settle(&storage).await;
        drop(storage);
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn test_remove_forgets_first_open_names() {
        let storage_directory = env::temp_dir().join(format!(
            "storage_tokio_first_open_remove_{}",
            random_suffix()
        ));
        let storage = Storage::new(Config::new(storage_directory.clone(), Layout::ALL));
        for (partition, name) in [("a", b"1"), ("a", b"2"), ("b", b"1")] {
            drop(storage.open(partition, name).await.unwrap());
        }
        assert_eq!(storage.pending.flushed.lock().len(), 3);

        storage.remove("a", Some(b"1")).await.unwrap();
        assert!(
            !storage
                .pending
                .flushed
                .lock()
                .contains(&("a".to_owned(), b"1".to_vec()))
        );
        drop(storage.open("a", b"1").await.unwrap());
        drop(storage.open("a", b"1").await.unwrap());
        assert_eq!(storage.pending.completions(), 0);
        assert_eq!(storage.pending.flushed.lock().len(), 3);

        storage.remove("a", None).await.unwrap();
        assert_eq!(storage.pending.flushed.lock().len(), 1);
        assert!(
            storage
                .pending
                .flushed
                .lock()
                .contains(&("b".to_owned(), b"1".to_vec()))
        );
        storage.remove("b", None).await.unwrap();
        assert!(storage.pending.flushed.lock().is_empty());

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    /// A failed first-open flush is retained for the name until it is removed.
    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn test_first_open_flush_failure_is_retained() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_first_open_fail_{}", random_suffix()));
        let config = Config::new(storage_directory.clone(), Layout::ALL);
        {
            let storage = Storage::new(config.clone());
            let (blob, _) = storage.open("partition", b"blob").await.unwrap();
            blob.write_at(0, b"hello", WriteOptions::SYNC)
                .await
                .unwrap();
            drop(blob);
            settle(&storage).await;
        }

        let storage = Storage::new(config);
        *storage.pending.test.fail_flush.lock() = Some(Error::Closed);
        assert!(matches!(
            storage.open("partition", b"blob").await,
            Err(Error::Closed)
        ));
        assert!(matches!(
            storage.open("partition", b"blob").await,
            Err(Error::Closed)
        ));
        assert_eq!(storage.pending.completions(), 0);

        storage.remove("partition", Some(b"blob")).await.unwrap();
        let (_, len) = storage.open("partition", b"blob").await.unwrap();
        assert_eq!(len, 0);

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    /// Handles whose mutations are all durable leave no debt.
    #[tokio::test]
    async fn test_synced_drop_leaves_no_debt() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_synced_{}", random_suffix()));
        let config = Config::new(storage_directory.clone(), Layout::ALL);
        let storage = Storage::new(config);

        let (blob, _) = storage.open("partition", b"sync").await.unwrap();
        blob.write_at(0, b"hello", WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        let (blob, _) = storage.open("partition", b"start_sync").await.unwrap();
        blob.resize(16).await.unwrap();
        blob.start_sync().await.await.unwrap();
        drop(blob);

        let (blob, _) = storage.open("partition", b"sync_write").await.unwrap();
        blob.write_at(0, b"hello", WriteOptions::SYNC)
            .await
            .unwrap();
        drop(blob);

        settle(&storage).await;
        for name in [b"sync".as_slice(), b"start_sync", b"sync_write"] {
            assert!(!storage.pending.owes("partition", name));
            drop(storage.open("partition", name).await.unwrap());
        }
        assert_eq!(storage.pending.completions(), 0);

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    /// Shared owners retain one open: debt is recorded when its last owner drops dirty, and a
    /// sync through any owner clears the state.
    #[tokio::test]
    async fn test_shared_blob_dirty_state() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_shared_{}", random_suffix()));
        let config = Config::new(storage_directory.clone(), Layout::ALL);
        let storage = Storage::new(config);

        // Dropping one owner cannot publish debt while another can still synchronize it.
        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        let blob = Arc::new(blob);
        let retained = Arc::clone(&blob);
        blob.write_at(0, b"hello", WriteOptions::default())
            .await
            .unwrap();
        drop(blob);
        assert_eq!(storage.pending.outstanding(), 0);
        assert!(!storage.pending.owes("partition", b"blob"));

        // A sync through the remaining owner covers the write, so the final drop leaves no debt.
        retained.sync().await.unwrap();
        drop(retained);
        settle(&storage).await;
        assert!(!storage.pending.owes("partition", b"blob"));

        // An unsynced resize leaves debt only after the final owner drops. The next open
        // must establish that debt exactly once.
        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        let blob = Arc::new(blob);
        let retained = Arc::clone(&blob);
        blob.resize(0).await.unwrap();
        drop(blob);
        assert!(!storage.pending.owes("partition", b"blob"));
        drop(retained);
        settle(&storage).await;
        assert!(storage.pending.owes("partition", b"blob"));
        drop(storage.open("partition", b"blob").await.unwrap());
        assert_eq!(storage.pending.completions(), 1);

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_recreate_reopen_flushes_replacement() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_recreate_{}", random_suffix()));
        let storage = Storage::new(Config::new(storage_directory.clone(), Layout::ALL));
        shared::check_recreate_reopen(&storage, &storage.pending).await;
        shared::check_recreate_clean(&storage, &storage.pending).await;
        drop(storage);
        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_failed_creation_does_not_publish_unsynced_header() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_creation_{}", random_suffix()));
        let storage = Storage::new(Config::new(storage_directory.clone(), Layout::ALL));
        shared::check_failed_creation(&storage, &storage.pending).await;
        drop(storage);
        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_remove_live_dirty_owner_leaves_no_debt() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_remove_live_{}", random_suffix()));
        let storage = Storage::new(Config::new(storage_directory.clone(), Layout::ALL));
        shared::check_remove_live_dirty_owner(&storage, &storage.pending).await;
        drop(storage);
        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_durable_writes_need_no_reopen_flush() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_durable_{}", random_suffix()));
        let storage = Storage::new(Config::new(storage_directory.clone(), Layout::ALL));
        shared::check_sync_writes(&storage, &storage.pending).await;
        drop(storage);
        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_orphaned_write_lands_before_reopen() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_orphaned_{}", random_suffix()));
        let storage = Storage::new(Config::new(storage_directory.clone(), Layout::ALL));
        shared::check_orphaned_write(&storage).await;
        drop(storage);
        let _ = std::fs::remove_dir_all(storage_directory);
    }

    #[tokio::test]
    async fn test_untouched_creation_needs_no_reopen_flush() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_eager_creation_{}", random_suffix()));
        let storage = Storage::new(Config::new(storage_directory.clone(), Layout::ALL));
        shared::check_untouched_creation_leaves_no_debt(&storage, &storage.pending).await;
        drop(storage);
        std::fs::remove_dir_all(storage_directory).unwrap();
    }

    /// A sync on an open with no uncovered mutation returns without a device flush, so callers
    /// may sync freely, including immediately after a successful open.
    #[tokio::test]
    async fn test_clean_sync_is_skipped() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_clean_sync_{}", random_suffix()));
        let config = Config::new(storage_directory.clone(), Layout::ALL);
        let storage = Storage::new(config);

        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        blob.sync().await.unwrap();
        blob.start_sync().await.await.unwrap();
        assert_eq!(blob.skipped_syncs(), 2);

        // A mutation makes the next sync real, and only the next one.
        blob.write_at(0, b"hello", WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();
        assert_eq!(blob.skipped_syncs(), 2);
        blob.sync().await.unwrap();
        blob.resize(3).await.unwrap();
        blob.start_sync().await.await.unwrap();
        blob.start_sync().await.await.unwrap();
        assert_eq!(blob.skipped_syncs(), 4);
        drop(blob);
        settle(&storage).await;
        assert!(!storage.pending.owes("partition", b"blob"));

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    /// A failed flush is retained: the handle reports it on every later sync, and once it drops
    /// every open of the name fails until the blob is removed.
    #[tokio::test]
    async fn test_flush_failure_is_retained() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_flush_failure_{}", random_suffix()));
        let config = Config::new(storage_directory.clone(), Layout::ALL);
        let storage = Storage::new(config);

        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        blob.write_at(0, b"hello", WriteOptions::default())
            .await
            .unwrap();
        *storage.pending.test.fail_flush.lock() = Some(Error::Closed);
        assert!(matches!(blob.sync().await, Err(Error::Closed)));
        assert!(matches!(blob.sync().await, Err(Error::Closed)));
        assert!(matches!(blob.start_sync().await.await, Err(Error::Closed)));
        drop(blob);
        for _ in 0..2 {
            assert!(matches!(
                storage.open("partition", b"blob").await,
                Err(Error::Closed)
            ));
        }
        storage.remove("partition", Some(b"blob")).await.unwrap();
        let (blob, size) = storage.open("partition", b"blob").await.unwrap();
        assert_eq!(size, 0);
        drop(blob);

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    #[tokio::test]
    async fn test_durable_write_retains_prior_flush_failure() {
        let storage_directory = env::temp_dir().join(format!(
            "storage_tokio_durable_write_failure_{}",
            random_suffix()
        ));
        let storage = Storage::new(Config::new(storage_directory.clone(), Layout::ALL));

        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        blob.write_at(0, b"before", WriteOptions::default())
            .await
            .unwrap();
        *storage.pending.test.fail_flush.lock() = Some(Error::Closed);
        assert!(matches!(blob.sync().await, Err(Error::Closed)));

        // A later SYNC write must return the retained flush failure.
        let result = blob.write_at(6, b"after", WriteOptions::SYNC).await;
        drop(blob);
        storage.remove("partition", None).await.unwrap();
        drop(storage);
        std::fs::remove_dir_all(storage_directory).unwrap();
        assert!(matches!(result, Err(Error::Closed)), "{result:?}");
    }

    /// A completion that fails at open is retained for later opens instead of being retried, so
    /// a fresh descriptor cannot certify bytes the kernel already reported lost.
    #[tokio::test]
    async fn test_completion_failure_is_retained() {
        let storage_directory = env::temp_dir().join(format!(
            "storage_tokio_completion_failure_{}",
            random_suffix()
        ));
        let config = Config::new(storage_directory.clone(), Layout::ALL);
        let storage = Storage::new(config);

        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        blob.write_at(0, b"hello", WriteOptions::default())
            .await
            .unwrap();
        drop(blob);
        *storage.pending.test.fail_flush.lock() = Some(Error::WriteFailed);
        for _ in 0..2 {
            assert!(matches!(
                storage.open("partition", b"blob").await,
                Err(Error::WriteFailed)
            ));
        }
        assert_eq!(storage.pending.completions(), 0);
        storage.remove("partition", None).await.unwrap();
        let (blob, size) = storage.open("partition", b"blob").await.unwrap();
        assert_eq!(size, 0);
        drop(blob);

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    /// A completion that fails after its open was cancelled still retains the failure: the
    /// cancelled open's settlement carries it to the successor waiting on it, which fails
    /// instead of flushing a fresh descriptor past the error.
    #[tokio::test]
    async fn test_cancelled_completion_failure_is_retained() {
        let storage_directory = env::temp_dir().join(format!(
            "storage_tokio_cancelled_completion_{}",
            random_suffix()
        ));
        let config = Config::new(storage_directory.clone(), Layout::ALL);
        let storage = Storage::new(config);

        let (blob, _) = storage.open("partition", b"blob").await.unwrap();
        blob.write_at(0, b"hello", WriteOptions::default())
            .await
            .unwrap();
        drop(blob);

        // Hold the first reopen inside its flush, then cancel it while a second reopen waits.
        let (entered, entering) = oneshot::channel();
        let (release, gate) = mpsc::channel();
        *storage.pending.test.before_complete.lock() = Some((entered, gate));
        let mut cancelled = Box::pin(storage.open("partition", b"blob"));
        commonware_macros::select! {
            entered = entering => entered.unwrap(),
            _ = &mut cancelled => panic!("reopen must block in its flush"),
        }
        drop(cancelled);
        let mut successor = Box::pin(storage.open("partition", b"blob"));
        assert!((&mut successor).now_or_never().is_none());
        storage.scan("partition").await.unwrap();

        // The cancelled flush fails. The successor must inherit that failure, not flush again.
        *storage.pending.test.fail_flush.lock() = Some(Error::WriteFailed);
        release.send(()).unwrap();
        assert!(matches!(successor.await, Err(Error::WriteFailed)));
        assert_eq!(storage.pending.completions(), 0);
        assert!(matches!(
            storage.open("partition", b"blob").await,
            Err(Error::WriteFailed)
        ));
        storage.remove("partition", None).await.unwrap();

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    /// A reopen whose name is removed and recreated while it flushes publishes nothing into the
    /// recreated name, which still owes its own flush.
    #[tokio::test]
    async fn test_removed_incarnation_completion_publishes_nothing() {
        let storage_directory = env::temp_dir().join(format!(
            "storage_tokio_removed_completion_{}",
            random_suffix()
        ));
        let config = Config::new(storage_directory.clone(), Layout::ALL);
        let storage = Storage::new(config);

        let (old, _) = storage.open("partition", b"blob").await.unwrap();
        old.write_at(0, b"old", WriteOptions::default())
            .await
            .unwrap();
        drop(old);
        let (entered, entering) = oneshot::channel();
        let (release, gate) = mpsc::channel();
        *storage.pending.test.before_complete.lock() = Some((entered, gate));
        let mut reopen = Box::pin(storage.open("partition", b"blob"));
        commonware_macros::select! {
            entered = entering => entered.unwrap(),
            _ = &mut reopen => panic!("reopen must block in its flush"),
        }

        // Recreate the name underneath the blocked reopen and leave the replacement dirty.
        storage.remove("partition", Some(b"blob")).await.unwrap();
        let (current, len) = storage.open("partition", b"blob").await.unwrap();
        assert_eq!(len, 0);
        current
            .write_at(0, b"new", WriteOptions::default())
            .await
            .unwrap();
        drop(current);
        release.send(()).unwrap();
        let (removed, size) = reopen.await.unwrap();
        assert_eq!(size, 3);
        assert_eq!(
            removed
                .read_at(0, 3, ReadOptions::default())
                .await
                .unwrap()
                .coalesce()
                .as_ref(),
            b"old"
        );
        drop(removed);

        // The replacement's debt survived the removed incarnation's flush.
        assert!(storage.pending.owes("partition", b"blob"));
        let (blob, size) = storage.open("partition", b"blob").await.unwrap();
        assert_eq!(size, 3);
        assert_eq!(
            blob.read_at(0, 3, ReadOptions::default())
                .await
                .unwrap()
                .coalesce()
                .as_ref(),
            b"new"
        );
        assert_eq!(storage.pending.completions(), 2);
        drop(blob);

        let _ = std::fs::remove_dir_all(&storage_directory);
    }

    /// Removing a blob or its partition forgets its debt.
    #[tokio::test]
    async fn test_remove_forgets_debt() {
        let storage_directory =
            env::temp_dir().join(format!("storage_tokio_forget_{}", random_suffix()));
        let config = Config::new(storage_directory.clone(), Layout::ALL);
        let storage = Storage::new(config);

        for name in [b"a".as_slice(), b"b".as_slice()] {
            let (blob, _) = storage.open("partition", name).await.unwrap();
            blob.write_at(0, b"hello", WriteOptions::default())
                .await
                .unwrap();
            drop(blob);
            assert!(storage.pending.owes("partition", name));
        }
        storage.remove("partition", Some(b"a")).await.unwrap();
        assert!(!storage.pending.owes("partition", b"a"));
        assert!(storage.pending.owes("partition", b"b"));
        storage.remove("partition", None).await.unwrap();
        assert!(!storage.pending.owes("partition", b"b"));
        assert!(storage.pending.entries.lock().is_empty());

        let _ = std::fs::remove_dir_all(&storage_directory);
    }
}
