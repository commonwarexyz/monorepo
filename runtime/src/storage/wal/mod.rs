//! A [crate::Storage] backend where blobs stay ordinary files and one write-ahead log
//! per family owns the namespace.
//!
//! Blob creation, deletion, and partition teardown become records in the family's WAL,
//! group-committed under shared barriers: K concurrent namespace operations cost one
//! fdatasync and no directory fsyncs on their path. `scan` reads the catalog, never
//! the directory. Blob *content* stays exactly where it is today: ordinary files,
//! written and synced through their own descriptors, with kernel fd isolation and
//! self-describing salvage. The WAL is the namespace's truth; the file is the bytes'.
//!
//! This split is what later phases build on: atomic blobs add WAL-owned logical
//! lengths and multi-blob atomic publication on the same log, without moving payload
//! into a shared container.
//!
//! # Families
//!
//! A family is the unit of WAL ownership: one log, one committer, one failure domain.
//! Today each partition is its own family (the mapping is intrinsic; no routing
//! configuration exists to misconfigure). Grouping several partitions into one family
//! buys nothing until multi-blob batches exist, so it arrives with them.
//!
//! # The master rule (M)
//!
//! A byte of blob-file content, a directory entry, or a directory may become
//! load-bearing (some durable WAL record or snapshot asserts state depending on it)
//! only after a completed barrier on the file or directory holding it, issued and
//! completed before the asserting record was written. The [medium::Checked] wrapper
//! makes this machine-checkable in every test. Today's records assert nothing about
//! blob files, so the rule binds only the WAL's own creation staging; it becomes
//! load-bearing when atomic publication lands.
//!
//! # Crash semantics for ordinary blobs
//!
//! Identical to the per-file backends, with one deliberate divergence: a blob whose
//! file vanishes (its dentry was never synced before a crash) reopens empty rather
//! than surfacing an error, exactly as a never-created blob would today. Acknowledged
//! namespace operations always survive: `open`'s Ok proves the create record is
//! durable, `remove`'s Ok proves the delete record is durable. A blob's first
//! successful durability event (sync, or a SYNC write) additionally syncs its
//! directory and the root, so acknowledged *content* is never orphaned by a missing
//! dentry.
//!
//! Built bottom-up: [medium] is the I/O seam and crash model; [mod@format] the on-disk
//! layout; [catalog] the namespace as a fold over records; [journal] creation,
//! recovery, and checkpoints; [committer] group commit; [blob] the handles; this
//! module the family registry and the [crate::Storage] implementation.

mod blob;
mod catalog;
mod committer;
mod format;
mod journal;
pub mod medium;

pub use blob::Blob;
pub use committer::Spawn;
use committer::{Committer, Stage};
use commonware_cryptography::{Hasher as _, Sha256};
use commonware_formatting::hex;
use commonware_utils::{channel::oneshot, sync::Mutex};
use format::{Kind, MAX_NAME_LEN, Record};
use journal::Journal;
use medium::Medium;
use std::{collections::BTreeMap, ops::RangeInclusive, sync::Arc};

/// Directory holding every family's WAL file. Not a legal partition name (partition
/// names cannot contain dots), so user blobs can never collide with it.
const WAL_DIR: &str = ".wal";

/// Configuration for a WAL storage.
#[derive(Clone, Debug, Default)]
pub struct Config {
    /// Entropy for the incarnation stamped into newly created WAL files (existing
    /// files keep the incarnation in their header). Mixed with the partition name, so
    /// one seed serves every family; supply real entropy in production so records
    /// from a copied or resurrected file can never validate against a recreated one.
    pub creation_seed: [u8; 16],
}

/// A WAL-backed storage: blobs are ordinary files; each partition's namespace lives
/// in one write-ahead log.
pub struct Storage<M: Medium> {
    medium: M,
    spawn: Spawn,
    creation_seed: [u8; 16],
    families: Arc<Mutex<BTreeMap<String, Slot>>>,
}

impl<M: Medium> Clone for Storage<M> {
    fn clone(&self) -> Self {
        Self {
            medium: self.medium.clone(),
            spawn: self.spawn.clone(),
            creation_seed: self.creation_seed,
            families: self.families.clone(),
        }
    }
}

/// Registry state of one family.
enum Slot {
    /// Being opened (or removed) by one task; waiters are notified with the outcome.
    /// `Ok(None)` means the family does not exist (or was just removed).
    Busy(Vec<oneshot::Sender<Result<Option<Committer>, crate::Error>>>),
    Open(Committer),
}

/// Removes a `Busy` slot if its owner is dropped mid-operation, waking waiters to
/// retry.
struct BusyGuard<'a> {
    families: &'a Mutex<BTreeMap<String, Slot>>,
    partition: &'a str,
    armed: bool,
}

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Dropping the slot drops the waiters' senders; their receivers error and the
        // waiters retry from scratch.
        self.families.lock().remove(self.partition);
    }
}

impl BusyGuard<'_> {
    /// Publishes the operation's outcome: registers the family (if any) and notifies
    /// every waiter.
    fn finish(mut self, result: &Result<Option<Committer>, crate::Error>) {
        self.armed = false;
        let mut families = self.families.lock();
        let Some(Slot::Busy(waiters)) = families.remove(self.partition) else {
            unreachable!("busy slot owned by this guard");
        };
        if let Ok(Some(committer)) = result {
            families.insert(self.partition.to_string(), Slot::Open(committer.clone()));
        }
        drop(families);
        for waiter in waiters {
            let _ = waiter.send(result.clone());
        }
    }
}

impl<M: Medium> Storage<M> {
    /// Wraps `medium` so each partition's namespace lives in one write-ahead log.
    pub fn new(medium: M, spawn: Spawn, cfg: Config) -> Self {
        Self {
            medium,
            spawn,
            creation_seed: cfg.creation_seed,
            families: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// The family's WAL file name.
    fn wal_name(partition: &str) -> String {
        format!("{partition}.cww")
    }

    /// Returns the partition's committer, opening its family if needed. With
    /// `create`, a missing family is created; without, `Ok(None)` is returned.
    async fn family(
        &self,
        partition: &str,
        create: bool,
    ) -> Result<Option<Committer>, crate::Error> {
        loop {
            // Claim the slot or join the waiters of whoever holds it.
            let waiter = {
                let mut families = self.families.lock();
                match families.get_mut(partition) {
                    None => {
                        families.insert(partition.to_string(), Slot::Busy(Vec::new()));
                        None
                    }
                    Some(Slot::Busy(waiters)) => {
                        let (tx, rx) = oneshot::channel();
                        waiters.push(tx);
                        Some(rx)
                    }
                    Some(Slot::Open(committer)) => return Ok(Some(committer.clone())),
                }
            };
            if let Some(rx) = waiter {
                match rx.await {
                    Ok(result) => {
                        // A `None` outcome (missing or removed) is final for the
                        // opener but not for us: with `create` we retry and create.
                        match result? {
                            Some(committer) => return Ok(Some(committer)),
                            None if !create => return Ok(None),
                            None => continue,
                        }
                    }
                    // The opener was dropped mid-operation; retry from scratch.
                    Err(_) => continue,
                }
            }

            // We own the Busy slot: open (or decline to create) the family.
            let guard = BusyGuard {
                families: &self.families,
                partition,
                armed: true,
            };
            if !create
                && matches!(
                    self.medium.open(WAL_DIR, &Self::wal_name(partition)).await,
                    Ok(None)
                )
            {
                let result = Ok(None);
                guard.finish(&result);
                return result;
            }
            let incarnation = incarnation(&self.creation_seed, partition);
            let result = Journal::open(
                &self.medium,
                WAL_DIR,
                &Self::wal_name(partition),
                incarnation,
            )
            .await
            .map(|(journal, catalog)| {
                let shared = Arc::new(committer::Shared::new(catalog));
                Some(Committer::spawn::<M>(&self.spawn, journal, shared))
            });
            guard.finish(&result);
            return result;
        }
    }

    /// Opens (creating if needed) the blob's file. A row may exist without a file
    /// (lazy creation, or a dentry lost before its first sync): it reopens empty,
    /// exactly as a never-created blob would under the per-file backends. Stale
    /// predecessor files cannot reach here: acknowledged removes unlink durably, and
    /// the mint path durably replaces any leftover before its record is staged.
    async fn blob_file(&self, partition: &str, name: &str) -> Result<M::File, crate::Error> {
        if let Some(file) = self.medium.open(partition, name).await? {
            return Ok(file);
        }
        self.medium.create(partition, name).await
    }
}

/// Derives a family's forever-identity from the deployment seed and its name.
fn incarnation(seed: &[u8; 16], partition: &str) -> [u8; 16] {
    let digest = Sha256::hash(&[seed, partition.as_bytes()]);
    digest.0[..16].try_into().unwrap()
}

fn invalid_input(partition: &str, name: &[u8], reason: &str) -> crate::Error {
    crate::Error::BlobOpenFailed(
        partition.to_string(),
        hex(name),
        Arc::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            reason.to_string(),
        )),
    )
}

impl<M: Medium> crate::Storage for Storage<M> {
    type Blob = Blob<M>;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
    ) -> Result<(Self::Blob, u64, u16), crate::Error> {
        super::validate_partition_name(partition)?;
        // Reject names the record format cannot carry: accepting one would journal a
        // create that replay refuses, poisoning the whole family.
        if name.len() > MAX_NAME_LEN {
            return Err(invalid_input(partition, name, "blob name too long"));
        }
        let committer = self
            .family(partition, true)
            .await?
            .expect("creating family lookups always return a committer");

        // Find the row, or mint one under a name reservation. An existing row stages
        // a rider, because its create (staged by a concurrent opener) may not be
        // durable yet and our Ok must prove it is.
        let filename = hex(name);
        let (ack, version) = loop {
            let existing = committer
                .shared()
                .read(|catalog| catalog.get(partition, name).map(|row| row.version));
            if let Some(version) = existing {
                let (ack, ()) = committer.transact(|catalog| {
                    match catalog.get(partition, name) {
                        Some(_) => (Stage::Rider, ()),
                        // Deleted between the read and the transact; mint instead.
                        None => (Stage::Nothing, ()),
                    }
                })?;
                match ack {
                    Some(ack) => break (ack, version),
                    None => continue,
                }
            }

            // Mint path, serialized per name: a file already under the name can only
            // be an unacknowledged remove's leftover (acknowledged removes unlink
            // durably), and it must be replaced durably BEFORE the create record is
            // staged, or a crash could revive it under the durable new row.
            let reservation = match committer.shared().reserve(name) {
                Ok(reservation) => reservation,
                Err(waiter) => {
                    let _ = waiter.await;
                    continue;
                }
            };
            if self.medium.open(partition, &filename).await?.is_some() {
                let _ = self.medium.remove(partition, &filename).await;
                self.medium.create(partition, &filename).await?;
                self.medium.sync_dir(partition).await?;
            }
            let version = *versions.end();
            let (ack, staged) = committer.transact(|catalog| {
                if catalog.get(partition, name).is_some() {
                    // Lost a race that slipped a row in; retry as existing.
                    return (Stage::Nothing, false);
                }
                let record = Record::Create {
                    id: catalog.mint_id(),
                    kind: Kind::Ordinary,
                    version,
                    partition: partition.to_string(),
                    name: name.to_vec(),
                };
                (Stage::Record(record), true)
            })?;
            drop(reservation);
            match (ack, staged) {
                (Some(ack), true) => break (ack, version),
                _ => continue,
            }
        };
        if !versions.contains(&version) {
            return Err(crate::Error::BlobVersionMismatch {
                expected: versions,
                found: version,
            });
        }
        // "Ok means durably created": await the create record, or the rider proving
        // an earlier opener's create is durable.
        ack.await.map_err(|_| crate::Error::Closed)??;

        let file = self.blob_file(partition, &filename).await?;
        let blob = Blob::new(self.medium.clone(), file, partition, name);
        let size = blob.size().await?;
        Ok((blob, size, version))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), crate::Error> {
        super::validate_partition_name(partition)?;
        let Some(committer) = self.family(partition, false).await? else {
            return Err(crate::Error::PartitionMissing(partition.to_string()));
        };
        match name {
            Some(name) => {
                // Journal the delete; Ok proves it durable. The unlink is lazy:
                // completion means catalog truth, and a lingering dentry is invisible
                // (scan reads the catalog) and swept on recreation.
                let (ack, found) = committer.transact(|catalog| {
                    catalog
                        .get(partition, name)
                        .map_or((Stage::Nothing, false), |row| {
                            (Stage::Record(Record::Delete { id: row.id }), true)
                        })
                })?;
                if !found {
                    return Err(crate::Error::BlobMissing(partition.to_string(), hex(name)));
                }
                ack.expect("delete staged")
                    .await
                    .map_err(|_| crate::Error::Closed)??;
                // Durable unlink before Ok (the per-file backends' cost, honestly
                // kept): once removal acknowledges, no crash can revive the file, so
                // recreation freshness needs no content identity.
                if self.medium.remove(partition, &hex(name)).await.is_ok() {
                    self.medium.sync_dir(partition).await?;
                }
                Ok(())
            }
            None => {
                // Removing the partition removes the family. Sweep the blob files
                // durably FIRST, then unlink the WAL: once the WAL is durably gone,
                // the directory holds nothing revivable, so a future adoption pass
                // can never resurrect removed blobs. A crash mid-sweep leaves the
                // WAL governing (partial teardown, unacknowledged: the same shape a
                // crash mid-unlink-loop produces today).
                let names = committer.shared().read(|catalog| catalog.scan(partition));
                {
                    let mut families = self.families.lock();
                    families.remove(partition);
                }
                for blob in names.unwrap_or_default() {
                    let _ = self.medium.remove(partition, &hex(&blob)).await;
                }
                self.medium.sync_dir(partition).await?;
                self.medium
                    .remove(WAL_DIR, &Self::wal_name(partition))
                    .await?;
                self.medium.sync_dir(WAL_DIR).await?;
                Ok(())
            }
        }
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, crate::Error> {
        super::validate_partition_name(partition)?;
        let Some(committer) = self.family(partition, false).await? else {
            return Err(crate::Error::PartitionMissing(partition.to_string()));
        };
        // The family exists, so the partition exists, even before its first record
        // lands a partition row (or after every blob is removed).
        Ok(committer
            .shared()
            .read(|catalog| catalog.scan(partition))
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Blob as _, Storage as _,
        storage::{tests::run_storage_tests, wal::medium::Sim},
    };

    fn test_spawn() -> Spawn {
        Arc::new(|future| {
            tokio::spawn(future);
        })
    }

    fn wal_storage(sim: &Sim) -> Storage<Sim> {
        Storage::new(sim.clone(), test_spawn(), Config::default())
    }

    #[tokio::test]
    async fn storage_suite() {
        run_storage_tests(wal_storage(&Sim::new(1))).await;
    }

    #[tokio::test]
    async fn acknowledged_namespace_survives_crashes() {
        for seed in 0..16 {
            let sim = Sim::new(seed);
            let storage = wal_storage(&sim);
            let (blob, _) = storage.open("p", b"kept").await.unwrap();
            blob.write_at(0, vec![7u8; 64], crate::WriteOptions::default())
                .await
                .unwrap();
            blob.sync().await.unwrap();
            storage.open("p", b"removed").await.unwrap();
            storage.remove("p", Some(b"removed")).await.unwrap();

            sim.crash();
            let storage = wal_storage(&sim);
            let names = storage.scan("p").await.unwrap();
            assert_eq!(names, vec![b"kept".to_vec()], "seed {seed}");
            let (blob, size) = storage.open("p", b"kept").await.unwrap();
            assert_eq!(size, 64, "seed {seed}");
            let bytes = blob.read_at(0, 64).await.unwrap().coalesce();
            assert_eq!(bytes.as_ref(), &[7u8; 64][..], "seed {seed}");
        }
    }

    #[tokio::test]
    async fn removed_partition_is_missing_after_crash() {
        let sim = Sim::new(3);
        let storage = wal_storage(&sim);
        storage.open("p", b"a").await.unwrap();
        storage.remove("p", None).await.unwrap();
        assert!(matches!(
            storage.scan("p").await,
            Err(crate::Error::PartitionMissing(_))
        ));

        sim.crash();
        let storage = wal_storage(&sim);
        assert!(matches!(
            storage.scan("p").await,
            Err(crate::Error::PartitionMissing(_))
        ));
    }

    #[tokio::test]
    async fn recreation_after_crash_reverted_unlink_is_empty() {
        // Remove's unlink is lazy (an unsynced dentry operation), so a crash can
        // revive the file while the delete record stays durable. The recreated row
        // must still open empty: the replacement happens before the create record is
        // staged, so no crash window exposes the predecessor's bytes.
        for seed in 0..16 {
            let sim = Sim::new(seed);
            let storage = wal_storage(&sim);
            let (blob, _) = storage.open("p", b"a").await.unwrap();
            blob.write_at(0, vec![0xAA; 32], crate::WriteOptions::SYNC)
                .await
                .unwrap();
            storage.remove("p", Some(b"a")).await.unwrap();

            sim.crash();
            let storage = wal_storage(&sim);
            assert!(storage.scan("p").await.unwrap().is_empty(), "seed {seed}");
            let (blob, size) = storage.open("p", b"a").await.unwrap();
            assert_eq!(size, 0, "seed {seed}: stale predecessor bytes exposed");
            drop(blob);
        }
    }

    #[tokio::test]
    async fn recreation_replacement_survives_crash() {
        // The dangerous window: the recreate's file replacement is itself an unsynced
        // dentry operation. If a crash reverts it after the create record became
        // durable, the revived predecessor file must still never be served under the
        // new row.
        for seed in 0..16 {
            let sim = Sim::new(seed);
            let storage = wal_storage(&sim);
            let (blob, _) = storage.open("p", b"a").await.unwrap();
            blob.write_at(0, vec![0xAA; 32], crate::WriteOptions::SYNC)
                .await
                .unwrap();
            storage.remove("p", Some(b"a")).await.unwrap();
            // Recreate: the create record is durable at Ok, the file ops are not.
            let (fresh, size) = storage.open("p", b"a").await.unwrap();
            assert_eq!(size, 0, "seed {seed}");
            drop(fresh);

            sim.crash();
            let storage = wal_storage(&sim);
            let (blob, size) = storage.open("p", b"a").await.unwrap();
            assert_eq!(size, 0, "seed {seed}: revived predecessor served");
            drop(blob);
        }
    }

    #[tokio::test]
    async fn recreated_name_never_shows_stale_bytes() {
        let sim = Sim::new(4);
        let storage = wal_storage(&sim);
        let (blob, _) = storage.open("p", b"a").await.unwrap();
        blob.write_at(0, vec![0xAA; 32], crate::WriteOptions::SYNC)
            .await
            .unwrap();
        storage.remove("p", Some(b"a")).await.unwrap();

        // Recreate under the same name: a fresh, empty blob, even though the old
        // handle still reads the old bytes.
        let (fresh, size) = storage.open("p", b"a").await.unwrap();
        assert_eq!(size, 0);
        drop(fresh);
        assert_eq!(
            blob.read_at(0, 32).await.unwrap().coalesce().as_ref(),
            &[0xAA; 32][..]
        );
    }
}
