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
//! Built bottom-up: [medium] is the I/O seam and crash model; `format` the on-disk
//! layout; `catalog` the namespace as a fold over records; `journal` creation,
//! recovery, and checkpoints; `committer` group commit; `blob` and `atomic` the
//! handles; this module the family registry and the [crate::Storage] and
//! [crate::AtomicStorage] implementations.

mod atomic;
mod blob;
mod catalog;
mod committer;
mod format;
#[cfg(unix)]
mod fs;
mod journal;
pub mod medium;

use super::header::{Header, Layout, resolve as resolve_header};
pub use atomic::AtomicBlob;
pub use blob::Blob;
pub use committer::Spawn;
use committer::{Committer, Stage};
use commonware_cryptography::{Hasher as _, Sha256};
use commonware_formatting::{from_hex, hex};
use commonware_utils::{channel::oneshot, sync::Mutex};
use format::{Kind, MAX_NAME_LEN, Record};
#[cfg(unix)]
pub use fs::Fs;
use journal::Journal;
use medium::{File as _, Medium};
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
            let result = self.open_family(partition, create).await;
            guard.finish(&result);
            return result;
        }
    }

    /// Opens, creates, or declines to create one family (under the registry's Busy
    /// slot). A partition directory holding blob files but no WAL is pre-WAL data:
    /// creating its family first adopts every file into the catalog, before anything
    /// serves, so catalog-backed scans can never hide legacy blobs.
    async fn open_family(
        &self,
        partition: &str,
        create: bool,
    ) -> Result<Option<Committer>, crate::Error> {
        let existed = self
            .medium
            .open(WAL_DIR, &Self::wal_name(partition))
            .await?
            .is_some();
        if !existed && !create {
            // No WAL: the partition exists only if legacy files do (then any
            // operation, even a scan, performs the adoption).
            let legacy = self
                .medium
                .list(partition)
                .await?
                .is_some_and(|files| !files.is_empty());
            if !legacy {
                return Ok(None);
            }
        }
        let incarnation = incarnation(&self.creation_seed, partition);
        let (journal, catalog) = Journal::open(
            &self.medium,
            WAL_DIR,
            &Self::wal_name(partition),
            incarnation,
        )
        .await?;
        let shared = Arc::new(committer::Shared::new(catalog));
        let committer = Committer::spawn::<M>(&self.spawn, journal, shared);
        if !existed {
            self.adopt(partition, &committer).await?;
        }
        Ok(Some(committer))
    }

    /// Adopts every pre-WAL blob file in the partition directory: one catalog row per
    /// file, version read from its header, no payload touched. Runs exactly once, at
    /// family creation; afterwards un-cataloged files are unlink leftovers, never
    /// adoptees. Extraction is the inverse: delete the WAL and the files stand alone.
    async fn adopt(&self, partition: &str, committer: &Committer) -> Result<(), crate::Error> {
        let Some(files) = self.medium.list(partition).await? else {
            return Ok(());
        };
        let mut acks = Vec::new();
        for filename in files {
            // Only files this backend's naming could have produced are adoptable;
            // anything else is foreign, and adopting around it would silently shadow
            // data. Fail loudly instead.
            let name = from_hex(&filename)
                .filter(|name| hex(name) == filename)
                .ok_or_else(|| {
                    crate::Error::PartitionCorrupt(format!(
                        "{partition}: foreign file {filename:?} in a partition being adopted"
                    ))
                })?;
            let file = self
                .medium
                .open(partition, &filename)
                .await?
                .expect("listed file exists");
            let raw_len = file.size().await?;
            let raw = file.read_at(0, Header::resolve_len(raw_len)).await?;
            // Empty or torn-creation files (None) are effectively nonexistent,
            // exactly as the per-file backends treat them; the next open recreates.
            if let Some((_, version, _)) =
                resolve_header(&raw, raw_len, &(0..=u16::MAX), partition, &name)?
            {
                let (ack, ()) = committer.transact(|catalog| {
                    let record = Record::Create {
                        id: catalog.mint_id(),
                        kind: Kind::Ordinary,
                        version,
                        partition: partition.to_string(),
                        name: name.clone(),
                    };
                    (Stage::Record(record), ())
                })?;
                acks.push(ack.expect("adoption staged"));
            }
        }
        for ack in acks {
            ack.await.map_err(|_| crate::Error::Closed)??;
        }
        Ok(())
    }

    /// Finds the blob's row or mints one, returning it once its creation is
    /// provably durable ("Ok means durably created").
    ///
    /// An existing row rides a frameless request behind its create in the committer
    /// queue, so a concurrent opener's not-yet-durable create is covered. Minting is
    /// serialized per name by a reservation, and a file already under the name (only
    /// possible from an unacknowledged remove, since acknowledged removes unlink
    /// durably) is replaced durably BEFORE the create record is staged, so no crash
    /// can revive predecessor bytes under the durable new row.
    async fn claim_row(
        &self,
        committer: &Committer,
        partition: &str,
        name: &[u8],
        mint: impl Fn() -> Kind,
        versions: &RangeInclusive<u16>,
    ) -> Result<catalog::Row, crate::Error> {
        let filename = hex(name);
        let (ack, row) = loop {
            let existing = committer
                .shared()
                .read(|catalog| catalog.get(partition, name).cloned());
            if let Some(row) = existing {
                let (ack, ()) = committer.transact(|catalog| {
                    match catalog.get(partition, name) {
                        Some(_) => (Stage::Rider, ()),
                        // Deleted between the read and the transact; mint instead.
                        None => (Stage::Nothing, ()),
                    }
                })?;
                match ack {
                    Some(ack) => break (ack, row),
                    None => continue,
                }
            }

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
            let (ack, row) = committer.transact(|catalog| {
                if catalog.get(partition, name).is_some() {
                    // Lost a race that slipped a row in; retry as existing.
                    return (Stage::Nothing, None);
                }
                let row = catalog::Row {
                    id: catalog.mint_id(),
                    kind: mint(),
                    version,
                };
                let record = Record::Create {
                    id: row.id,
                    kind: row.kind.clone(),
                    version,
                    partition: partition.to_string(),
                    name: name.to_vec(),
                };
                (Stage::Record(record), Some(row))
            })?;
            drop(reservation);
            match (ack, row) {
                (Some(ack), Some(row)) => break (ack, row),
                _ => continue,
            }
        };
        if !versions.contains(&row.version) {
            return Err(crate::Error::BlobVersionMismatch {
                expected: versions.clone(),
                found: row.version,
            });
        }
        ack.await.map_err(|_| crate::Error::Closed)??;
        Ok(row)
    }

    /// Opens an existing atomic blob or creates a new one. The returned handle is
    /// append-only with all-or-nothing publication; see [AtomicBlob]. Opening an
    /// ordinary blob this way fails (promote it first); opening an atomic blob with
    /// [crate::Storage::open_versioned] fails symmetrically.
    pub async fn open_atomic_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
    ) -> Result<(AtomicBlob<M>, u64, u16), crate::Error> {
        super::validate_partition_name(partition)?;
        if name.len() > MAX_NAME_LEN {
            return Err(invalid_input(partition, name, "blob name too long"));
        }
        let committer = self
            .family(partition, true)
            .await?
            .expect("creating family lookups always return a committer");
        let row = self
            .claim_row(&committer, partition, name, Kind::atomic, &versions)
            .await?;
        let (committed, trusted) = match &row.kind {
            Kind::Atomic {
                committed, trusted, ..
            } => (*committed, *trusted),
            Kind::Ordinary => {
                return Err(invalid_input(
                    partition,
                    name,
                    "blob is ordinary; promote it first",
                ));
            }
        };
        let filename = hex(name);
        let (file, data_offset) = self
            .open_atomic_file(partition, name, &filename, row.version, trusted)
            .await?;
        let blob = AtomicBlob::new(
            self.medium.clone(),
            file,
            committer,
            row.id,
            partition,
            name,
            data_offset,
            committed,
        );
        Ok((blob, committed, row.version))
    }

    /// Opens an atomic blob's file. Unlike ordinary blobs, a missing or torn file
    /// under a row with trusted content is a hard error: those bytes were barriered
    /// before the record asserting them was written (rule M), so their absence means
    /// the filesystem broke its guarantee, never a legal crash shape. A row with no
    /// trusted content recreates freely (all its committed bytes live in the WAL).
    async fn open_atomic_file(
        &self,
        partition: &str,
        name: &[u8],
        filename: &str,
        version: u16,
        trusted: u64,
    ) -> Result<(M::File, u64), crate::Error> {
        let existing = self.medium.open(partition, filename).await?;
        let file = match existing {
            Some(file) => file,
            None if trusted == 0 => self.medium.create(partition, filename).await?,
            None => {
                return Err(crate::Error::BlobCorrupt(
                    partition.to_string(),
                    hex(name),
                    "atomic blob file with trusted content is missing".into(),
                ));
            }
        };
        let raw_len = file.size().await?;
        let raw = file.read_at(0, Header::resolve_len(raw_len)).await?;
        match resolve_header(&raw, raw_len, &(version..=version), partition, name)? {
            Some((_, _, data_offset)) => Ok((file, data_offset)),
            None if trusted == 0 => {
                let (region, _) = Header::create(&(version..=version));
                file.write_at(0, region).await?;
                Ok((file, Layout::V1.data_offset()))
            }
            None => Err(crate::Error::BlobCorrupt(
                partition.to_string(),
                hex(name),
                "atomic blob file with trusted content has no valid header".into(),
            )),
        }
    }

    /// Publishes several atomic blobs' staged epochs all-or-nothing: after Ok,
    /// recovery reproduces every epoch; a crash before the shared frame survives
    /// reproduces none of them. All blobs must live in `partition` (one family).
    ///
    /// Bulk epochs are welcome (their waves complete before the frame), except one
    /// that rewinds below its trusted length, which needs a durability split that
    /// would break the batch's atomicity: publish that blob alone.
    pub async fn publish_all(
        &self,
        partition: &str,
        blobs: &[&AtomicBlob<M>],
    ) -> Result<(), crate::Error> {
        let Some(committer) = self.family(partition, false).await? else {
            return Err(crate::Error::PartitionMissing(partition.to_string()));
        };
        for blob in blobs {
            if blob.partition() != partition {
                return Err(crate::Error::Io(Arc::new(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "a batch cannot span partitions (families)",
                ))));
            }
        }

        // Freeze every epoch, plan each (waves included), and stage one frame.
        let mut frozen: Vec<(usize, usize)> = Vec::new();
        let result: Result<Option<committer::Ack>, crate::Error> = async {
            let mut records = Vec::new();
            for (i, blob) in blobs.iter().enumerate() {
                if let Some(ops) = blob.freeze()? {
                    frozen.push((i, ops.len()));
                    for record in blob.plan(&ops, false).await? {
                        blob.verify_claims(&record);
                        records.push(record);
                    }
                }
            }
            if records.is_empty() {
                return Ok(None);
            }
            let record = if records.len() == 1 {
                records.pop().expect("one record")
            } else {
                Record::Batch(records)
            };
            let (ack, ()) = committer.transact(|_| (Stage::Record(record), ()))?;
            Ok(ack)
        }
        .await;

        let failed = result.is_err();
        for (i, count) in frozen {
            blobs[i].unfreeze(count, failed);
        }
        match result? {
            Some(ack) => ack.await.map_err(|_| crate::Error::Closed)?,
            None => Ok(()),
        }
    }

    /// Extracts a partition from WAL management, the inverse of adoption: every
    /// atomic row's overlay is materialized into its file and the file clamped to
    /// the committed length (so the file alone is the whole truth), then the WAL is
    /// durably deleted. The files stand alone afterwards, readable by the per-file
    /// backends; reopening the partition through this backend re-adopts them as
    /// ordinary blobs (atomicity is a property of WAL management, not of files;
    /// promote to restore it).
    ///
    /// Nothing may operate on the partition concurrently.
    pub async fn extract(&self, partition: &str) -> Result<(), crate::Error> {
        super::validate_partition_name(partition)?;
        let Some(committer) = self.family(partition, false).await? else {
            return Err(crate::Error::PartitionMissing(partition.to_string()));
        };
        // Exclude new operations; in-flight ones were the caller's to drain.
        self.families.lock().remove(partition);

        let rows: Vec<(Vec<u8>, catalog::Row)> = committer.shared().read(|catalog| {
            catalog
                .scan(partition)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|name| {
                    catalog
                        .get(partition, &name)
                        .cloned()
                        .map(|row| (name, row))
                })
                .collect()
        });
        for (name, row) in rows {
            let Kind::Atomic {
                committed,
                trusted,
                overlay,
            } = row.kind
            else {
                continue;
            };
            let filename = hex(&name);
            let (file, data_offset) = self
                .open_atomic_file(partition, &name, &filename, row.version, trusted)
                .await?;
            if !overlay.is_empty() {
                file.write_at(data_offset + trusted, overlay).await?;
            }
            // Rewound blobs may have dead bytes past the committed length; the
            // per-file backends would surface them, so clamp.
            file.set_len(data_offset + committed).await?;
            file.sync().await?;
        }
        self.medium.sync_dir(partition).await?;

        self.medium
            .remove(WAL_DIR, &Self::wal_name(partition))
            .await?;
        self.medium.sync_dir(WAL_DIR).await?;
        Ok(())
    }

    /// Promotes an ordinary blob to atomic, adopting its current content as the
    /// committed (and trusted) state. The file and its dentry chain are barriered
    /// before the record asserting them is journaled (rule M). Ordinary handles
    /// opened before promotion must not mutate the blob afterwards; doing so is
    /// unspecified, like any conflicting concurrent mutation.
    pub async fn promote(&self, partition: &str, name: &[u8]) -> Result<(), crate::Error> {
        super::validate_partition_name(partition)?;
        let Some(committer) = self.family(partition, false).await? else {
            return Err(crate::Error::PartitionMissing(partition.to_string()));
        };
        let row = committer
            .shared()
            .read(|catalog| catalog.get(partition, name).cloned())
            .ok_or_else(|| crate::Error::BlobMissing(partition.to_string(), hex(name)))?;
        if row.kind != Kind::Ordinary {
            return Ok(()); // already atomic
        }
        let filename = hex(name);
        let (file, data_offset, size) = self
            .open_blob(partition, name, &filename, row.version)
            .await?;
        // The wave: content and dentry chain durable before the record.
        file.sync().await?;
        self.medium.sync_dir(partition).await?;
        self.medium.sync_root().await?;
        debug_assert!(self.medium.covered(&medium::Claim::FileBytes {
            dir: partition,
            name: &filename,
            start: 0,
            end: data_offset + size,
        }));
        let (ack, staged) = committer.transact(|catalog| {
            match catalog.get(partition, name) {
                Some(current) if current.id == row.id && current.kind == Kind::Ordinary => (
                    Stage::Record(Record::Promote {
                        id: row.id,
                        len: size,
                    }),
                    true,
                ),
                // Deleted or promoted concurrently; nothing to do here.
                _ => (Stage::Nothing, false),
            }
        })?;
        if !staged {
            return Ok(());
        }
        ack.expect("promotion staged")
            .await
            .map_err(|_| crate::Error::Closed)?
    }

    /// Opens (creating if needed) the blob's file and resolves its header layout,
    /// returning the file, its data offset, and its logical size.
    ///
    /// A row may exist with a missing or torn-creation file (lazy creation, or a
    /// dentry lost before its first sync): it gets a fresh V1 header region and
    /// reopens empty, exactly as under the per-file backends. Stale predecessor
    /// files cannot reach here: acknowledged removes unlink durably, and the mint
    /// path durably replaces any leftover before its record is staged. The header
    /// write itself needs no barrier: until the blob's first durability event, a
    /// torn region reads as an interrupted creation and heals the same way.
    async fn open_blob(
        &self,
        partition: &str,
        name: &[u8],
        filename: &str,
        version: u16,
    ) -> Result<(M::File, u64, u64), crate::Error> {
        let file = match self.medium.open(partition, filename).await? {
            Some(file) => file,
            None => self.medium.create(partition, filename).await?,
        };
        let raw_len = file.size().await?;
        let raw = file.read_at(0, Header::resolve_len(raw_len)).await?;
        if let Some((size, _, data_offset)) =
            resolve_header(&raw, raw_len, &(version..=version), partition, name)?
        {
            return Ok((file, data_offset, size));
        }
        let (region, _) = Header::create(&(version..=version));
        file.write_at(0, region).await?;
        Ok((file, Layout::V1.data_offset(), 0))
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

        let row = self
            .claim_row(&committer, partition, name, || Kind::Ordinary, &versions)
            .await?;
        if row.kind != Kind::Ordinary {
            return Err(invalid_input(
                partition,
                name,
                "blob is atomic; use open_atomic_versioned",
            ));
        }
        let filename = hex(name);
        let (file, data_offset, size) = self
            .open_blob(partition, name, &filename, row.version)
            .await?;
        let blob = Blob::new(self.medium.clone(), file, partition, name, data_offset);
        Ok((blob, size, row.version))
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
        AtomicBlob as _, AtomicStorage as _, Blob as _, Storage as _,
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

    /// The same conformance suite over real files.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn storage_suite_fs() {
        let root = std::env::temp_dir().join(format!("wal-suite-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let medium = Fs::new(root.clone()).unwrap();
        run_storage_tests(Storage::new(medium, test_spawn(), Config::default())).await;
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Files created by this backend read back through header resolution with the
    /// standard V1 layout, so adoption and extraction round-trip without copies.
    #[tokio::test]
    async fn adoption_round_trips_without_copies() {
        let sim = Sim::new(9);
        let storage = wal_storage(&sim);
        let (blob, _) = storage.open("p", b"a").await.unwrap();
        blob.write_at(0, vec![1u8; 100], crate::WriteOptions::SYNC)
            .await
            .unwrap();
        let (blob, _) = storage.open("p", b"b").await.unwrap();
        blob.write_at(0, vec![2u8; 50], crate::WriteOptions::SYNC)
            .await
            .unwrap();
        drop(storage);

        // Extraction: delete the WAL; the files stand alone, self-describing.
        sim.remove(".wal", "p.cww").await.unwrap();
        sim.sync_dir(".wal").await.unwrap();

        // Adoption: a fresh storage over the same medium re-adopts the files into a
        // new catalog, payload untouched. Even a scan triggers it.
        let storage = wal_storage(&sim);
        let names = storage.scan("p").await.unwrap();
        assert_eq!(names, vec![b"a".to_vec(), b"b".to_vec()]);
        let (blob, size) = storage.open("p", b"a").await.unwrap();
        assert_eq!(size, 100);
        let bytes = blob.read_at(0, 100).await.unwrap().coalesce();
        assert_eq!(bytes.as_ref(), &[1u8; 100][..]);
    }

    /// Extraction materializes overlays and clamps rewound files, so atomic content
    /// survives WAL deletion; re-adoption then reproduces it exactly.
    #[tokio::test]
    async fn extraction_materializes_atomic_state() {
        let sim = Sim::new(11);
        let storage = wal_storage(&sim);
        let (blob, _, _) = storage
            .open_atomic_versioned("p", b"a", 0..=0)
            .await
            .unwrap();
        // Bulk base, rewind (file now longer than committed), inline tail (bytes
        // only in the WAL): extraction must handle all three shapes.
        blob.append(vec![0xAA; 100 << 10]).unwrap();
        blob.publish().await.unwrap();
        blob.rewind(1000).unwrap();
        blob.append(vec![0xBB; 100]).unwrap();
        blob.publish().await.unwrap();
        storage.extract("p").await.unwrap();

        // Re-adopt: the file alone carries the committed state, as an ordinary
        // blob (atomicity is a property of WAL management, not of the file; promote
        // to get it back).
        let storage = wal_storage(&sim);
        let (blob, size) = storage.open("p", b"a").await.unwrap();
        assert_eq!(size, 1100);
        let bytes = blob.read_at(990, 20).await.unwrap().coalesce();
        assert_eq!(&bytes.as_ref()[..10], &[0xAA; 10][..]);
        assert_eq!(&bytes.as_ref()[10..], &[0xBB; 10][..]);
        storage.promote("p", b"a").await.unwrap();
        let (_, committed, _) = storage
            .open_atomic_versioned("p", b"a", 0..=0)
            .await
            .unwrap();
        assert_eq!(committed, 1100);
    }

    /// The plan's centerpiece scenario: rewind below the trusted length, then
    /// append, published atomically in ONE barrier (the inline route writes no file
    /// bytes, so no durability split is needed).
    #[tokio::test]
    async fn rewind_then_append_publishes_atomically() {
        for seed in 0..16 {
            let sim = Sim::new(seed);
            let storage = wal_storage(&sim);
            // Bulk-publish 100 KiB so trusted == committed == 100 KiB (file-backed).
            let (blob, _, _) = storage
                .open_atomic_versioned("p", b"a", 0..=0)
                .await
                .unwrap();
            blob.append(vec![0xAA; 100 << 10]).unwrap();
            blob.publish().await.unwrap();

            // Rewind below trusted, then a small append: one inline publication.
            blob.rewind(50).unwrap();
            blob.append(vec![0xBB; 10]).unwrap();
            assert_eq!(blob.size(), 60);
            blob.publish().await.unwrap();

            sim.crash();
            let storage = wal_storage(&sim);
            let (blob, committed, _) = storage
                .open_atomic_versioned("p", b"a", 0..=0)
                .await
                .unwrap();
            assert_eq!(committed, 60, "seed {seed}");
            let bytes = blob.read_at(0, 60).await.unwrap().coalesce();
            assert_eq!(&bytes.as_ref()[..50], &[0xAA; 50][..], "seed {seed}");
            assert_eq!(&bytes.as_ref()[50..], &[0xBB; 10][..], "seed {seed}");
        }
    }

    /// Unpublished operations are invisible to recovery; published ones are
    /// reproduced whole. The epoch is the atomicity unit.
    #[tokio::test]
    async fn unpublished_epochs_vanish_published_epochs_survive() {
        for seed in 0..16 {
            let sim = Sim::new(seed);
            let storage = wal_storage(&sim);
            let (blob, _, _) = storage
                .open_atomic_versioned("p", b"a", 0..=0)
                .await
                .unwrap();
            blob.append(vec![1u8; 100]).unwrap();
            blob.publish().await.unwrap();
            blob.append(vec![2u8; 100]).unwrap(); // never published

            sim.crash();
            let storage = wal_storage(&sim);
            let (_, committed, _) = storage
                .open_atomic_versioned("p", b"a", 0..=0)
                .await
                .unwrap();
            assert_eq!(committed, 100, "seed {seed}");
        }
    }

    /// Two blobs' epochs published through publish_all recover together or not at
    /// all, even when one is inline and the other bulk.
    #[tokio::test]
    async fn multi_blob_publication_is_all_or_nothing() {
        for seed in 0..24 {
            let sim = Sim::new(seed);
            let storage = wal_storage(&sim);
            let (value, _, _) = storage
                .open_atomic_versioned("p", b"value", 0..=0)
                .await
                .unwrap();
            let (index, _, _) = storage
                .open_atomic_versioned("p", b"index", 0..=0)
                .await
                .unwrap();

            // A durable base pair.
            value.append(vec![0x11; 100 << 10]).unwrap(); // bulk
            index.append(vec![0x22; 16]).unwrap(); // inline
            storage.publish_all("p", &[&value, &index]).await.unwrap();

            // A second pair, racing a crash: publish concurrently with nothing
            // guaranteed, then crash. Whatever survives must be paired.
            value.append(vec![0x33; 80 << 10]).unwrap();
            index.append(vec![0x44; 16]).unwrap();
            // Let the publication run to completion or not; either way the crash
            // decides what became durable.
            let pair = [&value, &index];
            let _ = storage.publish_all("p", &pair).await;
            sim.crash();

            let storage = wal_storage(&sim);
            let (_, value_len, _) = storage
                .open_atomic_versioned("p", b"value", 0..=0)
                .await
                .unwrap();
            let (_, index_len, _) = storage
                .open_atomic_versioned("p", b"index", 0..=0)
                .await
                .unwrap();
            let first = value_len == (100 << 10) && index_len == 16;
            let both = value_len == (180 << 10) && index_len == 32;
            assert!(
                first || both,
                "seed {seed}: value {value_len} index {index_len}"
            );
        }
    }

    /// A bulk epoch rewinding below the trusted length publishes alone (with its
    /// durability split) and is rejected from multi-blob batches.
    #[tokio::test]
    async fn bulk_rewind_below_trusted_splits_and_rejects_batching() {
        let sim = Sim::new(7);
        let storage = wal_storage(&sim);
        let (blob, _, _) = storage
            .open_atomic_versioned("p", b"a", 0..=0)
            .await
            .unwrap();
        blob.append(vec![0xAA; 100 << 10]).unwrap();
        blob.publish().await.unwrap();

        // Rewind below trusted plus a bulk append: batching is refused...
        blob.rewind(10).unwrap();
        blob.append(vec![0xBB; 90 << 10]).unwrap();
        assert!(storage.publish_all("p", &[&blob]).await.is_err());
        // ...but single-blob publication handles it (rewind barrier, then bulk).
        blob.publish().await.unwrap();

        sim.crash();
        let storage = wal_storage(&sim);
        let (blob, committed, _) = storage
            .open_atomic_versioned("p", b"a", 0..=0)
            .await
            .unwrap();
        assert_eq!(committed, 10 + (90 << 10));
        let bytes = blob.read_at(0, 20).await.unwrap().coalesce();
        assert_eq!(&bytes.as_ref()[..10], &[0xAA; 10][..]);
        assert_eq!(&bytes.as_ref()[10..], &[0xBB; 10][..]);
    }

    /// Inline (WAL-resident) bytes survive checkpoints: the snapshot rows carry
    /// overlays forward, and recovery still reads no payload from blob files.
    #[tokio::test]
    async fn checkpoints_carry_overlays() {
        let sim = Sim::new(8);
        let storage = wal_storage(&sim);
        let (blob, _, _) = storage
            .open_atomic_versioned("p", b"a", 0..=0)
            .await
            .unwrap();
        blob.append(vec![0x77; 1000]).unwrap();
        blob.publish().await.unwrap(); // inline: bytes live only in the WAL

        // Force checkpoints with namespace churn.
        for i in 0..128u32 {
            let name = format!("{i:04}-{}", "x".repeat(1000));
            storage.open("p", name.as_bytes()).await.unwrap();
        }

        sim.crash();
        let storage = wal_storage(&sim);
        let (blob, committed, _) = storage
            .open_atomic_versioned("p", b"a", 0..=0)
            .await
            .unwrap();
        assert_eq!(committed, 1000);
        let bytes = blob.read_at(0, 1000).await.unwrap().coalesce();
        assert_eq!(bytes.as_ref(), &[0x77; 1000][..]);
    }

    /// Promotion adopts an ordinary blob's synced content as the atomic committed
    /// state; cross-kind opens fail in both directions.
    #[tokio::test]
    async fn promotion_and_cross_kind_opens() {
        let sim = Sim::new(9);
        let storage = wal_storage(&sim);
        let (blob, _) = storage.open("p", b"a").await.unwrap();
        blob.write_at(0, vec![0x55; 300], crate::WriteOptions::SYNC)
            .await
            .unwrap();
        // An ordinary blob cannot be opened atomically...
        assert!(
            storage
                .open_atomic_versioned("p", b"a", 0..=0)
                .await
                .is_err()
        );
        storage.promote("p", b"a").await.unwrap();
        // ...and a promoted blob cannot be opened ordinarily.
        assert!(storage.open("p", b"a").await.is_err());

        sim.crash();
        let storage = wal_storage(&sim);
        let (blob, committed, _) = storage
            .open_atomic_versioned("p", b"a", 0..=0)
            .await
            .unwrap();
        assert_eq!(committed, 300);
        blob.append(vec![0x66; 10]).unwrap();
        blob.publish().await.unwrap();
        let bytes = blob.read_at(295, 15).await.unwrap().coalesce();
        assert_eq!(&bytes.as_ref()[..5], &[0x55; 5][..]);
        assert_eq!(&bytes.as_ref()[5..], &[0x66; 10][..]);
    }

    /// The whole stack over the rule-M checker: every CommitAtomic and Promote
    /// claim is verified against what barriers actually covered.
    #[tokio::test]
    async fn atomic_paths_pass_the_rule_m_checker() {
        let medium = medium::Checked::new(Sim::new(10));
        let storage = Storage::new(medium, test_spawn(), Config::default());
        let (blob, _, _) = storage
            .open_atomic_versioned("p", b"a", 0..=0)
            .await
            .unwrap();
        blob.append(vec![0xAB; 100 << 10]).unwrap(); // bulk: wave then record
        blob.publish().await.unwrap();
        blob.append(vec![0xCD; 100]).unwrap(); // inline
        blob.publish().await.unwrap();
        blob.append(vec![0xEF; 100 << 10]).unwrap(); // bulk over an overlay
        blob.publish().await.unwrap();

        let (ordinary, _) = storage.open("p", b"b").await.unwrap();
        ordinary
            .write_at(0, vec![1u8; 64], crate::WriteOptions::SYNC)
            .await
            .unwrap();
        storage.promote("p", b"b").await.unwrap();
    }

    #[tokio::test]
    async fn foreign_file_fails_adoption_loudly() {
        let sim = Sim::new(10);
        // A partition directory with a file this backend could not have produced.
        sim.create("p", "not-hex!").await.unwrap();
        sim.sync_dir("p").await.unwrap();
        sim.sync_root().await.unwrap();
        let storage = wal_storage(&sim);
        assert!(matches!(
            storage.scan("p").await,
            Err(crate::Error::PartitionCorrupt(_))
        ));
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
