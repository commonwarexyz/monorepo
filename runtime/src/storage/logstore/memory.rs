//! In-memory implementation of [`crate::LogStorage`].
//!
//! The reference backend: it implements the full transactional contract --
//! private staging, one writer per family with fair cancellable waiting,
//! closed-on-remove, the draft lifecycle, poisoning and recovery -- with no
//! durability. State lives on the heap and dies with the [`LogStorage`] value.
//!
//! Nothing here can genuinely fail to persist, so tests exercise the
//! poisoning protocol through the `fail_next_commit` fault fuse in [`State`].

pub use super::family::Draft;
use super::{
    Bounds,
    family::{Control, Host, Liveness, Permit, Staged, Staging, fill},
};
use crate::{BufferPool, Handle, IoBufs, IoBufsMut};
use commonware_utils::sync::Mutex;
use std::{collections::BTreeMap, sync::Arc};

/// In-memory log storage.
#[derive(Clone)]
pub struct LogStorage {
    families: Arc<Mutex<BTreeMap<String, Arc<Shared>>>>,
    pool: BufferPool,
    bounds: Bounds,
}

impl LogStorage {
    /// Create an empty log storage enforcing `bounds` on every transaction.
    pub fn new(pool: BufferPool, bounds: Bounds) -> Self {
        Self {
            families: Arc::new(Mutex::new(BTreeMap::new())),
            pool,
            bounds,
        }
    }
}

impl crate::LogStorage for LogStorage {
    type Family = Family;

    async fn open_family(&self, name: &str) -> Result<Family, crate::Error> {
        crate::storage::validate_name(name)?;
        let mut families = self.families.lock();
        let shared = families
            .entry(name.into())
            .or_insert_with(|| Arc::new(Shared::new(name)))
            .clone();
        let mut state = shared.state.lock();
        if matches!(state.control.liveness, Liveness::Poisoned) {
            // Recovery: committed state is never torn in memory, so recovery
            // just mints a fresh session; handles from before it are dead.
            state.control.liveness = Liveness::Open;
            state.control.session += 1;
        }
        let session = state.control.session;
        drop(state);
        Ok(Family {
            shared,
            session,
            pool: self.pool.clone(),
            bounds: self.bounds,
        })
    }

    async fn scan_families(&self) -> Result<Vec<String>, crate::Error> {
        Ok(self.families.lock().keys().cloned().collect())
    }

    async fn destroy_family(&self, name: &str) -> Result<(), crate::Error> {
        crate::storage::validate_name(name)?;
        // Hold the registry lock until the family is flagged, so no operation
        // lands between the name vanishing and the incarnation dying.
        let mut families = self.families.lock();
        let Some(shared) = families.remove(name) else {
            return Ok(());
        };
        let mut state = shared.state.lock();
        state.control.liveness = Liveness::Destroyed;
        // Handles and the live transaction discover destruction through the
        // liveness.
        state.control.writer.close_waiters();
        state.names.clear();
        state.logs.clear();
        Ok(())
    }
}

/// State shared by every handle into one family incarnation.
///
/// A `Shared` value *is* one incarnation: destroy-then-recreate mints a new
/// `Shared`, so handles into the old incarnation can never observe the new
/// one.
struct Shared {
    name: String,
    state: Mutex<State>,
}

impl Shared {
    fn new(name: &str) -> Self {
        Self {
            name: name.into(),
            state: Mutex::new(State::default()),
        }
    }
}

impl Host for Shared {
    fn name(&self) -> &str {
        &self.name
    }

    fn with_control<R>(&self, f: impl FnOnce(&mut Control<Self>) -> R) -> R {
        f(&mut self.state.lock().control)
    }
}

/// Mutable state of one family incarnation.
#[derive(Default)]
struct State {
    /// Handle validity, liveness, the fault fuse, and the writer queue.
    control: Control<Shared>,
    /// Next log id to mint at commit. Ids are never reused within an
    /// incarnation, so a recreated name is a new identity and handles to the
    /// removed log stay closed.
    next_log: u64,
    /// Committed log name -> id.
    names: BTreeMap<Vec<u8>, u64>,
    /// Committed log id -> log.
    logs: BTreeMap<u64, CommittedLog>,
}

/// A committed log.
struct CommittedLog {
    name: Vec<u8>,
    content: Vec<u8>,
}

/// Handle to a family.
#[derive(Clone)]
pub struct Family {
    shared: Arc<Shared>,
    /// The session this handle was minted in; recovery invalidates it.
    session: u64,
    pool: BufferPool,
    bounds: Bounds,
}

impl Family {
    /// Validate this handle against the current family state.
    fn ensure_open(&self) -> Result<(), crate::Error> {
        self.shared
            .state
            .lock()
            .control
            .ensure_open(&self.shared.name, self.session)
    }
}

impl crate::LogFamily for Family {
    type Log = Log;
    type Transaction = Transaction;

    async fn open(&self, name: &[u8]) -> Result<Option<Log>, crate::Error> {
        let state = self.shared.state.lock();
        state.control.ensure_open(&self.shared.name, self.session)?;
        Ok(state.names.get(name).map(|&id| Log {
            shared: self.shared.clone(),
            session: self.session,
            id,
            pool: self.pool.clone(),
        }))
    }

    async fn scan(&self) -> Result<Vec<Vec<u8>>, crate::Error> {
        let state = self.shared.state.lock();
        state.control.ensure_open(&self.shared.name, self.session)?;
        Ok(state.names.keys().cloned().collect())
    }

    async fn transaction(&self) -> Result<Transaction, crate::Error> {
        let permit = Permit::acquire(&self.shared, self.session).await?;
        Ok(Transaction {
            family: self.clone(),
            permit,
            staging: Staging::new(self.bounds),
        })
    }
}

/// Read handle to a committed log.
#[derive(Clone)]
pub struct Log {
    shared: Arc<Shared>,
    /// The session this handle was minted in; recovery invalidates it.
    session: u64,
    id: u64,
    pool: BufferPool,
}

impl crate::Log for Log {
    fn len(&self) -> Result<u64, crate::Error> {
        let state = self.shared.state.lock();
        state.control.ensure_open(&self.shared.name, self.session)?;
        let log = state.logs.get(&self.id).ok_or(crate::Error::Closed)?;
        Ok(log.content.len() as u64)
    }

    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, crate::Error> {
        self.read_at_buf(offset, len, self.pool.alloc(len)).await
    }

    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, crate::Error> {
        let data = {
            let state = self.shared.state.lock();
            state.control.ensure_open(&self.shared.name, self.session)?;
            let log = state.logs.get(&self.id).ok_or(crate::Error::Closed)?;
            read_view(&log.content, log.content.len() as u64, &[], offset, len)?
        };
        Ok(fill(bufs, &data))
    }
}

/// The family's single write transaction.
pub struct Transaction {
    family: Family,
    /// Held for the transaction's lifetime; dropping it (abort or commit)
    /// hands the writer to the next waiter.
    #[allow(dead_code)]
    permit: Permit<Shared>,
    /// Staged mutations and drafts, with bounds accounting.
    staging: Staging<u64>,
}

impl Transaction {
    /// Validate `log` as a target of this transaction under `state` and
    /// return its committed form.
    fn committed<'a>(&self, state: &'a State, log: &Log) -> Result<&'a CommittedLog, crate::Error> {
        // Family identity first: ids and sessions are per-incarnation, so a
        // foreign log's id could collide with a local one.
        if !Arc::ptr_eq(&log.shared, &self.family.shared) {
            return Err(crate::Error::InvalidTransaction(
                "log from another family".into(),
            ));
        }
        state
            .control
            .ensure_open(&self.family.shared.name, self.family.session)?;
        if log.session != self.family.session {
            return Err(crate::Error::Closed);
        }
        let committed = state.logs.get(&log.id).ok_or(crate::Error::Closed)?;
        self.staging.ensure_unremoved(log.id)?;
        Ok(committed)
    }

    /// [`Transaction::committed`], returning just the committed length.
    fn committed_len(&self, log: &Log) -> Result<u64, crate::Error> {
        let state = self.family.shared.state.lock();
        Ok(self.committed(&state, log)?.content.len() as u64)
    }
}

impl crate::LogTransaction for Transaction {
    type Log = Log;
    type Draft = Draft;

    fn create(&mut self, name: &[u8]) -> Result<Draft, crate::Error> {
        let taken = {
            let state = self.family.shared.state.lock();
            state
                .control
                .ensure_open(&self.family.shared.name, self.family.session)?;
            state.names.contains_key(name)
        };
        self.staging.create(name, taken)
    }

    fn append(&mut self, log: &Log, data: impl Into<IoBufs>) -> Result<u64, crate::Error> {
        let committed = self.committed_len(log)?;
        self.staging.append(log.id, committed, data.into())
    }

    fn rewind(&mut self, log: &Log, len: u64) -> Result<(), crate::Error> {
        let committed = self.committed_len(log)?;
        self.staging.rewind(log.id, committed, len)
    }

    fn remove(&mut self, log: &Log) -> Result<(), crate::Error> {
        self.committed_len(log)?;
        self.staging.remove(log.id)
    }

    fn len(&self, log: &Log) -> u64 {
        let committed = self.committed_len(log).expect("invalid log target");
        self.staging.len(log.id, committed)
    }

    async fn read_at(&self, log: &Log, offset: u64, len: usize) -> Result<IoBufsMut, crate::Error> {
        self.read_at_buf(log, offset, len, self.family.pool.alloc(len))
            .await
    }

    async fn read_at_buf(
        &self,
        log: &Log,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, crate::Error> {
        let data = {
            let state = self.family.shared.state.lock();
            let committed = self.committed(&state, log)?;
            let (keep, appended) = self.staging.view(log.id, committed.content.len() as u64);
            read_view(&committed.content, keep, appended, offset, len)?
        };
        Ok(fill(bufs, &data))
    }

    fn append_draft(&mut self, log: &Draft, data: impl Into<IoBufs>) -> Result<u64, crate::Error> {
        self.family.ensure_open()?;
        self.staging.append_draft(log, data.into())
    }

    fn rewind_draft(&mut self, log: &Draft, len: u64) -> Result<(), crate::Error> {
        self.family.ensure_open()?;
        self.staging.rewind_draft(log, len)
    }

    fn len_draft(&self, log: &Draft) -> u64 {
        self.staging.len_draft(log)
    }

    async fn read_draft_at(
        &self,
        log: &Draft,
        offset: u64,
        len: usize,
    ) -> Result<IoBufsMut, crate::Error> {
        self.read_draft_at_buf(log, offset, len, self.family.pool.alloc(len))
            .await
    }

    async fn read_draft_at_buf(
        &self,
        log: &Draft,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, crate::Error> {
        self.family.ensure_open()?;
        let data = self.staging.read_draft(log, offset, len)?;
        Ok(fill(bufs, data))
    }

    fn discard(&mut self, log: Draft) -> Result<(), crate::Error> {
        self.family.ensure_open()?;
        self.staging.discard(log)
    }

    async fn start_commit(mut self) -> Result<Handle<()>, crate::Error> {
        let (staged, drafts) = self.staging.take();
        {
            let mut state = self.family.shared.state.lock();
            state
                .control
                .ensure_open(&self.family.shared.name, self.family.session)?;

            // Fault fuse: fail after admission, poisoning the family. The
            // transaction is lost, modeling a frame that never became
            // durable.
            if state.control.fail_next_commit {
                state.control.fail_next_commit = false;
                state.control.liveness = Liveness::Poisoned;
                drop(state);
                let name = self.family.shared.name.clone();
                drop(self);
                return Ok(Handle::ready(Err(crate::Error::FamilyPoisoned(name))));
            }

            // Apply the net staged state. Targets were validated at staging
            // time and this transaction holds the writer, so they are still
            // current.
            for (id, staged) in staged {
                match staged {
                    Staged::Edit { keep, appended } => {
                        let log = state.logs.get_mut(&id).expect("validated at staging");
                        log.content.truncate(keep as usize);
                        log.content.extend_from_slice(&appended);
                    }
                    Staged::Removal => {
                        let log = state.logs.remove(&id).expect("validated at staging");
                        state.names.remove(&log.name);
                    }
                }
            }
            for draft in drafts.into_iter().flatten() {
                let id = state.next_log;
                state.next_log += 1;
                state.names.insert(draft.name.clone(), id);
                state.logs.insert(
                    id,
                    CommittedLog {
                        name: draft.name,
                        content: draft.content,
                    },
                );
            }
        }
        // Dropping the transaction releases the writer, so the handle
        // resolves only after the next waiter can proceed.
        drop(self);
        Ok(Handle::ready(Ok(())))
    }
}

/// Copy `[offset, offset + len)` out of a staged view: `committed` truncated
/// to `keep` bytes, then `appended`.
///
/// `keep <= committed.len()` always; committed reads pass the full length and
/// no appended bytes.
fn read_view(
    committed: &[u8],
    keep: u64,
    appended: &[u8],
    offset: u64,
    len: usize,
) -> Result<Vec<u8>, crate::Error> {
    let end = offset
        .checked_add(len as u64)
        .ok_or(crate::Error::OffsetOverflow)?;
    if end > keep + appended.len() as u64 {
        return Err(crate::Error::LogInsufficientLength);
    }
    let mut data = Vec::with_capacity(len);
    if offset < keep {
        let take = (keep - offset).min(len as u64) as usize;
        data.extend_from_slice(&committed[offset as usize..offset as usize + take]);
    }
    if end > keep {
        let from = offset.max(keep) - keep;
        data.extend_from_slice(&appended[from as usize..(end - keep) as usize]);
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BufferPoolConfig, Error, Log as _, LogFamily as _, LogStorage as _, LogTransaction as _,
        storage::logstore::tests::run_log_storage_tests, telemetry::metrics::Registry,
    };

    fn test_pool() -> BufferPool {
        let mut registry = Registry::default();
        BufferPool::new(BufferPoolConfig::for_storage(), &mut registry)
    }

    /// Small bounds so conformance tests can hit every limit cheaply.
    fn test_bounds() -> Bounds {
        Bounds {
            max_transaction_bytes: 1024,
            max_transaction_logs: 8,
            max_log_name_len: 64,
        }
    }

    /// Arm the fault fuse: the next admitted commit in `family` fails,
    /// poisoning it.
    fn fail_next_commit(storage: &LogStorage, family: &str) {
        storage.families.lock()[family]
            .state
            .lock()
            .control
            .fail_next_commit = true;
    }

    #[tokio::test]
    async fn test_memory_log_storage() {
        let storage = LogStorage::new(test_pool(), test_bounds());
        let fuse = storage.clone();
        run_log_storage_tests(storage, test_bounds(), move |family| {
            fail_next_commit(&fuse, family)
        })
        .await;
    }

    /// The memory fuse models a frame that never became durable: the failed
    /// transaction is lost, and recovery serves the state before it.
    #[tokio::test]
    async fn test_failed_commit_is_lost() {
        let storage = LogStorage::new(test_pool(), test_bounds());
        let family = storage.open_family("fam").await.unwrap();
        let mut txn = family.transaction().await.unwrap();
        let draft = txn.create(b"a").unwrap();
        txn.append_draft(&draft, b"hello").unwrap();
        txn.commit().await.unwrap();
        let log = family.open(b"a").await.unwrap().unwrap();

        fail_next_commit(&storage, "fam");
        let mut txn = family.transaction().await.unwrap();
        txn.append(&log, b" world").unwrap();
        let handle = txn.start_commit().await.unwrap();
        assert!(matches!(handle.await, Err(Error::FamilyPoisoned(_))));

        let recovered = storage.open_family("fam").await.unwrap();
        let log = recovered.open(b"a").await.unwrap().unwrap();
        assert_eq!(log.len().unwrap(), 5);
    }
}
