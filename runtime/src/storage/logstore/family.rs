//! The per-family machinery shared by every [`crate::LogStorage`] backend:
//! the control state (session, liveness, fault fuse), the single-writer
//! permit with its fair wait queue, and the staging layer a transaction folds
//! its mutations into.
//!
//! Backends keep what genuinely differs -- committed state, how it is read,
//! and how a commit becomes durable -- and plug in here through [Host]:
//! locked access to the [Control] embedded in their per-family state.
//! Staging is committed-state-agnostic: the backend validates each target and
//! hands in its id and committed length.

use super::Bounds;
use crate::{Error, IoBufs, IoBufsMut};
use commonware_utils::channel::oneshot;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

/// Source of process-unique transaction identities, binding every [`Draft`] to
/// the transaction that created it.
static NEXT_TRANSACTION: AtomicU64 = AtomicU64::new(0);

/// A backend's shared per-family state, hosting the [Control] under the same
/// lock as the backend's committed state.
pub(super) trait Host: Sized + Send + Sync + 'static {
    /// The family name, for error reporting.
    fn name(&self) -> &str;

    /// Runs `f` under the family's state lock, over its control state.
    fn with_control<R>(&self, f: impl FnOnce(&mut Control<Self>) -> R) -> R;
}

/// Lifecycle of a family incarnation. Transitions: `Open -> Poisoned` after a
/// failed admitted commit, uncertain mutable I/O, or corruption discovered on
/// read; `Poisoned -> Open` on recovery (with a session bump); anything
/// `-> Destroyed` permanently.
#[derive(Clone, Copy, Default)]
pub(super) enum Liveness {
    #[default]
    Open,
    Poisoned,
    Destroyed,
}

/// The control state of one family incarnation: handle validity, liveness,
/// the fault fuse, and the writer queue.
pub(super) struct Control<H: Host> {
    /// Process-local handle validity: bumped by recovery after poisoning, so
    /// handles minted before recovery fail with Closed. A plain reopen keeps
    /// the session, so handles stay interchangeable across `open_family`
    /// calls.
    pub(super) session: u64,
    pub(super) liveness: Liveness,
    /// Fault fuse: fail the next admitted commit, poisoning the family.
    pub(super) fail_next_commit: bool,
    /// Fault fuse: poison the family at the start of its next maintenance
    /// pass, modeling a concurrent read poisoning it in the window between a
    /// commit's install and its maintenance.
    pub(super) poison_next_maintenance: bool,
    /// The writer permit and its fair wait queue.
    pub(super) writer: Writer<H>,
}

impl<H: Host> Default for Control<H> {
    fn default() -> Self {
        Self {
            session: 0,
            liveness: Liveness::Open,
            fail_next_commit: false,
            poison_next_maintenance: false,
            writer: Writer::default(),
        }
    }
}

impl<H: Host> Control<H> {
    /// Validate that a handle minted in `session` may use the family.
    pub(super) fn ensure_open(&self, name: &str, session: u64) -> Result<(), Error> {
        match self.liveness {
            Liveness::Destroyed => Err(Error::Closed),
            _ if self.session != session => Err(Error::Closed),
            Liveness::Poisoned => Err(Error::FamilyPoisoned(name.into())),
            Liveness::Open => Ok(()),
        }
    }
}

/// One writer per family: `held` is the permit, `waiters` the fair queue.
pub(super) struct Writer<H: Host> {
    held: bool,
    waiters: VecDeque<oneshot::Sender<Permit<H>>>,
}

impl<H: Host> Default for Writer<H> {
    fn default() -> Self {
        Self {
            held: false,
            waiters: VecDeque::new(),
        }
    }
}

impl<H: Host> Writer<H> {
    /// Take the writer if free (`None`), or join the fair queue (a receiver
    /// resolving to the permit). Callers hold the family's state lock.
    fn acquire(&mut self) -> Option<oneshot::Receiver<Permit<H>>> {
        if self.held {
            let (sender, receiver) = oneshot::channel();
            self.waiters.push_back(sender);
            Some(receiver)
        } else {
            self.held = true;
            None
        }
    }

    /// Drop every waiter's sender, waking it with Closed. Destruction only:
    /// a held permit discovers destruction through the liveness.
    pub(super) fn close_waiters(&mut self) {
        self.waiters.clear();
    }
}

/// The family's writer permit.
///
/// Dropping a permit hands the writer to the next live waiter (or marks it
/// free), so cancellation anywhere -- a waiting future dropped before or
/// after handoff, a transaction aborted -- can never strand the writer.
pub(super) struct Permit<H: Host> {
    host: Arc<H>,
    /// Cleared when a dead waiter's channel hands the permit back, so
    /// dropping it there does not release twice.
    armed: bool,
}

impl<H: Host> Permit<H> {
    const fn new(host: Arc<H>) -> Self {
        Self { host, armed: true }
    }

    /// Acquire the family's writer through the fair queue, validating the
    /// handle's `session` before joining and again after any wait (the family
    /// may have been poisoned or destroyed while waiting; the permit then
    /// drops here and passes the writer on).
    pub(super) async fn acquire(host: &Arc<H>, session: u64) -> Result<Self, Error> {
        let waiter = host.with_control(|control| {
            control.ensure_open(host.name(), session)?;
            Ok::<_, Error>(control.writer.acquire())
        })?;
        let permit = match waiter {
            None => Self::new(host.clone()),
            // A dropped sender means the family was destroyed while waiting.
            Some(receiver) => receiver.await.map_err(|_| Error::Closed)?,
        };
        host.with_control(|control| control.ensure_open(host.name(), session))?;
        Ok(permit)
    }

    /// [Permit::acquire] without the liveness checks: recovery takes a
    /// poisoned family's writer through the same fair queue, waiting for a
    /// live poisoned transaction to drop exactly as `transaction()` would.
    pub(super) async fn acquire_for_recovery(host: &Arc<H>) -> Result<Self, Error> {
        match host.with_control(|control| control.writer.acquire()) {
            None => Ok(Self::new(host.clone())),
            // A dropped sender means the family was destroyed while waiting.
            Some(receiver) => receiver.await.map_err(|_| Error::Closed),
        }
    }

    /// Hand the writer to the next live waiter, or mark it free.
    fn release(host: &Arc<H>) {
        host.with_control(|control| {
            loop {
                let Some(waiter) = control.writer.waiters.pop_front() else {
                    control.writer.held = false;
                    return;
                };
                match waiter.send(Self::new(host.clone())) {
                    Ok(()) => return,
                    // The waiter was cancelled; pass to the next one.
                    Err(mut permit) => permit.armed = false,
                }
            }
        })
    }
}

impl<H: Host> Drop for Permit<H> {
    fn drop(&mut self) {
        if self.armed {
            Self::release(&self.host);
        }
    }
}

/// The staging state of one transaction: net edits to committed logs, draft
/// logs, and bounds accounting, keyed by the backend's log id type.
pub(super) struct Staging<Id> {
    /// Binds [`Draft`]s to this transaction.
    id: u64,
    /// Staged mutations to committed logs, by log id.
    staged: BTreeMap<Id, Staged>,
    /// Logs staged for creation; a [`Draft`] indexes here. `None` once
    /// discarded.
    drafts: Vec<Option<DraftLog>>,
    /// Size bounds staging enforces.
    bounds: Bounds,
}

/// Staged mutations to one committed log: the net edit folded from every
/// append and rewind, or removal. A transaction may edit a log or remove it,
/// never both.
pub(super) enum Staged {
    /// Committed bytes beyond `keep` are discarded, then `appended` follows.
    Edit { keep: u64, appended: Vec<u8> },
    /// The log is removed at commit.
    Removal,
}

/// The staged state of a log this transaction creates.
pub(super) struct DraftLog {
    pub(super) name: Vec<u8>,
    pub(super) content: Vec<u8>,
}

/// Token identifying a log staged for creation by a transaction. See
/// [`crate::LogTransaction::Draft`].
pub struct Draft {
    /// The transaction that created this draft.
    transaction: u64,
    /// Index into that transaction's draft table.
    index: usize,
}

impl<Id: Copy + Ord> Staging<Id> {
    /// An empty staging state enforcing `bounds`, with a fresh transaction
    /// identity for its drafts.
    pub(super) fn new(bounds: Bounds) -> Self {
        Self {
            id: NEXT_TRANSACTION.fetch_add(1, Ordering::Relaxed),
            staged: BTreeMap::new(),
            drafts: Vec::new(),
            bounds,
        }
    }

    /// Reject a committed-log target this transaction stages for removal.
    pub(super) fn ensure_unremoved(&self, id: Id) -> Result<(), Error> {
        if matches!(self.staged.get(&id), Some(Staged::Removal)) {
            return Err(Error::InvalidTransaction(
                "log removed by this transaction".into(),
            ));
        }
        Ok(())
    }

    /// Stage the creation of a log named `name`. `taken` is the backend's
    /// committed-name check: whether a committed log already holds the name
    /// (a name this transaction removes is still taken -- removal activates
    /// only at commit).
    pub(super) fn create(&mut self, name: &[u8], taken: bool) -> Result<Draft, Error> {
        if name.len() > self.bounds.max_log_name_len {
            return Err(Error::InvalidTransaction(format!(
                "log name longer than {} bytes",
                self.bounds.max_log_name_len
            )));
        }
        if taken {
            return Err(Error::InvalidTransaction("log name already exists".into()));
        }
        if self.drafts.iter().flatten().any(|draft| draft.name == name) {
            return Err(Error::InvalidTransaction("log name already staged".into()));
        }
        self.ensure_bounds(0, 1)?;
        let index = self.drafts.len();
        self.drafts.push(Some(DraftLog {
            name: name.into(),
            content: Vec::new(),
        }));
        Ok(Draft {
            transaction: self.id,
            index,
        })
    }

    /// Stage an append of `data` to the committed log `id`, whose committed
    /// length is `committed`. Returns the log offset the data lands at.
    pub(super) fn append(&mut self, id: Id, committed: u64, data: IoBufs) -> Result<u64, Error> {
        let data = data.coalesce();
        let new_target = usize::from(!self.staged.contains_key(&id));
        self.ensure_bounds(data.len(), new_target)?;
        let (keep, appended) = self.edit(id, committed);
        let offset = *keep + appended.len() as u64;
        appended.extend_from_slice(data.as_ref());
        Ok(offset)
    }

    /// Stage a rewind of the committed log `id` to `len` bytes.
    pub(super) fn rewind(&mut self, id: Id, committed: u64, len: u64) -> Result<(), Error> {
        let length = self.len(id, committed);
        if len > length {
            return Err(Error::RewindBeyondLength {
                length,
                requested: len,
            });
        }
        let new_target = usize::from(!self.staged.contains_key(&id));
        self.ensure_bounds(0, new_target)?;
        let (keep, appended) = self.edit(id, committed);
        if len >= *keep {
            appended.truncate((len - *keep) as usize);
        } else {
            *keep = len;
            appended.clear();
        }
        Ok(())
    }

    /// Stage the removal of the committed log `id`.
    pub(super) fn remove(&mut self, id: Id) -> Result<(), Error> {
        if self.staged.contains_key(&id) {
            return Err(Error::InvalidTransaction(
                "removed log also appended or rewound".into(),
            ));
        }
        self.ensure_bounds(0, 1)?;
        self.staged.insert(id, Staged::Removal);
        Ok(())
    }

    /// The staged length of the committed log `id`, whose committed length is
    /// `committed`.
    pub(super) fn len(&self, id: Id, committed: u64) -> u64 {
        let (keep, appended) = self.view(id, committed);
        keep + appended.len() as u64
    }

    /// The staged view of the committed log `id`: committed bytes below the
    /// returned `keep` length, then the returned appended bytes. An untouched
    /// target views its full committed length.
    pub(super) fn view(&self, id: Id, committed: u64) -> (u64, &[u8]) {
        match self.staged.get(&id) {
            Some(Staged::Edit { keep, appended }) => (*keep, appended),
            Some(Staged::Removal) => unreachable!("targets validate as unremoved"),
            None => (committed, &[]),
        }
    }

    /// Stage an append of `data` to `draft`. Returns the log offset the data
    /// lands at.
    pub(super) fn append_draft(&mut self, draft: &Draft, data: IoBufs) -> Result<u64, Error> {
        let index = self.draft_index(draft)?;
        let data = data.coalesce();
        self.ensure_bounds(data.len(), 0)?;
        let draft = self.drafts[index].as_mut().expect("validated");
        let offset = draft.content.len() as u64;
        draft.content.extend_from_slice(data.as_ref());
        Ok(offset)
    }

    /// Stage a rewind of `draft` to `len` bytes.
    pub(super) fn rewind_draft(&mut self, draft: &Draft, len: u64) -> Result<(), Error> {
        let index = self.draft_index(draft)?;
        let draft = self.drafts[index].as_mut().expect("validated");
        let length = draft.content.len() as u64;
        if len > length {
            return Err(Error::RewindBeyondLength {
                length,
                requested: len,
            });
        }
        draft.content.truncate(len as usize);
        Ok(())
    }

    /// The staged length of `draft`. Panics on a foreign draft (see
    /// [`crate::LogTransaction::len_draft`]).
    pub(super) fn len_draft(&self, draft: &Draft) -> u64 {
        let index = self.draft_index(draft).expect("invalid draft target");
        self.drafts[index]
            .as_ref()
            .expect("validated")
            .content
            .len() as u64
    }

    /// The staged bytes `[offset, offset + len)` of `draft`.
    pub(super) fn read_draft(
        &self,
        draft: &Draft,
        offset: u64,
        len: usize,
    ) -> Result<&[u8], Error> {
        let index = self.draft_index(draft)?;
        let content = &self.drafts[index].as_ref().expect("validated").content;
        let end = offset
            .checked_add(len as u64)
            .ok_or(Error::OffsetOverflow)?;
        if end > content.len() as u64 {
            return Err(Error::LogInsufficientLength);
        }
        Ok(&content[offset as usize..end as usize])
    }

    /// Discard `draft`, consuming it.
    pub(super) fn discard(&mut self, draft: Draft) -> Result<(), Error> {
        let index = self.draft_index(&draft)?;
        self.drafts[index] = None;
        Ok(())
    }

    /// Consume the staged state for commit: the net edits by log id and the
    /// drafts in creation order (`None` where discarded).
    pub(super) fn take(&mut self) -> (BTreeMap<Id, Staged>, Vec<Option<DraftLog>>) {
        (
            std::mem::take(&mut self.staged),
            std::mem::take(&mut self.drafts),
        )
    }

    /// Validate `draft` as a target of this transaction and return its index.
    fn draft_index(&self, draft: &Draft) -> Result<usize, Error> {
        if draft.transaction != self.id {
            return Err(Error::InvalidTransaction(
                "draft from another transaction".into(),
            ));
        }
        // Drafts are consumed by discard, so a live Draft always points at a
        // live entry.
        assert!(self.drafts[draft.index].is_some(), "draft outlived discard");
        Ok(draft.index)
    }

    /// The net staged payload across every target, in bytes.
    fn payload_bytes(&self) -> u64 {
        let staged: u64 = self
            .staged
            .values()
            .map(|staged| match staged {
                Staged::Edit { appended, .. } => appended.len() as u64,
                Staged::Removal => 0,
            })
            .sum();
        let drafts: u64 = self
            .drafts
            .iter()
            .flatten()
            .map(|draft| draft.content.len() as u64)
            .sum();
        staged + drafts
    }

    /// The number of logs this transaction touches.
    fn touched(&self) -> usize {
        self.staged.len() + self.drafts.iter().flatten().count()
    }

    /// Reject staging that would put the transaction over its bounds:
    /// `bytes` new payload bytes and `targets` newly touched logs.
    fn ensure_bounds(&self, bytes: usize, targets: usize) -> Result<(), Error> {
        if self.touched() + targets > self.bounds.max_transaction_logs {
            return Err(Error::TransactionTooLarge(format!(
                "touches more than {} logs",
                self.bounds.max_transaction_logs
            )));
        }
        if self.payload_bytes() + bytes as u64 > self.bounds.max_transaction_bytes {
            return Err(Error::TransactionTooLarge(format!(
                "more than {} payload bytes",
                self.bounds.max_transaction_bytes
            )));
        }
        Ok(())
    }

    /// The staged edit for `id`, created from its committed length on first
    /// touch. Callers validate first.
    fn edit(&mut self, id: Id, committed: u64) -> (&mut u64, &mut Vec<u8>) {
        let Staged::Edit { keep, appended } = self.staged.entry(id).or_insert(Staged::Edit {
            keep: committed,
            appended: Vec::new(),
        }) else {
            unreachable!("targets validate as unremoved");
        };
        (keep, appended)
    }
}

/// Fill caller buffer(s) with `data`, preserving their chunk layout.
pub(super) fn fill(bufs: impl Into<IoBufsMut>, data: &[u8]) -> IoBufsMut {
    let mut bufs = bufs.into();
    // SAFETY: set_len panics if `data.len()` exceeds the buffers' capacity
    // (the documented read_at_buf contract), and every byte up to that length
    // is initialized by the copy_from_slice below before any read.
    unsafe { bufs.set_len(data.len()) };
    bufs.copy_from_slice(data);
    bufs
}
