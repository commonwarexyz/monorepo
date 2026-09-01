//! Commands to the persistence actor and the results it reports.

use crate::{
    multimmit::{
        actors::util::reliable_policy,
        machine::{BarrierAck, Cursor, PersistJob, Snapshot},
        storage::{JournalError, SnapshotError},
    },
    types::{Epoch, View},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_runtime::Error as RuntimeError;
use commonware_utils::channel::mpsc;
use tracing::Span;

/// Queued flush requests; one pending request already covers every later one.
const FLUSH_REQUESTS: usize = 1;

/// Commands accepted by the persistence actor, applied in the order they were admitted.
pub(crate) enum Message<H: Hasher, V: Variant> {
    /// Appends one barrier; its [`Output::Durable`] follows once a covering sync completes.
    Append(Append<V, H::Digest>),
    /// Rolls the journal, then stores `cut` as the newest snapshot.
    ///
    /// Admitted only while no append is pending.
    Checkpoint {
        /// The acknowledged state to snapshot, boxed so appends stay small in the queue.
        cut: Box<Snapshot<V, H::Digest>>,
        /// Where the checkpoint was cut, recorded on its spans.
        origin: CheckpointOrigin,
        /// The span that owns the roll.
        span: Span,
    },
}

/// One barrier to append, returned untouched when admission fails.
#[derive(Debug)]
pub(crate) struct Append<V: Variant, D: Digest> {
    /// The root span that owns terminal failures from this barrier.
    pub(crate) root: Span,
    /// The barrier's tracing span.
    pub(crate) span: Span,
    /// The machine-issued barrier.
    pub(crate) job: PersistJob<V, D>,
}

/// Where one checkpoint was cut, recorded on its roll, store, and prune spans.
#[derive(Copy, Clone, Debug)]
pub(crate) struct CheckpointOrigin {
    pub(crate) epoch: Epoch,
    pub(crate) view: View,
    pub(crate) cursor: Cursor,
    pub(crate) retired_views: View,
}

/// Result of a nonblocking command admission.
#[derive(Debug)]
pub(crate) enum Admission<T> {
    /// The bounded command queue has no free slot.
    Full(T),
    /// The persistence actor stopped accepting commands.
    Closed(T),
}

/// One result of the persistence actor, reported in the order it was produced.
pub(crate) enum Output<V: Variant, D: Digest> {
    /// One appended barrier is durable. Barriers become durable in append order.
    Durable(Durable<V, D>),
    /// The checkpoint snapshot is durable; the journal prunes once no append is pending.
    Stored,
    /// The journal sections covered by the stored snapshot were pruned.
    Pruned,
    /// A storage operation failed and the actor stopped.
    Failed {
        /// The root span that owns the failed work.
        root: Span,
        /// Why the actor stopped.
        error: Error,
    },
}

// The voter bounds the unconsumed outputs: one durability per append it has outstanding, plus at
// most one of each other kind.
reliable_policy!(impl<V: Variant, D: Digest> for Output<V, D>);

/// One durable barrier with its tracing context.
pub(crate) struct Durable<V: Variant, D: Digest> {
    /// The root span that owns terminal failures from this barrier.
    pub(crate) root: Span,
    /// The barrier's tracing span.
    pub(crate) span: Span,
    /// The barrier as appended.
    pub(crate) job: PersistJob<V, D>,
    /// The acknowledgement to admit to the core.
    pub(crate) ack: BarrierAck,
}

/// Fatal persistence failure.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    /// The journal rejected or failed a storage operation.
    #[error("safety journal failed: {0}")]
    Journal(#[from] JournalError),
    /// A started prefix sync failed in the runtime.
    #[error("safety journal sync failed: {0}")]
    Sync(#[source] RuntimeError),
    /// The checkpoint snapshot could not be stored.
    #[error("checkpoint store failed: {0}")]
    Checkpoint(#[from] SnapshotError),
    /// The snapshot write task failed in the runtime.
    #[error("checkpoint store task failed: {0}")]
    StoreTask(#[source] RuntimeError),
    /// A checkpoint arrived while appends were pending or a checkpoint was in progress.
    #[error("checkpoint requested while persistence was busy")]
    Busy,
    /// The persistence actor stopped without reporting a failure.
    #[error("persistence actor closed")]
    Closed,
}

/// Requests durability for every append admitted to one persistence actor.
///
/// Requests collapse into one and never take command capacity.
#[derive(Clone)]
pub(crate) struct Flusher {
    flushes: mpsc::Sender<()>,
}

impl Flusher {
    /// Requests durability for every append admitted before this call.
    pub(crate) fn flush(&self) -> Result<(), Error> {
        match self.flushes.try_send(()) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(())) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(())) => Err(Error::Closed),
        }
    }
}

/// One persistence actor's flush channel, opened before the actor so a [`Flusher`] can be held
/// before it starts.
pub(crate) struct Flushes {
    flusher: Flusher,
    requests: mpsc::Receiver<()>,
}

impl Default for Flushes {
    fn default() -> Self {
        let (flushes, requests) = mpsc::channel(FLUSH_REQUESTS);
        Self {
            flusher: Flusher { flushes },
            requests,
        }
    }
}

impl Flushes {
    /// Returns a handle that requests durability from the actor this channel is given to.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) fn flusher(&self) -> Flusher {
        self.flusher.clone()
    }

    /// Splits the channel into the mailbox's flusher and the actor's request receiver.
    pub(super) fn split(self) -> (Flusher, mpsc::Receiver<()>) {
        (self.flusher, self.requests)
    }
}

/// Nonblocking handle to the persistence actor.
pub(crate) struct Mailbox<H: Hasher, V: Variant> {
    commands: mpsc::Sender<Message<H, V>>,
    flusher: Flusher,
}

impl<H: Hasher, V: Variant> Clone for Mailbox<H, V> {
    fn clone(&self) -> Self {
        Self {
            commands: self.commands.clone(),
            flusher: self.flusher.clone(),
        }
    }
}

impl<H: Hasher, V: Variant> Mailbox<H, V> {
    pub(super) const fn new(commands: mpsc::Sender<Message<H, V>>, flusher: Flusher) -> Self {
        Self { commands, flusher }
    }

    /// Admits one append without waiting for command capacity.
    ///
    /// On saturation or closure the append is returned, so the caller never clones or drops a
    /// mandatory barrier.
    pub(crate) fn append(
        &self,
        root: Span,
        span: Span,
        job: PersistJob<V, H::Digest>,
    ) -> Result<(), Admission<Append<V, H::Digest>>> {
        let append = Append { root, span, job };
        match self.commands.try_send(Message::Append(append)) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(Message::Append(append))) => {
                Err(Admission::Full(append))
            }
            Err(mpsc::error::TrySendError::Closed(Message::Append(append))) => {
                Err(Admission::Closed(append))
            }
            Err(_) => unreachable!("append sends an append command"),
        }
    }

    /// Admits one checkpoint without waiting for command capacity.
    pub(crate) fn checkpoint(
        &self,
        cut: Snapshot<V, H::Digest>,
        origin: CheckpointOrigin,
        span: Span,
    ) -> Result<(), Admission<()>> {
        let cut = Box::new(cut);
        match self
            .commands
            .try_send(Message::Checkpoint { cut, origin, span })
        {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Err(Admission::Full(())),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(Admission::Closed(())),
        }
    }

    /// Requests durability for every append admitted before this call.
    ///
    /// Requests collapse into one and never take command capacity.
    pub(crate) fn flush(&self) -> Result<(), Error> {
        self.flusher.flush()
    }

    /// Returns whether a command can be admitted without waiting at this instant.
    ///
    /// The voter is the only sender, so it can check before running core work that may stage a
    /// mandatory barrier. [`Self::append`] stays authoritative.
    pub(crate) fn has_capacity(&self) -> bool {
        self.commands.capacity() != 0
    }

    /// Waits until one command slot can be reserved, then releases it without sending.
    pub(crate) async fn wait_for_capacity(&self) -> Result<(), Error> {
        let permit = self.commands.reserve().await.map_err(|_| Error::Closed)?;
        drop(permit);
        Ok(())
    }
}
