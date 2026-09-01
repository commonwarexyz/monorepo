//! The application acknowledgement window and the cursor syncs it feeds.
//!
//! Simplex marshal's acknowledgement tracker retires each acknowledgement on its own. Here
//! contiguous acknowledgements coalesce into one ready prefix while a cursor sync runs, so the
//! window of unacknowledged outputs never waits on storage, and only one sync is in flight.

use super::actor::Error;
use crate::multimmit::marshal::types::OutputIndex;
use commonware_macros::select;
use commonware_runtime::telemetry::metrics::histogram::Timer;
use commonware_utils::acknowledgement::{Canceled, ExactWaiter};
use futures::{FutureExt as _, future::BoxFuture};
use std::{collections::VecDeque, num::NonZeroUsize};

/// One reported output awaiting its acknowledgement.
struct PendingAck {
    index: OutputIndex,
    waiter: ExactWaiter,
}

/// A contiguous run of acknowledged outputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Acknowledged {
    /// Last output of the run.
    pub(super) through: OutputIndex,
    /// Outputs in the run.
    pub(super) outputs: usize,
}

/// One contiguous application-ready prefix awaiting its next cursor synchronization.
pub(super) struct ReadyAcks {
    pub(super) through: OutputIndex,
    outputs: usize,
    completion_timer: Timer,
}

/// The ready prefix whose cursor sync is in flight.
pub(super) struct SyncingAcks {
    pub(super) through: OutputIndex,
    pub(super) outputs: usize,
    pub(super) durability_timer: Timer,
    pub(super) completion_timer: Timer,
    completion: BoxFuture<'static, Result<(), Error>>,
}

/// Unresolved application work plus constant-space ready and syncing FIFO prefixes.
pub(super) struct PendingAcks {
    queue: VecDeque<PendingAck>,
    ready: Option<ReadyAcks>,
    syncing: Option<SyncingAcks>,
    max: usize,
}

impl PendingAcks {
    pub(super) const fn new(max: NonZeroUsize) -> Self {
        Self {
            queue: VecDeque::new(),
            ready: None,
            syncing: None,
            max: max.get(),
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.queue.is_empty() && self.ready.is_none() && self.syncing.is_none()
    }

    pub(super) fn clear(&mut self) {
        self.queue.clear();
        self.ready = None;
        self.syncing = None;
    }

    pub(super) fn has_capacity(&self) -> bool {
        self.queue.len() < self.max
    }

    /// Returns the number of reported outputs awaiting an application acknowledgement.
    pub(super) fn in_flight(&self) -> usize {
        self.queue.len()
    }

    pub(super) fn remaining(&self) -> NonZeroUsize {
        NonZeroUsize::new(self.max - self.queue.len()).expect("delivery window has capacity")
    }

    pub(super) fn next(
        &self,
        acknowledged: Option<OutputIndex>,
    ) -> Result<Option<OutputIndex>, Error> {
        if let Some(pending) = self.queue.back() {
            return Ok(pending.index.next());
        }
        if let Some(ready) = &self.ready {
            return Ok(ready.through.next());
        }
        self.syncing.as_ref().map_or_else(
            || {
                OutputIndex::after(acknowledged)
                    .map(Some)
                    .ok_or(Error::IndexExhausted)
            },
            |syncing| Ok(syncing.through.next()),
        )
    }

    pub(super) fn push(&mut self, index: OutputIndex, waiter: ExactWaiter) {
        debug_assert!(self.has_capacity());
        self.queue.push_back(PendingAck { index, waiter });
    }

    /// Retires the acknowledged oldest output and every following output already acknowledged.
    pub(super) fn complete(&mut self, result: Result<(), Canceled>) -> Result<Acknowledged, Error> {
        result.map_err(|_| Error::AcknowledgementCanceled)?;
        let mut outputs = 1usize;
        let mut through = self
            .queue
            .pop_front()
            .expect("the completed acknowledgement is pending")
            .index;
        while let Some(result) = self.try_current() {
            result.map_err(|_| Error::AcknowledgementCanceled)?;
            outputs = outputs.saturating_add(1);
            through = self
                .queue
                .pop_front()
                .expect("the ready acknowledgement is pending")
                .index;
        }
        Ok(Acknowledged { through, outputs })
    }

    /// Appends an acknowledged run to the ready prefix.
    pub(super) fn coalesce_ready<F>(&mut self, acknowledged: Acknowledged, completion_timer: F)
    where
        F: FnOnce() -> Timer,
    {
        let Acknowledged { through, outputs } = acknowledged;
        debug_assert_ne!(outputs, 0);
        if let Some(ready) = &mut self.ready {
            let first = through
                .get()
                .checked_sub(u64::try_from(outputs - 1).unwrap_or(u64::MAX))
                .map(OutputIndex::new);
            debug_assert_eq!(ready.through.next(), first);
            ready.through = through;
            ready.outputs = ready.outputs.saturating_add(outputs);
        } else {
            self.ready = Some(ReadyAcks {
                through,
                outputs,
                completion_timer: completion_timer(),
            });
        }
    }

    pub(super) fn start_sync(
        &mut self,
        ready: ReadyAcks,
        durability_timer: Timer,
        completion: BoxFuture<'static, Result<(), Error>>,
    ) {
        debug_assert!(self.syncing.is_none());
        self.syncing = Some(SyncingAcks {
            through: ready.through,
            outputs: ready.outputs,
            durability_timer,
            completion_timer: ready.completion_timer,
            completion,
        });
    }

    pub(super) fn take_ready(&mut self) -> Option<ReadyAcks> {
        debug_assert!(self.syncing.is_none());
        self.ready.take()
    }

    pub(super) const fn is_syncing(&self) -> bool {
        self.syncing.is_some()
    }

    /// Returns the front acknowledgement's result if it is already resolved.
    pub(super) fn try_current(&mut self) -> Option<Result<(), Canceled>> {
        self.queue
            .front_mut()
            .and_then(|pending| (&mut pending.waiter).now_or_never())
    }

    pub(super) async fn next_event(&mut self) -> AcknowledgementEvent {
        let current = self.queue.front_mut().map(|pending| &mut pending.waiter);
        let syncing = self.syncing.as_mut().map(|syncing| &mut syncing.completion);
        match (current, syncing) {
            // A ready cursor sync must retire even when application acknowledgements are
            // continuously ready, so durable progress does not depend on an idle delivery window.
            (Some(current), Some(syncing)) => select! {
                result = syncing => AcknowledgementEvent::Durable(result),
                result = current => AcknowledgementEvent::Ready(result),
            },
            (Some(current), None) => AcknowledgementEvent::Ready(current.await),
            (None, Some(syncing)) => AcknowledgementEvent::Durable(syncing.await),
            (None, None) => unreachable!("a pending acknowledgement event exists"),
        }
    }

    pub(super) fn complete_sync(
        &mut self,
        result: Result<(), Error>,
    ) -> Result<SyncingAcks, Error> {
        result?;
        Ok(self
            .syncing
            .take()
            .expect("the completed acknowledgement sync is active"))
    }

    pub(super) fn pending_durability(&self) -> usize {
        self.syncing
            .as_ref()
            .map_or(0, |syncing| syncing.outputs)
            .saturating_add(self.ready.as_ref().map_or(0, |ready| ready.outputs))
    }
}

/// What the acknowledgement window is waiting on.
pub(super) enum AcknowledgementEvent {
    /// The oldest reported output was acknowledged (or its acknowledgement dropped).
    Ready(Result<(), Canceled>),
    /// The in-flight cursor sync finished.
    Durable(Result<(), Error>),
}
