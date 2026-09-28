//! Durability of applied database state and the acknowledgements that wait on it.

use crate::stateful::db::Barrier;
use commonware_consensus::types::Height;
use commonware_runtime::Handle;
use commonware_utils::{Acknowledgement as _, acknowledgement::Exact};
use futures::future::pending;
use std::collections::VecDeque;

/// Tracks the durable database prefix and marshal acknowledgements awaiting it.
///
/// At most one barrier covers a captured prefix. Applied heights beyond that prefix remain queued
/// for a successor barrier.
pub(super) struct Durability {
    /// Highest applied height known to be durable.
    durable: Height,
    /// Applied heights whose marshal acknowledgements await durability, in nondecreasing order.
    acknowledgements: VecDeque<(Height, Exact)>,
    /// Active barrier, whose output is the height of its captured prefix once durable.
    pub(super) barrier: Option<Handle<Option<Height>>>,
}

impl Durability {
    /// Initializes tracking at a height already known to be durable.
    pub(super) const fn new(height: Height) -> Self {
        Self {
            durable: height,
            acknowledgements: VecDeque::new(),
            barrier: None,
        }
    }

    /// Returns the highest applied height (the durable height when no acknowledgement is pending).
    pub(super) fn applied(&self) -> Height {
        self.acknowledgements
            .back()
            .map_or(self.durable, |(height, _)| *height)
    }

    /// Holds the acknowledgement for a newly applied `height` until it is durable.
    ///
    /// Panics unless `height` is above every applied height.
    pub(super) fn record(&mut self, height: Height, acknowledgement: Exact) {
        assert!(height > self.applied(), "finalized heights must increase");
        self.acknowledgements.push_back((height, acknowledgement));
    }

    /// Holds the acknowledgement for a newly applied `height` whose state is its parent's, and
    /// acknowledges it at once if every earlier applied height is durable, since no later barrier
    /// is needed to cover it.
    ///
    /// Panics unless `height` is above every applied height.
    pub(super) fn record_unchanged(&mut self, height: Height, acknowledgement: Exact) {
        assert!(height > self.applied(), "finalized heights must increase");
        if self.acknowledgements.is_empty() {
            self.durable = height;
            acknowledgement.acknowledge();
            return;
        }
        self.acknowledgements.push_back((height, acknowledgement));
    }

    /// Holds a duplicate receipt until its height is durable (acknowledging it at once if it
    /// already is).
    ///
    /// Panics if `height` is neither durable nor applied.
    pub(super) fn record_duplicate(&mut self, height: Height, acknowledgement: Exact) {
        if self.covers(height) {
            acknowledgement.acknowledge();
            return;
        }
        let index = self
            .acknowledgements
            .iter()
            .rposition(|(applied, _)| *applied == height)
            .expect("an undurable applied height must retain its acknowledgement");
        self.acknowledgements
            .insert(index + 1, (height, acknowledgement));
    }

    /// Returns whether applied state is not yet durable and no barrier is active.
    pub(super) fn needs_barrier(&self) -> bool {
        self.barrier.is_none() && self.durable < self.applied()
    }

    /// Tracks `barrier` as covering applied state through `height`.
    ///
    /// Panics if a barrier is active or `height` is not above the durable height and at or below
    /// the applied height.
    pub(super) fn set_barrier(&mut self, height: Height, barrier: Barrier) {
        assert!(self.barrier.is_none(), "barrier already active");
        assert!(height > self.durable && height <= self.applied());
        self.barrier = Some(Handle::from_future(async move {
            Ok(barrier.durable().await.then_some(height))
        }));
    }

    /// Awaits the active barrier, staying pending when none is active so callers can select on it
    /// unconditionally.
    ///
    /// Resolves to the covered height, or `None` if shutdown interrupted the barrier.
    pub(super) async fn completion(&mut self) -> Option<Height> {
        let Some(barrier) = &mut self.barrier else {
            return pending().await;
        };
        barrier.await.expect("internal barrier handle cannot fail")
    }

    /// Clears the active barrier and acknowledges every height it made durable.
    ///
    /// Returns `false` without advancing the durable height if `completion` is `None`. Panics if no
    /// barrier is active.
    pub(super) fn complete(&mut self, completion: Option<Height>) -> bool {
        assert!(self.barrier.take().is_some(), "barrier not active");
        let Some(height) = completion else {
            return false;
        };
        assert!(height > self.durable && height <= self.applied());
        self.durable = height;
        let covered = self
            .acknowledgements
            .iter()
            .take_while(|(height, _)| *height <= self.durable)
            .count();
        for (_, acknowledgement) in self.acknowledgements.drain(..covered) {
            acknowledgement.acknowledge();
        }
        true
    }

    /// Returns whether `height` lies within the known durable prefix.
    pub(super) fn covers(&self, height: Height) -> bool {
        self.durable >= height
    }
}
