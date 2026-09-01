//! Temporary-custody staging of fetched blocks before their waiters complete.

use super::{BackfillSubscriber, Error, mailbox::DeliveryReply, waiter::Resolved};
use crate::multimmit::{
    marshal::{actors::catalog, wire::BackfillKey},
    types::{Body, TransactionBlock},
};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use commonware_resolver::Delivery;
use commonware_runtime::telemetry::metrics::histogram::Timer;
use commonware_utils::futures::Pool;
use std::{
    collections::{BTreeSet, VecDeque},
    sync::Arc,
};
use tracing::{Instrument as _, Span};

/// A validated delivery waiting for its outcome.
pub(super) struct Ready<H: Hasher, V: Variant, B: Body<H>> {
    pub delivery: Delivery<BackfillKey<H::Digest>, BackfillSubscriber>,
    pub resolved: Resolved<H, V, B>,
    pub response: DeliveryReply,
}

/// Ready deliveries whose blocks are staged in temporary custody with one catalog request.
pub(super) struct StagingJob<H: Hasher, V: Variant, B: Body<H>> {
    pub ready: Vec<Ready<H, V, B>>,
    /// Blocks to stage, in delivery order.
    pub blocks: Vec<Arc<TransactionBlock<H, B>>>,
    /// Keys reserved by the job until it completes.
    pub keys: BTreeSet<BackfillKey<H::Digest>>,
    /// Encoded bytes of the staged deliveries.
    pub bytes: u64,
}

impl<H: Hasher, V: Variant, B: Body<H>> StagingJob<H, V, B> {
    pub(super) const fn new() -> Self {
        Self {
            ready: Vec::new(),
            blocks: Vec::new(),
            keys: BTreeSet::new(),
            bytes: 0,
        }
    }

    /// Adds a ready delivery whose blocks must be staged, counting `bytes` encoded bytes.
    pub(super) fn push(&mut self, ready: Ready<H, V, B>, bytes: u64) {
        self.blocks.extend(ready.resolved.blocks().iter().cloned());
        self.keys.insert(ready.delivery.key);
        self.bytes = self.bytes.saturating_add(bytes);
        self.ready.push(ready);
    }

    /// Returns whether the job stages nothing.
    pub(super) const fn is_empty(&self) -> bool {
        self.ready.is_empty()
    }
}

/// A finished staging request.
pub(super) struct StagingCompletion<H: Hasher, V: Variant, B: Body<H>> {
    pub job: StagingJob<H, V, B>,
    pub timer: Timer,
    pub result: Result<(), Error>,
}

/// A staging job waiting for a free slot, with the span its request runs under.
struct Queued<H: Hasher, V: Variant, B: Body<H>> {
    job: StagingJob<H, V, B>,
    span: Span,
}

/// Staging requests: at most `max_active` in flight, the rest queued in order.
///
/// A key stays reserved from admission until its job completes, so a duplicate delivery for it is
/// ignored instead of staged twice. At most `max_reserved` keys are reserved at once.
pub(super) struct Staging<H: Hasher, V: Variant, B: Body<H>> {
    queued: VecDeque<Queued<H, V, B>>,
    queued_bytes: u64,
    active: Pool<'static, StagingCompletion<H, V, B>>,
    active_bytes: u64,
    reserved: BTreeSet<BackfillKey<H::Digest>>,
    max_active: usize,
    max_reserved: usize,
}

impl<H: Hasher, V: Variant, B: Body<H>> Staging<H, V, B> {
    pub(super) fn new(max_active: usize, max_reserved: usize) -> Self {
        Self {
            queued: VecDeque::new(),
            queued_bytes: 0,
            active: Pool::default(),
            active_bytes: 0,
            reserved: BTreeSet::new(),
            max_active,
            max_reserved,
        }
    }

    /// Returns whether a queued or active job reserves `key`.
    pub(super) fn is_reserved(&self, key: &BackfillKey<H::Digest>) -> bool {
        self.reserved.contains(key)
    }

    /// Returns whether no further key can be reserved.
    pub(super) fn is_saturated(&self) -> bool {
        self.reserved.len() >= self.max_reserved
    }

    /// Reserves `key` for a job being assembled.
    pub(super) fn reserve(&mut self, key: BackfillKey<H::Digest>) {
        self.reserved.insert(key);
    }

    /// Queues `job`, whose staging request runs under `span`.
    pub(super) fn queue(&mut self, job: StagingJob<H, V, B>, span: Span) {
        self.queued_bytes = self.queued_bytes.saturating_add(job.bytes);
        self.queued.push_back(Queued { job, span });
    }

    /// Starts queued jobs while slots are free; `timer` starts each job's latency timer.
    pub(super) fn schedule(
        &mut self,
        catalog: &catalog::Mailbox<H, V, B>,
        mut timer: impl FnMut() -> Timer,
    ) {
        while self.active.len() < self.max_active {
            let Some(Queued { job, span }) = self.queued.pop_front() else {
                break;
            };
            self.queued_bytes = self
                .queued_bytes
                .checked_sub(job.bytes)
                .expect("queued staging byte accounting underflow");
            self.active_bytes = self.active_bytes.saturating_add(job.bytes);
            let catalog = catalog.clone();
            let timer = timer();
            self.active.push(
                async move {
                    let result = catalog.stage_blocks(&job.blocks).await.map_err(Error::from);
                    StagingCompletion { job, timer, result }
                }
                .instrument(span),
            );
        }
    }

    /// Releases the accounting and reservations of a finished job.
    pub(super) fn finish(&mut self, job: &StagingJob<H, V, B>) -> Result<(), Error> {
        self.active_bytes = self
            .active_bytes
            .checked_sub(job.bytes)
            .ok_or(Error::Invalid("staging byte accounting underflow"))?;
        for key in &job.keys {
            if !self.reserved.remove(key) {
                return Err(Error::Invalid("completed staging key is not active"));
            }
        }
        Ok(())
    }

    /// Returns whether no job is queued or active.
    pub(super) fn is_idle(&self) -> bool {
        self.queued.is_empty() && self.active.is_empty()
    }

    /// Returns the number and bytes of active jobs, then of queued jobs.
    pub(super) fn load(&self) -> Load {
        Load {
            active: self.active.len(),
            active_bytes: self.active_bytes,
            queued: self.queued.len(),
            queued_bytes: self.queued_bytes,
        }
    }

    /// Resolves to the next finished job.
    pub(super) async fn next_completed(&mut self) -> StagingCompletion<H, V, B> {
        self.active.next_completed().await
    }
}

/// Staging jobs and bytes in flight and queued.
pub(super) struct Load {
    pub active: usize,
    pub active_bytes: u64,
    pub queued: usize,
    pub queued_bytes: u64,
}
