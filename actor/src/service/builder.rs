use super::{
    driver::ActorService,
    types::{DuplicateLaneError, LaneReceiver, LaneReceiverKind, Lanes},
    DEFAULT_MAILBOX_CAPACITY, DEFAULT_MAX_INFLIGHT_READS,
};
use crate::{
    mailbox::{Mailbox, UnboundedMailbox},
    Actor,
};
use commonware_runtime::{ContextCell, Spawner};
use commonware_utils::channel::mpsc;
use std::{collections::BTreeMap, num::NonZeroUsize};

type SingleLaneBuildOutput<E, A> = (<A as Actor<E>>::Mailbox, ActorService<E, A>);

type MultiLaneBuildOutput<E, A, L> = (Lanes<L, <A as Actor<E>>::Mailbox>, ActorService<E, A>);

fn validate_unique_lanes<'a, L>(
    lanes: impl IntoIterator<Item = &'a L>,
) -> Result<(), DuplicateLaneError>
where
    L: Ord + 'a,
{
    let mut seen = std::collections::BTreeSet::new();
    for lane in lanes {
        if !seen.insert(lane) {
            return Err(DuplicateLaneError);
        }
    }
    Ok(())
}

fn build_service<E, A>(
    context: E,
    actor: A,
    lanes: Vec<LaneReceiver<A::Ingress>>,
    max_inflight_reads: NonZeroUsize,
) -> ActorService<E, A>
where
    E: Spawner,
    A: Actor<E>,
{
    let shutdown = context.stopped();
    ActorService {
        context: ContextCell::new(context),
        actor,
        lanes,
        shutdown,
        max_inflight_reads,
    }
}

/// Configures an actor service loop before lane type is selected.
///
/// Polling is biased and deterministic:
/// - shutdown is always checked first
/// - lane polling is declaration-order biased
/// - the actor-defined [`Actor::on_external`] future is polled after lanes
///
/// **Note:** Under sustained load, earlier lanes can starve later lanes
/// because the first ready lane is always selected.
///
/// # Behavioral Semantics
///
/// - Each iteration dispatches at most one external event, or a batch of up
///   to [`Actor::max_lane_batch`] messages from one winning lane.
/// - Returning `Err` from [`Actor::on_read_only`] or [`Actor::on_read_write`]
///   is fatal: the error is logged, remaining in-flight reads are drained,
///   and then [`Actor::on_shutdown`] is called before the loop exits.
/// - A lane closing (`None`) or [`Actor::on_external`] returning `None`
///   triggers [`Actor::on_shutdown`] before exiting.
///
/// For single-lane actors with mailbox ergonomics, use
/// [`ServiceBuilder::build`] or [`ServiceBuilder::build_with_capacity`].
///
/// Adding the first lane transitions this typestate to [`MultiLaneServiceBuilder`].
pub struct ServiceBuilder<A> {
    actor: A,
    max_inflight_reads: NonZeroUsize,
}

impl<A> ServiceBuilder<A> {
    /// Create a new service builder for `actor`.
    pub const fn new(actor: A) -> Self {
        Self {
            actor,
            max_inflight_reads: DEFAULT_MAX_INFLIGHT_READS,
        }
    }

    /// Configure the maximum number of in-flight read-only handlers.
    pub const fn with_read_concurrency(mut self, max_inflight_reads: NonZeroUsize) -> Self {
        self.max_inflight_reads = max_inflight_reads;
        self
    }

    /// Add a bounded lane, transitioning to a [`MultiLaneServiceBuilder`].
    ///
    /// `capacity` is per-lane queue depth and must be non-zero.
    pub fn with_lane<L>(self, lane: L, capacity: NonZeroUsize) -> MultiLaneServiceBuilder<A, L>
    where
        L: Ord,
    {
        MultiLaneServiceBuilder {
            actor: self.actor,
            lanes: vec![(lane, capacity)],
            max_inflight_reads: self.max_inflight_reads,
        }
    }

    /// Add an unbounded lane, transitioning to a [`MultiLaneUnboundedServiceBuilder`].
    pub fn with_unbounded_lane<L>(self, lane: L) -> MultiLaneUnboundedServiceBuilder<A, L>
    where
        L: Ord,
    {
        MultiLaneUnboundedServiceBuilder {
            actor: self.actor,
            lanes: vec![lane],
            max_inflight_reads: self.max_inflight_reads,
        }
    }

    /// Build a single-lane service with the default non-zero mailbox capacity of 64.
    ///
    /// This is a convenience for simple actors that only need one lane.
    pub fn build<E>(self, context: E) -> SingleLaneBuildOutput<E, A>
    where
        E: Spawner,
        A: Actor<E>,
        A::Mailbox: From<Mailbox<A::Ingress>>,
    {
        self.build_with_capacity(context, DEFAULT_MAILBOX_CAPACITY)
    }

    /// Build a single-lane service with an unbounded mailbox.
    ///
    /// This is a convenience for actors whose callers must never block on enqueue
    /// (e.g., when messages are sent from `Drop` implementations).
    pub fn build_unbounded<E>(self, context: E) -> SingleLaneBuildOutput<E, A>
    where
        E: Spawner,
        A: Actor<E>,
        A::Mailbox: From<UnboundedMailbox<A::Ingress>>,
    {
        let (tx, rx) = mpsc::unbounded_channel();
        let mailbox = A::Mailbox::from(UnboundedMailbox::new(tx));
        let service = build_service(
            context,
            self.actor,
            vec![LaneReceiver {
                receiver: LaneReceiverKind::Unbounded(rx),
            }],
            self.max_inflight_reads,
        );

        (mailbox, service)
    }

    /// Build a single-lane service with the provided mailbox capacity.
    ///
    /// `capacity` must be non-zero.
    pub fn build_with_capacity<E>(
        self,
        context: E,
        capacity: NonZeroUsize,
    ) -> SingleLaneBuildOutput<E, A>
    where
        E: Spawner,
        A: Actor<E>,
        A::Mailbox: From<Mailbox<A::Ingress>>,
    {
        let (tx, rx) = mpsc::channel(capacity.get());
        let mailbox = A::Mailbox::from(Mailbox::new(tx));
        let service = build_service(
            context,
            self.actor,
            vec![LaneReceiver {
                receiver: LaneReceiverKind::Bounded(rx),
            }],
            self.max_inflight_reads,
        );

        (mailbox, service)
    }
}

/// Configures a multi-lane actor service loop with bounded lanes.
pub struct MultiLaneServiceBuilder<A, L>
where
    L: Ord,
{
    actor: A,
    lanes: Vec<(L, NonZeroUsize)>,
    max_inflight_reads: NonZeroUsize,
}

impl<A, L> MultiLaneServiceBuilder<A, L>
where
    L: Ord,
{
    /// Add another bounded lane.
    ///
    /// `capacity` is per-lane queue depth and must be non-zero.
    pub fn with_lane(mut self, lane: L, capacity: NonZeroUsize) -> Self {
        self.lanes.push((lane, capacity));
        self
    }

    /// Configure the maximum number of in-flight read-only handlers.
    pub const fn with_read_concurrency(mut self, max_inflight_reads: NonZeroUsize) -> Self {
        self.max_inflight_reads = max_inflight_reads;
        self
    }

    /// Finalize construction, returning per-lane mailboxes and control loop driver.
    ///
    /// # Errors
    ///
    /// Returns [`DuplicateLaneError`] when the same lane key is added
    /// more than once.
    pub fn build<E>(self, context: E) -> Result<MultiLaneBuildOutput<E, A, L>, DuplicateLaneError>
    where
        E: Spawner,
        A: Actor<E>,
        A::Mailbox: From<Mailbox<A::Ingress>>,
    {
        validate_unique_lanes(self.lanes.iter().map(|(lane, _)| lane))?;

        let mut mailboxes = BTreeMap::new();
        let mut receivers = Vec::with_capacity(self.lanes.len());

        for (lane, capacity) in self.lanes {
            let (tx, rx) = mpsc::channel(capacity.get());
            mailboxes.insert(lane, A::Mailbox::from(Mailbox::new(tx)));
            receivers.push(LaneReceiver {
                receiver: LaneReceiverKind::Bounded(rx),
            });
        }

        let service = build_service(context, self.actor, receivers, self.max_inflight_reads);

        Ok((Lanes { mailboxes }, service))
    }
}

/// Configures a multi-lane actor service loop with unbounded lanes.
pub struct MultiLaneUnboundedServiceBuilder<A, L>
where
    L: Ord,
{
    actor: A,
    lanes: Vec<L>,
    max_inflight_reads: NonZeroUsize,
}

impl<A, L> MultiLaneUnboundedServiceBuilder<A, L>
where
    L: Ord,
{
    /// Add another unbounded lane.
    pub fn with_unbounded_lane(mut self, lane: L) -> Self {
        self.lanes.push(lane);
        self
    }

    /// Configure the maximum number of in-flight read-only handlers.
    pub const fn with_read_concurrency(mut self, max_inflight_reads: NonZeroUsize) -> Self {
        self.max_inflight_reads = max_inflight_reads;
        self
    }

    /// Finalize construction, returning per-lane mailboxes and control loop driver.
    ///
    /// # Errors
    ///
    /// Returns [`DuplicateLaneError`] when the same lane key is added
    /// more than once.
    pub fn build<E>(self, context: E) -> Result<MultiLaneBuildOutput<E, A, L>, DuplicateLaneError>
    where
        E: Spawner,
        A: Actor<E>,
        A::Mailbox: From<UnboundedMailbox<A::Ingress>>,
    {
        validate_unique_lanes(self.lanes.iter())?;

        let mut mailboxes = BTreeMap::new();
        let mut receivers = Vec::with_capacity(self.lanes.len());

        for lane in self.lanes {
            let (tx, rx) = mpsc::unbounded_channel();
            mailboxes.insert(lane, A::Mailbox::from(UnboundedMailbox::new(tx)));
            receivers.push(LaneReceiver {
                receiver: LaneReceiverKind::Unbounded(rx),
            });
        }

        let service = build_service(context, self.actor, receivers, self.max_inflight_reads);

        Ok((Lanes { mailboxes }, service))
    }
}
