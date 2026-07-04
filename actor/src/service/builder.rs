use super::{
    driver::Service,
    reliable::Reliable,
    types::{DuplicateLaneError, Lanes},
    unreliable::Unreliable,
    FenceMode, DEFAULT_MAILBOX_CAPACITY, DEFAULT_MAX_INFLIGHT_READS,
};
use crate::{
    ingress::{Mailbox, UnreliableMailbox},
    mailbox::{self, Policy, Receiver, UnreliablePolicy, UnreliableReceiver},
    Actor,
};
use commonware_runtime::{Metrics as RuntimeMetrics, Spawner};
use std::{collections::BTreeMap, num::NonZeroUsize};

type SingleLaneBuildOutput<E, A> = (<A as Actor<E>>::Mailbox, Reliable<E, A>);

type MultiLaneBuildOutput<E, A, L> = (Lanes<L, <A as Actor<E>>::Mailbox>, Reliable<E, A>);

type SingleLaneUnreliableBuildOutput<E, A> = (<A as Actor<E>>::Mailbox, Unreliable<E, A>);

type MultiLaneUnreliableBuildOutput<E, A, L> =
    (Lanes<L, <A as Actor<E>>::Mailbox>, Unreliable<E, A>);

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

fn build_reliable_service<E, A>(
    context: E,
    actor: A,
    lanes: Vec<Receiver<A::Ingress>>,
    max_inflight_reads: NonZeroUsize,
    fence_mode: FenceMode,
) -> Reliable<E, A>
where
    E: RuntimeMetrics + Spawner,
    A: Actor<E>,
    A::Ingress: Policy<Overflow: Send> + Send + 'static,
{
    Reliable::new(Service::new(
        context,
        actor,
        lanes,
        max_inflight_reads,
        fence_mode,
    ))
}

fn build_unreliable_service<E, A>(
    context: E,
    actor: A,
    lanes: Vec<UnreliableReceiver<A::Ingress>>,
    max_inflight_reads: NonZeroUsize,
    fence_mode: FenceMode,
) -> Unreliable<E, A>
where
    E: RuntimeMetrics + Spawner,
    A: Actor<E>,
    A::Ingress: UnreliablePolicy<Overflow: Send> + Send + 'static,
{
    Unreliable::new(Service::new(
        context,
        actor,
        lanes,
        max_inflight_reads,
        fence_mode,
    ))
}

/// Configures an actor service loop before lane type is selected.
///
/// Polling is biased and deterministic:
/// - lane polling is declaration-order biased
/// - actor-defined source ordering lives in [`Actor::next_event`]
///
/// Runtime shutdown and read-only handler completion can cancel and restart
/// [`Actor::next_event`]. Under sustained load, earlier lanes can starve later
/// lanes because the first ready lane is always selected.
///
/// [`Builder::build`] creates reliable lanes backed by
/// [`crate::mailbox::Policy`]. [`Builder::build_unreliable`] creates
/// unreliable lanes backed by [`crate::mailbox::UnreliablePolicy`].
pub struct Builder<A> {
    actor: A,
    max_inflight_reads: NonZeroUsize,
    fence_mode: FenceMode,
}

impl<A> Builder<A> {
    /// Create a new service builder for `actor`.
    pub const fn new(actor: A) -> Self {
        Self {
            actor,
            max_inflight_reads: DEFAULT_MAX_INFLIGHT_READS,
            fence_mode: FenceMode::Linearizable,
        }
    }

    /// Configure the maximum number of in-flight read-only handlers.
    ///
    /// The default is [`DEFAULT_MAX_INFLIGHT_READS`].
    pub const fn with_read_concurrency(mut self, max_inflight_reads: NonZeroUsize) -> Self {
        self.max_inflight_reads = max_inflight_reads;
        self
    }

    /// Configure how read-write handlers order against in-flight reads.
    ///
    /// The default is [`FenceMode::Linearizable`].
    pub const fn with_fence_mode(mut self, fence_mode: FenceMode) -> Self {
        self.fence_mode = fence_mode;
        self
    }

    /// Add a bounded lane, transitioning to a [`MultiLaneBuilder`].
    ///
    /// `capacity` is per-lane ready-queue depth; overflow beyond it is
    /// managed by the ingress policy.
    pub fn with_lane<L>(self, lane: L, capacity: NonZeroUsize) -> MultiLaneBuilder<A, L>
    where
        L: Ord,
    {
        MultiLaneBuilder {
            actor: self.actor,
            lanes: vec![(lane, capacity)],
            max_inflight_reads: self.max_inflight_reads,
            fence_mode: self.fence_mode,
        }
    }

    /// Build a single-lane service with [`DEFAULT_MAILBOX_CAPACITY`].
    pub fn build<E>(self, context: E) -> SingleLaneBuildOutput<E, A>
    where
        E: RuntimeMetrics + Spawner,
        A: Actor<E>,
        A::Ingress: Policy<Overflow: Send>,
        A::Mailbox: From<Mailbox<A::Ingress>>,
    {
        self.build_with_capacity(context, DEFAULT_MAILBOX_CAPACITY)
    }

    /// Build a single-lane service with the provided mailbox capacity.
    ///
    /// `capacity` is the ready-queue depth; overflow beyond it is managed by
    /// the ingress policy.
    pub fn build_with_capacity<E>(
        self,
        context: E,
        capacity: NonZeroUsize,
    ) -> SingleLaneBuildOutput<E, A>
    where
        E: RuntimeMetrics + Spawner,
        A: Actor<E>,
        A::Ingress: Policy<Overflow: Send>,
        A::Mailbox: From<Mailbox<A::Ingress>>,
    {
        let (sender, receiver) = mailbox::new(context.child("mailbox"), capacity);
        let mailbox = A::Mailbox::from(Mailbox::new(sender));
        let service = build_reliable_service(
            context,
            self.actor,
            vec![receiver],
            self.max_inflight_reads,
            self.fence_mode,
        );

        (mailbox, service)
    }

    /// Build a single-lane unreliable service with [`DEFAULT_MAILBOX_CAPACITY`].
    pub fn build_unreliable<E>(self, context: E) -> SingleLaneUnreliableBuildOutput<E, A>
    where
        E: RuntimeMetrics + Spawner,
        A: Actor<E>,
        A::Ingress: UnreliablePolicy<Overflow: Send>,
        A::Mailbox: From<UnreliableMailbox<A::Ingress>>,
    {
        self.build_unreliable_with_capacity(context, DEFAULT_MAILBOX_CAPACITY)
    }

    /// Build a single-lane unreliable service with the provided mailbox capacity.
    ///
    /// `capacity` is the ready-queue depth; overflow beyond it is managed by
    /// the unreliable ingress policy and may reject submitted work.
    pub fn build_unreliable_with_capacity<E>(
        self,
        context: E,
        capacity: NonZeroUsize,
    ) -> SingleLaneUnreliableBuildOutput<E, A>
    where
        E: RuntimeMetrics + Spawner,
        A: Actor<E>,
        A::Ingress: UnreliablePolicy<Overflow: Send>,
        A::Mailbox: From<UnreliableMailbox<A::Ingress>>,
    {
        let (sender, receiver) = mailbox::new_unreliable(context.child("mailbox"), capacity);
        let mailbox = A::Mailbox::from(UnreliableMailbox::new(sender));
        let service = build_unreliable_service(
            context,
            self.actor,
            vec![receiver],
            self.max_inflight_reads,
            self.fence_mode,
        );

        (mailbox, service)
    }
}

/// Configures a multi-lane actor service loop with bounded lanes.
pub struct MultiLaneBuilder<A, L>
where
    L: Ord,
{
    actor: A,
    lanes: Vec<(L, NonZeroUsize)>,
    max_inflight_reads: NonZeroUsize,
    fence_mode: FenceMode,
}

impl<A, L> MultiLaneBuilder<A, L>
where
    L: Ord,
{
    /// Add another bounded lane.
    ///
    /// `capacity` is per-lane ready-queue depth; overflow beyond it is
    /// managed by the ingress policy.
    pub fn with_lane(mut self, lane: L, capacity: NonZeroUsize) -> Self {
        self.lanes.push((lane, capacity));
        self
    }

    /// Configure the maximum number of in-flight read-only handlers.
    ///
    /// The default is [`DEFAULT_MAX_INFLIGHT_READS`].
    pub const fn with_read_concurrency(mut self, max_inflight_reads: NonZeroUsize) -> Self {
        self.max_inflight_reads = max_inflight_reads;
        self
    }

    /// Configure how read-write handlers order against in-flight reads.
    ///
    /// The default is [`FenceMode::Linearizable`].
    pub const fn with_fence_mode(mut self, fence_mode: FenceMode) -> Self {
        self.fence_mode = fence_mode;
        self
    }

    /// Finalize construction, returning per-lane mailboxes and control loop driver.
    ///
    /// # Errors
    ///
    /// Returns [`DuplicateLaneError`] when the same lane key is added more than once.
    pub fn build<E>(self, context: E) -> Result<MultiLaneBuildOutput<E, A, L>, DuplicateLaneError>
    where
        E: RuntimeMetrics + Spawner,
        A: Actor<E>,
        A::Ingress: Policy<Overflow: Send>,
        A::Mailbox: From<Mailbox<A::Ingress>>,
    {
        validate_unique_lanes(self.lanes.iter().map(|(lane, _)| lane))?;

        let mut mailboxes = BTreeMap::new();
        let mut receivers = Vec::with_capacity(self.lanes.len());

        for (index, (lane, capacity)) in self.lanes.into_iter().enumerate() {
            let lane_context = context.child("mailbox").with_attribute("lane", index);
            let (sender, receiver) = mailbox::new(lane_context, capacity);
            mailboxes.insert(lane, A::Mailbox::from(Mailbox::new(sender)));
            receivers.push(receiver);
        }

        let service = build_reliable_service(
            context,
            self.actor,
            receivers,
            self.max_inflight_reads,
            self.fence_mode,
        );

        Ok((Lanes { mailboxes }, service))
    }

    /// Finalize construction with unreliable lanes.
    ///
    /// # Errors
    ///
    /// Returns [`DuplicateLaneError`] when the same lane key is added more than once.
    pub fn build_unreliable<E>(
        self,
        context: E,
    ) -> Result<MultiLaneUnreliableBuildOutput<E, A, L>, DuplicateLaneError>
    where
        E: RuntimeMetrics + Spawner,
        A: Actor<E>,
        A::Ingress: UnreliablePolicy<Overflow: Send>,
        A::Mailbox: From<UnreliableMailbox<A::Ingress>>,
    {
        validate_unique_lanes(self.lanes.iter().map(|(lane, _)| lane))?;

        let mut mailboxes = BTreeMap::new();
        let mut receivers = Vec::with_capacity(self.lanes.len());

        for (index, (lane, capacity)) in self.lanes.into_iter().enumerate() {
            let lane_context = context.child("mailbox").with_attribute("lane", index);
            let (sender, receiver) = mailbox::new_unreliable(lane_context, capacity);
            mailboxes.insert(lane, A::Mailbox::from(UnreliableMailbox::new(sender)));
            receivers.push(receiver);
        }

        let service = build_unreliable_service(
            context,
            self.actor,
            receivers,
            self.max_inflight_reads,
            self.fence_mode,
        );

        Ok((Lanes { mailboxes }, service))
    }
}
