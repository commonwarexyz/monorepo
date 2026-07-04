//! Safely coordinate concurrent components.
//!
//! An actor is a task that owns mutable state and processes messages sent by
//! other components. Getting that pattern right by hand is subtle: senders
//! need backpressure that never blocks them, request/response needs typing and
//! tracing, reads want to run concurrently while writes stay exclusive, and
//! shutdown must not strand callers awaiting a response. This crate packages
//! the pattern into three layers, each usable without the ones above it:
//!
//! ```text
//!   callers
//!      |  tell / ask / subscribe        typed methods from ingress!
//!      v
//!   +--------------------------+
//!   |    mailbox (per lane)    |        bounded ready queue + policy overflow
//!   +--------------------------+
//!      |
//!      v
//!   +--------------------------+        read-only  --> read pool (snapshots)
//!   |       service loop       |
//!   +--------------------------+        read-write --> control loop (serial)
//!      |
//!      v
//!   actor hooks (on_read_only, on_read_write, ...)
//! ```
//!
//! # Mailbox
//!
//! [`mailbox`] provides a bounded, non-blocking queue. Sends never block: when
//! the ready queue is full, the message is handed to a caller-defined
//! [`mailbox::Policy`] that can retain, coalesce, replace, or deliberately
//! drop it. Backpressure behavior is part of an actor's message type rather
//! than a property discovered under load.
//!
//! # Ingress
//!
//! [`ingress!`] turns message declarations into typed enums and a mailbox
//! wrapper with `tell` (fire-and-forget), `ask` (request/response), and
//! `subscribe` (enqueue now, await later) methods. Each declaration routes to
//! a read-only or read-write handler, and generated methods carry tracing
//! spans across the channel so a request's trace follows it between actors.
//!
//! # Service
//!
//! [`service::Builder`] runs an [`Actor`] on a managed control loop.
//! Read-only ingress is dispatched concurrently to a bounded worker pool,
//! each handler executing on a snapshot of actor state captured at admission.
//! Read-write ingress runs serially on the control loop, ordered against
//! in-flight reads by a configurable [`service::FenceMode`]. See [`service`]
//! for the concurrency model and its ordering guarantees.
//!
//! # Status
//!
//! Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

// Macro expansions use one stable path in this crate, doctests, and downstream crates.
#[allow(unused_extern_crates)]
extern crate self as commonware_actor;

#[cfg(test)]
mod mocks;

commonware_macros::stability_scope!(BETA {
    /// Feedback from submitting work to a bounded endpoint.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Feedback {
        /// The work was accepted within the configured capacity.
        Ok,
        /// The submission exceeded configured capacity but was handled by the overflow policy.
        Backoff,
        /// The endpoint is closed.
        Closed,
    }

    impl Feedback {
        /// Returns `true` when the endpoint handled the submission.
        pub const fn accepted(self) -> bool {
            matches!(self, Self::Ok | Self::Backoff)
        }
    }

    /// Feedback from endpoints that may reject work under backpressure.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Unreliable<T> {
        /// Endpoint outcome from the submission attempt.
        Outcome(T),
        /// The work was rejected by the endpoint.
        Rejected,
    }

    impl<T> Unreliable<T> {
        /// Wrap an outcome for an operation that may reject work.
        pub const fn new(outcome: T) -> Self {
            Self::Outcome(outcome)
        }

        /// Create a rejected result.
        pub const fn rejected() -> Self {
            Self::Rejected
        }

        /// Returns `true` when the operation was rejected before producing an outcome.
        pub const fn is_rejected(&self) -> bool {
            matches!(self, Self::Rejected)
        }

        /// Returns the outcome when the operation was not rejected.
        pub fn outcome(self) -> Option<T> {
            match self {
                Self::Outcome(outcome) => Some(outcome),
                Self::Rejected => None,
            }
        }
    }

    impl Unreliable<Feedback> {
        /// Returns `true` when the endpoint handled the submission.
        pub const fn accepted(self) -> bool {
            match self {
                Self::Outcome(feedback) => feedback.accepted(),
                Self::Rejected => false,
            }
        }
    }

    pub mod mailbox;
});

commonware_macros::stability_scope!(ALPHA {
    use std::{
        fmt::{Debug, Display},
        future::Future,
        num::NonZeroUsize,
    };

    pub mod ingress;
    pub mod service;

    #[doc(hidden)]
    pub use commonware_utils::channel::oneshot;
    #[doc(hidden)]
    pub use tracing;

    pub use commonware_actor_macros::ingress;

    /// Stateful task driven by the actor service loop.
    ///
    /// See [`service`] for the loop's concurrency model and ordering
    /// guarantees.
    ///
    /// # Lifecycle
    ///
    /// In driver mode ([`service::Builder`]), hooks run in this order:
    ///
    /// 1. `on_startup` once (receives [`Actor::Args`] data).
    /// 2. Per iteration: `preprocess`, then [`Actor::next_event`] selects
    ///    one event (with runtime shutdown and read failures checked by the
    ///    service loop). If a lane message is selected, the service may drain
    ///    additional ready messages from that same lane, up to
    ///    [`Actor::max_lane_batch`]. Each message is dispatched to
    ///    `on_read_only` (concurrent) or `on_read_write` (serial). After at
    ///    least one message is dispatched, `postprocess` runs once.
    /// 3. `on_shutdown` once, on graceful exit (runtime stop,
    ///    [`service::Event::Stop`], or a fatal handler error).
    ///
    /// Returning `Err` from `on_read_only` or `on_read_write` is fatal: the
    /// error is logged and `on_shutdown` is called before the loop exits.
    ///
    /// # Shutdown
    ///
    /// Shutdown is prompt: in-flight read-only handlers are aborted before
    /// [`Actor::on_shutdown`] runs, and their pending askers observe
    /// [`ingress::Cancelled`]. A read-only handler must not be relied upon to
    /// run to completion across shutdown.
    pub trait Actor<E>: Send + 'static {
        /// Typed mailbox returned by the service builder.
        ///
        /// Set this to the mailbox wrapper generated by [`ingress!`] so that
        /// [`service::Builder::build`] returns the typed mailbox
        /// directly.
        type Mailbox: Send + Clone + 'static;

        /// Envelope ingress type consumed by the service mailbox.
        ///
        /// Generated mailbox wrappers from [`ingress!`] set this to
        /// `<MailboxName>Message`.
        ///
        /// Service builders choose whether lanes are backed by reliable or
        /// unreliable mailbox endpoints.
        type Ingress: service::Ingress;

        /// Fatal error type returned by [`Actor::on_read_only`] and
        /// [`Actor::on_read_write`].
        ///
        /// Returning `Err` from read or write handlers logs the error and
        /// stops the actor.
        type Error: Debug + Display + Send + 'static;

        /// Snapshot type used by concurrent read-only ingress handlers.
        ///
        /// Must be cheap to create and clone because the service captures or
        /// clones one snapshot for each read-only message.
        type Snapshot: Clone + Send + 'static;

        /// Data provided to the service on start up.
        ///
        /// Use `()` for actors that do not need external start-up data.
        /// Actors with non-unit `Args` must be started via
        /// [`service::Reliable::start_with`].
        type Args: Send + 'static;

        /// Maximum number of messages to process from a winning lane in one
        /// iteration.
        ///
        /// After the loop receives a mailbox event from a lane, it may
        /// non-blockingly drain additional ready messages from that same lane
        /// until this cap is reached.
        ///
        /// Tradeoff:
        /// - lower values improve fairness across lanes and reduce tail
        ///   latency for events waiting on other lanes.
        /// - higher values improve throughput by reducing loop overhead and
        ///   enabling batching on hot lanes.
        ///
        /// Raising this value can temporarily starve colder lanes and delay
        /// processing of actor-owned sources while a hot lane is being drained.
        /// [`Actor::next_event`] chooses the first event in an iteration; batch
        /// draining does not re-enter that selection until the batch ends.
        ///
        /// A batch does not always reach this cap. It ends early when the
        /// lane has no ready message or when the read-only concurrency limit
        /// fills; remaining lane messages wait for a later iteration and can
        /// lose the next [`Actor::next_event`] selection to another source.
        /// A read-write message inside a batch is also not free: under
        /// [`service::FenceMode::Linearizable`] it drains every in-flight
        /// read-only handler before running, so a batch mixing reads and
        /// writes re-serializes at each write instead of streaming through.
        ///
        /// The default is `1`, which preserves single-message iteration
        /// behavior.
        fn max_lane_batch(&self, _args: &Self::Args) -> NonZeroUsize {
            NonZeroUsize::MIN
        }

        /// Create a snapshot for handling read-only ingress concurrently.
        ///
        /// The service loop captures a snapshot when a read-only message is
        /// admitted, then executes [`Actor::on_read_only`] on a read worker.
        /// Consecutive read-only messages admitted without an intervening
        /// `&mut self` hook share one snapshot: the service calls this once
        /// and clones the result for the rest of the run.
        ///
        /// This must be cheap to create and clone. Prefer `Arc`-backed
        /// structures or `Copy` types. Avoid copying large data structures.
        fn snapshot(&self, args: &Self::Args) -> Self::Snapshot;

        /// Runs once when the control loop starts.
        ///
        /// `args` carries externally-provided data that the actor needs
        /// before processing messages (e.g., connection handles, peer
        /// identity).
        fn on_startup(
            &mut self,
            _context: &mut E,
            _args: &mut Self::Args,
        ) -> impl Future<Output = ()> + Send {
            async {}
        }

        /// Runs once when the control loop stops gracefully.
        ///
        /// Called on: runtime shutdown signal, [`service::Event::Stop`], or
        /// after a fatal handler error from [`Actor::on_read_only`] or
        /// [`Actor::on_read_write`]. In-flight read-only handlers are
        /// aborted before this hook runs, so no read-only handler executes
        /// concurrently with it or responds after it.
        fn on_shutdown(
            &mut self,
            _context: &mut E,
            _args: &mut Self::Args,
        ) -> impl Future<Output = ()> + Send {
            async {}
        }

        /// Runs at the beginning of each iteration, before polling for events.
        ///
        /// Use this for periodic housekeeping that should run every loop
        /// iteration regardless of which event fires (e.g., cleaning stale
        /// subscriptions, refreshing state).
        ///
        /// Iterations are not one-to-one with dispatched messages. An
        /// iteration also occurs when a read-only handler retires, when
        /// [`Actor::next_event`] returns [`service::Event::Continue`], and
        /// each time the loop re-checks read capacity, so `preprocess` can
        /// run many times between two dispatched messages and is not paired
        /// with [`Actor::postprocess`]. Keep it cheap and do not treat a
        /// call as evidence that a message was processed.
        fn preprocess(
            &mut self,
            _context: &mut E,
            _args: &mut Self::Args,
        ) -> impl Future<Output = ()> + Send {
            async {}
        }

        /// Runs at the end of each iteration that dispatched ingress.
        ///
        /// Only called when at least one message was dispatched in the
        /// iteration, from a lane or as [`service::Event::External`]. Skipped
        /// when the loop merely waited for read capacity, retired a read-only
        /// handler, or observed [`service::Event::Continue`], so it is not
        /// paired with [`Actor::preprocess`], which runs on every iteration.
        /// When a lane batch is enabled via [`Actor::max_lane_batch`],
        /// `postprocess` runs once after the full batch completes.
        fn postprocess(
            &mut self,
            _context: &mut E,
            _args: &mut Self::Args,
        ) -> impl Future<Output = ()> + Send {
            async {}
        }

        /// Handle one read-only ingress message.
        ///
        /// Read-only handlers execute concurrently on read workers, receive
        /// only the captured `snapshot`, and must not mutate actor state. The
        /// `context` parameter is a child of the actor's runtime context,
        /// suitable for spawning sub-tasks, accessing metrics, etc.
        ///
        /// Returning `Err` is fatal: the service loop logs the error and
        /// calls [`Actor::on_shutdown`] before exiting. Other in-flight
        /// reads are aborted before [`Actor::on_shutdown`] runs.
        ///
        /// Do not send ingress to the same actor from a read-only handler.
        /// Read-write handlers fence behind earlier reads, so a read-only
        /// handler waiting on its own actor can deadlock the service.
        fn on_read_only(
            _context: E,
            _snapshot: Self::Snapshot,
            _message: <Self::Ingress as ingress::IntoEnvelope>::ReadOnlyMessage,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send {
            async {
                panic!(
                    "Actor::on_read_only must be implemented when read-only ingress is dispatched"
                )
            }
        }

        /// Handle one ingress message that may mutate actor state.
        ///
        /// Read-write handlers execute serially on the actor loop. Under the
        /// default [`service::FenceMode::Linearizable`], they are fenced
        /// behind in-flight read-only handlers that were dispatched before
        /// the write arrived; reads dispatched after are not waited on. Under
        /// [`service::FenceMode::Snapshot`], they run immediately,
        /// concurrently with in-flight reads.
        ///
        /// Returning `Err` is fatal: the service loop logs the error and
        /// calls [`Actor::on_shutdown`] before exiting.
        fn on_read_write(
            &mut self,
            _context: &mut E,
            _args: &mut Self::Args,
            _message: <Self::Ingress as ingress::IntoEnvelope>::ReadWriteMessage,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send {
            async {
                panic!(
                    "Actor::on_read_write must be implemented when read-write ingress is dispatched"
                )
            }
        }

        /// Select the next event for one service-loop iteration.
        ///
        /// The default implementation serves lanes only and stops when a
        /// lane closes. Override this to race self-owned sources directly
        /// against [`service::LaneSet::recv`]. The order of arms in
        /// `commonware_macros::select!` is the actor's priority order, so
        /// actors can place internal sources before lanes and lower-priority
        /// sources after lanes without boxing futures or registering sources
        /// with the driver.
        ///
        /// Source exhaustion policy belongs in the select arm that observed
        /// it. For example, a closed peer receiver can set a flag and return
        /// [`service::Event::Continue`] so future iterations replace only
        /// that arm with [`commonware_utils::futures::OptionFuture`], while a
        /// closed task handle can return [`service::Event::Stop`]. Always mute
        /// an immediately-ready source before returning
        /// [`service::Event::Continue`], or the service loop will keep
        /// selecting it. If every source has closed, return
        /// [`service::Event::Stop`]; [`service::LaneSet::recv`] never resolves
        /// once every lane has closed.
        ///
        /// This future is short-lived: it is rebuilt after every selected
        /// event and after read-only handlers retire. Relative timers such as
        /// `context.sleep(interval)` restart each time and can starve under
        /// steady mailbox or read-only traffic. Store an absolute deadline in
        /// `self` or `args`, then await `sleep_until`.
        ///
        /// If a non-replayable source such as [`service::LaneSet::recv`] wins,
        /// return the selected [`service::Event`] without awaiting again. Any
        /// `.await` after receiving from such a source creates a cancellation
        /// point where the consumed message or one-shot closure event can be
        /// lost if shutdown or a read-only handler retirement wins the driver
        /// race.
        ///
        /// When the read-only concurrency limit is full, the service waits for
        /// read capacity before calling `next_event` again. Actor-owned sources
        /// are not polled during that wait.
        ///
        /// # Cancellation safety
        ///
        /// This future is dropped and recreated whenever runtime shutdown or
        /// a read-handler completion wins the race. Implementations must be
        /// **cancellation-safe**: any work done before an internal `.await`
        /// point may be lost if the future is cancelled at that point. Hold
        /// intermediate state in `self` or `args` rather than in local
        /// variables across `.await` boundaries.
        ///
        /// Cancellation does not roll anything back: mutations made through
        /// `self` or `args` before the cancellation point persist and are
        /// observed by every later hook. A cancelled `next_event` that
        /// dequeued from an internal source and then awaited something else
        /// loses that item unless it was stashed in `self` or `args` first.
        fn next_event<R>(
            &mut self,
            _context: &mut E,
            _args: &mut Self::Args,
            mut lanes: service::LaneSet<'_, Self::Ingress, R>,
        ) -> impl Future<
            Output = service::Event<
                Self::Ingress,
                <Self::Ingress as ingress::IntoEnvelope>::ReadWriteMessage,
            >,
        > + Send
        where
            R: service::LaneReceiver<Self::Ingress>,
        {
            async move {
                match lanes.recv().await {
                    service::LaneEvent::Message { lane, message } => {
                        service::Event::Ingress { lane, message }
                    }
                    service::LaneEvent::Closed { .. } => service::Event::Stop,
                }
            }
        }
    }
});
