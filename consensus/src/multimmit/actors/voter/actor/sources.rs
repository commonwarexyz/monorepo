//! Selection of the next runtime input the voter admits into the core.
//!
//! Every input the voter waits on is polled through [`Live::poll_arm`] or a deadline check. Two
//! walks order the polls:
//!
//! - The ready scan visits the [`Source`]s in rotation, starting after the last one serviced, and
//!   rotates within the completion and timer sources the same way. It probes with [`Probe::Now`]
//!   and never waits.
//! - The blocking wait polls every enabled input in a fixed priority order and sleeps until one
//!   is ready. It runs only when the scan found nothing and the core has no runnable work.

use super::{
    ChainUpdate, DigestOf, Finished, VoterTypes,
    app::AppResult,
    crypto::CryptoResult,
    live::{Live, PendingInspection},
    timers::TimerKind,
};
use crate::multimmit::{
    actors::voter::{
        mailbox::{Completed, Message, Observed, Query},
        persistence::{self, Output},
    },
    machine::{IdentifiedArtifact, Lane},
};
use commonware_actor::mailbox::{self, Policy, UnreliablePolicy};
use commonware_cryptography::{Digest, PublicKey, bls12381::primitives::variant::Variant};
use commonware_p2p::Sender;
use commonware_runtime::Clock as _;
use futures::{FutureExt as _, future::poll_fn, task::noop_waker_ref};
use std::{
    future::Future,
    pin::{Pin, pin},
    task::{Context, Poll, ready},
    time::SystemTime,
};
use tracing::Span;

/// A runtime input the voter rotates over when several are ready.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Source {
    Persistence,
    Completion,
    Timer,
    Resolution,
    Observation,
    Publication,
    Heartbeat,
    Inspection,
}

impl Source {
    pub(crate) const COUNT: usize = 8;
    pub(crate) const ALL: [Self; Self::COUNT] = [
        Self::Persistence,
        Self::Completion,
        Self::Timer,
        Self::Resolution,
        Self::Observation,
        Self::Publication,
        Self::Heartbeat,
        Self::Inspection,
    ];

    /// Returns the core lane this source feeds, if any.
    pub(crate) const fn lane(self) -> Option<Lane> {
        match self {
            Self::Persistence => Some(Lane::PersistenceCompletion),
            Self::Completion => Some(Lane::LocalCompletion),
            Self::Timer => Some(Lane::Timer),
            Self::Resolution => Some(Lane::ResolverResult),
            Self::Observation => Some(Lane::PeerObservation),
            Self::Publication | Self::Heartbeat | Self::Inspection => None,
        }
    }

    /// Returns the source after this one in rotation order.
    const fn next(self) -> Self {
        Self::ALL[(self as usize + 1) % Self::COUNT]
    }
}

/// Which sources may be admitted in one arbitration pass.
#[derive(Clone, Copy)]
pub(crate) struct Gates(pub(crate) [bool; Source::COUNT]);

impl Gates {
    /// Returns whether `source` is admitted and does not feed the `excluded` lane.
    pub(crate) fn allows(self, source: Source, excluded: Option<Lane>) -> bool {
        self.0[source as usize] && (excluded.is_none() || source.lane() != excluded)
    }
}

/// A completion input, in rotation order within [`Source::Completion`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompletionArm {
    Verification,
    Application,
    Crypto,
    ChainTask,
}

impl CompletionArm {
    const ALL: [Self; 4] = [
        Self::Verification,
        Self::Application,
        Self::Crypto,
        Self::ChainTask,
    ];

    /// Returns the rotation index of the completion input after this one.
    const fn next_index(self) -> usize {
        (self as usize + 1) % Self::ALL.len()
    }

    const fn arm(self) -> Arm {
        match self {
            Self::Verification => Arm::Verification,
            Self::Application => Arm::Application,
            Self::Crypto => Arm::Crypto,
            Self::ChainTask => Arm::ChainTask,
        }
    }
}

/// Where the next ready scan starts, within and across sources.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ReadinessCursor {
    source: usize,
    completion: usize,
    timer: usize,
}

impl ReadinessCursor {
    /// Returns a cursor whose next scan starts at `source`.
    #[cfg(test)]
    pub(crate) const fn at(source: Source) -> Self {
        Self {
            source: source as usize,
            completion: 0,
            timer: 0,
        }
    }

    /// Returns a cursor at `source` with the inner rotations at `completion` and `timer`.
    #[cfg(test)]
    pub(crate) const fn at_rotation(source: Source, completion: usize, timer: usize) -> Self {
        Self {
            source: source as usize,
            completion,
            timer,
        }
    }

    /// Returns the sources in scan order.
    fn sources(&self) -> impl Iterator<Item = Source> + use<> {
        let start = self.source;
        (0..Source::COUNT).map(move |offset| Source::ALL[(start + offset) % Source::COUNT])
    }

    /// Returns the completion inputs in scan order.
    fn completions(&self) -> impl Iterator<Item = CompletionArm> + use<> {
        let start = self.completion;
        (0..CompletionArm::ALL.len())
            .map(move |offset| CompletionArm::ALL[(start + offset) % CompletionArm::ALL.len()])
    }

    /// Returns the timers in scan order.
    fn timers(&self) -> impl Iterator<Item = TimerKind> + use<> {
        let start = self.timer;
        (0..TimerKind::ALL.len())
            .map(move |offset| TimerKind::ALL[(start + offset) % TimerKind::ALL.len()])
    }

    /// Moves the scan start past `event`'s input and, for a rotating source, past `source`.
    pub(crate) const fn record<P: PublicKey, V: Variant, D: Digest>(
        &mut self,
        source: Option<Source>,
        event: &RuntimeEvent<P, V, D>,
    ) {
        match event {
            // Checkpoint progress, like other housekeeping, leaves the rotation where it was.
            RuntimeEvent::Persistence(output) if !matches!(output, Output::Durable(_)) => return,
            RuntimeEvent::Verification(_) => {
                self.completion = CompletionArm::Verification.next_index();
            }
            RuntimeEvent::Application(_) => {
                self.completion = CompletionArm::Application.next_index();
            }
            RuntimeEvent::Crypto(_) => self.completion = CompletionArm::Crypto.next_index(),
            RuntimeEvent::ChainTask(_) => self.completion = CompletionArm::ChainTask.next_index(),
            RuntimeEvent::ViewTimer => self.timer = TimerKind::View.next_index(),
            RuntimeEvent::ProductionTimer => self.timer = TimerKind::Production.next_index(),
            _ => {}
        }
        if let Some(source) = source {
            self.advance_past(source);
        }
    }

    /// Starts the next scan at the source after `source`.
    pub(crate) const fn advance_past(&mut self, source: Source) {
        self.source = source.next() as usize;
    }
}

/// An input whose readiness is polled the same way by the scan and the wait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Arm {
    Persistence,
    Application,
    Crypto,
    ChainTask,
    Verification,
    Resolution,
    Inspection,
    Observation,
}

/// One ready runtime input, before it is admitted to the core.
pub(crate) enum RuntimeEvent<P: PublicKey, V: Variant, D: Digest> {
    Persistence(Output<V, D>),
    /// A persistence command slot freed, or the persistence actor closed.
    PersistenceCapacity(Result<(), persistence::Error>),
    Application(Finished<AppResult<D>>),
    Crypto(Finished<CryptoResult<V, D>>),
    ChainTask(ChainUpdate<V, D>),
    ViewTimer,
    ProductionTimer,
    Publication,
    Heartbeat,
    Verification(Completed<V, D>),
    Resolution(Message<V, D>),
    Inspection(Query<D>),
    Observation(ObservedBatch<P, V, D>),
    InputClosed,
}

impl<P: PublicKey, V: Variant, D: Digest> RuntimeEvent<P, V, D> {
    /// Returns the core lane this event feeds, if any.
    pub(crate) const fn core_lane(&self) -> Option<Lane> {
        match self {
            Self::Persistence(Output::Durable(_)) => Some(Lane::PersistenceCompletion),
            Self::Application(_) | Self::Crypto(_) | Self::Verification(_) | Self::ChainTask(_) => {
                Some(Lane::LocalCompletion)
            }
            Self::ViewTimer | Self::ProductionTimer => Some(Lane::Timer),
            Self::Resolution(_) => Some(Lane::ResolverResult),
            Self::Observation(_) => Some(Lane::PeerObservation),
            Self::Persistence(_)
            | Self::PersistenceCapacity(_)
            | Self::Publication
            | Self::Heartbeat
            | Self::Inspection(_)
            | Self::InputClosed => None,
        }
    }
}

/// Adjacent observation cohorts from the same verification pool merged into one machine step.
///
/// Draining queued cohorts together does not wait for new arrivals and lets one machine step
/// and verification batch cover work that accumulated while the voter was busy.
/// View-critical batches retain the ingress actor's small artifact bound. Whole cohorts stay
/// intact, including indivisible parent-and-proposal groups.
pub(crate) struct ObservedBatch<P: PublicKey, V: Variant, D: Digest> {
    pub(crate) artifacts: Vec<(P, IdentifiedArtifact<V, D>)>,
    pub(crate) spans: Vec<Span>,
    pub(crate) cohorts: usize,
    /// The earliest hand-off among the merged cohorts.
    pub(crate) forwarded_at: SystemTime,
    /// The encoded weight of every merged artifact, measured at admission.
    pub(crate) bytes: usize,
}

impl<P: PublicKey, V: Variant, D: Digest> ObservedBatch<P, V, D> {
    /// Merges adjacent compatible cohorts within their item bound, carrying the first incompatible
    /// cohort into the next batch without reordering observations.
    ///
    /// View-critical batches stop at `view_items`. A cohort's plane decides whether it is
    /// view-critical, and only cohorts of equal criticality merge.
    pub(crate) fn drain(
        first: Observed<P, V, D>,
        observations: &mut mailbox::UnreliableReceiver<Observed<P, V, D>>,
        max_items: usize,
        view_items: usize,
    ) -> (Self, Option<Observed<P, V, D>>) {
        let Observed {
            artifacts,
            bytes,
            plane,
            span,
            forwarded_at,
        } = first;
        let mut batch = Self {
            artifacts,
            spans: vec![span],
            cohorts: 1,
            forwarded_at,
            bytes,
        };
        let critical = plane.view_critical();
        let max_items = if critical {
            max_items.min(view_items)
        } else {
            max_items
        };
        while batch.artifacts.len() < max_items {
            let Ok(next) = observations.try_recv() else {
                break;
            };
            if batch.artifacts.len() + next.artifacts.len() > max_items
                || next.plane.view_critical() != critical
            {
                return (batch, Some(next));
            }
            batch.artifacts.extend(next.artifacts);
            batch.spans.push(next.span);
            batch.cohorts += 1;
            batch.forwarded_at = batch.forwarded_at.min(next.forwarded_at);
            batch.bytes = batch.bytes.saturating_add(next.bytes);
        }
        (batch, None)
    }
}

/// Polls an optional future, pending forever when it is absent.
fn poll_optional<F: Future>(future: Pin<&mut Option<F>>, cx: &mut Context<'_>) -> Poll<F::Output> {
    future
        .as_pin_mut()
        .map_or(Poll::Pending, |future| future.poll(cx))
}

/// How [`Live::poll_arm`] treats an input with nothing ready.
pub(crate) enum Probe<'a, 'b> {
    /// Take only what is ready now. Channels are checked without registering the task, and
    /// futures are polled with a no-op waker.
    Now,
    /// Poll with this context, registering the task to wake when the input becomes ready.
    Register(&'a mut Context<'b>),
}

impl Probe<'_, '_> {
    /// Polls `poll` with the registered context, or once with a no-op waker.
    fn poll<R>(&mut self, poll: impl FnOnce(&mut Context<'_>) -> Poll<R>) -> Poll<R> {
        match self {
            Self::Now => poll(&mut Context::from_waker(noop_waker_ref())),
            Self::Register(cx) => poll(cx),
        }
    }

    /// Receives one message; `Ready(None)` means the channel closed, which [`Self::Now`] never
    /// reports.
    fn recv<R: Inbound>(&mut self, receiver: &mut R) -> Poll<Option<R::Item>> {
        match self {
            Self::Now => receiver
                .try_take()
                .map_or(Poll::Pending, |item| Poll::Ready(Some(item))),
            Self::Register(cx) => receiver.poll_take(cx),
        }
    }
}

/// A mailbox receiver the voter polls.
trait Inbound {
    type Item;

    /// Returns a ready message without registering for wakeups.
    fn try_take(&mut self) -> Option<Self::Item>;

    /// Polls for a message, returning `Ready(None)` once the channel closed.
    fn poll_take(&mut self, cx: &mut Context<'_>) -> Poll<Option<Self::Item>>;
}

impl<T: Policy> Inbound for mailbox::Receiver<T> {
    type Item = T;

    fn try_take(&mut self) -> Option<T> {
        self.try_recv().ok()
    }

    fn poll_take(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        pin!(self.recv()).poll(cx)
    }
}

impl<T: UnreliablePolicy> Inbound for mailbox::UnreliableReceiver<T> {
    type Item = T;

    fn try_take(&mut self) -> Option<T> {
        self.try_recv().ok()
    }

    fn poll_take(&mut self, cx: &mut Context<'_>) -> Poll<Option<T>> {
        pin!(self.recv()).poll(cx)
    }
}

impl<T, S> Live<T, S>
where
    T: VoterTypes,
    S: Sender<PublicKey = T::PublicKey>,
{
    /// Captures which sources the core can admit right now.
    pub(crate) fn gates(&self) -> Gates {
        let authority = !self.persistence.ledger().fenced();
        let mut gates = [true; Source::COUNT];
        gates[Source::Persistence as usize] = self.persistence_receivable();
        gates[Source::Completion as usize] = self.machine.can_admit(Lane::LocalCompletion);
        gates[Source::Timer as usize] = authority && self.machine.can_admit(Lane::Timer);
        gates[Source::Resolution as usize] =
            authority && self.machine.can_admit(Lane::ResolverResult);
        gates[Source::Observation as usize] =
            authority && self.machine.can_admit(Lane::PeerObservation);
        gates[Source::Inspection as usize] =
            !self.machine.has_runnable_work() && self.pending_inspection.is_none();
        Gates(gates)
    }

    /// Returns the next input to admit, or `None` when the core should run first.
    ///
    /// A deferred inspection yields to at most one input that is already ready and is answered
    /// on the following call.
    pub(crate) async fn next_event(
        &mut self,
        cursor: &mut ReadinessCursor,
    ) -> Option<RuntimeEvent<T::PublicKey, T::Variant, DigestOf<T>>> {
        if self.pending_inspection.is_some() {
            // The inspection stays pending during the scan, which keeps the query source closed.
            if matches!(
                self.pending_inspection,
                Some(PendingInspection::Deferred(_))
            ) && let Some(event) = self.scan(cursor, None)
            {
                if let Some(PendingInspection::Deferred(query)) = self.pending_inspection.take() {
                    self.pending_inspection = Some(PendingInspection::Due(query));
                }
                return Some(event);
            }
            if let Some(PendingInspection::Deferred(query) | PendingInspection::Due(query)) =
                self.pending_inspection.take()
            {
                self.answer_inspection(query);
            }
            return None;
        }
        if let Some(event) = self.scan(cursor, None) {
            return Some(event);
        }
        if self.machine.has_runnable_work() && self.persistence.has_capacity() {
            return None;
        }
        Some(self.wait(cursor).await)
    }

    /// Returns the first ready input without waiting, rotating from `cursor`.
    ///
    /// Sources that feed the `excluded` lane are skipped.
    pub(crate) fn scan(
        &mut self,
        cursor: &mut ReadinessCursor,
        excluded: Option<Lane>,
    ) -> Option<RuntimeEvent<T::PublicKey, T::Variant, DigestOf<T>>> {
        if !self.persistence.has_capacity()
            && let Some(result) = self
                .persistence
                .mailbox()
                .wait_for_capacity()
                .now_or_never()
        {
            return Some(RuntimeEvent::PersistenceCapacity(result));
        }
        let gates = self.gates();
        let now = self.context.current();
        for source in cursor.sources() {
            if !gates.allows(source, excluded) {
                continue;
            }
            let event = match source {
                Source::Persistence => self.poll_arm(Arm::Persistence, &mut Probe::Now),
                Source::Completion => cursor
                    .completions()
                    .find_map(|arm| match self.poll_arm(arm.arm(), &mut Probe::Now) {
                        Poll::Ready(event) => Some(event),
                        Poll::Pending => None,
                    })
                    .map_or(Poll::Pending, Poll::Ready),
                Source::Timer => cursor
                    .timers()
                    .find(|&kind| self.timers.due(kind, now))
                    .map_or(Poll::Pending, |kind| {
                        Poll::Ready(match kind {
                            TimerKind::View => RuntimeEvent::ViewTimer,
                            TimerKind::Production => RuntimeEvent::ProductionTimer,
                        })
                    }),
                Source::Resolution => self.poll_arm(Arm::Resolution, &mut Probe::Now),
                Source::Observation => self.poll_arm(Arm::Observation, &mut Probe::Now),
                Source::Publication => {
                    if self.egress.next_attempt().is_some_and(|at| at <= now) {
                        Poll::Ready(RuntimeEvent::Publication)
                    } else {
                        Poll::Pending
                    }
                }
                Source::Heartbeat => {
                    if self.timers.heartbeat_at() <= now {
                        Poll::Ready(RuntimeEvent::Heartbeat)
                    } else {
                        Poll::Pending
                    }
                }
                Source::Inspection => self.poll_arm(Arm::Inspection, &mut Probe::Now),
            };
            if let Poll::Ready(event) = event {
                cursor.record(Some(source), &event);
                return Some(event);
            }
        }
        None
    }

    /// Waits for the first enabled input to become ready.
    ///
    /// Inputs are polled in a fixed priority order: persistence results and command capacity,
    /// application, cryptographic, and DA task completions, timers, publication retries, the
    /// heartbeat, verification completions, resolutions, inspections, and observations.
    pub(super) async fn wait(
        &mut self,
        cursor: &mut ReadinessCursor,
    ) -> RuntimeEvent<T::PublicKey, T::Variant, DigestOf<T>> {
        let gates = self.gates();
        // A fenced voter cannot rely on new ingress to fill a quiet journal prefix.
        if self.persistence.ledger().fenced()
            && self.persistence.ledger().outstanding() > 0
            && let Err(error) = self.persistence.flush()
        {
            return RuntimeEvent::PersistenceCapacity(Err(error));
        }
        let mut capacity = pin!((!self.persistence.has_capacity()).then(|| {
            let mailbox = self.persistence.mailbox().clone();
            async move { mailbox.wait_for_capacity().await }
        }));
        let timers = gates.allows(Source::Timer, None);
        let sleep = |deadline: Option<SystemTime>| deadline.map(|at| self.context.sleep_until(at));
        let mut view = pin!(sleep(
            timers
                .then(|| self.timers.deadline(TimerKind::View))
                .flatten()
        ));
        let mut production = pin!(sleep(
            timers
                .then(|| self.timers.deadline(TimerKind::Production))
                .flatten()
        ));
        let mut publication = pin!(sleep(self.egress.next_attempt()));
        let mut heartbeat = pin!(sleep(Some(self.timers.heartbeat_at())));
        let (source, event) = poll_fn(|cx| {
            if gates.allows(Source::Persistence, None)
                && let Poll::Ready(event) =
                    self.poll_arm(Arm::Persistence, &mut Probe::Register(cx))
            {
                return Poll::Ready((Some(Source::Persistence), event));
            }
            if let Poll::Ready(result) = poll_optional(capacity.as_mut(), cx) {
                return Poll::Ready((None, RuntimeEvent::PersistenceCapacity(result)));
            }
            if gates.allows(Source::Completion, None) {
                for arm in [Arm::Application, Arm::Crypto, Arm::ChainTask] {
                    if let Poll::Ready(event) = self.poll_arm(arm, &mut Probe::Register(cx)) {
                        return Poll::Ready((Some(Source::Completion), event));
                    }
                }
            }
            if poll_optional(view.as_mut(), cx).is_ready() {
                return Poll::Ready((Some(Source::Timer), RuntimeEvent::ViewTimer));
            }
            if poll_optional(production.as_mut(), cx).is_ready() {
                return Poll::Ready((Some(Source::Timer), RuntimeEvent::ProductionTimer));
            }
            if poll_optional(publication.as_mut(), cx).is_ready() {
                return Poll::Ready((Some(Source::Publication), RuntimeEvent::Publication));
            }
            if poll_optional(heartbeat.as_mut(), cx).is_ready() {
                return Poll::Ready((Some(Source::Heartbeat), RuntimeEvent::Heartbeat));
            }
            for (source, arm) in [
                (Source::Completion, Arm::Verification),
                (Source::Resolution, Arm::Resolution),
                (Source::Inspection, Arm::Inspection),
                (Source::Observation, Arm::Observation),
            ] {
                if gates.allows(source, None)
                    && let Poll::Ready(event) = self.poll_arm(arm, &mut Probe::Register(cx))
                {
                    return Poll::Ready((Some(source), event));
                }
            }
            Poll::Pending
        })
        .await;
        cursor.record(source, &event);
        event
    }

    /// Polls one input.
    ///
    /// Under [`Probe::Register`], a closed mandatory input yields [`RuntimeEvent::InputClosed`]
    /// and a closed query queue stays quiet.
    pub(crate) fn poll_arm(
        &mut self,
        arm: Arm,
        probe: &mut Probe<'_, '_>,
    ) -> Poll<RuntimeEvent<T::PublicKey, T::Variant, DigestOf<T>>> {
        match arm {
            Arm::Persistence => probe.recv(self.persistence.output()).map(|output| {
                RuntimeEvent::Persistence(output.unwrap_or_else(|| self.persistence_closed()))
            }),
            Arm::Application => probe
                .poll(|cx| self.app.poll_completed(cx))
                .map(RuntimeEvent::Application),
            Arm::Crypto => probe
                .poll(|cx| self.crypto.poll_completed(cx))
                .map(RuntimeEvent::Crypto),
            Arm::ChainTask => self.chains.updates().map_or(Poll::Pending, |updates| {
                probe
                    .recv(updates)
                    .map(|update| update.map_or(RuntimeEvent::InputClosed, RuntimeEvent::ChainTask))
            }),
            Arm::Verification => probe.recv(&mut self.inbox.completions).map(|completed| {
                completed.map_or(RuntimeEvent::InputClosed, RuntimeEvent::Verification)
            }),
            Arm::Resolution => probe
                .recv(&mut self.inbox.resolutions)
                .map(|message| message.map_or(RuntimeEvent::InputClosed, RuntimeEvent::Resolution)),
            Arm::Inspection => match probe.recv(&mut self.inbox.queries) {
                Poll::Ready(Some(query)) => Poll::Ready(RuntimeEvent::Inspection(query)),
                Poll::Ready(None) | Poll::Pending => Poll::Pending,
            },
            Arm::Observation => {
                let first = match self.carried_observation.take() {
                    Some(first) => first,
                    None => match ready!(probe.recv(&mut self.inbox.observations)) {
                        Some(first) => first,
                        None => return Poll::Ready(RuntimeEvent::InputClosed),
                    },
                };
                let (batch, carried) = ObservedBatch::drain(
                    first,
                    &mut self.inbox.observations,
                    self.observation_batch,
                    self.limits.view_cohort_items.get(),
                );
                self.carried_observation = carried;
                Poll::Ready(RuntimeEvent::Observation(batch))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multimmit::actors::util::reliable_policy;
    use commonware_cryptography::{
        bls12381::primitives::variant::MinPk, ed25519, sha256::Digest as Sha256Digest,
    };
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use futures::task::{ArcWake, waker};
    use std::{
        num::NonZeroUsize,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    type Event = RuntimeEvent<ed25519::PublicKey, MinPk, Sha256Digest>;

    #[derive(Debug, PartialEq, Eq)]
    struct Item(u8);

    reliable_policy!(impl for Item);

    #[derive(Default)]
    struct WakeCounter(AtomicUsize);

    impl ArcWake for WakeCounter {
        fn wake_by_ref(counter: &Arc<Self>) {
            counter.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn probing_now_keeps_the_waiting_task_registered() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, mut receiver) =
                mailbox::new::<Item>(context.child("probe"), NonZeroUsize::new(4).unwrap());
            let woken = Arc::new(WakeCounter::default());
            let waiting = waker(Arc::clone(&woken));
            let mut cx = Context::from_waker(&waiting);
            assert!(Probe::Register(&mut cx).recv(&mut receiver).is_pending());
            assert!(Probe::Now.recv(&mut receiver).is_pending());

            assert!(sender.enqueue(Item(1)).accepted());
            assert_eq!(
                woken.0.load(Ordering::Relaxed),
                1,
                "a ready scan must not replace the waker a wait registered"
            );
            assert_eq!(Probe::Now.recv(&mut receiver), Poll::Ready(Some(Item(1))));

            drop(sender);
            assert!(
                Probe::Now.recv(&mut receiver).is_pending(),
                "a ready scan does not report closure"
            );
            assert_eq!(
                Probe::Register(&mut cx).recv(&mut receiver),
                Poll::Ready(None)
            );
        });
    }

    #[test]
    fn gates_apply_canonical_lane_exclusions() {
        let open = Gates([true; Source::COUNT]);
        for (source, lane) in [
            (Source::Persistence, Lane::PersistenceCompletion),
            (Source::Completion, Lane::LocalCompletion),
            (Source::Timer, Lane::Timer),
            (Source::Resolution, Lane::ResolverResult),
            (Source::Observation, Lane::PeerObservation),
        ] {
            assert!(open.allows(source, None));
            assert!(!open.allows(source, Some(lane)));
        }
        for source in [Source::Publication, Source::Heartbeat, Source::Inspection] {
            assert!(open.allows(source, Some(Lane::Timer)));
        }

        let mut closed = [false; Source::COUNT];
        closed[Source::Publication as usize] = true;
        closed[Source::Heartbeat as usize] = true;
        let closed = Gates(closed);
        for source in [
            Source::Persistence,
            Source::Completion,
            Source::Timer,
            Source::Resolution,
            Source::Observation,
            Source::Inspection,
        ] {
            assert!(!closed.allows(source, None));
        }
        assert!(closed.allows(Source::Publication, None));
        assert!(closed.allows(Source::Heartbeat, None));
    }

    #[test]
    fn cursor_records_source_and_inner_rotation() {
        let mut cursor = ReadinessCursor::default();
        cursor.record(Some(Source::Timer), &Event::ViewTimer);
        assert_eq!(cursor.source, Source::Resolution as usize);
        assert_eq!(cursor.timer, 1);

        cursor.record(Some(Source::Timer), &Event::ProductionTimer);
        assert_eq!(cursor.timer, 0);
        cursor.record(Some(Source::Observation), &Event::InputClosed);
        assert_eq!(cursor.source, Source::Publication as usize);
        cursor.advance_past(Source::Inspection);
        assert_eq!(cursor.source, Source::Persistence as usize);

        // Housekeeping events move neither the source nor the inner cursors.
        cursor.record(None, &Event::Heartbeat);
        assert_eq!(cursor.source, Source::Persistence as usize);

        // Checkpoint progress arrives through the persistence source but, like housekeeping,
        // leaves the rotation where it was.
        cursor.advance_past(Source::Observation);
        for output in [Output::Stored, Output::Pruned] {
            cursor.record(Some(Source::Persistence), &Event::Persistence(output));
            assert_eq!(cursor.source, Source::Publication as usize);
        }
    }

    #[test]
    fn rotation_indices_follow_the_rotation_order() {
        for (index, arm) in CompletionArm::ALL.into_iter().enumerate() {
            assert_eq!(arm as usize, index);
            assert_eq!(arm.next_index(), (index + 1) % CompletionArm::ALL.len());
        }
        for (index, kind) in TimerKind::ALL.into_iter().enumerate() {
            assert_eq!(kind as usize, index);
            assert_eq!(kind.next_index(), (index + 1) % TimerKind::ALL.len());
        }
        for (index, source) in Source::ALL.into_iter().enumerate() {
            assert_eq!(source as usize, index);
        }
    }

    #[test]
    fn scan_order_rotates_from_the_cursor() {
        let mut cursor = ReadinessCursor::at(Source::Observation);
        assert_eq!(
            cursor.sources().collect::<Vec<_>>(),
            [
                Source::Observation,
                Source::Publication,
                Source::Heartbeat,
                Source::Inspection,
                Source::Persistence,
                Source::Completion,
                Source::Timer,
                Source::Resolution,
            ]
        );
        assert_eq!(cursor.completions().collect::<Vec<_>>(), CompletionArm::ALL);
        cursor.completion = 3;
        assert_eq!(
            cursor.completions().collect::<Vec<_>>(),
            [
                CompletionArm::ChainTask,
                CompletionArm::Verification,
                CompletionArm::Application,
                CompletionArm::Crypto,
            ]
        );
        cursor.timer = 1;
        assert_eq!(
            cursor.timers().collect::<Vec<_>>(),
            [TimerKind::Production, TimerKind::View]
        );
    }
}
