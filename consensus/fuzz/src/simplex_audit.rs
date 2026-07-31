//! Fuzz-only observation of Simplex activity and automaton interactions.
//!
//! The production Simplex reporter exports complete protocol activities, but
//! the mock reporter intentionally reduces them to summary maps. This module
//! preserves the existing mock reporter behavior while retaining every
//! activity and every automaton request/result in one per-node append-only log.

use commonware_actor::Feedback;
use commonware_consensus::{
    Automaton, CertifiableAutomaton, Monitor, Reporter as ReporterTrait,
    simplex::{
        elector::Config as ElectorConfig,
        mocks::reporter,
        scheme,
        types::{Activity, Context},
    },
    types::{Round, View},
};
use commonware_cryptography::{Digest, PublicKey, certificate};
use commonware_macros::select;
use commonware_parallel::Sequential;
use commonware_runtime::Spawner;
use commonware_utils::{
    TestRng,
    channel::{fallible::OneshotExt, mpsc::Receiver, oneshot},
    sync::Mutex,
};
use rand_core::CryptoRng;
use std::{hash::Hash, sync::Arc};

/// Completion of an automaton request at the proxy response boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Completion<T> {
    /// The proxy successfully placed the returned value on consensus's response channel.
    Returned(T),
    /// The automaton dropped its response channel while consensus was still waiting.
    Closed,
    /// Consensus dropped its response receiver before the proxy could deliver a value.
    Canceled,
}

/// An automaton interaction observed at the fuzz harness boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AutomatonEvent<D: Digest, P: PublicKey> {
    ProposeRequested {
        context: Context<D, P>,
    },
    ProposeCompleted {
        context: Context<D, P>,
        outcome: Completion<D>,
    },
    VerifyRequested {
        context: Context<D, P>,
        payload: D,
    },
    VerifyCompleted {
        context: Context<D, P>,
        payload: D,
        outcome: Completion<bool>,
    },
    CertifyCompleted {
        round: Round,
        payload: D,
        outcome: Completion<bool>,
    },
}

/// A complete fuzz observation from either the Reporter or automaton boundary.
#[derive(Clone, Debug)]
pub enum Event<S: certificate::Scheme, D: Digest> {
    /// A Simplex activity together with an independent validity result.
    Activity {
        valid: bool,
        activity: Activity<S, D>,
    },
    /// A request to or result from the application automaton.
    Automaton(AutomatonEvent<D, S::PublicKey>),
}

/// One item in a node's append-only audit history.
#[derive(Clone, Debug)]
pub struct RecordedEvent<S: certificate::Scheme, D: Digest> {
    pub sequence: u64,
    pub generation: u32,
    pub event: Event<S, D>,
}

/// Shared append-only history for one validator identity.
pub struct AuditLog<S: certificate::Scheme, D: Digest> {
    observer: S::PublicKey,
    state: Arc<Mutex<AuditState<S, D>>>,
}

struct AuditState<S: certificate::Scheme, D: Digest> {
    generation: u32,
    events: Vec<RecordedEvent<S, D>>,
}

impl<S: certificate::Scheme, D: Digest> Clone for AuditLog<S, D> {
    fn clone(&self) -> Self {
        Self {
            observer: self.observer.clone(),
            state: self.state.clone(),
        }
    }
}

impl<S: certificate::Scheme, D: Digest> AuditLog<S, D> {
    fn new(observer: S::PublicKey, generation: u32) -> Self {
        Self {
            observer,
            state: Arc::new(Mutex::new(AuditState {
                generation,
                events: Vec::new(),
            })),
        }
    }

    /// Validator whose local engine owns this log.
    pub const fn observer(&self) -> &S::PublicKey {
        &self.observer
    }

    /// Selects the incarnation attached to subsequently recorded events.
    pub fn set_generation(&self, generation: u32) {
        self.state.lock().generation = generation;
    }

    /// Returns a stable snapshot in report-call order.
    pub fn events(&self) -> Vec<RecordedEvent<S, D>> {
        self.state.lock().events.clone()
    }

    pub(crate) fn record(&self, event: Event<S, D>) {
        let mut state = self.state.lock();
        let sequence = u64::try_from(state.events.len()).expect("audit history exceeds u64");
        let recorded = RecordedEvent {
            sequence,
            generation: state.generation,
            event,
        };
        state.events.push(recorded);
    }

    /// Checks only append-order metadata. Activity validity is independently
    /// computed when the event is recorded; event content is not validated here.
    fn assert_history_ordering(&self) {
        let mut previous_generation = None;
        for (expected, recorded) in self.events().iter().enumerate() {
            assert_eq!(
                recorded.sequence,
                u64::try_from(expected).expect("audit history exceeds u64"),
                "audit sequence is not append-only"
            );
            if let Some(previous) = previous_generation {
                assert!(
                    recorded.generation >= previous,
                    "audit generation regressed from {previous} to {}",
                    recorded.generation
                );
            }
            previous_generation = Some(recorded.generation);
        }
    }
}

/// Fuzz Reporter that keeps the existing mock summaries and a lossless history.
pub struct RecordingReporter<E, S, L, D>
where
    E: CryptoRng,
    S: certificate::Scheme,
    L: ElectorConfig<S>,
    D: Digest,
{
    inner: reporter::Reporter<E, S, L, D>,
    /// Shared across clones; activity validity is RNG-state-independent, and
    /// this verifier RNG never perturbs the simulated consensus runtime.
    verifier: Arc<Mutex<TestRng>>,
    scheme: S,
    /// Built copy of the configured elector: the inner mock keeps its own
    /// instance private, and the audit invariants need certificate-less
    /// election for views no certificate unlocked (view 1).
    elector: L::Elector,
    audit: AuditLog<S, D>,
}

impl<E, S, L, D> Clone for RecordingReporter<E, S, L, D>
where
    E: CryptoRng,
    S: certificate::Scheme,
    L: ElectorConfig<S>,
    L::Elector: Clone,
    D: Digest,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            verifier: self.verifier.clone(),
            scheme: self.scheme.clone(),
            elector: self.elector.clone(),
            audit: self.audit.clone(),
        }
    }
}

impl<E, S, L, D> RecordingReporter<E, S, L, D>
where
    E: CryptoRng,
    S: certificate::Scheme,
    L: ElectorConfig<S> + Clone,
    D: Digest + Eq + Hash + Clone,
{
    /// Creates a recording layer over the existing mock Reporter.
    pub fn new(
        context: E,
        observer: S::PublicKey,
        generation: u32,
        config: reporter::Config<S, L>,
    ) -> Self {
        Self {
            scheme: config.scheme.clone(),
            elector: config.elector.clone().build(&config.participants),
            inner: reporter::Reporter::new(context, config),
            verifier: Arc::new(Mutex::new(TestRng::new(0))),
            audit: AuditLog::new(observer, generation),
        }
    }
}

impl<E, S, L, D> RecordingReporter<E, S, L, D>
where
    E: CryptoRng,
    S: certificate::Scheme,
    L: ElectorConfig<S>,
    D: Digest + Eq + Hash + Clone,
{
    /// Built copy of the configured elector.
    pub(crate) const fn elector(&self) -> &L::Elector {
        &self.elector
    }

    /// Existing mock Reporter used by legacy summaries and invariants.
    pub const fn inner(&self) -> &reporter::Reporter<E, S, L, D> {
        &self.inner
    }

    /// Shared event history used by the Reporter and automaton decorator.
    pub fn audit(&self) -> AuditLog<S, D> {
        self.audit.clone()
    }

    /// Selects the incarnation attached to subsequently recorded events.
    pub fn set_generation(&self, generation: u32) {
        self.audit.set_generation(generation);
    }
}

/// Clones the Arc-backed summary reporters expected by existing invariants.
pub fn summaries<E, S, L, D>(
    reporters: &[RecordingReporter<E, S, L, D>],
) -> Vec<reporter::Reporter<E, S, L, D>>
where
    E: CryptoRng,
    S: certificate::Scheme,
    L: ElectorConfig<S>,
    L::Elector: Clone,
    D: Digest + Eq + Hash + Clone,
{
    for reporter in reporters {
        reporter.audit.assert_history_ordering();
    }
    reporters
        .iter()
        .map(|reporter| reporter.inner().clone())
        .collect()
}

impl<E, S, L, D> ReporterTrait for RecordingReporter<E, S, L, D>
where
    E: CryptoRng + Send + Sync + 'static,
    S: scheme::Scheme<D>,
    L: ElectorConfig<S>,
    D: Digest + Eq + Hash + Clone,
{
    type Activity = Activity<S, D>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        // Use a dedicated deterministic verifier so recording cannot consume
        // randomness from the simulated consensus runtime.
        let valid = activity.verify(&mut *self.verifier.lock(), &self.scheme, &Sequential);
        self.audit.record(Event::Activity {
            valid,
            activity: activity.clone(),
        });
        self.inner.report(activity)
    }
}

impl<E, S, L, D> Monitor for RecordingReporter<E, S, L, D>
where
    E: CryptoRng + Send + Sync + 'static,
    S: certificate::Scheme,
    L: ElectorConfig<S>,
    D: Digest + Eq + Hash + Clone,
{
    type Index = View;

    async fn subscribe(&mut self) -> (Self::Index, Receiver<Self::Index>) {
        self.inner.subscribe().await
    }
}

/// Automaton decorator that records requests and their delivered outcomes.
pub struct RecordingAutomaton<E, A, S, D>
where
    S: certificate::Scheme,
    D: Digest,
{
    context: Arc<Mutex<E>>,
    inner: A,
    audit: AuditLog<S, D>,
}

impl<E, A, S, D> Clone for RecordingAutomaton<E, A, S, D>
where
    A: Clone,
    S: certificate::Scheme,
    D: Digest,
{
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
            inner: self.inner.clone(),
            audit: self.audit.clone(),
        }
    }
}

impl<E, A, S, D> RecordingAutomaton<E, A, S, D>
where
    E: Spawner,
    A: CertifiableAutomaton<Context = Context<D, S::PublicKey>, Digest = D>,
    S: certificate::Scheme,
    D: Digest,
{
    pub fn new(context: E, inner: A, audit: AuditLog<S, D>) -> Self {
        Self {
            context: Arc::new(Mutex::new(context)),
            inner,
            audit,
        }
    }

    fn proxy<T, F>(&self, receiver: oneshot::Receiver<T>, completed: F) -> oneshot::Receiver<T>
    where
        T: Clone + Send + 'static,
        F: FnOnce(Completion<T>) -> AutomatonEvent<D, S::PublicKey> + Send + 'static,
        S: 'static,
        D: 'static,
    {
        let (mut sender, output) = oneshot::channel();
        let audit = self.audit.clone();
        self.context
            .lock()
            .child("automaton_response")
            .spawn(move |_| async move {
                select! {
                    result = receiver => {
                        match result {
                            Ok(value) => {
                                let completion = if sender.send_lossy(value.clone()) {
                                    Completion::Returned(value)
                                } else {
                                    Completion::Canceled
                                };
                                audit.record(Event::Automaton(completed(completion)));
                            }
                            Err(_) => {
                                let completion = if sender.is_closed() {
                                    Completion::Canceled
                                } else {
                                    Completion::Closed
                                };
                                audit.record(Event::Automaton(completed(completion)));
                            }
                        }
                    },
                    _ = sender.closed() => {
                        audit.record(Event::Automaton(completed(Completion::Canceled)));
                    },
                }
            });
        output
    }
}

impl<E, A, S, D> Automaton for RecordingAutomaton<E, A, S, D>
where
    E: Spawner,
    A: CertifiableAutomaton<Context = Context<D, S::PublicKey>, Digest = D>,
    S: certificate::Scheme + 'static,
    D: Digest + 'static,
{
    type Context = Context<D, S::PublicKey>;
    type Digest = D;

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        self.audit
            .record(Event::Automaton(AutomatonEvent::ProposeRequested {
                context: context.clone(),
            }));
        let completion_context = context.clone();
        let receiver = self.inner.propose(context).await;
        self.proxy(receiver, move |outcome| AutomatonEvent::ProposeCompleted {
            context: completion_context,
            outcome,
        })
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        self.audit
            .record(Event::Automaton(AutomatonEvent::VerifyRequested {
                context: context.clone(),
                payload,
            }));
        let completion_context = context.clone();
        let receiver = self.inner.verify(context, payload).await;
        self.proxy(receiver, move |outcome| AutomatonEvent::VerifyCompleted {
            context: completion_context,
            payload,
            outcome,
        })
    }
}

impl<E, A, S, D> CertifiableAutomaton for RecordingAutomaton<E, A, S, D>
where
    E: Spawner,
    A: CertifiableAutomaton<Context = Context<D, S::PublicKey>, Digest = D>,
    S: certificate::Scheme + 'static,
    D: Digest + 'static,
{
    async fn certify(&mut self, round: Round, payload: Self::Digest) -> oneshot::Receiver<bool> {
        let receiver = self.inner.certify(round, payload).await;
        self.proxy(receiver, move |outcome| AutomatonEvent::CertifyCompleted {
            round,
            payload,
            outcome,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id_mock;
    use commonware_consensus::{
        simplex::{
            elector::RoundRobin,
            mocks::reporter::Config as ReporterConfig,
            types::{Notarization, Notarize, Proposal},
        },
        types::Epoch,
    };
    use commonware_cryptography::sha256::Digest as Sha256Digest;
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::{ordered::Set, test_rng};

    const N: u32 = 4;
    const QUORUM: usize = 3;

    type TestReporter = RecordingReporter<TestRng, id_mock::Scheme, RoundRobin, Sha256Digest>;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest([byte; 32])
    }

    fn round(view: u64) -> Round {
        Round::new(Epoch::new(0), View::new(view))
    }

    fn recording_reporter() -> (TestReporter, Vec<id_mock::PublicKey>, Vec<id_mock::Scheme>) {
        let (participants, schemes) = id_mock::fixture(&mut test_rng(), b"simplex-audit-tests", N);
        let reporter = RecordingReporter::new(
            test_rng(),
            participants[0].clone(),
            0,
            ReporterConfig {
                participants: Set::try_from(participants.clone()).expect("unique keys"),
                scheme: schemes[0].clone(),
                elector: RoundRobin::default(),
            },
        );
        (reporter, participants, schemes)
    }

    #[test]
    fn reporter_retains_full_ordered_activity_history_across_generations() {
        let (mut reporter, _, schemes) = recording_reporter();
        let payload = digest(0xA);
        let proposal_a = Proposal::new(round(5), View::new(1), payload);
        let proposal_b = Proposal::new(round(5), View::new(2), payload);

        reporter.report(Activity::Notarize(
            Notarize::sign(&schemes[0], proposal_a.clone()).unwrap(),
        ));
        reporter.report(Activity::Notarize(
            Notarize::sign(&schemes[0], proposal_b.clone()).unwrap(),
        ));

        let votes: Vec<_> = schemes[..QUORUM]
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal_a.clone()).unwrap())
            .collect();
        let notarization = Notarization::from_notarizes(&schemes[0], &votes, &Sequential).unwrap();
        reporter.report(Activity::Notarization(notarization.clone()));

        reporter.set_generation(1);
        reporter.report(Activity::Certification(notarization));

        // The legacy Reporter intentionally summarizes votes by (view, payload),
        // so these two full proposals occupy one summary bucket.
        let summarized = reporter.inner().notarizes.lock();
        let signers = summarized
            .get(&View::new(5))
            .and_then(|payloads| payloads.get(&payload))
            .expect("summarized vote");
        assert_eq!(signers.len(), 1);
        drop(summarized);

        let events = reporter.audit().events();
        assert_eq!(events.len(), 4);
        assert_eq!(
            events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            [0, 1, 2, 3]
        );
        assert_eq!(
            events
                .iter()
                .map(|event| event.generation)
                .collect::<Vec<_>>(),
            [0, 0, 0, 1]
        );

        let proposal_at = |index: usize| match &events[index].event {
            Event::Activity {
                valid: true,
                activity: Activity::Notarize(vote),
            } => &vote.proposal,
            event => panic!("unexpected event at {index}: {event:?}"),
        };
        assert_eq!(proposal_at(0), &proposal_a);
        assert_eq!(proposal_at(1), &proposal_b);
        assert!(matches!(
            &events[2].event,
            Event::Activity {
                valid: true,
                activity: Activity::Notarization(_),
            }
        ));
        assert!(matches!(
            &events[3].event,
            Event::Activity {
                valid: true,
                activity: Activity::Certification(_),
            }
        ));

        // Existing invariant inputs remain available through the wrapper.
        assert_eq!(summaries(std::slice::from_ref(&reporter)).len(), 1);
    }

    #[derive(Clone)]
    struct ImmediateAutomaton {
        proposed: Sha256Digest,
    }

    impl Automaton for ImmediateAutomaton {
        type Context = Context<Sha256Digest, id_mock::PublicKey>;
        type Digest = Sha256Digest;

        async fn propose(&mut self, _: Self::Context) -> oneshot::Receiver<Self::Digest> {
            let (sender, receiver) = oneshot::channel();
            sender.send_lossy(self.proposed);
            receiver
        }

        async fn verify(&mut self, _: Self::Context, _: Self::Digest) -> oneshot::Receiver<bool> {
            let (sender, receiver) = oneshot::channel();
            sender.send_lossy(true);
            receiver
        }
    }

    impl CertifiableAutomaton for ImmediateAutomaton {
        async fn certify(&mut self, _: Round, _: Self::Digest) -> oneshot::Receiver<bool> {
            let (sender, receiver) = oneshot::channel();
            sender.send_lossy(false);
            receiver
        }
    }

    #[test]
    fn automaton_records_each_request_and_delivered_outcome() {
        deterministic::Runner::seeded(7).start(|context| async move {
            let (participants, _) =
                id_mock::fixture(&mut test_rng(), b"simplex-audit-automaton", N);
            let audit: AuditLog<id_mock::Scheme, Sha256Digest> =
                AuditLog::new(participants[0].clone(), 7);
            let proposed = digest(0xA);
            let verified = digest(0xB);
            let certified = digest(0xC);
            let request_context = Context {
                round: round(5),
                leader: participants[1].clone(),
                parent: (View::new(3), digest(0xD)),
            };
            let mut automaton =
                RecordingAutomaton::new(context, ImmediateAutomaton { proposed }, audit.clone());

            assert_eq!(
                automaton
                    .propose(request_context.clone())
                    .await
                    .await
                    .unwrap(),
                proposed
            );
            assert!(
                automaton
                    .verify(request_context.clone(), verified)
                    .await
                    .await
                    .unwrap()
            );
            assert!(
                !automaton
                    .certify(request_context.round, certified)
                    .await
                    .await
                    .unwrap()
            );

            let events = audit.events();
            assert_eq!(events.len(), 5);
            assert!(
                events
                    .iter()
                    .enumerate()
                    .all(|(sequence, event)| event.sequence == sequence as u64
                        && event.generation == 7)
            );
            assert!(matches!(
                &events[0].event,
                Event::Automaton(AutomatonEvent::ProposeRequested { context })
                    if context == &request_context
            ));
            assert!(matches!(
                &events[1].event,
                Event::Automaton(AutomatonEvent::ProposeCompleted {
                    context,
                    outcome: Completion::Returned(payload),
                }) if context == &request_context && payload == &proposed
            ));
            assert!(matches!(
                &events[2].event,
                Event::Automaton(AutomatonEvent::VerifyRequested { context, payload })
                    if context == &request_context && payload == &verified
            ));
            assert!(matches!(
                &events[3].event,
                Event::Automaton(AutomatonEvent::VerifyCompleted {
                    context,
                    payload,
                    outcome: Completion::Returned(true),
                }) if context == &request_context && payload == &verified
            ));
            assert!(matches!(
                &events[4].event,
                Event::Automaton(AutomatonEvent::CertifyCompleted {
                    round,
                    payload,
                    outcome: Completion::Returned(false),
                }) if round == &request_context.round && payload == &certified
            ));
        });
    }

    #[test]
    fn automaton_records_canceled_when_immediate_value_cannot_be_delivered() {
        deterministic::Runner::seeded(7).start(|context| async move {
            let (participants, _) = id_mock::fixture(&mut test_rng(), b"simplex-audit-canceled", N);
            let audit: AuditLog<id_mock::Scheme, Sha256Digest> =
                AuditLog::new(participants[0].clone(), 0);
            let request_context = Context {
                round: round(5),
                leader: participants[0].clone(),
                parent: (View::new(3), digest(0xD)),
            };
            let mut automaton = RecordingAutomaton::new(
                context,
                ImmediateAutomaton {
                    proposed: digest(0xA),
                },
                audit.clone(),
            );

            let output = automaton.propose(request_context.clone()).await;
            drop(output);
            assert!(
                automaton
                    .verify(request_context.clone(), digest(0xB))
                    .await
                    .await
                    .unwrap()
            );

            let events = audit.events();
            assert!(events.iter().any(|recorded| matches!(
                &recorded.event,
                Event::Automaton(AutomatonEvent::ProposeCompleted {
                    context,
                    outcome: Completion::Canceled,
                }) if context == &request_context
            )));
        });
    }
}
