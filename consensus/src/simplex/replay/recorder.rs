//! Canonical event recorder for simplex consensus.
//!
//! Pure outer-boundary wrapping — no voter-actor or engine edits. A
//! typical recording session wraps each node's:
//!
//! - **vote channel receiver** with [`RecordingReceiver`] (channel
//!   `Vote`) to record [`Event::Deliver`] for every incoming vote;
//! - **certificate channel receiver** with [`RecordingReceiver`]
//!   (channel `Certificate`) similarly for certificates;
//! - **vote channel sender** with [`RecordingSender`] to record
//!   [`Event::Construct`] for every locally-built vote the voter
//!   broadcasts;
//! - **application automaton** (the `Automaton + CertifiableAutomaton
//!   + Relay` object) with [`RecordingApp`] to record [`Event::Propose`]
//!   when the leader's proposal completes.
//!
//! The recorder accumulates events into a shared [`Recorder`] handle
//! that can be frozen into a [`Trace`] at the end of the session. The
//! order of events in the final trace is the order in which each hook
//! was reached — which matches what the engine ingested, so replay is
//! straightforward.
//!
//! `Event::Timeout` is **not** recorded automatically. If the caller
//! triggers timeouts externally (via [`voter::Mailbox::timeout`]) or
//! observes internal timeouts through some other mechanism, the caller
//! should emit `Timeout` events via [`Recorder::record_timeout`].

use super::trace::{Event, Snapshot, Topology, Trace, Wire};
use crate::{
    simplex::{
        scheme::ed25519::Scheme,
        types::{Certificate, Context, Proposal, Vote},
        Plan,
    },
    types::{Round, View},
    Automaton as Au, CertifiableAutomaton as CAu, Relay as Re,
};
use commonware_codec::{Decode, DecodeExt};
use commonware_cryptography::{
    ed25519::PublicKey,
    sha256::Digest as Sha256Digest,
};
use commonware_p2p::{CheckedSender, LimitedSender, Message, Receiver, Recipients};
use commonware_runtime::{IoBuf, IoBufs};
use commonware_utils::{channel::oneshot, Participant};
use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::SystemTime,
};

// --- Shared log ---

/// Shared, cloneable event accumulator used by all recorder wrappers.
#[derive(Clone)]
pub struct Recorder {
    inner: Arc<Mutex<Inner>>,
}

impl std::fmt::Debug for Recorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recorder").field("len", &self.len()).finish()
    }
}

struct Inner {
    events: Vec<Event>,
    participants: Vec<PublicKey>,
}

impl Recorder {
    /// Build a recorder keyed by the sorted participant list. Sender
    /// public keys seen by wrappers are mapped back to `Participant`
    /// indices using this list.
    pub fn new(participants: Vec<PublicKey>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                events: Vec::new(),
                participants,
            })),
        }
    }

    /// Current event count (for progress reporting / assertions).
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().events.len()
    }

    /// Whether any events have been recorded yet.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clone the recorded event list.
    pub fn events(&self) -> Vec<Event> {
        self.inner.lock().unwrap().events.clone()
    }

    /// Append an event explicitly. Intended for [`Event::Timeout`] since
    /// the wrapper set does not observe timeouts.
    pub fn record(&self, event: Event) {
        self.inner.lock().unwrap().events.push(event);
    }

    /// Convenience wrapper around `record` for the most common external
    /// case: pushing a `Timeout` event keyed by node + view + reason.
    pub fn record_timeout(
        &self,
        node: Participant,
        view: View,
        reason: crate::simplex::metrics::TimeoutReason,
    ) {
        self.record(Event::Timeout { node, view, reason });
    }

    /// Freeze the recorded events + the provided topology and snapshot
    /// into a canonical [`Trace`] ready for JSON serialization.
    pub fn freeze(&self, topology: Topology, expected: Snapshot) -> Trace {
        Trace {
            topology,
            events: self.events(),
            expected,
        }
    }

    fn pk_to_participant(&self, pk: &PublicKey) -> Option<Participant> {
        let inner = self.inner.lock().unwrap();
        inner
            .participants
            .iter()
            .position(|p| p == pk)
            .map(|i| Participant::new(i as u32))
    }
}

/// Channel type carried by a recorded `Deliver` event.
#[derive(Clone, Copy, Debug)]
pub enum ChannelKind {
    Vote,
    Certificate,
}

// --- RecordingReceiver: Event::Deliver ---

/// Wraps any [`Receiver<PublicKey = PublicKey>`] and records an
/// [`Event::Deliver`] for every decoded payload before forwarding it
/// unchanged to the inner receiver's caller.
#[derive(Debug)]
pub struct RecordingReceiver<R> {
    inner: R,
    recorder: Recorder,
    me: Participant,
    channel: ChannelKind,
    cert_cfg: usize,
}

impl<R> RecordingReceiver<R> {
    /// `cert_cfg` is the participant count (needed to decode
    /// certificates); it is ignored for `ChannelKind::Vote`.
    pub fn new(
        inner: R,
        recorder: Recorder,
        me: Participant,
        channel: ChannelKind,
        cert_cfg: usize,
    ) -> Self {
        Self {
            inner,
            recorder,
            me,
            channel,
            cert_cfg,
        }
    }
}

impl<R> Receiver for RecordingReceiver<R>
where
    R: Receiver<PublicKey = PublicKey>,
{
    type Error = R::Error;
    type PublicKey = PublicKey;

    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
        let (sender_pk, payload) = self.inner.recv().await?;
        if let Some(from) = self.recorder.pk_to_participant(&sender_pk) {
            match self.channel {
                ChannelKind::Vote => {
                    if let Ok(vote) = Vote::<Scheme, Sha256Digest>::decode(payload.clone()) {
                        self.recorder.record(Event::Deliver {
                            to: self.me,
                            from,
                            msg: Wire::Vote(vote),
                        });
                    }
                }
                ChannelKind::Certificate => {
                    if let Ok(cert) = Certificate::<Scheme, Sha256Digest>::decode_cfg(
                        payload.clone(),
                        &self.cert_cfg,
                    ) {
                        self.recorder.record(Event::Deliver {
                            to: self.me,
                            from,
                            msg: Wire::Cert(cert),
                        });
                    }
                }
            }
        }
        Ok((sender_pk, payload))
    }
}

// --- RecordingSender: Event::Construct ---

/// Wraps the vote-channel sender and records an [`Event::Construct`]
/// for every outgoing payload that decodes as a [`Vote`]. Payloads that
/// do not decode (malformed or different codec) are forwarded silently.
///
/// Wrap only the **vote** channel sender — certificate constructions
/// are not part of the canonical [`Event`] set (they're replayable
/// from their constituent votes).
pub struct RecordingSender<S> {
    inner: S,
    recorder: Recorder,
    me: Participant,
}

impl<S> RecordingSender<S> {
    pub fn new(inner: S, recorder: Recorder, me: Participant) -> Self {
        Self {
            inner,
            recorder,
            me,
        }
    }
}

impl<S: Clone> Clone for RecordingSender<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            recorder: self.recorder.clone(),
            me: self.me,
        }
    }
}

pub struct RecordingCheckedSender<C> {
    inner: C,
    recorder: Recorder,
    me: Participant,
}

impl<C> CheckedSender for RecordingCheckedSender<C>
where
    C: CheckedSender<PublicKey = PublicKey>,
{
    type PublicKey = PublicKey;
    type Error = C::Error;

    fn send(
        self,
        message: impl Into<IoBufs> + Send,
        priority: bool,
    ) -> impl Future<Output = Result<Vec<Self::PublicKey>, Self::Error>> + Send {
        let iobufs: IoBufs = message.into();
        // Try to decode outgoing payload as a Vote. Clone is cheap —
        // IoBufs is ref-counted internally.
        if let Ok(vote) = Vote::<Scheme, Sha256Digest>::decode(iobufs.clone()) {
            self.recorder.record(Event::Construct {
                node: self.me,
                vote,
            });
        }
        self.inner.send(iobufs, priority)
    }
}

impl<S> LimitedSender for RecordingSender<S>
where
    S: LimitedSender<PublicKey = PublicKey>,
{
    type PublicKey = PublicKey;
    type Checked<'a>
        = RecordingCheckedSender<S::Checked<'a>>
    where
        Self: 'a;

    fn check<'a>(
        &'a mut self,
        recipients: Recipients<Self::PublicKey>,
    ) -> impl Future<Output = Result<Self::Checked<'a>, SystemTime>> + Send {
        let recorder = self.recorder.clone();
        let me = self.me;
        async move {
            let inner = self.inner.check(recipients).await?;
            Ok(RecordingCheckedSender {
                inner,
                recorder,
                me,
            })
        }
    }
}

// --- RecordingApp: Event::Propose ---

/// Wraps a simplex application (an object implementing
/// [`Automaton`](Au), [`CertifiableAutomaton`](CAu), and [`Relay`](Re)
/// all at once — the typical shape for simplex applications).
///
/// Records [`Event::Propose`] by correlating:
/// 1. `Automaton::propose(context)` — stashes `(view, parent_view)`
///    from `context` into a single-entry "latest pending proposal" slot
///    (**overwritten** on every call, not pushed to a FIFO).
/// 2. `Relay::broadcast(digest, Plan::Propose)` — the leader's voter
///    invokes this after its proposal resolves. Takes the slotted
///    `(view, parent_view)` and emits `Event::Propose { leader,
///    proposal: Proposal::new(round, parent_view, digest) }`.
///
/// The slot (rather than a FIFO) matches the engine's one-active-proposal
/// invariant: at most one `propose()` is in flight at a time, and a
/// proposal that never results in `Plan::Propose` (timeout, error, view
/// moved) must be discarded — not left behind to match the *next*
/// broadcast with stale `(view, parent_view)`.
///
/// Every other trait method is forwarded unchanged.
#[derive(Clone)]
pub struct RecordingApp<A> {
    inner: A,
    recorder: Recorder,
    me: Participant,
    /// Latest pending proposal that has been requested via `propose()`
    /// but whose digest has not yet been observed via
    /// `Relay::broadcast(_, Plan::Propose)`. Overwritten on each
    /// `propose()` call — we track only the most recent one.
    pending: Arc<Mutex<Option<PendingPropose>>>,
}

#[derive(Clone, Copy, Debug)]
struct PendingPropose {
    round: Round,
    parent_view: View,
}

impl<A> RecordingApp<A> {
    pub fn new(inner: A, recorder: Recorder, me: Participant) -> Self {
        Self {
            inner,
            recorder,
            me,
            pending: Arc::new(Mutex::new(None)),
        }
    }
}

impl<A> Au for RecordingApp<A>
where
    A: Au<Context = Context<Sha256Digest, PublicKey>, Digest = Sha256Digest> + Send,
{
    type Context = Context<Sha256Digest, PublicKey>;
    type Digest = Sha256Digest;

    async fn genesis(&mut self, epoch: crate::types::Epoch) -> Sha256Digest {
        self.inner.genesis(epoch).await
    }

    async fn propose(
        &mut self,
        context: Self::Context,
    ) -> oneshot::Receiver<Self::Digest> {
        let round = context.round;
        let parent_view = context.parent.0;
        // Overwrite: any previously-slotted proposal that never
        // produced a `Plan::Propose` broadcast is discarded.
        *self.pending.lock().unwrap() = Some(PendingPropose { round, parent_view });
        self.inner.propose(context).await
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        self.inner.verify(context, payload).await
    }
}

impl<A> CAu for RecordingApp<A>
where
    A: CAu<Context = Context<Sha256Digest, PublicKey>, Digest = Sha256Digest> + Send,
{
    async fn certify(
        &mut self,
        round: Round,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        self.inner.certify(round, payload).await
    }
}

impl<A> Re for RecordingApp<A>
where
    A: Re<Digest = Sha256Digest, PublicKey = PublicKey, Plan = Plan<PublicKey>> + Send,
{
    type Digest = Sha256Digest;
    type PublicKey = PublicKey;
    type Plan = Plan<PublicKey>;

    async fn broadcast(&mut self, payload: Self::Digest, plan: Plan<PublicKey>) {
        if matches!(plan, Plan::Propose) {
            if let Some(p) = self.pending.lock().unwrap().take() {
                let proposal = Proposal::new(p.round, p.parent_view, payload);
                self.recorder.record(Event::Propose {
                    leader: self.me,
                    proposal,
                });
            }
            // If the slot is empty we silently skip: the relay must
            // have been called for some non-local proposal, which
            // shouldn't happen in simplex but we refuse to panic.
        }
        self.inner.broadcast(payload, plan).await;
    }
}

// Silence unused warnings for re-exported items on narrow configs.
const _: Option<IoBuf> = None;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simplex::types::{Notarize, Proposal};
    use crate::types::Epoch;
    use commonware_codec::Encode;
    use commonware_cryptography::sha256::Digest as Sha256Digest;
    use commonware_p2p::Message;
    use commonware_runtime::{deterministic, Runner};
    use commonware_utils::channel::mpsc;

    /// Minimal hand-rolled `Receiver` that yields a pre-queued message.
    #[derive(Debug)]
    struct StubReceiver {
        rx: mpsc::UnboundedReceiver<(PublicKey, IoBuf)>,
    }

    impl Receiver for StubReceiver {
        type Error = std::io::Error;
        type PublicKey = PublicKey;
        async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
            self.rx
                .recv()
                .await
                .ok_or_else(|| std::io::Error::other("closed"))
        }
    }

    fn make_fixture() -> commonware_cryptography::certificate::mocks::Fixture<Scheme> {
        let captured = Arc::new(Mutex::new(None));
        let captured_clone = captured.clone();
        let runner = deterministic::Runner::seeded(0);
        runner.start(|mut ctx| async move {
            let fx = crate::simplex::scheme::ed25519::fixture(
                &mut ctx,
                b"consensus_fuzz",
                4,
            );
            *captured_clone.lock().unwrap() = Some(fx);
        });
        let mut guard = captured.lock().unwrap();
        guard.take().unwrap()
    }

    #[test]
    fn recording_receiver_emits_deliver_for_decodable_vote() {
        let fx = make_fixture();
        let recorder = Recorder::new(fx.participants.clone());

        let (tx, rx) = mpsc::unbounded_channel();
        let inner = StubReceiver { rx };
        let mut rr = RecordingReceiver::new(
            inner,
            recorder.clone(),
            Participant::new(1),
            ChannelKind::Vote,
            fx.participants.len(),
        );

        // Build a real signed Notarize from n0 and queue it.
        let round = Round::new(Epoch::new(0), View::new(1));
        let proposal = Proposal::new(round, View::new(0), Sha256Digest([7u8; 32]));
        let notarize =
            Notarize::<Scheme, Sha256Digest>::sign(&fx.schemes[0], proposal).unwrap();
        let vote = Vote::Notarize(notarize);
        let bytes: IoBuf = vote.encode().into();
        let _ = tx.send((fx.participants[0].clone(), bytes));
        drop(tx);

        let runner = deterministic::Runner::timed(std::time::Duration::from_secs(5));
        runner.start(|_ctx| async move {
            let _ = rr.recv().await.unwrap();
        });

        let events = recorder.events();
        assert_eq!(events.len(), 1);
        match &events[0] {
            Event::Deliver { to, from, msg } => {
                assert_eq!(*to, Participant::new(1));
                assert_eq!(*from, Participant::new(0));
                assert!(matches!(msg, Wire::Vote(Vote::Notarize(_))));
            }
            other => panic!("expected Deliver, got {other:?}"),
        }
    }

    #[test]
    fn recording_receiver_ignores_undecodable() {
        let fx = make_fixture();
        let recorder = Recorder::new(fx.participants.clone());
        let (tx, rx) = mpsc::unbounded_channel();
        let inner = StubReceiver { rx };
        let mut rr = RecordingReceiver::new(
            inner,
            recorder.clone(),
            Participant::new(1),
            ChannelKind::Vote,
            fx.participants.len(),
        );

        // Garbage payload — should not produce a Deliver event.
        let bytes: IoBuf = vec![0xFFu8; 4].into();
        let _ = tx.send((fx.participants[0].clone(), bytes));
        drop(tx);

        let runner = deterministic::Runner::timed(std::time::Duration::from_secs(5));
        runner.start(|_ctx| async move {
            let _ = rr.recv().await.unwrap();
        });

        assert!(recorder.events().is_empty());
    }

    #[test]
    fn recording_sender_emits_construct_for_vote() {
        use super::super::injected::{NullSender, NullCheckedSender};

        let fx = make_fixture();
        let recorder = Recorder::new(fx.participants.clone());
        let inner = NullSender;
        let mut rs = RecordingSender::new(inner, recorder.clone(), Participant::new(0));

        let round = Round::new(Epoch::new(0), View::new(3));
        let proposal = Proposal::new(round, View::new(0), Sha256Digest([11u8; 32]));
        let notarize =
            Notarize::<Scheme, Sha256Digest>::sign(&fx.schemes[0], proposal).unwrap();
        let vote: Vote<Scheme, Sha256Digest> = Vote::Notarize(notarize);

        let runner = deterministic::Runner::timed(std::time::Duration::from_secs(5));
        runner.start(|_ctx| async move {
            let checked = rs.check(Recipients::All).await.unwrap();
            let iobufs: IoBufs = IoBuf::from(vote.encode()).into();
            let _ = checked.send(iobufs, false).await;
            // Keep NullSender/NullCheckedSender referenced so the compiler
            // doesn't complain if we ever expand the import footprint.
            let _ = NullCheckedSender;
        });

        let events = recorder.events();
        assert_eq!(events.len(), 1, "expected exactly one Construct event");
        match &events[0] {
            Event::Construct { node, vote: v } => {
                assert_eq!(*node, Participant::new(0));
                assert!(matches!(v, Vote::Notarize(_)));
            }
            other => panic!("expected Construct, got {other:?}"),
        }
    }

    /// Stub automaton whose `propose()` returns a preset digest and whose
    /// `broadcast(_, Plan::Propose)` never fires on its own — the test
    /// drives the broadcast explicitly to check the correlation path.
    #[derive(Clone)]
    struct StubApp {
        digest: Sha256Digest,
    }

    impl crate::Automaton for StubApp {
        type Context = crate::simplex::types::Context<Sha256Digest, PublicKey>;
        type Digest = Sha256Digest;
        async fn genesis(&mut self, _: crate::types::Epoch) -> Sha256Digest {
            Sha256Digest([0u8; 32])
        }
        async fn propose(&mut self, _: Self::Context) -> oneshot::Receiver<Self::Digest> {
            let (tx, rx) = oneshot::channel();
            let _ = tx.send(self.digest);
            rx
        }
        async fn verify(
            &mut self,
            _: Self::Context,
            _: Self::Digest,
        ) -> oneshot::Receiver<bool> {
            let (tx, rx) = oneshot::channel();
            let _ = tx.send(true);
            rx
        }
    }

    impl crate::CertifiableAutomaton for StubApp {
        async fn certify(&mut self, _: Round, _: Self::Digest) -> oneshot::Receiver<bool> {
            let (tx, rx) = oneshot::channel();
            let _ = tx.send(true);
            rx
        }
    }

    impl crate::Relay for StubApp {
        type Digest = Sha256Digest;
        type PublicKey = PublicKey;
        type Plan = Plan<PublicKey>;
        async fn broadcast(&mut self, _: Self::Digest, _: Self::Plan) {}
    }

    #[test]
    fn recording_app_emits_propose_on_plan_propose() {
        use crate::simplex::types::Context as Ctx;
        use crate::Viewable;
        let fx = make_fixture();
        let recorder = Recorder::new(fx.participants.clone());
        let digest = Sha256Digest([42u8; 32]);
        let app = StubApp { digest };
        let mut rec = RecordingApp::new(app, recorder.clone(), Participant::new(2));

        let round = Round::new(crate::types::Epoch::new(0), View::new(5));
        let ctx: Ctx<Sha256Digest, PublicKey> = Ctx {
            round,
            leader: fx.participants[2].clone(),
            parent: (View::new(4), Sha256Digest([0u8; 32])),
        };

        let runner = deterministic::Runner::timed(std::time::Duration::from_secs(5));
        runner.start(|_ctx| async move {
            let _rx = rec.propose(ctx).await;
            // Simulate the voter's post-propose Relay call.
            rec.broadcast(digest, Plan::Propose).await;
        });

        let events = recorder.events();
        assert_eq!(events.len(), 1);
        match &events[0] {
            Event::Propose { leader, proposal } => {
                assert_eq!(*leader, Participant::new(2));
                assert_eq!(proposal.view(), View::new(5));
                assert_eq!(proposal.parent, View::new(4));
                assert_eq!(proposal.payload, digest);
            }
            other => panic!("expected Propose, got {other:?}"),
        }
    }

    #[test]
    fn recording_app_discards_orphaned_propose() {
        // Regression test: a propose() call that is never followed by
        // Plan::Propose (timeout / view moved / error) must not
        // contaminate the next propose()/broadcast pair with a stale
        // (view, parent_view).
        use crate::simplex::types::Context as Ctx;
        use crate::Viewable;

        let fx = make_fixture();
        let recorder = Recorder::new(fx.participants.clone());
        let digest_orphan = Sha256Digest([0x11; 32]);
        let digest_real = Sha256Digest([0x22; 32]);
        let app = StubApp {
            digest: digest_real,
        };
        let mut rec = RecordingApp::new(app, recorder.clone(), Participant::new(3));

        let round_a = Round::new(crate::types::Epoch::new(0), View::new(10));
        let ctx_a: Ctx<Sha256Digest, PublicKey> = Ctx {
            round: round_a,
            leader: fx.participants[3].clone(),
            parent: (View::new(9), Sha256Digest([0u8; 32])),
        };
        let round_b = Round::new(crate::types::Epoch::new(0), View::new(12));
        let ctx_b: Ctx<Sha256Digest, PublicKey> = Ctx {
            round: round_b,
            leader: fx.participants[3].clone(),
            parent: (View::new(11), Sha256Digest([0u8; 32])),
        };

        let runner = deterministic::Runner::timed(std::time::Duration::from_secs(5));
        runner.start(|_ctx| async move {
            // Orphaned propose at view 10 — never broadcast.
            let _ = rec.propose(ctx_a).await;
            let _ = digest_orphan; // referenced for clarity in the test
            // Then a real propose at view 12 that DOES broadcast.
            let _ = rec.propose(ctx_b).await;
            rec.broadcast(digest_real, Plan::Propose).await;
        });

        let events = recorder.events();
        assert_eq!(events.len(), 1, "exactly one Propose should be recorded");
        match &events[0] {
            Event::Propose { leader, proposal } => {
                assert_eq!(*leader, Participant::new(3));
                assert_eq!(
                    proposal.view(),
                    View::new(12),
                    "view must come from the *most recent* propose(), not the orphaned one"
                );
                assert_eq!(proposal.parent, View::new(11));
                assert_eq!(proposal.payload, digest_real);
            }
            other => panic!("expected Propose, got {other:?}"),
        }
    }

    #[test]
    fn recording_app_ignores_non_propose_broadcast() {
        let fx = make_fixture();
        let recorder = Recorder::new(fx.participants.clone());
        let app = StubApp {
            digest: Sha256Digest([0u8; 32]),
        };
        let mut rec = RecordingApp::new(app, recorder.clone(), Participant::new(0));

        let runner = deterministic::Runner::timed(std::time::Duration::from_secs(5));
        runner.start(|_ctx| async move {
            // Forward without a preceding propose(); should be ignored.
            rec.broadcast(
                Sha256Digest([1u8; 32]),
                Plan::Forward {
                    round: Round::new(crate::types::Epoch::new(0), View::new(1)),
                    peers: fx.participants.clone(),
                },
            )
            .await;
        });

        assert!(recorder.events().is_empty());
    }
}
