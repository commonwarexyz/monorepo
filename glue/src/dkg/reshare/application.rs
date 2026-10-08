use crate::dkg::{
    ReshareBlock,
    network::Directory,
    reshare::{EpochInfoResponse, LogReservation, Mailbox},
    types::Payload,
};
use commonware_consensus::{
    Application as ConsensusApplication, CertifiableBlock, Handoff,
    marshal::ancestry::{Ancestry, Parent},
    types::{EpochPhase, Epocher as _, FixedEpocher, Height},
};
use commonware_cryptography::{Signer, bls12381::primitives::variant::Variant};
use commonware_runtime::{Clock, Metrics, Spawner, telemetry::traces::TracedExt as _};
use commonware_utils::sequence::Unit;
use rand_core::Rng;
use std::{future, num::NonZeroU64};
use tracing::{debug, field};

/// Per-proposal input handed to an application wrapped by [`Application`].
///
/// Carries the upstream input and the reshare `payload` selected for the block
/// being proposed. The wrapped application must include `payload` in the block
/// it builds.
pub struct Input<Upstream, V: Variant, C: Signer, D: Directory<C::PublicKey> = Unit> {
    /// Input passed to [`Application`], forwarded unchanged.
    pub upstream: Upstream,

    /// The reshare payload selected for this proposal, if any.
    pub payload: Option<Payload<V, C, D>>,
}

/// An [`Application`](commonware_consensus::Application) wrapper that implements
/// the reshare [application contract](crate::dkg::reshare#application-contract).
///
/// At the final block, verification compares the block's payload with the
/// independently derived one from [`Mailbox::epoch_info`]. It rejects a
/// mismatch or [`EpochInfoResponse::Unavailable`]. On
/// [`EpochInfoResponse::Pending`] or [`EpochInfoResponse::Following`] (for
/// example, while the actor follows an epoch), it stays unresolved until
/// consensus cancels it. Before the final block, verification rejects a block
/// that carries any payload except a dealer log from the midpoint onward.
///
/// Proposals from the midpoint onward carry this node's dealer log when one is
/// available, and the final block carries the payload returned by
/// [`Mailbox::epoch_info`]. No block is proposed at the final height when the
/// actor cannot supply that payload. The inner application does not need to
/// call the reshare [`Mailbox`] or track epoch boundaries.
///
/// The inner application may be one adapted through
/// [`stateful`](crate::stateful). [`Application`] forwards its own input to the
/// inner application as [`Input::upstream`].
pub struct Application<A, B, V, C>
where
    B: ReshareBlock<Variant = V, Signer = C>,
    V: Variant,
    C: Signer,
{
    inner: A,
    reshare: Mailbox<B, V, C>,
    epocher: FixedEpocher,
}

impl<A, B, V, C> Application<A, B, V, C>
where
    B: ReshareBlock<Variant = V, Signer = C>,
    V: Variant,
    C: Signer,
{
    /// Wraps `inner`, using `reshare` to fetch reshare payloads.
    ///
    /// `blocks_per_epoch` must equal the actor's
    /// [`Config::blocks_per_epoch`](crate::dkg::reshare::Config::blocks_per_epoch).
    pub const fn new(inner: A, reshare: Mailbox<B, V, C>, blocks_per_epoch: NonZeroU64) -> Self {
        Self {
            inner,
            reshare,
            epocher: FixedEpocher::new(blocks_per_epoch),
        }
    }

    fn final_block(&self, height: Height) -> bool {
        self.epocher
            .containing(height)
            .is_some_and(|info| info.last() == height)
    }

    fn phase(&self, height: Height) -> Option<EpochPhase> {
        self.epocher.containing(height).map(|info| info.phase())
    }

    /// Selects the reshare payload for the block that extends `ancestry`, with the dealer-log
    /// reservation it was taken from.
    ///
    /// Returns `None` when no block may be proposed on this ancestry: the parent is missing, or
    /// the final block's epoch info is not available. Records the height, phase, and payload
    /// presence on the current span.
    async fn payload(
        &mut self,
        ancestry: impl Ancestry<B>,
    ) -> Option<(
        Option<Payload<V, C, B::Directory>>,
        Option<LogReservation<B, V, C>>,
    )> {
        let Some(parent) = ancestry.peek() else {
            debug!("proposal rejected: missing parent ancestry");
            return None;
        };
        let height = parent.height().next();
        let phase = self.phase(height);
        let span = tracing::Span::current();
        span.record("height", height.traced());
        span.record("phase", field::debug(phase));

        let (payload, log_reservation) = if self.final_block(height) {
            match self.reshare.epoch_info(ancestry).await {
                EpochInfoResponse::Available(payload) => (payload, None),
                EpochInfoResponse::Pending => {
                    debug!("proposal skipped: final block epoch info is not ready");
                    return None;
                }
                EpochInfoResponse::Following => {
                    debug!("proposal skipped: follower has no final block epoch info");
                    return None;
                }
                EpochInfoResponse::Unavailable => {
                    debug!("proposal skipped: final block epoch info is unavailable");
                    return None;
                }
            }
        } else if matches!(phase, Some(EpochPhase::Midpoint | EpochPhase::Late)) {
            let mut reservation = self.reshare.next_log(height).await;
            let payload = reservation
                .as_mut()
                .and_then(|reservation| reservation.take_payload());
            (payload, reservation)
        } else {
            (None, None)
        };
        span.record("has_payload", payload.is_some());
        Some((payload, log_reservation))
    }
}

impl<A, B, V, C> Clone for Application<A, B, V, C>
where
    A: Clone,
    B: ReshareBlock<Variant = V, Signer = C>,
    V: Variant,
    C: Signer,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            reshare: self.reshare.clone(),
            epocher: self.epocher.clone(),
        }
    }
}

impl<A, E, B, V, C, I> ConsensusApplication<E> for Application<A, B, V, C>
where
    E: Rng + Spawner + Metrics + Clock,
    A: ConsensusApplication<E, Block = B, Input = Input<I, V, C, B::Directory>>,
    A::Context: Send,
    B: ReshareBlock<Variant = V, Signer = C> + CertifiableBlock,
    V: Variant,
    C: Signer,
    I: Send,
{
    type SigningScheme = A::SigningScheme;
    type Context = A::Context;
    type Block = A::Block;
    type Input = I;

    #[tracing::instrument(
        name = "dkg.reshare.application.propose",
        level = "info",
        skip_all,
        fields(
            height = field::Empty,
            phase = field::Empty,
            has_payload = field::Empty
        )
    )]
    async fn propose(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        input: Self::Input,
    ) -> Option<Self::Block> {
        let (payload, log_reservation) = self.payload(ancestry.clone()).await?;
        let proposed = self
            .inner
            .propose(
                context,
                ancestry,
                Input {
                    upstream: input,
                    payload,
                },
            )
            .await;
        if proposed.is_some()
            && let Some(reservation) = log_reservation
        {
            reservation.included();
        }
        proposed
    }

    /// Prepares on an uncertified parent as [`Self::propose`] builds on a certified one.
    ///
    /// The payload depends on the parent's height, so the parent is fetched before the inner
    /// application is asked. The inner application then receives the fetched ancestry as its
    /// parent, and an inner application that declines still costs the fetch and the payload
    /// selection (a dealer-log reservation, released afterward, or the final block's epoch
    /// info).
    #[tracing::instrument(
        name = "dkg.reshare.application.prepare",
        level = "info",
        skip_all,
        fields(
            height = field::Empty,
            phase = field::Empty,
            has_payload = field::Empty
        )
    )]
    async fn prepare(
        &mut self,
        context: (E, Self::Context),
        parent: impl Parent<Self::Block>,
        input: Self::Input,
    ) -> Handoff<Self::Block> {
        let Some(ancestry) = parent.ancestry().await else {
            return Handoff::Wait;
        };
        let Some((payload, log_reservation)) = self.payload(ancestry.clone()).await else {
            return Handoff::Wait;
        };
        let prepared = self
            .inner
            .prepare(
                context,
                ancestry,
                Input {
                    upstream: input,
                    payload,
                },
            )
            .await;
        if !prepared.is_wait()
            && let Some(reservation) = log_reservation
        {
            reservation.included();
        }
        prepared
    }

    #[tracing::instrument(
        name = "dkg.reshare.application.verify",
        level = "info",
        skip_all,
        fields(
            height = field::Empty,
            phase = field::Empty,
            has_payload = field::Empty
        )
    )]
    async fn verify(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
    ) -> bool {
        let Some(tip) = ancestry.peek().cloned() else {
            return self.inner.verify(context, ancestry).await;
        };
        let height = tip.height();
        let phase = self.phase(height);
        let tip_payload = tip.payload();
        let span = tracing::Span::current();
        span.record("height", height.traced());
        span.record("phase", field::debug(phase));
        span.record("has_payload", tip_payload.is_some());

        if self.final_block(height) {
            match self.reshare.epoch_info(ancestry.clone()).await {
                EpochInfoResponse::Available(derived) => {
                    if derived != tip_payload {
                        debug!("verification rejected: final block payload mismatch");
                        return false;
                    }
                }
                response @ (EpochInfoResponse::Pending | EpochInfoResponse::Following) => {
                    // Neither response is a verdict, so verification stays
                    // unresolved until consensus cancels it.
                    debug!(
                        following = matches!(response, EpochInfoResponse::Following),
                        "verification pending: final block epoch info cannot be derived locally"
                    );
                    future::pending::<()>().await;
                    unreachable!("pending future must not resolve");
                }
                EpochInfoResponse::Unavailable => {
                    debug!("verification rejected: final block epoch info is unavailable");
                    return false;
                }
            }
        } else {
            // Before the final block, only a dealer log may be carried, and only
            // from the midpoint onward. A height outside every supported epoch
            // has no midpoint, so no payload is allowed there.
            let allowed = match tip_payload {
                None => true,
                Some(Payload::DealerLog(_)) => {
                    matches!(phase, Some(EpochPhase::Midpoint | EpochPhase::Late))
                }
                Some(Payload::EpochInfo(_)) => false,
            };
            if !allowed {
                debug!("verification rejected: non-final block carried misplaced reshare payload");
                return false;
            }
        }
        self.inner.verify(context, ancestry).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::{
        reshare::{LogReservation, Message},
        tests::mocks::{self, TestBlock, TestBlsVariant, TestContext, TestScheme},
        types::{EpochInfo, EpochOutcome},
    };
    use commonware_actor::mailbox;
    use commonware_consensus::{
        CertifiableBlock, Heightable,
        marshal::ancestry,
        types::{Epoch, Height, Round, View},
    };
    use commonware_cryptography::{
        Digestible, Signer,
        bls12381::{
            dkg::feldman_desmedt::{Dealer, Info, Reveal, deal},
            primitives::{sharing::Mode, variant::MinPk},
        },
        ed25519::{PrivateKey, PublicKey},
        sha256::Sha256,
    };
    use commonware_runtime::{Clock, Metrics, Runner, Spawner, Supervisor, deterministic};
    use commonware_utils::{
        Acknowledgement, N3f1, NZU32, NZU64, NZUsize, TestRng, channel::oneshot, ordered::Set,
        sync::Mutex,
    };
    use futures::{
        FutureExt, StreamExt,
        future::{Either, select},
        pin_mut,
    };
    use rand_core::Rng;
    use std::{sync::Arc, time::Duration};

    type TestPayload = Payload<TestBlsVariant, PrivateKey>;
    type TestResponse = EpochInfoResponse<TestBlsVariant, PrivateKey>;
    type TestWrapper = Application<RecordingApp, TestBlock, TestBlsVariant, PrivateKey>;

    impl CertifiableBlock for TestBlock {
        type Context = TestContext;

        fn context(&self) -> Self::Context {
            self.context().clone()
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ProposalBehavior {
        Accept,
        Reject,
        Pending,
    }

    #[derive(Clone)]
    struct RecordingApp {
        proposed: Arc<Mutex<Vec<Option<TestPayload>>>>,
        proposal_behavior: ProposalBehavior,
        proposal_entered: Arc<Mutex<Option<oneshot::Sender<()>>>>,
        verify_count: Arc<Mutex<usize>>,
        verify_result: bool,
        /// The decision `prepare` attaches to a built block; `Wait` builds nothing.
        handoff: Handoff<()>,
    }

    impl RecordingApp {
        fn accepting() -> Self {
            Self {
                proposed: Arc::new(Mutex::new(Vec::new())),
                proposal_behavior: ProposalBehavior::Accept,
                proposal_entered: Arc::new(Mutex::new(None)),
                verify_count: Arc::new(Mutex::new(0)),
                verify_result: true,
                handoff: Handoff::Wait,
            }
        }

        fn rejecting() -> Self {
            Self {
                proposal_behavior: ProposalBehavior::Reject,
                ..Self::accepting()
            }
        }

        fn pending(proposal_entered: oneshot::Sender<()>) -> Self {
            Self {
                proposal_behavior: ProposalBehavior::Pending,
                proposal_entered: Arc::new(Mutex::new(Some(proposal_entered))),
                ..Self::accepting()
            }
        }

        fn proposed(&self) -> Vec<Option<TestPayload>> {
            self.proposed.lock().clone()
        }

        fn verify_count(&self) -> usize {
            *self.verify_count.lock()
        }
    }

    impl<E> ConsensusApplication<E> for RecordingApp
    where
        E: Rng + Spawner + Metrics + Clock,
    {
        type SigningScheme = TestScheme;
        type Context = TestContext;
        type Block = TestBlock;
        type Input = Input<(), TestBlsVariant, PrivateKey>;

        async fn propose(
            &mut self,
            (_, context): (E, Self::Context),
            ancestry: impl Ancestry<Self::Block>,
            input: Self::Input,
        ) -> Option<Self::Block> {
            let parent = ancestry.peek()?.clone();
            self.proposed.lock().push(input.payload.clone());
            if let Some(entered) = self.proposal_entered.lock().take() {
                let _ = entered.send(());
            }

            if self.proposal_behavior == ProposalBehavior::Reject {
                return None;
            }

            if self.proposal_behavior == ProposalBehavior::Pending {
                future::pending().await
            }

            let block =
                TestBlock::new::<Sha256>(context, parent.digest(), parent.height().next(), 0);
            Some(match input.payload {
                Some(payload) => {
                    block.with_payload::<Sha256, TestBlsVariant, PrivateKey>(NZU32!(16), payload)
                }
                None => block,
            })
        }

        async fn prepare(
            &mut self,
            context: (E, Self::Context),
            parent: impl Parent<Self::Block>,
            input: Self::Input,
        ) -> Handoff<Self::Block> {
            if self.handoff.is_wait() {
                return Handoff::Wait;
            }
            let Some(ancestry) = parent.ancestry().await else {
                return Handoff::Wait;
            };
            let decision = self.handoff;
            self.propose(context, ancestry, input)
                .await
                .map_or(Handoff::Wait, |block| decision.map(|()| block))
        }

        async fn verify(&mut self, _: (E, Self::Context), _: impl Ancestry<Self::Block>) -> bool {
            *self.verify_count.lock() += 1;
            self.verify_result
        }
    }

    fn wrapper(context: &deterministic::Context, response: TestResponse) -> TestWrapper {
        wrapper_with_inner(context, response, RecordingApp::accepting())
    }

    fn wrapper_with_inner(
        context: &deterministic::Context,
        response: TestResponse,
        inner: RecordingApp,
    ) -> TestWrapper {
        let (sender, mut receiver) = mailbox::new::<Message<TestBlock, TestBlsVariant, PrivateKey>>(
            context.child("mailbox"),
            NZUsize!(1),
        );
        context.child("fake_actor").spawn(|_| async move {
            let Some(Message::EpochInfo {
                response: reply, ..
            }) = receiver.recv().await
            else {
                return;
            };
            let _ = reply.send(response);
        });

        Application::new(inner, Mailbox::new(sender), NZU64!(2))
    }

    fn log_wrapper(
        context: &deterministic::Context,
        payload: TestPayload,
        inner: RecordingApp,
    ) -> (TestWrapper, oneshot::Receiver<Height>) {
        let (sender, mut receiver) = mailbox::new::<Message<TestBlock, TestBlsVariant, PrivateKey>>(
            context.child("mailbox"),
            NZUsize!(4),
        );
        let (release_tx, release_rx) = oneshot::channel();
        context.child("fake_actor").spawn(|_| async move {
            let mut served_at = None;
            let mut release_tx = Some(release_tx);
            while let Some(message) = receiver.recv().await {
                match message {
                    Message::NextLog {
                        height,
                        release,
                        response,
                        ..
                    } => {
                        let reservation = served_at.is_none().then(|| {
                            served_at = Some(height);
                            LogReservation::new(height, payload.clone(), release)
                        });
                        let _ = response.send(reservation);
                    }
                    Message::ReleaseLog { height } => {
                        if served_at == Some(height) {
                            served_at = None;
                        }
                        if let Some(release_tx) = release_tx.take() {
                            let _ = release_tx.send(height);
                        }
                    }
                    Message::EpochInfo { response, .. } => {
                        let _ = response.send(EpochInfoResponse::Unavailable);
                    }
                    Message::Finalized { response, .. } => {
                        response.acknowledge();
                    }
                }
            }
        });

        (
            Application::new(inner, Mailbox::new(sender), NZU64!(4)),
            release_rx,
        )
    }

    fn leader() -> PrivateKey {
        PrivateKey::from_seed(99)
    }

    fn block_context(parent: &TestBlock, view: u64) -> TestContext {
        TestContext {
            round: Round::new(Epoch::zero(), View::new(view)),
            leader: leader().public_key(),
            parent: (View::zero(), parent.digest()),
        }
    }

    fn signers() -> Vec<PrivateKey> {
        (0..4).map(PrivateKey::from_seed).collect()
    }

    fn players() -> Set<PublicKey> {
        Set::from_iter_dedup(signers().iter().map(Signer::public_key))
    }

    fn epoch_payload(seed: u64) -> TestPayload {
        let (output, _) =
            deal::<MinPk, _, N3f1>(TestRng::new(seed), Mode::NonZeroCounter, players())
                .expect("trusted deal");
        Payload::EpochInfo(EpochInfo {
            outcome: EpochOutcome::Success,
            epoch: Epoch::new(1),
            output,
            players: Set::default(),
            next_players: Set::default(),
            directory: Unit,
        })
    }

    fn final_block(parent: &TestBlock, payload: Option<TestPayload>) -> Arc<TestBlock> {
        let block = TestBlock::new::<Sha256>(
            block_context(parent, 1),
            parent.digest(),
            parent.height().next(),
            0,
        );
        let block = match payload {
            Some(payload) => {
                block.with_payload::<Sha256, TestBlsVariant, PrivateKey>(NZU32!(16), payload)
            }
            None => block,
        };
        Arc::new(block)
    }

    fn midpoint_parent() -> TestBlock {
        let genesis = mocks::genesis_block(leader().public_key());
        TestBlock::new::<Sha256>(
            block_context(&genesis, 1),
            genesis.digest(),
            genesis.height().next(),
            0,
        )
    }

    /// The wrapper forwards a prepare request to the inner application with the reshare
    /// payload for the prepared height, so an inner application that opts into pipelined
    /// handoffs keeps its decision and its block carries the payload. An inner application
    /// that declines releases the dealer-log reservation.
    #[test]
    fn prepare_forwards_inner_decision_with_payload() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let parent = midpoint_parent();
            let payload = epoch_payload(10);
            for decision in [Handoff::Publish(()), Handoff::Stage(()), Handoff::Wait] {
                let inner = RecordingApp {
                    handoff: decision,
                    ..RecordingApp::accepting()
                };
                let (mut app, release_rx) = log_wrapper(&context, payload.clone(), inner.clone());
                let prepared = app
                    .prepare(
                        (context.child("app"), block_context(&parent, 2)),
                        ancestry::from_iter([Arc::new(parent.clone())]),
                        (),
                    )
                    .await;
                match (decision, prepared) {
                    (Handoff::Publish(()), Handoff::Publish(block))
                    | (Handoff::Stage(()), Handoff::Stage(block)) => {
                        assert!(inner.proposed() == vec![Some(payload.clone())]);
                        assert!(block.payload() == Some(payload.clone()));
                        assert!(
                            release_rx.now_or_never().is_none(),
                            "an included payload must keep its reservation"
                        );
                    }
                    (Handoff::Wait, Handoff::Wait) => {
                        assert!(
                            inner.proposed().is_empty(),
                            "a declined prepare builds nothing"
                        );
                        assert_eq!(
                            release_rx.await.expect("reservation should be released"),
                            parent.height().next()
                        );
                    }
                    _ => panic!("the wrapper must forward the inner decision"),
                }
            }
        });
    }

    #[test]
    fn proposal_none_releases_dealer_log_reservation() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let parent = midpoint_parent();
            let payload = epoch_payload(10);
            let inner = RecordingApp::rejecting();
            let (mut app, release_rx) = log_wrapper(&context, payload.clone(), inner.clone());

            let proposed = app
                .propose(
                    (context.child("app"), block_context(&parent, 2)),
                    ancestry::from_iter([Arc::new(parent.clone())]),
                    (),
                )
                .await;
            assert!(proposed.is_none());
            assert_eq!(
                release_rx.await.expect("reservation should be released"),
                Height::new(2)
            );

            let proposed = app
                .propose(
                    (context.child("app_retry"), block_context(&parent, 3)),
                    ancestry::from_iter([Arc::new(parent)]),
                    (),
                )
                .await;
            assert!(proposed.is_none());
            let proposed_payloads = inner.proposed();
            assert_eq!(proposed_payloads.len(), 2);
            assert!(proposed_payloads[0] == Some(payload.clone()));
            assert!(proposed_payloads[1] == Some(payload));
        });
    }

    #[test]
    fn dropped_proposal_future_releases_dealer_log_reservation() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let parent = midpoint_parent();
            let payload = epoch_payload(11);
            let (entered_tx, entered_rx) = oneshot::channel();
            let mut entered_rx = entered_rx;
            let inner = RecordingApp::pending(entered_tx);
            let (sender, mut receiver) = mailbox::new::<
                Message<TestBlock, TestBlsVariant, PrivateKey>,
            >(context.child("mailbox"), NZUsize!(4));
            let mut app = Application::new(inner.clone(), Mailbox::new(sender), NZU64!(4));

            let mut propose = Box::pin(app.propose(
                (context.child("app"), block_context(&parent, 2)),
                ancestry::from_iter([Arc::new(parent)]),
                (),
            ));
            assert!(propose.as_mut().now_or_never().is_none());

            let Some(Message::NextLog {
                height,
                release,
                response,
                ..
            }) = receiver.recv().await
            else {
                panic!("proposal should request a dealer log");
            };
            assert_eq!(height, Height::new(2));
            let reservation = LogReservation::new(height, payload.clone(), release);
            assert!(
                response.send(Some(reservation)).is_ok(),
                "proposal should still be waiting for log"
            );

            assert!(propose.as_mut().now_or_never().is_none());
            entered_rx
                .try_recv()
                .expect("proposal should enter inner application");
            drop(propose);

            let Some(Message::ReleaseLog { height }) = receiver.recv().await else {
                panic!("dropped proposal should release reservation");
            };
            assert_eq!(height, Height::new(2));

            if let Ok(Message::ReleaseLog { height }) = receiver.try_recv() {
                panic!("reservation released more than once at {height:?}");
            }
            let proposed_payloads = inner.proposed();
            assert_eq!(proposed_payloads.len(), 1);
            assert!(proposed_payloads[0] == Some(payload));
        });
    }

    #[test]
    fn successful_proposal_keeps_dealer_log_reserved() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let parent = midpoint_parent();
            let payload = epoch_payload(12);
            let inner = RecordingApp::accepting();
            let (mut app, release_rx) = log_wrapper(&context, payload.clone(), inner.clone());

            let proposed = app
                .propose(
                    (context.child("app"), block_context(&parent, 2)),
                    ancestry::from_iter([Arc::new(parent)]),
                    (),
                )
                .await
                .expect("proposal should be built");
            assert!(proposed.payload() == Some(payload.clone()));
            let proposed_payloads = inner.proposed();
            assert_eq!(proposed_payloads.len(), 1);
            assert!(proposed_payloads[0] == Some(payload));

            let timeout = context.sleep(Duration::from_millis(1));
            pin_mut!(release_rx);
            pin_mut!(timeout);
            match select(release_rx, timeout).await {
                Either::Left((released, _)) => {
                    panic!("successful proposal released reservation: {released:?}");
                }
                Either::Right(((), _)) => {}
            }
        });
    }

    #[test]
    fn proposal_skips_unavailable_final_epoch_info() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let parent = mocks::genesis_block(leader().public_key());
            let mut app = wrapper(&context, EpochInfoResponse::Unavailable);
            let inner = app.inner.clone();

            let proposed = app
                .propose(
                    (context.child("app"), block_context(&parent, 1)),
                    ancestry::from_iter([Arc::new(parent)]),
                    (),
                )
                .await;

            assert!(proposed.is_none());
            assert!(inner.proposed().is_empty());
        });
    }

    #[test]
    fn proposal_preserves_legitimate_no_artifact_final_block() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let parent = mocks::genesis_block(leader().public_key());
            let mut app = wrapper(&context, EpochInfoResponse::Available(None));
            let inner = app.inner.clone();

            let proposed = app
                .propose(
                    (context.child("app"), block_context(&parent, 1)),
                    ancestry::from_iter([Arc::new(parent)]),
                    (),
                )
                .await
                .expect("proposal should be built");

            assert!(proposed.payload().is_none());
            let proposed_payloads = inner.proposed();
            assert_eq!(proposed_payloads.len(), 1);
            assert!(proposed_payloads[0].is_none());
        });
    }

    #[test]
    fn proposal_includes_available_final_epoch_info() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let parent = mocks::genesis_block(leader().public_key());
            let payload = epoch_payload(7);
            let mut app = wrapper(
                &context,
                EpochInfoResponse::Available(Some(payload.clone())),
            );
            let inner = app.inner.clone();

            let proposed = app
                .propose(
                    (context.child("app"), block_context(&parent, 1)),
                    ancestry::from_iter([Arc::new(parent)]),
                    (),
                )
                .await
                .expect("proposal should be built");

            assert!(proposed.payload() == Some(payload.clone()));
            let proposed_payloads = inner.proposed();
            assert_eq!(proposed_payloads.len(), 1);
            assert!(proposed_payloads[0] == Some(payload));
        });
    }

    #[test]
    fn verification_rejects_unavailable_final_epoch_info() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let parent = Arc::new(mocks::genesis_block(leader().public_key()));
            let tip = final_block(&parent, Some(epoch_payload(1)));
            let mut app = wrapper(&context, EpochInfoResponse::Unavailable);
            let inner = app.inner.clone();

            let verified = app
                .verify(
                    (context.child("app"), block_context(&parent, 1)),
                    ancestry::from_iter([tip, parent]),
                )
                .await;

            assert!(!verified);
            assert_eq!(inner.verify_count(), 0);
        });
    }

    #[test]
    fn verification_stays_pending_without_final_epoch_info() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for response in [EpochInfoResponse::Following, EpochInfoResponse::Pending] {
                let parent = Arc::new(mocks::genesis_block(leader().public_key()));
                let tip = final_block(&parent, Some(epoch_payload(1)));
                let expected_tip = tip.digest();
                let expected_parent = parent.digest();
                let inner = RecordingApp::accepting();
                let (sender, mut receiver) = mailbox::new::<
                    Message<TestBlock, TestBlsVariant, PrivateKey>,
                >(
                    context.child("mailbox"), NZUsize!(1)
                );
                let mut app = Application::new(inner.clone(), Mailbox::new(sender), NZU64!(2));
                let mut verify = Box::pin(app.verify(
                    (context.child("app"), block_context(&parent, 1)),
                    ancestry::from_iter([tip, parent]),
                ));

                assert!(verify.as_mut().now_or_never().is_none());
                let Some(Message::EpochInfo {
                    mut ancestry,
                    response: reply,
                    ..
                }) = receiver.recv().await
                else {
                    panic!("verification should request final epoch info");
                };
                assert_eq!(
                    ancestry
                        .next()
                        .await
                        .expect("verification ancestry should retain the candidate")
                        .digest(),
                    expected_tip
                );
                assert_eq!(
                    ancestry
                        .next()
                        .await
                        .expect("candidate should be followed by its parent")
                        .digest(),
                    expected_parent
                );
                assert!(reply.send(response).is_ok());
                assert!(
                    verify.as_mut().now_or_never().is_none(),
                    "verification resolved without final epoch info"
                );
                assert_eq!(inner.verify_count(), 0);
            }
        });
    }

    #[test]
    fn verification_accepts_legitimate_no_artifact_final_block() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let parent = Arc::new(mocks::genesis_block(leader().public_key()));
            let tip = final_block(&parent, None);
            let mut app = wrapper(&context, EpochInfoResponse::Available(None));
            let inner = app.inner.clone();

            let verified = app
                .verify(
                    (context.child("app"), block_context(&parent, 1)),
                    ancestry::from_iter([tip, parent]),
                )
                .await;

            assert!(verified);
            assert_eq!(inner.verify_count(), 1);
        });
    }

    #[test]
    fn verification_accepts_equal_final_epoch_info() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let parent = Arc::new(mocks::genesis_block(leader().public_key()));
            let payload = epoch_payload(2);
            let tip = final_block(&parent, Some(payload.clone()));
            let mut app = wrapper(&context, EpochInfoResponse::Available(Some(payload)));
            let inner = app.inner.clone();

            let verified = app
                .verify(
                    (context.child("app"), block_context(&parent, 1)),
                    ancestry::from_iter([tip, parent]),
                )
                .await;

            assert!(verified);
            assert_eq!(inner.verify_count(), 1);
        });
    }

    #[test]
    fn verification_rejects_mismatched_final_epoch_info() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let parent = Arc::new(mocks::genesis_block(leader().public_key()));
            let tip = final_block(&parent, Some(epoch_payload(3)));
            let response = EpochInfoResponse::Available(Some(epoch_payload(4)));
            let mut app = wrapper(&context, response);
            let inner = app.inner.clone();

            let verified = app
                .verify(
                    (context.child("app"), block_context(&parent, 1)),
                    ancestry::from_iter([tip, parent]),
                )
                .await;

            assert!(!verified);
            assert_eq!(inner.verify_count(), 0);
        });
    }

    /// Verification rejects epoch info carried by an early, midpoint, or late
    /// block before the final block, without consulting the inner application.
    #[test]
    fn verification_rejects_non_final_epoch_info() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // In a six-block epoch, heights 0 through 2 are early, height 3 is
            // the midpoint, height 4 is late, and height 5 is the final block.
            let inner = RecordingApp::accepting();
            let (sender, _receiver) = mailbox::new::<
                Message<TestBlock, TestBlsVariant, PrivateKey>,
            >(context.child("mailbox"), NZUsize!(1));
            let mut app = Application::new(inner.clone(), Mailbox::new(sender), NZU64!(6));
            let mut parent = mocks::child(&mocks::genesis_block(leader().public_key()));

            // Each candidate extends the previous one and carries epoch info.
            let payload = epoch_payload(5);
            for phase in [EpochPhase::Early, EpochPhase::Midpoint, EpochPhase::Late] {
                let tip = mocks::child(&parent).with_payload::<Sha256, TestBlsVariant, PrivateKey>(
                    NZU32!(16),
                    payload.clone(),
                );
                assert_eq!(app.phase(tip.height()), Some(phase));
                assert!(!app.final_block(tip.height()));

                let verified = app
                    .verify(
                        (context.child("app"), block_context(&parent, tip.height().get())),
                        ancestry::from_iter([Arc::new(tip.clone()), Arc::new(parent)]),
                    )
                    .await;
                assert!(!verified, "{phase:?} block carried epoch info");
                parent = tip;
            }

            // No rejected candidate reached the inner application.
            assert_eq!(inner.verify_count(), 0);
        });
    }

    /// Verification rejects a dealer log carried by an early block without
    /// consulting the inner application, and passes one carried by a midpoint
    /// or late block to the inner application.
    #[test]
    fn verification_gates_dealer_log_by_phase() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // In a six-block epoch, heights 0 through 2 are early, height 3 is
            // the midpoint, height 4 is late, and height 5 is the final block.
            let inner = RecordingApp::accepting();
            let (sender, _receiver) = mailbox::new::<
                Message<TestBlock, TestBlsVariant, PrivateKey>,
            >(context.child("mailbox"), NZUsize!(1));
            let mut app = Application::new(inner.clone(), Mailbox::new(sender), NZU64!(6));
            let mut parent = mocks::child(&mocks::genesis_block(leader().public_key()));

            // Build one signed dealer log for the epoch.
            let info = Info::<TestBlsVariant, PublicKey>::new::<N3f1>(
                b"_COMMONWARE_GLUE_DKG_RESHARE_APPLICATION_TEST",
                0,
                None,
                Mode::NonZeroCounter,
                Reveal::V1,
                players(),
                players(),
            )
            .expect("valid info");
            let (dealer, _, _) =
                Dealer::start::<N3f1>(TestRng::new(0), info, signers()[0].clone(), None)
                    .expect("dealer should start");
            let payload: TestPayload = Payload::DealerLog(dealer.finalize::<N3f1>());

            // Each candidate extends the previous one and carries the log. Only
            // the early candidate is rejected before the inner application.
            for (phase, accepted) in [
                (EpochPhase::Early, false),
                (EpochPhase::Midpoint, true),
                (EpochPhase::Late, true),
            ] {
                let tip = mocks::child(&parent).with_payload::<Sha256, TestBlsVariant, PrivateKey>(
                    NZU32!(16),
                    payload.clone(),
                );
                assert_eq!(app.phase(tip.height()), Some(phase));
                assert!(!app.final_block(tip.height()));

                let consulted = inner.verify_count();
                let verified = app
                    .verify(
                        (context.child("app"), block_context(&parent, tip.height().get())),
                        ancestry::from_iter([Arc::new(tip.clone()), Arc::new(parent)]),
                    )
                    .await;
                assert_eq!(verified, accepted, "{phase:?} block carried a dealer log");
                assert_eq!(inner.verify_count(), consulted + usize::from(accepted));
                parent = tip;
            }
        });
    }
}
