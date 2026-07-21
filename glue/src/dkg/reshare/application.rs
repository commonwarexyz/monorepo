use crate::dkg::{
    ReshareBlock,
    reshare::{EpochInfoResponse, Mailbox},
    types::Payload,
};
use commonware_consensus::{
    Application as ConsensusApplication, CertifiableBlock,
    marshal::ancestry::Ancestry,
    types::{EpochPhase, Epocher as _, FixedEpocher, Height},
};
use commonware_cryptography::{Signer, bls12381::primitives::variant::Variant};
use commonware_runtime::{Clock, Metrics, Spawner, telemetry::traces::TracedExt as _};
use rand_core::Rng;
use std::{future, num::NonZeroU64};
use tracing::{debug, field};

/// Per-proposal input handed to an application wrapped by [`Application`].
///
/// Carries the wrapper's upstream input alongside the reshare `payload` selected
/// and fetched for the block being proposed. The wrapped application attaches
/// `payload` to the block it builds and uses `upstream` for its own purposes.
pub struct Input<Upstream, V: Variant, C: Signer> {
    /// Input forwarded from the application wrapping the reshare wrapper.
    pub upstream: Upstream,

    /// The reshare payload selected for this proposal, if any.
    pub payload: Option<Payload<V, C>>,
}

/// An [`Application`](commonware_consensus::Application) wrapper that enforces the
/// reshare block-validity contract and drives the reshare payload for proposals.
///
/// When the reshare actor tracks an epoch's ceremony, the wrapper rejects a
/// final block whose payload differs from the independently reconstructed
/// [`EpochInfo`](crate::dkg::types::EpochInfo). An actor that starts following
/// mid-epoch lacks the protocol history required for that comparison, so the
/// wrapper delegates verification to the inner application rather than treating
/// missing local state as an invalid proposal. The wrapper always rejects stray
/// payloads carried by non-final blocks in the early dealing window.
///
/// For proposals, the wrapper selects and fetches the payload for the block being
/// built (a dealer log from the midpoint onward, the epoch info on the final
/// block) and hands it to the inner application through [`Input`], so the
/// inner application neither talks to the reshare mailbox nor tracks epoch
/// boundaries. It only attaches the handed-over payload to the block it builds,
/// because the wrapper cannot build the application's block type itself.
///
/// The wrapper is a plain [`Application`](commonware_consensus::Application), so
/// it composes with any consensus application, including one adapted through
/// [`stateful`](crate::stateful). It forwards its own upstream input to the inner
/// application as [`Input::upstream`], so nesting under another
/// input-providing application still works.
pub struct Application<A, B, V, C>
where
    B: ReshareBlock,
    V: Variant,
    C: Signer,
{
    inner: A,
    reshare: Mailbox<B, V, C>,
    epocher: FixedEpocher,
}

impl<A, B, V, C> Application<A, B, V, C>
where
    B: ReshareBlock,
    V: Variant,
    C: Signer,
{
    /// Wraps `inner`, using `reshare` to select final-block epoch info and dealer
    /// logs and `blocks_per_epoch` to locate epoch boundaries and phases.
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
}

impl<A, B, V, C> Clone for Application<A, B, V, C>
where
    A: Clone,
    B: ReshareBlock,
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
    A: ConsensusApplication<E, Block = B, Input = Input<I, V, C>>,
    A::Context: Send,
    B: ReshareBlock<Variant = V, Signer = C> + CertifiableBlock + Clone,
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
        // Select and fetch the payload for the block being built, then hand it to
        // the inner application alongside its own input.
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
            match self.reshare.epoch_info(ancestry.clone()).await {
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
                EpochInfoResponse::Pending => {
                    debug!("verification pending: final block epoch info is not ready");
                    future::pending::<()>().await;
                    unreachable!("pending future must not resolve");
                }
                EpochInfoResponse::Following => {
                    debug!("verification delegated: follower has no final block epoch info");
                }
                EpochInfoResponse::Unavailable => {
                    debug!("verification rejected: final block epoch info is unavailable");
                    return false;
                }
            }
        } else if matches!(phase, Some(EpochPhase::Early)) && tip_payload.is_some() {
            // Dealer logs are only posted from the midpoint onward, so an early
            // block must not carry a reshare payload.
            debug!("verification rejected: early block carried reshare payload");
            return false;
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
            dkg::feldman_desmedt::deal,
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
        FutureExt,
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
    }

    impl RecordingApp {
        fn accepting() -> Self {
            Self {
                proposed: Arc::new(Mutex::new(Vec::new())),
                proposal_behavior: ProposalBehavior::Accept,
                proposal_entered: Arc::new(Mutex::new(None)),
                verify_count: Arc::new(Mutex::new(0)),
                verify_result: true,
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
    fn verification_delegates_when_following_without_epoch_info() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for expected in [true, false] {
                let parent = Arc::new(mocks::genesis_block(leader().public_key()));
                let tip = final_block(&parent, Some(epoch_payload(1)));
                let mut app = wrapper(&context, EpochInfoResponse::Following);
                app.inner.verify_result = expected;
                let inner = app.inner.clone();

                let verified = app
                    .verify(
                        (context.child("app"), block_context(&parent, 1)),
                        ancestry::from_iter([tip, parent]),
                    )
                    .await;

                assert_eq!(verified, expected);
                assert_eq!(inner.verify_count(), 1);
            }
        });
    }

    #[test]
    fn verification_stays_pending_when_final_epoch_info_not_ready() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let parent = Arc::new(mocks::genesis_block(leader().public_key()));
            let tip = final_block(&parent, Some(epoch_payload(1)));
            let mut app = wrapper(&context, EpochInfoResponse::Pending);
            let inner = app.inner.clone();

            let verify = app.verify(
                (context.child("app"), block_context(&parent, 1)),
                ancestry::from_iter([tip, parent]),
            );
            let timeout = context.sleep(Duration::from_millis(1));
            pin_mut!(verify);
            pin_mut!(timeout);

            match select(verify, timeout).await {
                Either::Left((verified, _)) => {
                    panic!("verification resolved before epoch info was ready: {verified}");
                }
                Either::Right(((), _)) => {}
            }
            assert_eq!(inner.verify_count(), 0);
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
}
