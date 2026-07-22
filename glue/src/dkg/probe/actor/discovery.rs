use super::service::Service;
use crate::{
    dkg::{
        ReshareBlock,
        probe::{ActorArtifact, Artifact, mailbox::Message, wire},
        types::{EpochInfo, Participants, Payload},
    },
    stateful::probe::sample::Sample,
};
use bytes::Buf;
use commonware_actor::mailbox::Receiver as ActorReceiver;
use commonware_codec::{Encode as _, Error as CodecError, Read};
use commonware_consensus::{
    Epochable, Heightable,
    marshal::core::Variant,
    simplex::{scheme::Scheme, types::Finalization},
    types::{Epoch, Epocher, FixedEpocher, Height},
};
use commonware_cryptography::Signer;
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Manager, Receiver, Recipients, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner};
use commonware_utils::{
    NonZeroDuration,
    channel::{fallible::OneshotExt as _, oneshot},
};
use futures::future::{self, Either};
use rand_core::CryptoRng;
use std::collections::VecDeque;
use tracing::{debug, warn};

#[derive(Debug)]
enum BoundaryBlockError {
    Commitment,
    Decode(CodecError),
}

struct Candidate<S, V>
where
    S: Scheme<V::Commitment>,
    V: Variant,
{
    peer: S::PublicKey,
    finalization: Finalization<S, V::Commitment>,
}

pub(super) struct Pending<S, V>
where
    S: Scheme<V::Commitment>,
    V: Variant,
{
    height: Height,
    epoch: Epoch,
    in_flight: Option<Candidate<S, V>>,
    candidates: VecDeque<Candidate<S, V>>,
}

/// The discovery phase of the DKG probe actor.
///
/// Waits for subscribers, solicits the configured bootstrap committee's latest
/// finalizations, and selects the highest valid finalization from `f + 1`
/// distinct replies as the state-sync floor. The floor's epoch names the target
/// epoch: discovery then fetches that epoch's boundary finalization and block
/// from peers. Once the boundary block yields the target epoch's public
/// [`Artifact`], discovery resolves all subscribers and can hand off to
/// [`Service`] after marshal is attached.
pub(super) struct Discovery<E, M, S, V, T, B>
where
    E: Spawner + CryptoRng + Clock + Metrics,
    M: Manager<PublicKey = S::PublicKey>,
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    <V::ApplicationBlock as ReshareBlock>::Signer: Signer<PublicKey = S::PublicKey>,
    T: Strategy,
    B: Blocker<PublicKey = S::PublicKey>,
{
    pub(super) context: ContextCell<E>,
    pub(super) mailbox: ActorReceiver<Message<S, V>>,
    pub(super) manager: M,
    pub(super) bootstrap_participants: Participants<S::PublicKey>,
    pub(super) verifier: S,
    pub(super) genesis: EpochInfo<<V::ApplicationBlock as ReshareBlock>::Variant, S::PublicKey>,
    pub(super) strategy: T,
    pub(super) blocker: B,
    pub(super) epocher: FixedEpocher,
    pub(super) block_codec_config: <V::ApplicationBlock as Read>::Cfg,
    pub(super) retry_timeout: NonZeroDuration,
    pub(super) artifact: Option<ActorArtifact<S, V>>,
    pub(super) sample: Sample<S, V::Commitment>,
    pub(super) subscribers: Vec<oneshot::Sender<ActorArtifact<S, V>>>,
    pub(super) pending: Option<Pending<S, V>>,
}

impl<E, M, S, V, T, B> Discovery<E, M, S, V, T, B>
where
    E: Spawner + CryptoRng + Clock + Metrics,
    M: Manager<PublicKey = S::PublicKey>,
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    <V::ApplicationBlock as ReshareBlock>::Signer: Signer<PublicKey = S::PublicKey>,
    T: Strategy,
    B: Blocker<PublicKey = S::PublicKey>,
{
    /// Runs discovery until shutdown or until it can hand off to [`Service`].
    pub(super) async fn run<BSE, BRE>(
        mut self,
        mut boundary_sender: BSE,
        mut boundary_receiver: BRE,
    ) where
        BSE: Sender<PublicKey = S::PublicKey>,
        BRE: Receiver<PublicKey = S::PublicKey>,
    {
        let mut marshal = None;
        let mut deadline = self.context.current() + self.retry_timeout.get();

        select_loop! {
            self.context,
            on_start => {
                self.subscribers
                    .retain(|subscriber| !subscriber.is_closed());
                if marshal.is_some() && self.subscribers.is_empty() {
                    break;
                }

                // Arm the retry timer only while actively discovering.
                let retry = if self.artifact.is_none() && !self.subscribers.is_empty() {
                    Either::Left(self.context.sleep_until(deadline))
                } else {
                    Either::Right(future::pending())
                };
            },
            on_stopped => {
                debug!("shutdown signal received");
                return;
            },
            Some(message) = self.mailbox.recv() else {
                debug!("mailbox closed, shutting down");
                return;
            } => match message {
                Message::Subscribe { response } => {
                    if self.subscribe(response, &mut boundary_sender) {
                        deadline = self.context.current() + self.retry_timeout.get();
                    }
                }
                Message::Attach { marshal: attached } => {
                    marshal = Some(attached);
                }
            },
            Ok((peer, message)) = boundary_receiver.recv() else {
                debug!("boundary receiver closed, shutting down");
                return;
            } => {
                if self.handle_boundary_response(peer, message, &mut boundary_sender) {
                    deadline = self.context.current() + self.retry_timeout.get();
                }
            },
            _ = retry => {
                if self.pending.is_some() {
                    self.retry_boundary(&mut boundary_sender);
                } else if self.sample.floor().is_none() {
                    debug!(reason = "deadline elapsed", "re-soliciting latest finalizations");
                    self.request_latest(&mut boundary_sender);
                }
                deadline = self.context.current() + self.retry_timeout.get();
            },
        }

        Service {
            context: self.context,
            mailbox: self.mailbox,
            marshal: marshal.expect("serving requires attached marshal"),
            blocker: self.blocker,
            epocher: self.epocher,
            artifact: self.artifact,
        }
        .run(boundary_sender, boundary_receiver)
        .await;
    }

    /// Handle a new subscriber, returning whether a solicitation was sent (so
    /// the caller can reset the retry deadline).
    fn subscribe(
        &mut self,
        response: oneshot::Sender<ActorArtifact<S, V>>,
        boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) -> bool {
        if let Some(artifact) = &self.artifact {
            response.send_lossy(artifact.clone());
            return false;
        }
        let solicit = self.subscribers.is_empty() && self.sample.floor().is_none();
        self.subscribers.push(response);
        if solicit {
            // Track the bootstrap epoch's canonical peer set at its own ID so
            // the configured committee is dialable. The contents match what
            // the orchestrator tracks if it later enters this epoch, so a
            // duplicate registration is rejected harmlessly. Tracking is
            // deferred until discovery actually solicits: a node that never
            // bootstraps must not claim an ID above the epochs its
            // orchestrator still enters.
            let _ = self.manager.track(
                self.sample.minimum_epoch().get(),
                self.bootstrap_participants.tracked_peers(),
            );
            self.request_latest(boundary_sender);
        }
        solicit
    }

    /// Clears collected replies and solicits the configured committee's latest
    /// finalizations.
    fn request_latest(&mut self, boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>) {
        self.sample.reset();
        boundary_sender.send(
            Recipients::Some(
                self.bootstrap_participants
                    .dealers
                    .iter()
                    .cloned()
                    .collect(),
            ),
            wire::Message::<S, V>::LatestRequest.encode(),
            false,
        );
    }

    /// Broadcast a request for the boundary finalization of `epoch` to all peers.
    fn request_boundary_finalization(
        epoch: Epoch,
        boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) {
        boundary_sender.send(
            Recipients::All,
            wire::Message::<S, V>::BoundaryRequest(epoch).encode(),
            false,
        );
    }

    /// Handle a boundary protocol response, returning whether a new request was
    /// sent so the caller can reset the retry deadline.
    fn handle_boundary_response(
        &mut self,
        peer: S::PublicKey,
        message: impl Buf,
        boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) -> bool {
        let response = match wire::read_response::<S, V, _>(
            message,
            &self.verifier.certificate_codec_config(),
        ) {
            Ok(Some(response)) => response,
            Ok(None) => return false,
            Err(err) => {
                commonware_p2p::block!(
                    self.blocker,
                    peer,
                    ?err,
                    "invalid bootstrap boundary response"
                );
                return false;
            }
        };

        match response {
            wire::Response::Latest(finalization) => {
                self.handle_latest(peer, finalization, boundary_sender)
            }
            wire::Response::Boundary(finalization) => {
                if self.pending.is_none() {
                    return false;
                }
                self.handle_boundary_finalization(peer, finalization, boundary_sender)
            }
            wire::Response::Block { epoch, body } => {
                if self.pending.is_none() {
                    return false;
                }
                self.handle_boundary_block(peer, epoch, body, boundary_sender)
            }
        }
    }

    /// Handle a solicited latest-finalization reply, returning whether the
    /// completed sample sent a boundary request (so the caller can reset the
    /// retry deadline).
    ///
    /// At most one reply is counted per peer. Replies must come from the
    /// configured committee and verify under the all-epoch verifier. Replies
    /// below the bootstrap epoch are ignored without blocking: the chain
    /// reached the bootstrap epoch by definition, so they are stale but not
    /// proof of misbehavior.
    fn handle_latest(
        &mut self,
        peer: S::PublicKey,
        finalization: Finalization<S, V::Commitment>,
        boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) -> bool {
        // Once the floor is selected or the peer has contributed this request
        // round, further replies are ignored without verification.
        if !self.sample.pending(&peer) {
            return false;
        }
        if self
            .bootstrap_participants
            .dealers
            .position(&peer)
            .is_none()
        {
            commonware_p2p::block!(self.blocker, peer, "latest finalization from non-member");
            return false;
        }
        if finalization.epoch() < self.sample.minimum_epoch() {
            debug!(
                epoch = %finalization.epoch(),
                bootstrap_epoch = %self.sample.minimum_epoch(),
                "ignoring latest finalization below bootstrap epoch"
            );
            return false;
        }
        if !finalization.verify(
            self.context.as_present_mut(),
            &self.verifier,
            &self.strategy,
        ) {
            commonware_p2p::block!(self.blocker, peer, "invalid latest finalization");
            return false;
        }
        if self.subscribers.is_empty() {
            self.sample.reset();
            return false;
        }
        self.sample.record(peer, finalization);
        self.try_select_floor(boundary_sender)
    }

    /// Selects the highest finalization once `f + 1` distinct committee members
    /// have replied, then begins the boundary fetch for the floor's epoch.
    ///
    /// Returns whether a boundary request was sent.
    fn try_select_floor(
        &mut self,
        boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) -> bool {
        // The all-epoch verifier judges every recorded reply.
        let Some(floor) = self
            .sample
            .select(self.bootstrap_participants.dealers.len(), |_| true)
        else {
            return false;
        };
        let target = floor.epoch();

        if target.is_zero() {
            // Epoch zero is anchored by genesis and has no boundary block.
            self.resolve(Artifact {
                finalization: None,
                info: self.genesis.clone(),
                floor,
            });
            return false;
        }

        let Some(height) = target.previous().and_then(|epoch| self.epocher.last(epoch)) else {
            // Unreachable without a forged quorum: re-sample rather than wedge.
            warn!(epoch = %target, "sampled floor epoch has no boundary height");
            self.sample = Sample::new(self.sample.minimum_epoch());
            return false;
        };
        Self::request_boundary_finalization(target, boundary_sender);
        self.pending = Some(Pending {
            height,
            epoch: target,
            in_flight: None,
            candidates: VecDeque::new(),
        });
        true
    }

    fn handle_boundary_finalization(
        &mut self,
        peer: S::PublicKey,
        finalization: Finalization<S, V::Commitment>,
        boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) -> bool {
        let mut pending = self.pending.take().expect("pending checked by caller");

        let Some(expected_finalization_epoch) = pending.epoch.previous() else {
            commonware_p2p::block!(self.blocker, peer, "invalid bootstrap boundary response");
            self.pending = Some(pending);
            return false;
        };

        let response_finalization_epoch = finalization.epoch();
        if response_finalization_epoch < expected_finalization_epoch {
            debug!(
                response_finalization_epoch = %response_finalization_epoch,
                pending_epoch = %pending.epoch,
                "ignoring stale bootstrap boundary response"
            );
            self.pending = Some(pending);
            return false;
        }

        if response_finalization_epoch != expected_finalization_epoch {
            commonware_p2p::block!(self.blocker, peer, "invalid bootstrap boundary response");
            self.pending = Some(pending);
            return false;
        }

        let duplicate = pending
            .in_flight
            .as_ref()
            .is_some_and(|candidate| candidate.peer == peer)
            || pending
                .candidates
                .iter()
                .any(|candidate| candidate.peer == peer);
        if duplicate {
            self.pending = Some(pending);
            return false;
        }

        if !finalization.verify(
            self.context.as_present_mut(),
            &self.verifier,
            &self.strategy,
        ) {
            commonware_p2p::block!(self.blocker, peer, "invalid bootstrap boundary response");
            self.pending = Some(pending);
            return false;
        }

        pending
            .candidates
            .push_back(Candidate { peer, finalization });
        let requested = pending.in_flight.is_none();
        if requested {
            Self::request_next_block(&mut pending, boundary_sender);
        }
        self.pending = Some(pending);
        requested
    }

    fn handle_boundary_block(
        &mut self,
        peer: S::PublicKey,
        epoch: Epoch,
        body: impl Buf,
        boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) -> bool {
        let mut pending = self.pending.take().expect("pending checked by caller");
        let Some(candidate) = pending.in_flight.take() else {
            self.pending = Some(pending);
            return false;
        };
        if candidate.peer != peer || pending.epoch != epoch {
            pending.in_flight = Some(candidate);
            self.pending = Some(pending);
            return false;
        }

        let commitment = candidate.finalization.proposal.payload;
        let block =
            match authenticate_boundary_block::<V>(&self.block_codec_config, commitment, body) {
                Ok(block) => block,
                Err(BoundaryBlockError::Decode(err)) => {
                    commonware_p2p::block!(
                        self.blocker,
                        peer,
                        ?err,
                        "invalid bootstrap boundary block"
                    );
                    Self::request_next_block(&mut pending, boundary_sender);
                    self.pending = Some(pending);
                    return true;
                }
                Err(BoundaryBlockError::Commitment) => {
                    commonware_p2p::block!(self.blocker, peer, "invalid bootstrap boundary block");
                    Self::request_next_block(&mut pending, boundary_sender);
                    self.pending = Some(pending);
                    return true;
                }
            };

        let Some(artifact) = self.artifact_from_block(&pending, candidate.finalization, block)
        else {
            commonware_p2p::block!(self.blocker, peer, "invalid bootstrap boundary block");
            Self::request_next_block(&mut pending, boundary_sender);
            self.pending = Some(pending);
            return true;
        };
        self.resolve(artifact);
        false
    }

    fn retry_boundary(&mut self, boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>) {
        let pending = self
            .pending
            .as_mut()
            .expect("retry requires pending boundary");
        pending.in_flight = None;
        Self::request_next_block(pending, boundary_sender);
    }

    fn request_next_block(
        pending: &mut Pending<S, V>,
        boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) {
        let Some(candidate) = pending.candidates.pop_front() else {
            debug!(epoch = %pending.epoch, "requesting boundary finalizations");
            Self::request_boundary_finalization(pending.epoch, boundary_sender);
            return;
        };

        let commitment = candidate.finalization.proposal.payload;
        debug!(epoch = %pending.epoch, ?commitment, "requesting boundary block");
        boundary_sender.send(
            Recipients::One(candidate.peer.clone()),
            wire::Message::<S, V>::BlockRequest(pending.epoch).encode(),
            false,
        );
        pending.in_flight = Some(candidate);
    }

    fn artifact_from_block(
        &self,
        pending: &Pending<S, V>,
        finalization: Finalization<S, V::Commitment>,
        block: V::Block,
    ) -> Option<ActorArtifact<S, V>> {
        if block.height() != pending.height {
            return None;
        }

        let block = V::into_inner(block);
        let Some(Payload::EpochInfo(info)) = block.payload() else {
            return None;
        };
        if info.epoch != pending.epoch {
            return None;
        }

        Some(Artifact {
            finalization: Some(finalization),
            info,
            floor: self
                .sample
                .floor()
                .cloned()
                .expect("boundary fetch requires a selected floor"),
        })
    }

    fn resolve(&mut self, artifact: ActorArtifact<S, V>) {
        self.pending = None;
        self.subscribers.drain(..).for_each(|subscriber| {
            subscriber.send_lossy(artifact.clone());
        });
        self.artifact = Some(artifact);
    }
}

fn authenticate_boundary_block<V: Variant>(
    block_codec_config: &<V::ApplicationBlock as Read>::Cfg,
    commitment: V::Commitment,
    body: impl Buf,
) -> Result<V::Block, BoundaryBlockError> {
    let block = wire::read_block::<V>(body, commitment, block_codec_config)
        .map_err(BoundaryBlockError::Decode)?;
    if V::commitment(&block) != commitment {
        return Err(BoundaryBlockError::Commitment);
    }
    Ok(block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::tests::mocks;
    use commonware_coding::ReedSolomon;
    use commonware_consensus::{
        CertifiableBlock,
        marshal::coding::{
            Coding,
            types::{CodedBlock, coding_config_for_participants},
        },
        simplex::{
            scheme::bls12381_threshold::vrf::Scheme as ThresholdScheme,
            types::{Finalization, Finalize, Proposal},
        },
        types::{Epoch, Height, Round, View, coding::Commitment},
    };
    use commonware_cryptography::{
        Digest as _, Digestible as _, Hasher as _, bls12381::primitives::variant::MinPk,
        sha256::Sha256,
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, deterministic};
    use std::time::Duration;

    const THRESHOLD_NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_DKG_PROBE_DISCOVERY_TEST";

    type CodingContext =
        commonware_consensus::simplex::types::Context<Commitment, mocks::TestPublicKey>;
    type CodingBlock = mocks::MockBlock<mocks::TestDigest, CodingContext>;
    type TestCodingVariant = Coding<CodingBlock, ReedSolomon<Sha256>, Sha256, mocks::TestPublicKey>;
    type TestThresholdScheme = ThresholdScheme<mocks::TestPublicKey, MinPk>;

    impl CertifiableBlock for CodingBlock {
        type Context = CodingContext;

        fn context(&self) -> Self::Context {
            self.context().clone()
        }
    }

    fn finalization<S, D>(proposal: Proposal<D>, schemes: &[S]) -> Finalization<S, D>
    where
        D: commonware_cryptography::Digest,
        S: commonware_consensus::simplex::scheme::Scheme<D>,
    {
        let finalizes = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect::<Vec<_>>();
        Finalization::from_finalizes(&schemes[0], &finalizes, &Sequential)
            .expect("finalization quorum")
    }

    fn decode_finalization_response<S, V>(
        message: &[u8],
        verifier: &S,
    ) -> Finalization<S, V::Commitment>
    where
        S: Scheme<V::Commitment>,
        V: Variant,
    {
        match wire::read_response::<S, V, _>(message, &verifier.certificate_codec_config())
            .expect("response decoded")
            .expect("response tag")
        {
            wire::Response::Boundary(finalization) => finalization,
            wire::Response::Block { .. } | wire::Response::Latest(_) => {
                panic!("expected finalization response")
            }
        }
    }

    fn split_block_response<'a, S, V>(message: &'a [u8], verifier: &S) -> (Epoch, &'a [u8])
    where
        S: Scheme<V::Commitment>,
        V: Variant,
    {
        match wire::read_response::<S, V, _>(message, &verifier.certificate_codec_config())
            .expect("response decoded")
            .expect("response tag")
        {
            wire::Response::Block { epoch, body } => (epoch, body),
            wire::Response::Boundary(_) | wire::Response::Latest(_) => {
                panic!("expected block response")
            }
        }
    }

    fn threshold_fixture(
        context: &mut deterministic::Context,
    ) -> commonware_cryptography::certificate::mocks::Fixture<TestThresholdScheme> {
        commonware_consensus::simplex::scheme::bls12381_threshold::vrf::fixture::<MinPk, _>(
            context,
            THRESHOLD_NAMESPACE,
            4,
        )
    }

    fn coding_block(
        leader: mocks::TestPublicKey,
        participants: u16,
    ) -> CodedBlock<CodingBlock, ReedSolomon<Sha256>, Sha256> {
        let parent = Sha256::hash(&[b"parent"]);
        let context = CodingContext {
            round: Round::new(Epoch::zero(), View::new(1)),
            leader,
            parent: (
                View::zero(),
                Commitment::from((
                    mocks::TestDigest::EMPTY,
                    mocks::TestDigest::EMPTY,
                    mocks::TestDigest::EMPTY,
                    coding_config_for_participants(participants),
                )),
            ),
        };
        let block = CodingBlock::new::<Sha256>(context, parent, Height::new(1), 0);
        CodedBlock::new(
            block,
            coding_config_for_participants(participants),
            &Sequential,
        )
    }

    #[test]
    fn invalid_coding_finalization_is_rejected_before_block_request() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|mut context| async move {
            let fixture = threshold_fixture(&mut context);
            let verifier = TestThresholdScheme::certificate_verifier(
                THRESHOLD_NAMESPACE,
                *fixture.verifier.identity(),
            );
            let block = coding_block(
                fixture.participants[0].clone(),
                fixture
                    .participants
                    .len()
                    .try_into()
                    .expect("participant count fits u16"),
            );
            let payload = TestCodingVariant::commitment(&block);
            let mut finalization = finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(1)),
                    View::zero(),
                    payload,
                ),
                &fixture.schemes,
            );
            finalization.proposal.payload = Commitment::from((
                Sha256::hash(&[b"tampered block"]),
                Sha256::hash(&[b"tampered root"]),
                Sha256::hash(&[b"tampered context"]),
                coding_config_for_participants(
                    fixture
                        .participants
                        .len()
                        .try_into()
                        .expect("participant count fits u16"),
                ),
            ));
            let message = wire::Message::<TestThresholdScheme, TestCodingVariant>::BoundaryResponse(
                finalization,
            )
            .encode()
            .to_vec();
            let finalization = decode_finalization_response::<
                TestThresholdScheme,
                TestCodingVariant,
            >(&message, &verifier);
            let authenticated = finalization.verify(&mut context, &verifier, &Sequential);

            assert!(!authenticated);
        });
    }

    #[test]
    fn valid_standard_block_decodes_after_finalization_authentication() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|mut context| async move {
            let fixture = mocks::scheme_fixture_n(&mut context, 4);
            let block = mocks::genesis_block(fixture.participants[0].clone());
            let finalization = finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(1)),
                    View::zero(),
                    block.digest(),
                ),
                &fixture.schemes,
            );
            let finalization_message = wire::Message::<
                mocks::TestScheme,
                mocks::TestMarshalVariant,
            >::BoundaryResponse(finalization)
            .encode()
            .to_vec();
            let finalization = decode_finalization_response::<
                mocks::TestScheme,
                mocks::TestMarshalVariant,
            >(&finalization_message, &fixture.schemes[0]);
            let authenticated = finalization.verify(&mut context, &fixture.schemes[0], &Sequential);
            assert!(authenticated);
            let commitment = finalization.proposal.payload;
            let block_message =
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::BlockResponse {
                    epoch: Epoch::zero(),
                    block: block.clone(),
                }
                .encode()
                .to_vec();
            let (epoch, body) = split_block_response::<
                mocks::TestScheme,
                mocks::TestMarshalVariant,
            >(&block_message, &fixture.schemes[0]);
            assert_eq!(epoch, Epoch::zero());
            let decoded =
                authenticate_boundary_block::<mocks::TestMarshalVariant>(&(), commitment, body)
                    .expect("standard block authenticated");

            assert_eq!(decoded, block);
        });
    }

    #[test]
    fn valid_coding_block_decodes_after_finalization_authentication() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|mut context| async move {
            let fixture = mocks::scheme_fixture_n(&mut context, 4);
            let block = coding_block(
                fixture.participants[0].clone(),
                fixture
                    .participants
                    .len()
                    .try_into()
                    .expect("participant count fits u16"),
            );
            let payload = TestCodingVariant::commitment(&block);
            let finalization = finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(1)),
                    View::zero(),
                    payload,
                ),
                &fixture.schemes,
            );
            let finalization_message =
                wire::Message::<mocks::TestScheme, TestCodingVariant>::BoundaryResponse(
                    finalization,
                )
                .encode()
                .to_vec();
            let finalization = decode_finalization_response::<mocks::TestScheme, TestCodingVariant>(
                &finalization_message,
                &fixture.schemes[0],
            );
            let authenticated = finalization.verify(&mut context, &fixture.schemes[0], &Sequential);
            assert!(authenticated);
            let block_message =
                wire::Message::<mocks::TestScheme, TestCodingVariant>::BlockResponse {
                    epoch: Epoch::zero(),
                    block,
                }
                .encode()
                .to_vec();
            let (epoch, body) = split_block_response::<mocks::TestScheme, TestCodingVariant>(
                &block_message,
                &fixture.schemes[0],
            );
            assert_eq!(epoch, Epoch::zero());
            let commitment = finalization.proposal.payload;
            let decoded = authenticate_boundary_block::<TestCodingVariant>(&(), commitment, body)
                .expect("coding block authenticated");

            assert_eq!(decoded.height(), Height::new(1));
            assert_eq!(TestCodingVariant::commitment(&decoded), payload);
        });
    }

    #[test]
    fn valid_coding_block_decodes_with_certificate_verifier() {
        let runner = deterministic::Runner::timed(Duration::from_secs(5));
        runner.start(|mut context| async move {
            let fixture = threshold_fixture(&mut context);
            let verifier = TestThresholdScheme::certificate_verifier(
                THRESHOLD_NAMESPACE,
                *fixture.verifier.identity(),
            );
            let block = coding_block(
                fixture.participants[0].clone(),
                fixture
                    .participants
                    .len()
                    .try_into()
                    .expect("participant count fits u16"),
            );
            let payload = TestCodingVariant::commitment(&block);
            let finalization = finalization(
                Proposal::new(
                    Round::new(Epoch::zero(), View::new(1)),
                    View::zero(),
                    payload,
                ),
                &fixture.schemes,
            );
            let finalization_message = wire::Message::<
                TestThresholdScheme,
                TestCodingVariant,
            >::BoundaryResponse(finalization)
            .encode()
            .to_vec();
            let finalization = decode_finalization_response::<
                TestThresholdScheme,
                TestCodingVariant,
            >(&finalization_message, &verifier);
            let authenticated = finalization.verify(&mut context, &verifier, &Sequential);
            assert!(authenticated);
            let block_message = wire::Message::<
                TestThresholdScheme,
                TestCodingVariant,
            >::BlockResponse {
                epoch: Epoch::zero(),
                block,
            }
            .encode()
            .to_vec();
            let (epoch, body) = split_block_response::<
                TestThresholdScheme,
                TestCodingVariant,
            >(&block_message, &verifier);
            assert_eq!(epoch, Epoch::zero());
            let commitment = finalization.proposal.payload;
            let decoded = authenticate_boundary_block::<TestCodingVariant>(&(), commitment, body)
                .expect("coding block authenticated");

            assert_eq!(decoded.height(), Height::new(1));
            assert_eq!(TestCodingVariant::commitment(&decoded), payload);
        });
    }
}
