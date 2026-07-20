use super::serving::Serving;
use crate::dkg::{
    ReshareBlock,
    anchor::{ActorArtifact, Artifact, mailbox::Message, wire},
    types::{EpochInfo, Payload},
};
use bytes::Buf;
use commonware_actor::mailbox::Receiver as ActorReceiver;
use commonware_codec::{Decode as _, Encode as _, Error as CodecError, Read};
use commonware_consensus::{
    Epochable, Heightable,
    marshal::core::Variant,
    simplex::{
        scheme::Scheme,
        types::{Certificate, Finalization},
    },
    types::{Epoch, Epocher, FixedEpocher, Height},
};
use commonware_cryptography::Signer;
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Channel, Message as P2pMessage, Receiver, Recipients, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner};
use commonware_utils::{
    NonZeroDuration,
    channel::{fallible::OneshotExt as _, mpsc, oneshot},
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

/// The discovery phase of the anchor actor.
///
/// Waits for subscribers, listens to the Simplex certificate channel, and uses
/// the first verifiable target finalization to discover the previous epoch's
/// boundary finalization. It then fetches the committed block from one responder.
/// Once the boundary block yields the target epoch's public
/// [`Artifact`], discovery resolves all subscribers and can hand off to
/// [`Serving`] after marshal is attached.
pub(super) struct Discovery<E, S, V, T, B>
where
    E: Spawner + CryptoRng + Clock + Metrics,
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    <V::ApplicationBlock as ReshareBlock>::Signer: Signer<PublicKey = S::PublicKey>,
    T: Strategy,
    B: Blocker<PublicKey = S::PublicKey>,
{
    pub(super) context: ContextCell<E>,
    pub(super) mailbox: ActorReceiver<Message<S, V>>,
    pub(super) verifier: S,
    pub(super) genesis: EpochInfo<<V::ApplicationBlock as ReshareBlock>::Variant, S::PublicKey>,
    pub(super) strategy: T,
    pub(super) blocker: B,
    pub(super) epocher: FixedEpocher,
    pub(super) block_codec_config: <V::ApplicationBlock as Read>::Cfg,
    pub(super) retry_timeout: NonZeroDuration,
    pub(super) artifact: Option<ActorArtifact<S, V>>,
    pub(super) subscribers: Vec<oneshot::Sender<ActorArtifact<S, V>>>,
    pub(super) pending: Option<Pending<S, V>>,
}

impl<E, S, V, T, B> Discovery<E, S, V, T, B>
where
    E: Spawner + CryptoRng + Clock + Metrics,
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock,
    <V::ApplicationBlock as ReshareBlock>::Signer: Signer<PublicKey = S::PublicKey>,
    T: Strategy,
    B: Blocker<PublicKey = S::PublicKey>,
{
    /// Runs discovery until shutdown or until it can hand off to [`Serving`].
    pub(super) async fn run<BSE, BRE>(
        mut self,
        mut certificate_receiver: mpsc::Receiver<(Channel, P2pMessage<S::PublicKey>)>,
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

                // Arm the retry timer only while a boundary request is outstanding.
                let retry = if self.pending.is_some() && self.artifact.is_none() {
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
                Message::Subscribe { response } => self.subscribe(response),
                Message::Attach { marshal: attached } => {
                    marshal = Some(attached);
                }
            },
            Some((_channel, (peer, message))) = certificate_receiver.recv() else {
                debug!("certificate receiver closed, shutting down");
                return;
            } => {
                if self.handle_certificate(peer, message, &mut boundary_sender) {
                    deadline = self.context.current() + self.retry_timeout.get();
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
                if let Some(epoch) = self.pending.as_ref().map(|pending| pending.epoch) {
                    if epoch.is_zero() {
                        // The genesis grace elapsed with no strictly-newer
                        // finalization; resolve from the locally known genesis.
                        let artifact = Artifact {
                            epoch: Epoch::zero(),
                            finalization: None,
                            info: self.genesis.clone(),
                        };
                        self.resolve(artifact);
                        self.pending = None;
                    } else {
                        self.retry_boundary(&mut boundary_sender);
                        deadline = self.context.current() + self.retry_timeout.get();
                    }
                }
            },
        }

        Serving {
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

    fn subscribe(&mut self, response: oneshot::Sender<ActorArtifact<S, V>>) {
        if let Some(artifact) = &self.artifact {
            response.send_lossy(artifact.clone());
            return;
        }
        self.subscribers.push(response);
    }

    /// Handle an incoming certificate, returning whether a boundary request was
    /// broadcast (so the caller can arm the retry timer).
    fn handle_certificate(
        &mut self,
        peer: S::PublicKey,
        message: impl Buf,
        boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) -> bool {
        if self.artifact.is_some() || self.subscribers.is_empty() {
            return false;
        }

        let certificate = match Certificate::<S, V::Commitment>::decode_cfg(
            message,
            &self.verifier.certificate_codec_config(),
        ) {
            Ok(certificate) => certificate,
            Err(err) => {
                commonware_p2p::block!(self.blocker, peer, ?err, "invalid bootstrap certificate");
                return false;
            }
        };
        let Certificate::Finalization(finalization) = certificate else {
            return false;
        };
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| finalization.epoch() <= pending.epoch)
        {
            return false;
        }
        if !finalization.verify(
            self.context.as_present_mut(),
            &self.verifier,
            &self.strategy,
        ) {
            commonware_p2p::block!(self.blocker, peer, "invalid bootstrap finalization");
            return false;
        }
        if finalization.epoch().is_zero() {
            // Genesis needs no boundary block, but a strictly-newer finalization
            // must still be able to supersede a replayed epoch-zero candidate.
            // Record it as a pending candidate and resolve from local genesis only
            // once the retry window elapses with nothing newer, matching the
            // supersede window every non-zero epoch already gets.
            self.pending = Some(Pending {
                height: Height::zero(),
                epoch: Epoch::zero(),
                in_flight: None,
                candidates: VecDeque::new(),
            });
            return true;
        }

        let Some(height) = finalization
            .epoch()
            .previous()
            .and_then(|e| self.epocher.last(e))
        else {
            warn!(
                epoch = %finalization.epoch(),
                "bootstrap finalization epoch has no boundary height"
            );
            return false;
        };
        Self::request_boundary_finalization(finalization.epoch(), boundary_sender);
        self.pending = Some(Pending {
            height,
            epoch: finalization.epoch(),
            in_flight: None,
            candidates: VecDeque::new(),
        });
        true
    }

    /// Broadcast a request for the boundary finalization of `epoch` to all peers.
    fn request_boundary_finalization(
        epoch: Epoch,
        boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) {
        boundary_sender.send(
            Recipients::All,
            wire::Message::<S, V>::FinalizationRequest(epoch).encode(),
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
        if self.pending.is_none() {
            return false;
        }

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
            wire::Response::Finalization(finalization) => {
                self.handle_boundary_finalization(peer, finalization, boundary_sender)
            }
            wire::Response::Block { epoch, body } => {
                self.handle_boundary_block(peer, epoch, body, boundary_sender)
            }
        }
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

        let Some(artifact) = Self::artifact_from_block(&pending, candidate.finalization, block)
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
            epoch: info.epoch,
            finalization: Some(finalization),
            info,
        })
    }

    fn resolve(&mut self, artifact: ActorArtifact<S, V>) {
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

    const THRESHOLD_NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_DKG_ANCHOR_DISCOVERY_TEST";

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
            wire::Response::Finalization(finalization) => finalization,
            wire::Response::Block { .. } => panic!("expected finalization response"),
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
            wire::Response::Finalization(_) => panic!("expected block response"),
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
        let parent = Sha256::hash(b"parent");
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
                Sha256::hash(b"tampered block"),
                Sha256::hash(b"tampered root"),
                Sha256::hash(b"tampered context"),
                coding_config_for_participants(
                    fixture
                        .participants
                        .len()
                        .try_into()
                        .expect("participant count fits u16"),
                ),
            ));
            let message = wire::Message::<TestThresholdScheme, TestCodingVariant>::FinalizationResponse(
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
            >::FinalizationResponse(finalization)
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
                wire::Message::<mocks::TestScheme, TestCodingVariant>::FinalizationResponse(
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
            >::FinalizationResponse(finalization)
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
