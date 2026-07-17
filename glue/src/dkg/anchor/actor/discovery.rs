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
    simplex::{scheme::Scheme, types::Certificate},
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
use tracing::{debug, warn};

#[derive(Debug)]
enum BoundaryResponseError {
    BlockCommitment,
    Decode(CodecError),
    InvalidFinalization,
}

pub(super) struct Pending {
    height: Height,
    epoch: Epoch,
}

/// The discovery phase of the anchor actor.
///
/// Waits for subscribers, listens to the Simplex certificate channel, and uses
/// the first verifiable target finalization to fetch the previous epoch boundary
/// block. Once the boundary block yields the target epoch's public
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
    pub(super) pending: Option<Pending>,
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
                self.handle_boundary_response(peer, message);
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
                        debug!(%epoch, "re-requesting boundary block");
                        Self::request_boundary(epoch, &mut boundary_sender);
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
        Self::request_boundary(finalization.epoch(), boundary_sender);
        self.pending = Some(Pending {
            height,
            epoch: finalization.epoch(),
        });
        true
    }

    /// Broadcast a request for the boundary block of `epoch` to all peers.
    fn request_boundary(epoch: Epoch, boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>) {
        boundary_sender.send(
            Recipients::All,
            wire::Message::<S, V>::Request(epoch).encode(),
            false,
        );
    }

    fn handle_boundary_response(&mut self, peer: S::PublicKey, message: impl Buf) {
        let Some(pending) = self.pending.take() else {
            return;
        };

        let response = match wire::read_response_finalization::<S, V, _>(
            message,
            &self.verifier.certificate_codec_config(),
        ) {
            Ok(Some(response)) => response,
            Ok(None) => {
                self.pending = Some(pending);
                return;
            }
            Err(err) => {
                commonware_p2p::block!(
                    self.blocker,
                    peer,
                    ?err,
                    "invalid bootstrap boundary response"
                );
                self.pending = Some(pending);
                return;
            }
        };
        let finalization = response.finalization;
        let body = response.body;

        let Some(expected_finalization_epoch) = pending.epoch.previous() else {
            commonware_p2p::block!(self.blocker, peer, "invalid bootstrap boundary response");
            self.pending = Some(pending);
            return;
        };

        let response_finalization_epoch = finalization.epoch();
        if response_finalization_epoch < expected_finalization_epoch {
            debug!(
                response_finalization_epoch = %response_finalization_epoch,
                pending_epoch = %pending.epoch,
                "ignoring stale bootstrap boundary response"
            );
            self.pending = Some(pending);
            return;
        }

        if response_finalization_epoch != expected_finalization_epoch {
            commonware_p2p::block!(self.blocker, peer, "invalid bootstrap boundary response");
            self.pending = Some(pending);
            return;
        }

        let response = match authenticate_boundary_response::<_, S, V, _>(
            self.context.as_present_mut(),
            &self.verifier,
            &self.strategy,
            &self.block_codec_config,
            finalization,
            body,
        ) {
            Ok(response) => response,
            Err(BoundaryResponseError::Decode(err)) => {
                commonware_p2p::block!(
                    self.blocker,
                    peer,
                    ?err,
                    "invalid bootstrap boundary response"
                );
                self.pending = Some(pending);
                return;
            }
            Err(
                BoundaryResponseError::BlockCommitment | BoundaryResponseError::InvalidFinalization,
            ) => {
                commonware_p2p::block!(self.blocker, peer, "invalid bootstrap boundary response");
                self.pending = Some(pending);
                return;
            }
        };

        match self.artifact_from_response(&pending, response) {
            Some(artifact) => self.resolve(artifact),
            None => {
                commonware_p2p::block!(self.blocker, peer, "invalid bootstrap boundary response");
                self.pending = Some(pending);
            }
        }
    }

    fn artifact_from_response(
        &mut self,
        pending: &Pending,
        response: wire::Response<S, V>,
    ) -> Option<ActorArtifact<S, V>> {
        if response.block.height() != pending.height {
            return None;
        }

        let block = V::into_inner(response.block);
        let Some(Payload::EpochInfo(info)) = block.payload() else {
            return None;
        };
        if info.epoch != pending.epoch {
            return None;
        }

        Some(Artifact {
            epoch: info.epoch,
            finalization: Some(response.finalization),
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

fn authenticate_boundary_response<R, S, V, T>(
    rng: &mut R,
    verifier: &S,
    strategy: &T,
    block_codec_config: &<V::ApplicationBlock as Read>::Cfg,
    finalization: commonware_consensus::simplex::types::Finalization<S, V::Commitment>,
    body: impl Buf,
) -> Result<wire::Response<S, V>, BoundaryResponseError>
where
    R: CryptoRng,
    S: Scheme<V::Commitment>,
    V: Variant,
    T: Strategy,
{
    if !finalization.verify(rng, verifier, strategy) {
        return Err(BoundaryResponseError::InvalidFinalization);
    }

    let response = wire::read_response_block(body, finalization, block_codec_config)
        .map_err(BoundaryResponseError::Decode)?;
    if V::commitment(&response.block) != response.finalization.proposal.payload {
        return Err(BoundaryResponseError::BlockCommitment);
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::tests::mocks;
    use commonware_codec::Write as _;
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

    fn split_response<'a, S, V>(
        message: &'a [u8],
        verifier: &S,
    ) -> (Finalization<S, V::Commitment>, &'a [u8])
    where
        S: Scheme<V::Commitment>,
        V: Variant,
    {
        let response = wire::read_response_finalization::<S, V, _>(
            message,
            &verifier.certificate_codec_config(),
        )
        .expect("response decoded")
        .expect("response tag");
        (response.finalization, response.body)
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
    fn invalid_coding_finalization_is_rejected_before_block_decode() {
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
            let mut message = Vec::new();
            wire::Tag::Response.write(&mut message);
            finalization.write(&mut message);
            message.extend_from_slice(b"body must not be decoded");

            let (finalization, body) =
                split_response::<TestThresholdScheme, TestCodingVariant>(&message, &verifier);
            let result =
                authenticate_boundary_response::<_, TestThresholdScheme, TestCodingVariant, _>(
                    &mut context,
                    &verifier,
                    &Sequential,
                    &(),
                    finalization,
                    body,
                );

            assert!(matches!(
                result,
                Err(BoundaryResponseError::InvalidFinalization)
            ));
        });
    }

    #[test]
    fn valid_standard_response_decodes_after_authentication() {
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
            let message = wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::Response(
                wire::Response {
                    finalization,
                    block: block.clone(),
                },
            )
            .encode()
            .to_vec();
            let (finalization, body) =
                split_response::<mocks::TestScheme, mocks::TestMarshalVariant>(
                    &message,
                    &fixture.schemes[0],
                );

            let response = authenticate_boundary_response::<
                _,
                mocks::TestScheme,
                mocks::TestMarshalVariant,
                _,
            >(
                &mut context,
                &fixture.schemes[0],
                &Sequential,
                &(),
                finalization,
                body,
            )
            .expect("standard response authenticated");

            assert_eq!(response.block, block);
        });
    }

    #[test]
    fn valid_coding_response_decodes_after_authentication() {
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
            let message =
                wire::Message::<mocks::TestScheme, TestCodingVariant>::Response(wire::Response {
                    finalization,
                    block,
                })
                .encode()
                .to_vec();
            let (finalization, body) = split_response::<mocks::TestScheme, TestCodingVariant>(
                &message,
                &fixture.schemes[0],
            );

            let response =
                authenticate_boundary_response::<_, mocks::TestScheme, TestCodingVariant, _>(
                    &mut context,
                    &fixture.schemes[0],
                    &Sequential,
                    &(),
                    finalization,
                    body,
                )
                .expect("coding response authenticated");

            assert_eq!(response.block.height(), Height::new(1));
            assert_eq!(TestCodingVariant::commitment(&response.block), payload);
        });
    }

    #[test]
    fn valid_coding_response_decodes_with_certificate_verifier() {
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
            let message =
                wire::Message::<TestThresholdScheme, TestCodingVariant>::Response(wire::Response {
                    finalization,
                    block,
                })
                .encode()
                .to_vec();
            let (finalization, body) =
                split_response::<TestThresholdScheme, TestCodingVariant>(&message, &verifier);

            let response =
                authenticate_boundary_response::<_, TestThresholdScheme, TestCodingVariant, _>(
                    &mut context,
                    &verifier,
                    &Sequential,
                    &(),
                    finalization,
                    body,
                )
                .expect("coding response authenticated");

            assert_eq!(response.block.height(), Height::new(1));
            assert_eq!(TestCodingVariant::commitment(&response.block), payload);
        });
    }
}
