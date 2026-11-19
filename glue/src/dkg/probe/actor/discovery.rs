use super::service::Service;
use crate::{
    dkg::{
        ReshareBlock,
        network::Manager,
        probe::{ActorArtifact, Artifact, Bootstrap, mailbox::Message, wire},
        types::{EpochInfo, Payload},
    },
    stateful::probe::sample::Sample,
};
use commonware_actor::mailbox::Receiver as ActorReceiver;
use commonware_codec::{Buf, Encode as _, Read};
use commonware_consensus::{
    Epochable, Heightable,
    marshal::core::Variant,
    simplex::{scheme::Scheme, types::Finalization},
    types::{Epoch, Epocher, FixedEpocher, Height},
};
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Receiver, Recipients, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, ContextCell, Metrics, Spawner};
use commonware_utils::{
    NonZeroDuration,
    channel::{fallible::OneshotExt as _, oneshot},
};
use futures::future::{self, Either};
use rand_core::CryptoRng;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    time::SystemTime,
};
use tracing::{debug, warn};

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
    floor: Finalization<S, V::Commitment>,
    retry_at: SystemTime,
    in_flight: Option<S::PublicKey>,
    candidates: VecDeque<Candidate<S, V>>,
    // A peer can enter the queue only once per pass.
    seen: BTreeSet<S::PublicKey>,
    // Keep the certificates for requests from previous passes so late blocks still match.
    requested: BTreeMap<S::PublicKey, Finalization<S, V::Commitment>>,
}

impl<S, V> Pending<S, V>
where
    S: Scheme<V::Commitment>,
    V: Variant,
{
    fn epoch(&self) -> Epoch {
        self.floor.epoch()
    }

    /// Starts another pass if the current one has no remaining candidates.
    /// Returns whether it started a pass.
    fn retry(
        &mut self,
        retry_at: SystemTime,
        sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) -> bool {
        self.in_flight = None;
        if self.request_next_block(retry_at, sender) {
            return false;
        }

        self.seen.clear();
        self.request_boundary(retry_at, sender);
        true
    }

    fn request_boundary(
        &mut self,
        retry_at: SystemTime,
        sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) {
        let epoch = self.epoch();
        debug!(%epoch, "requesting boundary finalizations");
        sender.send(
            Recipients::All,
            wire::Message::<S, V>::BoundaryRequest(epoch).encode(),
            false,
        );
        self.retry_at = retry_at;
    }

    fn request_next_block(
        &mut self,
        retry_at: SystemTime,
        sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) -> bool {
        let Some(Candidate { peer, finalization }) = self.candidates.pop_front() else {
            return false;
        };
        let epoch = self.epoch();
        // Keep the first proof so a retry can still accept a reply to an earlier request.
        let finalization = self.requested.entry(peer.clone()).or_insert(finalization);
        debug!(%epoch, commitment = ?finalization.proposal.payload, "requesting boundary block");
        sender.send(
            Recipients::One(peer.clone()),
            wire::Message::<S, V>::BlockRequest(epoch).encode(),
            false,
        );
        self.in_flight = Some(peer);
        self.retry_at = retry_at;
        true
    }
}

/// Discovery phase of the probe actor (see the
/// [module docs](crate::dkg::probe#protocol)).
pub(super) struct Discovery<E, M, S, V, T, B>
where
    E: Spawner + CryptoRng + Clock + Metrics,
    M: Manager<
            PublicKey = S::PublicKey,
            Directory = <V::ApplicationBlock as ReshareBlock>::Directory,
        >,
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock<PublicKey = S::PublicKey>,
    T: Strategy,
    B: Blocker<PublicKey = S::PublicKey>,
{
    pub(super) context: ContextCell<E>,
    pub(super) mailbox: ActorReceiver<Message<S, V>>,
    pub(super) manager: M,
    pub(super) bootstrap: Bootstrap<S::PublicKey, <V::ApplicationBlock as ReshareBlock>::Directory>,
    pub(super) verifier: S,
    pub(super) genesis: EpochInfo<
        <V::ApplicationBlock as ReshareBlock>::Variant,
        S::PublicKey,
        <V::ApplicationBlock as ReshareBlock>::Directory,
    >,
    pub(super) strategy: T,
    pub(super) blocker: B,
    pub(super) epocher: FixedEpocher,
    pub(super) block_codec_config: <V::ApplicationBlock as Read>::Cfg,
    pub(super) retry_timeout: NonZeroDuration,
    pub(super) artifact: Option<ActorArtifact<S, V>>,
    pub(super) sample: Sample<S, V::Commitment>,
    pub(super) subscribers: Vec<oneshot::Sender<ActorArtifact<S, V>>>,
    pub(super) pending: Option<Pending<S, V>>,
    pub(super) fallback: Option<Pending<S, V>>,
}

impl<E, M, S, V, T, B> Discovery<E, M, S, V, T, B>
where
    E: Spawner + CryptoRng + Clock + Metrics,
    M: Manager<
            PublicKey = S::PublicKey,
            Directory = <V::ApplicationBlock as ReshareBlock>::Directory,
        >,
    S: Scheme<V::Commitment>,
    V: Variant,
    V::ApplicationBlock: ReshareBlock<PublicKey = S::PublicKey>,
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
        let mut attached = None;
        let mut sample_retry_at = self.context.current() + self.retry_timeout.get();

        select_loop! {
            self.context,
            on_start => {
                self.subscribers
                    .retain(|subscriber| !subscriber.is_closed());
                if attached.is_some() && self.subscribers.is_empty() {
                    break;
                }

                // Arm the retry timer only while actively discovering.
                let retry = if self.artifact.is_none() && !self.subscribers.is_empty() {
                    let deadline = self.pending.iter().chain(&self.fallback)
                        .map(|pending| pending.retry_at)
                        .min()
                        .unwrap_or(sample_retry_at);
                    Either::Left(self.context.sleep_until(deadline))
                } else {
                    Either::Right(future::pending())
                };
            },
            on_stopped => {
                debug!("shutdown signal received");
                return;
            },
            _ = retry => {
                let now = self.context.current();
                let retry_at = now + self.retry_timeout.get();
                if let Some(pending) = &mut self.pending {
                    if now >= pending.retry_at && pending.retry(retry_at, &mut boundary_sender) {
                        debug!(epoch = %pending.epoch(), "responder pass exhausted, re-soliciting latest finalizations");
                        self.request_latest(&mut boundary_sender);
                    }
                } else if self.sample.floor().is_none() {
                    debug!(reason = "deadline elapsed", "re-soliciting latest finalizations");
                    self.request_latest(&mut boundary_sender);
                    sample_retry_at = retry_at;
                }
                if let Some(fallback) = &mut self.fallback
                    && now >= fallback.retry_at
                {
                    fallback.retry(retry_at, &mut boundary_sender);
                }
            },
            Some(message) = self.mailbox.recv() else {
                debug!("mailbox closed, shutting down");
                return;
            } => match message {
                Message::Subscribe { response } => {
                    match self.subscribe(response, &mut boundary_sender) {
                        Ok(true) => {
                            sample_retry_at = self.context.current() + self.retry_timeout.get();
                        }
                        Ok(false) => {}
                        Err(error) => {
                            warn!(
                                epoch = %self.bootstrap.epoch,
                                %error,
                                "failed to activate bootstrap peer set, shutting down",
                            );
                            return;
                        }
                    }
                }
                Message::Attach { marshal: attached_marshal, plan: attached_plan } => {
                    attached = Some((attached_marshal, attached_plan));
                }
            },
            Ok((peer, message)) = boundary_receiver.recv() else {
                debug!("boundary receiver closed, shutting down");
                return;
            } => {
                self.handle_boundary_response(peer, message, &mut boundary_sender).await;
            },
        }

        let (marshal, plan) = attached.expect("marshal and plan must be attached before serving");
        Service {
            context: self.context,
            mailbox: self.mailbox,
            marshal,
            plan,
            blocker: self.blocker,
            artifact: self.artifact,
        }
        .run(boundary_sender, boundary_receiver)
        .await;
    }

    /// Handles a subscriber and returns whether it started a solicitation.
    ///
    /// Answers the subscriber immediately if the artifact is known. Returns an
    /// error if the bootstrap snapshot cannot be activated.
    fn subscribe(
        &mut self,
        response: oneshot::Sender<ActorArtifact<S, V>>,
        boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) -> Result<bool, M::Error> {
        if let Some(artifact) = &self.artifact {
            response.send_lossy(artifact.clone());
            return Ok(false);
        }
        let solicit = self.subscribers.is_empty() && self.pending.is_none();
        self.subscribers.push(response);
        if solicit {
            // Activate the snapshot only when soliciting: a node that never
            // bootstraps must not claim a peer-set ID above the epochs its
            // orchestrator still enters. A later orchestrator activation of this
            // epoch has identical contents.
            self.manager.track(
                self.bootstrap.epoch,
                self.bootstrap.participants.tracked_peers(),
                &self.bootstrap.directory,
            )?;
            self.request_latest(boundary_sender);
        }
        Ok(solicit)
    }

    /// Clears collected replies and solicits the snapshot dealers' latest
    /// finalizations.
    fn request_latest(&mut self, boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>) {
        self.sample.reset();
        boundary_sender.send(
            Recipients::Some(
                self.bootstrap
                    .participants
                    .dealers
                    .iter()
                    .cloned()
                    .collect(),
            ),
            wire::Message::<S, V>::LatestRequest.encode(),
            false,
        );
    }

    /// Handles a probe response.
    async fn handle_boundary_response(
        &mut self,
        peer: S::PublicKey,
        message: impl Buf,
        boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) {
        let response = match wire::read_response::<S, V, _>(
            message,
            &self.verifier.certificate_codec_config(),
        ) {
            Ok(Some(response)) => response,
            Ok(None) => return,
            Err(err) => {
                commonware_p2p::block!(
                    self.blocker,
                    peer,
                    ?err,
                    "invalid bootstrap boundary response"
                );
                return;
            }
        };

        match response {
            wire::Response::Latest(finalization) => {
                self.handle_latest(peer, finalization, boundary_sender)
            }
            wire::Response::Boundary(finalization) => {
                self.handle_boundary_finalization(peer, finalization, boundary_sender)
            }
            wire::Response::Block { epoch, body } => {
                self.handle_boundary_block(peer, epoch, body, boundary_sender)
                    .await
            }
        }
    }

    /// Records a latest-finalization reply that passes the discovery rules (see
    /// the [module docs](crate::dkg::probe#protocol)).
    fn handle_latest(
        &mut self,
        peer: S::PublicKey,
        finalization: Finalization<S, V::Commitment>,
        boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) {
        // Once the floor is selected or the peer has contributed this request
        // round, further replies are ignored without verification.
        if self.subscribers.is_empty() || !self.sample.awaits(&peer) {
            return;
        }
        if self
            .bootstrap
            .participants
            .dealers
            .position(&peer)
            .is_none()
        {
            commonware_p2p::block!(self.blocker, peer, "latest finalization from non-member");
            return;
        }
        if finalization.epoch() < self.sample.minimum_epoch() {
            debug!(
                epoch = %finalization.epoch(),
                minimum_epoch = %self.sample.minimum_epoch(),
                "ignoring latest finalization below minimum epoch"
            );
            return;
        }
        if !finalization.verify(
            self.context.as_present_mut(),
            &self.verifier,
            &self.strategy,
        ) {
            commonware_p2p::block!(self.blocker, peer, "invalid latest finalization");
            return;
        }
        self.sample.record(peer, finalization);
        self.select(boundary_sender);
    }

    /// Selects the highest finalization once `f + 1` distinct dealers have
    /// replied and starts a boundary fetch if the epoch is new.
    fn select(&mut self, boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>) {
        // Every recorded reply was verified under the all-epoch verifier.
        let Some(floor) = self
            .sample
            .select(self.bootstrap.participants.dealers.len(), |_| true)
        else {
            return;
        };
        let target = floor.epoch();
        if let Some(pending) = &mut self.pending
            && target <= pending.epoch()
        {
            // A newer round in the same epoch uses the same boundary fetch.
            for fetch in std::iter::once(pending).chain(self.fallback.iter_mut()) {
                if target == fetch.epoch() && floor.round() > fetch.floor.round() {
                    fetch.floor = floor;
                    break;
                }
            }
            return;
        }

        if target.is_zero() {
            // Epoch zero is anchored by genesis and has no boundary block.
            self.resolve(Artifact {
                finalization: None,
                info: self.genesis.clone(),
                floor,
            });
            return;
        }

        let Some(height) = target.previous().and_then(|epoch| self.epocher.last(epoch)) else {
            // Unreachable without a forged quorum: re-sample rather than wedge.
            warn!(epoch = %target, "sampled floor epoch has no boundary height");
            self.sample.reset();
            return;
        };
        let retry_at = self.context.current() + self.retry_timeout.get();
        let mut pending = Pending {
            height,
            floor,
            retry_at,
            in_flight: None,
            candidates: VecDeque::new(),
            seen: BTreeSet::new(),
            requested: BTreeMap::new(),
        };
        pending.request_boundary(retry_at, boundary_sender);
        // A newer finalization does not mean a reachable peer can serve its checkpoint.
        self.fallback = self.pending.replace(pending);
    }

    fn handle_boundary_finalization(
        &mut self,
        peer: S::PublicKey,
        finalization: Finalization<S, V::Commitment>,
        boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) {
        let Some(primary) = &mut self.pending else {
            return;
        };
        let response_finalization_epoch = finalization.epoch();
        let primary_boundary_epoch = primary.epoch().previous().expect("non-genesis fetch");
        let pending = if response_finalization_epoch == primary_boundary_epoch {
            primary
        } else if let Some(fallback) = &mut self.fallback
            && fallback.epoch().previous() == Some(response_finalization_epoch)
        {
            fallback
        } else {
            // A delayed response for a retired epoch is harmless.
            if response_finalization_epoch > primary_boundary_epoch {
                commonware_p2p::block!(self.blocker, peer, "invalid bootstrap boundary response");
            }
            return;
        };
        if pending.seen.contains(&peer) {
            return;
        }

        if !finalization.verify(
            self.context.as_present_mut(),
            &self.verifier,
            &self.strategy,
        ) {
            commonware_p2p::block!(self.blocker, peer, "invalid bootstrap boundary response");
            return;
        }

        pending.seen.insert(peer.clone());
        pending
            .candidates
            .push_back(Candidate { peer, finalization });
        if pending.in_flight.is_none() {
            let retry_at = self.context.current() + self.retry_timeout.get();
            pending.request_next_block(retry_at, boundary_sender);
        }
    }

    async fn handle_boundary_block(
        &mut self,
        peer: S::PublicKey,
        epoch: Epoch,
        body: impl Buf,
        boundary_sender: &mut impl Sender<PublicKey = S::PublicKey>,
    ) {
        let Some(pending) = self
            .pending
            .iter_mut()
            .chain(&mut self.fallback)
            .find(|pending| pending.epoch() == epoch)
        else {
            return;
        };
        let Some(finalization) = pending.requested.get(&peer) else {
            return;
        };
        let commitment = finalization.proposal.payload;
        let artifact =
            match wire::read_block::<V>(body, commitment, &self.block_codec_config, &self.strategy)
                .await
            {
                Ok(block) => Self::artifact_from_block(pending, finalization, block),
                Err(err) => {
                    debug!(?err, %epoch, "failed to decode bootstrap boundary block");
                    None
                }
            };
        if let Some(artifact) = artifact {
            self.resolve(artifact);
            return;
        }

        pending.requested.remove(&peer);
        pending
            .candidates
            .retain(|candidate| candidate.peer != peer);
        let was_in_flight = pending.in_flight.as_ref() == Some(&peer);
        commonware_p2p::block!(self.blocker, peer, "invalid bootstrap boundary block");
        if was_in_flight {
            pending.in_flight = None;
            let retry_at = self.context.current() + self.retry_timeout.get();
            pending.request_next_block(retry_at, boundary_sender);
        }
    }

    fn artifact_from_block(
        pending: &Pending<S, V>,
        finalization: &Finalization<S, V::Commitment>,
        block: V::Block,
    ) -> Option<ActorArtifact<S, V>> {
        if block.height() != pending.height {
            return None;
        }

        let block = V::into_shared(block);
        let Some(Payload::EpochInfo(info)) = block.inner().payload() else {
            return None;
        };
        if info.epoch != pending.floor.epoch() {
            return None;
        }

        Some(Artifact {
            finalization: Some(finalization.clone()),
            info,
            floor: pending.floor.clone(),
        })
    }

    fn resolve(&mut self, artifact: ActorArtifact<S, V>) {
        self.pending = None;
        self.fallback = None;
        self.subscribers.drain(..).for_each(|subscriber| {
            subscriber.send_lossy(artifact.clone());
        });
        self.artifact = Some(artifact);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::tests::mocks;
    use bytes::{BufMut, Bytes};
    use commonware_codec::{EncodeSize, Error as CodecError, Read, Write};
    use commonware_coding::ReedSolomon;
    use commonware_consensus::{
        Block as ConsensusBlock, CertifiableBlock, Heightable,
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
        Digest as _, Digested, Digestible, Hasher, bls12381::primitives::variant::MinPk,
        sha256::Sha256,
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::non_empty;
    use std::{sync::Arc, time::Duration};

    const THRESHOLD_NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_DKG_PROBE_DISCOVERY_TEST";

    type TestCommitment = Commitment<CodingBlock, ReedSolomon<Sha256>, Sha256>;
    type CodingContext =
        commonware_consensus::simplex::types::Context<TestCommitment, mocks::TestPublicKey>;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct CodingBlock(mocks::MockBlock<mocks::TestDigest, CodingContext>);

    impl CodingBlock {
        fn new<H: Hasher<Digest = mocks::TestDigest>>(
            context: CodingContext,
            parent: mocks::TestDigest,
            height: Height,
            timestamp: u64,
        ) -> Self {
            Self(mocks::MockBlock::new::<H>(
                context, parent, height, timestamp,
            ))
        }
    }

    impl Write for CodingBlock {
        fn write(&self, writer: &mut impl BufMut) {
            self.0.write(writer);
        }
    }

    impl Read for CodingBlock {
        type Cfg = ();

        fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
            mocks::MockBlock::read_cfg(reader, cfg).map(Self)
        }
    }

    impl EncodeSize for CodingBlock {
        fn encode_size(&self) -> usize {
            self.0.encode_size()
        }
    }

    impl Digestible for CodingBlock {
        type Digest = mocks::TestDigest;

        fn digest(&self) -> Self::Digest {
            self.0.digest()
        }
    }

    impl Heightable for CodingBlock {
        fn height(&self) -> Height {
            self.0.height()
        }
    }

    impl ConsensusBlock for CodingBlock {
        fn parent(&self) -> Self::Digest {
            self.0.parent()
        }
    }

    impl CertifiableBlock for CodingBlock {
        type Context = CodingContext;

        fn context(&self) -> Self::Context {
            self.0.context().clone()
        }
    }

    type TestCodingVariant = Coding<CodingBlock, ReedSolomon<Sha256>, Sha256, mocks::TestPublicKey>;
    type TestThresholdScheme = ThresholdScheme<mocks::TestPublicKey, MinPk>;

    fn finalization<S, D>(proposal: Proposal<D>, schemes: &[S]) -> Finalization<S, D>
    where
        D: commonware_cryptography::Digest,
        S: commonware_consensus::simplex::scheme::Scheme<D>,
    {
        let finalizes = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect::<Vec<_>>();
        Finalization::from_finalizes(&schemes[0], non_empty![@finalizes.iter()], &Sequential)
            .expect("finalization quorum")
    }

    fn decode_finalization_response<S, V>(
        message: Bytes,
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

    fn split_block_response<S, V>(message: Bytes, verifier: &S) -> (Epoch, Bytes)
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

    async fn coding_block(
        leader: mocks::TestPublicKey,
        participants: u16,
    ) -> Arc<CodedBlock<CodingBlock, ReedSolomon<Sha256>, Sha256>> {
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
        Arc::new(
            CodedBlock::encode(
                Digested::precomputed(block.clone(), block.digest()),
                coding_config_for_participants(participants),
                &Sequential,
            )
            .await,
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
            )
            .await;
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
            .encode();
            let finalization = decode_finalization_response::<
                TestThresholdScheme,
                TestCodingVariant,
            >(message, &verifier);
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
            .encode();
            let finalization = decode_finalization_response::<
                mocks::TestScheme,
                mocks::TestMarshalVariant,
            >(finalization_message, &fixture.schemes[0]);
            let authenticated = finalization.verify(&mut context, &fixture.schemes[0], &Sequential);
            assert!(authenticated);
            let commitment = finalization.proposal.payload;
            let block_message =
                wire::Message::<mocks::TestScheme, mocks::TestMarshalVariant>::BlockResponse {
                    epoch: Epoch::zero(),
                    block: Digested::precomputed(block.clone(), block.digest()),
                }
                .encode();
            let (epoch, body) = split_block_response::<
                mocks::TestScheme,
                mocks::TestMarshalVariant,
            >(block_message, &fixture.schemes[0]);
            assert_eq!(epoch, Epoch::zero());
            let decoded =
                wire::read_block::<mocks::TestMarshalVariant>(body, commitment, &(), &Sequential)
                    .await
                    .expect("standard block authenticated");

            assert_eq!(decoded.inner(), &block);
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
            )
            .await;
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
                .encode();
            let finalization = decode_finalization_response::<mocks::TestScheme, TestCodingVariant>(
                finalization_message,
                &fixture.schemes[0],
            );
            let authenticated = finalization.verify(&mut context, &fixture.schemes[0], &Sequential);
            assert!(authenticated);
            let block_message =
                wire::Message::<mocks::TestScheme, TestCodingVariant>::BlockResponse {
                    epoch: Epoch::zero(),
                    block,
                }
                .encode();
            let (epoch, body) = split_block_response::<mocks::TestScheme, TestCodingVariant>(
                block_message,
                &fixture.schemes[0],
            );
            assert_eq!(epoch, Epoch::zero());
            let commitment = finalization.proposal.payload;
            let decoded = wire::read_block::<TestCodingVariant>(body, commitment, &(), &Sequential)
                .await
                .expect("coding block authenticated");

            assert_eq!(decoded.height(), Height::new(1));
            assert_eq!(TestCodingVariant::commitment(&decoded), payload);

            // The finalized payload fixes the root, so the probe decodes without re-encoding.
            assert!(decoded.shard(0).is_none());
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
            )
            .await;
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
            .encode();
            let finalization = decode_finalization_response::<
                TestThresholdScheme,
                TestCodingVariant,
            >(finalization_message, &verifier);
            let authenticated = finalization.verify(&mut context, &verifier, &Sequential);
            assert!(authenticated);
            let block_message = wire::Message::<
                TestThresholdScheme,
                TestCodingVariant,
            >::BlockResponse {
                epoch: Epoch::zero(),
                block,
            }
            .encode();
            let (epoch, body) = split_block_response::<
                TestThresholdScheme,
                TestCodingVariant,
            >(block_message, &verifier);
            assert_eq!(epoch, Epoch::zero());
            let commitment = finalization.proposal.payload;
            let decoded = wire::read_block::<TestCodingVariant>(body, commitment, &(), &Sequential)
                .await
                .expect("coding block authenticated");

            assert_eq!(decoded.height(), Height::new(1));
            assert_eq!(TestCodingVariant::commitment(&decoded), payload);

            // The finalized payload fixes the root, so the probe decodes without re-encoding.
            assert!(decoded.shard(0).is_none());
        });
    }
}
