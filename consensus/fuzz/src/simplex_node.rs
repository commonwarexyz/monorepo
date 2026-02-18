use crate::{
    simplex,
    strategy::{SmallScope, Strategy},
    utils::Partition,
    FuzzInput, StrategyChoice, MAX_REQUIRED_CONTAINERS, N4F3C1,
};
use arbitrary::Arbitrary;
use commonware_codec::{Encode, Read, ReadExt};
use commonware_consensus::{
    simplex::{
        scheme::Scheme as SimplexScheme,
        types::{
            Certificate, Finalization, Finalize, Notarization, Notarize, Nullification, Nullify,
            Proposal, Vote,
        },
    },
    types::{Epoch, Round, View},
    Monitor, Viewable,
};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_p2p::{simulated, Receiver as _, Recipients, Sender as _};
use commonware_parallel::Sequential;
use commonware_runtime::{deterministic, Metrics, Runner};
use commonware_utils::{channel::mpsc::Receiver, BytesRng};
use futures::FutureExt;
use rand::Rng;
use std::collections::{HashMap, HashSet, VecDeque};

const MIN_EVENTS: usize = 10;
const MAX_EVENTS: usize = 40;
const MAX_SAFE_VIEW: u64 = u64::MAX - 2;
const PROPOSAL_CACHE_LIMIT: usize = 64;

#[derive(Debug, Clone, Copy, Arbitrary)]
pub enum Event {
    OnBroadcastPayload,
    OnBroadcastAndNotarize,
    OnNotarize,
    OnNullify,
    OnFinalize,
    OnNotarization,
    OnNullification,
    OnFinalization,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
pub struct SimplexNodeEvent {
    pub from_node_idx: u8,
    pub event: Event,
}

#[derive(Debug, Clone)]
pub struct SimplexNodeFuzzInput {
    pub raw_bytes: Vec<u8>,
    pub events: Vec<SimplexNodeEvent>,
}

impl Arbitrary<'_> for SimplexNodeFuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let event_count = u.int_in_range(MIN_EVENTS..=MAX_EVENTS)?;

        let mut events = Vec::with_capacity(event_count);
        for _ in 0..event_count {
            events.push(SimplexNodeEvent::arbitrary(u)?);
        }

        let remaining = u.len().min(crate::MAX_RAW_BYTES);
        let raw_bytes = if remaining == 0 {
            vec![0]
        } else {
            u.bytes(remaining)?.to_vec()
        };

        Ok(Self { raw_bytes, events })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum VoteKey {
    Notarize {
        signer: usize,
        view: u64,
        payload: Sha256Digest,
    },
    Nullify {
        signer: usize,
        view: u64,
    },
    Finalize {
        signer: usize,
        view: u64,
        payload: Sha256Digest,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum CertificateKey {
    Notarization {
        signer: usize,
        view: u64,
        payload: Sha256Digest,
        with_honest_vote: bool,
    },
    Finalization {
        signer: usize,
        view: u64,
        payload: Sha256Digest,
        with_honest_vote: bool,
    },
}

struct NodeDriver<S>
where
    S: SimplexScheme<Sha256Digest>,
    S::PublicKey: Send + Sync + 'static,
{
    context: deterministic::Context,
    honest: S::PublicKey,
    relay: std::sync::Arc<
        commonware_consensus::simplex::mocks::relay::Relay<Sha256Digest, S::PublicKey>,
    >,
    byzantine_participants: Vec<S::PublicKey>,
    schemes: Vec<S>,
    vote_senders: Vec<simulated::Sender<S::PublicKey, deterministic::Context>>,
    certificate_senders: Vec<simulated::Sender<S::PublicKey, deterministic::Context>>,
    resolver_senders: Vec<simulated::Sender<S::PublicKey, deterministic::Context>>,
    vote_receivers: Vec<simulated::Receiver<S::PublicKey>>,
    certificate_receivers: Vec<simulated::Receiver<S::PublicKey>>,
    resolver_receivers: Vec<simulated::Receiver<S::PublicKey>>,
    strategy: SmallScope,

    last_view: u64,
    last_finalized_view: u64,
    last_notarized_view: u64,
    last_nullified_view: u64,

    latest_proposals: VecDeque<Proposal<Sha256Digest>>,
    proposal_by_view: HashMap<u64, Proposal<Sha256Digest>>,

    used_votes: HashSet<VoteKey>,
    used_certificates: HashSet<CertificateKey>,

    honest_notarize_votes: HashMap<Proposal<Sha256Digest>, Notarize<S, Sha256Digest>>,
    honest_finalize_votes: HashMap<Proposal<Sha256Digest>, Finalize<S, Sha256Digest>>,
    injected_finalize_views: HashSet<u64>,

    notarized_by_view: HashMap<u64, Sha256Digest>,
    finalized_by_view: HashMap<u64, Sha256Digest>,
}

impl<S> NodeDriver<S>
where
    S: SimplexScheme<Sha256Digest>,
    S::PublicKey: Send + Sync + 'static,
{
    #[allow(clippy::too_many_arguments)]
    fn new(
        context: deterministic::Context,
        honest: S::PublicKey,
        relay: std::sync::Arc<
            commonware_consensus::simplex::mocks::relay::Relay<Sha256Digest, S::PublicKey>,
        >,
        byzantine_participants: Vec<S::PublicKey>,
        schemes: Vec<S>,
        vote_senders: Vec<simulated::Sender<S::PublicKey, deterministic::Context>>,
        certificate_senders: Vec<simulated::Sender<S::PublicKey, deterministic::Context>>,
        resolver_senders: Vec<simulated::Sender<S::PublicKey, deterministic::Context>>,
        vote_receivers: Vec<simulated::Receiver<S::PublicKey>>,
        certificate_receivers: Vec<simulated::Receiver<S::PublicKey>>,
        resolver_receivers: Vec<simulated::Receiver<S::PublicKey>>,
    ) -> Self {
        Self {
            context,
            honest,
            relay,
            byzantine_participants,
            schemes,
            vote_senders,
            certificate_senders,
            resolver_senders,
            vote_receivers,
            certificate_receivers,
            resolver_receivers,
            strategy: SmallScope {
                fault_rounds: 1,
                fault_rounds_bound: 1,
            },
            last_view: 1,
            last_finalized_view: 0,
            last_notarized_view: 0,
            last_nullified_view: 0,
            latest_proposals: VecDeque::new(),
            proposal_by_view: HashMap::new(),
            used_votes: HashSet::new(),
            used_certificates: HashSet::new(),
            honest_notarize_votes: HashMap::new(),
            honest_finalize_votes: HashMap::new(),
            injected_finalize_views: HashSet::new(),
            notarized_by_view: HashMap::new(),
            finalized_by_view: HashMap::new(),
        }
    }

    fn signer_index(&self, node_idx: u8) -> usize {
        usize::from(node_idx) % self.schemes.len()
    }

    fn is_round_robin_leader(&self, signer_idx: usize, view: u64) -> bool {
        let participant_count = self.byzantine_participants.len() + 1; // + honest
        if participant_count == 0 {
            return false;
        }
        let leader_idx = (crate::EPOCH.wrapping_add(view) as usize) % participant_count;
        leader_idx == signer_idx
    }

    // Picks a proposal for the next fuzz event. It may reuse a recent proposal
    // or mutate one to create nearby variants.
    fn select_event_proposal(&mut self) -> Proposal<Sha256Digest> {
        let base = self
            .strategy
            .repeated_proposal_index(&mut self.context, self.latest_proposals.len())
            .and_then(|idx| self.latest_proposals.get(idx).cloned())
            .unwrap_or_else(|| {
                self.strategy.random_proposal(
                    &mut self.context,
                    self.last_view,
                    self.last_finalized_view,
                    self.last_notarized_view,
                    self.last_nullified_view,
                )
            });

        let proposal = self.strategy.mutate_proposal(
            &mut self.context,
            &base,
            self.last_view,
            self.last_finalized_view,
            self.last_notarized_view,
            self.last_nullified_view,
        );

        self.proposal_by_view
            .insert(proposal.view().get(), proposal.clone());
        self.latest_proposals.push_back(proposal.clone());
        while self.latest_proposals.len() > PROPOSAL_CACHE_LIMIT {
            self.latest_proposals.pop_front();
        }

        proposal
    }

    // Returns a proposal anchored to a specific view, reusing the existing one
    // for that view when present.
    fn get_or_build_proposal_for_view(&mut self, view: u64) -> Proposal<Sha256Digest> {
        if let Some(existing) = self.proposal_by_view.get(&view) {
            return existing.clone();
        }

        let proposal = self.strategy.random_proposal(
            &mut self.context,
            view,
            self.last_finalized_view,
            self.last_notarized_view,
            self.last_nullified_view,
        );

        self.proposal_by_view.insert(view, proposal.clone());
        self.latest_proposals.push_back(proposal.clone());
        while self.latest_proposals.len() > PROPOSAL_CACHE_LIMIT {
            self.latest_proposals.pop_front();
        }

        proposal
    }

    fn build_notarization_from_byz(
        &self,
        proposal: &Proposal<Sha256Digest>,
        signers: &[usize],
    ) -> Option<Notarization<S, Sha256Digest>> {
        let votes: Vec<_> = signers
            .iter()
            .map(|idx| Notarize::sign(&self.schemes[*idx], proposal.clone()))
            .collect::<Option<Vec<_>>>()?;
        Notarization::from_notarizes(&self.schemes[signers[0]], &votes, &Sequential)
    }

    fn build_nullification_from_byz(
        &self,
        round: Round,
        signers: &[usize],
    ) -> Option<Nullification<S>> {
        let votes: Vec<_> = signers
            .iter()
            .map(|idx| Nullify::<S>::sign::<Sha256Digest>(&self.schemes[*idx], round))
            .collect::<Option<Vec<_>>>()?;
        Nullification::from_nullifies(&self.schemes[signers[0]], &votes, &Sequential)
    }

    fn build_finalization_from_byz(
        &self,
        proposal: &Proposal<Sha256Digest>,
        signers: &[usize],
    ) -> Option<Finalization<S, Sha256Digest>> {
        let votes: Vec<_> = signers
            .iter()
            .map(|idx| Finalize::sign(&self.schemes[*idx], proposal.clone()))
            .collect::<Option<Vec<_>>>()?;
        Finalization::from_finalizes(&self.schemes[signers[0]], &votes, &Sequential)
    }

    fn notarization_with_optional_honest_vote(
        &mut self,
        proposal: &Proposal<Sha256Digest>,
        prefer_honest_vote: bool,
    ) -> Option<(Notarization<S, Sha256Digest>, bool)> {
        if prefer_honest_vote {
            if let Some(honest_vote) = self.honest_notarize_votes.get(proposal).cloned() {
                let byz_vote_0 = Notarize::sign(&self.schemes[0], proposal.clone())?;
                let byz_vote_1 = Notarize::sign(&self.schemes[1], proposal.clone())?;
                let votes = vec![honest_vote, byz_vote_0, byz_vote_1];
                let cert = Notarization::from_notarizes(&self.schemes[0], &votes, &Sequential)?;
                return Some((cert, true));
            }
        }

        let cert = self.build_notarization_from_byz(proposal, &[0, 1, 2])?;
        Some((cert, false))
    }

    fn finalization_with_optional_honest_vote(
        &mut self,
        proposal: &Proposal<Sha256Digest>,
        prefer_honest_vote: bool,
    ) -> Option<(Finalization<S, Sha256Digest>, bool)> {
        if prefer_honest_vote {
            if let Some(honest_vote) = self.honest_finalize_votes.get(proposal).cloned() {
                let byz_vote_0 = Finalize::sign(&self.schemes[0], proposal.clone())?;
                let byz_vote_1 = Finalize::sign(&self.schemes[1], proposal.clone())?;
                let votes = vec![honest_vote, byz_vote_0, byz_vote_1];
                let cert = Finalization::from_finalizes(&self.schemes[0], &votes, &Sequential)?;
                return Some((cert, true));
            }
        }

        let cert = self.build_finalization_from_byz(proposal, &[0, 1, 2])?;
        Some((cert, false))
    }

    fn build_invalid_notarization_for_view(
        &mut self,
        view: u64,
    ) -> Option<Notarization<S, Sha256Digest>> {
        let base = self.get_or_build_proposal_for_view(view);
        let mut conflicting = self.strategy.mutate_proposal(
            &mut self.context,
            &base,
            self.last_view,
            self.last_finalized_view,
            self.last_notarized_view,
            self.last_nullified_view,
        );
        conflicting = self
            .strategy
            .proposal_with_view(&conflicting, base.view().get());
        if conflicting.payload == base.payload {
            conflicting = Proposal::new(
                conflicting.round,
                conflicting.parent,
                self.strategy.random_payload(&mut self.context),
            );
        }

        let votes = [
            Notarize::sign(&self.schemes[0], base.clone())?,
            Notarize::sign(&self.schemes[1], base.clone())?,
            Notarize::sign(&self.schemes[2], conflicting)?,
        ];
        Notarization::from_notarizes(&self.schemes[0], votes.iter(), &Sequential)
    }

    fn build_invalid_nullification_for_view(&mut self, view: u64) -> Option<Nullification<S>> {
        let mut conflicting_view = self.strategy.mutate_nullify_view(
            &mut self.context,
            view,
            self.last_finalized_view,
            self.last_notarized_view,
            self.last_nullified_view,
        );
        conflicting_view = conflicting_view.clamp(1, MAX_SAFE_VIEW);
        if conflicting_view == view {
            conflicting_view = view.saturating_add(1).min(MAX_SAFE_VIEW);
            if conflicting_view == view {
                conflicting_view = view.saturating_sub(1).max(1);
            }
        }

        let base_round = Round::new(Epoch::new(crate::EPOCH), View::new(view));
        let conflicting_round = Round::new(Epoch::new(crate::EPOCH), View::new(conflicting_view));
        let votes = [
            Nullify::<S>::sign::<Sha256Digest>(&self.schemes[0], base_round)?,
            Nullify::<S>::sign::<Sha256Digest>(&self.schemes[1], base_round)?,
            Nullify::<S>::sign::<Sha256Digest>(&self.schemes[2], conflicting_round)?,
        ];
        Nullification::from_nullifies(&self.schemes[0], votes.iter(), &Sequential)
    }

    fn decode_resolver_request(msg: &[u8]) -> Option<(u64, u64)> {
        if msg.len() < 17 {
            return None;
        }
        let id = u64::from_be_bytes(msg.get(0..8)?.try_into().ok()?);
        if msg[8] != 0 {
            return None;
        }
        let requested_view = u64::from_be_bytes(msg.get(9..17)?.try_into().ok()?);
        Some((id, requested_view))
    }

    fn encode_resolver_response(id: u64, data: Vec<u8>) -> Vec<u8> {
        let mut out = Vec::with_capacity(9 + data.len() + 2);
        out.extend_from_slice(&id.to_be_bytes());
        out.push(1); // response payload
        out.extend_from_slice(&data.encode()); // length-prefixed bytes
        out
    }

    fn certificate_for_requested_view(
        &mut self,
        view: u64,
    ) -> Option<Certificate<S, Sha256Digest>> {
        let wrong_epoch = Epoch::new(crate::EPOCH.saturating_add(1));
        let base = self.get_or_build_proposal_for_view(view);

        match self.context.gen_range(0..=3u8) {
            0 => {
                let cert = if self.context.gen_bool(0.8) {
                    self.build_notarization_from_byz(&base, &[0, 1, 2])?
                } else {
                    let wrong = Proposal::new(
                        Round::new(wrong_epoch, base.view()),
                        base.parent,
                        base.payload,
                    );
                    self.build_notarization_from_byz(&wrong, &[0, 1, 2])?
                };
                Some(Certificate::Notarization(cert))
            }
            1 => {
                let proposal = self.strategy.proposal_with_parent_view(
                    &self.strategy.proposal_with_view(&base, view),
                    view.saturating_sub(1),
                );
                let cert = if self.context.gen_bool(0.8) {
                    self.build_finalization_from_byz(&proposal, &[0, 1, 2])?
                } else {
                    let wrong = Proposal::new(
                        Round::new(wrong_epoch, proposal.view()),
                        proposal.parent,
                        proposal.payload,
                    );
                    self.build_finalization_from_byz(&wrong, &[0, 1, 2])?
                };
                Some(Certificate::Finalization(cert))
            }
            2 => {
                let view = self.strategy.mutate_nullify_view(
                    &mut self.context,
                    view,
                    self.last_finalized_view,
                    self.last_notarized_view,
                    self.last_nullified_view,
                );
                let round = if self.context.gen_bool(0.8) {
                    Round::new(Epoch::new(crate::EPOCH), View::new(view))
                } else {
                    Round::new(wrong_epoch, View::new(view.max(1)))
                };
                let cert = self.build_nullification_from_byz(round, &[0, 1, 2])?;
                Some(Certificate::Nullification(cert))
            }
            // Default: valid responses.
            _ => match self.context.gen_range(0..3usize) {
                0 => {
                    let cert = self.build_notarization_from_byz(&base, &[0, 1, 2])?;
                    Some(Certificate::Notarization(cert))
                }
                1 => {
                    let cert = self.build_finalization_from_byz(&base, &[0, 1, 2])?;
                    Some(Certificate::Finalization(cert))
                }
                _ => {
                    let round = Round::new(Epoch::new(crate::EPOCH), View::new(base.view().get()));
                    let cert = self.build_nullification_from_byz(round, &[0, 1, 2])?;
                    Some(Certificate::Nullification(cert))
                }
            },
        }
    }

    fn handle_honest_votes(&mut self, sender: &S::PublicKey, bytes: Vec<u8>) {
        if sender != &self.honest {
            return;
        }
        let Ok(vote) = Vote::<S, Sha256Digest>::read(&mut bytes.as_slice()) else {
            return;
        };

        self.last_view = self.last_view.max(vote.view().get());

        match vote {
            Vote::Notarize(notarize) => {
                let view = notarize.view().get();
                self.honest_notarize_votes
                    .insert(notarize.proposal.clone(), notarize.clone());
                self.proposal_by_view
                    .insert(view, notarize.proposal.clone());
                self.latest_proposals.push_back(notarize.proposal);
            }
            Vote::Nullify(_) => {}
            Vote::Finalize(finalize) => {
                let view = finalize.view().get();
                self.honest_finalize_votes
                    .insert(finalize.proposal.clone(), finalize.clone());
                self.proposal_by_view
                    .insert(view, finalize.proposal.clone());
                self.latest_proposals.push_back(finalize.proposal);
            }
        }

        while self.latest_proposals.len() > PROPOSAL_CACHE_LIMIT {
            self.latest_proposals.pop_front();
        }
    }

    async fn handle_resolvers(&mut self, idx: usize, bytes: Vec<u8>) {
        let default_response = self
            .strategy
            .mutate_resolver_bytes(&mut self.context, &bytes);
        let response = if let Some((id, requested_view)) = Self::decode_resolver_request(&bytes) {
            if self.context.gen_bool(0.8) {
                if let Some(certificate) = self.certificate_for_requested_view(requested_view) {
                    let mut cert_bytes = certificate.encode().to_vec();
                    if self.context.gen_bool(0.2) {
                        cert_bytes = self
                            .strategy
                            .mutate_certificate_bytes(&mut self.context, &cert_bytes);
                    }
                    Self::encode_resolver_response(id, cert_bytes)
                } else {
                    default_response
                }
            } else {
                default_response
            }
        } else {
            default_response
        };
        let _ = self.resolver_senders[idx]
            .send(Recipients::One(self.honest.clone()), response, true)
            .await;
    }

    fn handle_certificates(&mut self, bytes: Vec<u8>) {
        let cfg = self.schemes[0].certificate_codec_config();
        let Ok(certificate) = Certificate::<S, Sha256Digest>::read_cfg(&mut bytes.as_slice(), &cfg)
        else {
            return;
        };

        match certificate {
            Certificate::Notarization(notarization) => {
                let view = notarization.view().get();
                self.last_notarized_view = self.last_notarized_view.max(view);
                self.notarized_by_view
                    .insert(view, notarization.proposal.payload);
                self.proposal_by_view
                    .insert(view, notarization.proposal.clone());
                self.latest_proposals.push_back(notarization.proposal);
            }
            Certificate::Nullification(nullification) => {
                let view = nullification.view().get();
                self.last_nullified_view = self.last_nullified_view.max(view);
            }
            Certificate::Finalization(finalization) => {
                let view = finalization.view().get();
                self.last_finalized_view = self.last_finalized_view.max(view);
                self.finalized_by_view
                    .insert(view, finalization.proposal.payload);
                self.proposal_by_view
                    .insert(view, finalization.proposal.clone());
                self.latest_proposals.push_back(finalization.proposal);
            }
        }

        while self.latest_proposals.len() > PROPOSAL_CACHE_LIMIT {
            self.latest_proposals.pop_front();
        }
    }

    async fn handle_receivers(&mut self) {
        for idx in 0..self.vote_receivers.len() {
            while let Some(Ok((sender, msg))) = self.vote_receivers[idx].recv().now_or_never() {
                let bytes: Vec<u8> = msg.into();
                self.handle_honest_votes(&sender, bytes);
            }
        }

        for idx in 0..self.certificate_receivers.len() {
            while let Some(Ok((_, msg))) = self.certificate_receivers[idx].recv().now_or_never() {
                let bytes: Vec<u8> = msg.into();
                self.handle_certificates(bytes);
            }
        }

        for idx in 0..self.resolver_receivers.len() {
            while let Some(Ok((_, msg))) = self.resolver_receivers[idx].recv().now_or_never() {
                let bytes: Vec<u8> = msg.into();
                self.handle_resolvers(idx, bytes).await;
            }
        }
    }

    fn check_finalization(&mut self, latest: &mut View, monitor: &mut Receiver<View>) -> bool {
        let mut progressed = false;
        while let Ok(update) = monitor.try_recv() {
            if update.get() > latest.get() {
                *latest = update;
                self.last_finalized_view = update.get();
                progressed = true;
            }
        }
        progressed
    }

    async fn apply_event(&mut self, event: SimplexNodeEvent) {
        let signer_idx = self.signer_index(event.from_node_idx);
        match event.event {
            Event::OnBroadcastPayload => self.broadcast_payload_event(signer_idx).await,
            Event::OnBroadcastAndNotarize => self.send_broadcast_and_notarize(signer_idx).await,
            Event::OnNotarize => self.send_notarize_vote(signer_idx).await,
            Event::OnNullify => self.send_nullify_vote(signer_idx).await,
            Event::OnFinalize => self.send_finalize_vote(signer_idx).await,
            Event::OnNotarization => self.send_notarization_certificate(signer_idx).await,
            Event::OnNullification => self.send_nullification_certificate(signer_idx).await,
            Event::OnFinalization => self.send_finalization_certificate(signer_idx).await,
        }
    }

    async fn broadcast_payload_event(&mut self, signer_idx: usize) {
        let proposal = self.select_event_proposal();
        let view = proposal.view().get();
        if !self.is_round_robin_leader(signer_idx, view) {
            return;
        }
        self.broadcast_payload_for_verify(signer_idx, &proposal)
            .await;
    }

    async fn broadcast_payload_for_verify(
        &mut self,
        signer_idx: usize,
        proposal: &Proposal<Sha256Digest>,
    ) {
        let Some(sender) = self.byzantine_participants.get(signer_idx).cloned() else {
            return;
        };
        // Mirror equivocator behavior: make payload bytes available to the mock app so
        // verify requests can resolve through relay delivery.
        let contents = self
            .strategy
            .mutate_resolver_bytes(&mut self.context, &[0u8]);
        self.relay
            .broadcast(&sender, (proposal.payload, contents.into()))
            .await;
    }

    async fn send_notarize_vote(&mut self, signer_idx: usize) {
        let proposal = self.select_event_proposal();
        self.send_notarize_vote_for_proposal(signer_idx, proposal)
            .await;
    }

    async fn send_broadcast_and_notarize(&mut self, signer_idx: usize) {
        let proposal = self.select_event_proposal();
        let view = proposal.view().get();
        if self.is_round_robin_leader(signer_idx, view) {
            self.broadcast_payload_for_verify(signer_idx, &proposal)
                .await;
        }
        self.send_notarize_vote_for_proposal(signer_idx, proposal)
            .await;
    }

    async fn send_notarize_vote_for_proposal(
        &mut self,
        signer_idx: usize,
        proposal: Proposal<Sha256Digest>,
    ) {
        let view = proposal.view().get();
        let payload = proposal.payload;

        let key = VoteKey::Notarize {
            signer: signer_idx,
            view,
            payload,
        };
        self.used_votes.insert(key);

        let Some(vote) = Notarize::sign(&self.schemes[signer_idx], proposal) else {
            return;
        };

        let msg = Vote::<S, Sha256Digest>::Notarize(vote).encode();
        let _ = self.vote_senders[signer_idx]
            .send(Recipients::One(self.honest.clone()), msg, true)
            .await;
    }

    async fn send_nullify_vote(&mut self, signer_idx: usize) {
        let view = self.strategy.mutate_nullify_view(
            &mut self.context,
            self.last_view,
            self.last_finalized_view,
            self.last_notarized_view,
            self.last_nullified_view,
        );

        let key = VoteKey::Nullify {
            signer: signer_idx,
            view,
        };
        self.used_votes.insert(key);

        let round = Round::new(Epoch::new(crate::EPOCH), View::new(view));
        let Some(vote) = Nullify::<S>::sign::<Sha256Digest>(&self.schemes[signer_idx], round)
        else {
            return;
        };

        let msg = Vote::<S, Sha256Digest>::Nullify(vote).encode();
        let _ = self.vote_senders[signer_idx]
            .send(Recipients::One(self.honest.clone()), msg, true)
            .await;
    }

    async fn send_finalize_vote(&mut self, signer_idx: usize) {
        let proposal = self.select_event_proposal();
        self.send_finalize_vote_for_proposal(signer_idx, proposal)
            .await;
    }

    async fn send_finalize_vote_for_proposal(
        &mut self,
        signer_idx: usize,
        proposal: Proposal<Sha256Digest>,
    ) {
        let view = proposal.view().get();
        let payload = proposal.payload;

        let key = VoteKey::Finalize {
            signer: signer_idx,
            view,
            payload,
        };
        self.used_votes.insert(key);

        let Some(vote) = Finalize::sign(&self.schemes[signer_idx], proposal) else {
            return;
        };

        let msg = Vote::<S, Sha256Digest>::Finalize(vote).encode();
        let _ = self.vote_senders[signer_idx]
            .send(Recipients::One(self.honest.clone()), msg, true)
            .await;
    }

    async fn send_certificate_bytes(&mut self, signer_idx: usize, msg: Vec<u8>) {
        let _ = self.certificate_senders[signer_idx]
            .send(Recipients::One(self.honest.clone()), msg, true)
            .await;
    }

    async fn send_malformed_certificate(&mut self, signer_idx: usize) {
        let msg = self
            .strategy
            .mutate_certificate_bytes(&mut self.context, &[0u8]);
        self.send_certificate_bytes(signer_idx, msg).await;
    }

    async fn send_wrong_epoch_nullification_certificate(&mut self, signer_idx: usize) {
        let view = self.last_view.clamp(1, MAX_SAFE_VIEW);
        let wrong_epoch = Epoch::new(crate::EPOCH.saturating_add(1));
        let round = Round::new(wrong_epoch, View::new(view));
        let Some(cert) = self.build_nullification_from_byz(round, &[0, 1, 2]) else {
            return;
        };

        let msg = Certificate::<S, Sha256Digest>::Nullification(cert)
            .encode()
            .to_vec();
        self.send_certificate_bytes(signer_idx, msg).await;
    }

    async fn send_invalid_notarization_certificate(&mut self, signer_idx: usize) {
        let view = self
            .last_view
            .max(self.last_notarized_view)
            .max(self.last_finalized_view)
            .clamp(1, MAX_SAFE_VIEW);
        let Some(cert) = self.build_invalid_notarization_for_view(view) else {
            return;
        };

        let msg = Certificate::<S, Sha256Digest>::Notarization(cert)
            .encode()
            .to_vec();
        self.send_certificate_bytes(signer_idx, msg).await;
    }

    async fn send_invalid_nullification_certificate(&mut self, signer_idx: usize) {
        let view = self
            .last_view
            .max(self.last_nullified_view)
            .max(self.last_finalized_view)
            .clamp(1, MAX_SAFE_VIEW);
        let Some(cert) = self.build_invalid_nullification_for_view(view) else {
            return;
        };

        let msg = Certificate::<S, Sha256Digest>::Nullification(cert)
            .encode()
            .to_vec();
        self.send_certificate_bytes(signer_idx, msg).await;
    }

    // The goal of this function is to unlock the honest node using
    // finalize votes for the votes that were notarized by the honest node.
    async fn inject_finalize_quorum_for_honest_notarize_views(&mut self) {
        let notarized: Vec<_> = self
            .honest_notarize_votes
            .iter()
            .filter(|(proposal, _)| {
                !self
                    .injected_finalize_views
                    .contains(&proposal.view().get())
            })
            .map(|(proposal, _)| (proposal.view().get(), proposal.clone()))
            .collect();

        if notarized.is_empty() {
            return;
        }
        let budget = self.context.gen_range(1..=notarized.len());

        for (view, proposal) in notarized.into_iter().take(budget) {
            for signer_idx in 0..self.schemes.len() {
                self.send_finalize_vote_for_proposal(signer_idx, proposal.clone())
                    .await;
            }
            self.injected_finalize_views.insert(view);
        }
    }

    async fn send_notarization_certificate_for_proposal(
        &mut self,
        signer_idx: usize,
        proposal: Proposal<Sha256Digest>,
        prefer_honest_vote: bool,
    ) {
        let view = proposal.view().get();
        let payload = proposal.payload;

        let cert = self.notarization_with_optional_honest_vote(&proposal, prefer_honest_vote);

        let Some((certificate, with_honest_vote)) = cert else {
            return;
        };

        let key = CertificateKey::Notarization {
            signer: signer_idx,
            view,
            payload,
            with_honest_vote,
        };
        self.used_certificates.insert(key);

        self.notarized_by_view.insert(view, payload);
        self.last_notarized_view = self.last_notarized_view.max(view);

        let msg = Certificate::<S, Sha256Digest>::Notarization(certificate).encode();
        let _ = self.certificate_senders[signer_idx]
            .send(Recipients::One(self.honest.clone()), msg, true)
            .await;
    }

    async fn send_notarization_certificate(&mut self, signer_idx: usize) {
        let proposal = self.select_event_proposal();
        let prefer_honest_vote = self.context.gen_bool(0.5);

        match self.context.gen_range(0..100u8) {
            // 90% — normal notarization (the primary path)
            0..=89 => {
                self.send_notarization_certificate_for_proposal(
                    signer_idx,
                    proposal,
                    prefer_honest_vote,
                )
                .await;
            }
            // 4% — malformed bytes on the wire
            90..=93 => {
                self.send_malformed_certificate(signer_idx).await;
            }
            // 3% — wrong epoch nullification
            94..=96 => {
                self.send_wrong_epoch_nullification_certificate(signer_idx)
                    .await;
            }
            // 3% — structurally valid but cryptographically invalid notarization
            97..=99 => {
                self.send_invalid_notarization_certificate(signer_idx).await;
            }
            _ => unreachable!(),
        }
    }

    async fn send_nullification_certificate_for_view(&mut self, signer_idx: usize, view: u64) {
        let view = view.max(1);

        let round = Round::new(Epoch::new(crate::EPOCH), View::new(view));
        let cert = self
            .build_nullification_from_byz(round, &[0, 1, 2])
            .expect("byzantine nullification should build");

        self.last_nullified_view = self.last_nullified_view.max(view);

        let msg = Certificate::<S, Sha256Digest>::Nullification(cert).encode();
        let _ = self.certificate_senders[signer_idx]
            .send(Recipients::One(self.honest.clone()), msg, true)
            .await;
    }

    async fn send_nullification_certificate(&mut self, signer_idx: usize) {
        let view = self.strategy.mutate_nullify_view(
            &mut self.context,
            self.last_view,
            self.last_finalized_view,
            self.last_notarized_view,
            self.last_nullified_view,
        );

        match self.context.gen_range(0..100u8) {
            // 90% — normal nullification
            0..=89 => {
                self.send_nullification_certificate_for_view(signer_idx, view)
                    .await;
            }
            // 4% — malformed bytes
            90..=93 => {
                self.send_malformed_certificate(signer_idx).await;
            }
            // 3% — wrong epoch nullification
            94..=96 => {
                self.send_wrong_epoch_nullification_certificate(signer_idx)
                    .await;
            }
            // 3% — structurally valid but cryptographically invalid nullification
            97..=99 => {
                self.send_invalid_nullification_certificate(signer_idx)
                    .await;
            }
            _ => unreachable!(),
        }
    }

    async fn send_finalization_certificate_for_proposal(
        &mut self,
        signer_idx: usize,
        proposal: Proposal<Sha256Digest>,
    ) {
        let view = proposal.view().get();
        let payload = proposal.payload;

        if self
            .notarized_by_view
            .get(&view)
            .is_none_or(|d| *d != payload)
        {
            self.send_notarization_certificate_for_proposal(signer_idx, proposal.clone(), true)
                .await;
        }

        let prefer_honest_vote = self.context.gen_bool(0.5);
        let cert = self.finalization_with_optional_honest_vote(&proposal, prefer_honest_vote);

        let Some((certificate, with_honest_vote)) = cert else {
            return;
        };

        let key = CertificateKey::Finalization {
            signer: signer_idx,
            view,
            payload,
            with_honest_vote,
        };
        self.used_certificates.insert(key);

        self.finalized_by_view.insert(view, payload);
        self.last_finalized_view = self.last_finalized_view.max(view);

        let msg = Certificate::<S, Sha256Digest>::Finalization(certificate).encode();
        let _ = self.certificate_senders[signer_idx]
            .send(Recipients::One(self.honest.clone()), msg, true)
            .await;
    }

    async fn send_invalid_finalization_certificate(&mut self, signer_idx: usize) -> bool {
        let view = self
            .last_view
            .max(self.last_notarized_view)
            .max(self.last_finalized_view)
            .max(1)
            .min(MAX_SAFE_VIEW);
        let Some(cert) = self.build_invalid_finalization_for_view(view) else {
            return false;
        };

        let msg = Certificate::<S, Sha256Digest>::Finalization(cert).encode();
        let _ = self.certificate_senders[signer_idx]
            .send(Recipients::One(self.honest.clone()), msg, true)
            .await;
    }

    async fn send_finalization_certificate(&mut self, signer_idx: usize) {
        let proposal = self.select_event_proposal();

        match self.context.gen_range(0..100u8) {
            // 96% — normal nullification
            0..=95 => {
                self.send_finalization_certificate_for_proposal(signer_idx, proposal)
                    .await;
            }
            // 4% — malformed bytes
            96..=99 => {
                self.send_invalid_finalization_certificate(signer_idx).await;
            }
            _ => unreachable!(),
        }
    }
}

pub fn fuzz_simplex_node<P: simplex::Simplex>(input: SimplexNodeFuzzInput) {
    run::<P>(input);
}

fn run<P: simplex::Simplex>(input: SimplexNodeFuzzInput) {
    let raw_bytes_for_panic = input.raw_bytes.clone();
    let run_result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_inner::<P>(input)));
    if let Err(payload) = run_result {
        println!("Panicked with raw_bytes: {:?}", raw_bytes_for_panic);
        std::panic::resume_unwind(payload);
    }
}

fn run_inner<P: simplex::Simplex>(input: SimplexNodeFuzzInput) {
    let rng = BytesRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    executor.start(|mut context| async move {
        let base = FuzzInput {
            raw_bytes: input.raw_bytes.clone(),
            required_containers: MAX_REQUIRED_CONTAINERS,
            degraded_network: false,
            configuration: N4F3C1,
            partition: Partition::Connected,
            strategy: StrategyChoice::SmallScope {
                fault_rounds: 1,
                fault_rounds_bound: 1,
            },
            honest_messages_drop_percent: 0,
        };

        let (oracle, participants, schemes, mut registrations) =
            crate::setup_network::<P>(&mut context, &base).await;

        let (fuzzer_schemes, honest_schemes) = schemes.split_at(3);
        let honest_scheme = honest_schemes[0].clone();

        let relay = std::sync::Arc::new(commonware_consensus::simplex::mocks::relay::Relay::new());
        let byzantine_participants: Vec<_> = participants.iter().take(3).cloned().collect();

        let mut vote_senders = Vec::new();
        let mut certificate_senders = Vec::new();
        let mut resolver_senders = Vec::new();
        let mut vote_receivers = Vec::new();
        let mut certificate_receivers = Vec::new();
        let mut resolver_receivers = Vec::new();

        for byz in participants.iter().take(3usize) {
            let (
                (vote_sender, vote_receiver),
                (cert_sender, cert_receiver),
                (resolver_sender, resolver_receiver),
            ) = registrations
                .remove(byz)
                .expect("byzantine participant must exist");

            vote_senders.push(vote_sender);
            certificate_senders.push(cert_sender);
            resolver_senders.push(resolver_sender);
            vote_receivers.push(vote_receiver);
            certificate_receivers.push(cert_receiver);
            resolver_receivers.push(resolver_receiver);
        }

        let honest = participants[3].clone();
        let honest_channels = registrations
            .remove(&honest)
            .expect("honest participant must exist");
        let mut reporter = crate::spawn_honest_validator::<P>(
            context.with_label("honest_validator"),
            &oracle,
            &participants,
            honest_scheme,
            honest.clone(),
            relay.clone(),
            honest_channels,
        );

        let (mut latest, mut monitor): (View, Receiver<View>) = reporter.subscribe().await;

        let mut driver = NodeDriver::<P::Scheme>::new(
            context.with_label("simplex_ed25519_node_driver"),
            honest,
            relay,
            byzantine_participants,
            fuzzer_schemes.to_vec(),
            vote_senders,
            certificate_senders,
            resolver_senders,
            vote_receivers,
            certificate_receivers,
            resolver_receivers,
        );

        for event in input.events.iter() {
            driver.check_finalization(&mut latest, &mut monitor);
            driver.handle_receivers().await;
            driver
                .inject_finalize_quorum_for_honest_notarize_views()
                .await;
            driver.apply_event(*event).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simplex_node_smoke() {
        let input = SimplexNodeFuzzInput {
            raw_bytes: vec![1, 2, 3, 4, 5],
            events: vec![
                SimplexNodeEvent {
                    from_node_idx: 0,
                    event: Event::OnNotarize,
                },
                SimplexNodeEvent {
                    from_node_idx: 1,
                    event: Event::OnNotarization,
                },
                SimplexNodeEvent {
                    from_node_idx: 2,
                    event: Event::OnFinalization,
                },
            ],
        };
        fuzz_simplex_node::<simplex::SimplexEd25519>(input);
    }
}
