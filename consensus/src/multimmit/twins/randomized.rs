//! Bounded, reproducible schedules over complete engines sharing Byzantine identities.

use super::*;
#[cfg(test)]
use crate::Epochable as _;
use crate::{
    Viewable as _,
    multimmit::{
        machine::{FinalityFact, FinalityId},
        types::{
            Activity, Anchor, BlockRef, CertificateId, Height, LeaderBlock, TransactionBlockHeader,
            VoteBody, Vqc,
        },
    },
    types::Attributable as _,
};
use commonware_actor::Feedback;
use commonware_utils::TestRng;
use std::{
    collections::{BTreeSet, VecDeque},
    time::SystemTime,
};

const MAX_SCHEDULE_BYTES: usize = 768;
// Covers the largest live artifact window configured by this campaign.
const MAX_DELIVERED_EVIDENCE: usize = 2_048;

/// Observed actions, rather than requested adversarial behavior.
#[derive(Debug, Default)]
struct Coverage {
    dropped: usize,
    held: usize,
    reordered: usize,
    duplicated: usize,
    delayed: usize,
    fair_deliveries: usize,
    selective_broadcasts: usize,
    conflicting_producers: usize,
    finalized_leaders: usize,
}

struct Schedule<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Schedule<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    const fn byte(&mut self) -> u8 {
        if self.bytes.is_empty() {
            return 0;
        }
        let byte = self.bytes[self.cursor % self.bytes.len()];
        self.cursor += 1;
        byte
    }

    const fn word(&mut self) -> u16 {
        u16::from_le_bytes([self.byte(), self.byte()])
    }

    fn take<const N: usize>(&mut self) -> [u8; N] {
        core::array::from_fn(|_| self.byte())
    }

    fn shuffle<T>(&mut self, values: &mut [T]) {
        for upper in (1..values.len()).rev() {
            let other = usize::from(self.byte()) % (upper + 1);
            values.swap(upper, other);
        }
    }
}

struct LinkStep {
    from: usize,
    to: usize,
    success_rate: f64,
    observations: usize,
}

#[derive(Clone)]
struct WireEvidence {
    node: usize,
    plane: u64,
    agreement: Arc<Mutex<Agreement>>,
    delivered: Arc<Mutex<DeliveredEvidence>>,
    epoch: Epoch,
    codec: CodecConfig,
}

impl WireEvidence {
    fn record_agreement(&self, bytes: &[u8]) {
        self.agreement
            .lock()
            .record_wire(self.node, self.plane, bytes, self.epoch, self.codec);
    }

    fn record_accountability(&self, bytes: &IoBuf) {
        self.delivered.lock().record(self.plane, bytes);
    }
}

#[derive(Clone, Default)]
struct DeliveredEvidence {
    frames: VecDeque<(u64, IoBuf)>,
}

impl DeliveredEvidence {
    fn record(&mut self, plane: u64, bytes: &IoBuf) {
        if self.frames.len() == MAX_DELIVERED_EVIDENCE {
            self.frames.pop_front();
        }
        self.frames.push_back((plane, bytes.clone()));
    }

    fn proves(
        &self,
        observer: usize,
        target: Participant,
        verifier: Scheme<ed25519::PublicKey, MinPk>,
        codec: CodecConfig,
        seed: u64,
        targets: BTreeSet<Participant>,
    ) -> bool {
        let mut oracle = AccountabilityOracle::new(verifier, codec, seed, targets);
        for (plane, frame) in &self.frames {
            oracle.record_wire(observer, *plane, frame.as_ref());
        }
        oracle.proves(observer, target)
    }
}

struct RandomizedReceiver<E> {
    receiver: mpsc::UnboundedReceiver<Result<commonware_p2p::Message<ed25519::PublicKey>, E>>,
    evidence: WireEvidence,
}

impl<E> Debug for RandomizedReceiver<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RandomizedReceiver")
            .finish_non_exhaustive()
    }
}

impl<E> commonware_p2p::Receiver for RandomizedReceiver<E>
where
    E: Debug + std::error::Error + Send + Sync + 'static,
{
    type Error = E;
    type PublicKey = ed25519::PublicKey;

    async fn recv(&mut self) -> Result<commonware_p2p::Message<Self::PublicKey>, E> {
        let message = self
            .receiver
            .recv()
            .await
            .expect("delivery pump stays live")?;
        self.evidence.record_accountability(&message.1);
        Ok(message)
    }
}

impl<E> RandomizedReceiver<E>
where
    E: Debug + std::error::Error + Send + Sync + 'static,
{
    /// The pump owns held frames and delays independently of engine receive cancellation.
    fn randomized<R>(
        context: deterministic::Context,
        mut inner: R,
        script: [u8; 16],
        deadline: SystemTime,
        coverage: Arc<Mutex<Coverage>>,
        evidence: WireEvidence,
    ) -> Self
    where
        R: commonware_p2p::Receiver<Error = E, PublicKey = ed25519::PublicKey>,
    {
        let (sender, receiver) = mpsc::unbounded_channel();
        let agreement_evidence = evidence.clone();
        context.spawn(move |context| async move {
            let mut held: Option<commonware_p2p::Message<ed25519::PublicKey>> = None;
            let mut remaining = 64;
            loop {
                let adversarial = remaining > 0 && context.current() < deadline;
                if !adversarial
                    && let Some(message) = held.take()
                    && sender.send(Ok(message)).is_err()
                {
                    return;
                }
                let received = if adversarial {
                    select! {
                        message = inner.recv() => message,
                        _ = context.sleep_until(deadline) => continue,
                    }
                } else {
                    inner.recv().await
                };
                let message = match received {
                    Ok(message) => message,
                    Err(error) => {
                        let _ = sender.send(Err(error));
                        return;
                    }
                };
                agreement_evidence.record_agreement(message.1.as_ref());
                if adversarial {
                    let step = 64 - remaining;
                    remaining -= 1;
                    match script[step % script.len()] % 8 {
                        1 => {
                            coverage.lock().dropped += 1;
                            continue;
                        }
                        2 if held.is_none() => {
                            held = Some(message);
                            coverage.lock().held += 1;
                            continue;
                        }
                        3 => {
                            if sender.send(Ok(message.clone())).is_err() {
                                return;
                            }
                            coverage.lock().duplicated += 1;
                        }
                        4 => {
                            let delay = u64::from(script[(step + 1) % script.len()] % 20) + 1;
                            context.sleep(Duration::from_millis(delay)).await;
                            coverage.lock().delayed += 1;
                        }
                        _ => {}
                    }
                } else {
                    coverage.lock().fair_deliveries += 1;
                }
                if sender.send(Ok(message)).is_err() {
                    return;
                }
                if let Some(message) = held.take() {
                    if sender.send(Ok(message)).is_err() {
                        return;
                    }
                    coverage.lock().reordered += 1;
                }
            }
        });
        Self { receiver, evidence }
    }
}

#[derive(Default)]
struct ViewClaims {
    leader: Option<Sha256Digest>,
    vote: Option<VoteBody<Sha256Digest>>,
    novote: bool,
}

#[derive(Default)]
struct ObserverClaims {
    producers: BTreeMap<(ChainId, Height), (Participant, TransactionBlockHeader<Sha256Digest>)>,
    views: BTreeMap<(View, Participant), ViewClaims>,
    da_votes: BTreeMap<(ChainId, Height, Participant), TransactionBlockHeader<Sha256Digest>>,
    proven: BTreeSet<Participant>,
}

impl ObserverClaims {
    fn record_producer(
        &mut self,
        signer: Participant,
        header: &TransactionBlockHeader<Sha256Digest>,
    ) {
        let slot = (header.chain(), header.height());
        if let Some((previous_signer, previous)) = self.producers.get(&slot) {
            if previous != header {
                self.proven.extend([*previous_signer, signer]);
            }
            return;
        }
        if let Some(previous_height) = header.height().previous()
            && let Some((previous_signer, previous)) =
                self.producers.get(&(header.chain(), previous_height))
            && previous.digest::<Sha256>() != header.parent()
        {
            self.proven.extend([*previous_signer, signer]);
        }
        if let Some(next_height) = header.height().get().checked_add(1).map(Height::new)
            && let Some((next_signer, next)) = self.producers.get(&(header.chain(), next_height))
            && header.digest::<Sha256>() != next.parent()
        {
            self.proven.extend([*next_signer, signer]);
        }
        self.producers.insert(slot, (signer, header.clone()));
    }

    fn record_leader(&mut self, signer: Participant, leader: &LeaderBlock<MinPk, Sha256Digest>) {
        let digest = leader.digest::<Sha256>();
        let claims = self.views.entry((leader.view(), signer)).or_default();
        if claims.leader.is_some_and(|previous| previous != digest) {
            self.proven.insert(signer);
        }
        claims.leader.get_or_insert(digest);
    }

    fn record_vote(&mut self, signer: Participant, vote: &VoteBody<Sha256Digest>) {
        let claims = self.views.entry((vote.view(), signer)).or_default();
        if claims.novote
            || claims
                .vote
                .as_ref()
                .is_some_and(|previous| previous != vote)
        {
            self.proven.insert(signer);
        }
        claims.vote.get_or_insert_with(|| vote.clone());
    }

    fn record_novote(&mut self, signer: Participant, view: View) {
        let claims = self.views.entry((view, signer)).or_default();
        if claims.vote.is_some() {
            self.proven.insert(signer);
        }
        claims.novote = true;
    }

    fn record_da_vote(
        &mut self,
        signer: Participant,
        header: &TransactionBlockHeader<Sha256Digest>,
    ) {
        let slot = (header.chain(), header.height(), signer);
        if self
            .da_votes
            .get(&slot)
            .is_some_and(|previous| previous != header)
        {
            self.proven.insert(signer);
        }
        self.da_votes.entry(slot).or_insert_with(|| header.clone());
    }
}

/// Independently indexes only claims whose signatures it verifies for each observer.
struct AccountabilityOracle {
    verifier: Scheme<ed25519::PublicKey, MinPk>,
    rng: TestRng,
    codec: CodecConfig,
    targets: BTreeSet<Participant>,
    observers: BTreeMap<usize, ObserverClaims>,
}

impl AccountabilityOracle {
    fn new(
        verifier: Scheme<ed25519::PublicKey, MinPk>,
        codec: CodecConfig,
        seed: u64,
        targets: BTreeSet<Participant>,
    ) -> Self {
        Self {
            verifier,
            rng: TestRng::new(seed),
            codec,
            targets,
            observers: BTreeMap::new(),
        }
    }

    fn proves(&self, observer: usize, target: Participant) -> bool {
        self.observers
            .get(&observer)
            .is_some_and(|claims| claims.proven.contains(&target))
    }

    fn claims(&mut self, observer: usize) -> &mut ObserverClaims {
        self.observers.entry(observer).or_default()
    }

    fn record_artifact(&mut self, observer: usize, artifact: &Artifact<MinPk, Sha256Digest>) {
        match artifact {
            Artifact::TransactionBlock(block)
                if self.targets.contains(&block.signer())
                    && self.verifier.verify_transaction_block(block) =>
            {
                self.claims(observer)
                    .record_producer(block.signer(), block.header());
            }
            Artifact::LeaderBlock(block)
                if self.targets.contains(&block.signer())
                    && self.verifier.verify_leader_block(block, &Sequential) =>
            {
                self.claims(observer)
                    .record_leader(block.signer(), block.block());
            }
            Artifact::Vote(vote)
                if self.targets.contains(&vote.signer()) && self.verifier.verify_vote(vote) =>
            {
                self.claims(observer)
                    .record_vote(vote.signer(), vote.body());
            }
            Artifact::NoVote(novote)
                if self.targets.contains(&novote.signer())
                    && self.verifier.verify_novote(novote) =>
            {
                self.claims(observer)
                    .record_novote(novote.signer(), novote.view());
            }
            Artifact::DaVote(vote)
                if self.targets.contains(&vote.signer()) && self.verifier.verify_da_vote(vote) =>
            {
                self.claims(observer)
                    .record_da_vote(vote.signer(), vote.header());
            }
            Artifact::Vqc(certificate) => self.record_vqc(observer, certificate),
            Artifact::Lqc(certificate) => self.record_lqc(observer, certificate),
            Artifact::TransactionBlock(_)
            | Artifact::DaVote(_)
            | Artifact::DaCertificate(_)
            | Artifact::LeaderBlock(_)
            | Artifact::Vote(_)
            | Artifact::NoVote(_)
            | Artifact::Nullify(_)
            | Artifact::Nullification(_) => {}
        }
    }

    fn record_vqc(&mut self, observer: usize, certificate: &Vqc<MinPk, Sha256Digest>) {
        if self
            .verifier
            .verify_vqc::<_, Sha256, _>(&mut self.rng, certificate, &Sequential)
            .is_none()
        {
            return;
        }
        let leader = certificate.leader();
        for signer in certificate.tally().signers().iter() {
            if !self.targets.contains(&signer) {
                continue;
            }
            let vote = certificate
                .tally()
                .vote::<MinPk, Sha256>(leader, signer, self.codec)
                .expect("a verified V-QC has a reversible tally");
            self.claims(observer).record_vote(signer, &vote);
        }
        for signer in certificate.novoters().iter() {
            if !self.targets.contains(&signer) {
                continue;
            }
            self.claims(observer)
                .record_novote(signer, certificate.view());
        }
        for conflicting in certificate.conflicting_votes() {
            if !self.targets.contains(&conflicting.signer()) {
                continue;
            }
            let vote = conflicting
                .vote_body(leader.round(), self.codec)
                .expect("a verified V-QC has a reversible conflicting vote");
            self.claims(observer)
                .record_vote(conflicting.signer(), &vote);
        }
    }

    fn record_lqc(
        &mut self,
        observer: usize,
        certificate: &crate::multimmit::types::Lqc<MinPk, Sha256Digest>,
    ) {
        if self
            .verifier
            .verify_lqc::<_, Sha256, _>(&mut self.rng, certificate, &Sequential)
            .is_none()
        {
            return;
        }
        for signer in certificate.tally().signers().iter() {
            if !self.targets.contains(&signer) {
                continue;
            }
            let vote = certificate
                .tally()
                .vote::<MinPk, Sha256>(certificate.leader(), signer, self.codec)
                .expect("a verified L-QC has a reversible tally");
            self.claims(observer).record_vote(signer, &vote);
        }
    }

    fn record_wire(&mut self, observer: usize, plane: u64, bytes: &[u8]) {
        let Ok(bounds) = self.codec.encoded_bounds::<MinPk, Sha256Digest>() else {
            return;
        };
        match plane {
            0 => {
                let config = EnvelopeConfig {
                    max_frame_bytes: bounds.max_data_frame_bytes(),
                    epoch: self.verifier.epoch(),
                    payload: (),
                };
                let Ok(message) = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
                    Copying(bytes),
                    &config,
                ) else {
                    return;
                };
                self.record_artifact(observer, &message.into_payload().into_artifact());
            }
            1 => {
                let config = EnvelopeConfig {
                    max_frame_bytes: bounds.max_consensus_frame_bytes(),
                    epoch: self.verifier.epoch(),
                    payload: self.codec,
                };
                let Ok(message) = Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(
                    Copying(bytes),
                    &config,
                ) else {
                    return;
                };
                for artifact in message.into_payload().into_artifacts() {
                    self.record_artifact(observer, &artifact);
                }
            }
            2 => {
                let config = EnvelopeConfig {
                    max_frame_bytes: bounds.max_certificate_frame_bytes(),
                    epoch: self.verifier.epoch(),
                    payload: self.codec,
                };
                let Ok(message) = Envelope::<CertificateMessage<MinPk, Sha256Digest>>::decode_cfg(
                    Copying(bytes),
                    &config,
                ) else {
                    return;
                };
                self.record_artifact(observer, &message.into_payload().into_artifact());
            }
            _ => {}
        }
    }
}

#[derive(Default)]
struct Agreement {
    leaders: BTreeMap<View, Sha256Digest>,
    facts: BTreeMap<FinalityId<Sha256Digest>, FinalityFact<Sha256Digest>>,
    leader_views: BTreeMap<Sha256Digest, View>,
    leader_parents: BTreeMap<Sha256Digest, CertificateId<Sha256Digest>>,
    certificates: BTreeMap<CertificateId<Sha256Digest>, Sha256Digest>,
    producer_parents: BTreeMap<BlockRef<Sha256Digest>, BlockRef<Sha256Digest>>,
    blocks: BTreeMap<u32, BTreeMap<u64, BlockRef<Sha256Digest>>>,
    leader_blocks: BTreeMap<Sha256Digest, LeaderBlock<MinPk, Sha256Digest>>,
    pending_votes: BTreeMap<Sha256Digest, Vec<VoteBody<Sha256Digest>>>,
}

impl Agreement {
    fn record_header(&mut self, node: usize, header: &TransactionBlockHeader<Sha256Digest>) {
        let block = header.block_ref::<Sha256>();
        let parent = BlockRef::new(
            header.chain(),
            Height::new(header.height().get() - 1),
            header.parent(),
        );
        if let Some(previous) = self.producer_parents.insert(block, parent) {
            assert_eq!(
                previous, parent,
                "one producer block has conflicting parents"
            );
        }
        self.validate_producer_histories(node);
    }

    fn record_payload_path(
        &mut self,
        node: usize,
        epoch: Epoch,
        mut parent: BlockRef<Sha256Digest>,
        payloads: &[Sha256Digest],
    ) -> Vec<BlockRef<Sha256Digest>> {
        let mut path = Vec::with_capacity(payloads.len() + 1);
        path.push(parent);
        for payload in payloads {
            let header = TransactionBlockHeader::new(
                epoch,
                parent.chain(),
                Height::new(parent.height().get() + 1),
                parent.digest(),
                *payload,
            )
            .expect("validated proposal and vote paths cannot overflow");
            self.record_header(node, &header);
            parent = header.block_ref::<Sha256>();
            path.push(parent);
        }
        path
    }

    fn record_vote_body(&mut self, node: usize, body: &VoteBody<Sha256Digest>) {
        let leader_digest = body.leader();
        let Some(leader) = self.leader_blocks.get(&leader_digest).cloned() else {
            self.pending_votes
                .entry(leader_digest)
                .or_default()
                .push(body.clone());
            return;
        };
        if !body.valid_for::<Sha256, MinPk>(&leader) {
            return;
        }
        for ((proposal, position), extension) in leader
            .proposals()
            .iter()
            .zip(body.positions())
            .zip(body.extensions())
        {
            if let Anchor::Certificate(certificate) = proposal.anchor() {
                self.record_header(node, certificate.header());
            }
            let proposal_path = self.record_payload_path(
                node,
                leader.round().epoch(),
                proposal.anchor().block_ref::<Sha256>(),
                proposal.payloads(),
            );
            let parent = proposal_path[position.get() as usize];
            self.record_payload_path(node, leader.round().epoch(), parent, extension.payloads());
        }
    }

    fn descends_from(
        &self,
        mut descendant: BlockRef<Sha256Digest>,
        ancestor: BlockRef<Sha256Digest>,
    ) -> Option<bool> {
        while descendant.height() > ancestor.height() {
            let parent = self.producer_parents.get(&descendant)?;
            descendant = *parent;
        }
        Some(descendant == ancestor)
    }

    fn validate_producer_histories(&self, node: usize) {
        for (&chain_id, chain) in &self.blocks {
            let known = chain.values().copied().collect::<Vec<_>>();
            for (index, ancestor) in known.iter().copied().enumerate() {
                for descendant in known[index + 1..].iter().copied() {
                    if let Some(compatible) = self.descends_from(descendant, ancestor) {
                        assert!(
                            compatible,
                            "honest nodes finalized incompatible producer histories on chain {chain_id} at heights {} and {} (latest reporter: {node})",
                            ancestor.height(),
                            descendant.height(),
                        );
                    }
                }
            }
        }
    }

    fn producer_histories_complete(&self) -> bool {
        self.blocks.values().all(|chain| {
            let finalized = chain.values().copied().collect::<Vec<_>>();
            finalized.iter().enumerate().all(|(index, &ancestor)| {
                finalized[index + 1..]
                    .iter()
                    .all(|&descendant| self.descends_from(descendant, ancestor) == Some(true))
            })
        })
    }

    fn record_leader(
        &mut self,
        view: View,
        leader: Sha256Digest,
        parent: CertificateId<Sha256Digest>,
    ) {
        if let Some(previous) = self.leader_views.insert(leader, view) {
            assert_eq!(previous, view, "one leader digest has conflicting views");
        }
        if let Some(previous) = self.leader_parents.insert(leader, parent) {
            assert_eq!(
                previous, parent,
                "one leader digest has conflicting parents"
            );
        }
    }

    fn record_leader_block(&mut self, node: usize, leader: &LeaderBlock<MinPk, Sha256Digest>) {
        let digest = leader.digest::<Sha256>();
        self.record_leader(leader.view(), digest, leader.parent());
        if let Some(previous) = self.leader_blocks.insert(digest, leader.clone()) {
            assert_eq!(
                previous, *leader,
                "one leader digest has conflicting bodies"
            );
        }
        for proposal in leader.proposals() {
            if let Anchor::Certificate(certificate) = proposal.anchor() {
                self.record_header(node, certificate.header());
            }
            self.record_payload_path(
                node,
                leader.round().epoch(),
                proposal.anchor().block_ref::<Sha256>(),
                proposal.payloads(),
            );
        }
        if let Some(votes) = self.pending_votes.remove(&digest) {
            for vote in votes {
                self.record_vote_body(node, &vote);
            }
        }
    }

    fn record_vqc(
        &mut self,
        node: usize,
        certificate: &Vqc<MinPk, Sha256Digest>,
        codec: CodecConfig,
    ) {
        let leader = certificate.leader().digest::<Sha256>();
        self.record_leader_block(node, certificate.leader());
        for signer in certificate.tally().signers().iter() {
            let vote = certificate
                .tally()
                .vote::<MinPk, Sha256>(certificate.leader(), signer, codec)
                .expect("a decoded V-QC has a reversible tally");
            self.record_vote_body(node, &vote);
        }
        let id = certificate.id::<Sha256>();
        if let Some(previous) = self.certificates.insert(id, leader) {
            assert_eq!(
                previous, leader,
                "one certificate names conflicting leaders"
            );
        }
    }

    fn record_wire(
        &mut self,
        node: usize,
        plane: u64,
        bytes: &[u8],
        epoch: Epoch,
        codec: CodecConfig,
    ) {
        let Ok(bounds) = codec.encoded_bounds::<MinPk, Sha256Digest>() else {
            return;
        };
        // Structurally decoded paths are digest-addressed hints. Agreement checks traverse them
        // only from machine-reported finality identities, which authenticate the referenced bytes.
        match plane {
            0 => {
                let config = EnvelopeConfig {
                    max_frame_bytes: bounds.max_data_frame_bytes(),
                    epoch,
                    payload: (),
                };
                let Ok(message) = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
                    Copying(bytes),
                    &config,
                ) else {
                    return;
                };
                match message.into_payload() {
                    DataMessage::Block(block) => self.record_header(node, block.header()),
                    DataMessage::DaVote(vote) => self.record_header(node, vote.header()),
                    DataMessage::DaCertificate(certificate) => {
                        self.record_header(node, certificate.header());
                    }
                }
            }
            1 => {
                let config = EnvelopeConfig {
                    max_frame_bytes: bounds.max_consensus_frame_bytes(),
                    epoch,
                    payload: codec,
                };
                let Ok(message) = Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(
                    Copying(bytes),
                    &config,
                ) else {
                    return;
                };
                match message.into_payload() {
                    ConsensusMessage::Proposal { parent, block } => {
                        if let Some(parent) = parent {
                            self.record_vqc(node, &parent, codec);
                        }
                        self.record_leader_block(node, block.block());
                    }
                    ConsensusMessage::Vote(vote) => self.record_vote_body(node, vote.body()),
                    ConsensusMessage::NoVote(_) | ConsensusMessage::Nullify(_) => {}
                }
            }
            2 => {
                let config = EnvelopeConfig {
                    max_frame_bytes: bounds.max_certificate_frame_bytes(),
                    epoch,
                    payload: codec,
                };
                let Ok(message) = Envelope::<CertificateMessage<MinPk, Sha256Digest>>::decode_cfg(
                    Copying(bytes),
                    &config,
                ) else {
                    return;
                };
                match message.into_payload() {
                    CertificateMessage::Vqc(certificate) => {
                        self.record_vqc(node, &certificate, codec);
                    }
                    CertificateMessage::Lqc(certificate) => {
                        let derived = certificate
                            .derive_vqc(codec)
                            .expect("a decoded L-QC derives its equivalent V-QC");
                        self.record_vqc(node, &derived, codec);
                    }
                    CertificateMessage::Nullification(_) => {}
                }
            }
            _ => {}
        }
    }

    fn leader_descends_from(
        &self,
        mut descendant: Sha256Digest,
        ancestor: Sha256Digest,
        ancestor_view: View,
    ) -> Option<bool> {
        let mut descendant_view = *self.leader_views.get(&descendant)?;
        while descendant_view > ancestor_view {
            let parent = self.leader_parents.get(&descendant)?;
            descendant = *self.certificates.get(parent)?;
            let parent_view = *self.leader_views.get(&descendant)?;
            assert!(
                parent_view < descendant_view,
                "a leader certificate must point to an earlier view"
            );
            descendant_view = parent_view;
        }
        Some(descendant_view == ancestor_view && descendant == ancestor)
    }

    fn validate_leader_histories(&self, node: usize) {
        let finalized = self
            .leaders
            .iter()
            .map(|(&view, &leader)| (view, leader))
            .collect::<Vec<_>>();
        for (index, (ancestor_view, ancestor)) in finalized.iter().copied().enumerate() {
            for (_, descendant) in finalized[index + 1..].iter().copied() {
                if let Some(compatible) =
                    self.leader_descends_from(descendant, ancestor, ancestor_view)
                {
                    assert!(
                        compatible,
                        "honest nodes finalized incompatible leader histories (latest reporter: {node})"
                    );
                }
            }
        }
    }

    fn leader_histories_complete(&self) -> bool {
        let finalized = self
            .leaders
            .iter()
            .map(|(&view, &leader)| (view, leader))
            .collect::<Vec<_>>();
        finalized
            .iter()
            .enumerate()
            .all(|(index, &(ancestor_view, ancestor))| {
                finalized[index + 1..].iter().all(|&(_, descendant)| {
                    self.leader_descends_from(descendant, ancestor, ancestor_view) == Some(true)
                })
            })
    }

    fn record(
        &mut self,
        node: usize,
        view: View,
        leader: Sha256Digest,
        blocks: &[BlockRef<Sha256Digest>],
    ) {
        if let Some(previous) = self.leaders.insert(view, leader) {
            assert_eq!(
                previous, leader,
                "honest nodes finalized different leaders at view {view} (latest reporter: {node})"
            );
        }
        for block in blocks {
            let chain = self.blocks.entry(block.chain().get()).or_default();
            if let Some(previous) = chain.insert(block.height().get(), *block) {
                assert_eq!(
                    previous,
                    *block,
                    "honest nodes finalized different producer blocks at chain {} height {} (latest reporter: {node})",
                    block.chain(),
                    block.height()
                );
            }
        }
        self.validate_producer_histories(node);
        self.validate_leader_histories(node);
    }

    fn record_fact(&mut self, node: usize, fact: &FinalityFact<Sha256Digest>) {
        if let Some(previous) = self.facts.insert(fact.id(), fact.clone()) {
            assert_eq!(
                previous, *fact,
                "one finality evidence identifier has conflicting facts"
            );
        }
        self.record_leader(fact.round().view(), fact.leader(), fact.parent());
        self.record(node, fact.round().view(), fact.leader(), fact.blocks());
    }
}

#[derive(Clone)]
struct ActivityReporter {
    node: usize,
    agreement: Arc<Mutex<Agreement>>,
    codec: CodecConfig,
}

impl crate::Reporter for ActivityReporter {
    type Activity = Activity<MinPk, Sha256Digest>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match activity {
            Activity::LeaderFinalized { fact } | Activity::LeaderFinalityUpdated { fact } => {
                self.agreement.lock().record_fact(self.node, &fact);
            }
            Activity::ProtocolAccepted { artifact, .. } => {
                let mut agreement = self.agreement.lock();
                match artifact.as_ref() {
                    Artifact::TransactionBlock(block) => {
                        agreement.record_header(self.node, block.header());
                    }
                    Artifact::DaVote(vote) => agreement.record_header(self.node, vote.header()),
                    Artifact::DaCertificate(certificate) => {
                        agreement.record_header(self.node, certificate.header());
                    }
                    Artifact::LeaderBlock(block) => {
                        agreement.record_leader_block(self.node, block.block());
                    }
                    Artifact::Vote(vote) => agreement.record_vote_body(self.node, vote.body()),
                    Artifact::Vqc(certificate) => {
                        agreement.record_vqc(self.node, certificate, self.codec);
                    }
                    Artifact::Lqc(certificate) => {
                        let derived = certificate
                            .derive_vqc(self.codec)
                            .expect("accepted L-QC derives its equivalent V-QC");
                        agreement.record_vqc(self.node, &derived, self.codec);
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        Feedback::Ok
    }
}

/// Retains independent agreement and accountability evidence for honest engines.
#[derive(Clone)]
struct Safety {
    agreement: Arc<Mutex<Agreement>>,
    block_snapshots: Arc<Mutex<Vec<BlockSnapshot>>>,
    delivered: BTreeMap<usize, Arc<Mutex<DeliveredEvidence>>>,
    verifier: Scheme<ed25519::PublicKey, MinPk>,
    targets: BTreeSet<Participant>,
    seed: u64,
    codec: CodecConfig,
}

struct BlockSnapshot {
    observer: usize,
    target: usize,
    delivered: DeliveredEvidence,
}

impl Safety {
    fn new(
        verifier: Scheme<ed25519::PublicKey, MinPk>,
        codec: CodecConfig,
        seed: u64,
        targets: BTreeSet<Participant>,
    ) -> Self {
        Self {
            agreement: Arc::new(Mutex::new(Agreement::default())),
            block_snapshots: Arc::new(Mutex::new(Vec::new())),
            delivered: BTreeMap::new(),
            verifier,
            targets,
            seed,
            codec,
        }
    }

    fn delivered(&mut self, node: usize) -> Arc<Mutex<DeliveredEvidence>> {
        Arc::clone(
            self.delivered
                .entry(node)
                .or_insert_with(|| Arc::new(Mutex::new(DeliveredEvidence::default()))),
        )
    }

    fn reporter(&self, node: usize) -> ActivityReporter {
        ActivityReporter {
            node,
            agreement: Arc::clone(&self.agreement),
            codec: self.codec,
        }
    }

    async fn observe(&mut self, cluster: &mut Cluster<MinPk>, honest: &[usize]) -> bool {
        cluster.observe_finality(honest).await;
        let mut complete = true;
        for &node in honest {
            let inspection = cluster
                .inspect(node)
                .await
                .expect("honest engine stays live");
            complete &= honest
                .iter()
                .all(|producer| inspection.chain_progress()[*producer].finalized().get() >= 2);
        }
        complete
    }

    fn finalized_leaders(&self) -> usize {
        self.agreement.lock().leaders.len()
    }

    fn assert_complete_histories(&self) {
        let agreement = self.agreement.lock();
        assert!(
            agreement.leader_histories_complete(),
            "finalized leaders require a complete authenticated ancestry path"
        );
        assert!(
            agreement.producer_histories_complete(),
            "finalized producer tips require complete authenticated ancestry paths"
        );
    }
}

/// Runs one bounded case. Input bytes seed runtime scheduling and directly select topology, twin
/// masks, delivery actions, and link perturbations.
pub(crate) fn fuzz(input: &[u8]) -> BTreeSet<(usize, usize)> {
    let mut seed = [0; 8];
    let copied = input.len().min(seed.len());
    seed[..copied].copy_from_slice(&input[..copied]);
    let seed = u64::from_le_bytes(seed);
    let mut schedule = Schedule::new(&input[..input.len().min(MAX_SCHEDULE_BYTES)]);
    let participants = if schedule.byte() == u8::MAX {
        LARGE_PARTICIPANTS
    } else {
        PARTICIPANTS
    };
    let faults = usize::from(schedule.byte() % N5f1::max_faults(participants) as u8) + 1;
    let mut placement = (0..participants as usize).collect::<Vec<_>>();
    schedule.shuffle(&mut placement);
    let byzantine = placement[..faults].to_vec();
    let honest = placement[faults..].to_vec();

    let mut leader_order = (0..participants as usize).collect::<Vec<_>>();
    schedule.shuffle(&mut leader_order);
    let leaders = LeaderSchedule::round_robin(participants as usize)
        .clone_with(
            leader_order
                .iter()
                .copied()
                .map(Participant::from_usize)
                .collect(),
        )
        .expect("a permutation is a valid leader schedule");
    let all = participant_mask(0..participants as usize);
    let rounds = usize::from(schedule.byte() % 4) + 1;
    let scenario = Scenario::new(
        (0..rounds)
            .map(|round| {
                RoundScenario::new(
                    leader_order[(round + 1) % leader_order.len()],
                    u64::from(schedule.word()) & all,
                    u64::from(schedule.word()) & all,
                )
            })
            .collect(),
    );
    let deadline_offset = Duration::from_millis(250 + u64::from(schedule.word() % 1_251));
    let latency = Duration::from_millis(u64::from(schedule.byte() % 5) + 1);
    let jitter = Duration::from_millis(u64::from(schedule.byte() % 6));
    let delivery_scripts = (0..participants as usize)
        .map(|_| (0..4).map(|_| schedule.take::<16>()).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let link_steps = (0..usize::from(schedule.byte() % 4) + 1)
        .map(|_| {
            let from = usize::from(schedule.byte()) % participants as usize;
            let mut to = usize::from(schedule.byte()) % (participants as usize - 1);
            if to >= from {
                to += 1;
            }
            LinkStep {
                from,
                to,
                success_rate: f64::from(schedule.byte() % 3) / 2.0,
                observations: usize::from(schedule.byte() % 10) + 1,
            }
        })
        .collect::<Vec<_>>();
    let executor = deterministic::Runner::new(
        deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(180))),
    );
    executor.start(move |context| async move {
        let coverage = Arc::new(Mutex::new(Coverage::default()));
        let deadline = context.current() + deadline_offset;
        let mut cluster = Cluster::<MinPk>::new(&context, ClusterOptions {
            leaders: Some(leaders),
            latency: Some(latency),
            jitter: Some(jitter),
            ..ClusterOptions::new(seed, participants)
        }).await;
        for participant in 0..participants as usize {
            assert_eq!(cluster.reserve_slot(""), participant);
        }
        let fixture = cluster.fixture();
        let codec = fixture.codec();
        let targets = byzantine
            .iter()
            .copied()
            .map(Participant::from_usize)
            .collect();
        let mut safety = Safety::new(fixture.verifier, codec, seed, targets);
        let identities = cluster.identities();
        for &participant in &honest {
            safety.delivered(participant);
        }
        let delivered = safety.delivered.clone();
        let block_snapshots = Arc::clone(&safety.block_snapshots);
        let block_identities = identities.clone();
        let block_honest = honest.clone();
        cluster.set_block_callback(move |observer, target| {
            let observer = block_identities
                .iter()
                .position(|identity| identity == &observer)
                .expect("a blocking observer belongs to the committee");
            if !block_honest.contains(&observer) {
                return;
            }
            let target = block_identities
                .iter()
                .position(|identity| identity == &target)
                .expect("a blocked target belongs to the committee");
            let snapshot = delivered[&observer].lock().clone();
            block_snapshots.lock().push(BlockSnapshot {
                observer,
                target,
                delivered: snapshot,
            });
        });
        for &participant in &honest {
            let delivered = safety.delivered(participant);
            let mut planes = Vec::new();
            for plane in 0..4 {
                let (sender, receiver) = cluster.tap(participant, plane).await;
                let receiver = RandomizedReceiver::randomized(
                    context.child("random_delivery")
                        .with_attribute("participant", participant).with_attribute("plane", plane),
                    receiver,
                    delivery_scripts[participant][plane as usize],
                    deadline,
                    coverage.clone(),
                    WireEvidence {
                        node: participant,
                        plane,
                        agreement: Arc::clone(&safety.agreement),
                        delivered: Arc::clone(&delivered),
                        epoch: Epoch::new(seed),
                        codec: safety.codec,
                    },
                );
                planes.push((sender, receiver));
            }
            let [data, consensus, certificates, resolver] = planes.try_into()
                .unwrap_or_else(|_| panic!("exactly four network planes"));
            cluster
                .launch_with_transports_and_reporter(
                    participant,
                    participant,
                    None,
                    data,
                    consensus,
                    certificates,
                    resolver,
                    safety.reporter(participant),
                )
                .await;
        }
        let mut twins = Vec::new();
        for (index, &participant) in byzantine.iter().enumerate() {
            twins.push(Box::pin(launch_scenario_twins(
                &context, &mut cluster, participant, &scenario, twin_labels(index),
            )).await);
        }
        cluster.await_ready(&honest).await;
        cluster.produce_once();
        for step in link_steps {
            cluster
                .set_directed_success_rate(step.from, step.to, step.success_rate)
                .await;
            for _ in 0..step.observations {
                context.sleep(Duration::from_millis(20)).await;
                safety.observe(&mut cluster, &honest).await;
            }
        }
        context.sleep_until(deadline + Duration::from_millis(20)).await;
        // Link changes inspect only honest engines: faulty twin processes may have exited.
        for from in 0..participants as usize {
            for to in 0..participants as usize {
                if from != to { cluster.set_directed_success_rate(from, to, 1.0).await; }
            }
        }
        for &producer in &honest {
            cluster.app(producer).permit_builds(2);
        }
        let mut complete = false;
        for _ in 0..1200 {
            context.sleep(Duration::from_millis(100)).await;
            complete = safety.observe(&mut cluster, &honest).await;
            if complete { break; }
        }
        let blocked = cluster.blocked_peers().await;
        let blocked = blocked
            .iter()
            .map(|(observer, target)| {
                let observer = identities
                    .iter()
                    .position(|identity| identity == observer)
                    .expect("a blocking observer belongs to the committee");
                let target = identities
                    .iter()
                    .position(|identity| identity == target)
                    .expect("a blocked target belongs to the committee");
                (observer, target)
            })
            .collect::<BTreeSet<_>>();
        for &(_, target) in &blocked {
            assert!(
                byzantine.contains(&target),
                "honest participant {target} was blocked without objective evidence"
            );
        }
        let snapshots = safety.block_snapshots.lock();
        let mut objective_blocks = BTreeSet::new();
        for snapshot in snapshots.iter() {
            assert!(
                snapshot.delivered.proves(
                    snapshot.observer,
                    Participant::from_usize(snapshot.target),
                    safety.verifier.clone(),
                    safety.codec,
                    safety.seed,
                    safety.targets.clone(),
                ),
                "honest observer {} blocked participant {} before receiving authenticated conflicting claims from that signer",
                snapshot.observer,
                snapshot.target,
            );
            objective_blocks.insert((snapshot.observer, snapshot.target));
        }
        assert!(
            blocked
                .iter()
                .all(|pair| !honest.contains(&pair.0) || objective_blocks.contains(pair)),
            "every honest-node block has a synchronous evidence snapshot"
        );
        drop(snapshots);
        for (&participant, slots) in byzantine.iter().zip(&twins) {
            let equivocated = slots.has_producer_equivocation(&cluster, participant);
            let selective = slots.traffic.lock().iter().filter(|transmission| {
                assert_eq!(transmission.artifact.signer, Participant::from_usize(participant));
                assert_eq!(transmission.artifact.source, identities[participant]);
                let (primary, secondary) = scenario.partitions(transmission.artifact.view, TERM, &identities);
                let expected = match transmission.origin {
                    SplitOrigin::Primary => primary,
                    SplitOrigin::Secondary => secondary,
                };
                if let Some(actual) = &transmission.broadcast_recipients {
                    assert_eq!(actual, &expected, "actual recipients honor the sampled twin mask");
                }
                transmission.broadcast_recipients.as_ref()
                    .is_some_and(|recipients| !recipients.is_empty() && recipients.len() < identities.len())
            }).count();
            let mut reached = coverage.lock();
            reached.conflicting_producers += usize::from(equivocated);
            reached.selective_broadcasts += selective;
        }
        coverage.lock().finalized_leaders = safety.finalized_leaders();
        let reached = coverage.lock();
        assert!(complete, "seed={seed}, byzantine={byzantine:?}, coverage={reached:?}: fair suffix must finalize honest producers");
        assert!(reached.fair_deliveries > 0);
        drop(reached);
        safety.assert_complete_histories();
        objective_blocks
    })
}

#[cfg(test)]
fn oracle(fixture: &Committee<MinPk>) -> AccountabilityOracle {
    AccountabilityOracle::new(
        fixture.verifier.clone(),
        fixture.codec(),
        0,
        (0..PARTICIPANTS).map(Participant::new).collect(),
    )
}

#[cfg(test)]
fn deliver_data(
    oracle: &mut AccountabilityOracle,
    fixture: &Committee<MinPk>,
    observer: usize,
    message: DataMessage<MinPk, Sha256Digest>,
) {
    let frame = Envelope::new(fixture.config.epoch(), message).encode();
    oracle.record_wire(observer, 0, frame.as_ref());
}

#[cfg(test)]
fn deliver_consensus(
    oracle: &mut AccountabilityOracle,
    fixture: &Committee<MinPk>,
    observer: usize,
    message: ConsensusMessage<MinPk, Sha256Digest>,
) {
    let frame = Envelope::new(fixture.config.epoch(), message).encode();
    oracle.record_wire(observer, 1, frame.as_ref());
}

#[cfg(test)]
fn deliver_certificate(
    oracle: &mut AccountabilityOracle,
    fixture: &Committee<MinPk>,
    observer: usize,
    message: CertificateMessage<MinPk, Sha256Digest>,
) {
    let frame = Envelope::new(fixture.config.epoch(), message).encode();
    oracle.record_wire(observer, 2, frame.as_ref());
}

#[test]
fn accountability_oracle_requires_delivered_verified_evidence() {
    let fixture = Committee::<MinPk>::new(7, PARTICIPANTS, Limits::new(2, 1).unwrap());
    let mut oracle = oracle(&fixture);
    let first = fixture.signed_block(0, Sha256::hash(&[b"first"]));
    let second = fixture.signed_block(0, Sha256::hash(&[b"second"]));
    let target = first.signer();

    deliver_data(&mut oracle, &fixture, 0, DataMessage::Block(first.clone()));
    assert!(!oracle.proves(0, target), "one claim is not evidence");

    let forged = SignedTransactionBlock::new(second.header().clone(), first.attestation().clone());
    deliver_data(&mut oracle, &fixture, 0, DataMessage::Block(forged));
    assert!(!oracle.proves(0, target), "a forged claim is not evidence");
    assert!(
        !oracle.proves(1, target),
        "claims delivered elsewhere are not observer evidence"
    );

    deliver_data(&mut oracle, &fixture, 0, DataMessage::Block(second));
    assert!(oracle.proves(0, target));
    assert!(!oracle.proves(1, target));
}

#[test]
fn accountability_oracle_covers_wire_equivocation_families() {
    let fixture = Committee::<MinPk>::new(11, PARTICIPANTS, Limits::new(2, 1).unwrap());
    let mut oracle = oracle(&fixture);

    let first = fixture.signed_block(0, Sha256::hash(&[b"parent"]));
    let adjacent = TransactionBlockHeader::new(
        fixture.config.epoch(),
        ChainId::new(0),
        Height::new(2),
        Sha256::hash(&[b"wrong parent"]),
        Sha256::hash(&[b"child"]),
    )
    .unwrap();
    let adjacent =
        crate::multimmit::mocks::sign_transaction_block(&fixture.signers[0], adjacent).unwrap();
    deliver_data(&mut oracle, &fixture, 0, DataMessage::Block(first));
    deliver_data(&mut oracle, &fixture, 0, DataMessage::Block(adjacent));
    assert!(oracle.proves(0, Participant::new(0)));

    let plain_leader = fixture.leader_block(2);
    let parent = fixture.vqc(1);
    let parented_leader = fixture.leader_block_with_parent(2, &parent);
    deliver_consensus(
        &mut oracle,
        &fixture,
        1,
        ConsensusMessage::Proposal {
            parent: None,
            block: Box::new(plain_leader.clone()),
        },
    );
    deliver_consensus(
        &mut oracle,
        &fixture,
        1,
        ConsensusMessage::Proposal {
            parent: Some(Box::new(parent)),
            block: Box::new(parented_leader.clone()),
        },
    );
    assert!(oracle.proves(1, plain_leader.signer()));

    let first_vote = fixture.vote(3, &plain_leader);
    let second_vote = fixture.vote(3, &parented_leader);
    deliver_consensus(&mut oracle, &fixture, 2, ConsensusMessage::Vote(first_vote));
    deliver_consensus(
        &mut oracle,
        &fixture,
        2,
        ConsensusMessage::Vote(second_vote),
    );
    assert!(oracle.proves(2, Participant::new(3)));

    let vote = fixture.vote(4, &plain_leader);
    let novote = fixture.novote(4, 2);
    deliver_consensus(&mut oracle, &fixture, 3, ConsensusMessage::Vote(vote));
    deliver_consensus(&mut oracle, &fixture, 3, ConsensusMessage::NoVote(novote));
    assert!(oracle.proves(3, Participant::new(4)));

    let first_header = fixture.transaction_header(0, Sha256::hash(&[b"da first"]));
    let second_header = fixture.transaction_header(0, Sha256::hash(&[b"da second"]));
    deliver_data(
        &mut oracle,
        &fixture,
        4,
        DataMessage::DaVote(fixture.da_vote(5, first_header)),
    );
    deliver_data(
        &mut oracle,
        &fixture,
        4,
        DataMessage::DaVote(fixture.da_vote(5, second_header)),
    );
    assert!(oracle.proves(4, Participant::new(5)));
}

#[test]
fn accountability_oracle_expands_authenticated_certificate_transcripts() {
    let fixture = Committee::<MinPk>::new(13, PARTICIPANTS, Limits::new(2, 1).unwrap());
    let mut oracle = oracle(&fixture);
    let leader = fixture.leader_block(1);
    let messages =
        std::iter::once(crate::multimmit::types::ViewMessage::NoVote(
            fixture.novote(0, 1),
        ))
        .chain((1..fixture.codec().view_quorum()).map(|signer| {
            crate::multimmit::types::ViewMessage::Vote(fixture.vote(signer, &leader))
        }))
        .collect::<Vec<_>>();
    let vqc = fixture
        .verifier
        .assemble_vqc::<Sha256, _>(leader.block().clone(), &messages, &Sequential)
        .unwrap();

    deliver_certificate(
        &mut oracle,
        &fixture,
        0,
        CertificateMessage::Lqc(fixture.lqc(1)),
    );
    assert!(
        !oracle.proves(0, Participant::new(0)),
        "one authenticated certificate transcript is not evidence"
    );
    deliver_certificate(&mut oracle, &fixture, 0, CertificateMessage::Vqc(vqc));
    assert!(oracle.proves(0, Participant::new(0)));
}

#[test]
fn randomized_twins_smoke() {
    fuzz(&0u64.to_le_bytes());
}

#[test]
fn randomized_twins_correlates_blocks_with_observer_evidence() {
    let outcome = fuzz(&[10, 10, 1]);
    assert!(outcome.contains(&(0, 3)));
}

#[test]
fn reporter_oracle_distinguishes_incomplete_ancestry_from_conflict() {
    let first = Sha256::hash(&[b"first"]);
    let second = Sha256::hash(&[b"second"]);
    let missing = CertificateId::new(Sha256::hash(&[b"missing"]));
    let mut agreement = Agreement::default();
    agreement.record_leader(View::new(1), first, missing);
    agreement.record(0, View::new(1), first, &[]);
    agreement.record_leader(View::new(2), second, missing);
    agreement.record(1, View::new(2), second, &[]);
    assert_eq!(
        agreement.leader_descends_from(second, first, View::new(1)),
        None
    );
    assert!(!agreement.leader_histories_complete());
}

#[test]
#[should_panic(expected = "honest nodes finalized different leaders")]
fn reporter_oracle_rejects_conflicting_finality() {
    let mut agreement = Agreement::default();
    agreement.record(0, View::new(7), Sha256::hash(&[b"left"]), &[]);
    agreement.record(1, View::new(7), Sha256::hash(&[b"right"]), &[]);
}

#[test]
#[should_panic(expected = "honest nodes finalized incompatible producer histories")]
fn reporter_oracle_rejects_cross_height_forks() {
    let epoch = Epoch::new(1);
    let chain = ChainId::new(0);
    let first = TransactionBlockHeader::new(
        epoch,
        chain,
        crate::multimmit::types::Height::new(1),
        Sha256::hash(&[b"genesis"]),
        Sha256::hash(&[b"first"]),
    )
    .unwrap();
    let fork = TransactionBlockHeader::new(
        epoch,
        chain,
        crate::multimmit::types::Height::new(2),
        Sha256::hash(&[b"other first"]),
        Sha256::hash(&[b"fork"]),
    )
    .unwrap();
    let first_ref = first.block_ref::<Sha256>();
    let fork_ref = fork.block_ref::<Sha256>();
    let mut agreement = Agreement::default();
    agreement.record_header(0, &first);
    agreement.record_header(1, &fork);
    agreement.record(0, View::new(1), Sha256::hash(&[b"leader 1"]), &[first_ref]);
    agreement.record(1, View::new(2), Sha256::hash(&[b"leader 2"]), &[fork_ref]);
}

#[test]
#[should_panic(expected = "honest nodes finalized incompatible leader histories")]
fn reporter_oracle_rejects_cross_view_leader_forks() {
    let left = Sha256::hash(&[b"left"]);
    let right = Sha256::hash(&[b"right"]);
    let child = Sha256::hash(&[b"child"]);
    let genesis = CertificateId::new(Sha256::hash(&[b"genesis"]));
    let right_certificate = CertificateId::new(Sha256::hash(&[b"right certificate"]));
    let mut agreement = Agreement::default();
    agreement.record_leader(View::new(1), left, genesis);
    agreement.record(0, View::new(1), left, &[]);
    agreement.record_leader(View::new(1), right, genesis);
    agreement.certificates.insert(right_certificate, right);
    agreement.record_leader(View::new(2), child, right_certificate);
    agreement.record(1, View::new(2), child, &[]);
}

#[test]
#[should_panic(expected = "one finality evidence identifier has conflicting facts")]
fn reporter_oracle_rejects_conflicting_exact_evidence() {
    let evidence = FinalityId::Direct(Sha256::hash(&[b"evidence"]));
    let parent = CertificateId::new(Sha256::hash(&[b"parent"]));
    let leader = Sha256::hash(&[b"leader"]);
    let fact = |votes| {
        FinalityFact::for_test(
            evidence,
            Round::new(Epoch::new(1), View::new(1)),
            leader,
            parent,
            votes,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    };
    let mut agreement = Agreement::default();
    agreement.record_fact(0, &fact(5));
    agreement.record_fact(1, &fact(6));
}
