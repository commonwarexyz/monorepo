//! Scripted Twins campaigns: exhaustive Byzantine placements, leader censorship, and held,
//! reordered, and duplicated delivery before a fair suffix.

use super::*;
use crate::{
    multimmit::{
        Inspection,
        mocks::{Committee, cluster::link_all},
        types::{
            Anchor, ChainProposal, DaVote, LeaderBlock, SignedLeaderBlock, SignedTransactionBlock,
            Vote, genesis_tip_commitment,
        },
    },
    types::{Attributable as _, Round},
};
use commonware_codec::Encode as _;
use commonware_macros::{test_group, test_traced};
use commonware_p2p::{
    Manager as _, Provider as _, Receiver as _, Sender as _, simulated::Sender as SimulatedSender,
};
use commonware_utils::ordered::Set;

/// Each shard contains one singleton and five unordered pairs at `n=11, f=2`.
const F2_PLACEMENT_SHARDS: usize = LARGE_PARTICIPANTS as usize;

/// Scripted adversarial rounds before the fair synchronous suffix.
const ROUNDS: usize = 2;

const FAIR_SUFFIX_VIEW: View = View::new(3);
const CENSORSHIP_VIEW: View = View::new(1);
const CENSORSHIP_DEADLINE_VIEW: View = View::new(2);

type NetworkSender = SimulatedSender<ed25519::PublicKey, deterministic::Context>;

/// One held first-half delivery awaiting its scripted reordering.
struct ReorderedDelivery {
    message: commonware_p2p::Message<ed25519::PublicKey>,
    artifact: DeliveryArtifact,
}

#[derive(Default)]
struct InclusionEvents {
    blocks: Vec<(usize, SignedTransactionBlock<MinPk, Sha256Digest>)>,
    da_votes: Vec<(usize, DaVote<MinPk, Sha256Digest>)>,
    proposals: Vec<(usize, SignedLeaderBlock<MinPk, Sha256Digest>)>,
    votes: Vec<(usize, Vote<MinPk, Sha256Digest>)>,
}

#[derive(Clone)]
struct InclusionTrace {
    events: Arc<Mutex<InclusionEvents>>,
    epoch: Epoch,
    codec: CodecConfig,
    verifier: Scheme<ed25519::PublicKey, MinPk>,
}

impl InclusionTrace {
    fn new(fixture: &Committee<MinPk>) -> Self {
        Self {
            events: Arc::new(Mutex::new(InclusionEvents::default())),
            epoch: fixture.config.epoch(),
            codec: fixture.codec(),
            verifier: fixture.verifier.clone(),
        }
    }

    fn record(&self, source: usize, plane: u64, bytes: &[u8]) -> bool {
        match plane {
            0 => self.record_data(source, bytes),
            1 => {
                self.record_consensus(source, bytes);
                false
            }
            _ => false,
        }
    }

    fn record_data(&self, source: usize, bytes: &[u8]) -> bool {
        let Some(bounds) = self.codec.encoded_bounds::<MinPk, Sha256Digest>() else {
            return false;
        };
        let Ok(envelope) = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
            Copying(bytes),
            &EnvelopeConfig {
                max_frame_bytes: bounds.max_data_frame_bytes(),
                epoch: self.epoch,
                payload: self.codec,
            },
        ) else {
            return false;
        };
        let mut events = self.events.lock();
        match envelope.into_payload() {
            DataMessage::Block(block) if self.verifier.verify_transaction_block(&block) => {
                assert_eq!(block.signer(), Participant::from_usize(source));
                events.blocks.push((source, block));
                false
            }
            DataMessage::DaVote(vote) if self.verifier.verify_da_vote(&vote) => {
                assert_eq!(vote.signer(), Participant::from_usize(source));
                events.da_votes.push((source, vote));
                true
            }
            _ => false,
        }
    }

    fn record_consensus(&self, source: usize, bytes: &[u8]) {
        let Some(bounds) = self.codec.encoded_bounds::<MinPk, Sha256Digest>() else {
            return;
        };
        let Ok(envelope) = Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(
            Copying(bytes),
            &EnvelopeConfig {
                max_frame_bytes: bounds.max_consensus_frame_bytes(),
                epoch: self.epoch,
                payload: self.codec,
            },
        ) else {
            return;
        };
        let mut events = self.events.lock();
        match envelope.into_payload() {
            ConsensusMessage::Proposal { block, .. }
                if self.verifier.verify_leader_block(&block, &Sequential) =>
            {
                assert_eq!(block.signer(), Participant::from_usize(source));
                events.proposals.push((source, *block));
            }
            ConsensusMessage::Vote(vote) if self.verifier.verify_vote(&vote) => {
                assert_eq!(vote.signer(), Participant::from_usize(source));
                events.votes.push((source, vote));
            }
            _ => {}
        }
    }

    fn block_from(&self, source: usize) -> Option<SignedTransactionBlock<MinPk, Sha256Digest>> {
        self.events
            .lock()
            .blocks
            .iter()
            .find(|(sender, _)| *sender == source)
            .map(|(_, block)| block.clone())
    }

    fn da_voters(&self, header: &TransactionBlockHeader<Sha256Digest>) -> Vec<usize> {
        let mut voters = self
            .events
            .lock()
            .da_votes
            .iter()
            .filter(|(_, vote)| vote.header() == header)
            .map(|(source, _)| *source)
            .collect::<Vec<_>>();
        voters.sort_unstable();
        voters.dedup();
        voters
    }

    fn votes_for(&self, leader: Sha256Digest) -> Vec<(usize, Vote<MinPk, Sha256Digest>)> {
        let mut votes = BTreeMap::new();
        for (source, vote) in &self.events.lock().votes {
            if vote.body().leader() == leader {
                votes.entry(*source).or_insert_with(|| vote.clone());
            }
        }
        votes.into_iter().collect()
    }

    fn proposal_at(&self, view: View) -> Option<SignedLeaderBlock<MinPk, Sha256Digest>> {
        self.events
            .lock()
            .proposals
            .iter()
            .find(|(_, proposal)| proposal.view() == view)
            .map(|(_, proposal)| proposal.clone())
    }
}

#[derive(Debug, Default)]
struct DeliveryEvents {
    held: Option<DeliveryArtifact>,
    reordered: Option<DeliveryArtifact>,
    duplicated: Option<DeliveryArtifact>,
    fair: Option<DeliveryArtifact>,
}

/// Protocol artifacts selected by one deterministic delivery script.
#[derive(Clone, Default)]
struct DeliveryScript(Arc<Mutex<DeliveryEvents>>);

impl DeliveryScript {
    fn record_held(&self, artifact: DeliveryArtifact) {
        let mut events = self.0.lock();
        assert!(
            events.held.replace(artifact).is_none(),
            "one artifact is held"
        );
    }

    fn record_delivery(&self, event: DeliveryEvent, artifact: DeliveryArtifact) {
        let mut events = self.0.lock();
        let slot = match event {
            DeliveryEvent::Reordered => &mut events.reordered,
            DeliveryEvent::Duplicated => &mut events.duplicated,
            DeliveryEvent::Fair => &mut events.fair,
        };
        assert!(
            slot.replace(artifact).is_none(),
            "delivery event is recorded once"
        );
    }

    fn is_complete(&self) -> bool {
        let events = self.0.lock();
        events.held.is_some()
            && events.reordered.is_some()
            && events.duplicated.is_some()
            && events.fair.is_some()
    }

    fn assert_complete(&self, source: &ed25519::PublicKey, signer: Participant) {
        let events = self.0.lock();
        let held = events.held.as_ref().expect("prefix artifact was held");
        let reordered = events
            .reordered
            .as_ref()
            .expect("a distinct prefix artifact was delivered first");
        let duplicated = events
            .duplicated
            .as_ref()
            .expect("the held artifact was delivered twice");
        let fair = events
            .fair
            .as_ref()
            .expect("a fair-suffix artifact was delivered");

        for artifact in [held, reordered, duplicated, fair] {
            assert_eq!(&artifact.source, source, "authenticated source is exact");
            assert_eq!(artifact.signer, signer, "protocol signer is exact");
        }
        assert!(
            held.view < FAIR_SUFFIX_VIEW,
            "held artifact is from the prefix"
        );
        assert!(
            reordered.view < FAIR_SUFFIX_VIEW,
            "reordered artifact is from the prefix"
        );
        assert_ne!(
            held.id, reordered.id,
            "two distinct artifacts are reordered"
        );
        assert_eq!(held, duplicated, "the exact held artifact is duplicated");
        assert!(
            fair.view >= FAIR_SUFFIX_VIEW,
            "fair artifact is from the suffix"
        );
    }
}

#[derive(Clone, Copy, Debug)]
enum DeliveryEvent {
    Reordered,
    Duplicated,
    Fair,
}

#[derive(Clone)]
struct DeliveryPlan {
    script: DeliveryScript,
    source: ed25519::PublicKey,
    signer: Participant,
    fair_view: View,
    epoch: Epoch,
    codec: CodecConfig,
    verifier: Scheme<ed25519::PublicKey, MinPk>,
}

impl DeliveryPlan {
    fn identify(
        &self,
        message: &commonware_p2p::Message<ed25519::PublicKey>,
    ) -> Option<DeliveryArtifact> {
        if message.0 != self.source {
            return None;
        }
        let artifact = identify_consensus(
            message.0.clone(),
            message.1.as_ref(),
            self.epoch,
            self.codec,
            &self.verifier,
        )?;
        (artifact.signer == self.signer).then_some(artifact)
    }
}

#[derive(Clone)]
struct RotationProbe {
    source: ed25519::PublicKey,
    seen: Arc<Mutex<Vec<IoBuf>>>,
}

impl RotationProbe {
    fn new(source: ed25519::PublicKey) -> Self {
        Self {
            source,
            seen: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn observe(&self, message: &commonware_p2p::Message<ed25519::PublicKey>) {
        if message.0 == self.source {
            self.seen.lock().push(message.1.clone());
        }
    }

    fn saw(&self, marker: &[u8]) -> bool {
        self.seen
            .lock()
            .iter()
            .any(|message| message.as_ref() == marker)
    }
}

enum PumpState {
    Hold,
    Reorder(Box<ReorderedDelivery>),
    FairSuffix,
    Fair,
}

/// Holds, reorders, and duplicates one source's prefix artifacts before delivering fairly, or
/// delivers fairly from the start.
struct ScriptedDelivery {
    plan: Option<DeliveryPlan>,
    probe: Option<RotationProbe>,
}

impl ScriptedDelivery {
    /// Follows `plan`, reporting every frame to `probe`.
    const fn scripted(plan: DeliveryPlan, probe: RotationProbe) -> Self {
        Self {
            plan: Some(plan),
            probe: Some(probe),
        }
    }

    /// Delivers every frame in arrival order.
    const fn fair() -> Self {
        Self {
            plan: None,
            probe: None,
        }
    }
}

impl<E> PumpStrategy<E> for ScriptedDelivery
where
    E: Debug + std::error::Error + Send + Sync + 'static,
{
    type Tag = Option<(DeliveryEvent, DeliveryArtifact)>;
    type Observer = Option<DeliveryScript>;

    fn observer(&self) -> Self::Observer {
        self.plan.as_ref().map(|plan| plan.script.clone())
    }

    async fn pump<R>(
        self,
        _context: deterministic::Context,
        mut inner: R,
        sender: PumpSender<E, Self::Tag>,
    ) where
        R: commonware_p2p::Receiver<Error = E, PublicKey = ed25519::PublicKey>,
    {
        let Self { plan, probe } = self;
        let mut state = if plan.is_some() {
            PumpState::Hold
        } else {
            PumpState::Fair
        };

        loop {
            let message = match inner.recv().await {
                Ok(message) => message,
                Err(error) => {
                    let _ = sender.send((Err(error), None));
                    return;
                }
            };
            if let Some(probe) = &probe {
                probe.observe(&message);
            }

            let identified = plan.as_ref().and_then(|plan| plan.identify(&message));
            match (&mut state, identified) {
                (PumpState::Hold, Some(artifact))
                    if artifact.view < plan.as_ref().unwrap().fair_view =>
                {
                    plan.as_ref().unwrap().script.record_held(artifact.clone());
                    state = PumpState::Reorder(Box::new(ReorderedDelivery { message, artifact }));
                }
                (PumpState::Reorder(reordered), Some(artifact))
                    if artifact.view < plan.as_ref().unwrap().fair_view
                        && artifact.id != reordered.artifact.id =>
                {
                    let held = reordered.message.clone();
                    let held_artifact = reordered.artifact.clone();
                    let deliveries = [
                        (message, Some((DeliveryEvent::Reordered, artifact))),
                        (held.clone(), None),
                        (held, Some((DeliveryEvent::Duplicated, held_artifact))),
                    ];
                    for (message, event) in deliveries {
                        if sender.send((Ok(message), event)).is_err() {
                            return;
                        }
                    }
                    state = PumpState::FairSuffix;
                }
                (PumpState::FairSuffix, Some(artifact))
                    if artifact.view >= plan.as_ref().unwrap().fair_view =>
                {
                    if sender
                        .send((Ok(message), Some((DeliveryEvent::Fair, artifact))))
                        .is_err()
                    {
                        return;
                    }
                    state = PumpState::Fair;
                }
                _ => {
                    if sender.send((Ok(message), None)).is_err() {
                        return;
                    }
                }
            }
        }
    }

    fn taken(script: &Self::Observer, _: &Frame<E>, tag: Self::Tag) {
        if let (Some(script), Some((event, artifact))) = (script, tag) {
            script.record_delivery(event, artifact);
        }
    }
}

/// A plane receiver that follows a [`ScriptedDelivery`].
type ScriptedReceiver<E> = PumpedReceiver<E, ScriptedDelivery>;

/// Asserts that every attack-prefix broadcast of `byzantine` reached exactly its scripted mask.
fn assert_selective_disclosure(
    slots: &TwinSlots,
    byzantine: usize,
    scenario: &Scenario,
    identities: &[ed25519::PublicKey],
) {
    let traffic = slots.traffic.lock();
    let transmissions = traffic
        .iter()
        .filter(|transmission| {
            transmission.artifact.signer == Participant::from_usize(byzantine)
                && transmission.artifact.view < FAIR_SUFFIX_VIEW
                && transmission.broadcast_recipients.is_some()
        })
        .collect::<Vec<_>>();
    assert!(
        !transmissions.is_empty(),
        "the shared Byzantine identity emitted a signature-verified attack-prefix broadcast"
    );
    for transmission in transmissions {
        let (primary, secondary) =
            scenario.partitions(transmission.artifact.view, TERM, identities);
        let expected = match transmission.origin {
            SplitOrigin::Primary => primary,
            SplitOrigin::Secondary => secondary,
        };
        let actual = transmission
            .broadcast_recipients
            .as_ref()
            .expect("broadcast recipient set was recorded");
        assert_eq!(
            transmission.artifact.source, identities[byzantine],
            "the authenticated endpoint and protocol signer identify one participant"
        );
        assert_eq!(actual, &expected, "the exact scripted mask is installed");
        assert!(
            actual.len() < identities.len(),
            "attack-prefix disclosure excludes at least one participant"
        );
    }
}

/// Asserts that both halves built conflicting headers at one producer-chain position.
fn assert_producer_equivocation(slots: &TwinSlots, cluster: &Cluster<MinPk>, byzantine: usize) {
    assert!(
        slots.has_producer_equivocation(cluster, byzantine),
        "both halves built conflicting headers at one producer-chain position"
    );
}

/// Returns the view a scripted round runs at.
///
/// Round `r` runs at view `r + 1`; view zero is synthetic genesis.
const fn round_view(round: usize) -> View {
    View::new(round as u64 + 1)
}

/// Returns the leader schedule that makes each scripted round's view elect that round's leader.
///
/// The generator picks a leader per round; Multimmit elects `schedule[view % n]`. Placing each
/// round's leader at its view's slot honors the scenario exactly, and the remaining slots keep
/// their round-robin participants so later views stay well defined.
fn schedule_for(scenario: &Scenario, participants: usize) -> LeaderSchedule {
    let mut order: Vec<Participant> = (0..participants).map(Participant::from_usize).collect();
    for (round, scripted) in scenario.rounds().iter().enumerate() {
        let slot = (round_view(round).get() as usize) % participants;
        order[slot] = Participant::from_usize(scripted.leader());
    }
    LeaderSchedule::from_order(order, participants).expect("scenario leaders are committee members")
}

/// Two explicit view-scoped masks exercise selective disclosure before full synchrony.
fn placement_scenario(participants: usize) -> Scenario {
    assert!(participants >= 4, "the placement scenario needs four roles");
    assert!(
        participants <= u64::BITS as usize,
        "participant masks fit in u64"
    );
    let all = participant_mask(0..participants);
    let without = |participant: usize| all & !(1u64 << participant);

    Scenario::new(vec![
        RoundScenario::new(0, without(participants - 1), without(0)),
        RoundScenario::new(0, without(participants / 2), without(1)),
    ])
}

async fn launch_traced_honest(
    cluster: &mut Cluster<MinPk>,
    honest: &[usize],
    trace: &InclusionTrace,
) {
    for participant in 0..PARTICIPANTS as usize {
        assert_eq!(
            cluster.reserve_slot(""),
            participant,
            "committee storage slots stay in participant order"
        );
    }

    for &participant in honest {
        let mut planes = Vec::new();
        for plane in 0..4u64 {
            let (sender, receiver) = cluster.tap(participant, plane).await;
            let trace = trace.clone();
            let forwarder = move |origin: SplitOrigin,
                                  recipients: &Recipients<ed25519::PublicKey>,
                                  message: &IoBuf| {
                if message_view(plane, message.as_ref(), trace.epoch, trace.codec)
                    .is_some_and(|view| view > CENSORSHIP_DEADLINE_VIEW)
                {
                    return None;
                }
                if origin == SplitOrigin::Primary
                    && trace.record(participant, plane, message.as_ref())
                {
                    return None;
                }
                Some(recipients.clone())
            };
            let (sender, _unused) = sender.split_with(forwarder);
            planes.push((sender, receiver));
        }
        let [data, consensus, certificates, resolver] = planes
            .try_into()
            .unwrap_or_else(|_| panic!("exactly four honest planes"));
        Box::pin(cluster.launch_over(
            LaunchSpec::new(participant),
            Planes {
                data,
                consensus,
                certificates,
                resolver,
            },
        ))
        .await;
    }
}

fn censorship_proposal(
    fixture: &Committee<MinPk>,
    junk: Option<Sha256Digest>,
) -> SignedLeaderBlock<MinPk, Sha256Digest> {
    let view = CENSORSHIP_VIEW;
    let codec = fixture.codec();
    let genesis = fixture.config.genesis();
    let proposals = genesis
        .tips()
        .iter()
        .enumerate()
        .map(|(chain, tip)| {
            let payloads = if chain == 0 {
                junk.iter().copied().collect()
            } else {
                Vec::new()
            };
            ChainProposal::new(
                tip.chain(),
                Anchor::Tip(*tip),
                payloads,
                codec.pipeline_depth(),
            )
            .expect("Byzantine proposal remains structurally valid")
        })
        .collect();
    let block = LeaderBlock::new(
        Round::new(fixture.config.epoch(), view),
        genesis.vqc(),
        genesis_tip_commitment::<Sha256>(genesis),
        proposals,
        codec,
    )
    .expect("Byzantine proposal remains structurally valid");
    fixture.signers[1]
        .sign_leader_block(block)
        .expect("participant one is the view-one leader")
}

fn send_consensus(
    sender: &mut NetworkSender,
    recipients: Vec<ed25519::PublicKey>,
    epoch: Epoch,
    message: ConsensusMessage<MinPk, Sha256Digest>,
) {
    let frame = IoBuf::from(Envelope::new(epoch, message).encode());
    assert_eq!(
        sender.send(Recipients::Some(recipients.clone()), frame, true),
        recipients,
        "every selected recipient accepts the authenticated Byzantine frame"
    );
}

fn vote_counts_for(
    vote: &Vote<MinPk, Sha256Digest>,
    leader: &SignedLeaderBlock<MinPk, Sha256Digest>,
    target: &TransactionBlockHeader<Sha256Digest>,
) -> bool {
    let chain = target.chain().get() as usize;
    let proposal = &leader.block().proposals()[chain];
    let anchor = proposal.anchor().block_ref::<Sha256>();
    if target.parent() != anchor.digest() || target.height().get() != anchor.height().get() + 1 {
        return false;
    }

    let position = vote.body().positions()[chain].get() as usize;
    if position == 1 {
        return proposal.payloads().first() == Some(&target.body_digest());
    }
    if position != 0 {
        return false;
    }
    vote.body().extensions()[chain].payloads().first() == Some(&target.body_digest())
}

fn proposal_extends(
    proposal: &SignedLeaderBlock<MinPk, Sha256Digest>,
    target: &TransactionBlockHeader<Sha256Digest>,
) -> bool {
    let chain = target.chain().get() as usize;
    let chain_proposal = &proposal.block().proposals()[chain];
    let anchor = chain_proposal.anchor().block_ref::<Sha256>();
    let target_ref = target.block_ref::<Sha256>();
    if anchor == target_ref {
        return true;
    }
    target.parent() == anchor.digest()
        && target.height().get() == anchor.height().get() + 1
        && chain_proposal.payloads().first() == Some(&target.body_digest())
}

async fn launch_scripted_honest(
    context: &deterministic::Context,
    cluster: &mut Cluster<MinPk>,
    honest: &[usize],
    scripted_node: usize,
    plan: &DeliveryPlan,
    probe: &RotationProbe,
) {
    for participant in 0..PARTICIPANTS as usize {
        assert_eq!(
            cluster.reserve_slot(""),
            participant,
            "committee storage slots stay in participant order"
        );
    }

    for &participant in honest {
        let mut planes = Vec::new();
        for plane in 0..4u64 {
            let (sender, receiver) = cluster.tap(participant, plane).await;
            let receiver = if participant == scripted_node && plane == 1 {
                ScriptedReceiver::spawn(
                    context
                        .child("scripted_delivery")
                        .with_attribute("participant", participant)
                        .with_attribute("plane", plane),
                    receiver,
                    ScriptedDelivery::scripted(plan.clone(), probe.clone()),
                )
            } else {
                ScriptedReceiver::spawn(
                    context
                        .child("fair_delivery")
                        .with_attribute("participant", participant)
                        .with_attribute("plane", plane),
                    receiver,
                    ScriptedDelivery::fair(),
                )
            };
            planes.push((sender, receiver));
        }
        let [data, consensus, certificates, resolver] = planes
            .try_into()
            .unwrap_or_else(|_| panic!("exactly four honest planes"));
        cluster
            .launch_over(
                LaunchSpec::new(participant),
                Planes {
                    data,
                    consensus,
                    certificates,
                    resolver,
                },
            )
            .await;
    }
}

async fn wait_twin_equivocation(
    context: &deterministic::Context,
    cluster: &mut Cluster<MinPk>,
    twins: &TwinSlots,
    byzantine: usize,
) {
    for _ in 0..600 {
        if twins.has_producer_equivocation(cluster, byzantine) {
            break;
        }
        context.sleep(Duration::from_millis(10)).await;
        cluster.refresh();
    }
    assert_producer_equivocation(twins, cluster, byzantine);
}

async fn run_placement_case(
    context: &deterministic::Context,
    participants: u32,
    byzantine: &[usize],
    seed: u64,
) {
    assert!(
        !byzantine.is_empty() && byzantine.len() <= N5f1::max_faults(participants) as usize,
        "the case uses a nonempty placement within the declared fault budget"
    );
    let mut distinct = byzantine.to_vec();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(
        distinct.len(),
        byzantine.len(),
        "Byzantine placements are disjoint"
    );

    let participants = participants as usize;
    let scenario = placement_scenario(participants);
    assert_eq!(scenario.rounds().len(), ROUNDS);
    let mut cluster = Cluster::<MinPk>::new(
        context,
        ClusterOptions {
            leaders: Some(schedule_for(&scenario, participants)),
            ..ClusterOptions::new(seed, participants as u32)
        },
    )
    .await;
    let honest = (0..participants)
        .filter(|participant| !byzantine.contains(participant))
        .collect::<Vec<_>>();
    for &participant in &honest {
        cluster.start_one(participant).await;
    }

    let mut twins = Vec::with_capacity(byzantine.len());
    for (index, &participant) in byzantine.iter().enumerate() {
        twins.push(
            Box::pin(launch_scenario_twins(
                context,
                &mut cluster,
                participant,
                &scenario,
                twin_labels(index),
            ))
            .await,
        );
    }

    let mut running = honest.clone();
    running.extend(
        twins
            .iter()
            .flat_map(|slots| [slots.primary, slots.secondary]),
    );
    cluster.await_ready(&running).await;
    cluster
        .wait_view(&honest, round_view(ROUNDS), Duration::from_secs(36))
        .await;
    let identities = cluster.identities();
    for (&participant, slots) in byzantine.iter().zip(&twins) {
        assert_selective_disclosure(slots, participant, &scenario, &identities);
    }

    cluster.produce_once();
    cluster
        .wait_produced(&honest, 1, Duration::from_secs(60))
        .await;
    for (&participant, slots) in byzantine.iter().zip(&twins) {
        wait_twin_equivocation(context, &mut cluster, slots, participant).await;
    }

    cluster.observe_finality(&honest).await;
    require_fair_suffix_progress(&mut cluster, &honest, 2).await;
}

fn f2_placements() -> Vec<Vec<usize>> {
    let participants = LARGE_PARTICIPANTS as usize;
    let mut placements = Vec::with_capacity(participants + participants * (participants - 1) / 2);

    placements.extend((0..participants).map(|participant| vec![participant]));
    for left in 0..participants {
        for right in left + 1..participants {
            placements.push(vec![left, right]);
        }
    }

    assert_eq!(placements.len(), 11 + 55);
    placements
}

fn run_f2_placement_shard(shard: usize) {
    assert!(shard < F2_PLACEMENT_SHARDS);
    let cases = f2_placements()
        .into_iter()
        .enumerate()
        .filter(|(ordinal, _)| ordinal % F2_PLACEMENT_SHARDS == shard)
        .collect::<Vec<_>>();
    assert_eq!(cases.len(), 6, "every shard has equal work");

    for (ordinal, byzantine) in cases {
        let executor = deterministic::Runner::timed(Duration::from_secs(900));
        executor.start(move |context| async move {
            Box::pin(run_placement_case(
                &context,
                LARGE_PARTICIPANTS,
                &byzantine,
                920 + ordinal as u64,
            ))
            .await;
        });
    }
}

async fn require_fair_suffix_progress(cluster: &mut Cluster<MinPk>, honest: &[usize], height: u64) {
    cluster.produce_once();
    cluster
        .wait_produced(honest, height, Duration::from_secs(60))
        .await;
    let chains = honest.iter().map(|index| *index as u32).collect::<Vec<_>>();
    cluster
        .wait_finalized(honest, &chains, height, Duration::from_secs(360))
        .await;
    cluster.observe_finality(honest).await;
}

async fn rotate_byzantine_peer(
    context: &deterministic::Context,
    cluster: &mut Cluster<MinPk>,
    honest: &[usize],
    attacker: &mut NetworkSender,
    target: &ed25519::PublicKey,
    probe: &RotationProbe,
) {
    let identities = cluster.identities();
    let honest_identities = honest
        .iter()
        .map(|index| identities[*index].clone())
        .collect::<Vec<_>>();
    let mut manager = cluster.oracle().manager();
    assert!(
        manager
            .track(1, Set::from_iter_dedup(honest_identities))
            .accepted(),
        "Byzantine peer is rotated out"
    );
    let removed = manager
        .peer_set(1)
        .await
        .expect("removed peer set is installed");
    assert!(
        removed.union().position(&probe.source).is_none(),
        "Byzantine identity is absent from the installed peer set"
    );

    let removed_marker = vec![0xa5; 32];
    assert_eq!(
        attacker.send(
            Recipients::One(target.clone()),
            IoBuf::from(removed_marker.clone()),
            true,
        ),
        vec![target.clone()],
        "local submission remains accepted while the authenticated source is untracked"
    );
    cluster.produce_once();
    cluster
        .wait_produced(honest, 2, Duration::from_secs(60))
        .await;
    context.sleep(Duration::from_millis(10)).await;
    assert!(
        !probe.saw(&removed_marker),
        "traffic from the rotated-out identity is not delivered"
    );
    cluster.observe_finality(honest).await;

    assert!(
        manager
            .track(2, Set::from_iter_dedup(identities.clone()))
            .accepted(),
        "Byzantine peer is rotated back in"
    );
    let restored = manager
        .peer_set(2)
        .await
        .expect("restored peer set is installed");
    assert!(
        restored.union().position(&probe.source).is_some(),
        "Byzantine identity is present after rotation"
    );
    link_all(cluster.oracle(), &identities).await;
    let restored_marker = vec![0x5a; 32];
    assert_eq!(
        attacker.send(
            Recipients::One(target.clone()),
            IoBuf::from(restored_marker.clone()),
            true,
        ),
        vec![target.clone()],
        "the restored endpoint submits authenticated traffic"
    );
    for _ in 0..100 {
        if probe.saw(&restored_marker) {
            break;
        }
        context.sleep(Duration::from_millis(1)).await;
    }
    assert!(
        probe.saw(&restored_marker),
        "traffic is observed after the peer is re-added"
    );
    cluster.observe_finality(honest).await;
}

#[derive(Debug)]
struct ControlledReceiver {
    messages: mpsc::UnboundedReceiver<commonware_p2p::Message<ed25519::PublicKey>>,
    taken: mpsc::UnboundedSender<()>,
}

impl commonware_p2p::Receiver for ControlledReceiver {
    type Error = std::io::Error;
    type PublicKey = ed25519::PublicKey;

    async fn recv(&mut self) -> Result<commonware_p2p::Message<Self::PublicKey>, Self::Error> {
        let message = self
            .messages
            .recv()
            .await
            .ok_or_else(|| std::io::Error::other("controlled receiver closed"))?;
        let _ = self.taken.send(());
        Ok(message)
    }
}

async fn cancel_pending_recv(
    context: &deterministic::Context,
    receiver: &mut ScriptedReceiver<std::io::Error>,
) {
    select! {
        result = receiver.recv() => panic!("scripted receive unexpectedly completed: {result:?}"),
        _ = context.sleep(Duration::from_millis(1)) => {},
    }
}

#[test_traced]
fn scripted_receiver_survives_cancelled_receives() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let fixture = Committee::<MinPk>::builder(979, PARTICIPANTS).build();
        let source = fixture.identities[1].clone();
        let signer = Participant::new(1);
        let script = DeliveryScript::default();
        let plan = DeliveryPlan {
            script: script.clone(),
            source: source.clone(),
            signer,
            fair_view: FAIR_SUFFIX_VIEW,
            epoch: fixture.config.epoch(),
            codec: fixture.codec(),
            verifier: fixture.verifier.clone(),
        };
        let frame = |payload: ConsensusMessage<MinPk, Sha256Digest>| {
            IoBuf::from(Envelope::new(fixture.config.epoch(), payload).encode())
        };
        let held = frame(ConsensusMessage::NoVote(
            fixture.novote(Participant::new(1), View::new(1)),
        ));
        let reordered = frame(ConsensusMessage::Nullify(
            fixture.nullify(Participant::new(1), View::new(2)),
        ));
        let fair = frame(ConsensusMessage::Nullify(
            fixture.nullify(Participant::new(1), View::new(3)),
        ));
        let (sender, messages) = mpsc::unbounded_channel();
        let (taken, mut acknowledgements) = mpsc::unbounded_channel();
        let inner = ControlledReceiver { messages, taken };
        let probe = RotationProbe::new(fixture.identities[5].clone());
        let mut receiver = ScriptedReceiver::spawn(
            context.child("cancellation_safe_delivery"),
            inner,
            ScriptedDelivery::scripted(plan, probe),
        );

        cancel_pending_recv(&context, &mut receiver).await;
        sender.send((source.clone(), held.clone())).unwrap();
        acknowledgements.recv().await.unwrap();
        cancel_pending_recv(&context, &mut receiver).await;

        sender.send((source.clone(), reordered.clone())).unwrap();
        acknowledgements.recv().await.unwrap();
        assert_eq!(receiver.recv().await.unwrap().1, reordered);
        assert_eq!(receiver.recv().await.unwrap().1, held);
        assert_eq!(receiver.recv().await.unwrap().1, held);

        cancel_pending_recv(&context, &mut receiver).await;
        sender.send((source.clone(), fair.clone())).unwrap();
        acknowledgements.recv().await.unwrap();
        assert_eq!(receiver.recv().await.unwrap().1, fair);
        script.assert_complete(&source, signer);
    });
}

/// Lets `producer` build one block and waits until every honest engine DA-votes it, while every
/// honest engine is still in the view the Byzantine leader will censor.
async fn disseminate_target(
    context: &deterministic::Context,
    cluster: &mut Cluster<MinPk>,
    trace: &InclusionTrace,
    honest: &[usize],
    producer: usize,
) -> SignedTransactionBlock<MinPk, Sha256Digest> {
    cluster.app(producer).permit_builds(1);
    let mut target = None;
    for _ in 0..80 {
        context.sleep(Duration::from_millis(5)).await;
        cluster.observe_finality(honest).await;
        let Some(block) = trace.block_from(producer) else {
            continue;
        };
        let voters = trace.da_voters(block.header());
        if honest
            .iter()
            .all(|participant| voters.contains(participant))
        {
            target = Some(block);
            break;
        }
    }
    let target = target.expect("every honest engine DA-votes the target before view-one voting");
    assert_eq!(target.header().chain().get(), producer as u32);
    assert_eq!(target.header().height().get(), 1);
    for &participant in honest {
        assert_eq!(
            cluster.inspect(participant).await.unwrap().view(),
            CENSORSHIP_VIEW,
            "the well-disseminated block precedes every view-one vote"
        );
    }
    target
}

/// Returns the censoring leader's two conflicting proposals, each carrying junk on `producer`'s
/// chain in place of `target`.
fn equivocating_proposals(
    fixture: &Committee<MinPk>,
    producer: usize,
    target: &TransactionBlockHeader<Sha256Digest>,
) -> [SignedLeaderBlock<MinPk, Sha256Digest>; 2] {
    let junk = [
        Sha256::hash(&[b"primary junk"]),
        Sha256::hash(&[b"secondary junk"]),
    ];
    let proposals = junk.map(|junk| censorship_proposal(fixture, Some(junk)));
    assert_ne!(
        proposals[0].block().digest::<Sha256>(),
        proposals[1].block().digest::<Sha256>(),
        "the leader equivocates"
    );
    for (proposal, junk) in proposals.iter().zip(junk) {
        assert!(fixture.verifier.verify_leader_block(proposal, &Sequential));
        let chain = &proposal.block().proposals()[producer];
        assert_eq!(chain.anchor().height().get(), 0, "the proposal is stale");
        assert_eq!(chain.payloads(), &[junk], "the proposal carries junk");
        assert_ne!(junk, target.body_digest(), "the honest block is omitted");
    }
    proposals
}

/// Waits for every `voters` participant's vote for `leader` and returns them.
async fn collect_votes(
    context: &deterministic::Context,
    trace: &InclusionTrace,
    leader: Sha256Digest,
    voters: &[usize],
) -> Vec<(usize, Vote<MinPk, Sha256Digest>)> {
    let mut supporting = Vec::new();
    for _ in 0..80 {
        context.sleep(Duration::from_millis(5)).await;
        supporting = trace
            .votes_for(leader)
            .into_iter()
            .filter(|(source, _)| voters.contains(source))
            .collect();
        if supporting.len() == voters.len() {
            break;
        }
    }
    supporting
}

/// Waits until every honest engine holds a finality fact for the view after the censored one,
/// and returns their inspections.
async fn wait_deadline_finality(
    context: &deterministic::Context,
    cluster: &mut Cluster<MinPk>,
    honest: &[usize],
) -> Vec<Inspection<Sha256Digest>> {
    for _ in 0..600 {
        context.sleep(Duration::from_millis(10)).await;
        cluster.observe_finality(honest).await;
        let mut inspections = Vec::with_capacity(honest.len());
        for &participant in honest {
            inspections.push(cluster.inspect(participant).await.unwrap());
        }
        if inspections.iter().all(|inspection| {
            inspection
                .finality()
                .iter()
                .any(|fact| fact.round().view() == CENSORSHIP_DEADLINE_VIEW)
        }) {
            return inspections;
        }
    }
    panic!("every honest engine observes the next finalized leader");
}

#[test_group("slow")]
#[test_traced]
fn well_disseminated_block_survives_byzantine_leader_censorship() {
    let executor = deterministic::Runner::timed(Duration::from_secs(60));
    executor.start(|context| async move {
        const PRODUCER: usize = 0;
        const BYZANTINE: usize = 1;

        let honest = (0..PARTICIPANTS as usize)
            .filter(|participant| *participant != BYZANTINE)
            .collect::<Vec<_>>();
        let mut cluster = Cluster::<MinPk>::new(
            &context,
            ClusterOptions {
                production: Duration::from_millis(10),
                ..ClusterOptions::new(990, PARTICIPANTS)
            },
        )
        .await;
        let fixture = cluster.fixture();
        let trace = InclusionTrace::new(&fixture);
        Box::pin(launch_traced_honest(&mut cluster, &honest, &trace)).await;

        let mut byzantine_planes = Vec::new();
        for plane in 0..4u64 {
            byzantine_planes.push(cluster.tap(BYZANTINE, plane).await);
        }
        cluster.await_ready(&honest).await;

        let target = disseminate_target(&context, &mut cluster, &trace, &honest, PRODUCER).await;
        let target_header = target.header();
        let target_ref = target_header.block_ref::<Sha256>();
        let [primary, secondary] = equivocating_proposals(&fixture, PRODUCER, target_header);
        let primary_digest = primary.block().digest::<Sha256>();

        // A DA quorum votes for the primary proposal: support for the omitted block, but short of
        // the n-f that finalizes it.
        let identities = cluster.identities();
        let primary_voters = &honest[..4];
        send_consensus(
            &mut byzantine_planes[1].0,
            primary_voters
                .iter()
                .map(|participant| identities[*participant].clone())
                .collect(),
            fixture.config.epoch(),
            ConsensusMessage::Proposal {
                parent: None,
                block: Box::new(primary.clone()),
            },
        );
        let supporting = collect_votes(&context, &trace, primary_digest, primary_voters).await;
        assert_eq!(supporting.len(), fixture.codec().da_quorum());
        assert!(
            supporting
                .iter()
                .all(|(_, vote)| vote_counts_for(vote, &primary, target_header)),
            "every correct primary vote independently counts for the omitted block"
        );
        for &participant in &honest {
            let inspection = cluster.inspect(participant).await.unwrap();
            assert!(
                inspection.finality_floor() < CENSORSHIP_VIEW,
                "four votes do not cross the view-one finality floor"
            );
            assert!(
                inspection.chain_progress()[PRODUCER].finalized() < target_ref.height(),
                "four votes establish support but cannot finalize the omitted block"
            );
        }

        // One honest engine authenticates the conflicting secondary proposal.
        let equivocation_observer = primary_voters[0];
        send_consensus(
            &mut byzantine_planes[1].0,
            vec![identities[equivocation_observer].clone()],
            fixture.config.epoch(),
            ConsensusMessage::Proposal {
                parent: None,
                block: Box::new(secondary.clone()),
            },
        );
        let secondary_id = Artifact::LeaderBlock(secondary).id::<Sha256>();
        for _ in 0..50 {
            context.sleep(Duration::from_millis(5)).await;
            if cluster
                .inspect(equivocation_observer)
                .await
                .unwrap()
                .ready_artifacts()
                .contains(&secondary_id)
            {
                break;
            }
        }
        assert!(
            cluster
                .inspect(equivocation_observer)
                .await
                .unwrap()
                .ready_artifacts()
                .contains(&secondary_id),
            "an honest engine authenticates the leader's pre-finality equivocation"
        );

        // The leader's own vote completes n-f without counting for the omitted block.
        let byzantine_vote = fixture.vote(Participant::from_usize(BYZANTINE), &primary);
        assert!(fixture.verifier.verify_vote(&byzantine_vote));
        assert!(!vote_counts_for(&byzantine_vote, &primary, target_header));
        assert_eq!(supporting.len() + 1, fixture.codec().view_quorum());
        send_consensus(
            &mut byzantine_planes[1].0,
            honest
                .iter()
                .map(|participant| identities[*participant].clone())
                .collect(),
            fixture.config.epoch(),
            ConsensusMessage::Vote(byzantine_vote),
        );

        // The next view's leader extends the omitted block, and its L-QC finalizes it.
        let inspections = wait_deadline_finality(&context, &mut cluster, &honest).await;
        let next_proposal = trace
            .proposal_at(CENSORSHIP_DEADLINE_VIEW)
            .expect("the correct view-two leader proposes");
        assert!(
            proposal_extends(&next_proposal, target_header),
            "the independently reconstructed view-two proposal safely extends the target"
        );
        let deadline_digest = next_proposal.block().digest::<Sha256>();
        let deadline_votes = trace.votes_for(deadline_digest);
        assert_eq!(
            deadline_votes
                .iter()
                .filter(|(source, _)| honest.contains(source))
                .count(),
            fixture.codec().view_quorum(),
            "the exact next-view n-f pool is the paper deadline"
        );
        for inspection in &inspections {
            assert!(
                inspection.finality_floor() >= CENSORSHIP_VIEW,
                "the next-view L-QC crosses the censored view's finality floor"
            );
            assert!(
                inspection.chain_progress()[PRODUCER].finalized() >= target_ref.height(),
                "the next-view L-QC finalizes the well-disseminated block"
            );
        }
    });
}

#[test_group("slow")]
#[test_traced]
fn every_f1_byzantine_placement_selectively_discloses_and_equivocates() {
    for byzantine in 0..PARTICIPANTS as usize {
        let executor = deterministic::Runner::timed(Duration::from_secs(900));
        executor.start(move |context| async move {
            run_placement_case(&context, PARTICIPANTS, &[byzantine], 900 + byzantine as u64).await;
        });
    }
}

#[test_group("slow")]
#[test_traced]
fn faulty_twin_exit_after_equivocation_does_not_fail_campaign() {
    let executor = deterministic::Runner::timed(Duration::from_secs(900));
    executor.start(|context| async move {
        run_placement_case(&context, LARGE_PARTICIPANTS, &[0, 1], 931).await;
    });
}

macro_rules! f2_placement_shards {
    ($($name:ident => $shard:expr),+ $(,)?) => {
        $(
            #[test_group("slow")]
            #[test_traced]
            fn $name() {
                run_f2_placement_shard($shard);
            }
        )+
    };
}

f2_placement_shards! {
    every_f2_byzantine_placement_shard_00 => 0,
    every_f2_byzantine_placement_shard_01 => 1,
    every_f2_byzantine_placement_shard_02 => 2,
    every_f2_byzantine_placement_shard_03 => 3,
    every_f2_byzantine_placement_shard_04 => 4,
    every_f2_byzantine_placement_shard_05 => 5,
    every_f2_byzantine_placement_shard_06 => 6,
    every_f2_byzantine_placement_shard_07 => 7,
    every_f2_byzantine_placement_shard_08 => 8,
    every_f2_byzantine_placement_shard_09 => 9,
    every_f2_byzantine_placement_shard_10 => 10,
}

#[test_group("slow")]
#[test_traced]
fn scripted_delivery_and_peer_rotation_recover_to_fairness() {
    let executor = deterministic::Runner::timed(Duration::from_secs(900));
    executor.start(|context| async move {
        let scenario = placement_scenario(PARTICIPANTS as usize);
        let byzantine = PARTICIPANTS as usize - 1;
        let honest = (0..PARTICIPANTS as usize)
            .filter(|index| *index != byzantine)
            .collect::<Vec<_>>();
        let scripted_node = honest[0];
        let source_node = honest[1];
        let script = DeliveryScript::default();
        let mut cluster = Cluster::<MinPk>::new(
            &context,
            ClusterOptions {
                leaders: Some(schedule_for(&scenario, PARTICIPANTS as usize)),
                ..ClusterOptions::new(980, PARTICIPANTS)
            },
        )
        .await;
        let fixture = cluster.fixture();
        let source = cluster.identity(source_node);
        let byzantine_identity = cluster.identity(byzantine);
        let plan = DeliveryPlan {
            script: script.clone(),
            source: source.clone(),
            signer: Participant::from_usize(source_node),
            fair_view: FAIR_SUFFIX_VIEW,
            epoch: fixture.config.epoch(),
            codec: fixture.codec(),
            verifier: fixture.verifier,
        };
        let probe = RotationProbe::new(byzantine_identity);

        launch_scripted_honest(
            &context,
            &mut cluster,
            &honest,
            scripted_node,
            &plan,
            &probe,
        )
        .await;
        let (mut attacker, _receiver) = cluster.tap(byzantine, 1).await;
        cluster.await_ready(&honest).await;

        cluster.produce_once();
        cluster
            .wait_produced(&honest, 1, Duration::from_secs(60))
            .await;
        cluster
            .wait_view(&honest, round_view(ROUNDS), Duration::from_secs(36))
            .await;
        for _ in 0..600 {
            if script.is_complete() {
                break;
            }
            context.sleep(Duration::from_millis(10)).await;
            cluster.observe_finality(&honest).await;
        }
        script.assert_complete(&source, Participant::from_usize(source_node));

        let scripted_identity = cluster.identity(scripted_node);
        rotate_byzantine_peer(
            &context,
            &mut cluster,
            &honest,
            &mut attacker,
            &scripted_identity,
            &probe,
        )
        .await;
        cluster.observe_finality(&honest).await;
        require_fair_suffix_progress(&mut cluster, &honest, 3).await;
    });
}

#[test_traced]
fn twin_halves_equivocate_without_extra_weight() {
    // A fully connected split: both halves see every honest peer in every view, so honest nodes
    // observe conflicting artifacts signed by one participant.
    let executor = deterministic::Runner::timed(Duration::from_secs(900));
    executor.start(|context| async move {
        let byzantine = PARTICIPANTS as usize - 1;
        let mut cluster = Cluster::<MinPk>::new(
            &context,
            ClusterOptions::new(950, PARTICIPANTS),
        )
        .await;

        let honest: Vec<usize> = (0..PARTICIPANTS as usize)
            .filter(|index| *index != byzantine)
            .collect();
        for &index in &honest {
            cluster.start_one(index).await;
        }

        let mut primary = Vec::new();
        let mut secondary = Vec::new();
        for plane in 0..4u64 {
            let (sender, receiver) = cluster.tap(byzantine, plane).await;
            let (sender_primary, sender_secondary) = sender
                .split_with(|_, recipients: &Recipients<_>, _: &_| Some(recipients.clone()));
            let (receiver_primary, receiver_secondary) = receiver.split_with(
                context.child("equivocate_split").with_attribute("plane", plane),
                |_: &(ed25519::PublicKey, IoBuf)| SplitTarget::Both,
            );
            primary.push((sender_primary, receiver_primary));
            secondary.push((sender_secondary, receiver_secondary));
        }

        let (primary_slot, secondary_slot) = launch_halves(
            &mut cluster,
            byzantine,
            primary,
            secondary,
            ["equivocator_primary", "equivocator_secondary"],
        )
        .await;

        cluster.await_ready(&honest).await;
        cluster.produce();
        let mut producers = honest.clone();
        producers.extend([primary_slot, secondary_slot]);
        cluster.wait_produced(&producers, 1, Duration::from_secs(60)).await;
        cluster.stop_producing();

        // Both halves produce for the same chain from the same opportunity, so their bodies
        // conflict at one height. Honest chains still make finality progress without
        // compromising agreement.
        let honest_chains = honest.iter().map(|index| *index as u32).collect::<Vec<_>>();
        cluster
            .wait_finalized(&honest, &honest_chains, 1, Duration::from_secs(360))
            .await;
        cluster.observe_finality(&honest).await;

        // Both halves must have produced once, and their salts make the bodies conflict at one
        // chain height under one participant's signature.
        let primary_built = cluster.app(primary_slot).log().lock().built;
        let secondary_built = cluster.app(secondary_slot).log().lock().built;
        assert!(
            primary_built > 0 && secondary_built > 0,
            "expected both halves to produce conflicting blocks (primary={primary_built}, secondary={secondary_built})"
        );
        let byzantine_identity = cluster.identity(byzantine);
        let deadline = context.current() + Duration::from_secs(5);
        loop {
            let blocked = cluster.blocked_peers().await;
            assert!(
                blocked
                    .iter()
                    .all(|(_, target)| target == &byzantine_identity),
                "twins execution blocked an honest identity: {blocked:?}"
            );
            if blocked
                .iter()
                .any(|(_, target)| target == &byzantine_identity)
            {
                break;
            }
            select! {
                () = context.sleep(Duration::from_millis(1)) => {},
                () = context.sleep_until(deadline) => {
                    panic!("fully disseminated producer equivocation did not block its signer")
                },
            }
        }
    });
}
