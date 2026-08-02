use super::{Runner, RunnerError, SymbolicVerifier, cohort};
use crate::{
    Viewable as _,
    multimmit::{
        config::{CodecConfig, Config, Limits},
        machine::{
            Artifact, ArtifactId, BlockValidity, BuildCompletion, Capability, Change, Cursor,
            DomainEvent, DurabilityCapability, DurableEffect, DurableJob, EffectCompletion,
            EffectId, FinalityFact, Input, Inspection, LeaderCapability, LqcAggregateCompletion,
            LqcAggregateJob, Machine, PersistJob, ProducerCapability, ProductionTimer, Profile,
            ResolutionCompletion, ResolverCapability, Role, SignRequest, Snapshot, Step, StepError,
            StepStatus, Timer, Tuning, ValidationCompletion, Verdict, VerificationCapability,
            VerificationCompletion, VerificationTicket, ViewProof, VqcAggregateCompletion,
            VqcAggregateJob,
        },
        types::{
            Anchor, Attestation, BlockRef, CertificateId, ChainId, ChainProposal, DaVote,
            EpochGenesis, Extension, Height, LeaderBlock, Lqc, NoVote, Nullification, Nullify,
            Position, SignedLeaderBlock, SignedTransactionBlock, Tally, ThresholdShare, TipRecord,
            TransactionBlockHeader, ViewMessage, Vote, VoteBody, Vqc, genesis_history,
        },
    },
    types::{Attributable, Epoch, Participant, Round, View},
};
use commonware_codec::types::lazy::Lazy;
use commonware_cryptography::{
    Hasher, Sha256,
    bls12381::{
        certificate::threshold::Certificate as ThresholdCertificate,
        primitives::{
            ops::aggregate,
            variant::{MinPk, Variant},
        },
    },
    certificate::Signers,
    sha256::Digest,
};
use commonware_math::algebra::Additive;
use core::{num::NonZeroUsize, time::Duration};
use std::{
    array::from_fn,
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
};

#[cfg(test)]
include!("../world.rs");

const PARTICIPANTS: usize = 6;
const REPLICA_PARTICIPANTS: [usize; 3] = [0, 3, 4];
const REPLICAS: usize = REPLICA_PARTICIPANTS.len();
const HONEST: usize = 5;
const BYZANTINE: usize = 5;
const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_MACHINE_WORLD_TEST";

const VIEW_ONE_LEADER: usize = 0;
const VIEW_ONE_HONEST_VOTES: usize = 1;
const VIEW_ONE_BYZANTINE_FULL: usize = 6;
const VIEW_ONE_BYZANTINE_EMPTY: usize = 7;
const VIEW_TWO_LEADER: usize = 8;
const VIEW_TWO_VOTES: usize = 9;
const VIEW_TWO_BYZANTINE_VOTE: usize = 14;
const FIRST_TRANSACTION_BLOCK: usize = 15;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum CompletionOrder {
    Oldest,
    Newest,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum CrashCut {
    None,
    BeforeAppend,
    AfterAppend,
    AfterAcknowledgement,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum MalformedCompletion {
    StaleGeneration,
    MissingVerdict,
    DuplicateVerdict,
    ForeignTicket,
    ReorderedVerdicts,
    WrongArtifact,
    WrongObservation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Action {
    Start {
        replica: usize,
    },
    Deliver {
        replica: usize,
        artifact: usize,
    },
    DeliverPair {
        replica: usize,
        artifacts: [usize; 2],
    },
    Verify {
        replica: usize,
        order: CompletionOrder,
        valid: bool,
    },
    MalformedVerify {
        replica: usize,
        kind: MalformedCompletion,
    },
    Persist {
        replica: usize,
    },
    Poll {
        replica: usize,
    },
    FireTimer {
        replica: usize,
    },
    FireProductionTimer {
        replica: usize,
    },
    ProducerWake {
        replica: usize,
    },
    Build {
        replica: usize,
        empty: bool,
    },
    HandleResolutionEffect {
        replica: usize,
    },
    Validate {
        replica: usize,
        order: CompletionOrder,
    },
    Resolve {
        replica: usize,
    },
    AggregateVqc {
        replica: usize,
        order: CompletionOrder,
    },
    AggregateLqc {
        replica: usize,
        order: CompletionOrder,
    },
    Sign {
        replica: usize,
        order: CompletionOrder,
    },
    SignBatch {
        replica: usize,
        order: CompletionOrder,
    },
    AcknowledgeDelivery {
        replica: usize,
    },
    CrashAfterAppend {
        replica: usize,
    },
    CrashAndRestore {
        replica: usize,
    },
}

#[derive(Debug)]
struct ReplayPlan {
    blocks: usize,
    actions: Vec<Action>,
}

impl ReplayPlan {
    const fn new(blocks: usize) -> Self {
        Self {
            blocks,
            actions: Vec::new(),
        }
    }
}

struct Fixture {
    profiles: Vec<Profile<Sha256, MinPk>>,
    artifacts: Vec<Artifact<MinPk, Digest>>,
}

impl Fixture {
    fn new(blocks: usize) -> Self {
        let epoch = Epoch::new(7);
        let genesis_tips = (0..PARTICIPANTS)
            .map(|chain| {
                BlockRef::new(
                    ChainId::new(chain as u32),
                    Height::zero(),
                    digest(format!("world chain {chain} genesis").as_bytes()),
                )
            })
            .collect::<Vec<_>>();
        let genesis = EpochGenesis::new(
            epoch,
            digest(b"world leader genesis"),
            CertificateId::new(digest(b"world vqc genesis")),
            CertificateId::new(digest(b"world lqc genesis")),
            genesis_tips.clone(),
        )
        .unwrap();
        let protocol = Config::new(
            epoch,
            NAMESPACE,
            PARTICIPANTS,
            (0..PARTICIPANTS).map(Participant::from_usize).collect(),
            Limits::new(blocks as u32, 1).unwrap(),
            genesis,
        )
        .unwrap();
        assert_eq!(protocol.codec_config().view_quorum(), HONEST);
        assert_eq!(protocol.codec_config().nullification_quorum(), 3);

        let profiles = (0..REPLICAS)
            .map(|replica| {
                Profile::new(
                    protocol.clone(),
                    Role::Validator(Participant::from_usize(REPLICA_PARTICIPANTS[replica])),
                    Tuning {
                        view_timeout: Duration::from_secs(1),
                        production_interval: Duration::from_millis(100),
                        ..Tuning::default()
                    },
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        let mut commitments = vec![Vec::new(); PARTICIPANTS];
        for index in 0..blocks {
            let chain = index % 2;
            commitments[chain].push(digest(
                format!("world chain {chain} block {index}").as_bytes(),
            ));
        }
        let positions = commitments
            .iter()
            .map(|chain| chain.len() as u32)
            .collect::<Vec<_>>();
        let proposals = genesis_tips
            .iter()
            .enumerate()
            .map(|(chain, tip)| {
                ChainProposal::new(
                    ChainId::new(chain as u32),
                    Anchor::Tip(*tip),
                    commitments[chain].clone(),
                    protocol.codec_config().pipeline_depth(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let history = TipRecord::new(
            genesis_history::<Sha256>(protocol.genesis()),
            genesis_tips.clone(),
        )
        .unwrap();
        let first_leader = LeaderBlock::new(
            Round::new(epoch, View::new(1)),
            protocol.genesis().vqc(),
            history.commitment::<Sha256>(),
            proposals,
            protocol.codec_config(),
        )
        .unwrap();

        let empty_positions = vec![0; PARTICIPANTS];
        let mut artifacts = vec![Artifact::LeaderBlock(SignedLeaderBlock::new(
            first_leader.clone(),
            attestation(1),
        ))];
        for signer in 0..HONEST {
            artifacts.push(Artifact::Vote(vote(
                &first_leader,
                signer,
                &positions,
                protocol.codec_config(),
            )));
        }
        artifacts.push(Artifact::Vote(vote(
            &first_leader,
            BYZANTINE,
            &positions,
            protocol.codec_config(),
        )));
        artifacts.push(Artifact::Vote(vote(
            &first_leader,
            BYZANTINE,
            &empty_positions,
            protocol.codec_config(),
        )));

        let empty_proposals = genesis_tips
            .iter()
            .enumerate()
            .map(|(chain, tip)| {
                ChainProposal::new(
                    ChainId::new(chain as u32),
                    Anchor::Tip(*tip),
                    Vec::new(),
                    protocol.codec_config().pipeline_depth(),
                )
                .unwrap()
            })
            .collect();
        let second_leader = LeaderBlock::new(
            Round::new(epoch, View::new(2)),
            protocol.genesis().vqc(),
            history.commitment::<Sha256>(),
            empty_proposals,
            protocol.codec_config(),
        )
        .unwrap();
        artifacts.push(Artifact::LeaderBlock(SignedLeaderBlock::new(
            second_leader.clone(),
            attestation(2),
        )));
        for signer in 0..HONEST {
            artifacts.push(Artifact::Vote(vote(
                &second_leader,
                signer,
                &empty_positions,
                protocol.codec_config(),
            )));
        }
        artifacts.push(Artifact::Vote(vote(
            &second_leader,
            BYZANTINE,
            &empty_positions,
            protocol.codec_config(),
        )));

        let mut blocks_by_chain = Vec::with_capacity(PARTICIPANTS);
        for (chain, chain_commitments) in commitments.into_iter().enumerate() {
            let mut parent = genesis_tips[chain];
            let mut chain_blocks = Vec::with_capacity(chain_commitments.len());
            for (index, commitment) in chain_commitments.into_iter().enumerate() {
                let header = TransactionBlockHeader::new(
                    epoch,
                    ChainId::new(chain as u32),
                    Height::new(index as u64 + 1),
                    parent.digest(),
                    commitment,
                )
                .unwrap();
                parent = header.block_ref::<Sha256>();
                chain_blocks.push(SignedTransactionBlock::new(header, attestation(chain)));
            }
            blocks_by_chain.push(chain_blocks);
        }

        let horizon = blocks_by_chain
            .iter()
            .map(Vec::len)
            .max()
            .unwrap_or_default();
        for height in 0..horizon {
            for chain_blocks in &blocks_by_chain {
                let Some(block) = chain_blocks.get(height) else {
                    continue;
                };
                artifacts.push(Artifact::TransactionBlock(block.clone()));
            }
        }

        Self {
            profiles,
            artifacts,
        }
    }

    fn resolution(&self, view: View) -> Option<ViewProof<MinPk, Digest>> {
        Some(ViewProof::Nullification(Box::new(symbolic_nullification(
            self.profiles[0].protocol().epoch(),
            view,
        ))))
    }
}

struct Replica {
    runner: Runner<Sha256, MinPk>,
    pending: VecDeque<Capability<MinPk, Digest>>,
    view_timer: Option<Timer>,
    production_timer: Option<ProductionTimer<Digest>>,
    appended_cursor: Cursor,
    acknowledged_cursor: Cursor,
    protocol_events: BTreeMap<Cursor, Vec<OracleEvent>>,
    successor_candidates: BTreeMap<ArtifactId<Digest>, SuccessorCandidate>,
    candidate_publications: BTreeMap<ArtifactId<Digest>, Cursor>,
    successor_followups: BTreeMap<Cursor, Vec<OracleEvent>>,
    scheduled_followups: BTreeSet<(Cursor, OracleEvent)>,
    pending_successors: VecDeque<PendingSuccessor>,
    signing_events: BTreeMap<ArtifactId<Digest>, SigningOrigin>,
    pending_signings: VecDeque<PendingSigning>,
    externally_injected: BTreeSet<ArtifactId<Digest>>,
    publications: BTreeMap<EffectId, ObservedPublication>,
    publication_attempts: BTreeSet<(EffectId, u64)>,
    delivered_attempts: BTreeSet<(EffectId, u64)>,
    recovery_expected: Option<BTreeMap<EffectId, DurableEffect<MinPk, Digest>>>,
    exposed_signatures: BTreeMap<SignatureSlot, ArtifactId<Digest>>,
    poll_ready: bool,
    polls: usize,
    verifications: usize,
    validations: usize,
    deliveries: usize,
    max_pending: usize,
    vqcs: usize,
    lqcs: usize,
    signatures: usize,
    discharged_publications: BTreeSet<EffectId>,
    crashes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ObservedPublication {
    effect: DurableEffect<MinPk, Digest>,
    rules: Vec<PublicationRule>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SigningOrigin {
    sign: EffectId,
    subject: SignRequest<MinPk, Digest>,
    event_cursor: Cursor,
    covering_cursor: Cursor,
}

#[derive(Clone, Debug)]
struct PendingSigning {
    sign: EffectId,
    artifacts: Vec<(ArtifactId<Digest>, SignRequest<MinPk, Digest>)>,
    publication: DurableEffect<MinPk, Digest>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SuccessorCandidate {
    artifact: Artifact<MinPk, Digest>,
    event: OracleEvent,
    followups: Vec<OracleEvent>,
}

#[derive(Copy, Clone, Debug)]
struct PendingSuccessor {
    event: OracleEvent,
    barriers_to_skip: usize,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum PublicationRule {
    Block(ChainId, Height),
    Vote(ChainId, Height),
    Certificate(ChainId, Height),
    Exit(View),
    OwnMessage(View),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum OracleEvent {
    DaCertificate(ChainId, Height),
    Exit(View),
    ViewAdvanced,
    FinalityFloor(View),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SignatureSlot {
    TransactionBlock(ChainId, Height),
    DaVote(ChainId, Height),
    Leader(View),
    Stance(View),
    Nullify(View),
}

#[derive(Debug, PartialEq, Eq)]
struct DurableOutcome {
    journals: [Vec<DomainEvent<MinPk, Digest>>; REPLICAS],
    snapshots: [Snapshot<MinPk, Digest>; REPLICAS],
    inspections: [Inspection<Digest>; REPLICAS],
    finality: [Vec<FinalityFact<Digest>>; REPLICAS],
    publications: [BTreeMap<EffectId, ObservedPublication>; REPLICAS],
    exposed_signatures: [BTreeMap<SignatureSlot, ArtifactId<Digest>>; REPLICAS],
    signing_events: [BTreeMap<ArtifactId<Digest>, SigningOrigin>; REPLICAS],
    pending: [Vec<String>; REPLICAS],
}

struct World<'a> {
    fixture: &'a Fixture,
    replicas: [Replica; REPLICAS],
    actions: Vec<Action>,
    poll_budget: NonZeroUsize,
    fuzz_coordinate: Option<(usize, [u8; 4])>,
}

impl<'a> World<'a> {
    fn new(fixture: &'a Fixture) -> Self {
        Self {
            fixture,
            replicas: from_fn(|replica| {
                let profile = &fixture.profiles[replica];
                Replica {
                    runner: Runner::new(profile.clone()),
                    pending: VecDeque::new(),
                    view_timer: None,
                    production_timer: None,
                    appended_cursor: Cursor::zero(),
                    acknowledged_cursor: Cursor::zero(),
                    protocol_events: BTreeMap::new(),
                    successor_candidates: BTreeMap::new(),
                    candidate_publications: BTreeMap::new(),
                    successor_followups: BTreeMap::new(),
                    scheduled_followups: BTreeSet::new(),
                    pending_successors: VecDeque::new(),
                    signing_events: BTreeMap::new(),
                    pending_signings: VecDeque::new(),
                    externally_injected: BTreeSet::new(),
                    publications: BTreeMap::new(),
                    publication_attempts: BTreeSet::new(),
                    delivered_attempts: BTreeSet::new(),
                    recovery_expected: None,
                    exposed_signatures: BTreeMap::new(),
                    poll_ready: false,
                    polls: 0,
                    verifications: 0,
                    validations: 0,
                    deliveries: 0,
                    max_pending: 0,
                    vqcs: 0,
                    lqcs: 0,
                    signatures: 0,
                    discharged_publications: BTreeSet::new(),
                    crashes: 0,
                }
            }),
            actions: Vec::new(),
            poll_budget: NonZeroUsize::MIN,
            fuzz_coordinate: None,
        }
    }

    fn with_poll_budget(fixture: &'a Fixture, poll_budget: NonZeroUsize) -> Self {
        Self {
            poll_budget,
            ..Self::new(fixture)
        }
    }

    fn replay(fixture: &'a Fixture, actions: &[Action]) -> Self {
        let mut world = Self::new(fixture);
        for action in actions {
            world.apply(action.clone());
        }
        world
    }

    fn apply(&mut self, action: Action) {
        let replica = action.replica().unwrap();
        if matches!(action, Action::HandleResolutionEffect { .. }) {
            self.take(replica, CompletionOrder::Oldest, is_resolution_housekeeping);
            self.finish_action(replica, action);
            return;
        }
        if let Action::MalformedVerify { kind, .. } = action {
            self.submit_malformed_verification(replica, kind);
            self.finish_action(replica, action);
            return;
        }
        if matches!(action, Action::Poll { .. }) {
            let result = self.replicas[replica]
                .runner
                .poll(self.poll_budget)
                .unwrap();
            self.replicas[replica].poll_ready = result.work_remaining();
            self.replicas[replica].polls += 1;
            self.queue_effects(replica, result.into_capabilities());
            self.finish_action(replica, action);
            return;
        }

        let step = match action.clone() {
            Action::Poll { .. } => unreachable!(),
            Action::HandleResolutionEffect { .. } => unreachable!(),
            Action::Start { .. } => self.replicas[replica].runner.submit(Input::Start).unwrap(),
            Action::FireTimer { .. } => {
                let timer = self.replicas[replica]
                    .view_timer
                    .take()
                    .expect("a timer action requires an armed view timer");
                self.replicas[replica]
                    .runner
                    .submit(Input::TimerFired(timer))
                    .unwrap()
            }
            Action::FireProductionTimer { .. } => {
                let timer = self.replicas[replica]
                    .production_timer
                    .take()
                    .expect("a timer action requires an armed production timer");
                self.replicas[replica]
                    .runner
                    .submit(Input::ProductionTimerFired(timer))
                    .unwrap()
            }
            Action::ProducerWake { .. } => self.replicas[replica]
                .runner
                .submit(Input::ProducerWake)
                .unwrap(),
            Action::Build { empty, .. } => {
                let Capability::Producer(ProducerCapability::Build(job)) =
                    self.take(replica, CompletionOrder::Oldest, is_build)
                else {
                    unreachable!()
                };
                let commitment = (!empty).then(|| {
                    digest(
                        format!(
                            "fuzz build replica {replica} generation {} id {:?} parent {:?}",
                            job.generation(),
                            job.id(),
                            job.parent()
                        )
                        .as_bytes(),
                    )
                });
                self.replicas[replica]
                    .runner
                    .submit(Input::BlockBuilt(BuildCompletion::new(
                        job.id(),
                        job.generation(),
                        job.parent(),
                        commitment,
                    )))
                    .unwrap()
            }
            Action::Deliver { artifact, .. } => {
                self.replicas[replica].deliveries += 1;
                self.record_external_artifacts(replica, [artifact]);
                self.replicas[replica]
                    .runner
                    .submit(cohort::<Sha256, _>(vec![
                        self.fixture.artifacts[artifact].clone(),
                    ]))
                    .unwrap()
            }
            Action::DeliverPair { artifacts, .. } => {
                self.replicas[replica].deliveries += artifacts.len();
                self.record_external_artifacts(replica, artifacts);
                self.replicas[replica]
                    .runner
                    .submit(cohort::<Sha256, _>(
                        artifacts
                            .into_iter()
                            .map(|artifact| self.fixture.artifacts[artifact].clone())
                            .collect(),
                    ))
                    .unwrap()
            }
            Action::Verify { order, valid, .. } => {
                let Capability::Verification(VerificationCapability::Verify(job)) =
                    self.take(replica, order, is_verify)
                else {
                    unreachable!()
                };
                let completion = SymbolicVerifier::new(valid).complete(&job);
                let artifacts = job
                    .items()
                    .iter()
                    .map(|item| item.ticket().artifact())
                    .collect::<Vec<_>>();
                if valid {
                    for item in job.items() {
                        self.register_authenticated_successor(replica, item.artifact().clone());
                    }
                }
                self.replicas[replica].verifications += 1;
                self.replicas[replica]
                    .runner
                    .submit(Input::Verified(completion))
                    .unwrap_or_else(|error| {
                        panic!(
                            "replica {replica} failed verification in view {:?} for {artifacts:?}: {error:?}",
                            self.replicas[replica].runner.inspect().view(),
                        )
                    })
            }
            Action::MalformedVerify { .. } => unreachable!(),
            Action::Persist { .. } => {
                let Capability::Durability(DurabilityCapability::Persist(directive)) =
                    self.take(replica, CompletionOrder::Oldest, is_persist)
                else {
                    unreachable!()
                };
                let (job, staged_retention, release_after_enqueue, _) = directive.into_parts();
                self.append(replica, &job);
                Self::assert_staged_custody(&staged_retention, &release_after_enqueue);
                self.queue_effects(
                    replica,
                    release_after_enqueue
                        .into_iter()
                        .map(|job| Capability::Durability(DurabilityCapability::Released(job))),
                );
                self.acknowledge(replica, &job)
            }
            Action::Validate { order, .. } => {
                let Capability::Producer(ProducerCapability::Validate(job)) =
                    self.take(replica, order, is_validation)
                else {
                    unreachable!()
                };
                self.replicas[replica].validations += 1;
                self.replicas[replica]
                    .runner
                    .submit(Input::BlockValidated(ValidationCompletion::new(
                        job.id(),
                        job.generation(),
                        BlockValidity::Valid,
                    )))
                    .unwrap()
            }
            Action::Resolve { .. } => {
                let Capability::Resolver(ResolverCapability::Resolve(job)) =
                    self.take(replica, CompletionOrder::Oldest, is_resolution)
                else {
                    unreachable!()
                };
                let result = self
                    .fixture
                    .resolution(job.view())
                    .expect("the fair suffix supplies every requested block");
                self.replicas[replica]
                    .runner
                    .submit(Input::ResolutionCompleted(ResolutionCompletion::new(
                        job.id(),
                        job.generation(),
                        job.view(),
                        result,
                    )))
                    .unwrap()
            }
            Action::AggregateVqc { order, .. } => {
                let Capability::Leader(LeaderCapability::AggregateVqc(job)) =
                    self.take(replica, order, is_vqc)
                else {
                    unreachable!()
                };
                let certificate = symbolic_vqc(
                    &job,
                    self.fixture.profiles[replica].protocol().codec_config(),
                );
                self.register_authenticated_successor(replica, Artifact::Vqc(certificate.clone()));
                self.replicas[replica].vqcs += 1;
                self.replicas[replica]
                    .runner
                    .submit(Input::VqcAggregated(Box::new(VqcAggregateCompletion::new(
                        job.id(),
                        job.generation(),
                        certificate,
                    ))))
                    .unwrap()
            }
            Action::AggregateLqc { order, .. } => {
                let Capability::Leader(LeaderCapability::AggregateLqc(job)) =
                    self.take(replica, order, is_lqc)
                else {
                    unreachable!()
                };
                let certificate = symbolic_lqc(
                    &job,
                    self.fixture.profiles[replica].protocol().codec_config(),
                );
                self.register_authenticated_successor(replica, Artifact::Lqc(certificate.clone()));
                self.replicas[replica].lqcs += 1;
                self.replicas[replica]
                    .runner
                    .submit(Input::LqcAggregated(Box::new(LqcAggregateCompletion::new(
                        job.id(),
                        job.generation(),
                        certificate,
                    ))))
                    .unwrap()
            }
            Action::Sign { order, .. } => {
                let Capability::Durability(DurabilityCapability::Released(job)) =
                    self.take(replica, order, is_sign)
                else {
                    unreachable!()
                };
                let DurableEffect::Sign(request) = job.request() else {
                    unreachable!()
                };
                let artifact = sign(request, REPLICA_PARTICIPANTS[replica]);
                let publication = DurableEffect::publication(
                    Arc::new(artifact.clone()),
                    Some(request),
                    self.replicas[replica].runner.profile.protocol(),
                )
                .expect("a completed signing request has a publication shape");
                self.schedule_signing(
                    replica,
                    job.id(),
                    vec![(artifact.id::<Sha256>(), request.clone())],
                    publication,
                );
                self.replicas[replica].signatures += 1;
                self.replicas[replica]
                    .runner
                    .submit(Input::EffectCompleted(EffectCompletion::Signed {
                        id: job.id(),
                        generation: job.generation(),
                        artifact: Arc::new(artifact),
                    }))
                    .unwrap()
            }
            Action::SignBatch { order, .. } => {
                let Capability::Durability(DurabilityCapability::Released(job)) =
                    self.take(replica, order, is_sign_batch)
                else {
                    unreachable!()
                };
                let DurableEffect::SignBatch(requests) = job.request() else {
                    unreachable!()
                };
                let artifacts = requests
                    .iter()
                    .map(|request| sign(request, REPLICA_PARTICIPANTS[replica]))
                    .collect::<Vec<_>>();
                let publication = DurableEffect::publication_batch(
                    artifacts.iter().cloned().map(Arc::new).collect(),
                    self.replicas[replica].runner.profile.protocol(),
                )
                .expect("a completed signing batch has a publication shape");
                self.schedule_signing(
                    replica,
                    job.id(),
                    artifacts
                        .iter()
                        .zip(requests.iter())
                        .map(|(artifact, request)| (artifact.id::<Sha256>(), request.clone()))
                        .collect(),
                    publication,
                );
                self.replicas[replica].signatures += artifacts.len();
                self.replicas[replica]
                    .runner
                    .submit(Input::EffectCompleted(EffectCompletion::SignedBatch {
                        id: job.id(),
                        generation: job.generation(),
                        artifacts,
                    }))
                    .unwrap()
            }
            Action::AcknowledgeDelivery { .. } => {
                let effect = self.take(replica, CompletionOrder::Oldest, is_delivery);
                let (id, generation) = delivery_correlation(&effect);
                self.record_delivery(replica, id, generation);
                self.replicas[replica]
                    .runner
                    .submit(Input::EffectCompleted(EffectCompletion::Delivered {
                        id,
                        generation,
                    }))
                    .unwrap()
            }
            Action::CrashAfterAppend { .. } => {
                let Capability::Durability(DurabilityCapability::Persist(directive)) =
                    self.take(replica, CompletionOrder::Oldest, is_persist)
                else {
                    unreachable!()
                };
                let (job, staged_retention, release_after_enqueue, _) = directive.into_parts();
                self.append(replica, &job);
                Self::assert_staged_custody(&staged_retention, &release_after_enqueue);
                self.queue_effects(
                    replica,
                    release_after_enqueue
                        .into_iter()
                        .map(|job| Capability::Durability(DurabilityCapability::Released(job))),
                );
                self.crash_and_restore(replica)
            }
            Action::CrashAndRestore { .. } => self.crash_and_restore(replica),
        };
        self.replicas[replica].poll_ready = true;
        self.queue_effects(replica, step.into_capabilities());
        self.finish_action(replica, action);
    }

    fn finish_action(&mut self, replica: usize, action: Action) {
        self.actions.push(action);
        self.assert_invariants(replica);
    }

    fn assert_invariants(&mut self, replica: usize) {
        let action_index = self.actions.len() - 1;
        let action = self.actions[action_index].clone();
        let fuzz_coordinate = self.fuzz_coordinate;
        let coordinate = || {
            format!("action {action_index} {action:?}, replica {replica}, fuzz {fuzz_coordinate:?}")
        };
        let state = &self.replicas[replica];
        let runner = &state.runner;
        let mut replayed = Machine::restore(runner.profile.clone(), runner.checkpoint.clone())
            .expect("the invariant replay checkpoint must restore");
        for event in &runner.journal {
            replayed
                .replay(event.clone())
                .unwrap_or_else(|error| panic!("{}: replay failed: {error:?}", coordinate()));
        }
        let snapshot = replayed.snapshot();
        assert_eq!(
            snapshot.cursor(),
            state.appended_cursor,
            "{}: replay did not end at the exact appended cut",
            coordinate()
        );
        assert!(
            state.acknowledged_cursor <= state.appended_cursor,
            "{}: acknowledgement passed the durable journal cut",
            coordinate()
        );

        let inspection = runner.inspect();
        let resources = self.fixture.profiles[replica].resources();
        assert!(
            inspection.cached_artifacts() <= resources.max_cached_artifacts(),
            "{}: cached artifact bound exceeded",
            coordinate()
        );
        assert!(
            inspection.retained_artifact_references() <= resources.max_cached_artifacts(),
            "{}: durable artifact-reference bound exceeded",
            coordinate()
        );
        assert!(
            inspection.verification_jobs().len() <= resources.max_inflight_verifications(),
            "{}: verification service bound exceeded",
            coordinate()
        );
        assert!(
            inspection.future_artifacts() <= resources.max_future_artifacts(),
            "{}: future-artifact bound exceeded",
            coordinate()
        );
        assert!(
            inspection.outbox().len() <= resources.max_outbox_effects(),
            "{}: durable outbox bound exceeded",
            coordinate()
        );
        assert!(
            inspection.pending_artifacts()
                + inspection.waiting_artifacts()
                + inspection.ready_artifacts().len()
                <= inspection.cached_artifacts(),
            "{}: artifact lifecycle counts exceed retained artifacts",
            coordinate()
        );

        for artifact in state.exposed_signatures.values() {
            if state.externally_injected.contains(artifact) {
                continue;
            }
            let origin = state.signing_events.get(artifact).unwrap_or_else(|| {
                panic!(
                    "{}: exposed local signature has no durable origin",
                    coordinate()
                )
            });
            assert!(
                origin.covering_cursor <= state.acknowledged_cursor,
                "{}: signature escaped before its covering barrier",
                coordinate()
            );
        }

        self.assert_publication_state(replica, state.appended_cursor);
    }

    fn record_external_artifacts(
        &mut self,
        replica: usize,
        artifacts: impl IntoIterator<Item = usize>,
    ) {
        self.replicas[replica].externally_injected.extend(
            artifacts
                .into_iter()
                .map(|artifact| self.fixture.artifacts[artifact].id::<Sha256>()),
        );
    }

    fn register_authenticated_successor(
        &mut self,
        replica: usize,
        artifact: Artifact<MinPk, Digest>,
    ) {
        let candidate = match artifact {
            Artifact::DaCertificate(certificate) => SuccessorCandidate {
                event: OracleEvent::DaCertificate(
                    certificate.header().chain(),
                    certificate.header().height(),
                ),
                artifact: Artifact::DaCertificate(certificate),
                followups: Vec::new(),
            },
            Artifact::Vqc(certificate) => SuccessorCandidate {
                event: OracleEvent::Exit(certificate.view()),
                followups: vec![OracleEvent::ViewAdvanced],
                artifact: Artifact::Vqc(certificate),
            },
            Artifact::Nullification(certificate) => SuccessorCandidate {
                event: OracleEvent::Exit(certificate.view()),
                followups: vec![OracleEvent::ViewAdvanced],
                artifact: Artifact::Nullification(certificate),
            },
            Artifact::Lqc(certificate) => {
                let view = certificate.view();
                let derived = certificate
                    .derive_vqc(self.fixture.profiles[replica].protocol().codec_config())
                    .expect("the independently completed L-QC derives its exact V-QC");
                SuccessorCandidate {
                    event: OracleEvent::Exit(view),
                    followups: vec![OracleEvent::FinalityFloor(view)],
                    artifact: Artifact::Vqc(derived),
                }
            }
            Artifact::TransactionBlock(_)
            | Artifact::DaVote(_)
            | Artifact::LeaderBlock(_)
            | Artifact::Vote(_)
            | Artifact::NoVote(_)
            | Artifact::Nullify(_) => return,
        };
        let id = candidate.artifact.id::<Sha256>();
        match self.replicas[replica].successor_candidates.entry(id) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(candidate);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let prior = entry.get_mut();
                assert_eq!(prior.artifact, candidate.artifact);
                assert_eq!(prior.event, candidate.event);
                for followup in candidate.followups {
                    if !prior.followups.contains(&followup) {
                        prior.followups.push(followup);
                    }
                }
                prior.followups.sort_by_key(|event| match event {
                    OracleEvent::ViewAdvanced => 0,
                    OracleEvent::FinalityFloor(_) => 1,
                    OracleEvent::DaCertificate(_, _) | OracleEvent::Exit(_) => 2,
                });
            }
        }
        let Some(cursor) = self.replicas[replica]
            .candidate_publications
            .get(&id)
            .copied()
        else {
            return;
        };
        let followups = self.replicas[replica].successor_candidates[&id]
            .followups
            .clone();
        let recorded = self.replicas[replica]
            .successor_followups
            .entry(cursor)
            .or_default();
        for followup in followups {
            if !recorded.contains(&followup) {
                recorded.push(followup);
            }
        }
        recorded.sort_by_key(|event| match event {
            OracleEvent::ViewAdvanced => 0,
            OracleEvent::FinalityFloor(_) => 1,
            OracleEvent::DaCertificate(_, _) | OracleEvent::Exit(_) => 2,
        });
    }

    fn schedule_signing(
        &mut self,
        replica: usize,
        sign: EffectId,
        artifacts: Vec<(ArtifactId<Digest>, SignRequest<MinPk, Digest>)>,
        publication: DurableEffect<MinPk, Digest>,
    ) {
        let state = &mut self.replicas[replica];
        state.pending_signings.push_back(PendingSigning {
            sign,
            artifacts,
            publication,
        });
    }

    fn submit_malformed_verification(&mut self, replica: usize, kind: MalformedCompletion) {
        let jobs = self.replicas[replica]
            .pending
            .iter()
            .filter_map(|effect| match effect {
                Capability::Verification(VerificationCapability::Verify(job)) => Some(job.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let job = jobs
            .iter()
            .find(|job| job.items().len() >= 2)
            .expect("malformed verification requires a two-item job");
        let mut verdicts = job
            .items()
            .iter()
            .map(|item| Verdict::new(item.ticket(), true))
            .collect::<Vec<_>>();

        let generation = match kind {
            MalformedCompletion::StaleGeneration => job.generation().checked_add(1).unwrap(),
            MalformedCompletion::MissingVerdict => {
                verdicts.pop();
                job.generation()
            }
            MalformedCompletion::DuplicateVerdict => {
                verdicts[1] = verdicts[0];
                job.generation()
            }
            MalformedCompletion::ForeignTicket => {
                let foreign = jobs
                    .iter()
                    .find(|candidate| candidate.id() != job.id())
                    .expect("foreign-ticket coverage requires another live job");
                verdicts[1] = Verdict::new(foreign.items()[0].ticket(), true);
                job.generation()
            }
            MalformedCompletion::ReorderedVerdicts => {
                verdicts.reverse();
                job.generation()
            }
            MalformedCompletion::WrongArtifact => {
                let ticket = verdicts[1].ticket();
                verdicts[1] = Verdict::new(
                    VerificationTicket::new(
                        ticket.job(),
                        ArtifactId::new(digest(b"malformed verification artifact")),
                        ticket.observation(),
                    ),
                    true,
                );
                job.generation()
            }
            MalformedCompletion::WrongObservation => {
                let ticket = verdicts[1].ticket();
                verdicts[1] = Verdict::new(
                    VerificationTicket::new(
                        ticket.job(),
                        ticket.artifact(),
                        crate::multimmit::machine::Observation::new(
                            ticket.observation().cohort(),
                            ticket.observation().index().checked_add(1).unwrap(),
                        ),
                    ),
                    true,
                );
                job.generation()
            }
        };
        let completion = VerificationCompletion::new(job.id(), generation, verdicts);
        let result = self.replicas[replica]
            .runner
            .submit(Input::Verified(completion));
        match kind {
            MalformedCompletion::StaleGeneration => {
                assert_eq!(result.unwrap().status(), &StepStatus::StaleCompletion);
            }
            MalformedCompletion::MissingVerdict
            | MalformedCompletion::DuplicateVerdict
            | MalformedCompletion::ForeignTicket
            | MalformedCompletion::ReorderedVerdicts
            | MalformedCompletion::WrongArtifact
            | MalformedCompletion::WrongObservation => {
                assert!(matches!(
                    result,
                    Err(RunnerError::Step(StepError::CompletionMismatch))
                ));
            }
        }
        assert!(self.replicas[replica].pending.iter().any(
            |effect| matches!(effect, Capability::Verification(VerificationCapability::Verify(candidate)) if candidate.id() == job.id())
        ));
    }

    fn append(&mut self, replica: usize, job: &PersistJob<MinPk, Digest>) {
        self.replicas[replica]
            .runner
            .append(job)
            .unwrap_or_else(|error| {
                panic!(
                    "replica {replica} failed journal admission in view {:?} for barrier {} with events {:?}: {error:?}",
                    self.replicas[replica].runner.inspect().view(),
                    job.id().get(),
                    job.events(),
                )
            });
        self.replicas[replica].appended_cursor = job.last_cursor();
        self.assert_staging_matches_replay(replica);
    }

    fn acknowledge(
        &mut self,
        replica: usize,
        job: &PersistJob<MinPk, Digest>,
    ) -> Step<MinPk, Digest> {
        let step = self.replicas[replica]
            .runner
            .acknowledge(job)
            .unwrap_or_else(|error| {
                panic!(
                    "replica {replica} failed journal acknowledgement in view {:?} for barrier {} with events {:?}: {error:?}",
                    self.replicas[replica].runner.inspect().view(),
                    job.id().get(),
                    job.events(),
                )
            });
        self.replicas[replica].acknowledged_cursor = job.last_cursor();
        self.activate_acknowledged_followups(replica);
        self.record_publication_payloads(replica, step.capabilities());
        self.assert_publication_state(replica, job.last_cursor());
        if job
            .events()
            .iter()
            .any(|event| matches!(event.change(), Change::GenerationAdvanced(_)))
        {
            self.assert_recovery_releases(replica, step.capabilities());
        }
        step
    }

    fn assert_staged_custody(
        staged: &[Arc<Artifact<MinPk, Digest>>],
        released: &[DurableJob<DurableEffect<MinPk, Digest>>],
    ) {
        let staged = staged
            .iter()
            .map(|artifact| artifact.id::<Sha256>())
            .collect::<BTreeSet<_>>();
        for artifact in released.iter().flat_map(|job| job.request().artifacts()) {
            assert!(
                staged.contains(&artifact.id::<Sha256>()),
                "publication released without resolver custody"
            );
        }
    }

    fn activate_acknowledged_followups(&mut self, replica: usize) {
        let state = &mut self.replicas[replica];
        let ready = state
            .successor_followups
            .iter()
            .filter(|(cursor, _)| **cursor <= state.acknowledged_cursor)
            .flat_map(|(cursor, events)| events.iter().map(|event| (*cursor, *event)))
            .filter(|pair| !state.scheduled_followups.contains(pair))
            .collect::<Vec<_>>();
        for (cursor, event) in ready {
            state.scheduled_followups.insert((cursor, event));
            let skips_local_certificate = matches!(event, OracleEvent::ViewAdvanced)
                && state.successor_followups[&cursor]
                    .iter()
                    .any(|event| matches!(event, OracleEvent::FinalityFloor(_)))
                || matches!(event, OracleEvent::FinalityFloor(_));
            state.pending_successors.push_back(PendingSuccessor {
                event,
                barriers_to_skip: usize::from(skips_local_certificate),
            });
        }
    }

    fn bind_pending_successor(&mut self, replica: usize, job: &PersistJob<MinPk, Digest>) {
        let Some(pending) = self.replicas[replica].pending_successors.front_mut() else {
            return;
        };
        if pending.barriers_to_skip > 0 {
            pending.barriers_to_skip -= 1;
            return;
        }
        let pending = self.replicas[replica]
            .pending_successors
            .pop_front()
            .unwrap();
        self.record_protocol_event(replica, job.last_cursor(), pending.event);
    }

    fn crash_and_restore(&mut self, replica: usize) -> Step<MinPk, Digest> {
        let durable = self.replicas[replica].appended_cursor;
        let expected = self.expected_publications(replica, durable);
        let state = &mut self.replicas[replica];
        state.pending.clear();
        state.pending_signings.clear();
        state.pending_successors.clear();
        state.crashes += 1;
        state.protocol_events.retain(|cursor, _| *cursor <= durable);
        state
            .successor_followups
            .retain(|cursor, _| *cursor <= durable);
        state
            .candidate_publications
            .retain(|_, cursor| *cursor <= durable);
        state
            .scheduled_followups
            .retain(|(cursor, _)| *cursor <= durable);
        state
            .signing_events
            .retain(|_, origin| origin.event_cursor <= durable);
        state.publications.retain(|id, _| id.get() <= durable.get());
        let step = state.runner.crash_and_restore().unwrap();
        assert!(
            step.capabilities()
                .iter()
                .all(|effect| !is_delivery(effect))
        );
        assert!(state.recovery_expected.replace(expected).is_none());
        self.assert_publication_state(replica, durable);
        step
    }

    fn assert_staging_matches_replay(&self, replica: usize) {
        let runner = &self.replicas[replica].runner;
        let mut replayed = Machine::restore(runner.profile.clone(), runner.checkpoint.clone())
            .expect("the initial world checkpoint must restore");
        for event in &runner.journal {
            replayed
                .replay(event.clone())
                .expect("every staged world event must replay");
        }
        assert_eq!(replayed.snapshot(), runner.machine.snapshot());
    }

    fn record_persist_job(&mut self, replica: usize, job: &PersistJob<MinPk, Digest>) {
        for event in job.events() {
            match event.change() {
                Change::SignedArtifact { sign, artifact, .. } => {
                    self.record_signing_transition(
                        replica,
                        *sign,
                        event.cursor(),
                        job.last_cursor(),
                        [artifact.id::<Sha256>()],
                    );
                }
                Change::SignedArtifactBatch {
                    sign, artifacts, ..
                } => {
                    self.record_signing_transition(
                        replica,
                        *sign,
                        event.cursor(),
                        job.last_cursor(),
                        artifacts.iter().map(|artifact| artifact.id::<Sha256>()),
                    );
                }
                Change::GenerationAdvanced(_)
                | Change::OutboxQueued { .. }
                | Change::ArtifactCreated { .. }
                | Change::DaCertificateAdvanced { .. }
                | Change::ArtifactForwarded { .. }
                | Change::ViewAdvanced { .. }
                | Change::FinalityFloorAdvanced { .. }
                | Change::ViewCertificateCreated { .. } => {}
            }
        }
    }

    fn record_signing_transition(
        &mut self,
        replica: usize,
        sign_id: EffectId,
        event_cursor: Cursor,
        covering_cursor: Cursor,
        artifacts: impl IntoIterator<Item = ArtifactId<Digest>>,
    ) {
        let actual = artifacts.into_iter().collect::<Vec<_>>();
        let state = &mut self.replicas[replica];
        let index = state
            .pending_signings
            .iter()
            .position(|pending| pending.sign == sign_id)
            .expect("a signing transition must match an independently scheduled completion");
        let pending = state.pending_signings.remove(index).unwrap();
        assert_eq!(
            actual,
            pending
                .artifacts
                .iter()
                .map(|(artifact, _)| *artifact)
                .collect::<Vec<_>>()
        );
        for (artifact, subject) in pending.artifacts {
            assert_eq!(
                sign(&subject, REPLICA_PARTICIPANTS[replica]).id::<Sha256>(),
                artifact
            );
            let origin = SigningOrigin {
                sign: sign_id,
                subject,
                event_cursor,
                covering_cursor,
            };
            let prior = state.signing_events.insert(artifact, origin.clone());
            assert!(prior.is_none_or(|prior| prior == origin));
        }
        let publication_id = EffectId::from_cursor(event_cursor);
        self.record_known_publication(replica, publication_id, pending.publication);
    }

    fn record_protocol_event(&mut self, replica: usize, cursor: Cursor, event: OracleEvent) {
        let events = self.replicas[replica]
            .protocol_events
            .entry(cursor)
            .or_default();
        if !events.contains(&event) {
            events.push(event);
        }
    }

    fn record_known_publication(
        &mut self,
        replica: usize,
        id: EffectId,
        effect: DurableEffect<MinPk, Digest>,
    ) {
        let observed = ObservedPublication {
            rules: publication_rules(&effect),
            effect,
        };
        let prior = self.replicas[replica]
            .publications
            .insert(id, observed.clone());
        assert!(prior.is_none_or(|prior| prior == observed));
    }

    fn expected_publications(
        &self,
        replica: usize,
        cursor: Cursor,
    ) -> BTreeMap<EffectId, DurableEffect<MinPk, Digest>> {
        let state = successor_state(
            self.replicas[replica]
                .protocol_events
                .iter()
                .filter(|(event_cursor, _)| **event_cursor <= cursor)
                .flat_map(|(_, events)| events.iter().copied()),
            self.fixture.profiles[replica].view_retention().get(),
        );
        self.replicas[replica]
            .publications
            .iter()
            .filter(|(id, publication)| {
                id.get() <= cursor.get()
                    && !publication.rules.is_empty()
                    && publication
                        .rules
                        .iter()
                        .all(|rule| !matches!(rule, PublicationRule::OwnMessage(_)))
                    && !publication
                        .rules
                        .iter()
                        .all(|rule| rule.satisfied_by(&state))
            })
            .map(|(id, publication)| (*id, publication.effect.clone()))
            .collect()
    }

    fn assert_publication_state(&mut self, replica: usize, cursor: Cursor) {
        let expected = self.expected_publications(replica, cursor);
        let runner = &self.replicas[replica].runner;
        let mut durable = Machine::restore(runner.profile.clone(), runner.checkpoint.clone())
            .expect("the independently replayed publication prefix must restore");
        for event in runner
            .journal
            .iter()
            .filter(|event| event.cursor() <= cursor)
        {
            durable
                .replay(event.clone())
                .expect("the independently bounded publication prefix must replay");
        }
        let snapshot = durable.snapshot();
        let tracked = self.replicas[replica]
            .publications
            .iter()
            .filter(|(id, publication)| {
                id.get() <= cursor.get()
                    && !publication.rules.is_empty()
                    && publication
                        .rules
                        .iter()
                        .all(|rule| !matches!(rule, PublicationRule::OwnMessage(_)))
            })
            .map(|(id, _)| *id)
            .collect::<BTreeSet<_>>();
        let actual = snapshot
            .outbox()
            .iter()
            .filter(|(id, _)| tracked.contains(id))
            .map(|(id, effect)| (*id, effect.clone()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            &actual, &expected,
            "cursor {cursor:?}, oracle events {:?}, pending successors {:?}",
            self.replicas[replica].protocol_events, self.replicas[replica].pending_successors,
        );
        assert_eq!(
            snapshot
                .obligations()
                .keys()
                .filter(|id| tracked.contains(id))
                .copied()
                .collect::<BTreeSet<_>>(),
            expected.keys().copied().collect::<BTreeSet<_>>()
        );

        let known_durable = self.replicas[replica]
            .publications
            .iter()
            .filter(|(id, publication)| {
                id.get() <= cursor.get()
                    && !publication.rules.is_empty()
                    && publication
                        .rules
                        .iter()
                        .all(|rule| !matches!(rule, PublicationRule::OwnMessage(_)))
            })
            .map(|(id, _)| *id)
            .collect::<BTreeSet<_>>();
        let expected_ids = expected.keys().copied().collect::<BTreeSet<_>>();
        self.replicas[replica]
            .discharged_publications
            .extend(known_durable.difference(&expected_ids).copied());
    }

    fn record_publication_payloads(
        &mut self,
        replica: usize,
        effects: &[Capability<MinPk, Digest>],
    ) {
        for effect in effects {
            let Capability::Durability(DurabilityCapability::Released(job)) = effect else {
                continue;
            };
            if job.request().is_network_publication() {
                self.record_known_publication(replica, job.id(), job.request().clone());
            }
        }
    }

    fn assert_recovery_releases(&mut self, replica: usize, effects: &[Capability<MinPk, Digest>]) {
        let Some(expected) = self.replicas[replica].recovery_expected.take() else {
            return;
        };
        let mut actual = BTreeMap::new();
        for effect in effects {
            let Capability::Durability(DurabilityCapability::Released(job)) = effect else {
                continue;
            };
            if !expected.contains_key(&job.id()) {
                continue;
            }
            assert!(actual.insert(job.id(), job.request().clone()).is_none());
        }
        assert_eq!(actual, expected);
    }

    fn record_delivery(&mut self, replica: usize, id: EffectId, generation: u64) {
        assert!(
            self.replicas[replica]
                .publication_attempts
                .contains(&(id, generation))
        );
        assert!(
            self.replicas[replica]
                .delivered_attempts
                .insert((id, generation))
        );
    }

    fn queue_effects(
        &mut self,
        replica: usize,
        effects: impl IntoIterator<Item = Capability<MinPk, Digest>>,
    ) {
        for effect in effects {
            if let Capability::Durability(DurabilityCapability::Persist(job)) = &effect {
                self.bind_pending_successor(replica, job);
                self.record_persist_job(replica, job);
            }
            match effect {
                Capability::Durability(
                    DurabilityCapability::Acknowledged { .. } | DurabilityCapability::Retire(_),
                ) => {
                    // These capabilities mutate only actor-owned resolver/egress state. The pure
                    // Core world has neither collaborator, so execution completes inline here.
                    continue;
                }
                Capability::Leader(LeaderCapability::ArmTimer(timer)) => {
                    self.replicas[replica].view_timer = Some(timer);
                    continue;
                }
                Capability::Producer(ProducerCapability::ArmTimer(timer)) => {
                    self.replicas[replica].production_timer = Some(timer);
                    continue;
                }
                _ => {}
            }
            if is_delivery(&effect) {
                self.record_publication_attempt(replica, &effect);
            }
            self.replicas[replica].pending.push_back(effect);
        }
        self.replicas[replica].max_pending = self.replicas[replica]
            .max_pending
            .max(self.replicas[replica].pending.len());
    }

    fn record_publication_attempt(&mut self, replica: usize, effect: &Capability<MinPk, Digest>) {
        let Capability::Durability(DurabilityCapability::Released(job)) = effect else {
            unreachable!()
        };
        self.record_known_publication(replica, job.id(), job.request().clone());
        assert!(
            self.replicas[replica]
                .publication_attempts
                .insert((job.id(), job.generation()))
        );

        let local = Participant::from_usize(REPLICA_PARTICIPANTS[replica]);
        for artifact in job.request().artifacts() {
            let artifact_id = artifact.id::<Sha256>();
            let Some(candidate) = self.replicas[replica]
                .successor_candidates
                .get(&artifact_id)
                .cloned()
            else {
                continue;
            };
            assert_eq!(artifact.as_ref(), &candidate.artifact);
            let cursor = Cursor::new(job.id().get());
            let prior = self.replicas[replica]
                .candidate_publications
                .insert(artifact_id, cursor);
            assert!(prior.is_none_or(|prior| prior == cursor));
            self.record_protocol_event(replica, cursor, candidate.event);
            let followups = self.replicas[replica]
                .successor_followups
                .entry(cursor)
                .or_default();
            for followup in candidate.followups {
                if !followups.contains(&followup) {
                    followups.push(followup);
                }
            }
        }
        for (slot, artifact) in exposed_local_signatures(effect, local) {
            let Some(origin) = self.replicas[replica].signing_events.get(&artifact) else {
                assert!(
                    self.replicas[replica]
                        .externally_injected
                        .contains(&artifact),
                    "same-key artifact {artifact:?} was neither locally signed nor fixture-injected"
                );
                continue;
            };
            assert_eq!(
                sign(&origin.subject, REPLICA_PARTICIPANTS[replica]).id::<Sha256>(),
                artifact
            );
            assert!(origin.sign.get() <= origin.event_cursor.get());
            assert!(origin.event_cursor <= origin.covering_cursor);
            assert!(
                self.replicas[replica].acknowledged_cursor >= origin.covering_cursor,
                "artifact {artifact:?} from signing effect {:?} escaped before covering cursor {:?} was acknowledged at {:?}",
                origin.sign,
                origin.covering_cursor,
                self.replicas[replica].acknowledged_cursor,
            );
            let prior = self.replicas[replica]
                .exposed_signatures
                .insert(slot, artifact);
            assert!(prior.is_none_or(|prior| prior == artifact));
        }
    }

    fn take(
        &mut self,
        replica: usize,
        order: CompletionOrder,
        predicate: fn(&Capability<MinPk, Digest>) -> bool,
    ) -> Capability<MinPk, Digest> {
        let pending = &mut self.replicas[replica].pending;
        let index = match order {
            CompletionOrder::Oldest => pending.iter().position(predicate),
            CompletionOrder::Newest => pending.iter().rposition(predicate),
        }
        .expect("the replay action must name a pending effect");
        pending.remove(index).unwrap()
    }

    fn has(&self, replica: usize, predicate: fn(&Capability<MinPk, Digest>) -> bool) -> bool {
        self.replicas[replica].pending.iter().any(predicate)
    }

    fn can_malformed(&self, replica: usize, kind: MalformedCompletion) -> bool {
        let jobs = self.replicas[replica]
            .pending
            .iter()
            .filter_map(|effect| match effect {
                Capability::Verification(VerificationCapability::Verify(job)) => Some(job),
                _ => None,
            })
            .collect::<Vec<_>>();
        let has_batch = jobs.iter().any(|job| job.items().len() >= 2);
        has_batch && (!matches!(kind, MalformedCompletion::ForeignTicket) || jobs.len() >= 2)
    }

    fn apply_encoded(&mut self, step: usize, encoded: [u8; 4]) {
        let replica = usize::from(encoded[1]) % REPLICAS;
        let order = if encoded[3] & 1 == 0 {
            CompletionOrder::Oldest
        } else {
            CompletionOrder::Newest
        };
        let artifact = usize::from(encoded[2]) % self.fixture.artifacts.len();
        let malformed = malformed_completions(encoded[2])[replica];
        self.fuzz_coordinate = Some((step, encoded));

        let action = match encoded[0] {
            b'p' if self.replicas[replica].poll_ready => Some(Action::Poll { replica }),
            b'd' if self.replicas[replica].runner.inspect().is_live() => {
                Some(Action::Deliver { replica, artifact })
            }
            b'D' if self.replicas[replica].runner.inspect().is_live() => Some(Action::DeliverPair {
                replica,
                artifacts: [artifact, (artifact + 1) % self.fixture.artifacts.len()],
            }),
            b'q' if self.replicas[replica].runner.inspect().is_live() => Some(Action::DeliverPair {
                replica,
                artifacts: [artifact, artifact],
            }),
            b'v' if self.has(replica, is_verify) => Some(Action::Verify {
                replica,
                order,
                valid: true,
            }),
            b'x' if self.has(replica, is_verify) => Some(Action::Verify {
                replica,
                order,
                valid: false,
            }),
            b'm' if self.can_malformed(replica, malformed) => {
                Some(Action::MalformedVerify {
                    replica,
                    kind: malformed,
                })
            }
            b's' if self.has(replica, is_persist) => Some(Action::Persist { replica }),
            b'a' if self.has(replica, is_persist) => Some(Action::CrashAfterAppend { replica }),
            b'c' => Some(Action::CrashAndRestore { replica }),
            b'k' if self.has(replica, is_persist) => {
                self.apply(Action::Persist { replica });
                Some(Action::CrashAndRestore { replica })
            }
            b't' if self.replicas[replica].view_timer.is_some() => {
                Some(Action::FireTimer { replica })
            }
            b'T' if self.replicas[replica].production_timer.is_some() => {
                Some(Action::FireProductionTimer { replica })
            }
            b'w' if self.replicas[replica].runner.inspect().is_live() => {
                Some(Action::ProducerWake { replica })
            }
            b'b' if self.has(replica, is_build) => Some(Action::Build {
                replica,
                empty: false,
            }),
            b'B' if self.has(replica, is_build) => Some(Action::Build {
                replica,
                empty: true,
            }),
            b'V' if self.has(replica, is_validation) => Some(Action::Validate { replica, order }),
            b'r'
                if self.replicas[replica].pending.iter().any(|effect| {
                    matches!(effect, Capability::Resolver(ResolverCapability::Resolve(job)) if self.fixture.resolution(job.view()).is_some())
                }) =>
            {
                Some(Action::Resolve { replica })
            }
            b'C' if self.has(replica, is_resolution_housekeeping) => {
                Some(Action::HandleResolutionEffect { replica })
            }
            b'g' if self.has(replica, is_vqc) => Some(Action::AggregateVqc { replica, order }),
            b'G' if self.has(replica, is_lqc) => Some(Action::AggregateLqc { replica, order }),
            b'i' if self.has(replica, is_sign) => Some(Action::Sign { replica, order }),
            b'I' if self.has(replica, is_sign_batch) => {
                Some(Action::SignBatch { replica, order })
            }
            b'l' if self.has(replica, is_delivery) => {
                Some(Action::AcknowledgeDelivery { replica })
            }
            b'o' if self.has(replica, is_delivery) => {
                Some(Action::AcknowledgeDelivery { replica })
            }
            _ => None,
        };
        if let Some(action) = action {
            self.apply(action);
        }
        self.fuzz_coordinate = None;
    }

    fn durable_outcome(&self) -> DurableOutcome {
        DurableOutcome {
            journals: from_fn(|replica| self.replicas[replica].runner.journal.clone()),
            snapshots: from_fn(|replica| self.replicas[replica].runner.machine.snapshot()),
            inspections: from_fn(|replica| self.replicas[replica].runner.inspect()),
            finality: from_fn(|replica| {
                self.replicas[replica].runner.inspect().finality().to_vec()
            }),
            publications: from_fn(|replica| self.replicas[replica].publications.clone()),
            exposed_signatures: from_fn(|replica| {
                self.replicas[replica].exposed_signatures.clone()
            }),
            signing_events: from_fn(|replica| self.replicas[replica].signing_events.clone()),
            pending: from_fn(|replica| {
                self.replicas[replica]
                    .pending
                    .iter()
                    .map(|effect| format!("{effect:?}"))
                    .collect()
            }),
        }
    }

    fn settle(
        &mut self,
        replica: usize,
        verification: CompletionOrder,
        validation: CompletionOrder,
        local: bool,
    ) {
        for _ in 0..4_000 {
            let action = if self.has(replica, is_persist) {
                Action::Persist { replica }
            } else {
                let Some(action) =
                    self.schedulable_action(replica, verification, validation, local)
                else {
                    if local {
                        self.assert_locally_drained(replica);
                    }
                    return;
                };
                action
            };
            self.apply(action);
        }
        panic!("fair effect scheduling did not quiesce");
    }

    fn assert_locally_drained(&self, replica: usize) {
        let state = &self.replicas[replica];
        assert!(
            !state.poll_ready,
            "machine-owned scheduler work was stranded"
        );
        assert!(
            state.pending.is_empty(),
            "the machine executor left pending effects: {:?}",
            state.pending
        );
        let inspection = state.runner.inspect();
        assert!(inspection.pending_barrier().is_none());
        assert!(inspection.verification_jobs().is_empty());
        assert_eq!(inspection.resolution_jobs(), 0);
    }

    fn drive_until_persist(
        &mut self,
        replica: usize,
        verification: CompletionOrder,
        validation: CompletionOrder,
        local: bool,
    ) {
        for _ in 0..4_000 {
            if self.has(replica, is_persist) {
                return;
            }
            let action = self
                .schedulable_action(replica, verification, validation, local)
                .expect("the crash cut must reach a persistence barrier");
            self.apply(action);
        }
        panic!("persistence barrier did not become ready");
    }

    fn schedulable_action(
        &self,
        replica: usize,
        verification: CompletionOrder,
        validation: CompletionOrder,
        local: bool,
    ) -> Option<Action> {
        if self.has(replica, is_verify) {
            return Some(Action::Verify {
                replica,
                order: verification,
                valid: true,
            });
        }
        if self.has(replica, is_vqc) {
            return Some(Action::AggregateVqc {
                replica,
                order: verification,
            });
        }
        if self.has(replica, is_lqc) {
            return Some(Action::AggregateLqc {
                replica,
                order: verification,
            });
        }
        if self.has(replica, is_validation) {
            return Some(Action::Validate {
                replica,
                order: validation,
            });
        }
        if self.has(replica, is_resolution)
            && self.replicas[replica].pending.iter().any(|effect| {
                matches!(effect, Capability::Resolver(ResolverCapability::Resolve(job)) if self.fixture.resolution(job.view()).is_some())
            })
        {
            return Some(Action::Resolve { replica });
        }
        if self.has(replica, is_resolution_housekeeping) {
            return Some(Action::HandleResolutionEffect { replica });
        }
        if self.replicas[replica].poll_ready {
            return Some(Action::Poll { replica });
        }
        if self.has(replica, is_delivery) {
            return Some(Action::AcknowledgeDelivery { replica });
        }
        if local && self.has(replica, is_sign) {
            return Some(Action::Sign {
                replica,
                order: verification,
            });
        }
        if local && self.has(replica, is_sign_batch) {
            return Some(Action::SignBatch {
                replica,
                order: verification,
            });
        }
        None
    }
}

#[derive(Debug)]
struct SuccessorState {
    certified: BTreeMap<ChainId, Height>,
    exit: Option<View>,
    retention_floor: View,
}

fn successor_state(
    events: impl IntoIterator<Item = OracleEvent>,
    view_retention: u64,
) -> SuccessorState {
    let mut state = SuccessorState {
        certified: BTreeMap::new(),
        exit: None,
        retention_floor: View::zero(),
    };
    let mut view = View::new(1);
    let mut retired_view = View::zero();
    for event in events {
        match event {
            OracleEvent::DaCertificate(chain, height) => {
                let certified = state.certified.entry(chain).or_insert(Height::zero());
                *certified = (*certified).max(height);
            }
            OracleEvent::Exit(successor) => {
                state.exit = Some(state.exit.map_or(successor, |exit| exit.max(successor)));
            }
            OracleEvent::ViewAdvanced => {
                view = View::new(view.get().checked_add(1).unwrap());
                let floor = View::new(view.get().saturating_sub(view_retention).saturating_sub(1))
                    .max(retired_view);
                state.retention_floor = state.retention_floor.max(floor);
            }
            OracleEvent::FinalityFloor(floor) => {
                view = View::new(floor.get().checked_add(1).unwrap());
                retired_view = retired_view.max(floor);
                state.retention_floor = state.retention_floor.max(floor);
            }
        }
    }
    state
}

impl PublicationRule {
    fn satisfied_by(&self, state: &SuccessorState) -> bool {
        match *self {
            Self::Block(chain, height) | Self::Vote(chain, height) => state
                .certified
                .get(&chain)
                .is_some_and(|certified| *certified >= height),
            Self::Certificate(chain, height) => state
                .certified
                .get(&chain)
                .is_some_and(|certified| *certified > height),
            Self::Exit(view) => state.exit.is_some_and(|successor| successor > view),
            Self::OwnMessage(view) => state.retention_floor >= view,
        }
    }
}

fn publication_rules(effect: &DurableEffect<MinPk, Digest>) -> Vec<PublicationRule> {
    match effect {
        DurableEffect::Propose(proposal) => {
            vec![PublicationRule::OwnMessage(proposal.block().view())]
        }
        DurableEffect::Broadcast(_)
        | DurableEffect::BroadcastBatch(_)
        | DurableEffect::Send(_)
        | DurableEffect::SendBatch(_) => effect
            .artifacts()
            .into_iter()
            .map(|artifact| publication_rule(artifact.as_ref()))
            .collect(),
        DurableEffect::Sign(_) | DurableEffect::SignBatch(_) => Vec::new(),
    }
}

fn publication_rule(artifact: &Artifact<MinPk, Digest>) -> PublicationRule {
    match artifact {
        Artifact::TransactionBlock(block) => {
            PublicationRule::Block(block.header().chain(), block.header().height())
        }
        Artifact::DaVote(vote) => {
            PublicationRule::Vote(vote.header().chain(), vote.header().height())
        }
        Artifact::DaCertificate(certificate) => PublicationRule::Certificate(
            certificate.header().chain(),
            certificate.header().height(),
        ),
        Artifact::Vqc(certificate) => PublicationRule::Exit(certificate.view()),
        Artifact::Nullification(certificate) => PublicationRule::Exit(certificate.view()),
        Artifact::LeaderBlock(block) => PublicationRule::OwnMessage(block.view()),
        Artifact::Vote(vote) => PublicationRule::OwnMessage(vote.view()),
        Artifact::NoVote(vote) => PublicationRule::OwnMessage(vote.view()),
        Artifact::Nullify(vote) => PublicationRule::OwnMessage(vote.view()),
        Artifact::Lqc(certificate) => PublicationRule::OwnMessage(certificate.view()),
    }
}

fn exposed_local_signatures(
    effect: &Capability<MinPk, Digest>,
    local: Participant,
) -> Vec<(SignatureSlot, ArtifactId<Digest>)> {
    let Capability::Durability(DurabilityCapability::Released(job)) = effect else {
        return Vec::new();
    };
    if !job.request().is_network_publication() {
        return Vec::new();
    }

    let mut exposed = Vec::new();
    if let DurableEffect::Propose(proposal) = job.request() {
        let artifact = Artifact::LeaderBlock(proposal.block().as_ref().clone());
        record_local_signature(&mut exposed, &artifact, local);
        return exposed;
    }
    for artifact in job.request().artifacts() {
        record_local_signature(&mut exposed, artifact, local);
    }
    exposed
}

fn record_local_signature(
    exposed: &mut Vec<(SignatureSlot, ArtifactId<Digest>)>,
    artifact: &Artifact<MinPk, Digest>,
    local: Participant,
) {
    if artifact.signer() != Some(local) {
        return;
    }
    let slot = match artifact {
        Artifact::TransactionBlock(block) => {
            SignatureSlot::TransactionBlock(block.header().chain(), block.header().height())
        }
        Artifact::DaVote(vote) => {
            SignatureSlot::DaVote(vote.header().chain(), vote.header().height())
        }
        Artifact::LeaderBlock(block) => SignatureSlot::Leader(block.view()),
        Artifact::Vote(vote) => SignatureSlot::Stance(vote.view()),
        Artifact::NoVote(vote) => SignatureSlot::Stance(vote.view()),
        Artifact::Nullify(vote) => SignatureSlot::Nullify(vote.view()),
        Artifact::DaCertificate(_)
        | Artifact::Vqc(_)
        | Artifact::Nullification(_)
        | Artifact::Lqc(_) => return,
    };
    exposed.push((slot, artifact.id::<Sha256>()));
}

impl Action {
    const fn replica(&self) -> Option<usize> {
        match self {
            Self::Start { replica }
            | Self::Deliver { replica, .. }
            | Self::DeliverPair { replica, .. }
            | Self::Verify { replica, .. }
            | Self::MalformedVerify { replica, .. }
            | Self::Persist { replica }
            | Self::Poll { replica }
            | Self::FireTimer { replica }
            | Self::FireProductionTimer { replica }
            | Self::ProducerWake { replica }
            | Self::Build { replica, .. }
            | Self::HandleResolutionEffect { replica }
            | Self::Validate { replica, .. }
            | Self::Resolve { replica }
            | Self::AggregateVqc { replica, .. }
            | Self::AggregateLqc { replica, .. }
            | Self::Sign { replica, .. }
            | Self::SignBatch { replica, .. }
            | Self::AcknowledgeDelivery { replica }
            | Self::CrashAfterAppend { replica }
            | Self::CrashAndRestore { replica } => Some(*replica),
        }
    }
}

fn digest(label: &[u8]) -> Digest {
    Sha256::hash(&[label])
}

fn attestation(signer: usize) -> Attestation<MinPk> {
    Attestation::new(
        Participant::from_usize(signer),
        Lazy::from(<MinPk as Variant>::Signature::zero()),
    )
}

fn threshold_share(signer: usize) -> ThresholdShare<MinPk> {
    ThresholdShare::new(
        Participant::from_usize(signer),
        Lazy::from(<MinPk as Variant>::Signature::zero()),
    )
}

fn symbolic_nullification(epoch: Epoch, view: View) -> Nullification<MinPk> {
    Nullification::new(
        Round::new(epoch, view),
        ThresholdCertificate::new(<MinPk as Variant>::Signature::zero()),
    )
    .unwrap()
}

fn vote(
    leader: &LeaderBlock<MinPk, Digest>,
    signer: usize,
    positions: &[u32],
    config: CodecConfig,
) -> Vote<MinPk, Digest> {
    let positions = positions.iter().copied().map(Position::new).collect();
    let body = VoteBody::for_leader::<Sha256, MinPk>(
        leader,
        positions,
        vec![Extension::empty(); config.chains()],
        config,
    )
    .unwrap();
    Vote::new(body, attestation(signer))
}

fn symbolic_vqc(job: &VqcAggregateJob<MinPk, Digest>, config: CodecConfig) -> Vqc<MinPk, Digest> {
    let messages = job.messages().collect::<Vec<_>>();
    let leader = job.leader().clone();
    let leader_digest = leader.digest::<Sha256>();
    let votes = messages.iter().filter_map(|message| match message {
        ViewMessage::Vote(vote) if vote.body().leader() == leader_digest => {
            Some((vote.signer(), vote.body().clone()))
        }
        _ => None,
    });
    let tally = Tally::from_votes::<MinPk, Sha256, _>(&leader, votes, config).unwrap();
    let novoters = Signers::from(
        config.participants(),
        messages.iter().filter_map(|message| match message {
            ViewMessage::NoVote(vote) => Some(vote.signer()),
            ViewMessage::Vote(_) => None,
        }),
    );
    Vqc::new(
        leader,
        tally,
        novoters,
        Vec::new(),
        aggregate::Signature::<MinPk>::zero(),
        config,
    )
    .unwrap()
}

fn symbolic_lqc(job: &LqcAggregateJob<MinPk, Digest>, config: CodecConfig) -> Lqc<MinPk, Digest> {
    let leader = job.leader().clone();
    let tally = Tally::from_votes::<MinPk, Sha256, _>(
        &leader,
        job.votes().map(|vote| (vote.signer(), vote.body().clone())),
        config,
    )
    .unwrap();
    Lqc::new(leader, tally, aggregate::Signature::<MinPk>::zero(), config).unwrap()
}

fn sign(request: &SignRequest<MinPk, Digest>, replica: usize) -> Artifact<MinPk, Digest> {
    match request {
        SignRequest::TransactionBlock(header) => Artifact::TransactionBlock(
            SignedTransactionBlock::new(header.clone(), attestation(replica)),
        ),
        SignRequest::DaVote(request) => Artifact::DaVote(DaVote::new(
            request.header().clone(),
            threshold_share(replica),
        )),
        SignRequest::LeaderBlock(request) => Artifact::LeaderBlock(SignedLeaderBlock::new(
            request.block().clone(),
            attestation(replica),
        )),
        SignRequest::Vote(request) => {
            Artifact::Vote(Vote::new(request.body().clone(), attestation(replica)))
        }
        SignRequest::NoVote { round } => {
            Artifact::NoVote(NoVote::new(*round, attestation(replica)).unwrap())
        }
        SignRequest::Nullify { round } => {
            Artifact::Nullify(Nullify::new(*round, threshold_share(replica)).unwrap())
        }
    }
}

fn delivery_correlation(effect: &Capability<MinPk, Digest>) -> (EffectId, u64) {
    let Capability::Durability(DurabilityCapability::Released(job)) = effect else {
        unreachable!("delivery actions only consume publication effects")
    };
    assert!(matches!(
        job.request(),
        DurableEffect::Broadcast(_)
            | DurableEffect::BroadcastBatch(_)
            | DurableEffect::Propose(_)
            | DurableEffect::Send(_)
            | DurableEffect::SendBatch(_)
    ));
    (job.id(), job.generation())
}

const fn is_verify(effect: &Capability<MinPk, Digest>) -> bool {
    matches!(
        effect,
        Capability::Verification(VerificationCapability::Verify(_))
    )
}

const fn is_persist(effect: &Capability<MinPk, Digest>) -> bool {
    matches!(
        effect,
        Capability::Durability(DurabilityCapability::Persist(_))
    )
}

const fn is_validation(effect: &Capability<MinPk, Digest>) -> bool {
    matches!(
        effect,
        Capability::Producer(ProducerCapability::Validate(_))
    )
}

const fn is_build(effect: &Capability<MinPk, Digest>) -> bool {
    matches!(effect, Capability::Producer(ProducerCapability::Build(_)))
}

const fn is_resolution(effect: &Capability<MinPk, Digest>) -> bool {
    matches!(effect, Capability::Resolver(ResolverCapability::Resolve(_)))
}

const fn is_resolution_housekeeping(effect: &Capability<MinPk, Digest>) -> bool {
    matches!(
        effect,
        Capability::Resolver(ResolverCapability::Cancel(_))
            | Capability::Resolver(ResolverCapability::Reject(_))
            | Capability::Resolver(ResolverCapability::Prune(_))
    )
}

const fn is_vqc(effect: &Capability<MinPk, Digest>) -> bool {
    matches!(
        effect,
        Capability::Leader(LeaderCapability::AggregateVqc(_))
    )
}

const fn is_lqc(effect: &Capability<MinPk, Digest>) -> bool {
    matches!(
        effect,
        Capability::Leader(LeaderCapability::AggregateLqc(_))
    )
}

const fn is_sign(effect: &Capability<MinPk, Digest>) -> bool {
    matches!(
        effect,
        Capability::Durability(DurabilityCapability::Released(job))
            if matches!(job.request(), DurableEffect::Sign(_))
    )
}

const fn is_sign_batch(effect: &Capability<MinPk, Digest>) -> bool {
    matches!(
        effect,
        Capability::Durability(DurabilityCapability::Released(job))
            if matches!(job.request(), DurableEffect::SignBatch(_))
    )
}

const fn is_delivery(effect: &Capability<MinPk, Digest>) -> bool {
    matches!(
        effect,
        Capability::Durability(DurabilityCapability::Released(job))
            if matches!(
                job.request(),
                DurableEffect::Broadcast(_)
                    | DurableEffect::BroadcastBatch(_)
                    | DurableEffect::Propose(_)
                    | DurableEffect::Send(_)
                    | DurableEffect::SendBatch(_)
            )
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "each scenario axis is one per-replica knob; bundling them would hide the matrix"
)]
fn run_scenario(
    blocks: usize,
    proposal_first: [bool; REPLICAS],
    newest_verification: [bool; REPLICAS],
    reverse_votes: [bool; REPLICAS],
    byzantine_full: [bool; REPLICAS],
    reverse_blocks: [bool; REPLICAS],
    malformed: [MalformedCompletion; REPLICAS],
    crash: [CrashCut; REPLICAS],
) -> (ReplayPlan, DurableOutcome) {
    run_scenario_with_poll_budget(
        blocks,
        proposal_first,
        newest_verification,
        reverse_votes,
        byzantine_full,
        reverse_blocks,
        malformed,
        crash,
        NonZeroUsize::MIN,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_scenario_with_poll_budget(
    blocks: usize,
    proposal_first: [bool; REPLICAS],
    newest_verification: [bool; REPLICAS],
    reverse_votes: [bool; REPLICAS],
    byzantine_full: [bool; REPLICAS],
    reverse_blocks: [bool; REPLICAS],
    malformed: [MalformedCompletion; REPLICAS],
    crash: [CrashCut; REPLICAS],
    poll_budget: NonZeroUsize,
) -> (ReplayPlan, DurableOutcome) {
    let fixture = Fixture::new(blocks);
    let mut world = World::with_poll_budget(&fixture, poll_budget);
    for replica in 0..REPLICAS {
        world.apply(Action::Start { replica });
        world.settle(
            replica,
            CompletionOrder::Oldest,
            CompletionOrder::Oldest,
            false,
        );
    }

    for (replica, kind) in malformed.iter().copied().enumerate() {
        world.apply(Action::DeliverPair {
            replica,
            artifacts: [FIRST_TRANSACTION_BLOCK, FIRST_TRANSACTION_BLOCK + 1],
        });
        world.apply(Action::Deliver {
            replica,
            artifact: VIEW_ONE_LEADER,
        });
        world.apply(Action::MalformedVerify { replica, kind });
        world.apply(Action::Verify {
            replica,
            order: CompletionOrder::Oldest,
            valid: false,
        });
        world.settle(
            replica,
            CompletionOrder::Oldest,
            CompletionOrder::Oldest,
            false,
        );
    }

    for replica in 0..REPLICAS {
        let omitted = REPLICA_PARTICIPANTS[replica];
        let mut votes = (0..HONEST)
            .filter(|signer| *signer != omitted)
            .map(|signer| VIEW_ONE_HONEST_VOTES + signer)
            .collect::<Vec<_>>();
        votes.push(if byzantine_full[replica] {
            VIEW_ONE_BYZANTINE_FULL
        } else {
            VIEW_ONE_BYZANTINE_EMPTY
        });
        if reverse_votes[replica] {
            votes.reverse();
        }
        if proposal_first[replica] {
            votes.insert(0, VIEW_ONE_LEADER);
        } else {
            votes.push(VIEW_ONE_LEADER);
        }
        for artifact in &votes {
            world.apply(Action::Deliver {
                replica,
                artifact: *artifact,
            });
        }
        let verification = order(newest_verification[replica]);
        world.settle(replica, verification, CompletionOrder::Oldest, false);
        assert!(world.replicas[replica].runner.inspect().view() >= View::new(2));
        assert!(
            world.replicas[replica]
                .runner
                .inspect()
                .pools()
                .iter()
                .any(|pool| pool.finalized())
        );
    }

    for replica in (0..REPLICAS).step_by(2) {
        let transactions = transaction_order(blocks, reverse_blocks[replica]);
        for artifact in transactions {
            world.apply(Action::Deliver { replica, artifact });
        }
        let verification = order(newest_verification[replica]);
        world.settle(replica, verification, verification, false);
    }
    for replica in 0..REPLICAS {
        let mut artifacts = (0..HONEST)
            .filter(|signer| *signer != REPLICA_PARTICIPANTS[replica])
            .map(|signer| VIEW_TWO_VOTES + signer)
            .collect::<Vec<_>>();
        artifacts.push(VIEW_TWO_BYZANTINE_VOTE);
        if reverse_votes[replica] {
            artifacts.reverse();
        }
        if proposal_first[replica] {
            world.apply(Action::Deliver {
                replica,
                artifact: VIEW_TWO_LEADER,
            });
        }
        for artifact in artifacts {
            world.apply(Action::Deliver { replica, artifact });
        }
        if !proposal_first[replica] {
            world.apply(Action::Deliver {
                replica,
                artifact: VIEW_TWO_LEADER,
            });
        }
        let verification = order(newest_verification[replica]);
        world.settle(replica, verification, CompletionOrder::Oldest, false);
        assert!(world.replicas[replica].runner.inspect().view() >= View::new(3));
    }

    for replica in 0..REPLICAS {
        let mut artifacts = vec![
            VIEW_ONE_LEADER,
            VIEW_ONE_BYZANTINE_FULL,
            VIEW_ONE_BYZANTINE_EMPTY,
            VIEW_TWO_LEADER,
        ];
        artifacts.extend((0..HONEST).map(|signer| VIEW_ONE_HONEST_VOTES + signer));
        artifacts.extend((0..HONEST).map(|signer| VIEW_TWO_VOTES + signer));
        artifacts.retain(|artifact| {
            *artifact != VIEW_ONE_HONEST_VOTES + REPLICA_PARTICIPANTS[replica]
                && *artifact != VIEW_TWO_VOTES + REPLICA_PARTICIPANTS[replica]
        });
        artifacts.push(VIEW_TWO_BYZANTINE_VOTE);
        artifacts.extend(transaction_order(blocks, reverse_blocks[replica]));
        if reverse_votes[replica] {
            artifacts.reverse();
        }
        for artifact in artifacts {
            world.apply(Action::Deliver { replica, artifact });
        }
    }

    for replica in (0..REPLICAS).rev() {
        let verification = order(newest_verification[replica]);
        world.settle(replica, verification, verification, false);
        let action = if world.has(replica, is_sign) {
            Action::Sign {
                replica,
                order: verification,
            }
        } else {
            assert!(world.has(replica, is_sign_batch));
            Action::SignBatch {
                replica,
                order: verification,
            }
        };
        world.apply(action);
        world.drive_until_persist(replica, verification, verification, true);
        match crash[replica] {
            CrashCut::None => world.apply(Action::Persist { replica }),
            CrashCut::BeforeAppend => world.apply(Action::CrashAndRestore { replica }),
            CrashCut::AfterAppend => world.apply(Action::CrashAfterAppend { replica }),
            CrashCut::AfterAcknowledgement => {
                world.apply(Action::Persist { replica });
                if world.has(replica, is_delivery) {
                    world.apply(Action::AcknowledgeDelivery { replica });
                }
                world.apply(Action::CrashAndRestore { replica });
            }
        }
    }
    for replica in (0..REPLICAS).rev() {
        let verification = order(newest_verification[replica]);
        world.settle(replica, verification, verification, true);
    }

    for (replica, newest) in newest_verification.iter().copied().enumerate() {
        assert!(!world.replicas[replica].discharged_publications.is_empty());
        world.apply(Action::CrashAndRestore { replica });
        let verification = order(newest);
        world.settle(replica, verification, verification, true);
    }

    assert_eq!(
        world
            .replicas
            .iter()
            .map(|replica| replica.crashes)
            .sum::<usize>(),
        REPLICAS + crash.iter().filter(|cut| **cut != CrashCut::None).count()
    );
    for replica in &world.replicas {
        let inspection = replica.runner.inspect();
        assert!(inspection.view() >= View::new(3));
        assert!(inspection.finality().len() >= 2);
        assert!(inspection.finality_floor() >= View::new(1));
        assert!(inspection.pending_barrier().is_none());
        assert!(replica.polls > 0);
        assert!(replica.verifications > 0);
        assert!(replica.validations > 0);
        assert!(replica.deliveries > 0);
        assert!(replica.max_pending > 1);
        assert!(replica.vqcs >= 2);
        assert!(replica.lqcs >= 2);
        assert!(replica.signatures > 0);
        assert!(!replica.discharged_publications.is_empty());
    }

    let durable = world.durable_outcome();
    let mut plan = ReplayPlan::new(blocks);
    plan.actions = world.actions;
    (plan, durable)
}

const fn order(newest: bool) -> CompletionOrder {
    if newest {
        CompletionOrder::Newest
    } else {
        CompletionOrder::Oldest
    }
}

fn transaction_order(blocks: usize, reverse: bool) -> Vec<usize> {
    let range = FIRST_TRANSACTION_BLOCK..FIRST_TRANSACTION_BLOCK + blocks;
    if reverse {
        range.rev().collect()
    } else {
        range.collect()
    }
}

fn crash_cuts(bits: u8) -> [CrashCut; REPLICAS] {
    from_fn(|replica| match (bits >> (replica * 2)) & 0b11 {
        0 => CrashCut::None,
        1 => CrashCut::BeforeAppend,
        2 => CrashCut::AfterAppend,
        _ => CrashCut::AfterAcknowledgement,
    })
}

fn malformed_completions(bits: u8) -> [MalformedCompletion; REPLICAS] {
    const CASES: [MalformedCompletion; 7] = [
        MalformedCompletion::StaleGeneration,
        MalformedCompletion::MissingVerdict,
        MalformedCompletion::DuplicateVerdict,
        MalformedCompletion::ForeignTicket,
        MalformedCompletion::ReorderedVerdicts,
        MalformedCompletion::WrongArtifact,
        MalformedCompletion::WrongObservation,
    ];
    from_fn(|replica| CASES[usize::from(bits.wrapping_add(replica as u8)) % CASES.len()])
}

pub(super) fn exercise(input: &[u8]) {
    let byte = |index: usize| -> u8 { input.get(index).copied().unwrap_or_default() };
    let flags = |index| from_fn(|replica| byte(index) & (1 << replica) != 0);
    let blocks = usize::from(byte(0) % 5) + 2;
    if input.len() > 8 {
        let structured_fixture = Fixture::new(blocks);
        let mut structured = World::new(&structured_fixture);
        for replica in 0..REPLICAS {
            structured.apply(Action::Start { replica });
            structured.settle(
                replica,
                CompletionOrder::Oldest,
                CompletionOrder::Oldest,
                false,
            );
        }
        for (step, bytes) in input[8..].chunks(4).take(40).enumerate() {
            let mut encoded = [0; 4];
            encoded[..bytes.len()].copy_from_slice(bytes);
            structured.apply_encoded(step, encoded);
        }
    }
    let (plan, durable) = run_scenario(
        blocks,
        flags(1),
        flags(2),
        flags(3),
        flags(4),
        flags(5),
        malformed_completions(byte(7)),
        crash_cuts(byte(6)),
    );
    let replay_fixture = Fixture::new(plan.blocks);
    let replayed = World::replay(&replay_fixture, &plan.actions);
    for replica in 0..REPLICAS {
        replayed.assert_locally_drained(replica);
    }
    assert_eq!(replayed.durable_outcome(), durable);
}

#[cfg(test)]
mod successor_matrix {
    use super::*;
    use crate::{multimmit::types::DaCertificate, types::ViewDelta};

    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    enum SuccessorFamily {
        Da,
        ForwardedExit,
        ViewRetention,
        FinalityFloor,
    }

    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    enum SuccessorCut {
        BeforeAppend,
        AfterAppend,
        AfterAck,
    }

    #[derive(Clone, Debug)]
    struct PublicationWitness {
        id: EffectId,
        generation: u64,
        effect: DurableEffect<MinPk, Digest>,
    }

    fn only_persist(step: &Step<MinPk, Digest>) -> PersistJob<MinPk, Digest> {
        let jobs = step
            .capabilities()
            .iter()
            .filter_map(|effect| match effect {
                Capability::Durability(DurabilityCapability::Persist(job)) => {
                    Some(job.job().clone())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            jobs.len(),
            1,
            "the isolated transition must stage one barrier"
        );
        jobs.into_iter().next().unwrap()
    }

    fn publication_witness(
        effects: &[Capability<MinPk, Digest>],
        id: EffectId,
    ) -> PublicationWitness {
        effects
            .iter()
            .find_map(|effect| {
                let job = match effect {
                    Capability::Durability(DurabilityCapability::Released(job))
                        if job.id() == id =>
                    {
                        Some(job.clone())
                    }
                    Capability::Durability(DurabilityCapability::Persist(directive)) => directive
                        .clone()
                        .into_parts()
                        .2
                        .into_iter()
                        .find(|job| job.id() == id),
                    _ => None,
                }?;
                Some(PublicationWitness {
                    id,
                    generation: job.generation(),
                    effect: job.request().clone(),
                })
            })
            .unwrap_or_else(|| panic!("publication {id:?} was absent from {effects:?}"))
    }

    fn authenticate_one(
        runner: &mut Runner<Sha256, MinPk>,
        artifact: Artifact<MinPk, Digest>,
    ) -> Step<MinPk, Digest> {
        let artifact_id = artifact.id::<Sha256>();
        let observed = runner.submit(cohort::<Sha256, _>(vec![artifact])).unwrap();
        let verification = observed
            .capabilities()
            .iter()
            .find_map(|effect| match effect {
                Capability::Verification(VerificationCapability::Verify(job)) => Some(job.clone()),
                _ => None,
            })
            .expect("the independently supplied artifact must require verification");
        let completed = runner
            .submit(Input::Verified(
                SymbolicVerifier::new(true).complete(&verification),
            ))
            .unwrap();
        runner
            .settle(completed)
            .unwrap_or_else(|error| panic!("artifact {artifact_id:?} failed to settle: {error:?}"))
    }

    fn acknowledge_recovery_exit(
        runner: &mut Runner<Sha256, MinPk>,
        recovery: &Step<MinPk, Digest>,
        epoch: Epoch,
    ) {
        let resolution = recovery
            .capabilities()
            .iter()
            .find_map(|effect| match effect {
                Capability::Resolver(ResolverCapability::Resolve(job)) => Some(*job),
                _ => None,
            })
            .expect("recovery must request the exact current-view exit");
        let view = resolution.view();
        let resolving = runner
            .submit(Input::ResolutionCompleted(ResolutionCompletion::new(
                resolution.id(),
                resolution.generation(),
                resolution.view(),
                ViewProof::Nullification(Box::new(symbolic_nullification(epoch, view))),
            )))
            .unwrap();
        let verification = resolving
            .capabilities()
            .iter()
            .find_map(|effect| match effect {
                Capability::Verification(VerificationCapability::Verify(job)) => Some(job.clone()),
                _ => None,
            })
            .expect("the resolved exit must still be authenticated");
        let completed = runner
            .submit(Input::Verified(
                SymbolicVerifier::new(true).complete(&verification),
            ))
            .unwrap();
        let forwarding = runner.settle(completed).unwrap();
        let forwarded = runner.persist(&only_persist(&forwarding)).unwrap();
        let advanced = runner.settle(forwarded).unwrap();
        let advanced = runner.persist(&only_persist(&advanced)).unwrap();
        let drained = runner.settle(advanced).unwrap();
        assert!(drained.capabilities().iter().all(|effect| {
            !matches!(
                effect,
                Capability::Durability(DurabilityCapability::Persist(_))
                    | Capability::Verification(VerificationCapability::Verify(_))
                    | Capability::Resolver(ResolverCapability::Resolve(_))
            )
        }));
    }

    fn prepare_publication_case(
        fixture: &Fixture,
        family: SuccessorFamily,
    ) -> (Runner<Sha256, MinPk>, PublicationWitness) {
        let tuning = Tuning {
            view_timeout: Duration::from_secs(1),
            production_interval: Duration::from_millis(100),
            view_retention: if family == SuccessorFamily::ViewRetention {
                ViewDelta::new(1)
            } else {
                Tuning::default().view_retention
            },
            ..Tuning::default()
        };
        let profile = Profile::new(
            fixture.profiles[0].protocol().clone(),
            Role::Observer,
            tuning,
        )
        .unwrap();
        let epoch = profile.protocol().epoch();
        let predecessor = match family {
            SuccessorFamily::Da => {
                let genesis = profile.protocol().genesis().tips()[0];
                let header = TransactionBlockHeader::new(
                    epoch,
                    genesis.chain(),
                    Height::new(1),
                    genesis.digest(),
                    digest(b"matrix DA predecessor"),
                )
                .unwrap();
                Artifact::TransactionBlock(SignedTransactionBlock::new(header, attestation(0)))
            }
            SuccessorFamily::ForwardedExit => {
                Artifact::Nullification(symbolic_nullification(epoch, View::new(1)))
            }
            SuccessorFamily::ViewRetention | SuccessorFamily::FinalityFloor => {
                fixture.artifacts[VIEW_ONE_HONEST_VOTES].clone()
            }
        };
        let effect = DurableEffect::Broadcast(Arc::new(predecessor));
        let mut runner = Runner::new(profile);
        let started = runner.submit(Input::Start).unwrap();
        runner.persist(&only_persist(&started)).unwrap();

        let initial = if family == SuccessorFamily::ForwardedExit {
            let forwarding = authenticate_one(
                &mut runner,
                Artifact::Nullification(symbolic_nullification(epoch, View::new(1))),
            );
            let forwarding_job = only_persist(&forwarding);
            let publication = publication_witness(
                forwarding.capabilities(),
                EffectId::from_cursor(forwarding_job.last_cursor()),
            );
            assert_eq!(publication.effect, effect);
            let forwarded = runner.persist(&forwarding_job).unwrap();
            let advanced = runner.settle(forwarded).unwrap();
            let advanced = runner.persist(&only_persist(&advanced)).unwrap();
            let drained = runner.settle(advanced).unwrap();
            assert!(drained.capabilities().iter().all(|effect| {
                !matches!(
                    effect,
                    Capability::Durability(DurabilityCapability::Persist(_))
                )
            }));
            publication
        } else {
            let reserved = runner.reserve(effect.clone()).unwrap();
            let reservation = only_persist(&reserved);
            let publication = publication_witness(
                reserved.capabilities(),
                EffectId::from_cursor(reservation.last_cursor()),
            );
            assert_eq!(publication.effect, effect);
            runner.persist(&reservation).unwrap();
            publication
        };

        let delivered = runner
            .submit(Input::EffectCompleted(EffectCompletion::Delivered {
                id: initial.id,
                generation: initial.generation,
            }))
            .unwrap();
        assert!(
            delivered.capabilities().is_empty(),
            "Delivered must be volatile"
        );

        let recovery = runner.crash_and_restore().unwrap();
        let recovered = runner.persist(&only_persist(&recovery)).unwrap();
        let reissued = publication_witness(recovered.capabilities(), initial.id);
        assert_eq!(reissued.effect, initial.effect);
        assert_ne!(reissued.generation, initial.generation);

        if family == SuccessorFamily::ViewRetention {
            acknowledge_recovery_exit(&mut runner, &recovery, epoch);
        }
        (runner, reissued)
    }

    fn successor_barrier(
        fixture: &Fixture,
        runner: &mut Runner<Sha256, MinPk>,
        family: SuccessorFamily,
    ) -> (
        PersistJob<MinPk, Digest>,
        Option<DurableEffect<MinPk, Digest>>,
    ) {
        let epoch = runner.profile.protocol().epoch();
        match family {
            SuccessorFamily::Da => {
                let genesis = runner.profile.protocol().genesis().tips()[0];
                let header = TransactionBlockHeader::new(
                    epoch,
                    genesis.chain(),
                    Height::new(1),
                    genesis.digest(),
                    digest(b"matrix DA predecessor"),
                )
                .unwrap();
                let certificate = Artifact::DaCertificate(DaCertificate::new(
                    header,
                    ThresholdCertificate::new(<MinPk as Variant>::Signature::zero()),
                ));
                let expected = DurableEffect::Broadcast(Arc::new(certificate.clone()));
                let step = authenticate_one(runner, certificate);
                let barrier = only_persist(&step);
                let released = publication_witness(
                    step.capabilities(),
                    EffectId::from_cursor(barrier.last_cursor()),
                );
                assert_eq!(released.generation, barrier.generation());
                assert_eq!(released.effect, expected);
                (barrier, Some(expected))
            }
            SuccessorFamily::ForwardedExit => {
                let certificate =
                    Artifact::Nullification(symbolic_nullification(epoch, View::new(3)));
                let expected = DurableEffect::Broadcast(Arc::new(certificate.clone()));
                let step = authenticate_one(runner, certificate);
                let barrier = only_persist(&step);
                let released = publication_witness(
                    step.capabilities(),
                    EffectId::from_cursor(barrier.last_cursor()),
                );
                assert_eq!(released.generation, barrier.generation());
                assert_eq!(released.effect, expected);
                (barrier, Some(expected))
            }
            SuccessorFamily::ViewRetention => {
                let first = Artifact::Nullification(symbolic_nullification(epoch, View::new(2)));
                let forwarded = authenticate_one(runner, first);
                let advanced = runner.persist(&only_persist(&forwarded)).unwrap();
                let transition = runner.settle(advanced).unwrap();
                let advanced = runner.persist(&only_persist(&transition)).unwrap();
                let drained = runner.settle(advanced).unwrap();
                assert!(drained.capabilities().is_empty());

                let second = Artifact::Nullification(symbolic_nullification(epoch, View::new(3)));
                let forwarded = authenticate_one(runner, second);
                let advanced = runner.persist(&only_persist(&forwarded)).unwrap();
                let target = runner.settle(advanced).unwrap();
                let barrier = only_persist(&target);
                assert!(target.capabilities().iter().all(|effect| {
                    !matches!(effect, Capability::Durability(DurabilityCapability::Released(job))
                    if job.id() == EffectId::from_cursor(barrier.last_cursor()))
                }));
                (barrier, None)
            }
            SuccessorFamily::FinalityFloor => {
                let artifacts = core::iter::once(fixture.artifacts[VIEW_TWO_LEADER].clone())
                    .chain(
                        (0..HONEST)
                            .map(|signer| fixture.artifacts[VIEW_TWO_VOTES + signer].clone()),
                    )
                    .collect::<Vec<_>>();
                let observed = runner.submit(cohort::<Sha256, _>(artifacts)).unwrap();
                let verification = observed
                    .capabilities()
                    .iter()
                    .find_map(|effect| match effect {
                        Capability::Verification(VerificationCapability::Verify(job)) => {
                            Some(job.clone())
                        }
                        _ => None,
                    })
                    .unwrap();
                let verified = runner
                    .submit(Input::Verified(
                        SymbolicVerifier::new(true).complete(&verification),
                    ))
                    .unwrap();
                let ready = runner.settle(verified).unwrap();
                let vqc = ready
                    .capabilities()
                    .iter()
                    .find_map(|effect| match effect {
                        Capability::Leader(LeaderCapability::AggregateVqc(job)) => {
                            Some(job.clone())
                        }
                        _ => None,
                    })
                    .expect("the full-vote cohort must schedule its earlier V-QC");
                // The finalized pool may release its aggregation with the same settle that
                // scheduled the V-QC or only after the covering barrier is acknowledged.
                let aggregation = ready.capabilities().iter().find_map(|effect| match effect {
                    Capability::Leader(LeaderCapability::AggregateLqc(job)) => Some(job.clone()),
                    _ => None,
                });
                let ready = if ready.capabilities().iter().any(|effect| {
                    matches!(
                        effect,
                        Capability::Durability(DurabilityCapability::Persist(_))
                    )
                }) {
                    let acknowledged = runner.persist(&only_persist(&ready)).unwrap();
                    runner.settle(acknowledged).unwrap()
                } else {
                    ready
                };
                let aggregation = aggregation
                    .or_else(|| {
                        ready.capabilities().iter().find_map(|effect| match effect {
                            Capability::Leader(LeaderCapability::AggregateLqc(job)) => {
                                Some(job.clone())
                            }
                            _ => None,
                        })
                    })
                    .expect("the view-two full votes must schedule one L-QC");

                let certificate = symbolic_vqc(&vqc, runner.profile.protocol().codec_config());
                let completed = runner
                    .submit(Input::VqcAggregated(Box::new(VqcAggregateCompletion::new(
                        vqc.id(),
                        vqc.generation(),
                        certificate,
                    ))))
                    .unwrap();
                let completed = runner.settle(completed).unwrap();
                let retained = runner.persist(&only_persist(&completed)).unwrap();
                let retained = runner.settle(retained).unwrap();
                let forwarding = retained
                    .capabilities()
                    .iter()
                    .find_map(|effect| match effect {
                        Capability::Durability(DurabilityCapability::Persist(job)) => {
                            Some(job.clone())
                        }
                        _ => None,
                    })
                    .unwrap_or_else(|| {
                        panic!(
                            "the retained V-QC did not stage forwarding: {:?}",
                            retained.capabilities()
                        )
                    });
                let forwarded = runner.persist(&forwarding).unwrap();
                let forwarded = runner.settle(forwarded).unwrap();
                assert!(forwarded.capabilities().iter().all(|effect| {
                    !matches!(
                        effect,
                        Capability::Durability(DurabilityCapability::Persist(_))
                    )
                }));

                let certificate =
                    symbolic_lqc(&aggregation, runner.profile.protocol().codec_config());
                let created = runner
                    .submit(Input::LqcAggregated(Box::new(LqcAggregateCompletion::new(
                        aggregation.id(),
                        aggregation.generation(),
                        certificate,
                    ))))
                    .unwrap();
                let mut step = runner.settle(created).unwrap();
                for iteration in 0..4 {
                    let barrier = step
                        .capabilities()
                        .iter()
                        .find_map(|effect| match effect {
                            Capability::Durability(DurabilityCapability::Persist(job)) => {
                                Some(job.job().clone())
                            }
                            _ => None,
                        })
                        .unwrap_or_else(|| {
                            panic!(
                                "the finality path stalled after {iteration} barriers: {:?}",
                                step.capabilities()
                            )
                        });
                    if barrier
                        .events()
                        .iter()
                        .any(|event| matches!(event.change(), Change::FinalityFloorAdvanced { .. }))
                    {
                        assert!(step.capabilities().iter().all(|effect| {
                            !matches!(effect, Capability::Durability(DurabilityCapability::Released(job))
                            if job.id() == EffectId::from_cursor(barrier.last_cursor()))
                        }));
                        return (barrier, None);
                    }
                    let acknowledged = runner.persist(&barrier).unwrap();
                    let delivered =
                        acknowledged
                            .capabilities()
                            .iter()
                            .find_map(|effect| match effect {
                                Capability::Durability(DurabilityCapability::Released(job))
                                    if job.request().is_network_publication() =>
                                {
                                    Some((job.id(), job.generation()))
                                }
                                _ => None,
                            });
                    step = if let Some((id, generation)) = delivered {
                        let delivered = runner
                            .submit(Input::EffectCompleted(EffectCompletion::Delivered {
                                id,
                                generation,
                            }))
                            .unwrap();
                        runner.settle(delivered).unwrap()
                    } else {
                        runner.settle(acknowledged).unwrap()
                    };
                }
                panic!("the admitted L-QC did not stage a finality-floor successor")
            }
        }
    }

    fn recover_publications(
        runner: &mut Runner<Sha256, MinPk>,
        ids: &BTreeSet<EffectId>,
    ) -> (u64, BTreeMap<EffectId, PublicationWitness>) {
        let recovery = runner.crash_and_restore().unwrap();
        let recovery_barrier = only_persist(&recovery);
        let released = runner.persist(&recovery_barrier).unwrap();
        let generation = runner.inspect().generation();
        let publications = released
            .capabilities()
            .iter()
            .filter_map(|effect| match effect {
                Capability::Durability(DurabilityCapability::Released(job))
                    if ids.contains(&job.id()) =>
                {
                    Some((
                        job.id(),
                        PublicationWitness {
                            id: job.id(),
                            generation: job.generation(),
                            effect: job.request().clone(),
                        },
                    ))
                }
                _ => None,
            })
            .collect();
        (generation, publications)
    }

    fn run_successor_case(fixture: &Fixture, family: SuccessorFamily, cut: SuccessorCut) {
        let (mut runner, predecessor) = prepare_publication_case(fixture, family);
        let (target, replacement) = successor_barrier(fixture, &mut runner, family);
        assert_eq!(target.last_cursor(), target.previous().next().unwrap());

        let replacement_id = EffectId::from_cursor(target.last_cursor());
        match cut {
            SuccessorCut::BeforeAppend => {}
            SuccessorCut::AfterAppend => runner.append(&target).unwrap(),
            SuccessorCut::AfterAck => {
                runner.persist(&target).unwrap();
            }
        }

        let mut ids = BTreeSet::from([predecessor.id]);
        if replacement.is_some() {
            ids.insert(replacement_id);
        }
        let (recovery_generation, actual) = recover_publications(&mut runner, &ids);
        assert!(
            actual.iter().all(|(id, publication)| {
                *id == publication.id && publication.generation == recovery_generation
            }),
            "failed {family:?} at {cut:?}: recovery generation {recovery_generation}, publications {actual:?}"
        );
        let actual = actual
            .into_iter()
            .map(|(id, publication)| (id, publication.effect))
            .collect::<BTreeMap<_, _>>();
        let expected = if cut == SuccessorCut::BeforeAppend {
            BTreeMap::from([(predecessor.id, predecessor.effect)])
        } else {
            replacement
                .map(|effect| BTreeMap::from([(replacement_id, effect)]))
                .unwrap_or_default()
        };
        assert_eq!(actual, expected, "failed {family:?} at {cut:?}");
    }

    #[test]
    fn publication_successor_family_by_cut_matrix_is_complete() {
        let fixture = Fixture::new(2);
        let families = [
            SuccessorFamily::Da,
            SuccessorFamily::ForwardedExit,
            SuccessorFamily::ViewRetention,
            SuccessorFamily::FinalityFloor,
        ];
        let cuts = [
            SuccessorCut::BeforeAppend,
            SuccessorCut::AfterAppend,
            SuccessorCut::AfterAck,
        ];
        let mut covered = BTreeSet::new();
        for family in families {
            for cut in cuts {
                run_successor_case(&fixture, family, cut);
                assert!(covered.insert((family, cut)));
            }
        }
        let expected = families
            .into_iter()
            .flat_map(|family| cuts.into_iter().map(move |cut| (family, cut)))
            .collect::<BTreeSet<_>>();
        assert_eq!(covered, expected);
    }
}

#[test]
fn poll_budget_changes_latency_not_durable_semantics() {
    let mut expected: Option<DurableOutcome> = None;
    for budget in [1, 2, 17, usize::MAX] {
        let (_, durable) = run_scenario_with_poll_budget(
            4,
            [true, false, true],
            [false, true, false],
            [false, true, true],
            [true, false, true],
            [true, false, true],
            malformed_completions(0),
            [
                CrashCut::BeforeAppend,
                CrashCut::AfterAppend,
                CrashCut::AfterAcknowledgement,
            ],
            NonZeroUsize::new(budget).unwrap(),
        );
        if let Some(expected) = &expected {
            assert_eq!(
                &durable, expected,
                "poll budget {budget} changed normalized durable or pending state"
            );
        } else {
            expected = Some(durable);
        }
    }
}
