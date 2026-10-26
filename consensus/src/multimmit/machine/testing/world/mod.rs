//! Three-replica world model that interprets bytes as a production-machine schedule and checks
//! its oracles.

use super::{
    driver::{
        CapabilityExt as _, Drive as _, Driver, DriverError, MAX_DRAIN_TURNS, SymbolicVerifier,
        Until, cohort,
    },
    fixtures::{
        BarrierCut, TestConfig, attestation, digest, symbolic_lqc, symbolic_vqc, threshold_share,
        unsigned_nullification, vote,
    },
};
use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        actors::voter::validation_parallelism,
        config::{Profile, Role, Tuning},
        machine::{
            capability::{
                AppJob, Capability, CryptoJob, ObservedBlock, ResolverCommand, TimerCommand,
                ValidatorCommand,
            },
            durability::{
                Change, Cursor, DomainEvent, DurableEffect, DurableJob, EffectCompletion, EffectId,
                PersistDirective, PersistJob, Publication, Retained, SignRequest, Snapshot,
            },
            eligibility::{BlockValidity, ChainEligibility, ValidationCompletion},
            finality::LqcAggregateCompletion,
            input::{CryptoCompletion, DaVotesOffer, Input, Step, StepError, StepStatus},
            job::{Generation, Issued},
            producer::{BuildCompletion, CustodyCompletion, ProductionTimer},
            reducer::machine::{Inspection, Machine},
            resolution::ResolutionCompletion,
            verification::{Observation, Verdict, VerificationCompletion, VerificationTicket},
            view::{ViewTimer, VqcAggregateCompletion},
            vote_body::VoteBuild,
        },
        types::{
            Anchor, Artifact, ArtifactId, BlockRef, CertificateId, ChainId, ChainProposal, DaVote,
            EpochGenesis, FinalityFact, LeaderBlock, NoVote, Nullify, SignedLeaderBlock,
            SignedTransactionBlock, TipRecord, TransactionBlockHeader, ViewProof, Vote,
            genesis_history,
        },
    },
    types::{Epoch, Height, Participant, Round, View},
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, sha256::Digest};
use core::{num::NonZeroUsize, time::Duration};
use std::{
    array::from_fn,
    collections::{BTreeMap, BTreeSet, VecDeque, btree_map::Entry},
    sync::Arc,
};

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
    Block {
        replica: usize,
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
    Custody {
        replica: usize,
        order: CompletionOrder,
    },
    HandleResolutionEffect {
        replica: usize,
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
    profiles: Vec<Profile<Digest>>,
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
        let protocol = TestConfig::new(PARTICIPANTS)
            .depth(blocks as u32)
            .namespace(NAMESPACE)
            .genesis(genesis)
            .build();
        assert_eq!(protocol.codec_config().view_quorum(), HONEST);
        assert_eq!(protocol.codec_config().nullification_quorum(), 3);

        let profiles = (0..REPLICAS)
            .map(|replica| {
                Profile::new::<MinPk>(
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
        let history = TipRecord::at_tips(
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
                signer as u32,
                &positions,
                protocol.codec_config(),
            )));
        }
        artifacts.push(Artifact::Vote(vote(
            &first_leader,
            BYZANTINE as u32,
            &positions,
            protocol.codec_config(),
        )));
        artifacts.push(Artifact::Vote(vote(
            &first_leader,
            BYZANTINE as u32,
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
                signer as u32,
                &empty_positions,
                protocol.codec_config(),
            )));
        }
        artifacts.push(Artifact::Vote(vote(
            &second_leader,
            BYZANTINE as u32,
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
                chain_blocks.push(SignedTransactionBlock::new(
                    header,
                    attestation(chain as u32),
                ));
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
        Some(ViewProof::Nullification(Box::new(unsigned_nullification(
            Round::new(self.profiles[0].protocol().epoch(), view),
        ))))
    }
}

/// Builds one deterministic DA-eligibility state per producer chain, anchored at genesis.
fn build_eligibility(profile: &Profile<Digest>) -> Vec<ChainEligibility<MinPk, Digest>> {
    let codec = profile.codec();
    let pipeline_depth = codec.pipeline_depth() as u64;
    let items = validation_parallelism(profile);
    let bytes = items.saturating_mul(profile.resources().max_artifact_bytes());
    profile
        .protocol()
        .genesis()
        .tips()
        .iter()
        .enumerate()
        .map(|(chain, tip)| {
            ChainEligibility::new(
                ChainId::new(chain as u32),
                pipeline_depth,
                items,
                bytes,
                *tip,
                Generation::new(1),
            )
        })
        .collect()
}

/// One replica's machine driver, its oracles, and its coverage counters.
struct Replica {
    driver: ReplicaDriver,
    publication_oracle: PublicationOracle,
    signature_oracle: SignatureOracle,
    counters: Counters,
}

/// The replica's machine, its simulated chain planes, and the effects awaiting execution.
struct ReplicaDriver {
    runner: Driver<Sha256, MinPk>,
    // The per-chain remote chain planes the runtime tasks own, simulated inline here so the
    // pure-Core world drives the same DA-vote offers the tasks would.
    validators: Vec<ChainEligibility<MinPk, Digest>>,
    pending: VecDeque<Capability<MinPk, Digest>>,
    view_timer: Option<ViewTimer>,
    production_timer: Option<ProductionTimer<Digest>>,
    appended_cursor: Cursor,
    acknowledged_cursor: Cursor,
    poll_ready: bool,
}

/// Which publications each durable fact authorizes and discharges, checked against the machine.
#[derive(Default)]
struct PublicationOracle {
    protocol_events: BTreeMap<Cursor, Vec<OracleEvent>>,
    successor_candidates: BTreeMap<ArtifactId<Digest>, SuccessorCandidate>,
    candidate_publications: BTreeMap<ArtifactId<Digest>, Cursor>,
    successor_followups: BTreeMap<Cursor, Vec<OracleEvent>>,
    scheduled_followups: BTreeSet<(Cursor, OracleEvent)>,
    pending_successors: VecDeque<PendingSuccessor>,
    publications: BTreeMap<EffectId, ObservedPublication>,
    publication_attempts: BTreeSet<(EffectId, Generation)>,
    delivered_attempts: BTreeSet<(EffectId, Generation)>,
    recovery_expected: Option<BTreeMap<EffectId, Publication<MinPk, Digest>>>,
    discharged_publications: BTreeSet<EffectId>,
}

/// Which local signatures left the process, checked against their durable signing records.
#[derive(Default)]
struct SignatureOracle {
    signing_events: BTreeMap<ArtifactId<Digest>, SigningOrigin>,
    pending_signings: VecDeque<PendingSigning>,
    externally_injected: BTreeSet<ArtifactId<Digest>>,
    exposed_signatures: BTreeMap<SignatureSlot, ArtifactId<Digest>>,
}

/// How much of each kind of work the replica exercised.
#[derive(Default)]
struct Counters {
    polls: usize,
    verifications: usize,
    validations: usize,
    deliveries: usize,
    max_pending: usize,
    vqcs: usize,
    lqcs: usize,
    signatures: usize,
    crashes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ObservedPublication {
    publication: Publication<MinPk, Digest>,
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
    publication: Publication<MinPk, Digest>,
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
                    driver: ReplicaDriver {
                        runner: Driver::new(profile.clone()),
                        validators: build_eligibility(profile),
                        pending: VecDeque::new(),
                        view_timer: None,
                        production_timer: None,
                        appended_cursor: Cursor::zero(),
                        acknowledged_cursor: Cursor::zero(),
                        poll_ready: false,
                    },
                    publication_oracle: PublicationOracle::default(),
                    signature_oracle: SignatureOracle::default(),
                    counters: Counters::default(),
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
        // Actions that complete an input return its step; the rest update the world directly.
        let step = match action.clone() {
            Action::Block { .. } => {
                let Capability::Quarantine(participants) =
                    self.take(replica, CompletionOrder::Oldest, Capability::is_quarantine)
                else {
                    unreachable!()
                };
                assert!(
                    !participants.is_empty(),
                    "blocking requires attributed evidence"
                );
                assert!(
                    participants
                        .iter()
                        .all(|participant| *participant == Participant::from_usize(BYZANTINE)),
                    "symbolic execution attributed a fault to an honest participant: {participants:?}"
                );
                None
            }
            Action::HandleResolutionEffect { .. } => {
                self.take(
                    replica,
                    CompletionOrder::Oldest,
                    Capability::is_resolver_control,
                );
                None
            }
            Action::MalformedVerify { kind, .. } => {
                self.submit_malformed_verification(replica, kind);
                None
            }
            Action::Poll { .. } => {
                let due = self.replicas[replica].driver.runner.vote_build_due();
                let result = self.replicas[replica]
                    .driver
                    .runner
                    .poll_with(self.poll_budget)
                    .unwrap();
                // The voter opens a vote-build span before a poll the machine says begins the pass, so
                // that poll must begin it.
                assert!(
                    !due || result
                        .vote_builds
                        .into_iter()
                        .any(|build| matches!(build, VoteBuild::Started { .. })),
                    "a poll reported as beginning the vote pass did not begin it"
                );
                self.replicas[replica].driver.poll_ready = self.replicas[replica]
                    .driver
                    .runner
                    .machine()
                    .work_remaining();
                self.replicas[replica].counters.polls += 1;
                self.queue_effects(replica, result.into_capabilities());
                None
            }
            Action::Start { .. } => Some(
                self.replicas[replica]
                    .driver
                    .runner
                    .submit(Input::Start)
                    .unwrap(),
            ),
            Action::FireTimer { .. } => {
                let timer = self.replicas[replica]
                    .driver
                    .view_timer
                    .take()
                    .expect("a timer action requires an armed view timer");
                Some(
                    self.replicas[replica]
                        .driver
                        .runner
                        .submit(Input::TimerFired(timer))
                        .unwrap(),
                )
            }
            Action::FireProductionTimer { .. } => {
                let timer = self.replicas[replica]
                    .driver
                    .production_timer
                    .take()
                    .expect("a timer action requires an armed production timer");
                Some(
                    self.replicas[replica]
                        .driver
                        .runner
                        .submit(Input::ProductionTimerFired(timer))
                        .unwrap(),
                )
            }
            Action::ProducerWake { .. } => Some(
                self.replicas[replica]
                    .driver
                    .runner
                    .submit(Input::ProducerWake)
                    .unwrap(),
            ),
            Action::Build { empty, .. } => {
                let Capability::Application(AppJob::Build(job)) =
                    self.take(replica, CompletionOrder::Oldest, Capability::is_build)
                else {
                    unreachable!()
                };
                let commitment = (!empty).then(|| {
                    digest(
                        format!(
                            "fuzz build replica {replica} generation {} id {:?} parent {:?}",
                            job.issued().generation().get(),
                            job.issued().id(),
                            job.parent()
                        )
                        .as_bytes(),
                    )
                });
                Some(
                    self.replicas[replica]
                        .driver
                        .runner
                        .submit(Input::BlockBuilt(BuildCompletion::new(
                            job.issued(),
                            job.parent(),
                            commitment,
                        )))
                        .unwrap(),
                )
            }
            Action::Custody { order, .. } => {
                let Capability::Application(AppJob::Custody(job)) =
                    self.take(replica, order, Capability::is_custody)
                else {
                    unreachable!()
                };
                Some(
                    self.replicas[replica]
                        .driver
                        .runner
                        .submit(Input::BlockCustodied(CustodyCompletion::new(
                            job.issued(),
                            job.header().clone(),
                        )))
                        .unwrap(),
                )
            }
            Action::Deliver { artifact, .. } => {
                self.replicas[replica].counters.deliveries += 1;
                self.record_external_artifacts(replica, [artifact]);
                Some(
                    self.replicas[replica]
                        .driver
                        .runner
                        .submit(cohort::<Sha256, _>(vec![
                            self.fixture.artifacts[artifact].clone(),
                        ]))
                        .unwrap(),
                )
            }
            Action::DeliverPair { artifacts, .. } => {
                self.replicas[replica].counters.deliveries += artifacts.len();
                self.record_external_artifacts(replica, artifacts);
                Some(
                    self.replicas[replica]
                        .driver
                        .runner
                        .submit(cohort::<Sha256, _>(
                            artifacts
                                .into_iter()
                                .map(|artifact| self.fixture.artifacts[artifact].clone())
                                .collect(),
                        ))
                        .unwrap(),
                )
            }
            Action::Verify { order, valid, .. } => {
                let Capability::Verify(job) = self.take(replica, order, Capability::is_verify)
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
                self.replicas[replica].counters.verifications += 1;
                Some(self.replicas[replica]
                    .driver.runner
                    .submit(Input::Verified(completion))
                    .unwrap_or_else(|error| {
                        panic!(
                            "replica {replica} failed verification in view {:?} for {artifacts:?}: {error:?}",
                            self.replicas[replica].driver.runner.inspect().view(),
                        )
                    }))
            }
            Action::Persist { .. } => {
                let Capability::Journal(directive) =
                    self.take(replica, CompletionOrder::Oldest, Capability::is_journal)
                else {
                    unreachable!()
                };
                let PersistDirective {
                    job,
                    staged_retention,
                    release_after_enqueue,
                    ..
                } = directive;
                self.append(replica, &job);
                Self::assert_staged_custody(&staged_retention, &release_after_enqueue);
                self.queue_effects(
                    replica,
                    release_after_enqueue.into_iter().map(Capability::Released),
                );
                Some(self.acknowledge(replica, &job))
            }
            Action::Resolve { .. } => {
                let Capability::Resolver(ResolverCommand::Resolve(job)) =
                    self.take(replica, CompletionOrder::Oldest, Capability::is_resolve)
                else {
                    unreachable!()
                };
                let result = self
                    .fixture
                    .resolution(job.view())
                    .expect("the fair suffix supplies every requested block");
                Some(
                    self.replicas[replica]
                        .driver
                        .runner
                        .submit(Input::ResolutionCompleted(ResolutionCompletion::new(
                            job.issued(),
                            job.view(),
                            result,
                        )))
                        .unwrap(),
                )
            }
            Action::AggregateVqc { order, .. } => {
                let Capability::Crypto(CryptoJob::AggregateVqc(job)) =
                    self.take(replica, order, Capability::is_aggregate_vqc)
                else {
                    unreachable!()
                };
                let certificate = symbolic_vqc(
                    job.leader().clone(),
                    &job.messages().collect::<Vec<_>>(),
                    self.fixture.profiles[replica].codec(),
                );
                self.register_authenticated_successor(replica, Artifact::Vqc(certificate.clone()));
                self.replicas[replica].counters.vqcs += 1;
                Some(
                    self.replicas[replica]
                        .driver
                        .runner
                        .submit(Input::Crypto(CryptoCompletion::Vqc(Box::new(
                            VqcAggregateCompletion::prepare::<Sha256>(
                                &job,
                                certificate,
                                self.fixture.profiles[replica].codec(),
                            )
                            .expect("symbolic V-QCs match their transcripts"),
                        ))))
                        .unwrap(),
                )
            }
            Action::AggregateLqc { order, .. } => {
                let Capability::Crypto(CryptoJob::AggregateLqc(job)) =
                    self.take(replica, order, Capability::is_aggregate_lqc)
                else {
                    unreachable!()
                };
                let certificate = symbolic_lqc(
                    job.leader().clone(),
                    job.votes(),
                    self.fixture.profiles[replica].codec(),
                );
                self.register_authenticated_successor(replica, Artifact::Lqc(certificate.clone()));
                self.replicas[replica].counters.lqcs += 1;
                Some(
                    self.replicas[replica]
                        .driver
                        .runner
                        .submit(Input::Crypto(CryptoCompletion::Lqc(Box::new(
                            LqcAggregateCompletion::prepare::<Sha256>(
                                &job,
                                certificate,
                                self.fixture.profiles[replica].codec(),
                            )
                            .expect("symbolic L-QCs match their votes"),
                        ))))
                        .unwrap(),
                )
            }
            Action::Sign { order, .. } => {
                let Capability::Released(job) = self.take(replica, order, Capability::is_sign)
                else {
                    unreachable!()
                };
                let Some(requests @ [request]) = job.request().sign_requests() else {
                    unreachable!()
                };
                let artifact = Arc::new(sign(request, REPLICA_PARTICIPANTS[replica]));
                let publication = Publication::signed(
                    requests,
                    &Arc::from([Arc::clone(&artifact)]),
                    self.replicas[replica].driver.runner.profile().protocol(),
                )
                .expect("a completed signing request has a publication shape");
                self.schedule_signing(
                    replica,
                    job.issued().id(),
                    vec![(artifact.id::<Sha256>(), request.clone())],
                    publication,
                );
                self.replicas[replica].counters.signatures += 1;
                Some(
                    self.replicas[replica]
                        .driver
                        .runner
                        .submit(Input::EffectCompleted(EffectCompletion::signed(
                            job.issued(),
                            vec![artifact],
                        )))
                        .unwrap(),
                )
            }
            Action::SignBatch { order, .. } => {
                let Capability::Released(job) =
                    self.take(replica, order, Capability::is_sign_batch)
                else {
                    unreachable!()
                };
                let Some(requests) = job.request().sign_requests() else {
                    unreachable!()
                };
                let artifacts = requests
                    .iter()
                    .map(|request| Arc::new(sign(request, REPLICA_PARTICIPANTS[replica])))
                    .collect::<Vec<_>>();
                let publication = Publication::signed(
                    requests,
                    &artifacts.iter().cloned().collect(),
                    self.replicas[replica].driver.runner.profile().protocol(),
                )
                .expect("a completed signing batch has a publication shape");
                self.schedule_signing(
                    replica,
                    job.issued().id(),
                    artifacts
                        .iter()
                        .zip(requests.iter())
                        .map(|(artifact, request)| (artifact.id::<Sha256>(), request.clone()))
                        .collect(),
                    publication,
                );
                self.replicas[replica].counters.signatures += artifacts.len();
                Some(
                    self.replicas[replica]
                        .driver
                        .runner
                        .submit(Input::EffectCompleted(EffectCompletion::signed(
                            job.issued(),
                            artifacts,
                        )))
                        .unwrap(),
                )
            }
            Action::AcknowledgeDelivery { .. } => {
                let effect = self.take(replica, CompletionOrder::Oldest, Capability::is_publish);
                let (id, generation) = delivery_correlation(&effect);
                self.record_delivery(replica, id, generation);
                Some(
                    self.replicas[replica]
                        .driver
                        .runner
                        .submit(Input::EffectCompleted(EffectCompletion::delivered(
                            Issued::new(id, generation),
                        )))
                        .unwrap(),
                )
            }
            Action::CrashAfterAppend { .. } => {
                let Capability::Journal(directive) =
                    self.take(replica, CompletionOrder::Oldest, Capability::is_journal)
                else {
                    unreachable!()
                };
                let PersistDirective {
                    job,
                    staged_retention,
                    release_after_enqueue,
                    ..
                } = directive;
                self.append(replica, &job);
                Self::assert_staged_custody(&staged_retention, &release_after_enqueue);
                self.queue_effects(
                    replica,
                    release_after_enqueue.into_iter().map(Capability::Released),
                );
                Some(self.crash_and_restore(replica))
            }
            Action::CrashAndRestore { .. } => Some(self.crash_and_restore(replica)),
        };
        if let Some(step) = step {
            self.replicas[replica].driver.poll_ready = true;
            self.queue_effects(replica, step.into_capabilities());
        }
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
        let runner = &state.driver.runner;
        runner.machine().assert_artifact_indices();
        let mut replayed = Machine::<Sha256, MinPk>::restore(
            runner.profile().clone(),
            runner.checkpoint().clone(),
        )
        .expect("the invariant replay checkpoint must restore");
        for event in runner.journal() {
            replayed
                .replay(event.clone())
                .unwrap_or_else(|error| panic!("{}: replay failed: {error:?}", coordinate()));
        }
        let snapshot = replayed.live_snapshot_for_test();
        assert_eq!(
            snapshot.cursor(),
            state.driver.appended_cursor,
            "{}: replay did not end at the exact appended cut",
            coordinate()
        );
        assert!(
            state.driver.acknowledged_cursor <= state.driver.appended_cursor,
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

        for artifact in state.signature_oracle.exposed_signatures.values() {
            if state
                .signature_oracle
                .externally_injected
                .contains(artifact)
            {
                continue;
            }
            let origin = state
                .signature_oracle
                .signing_events
                .get(artifact)
                .unwrap_or_else(|| {
                    panic!(
                        "{}: exposed local signature has no durable origin",
                        coordinate()
                    )
                });
            assert!(
                origin.covering_cursor <= state.driver.acknowledged_cursor,
                "{}: signature escaped before its covering barrier",
                coordinate()
            );
        }

        self.assert_publication_state(replica, state.driver.appended_cursor);
    }

    fn record_external_artifacts(
        &mut self,
        replica: usize,
        artifacts: impl IntoIterator<Item = usize>,
    ) {
        self.replicas[replica]
            .signature_oracle
            .externally_injected
            .extend(
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
                    .derive_vqc(self.fixture.profiles[replica].codec())
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
        match self.replicas[replica]
            .publication_oracle
            .successor_candidates
            .entry(id)
        {
            Entry::Vacant(entry) => {
                entry.insert(candidate);
            }
            Entry::Occupied(mut entry) => {
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
            .publication_oracle
            .candidate_publications
            .get(&id)
            .copied()
        else {
            return;
        };
        let followups = self.replicas[replica]
            .publication_oracle
            .successor_candidates[&id]
            .followups
            .clone();
        let recorded = self.replicas[replica]
            .publication_oracle
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
        publication: Publication<MinPk, Digest>,
    ) {
        let state = &mut self.replicas[replica];
        state
            .signature_oracle
            .pending_signings
            .push_back(PendingSigning {
                sign,
                artifacts,
                publication,
            });
    }

    fn submit_malformed_verification(&mut self, replica: usize, kind: MalformedCompletion) {
        let jobs = self.replicas[replica]
            .driver
            .pending
            .iter()
            .filter_map(|effect| match effect {
                Capability::Verify(job) => Some(job.clone()),
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
            MalformedCompletion::StaleGeneration => job.issued().generation().next().unwrap(),
            MalformedCompletion::MissingVerdict => {
                verdicts.pop();
                job.issued().generation()
            }
            MalformedCompletion::DuplicateVerdict => {
                verdicts[1] = verdicts[0];
                job.issued().generation()
            }
            MalformedCompletion::ForeignTicket => {
                let foreign = jobs
                    .iter()
                    .find(|candidate| candidate.issued().id() != job.issued().id())
                    .expect("foreign-ticket coverage requires another live job");
                verdicts[1] = Verdict::new(foreign.items()[0].ticket(), true);
                job.issued().generation()
            }
            MalformedCompletion::ReorderedVerdicts => {
                verdicts.reverse();
                job.issued().generation()
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
                job.issued().generation()
            }
            MalformedCompletion::WrongObservation => {
                let ticket = verdicts[1].ticket();
                verdicts[1] = Verdict::new(
                    VerificationTicket::new(
                        ticket.job(),
                        ticket.artifact(),
                        Observation::new(
                            ticket.observation().cohort(),
                            ticket.observation().index().checked_add(1).unwrap(),
                        ),
                    ),
                    true,
                );
                job.issued().generation()
            }
        };
        let completion =
            VerificationCompletion::new(Issued::new(job.issued().id(), generation), verdicts);
        let result = self.replicas[replica]
            .driver
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
                    Err(DriverError::Step(StepError::CompletionMismatch))
                ));
            }
        }
        assert!(self.replicas[replica].driver.pending.iter().any(
            |effect| matches!(effect, Capability::Verify(candidate) if candidate.issued().id() == job.issued().id())
        ));
    }

    fn append(&mut self, replica: usize, job: &PersistJob<MinPk, Digest>) {
        self.replicas[replica]
            .driver.runner
            .append(job)
            .unwrap_or_else(|error| {
                panic!(
                    "replica {replica} failed journal admission in view {:?} for barrier {} with events {:?}: {error:?}",
                    self.replicas[replica].driver.runner.inspect().view(),
                    job.id().get(),
                    job.events(),
                )
            });
        self.replicas[replica].driver.appended_cursor = job.last_cursor();
        self.assert_staging_matches_replay(replica);
    }

    fn acknowledge(
        &mut self,
        replica: usize,
        job: &PersistJob<MinPk, Digest>,
    ) -> Step<MinPk, Digest> {
        let step = self.replicas[replica]
            .driver.runner
            .acknowledge(job)
            .unwrap_or_else(|error| {
                panic!(
                    "replica {replica} failed journal acknowledgement in view {:?} for barrier {} with events {:?}: {error:?}",
                    self.replicas[replica].driver.runner.inspect().view(),
                    job.id().get(),
                    job.events(),
                )
            });
        self.replicas[replica].driver.acknowledged_cursor = job.last_cursor();
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
        released: &[DurableJob<MinPk, Digest>],
    ) {
        let staged = staged
            .iter()
            .map(|artifact| artifact.id::<Sha256>())
            .collect::<BTreeSet<_>>();
        // A proposal's block and parent are not staged for resolver custody.
        for job in released {
            job.request().visit_retained(|retained| {
                if let Retained::Artifact(artifact) = retained {
                    assert!(
                        staged.contains(&artifact.id::<Sha256>()),
                        "publication released without resolver custody"
                    );
                }
            });
        }
    }

    fn activate_acknowledged_followups(&mut self, replica: usize) {
        let state = &mut self.replicas[replica];
        let ready = state
            .publication_oracle
            .successor_followups
            .iter()
            .filter(|(cursor, _)| **cursor <= state.driver.acknowledged_cursor)
            .flat_map(|(cursor, events)| events.iter().map(|event| (*cursor, *event)))
            .filter(|pair| !state.publication_oracle.scheduled_followups.contains(pair))
            .collect::<Vec<_>>();
        for (cursor, event) in ready {
            state
                .publication_oracle
                .scheduled_followups
                .insert((cursor, event));
            let skips_local_certificate = matches!(event, OracleEvent::ViewAdvanced)
                && state.publication_oracle.successor_followups[&cursor]
                    .iter()
                    .any(|event| matches!(event, OracleEvent::FinalityFloor(_)))
                || matches!(event, OracleEvent::FinalityFloor(_));
            state
                .publication_oracle
                .pending_successors
                .push_back(PendingSuccessor {
                    event,
                    barriers_to_skip: usize::from(skips_local_certificate),
                });
        }
    }

    fn bind_pending_successor(&mut self, replica: usize, job: &PersistJob<MinPk, Digest>) {
        let Some(pending) = self.replicas[replica]
            .publication_oracle
            .pending_successors
            .front_mut()
        else {
            return;
        };
        if pending.barriers_to_skip > 0 {
            pending.barriers_to_skip -= 1;
            return;
        }
        let pending = self.replicas[replica]
            .publication_oracle
            .pending_successors
            .pop_front()
            .unwrap();
        self.record_protocol_event(replica, job.last_cursor(), pending.event);
    }

    fn crash_and_restore(&mut self, replica: usize) -> Step<MinPk, Digest> {
        let durable = self.replicas[replica].driver.appended_cursor;
        let expected = self.expected_publications(replica, durable);
        let state = &mut self.replicas[replica];
        state.driver.pending.clear();
        state.signature_oracle.pending_signings.clear();
        state.publication_oracle.pending_successors.clear();
        state.counters.crashes += 1;
        state
            .publication_oracle
            .protocol_events
            .retain(|cursor, _| *cursor <= durable);
        state
            .publication_oracle
            .successor_followups
            .retain(|cursor, _| *cursor <= durable);
        state
            .publication_oracle
            .candidate_publications
            .retain(|_, cursor| *cursor <= durable);
        state
            .publication_oracle
            .scheduled_followups
            .retain(|(cursor, _)| *cursor <= durable);
        state
            .signature_oracle
            .signing_events
            .retain(|_, origin| origin.event_cursor <= durable);
        state
            .publication_oracle
            .publications
            .retain(|id, _| id.get() <= durable.get());
        let step = state.driver.runner.crash_and_restore().unwrap();
        assert!(
            step.capabilities()
                .iter()
                .all(|effect| !effect.is_publish())
        );
        state.publication_oracle.recovery_expected = Some(expected);
        self.assert_publication_state(replica, durable);
        step
    }

    fn assert_staging_matches_replay(&self, replica: usize) {
        let runner = &self.replicas[replica].driver.runner;
        let mut replayed = Machine::<Sha256, MinPk>::restore(
            runner.profile().clone(),
            runner.checkpoint().clone(),
        )
        .expect("the initial world checkpoint must restore");
        for event in runner.journal() {
            replayed
                .replay(event.clone())
                .expect("every staged world event must replay");
        }
        assert_eq!(
            replayed.live_snapshot_for_test(),
            runner.machine().live_snapshot_for_test()
        );
    }

    fn record_persist_job(&mut self, replica: usize, job: &PersistJob<MinPk, Digest>) {
        for event in job.events() {
            match event.change() {
                Change::SignedArtifacts {
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
            .signature_oracle
            .pending_signings
            .iter()
            .position(|pending| pending.sign == sign_id)
            .expect("a signing transition must match an independently scheduled completion");
        let pending = state
            .signature_oracle
            .pending_signings
            .remove(index)
            .unwrap();
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
            let prior = state
                .signature_oracle
                .signing_events
                .insert(artifact, origin.clone());
            assert!(prior.is_none_or(|prior| prior == origin));
        }
        let publication_id = EffectId::from_cursor(event_cursor);
        self.record_known_publication(replica, publication_id, pending.publication);
    }

    fn record_protocol_event(&mut self, replica: usize, cursor: Cursor, event: OracleEvent) {
        let events = self.replicas[replica]
            .publication_oracle
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
        publication: Publication<MinPk, Digest>,
    ) {
        let observed = ObservedPublication {
            rules: publication_rules(&publication),
            publication,
        };
        let prior = self.replicas[replica]
            .publication_oracle
            .publications
            .insert(id, observed.clone());
        assert!(prior.is_none_or(|prior| prior == observed));
    }

    fn expected_publications(
        &self,
        replica: usize,
        cursor: Cursor,
    ) -> BTreeMap<EffectId, Publication<MinPk, Digest>> {
        let state = successor_state(
            self.replicas[replica]
                .publication_oracle
                .protocol_events
                .iter()
                .filter(|(event_cursor, _)| **event_cursor <= cursor)
                .flat_map(|(_, events)| events.iter().copied()),
            self.fixture.profiles[replica].view_retention().get(),
        );
        self.replicas[replica]
            .publication_oracle
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
            .map(|(id, publication)| (*id, publication.publication.clone()))
            .collect()
    }

    fn assert_publication_state(&mut self, replica: usize, cursor: Cursor) {
        let expected = self.expected_publications(replica, cursor);
        let runner = &self.replicas[replica].driver.runner;
        let mut durable = Machine::<Sha256, MinPk>::restore(
            runner.profile().clone(),
            runner.checkpoint().clone(),
        )
        .expect("the independently replayed publication prefix must restore");
        for event in runner
            .journal()
            .iter()
            .filter(|event| event.cursor() <= cursor)
        {
            durable
                .replay(event.clone())
                .expect("the independently bounded publication prefix must replay");
        }
        let snapshot = durable.live_snapshot_for_test();
        let tracked = self.replicas[replica]
            .publication_oracle
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
            .map(|(id, entry)| (*id, entry.publication().clone()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            &actual,
            &expected,
            "cursor {cursor:?}, oracle events {:?}, pending successors {:?}",
            self.replicas[replica].publication_oracle.protocol_events,
            self.replicas[replica].publication_oracle.pending_successors,
        );

        let expected_ids = expected.keys().copied().collect::<BTreeSet<_>>();
        self.replicas[replica]
            .publication_oracle
            .discharged_publications
            .extend(tracked.difference(&expected_ids).copied());
    }

    fn record_publication_payloads(
        &mut self,
        replica: usize,
        effects: &[Capability<MinPk, Digest>],
    ) {
        for effect in effects {
            let Capability::Released(job) = effect else {
                continue;
            };
            if let Some(publication) = job.request().publication() {
                self.record_known_publication(replica, job.issued().id(), publication.clone());
            }
        }
    }

    fn assert_recovery_releases(&mut self, replica: usize, effects: &[Capability<MinPk, Digest>]) {
        let Some(expected) = self.replicas[replica]
            .publication_oracle
            .recovery_expected
            .take()
        else {
            return;
        };
        let mut actual = BTreeMap::new();
        for effect in effects {
            let Capability::Released(job) = effect else {
                continue;
            };
            if !expected.contains_key(&job.issued().id()) {
                continue;
            }
            let publication = job
                .request()
                .publication()
                .expect("recovery reissues only publications");
            assert!(
                actual
                    .insert(job.issued().id(), publication.clone())
                    .is_none()
            );
        }
        assert_eq!(actual, expected);
    }

    fn record_delivery(&mut self, replica: usize, id: EffectId, generation: Generation) {
        assert!(
            self.replicas[replica]
                .publication_oracle
                .publication_attempts
                .contains(&(id, generation))
        );
        assert!(
            self.replicas[replica]
                .publication_oracle
                .delivered_attempts
                .insert((id, generation))
        );
    }

    /// Simulates one remote validator task: stores the routed block, validates it (the world's
    /// deterministic verdict is always valid), and offers the eligible run.
    fn observe_validator_block(
        &mut self,
        replica: usize,
        id: ArtifactId<Digest>,
        observation: Observation,
        block: Arc<SignedTransactionBlock<MinPk, Digest>>,
        custodied: bool,
    ) {
        let chain = block.header().chain();
        self.replicas[replica].counters.validations += 1;
        {
            let validator = &mut self.replicas[replica].driver.validators[chain.get() as usize];
            validator.observe::<Sha256>(id, observation, block, custodied);
            while let Some(job) = validator.ready_validation() {
                let completion = ValidationCompletion::new(job.issued(), BlockValidity::Valid);
                validator.complete_validation(completion);
            }
        }
        self.offer_da_votes(replica, chain);
    }

    /// Recomputes one chain's eligible run and feeds it to the machine's frontier shadow.
    fn offer_da_votes(&mut self, replica: usize, chain: ChainId) {
        let cap = self.replicas[replica]
            .driver
            .runner
            .profile()
            .codec()
            .pipeline_depth();
        let run = self.replicas[replica].driver.validators[chain.get() as usize].eligible_run(cap);
        let runner = &mut self.replicas[replica].driver.runner;
        runner.offer_da_votes(DaVotesOffer {
            generation: runner.generation(),
            chain,
            candidates: run.run,
            ready_through: run.ready_through,
        });
    }

    fn queue_effects(
        &mut self,
        replica: usize,
        effects: impl IntoIterator<Item = Capability<MinPk, Digest>>,
    ) {
        for effect in effects {
            if let Capability::Journal(directive) = &effect {
                self.bind_pending_successor(replica, &directive.job);
                self.record_persist_job(replica, &directive.job);
            }
            match effect {
                // The runtime routes these to the per-chain validator tasks; the pure-Core world
                // drives the same planes inline and offers the resulting run back to the machine.
                Capability::Validator(
                    _,
                    ValidatorCommand::Observe(ObservedBlock {
                        id,
                        observation,
                        block,
                        custodied,
                    }),
                ) => {
                    self.observe_validator_block(replica, id, observation, block, custodied);
                    continue;
                }
                Capability::Validator(_, ValidatorCommand::AnchorAdvanced(anchor)) => {
                    let chain = anchor.chain().get() as usize;
                    self.replicas[replica].driver.validators[chain].advance_anchor(anchor);
                    self.offer_da_votes(replica, anchor.chain());
                    continue;
                }
                Capability::Validator(chain, ValidatorCommand::Chosen(choices)) => {
                    self.replicas[replica].driver.validators[chain.get() as usize]
                        .note_chosen(choices);
                    self.offer_da_votes(replica, chain);
                    continue;
                }
                Capability::Acknowledged { .. } | Capability::Retain(_) | Capability::Retire(_) => {
                    // These capabilities mutate only actor-owned resolver/egress state. The pure
                    // Core world has neither collaborator, so execution completes inline here.
                    continue;
                }
                Capability::Timer(TimerCommand::View(timer)) => {
                    self.replicas[replica].driver.view_timer = Some(timer);
                    continue;
                }
                Capability::Timer(TimerCommand::Production(timer)) => {
                    self.replicas[replica].driver.production_timer = Some(timer);
                    continue;
                }
                // The own-chain data-availability plane runs on a task the pure-Core world does
                // not host, so forwarded shares and anchor confirmations have no collaborator
                // here. Dropping them matches the pre-sharding machine, which pooled shares
                // silently; these scenarios certify own blocks through observed certificates.
                Capability::OwnChainDa(_) => {
                    continue;
                }
                _ => {}
            }
            if effect.is_publish() {
                self.record_publication_attempt(replica, &effect);
            }
            self.replicas[replica].driver.pending.push_back(effect);
        }
        self.replicas[replica].counters.max_pending = self.replicas[replica]
            .counters
            .max_pending
            .max(self.replicas[replica].driver.pending.len());
    }

    fn record_publication_attempt(&mut self, replica: usize, effect: &Capability<MinPk, Digest>) {
        let Capability::Released(job) = effect else {
            unreachable!()
        };
        let publication = job
            .request()
            .publication()
            .expect("publication attempts carry publications");
        self.record_known_publication(replica, job.issued().id(), publication.clone());
        assert!(
            self.replicas[replica]
                .publication_oracle
                .publication_attempts
                .insert((job.issued().id(), job.issued().generation()))
        );

        let local = Participant::from_usize(REPLICA_PARTICIPANTS[replica]);
        // A proposal's block and parent are not successor candidates.
        let mut published = Vec::new();
        job.request().visit_retained(|retained| {
            if let Retained::Artifact(artifact) = retained {
                published.push(Arc::clone(artifact));
            }
        });
        for artifact in published {
            let artifact_id = artifact.id::<Sha256>();
            let Some(candidate) = self.replicas[replica]
                .publication_oracle
                .successor_candidates
                .get(&artifact_id)
                .cloned()
            else {
                continue;
            };
            assert_eq!(artifact.as_ref(), &candidate.artifact);
            let cursor = Cursor::new(job.issued().id().get());
            let prior = self.replicas[replica]
                .publication_oracle
                .candidate_publications
                .insert(artifact_id, cursor);
            assert!(prior.is_none_or(|prior| prior == cursor));
            self.record_protocol_event(replica, cursor, candidate.event);
            let followups = self.replicas[replica]
                .publication_oracle
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
            let Some(origin) = self.replicas[replica]
                .signature_oracle
                .signing_events
                .get(&artifact)
            else {
                assert!(
                    self.replicas[replica]
                        .signature_oracle
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
                self.replicas[replica].driver.acknowledged_cursor >= origin.covering_cursor,
                "artifact {artifact:?} from signing effect {:?} escaped before covering cursor {:?} was acknowledged at {:?}",
                origin.sign,
                origin.covering_cursor,
                self.replicas[replica].driver.acknowledged_cursor,
            );
            let prior = self.replicas[replica]
                .signature_oracle
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
        let pending = &mut self.replicas[replica].driver.pending;
        let index = match order {
            CompletionOrder::Oldest => pending.iter().position(predicate),
            CompletionOrder::Newest => pending.iter().rposition(predicate),
        }
        .expect("the replay action must name a pending effect");
        pending.remove(index).unwrap()
    }

    fn has(&self, replica: usize, predicate: fn(&Capability<MinPk, Digest>) -> bool) -> bool {
        self.replicas[replica].driver.pending.iter().any(predicate)
    }

    fn can_malformed(&self, replica: usize, kind: MalformedCompletion) -> bool {
        let jobs = self.replicas[replica]
            .driver
            .pending
            .iter()
            .filter_map(|effect| match effect {
                Capability::Verify(job) => Some(job),
                _ => None,
            })
            .collect::<Vec<_>>();
        let has_batch = jobs.iter().any(|job| job.items().len() >= 2);
        has_batch && (!matches!(kind, MalformedCompletion::ForeignTicket) || jobs.len() >= 2)
    }

    fn durable_outcome(&self) -> DurableOutcome {
        DurableOutcome {
            journals: from_fn(|replica| self.replicas[replica].driver.runner.journal().to_vec()),
            snapshots: from_fn(|replica| {
                self.replicas[replica]
                    .driver
                    .runner
                    .machine()
                    .live_snapshot_for_test()
            }),
            inspections: from_fn(|replica| self.replicas[replica].driver.runner.inspect()),
            finality: from_fn(|replica| {
                self.replicas[replica]
                    .driver
                    .runner
                    .inspect()
                    .finality()
                    .to_vec()
            }),
            publications: from_fn(|replica| {
                self.replicas[replica]
                    .publication_oracle
                    .publications
                    .clone()
            }),
            exposed_signatures: from_fn(|replica| {
                self.replicas[replica]
                    .signature_oracle
                    .exposed_signatures
                    .clone()
            }),
            signing_events: from_fn(|replica| {
                self.replicas[replica]
                    .signature_oracle
                    .signing_events
                    .clone()
            }),
            pending: from_fn(|replica| {
                self.replicas[replica]
                    .driver
                    .pending
                    .iter()
                    .map(|effect| format!("{effect:?}"))
                    .collect()
            }),
        }
    }

    /// Applies schedulable actions for `replica` until `until` holds.
    ///
    /// [`Until::Persist`] stops as soon as a persistence barrier is pending. [`Until::Quiesce`]
    /// applies each pending barrier first and stops when nothing else is schedulable, asserting a
    /// full local drain when `local` is set. No other stop condition applies here.
    fn drive(
        &mut self,
        replica: usize,
        until: Until,
        verification: CompletionOrder,
        validation: CompletionOrder,
        local: bool,
    ) {
        for _ in 0..MAX_DRAIN_TURNS {
            let persist = self.has(replica, Capability::is_journal);
            let action = match until {
                Until::Persist if persist => return,
                Until::Persist => self
                    .schedulable_action(replica, verification, validation, local)
                    .expect("the crash cut must reach a persistence barrier"),
                Until::Quiesce if persist => Action::Persist { replica },
                Until::Quiesce => {
                    let Some(action) =
                        self.schedulable_action(replica, verification, validation, local)
                    else {
                        if local {
                            self.assert_locally_drained(replica);
                        }
                        return;
                    };
                    action
                }
                Until::Step | Until::CursorAdvance => {
                    unreachable!("the world drives to a barrier or to quiescence")
                }
            };
            self.apply(action);
        }
        panic!("fair effect scheduling did not reach {until:?}");
    }

    fn assert_locally_drained(&self, replica: usize) {
        let state = &self.replicas[replica];
        assert!(
            !state.driver.poll_ready,
            "machine-owned scheduler work was stranded"
        );
        assert!(
            state.driver.pending.is_empty(),
            "the machine executor left pending effects: {:?}",
            state.driver.pending
        );
        let inspection = state.driver.runner.inspect();
        assert!(inspection.pending_barrier().is_none());
        assert!(inspection.verification_jobs().is_empty());
        assert_eq!(inspection.resolution_jobs(), 0);
    }

    fn schedulable_action(
        &self,
        replica: usize,
        verification: CompletionOrder,
        validation: CompletionOrder,
        local: bool,
    ) -> Option<Action> {
        if self.has(replica, Capability::is_quarantine) {
            return Some(Action::Block { replica });
        }
        if self.has(replica, Capability::is_verify) {
            return Some(Action::Verify {
                replica,
                order: verification,
                valid: true,
            });
        }
        if self.has(replica, Capability::is_aggregate_vqc) {
            return Some(Action::AggregateVqc {
                replica,
                order: verification,
            });
        }
        if self.has(replica, Capability::is_aggregate_lqc) {
            return Some(Action::AggregateLqc {
                replica,
                order: verification,
            });
        }
        if self.has(replica, Capability::is_custody) {
            return Some(Action::Custody {
                replica,
                order: validation,
            });
        }
        if local && self.has(replica, Capability::is_build) {
            return Some(Action::Build {
                replica,
                empty: true,
            });
        }
        if self.has(replica, Capability::is_resolve)
            && self.replicas[replica].driver.pending.iter().any(|effect| {
                matches!(effect, Capability::Resolver(ResolverCommand::Resolve(job)) if self.fixture.resolution(job.view()).is_some())
            })
        {
            return Some(Action::Resolve { replica });
        }
        if self.has(replica, Capability::is_resolver_control) {
            return Some(Action::HandleResolutionEffect { replica });
        }
        if self.replicas[replica].driver.poll_ready {
            return Some(Action::Poll { replica });
        }
        if self.has(replica, Capability::is_publish) {
            return Some(Action::AcknowledgeDelivery { replica });
        }
        if local && self.has(replica, Capability::is_sign) {
            return Some(Action::Sign {
                replica,
                order: verification,
            });
        }
        if local && self.has(replica, Capability::is_sign_batch) {
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

fn publication_rules(publication: &Publication<MinPk, Digest>) -> Vec<PublicationRule> {
    match publication {
        Publication::Propose(proposal) => {
            vec![PublicationRule::OwnMessage(proposal.block().view())]
        }
        Publication::Broadcast(_) | Publication::Send(_) => publication
            .artifacts()
            .map(|artifact| publication_rule(artifact.as_ref()))
            .collect(),
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
    let Capability::Released(job) = effect else {
        return Vec::new();
    };
    let Some(publication) = job.request().publication() else {
        return Vec::new();
    };

    let mut exposed = Vec::new();
    publication.visit_retained(|retained| {
        record_local_signature(&mut exposed, &retained.to_artifact(), local);
    });
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
            | Self::Block { replica }
            | Self::MalformedVerify { replica, .. }
            | Self::Persist { replica }
            | Self::Poll { replica }
            | Self::FireTimer { replica }
            | Self::FireProductionTimer { replica }
            | Self::ProducerWake { replica }
            | Self::Build { replica, .. }
            | Self::Custody { replica, .. }
            | Self::HandleResolutionEffect { replica }
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

fn sign(request: &SignRequest<MinPk, Digest>, replica: usize) -> Artifact<MinPk, Digest> {
    match request {
        SignRequest::TransactionBlock(header) => Artifact::TransactionBlock(
            SignedTransactionBlock::new(header.clone(), attestation(replica as u32)),
        ),
        SignRequest::DaVote(request) => Artifact::DaVote(DaVote::new(
            request.header().clone(),
            threshold_share(replica as u32),
        )),
        SignRequest::LeaderBlock(request) => Artifact::LeaderBlock(SignedLeaderBlock::new(
            request.block().clone(),
            attestation(replica as u32),
        )),
        SignRequest::Vote(request) => {
            Artifact::Vote(Vote::new(request.clone(), attestation(replica as u32)))
        }
        SignRequest::NoVote { round } => {
            Artifact::NoVote(NoVote::new(*round, attestation(replica as u32)).unwrap())
        }
        SignRequest::Nullify { round } => {
            Artifact::Nullify(Nullify::new(*round, threshold_share(replica as u32)).unwrap())
        }
    }
}

fn delivery_correlation(effect: &Capability<MinPk, Digest>) -> (EffectId, Generation) {
    let Capability::Released(job) = effect else {
        unreachable!("delivery actions only consume publication effects")
    };
    assert!(matches!(job.request(), DurableEffect::Publish(_)));
    (job.issued().id(), job.issued().generation())
}

/// Per-replica knobs of one deterministic scenario.
#[derive(Copy, Clone, Debug)]
struct ReplicaKnobs {
    /// Delivers each leader block before its votes.
    proposal_first: bool,
    /// Completes the newest outstanding verification first.
    newest_verification: bool,
    /// Delivers votes in reverse order.
    reverse_votes: bool,
    /// The Byzantine participant votes the full view-one proposal.
    byzantine_full: bool,
    /// Delivers transaction blocks newest first.
    reverse_blocks: bool,
    /// The malformed verification completion submitted before the valid one.
    malformed: MalformedCompletion,
    /// Where the replica crashes around its signing barrier, if it does.
    crash: Option<BarrierCut>,
}

/// One deterministic three-replica schedule, from genesis through finality and recovery.
struct Scenario {
    /// Transaction blocks each producer chain carries.
    blocks: usize,
    /// Knobs of each replica.
    replicas: [ReplicaKnobs; REPLICAS],
    /// Work quanta one poll action may spend.
    poll_budget: NonZeroUsize,
}

impl Scenario {
    /// Creates a scenario that polls one work quantum at a time.
    const fn new(blocks: usize, replicas: [ReplicaKnobs; REPLICAS]) -> Self {
        Self {
            blocks,
            replicas,
            poll_budget: NonZeroUsize::MIN,
        }
    }

    /// Runs the schedule and returns its action plan and durable outcome.
    fn run(&self) -> (ReplayPlan, DurableOutcome) {
        let fixture = Fixture::new(self.blocks);
        let mut world = World::with_poll_budget(&fixture, self.poll_budget);
        for replica in 0..REPLICAS {
            world.apply(Action::Start { replica });
            world.drive(
                replica,
                Until::Quiesce,
                CompletionOrder::Oldest,
                CompletionOrder::Oldest,
                false,
            );
        }

        world.apply(Action::ProducerWake { replica: 0 });
        world.drive(
            0,
            Until::Quiesce,
            CompletionOrder::Oldest,
            CompletionOrder::Oldest,
            false,
        );
        assert!(world.has(0, Capability::is_build));
        world.apply(Action::Build {
            replica: 0,
            empty: false,
        });
        world.drive(
            0,
            Until::Quiesce,
            CompletionOrder::Oldest,
            CompletionOrder::Oldest,
            false,
        );
        assert!(world.has(0, Capability::is_build));
        world.apply(Action::Build {
            replica: 0,
            empty: true,
        });
        world.drive(
            0,
            Until::Quiesce,
            CompletionOrder::Oldest,
            CompletionOrder::Oldest,
            true,
        );

        for (replica, knobs) in self.replicas.iter().enumerate() {
            world.apply(Action::DeliverPair {
                replica,
                artifacts: [FIRST_TRANSACTION_BLOCK, FIRST_TRANSACTION_BLOCK + 1],
            });
            world.apply(Action::Deliver {
                replica,
                artifact: VIEW_ONE_LEADER,
            });
            world.apply(Action::MalformedVerify {
                replica,
                kind: knobs.malformed,
            });
            world.apply(Action::Verify {
                replica,
                order: CompletionOrder::Oldest,
                valid: false,
            });
            world.drive(
                replica,
                Until::Quiesce,
                CompletionOrder::Oldest,
                CompletionOrder::Oldest,
                false,
            );
        }

        for (replica, omitted) in REPLICA_PARTICIPANTS.into_iter().enumerate() {
            let mut votes = (0..HONEST)
                .filter(|signer| *signer != omitted)
                .map(|signer| VIEW_ONE_HONEST_VOTES + signer)
                .collect::<Vec<_>>();
            votes.push(if self.replicas[replica].byzantine_full {
                VIEW_ONE_BYZANTINE_FULL
            } else {
                VIEW_ONE_BYZANTINE_EMPTY
            });
            if self.replicas[replica].reverse_votes {
                votes.reverse();
            }
            if self.replicas[replica].proposal_first {
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
            let verification = order(self.replicas[replica].newest_verification);
            world.drive(
                replica,
                Until::Quiesce,
                verification,
                CompletionOrder::Oldest,
                false,
            );
            assert!(world.replicas[replica].driver.runner.inspect().view() >= View::new(2));
            assert!(
                world.replicas[replica]
                    .driver
                    .runner
                    .inspect()
                    .pools()
                    .iter()
                    .any(|pool| pool.finalized())
            );
        }

        for replica in (0..REPLICAS).step_by(2) {
            let transactions =
                transaction_order(self.blocks, self.replicas[replica].reverse_blocks);
            for artifact in transactions {
                world.apply(Action::Deliver { replica, artifact });
            }
            let verification = order(self.replicas[replica].newest_verification);
            world.drive(replica, Until::Quiesce, verification, verification, false);
        }
        for (replica, participant) in REPLICA_PARTICIPANTS.into_iter().enumerate() {
            let mut artifacts = (0..HONEST)
                .filter(|signer| *signer != participant)
                .map(|signer| VIEW_TWO_VOTES + signer)
                .collect::<Vec<_>>();
            artifacts.push(VIEW_TWO_BYZANTINE_VOTE);
            if self.replicas[replica].reverse_votes {
                artifacts.reverse();
            }
            if self.replicas[replica].proposal_first {
                world.apply(Action::Deliver {
                    replica,
                    artifact: VIEW_TWO_LEADER,
                });
            }
            for artifact in artifacts {
                world.apply(Action::Deliver { replica, artifact });
            }
            if !self.replicas[replica].proposal_first {
                world.apply(Action::Deliver {
                    replica,
                    artifact: VIEW_TWO_LEADER,
                });
            }
            let verification = order(self.replicas[replica].newest_verification);
            world.drive(
                replica,
                Until::Quiesce,
                verification,
                CompletionOrder::Oldest,
                false,
            );
            assert!(world.replicas[replica].driver.runner.inspect().view() >= View::new(3));
        }

        for (replica, participant) in REPLICA_PARTICIPANTS.into_iter().enumerate() {
            let mut artifacts = vec![
                VIEW_ONE_LEADER,
                VIEW_ONE_BYZANTINE_FULL,
                VIEW_ONE_BYZANTINE_EMPTY,
                VIEW_TWO_LEADER,
            ];
            artifacts.extend((0..HONEST).map(|signer| VIEW_ONE_HONEST_VOTES + signer));
            artifacts.extend((0..HONEST).map(|signer| VIEW_TWO_VOTES + signer));
            artifacts.retain(|artifact| {
                *artifact != VIEW_ONE_HONEST_VOTES + participant
                    && *artifact != VIEW_TWO_VOTES + participant
            });
            artifacts.push(VIEW_TWO_BYZANTINE_VOTE);
            artifacts.extend(transaction_order(
                self.blocks,
                self.replicas[replica].reverse_blocks,
            ));
            if self.replicas[replica].reverse_votes {
                artifacts.reverse();
            }
            for artifact in artifacts {
                world.apply(Action::Deliver { replica, artifact });
            }
        }

        for replica in (0..REPLICAS).rev() {
            let verification = order(self.replicas[replica].newest_verification);
            world.drive(replica, Until::Quiesce, verification, verification, false);
            let action = if world.has(replica, Capability::is_sign) {
                Action::Sign {
                    replica,
                    order: verification,
                }
            } else {
                assert!(world.has(replica, Capability::is_sign_batch));
                Action::SignBatch {
                    replica,
                    order: verification,
                }
            };
            world.apply(action);
            world.drive(replica, Until::Persist, verification, verification, true);
            match self.replicas[replica].crash {
                None => world.apply(Action::Persist { replica }),
                Some(BarrierCut::BeforeAppend) => world.apply(Action::CrashAndRestore { replica }),
                Some(BarrierCut::AfterAppend) => world.apply(Action::CrashAfterAppend { replica }),
                Some(BarrierCut::AfterAck) => {
                    world.apply(Action::Persist { replica });
                    if world.has(replica, Capability::is_publish) {
                        world.apply(Action::AcknowledgeDelivery { replica });
                    }
                    world.apply(Action::CrashAndRestore { replica });
                }
            }
        }
        for replica in (0..REPLICAS).rev() {
            let verification = order(self.replicas[replica].newest_verification);
            world.drive(replica, Until::Quiesce, verification, verification, true);
        }

        for (replica, knobs) in self.replicas.iter().enumerate() {
            assert!(
                !world.replicas[replica]
                    .publication_oracle
                    .discharged_publications
                    .is_empty()
            );
            world.apply(Action::CrashAndRestore { replica });
            let verification = order(knobs.newest_verification);
            world.drive(replica, Until::Quiesce, verification, verification, true);
        }

        assert_eq!(
            world
                .replicas
                .iter()
                .map(|replica| replica.counters.crashes)
                .sum::<usize>(),
            REPLICAS
                + self
                    .replicas
                    .iter()
                    .filter(|knobs| knobs.crash.is_some())
                    .count()
        );
        for replica in &world.replicas {
            let inspection = replica.driver.runner.inspect();
            assert!(inspection.view() >= View::new(3));
            assert!(inspection.finality().len() >= 2);
            assert!(inspection.finality_floor() >= View::new(1));
            assert!(inspection.pending_barrier().is_none());
            assert!(replica.counters.polls > 0);
            assert!(replica.counters.verifications > 0);
            assert!(replica.counters.validations > 0);
            assert!(replica.counters.deliveries > 0);
            assert!(replica.counters.max_pending > 1);
            assert!(replica.counters.vqcs >= 2);
            assert!(replica.counters.lqcs >= 2);
            assert!(replica.counters.signatures > 0);
            assert!(
                !replica
                    .publication_oracle
                    .discharged_publications
                    .is_empty()
            );
        }

        let durable = world.durable_outcome();
        let mut plan = ReplayPlan::new(self.blocks);
        plan.actions = world.actions;
        (plan, durable)
    }
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

pub(crate) mod fuzz;
#[cfg(test)]
mod tests;
