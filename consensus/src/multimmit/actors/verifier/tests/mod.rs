//! Deterministic verifier tests over machine-issued jobs.

use super::{Config, Mailbox, Verifier};
use crate::{
    Epochable as _,
    multimmit::{
        actors::{
            ingress::{self, IngressLimits},
            testing::CoreDriver,
            voter::{self, Completed, Endpoints, Inbox},
        },
        config::{Profile, Role, Tuning},
        machine::{CoreState, CoreTurn, Input, StepStatus, VerifyJob},
        mocks::Committee,
        testing::expect_within,
        types::{Artifact, ChainId, DaVote, SignedTransactionBlock},
    },
    types::{Epoch, Participant, Round, View},
};
use commonware_actor::mailbox;
use commonware_cryptography::{
    Hasher as _, Sha256, bls12381::primitives::variant::MinPk,
    ed25519::PublicKey as Ed25519PublicKey, sha256::Digest as Sha256Digest,
};
use commonware_macros::test_traced;
use commonware_p2p::Receiver;
use commonware_parallel::{Sequential, Strategy, mocks};
use commonware_runtime::{
    Clock as _, Handle, IoBuf, Metrics as _, Runner as _, Supervisor as _,
    deterministic::{Context as DeterministicContext, Runner as DeterministicRunner},
};
use std::{convert::Infallible, future::pending, num::NonZeroUsize, sync::Arc, time::Duration};
use tracing::Span;

mod unit;

/// A network plane that never delivers a frame.
#[derive(Debug)]
struct Silent;

impl Receiver for Silent {
    type Error = Infallible;
    type PublicKey = Ed25519PublicKey;

    async fn recv(&mut self) -> Result<(Self::PublicKey, IoBuf), Self::Error> {
        pending().await
    }
}

struct Harness {
    committee: Committee<MinPk>,
    mailbox: Mailbox<MinPk, Sha256Digest>,
    completions: mailbox::Receiver<Completed<MinPk, Sha256Digest>>,
    task: Handle<()>,
    _credits: ingress::Mailbox,
}

impl Harness {
    /// Starts a verifier whose bulk and view-critical pools are supplied separately, on the
    /// ingress task that serves it in production.
    fn new<T: Strategy, C: Strategy>(
        context: &DeterministicContext,
        seed: u64,
        strategy: T,
        critical_strategy: C,
    ) -> Self {
        let committee = Committee::<MinPk>::builder(seed, 6).build();
        let (verifier, mailbox): (Verifier<_, Sha256, Ed25519PublicKey, MinPk, T, C>, _) =
            Verifier::new(
                context.child("batcher"),
                Config {
                    scheme: committee.verifier.clone(),
                    strategy: strategy.clone(),
                    critical_strategy: critical_strategy.clone(),
                    inflight_jobs: NonZeroUsize::new(2).unwrap(),
                    mailbox_size: NonZeroUsize::new(16).unwrap(),
                },
            );
        let (ingress, credits) = ingress::Actor::new(
            context.child("batcher"),
            ingress::Config {
                epoch: committee.config.epoch(),
                participants: Arc::new(committee.verifier.participants().clone()),
                strategy,
                critical_strategy,
                codec: committee.codec(),
                bounds: committee
                    .codec()
                    .encoded_bounds::<MinPk, Sha256Digest>()
                    .unwrap(),
                limits: IngressLimits::from_profile::<MinPk, _>(&observer_profile(&committee)),
                mailbox_size: NonZeroUsize::new(16).unwrap(),
                observation_capacity: NonZeroUsize::new(8).unwrap(),
            },
        );
        let (voter, Inbox { completions, .. }) = voter::Mailbox::<Ed25519PublicKey, _, _>::new(
            &context.child("voter"),
            context,
            NonZeroUsize::new(8).unwrap(),
        );
        let Endpoints {
            observations,
            completions: endpoint,
            ..
        } = voter.into_endpoints();
        let task = ingress.start(verifier, endpoint, observations, Silent, Silent, Silent);
        Self {
            committee,
            mailbox,
            completions,
            task,
            _credits: credits,
        }
    }
}

/// Waits up to one second for the shared ingress and verifier task to stop.
async fn stops(context: &DeterministicContext, mut task: Handle<()>) {
    let _ = expect_within(
        context,
        Duration::from_secs(1),
        &mut task,
        "the shared task kept running",
    )
    .await;
}

/// Drives the production Core until it issues the verification jobs for `artifacts`.
fn machine_issued_jobs(
    committee: &Committee<MinPk>,
    artifacts: Vec<Artifact<MinPk, Sha256Digest>>,
) -> Vec<VerifyJob<MinPk, Sha256Digest>> {
    machine_issued_jobs_for(committee, Role::Observer, Vec::new(), artifacts).1
}

/// Returns the role of `chain`'s producer, the one node that keeps the chain's DA votes.
fn producer_role(committee: &Committee<MinPk>, chain: u32) -> Role {
    Role::Validator(committee.config.producer(ChainId::new(chain)).unwrap())
}

/// Drives a production Core in `role` until it issues the verification jobs for `artifacts`, and
/// returns the Core that awaits their completions.
///
/// The Core first verifies `held` itself, such as the producer block a DA vote names.
fn machine_issued_jobs_for(
    committee: &Committee<MinPk>,
    role: Role,
    held: Vec<Artifact<MinPk, Sha256Digest>>,
    artifacts: Vec<Artifact<MinPk, Sha256Digest>>,
) -> (
    CoreState<Sha256, MinPk>,
    Vec<VerifyJob<MinPk, Sha256Digest>>,
) {
    let mut core = CoreState::fresh(profile(committee, role)).unwrap();
    core.enqueue(Input::Start).unwrap();
    let mut driver = CoreDriver::new(&committee.verifier);
    let jobs = if held.is_empty() {
        let mut driver = driver.holding_verifications();
        driver.settle_observing(&mut core, artifacts);
        driver.take_held()
    } else {
        driver.settle_observing(&mut core, held);
        let mut driver = driver.holding_verifications();
        driver.observe(&mut core, artifacts);
        driver.settle(&mut core);
        driver.take_held()
    };
    assert!(!jobs.is_empty(), "observation schedules verification");
    (core, jobs)
}

#[test_traced]
fn executes_machine_issued_jobs_with_exact_tickets() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut harness = Harness::new(&context, 33, Sequential, Sequential);
        let committee = &harness.committee;

        let good_block = committee.signed_block(ChainId::new(0), Sha256::hash(&[b"good"]));
        let header = good_block.header().clone();
        let forged = SignedTransactionBlock::new(
            committee.transaction_header(ChainId::new(0), Sha256::hash(&[b"forged"])),
            good_block.attestation().clone(),
        );
        let artifacts = vec![
            Artifact::DaVote(committee.da_vote(Participant::new(1), header)),
            Artifact::NoVote(committee.novote(Participant::new(2), View::new(1))),
            Artifact::TransactionBlock(forged),
        ];

        // Drive the production Core boundary until it issues the verification job. The DA vote
        // reaches chain 0's producer, which already verified the block it names.
        let (mut core, jobs) = machine_issued_jobs_for(
            committee,
            producer_role(committee, 0),
            vec![Artifact::TransactionBlock(good_block)],
            artifacts,
        );

        let expected = jobs.iter().map(|job| job.items().len()).sum::<usize>();
        for job in jobs {
            assert!(
                harness
                    .mailbox
                    .verify(
                        Span::none(),
                        Round::new(Epoch::new(33), View::new(1)),
                        job,
                        context.current()
                    )
                    .accepted()
            );
        }

        let mut valid = 0;
        let mut invalid = 0;
        let mut items = 0;
        while items < expected {
            let Completed { completion, .. } =
                harness.completions.recv().await.expect("verifier running");
            items += completion.verdicts().len();
            core.enqueue(Input::Verified(completion)).unwrap();
            let status = loop {
                match core.next_action(|_| {}).unwrap() {
                    CoreTurn::Input(serviced) => break serviced.transition.status().clone(),
                    CoreTurn::Work(_) => {}
                    CoreTurn::YieldRequired => core.resume_after_yield().unwrap(),
                    CoreTurn::Idle => panic!("Core idled before accepting verification"),
                }
            };
            let StepStatus::Verified {
                valid: step_valid,
                invalid: step_invalid,
            } = status
            else {
                panic!("verification completion was not accepted: {status:?}");
            };
            valid += step_valid;
            invalid += step_invalid;
        }
        assert_eq!(valid, 2);
        assert_eq!(invalid, 1);
        let encoded = context.encode();
        assert!(
            encoded
                .lines()
                .any(|line| line.starts_with("batcher_verified_vote_lag_count ")
                    && !line.ends_with(" 0")),
            "valid votes did not record their lag behind the verifying round: {encoded}"
        );
        // Per-participant series scale as the validator count per node.
        assert!(
            !encoded.contains("batcher_latest_verified_vote"),
            "the per-participant vote gauge family is still registered: {encoded}"
        );
    });
}

/// Submits `jobs` and waits for a verdict on every item, panicking with `stalled` otherwise.
async fn verdicts_arrive(
    context: &DeterministicContext,
    harness: &mut Harness,
    jobs: Vec<VerifyJob<MinPk, Sha256Digest>>,
    stalled: &str,
) {
    let round = Round::new(harness.committee.config.epoch(), View::new(1));
    let mut expected = 0;
    for job in jobs {
        expected += job.items().len();
        assert!(
            harness
                .mailbox
                .verify(Span::none(), round, job, context.current())
                .accepted()
        );
    }
    let completions = &mut harness.completions;
    expect_within(
        context,
        Duration::from_secs(1),
        async move {
            let mut items = 0;
            while items < expected {
                let Completed { completion, .. } =
                    completions.recv().await.expect("verifier running");
                items += completion.verdicts().len();
            }
        },
        stalled,
    )
    .await;
}

#[test_traced]
fn view_critical_and_bulk_jobs_run_on_their_own_pools() {
    // Each phase gives the other pool no workers, so a job routed to it never completes. The
    // production Core issues the jobs, so the classification under test is the machine's.
    let idle = || mocks::pending(NonZeroUsize::new(2).unwrap());
    DeterministicRunner::default().start(|context| async move {
        let mut harness = Harness::new(&context, 61, idle(), Sequential);
        let novote = Artifact::NoVote(harness.committee.novote(Participant::new(2), View::new(1)));
        let jobs = machine_issued_jobs(&harness.committee, vec![novote]);
        assert!(
            jobs.iter().all(VerifyJob::view_critical),
            "a novote is view progress"
        );
        verdicts_arrive(
            &context,
            &mut harness,
            jobs,
            "a view-critical job queued behind bulk verification",
        )
        .await;
    });
    DeterministicRunner::default().start(|context| async move {
        let mut harness = Harness::new(&context, 61, Sequential, idle());
        let block = Artifact::TransactionBlock(
            harness
                .committee
                .signed_block(ChainId::new(0), Sha256::hash(&[b"bulk header"])),
        );
        let jobs = machine_issued_jobs(&harness.committee, vec![block]);
        assert!(
            !jobs.iter().any(VerifyJob::view_critical),
            "a transaction-block header is not view progress"
        );
        verdicts_arrive(
            &context,
            &mut harness,
            jobs,
            "a bulk job occupied the view-critical pool",
        )
        .await;
    });
}

#[test_traced]
fn an_invalid_da_share_is_admitted_and_keeps_its_sender() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut harness = Harness::new(&context, 52, Sequential, Sequential);
        let committee = &harness.committee;

        // A share signed over a different header is structurally perfect and cryptographically
        // wrong. Admission must not pay a pairing to discover that: threshold recovery checks
        // the whole quorum with one, and only then attributes the shares.
        let elsewhere = committee.da_vote(
            Participant::new(1),
            committee.transaction_header(ChainId::new(0), Sha256::hash(&[b"elsewhere"])),
        );
        let invalid = DaVote::new(
            committee.transaction_header(ChainId::new(0), Sha256::hash(&[b"subject"])),
            elsewhere.share().clone(),
        );
        let subject = committee.signed_block(ChainId::new(0), Sha256::hash(&[b"subject"]));
        let (_, jobs) = machine_issued_jobs_for(
            committee,
            producer_role(committee, 0),
            vec![Artifact::TransactionBlock(subject)],
            vec![Artifact::DaVote(invalid)],
        );
        let expected = jobs.iter().map(|job| job.items().len()).sum::<usize>();
        assert_eq!(expected, 1, "the cohort holds exactly the one share");
        for job in jobs {
            assert!(
                harness
                    .mailbox
                    .verify(
                        Span::none(),
                        Round::new(Epoch::new(52), View::new(1)),
                        job,
                        context.current()
                    )
                    .accepted()
            );
        }
        let Completed { completion, .. } =
            harness.completions.recv().await.expect("verifier running");
        assert_eq!(
            completion
                .verdicts()
                .iter()
                .map(|verdict| verdict.valid())
                .collect::<Vec<_>>(),
            vec![true],
        );
    });
}

#[test_traced]
fn closing_the_job_mailbox_stops_the_shared_task() {
    DeterministicRunner::default().start(|context| async move {
        let Harness {
            mailbox,
            completions: _completions,
            task,
            _credits,
            ..
        } = Harness::new(&context, 71, Sequential, Sequential);
        drop(mailbox);
        stops(&context, task).await;
    });
}

#[test_traced]
fn a_closed_voter_completion_path_stops_the_shared_task() {
    DeterministicRunner::default().start(|context| async move {
        let Harness {
            committee,
            mailbox,
            completions,
            task,
            _credits,
        } = Harness::new(&context, 72, Sequential, Sequential);
        drop(completions);
        let round = Round::new(committee.config.epoch(), View::new(1));
        for job in machine_issued_jobs(
            &committee,
            vec![Artifact::NoVote(
                committee.novote(Participant::new(2), View::new(1)),
            )],
        ) {
            assert!(
                mailbox
                    .verify(Span::none(), round, job, context.current())
                    .accepted()
            );
        }
        stops(&context, task).await;
    });
}

fn observer_profile(committee: &Committee<MinPk>) -> Profile<Sha256Digest> {
    profile(committee, Role::Observer)
}

fn profile(committee: &Committee<MinPk>, role: Role) -> Profile<Sha256Digest> {
    Profile::new::<MinPk>(
        committee.config.clone(),
        role,
        Tuning {
            view_timeout: Duration::from_secs(1),
            production_interval: Duration::from_millis(100),
            ..Tuning::default()
        },
    )
    .unwrap()
}
