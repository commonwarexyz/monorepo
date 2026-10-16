//! Deterministic tests of the verifier served by its ingress task.

use super::{Config, Mailbox, Verifier};
use crate::{
    Epochable as _,
    multimmit::{
        actors::{
            ingress::{self, IngressLimits},
            voter::{self, Completed},
        },
        machine::{
            Generation, Issued, JobId, Observation, VerificationCompletion, VerificationItem,
            VerificationTicket, VerifyJob,
        },
        mocks::Committee,
        testing::expect_within,
        types::{
            Artifact, ChainId, Lqc, SignedLeaderBlock, SignedTransactionBlock, VoteContent,
            VoteUpdate, Vqc,
        },
    },
    types::{Participant, Round, View},
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
    Clock as _, Handle, IoBuf, Runner as _, Supervisor as _,
    deterministic::{Context as DeterministicContext, Runner as DeterministicRunner},
};
use std::{
    collections::BTreeMap, convert::Infallible, future::pending, num::NonZeroUsize, sync::Arc,
    time::Duration,
};
use tracing::Span;

mod unit;

type TestArtifact = Artifact<MinPk, Sha256Digest>;
type TestJob = VerifyJob<MinPk, Sha256Digest>;

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

/// Builds job `id` over `artifacts` in order, attaching each vote update's rebuilt
/// content.
fn job(id: u64, artifacts: Vec<(TestArtifact, Option<VoteContent<Sha256Digest>>)>) -> TestJob {
    let job = JobId::new(id);
    let items = artifacts
        .into_iter()
        .enumerate()
        .map(|(index, (artifact, content))| {
            let ticket = VerificationTicket::new(
                job,
                artifact.id::<Sha256>(),
                Observation::new(id, index as u32),
            );
            let artifact = Arc::new(artifact);
            match content {
                Some(content) => VerificationItem::update(ticket, artifact, Arc::new(content)),
                None => VerificationItem::new(ticket, artifact),
            }
        })
        .collect();
    VerifyJob::new(Issued::new(job, Generation::new(0)), items)
}

/// `signer`'s first update in `view` with the content it signs, as a job item.
fn update(
    committee: &Committee<MinPk>,
    signer: u32,
    view: View,
) -> (TestArtifact, Option<VoteContent<Sha256Digest>>) {
    (
        Artifact::Update(committee.genesis_update(Participant::new(signer), view)),
        Some(committee.genesis_content(view)),
    )
}

struct Harness {
    committee: Committee<MinPk>,
    mailbox: Mailbox<MinPk, Sha256Digest>,
    completions: mailbox::Receiver<Completed<Sha256Digest>>,
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
                context.child("verifier"),
                Config {
                    scheme: committee.verifier.clone(),
                    strategy: strategy.clone(),
                    critical_strategy: critical_strategy.clone(),
                    inflight_jobs: NonZeroUsize::new(2).unwrap(),
                    mailbox_size: NonZeroUsize::new(16).unwrap(),
                },
            );
        let (ingress, credits) = ingress::Actor::new(
            context.child("ingress"),
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
                limits: IngressLimits::TEST,
                mailbox_size: NonZeroUsize::new(16).unwrap(),
                observation_capacity: NonZeroUsize::new(8).unwrap(),
            },
        );
        let voter_context = context.child("voter");
        let (voter, inbox) = voter::Mailbox::<MinPk, Sha256Digest>::new(
            &voter_context,
            context,
            NonZeroUsize::new(8).unwrap(),
            NonZeroUsize::new(8).unwrap(),
        );
        let completions = inbox.completions;
        let voter::Mailbox {
            observations,
            completions: endpoint,
            ..
        } = voter;
        let task = ingress.start(verifier, endpoint, observations, Silent, Silent, Silent);
        Self {
            committee,
            mailbox,
            completions,
            task,
            _credits: credits,
        }
    }

    /// Submits `jobs` issued in `view` and returns their completions keyed by job, panicking
    /// with `stalled` unless every one arrives within a second.
    async fn complete(
        &mut self,
        context: &DeterministicContext,
        view: View,
        jobs: &[TestJob],
        stalled: &str,
    ) -> BTreeMap<JobId, VerificationCompletion<Sha256Digest>> {
        let round = Round::new(self.committee.config.epoch(), view);
        for job in jobs {
            assert!(
                self.mailbox
                    .verify(Span::none(), round, job.clone(), context.current())
                    .accepted()
            );
        }
        let completions = &mut self.completions;
        expect_within(
            context,
            Duration::from_secs(1),
            async move {
                let mut done = BTreeMap::new();
                while done.len() < jobs.len() {
                    let Completed { completion, .. } =
                        completions.recv().await.expect("verifier running");
                    done.insert(completion.issued().id(), completion);
                }
                done
            },
            stalled,
        )
        .await
    }
}

/// Returns the verdict of every item of `job` after checking that `completion` answers exactly its
/// tickets, in item order.
fn verdicts(job: &TestJob, completion: &VerificationCompletion<Sha256Digest>) -> Vec<bool> {
    assert_eq!(completion.issued(), job.issued());
    let tickets = completion
        .verdicts()
        .iter()
        .map(|verdict| verdict.ticket())
        .collect::<Vec<_>>();
    let expected = job
        .items()
        .iter()
        .map(VerificationItem::ticket)
        .collect::<Vec<_>>();
    assert_eq!(tickets, expected);
    completion
        .verdicts()
        .iter()
        .map(|verdict| verdict.valid())
        .collect()
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

#[test_traced]
fn executes_jobs_with_exact_tickets_in_order() {
    DeterministicRunner::default().start(|context| async move {
        let mut harness = Harness::new(&context, 33, Sequential, Sequential);
        let committee = &harness.committee;
        let view = View::new(1);
        let critical = job(
            0,
            vec![
                (Artifact::LeaderBlock(committee.leader_block(view)), None),
                update(committee, 1, view),
                (Artifact::Vqc(committee.vqc(view)), None),
                (Artifact::Lqc(committee.lqc(view)), None),
            ],
        );
        let bulk = job(
            1,
            vec![
                (
                    Artifact::TransactionBlock(committee.genesis_child(ChainId::new(0), b"first")),
                    None,
                ),
                (
                    Artifact::TransactionBlock(committee.genesis_child(ChainId::new(1), b"second")),
                    None,
                ),
            ],
        );
        let jobs = [critical, bulk];

        let completions = harness
            .complete(&context, view, &jobs, "a job did not complete")
            .await;

        for job in &jobs {
            let valid = verdicts(job, &completions[&job.issued().id()]);
            assert!(valid.iter().all(|valid| *valid), "{valid:?}");
        }
    });
}

#[test_traced]
fn invalid_items_do_not_fail_valid_neighbours() {
    DeterministicRunner::default().start(|context| async move {
        let mut harness = Harness::new(&context, 34, Sequential, Sequential);
        let committee = &harness.committee;
        let view = View::new(3);
        let next = View::new(4);

        // Each forgery pairs a well-formed subject with a signature over a different one.
        let header = committee.genesis_child(ChainId::new(1), b"header");
        let stolen = SignedTransactionBlock::new(
            committee.header(&committee.genesis().tips()[2], Sha256::hash(&[b"stolen"])),
            header.attestation().clone(),
        );
        let leader = committee.leader_block(view);
        let unscheduled = SignedLeaderBlock::new(
            leader.block().clone(),
            committee.leader_block(next).attestation().clone(),
        );
        let vqc = committee.vqc(view);
        let forged_vqc = Vqc::new(
            vqc.round(),
            vqc.parent(),
            vqc.tally().clone(),
            committee.vqc(next).signature().unwrap().clone(),
            committee.codec(),
        )
        .unwrap();
        let lqc = committee.lqc(view);
        let forged_lqc = Lqc::new(
            lqc.leader().clone(),
            lqc.tally().clone(),
            committee.lqc(next).signature().unwrap().clone(),
        );
        let job = job(
            0,
            vec![
                (Artifact::TransactionBlock(header), None),
                (Artifact::TransactionBlock(stolen), None),
                (Artifact::LeaderBlock(leader), None),
                (Artifact::LeaderBlock(unscheduled), None),
                (Artifact::Vqc(vqc), None),
                (Artifact::Vqc(forged_vqc), None),
                (Artifact::Lqc(lqc), None),
                (Artifact::Lqc(forged_lqc), None),
            ],
        );

        let completions = harness
            .complete(
                &context,
                view,
                std::slice::from_ref(&job),
                "the job did not complete",
            )
            .await;

        assert_eq!(
            verdicts(&job, &completions[&job.issued().id()]),
            [true, false, true, false, true, false, true, false],
        );
    });
}

#[test_traced]
fn an_invalid_update_is_reported_without_affecting_other_items() {
    DeterministicRunner::default().start(|context| async move {
        let mut harness = Harness::new(&context, 52, Sequential, Sequential);
        let committee = &harness.committee;
        let view = View::new(1);

        // The update is structurally perfect, and its attestation is a genuine signature by its
        // signer, but over final content the update does not claim.
        let (_, content) = update(committee, 2, view);
        let content = content.unwrap();
        let other = committee.content(view, None, true, committee.genesis_endorsement());
        let signed = committee.update(Participant::new(2), &other, committee.genesis().tips(), 1);
        let invalid = VoteUpdate::new(
            content.round(),
            content.leader(),
            content.is_final(),
            content.declared().clone(),
            signed.seq(),
            signed.changes().to_vec(),
            signed.attestation().clone(),
            committee.codec(),
        )
        .unwrap();
        let job = job(
            0,
            vec![
                update(committee, 1, view),
                (Artifact::Update(invalid), Some(content)),
                update(committee, 3, view),
            ],
        );

        let completions = harness
            .complete(
                &context,
                View::new(4),
                std::slice::from_ref(&job),
                "the job did not complete",
            )
            .await;

        assert_eq!(
            verdicts(&job, &completions[&job.issued().id()]),
            [true, false, true]
        );
    });
}

#[test_traced]
fn view_critical_and_bulk_jobs_run_on_their_own_pools() {
    // Each phase gives the other pool no workers, so a job routed to it never completes.
    let idle = || mocks::pending(NonZeroUsize::new(2).unwrap());
    DeterministicRunner::default().start(|context| async move {
        let mut harness = Harness::new(&context, 61, idle(), Sequential);
        let view = View::new(1);
        let critical = job(0, vec![update(&harness.committee, 2, view)]);
        assert!(critical.view_critical(), "a vote update is view progress");
        harness
            .complete(
                &context,
                view,
                &[critical],
                "a view-critical job queued behind bulk verification",
            )
            .await;
    });
    DeterministicRunner::default().start(|context| async move {
        let mut harness = Harness::new(&context, 61, Sequential, idle());
        let bulk = job(
            0,
            vec![(
                Artifact::TransactionBlock(
                    harness
                        .committee
                        .genesis_child(ChainId::new(0), b"bulk header"),
                ),
                None,
            )],
        );
        assert!(
            !bulk.view_critical(),
            "a transaction-block header is not view progress"
        );
        let lqc = job(
            1,
            vec![(Artifact::Lqc(harness.committee.lqc(View::new(1))), None)],
        );
        assert!(!lqc.view_critical(), "an L-QC gates no view");
        harness
            .complete(
                &context,
                View::new(1),
                &[bulk, lqc],
                "a bulk job occupied the view-critical pool",
            )
            .await;
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
        let view = View::new(1);
        let job = job(0, vec![update(&committee, 2, view)]);
        assert!(
            mailbox
                .verify(
                    Span::none(),
                    Round::new(committee.config.epoch(), view),
                    job,
                    context.current()
                )
                .accepted()
        );
        stops(&context, task).await;
    });
}
