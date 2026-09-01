//! Voter actor tests over its inputs, scheduling, and crypto dispatch, without a network.

use super::{
    ChainUpdate, Fatal, Planes, TestEvent, TestHooks,
    app::AppExecutor,
    chains::ChainTasks,
    crypto::{CryptoExecutor, CryptoOutcome},
    live::Live,
    persist::{Ledger, Persistence},
    record_fatal,
    sources::{Arm, ObservedBatch, Probe, ReadinessCursor, RuntimeEvent, Source},
    timers::Timers,
    verification::VerificationQueue,
};
use crate::{
    Epochable as _,
    multimmit::{
        actors::{
            ingress, resolver,
            util::offload,
            verifier::{self, verify},
            voter::{
                VoterLimits, blocked_counter,
                da_recovery::DaUpdate,
                egress::Egress,
                mailbox::{Completed, Endpoints, Mailbox, Observed},
                persistence::{self, CheckpointOrigin, Output, checkpoint_span},
                tasks::{TaskClass, TaskLimits, TaskReservations},
                telemetry::{Correlation, PeerActivity, Telemetry, TraceContext, metrics::Metrics},
            },
        },
        config::{Profile, Role, Tuning},
        machine::{
            Capability, ChainCommand, CoreState, CoreTurn, Cursor, DaVotesOffer, DurableEffect,
            EffectCompletion, EffectId, Generation, Input, Issued, JobId, Lane, Observation,
            TimerCommand, VerificationItem, VerificationTicket, VerifyJob,
        },
        mocks::{Committee, MockApplication, RecordingRelay, RecordingReporter},
        scheme::bls12381_threshold::Error as SchemeError,
        storage::{Recovered, RecoveryConfig, recover},
        types::{Artifact, ChainId, TransactionBlockHeader},
        wire::Plane,
    },
    types::{Epoch, Height, Participant, View},
};
use commonware_actor::mailbox;
use commonware_codec::EncodeSize as _;
use commonware_cryptography::{
    Hasher as _, Sha256, bls12381::primitives::variant::MinPk, ed25519,
    sha256::Digest as Sha256Digest,
};
use commonware_macros::test_traced;
use commonware_p2p::{
    Sender,
    utils::mocks::{NoopBlocker, inert_channel},
};
use commonware_parallel::{Rayon, Sequential};
use commonware_runtime::{
    Clock as _, Metrics as _, Runner as _, Spawner as _, Supervisor as _,
    buffer::paged::{self, CacheRef},
    deterministic,
    telemetry::traces::collector::{CollectingLayer, TraceStorage},
    tokio,
    utils::reschedule,
};
use commonware_utils::{
    NZU64,
    channel::oneshot,
    sync::{Condvar, Mutex},
    test_rng,
};
use futures::{FutureExt as _, future::poll_fn};
use std::{
    collections::{BTreeMap, VecDeque},
    future::pending,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tracing::{Id, Instrument as _, Span, Subscriber, debug_span, info, info_span};
use tracing_subscriber::{Layer, layer::Context as LayerContext, prelude::*, registry::LookupSpan};

#[test]
fn observed_batches_merge_ready_cohorts_within_pool_bounds() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(81, 6).build();
        let critical = Artifact::LeaderBlock(committee.leader_block(View::new(1)));
        let bulk = Artifact::TransactionBlock(
            committee.signed_block(ChainId::new(0), Sha256::hash(&[b"coalesced body"])),
        );
        let (sender, mut receiver) = mailbox::new_unreliable(
            context.child("observations"),
            NonZeroUsize::new(16).unwrap(),
        );
        let shapes = [
            (true, 1),
            (true, 1),
            (false, 8),
            (false, 8),
            (true, 3),
            (true, 2),
            (true, 2),
            (true, 5),
            (true, 1),
            (false, 6),
            (false, 6),
            (false, 6),
        ];
        let mut expected = Vec::new();
        for (index, (view_critical, count)) in shapes.into_iter().enumerate() {
            let artifact = if view_critical { &critical } else { &bulk };
            let artifacts = vec![
                (
                    committee.identities[index % committee.identities.len()].clone(),
                    artifact.clone().identify::<Sha256>(&mut Vec::new()),
                );
                count
            ];
            expected.extend(artifacts.clone());
            assert!(
                sender
                    .enqueue(Observed {
                        artifacts,
                        span: Span::none(),
                        forwarded_at: context.current() + Duration::from_millis(16 - index as u64),
                        bytes: artifact.encode_size() * count,
                        plane: if view_critical {
                            Plane::Consensus
                        } else {
                            Plane::Data
                        },
                    })
                    .accepted()
            );
        }

        let mut carried = None;
        let mut received = Vec::new();
        for (items, cohorts, last, has_remainder) in [
            (2, 2, 1, true),
            (16, 2, 3, false),
            (3, 1, 4, true),
            (4, 2, 6, false),
            (5, 1, 7, false),
            (1, 1, 8, true),
            (12, 2, 10, true),
            (6, 1, 11, false),
        ] {
            let next = carried
                .take()
                .unwrap_or_else(|| receiver.try_recv().unwrap());
            let (batch, remainder) =
                ObservedBatch::drain(next, &mut receiver, 16, VIEW_COHORT_ITEMS.get());
            assert_eq!(batch.artifacts.len(), items);
            assert_eq!(batch.cohorts, cohorts);
            assert_eq!(batch.spans.len(), cohorts);
            assert_eq!(remainder.is_some(), has_remainder);
            assert_eq!(
                batch.forwarded_at,
                context.current() + Duration::from_millis(16 - last)
            );
            assert_eq!(
                batch.bytes,
                batch
                    .artifacts
                    .iter()
                    .map(|(_, identified)| identified.artifact.encode_size())
                    .sum::<usize>()
            );
            received.extend(batch.artifacts);
            carried = remainder;
        }
        assert_eq!(received, expected);
        assert!(carried.is_none());
        assert!(receiver.try_recv().is_err());
    });
}

#[test]
fn observed_batches_keep_parent_proposal_groups_atomic() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(82, 6).build();
        let parent = committee.vqc(View::new(1));
        let proposal = committee.leader_block_with_parent(View::new(2), &parent);
        let pair = vec![Artifact::Vqc(parent), Artifact::LeaderBlock(proposal)];
        let singleton = Artifact::Nullification(committee.nullification(View::new(1)));
        for (label, prefix, max_items, expected_batches) in [
            ("merged", 1, 16, vec![(3, 2)]),
            ("carried", 3, 16, vec![(3, 1), (2, 1)]),
            ("configured_bound", 1, 2, vec![(1, 1), (2, 1)]),
        ] {
            let (sender, mut receiver) =
                mailbox::new_unreliable(context.child(label), NonZeroUsize::new(2).unwrap());
            let mut expected = Vec::new();
            for (plane, artifacts) in [
                (Plane::Certificate, vec![singleton.clone(); prefix]),
                (Plane::Consensus, pair.clone()),
            ] {
                let bytes = artifacts.iter().map(Artifact::encoded_len).sum();
                let artifacts = artifacts
                    .into_iter()
                    .map(|artifact| {
                        (
                            committee.identities[0].clone(),
                            artifact.identify::<Sha256>(&mut Vec::new()),
                        )
                    })
                    .collect::<Vec<_>>();
                expected.extend(artifacts.clone());
                assert!(
                    sender
                        .enqueue(Observed {
                            artifacts,
                            bytes,
                            plane,
                            span: Span::none(),
                            forwarded_at: context.current(),
                        })
                        .accepted()
                );
            }
            let mut carried = None;
            let mut received = Vec::new();
            for (items, cohorts) in expected_batches {
                let first = carried
                    .take()
                    .unwrap_or_else(|| receiver.try_recv().unwrap());
                let (batch, remainder) =
                    ObservedBatch::drain(first, &mut receiver, max_items, VIEW_COHORT_ITEMS.get());
                assert_eq!(batch.artifacts.len(), items);
                assert_eq!(batch.cohorts, cohorts);
                assert_eq!(batch.spans.len(), cohorts);
                assert_eq!(
                    batch.bytes,
                    batch
                        .artifacts
                        .iter()
                        .map(|(_, identified)| identified.artifact.encoded_len())
                        .sum::<usize>()
                );
                received.extend(batch.artifacts);
                carried = remainder;
            }
            assert_eq!(received, expected);
            assert!(carried.is_none());
            assert!(receiver.try_recv().is_err());
        }
    });
}

#[test]
fn ready_persistence_successor_enters_the_ongoing_core_cycle() {
    ready_runtime_source_between_actions(RuntimeSourceScenario::Persistence);
}

#[test]
fn ready_heartbeat_is_serviced_between_component_quanta() {
    ready_runtime_source_between_actions(RuntimeSourceScenario::Heartbeat);
}

#[test]
fn released_signing_is_submitted_before_completion_poll() {
    ready_runtime_source_between_actions(RuntimeSourceScenario::Signing);
}

#[test]
fn closed_persistence_output_with_outstanding_appends_is_fatal() {
    ready_runtime_source_between_actions(RuntimeSourceScenario::PersistenceClosed);
}

#[test]
fn chain_updates_from_another_generation_are_stale() {
    ready_runtime_source_between_actions(RuntimeSourceScenario::ChainUpdates);
}

#[test]
fn blocking_wait_admits_ready_inputs_in_priority_order() {
    ready_runtime_source_between_actions(RuntimeSourceScenario::WaitPriority);
}

#[test]
fn critical_verification_dispatches_under_bulk_permit_saturation() {
    ready_runtime_source_between_actions(RuntimeSourceScenario::Verification);
}

#[test]
fn verification_trace_uses_owning_round_at_info_level() {
    for unrelated_ambient in [false, true] {
        let traces = TraceStorage::default();
        let subscriber = tracing_subscriber::registry()
            .with(CollectingLayer::new(traces.clone()))
            .with(tracing_subscriber::filter::LevelFilter::INFO);
        tracing::subscriber::with_default(subscriber, || {
            let ambient = if unrelated_ambient {
                info_span!(parent: None, "test.unrelated_round")
            } else {
                Span::none()
            };
            ambient.in_scope(|| {
                ready_runtime_source_between_actions(RuntimeSourceScenario::Verification);
            });
        });
        let events = traces.get_by_level(tracing::Level::INFO);
        let event = events
            .iter()
            .find(|event| event.metadata.content == "verification dispatched")
            .expect("verification reached its verifier message");
        let parents: Vec<_> = event
            .spans
            .iter()
            .map(|span| span.content.as_str())
            .collect();
        assert_eq!(
            parents,
            ["multimmit.voter.verify", "test.verification_round"],
            "verification must use its supplied root; unrelated ambient: {unrelated_ambient}"
        );
    }
}

enum RuntimeSourceScenario {
    PersistenceClosed,
    ChainUpdates,
    WaitPriority,
    Verification,
    Persistence,
    Heartbeat,
    Signing,
}

/// Waits until the persistence actor under `journal` has reported `expected` durable barriers.
async fn wait_for_durable_barriers(context: &deterministic::Context, expected: usize) {
    let sample = |encoded: String| {
        encoded
            .lines()
            .find_map(|line| line.strip_prefix("journal_durable_barriers_total "))
            .map(|value| value.parse::<usize>().unwrap())
    };
    for _ in 0..1024 {
        if sample(context.encode()) == Some(expected) {
            return;
        }
        reschedule().await;
    }
    assert_eq!(
        sample(context.encode()),
        Some(expected),
        "appends did not become durable"
    );
}

type TestTypes = (
    deterministic::Context,
    Sha256,
    ed25519::PublicKey,
    MinPk,
    MockApplication,
    RecordingRelay<Sha256Digest, ed25519::PublicKey>,
    RecordingReporter<MinPk, Sha256Digest>,
    Sequential,
    Sequential,
    NoopBlocker<ed25519::PublicKey>,
    TestHooks<MinPk, Sha256Digest>,
);

/// Drives the core and the persistence pipeline until neither has work left.
async fn settle<S: Sender<PublicKey = ed25519::PublicKey>>(driver: &mut Live<TestTypes, S>) {
    loop {
        while driver.machine.has_runnable_work() {
            driver.drive_core_cycle().await.unwrap();
        }
        if driver.persistence.ledger().outstanding() == 0 {
            return;
        }
        driver.persistence.flush().unwrap();
        let output = driver.persistence.output().recv().await.unwrap();
        driver.persisted(output).unwrap();
    }
}

/// Artifacts in one view-critical observation batch.
const VIEW_COHORT_ITEMS: NonZeroUsize = NonZeroUsize::new(4).unwrap();

fn ready_runtime_source_between_actions(scenario: RuntimeSourceScenario) {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
        let committee = Committee::<MinPk>::builder(87, 6).build();
        let profile = Profile::new::<MinPk>(
            committee.config.clone(),
            Role::Validator(Participant::new(0)),
            Tuning::default(),
        )
        .unwrap();
        let mut store_context = context.child("stores");
        let Recovered {
            core: mut machine,
            journal,
            checkpoints,
            replayed: None,
        } = Box::pin(recover(
            &mut store_context,
            RecoveryConfig {
                profile,
                partition_prefix: "ready_successor",
                scheme: &committee.verifier,
                strategy: &Sequential,
                page_cache: CacheRef::from_pooler(
                    &context,
                    paged::page_size(4096),
                    NonZeroUsize::new(8).unwrap(),
                ),
                checkpoint_interval: NZU64!(1_000_000),
                inflight_application: NonZeroUsize::new(4).unwrap(),
            },
            &MockApplication::new(),
        ))
        .await
        .unwrap()
        else {
            panic!("fresh stores");
        };
        let capacity = NonZeroUsize::new(64).unwrap();
        let (output, mut persisted) = mailbox::new(context.child("persisted"), capacity);
        let (actor, journal) = persistence::Actor::new(
            context.child("journal"),
            persistence::Config {
                journal,
                checkpoints,
                capacity,
                output,
                snapshot_tasks: context.child("snapshots"),
                flushes: persistence::Flushes::default(),
                hooks: persistence::NoHooks,
            },
        );
        let persistence_task = actor.start();

        // Issue real barriers without delivering their responses back to Core.
        let mut held_signing = None;
        let mut collect = |machine: &mut CoreState<Sha256, MinPk>| {
            let mut jobs = Vec::new();
            loop {
                let capabilities = match machine.next_action(|_| {}).unwrap() {
                    CoreTurn::Input(input) => input.transition.into_parts().0,
                    CoreTurn::Work(work) => work.capabilities,
                    CoreTurn::YieldRequired => {
                        machine.resume_after_yield().unwrap();
                        continue;
                    }
                    CoreTurn::Idle => break,
                };
                let mut released = Vec::new();
                for capability in capabilities {
                    match capability {
                        Capability::Journal(directive) => {
                            let (job, after_enqueue) = (directive.job, directive.release_after_enqueue);
                            jobs.push(job);
                            released.extend(after_enqueue);
                        }
                        Capability::Released(job) => {
                            released.push(job);
                        }
                        Capability::Timer(TimerCommand::View(timer)) => {
                            machine.enqueue(Input::TimerFired(timer)).unwrap();
                        }
                        Capability::Verify(job) => {
                            let completion = verify::<Sha256, _, _>(
                                &job,
                                &mut test_rng(),
                                &committee.verifier,
                                &Sequential,
                            );
                            machine.enqueue(Input::Verified(completion)).unwrap();
                        }
                        _ => {}
                    }
                }
                for job in released {
                    if matches!(scenario, RuntimeSourceScenario::Signing)
                        && held_signing.is_none()
                        && matches!(job.request(), DurableEffect::Sign(_))
                    {
                        held_signing = Some(job);
                        continue;
                    }
                    match job.request().sign_requests() {
                        Some([request]) => {
                            let artifact = request.sign(&committee.signers[0]).unwrap();
                            machine
                                .enqueue(Input::EffectCompleted(EffectCompletion::signed(job.issued(), vec![Arc::new(artifact)])))
                                .unwrap();
                        }
                        Some(requests) => {
                            let artifacts = requests
                                .iter()
                                .map(|request| Arc::new(request.sign(&committee.signers[0]).unwrap()))
                                .collect();
                            machine
                                .enqueue(Input::EffectCompleted(EffectCompletion::signed(job.issued(), artifacts)))
                                .unwrap();
                        }
                        None => {}
                    }
                }
            }
            jobs
        };
        machine.enqueue(Input::Start).unwrap();
        let mut startup = VecDeque::from(collect(&mut machine));
        let mut startup_barriers = 0;
        while let Some(job) = startup.pop_front() {
            journal.append(Span::none(), Span::none(), job).unwrap();
            journal.flush().unwrap();
            let Some(Output::Durable(durable)) = persisted.recv().await else {
                panic!("the startup barrier becomes durable");
            };
            startup_barriers += 1;
            machine.enqueue(Input::Persisted(durable.ack)).unwrap();
            startup.extend(collect(&mut machine));
        }
        let limits = VoterLimits {
            retry_initial: Duration::from_millis(100),
            retry_ceiling: Duration::from_millis(400),
            heartbeat: Duration::from_secs(3600),
            checkpoint_interval: NZU64!(1_000_000),
            skip_timeout: None,
            view_cohort_items: VIEW_COHORT_ITEMS,
        };
        let (ingress, _ingress_rx) =
            mailbox::new(context.child("ingress"), NonZeroUsize::new(64).unwrap());
        let (verifier, mut verifier_rx) =
            mailbox::new(context.child("verifier"), NonZeroUsize::new(64).unwrap());
        let (resolver, _resolver_rx) =
            mailbox::new(context.child("resolver"), NonZeroUsize::new(64).unwrap());
        let (queries, _queries_rx) =
            mailbox::new_unreliable(context.child("queries"), NonZeroUsize::new(64).unwrap());
        let (voter, inbox) = Mailbox::new(&context.child("inbox"), &context, NonZeroUsize::new(4).unwrap());
        // Every endpoint stays alive so no queue closes during the test.
        let Endpoints {
            observations,
            completions,
            resolutions: _resolutions,
            inspector: _inspector,
        } = voter.into_endpoints();
        let (sender, _receiver) = inert_channel(&committee.identities);
        let hooks = TestHooks::default();
        let metrics = Metrics::new(&context.child("metrics"), committee.identities.len());
        let epoch = committee.config.epoch();
        let tasks = TaskReservations::new(
            machine.machine().generation(),
            TaskLimits::derive(machine.machine().profile()),
        )
        .unwrap();
        let mut driver: Live<TestTypes, _> = Live {
            context: context.child("driver"),
            tasks,
            epoch,
            leaders: machine.machine().profile().protocol().leaders().clone(),
            participant: Some(Participant::new(0)),
            limits,
            inbox,
            carried_observation: None,
            observation_batch: 8,
            pending_inspection: None,
            persistence: Persistence::new(
                journal,
                persisted,
                Ledger::new(0, limits.checkpoint_interval),
            ),
            crypto: CryptoExecutor::new(
                Arc::new(committee.signers[0].clone()),
                Sequential,
                context.child("crypto"),
                &metrics,
            ),
            app: AppExecutor::new(MockApplication::default(), epoch),
            verification: VerificationQueue::new(64),
            verification_tasks: BTreeMap::new(),
            timers: Timers::new(context.current() + Duration::from_secs(3600)),
            egress: Egress::new(epoch, limits.into()),
            relay: RecordingRelay::default(),
            planes: Planes {
                data: sender.clone(),
                consensus: sender.clone(),
                certificates: sender,
            },
            ingress: ingress::Mailbox::new(ingress),
            verifier: verifier::Mailbox::new(verifier),
            resolver: resolver::Mailbox::new(resolver, queries),
            blocker: NoopBlocker::default(),
            blocked: blocked_counter(&context),
            reporter: RecordingReporter::default(),
            chains: ChainTasks::default(),
            telemetry: Telemetry::new(metrics, epoch, machine.machine().view(), None),
            activity: PeerActivity::new(committee.identities.len(), None, None, 0),
            correlation: Correlation::default(),
            hooks: hooks.clone(),
            machine,
        };
        for view in 1..=3 {
            let artifact = Artifact::Nullification(committee.nullification(View::new(view)))
                .identify::<Sha256>(&mut Vec::new());
            let bytes = artifact.id.encode_size() + artifact.artifact.encode_size();
            driver.machine.observe(vec![artifact], bytes).unwrap();
            for job in collect(&mut driver.machine) {
                driver
                    .persistence
                    .append(Span::none(), Span::none(), job)
                    .unwrap();
            }
        }
        let appended = driver.persistence.ledger().outstanding();
        assert!(
            appended >= 3,
            "two completions and a FIFO readiness witness: got {appended}"
        );
        // The actor reports in append order. Once every append is durable, every result is
        // already queued without polling or consuming any of them.
        driver.persistence.flush().unwrap();
        wait_for_durable_barriers(&context, startup_barriers + appended).await;
        let Ok(Output::Durable(first)) = driver.persistence.output().try_recv() else {
            panic!("the first append is durable");
        };
        let first_ack = first.ack;
        if matches!(scenario, RuntimeSourceScenario::PersistenceClosed) {
            // The actor stops without reporting a failure while appends are outstanding.
            persistence_task.abort();
            for _ in 0..8 {
                reschedule().await;
            }
            while driver.persistence.output().try_recv().is_ok() {}
            assert!(driver.persistence.ledger().outstanding() > 0);
            let event =
                poll_fn(|cx| driver.poll_arm(Arm::Persistence, &mut Probe::Register(cx))).await;
            let Err((root, fatal)) = driver.handle_runtime_event(event) else {
                panic!("a closed persistence output is fatal");
            };
            assert!(matches!(
                fatal,
                Fatal::Persistence(persistence::Error::Closed)
            ));
            assert_eq!(root.id(), driver.round_span().id());
            return;
        }
        if matches!(scenario, RuntimeSourceScenario::ChainUpdates) {
            driver.persisted(Output::Durable(first)).unwrap();
            settle(&mut driver).await;
            let current = driver.tasks.generation();
            let other = Generation::new(current.get() + 1);
            let header = TransactionBlockHeader::new(
                epoch,
                ChainId::new(1),
                Height::new(1),
                Sha256::hash(&[b"parent"]),
                Sha256::hash(&[b"body"]),
            )
            .unwrap();
            let votes = (0..committee.codec().da_quorum())
                .map(|signer| committee.da_vote(Participant::from_usize(signer), header.clone()))
                .collect::<Vec<_>>();
            let certificate = committee
                .verifier
                .assemble_da_certificate(&votes, &Sequential)
                .unwrap();
            let offer = |generation| {
                ChainUpdate::DaVoteReady(DaVotesOffer {
                    generation,
                    chain: ChainId::new(1),
                    candidates: Vec::new(),
                    ready_through: Height::zero(),
                })
            };
            let recovered = |generation| {
                ChainUpdate::Recovered(DaUpdate {
                    generation,
                    block: header.block_ref::<Sha256>(),
                    certificate: certificate.clone(),
                })
            };

            let stale = driver.telemetry.metrics.stale.get();
            driver.chain_update(recovered(other)).unwrap();
            assert_eq!(driver.telemetry.metrics.stale.get(), stale + 1);
            assert!(
                !driver.machine.has_runnable_work(),
                "a certificate from another generation never reaches the machine"
            );
            driver.chain_update(offer(other)).unwrap();
            assert_eq!(driver.telemetry.metrics.stale.get(), stale + 2);
            assert!(
                !driver.machine.has_runnable_work(),
                "the machine rejects an offer from another generation"
            );
            driver.chain_update(offer(current)).unwrap();
            assert!(
                driver.machine.has_runnable_work(),
                "a current offer wakes the machine"
            );
            settle(&mut driver).await;
            driver.chain_update(recovered(current)).unwrap();
            assert!(
                driver.machine.has_runnable_work(),
                "a current certificate is staged in the machine"
            );
            assert_eq!(driver.telemetry.metrics.stale.get(), stale + 2);
            driver.shutdown_tasks();
            return;
        }
        if matches!(scenario, RuntimeSourceScenario::WaitPriority) {
            // Settle the persistence pipeline and the machine's timers so only the inputs armed
            // below are ready.
            driver.persisted(Output::Durable(first)).unwrap();
            settle(&mut driver).await;
            driver.timers.clear();
            let now = context.current();

            let permit = driver
                .tasks
                .reserve_units(TaskClass::LocalSigning, 1)
                .unwrap();
            let wait = driver.telemetry.metrics.vqc_latency.clone();
            driver
                .crypto
                .submit(permit, wait, Span::none(), &Span::none(), |_| {
                    Err(SchemeError::VerifierOnly)
                });
            if driver.egress.next_attempt().is_none_or(|at| at > now) {
                driver.egress.install(
                    EffectId::from_cursor(Cursor::new(u64::MAX)),
                    driver.machine.machine().generation(),
                    Vec::new(),
                    now,
                    driver.telemetry.round_view(),
                );
            }
            driver.timers.set_heartbeat(now);
            let artifact = Artifact::Nullification(committee.nullification(View::new(4)));
            let job_id = JobId::new(4321);
            let ticket =
                VerificationTicket::new(job_id, artifact.id::<Sha256>(), Observation::new(4321, 0));
            let job = VerifyJob::new(
                Issued::new(job_id, driver.tasks.generation()),
                vec![VerificationItem::new(ticket, Arc::new(artifact), Vec::new())],
            );
            let completion =
                verify::<Sha256, _, _>(&job, &mut test_rng(), &committee.verifier, &Sequential);
            assert!(
                completions
                    .completed(Completed {
                        span: Span::none(),
                        completion,
                    })
                    .accepted()
            );
            let identified = Artifact::Nullification(committee.nullification(View::new(5)))
                .identify::<Sha256>(&mut Vec::new());
            let bytes = identified.artifact.encoded_len();
            assert!(
                observations
                    .observed(Observed {
                        artifacts: vec![(committee.identities[1].clone(), identified)],
                        bytes,
                        plane: Plane::Certificate,
                        span: Span::none(),
                        forwarded_at: now,
                    })
                    .accepted()
            );

            let mut cursor = ReadinessCursor::default();
            let event = driver.wait(&mut cursor).await;
            assert!(matches!(event, RuntimeEvent::Crypto(_)));
            assert_eq!(cursor, ReadinessCursor::at_rotation(Source::Timer, 3, 0));
            let event = driver.wait(&mut cursor).await;
            assert!(matches!(event, RuntimeEvent::Publication));
            assert_eq!(cursor, ReadinessCursor::at_rotation(Source::Heartbeat, 3, 0));
            driver.handle_runtime_event(event).unwrap();
            assert!(driver.egress.next_attempt().is_none_or(|at| at > now));
            let event = driver.wait(&mut cursor).await;
            assert!(matches!(event, RuntimeEvent::Heartbeat));
            assert_eq!(cursor, ReadinessCursor::at_rotation(Source::Inspection, 3, 0));
            driver.handle_runtime_event(event).unwrap();
            let event = driver.wait(&mut cursor).await;
            assert!(matches!(event, RuntimeEvent::Verification(_)));
            assert_eq!(cursor, ReadinessCursor::at_rotation(Source::Timer, 1, 0));
            let event = driver.wait(&mut cursor).await;
            assert!(matches!(event, RuntimeEvent::Observation(_)));
            assert_eq!(cursor, ReadinessCursor::at_rotation(Source::Publication, 1, 0));
            driver.shutdown_tasks();
            return;
        }
        let pending = driver.persistence.ledger().outstanding() - 1;
        driver.persisted(Output::Durable(first)).unwrap();
        assert!(!driver.machine.can_admit(Lane::PersistenceCompletion));
        if matches!(scenario, RuntimeSourceScenario::Verification) {
            let resources = driver.machine.machine().profile().resources();
            let bulk_units = resources.max_cached_artifacts() + resources.max_outbox_effects() - 2;
            let bulk = driver
                .tasks
                .reserve_units(TaskClass::BulkCrypto, bulk_units)
                .unwrap();
            let artifact = Artifact::Nullification(committee.nullification(View::new(4)));
            let job_id = JobId::new(1234);
            let ticket = VerificationTicket::new(
                job_id,
                artifact.id::<Sha256>(),
                Observation::new(1234, 0),
            );
            let job = VerifyJob::new(
                Issued::new(job_id, driver.tasks.generation()),
                vec![VerificationItem::new(ticket, Arc::new(artifact), Vec::new())],
            );
            let root = info_span!(parent: None, "test.verification_round");
            debug_span!("test.observation")
                .in_scope(|| {
                    driver.execute_capabilities(
                        vec![Capability::Verify(job)],
                        &root,
                    )
                })
                .unwrap();
            let message = verifier_rx.try_recv().expect(
                "critical verification must reach the verifier while producer permits remain held",
            );
            let verifier::Message::Verify { span, job, .. } = message;
            span.in_scope(|| info!("verification dispatched"));
            assert!(job.view_critical());
            assert_eq!(job.items().len(), 1);
            assert!(driver.verification.is_empty());
            assert_eq!(driver.verification_tasks.len(), 1);
            assert!(driver.finish_task(bulk).unwrap());
            driver.shutdown_tasks();
            return;
        }
        if matches!(scenario, RuntimeSourceScenario::Signing) {
            let job = held_signing.expect("startup must release a real signing request");
            driver
                .execute_capabilities(
                    vec![Capability::Released(job)],
                    &Span::none(),
                )
                .unwrap();
            assert_eq!(driver.crypto.len(), 1);
            let released = hooks.durable_effects();
            let signing = released
                .iter()
                .find_map(|(id, attempts)| {
                    attempts.iter().find_map(|attempt| {
                        matches!(attempt.effect, DurableEffect::Sign(_))
                            .then_some((*id, attempt.generation))
                    })
                })
                .expect("a real durable signing request must reach the executor");
            assert_eq!(driver.egress.len(), 0);
            // The critical pool runs a job when it is submitted, so the job's start is recorded
            // before the completion collection is polled only if release submitted it.
            let encoded = context.encode();
            assert!(
                encoded
                    .lines()
                    .any(|line| line == "metrics_crypto_submit_wait_signing_count 1"),
                "released crypto must be submitted before polling its completion collection: {encoded}"
            );
            let finished = poll_fn(|cx| driver.crypto.poll_completed(cx)).await;
            let encoded = context.encode();
            assert!(
                encoded
                    .lines()
                    .any(|line| line == "metrics_crypto_submit_wait_aggregation_count 0"),
                "{encoded}"
            );
            let (id, generation) = match finished.outcome.unwrap().unwrap() {
                CryptoOutcome::Signed { id, generation, .. }
                | CryptoOutcome::SignedBatch { id, generation, .. } => (id, generation),
                _ => panic!("the released job must return its signed artifacts"),
            };
            assert_eq!((id, generation), signing);
            assert_eq!(driver.egress.len(), 0);
            return;
        }
        if matches!(scenario, RuntimeSourceScenario::Heartbeat) {
            driver.timers.set_heartbeat(context.current());
            let mut cursor = ReadinessCursor::at(Source::Heartbeat);
            driver.drive_core_cycle().await.unwrap();
            let first_quanta = *hooks.work_quanta.lock();
            let work_remained = driver.machine.has_runnable_work();
            let event = driver.next_event(&mut cursor).await;
            assert!(
                matches!(event, Some(RuntimeEvent::Heartbeat)),
                "the expired heartbeat is ready at the runtime boundary"
            );
            driver.handle_runtime_event(event.unwrap()).unwrap();
            assert!(driver.timers.heartbeat_at() > context.current());
            while driver.machine.has_runnable_work() {
                driver.drive_core_cycle().await.unwrap();
            }
            assert!(
                *hooks.work_quanta.lock() >= 2,
                "the fixture must exercise multiple semantic quanta"
            );
            assert!(
                work_remained,
                "the ready heartbeat must be handled before draining the runnable semantic work (ran {first_quanta} quanta)"
            );
            assert_eq!(
                first_quanta, 1,
                "a ready runtime source must be reconsidered after one component quantum"
            );
            return;
        }
        driver.drive_core_cycle().await.unwrap();
        let services = hooks.services();
        assert_eq!(
            services.first().map(|(_, lane)| *lane),
            Some(Lane::PersistenceCompletion)
        );
        assert!(
            driver.persistence.ledger().outstanding() < pending,
            "a ready FIFO successor must enter Core during the cycle that frees its admission slot"
        );
        while driver.machine.has_runnable_work() {
            driver.drive_core_cycle().await.unwrap();
        }
        let services = hooks.services();
        assert!(services.windows(2).all(|pair| pair[0].0 == pair[1].0));
        assert!(
            services
                .iter()
                .filter(|(_, lane)| *lane == Lane::PersistenceCompletion)
                .count()
                >= 2
        );
        let acknowledgements = hooks
            .events()
            .into_iter()
            .filter_map(|event| match event {
                TestEvent::Acknowledged { ack } => Some(ack),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(acknowledgements[0], first_ack);
        assert!(
            acknowledgements
                .windows(2)
                .all(|pair| pair[0].cursor() <= pair[1].cursor())
        );
        assert_eq!(acknowledgements.len(), appended);
        assert_eq!(driver.persistence.ledger().outstanding(), 0);
    });
}

#[test]
fn chain_tasks_follow_the_role() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(87, 6).build();
        let metrics = Metrics::new(&context.child("metrics"), committee.identities.len());
        let scheme = Arc::new(committee.signers[0].clone());
        let mailbox_size = NonZeroUsize::new(4).unwrap();
        let profile = |role: Role| {
            Profile::new::<MinPk>(committee.config.clone(), role, Tuning::default()).unwrap()
        };
        let tasks = |label: &'static str, profile: &Profile<Sha256Digest>| {
            ChainTasks::<TestTypes>::new(
                &context.child(label),
                profile,
                &scheme,
                Sequential,
                &MockApplication::default(),
                &metrics,
                mailbox_size,
            )
        };

        let mut observer = tasks("observer", &profile(Role::Observer));
        assert!(observer.da().is_none());
        assert!(observer.plane(ChainId::new(0)).is_none());
        assert!(observer.updates().is_none());

        let participant = Participant::new(0);
        let profile = profile(Role::Validator(participant));
        let mut validator = tasks("validator", &profile);
        let chains = committee.config.codec_config().chains();
        assert!(chains > 1);
        for index in 0..chains {
            let chain = ChainId::new(index as u32);
            assert_eq!(validator.plane(chain).unwrap().chain(), chain);
        }
        assert!(validator.plane(ChainId::new(chains as u32)).is_none());
        assert_eq!(
            validator.da().is_some(),
            committee.config.producer_chain(participant).is_some(),
            "only a producer recovers its own chain's certificates"
        );
        assert!(validator.updates().is_some());

        let machine = CoreState::fresh(profile).unwrap();
        validator.enter(Generation::new(1), &machine);
        validator.enter(Generation::new(2), &machine);

        // A quorum recovered after the reconfiguration carries the new generation.
        let own_chain = committee.config.producer_chain(participant).unwrap();
        let header = TransactionBlockHeader::new(
            committee.config.epoch(),
            own_chain,
            Height::new(1),
            Sha256::hash(&[b"parent"]),
            Sha256::hash(&[b"body"]),
        )
        .unwrap();
        let da = validator.da().unwrap();
        for signer in committee.signers.iter().take(committee.codec().da_quorum()) {
            let vote = signer.sign_da_vote(header.clone()).unwrap();
            assert!(da.command(ChainCommand::Observe(Arc::new(vote))).accepted());
        }
        loop {
            match validator.updates().unwrap().recv().await.unwrap() {
                ChainUpdate::Recovered(DaUpdate {
                    generation, block, ..
                }) => {
                    assert_eq!(generation, Generation::new(2));
                    assert_eq!(block, header.block_ref::<Sha256>());
                    break;
                }
                ChainUpdate::DaVoteReady(update) => {
                    assert_eq!(update.generation, Generation::new(2))
                }
            }
        }

        // Tasks that all exit leave the result queue open rather than reporting a closed input.
        validator.close_commands();
        for _ in 0..16 {
            reschedule().await;
        }
        while let Some(update) = validator.updates().unwrap().recv().now_or_never() {
            assert!(update.is_some(), "the voter's result queue stays open");
        }
    });
}

#[derive(Clone)]
struct CloseLayer {
    round_closed: Arc<AtomicBool>,
}

impl<S> Layer<S> for CloseLayer
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_close(&self, id: Id, context: LayerContext<'_, S>) {
        let Some(metadata) = context.metadata(&id) else {
            return;
        };
        if matches!(metadata.name(), "test.checkpoint_round" | "test.task_round") {
            self.round_closed.store(true, Ordering::Relaxed);
        }
    }
}

#[test]
fn pending_checkpoint_does_not_retain_originating_round_span() {
    let round_closed = Arc::new(AtomicBool::new(false));
    let subscriber = tracing_subscriber::registry().with(CloseLayer {
        round_closed: Arc::clone(&round_closed),
    });

    tracing::subscriber::with_default(subscriber, || {
        deterministic::Runner::default().start(|context| async move {
            let round = tracing::info_span!(parent: None, "test.checkpoint_round");
            let origin = CheckpointOrigin {
                epoch: Epoch::new(7),
                view: View::new(11),
                cursor: Cursor::zero(),
                retired_views: View::new(9),
            };
            let checkpoint = checkpoint_span!(&round, "multimmit.voter.checkpoint", origin);
            let roll = checkpoint_span!(None, "multimmit.voter.checkpoint.roll", origin);
            roll.follows_from(checkpoint.id());
            drop(checkpoint);
            // The roll span travels with the checkpoint command and parents its storage work.
            let store = context
                .child("pending_store")
                .spawn(|_| pending::<()>().instrument(roll));

            drop(round);
            assert!(
                round_closed.load(Ordering::Relaxed),
                "pending checkpoint I/O must not own its originating round span"
            );

            store.abort();
            let _ = store.await;
        });
    });
}

#[test]
fn terminal_context_owns_errors_until_the_failed_work_is_released() {
    for queued_verification in [false, true] {
        let round_closed = Arc::new(AtomicBool::new(false));
        let traces = TraceStorage::default();
        let subscriber = tracing_subscriber::registry()
            .with(CollectingLayer::new(traces.clone()))
            .with(CloseLayer {
                round_closed: Arc::clone(&round_closed),
            });
        tracing::subscriber::with_default(subscriber, || {
            deterministic::Runner::default().start(|context| async move {
                let metrics = Metrics::new(&context, 1);
                let root = info_span!(parent: None, "test.task_round");
                let operation = info_span!(parent: &root, "test.task");
                let completed = TraceContext::new(operation, root);
                let later = info_span!(parent: None, "test.later_round");
                let (root, fatal) = if queued_verification {
                    (completed.root.clone(), Fatal::VerificationClosed)
                } else {
                    let (_, outcome) = offload(Sequential, 1, completed.span.clone(), |_| -> () {
                        panic!("worker failed");
                    })
                    .await;
                    assert!(outcome.is_err());
                    (completed.root.clone(), Fatal::CryptoTaskPanicked)
                };
                assert!(!round_closed.load(Ordering::Relaxed));
                later.in_scope(|| record_fatal(&metrics, &root, &fatal));
                let errors = traces.get_by_level(tracing::Level::ERROR);
                assert_eq!(errors.len(), 1);
                assert_eq!(errors[0].spans.len(), 1);
                assert_eq!(errors[0].spans[0].content, "test.task_round");
                assert_eq!(metrics.fatal.get(), 1);
                drop(root);
                drop(completed);
                assert!(round_closed.load(Ordering::Relaxed));
            });
        });
    }
}

#[derive(Default)]
struct CryptoServiceProbe {
    state: Mutex<CryptoServiceState>,
    changed: Condvar,
}

#[derive(Default)]
struct CryptoServiceState {
    crypto_started: bool,
    services_armed: bool,
    serviced: usize,
    crypto_released: bool,
}

impl CryptoServiceProbe {
    fn block_crypto(&self) {
        let mut state = self.state.lock();
        state.crypto_started = true;
        self.changed.notify_all();
        while !state.crypto_released {
            self.changed.wait(&mut state);
        }
    }

    fn arm_services(&self) {
        let mut state = self.state.lock();
        state.services_armed = true;
        self.changed.notify_all();
    }

    fn record_service(&self) {
        let mut state = self.state.lock();
        state.serviced += 1;
        self.changed.notify_all();
    }

    fn observe_then_release(&self, expected: usize) -> bool {
        let mut state = self.state.lock();
        while !state.crypto_started || !state.services_armed {
            self.changed.wait(&mut state);
        }

        let deadline = Instant::now() + Duration::from_secs(2);
        while state.serviced < expected {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            if self.changed.wait_for(&mut state, remaining).timed_out() {
                break;
            }
        }

        let serviced = state.serviced == expected;
        state.crypto_released = true;
        self.changed.notify_all();
        serviced
    }
}

// A one-worker tokio runner: blocked crypto must leave that one executor thread free, and the
// deterministic runtime would report a stall while its only task waits on rayon.
#[test_traced]
fn crypto_strategy_keeps_async_executor_serviceable() {
    const EXPECTED_SERVICES: usize = 4;

    let runner = tokio::Runner::new(tokio::Config::default().with_worker_threads(1));
    let serviced = runner.start(|context| async move {
        let probe = Arc::new(CryptoServiceProbe::default());
        let observer = {
            let probe = Arc::clone(&probe);
            thread::spawn(move || probe.observe_then_release(EXPECTED_SERVICES))
        };

        let crypto_probe = Arc::clone(&probe);
        let strategy = Rayon::new(NonZeroUsize::new(2).unwrap()).expect("compute pool starts");
        let operation = offload(strategy, 1, Span::none(), move |_| {
            crypto_probe.block_crypto()
        });
        let crypto = context.child("crypto").spawn(move |_| operation);

        let control = {
            let probe = Arc::clone(&probe);
            context.child("control").spawn(move |_| async move {
                probe.record_service();
            })
        };

        let (resolve, resolved) = oneshot::channel::<()>();
        let resolver = {
            let probe = Arc::clone(&probe);
            context.child("resolver").spawn(move |_| async move {
                resolved.await.expect("resolver control remains open");
                probe.record_service();
            })
        };
        resolve.send(()).expect("resolver remains active");

        let journal = {
            let probe = Arc::clone(&probe);
            context.child("journal").spawn(move |context| async move {
                context.sleep(Duration::from_millis(10)).await;
                probe.record_service();
            })
        };

        let timer = {
            let probe = Arc::clone(&probe);
            context.child("timer").spawn(move |context| async move {
                context.sleep(Duration::from_millis(20)).await;
                probe.record_service();
            })
        };

        let shutdown = {
            let probe = Arc::clone(&probe);
            context.child("shutdown").spawn(move |context| async move {
                context.stopped().await.expect("shutdown remains active");
                probe.record_service();
            })
        };

        probe.arm_services();
        context
            .stop(0, Some(Duration::from_secs(4)))
            .await
            .expect("runtime shuts down after crypto returns");

        crypto
            .await
            .expect("crypto task completes")
            .1
            .expect("crypto worker completes");
        control.await.expect("control task completes");
        resolver.await.expect("resolver task completes");
        journal.await.expect("journal task completes");
        timer.await.expect("timer task completes");
        shutdown.await.expect("shutdown task completes");
        observer.join().expect("service observer completes")
    });

    assert!(
        serviced,
        "crypto occupied the async executor before journal, resolver, control, and timer service"
    );
}
