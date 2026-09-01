//! Deterministic world scenarios: crash-prefix recovery, the publication successor matrix, and
//! replayable fault schedules.

use super::{
    fuzz::{crash_cut, exercise, exercise_prefix_crash, malformed_completion},
    *,
};
use crate::multimmit::machine::testing::{VerifyJobExt as _, fixtures::unsigned_da_certificate};
use proptest::prelude::*;

fn prefix_crash_plan() -> ReplayPlan {
    let (plan, _) = Scenario::new(
        6,
        from_fn(|replica| ReplicaKnobs {
            proposal_first: [true, false, true][replica],
            newest_verification: [false, true, false][replica],
            reverse_votes: [true, false, true][replica],
            byzantine_full: [true, true, true][replica],
            reverse_blocks: [true, false, true][replica],
            malformed: malformed_completion(3, replica),
            crash: [
                Some(BarrierCut::BeforeAppend),
                Some(BarrierCut::AfterAppend),
                Some(BarrierCut::AfterAck),
            ][replica],
        }),
    )
    .run();
    plan
}

#[test]
fn crash_prefix_boundaries_recover_and_replay() {
    let plan = prefix_crash_plan();
    let fixture = Fixture::new(plan.blocks);
    for family in 0..5 {
        for flags in [0, 1, 4, 7] {
            exercise_prefix_crash(&fixture, &plan, [family, 17, flags]);
        }
    }
}

#[test]
fn crash_prefix_can_interrupt_recovery() {
    let plan = prefix_crash_plan();
    let fixture = Fixture::new(plan.blocks);
    let crash = plan
        .actions
        .iter()
        .position(|action| matches!(action, Action::CrashAndRestore { .. }))
        .expect("the scenario contains a recovery prefix");
    let mut world = World::replay(&fixture, &plan.actions[..=crash]);
    let replica = plan.actions[crash].replica().unwrap();
    assert!(
        world.replicas[replica]
            .publication_oracle
            .recovery_expected
            .is_some()
    );
    world.apply(Action::CrashAndRestore { replica });
    world.drive(
        replica,
        Until::Quiesce,
        CompletionOrder::Oldest,
        CompletionOrder::Oldest,
        true,
    );
    world.assert_locally_drained(replica);
}

#[test]
#[should_panic(expected = "signature escaped before its covering barrier")]
fn crash_prefix_oracle_rejects_unacknowledged_signature() {
    let plan = prefix_crash_plan();
    let fixture = Fixture::new(plan.blocks);
    let mut world = World::replay(&fixture, &plan.actions);
    let replica = 0;
    let state = &mut world.replicas[replica];
    let artifact = *state
        .signature_oracle
        .exposed_signatures
        .values()
        .find(|artifact| {
            !state
                .signature_oracle
                .externally_injected
                .contains(*artifact)
        })
        .expect("the scenario exposes a locally signed artifact");
    let origin = state
        .signature_oracle
        .signing_events
        .get_mut(&artifact)
        .unwrap();
    origin.covering_cursor = Cursor::new(state.driver.acknowledged_cursor.get() + 1);
    world.assert_invariants(replica);
}

mod successor_matrix {
    use super::*;
    use crate::{multimmit::machine::durability::ChangeKind, types::ViewDelta};

    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    enum SuccessorFamily {
        Da,
        ForwardedExit,
        ViewRetention,
        FinalityFloor,
    }

    #[derive(Clone, Debug)]
    struct PublicationWitness {
        id: EffectId,
        generation: Generation,
        effect: DurableEffect<MinPk, Digest>,
    }

    fn only_persist(step: &Step<MinPk, Digest>) -> PersistJob<MinPk, Digest> {
        let jobs = step
            .capabilities()
            .iter()
            .filter_map(|effect| match effect {
                Capability::Journal(PersistDirective { job, .. }) => Some(job.clone()),
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

    /// Returns the publication reserved by the barrier's forwarding event.
    fn forwarded_publication(job: &PersistJob<MinPk, Digest>) -> EffectId {
        job.events()
            .iter()
            .find_map(|event| match event.change() {
                Change::ArtifactForwarded { publication, .. } => Some(*publication),
                _ => None,
            })
            .expect("the barrier must stage one forwarding")
    }

    /// Acknowledges each staged barrier in order until the machine stages no more.
    fn drain_barriers(
        runner: &mut Driver<Sha256, MinPk>,
        step: Step<MinPk, Digest>,
    ) -> Step<MinPk, Digest> {
        let mut step = step;
        let mut pending = VecDeque::new();
        for _ in 0..8 {
            pending.extend(
                step.capabilities()
                    .iter()
                    .filter_map(|effect| match effect {
                        Capability::Journal(PersistDirective { job, .. }) => Some(job.clone()),
                        _ => None,
                    }),
            );
            let Some(job) = pending.pop_front() else {
                return step;
            };
            let acknowledged = runner.persist(&job, Until::Step);
            step = runner.settle(acknowledged, Until::Quiesce);
        }
        panic!("the staged barriers did not drain")
    }

    fn publication_witness(
        effects: &[Capability<MinPk, Digest>],
        id: EffectId,
    ) -> PublicationWitness {
        effects
            .iter()
            .find_map(|effect| {
                let job = match effect {
                    Capability::Released(job) if job.issued().id() == id => Some(job.clone()),
                    Capability::Journal(directive) => directive
                        .clone()
                        .release_after_enqueue
                        .into_iter()
                        .find(|job| job.issued().id() == id),
                    _ => None,
                }?;
                Some(PublicationWitness {
                    id,
                    generation: job.issued().generation(),
                    effect: job.request().clone(),
                })
            })
            .unwrap_or_else(|| panic!("publication {id:?} was absent from {effects:?}"))
    }

    fn authenticate_one(
        runner: &mut Driver<Sha256, MinPk>,
        artifact: Artifact<MinPk, Digest>,
    ) -> Step<MinPk, Digest> {
        let observed = runner.submit(cohort::<Sha256, _>(vec![artifact])).unwrap();
        let verification = observed
            .capabilities()
            .iter()
            .find_map(|effect| match effect {
                Capability::Verify(job) => Some(job.clone()),
                _ => None,
            })
            .expect("the independently supplied artifact must require verification");
        let completed = runner
            .submit(Input::Verified(verification.all_valid()))
            .unwrap();
        runner.settle(completed, Until::Quiesce)
    }

    fn acknowledge_recovery_exit(
        runner: &mut Driver<Sha256, MinPk>,
        recovery: &Step<MinPk, Digest>,
        epoch: Epoch,
    ) {
        let resolution = recovery
            .capabilities()
            .iter()
            .find_map(|effect| match effect {
                Capability::Resolver(ResolverCommand::Resolve(job)) => Some(*job),
                _ => None,
            })
            .expect("recovery must request the exact current-view exit");
        let view = resolution.view();
        let resolving = runner
            .submit(Input::ResolutionCompleted(ResolutionCompletion::new(
                resolution.issued(),
                resolution.view(),
                ViewProof::Nullification(Box::new(unsigned_nullification(Round::new(epoch, view)))),
            )))
            .unwrap();
        let verification = resolving
            .capabilities()
            .iter()
            .find_map(|effect| match effect {
                Capability::Verify(job) => Some(job.clone()),
                _ => None,
            })
            .expect("the resolved exit must still be authenticated");
        let completed = runner
            .submit(Input::Verified(verification.all_valid()))
            .unwrap();
        let forwarding = runner.settle(completed, Until::Quiesce);
        let drained = drain_barriers(runner, forwarding);
        assert!(drained.capabilities().iter().all(|effect| {
            !matches!(
                effect,
                Capability::Verify(_) | Capability::Resolver(ResolverCommand::Resolve(_))
            )
        }));
    }

    fn prepare_publication_case(
        fixture: &Fixture,
        family: SuccessorFamily,
    ) -> (Driver<Sha256, MinPk>, PublicationWitness) {
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
        let protocol = fixture.profiles[0].protocol().clone();
        let role = if family == SuccessorFamily::Da {
            Role::Validator(protocol.producer(ChainId::new(0)).unwrap())
        } else {
            Role::Observer
        };
        let profile = Profile::new::<MinPk>(protocol, role, tuning).unwrap();
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
                Artifact::Nullification(unsigned_nullification(Round::new(epoch, View::new(1))))
            }
            SuccessorFamily::ViewRetention | SuccessorFamily::FinalityFloor => {
                fixture.artifacts[VIEW_ONE_HONEST_VOTES].clone()
            }
        };
        let effect = DurableEffect::broadcast(Arc::new(predecessor));
        let mut runner = Driver::new(profile);
        let started = runner.submit(Input::Start).unwrap();
        runner.persist(&only_persist(&started), Until::Step);

        let initial = if family == SuccessorFamily::ForwardedExit {
            let forwarding = authenticate_one(
                &mut runner,
                Artifact::Nullification(unsigned_nullification(Round::new(epoch, View::new(1)))),
            );
            // The exit derives beside the forwarding it reads, so the publication belongs to
            // the forwarding event rather than to the barrier's last cursor.
            let publication = publication_witness(
                forwarding.capabilities(),
                forwarded_publication(&only_persist(&forwarding)),
            );
            assert_eq!(publication.effect, effect);
            drain_barriers(&mut runner, forwarding);
            publication
        } else {
            let reserved = runner.reserve(effect.clone()).unwrap();
            let reservation = only_persist(&reserved);
            let publication = publication_witness(
                reserved.capabilities(),
                EffectId::from_cursor(reservation.last_cursor()),
            );
            assert_eq!(publication.effect, effect);
            runner.persist(&reservation, Until::Step);
            publication
        };

        let delivered = runner
            .submit(Input::EffectCompleted(EffectCompletion::delivered(
                Issued::new(initial.id, initial.generation),
            )))
            .unwrap();
        assert!(
            delivered.capabilities().is_empty(),
            "Delivered must be volatile"
        );

        let recovery = runner.crash_and_restore().unwrap();
        let recovered = runner.persist(&only_persist(&recovery), Until::Step);
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
        runner: &mut Driver<Sha256, MinPk>,
        family: SuccessorFamily,
    ) -> (
        PersistJob<MinPk, Digest>,
        Option<DurableEffect<MinPk, Digest>>,
    ) {
        let epoch = runner.profile().protocol().epoch();
        match family {
            SuccessorFamily::Da => {
                let genesis = runner.profile().protocol().genesis().tips()[0];
                let header = TransactionBlockHeader::new(
                    epoch,
                    genesis.chain(),
                    Height::new(1),
                    genesis.digest(),
                    digest(b"matrix DA predecessor"),
                )
                .unwrap();
                let certificate = Artifact::DaCertificate(unsigned_da_certificate(header));
                let expected = DurableEffect::broadcast(Arc::new(certificate.clone()));
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
                let certificate = Artifact::Nullification(unsigned_nullification(Round::new(
                    epoch,
                    View::new(3),
                )));
                let expected = DurableEffect::broadcast(Arc::new(certificate.clone()));
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
                let first = Artifact::Nullification(unsigned_nullification(Round::new(
                    epoch,
                    View::new(2),
                )));
                let forwarded = authenticate_one(runner, first);
                let drained = drain_barriers(runner, forwarded);
                // Only acknowledgement bookkeeping remains: the first exit stages nothing
                // further and owes no publication.
                assert!(!drained.capabilities().iter().any(|effect| matches!(
                    effect,
                    Capability::Journal(_) | Capability::Released(_)
                )));

                let second = Artifact::Nullification(unsigned_nullification(Round::new(
                    epoch,
                    View::new(3),
                )));
                let target = authenticate_one(runner, second);
                let barrier = only_persist(&target);
                // The exit that retires the aged publication stages beside the forwarding fact
                // it reads.
                assert_eq!(
                    barrier
                        .events()
                        .iter()
                        .map(|event| event.change().kind())
                        .collect::<Vec<_>>(),
                    [ChangeKind::ArtifactForwarded, ChangeKind::ViewAdvanced]
                );
                assert!(target.capabilities().iter().all(|effect| {
                    !matches!(effect, Capability::Released(job)
                    if job.issued().id() == EffectId::from_cursor(barrier.last_cursor()))
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
                        Capability::Verify(job) => Some(job.clone()),
                        _ => None,
                    })
                    .unwrap();
                let verified = runner
                    .submit(Input::Verified(verification.all_valid()))
                    .unwrap();
                let ready = runner.settle(verified, Until::Quiesce);
                let vqc = ready
                    .capabilities()
                    .iter()
                    .find_map(|effect| match effect {
                        Capability::Crypto(CryptoJob::AggregateVqc(job)) => Some(job.clone()),
                        _ => None,
                    })
                    .expect("the full-vote cohort must schedule its earlier V-QC");
                // The finalized pool may release its aggregation with the same settle that
                // scheduled the V-QC or only after the covering barrier is acknowledged.
                let aggregation = ready.capabilities().iter().find_map(|effect| match effect {
                    Capability::Crypto(CryptoJob::AggregateLqc(job)) => Some(job.clone()),
                    _ => None,
                });
                let ready = if ready
                    .capabilities()
                    .iter()
                    .any(|effect| matches!(effect, Capability::Journal(_)))
                {
                    let acknowledged = runner.persist(&only_persist(&ready), Until::Step);
                    runner.settle(acknowledged, Until::Quiesce)
                } else {
                    ready
                };
                let aggregation = aggregation
                    .or_else(|| {
                        ready.capabilities().iter().find_map(|effect| match effect {
                            Capability::Crypto(CryptoJob::AggregateLqc(job)) => Some(job.clone()),
                            _ => None,
                        })
                    })
                    .expect("the view-two full votes must schedule one L-QC");

                let certificate = symbolic_vqc(
                    vqc.leader().clone(),
                    &vqc.messages().collect::<Vec<_>>(),
                    runner.profile().codec(),
                );
                let completed = runner
                    .submit(Input::Crypto(CryptoCompletion::Vqc(Box::new(
                        VqcAggregateCompletion::prepare::<Sha256>(
                            &vqc,
                            certificate,
                            runner.profile().codec(),
                        )
                        .expect("symbolic V-QCs match their transcripts"),
                    ))))
                    .unwrap();
                let completed = runner.settle(completed, Until::Quiesce);
                let forwarded = drain_barriers(runner, completed);
                assert!(runner.machine().durable.state.vqc_forwarded(View::new(2)));
                assert!(
                    forwarded
                        .capabilities()
                        .iter()
                        .all(|effect| { !matches!(effect, Capability::Journal(_)) })
                );

                let certificate = symbolic_lqc(
                    aggregation.leader().clone(),
                    aggregation.votes(),
                    runner.profile().codec(),
                );
                let created = runner
                    .submit(Input::Crypto(CryptoCompletion::Lqc(Box::new(
                        LqcAggregateCompletion::prepare::<Sha256>(
                            &aggregation,
                            certificate,
                            runner.profile().codec(),
                        )
                        .expect("symbolic L-QCs match their votes"),
                    ))))
                    .unwrap();
                let mut step = runner.settle(created, Until::Quiesce);
                for iteration in 0..4 {
                    let barrier = step
                        .capabilities()
                        .iter()
                        .find_map(|effect| match effect {
                            Capability::Journal(PersistDirective { job, .. }) => Some(job.clone()),
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
                            !matches!(effect, Capability::Released(job)
                            if job.issued().id() == EffectId::from_cursor(barrier.last_cursor()))
                        }));
                        return (barrier, None);
                    }
                    let acknowledged = runner.persist(&barrier, Until::Step);
                    let delivered =
                        acknowledged
                            .capabilities()
                            .iter()
                            .find_map(|effect| match effect {
                                Capability::Released(job)
                                    if job.request().publication().is_some() =>
                                {
                                    Some((job.issued().id(), job.issued().generation()))
                                }
                                _ => None,
                            });
                    step = if let Some((id, generation)) = delivered {
                        let delivered = runner
                            .submit(Input::EffectCompleted(EffectCompletion::delivered(
                                Issued::new(id, generation),
                            )))
                            .unwrap();
                        runner.settle(delivered, Until::Quiesce)
                    } else {
                        runner.settle(acknowledged, Until::Quiesce)
                    };
                }
                panic!("the admitted L-QC did not stage a finality-floor successor")
            }
        }
    }

    fn recover_publications(
        runner: &mut Driver<Sha256, MinPk>,
        ids: &BTreeSet<EffectId>,
    ) -> (u64, BTreeMap<EffectId, PublicationWitness>) {
        let recovery = runner.crash_and_restore().unwrap();
        let recovery_barrier = only_persist(&recovery);
        let released = runner.persist(&recovery_barrier, Until::Step);
        let generation = runner.inspect().generation();
        let publications = released
            .capabilities()
            .iter()
            .filter_map(|effect| match effect {
                Capability::Released(job) if ids.contains(&job.issued().id()) => Some((
                    job.issued().id(),
                    PublicationWitness {
                        id: job.issued().id(),
                        generation: job.issued().generation(),
                        effect: job.request().clone(),
                    },
                )),
                _ => None,
            })
            .collect();
        (generation.get(), publications)
    }

    fn run_successor_case(fixture: &Fixture, family: SuccessorFamily, cut: BarrierCut) {
        let (mut runner, predecessor) = prepare_publication_case(fixture, family);
        let (target, replacement) = successor_barrier(fixture, &mut runner, family);
        if replacement.is_some() {
            // A replacement publication is identified by the barrier's only event.
            assert_eq!(target.last_cursor(), target.previous().next().unwrap());
        }

        let replacement_id = EffectId::from_cursor(target.last_cursor());
        match cut {
            BarrierCut::BeforeAppend => {}
            BarrierCut::AfterAppend => runner.append(&target).unwrap(),
            BarrierCut::AfterAck => {
                runner.persist(&target, Until::Step);
            }
        }

        let mut ids = BTreeSet::from([predecessor.id]);
        if replacement.is_some() {
            ids.insert(replacement_id);
        }
        let (recovery_generation, actual) = recover_publications(&mut runner, &ids);
        assert!(
            actual.iter().all(|(id, publication)| {
                *id == publication.id
                    && publication.generation == Generation::new(recovery_generation)
            }),
            "failed {family:?} at {cut:?}: recovery generation {recovery_generation}, publications {actual:?}"
        );
        let actual = actual
            .into_iter()
            .map(|(id, publication)| (id, publication.effect))
            .collect::<BTreeMap<_, _>>();
        let expected = if cut == BarrierCut::BeforeAppend {
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
            BarrierCut::BeforeAppend,
            BarrierCut::AfterAppend,
            BarrierCut::AfterAck,
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
        let (_, durable) = Scenario {
            poll_budget: NonZeroUsize::new(budget).unwrap(),
            ..Scenario::new(
                4,
                from_fn(|replica| ReplicaKnobs {
                    proposal_first: [true, false, true][replica],
                    newest_verification: [false, true, false][replica],
                    reverse_votes: [false, true, true][replica],
                    byzantine_full: [true, false, true][replica],
                    reverse_blocks: [true, false, true][replica],
                    malformed: malformed_completion(0, replica),
                    crash: [
                        Some(BarrierCut::BeforeAppend),
                        Some(BarrierCut::AfterAppend),
                        Some(BarrierCut::AfterAck),
                    ][replica],
                }),
            )
        }
        .run();
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

#[test]
fn canonical_fault_schedule_drains_all_locally_answerable_work() {
    exercise(&[]);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn honest_replicas_keep_compatible_finality_under_replayable_faults(
        blocks in 2usize..=6,
        proposal_first in any::<[bool; REPLICAS]>(),
        newest_verification in any::<[bool; REPLICAS]>(),
        reverse_votes in any::<[bool; REPLICAS]>(),
        byzantine_full in any::<[bool; REPLICAS]>(),
        reverse_blocks in any::<[bool; REPLICAS]>(),
        malformed_bits in any::<u8>(),
        crash_bits in any::<u8>(),
    ) {
        let (plan, durable) = Scenario::new(
            blocks,
            from_fn(|replica| ReplicaKnobs {
                proposal_first: proposal_first[replica],
                newest_verification: newest_verification[replica],
                reverse_votes: reverse_votes[replica],
                byzantine_full: byzantine_full[replica],
                reverse_blocks: reverse_blocks[replica],
                malformed: malformed_completion(malformed_bits, replica),
                crash: crash_cut(crash_bits, replica),
            }),
        ).run();

        let (_, canonical) = Scenario::new(
            blocks,
            from_fn(|replica| ReplicaKnobs {
                proposal_first: proposal_first[replica],
                newest_verification: [false; REPLICAS][replica],
                reverse_votes: reverse_votes[replica],
                byzantine_full: byzantine_full[replica],
                reverse_blocks: reverse_blocks[replica],
                malformed: malformed_completion(malformed_bits, replica),
                crash: [None; REPLICAS][replica],
            }),
        ).run();
        prop_assert_eq!(&durable.finality, &canonical.finality);
        prop_assert_eq!(
            durable.inspections[0].finality_floor(),
            canonical.inspections[0].finality_floor(),
        );

        let replay_fixture = Fixture::new(plan.blocks);
        let replayed = World::replay(&replay_fixture, &plan.actions);
        for replica in 0..REPLICAS {
            replayed.assert_locally_drained(replica);
        }
        prop_assert_eq!(replayed.durable_outcome(), durable);
    }
}
