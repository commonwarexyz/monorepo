//! Publication discharge and successor barrier acknowledgement tests.

use super::harness::{
    Attachments, ExposureLedger, Node, NodeBuilder, da_certificate, da_certificate_publications,
    slot_publications, wait_for_da_certificate, wait_for_live_publication, wait_for_slot_block,
};
use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        actors::voter::{
            actor::{RetentionBoundary, TestEvent, TestHooks},
            persistence::{JournalPoint, TestGates},
        },
        config::Role,
        machine::{
            BarrierAck, Cursor, DurableEffect, EffectId, Generation,
            testing::{EffectExt, fixtures::DischargeFamily},
        },
        mocks::MockApplication,
        testing::expect_before,
        types::{Artifact, ChainId, TransactionBlockHeader, ViewProof},
        wire::{CertificateMessage, ConsensusMessage, DataMessage, Envelope},
    },
    types::{Height, Participant, View},
};
use commonware_codec::{Decode as _, Encode as _};
use commonware_cryptography::{
    Hasher as _, Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
};
use commonware_macros::{select, test_traced};
use commonware_p2p::{Receiver as _, Recipients, Sender as _};
use commonware_runtime::{
    Clock as _, Runner as _,
    deterministic::{Context as DeterministicContext, Runner as DeterministicRunner},
};
use std::{num::NonZeroUsize, sync::Arc, time::Duration};
#[test_traced]
fn successor_barrier_retains_installs_then_retires() {
    let seed = 81;
    let application = MockApplication::new();
    application.pause_building();
    let recovered_application = application.clone();
    let first_hooks = TestHooks::default();
    let recovered_hooks = TestHooks::default();
    let runner = DeterministicRunner::timed(Duration::from_secs(10));
    let ((predecessor, successor, generation, header), checkpoint) =
        runner.start_and_recover(move |context| async move {
            let node =
                NodeBuilder::new(seed, Role::Validator(Participant::new(0)), "successor_node")
                    .attachments(Attachments {
                        application: application.clone(),
                        hooks: first_hooks.clone(),
                        ..Attachments::default()
                    })
                    .production_resolver()
                    .start(&context)
                    .await;
            let (mut data_tx, mut data_rx) = node.peer(2, 0).await;
            application.permit_builds(1);
            let mut exposure = ExposureLedger::default();
            let block = wait_for_slot_block(
                &context,
                &node,
                &mut data_rx,
                &mut exposure,
                ChainId::new(0),
                Height::new(1),
                Participant::new(0),
            )
            .await;
            let header = block.header().clone();
            let first = slot_publications(
                &first_hooks.durable_effects(),
                header.chain(),
                header.height(),
            );
            let first_entries = first.iter().collect::<Vec<_>>();
            let [(predecessor, attempts)] = first_entries.as_slice() else {
                panic!("the signed block did not create one exact obligation: {first:?}");
            };
            let [attempt] = attempts.as_slice() else {
                panic!("the signed-block obligation executed more than once: {attempts:?}");
            };
            assert_eq!(
                attempt.effect,
                DurableEffect::broadcast(Arc::new(Artifact::TransactionBlock(block.clone())))
            );
            let generation = attempt.generation;
            let predecessor = **predecessor;
            let certificate = da_certificate(&node.committee, &header);
            data_tx.send(
                Recipients::One(node.me.clone()),
                node.envelope(DataMessage::<MinPk, Sha256Digest>::DaCertificate(
                    certificate,
                ))
                .encode(),
                false,
            );
            let (successor, successor_attempt) =
                wait_for_live_publication(&context, &first_hooks, |effect| {
                    matches!(effect.broadcast_one(),
                    Some(artifact)
                        if matches!(artifact.as_ref(), Artifact::DaCertificate(certificate)
                            if certificate.header() == &header))
                })
                .await;
            assert!(matches!(
                &successor_attempt.effect.broadcast_one(),
                Some(artifact)
                    if matches!(artifact.as_ref(), Artifact::DaCertificate(certificate)
                        if certificate.header() == &header)
            ));
            wait_for_retirement_ack(&context, &first_hooks, predecessor).await;

            let events = first_hooks.events();
            let installed = events
                .iter()
                .position(
                    |event| matches!(event, TestEvent::Installed { id, .. } if *id == successor),
                )
                .expect("the DA successor was installed during acknowledgement service");
            let retired = events
                .iter()
                .position(
                    |event| matches!(event, TestEvent::Retired(ids) if ids.contains(&predecessor)),
                )
                .expect("the acknowledged predecessor was retired");
            assert!(
                installed < retired,
                "the predecessor retired before its successor was installed"
            );

            node.crash(&context).await;
            (predecessor, successor, generation, header)
        });

    DeterministicRunner::from(checkpoint).start(move |context| async move {
        let node = NodeBuilder::new(seed, Role::Validator(Participant::new(0)), "successor_node")
            .attachments(Attachments {
                application: recovered_application,
                hooks: recovered_hooks.clone(),
                ..Attachments::default()
            })
            .production_resolver()
            .start(&context)
            .await;
        let (_, mut data_rx) = node.peer(2, 0).await;
        wait_for_da_certificate(&context, &node, &mut data_rx, &header).await;
        let recovered = da_certificate_publications(&recovered_hooks.durable_effects());
        let recovered_entries = recovered.iter().collect::<Vec<_>>();
        let [(recovered_id, attempts)] = recovered_entries.as_slice() else {
            panic!("recovery did not reissue one exact DA successor: {recovered:?}");
        };
        assert_eq!(**recovered_id, successor);
        let [attempt] = attempts.as_slice() else {
            panic!("recovery executed the DA successor more than once");
        };
        assert_eq!(attempt.generation, Generation::new(generation.get() + 1));
        assert!(matches!(
            &attempt.effect.broadcast_one(),
            Some(artifact)
                if matches!(artifact.as_ref(), Artifact::DaCertificate(certificate)
                    if certificate.header() == &header)
        ));
        assert!(
            !recovered_hooks.durable_effects().contains_key(&predecessor),
            "recovery reissued the retired predecessor"
        );
    });
}

/// Returns the role that owns publications of `family`.
const fn family_role(family: DischargeFamily) -> Role {
    match family {
        DischargeFamily::ExitReplacedAfter => Role::Observer,
        DischargeFamily::BlockCertifiedAtLeast
        | DischargeFamily::VoteCertifiedAtLeast
        | DischargeFamily::CertificateSupersededAbove
        | DischargeFamily::ViewRetired => Role::Validator(Participant::new(0)),
    }
}

#[derive(Clone)]
enum ActorDischargeSuccessor {
    DaCertificate(TransactionBlockHeader<Sha256Digest>),
    Nullification(View),
    FinalityFloor(View),
}

#[derive(Clone)]
struct PreparedActorDischarge {
    predecessor: EffectId,
    generation: u64,
    successor: ActorDischargeSuccessor,
}

async fn wait_for_publication_ack(
    context: &DeterministicContext,
    hooks: &TestHooks<MinPk, Sha256Digest>,
    publication: EffectId,
) -> BarrierAck {
    let deadline = context.current() + Duration::from_secs(2);
    loop {
        if let Some(ack) = hooks.events().iter().find_map(|event| match event {
            TestEvent::Acknowledged { ack } if ack.cursor().get() >= publication.get() => {
                Some(*ack)
            }
            _ => None,
        }) {
            return ack;
        }
        select! {
            () = context.sleep(Duration::from_millis(10)) => {},
            () = context.sleep_until(deadline) => {
                panic!("publication {publication:?} was not acknowledged");
            },
        }
    }
}

async fn wait_for_later_ack(
    context: &DeterministicContext,
    hooks: &TestHooks<MinPk, Sha256Digest>,
    cursor: Cursor,
) {
    let deadline = context.current() + Duration::from_secs(2);
    loop {
        if hooks
            .events()
            .iter()
            .any(|event| matches!(event, TestEvent::Acknowledged { ack } if ack.cursor() > cursor))
        {
            return;
        }
        select! {
            () = context.sleep(Duration::from_millis(10)) => {},
            () = context.sleep_until(deadline) => {
                panic!("no acknowledgement advanced beyond {cursor:?}");
            },
        }
    }
}

async fn wait_for_retirement_ack(
    context: &DeterministicContext,
    hooks: &TestHooks<MinPk, Sha256Digest>,
    predecessor: EffectId,
) -> BarrierAck {
    let deadline = context.current() + Duration::from_secs(2);
    loop {
        let events = hooks.events();
        let retirement = events.iter().position(
            |event| matches!(event, TestEvent::Retired(retired) if retired.contains(&predecessor)),
        );
        if let Some(retirement) = retirement {
            // Retirements run inside the step of the acknowledgement serviced just before them.
            let ack = events[..retirement]
                .iter()
                .rev()
                .find_map(|event| match event {
                    TestEvent::Acknowledged { ack } => Some(*ack),
                    _ => None,
                })
                .unwrap_or_else(|| {
                    panic!("publication retired before any acknowledgement: {events:?}")
                });
            return ack;
        }
        select! {
            () = context.sleep(Duration::from_millis(10)) => {},
            () = context.sleep_until(deadline) => {
                panic!("publication {predecessor:?} was not retired: {events:?}");
            },
        }
    }
}

fn assert_exact_journal_ack(gates: &TestGates, ack: BarrierAck) -> JournalPoint {
    let point = gates
        .appends()
        .into_iter()
        .find(|point| {
            point.barrier == ack.barrier()
                && point.generation == ack.generation()
                && point.result == ack.cursor()
        })
        .unwrap_or_else(|| panic!("acknowledgement did not name an exact append: {ack:?}"));
    assert!(point.previous.get() < point.result.get());
    point
}

async fn prepare_actor_discharge(
    context: &DeterministicContext,
    node: &Node,
    application: &MockApplication,
    hooks: &TestHooks<MinPk, Sha256Digest>,
    family: DischargeFamily,
) -> PreparedActorDischarge {
    match family {
        DischargeFamily::BlockCertifiedAtLeast
        | DischargeFamily::VoteCertifiedAtLeast
        | DischargeFamily::CertificateSupersededAbove => {
            let (mut data_tx, mut data_rx) = node.peer(1, 0).await;
            application.permit_builds(1);
            let mut exposure = ExposureLedger::default();
            let block = wait_for_slot_block(
                context,
                node,
                &mut data_rx,
                &mut exposure,
                ChainId::new(0),
                Height::new(1),
                Participant::new(0),
            )
            .await;
            let header = block.header().clone();
            let (block_id, block_attempt) = wait_for_live_publication(context, hooks, |effect| {
                matches!(effect.broadcast_one(), Some(artifact)
                    if matches!(artifact.as_ref(), Artifact::TransactionBlock(actual)
                        if actual.header() == &header))
            })
            .await;
            let (vote_id, vote_attempt) = wait_for_live_publication(context, hooks, |effect| {
                matches!(effect.send_one(), Some(request)
                    if matches!(request.artifact().as_ref(), Artifact::DaVote(vote)
                        if vote.header() == &header))
            })
            .await;
            assert_eq!(block_attempt.generation, vote_attempt.generation);

            if !matches!(family, DischargeFamily::CertificateSupersededAbove) {
                let predecessor = if matches!(family, DischargeFamily::BlockCertifiedAtLeast) {
                    block_id
                } else {
                    vote_id
                };
                return PreparedActorDischarge {
                    predecessor,
                    generation: block_attempt.generation.get(),
                    successor: ActorDischargeSuccessor::DaCertificate(header),
                };
            }

            let certificate = da_certificate(&node.committee, &header);
            data_tx.send(
                Recipients::One(node.me.clone()),
                node.envelope(DataMessage::<MinPk, Sha256Digest>::DaCertificate(
                    certificate,
                ))
                .encode(),
                false,
            );
            let (certificate_id, certificate_attempt) =
                wait_for_live_publication(context, hooks, |effect| {
                    matches!(effect.broadcast_one(), Some(artifact)
                        if matches!(artifact.as_ref(), Artifact::DaCertificate(certificate)
                            if certificate.header() == &header))
                })
                .await;
            wait_for_publication_ack(context, hooks, certificate_id).await;
            assert!(
                hooks.live_publications().contains(&certificate_id),
                "a certificate retired at its own height"
            );
            assert!(
                !hooks.live_publications().contains(&block_id)
                    && !hooks.live_publications().contains(&vote_id),
                "the same-height certificate did not replace the block and vote"
            );

            let parent = header.block_ref::<Sha256>();
            let next_header = TransactionBlockHeader::new(
                node.committee.config.epoch(),
                header.chain(),
                Height::new(2),
                parent.digest(),
                Sha256::hash(&[b"strictly higher certificate payload"]),
            )
            .expect("height two extends the certified predecessor");
            let next_block = node.committee.signers[0]
                .sign_transaction_block(next_header.clone())
                .expect("the producer signs its height-two block");
            data_tx.send(
                Recipients::One(node.me.clone()),
                node.envelope(DataMessage::<MinPk, Sha256Digest>::Block(next_block))
                    .encode(),
                false,
            );
            wait_for_live_publication(context, hooks, |effect| {
                matches!(effect.send_one(), Some(request)
                    if matches!(request.artifact().as_ref(), Artifact::DaVote(vote)
                        if vote.header() == &next_header))
            })
            .await;

            PreparedActorDischarge {
                predecessor: certificate_id,
                generation: certificate_attempt.generation.get(),
                successor: ActorDischargeSuccessor::DaCertificate(next_header),
            }
        }
        DischargeFamily::ExitReplacedAfter => {
            let (mut certificates_tx, _) = node.peer(1, 2).await;
            let view = View::new(1);
            certificates_tx.send(
                Recipients::One(node.me.clone()),
                node.envelope(CertificateMessage::<MinPk, Sha256Digest>::Nullification(
                    node.committee.nullification(view),
                ))
                .encode(),
                true,
            );
            let (predecessor, attempt) = wait_for_live_publication(context, hooks, |effect| {
                matches!(effect.broadcast_one(), Some(artifact)
                    if matches!(artifact.as_ref(), Artifact::Nullification(certificate)
                        if certificate.view() == view))
            })
            .await;
            wait_for_publication_ack(context, hooks, predecessor).await;
            wait_for_later_ack(context, hooks, Cursor::new(predecessor.get())).await;
            PreparedActorDischarge {
                predecessor,
                generation: attempt.generation.get(),
                successor: ActorDischargeSuccessor::Nullification(View::new(2)),
            }
        }
        DischargeFamily::ViewRetired => {
            let (_, mut consensus_rx) = node.peer(1, 1).await;
            let deadline = context.current() + Duration::from_secs(2);
            let view = loop {
                let (_, bytes) = expect_before(
                    context,
                    deadline,
                    consensus_rx.recv(),
                    "the timeout did not publish an own-message batch",
                )
                .await
                .expect("network stays up");
                let envelope = Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(
                    bytes,
                    &node.envelope_cfg(node.committee.codec()),
                )
                .expect("canonical consensus envelope");
                match envelope.into_payload() {
                    ConsensusMessage::NoVote(message) => break message.view(),
                    ConsensusMessage::Nullify(message) => break message.view(),
                    _ => {}
                }
            };
            let (predecessor, attempt) = wait_for_live_publication(context, hooks, |effect| {
                matches!(effect.broadcast_many(), Some(artifacts)
                if artifacts.iter().all(|artifact| match artifact.as_ref() {
                    Artifact::NoVote(message) => message.view() == view,
                    Artifact::Nullify(message) => message.view() == view,
                    _ => false,
                }))
            })
            .await;
            PreparedActorDischarge {
                predecessor,
                generation: attempt.generation.get(),
                successor: ActorDischargeSuccessor::FinalityFloor(View::new(view.get() + 1)),
            }
        }
    }
}

async fn submit_actor_discharge_successor(node: &Node, successor: &ActorDischargeSuccessor) {
    match successor {
        ActorDischargeSuccessor::DaCertificate(header) => {
            let (mut data_tx, _) = node.peer(2, 0).await;
            let certificate = da_certificate(&node.committee, header);
            data_tx.send(
                Recipients::One(node.me.clone()),
                node.envelope(DataMessage::<MinPk, Sha256Digest>::DaCertificate(
                    certificate,
                ))
                .encode(),
                false,
            );
        }
        ActorDischargeSuccessor::Nullification(view) => {
            let (mut certificates_tx, _) = node.peer(2, 2).await;
            certificates_tx.send(
                Recipients::One(node.me.clone()),
                node.envelope(CertificateMessage::<MinPk, Sha256Digest>::Nullification(
                    node.committee.nullification(*view),
                ))
                .encode(),
                true,
            );
        }
        ActorDischargeSuccessor::FinalityFloor(view) => {
            let (mut certificates_tx, _) = node.peer(2, 2).await;
            certificates_tx.send(
                Recipients::One(node.me.clone()),
                node.envelope(CertificateMessage::Lqc(node.committee.lqc(*view)))
                    .encode(),
                true,
            );
        }
    }
}

async fn wait_for_successor_publication(
    context: &DeterministicContext,
    hooks: &TestHooks<MinPk, Sha256Digest>,
    successor: &ActorDischargeSuccessor,
) -> Option<EffectId> {
    match successor {
        ActorDischargeSuccessor::DaCertificate(header) => Some(
            wait_for_live_publication(context, hooks, |effect| {
                matches!(effect.broadcast_one(), Some(artifact)
                    if matches!(artifact.as_ref(), Artifact::DaCertificate(certificate)
                        if certificate.header() == header))
            })
            .await
            .0,
        ),
        ActorDischargeSuccessor::Nullification(view) => Some(
            wait_for_live_publication(context, hooks, |effect| {
                matches!(effect.broadcast_one(), Some(artifact)
                    if matches!(artifact.as_ref(), Artifact::Nullification(certificate)
                        if certificate.view() == *view))
            })
            .await
            .0,
        ),
        ActorDischargeSuccessor::FinalityFloor(_) => None,
    }
}

fn assert_pre_ack_publications(
    hooks: &TestHooks<MinPk, Sha256Digest>,
    predecessor: EffectId,
    successor: Option<EffectId>,
) {
    let live = hooks.live_publications();
    assert!(
        live.contains(&predecessor),
        "predecessor retired before its covering BarrierAck: {:?}",
        hooks.events()
    );
    if let Some(successor) = successor {
        assert!(
            live.contains(&successor),
            "replayable successor was not installed before its BarrierAck"
        );
    }
    assert!(
        !hooks.events().iter().any(|event| {
            matches!(event, TestEvent::Retired(retired) if retired.contains(&predecessor))
        }),
        "the exact retiring acknowledgement crossed the sync gate"
    );
}

#[test_traced]
fn all_publication_discharge_families_wait_for_their_exact_barrier_ack() {
    for (index, family) in DischargeFamily::ALL.into_iter().enumerate() {
        let seed = 90 + index as u64;
        DeterministicRunner::timed(Duration::from_secs(15)).start(move |context| async move {
            let application = MockApplication::new();
            application.pause_building();
            let gates = TestGates::default();
            let hooks = TestHooks::default();
            let node = NodeBuilder::new(seed, family_role(family), "publication_ack_node")
                .attachments(Attachments {
                    application: application.clone(),
                    hooks: hooks.clone().with_gates(gates.clone()),
                    ..Attachments::default()
                })
                .production_resolver()
                .limits(move |limits| limits.journal_capacity = Some(NonZeroUsize::MIN))
                .start(&context)
                .await;
            let prepared =
                prepare_actor_discharge(&context, &node, &application, &hooks, family).await;

            let mut gate = gates.arm_next_after_sync();
            submit_actor_discharge_successor(&node, &prepared.successor).await;
            select! {
                () = gate.wait_entered() => {},
                () = context.sleep(Duration::from_secs(2)) => {
                    panic!("{family:?} did not reach its successor sync cut");
                },
            }
            let successor =
                wait_for_successor_publication(&context, &hooks, &prepared.successor).await;
            assert_pre_ack_publications(&hooks, prepared.predecessor, successor);

            gate.release();
            let ack = wait_for_retirement_ack(&context, &hooks, prepared.predecessor).await;
            let point = assert_exact_journal_ack(&gates, ack);
            if let Some(successor) = successor {
                assert!(
                    point.previous.get() < successor.get() && successor.get() <= point.result.get(),
                    "{family:?} retired on a barrier that did not cover its successor"
                );
                assert!(hooks.live_publications().contains(&successor));
            }
            assert!(!hooks.live_publications().contains(&prepared.predecessor));
        });
    }
}

#[test_traced]
fn resolver_retention_obeys_its_signature_exposure_boundary() {
    let seed = 110;
    DeterministicRunner::timed(Duration::from_secs(10)).start(move |context| async move {
        let application = MockApplication::new();
        application.pause_building();
        let gates = TestGates::default();
        let hooks = TestHooks::default();
        let node = NodeBuilder::new(seed, Role::Observer, "resolver_retention_node")
            .attachments(Attachments {
                application,
                hooks: hooks.clone().with_gates(gates.clone()),
                ..Attachments::default()
            })
            .production_resolver()
            .start(&context)
            .await;
        let (mut certificates_tx, _) = node.peer(1, 2).await;
        // Holding every new sync proves neither independently verifiable proof needs its own
        // metadata acknowledgement. This observer has no fresh local signature exposure.
        let _sync = gates.arm_next_start_sync();
        let first_view = View::new(1);
        certificates_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(CertificateMessage::<MinPk, Sha256Digest>::Nullification(
                node.committee.nullification(first_view),
            ))
            .encode(),
            true,
        );
        let deadline = context.current() + Duration::from_secs(2);
        loop {
            if hooks.events().iter().any(|event| {
                matches!(event, TestEvent::Retained {
                object: ViewProof::Nullification(certificate),
                boundary: RetentionBoundary::Staged(_),
            } if certificate.view() == first_view)
            }) {
                break;
            }
            assert!(
                context.current() < deadline,
                "forwarded nullification never entered custody"
            );
            context.sleep(Duration::from_millis(1)).await;
        }
        let lqc_view = View::new(3);
        certificates_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(CertificateMessage::Lqc(node.committee.lqc(lqc_view)))
                .encode(),
            true,
        );
        let deadline = context.current() + Duration::from_secs(2);
        loop {
            let events = hooks.events();
            let forwarded = events.iter().any(|event| {
                matches!(event, TestEvent::Retained {
                object: ViewProof::Nullification(certificate),
                boundary: RetentionBoundary::Staged(_),
            } if certificate.view() == first_view)
            });
            let floor = events.iter().any(|event| {
                matches!(event, TestEvent::Retained {
                object: ViewProof::Lqc(certificate),
                boundary: RetentionBoundary::Exposure,
            } if certificate.view() == lqc_view)
            });
            if forwarded && floor {
                break;
            }
            select! {
                () = context.sleep(Duration::from_millis(1)) => {},
                () = context.sleep_until(deadline) => {
                    panic!("resolver proofs waited for reconstructible metadata durability");
                },
            }
        }
    });
}

#[test_traced]
fn crash_after_successor_append_releases_only_recovered_successors() {
    for (index, family) in DischargeFamily::ALL.into_iter().enumerate() {
        let seed = 100 + index as u64;
        let application = MockApplication::new();
        application.pause_building();
        let recovered_application = application.clone();
        let first_gates = TestGates::default();
        let first_hooks = TestHooks::default();
        let runner = DeterministicRunner::timed(Duration::from_secs(15));
        let ((prepared, successor), checkpoint) =
            runner.start_and_recover(move |context| async move {
                let node = NodeBuilder::new(seed, family_role(family), "publication_recovery_node")
                    .attachments(Attachments {
                        application: application.clone(),
                        hooks: first_hooks.clone().with_gates(first_gates.clone()),
                        ..Attachments::default()
                    })
                    .production_resolver()
                    .limits(move |limits| limits.journal_capacity = Some(NonZeroUsize::MIN))
                    .start(&context)
                    .await;
                let prepared =
                    prepare_actor_discharge(&context, &node, &application, &first_hooks, family)
                        .await;
                let mut gate = first_gates.arm_after_sync_retiring(prepared.predecessor);
                submit_actor_discharge_successor(&node, &prepared.successor).await;
                let successor = if matches!(
                    &prepared.successor,
                    ActorDischargeSuccessor::FinalityFloor(_)
                ) {
                    None
                } else {
                    wait_for_successor_publication(&context, &first_hooks, &prepared.successor)
                        .await
                };
                select! {
                    () = gate.wait_entered() => {},
                    () = context.sleep(Duration::from_secs(2)) => {
                        panic!("{family:?} did not reach its exact crash-after-sync cut");
                    },
                }
                assert_pre_ack_publications(&first_hooks, prepared.predecessor, successor);
                node.crash(&context).await;
                drop(gate);
                (prepared, successor)
            });

        let recovered_gates = TestGates::default();
        let recovered_hooks = TestHooks::default();
        let mut generation_gate = recovered_gates.arm_next_after_sync();
        DeterministicRunner::from(checkpoint).start(move |context| async move {
            let mut start = Box::pin(
                NodeBuilder::new(seed, family_role(family), "publication_recovery_node")
                    .attachments(Attachments {
                        application: recovered_application,
                        hooks: recovered_hooks.clone().with_gates(recovered_gates.clone()),
                        ..Attachments::default()
                    })
                    .production_resolver()
                    .limits(move |limits| limits.journal_capacity = Some(NonZeroUsize::MIN))
                    .start(&context),
            );
            select! {
                () = generation_gate.wait_entered() => {},
                _node = &mut start => {
                    panic!("{family:?} became ready before recovery generation ack");
                },
                () = context.sleep(Duration::from_secs(2)) => {
                    panic!("{family:?} did not stage its recovery generation");
                },
            }
            assert!(
                recovered_hooks.live_publications().is_empty(),
                "recovery exposed a publication before its generation ack"
            );
            assert!(
                !recovered_hooks.events().iter().any(|event| {
                    matches!(event, TestEvent::Retired(retired)
                        if retired.contains(&prepared.predecessor))
                }),
                "recovery retired a volatile predecessor before its generation ack"
            );
            let generation_point = recovered_gates
                .appends()
                .into_iter()
                .last()
                .expect("recovery appended its generation advance");
            assert_eq!(
                generation_point.generation,
                Generation::new(prepared.generation)
            );
            generation_gate.release();
            let _node = start.await;

            let generation_ack = recovered_hooks
                .events()
                .iter()
                .find_map(|event| match event {
                    TestEvent::Acknowledged { ack }
                        if ack.barrier() == generation_point.barrier =>
                    {
                        Some(*ack)
                    }
                    _ => None,
                })
                .expect("startup waited for the recovery generation ack");
            assert_eq!(
                generation_ack,
                BarrierAck::new(
                    generation_point.barrier,
                    generation_point.generation,
                    generation_point.result,
                )
            );
            assert!(
                !recovered_hooks
                    .live_publications()
                    .contains(&prepared.predecessor)
            );
            if let Some(successor) = successor {
                let recovered =
                    wait_for_successor_publication(&context, &recovered_hooks, &prepared.successor)
                        .await;
                assert_eq!(recovered, Some(successor));
                let attempts = recovered_hooks.durable_effects();
                assert_eq!(attempts[&successor].len(), 1);
                assert_eq!(
                    attempts[&successor][0].generation,
                    Generation::new(prepared.generation + 1)
                );
            }
        });
    }
}
