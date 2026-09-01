//! White-box tests of the ingress actor internals.

use crate::{
    Epochable as _,
    multimmit::{
        actors::{
            ingress::{
                Config, IngressLimits,
                actor::{Actor, Arrival, Ingress},
                lanes::{Group, LaneId},
                receiver::{IngressOutcome, InvalidIngress},
            },
            voter::{self, Inbox},
        },
        mocks::Committee,
        types::{Artifact, ChainId},
        wire::{ConsensusMessage, Envelope, EnvelopeConfig, Plane},
    },
    types::{Participant, View},
};
use bytes::Bytes;
use commonware_codec::{Decode as _, Encode as _};
use commonware_cryptography::{Hasher, Sha256, bls12381::primitives::variant::MinPk, ed25519};
use commonware_p2p::Receiver;
use commonware_parallel::{Rayon, Sequential, Strategy, mocks};
use commonware_runtime::{Clock as _, IoBuf, Runner as _, Supervisor as _, deterministic};
use futures::FutureExt as _;
use std::{collections::VecDeque, future::pending, num::NonZeroUsize, sync::Arc};

type IngressActor<H = Sha256, T = Sequential> =
    Actor<deterministic::Context, H, ed25519::PublicKey, MinPk, T, Sequential>;

type TestIngress = Ingress<
    deterministic::Context,
    Sha256,
    ed25519::PublicKey,
    MinPk,
    Sequential,
    Sequential,
    RawReceiver,
    RawReceiver,
    RawReceiver,
>;

fn ingress_actor<H: Hasher<Digest = <Sha256 as Hasher>::Digest>, T: Strategy>(
    context: deterministic::Context,
    committee: &Committee<MinPk>,
    strategy: T,
) -> IngressActor<H, T> {
    Actor::new(
        context,
        Config {
            epoch: committee.config.epoch(),
            participants: Arc::new(committee.verifier.participants().clone()),
            strategy,
            critical_strategy: Sequential,
            codec: committee.codec(),
            bounds: committee
                .codec()
                .encoded_bounds::<MinPk, <Sha256 as Hasher>::Digest>()
                .unwrap(),
            limits: IngressLimits {
                cohort_items: NonZeroUsize::new(2).unwrap(),
                ..IngressLimits::TEST
            },
            mailbox_size: NonZeroUsize::new(4).unwrap(),
            observation_capacity: NonZeroUsize::MIN,
        },
    )
    .0
}

/// Builds the running state over closed network receivers, so only pushed jobs complete.
fn idle_ingress(actor: &IngressActor) -> TestIngress {
    actor.ingress(
        RawReceiver::default(),
        RawReceiver::default(),
        RawReceiver::default(),
    )
}

fn ready(
    peer: &ed25519::PublicKey,
    lane: LaneId,
    artifact: Artifact<MinPk, <Sha256 as Hasher>::Digest>,
    received_at: std::time::SystemTime,
) -> IngressOutcome<ed25519::PublicKey, MinPk, <Sha256 as Hasher>::Digest> {
    IngressOutcome::Ready {
        peer: peer.clone(),
        lane,
        group: Group::one(artifact.identify::<Sha256>(&mut Vec::new()), received_at),
    }
}

#[test]
fn ready_ingress_batches_before_flush_without_waiting() {
    for (capacity, ready_count, pending_tail) in
        [(1, 1, false), (4, 4, false), (4, 2, true), (4, 5, false)]
    {
        deterministic::Runner::default().start(move |context| async move {
            let committee = Committee::<MinPk>::builder(40, 6).build();
            let actor =
                ingress_actor::<Sha256, _>(context.child("batcher"), &committee, Sequential);
            let mut ingress = idle_ingress(&actor);
            let mut expected_bytes = 0;
            let admitted = ready_count.min(capacity);
            let now = context.current();
            for view in 0..ready_count {
                let artifact = Artifact::NoVote(
                    committee.novote(Participant::new(1), View::new(view as u64 + 1)),
                );
                if view < admitted {
                    expected_bytes += artifact.encoded_len();
                }
                ingress.consensus.jobs.push(std::future::ready(ready(
                    &committee.identities[1],
                    LaneId::Consensus,
                    artifact,
                    now,
                )));
            }
            if pending_tail {
                ingress.consensus.jobs.push(pending());
            }
            let first = ingress
                .consensus
                .jobs
                .next_completed()
                .now_or_never()
                .expect("first completion is ready");
            ingress
                .drain_ready(
                    Arrival {
                        plane: Plane::Consensus,
                        outcome: first,
                    },
                    capacity,
                    &actor.metrics,
                )
                .unwrap();
            assert_eq!(ingress.lanes.items(), admitted);
            assert_eq!(
                ingress.consensus.jobs.len(),
                ready_count - admitted + usize::from(pending_tail)
            );
            assert_eq!(context.current(), now);

            let (
                voter,
                Inbox {
                    mut observations, ..
                },
            ) = voter::Mailbox::new(&context.child("voter"), &context, NonZeroUsize::MIN);
            let voter = voter.into_endpoints().observations;
            let mut forwarded = 0;
            let mut bytes = 0;
            while ingress.lanes.items() > 0 {
                ingress.flush(&context, &voter, &actor.metrics).unwrap();
                assert_eq!(ingress.inflight, 1);
                let cohort = observations
                    .try_recv()
                    .expect("ready ingress flushes with credit");
                assert_eq!(cohort.artifacts.len(), (admitted - forwarded).min(2));
                assert_eq!(cohort.plane, Plane::Consensus);
                forwarded += cohort.artifacts.len();
                bytes += cohort.bytes;
                ingress.flush(&context, &voter, &actor.metrics).unwrap();
                assert!(
                    observations.try_recv().is_err(),
                    "held credit prevents another cohort"
                );
                assert_eq!(ingress.lanes.items(), admitted - forwarded);
                ingress.consume(1).unwrap();
            }
            assert_eq!(forwarded, admitted);
            assert_eq!(bytes, expected_bytes);
            assert_eq!(context.current(), now);
            assert!(
                ingress.consume(1).is_err(),
                "a credit beyond the cohorts in flight is fatal"
            );
        });
    }
}

#[test]
fn ready_ingress_rotates_after_invalid_results_and_stops_at_budget() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(40, 6).build();
        let actor = ingress_actor::<Sha256, _>(context.child("batcher"), &committee, Sequential);
        let mut ingress = idle_ingress(&actor);
        let now = context.current();
        let peer = committee.identities[1].clone();
        for view in 2..=3 {
            ingress.consensus.jobs.push(std::future::ready(ready(
                &peer,
                LaneId::Consensus,
                Artifact::NoVote(committee.novote(Participant::new(1), View::new(view))),
                now,
            )));
        }
        ingress
            .certificates
            .jobs
            .push(std::future::ready(IngressOutcome::Invalid {
                reason: InvalidIngress::Decode,
            }));
        ingress.certificates.jobs.push(std::future::ready(ready(
            &peer,
            LaneId::Certificate,
            Artifact::Vqc(committee.vqc(View::new(1))),
            now,
        )));
        ingress.data.jobs.push(std::future::ready(ready(
            &peer,
            LaneId::Data(0),
            Artifact::TransactionBlock(
                committee.signed_block(ChainId::new(1), Sha256::hash(&[b"data"])),
            ),
            now,
        )));
        ingress.data.jobs.push(pending());
        let first = ready(
            &peer,
            LaneId::Consensus,
            Artifact::NoVote(committee.novote(Participant::new(1), View::new(1))),
            now,
        );
        ingress
            .drain_ready(
                Arrival {
                    plane: Plane::Consensus,
                    outcome: first,
                },
                3,
                &actor.metrics,
            )
            .unwrap();
        assert_eq!(ingress.next, Plane::Consensus);
        assert_eq!(ingress.lanes.items(), 2);
        assert_eq!(
            (
                ingress.consensus.jobs.len(),
                ingress.certificates.jobs.len(),
                ingress.data.jobs.len()
            ),
            (2, 1, 1)
        );
        let first = ingress
            .consensus
            .jobs
            .next_completed()
            .now_or_never()
            .unwrap();
        ingress
            .drain_ready(
                Arrival {
                    plane: Plane::Consensus,
                    outcome: first,
                },
                4,
                &actor.metrics,
            )
            .unwrap();
        assert_eq!(ingress.next, Plane::Certificate);
        assert_eq!(ingress.lanes.items(), 5);
        assert_eq!(
            (
                ingress.consensus.jobs.len(),
                ingress.certificates.jobs.len(),
                ingress.data.jobs.len()
            ),
            (0, 0, 1)
        );
        assert_eq!(context.current(), now);
    });
}

#[test]
fn ready_ingress_propagates_worker_panics() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(40, 6).build();
        let actor = ingress_actor::<Sha256, _>(context.child("batcher"), &committee, Sequential);
        let mut ingress = idle_ingress(&actor);
        assert!(
            ingress
                .drain_ready(
                    Arrival {
                        plane: Plane::Consensus,
                        outcome: IngressOutcome::Panicked,
                    },
                    4,
                    &actor.metrics,
                )
                .is_err()
        );
        assert_eq!(ingress.lanes.items(), 0);

        ingress
            .consensus
            .jobs
            .push(std::future::ready(IngressOutcome::Panicked));
        let first = ready(
            &committee.identities[1],
            LaneId::Consensus,
            Artifact::NoVote(committee.novote(Participant::new(1), View::new(1))),
            context.current(),
        );
        assert!(
            ingress
                .drain_ready(
                    Arrival {
                        plane: Plane::Consensus,
                        outcome: first,
                    },
                    4,
                    &actor.metrics,
                )
                .is_err()
        );
        assert_eq!(ingress.lanes.items(), 1);
        assert!(ingress.consensus.jobs.is_empty());
    });
}

#[derive(Debug, Default)]
struct RawReceiver(VecDeque<(ed25519::PublicKey, IoBuf)>);

impl Receiver for RawReceiver {
    type Error = std::io::Error;
    type PublicKey = ed25519::PublicKey;

    async fn recv(&mut self) -> Result<(Self::PublicKey, IoBuf), Self::Error> {
        self.0
            .pop_front()
            .ok_or_else(|| std::io::ErrorKind::UnexpectedEof.into())
    }
}

#[test]
fn ingress_envelope_shares_payload_buffer() {
    let payload = Bytes::from(vec![42; 96]);
    let epoch = crate::types::Epoch::new(1);
    let encoded = Envelope::new(epoch, payload.clone()).encode();
    let expected = encoded[encoded.len() - payload.len()..].as_ptr();
    let decoded = Envelope::<Bytes>::decode_cfg(
        IoBuf::from(encoded.clone()),
        &EnvelopeConfig {
            max_frame_bytes: encoded.len(),
            epoch,
            payload: (..=payload.len()).into(),
        },
    )
    .unwrap()
    .into_payload();
    assert_eq!(decoded, payload);
    assert_eq!(decoded.as_ptr(), expected);
}

#[test]
fn ingress_reports_one_outcome_per_frame() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(40, 6).build();
        let actor = ingress_actor::<Sha256, _>(context.child("batcher"), &committee, Sequential);
        let parent = committee.vqc(View::new(1));
        let block = committee.leader_block_with_parent(View::new(2), &parent);
        let frame = Envelope::new(
            committee.config.epoch(),
            ConsensusMessage::Proposal {
                parent: Some(Box::new(parent)),
                block: Box::new(block),
            },
        )
        .encode();
        let peer = committee.identities[1].clone();
        let raw = RawReceiver(VecDeque::from([
            (peer.clone(), IoBuf::from(frame)),
            (peer.clone(), IoBuf::from(Bytes::from_static(b"invalid"))),
        ]));
        let mut receiver = actor.receiver(raw, Plane::Consensus, actor.strategy.clone());
        let Some(IngressOutcome::Ready {
            peer: from,
            lane,
            group,
        }) = receiver.recv().await
        else {
            panic!("the proposal frame decodes");
        };
        assert_eq!(from, peer);
        assert_eq!(lane, LaneId::Consensus);
        assert_eq!(group.len(), 2);
        assert!(matches!(
            receiver.recv().await,
            Some(IngressOutcome::Invalid {
                reason: InvalidIngress::Decode
            })
        ));
        assert!(receiver.recv().await.is_none());
    });
}

#[test]
fn leader_ingress_progresses_while_data_workers_are_occupied() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(40, 6).build();
        let strategy = rayon();
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let manual = strategy.manual();
        let blockers = (0..2)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                manual.spawn(1, move |_| {
                    barrier.wait();
                    barrier.wait();
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let actor = ingress_actor::<Sha256, _>(context.child("batcher"), &committee, strategy);
        let raw = || {
            RawReceiver(VecDeque::from([(
                committee.identities[1].clone(),
                IoBuf::from(Bytes::from_static(b"invalid")),
            )]))
        };
        let mut data = actor.receiver(raw(), Plane::Data, actor.strategy.clone());
        let mut consensus =
            actor.receiver(raw(), Plane::Consensus, actor.critical_strategy.clone());
        let mut certificates =
            actor.receiver(raw(), Plane::Certificate, actor.critical_strategy.clone());
        let data_waiting = data.recv().now_or_never().is_none();
        let consensus_result = consensus.recv().now_or_never();
        let certificate_result = certificates.recv().now_or_never();
        barrier.wait();
        futures::executor::block_on(futures::future::join_all(blockers));
        assert!(data_waiting);
        for result in [consensus_result, certificate_result] {
            assert!(matches!(
                result,
                Some(Some(IngressOutcome::Invalid {
                    reason: InvalidIngress::Decode
                }))
            ));
        }
        assert!(matches!(
            data.recv().await,
            Some(IngressOutcome::Invalid {
                reason: InvalidIngress::Decode
            })
        ));
    });
}

#[test]
fn cancelled_ingress_receives_preserve_each_planes_capacity() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(40, 6).build();
        let strategy = rayon();
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let manual = strategy.manual();
        let blockers = (0..2)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                manual.spawn(1, move |_| {
                    barrier.wait();
                    barrier.wait();
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let actor = ingress_actor::<Sha256, _>(context.child("batcher"), &committee, strategy);
        let peer = committee.identities[1].clone();
        let mut receivers = Plane::ALL.map(|plane| {
            let raw = RawReceiver(
                (0..3)
                    .map(|_| (peer.clone(), IoBuf::from(Bytes::from_static(b"invalid"))))
                    .collect(),
            );
            actor.receiver(raw, plane, actor.strategy.clone())
        });
        for _ in 0..4 {
            for receiver in &mut receivers {
                assert!(receiver.recv().now_or_never().is_none());
                assert_eq!(receiver.jobs.len(), 2);
                assert_eq!(receiver.receiver.0.len(), 1);
            }
        }
        assert_eq!(
            receivers
                .iter()
                .map(|receiver| receiver.jobs.len())
                .sum::<usize>(),
            6
        );
        barrier.wait();
        futures::executor::block_on(futures::future::join_all(blockers));
        for receiver in &mut receivers {
            for _ in 0..2 {
                assert!(matches!(
                    futures::executor::block_on(receiver.jobs.next_completed()),
                    IngressOutcome::Invalid {
                        reason: InvalidIngress::Decode
                    }
                ));
            }
            assert!(receiver.jobs.is_empty());
            assert_eq!(receiver.receiver.0.len(), 1);
        }
    });
}

#[test]
fn closed_ingress_drains_owned_completion_after_cancellation() {
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(40, 6).build();
        let actor = ingress_actor::<Sha256, _>(
            context.child("batcher"),
            &committee,
            mocks::inline(NonZeroUsize::new(2).unwrap()),
        );
        let mut receiver = actor.receiver(
            RawReceiver::default(),
            Plane::Consensus,
            actor.strategy.clone(),
        );
        let (send, receive) = futures::channel::oneshot::channel();
        receiver.jobs.push(async { receive.await.unwrap() });
        for _ in 0..4 {
            assert!(receiver.recv().now_or_never().is_none());
            assert!(receiver.closed);
            assert_eq!(receiver.jobs.len(), 1);
        }
        assert!(
            send.send(IngressOutcome::Invalid {
                reason: InvalidIngress::Decode
            })
            .is_ok()
        );
        assert!(matches!(
            receiver.recv().await,
            Some(IngressOutcome::Invalid {
                reason: InvalidIngress::Decode
            })
        ));
        assert!(receiver.jobs.is_empty());
        assert!(receiver.recv().await.is_none());
    });
}

#[derive(Default)]
struct PanickingHasher;

impl Hasher for PanickingHasher {
    type Digest = <Sha256 as Hasher>::Digest;
    fn hash(_: &[&[u8]]) -> Self::Digest {
        panic!("identification panic")
    }
    fn hash_pair(_: &[&[u8]], _: &[&[u8]]) -> (Self::Digest, Self::Digest) {
        panic!("identification panic")
    }
    fn update(&mut self, _: &[u8]) -> &mut Self {
        panic!("identification panic")
    }
    fn finalize(self) -> (Self, Self::Digest) {
        panic!("identification panic")
    }
}

#[test]
fn ingress_catches_inline_and_offloaded_identification_panics() {
    for strategy in [mocks::inline(NonZeroUsize::MIN), rayon()] {
        deterministic::Runner::default().start(move |context| async move {
            let committee = Committee::<MinPk>::builder(40, 6).build();
            let actor = ingress_actor::<PanickingHasher, _>(
                context.child("batcher"),
                &committee,
                strategy.clone(),
            );
            let frame = Envelope::new(
                committee.config.epoch(),
                ConsensusMessage::<MinPk, <Sha256 as Hasher>::Digest>::NoVote(
                    committee.novote(Participant::new(1), View::new(1)),
                ),
            )
            .encode();
            let raw = RawReceiver(VecDeque::from([(
                committee.identities[1].clone(),
                IoBuf::from(frame),
            )]));
            let mut receiver = actor.receiver(raw, Plane::Consensus, actor.strategy.clone());
            // Driving from a pool member lets Rayon execute the job without an external wake.
            let outcome = strategy
                .manual()
                .spawn(1, move |_| futures::executor::block_on(receiver.recv()));
            let result = futures::executor::block_on(outcome);
            assert!(matches!(result, Some(IngressOutcome::Panicked)));
        });
    }
}

fn rayon() -> Rayon {
    Rayon::new(NonZeroUsize::new(2).unwrap()).expect("compute pool starts")
}
