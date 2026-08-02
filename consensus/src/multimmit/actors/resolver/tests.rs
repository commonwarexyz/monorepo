use super::{Actor, Config, ControlOverflow, Message, Query, ResolveRequest, Served, actor::State};
use crate::{
    multimmit::{
        config::Limits,
        machine::ResolutionJob,
        mocks::{
            Committee, RecordingBlocker,
            cluster::{QUOTA, link_all, start_network},
        },
    },
    types::{Epoch, Round, View},
};
use bytes::{Bytes, BytesMut};
use commonware_actor::mailbox::{self, Overflow as _, Policy as _};
use commonware_codec::{Decode as _, Encode as _, ReadExt as _, Write as _};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, sha256::Digest};
use commonware_macros::select;
use commonware_p2p::{Receiver as _, Recipients, Sender as _};
use commonware_parallel::{Rayon, Sequential, Strategy};
use commonware_runtime::{Clock as _, Runner as _, Supervisor as _, deterministic::Runner};
use commonware_utils::{
    channel::oneshot,
    sequence::U64,
    sync::{Condvar, Mutex},
};
use std::{collections::BTreeMap, num::NonZeroUsize, sync::Arc, time::Duration};
use tracing::{Id, Span, Subscriber};
use tracing_subscriber::{Layer, layer::Context as LayerContext, prelude::*, registry::LookupSpan};

#[derive(Clone)]
struct TraceNode {
    id: Id,
    parent: Option<Id>,
}

#[derive(Clone)]
struct TraceParentLayer {
    spans: Arc<Mutex<BTreeMap<String, TraceNode>>>,
}

impl<S> Layer<S> for TraceParentLayer
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_new_span(
        &self,
        attributes: &tracing::span::Attributes<'_>,
        id: &Id,
        context: LayerContext<'_, S>,
    ) {
        let name = attributes.metadata().name();
        if !matches!(
            name,
            "test.resolver.request"
                | "multimmit.resolver.resolve.process"
                | "multimmit.resolver.resolve.materialize"
                | "multimmit.resolver.resolve.complete"
        ) {
            return;
        }
        let parent = context
            .span(id)
            .and_then(|span| span.parent().map(|parent| parent.id()));
        self.spans.lock().insert(
            name.to_string(),
            TraceNode {
                id: id.clone(),
                parent,
            },
        );
    }
}

#[derive(Default)]
struct CodecGateState {
    started: usize,
    finished: usize,
    released: bool,
}

#[derive(Default)]
struct CodecGate {
    state: Mutex<CodecGateState>,
    changed: Condvar,
}

impl CodecGate {
    fn block(&self) {
        let mut state = self.state.lock();
        state.started += 1;
        self.changed.notify_all();
        while !state.released {
            self.changed.wait(&mut state);
        }
        state.finished += 1;
        self.changed.notify_all();
    }

    fn wait_started(&self, count: usize) {
        let mut state = self.state.lock();
        while state.started < count {
            self.changed.wait(&mut state);
        }
    }

    fn release(&self) {
        let mut state = self.state.lock();
        state.released = true;
        self.changed.notify_all();
    }

    fn wait_finished(&self, count: usize) {
        let mut state = self.state.lock();
        while state.finished < count {
            self.changed.wait(&mut state);
        }
    }
}

fn committee() -> Committee<MinPk> {
    Committee::new(7, 6, Limits::new(2, 1).unwrap())
}

fn resolver_response(
    request: impl AsRef<[u8]>,
    requested: View,
    proof: Served<MinPk, Digest>,
) -> Bytes {
    let mut request = request.as_ref();
    let id = u64::read(&mut request).expect("resolver request id");
    assert_eq!(u8::read(&mut request).expect("resolver request tag"), 0);
    assert_eq!(
        u64::from(U64::read(&mut request).expect("resolver request view")),
        requested.get()
    );
    assert!(request.is_empty());

    let mut response = BytesMut::new();
    id.write(&mut response);
    1u8.write(&mut response);
    proof.encode().write(&mut response);
    response.freeze()
}

#[test]
fn serve_overflow_does_not_retain_queries() {
    Runner::default().start(|context| async move {
        let (sender, _queries): (
            commonware_actor::mailbox::UnreliableSender<Query<MinPk, Digest>>,
            _,
        ) = commonware_actor::mailbox::new_unreliable(
            context.child("serve_queries"),
            NonZeroUsize::MIN,
        );
        let (first, _first_response) = oneshot::channel();
        assert!(
            sender
                .enqueue(Query::<MinPk, Digest>::Serve {
                    view: View::zero(),
                    responder: first,
                })
                .accepted()
        );

        let (overflow, overflow_response) = oneshot::channel();
        assert!(
            sender
                .enqueue(Query::<MinPk, Digest>::Serve {
                    view: View::zero(),
                    responder: overflow,
                })
                .is_rejected()
        );
        assert!(overflow_response.await.is_err());
    });
}

#[test]
fn proof_codec_round_trip() {
    let committee = committee();
    let codec = committee.codec();
    let proofs = [
        Served::Nullification(Box::new(committee.nullification(1))),
        Served::Vqc(Box::new(committee.vqc(2))),
        Served::Lqc(Box::new(committee.lqc(3))),
    ];

    for proof in proofs {
        let encoded = proof.encode();
        let decoded = Served::<MinPk, Digest>::decode_cfg(encoded, &codec).unwrap();
        assert_eq!(decoded, proof);
    }
}

#[test]
fn proof_codec_rejects_unknown_tag() {
    let committee = committee();
    assert!(Served::<MinPk, Digest>::decode_cfg([3].as_slice(), &committee.codec()).is_err());
}

#[test]
fn state_prefers_covering_lqc() {
    let committee = committee();
    let mut state = State::default();
    state.retain(Served::Vqc(Box::new(committee.vqc(2))));
    let floor = committee.lqc(4);
    state.retain(Served::Lqc(Box::new(floor.clone())));

    assert_eq!(
        state.proof(View::new(2)).as_deref(),
        Some(&Served::Lqc(Box::new(floor)))
    );
    assert!(state.proof(View::new(5)).is_none());
}

#[test]
fn state_prefers_vqc_to_nullification() {
    let committee = committee();
    let mut state = State::default();
    let nullification = committee.nullification(2);
    let vqc = committee.vqc(2);

    state.retain(Served::Nullification(Box::new(nullification)));
    state.retain(Served::Vqc(Box::new(vqc.clone())));
    state.retain(Served::Nullification(Box::new(committee.nullification(2))));

    assert_eq!(
        state.proof(View::new(2)).as_deref(),
        Some(&Served::Vqc(Box::new(vqc)))
    );
}

#[test]
fn state_prunes_exact_exits_but_keeps_floor() {
    let committee = committee();
    let mut state = State::default();
    let floor = committee.lqc(2);
    state.retain(Served::Lqc(Box::new(floor.clone())));
    state.retain(Served::Vqc(Box::new(committee.vqc(3))));
    state.prune(View::new(3));

    assert_eq!(
        state.proof(View::new(1)).as_deref(),
        Some(&Served::Lqc(Box::new(floor)))
    );
    assert!(state.proof(View::new(3)).is_none());
    state.retain(Served::Nullification(Box::new(committee.nullification(3))));
    assert!(state.proof(View::new(3)).is_none());
}

#[test]
fn local_cache_materialization_keeps_request_trace_parent() {
    let spans = Arc::new(Mutex::new(BTreeMap::new()));
    let subscriber = tracing_subscriber::registry().with(TraceParentLayer {
        spans: Arc::clone(&spans),
    });

    tracing::subscriber::with_default(subscriber, || {
        Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let committee = committee();
            let local = committee.identities[0].clone();
            let peer = committee.identities[1].clone();
            let oracle =
                start_network(&context, vec![local.clone(), peer.clone()], 2 * 1024 * 1024).await;
            link_all(&oracle, &[local.clone(), peer.clone()]).await;
            let network = oracle
                .control(local.clone())
                .register(3, QUOTA)
                .await
                .expect("resolver network registered");
            let (actor, endpoints): (Actor<_, Sha256, _, MinPk, _, _>, _) = Actor::new(
                context.child("resolver"),
                Config {
                    peers: vec![local.clone(), peer],
                    me: Some(local),
                    blocker: RecordingBlocker::default(),
                    epoch: committee.config.epoch(),
                    codec: committee.codec(),
                    strategy: Sequential,
                    fetch_timeout: Duration::from_secs(1),
                    mailbox_size: NonZeroUsize::new(8).unwrap(),
                },
            );
            let (voter, mut voter_receiver) =
                mailbox::new(context.child("voter"), NonZeroUsize::new(8).unwrap());
            let task = actor.start(voter, network);

            let view = View::new(3);
            let proof = Served::Vqc(Box::new(committee.vqc(view.get())));
            assert!(
                endpoints
                    .control
                    .enqueue(Message::Retain { proof })
                    .accepted()
            );
            let request = tracing::info_span!(parent: None, "test.resolver.request");
            assert!(
                endpoints
                    .control
                    .enqueue(Message::Resolve(ResolveRequest {
                        span: request,
                        round: Round::new(committee.config.epoch(), view),
                        job: ResolutionJob::fabricate(7, 11, view),
                    }))
                    .accepted()
            );
            let crate::multimmit::actors::voter::Message::Resolution { .. } =
                voter_receiver.recv().await.expect("cached proof completes");

            {
                let spans = spans.lock();
                let request = spans.get("test.resolver.request").expect("request span");
                let process = spans
                    .get("multimmit.resolver.resolve.process")
                    .expect("process span");
                let materialize = spans
                    .get("multimmit.resolver.resolve.materialize")
                    .expect("materialize span");
                let complete = spans
                    .get("multimmit.resolver.resolve.complete")
                    .expect("completion span");
                assert_eq!(process.parent.as_ref(), Some(&request.id));
                assert_eq!(materialize.parent.as_ref(), Some(&process.id));
                assert_eq!(complete.parent.as_ref(), Some(&materialize.id));
            }

            task.abort();
            let _ = task.await;
        });
    });
}

#[test]
fn stalled_codec_worker_keeps_control_and_queries_live() {
    Runner::timed(Duration::from_secs(10)).start(|context| async move {
        let committee = committee();
        let local = committee.identities[0].clone();
        let peer = committee.identities[1].clone();
        let oracle =
            start_network(&context, vec![local.clone(), peer.clone()], 2 * 1024 * 1024).await;
        link_all(&oracle, &[local.clone(), peer.clone()]).await;
        let network = oracle
            .control(local.clone())
            .register(3, QUOTA)
            .await
            .expect("resolver network registered");
        let strategy = Rayon::new(NonZeroUsize::new(2).unwrap()).expect("codec pool starts");
        let gate = Arc::new(CodecGate::default());
        let first_blocker = {
            let gate = Arc::clone(&gate);
            strategy.spawn(move |_| gate.block())
        };
        let second_blocker = {
            let gate = Arc::clone(&gate);
            strategy.spawn(move |_| gate.block())
        };
        gate.wait_started(2);
        let blocker = RecordingBlocker::default();
        let (actor, endpoints): (Actor<_, Sha256, _, MinPk, _, _>, _) = Actor::new(
            context.child("resolver"),
            Config {
                peers: vec![local.clone(), peer],
                me: Some(local),
                blocker,
                epoch: committee.config.epoch(),
                codec: committee.codec(),
                strategy: strategy.clone(),
                fetch_timeout: Duration::from_secs(1),
                mailbox_size: NonZeroUsize::new(8).unwrap(),
            },
        );
        let (voter, mut voter_receiver) =
            mailbox::new(context.child("voter"), NonZeroUsize::new(8).unwrap());
        let task = actor.start(voter, network);

        let view = View::new(3);
        let proof = Served::Vqc(Box::new(committee.vqc(view.get())));
        assert!(
            endpoints
                .control
                .enqueue(Message::Retain {
                    proof: proof.clone(),
                })
                .accepted()
        );
        let jobs = [
            ResolutionJob::fabricate(7, 11, view),
            ResolutionJob::fabricate(8, 12, view),
        ];
        for job in jobs {
            assert!(
                endpoints
                    .control
                    .enqueue(Message::Resolve(ResolveRequest {
                        span: Span::none(),
                        round: Round::new(committee.config.epoch(), view),
                        job,
                    }))
                    .accepted()
            );
        }

        let (respond, response) = oneshot::channel();
        assert!(
            endpoints
                .queries
                .enqueue(Query::Serve {
                    view,
                    responder: respond,
                })
                .accepted()
        );
        let served = select! {
            result = response => result.expect("query response"),
            () = context.sleep(Duration::from_secs(1)) => panic!("query stalled behind codec work"),
        };
        assert_eq!(served.as_deref(), Some(&proof));

        for job in jobs {
            assert!(
                endpoints
                    .control
                    .enqueue(Message::Cancel { job })
                    .accepted()
            );
        }
        assert!(
            endpoints
                .control
                .enqueue(Message::Prune { through: view })
                .accepted()
        );
        let deadline = context.current() + Duration::from_secs(2);
        loop {
            let (respond, response) = oneshot::channel();
            assert!(
                endpoints
                    .queries
                    .enqueue(Query::Serve {
                        view,
                        responder: respond,
                    })
                    .accepted()
            );
            let served = select! {
                result = response => result.expect("query response"),
                () = context.sleep_until(deadline) => panic!("control stalled behind codec work"),
            };
            if served.is_none() {
                break;
            }
        }

        gate.release();
        gate.wait_finished(2);
        drop((first_blocker, second_blocker));
        select! {
            _ = voter_receiver.recv() => panic!("canceled job completed"),
            () = context.sleep(Duration::from_millis(50)) => {},
        }
        task.abort();
        let _ = task.await;
    });
}

#[test]
fn wrong_view_response_is_rejected_and_blocks_only_its_peer() {
    Runner::timed(Duration::from_secs(10)).start(|context| async move {
        let committee = committee();
        let local = committee.identities[0].clone();
        let malicious = committee.identities[1].clone();
        let correct = committee.identities[2].clone();
        let oracle = start_network(
            &context,
            vec![local.clone(), malicious.clone(), correct.clone()],
            2 * 1024 * 1024,
        )
        .await;
        link_all(&oracle, &[local.clone(), malicious.clone()]).await;
        let local_network = oracle
            .control(local.clone())
            .register(3, QUOTA)
            .await
            .expect("local resolver network registered");
        let (mut malicious_sender, mut malicious_receiver) = oracle
            .control(malicious.clone())
            .register(3, QUOTA)
            .await
            .expect("malicious resolver network registered");
        let (mut correct_sender, mut correct_receiver) = oracle
            .control(correct.clone())
            .register(3, QUOTA)
            .await
            .expect("correct resolver network registered");
        let blocker = RecordingBlocker::default();
        let (actor, endpoints): (Actor<_, Sha256, _, MinPk, _, _>, _) = Actor::new(
            context.child("resolver"),
            Config {
                peers: vec![local.clone(), malicious.clone(), correct.clone()],
                me: Some(local.clone()),
                blocker: blocker.clone(),
                epoch: committee.config.epoch(),
                codec: committee.codec(),
                strategy: Sequential,
                fetch_timeout: Duration::from_secs(1),
                mailbox_size: NonZeroUsize::new(8).unwrap(),
            },
        );
        let (voter, mut voter_receiver) =
            mailbox::new(context.child("voter"), NonZeroUsize::new(8).unwrap());
        let task = actor.start(voter, local_network);

        let requested = View::new(4);
        let job = ResolutionJob::fabricate(9, 13, requested);
        assert!(
            endpoints
                .control
                .enqueue(Message::Resolve(ResolveRequest {
                    span: Span::none(),
                    round: Round::new(committee.config.epoch(), requested),
                    job,
                }))
                .accepted()
        );

        let (sender, request) = malicious_receiver
            .recv()
            .await
            .expect("malicious peer receives request");
        assert_eq!(sender, local);
        let wrong: Served<MinPk, Digest> =
            Served::Nullification(Box::new(committee.nullification(requested.next().get())));
        let _ = malicious_sender.send(
            Recipients::One(local.clone()),
            resolver_response(request, requested, wrong),
            true,
        );

        let deadline = context.current() + Duration::from_secs(2);
        while blocker.blocked().is_empty() {
            select! {
                () = context.sleep(Duration::from_millis(1)) => {},
                () = context.sleep_until(deadline) => panic!("invalid resolver response was not rejected"),
            }
        }
        assert_eq!(blocker.blocked(), vec![malicious]);
        link_all(&oracle, &[local.clone(), correct.clone()]).await;
        let (sender, request) = correct_receiver
            .recv()
            .await
            .expect("correct peer receives retry");
        assert_eq!(sender, local);
        let expected = Served::Vqc(Box::new(committee.vqc(requested.get())));
        let _ = correct_sender.send(
            Recipients::One(local),
            resolver_response(request, requested, expected.clone()),
            true,
        );
        let crate::multimmit::actors::voter::Message::Resolution { completion, .. } =
            voter_receiver.recv().await.expect("correct proof completes");
        assert_eq!(completion.id(), job.id());
        assert_eq!(completion.generation(), job.generation());
        assert_eq!(completion.view(), requested);
        assert_eq!(completion.proof(), &expected);
        task.abort();
        let _ = task.await;
    });
}

#[test]
fn control_overflow_coalesces_only_between_job_barriers() {
    let committee = committee();
    let mut expected = State::default();
    let mut overflow = ControlOverflow::default();

    for index in 0..1_024 {
        let view = 8 + index % 3;
        let proof = if index % 2 == 0 {
            Served::Nullification(Box::new(committee.nullification(view)))
        } else {
            Served::Vqc(Box::new(committee.vqc(view)))
        };
        expected.retain(proof.clone());
        Message::handle(&mut overflow, Message::Retain { proof });
        if index % 16 == 0 {
            expected.prune(View::new(7));
            Message::handle(
                &mut overflow,
                Message::Prune {
                    through: View::new(7),
                },
            );
        }
    }

    let first = ResolutionJob::fabricate(1, 3, View::new(9));
    Message::handle(
        &mut overflow,
        Message::Resolve(ResolveRequest {
            span: Span::none(),
            round: Round::new(Epoch::new(4), View::new(9)),
            job: first,
        }),
    );

    let floor = Served::Lqc(Box::new(committee.lqc(12)));
    expected.retain(floor.clone());
    Message::handle(&mut overflow, Message::Retain { proof: floor });
    expected.prune(View::new(13));
    Message::handle(
        &mut overflow,
        Message::Prune {
            through: View::new(13),
        },
    );
    Message::handle(&mut overflow, Message::Cancel { job: first });

    let second = ResolutionJob::fabricate(2, 3, View::new(14));
    for index in 0..1_024 {
        let proof = Served::Vqc(Box::new(committee.vqc(14 + index % 2)));
        expected.retain(proof.clone());
        Message::handle(&mut overflow, Message::Retain { proof });
    }
    Message::handle(&mut overflow, Message::Reject { job: second });

    assert_eq!(overflow.chunks.len(), 6);

    let mut drained = Vec::new();
    overflow.drain(|message| {
        drained.push(message);
        None
    });
    assert!(overflow.is_empty());

    let mut observed = State::default();
    let mut controls = Vec::new();
    for message in drained {
        match message {
            Message::Resolve(request) => controls.push((0, request.job)),
            Message::Cancel { job } => controls.push((1, job)),
            Message::Reject { job } => controls.push((2, job)),
            Message::Retain { proof } => {
                observed.retain(proof);
            }
            Message::Prune { through } => observed.prune(through),
        }
    }
    assert_eq!(controls, vec![(0, first), (1, first), (2, second)]);
    for view in 0..=16 {
        let view = View::new(view);
        assert_eq!(
            observed.proof(view).as_deref(),
            expected.proof(view).as_deref()
        );
    }
}

#[cfg(feature = "arbitrary")]
mod conformance {
    use super::*;
    use crate::multimmit::machine::ViewProof;
    use commonware_codec::conformance::CodecConformance;
    use commonware_cryptography::bls12381::primitives::variant::MinSig;

    commonware_conformance::conformance_tests! {
        CodecConformance<ViewProof<MinPk, Digest>> => 128,
        CodecConformance<ViewProof<MinSig, Digest>> => 128,
    }
}
