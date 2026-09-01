//! Resolver actor tests: response priority, retained proof state, control overflow, and codec
//! worker failures.

use super::{
    Actor, Config, Mailbox, Message, ResolveRequest,
    actor::{CodecCompletion, State, decode_delivery},
    mailbox::ControlOverflow,
};
use crate::{
    Epochable as _,
    multimmit::{
        actors::voter::{Inbox, Mailbox as VoterMailbox, Message as VoterMessage},
        machine::{Generation, ResolutionJob},
        mocks::{
            Committee, RecordingBlocker,
            cluster::{QUOTA, link_all, start_network},
        },
        testing::{SpanRecorder, expect_before, expect_within},
        types::ViewProof,
    },
    types::{Epoch, Round, View},
};
use bytes::{Bytes, BytesMut};
use commonware_actor::{
    Feedback, Unreliable,
    mailbox::{Overflow as _, Policy},
};
use commonware_codec::{Copying, Encode as _, ReadExt as _, Write as _};
use commonware_cryptography::{
    Sha256, bls12381::primitives::variant::MinPk, ed25519::PublicKey as Ed25519PublicKey,
    sha256::Digest,
};
use commonware_macros::select;
use commonware_p2p::{CheckedSender, LimitedSender, Receiver as _, Recipients, Sender as _};
use commonware_parallel::{Rayon, Sequential, Strategy, mocks};
use commonware_runtime::{
    Clock as _, IoBufs, Metrics as _, Runner as _, Supervisor as _, deterministic::Runner,
};
use commonware_utils::{
    channel::oneshot,
    sequence::U64,
    sync::{Condvar, Mutex},
};
use std::{
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::Span;
use tracing_subscriber::prelude::*;

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
    Committee::builder(7, 6).build()
}

fn resolver_response(
    request: impl AsRef<[u8]>,
    requested: View,
    proof: ViewProof<MinPk, Digest>,
) -> Bytes {
    let mut request = Copying(request.as_ref());
    let id = u64::read(&mut request).expect("resolver request id");
    assert_eq!(u8::read(&mut request).expect("resolver request tag"), 0);
    assert_eq!(
        u64::from(U64::read(&mut request).expect("resolver request view")),
        requested.get()
    );
    assert!(request.0.is_empty());

    let mut response = BytesMut::new();
    id.write(&mut response);
    1u8.write(&mut response);
    proof.encode().write(&mut response);
    response.freeze()
}

#[derive(Clone)]
struct PrioritySender<S> {
    inner: S,
    priorities: Arc<Mutex<Vec<bool>>>,
}

struct PriorityCheckedSender<C> {
    inner: C,
    priorities: Arc<Mutex<Vec<bool>>>,
}

impl<C: CheckedSender> CheckedSender for PriorityCheckedSender<C> {
    type PublicKey = C::PublicKey;

    fn recipients(&self) -> Vec<Self::PublicKey> {
        self.inner.recipients()
    }

    fn send(self, message: impl Into<IoBufs> + Send, priority: bool) -> Unreliable<Feedback> {
        self.priorities.lock().push(priority);
        self.inner.send(message, priority)
    }
}

impl<S: LimitedSender> LimitedSender for PrioritySender<S> {
    type PublicKey = S::PublicKey;
    type Checked<'a>
        = PriorityCheckedSender<S::Checked<'a>>
    where
        Self: 'a;

    fn check(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
    ) -> Result<Self::Checked<'_>, SystemTime> {
        self.inner
            .check(recipients)
            .map(|inner| PriorityCheckedSender {
                inner,
                priorities: Arc::clone(&self.priorities),
            })
    }
}

#[test]
fn resolver_responses_are_prioritized() {
    Runner::timed(Duration::from_secs(10)).start(|context| async move {
        let committee = committee();
        let local = committee.identities[0].clone();
        let peer = committee.identities[1].clone();
        let oracle = start_network(&context, committee.identities.clone(), 2 * 1024 * 1024).await;
        link_all(&oracle, &[local.clone(), peer.clone()]).await;
        let (local_sender, local_receiver) = oracle
            .control(local.clone())
            .register(3, QUOTA)
            .await
            .expect("local resolver network registered");
        let (mut peer_sender, mut peer_receiver) = oracle
            .control(peer.clone())
            .register(3, QUOTA)
            .await
            .expect("peer resolver network registered");
        let priorities = Arc::new(Mutex::new(Vec::new()));
        let local_sender = PrioritySender {
            inner: local_sender,
            priorities: Arc::clone(&priorities),
        };
        let (actor, _endpoints): (Actor<_, Sha256, _, MinPk, _, _>, _) = Actor::new(
            context.child("resolver"),
            Config {
                scheme: committee.signers[0].clone(),
                blocker: RecordingBlocker::default(),
                strategy: Sequential,
                fetch_timeout: Duration::from_secs(1),
                mailbox_size: NonZeroUsize::new(8).unwrap(),
            },
        );
        let (voter, _inbox) = VoterMailbox::<Ed25519PublicKey, MinPk, Digest>::new(
            &context.child("voter"),
            &context,
            NonZeroUsize::new(8).unwrap(),
        );
        let task = actor.start(
            voter.into_endpoints().resolutions,
            (local_sender, local_receiver),
        );

        let mut request = BytesMut::new();
        0u64.write(&mut request);
        0u8.write(&mut request);
        U64::new(3).write(&mut request);
        assert_eq!(
            peer_sender.send(Recipients::One(local), request.freeze(), false),
            vec![committee.identities[0].clone()]
        );
        let (sender, _response) = peer_receiver.recv().await.expect("peer receives response");
        assert_eq!(sender, committee.identities[0]);
        assert_eq!(*priorities.lock(), vec![true]);

        task.abort();
        let _ = task.await;
    });
}

#[test]
fn serve_overflow_does_not_retain_queries() {
    Runner::default().start(|context| async move {
        let (control, _controls) =
            commonware_actor::mailbox::new(context.child("serve_control"), NonZeroUsize::MIN);
        let (queries, mut queued) = commonware_actor::mailbox::new_unreliable(
            context.child("serve_queries"),
            NonZeroUsize::MIN,
        );
        let server = Mailbox::<MinPk, Digest>::new(control, queries).server();
        let mut first = server.serve(View::zero());
        let overflow = server.serve(View::zero());
        assert!(
            overflow.await.is_err(),
            "a rejected query closes its receiver instead of waiting"
        );

        // The first query stays queued with its responder open.
        assert!(matches!(
            first.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        let retained = queued.try_recv().expect("the first query is retained");
        assert_eq!(retained.view, View::zero());
    });
}

#[test]
fn state_prefers_covering_lqc() {
    let committee = committee();
    let mut state = State::new();
    state.retain(ViewProof::Vqc(Box::new(committee.vqc(View::new(2)))));
    let floor = committee.lqc(View::new(4));
    state.retain(ViewProof::Lqc(Box::new(floor.clone())));

    assert_eq!(
        state.proof(View::new(2)).as_deref(),
        Some(&ViewProof::Lqc(Box::new(floor)))
    );
    assert!(state.proof(View::new(5)).is_none());
}

#[test]
fn state_prefers_vqc_to_nullification() {
    let committee = committee();
    let mut state = State::new();
    let nullification = committee.nullification(View::new(2));
    let vqc = committee.vqc(View::new(2));

    state.retain(ViewProof::Nullification(Box::new(nullification)));
    state.retain(ViewProof::Vqc(Box::new(vqc.clone())));
    state.retain(ViewProof::Nullification(Box::new(
        committee.nullification(View::new(2)),
    )));

    assert_eq!(
        state.proof(View::new(2)).as_deref(),
        Some(&ViewProof::Vqc(Box::new(vqc)))
    );
}

#[test]
fn state_prunes_exact_exits_but_keeps_floor() {
    let committee = committee();
    let mut state = State::new();
    let floor = committee.lqc(View::new(2));
    state.retain(ViewProof::Lqc(Box::new(floor.clone())));
    state.retain(ViewProof::Vqc(Box::new(committee.vqc(View::new(3)))));
    state.prune(View::new(3));

    assert_eq!(
        state.proof(View::new(1)).as_deref(),
        Some(&ViewProof::Lqc(Box::new(floor)))
    );
    assert!(state.proof(View::new(3)).is_none());
    state.retain(ViewProof::Nullification(Box::new(
        committee.nullification(View::new(3)),
    )));
    assert!(state.proof(View::new(3)).is_none());
}

#[test]
fn local_cache_materialization_keeps_request_trace_parent_and_root_until_cancel() {
    let spans = SpanRecorder::default();
    tracing::subscriber::with_default(tracing_subscriber::registry().with(spans.clone()), || {
        Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let committee = committee();
            let local = committee.identities[0].clone();
            let peer = committee.identities[1].clone();
            let oracle =
                start_network(&context, committee.identities.clone(), 2 * 1024 * 1024).await;
            link_all(&oracle, &[local.clone(), peer.clone()]).await;
            let network = oracle
                .control(local.clone())
                .register(3, QUOTA)
                .await
                .expect("resolver network registered");
            let (actor, endpoints): (Actor<_, Sha256, _, MinPk, _, _>, _) = Actor::new(
                context.child("resolver"),
                Config {
                    scheme: committee.signers[0].clone(),
                    blocker: RecordingBlocker::default(),
                    strategy: Sequential,
                    fetch_timeout: Duration::from_secs(1),
                    mailbox_size: NonZeroUsize::new(8).unwrap(),
                },
            );
            let (
                voter,
                Inbox {
                    resolutions: mut voter_receiver,
                    ..
                },
            ) = VoterMailbox::<Ed25519PublicKey, MinPk, Digest>::new(
                &context.child("voter"),
                &context,
                NonZeroUsize::new(8).unwrap(),
            );
            let task = actor.start(voter.into_endpoints().resolutions, network);

            let view = View::new(3);
            let proof = ViewProof::Vqc(Box::new(committee.vqc(view)));
            assert!(endpoints.retain(proof).accepted());
            let request = tracing::info_span!(parent: None, "test.resolver.request");
            let root = tracing::info_span!(parent: None, "test.resolver.root");
            let root_id = root.id().expect("root enabled");
            let job = ResolutionJob::issue(7, Generation::new(11), view);
            assert!(
                endpoints
                    .resolve(ResolveRequest {
                        root,
                        span: request,
                        round: Round::new(committee.config.epoch(), view),
                        job,
                    })
                    .accepted()
            );
            let completion = voter_receiver.recv().await.expect("cached proof completes");
            let VoterMessage::Resolution { root, .. } = &completion;
            assert_eq!(root.id(), Some(root_id));

            let request = spans.last("test.resolver.request").expect("request span");
            let process = spans
                .last("multimmit.resolver.resolve.process")
                .expect("process span");
            let materialize = spans
                .last("multimmit.resolver.resolve.materialize")
                .expect("materialize span");
            let complete = spans
                .last("multimmit.resolver.resolve.complete")
                .expect("completion span");
            assert_eq!(process.parent, Some(request.id));
            assert_eq!(materialize.parent, Some(process.id));
            assert_eq!(complete.parent, Some(materialize.id));

            drop(completion);
            let root_closed = || spans.last("test.resolver.root").unwrap().closed();
            assert!(!root_closed());
            assert!(endpoints.cancel(job).accepted());
            while !root_closed() {
                context.sleep(Duration::from_millis(1)).await;
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
        let oracle = start_network(&context, committee.identities.clone(), 2 * 1024 * 1024).await;
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
            strategy.manual().spawn(1, move |_| gate.block())
        };
        let second_blocker = {
            let gate = Arc::clone(&gate);
            strategy.manual().spawn(1, move |_| gate.block())
        };
        gate.wait_started(2);
        let blocker = RecordingBlocker::default();
        let (actor, endpoints): (Actor<_, Sha256, _, MinPk, _, _>, _) = Actor::new(
            context.child("resolver"),
            Config {
                scheme: committee.signers[0].clone(),
                blocker,
                strategy: strategy.clone(),
                fetch_timeout: Duration::from_secs(1),
                mailbox_size: NonZeroUsize::new(8).unwrap(),
            },
        );
        let (
            voter,
            Inbox {
                resolutions: mut voter_receiver,
                ..
            },
        ) = VoterMailbox::<Ed25519PublicKey, MinPk, Digest>::new(
            &context.child("voter"),
            &context,
            NonZeroUsize::new(8).unwrap(),
        );
        let task = actor.start(voter.into_endpoints().resolutions, network);

        let view = View::new(3);
        let proof = ViewProof::Vqc(Box::new(committee.vqc(view)));
        assert!(endpoints.retain(proof.clone()).accepted());
        let jobs = [
            ResolutionJob::issue(7, Generation::new(11), view),
            ResolutionJob::issue(8, Generation::new(12), view),
        ];
        for job in jobs {
            assert!(
                endpoints
                    .resolve(ResolveRequest {
                        root: Span::none(),
                        span: Span::none(),
                        round: Round::new(committee.config.epoch(), view),
                        job,
                    })
                    .accepted()
            );
        }

        let response = endpoints.server().serve(view);
        let served = expect_within(
            &context,
            Duration::from_secs(1),
            response,
            "query stalled behind codec work",
        )
        .await
        .expect("query response");
        assert_eq!(served.as_deref(), Some(&proof));

        for job in jobs {
            assert!(endpoints.cancel(job).accepted());
        }
        assert!(endpoints.prune(view).accepted());
        let deadline = context.current() + Duration::from_secs(2);
        loop {
            let response = endpoints.server().serve(view);
            let served = expect_before(
                &context,
                deadline,
                response,
                "control stalled behind codec work",
            )
            .await
            .expect("query response");
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
fn wrong_view_response_is_rejected_without_blocking_its_peer() {
    Runner::timed(Duration::from_secs(10)).start(|context| async move {
        let committee = committee();
        let local = committee.identities[0].clone();
        let malicious = committee.identities[1].clone();
        let correct = committee.identities[2].clone();
        let oracle = start_network(&context, committee.identities.clone(), 2 * 1024 * 1024).await;
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
                scheme: committee.signers[0].clone(),
                blocker: blocker.clone(),
                strategy: Sequential,
                fetch_timeout: Duration::from_secs(1),
                mailbox_size: NonZeroUsize::new(8).unwrap(),
            },
        );
        let (
            voter,
            Inbox {
                resolutions: mut voter_receiver,
                ..
            },
        ) = VoterMailbox::<Ed25519PublicKey, MinPk, Digest>::new(
            &context.child("voter"),
            &context,
            NonZeroUsize::new(8).unwrap(),
        );
        let task = actor.start(voter.into_endpoints().resolutions, local_network);

        let requested = View::new(4);
        let job = ResolutionJob::issue(9, Generation::new(13), requested);
        assert!(
            endpoints
                .resolve(ResolveRequest {
                    root: Span::none(),
                    span: Span::none(),
                    round: Round::new(committee.config.epoch(), requested),
                    job,
                })
                .accepted()
        );

        let (sender, request) = malicious_receiver
            .recv()
            .await
            .expect("malicious peer receives request");
        assert_eq!(sender, local);
        let wrong: ViewProof<MinPk, Digest> =
            ViewProof::Nullification(Box::new(committee.nullification(requested.next())));
        let _ = malicious_sender.send(
            Recipients::One(local.clone()),
            resolver_response(request, requested, wrong),
            true,
        );

        context.sleep(Duration::from_millis(10)).await;
        assert!(blocker.blocked().is_empty());
        let metrics = context.encode();
        assert!(
            metrics.contains("resolver_mismatched_total 1\n"),
            "an unusable peer response is counted as mismatched: {metrics}"
        );
        assert!(metrics.contains("resolver_rejected_total 0\n"), "{metrics}");
        link_all(&oracle, &[local.clone(), correct.clone()]).await;
        let (sender, request) = correct_receiver
            .recv()
            .await
            .expect("correct peer receives retry");
        assert_eq!(sender, local);
        let expected = ViewProof::Vqc(Box::new(committee.vqc(requested)));
        let _ = correct_sender.send(
            Recipients::One(local),
            resolver_response(request, requested, expected.clone()),
            true,
        );
        let VoterMessage::Resolution { completion, .. } = voter_receiver
            .recv()
            .await
            .expect("correct proof completes");
        assert_eq!(completion.issued().id(), job.issued().id());
        assert_eq!(completion.issued().generation(), job.issued().generation());
        assert_eq!(completion.view(), requested);
        assert_eq!(completion.proof(), &expected);

        // A machine rejection is counted apart from unusable responses.
        assert!(endpoints.reject(job).accepted());
        context.sleep(Duration::from_millis(10)).await;
        let metrics = context.encode();
        assert!(metrics.contains("resolver_rejected_total 1\n"), "{metrics}");
        assert!(
            metrics.contains("resolver_mismatched_total 1\n"),
            "{metrics}"
        );
        assert!(blocker.blocked().is_empty());
        task.abort();
        let _ = task.await;
    });
}

#[test]
fn control_overflow_coalesces_only_between_job_barriers() {
    let committee = committee();
    let mut expected = State::new();
    let mut overflow = ControlOverflow::default();

    for index in 0..1_024 {
        let view = 8 + index % 3;
        let proof = if index % 2 == 0 {
            ViewProof::Nullification(Box::new(committee.nullification(View::new(view))))
        } else {
            ViewProof::Vqc(Box::new(committee.vqc(View::new(view))))
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

    let first = ResolutionJob::issue(1, Generation::new(3), View::new(9));
    Message::handle(
        &mut overflow,
        Message::Resolve(ResolveRequest {
            root: Span::none(),
            span: Span::none(),
            round: Round::new(Epoch::new(4), View::new(9)),
            job: first,
        }),
    );

    let floor = ViewProof::Lqc(Box::new(committee.lqc(View::new(12))));
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

    let second = ResolutionJob::issue(2, Generation::new(3), View::new(14));
    for index in 0..1_024 {
        let proof = ViewProof::Vqc(Box::new(committee.vqc(View::new(14 + index % 2))));
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

    let mut observed = State::new();
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

#[test]
fn control_overflow_drains_trailing_retention_and_resumes_after_backpressure() {
    let committee = committee();
    let mut overflow = ControlOverflow::default();
    let job = ResolutionJob::issue(1, Generation::new(3), View::new(9));
    let early = ViewProof::Vqc(Box::new(committee.vqc(View::new(8))));
    let late = ViewProof::Vqc(Box::new(committee.vqc(View::new(10))));
    let floor = ViewProof::Lqc(Box::new(committee.lqc(View::new(9))));
    Message::handle(
        &mut overflow,
        Message::Retain {
            proof: early.clone(),
        },
    );
    Message::handle(&mut overflow, Message::Cancel { job });
    Message::handle(
        &mut overflow,
        Message::Retain {
            proof: late.clone(),
        },
    );
    Message::handle(
        &mut overflow,
        Message::Prune {
            through: View::new(9),
        },
    );
    Message::handle(
        &mut overflow,
        Message::Retain {
            proof: floor.clone(),
        },
    );
    assert!(!overflow.is_empty());

    // Accept one message per drain, so every chunk resumes where the last drain stopped and the
    // prune point, floor, and exit of the trailing delta are each handed back once.
    let mut drained = Vec::new();
    while !overflow.is_empty() {
        let mut accepted = false;
        overflow.drain(|message| {
            if accepted {
                return Some(message);
            }
            accepted = true;
            drained.push(message);
            None
        });
        assert!(accepted, "a non-empty overflow made no progress");
    }
    assert!(matches!(
        drained.as_slice(),
        [
            Message::Retain { proof: first },
            Message::Cancel { job: cancelled },
            Message::Prune { through },
            Message::Retain { proof: retained_floor },
            Message::Retain { proof: second },
        ] if *first == early
            && *cancelled == job
            && *through == View::new(9)
            && *retained_floor == floor
            && *second == late
    ));
}

#[test]
fn panicked_decode_is_an_invalid_response() {
    let strategies = [
        mocks::inline(NonZeroUsize::MIN),
        Rayon::new(NonZeroUsize::new(2).unwrap()).expect("compute pool starts"),
    ];
    for strategy in strategies {
        let (response, _verdict) = oneshot::channel();
        let (_, completion) = futures::executor::block_on(decode_delivery::<_, MinPk, Digest>(
            strategy,
            Span::none(),
            response,
            || panic!("malformed proof"),
        ));
        assert!(
            matches!(completion, CodecCompletion::Decoded { proofs: None, .. }),
            "a panicked decode must complete without proofs"
        );
    }
}
