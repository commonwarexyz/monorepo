//! Resolver actor tests: response priority, retained-artifact state, pruning, and codec worker
//! failures.

use super::{
    Actor, Config, Mailbox, ResolveRequest,
    actor::{CodecCompletion, State, decode, decode_delivery},
};
use crate::{
    multimmit::{
        actors::voter::{Inbox, Mailbox as VoterMailbox, Message as VoterMessage},
        machine::{Generation, ResolutionJob, RetrievalKey},
        mocks::{
            Committee, RecordingBlocker,
            cluster::{QUOTA, link_all, start_network},
        },
        testing::{SpanRecorder, expect_before, expect_within},
        types::{Artifact, ChainChange, ChainId},
    },
    types::{Height, Participant, View},
};
use bytes::{Bytes, BytesMut};
use commonware_actor::{Feedback, Unreliable, mailbox};
use commonware_codec::{Copying, ReadExt as _, Write as _};
use commonware_cryptography::{
    Hasher as _, Sha256, bls12381::primitives::variant::MinPk,
    ed25519::PublicKey as Ed25519PublicKey, sha256::Digest,
};
use commonware_macros::select;
use commonware_p2p::{
    CheckedSender, LimitedSender, Receiver, Recipients, Sender, simulated::Oracle,
};
use commonware_parallel::{Rayon, Sequential, Strategy, mocks};
use commonware_runtime::{
    Clock as _, Handle, IoBufs, Metrics as _, Runner as _, Supervisor as _,
    deterministic::{Context, Runner},
    telemetry::metrics::metric_sum,
};
use commonware_utils::{
    channel::oneshot,
    sync::{Condvar, Mutex},
};
use std::{
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::Span;
use tracing_subscriber::prelude::*;

type Artifacts = Arc<Artifact<MinPk, Digest>>;
type Resolutions = mailbox::Receiver<VoterMessage<MinPk, Digest>>;

/// Blocks codec pool workers until released.
#[derive(Default)]
struct CodecGate {
    state: Mutex<(usize, usize, bool)>,
    changed: Condvar,
}

impl CodecGate {
    fn block(&self) {
        let mut state = self.state.lock();
        state.0 += 1;
        self.changed.notify_all();
        while !state.2 {
            self.changed.wait(&mut state);
        }
        state.1 += 1;
        self.changed.notify_all();
    }

    fn wait(&self, count: usize, finished: bool) {
        let mut state = self.state.lock();
        while (if finished { state.1 } else { state.0 }) < count {
            self.changed.wait(&mut state);
        }
    }

    fn release(&self) {
        self.state.lock().2 = true;
        self.changed.notify_all();
    }
}

fn committee() -> Committee<MinPk> {
    Committee::builder(7, 6).build()
}

fn shared(artifact: Artifact<MinPk, Digest>) -> Artifacts {
    Arc::new(artifact)
}

fn vqc(committee: &Committee<MinPk>, view: u64) -> Artifacts {
    shared(Artifact::Vqc(committee.vqc(View::new(view))))
}

fn lqc(committee: &Committee<MinPk>, view: u64) -> Artifacts {
    shared(Artifact::Lqc(committee.lqc(View::new(view))))
}

fn header(committee: &Committee<MinPk>, chain: u32, body: &[u8]) -> Artifacts {
    shared(Artifact::TransactionBlock(
        committee.genesis_child(ChainId::new(chain), body),
    ))
}

/// Returns the first key `artifact` provides.
fn key(artifact: &Artifacts) -> RetrievalKey<Digest> {
    artifact.provisions::<Sha256>()[0]
}

fn retain(state: &mut State<MinPk, Digest>, artifact: &Artifacts) {
    state.retain(artifact.provisions::<Sha256>(), Arc::clone(artifact), None);
}

fn served(state: &State<MinPk, Digest>, artifact: &Artifacts) -> bool {
    artifact
        .provisions::<Sha256>()
        .iter()
        .all(|key| state.artifact(key).as_ref() == Some(artifact))
}

fn job(id: u64, key: RetrievalKey<Digest>) -> ResolutionJob<Digest> {
    ResolutionJob::for_test(id, Generation::new(3), key)
}

fn request(committee: &Committee<MinPk>, job: ResolutionJob<Digest>) -> ResolveRequest<Digest> {
    ResolveRequest {
        root: Span::none(),
        span: Span::none(),
        round: committee.round(job.key().view().unwrap_or_else(View::zero)),
        job,
    }
}

/// Returns the key a resolver request asks for.
fn requested(request: &[u8]) -> RetrievalKey<Digest> {
    let mut request = Copying(request);
    let _id = u64::read(&mut request).expect("resolver request id");
    assert_eq!(u8::read(&mut request).expect("resolver request tag"), 0);
    let key = RetrievalKey::read(&mut request).expect("resolver request key");
    assert!(request.0.is_empty());
    key
}

/// Encodes a peer response to the resolver `request` for `expected`, carrying `artifact`.
fn response(
    request: impl AsRef<[u8]>,
    expected: RetrievalKey<Digest>,
    artifact: &Artifacts,
) -> Bytes {
    let request = request.as_ref();
    assert_eq!(requested(request), expected);
    let id = u64::read(&mut Copying(request)).expect("resolver request id");
    let mut response = BytesMut::new();
    id.write(&mut response);
    1u8.write(&mut response);
    let mut encoded = Vec::new();
    artifact.write_canonical_encoding(&mut encoded);
    Bytes::from(encoded).write(&mut response);
    response.freeze()
}

/// Registers `participant`'s resolver plane on the simulated network.
async fn register(
    oracle: &Oracle<Ed25519PublicKey, Context>,
    committee: &Committee<MinPk>,
    participant: usize,
) -> (
    impl Sender<PublicKey = Ed25519PublicKey>,
    impl Receiver<PublicKey = Ed25519PublicKey>,
) {
    oracle
        .control(committee.identities[participant].clone())
        .register(3, QUOTA)
        .await
        .expect("resolver network registered")
}

/// Starts participant zero's resolver over `network`, returning its control mailbox, the voter's
/// resolution queue, and the actor task.
fn start<T: Strategy>(
    context: &Context,
    committee: &Committee<MinPk>,
    strategy: T,
    blocker: RecordingBlocker,
    network: (
        impl Sender<PublicKey = Ed25519PublicKey>,
        impl Receiver<PublicKey = Ed25519PublicKey>,
    ),
) -> (Mailbox<MinPk, Digest>, Resolutions, Handle<()>) {
    let (actor, endpoints): (Actor<_, Sha256, _, MinPk, _, _>, _) = Actor::new(
        context.child("resolver"),
        Config {
            scheme: committee.signers[0].clone(),
            blocker,
            strategy,
            fetch_timeout: Duration::from_secs(1),
            mailbox_size: NonZeroUsize::new(8).unwrap(),
        },
    );
    let voter_context = context.child("voter");
    let (voter, Inbox { resolutions, .. }) = VoterMailbox::<MinPk, Digest>::new(
        &voter_context,
        context,
        NonZeroUsize::new(8).unwrap(),
        NonZeroUsize::new(8).unwrap(),
    );
    let task = actor.start(voter.resolutions, network);
    (endpoints, resolutions, task)
}

async fn stop(task: Handle<()>) {
    task.abort();
    let _ = task.await;
}

/// Asserts that the voter receives no resolution within a short wait.
async fn assert_quiet(context: &Context, resolutions: &mut Resolutions) {
    select! {
        _ = resolutions.recv() => panic!("a retired retrieval completed"),
        () = context.sleep(Duration::from_millis(50)) => {},
    }
}

/// Retains `artifact` and waits until the resolver serves it under `key`.
async fn retained(
    context: &Context,
    endpoints: &Mailbox<MinPk, Digest>,
    artifact: &Artifacts,
    key: RetrievalKey<Digest>,
) {
    assert!(endpoints.retain(Arc::clone(artifact)).accepted());
    let deadline = context.current() + Duration::from_secs(1);
    while expect_before(
        context,
        deadline,
        endpoints.server().serve(key),
        "retention stalled",
    )
    .await
    .expect("query response")
    .is_none()
    {}
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
        let oracle = start_network(&context, committee.identities.clone(), 2 * 1024 * 1024).await;
        link_all(&oracle, &committee.identities[..2]).await;
        let (sender, receiver) = register(&oracle, &committee, 0).await;
        let (mut peer_sender, mut peer_receiver) = register(&oracle, &committee, 1).await;
        let priorities = Arc::new(Mutex::new(Vec::new()));
        let sender = PrioritySender {
            inner: sender,
            priorities: Arc::clone(&priorities),
        };
        let (_endpoints, _resolutions, task) = start(
            &context,
            &committee,
            Sequential,
            RecordingBlocker::default(),
            (sender, receiver),
        );

        let mut request = BytesMut::new();
        0u64.write(&mut request);
        0u8.write(&mut request);
        RetrievalKey::<Digest>::VqcView(View::new(3)).write(&mut request);
        assert_eq!(
            peer_sender.send(Recipients::One(local.clone()), request.freeze(), false),
            vec![local.clone()]
        );
        let (sender, _response) = peer_receiver.recv().await.expect("peer receives response");
        assert_eq!(sender, local);
        assert_eq!(*priorities.lock(), vec![true]);
        stop(task).await;
    });
}

#[test]
fn serve_overflow_does_not_retain_queries() {
    Runner::default().start(|context| async move {
        let (control, _controls) = mailbox::new(context.child("serve_control"), NonZeroUsize::MIN);
        let (queries, mut queued) =
            mailbox::new_unreliable(context.child("serve_queries"), NonZeroUsize::MIN);
        let server = Mailbox::<MinPk, Digest>::new(control, queries).server();
        let key = RetrievalKey::VqcView(View::new(1));
        let mut first = server.serve(key);
        let overflow = server.serve(key);
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
        assert_eq!(retained.key, key);
    });
}

#[test]
fn state_serves_every_key_an_artifact_provides_and_keeps_the_first() {
    let committee = committee();
    let mut state = State::new();
    let first = vqc(&committee, 2);
    retain(&mut state, &first);
    assert!(served(&state, &first));

    // Another V-QC of the same view keeps its own identity but not the view key.
    let content = committee.content(View::new(2), None, true, committee.genesis_endorsement());
    let quorum = (0..5).map(|signer| (Participant::new(signer), content.clone()));
    let other = shared(Artifact::Vqc(committee.vqc_from(
        committee.genesis().vqc(),
        quorum.collect(),
        Vec::new(),
    )));
    retain(&mut state, &other);
    let [identity, view] = other.provisions::<Sha256>()[..] else {
        panic!("a V-QC provides its identity and its view");
    };
    assert_eq!(state.artifact(&identity).as_ref(), Some(&other));
    assert_eq!(state.artifact(&view).as_ref(), Some(&first));

    let block = header(&committee, 1, b"block");
    retain(&mut state, &block);
    assert!(served(&state, &block));
    assert!(
        state
            .artifact(&RetrievalKey::Header {
                chain: ChainId::new(1),
                digest: Sha256::hash(&[b"unknown"]),
            })
            .is_none()
    );
}

#[test]
fn a_senders_tag_serves_its_latest_update_naming_every_chain() {
    let committee = committee();
    let mut state = State::new();
    let signer = Participant::new(1);
    let view = View::new(2);
    let content = committee.content(view, None, false, committee.genesis_endorsement());
    let every_chain = content
        .tips()
        .iter()
        .map(|tip| ChainChange::new(*tip, Vec::new(), committee.codec()).unwrap())
        .collect::<Vec<_>>();
    let complete = |seq| {
        shared(Artifact::Update(committee.update_with(
            signer,
            &content,
            every_chain.clone(),
            seq,
        )))
    };
    let (second, first, third) = (complete(2), complete(1), complete(3));

    // A later update of the tag replaces an earlier one; an earlier one never replaces it.
    retain(&mut state, &second);
    retain(&mut state, &first);
    assert!(served(&state, &second));
    retain(&mut state, &third);
    assert!(served(&state, &third));

    // A fetched update must name every chain.
    let codec = committee.codec();
    let key = RetrievalKey::Update { signer, view };
    let encode = |artifact: &Artifacts| {
        let Artifact::Update(update) = artifact.as_ref() else {
            unreachable!("an update");
        };
        Bytes::from(commonware_codec::Encode::encode(update).to_vec())
    };
    assert!(decode::<Sha256, MinPk>(key, encode(&third), &codec).is_some());
    let partial = shared(Artifact::Update(committee.update(
        signer,
        &content,
        committee.genesis().tips(),
        4,
    )));
    assert!(decode::<Sha256, MinPk>(key, encode(&partial), &codec).is_none());
}

#[test]
fn state_prunes_through_a_view_and_refuses_later_retention_below_it() {
    let committee = committee();
    let mut state = State::new();
    let (early, late) = (vqc(&committee, 2), vqc(&committee, 4));
    let update = shared(Artifact::Update(
        committee.genesis_update(Participant::new(1), View::new(3)),
    ));
    for artifact in [&early, &update, &late] {
        retain(&mut state, artifact);
    }

    state.prune(View::new(3));
    assert!(!served(&state, &early) && state.artifact(&key(&early)).is_none());
    assert!(state.artifact(&key(&update)).is_none());
    assert!(served(&state, &late));

    // Retention at or below the prune point is refused; a lower prune changes nothing.
    retain(&mut state, &early);
    assert!(state.artifact(&key(&early)).is_none());
    state.prune(View::new(1));
    assert!(served(&state, &late));
}

#[test]
fn headers_retire_when_their_chain_settles() {
    let committee = committee();
    let mut state = State::new();
    let (first, fork, other) = (
        header(&committee, 0, b"first"),
        header(&committee, 0, b"fork"),
        header(&committee, 1, b"other"),
    );
    let Artifact::TransactionBlock(parent) = first.as_ref() else {
        unreachable!("headers are transaction blocks");
    };
    let second = shared(Artifact::TransactionBlock(committee.sign_header(
        committee.header(
            &parent.header().block_ref::<Sha256>(),
            Sha256::hash(&[b"second"]),
        ),
    )));
    for artifact in [&first, &fork, &other, &second] {
        retain(&mut state, artifact);
    }

    // View pruning never retires a header.
    state.prune(View::new(100));
    assert!(
        [&first, &fork, &other, &second]
            .iter()
            .all(|header| served(&state, header))
    );

    // Settling a chain retires every fork at or below the height, on that chain only.
    state.settle(ChainId::new(0), Height::new(1));
    assert!(state.artifact(&key(&first)).is_none());
    assert!(state.artifact(&key(&fork)).is_none());
    assert!(served(&state, &second) && served(&state, &other));

    // Retention at or below the settled height is refused; a lower settlement changes nothing.
    retain(&mut state, &first);
    assert!(state.artifact(&key(&first)).is_none());
    state.settle(ChainId::new(0), Height::zero());
    assert!(served(&state, &second));
}

#[test]
fn recovery_seeding_keeps_only_the_newest_lqc_below_the_floor() {
    let committee = committee();
    let (old_lqc, old_vqc, newest_lqc, live_vqc) = (
        lqc(&committee, 4),
        vqc(&committee, 5),
        lqc(&committee, 8),
        vqc(&committee, 12),
    );
    // The voter prunes through the durable floor before retaining the recovered proofs, which
    // arrive in any order.
    for order in [
        [&old_lqc, &old_vqc, &newest_lqc, &live_vqc],
        [&live_vqc, &newest_lqc, &old_vqc, &old_lqc],
    ] {
        let mut state = State::new();
        state.prune(View::new(10));
        for artifact in order {
            retain(&mut state, artifact);
        }
        assert!(served(&state, &newest_lqc) && served(&state, &live_vqc));
        assert!(state.artifact(&key(&old_lqc)).is_none());
        assert!(state.artifact(&key(&old_vqc)).is_none());
    }
}

#[test]
fn the_newest_lqc_survives_pruning() {
    let committee = committee();
    let mut state = State::new();
    let (older, newest) = (lqc(&committee, 2), lqc(&committee, 3));
    retain(&mut state, &older);
    retain(&mut state, &newest);
    state.prune(View::new(5));
    assert!(state.artifact(&key(&older)).is_none());
    assert!(served(&state, &newest));

    // An older L-QC is refused below the prune point; a newer one replaces the survivor.
    retain(&mut state, &older);
    assert!(state.artifact(&key(&older)).is_none());
    let next = lqc(&committee, 4);
    retain(&mut state, &next);
    assert!(served(&state, &next));
    assert!(state.artifact(&key(&newest)).is_none());

    // An L-QC above the prune point ages out normally once a newer one replaces it.
    let (above, newer) = (lqc(&committee, 7), lqc(&committee, 8));
    retain(&mut state, &above);
    retain(&mut state, &newer);
    assert!(state.artifact(&key(&next)).is_none());
    state.prune(View::new(7));
    assert!(state.artifact(&key(&above)).is_none());
    assert!(served(&state, &newer));
}

#[test]
fn served_artifacts_count_their_encoded_bytes() {
    Runner::timed(Duration::from_secs(10)).start(|context| async move {
        let committee = committee();
        let local = committee.identities[0].clone();
        let oracle = start_network(&context, committee.identities.clone(), 2 * 1024 * 1024).await;
        link_all(&oracle, &committee.identities[..2]).await;
        let network = register(&oracle, &committee, 0).await;
        let (mut peer_sender, mut peer_receiver) = register(&oracle, &committee, 1).await;
        let (endpoints, _resolutions, task) = start(
            &context,
            &committee,
            Sequential,
            RecordingBlocker::default(),
            network,
        );
        let certificate = vqc(&committee, 3);
        let key = RetrievalKey::VqcView(View::new(3));
        retained(&context, &endpoints, &certificate, key).await;

        let mut request = BytesMut::new();
        0u64.write(&mut request);
        0u8.write(&mut request);
        key.write(&mut request);
        assert_eq!(
            peer_sender.send(Recipients::One(local.clone()), request.freeze(), false),
            vec![local]
        );
        peer_receiver.recv().await.expect("peer receives response");
        let metrics = context.encode();
        assert!(metrics.contains("resolver_served_total 1\n"), "{metrics}");
        assert!(
            metrics.contains(&format!(
                "resolver_served_bytes_total {}\n",
                certificate.encoded_len()
            )),
            "{metrics}"
        );
        stop(task).await;
    });
}

#[test]
fn local_materialization_keeps_request_trace_parent_and_root_until_cancel() {
    let spans = SpanRecorder::default();
    tracing::subscriber::with_default(tracing_subscriber::registry().with(spans.clone()), || {
        Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let committee = committee();
            let oracle =
                start_network(&context, committee.identities.clone(), 2 * 1024 * 1024).await;
            link_all(&oracle, &committee.identities[..2]).await;
            let network = register(&oracle, &committee, 0).await;
            let (endpoints, mut resolutions, task) = start(
                &context,
                &committee,
                Sequential,
                RecordingBlocker::default(),
                network,
            );

            let certificate = vqc(&committee, 3);
            let key = RetrievalKey::VqcView(View::new(3));
            retained(&context, &endpoints, &certificate, key).await;
            let root = tracing::info_span!(parent: None, "test.resolver.root");
            let root_id = root.id().expect("root enabled");
            let job = job(7, key);
            assert!(
                endpoints
                    .resolve(ResolveRequest {
                        root,
                        span: tracing::info_span!(parent: None, "test.resolver.request"),
                        ..request(&committee, job)
                    })
                    .accepted()
            );
            let completion = resolutions
                .recv()
                .await
                .expect("retained artifact completes");
            let VoterMessage::Resolution {
                root,
                completion: resolved,
                ..
            } = &completion;
            assert_eq!(root.id(), Some(root_id));
            assert_eq!(resolved.job(), job);
            assert_eq!(&resolved.artifact().artifact, certificate.as_ref());

            let span = |name| spans.last(name).expect(name);
            let process = span("multimmit.resolver.resolve.process");
            let materialize = span("multimmit.resolver.resolve.materialize");
            assert_eq!(process.parent, Some(span("test.resolver.request").id));
            assert_eq!(materialize.parent, Some(process.id));
            assert_eq!(
                span("multimmit.resolver.resolve.complete").parent,
                Some(materialize.id)
            );

            drop(completion);
            let root_closed = || spans.last("test.resolver.root").unwrap().closed();
            assert!(!root_closed());
            assert!(endpoints.cancel(job).accepted());
            while !root_closed() {
                context.sleep(Duration::from_millis(1)).await;
            }
            stop(task).await;
        });
    });
}

#[test]
fn stalled_codec_worker_keeps_control_and_queries_live() {
    Runner::timed(Duration::from_secs(10)).start(|context| async move {
        let committee = committee();
        let oracle = start_network(&context, committee.identities.clone(), 2 * 1024 * 1024).await;
        link_all(&oracle, &committee.identities[..2]).await;
        let network = register(&oracle, &committee, 0).await;
        let strategy = Rayon::new(NonZeroUsize::new(2).unwrap()).expect("codec pool starts");
        let (endpoints, mut resolutions, task) = start(
            &context,
            &committee,
            strategy.clone(),
            RecordingBlocker::default(),
            network,
        );
        // A leader block is identified on the actor loop, so retaining it needs no codec worker.
        let block = shared(Artifact::LeaderBlock(committee.leader_block(View::new(3))));
        let key = RetrievalKey::LeaderBlock(View::new(3));
        retained(&context, &endpoints, &block, key).await;

        // With every codec worker blocked, both retrievals wait to copy the retained artifact.
        let gate = Arc::new(CodecGate::default());
        let blockers = [0, 1].map(|_| {
            let gate = Arc::clone(&gate);
            strategy.manual().spawn(1, move |_| gate.block())
        });
        gate.wait(2, false);
        let jobs = [job(7, key), job(8, key)];
        for job in jobs {
            assert!(endpoints.resolve(request(&committee, job)).accepted());
        }

        let served = expect_within(
            &context,
            Duration::from_secs(1),
            endpoints.server().serve(key),
            "query stalled behind codec work",
        )
        .await
        .expect("query response");
        assert_eq!(served, Some(block));

        // One retrieval is cancelled; the prune retires the other while it waits for a worker.
        assert!(endpoints.cancel(jobs[0]).accepted());
        assert!(endpoints.prune(View::new(3)).accepted());
        let deadline = context.current() + Duration::from_secs(2);
        while expect_before(
            &context,
            deadline,
            endpoints.server().serve(key),
            "control stalled behind codec work",
        )
        .await
        .expect("query response")
        .is_some()
        {}

        gate.release();
        gate.wait(2, true);
        drop(blockers);
        assert_quiet(&context, &mut resolutions).await;
        stop(task).await;
    });
}

#[test]
fn mismatched_response_is_rejected_without_blocking_its_peer() {
    Runner::timed(Duration::from_secs(10)).start(|context| async move {
        let committee = committee();
        let local = committee.identities[0].clone();
        let oracle = start_network(&context, committee.identities.clone(), 2 * 1024 * 1024).await;
        link_all(&oracle, &[local.clone(), committee.identities[1].clone()]).await;
        let network = register(&oracle, &committee, 0).await;
        let (mut malicious_sender, mut malicious_receiver) = register(&oracle, &committee, 1).await;
        let (mut correct_sender, mut correct_receiver) = register(&oracle, &committee, 2).await;
        let blocker = RecordingBlocker::default();
        let (endpoints, mut resolutions, task) =
            start(&context, &committee, Sequential, blocker.clone(), network);

        let key = RetrievalKey::VqcView(View::new(4));
        let job = job(9, key);
        assert!(endpoints.resolve(request(&committee, job)).accepted());

        // A V-QC of another view decodes but does not provide the requested key.
        let (sender, fetch) = malicious_receiver
            .recv()
            .await
            .expect("malicious peer receives request");
        assert_eq!(sender, local);
        let _ = malicious_sender.send(
            Recipients::One(local.clone()),
            response(fetch, key, &vqc(&committee, 5)),
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

        link_all(&oracle, &[local.clone(), committee.identities[2].clone()]).await;
        let (sender, fetch) = correct_receiver
            .recv()
            .await
            .expect("correct peer receives retry");
        assert_eq!(sender, local);
        let expected = vqc(&committee, 4);
        let _ = correct_sender.send(
            Recipients::One(local),
            response(fetch, key, &expected),
            true,
        );
        let VoterMessage::Resolution { completion, .. } = resolutions
            .recv()
            .await
            .expect("correct artifact completes");
        assert_eq!(completion.job(), job);
        assert_eq!(&completion.artifact().artifact, expected.as_ref());

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
        stop(task).await;
    });
}

#[test]
fn pruning_retires_view_scoped_retrievals_and_answers_their_deliveries() {
    Runner::timed(Duration::from_secs(10)).start(|context| async move {
        let committee = committee();
        let local = committee.identities[0].clone();
        let oracle = start_network(&context, committee.identities.clone(), 2 * 1024 * 1024).await;
        link_all(&oracle, &committee.identities[..2]).await;
        let network = register(&oracle, &committee, 0).await;
        let (mut peer_sender, mut peer_receiver) = register(&oracle, &committee, 1).await;
        let (endpoints, mut resolutions, task) = start(
            &context,
            &committee,
            Sequential,
            RecordingBlocker::default(),
            network,
        );

        // A retrieval answered before the prune, one whose answer arrives after it, one above the
        // pruned view, and a view-less header.
        let (delivered, pending, above) =
            (vqc(&committee, 4), vqc(&committee, 5), vqc(&committee, 6));
        let block = header(&committee, 0, b"block");
        let artifacts = [&delivered, &pending, &above, &block];
        let keys = artifacts.map(|artifact| match artifact.as_ref() {
            Artifact::Vqc(_) => RetrievalKey::VqcView(artifact.view().unwrap()),
            _ => key(artifact),
        });
        for (id, key) in keys.into_iter().enumerate() {
            assert!(
                endpoints
                    .resolve(request(&committee, job(id as u64, key)))
                    .accepted()
            );
        }
        let mut fetches = Vec::new();
        while fetches.len() < keys.len() {
            let (_, fetch) = peer_receiver.recv().await.expect("peer receives request");
            fetches.push(fetch);
        }
        let mut answer = |key: RetrievalKey<Digest>| {
            let index = keys.iter().position(|candidate| *candidate == key).unwrap();
            let fetch = fetches
                .iter()
                .find(|fetch| requested(fetch.as_ref()) == key)
                .expect("every key was requested");
            let _ = peer_sender.send(
                Recipients::One(local.clone()),
                response(fetch, key, artifacts[index]),
                true,
            );
        };

        answer(keys[0]);
        let VoterMessage::Resolution { completion, .. } = resolutions
            .recv()
            .await
            .expect("the delivered retrieval completes");
        assert_eq!(completion.job().key(), keys[0]);
        assert!(endpoints.prune(View::new(5)).accepted());
        context.sleep(Duration::from_millis(10)).await;
        for key in &keys[1..] {
            answer(*key);
        }

        // Only the retrievals the prune did not retire complete.
        let mut completed = Vec::new();
        for _ in 0..2 {
            let VoterMessage::Resolution { completion, .. } = resolutions
                .recv()
                .await
                .expect("a surviving retrieval completes");
            completed.push(completion.job().key());
        }
        completed.sort();
        let mut expected = vec![keys[2], keys[3]];
        expected.sort();
        assert_eq!(completed, expected);
        assert_quiet(&context, &mut resolutions).await;

        // The prune answered the delivered response as valid, so no fetch failed and none was
        // repeated.
        select! {
            _ = peer_receiver.recv() => panic!("a retired retrieval was fetched again"),
            () = context.sleep(Duration::from_secs(3)) => {},
        }
        let metrics = context.encode();
        let fetches =
            |status: &str| metric_sum(&metrics, "resolver_p2p_fetch_total", &[("status", status)]);
        assert_eq!(fetches("Failure"), 0.0, "{metrics}");
        assert_eq!(fetches("Success"), 1.0, "{metrics}");
        stop(task).await;
    });
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
            || panic!("malformed artifact"),
        ));
        assert!(
            matches!(
                completion,
                CodecCompletion::Decoded {
                    artifacts: None,
                    ..
                }
            ),
            "a panicked decode must complete without artifacts"
        );
    }
}

#[test]
fn an_update_is_fetched_only_from_its_signer() {
    Runner::timed(Duration::from_secs(30)).start(|context| async move {
        let committee = committee();
        let local = committee.identities[0].clone();
        let oracle = start_network(&context, committee.identities.clone(), 2 * 1024 * 1024).await;
        link_all(&oracle, &committee.identities[..3]).await;
        let network = register(&oracle, &committee, 0).await;
        let (_other_sender, mut other_receiver) = register(&oracle, &committee, 1).await;
        let (mut signer_sender, mut signer_receiver) = register(&oracle, &committee, 2).await;
        let (endpoints, mut resolutions, task) = start(
            &context,
            &committee,
            Sequential,
            RecordingBlocker::default(),
            network,
        );

        let (signer, view) = (Participant::new(2), View::new(2));
        let content = committee.content(view, None, false, committee.genesis_endorsement());
        let every_chain = content
            .tips()
            .iter()
            .map(|tip| ChainChange::new(*tip, Vec::new(), committee.codec()).unwrap())
            .collect::<Vec<_>>();
        let update = shared(Artifact::Update(committee.update_with(
            signer,
            &content,
            every_chain,
            1,
        )));
        let requested_key = RetrievalKey::Update { signer, view };
        assert_eq!(key(&update), requested_key);
        let job = job(1, requested_key);
        assert!(endpoints.resolve(request(&committee, job)).accepted());

        // An unanswered request is repeated to the signer and never sent to another peer, which
        // cannot hold the signer's latest update.
        let mut fetch = None;
        for _ in 0..3 {
            select! {
                _ = other_receiver.recv() => panic!("an update was requested from a non-signer"),
                received = signer_receiver.recv() => {
                    let (sender, request) = received.expect("signer receives request");
                    assert_eq!(sender, local);
                    fetch = Some(request);
                },
            }
        }
        let _ = signer_sender.send(
            Recipients::One(local),
            response(fetch.expect("signer was asked"), requested_key, &update),
            true,
        );
        let VoterMessage::Resolution { completion, .. } = resolutions
            .recv()
            .await
            .expect("the signer's update completes");
        assert_eq!(completion.job(), job);
        assert_eq!(&completion.artifact().artifact, update.as_ref());
        stop(task).await;
    });
}
