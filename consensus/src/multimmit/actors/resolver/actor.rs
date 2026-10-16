//! The resolver task: the `commonware-resolver` engine, retained artifacts, and the codec pool.
//!
//! [`Actor::start`] spawns the p2p engine over the committee and one task that serves machine
//! controls, local artifact queries, codec completions, and peer requests and deliveries. Peer
//! work waits while every codec worker is busy, so encode and decode work stays bounded by the
//! pool.

use super::{Config, Mailbox, Message, ResolveRequest, Serve, metrics::Metrics as ActorMetrics};
use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        actors::{
            util::{self, Handler, WorkerPanicked, gated, offload, some_or_pending},
            voter::Resolutions,
        },
        machine::{IdentifiedArtifact, ResolutionCompletion, ResolutionJob, RetrievalKey},
        scheme::bls12381::Scheme,
        types::{
            Artifact, ChainId, CodecConfig, Floor, Lqc, SignedLeaderBlock, SignedTransactionBlock,
            VoteUpdate, Vqc,
        },
    },
    types::{Epoch, Height, Round, View},
};
use bytes::Bytes;
use commonware_actor::{Feedback, mailbox};
use commonware_codec::{Decode as _, DecodeExt as _};
use commonware_cryptography::{Digest, Hasher, PublicKey, bls12381::primitives::variant::Variant};
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Receiver, Sender, utils::StaticProvider};
use commonware_parallel::Strategy;
use commonware_resolver::{Delivery, Fetch, Resolver, TargetedResolver as _, p2p};
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell,
    telemetry::{metrics::HistogramExt as _, traces::TracedExt as _},
};
use commonware_utils::{
    channel::{fallible::OneshotExt as _, oneshot},
    futures::Pool,
    ordered::Set,
    vec::NonEmptyVec,
};
use rand_core::Rng;
use std::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    iter::repeat_n,
    marker::PhantomData,
    mem,
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::{Span, debug, error, info_span};

/// The issuing context of one outstanding resolution job.
struct Origin {
    root: Span,
    round: Round,
    started_at: SystemTime,
}

/// A blocker that never blocks and forwards only the blocked-peer subscription.
///
/// `p2p::Engine` uses its blocker for two things: blocking peers that send invalid responses and
/// subscribing to peers blocked elsewhere. A bad response is not portable proof of a protocol
/// fault, so this actor keeps only the subscription.
#[derive(Clone)]
struct NonBlocking<B>(B);

impl<B: Blocker> Blocker for NonBlocking<B> {
    type PublicKey = B::PublicKey;

    fn block(&mut self, _: Self::PublicKey) -> Feedback {
        Feedback::Ok
    }

    fn blocked(&mut self) -> commonware_p2p::BlockedSubscription<Self::PublicKey> {
        self.0.blocked()
    }
}

/// A fetched artifact to validate or a peer request to serve one, keyed by retrieval key.
type HandlerMessage<D> = util::HandlerMessage<RetrievalKey<D>, ResolutionJob<D>, bool>;

/// Decoded artifacts paired with the jobs they complete.
type Resolved<V, D> = Vec<(ResolutionJob<D>, IdentifiedArtifact<V, D>)>;

/// The result of one artifact encode or decode on the codec pool.
pub(super) enum CodecCompletion<V: Variant, D: Digest> {
    /// A peer response decoded for each subscribed job, or `None` if it is unusable.
    Decoded {
        artifacts: Option<Resolved<V, D>>,
        response: oneshot::Sender<bool>,
    },
    /// A retained artifact encoded to serve one peer request for `key`.
    Encoded {
        key: RetrievalKey<D>,
        artifact: Arc<Artifact<V, D>>,
        value: Bytes,
        response: oneshot::Sender<Bytes>,
    },
    /// A retained certificate identified on the codec pool, with its canonical encoding.
    Identified {
        keys: Vec<RetrievalKey<D>>,
        artifact: Arc<Artifact<V, D>>,
        canonical: Bytes,
    },
    /// A copy of a retained artifact that completes one job without a fetch.
    ///
    /// Retained artifacts are shared with the serving state, while a completion hands the machine
    /// an owned artifact. Copying a certificate deep-copies its transcript and signatures, so the
    /// copy runs on the codec pool instead of the actor loop.
    Materialized(ResolutionCompletion<V, D>),
}

type CodecResult<V, D> = (Span, CodecCompletion<V, D>);
type CodecResults<V, D> = Pool<'static, CodecResult<V, D>>;
/// Jobs a retained artifact completes, awaiting a codec worker to copy it, with their issuing
/// span.
type PendingLocal<V, D> = BTreeMap<ResolutionJob<D>, (Arc<Artifact<V, D>>, Span)>;

/// Decodes an untrusted delivery on `strategy`, counting a worker panic as an invalid response so
/// a codec defect cannot stop the actor.
pub(super) async fn decode_delivery<S, V, D>(
    strategy: S,
    span: Span,
    response: oneshot::Sender<bool>,
    decode: impl FnOnce() -> Option<Resolved<V, D>> + Send + 'static,
) -> CodecResult<V, D>
where
    S: Strategy,
    V: Variant,
    D: Digest,
{
    let (span, artifacts) = offload(strategy, 1, span, move |_| decode()).await;
    let artifacts = artifacts.unwrap_or_else(|WorkerPanicked| {
        span.in_scope(|| error!("resolver decode worker panicked"));
        None
    });
    (
        span,
        CodecCompletion::Decoded {
            artifacts,
            response,
        },
    )
}

/// Runs codec work over locally held artifacts on `strategy`. A worker panic is a local defect and
/// propagates.
async fn encode_local<S, V, D>(
    strategy: S,
    span: Span,
    operation: impl FnOnce() -> CodecCompletion<V, D> + Send + 'static,
) -> CodecResult<V, D>
where
    S: Strategy,
    V: Variant,
    D: Digest,
{
    let (span, completion) = offload(strategy, 1, span, move |_| operation()).await;
    (span, completion.expect("resolver codec worker panicked"))
}

/// A peer delivery whose p2p response waits until the machine settles every job it completed.
struct Verdict<D: Digest> {
    jobs: BTreeSet<ResolutionJob<D>>,
    response: oneshot::Sender<bool>,
}

/// How the machine settled a job that a peer delivery may be waiting on.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// The machine retracted the job; deliveries waiting only on it settle as valid.
    Cancelled,
    /// The machine rejected the delivered artifact; deliveries carrying it settle as invalid.
    Rejected,
}

/// A retained artifact and its canonical encoding, once known.
struct Stored<V: Variant, D: Digest> {
    artifact: Arc<Artifact<V, D>>,
    canonical: Option<Bytes>,
}

/// The retained headers of one chain.
struct ChainHeaders<D: Digest> {
    /// Headers at or below this height are settled and no longer served.
    settled: Height,
    /// Retained header keys by height; forks put several keys at one height.
    heights: BTreeMap<Height, Vec<RetrievalKey<D>>>,
}

impl<D: Digest> Default for ChainHeaders<D> {
    fn default() -> Self {
        Self {
            settled: Height::zero(),
            heights: BTreeMap::new(),
        }
    }
}

/// In-memory artifacts this node serves to peers, by the retrieval keys that name them.
///
/// The machine owns retention and the state follows its two floors. View-scoped artifacts
/// (updates, leader blocks, V-QCs, L-QCs) retire when the machine prunes through their view,
/// except the newest L-QC, which stays servable as the finality evidence a lagging peer resumes
/// from. The newest finalization certificate with its opening is served under
/// [`RetrievalKey::LatestFloor`] until a newer one replaces it, whatever the floors.
/// Headers retire when the machine settles their chain at or above their height. Retention below
/// either floor is refused.
pub(super) struct State<V: Variant, D: Digest> {
    entries: BTreeMap<RetrievalKey<D>, Stored<V, D>>,
    /// Retained view-scoped keys in view order, so pruning visits only the entries it removes.
    views: BTreeSet<(View, RetrievalKey<D>)>,
    /// Retained headers per chain.
    headers: BTreeMap<ChainId, ChainHeaders<D>>,
    /// The highest view pruned through.
    pruned: Option<View>,
    /// The view and key of the newest retained L-QC.
    newest_lqc: Option<(View, RetrievalKey<D>)>,
}

impl<V: Variant, D: Digest> State<V, D> {
    /// Returns a state that serves nothing.
    pub(super) const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            views: BTreeSet::new(),
            headers: BTreeMap::new(),
            pruned: None,
            newest_lqc: None,
        }
    }

    /// Returns whether pruning retired `view`.
    fn is_pruned(&self, view: View) -> bool {
        self.pruned.is_some_and(|pruned| view <= pruned)
    }

    /// Serves `artifact`, whose encoding is `canonical` when known, under each of `keys` that no
    /// earlier artifact already provides. A vote update instead replaces one of its sender and tag
    /// with a lower sequence number, so the key serves the sender's latest update.
    ///
    /// An artifact below its floor is refused, except an L-QC newer than every retained one.
    pub(super) fn retain(
        &mut self,
        keys: Vec<RetrievalKey<D>>,
        artifact: Arc<Artifact<V, D>>,
        canonical: Option<Bytes>,
    ) {
        match artifact.as_ref() {
            Artifact::TransactionBlock(block) => {
                let (chain, height) = (block.header().chain(), block.header().height());
                if self
                    .headers
                    .get(&chain)
                    .is_some_and(|headers| height <= headers.settled)
                {
                    return;
                }
                let inserted = self.insert(keys, &artifact, canonical);
                self.headers
                    .entry(chain)
                    .or_default()
                    .heights
                    .entry(height)
                    .or_default()
                    .extend(inserted);
            }
            Artifact::Lqc(certificate) => {
                debug_assert_eq!(keys.len(), 1, "an L-QC is named only by its identity");
                let (view, key) = (certificate.view(), keys[0]);
                let newest = self.newest_lqc.is_none_or(|(newest, _)| view > newest);
                if !newest && self.is_pruned(view) {
                    return;
                }
                let inserted = self.insert(keys, &artifact, canonical);
                self.views
                    .extend(inserted.into_iter().map(|key| (view, key)));
                if newest
                    && let Some((replaced_view, replaced)) = self.newest_lqc.replace((view, key))
                    && self.is_pruned(replaced_view)
                {
                    self.views.remove(&(replaced_view, replaced));
                    self.entries.remove(&replaced);
                }
            }
            Artifact::Update(update) => {
                let view = update.view();
                if self.is_pruned(view) {
                    return;
                }
                debug_assert_eq!(
                    keys.len(),
                    1,
                    "an update is named only by its sender and tag"
                );
                let key = keys[0];
                let newer = self.entries.get(&key).is_none_or(|stored| {
                    matches!(
                        stored.artifact.as_ref(),
                        Artifact::Update(held) if held.seq() < update.seq()
                    )
                });
                if newer {
                    self.entries.insert(
                        key,
                        Stored {
                            artifact,
                            canonical,
                        },
                    );
                    self.views.insert((view, key));
                }
            }
            Artifact::Floor(floor) => {
                debug_assert_eq!(keys, [RetrievalKey::LatestFloor]);
                let view = floor.lqc().view();
                let newer = self
                    .entries
                    .get(&RetrievalKey::LatestFloor)
                    .is_none_or(|stored| stored.artifact.view().is_some_and(|held| held < view));
                if newer {
                    self.entries.insert(
                        RetrievalKey::LatestFloor,
                        Stored {
                            artifact,
                            canonical,
                        },
                    );
                }
            }
            Artifact::LeaderBlock(_) | Artifact::Vqc(_) => {
                let view = artifact
                    .view()
                    .expect("leader blocks and V-QCs have a view");
                if self.is_pruned(view) {
                    return;
                }
                let inserted = self.insert(keys, &artifact, canonical);
                self.views
                    .extend(inserted.into_iter().map(|key| (view, key)));
            }
        }
    }

    /// Stores `artifact` under each vacant key of `keys` and returns the keys it took.
    fn insert(
        &mut self,
        keys: Vec<RetrievalKey<D>>,
        artifact: &Arc<Artifact<V, D>>,
        canonical: Option<Bytes>,
    ) -> Vec<RetrievalKey<D>> {
        keys.into_iter()
            .filter(|&key| match self.entries.entry(key) {
                Entry::Vacant(vacant) => {
                    vacant.insert(Stored {
                        artifact: Arc::clone(artifact),
                        canonical: canonical.clone(),
                    });
                    true
                }
                Entry::Occupied(_) => false,
            })
            .collect()
    }

    /// Retires the view-scoped entries at or below `through`, keeping the newest L-QC.
    pub(super) fn prune(&mut self, through: View) {
        if self.is_pruned(through) {
            return;
        }
        self.pruned = Some(through);
        let mut kept = None;
        while let Some(&(view, key)) = self.views.first()
            && view <= through
        {
            self.views.pop_first();
            if self.newest_lqc == Some((view, key)) {
                kept = Some((view, key));
            } else {
                self.entries.remove(&key);
            }
        }
        if let Some(kept) = kept {
            self.views.insert(kept);
        }
    }

    /// Retires the headers of `chain` at or below `height`.
    pub(super) fn settle(&mut self, chain: ChainId, height: Height) {
        let headers = self.headers.entry(chain).or_default();
        if height <= headers.settled {
            return;
        }
        headers.settled = height;
        let kept = headers.heights.split_off(&height.next());
        for key in mem::replace(&mut headers.heights, kept)
            .into_values()
            .flatten()
        {
            self.entries.remove(&key);
        }
    }

    /// Returns the retained artifact `key` names.
    pub(super) fn artifact(&self, key: &RetrievalKey<D>) -> Option<Arc<Artifact<V, D>>> {
        self.entries
            .get(key)
            .map(|stored| Arc::clone(&stored.artifact))
    }

    /// Returns the cached canonical encoding of the artifact `key` names.
    fn canonical(&self, key: &RetrievalKey<D>) -> Option<Bytes> {
        self.entries
            .get(key)
            .and_then(|stored| stored.canonical.clone())
    }

    /// Caches `canonical` as the encoding of `artifact`, if `key` still names it.
    fn cache(&mut self, key: &RetrievalKey<D>, artifact: &Arc<Artifact<V, D>>, canonical: Bytes) {
        if let Some(stored) = self.entries.get_mut(key)
            && Arc::ptr_eq(&stored.artifact, artifact)
        {
            stored.canonical = Some(canonical);
        }
    }
}

/// Returns the canonical encoding of `artifact`, the value peers exchange for its keys.
fn encode<V: Variant, D: Digest>(artifact: &Artifact<V, D>) -> Bytes {
    let mut encoded = Vec::new();
    artifact.write_canonical_encoding(&mut encoded);
    Bytes::from(encoded)
}

/// Decodes a peer's `value` as the artifact kind `key` names and identifies it, returning it
/// only when it provides `key`. A vote update must name every chain: only that form is read
/// without the sender's earlier updates.
pub(super) fn decode<H: Hasher, V: Variant>(
    key: RetrievalKey<H::Digest>,
    value: Bytes,
    codec: &CodecConfig,
) -> Option<IdentifiedArtifact<V, H::Digest>> {
    let artifact = match key {
        RetrievalKey::Update { .. } => {
            let update = VoteUpdate::decode_cfg(value, codec).ok()?;
            if update.changes().len() != codec.chains() {
                return None;
            }
            Artifact::Update(update)
        }
        RetrievalKey::Header { .. } => {
            Artifact::TransactionBlock(SignedTransactionBlock::decode(value).ok()?)
        }
        RetrievalKey::Vqc(_) | RetrievalKey::VqcView(_) => {
            Artifact::Vqc(Vqc::decode_cfg(value, codec).ok()?)
        }
        RetrievalKey::LeaderBlock(_) => {
            Artifact::LeaderBlock(SignedLeaderBlock::decode(value).ok()?)
        }
        RetrievalKey::Lqc(_) => Artifact::Lqc(Lqc::decode_cfg(value, codec).ok()?),
        RetrievalKey::LatestFloor => Artifact::Floor(Floor::decode_cfg(value, codec).ok()?),
    };
    let identified = artifact.identify::<H>(&mut Vec::new());
    identified.provisions.contains(&key).then_some(identified)
}

/// Fetches and serves retrieval-keyed artifacts for one fixed epoch.
pub(crate) struct Actor<E, H, P, V, B, T>
where
    E: Clock + Spawner + Metrics + BufferPooler + Rng,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    B: Blocker<PublicKey = P>,
    T: Strategy,
{
    context: ContextCell<E>,
    scheme: Scheme<P, V>,
    blocker: B,
    strategy: T,
    fetch_timeout: Duration,
    mailbox_size: NonZeroUsize,
    mailbox: mailbox::Receiver<Message<V, H::Digest>>,
    queries: mailbox::UnreliableReceiver<Serve<V, H::Digest>>,
    metrics: ActorMetrics,
    _hasher: PhantomData<H>,
}

impl<E, H, P, V, B, T> Actor<E, H, P, V, B, T>
where
    E: Clock + Spawner + Metrics + BufferPooler + Rng,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    B: Blocker<PublicKey = P>,
    T: Strategy,
{
    /// Creates the resolver and its voter-facing control and query mailboxes.
    pub(crate) fn new(context: E, config: Config<P, V, B, T>) -> (Self, Mailbox<V, H::Digest>) {
        let (sender, receiver) = mailbox::new(context.child("mailbox"), config.mailbox_size);
        let (query_sender, query_receiver) =
            mailbox::new_unreliable(context.child("queries"), config.mailbox_size);
        (
            Self {
                metrics: ActorMetrics::new(&context),
                context: ContextCell::new(context),
                scheme: config.scheme,
                blocker: config.blocker,
                strategy: config.strategy,
                fetch_timeout: config.fetch_timeout,
                mailbox_size: config.mailbox_size,
                mailbox: receiver,
                queries: query_receiver,
                _hasher: PhantomData,
            },
            Mailbox::new(sender, query_sender),
        )
    }

    /// Starts the resolver over the epoch's registered resolver plane.
    pub(crate) fn start(
        mut self,
        voter: Resolutions<V, H::Digest>,
        network: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(voter, network))
    }

    /// Starts the p2p engine over the committee and serves until shutdown.
    async fn run(
        self,
        voter: Resolutions<V, H::Digest>,
        network: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) {
        let Self {
            context,
            scheme,
            blocker,
            strategy,
            fetch_timeout,
            mailbox_size,
            mailbox,
            queries,
            metrics,
            _hasher,
        } = self;
        let participants = scheme.participants().clone();
        let me = scheme
            .me()
            .and_then(|participant| participants.get(participant.into()))
            .cloned();
        let epoch = scheme.epoch();
        let (handler_sender, handler) =
            mailbox::new(context.as_ref().child("handler"), mailbox_size);
        let endpoint = Handler::new(handler_sender);
        let (engine, fetcher) = p2p::Engine::new(
            context.as_ref().child("p2p"),
            p2p::Config {
                peer_provider: StaticProvider::new(epoch.get(), participants),
                blocker: NonBlocking(blocker),
                consumer: endpoint.clone(),
                producer: endpoint,
                mailbox_size,
                me,
                timeout: fetch_timeout,
                fetch_retry_timeout: fetch_timeout,
                priority_requests: true,
                priority_responses: true,
            },
        );
        let engine = engine.start(network);
        Service {
            context,
            epoch,
            participants: scheme.participants().clone(),
            codec: scheme.codec_config(),
            codec_capacity: strategy.manual().parallelism(),
            strategy,
            mailbox,
            queries,
            handler,
            fetcher,
            engine,
            voter,
            state: State::new(),
            outstanding: BTreeMap::new(),
            pending_local: PendingLocal::new(),
            verdicts: Vec::new(),
            codecs: CodecResults::default(),
            peer_work_ready: true,
            metrics,
            _hasher: PhantomData::<H>,
        }
        .run()
        .await;
    }
}

/// The running resolver: its inputs, the p2p fetcher, retained artifacts, and in-flight work.
struct Service<E, H, P, V, T>
where
    E: Clock + Spawner + Metrics,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    T: Strategy,
{
    context: ContextCell<E>,
    epoch: Epoch,
    /// The committee's identity keys, indexed by participant.
    participants: Set<P>,
    codec: CodecConfig,
    strategy: T,
    /// Codec jobs allowed in flight before peer requests wait.
    codec_capacity: usize,
    mailbox: mailbox::Receiver<Message<V, H::Digest>>,
    queries: mailbox::UnreliableReceiver<Serve<V, H::Digest>>,
    handler: mailbox::Receiver<HandlerMessage<H::Digest>>,
    fetcher: p2p::Mailbox<RetrievalKey<H::Digest>, P, ResolutionJob<H::Digest>>,
    engine: Handle<()>,
    voter: Resolutions<V, H::Digest>,
    state: State<V, H::Digest>,
    outstanding: BTreeMap<ResolutionJob<H::Digest>, Origin>,
    pending_local: PendingLocal<V, H::Digest>,
    verdicts: Vec<Verdict<H::Digest>>,
    codecs: CodecResults<V, H::Digest>,
    /// Whether a codec worker is free for peer requests, computed before each select.
    peer_work_ready: bool,
    metrics: ActorMetrics,
    _hasher: PhantomData<H>,
}

impl<E, H, P, V, T> Service<E, H, P, V, T>
where
    E: Clock + Spawner + Metrics,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    T: Strategy,
{
    async fn run(mut self) {
        select_loop! {
            self.context,
            on_start => {
                self.peer_work_ready = self.materialize_pending();
            },
            on_stopped => {
                debug!("context shutdown, stopping resolver");
            },
            _ = &mut self.engine => break,
            result = self.codecs.next_completed() => {
                let (span, completion) = result;
                span.in_scope(|| self.on_codec(completion));
            },
            Some(message) = self.mailbox.recv() else break => self.on_control(message),
            // A closed query mailbox goes quiet instead of stopping the actor.
            query = some_or_pending(self.queries.recv()) => {
                let Serve { key, responder } = query;
                let _ = responder.send(self.state.artifact(&key));
            },
            // Peer requests wait while every codec worker is busy, so encode and decode work
            // stays bounded by the pool.
            Some(message) = gated(self.peer_work_ready, self.handler.recv()) else break => {
                match message {
                    HandlerMessage::Produce { key, response } => {
                        self.on_produce(key, response);
                    }
                    HandlerMessage::Deliver {
                        delivery,
                        value,
                        response,
                    } => self.on_deliver(delivery, value, response),
                }
            },
        }
    }

    /// Starts copying retained artifacts for local jobs while codec workers are free.
    ///
    /// Returns whether a worker remains for peer requests.
    fn materialize_pending(&mut self) -> bool {
        while self.codecs.len() < self.codec_capacity {
            let Some((job, (artifact, parent))) = self.pending_local.pop_first() else {
                break;
            };
            let span = info_span!(
                parent: &parent,
                "multimmit.resolver.resolve.materialize",
                key = %job.key(),
                job = job.issued().id().get().traced(),
            );
            let operation = move || {
                CodecCompletion::Materialized(ResolutionCompletion::new(
                    job,
                    artifact.as_ref().clone().identify::<H>(&mut Vec::new()),
                ))
            };
            self.codecs
                .push(encode_local(self.strategy.clone(), span, operation));
        }
        self.codecs.len() < self.codec_capacity
    }

    /// Applies one finished codec job.
    fn on_codec(&mut self, completion: CodecCompletion<V, H::Digest>) {
        match completion {
            CodecCompletion::Decoded {
                artifacts: None,
                response,
            } => {
                self.metrics.mismatched.inc();
                response.send_lossy(false);
            }
            CodecCompletion::Decoded {
                artifacts: Some(artifacts),
                response,
            } => {
                let mut jobs = BTreeSet::new();
                for (job, artifact) in artifacts {
                    let Some(origin) = self.outstanding.get(&job) else {
                        continue;
                    };
                    jobs.insert(job);
                    self.complete(origin, ResolutionCompletion::new(job, artifact));
                }
                if jobs.is_empty() {
                    response.send_lossy(true);
                } else {
                    self.verdicts.push(Verdict { jobs, response });
                }
            }
            CodecCompletion::Encoded {
                key,
                artifact,
                value,
                response,
            } => {
                self.state.cache(&key, &artifact, value.clone());
                self.metrics.served.inc();
                self.metrics.served_bytes.inc_by(value.len() as u64);
                response.send_lossy(value);
            }
            CodecCompletion::Identified {
                keys,
                artifact,
                canonical,
            } => self.state.retain(keys, artifact, Some(canonical)),
            CodecCompletion::Materialized(completion) => {
                if let Some(origin) = self.outstanding.get(&completion.job()) {
                    self.complete(origin, completion);
                }
            }
        }
    }

    /// Applies one control message from the voter.
    fn on_control(&mut self, message: Message<V, H::Digest>) {
        match message {
            Message::Resolve(request) => self.on_resolve(request),
            Message::Cancel { job } => self.retire(BTreeSet::from([job]), Outcome::Cancelled),
            Message::Reject { job } => {
                self.metrics.rejected.inc();
                self.retire(BTreeSet::from([job]), Outcome::Rejected);
            }
            Message::Retain { artifact } => self.retain(artifact),
            Message::Prune { through } => self.prune(through),
            Message::SettleHeaders { chain, height } => self.state.settle(chain, height),
        }
    }

    /// Serves one machine-verified artifact.
    ///
    /// A certificate's identity hashes its whole canonical encoding, which can be megabytes, so a
    /// codec worker identifies it and the encoding is kept to serve peers. Every other artifact is
    /// identified from its fields here.
    fn retain(&mut self, artifact: Arc<Artifact<V, H::Digest>>) {
        if !matches!(artifact.as_ref(), Artifact::Vqc(_) | Artifact::Lqc(_)) {
            self.state
                .retain(artifact.provisions::<H>(), artifact, None);
            return;
        }
        let span = info_span!(
            "multimmit.resolver.retain.identify",
            epoch = self.epoch.get().traced(),
        );
        let operation = move || {
            let canonical = encode(&artifact);
            let keys = artifact.provisions_from_canonical_encoding::<H>(&canonical);
            CodecCompletion::Identified {
                keys,
                artifact,
                canonical,
            }
        };
        self.codecs
            .push(encode_local(self.strategy.clone(), span, operation));
    }

    /// Retires served evidence and outstanding view-scoped retrievals at or below `through`.
    fn prune(&mut self, through: View) {
        self.state.prune(through);
        let retired = self
            .outstanding
            .keys()
            .filter(|job| job.key().view().is_some_and(|view| view <= through))
            .copied()
            .collect::<BTreeSet<_>>();
        if !retired.is_empty() {
            self.retire(retired, Outcome::Cancelled);
        }
    }

    /// Starts one machine-issued request, completing it from retained artifacts when possible.
    ///
    /// A request for a peer's newest floor is always fetched: this node's own floor answers
    /// nothing it asks.
    fn on_resolve(&mut self, request: ResolveRequest<H::Digest>) {
        let process = info_span!(
            parent: &request.span,
            "multimmit.resolver.resolve.process",
            epoch = request.round.epoch().get().traced(),
            view = request.round.view().get().traced(),
            job = request.job.issued().id().get().traced(),
        );
        let _entered = process.enter();
        let job = request.job;
        if self.outstanding.contains_key(&job) {
            return;
        }
        self.metrics.requests.inc();
        self.outstanding.insert(
            job,
            Origin {
                root: request.root,
                round: request.round,
                started_at: self.context.current(),
            },
        );
        if job.key() != RetrievalKey::LatestFloor
            && let Some(artifact) = self.state.artifact(&job.key())
        {
            self.pending_local.insert(job, (artifact, process.clone()));
            return;
        }
        let span = info_span!(
            parent: &process,
            "multimmit.resolver.resolve.fetch",
            key = %job.key(),
            job = job.issued().id().get().traced(),
        );
        let fetch = Fetch {
            key: job.key(),
            subscriber: job,
            span,
        };
        // Only its signer holds a sender's latest update of a tag, so an update is requested from
        // the signer alone and waits for it instead of spending retry periods on peers that cannot
        // answer. Any peer that holds a header or certificate may serve it.
        if let RetrievalKey::Update { signer, .. } = job.key() {
            let Some(signer) = self.participants.get(usize::from(signer)) else {
                return;
            };
            let _ = self
                .fetcher
                .fetch_targeted(fetch, NonEmptyVec::new(signer.clone()));
        } else {
            let _ = self.fetcher.fetch(fetch);
        }
    }

    /// Serves one peer request for `key` from retained artifacts.
    fn on_produce(&mut self, key: RetrievalKey<H::Digest>, response: oneshot::Sender<Bytes>) {
        if let Some(value) = self.state.canonical(&key) {
            self.metrics.served.inc();
            self.metrics.served_bytes.inc_by(value.len() as u64);
            response.send_lossy(value);
            return;
        }
        let Some(artifact) = self.state.artifact(&key) else {
            return;
        };
        let span = info_span!(
            "multimmit.resolver.serve.encode",
            epoch = self.epoch.get().traced(),
            key = %key,
        );
        let operation = move || CodecCompletion::Encoded {
            key,
            value: encode(&artifact),
            artifact,
            response,
        };
        self.codecs
            .push(encode_local(self.strategy.clone(), span, operation));
    }

    /// Decodes one fetched value for every job subscribed to its key.
    fn on_deliver(
        &mut self,
        delivery: Delivery<RetrievalKey<H::Digest>, ResolutionJob<H::Digest>>,
        value: Bytes,
        response: oneshot::Sender<bool>,
    ) {
        let requested = delivery.key;
        let (_, cause) = delivery.subscribers.first();
        let deliver = info_span!(
            parent: cause,
            "multimmit.resolver.resolve.deliver",
            epoch = self.epoch.get().traced(),
            key = %requested,
        );
        for (_, cause) in delivery.subscribers.iter().skip(1) {
            deliver.follows_from(cause.id());
        }
        let codec = self.codec;
        let decode = move || {
            let artifact = decode::<H, V>(requested, value, &codec)?;
            let artifacts = repeat_n(artifact, delivery.subscribers.len().get())
                .zip(delivery.subscribers.iter())
                .map(|(artifact, (job, _))| (*job, artifact))
                .collect();
            Some(artifacts)
        };
        self.codecs.push(decode_delivery(
            self.strategy.clone(),
            deliver,
            response,
            decode,
        ));
    }

    /// Hands one resolved artifact to the voter.
    fn complete(&self, origin: &Origin, completion: ResolutionCompletion<V, H::Digest>) {
        self.metrics.resolved.inc();
        self.metrics
            .resolved_latency
            .observe_between(origin.started_at, self.context.current());
        let span = info_span!(
            "multimmit.resolver.resolve.complete",
            epoch = origin.round.epoch().get().traced(),
            view = origin.round.view().get().traced()
        );
        let _ = self
            .voter
            .resolved(origin.root.clone(), span, origin.round, completion);
    }

    /// Stops tracking jobs the machine settled and answers the peer deliveries waiting on them.
    fn retire(&mut self, jobs: BTreeSet<ResolutionJob<H::Digest>>, outcome: Outcome) {
        self.outstanding.retain(|job, _| !jobs.contains(job));
        self.pending_local.retain(|job, _| !jobs.contains(job));
        settle(&mut self.verdicts, &jobs, outcome);
        let _ = self
            .fetcher
            .retain(move |_, candidate| !jobs.contains(candidate));
    }
}

/// Answers every delivery whose verdict `jobs` decide.
///
/// A rejection settles each delivery carrying one of `jobs` as invalid. A cancellation settles a
/// delivery as valid once none of its jobs remain.
fn settle<D: Digest>(
    verdicts: &mut Vec<Verdict<D>>,
    jobs: &BTreeSet<ResolutionJob<D>>,
    outcome: Outcome,
) {
    let settled = verdicts.extract_if(.., |verdict| {
        let waiting = verdict.jobs.len();
        verdict.jobs.retain(|job| !jobs.contains(job));
        verdict.jobs.len() < waiting && (outcome == Outcome::Rejected || verdict.jobs.is_empty())
    });
    for verdict in settled {
        verdict.response.send_lossy(outcome == Outcome::Cancelled);
    }
}
