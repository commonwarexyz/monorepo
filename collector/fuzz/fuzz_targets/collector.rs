#![no_main]

//! Fuzz collector engines over a simulated network.
//!
//! Every honest peer runs an engine whose handler and monitor record what they observe. One more
//! peer, the Byzantine peer, runs no engine. It injects well-formed, malformed, unsolicited, and
//! duplicate traffic on the channel and answers the requests it receives. The input may also
//! leave one engine unable to send responses.
//!
//! The harness builds and parses messages itself from the layout the crate documents, where a tag
//! byte of 0 opens a request and 1 opens a response. Every message an engine sends the Byzantine
//! peer must parse, so the harness also checks that layout.
//!
//! After every operation the harness checks what the monitors collected and what the handlers
//! processed against a model of what the originators asked for. Every mailbox call must be
//! accepted, so an engine that stops early fails the run.
//!
//! A final settle phase checks response routing, blocking, and the engines' metrics. On reliable
//! links it also checks that an originator collected every honest peer that answered one of its
//! requests immediately, unless the request's commitment was ever cancelled or the peer cannot send
//! responses.

use arbitrary::{Arbitrary, Unstructured};
use commonware_actor::{Feedback, Unreliable};
use commonware_codec::{
    Buf, Copying, Decode, Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read,
    ReadExt, ReadRangeExt, Write,
};
use commonware_collector::{
    Handler, Monitor, Originator,
    p2p::{Config, Engine, Mailbox},
};
use commonware_cryptography::{
    Committable, Hasher, Sha256, Signer,
    ed25519::{PrivateKey, PublicKey},
    sha256::Digest,
};
use commonware_p2p::{
    CheckedSender, LimitedSender, Receiver, Recipients, Sender,
    simulated::{Config as NetworkConfig, Link, Network},
};
use commonware_runtime::{
    BufMut, Clock, IoBufs, Metrics as _, Quota, Runner, Supervisor as _, deterministic,
    telemetry::metrics::status::Status,
};
use commonware_utils::{
    NZU32, NZUsize, Widen,
    channel::{fallible::OneshotExt as _, oneshot},
    probability,
    sync::Mutex,
};
use futures::FutureExt as _;
use libfuzzer_sys::fuzz_target;
use std::{
    collections::{HashMap, HashSet},
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, SystemTime},
};

/// Channel carrying requests and responses.
const CHANNEL: u64 = 0;

/// Tag that opens a request on the channel.
const REQUEST: u8 = 0;

/// Tag that opens a response on the channel.
const RESPONSE: u8 = 1;

/// Rate limit high enough that honest traffic is never limited.
const QUOTA: Quota = Quota::per_second(NZU32!(1_000_000));

/// Longest payload either codec accepts.
const MAX_DATA: usize = 32;

/// Longest message the Byzantine peer sends. It stays far below the network's maximum message size.
const MAX_RAW: usize = 1024;

/// Number of distinct request ids. It is small so that commitments collide often.
const ID_SPACE: u64 = 8;

/// Largest number of honest peers in a run.
const MAX_HONEST: usize = 4;

/// Largest number of operations in a run.
const MAX_OPERATIONS: usize = 64;

/// Longest sleep between two operations, in milliseconds.
const MAX_SLEEP_MS: u64 = 500;

/// Time for every message in flight, and every response it prompts, to arrive.
const SETTLE: Duration = Duration::from_secs(5);

/// Codec configuration every engine uses for requests and responses.
fn codec() -> RangeCfg<usize> {
    RangeCfg::from(..=MAX_DATA)
}

/// Commitment shared by every request and response with `id`.
fn commitment(id: u64) -> Digest {
    Sha256::hash(&[&id.to_be_bytes()])
}

/// A request whose commitment covers its id and not its data.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct FuzzRequest {
    id: u64,
    data: Vec<u8>,
}

impl Write for FuzzRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.id.write(buf);
        self.data.write(buf);
    }
}

impl EncodeSize for FuzzRequest {
    fn encode_size(&self) -> usize {
        u64::SIZE + self.data.encode_size()
    }
}

impl Read for FuzzRequest {
    type Cfg = RangeCfg<usize>;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let id = u64::read(buf)?;
        let data = Vec::read_range(buf, *cfg)?;
        Ok(Self { id, data })
    }
}

impl Committable for FuzzRequest {
    type Commitment = Digest;

    fn commitment(&self) -> Digest {
        commitment(self.id)
    }
}

/// A response whose commitment covers its id and not its result.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct FuzzResponse {
    id: u64,
    result: Vec<u8>,
}

impl Write for FuzzResponse {
    fn write(&self, buf: &mut impl BufMut) {
        self.id.write(buf);
        self.result.write(buf);
    }
}

impl EncodeSize for FuzzResponse {
    fn encode_size(&self) -> usize {
        u64::SIZE + self.result.encode_size()
    }
}

impl Read for FuzzResponse {
    type Cfg = RangeCfg<usize>;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let id = u64::read(buf)?;
        let result = Vec::read_range(buf, *cfg)?;
        Ok(Self { id, result })
    }
}

impl Committable for FuzzResponse {
    type Commitment = Digest;

    fn commitment(&self) -> Digest {
        commitment(self.id)
    }
}

/// A message on the channel.
enum Message {
    Request(FuzzRequest),
    Response(FuzzResponse),
}

/// Parses `bytes` as a tag followed by the encoding it names. Returns `None` when the tag is
/// missing or unknown, when the body does not decode, or when bytes trail the body.
fn decode(bytes: &[u8]) -> Option<Message> {
    let (tag, body) = bytes.split_first()?;
    match *tag {
        REQUEST => FuzzRequest::decode_cfg(Copying(body), &codec())
            .ok()
            .map(Message::Request),
        RESPONSE => FuzzResponse::decode_cfg(Copying(body), &codec())
            .ok()
            .map(Message::Response),
        _ => None,
    }
}

/// A sender that reports each response as not accepted without sending it and forwards every
/// other message to the sender it wraps.
#[derive(Clone)]
struct Muted<S>(S);

impl<S: LimitedSender> LimitedSender for Muted<S> {
    type PublicKey = S::PublicKey;
    type Checked<'a>
        = CheckedMuted<S::Checked<'a>>
    where
        Self: 'a;

    fn check(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
    ) -> Result<Self::Checked<'_>, SystemTime> {
        self.0.check(recipients).map(CheckedMuted)
    }
}

/// The [CheckedSender] of a [Muted] sender.
struct CheckedMuted<C>(C);

impl<C: CheckedSender> CheckedSender for CheckedMuted<C> {
    type PublicKey = C::PublicKey;

    fn recipients(&self) -> Vec<Self::PublicKey> {
        self.0.recipients()
    }

    fn send(self, message: impl Into<IoBufs> + Send, priority: bool) -> Unreliable<Feedback> {
        let message = message.into();
        if message.chunk_at(0).and_then(<[u8]>::first) == Some(&RESPONSE) {
            return Unreliable::new(Feedback::Closed);
        }
        self.0.send(message, priority)
    }
}

/// How a handler treats a request, chosen by the first byte of its data.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Behavior {
    /// Answer immediately.
    Respond,
    /// Drop the responder.
    Drop,
    /// Keep the responder until an [Operation::Release].
    Hold,
}

/// Returns how every handler treats `request`.
fn behavior(request: &FuzzRequest) -> Behavior {
    match request.data.first().copied().unwrap_or(0) % 3 {
        0 => Behavior::Respond,
        1 => Behavior::Drop,
        _ => Behavior::Hold,
    }
}

/// Returns the response to `request`.
fn answer(request: &FuzzRequest) -> FuzzResponse {
    FuzzResponse {
        id: request.id,
        result: request.data.iter().rev().copied().collect(),
    }
}

/// The engine that served a request, the request's authenticated origin, and the request.
type Processed = (usize, PublicKey, FuzzRequest);

/// The engine that collected a response, the handler that sent it, the response, and the reported
/// count.
type Collected = (usize, PublicKey, FuzzResponse, usize);

/// The engine whose handler holds a responder, the request, and the responder.
type Held = (usize, FuzzRequest, oneshot::Sender<FuzzResponse>);

/// Observations shared by every handler and monitor.
#[derive(Clone, Default)]
struct Log {
    processed: Arc<Mutex<Vec<Processed>>>,
    collected: Arc<Mutex<Vec<Collected>>>,
    held: Arc<Mutex<Vec<Held>>>,
}

/// A handler that logs each request and treats it as its [Behavior] says.
#[derive(Clone)]
struct RecordingHandler {
    index: usize,
    log: Log,
}

impl Handler for RecordingHandler {
    type PublicKey = PublicKey;
    type Request = FuzzRequest;
    type Response = FuzzResponse;

    fn process(
        &mut self,
        origin: PublicKey,
        request: FuzzRequest,
    ) -> oneshot::Receiver<FuzzResponse> {
        self.log
            .processed
            .lock()
            .push((self.index, origin, request.clone()));
        let (responder, receiver) = oneshot::channel();
        match behavior(&request) {
            Behavior::Respond => {
                responder.send_lossy(answer(&request));
            }
            Behavior::Drop => drop(responder),
            Behavior::Hold => self.log.held.lock().push((self.index, request, responder)),
        }
        receiver
    }
}

/// A monitor that logs each response it is given.
#[derive(Clone)]
struct RecordingMonitor {
    index: usize,
    log: Log,
}

impl Monitor for RecordingMonitor {
    type PublicKey = PublicKey;
    type Response = FuzzResponse;

    fn collected(&mut self, handler: PublicKey, response: FuzzResponse, count: usize) {
        self.log
            .collected
            .lock()
            .push((self.index, handler, response, count));
    }
}

/// Recipients of an honest send. Each index wraps around the honest peers followed by the
/// Byzantine peer.
#[derive(Debug, Arbitrary)]
enum Target {
    All,
    One(u8),
    Some(Vec<u8>),
}

/// Body the Byzantine peer sends under a tag.
#[derive(Debug, Arbitrary)]
enum Payload {
    /// A well-formed body with a colliding id.
    Valid { id: u8, data: Vec<u8> },
    /// Arbitrary bytes that may or may not decode.
    Raw(Vec<u8>),
}

impl Payload {
    /// Returns the message carrying this body under `tag`. A valid body is the encoding of what
    /// `valid` builds from its id and data.
    fn tagged<T: Encode>(self, tag: u8, valid: impl FnOnce(u64, Vec<u8>) -> T) -> Vec<u8> {
        match self {
            Self::Valid { id, mut data } => {
                data.truncate(MAX_DATA);
                (tag, valid(u64::from(id) % ID_SPACE, data))
                    .encode()
                    .to_vec()
            }
            Self::Raw(body) => std::iter::once(tag).chain(body).collect(),
        }
    }
}

/// One step of a run.
#[derive(Debug, Arbitrary)]
enum Operation {
    /// An honest engine sends a request.
    Send {
        from: u8,
        id: u8,
        data: Vec<u8>,
        target: Target,
    },
    /// An honest engine sends the same request to each target in turn, so later sends join the
    /// collection an earlier one started.
    Burst {
        from: u8,
        id: u8,
        data: Vec<u8>,
        targets: Vec<u8>,
    },
    /// An honest engine cancels a commitment.
    Cancel { from: u8, id: u8 },
    /// Every held responder answers.
    Release,
    /// The Byzantine peer sends a body under the request tag.
    ByzantineRequest { to: u8, payload: Payload },
    /// The Byzantine peer sends a body under the response tag.
    ByzantineResponse { to: u8, payload: Payload },
    /// The Byzantine peer sends arbitrary bytes with no tag added, so a message may be empty or
    /// open with an unknown tag.
    ByzantineBytes { to: u8, bytes: Vec<u8> },
    /// The Byzantine peer answers each request it has received since its last answer, sending one
    /// to three copies.
    ByzantineAnswer { copies: u8 },
    /// Simulated time passes.
    Sleep { ms: u16 },
}

/// The network, the engines' configuration, and the operations of one run.
#[derive(Debug)]
struct FuzzInput {
    seed: u64,
    honest: usize,
    mailbox_size: NonZeroUsize,
    reliable: bool,
    disconnect_on_block: bool,
    muted: Option<u8>,
    latency_ms: u64,
    priority_requests: bool,
    priority_responses: bool,
    operations: Vec<Operation>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let seed = u.arbitrary()?;
        let honest = u.int_in_range(2..=MAX_HONEST)?;
        let mailbox_size = NonZeroUsize::new(u.int_in_range(1..=4)?).unwrap();
        let reliable = u.arbitrary()?;
        let disconnect_on_block = u.arbitrary()?;
        let muted = if u.ratio(1u8, 4u8)? {
            Some(u.arbitrary()?)
        } else {
            None
        };
        let latency_ms = u.int_in_range(1..=100)?;
        let priority_requests = u.arbitrary()?;
        let priority_responses = u.arbitrary()?;
        let count = u.int_in_range(1..=MAX_OPERATIONS)?;
        let operations = (0..count)
            .map(|_| Operation::arbitrary(u))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            seed,
            honest,
            mailbox_size,
            reliable,
            disconnect_on_block,
            muted,
            latency_ms,
            priority_requests,
            priority_responses,
            operations,
        })
    }
}

/// What the harness knows about one honest originator. Period `k` of a commitment holds the sends
/// enqueued after `k` cancels of that commitment.
#[derive(Default)]
struct Sent {
    /// Peers each commitment was addressed to in each of its periods.
    addressed: HashMap<Digest, Vec<HashSet<PublicKey>>>,
    /// Every request enqueued, paired with each peer it was addressed to.
    sent: HashSet<(PublicKey, FuzzRequest)>,
    /// Number of cancels enqueued for each commitment.
    cancels: HashMap<Digest, usize>,
    /// Periods the latest collection of each commitment may belong to, and the handlers collected.
    collections: HashMap<Digest, (Vec<usize>, HashSet<PublicKey>)>,
    /// Commitments the engine must be collecting once it has handled every enqueued command.
    live: HashSet<Digest>,
    /// Number of sends enqueued.
    sends: usize,
}

/// What the harness expects of every engine.
struct Model {
    /// What each honest originator has sent and cancelled.
    originators: Vec<Sent>,
    /// Decodable requests the Byzantine peer sent to each engine.
    byzantine_requests: Vec<Vec<FuzzRequest>>,
    /// Number of responses each engine sent the Byzantine peer.
    answered: Vec<usize>,
    /// Engines the Byzantine peer sent undecodable bytes to.
    expect_block: Vec<bool>,
    /// The engine that cannot send responses, if any.
    muted: Option<PublicKey>,
    /// Number of responses each engine's monitor collected.
    collected: Vec<usize>,
    /// Number of requests each engine's handler processed.
    processed: Vec<usize>,
    /// Number of requests each engine's handler declined.
    declined: Vec<usize>,
}

impl Model {
    /// Records that originator `from` enqueues `request` for the peers in `addressed`.
    fn record_send(&mut self, from: usize, request: &FuzzRequest, addressed: Vec<PublicKey>) {
        let commitment = request.commitment();
        let originator = &mut self.originators[from];
        originator.sends += 1;
        if !addressed.is_empty() {
            originator.live.insert(commitment);
        }
        for peer in &addressed {
            originator.sent.insert((peer.clone(), request.clone()));
        }
        let period = originator.cancels.get(&commitment).copied().unwrap_or(0);
        let periods = originator.addressed.entry(commitment).or_default();
        if periods.len() <= period {
            periods.resize_with(period + 1, HashSet::new);
        }
        periods[period].extend(addressed);
    }

    /// Checks every observation recorded since the previous call.
    fn check(&mut self, log: &Log, peers: &[PublicKey], byzantine: &PublicKey) {
        // A collected response never comes from the engine that cannot send responses, and a
        // collection collects each handler at most once with a count that grows by one per handler.
        //
        // The engine handles commands in order and its mailbox drops only queued sends and repeated
        // cancels. Every handler of a collection was therefore addressed in one period, and that
        // period is later than the previous collection's.
        for (index, handler, response, count) in log.collected.lock().drain(..) {
            self.collected[index] += 1;
            let originator = &mut self.originators[index];
            let commitment = response.commitment();
            let periods = originator
                .addressed
                .get(&commitment)
                .expect("a collected commitment must have been sent");
            assert_ne!(
                self.muted.as_ref(),
                Some(&handler),
                "an engine that cannot send responses must not be collected"
            );
            let (candidates, responders) = originator.collections.entry(commitment).or_default();
            if count == 1 {
                let first = candidates.first().map_or(0, |period| period + 1);
                *candidates = (first..periods.len()).collect();
                responders.clear();
            }
            assert_eq!(
                responders.len() + 1,
                count,
                "count must grow by one with each handler collected"
            );
            assert!(
                responders.insert(handler.clone()),
                "a handler must be collected at most once per collection"
            );
            candidates.retain(|period| periods[*period].contains(&handler));
            assert!(
                !candidates.is_empty(),
                "a collection's handlers must share a period later than the previous collection's"
            );
        }

        // Each processed request is one its origin sent to this handler.
        for (index, origin, request) in log.processed.lock().drain(..) {
            self.processed[index] += 1;
            if behavior(&request) == Behavior::Drop {
                self.declined[index] += 1;
            }
            if &origin == byzantine {
                assert!(
                    self.byzantine_requests[index].contains(&request),
                    "a handler must only see requests the Byzantine peer sent"
                );
                continue;
            }
            let from = peers
                .iter()
                .position(|peer| peer == &origin)
                .expect("a request must come from a known peer");
            assert!(
                self.originators[from]
                    .sent
                    .contains(&(peers[index].clone(), request)),
                "a handler must only see requests its origin addressed to it"
            );
        }
    }

    /// Drains the messages the Byzantine peer has received and returns each request with its
    /// origin. Each request must be one its origin addressed to the Byzantine peer, and each
    /// response must answer a request the Byzantine peer sent the engine it comes from.
    fn drain(
        &mut self,
        receiver: &mut impl Receiver<PublicKey = PublicKey>,
        peers: &[PublicKey],
        byzantine: &PublicKey,
    ) -> Vec<(PublicKey, FuzzRequest)> {
        let mut requests = Vec::new();
        while let Some(Ok((origin, bytes))) = receiver.recv().now_or_never() {
            let index = peers
                .iter()
                .position(|peer| peer == &origin)
                .expect("a message must come from an engine");
            match decode(bytes.as_ref())
                .expect("an engine must send a tag followed by the encoding it names")
            {
                // An engine sends the Byzantine peer only the requests its originator addressed
                // to it.
                Message::Request(request) => {
                    assert!(
                        self.originators[index]
                            .sent
                            .contains(&(byzantine.clone(), request.clone())),
                        "the Byzantine peer must only receive requests their origin addressed to it"
                    );
                    requests.push((origin, request));
                }

                // Engines answer only the requester, so the Byzantine peer receives at most one
                // response per decodable request it sent, and each one answers such a request.
                Message::Response(response) => {
                    self.answered[index] += 1;
                    assert!(
                        self.answered[index] <= self.byzantine_requests[index].len(),
                        "an engine must only answer requests the Byzantine peer sent"
                    );
                    assert!(
                        self.byzantine_requests[index]
                            .iter()
                            .any(|request| answer(request) == response),
                        "an engine must send the Byzantine peer only the answers its handler gave"
                    );
                }
            }
        }
        requests
    }
}

/// Truncates `message` to [MAX_RAW] bytes and sends it from the Byzantine peer to the engine `to`
/// picks. Records in `model` whether that engine may serve it or must block its sender.
fn send_byzantine(
    model: &mut Model,
    sender: &mut impl Sender<PublicKey = PublicKey>,
    peers: &[PublicKey],
    to: u8,
    mut message: Vec<u8>,
) {
    let to = usize::from(to) % peers.len();
    message.truncate(MAX_RAW);
    match decode(&message) {
        Some(Message::Request(request)) => model.byzantine_requests[to].push(request),
        Some(Message::Response(_)) => {}
        None => model.expect_block[to] = true,
    }
    sender.send(Recipients::One(peers[to].clone()), message, false);
}

/// Asserts that a mailbox accepted a call. Every engine runs until the harness drops its
/// mailbox, so a closed mailbox means the engine stopped early.
fn expect_running(feedback: Feedback) {
    assert!(
        feedback.accepted(),
        "an engine must keep running: {feedback:?}"
    );
}

/// Reads the metric exported as `name` by the engine at `index` from the encoded `metrics`.
fn metric(metrics: &str, name: &str, index: usize) -> usize {
    let prefix = format!("engine_{name}{{");
    let label = format!("index=\"{index}\"");
    metrics
        .lines()
        .find(|line| line.starts_with(&prefix) && line.contains(&label))
        .and_then(|line| line.rsplit(' ').next()?.parse().ok())
        .expect("every engine must export its metrics")
}

/// Reads from the encoded `metrics` how often the engine at `index` counted `status` in `family`. A
/// status that was never counted reads as zero.
fn count(metrics: &str, family: &str, status: Status, index: usize) -> usize {
    let prefix = format!("engine_{family}_total{{");
    let engine = format!("index=\"{index}\"");
    let status = format!("status=\"{status:?}\"");
    metrics
        .lines()
        .find(|line| line.starts_with(&prefix) && line.contains(&engine) && line.contains(&status))
        .map_or(0, |line| {
            line.rsplit(' ')
                .next()
                .and_then(|value| value.parse().ok())
                .expect("a counter line must end in its value")
        })
}

/// Runs the operations of `input` against a fresh network and checks the engines against the
/// model.
fn fuzz(input: FuzzInput) {
    let executor = deterministic::Runner::seeded(input.seed);
    executor.start(|context| async move {
        // Derive the honest peers and the Byzantine peer.
        let honest = input.honest;
        let peers: Vec<PublicKey> = (0..honest)
            .map(|seed| PrivateKey::from_seed(Widen::widen(seed)).public_key())
            .collect();
        let byzantine = PrivateKey::from_seed(u64::MAX).public_key();
        let everyone: Vec<PublicKey> = peers
            .iter()
            .cloned()
            .chain(std::iter::once(byzantine.clone()))
            .collect();

        // Every peer tracks everyone. Links touching the Byzantine peer are reliable so that its
        // malformed bytes always arrive. Honest links lose messages unless the input makes them
        // reliable.
        let (network, oracle) = Network::<_, PublicKey>::new_with_peers(
            context.child("network"),
            NetworkConfig {
                max_size: 1024 * 1024,
                max_peers_per_set: NZUsize!(everyone.len()),
                disconnect_on_block: input.disconnect_on_block,
                tracked_peer_sets: NZUsize!(1),
            },
            everyone.clone(),
        )
        .await;
        network.start();
        let honest_link = Link {
            latency: Duration::from_millis(input.latency_ms),
            jitter: Duration::from_millis(input.latency_ms / 4),
            success_rate: if input.reliable {
                probability!(1.0)
            } else {
                probability!(9, 10)
            },
        };
        let byzantine_link = Link {
            success_rate: probability!(1.0),
            ..honest_link.clone()
        };
        for from in &everyone {
            for to in &everyone {
                if from == to {
                    continue;
                }
                let link = if from == &byzantine || to == &byzantine {
                    byzantine_link.clone()
                } else {
                    honest_link.clone()
                };
                oracle
                    .add_link(from.clone(), to.clone(), link)
                    .await
                    .unwrap();
            }
        }

        // Start one engine per honest peer, and register the Byzantine peer on the channel.
        let muted = input
            .muted
            .map(|index| peers[usize::from(index) % honest].clone());
        let log = Log::default();
        let mut mailboxes: Vec<Mailbox<PublicKey, FuzzRequest>> = Vec::new();
        for (index, peer) in peers.iter().enumerate() {
            let control = oracle.control(peer.clone());
            let (sender, receiver) = control.register(CHANNEL, QUOTA).await.unwrap();
            let (engine, mailbox) = Engine::new(
                context.child("engine").with_attribute("index", index),
                Config {
                    blocker: control,
                    monitor: RecordingMonitor {
                        index,
                        log: log.clone(),
                    },
                    handler: RecordingHandler {
                        index,
                        log: log.clone(),
                    },
                    mailbox_size: input.mailbox_size,
                    priority_requests: input.priority_requests,
                    request_codec_config: codec(),
                    priority_responses: input.priority_responses,
                    response_codec_config: codec(),
                },
            );

            // `Muted` drops only responses, so the engine that cannot send responses still sends
            // requests.
            if muted.as_ref() == Some(peer) {
                engine.start((Muted(sender), receiver));
            } else {
                engine.start((sender, receiver));
            }
            mailboxes.push(mailbox);
        }
        let control = oracle.control(byzantine.clone());
        let (mut byzantine_sender, mut byzantine_inbox) =
            control.register(CHANNEL, QUOTA).await.unwrap();

        // The model starts with nothing sent, processed, or collected.
        let mut model = Model {
            originators: (0..honest).map(|_| Sent::default()).collect(),
            byzantine_requests: vec![Vec::new(); honest],
            answered: vec![0; honest],
            expect_block: vec![false; honest],
            muted,
            collected: vec![0; honest],
            processed: vec![0; honest],
            declined: vec![0; honest],
        };

        // Apply each operation, then check what the engines observed against the model.
        let pick = |index: u8| everyone[usize::from(index) % everyone.len()].clone();
        for operation in input.operations {
            match operation {
                Operation::Send {
                    from,
                    id,
                    mut data,
                    target,
                } => {
                    let from = usize::from(from) % honest;
                    data.truncate(MAX_DATA);
                    let request = FuzzRequest {
                        id: u64::from(id) % ID_SPACE,
                        data,
                    };
                    let (recipients, addressed) = match target {
                        Target::All => {
                            let others: Vec<_> = everyone
                                .iter()
                                .filter(|peer| *peer != &peers[from])
                                .cloned()
                                .collect();
                            (Recipients::All, others)
                        }
                        Target::One(index) => {
                            let peer = pick(index);
                            (Recipients::One(peer.clone()), vec![peer])
                        }
                        Target::Some(indices) => {
                            let chosen: Vec<_> = indices
                                .into_iter()
                                .take(everyone.len() + 1)
                                .map(pick)
                                .collect();
                            (Recipients::Some(chosen.clone()), chosen)
                        }
                    };
                    model.record_send(from, &request, addressed);
                    expect_running(mailboxes[from].send(recipients, request));
                }
                Operation::Burst {
                    from,
                    id,
                    mut data,
                    targets,
                } => {
                    let from = usize::from(from) % honest;
                    data.truncate(MAX_DATA);
                    let request = FuzzRequest {
                        id: u64::from(id) % ID_SPACE,
                        data,
                    };
                    for peer in targets.into_iter().take(everyone.len() + 1).map(pick) {
                        model.record_send(from, &request, vec![peer.clone()]);
                        expect_running(
                            mailboxes[from].send(Recipients::One(peer), request.clone()),
                        );
                    }
                }
                Operation::Cancel { from, id } => {
                    let from = usize::from(from) % honest;
                    let commitment = commitment(u64::from(id) % ID_SPACE);
                    let originator = &mut model.originators[from];
                    *originator.cancels.entry(commitment).or_default() += 1;
                    originator.live.remove(&commitment);
                    expect_running(mailboxes[from].cancel(commitment));
                }
                Operation::Release => {
                    for (_, request, responder) in log.held.lock().drain(..) {
                        responder.send_lossy(answer(&request));
                    }
                }
                Operation::ByzantineRequest { to, payload } => {
                    let message = payload.tagged(REQUEST, |id, data| FuzzRequest { id, data });
                    send_byzantine(&mut model, &mut byzantine_sender, &peers, to, message);
                }
                Operation::ByzantineResponse { to, payload } => {
                    let message =
                        payload.tagged(RESPONSE, |id, result| FuzzResponse { id, result });
                    send_byzantine(&mut model, &mut byzantine_sender, &peers, to, message);
                }
                Operation::ByzantineBytes { to, bytes } => {
                    send_byzantine(&mut model, &mut byzantine_sender, &peers, to, bytes);
                }
                Operation::ByzantineAnswer { copies } => {
                    let requests = model.drain(&mut byzantine_inbox, &peers, &byzantine);
                    for (origin, request) in requests {
                        for _ in 0..=copies % 3 {
                            byzantine_sender.send(
                                Recipients::One(origin.clone()),
                                (RESPONSE, answer(&request)).encode(),
                                false,
                            );
                        }
                    }
                }
                Operation::Sleep { ms } => {
                    let ms = u64::from(ms) % (MAX_SLEEP_MS + 1);
                    context.sleep(Duration::from_millis(ms)).await;
                }
            }
            model.check(&log, &peers, &byzantine);
        }

        // Let every message in flight arrive and check what the engines observed, then confirm each
        // engine is still running.
        context.sleep(SETTLE).await;
        model.check(&log, &peers, &byzantine);
        for mailbox in &mut mailboxes {
            expect_running(mailbox.cancel(commitment(ID_SPACE)));
        }

        // Check every message the Byzantine peer has received since its last answer. The requests
        // it received since then go unanswered.
        model.drain(&mut byzantine_inbox, &peers, &byzantine);

        // Only undecodable bytes block, and only their sender.
        let blocked = oracle.blocked().await.unwrap();
        for (blocker, blockee) in &blocked {
            assert_eq!(blockee, &byzantine, "an honest peer must not be blocked");
            let index = peers
                .iter()
                .position(|peer| peer == blocker)
                .expect("a blocker must be an engine");
            assert!(
                model.expect_block[index],
                "an engine must block only after undecodable bytes"
            );
        }
        for (index, expected) in model.expect_block.iter().enumerate() {
            if *expected {
                assert!(
                    blocked.contains(&(peers[index].clone(), byzantine.clone())),
                    "undecodable bytes must block their sender"
                );
            }
        }

        // Every engine has settled, so one encoding of the metrics serves every check below.
        let metrics = context.encode();

        // Each engine is collecting exactly the commitments sent and not cancelled since.
        for (index, originator) in model.originators.iter().enumerate() {
            assert_eq!(
                metric(&metrics, "outstanding", index),
                originator.live.len(),
                "outstanding commitments must match the model"
            );
        }

        // Each engine's metrics agree with the model.
        for index in 0..honest {
            // The engine still waits on exactly the responders its handler holds.
            let held = log
                .held
                .lock()
                .iter()
                .filter(|(holder, ..)| *holder == index)
                .count();
            assert_eq!(
                metric(&metrics, "serve_processing", index),
                held,
                "pending requests must match the responders a handler holds"
            );

            // Every request the handler processed is either still held or counted as served.
            let success = count(&metrics, "serve", Status::Success, index);
            let failure = count(&metrics, "serve", Status::Failure, index);
            let dropped = count(&metrics, "serve", Status::Dropped, index);
            assert_eq!(
                success + failure + dropped + held,
                model.processed[index],
                "served and pending requests must add up to the requests processed"
            );

            // A declined request is counted as a failure, and a response is counted as dropped
            // exactly when its engine cannot send it.
            assert_eq!(
                failure, model.declined[index],
                "declined requests must be counted as failures"
            );
            if model.muted.as_ref() == Some(&peers[index]) {
                assert_eq!(
                    success, 0,
                    "an engine that cannot send responses must count none as sent"
                );
            } else {
                assert_eq!(
                    dropped, 0,
                    "an engine that can send responses must count none as dropped"
                );
            }

            // Every response the monitor collected is a success.
            assert_eq!(
                count(&metrics, "collect", Status::Success, index),
                model.collected[index],
                "collected responses must be counted as successes"
            );

            // A cancel can discard sends that wait behind the inbox, so the engine counts at most
            // the sends enqueued.
            let sent = count(&metrics, "send", Status::Success, index)
                + count(&metrics, "send", Status::Dropped, index);
            assert!(
                sent <= model.originators[index].sends,
                "an engine must not count more sends than were enqueued"
            );

            // Undecodable bytes are counted as invalid, and nothing else is.
            assert_eq!(
                metric(&metrics, "invalid_total", index) > 0,
                model.expect_block[index],
                "undecodable bytes, and only they, must be counted as invalid"
            );
        }

        // On reliable links, an originator collects every honest peer that answered one of its
        // requests immediately, unless the request's commitment was ever cancelled or the peer
        // cannot send responses.
        if input.reliable {
            for (index, originator) in model.originators.iter().enumerate() {
                for (peer, request) in &originator.sent {
                    let commitment = request.commitment();
                    if peer == &peers[index]
                        || peer == &byzantine
                        || Some(peer) == model.muted.as_ref()
                        || behavior(request) != Behavior::Respond
                        || originator.cancels.contains_key(&commitment)
                    {
                        continue;
                    }
                    assert!(
                        originator
                            .collections
                            .get(&commitment)
                            .is_some_and(|(_, responders)| responders.contains(peer)),
                        "a peer that answers immediately must be collected"
                    );
                }
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
