#![no_main]

//! Fuzz collector engines over a simulated network.
//!
//! Every honest peer runs an engine whose handler and monitor record what they observe. One more
//! peer, the Byzantine peer, runs no engine. It injects well-formed, malformed, unsolicited, and
//! duplicate traffic on both channels and answers the requests it receives.
//!
//! After every operation the harness checks what the monitors collected and what the handlers
//! processed against a model of what the originators asked for. Every mailbox call must be
//! accepted, so an engine that stops early fails the run. A final settle phase checks response
//! routing, blocking and the engines' metrics. On reliable links it also checks that every request
//! a handler answered immediately with its own commitment was collected unless that commitment was
//! ever cancelled.

use arbitrary::{Arbitrary, Unstructured};
use commonware_actor::Feedback;
use commonware_codec::{
    Buf, Decode, Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt,
    ReadRangeExt, Write,
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
    Receiver as _, Recipients, Sender as _,
    simulated::{Config as NetworkConfig, Link, Network},
};
use commonware_runtime::{
    BufMut, Clock, Metrics as _, Quota, Runner, Supervisor as _, deterministic,
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
    time::Duration,
};

/// Channel carrying requests.
const REQUESTS: u64 = 0;

/// Channel carrying responses.
const RESPONSES: u64 = 1;

/// Rate limit high enough that honest traffic is never limited.
const QUOTA: Quota = Quota::per_second(NZU32!(1_000_000));

/// Longest payload either codec accepts.
const MAX_DATA: usize = 32;

/// Longest arbitrary byte string the Byzantine peer sends. It stays far below the network's
/// maximum message size.
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

/// How a handler treats a request, chosen by the first byte of its data.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Behavior {
    /// Answer with the request's commitment.
    Respond,
    /// Drop the responder.
    Drop,
    /// Answer with the next id's commitment.
    Redirect,
    /// Keep the responder until a [Operation::Release].
    Hold,
}

/// Returns how every handler treats `request`.
fn behavior(request: &FuzzRequest) -> Behavior {
    match request.data.first().copied().unwrap_or(0) % 4 {
        0 => Behavior::Respond,
        1 => Behavior::Drop,
        2 => Behavior::Redirect,
        _ => Behavior::Hold,
    }
}

/// Returns the response to `request`. The response has the next id's commitment when
/// `redirect` is set.
fn answer(request: &FuzzRequest, redirect: bool) -> FuzzResponse {
    let id = if redirect {
        request.id.wrapping_add(1) % ID_SPACE
    } else {
        request.id
    };
    FuzzResponse {
        id,
        result: request.data.iter().rev().copied().collect(),
    }
}

/// The engine that served a request, the request's authenticated origin, and the request.
type Processed = (usize, PublicKey, FuzzRequest);

/// The engine that collected a response, its responder, the response, and the reported count.
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
        responder: oneshot::Sender<FuzzResponse>,
    ) {
        self.log
            .processed
            .lock()
            .push((self.index, origin, request.clone()));
        match behavior(&request) {
            Behavior::Respond => {
                responder.send_lossy(answer(&request, false));
            }
            Behavior::Redirect => {
                responder.send_lossy(answer(&request, true));
            }
            Behavior::Drop => drop(responder),
            Behavior::Hold => self.log.held.lock().push((self.index, request, responder)),
        }
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

/// Bytes the Byzantine peer sends.
#[derive(Debug, Arbitrary)]
enum Payload {
    /// A well-formed message with a colliding id.
    Valid { id: u8, data: Vec<u8> },
    /// Arbitrary bytes that may or may not decode.
    Raw(Vec<u8>),
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
    /// The Byzantine peer sends bytes on the requests channel.
    ByzantineRequest { to: u8, payload: Payload },
    /// The Byzantine peer sends bytes on the responses channel.
    ByzantineResponse { to: u8, payload: Payload },
    /// The Byzantine peer answers each decodable request it has received since its last answer,
    /// sending one to three copies.
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
            latency_ms,
            priority_requests,
            priority_responses,
            operations,
        })
    }
}

/// What the harness knows about one honest originator.
#[derive(Default)]
struct Sent {
    /// Every peer each commitment was ever addressed to.
    addressed: HashMap<Digest, HashSet<PublicKey>>,
    /// Every request payload sent under each commitment.
    payloads: HashMap<Digest, HashSet<FuzzRequest>>,
    /// Number of cancels enqueued for each commitment.
    cancels: HashMap<Digest, usize>,
    /// Collections started so far for each commitment, and the responders of the latest one.
    collections: HashMap<Digest, (usize, HashSet<PublicKey>)>,
    /// Each request sent and the honest peers it was addressed to, for the completeness check.
    requests: Vec<(FuzzRequest, Vec<usize>)>,
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
    /// Engines the Byzantine peer sent undecodable bytes to.
    expect_block: Vec<bool>,
    /// Every (collector, responder, commitment) observed.
    seen: HashSet<(usize, PublicKey, Digest)>,
    /// Number of responses each engine's monitor collected.
    collected: Vec<usize>,
    /// Number of requests each engine's handler processed.
    processed: Vec<usize>,
}

impl Model {
    /// Records that originator `from` enqueues `request` for the peers in `addressed`.
    fn record_send(
        &mut self,
        peers: &[PublicKey],
        from: usize,
        request: &FuzzRequest,
        addressed: Vec<PublicKey>,
    ) {
        let commitment = request.commitment();
        let originator = &mut self.originators[from];
        originator.sends += 1;
        if !addressed.is_empty() {
            originator.live.insert(commitment);
            let targets = peers
                .iter()
                .enumerate()
                .filter(|(index, peer)| *index != from && addressed.contains(peer))
                .map(|(index, _)| index)
                .collect();
            originator.requests.push((request.clone(), targets));
        }
        originator
            .addressed
            .entry(commitment)
            .or_default()
            .extend(addressed);
        originator
            .payloads
            .entry(commitment)
            .or_default()
            .insert(request.clone());
    }

    /// Checks every observation recorded since the previous call.
    fn check(&mut self, log: &Log, peers: &[PublicKey], byzantine: &PublicKey) {
        // Each collected response comes from a peer its commitment was sent to, once per
        // collection, with a count that grows by one per responder.
        for (index, handler, response, count) in log.collected.lock().drain(..) {
            self.collected[index] += 1;
            let originator = &mut self.originators[index];
            let commitment = response.commitment();
            let addressed = originator
                .addressed
                .get(&commitment)
                .expect("a collected commitment must have been sent");
            assert!(
                addressed.contains(&handler),
                "a response must be collected from a peer its commitment was sent to"
            );
            let cancels = originator.cancels.get(&commitment).copied().unwrap_or(0);
            let (started, responders) = originator.collections.entry(commitment).or_default();
            if count == 1 {
                *started += 1;
                assert!(
                    *started <= cancels + 1,
                    "a collection must restart only after a cancel"
                );
                responders.clear();
            }
            assert_eq!(
                responders.len() + 1,
                count,
                "count must grow by one per responder"
            );
            assert!(
                responders.insert(handler.clone()),
                "a responder must be collected once per collection"
            );
            self.seen.insert((index, handler, commitment));
        }

        // Each processed request is one its origin sent to this handler.
        for (index, origin, request) in log.processed.lock().drain(..) {
            self.processed[index] += 1;
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
            let commitment = request.commitment();
            let originator = &self.originators[from];
            assert!(
                originator
                    .payloads
                    .get(&commitment)
                    .is_some_and(|payloads| payloads.contains(&request)),
                "a handler must only see payloads its origin sent"
            );
            assert!(
                originator.addressed[&commitment].contains(&peers[index]),
                "a handler must only see requests addressed to it"
            );
        }
    }
}

/// Asserts that a mailbox accepted a call. Every engine runs until the harness drops its
/// mailbox, so a closed mailbox means the engine stopped early.
fn expect_running(feedback: Feedback) {
    assert!(
        feedback.accepted(),
        "an engine must keep running: {feedback:?}"
    );
}

/// Reads gauge `name` of the engine at `index`.
fn gauge(context: &deterministic::Context, name: &str, index: usize) -> usize {
    let prefix = format!("engine_{name}{{");
    let label = format!("index=\"{index}\"");
    context
        .encode()
        .lines()
        .find(|line| line.starts_with(&prefix) && line.contains(&label))
        .and_then(|line| line.rsplit(' ').next()?.parse().ok())
        .expect("every engine must export its gauges")
}

/// Reads how often the engine at `index` counted `status` in `family`. A status that was never
/// counted reads as zero.
fn count(context: &deterministic::Context, family: &str, status: Status, index: usize) -> usize {
    let prefix = format!("engine_{family}_total{{");
    let engine = format!("index=\"{index}\"");
    let status = format!("status=\"{status:?}\"");
    context
        .encode()
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

        // Start one engine per honest peer, and register the Byzantine peer's channels.
        let log = Log::default();
        let mut mailboxes: Vec<Mailbox<PublicKey, FuzzRequest>> = Vec::new();
        for (index, peer) in peers.iter().enumerate() {
            let control = oracle.control(peer.clone());
            let requests = control.register(REQUESTS, QUOTA).await.unwrap();
            let responses = control.register(RESPONSES, QUOTA).await.unwrap();
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
            engine.start(requests, responses);
            mailboxes.push(mailbox);
        }
        let control = oracle.control(byzantine.clone());
        let (mut byzantine_requests, mut byzantine_inbox) =
            control.register(REQUESTS, QUOTA).await.unwrap();
        let (mut byzantine_responses, mut byzantine_response_inbox) =
            control.register(RESPONSES, QUOTA).await.unwrap();

        // The model starts with nothing sent, processed, or collected.
        let mut model = Model {
            originators: (0..honest).map(|_| Sent::default()).collect(),
            byzantine_requests: vec![Vec::new(); honest],
            expect_block: vec![false; honest],
            seen: HashSet::new(),
            collected: vec![0; honest],
            processed: vec![0; honest],
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
                    model.record_send(&peers, from, &request, addressed);
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
                        model.record_send(&peers, from, &request, vec![peer.clone()]);
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
                        responder.send_lossy(answer(&request, false));
                    }
                }
                Operation::ByzantineRequest { to, payload } => {
                    let to = usize::from(to) % honest;
                    let bytes = match payload {
                        Payload::Valid { id, mut data } => {
                            data.truncate(MAX_DATA);
                            FuzzRequest {
                                id: u64::from(id) % ID_SPACE,
                                data,
                            }
                            .encode()
                            .to_vec()
                        }
                        Payload::Raw(mut bytes) => {
                            bytes.truncate(MAX_RAW);
                            bytes
                        }
                    };
                    match FuzzRequest::decode_cfg(bytes.clone(), &codec()) {
                        Ok(request) => model.byzantine_requests[to].push(request),
                        Err(_) => model.expect_block[to] = true,
                    }
                    byzantine_requests.send(Recipients::One(peers[to].clone()), bytes, false);
                }
                Operation::ByzantineResponse { to, payload } => {
                    let to = usize::from(to) % honest;
                    let bytes = match payload {
                        Payload::Valid { id, mut data } => {
                            data.truncate(MAX_DATA);
                            FuzzResponse {
                                id: u64::from(id) % ID_SPACE,
                                result: data,
                            }
                            .encode()
                            .to_vec()
                        }
                        Payload::Raw(mut bytes) => {
                            bytes.truncate(MAX_RAW);
                            bytes
                        }
                    };
                    if FuzzResponse::decode_cfg(bytes.clone(), &codec()).is_err() {
                        model.expect_block[to] = true;
                    }
                    byzantine_responses.send(Recipients::One(peers[to].clone()), bytes, false);
                }
                Operation::ByzantineAnswer { copies } => {
                    while let Some(Ok((origin, bytes))) = byzantine_inbox.recv().now_or_never() {
                        let Ok(request) = FuzzRequest::decode_cfg(bytes, &codec()) else {
                            continue;
                        };
                        for _ in 0..=copies % 3 {
                            byzantine_responses.send(
                                Recipients::One(origin.clone()),
                                answer(&request, false).encode(),
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

        // Let every message in flight arrive, then confirm each engine is still running.
        context.sleep(SETTLE).await;
        model.check(&log, &peers, &byzantine);
        for mailbox in &mut mailboxes {
            expect_running(mailbox.cancel(commitment(ID_SPACE)));
        }
        context.sleep(Duration::from_millis(10)).await;
        model.check(&log, &peers, &byzantine);

        // Engines answer only the requester, so the Byzantine peer receives at most one response
        // per decodable request it sent.
        let mut answered = vec![0usize; honest];
        while let Some(Ok((origin, _))) = byzantine_response_inbox.recv().now_or_never() {
            let index = peers
                .iter()
                .position(|peer| peer == &origin)
                .expect("a response must come from an engine");
            answered[index] += 1;
            assert!(
                answered[index] <= model.byzantine_requests[index].len(),
                "an engine must only answer requests the Byzantine peer sent"
            );
        }

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

        // Each engine is collecting exactly the commitments sent and not cancelled since.
        for (index, originator) in model.originators.iter().enumerate() {
            assert_eq!(
                gauge(&context, "outstanding", index),
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
                gauge(&context, "serve_processing", index),
                held,
                "pending requests must match the responders a handler holds"
            );

            // Every request the handler processed is either still held or counted as served.
            let served = count(&context, "serve", Status::Success, index)
                + count(&context, "serve", Status::Failure, index)
                + count(&context, "serve", Status::Dropped, index);
            assert_eq!(
                served + held,
                model.processed[index],
                "served and pending requests must add up to the requests processed"
            );

            // Every response the monitor collected is a success.
            assert_eq!(
                count(&context, "collect", Status::Success, index),
                model.collected[index],
                "collected responses must be counted as successes"
            );

            // A send that a cancel discarded is not counted.
            let sent = count(&context, "send", Status::Success, index)
                + count(&context, "send", Status::Dropped, index);
            assert!(
                sent <= model.originators[index].sends,
                "an engine must not count more sends than were enqueued"
            );

            // Undecodable bytes are counted as invalid, and nothing else is.
            let invalid = count(&context, "serve", Status::Invalid, index)
                + count(&context, "collect", Status::Invalid, index);
            assert_eq!(
                invalid > 0,
                model.expect_block[index],
                "undecodable bytes, and only they, must be counted as invalid"
            );
        }

        // On reliable links, every request a handler answered immediately with its own commitment
        // is collected unless that commitment was ever cancelled.
        if input.reliable {
            for (index, originator) in model.originators.iter().enumerate() {
                for (request, targets) in &originator.requests {
                    let commitment = request.commitment();
                    if behavior(request) != Behavior::Respond
                        || originator.cancels.contains_key(&commitment)
                    {
                        continue;
                    }
                    for target in targets {
                        assert!(
                            model
                                .seen
                                .contains(&(index, peers[*target].clone(), commitment)),
                            "an answered request must be collected"
                        );
                    }
                }
            }
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
