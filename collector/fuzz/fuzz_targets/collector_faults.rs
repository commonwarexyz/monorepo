#![no_main]

//! Fuzz collector engines over a mock transport that injects faults.
//!
//! Each peer runs an engine on one channel that carries requests and responses, each opened by a
//! tag byte (0 for a request, 1 for a response). The transport can reject what an engine sends,
//! with separate feedback for requests and for responses, deliver well-formed or malformed
//! messages from any peer, and fail an engine's receiver. An operation can also replace a peer's
//! engine with a new one under a different configuration.
//!
//! After every operation the harness checks each collected response against a model of the
//! commitments its originator sent and has not cancelled: the response comes from a recipient of
//! the commitment, at most once per collection, with a count equal to the responders collected.

use arbitrary::Arbitrary;
use commonware_actor::{Feedback, Unreliable};
use commonware_codec::{
    Buf, Encode, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, ReadRangeExt, Write,
};
use commonware_collector::{
    Handler, Monitor, Originator,
    p2p::{Config, Engine, Mailbox},
};
use commonware_cryptography::{
    Committable, Digestible, Hasher, Sha256, Signer,
    ed25519::{PrivateKey, PublicKey},
    sha256::Digest,
};
use commonware_p2p::{Blocker, CheckedSender, LimitedSender, Receiver, Recipients};
use commonware_runtime::{
    BufMut, Clock, Handle, IoBuf, IoBufMut, IoBufs, Runner, Supervisor as _, deterministic,
};
use commonware_utils::{
    FuzzRng, NZUsize,
    channel::{mpsc, oneshot},
    sync::Mutex,
};
use libfuzzer_sys::fuzz_target;
use rand::{Rng, RngExt as _};
use std::{
    collections::{HashMap, HashSet},
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, SystemTime},
};

const MAX_LEN: usize = 1_000_000;
const MAX_OPERATIONS: usize = 256;
const MAX_RAW_BYTES: usize = 32_768;
const DEFAULT_MAILBOX_SIZE: usize = 8;
const MIN_BUFFER_SIZE: u16 = 1;
const SETTLE_DURATION: Duration = Duration::from_millis(1);

/// Tag that opens a request on the channel.
const REQUEST: u8 = 0;

/// Tag that opens a response on the channel.
const RESPONSE: u8 = 1;

#[derive(Debug, Arbitrary)]
enum RecipientsType {
    All,
    One,
    Some,
}

#[derive(Clone, Copy, Debug, Arbitrary)]
enum FeedbackKind {
    Ok,
    Backoff,
    Closed,
}

impl From<FeedbackKind> for Feedback {
    fn from(kind: FeedbackKind) -> Self {
        match kind {
            FeedbackKind::Ok => Feedback::Ok,
            FeedbackKind::Backoff => Feedback::Backoff,
            FeedbackKind::Closed => Feedback::Closed,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Arbitrary)]
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

impl Read for FuzzRequest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &()) -> Result<Self, CodecError> {
        let id = u64::read(buf)?;
        let data = Vec::<u8>::read_range(buf, ..=MAX_LEN)?;
        Ok(Self { id, data })
    }
}

impl EncodeSize for FuzzRequest {
    fn encode_size(&self) -> usize {
        u64::SIZE + self.data.encode_size()
    }
}

impl Committable for FuzzRequest {
    type Commitment = Digest;

    fn commitment(&self) -> Self::Commitment {
        Sha256::hash(&[&self.id.encode()])
    }
}

impl Digestible for FuzzRequest {
    type Digest = Digest;

    fn digest(&self) -> Self::Digest {
        Sha256::hash(&[&self.encode()])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Arbitrary)]
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

impl Read for FuzzResponse {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &()) -> Result<Self, CodecError> {
        let id = u64::read(buf)?;
        let result = Vec::<u8>::read_range(buf, ..=MAX_LEN)?;
        Ok(Self { id, result })
    }
}

impl EncodeSize for FuzzResponse {
    fn encode_size(&self) -> usize {
        u64::SIZE + self.result.encode_size()
    }
}

impl Committable for FuzzResponse {
    type Commitment = Digest;

    fn commitment(&self) -> Self::Commitment {
        Sha256::hash(&[&self.id.encode()])
    }
}

impl Digestible for FuzzResponse {
    type Digest = Digest;

    fn digest(&self) -> Self::Digest {
        Sha256::hash(&[&self.encode()])
    }
}

#[derive(Clone)]
struct FuzzHandler {
    respond: bool,
    response_map: HashMap<u64, FuzzResponse>,
}

impl FuzzHandler {
    fn new(respond: bool, rng: &mut impl Rng) -> Self {
        let mut response_map = HashMap::new();
        for _ in 0..rng.random_range(0..10) {
            let id = rng.random();
            let result_len = rng.random_range(0..100);
            let mut result = vec![0u8; result_len];
            rng.fill(&mut result[..]);
            response_map.insert(id, FuzzResponse { id, result });
        }
        Self {
            respond,
            response_map,
        }
    }
}

impl Handler for FuzzHandler {
    type PublicKey = PublicKey;
    type Request = FuzzRequest;
    type Response = FuzzResponse;

    fn process(
        &mut self,
        _origin: Self::PublicKey,
        request: Self::Request,
    ) -> oneshot::Receiver<Self::Response> {
        let (response, receiver) = oneshot::channel();
        if self.respond {
            let resp = self
                .response_map
                .get(&request.id)
                .cloned()
                .unwrap_or_else(|| FuzzResponse {
                    id: request.id,
                    result: request.data.clone(),
                });
            let _ = response.send(resp);
        }
        receiver
    }
}

#[derive(Debug)]
struct CollectedEvent {
    handler: PublicKey,
    response: FuzzResponse,
    count: usize,
}

#[derive(Debug, Default)]
struct TrackedCommitment {
    recipients: HashSet<PublicKey>,
    responders: HashSet<PublicKey>,
}

#[derive(Debug, Default)]
struct EngineModel {
    tracked: HashMap<Digest, TrackedCommitment>,
    events: Vec<CollectedEvent>,
}

type SharedModel = Arc<Mutex<EngineModel>>;

#[derive(Clone)]
struct FuzzMonitor {
    model: SharedModel,
}

impl FuzzMonitor {
    fn new(model: SharedModel) -> Self {
        Self { model }
    }
}

impl Monitor for FuzzMonitor {
    type PublicKey = PublicKey;
    type Response = FuzzResponse;

    fn collected(&mut self, handler: Self::PublicKey, response: Self::Response, count: usize) {
        self.model.lock().events.push(CollectedEvent {
            handler,
            response,
            count,
        });
    }
}

fn record_request(model: &SharedModel, commitment: Digest, recipients: Vec<PublicKey>) {
    let mut model = model.lock();
    model
        .tracked
        .entry(commitment)
        .or_default()
        .recipients
        .extend(recipients);
}

fn record_cancel(model: &SharedModel, commitment: &Digest) {
    model.lock().tracked.remove(commitment);
}

fn validate_monitor_events(models: &[SharedModel]) {
    for model in models {
        let mut model = model.lock();
        let events = std::mem::take(&mut model.events);
        for event in events {
            let commitment = event.response.commitment();
            let tracked = model
                .tracked
                .get_mut(&commitment)
                .expect("monitor event for unknown or cancelled commitment");
            assert!(
                tracked.recipients.contains(&event.handler),
                "monitor event from non-recipient"
            );
            assert!(
                tracked.responders.insert(event.handler.clone()),
                "duplicate monitor event"
            );
            assert_eq!(
                event.count,
                tracked.responders.len(),
                "monitor count must match collected responses"
            );
        }
    }
}

#[derive(Clone)]
struct FuzzBlocker;

impl Blocker for FuzzBlocker {
    type PublicKey = PublicKey;

    fn block(&mut self, _peer: Self::PublicKey) -> Feedback {
        Feedback::Ok
    }

    fn blocked(&mut self) -> commonware_p2p::BlockedSubscription<Self::PublicKey> {
        let (_, receiver) = commonware_utils::channel::ring::channel(commonware_utils::NZUsize!(1));
        receiver
    }
}

#[derive(Debug)]
enum MockInbound {
    Message(Box<PublicKey>, IoBuf),
    Error,
}

type MockRoutes = Arc<Mutex<HashMap<PublicKey, mpsc::UnboundedSender<MockInbound>>>>;

/// Feedback the transport returns for what an engine sends, by message kind.
#[derive(Debug, Clone, Copy)]
struct SendFeedback {
    request: FeedbackKind,
    response: FeedbackKind,
}

impl SendFeedback {
    /// Returns the feedback for a message opened by `tag`. A message with any other tag is
    /// treated as a request.
    fn for_tag(self, tag: Option<u8>) -> Feedback {
        match tag {
            Some(RESPONSE) => self.response.into(),
            _ => self.request.into(),
        }
    }
}

#[derive(Debug, Clone)]
struct MockSender {
    origin: PublicKey,
    peers: Arc<Vec<PublicKey>>,
    routes: MockRoutes,
    feedback: SendFeedback,
}

impl MockSender {
    fn new(
        origin: PublicKey,
        peers: Arc<Vec<PublicKey>>,
        routes: MockRoutes,
        feedback: SendFeedback,
    ) -> Self {
        Self {
            origin,
            peers,
            routes,
            feedback,
        }
    }
}

impl LimitedSender for MockSender {
    type PublicKey = PublicKey;
    type Checked<'a>
        = MockCheckedSender
    where
        Self: 'a;

    fn check(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
    ) -> Result<Self::Checked<'_>, SystemTime> {
        Ok(MockCheckedSender {
            origin: self.origin.clone(),
            peers: self.peers.clone(),
            routes: self.routes.clone(),
            recipients,
            feedback: self.feedback,
        })
    }
}

struct MockCheckedSender {
    origin: PublicKey,
    peers: Arc<Vec<PublicKey>>,
    routes: MockRoutes,
    recipients: Recipients<PublicKey>,
    feedback: SendFeedback,
}

impl CheckedSender for MockCheckedSender {
    type PublicKey = PublicKey;

    fn recipients(&self) -> Vec<Self::PublicKey> {
        match &self.recipients {
            Recipients::All => self.peers.iter().cloned().collect(),
            Recipients::One(peer) => vec![peer.clone()],
            Recipients::Some(peers) => peers.clone(),
        }
        .into_iter()
        .filter(|recipient| *recipient != self.origin)
        .collect()
    }

    fn send(self, message: impl Into<IoBufs> + Send, _priority: bool) -> Unreliable<Feedback> {
        let message = message.into().coalesce();
        let feedback = self.feedback.for_tag(message.as_ref().first().copied());
        if !feedback.accepted() {
            return Unreliable::new(feedback);
        }
        let recipients = self.recipients();
        let deliveries = {
            let routes = self.routes.lock();
            recipients
                .into_iter()
                .filter_map(|recipient| routes.get(&recipient).cloned())
                .collect::<Vec<_>>()
        };

        for tx in deliveries {
            let _ = tx.send(MockInbound::Message(
                Box::new(self.origin.clone()),
                message.clone(),
            ));
        }
        Unreliable::new(feedback)
    }
}

#[derive(Debug)]
struct MockReceiver {
    rx: mpsc::UnboundedReceiver<MockInbound>,
}

#[derive(Debug, thiserror::Error)]
#[error("mock receive error")]
struct MockRecvError;

impl Receiver for MockReceiver {
    type PublicKey = PublicKey;
    type Error = MockRecvError;

    async fn recv(&mut self) -> Result<(Self::PublicKey, IoBuf), Self::Error> {
        match self.rx.recv().await.ok_or(MockRecvError)? {
            MockInbound::Message(peer, message) => Ok((*peer, message)),
            MockInbound::Error => Err(MockRecvError),
        }
    }

    fn capacity(&self) -> NonZeroUsize {
        NZUsize!(1024)
    }
}

/// Returns `message` opened by `tag`.
fn encode_message<T: Write + EncodeSize>(tag: u8, message: &T) -> IoBuf {
    let mut buf = IoBufMut::with_capacity(1 + message.encode_size());
    tag.write(&mut buf);
    message.write(&mut buf);
    buf.freeze()
}

/// Returns `tag` followed by 1 to 7 bytes of `seed`, too short for any body to decode.
fn malformed_message(tag: u8, seed: u64) -> IoBuf {
    let len = ((seed as usize) % 7) + 1;
    let mut bytes = vec![tag];
    bytes.extend_from_slice(&seed.to_be_bytes()[..len]);
    IoBuf::from(bytes)
}

fn send_inbound(routes: &MockRoutes, recipient: &PublicKey, message: MockInbound) {
    let tx = routes.lock().get(recipient).cloned();
    if let Some(tx) = tx {
        let _ = tx.send(message);
    }
}

// Mirrors MockCheckedSender::recipients without consuming the checked sender.
fn model_recipients(
    recipients: &Recipients<PublicKey>,
    origin: &PublicKey,
    peers: &[PublicKey],
) -> Vec<PublicKey> {
    match recipients {
        Recipients::All => peers.to_vec(),
        Recipients::One(peer) => vec![peer.clone()],
        Recipients::Some(peers) => peers.clone(),
    }
    .into_iter()
    .filter(|recipient| recipient != origin)
    .collect()
}

#[derive(Arbitrary, Debug)]
enum CollectorOperation {
    SendRequest {
        peer_idx: u8,
        request: FuzzRequest,
        recipients_type: RecipientsType,
    },
    CancelRequest {
        peer_idx: u8,
        request_id: u64,
    },
    InjectRequest {
        engine_idx: u8,
        origin_idx: u8,
        request: FuzzRequest,
        valid: bool,
    },
    InjectResponse {
        engine_idx: u8,
        origin_idx: u8,
        response: FuzzResponse,
        valid: bool,
    },
    CloseReceiver {
        engine_idx: u8,
    },
    CreateEngine {
        peer_idx: u8,
        mailbox_size: u16,
        priority_request: bool,
        priority_response: bool,
        handler_responds: bool,
        request_feedback: FeedbackKind,
        response_feedback: FeedbackKind,
    },
}

#[derive(Debug)]
struct FuzzInput {
    raw_bytes: Vec<u8>,
    operations: Vec<CollectorOperation>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let seed: u64 = u.arbitrary()?;
        let mut raw_bytes = seed.to_be_bytes().to_vec();
        let max_ops = MAX_OPERATIONS.min(u.len().max(1));
        let num_ops = u.int_in_range(1..=max_ops)?;
        let operations = (0..num_ops)
            .map(|_| CollectorOperation::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;
        let remaining = u.len().min(MAX_RAW_BYTES);
        raw_bytes.extend_from_slice(u.bytes(remaining)?);
        Ok(Self {
            raw_bytes,
            operations,
        })
    }
}

struct FuzzState {
    mailboxes: HashMap<usize, Mailbox<PublicKey, FuzzRequest>>,
    handles: HashMap<usize, Handle<()>>,
    models: HashMap<usize, SharedModel>,
    all_models: Vec<SharedModel>,
    restarts: usize,
}

impl FuzzState {
    fn new() -> Self {
        Self {
            mailboxes: HashMap::new(),
            handles: HashMap::new(),
            models: HashMap::new(),
            all_models: Vec::new(),
            restarts: 0,
        }
    }
}

struct EngineParams {
    peer_idx: usize,
    mailbox_size: usize,
    priority_request: bool,
    priority_response: bool,
    handler_responds: bool,
    request_feedback: FeedbackKind,
    response_feedback: FeedbackKind,
}

fn start_engine(
    context: &mut deterministic::Context,
    state: &mut FuzzState,
    public_keys: Arc<Vec<PublicKey>>,
    routes: MockRoutes,
    params: EngineParams,
) {
    let model = Arc::new(Mutex::new(EngineModel::default()));
    let cfg = Config {
        blocker: FuzzBlocker,
        monitor: FuzzMonitor::new(model.clone()),
        handler: FuzzHandler::new(params.handler_responds, context),
        mailbox_size: NonZeroUsize::new(params.mailbox_size.max(MIN_BUFFER_SIZE as usize)).unwrap(),
        priority_requests: params.priority_request,
        request_codec_config: (),
        priority_responses: params.priority_response,
        response_codec_config: (),
    };
    let engine_context = context
        .child("engine")
        .with_attribute("peer", params.peer_idx)
        .with_attribute("instance", state.restarts);
    state.restarts += 1;

    let (tx, rx) = mpsc::unbounded_channel();
    routes
        .lock()
        .insert(public_keys[params.peer_idx].clone(), tx);

    let (engine, mailbox) = Engine::new(engine_context, cfg);
    let origin = public_keys[params.peer_idx].clone();
    let feedback = SendFeedback {
        request: params.request_feedback,
        response: params.response_feedback,
    };
    let handle = engine.start((
        MockSender::new(origin, public_keys, routes, feedback),
        MockReceiver { rx },
    ));

    state.mailboxes.insert(params.peer_idx, mailbox);
    state.handles.insert(params.peer_idx, handle);
    state.models.insert(params.peer_idx, model.clone());
    state.all_models.push(model);
}

fn fuzz(input: FuzzInput) {
    let cfg = deterministic::Config::new().with_rng(FuzzRng::new(input.raw_bytes));
    let executor = deterministic::Runner::new(cfg);

    executor.start(|mut context| async move {
        let mut private_keys = Vec::new();
        for _ in 0..3 {
            private_keys.push(PrivateKey::from_seed(context.random()));
        }
        let public_keys = Arc::new(
            private_keys
                .iter()
                .map(PrivateKey::public_key)
                .collect::<Vec<_>>(),
        );

        let routes: MockRoutes = Arc::new(Mutex::new(HashMap::new()));
        let mut state = FuzzState::new();

        for peer_idx in 0..public_keys.len() {
            start_engine(
                &mut context,
                &mut state,
                public_keys.clone(),
                routes.clone(),
                EngineParams {
                    peer_idx,
                    mailbox_size: DEFAULT_MAILBOX_SIZE,
                    priority_request: false,
                    priority_response: false,
                    handler_responds: true,
                    request_feedback: FeedbackKind::Ok,
                    response_feedback: FeedbackKind::Ok,
                },
            );
        }

        for op in input.operations {
            let mut processed_cancel = None;
            match op {
                CollectorOperation::SendRequest {
                    peer_idx,
                    request,
                    recipients_type,
                } => {
                    let idx = peer_idx as usize % public_keys.len();
                    if let Some(mailbox) = state.mailboxes.get_mut(&idx) {
                        let commitment = request.commitment();
                        let recipients = match recipients_type {
                            RecipientsType::All => Recipients::All,
                            RecipientsType::One => {
                                let peer =
                                    public_keys[context.random_range(0..public_keys.len())].clone();
                                Recipients::One(peer)
                            }
                            RecipientsType::Some => {
                                let count = context.random_range(0..=public_keys.len());
                                let peers = (0..count)
                                    .map(|_| {
                                        public_keys[context.random_range(0..public_keys.len())]
                                            .clone()
                                    })
                                    .collect();
                                Recipients::Some(peers)
                            }
                        };
                        let recorded =
                            model_recipients(&recipients, &public_keys[idx], &public_keys);
                        if mailbox.send(recipients, request).accepted()
                            && let Some(model) = state.models.get(&idx)
                        {
                            record_request(model, commitment, recorded);
                        }
                    }
                }
                CollectorOperation::CancelRequest {
                    peer_idx,
                    request_id,
                } => {
                    let idx = peer_idx as usize % public_keys.len();
                    let commitment = FuzzRequest {
                        id: request_id,
                        data: Vec::new(),
                    }
                    .commitment();
                    if let Some(mailbox) = state.mailboxes.get(&idx) {
                        let mut mailbox = mailbox.clone();
                        if mailbox.cancel(commitment).accepted() {
                            processed_cancel = Some((idx, commitment));
                        }
                    }
                }
                CollectorOperation::InjectRequest {
                    engine_idx,
                    origin_idx,
                    request,
                    valid,
                } => {
                    let idx = engine_idx as usize % public_keys.len();
                    let origin = public_keys[origin_idx as usize % public_keys.len()].clone();
                    let message = if valid {
                        encode_message(REQUEST, &request)
                    } else {
                        malformed_message(REQUEST, request.id)
                    };
                    send_inbound(
                        &routes,
                        &public_keys[idx],
                        MockInbound::Message(Box::new(origin), message),
                    );
                }
                CollectorOperation::InjectResponse {
                    engine_idx,
                    origin_idx,
                    response,
                    valid,
                } => {
                    let idx = engine_idx as usize % public_keys.len();
                    let origin = public_keys[origin_idx as usize % public_keys.len()].clone();
                    let message = if valid {
                        encode_message(RESPONSE, &response)
                    } else {
                        malformed_message(RESPONSE, response.id)
                    };
                    send_inbound(
                        &routes,
                        &public_keys[idx],
                        MockInbound::Message(Box::new(origin), message),
                    );
                }
                CollectorOperation::CloseReceiver { engine_idx } => {
                    let idx = engine_idx as usize % public_keys.len();
                    send_inbound(&routes, &public_keys[idx], MockInbound::Error);
                }
                CollectorOperation::CreateEngine {
                    peer_idx,
                    mailbox_size,
                    priority_request,
                    priority_response,
                    handler_responds,
                    request_feedback,
                    response_feedback,
                } => {
                    let idx = peer_idx as usize % public_keys.len();
                    if let Some(handle) = state.handles.remove(&idx) {
                        handle.abort();
                        context.sleep(SETTLE_DURATION).await;
                        validate_monitor_events(&state.all_models);
                    }

                    // A replacement engine starts with an empty model. Responses for
                    // requests tracked only by the old engine should therefore be ignored.
                    start_engine(
                        &mut context,
                        &mut state,
                        public_keys.clone(),
                        routes.clone(),
                        EngineParams {
                            peer_idx: idx,
                            mailbox_size: mailbox_size.max(MIN_BUFFER_SIZE) as usize,
                            priority_request,
                            priority_response,
                            handler_responds,
                            request_feedback,
                            response_feedback,
                        },
                    );
                }
            }

            context.sleep(SETTLE_DURATION).await;

            // A response that was already in flight may be collected before a
            // cancel command from the same operation is processed. Validate those
            // events first, then apply the model cancel so only future events are
            // rejected.
            validate_monitor_events(&state.all_models);
            if let Some((idx, commitment)) = processed_cancel
                && let Some(model) = state.models.get(&idx)
            {
                record_cancel(model, &commitment);
            }
        }

        context.sleep(SETTLE_DURATION).await;
        validate_monitor_events(&state.all_models);

        for peer in public_keys.iter() {
            send_inbound(&routes, peer, MockInbound::Error);
        }
        context.sleep(SETTLE_DURATION).await;
        validate_monitor_events(&state.all_models);

        for handle in state.handles.into_values() {
            handle.abort();
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
