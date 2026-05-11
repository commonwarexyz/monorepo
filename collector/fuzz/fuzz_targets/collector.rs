#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{
    Encode, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, ReadRangeExt, Write,
};
use commonware_collector::{
    p2p::{Config, Engine, Mailbox},
    Handler, Monitor, Originator,
};
use commonware_cryptography::{
    ed25519::{PrivateKey, PublicKey},
    sha256::Digest,
    Committable, Digestible, Hasher, Sha256, Signer,
};
use commonware_p2p::{Blocker, CheckedSender, LimitedSender, Receiver, Recipients};
use commonware_runtime::{
    deterministic, Buf, BufMut, Clock, Handle, IoBuf, IoBufMut, IoBufs, Runner, Supervisor as _,
};
use commonware_utils::{
    channel::{mpsc, oneshot},
    sync::Mutex,
    FuzzRng,
};
use libfuzzer_sys::fuzz_target;
use rand::Rng;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, SystemTime},
};

const MAX_LEN: usize = 1_000_000;
const MAX_OPERATIONS: usize = 256;
const MAX_RAW_BYTES: usize = 32_768;
const DEFAULT_MAILBOX_SIZE: usize = 8;
const MIN_BUFFER_SIZE: u16 = 1;
const SETTLE_DURATION: Duration = Duration::from_millis(1);

#[derive(Debug, Arbitrary)]
enum RecipientsType {
    All,
    One,
    Some,
}

#[derive(Debug, Arbitrary)]
enum ChannelKind {
    Requests,
    Responses,
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
        Sha256::hash(&self.id.encode())
    }
}

impl Digestible for FuzzRequest {
    type Digest = Digest;

    fn digest(&self) -> Self::Digest {
        Sha256::hash(&self.encode())
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
        Sha256::hash(&self.id.encode())
    }
}

impl Digestible for FuzzResponse {
    type Digest = Digest;

    fn digest(&self) -> Self::Digest {
        Sha256::hash(&self.encode())
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
        for _ in 0..rng.gen_range(0..10) {
            let id = rng.gen();
            let result_len = rng.gen_range(0..100);
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

    async fn process(
        &mut self,
        _origin: Self::PublicKey,
        request: Self::Request,
        response: oneshot::Sender<Self::Response>,
    ) {
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

    async fn collected(
        &mut self,
        handler: Self::PublicKey,
        response: Self::Response,
        count: usize,
    ) {
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

    async fn block(&mut self, _peer: Self::PublicKey) {}
}

#[derive(Debug)]
enum MockInbound {
    Message(Box<PublicKey>, IoBuf),
    Error,
}

type MockRoutes = Arc<Mutex<HashMap<PublicKey, mpsc::UnboundedSender<MockInbound>>>>;

#[derive(Debug, Clone)]
struct MockSender {
    origin: PublicKey,
    peers: Arc<Vec<PublicKey>>,
    routes: MockRoutes,
    fail: bool,
}

impl MockSender {
    fn new(origin: PublicKey, peers: Arc<Vec<PublicKey>>, routes: MockRoutes, fail: bool) -> Self {
        Self {
            origin,
            peers,
            routes,
            fail,
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("mock send error")]
struct MockSendError;

impl LimitedSender for MockSender {
    type PublicKey = PublicKey;
    type Checked<'a>
        = MockCheckedSender
    where
        Self: 'a;

    async fn check(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
    ) -> Result<Self::Checked<'_>, SystemTime> {
        Ok(MockCheckedSender {
            origin: self.origin.clone(),
            peers: self.peers.clone(),
            routes: self.routes.clone(),
            recipients,
            fail: self.fail,
        })
    }
}

struct MockCheckedSender {
    origin: PublicKey,
    peers: Arc<Vec<PublicKey>>,
    routes: MockRoutes,
    recipients: Recipients<PublicKey>,
    fail: bool,
}

impl CheckedSender for MockCheckedSender {
    type PublicKey = PublicKey;
    type Error = MockSendError;

    async fn send(
        self,
        message: impl Into<IoBufs> + Send,
        _priority: bool,
    ) -> Result<Vec<Self::PublicKey>, Self::Error> {
        if self.fail {
            return Err(MockSendError);
        }

        let message = message.into().coalesce();
        let recipients = match self.recipients {
            Recipients::All => self.peers.iter().cloned().collect(),
            Recipients::One(peer) => vec![peer],
            Recipients::Some(peers) => peers,
        };
        let deliveries = {
            let routes = self.routes.lock();
            recipients
                .into_iter()
                .filter(|recipient| *recipient != self.origin)
                .filter_map(|recipient| routes.get(&recipient).cloned().map(|tx| (recipient, tx)))
                .collect::<Vec<_>>()
        };

        let mut delivered = Vec::new();
        for (recipient, tx) in deliveries {
            if tx
                .send(MockInbound::Message(
                    Box::new(self.origin.clone()),
                    message.clone(),
                ))
                .is_ok()
            {
                delivered.push(recipient);
            }
        }
        Ok(delivered)
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
}

fn encode_message<T: Write + EncodeSize>(message: &T) -> IoBuf {
    let mut buf = IoBufMut::with_capacity(message.encode_size());
    message.write(&mut buf);
    buf.freeze()
}

fn malformed_message(seed: u64) -> IoBuf {
    let len = ((seed as usize) % 7) + 1;
    IoBuf::from(seed.to_be_bytes()[..len].to_vec())
}

fn send_inbound(routes: &MockRoutes, recipient: &PublicKey, message: MockInbound) {
    let tx = routes.lock().get(recipient).cloned();
    if let Some(tx) = tx {
        let _ = tx.send(message);
    }
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
        channel: ChannelKind,
    },
    CreateEngine {
        peer_idx: u8,
        mailbox_size: u16,
        priority_request: bool,
        priority_response: bool,
        handler_responds: bool,
        fail_request: bool,
        fail_response: bool,
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
    fail_request: bool,
    fail_response: bool,
}

fn start_engine(
    context: &mut deterministic::Context,
    state: &mut FuzzState,
    public_keys: Arc<Vec<PublicKey>>,
    request_routes: MockRoutes,
    response_routes: MockRoutes,
    params: EngineParams,
) {
    let model = Arc::new(Mutex::new(EngineModel::default()));
    let cfg = Config {
        blocker: FuzzBlocker,
        monitor: FuzzMonitor::new(model.clone()),
        handler: FuzzHandler::new(params.handler_responds, context),
        mailbox_size: params.mailbox_size.max(MIN_BUFFER_SIZE as usize),
        priority_request: params.priority_request,
        request_codec: (),
        priority_response: params.priority_response,
        response_codec: (),
    };
    let engine_context = context
        .child("engine")
        .with_attribute("peer", params.peer_idx)
        .with_attribute("instance", state.restarts);
    state.restarts += 1;

    let (request_tx, request_rx) = mpsc::unbounded_channel();
    let (response_tx, response_rx) = mpsc::unbounded_channel();
    request_routes
        .lock()
        .insert(public_keys[params.peer_idx].clone(), request_tx);
    response_routes
        .lock()
        .insert(public_keys[params.peer_idx].clone(), response_tx);

    let (engine, mailbox) = Engine::new(engine_context, cfg);
    let origin = public_keys[params.peer_idx].clone();
    let handle = engine.start(
        (
            MockSender::new(
                origin.clone(),
                public_keys.clone(),
                request_routes,
                params.fail_request,
            ),
            MockReceiver { rx: request_rx },
        ),
        (
            MockSender::new(origin, public_keys, response_routes, params.fail_response),
            MockReceiver { rx: response_rx },
        ),
    );

    state.mailboxes.insert(params.peer_idx, mailbox);
    state.handles.insert(params.peer_idx, handle);
    state.models.insert(params.peer_idx, model.clone());
    state.all_models.push(model);
}

fn fuzz(input: FuzzInput) {
    let cfg = deterministic::Config::new().with_rng(Box::new(FuzzRng::new(input.raw_bytes)));
    let executor = deterministic::Runner::new(cfg);

    executor.start(|mut context| async move {
        let mut private_keys = Vec::new();
        for _ in 0..3 {
            private_keys.push(PrivateKey::from_seed(context.gen()));
        }
        let public_keys = Arc::new(
            private_keys
                .iter()
                .map(PrivateKey::public_key)
                .collect::<Vec<_>>(),
        );

        let request_routes: MockRoutes = Arc::new(Mutex::new(HashMap::new()));
        let response_routes: MockRoutes = Arc::new(Mutex::new(HashMap::new()));
        let mut state = FuzzState::new();

        for peer_idx in 0..public_keys.len() {
            start_engine(
                &mut context,
                &mut state,
                public_keys.clone(),
                request_routes.clone(),
                response_routes.clone(),
                EngineParams {
                    peer_idx,
                    mailbox_size: DEFAULT_MAILBOX_SIZE,
                    priority_request: false,
                    priority_response: false,
                    handler_responds: true,
                    fail_request: false,
                    fail_response: false,
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
                                    public_keys[context.gen_range(0..public_keys.len())].clone();
                                Recipients::One(peer)
                            }
                            RecipientsType::Some => {
                                let count = context.gen_range(0..=public_keys.len());
                                let peers = (0..count)
                                    .map(|_| {
                                        public_keys[context.gen_range(0..public_keys.len())].clone()
                                    })
                                    .collect();
                                Recipients::Some(peers)
                            }
                        };
                        if let Ok(recipients) = mailbox.send(recipients, request).await {
                            if let Some(model) = state.models.get(&idx) {
                                record_request(model, commitment, recipients);
                            }
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
                        mailbox.cancel(commitment).await;
                        processed_cancel = Some((idx, commitment));
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
                        encode_message(&request)
                    } else {
                        malformed_message(request.id)
                    };
                    send_inbound(
                        &request_routes,
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
                        encode_message(&response)
                    } else {
                        malformed_message(response.id)
                    };
                    send_inbound(
                        &response_routes,
                        &public_keys[idx],
                        MockInbound::Message(Box::new(origin), message),
                    );
                }
                CollectorOperation::CloseReceiver {
                    engine_idx,
                    channel,
                } => {
                    let idx = engine_idx as usize % public_keys.len();
                    match channel {
                        ChannelKind::Requests => {
                            send_inbound(&request_routes, &public_keys[idx], MockInbound::Error);
                        }
                        ChannelKind::Responses => {
                            send_inbound(&response_routes, &public_keys[idx], MockInbound::Error);
                        }
                    }
                }
                CollectorOperation::CreateEngine {
                    peer_idx,
                    mailbox_size,
                    priority_request,
                    priority_response,
                    handler_responds,
                    fail_request,
                    fail_response,
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
                        request_routes.clone(),
                        response_routes.clone(),
                        EngineParams {
                            peer_idx: idx,
                            mailbox_size: mailbox_size.max(MIN_BUFFER_SIZE) as usize,
                            priority_request,
                            priority_response,
                            handler_responds,
                            fail_request,
                            fail_response,
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
            if let Some((idx, commitment)) = processed_cancel {
                if let Some(model) = state.models.get(&idx) {
                    record_cancel(model, &commitment);
                }
            }
        }

        context.sleep(SETTLE_DURATION).await;
        validate_monitor_events(&state.all_models);

        for peer in public_keys.iter() {
            send_inbound(&request_routes, peer, MockInbound::Error);
            send_inbound(&response_routes, peer, MockInbound::Error);
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
