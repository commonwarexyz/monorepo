#![no_main]

use arbitrary::Arbitrary;
use bytes::{Buf, BufMut};
use commonware_codec::{
    Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, ReadRangeExt,
    Write,
};
use commonware_collector::{
    p2p::{Config, Engine, Mailbox},
    Handler, Monitor, Originator,
};
use commonware_cryptography::{
    ed25519::{PrivateKey, PublicKey},
    sha256::Digest,
    Committable, Digestible, Hasher, PrivateKeyExt, Sha256, Signer,
};
use commonware_p2p::{Blocker, Receiver, Recipients, Sender};
use commonware_runtime::{deterministic, Clock, Runner};
use futures::{
    channel::{mpsc, oneshot},
    StreamExt,
};
use libfuzzer_sys::fuzz_target;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{collections::HashMap, time::Duration};

const MAX_LEN: usize = 1_000_000;
const MAX_OPERATIONS: usize = 256;

#[derive(Debug, Arbitrary)]
enum RecipientsType {
    All,
    One,
    Some,
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
    type Cfg = RangeCfg<usize>;
    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let id = u64::read(buf)?;
        let data = Vec::read_range(buf, *cfg)?;
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
    type Cfg = RangeCfg<usize>;
    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let id = u64::read(buf)?;
        let result = Vec::read_range(buf, *cfg)?;
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
    fn new(respond: bool, mut rng: StdRng) -> Self {
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

#[derive(Clone)]
struct FuzzMonitor {
    collected_count: usize,
}

impl FuzzMonitor {
    fn new() -> Self {
        Self { collected_count: 0 }
    }
}

impl Monitor for FuzzMonitor {
    type PublicKey = PublicKey;
    type Response = FuzzResponse;

    async fn collected(
        &mut self,
        _handler: Self::PublicKey,
        _response: Self::Response,
        _count: usize,
    ) {
        self.collected_count += 1;
    }
}

#[derive(Clone)]
struct FuzzBlocker;

impl Blocker for FuzzBlocker {
    type PublicKey = PublicKey;

    async fn block(&mut self, _peer: Self::PublicKey) {}
}

#[derive(Debug, Clone)]
struct MockSender;

#[derive(Debug, thiserror::Error)]
#[error("mock send error")]
struct MockSendError;

impl Sender for MockSender {
    type Error = MockSendError;
    type PublicKey = PublicKey;

    async fn send(
        &mut self,
        _recipients: Recipients<Self::PublicKey>,
        _message: bytes::Bytes,
        _priority: bool,
    ) -> Result<Vec<Self::PublicKey>, Self::Error> {
        Ok(vec![])
    }
}

#[derive(Debug)]
struct MockReceiver {
    rx: mpsc::UnboundedReceiver<(PublicKey, Result<FuzzRequest, CodecError>)>,
}

#[derive(Debug, thiserror::Error)]
#[error("mock receive error")]
struct MockRecvError;

impl Receiver for MockReceiver {
    type Error = MockRecvError;
    type PublicKey = PublicKey;

    async fn recv(&mut self) -> Result<(Self::PublicKey, bytes::Bytes), Self::Error> {
        let (pk, msg) = self.rx.next().await.ok_or(MockRecvError)?;
        match msg {
            Ok(req) => {
                let mut buf = bytes::BytesMut::new();
                req.write(&mut buf);
                Ok((pk, buf.freeze()))
            }
            Err(_) => Err(MockRecvError),
        }
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
        request_id: u64,
    },
    ProcessHandler {
        peer_idx: u8,
        origin_idx: u8,
        request: FuzzRequest,
        should_respond: bool,
    },
    MonitorCollected {
        peer_idx: u8,
        response: FuzzResponse,
        count: usize,
    },
    CreateEngine {
        peer_idx: u8,
        mailbox_size: u16,
        priority_request: bool,
        priority_response: bool,
    },
}

#[derive(Debug)]
struct FuzzInput {
    seed: u64,
    operations: Vec<CollectorOperation>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let seed = u.arbitrary()?;
        let num_ops = u.int_in_range(1..=MAX_OPERATIONS)?;
        let operations = (0..num_ops)
            .map(|_| CollectorOperation::arbitrary(u))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(FuzzInput { seed, operations })
    }
}

fn fuzz(input: FuzzInput) {
    let mut rng = StdRng::seed_from_u64(input.seed);

    let executor = deterministic::Runner::seeded(input.seed);
    executor.start(|context| async move {
        let mut peers: Vec<PrivateKey> = Vec::new();
        let mut mailboxes: HashMap<usize, Mailbox<PublicKey, FuzzRequest>> = HashMap::new();
        let mut handlers: HashMap<usize, FuzzHandler> = HashMap::new();
        let mut monitors: HashMap<usize, FuzzMonitor> = HashMap::new();

        for i in 2..5 {
            let seed = rng.gen();
            peers.push(PrivateKey::from_seed(seed));
            handlers.insert(i, FuzzHandler::new(rng.gen(), StdRng::seed_from_u64(seed)));
            monitors.insert(i, FuzzMonitor::new());
        }
        assert!(!peers.is_empty(), "no peers");

        for op in input.operations {
            match op {
                CollectorOperation::SendRequest {
                    peer_idx,
                    request,
                    recipients_type,
                } => {
                    let idx = (peer_idx as usize) % peers.len();
                    if let Some(mailbox) = mailboxes.get_mut(&idx) {
                        let recipients = match recipients_type {
                            RecipientsType::All => Recipients::All,
                            RecipientsType::One => {
                                let target_idx = rng.gen_range(0..peers.len());
                                Recipients::One(peers[target_idx].public_key())
                            }
                            RecipientsType::Some => {
                                let mut selected = vec![];
                                for (i, peer) in peers.iter().enumerate() {
                                    if i != idx && rng.gen_bool(0.5) {
                                        selected.push(peer.public_key());
                                    }
                                }
                                Recipients::Some(selected)
                            }
                        };
                        let _ = mailbox.send(recipients, request).await;
                    }
                }

                CollectorOperation::CancelRequest { request_id } => {
                    let request = FuzzRequest {
                        id: request_id,
                        data: vec![],
                    };
                    let commitment = request.commitment();

                    for mailbox in mailboxes.values_mut() {
                        mailbox.cancel(commitment).await;
                    }
                }

                CollectorOperation::ProcessHandler {
                    peer_idx,
                    origin_idx,
                    request,
                    should_respond,
                } => {
                    let handler_idx = (peer_idx as usize) % peers.len();
                    let origin_idx = (origin_idx as usize) % peers.len();

                    if let Some(handler) = handlers.get_mut(&handler_idx) {
                        let (tx, rx) = oneshot::channel();
                        handler
                            .process(peers[origin_idx].public_key(), request.clone(), tx)
                            .await;

                        if should_respond {
                            if let Ok(response) = rx.await {
                                assert_eq!(response.id, request.id);
                            }
                        }
                    }
                }

                CollectorOperation::MonitorCollected {
                    peer_idx,
                    response,
                    count,
                } => {
                    let monitor_idx = (peer_idx as usize) % peers.len();
                    let handler_idx = (peer_idx as usize) % peers.len();

                    if let Some(monitor) = monitors.get_mut(&monitor_idx) {
                        monitor
                            .collected(peers[handler_idx].public_key(), response, count)
                            .await;
                    }
                }

                CollectorOperation::CreateEngine {
                    peer_idx,
                    mailbox_size,
                    priority_request,
                    priority_response,
                } => {
                    let idx = (peer_idx as usize) % peers.len();
                    let handler = handlers.get(&idx).cloned().unwrap_or_else(|| {
                        FuzzHandler::new(true, StdRng::seed_from_u64(rng.gen()))
                    });
                    let monitor = monitors.get(&idx).cloned().unwrap_or_else(FuzzMonitor::new);
                    let config = Config {
                        blocker: FuzzBlocker,
                        monitor,
                        handler,
                        mailbox_size: (mailbox_size as usize),
                        priority_request,
                        request_codec: RangeCfg::from(..=MAX_LEN),
                        priority_response,
                        response_codec: RangeCfg::from(..=MAX_LEN),
                    };

                    let (engine, mailbox) = Engine::new(context.clone(), config);
                    mailboxes.insert(idx, mailbox);

                    let (_tx, _rx) = mpsc::unbounded();
                    let mock_receiver = MockReceiver { rx: _rx };
                    engine.start(
                        (MockSender, mock_receiver),
                        (
                            MockSender,
                            MockReceiver {
                                rx: mpsc::unbounded().1,
                            },
                        ),
                    );
                }
            }
            context.sleep(Duration::from_millis(100)).await;
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
