use super::{Config, Network};
use crate::{
    Address, AddressableManager as _, AddressableTrackedPeers, Receiver as _, Recipients,
    Sender as _,
    authenticated::{MAX_PAYLOAD_OVERHEAD, max_size},
};
use commonware_codec::{Decode as _, Encode as _, FixedSize};
use commonware_cryptography::{AsyncSigner, Signer, Verifier as _, ed25519};
use commonware_macros::test_traced;
use commonware_runtime::{
    BufferPooler, Clock, IoBuf, IoBufs, Quota, Runner as _, Sink, Spawner as _, Stream,
    Supervisor as _, deterministic,
};
use commonware_stream::{Handshake, Receiver as StreamReceiver, Sender as StreamSender, encrypted};
use commonware_utils::{NZU32, NZUsize, ordered::Map, sync::Mutex};
use rand_core::CryptoRng;
use std::{
    collections::HashMap,
    future::{Future, pending, poll_fn},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::Poll,
    time::Duration,
};
use thiserror::Error;

const MAX_MESSAGE_SIZE: u32 = 1_024;
const MAX_FRAME_SIZE: u32 = MAX_MESSAGE_SIZE + MAX_PAYLOAD_OVERHEAD;

#[derive(Default)]
struct Observations {
    dials: Mutex<Vec<ed25519::PublicKey>>,
    inbound: Mutex<Vec<ed25519::PublicKey>>,
    sends: AtomicUsize,
    receives: AtomicUsize,
    bouncer_calls: AtomicUsize,
    rejections: AtomicUsize,
    listen_proof_receives: AtomicUsize,
    signing_calls: AtomicUsize,
    pending_signatures: AtomicUsize,
    reject_inbound: AtomicBool,
    fail_signing: AtomicBool,
    stall_next_signature: AtomicBool,
    signing_failures: AtomicUsize,
}

struct TestSender<O: Sink> {
    inner: encrypted::Sender<O>,
    observations: Arc<Observations>,
}

impl<O: Sink> StreamSender for TestSender<O> {
    type Error = encrypted::Error;

    fn send(
        &mut self,
        bufs: impl Into<IoBufs> + Send,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.observations.sends.fetch_add(1, Ordering::Relaxed);
        self.inner.send(bufs)
    }

    fn send_many<B, I>(&mut self, bufs: I) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        B: Into<IoBufs> + Send,
        I: IntoIterator<Item = B> + Send,
        I::IntoIter: Send,
    {
        self.observations.sends.fetch_add(1, Ordering::Relaxed);
        self.inner.send_many(bufs)
    }
}

struct TestReceiver<I: Stream> {
    inner: encrypted::Receiver<I>,
    observations: Arc<Observations>,
}

impl<I: Stream> StreamReceiver for TestReceiver<I> {
    type Error = encrypted::Error;

    fn recv(&mut self) -> impl Future<Output = Result<IoBufs, Self::Error>> + Send {
        self.observations.receives.fetch_add(1, Ordering::Relaxed);
        self.inner.recv()
    }
}

#[derive(Clone)]
struct TestScheme {
    application_signer: ed25519::PrivateKey,
    observations: Arc<Observations>,
}

#[derive(Debug, Error)]
#[error("application signer unavailable")]
struct TestSigningError;

impl AsyncSigner for TestScheme {
    type Signature = ed25519::Signature;
    type PublicKey = ed25519::PublicKey;
    type Error = TestSigningError;

    fn public_key(&self) -> Self::PublicKey {
        Signer::public_key(&self.application_signer)
    }

    async fn sign(&self, namespace: &[u8], message: &[u8]) -> Result<Self::Signature, Self::Error> {
        self.observations
            .signing_calls
            .fetch_add(1, Ordering::Relaxed);
        yield_once().await;
        if self
            .observations
            .stall_next_signature
            .swap(false, Ordering::Relaxed)
        {
            self.observations
                .pending_signatures
                .fetch_add(1, Ordering::Relaxed);
            pending::<()>().await;
        }
        if self.observations.fail_signing.load(Ordering::Relaxed) {
            self.observations
                .signing_failures
                .fetch_add(1, Ordering::Relaxed);
            return Err(TestSigningError);
        }
        Ok(Signer::sign(&self.application_signer, namespace, message))
    }
}

type ApplicationProof = (ed25519::PublicKey, ed25519::PublicKey, ed25519::Signature);
const APPLICATION_PROOF_SIZE: usize = ed25519::PublicKey::SIZE * 2 + ed25519::Signature::SIZE;

#[derive(Clone)]
struct TestHandshake<const MAX_SIZE: u32 = MAX_FRAME_SIZE> {
    scheme: TestScheme,
    transport_signer: ed25519::PrivateKey,
    application_to_transport: Arc<HashMap<ed25519::PublicKey, ed25519::PublicKey>>,
    transport_to_application: Arc<HashMap<ed25519::PublicKey, ed25519::PublicKey>>,
    observations: Arc<Observations>,
}

#[derive(Debug, Error)]
enum TestHandshakeError {
    #[error("encrypted handshake failed: {0}")]
    Encrypted(#[from] encrypted::Error),
    #[error("unknown application identity")]
    UnknownApplicationIdentity,
    #[error("unknown transport identity")]
    UnknownTransportIdentity,
    #[error("application signing failed: {0}")]
    Signing(#[from] TestSigningError),
    #[error("sending application proof failed: {0}")]
    SendProof(commonware_runtime::Error),
    #[error("receiving application proof failed: {0}")]
    ReceiveProof(commonware_runtime::Error),
    #[error("decoding application proof failed: {0}")]
    DecodeProof(commonware_codec::Error),
    #[error("invalid application proof")]
    InvalidApplicationProof,
    #[error("application identity rejected")]
    Rejected,
}

async fn yield_once() {
    let mut yielded = false;
    poll_fn(move |context| {
        if yielded {
            Poll::Ready(())
        } else {
            yielded = true;
            context.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
}

impl<const MAX_SIZE: u32> TestHandshake<MAX_SIZE> {
    fn encrypted_handshake(&self) -> encrypted::Handshake<ed25519::PrivateKey> {
        encrypted::Handshake {
            signing_key: self.transport_signer.clone(),
            synchrony_bound: Duration::from_secs(5),
            max_handshake_age: Duration::from_secs(10),
        }
    }

    async fn application_proof(
        &self,
        namespace: &[u8],
    ) -> Result<ApplicationProof, TestSigningError> {
        let transport_key = Signer::public_key(&self.transport_signer);
        let signature = self.scheme.sign(namespace, transport_key.as_ref()).await?;
        Ok((self.scheme.public_key(), transport_key, signature))
    }

    fn verify_application_proof(
        &self,
        namespace: &[u8],
        proof: &ApplicationProof,
    ) -> Result<(), TestHandshakeError> {
        let (application_key, proof_transport_key, signature) = proof;
        let Some(transport_key) = self.application_to_transport.get(application_key) else {
            return Err(TestHandshakeError::UnknownApplicationIdentity);
        };
        if transport_key != proof_transport_key
            || !application_key.verify(namespace, proof_transport_key.as_ref(), signature)
        {
            return Err(TestHandshakeError::InvalidApplicationProof);
        }
        Ok(())
    }

    async fn send_application_proof(
        &self,
        namespace: &[u8],
        sink: &mut impl Sink,
    ) -> Result<(), TestHandshakeError> {
        let proof = self.application_proof(namespace).await?;
        sink.send(proof.encode())
            .await
            .map_err(TestHandshakeError::SendProof)
    }

    async fn receive_application_proof(
        &self,
        namespace: &[u8],
        stream: &mut impl Stream,
    ) -> Result<ApplicationProof, TestHandshakeError> {
        let encoded = stream
            .recv(APPLICATION_PROOF_SIZE)
            .await
            .map_err(TestHandshakeError::ReceiveProof)?;
        let proof = ApplicationProof::decode_cfg(encoded, &((), (), ()))
            .map_err(TestHandshakeError::DecodeProof)?;
        self.verify_application_proof(namespace, &proof)?;
        Ok(proof)
    }
}

impl<const MAX_SIZE: u32> Handshake for TestHandshake<MAX_SIZE> {
    const MAX_SIZE: u32 = MAX_SIZE;

    type Scheme = TestScheme;
    type Error = TestHandshakeError;
    type Sender<O: Sink> = TestSender<O>;
    type Receiver<I: Stream> = TestReceiver<I>;

    fn scheme(&self) -> &Self::Scheme {
        &self.scheme
    }

    async fn dial<C, I, O>(
        self,
        context: C,
        namespace: Vec<u8>,
        max_message_size: u32,
        expected_peer: ed25519::PublicKey,
        mut stream: I,
        mut sink: O,
    ) -> Result<(Self::Sender<O>, Self::Receiver<I>), Self::Error>
    where
        C: BufferPooler + Clock + CryptoRng,
        I: Stream,
        O: Sink,
    {
        self.observations.dials.lock().push(expected_peer.clone());

        let transport_peer = self
            .application_to_transport
            .get(&expected_peer)
            .cloned()
            .ok_or(TestHandshakeError::UnknownApplicationIdentity)?;
        self.send_application_proof(&namespace, &mut sink).await?;
        let proof = self
            .receive_application_proof(&namespace, &mut stream)
            .await?;
        if proof.0 != expected_peer || proof.1 != transport_peer {
            return Err(TestHandshakeError::InvalidApplicationProof);
        }
        let (sender, receiver) = self
            .encrypted_handshake()
            .dial(
                context,
                namespace,
                max_message_size,
                transport_peer,
                stream,
                sink,
            )
            .await?;

        Ok((
            TestSender {
                inner: sender,
                observations: self.observations.clone(),
            },
            TestReceiver {
                inner: receiver,
                observations: self.observations,
            },
        ))
    }

    async fn listen<C, I, O, B, F>(
        self,
        context: C,
        namespace: Vec<u8>,
        max_message_size: u32,
        bouncer: B,
        mut stream: I,
        mut sink: O,
    ) -> Result<(ed25519::PublicKey, Self::Sender<O>, Self::Receiver<I>), Self::Error>
    where
        C: BufferPooler + Clock + CryptoRng,
        I: Stream,
        O: Sink,
        B: FnOnce(ed25519::PublicKey) -> F + Send,
        F: Future<Output = bool> + Send,
    {
        self.observations
            .listen_proof_receives
            .fetch_add(1, Ordering::Relaxed);
        let proof = self
            .receive_application_proof(&namespace, &mut stream)
            .await?;
        self.send_application_proof(&namespace, &mut sink).await?;
        let expected_transport = proof.1.clone();
        let (transport_peer, sender, receiver) = self
            .encrypted_handshake()
            .listen(
                context,
                namespace,
                max_message_size,
                move |transport_peer| async move { transport_peer == expected_transport },
                stream,
                sink,
            )
            .await?;
        let application_peer = self
            .transport_to_application
            .get(&transport_peer)
            .cloned()
            .ok_or(TestHandshakeError::UnknownTransportIdentity)?;
        if application_peer != proof.0 {
            return Err(TestHandshakeError::InvalidApplicationProof);
        }
        self.observations
            .inbound
            .lock()
            .push(application_peer.clone());
        self.observations
            .bouncer_calls
            .fetch_add(1, Ordering::Relaxed);
        let acceptable = bouncer(application_peer.clone()).await;
        if !acceptable || self.observations.reject_inbound.load(Ordering::Relaxed) {
            self.observations.rejections.fetch_add(1, Ordering::Relaxed);
            return Err(TestHandshakeError::Rejected);
        }

        Ok((
            application_peer,
            TestSender {
                inner: sender,
                observations: self.observations.clone(),
            },
            TestReceiver {
                inner: receiver,
                observations: self.observations,
            },
        ))
    }
}

fn handshakes<const MAX_SIZE: u32>() -> (
    TestHandshake<MAX_SIZE>,
    Arc<Observations>,
    TestHandshake<MAX_SIZE>,
    Arc<Observations>,
) {
    let mut handshakes = make_handshakes::<MAX_SIZE>(&[(0, 100), (1, 101)]).into_iter();
    let (handshake_0, observations_0) = handshakes.next().unwrap();
    let (handshake_1, observations_1) = handshakes.next().unwrap();
    (handshake_0, observations_0, handshake_1, observations_1)
}

fn make_handshakes<const MAX_SIZE: u32>(
    seeds: &[(u64, u64)],
) -> Vec<(TestHandshake<MAX_SIZE>, Arc<Observations>)> {
    let keys = seeds
        .iter()
        .map(|(transport, application)| {
            (
                ed25519::PrivateKey::from_seed(*transport),
                ed25519::PrivateKey::from_seed(*application),
            )
        })
        .collect::<Vec<_>>();
    let application_to_transport: Arc<HashMap<_, _>> = Arc::new(
        keys.iter()
            .map(|(transport, application)| {
                (
                    Signer::public_key(application),
                    Signer::public_key(transport),
                )
            })
            .collect(),
    );
    let transport_to_application: Arc<HashMap<_, _>> = Arc::new(
        keys.iter()
            .map(|(transport, application)| {
                (
                    Signer::public_key(transport),
                    Signer::public_key(application),
                )
            })
            .collect(),
    );

    keys.into_iter()
        .map(|(transport_signer, application_signer)| {
            let observations = Arc::new(Observations::default());
            (
                TestHandshake {
                    scheme: TestScheme {
                        application_signer,
                        observations: observations.clone(),
                    },
                    transport_signer,
                    application_to_transport: application_to_transport.clone(),
                    transport_to_application: transport_to_application.clone(),
                    observations: observations.clone(),
                },
                observations,
            )
        })
        .collect()
}

fn config(handshake: TestHandshake, listen: SocketAddr) -> Config<TestHandshake> {
    let mut config = custom_config(handshake, listen, MAX_MESSAGE_SIZE);
    // Recovery within the test deadline must come from the handshake timeout.
    config.handshake_timeout = Duration::from_millis(50);
    config.dial_timeout = Duration::from_secs(20);
    config.peer_connection_cooldown = Duration::from_millis(10);
    config.dial_frequency = Duration::from_millis(5);
    config.max_concurrent_handshakes = NZU32!(2);
    config
}

fn custom_config<const MAX_SIZE: u32>(
    handshake: TestHandshake<MAX_SIZE>,
    listen: SocketAddr,
    max_message_size: u32,
) -> Config<TestHandshake<MAX_SIZE>> {
    Config::local(
        handshake,
        b"_COMMONWARE_P2P_CUSTOM_HANDSHAKE_TEST",
        listen,
        NZUsize!(2),
        max_message_size,
    )
}

struct Pair {
    listener_key: ed25519::PublicKey,
    dialer_key: ed25519::PublicKey,
    listener_sender: super::Sender<ed25519::PublicKey, deterministic::Context>,
    listener_receiver: super::Receiver<ed25519::PublicKey>,
    dialer_sender: super::Sender<ed25519::PublicKey, deterministic::Context>,
    dialer_receiver: super::Receiver<ed25519::PublicKey>,
}

fn start_pair(
    context: &deterministic::Context,
    base_port: u16,
    listener_handshake: TestHandshake,
    dialer_handshake: TestHandshake,
) -> Pair {
    let listener_key = listener_handshake.scheme().public_key();
    let dialer_key = dialer_handshake.scheme().public_key();
    let listener_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), base_port);
    let dialer_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), base_port + 1);
    let (mut listener_network, mut listener_oracle) = Network::new(
        context.child("listener"),
        config(listener_handshake, listener_address),
    );
    let (listener_sender, listener_receiver) =
        listener_network.register(0, Quota::per_second(NZU32!(100)));
    let (mut dialer_network, mut dialer_oracle) = Network::new(
        context.child("dialer"),
        config(dialer_handshake, dialer_address),
    );
    let (dialer_sender, dialer_receiver) =
        dialer_network.register(0, Quota::per_second(NZU32!(100)));

    listener_oracle.track(
        0,
        AddressableTrackedPeers::new(
            Map::<_, Address>::try_from([(listener_key.clone(), listener_address.into())]).unwrap(),
            Map::<_, Address>::try_from([(dialer_key.clone(), dialer_address.into())]).unwrap(),
        ),
    );
    dialer_oracle.track(
        0,
        Map::<_, Address>::try_from([
            (listener_key.clone(), listener_address.into()),
            (dialer_key.clone(), dialer_address.into()),
        ])
        .unwrap(),
    );
    listener_network.start();
    dialer_network.start();

    Pair {
        listener_key,
        dialer_key,
        listener_sender,
        listener_receiver,
        dialer_sender,
        dialer_receiver,
    }
}

fn repeat_send(
    context: &deterministic::Context,
    mut sender: super::Sender<ed25519::PublicKey, deterministic::Context>,
    recipient: ed25519::PublicKey,
    message: &'static [u8],
) {
    context.child("sender").spawn(move |context| async move {
        loop {
            sender.send(
                Recipients::One(recipient.clone()),
                IoBuf::from(message),
                true,
            );
            context.sleep(Duration::from_millis(10)).await;
        }
    });
}

async fn wait_for_counter(context: &impl Clock, counter: &AtomicUsize) {
    while counter.load(Ordering::Relaxed) == 0 {
        context.sleep(Duration::from_millis(1)).await;
    }
}

#[test_traced]
fn test_construction_enforces_handshake_message_limit() {
    deterministic::Runner::default().start(|context| async move {
        assert_eq!(max_size::<TestHandshake>(), MAX_MESSAGE_SIZE);
        let (below, _, boundary, _) = handshakes::<MAX_FRAME_SIZE>();
        Network::new(
            context.child("below_default_limit"),
            custom_config(
                below,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5_000),
                MAX_MESSAGE_SIZE - 1,
            ),
        );
        Network::new(
            context.child("at_default_limit"),
            custom_config(
                boundary,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5_001),
                MAX_MESSAGE_SIZE,
            ),
        );

        let (over, _, _, _) = handshakes::<MAX_FRAME_SIZE>();
        let result = catch_unwind(AssertUnwindSafe(|| {
            Network::new(
                context.child("over_default_limit"),
                custom_config(
                    over,
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5_002),
                    MAX_MESSAGE_SIZE + 1,
                ),
            )
        }));
        assert!(result.is_err());

        let (too_small, _, _, _) = handshakes::<{ MAX_PAYLOAD_OVERHEAD - 1 }>();
        let result = catch_unwind(AssertUnwindSafe(|| {
            Network::new(
                context.child("smaller_than_framing_overhead"),
                custom_config(
                    too_small,
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5_003),
                    0,
                ),
            )
        }));
        assert!(result.is_err());

        let (zero_boundary, _, zero_over, _) = handshakes::<MAX_PAYLOAD_OVERHEAD>();
        assert_eq!(max_size::<TestHandshake<MAX_PAYLOAD_OVERHEAD>>(), 0);
        Network::new(
            context.child("zero_payload_boundary"),
            custom_config(
                zero_boundary,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5_004),
                0,
            ),
        );
        let result = catch_unwind(AssertUnwindSafe(|| {
            Network::new(
                context.child("over_zero_payload_boundary"),
                custom_config(
                    zero_over,
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5_005),
                    1,
                ),
            )
        }));
        assert!(result.is_err());
    });
}

#[test_traced]
fn test_custom_handshake_routes_application_identities_bidirectionally() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
        let (handshake_0, observations_0, handshake_1, observations_1) =
            handshakes::<MAX_FRAME_SIZE>();
        let mut pair = start_pair(&context, 5_100, handshake_0, handshake_1);

        repeat_send(
            &context,
            pair.dialer_sender,
            pair.listener_key.clone(),
            b"from dialer",
        );
        let (peer, message) = pair.listener_receiver.recv().await.unwrap();
        assert_eq!(peer, pair.dialer_key);
        assert_eq!(message.as_ref(), b"from dialer");

        repeat_send(
            &context,
            pair.listener_sender,
            pair.dialer_key.clone(),
            b"from listener",
        );
        let (peer, message) = pair.dialer_receiver.recv().await.unwrap();
        assert_eq!(peer, pair.listener_key);
        assert_eq!(message.as_ref(), b"from listener");

        let dials = observations_1.dials.lock();
        assert!(!dials.is_empty());
        assert!(dials.iter().all(|peer| peer == &pair.listener_key));
        let inbound = observations_0.inbound.lock();
        assert!(!inbound.is_empty());
        assert!(inbound.iter().all(|peer| peer == &pair.dialer_key));
        assert!(observations_0.sends.load(Ordering::Relaxed) > 0);
        assert!(observations_0.receives.load(Ordering::Relaxed) > 0);
        assert!(observations_1.sends.load(Ordering::Relaxed) > 0);
        assert!(observations_1.receives.load(Ordering::Relaxed) > 0);
    });
}

fn tracked_peers(
    local: (ed25519::PublicKey, SocketAddr),
    peers: impl IntoIterator<Item = (ed25519::PublicKey, SocketAddr)>,
    dial_peers: bool,
) -> AddressableTrackedPeers<ed25519::PublicKey> {
    let peers = peers
        .into_iter()
        .map(|(key, address)| (key, address.into()))
        .collect::<Vec<_>>();
    let mut primary = vec![(local.0, local.1.into())];
    let secondary = if dial_peers {
        primary.extend(peers);
        Vec::new()
    } else {
        peers
    };
    AddressableTrackedPeers::new(
        Map::try_from(primary).unwrap(),
        Map::try_from(secondary).unwrap(),
    )
}

async fn assert_pending_authentication_does_not_block_peer(
    context: deterministic::Context,
    central_dials: bool,
) {
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

    let mut handshakes =
        make_handshakes::<MAX_FRAME_SIZE>(&[(10, 110), (11, 111), (12, 112)]).into_iter();
    let (central_handshake, central_observations) = handshakes.next().unwrap();
    let (blocked_handshake, blocked_observations) = handshakes.next().unwrap();
    let (healthy_handshake, healthy_observations) = handshakes.next().unwrap();
    central_observations
        .stall_next_signature
        .store(true, Ordering::Relaxed);

    let central_key = central_handshake.scheme().public_key();
    let blocked_key = blocked_handshake.scheme().public_key();
    let healthy_key = healthy_handshake.scheme().public_key();
    let central_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5_300);
    let blocked_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5_301);
    let healthy_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5_302);

    let mut central_config = config(central_handshake, central_address);
    central_config.handshake_timeout = HANDSHAKE_TIMEOUT;
    central_config.max_peers_per_set = NZUsize!(3);
    let (mut central_network, mut central_oracle) =
        Network::new(context.child("central"), central_config);
    let (central_sender, central_receiver) =
        central_network.register(0, Quota::per_second(NZU32!(100)));
    central_oracle.track(
        0,
        tracked_peers(
            (central_key.clone(), central_address),
            [
                (blocked_key.clone(), blocked_address),
                (healthy_key.clone(), healthy_address),
            ],
            central_dials,
        ),
    );

    let mut blocked_config = config(blocked_handshake, blocked_address);
    blocked_config.handshake_timeout = HANDSHAKE_TIMEOUT;
    let (mut blocked_network, mut blocked_oracle) =
        Network::new(context.child("blocked"), blocked_config);
    blocked_network.register(0, Quota::per_second(NZU32!(100)));
    blocked_oracle.track(
        0,
        tracked_peers(
            (blocked_key.clone(), blocked_address),
            [(central_key.clone(), central_address)],
            !central_dials,
        ),
    );

    let stalled_at = context.current();
    central_network.start();
    blocked_network.start();
    wait_for_counter(&context, &central_observations.pending_signatures).await;
    let blocked_listener = if central_dials {
        &blocked_observations.listen_proof_receives
    } else {
        &central_observations.listen_proof_receives
    };
    wait_for_counter(&context, blocked_listener).await;

    let mut healthy_config = config(healthy_handshake, healthy_address);
    healthy_config.handshake_timeout = HANDSHAKE_TIMEOUT;
    let (mut healthy_network, mut healthy_oracle) =
        Network::new(context.child("healthy"), healthy_config);
    let (healthy_sender, healthy_receiver) =
        healthy_network.register(0, Quota::per_second(NZU32!(100)));
    healthy_oracle.track(
        0,
        tracked_peers(
            (healthy_key.clone(), healthy_address),
            [(central_key.clone(), central_address)],
            !central_dials,
        ),
    );
    healthy_network.start();

    let (sender, mut receiver, recipient, expected_peer) = if central_dials {
        (
            central_sender,
            healthy_receiver,
            healthy_key.clone(),
            central_key.clone(),
        )
    } else {
        (
            healthy_sender,
            central_receiver,
            central_key.clone(),
            healthy_key.clone(),
        )
    };
    repeat_send(&context, sender, recipient, b"healthy peer progressed");
    let (peer, message) = receiver.recv().await.unwrap();
    assert_eq!(peer, expected_peer);
    assert_eq!(message.as_ref(), b"healthy peer progressed");
    assert!(context.current().duration_since(stalled_at).unwrap() < HANDSHAKE_TIMEOUT);
    assert_eq!(
        central_observations
            .pending_signatures
            .load(Ordering::Relaxed),
        1
    );
    assert!(central_observations.signing_calls.load(Ordering::Relaxed) >= 2);

    if central_dials {
        let dials = central_observations.dials.lock();
        assert!(dials.contains(&blocked_key));
        assert!(dials.contains(&healthy_key));
        assert!(
            healthy_observations
                .listen_proof_receives
                .load(Ordering::Relaxed)
                > 0
        );
    } else {
        assert!(central_observations.dials.lock().is_empty());
        assert!(
            central_observations
                .listen_proof_receives
                .load(Ordering::Relaxed)
                >= 2
        );
        assert!(blocked_observations.dials.lock().contains(&central_key));
        assert!(healthy_observations.dials.lock().contains(&central_key));
    }
}

#[test_traced]
fn test_pending_authentication_does_not_block_another_peer() {
    for central_dials in [true, false] {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            assert_pending_authentication_does_not_block_peer(context, central_dials).await;
        });
    }
}

#[test_traced]
fn test_custom_handshake_failures_release_for_retry() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
        let (handshake_0, observations_0, handshake_1, observations_1) =
            handshakes::<MAX_FRAME_SIZE>();
        observations_0.reject_inbound.store(true, Ordering::Relaxed);
        let mut pair = start_pair(&context, 5_200, handshake_0, handshake_1);

        wait_for_counter(&context, &observations_0.rejections).await;
        observations_1.fail_signing.store(true, Ordering::Relaxed);
        observations_0
            .reject_inbound
            .store(false, Ordering::Relaxed);
        wait_for_counter(&context, &observations_1.signing_failures).await;

        let completed_signing_calls = observations_1.signing_calls.load(Ordering::Relaxed);
        let stalled_at = context.current();
        observations_1
            .stall_next_signature
            .store(true, Ordering::Relaxed);
        observations_1.fail_signing.store(false, Ordering::Relaxed);
        wait_for_counter(&context, &observations_1.pending_signatures).await;

        repeat_send(
            &context,
            pair.dialer_sender,
            pair.listener_key.clone(),
            b"accepted",
        );
        let (peer, message) = pair.listener_receiver.recv().await.unwrap();
        assert_eq!(peer, pair.dialer_key);
        assert_eq!(message.as_ref(), b"accepted");
        assert!(observations_0.bouncer_calls.load(Ordering::Relaxed) > 0);
        assert!(context.current().duration_since(stalled_at).unwrap() >= Duration::from_millis(50));
        assert!(observations_1.signing_failures.load(Ordering::Relaxed) > 0);
        assert!(
            observations_1.signing_calls.load(Ordering::Relaxed) >= completed_signing_calls + 2
        );
    });
}
