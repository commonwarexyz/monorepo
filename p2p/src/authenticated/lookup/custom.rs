use super::{Config, Network};
use crate::{
    Address, AddressableManager as _, AddressableTrackedPeers, Receiver as _, Recipients,
    Sender as _,
};
use commonware_cryptography::{Signer as _, ed25519};
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
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::Poll,
    time::Duration,
};
use thiserror::Error;

const MAX_MESSAGE_SIZE: u32 = 1_024;

#[derive(Default)]
struct Observations {
    dials: Mutex<Vec<ed25519::PublicKey>>,
    inbound: Mutex<Vec<ed25519::PublicKey>>,
    sends: AtomicUsize,
    receives: AtomicUsize,
    bouncer_calls: AtomicUsize,
    rejections: AtomicUsize,
    pending_dials: AtomicUsize,
    reject_inbound: AtomicBool,
    pending_outbound: AtomicBool,
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
struct TestSigner {
    application_key: ed25519::PublicKey,
    transport_signer: ed25519::PrivateKey,
}

#[derive(Clone)]
struct TestHandshake {
    signer: TestSigner,
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

impl TestHandshake {
    fn encrypted_handshake(&self) -> encrypted::Handshake<ed25519::PrivateKey> {
        encrypted::Handshake {
            signing_key: self.signer.transport_signer.clone(),
            synchrony_bound: Duration::from_secs(5),
            max_handshake_age: Duration::from_secs(10),
        }
    }
}

impl Handshake for TestHandshake {
    type PublicKey = ed25519::PublicKey;
    type Signer = TestSigner;
    type Error = TestHandshakeError;
    type Sender<O: Sink> = TestSender<O>;
    type Receiver<I: Stream> = TestReceiver<I>;

    fn public_key(&self) -> Self::PublicKey {
        self.signer.application_key.clone()
    }

    fn signer(&self) -> &Self::Signer {
        &self.signer
    }

    async fn dial<C, I, O>(
        self,
        context: C,
        namespace: Vec<u8>,
        max_message_size: u32,
        expected_peer: Self::PublicKey,
        stream: I,
        sink: O,
    ) -> Result<(Self::Sender<O>, Self::Receiver<I>), Self::Error>
    where
        C: BufferPooler + Clock + CryptoRng,
        I: Stream,
        O: Sink,
    {
        self.observations.dials.lock().push(expected_peer.clone());

        if self.observations.pending_outbound.load(Ordering::Relaxed) {
            self.observations
                .pending_dials
                .fetch_add(1, Ordering::Relaxed);
            pending::<()>().await;
        }

        let transport_peer = self
            .application_to_transport
            .get(&expected_peer)
            .cloned()
            .ok_or(TestHandshakeError::UnknownApplicationIdentity)?;
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
        stream: I,
        sink: O,
    ) -> Result<(Self::PublicKey, Self::Sender<O>, Self::Receiver<I>), Self::Error>
    where
        C: BufferPooler + Clock + CryptoRng,
        I: Stream,
        O: Sink,
        B: FnOnce(Self::PublicKey) -> F + Send,
        F: Future<Output = bool> + Send,
    {
        let transport_to_application = self.transport_to_application.clone();
        let observations = self.observations.clone();
        let (transport_peer, sender, receiver) = self
            .encrypted_handshake()
            .listen(
                context,
                namespace,
                max_message_size,
                move |transport_peer| {
                    let application_peer = transport_to_application.get(&transport_peer).cloned();
                    let observations = observations.clone();
                    async move {
                        yield_once().await;
                        let Some(application_peer) = application_peer else {
                            return false;
                        };
                        observations.inbound.lock().push(application_peer.clone());
                        observations.bouncer_calls.fetch_add(1, Ordering::Relaxed);
                        let acceptable = bouncer(application_peer).await;
                        if observations.reject_inbound.load(Ordering::Relaxed) {
                            observations.rejections.fetch_add(1, Ordering::Relaxed);
                            false
                        } else {
                            acceptable
                        }
                    }
                },
                stream,
                sink,
            )
            .await?;
        let application_peer = self
            .transport_to_application
            .get(&transport_peer)
            .cloned()
            .ok_or(TestHandshakeError::UnknownTransportIdentity)?;

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

fn handshakes() -> (
    TestHandshake,
    Arc<Observations>,
    TestHandshake,
    Arc<Observations>,
) {
    let transport_signer_0 = ed25519::PrivateKey::from_seed(0);
    let transport_signer_1 = ed25519::PrivateKey::from_seed(1);
    let application_key_0 = ed25519::PrivateKey::from_seed(100).public_key();
    let application_key_1 = ed25519::PrivateKey::from_seed(101).public_key();
    let application_to_transport = Arc::new(HashMap::from([
        (application_key_0.clone(), transport_signer_0.public_key()),
        (application_key_1.clone(), transport_signer_1.public_key()),
    ]));
    let transport_to_application = Arc::new(HashMap::from([
        (transport_signer_0.public_key(), application_key_0.clone()),
        (transport_signer_1.public_key(), application_key_1.clone()),
    ]));
    let observations_0 = Arc::new(Observations::default());
    let observations_1 = Arc::new(Observations::default());

    (
        TestHandshake {
            signer: TestSigner {
                application_key: application_key_0,
                transport_signer: transport_signer_0,
            },
            application_to_transport: application_to_transport.clone(),
            transport_to_application: transport_to_application.clone(),
            observations: observations_0.clone(),
        },
        observations_0,
        TestHandshake {
            signer: TestSigner {
                application_key: application_key_1,
                transport_signer: transport_signer_1,
            },
            application_to_transport,
            transport_to_application,
            observations: observations_1.clone(),
        },
        observations_1,
    )
}

fn config(handshake: TestHandshake, listen: SocketAddr) -> Config<TestHandshake> {
    let mut config = Config::local_with_handshake(
        handshake,
        b"_COMMONWARE_P2P_CUSTOM_HANDSHAKE_TEST",
        listen,
        NZUsize!(2),
        MAX_MESSAGE_SIZE,
    );
    // Recovery within the test deadline must come from the handshake timeout.
    config.handshake_timeout = Duration::from_millis(50);
    config.dial_timeout = Duration::from_secs(20);
    config.peer_connection_cooldown = Duration::from_millis(10);
    config.dial_frequency = Duration::from_millis(5);
    config.max_concurrent_handshakes = NZU32!(1);
    config
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
    let listener_key = listener_handshake.public_key();
    let dialer_key = dialer_handshake.public_key();
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
fn test_custom_handshake_routes_application_identities_bidirectionally() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
        let (handshake_0, observations_0, handshake_1, observations_1) = handshakes();
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

#[test_traced]
fn test_custom_handshake_failures_release_for_retry() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
        let (handshake_0, observations_0, handshake_1, observations_1) = handshakes();
        observations_0.reject_inbound.store(true, Ordering::Relaxed);
        let mut pair = start_pair(&context, 5_200, handshake_0, handshake_1);

        wait_for_counter(&context, &observations_0.rejections).await;
        observations_1
            .pending_outbound
            .store(true, Ordering::Relaxed);
        observations_0
            .reject_inbound
            .store(false, Ordering::Relaxed);
        wait_for_counter(&context, &observations_1.pending_dials).await;
        observations_1
            .pending_outbound
            .store(false, Ordering::Relaxed);

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
        assert!(observations_1.dials.lock().len() >= 3);
    });
}
