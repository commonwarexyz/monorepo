use super::*;
use crate::Consumer;
use bytes::Bytes;
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{ed25519, PrivateKeyExt as _, Signer as _};
use commonware_p2p::{simulated, Recipients, Receiver as _, Sender as _};
use commonware_runtime::{deterministic, Clock as _, Metrics as _, Runner as _};
use commonware_utils::sequence::u64::U64;
use futures::channel::oneshot;
use crate::Resolver as _;

#[derive(Clone)]
struct TestConsumer;
impl Consumer for TestConsumer {
    type Key = U64;
    type Value = Bytes;
    type Failure = ();
    async fn deliver(&mut self, _key: Self::Key, _value: Self::Value) -> bool { true }
    async fn failed(&mut self, _key: Self::Key, _failure: Self::Failure) {}
}

#[derive(Clone)]
struct TestProducer;
impl super::Producer for TestProducer {
    type Key = U64;
    async fn produce(&mut self, _key: Self::Key) -> oneshot::Receiver<Bytes> {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(Bytes::from_static(b"ok"));
        rx
    }
}

#[derive(Clone)]
struct TestCoordinator {
    peers: Vec<ed25519::PublicKey>,
    id: u64,
}
impl super::Coordinator for TestCoordinator {
    type PublicKey = ed25519::PublicKey;
    fn peers(&self) -> &Vec<Self::PublicKey> { &self.peers }
    fn peer_set_id(&self) -> u64 { self.id }
}

#[test]
fn test_broadcast_request_and_push_response() {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        // Setup network
        let (network, mut oracle) = simulated::Network::new(
            context.with_label("network"),
            simulated::Config { max_size: 1024 * 1024 },
        );
        network.start();

        // Peers
        let pk_a = ed25519::PrivateKey::from_seed(1).public_key();
        let pk_b = ed25519::PrivateKey::from_seed(2).public_key();

        // Register channel 0 for broadcast resolver
        let (sender_a, receiver_a) = oracle.register(pk_a.clone(), 0).await.unwrap();
        let (mut sender_b, mut receiver_b) = oracle.register(pk_b.clone(), 0).await.unwrap();

        // Link both directions
        oracle.add_link(pk_a.clone(), pk_b.clone(), simulated::Link { latency: std::time::Duration::from_millis(1), jitter: std::time::Duration::from_millis(0), success_rate: 1.0 }).await.unwrap();
        oracle.add_link(pk_b.clone(), pk_a.clone(), simulated::Link { latency: std::time::Duration::from_millis(1), jitter: std::time::Duration::from_millis(0), success_rate: 1.0 }).await.unwrap();

        // Start Engine at A
        let cfg = Config {
            coordinator: TestCoordinator { peers: vec![pk_b.clone()], id: 0 },
            consumer: TestConsumer,
            producer: TestProducer,
            mailbox_size: 1024,
            priority_requests: false,
            priority_responses: false,
        };
        let (engine_a, mut mailbox_a) = Engine::new(context.with_label("engine"), cfg);
        engine_a.start((sender_a.clone(), receiver_a));

        // B sends unsolicited push response to A for key=7
        let msg = wire::Message { payload: wire::Payload::Response { key: U64::from(7), data: Bytes::from_static(b"hello") } };
        let _ = sender_b.send(Recipients::One(pk_a.clone()), msg.encode().freeze(), false).await.unwrap();

        // Broadcast a request from A for key=42
        mailbox_a.fetch(U64::from(42)).await;

        // Let the system run a bit
        context.sleep(std::time::Duration::from_millis(10)).await;

        // Ensure B received the broadcast request
        let (_origin, bytes) = receiver_b.recv().await.unwrap();
        let decoded = wire::Message::<U64>::decode(bytes).unwrap();
        match decoded.payload { wire::Payload::Request(key) => assert_eq!(u64::from(key), 42), _ => panic!("unexpected payload") }
    });
}


