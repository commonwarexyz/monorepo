//! This utility wraps a [Sender] and [Receiver], providing lightweight sub-channels keyed by
//! [Channel].
//!
//! Usage:
//! - Call [Muxer::new] to create the multiplexer.
//! - Call [Muxer::register] to obtain a ([SubSender], [SubReceiver]) pair for that subchannel.
//! - Drive [Muxer::run] in a background task to demux incoming messages into per-subchannel queues.

use crate::{Channel, Message, Receiver, Recipients, Sender};
use bytes::{BufMut, Bytes, BytesMut};
use commonware_codec::{varint::UInt, EncodeSize, ReadExt, Write};
use commonware_cryptography::PublicKey;
use commonware_runtime::{Handle, Spawner};
use futures::{channel::mpsc, SinkExt, StreamExt};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};
use thiserror::Error;
use tracing::debug;

/// Thread-safe routing table mapping each [Channel] to the [mpsc::Sender] for [`Message<P>`].
type Routes<P> = Arc<Mutex<HashMap<Channel, mpsc::Sender<Message<P>>>>>;

/// Errors that can occur when interacting with a [Muxer].
#[derive(Error, Debug)]
pub enum Error {
    #[error("recv failed")]
    RecvFailed,
}

/// A multiplexer of p2p channels into subchannels.
pub struct Muxer<S: Sender, R: Receiver> {
    sender: S,
    receiver: R,
    routes: Routes<R::PublicKey>,
    registered: Arc<Mutex<HashSet<Channel>>>,
    mailbox_size: usize,
}

impl<S: Sender, R: Receiver> Muxer<S, R> {
    /// Create a multiplexed wrapper around a [Sender] and [Receiver] pair.
    pub fn new(sender: S, receiver: R, mailbox_size: usize) -> Self {
        Self {
            sender,
            receiver,
            routes: Arc::new(Mutex::new(HashMap::new())),
            registered: Arc::new(Mutex::new(HashSet::new())),
            mailbox_size,
        }
    }

    /// Open a `subchannel`. Returns a `(SubSender, SubReceiver)` pair that can be used to send and
    /// receive messages for that subchannel.
    ///
    /// The caller must be driving [Muxer::run], or have started it using [Muxer::start], for the
    /// receiver to yield messages.
    ///
    /// # Panics
    ///
    /// Panics if the subchannel is already registered.
    pub fn register(&self, subchannel: Channel) -> (SubSender<S>, SubReceiver<R::PublicKey>) {
        // Panic if the subchannel was already registered at any point.
        if !self.registered.lock().unwrap().insert(subchannel) {
            panic!("duplicate subchannel registration: {subchannel}");
        }

        // Create a new channel to forward messages for the subchannel.
        let (tx, rx) = mpsc::channel(self.mailbox_size);
        assert!(self.routes.lock().unwrap().insert(subchannel, tx).is_none());

        // Return the subchannel sender and receiver.
        (
            SubSender {
                subchannel,
                inner: self.sender.clone(),
            },
            SubReceiver {
                receiver: rx,
                subchannel,
                routes: self.routes.clone(),
            },
        )
    }

    /// Start the demuxer using the given spawner.
    pub fn start<E: Spawner>(self, mut spawner: E) -> Handle<Result<(), R::Error>> {
        spawner.spawn_ref()(self.run())
    }

    /// Drive demultiplexing of messages into per-subchannel receivers.
    ///
    /// Callers should run this in a background task for as long as the underlying `Receiver` is
    /// expected to receive traffic.
    pub async fn run(mut self) -> Result<(), R::Error> {
        loop {
            let (pk, mut bytes) = self.receiver.recv().await?;

            // Decode message: varint(subchannel) || bytes
            let subchannel: Channel = match UInt::read(&mut bytes) {
                Ok(v) => v.into(),
                Err(_) => {
                    debug!(?pk, "invalid message: missing subchannel");
                    continue;
                }
            };

            // Get the route for the subchannel.
            //
            // Note: We intentionally avoid cloning the Sender here to preserve the bounded
            // semantics of the channel. Cloning `Sender` would introduce a new fairness slot on
            // every clone which would effectively infinitely increase capacity.
            let Some(mut sender) = ({
                let mut routes = self.routes.lock().unwrap();
                routes.remove(&subchannel)
            }) else {
                // Drops the message if the subchannel is not found
                continue;
            };

            // Send the message to the subchannel, blocking if the queue is full.
            // Warning: This blocks across all subchannels.
            if let Err(e) = sender.send((pk, bytes)).await {
                // Failure, drop the sender since the receiver is no longer interested.
                debug!(?subchannel, ?e, "failed to send message to subchannel");
            } else {
                // Place the sender back in the map for next time.
                let mut routes = self.routes.lock().unwrap();
                assert!(routes.insert(subchannel, sender).is_none());
            }
        }
    }
}

/// Sender that routes messages to the `subchannel`.
#[derive(Clone, Debug)]
pub struct SubSender<S: Sender> {
    inner: S,
    subchannel: Channel,
}

impl<S: Sender> Sender for SubSender<S> {
    type Error = S::Error;
    type PublicKey = S::PublicKey;

    async fn send(
        &mut self,
        recipients: Recipients<S::PublicKey>,
        payload: Bytes,
        priority: bool,
    ) -> Result<Vec<S::PublicKey>, S::Error> {
        let subchannel = UInt(self.subchannel);
        let mut buf = BytesMut::with_capacity(subchannel.encode_size() + payload.len());
        subchannel.write(&mut buf);
        buf.put_slice(&payload);
        self.inner.send(recipients, buf.freeze(), priority).await
    }
}

/// Receiver that yields messages for a specific subchannel.
#[derive(Debug)]
pub struct SubReceiver<P: PublicKey> {
    receiver: mpsc::Receiver<Message<P>>,
    subchannel: Channel,
    routes: Routes<P>,
}

impl<P: PublicKey> Receiver for SubReceiver<P> {
    type Error = Error;
    type PublicKey = P;

    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
        self.receiver.next().await.ok_or(Error::RecvFailed)
    }
}

impl<P: PublicKey> Drop for SubReceiver<P> {
    fn drop(&mut self) {
        // Remove the route for the subchannel. It may be temporarily removed already if the sender
        // was trying to send a message and the queue was full, so we don't assert that it exists.
        let mut routes = self.routes.lock().unwrap();
        routes.remove(&self.subchannel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simulated::{Config as SimConfig, Link, Network, Oracle},
        Recipients,
    };
    use bytes::Bytes;
    use commonware_cryptography::{ed25519::PrivateKey, PrivateKeyExt, Signer};
    use commonware_macros::{select, test_traced};
    use commonware_runtime::{deterministic, Clock, Metrics, Runner};
    use std::time::Duration;

    type Pk = commonware_cryptography::ed25519::PublicKey;

    const LINK: Link = Link {
        latency: 0.0,
        jitter: 0.0,
        success_rate: 1.0,
    };
    const CAPACITY: usize = 5usize;

    /// Start the network and return the oracle.
    fn start_network<P: PublicKey>(context: deterministic::Context) -> Oracle<P> {
        let (network, oracle) = Network::new(
            context.with_label("network"),
            SimConfig {
                max_size: 1024 * 1024,
            },
        );
        network.start();
        oracle
    }

    /// Create a public key from a seed.
    fn pk(seed: u64) -> Pk {
        PrivateKey::from_seed(seed).public_key()
    }

    /// Link two peers bidirectionally.
    async fn link_bidirectional(oracle: &mut Oracle<Pk>, a: Pk, b: Pk) {
        oracle.add_link(a.clone(), b.clone(), LINK).await.unwrap();
        oracle.add_link(b, a, LINK).await.unwrap();
    }

    /// Create a peer and register it with the oracle.
    async fn create_peer(
        oracle: &mut Oracle<Pk>,
        seed: u64,
    ) -> (
        Pk,
        Muxer<impl Sender<PublicKey = Pk>, impl Receiver<PublicKey = Pk>>,
    ) {
        let pubkey = pk(seed);
        let (sender, receiver) = oracle.register(pubkey.clone(), 0).await.unwrap();
        (pubkey, Muxer::new(sender, receiver, CAPACITY))
    }

    /// Test-only: open only a sender for a subchannel without registering a route.
    fn open_tx<S: Sender, R: Receiver>(mux: &Muxer<S, R>, subchannel: Channel) -> SubSender<S> {
        SubSender {
            subchannel,
            inner: mux.sender.clone(),
        }
    }

    /// Test-only: open only a receiver for a subchannel (registers the route).
    fn open_rx<S: Sender, R: Receiver>(
        mux: &Muxer<S, R>,
        subchannel: Channel,
    ) -> SubReceiver<R::PublicKey> {
        let (_tx, rx) = mux.register(subchannel);
        rx
    }

    /// Send a burst of messages to a list of senders.
    async fn send_burst<S: Sender>(txs: &mut [SubSender<S>], count: usize) {
        for i in 0..count {
            let payload = Bytes::from(vec![i as u8]);
            for tx in txs.iter_mut() {
                let _ = tx
                    .send(Recipients::All, payload.clone(), false)
                    .await
                    .unwrap();
            }
        }
    }

    /// Wait for `n` messages to be received on the receiver.
    async fn expect_n_messages<P: PublicKey>(
        rx: &mut SubReceiver<P>,
        n: usize,
        context: &deterministic::Context,
    ) {
        let mut count = 0;
        loop {
            select! {
                res = rx.recv() => {
                    res.expect("should have received message");
                    count += 1;
                },
                _ = context.sleep(Duration::from_millis(100)) => { break; },
            }
        }
        assert_eq!(n, count);
    }

    #[test]
    fn test_basic_routing() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut oracle = start_network(context.clone());

            let (pk1, mux1) = create_peer(&mut oracle, 0).await;
            let (pk2, mux2) = create_peer(&mut oracle, 1).await;
            link_bidirectional(&mut oracle, pk1.clone(), pk2.clone()).await;

            let mut sub_rx1 = open_rx(&mux1, 7);
            mux1.start(context.clone());

            let mut sub_tx2 = open_tx(&mux2, 7);

            // Send and receive
            let payload = Bytes::from_static(b"hello");
            let _ = sub_tx2
                .send(Recipients::One(pk1.clone()), payload.clone(), false)
                .await
                .unwrap();
            let (from, bytes) = sub_rx1.recv().await.unwrap();
            assert_eq!(from, pk2);
            assert_eq!(bytes, payload);
        });
    }

    #[test]
    fn test_multiple_routes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut oracle = start_network(context.clone());

            let (pk1, mux1) = create_peer(&mut oracle, 0).await;
            let (pk2, mux2) = create_peer(&mut oracle, 1).await;
            link_bidirectional(&mut oracle, pk1.clone(), pk2.clone()).await;

            let mut rx_a = open_rx(&mux1, 10);
            let mut rx_b = open_rx(&mux1, 20);
            mux1.start(context.clone());

            let mut tx2_a = open_tx(&mux2, 10);
            let mut tx2_b = open_tx(&mux2, 20);

            let payload_a = Bytes::from_static(b"A");
            let payload_b = Bytes::from_static(b"B");
            let _ = tx2_a
                .send(Recipients::One(pk1.clone()), payload_a.clone(), false)
                .await
                .unwrap();
            let _ = tx2_b
                .send(Recipients::One(pk1.clone()), payload_b.clone(), false)
                .await
                .unwrap();

            let (from_a, bytes_a) = rx_a.recv().await.unwrap();
            assert_eq!(from_a, pk2);
            assert_eq!(bytes_a, payload_a);

            let (from_b, bytes_b) = rx_b.recv().await.unwrap();
            assert_eq!(from_b, pk2);
            assert_eq!(bytes_b, payload_b);
        });
    }

    #[test_traced]
    fn test_mailbox_capacity_blocks() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut oracle = start_network(context.clone());

            let (pk1, mux1) = create_peer(&mut oracle, 0).await;
            let (pk2, mux2) = create_peer(&mut oracle, 1).await;
            link_bidirectional(&mut oracle, pk1.clone(), pk2.clone()).await;

            // Register the subchannels.
            let tx1 = open_tx(&mux1, 99);
            let tx2 = open_tx(&mux1, 100);
            let mut rx1 = open_rx(&mux2, 99);
            let mut rx2 = open_rx(&mux2, 100);

            // Send 10 messages to each subchannel from pk1 to pk2.
            send_burst(&mut [tx1, tx2], CAPACITY * 2).await;

            // Give the demuxers a moment to process messages.
            mux1.start(context.clone());
            mux2.start(context.clone());
            context.sleep(Duration::from_millis(100)).await;

            // Try receiving all messages from the second subchannel.
            expect_n_messages(&mut rx2, CAPACITY, &context).await;

            // Try receiving from the first subchannel.
            expect_n_messages(&mut rx1, CAPACITY * 2, &context).await;

            // The second subchannel should be unblocked and receive the rest of the messages.
            expect_n_messages(&mut rx2, CAPACITY, &context).await;
        });
    }

    #[test]
    fn test_drop_a_full_subchannel() {
        // Drops the subchannel receiver while the sender is blocked.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut oracle = start_network(context.clone());

            let (pk1, mux1) = create_peer(&mut oracle, 0).await;
            let (pk2, mux2) = create_peer(&mut oracle, 1).await;
            link_bidirectional(&mut oracle, pk1.clone(), pk2.clone()).await;

            // Register the subchannels.
            let tx1 = open_tx(&mux1, 99);
            let tx2 = open_tx(&mux1, 100);
            let rx1 = open_rx(&mux2, 99);
            let mut rx2 = open_rx(&mux2, 100);

            // Send 10 messages to each subchannel from pk1 to pk2.
            send_burst(&mut [tx1, tx2], CAPACITY * 2).await;

            // Give the demuxers a moment to process messages.
            mux1.start(context.clone());
            mux2.start(context.clone());
            context.sleep(Duration::from_millis(100)).await;

            // Try receiving all messages from the second subchannel.
            expect_n_messages(&mut rx2, CAPACITY, &context).await;

            // Drop the first subchannel, erroring the sender and dropping it.
            drop(rx1);

            // The second subchannel should be unblocked and receive the rest of the messages.
            expect_n_messages(&mut rx2, CAPACITY, &context).await;
        });
    }

    #[test]
    fn test_drop_messages_for_unregistered_subchannel() {
        // Messages are dropped if the subchannel they are for is not registered.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut oracle = start_network(context.clone());

            let (pk1, mux1) = create_peer(&mut oracle, 0).await;
            let (pk2, mux2) = create_peer(&mut oracle, 1).await;
            link_bidirectional(&mut oracle, pk1.clone(), pk2.clone()).await;

            // Register the subchannels.
            let tx1 = open_tx(&mux1, 1);
            let tx2 = open_tx(&mux1, 2);
            // Do not register the first subchannel on the second peer.
            let mut rx2 = open_rx(&mux2, 2);

            // Send 10 messages to each subchannel from pk1 to pk2.
            send_burst(&mut [tx1, tx2], CAPACITY * 2).await;

            // Give the demuxers a moment to process messages.
            mux1.start(context.clone());
            mux2.start(context.clone());
            context.sleep(Duration::from_millis(100)).await;

            // Try receiving all messages from the second subchannel.
            expect_n_messages(&mut rx2, CAPACITY * 2, &context).await;
        });
    }

    #[test]
    #[should_panic(expected = "duplicate subchannel registration: 7")]
    fn test_duplicate_registration() {
        // Panics if the subchannel is already registered.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut oracle = start_network(context.clone());

            let (_pk1, mux1) = create_peer(&mut oracle, 0).await;
            let _rx1 = open_rx(&mux1, 7);
            let _rx2 = open_rx(&mux1, 7); // panics
        });
    }
}
