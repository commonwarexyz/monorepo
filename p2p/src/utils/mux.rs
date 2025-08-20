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
        if self.routes.lock().unwrap().insert(subchannel, tx).is_some() {
            panic!("duplicate subchannel registration: {subchannel}");
        }

        // Return the subchannel sender and receiver.
        (
            SubSender {
                subchannel,
                inner: self.sender.clone(),
            },
            SubReceiver { receiver: rx },
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
                    debug!(?pk, "no subchannel");
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
}

impl<P: PublicKey> Receiver for SubReceiver<P> {
    type Error = Error;
    type PublicKey = P;

    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
        self.receiver.next().await.ok_or(Error::RecvFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simulated::{Config as SimConfig, Link, Network},
        Recipients,
    };
    use bytes::Bytes;
    use commonware_cryptography::{ed25519::PrivateKey, PrivateKeyExt, Signer};
    use commonware_macros::{select, test_traced};
    use commonware_runtime::{deterministic, Clock, Metrics, Runner, Spawner};
    use std::time::Duration;

    const LINK: Link = Link {
        latency: 0.0,
        jitter: 0.0,
        success_rate: 1.0,
    };

    #[test]
    fn test_basic_routing() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create simulated network with two peers
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                SimConfig {
                    max_size: 1024 * 1024,
                },
            );
            network.start();

            let pk1 = PrivateKey::from_seed(0).public_key();
            let pk2 = PrivateKey::from_seed(1).public_key();
            let (sender1, receiver1) = oracle.register(pk1.clone(), 0).await.unwrap();
            let (sender2, receiver2) = oracle.register(pk2.clone(), 0).await.unwrap();

            // Fully link peers
            oracle
                .add_link(pk1.clone(), pk2.clone(), LINK)
                .await
                .unwrap();
            oracle
                .add_link(pk2.clone(), pk1.clone(), LINK)
                .await
                .unwrap();

            // Start demuxer on peer1
            let mux1 = Muxer::new(sender1, receiver1, 16);
            let (_sub_tx1, mut sub_rx1) = mux1.register(7);
            context.spawn(|_| async move {
                let _ = mux1.run().await;
            });

            // Create a sender for the same stream on peer2
            let mux2 = Muxer::new(sender2, receiver2, 16);
            let (mut sub_tx2, _sub_rx2) = mux2.register(7);

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
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                SimConfig {
                    max_size: 1024 * 1024,
                },
            );
            network.start();

            let pk1 = PrivateKey::from_seed(0).public_key();
            let pk2 = PrivateKey::from_seed(1).public_key();
            let (sender1, receiver1) = oracle.register(pk1.clone(), 0).await.unwrap();
            let (sender2, receiver2) = oracle.register(pk2.clone(), 0).await.unwrap();

            oracle
                .add_link(pk1.clone(), pk2.clone(), LINK)
                .await
                .unwrap();
            oracle
                .add_link(pk2.clone(), pk1.clone(), LINK)
                .await
                .unwrap();

            let mux1 = Muxer::new(sender1, receiver1, 16);
            let (_rx_a_tx, mut rx_a) = mux1.register(10);
            let (_rx_b_tx, mut rx_b) = mux1.register(20);
            context.clone().spawn(|_| async move {
                let _ = mux1.run().await;
            });

            let mux2 = Muxer::new(sender2, receiver2, 16);
            let (mut tx2_a, _rx2_a) = mux2.register(10);
            let (mut tx2_b, _rx2_b) = mux2.register(20);

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
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                SimConfig {
                    max_size: 1024 * 1024,
                },
            );
            network.start();

            // Test parameters.
            const CAPACITY: usize = 5usize;
            const TOTAL: usize = 10usize;

            // Create the peer who sends messages.
            let pk1 = PrivateKey::from_seed(0).public_key();
            let (og_tx1, og_rx1) = oracle.register(pk1.clone(), 0).await.unwrap();
            let mux1 = Muxer::new(og_tx1, og_rx1, CAPACITY);

            // Create the peer who receives messages.
            let pk2 = PrivateKey::from_seed(1).public_key();
            let (og_tx2, og_rx2) = oracle.register(pk2.clone(), 0).await.unwrap();
            let mux2 = Muxer::new(og_tx2, og_rx2, CAPACITY);

            oracle
                .add_link(pk1.clone(), pk2.clone(), LINK)
                .await
                .unwrap();
            oracle
                .add_link(pk2.clone(), pk1.clone(), LINK)
                .await
                .unwrap();

            // Register the subchannels.
            let (mut tx1, _rx1) = mux1.register(99);
            let (mut tx2, _rx2) = mux1.register(100);
            let (_tx1, mut rx1) = mux2.register(99);
            let (_tx2, mut rx2) = mux2.register(100);

            // Send 10 messages to each subchannel from pk1 to pk2.
            for i in 0..TOTAL {
                let payload = Bytes::from(vec![i as u8]);
                let _ = tx1
                    .send(Recipients::All, payload.clone(), false)
                    .await
                    .unwrap();
                let _ = tx2.send(Recipients::All, payload, false).await.unwrap();
            }

            // Give the demuxers a moment to process messages.
            mux1.start(context.clone());
            mux2.start(context.clone());
            context.sleep(Duration::from_millis(100)).await;

            // Count the number of messages received from each subchannel.
            let mut count1 = 0usize;
            let mut count2 = 0usize;

            // Try receiving all messages from the second subchannel.
            loop {
                select! {
                    res = rx2.recv() => {
                        match res {
                            Ok(_) => count2 += 1,
                            Err(_) => break,
                        }
                    },
                    _ = context.sleep(Duration::from_millis(100)) => { break; },
                }
            }

            // It should have received the buffered messages, but the sender is blocked.
            assert_eq!(count2, CAPACITY);

            // Try receiving from the first subchannel.
            loop {
                select! {
                    res = rx1.recv() => {
                        match res {
                            Ok(_) => count1 += 1,
                            Err(_) => break,
                        }
                    },
                    _ = context.sleep(Duration::from_millis(100)) => { break; },
                }
            }

            // It should have received all buffered messages, been unblocked, and received the
            // next messages.
            assert_eq!(count1, CAPACITY * 2);

            // The second subchannel should be unblocked.
            loop {
                select! {
                    res = rx2.recv() => {
                        match res {
                            Ok(_) => count2 += 1,
                            Err(_) => break,
                        }
                    },
                    _ = context.sleep(Duration::from_millis(100)) => { break; },
                }
            }

            // It should have received all messages.
            assert_eq!(count2, TOTAL);
        });
    }
}
