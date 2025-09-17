//! This utility wraps a [Sender] and [Receiver], providing lightweight sub-channels keyed by
//! [Channel].
//!
//! Usage:
//! - Call [Muxer::new] to obtain a ([Muxer], [MuxHandle]) pair.
//! - Call [Muxer::start] or run [Muxer::run] in a background task to demux incoming messages into
//!   per-subchannel queues.
//! - Call [MuxHandle::register] to obtain a ([SubSender], [SubReceiver]) pair for that subchannel,
//!   even if the muxer is already running.

use crate::{Channel, Message, Receiver, Recipients, Sender};
use bytes::{BufMut, Bytes, BytesMut};
use commonware_codec::{varint::UInt, EncodeSize, ReadExt, Write};
use commonware_macros::select;
use commonware_runtime::{Handle, Spawner};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use std::{collections::HashMap, fmt::Debug};
use thiserror::Error;
use tracing::debug;

/// Errors that can occur when interacting with a [SubReceiver] or [MuxHandle].
#[derive(Error, Debug)]
pub enum Error {
    #[error("subchannel already registered: {0}")]
    AlreadyRegistered(Channel),
    #[error("muxer is closed")]
    Closed,
    #[error("recv failed")]
    RecvFailed,
}

/// Control messages for the [Muxer].
enum Control<R: Receiver> {
    Register {
        subchannel: Channel,
        sender: oneshot::Sender<mpsc::Receiver<Message<R::PublicKey>>>,
    },
    Deregister {
        subchannel: Channel,
    },
}

/// Thread-safe routing table mapping each [Channel] to the [mpsc::Sender] for [`Message<P>`].
type Routes<P> = HashMap<Channel, mpsc::Sender<Message<P>>>;

/// A multiplexer of p2p channels into subchannels.
pub struct Muxer<E: Spawner, S: Sender, R: Receiver> {
    context: E,
    sender: S,
    receiver: R,
    mailbox_size: usize,
    control_rx: mpsc::Receiver<Control<R>>,
    routes: Routes<R::PublicKey>,
}

impl<E: Spawner, S: Sender, R: Receiver> Muxer<E, S, R> {
    /// Create a multiplexed wrapper around a [Sender] and [Receiver] pair, and return a ([Muxer],
    /// [MuxHandle]) pair that can be used to register routes dynamically.
    pub fn new(
        context: E,
        sender: S,
        receiver: R,
        mailbox_size: usize,
    ) -> (Self, MuxHandle<E, S, R>) {
        let (control_tx, control_rx) = mpsc::channel(mailbox_size);
        let mux = Self {
            context: context.clone(),
            sender,
            receiver,
            mailbox_size,
            control_rx,
            routes: HashMap::new(),
        };

        let handle = MuxHandle {
            context,
            sender: mux.sender.clone(),
            control_tx,
        };

        (mux, handle)
    }

    /// Start the demuxer using the given spawner.
    pub fn start(mut self) -> Handle<Result<(), R::Error>> {
        self.context.spawn_ref()(self.run())
    }

    /// Drive demultiplexing of messages into per-subchannel receivers.
    ///
    /// Callers should run this in a background task for as long as the underlying `Receiver` is
    /// expected to receive traffic.
    pub async fn run(mut self) -> Result<(), R::Error> {
        loop {
            select! {
                // Control messages (registration/deregistration)
                control = self.control_rx.next() => {
                    match control {
                        Some(Control::Register { subchannel, sender }) => {
                            // If the subchannel is already registered, drop the sender.
                            if self.routes.contains_key(&subchannel) {
                                continue;
                            }

                            // Otherwise, create a new subchannel and send the receiver to the caller.
                            let (tx, rx) = mpsc::channel(self.mailbox_size);
                            self.routes.insert(subchannel, tx);
                            let _ = sender.send(rx);
                        },
                        Some(Control::Deregister { subchannel }) => {
                            // Remove the route.
                            self.routes.remove(&subchannel);
                        },
                        None => {
                            // If the control channel is closed, we can shut down since there must
                            // be no more registrations, and all receivers must have been dropped.
                            return Ok(());
                        }
                    }
                },
                // Network messages
                message = self.receiver.recv() => {
                    let (pk, mut bytes) = message?;

                    // Decode message: varint(subchannel) || bytes
                    let subchannel: Channel = match UInt::read(&mut bytes) {
                        Ok(v) => v.into(),
                        Err(_) => {
                            debug!(?pk, "invalid message: missing subchannel");
                            continue;
                        }
                    };

                    // Get the route for the subchannel.
                    let Some(sender) = self.routes.get_mut(&subchannel) else {
                        // Drops the message if the subchannel is not found
                        continue;
                    };

                    // Send the message to the subchannel, blocking if the queue is full.
                    if let Err(e) = sender.send((pk, bytes)).await {
                        // Remove the route for the subchannel.
                        self.routes.remove(&subchannel);

                        // Failure, drop the sender since the receiver is no longer interested.
                        debug!(?subchannel, ?e, "failed to send message to subchannel");
                    }
                }
            }
        }
    }
}

/// A clonable handle that allows registering routes at any time, even after the [Muxer] is running.
#[derive(Clone)]
pub struct MuxHandle<E: Spawner, S: Sender, R: Receiver> {
    context: E,
    sender: S,
    control_tx: mpsc::Sender<Control<R>>,
}

impl<E: Spawner, S: Sender, R: Receiver> MuxHandle<E, S, R> {
    /// Open a `subchannel`. Returns a ([SubSender], [SubReceiver]) pair that can be used to send
    /// and receive messages for that subchannel.
    ///
    /// Panics if the subchannel is already registered at any point.
    pub async fn register(
        &mut self,
        subchannel: Channel,
    ) -> Result<(SubSender<S>, SubReceiver<E, R>), Error> {
        let (tx, rx) = oneshot::channel();
        self.control_tx
            .send(Control::Register {
                subchannel,
                sender: tx,
            })
            .await
            .map_err(|_| Error::Closed)?;
        let receiver = rx.await.map_err(|_| Error::AlreadyRegistered(subchannel))?;

        Ok((
            SubSender {
                subchannel,
                inner: self.sender.clone(),
            },
            SubReceiver {
                context: self.context.clone(),
                receiver,
                control_tx: Some(self.control_tx.clone()),
                subchannel,
            },
        ))
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
pub struct SubReceiver<E: Spawner, R: Receiver> {
    context: E,
    receiver: mpsc::Receiver<Message<R::PublicKey>>,
    control_tx: Option<mpsc::Sender<Control<R>>>,
    subchannel: Channel,
}

impl<E: Spawner, R: Receiver> Receiver for SubReceiver<E, R> {
    type Error = Error;
    type PublicKey = R::PublicKey;

    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
        self.receiver.next().await.ok_or(Error::RecvFailed)
    }
}

impl<E: Spawner, R: Receiver> Debug for SubReceiver<E, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SubReceiver({})", self.subchannel)
    }
}

impl<E: Spawner, R: Receiver> Drop for SubReceiver<E, R> {
    fn drop(&mut self) {
        // Take the control channel to avoid cloning.
        let mut control_tx = self
            .control_tx
            .take()
            .expect("SubReceiver::drop called twice");

        // If the control channel is not full, deregister the subchannel immediately.
        let subchannel = self.subchannel;
        if control_tx
            .try_send(Control::Deregister { subchannel })
            .is_ok()
        {
            return;
        }

        // Otherwise, spawn a task to deregister the subchannel.
        self.context.spawn_ref()(async move {
            let _ = control_tx.send(Control::Deregister { subchannel }).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simulated::{self, Link, Network, Oracle},
        Recipients,
    };
    use bytes::Bytes;
    use commonware_cryptography::{ed25519::PrivateKey, PrivateKeyExt, Signer};
    use commonware_macros::{select, test_traced};
    use commonware_runtime::{deterministic, Clock, Metrics, Runner};
    use std::time::Duration;

    type Pk = commonware_cryptography::ed25519::PublicKey;

    const LINK: Link = Link {
        latency: Duration::from_millis(0),
        jitter: Duration::from_millis(0),
        success_rate: 1.0,
    };
    const CAPACITY: usize = 5usize;

    /// Start the network and return the oracle.
    fn start_network(context: deterministic::Context) -> Oracle<Pk> {
        let (network, oracle) = Network::new(
            context.with_label("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
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
    async fn create_peer<E: Spawner>(
        context: &E,
        oracle: &mut Oracle<Pk>,
        seed: u64,
    ) -> (
        Pk,
        MuxHandle<E, impl Sender<PublicKey = Pk>, impl Receiver<PublicKey = Pk>>,
    ) {
        let pubkey = pk(seed);
        let (sender, receiver) = oracle.register(pubkey.clone(), 0).await.unwrap();
        let (mux, handle) = Muxer::new(context.clone(), sender, receiver, CAPACITY);
        mux.start();
        (pubkey, handle)
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
    async fn expect_n_messages<E: Spawner + Clock>(
        rx: &mut SubReceiver<E, impl Receiver<PublicKey = Pk>>,
        n: usize,
        context: &E,
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
        // Can register a subchannel and send messages to it.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut oracle = start_network(context.clone());

            let (pk1, mut handle1) = create_peer(&context, &mut oracle, 0).await;
            let (pk2, mut handle2) = create_peer(&context, &mut oracle, 1).await;
            link_bidirectional(&mut oracle, pk1.clone(), pk2.clone()).await;

            let (_, mut sub_rx1) = handle1.register(7).await.unwrap();
            let (mut sub_tx2, _) = handle2.register(7).await.unwrap();

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
        // Can register multiple subchannels and send messages to each.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut oracle = start_network(context.clone());

            let (pk1, mut handle1) = create_peer(&context, &mut oracle, 0).await;
            let (pk2, mut handle2) = create_peer(&context, &mut oracle, 1).await;
            link_bidirectional(&mut oracle, pk1.clone(), pk2.clone()).await;

            let (_, mut rx_a) = handle1.register(10).await.unwrap();
            let (_, mut rx_b) = handle1.register(20).await.unwrap();

            let (mut tx2_a, _) = handle2.register(10).await.unwrap();
            let (mut tx2_b, _) = handle2.register(20).await.unwrap();

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
        // If a single subchannel is full, messages are blocked for all subchannels.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut oracle = start_network(context.clone());

            let (pk1, mut handle1) = create_peer(&context, &mut oracle, 0).await;
            let (pk2, mut handle2) = create_peer(&context, &mut oracle, 1).await;
            link_bidirectional(&mut oracle, pk1.clone(), pk2.clone()).await;

            // Register the subchannels.
            let (tx1, _) = handle1.register(99).await.unwrap();
            let (tx2, _) = handle1.register(100).await.unwrap();
            let (_, mut rx1) = handle2.register(99).await.unwrap();
            let (_, mut rx2) = handle2.register(100).await.unwrap();

            // Send 10 messages to each subchannel from pk1 to pk2.
            send_burst(&mut [tx1, tx2], CAPACITY * 2).await;

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

            let (pk1, mut handle1) = create_peer(&context, &mut oracle, 0).await;
            let (pk2, mut handle2) = create_peer(&context, &mut oracle, 1).await;
            link_bidirectional(&mut oracle, pk1.clone(), pk2.clone()).await;

            // Register the subchannels.
            let (tx1, _) = handle1.register(99).await.unwrap();
            let (tx2, _) = handle1.register(100).await.unwrap();
            let (_, rx1) = handle2.register(99).await.unwrap();
            let (_, mut rx2) = handle2.register(100).await.unwrap();

            // Send 10 messages to each subchannel from pk1 to pk2.
            send_burst(&mut [tx1, tx2], CAPACITY * 2).await;

            // Give the demuxers a moment to process messages.
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

            let (pk1, mut handle1) = create_peer(&context, &mut oracle, 0).await;
            let (pk2, mut handle2) = create_peer(&context, &mut oracle, 1).await;
            link_bidirectional(&mut oracle, pk1.clone(), pk2.clone()).await;

            // Register the subchannels.
            let (tx1, _) = handle1.register(1).await.unwrap();
            let (tx2, _) = handle1.register(2).await.unwrap();
            // Do not register the first subchannel on the second peer.
            let (_, mut rx2) = handle2.register(2).await.unwrap();

            // Send 10 messages to each subchannel from pk1 to pk2.
            send_burst(&mut [tx1, tx2], CAPACITY * 2).await;

            // Give the demuxers a moment to process messages.
            context.sleep(Duration::from_millis(100)).await;

            // Try receiving all messages from the second subchannel.
            expect_n_messages(&mut rx2, CAPACITY * 2, &context).await;
        });
    }

    #[test]
    fn test_duplicate_registration() {
        // Returns an error if the subchannel is already registered.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut oracle = start_network(context.clone());

            let (_pk1, mut handle1) = create_peer(&context, &mut oracle, 0).await;

            // Register the subchannel.
            let (_, _rx) = handle1.register(7).await.unwrap();

            // Registering again should return an error.
            assert!(matches!(
                handle1.register(7).await,
                Err(Error::AlreadyRegistered(_))
            ));
        });
    }

    #[test]
    fn test_register_after_deregister() {
        // Can register a channel after it has been deregistered.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut oracle = start_network(context.clone());

            let (_, mut handle) = create_peer(&context, &mut oracle, 0).await;
            let (_, rx) = handle.register(7).await.unwrap();
            drop(rx);

            // Registering again should not return an error.
            handle.register(7).await.unwrap();
        });
    }
}
