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
use commonware_codec::{varint::UInt, EncodeSize, Error as CodecError, ReadExt, Write};
use commonware_macros::select_loop;
use commonware_runtime::{spawn_cell, ContextCell, Handle, Spawner};
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

/// Parse a muxed message into its subchannel and payload.
pub fn parse(mut bytes: Bytes) -> Result<(Channel, Bytes), CodecError> {
    let subchannel: Channel = UInt::read(&mut bytes)?.into();
    Ok((subchannel, bytes))
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

/// A backup channel response, with a [SubSender] to respond, the [Channel] that wasn't registered,
/// and the [Message] received.
type BackupResponse<P> = (Channel, Message<P>);

/// A multiplexer of p2p channels into subchannels.
pub struct Muxer<E: Spawner, S: Sender, R: Receiver> {
    context: ContextCell<E>,
    sender: S,
    receiver: R,
    mailbox_size: usize,
    control_rx: mpsc::UnboundedReceiver<Control<R>>,
    routes: Routes<R::PublicKey>,
    backup: Option<mpsc::Sender<BackupResponse<R::PublicKey>>>,
}

impl<E: Spawner, S: Sender, R: Receiver> Muxer<E, S, R> {
    /// Create a multiplexed wrapper around a [Sender] and [Receiver] pair, and return a ([Muxer],
    /// [MuxHandle]) pair that can be used to register routes dynamically.
    pub fn new(context: E, sender: S, receiver: R, mailbox_size: usize) -> (Self, MuxHandle<S, R>) {
        Self::builder(context, sender, receiver, mailbox_size).build()
    }

    /// Creates a [MuxerBuilder] that can be used to configure and build a [Muxer].
    pub fn builder(
        context: E,
        sender: S,
        receiver: R,
        mailbox_size: usize,
    ) -> MuxerBuilder<E, S, R> {
        let (control_tx, control_rx) = mpsc::unbounded();
        let mux = Self {
            context: ContextCell::new(context),
            sender,
            receiver,
            mailbox_size,
            control_rx,
            routes: HashMap::new(),
            backup: None,
        };

        let mux_handle = MuxHandle {
            sender: mux.sender.clone(),
            control_tx,
        };

        MuxerBuilder { mux, mux_handle }
    }

    /// Start the demuxer using the given spawner.
    pub fn start(mut self) -> Handle<Result<(), R::Error>> {
        spawn_cell!(self.context, self.run().await)
    }

    /// Drive demultiplexing of messages into per-subchannel receivers.
    ///
    /// Callers should run this in a background task for as long as the underlying `Receiver` is
    /// expected to receive traffic.
    pub async fn run(mut self) -> Result<(), R::Error> {
        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping muxer");
            },
            // Prefer control messages because network messages will
            // already block when full (providing backpressure).
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
            // Process network messages.
            message = self.receiver.recv() => {
                // Decode the message.
                let (pk, bytes) = message?;
                let (subchannel, bytes) = match parse(bytes) {
                    Ok(parsed) => parsed,
                    Err(_) => {
                        debug!(?pk, "invalid message: missing subchannel");
                        continue;
                    }
                };

                // Get the route for the subchannel.
                let Some(sender) = self.routes.get_mut(&subchannel) else {
                    // Attempt to use the backup channel if available.
                    if let Some(backup) = &mut self.backup {
                        if let Err(e) = backup.send((subchannel, (pk, bytes))).await {
                            debug!(?subchannel, ?e, "failed to send message to backup channel");
                        }
                    }

                    // Drops the message if the subchannel is not found or the backup
                    // channel was not used.
                    continue;
                };

                // Send the message to the subchannel, blocking if the queue is full.
                if let Err(e) = sender.send((pk, bytes)).await {
                    // Remove the route for the subchannel.
                    self.routes.remove(&subchannel);

                    // Failure, drop the sender since the receiver is no longer interested.
                    debug!(?subchannel, ?e, "failed to send message to subchannel");

                    // NOTE: The channel is deregistered, but it wasn't when the message was received.
                    // The backup channel is not used in this case.
                }
            }
        }

        Ok(())
    }
}

/// A clonable handle that allows registering routes at any time, even after the [Muxer] is running.
#[derive(Clone)]
pub struct MuxHandle<S: Sender, R: Receiver> {
    sender: S,
    control_tx: mpsc::UnboundedSender<Control<R>>,
}

impl<S: Sender, R: Receiver> MuxHandle<S, R> {
    /// Open a `subchannel`. Returns a ([SubSender], [SubReceiver]) pair that can be used to send
    /// and receive messages for that subchannel.
    ///
    /// Panics if the subchannel is already registered at any point.
    pub async fn register(
        &mut self,
        subchannel: Channel,
    ) -> Result<(SubSender<S>, SubReceiver<R>), Error> {
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
                inner: GlobalSender::new(self.sender.clone()),
            },
            SubReceiver {
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
    inner: GlobalSender<S>,
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
        self.inner
            .send(self.subchannel, recipients, payload, priority)
            .await
    }
}

/// Receiver that yields messages for a specific subchannel.
pub struct SubReceiver<R: Receiver> {
    receiver: mpsc::Receiver<Message<R::PublicKey>>,
    control_tx: Option<mpsc::UnboundedSender<Control<R>>>,
    subchannel: Channel,
}

impl<R: Receiver> Receiver for SubReceiver<R> {
    type Error = Error;
    type PublicKey = R::PublicKey;

    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
        self.receiver.next().await.ok_or(Error::RecvFailed)
    }
}

impl<R: Receiver> Debug for SubReceiver<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SubReceiver({})", self.subchannel)
    }
}

impl<R: Receiver> Drop for SubReceiver<R> {
    fn drop(&mut self) {
        // Take the control channel to avoid cloning.
        let control_tx = self
            .control_tx
            .take()
            .expect("SubReceiver::drop called twice");

        // Deregister the subchannel immediately.
        let _ = control_tx.unbounded_send(Control::Deregister {
            subchannel: self.subchannel,
        });
    }
}

/// Sender that can send messages over any sub [Channel].
#[derive(Clone, Debug)]
pub struct GlobalSender<S: Sender> {
    inner: S,
}

impl<S: Sender> GlobalSender<S> {
    /// Create a new [GlobalSender] wrapping the given [Sender].
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }

    /// Send a message over the given `subchannel`.
    pub async fn send(
        &mut self,
        subchannel: Channel,
        recipients: Recipients<S::PublicKey>,
        payload: Bytes,
        priority: bool,
    ) -> Result<Vec<S::PublicKey>, S::Error> {
        let subchannel = UInt(subchannel);
        let mut buf = BytesMut::with_capacity(subchannel.encode_size() + payload.len());
        subchannel.write(&mut buf);
        buf.put_slice(&payload);
        self.inner.send(recipients, buf.freeze(), priority).await
    }
}

/// A generic builder interface.
pub trait Builder {
    /// The output type produced by the builder.
    type Output;

    /// Builds the output type, consuming `self`.
    fn build(self) -> Self::Output;
}

/// A builder that constructs a [Muxer].
pub struct MuxerBuilder<E: Spawner, S: Sender, R: Receiver> {
    mux: Muxer<E, S, R>,
    mux_handle: MuxHandle<S, R>,
}

impl<E: Spawner, S: Sender, R: Receiver> Builder for MuxerBuilder<E, S, R> {
    type Output = (Muxer<E, S, R>, MuxHandle<S, R>);

    fn build(self) -> Self::Output {
        (self.mux, self.mux_handle)
    }
}

impl<E: Spawner, S: Sender, R: Receiver> MuxerBuilder<E, S, R> {
    /// Registers a backup channel with the muxer.
    pub fn with_backup(mut self) -> MuxerBuilderWithBackup<E, S, R> {
        let (tx, rx) = mpsc::channel(self.mux.mailbox_size);
        self.mux.backup = Some(tx);

        MuxerBuilderWithBackup {
            mux: self.mux,
            mux_handle: self.mux_handle,
            backup_rx: rx,
        }
    }

    /// Registers a global sender with the muxer.
    pub fn with_global_sender(self) -> MuxerBuilderWithGlobalSender<E, S, R> {
        let global_sender = GlobalSender::new(self.mux.sender.clone());

        MuxerBuilderWithGlobalSender {
            mux: self.mux,
            mux_handle: self.mux_handle,
            global_sender,
        }
    }
}

/// A builder that constructs a [Muxer] with a backup channel.
pub struct MuxerBuilderWithBackup<E: Spawner, S: Sender, R: Receiver> {
    mux: Muxer<E, S, R>,
    mux_handle: MuxHandle<S, R>,
    backup_rx: mpsc::Receiver<BackupResponse<R::PublicKey>>,
}

impl<E: Spawner, S: Sender, R: Receiver> MuxerBuilderWithBackup<E, S, R> {
    /// Registers a global sender with the muxer.
    pub fn with_global_sender(self) -> MuxerBuilderAllOpts<E, S, R> {
        let global_sender = GlobalSender::new(self.mux.sender.clone());

        MuxerBuilderAllOpts {
            mux: self.mux,
            mux_handle: self.mux_handle,
            backup_rx: self.backup_rx,
            global_sender,
        }
    }
}

impl<E: Spawner, S: Sender, R: Receiver> Builder for MuxerBuilderWithBackup<E, S, R> {
    type Output = (
        Muxer<E, S, R>,
        MuxHandle<S, R>,
        mpsc::Receiver<BackupResponse<R::PublicKey>>,
    );

    fn build(self) -> Self::Output {
        (self.mux, self.mux_handle, self.backup_rx)
    }
}

/// A builder that constructs a [Muxer] with a [GlobalSender].
pub struct MuxerBuilderWithGlobalSender<E: Spawner, S: Sender, R: Receiver> {
    mux: Muxer<E, S, R>,
    mux_handle: MuxHandle<S, R>,
    global_sender: GlobalSender<S>,
}

impl<E: Spawner, S: Sender, R: Receiver> MuxerBuilderWithGlobalSender<E, S, R> {
    /// Registers a backup channel with the muxer.
    pub fn with_backup(mut self) -> MuxerBuilderAllOpts<E, S, R> {
        let (tx, rx) = mpsc::channel(self.mux.mailbox_size);
        self.mux.backup = Some(tx);

        MuxerBuilderAllOpts {
            mux: self.mux,
            mux_handle: self.mux_handle,
            backup_rx: rx,
            global_sender: self.global_sender,
        }
    }
}

impl<E: Spawner, S: Sender, R: Receiver> Builder for MuxerBuilderWithGlobalSender<E, S, R> {
    type Output = (Muxer<E, S, R>, MuxHandle<S, R>, GlobalSender<S>);

    fn build(self) -> Self::Output {
        (self.mux, self.mux_handle, self.global_sender)
    }
}

/// A builder that constructs a [Muxer] with a [GlobalSender] and backup channel.
pub struct MuxerBuilderAllOpts<E: Spawner, S: Sender, R: Receiver> {
    mux: Muxer<E, S, R>,
    mux_handle: MuxHandle<S, R>,
    backup_rx: mpsc::Receiver<BackupResponse<R::PublicKey>>,
    global_sender: GlobalSender<S>,
}

impl<E: Spawner, S: Sender, R: Receiver> Builder for MuxerBuilderAllOpts<E, S, R> {
    type Output = (
        Muxer<E, S, R>,
        MuxHandle<S, R>,
        mpsc::Receiver<BackupResponse<R::PublicKey>>,
        GlobalSender<S>,
    );

    fn build(self) -> Self::Output {
        (
            self.mux,
            self.mux_handle,
            self.backup_rx,
            self.global_sender,
        )
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
    use commonware_cryptography::{ed25519::PrivateKey, Signer};
    use commonware_macros::{select, test_traced};
    use commonware_runtime::{deterministic, Metrics, Quota, Runner};
    use std::{num::NonZeroU32, time::Duration};

    type Pk = commonware_cryptography::ed25519::PublicKey;

    const LINK: Link = Link {
        latency: Duration::from_millis(0),
        jitter: Duration::from_millis(0),
        success_rate: 1.0,
    };
    const CAPACITY: usize = 5usize;

    /// Default rate limit set high enough to not interfere with normal operation
    const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

    /// Start the network and return the oracle.
    fn start_network(context: deterministic::Context) -> Oracle<Pk, deterministic::Context> {
        let (network, oracle) = Network::new(
            context.with_label("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: None,
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
    async fn link_bidirectional(oracle: &mut Oracle<Pk, deterministic::Context>, a: Pk, b: Pk) {
        oracle.add_link(a.clone(), b.clone(), LINK).await.unwrap();
        oracle.add_link(b, a, LINK).await.unwrap();
    }

    /// Create a peer and register it with the oracle.
    async fn create_peer(
        context: &deterministic::Context,
        oracle: &mut Oracle<Pk, deterministic::Context>,
        seed: u64,
    ) -> (
        Pk,
        MuxHandle<impl Sender<PublicKey = Pk>, impl Receiver<PublicKey = Pk>>,
    ) {
        let pubkey = pk(seed);
        let (sender, receiver) = oracle
            .control(pubkey.clone())
            .register(0, TEST_QUOTA)
            .await
            .unwrap();
        let (mux, handle) = Muxer::new(context.with_label("mux"), sender, receiver, CAPACITY);
        mux.start();
        (pubkey, handle)
    }

    /// Create a peer and register it with the oracle.
    async fn create_peer_with_backup_and_global_sender(
        context: &deterministic::Context,
        oracle: &mut Oracle<Pk, deterministic::Context>,
        seed: u64,
    ) -> (
        Pk,
        MuxHandle<impl Sender<PublicKey = Pk>, impl Receiver<PublicKey = Pk>>,
        mpsc::Receiver<BackupResponse<Pk>>,
        GlobalSender<simulated::Sender<Pk, deterministic::Context>>,
    ) {
        let pubkey = pk(seed);
        let (sender, receiver) = oracle
            .control(pubkey.clone())
            .register(0, TEST_QUOTA)
            .await
            .unwrap();
        let (mux, handle, backup, global_sender) =
            Muxer::builder(context.with_label("mux"), sender, receiver, CAPACITY)
                .with_backup()
                .with_global_sender()
                .build();
        mux.start();
        (pubkey, handle, backup, global_sender)
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
    async fn expect_n_messages(rx: &mut SubReceiver<impl Receiver<PublicKey = Pk>>, n: usize) {
        let mut count = 0;
        loop {
            select! {
                res = rx.recv() => {
                    res.expect("should have received message");
                    count += 1;
                },
            }

            if count >= n {
                break;
            }
        }
        assert_eq!(n, count);
    }

    /// Wait for `n` messages to be received on the receiver + backup receiver.
    async fn expect_n_messages_with_backup(
        rx: &mut SubReceiver<impl Receiver<PublicKey = Pk>>,
        backup_rx: &mut mpsc::Receiver<BackupResponse<Pk>>,
        n: usize,
        n_backup: usize,
    ) {
        let mut count_std = 0;
        let mut count_backup = 0;
        loop {
            select! {
                res = rx.recv() => {
                    res.expect("should have received message");
                    count_std += 1;
                },
                res = backup_rx.next() => {
                    res.expect("should have received message");
                    count_backup += 1;
                },
            }

            if count_std >= n && count_backup >= n_backup {
                break;
            }
        }
        assert_eq!(n, count_std);
        assert_eq!(n_backup, count_backup);
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
            expect_n_messages(&mut rx2, CAPACITY).await;

            // Try receiving from the first subchannel.
            expect_n_messages(&mut rx1, CAPACITY * 2).await;

            // The second subchannel should be unblocked and receive the rest of the messages.
            expect_n_messages(&mut rx2, CAPACITY).await;
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

            // Try receiving all messages from the second subchannel.
            expect_n_messages(&mut rx2, CAPACITY).await;

            // Drop the first subchannel, erroring the sender and dropping it.
            drop(rx1);

            // The second subchannel should be unblocked and receive the rest of the messages.
            expect_n_messages(&mut rx2, CAPACITY).await;
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

            // Try receiving all messages from the second subchannel.
            expect_n_messages(&mut rx2, CAPACITY * 2).await;
        });
    }

    #[test]
    fn test_backup_for_unregistered_subchannel() {
        // Messages are forwarded to the backup channel if the subchannel they are for
        // is not registered.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut oracle = start_network(context.clone());

            let (pk1, mut handle1) = create_peer(&context, &mut oracle, 0).await;
            let (pk2, mut handle2, mut backup2, _) =
                create_peer_with_backup_and_global_sender(&context, &mut oracle, 1).await;
            link_bidirectional(&mut oracle, pk1.clone(), pk2.clone()).await;

            // Register the subchannels.
            let (tx1, _) = handle1.register(1).await.unwrap();
            let (tx2, _) = handle1.register(2).await.unwrap();
            // Do not register the first subchannel on the second peer.
            let (_, mut rx2) = handle2.register(2).await.unwrap();

            // Send 10 messages to each subchannel from pk1 to pk2.
            send_burst(&mut [tx1, tx2], CAPACITY * 2).await;

            // Try receiving all messages from the second subchannel and backup channel.
            // All 20 messages sent should be received.
            expect_n_messages_with_backup(&mut rx2, &mut backup2, CAPACITY * 2, CAPACITY * 2).await;
        });
    }

    #[test]
    fn test_backup_for_unregistered_subchannel_response() {
        // Messages are forwarded to the backup channel if the subchannel they are for
        // is not registered.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut oracle = start_network(context.clone());

            let (pk1, mut handle1) = create_peer(&context, &mut oracle, 0).await;
            let (pk2, _handle2, mut backup2, mut global_sender2) =
                create_peer_with_backup_and_global_sender(&context, &mut oracle, 1).await;
            link_bidirectional(&mut oracle, pk1.clone(), pk2.clone()).await;

            // Register the subchannels.
            let (tx1, mut rx1) = handle1.register(1).await.unwrap();
            // Do not register any subchannels on the second peer.

            // Send 1 message to each subchannel from pk1 to pk2.
            send_burst(&mut [tx1], 1).await;

            // Get the message from pk2's backup channel and respond.
            let (subchannel, (from, _)) = backup2.next().await.unwrap();
            assert_eq!(subchannel, 1);
            assert_eq!(from, pk1);
            global_sender2
                .send(
                    subchannel,
                    Recipients::One(pk1),
                    b"TEST".to_vec().into(),
                    true,
                )
                .await
                .unwrap();

            // Receive the response with pk1's receiver.
            let (from, bytes) = rx1.recv().await.unwrap();
            assert_eq!(from, pk2);
            assert_eq!(bytes.as_ref(), b"TEST");
        });
    }

    #[test]
    fn test_message_dropped_for_closed_subchannel() {
        // Messages are dropped if the subchannel they are for is registered, but has been closed.
        //
        // NOTE: This case should be exceedingly rare in practice due to `SubReceiver` deregistering
        // the subchannel on drop, but is included for completeness.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut oracle = start_network(context.clone());

            let (pk1, mut handle1) = create_peer(&context, &mut oracle, 0).await;
            let (pk2, mut handle2) = create_peer(&context, &mut oracle, 1).await;
            link_bidirectional(&mut oracle, pk1.clone(), pk2.clone()).await;

            // Register the subchannels.
            let (tx1, _) = handle1.register(1).await.unwrap();
            let (tx2, _) = handle1.register(2).await.unwrap();
            let (_, mut rx1) = handle2.register(1).await.unwrap();
            let (_, mut rx2) = handle2.register(2).await.unwrap();

            // Send 10 messages to subchannel 1 from pk1 to pk2.
            send_burst(&mut [tx1.clone()], CAPACITY * 2).await;

            // Try receiving all messages from the first subchannel.
            expect_n_messages(&mut rx1, CAPACITY * 2).await;

            // Send 10 messages to subchannel 2 from pk1 to pk2.
            send_burst(&mut [tx2.clone()], CAPACITY * 2).await;

            // Try receiving all messages from the first subchannel.
            expect_n_messages(&mut rx2, CAPACITY * 2).await;

            // Explicitly close the underlying receiver for the first subchannel.
            rx1.receiver.close();

            // Send 10 messages to each subchannel from pk1 to pk2.
            send_burst(&mut [tx1, tx2], CAPACITY * 2).await;

            // Try receiving all messages from the second subchannel.
            expect_n_messages(&mut rx2, CAPACITY * 2).await;
        });
    }

    #[test]
    fn test_dropped_backup_channel_doesnt_block() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut oracle = start_network(context.clone());

            let (pk1, mut handle1) = create_peer(&context, &mut oracle, 0).await;
            let (pk2, mut handle2, backup2, _) =
                create_peer_with_backup_and_global_sender(&context, &mut oracle, 1).await;
            link_bidirectional(&mut oracle, pk1.clone(), pk2.clone()).await;

            // Explicitly drop the backup receiver.
            drop(backup2);

            // Register the subchannels.
            let (tx1, _) = handle1.register(1).await.unwrap();
            let (tx2, _) = handle1.register(2).await.unwrap();
            // Do not register the first subchannel on the second peer.
            let (_, mut rx2) = handle2.register(2).await.unwrap();

            // Send 10 messages to each subchannel from pk1 to pk2.
            send_burst(&mut [tx1, tx2], CAPACITY * 2).await;

            // Try receiving all messages from the second subchannel.
            expect_n_messages(&mut rx2, CAPACITY * 2).await;
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
