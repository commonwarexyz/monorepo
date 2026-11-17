//! Per-connection queues, counters and rate limiters shared by the peer actors.

use super::{
    channels::{self, Channels},
    data::{Data, EncodedData},
    relay::{self, Prioritized, Receivers},
    throttle::Throttle,
};
use crate::Channel;
use commonware_actor::mailbox;
use commonware_cryptography::PublicKey;
use commonware_macros::select;
use commonware_runtime::{
    Clock, Error as RuntimeError, Handle, IoBufs, RateLimiter, Spawner, Supervisor,
    telemetry::metrics::{CounterFamily, raw::Counter},
};
use commonware_utils::channel::ring;
use std::{
    collections::BTreeMap,
    convert::Infallible,
    future::{self, Future},
    hash::Hash,
    vec::Drain,
};
use thiserror::Error;
use tracing::debug;

/// Errors that end a connection in shared peer code.
#[derive(Error, Debug)]
pub(crate) enum Error {
    #[error("peer killed")]
    Killed,
    #[error("peer disconnected")]
    Disconnected,
    #[error("invalid channel")]
    InvalidChannel,
}

/// Counter label for the messages of one connection.
pub(crate) trait Label<P>: Clone + Hash + Eq {
    /// Returns the label for data on `channel`.
    fn data(peer: &P, channel: Channel) -> Self;

    /// Returns the label for messages that fail to decode or name an unregistered channel.
    fn invalid(peer: &P) -> Self;
}

/// Control channel of one connection.
pub(crate) trait Control {
    /// Message received on the control channel.
    type Message;

    /// Awaits the next control message, returning `None` once the channel closes.
    fn recv(&mut self) -> impl Future<Output = Option<Self::Message>> + Send;

    /// Returns the next already-queued control message, if any.
    fn try_recv(&mut self) -> Option<Self::Message>;

    /// Records `msg` as sent and returns its payload.
    fn encode(&self, msg: Self::Message) -> IoBufs;
}

/// Control channel of a connection that has no control messages.
impl Control for () {
    type Message = Infallible;

    fn recv(&mut self) -> impl Future<Output = Option<Infallible>> + Send {
        future::pending()
    }

    fn try_recv(&mut self) -> Option<Infallible> {
        None
    }

    fn encode(&self, msg: Infallible) -> IoBufs {
        match msg {}
    }
}

/// Outbound queues, data send counters and the pending batch for one connection.
pub(crate) struct Outbox<T: Control> {
    control: T,
    high: mailbox::UnreliableReceiver<relay::Message<EncodedData>>,
    low: mailbox::UnreliableReceiver<relay::Message<EncodedData>>,

    sent: BTreeMap<Channel, Counter>,
    batch: Vec<IoBufs>,
    size: usize,
}

impl<T: Control> Outbox<T> {
    /// Creates an outbox that batches at most `size` payloads, with a send counter for each of
    /// `channels`.
    pub(crate) fn new<P: PublicKey, L: Label<P>>(
        peer: &P,
        control: T,
        receivers: Receivers<EncodedData>,
        channels: impl Iterator<Item = Channel>,
        sent: &CounterFamily<L>,
        size: usize,
    ) -> Self {
        let sent = channels
            .map(|channel| (channel, sent.get_or_create_owned(&L::data(peer, channel))))
            .collect();
        Self {
            control,
            high: receivers.high,
            low: receivers.low,
            sent,
            batch: Vec::with_capacity(size),
            size,
        }
    }

    /// Awaits the next outbound message.
    ///
    /// Priority order: control > high > low.
    pub(crate) async fn recv(&mut self) -> Prioritized<T::Message, EncodedData> {
        select! {
            msg = self.control.recv() => msg.map_or(Prioritized::Closed, Prioritized::Control),
            msg = self.high.recv() => msg.map_or(Prioritized::Closed, |msg| Prioritized::Data(
                msg.into_inner()
            )),
            msg = self.low.recv() => msg.map_or(Prioritized::Closed, |msg| Prioritized::Data(
                msg.into_inner()
            )),
        }
    }

    /// Returns the next already-queued outbound message, if any.
    ///
    /// Priority order: control > high > low.
    fn try_recv(&mut self) -> Option<Prioritized<T::Message, EncodedData>> {
        if let Some(msg) = self.control.try_recv() {
            return Some(Prioritized::Control(msg));
        }
        self.high
            .try_recv()
            .or_else(|_| self.low.try_recv())
            .ok()
            .map(|msg| Prioritized::Data(msg.into_inner()))
    }

    /// Records a message as sent and appends its payload to the batch.
    ///
    /// Returns [Error::Disconnected] if `msg` reports that an outbound channel closed.
    pub(crate) fn push(&mut self, msg: Prioritized<T::Message, EncodedData>) -> Result<(), Error> {
        let payload = match msg {
            Prioritized::Closed => return Err(Error::Disconnected),
            Prioritized::Control(msg) => self.control.encode(msg),
            Prioritized::Data(msg) => {
                self.sent
                    .get(&msg.channel)
                    .expect("outbound message on invalid channel")
                    .inc();
                msg.payload
            }
        };
        self.batch.push(payload);
        Ok(())
    }

    /// Appends `payload` to the batch without recording it as sent.
    pub(crate) fn append(&mut self, payload: IoBufs) {
        self.batch.push(payload);
    }

    /// Appends already-queued messages to the batch until it is full.
    ///
    /// Only consumes messages that are already ready, so batching adds no
    /// buffering latency.
    pub(crate) fn fill(&mut self) -> Result<(), Error> {
        while self.batch.len() < self.size
            && let Some(msg) = self.try_recv()
        {
            self.push(msg)?;
        }
        Ok(())
    }

    /// Removes and returns the batched payloads.
    pub(crate) fn drain(&mut self) -> Drain<'_, IoBufs> {
        self.batch.drain(..)
    }
}

/// Inbound rate limiters, application senders and the invalid counter for one connection.
pub(crate) struct Inbox<E: Clock, P: PublicKey> {
    peer: P,
    channels: BTreeMap<Channel, (Throttle<E>, mailbox::UnreliableSender<channels::Inbound<P>>)>,
    invalid: Counter,
}

impl<E: Clock + Supervisor, P: PublicKey> Inbox<E, P> {
    /// Creates a rate limiter for each registered channel.
    pub(crate) fn new<L: Label<P>>(
        context: &E,
        peer: P,
        channels: Channels<P>,
        received: &CounterFamily<L>,
        limited: &CounterFamily<L>,
    ) -> Self {
        let mut inbound = BTreeMap::new();
        for (channel, (rate, sender)) in channels.collect() {
            let label = L::data(&peer, channel);
            let limiter = RateLimiter::direct_with_clock(
                rate,
                context
                    .child("rate_limiter")
                    .with_attribute("channel", channel),
            );
            let throttle = Throttle::new(limiter, received, limited, &label);
            inbound.insert(channel, (throttle, sender));
        }
        let invalid = received.get_or_create_owned(&L::invalid(&peer));
        Self {
            peer,
            channels: inbound,
            invalid,
        }
    }

    /// Returns the registered channels.
    pub(crate) fn channels(&self) -> impl Iterator<Item = Channel> + '_ {
        self.channels.keys().copied()
    }

    /// Counts a message that failed to decode.
    pub(crate) fn invalid(&self) {
        self.invalid.inc();
    }

    /// Rate limits `data` and enqueues it on its channel, dropping it if the channel is full or
    /// closed.
    ///
    /// Returns [Error::InvalidChannel] if `data` names an unregistered channel.
    pub(crate) async fn deliver(&self, data: Data) -> Result<(), Error> {
        let Some((throttle, sender)) = self.channels.get(&data.channel) else {
            debug!(peer = ?self.peer, channel = data.channel, "invalid channel");
            self.invalid.inc();
            return Err(Error::InvalidChannel);
        };
        throttle.receive(true).await;

        // Send message to application without blocking.
        //
        // We intentionally drop messages when the application buffer is
        // full rather than blocking. Blocking here would also block
        // processing of the peer's other messages, causing the peer
        // connection to stall and potentially disconnect.
        let _ = sender.enqueue(channels::Inbound((self.peer.clone(), data.message)));
        Ok(())
    }
}

/// Waits for `context` to stop, for `kill` to end the connection, or for either handler to finish.
///
/// `kill` is the receiver paired with the peer's mailbox. It ends the connection with
/// [Error::Killed] once any clone of the mailbox kills the peer, or with [Error::Disconnected] once
/// every clone is dropped. Neither outcome waits for the handlers, so a write blocked on a peer
/// that stopped reading cannot delay the end of the connection.
///
/// Returns `Ok(Ok(()))` if `context` stops first, otherwise the kill outcome or the result of the
/// first handler to finish. When several are ready, shutdown wins over a kill and a kill over
/// either handler. `wait` does not abort the handlers, so run it in the task whose context spawned
/// them and they stop when that task returns.
pub(crate) async fn wait<E: From<Error> + Send + 'static>(
    context: &impl Spawner,
    mut kill: ring::Receiver<()>,
    mut send: Handle<Result<(), E>>,
    mut receive: Handle<Result<(), E>>,
) -> Result<Result<(), E>, RuntimeError> {
    let mut shutdown = context.stopped();
    select! {
        _ = &mut shutdown => {
            debug!("context shutdown, stopping peer");
            Ok(Ok(()))
        },
        killed = kill.recv() => {
            let err = killed.map_or(Error::Disconnected, |()| Error::Killed);
            Ok(Err(err.into()))
        },
        send_result = &mut send => send_result,
        receive_result = &mut receive => receive_result,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use commonware_cryptography::{ChaCha20Poly1305, Signer as _, ed25519::PrivateKey};
    use commonware_runtime::{Runner as _, Sink, deterministic, mocks};
    use commonware_stream::{
        Receiver, Sender, Upgrader as _,
        cups::{self, Cups},
        sake::{self, Sake},
    };
    use commonware_utils::NZUsize;
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::Duration,
    };

    const NAMESPACE: &[u8] = b"test_connection";
    const MAX_MESSAGE_SIZE: u32 = 64 * 1024;

    /// Sink whose writes never complete once `stalled` is set, like a peer that stopped reading.
    struct StalledSink<S> {
        inner: S,
        stalled: Arc<AtomicBool>,
        blocked: Arc<AtomicUsize>,
    }

    impl<S: Sink> Sink for StalledSink<S> {
        async fn send(&mut self, bufs: impl Into<IoBufs> + Send) -> Result<(), RuntimeError> {
            if !self.stalled.load(Ordering::Relaxed) {
                return self.inner.send(bufs).await;
            }
            self.blocked.fetch_add(1, Ordering::Relaxed);
            future::pending().await
        }
    }

    /// Authenticates a mock connection from `dialer` to `listener` in which every write the
    /// listener makes after the handshake blocks forever.
    ///
    /// Returns the dialer's sender and receiver, the listener's sender and receiver, and the
    /// number of listener writes blocked so far.
    pub(crate) async fn stalled_connection(
        context: &deterministic::Context,
        dialer: PrivateKey,
        listener: PrivateKey,
    ) -> (
        impl Sender,
        impl Receiver,
        impl Sender,
        impl Receiver,
        Arc<AtomicUsize>,
    ) {
        let upgrader = |signer| {
            Cups::<_, ChaCha20Poly1305>::new(
                Sake {
                    signer,
                    synchrony_bound: Duration::from_secs(10),
                    max_handshake_age: Duration::from_secs(10),
                    version: sake::Version::V1,
                },
                cups::Version::V1,
            )
        };
        let (dialer_sink, listener_stream) = mocks::Channel::init();
        let (listener_sink, dialer_stream) = mocks::Channel::init();
        let stalled = Arc::new(AtomicBool::new(false));
        let blocked = Arc::new(AtomicUsize::new(0));
        let listener_sink = StalledSink {
            inner: listener_sink,
            stalled: stalled.clone(),
            blocked: blocked.clone(),
        };
        let listener_key = listener.public_key();
        let listen = context.child("listener").spawn(move |context| {
            upgrader(listener).listen(
                context,
                NAMESPACE,
                MAX_MESSAGE_SIZE,
                |_| async { true },
                listener_stream,
                listener_sink,
            )
        });
        let (dialer_sender, dialer_receiver) = upgrader(dialer)
            .dial(
                context.child("dialer"),
                NAMESPACE,
                MAX_MESSAGE_SIZE,
                listener_key,
                dialer_stream,
                dialer_sink,
            )
            .await
            .expect("dial must succeed");
        let (_, listener_sender, listener_receiver) = listen
            .await
            .expect("listener task must not fail")
            .expect("listen must succeed");
        stalled.store(true, Ordering::Relaxed);
        (
            dialer_sender,
            dialer_receiver,
            listener_sender,
            listener_receiver,
            blocked,
        )
    }

    /// `wait` ends the connection on a kill sent before it starts and on a dropped mailbox,
    /// without waiting for either handler.
    #[test]
    fn test_wait_ends_on_kill_or_dropped_mailbox() {
        for kill in [true, false] {
            deterministic::Runner::default().start(|context| async move {
                let (mailbox, receiver) = ring::channel(NZUsize!(1));
                if kill {
                    mailbox.send_lossy(());
                }
                drop(mailbox);

                let handler = |label| {
                    context
                        .child(label)
                        .spawn(|_| future::pending::<Result<(), Error>>())
                };
                let result = wait(&context, receiver, handler("sender"), handler("receiver"))
                    .await
                    .expect("handler tasks must not fail");
                if kill {
                    assert!(matches!(result, Err(Error::Killed)), "{result:?}");
                } else {
                    assert!(matches!(result, Err(Error::Disconnected)), "{result:?}");
                }
            });
        }
    }
}
