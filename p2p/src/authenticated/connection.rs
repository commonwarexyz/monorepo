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
use std::{collections::BTreeMap, future::Future, hash::Hash, vec::Drain};
use thiserror::Error;
use tracing::debug;

/// Errors that end a connection in shared peer code.
#[derive(Error, Debug)]
pub(crate) enum Error {
    #[error("peer killed: {0}")]
    Killed(String),
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

    /// Records `msg` as sent and returns its payload, or `None` if `msg` kills the connection.
    fn encode(&self, msg: Self::Message) -> Option<IoBufs>;
}

/// Outbound queues, data send counters and the pending batch for one connection.
pub(crate) struct Outbox<P: PublicKey, T: Control> {
    peer: P,

    control: T,
    high: mailbox::UnreliableReceiver<relay::Message<EncodedData>>,
    low: mailbox::UnreliableReceiver<relay::Message<EncodedData>>,

    sent: BTreeMap<Channel, Counter>,
    batch: Vec<IoBufs>,
    size: usize,
}

impl<P: PublicKey, T: Control> Outbox<P, T> {
    /// Creates an outbox that batches at most `size` payloads, with a send counter for each of
    /// `channels`.
    pub(crate) fn new<L: Label<P>>(
        peer: P,
        control: T,
        receivers: Receivers<EncodedData>,
        channels: impl Iterator<Item = Channel>,
        sent: &CounterFamily<L>,
        size: usize,
    ) -> Self {
        let sent = channels
            .map(|channel| (channel, sent.get_or_create_owned(&L::data(&peer, channel))))
            .collect();
        Self {
            peer,
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
    /// Returns `Err` if `msg` terminates the connection (`Closed` or a kill).
    pub(crate) fn push(&mut self, msg: Prioritized<T::Message, EncodedData>) -> Result<(), Error> {
        let payload = match msg {
            Prioritized::Closed => return Err(Error::Disconnected),
            Prioritized::Control(msg) => self
                .control
                .encode(msg)
                .ok_or_else(|| Error::Killed(self.peer.to_string()))?,
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

/// Waits for `context` to stop or for either handler to finish.
///
/// Returns `Ok(Ok(()))` if `context` stops first, otherwise the result of the first handler to
/// finish.
pub(crate) async fn wait<E: Send + 'static>(
    context: &impl Spawner,
    mut send: Handle<Result<(), E>>,
    mut receive: Handle<Result<(), E>>,
) -> Result<Result<(), E>, RuntimeError> {
    let mut shutdown = context.stopped();
    select! {
        _ = &mut shutdown => {
            debug!("context shutdown, stopping peer");
            Ok(Ok(()))
        },
        send_result = &mut send => send_result,
        receive_result = &mut receive => receive_result,
    }
}
