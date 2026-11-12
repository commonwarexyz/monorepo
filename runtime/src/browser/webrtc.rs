//! Connections between pages over WebRTC data channels.
//!
//! The two halves of a connection share its JavaScript objects, and tasks hold the halves. The
//! callbacks the browser invokes and the promises of the steps that establish a connection are
//! not [Send]. They stay in the task that drives the endpoint:
//!
//! ```text
//!  tasks (Send)                              driver task (not Send)
//!  ------------                              ----------------------
//!  Sink ----+                                Driver
//!           +--> Arc<Connection> <-- weak -- callbacks for events and messages
//!  Stream --+      RtcPeerConnection         promise of each step
//!                  RtcDataChannel
//!                  Mutex<State>  -- drop --> callbacks released
//! ```
//!
//! Every callback except the one for messages only wakes whoever waits on the connection. That
//! is the driver until the connection opens, a pending read, or a pending send. Each then reads
//! what changed from the browser itself.
//!
//! # Endpoints
//!
//! A browser connects two pages once each has given it a description of its own end and a
//! description of the other. Every endpoint describes itself with an offer, which depends on
//! nothing the other page says. Its [Address] holds the parts of that offer the other page
//! cannot know in advance. A page that dials an address rebuilds from it the answer the
//! endpoint there would have given to the page's own offer, so neither page waits for the
//! other to describe itself. Both pages offered, so their addresses decide which endpoint
//! begins the handshake that secures the connection.

use super::{Address, Config};
use crate::{Error, IoBufs};
use bytes::{Buf as _, BytesMut};
use commonware_macros::select;
use commonware_utils::{Widen, channel::oneshot, sync::Mutex};
use js_sys::{
    Array, ArrayBuffer, Reflect, Uint8Array,
    futures::{JsFuture, spawn_local},
};
use std::{
    cmp::Ordering,
    future::poll_fn,
    mem,
    sync::{Arc, Weak},
    task::{Poll, Waker},
};
use tracing::debug;
use wasm_bindgen::{JsCast as _, JsValue, closure::Closure};
use web_sys::{
    MessageEvent, RtcConfiguration, RtcDataChannel, RtcDataChannelInit, RtcDataChannelState,
    RtcDataChannelType, RtcIceGatheringState, RtcIceServer, RtcPeerConnection,
    RtcPeerConnectionState, RtcSdpType, RtcSessionDescriptionInit,
};

/// Label of the data channel. Both pages create the channel themselves, so it is never sent.
const LABEL: &str = "commonware";

/// Identifier of the data channel. Both pages fix it in advance, so the channel opens without
/// negotiating one.
const CHANNEL: u16 = 0;

/// Largest message handed to the data channel. Every browser accepts messages of this size.
const MESSAGE_SIZE: usize = 16 * 1024;

/// Number of bytes the browser may hold unsent before a send waits.
const HIGH_WATERMARK: u32 = 1024 * 1024;

/// Number of unsent bytes at which a waiting send resumes.
const LOW_WATERMARK: u32 = 256 * 1024;

/// Outcome of dialing an address.
type Connected = Result<(Sink, Stream), Error>;

/// Wakes a task whose waker was taken while holding a lock.
fn wake(waker: Option<Waker>) {
    if let Some(waker) = waker {
        waker.wake();
    }
}

/// Logs why the browser refused a step and returns the error its caller reports.
fn refused(err: JsValue, reported: Error) -> Error {
    debug!(?err, ?reported, "browser refused");
    reported
}

/// Bytes a connection received, and the tasks waiting for it to change.
#[derive(Default)]
struct State {
    /// Bytes received that the stream has not taken.
    inbound: BytesMut,
    /// Number of bytes the stream took and has not returned from a read.
    taken: usize,
    /// Length of the stream's pending read.
    requested: usize,
    /// Whether newly received bytes are discarded.
    discarding: bool,
    /// Waker of a pending read.
    reader: Option<Waker>,
    /// Waker of a send waiting for the browser to drain its buffer.
    writer: Option<Waker>,
    /// Waker of the task establishing the connection.
    driver: Option<Waker>,
}

/// A peer connection and its data channel, closed when dropped.
struct Connection {
    peer: RtcPeerConnection,
    channel: RtcDataChannel,
    /// See [super::Config].
    receive_buffer_size: usize,
    state: Mutex<State>,
    /// Tells the driver to release the callbacks once the connection is dropped.
    _released: oneshot::Sender<()>,
}

impl Connection {
    /// Returns whether the connection has ended.
    fn finished(&self) -> bool {
        matches!(
            self.channel.ready_state(),
            RtcDataChannelState::Closing | RtcDataChannelState::Closed
        ) || matches!(
            self.peer.connection_state(),
            RtcPeerConnectionState::Failed | RtcPeerConnectionState::Closed
        )
    }

    /// Returns whether the handshake that secures the connection failed or the other page
    /// ended the connection before the data channel opened. Nothing repairs either.
    fn unsecured(&self) -> bool {
        // The handshake runs in a transport that `web-sys` does not describe, so its state is
        // read by name.
        let state = Reflect::get(&self.peer, &"sctp".into())
            .and_then(|sctp| Reflect::get(&sctp, &"transport".into()))
            .and_then(|transport| Reflect::get(&transport, &"state".into()));
        state
            .ok()
            .and_then(|state| state.as_string())
            .is_some_and(|state| state == "failed" || state == "closed")
    }

    /// Closes the data channel and the peer connection.
    fn close(&self) {
        self.channel.close();
        self.peer.close();
    }

    /// Wakes every task waiting for the connection to change. Each reads the new state from
    /// the browser itself.
    fn changed(&self) {
        let (reader, writer, driver) = {
            let mut state = self.state.lock();
            (
                state.reader.take(),
                state.writer.take(),
                state.driver.take(),
            )
        };
        wake(reader);
        wake(writer);
        wake(driver);
    }

    /// Queues a received message for the stream.
    ///
    /// A page cannot slow its peer down, so a peer that outruns the reader by more than the
    /// configured bound ends the connection. A peer that sends text ends it too.
    fn received(&self, event: MessageEvent) {
        // Accept a binary message that fits beside what the stream already holds.
        let data = event
            .data()
            .dyn_into::<ArrayBuffer>()
            .ok()
            .map(|data| Uint8Array::new(&data));
        let mut state = self.state.lock();
        if state.discarding {
            return;
        }
        let data = data.filter(|data| {
            let held = state
                .taken
                .saturating_add(state.inbound.len())
                .saturating_add(Widen::<usize>::widen(data.length()));
            held <= self.receive_buffer_size.saturating_add(state.requested)
        });

        // End the connection on any other message.
        let Some(data) = data else {
            state.discarding = true;
            drop(state);
            self.close();
            self.changed();
            return;
        };

        // Copy the message behind the bytes already received and wake a pending read.
        let start = state.inbound.len();
        state
            .inbound
            .resize(start + Widen::<usize>::widen(data.length()), 0);
        data.copy_to(&mut state.inbound[start..]);
        let reader = state.reader.take();
        drop(state);
        wake(reader);
    }

    /// Discards the bytes held for a stream that will never read them, and every byte
    /// received from then on.
    fn discard(&self) {
        let mut state = self.state.lock();
        state.discarding = true;
        state.inbound = BytesMut::new();
        state.taken = 0;
        state.requested = 0;
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // Detach the callbacks before their owner releases them.
        self.peer.set_onicegatheringstatechange(None);
        self.peer.set_onconnectionstatechange(None);
        self.channel.set_onopen(None);
        self.channel.set_onclose(None);
        self.channel.set_onerror(None);
        self.channel.set_onbufferedamountlow(None);
        self.channel.set_onmessage(None);
        self.close();
    }
}

/// Establishes a connection and owns the callbacks the browser invokes for it.
///
/// Callbacks and pending browser operations are not [Send]. They stay in the task that drives
/// the attempt, so the [Sink] and [Stream] can move to other tasks.
struct Driver {
    connection: Arc<Connection>,
    released: oneshot::Receiver<()>,
    _on_event: Closure<dyn FnMut()>,
    _on_message: Closure<dyn FnMut(MessageEvent)>,
}

impl Driver {
    fn new(config: &Config) -> Result<Self, JsValue> {
        // Create the peer connection
        let servers = Array::new();
        if !config.stun_servers().is_empty() {
            let server = RtcIceServer::new();
            let urls = config
                .stun_servers()
                .iter()
                .map(|url| JsValue::from_str(url))
                .collect::<Array>();
            server.set_urls(&urls);
            servers.push(&server);
        }
        let configuration = RtcConfiguration::new();
        configuration.set_ice_servers(&servers);
        let peer = RtcPeerConnection::new_with_configuration(&configuration)?;

        // Create the data channel under an identifier both pages know, so it opens on each
        // side as soon as the transport connects.
        let init = RtcDataChannelInit::new();
        init.set_negotiated(true);
        init.set_id(CHANNEL);
        let channel = peer.create_data_channel_with_data_channel_dict(LABEL, &init);
        channel.set_binary_type(RtcDataChannelType::Arraybuffer);
        channel.set_buffered_amount_low_threshold(LOW_WATERMARK);
        let (_released, released) = oneshot::channel();
        let connection = Arc::new(Connection {
            peer,
            channel,
            receive_buffer_size: config.receive_buffer_size(),
            state: Mutex::new(State::default()),
            _released,
        });

        // The callbacks hold the connection weakly, so dropping its halves still closes it.
        let on_event = Closure::<dyn FnMut()>::new({
            let connection = Arc::downgrade(&connection);
            move || {
                if let Some(connection) = Weak::upgrade(&connection) {
                    connection.changed();
                }
            }
        });
        let callback = on_event.as_ref().unchecked_ref();
        connection
            .peer
            .set_onicegatheringstatechange(Some(callback));
        connection.peer.set_onconnectionstatechange(Some(callback));
        connection.channel.set_onopen(Some(callback));
        connection.channel.set_onclose(Some(callback));
        connection.channel.set_onerror(Some(callback));
        connection.channel.set_onbufferedamountlow(Some(callback));
        let on_message = Closure::<dyn FnMut(MessageEvent)>::new({
            let connection = Arc::downgrade(&connection);
            move |event| {
                if let Some(connection) = Weak::upgrade(&connection) {
                    connection.received(event);
                }
            }
        });
        connection
            .channel
            .set_onmessage(Some(on_message.as_ref().unchecked_ref()));

        Ok(Self {
            connection,
            released,
            _on_event: on_event,
            _on_message: on_message,
        })
    }

    /// Waits until `ready` returns a value, checking again whenever the connection changes.
    async fn wait<T>(&self, mut ready: impl FnMut(&Connection) -> Option<T>) -> T {
        poll_fn(|cx| {
            if let Some(value) = ready(&self.connection) {
                return Poll::Ready(value);
            }
            self.connection.state.lock().driver = Some(cx.waker().clone());
            Poll::Pending
        })
        .await
    }

    /// Creates an offer and applies it as the description of this page's end.
    async fn offer(&self) -> Result<(), JsValue> {
        let peer = &self.connection.peer;
        let offer = JsFuture::from(peer.create_offer()).await?;
        JsFuture::from(peer.set_local_description(offer.unchecked_ref())).await?;
        Ok(())
    }

    /// Returns the description of this page's end once it lists every socket the page can be
    /// reached at.
    async fn described(&self) -> Result<String, JsValue> {
        self.wait(|connection| {
            let gathered = connection.peer.ice_gathering_state() == RtcIceGatheringState::Complete;
            gathered.then_some(())
        })
        .await;
        self.connection
            .peer
            .local_description()
            .map(|description| description.sdp())
            .ok_or(JsValue::NULL)
    }

    /// Applies `answer` as the description of the other page's end.
    async fn answered(&self, answer: &str) -> Result<(), JsValue> {
        let description = RtcSessionDescriptionInit::new(RtcSdpType::Answer);
        description.set_sdp(answer);
        JsFuture::from(self.connection.peer.set_remote_description(&description)).await?;
        Ok(())
    }

    /// Waits for the data channel to open.
    ///
    /// The other page may not have dialed yet. A browser that has given up on an address that
    /// stayed silent can still connect once the page there reaches it, so the connection
    /// failing does not end the wait. A closed channel or a failed handshake does.
    async fn opened(&self) -> Result<(), Error> {
        self.wait(|connection| match connection.channel.ready_state() {
            RtcDataChannelState::Open => Some(Ok(())),
            RtcDataChannelState::Closing | RtcDataChannelState::Closed => {
                Some(Err(Error::ConnectionFailed))
            }
            _ => connection
                .unsecured()
                .then_some(Err(Error::ConnectionFailed)),
        })
        .await
    }

    /// Reports the outcome of the dial. If the channel opened, hands the connection to its
    /// halves and holds the callbacks until both halves are dropped.
    async fn finish(self, opened: Result<(), Error>, connected: oneshot::Sender<Connected>) {
        let Self {
            connection,
            released,
            _on_event,
            _on_message,
        } = self;

        // A failed dial has no connection to hand over.
        if let Err(err) = opened {
            let _ = connected.send(Err(err));
            return;
        }

        // Hand the connection to its halves. Only they keep it alive, so it closes once both
        // are dropped.
        let sink = Sink {
            connection: connection.clone(),
            state: SinkState::Open,
        };
        let stream = Stream {
            connection,
            buffer: BytesMut::new(),
            poisoned: false,
        };
        if connected.send(Ok((sink, stream))).is_err() {
            return;
        }

        // Hold the callbacks until then.
        let _ = released.await;
    }
}

/// Drives an endpoint until it fails, is abandoned, or connects and has both halves of the
/// connection dropped.
async fn drive(
    config: Config,
    mut bound: oneshot::Sender<Result<Address, Error>>,
    dialed: oneshot::Receiver<Address>,
    mut connected: oneshot::Sender<Connected>,
) {
    // Describe this page's end. Each of these steps finishes promptly, and the browser never
    // settles one whose connection closes under it, so none is abandoned midway.
    let started = async {
        let driver = Driver::new(&config)?;
        driver.offer().await?;
        Ok(driver)
    };
    let driver = match started.await {
        Ok(driver) => driver,
        Err(err) => {
            let _ = bound.send(Err(refused(err, Error::BindFailed)));
            return;
        }
    };

    // Learn where the endpoint can be reached, unless the caller stops waiting for it.
    let description = select! {
        _ = bound.closed() => return,
        description = driver.described() => description,
    };
    let address = description
        .map_err(|err| refused(err, Error::BindFailed))
        .and_then(|description| Address::read(&description).ok_or(Error::BindFailed));
    let (local, section) = match address {
        Ok(address) => address,
        Err(err) => {
            let _ = bound.send(Err(err));
            return;
        }
    };
    if bound.send(Ok(local.clone())).is_err() {
        return;
    }

    // Wait for the address to dial. Its sender is dropped if the caller abandons the endpoint.
    let Ok(remote) = dialed.await else {
        return;
    };

    // Both pages offered, so their addresses decide which endpoint begins the handshake that
    // secures the connection. An endpoint cannot dial itself.
    let active = match remote.cmp(&local) {
        Ordering::Less => true,
        Ordering::Greater => false,
        Ordering::Equal => {
            let _ = connected.send(Err(Error::ConnectionFailed));
            return;
        }
    };
    if let Err(err) = driver.answered(&remote.answer(&section, active)).await {
        let _ = connected.send(Err(refused(err, Error::ConnectionFailed)));
        return;
    }

    // Wait for the channel to open, unless the caller stops waiting for the connection.
    let opened = select! {
        _ = connected.closed() => return,
        opened = driver.opened() => opened,
    };
    driver.finish(opened, connected).await;
}

/// Opens an endpoint for [super::Context::bind].
pub(super) async fn bind(config: Config) -> Result<Endpoint, Error> {
    let (bound, address) = oneshot::channel();
    let (remote, dialed) = oneshot::channel();
    let (connected, connection) = oneshot::channel();
    spawn_local(drive(config, bound, dialed, connected));
    let address = address.await.map_err(|_| Error::BindFailed)??;
    Ok(Endpoint {
        address,
        remote,
        connection,
    })
}

/// One end of a connection that is yet to be made, opened with
/// [Context::bind](super::Context::bind).
///
/// The page at the other end dials this endpoint's [Address], and this page dials that page's
/// address with [Endpoint::dial]. Dropping the endpoint closes it.
pub struct Endpoint {
    address: Address,
    remote: oneshot::Sender<Address>,
    connection: oneshot::Receiver<Connected>,
}

impl Endpoint {
    /// Returns the address the other page dials to reach this endpoint.
    pub const fn address(&self) -> &Address {
        &self.address
    }

    /// Connect to the endpoint at `address`.
    ///
    /// The pages connect once the page that owns that endpoint has dialed this endpoint's
    /// address too. Either page may dial first. The dial fails if `address` is this endpoint's
    /// own, or once the endpoint it reaches proves another certificate than `address` names.
    ///
    /// Callers must enforce a deadline. Dropping the returned future closes the endpoint.
    pub async fn dial(self, address: Address) -> Result<(Sink, Stream), Error> {
        self.remote
            .send(address)
            .map_err(|_| Error::ConnectionFailed)?;
        self.connection.await.map_err(|_| Error::ConnectionFailed)?
    }
}

/// Lifecycle state for the write half of a connection.
enum SinkState {
    /// Sends may be attempted.
    Open,
    /// A send is currently in progress.
    Sending,
    /// The write half is unusable.
    Closed,
}

/// Implementation of [crate::Sink] for the `browser` runtime.
///
/// A send completes once the browser has accepted its bytes. They may not have reached the
/// other page yet. The connection closes when both the sink and its [Stream] are dropped.
/// Closing does not wait for the bytes the browser still holds, so they may never be delivered.
pub struct Sink {
    connection: Arc<Connection>,
    state: SinkState,
}

impl Sink {
    /// Sends `bufs` as a sequence of messages, waiting whenever the browser holds too many
    /// unsent bytes.
    async fn send_all(&self, mut bufs: IoBufs) -> Result<(), Error> {
        let connection = &self.connection;
        while bufs.has_remaining() {
            poll_fn(|cx| {
                if connection.finished() {
                    return Poll::Ready(Err(Error::SendFailed));
                }
                if connection.channel.buffered_amount() <= HIGH_WATERMARK {
                    return Poll::Ready(Ok(()));
                }
                connection.state.lock().writer = Some(cx.waker().clone());
                Poll::Pending
            })
            .await?;
            let message = bufs.copy_to_bytes(bufs.remaining().min(MESSAGE_SIZE));
            connection
                .channel
                .send_with_u8_array(&message)
                .map_err(|err| {
                    debug!(?err, "send failed");
                    Error::SendFailed
                })?;
        }
        Ok(())
    }
}

impl crate::Sink for Sink {
    async fn send(&mut self, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        match self.state {
            SinkState::Open => {}
            SinkState::Sending => {
                self.state = SinkState::Closed;
                return Err(Error::Closed);
            }
            SinkState::Closed => return Err(Error::Closed),
        }

        // Mark the sink as sending before awaiting so cancellation can be detected by the next
        // send.
        self.state = SinkState::Sending;
        let result = self.send_all(bufs.into()).await;

        // A failed send leaves the write half unusable.
        self.state = if result.is_ok() {
            SinkState::Open
        } else {
            SinkState::Closed
        };
        result
    }
}

/// Implementation of [crate::Stream] for the `browser` runtime.
///
/// Bytes received before the connection closed remain readable. Dropping the stream or a
/// pending read discards the bytes it has not returned and everything received afterwards.
/// Its [Sink] stays usable.
pub struct Stream {
    connection: Arc<Connection>,
    buffer: BytesMut,
    poisoned: bool,
}

/// A read in progress. Unless it completes, dropping it discards every byte received for the
/// stream.
struct Reading<'a> {
    connection: &'a Connection,
    buffer: &'a mut BytesMut,
    completed: bool,
}

impl Drop for Reading<'_> {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        *self.buffer = BytesMut::new();
        self.connection.discard();
    }
}

impl crate::Stream for Stream {
    async fn recv(&mut self, len: usize) -> Result<IoBufs, Error> {
        if self.poisoned {
            return Err(Error::Closed);
        }

        // Pre-poison so that cancellation leaves the stream permanently closed. A read that
        // fails or is dropped also releases the bytes held for the stream.
        self.poisoned = true;
        let mut reading = Reading {
            connection: &self.connection,
            buffer: &mut self.buffer,
            completed: false,
        };
        poll_fn(|cx| {
            let connection = reading.connection;
            let finished = connection.finished();

            // Take everything received so far.
            let mut state = connection.state.lock();
            if reading.buffer.is_empty() {
                mem::swap(reading.buffer, &mut state.inbound);
            } else {
                reading.buffer.extend_from_slice(&state.inbound);
                state.inbound.clear();
            }

            // Report what this read holds and asks for, so the connection can bound the
            // bytes held beyond that.
            if reading.buffer.len() >= len {
                state.taken = reading.buffer.len() - len;
                state.requested = 0;
                return Poll::Ready(Ok(()));
            }
            state.taken = reading.buffer.len();
            state.requested = len;
            if finished {
                return Poll::Ready(Err(Error::RecvFailed));
            }
            state.reader = Some(cx.waker().clone());
            Poll::Pending
        })
        .await?;
        reading.completed = true;
        drop(reading);

        // Unpoison on success.
        self.poisoned = false;
        Ok(IoBufs::from(self.buffer.split_to(len).freeze()))
    }

    fn peek(&self, max_len: usize) -> &[u8] {
        let len = max_len.min(self.buffer.len());
        &self.buffer[..len]
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.connection.discard();
    }
}
