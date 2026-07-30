use super::{ConfigError, PROTOCOL, WebRtcConfig};
use bytes::Bytes;
use commonware_runtime::{
    Connection, ConnectionInfo, Error, IoBuf, IoBufs, Sink, Stream,
};
use futures::{
    future::{Either, poll_fn, select},
    pin_mut,
};
use js_sys::{ArrayBuffer, Reflect, Uint8Array};
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    future::Future,
    pin::Pin,
    rc::{Rc, Weak},
    task::{Context, Poll, Waker},
    time::Duration,
};
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use web_sys::{
    Event, MessageEvent, RtcDataChannel, RtcDataChannelState, RtcDataChannelType,
    RtcPeerConnection, RtcPeerConnectionState,
};

/// Opaque browser-side WebRTC transport observation.
#[derive(Clone, Debug)]
pub struct WebRtcOrigin;

/// An established WebRTC peer connection and reliable ordered data channel.
pub struct WebRtcConnection {
    inner: Rc<Inner>,
}

impl WebRtcConnection {
    /// Validate an established peer and data channel without taking ownership.
    pub fn validate(
        peer: &RtcPeerConnection,
        channel: &RtcDataChannel,
    ) -> Result<(), ConfigError> {
        if peer.connection_state() != RtcPeerConnectionState::Connected {
            return Err(ConfigError::PeerNotConnected);
        }
        if channel.ready_state() != RtcDataChannelState::Open {
            return Err(ConfigError::ChannelNotOpen);
        }
        if channel.label() != PROTOCOL {
            return Err(ConfigError::InvalidLabel);
        }
        let protocol = Reflect::get(channel.as_ref(), &JsValue::from_str("protocol"))
            .ok()
            .and_then(|value| value.as_string());
        if protocol.as_deref() != Some(PROTOCOL) {
            return Err(ConfigError::InvalidProtocol);
        }

        let ordered = Reflect::get(channel.as_ref(), &JsValue::from_str("ordered"))
            .map_err(|_| ConfigError::OrderedUnavailable)?
            .as_bool()
            .ok_or(ConfigError::OrderedUnavailable)?;
        if !ordered {
            return Err(ConfigError::Unordered);
        }
        if channel.max_retransmits().is_some() {
            return Err(ConfigError::MaxRetransmitsSet);
        }
        if channel.max_packet_life_time().is_some() {
            return Err(ConfigError::MaxPacketLifeTimeSet);
        }
        Ok(())
    }

    /// Wrap an already-established peer connection and data channel.
    pub fn new(
        peer: RtcPeerConnection,
        channel: RtcDataChannel,
        config: WebRtcConfig,
    ) -> Result<Self, ConfigError> {
        config.validate()?;
        Self::validate(&peer, &channel)?;

        channel.set_binary_type(RtcDataChannelType::Arraybuffer);
        channel.set_buffered_amount_low_threshold(config.send_low_watermark);
        let inner = Inner::new(peer, channel, config);
        inner.install_handlers();
        Ok(Self { inner })
    }
}

impl Connection for WebRtcConnection {
    type Sink = WebRtcSink;
    type Stream = WebRtcStream;
    type Origin = WebRtcOrigin;

    fn split(self) -> (Self::Sink, Self::Stream, ConnectionInfo<Self::Origin>) {
        (
            WebRtcSink {
                inner: Rc::clone(&self.inner),
                state: SendState::Open,
            },
            WebRtcStream {
                inner: self.inner,
                buffered: ByteQueue::default(),
                poisoned: false,
            },
            ConnectionInfo {
                origin: None,
                transport: "webrtc",
            },
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SendState {
    Open,
    Sending,
    Closed,
}

/// WebRTC data-channel write half.
pub struct WebRtcSink {
    inner: Rc<Inner>,
    state: SendState,
}

impl WebRtcSink {
    async fn send_inner(&self, bufs: IoBufs) -> Result<(), Error> {
        self.inner.check_terminal()?;
        let buffer = bufs.coalesce();
        for chunk in buffer.as_ref().chunks(self.inner.config.max_message_size) {
            if self.inner.channel.buffered_amount() > self.inner.config.send_high_watermark {
                self.inner.wait_for_backpressure().await?;
            }
            self.inner.check_terminal()?;
            self.inner
                .channel
                .send_with_u8_array(chunk)
                .map_err(|error| Error::TransportFailed(js_error(&error)))?;
        }
        Ok(())
    }
}

impl Sink for WebRtcSink {
    async fn send(&mut self, bufs: impl Into<IoBufs>) -> Result<(), Error> {
        match self.state {
            SendState::Open => self.state = SendState::Sending,
            SendState::Sending => {
                self.state = SendState::Closed;
                self.inner.terminate(Error::Closed);
                return Err(Error::Closed);
            }
            SendState::Closed => return Err(Error::Closed),
        }

        let mut cancellation = CancellationGuard::new(Rc::clone(&self.inner));
        let result = self.send_inner(bufs.into()).await;
        match result {
            Ok(()) => {
                cancellation.disarm();
                self.state = SendState::Open;
                Ok(())
            }
            Err(error) => {
                self.inner.terminate(error.clone());
                cancellation.disarm();
                self.state = SendState::Closed;
                Err(error)
            }
        }
    }
}

impl Drop for WebRtcSink {
    fn drop(&mut self) {
        self.inner.terminate(Error::Closed);
    }
}

/// WebRTC data-channel exact-length read half.
pub struct WebRtcStream {
    inner: Rc<Inner>,
    buffered: ByteQueue,
    poisoned: bool,
}

impl WebRtcStream {
    fn drain_shared(&mut self) {
        self.buffered.append(&mut self.inner.incoming.borrow_mut());
    }

    async fn recv_inner(&mut self, len: usize) -> Result<IoBufs, Error> {
        let recv_timeout = self.inner.config.recv_timeout;
        let receive = poll_fn(|context| {
            self.drain_shared();
            if self.buffered.len() >= len {
                let chunks = self.buffered.take_exact(len);
                self.inner
                    .queued_bytes
                    .set(self.inner.queued_bytes.get() - len);
                let chunks = chunks.into_iter().map(IoBuf::from).collect::<Vec<_>>();
                return Poll::Ready(Ok(IoBufs::from(chunks)));
            }
            if let Err(error) = self.inner.check_terminal() {
                return Poll::Ready(Err(error));
            }
            *self.inner.receive_waker.borrow_mut() = Some(context.waker().clone());

            self.drain_shared();
            if self.buffered.len() >= len {
                let chunks = self.buffered.take_exact(len);
                self.inner
                    .queued_bytes
                    .set(self.inner.queued_bytes.get() - len);
                let chunks = chunks.into_iter().map(IoBuf::from).collect::<Vec<_>>();
                return Poll::Ready(Ok(IoBufs::from(chunks)));
            }
            Poll::Pending
        });
        let timeout = Delay::new(recv_timeout)?;
        pin_mut!(receive, timeout);
        match select(receive, timeout).await {
            Either::Left((result, _)) => result,
            Either::Right(_) => Err(Error::Timeout),
        }
    }
}

impl Stream for WebRtcStream {
    async fn recv(&mut self, len: usize) -> Result<IoBufs, Error> {
        if self.poisoned {
            return Err(Error::Closed);
        }
        if len == 0 {
            return Ok(IoBufs::default());
        }
        self.poisoned = true;

        let mut cancellation = CancellationGuard::new(Rc::clone(&self.inner));
        let result = self.recv_inner(len).await;
        match result {
            Ok(bufs) => {
                cancellation.disarm();
                self.poisoned = false;
                Ok(bufs)
            }
            Err(error) => {
                self.inner.terminate(error.clone());
                cancellation.disarm();
                Err(error)
            }
        }
    }

    fn peek(&self, max_len: usize) -> &[u8] {
        self.buffered.front(max_len)
    }
}

impl Drop for WebRtcStream {
    fn drop(&mut self) {
        self.inner.terminate(Error::Closed);
    }
}

#[derive(Default)]
struct ByteQueue {
    chunks: VecDeque<Bytes>,
    len: usize,
}

impl ByteQueue {
    fn push(&mut self, chunk: Bytes) {
        self.len += chunk.len();
        self.chunks.push_back(chunk);
    }

    fn append(&mut self, other: &mut Self) {
        self.len += other.len;
        other.len = 0;
        self.chunks.append(&mut other.chunks);
    }

    const fn len(&self) -> usize {
        self.len
    }

    fn front(&self, max_len: usize) -> &[u8] {
        let Some(front) = self.chunks.front() else {
            return &[];
        };
        &front[..front.len().min(max_len)]
    }

    fn take_exact(&mut self, len: usize) -> Vec<Bytes> {
        debug_assert!(self.len >= len);
        self.len -= len;
        let mut remaining = len;
        let mut output = Vec::new();
        while remaining > 0 {
            let mut front = self.chunks.pop_front().expect("queue length checked");
            if front.len() > remaining {
                let prefix = front.split_to(remaining);
                self.chunks.push_front(front);
                output.push(prefix);
                break;
            }
            remaining -= front.len();
            output.push(front);
        }
        output
    }
}

struct Handlers {
    _message: Closure<dyn FnMut(MessageEvent)>,
    _error: Closure<dyn FnMut(Event)>,
    _close: Closure<dyn FnMut(Event)>,
    _buffered_amount_low: Closure<dyn FnMut(Event)>,
    _connection_state: Closure<dyn FnMut(Event)>,
}

struct Inner {
    peer: RtcPeerConnection,
    channel: RtcDataChannel,
    config: WebRtcConfig,
    terminal: RefCell<Option<Error>>,
    incoming: RefCell<ByteQueue>,
    queued_bytes: Cell<usize>,
    receive_waker: RefCell<Option<Waker>>,
    send_waker: RefCell<Option<Waker>>,
    handlers: RefCell<Option<Handlers>>,
    closed: Cell<bool>,
}

impl Inner {
    fn new(
        peer: RtcPeerConnection,
        channel: RtcDataChannel,
        config: WebRtcConfig,
    ) -> Rc<Self> {
        Rc::new(Self {
            peer,
            channel,
            config,
            terminal: RefCell::new(None),
            incoming: RefCell::new(ByteQueue::default()),
            queued_bytes: Cell::new(0),
            receive_waker: RefCell::new(None),
            send_waker: RefCell::new(None),
            handlers: RefCell::new(None),
            closed: Cell::new(false),
        })
    }

    fn install_handlers(self: &Rc<Self>) {
        let weak = Rc::downgrade(self);
        let message = Closure::new(move |event: MessageEvent| {
            let Some(inner) = weak.upgrade() else {
                return;
            };
            let Ok(buffer) = event.data().dyn_into::<ArrayBuffer>() else {
                inner.terminate(Error::ProtocolViolation(
                    "WebRTC data channel received a non-ArrayBuffer message".into(),
                ));
                return;
            };
            let array = Uint8Array::new(&buffer);
            let len = array.length() as usize;
            if len == 0 {
                return;
            }
            if len > inner.config.max_message_size {
                inner.terminate(Error::ProtocolViolation(
                    "WebRTC data-channel message exceeds configured limit".into(),
                ));
                return;
            }
            let Some(queued) = inner.queued_bytes.get().checked_add(len) else {
                inner.terminate(Error::IncomingBufferExceeded);
                return;
            };
            if queued > inner.config.max_incoming_buffer {
                inner.terminate(Error::IncomingBufferExceeded);
                return;
            }

            let mut bytes = vec![0; len];
            array.copy_to(&mut bytes);
            inner.incoming.borrow_mut().push(Bytes::from(bytes));
            inner.queued_bytes.set(queued);
            wake(&inner.receive_waker);
        });

        let weak = Rc::downgrade(self);
        let error = Closure::new(move |_event: Event| {
            let Some(inner) = weak.upgrade() else {
                return;
            };
            inner.terminate(Error::TransportFailed("WebRTC data-channel error".into()));
        });

        let weak = Rc::downgrade(self);
        let close = Closure::new(move |_event: Event| {
            let Some(inner) = weak.upgrade() else {
                return;
            };
            inner.terminate(Error::Closed);
        });

        let weak = Rc::downgrade(self);
        let buffered_amount_low = Closure::new(move |_event: Event| {
            let Some(inner) = weak.upgrade() else {
                return;
            };
            wake(&inner.send_waker);
        });

        let weak = Rc::downgrade(self);
        let connection_state = Closure::new(move |_event: Event| {
            let Some(inner) = weak.upgrade() else {
                return;
            };
            if matches!(
                inner.peer.connection_state(),
                RtcPeerConnectionState::Failed | RtcPeerConnectionState::Closed
            ) {
                inner.terminate(Error::Closed);
            }
        });

        self.channel
            .set_onmessage(Some(message.as_ref().unchecked_ref()));
        self.channel.set_onerror(Some(error.as_ref().unchecked_ref()));
        self.channel.set_onclose(Some(close.as_ref().unchecked_ref()));
        self.channel
            .set_onbufferedamountlow(Some(buffered_amount_low.as_ref().unchecked_ref()));
        self.peer
            .set_onconnectionstatechange(Some(connection_state.as_ref().unchecked_ref()));
        *self.handlers.borrow_mut() = Some(Handlers {
            _message: message,
            _error: error,
            _close: close,
            _buffered_amount_low: buffered_amount_low,
            _connection_state: connection_state,
        });
    }

    fn check_terminal(&self) -> Result<(), Error> {
        if let Some(error) = self.terminal.borrow().clone() {
            return Err(error);
        }
        if self.channel.ready_state() != RtcDataChannelState::Open {
            return Err(Error::Closed);
        }
        Ok(())
    }

    async fn wait_for_backpressure(&self) -> Result<(), Error> {
        let ready = poll_fn(|context| {
            self.check_terminal()?;
            if self.channel.buffered_amount() <= self.config.send_low_watermark {
                return Poll::Ready(Ok(()));
            }
            *self.send_waker.borrow_mut() = Some(context.waker().clone());

            self.check_terminal()?;
            if self.channel.buffered_amount() <= self.config.send_low_watermark {
                self.send_waker.borrow_mut().take();
                return Poll::Ready(Ok(()));
            }
            Poll::Pending
        });
        let timeout = Delay::new(self.config.send_timeout)?;
        pin_mut!(ready, timeout);
        match select(ready, timeout).await {
            Either::Left((result, _)) => result,
            Either::Right(_) => Err(Error::Timeout),
        }
    }

    fn terminate(&self, error: Error) {
        if self.terminal.borrow().is_some() {
            return;
        }
        *self.terminal.borrow_mut() = Some(error);
        self.clear_handlers();
        self.close_resources();
        wake(&self.receive_waker);
        wake(&self.send_waker);
    }

    fn close_resources(&self) {
        if self.closed.replace(true) {
            return;
        }
        self.channel.close();
        self.peer.close();
    }

    fn clear_handlers(&self) {
        self.channel.set_onmessage(None);
        self.channel.set_onerror(None);
        self.channel.set_onclose(None);
        self.channel.set_onbufferedamountlow(None);
        self.peer.set_onconnectionstatechange(None);
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.clear_handlers();
        self.handlers.get_mut().take();
        self.close_resources();
    }
}

struct CancellationGuard {
    inner: Rc<Inner>,
    armed: bool,
}

impl CancellationGuard {
    fn new(inner: Rc<Inner>) -> Self {
        Self { inner, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CancellationGuard {
    fn drop(&mut self) {
        if self.armed {
            self.inner.terminate(Error::Closed);
        }
    }
}

fn wake(slot: &RefCell<Option<Waker>>) {
    let waker = slot.borrow_mut().take();
    if let Some(waker) = waker {
        waker.wake();
    }
}

fn js_error(error: &JsValue) -> String {
    error
        .as_string()
        .unwrap_or_else(|| "JavaScript WebRTC operation failed".into())
        .chars()
        .take(256)
        .collect()
}

struct DelayState {
    window: web_sys::Window,
    timer_id: Cell<Option<i32>>,
    ready: Cell<bool>,
    waker: RefCell<Option<Waker>>,
    callback: RefCell<Option<Closure<dyn FnMut()>>>,
}

struct Delay {
    state: Rc<DelayState>,
}

impl Delay {
    fn new(duration: Duration) -> Result<Self, Error> {
        let window = web_sys::window().ok_or_else(|| {
            Error::TransportFailed("WebRTC transport requires a browser window".into())
        })?;
        let state = Rc::new(DelayState {
            window,
            timer_id: Cell::new(None),
            ready: Cell::new(false),
            waker: RefCell::new(None),
            callback: RefCell::new(None),
        });
        let weak: Weak<DelayState> = Rc::downgrade(&state);
        let callback = Closure::new(move || {
            let Some(state) = weak.upgrade() else {
                return;
            };
            state.timer_id.set(None);
            state.ready.set(true);
            wake(&state.waker);
        });
        let delay_ms = duration.as_millis().min(i32::MAX as u128) as i32;
        let timer_id = state
            .window
            .set_timeout_with_callback_and_timeout_and_arguments_0(
                callback.as_ref().unchecked_ref(),
                delay_ms,
            )
            .map_err(|error| Error::TransportFailed(js_error(&error)))?;
        state.timer_id.set(Some(timer_id));
        *state.callback.borrow_mut() = Some(callback);
        Ok(Self { state })
    }
}

impl Future for Delay {
    type Output = ();

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if self.state.ready.get() {
            return Poll::Ready(());
        }
        *self.state.waker.borrow_mut() = Some(context.waker().clone());
        Poll::Pending
    }
}

impl Drop for Delay {
    fn drop(&mut self) {
        if let Some(timer_id) = self.state.timer_id.take() {
            self.state.window.clear_timeout_with_handle(timer_id);
        }
        self.state.callback.borrow_mut().take();
        self.state.waker.borrow_mut().take();
    }
}
