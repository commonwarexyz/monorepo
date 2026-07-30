use super::{ConfigError, WebSocketConfig, WebSocketEndpoint};
use bytes::Bytes;
use commonware_runtime::{
    Connection, ConnectionInfo, Dialer, Error, IoBuf, IoBufs, Sink, Stream,
};
use futures::{
    future::{Either, poll_fn, select},
    pin_mut,
};
use js_sys::{ArrayBuffer, Uint8Array};
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    future::Future,
    pin::Pin,
    rc::{Rc, Weak},
    task::{Context as TaskContext, Poll, Waker},
    time::Duration,
};
use wasm_bindgen::{JsCast, closure::Closure};
use web_sys::{BinaryType, CloseEvent, ErrorEvent, Event, MessageEvent, WebSocket};

/// Browser WebSocket transport.
#[derive(Clone)]
pub struct WebSocketDialer {
    config: WebSocketConfig,
}

impl WebSocketDialer {
    /// Create a dialer after validating resource limits.
    pub fn new(config: WebSocketConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self { config })
    }
}

impl Default for WebSocketDialer {
    fn default() -> Self {
        Self::new(WebSocketConfig::default()).expect("default WebSocket configuration is valid")
    }
}

impl Dialer for WebSocketDialer {
    type Endpoint = WebSocketEndpoint;
    type Connection = WebSocketConnection;

    async fn dial(&self, endpoint: &Self::Endpoint) -> Result<Self::Connection, Error> {
        let socket = WebSocket::new(endpoint.as_str())
            .map_err(|error| Error::TransportFailed(js_error(&error)))?;
        socket.set_binary_type(BinaryType::Arraybuffer);
        let inner = Inner::new(socket, self.config.clone());
        inner.install_handlers();

        let opened = poll_fn({
            let inner = Rc::clone(&inner);
            move |context| inner.poll_open(context)
        });
        let timeout = Delay::new(self.config.connect_timeout);
        pin_mut!(opened, timeout);
        match select(opened, timeout).await {
            Either::Left((result, _)) => result?,
            Either::Right(_) => {
                inner.terminate(Error::Timeout, true);
                return Err(Error::Timeout);
            }
        }

        Ok(WebSocketConnection { inner })
    }
}

/// Opaque browser-side transport observation.
#[derive(Clone, Debug)]
pub struct WebSocketOrigin;

/// Established browser WebSocket connection.
pub struct WebSocketConnection {
    inner: Rc<Inner>,
}

impl Connection for WebSocketConnection {
    type Sink = WebSocketSink;
    type Stream = WebSocketStream;
    type Origin = WebSocketOrigin;

    fn split(self) -> (Self::Sink, Self::Stream, ConnectionInfo<Self::Origin>) {
        (
            WebSocketSink {
                inner: Rc::clone(&self.inner),
                state: SendState::Open,
            },
            WebSocketStream {
                inner: self.inner,
                chunks: VecDeque::new(),
                poisoned: false,
            },
            ConnectionInfo {
                origin: None,
                transport: "websocket",
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

/// Browser WebSocket write half.
pub struct WebSocketSink {
    inner: Rc<Inner>,
    state: SendState,
}

impl Sink for WebSocketSink {
    async fn send(&mut self, bufs: impl Into<IoBufs>) -> Result<(), Error> {
        match self.state {
            SendState::Open => self.state = SendState::Sending,
            SendState::Sending => {
                self.state = SendState::Closed;
                self.inner.terminate(Error::Closed, true);
                return Err(Error::Closed);
            }
            SendState::Closed => return Err(Error::Closed),
        }

        let buffer = bufs.into().coalesce();
        for chunk in buffer.as_ref().chunks(self.inner.config.max_message_size) {
            if u64::from(self.inner.socket.buffered_amount())
                > self.inner.config.send_high_watermark
            {
                while u64::from(self.inner.socket.buffered_amount())
                    > self.inner.config.send_low_watermark
                {
                    self.inner
                        .wait_or_terminal(self.inner.config.backpressure_poll_interval)
                        .await?;
                }
            }
            self.inner.check_terminal()?;
            self.inner
                .socket
                .send_with_u8_array(chunk)
                .map_err(|error| {
                    let error = Error::TransportFailed(js_error(&error));
                    self.inner.terminate(error.clone(), true);
                    error
                })?;
        }

        self.state = SendState::Open;
        Ok(())
    }
}

/// Browser WebSocket exact-length read half.
pub struct WebSocketStream {
    inner: Rc<Inner>,
    chunks: VecDeque<Bytes>,
    poisoned: bool,
}

impl WebSocketStream {
    fn drain_shared(&mut self) {
        self.chunks.append(&mut self.inner.incoming.borrow_mut());
    }

    fn available(&self) -> usize {
        self.chunks.iter().map(Bytes::len).sum()
    }

    fn take_exact(&mut self, len: usize) -> IoBufs {
        let mut remaining = len;
        let mut output = Vec::new();
        while remaining > 0 {
            let mut front = self.chunks.pop_front().expect("available bytes checked");
            if front.len() > remaining {
                let prefix = front.split_to(remaining);
                self.chunks.push_front(front);
                output.push(IoBuf::from(prefix));
                remaining = 0;
            } else {
                remaining -= front.len();
                output.push(IoBuf::from(front));
            }
        }
        self.inner
            .queued_bytes
            .set(self.inner.queued_bytes.get().saturating_sub(len));
        IoBufs::from(output)
    }
}

impl Stream for WebSocketStream {
    async fn recv(&mut self, len: usize) -> Result<IoBufs, Error> {
        if self.poisoned {
            return Err(Error::Closed);
        }
        self.poisoned = true;

        let result = poll_fn(|context| {
            self.drain_shared();
            if self.available() >= len {
                return Poll::Ready(Ok(self.take_exact(len)));
            }
            if let Err(error) = self.inner.check_terminal() {
                return Poll::Ready(Err(error));
            }
            *self.inner.receive_waker.borrow_mut() = Some(context.waker().clone());
            Poll::Pending
        })
        .await;

        if result.is_ok() {
            self.poisoned = false;
        }
        result
    }

    fn peek(&self, max_len: usize) -> &[u8] {
        let Some(front) = self.chunks.front() else {
            return &[];
        };
        &front[..front.len().min(max_len)]
    }
}

struct Handlers {
    _open: Closure<dyn FnMut(Event)>,
    _message: Closure<dyn FnMut(MessageEvent)>,
    _error: Closure<dyn FnMut(ErrorEvent)>,
    _close: Closure<dyn FnMut(CloseEvent)>,
}

struct Inner {
    socket: WebSocket,
    config: WebSocketConfig,
    opened: Cell<bool>,
    terminal: RefCell<Option<Error>>,
    incoming: RefCell<VecDeque<Bytes>>,
    queued_bytes: Cell<usize>,
    open_waker: RefCell<Option<Waker>>,
    receive_waker: RefCell<Option<Waker>>,
    send_waker: RefCell<Option<Waker>>,
    handlers: RefCell<Option<Handlers>>,
}

impl Inner {
    fn new(socket: WebSocket, config: WebSocketConfig) -> Rc<Self> {
        Rc::new(Self {
            socket,
            config,
            opened: Cell::new(false),
            terminal: RefCell::new(None),
            incoming: RefCell::new(VecDeque::new()),
            queued_bytes: Cell::new(0),
            open_waker: RefCell::new(None),
            receive_waker: RefCell::new(None),
            send_waker: RefCell::new(None),
            handlers: RefCell::new(None),
        })
    }

    fn install_handlers(self: &Rc<Self>) {
        let weak = Rc::downgrade(self);
        let open = Closure::new(move |_event: Event| {
            let Some(inner) = weak.upgrade() else {
                return;
            };
            inner.opened.set(true);
            wake(&inner.open_waker);
        });

        let weak = Rc::downgrade(self);
        let message = Closure::new(move |event: MessageEvent| {
            let Some(inner) = weak.upgrade() else {
                return;
            };
            let Ok(buffer) = event.data().dyn_into::<ArrayBuffer>() else {
                inner.terminate(Error::ProtocolViolation("text WebSocket message".into()), true);
                return;
            };
            let array = Uint8Array::new(&buffer);
            let len = array.length() as usize;
            if len > inner.config.max_message_size {
                inner.terminate(Error::ProtocolViolation("WebSocket message too large".into()), true);
                return;
            }
            let queued = inner.queued_bytes.get().saturating_add(len);
            if queued > inner.config.max_incoming_buffer {
                inner.terminate(Error::IncomingBufferExceeded, true);
                return;
            }
            let mut bytes = vec![0; len];
            array.copy_to(&mut bytes);
            inner.incoming.borrow_mut().push_back(Bytes::from(bytes));
            inner.queued_bytes.set(queued);
            wake(&inner.receive_waker);
        });

        let weak = Rc::downgrade(self);
        let error = Closure::new(move |_event: ErrorEvent| {
            let Some(inner) = weak.upgrade() else {
                return;
            };
            inner.terminate(Error::TransportFailed("WebSocket error".into()), false);
        });

        let weak = Rc::downgrade(self);
        let close = Closure::new(move |_event: CloseEvent| {
            let Some(inner) = weak.upgrade() else {
                return;
            };
            inner.terminate(Error::Closed, false);
        });

        self.socket.set_onopen(Some(open.as_ref().unchecked_ref()));
        self.socket
            .set_onmessage(Some(message.as_ref().unchecked_ref()));
        self.socket.set_onerror(Some(error.as_ref().unchecked_ref()));
        self.socket.set_onclose(Some(close.as_ref().unchecked_ref()));
        *self.handlers.borrow_mut() = Some(Handlers {
            _open: open,
            _message: message,
            _error: error,
            _close: close,
        });
    }

    fn poll_open(&self, context: &mut TaskContext<'_>) -> Poll<Result<(), Error>> {
        if let Some(error) = self.terminal.borrow().clone() {
            return Poll::Ready(Err(error));
        }
        if self.opened.get() {
            return Poll::Ready(Ok(()));
        }
        *self.open_waker.borrow_mut() = Some(context.waker().clone());
        Poll::Pending
    }

    fn check_terminal(&self) -> Result<(), Error> {
        self.terminal.borrow().clone().map_or(Ok(()), Err)
    }

    async fn wait_or_terminal(&self, duration: Duration) -> Result<(), Error> {
        let terminal = poll_fn(|context| {
            if let Some(error) = self.terminal.borrow().clone() {
                return Poll::Ready(Err(error));
            }
            *self.send_waker.borrow_mut() = Some(context.waker().clone());
            Poll::Pending
        });
        let delay = Delay::new(duration);
        pin_mut!(terminal, delay);
        match select(terminal, delay).await {
            Either::Left((result, _)) => result,
            Either::Right(_) => {
                self.send_waker.borrow_mut().take();
                Ok(())
            }
        }
    }

    fn terminate(&self, error: Error, close: bool) {
        if self.terminal.borrow().is_some() {
            return;
        }
        *self.terminal.borrow_mut() = Some(error);
        self.socket.set_onopen(None);
        self.socket.set_onmessage(None);
        self.socket.set_onerror(None);
        self.socket.set_onclose(None);
        if close {
            let _ = self.socket.close();
        }
        wake(&self.open_waker);
        wake(&self.receive_waker);
        wake(&self.send_waker);
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.socket.set_onopen(None);
        self.socket.set_onmessage(None);
        self.socket.set_onerror(None);
        self.socket.set_onclose(None);
        self.handlers.borrow_mut().take();
        let _ = self.socket.close();
    }
}

fn wake(slot: &RefCell<Option<Waker>>) {
    let waker = slot.borrow_mut().take();
    if let Some(waker) = waker {
        waker.wake();
    }
}

fn js_error(error: &wasm_bindgen::JsValue) -> String {
    error
        .as_string()
        .unwrap_or_else(|| "JavaScript WebSocket operation failed".into())
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
    fn new(duration: Duration) -> Self {
        let window = web_sys::window().expect("WebSocket transport requires a browser window");
        let state = Rc::new(DelayState {
            window,
            timer_id: Cell::new(None),
            ready: Cell::new(duration.is_zero()),
            waker: RefCell::new(None),
            callback: RefCell::new(None),
        });
        if duration.is_zero() {
            return Self { state };
        }
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
            .expect("setTimeout failed");
        state.timer_id.set(Some(timer_id));
        *state.callback.borrow_mut() = Some(callback);
        Self { state }
    }
}

impl Future for Delay {
    type Output = ();

    fn poll(self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<Self::Output> {
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
