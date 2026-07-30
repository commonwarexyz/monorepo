use super::{ConfigError, WebSocketConfig};
use bytes::Bytes;
use commonware_runtime::{
    Connection, ConnectionInfo, Error, IoBuf, IoBufs, PlatformSend, Sink, Stream,
};
use commonware_utils::sync::Mutex;
use futures::{SinkExt, StreamExt, stream::SplitSink, stream::SplitStream};
use std::{
    collections::VecDeque,
    fmt::Debug,
    net::SocketAddr,
    sync::Arc,
};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{
    WebSocketStream as TungsteniteStream, accept_hdr_async_with_config,
    tungstenite::{
        Error as TungsteniteError, Message,
        handshake::server::{Callback, ErrorResponse, Request, Response},
        protocol::WebSocketConfig as TungsteniteConfig,
    },
};

/// HTTP request presented before the WebSocket upgrade is accepted.
pub type UpgradeRequest = Request;

/// HTTP response sent when the WebSocket upgrade is accepted.
pub type UpgradeResponse = Response;

/// HTTP response sent when admission rejects a WebSocket upgrade.
pub type UpgradeErrorResponse = Box<ErrorResponse>;

/// Synchronous admission policy for inbound WebSocket upgrades.
///
/// The policy can validate paths, headers, and application-defined capabilities. The transport
/// does not interpret any of those values. A successful permit is attached to the connection's
/// transport metadata and is never sent over the byte stream.
pub trait Admission: Send + Sync + 'static {
    type Permit: Clone + Debug + Send + Sync + 'static;

    /// Validate an upgrade and optionally modify its successful response.
    fn admit(
        &self,
        remote: SocketAddr,
        request: &UpgradeRequest,
        response: &mut UpgradeResponse,
    ) -> Result<Self::Permit, UpgradeErrorResponse>;
}

impl<F, P> Admission for F
where
    F: Fn(SocketAddr, &UpgradeRequest, &mut UpgradeResponse) -> Result<P, UpgradeErrorResponse>
        + Send
        + Sync
        + 'static,
    P: Clone + Debug + Send + Sync + 'static,
{
    type Permit = P;

    fn admit(
        &self,
        remote: SocketAddr,
        request: &UpgradeRequest,
        response: &mut UpgradeResponse,
    ) -> Result<Self::Permit, UpgradeErrorResponse> {
        self(remote, request, response)
    }
}

/// Native WebSocket acceptor backed by Tokio and Tungstenite.
#[derive(Clone)]
pub struct WebSocketAcceptor<A> {
    admission: Arc<A>,
    config: WebSocketConfig,
}

impl<A: Admission> WebSocketAcceptor<A> {
    /// Create an acceptor after validating its resource limits.
    pub fn new(config: WebSocketConfig, admission: A) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self {
            admission: Arc::new(admission),
            config,
        })
    }
}

impl<A: Admission> commonware_runtime::Acceptor for WebSocketAcceptor<A> {
    type Bind = SocketAddr;
    type Connection = WebSocketConnection<A::Permit>;
    type Listener = WebSocketListener<A>;

    async fn bind(&self, bind: &Self::Bind) -> Result<Self::Listener, Error> {
        let listener = TcpListener::bind(bind).await.map_err(|_| Error::BindFailed)?;
        Ok(WebSocketListener {
            admission: Arc::clone(&self.admission),
            config: self.config.clone(),
            listener,
        })
    }
}

/// Bound native WebSocket listener.
pub struct WebSocketListener<A> {
    admission: Arc<A>,
    config: WebSocketConfig,
    listener: TcpListener,
}

impl<A: Admission> commonware_runtime::Listener for WebSocketListener<A> {
    type Connection = WebSocketConnection<A::Permit>;

    async fn accept(&mut self) -> Result<Self::Connection, Error> {
        let (stream, remote) = self.listener.accept().await.map_err(|_| Error::Closed)?;
        let permit = Arc::new(Mutex::new(None));
        let captured_permit = Arc::clone(&permit);
        let admission = Arc::clone(&self.admission);

        let callback = UpgradeCallback {
            admission,
            permit: captured_permit,
            remote,
        };
        let websocket = accept_hdr_async_with_config(
            stream,
            callback,
            Some(tungstenite_config(&self.config)),
        )
        .await
        .map_err(|_| Error::ConnectionFailed)?;
        let permit = permit
            .lock()
            .take()
            .expect("successful upgrade must produce an admission permit");
        let (sink, stream) = websocket.split();

        Ok(WebSocketConnection {
            sink: WebSocketSink {
                config: self.config.clone(),
                sink,
                state: SendState::Open,
            },
            stream: WebSocketStream {
                buffered: VecDeque::new(),
                buffered_len: 0,
                config: self.config.clone(),
                poisoned: false,
                stream,
            },
            origin: WebSocketOrigin { permit, remote },
        })
    }
}

struct UpgradeCallback<A: Admission> {
    admission: Arc<A>,
    permit: Arc<Mutex<Option<A::Permit>>>,
    remote: SocketAddr,
}

impl<A: Admission> Callback for UpgradeCallback<A> {
    #[allow(clippy::result_large_err)]
    fn on_request(
        self,
        request: &Request,
        mut response: Response,
    ) -> Result<Response, ErrorResponse> {
        let permit = self
            .admission
            .admit(self.remote, request, &mut response)
            .map_err(|response| *response)?;
        *self.permit.lock() = Some(permit);
        Ok(response)
    }
}

impl<A: Admission> commonware_runtime::TcpListener for WebSocketListener<A> {
    fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.listener.local_addr()
    }
}

/// Transport-observed metadata for an admitted native WebSocket connection.
#[derive(Clone, Debug)]
pub struct WebSocketOrigin<P> {
    remote: SocketAddr,
    permit: P,
}

impl<P> WebSocketOrigin<P> {
    /// Return the TCP peer observed by the acceptor.
    pub const fn remote(&self) -> SocketAddr {
        self.remote
    }

    /// Return the application-defined permit produced during admission.
    pub const fn permit(&self) -> &P {
        &self.permit
    }
}

/// Established native WebSocket connection.
pub struct WebSocketConnection<P>
where
    P: Clone + Debug + Send + Sync + 'static,
{
    sink: WebSocketSink,
    stream: WebSocketStream,
    origin: WebSocketOrigin<P>,
}

impl<P> Connection for WebSocketConnection<P>
where
    P: Clone + Debug + Send + Sync + 'static,
{
    type Sink = WebSocketSink;
    type Stream = WebSocketStream;
    type Origin = WebSocketOrigin<P>;

    fn split(self) -> (Self::Sink, Self::Stream, ConnectionInfo<Self::Origin>) {
        (
            self.sink,
            self.stream,
            ConnectionInfo {
                origin: Some(self.origin),
                transport: "websocket",
            },
        )
    }
}

type NativeSocket = TungsteniteStream<TcpStream>;
type NativeSink = SplitSink<NativeSocket, Message>;
type NativeStream = SplitStream<NativeSocket>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum SendState {
    Open,
    Sending,
    Closed,
}

/// Native WebSocket write half.
pub struct WebSocketSink {
    config: WebSocketConfig,
    sink: NativeSink,
    state: SendState,
}

impl Sink for WebSocketSink {
    async fn send(
        &mut self,
        bufs: impl Into<IoBufs> + PlatformSend,
    ) -> Result<(), Error> {
        match self.state {
            SendState::Open => self.state = SendState::Sending,
            SendState::Sending => {
                self.state = SendState::Closed;
                return Err(Error::Closed);
            }
            SendState::Closed => return Err(Error::Closed),
        }

        let buffer = bufs.into().coalesce();
        for chunk in buffer.as_ref().chunks(self.config.max_message_size) {
            if self
                .sink
                .send(Message::Binary(Bytes::copy_from_slice(chunk)))
                .await
                .is_err()
            {
                self.state = SendState::Closed;
                return Err(Error::SendFailed);
            }
        }

        self.state = SendState::Open;
        Ok(())
    }
}

/// Native WebSocket exact-length read half.
pub struct WebSocketStream {
    buffered: VecDeque<Bytes>,
    buffered_len: usize,
    config: WebSocketConfig,
    poisoned: bool,
    stream: NativeStream,
}

impl WebSocketStream {
    fn take_buffered(&mut self, remaining: &mut usize, output: &mut Vec<IoBuf>) {
        while *remaining > 0 {
            let Some(mut front) = self.buffered.pop_front() else {
                return;
            };
            if front.len() > *remaining {
                let prefix = front.split_to(*remaining);
                self.buffered.push_front(front);
                output.push(IoBuf::from(prefix));
                self.buffered_len -= *remaining;
                *remaining = 0;
                break;
            }
            *remaining -= front.len();
            self.buffered_len -= front.len();
            output.push(IoBuf::from(front));
        }
    }

    async fn receive_exact(&mut self, len: usize) -> Result<IoBufs, Error> {
        let mut remaining = len;
        let mut output = Vec::new();
        self.take_buffered(&mut remaining, &mut output);

        while remaining > 0 {
            let Some(message) = self.stream.next().await else {
                return Err(Error::RecvFailed);
            };
            match message {
                Ok(Message::Binary(mut bytes)) => {
                    if bytes.len() > self.config.max_message_size {
                        return Err(Error::ProtocolViolation("WebSocket message too large".into()));
                    }
                    if bytes.len() > remaining {
                        let prefix = bytes.split_to(remaining);
                        output.push(IoBuf::from(prefix));
                        self.buffered_len = bytes.len();
                        self.buffered.push_back(bytes);
                        remaining = 0;
                        continue;
                    }
                    remaining -= bytes.len();
                    output.push(IoBuf::from(bytes));
                }
                Ok(Message::Text(_)) => {
                    return Err(Error::ProtocolViolation("text WebSocket message".into()));
                }
                Ok(Message::Close(_)) => return Err(Error::Closed),
                Ok(Message::Ping(_) | Message::Pong(_)) => {}
                Ok(Message::Frame(_)) => {
                    return Err(Error::ProtocolViolation("raw WebSocket frame".into()));
                }
                Err(TungsteniteError::Capacity(_)) => {
                    return Err(Error::ProtocolViolation("WebSocket message too large".into()));
                }
                Err(_) => return Err(Error::RecvFailed),
            }
        }
        Ok(IoBufs::from(output))
    }
}

impl Stream for WebSocketStream {
    async fn recv(&mut self, len: usize) -> Result<IoBufs, Error> {
        if self.poisoned {
            return Err(Error::Closed);
        }
        self.poisoned = true;

        let result = self.receive_exact(len).await;
        if result.is_ok() {
            self.poisoned = false;
        }
        result
    }

    fn peek(&self, max_len: usize) -> &[u8] {
        let Some(front) = self.buffered.front() else {
            return &[];
        };
        &front[..front.len().min(max_len)]
    }
}

fn tungstenite_config(config: &WebSocketConfig) -> TungsteniteConfig {
    TungsteniteConfig::default()
        .max_message_size(Some(config.max_message_size))
        .max_frame_size(Some(config.max_message_size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{Acceptor as _, Listener as _, TcpListener as _};
    use futures::SinkExt;
    use tokio_tungstenite::{client_async, tungstenite::Message};

    async fn connection() -> (WebSocketStream, SplitSink<NativeSocket, Message>) {
        let admission = |_remote, _request: &UpgradeRequest, _response: &mut UpgradeResponse| {
            Ok::<_, UpgradeErrorResponse>(())
        };
        let acceptor = WebSocketAcceptor::new(WebSocketConfig::default(), admission).unwrap();
        let mut listener = acceptor.bind(&"127.0.0.1:0".parse().unwrap()).await.unwrap();
        let address = listener.local_addr().unwrap();

        let server = tokio::spawn(async move { listener.accept().await.unwrap() });
        let tcp = TcpStream::connect(address).await.unwrap();
        let (client, _) = client_async(format!("ws://{address}/test"), tcp).await.unwrap();
        let connection = server.await.unwrap();
        let (_, stream, info) = connection.split();
        assert_eq!(info.origin.unwrap().permit(), &());
        let (client_sink, _) = client.split();
        (stream, client_sink)
    }

    #[tokio::test]
    async fn removes_binary_message_boundaries() {
        let (mut stream, mut client) = connection().await;
        client
            .send(Message::binary(&b"ab"[..]))
            .await
            .unwrap();
        client
            .send(Message::binary(&b"cdef"[..]))
            .await
            .unwrap();

        let bytes = stream.recv(4).await.unwrap().coalesce();
        assert_eq!(bytes.as_ref(), b"abcd");
        assert_eq!(stream.peek(10), b"ef");
        let bytes = stream.recv(2).await.unwrap().coalesce();
        assert_eq!(bytes.as_ref(), b"ef");
    }

    #[tokio::test]
    async fn rejects_text_messages() {
        let (mut stream, mut client) = connection().await;
        client.send(Message::text("not bytes")).await.unwrap();

        assert!(matches!(
            stream.recv(1).await,
            Err(Error::ProtocolViolation(_))
        ));
        assert!(matches!(stream.recv(1).await, Err(Error::Closed)));
    }

    #[tokio::test]
    async fn canceled_receive_poisons_stream() {
        let (mut stream, _client) = connection().await;
        let mut receive = Box::pin(stream.recv(1));
        assert!(futures::poll!(&mut receive).is_pending());
        drop(receive);

        assert!(matches!(stream.recv(1).await, Err(Error::Closed)));
    }
}
