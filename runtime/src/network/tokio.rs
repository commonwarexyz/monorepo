use crate::Error;
use prometheus_client::{metrics::counter::Counter, registry::Registry};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream,
    },
    time::timeout,
};
use tracing::warn;

#[derive(Debug)]
struct Metrics {
    inbound_connections: Counter,
    outbound_connections: Counter,
    inbound_bandwidth: Counter,
    outbound_bandwidth: Counter,
}

impl Metrics {
    fn new(registry: &mut Registry) -> Self {
        let metrics = Self {
            inbound_connections: Counter::default(),
            outbound_connections: Counter::default(),
            inbound_bandwidth: Counter::default(),
            outbound_bandwidth: Counter::default(),
        };
        registry.register(
            "inbound_connections",
            "Number of connections created by dialing us",
            metrics.inbound_connections.clone(),
        );
        registry.register(
            "outbound_connections",
            "Number of connections created by dialing others",
            metrics.outbound_connections.clone(),
        );
        registry.register(
            "inbound_bandwidth",
            "Bandwidth used by receiving data from others",
            metrics.inbound_bandwidth.clone(),
        );
        registry.register(
            "outbound_bandwidth",
            "Bandwidth used by sending data to others",
            metrics.outbound_bandwidth.clone(),
        );
        metrics
    }
}

/// Implementation of [crate::Listener] using the [tokio] runtime.
pub struct Listener {
    /// If given, enables/disables TCP_NODELAY on the socket
    tcp_nodelay: Option<bool>,
    /// Write timeout for sockets created by this listener
    write_timeout: Duration,
    /// Read timeout for sockets created by this listener
    read_timeout: Duration,
    metrics: Arc<Metrics>,
    listener: TcpListener,
}

impl crate::Listener for Listener {
    type Sink = Sink;
    type Stream = Stream;

    async fn accept(&mut self) -> Result<(SocketAddr, Self::Sink, Self::Stream), Error> {
        // Accept a new TCP stream
        let (stream, addr) = self.listener.accept().await.map_err(|_| Error::Closed)?;
        self.metrics.inbound_connections.inc();

        // Set TCP_NODELAY if configured
        if let Some(tcp_nodelay) = self.tcp_nodelay {
            if let Err(err) = stream.set_nodelay(tcp_nodelay) {
                warn!(?err, "failed to set TCP_NODELAY");
            }
        }

        // Return the sink and stream
        let (stream, sink) = stream.into_split();
        Ok((
            addr,
            Sink {
                write_timeout: self.write_timeout,
                metrics: self.metrics.clone(),
                sink,
            },
            Stream {
                read_timeout: self.read_timeout,
                metrics: self.metrics.clone(),
                stream,
            },
        ))
    }
}

impl axum::serve::Listener for Listener {
    type Io = TcpStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let (stream, addr) = self.listener.accept().await.unwrap();
        (stream, addr)
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

/// Implementation of [crate::Sink] for the `tokio` runtime.
pub struct Sink {
    write_timeout: Duration,
    metrics: Arc<Metrics>,
    sink: OwnedWriteHalf,
}

impl crate::Sink for Sink {
    async fn send(&mut self, msg: &[u8]) -> Result<(), Error> {
        let len = msg.len();
        timeout(self.write_timeout, self.sink.write_all(msg))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::SendFailed)?;
        self.metrics.outbound_bandwidth.inc_by(len as u64);
        Ok(())
    }
}

/// Implementation of [crate::Stream] for the `tokio` runtime.
pub struct Stream {
    read_timeout: Duration,
    metrics: Arc<Metrics>,
    stream: OwnedReadHalf,
}

impl crate::Stream for Stream {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        // Wait for the stream to be readable
        timeout(self.read_timeout, self.stream.read_exact(buf))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::RecvFailed)?;

        // Record metrics
        self.metrics.inbound_bandwidth.inc_by(buf.len() as u64);

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Network {
    /// If given, enables/disables TCP_NODELAY on the socket
    tcp_nodelay: Option<bool>,
    /// Write timeout for sockets created by this listener
    write_timeout: Duration,
    /// Read timeout for sockets created by this listener
    read_timeout: Duration,
    metrics: Arc<Metrics>,
}

impl crate::Network for Network {
    type Listener = Listener;

    async fn bind(&self, socket: SocketAddr) -> Result<Self::Listener, crate::Error> {
        TcpListener::bind(socket)
            .await
            .map_err(|_| Error::BindFailed)
            .map(|listener| Listener {
                tcp_nodelay: self.tcp_nodelay,
                write_timeout: self.write_timeout,
                read_timeout: self.read_timeout,
                metrics: Arc::new(Metrics::new(&mut Registry::default())), // TODO danlaine: pass registry
                listener,
            })
    }

    async fn dial(
        &self,
        socket: SocketAddr,
    ) -> Result<(crate::SinkOf<Self>, crate::StreamOf<Self>), crate::Error> {
        // Create a new TCP stream
        let stream = TcpStream::connect(socket)
            .await
            .map_err(|_| Error::ConnectionFailed)?;
        self.metrics.outbound_connections.inc();

        // Set TCP_NODELAY if configured
        if let Some(tcp_nodelay) = self.tcp_nodelay {
            if let Err(err) = stream.set_nodelay(tcp_nodelay) {
                warn!(?err, "failed to set TCP_NODELAY");
            }
        }

        // Return the sink and stream
        let (stream, sink) = stream.into_split();
        Ok((
            Sink {
                write_timeout: self.write_timeout,
                metrics: self.metrics.clone(),
                sink,
            },
            Stream {
                read_timeout: self.read_timeout,
                metrics: self.metrics.clone(),
                stream,
            },
        ))
    }
}
