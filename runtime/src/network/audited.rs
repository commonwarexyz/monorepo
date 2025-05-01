use crate::{deterministic::Auditor, Error, SinkOf, StreamOf};
use sha2::Digest;
use std::{net::SocketAddr, sync::Arc};

/// A sink that audits network operations.
pub struct Sink<S: crate::Sink> {
    auditor: Arc<Auditor>,
    inner: S,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

impl<S: crate::Sink> crate::Sink for Sink<S> {
    async fn send(&mut self, data: &[u8]) -> Result<(), Error> {
        self.auditor.event(b"send", |hasher| {
            hasher.update(self.local_addr.to_string().as_bytes());
            hasher.update(self.remote_addr.to_string().as_bytes());
            hasher.update(data);
        });
        self.inner.send(data).await
    }
}

/// A stream that audits network operations.
pub struct Stream<S: crate::Stream> {
    auditor: Arc<Auditor>,
    inner: S,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

impl<S: crate::Stream> crate::Stream for Stream<S> {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        let result = self.inner.recv(buf).await;
        if result.is_ok() {
            self.auditor.event(b"recv", |hasher| {
                hasher.update(self.local_addr.to_string().as_bytes());
                hasher.update(self.remote_addr.to_string().as_bytes());
                hasher.update(buf);
            });
        }
        result
    }
}

/// A listener that audits network operations.
pub struct Listener<L: crate::Listener> {
    auditor: Arc<Auditor>,
    inner: L,
    local_addr: SocketAddr,
}

impl<L: crate::Listener> crate::Listener for Listener<L> {
    type Sink = Sink<L::Sink>;
    type Stream = Stream<L::Stream>;

    async fn accept(&mut self) -> Result<(SocketAddr, Self::Sink, Self::Stream), Error> {
        let (addr, sink, stream) = self.inner.accept().await?;

        self.auditor.event(b"accept", |hasher| {
            hasher.update(self.local_addr.to_string().as_bytes());
            hasher.update(addr.to_string().as_bytes());
        });

        Ok((
            addr,
            Sink {
                auditor: self.auditor.clone(),
                inner: sink,
                local_addr: self.local_addr,
                remote_addr: addr,
            },
            Stream {
                auditor: self.auditor.clone(),
                inner: stream,
                local_addr: self.local_addr,
                remote_addr: addr,
            },
        ))
    }
}

/// An audited network implementation which wraps another
/// [crate::Network] and records audit events for network operations.
#[derive(Clone)]
pub struct Network<N: crate::Network> {
    auditor: Arc<Auditor>,
    inner: N,
}

impl<N: crate::Network> Network<N> {
    /// Creates a new audited network that wraps the provided network implementation.
    pub fn new(inner: N, auditor: Arc<Auditor>) -> Self {
        Self { auditor, inner }
    }
}

impl<N: crate::Network> crate::Network for Network<N> {
    type Listener = Listener<N::Listener>;

    async fn bind(&self, socket: SocketAddr) -> Result<Self::Listener, Error> {
        self.auditor.event(b"bind", |hasher| {
            hasher.update(socket.to_string().as_bytes());
        });

        let inner = self.inner.bind(socket).await?;

        Ok(Listener {
            auditor: self.auditor.clone(),
            inner,
            local_addr: socket,
        })
    }

    async fn dial(&self, socket: SocketAddr) -> Result<(SinkOf<Self>, StreamOf<Self>), Error> {
        // Assume we get local address from the connection itself
        // In a real implementation, we'd get this from the socket
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 0));

        self.auditor.event(b"dial", |hasher| {
            hasher.update(local_addr.to_string().as_bytes());
            hasher.update(socket.to_string().as_bytes());
        });

        let (sink, stream) = self.inner.dial(socket).await?;

        Ok((
            Sink {
                auditor: self.auditor.clone(),
                inner: sink,
                local_addr,
                remote_addr: socket,
            },
            Stream {
                auditor: self.auditor.clone(),
                inner: stream,
                local_addr,
                remote_addr: socket,
            },
        ))
    }
}
