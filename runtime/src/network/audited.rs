use crate::{deterministic::Auditor, Error, SinkOf, StreamOf};
use sha2::Digest;
use std::{net::SocketAddr, sync::Arc};

/// A sink that audits network operations.
pub struct Sink<S: crate::Sink> {
    auditor: Arc<Auditor>,
    inner: S,
    remote_addr: SocketAddr,
}

impl<S: crate::Sink> crate::Sink for Sink<S> {
    async fn send(&mut self, data: &[u8]) -> Result<(), Error> {
        self.auditor.event(b"send_attempt", |hasher| {
            hasher.update(self.remote_addr.to_string().as_bytes());
            hasher.update(data);
        });

        self.inner.send(data).await.inspect_err(|e| {
            self.auditor.event(b"send_failure", |hasher| {
                hasher.update(self.remote_addr.to_string().as_bytes());
                hasher.update(e.to_string().as_bytes());
            });
        })?;

        self.auditor.event(b"send_success", |hasher| {
            hasher.update(self.remote_addr.to_string().as_bytes());
            hasher.update(data);
        });
        Ok(())
    }
}

/// A stream that audits network operations.
pub struct Stream<S: crate::Stream> {
    auditor: Arc<Auditor>,
    inner: S,
    remote_addr: SocketAddr,
}

impl<S: crate::Stream> crate::Stream for Stream<S> {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        self.auditor.event(b"recv_attempt", |hasher| {
            hasher.update(self.remote_addr.to_string().as_bytes());
        });

        self.inner.recv(buf).await.inspect_err(|e| {
            self.auditor.event(b"recv_failure", |hasher| {
                hasher.update(self.remote_addr.to_string().as_bytes());
                hasher.update(e.to_string().as_bytes());
            });
        })?;

        self.auditor.event(b"recv_success", |hasher| {
            hasher.update(self.remote_addr.to_string().as_bytes());
            hasher.update(buf);
        });
        Ok(())
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
        self.auditor.event(b"accept_attempt", |hasher| {
            hasher.update(self.local_addr.to_string().as_bytes());
        });

        let (addr, sink, stream) = self.inner.accept().await.inspect_err(|e| {
            self.auditor.event(b"accept_failure", |hasher| {
                hasher.update(self.local_addr.to_string().as_bytes());
                hasher.update(e.to_string().as_bytes());
            });
        })?;

        self.auditor.event(b"accept_success", |hasher| {
            hasher.update(self.local_addr.to_string().as_bytes());
            hasher.update(addr.to_string().as_bytes());
        });

        Ok((
            addr,
            Sink {
                auditor: self.auditor.clone(),
                inner: sink,
                remote_addr: addr,
            },
            Stream {
                auditor: self.auditor.clone(),
                inner: stream,
                remote_addr: addr,
            },
        ))
    }

    fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.inner.local_addr()
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

    async fn bind(&self, local_addr: SocketAddr) -> Result<Self::Listener, Error> {
        self.auditor.event(b"bind_attempt", |hasher| {
            hasher.update(local_addr.to_string().as_bytes());
        });

        let inner = self.inner.bind(local_addr).await.inspect_err(|e| {
            self.auditor.event(b"bind_failure", |hasher| {
                hasher.update(local_addr.to_string().as_bytes());
                hasher.update(e.to_string().as_bytes());
            });
        })?;

        self.auditor.event(b"bind_success", |hasher| {
            hasher.update(local_addr.to_string().as_bytes());
        });

        Ok(Listener {
            auditor: self.auditor.clone(),
            inner,
            local_addr,
        })
    }

    async fn dial(&self, remote_addr: SocketAddr) -> Result<(SinkOf<Self>, StreamOf<Self>), Error> {
        self.auditor.event(b"dial_attempt", |hasher| {
            hasher.update(remote_addr.to_string().as_bytes());
        });

        let (sink, stream) = self.inner.dial(remote_addr).await.inspect_err(|e| {
            self.auditor.event(b"dial_failure", |hasher| {
                hasher.update(remote_addr.to_string().as_bytes());
                hasher.update(e.to_string().as_bytes());
            });
        })?;

        self.auditor.event(b"dial_success", |hasher| {
            hasher.update(remote_addr.to_string().as_bytes());
        });

        Ok((
            Sink {
                auditor: self.auditor.clone(),
                inner: sink,
                remote_addr,
            },
            Stream {
                auditor: self.auditor.clone(),
                inner: stream,
                remote_addr,
            },
        ))
    }
}
