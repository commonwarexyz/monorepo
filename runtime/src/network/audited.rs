use crate::{Acceptor, Dialer, Error, IoBufs, deterministic::Auditor};
use std::sync::Arc;

/// A sink that audits network operations.
pub struct Sink<S: crate::Sink> {
    auditor: Arc<Auditor>,
    inner: S,
    remote: String,
}

impl<S: crate::Sink> crate::Sink for Sink<S> {
    async fn send(&mut self, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        let bufs = bufs.into();
        self.auditor.event(b"send_attempt", |hasher| {
            hasher.update(self.remote.as_bytes());
            hasher.update_bufs(&bufs);
        });

        self.inner.send(bufs).await.inspect_err(|e| {
            self.auditor.event(b"send_failure", |hasher| {
                hasher.update(self.remote.as_bytes());
                hasher.update(e.to_string().as_bytes());
            });
        })?;

        self.auditor.event(b"send_success", |hasher| {
            hasher.update(self.remote.as_bytes());
        });
        Ok(())
    }
}

/// A stream that audits network operations.
pub struct Stream<S: crate::Stream> {
    auditor: Arc<Auditor>,
    inner: S,
    remote: String,
}

impl<S: crate::Stream> crate::Stream for Stream<S> {
    async fn recv(&mut self, len: usize) -> Result<IoBufs, Error> {
        self.auditor.event(b"recv_attempt", |hasher| {
            hasher.update(self.remote.as_bytes());
            hasher.update(len.to_be_bytes());
        });

        let bufs = self.inner.recv(len).await.inspect_err(|e| {
            self.auditor.event(b"recv_failure", |hasher| {
                hasher.update(self.remote.as_bytes());
                hasher.update(e.to_string().as_bytes());
            });
        })?;

        self.auditor.event(b"recv_success", |hasher| {
            hasher.update(self.remote.as_bytes());
            hasher.update_bufs(&bufs);
        });

        Ok(bufs)
    }

    fn peek(&self, max_len: usize) -> &[u8] {
        self.inner.peek(max_len)
    }
}

pub struct Connection<C: crate::Connection> {
    auditor: Arc<Auditor>,
    inner: C,
    remote: Option<String>,
}

impl<C: crate::Connection> crate::Connection for Connection<C> {
    type Sink = Sink<C::Sink>;
    type Stream = Stream<C::Stream>;
    type Origin = C::Origin;

    fn split(
        self,
    ) -> (
        Self::Sink,
        Self::Stream,
        crate::ConnectionInfo<Self::Origin>,
    ) {
        let (sink, stream, info) = self.inner.split();
        let remote = self.remote.unwrap_or_else(|| format!("{:?}", info.origin));
        (
            Sink {
                auditor: Arc::clone(&self.auditor),
                inner: sink,
                remote: remote.clone(),
            },
            Stream {
                auditor: self.auditor,
                inner: stream,
                remote,
            },
            info,
        )
    }
}

/// A listener that audits network operations.
pub struct Listener<L: crate::Listener> {
    auditor: Arc<Auditor>,
    inner: L,
    bind: String,
}

impl<L: crate::Listener> crate::Listener for Listener<L> {
    type Connection = Connection<L::Connection>;

    async fn accept(&mut self) -> Result<Self::Connection, Error> {
        self.auditor.event(b"accept_attempt", |hasher| {
            hasher.update(self.bind.as_bytes());
        });

        let inner = self.inner.accept().await.inspect_err(|e| {
            self.auditor.event(b"accept_failure", |hasher| {
                hasher.update(self.bind.as_bytes());
                hasher.update(e.to_string().as_bytes());
            });
        })?;
        self.auditor.event(b"accept_success", |hasher| {
            hasher.update(self.bind.as_bytes());
        });

        Ok(Connection {
            auditor: Arc::clone(&self.auditor),
            inner,
            remote: None,
        })
    }
}

/// An audited network implementation which wraps another
/// transport and records audit events for network operations.
#[derive(Clone)]
pub struct Network<N> {
    auditor: Arc<Auditor>,
    inner: N,
}

impl<N> Network<N> {
    /// Creates a new audited network that wraps the provided network implementation.
    pub const fn new(inner: N, auditor: Arc<Auditor>) -> Self {
        Self { auditor, inner }
    }
}

impl<N: Acceptor> Acceptor for Network<N> {
    type Bind = N::Bind;
    type Connection = Connection<N::Connection>;
    type Listener = Listener<N::Listener>;

    async fn bind(&self, bind: &Self::Bind) -> Result<Self::Listener, Error> {
        let bind_label = format!("{bind:?}");
        self.auditor.event(b"bind_attempt", |hasher| {
            hasher.update(bind_label.as_bytes());
        });

        let inner = self.inner.bind(bind).await.inspect_err(|e| {
            self.auditor.event(b"bind_failure", |hasher| {
                hasher.update(bind_label.as_bytes());
                hasher.update(e.to_string().as_bytes());
            });
        })?;

        self.auditor.event(b"bind_success", |hasher| {
            hasher.update(bind_label.as_bytes());
        });

        Ok(Listener {
            auditor: Arc::clone(&self.auditor),
            inner,
            bind: bind_label,
        })
    }
}

impl<N: Dialer> Dialer for Network<N> {
    type Endpoint = N::Endpoint;
    type Connection = Connection<N::Connection>;

    fn supports(&self, endpoint: &Self::Endpoint) -> bool {
        self.inner.supports(endpoint)
    }

    async fn dial(&self, endpoint: &Self::Endpoint) -> Result<Self::Connection, Error> {
        let remote = format!("{endpoint:?}");
        self.auditor.event(b"dial_attempt", |hasher| {
            hasher.update(remote.as_bytes());
        });

        let inner = self.inner.dial(endpoint).await.inspect_err(|e| {
            self.auditor.event(b"dial_failure", |hasher| {
                hasher.update(remote.as_bytes());
                hasher.update(e.to_string().as_bytes());
            });
        })?;

        self.auditor.event(b"dial_success", |hasher| {
            hasher.update(remote.as_bytes());
        });

        Ok(Connection {
            auditor: Arc::clone(&self.auditor),
            inner,
            remote: Some(remote),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        Acceptor as _, Connection as _, Dialer as _, Error, IoBuf, IoBufs, Listener as _,
        Sink as _, Stream as _, TcpEndpoint,
        deterministic::Auditor,
        network::{
            audited::Network as AuditedNetwork, deterministic::Network as DeterministicNetwork,
            tests,
        },
    };
    use commonware_macros::test_group;
    use commonware_utils::sync::Mutex;
    use std::{net::SocketAddr, sync::Arc};

    impl<L: crate::TcpListener> crate::TcpListener for super::Listener<L> {
        fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
            self.inner.local_addr()
        }
    }

    #[derive(Clone)]
    struct RecordingSink {
        chunk_counts: Arc<Mutex<Vec<usize>>>,
    }

    impl crate::Sink for RecordingSink {
        async fn send(&mut self, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
            self.chunk_counts.lock().push(bufs.into().chunk_count());
            Ok(())
        }
    }

    #[derive(Clone)]
    struct RecordingStream {
        bufs: Arc<Mutex<Option<IoBufs>>>,
    }

    impl crate::Stream for RecordingStream {
        async fn recv(&mut self, _len: usize) -> Result<IoBufs, Error> {
            Ok(self.bufs.lock().take().unwrap())
        }

        fn peek(&self, _max_len: usize) -> &[u8] {
            &[]
        }
    }

    #[tokio::test]
    async fn test_trait() {
        tests::test_network_trait(|| {
            AuditedNetwork::new(
                DeterministicNetwork::default(),
                Arc::new(Auditor::default()),
            )
        })
        .await;
    }

    #[test_group("slow")]
    #[tokio::test]
    async fn test_stress_trait() {
        tests::stress_test_network_trait(|| {
            AuditedNetwork::new(
                DeterministicNetwork::default(),
                Arc::new(Auditor::default()),
            )
        })
        .await;
    }

    // Test that running the same network operations on two audited networks
    // produces the same audit events.
    #[tokio::test]
    async fn test_audit() {
        const SERVER_MSG: &str = "server";
        const CLIENT_MSG: &str = "client";

        // Create two identical deterministic networks with separate auditors
        let auditors = [Arc::new(Auditor::default()), Arc::new(Auditor::default())];
        let networks = [
            AuditedNetwork::new(DeterministicNetwork::default(), auditors[0].clone()),
            AuditedNetwork::new(DeterministicNetwork::default(), auditors[1].clone()),
        ];

        // Helper function to verify auditor states match
        let verify_auditors = |msg: &str| {
            assert_eq!(
                auditors[0].state(),
                auditors[1].state(),
                "Auditor states differ: {msg}"
            );
        };

        // Step 1: Test binding to an address
        //
        // Note that we're using a deterministic network, so both networks can use
        // the same address because we're not actually binding to it.
        let listener_addr = SocketAddr::from(([127, 0, 0, 1], 1234));
        let listeners = [
            networks[0].bind(&listener_addr).await.unwrap(),
            networks[1].bind(&listener_addr).await.unwrap(),
        ];
        verify_auditors("after binding");

        // Step 2: Test accepting connections
        let mut server_handles = Vec::new();
        for mut listener in listeners {
            let handle = tokio::spawn(async move {
                let (mut sink, mut stream, _) = listener.accept().await.unwrap().split();

                // Receive data from client
                let received = stream.recv(CLIENT_MSG.len()).await.unwrap();
                assert_eq!(received.coalesce(), CLIENT_MSG.as_bytes());

                // Send response
                sink.send(SERVER_MSG.as_bytes()).await.unwrap();
            });
            server_handles.push(handle);
        }
        verify_auditors("after accepting connections");

        // Step 3: Test dialing and data exchange
        let mut client_handles = Vec::new();
        for network in &networks {
            let network = network.clone();
            let handle = tokio::spawn(async move {
                let (mut sink, mut stream, _) = network
                    .dial(&TcpEndpoint::Socket(listener_addr))
                    .await
                    .unwrap()
                    .split();

                // Send data to server
                sink.send(CLIENT_MSG.as_bytes()).await.unwrap();

                // Receive response
                let received = stream.recv(SERVER_MSG.len()).await.unwrap();
                assert_eq!(received.coalesce(), SERVER_MSG.as_bytes());
            });
            client_handles.push(handle);
        }
        // Wait for all tasks to complete
        for handle in server_handles {
            handle.await.unwrap();
        }
        verify_auditors("after network operations");

        // Step 4: Test error conditions (attempting to bind to same address again)
        for network in &networks {
            let result = network.bind(&listener_addr).await;
            assert!(result.is_err());
        }
        verify_auditors("after bind error");

        // Step 5: Test dialing to non-existent server
        let bad_addr = SocketAddr::from(([127, 0, 0, 1], 9999));
        for network in &networks {
            let result = network.dial(&TcpEndpoint::Socket(bad_addr)).await;
            assert!(result.is_err());
        }
        verify_auditors("after failed dial attempts");
    }

    #[tokio::test]
    async fn test_sink_preserves_chunking() {
        let chunk_counts = Arc::new(Mutex::new(Vec::new()));
        let mut sink = super::Sink {
            auditor: Arc::new(Auditor::default()),
            inner: RecordingSink {
                chunk_counts: chunk_counts.clone(),
            },
            remote: SocketAddr::from(([127, 0, 0, 1], 1234)).to_string(),
        };

        sink.send(IoBufs::from(vec![
            IoBuf::from(b"a".to_vec()),
            IoBuf::from(b"b".to_vec()),
            IoBuf::from(b"c".to_vec()),
            IoBuf::from(b"d".to_vec()),
        ]))
        .await
        .unwrap();

        assert_eq!(*chunk_counts.lock(), vec![4]);
    }

    #[tokio::test]
    async fn test_stream_preserves_chunking() {
        let mut stream = super::Stream {
            auditor: Arc::new(Auditor::default()),
            inner: RecordingStream {
                bufs: Arc::new(Mutex::new(Some(IoBufs::from(vec![
                    IoBuf::from(b"a".to_vec()),
                    IoBuf::from(b"b".to_vec()),
                    IoBuf::from(b"c".to_vec()),
                    IoBuf::from(b"d".to_vec()),
                ])))),
            },
            remote: SocketAddr::from(([127, 0, 0, 1], 1234)).to_string(),
        };

        let received = stream.recv(4).await.unwrap();
        assert_eq!(received.chunk_count(), 4);
        assert_eq!(received.coalesce(), b"abcd");
    }
}
