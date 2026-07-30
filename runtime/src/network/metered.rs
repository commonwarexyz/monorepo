use crate::{
    Acceptor, Dialer, IoBufs, PlatformSend,
    telemetry::metrics::{Counter, Register, raw},
};
use std::sync::Arc;

#[derive(Debug)]
/// Tracks network metrics.
struct Metrics {
    /// Number of connections created by dialing us.
    inbound_connections: Counter,
    /// Number of connections created by dialing others.
    outbound_connections: Counter,
    /// Bandwidth used by receiving data from others.
    inbound_bandwidth: Counter,
    /// Bandwidth used by sending data to others.
    outbound_bandwidth: Counter,
}

impl Metrics {
    fn new(registry: &mut impl Register) -> Self {
        Self {
            inbound_connections: registry.register(
                "inbound_connections",
                "Number of connections created by dialing us",
                raw::Counter::default(),
            ),
            outbound_connections: registry.register(
                "outbound_connections",
                "Number of connections created by dialing others",
                raw::Counter::default(),
            ),
            inbound_bandwidth: registry.register(
                "inbound_bandwidth",
                "Bandwidth used by receiving data from others",
                raw::Counter::default(),
            ),
            outbound_bandwidth: registry.register(
                "outbound_bandwidth",
                "Bandwidth used by sending data to others",
                raw::Counter::default(),
            ),
        }
    }
}

/// Sends using the `inner` sink and tracks metrics for it.
pub struct Sink<S: crate::Sink> {
    inner: S,
    metrics: Arc<Metrics>,
}

impl<S: crate::Sink> crate::Sink for Sink<S> {
    async fn send(&mut self, bufs: impl Into<IoBufs> + PlatformSend) -> Result<(), crate::Error> {
        let bufs = bufs.into();
        let len = bufs.len();
        self.inner.send(bufs).await?;
        self.metrics.outbound_bandwidth.inc_by(len as u64);
        Ok(())
    }
}

/// Receives from the `inner` stream and tracks metrics for it.
pub struct Stream<S: crate::Stream> {
    inner: S,
    metrics: Arc<Metrics>,
}

/// Adds byte counters to an established connection.
pub struct Connection<C: crate::Connection> {
    inner: C,
    metrics: Arc<Metrics>,
}

impl<C: crate::Connection> crate::Connection for Connection<C> {
    type Sink = Sink<C::Sink>;
    type Stream = Stream<C::Stream>;
    type Origin = C::Origin;

    fn split(self) -> (Self::Sink, Self::Stream, crate::ConnectionInfo<Self::Origin>) {
        let (sink, stream, info) = self.inner.split();
        (
            Sink {
                inner: sink,
                metrics: Arc::clone(&self.metrics),
            },
            Stream {
                inner: stream,
                metrics: self.metrics,
            },
            info,
        )
    }
}

impl<S: crate::Stream> crate::Stream for Stream<S> {
    async fn recv(&mut self, len: usize) -> Result<IoBufs, crate::Error> {
        let bufs = self.inner.recv(len).await?;
        self.metrics.inbound_bandwidth.inc_by(len as u64);
        Ok(bufs)
    }

    fn peek(&self, max_len: usize) -> &[u8] {
        self.inner.peek(max_len)
    }
}

/// Listens for incoming connections using the `inner` listener
/// and tracks metrics for it.
pub struct Listener<L: crate::Listener> {
    inner: L,
    metrics: Arc<Metrics>,
}

impl<L: crate::Listener> crate::Listener for Listener<L> {
    type Connection = Connection<L::Connection>;

    async fn accept(&mut self) -> Result<Self::Connection, crate::Error> {
        let inner = self.inner.accept().await?;
        self.metrics.inbound_connections.inc();
        Ok(Connection {
            inner,
            metrics: Arc::clone(&self.metrics),
        })
    }
}

/// A metered network implementation which wraps another
/// [crate::Network] and tracks metrics for it.
#[derive(Debug, Clone)]
pub struct Network<N> {
    inner: N,
    /// Metrics for the network.
    /// Note these are not tracked on a per-connection basis.
    /// That would be nice but it would be very expensive
    /// and potentially an OOM vector.
    metrics: Arc<Metrics>,
}

impl<N> Network<N> {
    /// Wraps `inner` to make it metered.
    /// The `registry` is used to register the metrics.
    pub(crate) fn new(inner: N, registry: &mut impl Register) -> Self {
        let metrics = Metrics::new(registry);
        Self {
            inner,
            metrics: Arc::new(metrics),
        }
    }
}

impl<N: Dialer> Dialer for Network<N> {
    type Endpoint = N::Endpoint;
    type Connection = Connection<N::Connection>;

    fn supports(&self, endpoint: &Self::Endpoint) -> bool {
        self.inner.supports(endpoint)
    }

    async fn dial(&self, endpoint: &Self::Endpoint) -> Result<Self::Connection, crate::Error> {
        let inner = self.inner.dial(endpoint).await?;
        self.metrics.outbound_connections.inc();
        Ok(Connection {
            inner,
            metrics: Arc::clone(&self.metrics),
        })
    }
}

impl<N: Acceptor> Acceptor for Network<N> {
    type Bind = N::Bind;
    type Connection = Connection<N::Connection>;
    type Listener = Listener<N::Listener>;

    async fn bind(&self, bind: &Self::Bind) -> Result<Self::Listener, crate::Error> {
        let inner = self.inner.bind(bind).await?;
        Ok(Listener {
            inner,
            metrics: Arc::clone(&self.metrics),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        Acceptor as _, Connection as _, Dialer as _, Listener as _, Sink as _, Stream as _,
        TcpEndpoint,
        network::{
            deterministic::Network as DeterministicNetwork, metered::Network as MeteredNetwork,
            tests,
        },
    };
    use commonware_macros::test_group;
    use std::net::SocketAddr;

    impl<L: crate::TcpListener> crate::TcpListener for super::Listener<L> {
        fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
            self.inner.local_addr()
        }
    }

    #[tokio::test]
    async fn test_trait() {
        tests::test_network_trait(|| {
            let mut registry = crate::telemetry::metrics::Registry::default();
            MeteredNetwork::new(DeterministicNetwork::default(), &mut registry)
        })
        .await;
    }

    #[test_group("slow")]
    #[tokio::test]
    async fn test_stress_trait() {
        tests::stress_test_network_trait(|| {
            let mut registry = crate::telemetry::metrics::Registry::default();
            MeteredNetwork::new(DeterministicNetwork::default(), &mut registry)
        })
        .await;
    }

    #[tokio::test]
    async fn test_metrics() {
        const MSG_SIZE: usize = 100;

        // Create a registry and network
        let mut registry = crate::telemetry::metrics::Registry::default();
        let network = MeteredNetwork::new(DeterministicNetwork::default(), &mut registry);

        // Set up server.
        // Note this is a deterministic network, so we can use any address
        // since we're not actually binding to a real socket.
        let addr = SocketAddr::from(([127, 0, 0, 1], 1234));
        let mut listener = network.bind(&addr).await.unwrap();

        // Create a server task that accepts one connection and echoes data
        let server = tokio::spawn(async move {
            let (mut sink, mut stream, _) = listener.accept().await.unwrap().split();
            let received = stream.recv(MSG_SIZE).await.unwrap();
            sink.send(received).await.unwrap();
        });

        // Send and receive data as client
        let (mut client_sink, mut client_stream, _) = network
            .dial(&TcpEndpoint::Socket(addr))
            .await
            .unwrap()
            .split();

        // Send fixed-size data and receive response
        let msg = vec![42u8; MSG_SIZE];
        client_sink.send(msg.clone()).await.unwrap();

        let response = client_stream.recv(MSG_SIZE).await.unwrap().coalesce();
        assert_eq!(response.len(), MSG_SIZE);
        assert_eq!(response, msg.as_slice());

        // Wait for server to complete
        server.await.unwrap();

        // Verify metrics were incremented correctly
        assert_eq!(network.metrics.inbound_connections.get(), 1,);
        assert_eq!(network.metrics.outbound_connections.get(), 1,);
        assert_eq!(
            network.metrics.inbound_bandwidth.get(),
            2 * MSG_SIZE as u64,
            "client and server should both have received MSG_SIZE"
        );
        assert_eq!(
            network.metrics.outbound_bandwidth.get(),
            2 * MSG_SIZE as u64,
            "client and server should both have sent MSG_SIZE"
        );
    }
}
