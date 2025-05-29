use crate::{SinkOf, StreamOf};
use commonware_utils::StableBuf;
use prometheus_client::{metrics::counter::Counter, registry::Registry};
use std::{net::SocketAddr, sync::Arc};

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

/// Sends using the `inner` sink and tracks metrics for it.
pub struct Sink<S: crate::Sink> {
    inner: S,
    metrics: Arc<Metrics>,
}

impl<S: crate::Sink> crate::Sink for Sink<S> {
    async fn send(&mut self, data: impl Into<StableBuf> + Send) -> Result<(), crate::Error> {
        let data = data.into();
        let len = data.len();
        self.inner.send(data).await?;
        self.metrics.outbound_bandwidth.inc_by(len as u64);
        Ok(())
    }
}

/// Receives from the `inner` stream and tracks metrics for it.
pub struct Stream<S: crate::Stream> {
    inner: S,
    metrics: Arc<Metrics>,
}

impl<S: crate::Stream> crate::Stream for Stream<S> {
    async fn recv(&mut self, buf: impl Into<StableBuf> + Send) -> Result<StableBuf, crate::Error> {
        let buf = self.inner.recv(buf).await?;
        self.metrics.inbound_bandwidth.inc_by(buf.len() as u64);
        Ok(buf)
    }
}

/// Listens for incoming connections using the `inner` listener
/// and tracks metrics for it.
pub struct Listener<L: crate::Listener> {
    inner: L,
    metrics: Arc<Metrics>,
}

impl<L: crate::Listener> crate::Listener for Listener<L> {
    type Sink = Sink<L::Sink>;
    type Stream = Stream<L::Stream>;

    async fn accept(&mut self) -> Result<(SocketAddr, Self::Sink, Self::Stream), crate::Error> {
        let (addr, sink, stream) = self.inner.accept().await?;
        self.metrics.inbound_connections.inc();
        Ok((
            addr,
            Sink {
                inner: sink,
                metrics: self.metrics.clone(),
            },
            Stream {
                inner: stream,
                metrics: self.metrics.clone(),
            },
        ))
    }

    fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.inner.local_addr()
    }
}

/// A metered network implementation which wraps another
/// [crate::Network] and tracks metrics for it.
#[derive(Debug, Clone)]
pub struct Network<N: crate::Network> {
    inner: N,
    /// Metrics for the network.
    /// Note these are not tracked on a per-connection basis.
    /// That would be nice but it would be very expensive
    /// and potentially an OOM vector.
    metrics: Arc<Metrics>,
}

impl<N: crate::Network> Network<N> {
    /// Wraps `inner` to make it metered.
    /// The `registry` is used to register the metrics.
    pub fn new(inner: N, registry: &mut Registry) -> Self {
        let metrics = Metrics::new(registry);
        Self {
            inner,
            metrics: Arc::new(metrics),
        }
    }
}

impl<N: crate::Network> crate::Network for Network<N> {
    type Listener = Listener<N::Listener>;

    async fn bind(&self, socket: SocketAddr) -> Result<Self::Listener, crate::Error> {
        let inner = self.inner.bind(socket).await?;
        Ok(Listener {
            inner,
            metrics: self.metrics.clone(),
        })
    }

    async fn dial(
        &self,
        socket: SocketAddr,
    ) -> Result<(SinkOf<Self>, StreamOf<Self>), crate::Error> {
        let (sink, stream) = self.inner.dial(socket).await?;
        self.metrics.outbound_connections.inc();
        Ok((
            Sink {
                inner: sink,
                metrics: self.metrics.clone(),
            },
            Stream {
                inner: stream,
                metrics: self.metrics.clone(),
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::network::deterministic::Network as DeterministicNetwork;
    use crate::network::metered::Network as MeteredNetwork;
    use crate::network::tests;
    use crate::{Listener as _, Network as _, Sink as _, Stream as _};
    use prometheus_client::registry::Registry;
    use std::net::SocketAddr;

    #[tokio::test]
    async fn test_trait() {
        tests::test_network_trait(|| {
            MeteredNetwork::new(
                DeterministicNetwork::default(),
                &mut prometheus_client::registry::Registry::default(),
            )
        })
        .await;
    }

    #[tokio::test]
    #[ignore]
    async fn stress_test_trait() {
        tests::stress_test_network_trait(|| {
            MeteredNetwork::new(
                DeterministicNetwork::default(),
                &mut prometheus_client::registry::Registry::default(),
            )
        })
        .await;
    }

    #[tokio::test]
    async fn test_metrics() {
        const MSG_SIZE: u64 = 100;

        // Create a registry and network
        let mut registry = Registry::default();
        let network = MeteredNetwork::new(DeterministicNetwork::default(), &mut registry);

        // Set up server.
        // Note this is a deterministic network, so we can use any address
        // since we're not actually binding to a real socket.
        let addr = SocketAddr::from(([127, 0, 0, 1], 1234));
        let mut listener = network.bind(addr).await.unwrap();

        // Create a server task that accepts one connection and echoes data
        let server = tokio::spawn(async move {
            let (_, mut sink, mut stream) = listener.accept().await.unwrap();
            let buf = stream.recv(vec![0; MSG_SIZE as usize]).await.unwrap();
            sink.send(buf).await.unwrap();
        });

        // Send and receive data as client
        let (mut client_sink, mut client_stream) = network.dial(addr).await.unwrap();

        // Send fixed-size data and receive response
        let msg = vec![42u8; MSG_SIZE as usize];
        client_sink.send(msg.clone()).await.unwrap();

        let response = client_stream
            .recv(vec![0; MSG_SIZE as usize])
            .await
            .unwrap();
        assert_eq!(response.len(), MSG_SIZE as usize);
        assert_eq!(response.as_ref(), msg);

        // Wait for server to complete
        server.await.unwrap();

        // Verify metrics were incremented correctly
        assert_eq!(network.metrics.inbound_connections.get(), 1,);
        assert_eq!(network.metrics.outbound_connections.get(), 1,);
        assert_eq!(
            network.metrics.inbound_bandwidth.get(),
            2 * MSG_SIZE,
            "client and server should both have received MSG_SIZE"
        );
        assert_eq!(
            network.metrics.outbound_bandwidth.get(),
            2 * MSG_SIZE,
            "client and server should both have sent MSG_SIZE"
        );
    }
}
