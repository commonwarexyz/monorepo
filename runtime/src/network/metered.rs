use crate::{SinkOf, StreamOf};
use prometheus_client::{metrics::counter::Counter, registry::Registry};
use std::{net::SocketAddr, sync::Arc};

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

#[derive(Debug, Clone)]
pub struct Network<N: crate::Network> {
    inner: N,
    metrics: Arc<Metrics>,
}

impl<N: crate::Network> Network<N> {
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

        let sink = sink;
        let sink = Sink {
            inner: sink,
            metrics: self.metrics.clone(),
        };

        let stream = stream;
        let stream = Stream {
            inner: stream,
            metrics: self.metrics.clone(),
        };

        Ok((sink, stream))
    }
}

pub struct Listener<L: crate::Listener> {
    inner: L,
    metrics: Arc<Metrics>,
}

impl<L: crate::Listener> crate::Listener for Listener<L> {
    type Sink = Sink<L::Sink>;
    type Stream = Stream<L::Stream>;

    async fn accept(
        &mut self,
    ) -> Result<(std::net::SocketAddr, Self::Sink, Self::Stream), crate::Error> {
        self.inner.accept().await.map(|(addr, sink, stream)| {
            self.metrics.inbound_connections.inc();
            let sink = Sink {
                inner: sink,
                metrics: self.metrics.clone(),
            };
            let stream = Stream {
                inner: stream,
                metrics: self.metrics.clone(),
            };
            (addr, sink, stream)
        })
    }
}

pub struct Sink<S: crate::Sink> {
    inner: S,
    metrics: Arc<Metrics>,
}

impl<S: crate::Sink> crate::Sink for Sink<S> {
    async fn send(&mut self, data: &[u8]) -> Result<(), crate::Error> {
        self.inner.send(data).await?;
        self.metrics.outbound_bandwidth.inc_by(data.len() as u64);
        Ok(())
    }
}

pub struct Stream<S: crate::Stream> {
    inner: S,
    metrics: Arc<Metrics>,
}

impl<S: crate::Stream> crate::Stream for Stream<S> {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<(), crate::Error> {
        self.inner.recv(buf).await?;
        self.metrics.inbound_bandwidth.inc_by(buf.len() as u64);
        Ok(())
    }
}
