use std::net::SocketAddr;

#[derive(Debug, Clone)]
struct Network {}

impl crate::Network for Network {
    type Listener = Listener;

    async fn bind(&self, socket: SocketAddr) -> Result<Self::Listener, crate::Error> {
        todo!()
    }

    async fn dial(&self, socket: SocketAddr) -> Result<(Sink, Stream), crate::Error> {
        todo!()
    }
}

struct Listener {}

impl crate::Listener for Listener {
    type Stream = Stream;
    type Sink = Sink;

    async fn accept(
        &mut self,
    ) -> Result<(std::net::SocketAddr, Self::Sink, Self::Stream), crate::Error> {
        todo!()
    }
}

struct Sink {}

impl crate::Sink for Sink {
    async fn send(&mut self, data: &[u8]) -> Result<(), crate::Error> {
        todo!()
    }
}

struct Stream {}

impl crate::Stream for Stream {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<(), crate::Error> {
        todo!()
    }
}
