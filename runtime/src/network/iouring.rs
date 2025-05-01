use std::net::SocketAddr;

#[derive(Clone, Debug)]
pub(crate) struct Network {}

impl crate::Network for Network {
    type Listener = Listener;

    async fn bind(&self, socket: SocketAddr) -> Result<Self::Listener, crate::Error> {
        todo!()
    }

    async fn dial(
        &self,
        socket: SocketAddr,
    ) -> Result<(crate::SinkOf<Self>, crate::StreamOf<Self>), crate::Error> {
        todo!()
    }
}

pub(crate) struct Listener {}

impl crate::Listener for Listener {
    type Stream = Stream;
    type Sink = Sink;

    async fn accept(&mut self) -> Result<(SocketAddr, Self::Sink, Self::Stream), crate::Error> {
        todo!()
    }
}

pub(crate) struct Sink {}

impl crate::Sink for Sink {
    async fn send(&mut self, msg: &[u8]) -> Result<(), crate::Error> {
        todo!()
    }
}

pub(crate) struct Stream {}

impl crate::Stream for Stream {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<(), crate::Error> {
        todo!()
    }
}
