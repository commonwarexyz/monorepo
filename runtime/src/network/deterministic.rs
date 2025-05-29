use crate::{mocks, Error, StableBuf};
use futures::{channel::mpsc, SinkExt as _, StreamExt as _};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    ops::Range,
    sync::{Arc, Mutex},
};

/// Range of ephemeral ports assigned to dialers.
const EPHEMERAL_PORT_RANGE: Range<u16> = 32768..61000;

/// Implementation of [crate::Sink] for a deterministic [Network].
pub struct Sink {
    sender: mocks::Sink,
}

impl crate::Sink for Sink {
    async fn send(&mut self, msg: impl Into<StableBuf> + Send) -> Result<(), Error> {
        self.sender.send(msg).await.map_err(|_| Error::SendFailed)
    }
}

/// Implementation of [crate::Stream] for a deterministic [Network].
pub struct Stream {
    receiver: mocks::Stream,
}

impl crate::Stream for Stream {
    async fn recv(&mut self, buf: impl Into<StableBuf> + Send) -> Result<StableBuf, Error> {
        self.receiver.recv(buf).await.map_err(|_| Error::RecvFailed)
    }
}

/// Implementation of [crate::Listener] for a deterministic [Network].
pub struct Listener {
    address: SocketAddr,
    listener: mpsc::UnboundedReceiver<(SocketAddr, mocks::Sink, mocks::Stream)>,
}

impl crate::Listener for Listener {
    type Sink = Sink;
    type Stream = Stream;

    async fn accept(&mut self) -> Result<(SocketAddr, Self::Sink, Self::Stream), Error> {
        let (socket, sender, receiver) = self.listener.next().await.ok_or(Error::ReadFailed)?;
        Ok((socket, Sink { sender }, Stream { receiver }))
    }

    fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        Ok(self.address)
    }
}

type Dialable = mpsc::UnboundedSender<(
    SocketAddr,
    mocks::Sink,   // Listener -> Dialer
    mocks::Stream, // Dialer -> Listener
)>;

/// Deterministic implementation of [crate::Network].
///
/// When a dialer connects to a listener, the listener is given a new ephemeral port
/// from the range `32768..61000`. To keep things simple, it is not possible to
/// bind to an ephemeral port. Likewise, if ports are not reused and when exhausted,
/// the runtime will panic.
#[derive(Clone)]
pub struct Network {
    ephemeral: Arc<Mutex<u16>>,
    listeners: Arc<Mutex<HashMap<SocketAddr, Dialable>>>,
}

impl Default for Network {
    fn default() -> Self {
        Self {
            ephemeral: Arc::new(Mutex::new(EPHEMERAL_PORT_RANGE.start)),
            listeners: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl crate::Network for Network {
    type Listener = Listener;

    async fn bind(&self, socket: SocketAddr) -> Result<Self::Listener, Error> {
        // If the IP is localhost, ensure the port is not in the ephemeral range
        // so that it can be used for binding in the dial method
        if socket.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST)
            && EPHEMERAL_PORT_RANGE.contains(&socket.port())
        {
            return Err(Error::BindFailed);
        }

        // Ensure the port is not already bound
        let mut listeners = self.listeners.lock().unwrap();
        if listeners.contains_key(&socket) {
            return Err(Error::BindFailed);
        }

        // Bind the socket
        let (sender, receiver) = mpsc::unbounded();
        listeners.insert(socket, sender);
        Ok(Listener {
            address: socket,
            listener: receiver,
        })
    }

    async fn dial(&self, socket: SocketAddr) -> Result<(Sink, Stream), Error> {
        // Assign dialer a port from the ephemeral range
        let dialer = {
            let mut ephemeral = self.ephemeral.lock().unwrap();
            let dialer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), *ephemeral);
            *ephemeral = ephemeral
                .checked_add(1)
                .expect("ephemeral port range exhausted");
            dialer
        };

        // Get listener
        let mut sender = {
            let listeners = self.listeners.lock().unwrap();
            let sender = listeners.get(&socket).ok_or(Error::ConnectionFailed)?;
            sender.clone()
        };

        // Construct connection
        let (dialer_sender, dialer_receiver) = mocks::Channel::init();
        let (listener_sender, listener_receiver) = mocks::Channel::init();
        sender
            .send((dialer, dialer_sender, listener_receiver))
            .await
            .map_err(|_| Error::ConnectionFailed)?;
        Ok((
            Sink {
                sender: listener_sender,
            },
            Stream {
                receiver: dialer_receiver,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::network::deterministic as DeterministicNetwork;
    use crate::network::tests;

    #[tokio::test]
    async fn test_trait() {
        tests::test_network_trait(DeterministicNetwork::Network::default).await;
    }

    #[tokio::test]
    #[ignore]
    async fn stress_test_trait() {
        tests::stress_test_network_trait(DeterministicNetwork::Network::default).await;
    }
}
