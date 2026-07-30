use crate::{Acceptor, ConnectionInfo, Dialer, Error, TcpEndpoint, TcpOrigin, mocks};
use commonware_utils::{channel::mpsc, sync::Mutex};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    ops::Range,
    sync::Arc,
};

/// Range of ephemeral ports assigned to dialers.
const EPHEMERAL_PORT_RANGE: Range<u16> = 32768..61000;

/// Implementation of [crate::Sink] for a deterministic [Network].
pub type Sink = mocks::Sink;

/// Implementation of [crate::Stream] for a deterministic [Network].
pub type Stream = mocks::Stream;

pub struct Connection {
    sink: Sink,
    stream: Stream,
    origin: TcpOrigin,
}

impl crate::Connection for Connection {
    type Sink = Sink;
    type Stream = Stream;
    type Origin = TcpOrigin;

    fn split(self) -> (Self::Sink, Self::Stream, ConnectionInfo<Self::Origin>) {
        (
            self.sink,
            self.stream,
            ConnectionInfo {
                origin: Some(self.origin),
                transport: "deterministic_tcp",
            },
        )
    }
}

/// Implementation of [crate::Listener] for a deterministic [Network].
pub struct Listener {
    address: SocketAddr,
    listener: mpsc::UnboundedReceiver<(SocketAddr, mocks::Sink, mocks::Stream)>,
}

impl crate::Listener for Listener {
    type Connection = Connection;

    async fn accept(&mut self) -> Result<Self::Connection, Error> {
        let (socket, sender, receiver) = self.listener.recv().await.ok_or(Error::ReadFailed)?;
        Ok(Connection {
            sink: sender,
            stream: receiver,
            origin: TcpOrigin { remote: socket },
        })
    }
}

impl crate::TcpListener for Listener {
    fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        Ok(self.address)
    }
}

type Dialable = mpsc::UnboundedSender<(
    SocketAddr,
    mocks::Sink,   // Listener -> Dialer
    mocks::Stream, // Dialer -> Listener
)>;

/// Deterministic TCP transport.
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

impl Acceptor for Network {
    type Bind = SocketAddr;
    type Connection = Connection;
    type Listener = Listener;

    async fn bind(&self, socket: &SocketAddr) -> Result<Self::Listener, Error> {
        let socket = *socket;
        // If the IP is localhost, ensure the port is not in the ephemeral range
        // so that it can be used for binding in the dial method
        if socket.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST)
            && EPHEMERAL_PORT_RANGE.contains(&socket.port())
        {
            return Err(Error::BindFailed);
        }

        // Ensure the port is not already bound
        let mut listeners = self.listeners.lock();
        if listeners.contains_key(&socket) {
            return Err(Error::BindFailed);
        }

        // Bind the socket
        let (sender, receiver) = mpsc::unbounded_channel();
        listeners.insert(socket, sender);
        Ok(Listener {
            address: socket,
            listener: receiver,
        })
    }
}

impl Dialer for Network {
    type Endpoint = TcpEndpoint;
    type Connection = Connection;

    fn supports(&self, endpoint: &Self::Endpoint) -> bool {
        matches!(endpoint, TcpEndpoint::Socket(_))
    }

    async fn dial(&self, endpoint: &TcpEndpoint) -> Result<Self::Connection, Error> {
        let TcpEndpoint::Socket(socket) = endpoint else {
            return Err(Error::UnsupportedEndpoint);
        };
        let socket = *socket;
        // Assign dialer a port from the ephemeral range
        let dialer = {
            let mut ephemeral = self.ephemeral.lock();
            let dialer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), *ephemeral);
            *ephemeral = ephemeral
                .checked_add(1)
                .expect("ephemeral port range exhausted");
            dialer
        };

        // Get listener
        let sender = {
            let listeners = self.listeners.lock();
            let sender = listeners.get(&socket).ok_or(Error::ConnectionFailed)?;
            sender.clone()
        };

        // Construct connection
        let (dialer_sender, dialer_receiver) = mocks::Channel::init();
        let (listener_sender, listener_receiver) = mocks::Channel::init();
        sender
            .send((dialer, dialer_sender, listener_receiver))
            .map_err(|_| Error::ConnectionFailed)?;
        Ok(Connection {
            sink: listener_sender,
            stream: dialer_receiver,
            origin: TcpOrigin { remote: socket },
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::network::{deterministic as DeterministicNetwork, tests};
    use commonware_macros::test_group;

    #[tokio::test]
    async fn test_trait() {
        tests::test_network_trait(DeterministicNetwork::Network::default).await;
    }

    #[test_group("slow")]
    #[tokio::test]
    async fn test_stress_trait() {
        tests::stress_test_network_trait(DeterministicNetwork::Network::default).await;
    }
}
