use crate::{deterministic::Auditor, mocks, Error};
use futures::{channel::mpsc, SinkExt as _, StreamExt as _};
use sha2::Digest;
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
    auditor: Arc<Auditor>,
    me: SocketAddr,
    peer: SocketAddr,
    sender: mocks::Sink,
}

impl crate::Sink for Sink {
    async fn send(&mut self, msg: &[u8]) -> Result<(), Error> {
        self.auditor.event(b"send", |hasher| {
            hasher.update(self.me.to_string().as_bytes());
            hasher.update(self.peer.to_string().as_bytes());
            hasher.update(msg);
        });
        self.sender.send(msg).await.map_err(|_| Error::SendFailed)
    }
}

/// Implementation of [crate::Stream] for a deterministic [Network].
pub struct Stream {
    auditor: Arc<Auditor>,
    me: SocketAddr,
    peer: SocketAddr,
    receiver: mocks::Stream,
}

impl crate::Stream for Stream {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        self.auditor.event(b"recv", |hasher| {
            hasher.update(self.me.to_string().as_bytes());
            hasher.update(self.peer.to_string().as_bytes());
            hasher.update(&buf);
        });
        self.receiver
            .recv(buf)
            .await
            .map_err(|_| Error::RecvFailed)?;
        Ok(())
    }
}

/// Implementation of [crate::Listener] for a deterministic [Network].
pub struct Listener {
    auditor: Arc<Auditor>,
    address: SocketAddr,
    listener: mpsc::UnboundedReceiver<(SocketAddr, mocks::Sink, mocks::Stream)>,
}

impl crate::Listener for Listener {
    type Sink = Sink;
    type Stream = Stream;

    async fn accept(&mut self) -> Result<(SocketAddr, Self::Sink, Self::Stream), Error> {
        let (socket, sender, receiver) = self.listener.next().await.ok_or(Error::ReadFailed)?;

        self.auditor.event(b"accept", |hasher| {
            hasher.update(self.address.to_string().as_bytes());
            hasher.update(socket.to_string().as_bytes());
        });

        Ok((
            socket,
            Sink {
                auditor: self.auditor.clone(),
                me: self.address,
                peer: socket,
                sender,
            },
            Stream {
                auditor: self.auditor.clone(),
                me: self.address,
                peer: socket,
                receiver,
            },
        ))
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
    auditor: Arc<Auditor>,
    ephemeral: Arc<Mutex<u16>>,
    listeners: Arc<Mutex<HashMap<SocketAddr, Dialable>>>,
}

impl Network {
    pub fn new(auditor: Arc<Auditor>) -> Self {
        Self {
            auditor,
            ephemeral: Arc::new(Mutex::new(EPHEMERAL_PORT_RANGE.start)),
            listeners: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl crate::Network for Network {
    type Listener = Listener;

    async fn bind(&self, socket: SocketAddr) -> Result<Self::Listener, Error> {
        self.auditor.event(b"bind", |hasher| {
            hasher.update(socket.to_string().as_bytes());
        });

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
            auditor: self.auditor.clone(),
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

        self.auditor.event(b"dial", |hasher| {
            hasher.update(dialer.to_string().as_bytes());
            hasher.update(socket.to_string().as_bytes());
        });

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
                auditor: self.auditor.clone(),
                me: dialer,
                peer: socket,
                sender: listener_sender,
            },
            Stream {
                auditor: self.auditor.clone(),
                me: dialer,
                peer: socket,
                receiver: dialer_receiver,
            },
        ))
    }
}
