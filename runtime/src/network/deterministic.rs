use crate::{Error, mocks};
use commonware_utils::{channel::mpsc, sync::Mutex};
use std::{
    collections::BTreeMap,
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

/// Implementation of [crate::Listener] for a deterministic [Network].
pub struct Listener {
    address: SocketAddr,
    listener: mpsc::UnboundedReceiver<(SocketAddr, mocks::Sink, mocks::Stream)>,
}

impl crate::Listener for Listener {
    type Sink = Sink;
    type Stream = Stream;

    async fn accept(&mut self) -> Result<(SocketAddr, Self::Sink, Self::Stream), Error> {
        let (socket, sender, receiver) = self.listener.recv().await.ok_or(Error::ReadFailed)?;
        Ok((socket, sender, receiver))
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

    /// Delivers dialed connections to the listener bound at each address.
    ///
    /// Ordered so that dropping the network closes listeners in a reproducible order.
    listeners: Arc<Mutex<BTreeMap<SocketAddr, Dialable>>>,
}

impl Default for Network {
    fn default() -> Self {
        Self {
            ephemeral: Arc::new(Mutex::new(EPHEMERAL_PORT_RANGE.start)),
            listeners: Arc::new(Mutex::new(BTreeMap::new())),
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

    async fn dial(&self, socket: SocketAddr) -> Result<(Sink, Stream), Error> {
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
        Ok((listener_sender, dialer_receiver))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        Clock, Listener as _, Network as _, Runner, Spawner, Supervisor as _, deterministic,
        network::{deterministic as DeterministicNetwork, tests},
    };
    use commonware_macros::test_group;
    use commonware_utils::{channel::oneshot, sync::Mutex};
    use rstest::rstest;
    use std::{net::SocketAddr, sync::Arc};

    #[rstest]
    #[case::tokio(crate::tokio::Runner::default())]
    #[cfg_attr(
        all(target_os = "linux", feature = "iouring"),
        case::iouring(crate::iouring::Runner::default())
    )]
    fn test_trait<R: Runner>(#[case] runner: R)
    where
        R::Context: Spawner + Clock,
    {
        runner.start(|context| async move {
            tests::test_network_trait(context, DeterministicNetwork::Network::default).await;
        });
    }

    #[rstest]
    #[case::tokio(crate::tokio::Runner::default())]
    #[cfg_attr(
        all(target_os = "linux", feature = "iouring"),
        case::iouring(crate::iouring::Runner::default())
    )]
    #[test_group("slow")]
    fn test_stress_trait<R: Runner>(#[case] runner: R)
    where
        R::Context: Spawner + Clock,
    {
        runner.start(|context| async move {
            tests::stress_test_network_trait(context, DeterministicNetwork::Network::default).await;
        });
    }

    /// Regression test for https://github.com/commonwarexyz/monorepo/pull/5152.
    ///
    /// Dropping the last context drops the network and the sender of every bound
    /// listener, which wakes the task accepting on it. The listeners must close in
    /// the same order for two runs with the same seed to match.
    #[test]
    fn pr_5152_regression() {
        fn run(seed: u64) -> (Vec<u16>, String) {
            deterministic::Runner::seeded(seed).start(|context| async move {
                let auditor = context.auditor();
                let closed = Arc::new(Mutex::new(Vec::new()));
                let mut acceptors = Vec::new();
                for port in 10_000..10_008 {
                    let address = SocketAddr::from(([127, 0, 0, 1], port));
                    let mut listener = context.bind(address).await.unwrap();
                    let (parked, ready) = oneshot::channel();
                    let closed = closed.clone();
                    acceptors.push(context.child("acceptor").spawn(move |_| async move {
                        parked.send(()).unwrap();
                        assert!(listener.accept().await.is_err());
                        closed.lock().push(port);
                    }));
                    ready.await.unwrap();
                }

                drop(context);
                for acceptor in acceptors {
                    acceptor.await.unwrap();
                }
                let closed = closed.lock().clone();
                (closed, auditor.state())
            })
        }
        for seed in 0..8 {
            assert_eq!(run(seed), run(seed));
        }
    }
}
